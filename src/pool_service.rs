//! Runtime, persistence CRUD, and SOCKS5 listeners for exit pools.
//!
//! Pool membership is stored by tunnel hostname and resolved on every dial, so
//! reconnects and node swaps do not require rebuilding listeners. Dialing never
//! falls back to the host network: it only uses a selected tunnel's dialer.

use crate::{
    manager::Manager,
    models::{Pool, PoolStore, PoolView, SocksCred, TunnelState},
    nodes::{new_socks_cred, node_supports_aead, validate_cred},
    panel_native::egress_tag,
    pools_logic::{
        assess_pool_fill, canonical_pool_mode, creation_room, fill_avoid, fill_candidates,
        fill_completion_note, fill_failure_reason, fill_slot, host_in_pool, load_pool_store,
        parse_pool_seq, pool_reuse_pick, pool_view, retire_slot, target_key, PoolFillState,
        PoolMember, PoolRuntimeState, POOL_FILL_INTERVAL, POOL_FILL_SLOT_FLOOR, POOL_FILL_WAIT_UP,
        POOL_MODE_BALANCE, POOL_MODE_SINGLE, POOL_PROBE_INTERVAL, POOL_PROBE_TARGET,
        POOL_TRY_TIMEOUT,
    },
    socks5::{serve_socks, DialNetwork, DialSocket, SocksDialer},
};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use futures::StreamExt;
use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex, MutexGuard, OnceLock, Weak,
    },
    time::{Duration, Instant as StdInstant},
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Mutex as AsyncMutex},
    task::JoinHandle,
    time::{interval_at, sleep, timeout, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
const RAND_PORT_MIN: u16 = 20_000;
const RAND_PORT_MAX: u16 = 60_000;
const LISTEN_ATTEMPTS: usize = 4;
const MEMBER_CACHE_TTL: Duration = Duration::from_millis(250);
const EXTERNAL_XRAY_CONFIG: &str = "/usr/local/etc/xray/config.json";

static POOL_PORTS: OnceLock<StdMutex<HashSet<u16>>> = OnceLock::new();

fn pool_port_set() -> &'static StdMutex<HashSet<u16>> {
    POOL_PORTS.get_or_init(|| StdMutex::new(HashSet::new()))
}

/// Returns the loopback ports currently reserved by pool listeners.
///
/// This deliberately does not touch `Manager` or service state, so future port
/// allocation can call it while holding the manager's tunnel lock.
pub fn pool_ports() -> HashSet<u16> {
    lock_unpoisoned(pool_port_set()).clone()
}

fn note_pool_port(port: u16) {
    if port != 0 {
        lock_unpoisoned(pool_port_set()).insert(port);
    }
}

fn unnote_pool_port(port: u16) {
    if port != 0 {
        lock_unpoisoned(pool_port_set()).remove(&port);
    }
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The information a routing backend needs for one live pool listener.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PoolEgress {
    pub identity: String,
    pub tag: String,
    pub port: u16,
    pub cred: SocksCred,
    pub up: usize,
}

/// A SOCKS5 dialer bound to one pool. Clones share the service and pool ID.
#[derive(Clone)]
pub struct PoolDialer {
    service: PoolService,
    pool_id: String,
}

impl fmt::Debug for PoolDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolDialer")
            .field("pool_id", &self.pool_id)
            .finish()
    }
}

#[async_trait]
impl SocksDialer for PoolDialer {
    async fn dial(&self, network: DialNetwork, addr: &str) -> Result<DialSocket> {
        self.service
            .dial(&self.pool_id, network, addr)
            .await
            .map(|(socket, _)| socket)
    }
}

#[derive(Default)]
struct ServiceState {
    store: PoolStore,
    runs: HashMap<String, Arc<PoolRun>>,
    probing: HashSet<(String, String)>,
    fill: PoolFillState,
    member_cache: HashMap<String, (StdInstant, Vec<ResolvedMember>)>,
}

struct PoolServiceInner {
    dir: PathBuf,
    manager: Arc<Manager>,
    state: StdMutex<ServiceState>,
    operations: AsyncMutex<()>,
    closed: AtomicBool,
    shutdown: CancellationToken,
    probe_task: StdMutex<Option<JoinHandle<()>>>,
    fill_task: StdMutex<Option<JoinHandle<()>>>,
}

impl Drop for PoolServiceInner {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        self.shutdown.cancel();
        if let Some(task) = lock_unpoisoned(&self.probe_task).take() {
            task.abort();
        }
        if let Some(task) = lock_unpoisoned(&self.fill_task).take() {
            task.abort();
        }
        let runs = {
            let mut state = lock_unpoisoned(&self.state);
            state.probing.clear();
            std::mem::take(&mut state.runs)
        };
        for (_, run) in &runs {
            if let Some(task) = run.shutdown() {
                task.abort();
            }
            unnote_pool_port(run.port);
        }
        drop(runs);
    }
}

struct PoolRun {
    listener: StdMutex<Option<Arc<TcpListener>>>,
    port: u16,
    runtime: Arc<StdMutex<PoolRuntimeState>>,
    shutdown: CancellationToken,
    task: StdMutex<Option<JoinHandle<()>>>,
}

impl PoolRun {
    fn new(listener: TcpListener, pool: &Pool) -> Self {
        let port = listener
            .local_addr()
            .expect("a bound pool listener has a local address")
            .port();
        note_pool_port(port);
        Self {
            listener: StdMutex::new(Some(Arc::new(listener))),
            port,
            runtime: Arc::new(StdMutex::new(PoolRuntimeState::new(
                &pool.mode,
                pool.rr_step,
            ))),
            shutdown: CancellationToken::new(),
            task: StdMutex::new(None),
        }
    }

    fn choose(
        &self,
        target: &str,
        members: &[PoolMember],
        allow_race: bool,
    ) -> crate::pools_logic::PoolChoice {
        let mut choice = lock_unpoisoned(&self.runtime).policy.pick(target, members);
        if !allow_race {
            choice.concurrent = false;
        }
        choice
    }

    fn apply_state(&self, members: &mut [PoolMember]) {
        lock_unpoisoned(&self.runtime).apply_state(members, Utc::now());
    }

    fn reconfigure(&self, mode: &str, step: usize) {
        lock_unpoisoned(&self.runtime)
            .policy
            .reconfigure(mode, step);
    }

    fn apply_target_state(&self, target: &str, members: &mut [PoolMember]) {
        lock_unpoisoned(&self.runtime).apply_target_state(target, members);
    }

    fn note_success(&self, target: &str, host: &str, sample: Duration) {
        lock_unpoisoned(&self.runtime).note_target_success(target, host, sample, Utc::now());
    }

    fn note_failure(&self, host: &str) {
        lock_unpoisoned(&self.runtime).note_failure(host, Utc::now());
    }

    fn listener(&self) -> Arc<TcpListener> {
        lock_unpoisoned(&self.listener)
            .as_ref()
            .expect("a running pool has a listener")
            .clone()
    }

    fn shutdown(&self) -> Option<JoinHandle<()>> {
        self.shutdown.cancel();
        drop(lock_unpoisoned(&self.listener).take());
        lock_unpoisoned(&self.task).take()
    }

    async fn stop(&self) {
        if let Some(task) = self.shutdown() {
            task.abort();
            let _ = task.await;
        }
        unnote_pool_port(self.port);
    }
}

impl Drop for PoolRun {
    fn drop(&mut self) {
        if let Some(task) = self.shutdown() {
            task.abort();
        }
        unnote_pool_port(self.port);
    }
}

/// Owns all pool listeners and their persistent configuration.
///
/// Clones share one service. Call [`PoolService::close`] during shutdown; the
/// inner object also aborts listeners if the last service clone is dropped.
#[derive(Clone)]
pub struct PoolService {
    inner: Arc<PoolServiceInner>,
}

impl PoolService {
    /// Loads `pools.json` and starts one loopback listener per stored pool.
    /// A listener bind failure is logged and retained for a later `set_pool`.
    pub async fn new(dir: impl Into<PathBuf>, manager: Arc<Manager>) -> Result<Self> {
        let dir = dir.into();
        let store = load_pool_store(&dir)?;
        Self::load(dir, manager, store).await
    }

    /// Starts a service from an already-loaded store, normalizing it as the Go
    /// loader does. This is also useful for tests and explicit reloads.
    pub async fn load(
        dir: impl Into<PathBuf>,
        manager: Arc<Manager>,
        mut store: PoolStore,
    ) -> Result<Self> {
        for pool in &mut store.pools {
            pool.normalize();
        }
        let highest = store
            .pools
            .iter()
            .map(|pool| parse_pool_seq(&pool.id))
            .max()
            .unwrap_or(0);
        store.next = store.next.max(highest.saturating_add(1)).max(1);

        let inner = Arc::new(PoolServiceInner {
            dir: dir.into(),
            manager,
            state: StdMutex::new(ServiceState {
                store,
                ..ServiceState::default()
            }),
            operations: AsyncMutex::new(()),
            closed: AtomicBool::new(false),
            shutdown: CancellationToken::new(),
            probe_task: StdMutex::new(None),
            fill_task: StdMutex::new(None),
        });
        let service = Self { inner };
        for pool in service.pools() {
            if let Err(error) = service.ensure_listener(&pool).await {
                warn!(
                    "出口组 {} 监听没起来: {error}（绑定关系保留，下次启动重试）",
                    pool.name
                );
            }
        }

        let shutdown = service.inner.shutdown.clone();
        let task = tokio::spawn(probe_loop(service.clone(), shutdown));
        *lock_unpoisoned(&service.inner.probe_task) = Some(task);
        Ok(service)
    }

    /// Adds or updates a pool and returns the stored value, including its
    /// assigned ID, generated credentials, and actual listener port.
    ///
    /// Editing preserves the existing port and credentials. New IDs are `pN`
    /// and are never taken from caller input.
    pub async fn set_pool(&self, mut pool: Pool) -> Result<Pool> {
        let _operation = self.inner.operations.lock().await;
        self.ensure_open()?;
        pool.id = pool.id.trim().to_string();
        pool.normalize();
        pool.validate()?;

        let mut store = lock_unpoisoned(&self.inner.state).store.clone();
        let existing = store.get(&pool.id).is_some();
        if let Some(index) = store.pools.iter().position(|item| item.id == pool.id) {
            pool.port = store.pools[index].port;
            pool.cred = store.pools[index].cred.clone();
            store.pools[index] = pool.clone();
        } else {
            pool.id = format!("p{}", store.next);
            store.next = store
                .next
                .checked_add(1)
                .ok_or_else(|| anyhow!("出口组编号已用完"))?;
            if pool.cred.user.is_empty() {
                pool.cred = new_socks_cred();
            }
            store.pools.push(pool.clone());
        }
        store.save(&self.inner.dir)?;

        {
            let mut state = lock_unpoisoned(&self.inner.state);
            state.store = store;
            state.member_cache.remove(&pool.id);
            if existing {
                if let Some(run) = state.runs.get(&pool.id) {
                    run.reconfigure(&pool.mode, pool.rr_step);
                }
            }
        }
        self.ensure_listener(&pool).await?;
        Ok(self.pool(&pool.id).unwrap_or(pool))
    }

    /// Deletes a pool, persists the removal, and stops its listener. Existing
    /// established SOCKS5 sessions are left alone, matching the Go service.
    pub async fn delete_pool(&self, id: &str) -> Result<()> {
        let _operation = self.inner.operations.lock().await;
        self.ensure_open()?;
        let mut store = lock_unpoisoned(&self.inner.state).store.clone();
        let index = store
            .pools
            .iter()
            .position(|pool| pool.id == id)
            .ok_or_else(|| anyhow!("出口组不存在"))?;
        store.pools.remove(index);
        store.save(&self.inner.dir)?;
        {
            let mut state = lock_unpoisoned(&self.inner.state);
            state.store = store;
            state.fill.drop_ledger(id);
        }
        let run = lock_unpoisoned(&self.inner.state).runs.remove(id);
        if let Some(run) = run {
            run.stop().await;
        }
        Ok(())
    }

    /// Changes SOCKS5 credentials without rebuilding the listener. Two empty
    /// fields generate a credential pair; all other values are validated.
    pub async fn set_cred(&self, id: &str, cred: SocksCred) -> Result<SocksCred> {
        let _operation = self.inner.operations.lock().await;
        self.ensure_open()?;
        let cred = if cred.user.is_empty() && cred.pass.is_empty() {
            new_socks_cred()
        } else {
            validate_cred(&cred)?;
            cred
        };

        let mut store = lock_unpoisoned(&self.inner.state).store.clone();
        let pool = store.get_mut(id).ok_or_else(|| anyhow!("出口组不存在"))?;
        pool.cred = cred.clone();
        store.save(&self.inner.dir)?;
        lock_unpoisoned(&self.inner.state).store = store;
        Ok(cred)
    }

    /// Updates member hostnames after a tunnel changes nodes.
    pub async fn rename_host(&self, old_host: &str, new_host: &str) -> Result<bool> {
        let _operation = self.inner.operations.lock().await;
        self.ensure_open()?;
        if old_host.is_empty() || new_host.is_empty() || old_host == new_host {
            return Ok(false);
        }
        let mut store = lock_unpoisoned(&self.inner.state).store.clone();
        let mut changed = false;
        for pool in &mut store.pools {
            for host in &mut pool.hosts {
                if host == old_host {
                    *host = new_host.to_string();
                    changed = true;
                }
            }
        }
        if !changed {
            return Ok(false);
        }
        store.save(&self.inner.dir)?;
        lock_unpoisoned(&self.inner.state).store = store;
        Ok(true)
    }

    /// Returns deep copies sorted by display name and numeric pool sequence.
    pub fn pools(&self) -> Vec<Pool> {
        lock_unpoisoned(&self.inner.state)
            .store
            .sorted()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Returns a deep copy of one pool.
    pub fn pool(&self, id: &str) -> Option<Pool> {
        lock_unpoisoned(&self.inner.state).store.get(id).cloned()
    }

    /// Resolves configured hostnames against the manager's current tunnels and
    /// applies this pool's latency/cooldown snapshot.
    pub async fn resolve_members(&self, id: &str) -> Vec<PoolMember> {
        self.resolved_members(id)
            .await
            .into_iter()
            .map(|member| member.member)
            .collect()
    }

    /// Builds UI views. Inbound attachment and autofill notes remain concerns
    /// of the later HTTP/autofill integration.
    pub async fn views(&self) -> Vec<PoolView> {
        let aead_hosts: HashSet<String> = self
            .inner
            .manager
            .states()
            .await
            .iter()
            .filter(|state| node_supports_aead(&state.node.config))
            .map(|state| state.node.hostname.clone())
            .collect();
        let mut views = Vec::new();
        for pool in self.pools() {
            let members = self.resolve_members(&pool.id).await;
            let running = lock_unpoisoned(&self.inner.state)
                .runs
                .contains_key(&pool.id);
            let note = lock_unpoisoned(&self.inner.state)
                .fill
                .notes()
                .remove(&pool.id);
            views.push(pool_view(
                &pool,
                &members,
                running,
                note.as_deref(),
                &aead_hosts,
            ));
        }
        views
    }

    /// The pool_api.go host validator, exposed for the future HTTP layer.
    /// Blank and duplicate entries are removed in configured order.
    pub async fn check_pool_hosts(&self, pool: &mut Pool) -> Result<()> {
        let known: HashSet<String> = self
            .inner
            .manager
            .states()
            .await
            .into_iter()
            .map(|state| state.node.hostname)
            .collect();
        let mut seen = HashSet::new();
        let mut unique = Vec::with_capacity(pool.hosts.len());
        let mut missing = Vec::new();
        for raw in &pool.hosts {
            let host = raw.trim();
            if host.is_empty() || !seen.insert(host.to_string()) {
                continue;
            }
            if !known.contains(host) {
                missing.push(host.to_string());
            }
            unique.push(host.to_string());
        }
        if !missing.is_empty() {
            bail!("这些出口当前不存在，请重新勾选：{}", missing.join("、"));
        }
        pool.hosts = unique;
        Ok(())
    }

    /// Lists only pools whose listeners are actually running.
    pub async fn egresses(&self) -> Vec<PoolEgress> {
        let snapshots: Vec<(Pool, String)> = {
            let state = lock_unpoisoned(&self.inner.state);
            state
                .store
                .sorted()
                .into_iter()
                .filter_map(|pool| {
                    state
                        .runs
                        .get(&pool.id)
                        .map(|_| (pool.clone(), pool.identity()))
                })
                .collect()
        };
        let mut out = Vec::with_capacity(snapshots.len());
        for (pool, identity) in snapshots {
            let up = self
                .resolve_members(&pool.id)
                .await
                .into_iter()
                .filter(|member| member.up)
                .count();
            out.push(PoolEgress {
                tag: egress_tag(&identity),
                identity,
                port: pool.port,
                cred: pool.cred,
                up,
            });
        }
        out
    }

    /// Looks up a live pool by its `pool-<id>` identity.
    pub async fn egress(&self, identity: &str) -> Option<PoolEgress> {
        self.egresses()
            .await
            .into_iter()
            .find(|egress| egress.identity == identity)
    }

    /// Returns the dialer accepted by `serve_socks` for one pool.
    pub fn dialer_for(&self, id: &str) -> PoolDialer {
        PoolDialer {
            service: self.clone(),
            pool_id: id.to_string(),
        }
    }

    /// Alias for [`PoolService::dialer_for`].
    pub fn dialer(&self, id: &str) -> PoolDialer {
        self.dialer_for(id)
    }

    /// Selects and dials a pool member, returning the chosen hostname as well
    /// as the socket. No host-network fallback is performed.
    pub async fn dial(
        &self,
        id: &str,
        network: DialNetwork,
        addr: &str,
    ) -> Result<(DialSocket, String)> {
        self.ensure_open()?;
        let run = self.run_of(id).ok_or_else(|| anyhow!("出口组未在运行"))?;
        let target = target_key(addr);
        let members = self.resolved_members(id).await;
        let mut policy_members: Vec<PoolMember> =
            members.iter().map(|member| member.member.clone()).collect();
        run.apply_target_state(&target, &mut policy_members);
        let choice = run.choose(&target, &policy_members, network == DialNetwork::Tcp);
        if choice.order.is_empty() {
            bail!("出口组内没有可用出口");
        }

        if choice.concurrent {
            let candidates: Vec<_> = choice
                .order
                .iter()
                .filter_map(|chosen| {
                    members
                        .iter()
                        .find(|member| member.member.host == chosen.host)
                        .filter(|member| usable(member))
                        .cloned()
                })
                .collect();
            return Self::race_dial(&run, candidates, network, addr, &target).await;
        }

        let mut last_error = None;
        for chosen in choice.order {
            let Some(member) = members
                .iter()
                .find(|member| member.member.host == chosen.host)
                .filter(|member| usable(member))
            else {
                continue;
            };
            let outcome = dial_candidate(member, network, addr).await;
            match outcome.result {
                Ok(socket) => {
                    run.note_success(&target, &outcome.host, outcome.elapsed);
                    return Ok((socket, outcome.host));
                }
                Err(error) => {
                    last_error = Some(error);
                    run.note_failure(&outcome.host);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("出口组内没有可用出口")))
    }

    /// Runs one periodic stale-sample probe pass. The background task calls
    /// this automatically; it is public for diagnostics and focused tests.
    pub async fn probe_stale(&self) {
        let pools = self.pools();
        for pool in pools {
            if !matches!(
                canonical_pool_mode(&pool.mode),
                Some(POOL_MODE_SINGLE) | Some(POOL_MODE_BALANCE)
            ) {
                continue;
            }
            let Some(run) = self.run_of(&pool.id) else {
                continue;
            };
            let members = self.resolved_members(&pool.id).await;
            let stale: Vec<_> = {
                let runtime = lock_unpoisoned(&run.runtime);
                let now = Utc::now();
                members
                    .iter()
                    .filter(|member| runtime.needs_probe(&pool.mode, &member.member, now))
                    .cloned()
                    .collect()
            };
            for member in stale {
                let Some(dialer) = member.dialer.as_ref() else {
                    continue;
                };
                let key = (pool.id.clone(), member.member.host.clone());
                let inserted = {
                    let mut state = lock_unpoisoned(&self.inner.state);
                    !self.inner.closed.load(Ordering::SeqCst) && state.probing.insert(key.clone())
                };
                if !inserted {
                    continue;
                }

                let runtime = Arc::clone(&run.runtime);
                let dialer = Arc::clone(dialer);
                let host = member.member.host.clone();
                let shutdown = self.inner.shutdown.clone();
                let weak = Arc::downgrade(&self.inner);
                tokio::spawn(async move {
                    let started = Instant::now();
                    let attempt = tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => None,
                        result = timeout(
                            POOL_TRY_TIMEOUT,
                            dialer.dial(DialNetwork::Tcp, POOL_PROBE_TARGET),
                        ) => Some(result),
                    };
                    if let Some(result) = attempt {
                        match result {
                            Ok(Ok(DialSocket::Tcp(socket))) => {
                                drop(socket);
                                lock_unpoisoned(&runtime).note_success(
                                    &host,
                                    started.elapsed(),
                                    Utc::now(),
                                );
                            }
                            _ => lock_unpoisoned(&runtime).note_failure(&host, Utc::now()),
                        }
                    }
                    if let Some(service) = weak.upgrade() {
                        lock_unpoisoned(&service.state).probing.remove(&key);
                    }
                });
            }
        }
    }

    /// Starts autofill after persisted tunnels have been restored.
    pub fn start_fill_task(&self) {
        if self.inner.closed.load(Ordering::SeqCst)
            || lock_unpoisoned(&self.inner.fill_task).is_some()
        {
            return;
        }
        let task = tokio::spawn(fill_loop(self.clone(), self.inner.shutdown.clone()));
        *lock_unpoisoned(&self.inner.fill_task) = Some(task);
    }

    /// Runs one autofill pass. A previous pass that is still connecting a new
    /// exit makes this call a no-op, so slow nodes cannot queue extra work.
    pub async fn fill_once(&self) {
        if !self.ensure_open().is_ok() {
            return;
        }
        {
            let mut state = lock_unpoisoned(&self.inner.state);
            if !state.fill.begin_fill() {
                return;
            }
        }
        let pools: Vec<_> = self
            .pools()
            .into_iter()
            .filter(|pool| pool.auto_fill)
            .collect();
        let mut fills = futures::stream::iter(pools.into_iter().map(|pool| async move {
            self.fill_pool(&pool).await;
        }))
        .buffer_unordered(2);
        while fills.next().await.is_some() {}
        let mut state = lock_unpoisoned(&self.inner.state);
        state.fill.finish_fill();
        state.fill.prune_bad(Utc::now());
    }

    async fn fill_pool(&self, pool: &Pool) {
        let now = Utc::now();
        let mut first_dead = lock_unpoisoned(&self.inner.state)
            .fill
            .dead_snapshot(&pool.id);
        let members = self.resolve_members(&pool.id).await;
        let assessment = assess_pool_fill(pool, &members, &mut first_dead, now);
        {
            let mut state = lock_unpoisoned(&self.inner.state);
            let store = state.store.clone();
            state.fill.merge_dead(&pool.id, first_dead, &store);
        }
        if assessment.need == 0 {
            lock_unpoisoned(&self.inner.state)
                .fill
                .set_note(&pool.id, assessment.note);
            return;
        }

        let tunnels = self.inner.manager.states().await;
        let candidates = {
            let state = lock_unpoisoned(&self.inner.state);
            fill_candidates(
                &state.store.pools,
                &pool.id,
                &tunnels,
                &state.fill.bad_until,
                now,
            )
        };
        let picks = pool_reuse_pick(&candidates, assessment.need);
        let mut reused = 0;
        for host in picks {
            let old_host = fill_slot(&assessment.gone, reused).unwrap_or("");
            if self.reuse_one(pool, old_host, &host).await {
                reused += 1;
            }
        }

        let mut room = creation_room(
            self.inner
                .manager
                .max_slots
                .saturating_sub(self.inner.manager.tunnels().await.len()),
        );
        let mut created = 0;
        let mut reason = None;
        for index in 0..assessment.need.saturating_sub(reused) {
            if room == 0 {
                break;
            }
            room -= 1;
            let current_members = self.resolve_members(&pool.id).await;
            let avoid = {
                let state = lock_unpoisoned(&self.inner.state);
                fill_avoid(&current_members, &state.fill.bad_until, Utc::now())
            };
            let node = match self.pick_fill_node(&avoid).await {
                Ok(node) => node,
                Err(err) => {
                    reason = Some(err.to_string());
                    break;
                }
            };
            let old_host = fill_slot(&assessment.gone, reused + created).unwrap_or("");
            match self.fill_one(pool, node, old_host).await {
                Ok(()) => created += 1,
                Err(host) => reason = Some(fill_failure_reason(&host)),
            }
        }
        let note = fill_completion_note(pool, &assessment, reused, created, reason);
        lock_unpoisoned(&self.inner.state)
            .fill
            .set_note(&pool.id, note);
    }

    async fn pick_fill_node(&self, avoid: &HashSet<String>) -> Result<crate::models::Node> {
        self.inner.manager.ensure_nodes().await.ok();
        let nodes = self.inner.manager.node_list(false).await.0;
        let used: HashSet<_> = self
            .inner
            .manager
            .states()
            .await
            .into_iter()
            .map(|state| state.node.hostname)
            .collect();
        nodes
            .into_iter()
            .find(|node| !avoid.contains(&node.hostname) && !used.contains(&node.hostname))
            .ok_or_else(|| anyhow!("挑不到可补位的空闲节点"))
    }

    async fn reuse_one(&self, pool: &Pool, old_host: &str, host: &str) -> bool {
        if let Err(err) = self.swap_member(&pool.id, old_host, host).await {
            warn!("出口组 {} 顶替 {} 失败: {err}", pool.name, host);
            return false;
        }
        lock_unpoisoned(&self.inner.state)
            .fill
            .forget_dead(&pool.id, old_host);
        self.retire_member(old_host).await;
        true
    }

    async fn fill_one(
        &self,
        pool: &Pool,
        node: crate::models::Node,
        old_host: &str,
    ) -> Result<(), String> {
        let tunnel = match self.inner.manager.start(node.clone()).await {
            Ok(tunnel) => tunnel,
            Err(err) => {
                warn!("出口组 {} 补位起不来: {err}", pool.name);
                self.mark_fill_bad(&node.hostname).await;
                return Err(node.hostname);
            }
        };
        if self.inner.manager.wait_up(&tunnel, POOL_FILL_WAIT_UP).await != "up" {
            let _ = self.inner.manager.stop(tunnel.slot).await;
            self.mark_fill_bad(&node.hostname).await;
            return Err(node.hostname);
        }
        if let Err(err) = self.swap_member(&pool.id, old_host, &node.hostname).await {
            warn!("出口组 {} 补位成功但写回成员失败: {err}", pool.name);
            self.mark_fill_bad(&node.hostname).await;
            return Err(node.hostname);
        }
        lock_unpoisoned(&self.inner.state)
            .fill
            .forget_dead(&pool.id, old_host);
        self.retire_member(old_host).await;
        Ok(())
    }

    async fn mark_fill_bad(&self, host: &str) {
        lock_unpoisoned(&self.inner.state)
            .fill
            .mark_bad(host, Utc::now());
    }

    async fn swap_member(&self, id: &str, old_host: &str, new_host: &str) -> Result<()> {
        let mut state = lock_unpoisoned(&self.inner.state);
        let mut store = state.store.clone();
        if store.swap_member(id, old_host, new_host)? {
            store.save(&self.inner.dir)?;
            state.store = store;
            state.member_cache.remove(id);
        }
        Ok(())
    }

    async fn retire_member(&self, host: &str) {
        let Some(tunnel) = self
            .inner
            .manager
            .states()
            .await
            .into_iter()
            .find(|state| state.node.hostname == host)
        else {
            return;
        };
        let used_by_pool = host_in_pool(&self.pools(), host);
        let inbound_bound = self.host_bound(host).await;
        if let Some(slot) = retire_slot(host, Some(&tunnel), used_by_pool, inbound_bound) {
            if let Err(err) = self.inner.manager.stop(slot).await {
                warn!("出口组顶替后收尾 {host} 失败: {err}");
            }
        }
    }

    async fn host_bound(&self, host: &str) -> Option<bool> {
        let panel = self.inner.manager.panel()?;
        let inbounds = panel.inbounds().await.ok()?;
        let tag = crate::panel_native::sanitize_tag(host);
        Some(inbounds.iter().any(|inbound| inbound.bound_to == tag))
    }

    /// Stops probing and all listeners. Established relay sessions are not
    /// forcibly aborted. Calling `close` more than once is safe.
    pub async fn close(&self) {
        let _operation = self.inner.operations.lock().await;
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.inner.shutdown.cancel();
        let probe_task = lock_unpoisoned(&self.inner.probe_task).take();
        if let Some(task) = probe_task {
            task.abort();
            let _ = task.await;
        }
        let fill_task = lock_unpoisoned(&self.inner.fill_task).take();
        if let Some(task) = fill_task {
            task.abort();
            let _ = task.await;
        }
        let runs: Vec<_> = {
            let mut state = lock_unpoisoned(&self.inner.state);
            state.probing.clear();
            state.runs.drain().map(|(_, run)| run).collect()
        };
        for run in runs {
            run.stop().await;
        }
    }

    fn ensure_open(&self) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            bail!("出口组服务已关闭");
        }
        Ok(())
    }

    fn run_of(&self, id: &str) -> Option<Arc<PoolRun>> {
        lock_unpoisoned(&self.inner.state).runs.get(id).cloned()
    }

    pub fn cred_of(&self, id: &str) -> Option<SocksCred> {
        lock_unpoisoned(&self.inner.state)
            .store
            .get(id)
            .map(|pool| pool.cred.clone())
    }

    async fn resolved_members(&self, id: &str) -> Vec<ResolvedMember> {
        if let Some((_at, members)) = lock_unpoisoned(&self.inner.state)
            .member_cache
            .get(id)
            .filter(|(at, _)| at.elapsed() < MEMBER_CACHE_TTL)
            .cloned()
        {
            return members;
        }
        let Some(pool) = self.pool(id) else {
            return Vec::new();
        };
        // Resolve the manager before taking any service-state lock. This keeps
        // the lock direction opposite to the one used by Go's port registry.
        let wanted: HashSet<&str> = pool.hosts.iter().map(String::as_str).collect();
        let mut by_host: HashMap<String, ResolvedTunnel> = HashMap::new();
        for tunnel in self.inner.manager.tunnels().await {
            let Some(state) = tunnel.state_if_host(&wanted).await else {
                continue;
            };
            let dialer = tunnel.runtime.socks_dialer();
            by_host.insert(
                state.node.hostname.clone(),
                ResolvedTunnel { state, dialer },
            );
        }
        let run = self.run_of(id);
        let mut members: Vec<_> = pool
            .hosts
            .iter()
            .map(|host| {
                let tunnel = by_host.get(host);
                // `namespace` is the pure policy layer's existence marker. The
                // actual namespace-affine dialer travels beside this snapshot.
                let member = PoolMember {
                    host: host.clone(),
                    namespace: if tunnel.is_some() {
                        host.clone()
                    } else {
                        String::new()
                    },
                    slot: tunnel.map_or(0, |tunnel| tunnel.state.slot),
                    exit_ip: tunnel.map_or_else(String::new, |tunnel| tunnel.state.exit_ip.clone()),
                    up: tunnel.is_some_and(|tunnel| tunnel.state.status == "up"),
                    status: tunnel.map_or_else(String::new, |tunnel| tunnel.state.status.clone()),
                    ..PoolMember::default()
                };
                ResolvedMember {
                    member,
                    dialer: tunnel.map(|tunnel| Arc::clone(&tunnel.dialer)),
                }
            })
            .collect();
        if let Some(run) = run {
            let mut snapshots: Vec<_> =
                members.iter().map(|member| member.member.clone()).collect();
            run.apply_state(&mut snapshots);
            for (member, snapshot) in members.iter_mut().zip(snapshots) {
                member.member.latency = snapshot.latency;
                member.member.cooling = snapshot.cooling;
            }
        }
        {
            let mut state = lock_unpoisoned(&self.inner.state);
            if state.member_cache.len() >= 128 {
                state.member_cache.clear();
            }
            state
                .member_cache
                .insert(id.to_string(), (StdInstant::now(), members.clone()));
        }
        members
    }

    async fn ensure_listener(&self, pool: &Pool) -> Result<()> {
        if self.run_of(&pool.id).is_some() {
            return Ok(());
        }
        let listener = match listen_pool(pool.port).await {
            Ok(listener) => listener,
            Err(error) => {
                let taken = self.taken_ports().await;
                free_random_listener(taken)
                    .await
                    .with_context(|| format!("监听 {} 失败且无备用端口: {error}", pool.port))?
            }
        };
        let port = listener
            .local_addr()
            .context("读取出口组监听地址失败")?
            .port();
        let mut current = self.pool(&pool.id).unwrap_or_else(|| pool.clone());
        if current.port != port {
            current.port = port;
            let mut store = lock_unpoisoned(&self.inner.state).store.clone();
            if let Some(saved) = store.get_mut(&pool.id) {
                saved.port = port;
            }
            lock_unpoisoned(&self.inner.state).store = store.clone();
            if let Err(error) = store.save(&self.inner.dir) {
                warn!("出口组 {} 端口回写失败: {error}", current.name);
            }
        }

        let run = Arc::new(PoolRun::new(listener, &current));
        let id = current.id.clone();
        let listener = run.listener();
        let shutdown = run.shutdown.clone();
        let task = tokio::spawn(accept_loop(self.clone(), id.clone(), listener, shutdown));
        *lock_unpoisoned(&run.task) = Some(task);
        lock_unpoisoned(&self.inner.state).runs.insert(id, run);
        Ok(())
    }

    async fn taken_ports(&self) -> HashSet<u16> {
        let mut taken = pool_ports();
        taken.extend(external_used_ports());
        taken.extend(
            self.inner
                .manager
                .tunnels()
                .await
                .into_iter()
                .map(|tunnel| tunnel.port),
        );
        let state = lock_unpoisoned(&self.inner.state);
        taken.extend(state.store.pools.iter().map(|pool| pool.port));
        taken.extend(state.runs.values().map(|run| run.port));
        taken
    }

    async fn race_dial(
        run: &PoolRun,
        candidates: Vec<ResolvedMember>,
        network: DialNetwork,
        addr: &str,
        target: &str,
    ) -> Result<(DialSocket, String)> {
        if candidates.is_empty() {
            bail!("出口组内没有可用出口");
        }
        let (tx, mut rx) = mpsc::channel(candidates.len());
        for member in candidates.iter().cloned() {
            let tx = tx.clone();
            let addr = addr.to_string();
            tokio::spawn(async move {
                let outcome = dial_candidate(&member, network, &addr).await;
                let _ = tx.send(outcome).await;
            });
        }
        drop(tx);

        let mut first_error = None;
        for index in 0..candidates.len() {
            let Some(outcome) = rx.recv().await else {
                break;
            };
            match outcome.result {
                Ok(socket) => {
                    run.note_success(target, &outcome.host, outcome.elapsed);
                    let remaining = candidates.len() - index - 1;
                    if remaining != 0 {
                        let runtime = Arc::clone(&run.runtime);
                        let late_target = target.to_string();
                        tokio::spawn(async move {
                            while let Some(late) = rx.recv().await {
                                note_outcome(&runtime, &late, &late_target);
                                if let Ok(socket) = late.result {
                                    drop(socket);
                                }
                            }
                        });
                    }
                    return Ok((socket, outcome.host));
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    run.note_failure(&outcome.host);
                }
            }
        }
        Err(first_error.unwrap_or_else(|| anyhow!("出口组内没有可用出口")))
    }
}

#[derive(Clone)]
struct ResolvedTunnel {
    state: TunnelState,
    dialer: Arc<dyn SocksDialer>,
}

#[derive(Clone)]
struct ResolvedMember {
    member: PoolMember,
    dialer: Option<Arc<dyn SocksDialer>>,
}

struct AttemptOutcome {
    host: String,
    elapsed: Duration,
    result: Result<DialSocket>,
}

fn usable(member: &ResolvedMember) -> bool {
    member.member.up && !member.member.namespace.is_empty() && member.dialer.is_some()
}

async fn dial_candidate(
    member: &ResolvedMember,
    network: DialNetwork,
    addr: &str,
) -> AttemptOutcome {
    let started = Instant::now();
    let host = member.member.host.clone();
    let result = async {
        let dialer = member
            .dialer
            .as_ref()
            .ok_or_else(|| anyhow!("成员没有可用拨号器"))?;
        let socket = timeout(POOL_TRY_TIMEOUT, dialer.dial(network, addr))
            .await
            .map_err(|_| anyhow!("拨号超时"))??;
        let matches = match (&socket, network) {
            (DialSocket::Tcp(_), DialNetwork::Tcp) | (DialSocket::Udp(_), DialNetwork::Udp) => true,
            _ => false,
        };
        if !matches {
            drop(socket);
            let expected = match network {
                DialNetwork::Tcp => "TcpStream",
                DialNetwork::Udp => "UdpSocket",
            };
            bail!("拨号返回的 socket 类型不是 {expected}");
        }
        Ok(socket)
    }
    .await;
    AttemptOutcome {
        host,
        elapsed: started.elapsed(),
        result,
    }
}

fn note_outcome(runtime: &StdMutex<PoolRuntimeState>, outcome: &AttemptOutcome, target: &str) {
    let mut runtime = lock_unpoisoned(runtime);
    match &outcome.result {
        Ok(_) => runtime.note_target_success(target, &outcome.host, outcome.elapsed, Utc::now()),
        Err(_) => runtime.note_failure(&outcome.host, Utc::now()),
    }
}

async fn accept_loop(
    service: PoolService,
    id: String,
    listener: Arc<TcpListener>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (client, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                        ) => continue,
                    Err(error) => {
                        warn!("出口组 {id} 接受连接失败，稍后重试: {error}");
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // Missing pools must be dropped, not served with AUTH_NONE.
                let Some(cred) = service.cred_of(&id) else {
                    drop(client);
                    continue;
                };
                let dialer = service.dialer_for(&id);
                tokio::spawn(async move {
                    if let Err(error) = serve_socks(client, Some(&cred), &dialer).await {
                        debug!("出口组 SOCKS5 连接结束: {error}");
                    }
                });
            }
        }
    }
}

async fn probe_loop(service: PoolService, shutdown: CancellationToken) {
    let mut ticker = interval_at(Instant::now() + POOL_PROBE_INTERVAL, POOL_PROBE_INTERVAL);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                service.probe_stale().await;
            }
        }
    }
}

async fn fill_loop(service: PoolService, shutdown: CancellationToken) {
    let mut ticker = interval_at(Instant::now() + POOL_FILL_INTERVAL, POOL_FILL_INTERVAL);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                service.fill_once().await;
            }
        }
    }
}

async fn listen_pool(port: u16) -> std::io::Result<TcpListener> {
    let mut last_error = None;
    for attempt in 0..LISTEN_ATTEMPTS {
        match TcpListener::bind(SocketAddr::from((LOOPBACK, port))).await {
            Ok(listener) => return Ok(listener),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < LISTEN_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    Err(last_error.expect("at least one listen attempt was made"))
}

async fn free_random_listener(taken: HashSet<u16>) -> std::io::Result<TcpListener> {
    let mut last_error = None;
    for _ in 0..200 {
        let port = RAND_PORT_MIN + rand::random::<u16>() % (RAND_PORT_MAX - RAND_PORT_MIN);
        if taken.contains(&port) {
            continue;
        }
        match TcpListener::bind(SocketAddr::from((LOOPBACK, port))).await {
            Ok(listener) => return Ok(listener),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "找不到可用端口")
    }))
}

fn external_used_ports() -> HashSet<u16> {
    let mut used = HashSet::new();
    let Ok(blob) = fs::read(EXTERNAL_XRAY_CONFIG) else {
        return used;
    };
    let Ok(config) = serde_json::from_slice::<serde_json::Value>(&blob) else {
        return used;
    };
    if let Some(inbounds) = config.get("inbounds").and_then(serde_json::Value::as_array) {
        for inbound in inbounds {
            if let Some(port) = inbound
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .filter(|port| *port > 0 && *port <= u64::from(u16::MAX))
            {
                used.insert(port as u16);
            }
        }
    }
    used
}

#[cfg(test)]
#[path = "pool_service_test.rs"]
mod tests;
