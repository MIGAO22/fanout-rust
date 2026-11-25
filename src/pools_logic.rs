use crate::models::{self, Pool, PoolMemberView, PoolStore, PoolView, SocksCred, TunnelState};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use crate::models::{POOL_DEFAULT_RR_STEP, POOL_MAX_HOSTS, POOL_MODES};

pub const POOL_MODE_SINGLE: &str = "single";
pub const POOL_MODE_ROUND_ROBIN: &str = "roundrobin";
pub const POOL_MODE_BALANCE: &str = "balance";
pub const POOL_MODE_CONCURRENT: &str = "concurrent";
// The Rust UI already uses these two spellings. Accept them without rewriting
// stored JSON, while treating them as the Go policies during selection.
pub const POOL_MODE_LATENCY: &str = "latency";
pub const POOL_MODE_RACE: &str = "race";
pub const GO_POOL_MODES: &[&str] = &[
    POOL_MODE_SINGLE,
    POOL_MODE_ROUND_ROBIN,
    POOL_MODE_BALANCE,
    POOL_MODE_CONCURRENT,
];

pub const POOL_TAG_PREFIX: &str = "pool-";
pub const POOL_MAX_RR_STEP: usize = 1000;
pub const POOL_TRY_TIMEOUT: Duration = Duration::from_secs(8);
pub const POOL_AFFINITY_MAX: usize = 4096;
pub const POOL_SWITCH_FLOOR: Duration = Duration::from_millis(600);
pub const POOL_SWITCH_RATIO: u32 = 2;
pub const POOL_EWMA_ALPHA: f64 = 0.3;
pub const POOL_COOL_BASE: Duration = Duration::from_secs(10);
pub const POOL_COOL_MAX: Duration = Duration::from_secs(180);
pub const POOL_PROBE_INTERVAL: Duration = Duration::from_secs(20);
pub const POOL_PROBE_STALE: Duration = Duration::from_secs(120);
pub const POOL_PROBE_TARGET: &str = "1.1.1.1:443";

pub const POOL_FILL_INTERVAL: Duration = Duration::from_secs(10);
pub const POOL_FILL_DEAD_AFTER: Duration = Duration::from_secs(90);
pub const POOL_FILL_SLOT_FLOOR: usize = 2;
pub const POOL_FILL_PENALTY: Duration = Duration::from_secs(600);
pub const POOL_MAX_SIZE: usize = POOL_MAX_HOSTS;

/// Returns the canonical Go policy spelling. Rust's `latency` and `race`
/// aliases are intentionally accepted alongside `balance` and `concurrent`.
pub fn canonical_pool_mode(mode: &str) -> Option<&'static str> {
    match mode {
        POOL_MODE_SINGLE => Some(POOL_MODE_SINGLE),
        POOL_MODE_ROUND_ROBIN => Some(POOL_MODE_ROUND_ROBIN),
        POOL_MODE_BALANCE | POOL_MODE_LATENCY => Some(POOL_MODE_BALANCE),
        POOL_MODE_CONCURRENT | POOL_MODE_RACE => Some(POOL_MODE_CONCURRENT),
        _ => None,
    }
}

pub fn valid_pool_mode(mode: &str) -> bool {
    canonical_pool_mode(mode).is_some()
}

impl Pool {
    pub fn identity(&self) -> String {
        format!("{POOL_TAG_PREFIX}{}", self.id)
    }

    /// Normalizes user input while preserving a valid stored mode spelling.
    pub fn normalize(&mut self) {
        if !valid_pool_mode(&self.mode) {
            self.mode = POOL_MODE_SINGLE.to_string();
        }
        self.rr_step = self.rr_step.clamp(POOL_DEFAULT_RR_STEP, POOL_MAX_RR_STEP);

        let mut seen = HashSet::with_capacity(self.hosts.len());
        let mut hosts = Vec::with_capacity(self.hosts.len());
        for host in &self.hosts {
            let host = host.trim();
            if host.is_empty() || !seen.insert(host.to_string()) {
                continue;
            }
            hosts.push(host.to_string());
        }
        self.hosts = hosts;

        self.size = self.size.min(POOL_MAX_SIZE);
        if self.auto_fill && self.size < 1 {
            self.size = self.hosts.len();
        }
        if self.name.trim().is_empty() {
            self.name = format!("出口组 {}", self.id);
        }
        self.name = self.name.trim().to_string();
    }

    pub fn validate(&self) -> Result<()> {
        if self.hosts.is_empty() {
            anyhow::bail!("出口组至少要选一个出口");
        }
        if self.hosts.len() > POOL_MAX_SIZE {
            anyhow::bail!("一个出口组最多 32 个出口");
        }
        // Go's len(string) counts bytes, not Unicode scalar values.
        if self.name.len() > 64 {
            anyhow::bail!("组名最长 64 个字符");
        }
        Ok(())
    }
}

pub fn pool_identity_to_id(identity: &str) -> Option<String> {
    let id = identity.strip_prefix(POOL_TAG_PREFIX)?;
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

pub fn pool_state_path(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join("pools.json")
}

/// Extracts the sequence from IDs such as `p12`. Invalid IDs and overflows
/// are treated as sequence zero.
pub fn parse_pool_seq(id: &str) -> u64 {
    let Some(digits) = id.strip_prefix('p') else {
        return 0;
    };
    if digits.is_empty() {
        return 0;
    }
    digits
        .bytes()
        .try_fold(0u64, |n, b| {
            if !b.is_ascii_digit() {
                return None;
            }
            n.checked_mul(10)?.checked_add(u64::from(b - b'0'))
        })
        .unwrap_or(0)
}

impl PoolStore {
    pub fn new() -> Self {
        Self {
            next: 1,
            pools: Vec::new(),
        }
    }

    pub fn get(&self, id: &str) -> Option<&Pool> {
        self.pools.iter().find(|pool| pool.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Pool> {
        self.pools.iter_mut().find(|pool| pool.id == id)
    }

    /// Sorts by display name and then numeric pool sequence, without
    /// reordering the store itself.
    pub fn sorted(&self) -> Vec<&Pool> {
        let mut pools: Vec<&Pool> = self.pools.iter().collect();
        pools.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| parse_pool_seq(&a.id).cmp(&parse_pool_seq(&b.id)))
        });
        pools
    }

    /// Applies an autofill member swap in memory. The caller persists the
    /// store only when `Ok(true)` is returned. An already-present new host is
    /// a successful no-op, matching the Go service.
    pub fn swap_member(&mut self, id: &str, old_host: &str, new_host: &str) -> Result<bool> {
        let pool = self
            .get_mut(id)
            .ok_or_else(|| anyhow!("出口组 {} 已不存在", id))?;
        if pool.hosts.iter().any(|host| host == new_host) {
            return Ok(false);
        }
        if !old_host.is_empty() {
            if let Some(index) = pool.hosts.iter().position(|host| host == old_host) {
                pool.hosts[index] = new_host.to_string();
                return Ok(true);
            }
        }
        pool.hosts.push(new_host.to_string());
        Ok(true)
    }

    pub fn save(&self, dir: impl AsRef<Path>) -> Result<()> {
        let path = pool_state_path(dir);
        let blob = serde_json::to_vec_pretty(self).context("序列化出口组存档失败")?;
        crate::util::atomic_write(&path, &blob, 0o600)
            .with_context(|| format!("保存 {} 失败", path.display()))
    }
}

// The existing public models use usize/u16. This wire mirror retains Go's
// zero-value behavior for missing/null fields and accepts negative integers
// so normalize can apply the same defaults and clamps as the Go loader.
#[derive(Default, Deserialize)]
#[serde(default)]
struct StoredCred {
    user: Option<String>,
    pass: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct StoredPool {
    id: Option<String>,
    name: Option<String>,
    mode: Option<String>,
    hosts: Option<Vec<String>>,
    rr_step: Option<i64>,
    port: Option<i64>,
    cred: Option<StoredCred>,
    auto_fill: Option<bool>,
    size: Option<i64>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct StoredPoolStore {
    next: Option<i64>,
    pools: Option<Vec<StoredPool>>,
}

fn go_usize(value: Option<i64>) -> usize {
    usize::try_from(value.unwrap_or(0).max(0)).unwrap_or(usize::MAX)
}

fn go_u64(value: Option<i64>) -> u64 {
    u64::try_from(value.unwrap_or(0).max(0)).unwrap_or(u64::MAX)
}

fn go_port(value: Option<i64>) -> u16 {
    value.unwrap_or(0).clamp(0, i64::from(u16::MAX)) as u16
}

impl From<StoredPool> for Pool {
    fn from(stored: StoredPool) -> Self {
        let cred = stored.cred.unwrap_or_default();
        let mut pool = Pool {
            id: stored.id.unwrap_or_default(),
            name: stored.name.unwrap_or_default(),
            mode: stored.mode.unwrap_or_default(),
            hosts: stored.hosts.unwrap_or_default(),
            rr_step: go_usize(stored.rr_step),
            port: go_port(stored.port),
            cred: SocksCred {
                user: cred.user.unwrap_or_default(),
                pass: cred.pass.unwrap_or_default(),
            },
            auto_fill: stored.auto_fill.unwrap_or(false),
            size: go_usize(stored.size),
        };
        pool.normalize();
        pool
    }
}

pub fn load_pool_store(dir: impl AsRef<Path>) -> Result<PoolStore> {
    let path = pool_state_path(dir);
    let blob = match fs::read(&path) {
        Ok(blob) => blob,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(PoolStore::new()),
        Err(error) => return Err(error).with_context(|| format!("读取 {} 失败", path.display())),
    };
    let stored: Option<StoredPoolStore> =
        serde_json::from_slice(&blob).with_context(|| format!("解析 {} 失败", path.display()))?;
    let stored = stored.unwrap_or_default();
    let pools = stored.pools.unwrap_or_default();
    let mut store = PoolStore {
        next: go_u64(stored.next),
        pools: pools.into_iter().map(Pool::from).collect(),
    };
    let highest = store
        .pools
        .iter()
        .map(|pool| parse_pool_seq(&pool.id))
        .max()
        .unwrap_or(0);
    store.next = store.next.max(highest.saturating_add(1)).max(1);
    Ok(store)
}

/// A resolved runtime snapshot of one configured pool member.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolMember {
    pub host: String,
    pub namespace: String,
    pub slot: usize,
    pub exit_ip: String,
    pub up: bool,
    pub status: String,
    /// Zero means that no latency sample exists.
    pub latency: Duration,
    pub cooling: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolChoice {
    /// Priority order for sequential attempts, or the full race set when
    /// `concurrent` is true.
    pub order: Vec<PoolMember>,
    pub concurrent: bool,
}

/// Cross-connection selection state. The future listener/service should call
/// `pick` while holding its own lock; this type deliberately has no I/O.
#[derive(Clone, Debug)]
pub struct PoolPolicy {
    pub mode: String,
    pub step: usize,
    current: String,
    cursor: usize,
    affinity: HashMap<String, String>,
    affinity_order: Vec<String>,
}

impl PoolPolicy {
    pub fn new(mode: &str, step: usize) -> Self {
        Self {
            mode: mode.to_string(),
            step: if step < 1 { POOL_DEFAULT_RR_STEP } else { step },
            current: String::new(),
            cursor: 0,
            affinity: HashMap::new(),
            affinity_order: Vec::new(),
        }
    }

    pub fn pick(&mut self, target: &str, members: &[PoolMember]) -> PoolChoice {
        let mut available = Vec::with_capacity(members.len());
        let mut cold = Vec::with_capacity(members.len());
        for member in members {
            if !member.up {
                continue;
            }
            if member.cooling {
                cold.push(member.clone());
            } else {
                available.push(member.clone());
            }
        }
        if available.is_empty() {
            available = cold;
            cold = Vec::new();
        }
        if available.is_empty() {
            return PoolChoice::default();
        }

        let with_cold = |chosen: &str| {
            let mut order = put_first(&available, chosen);
            order.extend(cold.iter().cloned());
            order
        };
        let mode = canonical_pool_mode(&self.mode);

        if mode == Some(POOL_MODE_CONCURRENT) {
            return PoolChoice {
                order: available.clone(),
                concurrent: true,
            };
        }
        if mode == Some(POOL_MODE_SINGLE) {
            if !self.current.is_empty() && member_of(&available, &self.current).is_some() {
                return PoolChoice {
                    order: with_cold(&self.current),
                    concurrent: false,
                };
            }
            self.current = available[0].host.clone();
            return PoolChoice {
                order: with_cold(&self.current),
                concurrent: false,
            };
        }

        if let Some(host) = self.affinity.get(target).cloned() {
            if let Some(member) = member_of(&available, &host) {
                if self.still_sticky(member, &available) {
                    return PoolChoice {
                        order: with_cold(&host),
                        concurrent: false,
                    };
                }
            }
            self.affinity.remove(target);
        }

        let chosen = if mode == Some(POOL_MODE_BALANCE) {
            best_by_latency(&available)
                .map(|member| member.host)
                .unwrap_or_else(|| available[0].host.clone())
        } else {
            let step = self.step.max(POOL_DEFAULT_RR_STEP);
            let index = (self.cursor / step) % available.len();
            let host = available[index].host.clone();
            self.cursor = self.cursor.wrapping_add(1);
            host
        };
        self.bind(target, &chosen);
        PoolChoice {
            order: with_cold(&chosen),
            concurrent: false,
        }
    }

    fn still_sticky(&self, member: &PoolMember, available: &[PoolMember]) -> bool {
        if canonical_pool_mode(&self.mode) != Some(POOL_MODE_BALANCE) {
            return true;
        }
        if member.latency.is_zero() {
            return true;
        }
        let Some(best) = best_by_latency(available) else {
            return true;
        };
        if best.latency.is_zero() {
            return true;
        }
        member.latency <= POOL_SWITCH_FLOOR
            || member.latency.as_nanos()
                <= best
                    .latency
                    .as_nanos()
                    .saturating_mul(u128::from(POOL_SWITCH_RATIO))
    }

    fn bind(&mut self, target: &str, host: &str) {
        if !self.affinity.contains_key(target) {
            if self.affinity.len() >= POOL_AFFINITY_MAX && !self.affinity_order.is_empty() {
                let oldest = self.affinity_order.remove(0);
                self.affinity.remove(&oldest);
            }
            self.affinity_order.push(target.to_string());
        }
        self.affinity.insert(target.to_string(), host.to_string());
    }

    pub fn forget_member(&mut self, host: &str) {
        self.affinity.retain(|_, bound| bound.as_str() != host);
        let affinity = &self.affinity;
        self.affinity_order
            .retain(|target| affinity.contains_key(target));
        if self.current == host {
            self.current.clear();
        }
    }

    /// Mirrors policy replacement on config edits: retain target affinity,
    /// but reset single-mode stickiness and the round-robin cursor.
    pub fn reconfigure(&mut self, mode: &str, step: usize) {
        self.mode = mode.to_string();
        self.step = if step < 1 { POOL_DEFAULT_RR_STEP } else { step };
        self.current.clear();
        self.cursor = 0;
    }

    pub fn affinity(&self) -> &HashMap<String, String> {
        &self.affinity
    }

    pub fn affinity_order(&self) -> &[String] {
        &self.affinity_order
    }

    pub fn current_host(&self) -> &str {
        &self.current
    }
}

pub fn member_of<'a>(members: &'a [PoolMember], host: &str) -> Option<&'a PoolMember> {
    members.iter().find(|member| member.host == host)
}

pub fn put_first(members: &[PoolMember], host: &str) -> Vec<PoolMember> {
    let mut out = Vec::with_capacity(members.len());
    if let Some(member) = member_of(members, host) {
        out.push(member.clone());
    }
    out.extend(members.iter().filter(|member| member.host != host).cloned());
    out
}

/// Unknown (zero) samples sort before measured samples; measured samples sort
/// by latency. Equal samples retain their input order.
pub fn best_by_latency(members: &[PoolMember]) -> Option<PoolMember> {
    let mut sorted = members.to_vec();
    sorted.sort_by(|a, b| match (a.latency.is_zero(), b.latency.is_zero()) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.latency.cmp(&b.latency),
    });
    sorted.into_iter().next()
}

/// Performs the host-only parsing done by Go's net.SplitHostPort, without DNS
/// resolution or numeric-port validation.
pub fn target_key(addr: &str) -> String {
    if let Some(rest) = addr.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return addr.to_string();
        };
        let after = &rest[end + 1..];
        if after.starts_with(':') && !after[1..].contains(':') {
            return rest[..end].to_string();
        }
        return addr.to_string();
    }

    match addr.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !port.contains(':') => host.to_string(),
        _ => addr.to_string(),
    }
}

pub fn ewma_latency(previous: Duration, sample: Duration) -> Duration {
    if previous.is_zero() {
        return sample;
    }
    let nanos = POOL_EWMA_ALPHA * sample.as_nanos() as f64
        + (1.0 - POOL_EWMA_ALPHA) * previous.as_nanos() as f64;
    Duration::from_nanos(nanos as u64)
}

/// The Go implementation shifts the base by the failure count, so the first
/// failure cools for 20 seconds; the result is capped at three minutes.
pub fn cooldown_for_failures(failures: u32) -> Duration {
    let multiplier = 1u32 << failures.min(5);
    POOL_COOL_BASE.saturating_mul(multiplier).min(POOL_COOL_MAX)
}

#[derive(Clone, Debug, Default)]
pub struct MemberStat {
    pub latency: Duration,
    pub failures: u32,
    pub cooling_until: Option<DateTime<Utc>>,
    pub probed_at: Option<DateTime<Utc>>,
}

impl MemberStat {
    pub fn note_ok(&mut self, sample: Duration, now: DateTime<Utc>) {
        self.latency = ewma_latency(self.latency, sample);
        self.failures = self.failures.saturating_sub(1);
        self.cooling_until = None;
        self.probed_at = Some(now);
    }

    pub fn note_fail(&mut self, now: DateTime<Utc>) {
        self.failures = self.failures.saturating_add(1);
        self.cooling_until =
            Some(now + ChronoDuration::from_std(cooldown_for_failures(self.failures)).unwrap());
    }

    pub fn is_cooling(&self, now: DateTime<Utc>) -> bool {
        self.failures > 0 && self.cooling_until.is_some_and(|until| now < until)
    }

    pub fn is_stale(&self, now: DateTime<Utc>) -> bool {
        self.latency.is_zero()
            || self.probed_at.is_none_or(|probed| {
                now.signed_duration_since(probed)
                    > ChronoDuration::from_std(POOL_PROBE_STALE).unwrap()
            })
    }
}

/// Pure per-pool runtime state. Network dialing, probing, and locking remain
/// the responsibility of the later listener/service integration.
#[derive(Clone, Debug)]
pub struct PoolRuntimeState {
    pub policy: PoolPolicy,
    pub stats: HashMap<String, MemberStat>,
}

impl PoolRuntimeState {
    pub fn new(mode: &str, step: usize) -> Self {
        Self {
            policy: PoolPolicy::new(mode, step),
            stats: HashMap::new(),
        }
    }

    pub fn note_success(&mut self, host: &str, sample: Duration, now: DateTime<Utc>) {
        self.stats
            .entry(host.to_string())
            .or_default()
            .note_ok(sample, now);
    }

    pub fn note_failure(&mut self, host: &str, now: DateTime<Utc>) {
        self.stats
            .entry(host.to_string())
            .or_default()
            .note_fail(now);
        self.policy.forget_member(host);
    }

    pub fn apply_state(&self, members: &mut [PoolMember], now: DateTime<Utc>) {
        for member in members {
            if let Some(stat) = self.stats.get(&member.host) {
                member.latency = stat.latency;
                member.cooling = stat.is_cooling(now);
            } else {
                member.latency = Duration::ZERO;
                member.cooling = false;
            }
        }
    }

    pub fn needs_probe(&self, mode: &str, member: &PoolMember, now: DateTime<Utc>) -> bool {
        if !matches!(
            canonical_pool_mode(mode),
            Some(POOL_MODE_SINGLE) | Some(POOL_MODE_BALANCE)
        ) || !member.up
            || member.namespace.is_empty()
        {
            return false;
        }
        self.stats
            .get(&member.host)
            .is_none_or(|stat| stat.is_stale(now))
    }
}

pub fn pool_member_view(member: &PoolMember, aead: bool) -> PoolMemberView {
    let latency_ms = u64::try_from(member.latency.as_millis())
        .unwrap_or(i64::MAX as u64)
        .min(i64::MAX as u64) as i64;
    PoolMemberView {
        host: member.host.clone(),
        slot: member.slot,
        status: if member.status.is_empty() {
            "missing".to_string()
        } else {
            member.status.clone()
        },
        exit_ip: member.exit_ip.clone(),
        latency_ms,
        cooling: member.cooling,
        aead,
    }
}

/// Projects a pool and resolved member snapshots into the existing UI model.
/// Panel inbounds can be attached to the returned view by the integration.
pub fn pool_view(
    pool: &Pool,
    members: &[PoolMember],
    running: bool,
    fill_note: Option<&str>,
    aead_hosts: &HashSet<String>,
) -> PoolView {
    let ui_mode = match canonical_pool_mode(&pool.mode) {
        Some(POOL_MODE_BALANCE) => POOL_MODE_LATENCY,
        Some(POOL_MODE_CONCURRENT) => POOL_MODE_RACE,
        _ => pool.mode.as_str(),
    };
    PoolView {
        id: pool.id.clone(),
        identity: pool.identity(),
        name: pool.name.clone(),
        mode: pool.mode.clone(),
        mode_label: models::pool_mode_label(ui_mode).to_string(),
        mode_desc: models::pool_mode_desc(ui_mode).to_string(),
        rr_step: pool.rr_step,
        port: pool.port,
        running,
        up: members.iter().filter(|member| member.up).count(),
        total: members.len(),
        socks_user: pool.cred.user.clone(),
        socks_pass: pool.cred.pass.clone(),
        cred: pool.cred.clone(),
        members: members
            .iter()
            .map(|member| pool_member_view(member, aead_hosts.contains(&member.host)))
            .collect(),
        inbounds: Vec::new(),
        auto_fill: pool.auto_fill,
        size: pool.size,
        fill_note: fill_note.unwrap_or("").to_string(),
    }
}

fn elapsed_at_least(start: DateTime<Utc>, now: DateTime<Utc>, after: Duration) -> bool {
    now.signed_duration_since(start)
        .to_std()
        .is_ok_and(|elapsed| elapsed >= after)
}

/// Classifies members and updates the per-group first-failure ledger in place.
/// `gone` retains configured member order so replacements stay in place.
pub fn pool_gone_hosts(
    members: &[PoolMember],
    first_dead: &mut HashMap<String, DateTime<Utc>>,
    after: Duration,
    now: DateTime<Utc>,
) -> (usize, Vec<String>) {
    let mut live = 0;
    let mut gone = Vec::new();
    for member in members {
        if member.up {
            first_dead.remove(&member.host);
            live += 1;
            continue;
        }
        if member.namespace.is_empty() || member.status == "failed" || member.status == "stopped" {
            gone.push(member.host.clone());
            first_dead.remove(&member.host);
            continue;
        }
        match first_dead.get(&member.host).copied() {
            Some(first) if elapsed_at_least(first, now, after) => gone.push(member.host.clone()),
            Some(_) => {}
            None => {
                first_dead.insert(member.host.clone(), now);
            }
        }
    }
    (live, gone)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolFillCand {
    pub host: String,
    pub online: bool,
    pub shared: bool,
}

/// Prefers online spares, then online members shared with other pools.
pub fn pool_reuse_pick(candidates: &[PoolFillCand], need: usize) -> Vec<String> {
    if need == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(need.min(candidates.len()));
    for want_spare in [true, false] {
        for candidate in candidates {
            if out.len() >= need {
                return out;
            }
            if candidate.online && candidate.shared != want_spare {
                out.push(candidate.host.clone());
            }
        }
    }
    out
}

/// Builds reuse candidates while excluding this pool's members and nodes
/// still serving an autofill failure penalty. Offline exits remain in the
/// result with `online=false`, matching the Go candidate snapshot.
pub fn fill_candidates(
    pools: &[Pool],
    id: &str,
    tunnels: &[TunnelState],
    bad_until: &HashMap<String, DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Vec<PoolFillCand> {
    let mut in_pool = HashSet::new();
    let mut shared = HashSet::new();
    for pool in pools {
        for host in &pool.hosts {
            shared.insert(host.clone());
            if pool.id == id {
                in_pool.insert(host.clone());
            }
        }
    }

    tunnels
        .iter()
        .filter_map(|tunnel| {
            let host = tunnel.node.hostname.clone();
            if host.is_empty()
                || in_pool.contains(&host)
                || bad_until.get(&host).is_some_and(|until| now < *until)
            {
                return None;
            }
            Some(PoolFillCand {
                host,
                online: tunnel.status == "up",
                shared: shared.contains(&tunnel.node.hostname),
            })
        })
        .collect()
}

pub fn fill_avoid(
    members: &[PoolMember],
    bad_until: &HashMap<String, DateTime<Utc>>,
    now: DateTime<Utc>,
) -> HashSet<String> {
    let mut avoid: HashSet<String> = bad_until
        .iter()
        .filter_map(|(host, until)| (now < *until).then(|| host.clone()))
        .collect();
    avoid.extend(members.iter().map(|member| member.host.clone()));
    avoid
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillAssessment {
    pub live: usize,
    pub short: usize,
    /// Number of replacements/additions allowed this round. Members still in
    /// their reconnect window never contribute a replacement slot.
    pub need: usize,
    pub gone: Vec<String>,
    pub note: Option<String>,
}

/// Computes the pure decision made before any reuse/create side effects.
/// Call this only for AutoFill-enabled pools. Pass a per-pool ledger snapshot
/// and replace that ledger after this call.
pub fn assess_pool_fill(
    pool: &Pool,
    members: &[PoolMember],
    first_dead: &mut HashMap<String, DateTime<Utc>>,
    now: DateTime<Utc>,
) -> FillAssessment {
    let (live, gone) = pool_gone_hosts(members, first_dead, POOL_FILL_DEAD_AFTER, now);
    let short = pool.size.saturating_sub(live);
    if short == 0 {
        return FillAssessment {
            live,
            short,
            need: 0,
            gone,
            note: None,
        };
    }
    let growth = pool.size.saturating_sub(members.len());
    let need = short.min(gone.len().saturating_add(growth));
    FillAssessment {
        live,
        short,
        need,
        note: if need == 0 {
            Some(waiting_note(short))
        } else {
            None
        },
        gone,
    }
}

pub fn waiting_note(count: usize) -> String {
    format!(
        "另有 {count} 条正在自动重连，等满 {} 秒没回来才顶替",
        POOL_FILL_DEAD_AFTER.as_secs()
    )
}

/// `None` means this is a net-new slot rather than a replacement.
pub fn fill_slot(gone: &[String], index: usize) -> Option<&str> {
    gone.get(index).map(String::as_str)
}

/// Number of new exits this round may create while preserving the slot floor.
pub fn creation_room(slot_headroom: usize) -> usize {
    slot_headroom.saturating_sub(POOL_FILL_SLOT_FLOOR)
}

pub fn fill_failure_reason(host: &str) -> String {
    format!(
        "试了 {host} 还是连不上（冷却 {} 分钟）",
        POOL_FILL_PENALTY.as_secs() / 60
    )
}

/// Produces the final UI note after reuse/create attempts. `reused` and
/// `created` count successes only; failed attempts must be penalized and
/// supply a reason through `PoolFillState` / `fill_failure_reason`.
pub fn fill_completion_note(
    pool: &Pool,
    assessment: &FillAssessment,
    reused: usize,
    created: usize,
    reason: Option<String>,
) -> Option<String> {
    let filled = reused.saturating_add(created);
    let leftover = pool
        .size
        .saturating_sub(assessment.live)
        .saturating_sub(filled);
    if leftover == 0 {
        return None;
    }
    let creation_need = assessment.need.saturating_sub(reused);
    let reason = reason
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| {
            if created < creation_need {
                format!("在线出口都用上了，新建又受槽位限制（要留 {POOL_FILL_SLOT_FLOOR} 个余量）")
            } else {
                String::new()
            }
        });
    if reason.is_empty() {
        Some(waiting_note(leftover))
    } else {
        Some(format!("已顶回 {filled} 条，还差 {leftover} 条：{reason}"))
    }
}

/// Persistent-in-memory ledgers needed by the future autofill service.
#[derive(Clone, Debug, Default)]
pub struct PoolFillState {
    pub first_dead: HashMap<String, HashMap<String, DateTime<Utc>>>,
    pub bad_until: HashMap<String, DateTime<Utc>>,
    pub notes: HashMap<String, String>,
    pub filling: bool,
}

impl PoolFillState {
    pub fn begin_fill(&mut self) -> bool {
        if self.filling {
            false
        } else {
            self.filling = true;
            true
        }
    }

    pub fn finish_fill(&mut self) {
        self.filling = false;
    }

    pub fn dead_snapshot(&self, id: &str) -> HashMap<String, DateTime<Utc>> {
        self.first_dead.get(id).cloned().unwrap_or_default()
    }

    pub fn merge_dead(
        &mut self,
        id: &str,
        ledger: HashMap<String, DateTime<Utc>>,
        store: &PoolStore,
    ) {
        if store.get(id).is_some() {
            self.first_dead.insert(id.to_string(), ledger);
        } else {
            self.first_dead.remove(id);
        }
    }

    pub fn forget_dead(&mut self, id: &str, host: &str) {
        if host.is_empty() {
            return;
        }
        if let Some(ledger) = self.first_dead.get_mut(id) {
            ledger.remove(host);
        }
    }

    pub fn drop_ledger(&mut self, id: &str) {
        self.first_dead.remove(id);
        self.notes.remove(id);
    }

    pub fn set_note(&mut self, id: &str, note: Option<String>) {
        match note.filter(|note| !note.is_empty()) {
            Some(note) => {
                self.notes.insert(id.to_string(), note);
            }
            None => {
                self.notes.remove(id);
            }
        }
    }

    pub fn notes(&self) -> HashMap<String, String> {
        self.notes.clone()
    }

    pub fn mark_bad(&mut self, host: &str, now: DateTime<Utc>) {
        self.bad_until.insert(
            host.to_string(),
            now + ChronoDuration::from_std(POOL_FILL_PENALTY).unwrap(),
        );
    }

    pub fn prune_bad(&mut self, now: DateTime<Utc>) {
        self.bad_until.retain(|_, until| now <= *until);
    }
}

pub fn host_in_pool(pools: &[Pool], host: &str) -> bool {
    pools
        .iter()
        .any(|pool| pool.hosts.iter().any(|member| member == host))
}

/// Pure retirement safeguard. `inbound_bound=None` means the backend could
/// not answer, which must keep the tunnel just like a positive binding.
pub fn retire_slot(
    host: &str,
    tunnel: Option<&TunnelState>,
    used_by_pool: bool,
    inbound_bound: Option<bool>,
) -> Option<usize> {
    if host.is_empty() || used_by_pool || inbound_bound != Some(false) {
        return None;
    }
    let tunnel = tunnel?;
    if tunnel.status == "up" {
        return None;
    }
    Some(tunnel.slot)
}

#[cfg(test)]
#[path = "pools_logic_test.rs"]
mod tests;
