use anyhow::{anyhow, Result};
use chrono::Utc;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock, Semaphore};

use crate::{
    config::WebSettings,
    jobs::{JobHandle, JobStore},
    models::{Exit, Node, PersistedTunnel, RegionStat, SocksCred, TunnelState, MAX_EXITS},
    nodecache::NodeCache,
    nodes::{country_label, fetch_nodes_via_socks, new_socks_cred, node_label, order_candidates},
    panel::Panel,
    pool_service::PoolService,
    runtime::{TunnelFactory, TunnelRuntime},
    state::{load_state, save_state, StateFile},
    util::{one_line, random_token},
    warp_runtime::WarpService,
};

pub struct TunnelInner {
    pub node: Node,
    pub status: String,
    pub exit_ip: String,
    pub err: String,
    pub since: chrono::DateTime<Utc>,
    pub prev_host: Option<String>,
    pub avoid: Vec<String>,
}

pub struct Tunnel {
    pub slot: usize,
    pub port: u16,
    pub cred: RwLock<SocksCred>,
    pub runtime: Arc<dyn TunnelRuntime>,
    pub inner: Mutex<TunnelInner>,
    generation: AtomicU64,
    run_lock: Mutex<()>,
}

impl Tunnel {
    fn new(
        slot: usize,
        port: u16,
        cred: SocksCred,
        node: Node,
        runtime: Arc<dyn TunnelRuntime>,
    ) -> Arc<Self> {
        Arc::new(Self {
            slot,
            port,
            cred: RwLock::new(cred),
            runtime,
            inner: Mutex::new(TunnelInner {
                node,
                status: "starting".into(),
                exit_ip: String::new(),
                err: String::new(),
                since: Utc::now(),
                prev_host: None,
                avoid: Vec::new(),
            }),
            generation: AtomicU64::new(0),
            run_lock: Mutex::new(()),
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn bump_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub async fn state(&self) -> TunnelState {
        let i = self.inner.lock().await;
        TunnelState {
            slot: self.slot,
            port: self.port,
            node: i.node.clone(),
            status: i.status.clone(),
            exit_ip: i.exit_ip.clone(),
            err: i.err.clone(),
            since: i.since,
            cred: self.cred.read().await.clone(),
        }
    }

    pub async fn state_if_host(&self, hosts: &HashSet<&str>) -> Option<TunnelState> {
        let i = self.inner.lock().await;
        if !hosts.contains(i.node.hostname.as_str()) {
            return None;
        }
        Some(TunnelState {
            slot: self.slot,
            port: self.port,
            node: i.node.clone(),
            status: i.status.clone(),
            exit_ip: i.exit_ip.clone(),
            err: i.err.clone(),
            since: i.since,
            cred: self.cred.read().await.clone(),
        })
    }

    pub async fn persisted(&self) -> PersistedTunnel {
        let i = self.inner.lock().await;
        let cred = self.cred.read().await.clone();
        PersistedTunnel {
            slot: self.slot,
            port: self.port,
            hostname: i.node.hostname.clone(),
            country_code: i.node.country_code.clone(),
            country: i.node.country.clone(),
            config: i.node.config.clone(),
            socks_user: Some(cred.user),
            socks_pass: Some(cred.pass),
            prev_host: i.prev_host.clone(),
        }
    }

    pub async fn set_node(&self, node: Node) {
        self.inner.lock().await.node = node;
    }

    pub async fn set_status(&self, status: &str, err: &str) {
        let mut i = self.inner.lock().await;
        i.status = status.into();
        i.err = one_line(err, 500);
        if status == "up" {
            i.since = Utc::now();
        }
    }

    pub async fn set_up(&self, ip: String) {
        let mut i = self.inner.lock().await;
        i.status = "up".into();
        i.exit_ip = ip;
        i.err.clear();
        i.avoid.clear();
        i.since = Utc::now();
    }

    pub async fn host(&self) -> String {
        self.inner.lock().await.node.hostname.clone()
    }

    pub async fn node(&self) -> Node {
        self.inner.lock().await.node.clone()
    }

    pub async fn status(&self) -> String {
        self.inner.lock().await.status.clone()
    }

    pub async fn exit_ip(&self) -> String {
        self.inner.lock().await.exit_ip.clone()
    }
}

#[derive(Clone, Default)]
pub struct ProvisionRequest {
    pub region: String,
    pub count: usize,
    pub template_id: usize,
    pub every_region: bool,
}

#[derive(Clone)]
pub struct Manager {
    pub dir: PathBuf,
    pub max_slots: usize,
    pub settings: Arc<RwLock<WebSettings>>,
    pub nodes: NodeCache,
    pub jobs: Arc<JobStore>,
    factory: Arc<dyn TunnelFactory>,
    pub tunnels: Arc<Mutex<HashMap<usize, Arc<Tunnel>>>>,
    allocate: Arc<Mutex<()>>,
    panel: std::sync::OnceLock<Arc<dyn Panel>>,
}

impl Manager {
    pub fn new(
        dir: PathBuf,
        max_slots: usize,
        settings: Arc<RwLock<WebSettings>>,
        jobs: Arc<JobStore>,
        factory: Arc<dyn TunnelFactory>,
    ) -> Arc<Self> {
        Arc::new(Self {
            dir,
            max_slots,
            settings,
            nodes: NodeCache::default(),
            jobs,
            factory,
            tunnels: Arc::new(Mutex::new(HashMap::new())),
            allocate: Arc::new(Mutex::new(())),
            panel: std::sync::OnceLock::new(),
        })
    }

    pub fn set_panel(&self, panel: Arc<dyn Panel>) {
        let _ = self.panel.set(panel);
    }

    pub fn panel(&self) -> Option<Arc<dyn Panel>> {
        self.panel.get().cloned()
    }

    pub fn exit_limit(&self) -> usize {
        self.max_slots.min(MAX_EXITS)
    }

    pub async fn settings(&self) -> WebSettings {
        self.settings.read().await.clone()
    }

    pub async fn update_settings(&self, next: WebSettings) -> Result<()> {
        let next = next.normalized();
        {
            let _file_guard = crate::config::settings_file_lock()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            crate::config::save_settings(&self.dir, &next)?;
        }
        *self.settings.write().await = next;
        Ok(())
    }

    pub async fn tunnels(&self) -> Vec<Arc<Tunnel>> {
        let mut v: Vec<_> = self.tunnels.lock().await.values().cloned().collect();
        v.sort_by_key(|t| t.slot);
        v
    }

    pub async fn states(&self) -> Vec<TunnelState> {
        let mut out = Vec::new();
        for t in self.tunnels().await {
            out.push(t.state().await);
        }
        out
    }

    pub async fn refresh_nodes(&self) -> Result<usize> {
        let s = self.settings().await;
        if let Ok(count) = self
            .nodes
            .refresh(&s.conn.score_mode, s.residential_only())
            .await
        {
            return Ok(count);
        }
        self.refresh_nodes_via_proxies(&s).await
    }

    pub async fn ensure_nodes(&self) -> Result<usize> {
        let s = self.settings().await;
        if let Ok(count) = self
            .nodes
            .ensure(s.conn.node_ttl, &s.conn.score_mode, s.residential_only())
            .await
        {
            return Ok(count);
        }
        self.refresh_nodes_via_proxies(&s).await
    }

    async fn refresh_nodes_via_proxies(&self, settings: &WebSettings) -> Result<usize> {
        let mut last_error = None;
        for tunnel in self.tunnels().await {
            if tunnel.status().await != "up" {
                continue;
            }
            let cred = tunnel.cred.read().await.clone();
            let proxy = format!(
                "socks5h://{}:{}@127.0.0.1:{}",
                cred.user, cred.pass, tunnel.port
            );
            match fetch_nodes_via_socks(&proxy, Duration::from_secs(25), &settings.conn.score_mode)
                .await
            {
                Ok(nodes) => {
                    let count = nodes.len();
                    self.nodes.replace(nodes).await;
                    return Ok(count);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("没有在线出口可用于拉取节点列表")))
    }

    pub async fn node_list(&self, all: bool) -> (Vec<Node>, bool) {
        let fetched = self.nodes.fetched().await;
        let s = self.settings().await;
        let nodes = if all {
            self.nodes.all_nodes().await
        } else {
            self.nodes.nodes(s.residential_only()).await
        };
        (nodes, fetched)
    }

    async fn used_hosts(&self, except: Option<usize>) -> HashSet<String> {
        let mut used = HashSet::new();
        for t in self.tunnels().await {
            if Some(t.slot) == except {
                continue;
            }
            used.insert(t.host().await);
        }
        used
    }

    async fn free_slot_port(&self) -> Result<(usize, u16)> {
        let tunnels = self.tunnels.lock().await;
        let slot = (1..=self.exit_limit())
            .find(|s| !tunnels.contains_key(s))
            .ok_or_else(|| anyhow!("出口总数已达 {} 台上限", self.exit_limit()))?;
        let mut ports: HashSet<u16> = tunnels.values().map(|t| t.port).collect();
        for p in crate::pool_service::pool_ports() {
            ports.insert(p);
        }
        drop(tunnels);
        for _ in 0..200 {
            let p = rand::random::<u16>() % 40000 + 20000;
            if !ports.contains(&p) {
                return Ok((slot, p));
            }
        }
        Err(anyhow!("找不到空闲 SOCKS5 端口"))
    }

    pub async fn start(&self, node: Node) -> Result<Arc<Tunnel>> {
        self.ensure_nodes().await.ok();
        let _allocation = self.allocate.lock().await;
        let (slot, port) = self.free_slot_port().await?;
        let cred = new_socks_cred();
        let runtime = self.factory.create(slot, port, cred.clone(), &self.dir);
        let t = Tunnel::new(slot, port, cred, node, runtime);
        self.tunnels.lock().await.insert(slot, t.clone());
        self.persist().await?;
        let m = self.clone();
        let bg = t.clone();
        tokio::spawn(async move {
            m.bring_up(bg, true, false).await;
        });
        Ok(t)
    }

    pub async fn stop(&self, slot: usize) -> Result<()> {
        let _allocation = self.allocate.lock().await;
        let t = self
            .tunnels
            .lock()
            .await
            .remove(&slot)
            .ok_or_else(|| anyhow!("出口不存在"))?;
        t.bump_generation();
        t.set_status("stopped", "").await;
        let _ = t.runtime.stop().await;
        self.persist().await?;
        self.notify_panel().await;
        Ok(())
    }

    pub async fn set_cred(&self, slot: usize, user: String, pass: String) -> Result<SocksCred> {
        let t = self
            .tunnels
            .lock()
            .await
            .get(&slot)
            .cloned()
            .ok_or_else(|| anyhow!("出口不存在"))?;
        let cred = if user.is_empty() && pass.is_empty() {
            new_socks_cred()
        } else {
            SocksCred { user, pass }
        };
        crate::nodes::validate_cred(&cred)?;
        t.runtime.set_cred(cred.clone()).await?;
        *t.cred.write().await = cred.clone();
        self.persist().await?;
        self.notify_panel().await;
        Ok(cred)
    }

    pub async fn swap(&self, slot: usize) -> Result<()> {
        let t = self
            .tunnels
            .lock()
            .await
            .get(&slot)
            .cloned()
            .ok_or_else(|| anyhow!("出口不存在"))?;
        let old = t.host().await;
        let candidates = self.candidates_for(&t, true).await;
        let next = candidates
            .into_iter()
            .find(|n| n.hostname != old)
            .ok_or_else(|| anyhow!("没有可换的节点"))?;
        t.bump_generation();
        t.set_node(next).await;
        let m = self.clone();
        tokio::spawn(async move {
            m.reconnect(t, old).await;
        });
        Ok(())
    }

    pub async fn reconnect(&self, t: Arc<Tunnel>, old_host: String) {
        t.bump_generation();
        t.set_status("starting", "正在换节点重连").await;
        {
            let mut i = t.inner.lock().await;
            i.exit_ip.clear();
            i.prev_host = Some(old_host.clone());
        }
        self.persist().await.ok();
        let m = self.clone();
        tokio::spawn(async move {
            let _ = t.runtime.stop().await;
            m.bring_up(t.clone(), false, true).await;
            if t.status().await == "up" && t.host().await != old_host {
                if let Some(p) = m.panel.get() {
                    let _ = p.rebind(&old_host, &t.host().await).await;
                }
            }
            let _ = p_resync(&m, &t).await;
        });
    }

    pub async fn replace_warp_failed(
        &self,
        t: Arc<Tunnel>,
        old_host: String,
        warp: Arc<WarpService>,
        pools: Arc<PoolService>,
    ) {
        t.bump_generation();
        t.set_status("starting", "WARP 握手超时，正在清除并更换出口")
            .await;
        {
            let mut i = t.inner.lock().await;
            i.exit_ip.clear();
            i.prev_host = Some(old_host.clone());
            if !i.avoid.contains(&old_host) {
                i.avoid.push(old_host.clone());
            }
        }
        if let Some(next) = self
            .candidates_for(&t, false)
            .await
            .into_iter()
            .find(|node| node.hostname != old_host)
        {
            tracing::info!(
                "隧道 {} WARP 超时，换节点 {} -> {}",
                t.slot,
                old_host,
                next.hostname
            );
            t.set_node(next).await;
        } else {
            tracing::warn!("隧道 {} WARP 超时，但没有其它候选节点", t.slot);
        }
        self.persist().await.ok();
        let m = self.clone();
        tokio::spawn(async move {
            let _ = t.runtime.stop().await;
            if let Err(err) = warp.remove(t.slot).await {
                tracing::warn!("清理隧道 {} 的 WARP 注册失败: {err}", t.slot);
            }
            m.bring_up(t.clone(), false, true).await;
            if t.status().await == "up" && t.host().await != old_host {
                let new_host = t.host().await;
                if let Err(err) = pools.rename_host(&old_host, &new_host).await {
                    tracing::warn!("更新出口组成员 {} -> {} 失败: {err}", old_host, new_host);
                }
                if let Some(p) = m.panel.get() {
                    let _ = p.rebind(&old_host, &new_host).await;
                }
            }
            let _ = p_resync(&m, &t).await;
        });
    }

    async fn avoid_failed(&self, t: &Arc<Tunnel>, host: &str) {
        let max_avoid = self
            .settings()
            .await
            .conn
            .max_tries
            .saturating_mul(2)
            .clamp(4, 64);
        let mut inner = t.inner.lock().await;
        if !inner.avoid.iter().any(|candidate| candidate == host) {
            inner.avoid.push(host.to_string());
        }
        while inner.avoid.len() > max_avoid {
            inner.avoid.remove(0);
        }
    }

    async fn candidates_for(&self, t: &Arc<Tunnel>, prefer_current: bool) -> Vec<Node> {
        let s = self.settings().await;
        let nodes = self.nodes.nodes(s.residential_only()).await;
        let first = t.node().await;
        let region = if first.country_code.is_empty() {
            String::new()
        } else {
            first.country_code.clone()
        };
        let used = self.used_hosts(Some(t.slot)).await;
        let mut used_map = HashMap::new();
        for h in &used {
            used_map.insert(h.clone(), true);
        }
        let avoid = t.inner.lock().await.avoid.clone();
        let mut avoid_map = HashMap::new();
        for h in &avoid {
            avoid_map.insert(h.clone(), true);
        }
        order_candidates(
            &first,
            &region,
            prefer_current,
            s.conn.max_tries,
            &nodes,
            &used_map,
            &avoid_map,
        )
    }

    async fn active(&self, t: &Arc<Tunnel>) -> bool {
        if t.status().await == "stopped" {
            return false;
        }
        self.tunnels
            .lock()
            .await
            .get(&t.slot)
            .is_some_and(|v| Arc::ptr_eq(v, t))
    }

    async fn bring_up(&self, t: Arc<Tunnel>, notify: bool, persist: bool) {
        let _run = t.run_lock.lock().await;
        let generation = t.generation();
        let s = self.settings().await;
        let mut backoff = Duration::from_secs(s.conn.backoff_min);
        let ceiling = Duration::from_secs(s.conn.backoff_max);
        let mut prefer = true;
        loop {
            if generation != t.generation() || !self.active(&t).await {
                return;
            }
            let (ok, err) = self.try_candidates(&t, notify, prefer, generation).await;
            if generation != t.generation() {
                return;
            }
            if ok {
                return;
            }
            if !persist || !self.active(&t).await {
                if persist {
                    return;
                }
                t.set_status("failed", &err).await;
                self.persist().await.ok();
                return;
            }
            prefer = false;
            t.set_status(
                "starting",
                &format!(
                    "暂无可用节点，{:.0} 秒后重试（{}）",
                    backoff.as_secs_f64(),
                    one_line(&err, 320)
                ),
            )
            .await;
            tokio::time::sleep(backoff).await;
            if generation != t.generation() || !self.active(&t).await {
                return;
            }
            self.refresh_nodes().await.ok();
            backoff = (backoff * 2).min(ceiling);
        }
    }

    async fn try_candidates(
        &self,
        t: &Arc<Tunnel>,
        notify: bool,
        prefer_current: bool,
        generation: u64,
    ) -> (bool, String) {
        let candidates = self.candidates_for(t, prefer_current).await;
        let home = t.node().await.country_code;
        let mut last = "没有可用候选节点".to_string();
        for (i, node) in candidates.into_iter().enumerate() {
            if generation != t.generation() || !self.active(t).await {
                return (false, last);
            }
            if i > 0 && self.used_hosts(Some(t.slot)).await.contains(&node.hostname) {
                continue;
            }
            t.set_node(node.clone()).await;
            let note = if i == 0 {
                String::new()
            } else {
                crate::nodes::swap_note(i, &home, &node.country_code)
            };
            t.set_status("starting", &note).await;
            match t.runtime.start(&node).await {
                Ok(ip) => {
                    if generation != t.generation() || !self.active(t).await {
                        return (false, last);
                    }
                    t.set_up(ip).await;
                    self.persist().await.ok();
                    if notify {
                        self.notify_panel().await;
                    }
                    return (true, String::new());
                }
                Err(e) => {
                    if generation != t.generation() || !self.active(t).await {
                        return (false, last);
                    }
                    last = e.to_string();
                    let _ = t.runtime.stop().await;
                    self.avoid_failed(t, &node.hostname).await;
                }
            }
        }
        (false, last)
    }

    pub async fn provision(&self, req: ProvisionRequest) -> Result<JobHandle> {
        if req.count == 0 {
            return Err(anyhow!("数量至少为 1"));
        }
        self.ensure_nodes().await.ok();
        let picks = self.pick_nodes(&req).await?;
        let labels = picks
            .iter()
            .map(|n| format!("{} 出口", node_label(n)))
            .collect();
        let job = self
            .jobs
            .new_job(
                if req.region.is_empty() {
                    format!("开 {} 个任意地区出口", picks.len())
                } else {
                    format!("开 {} 个 {} 出口", picks.len(), req.region)
                },
                labels,
            )
            .await;
        let mut tasks = Vec::new();
        for (i, node) in picks.into_iter().enumerate() {
            job.set(i, "running", &format!("正在连接 {}", node.hostname))
                .await;
            let m = self.clone();
            let j = job.clone();
            tasks.push(tokio::spawn(async move {
                match m.start(node).await {
                    Ok(t) => {
                        if m.wait_up(&t, Duration::from_secs(420)).await == "up" {
                            j.set(i, "ok", &t.exit_ip().await).await;
                        } else {
                            j.set(i, "failed", &t.inner.lock().await.err).await;
                        }
                    }
                    Err(e) => j.set(i, "failed", &e.to_string()).await,
                }
            }));
        }
        let done = job.clone();
        tokio::spawn(async move {
            for task in tasks {
                let _ = task.await;
            }
            done.finish().await;
        });
        Ok(job)
    }

    async fn pick_nodes(&self, req: &ProvisionRequest) -> Result<Vec<Node>> {
        let s = self.settings().await;
        let nodes = self.nodes.nodes(s.residential_only()).await;
        let used = self.used_hosts(None).await;
        let mut out = Vec::new();
        if req.every_region {
            let mut by: HashMap<String, Vec<Node>> = HashMap::new();
            for n in nodes {
                if !used.contains(&n.hostname) {
                    by.entry(n.country_code.clone()).or_default().push(n);
                }
            }
            let mut regions: Vec<_> = by.keys().cloned().collect();
            regions.sort();
            for r in regions {
                for n in by.remove(&r).unwrap().into_iter().take(req.count) {
                    out.push(n);
                }
            }
        } else {
            for n in nodes {
                if !req.region.is_empty() && n.country_code != req.region {
                    continue;
                }
                if used.contains(&n.hostname) {
                    continue;
                }
                out.push(n);
                if out.len() == req.count {
                    break;
                }
            }
        }
        if out.is_empty() {
            Err(anyhow!("没有符合条件的空闲节点"))
        } else {
            Ok(out)
        }
    }

    pub async fn wait_up(&self, t: &Arc<Tunnel>, timeout: Duration) -> String {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let s = t.status().await;
            if s == "up" || s == "failed" || s == "stopped" {
                return s;
            }
            if tokio::time::Instant::now() >= deadline {
                return s;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn regions(&self) -> Vec<RegionStat> {
        self.ensure_nodes().await.ok();
        let s = self.settings().await;
        let nodes = self.nodes.nodes(s.residential_only()).await;
        let used = self.used_hosts(None).await;
        let mut map: HashMap<String, RegionStat> = HashMap::new();
        for n in nodes {
            if used.contains(&n.hostname) {
                continue;
            }
            let r = map
                .entry(n.country_code.clone())
                .or_insert_with(|| RegionStat {
                    code: n.country_code.clone(),
                    name: country_label(&n.country_code, &n.country),
                    ..Default::default()
                });
            r.available += 1;
            if r.best_ping == 0 || n.ping < r.best_ping {
                r.best_ping = n.ping;
            }
            if n.speed_mbps > r.best_speed_mbps {
                r.best_speed_mbps = n.speed_mbps;
            }
        }
        let mut out: Vec<_> = map.into_values().collect();
        out.sort_by(|a, b| a.code.cmp(&b.code));
        out
    }

    pub async fn country_choices(&self) -> Vec<RegionStat> {
        self.ensure_nodes().await.ok();
        let s = self.settings().await;
        let nodes = self.nodes.nodes(s.residential_only()).await;
        let mut map: HashMap<String, RegionStat> = HashMap::new();
        for node in nodes {
            let region = map
                .entry(node.country_code.clone())
                .or_insert_with(|| RegionStat {
                    code: node.country_code.clone(),
                    name: country_label(&node.country_code, &node.country),
                    ..Default::default()
                });
            region.available += 1;
            if region.best_ping == 0 || node.ping < region.best_ping {
                region.best_ping = node.ping;
            }
            if node.speed_mbps > region.best_speed_mbps {
                region.best_speed_mbps = node.speed_mbps;
            }
        }
        let mut out: Vec<_> = map.into_values().collect();
        out.sort_by(|a, b| a.code.cmp(&b.code));
        out
    }

    pub async fn exits(&self) -> Vec<Exit> {
        let mut out = Vec::new();
        for t in self.tunnels().await {
            let s = t.state().await;
            let country = node_label(&s.node);
            let aead = crate::nodes::node_supports_aead(&s.node.config);
            let (warp_ip, warp_live) = t.runtime.transit_status().await;
            out.push(Exit {
                slot: s.slot,
                port: s.port,
                host: s.node.hostname,
                region: s.node.country_code,
                country,
                exit_ip: s.exit_ip,
                status: s.status,
                err: s.err,
                since: s.since,
                socks_user: s.cred.user,
                socks_pass: s.cred.pass,
                inbounds: Vec::new(),
                warp_ip,
                warp_live,
                aead,
            });
        }
        out
    }

    pub async fn restore(&self) -> Result<()> {
        let state = load_state(&self.dir)?;
        for p in state.tunnels {
            if p.slot == 0 || p.slot > self.max_slots {
                continue;
            }
            let node = Node {
                hostname: p.hostname,
                ip: String::new(),
                country: p.country.clone(),
                country_code: p.country_code,
                ping: 0,
                speed_mbps: 0.0,
                sessions: 0,
                residential: true,
                config: p.config,
            };
            let cred = SocksCred {
                user: p.socks_user.unwrap_or_else(|| random_token(10)),
                pass: p.socks_pass.unwrap_or_else(|| random_token(10)),
            };
            let runtime = self.factory.create(p.slot, p.port, cred.clone(), &self.dir);
            let t = Tunnel::new(p.slot, p.port, cred, node, runtime);
            t.inner.lock().await.prev_host = p.prev_host;
            self.tunnels.lock().await.insert(p.slot, t.clone());
            let m = self.clone();
            tokio::spawn(async move {
                m.bring_up(t, true, true).await;
            });
        }
        Ok(())
    }

    pub async fn persist(&self) -> Result<()> {
        let mut state = StateFile::default();
        for t in self.tunnels().await {
            state.tunnels.push(t.persisted().await);
        }
        save_state(&self.dir, &state)
    }

    async fn notify_panel(&self) {
        if let Some(p) = self.panel.get() {
            if let Err(e) = p.on_tunnels_changed().await {
                tracing::warn!("同步节点链接后端失败: {e}");
            }
        }
    }

    pub async fn health_loop(self: Arc<Self>, warp: Arc<WarpService>, pools: Arc<PoolService>) {
        let mut fails: HashMap<usize, u32> = HashMap::new();
        let mut warp_fail_since: HashMap<usize, Instant> = HashMap::new();
        loop {
            let s = self.settings().await;
            tokio::time::sleep(Duration::from_secs(s.conn.health_interval)).await;
            let warp_enabled = s.warp().enabled;
            let tunnels = self.tunnels().await;
            let active_slots: HashSet<_> = tunnels.iter().map(|tunnel| tunnel.slot).collect();
            if let Err(error) = warp.prune(&active_slots).await {
                tracing::warn!("清理停止槽位的 WARP 注册失败: {error}");
            }
            let sem = Arc::new(Semaphore::new(8));
            let mut tasks = Vec::new();
            for t in tunnels {
                if t.status().await != "up" {
                    warp_fail_since.remove(&t.slot);
                    continue;
                }
                let sem = sem.clone();
                tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire_owned().await.ok();
                    if let Err(e) = t.runtime.guard_transit().await {
                        tracing::warn!("隧道 {} 中转路由对齐失败: {e}", t.slot);
                    }
                    if warp_enabled {
                        let (_, live) = t.runtime.transit_status().await;
                        if !live {
                            return (t, false, "WARP 尚未握手".to_string(), false, true);
                        }
                    }
                    if let Some(why) = t.runtime.dead_reason() {
                        return (t, false, why, true, false);
                    }
                    match t.runtime.probe_exit_ip().await {
                        Ok(ip) => {
                            let expected = t.exit_ip().await;
                            let same = ip == expected;
                            (
                                t,
                                same,
                                if same {
                                    String::new()
                                } else {
                                    format!("出口变成 {ip}")
                                },
                                false,
                                false,
                            )
                        }
                        Err(e) => (t, false, e.to_string(), false, false),
                    }
                }));
            }
            let mut down = Vec::new();
            for task in tasks {
                if let Ok((t, ok, why, certain, warp_pending)) = task.await {
                    if warp_pending {
                        let since = warp_fail_since.entry(t.slot).or_insert_with(Instant::now);
                        let timeout =
                            Duration::from_secs(s.conn.warp_handshake_timeout.saturating_mul(60));
                        if since.elapsed() >= timeout {
                            warp_fail_since.remove(&t.slot);
                            down.push((t, why, true));
                        }
                        continue;
                    }
                    warp_fail_since.remove(&t.slot);
                    if ok {
                        fails.insert(t.slot, 0);
                        continue;
                    }
                    let n = fails.entry(t.slot).or_insert(0);
                    *n += 1;
                    if certain || *n >= s.conn.health_failures {
                        fails.insert(t.slot, 0);
                        down.push((t, why, false));
                    }
                }
            }
            for (t, why, warp_timeout) in down.into_iter().take(s.conn.reconnect_limit) {
                tracing::info!("隧道 {} 已掉线：{}", t.slot, why);
                let old = t.host().await;
                if warp_timeout {
                    self.replace_warp_failed(t, old, warp.clone(), pools.clone())
                        .await;
                } else {
                    self.reconnect(t, old).await;
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        let list = self.tunnels().await;
        for t in list {
            let _ = t.runtime.stop().await;
        }
        if let Some(p) = self.panel.get() {
            let _ = p.close().await;
        }
    }
}

async fn p_resync(m: &Manager, t: &Arc<Tunnel>) -> Result<()> {
    if t.status().await != "up" {
        return Ok(());
    }
    if let Some(p) = m.panel.get() {
        p.resync_outbound(&t.host().await).await?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "manager_test.rs"]
mod tests;
