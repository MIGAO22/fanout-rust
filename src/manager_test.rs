use super::*;
use crate::{
    factory::UnavailableDialer,
    runtime::{TunnelFactory, TunnelRuntime},
    socks5::SocksDialer,
};
use async_trait::async_trait;
use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;

struct MockRuntime {
    cred: RwLock<SocksCred>,
    starts: AtomicUsize,
    stops: AtomicUsize,
    start_entered: Notify,
    start_release: Notify,
    delay: bool,
}

impl MockRuntime {
    fn new(cred: SocksCred, delay: bool) -> Self {
        Self {
            cred: RwLock::new(cred),
            starts: AtomicUsize::new(0),
            stops: AtomicUsize::new(0),
            start_entered: Notify::new(),
            start_release: Notify::new(),
            delay,
        }
    }
}

#[async_trait]
impl TunnelRuntime for MockRuntime {
    async fn start(&self, _node: &Node) -> Result<String> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        self.start_entered.notify_one();
        if self.delay {
            self.start_release.notified().await;
        }
        Ok("203.0.113.10".into())
    }

    async fn stop(&self) -> Result<()> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn set_cred(&self, cred: SocksCred) -> Result<()> {
        *self.cred.write().await = cred;
        Ok(())
    }

    async fn probe_exit_ip(&self) -> Result<String> {
        Ok("203.0.113.10".into())
    }

    fn dead_reason(&self) -> Option<String> {
        None
    }

    async fn healthy(&self) -> bool {
        true
    }

    fn socks_dialer(&self) -> Arc<dyn SocksDialer> {
        Arc::new(UnavailableDialer)
    }
}

struct MockFactory;

impl TunnelFactory for MockFactory {
    fn create(
        &self,
        _slot: usize,
        _port: u16,
        cred: SocksCred,
        _dir: &Path,
    ) -> Arc<dyn TunnelRuntime> {
        Arc::new(MockRuntime::new(cred, false))
    }
}

fn node(name: &str) -> Node {
    Node {
        hostname: name.into(),
        country_code: "JP".into(),
        country: "Japan".into(),
        ..Node::default()
    }
}

fn manager(dir: &Path) -> Arc<Manager> {
    Manager::new(
        dir.to_path_buf(),
        MAX_EXITS,
        Arc::new(RwLock::new(WebSettings::default())),
        JobStore::new(),
        Arc::new(MockFactory),
        Arc::new(crate::observability::ObservabilityStore::default()),
    )
}

#[tokio::test]
async fn concurrent_starts_reserve_unique_slots_and_ports() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = manager(temporary.path());
    manager.nodes.replace(Vec::new()).await;
    let mut tasks = Vec::new();
    for index in 0..MAX_EXITS {
        let manager = manager.clone();
        tasks.push(tokio::spawn(async move {
            manager.start(node(&format!("node-{index}"))).await
        }));
    }
    let mut tunnels = Vec::new();
    for task in tasks {
        tunnels.push(task.await.unwrap().unwrap());
    }
    let slots: HashSet<_> = tunnels.iter().map(|tunnel| tunnel.slot).collect();
    let ports: HashSet<_> = tunnels.iter().map(|tunnel| tunnel.port).collect();
    assert_eq!(slots.len(), MAX_EXITS);
    assert_eq!(ports.len(), MAX_EXITS);
    for tunnel in tunnels {
        manager.stop(tunnel.slot).await.unwrap();
    }
}

#[tokio::test]
async fn stale_bring_up_cannot_mark_tunnel_up() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = manager(temporary.path());
    manager.nodes.replace(vec![node("node-1")]).await;
    let runtime = Arc::new(MockRuntime::new(new_socks_cred(), true));
    let tunnel = Tunnel::new(1, 30_001, new_socks_cred(), node("node-1"), runtime.clone());
    manager.tunnels.lock().await.insert(1, tunnel.clone());
    let task_manager = manager.clone();
    let task_tunnel = tunnel.clone();
    let generation = tunnel.generation();
    let task = tokio::spawn(async move {
        task_manager
            .bring_up(task_tunnel, false, false, generation)
            .await;
    });
    runtime.start_entered.notified().await;
    tunnel.bump_generation();
    runtime.start_release.notify_one();
    task.await.unwrap();
    assert_ne!(tunnel.status().await, "up");
    assert_eq!(runtime.starts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn shutdown_stops_current_tunnels_and_rejects_new_starts() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = manager(temporary.path());
    manager.nodes.replace(vec![node("node-1")]).await;
    let tunnel = manager.start(node("node-1")).await.unwrap();
    manager.shutdown().await;
    assert_eq!(tunnel.status().await, "stopped");
    assert!(manager.start(node("node-2")).await.is_err());
}

#[tokio::test]
async fn queued_bring_up_keeps_its_own_generation() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = manager(temporary.path());
    manager.nodes.replace(vec![node("node-1")]).await;
    let runtime = Arc::new(MockRuntime::new(new_socks_cred(), true));
    let tunnel = Tunnel::new(1, 30_001, new_socks_cred(), node("node-1"), runtime.clone());
    manager.tunnels.lock().await.insert(1, tunnel.clone());

    let first_manager = manager.clone();
    let first_tunnel = tunnel.clone();
    let first_generation = tunnel.generation();
    let first = tokio::spawn(async move {
        first_manager
            .bring_up(first_tunnel, false, false, first_generation)
            .await;
    });
    runtime.start_entered.notified().await;
    let second_generation = tunnel.bump_generation();
    let second_manager = manager.clone();
    let second_tunnel = tunnel.clone();
    let second = tokio::spawn(async move {
        second_manager
            .bring_up(second_tunnel, false, false, second_generation)
            .await;
    });
    runtime.start_release.notify_one();
    runtime.start_entered.notified().await;
    runtime.start_release.notify_one();
    first.await.unwrap();
    second.await.unwrap();
    assert_eq!(runtime.starts.load(Ordering::SeqCst), 2);
    assert_eq!(tunnel.status().await, "up");
}

#[tokio::test]
async fn failed_status_records_timeout_origin_and_recovery_clears_it() {
    let runtime = Arc::new(MockRuntime::new(new_socks_cred(), false));
    let tunnel = Tunnel::new(1, 30_001, new_socks_cred(), node("node-1"), runtime);
    assert!(tunnel.failed_since().await.is_none());

    tunnel
        .set_status("failed", "openvpn 退出: exit status 1")
        .await;
    let first_failure = tunnel.failed_since().await.unwrap();
    tunnel
        .set_status("failed", "openvpn 退出: exit status 1")
        .await;
    assert_eq!(tunnel.failed_since().await, Some(first_failure));

    tunnel.set_status("starting", "正在换节点重连").await;
    assert!(tunnel.failed_since().await.is_none());
    tunnel
        .set_status("failed", "openvpn 退出: exit status 1")
        .await;
    tunnel.set_up("203.0.113.10".into()).await;
    assert!(tunnel.failed_since().await.is_none());
}

#[test]
fn failed_exit_retry_requires_warp_failure_and_elapsed_timeout() {
    let timeout = Duration::from_secs(60);
    let fresh = std::time::Instant::now();
    let expired = fresh - Duration::from_secs(61);

    assert!(!failed_exit_retry_due("failed", true, None, timeout));
    assert!(!failed_exit_retry_due("failed", true, Some(fresh), timeout));
    assert!(failed_exit_retry_due(
        "failed",
        true,
        Some(expired),
        timeout
    ));
    assert!(!failed_exit_retry_due(
        "failed",
        false,
        Some(expired),
        timeout
    ));
    assert!(!failed_exit_retry_due(
        "starting",
        true,
        Some(expired),
        timeout
    ));
    assert!(!failed_exit_retry_due("up", true, Some(expired), timeout));
}

#[tokio::test]
async fn automatic_switch_respects_dwell_and_cooldown_but_not_hard_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = manager(temporary.path());
    manager.settings.write().await = WebSettings {
        conn: crate::config::ConnSettings {
            smart_selection: true,
            min_dwell_secs: 60,
            switch_cooldown_secs: 30,
            ..crate::config::ConnSettings::defaults()
        },
        ..WebSettings::default()
    }
    .normalized();
    let runtime = Arc::new(MockRuntime::new(new_socks_cred(), false));
    let tunnel = Tunnel::new(1, 30_001, new_socks_cred(), node("node-1"), runtime);
    tunnel.set_up("203.0.113.10".into()).await;
    assert!(!manager.automatic_switch_allowed(&tunnel, false).await);
    assert!(manager.automatic_switch_allowed(&tunnel, true).await);
    {
        let mut inner = tunnel.inner.lock().await;
        inner.up_since = Some(Instant::now() - Duration::from_secs(61));
        inner.last_switch_at = Some(Instant::now() - Duration::from_secs(31));
    }
    assert!(manager.automatic_switch_allowed(&tunnel, false).await);
}
