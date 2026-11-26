use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use std::sync::Mutex as StdMutex;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
    time::sleep,
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::WebSettings,
    instance::Instance,
    models::{Node, SocksCred},
    netns::{netns_has_default, route_has_default, tun0_up, wait_tun_up, Netns, NetnsDialer},
    nodes::{compression_off_args, data_cipher_args, node_supports_aead},
    process::{
        openvpn_paths, output_command, ovpn_log_hint, ovpn_tuning, spawn_openvpn_in_netns, OvpnProc,
    },
    runtime::{TunnelFactory, TunnelRuntime},
    socks5::{serve_socks, DialNetwork, DialSocket, SocksDialer},
    util::{one_line, write_file},
    warp_logic::{
        warp_budget, warp_exit_is_transit_only, warp_gate_ips, warp_gate_names, warp_openvpn_args,
        warp_path_mtu, warp_pull_filters, WarpAccount,
    },
    warp_runtime::WarpService,
};

const EXIT_IP_ORACLES: &[&str] = &[
    "http://api.ipify.org",
    "http://ipv4.icanhazip.com",
    "http://4.ident.me",
    "http://ifconfig.me/ip",
    "http://ipecho.net/plain",
];
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_CACHE_LIMIT: usize = 4096;

type DnsCacheKey = (String, String, u16);
type DnsCache = StdMutex<HashMap<DnsCacheKey, (Vec<SocketAddr>, Instant)>>;

static DNS_CACHE: OnceLock<DnsCache> = OnceLock::new();

fn dns_cache() -> &'static DnsCache {
    DNS_CACHE.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn cached_ipv4_targets(key: &DnsCacheKey) -> Option<Vec<SocketAddr>> {
    lock_unpoisoned(dns_cache())
        .get(key)
        .filter(|(_, at)| at.elapsed() < DNS_CACHE_TTL)
        .map(|(addresses, _)| addresses.clone())
}

async fn resolve_ipv4_targets(dialer: &NetnsDialer, addr: &str) -> Result<Vec<SocketAddr>> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("目标地址格式错误: {addr}"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow!("目标端口无效: {addr}"))?;
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(vec![SocketAddr::from((ip, port))]);
    }
    let key = (dialer.namespace().to_string(), host.to_string(), port);
    if let Some(cached) = cached_ipv4_targets(&key) {
        return Ok(cached);
    }
    let addresses = dialer
        .resolve_ipv4(host, port)
        .await
        .with_context(|| format!("解析目标 {addr} 失败"))?;
    let mut cache = lock_unpoisoned(dns_cache());
    if cache.len() >= DNS_CACHE_LIMIT {
        cache.clear();
    }
    cache.insert(key, (addresses.clone(), Instant::now()));
    Ok(addresses)
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub struct NetnsSocksDialer {
    dialer: NetnsDialer,
}

#[async_trait]
impl SocksDialer for NetnsSocksDialer {
    async fn dial(&self, network: DialNetwork, addr: &str) -> Result<DialSocket> {
        let targets = resolve_ipv4_targets(&self.dialer, addr).await?;
        if network == DialNetwork::Udp {
            let target = targets
                .first()
                .copied()
                .ok_or_else(|| anyhow!("目标 {addr} 没有 IPv4 地址"))?;
            return self
                .dialer
                .dial_udp(target)
                .await
                .map(DialSocket::Udp)
                .map_err(Into::into);
        }
        let mut last_error = None;
        for target in targets {
            match self.dialer.dial_tcp(target).await {
                Ok(stream) => return Ok(DialSocket::Tcp(stream)),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("目标 {addr} 没有 IPv4 地址")))
    }
}

pub struct LinuxTunnelRuntime {
    slot: usize,
    port: u16,
    dir: PathBuf,
    instance: Instance,
    netns: Netns,
    socks_dialer: OnceLock<Arc<dyn SocksDialer>>,
    settings: Arc<RwLock<WebSettings>>,
    warp: Option<Arc<WarpService>>,
    node: RwLock<Option<Node>>,
    cred: Arc<RwLock<SocksCred>>,
    proc: Mutex<Option<OvpnProc>>,
    listener: Mutex<Option<Arc<TcpListener>>>,
    accepting: AtomicBool,
    stop: Mutex<CancellationToken>,
    dead: Arc<StdMutex<Option<String>>>,
}

impl LinuxTunnelRuntime {
    fn new(
        slot: usize,
        port: u16,
        cred: SocksCred,
        dir: &Path,
        instance: Instance,
        settings: Arc<RwLock<WebSettings>>,
        warp: Option<Arc<WarpService>>,
    ) -> Self {
        let netns = Netns::new(instance.clone(), slot);
        Self {
            slot,
            port,
            dir: dir.to_path_buf(),
            instance,
            netns,
            socks_dialer: OnceLock::new(),
            settings,
            warp,
            node: RwLock::new(None),
            cred: Arc::new(RwLock::new(cred)),
            proc: Mutex::new(None),
            listener: Mutex::new(None),
            accepting: AtomicBool::new(false),
            stop: Mutex::new(CancellationToken::new()),
            dead: Arc::new(StdMutex::new(None)),
        }
    }

    async fn stop_old(&self) {
        self.accepting.store(false, Ordering::Release);
        {
            let mut stop = self.stop.lock().await;
            stop.cancel();
            *stop = CancellationToken::new();
        }
        self.listener.lock().await.take();
        if let Some(p) = self.proc.lock().await.take() {
            p.kill();
        }
        self.netns.teardown();
    }

    async fn resolve_direct_ips(&self, node: &Node) -> Vec<String> {
        let mut ips = warp_gate_ips(&node.config, &node.ip);
        for host in warp_gate_names(&node.config) {
            if let Ok(addrs) = tokio::net::lookup_host((host.as_str(), 0)).await {
                for a in addrs.filter(|a| matches!(a, SocketAddr::V4(_))) {
                    let ip = a.ip().to_string();
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
        ips
    }

    fn openvpn_binary(&self) -> String {
        if let Ok(v) = std::env::var("FANOUT_OPENVPN_BIN") {
            return v;
        }
        "openvpn".into()
    }

    async fn start_listener(&self) -> Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", self.port))
            .await
            .with_context(|| format!("监听 SOCKS5 0.0.0.0:{} 失败", self.port))?;
        let listener = Arc::new(listener);
        *self.listener.lock().await = Some(listener.clone());
        self.accepting.store(true, Ordering::Release);
        let ns = self.netns.name();
        let dialer = Arc::new(NetnsSocksDialer {
            dialer: NetnsDialer::new(ns),
        });
        let cred = self.cred.clone();
        let accepting = Arc::new(AtomicBool::new(true));
        self.accepting.store(true, Ordering::Release);
        let stop = self.stop.lock().await.clone();
        let port = self.port;
        tokio::spawn(async move {
            loop {
                if !accepting.load(Ordering::Acquire) {
                    break;
                }
                tokio::select! {
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                let c = cred.read().await.clone();
                                let d = dialer.clone();
                                tokio::spawn(async move { let _ = serve_socks(stream, Some(&c), d.as_ref()).await; });
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::ConnectionAborted
                                        | std::io::ErrorKind::Interrupted
                                        | std::io::ErrorKind::WouldBlock
                                ) => continue,
                            Err(error) => {
                                tracing::warn!("SOCKS5 {port} 接受连接失败，稍后重试: {error}");
                                sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                    _ = stop.cancelled() => break,
                }
            }
        });
        Ok(())
    }
}

#[async_trait]
impl TunnelRuntime for LinuxTunnelRuntime {
    async fn start(&self, node: &Node) -> Result<String> {
        self.stop_old().await;
        *self.dead.lock().unwrap_or_else(|p| p.into_inner()) = None;
        let direct = self.resolve_direct_ips(node).await;
        self.netns.setup(&direct)?;
        *self.node.write().await = Some(node.clone());
        let settings = self.settings.read().await.clone();
        let acc: Option<WarpAccount> = if settings.warp().enabled {
            let svc = self
                .warp
                .as_ref()
                .ok_or_else(|| anyhow!("WARP 中转已开启，但注册服务未加载"))?;
            let account = svc.setup(&self.netns, node).await?;
            if !svc
                .wait(
                    &self.netns,
                    self.slot,
                    crate::warp_runtime::WARP_HANDSHAKE_BUDGET,
                )
                .await
            {
                self.netns.teardown();
                return Err(anyhow!("WARP 握手超时"));
            }
            Some(account)
        } else {
            None
        };
        let (cfg, auth, log) = openvpn_paths(&self.dir, &self.netns.name());
        write_file(&cfg, node.config.as_bytes(), 0o600)?;
        write_file(&auth, b"vpn\nvpn\n", 0o600)?;

        let bin = self.openvpn_binary();
        let version_out = output_command(&bin, &["--version".into()])?;
        let version_text = String::from_utf8_lossy(&version_out.stdout);
        let version = version_text
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .find(|p| p.chars().next().is_some_and(|c| c.is_ascii_digit()))
            .unwrap_or("")
            .to_string();
        let on = acc.is_some();
        let budget = warp_budget(Duration::from_secs(settings.conn.connect_budget), on);
        let (_, tun_mtu, mssfix) = warp_path_mtu(on, 1500);
        let aead_only = settings.conn.aead_only && node_supports_aead(&node.config);
        let mut args = vec![
            "--config".into(),
            cfg.to_string_lossy().to_string(),
            "--auth-user-pass".into(),
            auth.to_string_lossy().to_string(),
            "--auth-nocache".into(),
            "--dev".into(),
            "tun0".into(),
            "--verb".into(),
            "3".into(),
            "--log".into(),
            log.to_string_lossy().to_string(),
        ];
        args.extend(data_cipher_args(&version, aead_only));
        if aead_only {
            args.extend(compression_off_args(&version));
        }
        args.extend(warp_openvpn_args(on, tun_mtu));
        args.extend(warp_pull_filters(on, &version));
        args.extend(ovpn_tuning(budget, mssfix));

        let proc = spawn_openvpn_in_netns(&self.netns.name(), &bin, &args).await?;
        let ready = wait_tun_up(&proc, &self.netns.name(), budget).await;
        if let Err(e) = ready {
            let hint = ovpn_log_hint(&log);
            let why = if hint.is_empty() {
                e.to_string()
            } else {
                format!("{e}；{hint}")
            };
            proc.kill();
            self.netns.teardown();
            return Err(anyhow!(one_line(&why, 500)));
        }
        if let (Some(svc), Some(a)) = (&self.warp, &acc) {
            svc.split(&self.netns, node, a).await?;
        }
        *self.proc.lock().await = Some(proc.clone());
        let watch = proc.clone();
        let watch_log = log.clone();
        let dead = self.dead.clone();
        tokio::spawn(async move {
            watch.watch_ovpn_exit(&watch_log).await;
            if let Some(why) = watch.dead_reason() {
                *dead.lock().unwrap_or_else(|p| p.into_inner()) = Some(why);
            }
        });
        self.start_listener().await?;
        self.probe_exit_ip().await
    }

    async fn stop(&self) -> Result<()> {
        self.stop_old().await;
        Ok(())
    }

    async fn set_cred(&self, cred: SocksCred) -> Result<()> {
        *self.cred.write().await = cred;
        Ok(())
    }

    async fn probe_exit_ip(&self) -> Result<String> {
        let timeout = self
            .settings
            .read()
            .await
            .conn
            .health_timeout
            .saturating_mul(2);
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout);
        let mut reason = "没有可用探测源".to_string();
        for url in EXIT_IP_ORACLES {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                reason = "探测超时".into();
                break;
            }
            let secs = left.as_secs().min(15).max(1);
            let args = vec![
                "netns".into(),
                "exec".into(),
                self.netns.name(),
                "curl".into(),
                "-s".into(),
                "--max-time".into(),
                secs.to_string(),
                (*url).into(),
            ];
            match output_command("ip", &args) {
                Ok(out) => {
                    let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                        if self.settings.read().await.warp().enabled
                            && warp_exit_is_transit_only(&ip)
                        {
                            reason = format!("出口只走到了 Cloudflare 中转（{ip}），没走节点");
                            continue;
                        }
                        return Ok(v4.to_string());
                    }
                    reason = format!("返回不是 IPv4: {}", one_line(&ip, 120));
                }
                Err(e) => reason = e.to_string(),
            }
        }
        bail!("查询出口 IP 失败: {}", one_line(&reason, 300))
    }

    fn dead_reason(&self) -> Option<String> {
        self.dead.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn socks_dialer(&self) -> Arc<dyn SocksDialer> {
        self.socks_dialer
            .get_or_init(|| {
                Arc::new(NetnsSocksDialer {
                    dialer: NetnsDialer::new(self.netns.name()),
                })
            })
            .clone()
    }

    async fn healthy(&self) -> bool {
        if !tun0_up(&self.netns.name()) {
            return false;
        }
        if self.settings.read().await.warp().enabled {
            return self.transit_status().await.1;
        }
        netns_has_default(&self.netns.name())
    }

    async fn guard_transit(&self) -> Result<()> {
        if !self.settings.read().await.warp().enabled {
            return Ok(());
        }
        let node = self.node.read().await.clone();
        let Some(svc) = &self.warp else {
            return Ok(());
        };
        let Some(acc) = svc.get(self.slot).await else {
            return Ok(());
        };
        if let Some(node) = node {
            svc.guard(&self.netns, &node, &acc).await?;
        }
        Ok(())
    }

    async fn transit_status(&self) -> (String, bool) {
        if !self.settings.read().await.warp().enabled {
            return (String::new(), false);
        }
        let Some(svc) = &self.warp else {
            return (String::new(), false);
        };
        svc.status(&self.netns, self.slot).await
    }
}

pub struct LinuxTunnelFactory {
    pub instance: Instance,
    pub settings: Arc<RwLock<WebSettings>>,
    pub warp: Option<Arc<WarpService>>,
}

impl TunnelFactory for LinuxTunnelFactory {
    fn create(
        &self,
        slot: usize,
        port: u16,
        cred: SocksCred,
        dir: &Path,
    ) -> Arc<dyn TunnelRuntime> {
        Arc::new(LinuxTunnelRuntime::new(
            slot,
            port,
            cred,
            dir,
            self.instance.clone(),
            self.settings.clone(),
            self.warp.clone(),
        ))
    }
}

pub fn has_default_route(output: &str) -> bool {
    route_has_default(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn numeric_targets_skip_dns_and_reject_bad_ports() {
        let dialer = NetnsDialer::new("missing-test-netns");
        let targets = resolve_ipv4_targets(&dialer, "1.2.3.4:443").await.unwrap();
        assert_eq!(
            targets,
            vec![SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 443))]
        );
        assert!(resolve_ipv4_targets(&dialer, "1.2.3.4:not-a-port")
            .await
            .is_err());
    }

    #[test]
    fn dns_cache_separates_namespaces_and_ports() {
        let key = (
            "cache-test-netns".to_string(),
            "example.invalid".to_string(),
            443,
        );
        let addresses = vec![SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443))];
        {
            let mut cache = lock_unpoisoned(dns_cache());
            cache.insert(key.clone(), (addresses.clone(), Instant::now()));
        }
        assert_eq!(cached_ipv4_targets(&key), Some(addresses));
        assert!(cached_ipv4_targets(&(key.0.clone(), key.1.clone(), 80)).is_none());
        assert!(
            cached_ipv4_targets(&("other-test-netns".to_string(), key.1.clone(), key.2)).is_none()
        );
        lock_unpoisoned(dns_cache()).remove(&key);
    }
}
