use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use std::sync::Mutex as StdMutex;
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify, RwLock},
};

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
    warp_logic::{warp_gate_ips, warp_gate_names},
};

const EXIT_IP_ORACLES: &[&str] = &[
    "http://api.ipify.org",
    "http://ipv4.icanhazip.com",
    "http://4.ident.me",
    "http://ifconfig.me/ip",
    "http://ipecho.net/plain",
];

pub struct NetnsSocksDialer {
    dialer: NetnsDialer,
}

#[async_trait]
impl SocksDialer for NetnsSocksDialer {
    async fn dial(&self, network: DialNetwork, addr: &str) -> Result<DialSocket> {
        let mut addrs = tokio::net::lookup_host(addr)
            .await
            .with_context(|| format!("解析目标 {addr} 失败"))?;
        let target = addrs
            .find(|a| matches!(a, SocketAddr::V4(_)))
            .ok_or_else(|| anyhow!("目标 {addr} 没有 IPv4 地址"))?;
        match network {
            DialNetwork::Tcp => self
                .dialer
                .dial_tcp(target)
                .await
                .map(DialSocket::Tcp)
                .map_err(Into::into),
            DialNetwork::Udp => self
                .dialer
                .dial_udp(target)
                .await
                .map(DialSocket::Udp)
                .map_err(Into::into),
        }
    }
}

pub struct LinuxTunnelRuntime {
    slot: usize,
    port: u16,
    dir: PathBuf,
    instance: Instance,
    netns: Netns,
    settings: Arc<RwLock<WebSettings>>,
    cred: Arc<RwLock<SocksCred>>,
    proc: Mutex<Option<OvpnProc>>,
    listener: Mutex<Option<Arc<TcpListener>>>,
    accepting: AtomicBool,
    stop_notify: Arc<Notify>,
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
    ) -> Self {
        let netns = Netns::new(instance.clone(), slot);
        Self {
            slot,
            port,
            dir: dir.to_path_buf(),
            instance,
            netns,
            settings,
            cred: Arc::new(RwLock::new(cred)),
            proc: Mutex::new(None),
            listener: Mutex::new(None),
            accepting: AtomicBool::new(false),
            stop_notify: Arc::new(Notify::new()),
            dead: Arc::new(StdMutex::new(None)),
        }
    }

    async fn stop_old(&self) {
        self.accepting.store(false, Ordering::Release);
        self.stop_notify.notify_one();
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
        let stop = self.stop_notify.clone();
        tokio::spawn(async move {
            loop {
                if !accepting.load(Ordering::Acquire) {
                    break;
                }
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let c = cred.read().await.clone();
                        let d = dialer.clone();
                        tokio::spawn(async move { let _ = serve_socks(stream, Some(&c), d.as_ref()).await; });
                    }
                    _ = stop.notified() => break,
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
        let settings = self.settings.read().await.clone();
        let budget = Duration::from_secs(settings.conn.connect_budget);
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
        let mssfix = 1400;
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

    async fn healthy(&self) -> bool {
        tun0_up(&self.netns.name()) && netns_has_default(&self.netns.name())
    }
}

pub struct LinuxTunnelFactory {
    pub instance: Instance,
    pub settings: Arc<RwLock<WebSettings>>,
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
        ))
    }
}

pub fn has_default_route(output: &str) -> bool {
    route_has_default(output)
}
