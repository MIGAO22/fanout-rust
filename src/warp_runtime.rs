use anyhow::{bail, Result};
use std::{path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex, RwLock, Semaphore},
};

use crate::{
    config::WebSettings,
    instance::Instance,
    jobs::JobHandle,
    manager::Manager,
    models::{Node, WarpOverview},
    netns::Netns,
    process::{output_command, start_tokio_command},
    util::atomic_write,
    warp_logic::{
        new_warp_reg_request, parse_warp_reg, parse_warp_store, parse_wg_dump, render_warp_store,
        warp_account_of, warp_argv, warp_gate_ips, warp_gate_names, warp_guard_cmds, warp_key_for,
        warp_live_endpoint, warp_path_mtu, warp_setup_cmds, warp_split_cmds, WarpAccount,
        WarpSetupInput,
    },
};

const WARP_API_VER: &str = "v0a2317";
const WARP_CLIENT_VERSION: &str = "2026.8.2115.0";

pub struct WarpService {
    dir: std::path::PathBuf,
    instance: Instance,
    settings: Arc<RwLock<WebSettings>>,
    accounts: Arc<Mutex<Vec<WarpAccount>>>,
    lock: Arc<Semaphore>,
}

impl WarpService {
    pub fn load(
        dir: &Path,
        instance: Instance,
        settings: Arc<RwLock<WebSettings>>,
    ) -> Result<Arc<Self>> {
        let blob = std::fs::read(dir.join("warp.json")).unwrap_or_default();
        let accounts = if blob.is_empty() {
            Vec::new()
        } else {
            parse_warp_store(&blob)?
        };
        Ok(Arc::new(Self {
            dir: dir.to_path_buf(),
            instance,
            settings,
            accounts: Arc::new(Mutex::new(accounts)),
            lock: Arc::new(Semaphore::new(1)),
        }))
    }

    pub async fn all(&self) -> Vec<WarpAccount> {
        self.accounts.lock().await.clone()
    }

    pub async fn get(&self, slot: usize) -> Option<WarpAccount> {
        self.accounts
            .lock()
            .await
            .iter()
            .find(|a| a.slot == slot)
            .cloned()
    }

    async fn save(&self, accounts: &[WarpAccount]) -> Result<()> {
        atomic_write(
            self.dir.join("warp.json"),
            &render_warp_store(accounts)?,
            0o600,
        )
    }

    async fn register(&self, slot: usize, version: &str) -> Result<WarpAccount> {
        let (priv_key, pub_key) = crate::warp_logic::new_warp_keys()?;
        let req = new_warp_reg_request(&pub_key, version)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(25))
            .build()?;
        let resp = client
            .post(format!(
                "https://api.cloudflareclient.com/{WARP_API_VER}/reg"
            ))
            .json(&req)
            .send()
            .await?
            .error_for_status()?;
        let body = resp.bytes().await?;
        let parsed = parse_warp_reg(&body)?;
        warp_account_of(
            slot,
            &parsed,
            &priv_key,
            &pub_key,
            version,
            chrono::Utc::now(),
        )
    }

    pub async fn ensure(&self, slot: usize, version: &str) -> Result<WarpAccount> {
        let _permit = self
            .lock
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("WARP 服务已关闭"))?;
        let mut accounts = self.accounts.lock().await;
        if let Some(a) = accounts.iter().find(|a| a.slot == slot) {
            if a.version == version {
                return Ok(a.clone());
            }
            unregister(a).await;
            accounts.retain(|a| a.slot != slot);
        }
        let a = self.register(slot, version).await?;
        accounts.push(a.clone());
        self.save(&accounts).await?;
        Ok(a)
    }

    pub async fn drop(&self, slot: usize) -> Result<()> {
        let _permit = self
            .lock
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("WARP 服务已关闭"))?;
        let mut accounts = self.accounts.lock().await;
        if let Some(a) = accounts.iter().find(|a| a.slot == slot) {
            unregister(a).await;
        }
        accounts.retain(|a| a.slot != slot);
        self.save(&accounts).await
    }

    pub async fn drop_all(&self) -> Result<()> {
        let _permit = self
            .lock
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("WARP 服务已关闭"))?;
        let mut accounts = self.accounts.lock().await;
        for a in accounts.iter() {
            unregister(a).await;
        }
        accounts.clear();
        self.save(&accounts).await
    }

    pub async fn setup(&self, ns: &Netns, node: &Node) -> Result<WarpAccount> {
        let settings = self.settings.read().await.clone();
        let version = settings
            .warp()
            .client_version
            .unwrap_or_else(|| WARP_CLIENT_VERSION.into());
        let a = self.ensure(ns.slot, &version).await?;
        let mtu = warp_path_mtu(true, 1500).0;
        let mut direct = vec!["8.8.8.8".to_string()];
        for host in warp_gate_names(&node.config) {
            if let Ok(addrs) = tokio::net::lookup_host((host.as_str(), 0)).await {
                for addr in addrs.filter(|a| matches!(a, std::net::SocketAddr::V4(_))) {
                    direct.push(addr.ip().to_string());
                }
            }
        }
        let cmds = warp_setup_cmds(&WarpSetupInput {
            dev: a.dev_name(&self.instance.tag),
            peer_key: a.peer_key.clone(),
            endpoint: a.endpoint.clone(),
            port: a.port,
            tun_ip: a.tun_ip.clone(),
            mtu,
            veth_gw: ns.gateway(),
            veth: ns.peer(),
            direct_ips: direct,
        });
        for c in cmds {
            run_warp(ns, &c, &a.priv_key).await?;
        }
        let ips = warp_gate_ips(&node.config, &node.ip);
        for c in crate::warp_logic::warp_gate_pin_cmds(&a.dev_name(&self.instance.tag), &ips) {
            run_warp(ns, &c, "").await?;
        }
        Ok(a)
    }

    pub async fn split(&self, ns: &Netns, node: &Node, a: &WarpAccount) -> Result<()> {
        for c in warp_split_cmds(
            &a.dev_name(&self.instance.tag),
            "tun0",
            &warp_gate_ips(&node.config, &node.ip),
        ) {
            run_warp(ns, &c, "").await?;
        }
        Ok(())
    }

    pub async fn guard(&self, ns: &Netns, node: &Node, a: &WarpAccount) -> Result<bool> {
        let out = output_command(
            "ip",
            &[
                "netns".into(),
                "exec".into(),
                ns.name(),
                "ip".into(),
                "-o".into(),
                "route".into(),
                "show".into(),
            ],
        )?;
        let state = crate::warp_logic::parse_warp_routes(
            &String::from_utf8_lossy(&out.stdout),
            &a.dev_name(&self.instance.tag),
        );
        if !crate::warp_logic::warp_guard_needed(&state) {
            return Ok(false);
        }
        for c in warp_guard_cmds(
            &a.dev_name(&self.instance.tag),
            "tun0",
            &warp_gate_ips(&node.config, &node.ip),
            state.tun_up,
        ) {
            run_warp(ns, &c, "").await?;
        }
        Ok(true)
    }

    pub async fn status(&self, ns: &Netns, slot: usize) -> (String, bool) {
        let Ok(accounts) = self.accounts.try_lock() else {
            return (String::new(), false);
        };
        let Some(a) = accounts.iter().find(|a| a.slot == slot) else {
            return (String::new(), false);
        };
        let dev = a.dev_name(&self.instance.tag);
        let args = vec![
            "netns".into(),
            "exec".into(),
            ns.name(),
            "wg".into(),
            "show".into(),
            dev,
            "dump".into(),
        ];
        let Ok(out) = output_command("ip", &args) else {
            return (a.endpoint.clone(), false);
        };
        let peers = parse_wg_dump(&String::from_utf8_lossy(&out.stdout));
        let (ep, live) = warp_live_endpoint(&peers, proc_uptime(), chrono::Utc::now().timestamp());
        (
            if ep.is_empty() {
                a.endpoint.clone()
            } else {
                ep
            },
            live,
        )
    }

    pub async fn wait(&self, ns: &Netns, slot: usize, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.status(ns, slot).await.1 {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn reregister(&self, manager: &Arc<Manager>, job: JobHandle) -> Result<()> {
        let settings = self.settings.read().await.clone();
        if !settings.warp().enabled {
            bail!("中转还没打开，开了才谈得上重新注册");
        }
        let tunnels = manager.tunnels().await;
        if tunnels.is_empty() {
            bail!("现在没有出口，没有可重新注册的线路");
        }
        let version = settings
            .warp()
            .client_version
            .unwrap_or_else(|| WARP_CLIENT_VERSION.into());
        let mut at = 0;
        if !crate::clients::has_cmd("wg") {
            job.set(at, "running", "正在安装 wireguard-tools").await;
            let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
            let plan = match crate::clients::wireguard_install_plan(
                &os_release,
                crate::clients::has_cmd,
            ) {
                Ok((steps, _)) => steps,
                Err(err) => {
                    job.set(at, "failed", &err.to_string()).await;
                    job.finish().await;
                    return Err(err);
                }
            };
            for command in plan {
                if let Err(err) =
                    crate::clients::run_repo_query(&command, Duration::from_secs(10 * 60))
                {
                    job.set(at, "failed", &err.to_string()).await;
                    job.finish().await;
                    return Err(err);
                }
            }
            job.set(at, "ok", "wg 已就位").await;
            at += 1;
        }
        for tunnel in tunnels {
            let host = tunnel.host().await;
            job.set(at, "running", "正在重新注册").await;
            if let Err(err) = self.drop(tunnel.slot).await {
                job.set(at, "failed", &err.to_string()).await;
                at += 1;
                continue;
            }
            let account = match self.ensure(tunnel.slot, &version).await {
                Ok(account) => account,
                Err(err) => {
                    job.set(at, "failed", &err.to_string()).await;
                    at += 1;
                    continue;
                }
            };
            manager.reconnect(tunnel.clone(), host).await;
            let ns = Netns::new(self.instance.clone(), tunnel.slot);
            if self.wait(&ns, tunnel.slot, Duration::from_secs(120)).await {
                job.set(at, "ok", &format!("Cloudflare 接入 {}", account.endpoint))
                    .await;
            } else {
                job.set(at, "failed", "WARP 握手超时").await;
            }
            at += 1;
        }
        job.finish().await;
        Ok(())
    }

    pub async fn overview(&self) -> WarpOverview {
        let settings = self.settings.read().await.clone();
        let accounts = self.all().await;
        let version = settings
            .warp()
            .client_version
            .unwrap_or_else(|| WARP_CLIENT_VERSION.into());
        let (ready, reason, need_tools, pkg_cmd) = if crate::clients::has_cmd("wg") {
            (true, String::new(), false, String::new())
        } else {
            let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
            match crate::clients::wireguard_install_plan(&os_release, crate::clients::has_cmd) {
                Ok((steps, _)) => (
                    true,
                    String::new(),
                    true,
                    steps
                        .iter()
                        .map(|step| step.join(" "))
                        .collect::<Vec<_>>()
                        .join(" && "),
                ),
                Err(err) => (false, err.to_string(), false, String::new()),
            }
        };
        WarpOverview {
            enabled: settings.warp().enabled,
            ready,
            reason,
            need_tools,
            pkg_cmd,
            last_err: String::new(),
            version: version.clone(),
            count: accounts.len(),
            live: 0,
            stale: accounts
                .iter()
                .filter(|account| account.version != version)
                .count(),
        }
    }
}

async fn unregister(a: &WarpAccount) {
    if a.id.is_empty() || a.token.is_empty() {
        return;
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = client
        .delete(format!(
            "https://api.cloudflareclient.com/{WARP_API_VER}/reg/{}",
            a.id
        ))
        .bearer_auth(&a.token)
        .send()
        .await;
}

async fn run_warp(ns: &Netns, command: &[String], private_key: &str) -> Result<()> {
    let (program, args) = warp_argv(&ns.name(), command);
    let mut c = tokio::process::Command::new(program);
    c.args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = start_tokio_command(&mut c)?;
    let key = warp_key_for(command, private_key);
    if !key.is_empty() {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(key.as_bytes()).await?;
        }
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!(
            "{} {}: {}",
            command.first().map(String::as_str).unwrap_or(""),
            command.get(1).map(String::as_str).unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn proc_uptime() -> i64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|v| v as i64)
        .unwrap_or(0)
}
