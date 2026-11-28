use crate::{
    config::DEFAULT_PANEL_DEBOUNCE,
    models::{Inbound, InboundDetail, PoolView, SocksCred, TunnelState},
    panel::{CreatedInbound, Panel},
};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Map, Value};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

pub const XCL_CONFIG_PATH: &str = "/usr/local/etc/xray/config.json";
pub const XCL_STATE_DIR: &str = "/etc/xray-cf-lite";
const XCL_SERVICE_NAME: &str = "xray";
const XCL_RESTART_OWNER: &str = "xray-cf-lite";
const FANOUT_TAG_PREFIX: &str = "fanout-";
const XCL_READ_ONLY_ERROR: &str = "xray-cf-lite 模式下节点由 xray-cf-lite 管理，fanout 只能改路由（绑定出口），不能增删或改节点本身";
const RESTART_RETRY_MAX: u32 = 4;
const RESTART_RETRY_BASE: Duration = Duration::from_secs(2);
const RESTART_RETRY_CAP: Duration = Duration::from_secs(30);

type RestartFn = Arc<dyn Fn() -> Result<()> + Send + Sync>;

/// Supplies the live tunnel and pool snapshots needed by the argument-free Panel trait.
/// A pool is exported to Xray only when `running` is true; `up` controls its green status.
pub trait XCLRuntime: Send + Sync {
    fn tunnels(&self) -> Vec<TunnelState> {
        Vec::new()
    }

    fn pools(&self) -> Vec<PoolView> {
        Vec::new()
    }

    fn snapshot(&self) -> (Vec<TunnelState>, Vec<PoolView>) {
        (self.tunnels(), self.pools())
    }
}

impl XCLRuntime for () {}

impl<T: XCLRuntime + ?Sized> XCLRuntime for Arc<T> {
    fn tunnels(&self) -> Vec<TunnelState> {
        (**self).tunnels()
    }

    fn pools(&self) -> Vec<PoolView> {
        (**self).pools()
    }
}

/// Xray configuration managed by xray-cf-lite, with fanout-owned SOCKS outbounds and routes.
#[derive(Clone)]
pub struct XCL {
    cfg_path: PathBuf,
    init_sys: String,
    svc_name: String,
    restart: Option<RestartFn>,
    runtime: Arc<dyn XCLRuntime>,
    restart_debounce: Duration,
    restart_gate: Arc<RestartGate>,
}

impl XCL {
    /// Creates an XCL backend for an existing config path without probing system locations.
    pub fn new<R: XCLRuntime + 'static>(cfg_path: impl Into<PathBuf>, runtime: R) -> Self {
        Self {
            cfg_path: cfg_path.into(),
            init_sys: detect_init_system(),
            svc_name: XCL_SERVICE_NAME.into(),
            restart: None,
            runtime: Arc::new(runtime),
            restart_debounce: Duration::from_millis(DEFAULT_PANEL_DEBOUNCE),
            restart_gate: Arc::new(RestartGate::new(RESTART_RETRY_MAX)),
        }
    }

    /// Detects xray-cf-lite with an empty runtime snapshot.
    pub fn detect_xcl() -> Result<Self> {
        Self::detect(())
    }

    /// Detects xray-cf-lite and attaches the application's live tunnel/pool provider.
    pub fn detect<R: XCLRuntime + 'static>(runtime: R) -> Result<Self> {
        Self::detect_at(XCL_STATE_DIR, XCL_CONFIG_PATH, runtime)
    }

    /// Path-injectable detection entry point, also useful for isolated tests.
    pub fn detect_at<R: XCLRuntime + 'static>(
        state_dir: impl AsRef<Path>,
        cfg_path: impl AsRef<Path>,
        runtime: R,
    ) -> Result<Self> {
        let state_dir = state_dir.as_ref();
        let cfg_path = cfg_path.as_ref();
        fs::metadata(state_dir)
            .map_err(|_| anyhow!("未发现 xray-cf-lite 状态目录 {}", state_dir.display()))?;
        fs::metadata(cfg_path).map_err(|_| anyhow!("未发现 Xray 配置 {}", cfg_path.display()))?;
        let xcl = Self::new(cfg_path, runtime);
        // Detection rejects unreadable or malformed configuration before selecting the backend.
        xcl.load_cfg()?;
        Ok(xcl)
    }

    pub fn with_runtime<R: XCLRuntime + 'static>(mut self, runtime: R) -> Self {
        self.runtime = Arc::new(runtime);
        self
    }

    pub fn with_init_system(mut self, init_system: impl Into<String>) -> Self {
        self.init_sys = init_system.into();
        self
    }

    pub fn with_service_name(mut self, service_name: impl Into<String>) -> Self {
        self.svc_name = service_name.into();
        self
    }

    /// Replaces the system service restart with an injectable function.
    pub fn with_restart<F>(mut self, restart: F) -> Self
    where
        F: Fn() -> Result<()> + Send + Sync + 'static,
    {
        self.restart = Some(Arc::new(restart));
        self
    }

    /// Sets the config-write coalescing window. Zero restarts synchronously.
    pub fn with_restart_debounce(mut self, debounce: Duration) -> Self {
        self.restart_debounce = debounce;
        self
    }

    pub fn with_restart_debounce_ms(mut self, debounce_ms: u64) -> Self {
        self.restart_debounce = Duration::from_millis(debounce_ms);
        self
    }

    pub fn config_path(&self) -> &Path {
        &self.cfg_path
    }

    pub fn init_system(&self) -> &str {
        &self.init_sys
    }

    pub fn service_name(&self) -> &str {
        &self.svc_name
    }

    pub fn load_cfg(&self) -> Result<Value> {
        let blob = fs::read(&self.cfg_path)
            .with_context(|| format!("读取 {} 失败", self.cfg_path.display()))?;
        let cfg: Value = serde_json::from_slice(&blob)
            .with_context(|| format!("解析 {} 失败", self.cfg_path.display()))?;
        if !cfg.is_object() {
            bail!(
                "解析 {} 失败: 配置顶层必须是 JSON 对象",
                self.cfg_path.display()
            );
        }
        Ok(cfg)
    }

    /// Atomically replaces the config, then coalesces the xray-cf-lite service restart.
    pub fn save_cfg(&self, cfg: &Value) -> Result<()> {
        if !cfg.is_object() {
            bail!("配置顶层必须是 JSON 对象");
        }
        let blob = serde_json::to_vec_pretty(cfg).context("序列化配置失败")?;
        let mut tmp_name = self.cfg_path.as_os_str().to_os_string();
        tmp_name.push(".fanout.tmp");
        let tmp = PathBuf::from(tmp_name);
        let mut file = crate::util::open_file(&tmp, 0o644, false)
            .with_context(|| format!("写入临时配置失败: {}", tmp.display()))?;
        file.write_all(&blob)
            .with_context(|| format!("写入临时配置失败: {}", tmp.display()))?;
        drop(file);
        fs::rename(&tmp, &self.cfg_path)
            .with_context(|| format!("替换配置失败: {}", self.cfg_path.display()))?;

        let restart = self.restart.clone().unwrap_or_else(|| {
            let this = self.clone();
            Arc::new(move || this.restart_xray())
        });
        self.restart_gate
            .defer_restart(restart, self.restart_debounce)
    }

    pub fn restart_xray(&self) -> Result<()> {
        let (program, args) = self.restart_command();
        let output = Command::new(program)
            .args(&args)
            .output()
            .with_context(|| format!("执行 {} {} 失败", program, args.join(" ")))?;
        if !output.status.success() {
            let mut combined = output.stdout;
            combined.extend(output.stderr);
            bail!("重启 {} 失败: {}", self.svc_name, trim_output(&combined));
        }
        Ok(())
    }

    fn restart_command(&self) -> (&'static str, Vec<String>) {
        if self.init_sys == "systemd" {
            ("systemctl", vec!["restart".into(), self.svc_name.clone()])
        } else {
            ("rc-service", vec![self.svc_name.clone(), "restart".into()])
        }
    }

    pub fn inbounds_with_live(&self, live: &HashMap<String, bool>) -> Result<Vec<Inbound>> {
        let cfg = self.load_cfg()?;
        let bound = self.bound_inbounds(&cfg);
        let raw_inbounds = cfg
            .get("inbounds")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut out = Vec::with_capacity(raw_inbounds.len());
        for raw in raw_inbounds {
            let Some(inbound) = raw.as_object() else {
                continue;
            };
            let tag = xcl_inbound_tag(inbound);
            let port = json_port(inbound.get("port"));
            let protocol = inbound
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let host = bound.get(&tag).map(String::as_str).unwrap_or_default();
            out.push(Inbound {
                id: port.to_string(),
                port,
                protocol: protocol.into(),
                remark: tag.clone(),
                enable: true,
                tag,
                bound_to: host.into(),
                bound_up: *live.get(host).unwrap_or(&false),
            });
        }
        out.sort_by_key(|inbound| inbound.port);
        Ok(out)
    }

    /// Reconstructs inbound tag -> sanitized exit identity from fanout routing rules.
    pub fn bound_inbounds(&self, cfg: &Value) -> HashMap<String, String> {
        let mut bound = HashMap::new();
        let Some(rules) = cfg
            .get("routing")
            .and_then(Value::as_object)
            .and_then(|routing| routing.get("rules"))
            .and_then(Value::as_array)
        else {
            return bound;
        };
        for mut rule in rules {
            let Some(rule) = rule.as_object() else {
                continue;
            };
            let Some(tag) = rule.get("outboundTag").and_then(Value::as_str) else {
                continue;
            };
            let Some(host) = tag.strip_prefix(FANOUT_TAG_PREFIX) else {
                continue;
            };
            // Ignore legacy slot-number tags, which can silently point at another node.
            if is_all_digits(host) {
                continue;
            }
            for inbound_tag in to_string_slice(rule.get("inboundTag")) {
                bound.insert(inbound_tag, host.to_string());
            }
        }
        bound
    }

    /// Replaces only fanout outbounds, preserving xray-cf-lite entries and forcing direct IPv4.
    pub fn sync_outbounds(&self, cfg: &mut Value, tunnels: &[TunnelState], pools: &[PoolView]) {
        let Some(root) = cfg.as_object_mut() else {
            return;
        };
        let existing = match root.get_mut("outbounds") {
            Some(Value::Array(outbounds)) => std::mem::take(outbounds),
            _ => Vec::new(),
        };
        let mut kept = Vec::with_capacity(existing.len() + tunnels.len() + pools.len());
        for mut outbound in existing {
            let is_fanout = outbound
                .as_object()
                .and_then(|outbound| outbound.get("tag"))
                .and_then(Value::as_str)
                .is_some_and(|tag| tag.starts_with(FANOUT_TAG_PREFIX));
            if is_fanout {
                continue;
            }
            if let Some(outbound) = outbound.as_object_mut() {
                force_ipv4(outbound);
            }
            kept.push(outbound);
        }
        for tunnel in tunnels.iter().filter(|tunnel| tunnel.status == "up") {
            kept.push(socks_outbound(
                egress_tag(&tunnel.node.hostname),
                socks_server(tunnel.port, &tunnel.cred),
            ));
        }
        for pool in egress_pools(pools) {
            kept.push(socks_outbound(
                egress_tag(&pool.identity),
                socks_server(pool.port, &pool_socks_cred(&pool)),
            ));
        }
        root.insert("outbounds".into(), Value::Array(kept));
    }

    /// Go-compatible bind operation with explicit state snapshots.
    pub fn bind_with_state(
        &self,
        inbound_tag: &str,
        hostname: &str,
        tunnels: &[TunnelState],
        pools: &[PoolView],
    ) -> Result<()> {
        let tag = if hostname.is_empty() {
            String::new()
        } else if pool_identity_to_id(hostname).1 {
            let pool = egress_pools(pools)
                .into_iter()
                .find(|pool| pool.identity == hostname)
                .ok_or_else(|| anyhow!("出口组 {} 不存在或监听没起来", hostname))?;
            egress_tag(&pool.identity)
        } else {
            let target = tunnels
                .iter()
                .find(|tunnel| tunnel.node.hostname == hostname)
                .ok_or_else(|| anyhow!("节点 {} 没有运行中的隧道", hostname))?;
            if target.status != "up" {
                bail!("节点 {} 的隧道还没连通（当前 {}）", hostname, target.status);
            }
            egress_tag(&target.node.hostname)
        };

        let live = live_map(tunnels, pools);
        let current = self.inbounds_with_live(&live)?;
        let known_tags: HashSet<_> = current.into_iter().map(|inbound| inbound.tag).collect();
        if !known_tags.contains(inbound_tag) {
            bail!("入站 {} 不存在", inbound_tag);
        }

        let mut cfg = self.load_cfg()?;
        self.sync_outbounds(&mut cfg, tunnels, pools);
        let root = cfg.as_object_mut().expect("load_cfg guarantees an object");
        let routing = root.entry("routing").or_insert_with(|| json!({}));
        if !routing.is_object() {
            *routing = json!({});
        }
        let routing = routing
            .as_object_mut()
            .expect("routing was normalized to an object");
        let rules = match routing.get_mut("rules") {
            Some(Value::Array(existing)) => std::mem::take(existing),
            _ => Vec::new(),
        };
        let mut cleaned = Vec::with_capacity(rules.len() + 1);
        for mut rule in rules {
            let is_fanout = rule
                .as_object()
                .and_then(|rule| rule.get("outboundTag"))
                .and_then(Value::as_str)
                .is_some_and(|tag| tag.starts_with(FANOUT_TAG_PREFIX));
            if !is_fanout {
                cleaned.push(rule);
                continue;
            }
            let rule = rule
                .as_object_mut()
                .expect("fanout rule was identified as an object");
            let remaining: Vec<Value> = to_string_slice(rule.get("inboundTag"))
                .into_iter()
                .filter(|tag| tag != inbound_tag && known_tags.contains(tag))
                .map(Value::String)
                .collect();
            if !remaining.is_empty() {
                rule.insert("inboundTag".into(), Value::Array(remaining));
                cleaned.push(Value::Object(rule.clone()));
            }
        }
        if !tag.is_empty() {
            cleaned.push(json!({
                "type": "field",
                "inboundTag": [inbound_tag],
                "outboundTag": tag,
            }));
        }
        routing.insert("rules".into(), Value::Array(cleaned));
        self.save_cfg(&cfg)
    }

    /// Moves every inbound currently bound to `old_host` to `new_host`.
    pub fn rebind_with_state(
        &self,
        old_host: &str,
        new_host: &str,
        tunnels: &[TunnelState],
        pools: &[PoolView],
    ) -> Result<()> {
        if new_host.is_empty() {
            bail!("目标节点为空");
        }
        let cfg = self.load_cfg()?;
        let bound = self.bound_inbounds(&cfg);
        let mut tags: Vec<_> = bound
            .into_iter()
            .filter_map(|(tag, host)| (host == old_host).then_some(tag))
            .collect();
        tags.sort();
        if tags.is_empty() {
            bail!("没有入站绑在 {} 上", old_host);
        }
        for tag in tags {
            self.bind_with_state(&tag, new_host, tunnels, pools)?;
        }
        Ok(())
    }

    pub fn resync_outbound_with_state(
        &self,
        _host: &str,
        tunnels: &[TunnelState],
        pools: &[PoolView],
    ) -> Result<()> {
        self.on_tunnels_changed_with_state(tunnels, pools)
    }

    pub fn on_tunnels_changed_with_state(
        &self,
        tunnels: &[TunnelState],
        pools: &[PoolView],
    ) -> Result<()> {
        let mut cfg = self.load_cfg()?;
        self.sync_outbounds(&mut cfg, tunnels, pools);
        self.save_cfg(&cfg)
    }
}

#[async_trait]
impl Panel for XCL {
    fn kind(&self) -> String {
        "xray-cf-lite".into()
    }

    fn describe(&self) -> String {
        format!(
            "xray-cf-lite 接管（{}，配置 {}）",
            self.init_sys,
            self.cfg_path.display()
        )
    }

    async fn inbounds(&self) -> Result<Vec<Inbound>> {
        let (tunnels, pools) = self.runtime.snapshot();
        self.inbounds_with_live(&live_map(&tunnels, &pools))
    }

    async fn inbound_detail(&self, id: &str, _host: &str) -> Result<InboundDetail> {
        let port = id
            .parse::<u16>()
            .with_context(|| format!("入站 ID 无效: {id}"))?;
        let (tunnels, pools) = self.runtime.snapshot();
        let inbound = self
            .inbounds_with_live(&live_map(&tunnels, &pools))?
            .into_iter()
            .find(|inbound| inbound.port == port)
            .ok_or_else(|| anyhow!("入站 {} 不存在", id))?;
        Ok(InboundDetail {
            id: inbound.id,
            port: inbound.port,
            protocol: inbound.protocol,
            remark: inbound.remark,
            enable: inbound.enable,
            tag: inbound.tag,
            bound_to: inbound.bound_to,
            bound_up: inbound.bound_up,
            ..InboundDetail::default()
        })
    }

    async fn inbound_links(&self, _ids: &[String], _host: &str) -> Result<Vec<String>> {
        // xray-cf-lite owns its subscription service; this backend never synthesizes links.
        Ok(Vec::new())
    }

    async fn bind(&self, tag: &str, host: &str) -> Result<()> {
        let (tunnels, pools) = self.runtime.snapshot();
        self.bind_with_state(tag, host, &tunnels, &pools)
    }

    async fn rebind(&self, old_host: &str, new_host: &str) -> Result<()> {
        let (tunnels, pools) = self.runtime.snapshot();
        self.rebind_with_state(old_host, new_host, &tunnels, &pools)
    }

    async fn resync_outbound(&self, _host: &str) -> Result<()> {
        let (tunnels, pools) = self.runtime.snapshot();
        self.resync_outbound_with_state(_host, &tunnels, &pools)
    }

    async fn clone_to_tunnels(&self, _id: &str, _hosts: &[String]) -> Result<Vec<u16>> {
        Err(anyhow!(XCL_READ_ONLY_ERROR))
    }

    async fn delete_inbounds(&self, _ids: &[String]) -> Result<usize> {
        Err(anyhow!(XCL_READ_ONLY_ERROR))
    }

    async fn create_inbound(&self, _spec: &Value) -> Result<CreatedInbound> {
        Err(anyhow!(XCL_READ_ONLY_ERROR))
    }

    async fn update_inbound(&self, _id: &str, _patch: &crate::panel::InboundPatch) -> Result<()> {
        Err(anyhow!(XCL_READ_ONLY_ERROR))
    }

    async fn add_client(&self, _id: &str, _email: &str) -> Result<()> {
        Err(anyhow!(XCL_READ_ONLY_ERROR))
    }

    async fn delete_client(&self, _id: &str, _email: &str) -> Result<()> {
        Err(anyhow!(XCL_READ_ONLY_ERROR))
    }

    async fn reset_client(&self, _id: &str, _email: &str) -> Result<crate::models::ClientInfo> {
        Err(anyhow!(XCL_READ_ONLY_ERROR))
    }

    async fn on_tunnels_changed(&self) -> Result<()> {
        let (tunnels, pools) = self.runtime.snapshot();
        self.on_tunnels_changed_with_state(&tunnels, &pools)
    }

    async fn close(&self) -> Result<()> {
        // xray-cf-lite owns the process; fanout must not stop it.
        Ok(())
    }
}

pub fn detect_init_system() -> String {
    if Path::new("/run/systemd/system").exists() {
        "systemd".into()
    } else {
        "openrc".into()
    }
}

fn xcl_inbound_tag(inbound: &Map<String, Value>) -> String {
    inbound
        .get("tag")
        .and_then(Value::as_str)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let protocol = inbound
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or_default();
            format!("in-{}-{}", protocol, json_port(inbound.get("port")))
        })
}

fn json_int(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Number(number)) => {
            if let Some(value) = number.as_i64() {
                value
            } else if let Some(value) = number.as_u64() {
                i64::try_from(value).unwrap_or(i64::MAX)
            } else {
                number.as_f64().unwrap_or_default() as i64
            }
        }
        _ => 0,
    }
}

fn json_port(value: Option<&Value>) -> u16 {
    u16::try_from(json_int(value)).unwrap_or(0)
}

fn is_all_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn to_string_slice(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn sanitize_tag(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "unknown".into()
    } else {
        sanitized
    }
}

fn egress_tag(identity: &str) -> String {
    format!("{}{}", FANOUT_TAG_PREFIX, sanitize_tag(identity))
}

fn pool_identity_to_id(identity: &str) -> (String, bool) {
    let Some(id) = identity.strip_prefix("pool-") else {
        return (String::new(), false);
    };
    (id.to_string(), !id.is_empty())
}

fn egress_pools(pools: &[PoolView]) -> Vec<PoolView> {
    pools.iter().filter(|pool| pool.running).cloned().collect()
}

fn pool_socks_cred(pool: &PoolView) -> SocksCred {
    if pool.cred.user.is_empty() {
        SocksCred {
            user: pool.socks_user.clone(),
            pass: pool.socks_pass.clone(),
        }
    } else {
        pool.cred.clone()
    }
}

fn live_map(tunnels: &[TunnelState], pools: &[PoolView]) -> HashMap<String, bool> {
    let mut live = HashMap::new();
    for tunnel in tunnels.iter().filter(|tunnel| tunnel.status == "up") {
        live.insert(sanitize_tag(&tunnel.node.hostname), true);
    }
    for pool in egress_pools(pools) {
        live.insert(sanitize_tag(&pool.identity), pool.ready);
    }
    live
}

fn socks_server(port: u16, cred: &SocksCred) -> Value {
    let mut server = Map::new();
    server.insert("address".into(), json!("127.0.0.1"));
    server.insert("port".into(), json!(port));
    if !cred.user.is_empty() {
        server.insert(
            "users".into(),
            json!([{ "user": cred.user, "pass": cred.pass }]),
        );
    }
    Value::Object(server)
}

fn socks_outbound(tag: String, server: Value) -> Value {
    json!({
        "tag": tag,
        "protocol": "socks",
        "settings": { "servers": [server] },
    })
}

fn force_ipv4(outbound: &mut Map<String, Value>) {
    if outbound.get("protocol").and_then(Value::as_str) != Some("freedom") {
        return;
    }
    let settings = outbound.entry("settings").or_insert_with(|| json!({}));
    if !settings.is_object() {
        *settings = json!({});
    }
    settings
        .as_object_mut()
        .expect("settings was normalized to an object")
        .insert("domainStrategy".into(), json!("UseIPv4"));
}

fn trim_output(output: &[u8]) -> String {
    let text = String::from_utf8_lossy(output);
    let mut end = text.len().min(400);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut trimmed = text[..end].to_string();
    if text.len() > 400 {
        trimmed.push_str("...");
    }
    trimmed
}

/// Coalesces writes and serializes restarts. Retry timers are invalidated by newer writes.
struct RestartGate {
    state: Mutex<RestartState>,
    exec: Mutex<()>,
    retry_max: u32,
}

struct RestartState {
    run: Option<RestartFn>,
    generation: u64,
    attempts: u32,
}

impl RestartGate {
    fn new(retry_max: u32) -> Self {
        Self {
            state: Mutex::new(RestartState {
                run: None,
                generation: 0,
                attempts: 0,
            }),
            exec: Mutex::new(()),
            retry_max,
        }
    }

    fn defer_restart(self: &Arc<Self>, run: RestartFn, window: Duration) -> Result<()> {
        let generation = {
            let mut state = self.state.lock().expect("restart state poisoned");
            state.run = Some(run);
            state.generation = state.generation.wrapping_add(1);
            state.generation
        };
        if window.is_zero() {
            return self.flush(generation);
        }
        self.schedule(generation, window);
        Ok(())
    }

    fn schedule(self: &Arc<Self>, generation: u64, delay: Duration) {
        let gate = Arc::clone(self);
        thread::spawn(move || {
            thread::sleep(delay);
            if let Err(error) = gate.flush(generation) {
                tracing::error!("{} 重载失败: {}", XCL_RESTART_OWNER, error);
            }
        });
    }

    fn flush(self: &Arc<Self>, generation: u64) -> Result<()> {
        let (run, execution_generation) = {
            let mut state = self.state.lock().expect("restart state poisoned");
            if state.generation != generation {
                return Ok(());
            }
            let run = state.run.take().expect("pending restart missing");
            state.generation = state.generation.wrapping_add(1);
            (run, state.generation)
        };
        let result = {
            let _serial = self.exec.lock().expect("restart execution poisoned");
            run()
        };
        match result {
            Ok(()) => {
                self.state.lock().expect("restart state poisoned").attempts = 0;
                Ok(())
            }
            Err(error) => {
                let mut state = self.state.lock().expect("restart state poisoned");
                // A newer write already queued its own restart; do not overwrite it.
                if state.generation != execution_generation {
                    return Ok(());
                }
                state.attempts = state.attempts.saturating_add(1);
                let attempt = state.attempts;
                if attempt <= self.retry_max {
                    let multiplier = 1u32.checked_shl(attempt - 1).unwrap_or(u32::MAX);
                    let delay = RESTART_RETRY_BASE
                        .saturating_mul(multiplier)
                        .min(RESTART_RETRY_CAP);
                    state.run = Some(run);
                    state.generation = state.generation.wrapping_add(1);
                    let retry_generation = state.generation;
                    drop(state);
                    self.schedule(retry_generation, delay);
                    tracing::warn!(
                        "{} 重载失败（第 {} 次，稍后自动重试）: {}",
                        XCL_RESTART_OWNER,
                        attempt,
                        error
                    );
                    Ok(())
                } else {
                    state.attempts = 0;
                    drop(state);
                    tracing::error!(
                        "{} 重载连续失败 {} 次，放弃自动重试：配置已写入但可能尚未生效: {}",
                        XCL_RESTART_OWNER,
                        self.retry_max,
                        error
                    );
                    Err(error)
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "panel_xcl_test.rs"]
mod tests;
