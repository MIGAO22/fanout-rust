//! 3x-ui panel backend.
//!
//! The panel owns Xray, so this module only edits its Xray template and calls the
//! panel API. Tunnel and pool state is supplied by the caller because the common
//! `Panel` trait deliberately does not expose the tunnel manager.

use crate::{
    models::{ClientInfo, Inbound, InboundDetail, PoolView, TunnelState},
    panel::{CreatedInbound, InboundPatch, Panel},
    util::atomic_write,
};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rand::Rng;
use regex::Regex;
use reqwest::{Client, Method, StatusCode};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, process::Command, sync::Mutex, time::sleep};
use urlencoding::encode as url_encode;
use uuid::Uuid;

pub const XUI_BINARY: &str = "/usr/local/x-ui/x-ui";
pub const XUI_MENU: &str = "/usr/bin/x-ui";
pub const XUI_TOKEN_FILE: &str = "xui-token";
const XUI_TAG_PREFIX: &str = "fanout-";
const POOL_TAG_PREFIX: &str = "pool-";
const PANEL_RETRIES: usize = 3;
const RAND_PORT_MIN: u16 = 20_000;
const RAND_PORT_MAX: u16 = 60_000;

static CACHED_TOKEN: OnceLock<Mutex<String>> = OnceLock::new();

fn token_cache() -> &'static Mutex<String> {
    CACHED_TOKEN.get_or_init(|| Mutex::new(String::new()))
}

#[derive(Clone, Debug, Default)]
struct Runtime {
    tunnels: Vec<TunnelState>,
    pools: Vec<PoolView>,
}

#[derive(Debug, Default)]
struct XuiState {
    token: String,
    runtime: Runtime,
}

/// A 3x-ui backend. Clones share the HTTP client, token, and runtime snapshot.
#[derive(Clone)]
pub struct XUI {
    pub host: String,
    pub port: u16,
    pub base_path: String,
    pub scheme: String,
    client: Client,
    work_dir: Option<PathBuf>,
    state: Arc<Mutex<XuiState>>,
}

impl std::fmt::Debug for XUI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XUI")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("base_path", &self.base_path)
            .field("scheme", &self.scheme)
            .field("work_dir", &self.work_dir)
            .finish_non_exhaustive()
    }
}

impl XUI {
    /// Construct a backend without running detection or token validation.
    ///
    /// `base_path` is normalized like 3x-ui's setting (one trailing slash is
    /// removed). The default client accepts the panel's local self-signed TLS
    /// certificate, matching the Go backend.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        base_path: impl Into<String>,
        scheme: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self> {
        let mut base_path = base_path.into();
        if base_path.ends_with('/') {
            base_path.pop();
        }
        Ok(Self {
            host: host.into(),
            port,
            base_path,
            scheme: scheme.into(),
            client: local_client()?,
            work_dir: None,
            state: Arc::new(Mutex::new(XuiState {
                token: token.into(),
                runtime: Runtime::default(),
            })),
        })
    }

    /// Set the directory used for the persisted API token and generated certs.
    pub fn with_work_dir(mut self, work_dir: impl AsRef<Path>) -> Self {
        self.work_dir = Some(work_dir.as_ref().to_path_buf());
        self
    }

    /// Use an already configured HTTP client (primarily useful for embedding
    /// and tests). Certificate verification is otherwise disabled for the local
    /// panel endpoint, as in the original implementation.
    pub fn with_client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }

    pub fn base(&self) -> String {
        format!(
            "{}://{}:{}{}",
            self.scheme, self.host, self.port, self.base_path
        )
    }

    pub fn work_dir(&self) -> Option<&Path> {
        self.work_dir.as_deref()
    }

    pub async fn token(&self) -> String {
        self.state.lock().await.token.clone()
    }

    /// Replace the tunnel snapshot used for liveness, tags, cloning, and
    /// outbound synchronization.
    pub async fn set_tunnels(&self, tunnels: Vec<TunnelState>) {
        self.state.lock().await.runtime.tunnels = tunnels;
    }

    /// Replace the running pool snapshot. A pool is emitted as an outbound even
    /// when `up == 0`; `up` only controls the displayed liveness flag.
    pub async fn set_pools(&self, pools: Vec<PoolView>) {
        self.state.lock().await.runtime.pools = pools;
    }

    pub async fn set_runtime(&self, tunnels: Vec<TunnelState>, pools: Vec<PoolView>) {
        let mut state = self.state.lock().await;
        state.runtime = Runtime { tunnels, pools };
    }

    async fn runtime(&self) -> Runtime {
        self.state.lock().await.runtime.clone()
    }

    async fn runtime_live(&self) -> HashMap<String, bool> {
        let runtime = self.runtime().await;
        let mut live = HashMap::new();
        for tunnel in &runtime.tunnels {
            if tunnel.status == "up" {
                live.insert(sanitize_tag(&tunnel.node.hostname), true);
            }
        }
        for pool in &runtime.pools {
            live.insert(sanitize_tag(&pool_identity(&pool.id)), pool.up > 0);
        }
        live
    }

    /// Detect the local panel. This is the associated-form equivalent of the
    /// module-level [`detect`] function.
    pub async fn detect(work_dir: impl AsRef<Path>) -> Result<Self> {
        detect(work_dir).await
    }

    /// Validate the current token with a read-only request.
    pub async fn token_valid(&self) -> bool {
        self.call(Method::GET, "panel/api/inbounds/list", None, true)
            .await
            .is_ok()
    }

    async fn saved_token_valid(&self) -> bool {
        for failure in 0..PANEL_RETRIES {
            match self
                .call_once(Method::GET, "panel/api/inbounds/list", None)
                .await
            {
                Ok(_) => return true,
                Err(err) if is_panel_auth(&err) => return false,
                Err(_) if failure + 1 < PANEL_RETRIES => {
                    sleep(panel_backoff(failure + 1)).await;
                }
                Err(_) => return false,
            }
        }
        false
    }

    /// Ask the CLI for a fresh token, update all caches, and best-effort persist
    /// it. The CLI creates a new token on every invocation, so callers must only
    /// use this after an authorization failure or during detection.
    pub async fn refresh_token(&self) -> Result<()> {
        let out =
            command_output_checked(Command::new(XUI_BINARY).args(["setting", "-getApiToken"]))
                .await
                .context("获取 API token 失败")?;
        let text = strip_ansi(&String::from_utf8_lossy(&out.stdout));
        let token = parse_api_token(&text).context("未能取得 API token")?;
        self.state.lock().await.token = token.clone();
        *token_cache().lock().await = token.clone();
        if let Some(dir) = &self.work_dir {
            save_token(dir, &token);
        }
        tracing::info!("已换新 3x-ui API token");
        Ok(())
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        form: Option<&[(String, String)]>,
        safe: bool,
    ) -> Result<Value> {
        let tries = if safe { PANEL_RETRIES } else { 1 };
        let mut failures = 0usize;
        let mut refreshed = false;
        loop {
            match self.call_once(method.clone(), path, form).await {
                Ok(value) => return Ok(value),
                Err(err) if is_panel_auth(&err) && !refreshed => {
                    if self.refresh_token().await.is_err() {
                        return Err(err);
                    }
                    refreshed = true;
                }
                Err(err) => {
                    if failures + 1 >= tries {
                        return Err(err);
                    }
                    failures += 1;
                    sleep(panel_backoff(failures)).await;
                }
            }
        }
    }

    async fn call_once(
        &self,
        method: Method,
        path: &str,
        form: Option<&[(String, String)]>,
    ) -> Result<Value> {
        let endpoint = self.endpoint(path);
        let token = self.token().await;
        let mut request = self.client.request(method, &endpoint).bearer_auth(token);
        if let Some(form) = form {
            request = request.form(form);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("调用 {path} 失败"))?;
        let status = response.status();
        let raw = response
            .bytes()
            .await
            .with_context(|| format!("读取 {path} 响应失败"))?;
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(PanelAuth {
                path: path.to_string(),
                status,
            }
            .into());
        }
        if status != StatusCode::OK {
            bail!("调用 {path} 返回 HTTP {}", status.as_u16());
        }
        let envelope: Envelope =
            serde_json::from_slice(&raw).with_context(|| format!("解析 {path} 响应失败"))?;
        if !envelope.success {
            bail!("面板返回失败: {}", envelope.msg);
        }
        Ok(envelope.obj)
    }

    /// JSON write endpoints in 3x-ui return the same envelope but historically
    /// do not retry network failures. Authorization is refreshed once.
    async fn json_call(&self, path: &str, payload: &Value) -> Result<Value> {
        let mut refreshed = false;
        loop {
            match self.json_call_once(path, payload).await {
                Ok(value) => return Ok(value),
                Err(err) if is_panel_auth(&err) && !refreshed => {
                    if self.refresh_token().await.is_err() {
                        return Err(err);
                    }
                    refreshed = true;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn json_call_once(&self, path: &str, payload: &Value) -> Result<Value> {
        let endpoint = self.endpoint(path);
        let response = self
            .client
            .post(&endpoint)
            .bearer_auth(self.token().await)
            .json(payload)
            .send()
            .await
            .with_context(|| format!("调用 {path} 失败"))?;
        let status = response.status();
        let raw = response
            .bytes()
            .await
            .with_context(|| format!("读取 {path} 响应失败"))?;
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(PanelAuth {
                path: path.to_string(),
                status,
            }
            .into());
        }
        let envelope: Value = serde_json::from_slice(&raw).with_context(|| {
            format!(
                "解析 {path} 响应失败: {}",
                String::from_utf8_lossy(&raw).trim()
            )
        })?;
        if !status.is_success() && envelope["success"].as_bool() != Some(true) {
            bail!("调用 {path} 返回 HTTP {}", status.as_u16());
        }
        Ok(envelope)
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base(), path.trim_start_matches('/'))
    }

    async fn load_xray(&self) -> Result<(Value, String)> {
        let obj = self
            .call(Method::POST, "panel/api/xray/", None, true)
            .await?;
        parse_xray_config(&obj).context("解析 Xray 配置失败")
    }

    async fn save_xray(&self, setting: Value, test_url: String) -> Result<()> {
        let mut form = vec![("xraySetting".to_string(), setting.to_string())];
        if !test_url.is_empty() {
            form.push(("outboundTestUrl".to_string(), test_url));
        }
        self.call(Method::POST, "panel/api/xray/update", Some(&form), true)
            .await?;
        self.call(
            Method::POST,
            "panel/api/server/restartXrayService",
            None,
            false,
        )
        .await
        .context("配置已保存但重载 Xray 失败")?;
        Ok(())
    }

    async fn inbounds_snapshot(&self) -> Result<Vec<Inbound>> {
        let obj = self
            .call(Method::GET, "panel/api/inbounds/list", None, true)
            .await?;
        let raw = obj.as_array().context("解析入站列表失败: obj 不是数组")?;
        let bound = self.bound_inbounds().await?;
        let live = self.runtime_live().await;
        let mut out = Vec::with_capacity(raw.len());
        for item in raw {
            let stream = item.get("streamSettings").cloned().unwrap_or(Value::Null);
            let port = value_to_u16(item.get("port"));
            let api_tag = scalar_string(item.get("tag"));
            let tag = resolved_inbound_tag(&api_tag, port, &stream);
            let bound_to = bound.get(&tag).cloned().unwrap_or_default();
            let bound_up = live.get(&bound_to).copied().unwrap_or(false);
            out.push(Inbound {
                id: value_to_i64(item.get("id")).to_string(),
                port,
                protocol: scalar_string(item.get("protocol")),
                remark: scalar_string(item.get("remark")),
                enable: item.get("enable").and_then(Value::as_bool) == Some(true),
                tag,
                bound_to,
                bound_up,
            });
        }
        Ok(out)
    }

    async fn bound_inbounds(&self) -> Result<HashMap<String, String>> {
        let (setting, _) = self.load_xray().await?;
        Ok(bound_from_setting(&setting))
    }

    async fn bind_runtime(&self, inbound_tag: &str, hostname: &str) -> Result<()> {
        let runtime = self.runtime().await;
        let tag = if hostname.is_empty() {
            String::new()
        } else if let Some(id) = hostname
            .strip_prefix(POOL_TAG_PREFIX)
            .filter(|id| !id.is_empty())
        {
            let pool = runtime
                .pools
                .iter()
                .find(|pool| pool.id == id)
                .ok_or_else(|| anyhow!("出口组 {hostname} 不存在或监听没起来"))?;
            egress_tag(&pool_identity(&pool.id))
        } else {
            let tunnel = runtime
                .tunnels
                .iter()
                .find(|tunnel| tunnel.node.hostname == hostname)
                .ok_or_else(|| anyhow!("节点 {hostname} 没有运行中的隧道"))?;
            if tunnel.status != "up" {
                bail!("节点 {hostname} 的隧道还没连通（当前 {}）", tunnel.status);
            }
            egress_tag(&tunnel.node.hostname)
        };

        let current = self.inbounds_snapshot().await?;
        let known_tags: HashSet<String> = current.into_iter().map(|ib| ib.tag).collect();
        let (mut setting, test_url) = self.load_xray().await?;
        sync_outbounds_with_runtime(&mut setting, &runtime);

        let mut routing = setting
            .get("routing")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let rules = routing
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut cleaned = Vec::with_capacity(rules.len() + 1);
        for rule in rules {
            let Some(mut object) = rule.as_object().cloned() else {
                cleaned.push(rule);
                continue;
            };
            let outbound_tag = scalar_string(object.get("outboundTag"));
            if !outbound_tag.starts_with(XUI_TAG_PREFIX) {
                cleaned.push(Value::Object(object));
                continue;
            }
            let remain: Vec<Value> = to_string_slice(object.get("inboundTag"))
                .into_iter()
                .filter(|tag| tag != inbound_tag && known_tags.contains(tag))
                .map(Value::String)
                .collect();
            if !remain.is_empty() {
                object.insert("inboundTag".into(), Value::Array(remain));
                cleaned.push(Value::Object(object));
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
        setting.insert("routing".into(), Value::Object(routing));
        self.save_xray(setting, test_url).await
    }

    async fn raw_inbound(&self, id: i64) -> Result<Map<String, Value>> {
        let obj = self
            .call(Method::GET, "panel/api/inbounds/list", None, true)
            .await?;
        let list = obj.as_array().context("解析入站列表失败: obj 不是数组")?;
        for item in list {
            if value_to_i64(item.get("id")) == id {
                return item
                    .as_object()
                    .cloned()
                    .ok_or_else(|| anyhow!("入站 {id} 格式错误"));
            }
        }
        bail!("入站 {id} 不存在")
    }

    async fn used_ports(&self) -> Result<HashSet<u16>> {
        let list = self.inbounds_snapshot().await?;
        let runtime = self.runtime().await;
        let mut used: HashSet<u16> = list.into_iter().map(|ib| ib.port).collect();
        used.extend(runtime.pools.into_iter().map(|pool| pool.port));
        Ok(used)
    }

    async fn clone_to_tunnels_runtime(
        &self,
        template_id: i64,
        hosts: &[String],
    ) -> Result<Vec<u16>> {
        let raw = self.raw_inbound(template_id).await?;
        let runtime = self.runtime().await;
        let by_host: HashMap<&str, &TunnelState> = runtime
            .tunnels
            .iter()
            .map(|tunnel| (tunnel.node.hostname.as_str(), tunnel))
            .collect();
        let mut used = self.used_ports().await?;
        let emails = client_emails(&raw)?;
        let mut taken_remarks = HashSet::new();
        if let Ok(list) = self.inbounds_snapshot().await {
            taken_remarks.extend(list.into_iter().map(|ib| ib.remark));
        }

        let mut created = Vec::new();
        for host in hosts {
            let Some(tunnel) = by_host.get(host.as_str()).copied() else {
                continue;
            };
            if tunnel.status != "up" {
                continue;
            }
            let port = free_random_port(&used).await?;
            used.insert(port);
            let mut clone = clone_inbound_payload(&raw, port, tunnel)?;
            if let Some(remark) = clone.get("remark").and_then(Value::as_str) {
                let unique = unique_remark(remark, &taken_remarks);
                clone.insert("remark".into(), Value::String(unique.clone()));
                taken_remarks.insert(unique);
            }
            let new_id = self
                .add_inbound(&clone)
                .await
                .with_context(|| format!("复制到端口 {port} 失败"))?;
            self.attach_clients(&emails, new_id).await?;
            created.push(port);

            let new_raw = self
                .raw_inbound(new_id)
                .await
                .with_context(|| format!("读取端口 {port} 的入站标签失败"))?;
            let mut new_tag = scalar_string(new_raw.get("tag"));
            if new_tag.is_empty() {
                new_tag = inbound_tag_of(port, &raw);
            }
            self.bind_runtime(&new_tag, host)
                .await
                .with_context(|| format!("端口 {port} 绑定失败"))?;
        }
        Ok(created)
    }

    async fn add_inbound(&self, payload: &Value) -> Result<i64> {
        let envelope = self.json_call("panel/api/inbounds/add", payload).await?;
        if envelope["success"].as_bool() != Some(true) {
            bail!("{}", envelope["msg"].as_str().unwrap_or("新建入站失败"));
        }
        let id = value_to_i64(envelope["obj"].get("id"));
        if envelope["obj"].get("id").is_none() {
            bail!("新建入站响应缺少 id");
        }
        Ok(id)
    }

    async fn attach_clients(&self, emails: &[String], inbound_id: i64) -> Result<()> {
        for email in emails {
            match self.attach_once(email, inbound_id).await {
                Ok(()) => {}
                Err(err) if err.to_string().contains("Duplicate email") => {
                    self.normalize_client(email).await?;
                    self.attach_once(email, inbound_id).await?;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    async fn attach_once(&self, email: &str, inbound_id: i64) -> Result<()> {
        let path = format!("panel/api/clients/{}/attach", url_encode(email));
        let envelope = self
            .json_call(&path, &json!({"inboundIds": [inbound_id]}))
            .await?;
        if envelope["success"].as_bool() != Some(true) {
            bail!(
                "挂载客户端 {email} 失败: {}",
                envelope["msg"].as_str().unwrap_or("")
            );
        }
        Ok(())
    }

    async fn normalize_client(&self, email: &str) -> Result<()> {
        let path = format!("panel/api/clients/update/{}", url_encode(email));
        let envelope = self.json_call(&path, &json!({"email": email})).await?;
        if envelope["success"].as_bool() != Some(true) {
            bail!("{}", envelope["msg"].as_str().unwrap_or("更新客户端失败"));
        }
        Ok(())
    }

    async fn inbound_detail_snapshot(&self, id: i64, public_host: &str) -> Result<InboundDetail> {
        let raw = self.raw_inbound(id).await?;
        let settings = as_object(raw.get("settings")).context("解析 settings 失败")?;
        let stream = as_object(raw.get("streamSettings")).ok();
        let bound = self.bound_inbounds().await?;
        let live = self.runtime_live().await;
        let stream_value = raw.get("streamSettings").cloned().unwrap_or(Value::Null);
        let port = value_to_u16(raw.get("port"));
        let tag = resolved_inbound_tag(&scalar_string(raw.get("tag")), port, &stream_value);
        let bound_to = bound.get(&tag).cloned().unwrap_or_default();
        let bound_up = live.get(&bound_to).copied().unwrap_or(false);
        let mut detail = InboundDetail {
            id: id.to_string(),
            port,
            protocol: scalar_string(raw.get("protocol")),
            remark: scalar_string(raw.get("remark")),
            enable: raw.get("enable").and_then(Value::as_bool) == Some(true),
            tag,
            bound_to,
            bound_up,
            clients: Vec::new(),
            links: Vec::new(),
            listen: scalar_string(raw.get("listen")),
            network: stream
                .as_ref()
                .map(|stream| scalar_string(stream.get("network")))
                .unwrap_or_default(),
            tls: stream
                .as_ref()
                .map(|stream| scalar_string(stream.get("security")))
                .unwrap_or_default(),
        };
        let clients = settings
            .get("clients")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for client in clients {
            let Some(client) = client.as_object() else {
                continue;
            };
            let info = ClientInfo {
                email: scalar_string(client.get("email")),
                id: scalar_string(client.get("id")),
                enable: client.get("enable") != Some(&Value::Bool(false)),
            };
            if let Ok(links) = self.client_links(&info.email).await {
                for link in links {
                    if let Some((fixed, true)) = link_for_port(&link, port, public_host) {
                        detail.links.push(fixed);
                    }
                }
            }
            detail.clients.push(info);
        }
        Ok(detail)
    }

    async fn client_links(&self, email: &str) -> Result<Vec<String>> {
        let path = format!("panel/api/clients/links/{}", url_encode(email));
        let obj = self.call(Method::GET, &path, None, true).await?;
        serde_json::from_value(obj).context("解析客户端分享链接失败")
    }

    async fn delete_inbounds_runtime(&self, ids: &[i64]) -> Result<usize> {
        for id in ids {
            self.call(
                Method::POST,
                &format!("panel/api/inbounds/del/{id}"),
                None,
                true,
            )
            .await
            .with_context(|| format!("删除入站 {id} 失败"))?;
        }
        let runtime = self.runtime().await;
        let (mut setting, test_url) = self.load_xray().await?;
        sync_outbounds_with_runtime(&mut setting, &runtime);
        let remain = self.inbounds_snapshot().await?;
        let alive: HashSet<String> = remain.into_iter().map(|ib| ib.tag).collect();
        let mut routing = setting
            .get("routing")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let rules = routing
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut cleaned = Vec::with_capacity(rules.len());
        for rule in rules {
            let Some(mut object) = rule.as_object().cloned() else {
                cleaned.push(rule);
                continue;
            };
            if !scalar_string(object.get("outboundTag")).starts_with(XUI_TAG_PREFIX) {
                cleaned.push(Value::Object(object));
                continue;
            }
            let kept: Vec<Value> = to_string_slice(object.get("inboundTag"))
                .into_iter()
                .filter(|tag| alive.contains(tag))
                .map(Value::String)
                .collect();
            if !kept.is_empty() {
                object.insert("inboundTag".into(), Value::Array(kept));
                cleaned.push(Value::Object(object));
            }
        }
        routing.insert("rules".into(), Value::Array(cleaned));
        setting.insert("routing".into(), Value::Object(routing));
        self.save_xray(setting, test_url).await?;
        Ok(ids.len())
    }

    async fn rebind_runtime(&self, old_host: &str, new_host: &str) -> Result<()> {
        let runtime = self.runtime().await;
        let target = runtime
            .tunnels
            .iter()
            .find(|tunnel| tunnel.node.hostname == new_host)
            .ok_or_else(|| anyhow!("节点 {new_host} 没有运行中的隧道"))?;
        let new_label = exit_label(target);
        let list = self.inbounds_snapshot().await?;
        let old_tag = sanitize_tag(old_host);
        for ib in list {
            if ib.bound_to != old_tag {
                continue;
            }
            self.bind_runtime(&ib.tag, new_host).await?;
            let renamed = rename_exit_label(&ib.remark, &new_label);
            if renamed != ib.remark {
                self.rename_inbound(parse_id(&ib.id)?, &renamed).await?;
            }
        }
        Ok(())
    }

    async fn rename_inbound(&self, id: i64, remark: &str) -> Result<()> {
        self.update_inbound_raw(id, "改名", move |payload, _| {
            payload.insert("remark".into(), Value::String(remark.to_string()));
            Ok(())
        })
        .await
    }

    async fn update_inbound_raw<F>(&self, id: i64, what: &str, mutate: F) -> Result<()>
    where
        F: FnOnce(&mut Map<String, Value>, &Map<String, Value>) -> Result<()>,
    {
        let raw = self.raw_inbound(id).await?;
        let mut payload = inbound_payload(&raw);
        mutate(&mut payload, &raw)?;
        let envelope = self
            .json_call(
                &format!("panel/api/inbounds/update/{id}"),
                &Value::Object(payload),
            )
            .await?;
        if envelope["success"].as_bool() != Some(true) {
            bail!("{what}失败: {}", envelope["msg"].as_str().unwrap_or(""));
        }
        Ok(())
    }

    async fn update_inbound_runtime(&self, id: i64, patch: &InboundPatch) -> Result<()> {
        let mut old_tag = String::new();
        let mut bound_to = String::new();
        if let Some(port) = patch.port {
            let used = self.used_ports().await?;
            let current = self.raw_inbound(id).await?;
            if value_to_u16(current.get("port")) != port && used.contains(&port) {
                bail!("端口 {port} 已被别的入站占用");
            }
            let list = self.inbounds_snapshot().await?;
            if let Some(ib) = list
                .into_iter()
                .find(|ib| parse_id(&ib.id).ok() == Some(id))
            {
                old_tag = ib.tag;
                bound_to = ib.bound_to;
            }
        }

        self.update_inbound_raw(id, "改入站", |payload, _| {
            if let Some(port) = patch.port {
                payload.insert("port".into(), json!(port));
            }
            if let Some(remark) = &patch.remark {
                payload.insert("remark".into(), Value::String(remark.clone()));
            }
            if let Some(enable) = patch.enable {
                payload.insert("enable".into(), Value::Bool(enable));
            }
            Ok(())
        })
        .await?;

        if old_tag.is_empty() || bound_to.is_empty() {
            return Ok(());
        }
        let list = self.inbounds_snapshot().await?;
        let Some(ib) = list
            .into_iter()
            .find(|ib| parse_id(&ib.id).ok() == Some(id) && ib.tag != old_tag)
        else {
            return Ok(());
        };
        let runtime = self.runtime().await;
        for tunnel in &runtime.tunnels {
            if sanitize_tag(&tunnel.node.hostname) == bound_to {
                return self.bind_runtime(&ib.tag, &tunnel.node.hostname).await;
            }
        }
        Ok(())
    }

    async fn add_client_runtime(&self, id: i64, email: &str) -> Result<()> {
        let raw = self.raw_inbound(id).await?;
        let protocol = scalar_string(raw.get("protocol"));
        let email = if email.is_empty() {
            format!(
                "{protocol}-{}-{}",
                value_to_u16(raw.get("port")),
                random_hex(3)
            )
        } else {
            email.to_string()
        };
        self.update_inbound_raw(id, "加客户端", move |payload, raw| {
            let mut settings = as_object(raw.get("settings")).context("解析 settings 失败")?;
            let clients = settings
                .get("clients")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for client in &clients {
                if client
                    .as_object()
                    .is_some_and(|client| scalar_string(client.get("email")) == email)
                {
                    bail!("客户端 {email} 已存在");
                }
            }
            let mut clients = clients;
            clients.push(Value::Object(new_client_entry(&protocol, &email)));
            settings.insert("clients".into(), Value::Array(clients));
            payload.insert("settings".into(), Value::String(settings.to_string()));
            Ok(())
        })
        .await
    }

    async fn delete_client_runtime(&self, id: i64, email: &str) -> Result<()> {
        self.update_inbound_raw(id, "删客户端", move |payload, raw| {
            let mut settings = as_object(raw.get("settings")).context("解析 settings 失败")?;
            let clients = settings
                .get("clients")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let kept: Vec<Value> = clients
                .iter()
                .filter(|client| {
                    client
                        .as_object()
                        .is_none_or(|client| scalar_string(client.get("email")) != email)
                })
                .cloned()
                .collect();
            if kept.len() == clients.len() {
                bail!("客户端 {email} 不存在");
            }
            if kept.is_empty() {
                bail!("这是最后一个客户端，删掉入站就没人能连了");
            }
            settings.insert("clients".into(), Value::Array(kept));
            payload.insert("settings".into(), Value::String(settings.to_string()));
            Ok(())
        })
        .await
    }

    async fn reset_client_runtime(&self, id: i64, email: &str) -> Result<ClientInfo> {
        let raw = self.raw_inbound(id).await?;
        let protocol = scalar_string(raw.get("protocol"));
        let mut reset_info: Option<ClientInfo> = None;
        self.update_inbound_raw(id, "重置凭据", move |payload, raw| {
            let mut settings = as_object(raw.get("settings")).context("解析 settings 失败")?;
            let mut clients = settings
                .get("clients")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut found = false;
            for client in &mut clients {
                let Some(client) = client.as_object_mut() else {
                    continue;
                };
                if scalar_string(client.get("email")) != email {
                    continue;
                }
                found = true;
                let credential = if protocol == "trojan" {
                    client.insert("password".into(), Value::String(random_hex(8)));
                    scalar_string(client.get("password"))
                } else {
                    let id = Uuid::new_v4().to_string();
                    client.insert("id".into(), Value::String(id.clone()));
                    id
                };
                reset_info = Some(ClientInfo {
                    email: email.to_string(),
                    id: credential,
                    enable: client.get("enable") != Some(&Value::Bool(false)),
                });
            }
            if !found {
                bail!("客户端 {email} 不存在");
            }
            settings.insert("clients".into(), Value::Array(clients));
            payload.insert("settings".into(), Value::String(settings.to_string()));
            Ok(())
        })
        .await?;
        reset_info.context("重置后未返回客户端信息")
    }

    async fn resync_runtime(&self) -> Result<()> {
        let runtime = self.runtime().await;
        let (mut setting, test_url) = self.load_xray().await?;
        sync_outbounds_with_runtime(&mut setting, &runtime);
        self.save_xray(setting, test_url).await
    }

    async fn create_inbound_runtime(&self, spec: &Value) -> Result<CreatedInbound> {
        let used = self.used_ports().await?;
        let ns = normalize_inbound_spec(spec, &used).await?;
        let tls = match ns.security.as_str() {
            "tls" => Some(build_tls(self.work_dir.as_deref(), &ns).await?),
            _ => None,
        };
        let reality = match ns.security.as_str() {
            "reality" => Some(build_reality(self.work_dir.as_deref(), &ns).await?),
            _ => None,
        };
        let mut client = new_client_entry(&ns.protocol, &format!("{}-{}", ns.protocol, ns.port));
        if ns.protocol == "vless" {
            client.insert("flow".into(), Value::String(ns.flow.clone()));
        }
        let mut settings = Map::new();
        settings.insert("clients".into(), Value::Array(vec![Value::Object(client)]));
        settings.insert("fallbacks".into(), Value::Array(Vec::new()));
        if ns.protocol == "vless" {
            settings.insert("decryption".into(), Value::String("none".into()));
        }
        let payload = json!({
            "enable": true,
            "remark": ns.remark.clone(),
            "listen": "",
            "port": ns.port,
            "protocol": ns.protocol.clone(),
            "expiryTime": 0,
            "total": 0,
            "settings": Value::String(Value::Object(settings).to_string()),
            "streamSettings": Value::String(
                xui_stream_settings(&ns, tls.as_ref(), reality.as_ref()).to_string()
            ),
            "sniffing": Value::String(json!({
                "enabled": true,
                "destOverride": ["http", "tls"],
            }).to_string()),
            "allocate": "{}",
        });
        let id = self
            .add_inbound(&payload)
            .await
            .context("面板新建入站失败")?;
        Ok(CreatedInbound {
            id: id.to_string(),
            port: ns.port,
            protocol: ns.protocol,
            remark: ns.remark,
            network: ns.network,
            security: ns.security,
        })
    }
}

#[async_trait]
impl Panel for XUI {
    fn kind(&self) -> String {
        "3x-ui".into()
    }

    fn describe(&self) -> String {
        format!("接管本机 3x-ui 面板（{}:{}）", self.host, self.port)
    }

    async fn inbounds(&self) -> Result<Vec<Inbound>> {
        self.inbounds_snapshot().await
    }

    async fn inbound_detail(&self, id: &str, host: &str) -> Result<InboundDetail> {
        self.inbound_detail_snapshot(parse_id(id)?, host).await
    }

    async fn inbound_links(&self, ids: &[String], host: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for id in ids {
            let detail = self.inbound_detail_snapshot(parse_id(id)?, host).await?;
            out.extend(detail.links);
        }
        Ok(out)
    }

    async fn bind(&self, tag: &str, host: &str) -> Result<()> {
        self.bind_runtime(tag, host).await
    }

    async fn rebind(&self, old_host: &str, new_host: &str) -> Result<()> {
        self.rebind_runtime(old_host, new_host).await
    }

    async fn resync_outbound(&self, _host: &str) -> Result<()> {
        self.resync_runtime().await
    }

    async fn clone_to_tunnels(&self, id: &str, hosts: &[String]) -> Result<Vec<u16>> {
        self.clone_to_tunnels_runtime(parse_id(id)?, hosts).await
    }

    async fn delete_inbounds(&self, ids: &[String]) -> Result<usize> {
        let ids: Result<Vec<i64>> = ids.iter().map(|id| parse_id(id)).collect();
        self.delete_inbounds_runtime(&ids?).await
    }

    async fn create_inbound(&self, spec: &Value) -> Result<CreatedInbound> {
        self.create_inbound_runtime(spec).await
    }

    async fn update_inbound(&self, id: &str, patch: &InboundPatch) -> Result<()> {
        self.update_inbound_runtime(parse_id(id)?, patch).await
    }

    async fn add_client(&self, id: &str, email: &str) -> Result<()> {
        self.add_client_runtime(parse_id(id)?, email).await
    }

    async fn delete_client(&self, id: &str, email: &str) -> Result<()> {
        self.delete_client_runtime(parse_id(id)?, email).await
    }

    async fn reset_client(&self, id: &str, email: &str) -> Result<ClientInfo> {
        self.reset_client_runtime(parse_id(id)?, email).await
    }

    async fn on_tunnels_changed(&self) -> Result<()> {
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        // Xray is owned by 3x-ui. The Go XUI backend intentionally does not
        // stop it; template writes above already trigger a reload.
        Ok(())
    }
}

#[derive(Debug)]
struct PanelAuth {
    path: String,
    status: StatusCode,
}

impl std::fmt::Display for PanelAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "面板拒绝当前 API token: 调用 {} 返回 HTTP {}",
            self.path,
            self.status.as_u16()
        )
    }
}

impl std::error::Error for PanelAuth {}

fn is_panel_auth(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.downcast_ref::<PanelAuth>().is_some())
}

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    msg: String,
    #[serde(default)]
    obj: Value,
}

fn panel_backoff(attempt: usize) -> Duration {
    let millis = 200u64 * (1u64 << (attempt.saturating_sub(1)));
    let jitter = rand::thread_rng().gen_range(0..120);
    Duration::from_millis(millis + jitter)
}

fn local_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .danger_accept_invalid_certs(true)
        .build()
        .context("创建 3x-ui HTTP 客户端失败")
}

async fn command_output(mut command: Command) -> Result<std::process::Output> {
    command.output().await.context("执行命令失败")
}

async fn command_output_checked(command: Command) -> Result<std::process::Output> {
    let out = command_output(command).await?;
    if !out.status.success() {
        bail!(
            "命令执行失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out)
}

async fn command_succeeded(mut command: Command) -> bool {
    command.status().await.is_ok_and(|status| status.success())
}

async fn xui_running_async() -> bool {
    if command_succeeded(Command::new("systemctl").args(["is-active", "--quiet", "x-ui"])).await {
        return true;
    }
    command_succeeded(Command::new("rc-service").args(["x-ui", "status"])).await
}

async fn panel_access() -> Option<(String, String)> {
    let mut command = Command::new(XUI_MENU);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().await.ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"11\n\n0\n").await;
    }
    let out = child.wait_with_output().await.ok()?;
    if !out.status.success() && out.stdout.is_empty() {
        return None;
    }
    let text = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    parse_access_url(&text)
}

/// Detect the local 3x-ui installation, reusing the process cache, then the
/// token saved under `work_dir`, and finally asking the CLI for a new token.
pub async fn detect(work_dir: impl AsRef<Path>) -> Result<XUI> {
    if !xui_running_async().await {
        bail!("本机未安装或未运行 3x-ui");
    }
    let out = command_output_checked(Command::new(XUI_BINARY).args(["setting", "-show"]))
        .await
        .context("读取面板设置失败")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let settings = parse_panel_settings(&text)?;

    let mut scheme = "http".to_string();
    let mut host = "127.0.0.1".to_string();
    if let Some((access_scheme, access_host)) = panel_access().await {
        scheme = access_scheme;
        host = access_host;
    } else {
        let (on, stated) = xui_ssl_from_settings(&text);
        if stated {
            if on {
                scheme = "https".into();
            }
        } else if let Ok(cert) =
            command_output(Command::new(XUI_BINARY).args(["setting", "-getCert"])).await
        {
            if cert.status.success() && xui_cert_configured(&String::from_utf8_lossy(&cert.stdout)) {
                scheme = "https".into();
            }
        }
    }

    let cached = token_cache().lock().await.clone();
    if !cached.is_empty() {
        return XUI::new(host, settings.port, settings.base_path, scheme, cached)?
            .with_work_dir(work_dir);
    }
    if !work_dir.as_ref().as_os_str().is_empty() {
        if let Some(saved) = read_saved_token(work_dir.as_ref()).await {
            let xui = XUI::new(
                host.clone(),
                settings.port,
                settings.base_path.clone(),
                scheme.clone(),
                saved.clone(),
            )?
            .with_work_dir(work_dir.as_ref());
            if xui.saved_token_valid().await {
                *token_cache().lock().await = saved;
                return Ok(xui);
            }
        }
    }

    let token_out =
        command_output_checked(Command::new(XUI_BINARY).args(["setting", "-getApiToken"]))
            .await
            .context("获取 API token 失败")?;
    let token_text = strip_ansi(&String::from_utf8_lossy(&token_out.stdout));
    let token = parse_api_token(&token_text).context("未能取得 API token")?;
    *token_cache().lock().await = token.clone();
    let xui = XUI::new(
        host,
        settings.port,
        settings.base_path,
        scheme,
        token.clone(),
    )?
    .with_work_dir(work_dir);
    if !xui.work_dir().is_some_and(|dir| dir.as_os_str().is_empty()) {
        if let Some(dir) = xui.work_dir() {
            save_token(dir, &token);
        }
    }
    Ok(xui)
}

async fn read_saved_token(work_dir: &Path) -> Option<String> {
    let text = tokio::fs::read_to_string(work_dir.join(XUI_TOKEN_FILE))
        .await
        .ok()?;
    let token = text.trim().to_string();
    (!token.is_empty()).then_some(token)
}

fn save_token(work_dir: &Path, token: &str) {
    if let Err(err) = atomic_write(
        work_dir.join(XUI_TOKEN_FILE),
        format!("{token}\n").as_bytes(),
        0o600,
    ) {
        tracing::warn!("保存 API token 失败（不影响本次运行）: {err:#}");
    }
}

#[derive(Debug)]
struct PanelSettings {
    port: u16,
    base_path: String,
}

fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static regular expression is valid")
}

fn parse_panel_settings(text: &str) -> Result<PanelSettings> {
    let port = regex(r"(?m)^port:[^\S\r\n]*(\d+)")
        .captures(text)
        .and_then(|captures| captures.get(1))
        .and_then(|value| value.as_str().parse::<u16>().ok())
        .context("无法从面板设置中解析端口")?;
    let base_path = regex(r"(?m)^webBasePath:[^\S\r\n]*(\S+)")
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|value| {
            let mut path = value.as_str().to_string();
            if path.ends_with('/') {
                path.pop();
            }
            path
        })
        .context("无法从面板设置中解析路径")?;
    Ok(PanelSettings { port, base_path })
}

fn parse_api_token(text: &str) -> Option<String> {
    regex(r"(?m)^apiToken:[^\S\r\n]*([A-Za-z0-9]+)")
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn xui_ssl_from_settings(text: &str) -> (bool, bool) {
    if regex(r"(?i)panel is not secure with ssl").is_match(text) {
        (false, true)
    } else if regex(r"(?i)panel is secure with ssl").is_match(text) {
        (true, true)
    } else {
        (false, false)
    }
}

fn xui_cert_configured(text: &str) -> bool {
    regex(r"(?m)^cert:[^\S\r\n]*(\S+)").is_match(text)
}

fn parse_access_url(text: &str) -> Option<(String, String)> {
    let captures = regex(r"Access URL:\s*(https?)://([^:/\s]+):(\d+)(\S*)").captures(text)?;
    Some((
        captures.get(1)?.as_str().to_string(),
        captures.get(2)?.as_str().to_string(),
    ))
}

fn strip_ansi(text: &str) -> String {
    regex(r"\x1b\[[0-9;]*m").replace_all(text, "").into_owned()
}

fn parse_xray_config(obj: &Value) -> Result<(Value, String)> {
    let inner = obj
        .as_str()
        .ok_or_else(|| anyhow!("解析 Xray 配置外层失败: obj 不是字符串"))?;
    #[derive(Deserialize)]
    struct XrayConfig {
        #[serde(rename = "outboundTestUrl", default)]
        outbound_test_url: String,
        #[serde(rename = "xraySetting")]
        xray_setting: Value,
    }
    let config: XrayConfig = serde_json::from_str(inner).context("解析 Xray 配置失败")?;
    let setting = match config.xray_setting {
        Value::String(inner) => serde_json::from_str(&inner).context("解析 xraySetting 失败")?,
        value => value,
    };
    if !setting.is_object() {
        bail!("解析 xraySetting 失败: 不是对象");
    }
    Ok((setting, config.outbound_test_url))
}

fn scalar_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn value_to_i64(value: Option<&Value>) -> i64 {
    value
        .and_then(|value| match value {
            Value::Number(number) => number.as_i64(),
            Value::String(value) => value.parse().ok(),
            _ => None,
        })
        .unwrap_or(0)
}

fn value_to_u16(value: Option<&Value>) -> u16 {
    value
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64().and_then(|value| u16::try_from(value).ok()),
            Value::String(value) => value.parse().ok(),
            _ => None,
        })
        .unwrap_or(0)
}

fn value_to_u64(value: Option<&Value>) -> u64 {
    value
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64(),
            Value::String(value) => value.parse().ok(),
            _ => None,
        })
        .unwrap_or(0)
}

fn parse_id(id: &str) -> Result<i64> {
    id.parse::<i64>()
        .with_context(|| format!("无效的入站 id: {id}"))
}

fn inbound_tag(port: u16, stream_settings: &Value) -> String {
    let mut network = "tcp".to_string();
    let mut value = stream_settings;
    let decoded;
    if let Value::String(inner) = stream_settings {
        if let Ok(parsed) = serde_json::from_str::<Value>(inner) {
            decoded = parsed;
            value = &decoded;
        }
    }
    if let Some(stream) = value.as_object() {
        let candidate = scalar_string(stream.get("network"));
        if !candidate.is_empty() {
            network = candidate;
        }
    }
    format!("in-{port}-{network}")
}

fn resolved_inbound_tag(api_tag: &str, port: u16, stream_settings: &Value) -> String {
    if api_tag.is_empty() {
        inbound_tag(port, stream_settings)
    } else {
        api_tag.to_string()
    }
}

fn inbound_tag_of(port: u16, template: &Map<String, Value>) -> String {
    inbound_tag(port, template.get("streamSettings").unwrap_or(&Value::Null))
}

fn egress_tag(identity: &str) -> String {
    format!("{XUI_TAG_PREFIX}{}", sanitize_tag(identity))
}

fn pool_identity(id: &str) -> String {
    format!("{POOL_TAG_PREFIX}{id}")
}

fn sanitize_tag(name: &str) -> String {
    let mut out = String::new();
    for character in name.chars() {
        if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
            out.push(character);
        } else {
            out.push('-');
        }
    }
    if out.is_empty() {
        "unknown".into()
    } else {
        out
    }
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

fn bound_from_setting(setting: &Value) -> HashMap<String, String> {
    let mut bound = HashMap::new();
    let Some(routing) = setting.get("routing").and_then(Value::as_object) else {
        return bound;
    };
    let Some(rules) = routing.get("rules").and_then(Value::as_array) else {
        return bound;
    };
    for rule in rules {
        let Some(rule) = rule.as_object() else {
            continue;
        };
        let tag = scalar_string(rule.get("outboundTag"));
        let Some(host) = tag.strip_prefix(XUI_TAG_PREFIX) else {
            continue;
        };
        if is_all_digits(host) {
            continue;
        }
        for inbound in to_string_slice(rule.get("inboundTag")) {
            bound.insert(inbound, host.to_string());
        }
    }
    bound
}

fn socks_server(port: u16, user: &str, pass: &str) -> Value {
    let mut server = Map::new();
    server.insert("address".into(), Value::String("127.0.0.1".into()));
    server.insert("port".into(), json!(port));
    if !user.is_empty() {
        server.insert(
            "users".into(),
            Value::Array(vec![json!({"user": user, "pass": pass})]),
        );
    }
    Value::Object(server)
}

fn force_ipv4(outbound: &mut Map<String, Value>) {
    if scalar_string(outbound.get("protocol")) != "freedom" {
        return;
    }
    let mut settings = outbound
        .get("settings")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    settings.insert("domainStrategy".into(), Value::String("UseIPv4".into()));
    outbound.insert("settings".into(), Value::Object(settings));
}

fn sync_outbounds_with_runtime(setting: &mut Value, runtime: &Runtime) {
    let setting = setting.as_object_mut().expect("Xray setting is an object");
    let old = setting
        .get("outbounds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut kept = Vec::with_capacity(old.len() + runtime.tunnels.len() + runtime.pools.len());
    for outbound in old {
        if let Some(mut object) = outbound.as_object().cloned() {
            let tag = scalar_string(object.get("tag"));
            if tag.starts_with(XUI_TAG_PREFIX) {
                continue;
            }
            force_ipv4(&mut object);
            kept.push(Value::Object(object));
        } else {
            kept.push(outbound);
        }
    }
    for tunnel in runtime
        .tunnels
        .iter()
        .filter(|tunnel| tunnel.status == "up")
    {
        kept.push(json!({
            "tag": egress_tag(&tunnel.node.hostname),
            "protocol": "socks",
            "settings": {
                "servers": [socks_server(tunnel.port, &tunnel.cred.user, &tunnel.cred.pass)],
            },
        }));
    }
    for pool in &runtime.pools {
        kept.push(json!({
            "tag": egress_tag(&pool_identity(&pool.id)),
            "protocol": "socks",
            "settings": {
                "servers": [socks_server(pool.port, &pool.socks_user, &pool.socks_pass)],
            },
        }));
    }
    setting.insert("outbounds".into(), Value::Array(kept));
}

async fn free_random_port(taken: &HashSet<u16>) -> Result<u16> {
    for _ in 0..200 {
        let port = rand::thread_rng().gen_range(RAND_PORT_MIN..RAND_PORT_MAX);
        if taken.contains(&port) {
            continue;
        }
        if tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .is_ok()
        {
            return Ok(port);
        }
    }
    bail!("找不到可用端口（已尝试 200 次）")
}

fn as_object(value: Option<&Value>) -> Result<Map<String, Value>> {
    match value {
        Some(Value::Object(value)) => Ok(value.clone()),
        Some(Value::String(value)) => {
            let parsed: Value = serde_json::from_str(value).context("无法解析为对象")?;
            parsed
                .as_object()
                .cloned()
                .ok_or_else(|| anyhow!("无法解析为对象"))
        }
        _ => bail!("无法解析为对象"),
    }
}

fn must_json_field(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(value) => value.to_string(),
        None => Value::Null.to_string(),
    }
}

fn inbound_payload(raw: &Map<String, Value>) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert(
        "enable".into(),
        raw.get("enable").cloned().unwrap_or(Value::Null),
    );
    payload.insert(
        "remark".into(),
        Value::String(scalar_string(raw.get("remark"))),
    );
    payload.insert(
        "listen".into(),
        Value::String(scalar_string(raw.get("listen"))),
    );
    payload.insert("port".into(), json!(value_to_u16(raw.get("port"))));
    payload.insert(
        "protocol".into(),
        Value::String(scalar_string(raw.get("protocol"))),
    );
    payload.insert("expiryTime".into(), json!(0));
    payload.insert("total".into(), json!(0));
    payload.insert(
        "settings".into(),
        Value::String(must_json_field(raw.get("settings"))),
    );
    payload.insert(
        "streamSettings".into(),
        Value::String(must_json_field(raw.get("streamSettings"))),
    );
    payload.insert(
        "sniffing".into(),
        Value::String(must_json_field(raw.get("sniffing"))),
    );
    payload.insert("allocate".into(), Value::String("{}".into()));
    payload
}

fn clone_inbound_payload(
    template: &Map<String, Value>,
    port: u16,
    tunnel: &TunnelState,
) -> Result<Map<String, Value>> {
    let mut settings = as_object(template.get("settings"))?;
    settings.insert("clients".into(), Value::Array(Vec::new()));
    let stream = as_object(template.get("streamSettings"))?;
    let sniffing = as_object(template.get("sniffing")).unwrap_or_else(|_| {
        Map::from_iter([
            ("enabled".into(), Value::Bool(true)),
            ("destOverride".into(), json!(["http", "tls"])),
        ])
    });
    let mut payload = Map::new();
    payload.insert("enable".into(), Value::Bool(true));
    payload.insert("remark".into(), Value::String(exit_label(tunnel)));
    payload.insert(
        "listen".into(),
        Value::String(scalar_string(template.get("listen"))),
    );
    payload.insert("port".into(), json!(port));
    payload.insert(
        "protocol".into(),
        Value::String(scalar_string(template.get("protocol"))),
    );
    payload.insert("expiryTime".into(), json!(0));
    payload.insert("total".into(), json!(0));
    payload.insert(
        "settings".into(),
        Value::String(Value::Object(settings).to_string()),
    );
    payload.insert(
        "streamSettings".into(),
        Value::String(Value::Object(stream).to_string()),
    );
    payload.insert(
        "sniffing".into(),
        Value::String(Value::Object(sniffing).to_string()),
    );
    payload.insert("allocate".into(), Value::String("{}".into()));
    Ok(payload)
}

fn client_emails(template: &Map<String, Value>) -> Result<Vec<String>> {
    let settings = as_object(template.get("settings"))?;
    let mut emails = Vec::new();
    if let Some(clients) = settings.get("clients").and_then(Value::as_array) {
        for client in clients {
            if let Some(client) = client.as_object() {
                let email = scalar_string(client.get("email"));
                if !email.is_empty() {
                    emails.push(email);
                }
            }
        }
    }
    Ok(emails)
}

fn new_client_entry(protocol: &str, email: &str) -> Map<String, Value> {
    let mut client = Map::from_iter([
        ("email".into(), Value::String(email.to_string())),
        ("enable".into(), Value::Bool(true)),
        ("comment".into(), Value::String(String::new())),
        ("security".into(), Value::String(String::new())),
        ("expiryTime".into(), json!(0)),
        ("totalGB".into(), json!(0)),
        ("limitIp".into(), json!(0)),
        ("tgId".into(), json!(0)),
        ("subId".into(), Value::String(String::new())),
        ("reset".into(), json!(0)),
    ]);
    if protocol == "trojan" {
        client.insert("password".into(), Value::String(random_hex(8)));
    } else {
        client.insert("id".into(), Value::String(Uuid::new_v4().to_string()));
    }
    if protocol == "vless" {
        client.insert("flow".into(), Value::String(String::new()));
    }
    client
}

fn link_for_port(link: &str, port: u16, public_host: &str) -> Option<(String, bool)> {
    if let Some(link) = link.strip_prefix("vmess://") {
        return fix_vmess_link(link, port, public_host);
    }
    let query = format!(":{port}?");
    let fragment = format!(":{port}#");
    if link.contains(&query) || link.contains(&fragment) {
        Some((
            link.replacen("@localhost:", &format!("@{public_host}:"), 1),
            true,
        ))
    } else {
        None
    }
}

fn fix_vmess_link(payload: &str, port: u16, public_host: &str) -> Option<(String, bool)> {
    let Ok(blob) = BASE64_STANDARD.decode(payload) else {
        let query = format!(":{port}?");
        let fragment = format!(":{port}#");
        return Some((
            String::new(),
            payload.contains(&query) || payload.contains(&fragment),
        ));
    };
    let mut config: Value = serde_json::from_slice(&blob).ok()?;
    if value_to_u16(config.get("port")) != port {
        return None;
    }
    if config.get("add").and_then(Value::as_str) == Some("localhost") {
        config["add"] = Value::String(public_host.to_string());
    }
    let fixed = serde_json::to_vec(&config).ok()?;
    Some((format!("vmess://{}", BASE64_STANDARD.encode(fixed)), true))
}

fn flag_of(code: &str) -> String {
    if code.len() != 2 || !code.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return String::new();
    }
    code.chars()
        .map(|character| char::from_u32(0x1F1E6 + (character as u32 - 'A' as u32)).unwrap())
        .collect()
}

fn country_label(code: &str, fallback: &str) -> String {
    let code = code.trim().to_ascii_uppercase();
    let name = match code.as_str() {
        "JP" => "日本",
        "KR" => "韩国",
        "KP" => "朝鲜",
        "CN" => "中国",
        "HK" => "香港",
        "TW" => "台湾",
        "MO" => "澳门",
        "MN" => "蒙古",
        "SG" => "新加坡",
        "MY" => "马来西亚",
        "TH" => "泰国",
        "VN" => "越南",
        "PH" => "菲律宾",
        "ID" => "印尼",
        "BN" => "文莱",
        "KH" => "柬埔寨",
        "LA" => "老挝",
        "MM" => "缅甸",
        "TL" => "东帝汶",
        "IN" => "印度",
        "PK" => "巴基斯坦",
        "BD" => "孟加拉",
        "LK" => "斯里兰卡",
        "NP" => "尼泊尔",
        "BT" => "不丹",
        "MV" => "马尔代夫",
        "AF" => "阿富汗",
        "KZ" => "哈萨克斯坦",
        "UZ" => "乌兹别克斯坦",
        "KG" => "吉尔吉斯斯坦",
        "TJ" => "塔吉克斯坦",
        "TM" => "土库曼斯坦",
        "TR" => "土耳其",
        "IL" => "以色列",
        "AE" => "阿联酋",
        "SA" => "沙特",
        "QA" => "卡塔尔",
        "KW" => "科威特",
        "BH" => "巴林",
        "OM" => "阿曼",
        "JO" => "约旦",
        "LB" => "黎巴嫩",
        "SY" => "叙利亚",
        "IQ" => "伊拉克",
        "IR" => "伊朗",
        "YE" => "也门",
        "GE" => "格鲁吉亚",
        "AM" => "亚美尼亚",
        "AZ" => "阿塞拜疆",
        "CY" => "塞浦路斯",
        "RU" => "俄罗斯",
        "UA" => "乌克兰",
        "BY" => "白俄罗斯",
        "MD" => "摩尔多瓦",
        "PL" => "波兰",
        "CZ" => "捷克",
        "SK" => "斯洛伐克",
        "HU" => "匈牙利",
        "RO" => "罗马尼亚",
        "BG" => "保加利亚",
        "RS" => "塞尔维亚",
        "HR" => "克罗地亚",
        "SI" => "斯洛文尼亚",
        "BA" => "波黑",
        "ME" => "黑山",
        "MK" => "北马其顿",
        "AL" => "阿尔巴尼亚",
        "GR" => "希腊",
        "IT" => "意大利",
        "ES" => "西班牙",
        "PT" => "葡萄牙",
        "FR" => "法国",
        "DE" => "德国",
        "AT" => "奥地利",
        "CH" => "瑞士",
        "NL" => "荷兰",
        "BE" => "比利时",
        "LU" => "卢森堡",
        "GB" => "英国",
        "IE" => "爱尔兰",
        "DK" => "丹麦",
        "SE" => "瑞典",
        "NO" => "挪威",
        "FI" => "芬兰",
        "IS" => "冰岛",
        "EE" => "爱沙尼亚",
        "LV" => "拉脱维亚",
        "LT" => "立陶宛",
        "MT" => "马耳他",
        "MC" => "摩纳哥",
        "AD" => "安道尔",
        "SM" => "圣马力诺",
        "LI" => "列支敦士登",
        "US" => "美国",
        "CA" => "加拿大",
        "MX" => "墨西哥",
        "BR" => "巴西",
        "AR" => "阿根廷",
        "CL" => "智利",
        "CO" => "哥伦比亚",
        "PE" => "秘鲁",
        "VE" => "委内瑞拉",
        "EC" => "厄瓜多尔",
        "BO" => "玻利维亚",
        "PY" => "巴拉圭",
        "UY" => "乌拉圭",
        "CR" => "哥斯达黎加",
        "PA" => "巴拿马",
        "GT" => "危地马拉",
        "HN" => "洪都拉斯",
        "SV" => "萨尔瓦多",
        "NI" => "尼加拉瓜",
        "CU" => "古巴",
        "DO" => "多米尼加",
        "PR" => "波多黎各",
        "JM" => "牙买加",
        "TT" => "特立尼达",
        "BS" => "巴哈马",
        "BZ" => "伯利兹",
        "EG" => "埃及",
        "MA" => "摩洛哥",
        "DZ" => "阿尔及利亚",
        "TN" => "突尼斯",
        "LY" => "利比亚",
        "SD" => "苏丹",
        "ET" => "埃塞俄比亚",
        "KE" => "肯尼亚",
        "TZ" => "坦桑尼亚",
        "UG" => "乌干达",
        "RW" => "卢旺达",
        "NG" => "尼日利亚",
        "GH" => "加纳",
        "CI" => "科特迪瓦",
        "SN" => "塞内加尔",
        "CM" => "喀麦隆",
        "CD" => "刚果金",
        "CG" => "刚果布",
        "AO" => "安哥拉",
        "MZ" => "莫桑比克",
        "ZM" => "赞比亚",
        "ZW" => "津巴布韦",
        "BW" => "博茨瓦纳",
        "NA" => "纳米比亚",
        "ZA" => "南非",
        "MU" => "毛里求斯",
        "MG" => "马达加斯加",
        "AU" => "澳大利亚",
        "NZ" => "新西兰",
        "FJ" => "斐济",
        "PG" => "巴新",
        "NC" => "新喀里多尼亚",
        "GU" => "关岛",
        _ => "",
    };
    let name = if name.is_empty() {
        fallback.trim()
    } else {
        name
    };
    let name = if name.is_empty() { code.as_str() } else { name };
    let flag = flag_of(&code);
    if flag.is_empty() {
        name.to_string()
    } else if name.is_empty() {
        flag
    } else {
        format!("{flag} {name}")
    }
}

fn exit_label(tunnel: &TunnelState) -> String {
    let place = country_label(&tunnel.node.country_code, &tunnel.node.country);
    let suffix = if tunnel.exit_ip.is_empty() {
        tunnel.node.hostname.clone()
    } else {
        tunnel
            .exit_ip
            .rsplit_once('.')
            .map(|(_, suffix)| suffix.to_string())
            .unwrap_or_else(|| tunnel.exit_ip.clone())
    };
    if place.is_empty() {
        suffix
    } else {
        format!("{place} {suffix}")
    }
}

fn rename_exit_label(remark: &str, new_label: &str) -> String {
    let generated = remark
        .trim_start()
        .chars()
        .next()
        .is_some_and(|character| ('\u{1F1E6}'..='\u{1F1FF}').contains(&character));
    if new_label.is_empty() || !generated {
        remark.to_string()
    } else {
        new_label.to_string()
    }
}

fn unique_remark(want: &str, taken: &HashSet<String>) -> String {
    if want.is_empty() || !taken.contains(want) {
        return want.to_string();
    }
    for index in 2..1000 {
        let candidate = format!("{want} {index}");
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    want.to_string()
}

#[derive(Clone, Debug)]
struct NormalizedSpec {
    protocol: String,
    network: String,
    security: String,
    port: u16,
    path: String,
    host: String,
    remark: String,
    flow: String,
    server_name: String,
    cert_file: String,
    key_file: String,
    dest: String,
    server_names: String,
    short_id: String,
    fingerprint: String,
}

fn field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| value.get(*name))
}

fn text_field(value: &Value, names: &[&str]) -> String {
    field(value, names)
        .map(|value| scalar_string(Some(value)).trim().to_string())
        .unwrap_or_default()
}

async fn normalize_inbound_spec(spec: &Value, used: &HashSet<u16>) -> Result<NormalizedSpec> {
    let mut protocol = text_field(spec, &["protocol", "Protocol"]).to_ascii_lowercase();
    if protocol.is_empty() {
        protocol = "vless".into();
    }
    if !matches!(protocol.as_str(), "vless" | "vmess" | "trojan") {
        bail!("不支持的协议 {protocol:?}");
    }
    let mut network = text_field(spec, &["network", "Network"]).to_ascii_lowercase();
    if network.is_empty() {
        network = "tcp".into();
    }
    if !matches!(
        network.as_str(),
        "tcp" | "ws" | "grpc" | "httpupgrade" | "xhttp"
    ) {
        bail!("不支持的传输方式 {network:?}");
    }
    let mut security = text_field(spec, &["security", "Security"]).to_ascii_lowercase();
    if security.is_empty() {
        security = "none".into();
    }
    if !matches!(security.as_str(), "none" | "tls" | "reality") {
        bail!("不支持的安全层 {security:?}");
    }
    if security == "reality" && !matches!(network.as_str(), "tcp" | "xhttp" | "grpc") {
        bail!("REALITY 不支持 {network} 传输");
    }

    let requested_port = value_to_u64(field(spec, &["port", "Port"]));
    if requested_port > u16::MAX as u64 {
        bail!("端口 {requested_port} 超出范围");
    }
    let port = if requested_port == 0 {
        free_random_port(used).await?
    } else {
        let port = requested_port as u16;
        if used.contains(&port) {
            bail!("端口 {port} 已被别的入站占用");
        }
        port
    };

    let mut path = text_field(spec, &["path", "Path"]);
    if path.is_empty() {
        path = match network.as_str() {
            "ws" | "httpupgrade" | "xhttp" => format!("/{}", random_hex(6)),
            "grpc" => random_hex(6),
            _ => String::new(),
        };
    }
    let mut remark = text_field(spec, &["remark", "Remark"]);
    if remark.is_empty() {
        remark = format!("{protocol}-{port}");
    }
    let vision = field(spec, &["vision", "Vision"]).is_some_and(|value| {
        value.as_bool() == Some(true) || value.as_i64() == Some(1) || value.as_str() == Some("1")
    });
    let flow = if vision {
        if protocol != "vless"
            || network != "tcp"
            || !matches!(security.as_str(), "tls" | "reality")
        {
            bail!("xtls-rprx-vision 只能用于 VLESS + TCP + TLS/REALITY");
        }
        "xtls-rprx-vision".to_string()
    } else {
        String::new()
    };
    Ok(NormalizedSpec {
        protocol,
        network,
        security,
        port,
        path,
        host: text_field(spec, &["host", "Host"]),
        remark,
        flow,
        server_name: text_field(spec, &["sni", "serverName", "server_name", "ServerName"]),
        cert_file: text_field(spec, &["cert", "certFile", "cert_file", "CertFile"]),
        key_file: text_field(spec, &["key", "keyFile", "key_file", "KeyFile"]),
        dest: text_field(spec, &["dest", "Dest"]),
        server_names: text_field(spec, &["server_names", "serverNames", "ServerNames"]),
        short_id: text_field(spec, &["sid", "shortID", "short_id", "ShortID"]),
        fingerprint: text_field(spec, &["fp", "fingerprint", "Fingerprint"]),
    })
}

#[derive(Debug)]
struct TlsConfig {
    cert_file: String,
    key_file: String,
    server_name: String,
}

async fn build_tls(work_dir: Option<&Path>, spec: &NormalizedSpec) -> Result<TlsConfig> {
    let server_name = if spec.server_name.is_empty() {
        "localhost".to_string()
    } else {
        spec.server_name.clone()
    };
    if spec.cert_file.is_empty() != spec.key_file.is_empty() {
        bail!("证书和私钥要成对填写，或者都留空用自签证书");
    }
    if !spec.cert_file.is_empty() {
        if !fs::metadata(Path::new(&spec.cert_file))
            .with_context(|| format!("证书文件不可读: {}", spec.cert_file))?
            .is_file()
        {
            bail!("证书文件不可读: {}", spec.cert_file);
        }
        if !fs::metadata(Path::new(&spec.key_file))
            .with_context(|| format!("私钥文件不可读: {}", spec.key_file))?
            .is_file()
        {
            bail!("私钥文件不可读: {}", spec.key_file);
        }
        return Ok(TlsConfig {
            cert_file: spec.cert_file.clone(),
            key_file: spec.key_file.clone(),
            server_name,
        });
    }
    let dir = work_dir.unwrap_or_else(|| Path::new(""));
    let cert_dir = dir.join("certs");
    fs::create_dir_all(&cert_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cert_dir, fs::Permissions::from_mode(0o700))?;
    }
    let base = cert_dir.join(sanitize_tag(&server_name));
    let cert_file = base.with_extension("crt");
    let key_file = base.with_extension("key");
    let out = command_output(
        Command::new("openssl")
            .args([
                "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "3650", "-keyout",
            ])
            .arg(&key_file)
            .args(["-out"])
            .arg(&cert_file)
            .args(["-subj"])
            .arg(format!("/CN={server_name}"))
            .arg("-addext")
            .arg(format!("subjectAltName=DNS:{server_name}")),
    )
    .await?;
    if !out.status.success() {
        bail!(
            "生成自签证书失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(TlsConfig {
        cert_file: cert_file.to_string_lossy().into_owned(),
        key_file: key_file.to_string_lossy().into_owned(),
        server_name,
    })
}

#[derive(Debug)]
struct RealityConfig {
    dest: String,
    server_names: Vec<String>,
    private_key: String,
    public_key: String,
    short_ids: Vec<String>,
    fingerprint: String,
}

fn find_xray(work_dir: Option<&Path>) -> Result<PathBuf> {
    let os = std::env::consts::OS;
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm32",
        other => other,
    };
    let mut candidates = Vec::new();
    if let Some(dir) = work_dir {
        candidates.push(dir.join("bin/xray"));
    }
    candidates.push(PathBuf::from("/usr/local/bin/xray"));
    candidates.push(PathBuf::from("/usr/bin/xray"));
    candidates.push(PathBuf::from(format!(
        "/usr/local/x-ui/bin/xray-{os}-{arch}"
    )));
    let executable = |path: &Path| {
        path.is_file() && {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
    };
    for candidate in candidates {
        if executable(&candidate) {
            return Ok(candidate);
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for path in std::env::split_paths(&paths) {
            let candidate = path.join(if cfg!(windows) { "xray.exe" } else { "xray" });
            if executable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    bail!("找不到 xray 可执行文件")
}

async fn build_reality(work_dir: Option<&Path>, spec: &NormalizedSpec) -> Result<RealityConfig> {
    let mut dest = if spec.dest.is_empty() {
        "www.tesla.com:443".to_string()
    } else {
        spec.dest.clone()
    };
    if !dest.contains(':') {
        dest.push_str(":443");
    }
    let mut server_names: Vec<String> = spec
        .server_names
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();
    if server_names.is_empty() {
        server_names.push(dest.split(':').next().unwrap_or(&dest).to_string());
    }
    let bin = find_xray(work_dir)?;
    let out = command_output_checked(Command::new(&bin).arg("x25519"))
        .await
        .context("生成 REALITY 密钥失败")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let private_key = regex(r"(?i)private\s*key:\s*(\S+)")
        .captures(&text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
        .context("无法解析 xray x25519 私钥")?;
    let public_key = regex(r"(?i)(?:password\s*\(publickey\)|public\s*key):\s*(\S+)")
        .captures(&text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
        .context("无法解析 xray x25519 公钥")?;
    check_reality_dest(&dest, &server_names[0]).await?;
    let short_id = if spec.short_id.is_empty() {
        random_hex(4)
    } else {
        spec.short_id.clone()
    };
    let fingerprint = if spec.fingerprint.is_empty() {
        "chrome".to_string()
    } else {
        spec.fingerprint.clone()
    };
    Ok(RealityConfig {
        dest,
        server_names,
        private_key,
        public_key,
        short_ids: vec![short_id],
        fingerprint,
    })
}

async fn check_reality_dest(dest: &str, server_name: &str) -> Result<()> {
    let mut command = Command::new("openssl");
    command
        .args([
            "s_client",
            "-connect",
            dest,
            "-servername",
            server_name,
            "-tls1_3",
            "-brief",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = command.spawn().context("REALITY 目标站点检查失败")?;
    let out = tokio::time::timeout(Duration::from_secs(8), child.wait_with_output())
        .await
        .context("REALITY 目标站点 TLS1.3 握手超时")??;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success()
        || !text.to_ascii_lowercase().contains("tlsv1.3")
        || text.to_ascii_lowercase().contains("handshake failure")
    {
        bail!("{dest} 的 TLS1.3 握手失败: {}", text.trim());
    }
    Ok(())
}

fn random_hex(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::thread_rng().fill(&mut value);
    hex::encode(value)
}

fn xui_stream_settings(
    spec: &NormalizedSpec,
    tls: Option<&TlsConfig>,
    reality: Option<&RealityConfig>,
) -> Value {
    let mut stream = Map::from_iter([
        ("network".into(), Value::String(spec.network.clone())),
        ("security".into(), Value::String(spec.security.clone())),
    ]);
    let path = if spec.path.is_empty() {
        "/"
    } else {
        &spec.path
    };
    match spec.network.as_str() {
        "ws" => {
            let mut settings = Map::from_iter([("path".into(), Value::String(path.into()))]);
            if !spec.host.is_empty() {
                settings.insert("host".into(), Value::String(spec.host.clone()));
            }
            stream.insert("wsSettings".into(), Value::Object(settings));
        }
        "httpupgrade" => {
            let mut settings = Map::from_iter([("path".into(), Value::String(path.into()))]);
            if !spec.host.is_empty() {
                settings.insert("host".into(), Value::String(spec.host.clone()));
            }
            stream.insert("httpupgradeSettings".into(), Value::Object(settings));
        }
        "xhttp" => {
            let mut settings = Map::from_iter([
                ("path".into(), Value::String(path.into())),
                ("mode".into(), Value::String("auto".into())),
            ]);
            if !spec.host.is_empty() {
                settings.insert("host".into(), Value::String(spec.host.clone()));
            }
            stream.insert("xhttpSettings".into(), Value::Object(settings));
        }
        "grpc" => {
            stream.insert(
                "grpcSettings".into(),
                json!({"serviceName": spec.path.trim_start_matches('/')}),
            );
        }
        _ => {}
    }
    match spec.security.as_str() {
        "tls" => {
            if let Some(tls) = tls {
                let mut settings = Map::new();
                settings.insert(
                    "certificates".into(),
                    Value::Array(vec![json!({
                        "certificateFile": tls.cert_file,
                        "keyFile": tls.key_file,
                    })]),
                );
                if !tls.server_name.is_empty() {
                    settings.insert("serverName".into(), Value::String(tls.server_name.clone()));
                }
                stream.insert("tlsSettings".into(), Value::Object(settings));
            }
        }
        "reality" => {
            if let Some(reality) = reality {
                stream.insert(
                    "realitySettings".into(),
                    json!({
                        "dest": reality.dest,
                        "serverNames": reality.server_names,
                        "privateKey": reality.private_key,
                        "shortIds": reality.short_ids,
                        "show": false,
                        "xver": 0,
                        "settings": {
                            "publicKey": reality.public_key,
                            "fingerprint": reality.fingerprint,
                            "spiderX": "/",
                        },
                    }),
                );
            }
        }
        _ => {}
    }
    Value::Object(stream)
}

#[cfg(test)]
#[path = "panel_xui_test.rs"]
mod tests;
