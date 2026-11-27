//! Native Xray panel backend.
//!
//! This is the Rust counterpart of fanout's `native*.go`, `inbound_spec.go`,
//! `restart.go`, `cred.go` and `external_ports.go`.  `native.json` remains the
//! source of truth; `xray.json` is always regenerated from it and a snapshot of
//! the currently running exits.

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use futures::future::BoxFuture;
use rand::{rngs::ThreadRng, Rng, RngCore};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    future::Future,
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    process::{Output, Stdio},
    sync::{Arc, LazyLock, Mutex, OnceLock},
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    runtime::Handle,
    sync::Mutex as AsyncMutex,
    time::timeout,
};
use uuid::Uuid;

use crate::{
    config::{load_settings, DEFAULT_PANEL_DEBOUNCE, DEFAULT_PORT},
    models::{ClientInfo, Inbound, InboundDetail, PoolView, SocksCred, TunnelState},
    panel::{CreatedInbound, InboundPatch, Panel},
    util,
};

const NATIVE_OWNER: &str = "自建 Xray";
const XUI_TAG_PREFIX: &str = "fanout-";
const RAND_PORT_MIN: u16 = 20_000;
const RAND_PORT_MAX: u16 = 60_000;
const RETRY_MAX: u32 = 4;
const RETRY_BASE: Duration = Duration::from_secs(2);
const RETRY_CAP: Duration = Duration::from_secs(30);
const XRAY_EARLY_EXIT: Duration = Duration::from_millis(400);
const REALITY_TIMEOUT: Duration = Duration::from_secs(8);

// ---------------------------------------------------------------------------
// Persistent native.json schema
// ---------------------------------------------------------------------------

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NativeClient {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub enable: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub cert_file: String,
    #[serde(default)]
    pub key_file: String,
    #[serde(default)]
    pub self_signed: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cert_sha256: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RealityConfig {
    #[serde(default)]
    pub dest: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub server_names: Vec<String>,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub short_ids: Vec<String>,
    #[serde(default)]
    pub fingerprint: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NativeInbound {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub security: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub enable: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub clients: Vec<NativeClient>,
    #[serde(default)]
    pub bound_to: String,
}

impl NativeInbound {
    pub fn tag(&self) -> String {
        format!("in-{}-{}", self.port, self.net_or_tcp())
    }

    pub fn net_or_tcp(&self) -> String {
        if self.network.is_empty() {
            "tcp".into()
        } else {
            self.network.clone()
        }
    }

    pub fn security_or_none(&self) -> String {
        if self.security.is_empty() {
            "none".into()
        } else {
            self.security.clone()
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NativeStore {
    #[serde(default)]
    pub next_id: u64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub inbounds: Vec<NativeInbound>,
}

pub fn native_state_path(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join("native.json")
}

pub fn load_native_store(dir: impl AsRef<Path>) -> Result<NativeStore> {
    let path = native_state_path(dir);
    match fs::read(&path) {
        Ok(blob) => {
            let mut store: NativeStore = serde_json::from_slice(&blob)
                .with_context(|| format!("解析 {} 失败", path.display()))?;
            if store.next_id < 1 {
                store.next_id = 1;
            }
            Ok(store)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(NativeStore {
            next_id: 1,
            ..NativeStore::default()
        }),
        Err(e) => Err(e).with_context(|| format!("读取 {} 失败", path.display())),
    }
}

impl NativeStore {
    pub fn save(&self, dir: impl AsRef<Path>) -> Result<()> {
        let blob = serde_json::to_vec_pretty(self)?;
        util::atomic_write(native_state_path(dir), &blob, 0o600)
    }

    pub fn by_id(&self, id: u64) -> Option<&NativeInbound> {
        self.inbounds.iter().find(|ib| ib.id == id)
    }

    pub fn by_id_mut(&mut self, id: u64) -> Option<&mut NativeInbound> {
        self.inbounds.iter_mut().find(|ib| ib.id == id)
    }

    pub fn used_ports(&self) -> HashSet<u16> {
        let mut used = external_used_ports();
        used.extend(pool_ports());
        used.extend(self.inbounds.iter().map(|ib| ib.port));
        used
    }

    pub fn sorted(&self) -> Vec<NativeInbound> {
        let mut out = self.inbounds.clone();
        out.sort_by_key(|ib| ib.port);
        out
    }
}

// ---------------------------------------------------------------------------
// Credentials, tags, labels and random values
// ---------------------------------------------------------------------------

const CRED_ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CRED_USER_LEN: usize = 6;
const CRED_PASS_LEN: usize = 14;
const CRED_MAX_LEN: usize = 255;

fn random_cred_string_with_rng(n: usize, rng: &mut ThreadRng) -> Result<String> {
    let mut bytes = vec![0_u8; n];
    rng.fill_bytes(&mut bytes);
    Ok(bytes
        .into_iter()
        .map(|b| CRED_ALPHABET[b as usize % CRED_ALPHABET.len()] as char)
        .collect())
}

pub fn random_cred_string(n: usize) -> Result<String> {
    random_cred_string_with_rng(n, &mut rand::thread_rng())
}

pub fn new_socks_cred() -> Result<SocksCred> {
    Ok(SocksCred {
        user: format!("fo{}", random_cred_string(CRED_USER_LEN)?),
        pass: random_cred_string(CRED_PASS_LEN)?,
    })
}

pub fn validate_cred(cred: &SocksCred) -> Result<()> {
    if cred.user.is_empty() || cred.pass.is_empty() {
        bail!("用户名和口令都不能为空");
    }
    if cred.user.len() > CRED_MAX_LEN || cred.pass.len() > CRED_MAX_LEN {
        bail!("用户名和口令都不能超过 {CRED_MAX_LEN} 个字节");
    }
    for field in [&cred.user, &cred.pass] {
        if field
            .chars()
            .any(|c| matches!(c, ':' | ' ' | '/' | '@' | '\t' | '\r' | '\n'))
        {
            bail!("用户名和口令不能包含空格、冒号、斜杠或 @");
        }
    }
    Ok(())
}

pub fn socks_server_json(port: u16, cred: &SocksCred) -> Value {
    let mut server = Map::new();
    server.insert("address".into(), json!("127.0.0.1"));
    server.insert("port".into(), json!(port));
    if !cred.user.is_empty() {
        server.insert(
            "users".into(),
            json!([{"user": cred.user, "pass": cred.pass}]),
        );
    }
    Value::Object(server)
}

pub fn socks_url(host: &str, port: u16, cred: &SocksCred) -> String {
    if cred.user.is_empty() {
        format!("socks5://{host}:{port}")
    } else {
        format!("socks5://{}:{}@{host}:{port}", cred.user, cred.pass)
    }
}

pub fn new_uuid() -> String {
    Uuid::new_v4().to_string()
}

pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0_u8; n];
    if rand::thread_rng().try_fill_bytes(&mut bytes).is_err() {
        return hex::encode(format!("{}", std::process::id()).as_bytes());
    }
    hex::encode(bytes)
}

pub fn random_short_id() -> String {
    let mut bytes = [0_u8; 4];
    if rand::thread_rng().try_fill_bytes(&mut bytes).is_err() {
        return "0123abcd".into();
    }
    hex::encode(bytes)
}

pub(crate) fn sanitize_tag(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            out.push(ch);
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

pub(crate) fn egress_tag(identity: &str) -> String {
    format!("{XUI_TAG_PREFIX}{}", sanitize_tag(identity))
}

pub fn pool_identity(id: &str) -> String {
    format!("pool-{id}")
}

pub fn pool_identity_to_id(identity: &str) -> Option<String> {
    identity
        .strip_prefix("pool-")
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

pub fn is_generated_label(remark: &str) -> bool {
    remark
        .trim()
        .chars()
        .next()
        .is_some_and(|c| ('\u{1f1e6}'..='\u{1f1ff}').contains(&c))
}

pub fn unique_remark(want: &str, taken: &HashSet<String>) -> String {
    if want.is_empty() || !taken.contains(want) {
        return want.to_string();
    }
    for i in 2..1000 {
        let candidate = format!("{want} {i}");
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    want.to_string()
}

pub fn rename_exit_label(remark: &str, new_label: &str) -> String {
    if new_label.is_empty() || !is_generated_label(remark) {
        remark.to_string()
    } else {
        new_label.to_string()
    }
}

fn flag_of(code: &str) -> String {
    let code = code.trim().to_ascii_uppercase();
    if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
        return String::new();
    }
    code.bytes()
        .map(|b| char::from_u32(0x1f1e6 + u32::from(b - b'A')).unwrap_or('\u{fffd}'))
        .collect()
}

fn country_name(code: &str) -> &'static str {
    match code {
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
        "LI" => "列支敦斯坦",
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
    }
}

fn country_label(code: &str, fallback: &str) -> String {
    let code = code.trim().to_ascii_uppercase();
    let name = country_name(&code);
    let name = if name.is_empty() {
        fallback.trim()
    } else {
        name
    };
    let name = if name.is_empty() { code.as_str() } else { name };
    let flag = flag_of(&code);
    if flag.is_empty() {
        name.to_string()
    } else {
        format!("{flag} {name}")
    }
}

pub fn exit_label(tunnel: &TunnelState) -> String {
    let place = country_label(&tunnel.node.country_code, &tunnel.node.country);
    let suffix = if tunnel.exit_ip.is_empty() {
        tunnel.node.hostname.as_str()
    } else {
        tunnel
            .exit_ip
            .rsplit_once('.')
            .map_or(tunnel.exit_ip.as_str(), |(_, tail)| tail)
    };
    if place.is_empty() {
        suffix.to_string()
    } else {
        format!("{place} {suffix}")
    }
}

// ---------------------------------------------------------------------------
// Inbound specification and Xray JSON generation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NewInboundSpec {
    pub protocol: String,
    pub network: String,
    pub port: u16,
    pub remark: String,
    pub path: String,
    pub host: String,
    pub security: String,
    pub vision: bool,
    #[serde(alias = "sni", alias = "serverName")]
    pub server_name: String,
    #[serde(alias = "cert", alias = "certFile")]
    pub cert_file: String,
    #[serde(alias = "key", alias = "keyFile")]
    pub key_file: String,
    pub dest: String,
    #[serde(alias = "serverNames")]
    pub server_names: String,
    #[serde(alias = "sid", alias = "shortId")]
    pub short_id: String,
    #[serde(alias = "fp")]
    pub fingerprint: String,
}

impl NewInboundSpec {
    /// Accept both serde's snake_case names and the query/API aliases used by
    /// the Go frontend. Unknown fields are intentionally ignored.
    pub fn from_value(value: &Value) -> Result<Self> {
        fn text<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
            names.iter().find_map(|name| {
                value
                    .get(*name)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            })
        }

        fn boolean(value: &Value, names: &[&str]) -> Result<bool> {
            let Some(value) = names.iter().find_map(|name| value.get(*name)) else {
                return Ok(false);
            };
            match value {
                Value::Bool(v) => Ok(*v),
                Value::Number(v) if v.as_u64() == Some(0) => Ok(false),
                Value::Number(v) if v.as_u64() == Some(1) => Ok(true),
                Value::String(v) if matches!(v.as_str(), "0" | "false" | "off" | "no") => Ok(false),
                Value::String(v) if matches!(v.as_str(), "1" | "true" | "on" | "yes") => Ok(true),
                _ => bail!("vision 必须是布尔值或 0/1"),
            }
        }

        let port = match value.get("port") {
            None | Some(Value::Null) => 0,
            Some(Value::Number(v)) => u16::try_from(v.as_u64().unwrap_or(u64::MAX))
                .context("port 必须是 0-65535 的整数")?,
            Some(Value::String(v)) if v.trim().is_empty() => 0,
            Some(Value::String(v)) => v.trim().parse::<u16>().context("port 无效")?,
            _ => bail!("port 必须是整数"),
        };

        Ok(Self {
            protocol: text(value, &["protocol"]).unwrap_or("").into(),
            network: text(value, &["network"]).unwrap_or("").into(),
            port,
            remark: text(value, &["remark"]).unwrap_or("").into(),
            path: text(value, &["path"]).unwrap_or("").into(),
            host: text(value, &["host"]).unwrap_or("").into(),
            security: text(value, &["security"]).unwrap_or("").into(),
            vision: boolean(value, &["vision"])?,
            server_name: text(value, &["server_name", "sni", "serverName"])
                .unwrap_or("")
                .into(),
            cert_file: text(value, &["cert_file", "cert", "certFile"])
                .unwrap_or("")
                .into(),
            key_file: text(value, &["key_file", "key", "keyFile"])
                .unwrap_or("")
                .into(),
            dest: text(value, &["dest"]).unwrap_or("").into(),
            server_names: text(value, &["server_names", "serverNames"])
                .unwrap_or("")
                .into(),
            short_id: text(value, &["short_id", "sid", "shortId"])
                .unwrap_or("")
                .into(),
            fingerprint: text(value, &["fingerprint", "fp"]).unwrap_or("").into(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct NormalizedInboundSpec {
    pub protocol: String,
    pub network: String,
    pub security: String,
    pub port: u16,
    pub path: String,
    pub host: String,
    pub remark: String,
    pub flow: String,
}

pub fn vision_capable(protocol: &str, network: &str, security: &str) -> bool {
    protocol == "vless" && network == "tcp" && matches!(security, "tls" | "reality")
}

pub fn port_available(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

pub fn free_random_port(taken: &HashSet<u16>) -> Result<u16> {
    let mut rng = rand::thread_rng();
    for _ in 0..200 {
        let port = rng.gen_range(RAND_PORT_MIN..RAND_PORT_MAX);
        if !taken.contains(&port) && port_available(port) {
            return Ok(port);
        }
    }
    bail!("找不到可用端口（已尝试 200 次）")
}

pub fn normalize_inbound_spec(
    spec: &NewInboundSpec,
    used: &HashSet<u16>,
) -> Result<NormalizedInboundSpec> {
    let protocol = spec.protocol.trim().to_ascii_lowercase();
    let protocol = if protocol.is_empty() {
        "vless"
    } else {
        &protocol
    };
    if !matches!(protocol, "vless" | "vmess" | "trojan") {
        bail!("不支持的协议 {:?}", spec.protocol);
    }

    let network = spec.network.trim().to_ascii_lowercase();
    let network = if network.is_empty() { "tcp" } else { &network };
    if !matches!(network, "tcp" | "ws" | "grpc" | "httpupgrade" | "xhttp") {
        bail!("不支持的传输方式 {:?}", spec.network);
    }

    let security = spec.security.trim().to_ascii_lowercase();
    let security = if security.is_empty() {
        "none"
    } else {
        &security
    };
    if !matches!(security, "none" | "tls" | "reality") {
        bail!("不支持的安全层 {:?}", spec.security);
    }
    if security == "reality" && !matches!(network, "tcp" | "xhttp" | "grpc") {
        bail!("REALITY 不支持 {network} 传输");
    }

    let port = if spec.port == 0 {
        free_random_port(used)?
    } else {
        if used.contains(&spec.port) {
            bail!("端口 {} 已被别的入站占用", spec.port);
        }
        spec.port
    };

    let path = spec.path.trim();
    let path = if path.is_empty() {
        match network {
            "ws" | "httpupgrade" | "xhttp" => format!("/{}", random_hex(6)),
            "grpc" => random_hex(6),
            _ => String::new(),
        }
    } else {
        path.to_string()
    };

    let remark = spec.remark.trim();
    let remark = if remark.is_empty() {
        format!("{protocol}-{port}")
    } else {
        remark.to_string()
    };

    let flow = if spec.vision {
        if !vision_capable(protocol, network, security) {
            bail!("xtls-rprx-vision 只能用于 VLESS + TCP + TLS/REALITY");
        }
        "xtls-rprx-vision"
    } else {
        ""
    };

    Ok(NormalizedInboundSpec {
        protocol: protocol.into(),
        network: network.into(),
        security: security.into(),
        port,
        path,
        host: spec.host.trim().into(),
        remark,
        flow: flow.into(),
    })
}

pub fn native_inbound_json(ib: &NativeInbound) -> Value {
    let mut clients = Vec::new();
    for client in ib.clients.iter().filter(|c| c.enable) {
        clients.push(match ib.protocol.as_str() {
            "trojan" => json!({"password": client.password, "email": client.email}),
            "vmess" => json!({"id": client.id, "email": client.email}),
            _ => json!({"id": client.id, "email": client.email, "flow": client.flow}),
        });
    }
    let mut settings = Map::new();
    settings.insert("clients".into(), Value::Array(clients));
    if ib.protocol == "vless" {
        settings.insert("decryption".into(), json!("none"));
    }
    json!({
        "tag": ib.tag(),
        "listen": "0.0.0.0",
        "port": ib.port,
        "protocol": ib.protocol,
        "settings": Value::Object(settings),
        "streamSettings": stream_settings_json(ib),
        "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
    })
}

pub fn stream_settings_json(ib: &NativeInbound) -> Value {
    let network = ib.net_or_tcp();
    let security = ib.security_or_none();
    let mut stream = Map::new();
    stream.insert("network".into(), json!(network));
    stream.insert("security".into(), json!(security));

    let path = if ib.path.is_empty() { "/" } else { &ib.path };
    match network.as_str() {
        "ws" => {
            let mut ws = Map::new();
            ws.insert("path".into(), json!(path));
            if !ib.host.is_empty() {
                ws.insert("host".into(), json!(ib.host));
            }
            stream.insert("wsSettings".into(), Value::Object(ws));
        }
        "httpupgrade" => {
            let mut settings = Map::new();
            settings.insert("path".into(), json!(path));
            if !ib.host.is_empty() {
                settings.insert("host".into(), json!(ib.host));
            }
            stream.insert("httpupgradeSettings".into(), Value::Object(settings));
        }
        "xhttp" => {
            let mut settings = Map::new();
            settings.insert("path".into(), json!(path));
            settings.insert("mode".into(), json!("auto"));
            if !ib.host.is_empty() {
                settings.insert("host".into(), json!(ib.host));
            }
            stream.insert("xhttpSettings".into(), Value::Object(settings));
        }
        "grpc" => {
            stream.insert(
                "grpcSettings".into(),
                json!({"serviceName": ib.path.strip_prefix('/').unwrap_or(&ib.path)}),
            );
        }
        _ => {}
    }

    match security.as_str() {
        "tls" => {
            if let Some(tls) = &ib.tls {
                let mut settings = Map::new();
                settings.insert(
                    "certificates".into(),
                    json!([{"certificateFile": tls.cert_file, "keyFile": tls.key_file}]),
                );
                if !tls.server_name.is_empty() {
                    settings.insert("serverName".into(), json!(tls.server_name));
                }
                stream.insert("tlsSettings".into(), Value::Object(settings));
            }
        }
        "reality" => {
            if let Some(reality) = &ib.reality {
                stream.insert(
                    "realitySettings".into(),
                    json!({
                        "dest": reality.dest,
                        "serverNames": reality.server_names,
                        "privateKey": reality.private_key,
                        "shortIds": reality.short_ids,
                    }),
                );
            }
        }
        _ => {}
    }
    Value::Object(stream)
}

/// The caller supplies only pools whose SOCKS listeners are running. `up` is
/// used for UI liveness; the outbound stays in Xray even when every member is
/// down so traffic cannot silently fall back to the host's direct connection.
#[derive(Clone, Debug, Default)]
pub struct RuntimeSnapshot {
    pub tunnels: Vec<TunnelState>,
    pub pools: Vec<PoolView>,
}

impl RuntimeSnapshot {
    pub fn live_map(&self) -> HashMap<String, bool> {
        let mut live = HashMap::new();
        for tunnel in &self.tunnels {
            if tunnel.status == "up" {
                live.insert(sanitize_tag(&tunnel.node.hostname), true);
            }
        }
        for pool in &self.pools {
            live.insert(sanitize_tag(&pool_identity(&pool.id)), pool.up > 0);
        }
        live
    }
}

pub fn build_xray_config(
    inbounds: &[NativeInbound],
    tunnels: &[TunnelState],
    pools: &[PoolView],
) -> Value {
    let live: HashSet<String> = tunnels
        .iter()
        .filter(|t| t.status == "up")
        .map(|t| sanitize_tag(&t.node.hostname))
        .collect();

    let ins: Vec<Value> = inbounds
        .iter()
        .filter(|ib| ib.enable)
        .map(native_inbound_json)
        .collect();

    let mut outs = vec![
        json!({
            "tag": "direct",
            "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv4"},
        }),
        json!({"tag": "block", "protocol": "blackhole"}),
    ];
    for tunnel in tunnels.iter().filter(|t| t.status == "up") {
        outs.push(json!({
            "tag": egress_tag(&tunnel.node.hostname),
            "protocol": "socks",
            "settings": {"servers": [socks_server_json(tunnel.port, &tunnel.cred)]},
        }));
    }

    let mut pool_tags = HashSet::new();
    for pool in pools {
        let identity = pool_identity(&pool.id);
        let cred = SocksCred {
            user: pool.socks_user.clone(),
            pass: pool.socks_pass.clone(),
        };
        outs.push(json!({
            "tag": egress_tag(&identity),
            "protocol": "socks",
            "settings": {"servers": [socks_server_json(pool.port, &cred)]},
        }));
        pool_tags.insert(sanitize_tag(&identity));
    }

    let mut rules = Vec::new();
    for ib in inbounds.iter().filter(|ib| ib.enable) {
        if ib.bound_to.is_empty() {
            continue;
        }
        let outbound = if live.contains(&ib.bound_to) || pool_tags.contains(&ib.bound_to) {
            egress_tag(&ib.bound_to)
        } else {
            "block".to_string()
        };
        rules.push(json!({
            "type": "field",
            "inboundTag": [ib.tag()],
            "outboundTag": outbound,
        }));
    }

    json!({
        "log": {"loglevel": "warning"},
        "inbounds": ins,
        "outbounds": outs,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    })
}

fn percent_encode(value: &str, path_segment: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else if path_segment && matches!(byte, b'$' | b'&' | b'+' | b':' | b'=' | b'@') {
            out.push(byte as char);
        } else if !path_segment && byte == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

fn form_encode(value: &str) -> String {
    percent_encode(value, false)
}

fn path_escape(value: &str) -> String {
    percent_encode(value, true)
}

fn encode_query(query: &HashMap<String, String>) -> String {
    let mut sorted: Vec<_> = query.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .into_iter()
        .map(|(key, value)| format!("{key}={}", form_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn share_link(ib: &NativeInbound, client: &NativeClient, host: &str) -> String {
    let network = ib.net_or_tcp();
    let security = ib.security_or_none();
    let mut query = HashMap::new();
    query.insert("type".to_string(), network.clone());
    query.insert("security".to_string(), security.clone());

    match network.as_str() {
        "ws" | "httpupgrade" | "xhttp" => {
            query.insert("path".into(), ib.path.clone());
            if !ib.host.is_empty() {
                query.insert("host".into(), ib.host.clone());
            }
        }
        "grpc" => {
            query.insert(
                "serviceName".into(),
                ib.path.strip_prefix('/').unwrap_or(&ib.path).into(),
            );
        }
        _ => {}
    }

    match security.as_str() {
        "tls" => {
            if let Some(tls) = &ib.tls {
                if !tls.server_name.is_empty() {
                    query.insert("sni".into(), tls.server_name.clone());
                }
                if tls.self_signed && !tls.cert_sha256.is_empty() {
                    query.insert("pinSHA256".into(), tls.cert_sha256.clone());
                }
            }
        }
        "reality" => {
            if let Some(reality) = &ib.reality {
                if let Some(name) = reality.server_names.first() {
                    query.insert("sni".into(), name.clone());
                }
                query.insert("pbk".into(), reality.public_key.clone());
                if let Some(short_id) = reality.short_ids.first() {
                    query.insert("sid".into(), short_id.clone());
                }
                if !reality.fingerprint.is_empty() {
                    query.insert("fp".into(), reality.fingerprint.clone());
                }
            }
        }
        _ => {}
    }

    if !client.flow.is_empty() && ib.protocol == "vless" {
        query.insert("flow".into(), client.flow.clone());
    }

    let fragment = path_escape(&ib.remark);
    match ib.protocol.as_str() {
        "trojan" => format!(
            "trojan://{}@{host}:{}?{}#{fragment}",
            client.password,
            ib.port,
            encode_query(&query)
        ),
        "vmess" => {
            query.insert("encryption".into(), "auto".into());
            format!(
                "vmess://{}@{host}:{}?{}#{fragment}",
                client.id,
                ib.port,
                encode_query(&query)
            )
        }
        _ => {
            query.insert("encryption".into(), "none".into());
            format!(
                "vless://{}@{host}:{}?{}#{fragment}",
                client.id,
                ib.port,
                encode_query(&query)
            )
        }
    }
}

pub fn write_xray_config(dir: impl AsRef<Path>, config: &Value) -> Result<PathBuf> {
    let blob = serde_json::to_vec_pretty(config)?;
    let path = dir.as_ref().join("xray.json");
    util::atomic_write(&path, &blob, 0o600)?;
    Ok(path)
}

pub fn trim_output(output: &str) -> String {
    if output.len() <= 400 {
        return output.to_string();
    }
    let mut end = 400;
    while !output.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &output[..end])
}

// ---------------------------------------------------------------------------
// External Xray ports and pool-port registry
// ---------------------------------------------------------------------------

pub const EXTERNAL_XRAY_CONFIGS: &[&str] = &["/usr/local/etc/xray/config.json"];

pub fn xray_config_ports(blob: &[u8]) -> HashSet<u16> {
    let mut used = HashSet::new();
    let Ok(config) = serde_json::from_slice::<Value>(blob) else {
        return used;
    };
    let Some(inbounds) = config.get("inbounds").and_then(Value::as_array) else {
        return used;
    };
    for inbound in inbounds {
        if let Some(port) = inbound
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p > 0)
        {
            used.insert(port);
        }
    }
    used
}

pub fn merge_xray_config_ports(path: impl AsRef<Path>, used: &mut HashSet<u16>) {
    if let Ok(blob) = fs::read(path) {
        used.extend(xray_config_ports(&blob));
    }
}

pub fn external_used_ports() -> HashSet<u16> {
    let mut used = HashSet::new();
    for path in EXTERNAL_XRAY_CONFIGS {
        merge_xray_config_ports(path, &mut used);
    }
    used
}

static POOL_PORTS: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

pub fn note_pool_port(port: u16) {
    if port > 0 {
        POOL_PORTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(port);
    }
}

pub fn unnote_pool_port(port: u16) {
    if port > 0 {
        POOL_PORTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&port);
    }
}

pub fn clear_pool_ports() {
    POOL_PORTS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

pub fn pool_ports() -> HashSet<u16> {
    POOL_PORTS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

// ---------------------------------------------------------------------------
// Host network namespace and external commands
// ---------------------------------------------------------------------------

#[cfg(unix)]
use nix::sched::{setns, CloneFlags};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};

#[derive(Clone)]
struct MainNetns {
    #[cfg(unix)]
    fd: Arc<OwnedFd>,
}

impl MainNetns {
    fn capture() -> Result<Self> {
        #[cfg(unix)]
        {
            // /proc/self follows the calling thread. Use the process leader so
            // opening the panel from a Tokio worker cannot capture a tunnel's
            // namespace borrowed by some other thread.
            let fd = File::open(format!("/proc/{}/ns/net", std::process::id()))
                .context("记录母机网络命名空间失败")?;
            let fd: OwnedFd = fd.into();
            Ok(Self { fd: Arc::new(fd) })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    /// Run a future on a fresh OS thread after returning that thread to the
    /// host network namespace. A fresh thread is intentional: unlike Go, Rust
    /// does not expose LockOSThread, and changing a pooled Tokio worker would
    /// leak the namespace into unrelated work.
    async fn run<T, F, Fut>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        #[cfg(not(unix))]
        {
            operation().await
        }
        #[cfg(unix)]
        {
            let runtime = Handle::current();
            let fd = Arc::clone(&self.fd);
            tokio::task::spawn_blocking(move || {
                std::thread::spawn(move || {
                    setns(fd, CloneFlags::CLONE_NEWNET).context("切回母机网络命名空间失败")?;
                    runtime.block_on(operation())
                })
                .join()
                .map_err(|_| anyhow!("母机网络命名空间命令线程崩溃"))?
            })
            .await?
        }
    }
}

async fn command_output_with_timeout(
    netns: &MainNetns,
    program: impl Into<PathBuf>,
    args: Vec<String>,
    limit: Option<Duration>,
) -> Result<Output> {
    let program = program.into();
    netns
        .run(move || {
            let mut command = Command::new(program);
            command.args(args).stdin(Stdio::null()).kill_on_drop(true);
            async move {
                match limit {
                    Some(limit) => {
                        let out = timeout(limit, command.output())
                            .await
                            .context("外部命令执行超时")??;
                        Ok(out)
                    }
                    None => Ok(command.output().await?),
                }
            }
        })
        .await
}

async fn command_output(
    netns: &MainNetns,
    program: impl Into<PathBuf>,
    args: Vec<String>,
) -> Result<Output> {
    command_output_with_timeout(netns, program, args, None).await
}

fn combined_text(output: &Output) -> String {
    let mut text = output.stdout.clone();
    text.extend_from_slice(&output.stderr);
    String::from_utf8_lossy(&text).into_owned()
}

// ---------------------------------------------------------------------------
// Xray discovery, REALITY and TLS helpers
// ---------------------------------------------------------------------------

pub fn xui_arch_suffix() -> &'static str {
    match std::env::consts::ARCH {
        "amd64" => "amd64",
        "arm64" => "arm64",
        "arm" => "arm32",
        "s390x" => "s390x",
        arch => arch,
    }
}

pub fn xray_candidates(work_dir: impl AsRef<Path>) -> Vec<PathBuf> {
    let work_dir = work_dir.as_ref();
    let local = work_dir
        .join("bin")
        .join(if cfg!(windows) { "xray.exe" } else { "xray" });
    let system = if cfg!(windows) { "xray.exe" } else { "xray" };
    vec![
        local,
        PathBuf::from("/usr/local/bin").join(system),
        PathBuf::from("/usr/bin").join(system),
        PathBuf::from(format!(
            "/usr/local/x-ui/bin/xray-{}-{}",
            std::env::consts::OS,
            xui_arch_suffix()
        )),
    ]
}

fn executable(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) if !meta.is_file() => false,
        Ok(meta) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        Err(_) => false,
    }
}

fn path_candidates(program: &str) -> Vec<PathBuf> {
    let name = if cfg!(windows) && !program.to_ascii_lowercase().ends_with(".exe") {
        format!("{program}.exe")
    } else {
        program.to_string()
    };
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join(&name))
        .collect()
}

pub fn find_xray(work_dir: impl AsRef<Path>) -> Result<PathBuf> {
    for path in xray_candidates(&work_dir) {
        if executable(&path) {
            return Ok(path);
        }
    }
    for path in path_candidates("xray") {
        if executable(&path) {
            return Ok(path);
        }
    }
    bail!(
        "找不到 xray 可执行文件，装一份到 {} 或 /usr/local/bin/xray",
        work_dir.as_ref().join("bin").join("xray").display()
    )
}

fn resolve_binary(path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    if executable(path) {
        return Ok(path.to_path_buf());
    }
    if path.components().count() == 1 {
        for candidate in path_candidates(&path.to_string_lossy()) {
            if executable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    bail!("xray 不可执行: {}", path.display())
}

fn reality_host_port(dest: &str) -> (String, String) {
    let dest = dest.trim();
    if let Some((host, port)) = dest.rsplit_once(':') {
        if !host.is_empty() && port.parse::<u16>().is_ok() {
            return (
                host.trim_matches(|c| c == '[' || c == ']').to_string(),
                port.to_string(),
            );
        }
    }
    (
        dest.trim_matches(|c| c == '[' || c == ']').to_string(),
        "443".to_string(),
    )
}

async fn check_reality_dest(netns: &MainNetns, dest: &str, server_name: &str) -> Result<()> {
    let output = command_output_with_timeout(
        netns,
        "openssl",
        vec![
            "s_client".into(),
            "-connect".into(),
            dest.into(),
            "-servername".into(),
            server_name.into(),
            "-tls1_3".into(),
            "-brief".into(),
        ],
        Some(REALITY_TIMEOUT),
    )
    .await
    .with_context(|| format!("{dest} 的 TLS1.3 握手失败"))?;
    if !output.status.success() {
        bail!(
            "{} 的 TLS1.3 握手失败: {}",
            dest,
            trim_output(&combined_text(&output))
        );
    }
    Ok(())
}

async fn reality_keys(netns: &MainNetns, bin: &Path) -> Result<(String, String)> {
    let output = command_output(netns, bin.to_path_buf(), vec!["x25519".into()])
        .await
        .context("生成 REALITY 密钥失败")?;
    let text = combined_text(&output);
    if !output.status.success() {
        bail!("生成 REALITY 密钥失败: {}", trim_output(&text));
    }
    let private = Regex::new(r"(?i)private\s*key:\s*(\S+)")?;
    let public = Regex::new(r"(?i)(?:password\s*\(publickey\)|public\s*key):\s*(\S+)")?;
    let private = private
        .captures(&text)
        .and_then(|c| c.get(1))
        .ok_or_else(|| anyhow!("无法解析 xray x25519 输出: {}", trim_output(text.trim())))?;
    let public = public
        .captures(&text)
        .and_then(|c| c.get(1))
        .ok_or_else(|| anyhow!("无法解析 xray x25519 输出: {}", trim_output(text.trim())))?;
    Ok((private.as_str().into(), public.as_str().into()))
}

async fn self_signed_cert(
    netns: &MainNetns,
    dir: &Path,
    server_name: &str,
) -> Result<(String, String)> {
    let cert_dir = dir.join("certs");
    fs::create_dir_all(&cert_dir)?;
    #[cfg(unix)]
    fs::set_permissions(&cert_dir, fs::Permissions::from_mode(0o700))?;
    let base = cert_dir.join(sanitize_tag(server_name));
    let mut cert = base.clone();
    cert.as_mut_os_string().push(".crt");
    let mut key = base;
    key.as_mut_os_string().push(".key");
    let output = command_output(
        netns,
        "openssl",
        vec![
            "req".into(),
            "-x509".into(),
            "-nodes".into(),
            "-newkey".into(),
            "rsa:2048".into(),
            "-days".into(),
            "3650".into(),
            "-keyout".into(),
            key.to_string_lossy().into_owned(),
            "-out".into(),
            cert.to_string_lossy().into_owned(),
            "-subj".into(),
            format!("/CN={server_name}"),
            "-addext".into(),
            format!("subjectAltName=DNS:{server_name}"),
        ],
    )
    .await?;
    if !output.status.success() {
        bail!("生成自签证书失败: {}", trim_output(&combined_text(&output)));
    }
    Ok((
        cert.to_string_lossy().into_owned(),
        key.to_string_lossy().into_owned(),
    ))
}

async fn cert_fingerprint(netns: &MainNetns, cert_file: &str) -> Result<String> {
    let output = command_output(
        netns,
        "openssl",
        vec![
            "x509".into(),
            "-in".into(),
            cert_file.into(),
            "-outform".into(),
            "der".into(),
        ],
    )
    .await
    .context("读取证书失败")?;
    if !output.status.success() {
        bail!("读取证书失败: {}", trim_output(&combined_text(&output)));
    }
    Ok(hex::encode(Sha256::digest(output.stdout)))
}

async fn build_tls(netns: &MainNetns, dir: &Path, spec: &NewInboundSpec) -> Result<TlsConfig> {
    let server_name = if spec.server_name.trim().is_empty() {
        "localhost"
    } else {
        spec.server_name.trim()
    };
    let mut config = TlsConfig {
        server_name: server_name.into(),
        ..TlsConfig::default()
    };
    let cert = spec.cert_file.trim();
    let key = spec.key_file.trim();
    if cert.is_empty() != key.is_empty() {
        bail!("证书和私钥要成对填写，或者都留空用自签证书");
    }
    if !cert.is_empty() {
        fs::metadata(cert).with_context(|| format!("证书文件不可读: {cert}"))?;
        fs::metadata(key).with_context(|| format!("私钥文件不可读: {key}"))?;
        config.cert_file = cert.into();
        config.key_file = key.into();
        return Ok(config);
    }

    let (cert, key) = self_signed_cert(netns, dir, server_name).await?;
    config.self_signed = true;
    config.cert_sha256 = cert_fingerprint(netns, &cert).await?;
    config.cert_file = cert;
    config.key_file = key;
    Ok(config)
}

async fn build_reality(
    netns: &MainNetns,
    bin: &Path,
    spec: &NewInboundSpec,
) -> Result<RealityConfig> {
    let mut dest = spec.dest.trim().to_string();
    if dest.is_empty() {
        dest = "www.tesla.com:443".into();
    } else if !dest
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
    {
        dest.push_str(":443");
    }
    let mut names: Vec<String> = spec
        .server_names
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();
    if names.is_empty() {
        names.push(reality_host_port(&dest).0);
    }
    let (private_key, public_key) = reality_keys(netns, bin).await?;
    check_reality_dest(netns, &dest, &names[0])
        .await
        .with_context(|| format!("REALITY 目标站点不可用，换一个 dest: {dest}"))?;
    let short_id = if spec.short_id.trim().is_empty() {
        random_short_id()
    } else {
        spec.short_id.trim().into()
    };
    let fingerprint = if spec.fingerprint.trim().is_empty() {
        "chrome"
    } else {
        spec.fingerprint.trim()
    };
    Ok(RealityConfig {
        dest,
        server_names: names,
        private_key,
        public_key,
        short_ids: vec![short_id],
        fingerprint: fingerprint.into(),
    })
}

// ---------------------------------------------------------------------------
// Debounced restart gate (restart.go)
// ---------------------------------------------------------------------------

pub type RestartAction = Arc<dyn Fn() -> BoxFuture<'static, Result<()>> + Send + Sync>;

#[derive(Clone)]
struct PendingRestart {
    owner: String,
    generation: u64,
    action: RestartAction,
}

#[derive(Default)]
struct GateState {
    pending: Option<PendingRestart>,
    generation: u64,
    attempts: u32,
}

struct RestartGate {
    state: Mutex<GateState>,
    exec: AsyncMutex<()>,
}

impl RestartGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(GateState::default()),
            exec: AsyncMutex::new(()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn take(&self, expected: Option<u64>) -> Option<PendingRestart> {
        let mut state = self.lock();
        if expected.is_some_and(|generation| {
            state.pending.as_ref().map(|p| p.generation) != Some(generation)
        }) {
            return None;
        }
        state.pending.take()
    }

    fn schedule(&self, pending: PendingRestart, delay: Duration, owner: &str) {
        let generation = pending.generation;
        let owner = owner.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            if let Err(err) = restart_gate()
                .flush_expected(Some(generation), &owner)
                .await
            {
                tracing::warn!("{owner} 重载连续失败 {RETRY_MAX} 次，放弃自动重试：配置已写入但可能尚未生效: {err}");
            }
        });
    }

    async fn execute(&self, pending: PendingRestart, retry: bool, owner: &str) -> Result<()> {
        let result = {
            let _exec = self.exec.lock().await;
            (pending.action)().await
        };
        match result {
            Ok(()) => {
                self.lock().attempts = 0;
                Ok(())
            }
            Err(err) if retry => {
                let mut state = self.lock();
                let attempt = state.attempts.saturating_add(1);
                // A newer write owns the gate now. Never replace its action
                // with an older failed restart.
                if state.pending.is_some() || state.generation != pending.generation {
                    tracing::warn!("{owner} 重载失败，已有更新的待办重载: {err}");
                    return Ok(());
                }
                if attempt <= RETRY_MAX {
                    state.attempts = attempt;
                    state.pending = Some(pending.clone());
                    drop(state);
                    let delay = restart_delay(attempt).unwrap_or(RETRY_CAP);
                    self.schedule(pending, delay, owner);
                    tracing::warn!("{owner} 重载失败（第 {attempt} 次，稍后自动重试）: {err}");
                    Ok(())
                } else {
                    state.attempts = 0;
                    Err(err)
                }
            }
            Err(err) => Err(err),
        }
    }

    async fn flush_expected(&self, expected: Option<u64>, owner: &str) -> Result<()> {
        let Some(pending) = self.take(expected) else {
            return Ok(());
        };
        self.execute(pending, true, owner).await
    }
}

static RESTART_GATE: OnceLock<RestartGate> = OnceLock::new();

fn restart_gate() -> &'static RestartGate {
    RESTART_GATE.get_or_init(RestartGate::new)
}

pub fn restart_delay(attempt: u32) -> Option<Duration> {
    if attempt == 0 || attempt > RETRY_MAX {
        return None;
    }
    Some((RETRY_BASE * 2_u32.pow(attempt - 1)).min(RETRY_CAP))
}

pub async fn defer_restart(what: &str, window: Duration, action: RestartAction) -> Result<()> {
    let gate = restart_gate();
    let pending = {
        let mut state = gate.lock();
        state.generation = state.generation.wrapping_add(1);
        if state.generation == 0 {
            state.generation = 1;
        }
        PendingRestart {
            owner: what.into(),
            generation: state.generation,
            action,
        }
    };
    if window.is_zero() {
        return gate.flush_expected(None, what).await;
    }
    gate.schedule(pending, window, what);
    Ok(())
}

pub async fn call_restart(action: RestartAction) -> Result<()> {
    let _exec = restart_gate().exec.lock().await;
    action().await
}

pub async fn flush_restart(what: &str) -> Result<()> {
    restart_gate().flush_expected(None, what).await
}

pub async fn flush_restart_now(what: &str) -> Result<()> {
    let gate = restart_gate();
    let Some(pending) = gate.take(None) else {
        return Ok(());
    };
    let result = gate.execute(pending, false, what).await;
    if result.is_ok() {
        gate.lock().attempts = 0;
    }
    result
}

pub fn cancel_restart(what: &str) {
    let gate = restart_gate();
    let mut state = gate.lock();
    if state.pending.as_ref().is_some_and(|p| p.owner == what) {
        state.pending = None;
        state.attempts = 0;
        state.generation = state.generation.wrapping_add(1).max(1);
    }
}

pub fn pending_restart() -> bool {
    restart_gate().lock().pending.is_some()
}

// ---------------------------------------------------------------------------
// Xray process lifecycle
// ---------------------------------------------------------------------------

struct ProcState {
    child: Option<Child>,
    log: Option<File>,
}

pub(crate) struct XrayProc {
    bin: PathBuf,
    dir: PathBuf,
    netns: MainNetns,
    state: AsyncMutex<ProcState>,
}

impl XrayProc {
    fn new(bin: PathBuf, dir: PathBuf, netns: MainNetns) -> Self {
        Self {
            bin,
            dir,
            netns,
            state: AsyncMutex::new(ProcState {
                child: None,
                log: None,
            }),
        }
    }

    fn pid_path(&self) -> PathBuf {
        self.dir.join("xray.pid")
    }

    pub(crate) fn binary(&self) -> &Path {
        &self.bin
    }

    async fn verify(&self, config: &Path) -> Result<()> {
        let output = command_output(
            &self.netns,
            self.bin.clone(),
            vec![
                "run".into(),
                "-test".into(),
                "-c".into(),
                config.to_string_lossy().into_owned(),
            ],
        )
        .await?;
        if !output.status.success() {
            bail!(
                "Xray 配置校验失败: {}",
                trim_output(&combined_text(&output))
            );
        }
        Ok(())
    }

    async fn stop_locked(state: &mut ProcState, pid_path: &Path) {
        if let Some(mut child) = state.child.take() {
            let _ = child.start_kill();
            if timeout(Duration::from_secs(2), child.wait()).await.is_err() {
                tracing::warn!("等待 Xray 退出超时，PID {:?}", child.id());
            }
        }
        state.log.take();
        let _ = fs::remove_file(pid_path);
    }

    pub(crate) async fn stop(&self) {
        let mut state = self.state.lock().await;
        Self::stop_locked(&mut state, &self.pid_path()).await;
    }

    pub(crate) async fn restart(&self, config: PathBuf) -> Result<()> {
        let mut state = self.state.lock().await;
        Self::stop_locked(&mut state, &self.pid_path()).await;

        let log_path = self.dir.join("xray.log");
        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let log = options
            .open(&log_path)
            .with_context(|| format!("打开 Xray 日志失败: {}", log_path.display()))?;
        #[cfg(unix)]
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))?;

        let stdout_log = log.try_clone()?;
        let stderr_log = log.try_clone()?;
        let bin = self.bin.clone();
        let netns = self.netns.clone();
        let child = netns
            .run(move || {
                let mut command = Command::new(bin);
                command
                    .args(["run", "-c"])
                    .arg(config)
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(stdout_log))
                    .stderr(Stdio::from(stderr_log))
                    .kill_on_drop(true);
                async move { Ok(command.spawn()?) }
            })
            .await
            .context("启动 Xray 失败")?;

        let pid = child.id().ok_or_else(|| anyhow!("Xray 没有进程 PID"))?;
        util::write_file(self.pid_path(), pid.to_string().as_bytes(), 0o600)?;
        state.child = Some(child);
        state.log = Some(log);

        let early_exit = {
            let child = state.child.as_mut().expect("child was just stored");
            tokio::select! {
                biased;
                status = child.wait() => Some(status),
                _ = tokio::time::sleep(XRAY_EARLY_EXIT) => None,
            }
        };
        if let Some(status) = early_exit {
            state.child.take();
            state.log.take();
            let _ = fs::remove_file(self.pid_path());
            if status.as_ref().map_or(true, |status| !status.success()) {
                bail!("Xray 启动后立刻退出: {status:?}，详见 {log_path:?}");
            }
            bail!("Xray 启动后立刻退出，详见 {log_path:?}");
        }
        Ok(())
    }

    fn reap_orphan(&self) {
        let pid_path = self.pid_path();
        let Ok(blob) = fs::read(&pid_path) else {
            return;
        };
        let Some(pid) = std::str::from_utf8(&blob)
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
        else {
            let _ = fs::remove_file(&pid_path);
            return;
        };
        if pid <= 1 {
            let _ = fs::remove_file(&pid_path);
            return;
        }
        #[cfg(unix)]
        {
            if pid as u32 != std::process::id() {
                if let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) {
                    if exe == self.bin {
                        use nix::sys::signal::{kill, Signal};
                        use nix::unistd::Pid;
                        let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
                    }
                }
            }
        }
        let _ = fs::remove_file(&pid_path);
    }
}

// ---------------------------------------------------------------------------
// Native Panel implementation
// ---------------------------------------------------------------------------

struct NativeState {
    store: NativeStore,
    runtime: RuntimeSnapshot,
}

struct NativeInner {
    dir: PathBuf,
    debounce: Duration,
    state: AsyncMutex<NativeState>,
    proc: Arc<XrayProc>,
}

#[derive(Clone)]
pub struct Native {
    inner: Arc<NativeInner>,
}

impl Native {
    pub fn open(work_dir: impl AsRef<Path>) -> Result<Self> {
        let work_dir = work_dir.as_ref();
        if work_dir.as_os_str().is_empty() {
            bail!("自建模式缺少工作目录");
        }
        let bin = find_xray(work_dir)?;
        Self::open_with_binary(work_dir, bin)
    }

    pub fn open_with_binary(
        work_dir: impl AsRef<Path>,
        xray_binary: impl AsRef<Path>,
    ) -> Result<Self> {
        let debounce = load_settings(work_dir.as_ref(), DEFAULT_PORT, false)
            .map(|settings| Duration::from_millis(settings.conn.panel_debounce))
            .unwrap_or_else(|_| Duration::from_millis(DEFAULT_PANEL_DEBOUNCE));
        Self::with_binary(work_dir, xray_binary, debounce)
    }

    pub fn with_binary(
        work_dir: impl AsRef<Path>,
        xray_binary: impl AsRef<Path>,
        panel_debounce: Duration,
    ) -> Result<Self> {
        let work_dir = work_dir.as_ref();
        if work_dir.as_os_str().is_empty() {
            bail!("自建模式缺少工作目录");
        }
        let bin = resolve_binary(xray_binary)?;
        let store = load_native_store(work_dir)?;
        let netns = MainNetns::capture()?;
        let proc = Arc::new(XrayProc::new(bin, work_dir.to_path_buf(), netns));
        proc.reap_orphan();
        Ok(Self {
            inner: Arc::new(NativeInner {
                dir: work_dir.to_path_buf(),
                debounce: panel_debounce,
                state: AsyncMutex::new(NativeState {
                    store,
                    runtime: RuntimeSnapshot::default(),
                }),
                proc,
            }),
        })
    }

    pub fn work_dir(&self) -> &Path {
        &self.inner.dir
    }

    pub fn xray_binary(&self) -> &Path {
        self.inner.proc.binary()
    }

    pub async fn runtime_snapshot(&self) -> RuntimeSnapshot {
        self.inner.state.lock().await.runtime.clone()
    }

    /// Replace the tunnel snapshot used for liveness, cloning and outbounds.
    pub async fn set_tunnels(&self, tunnels: Vec<TunnelState>) {
        self.inner.state.lock().await.runtime.tunnels = tunnels;
    }

    /// Replace the running pool snapshot. Only listening pools should be passed.
    pub async fn set_pools(&self, pools: Vec<PoolView>) {
        self.inner.state.lock().await.runtime.pools = pools;
    }

    /// Install the manager's current exit/pool snapshot. Call
    /// `on_tunnels_changed` afterwards to regenerate and reload Xray.
    pub async fn set_runtime(&self, tunnels: Vec<TunnelState>, pools: Vec<PoolView>) {
        self.inner.state.lock().await.runtime = RuntimeSnapshot { tunnels, pools };
    }

    pub async fn update_runtime(&self, runtime: RuntimeSnapshot) {
        self.inner.state.lock().await.runtime = runtime;
    }

    pub async fn update_tunnel_states(&self, tunnels: Vec<TunnelState>) {
        self.set_tunnels(tunnels).await;
    }

    pub async fn update_pools(&self, pools: Vec<PoolView>) {
        self.set_pools(pools).await;
    }

    pub async fn set_runtime_and_apply(
        &self,
        tunnels: Vec<TunnelState>,
        pools: Vec<PoolView>,
    ) -> Result<()> {
        self.update_runtime_and_apply(RuntimeSnapshot { tunnels, pools })
            .await
    }

    pub async fn update_runtime_and_apply(&self, runtime: RuntimeSnapshot) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        state.runtime = runtime;
        self.apply_locked(&mut state, false).await
    }

    pub async fn start(&self) -> Result<()> {
        self.apply_current().await
    }

    async fn apply_current(&self) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        self.apply_locked(&mut state, false).await
    }

    async fn apply_locked(&self, state: &mut NativeState, immediate: bool) -> Result<()> {
        let previous_store = load_native_store(&self.inner.dir)?;
        let config_path = self.inner.dir.join("xray.json");
        let previous_config = fs::read(&config_path).ok();
        let config = build_xray_config(
            &state.store.sorted(),
            &state.runtime.tunnels,
            &state.runtime.pools,
        );
        let path = write_xray_config(&self.inner.dir, &config)?;
        self.inner.proc.verify(&path).await?;
        state.store.save(&self.inner.dir)?;

        let empty = config
            .get("inbounds")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        let proc = Arc::clone(&self.inner.proc);
        let action: RestartAction = Arc::new(move || {
            let proc = Arc::clone(&proc);
            let path = path.clone();
            Box::pin(async move {
                if empty {
                    proc.stop().await;
                    Ok(())
                } else {
                    proc.restart(path).await
                }
            })
        });
        if !immediate {
            return defer_restart(NATIVE_OWNER, self.inner.debounce, action).await;
        }

        cancel_restart(NATIVE_OWNER);
        if let Err(error) = call_restart(action).await {
            state.store = previous_store.clone();
            if let Err(restore_error) = previous_store.save(&self.inner.dir) {
                bail!("新版启动失败（{error}），恢复配置也失败: {restore_error}");
            }
            if let Some(blob) = previous_config {
                util::atomic_write(&config_path, &blob, 0o600)?;
                let old_empty = serde_json::from_slice::<Value>(&blob)
                    .ok()
                    .and_then(|value| value.get("inbounds").cloned())
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty);
                let proc = Arc::clone(&self.inner.proc);
                let rollback: RestartAction = Arc::new(move || {
                    let proc = Arc::clone(&proc);
                    let path = config_path.clone();
                    Box::pin(async move {
                        if old_empty {
                            proc.stop().await;
                            Ok(())
                        } else {
                            proc.restart(path).await
                        }
                    })
                });
                let _ = call_restart(rollback).await;
            } else {
                self.inner.proc.stop().await;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Re-run the on-disk config with the current binary after an Xray update.
    pub async fn swap_xray(&self) -> Result<()> {
        let _state = self.inner.state.lock().await;
        let path = self.inner.dir.join("xray.json");
        if !path.is_file() {
            bail!("找不到在用的配置 {}: 文件不存在", path.display());
        }
        self.inner.proc.verify(&path).await?;
        cancel_restart(NATIVE_OWNER);
        let proc = Arc::clone(&self.inner.proc);
        call_restart(Arc::new(move || {
            let proc = Arc::clone(&proc);
            let path = path.clone();
            Box::pin(async move { proc.restart(path).await })
        }))
        .await
    }

    fn parse_id(id: &str) -> Result<u64> {
        id.trim()
            .parse::<u64>()
            .with_context(|| format!("入站 ID 无效: {id}"))
    }

    fn view(ib: &NativeInbound, bound_up: bool) -> Inbound {
        Inbound {
            id: ib.id.to_string(),
            port: ib.port,
            protocol: ib.protocol.clone(),
            remark: ib.remark.clone(),
            enable: ib.enable,
            tag: ib.tag(),
            bound_to: ib.bound_to.clone(),
            bound_up,
        }
    }

    pub async fn close(&self) -> Result<()> {
        let _state = self.inner.state.lock().await;
        cancel_restart(NATIVE_OWNER);
        self.inner.proc.stop().await;
        Ok(())
    }
}

pub fn open_native(work_dir: impl AsRef<Path>) -> Result<Native> {
    Native::open(work_dir)
}

#[async_trait]
impl Panel for Native {
    fn kind(&self) -> String {
        "native".into()
    }

    fn describe(&self) -> String {
        format!("fanout 自建 Xray（{}）", self.inner.proc.binary().display())
    }

    async fn inbounds(&self) -> Result<Vec<Inbound>> {
        let state = self.inner.state.lock().await;
        let live = state.runtime.live_map();
        Ok(state
            .store
            .sorted()
            .iter()
            .map(|ib| Self::view(ib, live.get(&ib.bound_to).copied().unwrap_or(false)))
            .collect())
    }

    async fn inbound_detail(&self, id: &str, host: &str) -> Result<InboundDetail> {
        let id = Self::parse_id(id)?;
        let state = self.inner.state.lock().await;
        let ib = state
            .store
            .by_id(id)
            .ok_or_else(|| anyhow!("入站 {id} 不存在"))?;
        let live = state.runtime.live_map();
        let mut clients = Vec::with_capacity(ib.clients.len());
        let mut links = Vec::with_capacity(ib.clients.len());
        for client in &ib.clients {
            let credential = if ib.protocol == "trojan" {
                client.password.clone()
            } else {
                client.id.clone()
            };
            clients.push(ClientInfo {
                email: client.email.clone(),
                id: credential,
                enable: client.enable,
            });
            links.push(share_link(ib, client, host));
        }
        Ok(InboundDetail {
            id: ib.id.to_string(),
            port: ib.port,
            protocol: ib.protocol.clone(),
            remark: ib.remark.clone(),
            enable: ib.enable,
            tag: ib.tag(),
            bound_to: ib.bound_to.clone(),
            bound_up: live.get(&ib.bound_to).copied().unwrap_or(false),
            clients,
            links,
            listen: "0.0.0.0".into(),
            network: ib.net_or_tcp(),
            tls: "none".into(),
        })
    }

    async fn inbound_links(&self, ids: &[String], host: &str) -> Result<Vec<String>> {
        let state = self.inner.state.lock().await;
        let mut links = Vec::new();
        for id in ids {
            let id = Self::parse_id(id)?;
            if let Some(ib) = state.store.by_id(id) {
                links.extend(ib.clients.iter().map(|client| share_link(ib, client, host)));
            }
        }
        Ok(links)
    }

    async fn bind(&self, tag: &str, host: &str) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        let bound_to = if host.is_empty() {
            String::new()
        } else if pool_identity_to_id(host).is_some() {
            if !state
                .runtime
                .pools
                .iter()
                .any(|pool| pool_identity(&pool.id) == host)
            {
                bail!("出口组 {host} 不存在或监听没起来");
            }
            sanitize_tag(host)
        } else {
            let target = state
                .runtime
                .tunnels
                .iter()
                .find(|tunnel| tunnel.node.hostname == host)
                .ok_or_else(|| anyhow!("节点 {host} 没有运行中的隧道"))?;
            if target.status != "up" {
                bail!("节点 {host} 的隧道还没连通（当前 {}）", target.status);
            }
            sanitize_tag(&target.node.hostname)
        };
        let ib = state
            .store
            .inbounds
            .iter_mut()
            .find(|ib| ib.tag() == tag)
            .ok_or_else(|| anyhow!("入站 {tag} 不存在"))?;
        ib.bound_to = bound_to;
        self.apply_locked(&mut state, true).await
    }

    async fn rebind(&self, old_host: &str, new_host: &str) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        let target = state
            .runtime
            .tunnels
            .iter()
            .find(|tunnel| tunnel.node.hostname == new_host)
            .ok_or_else(|| anyhow!("节点 {new_host} 没有运行中的隧道"))?;
        let old_tag = sanitize_tag(old_host);
        let new_tag = sanitize_tag(&target.node.hostname);
        let label = exit_label(target);
        for ib in &mut state.store.inbounds {
            if ib.bound_to == old_tag {
                ib.bound_to = new_tag.clone();
                ib.remark = rename_exit_label(&ib.remark, &label);
            }
        }
        self.apply_locked(&mut state, true).await
    }

    async fn resync_outbound(&self, _host: &str) -> Result<()> {
        self.apply_current().await
    }

    async fn clone_to_tunnels(&self, id: &str, hosts: &[String]) -> Result<Vec<u16>> {
        let id = Self::parse_id(id)?;
        let mut state = self.inner.state.lock().await;
        let template = state
            .store
            .by_id(id)
            .ok_or_else(|| anyhow!("模板入站 {id} 不存在"))?
            .clone();
        let mut used = state.store.used_ports();
        used.extend(state.runtime.pools.iter().map(|pool| pool.port));
        let mut taken: HashSet<String> = state
            .store
            .inbounds
            .iter()
            .map(|ib| ib.remark.trim().to_string())
            .collect();
        let mut created = Vec::new();
        for host in hosts {
            let Some(tunnel) = state
                .runtime
                .tunnels
                .iter()
                .find(|tunnel| tunnel.node.hostname == *host && tunnel.status == "up")
            else {
                continue;
            };
            let port = free_random_port(&used)?;
            used.insert(port);
            let remark = unique_remark(&exit_label(tunnel), &taken);
            taken.insert(remark.clone());
            let clone = NativeInbound {
                id: state.store.next_id,
                port,
                protocol: template.protocol.clone(),
                network: template.network.clone(),
                path: template.path.clone(),
                host: template.host.clone(),
                security: template.security.clone(),
                tls: template.tls.clone(),
                reality: template.reality.clone(),
                remark,
                enable: true,
                clients: template.clients.clone(),
                bound_to: sanitize_tag(&tunnel.node.hostname),
            };
            state.store.next_id = state
                .store
                .next_id
                .checked_add(1)
                .ok_or_else(|| anyhow!("入站 ID 已溢出"))?;
            state.store.inbounds.push(clone);
            created.push(port);
        }
        if created.is_empty() {
            bail!("没有可用的隧道");
        }
        self.apply_locked(&mut state, true).await?;
        Ok(created)
    }

    async fn delete_inbounds(&self, ids: &[String]) -> Result<usize> {
        let drop: HashSet<u64> = ids
            .iter()
            .map(|id| Self::parse_id(id))
            .collect::<Result<_>>()?;
        let mut state = self.inner.state.lock().await;
        let before = state.store.inbounds.len();
        state.store.inbounds.retain(|ib| !drop.contains(&ib.id));
        let removed = before - state.store.inbounds.len();
        self.apply_locked(&mut state, true).await?;
        Ok(removed)
    }

    async fn create_inbound(&self, spec: &Value) -> Result<CreatedInbound> {
        let spec = NewInboundSpec::from_value(spec)?;
        let mut state = self.inner.state.lock().await;
        let mut used_ports = state.store.used_ports();
        used_ports.extend(state.runtime.pools.iter().map(|pool| pool.port));
        let normalized = normalize_inbound_spec(&spec, &used_ports)?;
        let mut ib = NativeInbound {
            id: state.store.next_id,
            port: normalized.port,
            protocol: normalized.protocol.clone(),
            network: normalized.network,
            path: normalized.path,
            host: normalized.host,
            security: normalized.security.clone(),
            remark: normalized.remark,
            enable: true,
            ..NativeInbound::default()
        };
        match normalized.security.as_str() {
            "tls" => {
                ib.tls = Some(build_tls(&self.inner.proc.netns, &self.inner.dir, &spec).await?)
            }
            "reality" => {
                ib.reality = Some(
                    build_reality(&self.inner.proc.netns, self.inner.proc.binary(), &spec).await?,
                )
            }
            _ => {}
        }
        ib.clients.push(NativeClient {
            email: format!("{}-{}", ib.protocol, ib.port),
            id: new_uuid(),
            password: random_hex(8),
            flow: normalized.flow,
            enable: true,
        });
        state.store.next_id = state
            .store
            .next_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("入站 ID 已溢出"))?;
        state.store.inbounds.push(ib.clone());
        self.apply_locked(&mut state, true).await?;
        let network = ib.net_or_tcp();
        let security = ib.security_or_none();
        Ok(CreatedInbound {
            id: ib.id.to_string(),
            port: ib.port,
            protocol: ib.protocol,
            remark: ib.remark,
            network,
            security,
        })
    }

    async fn update_inbound(&self, id: &str, patch: &InboundPatch) -> Result<()> {
        let id = Self::parse_id(id)?;
        let mut state = self.inner.state.lock().await;
        let current_port = state
            .store
            .by_id(id)
            .ok_or_else(|| anyhow!("入站 {id} 不存在"))?
            .port;
        let conflicting_remark = patch.port.and_then(|port| {
            state
                .store
                .inbounds
                .iter()
                .find(|other| other.id != id && other.port == port)
                .map(|other| other.remark.clone())
        });
        let runtime_port_used = patch.port.is_some_and(|port| {
            state
                .runtime
                .tunnels
                .iter()
                .any(|tunnel| tunnel.port == port)
                || state.runtime.pools.iter().any(|pool| pool.port == port)
                || external_used_ports().contains(&port)
        });
        let ib = state
            .store
            .by_id_mut(id)
            .ok_or_else(|| anyhow!("入站 {id} 不存在"))?;
        if let Some(port) = patch.port {
            if port != current_port {
                if port == 0 {
                    bail!("端口 0 不在合法范围");
                }
                if let Some(remark) = conflicting_remark {
                    bail!("端口 {port} 已被入站 {remark:?} 占用");
                }
                if runtime_port_used {
                    bail!("端口 {port} 已被运行中的服务占用");
                }
                ib.port = port;
            }
        }
        if let Some(remark) = &patch.remark {
            let remark = remark.trim();
            if !remark.is_empty() {
                ib.remark = remark.into();
            }
        }
        if let Some(enable) = patch.enable {
            ib.enable = enable;
        }
        self.apply_locked(&mut state, true).await
    }

    async fn add_client(&self, id: &str, email: &str) -> Result<()> {
        let id = Self::parse_id(id)?;
        let mut state = self.inner.state.lock().await;
        let ib = state
            .store
            .by_id_mut(id)
            .ok_or_else(|| anyhow!("入站 {id} 不存在"))?;
        let email = email.trim();
        let email = if email.is_empty() {
            format!("{}-{}-{}", ib.protocol, ib.port, random_hex(3))
        } else {
            email.to_string()
        };
        if ib.clients.iter().any(|client| client.email == email) {
            bail!("客户端 {email:?} 已存在");
        }
        let flow = ib
            .clients
            .iter()
            .find(|client| !client.flow.is_empty())
            .map(|client| client.flow.clone())
            .unwrap_or_default();
        ib.clients.push(NativeClient {
            email,
            id: new_uuid(),
            password: random_hex(8),
            enable: true,
            flow,
        });
        self.apply_locked(&mut state, true).await
    }

    async fn delete_client(&self, id: &str, email: &str) -> Result<()> {
        let id = Self::parse_id(id)?;
        let mut state = self.inner.state.lock().await;
        let ib = state
            .store
            .by_id_mut(id)
            .ok_or_else(|| anyhow!("入站 {id} 不存在"))?;
        if ib.clients.len() <= 1 {
            bail!("这是最后一个客户端，删掉就没人能连了");
        }
        let before = ib.clients.len();
        ib.clients.retain(|client| client.email != email);
        if ib.clients.len() == before {
            bail!("客户端 {email:?} 不存在");
        }
        self.apply_locked(&mut state, true).await
    }

    async fn reset_client(&self, id: &str, email: &str) -> Result<ClientInfo> {
        let id = Self::parse_id(id)?;
        let mut state = self.inner.state.lock().await;
        let ib = state
            .store
            .by_id_mut(id)
            .ok_or_else(|| anyhow!("入站 {id} 不存在"))?;
        let client = ib
            .clients
            .iter_mut()
            .find(|client| client.email == email)
            .ok_or_else(|| anyhow!("客户端 {email:?} 不存在"))?;
        client.id = new_uuid();
        client.password = random_hex(8);
        let info = ClientInfo {
            email: client.email.clone(),
            id: if ib.protocol == "trojan" {
                client.password.clone()
            } else {
                client.id.clone()
            },
            enable: client.enable,
        };
        self.apply_locked(&mut state, true).await?;
        Ok(info)
    }

    async fn on_tunnels_changed(&self) -> Result<()> {
        self.apply_current().await
    }

    async fn close(&self) -> Result<()> {
        Native::close(self).await
    }
}

#[cfg(test)]
#[path = "panel_native_test.rs"]
mod panel_native_test;
