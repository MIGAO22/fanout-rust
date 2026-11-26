use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use csv::ReaderBuilder;
use ipnet::Ipv4Net;
use rand::Rng;
use reqwest::{header::HeaderValue, Client, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::HashMap, net::IpAddr, num::IntErrorKind, process::Command, str::FromStr,
    time::Duration,
};

use crate::models::{Node, SocksCred};

const VPNGATE_API: &str = "https://www.vpngate.net/api/iphone/";
const VPNGATE_MIRROR: &str = "https://p.xy.kg/vpngate";
const MIRROR_KEY: &str = "8rhIFzFKRJMFAe-xP5OQPclDEvSjKlHo";
const VPNGATE_OWN_NET: &str = "219.100.37.0/24";

pub fn mirror_url() -> String {
    std::env::var("FANOUT_VPNGATE_MIRROR")
        .map(|v| v.trim().to_owned())
        .unwrap_or_else(|_| VPNGATE_MIRROR.to_owned())
}

pub fn mirror_access_key() -> String {
    std::env::var("FANOUT_VPNGATE_MIRROR_KEY")
        .map(|v| v.trim().to_owned())
        .unwrap_or_else(|_| MIRROR_KEY.to_owned())
}

pub async fn fetch_nodes(timeout: Duration) -> Result<Vec<Node>> {
    fetch_nodes_scored(timeout, "balanced").await
}

pub async fn fetch_nodes_scored(timeout: Duration, score_mode: &str) -> Result<Vec<Node>> {
    fetch_nodes_with(
        VPNGATE_API,
        &mirror_url(),
        &mirror_access_key(),
        timeout,
        score_mode,
    )
    .await
}

pub async fn fetch_nodes_with(
    direct: &str,
    mirror: &str,
    mirror_key: &str,
    timeout: Duration,
    score_mode: &str,
) -> Result<Vec<Node>> {
    let direct_err = match fetch_nodes_from(direct, "", timeout, score_mode).await {
        Ok(nodes) => return Ok(nodes),
        Err(err) => err,
    };
    let mirror = mirror.trim();
    if mirror.is_empty() {
        return Err(direct_err);
    }
    match fetch_nodes_from(mirror, mirror_key.trim(), timeout, score_mode).await {
        Ok(nodes) => Ok(nodes),
        Err(mirror_err) => Err(anyhow!("直连失败({direct_err})；反代也失败: {mirror_err}")),
    }
}

pub async fn fetch_nodes_from(
    url: &str,
    key: &str,
    timeout: Duration,
    score_mode: &str,
) -> Result<Vec<Node>> {
    let mut builder = Client::builder();
    if !timeout.is_zero() {
        builder = builder.timeout(timeout);
    }
    let client = builder
        .user_agent("fanout-rust/0.0.17")
        .build()
        .context("拉取节点列表失败: 创建 HTTP 客户端失败")?;
    let mut req = client.get(url);
    if !key.is_empty() {
        req = req.header("X-Fanout-Key", HeaderValue::from_str(key)?);
    }
    let resp = req.send().await.context("拉取节点列表失败")?;
    if resp.status() == StatusCode::TOO_MANY_REQUESTS {
        return fetch_nodes_from_curl(url, key, timeout, score_mode, None).await;
    }
    if resp.status() != StatusCode::OK {
        anyhow::bail!("拉取节点列表失败: HTTP {}", resp.status().as_u16());
    }
    let raw = resp.bytes().await.context("读取节点列表失败")?;
    parse_node_csv(&String::from_utf8_lossy(&raw), score_mode)
}

async fn fetch_nodes_from_curl(
    url: &str,
    key: &str,
    timeout: Duration,
    score_mode: &str,
    proxy: Option<&str>,
) -> Result<Vec<Node>> {
    let url = url.to_string();
    let key = key.to_string();
    let proxy = proxy.map(str::to_string);
    let secs = timeout.as_secs().clamp(5, 120).to_string();
    let body = tokio::task::spawn_blocking(move || {
        let mut command = Command::new("curl");
        command.args([
            "-fsSL".to_string(),
            "--connect-timeout".to_string(),
            "5".to_string(),
            "--max-time".to_string(),
            secs,
        ]);
        if !key.is_empty() {
            command.arg("-H").arg(format!("X-Fanout-Key: {key}"));
        }
        if let Some(proxy) = proxy {
            command.arg("--proxy").arg(proxy);
        }
        command.arg(url);
        let output = command.output().context("curl 拉取节点列表失败")?;
        if !output.status.success() {
            anyhow::bail!(
                "curl 拉取节点列表失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok::<String, anyhow::Error>(String::from_utf8_lossy(&output.stdout).into_owned())
    })
    .await
    .context("curl 节点拉取任务异常退出")??;
    parse_node_csv(&body, score_mode)
}

pub async fn fetch_nodes_via_socks(
    proxy: &str,
    timeout: Duration,
    score_mode: &str,
) -> Result<Vec<Node>> {
    fetch_nodes_from_curl(VPNGATE_API, "", timeout, score_mode, Some(proxy)).await
}

pub fn parse_node_csv(body: &str, score_mode: &str) -> Result<Vec<Node>> {
    let mut kept = Vec::new();
    for line in body.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('*') {
            continue;
        }
        kept.push(line.strip_prefix('#').unwrap_or(line));
    }
    if kept.len() < 2 {
        anyhow::bail!("节点列表格式异常: 有效行不足");
    }

    let input = kept.join("\n");
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(input.as_bytes());
    let records = reader
        .records()
        .collect::<Result<Vec<_>, _>>()
        .context("解析节点 CSV 失败")?;
    let Some(header) = records.first() else {
        anyhow::bail!("节点列表格式异常: 缺少表头");
    };
    let mut idx = HashMap::with_capacity(header.len());
    for (i, name) in header.iter().enumerate() {
        idx.insert(name.trim(), i);
    }
    for name in [
        "HostName",
        "IP",
        "CountryLong",
        "CountryShort",
        "Ping",
        "Speed",
        "OpenVPN_ConfigData_Base64",
    ] {
        if !idx.contains_key(name) {
            anyhow::bail!("节点列表缺少字段 {name}");
        }
    }

    let mut nodes = Vec::new();
    for rec in &records[1..] {
        let get = |name: &str| idx.get(name).and_then(|&i| rec.get(i)).unwrap_or("");
        let cfg_b64 = get("OpenVPN_ConfigData_Base64");
        let hostname = get("HostName");
        if cfg_b64.is_empty() || hostname.is_empty() {
            continue;
        }
        // Go's standard base64 decoder ignores CR and LF inside the input.
        let decoded = BASE64_STANDARD
            .decode(cfg_b64.replace(['\r', '\n'], ""))
            .ok();
        let Some(config) = decoded else {
            continue;
        };
        let ip = get("IP");
        nodes.push(Node {
            hostname: hostname.to_owned(),
            ip: ip.to_owned(),
            country: get("CountryLong").to_owned(),
            country_code: get("CountryShort").to_owned(),
            ping: parse_atoi(get("Ping")),
            speed_mbps: get("Speed").parse::<f64>().unwrap_or(0.0) / 1e6,
            sessions: parse_atoi(get("NumVpnSessions")),
            residential: is_residential(hostname, ip),
            config: String::from_utf8_lossy(&config).into_owned(),
        });
    }
    if nodes.is_empty() {
        anyhow::bail!("节点列表为空");
    }
    score_nodes(&mut nodes, score_mode);
    Ok(nodes)
}

fn parse_atoi(s: &str) -> i64 {
    match s.parse::<i64>() {
        Ok(n) => n,
        Err(err) => match err.kind() {
            IntErrorKind::PosOverflow => i64::MAX,
            IntErrorKind::NegOverflow => i64::MIN,
            IntErrorKind::Zero => 0,
            _ => 0,
        },
    }
}

pub fn is_residential(hostname: &str, ip: &str) -> bool {
    if hostname.trim().to_lowercase().starts_with("public-vpn-") {
        return false;
    }
    let Ok(addr) = ip.trim().parse::<IpAddr>() else {
        return true;
    };
    let own_net = Ipv4Net::from_str(VPNGATE_OWN_NET).expect("valid VPN Gate network");
    let in_own_net = match addr {
        IpAddr::V4(addr) => own_net.contains(&addr),
        IpAddr::V6(addr) => addr
            .to_ipv4_mapped()
            .is_some_and(|addr| own_net.contains(&addr)),
    };
    !in_own_net
}

pub fn selectable_nodes(nodes: &[Node], residential_only: bool) -> Vec<Node> {
    if residential_only {
        nodes
            .iter()
            .filter(|node| node.residential)
            .cloned()
            .collect()
    } else {
        nodes.to_vec()
    }
}

pub fn node_score(node: &Node, mode: &str) -> f64 {
    let speed = if node.speed_mbps > 0.0 {
        node.speed_mbps / (node.speed_mbps + 40.0)
    } else {
        0.25
    };
    let load = if node.sessions > 0 {
        1.0 - node.sessions.min(50) as f64 / 50.0
    } else {
        1.0
    };
    let ping = if node.ping > 0 {
        1.0 - node.ping.min(600) as f64 / 600.0
    } else {
        0.5
    };
    let (ws, wl, wp) = match mode {
        "speed" => (0.80, 0.10, 0.10),
        "idle" => (0.10, 0.55, 0.35),
        "ping" => (0.10, 0.20, 0.70),
        _ => (0.45, 0.30, 0.25),
    };
    ws * speed + wl * load + wp * ping
}

pub fn score_nodes(nodes: &mut [Node], mode: &str) {
    nodes.sort_by(|a, b| {
        node_score(b, mode)
            .partial_cmp(&node_score(a, mode))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

pub fn order_candidates(
    current: &Node,
    region: &str,
    prefer_current: bool,
    max_tries: usize,
    pool: &[Node],
    used: &HashMap<String, bool>,
    avoid: &HashMap<String, bool>,
) -> Vec<Node> {
    let mut same = Vec::new();
    let mut other = Vec::new();
    for node in pool {
        if node.hostname == current.hostname
            || used.get(&node.hostname).copied().unwrap_or(false)
            || avoid.get(&node.hostname).copied().unwrap_or(false)
        {
            continue;
        }
        if region.is_empty() || node.country_code == region {
            same.push(node.clone());
        } else {
            other.push(node.clone());
        }
    }

    let mut out = Vec::new();
    if prefer_current {
        out.push(current.clone());
    }
    for node in same {
        if out.len() >= max_tries {
            return out;
        }
        out.push(node);
    }
    if !prefer_current {
        for node in other {
            if out.len() >= max_tries {
                return out;
            }
            out.push(node);
        }
        if out.len() < max_tries {
            out.push(current.clone());
        }
    }
    out
}

pub fn swap_note(index: usize, home: &str, got: &str) -> String {
    if !home.is_empty() && !got.is_empty() && got != home {
        format!(
            "同区没有空闲节点，已跨区换到 {got}（第 {} 个候选）",
            index + 1
        )
    } else {
        format!("已换到第 {} 个候选节点", index + 1)
    }
}

const COUNTRY_CN: &[(&str, &str)] = &[
    ("JP", "日本"),
    ("KR", "韩国"),
    ("KP", "朝鲜"),
    ("CN", "中国"),
    ("HK", "香港"),
    ("TW", "台湾"),
    ("MO", "澳门"),
    ("MN", "蒙古"),
    ("SG", "新加坡"),
    ("MY", "马来西亚"),
    ("TH", "泰国"),
    ("VN", "越南"),
    ("PH", "菲律宾"),
    ("ID", "印尼"),
    ("BN", "文莱"),
    ("KH", "柬埔寨"),
    ("LA", "老挝"),
    ("MM", "缅甸"),
    ("TL", "东帝汶"),
    ("IN", "印度"),
    ("PK", "巴基斯坦"),
    ("BD", "孟加拉"),
    ("LK", "斯里兰卡"),
    ("NP", "尼泊尔"),
    ("BT", "不丹"),
    ("MV", "马尔代夫"),
    ("AF", "阿富汗"),
    ("KZ", "哈萨克斯坦"),
    ("UZ", "乌兹别克斯坦"),
    ("KG", "吉尔吉斯斯坦"),
    ("TJ", "塔吉克斯坦"),
    ("TM", "土库曼斯坦"),
    ("TR", "土耳其"),
    ("IL", "以色列"),
    ("AE", "阿联酋"),
    ("SA", "沙特"),
    ("QA", "卡塔尔"),
    ("KW", "科威特"),
    ("BH", "巴林"),
    ("OM", "阿曼"),
    ("JO", "约旦"),
    ("LB", "黎巴嫩"),
    ("SY", "叙利亚"),
    ("IQ", "伊拉克"),
    ("IR", "伊朗"),
    ("YE", "也门"),
    ("GE", "格鲁吉亚"),
    ("AM", "亚美尼亚"),
    ("AZ", "阿塞拜疆"),
    ("CY", "塞浦路斯"),
    ("RU", "俄罗斯"),
    ("UA", "乌克兰"),
    ("BY", "白俄罗斯"),
    ("MD", "摩尔多瓦"),
    ("PL", "波兰"),
    ("CZ", "捷克"),
    ("SK", "斯洛伐克"),
    ("HU", "匈牙利"),
    ("RO", "罗马尼亚"),
    ("BG", "保加利亚"),
    ("RS", "塞尔维亚"),
    ("HR", "克罗地亚"),
    ("SI", "斯洛文尼亚"),
    ("BA", "波黑"),
    ("ME", "黑山"),
    ("MK", "北马其顿"),
    ("AL", "阿尔巴尼亚"),
    ("GR", "希腊"),
    ("IT", "意大利"),
    ("ES", "西班牙"),
    ("PT", "葡萄牙"),
    ("FR", "法国"),
    ("DE", "德国"),
    ("AT", "奥地利"),
    ("CH", "瑞士"),
    ("NL", "荷兰"),
    ("BE", "比利时"),
    ("LU", "卢森堡"),
    ("GB", "英国"),
    ("IE", "爱尔兰"),
    ("DK", "丹麦"),
    ("SE", "瑞典"),
    ("NO", "挪威"),
    ("FI", "芬兰"),
    ("IS", "冰岛"),
    ("EE", "爱沙尼亚"),
    ("LV", "拉脱维亚"),
    ("LT", "立陶宛"),
    ("MT", "马耳他"),
    ("MC", "摩纳哥"),
    ("AD", "安道尔"),
    ("SM", "圣马力诺"),
    ("LI", "列支敦士登"),
    ("US", "美国"),
    ("CA", "加拿大"),
    ("MX", "墨西哥"),
    ("BR", "巴西"),
    ("AR", "阿根廷"),
    ("CL", "智利"),
    ("CO", "哥伦比亚"),
    ("PE", "秘鲁"),
    ("VE", "委内瑞拉"),
    ("EC", "厄瓜多尔"),
    ("BO", "玻利维亚"),
    ("PY", "巴拉圭"),
    ("UY", "乌拉圭"),
    ("CR", "哥斯达黎加"),
    ("PA", "巴拿马"),
    ("GT", "危地马拉"),
    ("HN", "洪都拉斯"),
    ("SV", "萨尔瓦多"),
    ("NI", "尼加拉瓜"),
    ("CU", "古巴"),
    ("DO", "多米尼加"),
    ("PR", "波多黎各"),
    ("JM", "牙买加"),
    ("TT", "特立尼达"),
    ("BS", "巴哈马"),
    ("BZ", "伯利兹"),
    ("EG", "埃及"),
    ("MA", "摩洛哥"),
    ("DZ", "阿尔及利亚"),
    ("TN", "突尼斯"),
    ("LY", "利比亚"),
    ("SD", "苏丹"),
    ("ET", "埃塞俄比亚"),
    ("KE", "肯尼亚"),
    ("TZ", "坦桑尼亚"),
    ("UG", "乌干达"),
    ("RW", "卢旺达"),
    ("NG", "尼日利亚"),
    ("GH", "加纳"),
    ("CI", "科特迪瓦"),
    ("SN", "塞内加尔"),
    ("CM", "喀麦隆"),
    ("CD", "刚果金"),
    ("CG", "刚果布"),
    ("AO", "安哥拉"),
    ("MZ", "莫桑比克"),
    ("ZM", "赞比亚"),
    ("ZW", "津巴布韦"),
    ("BW", "博茨瓦纳"),
    ("NA", "纳米比亚"),
    ("ZA", "南非"),
    ("MU", "毛里求斯"),
    ("MG", "马达加斯加"),
    ("AU", "澳大利亚"),
    ("NZ", "新西兰"),
    ("FJ", "斐济"),
    ("PG", "巴新"),
    ("NC", "新喀里多尼亚"),
    ("GU", "关岛"),
];

pub fn flag_of(code: &str) -> String {
    let code = code.trim().to_uppercase();
    if code.len() != 2 {
        return String::new();
    }
    let mut out = String::with_capacity(code.len() * 2);
    for c in code.bytes() {
        if !c.is_ascii_alphabetic() {
            return String::new();
        }
        out.push(char::from_u32((c.to_ascii_uppercase() - b'A') as u32 + 0x1F1E6).unwrap());
    }
    out
}

pub fn country_label(code: &str, fallback: &str) -> String {
    let code = code.trim().to_uppercase();
    let name = COUNTRY_CN
        .iter()
        .find_map(|&(candidate, name)| (candidate == code).then_some(name))
        .map(str::to_owned)
        .unwrap_or_else(|| {
            let fallback = fallback.trim();
            if fallback.is_empty() {
                code.clone()
            } else {
                fallback.to_owned()
            }
        });
    let flag = flag_of(&code);
    if flag.is_empty() {
        name
    } else {
        format!("{flag} {name}")
    }
}

pub fn node_label(node: &Node) -> String {
    country_label(&node.country_code, &node.country)
}

pub fn is_generated_label(remark: &str) -> bool {
    remark
        .trim()
        .chars()
        .next()
        .is_some_and(|c| ('\u{1F1E6}'..='\u{1F1FF}').contains(&c))
}

pub fn unique_remark(want: &str, taken: &HashMap<String, bool>) -> String {
    if want.is_empty() || !taken.get(want).copied().unwrap_or(false) {
        return want.to_owned();
    }
    for i in 2..1000 {
        let candidate = format!("{want} {i}");
        if !taken.get(&candidate).copied().unwrap_or(false) {
            return candidate;
        }
    }
    want.to_owned()
}

const AEAD_CIPHER_LIST: &str = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305";
const DATA_CIPHER_LIST: &str = "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC";

pub fn data_cipher_args(ver: &str, aead_only: bool) -> Vec<String> {
    let Some((major, minor)) = parse_version_parts(ver) else {
        return Vec::new();
    };
    if major > 2 || (major == 2 && minor >= 5) {
        if aead_only {
            return string_args(&["--data-ciphers", AEAD_CIPHER_LIST]);
        }
        return string_args(&[
            "--data-ciphers",
            DATA_CIPHER_LIST,
            "--data-ciphers-fallback",
            "AES-256-CBC",
        ]);
    }
    if major == 2 && minor == 4 {
        return string_args(&["--ncp-ciphers", DATA_CIPHER_LIST]);
    }
    Vec::new()
}

pub fn compression_off_args(ver: &str) -> Vec<String> {
    let Some((major, minor)) = parse_version_parts(ver) else {
        return Vec::new();
    };
    if major < 2 || (major == 2 && minor < 5) {
        return Vec::new();
    }
    string_args(&["--allow-compression", "no"])
}

fn string_args(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

pub fn ovpn_config_offers_aead(cfg: &str) -> bool {
    let mut seen = String::new();
    for line in cfg.split('\n') {
        let mut fields = line.split_whitespace();
        let Some(option) = fields.next() else {
            continue;
        };
        let Some(value) = fields.next() else {
            continue;
        };
        match option
            .strip_prefix("--")
            .unwrap_or(option)
            .to_lowercase()
            .as_str()
        {
            "data-ciphers" | "ncp-ciphers" | "cipher" => seen = value.to_lowercase(),
            _ => {}
        }
    }
    if seen.is_empty() {
        return false;
    }
    seen.split(|c| c == ':' || c == ',' || c == ' ')
        .any(|cipher| cipher.contains("-gcm") || cipher.contains("chacha20"))
}

pub fn ovpn_config_enables_compression(cfg: &str) -> bool {
    for line in cfg.split('\n') {
        let mut fields = line.split_whitespace();
        let Some(option) = fields.next() else {
            continue;
        };
        match option
            .strip_prefix("--")
            .unwrap_or(option)
            .to_lowercase()
            .as_str()
        {
            "comp-lzo" | "allow-compression" => {
                if fields
                    .next()
                    .map(|v| v.to_lowercase() != "no")
                    .unwrap_or(true)
                {
                    return true;
                }
            }
            "comp-lz4" | "comp-noadapt" | "compress" => return true,
            _ => {}
        }
    }
    false
}

pub fn node_supports_aead(cfg: &str) -> bool {
    ovpn_config_offers_aead(cfg) && !ovpn_config_enables_compression(cfg)
}

pub fn parse_version_parts(v: &str) -> Option<(i64, i64)> {
    let mut parts = v.trim().split('.');
    let major = leading_decimal(parts.next()?)?;
    let minor = leading_decimal(parts.next()?)?;
    Some((major, minor))
}

fn leading_decimal(s: &str) -> Option<i64> {
    let len = s.bytes().take_while(u8::is_ascii_digit).count();
    if len == 0 {
        return None;
    }
    s[..len].parse().ok()
}

const CRED_ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CRED_USER_LEN: usize = 6;
const CRED_PASS_LEN: usize = 14;
const CRED_MAX_LEN: usize = 255;

pub fn new_socks_cred() -> SocksCred {
    SocksCred {
        user: format!("fo{}", random_cred_string(CRED_USER_LEN)),
        pass: random_cred_string(CRED_PASS_LEN),
    }
}

pub fn random_cred_string(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| CRED_ALPHABET[rng.gen_range(0..CRED_ALPHABET.len())] as char)
        .collect()
}

pub fn validate_cred(cred: &SocksCred) -> Result<()> {
    if cred.user.is_empty() || cred.pass.is_empty() {
        anyhow::bail!("用户名和口令都不能为空");
    }
    if cred.user.len() > CRED_MAX_LEN || cred.pass.len() > CRED_MAX_LEN {
        anyhow::bail!("用户名和口令都不能超过 {CRED_MAX_LEN} 个字节");
    }
    for field in [&cred.user, &cred.pass] {
        if field
            .chars()
            .any(|c| matches!(c, ':' | ' ' | '/' | '@' | '\t' | '\r' | '\n'))
        {
            anyhow::bail!("用户名和口令不能包含空格、冒号、斜杠或 @");
        }
    }
    Ok(())
}

pub fn socks_server_port_cred(port: u16, cred: &SocksCred) -> Value {
    if cred.user.is_empty() {
        json!({"address": "127.0.0.1", "port": port})
    } else {
        json!({
            "address": "127.0.0.1",
            "port": port,
            "users": [{"user": cred.user, "pass": cred.pass}],
        })
    }
}

pub fn socks_url(host: &str, port: u16, cred: &SocksCred) -> String {
    if cred.user.is_empty() {
        format!("socks5://{host}:{port}")
    } else {
        format!("socks5://{}:{}@{host}:{port}", cred.user, cred.pass)
    }
}

#[cfg(test)]
#[path = "nodes_test.rs"]
mod tests;
