//! Pure WARP registration, parsing, and command-construction logic.
//!
//! This module deliberately performs no network, filesystem, or process I/O. The
//! long-running WARP service can consume these interfaces without making the
//! routing and protocol rules depend on a particular host.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::Ipv4Addr,
    time::Duration,
};
use x25519_dalek::{PublicKey, StaticSecret};

pub const WARP_API_VER: &str = "v0a2317";
pub const WARP_PEER_PUB: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
pub const WARP_TUN_IP: &str = "172.16.0.2";
pub const WARP_PORT: i32 = 2408;
pub const WARP_CLIENT_VERSION: &str = "2026.8.2115.0";
pub const WARP_PKG_INDEX: &str =
    "https://pkg.cloudflareclient.com/dists/%s/main/binary-amd64/Packages";
pub const WARP_CODENAMES: &str = "noble,bookworm,jammy,trixie";
pub const WARP_KEEPALIVE: i32 = 25;
pub const WARP_EXTRA_BUDGET: Duration = Duration::from_secs(12);
pub const WARP_FRESH_AFTER: Duration = Duration::from_secs(3 * 60);

pub const WARP_KEY_STDIN: &str = "/proc/self/fd/0";
pub const WARP_PROBE_DEV: &str = "foarpprobe";
pub const WIREGUARD_PKG: &str = "wireguard-tools";
pub const WARP_STORE_VERSION: u32 = 1;
const OS_RELEASE_PATH: &str = "/etc/os-release";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpAccount {
    pub slot: usize,
    pub id: String,
    pub token: String,
    #[serde(rename = "priv_key")]
    pub priv_key: String,
    #[serde(rename = "pub_key")]
    pub pub_key: String,
    #[serde(rename = "peer_key")]
    pub peer_key: String,
    pub endpoint: String,
    pub port: i32,
    #[serde(rename = "tun_ip")]
    pub tun_ip: String,
    pub version: String,
    #[serde(rename = "created_at")]
    pub created_at: String,
}

impl WarpAccount {
    /// The instance tag is explicit because it is derived from the runtime work
    /// directory, rather than being global protocol state.
    pub fn dev_name(&self, tag: &str) -> String {
        warp_dev_name(tag, self.slot)
    }
}

pub fn warp_dev_name(tag: &str, slot: usize) -> String {
    format!("fow{tag}{slot}")
}

pub fn warp_key_file_name(dev: &str) -> String {
    format!("{dev}.wgkey")
}

/// Only `wg` reads the private key from this command's stdin.
pub fn warp_key_for(command: &[String], private_key: &str) -> String {
    if command.first().map(String::as_str) == Some("wg") {
        format!("{private_key}\n")
    } else {
        String::new()
    }
}

pub fn new_warp_keys() -> Result<(String, String)> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    Ok((
        STANDARD.encode(secret.to_bytes()),
        STANDARD.encode(public.as_bytes()),
    ))
}

pub fn warp_install_id() -> Result<String> {
    let mut bytes = [0_u8; 8];
    OsRng.fill_bytes(&mut bytes);
    Ok(hex::encode(bytes))
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpRegRequest {
    pub key: String,
    #[serde(rename = "install_id")]
    pub install_id: String,
    pub version: String,
    pub os: String,
    #[serde(rename = "type")]
    pub request_type: String,
}

pub fn new_warp_reg_request(public_key: &str, version: &str) -> Result<WarpRegRequest> {
    let version = if version.trim().is_empty() {
        WARP_CLIENT_VERSION
    } else {
        version
    };
    Ok(WarpRegRequest {
        key: public_key.to_string(),
        install_id: warp_install_id()?,
        version: version.to_string(),
        os: "linux".to_string(),
        request_type: "WireGuard".to_string(),
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpRegResponse {
    pub id: String,
    pub key: String,
    pub token: String,
    pub config: WarpRegConfig,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpRegConfig {
    pub interface: WarpRegInterface,
    pub peers: Vec<WarpRegPeer>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpRegInterface {
    pub addresses: WarpRegAddresses,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpRegAddresses {
    pub v4: String,
    pub v6: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpRegPeer {
    #[serde(rename = "public_key")]
    pub public_key: String,
    pub endpoint: WarpRegEndpoint,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpRegEndpoint {
    pub v4: String,
    pub v6: String,
    pub host: String,
    pub ports: Vec<i32>,
}

pub fn parse_warp_reg(blob: &[u8]) -> Result<WarpRegResponse> {
    let response: WarpRegResponse =
        serde_json::from_slice(blob).context("看不懂 Cloudflare 的注册响应")?;
    if response.id.is_empty() || response.token.is_empty() {
        bail!("注册响应里没有 id 或 token");
    }
    if response.config.peers.is_empty() {
        bail!("注册响应里没有 WireGuard peer");
    }
    Ok(response)
}

pub fn warp_account_of(
    slot: usize,
    response: &WarpRegResponse,
    private_key: &str,
    public_key: &str,
    version: &str,
    now: DateTime<Utc>,
) -> Result<WarpAccount> {
    let peer = response
        .config
        .peers
        .first()
        .context("注册响应里没有 WireGuard peer")?;
    let peer_key = if peer.public_key.trim().is_empty() {
        WARP_PEER_PUB.to_string()
    } else {
        peer.public_key.trim().to_string()
    };
    let (endpoint, port) =
        warp_endpoint(&peer.endpoint.v4, &peer.endpoint.host, &peer.endpoint.ports)?;
    let tun_ip = if response.config.interface.addresses.v4.trim().is_empty() {
        WARP_TUN_IP.to_string()
    } else {
        response.config.interface.addresses.v4.trim().to_string()
    };
    if !public_key.is_empty() && !response.key.is_empty() && public_key != response.key {
        bail!("注册响应的公钥与本机生成的不一致");
    }
    Ok(WarpAccount {
        slot,
        id: response.id.clone(),
        token: response.token.clone(),
        priv_key: private_key.to_string(),
        pub_key: public_key.to_string(),
        peer_key,
        endpoint,
        port,
        tun_ip,
        version: version.to_string(),
        created_at: now.to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        rest[end + 1..].strip_prefix(':').map(|port| (host, port))
    } else if value.matches(':').count() == 1 {
        value.split_once(':')
    } else {
        None
    }
}

fn join_host_port(host: &str, port: i32) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Select an IPv4 endpoint and prefer its own port, then the host port, then
/// the first positive advertised port, and finally WireGuard's standard port.
pub fn warp_endpoint(v4: &str, host: &str, ports: &[i32]) -> Result<(String, i32)> {
    let raw = v4.trim();
    let mut ip = raw;
    let mut self_port = 0;
    if let Some((host, port)) = split_host_port(raw) {
        ip = host;
        self_port = port.parse::<i32>().unwrap_or(0);
    }
    let parsed: Ipv4Addr = ip
        .parse()
        .with_context(|| format!("注册响应里没有可用的 IPv4 接入点（{v4:?}）"))?;

    let mut port = 0;
    for candidate in [self_port, host_port(host)] {
        if candidate > 0 {
            port = candidate;
            break;
        }
    }
    if port == 0 {
        port = ports
            .iter()
            .copied()
            .find(|candidate| *candidate > 0)
            .unwrap_or(WARP_PORT);
    }
    Ok((parsed.to_string(), port))
}

pub fn host_port(host: &str) -> i32 {
    split_host_port(host.trim())
        .and_then(|(_, port)| port.parse::<i32>().ok())
        .unwrap_or(0)
}

pub fn warp_path_mtu(on: bool, under: i32) -> (i32, i32, i32) {
    if !on {
        return (0, 0, 1380);
    }
    let under = if under <= 0 || under > 1500 {
        1500
    } else {
        under
    };
    let wg = (under - 60).clamp(1280, 1420);
    let tun = wg - 40;
    (wg, tun, tun - 40)
}

pub fn warp_default_dev(blob: &str) -> String {
    let mut lines = blob.lines();
    let _header = lines.next();
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[1] == "00000000" {
            return fields[0].to_string();
        }
    }
    String::new()
}

pub fn warp_openvpn_args(on: bool, tun_mtu: i32) -> Vec<String> {
    if !on {
        return Vec::new();
    }
    vec![
        "--route-nopull".to_string(),
        "--tun-mtu".to_string(),
        tun_mtu.to_string(),
    ]
}

pub fn warp_pull_filters(on: bool, version: &str) -> Vec<String> {
    if !on {
        return Vec::new();
    }
    let Some((major, minor)) = openvpn_version_parts(version) else {
        return Vec::new();
    };
    if major < 2 || (major == 2 && minor < 4) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for name in ["tun-mtu", "link-mtu", "mssfix"] {
        out.extend(command(&["--pull-filter", "ignore", name]));
    }
    out
}

pub fn warp_budget(base: Duration, on: bool) -> Duration {
    if on {
        base + WARP_EXTRA_BUDGET
    } else {
        base
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireguardInstallError {
    pub family: String,
    message: String,
}

impl std::fmt::Display for WireguardInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WireguardInstallError {}

fn install_error(family: &str, message: String) -> WireguardInstallError {
    WireguardInstallError {
        family: family.to_string(),
        message,
    }
}

pub fn wireguard_install_plan<F>(
    os_release: &str,
    have: F,
) -> std::result::Result<(Vec<Vec<String>>, String), WireguardInstallError>
where
    F: Fn(&str) -> bool,
{
    let family = distro_family(&parse_os_release(os_release));
    let steps = match family {
        "deb" => {
            if !have("apt-get") {
                return Err(install_error(
                    family,
                    format!(
                        "认出来是 Debian/Ubuntu 系，但机器上没有 apt-get，装不了 {WIREGUARD_PKG}"
                    ),
                ));
            }
            vec![
                command(&["apt-get", "update", "-qq"]),
                command(&["apt-get", "install", "-y", WIREGUARD_PKG]),
            ]
        }
        "rpm" => {
            if have("dnf") {
                vec![command(&["dnf", "-y", "install", WIREGUARD_PKG])]
            } else if have("yum") {
                vec![command(&["yum", "-y", "install", WIREGUARD_PKG])]
            } else {
                return Err(install_error(
                    family,
                    format!(
                        "认出来是 RHEL/CentOS/Fedora 系，但机器上没有 dnf 或 yum，装不了 {WIREGUARD_PKG}"
                    ),
                ));
            }
        }
        "alpine" => {
            if !have("apk") {
                return Err(install_error(
                    family,
                    format!("认出来是 Alpine，但机器上没有 apk，装不了 {WIREGUARD_PKG}"),
                ));
            }
            vec![command(&["apk", "add", "--no-cache", WIREGUARD_PKG])]
        }
        "arch" => {
            if !have("pacman") {
                return Err(install_error(
                    family,
                    format!("认出来是 Arch 系，但机器上没有 pacman，装不了 {WIREGUARD_PKG}"),
                ));
            }
            vec![command(&[
                "pacman",
                "-Sy",
                "--noconfirm",
                "--needed",
                WIREGUARD_PKG,
            ])]
        }
        "suse" => {
            if !have("zypper") {
                return Err(install_error(
                    family,
                    format!("认出来是 openSUSE 系，但机器上没有 zypper，装不了 {WIREGUARD_PKG}"),
                ));
            }
            vec![command(&[
                "zypper",
                "--non-interactive",
                "install",
                "-y",
                WIREGUARD_PKG,
            ])]
        }
        "" => {
            return Err(install_error(
                "",
                format!(
                    "认不出这台机器的发行版（{OS_RELEASE_PATH} 里没有已支持的 ID），装不了 {WIREGUARD_PKG}：请手动安装后再拨开关"
                ),
            ));
        }
        other => unreachable!("unexpected distro family {other}"),
    };
    Ok((steps, family.to_string()))
}

pub fn wireguard_install_hint(family: &str, output: &str) -> String {
    let lower = output.to_lowercase();
    match family {
        "rpm"
            if lower.contains("unable to find a match")
                || lower.contains("no package")
                || lower.contains("nothing to do") =>
        {
            "RHEL/CentOS 系通常是没接 EPEL：先跑 dnf install epel-release（CentOS 7 用 yum）再拨开关".to_string()
        }
        "deb"
            if lower.contains("unable to locate package")
                || lower.contains("no installation candidate") =>
        {
            "多半是 apt 索引太旧：在服务器上跑一次 apt-get update 再拨开关".to_string()
        }
        _ => String::new(),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WarpSetupInput {
    pub dev: String,
    pub peer_key: String,
    pub endpoint: String,
    pub port: i32,
    pub tun_ip: String,
    pub mtu: i32,
    pub veth_gw: String,
    pub veth: String,
    pub direct_ips: Vec<String>,
}

/// Direct exceptions must be installed before the device and its default
/// route. Otherwise WireGuard's outer packets are routed back into itself.
pub fn warp_setup_cmds(input: &WarpSetupInput) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for ip in
        std::iter::once(input.endpoint.as_str()).chain(input.direct_ips.iter().map(String::as_str))
    {
        if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
            commands.push(vec![
                "ip".to_string(),
                "route".to_string(),
                "replace".to_string(),
                format!("{parsed}/32"),
                "via".to_string(),
                input.veth_gw.clone(),
                "dev".to_string(),
                input.veth.clone(),
            ]);
        }
    }
    commands.push(vec![
        "ip".to_string(),
        "link".to_string(),
        "add".to_string(),
        "dev".to_string(),
        input.dev.clone(),
        "mtu".to_string(),
        input.mtu.to_string(),
        "type".to_string(),
        "wireguard".to_string(),
    ]);
    commands.push(vec![
        "ip".to_string(),
        "addr".to_string(),
        "add".to_string(),
        format!("{}/32", input.tun_ip),
        "dev".to_string(),
        input.dev.clone(),
    ]);
    commands.push(vec![
        "wg".to_string(),
        "set".to_string(),
        input.dev.clone(),
        "private-key".to_string(),
        WARP_KEY_STDIN.to_string(),
        "peer".to_string(),
        input.peer_key.clone(),
        "endpoint".to_string(),
        join_host_port(&input.endpoint, input.port),
        "allowed-ips".to_string(),
        "0.0.0.0/0".to_string(),
        "persistent-keepalive".to_string(),
        WARP_KEEPALIVE.to_string(),
    ]);
    commands.push(vec![
        "ip".to_string(),
        "link".to_string(),
        "set".to_string(),
        "dev".to_string(),
        input.dev.clone(),
        "up".to_string(),
    ]);
    commands.push(vec![
        "ip".to_string(),
        "route".to_string(),
        "replace".to_string(),
        "default".to_string(),
        "dev".to_string(),
        input.dev.clone(),
    ]);
    commands
}

pub fn wireguard_error_hint(raw: &str) -> String {
    let lower = raw.to_lowercase();
    if lower.contains("garbage instead of arguments") {
        return "这台机器上的 ip/wg 不认这套参数：升级 wireguard-tools 与 iproute2 后再拨开关"
            .to_string();
    }
    if lower.contains("unable to read key")
        || lower.contains("bad private key")
        || lower.contains("failed to open key file")
    {
        return "WireGuard 私钥没能递给 wg（它读标准输入这一步失败了）".to_string();
    }
    if lower.contains("bad peer public key") {
        return "WARP 服务端公钥没被接受".to_string();
    }
    if lower.contains("operation not supported") || lower.contains("not supported") {
        return "这台机器的内核没有 WireGuard：先 modprobe wireguard，装不上就要补内核模块或升内核"
            .to_string();
    }
    if lower.contains("cannot find device") || lower.contains("no such device") {
        return "WireGuard 设备没建起来".to_string();
    }
    if lower.contains("permission denied") || lower.contains("operation not permitted") {
        return "权限不够：root 之外还有 SELinux、capability 这一层".to_string();
    }
    if lower.contains("protocol error") || lower.contains("network is down") {
        return "wg 与内核版本对不上：升级 wireguard-tools".to_string();
    }
    String::new()
}

pub fn warp_argv(namespace: &str, command: &[String]) -> (String, Vec<String>) {
    let Some((program, args)) = command.split_first() else {
        return (String::new(), Vec::new());
    };
    if namespace.is_empty() {
        (program.clone(), args.to_vec())
    } else {
        let mut argv = vec![
            "netns".to_string(),
            "exec".to_string(),
            namespace.to_string(),
        ];
        argv.extend(command.iter().cloned());
        ("ip".to_string(), argv)
    }
}

pub fn warp_cmd_tag(namespace: &str, command: &[String]) -> String {
    let head = command
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    if namespace.is_empty() {
        head
    } else {
        format!("{namespace}：{head}")
    }
}

pub fn warp_probe_cmds(
    peer_key: &str,
    endpoint: &str,
    port: i32,
    mtu: i32,
) -> (Vec<Vec<String>>, Vec<String>) {
    let setup = vec![
        vec![
            "ip".to_string(),
            "link".to_string(),
            "add".to_string(),
            "dev".to_string(),
            WARP_PROBE_DEV.to_string(),
            "mtu".to_string(),
            mtu.to_string(),
            "type".to_string(),
            "wireguard".to_string(),
        ],
        vec![
            "wg".to_string(),
            "set".to_string(),
            WARP_PROBE_DEV.to_string(),
            "private-key".to_string(),
            WARP_KEY_STDIN.to_string(),
            "peer".to_string(),
            peer_key.to_string(),
            "endpoint".to_string(),
            join_host_port(endpoint, port),
            "allowed-ips".to_string(),
            "0.0.0.0/0".to_string(),
            "persistent-keepalive".to_string(),
            WARP_KEEPALIVE.to_string(),
        ],
    ];
    let cleanup = vec![
        "ip".to_string(),
        "link".to_string(),
        "del".to_string(),
        WARP_PROBE_DEV.to_string(),
    ];
    (setup, cleanup)
}

pub fn warp_gate_pin_cmds(dev: &str, gate_ips: &[String]) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for ip in gate_ips {
        if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
            commands.push(vec![
                "ip".to_string(),
                "route".to_string(),
                "replace".to_string(),
                format!("{parsed}/32"),
                "dev".to_string(),
                dev.to_string(),
            ]);
        }
    }
    commands
}

pub fn warp_split_cmds(dev: &str, tun: &str, gate_ips: &[String]) -> Vec<Vec<String>> {
    let mut commands = warp_gate_pin_cmds(dev, gate_ips);
    commands.push(vec![
        "ip".to_string(),
        "route".to_string(),
        "replace".to_string(),
        "0.0.0.0/1".to_string(),
        "dev".to_string(),
        tun.to_string(),
    ]);
    commands.push(vec![
        "ip".to_string(),
        "route".to_string(),
        "replace".to_string(),
        "128.0.0.0/1".to_string(),
        "dev".to_string(),
        tun.to_string(),
    ]);
    commands
}

pub fn warp_guard_cmds(
    dev: &str,
    tun: &str,
    gate_ips: &[String],
    tun_up: bool,
) -> Vec<Vec<String>> {
    if !tun_up {
        return vec![command(&["ip", "route", "del", "default"])];
    }
    let mut commands = vec![vec![
        "ip".to_string(),
        "route".to_string(),
        "replace".to_string(),
        "default".to_string(),
        "dev".to_string(),
        dev.to_string(),
    ]];
    commands.extend(warp_split_cmds(dev, tun, gate_ips));
    commands
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WarpRouteState {
    pub tun_up: bool,
    pub split_ok: bool,
    pub def_on_dev: bool,
}

pub fn parse_warp_routes(route_output: &str, dev: &str) -> WarpRouteState {
    let mut state = WarpRouteState::default();
    let mut split = HashSet::new();
    for line in route_output.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let Some(dev_at) = fields
            .iter()
            .position(|token| *token == "dev")
            .and_then(|index| index.checked_add(1))
            .filter(|index| *index < fields.len())
        else {
            continue;
        };
        let route_dev = fields[dev_at];
        if route_dev == "tun0" && fields.contains(&"proto") && fields.contains(&"kernel") {
            state.tun_up = true;
        } else if route_dev == "tun0" && (fields[0] == "0.0.0.0/1" || fields[0] == "128.0.0.0/1") {
            split.insert(fields[0]);
        } else if fields[0] == "default" && route_dev == dev {
            state.def_on_dev = true;
        }
    }
    state.split_ok = split.contains("0.0.0.0/1") && split.contains("128.0.0.0/1");
    state
}

pub fn warp_guard_needed(state: &WarpRouteState) -> bool {
    if state.tun_up {
        !state.split_ok || !state.def_on_dev
    } else {
        state.def_on_dev
    }
}

const WARP_CLOUDFLARE_V4: &[&str] = &[
    "104.16.0.0/12",
    "172.64.0.0/13",
    "162.158.0.0/15",
    "198.41.128.0/17",
    "108.162.192.0/18",
    "173.245.48.0/20",
    "141.101.64.0/18",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "131.0.72.0/22",
    "197.234.240.0/22",
];

fn ipv4_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(prefix)) = (network.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(network) & mask
}

pub fn warp_exit_is_transit_only(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    WARP_CLOUDFLARE_V4.iter().any(|cidr| ipv4_in_cidr(ip, cidr))
}

pub fn warp_gate_hosts(config: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in config.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        if matches!(fields[0], "remote" | "server" | "remote-entry") {
            let host = fields[1].to_string();
            if seen.insert(host.clone()) {
                out.push(host);
            }
        }
    }
    out
}

pub fn warp_gate_ips(config: &str, node_ip: &str) -> Vec<String> {
    let mut out = Vec::new();
    for host in warp_gate_hosts(config)
        .into_iter()
        .chain(std::iter::once(node_ip.to_string()))
    {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            out.push(ip.to_string());
        }
    }
    dedupe_sorted(&out)
}

pub fn warp_gate_names(config: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for host in warp_gate_hosts(config) {
        if host.parse::<std::net::IpAddr>().is_ok() || !seen.insert(host.clone()) {
            continue;
        }
        out.push(host);
    }
    out
}

pub fn dedupe_sorted(values: &[String]) -> Vec<String> {
    values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn warp_nameservers(resolv: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in resolv.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 || fields[0] != "nameserver" {
            continue;
        }
        if let Ok(ip) = fields[1].parse::<Ipv4Addr>() {
            let ip = ip.to_string();
            if seen.insert(ip.clone()) {
                out.push(ip);
            }
        }
    }
    out
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WarpPeer {
    pub pub_key: String,
    pub handshake: i64,
    pub endpoint: String,
    pub rx: i64,
    pub tx: i64,
    pub keepalive: i32,
}

impl WarpPeer {
    pub fn up(&self) -> bool {
        self.handshake > 0 && !self.endpoint.is_empty()
    }
}

pub fn parse_wg_dump(output: &str) -> Vec<WarpPeer> {
    let mut peers = Vec::new();
    for line in output.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[0].len() != 44 {
            continue;
        }
        let handshake = fields[4].parse::<i64>().unwrap_or(0);
        let rx = fields[5].parse::<i64>().unwrap_or(0);
        let tx = fields[6].parse::<i64>().unwrap_or(0);
        let endpoint = if fields[2] == "(none)" {
            String::new()
        } else {
            fields[2].to_string()
        };
        let keepalive = fields[7].parse::<i32>().unwrap_or(0);
        peers.push(WarpPeer {
            pub_key: fields[0].to_string(),
            handshake,
            endpoint,
            rx,
            tx,
            keepalive,
        });
    }
    peers
}

pub fn warp_handshake_age(handshake: i64, now_uptime: i64, now_wall: i64) -> (i64, bool) {
    if handshake <= 0 {
        (0, false)
    } else if handshake <= now_uptime {
        (now_uptime - handshake, true)
    } else if handshake <= now_wall {
        (now_wall - handshake, true)
    } else {
        (0, false)
    }
}

pub fn warp_live(peer: &WarpPeer, now_uptime: i64, now_wall: i64) -> bool {
    if !peer.up() {
        return false;
    }
    let (age, ok) = warp_handshake_age(peer.handshake, now_uptime, now_wall);
    ok && age <= WARP_FRESH_AFTER.as_secs() as i64
}

pub fn warp_live_endpoint(peers: &[WarpPeer], now_uptime: i64, now_wall: i64) -> (String, bool) {
    for peer in peers {
        if warp_live(peer, now_uptime, now_wall) {
            return (peer.endpoint.clone(), true);
        }
    }
    for peer in peers {
        if peer.up() {
            return (peer.endpoint.clone(), false);
        }
    }
    (String::new(), false)
}

pub fn warp_version_less(a: &str, b: &str) -> bool {
    match (warp_version_parts(a), warp_version_parts(b)) {
        (Some(a), Some(b)) => {
            for index in 0..a.len().max(b.len()) {
                let x = a.get(index).copied().unwrap_or(0);
                let y = b.get(index).copied().unwrap_or(0);
                if x != y {
                    return x < y;
                }
            }
            false
        }
        _ => a.trim() != b.trim(),
    }
}

pub fn warp_version_parts(version: &str) -> Option<Vec<u64>> {
    let version = plain_version(version.trim());
    let version = version.strip_prefix('v').unwrap_or(version);
    if version.is_empty() {
        return None;
    }
    version
        .split('.')
        .map(|part| {
            if part.is_empty() {
                None
            } else {
                part.parse::<u64>().ok()
            }
        })
        .collect()
}

pub fn parse_warp_pkg_version(body: &str) -> String {
    let mut in_warp = false;
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(package) = line.strip_prefix("Package:") {
            in_warp = package.trim() == "cloudflare-warp";
        } else if in_warp {
            if let Some(version) = line.strip_prefix("Version:") {
                return version.trim().to_string();
            }
        }
    }
    String::new()
}

pub fn parse_warp_codenames(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|codename| !codename.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpStore {
    pub version: u32,
    pub accounts: Vec<WarpAccount>,
}

pub fn render_warp_store(accounts: &[WarpAccount]) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&WarpStore {
        version: WARP_STORE_VERSION,
        accounts: accounts.to_vec(),
    })?)
}

pub fn parse_warp_store(blob: &[u8]) -> Result<Vec<WarpAccount>> {
    let store: WarpStore = serde_json::from_slice(blob).context("解析 WARP 注册记录失败")?;
    let mut accounts = Vec::with_capacity(store.accounts.len());
    for mut account in store.accounts {
        if account.id.is_empty()
            || account.priv_key.is_empty()
            || account.endpoint.is_empty()
            || account.peer_key.is_empty()
        {
            continue;
        }
        if account.port <= 0 {
            account.port = WARP_PORT;
        }
        if account.tun_ip.is_empty() {
            account.tun_ip = WARP_TUN_IP.to_string();
        }
        accounts.push(account);
    }
    Ok(accounts)
}

fn command(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
}

fn plain_version(version: &str) -> &str {
    version
        .split(|character| character == '-' || character == '+')
        .next()
        .unwrap_or("")
}

fn openvpn_version_parts(version: &str) -> Option<(i32, i32)> {
    let mut parts = version.trim().split('.');
    let major = leading_digits(parts.next()?)?;
    let minor = leading_digits(parts.next()?)?;
    Some((major, minor))
}

fn leading_digits(value: &str) -> Option<i32> {
    let count = value
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if count == 0 {
        None
    } else {
        value[..count].parse().ok()
    }
}

fn parse_os_release(blob: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in blob.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        values.insert(
            key.trim().to_string(),
            value.trim_matches(&['"', '\''][..]).to_string(),
        );
    }
    values
}

fn distro_family(values: &HashMap<String, String>) -> &'static str {
    for key in ["ID_LIKE", "ID"] {
        for name in values
            .get(key)
            .map(String::as_str)
            .unwrap_or("")
            .split_whitespace()
        {
            match name.to_lowercase().as_str() {
                "debian" | "ubuntu" => return "deb",
                "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "amzn" | "ol" => {
                    return "rpm"
                }
                "suse" | "opensuse-tumbleweed" | "opensuse-leap" | "sles" => return "suse",
                "alpine" => return "alpine",
                "arch" | "manjaro" | "endeavouros" => return "arch",
                _ => {}
            }
        }
    }
    ""
}

#[cfg(test)]
#[path = "warp_logic_test.rs"]
mod tests;
