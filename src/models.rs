use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub hostname: String,
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub ping: i64,
    pub speed_mbps: f64,
    pub sessions: i64,
    pub residential: bool,
    #[serde(default, skip_serializing)]
    pub config: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SocksCred {
    pub user: String,
    pub pass: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PersistedTunnel {
    pub slot: usize,
    pub port: u16,
    pub hostname: String,
    pub country_code: String,
    pub country: String,
    pub config: String,
    #[serde(default)]
    pub socks_user: Option<String>,
    #[serde(default)]
    pub socks_pass: Option<String>,
    #[serde(default)]
    pub prev_host: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TunnelState {
    pub slot: usize,
    pub port: u16,
    pub node: Node,
    pub status: String,
    #[serde(default)]
    pub exit_ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub err: String,
    pub since: DateTime<Utc>,
    pub cred: SocksCred,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExitInbound {
    pub id: String,
    pub port: u16,
    pub remark: String,
    pub protocol: String,
    pub enable: bool,
    pub tag: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Exit {
    pub slot: usize,
    pub port: u16,
    pub host: String,
    pub region: String,
    pub country: String,
    pub exit_ip: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub err: String,
    pub since: DateTime<Utc>,
    pub socks_user: String,
    pub socks_pass: String,
    pub inbounds: Vec<ExitInbound>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub warp_ip: String,
    #[serde(default)]
    pub warp_live: bool,
    #[serde(default)]
    pub aead: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WarpOverview {
    pub enabled: bool,
    pub ready: bool,
    pub reason: String,
    pub need_tools: bool,
    pub pkg_cmd: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_err: String,
    pub version: String,
    pub count: usize,
    pub live: usize,
    pub stale: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PoolMemberView {
    pub host: String,
    pub slot: usize,
    pub status: String,
    pub exit_ip: String,
    pub latency_ms: i64,
    pub cooling: bool,
    pub aead: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PoolView {
    pub id: String,
    pub identity: String,
    pub name: String,
    pub mode: String,
    pub mode_label: String,
    pub mode_desc: String,
    pub rr_step: usize,
    pub port: u16,
    pub running: bool,
    pub up: usize,
    pub total: usize,
    pub socks_user: String,
    pub socks_pass: String,
    #[serde(skip)]
    pub cred: SocksCred,
    pub members: Vec<PoolMemberView>,
    pub inbounds: Vec<ExitInbound>,
    pub auto_fill: bool,
    pub size: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fill_note: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExitsView {
    pub exits: Vec<Exit>,
    #[serde(default)]
    pub direct: Vec<serde_json::Value>,
    pub pools: Vec<PoolView>,
    #[serde(default)]
    pub panel: Vec<serde_json::Value>,
    pub backend: String,
    pub panel_info: String,
    pub public_ip: String,
    pub warp: WarpOverview,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JobStep {
    pub label: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobView {
    pub id: String,
    pub summary: String,
    pub status: String,
    pub steps: Vec<JobStep>,
    pub started: DateTime<Utc>,
    pub done: DateTime<Utc>,
    pub total: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RegionStat {
    pub code: String,
    pub name: String,
    pub available: usize,
    pub best_ping: i64,
    pub best_speed_mbps: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostStats {
    pub cpu: f64,
    pub mem_pct: f64,
    pub mem_used: u64,
    pub mem_total: u64,
    pub swap_pct: f64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub disk_pct: f64,
    pub disk_used: u64,
    pub disk_total: u64,
    pub disk_mount: String,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub cores: usize,
    pub load_pct: f64,
    pub tcp: u64,
    pub tcp_pct: f64,
    pub udp: u64,
    pub udp_pct: f64,
    pub tcp6: u64,
    pub udp6: u64,
    pub sock_cap: u64,
    pub up_bps: u64,
    pub down_bps: u64,
    pub up_pct: f64,
    pub down_pct: f64,
    pub net_ready: bool,
    pub net_if: String,
    pub link_mbps: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub current: String,
    pub latest: String,
    pub has_update: bool,
    pub notes: String,
    pub url: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientBinStatus {
    pub backend: String,
    pub path: String,
    pub current: String,
    pub openvpn: String,
    pub latest: String,
    pub has_update: bool,
    pub updatable: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub check_error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_family: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_cmd: String,
    #[serde(default)]
    pub openvpn_updatable: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_latest: String,
    #[serde(default)]
    pub openvpn_has_update: bool,
    #[serde(default)]
    pub openvpn_stale: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_upstream: String,
    #[serde(default)]
    pub openvpn_behind_upstream: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_note: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_target: String,
    #[serde(default)]
    pub openvpn_official: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_from_official: String,
    #[serde(default)]
    pub openvpn_repo_wired: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_repo_line: String,
    #[serde(default)]
    pub openvpn_can_build: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_build_ver: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_build_cmd: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_build_path: String,
    #[serde(default)]
    pub openvpn_source_active: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_source_ver: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openvpn_source_bin: String,
    #[serde(default)]
    pub openvpn_apt: bool,
    #[serde(default)]
    pub warp_enabled: bool,
    #[serde(default)]
    pub warp_ready: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub warp_reason: String,
    #[serde(default)]
    pub warp_need_tools: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub warp_pkg_cmd: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub warp_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub warp_latest: String,
    #[serde(default)]
    pub warp_has_update: bool,
    pub warp_count: usize,
    pub warp_stale: usize,
    #[serde(default)]
    pub warp_can_apply: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub warp_check_error: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Inbound {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub remark: String,
    pub enable: bool,
    pub tag: String,
    pub bound_to: String,
    pub bound_up: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientInfo {
    pub email: String,
    pub id: String,
    pub enable: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InboundDetail {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub remark: String,
    pub enable: bool,
    pub tag: String,
    pub bound_to: String,
    pub bound_up: bool,
    pub clients: Vec<ClientInfo>,
    pub links: Vec<String>,
    pub listen: String,
    pub network: String,
    pub tls: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Pool {
    pub id: String,
    pub name: String,
    pub mode: String,
    pub hosts: Vec<String>,
    pub rr_step: usize,
    pub port: u16,
    pub cred: SocksCred,
    pub auto_fill: bool,
    pub size: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PoolStore {
    pub next: u64,
    pub pools: Vec<Pool>,
}

pub const POOL_MODES: &[&str] = &["single", "roundrobin", "latency", "race"];
pub const POOL_DEFAULT_RR_STEP: usize = 5;
pub const POOL_MAX_HOSTS: usize = 32;

pub fn pool_mode_label(mode: &str) -> &'static str {
    match mode {
        "single" => "单一出口",
        "roundrobin" => "轮询出口",
        "latency" => "负载均衡出口",
        "race" => "并发出口",
        _ => "",
    }
}

pub fn pool_mode_desc(mode: &str) -> &'static str {
    match mode {
        "single" => "咬住一条，不通才换组内下一条",
        "roundrobin" => "每 N 个新目标换一条",
        "latency" => "按实测拨号延迟挑最快的",
        "race" => "同时向组内所有可用出口发起，谁先通用谁",
        _ => "",
    }
}

pub fn empty_json_map() -> HashMap<String, serde_json::Value> {
    HashMap::new()
}
