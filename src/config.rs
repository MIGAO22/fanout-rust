use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::IpAddr,
    path::Path,
    sync::{Mutex, OnceLock},
};

pub const DEFAULT_PORT: u16 = 8899;
pub const DEFAULT_HEALTH_INTERVAL: u64 = 10;
pub const DEFAULT_HEALTH_FAILURES: u32 = 3;
pub const DEFAULT_HEALTH_TIMEOUT: u64 = 6;
pub const DEFAULT_BACKOFF_MIN: u64 = 5;
pub const DEFAULT_BACKOFF_MAX: u64 = 60;
pub const DEFAULT_CONNECT_BUDGET: u64 = 35;
pub const DEFAULT_MAX_TRIES: usize = 6;
pub const DEFAULT_PANEL_DEBOUNCE: u64 = 1500;
pub const DEFAULT_NODE_TTL: u64 = 600;
pub const DEFAULT_RECONNECT_LIMIT: usize = 2;
pub const DEFAULT_WARP_HANDSHAKE_TIMEOUT: u64 = 5;

fn default_true() -> bool {
    true
}

fn default_min_dwell_secs() -> u64 {
    60
}

fn default_switch_cooldown_secs() -> u64 {
    30
}

fn default_node_quarantine_secs() -> u64 {
    120
}

static SETTINGS_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn settings_file_lock() -> &'static Mutex<()> {
    SETTINGS_FILE_LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct WebSettings {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub listen_addr: String,
    #[serde(default)]
    pub residential_only: Option<bool>,
    #[serde(default)]
    pub sub_token: Option<String>,
    #[serde(default)]
    pub metrics_token: Option<String>,
    #[serde(default)]
    pub warp: Option<WarpSettings>,
    #[serde(default)]
    pub conn: ConnSettings,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpSettings {
    pub enabled: bool,
    pub client_version: Option<String>,
    pub pool: WarpPoolSettings,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpPoolSettings {
    pub enabled: bool,
    pub prewarm: bool,
    pub size: usize,
    pub prewarm_ttl_secs: u64,
    pub rotate_after_failures: u32,
}

impl WarpPoolSettings {
    fn normalized(&mut self) {
        self.size = if self.size == 0 {
            4
        } else {
            self.size.clamp(1, 20)
        };
        self.prewarm_ttl_secs = if self.prewarm_ttl_secs == 0 {
            1800
        } else {
            self.prewarm_ttl_secs.clamp(60, 86_400)
        };
        self.rotate_after_failures = if self.rotate_after_failures == 0 {
            3
        } else {
            self.rotate_after_failures.clamp(1, 20)
        };
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ConnSettings {
    #[serde(default)]
    pub health_interval: u64,
    #[serde(default)]
    pub health_failures: u32,
    #[serde(default)]
    pub health_timeout: u64,
    #[serde(default)]
    pub backoff_min: u64,
    #[serde(default)]
    pub backoff_max: u64,
    #[serde(default)]
    pub connect_budget: u64,
    #[serde(default)]
    pub max_tries: usize,
    #[serde(default)]
    pub panel_debounce: u64,
    #[serde(default)]
    pub node_ttl: u64,
    #[serde(default)]
    pub score_mode: String,
    #[serde(default)]
    pub reconnect_limit: usize,
    #[serde(default)]
    pub warp_handshake_timeout: u64,
    #[serde(default)]
    pub aead_only: bool,
    #[serde(default = "default_true")]
    pub smart_selection: bool,
    #[serde(default = "default_min_dwell_secs")]
    pub min_dwell_secs: u64,
    #[serde(default = "default_switch_cooldown_secs")]
    pub switch_cooldown_secs: u64,
    #[serde(default = "default_node_quarantine_secs")]
    pub node_quarantine_secs: u64,
}

impl WebSettings {
    pub fn normalized(mut self) -> Self {
        if self.port == 0 {
            self.port = DEFAULT_PORT;
        }
        self.listen_addr =
            normalize_listen_addr(&self.listen_addr).unwrap_or_else(|_| "0.0.0.0".into());
        let c = &mut self.conn;
        c.health_interval = if c.health_interval == 0 {
            DEFAULT_HEALTH_INTERVAL
        } else {
            c.health_interval.clamp(2, 3600)
        };
        c.health_failures = if c.health_failures == 0 {
            DEFAULT_HEALTH_FAILURES
        } else {
            c.health_failures.clamp(1, 20)
        };
        c.health_timeout = if c.health_timeout == 0 {
            DEFAULT_HEALTH_TIMEOUT
        } else {
            c.health_timeout.clamp(2, 120)
        };
        c.backoff_min = if c.backoff_min == 0 {
            DEFAULT_BACKOFF_MIN
        } else {
            c.backoff_min.clamp(1, 3600)
        };
        c.backoff_max = if c.backoff_max == 0 {
            DEFAULT_BACKOFF_MAX
        } else {
            c.backoff_max.clamp(c.backoff_min, 86400)
        };
        c.connect_budget = if c.connect_budget == 0 {
            DEFAULT_CONNECT_BUDGET
        } else {
            c.connect_budget.clamp(10, 600)
        };
        c.max_tries = if c.max_tries == 0 {
            DEFAULT_MAX_TRIES
        } else {
            c.max_tries.clamp(1, 50)
        };
        c.panel_debounce = if c.panel_debounce == 0 {
            DEFAULT_PANEL_DEBOUNCE
        } else {
            c.panel_debounce.clamp(100, 30_000)
        };
        c.node_ttl = if c.node_ttl == 0 {
            DEFAULT_NODE_TTL
        } else {
            c.node_ttl.clamp(30, 86_400)
        };
        c.reconnect_limit = if c.reconnect_limit == 0 {
            DEFAULT_RECONNECT_LIMIT
        } else {
            c.reconnect_limit.clamp(1, 50)
        };
        c.warp_handshake_timeout = if c.warp_handshake_timeout == 0 {
            DEFAULT_WARP_HANDSHAKE_TIMEOUT
        } else {
            c.warp_handshake_timeout.clamp(1, 60)
        };
        c.min_dwell_secs = if c.min_dwell_secs == 0 {
            default_min_dwell_secs()
        } else {
            c.min_dwell_secs.clamp(0, 3600)
        };
        c.switch_cooldown_secs = if c.switch_cooldown_secs == 0 {
            default_switch_cooldown_secs()
        } else {
            c.switch_cooldown_secs.clamp(0, 3600)
        };
        c.node_quarantine_secs = if c.node_quarantine_secs == 0 {
            default_node_quarantine_secs()
        } else {
            c.node_quarantine_secs.clamp(10, 3600)
        };
        if !matches!(
            c.score_mode.as_str(),
            "balanced" | "speed" | "idle" | "ping"
        ) {
            c.score_mode = "balanced".into();
        }
        if let Some(warp) = self.warp.as_mut() {
            warp.pool.normalized();
        }
        self
    }

    pub fn listen(&self) -> String {
        match self.listen_addr.parse::<IpAddr>() {
            Ok(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
            _ => format!("{}:{}", self.listen_addr, self.port),
        }
    }

    pub fn residential_only(&self) -> bool {
        self.residential_only.unwrap_or(true)
    }

    pub fn warp(&self) -> WarpSettings {
        self.warp.clone().unwrap_or_default()
    }
}

impl ConnSettings {
    pub fn defaults() -> Self {
        Self {
            health_interval: DEFAULT_HEALTH_INTERVAL,
            health_failures: DEFAULT_HEALTH_FAILURES,
            health_timeout: DEFAULT_HEALTH_TIMEOUT,
            backoff_min: DEFAULT_BACKOFF_MIN,
            backoff_max: DEFAULT_BACKOFF_MAX,
            connect_budget: DEFAULT_CONNECT_BUDGET,
            max_tries: DEFAULT_MAX_TRIES,
            panel_debounce: DEFAULT_PANEL_DEBOUNCE,
            node_ttl: DEFAULT_NODE_TTL,
            score_mode: "balanced".into(),
            reconnect_limit: DEFAULT_RECONNECT_LIMIT,
            warp_handshake_timeout: DEFAULT_WARP_HANDSHAKE_TIMEOUT,
            aead_only: false,
            smart_selection: true,
            min_dwell_secs: default_min_dwell_secs(),
            switch_cooldown_secs: default_switch_cooldown_secs(),
            node_quarantine_secs: default_node_quarantine_secs(),
        }
    }
}

pub fn normalize_listen_addr(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty() || s == "0.0.0.0" || s == "127.0.0.1" {
        return Ok(if s.is_empty() {
            "0.0.0.0".into()
        } else {
            s.into()
        });
    }
    let ip: IpAddr = s.parse()?;
    Ok(ip.to_string())
}

pub fn load_settings(dir: &Path, port: u16, explicit: bool) -> Result<WebSettings> {
    let path = dir.join("settings.json");
    let mut s = match fs::read(&path) {
        Ok(b) => serde_json::from_slice::<WebSettings>(&b)
            .context("settings.json 损坏，拒绝静默重置配置")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => WebSettings::default(),
        Err(e) => return Err(e.into()),
    };
    if explicit || s.port == 0 {
        s.port = port;
    }
    if s.conn == Default::default() {
        s.conn = ConnSettings::defaults();
    }
    Ok(s.normalized())
}

pub fn save_settings(dir: &Path, settings: &WebSettings) -> Result<()> {
    let data = serde_json::to_vec_pretty(settings)?;
    crate::util::atomic_write(dir.join("settings.json"), &data, 0o600)
}

#[cfg(test)]
#[path = "config_test.rs"]
mod tests;
