use crate::process::output_command;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

// Host-address probes from publicip.go. These are deliberately HTTPS and are
// separate from the HTTP exit-address oracles in health.go.
pub const PUBLIC_IP_SOURCES: [&str; 3] = [
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://ifconfig.me/ip",
];

// The five exit-IP oracles from health.go, kept here for the health-module port.
pub const IP_ORACLES: [&str; 5] = [
    "http://api.ipify.org",
    "http://ipv4.icanhazip.com",
    "http://4.ident.me",
    "http://ifconfig.me/ip",
    "http://ipecho.net/plain",
];

pub const PUBLIC_IP_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Default)]
pub(crate) struct PublicIPState {
    pub(crate) override_ip: String,
    pub(crate) cache: String,
    pub(crate) at: Option<Instant>,
}

static PUBLIC_IP_STATE: Mutex<PublicIPState> = Mutex::new(PublicIPState {
    override_ip: String::new(),
    cache: String::new(),
    at: None,
});

fn lock_unpoisoned(state: &Mutex<PublicIPState>) -> MutexGuard<'_, PublicIPState> {
    state.lock().unwrap_or_else(|err| err.into_inner())
}

impl PublicIPState {
    pub(crate) fn set_override(&mut self, ip: &str) {
        self.override_ip = ip.trim().to_string();
    }

    fn fresh_cache(&self, now: Instant) -> Option<String> {
        if self.cache.is_empty() {
            return None;
        }
        let fresh = self
            .at
            .map(|at| now.saturating_duration_since(at) < PUBLIC_IP_TTL)
            .unwrap_or(false);
        fresh.then(|| self.cache.clone())
    }
}

/// Set an explicit host IPv4 (or clear it with an empty/whitespace string).
/// Like the Go version, this override is not validated here.
pub fn set_public_ip_override(ip: &str) {
    lock_unpoisoned(&PUBLIC_IP_STATE).set_override(ip);
}

/// Return the explicit override, a fresh cached address, or a newly probed one.
/// If every probe fails, an expired cached address is still preferred to empty.
pub fn host_public_ip() -> String {
    resolve_public_ip(&PUBLIC_IP_STATE, probe_public_ip, Instant::now())
}

pub(crate) fn resolve_public_ip<F>(
    state: &Mutex<PublicIPState>,
    probe: F,
    now: Instant,
) -> String
where
    F: FnOnce() -> String,
{
    {
        let state = lock_unpoisoned(state);
        if !state.override_ip.is_empty() {
            return state.override_ip.clone();
        }
        if let Some(cached) = state.fresh_cache(now) {
            return cached;
        }
    }

    let probed = probe();
    let mut state = lock_unpoisoned(state);
    if probed.is_empty() {
        state.cache.clone()
    } else {
        state.cache = probed.clone();
        // The TTL starts when probing finishes, not when the request began.
        state.at = Some(Instant::now());
        probed
    }
}

pub(crate) fn is_ipv4_or_mapped(ip: &str) -> bool {
    let Ok(parsed) = ip.parse::<IpAddr>() else {
        return false;
    };
    match parsed {
        IpAddr::V4(_) => true,
        // Go's net.IP.To4 accepts IPv4-mapped IPv6 spellings too, and returns
        // the original trimmed spelling rather than normalizing it.
        IpAddr::V6(v6) => v6.to_ipv4().is_some(),
    }
}

pub(crate) fn probe_sources<I, F>(sources: I, mut fetch: F) -> String
where
    I: IntoIterator<Item = String>,
    F: FnMut(&str) -> Option<String>,
{
    for source in sources {
        let Some(body) = fetch(&source) else {
            continue;
        };
        let ip = body.trim();
        if is_ipv4_or_mapped(ip) {
            return ip.to_string();
        }
    }
    String::new()
}

/// Probe the three host-IP services in order, returning the first valid IPv4.
pub fn probe_public_ip() -> String {
    probe_sources(
        PUBLIC_IP_SOURCES.iter().map(|source| (*source).to_string()),
        |source| {
            let args = vec![
                "-4".to_string(),
                "-s".to_string(),
                "--max-time".to_string(),
                "5".to_string(),
                source.to_string(),
            ];
            output_command("curl", &args)
                .ok()
                .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        },
    )
}
