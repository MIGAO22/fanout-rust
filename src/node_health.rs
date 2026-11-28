use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Mutex as StdMutex,
    time::{Duration, Instant},
};

const EWMA_ALPHA: f64 = 0.3;

#[derive(Clone, Debug, Serialize)]
pub struct NodeHealthSnapshot {
    pub host: String,
    pub samples: u64,
    pub connect_latency_ms: Option<f64>,
    pub probe_latency_ms: Option<f64>,
    pub loss_ewma: f64,
    pub warp_success_ewma: Option<f64>,
    pub failure_streak: u32,
    pub success_streak: u32,
    pub last_success: Option<DateTime<Utc>>,
    pub last_failure: Option<DateTime<Utc>>,
    pub quarantined: bool,
}

struct NodeHealth {
    host: String,
    samples: u64,
    connect_latency_ms: Option<f64>,
    probe_latency_ms: Option<f64>,
    loss_ewma: f64,
    warp_success_ewma: Option<f64>,
    failure_streak: u32,
    success_streak: u32,
    last_success: Option<DateTime<Utc>>,
    last_failure: Option<DateTime<Utc>>,
    quarantine_until: Option<Instant>,
}

impl NodeHealth {
    fn new(host: String) -> Self {
        Self {
            host,
            samples: 0,
            connect_latency_ms: None,
            probe_latency_ms: None,
            loss_ewma: 0.0,
            warp_success_ewma: None,
            failure_streak: 0,
            success_streak: 0,
            last_success: None,
            last_failure: None,
            quarantine_until: None,
        }
    }

    fn update_latency(current: &mut Option<f64>, sample: f64) {
        *current = Some(match current {
            Some(previous) => *previous + (sample - *previous) * EWMA_ALPHA,
            None => sample,
        });
    }

    fn record_success(&mut self) {
        self.samples += 1;
        self.failure_streak = 0;
        self.success_streak = self.success_streak.saturating_add(1);
        self.last_success = Some(Utc::now());
        self.quarantine_until = None;
        self.loss_ewma += (0.0 - self.loss_ewma) * EWMA_ALPHA;
    }

    fn record_failure(&mut self, quarantine: Duration) {
        self.samples += 1;
        self.success_streak = 0;
        self.failure_streak = self.failure_streak.saturating_add(1);
        self.last_failure = Some(Utc::now());
        self.loss_ewma += (1.0 - self.loss_ewma) * EWMA_ALPHA;
        if self.failure_streak >= 3 {
            let exponent = (self.failure_streak - 3).min(6);
            let seconds = quarantine
                .as_secs()
                .saturating_mul(2_u64.pow(exponent))
                .min(900);
            self.quarantine_until = Some(Instant::now() + Duration::from_secs(seconds));
        }
    }

    fn quarantined(&self) -> bool {
        self.quarantine_until
            .is_some_and(|until| until > Instant::now())
    }

    fn score(&self, static_score: f64) -> f64 {
        if self.samples == 0 {
            return static_score.clamp(0.0, 1.0);
        }
        let mut score = static_score.clamp(0.0, 1.0) * 0.55;
        if let Some(latency) = self.probe_latency_ms.or(self.connect_latency_ms) {
            score += (1.0 - (latency / 1000.0).clamp(0.0, 1.0)) * 0.2;
        }
        score += (1.0 - self.loss_ewma.clamp(0.0, 1.0)) * 0.15;
        if let Some(warp) = self.warp_success_ewma {
            score += warp.clamp(0.0, 1.0) * 0.1;
        }
        score -= (self.failure_streak.min(5) as f64) * 0.05;
        score.clamp(0.0, 1.0)
    }

    fn snapshot(&self) -> NodeHealthSnapshot {
        NodeHealthSnapshot {
            host: self.host.clone(),
            samples: self.samples,
            connect_latency_ms: self.connect_latency_ms,
            probe_latency_ms: self.probe_latency_ms,
            loss_ewma: self.loss_ewma,
            warp_success_ewma: self.warp_success_ewma,
            failure_streak: self.failure_streak,
            success_streak: self.success_streak,
            last_success: self.last_success,
            last_failure: self.last_failure,
            quarantined: self.quarantined(),
        }
    }
}

#[derive(Default)]
pub struct NodeHealthStore {
    inner: StdMutex<HashMap<String, NodeHealth>>,
}

impl NodeHealthStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, NodeHealth>> {
        self.inner.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub fn record_connect(&self, host: &str, ok: bool, latency_ms: f64, quarantine: Duration) {
        let mut nodes = self.lock();
        let health = nodes
            .entry(host.to_string())
            .or_insert_with(|| NodeHealth::new(host.into()));
        if ok {
            health.record_success();
            NodeHealth::update_latency(&mut health.connect_latency_ms, latency_ms);
        } else {
            health.record_failure(quarantine);
        }
    }

    pub fn record_probe(
        &self,
        host: &str,
        ok: bool,
        latency_ms: Option<f64>,
        quarantine: Duration,
    ) {
        let mut nodes = self.lock();
        let health = nodes
            .entry(host.to_string())
            .or_insert_with(|| NodeHealth::new(host.into()));
        if ok {
            health.record_success();
            if let Some(latency) = latency_ms {
                NodeHealth::update_latency(&mut health.probe_latency_ms, latency);
            }
        } else {
            health.record_failure(quarantine);
        }
    }

    pub fn record_warp(&self, host: &str, ok: bool) {
        let mut nodes = self.lock();
        let health = nodes
            .entry(host.to_string())
            .or_insert_with(|| NodeHealth::new(host.into()));
        let previous = health
            .warp_success_ewma
            .unwrap_or(if ok { 1.0 } else { 0.0 });
        health.warp_success_ewma =
            Some(previous + ((if ok { 1.0 } else { 0.0 }) - previous) * EWMA_ALPHA);
    }

    pub fn is_quarantined(&self, host: &str) -> bool {
        self.lock()
            .get(host)
            .is_some_and(|health| health.quarantined())
    }

    pub fn score(&self, host: &str, static_score: f64) -> f64 {
        self.lock()
            .get(host)
            .map_or(static_score, |health| health.score(static_score))
    }

    pub fn snapshots(&self) -> Vec<NodeHealthSnapshot> {
        let mut out: Vec<_> = self.lock().values().map(NodeHealth::snapshot).collect();
        out.sort_by(|a, b| a.host.cmp(&b.host));
        out
    }

    pub fn retain_hosts(&self, hosts: &HashMap<String, bool>) {
        self.lock().retain(|host, _| hosts.contains_key(host));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_and_quarantine_are_bounded() {
        let store = NodeHealthStore::default();
        let quarantine = Duration::from_secs(60);
        store.record_connect("node", true, 100.0, quarantine);
        store.record_connect("node", true, 140.0, quarantine);
        store.record_probe("node", false, None, quarantine);
        store.record_probe("node", false, None, quarantine);
        store.record_probe("node", false, None, quarantine);
        assert!(store.is_quarantined("node"));
        let snapshot = store.snapshots().remove(0);
        assert_eq!(snapshot.failure_streak, 3);
        assert!(snapshot.loss_ewma > 0.0);
        assert!(store.score("node", 0.5) <= 0.5);
        store.record_probe("node", true, Some(120.0), quarantine);
        assert!(!store.is_quarantined("node"));
    }

    #[test]
    fn unknown_nodes_use_static_score() {
        let store = NodeHealthStore::default();
        assert_eq!(store.score("unknown", 0.7), 0.7);
    }
}
