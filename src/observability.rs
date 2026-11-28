use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Instant,
};

const TIMELINE_LIMIT: usize = 256;
const LOSS_WINDOW: usize = 20;

#[derive(Debug, Default)]
pub struct TrafficCounters {
    up: AtomicU64,
    down: AtomicU64,
    active: AtomicU64,
}

impl TrafficCounters {
    pub fn add_up(&self, bytes: usize) {
        self.up.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn add_down(&self, bytes: usize) {
        self.down.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn enter(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn leave(&self) {
        self.active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                active.checked_sub(1)
            })
            .ok();
    }

    pub fn active_connections(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TimelineEvent {
    pub at: DateTime<Utc>,
    pub slot: usize,
    pub host: String,
    pub generation: u64,
    pub kind: String,
    pub status: String,
    pub reason: String,
    pub latency_ms: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitMetricsSnapshot {
    pub slot: usize,
    pub host: String,
    pub generation: u64,
    pub probe_total: u64,
    pub probe_failures: u64,
    pub loss_ratio: f64,
    pub latency_ms: Option<f64>,
    pub jitter_ms: f64,
    pub reconnects: u64,
    pub failures: u64,
    pub last_probe: Option<DateTime<Utc>>,
    pub traffic_up_bytes: u64,
    pub traffic_down_bytes: u64,
    pub active_connections: u64,
    pub up_bps: f64,
    pub down_bps: f64,
}

struct ExitMetrics {
    slot: usize,
    host: String,
    generation: u64,
    probe_total: u64,
    probe_failures: u64,
    latency_ms: Option<f64>,
    jitter_ms: f64,
    recent: VecDeque<bool>,
    reconnects: u64,
    failures: u64,
    last_probe: Option<DateTime<Utc>>,
    traffic: Arc<TrafficCounters>,
    last_traffic_sample: Option<(Instant, u64, u64)>,
    up_bps: f64,
    down_bps: f64,
}

impl ExitMetrics {
    fn new(slot: usize, host: String, generation: u64, traffic: Arc<TrafficCounters>) -> Self {
        Self {
            slot,
            host,
            generation,
            probe_total: 0,
            probe_failures: 0,
            latency_ms: None,
            jitter_ms: 0.0,
            recent: VecDeque::with_capacity(LOSS_WINDOW),
            reconnects: 0,
            failures: 0,
            last_probe: None,
            traffic,
            last_traffic_sample: None,
            up_bps: 0.0,
            down_bps: 0.0,
        }
    }

    fn record_probe(&mut self, ok: bool, latency_ms: Option<f64>) -> bool {
        let was_failing = self.probe_failures > 0;
        self.probe_total += 1;
        self.last_probe = Some(Utc::now());
        self.recent.push_back(ok);
        if self.recent.len() > LOSS_WINDOW {
            self.recent.pop_front();
        }
        if ok {
            self.probe_failures = 0;
            if let Some(latency) = latency_ms {
                if let Some(previous) = self.latency_ms {
                    self.jitter_ms = self.jitter_ms * 0.7 + (latency - previous).abs() * 0.3;
                }
                self.latency_ms = Some(latency);
            }
        } else {
            self.probe_failures += 1;
            self.failures += 1;
        }
        was_failing
    }

    fn snapshot(&mut self) -> ExitMetricsSnapshot {
        let (up, down) = self.traffic.snapshot();
        let now = Instant::now();
        if let Some((at, prev_up, prev_down)) = self.last_traffic_sample {
            let elapsed = at.elapsed().as_secs_f64();
            if elapsed >= 0.5 {
                self.up_bps = (up.saturating_sub(prev_up) as f64 * 8.0 / elapsed).max(0.0);
                self.down_bps = (down.saturating_sub(prev_down) as f64 * 8.0 / elapsed).max(0.0);
                self.last_traffic_sample = Some((now, up, down));
            }
        } else {
            self.last_traffic_sample = Some((now, up, down));
        }
        let loss = if self.recent.is_empty() {
            0.0
        } else {
            self.recent.iter().filter(|ok| !**ok).count() as f64 / self.recent.len() as f64
        };
        ExitMetricsSnapshot {
            slot: self.slot,
            host: self.host.clone(),
            generation: self.generation,
            probe_total: self.probe_total,
            probe_failures: self.probe_failures,
            loss_ratio: loss,
            latency_ms: self.latency_ms,
            jitter_ms: self.jitter_ms,
            reconnects: self.reconnects,
            failures: self.failures,
            last_probe: self.last_probe,
            traffic_up_bytes: up,
            traffic_down_bytes: down,
            active_connections: self.traffic.active_connections(),
            up_bps: self.up_bps,
            down_bps: self.down_bps,
        }
    }
}

pub struct ObservabilityStore {
    slots: StdMutex<HashMap<usize, ExitMetrics>>,
    timeline: StdMutex<VecDeque<TimelineEvent>>,
}

impl Default for ObservabilityStore {
    fn default() -> Self {
        Self {
            slots: StdMutex::new(HashMap::new()),
            timeline: StdMutex::new(VecDeque::new()),
        }
    }
}

impl ObservabilityStore {
    fn lock_slots(&self) -> std::sync::MutexGuard<'_, HashMap<usize, ExitMetrics>> {
        self.slots.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn lock_timeline(&self) -> std::sync::MutexGuard<'_, VecDeque<TimelineEvent>> {
        self.timeline
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub fn reset_slot(
        &self,
        slot: usize,
        host: String,
        generation: u64,
        traffic: Arc<TrafficCounters>,
    ) {
        self.lock_slots()
            .insert(slot, ExitMetrics::new(slot, host, generation, traffic));
    }

    pub fn update_identity(&self, slot: usize, host: String, generation: u64) {
        if let Some(metrics) = self.lock_slots().get_mut(&slot) {
            metrics.host = host;
            metrics.generation = generation;
        }
    }

    pub fn remove_slot(&self, slot: usize) {
        self.lock_slots().remove(&slot);
    }

    pub fn record_probe(
        &self,
        slot: usize,
        host: String,
        generation: u64,
        ok: bool,
        latency_ms: Option<f64>,
        reason: &str,
    ) {
        let event = {
            let mut slots = self.lock_slots();
            let Some(metrics) = slots.get_mut(&slot) else {
                return;
            };
            if metrics.generation != generation {
                return;
            }
            metrics.host = host.clone();
            let was_failing = metrics.record_probe(ok, latency_ms);
            if ok && was_failing {
                Some((
                    "probe_recovered".to_string(),
                    "up".to_string(),
                    String::new(),
                ))
            } else if !ok {
                Some((
                    "probe_failed".to_string(),
                    "degraded".to_string(),
                    reason.to_string(),
                ))
            } else {
                None
            }
        };
        if let Some((kind, status, reason)) = event {
            self.push_event(TimelineEvent {
                at: Utc::now(),
                slot,
                host,
                generation,
                kind,
                status,
                reason,
                latency_ms,
            });
        }
    }

    pub fn record_reconnect(&self, slot: usize, host: String, generation: u64, trigger: &str) {
        {
            let mut slots = self.lock_slots();
            if let Some(metrics) = slots.get_mut(&slot) {
                if metrics.generation == generation {
                    metrics.reconnects += 1;
                }
            }
        }
        self.push_event(TimelineEvent {
            at: Utc::now(),
            slot,
            host,
            generation,
            kind: "reconnect_started".into(),
            status: "starting".into(),
            reason: trigger.into(),
            latency_ms: None,
        });
    }

    pub fn record_failure(
        &self,
        slot: usize,
        host: String,
        generation: u64,
        kind: &str,
        reason: &str,
    ) {
        {
            let mut slots = self.lock_slots();
            if let Some(metrics) = slots.get_mut(&slot) {
                if metrics.generation == generation {
                    metrics.failures += 1;
                }
            }
        }
        self.push_event(TimelineEvent {
            at: Utc::now(),
            slot,
            host,
            generation,
            kind: kind.into(),
            status: "failed".into(),
            reason: reason.into(),
            latency_ms: None,
        });
    }

    pub fn record_event(
        &self,
        slot: usize,
        host: String,
        generation: u64,
        kind: &str,
        status: &str,
        reason: &str,
    ) {
        self.push_event(TimelineEvent {
            at: Utc::now(),
            slot,
            host,
            generation,
            kind: kind.into(),
            status: status.into(),
            reason: reason.into(),
            latency_ms: None,
        });
    }

    fn push_event(&self, event: TimelineEvent) {
        let mut timeline = self.lock_timeline();
        timeline.push_front(event);
        timeline.truncate(TIMELINE_LIMIT);
    }

    pub fn snapshots(&self) -> Vec<ExitMetricsSnapshot> {
        let mut slots = self.lock_slots();
        let mut out: Vec<_> = slots.values_mut().map(ExitMetrics::snapshot).collect();
        out.sort_by_key(|item| item.slot);
        out
    }

    pub fn timeline(&self, slot: Option<usize>, limit: usize) -> Vec<TimelineEvent> {
        let limit = limit.clamp(1, TIMELINE_LIMIT);
        self.lock_timeline()
            .iter()
            .filter(|event| slot.is_none_or(|wanted| event.slot == wanted))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn render_prometheus(&self) -> String {
        let snapshots = self.snapshots();
        let mut out = String::with_capacity(4096);
        out.push_str("# HELP fanout_exit_info Static exit identity and current state.\n");
        out.push_str("# TYPE fanout_exit_info gauge\n");
        for item in &snapshots {
            out.push_str(&format!(
                "fanout_exit_info{{slot=\"{}\",host=\"{}\",generation=\"{}\"}} 1\n",
                item.slot,
                prom_escape(&item.host),
                item.generation
            ));
        }
        out.push_str("# HELP fanout_exit_probe_total Total exit-IP probes.\n");
        out.push_str("# TYPE fanout_exit_probe_total counter\n");
        for item in &snapshots {
            out.push_str(&format!(
                "fanout_exit_probe_total{{slot=\"{}\"}} {}\n",
                item.slot, item.probe_total
            ));
            out.push_str(&format!(
                "fanout_exit_probe_failures_total{{slot=\"{}\"}} {}\n",
                item.slot, item.probe_failures
            ));
        }
        out.push_str(
            "# HELP fanout_exit_probe_loss_ratio Recent application-level probe loss ratio.\n",
        );
        out.push_str("# TYPE fanout_exit_probe_loss_ratio gauge\n");
        for item in &snapshots {
            out.push_str(&format!(
                "fanout_exit_probe_loss_ratio{{slot=\"{}\"}} {:.6}\n",
                item.slot, item.loss_ratio
            ));
            if let Some(latency) = item.latency_ms {
                out.push_str(&format!(
                    "fanout_exit_probe_latency_seconds{{slot=\"{}\"}} {:.6}\n",
                    item.slot,
                    latency / 1000.0
                ));
            }
            out.push_str(&format!(
                "fanout_exit_probe_jitter_seconds{{slot=\"{}\"}} {:.6}\n",
                item.slot,
                item.jitter_ms / 1000.0
            ));
        }
        out.push_str("# HELP fanout_exit_traffic_bytes_total SOCKS relay payload bytes.\n");
        out.push_str("# TYPE fanout_exit_traffic_bytes_total counter\n");
        for item in &snapshots {
            out.push_str(&format!(
                "fanout_exit_traffic_bytes_total{{slot=\"{}\",direction=\"up\"}} {}\n",
                item.slot, item.traffic_up_bytes
            ));
            out.push_str(&format!(
                "fanout_exit_traffic_bytes_total{{slot=\"{}\",direction=\"down\"}} {}\n",
                item.slot, item.traffic_down_bytes
            ));
            out.push_str(&format!(
                "fanout_exit_traffic_bps{{slot=\"{}\",direction=\"up\"}} {:.2}\n",
                item.slot, item.up_bps
            ));
            out.push_str(&format!(
                "fanout_exit_traffic_bps{{slot=\"{}\",direction=\"down\"}} {:.2}\n",
                item.slot, item.down_bps
            ));
        }
        out.push_str("# HELP fanout_exit_reconnects_total Automatic reconnect attempts.\n");
        out.push_str("# TYPE fanout_exit_reconnects_total counter\n");
        for item in &snapshots {
            out.push_str(&format!(
                "fanout_exit_reconnects_total{{slot=\"{}\"}} {}\n",
                item.slot, item.reconnects
            ));
            out.push_str(&format!(
                "fanout_exit_failures_total{{slot=\"{}\"}} {}\n",
                item.slot, item.failures
            ));
        }
        out
    }
}

fn prom_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_update_ewma_loss_and_recovery_timeline() {
        let store = ObservabilityStore::default();
        let traffic = Arc::new(TrafficCounters::default());
        store.reset_slot(1, "node-1".into(), 7, traffic);
        store.record_probe(1, "node-1".into(), 7, true, Some(100.0), "");
        store.record_probe(1, "node-1".into(), 7, true, Some(140.0), "");
        store.record_probe(1, "node-1".into(), 7, false, None, "timeout");
        let snapshot = store.snapshots().remove(0);
        assert_eq!(snapshot.probe_total, 3);
        assert_eq!(snapshot.probe_failures, 1);
        assert!((snapshot.loss_ratio - 1.0 / 3.0).abs() < 0.001);
        assert!((snapshot.jitter_ms - 12.0).abs() < 0.001);
        assert_eq!(store.timeline(Some(1), 10).len(), 1);
        store.record_probe(1, "node-1".into(), 7, true, Some(120.0), "");
        assert_eq!(store.timeline(Some(1), 10)[0].kind, "probe_recovered");
    }

    #[test]
    fn stale_generation_cannot_mutate_metrics() {
        let store = ObservabilityStore::default();
        store.reset_slot(1, "old".into(), 1, Arc::new(TrafficCounters::default()));
        store.record_probe(1, "new".into(), 2, false, None, "stale");
        assert_eq!(store.snapshots()[0].probe_total, 0);
        assert_eq!(store.snapshots()[0].host, "old");
    }

    #[test]
    fn traffic_snapshot_reports_rates_and_cumulative_bytes() {
        let store = ObservabilityStore::default();
        let traffic = Arc::new(TrafficCounters::default());
        traffic.add_up(1_000_000);
        traffic.add_down(2_000_000);
        traffic.enter();
        store.reset_slot(1, "node-1".into(), 1, traffic.clone());

        let first = store.snapshots().remove(0);
        assert_eq!(first.traffic_up_bytes, 1_000_000);
        assert_eq!(first.traffic_down_bytes, 2_000_000);
        assert_eq!(first.active_connections, 1);
        assert_eq!(first.up_bps, 0.0);
        assert_eq!(first.down_bps, 0.0);

        std::thread::sleep(std::time::Duration::from_millis(550));
        traffic.add_up(1_000_000);
        traffic.add_down(2_000_000);
        traffic.leave();
        let second = store.snapshots().remove(0);
        assert_eq!(second.traffic_up_bytes, 2_000_000);
        assert_eq!(second.traffic_down_bytes, 4_000_000);
        assert_eq!(second.active_connections, 0);
        assert!(second.up_bps > 0.0);
        assert!(second.down_bps > 0.0);
    }

    #[test]
    fn prometheus_escapes_labels_and_emits_counters() {
        let store = ObservabilityStore::default();
        store.reset_slot(
            1,
            "node\"\\\n".into(),
            1,
            Arc::new(TrafficCounters::default()),
        );
        let text = store.render_prometheus();
        assert!(text.contains("fanout_exit_probe_total{slot=\"1\"} 0"));
        assert!(text.contains("node\\\"\\\\\\n"));
        assert!(!text.contains("token="));
    }
}
