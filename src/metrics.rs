//! Process-wide counters, rolling time series, per-message activity log and
//! Prometheus exposition.
//!
//! All state is lock-free counters plus two small mutex-guarded ring buffers.
//! The critical sections never span an `.await`, so a `std::sync::Mutex` is the
//! right primitive here.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Minutes of history retained for the dashboard charts.
const SERIES_MINUTES: usize = 120;
/// Messages retained in the activity log.
const ACTIVITY_CAPACITY: usize = 1_000;

/// Upper bounds (milliseconds) for the delivery latency histogram.
const LATENCY_BUCKETS_MS: [u64; 9] = [50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000];

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Counters {
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub connections_rejected: AtomicU64,
    pub sessions_timed_out: AtomicU64,

    pub messages_received: AtomicU64,
    pub messages_delivered: AtomicU64,
    pub messages_failed: AtomicU64,
    pub messages_deferred: AtomicU64,
    pub messages_dead: AtomicU64,
    pub messages_rejected: AtomicU64,

    pub recipients_total: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_delivered: AtomicU64,

    pub auth_success: AtomicU64,
    pub auth_failure: AtomicU64,

    pub queue_enqueued: AtomicU64,
    pub queue_retries: AtomicU64,

    pub routing_no_relay_available: AtomicU64,
    pub rewrite_errors: AtomicU64,
}

macro_rules! counter_snapshot {
    ($self:ident, $($field:ident),+ $(,)?) => {
        CountersSnapshot { $($field: $self.$field.load(Ordering::Relaxed)),+ }
    };
}

impl Counters {
    pub fn snapshot(&self) -> CountersSnapshot {
        counter_snapshot!(
            self,
            connections_total,
            connections_active,
            connections_rejected,
            sessions_timed_out,
            messages_received,
            messages_delivered,
            messages_failed,
            messages_deferred,
            messages_dead,
            messages_rejected,
            recipients_total,
            bytes_received,
            bytes_delivered,
            auth_success,
            auth_failure,
            queue_enqueued,
            queue_retries,
            routing_no_relay_available,
            rewrite_errors,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountersSnapshot {
    pub connections_total: u64,
    pub connections_active: u64,
    pub connections_rejected: u64,
    pub sessions_timed_out: u64,
    pub messages_received: u64,
    pub messages_delivered: u64,
    pub messages_failed: u64,
    pub messages_deferred: u64,
    pub messages_dead: u64,
    pub messages_rejected: u64,
    pub recipients_total: u64,
    pub bytes_received: u64,
    pub bytes_delivered: u64,
    pub auth_success: u64,
    pub auth_failure: u64,
    pub queue_enqueued: u64,
    pub queue_retries: u64,
    pub routing_no_relay_available: u64,
    pub rewrite_errors: u64,
}

// ---------------------------------------------------------------------------
// Rolling per-minute series
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Bucket {
    /// Unix timestamp of the start of this minute.
    pub minute: i64,
    pub received: u64,
    pub delivered: u64,
    pub failed: u64,
    pub deferred: u64,
}

impl Bucket {
    fn empty(minute: i64) -> Self {
        Self {
            minute,
            received: 0,
            delivered: 0,
            failed: 0,
            deferred: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sample {
    Received,
    Delivered,
    Failed,
    Deferred,
}

#[derive(Debug, Default)]
pub struct TimeSeries {
    buckets: Mutex<VecDeque<Bucket>>,
}

impl TimeSeries {
    fn current_minute() -> i64 {
        Utc::now().timestamp() / 60 * 60
    }

    pub fn record(&self, sample: Sample) {
        let minute = Self::current_minute();
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let needs_new = buckets.back().map(|b| b.minute != minute).unwrap_or(true);
        if needs_new {
            buckets.push_back(Bucket::empty(minute));
            while buckets.len() > SERIES_MINUTES {
                buckets.pop_front();
            }
        }

        if let Some(bucket) = buckets.back_mut() {
            match sample {
                Sample::Received => bucket.received += 1,
                Sample::Delivered => bucket.delivered += 1,
                Sample::Failed => bucket.failed += 1,
                Sample::Deferred => bucket.deferred += 1,
            }
        }
    }

    /// Last `minutes` buckets with gaps zero-filled, oldest first, so the
    /// dashboard can plot it directly.
    pub fn snapshot(&self, minutes: usize) -> Vec<Bucket> {
        let buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let window = minutes.clamp(1, SERIES_MINUTES);
        let now = Self::current_minute();
        let start = now - ((window as i64 - 1) * 60);

        let mut out = Vec::with_capacity(window);
        let mut cursor = buckets.iter().peekable();
        let mut minute = start;
        while minute <= now {
            while let Some(bucket) = cursor.peek() {
                if bucket.minute < minute {
                    cursor.next();
                } else {
                    break;
                }
            }
            match cursor.peek() {
                Some(bucket) if bucket.minute == minute => {
                    out.push(**bucket);
                    cursor.next();
                }
                _ => out.push(Bucket::empty(minute)),
            }
            minute += 60;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Latency histogram
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct LatencyHistogram {
    buckets: [AtomicU64; LATENCY_BUCKETS_MS.len()],
    overflow: AtomicU64,
    sum_ms: AtomicU64,
    count: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            buckets: Default::default(),
            overflow: AtomicU64::new(0),
            sum_ms: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl LatencyHistogram {
    pub fn observe(&self, millis: u64) {
        self.sum_ms.fetch_add(millis, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        for (index, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            if millis <= *bound {
                self.buckets[index].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.overflow.fetch_add(1, Ordering::Relaxed);
    }

    pub fn average_ms(&self) -> f64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        self.sum_ms.load(Ordering::Relaxed) as f64 / count as f64
    }

    /// Cumulative counts suitable for Prometheus `_bucket` series.
    fn cumulative(&self) -> (Vec<(String, u64)>, u64, u64) {
        let mut running = 0u64;
        let mut out = Vec::with_capacity(LATENCY_BUCKETS_MS.len() + 1);
        for (index, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            running += self.buckets[index].load(Ordering::Relaxed);
            out.push((format!("{:.3}", *bound as f64 / 1000.0), running));
        }
        running += self.overflow.load(Ordering::Relaxed);
        out.push(("+Inf".to_string(), running));
        (
            out,
            self.sum_ms.load(Ordering::Relaxed),
            self.count.load(Ordering::Relaxed),
        )
    }
}

// ---------------------------------------------------------------------------
// Activity log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStatus {
    /// Accepted from the client, not yet handed upstream.
    Accepted,
    /// Waiting in the retry queue.
    Queued,
    /// Being delivered right now.
    Sending,
    /// Accepted by the upstream relay.
    Delivered,
    /// Transient failure; will be retried.
    Deferred,
    /// Permanently failed or out of attempts.
    Failed,
    /// Refused during the inbound session.
    Rejected,
}

/// One row in the dashboard's message list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRecord {
    pub id: String,
    pub received_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: MessageStatus,
    /// Original `From` mailbox as submitted.
    pub original_from: String,
    /// `From` header actually handed to the upstream relay.
    #[serde(default)]
    pub from_header: String,
    /// Envelope sender used upstream.
    pub envelope_from: String,
    pub reply_to: Option<String>,
    pub recipients: Vec<String>,
    pub subject: Option<String>,
    pub size_bytes: u64,
    pub relay_id: Option<String>,
    pub attempts: u32,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
    pub client_ip: Option<String>,
    /// Transformations applied by the rewriter.
    pub notes: Vec<String>,
}

impl MessageRecord {
    pub fn new(id: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            received_at: now,
            updated_at: now,
            status: MessageStatus::Accepted,
            original_from: String::new(),
            from_header: String::new(),
            envelope_from: String::new(),
            reply_to: None,
            recipients: Vec::new(),
            subject: None,
            size_bytes: 0,
            relay_id: None,
            attempts: 0,
            latency_ms: None,
            error: None,
            client_ip: None,
            notes: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct ActivityLog {
    entries: Mutex<VecDeque<MessageRecord>>,
}

impl ActivityLog {
    /// Inserts a new record, evicting the oldest when at capacity.
    pub fn push(&self, record: MessageRecord) {
        let mut entries = self.lock();
        if entries.len() >= ACTIVITY_CAPACITY {
            entries.pop_front();
        }
        entries.push_back(record);
    }

    /// Applies `update` to the record with `id`, if it is still retained.
    pub fn update<F: FnOnce(&mut MessageRecord)>(&self, id: &str, update: F) {
        let mut entries = self.lock();
        if let Some(record) = entries.iter_mut().rev().find(|r| r.id == id) {
            update(record);
            record.updated_at = Utc::now();
        }
    }

    pub fn get(&self, id: &str) -> Option<MessageRecord> {
        let entries = self.lock();
        entries.iter().rev().find(|r| r.id == id).cloned()
    }

    /// Most recent records first, optionally filtered by status or relay.
    pub fn recent(
        &self,
        limit: usize,
        status: Option<MessageStatus>,
        relay_id: Option<&str>,
    ) -> Vec<MessageRecord> {
        let entries = self.lock();
        entries
            .iter()
            .rev()
            .filter(|record| status.map(|want| record.status == want).unwrap_or(true))
            .filter(|record| {
                relay_id
                    .map(|want| record.relay_id.as_deref() == Some(want))
                    .unwrap_or(true)
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn clear(&self) -> usize {
        let mut entries = self.lock();
        let count = entries.len();
        entries.clear();
        count
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<MessageRecord>> {
        match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Metrics {
    pub counters: Counters,
    pub series: TimeSeries,
    pub latency: LatencyHistogram,
    pub activity: ActivityLog,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, counter: &AtomicU64, value: u64) {
        counter.fetch_add(value, Ordering::Relaxed);
    }

    pub fn connection_opened(&self) {
        self.counters.connections_total.fetch_add(1, Ordering::Relaxed);
        self.counters.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed(&self) {
        // Saturating decrement: never wrap if open/close ever get unbalanced.
        let _ = self
            .counters
            .connections_active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            });
    }

    /// Prometheus text exposition for `GET /metrics`.
    pub fn render_prometheus(&self, uptime_seconds: u64, relays: &[RelayMetricsRow]) -> String {
        let counters = self.counters.snapshot();
        let mut out = String::with_capacity(4096);

        let mut counter = |name: &str, help: &str, value: u64| {
            out.push_str(&format!("# HELP smtp_relay_{name} {help}\n"));
            out.push_str(&format!("# TYPE smtp_relay_{name} counter\n"));
            out.push_str(&format!("smtp_relay_{name} {value}\n"));
        };

        counter(
            "connections_total",
            "Inbound SMTP connections accepted.",
            counters.connections_total,
        );
        counter(
            "connections_rejected_total",
            "Inbound connections refused by the allow-list or connection limit.",
            counters.connections_rejected,
        );
        counter(
            "messages_received_total",
            "Messages accepted from submitting clients.",
            counters.messages_received,
        );
        counter(
            "messages_delivered_total",
            "Messages accepted by an upstream relay.",
            counters.messages_delivered,
        );
        counter(
            "messages_failed_total",
            "Messages permanently failed.",
            counters.messages_failed,
        );
        counter(
            "messages_deferred_total",
            "Delivery attempts deferred for retry.",
            counters.messages_deferred,
        );
        counter(
            "messages_rejected_total",
            "Messages refused during the inbound session.",
            counters.messages_rejected,
        );
        counter(
            "recipients_total",
            "Envelope recipients accepted.",
            counters.recipients_total,
        );
        counter(
            "bytes_received_total",
            "Bytes of message data accepted.",
            counters.bytes_received,
        );
        counter(
            "bytes_delivered_total",
            "Bytes of message data handed upstream.",
            counters.bytes_delivered,
        );
        counter(
            "auth_failure_total",
            "Failed inbound AUTH attempts.",
            counters.auth_failure,
        );
        counter(
            "queue_retries_total",
            "Retry attempts started from the queue.",
            counters.queue_retries,
        );
        counter(
            "routing_no_relay_total",
            "Routing decisions that found no eligible relay.",
            counters.routing_no_relay_available,
        );

        out.push_str("# HELP smtp_relay_connections_active Currently open inbound connections.\n");
        out.push_str("# TYPE smtp_relay_connections_active gauge\n");
        out.push_str(&format!(
            "smtp_relay_connections_active {}\n",
            counters.connections_active
        ));

        out.push_str("# HELP smtp_relay_uptime_seconds Daemon uptime.\n");
        out.push_str("# TYPE smtp_relay_uptime_seconds gauge\n");
        out.push_str(&format!("smtp_relay_uptime_seconds {uptime_seconds}\n"));

        let (buckets, sum_ms, count) = self.latency.cumulative();
        out.push_str(
            "# HELP smtp_relay_delivery_duration_seconds Upstream delivery latency.\n",
        );
        out.push_str("# TYPE smtp_relay_delivery_duration_seconds histogram\n");
        for (bound, value) in buckets {
            out.push_str(&format!(
                "smtp_relay_delivery_duration_seconds_bucket{{le=\"{bound}\"}} {value}\n"
            ));
        }
        out.push_str(&format!(
            "smtp_relay_delivery_duration_seconds_sum {}\n",
            sum_ms as f64 / 1000.0
        ));
        out.push_str(&format!(
            "smtp_relay_delivery_duration_seconds_count {count}\n"
        ));

        out.push_str("# HELP smtp_relay_relay_up Relay eligibility (1 = in rotation).\n");
        out.push_str("# TYPE smtp_relay_relay_up gauge\n");
        for relay in relays {
            out.push_str(&format!(
                "smtp_relay_relay_up{{relay=\"{}\"}} {}\n",
                escape_label(&relay.id),
                u8::from(relay.available)
            ));
        }

        out.push_str("# HELP smtp_relay_relay_sent_total Messages delivered per relay.\n");
        out.push_str("# TYPE smtp_relay_relay_sent_total counter\n");
        for relay in relays {
            out.push_str(&format!(
                "smtp_relay_relay_sent_total{{relay=\"{}\"}} {}\n",
                escape_label(&relay.id),
                relay.sent
            ));
        }

        out.push_str("# HELP smtp_relay_relay_failed_total Failed deliveries per relay.\n");
        out.push_str("# TYPE smtp_relay_relay_failed_total counter\n");
        for relay in relays {
            out.push_str(&format!(
                "smtp_relay_relay_failed_total{{relay=\"{}\"}} {}\n",
                escape_label(&relay.id),
                relay.failed
            ));
        }

        out.push_str("# HELP smtp_relay_relay_inflight Deliveries in progress per relay.\n");
        out.push_str("# TYPE smtp_relay_relay_inflight gauge\n");
        for relay in relays {
            out.push_str(&format!(
                "smtp_relay_relay_inflight{{relay=\"{}\"}} {}\n",
                escape_label(&relay.id),
                relay.in_flight
            ));
        }

        out
    }
}

/// Minimal per-relay view needed by the Prometheus renderer, so `metrics` does
/// not have to depend on the relay pool.
#[derive(Debug, Clone)]
pub struct RelayMetricsRow {
    pub id: String,
    pub available: bool,
    pub sent: u64,
    pub failed: u64,
    pub in_flight: u64,
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_snapshot_reflects_increments() {
        let metrics = Metrics::new();
        metrics.connection_opened();
        metrics.connection_opened();
        metrics.connection_closed();
        metrics.inc(&metrics.counters.messages_received);
        metrics.add(&metrics.counters.bytes_received, 4096);

        let snapshot = metrics.counters.snapshot();
        assert_eq!(snapshot.connections_total, 2);
        assert_eq!(snapshot.connections_active, 1);
        assert_eq!(snapshot.messages_received, 1);
        assert_eq!(snapshot.bytes_received, 4096);
    }

    #[test]
    fn active_connections_never_underflow() {
        let metrics = Metrics::new();
        metrics.connection_closed();
        assert_eq!(metrics.counters.snapshot().connections_active, 0);
    }

    #[test]
    fn series_zero_fills_and_windows() {
        let series = TimeSeries::default();
        series.record(Sample::Received);
        series.record(Sample::Delivered);
        series.record(Sample::Delivered);

        let snapshot = series.snapshot(5);
        assert_eq!(snapshot.len(), 5);
        let last = snapshot.last().unwrap();
        assert_eq!(last.received, 1);
        assert_eq!(last.delivered, 2);
        // Older buckets are zero-filled, not missing.
        assert_eq!(snapshot[0].delivered, 0);
        assert!(snapshot[0].minute < last.minute);
    }

    #[test]
    fn latency_histogram_tracks_average_and_buckets() {
        let histogram = LatencyHistogram::default();
        histogram.observe(40);
        histogram.observe(60);
        histogram.observe(120_000);
        assert!((histogram.average_ms() - 40_033.33).abs() < 1.0);

        let (buckets, _, count) = histogram.cumulative();
        assert_eq!(count, 3);
        assert_eq!(buckets[0].1, 1, "one sample under 50ms");
        assert_eq!(buckets.last().unwrap().1, 3, "+Inf holds every sample");
    }

    #[test]
    fn activity_log_updates_and_filters() {
        let log = ActivityLog::default();
        let mut first = MessageRecord::new("a".to_string());
        first.relay_id = Some("relay_1".to_string());
        log.push(first);
        log.push(MessageRecord::new("b".to_string()));

        log.update("a", |record| {
            record.status = MessageStatus::Delivered;
            record.attempts = 1;
        });

        let delivered = log.recent(10, Some(MessageStatus::Delivered), None);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].id, "a");
        assert_eq!(delivered[0].attempts, 1);

        assert_eq!(log.recent(10, None, Some("relay_1")).len(), 1);
        assert_eq!(log.recent(10, None, None).len(), 2);
        // Newest first.
        assert_eq!(log.recent(1, None, None)[0].id, "b");
    }

    #[test]
    fn activity_log_evicts_oldest_at_capacity() {
        let log = ActivityLog::default();
        for index in 0..ACTIVITY_CAPACITY + 10 {
            log.push(MessageRecord::new(index.to_string()));
        }
        let all = log.recent(ACTIVITY_CAPACITY * 2, None, None);
        assert_eq!(all.len(), ACTIVITY_CAPACITY);
        assert!(log.get("0").is_none());
        assert!(log.get(&(ACTIVITY_CAPACITY + 9).to_string()).is_some());
    }

    #[test]
    fn prometheus_output_is_well_formed() {
        let metrics = Metrics::new();
        metrics.inc(&metrics.counters.messages_delivered);
        metrics.latency.observe(120);

        let rows = vec![RelayMetricsRow {
            id: "relay_node_1".to_string(),
            available: true,
            sent: 3,
            failed: 1,
            in_flight: 0,
        }];
        let text = metrics.render_prometheus(42, &rows);

        assert!(text.contains("smtp_relay_messages_delivered_total 1"));
        assert!(text.contains("smtp_relay_uptime_seconds 42"));
        assert!(text.contains("smtp_relay_relay_up{relay=\"relay_node_1\"} 1"));
        assert!(text.contains("smtp_relay_relay_sent_total{relay=\"relay_node_1\"} 3"));
        assert!(text.contains("smtp_relay_delivery_duration_seconds_bucket{le=\"0.250\"} 1"));
        // Every HELP line must be followed by a TYPE line.
        let helps = text.matches("# HELP ").count();
        let types = text.matches("# TYPE ").count();
        assert_eq!(helps, types);
    }
}
