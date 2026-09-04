//! Delivery queue with exponential backoff and optional on-disk spooling.
//!
//! Messages are stored **pre-rewrite**. Each attempt re-runs the header
//! rewrite for whichever relay it lands on, so a retry that moves to a
//! different relay still gets a correctly aligned `From` and envelope sender.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::config::QueueConfig;

/// A message awaiting delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    pub id: String,
    /// Envelope sender supplied by the submitting client.
    pub sender: String,
    /// Envelope recipients from `RCPT TO`.
    pub recipients: Vec<String>,
    /// `From` address of the submitting application, kept for sticky routing
    /// and for the activity log.
    pub original_from: String,
    pub subject: Option<String>,
    pub client_ip: Option<IpAddr>,
    pub helo: String,
    pub received_at: DateTime<Utc>,
    pub attempts: u32,
    pub next_attempt_at: DateTime<Utc>,
    /// Relays already tried, so retries prefer somewhere new.
    pub tried_relays: Vec<String>,
    pub last_error: Option<String>,
    /// The original RFC 5322 message. Spooled alongside the metadata rather
    /// than inside it, so the on-disk copy stays a readable `.eml`.
    #[serde(skip)]
    pub raw: Vec<u8>,
}

impl QueuedMessage {
    pub fn size_bytes(&self) -> u64 {
        self.raw.len() as u64
    }
}

/// Serialisable summary for the admin API.
#[derive(Debug, Clone, Serialize)]
pub struct QueueEntrySummary {
    pub id: String,
    pub sender: String,
    pub original_from: String,
    pub recipients: Vec<String>,
    pub subject: Option<String>,
    pub attempts: u32,
    pub received_at: DateTime<Utc>,
    pub next_attempt_at: DateTime<Utc>,
    pub seconds_until_retry: i64,
    pub tried_relays: Vec<String>,
    pub last_error: Option<String>,
    pub size_bytes: u64,
}

impl From<&QueuedMessage> for QueueEntrySummary {
    fn from(message: &QueuedMessage) -> Self {
        let now = Utc::now();
        Self {
            id: message.id.clone(),
            sender: message.sender.clone(),
            original_from: message.original_from.clone(),
            recipients: message.recipients.clone(),
            subject: message.subject.clone(),
            attempts: message.attempts,
            received_at: message.received_at,
            next_attempt_at: message.next_attempt_at,
            seconds_until_retry: (message.next_attempt_at - now).num_seconds().max(0),
            tried_relays: message.tried_relays.clone(),
            last_error: message.last_error.clone(),
            size_bytes: message.size_bytes(),
        }
    }
}

/// Why an enqueue was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueError {
    Disabled,
    Full { capacity: usize },
}

impl std::fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnqueueError::Disabled => f.write_str("the delivery queue is disabled"),
            EnqueueError::Full { capacity } => {
                write!(f, "the delivery queue is full ({capacity} messages)")
            }
        }
    }
}

/// Scheduling key: due time first, then insertion order for stability.
type ScheduleKey = (i64, u64);

#[derive(Default)]
struct Inner {
    /// Ordered by due time, so the earliest work is always the first entry.
    scheduled: BTreeMap<ScheduleKey, QueuedMessage>,
    by_id: HashMap<String, ScheduleKey>,
    /// Ids currently being delivered by a worker.
    in_flight: HashMap<String, DateTime<Utc>>,
}

/// A time-ordered delivery queue shared by all workers.
pub struct Queue {
    inner: Mutex<Inner>,
    /// Woken whenever new work is enqueued or the schedule is advanced.
    wake: Notify,
    sequence: AtomicU64,
    enabled: bool,
    capacity: usize,
    persist: bool,
    directory: PathBuf,
}

impl Queue {
    pub fn new(config: &QueueConfig) -> Self {
        let persist = config.enabled && config.persist;
        if persist {
            if let Err(error) = std::fs::create_dir_all(&config.directory) {
                tracing::warn!(
                    directory = %config.directory.display(),
                    %error,
                    "could not create the spool directory; continuing without on-disk persistence"
                );
            }
        }

        Self {
            inner: Mutex::new(Inner::default()),
            wake: Notify::new(),
            sequence: AtomicU64::new(0),
            enabled: config.enabled,
            capacity: config.capacity.max(1),
            persist: persist && config.directory.exists(),
            directory: config.directory.clone(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn is_persistent(&self) -> bool {
        self.persist
    }

    pub fn depth(&self) -> usize {
        self.lock().scheduled.len()
    }

    pub fn in_flight(&self) -> usize {
        self.lock().in_flight.len()
    }

    /// Number of messages whose retry time has already passed.
    pub fn due_count(&self) -> usize {
        let now = Utc::now().timestamp_millis();
        self.lock()
            .scheduled
            .keys()
            .take_while(|(due, _)| *due <= now)
            .count()
    }

    /// Adds a message to the queue and wakes one worker.
    pub fn enqueue(&self, message: QueuedMessage) -> Result<(), EnqueueError> {
        if !self.enabled {
            return Err(EnqueueError::Disabled);
        }

        {
            let mut inner = self.lock();
            if inner.scheduled.len() >= self.capacity {
                return Err(EnqueueError::Full {
                    capacity: self.capacity,
                });
            }
            let key = (
                message.next_attempt_at.timestamp_millis(),
                self.sequence.fetch_add(1, Ordering::Relaxed),
            );
            inner.by_id.insert(message.id.clone(), key);
            if self.persist {
                self.write_spool(&message);
            }
            inner.scheduled.insert(key, message);
        }

        self.wake.notify_one();
        Ok(())
    }

    /// Removes and returns the earliest message that is due, marking it
    /// in-flight so the dashboard can distinguish waiting from sending.
    pub fn take_due(&self) -> Option<QueuedMessage> {
        let now = Utc::now().timestamp_millis();
        let mut inner = self.lock();

        let key = match inner.scheduled.keys().next().copied() {
            Some(key) if key.0 <= now => key,
            _ => return None,
        };

        let message = inner.scheduled.remove(&key)?;
        inner.by_id.remove(&message.id);
        inner
            .in_flight
            .insert(message.id.clone(), Utc::now());
        Some(message)
    }

    /// Reports a finished attempt for a message taken with [`Queue::take_due`].
    pub fn finish(&self, id: &str) {
        let mut inner = self.lock();
        inner.in_flight.remove(id);
        drop(inner);
        if self.persist {
            self.remove_spool(id);
        }
    }

    /// Reschedules a message after a failed attempt.
    pub fn requeue(&self, mut message: QueuedMessage, delay: Duration) {
        message.next_attempt_at = Utc::now()
            + chrono::Duration::from_std(delay).unwrap_or_else(|_| chrono::Duration::seconds(60));

        {
            let mut inner = self.lock();
            inner.in_flight.remove(&message.id);
            let key = (
                message.next_attempt_at.timestamp_millis(),
                self.sequence.fetch_add(1, Ordering::Relaxed),
            );
            inner.by_id.insert(message.id.clone(), key);
            if self.persist {
                self.write_spool(&message);
            }
            inner.scheduled.insert(key, message);
        }

        self.wake.notify_one();
    }

    /// Drops a message from the queue entirely.
    pub fn remove(&self, id: &str) -> bool {
        let removed = {
            let mut inner = self.lock();
            match inner.by_id.remove(id) {
                Some(key) => inner.scheduled.remove(&key).is_some(),
                None => false,
            }
        };
        if removed && self.persist {
            self.remove_spool(id);
        }
        removed
    }

    /// Makes every queued message due immediately. Returns how many moved.
    pub fn flush_now(&self) -> usize {
        let moved = {
            let mut inner = self.lock();
            let now = Utc::now();
            let due = now.timestamp_millis();
            let pending: Vec<ScheduleKey> = inner
                .scheduled
                .keys()
                .filter(|(scheduled_for, _)| *scheduled_for > due)
                .copied()
                .collect();

            for key in &pending {
                if let Some(mut message) = inner.scheduled.remove(key) {
                    message.next_attempt_at = now;
                    let new_key = (due, self.sequence.fetch_add(1, Ordering::Relaxed));
                    inner.by_id.insert(message.id.clone(), new_key);
                    inner.scheduled.insert(new_key, message);
                }
            }
            pending.len()
        };

        if moved > 0 {
            // Wake every worker: there may be many newly-due messages.
            self.wake.notify_waiters();
            self.wake.notify_one();
        }
        moved
    }

    pub fn purge(&self) -> usize {
        let ids: Vec<String> = {
            let inner = self.lock();
            inner.by_id.keys().cloned().collect()
        };
        let mut removed = 0;
        for id in ids {
            if self.remove(&id) {
                removed += 1;
            }
        }
        removed
    }

    /// How long until the next message is due; `None` when the queue is empty.
    pub fn time_until_due(&self) -> Option<Duration> {
        let inner = self.lock();
        let (due, _) = inner.scheduled.keys().next().copied()?;
        let now = Utc::now().timestamp_millis();
        Some(Duration::from_millis((due - now).max(0) as u64))
    }

    /// Blocks until work may be available. Wakes on enqueue, on the next due
    /// time, or after `max_idle` so shutdown stays responsive.
    pub async fn wait_for_work(&self, max_idle: Duration) {
        let delay = self
            .time_until_due()
            .map(|until| until.min(max_idle))
            .unwrap_or(max_idle);

        if delay.is_zero() {
            return;
        }
        tokio::select! {
            _ = self.wake.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }
    }

    /// Snapshot of pending messages, earliest retry first.
    pub fn list(&self, limit: usize) -> Vec<QueueEntrySummary> {
        let inner = self.lock();
        inner
            .scheduled
            .values()
            .take(limit)
            .map(QueueEntrySummary::from)
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<QueuedMessage> {
        let inner = self.lock();
        let key = inner.by_id.get(id)?;
        inner.scheduled.get(key).cloned()
    }

    // -- persistence -------------------------------------------------------

    fn meta_path(&self, id: &str) -> PathBuf {
        self.directory.join(format!("{id}.json"))
    }

    fn body_path(&self, id: &str) -> PathBuf {
        self.directory.join(format!("{id}.eml"))
    }

    fn write_spool(&self, message: &QueuedMessage) {
        if let Err(error) = std::fs::write(self.body_path(&message.id), &message.raw) {
            tracing::warn!(id = %message.id, %error, "could not spool message body");
            return;
        }
        match serde_json::to_vec_pretty(message) {
            Ok(meta) => {
                if let Err(error) = std::fs::write(self.meta_path(&message.id), meta) {
                    tracing::warn!(id = %message.id, %error, "could not spool message metadata");
                }
            }
            Err(error) => {
                tracing::warn!(id = %message.id, %error, "could not serialise queue metadata");
            }
        }
    }

    fn remove_spool(&self, id: &str) {
        let _ = std::fs::remove_file(self.meta_path(id));
        let _ = std::fs::remove_file(self.body_path(id));
    }

    /// Reloads spooled messages after a restart. Returns how many were
    /// recovered; incomplete pairs are cleaned up rather than retried.
    pub fn recover(&self) -> usize {
        if !self.persist {
            return 0;
        }
        let entries = match std::fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(
                    directory = %self.directory.display(),
                    %error,
                    "could not read the spool directory"
                );
                return 0;
            }
        };

        let mut recovered = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match self.recover_one(&path) {
                Ok(Some(message)) => {
                    let id = message.id.clone();
                    // Re-insert without rewriting the spool files.
                    let mut inner = self.lock();
                    if inner.scheduled.len() >= self.capacity {
                        tracing::warn!(%id, "spool recovery stopped: queue is at capacity");
                        break;
                    }
                    let key = (
                        message.next_attempt_at.timestamp_millis(),
                        self.sequence.fetch_add(1, Ordering::Relaxed),
                    );
                    inner.by_id.insert(id, key);
                    inner.scheduled.insert(key, message);
                    recovered += 1;
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping unreadable spool entry");
                }
            }
        }

        if recovered > 0 {
            self.wake.notify_waiters();
            self.wake.notify_one();
        }
        recovered
    }

    fn recover_one(&self, meta_path: &Path) -> std::io::Result<Option<QueuedMessage>> {
        let meta = std::fs::read(meta_path)?;
        let mut message: QueuedMessage = serde_json::from_slice(&meta)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;

        let body_path = self.body_path(&message.id);
        match std::fs::read(&body_path) {
            Ok(raw) if !raw.is_empty() => {
                message.raw = raw;
                Ok(Some(message))
            }
            _ => {
                // Metadata without a body is unusable; clean both up.
                tracing::warn!(
                    id = %message.id,
                    "discarding spooled message with a missing or empty body"
                );
                let _ = std::fs::remove_file(meta_path);
                let _ = std::fs::remove_file(&body_path);
                Ok(None)
            }
        }
    }
}

impl std::fmt::Debug for Queue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Queue")
            .field("enabled", &self.enabled)
            .field("depth", &self.depth())
            .field("capacity", &self.capacity)
            .field("persistent", &self.persist)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: &str) -> QueuedMessage {
        QueuedMessage {
            id: id.to_string(),
            sender: "campaigns@acme.io".to_string(),
            recipients: vec!["lead@example.org".to_string()],
            original_from: "campaigns@acme.io".to_string(),
            subject: Some("Offer".to_string()),
            client_ip: Some("10.0.0.5".parse().unwrap()),
            helo: "mautic.local".to_string(),
            received_at: Utc::now(),
            attempts: 0,
            next_attempt_at: Utc::now(),
            tried_relays: Vec::new(),
            last_error: None,
            raw: b"From: a@b.io\r\n\r\nbody".to_vec(),
        }
    }

    fn memory_queue(capacity: usize) -> Queue {
        Queue::new(&QueueConfig {
            enabled: true,
            capacity,
            persist: false,
            ..Default::default()
        })
    }

    #[test]
    fn enqueue_and_take_round_trip() {
        let queue = memory_queue(10);
        queue.enqueue(message("a")).unwrap();
        assert_eq!(queue.depth(), 1);

        let taken = queue.take_due().expect("due immediately");
        assert_eq!(taken.id, "a");
        assert_eq!(queue.depth(), 0);
        assert_eq!(queue.in_flight(), 1);

        queue.finish("a");
        assert_eq!(queue.in_flight(), 0);
    }

    #[test]
    fn future_messages_are_not_taken_early() {
        let queue = memory_queue(10);
        let mut future = message("later");
        future.next_attempt_at = Utc::now() + chrono::Duration::seconds(60);
        queue.enqueue(future).unwrap();

        assert!(queue.take_due().is_none());
        assert_eq!(queue.depth(), 1);
        assert_eq!(queue.due_count(), 0);

        let until = queue.time_until_due().unwrap();
        assert!(until.as_secs() >= 58 && until.as_secs() <= 60);
    }

    #[test]
    fn earliest_due_message_is_taken_first() {
        let queue = memory_queue(10);
        let mut second = message("second");
        second.next_attempt_at = Utc::now() - chrono::Duration::seconds(1);
        let mut first = message("first");
        first.next_attempt_at = Utc::now() - chrono::Duration::seconds(10);

        queue.enqueue(second).unwrap();
        queue.enqueue(first).unwrap();

        assert_eq!(queue.take_due().unwrap().id, "first");
        assert_eq!(queue.take_due().unwrap().id, "second");
    }

    #[test]
    fn capacity_is_enforced() {
        let queue = memory_queue(2);
        queue.enqueue(message("a")).unwrap();
        queue.enqueue(message("b")).unwrap();
        assert_eq!(
            queue.enqueue(message("c")),
            Err(EnqueueError::Full { capacity: 2 })
        );
    }

    #[test]
    fn disabled_queue_refuses_work() {
        let queue = Queue::new(&QueueConfig {
            enabled: false,
            ..Default::default()
        });
        assert_eq!(queue.enqueue(message("a")), Err(EnqueueError::Disabled));
    }

    #[test]
    fn requeue_delays_and_flush_makes_due() {
        let queue = memory_queue(10);
        queue.enqueue(message("a")).unwrap();
        let mut taken = queue.take_due().unwrap();
        taken.attempts = 1;

        queue.requeue(taken, Duration::from_secs(300));
        assert_eq!(queue.depth(), 1);
        assert_eq!(queue.due_count(), 0);
        assert_eq!(queue.in_flight(), 0);

        assert_eq!(queue.flush_now(), 1);
        assert_eq!(queue.due_count(), 1);
        let taken = queue.take_due().unwrap();
        assert_eq!(taken.attempts, 1);
    }

    #[test]
    fn remove_and_purge_drop_messages() {
        let queue = memory_queue(10);
        queue.enqueue(message("a")).unwrap();
        queue.enqueue(message("b")).unwrap();

        assert!(queue.remove("a"));
        assert!(!queue.remove("a"));
        assert_eq!(queue.depth(), 1);
        assert_eq!(queue.purge(), 1);
        assert_eq!(queue.depth(), 0);
    }

    #[test]
    fn listing_reports_retry_timing() {
        let queue = memory_queue(10);
        let mut later = message("a");
        later.next_attempt_at = Utc::now() + chrono::Duration::seconds(120);
        later.attempts = 2;
        later.last_error = Some("421 too busy".to_string());
        later.tried_relays = vec!["relay_node_1".to_string()];
        queue.enqueue(later).unwrap();

        let listed = queue.list(10);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].attempts, 2);
        assert!(listed[0].seconds_until_retry > 100);
        assert_eq!(listed[0].tried_relays, vec!["relay_node_1".to_string()]);
        assert_eq!(listed[0].size_bytes, 20);
    }

    #[test]
    fn spooling_survives_a_restart() {
        let directory = std::env::temp_dir().join(format!(
            "smtp-relay-spool-test-{}",
            crate::util::new_queue_id()
        ));
        let config = QueueConfig {
            enabled: true,
            persist: true,
            directory: directory.clone(),
            ..Default::default()
        };

        {
            let queue = Queue::new(&config);
            assert!(queue.is_persistent());
            let mut pending = message("persisted");
            pending.attempts = 3;
            pending.next_attempt_at = Utc::now() + chrono::Duration::seconds(30);
            queue.enqueue(pending).unwrap();
        }

        // A fresh process reads the spool back.
        let queue = Queue::new(&config);
        assert_eq!(queue.recover(), 1);
        assert_eq!(queue.depth(), 1);

        let recovered = queue.get("persisted").unwrap();
        assert_eq!(recovered.attempts, 3);
        assert_eq!(recovered.raw, b"From: a@b.io\r\n\r\nbody".to_vec());
        assert_eq!(recovered.recipients, vec!["lead@example.org".to_string()]);

        // Finishing the message clears it from disk.
        queue.flush_now();
        let taken = queue.take_due().unwrap();
        queue.finish(&taken.id);
        let queue = Queue::new(&config);
        assert_eq!(queue.recover(), 0);

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn wait_for_work_returns_when_a_message_arrives() {
        use std::sync::Arc;
        let queue = Arc::new(memory_queue(10));

        let waiter = {
            let queue = Arc::clone(&queue);
            tokio::spawn(async move {
                queue.wait_for_work(Duration::from_secs(30)).await;
            })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;
        queue.enqueue(message("a")).unwrap();

        tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter should wake promptly")
            .unwrap();
    }

    #[tokio::test]
    async fn wait_for_work_caps_idle_time() {
        let queue = memory_queue(10);
        let started = std::time::Instant::now();
        queue.wait_for_work(Duration::from_millis(100)).await;
        assert!(started.elapsed() >= Duration::from_millis(90));
    }
}
