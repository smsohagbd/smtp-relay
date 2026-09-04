//! Live event bus backing the dashboard's server-sent-events stream.
//!
//! Publishing is non-blocking and lossy by design: if no dashboard is
//! connected, or a slow client falls behind, events are dropped rather than
//! applying back-pressure to mail delivery.

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::broadcast;

/// Events buffered per subscriber before the slowest ones start losing data.
const CHANNEL_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A message finished a delivery attempt (delivered/deferred/failed).
    Message,
    /// A relay changed state: activated, deactivated, circuit tripped, healthy.
    Relay,
    /// Queue depth or a queued item changed.
    Queue,
    /// Configuration was reloaded or rewritten.
    Config,
    /// Periodic counters push, so idle dashboards still tick along.
    Stats,
    /// Operational notice worth surfacing in the UI.
    Notice,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Message => "message",
            EventKind::Relay => "relay",
            EventKind::Queue => "queue",
            EventKind::Config => "config",
            EventKind::Stats => "stats",
            EventKind::Notice => "notice",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub seq: u64,
    pub at: DateTime<Utc>,
    pub kind: EventKind,
    pub data: Value,
}

/// Fan-out channel for dashboard events.
#[derive(Debug)]
pub struct EventBus {
    sender: broadcast::Sender<Event>,
    sequence: AtomicU64,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            sender,
            sequence: AtomicU64::new(0),
        }
    }

    /// Publishes an event. Returns the number of live subscribers, which is
    /// zero when nobody is watching.
    pub fn publish(&self, kind: EventKind, data: Value) -> usize {
        let event = Event {
            seq: self.sequence.fetch_add(1, Ordering::Relaxed),
            at: Utc::now(),
            kind,
            data,
        };
        self.sender.send(event).unwrap_or(0)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn subscribers_receive_published_events_in_order() {
        let bus = EventBus::new();
        let mut receiver = bus.subscribe();

        bus.publish(EventKind::Notice, json!({"text": "first"}));
        bus.publish(EventKind::Relay, json!({"id": "relay_1"}));

        let first = receiver.recv().await.unwrap();
        let second = receiver.recv().await.unwrap();

        assert_eq!(first.kind, EventKind::Notice);
        assert_eq!(first.data["text"], "first");
        assert_eq!(second.kind, EventKind::Relay);
        assert_eq!(second.seq, first.seq + 1);
    }

    #[tokio::test]
    async fn publishing_without_subscribers_is_harmless() {
        let bus = EventBus::new();
        assert_eq!(bus.subscriber_count(), 0);
        assert_eq!(bus.publish(EventKind::Stats, json!({})), 0);
    }

    #[tokio::test]
    async fn events_serialise_for_sse() {
        let bus = EventBus::new();
        let mut receiver = bus.subscribe();
        bus.publish(EventKind::Message, json!({"id": "q1", "status": "delivered"}));

        let event = receiver.recv().await.unwrap();
        let text = serde_json::to_string(&event).unwrap();
        assert!(text.contains("\"kind\":\"message\""));
        assert!(text.contains("\"status\":\"delivered\""));
    }
}
