//! Submission and delivery orchestration.
//!
//! This is where a message accepted by the inbound listener becomes one or
//! more upstream delivery attempts: route, reserve, rewrite, send, classify,
//! and either retire or reschedule.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::config::SubmissionMode;
use crate::error::DeliveryError;
use crate::events::EventKind;
use crate::message::rewrite::{rewrite, RewriteContext};
use crate::message::{headers, parse_mailbox};
use crate::metrics::{MessageRecord, MessageStatus, Sample};
use crate::queue::{EnqueueError, QueuedMessage};
use crate::relay::selector::{self, RouteRequest};
use crate::state::AppState;

/// A message handed over by a completed inbound `DATA` command.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub id: String,
    /// Envelope sender from `MAIL FROM`.
    pub sender: String,
    pub recipients: Vec<String>,
    pub raw: Vec<u8>,
    pub client_ip: Option<IpAddr>,
    pub helo: String,
}

/// What the inbound session should tell the submitting client.
#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    /// Handed upstream during the session.
    Delivered { relay_id: String, response: String },
    /// Accepted and scheduled for background delivery.
    Queued,
    /// Refused. The session replies with this SMTP status.
    Rejected {
        code: u16,
        enhanced: &'static str,
        message: String,
    },
}

/// Result of one delivery round (which may try several relays).
#[derive(Debug, Clone)]
pub enum AttemptOutcome {
    Delivered {
        relay_id: String,
        response: String,
    },
    /// Worth retrying later.
    Deferred { error: String },
    /// Retrying will not help.
    Failed { error: String },
}

/// Accepts a message and either delivers it inline or queues it, according to
/// `server.submission_mode`.
pub async fn submit(state: &Arc<AppState>, inbound: InboundMessage) -> SubmitOutcome {
    let config = state.config();

    // Read just the headers we need for routing and display; the body is not
    // touched or copied here.
    let original_from_raw = headers::peek(&inbound.raw, "from").unwrap_or_default();
    let original_from = parse_mailbox(&original_from_raw)
        .map(|mailbox| mailbox.address)
        .unwrap_or_else(|| inbound.sender.clone());
    let subject = headers::peek(&inbound.raw, "subject")
        .map(|value| crate::message::decode_encoded_words(&value));

    let size = inbound.raw.len() as u64;
    state.metrics.inc(&state.metrics.counters.messages_received);
    state
        .metrics
        .add(&state.metrics.counters.recipients_total, inbound.recipients.len() as u64);
    state.metrics.add(&state.metrics.counters.bytes_received, size);
    state.metrics.series.record(Sample::Received);

    let mut record = MessageRecord::new(inbound.id.clone());
    record.original_from = if original_from_raw.is_empty() {
        inbound.sender.clone()
    } else {
        original_from_raw.clone()
    };
    record.recipients = inbound.recipients.clone();
    record.subject = subject.clone();
    record.size_bytes = size;
    record.client_ip = inbound.client_ip.map(|ip| ip.to_string());
    state.metrics.activity.push(record);

    let mut message = QueuedMessage {
        id: inbound.id,
        sender: inbound.sender,
        recipients: inbound.recipients,
        original_from,
        subject,
        client_ip: inbound.client_ip,
        helo: inbound.helo,
        received_at: chrono::Utc::now(),
        attempts: 0,
        next_attempt_at: chrono::Utc::now(),
        tried_relays: Vec::new(),
        last_error: None,
        raw: inbound.raw,
    };

    match config.server.submission_mode {
        SubmissionMode::Queue => enqueue(state, message),
        SubmissionMode::Direct => match attempt_delivery(state, &mut message).await {
            AttemptOutcome::Delivered { relay_id, response, .. } => {
                SubmitOutcome::Delivered { relay_id, response }
            }
            // The submitting application owns the retry in direct mode, so a
            // transient failure is reported as 4xx rather than swallowed.
            AttemptOutcome::Deferred { error } => SubmitOutcome::Rejected {
                code: 451,
                enhanced: "4.4.1",
                message: format!("upstream relay unavailable: {error}"),
            },
            AttemptOutcome::Failed { error } => SubmitOutcome::Rejected {
                code: 550,
                enhanced: "5.7.1",
                message: format!("upstream relay rejected the message: {error}"),
            },
        },
        SubmissionMode::Hybrid => match attempt_delivery(state, &mut message).await {
            AttemptOutcome::Delivered { relay_id, response, .. } => {
                SubmitOutcome::Delivered { relay_id, response }
            }
            AttemptOutcome::Deferred { error } => {
                message.last_error = Some(error);
                schedule_retry(state, message)
            }
            AttemptOutcome::Failed { error } => SubmitOutcome::Rejected {
                code: 550,
                enhanced: "5.7.1",
                message: format!("upstream relay rejected the message: {error}"),
            },
        },
    }
}

/// Puts a never-attempted message on the queue.
fn enqueue(state: &Arc<AppState>, message: QueuedMessage) -> SubmitOutcome {
    let id = message.id.clone();
    match state.queue.enqueue(message) {
        Ok(()) => {
            state.metrics.inc(&state.metrics.counters.queue_enqueued);
            state
                .metrics
                .activity
                .update(&id, |record| record.status = MessageStatus::Queued);
            state.events.publish(
                EventKind::Queue,
                json!({ "action": "enqueued", "id": id, "depth": state.queue.depth() }),
            );
            SubmitOutcome::Queued
        }
        Err(error) => {
            state.metrics.inc(&state.metrics.counters.messages_rejected);
            state.metrics.activity.update(&id, |record| {
                record.status = MessageStatus::Rejected;
                record.error = Some(error.to_string());
            });
            let code = match error {
                EnqueueError::Full { .. } => 452,
                EnqueueError::Disabled => 451,
            };
            SubmitOutcome::Rejected {
                code,
                enhanced: "4.3.1",
                message: error.to_string(),
            }
        }
    }
}

/// Requeues after a failed inline attempt (hybrid mode).
fn schedule_retry(state: &Arc<AppState>, mut message: QueuedMessage) -> SubmitOutcome {
    let config = state.config();
    let delay = config.queue.backoff_for(message.attempts.max(1));
    message.next_attempt_at = chrono::Utc::now()
        + chrono::Duration::from_std(delay).unwrap_or_else(|_| chrono::Duration::seconds(60));

    let id = message.id.clone();
    match state.queue.enqueue(message) {
        Ok(()) => {
            state.metrics.inc(&state.metrics.counters.queue_enqueued);
            state
                .metrics
                .activity
                .update(&id, |record| record.status = MessageStatus::Queued);
            SubmitOutcome::Queued
        }
        Err(error) => SubmitOutcome::Rejected {
            code: 451,
            enhanced: "4.3.1",
            message: format!("could not queue the message for retry: {error}"),
        },
    }
}

/// Runs one delivery round, trying up to `routing.max_attempts_per_message`
/// distinct relays.
pub async fn attempt_delivery(
    state: &Arc<AppState>,
    message: &mut QueuedMessage,
) -> AttemptOutcome {
    let config = state.config();
    let pool = state.pool();

    message.attempts += 1;
    state
        .metrics
        .activity
        .update(&message.id, |record| {
            record.status = MessageStatus::Sending;
            record.attempts = message.attempts;
        });

    // Relays tried during *this* round. History in `message.tried_relays` is
    // kept for the dashboard but must not permanently exclude a relay: after a
    // backoff a previously failing relay may well be healthy again.
    let mut attempted: Vec<String> = Vec::new();
    let mut last_error: Option<DeliveryError> = None;
    let rounds = config.routing.max_attempts_per_message.max(1);

    for _ in 0..rounds {
        let request = RouteRequest {
            sender: &message.original_from,
            recipients: &message.recipients,
            exclude: &attempted,
        };

        let route = match selector::select(&pool, &request) {
            Ok(route) => route,
            Err(no_route) => {
                state
                    .metrics
                    .inc(&state.metrics.counters.routing_no_relay_available);
                let reason = match &last_error {
                    Some(error) => format!("{} (last error: {})", no_route.message, error.message),
                    None => no_route.message,
                };
                return finish_deferred(state, message, reason);
            }
        };

        let relay = route.relay;
        attempted.push(relay.id().to_string());
        if !message.tried_relays.iter().any(|id| id == relay.id()) {
            message.tried_relays.push(relay.id().to_string());
        }

        // The quota is reserved up-front so concurrent deliveries cannot
        // collectively overshoot a hard provider limit.
        if !relay.try_reserve_quota() {
            tracing::debug!(
                relay = relay.id(),
                "skipping relay: quota was consumed between selection and reservation"
            );
            continue;
        }
        let _slot = relay.begin_delivery();

        let rewritten = {
            let context = RewriteContext {
                rewrite: &config.rewrite,
                relay: &relay.config,
                hostname: &config.server.hostname,
                queue_id: &message.id,
                client_ip: message.client_ip,
                client_helo: &message.helo,
                original_sender: &message.sender,
            };
            match rewrite(&message.raw, &context) {
                Ok(rewritten) => rewritten,
                Err(error) => {
                    relay.release_quota();
                    state.metrics.inc(&state.metrics.counters.rewrite_errors);
                    return finish_failed(
                        state,
                        message,
                        relay.id().to_string(),
                        format!("could not rewrite the message: {error}"),
                    );
                }
            }
        };

        if config.logging.log_headers {
            tracing::debug!(
                id = %message.id,
                relay = relay.id(),
                notes = ?rewritten.notes,
                "rewritten headers: {}",
                String::from_utf8_lossy(
                    &rewritten.raw[..rewritten.raw.len().min(4096)]
                )
            );
        }

        state.metrics.activity.update(&message.id, |record| {
            record.from_header = rewritten.from_header.clone();
            record.envelope_from = rewritten.envelope_from.clone();
            record.notes = rewritten.notes.clone();
        });

        tracing::debug!(
            id = %message.id,
            relay = relay.id(),
            reason = route.reason,
            envelope_from = %rewritten.envelope_from,
            // The pair that has to line up for SPF/DMARC alignment.
            from_header = %rewritten.from_header,
            message_id = rewritten.message_id.as_deref().unwrap_or("-"),
            recipients = message.recipients.len(),
            attempt = message.attempts,
            "delivering upstream"
        );

        let outcome = crate::relay::sender::deliver(
            &relay,
            &rewritten.envelope_from,
            &message.recipients,
            &rewritten.raw,
        )
        .await;

        match outcome {
            Ok(report) => {
                relay.record_delivery(rewritten.raw.len() as u64, report.latency, &config.health);
                state.metrics.inc(&state.metrics.counters.messages_delivered);
                state
                    .metrics
                    .add(&state.metrics.counters.bytes_delivered, rewritten.raw.len() as u64);
                state.metrics.series.record(Sample::Delivered);
                state
                    .metrics
                    .latency
                    .observe(report.latency.as_millis() as u64);

                let relay_id = relay.id().to_string();
                let latency_ms = report.latency.as_millis() as u64;
                state.metrics.activity.update(&message.id, |record| {
                    record.status = MessageStatus::Delivered;
                    record.relay_id = Some(relay_id.clone());
                    record.envelope_from = rewritten.envelope_from.clone();
                    record.reply_to = rewritten.reply_to.clone();
                    record.latency_ms = Some(latency_ms);
                    record.error = None;
                    record.notes = rewritten.notes.clone();
                });

                tracing::info!(
                    id = %message.id,
                    relay = %relay_id,
                    reason = route.reason,
                    recipients = message.recipients.len(),
                    bytes = rewritten.raw.len(),
                    latency_ms,
                    attempt = message.attempts,
                    response = %report.response,
                    "delivered"
                );

                state.events.publish(
                    EventKind::Message,
                    json!({
                        "id": message.id,
                        "status": "delivered",
                        "relay": relay_id,
                        "latency_ms": latency_ms,
                        "recipients": message.recipients.len(),
                        "subject": message.subject,
                    }),
                );

                return AttemptOutcome::Delivered {
                    relay_id,
                    response: report.response,
                };
            }
            Err(error) => {
                // The message never left, so give the send budget back.
                relay.release_quota();

                if error.should_retry() {
                    let tripped = relay.record_deferral(&error.message, &config.health);
                    tracing::warn!(
                        id = %message.id,
                        relay = relay.id(),
                        status = ?error.status_code,
                        kind = %error.kind,
                        circuit_tripped = tripped,
                        "delivery attempt failed; will try another relay or retry later: {}",
                        error.message
                    );
                    if tripped {
                        state.events.publish(
                            EventKind::Relay,
                            json!({
                                "id": relay.id(),
                                "action": "circuit_opened",
                                "error": error.message,
                            }),
                        );
                    }
                    last_error = Some(error);
                    if !config.routing.fallback_on_failure {
                        break;
                    }
                    continue;
                }

                relay.record_permanent_failure(&error.message);
                let relay_id = relay.id().to_string();
                return finish_failed(state, message, relay_id, error.to_string());
            }
        }
    }

    let reason = last_error
        .map(|error| error.to_string())
        .unwrap_or_else(|| "no delivery attempt succeeded".to_string());
    finish_deferred(state, message, reason)
}

fn finish_deferred(
    state: &Arc<AppState>,
    message: &QueuedMessage,
    reason: String,
) -> AttemptOutcome {
    state.metrics.inc(&state.metrics.counters.messages_deferred);
    state.metrics.series.record(Sample::Deferred);
    let error = crate::util::truncate(&reason, 500);
    state.metrics.activity.update(&message.id, |record| {
        record.status = MessageStatus::Deferred;
        record.error = Some(error.clone());
    });
    state.events.publish(
        EventKind::Message,
        json!({
            "id": message.id,
            "status": "deferred",
            "attempts": message.attempts,
            "error": error,
        }),
    );
    AttemptOutcome::Deferred { error }
}

fn finish_failed(
    state: &Arc<AppState>,
    message: &QueuedMessage,
    relay_id: String,
    reason: String,
) -> AttemptOutcome {
    state.metrics.inc(&state.metrics.counters.messages_failed);
    state.metrics.series.record(Sample::Failed);
    let error = crate::util::truncate(&reason, 500);
    state.metrics.activity.update(&message.id, |record| {
        record.status = MessageStatus::Failed;
        record.relay_id = Some(relay_id.clone());
        record.error = Some(error.clone());
    });
    tracing::warn!(
        id = %message.id,
        relay = %relay_id,
        "permanent delivery failure: {error}"
    );
    state.events.publish(
        EventKind::Message,
        json!({
            "id": message.id,
            "status": "failed",
            "relay": relay_id,
            "error": error,
        }),
    );
    AttemptOutcome::Failed { error }
}

/// Drains the retry queue. One task per `queue.workers`.
pub async fn run_queue_worker(state: Arc<AppState>, worker: usize) {
    tracing::debug!(worker, "queue worker started");

    loop {
        if state.is_shutting_down() {
            break;
        }

        let Some(mut message) = state.queue.take_due() else {
            // Short cap keeps shutdown responsive without busy-waiting.
            state.queue.wait_for_work(Duration::from_millis(500)).await;
            continue;
        };

        if message.attempts > 0 {
            state.metrics.inc(&state.metrics.counters.queue_retries);
        }

        let id = message.id.clone();
        match attempt_delivery(&state, &mut message).await {
            AttemptOutcome::Delivered { .. } | AttemptOutcome::Failed { .. } => {
                state.queue.finish(&id);
                state.events.publish(
                    EventKind::Queue,
                    json!({ "action": "completed", "id": id, "depth": state.queue.depth() }),
                );
            }
            AttemptOutcome::Deferred { error } => {
                let config = state.config();
                message.last_error = Some(error.clone());

                if message.attempts >= config.queue.max_attempts {
                    state.queue.finish(&id);
                    // A message that ran out of retries is a failure as well as
                    // a dead letter; counting both keeps the success rate and
                    // the failure chart honest.
                    state.metrics.inc(&state.metrics.counters.messages_dead);
                    state.metrics.inc(&state.metrics.counters.messages_failed);
                    state.metrics.series.record(Sample::Failed);
                    state.metrics.activity.update(&id, |record| {
                        record.status = MessageStatus::Failed;
                        record.error = Some(format!(
                            "gave up after {} attempts: {}",
                            message.attempts, error
                        ));
                    });
                    tracing::error!(
                        %id,
                        attempts = message.attempts,
                        recipients = message.recipients.len(),
                        "message dropped after exhausting all retries: {error}"
                    );
                    state.events.publish(
                        EventKind::Message,
                        json!({
                            "id": id,
                            "status": "dead",
                            "attempts": message.attempts,
                            "error": error,
                        }),
                    );
                } else {
                    let delay = config.queue.backoff_for(message.attempts);
                    tracing::info!(
                        %id,
                        attempts = message.attempts,
                        retry_in_seconds = delay.as_secs(),
                        "message deferred"
                    );
                    state.queue.requeue(message, delay);
                    state.events.publish(
                        EventKind::Queue,
                        json!({
                            "action": "deferred",
                            "id": id,
                            "retry_in_seconds": delay.as_secs(),
                            "depth": state.queue.depth(),
                        }),
                    );
                }
            }
        }
    }

    tracing::debug!(worker, "queue worker stopped");
}
