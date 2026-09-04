//! Background health checking and circuit-breaker recovery.
//!
//! Each interval every configured relay gets a connect + EHLO + NOOP probe.
//! Successful probes are what close a tripped circuit breaker, so a relay that
//! recovers on its own comes back into rotation without operator action -
//! while a relay an operator switched off stays off, because activation and
//! breaker state are deliberately independent.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::task::JoinSet;

use crate::events::EventKind;
use crate::relay::pool::RelayRuntime;
use crate::relay::sender;
use crate::state::AppState;

/// Outcome of a single probe, reported back to the API and dashboard.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub relay_id: String,
    pub ok: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Runs the periodic health loop until shutdown.
pub async fn run(state: Arc<AppState>) {
    let mut shutdown = state.subscribe_shutdown();

    if !state.config().health.enabled {
        tracing::info!("health checks are disabled");
        return;
    }

    if state.config().health.probe_on_start {
        probe_all(&state).await;
    }

    loop {
        // Re-read each iteration so an interval change takes effect without a
        // restart.
        let health = state.config().health.clone();
        if !health.enabled {
            tracing::info!("health checks were disabled by a configuration change");
            return;
        }
        let interval = Duration::from_secs(health.interval_seconds.max(1));

        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(interval) => {
                if state.is_shutting_down() {
                    break;
                }
                probe_all(&state).await;
            }
        }
    }

    tracing::debug!("health checker stopped");
}

/// Probes every relay concurrently and records the results.
pub async fn probe_all(state: &Arc<AppState>) -> Vec<ProbeResult> {
    let pool = state.pool();
    let mut tasks: JoinSet<ProbeResult> = JoinSet::new();

    for relay in pool.relays() {
        let relay = Arc::clone(relay);
        let state = Arc::clone(state);
        tasks.spawn(async move { probe(&state, &relay).await });
    }

    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(result) => results.push(result),
            Err(error) => tracing::warn!(%error, "a health probe task failed to complete"),
        }
    }

    let unhealthy: Vec<&ProbeResult> = results.iter().filter(|r| !r.ok).collect();
    if unhealthy.is_empty() {
        tracing::debug!(relays = results.len(), "all relays healthy");
    } else {
        tracing::warn!(
            unhealthy = unhealthy.len(),
            total = results.len(),
            "some relays failed their health probe"
        );
    }

    results
}

/// Probes one relay, updating its breaker state.
pub async fn probe(state: &Arc<AppState>, relay: &Arc<RelayRuntime>) -> ProbeResult {
    let health = state.config().health.clone();
    let timeout = Duration::from_secs(health.timeout_seconds.max(1));

    let was_eligible = relay.is_eligible();
    let outcome = tokio::time::timeout(timeout, sender::probe(relay)).await;

    let result = match outcome {
        Ok(Ok(latency)) => {
            let millis = latency.as_millis() as u64;
            relay.record_probe(Some(millis));
            relay.record_success(&health, latency);
            ProbeResult {
                relay_id: relay.id().to_string(),
                ok: true,
                latency_ms: Some(millis),
                error: None,
            }
        }
        Ok(Err(error)) => {
            relay.record_probe(None);
            let tripped = relay.record_failure(&health, &error.message);
            if tripped {
                tracing::error!(
                    relay = relay.id(),
                    "circuit breaker opened after repeated probe failures: {}",
                    error.message
                );
            }
            ProbeResult {
                relay_id: relay.id().to_string(),
                ok: false,
                latency_ms: None,
                error: Some(error.message),
            }
        }
        Err(_) => {
            let message = format!("probe timed out after {}s", timeout.as_secs());
            relay.record_probe(None);
            relay.record_failure(&health, &message);
            ProbeResult {
                relay_id: relay.id().to_string(),
                ok: false,
                latency_ms: None,
                error: Some(message),
            }
        }
    };

    // Only publish when something an operator would care about changed.
    let now_eligible = relay.is_eligible();
    if was_eligible != now_eligible {
        state.events.publish(
            EventKind::Relay,
            json!({
                "id": result.relay_id,
                "action": if now_eligible { "recovered" } else { "unavailable" },
                "eligible": now_eligible,
                "reason": relay.ineligible_reason(),
                "error": result.error,
            }),
        );
        if now_eligible {
            tracing::info!(relay = %result.relay_id, "relay is back in rotation");
        } else {
            tracing::warn!(
                relay = %result.relay_id,
                reason = ?relay.ineligible_reason(),
                "relay left rotation"
            );
        }
    }

    result
}

/// Emits periodic counter snapshots so idle dashboards keep updating, and
/// re-publishes queue depth.
pub async fn run_stats_ticker(state: Arc<AppState>) {
    let mut shutdown = state.subscribe_shutdown();
    let interval = Duration::from_secs(5);

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(interval) => {
                if state.events.subscriber_count() == 0 {
                    continue;
                }
                let counters = state.metrics.counters.snapshot();
                let pool = state.pool();
                state.events.publish(
                    EventKind::Stats,
                    json!({
                        "uptime_seconds": state.uptime_seconds(),
                        "queue_depth": state.queue.depth(),
                        "queue_in_flight": state.queue.in_flight(),
                        "messages_received": counters.messages_received,
                        "messages_delivered": counters.messages_delivered,
                        "messages_failed": counters.messages_failed,
                        "messages_deferred": counters.messages_deferred,
                        "connections_active": counters.connections_active,
                        "relays_eligible": pool.eligible_count(),
                        "relays_total": pool.len(),
                    }),
                );
            }
        }
    }
}
