//! Relay pool: per-upstream runtime state and eligibility.
//!
//! A relay is *eligible* (in rotation) only when all of the following hold:
//!
//! * it is active (operator toggle),
//! * its circuit breaker is not open,
//! * it is below its per-minute, hourly and daily quota,
//! * it has a free concurrency slot.
//!
//! Every one of those is observable from the dashboard, so an operator can
//! always tell *why* a relay stopped receiving traffic.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::config::{Config, HealthConfig, RelayConfig, RoutingConfig};
use crate::metrics::RelayMetricsRow;
use crate::relay::sender::build_transport;
use crate::relay::Transport;

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Normal operation.
    Closed,
    /// Tripped: the relay is out of rotation until the cooldown expires.
    Open,
    /// Cooldown expired; a single probe or delivery decides the next state.
    HalfOpen,
}

#[derive(Debug)]
struct Circuit {
    state: CircuitState,
    /// Monotonic deadline for an open circuit.
    open_until: Option<Instant>,
    consecutive_failures: u32,
    consecutive_successes: u32,
    healthy: bool,
    last_error: Option<String>,
    last_error_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    last_probe_at: Option<DateTime<Utc>>,
    last_probe_ms: Option<u64>,
    /// How many times the breaker has tripped since start.
    trips: u64,
    /// Set when an operator manually deactivated the relay, so auto-recovery
    /// never puts it back into rotation behind their back.
    manually_disabled: bool,
}

impl Default for Circuit {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            open_until: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            healthy: true,
            last_error: None,
            last_error_at: None,
            last_success_at: None,
            last_probe_at: None,
            last_probe_ms: None,
            trips: 0,
            manually_disabled: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Quota windows
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Usage {
    minute_key: i64,
    minute_count: u64,
    hour_key: i64,
    hour_count: u64,
    day_key: i64,
    day_count: u64,
    /// Lifetime reservations, for the dashboard.
    total: u64,
}

impl Usage {
    fn roll(&mut self, now: i64) {
        let minute = now / 60;
        let hour = now / 3_600;
        let day = now / 86_400;
        if self.minute_key != minute {
            self.minute_key = minute;
            self.minute_count = 0;
        }
        if self.hour_key != hour {
            self.hour_key = hour;
            self.hour_count = 0;
        }
        if self.day_key != day {
            self.day_key = day;
            self.day_count = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Stats {
    sent: AtomicU64,
    failed: AtomicU64,
    deferred: AtomicU64,
    attempts: AtomicU64,
    bytes_sent: AtomicU64,
    latency_sum_ms: AtomicU64,
    latency_count: AtomicU64,
    last_latency_ms: AtomicU64,
}

// ---------------------------------------------------------------------------
// Relay runtime
// ---------------------------------------------------------------------------

/// One configured upstream relay plus everything mutable about it.
pub struct RelayRuntime {
    pub config: RelayConfig,
    transport: Transport,
    /// Operator on/off switch. Starts from `config.enabled`.
    active: AtomicBool,
    in_flight: AtomicUsize,
    circuit: Mutex<Circuit>,
    usage: Mutex<Usage>,
    stats: Stats,
}

impl std::fmt::Debug for RelayRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayRuntime")
            .field("id", &self.config.id)
            .field("endpoint", &self.config.endpoint())
            .field("active", &self.is_active())
            .finish()
    }
}

impl RelayRuntime {
    /// `fallback_timeout_seconds` comes from `server.timeout_seconds` and is
    /// used for relays that do not set their own `timeout_seconds`.
    pub fn new(config: RelayConfig, fallback_timeout_seconds: u64) -> Result<Self, String> {
        let transport = build_transport(&config, fallback_timeout_seconds)?;
        let active = AtomicBool::new(config.enabled);
        Ok(Self {
            config,
            transport,
            active,
            in_flight: AtomicUsize::new(0),
            circuit: Mutex::new(Circuit::default()),
            usage: Mutex::new(Usage::default()),
            stats: Stats::default(),
        })
    }

    pub fn id(&self) -> &str {
        &self.config.id
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    // -- activation ------------------------------------------------------

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Turns the relay on. Also clears a tripped breaker so the operator's
    /// intent takes effect immediately instead of after the cooldown.
    pub fn activate(&self) -> bool {
        let changed = !self.active.swap(true, Ordering::Relaxed);
        let mut circuit = self.circuit();
        circuit.manually_disabled = false;
        if circuit.state != CircuitState::Closed {
            circuit.state = CircuitState::Closed;
            circuit.open_until = None;
            circuit.consecutive_failures = 0;
        }
        changed
    }

    pub fn deactivate(&self) -> bool {
        let changed = self.active.swap(false, Ordering::Relaxed);
        self.circuit().manually_disabled = true;
        changed
    }

    pub fn set_active(&self, active: bool) -> bool {
        if active {
            self.activate()
        } else {
            self.deactivate()
        }
    }

    // -- circuit breaker -------------------------------------------------

    fn circuit(&self) -> std::sync::MutexGuard<'_, Circuit> {
        match self.circuit.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn usage(&self) -> std::sync::MutexGuard<'_, Usage> {
        match self.usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Moves an expired open circuit to half-open and reports the state.
    pub fn circuit_state(&self) -> CircuitState {
        let mut circuit = self.circuit();
        if circuit.state == CircuitState::Open {
            let expired = circuit
                .open_until
                .map(|deadline| Instant::now() >= deadline)
                .unwrap_or(true);
            if expired {
                circuit.state = CircuitState::HalfOpen;
                circuit.open_until = None;
            }
        }
        circuit.state
    }

    pub fn is_healthy(&self) -> bool {
        self.circuit().healthy
    }

    /// Records a successful delivery or probe.
    pub fn record_success(&self, health: &HealthConfig, latency: Duration) {
        let mut circuit = self.circuit();
        circuit.consecutive_failures = 0;
        circuit.consecutive_successes = circuit.consecutive_successes.saturating_add(1);
        circuit.last_success_at = Some(Utc::now());
        circuit.last_error = None;

        let threshold = health.success_threshold.max(1);
        if circuit.state != CircuitState::Closed
            && circuit.consecutive_successes >= threshold
            && health.auto_recover
            && !circuit.manually_disabled
        {
            circuit.state = CircuitState::Closed;
            circuit.open_until = None;
        }
        circuit.healthy = true;
        drop(circuit);

        let millis = latency.as_millis().min(u64::MAX as u128) as u64;
        self.stats.latency_sum_ms.fetch_add(millis, Ordering::Relaxed);
        self.stats.latency_count.fetch_add(1, Ordering::Relaxed);
        self.stats.last_latency_ms.store(millis, Ordering::Relaxed);
    }

    /// Records a failed delivery or probe. Returns true when this call tripped
    /// the breaker, so the caller can log and publish an event.
    pub fn record_failure(&self, health: &HealthConfig, error: &str) -> bool {
        let mut circuit = self.circuit();
        circuit.consecutive_successes = 0;
        circuit.consecutive_failures = circuit.consecutive_failures.saturating_add(1);
        circuit.last_error = Some(crate::util::truncate(error, 400));
        circuit.last_error_at = Some(Utc::now());
        circuit.healthy = false;

        let should_trip = health.auto_disable
            && circuit.state != CircuitState::Open
            && circuit.consecutive_failures >= health.failure_threshold.max(1);

        if should_trip {
            circuit.state = CircuitState::Open;
            circuit.open_until =
                Some(Instant::now() + Duration::from_secs(health.cooldown_seconds.max(1)));
            circuit.trips += 1;
            true
        } else {
            if circuit.state == CircuitState::HalfOpen {
                // A failed probe re-opens the circuit for another cooldown.
                circuit.state = CircuitState::Open;
                circuit.open_until =
                    Some(Instant::now() + Duration::from_secs(health.cooldown_seconds.max(1)));
            }
            false
        }
    }

    /// Clears a tripped breaker without changing the activation state.
    pub fn reset_circuit(&self) {
        let mut circuit = self.circuit();
        circuit.state = CircuitState::Closed;
        circuit.open_until = None;
        circuit.consecutive_failures = 0;
        circuit.last_error = None;
        circuit.healthy = true;
    }

    pub fn record_probe(&self, latency_ms: Option<u64>) {
        let mut circuit = self.circuit();
        circuit.last_probe_at = Some(Utc::now());
        circuit.last_probe_ms = latency_ms;
    }

    // -- quotas ----------------------------------------------------------

    /// Reserves one send slot against the per-minute/hourly/daily quota.
    ///
    /// Reserving up-front (rather than counting on success) is what keeps a
    /// hard provider limit from being exceeded by concurrent deliveries.
    pub fn try_reserve_quota(&self) -> bool {
        let now = Utc::now().timestamp();
        let mut usage = self.usage();
        usage.roll(now);

        if let Some(limit) = self.config.max_per_minute {
            if usage.minute_count >= limit {
                return false;
            }
        }
        if let Some(limit) = self.config.max_per_hour {
            if usage.hour_count >= limit {
                return false;
            }
        }
        if let Some(limit) = self.config.max_per_day {
            if usage.day_count >= limit {
                return false;
            }
        }

        usage.minute_count += 1;
        usage.hour_count += 1;
        usage.day_count += 1;
        usage.total += 1;
        true
    }

    /// Returns a reservation after a failed attempt, so a transient upstream
    /// error does not silently consume the operator's send budget.
    pub fn release_quota(&self) {
        let mut usage = self.usage();
        usage.minute_count = usage.minute_count.saturating_sub(1);
        usage.hour_count = usage.hour_count.saturating_sub(1);
        usage.day_count = usage.day_count.saturating_sub(1);
        usage.total = usage.total.saturating_sub(1);
    }

    pub fn quota_exhausted(&self) -> bool {
        let now = Utc::now().timestamp();
        let mut usage = self.usage();
        usage.roll(now);
        let minute_full = self
            .config
            .max_per_minute
            .map(|limit| usage.minute_count >= limit)
            .unwrap_or(false);
        let hour_full = self
            .config
            .max_per_hour
            .map(|limit| usage.hour_count >= limit)
            .unwrap_or(false);
        let day_full = self
            .config
            .max_per_day
            .map(|limit| usage.day_count >= limit)
            .unwrap_or(false);
        minute_full || hour_full || day_full
    }

    pub fn hour_count(&self) -> u64 {
        let now = Utc::now().timestamp();
        let mut usage = self.usage();
        usage.roll(now);
        usage.hour_count
    }

    // -- concurrency ------------------------------------------------------

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn has_capacity(&self) -> bool {
        self.in_flight() < self.config.max_concurrent.max(1)
    }

    /// RAII guard so an in-flight count can never leak on an early return.
    pub fn begin_delivery(self: &Arc<Self>) -> DeliveryGuard {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        DeliveryGuard {
            relay: Arc::clone(self),
        }
    }

    // -- eligibility ------------------------------------------------------

    /// True when this relay may receive traffic right now.
    pub fn is_eligible(&self) -> bool {
        self.is_active()
            && self.circuit_state() != CircuitState::Open
            && self.has_capacity()
            && !self.quota_exhausted()
    }

    /// Human-readable reason the relay is out of rotation, for the dashboard.
    pub fn ineligible_reason(&self) -> Option<&'static str> {
        if !self.is_active() {
            return Some("deactivated");
        }
        if self.circuit_state() == CircuitState::Open {
            return Some("circuit_open");
        }
        if self.quota_exhausted() {
            return Some("quota_reached");
        }
        if !self.has_capacity() {
            return Some("at_concurrency_limit");
        }
        None
    }

    // -- outcome recording -------------------------------------------------

    pub fn record_delivery(&self, bytes: u64, latency: Duration, health: &HealthConfig) {
        self.stats.sent.fetch_add(1, Ordering::Relaxed);
        self.stats.attempts.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.record_success(health, latency);
    }

    pub fn record_deferral(&self, error: &str, health: &HealthConfig) -> bool {
        self.stats.deferred.fetch_add(1, Ordering::Relaxed);
        self.stats.attempts.fetch_add(1, Ordering::Relaxed);
        self.record_failure(health, error)
    }

    pub fn record_permanent_failure(&self, error: &str) {
        self.stats.failed.fetch_add(1, Ordering::Relaxed);
        self.stats.attempts.fetch_add(1, Ordering::Relaxed);
        // A 5xx rejection is the upstream doing its job, not an unhealthy
        // relay, so the breaker is deliberately left alone. Only the message
        // is at fault.
        let mut circuit = self.circuit();
        circuit.last_error = Some(crate::util::truncate(error, 400));
        circuit.last_error_at = Some(Utc::now());
    }

    pub fn reset_stats(&self) {
        self.stats.sent.store(0, Ordering::Relaxed);
        self.stats.failed.store(0, Ordering::Relaxed);
        self.stats.deferred.store(0, Ordering::Relaxed);
        self.stats.attempts.store(0, Ordering::Relaxed);
        self.stats.bytes_sent.store(0, Ordering::Relaxed);
        self.stats.latency_sum_ms.store(0, Ordering::Relaxed);
        self.stats.latency_count.store(0, Ordering::Relaxed);
        self.stats.last_latency_ms.store(0, Ordering::Relaxed);
        let mut circuit = self.circuit();
        circuit.trips = 0;
        circuit.last_error = None;
    }

    pub fn sent(&self) -> u64 {
        self.stats.sent.load(Ordering::Relaxed)
    }

    pub fn failed(&self) -> u64 {
        self.stats.failed.load(Ordering::Relaxed)
    }

    /// Copies mutable runtime state from a previous generation of this relay,
    /// so a config reload does not reset counters or re-enable a relay the
    /// operator had switched off.
    fn carry_over_from(&self, previous: &RelayRuntime, keep_activation: bool) {
        macro_rules! copy {
            ($($field:ident),+ $(,)?) => {
                $(self.stats.$field.store(previous.stats.$field.load(Ordering::Relaxed), Ordering::Relaxed);)+
            };
        }
        copy!(
            sent,
            failed,
            deferred,
            attempts,
            bytes_sent,
            latency_sum_ms,
            latency_count,
            last_latency_ms,
        );

        {
            let previous_usage = previous.usage();
            let mut usage = self.usage();
            usage.hour_key = previous_usage.hour_key;
            usage.hour_count = previous_usage.hour_count;
            usage.day_key = previous_usage.day_key;
            usage.day_count = previous_usage.day_count;
            usage.total = previous_usage.total;
        }

        {
            let previous_circuit = previous.circuit();
            let mut circuit = self.circuit();
            circuit.state = previous_circuit.state;
            circuit.open_until = previous_circuit.open_until;
            circuit.consecutive_failures = previous_circuit.consecutive_failures;
            circuit.consecutive_successes = previous_circuit.consecutive_successes;
            circuit.healthy = previous_circuit.healthy;
            circuit.last_error = previous_circuit.last_error.clone();
            circuit.last_error_at = previous_circuit.last_error_at;
            circuit.last_success_at = previous_circuit.last_success_at;
            circuit.last_probe_at = previous_circuit.last_probe_at;
            circuit.last_probe_ms = previous_circuit.last_probe_ms;
            circuit.trips = previous_circuit.trips;
            circuit.manually_disabled = previous_circuit.manually_disabled;
        }

        if keep_activation {
            self.active
                .store(previous.is_active(), Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self, weight_percent: f64) -> RelaySnapshot {
        // Every value that needs a lock is read before the circuit snapshot is
        // taken: `is_eligible` re-enters the circuit mutex, which is not
        // reentrant, so nothing here may run while that guard is held.
        let circuit_state = self.circuit_state();
        let eligible = self.is_eligible();
        let ineligible_reason = self.ineligible_reason();
        let usage_now = Utc::now().timestamp();
        let (minute_count, hour_count, day_count, total) = {
            let mut usage = self.usage();
            usage.roll(usage_now);
            (
                usage.minute_count,
                usage.hour_count,
                usage.day_count,
                usage.total,
            )
        };
        let circuit = self.circuit();

        let latency_count = self.stats.latency_count.load(Ordering::Relaxed);
        let average_latency_ms = if latency_count == 0 {
            None
        } else {
            Some(self.stats.latency_sum_ms.load(Ordering::Relaxed) as f64 / latency_count as f64)
        };

        RelaySnapshot {
            id: self.config.id.clone(),
            host: self.config.host.clone(),
            port: self.config.port,
            tls: self.config.tls.as_str(),
            allow_invalid_certs: self.config.allow_invalid_certs,
            from_address: self.config.effective_from_address(),
            from_same_as_username: self.config.from_same_as_username,
            align_envelope: self.config.align_envelope,
            description: self.config.description.clone(),
            tags: self.config.tags.clone(),
            username: self.config.auth.as_ref().map(|a| a.username.clone()),
            has_auth: self.config.auth.is_some(),

            weight: self.config.weight,
            weight_percent,
            priority: self.config.priority,
            max_concurrent: self.config.max_concurrent,

            enabled: self.config.enabled,
            active: self.is_active(),
            eligible,
            ineligible_reason,
            circuit_state,
            healthy: circuit.healthy,
            manually_disabled: circuit.manually_disabled,
            circuit_trips: circuit.trips,
            cooldown_remaining_seconds: circuit
                .open_until
                .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
                .map(|remaining| remaining.as_secs()),

            in_flight: self.in_flight(),
            sent: self.stats.sent.load(Ordering::Relaxed),
            failed: self.stats.failed.load(Ordering::Relaxed),
            deferred: self.stats.deferred.load(Ordering::Relaxed),
            attempts: self.stats.attempts.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            average_latency_ms,
            last_latency_ms: match self.stats.last_latency_ms.load(Ordering::Relaxed) {
                0 => None,
                value => Some(value),
            },

            consecutive_failures: circuit.consecutive_failures,
            last_error: circuit.last_error.clone(),
            last_error_at: circuit.last_error_at,
            last_success_at: circuit.last_success_at,
            last_probe_at: circuit.last_probe_at,
            last_probe_ms: circuit.last_probe_ms,

            minute_count,
            minute_limit: self.config.max_per_minute,
            hour_count,
            hour_limit: self.config.max_per_hour,
            day_count,
            day_limit: self.config.max_per_day,
            total_reserved: total,
        }
    }
}

/// Decrements the in-flight counter when a delivery attempt ends, however it
/// ends.
pub struct DeliveryGuard {
    relay: Arc<RelayRuntime>,
}

impl Drop for DeliveryGuard {
    fn drop(&mut self) {
        let _ = self.relay.in_flight.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(1)),
        );
    }
}

/// Serialisable view of a relay for the API and dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct RelaySnapshot {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub tls: &'static str,
    pub allow_invalid_certs: bool,
    pub from_address: String,
    pub from_same_as_username: bool,
    pub align_envelope: bool,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub username: Option<String>,
    pub has_auth: bool,

    pub weight: u32,
    pub weight_percent: f64,
    pub priority: u32,
    pub max_concurrent: usize,

    pub enabled: bool,
    pub active: bool,
    pub eligible: bool,
    pub ineligible_reason: Option<&'static str>,
    pub circuit_state: CircuitState,
    pub healthy: bool,
    pub manually_disabled: bool,
    pub circuit_trips: u64,
    pub cooldown_remaining_seconds: Option<u64>,

    pub in_flight: usize,
    pub sent: u64,
    pub failed: u64,
    pub deferred: u64,
    pub attempts: u64,
    pub bytes_sent: u64,
    pub average_latency_ms: Option<f64>,
    pub last_latency_ms: Option<u64>,

    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_probe_at: Option<DateTime<Utc>>,
    pub last_probe_ms: Option<u64>,

    pub minute_count: u64,
    pub minute_limit: Option<u64>,
    pub hour_count: u64,
    pub hour_limit: Option<u64>,
    pub day_count: u64,
    pub day_limit: Option<u64>,
    pub total_reserved: u64,
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

/// The set of configured relays plus the routing state machine.
pub struct Pool {
    relays: Vec<Arc<RelayRuntime>>,
    index: HashMap<String, usize>,
    pub routing: RoutingConfig,
    /// Cursor for `round_robin`.
    cursor: AtomicUsize,
    /// Current weights for smooth weighted round-robin, indexed like `relays`.
    smooth_weights: Mutex<Vec<i64>>,
}

impl Pool {
    /// Builds a pool, constructing one reusable transport per relay.
    pub fn build(config: &Config) -> Result<Self, String> {
        let mut relays = Vec::with_capacity(config.relays.len());
        for relay_config in &config.relays {
            let runtime = RelayRuntime::new(relay_config.clone(), config.server.timeout_seconds)
                .map_err(|error| format!("relay `{}`: {}", relay_config.id, error))?;
            relays.push(Arc::new(runtime));
        }

        let index = relays
            .iter()
            .enumerate()
            .map(|(position, relay)| (relay.id().to_string(), position))
            .collect();
        let smooth_weights = Mutex::new(vec![0i64; relays.len()]);

        Ok(Self {
            relays,
            index,
            routing: config.routing.clone(),
            cursor: AtomicUsize::new(0),
            smooth_weights,
        })
    }

    /// Builds a new pool from `config` while carrying over runtime state for
    /// relays that still exist.
    pub fn rebuild_from(previous: &Pool, config: &Config) -> Result<Self, String> {
        let pool = Pool::build(config)?;
        for relay in &pool.relays {
            if let Some(old) = previous.get(relay.id()) {
                // If the operator changed `enabled` in the file, that wins;
                // otherwise the live toggle is preserved.
                let keep_activation = old.config.enabled == relay.config.enabled;
                relay.carry_over_from(&old, keep_activation);
            }
        }
        Ok(pool)
    }

    pub fn relays(&self) -> &[Arc<RelayRuntime>] {
        &self.relays
    }

    pub fn len(&self) -> usize {
        self.relays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<Arc<RelayRuntime>> {
        self.index
            .get(id)
            .and_then(|position| self.relays.get(*position))
            .map(Arc::clone)
    }

    pub fn contains(&self, id: &str) -> bool {
        self.index.contains_key(id)
    }

    pub fn active_count(&self) -> usize {
        self.relays.iter().filter(|relay| relay.is_active()).count()
    }

    pub fn eligible_count(&self) -> usize {
        self.relays.iter().filter(|relay| relay.is_eligible()).count()
    }

    pub fn healthy_count(&self) -> usize {
        self.relays.iter().filter(|relay| relay.is_healthy()).count()
    }

    // -- bulk activation --------------------------------------------------

    /// Activates every relay. Returns the ids that actually changed.
    pub fn activate_all(&self) -> Vec<String> {
        self.set_all(true)
    }

    /// Deactivates every relay. Returns the ids that actually changed.
    pub fn deactivate_all(&self) -> Vec<String> {
        self.set_all(false)
    }

    fn set_all(&self, active: bool) -> Vec<String> {
        self.relays
            .iter()
            .filter(|relay| relay.set_active(active))
            .map(|relay| relay.id().to_string())
            .collect()
    }

    /// Applies `active` to the given ids. Returns `(changed, unknown)`.
    pub fn set_many(&self, ids: &[String], active: bool) -> (Vec<String>, Vec<String>) {
        let mut changed = Vec::new();
        let mut unknown = Vec::new();
        for id in ids {
            match self.get(id) {
                Some(relay) => {
                    if relay.set_active(active) {
                        changed.push(id.clone());
                    }
                }
                None => unknown.push(id.clone()),
            }
        }
        (changed, unknown)
    }

    /// Activates exactly the given ids and deactivates everything else - the
    /// "select these only" action in the dashboard.
    pub fn set_exclusive(&self, ids: &[String]) -> (Vec<String>, Vec<String>) {
        let unknown: Vec<String> = ids
            .iter()
            .filter(|id| !self.contains(id))
            .cloned()
            .collect();
        let mut changed = Vec::new();
        for relay in &self.relays {
            let should_be_active = ids.iter().any(|id| id == relay.id());
            if relay.set_active(should_be_active) {
                changed.push(relay.id().to_string());
            }
        }
        (changed, unknown)
    }

    // -- weights ----------------------------------------------------------

    /// Share of traffic each relay should receive, as a percentage of the
    /// active pool.
    pub fn weight_percentages(&self) -> HashMap<String, f64> {
        let total: u64 = self
            .relays
            .iter()
            .filter(|relay| relay.is_active())
            .map(|relay| relay.config.weight as u64)
            .sum();

        self.relays
            .iter()
            .map(|relay| {
                let percent = if !relay.is_active() || total == 0 {
                    0.0
                } else {
                    (relay.config.weight as f64 / total as f64) * 100.0
                };
                (relay.id().to_string(), percent)
            })
            .collect()
    }

    pub fn snapshot(&self) -> Vec<RelaySnapshot> {
        let percentages = self.weight_percentages();
        self.relays
            .iter()
            .map(|relay| {
                let percent = percentages.get(relay.id()).copied().unwrap_or(0.0);
                relay.snapshot(percent)
            })
            .collect()
    }

    pub fn metrics_rows(&self) -> Vec<RelayMetricsRow> {
        self.relays
            .iter()
            .map(|relay| RelayMetricsRow {
                id: relay.id().to_string(),
                available: relay.is_eligible(),
                sent: relay.sent(),
                failed: relay.failed(),
                in_flight: relay.in_flight() as u64,
            })
            .collect()
    }

    // -- internals used by the selector ------------------------------------

    pub(crate) fn position_of(&self, id: &str) -> Option<usize> {
        self.index.get(id).copied()
    }

    pub(crate) fn next_cursor(&self, modulo: usize) -> usize {
        if modulo == 0 {
            return 0;
        }
        self.cursor.fetch_add(1, Ordering::Relaxed) % modulo
    }

    /// Smooth weighted round-robin step over `candidates` (pool indices).
    ///
    /// This is the nginx SWRR algorithm: it produces the exact configured
    /// ratio while spreading picks evenly, unlike a random weighted draw which
    /// clusters over short windows.
    pub(crate) fn smooth_weighted_pick(&self, candidates: &[usize]) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        let mut weights = match self.smooth_weights.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if weights.len() != self.relays.len() {
            weights.resize(self.relays.len(), 0);
        }

        let mut total = 0i64;
        let mut best: Option<usize> = None;
        for &candidate in candidates {
            let weight = self.relays[candidate].config.weight.max(1) as i64;
            total += weight;
            weights[candidate] += weight;
            let is_better = match best {
                Some(current) => weights[candidate] > weights[current],
                None => true,
            };
            if is_better {
                best = Some(candidate);
            }
        }

        if let Some(chosen) = best {
            weights[chosen] -= total;
        }
        best
    }
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("relays", &self.relays.len())
            .field("strategy", &self.routing.strategy.as_str())
            .finish()
    }
}
