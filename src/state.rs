//! Shared runtime state.
//!
//! `Config` and `Pool` live behind `RwLock<Arc<..>>` so that hot reloads can
//! swap a whole generation atomically while in-flight deliveries keep using
//! the generation they started with. Readers clone the `Arc` and release the
//! lock immediately, so no guard is ever held across an `.await`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::json;
use tokio::sync::watch;

use crate::config::Config;
use crate::error::ConfigError;
use crate::events::{EventBus, EventKind};
use crate::metrics::Metrics;
use crate::queue::Queue;
use crate::relay::pool::Pool;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct AppState {
    config: RwLock<Arc<Config>>,
    pool: RwLock<Arc<Pool>>,
    pub config_path: PathBuf,
    pub metrics: Arc<Metrics>,
    pub events: Arc<EventBus>,
    pub queue: Arc<Queue>,
    pub started_at: Instant,
    pub started_wall: DateTime<Utc>,
    shutdown: watch::Sender<bool>,
    shutting_down: AtomicBool,
    sessions: SessionStore,
}

impl AppState {
    pub fn new(config: Config, config_path: PathBuf) -> Result<Arc<Self>, String> {
        let pool = Pool::build(&config)?;
        let queue = Arc::new(Queue::new(&config.queue));
        let (shutdown, _) = watch::channel(false);

        Ok(Arc::new(Self {
            config: RwLock::new(Arc::new(config)),
            pool: RwLock::new(Arc::new(pool)),
            config_path,
            metrics: Arc::new(Metrics::new()),
            events: Arc::new(EventBus::new()),
            queue,
            started_at: Instant::now(),
            started_wall: Utc::now(),
            shutdown,
            shutting_down: AtomicBool::new(false),
            sessions: SessionStore::new(),
        }))
    }

    pub fn sessions(&self) -> &SessionStore {
        &self.sessions
    }

    /// Current configuration generation.
    pub fn config(&self) -> Arc<Config> {
        match self.config.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Current relay pool generation.
    pub fn pool(&self) -> Arc<Pool> {
        match self.pool.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    fn store_config(&self, config: Arc<Config>) {
        let mut guard = match self.config.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = config;
    }

    fn store_pool(&self, pool: Arc<Pool>) {
        let mut guard = match self.pool.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = pool;
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    // -- configuration changes --------------------------------------------

    /// Validates and installs a new configuration, preserving relay runtime
    /// state (counters, live activation, breaker) wherever the relay id
    /// survived the change.
    pub fn apply_config(&self, config: Config) -> Result<ConfigChange, String> {
        config.validate().map_err(|error| error.to_string())?;

        let previous = self.config();
        let previous_pool = self.pool();
        let new_pool = Pool::rebuild_from(&previous_pool, &config)?;

        let change = ConfigChange {
            added: config
                .relays
                .iter()
                .filter(|relay| !previous_pool.contains(&relay.id))
                .map(|relay| relay.id.clone())
                .collect(),
            removed: previous
                .relays
                .iter()
                .filter(|relay| !config.relays.iter().any(|new| new.id == relay.id))
                .map(|relay| relay.id.clone())
                .collect(),
            strategy_changed: previous.routing.strategy != config.routing.strategy,
            queue_settings_changed: !queue_settings_equal(&previous, &config),
        };

        self.store_config(Arc::new(config));
        self.store_pool(Arc::new(new_pool));

        self.events.publish(
            EventKind::Config,
            json!({
                "action": "applied",
                "relays_added": change.added,
                "relays_removed": change.removed,
                "strategy_changed": change.strategy_changed,
                "queue_restart_required": change.queue_settings_changed,
            }),
        );

        Ok(change)
    }

    /// Re-reads the configuration file and installs it.
    pub fn reload_from_disk(&self) -> Result<ConfigChange, String> {
        let config = Config::load(&self.config_path).map_err(|error| error.to_string())?;
        self.apply_config(config)
    }

    /// Writes the current configuration back to disk.
    pub fn persist_config(&self) -> Result<(), ConfigError> {
        self.config().save(&self.config_path)
    }

    /// Mutates the configuration through `edit`, then validates, installs and
    /// optionally persists it. The closure receives a deep copy, so a
    /// rejected edit leaves the running configuration untouched.
    pub fn edit_config<F>(&self, persist: bool, edit: F) -> Result<ConfigChange, String>
    where
        F: FnOnce(&mut Config),
    {
        let mut draft = (*self.config()).clone();
        edit(&mut draft);
        let change = self.apply_config(draft)?;
        if persist {
            self.persist_config().map_err(|error| error.to_string())?;
        }
        Ok(change)
    }

    /// Mirrors a live activation change into the configuration file so the
    /// state survives a restart.
    pub fn persist_activation(&self, changes: &[(String, bool)]) -> Result<(), String> {
        if changes.is_empty() {
            return Ok(());
        }
        let mut draft = (*self.config()).clone();
        for (id, active) in changes {
            if let Some(relay) = draft.relay_mut(id) {
                relay.enabled = *active;
            }
        }
        // Written directly rather than through `apply_config`: the pool has
        // already been toggled, and rebuilding it here would be a no-op that
        // only risks clobbering live state.
        self.store_config(Arc::new(draft));
        self.persist_config().map_err(|error| error.to_string())
    }

    // -- lifecycle ---------------------------------------------------------

    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Relaxed)
    }

    /// Signals every background task to stop accepting new work.
    pub fn begin_shutdown(&self) {
        if self.shutting_down.swap(true, Ordering::Relaxed) {
            return;
        }
        let _ = self.shutdown.send(true);
        self.events
            .publish(EventKind::Notice, json!({ "text": "shutting down" }));
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config_path", &self.config_path)
            .field("relays", &self.pool().len())
            .field("queue_depth", &self.queue.depth())
            .field("uptime_seconds", &self.uptime_seconds())
            .finish()
    }
}

/// In-memory dashboard sessions. A restart signs everyone out, which is
/// deliberate: the cookie is not persisted next to the mail spool.
pub struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
}

struct Session {
    username: String,
    expires: Instant,
}

const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

impl SessionStore {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn create(&self, username: impl Into<String>) -> String {
        let token = crate::util::new_session_token();
        self.lock().insert(
            token.clone(),
            Session {
                username: username.into(),
                expires: Instant::now() + SESSION_TTL,
            },
        );
        token
    }

    pub fn username(&self, token: &str) -> Option<String> {
        let mut guard = self.lock();
        guard.retain(|_, session| session.expires > Instant::now());
        let session = guard.get_mut(token)?;
        session.expires = Instant::now() + SESSION_TTL;
        Some(session.username.clone())
    }

    pub fn revoke(&self, token: &str) {
        self.lock().remove(token);
    }
}

/// What changed between two configuration generations.
#[derive(Debug, Clone, Default)]
pub struct ConfigChange {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub strategy_changed: bool,
    /// Queue sizing and spool settings are read once at startup, so a change
    /// there needs a restart to take effect. Surfaced rather than ignored.
    pub queue_settings_changed: bool,
}

fn queue_settings_equal(left: &Config, right: &Config) -> bool {
    left.queue.enabled == right.queue.enabled
        && left.queue.workers == right.queue.workers
        && left.queue.capacity == right.queue.capacity
        && left.queue.persist == right.queue.persist
        && left.queue.directory == right.queue.directory
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RelayConfig, RoutingConfig, Strategy};

    fn relay(id: &str) -> RelayConfig {
        RelayConfig {
            id: id.to_string(),
            host: format!("smtp.{id}.test"),
            from_address: format!("noreply@{id}.test"),
            ..Default::default()
        }
    }

    fn state_with(relays: Vec<RelayConfig>) -> Arc<AppState> {
        let config = Config {
            relays,
            queue: crate::config::QueueConfig {
                persist: false,
                ..Default::default()
            },
            ..Default::default()
        };
        AppState::new(config, PathBuf::from("config.yaml")).expect("state builds")
    }

    #[test]
    fn config_and_pool_are_readable() {
        let state = state_with(vec![relay("a")]);
        assert_eq!(state.config().relays.len(), 1);
        assert_eq!(state.pool().len(), 1);
    }

    #[test]
    fn applying_config_preserves_live_activation_and_counters() {
        let state = state_with(vec![relay("a"), relay("b")]);

        // Operator switches "a" off at runtime and traffic flows.
        state.pool().get("a").unwrap().deactivate();
        state
            .pool()
            .get("a")
            .unwrap()
            .record_delivery(1_024, std::time::Duration::from_millis(50), &state.config().health);

        // An unrelated config change arrives.
        let mut draft = (*state.config()).clone();
        draft.server.hostname = "changed.local".to_string();
        state.apply_config(draft).unwrap();

        let relay_a = state.pool().get("a").unwrap();
        assert!(!relay_a.is_active(), "runtime deactivation must survive");
        assert_eq!(relay_a.sent(), 1, "counters must survive");
        assert_eq!(state.config().server.hostname, "changed.local");
    }

    #[test]
    fn explicit_enabled_change_in_config_wins_over_live_state() {
        let state = state_with(vec![relay("a")]);
        state.pool().get("a").unwrap().deactivate();

        let mut draft = (*state.config()).clone();
        draft.relay_mut("a").unwrap().enabled = false;
        state.apply_config(draft).unwrap();
        assert!(!state.pool().get("a").unwrap().is_active());

        // Flipping the file back to enabled re-activates the relay.
        let mut draft = (*state.config()).clone();
        draft.relay_mut("a").unwrap().enabled = true;
        state.apply_config(draft).unwrap();
        assert!(state.pool().get("a").unwrap().is_active());
    }

    #[test]
    fn config_change_reports_added_and_removed_relays() {
        let state = state_with(vec![relay("a"), relay("b")]);
        let mut draft = (*state.config()).clone();
        draft.relays.retain(|r| r.id != "b");
        draft.relays.push(relay("c"));

        let change = state.apply_config(draft).unwrap();
        assert_eq!(change.added, vec!["c".to_string()]);
        assert_eq!(change.removed, vec!["b".to_string()]);
        assert!(state.pool().get("b").is_none());
        assert!(state.pool().get("c").is_some());
    }

    #[test]
    fn invalid_config_is_rejected_without_changing_state() {
        let state = state_with(vec![relay("a")]);
        let mut draft = (*state.config()).clone();
        draft.relays[0].from_address = "not-an-email".to_string();

        assert!(state.apply_config(draft).is_err());
        assert_eq!(state.config().relays.len(), 1, "state must be unchanged");
        assert_eq!(state.config().relays[0].from_address, "noreply@a.test");
        assert_eq!(state.pool().len(), 1);
    }

    #[test]
    fn edit_config_rolls_back_on_invalid_edits() {
        let state = state_with(vec![relay("a")]);
        let result = state.edit_config(false, |config| {
            config.relays[0].from_address = "bogus".to_string();
        });
        assert!(result.is_err());
        assert_eq!(state.config().relays[0].from_address, "noreply@a.test");
    }

    #[test]
    fn strategy_can_be_switched_at_runtime() {
        let state = state_with(vec![relay("a")]);
        assert_eq!(state.config().routing.strategy, Strategy::RoundRobin);
        state
            .edit_config(false, |config| {
                config.routing.strategy = Strategy::LeastUsed;
            })
            .unwrap();
        assert_eq!(state.config().routing.strategy, Strategy::LeastUsed);
        assert_eq!(state.pool().routing.strategy, Strategy::LeastUsed);
    }

    #[test]
    fn routing_changes_reach_the_pool() {
        let state = state_with(vec![relay("a")]);
        state
            .edit_config(false, |config| {
                config.routing = RoutingConfig {
                    strategy: Strategy::Failover,
                    max_attempts_per_message: 5,
                    ..Default::default()
                };
            })
            .unwrap();
        assert_eq!(state.pool().routing.max_attempts_per_message, 5);
    }

    #[tokio::test]
    async fn shutdown_is_broadcast_once() {
        let state = state_with(vec![relay("a")]);
        let mut receiver = state.subscribe_shutdown();
        assert!(!state.is_shutting_down());

        state.begin_shutdown();
        state.begin_shutdown();

        assert!(state.is_shutting_down());
        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
    }
}
