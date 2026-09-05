//! Configuration schema and loader.
//!
//! The daemon reads a single YAML (default), TOML or JSON document. Every
//! section is optional and falls back to a sane default, so a minimal file
//! containing only a `relays:` list is a valid configuration.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::util::{looks_like_email, Cidr};

/// Placeholder written in place of secrets when the configuration is exposed
/// over the admin API. A `PUT /api/config` that sends this value back is
/// interpreted as "keep the stored password".
pub const REDACTED: &str = "__redacted__";

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Root document
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub routing: RoutingConfig,
    pub rewrite: RewriteConfig,
    pub queue: QueueConfig,
    pub health: HealthConfig,
    pub admin: AdminConfig,
    pub logging: LoggingConfig,
    pub rotation: RotationConfig,
    pub relays: Vec<RelayConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            routing: RoutingConfig::default(),
            rewrite: RewriteConfig::default(),
            queue: QueueConfig::default(),
            health: HealthConfig::default(),
            admin: AdminConfig::default(),
            logging: LoggingConfig::default(),
            rotation: RotationConfig::default(),
            relays: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// server:
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Address the inbound SMTP listener binds to.
    pub bind_address: String,
    /// Name announced in the SMTP banner and in `Received` headers.
    pub hostname: String,
    /// Largest accepted `DATA` payload, advertised through the SIZE extension.
    pub max_message_size_mb: u64,
    /// Per-command idle timeout for inbound sessions.
    pub timeout_seconds: u64,
    /// Hard ceiling on simultaneously open inbound connections.
    pub max_connections: usize,
    /// Maximum `RCPT TO` commands accepted in a single transaction.
    pub max_recipients_per_message: usize,
    /// Require successful `AUTH` before `MAIL FROM` is accepted.
    pub require_auth: bool,
    /// How a message is handed to the upstream relay once `DATA` completes.
    pub submission_mode: SubmissionMode,
    /// Optional override for the 220 banner text.
    pub greeting: Option<String>,
    /// CIDRs permitted to submit mail. Empty means "accept from anywhere".
    pub allowed_networks: Vec<String>,
    /// Credentials accepted by the inbound `AUTH PLAIN` / `AUTH LOGIN`.
    pub auth_users: Vec<InboundUser>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:1025".to_string(),
            hostname: "smtp-proxy.local".to_string(),
            max_message_size_mb: 25,
            timeout_seconds: 30,
            max_connections: 512,
            max_recipients_per_message: 1000,
            require_auth: false,
            submission_mode: SubmissionMode::Queue,
            greeting: None,
            allowed_networks: Vec::new(),
            auth_users: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundUser {
    pub username: String,
    pub password: String,
}

/// Controls when the inbound session reports success to the submitting client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionMode {
    /// Accept, persist to the retry queue, deliver in the background.
    /// Highest throughput; the client always sees `250` for accepted mail.
    Queue,
    /// Deliver upstream before answering. The client sees the upstream verdict
    /// (4xx/5xx) and owns the retry, which is what Mautic expects by default.
    Direct,
    /// Try once inline; on a transient failure fall back to the retry queue and
    /// still answer `250`.
    Hybrid,
}

impl SubmissionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SubmissionMode::Queue => "queue",
            SubmissionMode::Direct => "direct",
            SubmissionMode::Hybrid => "hybrid",
        }
    }
}

// ---------------------------------------------------------------------------
// routing:
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    pub strategy: Strategy,
    /// Pin a given sender (or recipient domain) to one relay so that a campaign
    /// keeps a consistent identity.
    pub sticky: StickyMode,
    /// When a relay rejects the message, try the next eligible relay.
    pub fallback_on_failure: bool,
    /// How many distinct relays a single message may be offered to per attempt.
    pub max_attempts_per_message: usize,
    /// Force specific recipient domains onto specific relays.
    pub domain_overrides: Vec<DomainOverride>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            strategy: Strategy::RoundRobin,
            sticky: StickyMode::None,
            fallback_on_failure: true,
            max_attempts_per_message: 3,
            domain_overrides: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    /// Equal share, strict rotation.
    RoundRobin,
    /// Smooth weighted round-robin: honours `weight` as a percentage without
    /// the clustering you get from random weighted picks.
    #[serde(alias = "weighted_round_robin")]
    Weighted,
    /// Always prefer the relay that has sent the least in the current hour.
    #[serde(alias = "least_conn")]
    LeastUsed,
    /// Strict priority order; only move down the list when a relay is down.
    #[serde(alias = "priority")]
    Failover,
}

impl Strategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Strategy::RoundRobin => "round_robin",
            Strategy::Weighted => "weighted",
            Strategy::LeastUsed => "least_used",
            Strategy::Failover => "failover",
        }
    }
}

impl fmt::Display for Strategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StickyMode {
    None,
    /// Hash the original `From` address.
    Sender,
    /// Hash the first recipient's domain.
    RecipientDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainOverride {
    /// Recipient domain, e.g. `gmail.com`. `*.example.com` matches subdomains.
    pub domain: String,
    /// Relays eligible for this domain, in preference order.
    pub relay_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// rotation:
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RotationConfig {
    /// When true, inbound subject/body are replaced from templates whose
    /// `match_subject` equals the inbound Subject. Matching templates
    /// rotate round-robin. No match means the original body is kept.
    pub enabled: bool,
    pub templates: Vec<ContentTemplate>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            templates: Vec::new(),
        }
    }
}

impl RotationConfig {
    pub fn usable(&self) -> impl Iterator<Item = &ContentTemplate> {
        self.templates.iter().filter(|template| template.is_usable())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContentTemplate {
    pub id: String,
    /// Inbound Subject that selects this template (Mautic campaign subject).
    /// Compared after RFC 2047 decode, trim, and case-fold. Empty = never used.
    pub match_subject: String,
    /// Replacement Subject. Empty keeps the inbound Subject.
    pub subject: String,
    pub body: String,
}

impl Default for ContentTemplate {
    fn default() -> Self {
        Self {
            id: String::new(),
            match_subject: String::new(),
            subject: String::new(),
            body: String::new(),
        }
    }
}

impl ContentTemplate {
    pub fn is_usable(&self) -> bool {
        !self.match_subject.trim().is_empty()
            && (!self.subject.trim().is_empty() || !self.body.trim().is_empty())
    }
}

// ---------------------------------------------------------------------------
// rewrite:
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RewriteConfig {
    /// Replace the `From` address with the selected relay's identity.
    pub rewrite_from: bool,
    /// Keep the original display name when rewriting `From`.
    pub preserve_display_name: bool,
    /// Insert `Reply-To: <original From>` when the message has no `Reply-To`.
    pub inject_reply_to: bool,
    /// Used when the message has neither `Reply-To` nor a parsable `From`.
    pub reply_to_fallback: Option<String>,
    /// Remove `DKIM-Signature` / `DomainKey-Signature`; header mutation
    /// invalidates them and the upstream relay re-signs the message.
    pub strip_dkim: bool,
    /// Remove `ARC-Seal` / `ARC-Message-Signature` / `ARC-Authentication-Results`.
    pub strip_arc: bool,
    /// Remove a `Bcc` header if the submitting client left one in place.
    /// Envelope recipients are unaffected, so blind recipients still receive
    /// the message - this only stops their addresses being disclosed.
    pub strip_bcc_header: bool,
    /// Drop the inbound `Received` trace chain.
    pub strip_received: bool,
    /// Prepend our own `Received` header for traceability.
    pub add_received_header: bool,
    /// Synthesise a `Message-ID` when the client did not supply one.
    pub ensure_message_id: bool,
    /// Synthesise a `Date` when the client did not supply one.
    pub ensure_date: bool,
    /// Add `X-Relay-Node` / `X-Original-From` / `X-Queue-Id` diagnostics.
    pub add_relay_headers: bool,
    /// Value for the `X-Mailer` header; `null` leaves any existing one alone.
    pub x_mailer: Option<String>,
    /// Header names removed from every message (case-insensitive).
    pub remove_headers: Vec<String>,
    /// Headers force-set on every message.
    pub extra_headers: Vec<HeaderRule>,
}

impl Default for RewriteConfig {
    fn default() -> Self {
        Self {
            rewrite_from: true,
            preserve_display_name: true,
            inject_reply_to: false,
            reply_to_fallback: None,
            strip_dkim: false,
            strip_arc: false,
            strip_bcc_header: false,
            strip_received: false,
            add_received_header: false,
            ensure_message_id: true,
            ensure_date: true,
            add_relay_headers: false,
            x_mailer: None,
            remove_headers: Vec::new(),
            extra_headers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderRule {
    pub name: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// queue:
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueConfig {
    pub enabled: bool,
    /// Concurrent delivery workers draining the queue.
    pub workers: usize,
    /// Maximum messages held in the queue before submissions are refused.
    pub capacity: usize,
    /// Total delivery attempts before a message is marked dead.
    pub max_attempts: u32,
    pub initial_backoff_seconds: u64,
    pub backoff_multiplier: f64,
    pub max_backoff_seconds: u64,
    /// Write queued messages to disk so a restart does not lose mail.
    pub persist: bool,
    /// Spool directory used when `persist` is enabled.
    pub directory: PathBuf,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            workers: 8,
            capacity: 10_000,
            max_attempts: 5,
            initial_backoff_seconds: 30,
            backoff_multiplier: 3.0,
            max_backoff_seconds: 3_600,
            persist: true,
            directory: PathBuf::from("./spool"),
        }
    }
}

impl QueueConfig {
    /// Backoff delay before attempt number `attempt` (1-based).
    pub fn backoff_for(&self, attempt: u32) -> std::time::Duration {
        let multiplier = if self.backoff_multiplier <= 1.0 {
            1.0
        } else {
            self.backoff_multiplier
        };
        let exponent = attempt.saturating_sub(1).min(16) as f64;
        let seconds = (self.initial_backoff_seconds as f64) * multiplier.powf(exponent);
        let capped = seconds.min(self.max_backoff_seconds as f64).max(1.0);
        std::time::Duration::from_secs(capped as u64)
    }
}

// ---------------------------------------------------------------------------
// health:
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthConfig {
    pub enabled: bool,
    /// How often each relay is probed with a connect + EHLO + NOOP.
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    /// Consecutive failures that trip the circuit breaker.
    pub failure_threshold: u32,
    /// Consecutive successful probes needed to close the circuit again.
    pub success_threshold: u32,
    /// How long a tripped relay stays out of rotation before being re-probed.
    pub cooldown_seconds: u64,
    /// Trip the circuit breaker automatically on repeated delivery failures.
    pub auto_disable: bool,
    /// Bring a relay back automatically once probes succeed again.
    pub auto_recover: bool,
    /// Probe every relay once during startup.
    pub probe_on_start: bool,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 60,
            timeout_seconds: 10,
            failure_threshold: 3,
            success_threshold: 1,
            cooldown_seconds: 300,
            auto_disable: true,
            auto_recover: true,
            probe_on_start: true,
        }
    }
}

// ---------------------------------------------------------------------------
// admin:
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminConfig {
    pub enabled: bool,
    pub bind_address: String,
    /// Dashboard login name. Compared case-insensitively.
    pub username: String,
    /// Dashboard login password. When set, every client (including remote)
    /// must sign in. When empty, loopback stays open and remote clients need
    /// `api_token`.
    pub password: String,
    /// Bearer token for scripts and scrapers. Optional when `password` is set.
    pub api_token: String,
    /// Serve the bundled HTML dashboard at `/`.
    pub dashboard_enabled: bool,
    /// Permit mutating endpoints that rewrite `config.yaml` on disk.
    pub allow_config_write: bool,
    /// CIDRs permitted to reach the admin API. Empty means "no CIDR filter".
    pub allowed_networks: Vec<String>,
    /// Failed dashboard logins allowed from one IP before it is blocked.
    pub login_max_failures: u32,
    /// How long a blocked IP stays locked out.
    pub login_block_seconds: u64,
}

impl AdminConfig {
    /// A non-empty password turns the dashboard into a signed-in surface.
    pub fn login_required(&self) -> bool {
        !self.password.trim().is_empty()
    }

    /// Remote (non-loopback) clients are allowed when a dashboard password
    /// or an API token is configured.
    pub fn remote_access_configured(&self) -> bool {
        self.login_required() || !self.api_token.trim().is_empty()
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: "127.0.0.1:8025".to_string(),
            username: "admin".to_string(),
            password: String::new(),
            api_token: String::new(),
            dashboard_enabled: true,
            allow_config_write: true,
            allowed_networks: Vec::new(),
            login_max_failures: 5,
            login_block_seconds: 15 * 60,
        }
    }
}

// ---------------------------------------------------------------------------
// logging:
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// `error`, `warn`, `info`, `debug`, `trace`, or a full `RUST_LOG` filter.
    pub level: String,
    pub format: LogFormat,
    /// Directory for rolling daily log files. `null` logs to stdout only.
    pub directory: Option<PathBuf>,
    /// Base filename used inside `directory`.
    pub file_prefix: String,
    /// Log the full rewritten header block at debug level. Verbose; useful when
    /// diagnosing SPF/DKIM alignment problems.
    pub log_headers: bool,
    /// Capture each inbound MIME (the bytes Mautic actually submitted).
    /// Recent dumps stay in the dashboard; if `directory` is set they are
    /// also written as `{directory}/inbound/{id}.eml`.
    pub dump_inbound: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Text,
            directory: None,
            file_prefix: "smtp-relay".to_string(),
            log_headers: false,
            dump_inbound: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[serde(alias = "plain")]
    Text,
    Compact,
    Json,
}

// ---------------------------------------------------------------------------
// relays:
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayConfig {
    /// Stable identifier used by the API, dashboard and logs.
    pub id: String,
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    /// Envelope sender and `From` address applied to messages on this relay.
    /// Ignored when `from_same_as_username` is on and the SMTP username is an
    /// email address.
    pub from_address: String,
    /// When true, `from_address` is copied from `auth.username`.
    #[serde(default = "default_true")]
    pub from_same_as_username: bool,
    /// When true, SMTP `MAIL FROM` is rewritten to the relay From address
    /// (SPF alignment). Sending-as-username already rewrites MAIL FROM even
    /// when this is false, because authenticated hosts reject a foreign
    /// envelope sender. Uncheck only for a custom From that must keep the
    /// original bounce path.
    #[serde(default = "default_true")]
    pub align_envelope: bool,
    /// Relative share of traffic for the `weighted` strategy.
    pub weight: u32,
    /// Preference order for the `failover` strategy (lower wins).
    pub priority: u32,
    /// Configured on/off state. Toggled live from the dashboard and persisted.
    pub enabled: bool,
    /// Per-minute send cap; unset means unlimited.
    pub max_per_minute: Option<u64>,
    /// Hourly send cap; the relay leaves rotation once reached.
    pub max_per_hour: Option<u64>,
    /// Daily send cap (UTC day boundary).
    pub max_per_day: Option<u64>,
    /// Simultaneous deliveries allowed against this relay.
    pub max_concurrent: usize,
    /// Overrides `server.timeout_seconds` for this upstream.
    pub timeout_seconds: Option<u64>,
    /// EHLO name presented to the upstream relay.
    pub helo_name: Option<String>,
    /// Skip certificate verification. Only for test upstreams.
    pub allow_invalid_certs: bool,
    pub description: Option<String>,
    /// Free-form labels, filterable in the dashboard.
    pub tags: Vec<String>,
    /// SMTP credentials. Omit for an unauthenticated upstream.
    pub auth: Option<AuthConfig>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            host: String::new(),
            port: 465,
            tls: TlsMode::Tls,
            from_address: String::new(),
            from_same_as_username: true,
            align_envelope: true,
            weight: 1,
            priority: 100,
            enabled: true,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
            max_concurrent: 8,
            timeout_seconds: None,
            helo_name: None,
            allow_invalid_certs: false,
            description: None,
            tags: Vec::new(),
            auth: None,
        }
    }
}

impl RelayConfig {
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Address used in the rewritten `From` header.
    ///
    /// When `from_same_as_username` is on and the SMTP login looks like an
    /// email, that login wins so the operator does not have to type it twice.
    pub fn effective_from_address(&self) -> String {
        if self.from_same_as_username {
            if let Some(auth) = &self.auth {
                let username = auth.username.trim();
                if looks_like_email(username) {
                    return username.to_string();
                }
            }
        }
        self.from_address.trim().to_string()
    }

    /// Fills `from_address` from the username when the checkbox is on.
    pub fn sync_from_identity(&mut self) {
        if self.from_same_as_username {
            if let Some(auth) = &self.auth {
                let username = auth.username.trim();
                if looks_like_email(username) {
                    self.from_address = username.to_string();
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
    /// `plain`, `login` or `xoauth2`. Defaults to offering PLAIN then LOGIN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Plaintext. Never use across an untrusted network.
    #[serde(alias = "plain", alias = "false")]
    None,
    /// Connect in the clear, then upgrade with `STARTTLS`. Required. (port 587)
    #[serde(rename = "starttls", alias = "start_tls", alias = "true")]
    StartTls,
    /// TLS from the first byte. (port 465)
    #[serde(alias = "smtps", alias = "ssl", alias = "implicit", alias = "wrapper")]
    Tls,
    /// Upgrade when offered, continue in the clear otherwise.
    #[serde(alias = "auto")]
    Opportunistic,
}

impl Default for TlsMode {
    fn default() -> Self {
        TlsMode::StartTls
    }
}

impl TlsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TlsMode::None => "none",
            TlsMode::StartTls => "starttls",
            TlsMode::Tls => "tls",
            TlsMode::Opportunistic => "opportunistic",
        }
    }
}

// ---------------------------------------------------------------------------
// Loading, saving, validation
// ---------------------------------------------------------------------------

/// Serialisation formats accepted for the configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Yaml,
    Toml,
    Json,
}

impl Format {
    pub fn from_path(path: &Path) -> Option<Self> {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref()
        {
            Some("yaml") | Some("yml") => Some(Format::Yaml),
            Some("toml") => Some(Format::Toml),
            Some("json") => Some(Format::Json),
            _ => None,
        }
    }
}

impl Config {
    /// Reads and validates the configuration at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }
        let format =
            Format::from_path(path).ok_or_else(|| ConfigError::UnknownFormat(path.to_path_buf()))?;
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let config: Config = match format {
            Format::Yaml => serde_yaml::from_str(&text).map_err(|e| ConfigError::Parse {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?,
            Format::Toml => toml::from_str(&text).map_err(|e| ConfigError::Parse {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?,
            Format::Json => serde_json::from_str(&text).map_err(|e| ConfigError::Parse {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?,
        };

        config.validate()?;
        Ok(config)
    }

    /// Serialises the configuration in the format implied by `path`.
    pub fn serialize_for(&self, path: &Path) -> Result<String, ConfigError> {
        let format = Format::from_path(path).unwrap_or(Format::Yaml);
        match format {
            Format::Yaml => {
                serde_yaml::to_string(self).map_err(|e| ConfigError::Serialize(e.to_string()))
            }
            Format::Toml => toml::to_string_pretty(self)
                .map_err(|e| ConfigError::Serialize(e.to_string())),
            Format::Json => serde_json::to_string_pretty(self)
                .map_err(|e| ConfigError::Serialize(e.to_string())),
        }
    }

    /// Atomically rewrites the configuration file, keeping a `.bak` copy.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        let rendered = self.serialize_for(path)?;

        if path.exists() {
            let backup = path.with_extension(format!(
                "{}.bak",
                path.extension().and_then(|e| e.to_str()).unwrap_or("conf")
            ));
            let _ = std::fs::copy(path, backup);
        }

        let temp = path.with_extension("tmp-write");
        std::fs::write(&temp, rendered.as_bytes()).map_err(|source| ConfigError::Io {
            path: temp.clone(),
            source,
        })?;
        std::fs::rename(&temp, path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    pub fn max_message_size_bytes(&self) -> usize {
        (self.server.max_message_size_mb.max(1) * 1024 * 1024) as usize
    }

    pub fn relay(&self, id: &str) -> Option<&RelayConfig> {
        self.relays.iter().find(|r| r.id == id)
    }

    pub fn relay_mut(&mut self, id: &str) -> Option<&mut RelayConfig> {
        self.relays.iter_mut().find(|r| r.id == id)
    }

    /// Copy with every secret replaced by [`REDACTED`], safe to hand to the API.
    pub fn redacted(&self) -> Self {
        let mut clone = self.clone();
        for relay in &mut clone.relays {
            if let Some(auth) = &mut relay.auth {
                auth.password = REDACTED.to_string();
            }
        }
        for user in &mut clone.server.auth_users {
            user.password = REDACTED.to_string();
        }
        if !clone.admin.api_token.is_empty() {
            clone.admin.api_token = REDACTED.to_string();
        }
        if !clone.admin.password.is_empty() {
            clone.admin.password = REDACTED.to_string();
        }
        clone
    }

    /// Restores secrets that arrived from the API as [`REDACTED`] using the
    /// values held in `previous`, so a dashboard save never wipes passwords.
    pub fn restore_secrets_from(&mut self, previous: &Config) {
        for relay in &mut self.relays {
            let Some(auth) = &mut relay.auth else { continue };
            if auth.password != REDACTED {
                continue;
            }
            if let Some(old) = previous
                .relay(&relay.id)
                .and_then(|r| r.auth.as_ref())
                .filter(|old| old.username == auth.username)
            {
                auth.password = old.password.clone();
            }
        }

        let old_users: BTreeMap<&str, &str> = previous
            .server
            .auth_users
            .iter()
            .map(|u| (u.username.as_str(), u.password.as_str()))
            .collect();
        for user in &mut self.server.auth_users {
            if user.password == REDACTED {
                if let Some(old) = old_users.get(user.username.as_str()) {
                    user.password = (*old).to_string();
                }
            }
        }

        if self.admin.api_token == REDACTED {
            self.admin.api_token = previous.admin.api_token.clone();
        }
        if self.admin.password == REDACTED {
            self.admin.password = previous.admin.password.clone();
        }
    }

    /// Parsed inbound allow-list. Invalid entries are rejected by `validate`.
    pub fn inbound_networks(&self) -> Vec<Cidr> {
        self.server
            .allowed_networks
            .iter()
            .filter_map(|s| Cidr::parse(s).ok())
            .collect()
    }

    pub fn admin_networks(&self) -> Vec<Cidr> {
        self.admin
            .allowed_networks
            .iter()
            .filter_map(|s| Cidr::parse(s).ok())
            .collect()
    }

    /// Rejects configurations that would misroute or silently drop mail.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| ConfigError::Invalid(msg);

        self.server
            .bind_address
            .parse::<SocketAddr>()
            .map_err(|_| {
                invalid(format!(
                    "server.bind_address `{}` is not a valid socket address (expected e.g. 0.0.0.0:1025)",
                    self.server.bind_address
                ))
            })?;

        if self.admin.enabled {
            self.admin.bind_address.parse::<SocketAddr>().map_err(|_| {
                invalid(format!(
                    "admin.bind_address `{}` is not a valid socket address",
                    self.admin.bind_address
                ))
            })?;
        }

        if self.server.hostname.trim().is_empty() {
            return Err(invalid("server.hostname must not be empty".to_string()));
        }
        if self.server.max_message_size_mb == 0 {
            return Err(invalid(
                "server.max_message_size_mb must be at least 1".to_string(),
            ));
        }
        if self.server.timeout_seconds == 0 {
            return Err(invalid(
                "server.timeout_seconds must be at least 1".to_string(),
            ));
        }
        if self.server.max_connections == 0 {
            return Err(invalid(
                "server.max_connections must be at least 1".to_string(),
            ));
        }
        if self.server.require_auth && self.server.auth_users.is_empty() {
            return Err(invalid(
                "server.require_auth is enabled but server.auth_users is empty, so no client could ever submit mail"
                    .to_string(),
            ));
        }
        for user in &self.server.auth_users {
            if user.username.is_empty() || user.password.is_empty() {
                return Err(invalid(
                    "server.auth_users entries need a non-empty username and password".to_string(),
                ));
            }
        }

        for entry in &self.server.allowed_networks {
            Cidr::parse(entry)
                .map_err(|e| invalid(format!("server.allowed_networks: {e}")))?;
        }
        for entry in &self.admin.allowed_networks {
            Cidr::parse(entry).map_err(|e| invalid(format!("admin.allowed_networks: {e}")))?;
        }

        if self.routing.max_attempts_per_message == 0 {
            return Err(invalid(
                "routing.max_attempts_per_message must be at least 1".to_string(),
            ));
        }

        let mut seen_ids = BTreeMap::new();
        for (index, relay) in self.relays.iter().enumerate() {
            let label = if relay.id.is_empty() {
                format!("relays[{index}]")
            } else {
                format!("relay `{}`", relay.id)
            };

            if relay.id.trim().is_empty() {
                return Err(invalid(format!("{label} is missing an `id`")));
            }
            if relay.id.contains('/') || relay.id.contains(char::is_whitespace) {
                return Err(invalid(format!(
                    "{label}: ids must not contain whitespace or `/`"
                )));
            }
            if let Some(first) = seen_ids.insert(relay.id.clone(), index) {
                return Err(invalid(format!(
                    "duplicate relay id `{}` (relays[{}] and relays[{}])",
                    relay.id, first, index
                )));
            }
            if relay.host.trim().is_empty() {
                return Err(invalid(format!("{label} is missing a `host`")));
            }
            if relay.port == 0 {
                return Err(invalid(format!("{label}: port must be 1-65535")));
            }
            if !looks_like_email(&relay.effective_from_address()) {
                return Err(invalid(format!(
                    "{label}: from_address `{}` is not a valid email address (set from_address, or enable from_same_as_username with an email username)",
                    relay.effective_from_address()
                )));
            }
            if relay.max_concurrent == 0 {
                return Err(invalid(format!("{label}: max_concurrent must be at least 1")));
            }
            if let Some(auth) = &relay.auth {
                if auth.username.is_empty() {
                    return Err(invalid(format!(
                        "{label}: auth.username must not be empty (remove the `auth` block for an unauthenticated relay)"
                    )));
                }
                if let Some(mechanism) = &auth.mechanism {
                    let mech = mechanism.to_ascii_lowercase();
                    if !matches!(mech.as_str(), "plain" | "login" | "xoauth2") {
                        return Err(invalid(format!(
                            "{label}: auth.mechanism `{mechanism}` is not supported (use plain, login or xoauth2)"
                        )));
                    }
                }
            }
            if relay.tls == TlsMode::None && relay.auth.is_some() {
                tracing::warn!(
                    relay = %relay.id,
                    "relay sends credentials over an unencrypted connection (tls: none)"
                );
            }
        }

        if self.routing.strategy == Strategy::Weighted {
            let total: u64 = self
                .relays
                .iter()
                .filter(|r| r.enabled)
                .map(|r| r.weight as u64)
                .sum();
            if total == 0 {
                return Err(invalid(
                    "routing.strategy is `weighted` but every enabled relay has weight 0"
                        .to_string(),
                ));
            }
        }

        for override_rule in &self.routing.domain_overrides {
            if override_rule.domain.trim().is_empty() {
                return Err(invalid(
                    "routing.domain_overrides entries need a `domain`".to_string(),
                ));
            }
            if override_rule.relay_ids.is_empty() {
                return Err(invalid(format!(
                    "routing.domain_overrides for `{}` lists no relay_ids",
                    override_rule.domain
                )));
            }
            for id in &override_rule.relay_ids {
                if !seen_ids.contains_key(id) {
                    return Err(invalid(format!(
                        "routing.domain_overrides for `{}` references unknown relay `{}`",
                        override_rule.domain, id
                    )));
                }
            }
        }

        if self.queue.enabled {
            if self.queue.workers == 0 {
                return Err(invalid("queue.workers must be at least 1".to_string()));
            }
            if self.queue.capacity == 0 {
                return Err(invalid("queue.capacity must be at least 1".to_string()));
            }
            if self.queue.max_attempts == 0 {
                return Err(invalid("queue.max_attempts must be at least 1".to_string()));
            }
        }

        if self.server.submission_mode != SubmissionMode::Direct && !self.queue.enabled {
            return Err(invalid(format!(
                "server.submission_mode is `{}` which requires queue.enabled: true",
                self.server.submission_mode.as_str()
            )));
        }

        if self.health.enabled && self.health.interval_seconds == 0 {
            return Err(invalid(
                "health.interval_seconds must be at least 1".to_string(),
            ));
        }

        if let Some(fallback) = &self.rewrite.reply_to_fallback {
            if !looks_like_email(fallback) {
                return Err(invalid(format!(
                    "rewrite.reply_to_fallback `{fallback}` is not a valid email address"
                )));
            }
        }

        let mut seen_templates = BTreeMap::new();
        for (index, template) in self.rotation.templates.iter().enumerate() {
            let id = template.id.trim();
            if id.is_empty() {
                continue;
            }
            if let Some(first) = seen_templates.insert(id.to_string(), index) {
                return Err(invalid(format!(
                    "duplicate rotation template id `{id}` (templates[{first}] and templates[{index}])"
                )));
            }
        }

        Ok(())
    }

    /// Fully-commented starter configuration emitted by `--generate-config`.
    pub fn example_yaml() -> &'static str {
        include_str!("../config.example.yaml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_relay(id: &str) -> RelayConfig {
        RelayConfig {
            id: id.to_string(),
            host: format!("smtp.{id}.com"),
            from_address: format!("noreply@{id}.com"),
            ..Default::default()
        }
    }

    fn base_config() -> Config {
        Config {
            relays: vec![base_relay("one")],
            ..Default::default()
        }
    }

    #[test]
    fn defaults_validate_with_one_relay() {
        base_config().validate().expect("should be valid");
    }

    #[test]
    fn empty_relay_list_is_allowed() {
        let config = Config::default();
        config
            .validate()
            .expect("a fresh install with no relays must be valid so they can be added from the dashboard");
    }

    #[test]
    fn duplicate_relay_ids_are_rejected() {
        let mut config = base_config();
        config.relays.push(base_relay("one"));
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate relay id"), "{err}");
    }

    #[test]
    fn bad_from_address_is_rejected() {
        let mut config = base_config();
        config.relays[0].from_address = "not-an-email".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn weighted_strategy_needs_nonzero_weight() {
        let mut config = base_config();
        config.routing.strategy = Strategy::Weighted;
        config.relays[0].weight = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn unknown_override_target_is_rejected() {
        let mut config = base_config();
        config.routing.domain_overrides.push(DomainOverride {
            domain: "gmail.com".to_string(),
            relay_ids: vec!["missing".to_string()],
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn from_can_come_from_username() {
        let mut config = base_config();
        config.relays[0].from_address.clear();
        config.relays[0].from_same_as_username = true;
        config.relays[0].auth = Some(AuthConfig {
            username: "mailer@one.com".to_string(),
            password: "secret".to_string(),
            mechanism: None,
        });
        config.validate().expect("username is a valid from address");
        assert_eq!(
            config.relays[0].effective_from_address(),
            "mailer@one.com"
        );
    }

    #[test]
    fn yaml_round_trips_through_all_formats() {
        let config = base_config();
        for path in ["c.yaml", "c.toml", "c.json"] {
            let path = Path::new(path);
            let text = config.serialize_for(path).expect("serialise");
            let parsed: Config = match Format::from_path(path).unwrap() {
                Format::Yaml => serde_yaml::from_str(&text).unwrap(),
                Format::Toml => toml::from_str(&text).unwrap(),
                Format::Json => serde_json::from_str(&text).unwrap(),
            };
            assert_eq!(parsed.relays.len(), 1);
            assert_eq!(parsed.relays[0].id, "one");
            parsed.validate().expect("round-tripped config is valid");
        }
    }

    #[test]
    fn user_schema_from_the_brief_parses() {
        let yaml = r#"
server:
  bind_address: "0.0.0.0:2525"
  hostname: "smtp-proxy.local"
  max_message_size_mb: 25
  timeout_seconds: 30

routing:
  strategy: "weighted"

relays:
  - id: "relay_node_1"
    host: "smtp.domain1.com"
    port: 587
    tls: "starttls"
    auth:
      username: "mailer@domain1.com"
      password: "secret_password_1"
    from_address: "noreply@domain1.com"
    weight: 40

  - id: "relay_node_2"
    host: "smtp.domain2.com"
    port: 587
    tls: "starttls"
    auth:
      username: "mailer@domain2.com"
      password: "secret_password_2"
    from_address: "newsletter@domain2.com"
    weight: 60
"#;
        let config: Config = serde_yaml::from_str(yaml).expect("parses");
        config.validate().expect("valid");
        assert_eq!(config.routing.strategy, Strategy::Weighted);
        assert_eq!(config.relays.len(), 2);
        assert_eq!(config.relays[1].weight, 60);
        assert_eq!(config.relays[0].tls, TlsMode::StartTls);
        assert_eq!(
            config.relays[0].auth.as_ref().unwrap().password,
            "secret_password_1"
        );
    }

    #[test]
    fn redaction_hides_and_restores_secrets() {
        let mut config = base_config();
        config.relays[0].auth = Some(AuthConfig {
            username: "u".to_string(),
            password: "real-secret".to_string(),
            mechanism: None,
        });

        let mut redacted = config.redacted();
        assert_eq!(redacted.relays[0].auth.as_ref().unwrap().password, REDACTED);

        redacted.restore_secrets_from(&config);
        assert_eq!(
            redacted.relays[0].auth.as_ref().unwrap().password,
            "real-secret"
        );
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let queue = QueueConfig {
            initial_backoff_seconds: 30,
            backoff_multiplier: 3.0,
            max_backoff_seconds: 600,
            ..Default::default()
        };
        assert_eq!(queue.backoff_for(1).as_secs(), 30);
        assert_eq!(queue.backoff_for(2).as_secs(), 90);
        assert_eq!(queue.backoff_for(3).as_secs(), 270);
        assert_eq!(queue.backoff_for(9).as_secs(), 600);
    }
}
