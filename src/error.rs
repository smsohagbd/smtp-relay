//! Error types shared across the daemon.

use std::fmt;
use std::path::PathBuf;

/// Errors raised while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("configuration file `{0}` was not found")]
    NotFound(PathBuf),

    #[error("failed to read `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("unsupported configuration format for `{0}` (expected .yaml, .yml, .toml or .json)")]
    UnknownFormat(PathBuf),

    #[error("failed to parse `{path}`: {message}")]
    Parse { path: PathBuf, message: String },

    #[error("failed to serialise configuration: {0}")]
    Serialize(String),

    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Errors raised while rewriting an RFC 5322 message.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("message has no header/body separator (malformed RFC 5322 message)")]
    NoHeaderSeparator,
}

/// Reason a delivery attempt failed, used to decide whether to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// 4xx / connection level problem: worth retrying later.
    Transient,
    /// 5xx / malformed message: retrying will not help.
    Permanent,
}

impl FailureKind {
    pub fn is_transient(self) -> bool {
        matches!(self, FailureKind::Transient)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FailureKind::Transient => "transient",
            FailureKind::Permanent => "permanent",
        }
    }
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A delivery failure with its classification.
#[derive(Debug, Clone)]
pub struct DeliveryError {
    pub kind: FailureKind,
    pub message: String,
    pub status_code: Option<u16>,
}

impl DeliveryError {
    pub fn transient(message: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Transient,
            message: message.into(),
            status_code: None,
        }
    }

    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Permanent,
            message: message.into(),
            status_code: None,
        }
    }

    pub fn with_status(mut self, code: u16) -> Self {
        self.status_code = Some(code);
        self
    }

    /// True when the failure is the relay's fault rather than the message's.
    ///
    /// This is the distinction that matters operationally: a bad password or a
    /// refused connection should take the relay out of rotation and send the
    /// message somewhere else, whereas `550 unknown recipient` should not
    /// penalise the relay and must not be retried anywhere.
    pub fn is_relay_fault(&self) -> bool {
        match self.status_code {
            // No status code means we never got a usable SMTP reply: DNS,
            // TCP, TLS or timeout - all relay-side.
            None => true,
            // Every 4xx is by definition "try again later".
            Some(code) if (400..500).contains(&code) => true,
            // Authentication and command-level rejections indicate the
            // relay configuration is wrong, not the message.
            Some(530) | Some(534) | Some(535) | Some(538) => true,
            Some(code) if (500..=504).contains(&code) => true,
            _ => false,
        }
    }

    /// True when another delivery attempt (here or on a different relay) is
    /// worth making.
    pub fn should_retry(&self) -> bool {
        self.kind.is_transient() || self.is_relay_fault()
    }
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status_code {
            Some(code) => write!(f, "[{}/{}] {}", self.kind, code, self.message),
            None => write!(f, "[{}] {}", self.kind, self.message),
        }
    }
}

impl std::error::Error for DeliveryError {}
