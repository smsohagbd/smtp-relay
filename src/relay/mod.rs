//! Upstream relay pool, routing and delivery.

pub mod health;
pub mod pool;
pub mod selector;
pub mod sender;

/// The concrete outbound transport type used throughout the daemon.
pub type Transport = lettre::AsyncSmtpTransport<lettre::Tokio1Executor>;
