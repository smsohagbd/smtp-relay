//! Structured logging setup.

use std::io::IsTerminal;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer, Registry};

use crate::config::{LogFormat, LoggingConfig};

/// Boxed layer alias; the layer set is assembled at runtime from config.
type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

/// Installs the global subscriber.
///
/// The returned guard must be kept alive for the lifetime of the process: it
/// owns the background thread that flushes the log file. Dropping it early
/// silently loses buffered lines.
pub fn init(config: &LoggingConfig) -> Option<WorkerGuard> {
    let filter = build_filter(&config.level);
    let mut layers: Vec<BoxedLayer> = Vec::new();

    // `RUST_LOG` still wins, so an operator can raise verbosity without
    // touching the configuration file.
    let ansi = std::io::stdout().is_terminal();
    layers.push(match config.format {
        LogFormat::Text => Box::new(
            fmt::layer()
                .with_ansi(ansi)
                .with_target(true)
                .with_level(true),
        ),
        LogFormat::Compact => Box::new(fmt::layer().with_ansi(ansi).compact()),
        LogFormat::Json => Box::new(fmt::layer().json().flatten_event(true)),
    });

    let mut guard = None;
    if let Some(directory) = &config.directory {
        match std::fs::create_dir_all(directory) {
            Ok(()) => {
                let appender = tracing_appender::rolling::daily(directory, &config.file_prefix);
                let (writer, worker) = tracing_appender::non_blocking(appender);
                guard = Some(worker);

                // Files are always machine-readable and never coloured.
                layers.push(Box::new(
                    fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_ansi(false)
                        .with_writer(writer),
                ));
            }
            Err(error) => {
                eprintln!(
                    "warning: could not create the log directory {}: {error}",
                    directory.display()
                );
            }
        }
    }

    Registry::default().with(layers).with(filter).init();
    guard
}

/// `RUST_LOG` wins over the configuration file, so an operator can raise
/// verbosity without editing config.
fn build_filter(level: &str) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| filter_from_config(level))
}

/// Accepts either a bare level (`info`) or a full filter expression
/// (`smtp_relay=debug,lettre=warn`).
fn filter_from_config(level: &str) -> EnvFilter {
    EnvFilter::try_new(level).unwrap_or_else(|_| {
        eprintln!("warning: `{level}` is not a valid log filter; falling back to `info`");
        EnvFilter::new("info")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_levels_and_full_filters_both_parse() {
        for level in ["error", "warn", "info", "debug", "trace"] {
            assert_eq!(filter_from_config(level).to_string(), level);
        }
        let rendered = filter_from_config("smtp_relay=debug,lettre=warn").to_string();
        assert!(rendered.contains("smtp_relay=debug"), "{rendered}");
        assert!(rendered.contains("lettre=warn"), "{rendered}");
    }

    #[test]
    fn an_invalid_filter_falls_back_to_info() {
        assert_eq!(filter_from_config("=!=nonsense=!=").to_string(), "info");
    }
}
