//! smtp-relay - asynchronous SMTP proxy and load-balancing relay daemon.
//!
//! Startup order matters: the configuration is read and validated before any
//! socket is bound, so a bad file fails fast with a readable message instead
//! of a half-started daemon. Once the listeners are up, every long-running
//! task watches the same shutdown channel, which is what makes `SIGTERM`
//! deterministic.

mod admin;
mod config;
mod dispatch;
mod error;
mod events;
mod logging;
mod message;
mod metrics;
mod queue;
mod relay;
mod smtp;
mod state;
mod util;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::state::{AppState, VERSION};

/// Candidate locations tried when `--config` is not given.
const CONFIG_CANDIDATES: &[&str] = &[
    "config.yaml",
    "config.yml",
    "config.toml",
    "config.json",
    "/etc/smtp-relay/config.yaml",
    "/etc/smtp-relay/config.yml",
];

const USAGE: &str = "\
smtp-relay - asynchronous SMTP proxy and load-balancing relay

USAGE:
    smtp-relay [OPTIONS]

OPTIONS:
    -c, --config <PATH>       Configuration file (.yaml, .yml, .toml, .json).
                              Defaults to $SMTP_RELAY_CONFIG, then ./config.yaml,
                              then /etc/smtp-relay/config.yaml.
        --check               Validate the configuration and exit.
        --print-config        Print the effective configuration (secrets
                              redacted) and exit.
        --generate-config [PATH]
                              Write a fully commented starter configuration
                              (default: ./config.yaml) and exit.
        --force               Allow --generate-config to overwrite an existing
                              file.
        --probe               Connect to every configured relay, report the
                              result and exit. Useful as a deployment check.
    -V, --version             Print the version and exit.
    -h, --help                Print this help and exit.

ENVIRONMENT:
    SMTP_RELAY_CONFIG         Default configuration path.
    RUST_LOG                  Overrides `logging.level` from the configuration.
";

fn main() -> ExitCode {
    let options = match Options::parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("smtp-relay: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    if options.help {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    if options.version {
        println!("smtp-relay {VERSION}");
        return ExitCode::SUCCESS;
    }

    if let Some(target) = options.generate_config {
        return match generate_config(&target, options.force) {
            Ok(path) => {
                println!("wrote starter configuration to {}", path.display());
                println!("edit the `relays:` section, then start the daemon.");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("smtp-relay: {message}");
                ExitCode::FAILURE
            }
        };
    }

    let Some(path) = resolve_config_path(options.config.clone()) else {
        eprintln!(
            "smtp-relay: no configuration file found.\n\
             Looked for: {}\n\
             Run `smtp-relay --generate-config` to create one, or pass --config <PATH>.",
            CONFIG_CANDIDATES.join(", ")
        );
        return ExitCode::FAILURE;
    };

    // Loading validates, so `--check` needs nothing beyond this call.
    let config = match Config::load(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("smtp-relay: {} is not usable: {error}", path.display());
            return ExitCode::FAILURE;
        }
    };

    if options.check {
        println!(
            "{} is valid: {} relay(s), strategy `{}`, listener {}",
            path.display(),
            config.relays.len(),
            config.routing.strategy,
            config.server.bind_address
        );
        return ExitCode::SUCCESS;
    }

    if options.print_config {
        match config.redacted().serialize_for(Path::new("config.yaml")) {
            Ok(text) => {
                print!("{text}");
                return ExitCode::SUCCESS;
            }
            Err(error) => {
                eprintln!("smtp-relay: could not render configuration: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    // The guard flushes the file appender on drop, so it has to outlive the
    // runtime rather than the setup function.
    let _log_guard = logging::init(&config.logging);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("smtp-relay")
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("smtp-relay: could not start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(async move {
        if options.probe {
            probe_and_report(config, path).await
        } else {
            serve(config, path).await
        }
    })
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

async fn serve(config: Config, path: PathBuf) -> ExitCode {
    let smtp_bind = config.server.bind_address.clone();
    let admin_bind = config.admin.bind_address.clone();
    let admin_enabled = config.admin.enabled;
    let queue_enabled = config.queue.enabled;
    let workers = config.queue.workers.max(1);
    let shutdown_grace = Duration::from_secs(config.server.timeout_seconds.clamp(5, 120));

    let state = match AppState::new(config, path.clone()) {
        Ok(state) => state,
        Err(message) => {
            tracing::error!("could not initialise runtime state: {message}");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        version = VERSION,
        config = %path.display(),
        relays = state.pool().len(),
        strategy = %state.config().routing.strategy,
        "smtp-relay starting"
    );

    if state.queue.is_persistent() {
        let recovered = state.queue.recover();
        if recovered > 0 {
            tracing::info!(recovered, "restored spooled messages from the last run");
        }
    } else if queue_enabled {
        tracing::warn!(
            "queue.persist is disabled: messages waiting for a retry are lost on restart"
        );
    }

    warn_about_exposure(&state);

    // Background workers first: they only watch shared state, so they are safe
    // to start before anything can be accepted.
    let mut background = Vec::new();
    background.push(tokio::spawn(relay::health::run(Arc::clone(&state))));
    background.push(tokio::spawn(relay::health::run_stats_ticker(Arc::clone(
        &state,
    ))));
    if queue_enabled {
        for worker in 0..workers {
            background.push(tokio::spawn(dispatch::run_queue_worker(
                Arc::clone(&state),
                worker,
            )));
        }
        tracing::info!(workers, "queue workers started");
    } else {
        tracing::info!("retry queue disabled: deliveries are attempted inline only");
    }

    // Listeners. A bind failure has to be fatal, which is why their results
    // are selected on rather than ignored.
    let mut smtp_task = tokio::spawn(smtp::run(Arc::clone(&state)));
    let mut admin_task = tokio::spawn(admin::run(Arc::clone(&state)));

    let mut exit = ExitCode::SUCCESS;

    tokio::select! {
        result = &mut smtp_task => {
            exit = report_listener_exit("SMTP listener", &smtp_bind, result);
        }
        result = &mut admin_task, if admin_enabled => {
            exit = report_listener_exit("admin API", &admin_bind, result);
        }
        signal = wait_for_signal(&state) => {
            tracing::info!(signal, "shutdown requested");
        }
    }

    state.begin_shutdown();
    finish_in_flight(&state, shutdown_grace).await;

    // Both listeners stop on the shutdown watch; abort only covers the case
    // where one of them is wedged in a syscall.
    smtp_task.abort();
    admin_task.abort();
    for task in background {
        task.abort();
    }

    let counters = state.metrics.counters.snapshot();
    tracing::info!(
        received = counters.messages_received,
        delivered = counters.messages_delivered,
        failed = counters.messages_failed,
        queue_depth = state.queue.depth(),
        uptime_seconds = state.uptime_seconds(),
        "smtp-relay stopped"
    );

    exit
}

/// Maps a listener task result onto an exit code. A listener that returns on
/// its own before shutdown was requested is always an error.
fn report_listener_exit(
    what: &str,
    bind: &str,
    result: Result<std::io::Result<()>, tokio::task::JoinError>,
) -> ExitCode {
    match result {
        Ok(Ok(())) => {
            tracing::error!(%bind, "{what} stopped unexpectedly");
            ExitCode::FAILURE
        }
        Ok(Err(error)) => {
            tracing::error!(%bind, "{what} failed: {error}");
            ExitCode::FAILURE
        }
        Err(error) => {
            tracing::error!(%bind, "{what} task panicked: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Waits for open sessions and in-flight upstream deliveries to settle.
///
/// Queue workers stop claiming new messages as soon as shutdown is signalled,
/// so anything still queued stays on the spool for the next start; this only
/// waits for work that is already on the wire.
async fn finish_in_flight(state: &Arc<AppState>, grace: Duration) {
    let deadline = Instant::now() + grace;

    loop {
        let sending = state.queue.in_flight();
        let sessions = state
            .metrics
            .counters
            .connections_active
            .load(std::sync::atomic::Ordering::Relaxed);

        if sending == 0 && sessions == 0 {
            break;
        }

        if Instant::now() >= deadline {
            tracing::warn!(
                deliveries_in_flight = sending,
                open_sessions = sessions,
                grace_seconds = grace.as_secs(),
                "shutdown grace period expired, dropping remaining work"
            );
            break;
        }

        tracing::debug!(
            deliveries_in_flight = sending,
            open_sessions = sessions,
            "waiting for in-flight work"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let remaining = state.queue.depth();
    if remaining > 0 {
        if state.queue.is_persistent() {
            tracing::info!(remaining, "queued messages left on the spool for restart");
        } else {
            tracing::error!(
                remaining,
                "queued messages discarded: queue.persist is disabled"
            );
        }
    }
}

/// Points out the two configurations that turn this daemon into an open relay.
fn warn_about_exposure(state: &Arc<AppState>) {
    let config = state.config();

    let smtp_public = config.server.bind_address.starts_with("0.0.0.0")
        || config.server.bind_address.starts_with("[::]");
    if smtp_public && config.server.allowed_networks.is_empty() && !config.server.require_auth {
        tracing::warn!(
            bind = %config.server.bind_address,
            "inbound listener accepts mail from any host: set server.allowed_networks \
             or server.require_auth before exposing it"
        );
    }

    if config.admin.enabled && config.admin.api_token.is_empty() {
        let loopback = config.admin.bind_address.starts_with("127.")
            || config.admin.bind_address.starts_with("[::1]");
        if loopback {
            tracing::info!(
                bind = %config.admin.bind_address,
                "admin API has no token: only loopback clients are accepted"
            );
        } else {
            tracing::warn!(
                bind = %config.admin.bind_address,
                "admin API is bound off-loopback without admin.api_token: remote requests \
                 will be refused until a token is set"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// --probe
// ---------------------------------------------------------------------------

async fn probe_and_report(config: Config, path: PathBuf) -> ExitCode {
    let state = match AppState::new(config, path) {
        Ok(state) => state,
        Err(message) => {
            eprintln!("smtp-relay: {message}");
            return ExitCode::FAILURE;
        }
    };

    let mut results = relay::health::probe_all(&state).await;
    results.sort_by(|left, right| left.relay_id.cmp(&right.relay_id));

    let width = results
        .iter()
        .map(|result| result.relay_id.len())
        .max()
        .unwrap_or(0)
        .max(5);

    let mut failed = 0;
    for result in &results {
        let relay = state.config().relay(&result.relay_id).cloned();
        let endpoint = relay
            .map(|relay| format!("{}:{}", relay.host, relay.port))
            .unwrap_or_default();

        if result.ok {
            println!(
                "{:width$}  ok      {:>5} ms  {endpoint}",
                result.relay_id,
                result.latency_ms.unwrap_or(0),
                width = width
            );
        } else {
            failed += 1;
            println!(
                "{:width$}  FAILED            {endpoint}  {}",
                result.relay_id,
                result.error.as_deref().unwrap_or("unknown error"),
                width = width
            );
        }
    }

    println!(
        "\n{} of {} relay(s) reachable",
        results.len() - failed,
        results.len()
    );

    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

/// Resolves when the process should stop. `SIGHUP` reloads the configuration
/// in place instead, which is the conventional behaviour for a daemon.
#[cfg(unix)]
async fn wait_for_signal(state: &Arc<AppState>) -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(%error, "could not install the SIGTERM handler");
            let _ = tokio::signal::ctrl_c().await;
            return "SIGINT";
        }
    };
    let mut hangup = signal(SignalKind::hangup()).ok();

    loop {
        let hangup_received = async {
            match hangup.as_mut() {
                Some(stream) => {
                    stream.recv().await;
                }
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => return "SIGINT",
            _ = terminate.recv() => return "SIGTERM",
            _ = hangup_received => reload_on_hangup(state),
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_signal(_state: &Arc<AppState>) -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "ctrl-c"
}

#[cfg(unix)]
fn reload_on_hangup(state: &Arc<AppState>) {
    match state.reload_from_disk() {
        Ok(change) => tracing::info!(
            added = ?change.added,
            removed = ?change.removed,
            strategy_changed = change.strategy_changed,
            restart_required = change.queue_settings_changed,
            "configuration reloaded on SIGHUP"
        ),
        Err(message) => tracing::error!("SIGHUP reload rejected, keeping the running config: {message}"),
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Options {
    config: Option<PathBuf>,
    check: bool,
    print_config: bool,
    generate_config: Option<PathBuf>,
    force: bool,
    probe: bool,
    version: bool,
    help: bool,
}

impl Options {
    fn parse<I: IntoIterator<Item = String>>(arguments: I) -> Result<Self, String> {
        let mut options = Options::default();
        let mut arguments = arguments.into_iter().peekable();

        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "-h" | "--help" => options.help = true,
                "-V" | "--version" => options.version = true,
                "--check" => options.check = true,
                "--print-config" => options.print_config = true,
                "--probe" => options.probe = true,
                "--force" => options.force = true,
                "-c" | "--config" => {
                    let value = arguments
                        .next()
                        .ok_or_else(|| format!("{argument} needs a path"))?;
                    options.config = Some(PathBuf::from(value));
                }
                "--generate-config" => {
                    // The path is optional, so only consume the next argument
                    // when it is not another flag.
                    let target = match arguments.peek() {
                        Some(next) if !next.starts_with('-') => {
                            PathBuf::from(arguments.next().expect("peeked"))
                        }
                        _ => PathBuf::from("config.yaml"),
                    };
                    options.generate_config = Some(target);
                }
                other if other.starts_with("--config=") => {
                    options.config = Some(PathBuf::from(&other["--config=".len()..]));
                }
                other if other.starts_with("--generate-config=") => {
                    options.generate_config =
                        Some(PathBuf::from(&other["--generate-config=".len()..]));
                }
                other => return Err(format!("unknown argument `{other}`")),
            }
        }

        Ok(options)
    }
}

/// Explicit path wins, then the environment, then the well-known locations.
fn resolve_config_path(explicit: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path);
    }
    if let Some(value) = std::env::var_os("SMTP_RELAY_CONFIG") {
        return Some(PathBuf::from(value));
    }
    CONFIG_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.exists())
}

fn generate_config(target: &Path, force: bool) -> Result<PathBuf, String> {
    if target.exists() && !force {
        return Err(format!(
            "{} already exists; pass --force to overwrite it",
            target.display()
        ));
    }

    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
    }

    std::fs::write(target, Config::example_yaml())
        .map_err(|error| format!("could not write {}: {error}", target.display()))?;
    Ok(target.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Options, String> {
        Options::parse(arguments.iter().map(|argument| argument.to_string()))
    }

    #[test]
    fn no_arguments_is_the_default_daemon() {
        let options = parse(&[]).unwrap();
        assert_eq!(options, Options::default());
    }

    #[test]
    fn config_path_accepts_both_spellings() {
        assert_eq!(
            parse(&["-c", "/etc/relay.yaml"]).unwrap().config,
            Some(PathBuf::from("/etc/relay.yaml"))
        );
        assert_eq!(
            parse(&["--config", "relay.toml"]).unwrap().config,
            Some(PathBuf::from("relay.toml"))
        );
        assert_eq!(
            parse(&["--config=relay.json"]).unwrap().config,
            Some(PathBuf::from("relay.json"))
        );
    }

    #[test]
    fn generate_config_path_is_optional() {
        assert_eq!(
            parse(&["--generate-config"]).unwrap().generate_config,
            Some(PathBuf::from("config.yaml"))
        );
        assert_eq!(
            parse(&["--generate-config", "out.yaml"])
                .unwrap()
                .generate_config,
            Some(PathBuf::from("out.yaml"))
        );
        // A following flag must not be swallowed as the target path.
        let options = parse(&["--generate-config", "--force"]).unwrap();
        assert_eq!(options.generate_config, Some(PathBuf::from("config.yaml")));
        assert!(options.force);
    }

    #[test]
    fn missing_config_value_is_an_error() {
        assert!(parse(&["--config"]).is_err());
    }

    #[test]
    fn unknown_arguments_are_rejected() {
        assert!(parse(&["--nope"]).is_err());
    }

    #[test]
    fn explicit_config_path_beats_discovery() {
        let explicit = PathBuf::from("given.yaml");
        assert_eq!(
            resolve_config_path(Some(explicit.clone())),
            Some(explicit),
            "an explicit path must never be second-guessed"
        );
    }

    #[test]
    fn the_bundled_example_configuration_is_valid() {
        let parsed: Config =
            serde_yaml::from_str(Config::example_yaml()).expect("example config parses");
        parsed.validate().expect("example config validates");
        assert_eq!(parsed.relays.len(), 2);
    }
}
