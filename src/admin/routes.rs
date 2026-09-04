//! Admin REST API.
//!
//! Every mutating endpoint is explicit about whether it changes only the
//! running process or also rewrites the configuration file, because that
//! distinction decides what survives a restart.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::admin::http::{HandlerFuture, Reply, Request, Response};
use crate::config::{Config, RelayConfig, StickyMode, Strategy};
use crate::events::EventKind;
use crate::metrics::{MessageStatus, RelayMetricsRow};
use crate::relay::health;
use crate::relay::sender;
use crate::state::{AppState, VERSION};
use crate::util::{human_bytes, human_duration, is_loopback, new_queue_id, secret_eq, Cidr};

/// Routes that never require a token, so probes, the login page and scrapers
/// work unattended. The dashboard HTML is public so the browser can render the
/// sign-in form; the JSON API behind it is not.
const PUBLIC_PATHS: &[&str] = &[
    "/healthz",
    "/readyz",
    "/metrics",
    "/",
    "/index.html",
    "/favicon.ico",
    "/api/session",
    "/api/login",
    "/api/logout",
];

const SESSION_COOKIE: &str = "smtp_relay_session";
const SESSION_MAX_AGE: i64 = 12 * 60 * 60;

/// Entry point used by the HTTP server.
pub fn handle(state: Arc<AppState>, request: Request) -> HandlerFuture {
    Box::pin(async move { route(state, request).await })
}

async fn route(state: Arc<AppState>, request: Request) -> Reply {
    let config = state.config();

    // CORS preflight, so a dashboard served from elsewhere can call the API.
    if request.method == "OPTIONS" {
        return Reply::Complete(
            Response::new(204, "text/plain", Vec::new())
                .with_header("Access-Control-Allow-Origin", "*")
                .with_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                .with_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                .with_header("Access-Control-Max-Age", "600"),
        );
    }

    if !network_allowed(&config.admin_networks(), &request) {
        tracing::warn!(peer = %request.peer, "refused admin request: source not in admin.allowed_networks");
        return Response::error(403, "your address is not permitted to use the admin API").into();
    }

    if !PUBLIC_PATHS.contains(&request.path.as_str()) {
        if let Err(response) = authorize(&state, &request) {
            return response.into();
        }
    }

    let segments: Vec<&str> = request.segments.iter().map(|s| s.as_str()).collect();
    let method = request.method.as_str();

    let reply = match (method, segments.as_slice()) {
        // -- unauthenticated operational endpoints ------------------------
        ("GET", ["healthz"]) => Response::text(200, "ok").into(),
        ("GET", ["readyz"]) => ready(&state).into(),
        ("GET", ["metrics"]) => metrics_text(&state).into(),

        // -- dashboard / auth ----------------------------------------------
        ("GET", []) | ("GET", ["index.html"]) => dashboard(&state).into(),
        ("GET", ["favicon.ico"]) => Response::new(204, "image/x-icon", Vec::new()).into(),
        ("GET", ["api", "session"]) => session_status(&state, &request).into(),
        ("POST", ["api", "login"]) => login(&state, &request).into(),
        ("POST", ["api", "logout"]) => logout(&state, &request).into(),

        // -- overview ------------------------------------------------------
        ("GET", ["api", "status"]) => status(&state, &request).into(),
        ("GET", ["api", "series"]) => series(&state, &request).into(),
        ("GET", ["api", "events"]) => Reply::EventStream,

        // -- relays --------------------------------------------------------
        ("GET", ["api", "relays"]) => list_relays(&state).into(),
        ("POST", ["api", "relays"]) => add_relay(&state, &request).into(),
        ("POST", ["api", "relays", "activate-all"]) => {
            bulk_activation(&state, &request, BulkAction::ActivateAll).into()
        }
        ("POST", ["api", "relays", "deactivate-all"]) => {
            bulk_activation(&state, &request, BulkAction::DeactivateAll).into()
        }
        ("POST", ["api", "relays", "bulk"]) => bulk(&state, &request).into(),
        ("POST", ["api", "relays", "reset-stats"]) => reset_all_stats(&state).into(),
        ("GET", ["api", "relays", id]) => get_relay(&state, id).into(),
        ("PUT", ["api", "relays", id]) => update_relay(&state, &request, id).into(),
        ("DELETE", ["api", "relays", id]) => delete_relay(&state, &request, id).into(),
        ("POST", ["api", "relays", id, "activate"]) => {
            set_activation(&state, &request, id, Some(true)).into()
        }
        ("POST", ["api", "relays", id, "deactivate"]) => {
            set_activation(&state, &request, id, Some(false)).into()
        }
        ("POST", ["api", "relays", id, "toggle"]) => {
            set_activation(&state, &request, id, None).into()
        }
        ("POST", ["api", "relays", id, "reset-stats"]) => reset_stats(&state, id).into(),
        ("POST", ["api", "relays", id, "reset-circuit"]) => reset_circuit(&state, id).into(),
        ("POST", ["api", "relays", id, "probe"]) => probe_relay(&state, id).await.into(),
        ("POST", ["api", "relays", id, "test"]) => {
            send_test(&state, &request, id).await.into()
        }

        // -- routing -------------------------------------------------------
        ("GET", ["api", "routing"]) => routing(&state).into(),
        ("PUT", ["api", "routing"]) | ("POST", ["api", "routing"]) => {
            update_routing(&state, &request).into()
        }

        // -- configuration --------------------------------------------------
        ("GET", ["api", "config"]) => config_body(&state).into(),
        ("PUT", ["api", "config"]) => replace_config(&state, &request).into(),
        ("POST", ["api", "config", "reload"]) => reload_config(&state).into(),
        ("POST", ["api", "config", "save"]) => save_config(&state).into(),

        // -- messages -------------------------------------------------------
        ("GET", ["api", "messages"]) => messages(&state, &request).into(),
        ("DELETE", ["api", "messages"]) => clear_messages(&state).into(),
        ("GET", ["api", "messages", id]) => message(&state, id).into(),

        // -- queue ----------------------------------------------------------
        ("GET", ["api", "queue"]) => queue(&state, &request).into(),
        ("POST", ["api", "queue", "flush"]) => flush_queue(&state).into(),
        ("DELETE", ["api", "queue"]) => purge_queue(&state).into(),
        ("GET", ["api", "queue", id]) => queued_message(&state, id).into(),
        ("DELETE", ["api", "queue", id]) => drop_queued(&state, id).into(),

        ("GET", _) | ("POST", _) | ("PUT", _) | ("DELETE", _) => Response::error(
            404,
            &format!("no route for {} {}", request.method, request.path),
        )
        .into(),
        _ => Response::error(405, "unsupported method").into(),
    };

    // Attach CORS to buffered replies.
    match reply {
        Reply::Complete(response) => {
            Reply::Complete(response.with_header("Access-Control-Allow-Origin", "*"))
        }
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Access control
// ---------------------------------------------------------------------------

fn network_allowed(networks: &[Cidr], request: &Request) -> bool {
    networks.is_empty() || networks.iter().any(|network| network.contains(request.peer.ip()))
}

/// Session cookie, Bearer / `?token=` API token, or loopback when neither a
/// dashboard password nor an API token is configured.
fn authorize(state: &Arc<AppState>, request: &Request) -> Result<(), Response> {
    let config = state.config();

    if let Some(cookie) = request.cookie(SESSION_COOKIE) {
        if state.sessions().username(cookie).is_some() {
            return Ok(());
        }
    }

    let expected = config.admin.api_token.trim();
    let presented = presented_token(request);

    if let Some(token) = presented.as_deref() {
        if !expected.is_empty() && secret_eq(token, expected) {
            return Ok(());
        }
        if state.sessions().username(token).is_some() {
            return Ok(());
        }
        if !expected.is_empty() {
            return Err(Response::error(403, "invalid API token"));
        }
    }

    if config.admin.login_required() {
        return Err(Response::error(401, "sign in required")
            .with_header("WWW-Authenticate", "Bearer realm=\"smtp-relay\""));
    }

    if expected.is_empty() {
        return if is_loopback(request.peer.ip()) {
            Ok(())
        } else {
            Err(Response::error(
                401,
                "set admin.password or admin.api_token to use the API from a remote address",
            ))
        };
    }

    Err(Response::error(401, "missing API token")
        .with_header("WWW-Authenticate", "Bearer realm=\"smtp-relay\""))
}

fn presented_token(request: &Request) -> Option<String> {
    request
        .header("authorization")
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(|token| token.trim().to_string())
        .or_else(|| request.query_param("token").map(|t| t.to_string()))
}

fn session_cookie_header(token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_MAX_AGE}"
    )
}

fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn session_status(state: &Arc<AppState>, request: &Request) -> Response {
    let config = state.config();
    let username = request
        .cookie(SESSION_COOKIE)
        .and_then(|token| state.sessions().username(token));
    Response::json_value(
        200,
        &json!({
            "authenticated": username.is_some(),
            "login_required": config.admin.login_required(),
            "username": username,
            "display_username": config.admin.username,
        }),
    )
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

fn login(state: &Arc<AppState>, request: &Request) -> Response {
    let config = state.config();
    if !config.admin.login_required() {
        return Response::error(
            400,
            "dashboard login is not configured; set admin.password in the config file",
        );
    }

    let payload: LoginRequest = match request.body_json() {
        Ok(payload) => payload,
        Err(error) => return Response::error(400, &error),
    };

    let user_ok = payload
        .username
        .trim()
        .eq_ignore_ascii_case(config.admin.username.trim());
    let pass_ok = secret_eq(payload.password.trim(), config.admin.password.trim());
    if !user_ok || !pass_ok {
        tracing::warn!(peer = %request.peer, "dashboard login failed");
        return Response::error(401, "wrong username or password");
    }

    let token = state.sessions().create(config.admin.username.clone());
    tracing::info!(user = %config.admin.username, peer = %request.peer, "dashboard login");
    Response::json_value(
        200,
        &json!({
            "ok": true,
            "username": config.admin.username,
        }),
    )
    .with_header("Set-Cookie", &session_cookie_header(&token))
}

fn logout(state: &Arc<AppState>, request: &Request) -> Response {
    if let Some(token) = request.cookie(SESSION_COOKIE) {
        state.sessions().revoke(token);
    }
    Response::ok_message("signed out").with_header("Set-Cookie", &clear_session_cookie())
}

/// `persist=false` keeps a change in memory only.
fn should_persist(state: &Arc<AppState>, request: &Request) -> bool {
    let allowed = state.config().admin.allow_config_write;
    let requested = request
        .query_param("persist")
        .map(|value| !matches!(value, "0" | "false" | "no"))
        .unwrap_or(true);
    allowed && requested
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

fn ready(state: &Arc<AppState>) -> Response {
    let pool = state.pool();
    let eligible = pool.eligible_count();
    if eligible > 0 && !state.is_shutting_down() {
        Response::text(200, format!("ready: {eligible} relay(s) in rotation"))
    } else {
        Response::text(503, "not ready: no relay is currently eligible")
    }
}

fn metrics_text(state: &Arc<AppState>) -> Response {
    let rows: Vec<RelayMetricsRow> = state.pool().metrics_rows();
    let body = state
        .metrics
        .render_prometheus(state.uptime_seconds(), &rows);
    Response::new(200, "text/plain; version=0.0.4; charset=utf-8", body.into_bytes())
}

fn dashboard(state: &Arc<AppState>) -> Response {
    if !state.config().admin.dashboard_enabled {
        return Response::error(404, "the dashboard is disabled");
    }
    Response::html(include_str!("dashboard.html"))
}

fn status(state: &Arc<AppState>, request: &Request) -> Response {
    let config = state.config();
    let pool = state.pool();
    let counters = state.metrics.counters.snapshot();
    let minutes: usize = request.query_as("minutes").unwrap_or(60);

    let delivered = counters.messages_delivered as f64;
    let attempted = delivered + counters.messages_failed as f64;
    let success_rate = if attempted > 0.0 {
        (delivered / attempted) * 100.0
    } else {
        100.0
    };

    Response::json_value(
        200,
        &json!({
            "version": VERSION,
            "hostname": config.server.hostname,
            "config_path": state.config_path.display().to_string(),
            "started_at": state.started_wall,
            "uptime_seconds": state.uptime_seconds(),
            "uptime_human": human_duration(state.uptime_seconds()),
            "shutting_down": state.is_shutting_down(),
            "tls_backend": tls_backend(),
            "server": {
                "bind_address": config.server.bind_address,
                "submission_mode": config.server.submission_mode.as_str(),
                "max_message_size_mb": config.server.max_message_size_mb,
                "timeout_seconds": config.server.timeout_seconds,
                "max_connections": config.server.max_connections,
                "auth_required": config.server.require_auth,
                "auth_users": config.server.auth_users.len(),
                "allowed_networks": config.server.allowed_networks,
            },
            "routing": {
                "strategy": config.routing.strategy.as_str(),
                "sticky": config.routing.sticky,
                "fallback_on_failure": config.routing.fallback_on_failure,
                "max_attempts_per_message": config.routing.max_attempts_per_message,
                "domain_overrides": config.routing.domain_overrides.len(),
            },
            "relays": {
                "total": pool.len(),
                "active": pool.active_count(),
                "eligible": pool.eligible_count(),
                "healthy": pool.healthy_count(),
            },
            "queue": {
                "enabled": state.queue.is_enabled(),
                "persistent": state.queue.is_persistent(),
                "depth": state.queue.depth(),
                "due": state.queue.due_count(),
                "in_flight": state.queue.in_flight(),
                "capacity": state.queue.capacity(),
                "workers": config.queue.workers,
                "max_attempts": config.queue.max_attempts,
            },
            "counters": counters,
            "derived": {
                "success_rate_percent": (success_rate * 100.0).round() / 100.0,
                "average_latency_ms": (state.metrics.latency.average_ms() * 100.0).round() / 100.0,
                "bytes_received_human": human_bytes(counters.bytes_received),
                "bytes_delivered_human": human_bytes(counters.bytes_delivered),
            },
            "series": state.metrics.series.snapshot(minutes),
            "dashboard_clients": state.events.subscriber_count(),
        }),
    )
}

fn series(state: &Arc<AppState>, request: &Request) -> Response {
    let minutes: usize = request.query_as("minutes").unwrap_or(60);
    Response::json(200, &state.metrics.series.snapshot(minutes))
}

fn tls_backend() -> &'static str {
    if cfg!(feature = "tls-native") {
        "native-tls"
    } else if cfg!(feature = "tls-rustls") {
        "rustls"
    } else {
        "none"
    }
}

// ---------------------------------------------------------------------------
// Relays
// ---------------------------------------------------------------------------

fn list_relays(state: &Arc<AppState>) -> Response {
    let pool = state.pool();
    Response::json_value(
        200,
        &json!({
            "strategy": pool.routing.strategy.as_str(),
            "total": pool.len(),
            "active": pool.active_count(),
            "eligible": pool.eligible_count(),
            "relays": pool.snapshot(),
        }),
    )
}

fn get_relay(state: &Arc<AppState>, id: &str) -> Response {
    let pool = state.pool();
    match pool.get(id) {
        Some(relay) => {
            let percent = pool.weight_percentages().get(id).copied().unwrap_or(0.0);
            Response::json(200, &relay.snapshot(percent))
        }
        None => Response::error(404, &format!("no relay with id `{id}`")),
    }
}

#[derive(Debug, Clone, Copy)]
enum BulkAction {
    ActivateAll,
    DeactivateAll,
}

fn bulk_activation(state: &Arc<AppState>, request: &Request, action: BulkAction) -> Response {
    let pool = state.pool();
    let (changed, active) = match action {
        BulkAction::ActivateAll => (pool.activate_all(), true),
        BulkAction::DeactivateAll => (pool.deactivate_all(), false),
    };

    if matches!(action, BulkAction::DeactivateAll) && !changed.is_empty() {
        tracing::warn!(
            relays = changed.len(),
            "every relay was deactivated; new mail will be deferred until one is re-activated"
        );
    }

    finish_activation(state, request, changed, active)
}

#[derive(Debug, Deserialize)]
struct BulkRequest {
    /// `activate`, `deactivate` or `exclusive`.
    action: String,
    #[serde(default)]
    ids: Vec<String>,
}

fn bulk(state: &Arc<AppState>, request: &Request) -> Response {
    let payload: BulkRequest = match request.body_json() {
        Ok(payload) => payload,
        Err(error) => return Response::error(400, &error),
    };

    let pool = state.pool();
    let action = payload.action.to_ascii_lowercase();

    let (changed, unknown, active) = match action.as_str() {
        "activate" => {
            let (changed, unknown) = pool.set_many(&payload.ids, true);
            (changed, unknown, true)
        }
        "deactivate" => {
            let (changed, unknown) = pool.set_many(&payload.ids, false);
            (changed, unknown, false)
        }
        // "Select only these": activate the listed relays, deactivate the rest.
        "exclusive" | "only" => {
            let (changed, unknown) = pool.set_exclusive(&payload.ids);
            (changed, unknown, true)
        }
        other => {
            return Response::error(
                400,
                &format!("unknown action `{other}` (use activate, deactivate or exclusive)"),
            )
        }
    };

    if !unknown.is_empty() {
        return Response::error(
            404,
            &format!("unknown relay id(s): {}", unknown.join(", ")),
        );
    }

    if action == "exclusive" || action == "only" {
        // Persist the full activation map rather than just the changed ids.
        let persisted = if should_persist(state, request) {
            let pairs: Vec<(String, bool)> = pool
                .relays()
                .iter()
                .map(|relay| (relay.id().to_string(), relay.is_active()))
                .collect();
            state.persist_activation(&pairs).is_ok()
        } else {
            false
        };
        publish_activation(state, &changed, true);
        return activation_response(state, changed, persisted);
    }

    finish_activation(state, request, changed, active)
}

fn set_activation(
    state: &Arc<AppState>,
    request: &Request,
    id: &str,
    active: Option<bool>,
) -> Response {
    let pool = state.pool();
    let Some(relay) = pool.get(id) else {
        return Response::error(404, &format!("no relay with id `{id}`"));
    };

    let target = active.unwrap_or_else(|| !relay.is_active());
    let changed = relay.set_active(target);

    let changed_ids = if changed {
        vec![id.to_string()]
    } else {
        Vec::new()
    };
    finish_activation(state, request, changed_ids, target)
}

fn finish_activation(
    state: &Arc<AppState>,
    request: &Request,
    changed: Vec<String>,
    active: bool,
) -> Response {
    let persisted = if !changed.is_empty() && should_persist(state, request) {
        let pairs: Vec<(String, bool)> = changed
            .iter()
            .map(|id| (id.clone(), active))
            .collect();
        match state.persist_activation(&pairs) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(%error, "could not persist the activation change");
                false
            }
        }
    } else {
        false
    };

    publish_activation(state, &changed, active);
    activation_response(state, changed, persisted)
}

fn publish_activation(state: &Arc<AppState>, changed: &[String], active: bool) {
    if changed.is_empty() {
        return;
    }
    tracing::info!(
        relays = ?changed,
        active,
        "relay activation changed"
    );
    state.events.publish(
        EventKind::Relay,
        json!({
            "action": if active { "activated" } else { "deactivated" },
            "ids": changed,
        }),
    );
}

fn activation_response(state: &Arc<AppState>, changed: Vec<String>, persisted: bool) -> Response {
    let pool = state.pool();
    Response::json_value(
        200,
        &json!({
            "ok": true,
            "changed": changed,
            "persisted": persisted,
            "active": pool.active_count(),
            "eligible": pool.eligible_count(),
            "total": pool.len(),
            "relays": pool.snapshot(),
        }),
    )
}

fn reset_stats(state: &Arc<AppState>, id: &str) -> Response {
    match state.pool().get(id) {
        Some(relay) => {
            relay.reset_stats();
            Response::ok_message(&format!("statistics for `{id}` were reset"))
        }
        None => Response::error(404, &format!("no relay with id `{id}`")),
    }
}

fn reset_all_stats(state: &Arc<AppState>) -> Response {
    let pool = state.pool();
    for relay in pool.relays() {
        relay.reset_stats();
    }
    Response::ok_message(&format!("statistics for {} relay(s) were reset", pool.len()))
}

fn reset_circuit(state: &Arc<AppState>, id: &str) -> Response {
    match state.pool().get(id) {
        Some(relay) => {
            relay.reset_circuit();
            tracing::info!(relay = id, "circuit breaker reset by an operator");
            state.events.publish(
                EventKind::Relay,
                json!({ "id": id, "action": "circuit_reset" }),
            );
            Response::json(200, &relay.snapshot(0.0))
        }
        None => Response::error(404, &format!("no relay with id `{id}`")),
    }
}

async fn probe_relay(state: &Arc<AppState>, id: &str) -> Response {
    let Some(relay) = state.pool().get(id) else {
        return Response::error(404, &format!("no relay with id `{id}`"));
    };

    let result = health::probe(state, &relay).await;
    Response::json_value(
        200,
        &json!({
            "ok": result.ok,
            "relay": result.relay_id,
            "latency_ms": result.latency_ms,
            "error": result.error,
            "state": relay.snapshot(0.0),
        }),
    )
}

#[derive(Debug, Deserialize)]
struct TestRequest {
    to: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    body: Option<String>,
}

async fn send_test(state: &Arc<AppState>, request: &Request, id: &str) -> Response {
    let payload: TestRequest = match request.body_json() {
        Ok(payload) => payload,
        Err(error) => return Response::error(400, &error),
    };

    if !crate::util::looks_like_email(&payload.to) {
        return Response::error(400, &format!("`{}` is not a valid address", payload.to));
    }

    let Some(relay) = state.pool().get(id) else {
        return Response::error(404, &format!("no relay with id `{id}`"));
    };

    let config = state.config();
    let queue_id = new_queue_id();
    let subject = payload
        .subject
        .unwrap_or_else(|| format!("smtp-relay test via {id}"));
    let body = payload.body.unwrap_or_else(|| {
        format!(
            "This is a test message sent through the `{id}` relay by smtp-relay {VERSION} on {}.\r\n\
             \r\n\
             Envelope sender: {}\r\n\
             Relay endpoint:  {}\r\n",
            config.server.hostname,
            relay.config.effective_from_address(),
            relay.config.endpoint()
        )
    });

    let raw = sender::build_test_message(
        &relay.config,
        &config.server.hostname,
        &payload.to,
        &subject,
        &body,
        &queue_id,
    );

    let recipients = vec![payload.to.clone()];
    let _slot = relay.begin_delivery();
    let result = sender::deliver(
        &relay,
        &relay.config.effective_from_address(),
        &recipients,
        &raw,
    )
    .await;

    match result {
        Ok(report) => {
            relay.record_delivery(raw.len() as u64, report.latency, &config.health);
            tracing::info!(
                relay = id,
                to = %payload.to,
                latency_ms = report.latency.as_millis() as u64,
                "test message delivered"
            );
            Response::json_value(
                200,
                &json!({
                    "ok": true,
                    "relay": id,
                    "to": payload.to,
                    "id": queue_id,
                    "latency_ms": report.latency.as_millis() as u64,
                    "response": report.response,
                }),
            )
        }
        Err(error) => {
            if error.should_retry() {
                relay.record_deferral(&error.message, &config.health);
            } else {
                relay.record_permanent_failure(&error.message);
            }
            tracing::warn!(relay = id, to = %payload.to, "test message failed: {error}");
            Response::json_value(
                502,
                &json!({
                    "ok": false,
                    "relay": id,
                    "to": payload.to,
                    "error": error.message,
                    "status_code": error.status_code,
                    "kind": error.kind.as_str(),
                    "retryable": error.should_retry(),
                }),
            )
        }
    }
}

fn add_relay(state: &Arc<AppState>, request: &Request) -> Response {
    let mut relay: RelayConfig = match request.body_json() {
        Ok(relay) => relay,
        Err(error) => return Response::error(400, &error),
    };
    relay.sync_from_identity();

    if state.pool().contains(&relay.id) {
        return Response::error(409, &format!("a relay with id `{}` already exists", relay.id));
    }

    let id = relay.id.clone();
    match state.edit_config(should_persist(state, request), move |config| {
        config.relays.push(relay)
    }) {
        Ok(_) => {
            tracing::info!(relay = %id, "relay added");
            state
                .events
                .publish(EventKind::Relay, json!({ "action": "added", "id": id }));
            list_relays(state)
        }
        Err(error) => Response::error(422, &error),
    }
}

fn update_relay(state: &Arc<AppState>, request: &Request, id: &str) -> Response {
    let mut relay: RelayConfig = match request.body_json() {
        Ok(relay) => relay,
        Err(error) => return Response::error(400, &error),
    };

    if !state.pool().contains(id) {
        return Response::error(404, &format!("no relay with id `{id}`"));
    }
    // The path is authoritative, so a mismatched body cannot rename a relay.
    relay.id = id.to_string();

    // Keep the stored password when the client echoes back the redacted one.
    if let Some(auth) = &mut relay.auth {
        if auth.password == crate::config::REDACTED {
            if let Some(existing) = state
                .config()
                .relay(id)
                .and_then(|existing| existing.auth.clone())
            {
                auth.password = existing.password;
            }
        }
    }

    // The dashboard form only edits the identity fields. Everything else
    // (priority, concurrency, HELO, tags) is kept from the live config so an
    // edit cannot silently reset them to defaults.
    if let Some(existing) = state.config().relay(id).cloned() {
        relay.priority = existing.priority;
        relay.max_concurrent = existing.max_concurrent;
        relay.timeout_seconds = existing.timeout_seconds;
        relay.helo_name = existing.helo_name;
        relay.allow_invalid_certs = existing.allow_invalid_certs;
        relay.tags = existing.tags;
        if relay.auth.is_none() {
            relay.auth = existing.auth;
        }
    }
    relay.sync_from_identity();

    let target = id.to_string();
    match state.edit_config(should_persist(state, request), move |config| {
        if let Some(slot) = config.relays.iter_mut().find(|r| r.id == target) {
            *slot = relay;
        }
    }) {
        Ok(_) => {
            tracing::info!(relay = id, "relay updated");
            state
                .events
                .publish(EventKind::Relay, json!({ "action": "updated", "id": id }));
            get_relay(state, id)
        }
        Err(error) => Response::error(422, &error),
    }
}

fn delete_relay(state: &Arc<AppState>, request: &Request, id: &str) -> Response {
    if !state.pool().contains(id) {
        return Response::error(404, &format!("no relay with id `{id}`"));
    }

    let target = id.to_string();
    match state.edit_config(should_persist(state, request), move |config| {
        config.relays.retain(|relay| relay.id != target)
    }) {
        Ok(_) => {
            tracing::warn!(relay = id, "relay removed");
            state
                .events
                .publish(EventKind::Relay, json!({ "action": "removed", "id": id }));
            list_relays(state)
        }
        Err(error) => Response::error(422, &error),
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

fn routing(state: &Arc<AppState>) -> Response {
    let config = state.config();
    Response::json_value(
        200,
        &json!({
            "strategy": config.routing.strategy.as_str(),
            "available_strategies": ["round_robin", "weighted", "least_used", "failover"],
            "sticky": config.routing.sticky,
            "fallback_on_failure": config.routing.fallback_on_failure,
            "max_attempts_per_message": config.routing.max_attempts_per_message,
            "domain_overrides": config.routing.domain_overrides,
            "weights": state.pool().weight_percentages(),
        }),
    )
}

#[derive(Debug, Deserialize)]
struct RoutingUpdate {
    #[serde(default)]
    strategy: Option<String>,
    #[serde(default)]
    sticky: Option<String>,
    #[serde(default)]
    fallback_on_failure: Option<bool>,
    #[serde(default)]
    max_attempts_per_message: Option<usize>,
}

fn update_routing(state: &Arc<AppState>, request: &Request) -> Response {
    let payload: RoutingUpdate = match request.body_json() {
        Ok(payload) => payload,
        Err(error) => return Response::error(400, &error),
    };

    let strategy = match payload.strategy.as_deref() {
        None => None,
        Some(value) => match parse_strategy(value) {
            Some(strategy) => Some(strategy),
            None => {
                return Response::error(
                    400,
                    &format!(
                        "unknown strategy `{value}` (use round_robin, weighted, least_used or failover)"
                    ),
                )
            }
        },
    };

    let sticky = match payload.sticky.as_deref() {
        None => None,
        Some(value) => match parse_sticky(value) {
            Some(sticky) => Some(sticky),
            None => {
                return Response::error(
                    400,
                    &format!("unknown sticky mode `{value}` (use none, sender or recipient_domain)"),
                )
            }
        },
    };

    let result = state.edit_config(should_persist(state, request), |config| {
        if let Some(strategy) = strategy {
            config.routing.strategy = strategy;
        }
        if let Some(sticky) = sticky {
            config.routing.sticky = sticky;
        }
        if let Some(fallback) = payload.fallback_on_failure {
            config.routing.fallback_on_failure = fallback;
        }
        if let Some(attempts) = payload.max_attempts_per_message {
            config.routing.max_attempts_per_message = attempts;
        }
    });

    match result {
        Ok(_) => {
            let config = state.config();
            tracing::info!(
                strategy = config.routing.strategy.as_str(),
                "routing updated"
            );
            state.events.publish(
                EventKind::Config,
                json!({
                    "action": "routing",
                    "strategy": config.routing.strategy.as_str(),
                }),
            );
            routing(state)
        }
        Err(error) => Response::error(422, &error),
    }
}

fn parse_strategy(value: &str) -> Option<Strategy> {
    match value.to_ascii_lowercase().as_str() {
        "round_robin" | "roundrobin" | "rr" => Some(Strategy::RoundRobin),
        "weighted" | "weighted_round_robin" => Some(Strategy::Weighted),
        "least_used" | "least_conn" => Some(Strategy::LeastUsed),
        "failover" | "priority" => Some(Strategy::Failover),
        _ => None,
    }
}

fn parse_sticky(value: &str) -> Option<StickyMode> {
    match value.to_ascii_lowercase().as_str() {
        "none" | "off" => Some(StickyMode::None),
        "sender" | "from" => Some(StickyMode::Sender),
        "recipient_domain" | "domain" => Some(StickyMode::RecipientDomain),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn config_body(state: &Arc<AppState>) -> Response {
    let redacted = state.config().redacted();
    let yaml = redacted
        .serialize_for(std::path::Path::new("config.yaml"))
        .unwrap_or_else(|error| format!("# could not render YAML: {error}\n"));

    Response::json_value(
        200,
        &json!({
            "path": state.config_path.display().to_string(),
            "writable": state.config().admin.allow_config_write,
            "config": redacted,
            "yaml": yaml,
        }),
    )
}

fn replace_config(state: &Arc<AppState>, request: &Request) -> Response {
    if !state.config().admin.allow_config_write {
        return Response::error(403, "admin.allow_config_write is disabled");
    }

    // Accept either the bare document or `{"config": {...}}` as sent by the
    // dashboard's config editor.
    let value: Value = match request.body_json() {
        Ok(value) => value,
        Err(error) => return Response::error(400, &error),
    };
    let document = value.get("config").cloned().unwrap_or(value);

    let mut incoming: Config = match serde_json::from_value(document) {
        Ok(config) => config,
        Err(error) => return Response::error(422, &format!("invalid configuration: {error}")),
    };

    // Secrets arrive redacted from the dashboard; restore them before saving,
    // otherwise a config edit would silently destroy every password.
    incoming.restore_secrets_from(&state.config());

    match state.apply_config(incoming) {
        Ok(change) => {
            if let Err(error) = state.persist_config() {
                return Response::error(
                    500,
                    &format!("configuration applied but could not be saved: {error}"),
                );
            }
            tracing::info!(
                added = ?change.added,
                removed = ?change.removed,
                "configuration replaced through the API"
            );
            Response::json_value(
                200,
                &json!({
                    "ok": true,
                    "relays_added": change.added,
                    "relays_removed": change.removed,
                    "restart_required_for_queue_changes": change.queue_settings_changed,
                }),
            )
        }
        Err(error) => Response::error(422, &error),
    }
}

fn reload_config(state: &Arc<AppState>) -> Response {
    match state.reload_from_disk() {
        Ok(change) => {
            tracing::info!(
                added = ?change.added,
                removed = ?change.removed,
                "configuration reloaded from disk"
            );
            Response::json_value(
                200,
                &json!({
                    "ok": true,
                    "path": state.config_path.display().to_string(),
                    "relays_added": change.added,
                    "relays_removed": change.removed,
                    "restart_required_for_queue_changes": change.queue_settings_changed,
                }),
            )
        }
        Err(error) => Response::error(422, &error),
    }
}

fn save_config(state: &Arc<AppState>) -> Response {
    if !state.config().admin.allow_config_write {
        return Response::error(403, "admin.allow_config_write is disabled");
    }
    match state.persist_config() {
        Ok(()) => Response::ok_message(&format!(
            "configuration written to {}",
            state.config_path.display()
        )),
        Err(error) => Response::error(500, &error.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Messages and queue
// ---------------------------------------------------------------------------

fn messages(state: &Arc<AppState>, request: &Request) -> Response {
    let limit: usize = request.query_as("limit").unwrap_or(100).clamp(1, 1_000);
    let relay = request.query_param("relay");
    let status = match request.query_param("status") {
        None | Some("") | Some("all") => None,
        Some(value) => match parse_status(value) {
            Some(status) => Some(status),
            None => return Response::error(400, &format!("unknown status `{value}`")),
        },
    };

    let records = state.metrics.activity.recent(limit, status, relay);
    Response::json_value(
        200,
        &json!({
            "count": records.len(),
            "limit": limit,
            "messages": records,
        }),
    )
}

fn message(state: &Arc<AppState>, id: &str) -> Response {
    match state.metrics.activity.get(id) {
        Some(record) => Response::json(200, &record),
        None => Response::error(
            404,
            &format!("message `{id}` is not in the activity log (it may have aged out)"),
        ),
    }
}

fn clear_messages(state: &Arc<AppState>) -> Response {
    let cleared = state.metrics.activity.clear();
    Response::ok_message(&format!("cleared {cleared} activity record(s)"))
}

fn parse_status(value: &str) -> Option<MessageStatus> {
    match value.to_ascii_lowercase().as_str() {
        "accepted" => Some(MessageStatus::Accepted),
        "queued" => Some(MessageStatus::Queued),
        "sending" => Some(MessageStatus::Sending),
        "delivered" => Some(MessageStatus::Delivered),
        "deferred" => Some(MessageStatus::Deferred),
        "failed" => Some(MessageStatus::Failed),
        "rejected" => Some(MessageStatus::Rejected),
        _ => None,
    }
}

fn queue(state: &Arc<AppState>, request: &Request) -> Response {
    let limit: usize = request.query_as("limit").unwrap_or(100).clamp(1, 1_000);
    Response::json_value(
        200,
        &json!({
            "enabled": state.queue.is_enabled(),
            "persistent": state.queue.is_persistent(),
            "depth": state.queue.depth(),
            "due": state.queue.due_count(),
            "in_flight": state.queue.in_flight(),
            "capacity": state.queue.capacity(),
            "messages": state.queue.list(limit),
        }),
    )
}

fn flush_queue(state: &Arc<AppState>) -> Response {
    let moved = state.queue.flush_now();
    tracing::info!(messages = moved, "queue flushed by an operator");
    state.events.publish(
        EventKind::Queue,
        json!({ "action": "flushed", "messages": moved }),
    );
    Response::json_value(
        200,
        &json!({
            "ok": true,
            "message": format!("{moved} message(s) are now due for immediate retry"),
            "depth": state.queue.depth(),
        }),
    )
}

fn purge_queue(state: &Arc<AppState>) -> Response {
    let removed = state.queue.purge();
    tracing::warn!(messages = removed, "queue purged by an operator");
    state.events.publish(
        EventKind::Queue,
        json!({ "action": "purged", "messages": removed }),
    );
    Response::json_value(
        200,
        &json!({ "ok": true, "removed": removed, "depth": state.queue.depth() }),
    )
}

/// One queued message, including the first part of the raw payload so an
/// operator can see what is actually stuck without pulling it off the spool.
fn queued_message(state: &Arc<AppState>, id: &str) -> Response {
    let Some(message) = state.queue.get(id) else {
        return Response::error(404, &format!("message `{id}` is not in the queue"));
    };

    let preview_limit = message.raw.len().min(8 * 1024);
    Response::json_value(
        200,
        &json!({
            "id": message.id,
            "sender": message.sender,
            "recipients": message.recipients,
            "original_from": message.original_from,
            "subject": message.subject,
            "attempts": message.attempts,
            "received_at": message.received_at,
            "next_attempt_at": message.next_attempt_at,
            "tried_relays": message.tried_relays,
            "last_error": message.last_error,
            "size_bytes": message.size_bytes(),
            "raw_preview": String::from_utf8_lossy(&message.raw[..preview_limit]),
            "raw_truncated": preview_limit < message.raw.len(),
        }),
    )
}

fn drop_queued(state: &Arc<AppState>, id: &str) -> Response {
    if state.queue.remove(id) {
        tracing::warn!(%id, "queued message dropped by an operator");
        Response::ok_message(&format!("message `{id}` was removed from the queue"))
    } else {
        Response::error(404, &format!("message `{id}` is not in the queue"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AdminConfig;
    use std::collections::HashMap;
    use std::net::SocketAddr;

    fn request(peer: &str, token: Option<&str>) -> Request {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            headers.insert("authorization".to_string(), format!("Bearer {token}"));
        }
        Request {
            method: "GET".to_string(),
            path: "/api/status".to_string(),
            segments: vec!["api".to_string(), "status".to_string()],
            query: HashMap::new(),
            headers,
            body: Vec::new(),
            peer: peer.parse::<SocketAddr>().unwrap(),
        }
    }

    fn state_with_admin(admin: AdminConfig) -> Arc<AppState> {
        let config = Config {
            admin,
            relays: vec![crate::config::RelayConfig {
                id: "one".to_string(),
                host: "smtp.one.test".to_string(),
                from_address: "noreply@one.test".to_string(),
                ..Default::default()
            }],
            queue: crate::config::QueueConfig {
                persist: false,
                ..Default::default()
            },
            ..Default::default()
        };
        AppState::new(config, std::path::PathBuf::from("config.yaml")).expect("state")
    }

    fn state_with_token(token: &str) -> Arc<AppState> {
        state_with_admin(AdminConfig {
            api_token: token.to_string(),
            ..Default::default()
        })
    }

    #[test]
    fn a_valid_token_is_accepted_from_anywhere() {
        let state = state_with_token("s3cret");
        assert!(authorize(&state, &request("203.0.113.4:9000", Some("s3cret"))).is_ok());
    }

    #[test]
    fn a_wrong_token_is_forbidden() {
        let state = state_with_token("s3cret");
        let error = authorize(&state, &request("127.0.0.1:9000", Some("nope"))).unwrap_err();
        assert_eq!(error.status, 403);
    }

    #[test]
    fn a_missing_token_is_unauthorized_and_advertises_the_scheme() {
        let state = state_with_token("s3cret");
        let error = authorize(&state, &request("127.0.0.1:9000", None)).unwrap_err();
        assert_eq!(error.status, 401);
        assert!(error
            .headers
            .iter()
            .any(|(name, _)| name == "WWW-Authenticate"));
    }

    #[test]
    fn without_a_token_only_loopback_is_allowed() {
        let state = state_with_admin(AdminConfig::default());
        assert!(authorize(&state, &request("127.0.0.1:9000", None)).is_ok());
        assert!(authorize(&state, &request("[::1]:9000", None)).is_ok());

        let error = authorize(&state, &request("10.0.0.5:9000", None)).unwrap_err();
        assert_eq!(error.status, 401);
        let body: Value = serde_json::from_slice(&error.body).unwrap();
        assert!(body["error"].as_str().unwrap().contains("password"));
    }

    #[test]
    fn a_token_can_also_be_passed_as_a_query_parameter() {
        let state = state_with_token("s3cret");
        let mut req = request("203.0.113.4:9000", None);
        req.query
            .insert("token".to_string(), "s3cret".to_string());
        assert!(authorize(&state, &req).is_ok());
    }

    #[test]
    fn a_dashboard_password_requires_a_session() {
        let state = state_with_admin(AdminConfig {
            username: "admin".to_string(),
            password: "letmein".to_string(),
            ..Default::default()
        });
        let error = authorize(&state, &request("127.0.0.1:9000", None)).unwrap_err();
        assert_eq!(error.status, 401);

        let token = state.sessions().create("admin");
        let mut req = request("203.0.113.4:9000", None);
        req.headers
            .insert("cookie".to_string(), format!("{SESSION_COOKIE}={token}"));
        assert!(
            authorize(&state, &req).is_ok(),
            "a dashboard password is enough for remote clients after login"
        );
    }

    #[test]
    fn login_issues_a_session_cookie() {
        let state = state_with_admin(AdminConfig {
            username: "admin".to_string(),
            password: "letmein".to_string(),
            ..Default::default()
        });
        let mut req = request("127.0.0.1:9000", None);
        req.method = "POST".to_string();
        req.body = br#"{"username":"admin","password":"letmein"}"#.to_vec();
        let response = login(&state, &req);
        assert_eq!(response.status, 200);
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "Set-Cookie" && value.contains(SESSION_COOKIE)));
    }

    #[test]
    fn admin_network_filtering_applies() {
        let networks = vec![Cidr::parse("10.0.0.0/8").unwrap()];
        assert!(network_allowed(&networks, &request("10.1.2.3:9000", None)));
        assert!(!network_allowed(&networks, &request("192.0.2.1:9000", None)));
        assert!(network_allowed(&[], &request("192.0.2.1:9000", None)));
    }

    #[test]
    fn health_and_metrics_bypass_token_auth() {
        for path in ["/healthz", "/readyz", "/metrics", "/", "/api/login", "/api/session"] {
            assert!(PUBLIC_PATHS.contains(&path));
        }
        assert!(!PUBLIC_PATHS.contains(&"/api/status"));
        assert!(!PUBLIC_PATHS.contains(&"/api/config"));
    }

    #[test]
    fn strategy_and_sticky_names_parse_with_aliases() {
        assert_eq!(parse_strategy("weighted"), Some(Strategy::Weighted));
        assert_eq!(parse_strategy("RR"), Some(Strategy::RoundRobin));
        assert_eq!(parse_strategy("priority"), Some(Strategy::Failover));
        assert_eq!(parse_strategy("least_conn"), Some(Strategy::LeastUsed));
        assert_eq!(parse_strategy("nonsense"), None);

        assert_eq!(parse_sticky("domain"), Some(StickyMode::RecipientDomain));
        assert_eq!(parse_sticky("off"), Some(StickyMode::None));
        assert_eq!(parse_sticky("nonsense"), None);
    }

    #[test]
    fn message_statuses_parse() {
        assert_eq!(parse_status("delivered"), Some(MessageStatus::Delivered));
        assert_eq!(parse_status("DEFERRED"), Some(MessageStatus::Deferred));
        assert_eq!(parse_status("nope"), None);
    }
}
