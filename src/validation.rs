//! Pre-send recipient checks via Stalwart's delivery-test API.
//!
//! Each configured Stalwart server is asked `GET /api/live/delivery/{email}`
//! (Manage → Troubleshoot → Email Delivery). The stream reports MX / TLS /
//! SMTP stages and ends with `completed`. A mailbox is accepted only when
//! some server reports `rcptToSuccess`. `rcptToError` means skip that
//! address so it never hits the upstream SMTP pool.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use serde_json::Value;
use tokio::sync::Semaphore;

use crate::config::{ValidationConfig, ValidationServer, YahooEndpoint, YahooValidationConfig};

static YAHOO_RR: AtomicUsize = AtomicUsize::new(0);

const YAHOO_DOMAINS: &[&str] = &[
    "yahoo.com",
    "yahoo.co.uk",
    "yahoo.co.in",
    "yahoo.co.jp",
    "yahoo.com.au",
    "yahoo.com.br",
    "yahoo.com.mx",
    "yahoo.com.ar",
    "yahoo.com.sg",
    "yahoo.ca",
    "yahoo.de",
    "yahoo.fr",
    "yahoo.es",
    "yahoo.it",
    "yahoo.in",
    "ymail.com",
    "rocketmail.com",
    "myyahoo.com",
    "yahoo.com.tw",
];

const AOL_DOMAINS: &[&str] = &[
    "aol.com",
    "aol.co.uk",
    "aol.de",
    "aol.fr",
    "aol.in",
    "aim.com",
    "wow.com",
    "netscape.net",
    "love.com",
    "games.com",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Remote MX accepted `RCPT TO`.
    Acceptable { server: String },
    /// Remote MX rejected the mailbox (invalid / unknown user).
    InvalidMailbox { server: String, reason: String },
    /// This Stalwart instance could not complete the probe.
    ProbeFailed { server: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientCheck {
    pub address: String,
    pub deliver: bool,
    pub detail: String,
}

/// Filters `recipients` to those the configured probes will accept.
pub async fn filter_recipients(
    config: &ValidationConfig,
    recipients: &[String],
) -> Vec<RecipientCheck> {
    if !config.enabled || !config.has_any_channel() {
        return recipients
            .iter()
            .map(|address| RecipientCheck {
                address: address.clone(),
                deliver: true,
                detail: "validation disabled".into(),
            })
            .collect();
    }

    let timeout = Duration::from_secs(config.timeout_seconds.max(1));
    let client = http_client(timeout);
    let yahoo_endpoints = config.yahoo_endpoints();
    let yahoo_slots = Arc::new(Semaphore::new(
        config.yahoo.concurrency.max(1).min(32) as usize,
    ));
    futures_util::future::join_all(recipients.iter().map(|address| {
        let client = &client;
        let yahoo_slots = yahoo_slots.clone();
        let yahoo_on = !yahoo_endpoints.is_empty();
        async move {
            if yahoo_on && is_yahoo_address(address, &config.yahoo.extra_domains) {
                let _permit = yahoo_slots.acquire().await.expect("yahoo semaphore");
            }
            check_recipient(client, config, address, timeout).await
        }
    }))
    .await
}

async fn check_recipient(
    client: &reqwest::Client,
    config: &ValidationConfig,
    address: &str,
    timeout: Duration,
) -> RecipientCheck {
    if is_yahoo_address(address, &config.yahoo.extra_domains) {
        let endpoints = config.yahoo_endpoints();
        if !endpoints.is_empty() {
            return check_yahoo(client, &endpoints, address, config.allow_on_probe_error()).await;
        }
        if config.usable().next().is_none() {
            return RecipientCheck {
                address: address.to_string(),
                deliver: config.allow_on_probe_error(),
                detail: if config.allow_on_probe_error() {
                    "yahoo address but Yahoo API is off, sending anyway".into()
                } else {
                    "yahoo address but Yahoo API is off, skipped".into()
                },
            };
        }
        // Yahoo API off: do not use Stalwart (it always accepts Yahoo).
        return RecipientCheck {
            address: address.to_string(),
            deliver: config.allow_on_probe_error(),
            detail: if config.allow_on_probe_error() {
                "yahoo address, Stalwart skipped (catch-all), sending anyway".into()
            } else {
                "yahoo address, Stalwart skipped (catch-all), skipped".into()
            },
        };
    }

    if config.usable().next().is_none() {
        return RecipientCheck {
            address: address.to_string(),
            deliver: true,
            detail: "no Stalwart server configured".into(),
        };
    }

    let servers: Vec<_> = config.usable().cloned().collect();
    let mut tasks = Vec::with_capacity(servers.len());
    for server in servers {
        let client = client.clone();
        let address = address.to_string();
        tasks.push(tokio::spawn(async move {
            probe_server(&client, &server, &address, timeout).await
        }));
    }

    let mut outcomes = Vec::new();
    for task in tasks {
        match task.await {
            Ok(outcome) => outcomes.push(outcome),
            Err(error) => outcomes.push(ProbeOutcome::ProbeFailed {
                server: "join".into(),
                reason: error.to_string(),
            }),
        }
    }

    decide(address, &outcomes, config.allow_on_probe_error())
}

/// True for yahoo.com, ymail.com, rocketmail.com, aol.com, and extra_domains.
pub fn is_yahoo_address(address: &str, extra_domains: &[String]) -> bool {
    let Some((_, domain)) = address.rsplit_once('@') else {
        return false;
    };
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return false;
    }
    YAHOO_DOMAINS
        .iter()
        .chain(AOL_DOMAINS.iter())
        .any(|known| domain_matches(&domain, known))
        || extra_domains
            .iter()
            .any(|known| domain_matches(&domain, known.trim().to_ascii_lowercase().as_str()))
}

fn domain_matches(domain: &str, known: &str) -> bool {
    let known = known.trim().trim_start_matches('.').to_ascii_lowercase();
    if known.is_empty() {
        return false;
    }
    domain == known || domain.ends_with(&format!(".{known}"))
}

fn rotate_yahoo(endpoints: &[YahooEndpoint]) -> Vec<YahooEndpoint> {
    if endpoints.len() <= 1 {
        return endpoints.to_vec();
    }
    let start = YAHOO_RR.fetch_add(1, Ordering::Relaxed) % endpoints.len();
    endpoints
        .iter()
        .cycle()
        .skip(start)
        .take(endpoints.len())
        .cloned()
        .collect()
}

async fn check_yahoo(
    client: &reqwest::Client,
    endpoints: &[YahooEndpoint],
    address: &str,
    allow_on_probe_error: bool,
) -> RecipientCheck {
    let ordered = rotate_yahoo(endpoints);
    let mut errors = Vec::new();
    for endpoint in &ordered {
        let yahoo = endpoint.as_config(&YahooValidationConfig {
            concurrency: 1,
            ..YahooValidationConfig::default()
        });
        match call_yahoo_api(client, &yahoo, address).await {
            Ok(outcome) => {
                tracing::info!(
                    email = %address,
                    id = %endpoint.id,
                    url = %endpoint.url,
                    validated = outcome.validated,
                    "yahoo verify"
                );
                let detail = if endpoints.len() > 1 {
                    format!("{} via `{}`", outcome.detail, endpoint.id)
                } else {
                    outcome.detail
                };
                return RecipientCheck {
                    address: address.to_string(),
                    deliver: outcome.validated,
                    detail,
                };
            }
            Err(reason) => errors.push(format!("{}: {reason}", endpoint.id)),
        }
    }
    let joined = errors.join("; ");
    RecipientCheck {
        address: address.to_string(),
        deliver: allow_on_probe_error,
        detail: if allow_on_probe_error {
            format!("yahoo API error, sending anyway ({joined})")
        } else {
            format!("yahoo API error, skipped ({joined})")
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YahooApiOutcome {
    pub validated: bool,
    pub detail: String,
}

/// Calls the Yahoo verifier. Reads `validate` / `valid` / `validated`.
pub async fn call_yahoo_api(
    client: &reqwest::Client,
    yahoo: &YahooValidationConfig,
    address: &str,
) -> Result<YahooApiOutcome, String> {
    let url = yahoo_request_url(&yahoo.url, address);
    let mut request = if yahoo.method() == "GET" {
        client.get(&url)
    } else {
        client
            .post(&url)
            .json(&serde_json::json!({ "email": address }))
    };
    request = request.header("Accept", "application/json");
    if !yahoo.api_key.trim().is_empty() {
        request = request.bearer_auth(yahoo.api_key.trim());
    }

    let response = request
        .send()
        .await
        .map_err(|error| format!("could not reach Yahoo API: {error}"))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let value = serde_json::from_str::<Value>(&body).ok();
    if !status.is_success() {
        let hint = value
            .as_ref()
            .and_then(yahoo_error_text)
            .unwrap_or_else(|| body.chars().take(180).collect::<String>());
        return Err(format!("HTTP {status} {hint}"));
    }
    let value = value.ok_or_else(|| {
        format!(
            "Yahoo API did not return JSON: {}",
            body.chars().take(180).collect::<String>()
        )
    })?;
    interpret_yahoo_json(&value)
}

fn interpret_yahoo_json(value: &Value) -> Result<YahooApiOutcome, String> {
    let note = yahoo_error_text(value);
    if field_bool(value, "fail") == Some(true) {
        return Err(note.unwrap_or_else(|| "fail: true".into()));
    }
    if field_bool(value, "ok") == Some(false) {
        return Err(note.unwrap_or_else(|| "ok: false".into()));
    }
    let Some(validated) = read_validated(value) else {
        return Err(note.unwrap_or_else(|| {
            format!(
                "Yahoo API JSON has no validate/valid/validated field: {}",
                value.to_string().chars().take(180).collect::<String>()
            )
        }));
    };
    let detail = match (validated, note) {
        (true, Some(text)) => format!("yahoo API validate: true ({text})"),
        (true, None) => "yahoo API validate: true".into(),
        (false, Some(text)) => format!("yahoo API validate: false ({text})"),
        (false, None) => "yahoo API validate: false".into(),
    };
    Ok(YahooApiOutcome { validated, detail })
}

fn yahoo_error_text(value: &Value) -> Option<String> {
    json_text_field(value, &["error", "message", "detail", "reason"])
}

fn json_text_field(value: &Value, keys: &[&str]) -> Option<String> {
    let Value::Object(map) = value else {
        return None;
    };
    for (key, child) in map {
        if !keys.iter().any(|want| key.eq_ignore_ascii_case(want)) {
            continue;
        }
        match child {
            Value::Null => continue,
            Value::String(text) => {
                let text = text.trim();
                if !text.is_empty() && !text.eq_ignore_ascii_case("null") {
                    return Some(text.to_string());
                }
            }
            Value::Bool(_) => continue,
            other => {
                let text = other.to_string();
                if text != "null" {
                    return Some(text);
                }
            }
        }
    }
    None
}

fn field_bool(value: &Value, name: &str) -> Option<bool> {
    let Value::Object(map) = value else {
        return None;
    };
    map.iter().find_map(|(key, child)| {
        key.eq_ignore_ascii_case(name).then(|| json_bool(child)).flatten()
    })
}

fn yahoo_request_url(template: &str, address: &str) -> String {
    let base = template.trim();
    if base.contains("{email}") {
        return base.replace("{email}", &encode_path(address));
    }
    base.trim_end_matches('/').to_string()
}

const VALID_KEYS: &[&str] = &[
    "validate",
    "validated",
    "valid",
    "is_valid",
    "isvalid",
    "deliverable",
];

const STATUS_KEYS: &[&str] = &["status", "result", "verdict", "state", "quality"];

fn read_validated(value: &Value) -> Option<bool> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if VALID_KEYS.iter().any(|want| key.eq_ignore_ascii_case(want)) {
                    if let Some(found) = json_bool(child) {
                        return Some(found);
                    }
                    if let Some(found) = status_bool(child) {
                        return Some(found);
                    }
                }
            }
            for (key, child) in map {
                if STATUS_KEYS.iter().any(|want| key.eq_ignore_ascii_case(want)) {
                    if let Some(found) = status_bool(child).or_else(|| json_bool(child)) {
                        return Some(found);
                    }
                }
            }
            for (key, child) in map {
                if key.eq_ignore_ascii_case("data")
                    || key.eq_ignore_ascii_case("response")
                    || key.eq_ignore_ascii_case("payload")
                {
                    if let Some(found) = read_validated(child) {
                        return Some(found);
                    }
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(read_validated),
        _ => None,
    }
}

fn json_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::Number(n) => n.as_i64().map(|n| n != 0),
        Value::String(text) => status_bool(value).or_else(|| match text.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Some(true),
            "false" | "no" | "0" => Some(false),
            _ => None,
        }),
        _ => None,
    }
}

fn status_bool(value: &Value) -> Option<bool> {
    let text = match value {
        Value::String(text) => text.trim().to_ascii_lowercase(),
        Value::Bool(flag) => return Some(*flag),
        Value::Number(n) => return n.as_i64().map(|n| n != 0),
        _ => return None,
    };
    match text.replace('-', "_").as_str() {
        "valid" | "validated" | "true" | "yes" | "ok" | "deliverable" | "safe" | "good"
        | "safe_to_send" => Some(true),
        "invalid" | "false" | "no" | "undeliverable" | "bounce" | "unknown" | "do_not_mail"
        | "spamtrap" | "abuse" | "disposable" | "error" => Some(false),
        _ => None,
    }
}

fn decide(address: &str, outcomes: &[ProbeOutcome], allow_on_probe_error: bool) -> RecipientCheck {
    if let Some(ok) = outcomes.iter().find_map(|outcome| match outcome {
        ProbeOutcome::Acceptable { server } => Some(server.as_str()),
        _ => None,
    }) {
        return RecipientCheck {
            address: address.to_string(),
            deliver: true,
            detail: format!("delivery test ok via `{ok}`"),
        };
    }

    if let Some((server, reason)) = outcomes.iter().find_map(|outcome| match outcome {
        ProbeOutcome::InvalidMailbox { server, reason } => Some((server.as_str(), reason.as_str())),
        _ => None,
    }) {
        return RecipientCheck {
            address: address.to_string(),
            deliver: false,
            detail: format!("invalid via `{server}`: {reason}"),
        };
    }

    let reasons = outcomes
        .iter()
        .map(|outcome| match outcome {
            ProbeOutcome::ProbeFailed { server, reason } => format!("{server}: {reason}"),
            other => format!("{other:?}"),
        })
        .collect::<Vec<_>>()
        .join("; ");

    RecipientCheck {
        address: address.to_string(),
        deliver: allow_on_probe_error,
        detail: if allow_on_probe_error {
            format!("probe error, sending anyway ({reasons})")
        } else {
            format!("probe error, skipped ({reasons})")
        },
    }
}

async fn probe_server(
    client: &reqwest::Client,
    server: &ValidationServer,
    address: &str,
    timeout: Duration,
) -> ProbeOutcome {
    let url = delivery_url(&server.base_url, address, timeout.as_secs());
    let request = authorize(
        client
            .get(&url)
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache"),
        server,
    );

    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            return ProbeOutcome::ProbeFailed {
                server: server.id.clone(),
                reason: error.to_string(),
            };
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let reason = match status.as_u16() {
            401 => "wrong username or password".into(),
            403 => "account lacks LiveDeliveryTest permission".into(),
            _ => format!("HTTP {status} {}", body.chars().take(180).collect::<String>()),
        };
        return ProbeOutcome::ProbeFailed {
            server: server.id.clone(),
            reason,
        };
    }

    let mut leftover = String::new();
    let mut last_hint = String::new();
    let mut rcpt_error: Option<String> = None;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(bytes) => bytes,
            Err(error) => {
                return ProbeOutcome::ProbeFailed {
                    server: server.id.clone(),
                    reason: error.to_string(),
                };
            }
        };
        leftover.push_str(&String::from_utf8_lossy(&bytes));
        for stage in take_sse_stages(&mut leftover) {
            match classify_stage(&stage) {
                StageClass::Acceptable => {
                    return ProbeOutcome::Acceptable {
                        server: server.id.clone(),
                    };
                }
                StageClass::InvalidMailbox(reason) => {
                    // First MX may reject; later hosts can still accept.
                    rcpt_error = Some(reason);
                }
                StageClass::Done => {
                    return finish_probe(&server.id, rcpt_error, &last_hint);
                }
                StageClass::Continue => {
                    if let Some(hint) = stage_error_hint(&stage) {
                        last_hint = hint;
                    }
                }
            }
        }
    }

    finish_probe(&server.id, rcpt_error, &last_hint)
}

fn finish_probe(
    server: &str,
    rcpt_error: Option<String>,
    last_hint: &str,
) -> ProbeOutcome {
    if let Some(reason) = rcpt_error {
        return ProbeOutcome::InvalidMailbox {
            server: server.to_string(),
            reason,
        };
    }
    ProbeOutcome::ProbeFailed {
        server: server.to_string(),
        reason: if last_hint.is_empty() {
            "completed without RCPT TO".into()
        } else {
            format!("completed without RCPT TO ({last_hint})")
        },
    }
}

/// Confirms Stalwart admin credentials and `LiveDeliveryTest` permission.
pub async fn verify_credentials(server: &ValidationServer) -> Result<String, String> {
    let base = server.base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("base URL is empty".into());
    }
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err("base URL must start with http:// or https://".into());
    }
    if server.token.trim().is_empty() && server.username.trim().is_empty() {
        return Err("enter the Stalwart admin username and password".into());
    }

    let client = http_client(Duration::from_secs(12));
    let url = format!("{base}/api/token/delivery");
    let request = authorize(client.get(&url), server);
    let response = request
        .send()
        .await
        .map_err(|error| format!("could not reach {base}: {error}"))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let snippet = body.chars().take(180).collect::<String>();

    match status.as_u16() {
        200 => Ok("login ok — LiveDeliveryTest permission is present".into()),
        401 => Err("wrong username or password".into()),
        403 => Err("logged in, but this account lacks LiveDeliveryTest permission".into()),
        404 => Err("this Stalwart build has no /api/token/delivery endpoint".into()),
        other => Err(format!("HTTP {other} {snippet}")),
    }
}

fn authorize(request: reqwest::RequestBuilder, server: &ValidationServer) -> reqwest::RequestBuilder {
    if !server.token.trim().is_empty() {
        request.bearer_auth(server.token.trim())
    } else if !server.username.trim().is_empty() {
        request.basic_auth(server.username.trim(), Some(server.password.as_str()))
    } else {
        request
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StageClass {
    Acceptable,
    InvalidMailbox(String),
    Done,
    Continue,
}

fn classify_stage(stage: &Value) -> StageClass {
    let typ = stage.get("type").and_then(Value::as_str).unwrap_or("");
    let reason = stage
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or(typ)
        .to_string();
    match typ {
        // Only RCPT TO is a mailbox verdict. TLSA/DANE/MTA-STS errors are
        // path noise — Stalwart still continues to SMTP after "Bogus TLSA".
        "rcptToSuccess" => StageClass::Acceptable,
        "rcptToError" => StageClass::InvalidMailbox(reason),
        "completed" => StageClass::Done,
        _ => StageClass::Continue,
    }
}

fn stage_error_hint(stage: &Value) -> Option<String> {
    let typ = stage.get("type").and_then(Value::as_str)?;
    if !(typ.ends_with("Error") || typ.ends_with("Failed")) {
        return None;
    }
    let reason = stage.get("reason").and_then(Value::as_str).unwrap_or(typ);
    Some(format!("{typ}: {reason}"))
}

fn take_sse_stages(buffer: &mut String) -> Vec<Value> {
    if buffer.contains('\r') {
        *buffer = buffer.replace("\r\n", "\n").replace('\r', "\n");
    }
    let mut stages = Vec::new();
    while let Some(split) = buffer.find("\n\n") {
        let frame = buffer[..split].to_string();
        buffer.replace_range(..split + 2, "");
        for line in frame.lines() {
            let line = line.trim();
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() || data == "{}" {
                continue;
            }
            match serde_json::from_str::<Value>(data) {
                Ok(Value::Array(items)) => stages.extend(items),
                Ok(Value::Object(map)) => stages.push(Value::Object(map)),
                _ => {}
            }
        }
    }
    stages
}

fn delivery_url(base: &str, address: &str, timeout_secs: u64) -> String {
    let base = base.trim().trim_end_matches('/');
    format!(
        "{base}/api/live/delivery/{}?timeout={}",
        encode_path(address),
        timeout_secs.max(1)
    )
}

fn encode_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn http_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(8))
        .timeout(timeout + Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage_reason(typ: &str, reason: &str) -> Value {
        serde_json::json!({ "type": typ, "reason": reason, "elapsed": 1 })
    }

    #[test]
    fn sse_frames_unwrap_array_payload() {
        let mut buf = "event: event\ndata: [{\"type\":\"rcptToStart\"}]\n\n\
event: event\ndata: [{\"type\":\"rcptToSuccess\",\"elapsed\":9}]\n\n"
            .to_string();
        let stages = take_sse_stages(&mut buf);
        assert_eq!(stages[0]["type"], "rcptToStart");
        assert_eq!(classify_stage(&stages[1]), StageClass::Acceptable);
    }

    #[test]
    fn rcpt_error_is_an_invalid_mailbox() {
        assert_eq!(
            classify_stage(&stage_reason("rcptToError", "550 5.1.1 user unknown")),
            StageClass::InvalidMailbox("550 5.1.1 user unknown".into())
        );
    }

    #[test]
    fn tlsa_and_dane_errors_are_not_mailbox_verdicts() {
        assert_eq!(
            classify_stage(&stage_reason("tlsaLookupError", "Bogus TLSA record")),
            StageClass::Continue
        );
        assert_eq!(
            classify_stage(&stage_reason("daneVerifyError", "no match")),
            StageClass::Continue
        );
        assert_eq!(
            classify_stage(&stage_reason("connectionError", "refused")),
            StageClass::Continue
        );
    }

    #[test]
    fn crlf_sse_frames_are_parsed() {
        let mut buf =
            "event: event\r\ndata: [{\"type\":\"rcptToSuccess\",\"elapsed\":9}]\r\n\r\n".to_string();
        let stages = take_sse_stages(&mut buf);
        assert_eq!(classify_stage(&stages[0]), StageClass::Acceptable);
    }

    #[test]
    fn final_rcpt_error_is_used_after_path_noise() {
        let outcome = finish_probe(
            "sw1",
            Some("550 no such user".into()),
            "tlsaLookupError: Bogus TLSA record",
        );
        assert_eq!(
            outcome,
            ProbeOutcome::InvalidMailbox {
                server: "sw1".into(),
                reason: "550 no such user".into(),
            }
        );
    }

    #[test]
    fn path_error_without_rcpt_is_not_an_invalid_mailbox() {
        let outcome = finish_probe("sw1", None, "tlsaLookupError: Bogus TLSA record");
        match outcome {
            ProbeOutcome::ProbeFailed { reason, .. } => {
                assert!(reason.contains("Bogus TLSA"));
            }
            other => panic!("expected probe failed, got {other:?}"),
        }
    }

    #[test]
    fn first_success_wins_across_servers() {
        let check = decide(
            "lead@gmail.com",
            &[
                ProbeOutcome::ProbeFailed {
                    server: "a".into(),
                    reason: "timeout".into(),
                },
                ProbeOutcome::Acceptable {
                    server: "b".into(),
                },
            ],
            false,
        );
        assert!(check.deliver);
        assert!(check.detail.contains("`b`"));
    }

    #[test]
    fn invalid_mailbox_skips_the_address() {
        let check = decide(
            "nobody@gmail.com",
            &[ProbeOutcome::InvalidMailbox {
                server: "s1".into(),
                reason: "550 no such user".into(),
            }],
            true,
        );
        assert!(!check.deliver);
        assert!(check.detail.contains("550"));
    }

    #[test]
    fn probe_errors_can_fail_open() {
        let check = decide(
            "lead@gmail.com",
            &[ProbeOutcome::ProbeFailed {
                server: "s1".into(),
                reason: "connection refused".into(),
            }],
            true,
        );
        assert!(check.deliver);
    }

    #[test]
    fn delivery_url_encodes_the_mailbox() {
        assert_eq!(
            delivery_url("https://mail.example.com/", "a+b@x.io", 20),
            "https://mail.example.com/api/live/delivery/a%2Bb%40x.io?timeout=20"
        );
    }

    #[test]
    fn yahoo_domains_are_routed_separately() {
        assert!(is_yahoo_address("lead@yahoo.com", &[]));
        assert!(is_yahoo_address("Lead@Yahoo.CO.UK", &[]));
        assert!(is_yahoo_address("x@ymail.com", &[]));
        assert!(is_yahoo_address("x@rocketmail.com", &[]));
        assert!(is_yahoo_address("x@aol.com", &[]));
        assert!(is_yahoo_address("x@mail.yahoo.com", &[]));
        assert!(is_yahoo_address("x@myyahoo.com", &[]));
        assert!(is_yahoo_address("x@wow.com", &[]));
        assert!(is_yahoo_address("x@netscape.net", &[]));
        assert!(is_yahoo_address("x@aol.co.uk", &[]));
        assert!(is_yahoo_address("x@love.com", &[]));
        assert!(!is_yahoo_address("lead@gmail.com", &[]));
        assert!(is_yahoo_address(
            "x@custom-yahoo.test",
            &["custom-yahoo.test".into()]
        ));
    }

    #[test]
    fn yahoo_json_reads_validated_true_false() {
        assert_eq!(
            read_validated(&serde_json::json!({ "validate": true })),
            Some(true)
        );
        assert_eq!(
            read_validated(&serde_json::json!({ "validate": false })),
            Some(false)
        );
        assert_eq!(
            read_validated(&serde_json::json!({ "valid": true })),
            Some(true)
        );
        assert_eq!(
            read_validated(&serde_json::json!({ "Valid": "True" })),
            Some(true)
        );
        assert_eq!(
            read_validated(&serde_json::json!({ "validated": "False" })),
            Some(false)
        );
        assert_eq!(
            read_validated(&serde_json::json!({ "data": { "valid": false } })),
            Some(false)
        );
        assert_eq!(
            read_validated(&serde_json::json!({ "status": "valid" })),
            Some(true)
        );
        assert_eq!(
            read_validated(&serde_json::json!({ "result": "invalid" })),
            Some(false)
        );
        assert_eq!(
            read_validated(&serde_json::json!({ "ok": true, "count": 1 })),
            None
        );
    }

    #[test]
    fn yahoo_script_payloads_use_validate_and_message() {
        let exists = interpret_yahoo_json(&serde_json::json!({
            "ok": true,
            "fail": false,
            "validate": true,
            "error": null,
            "message": "Address already exists"
        }))
        .unwrap();
        assert!(exists.validated);
        assert!(exists.detail.contains("Address already exists"));

        let missing = interpret_yahoo_json(&serde_json::json!({
            "ok": true,
            "fail": false,
            "validate": false,
            "error": null,
            "message": "Address does not exist yet"
        }))
        .unwrap();
        assert!(!missing.validated);
        assert!(missing.detail.contains("Address does not exist yet"));

        let failed = interpret_yahoo_json(&serde_json::json!({
            "ok": false,
            "fail": true,
            "validate": false,
            "error": "proxy timeout",
            "message": "could not reach yahoo"
        }));
        assert!(failed.unwrap_err().contains("proxy timeout"));
    }

    #[test]
    fn yahoo_url_substitutes_email() {
        assert_eq!(
            yahoo_request_url("https://api.example.com/v?email={email}", "a@yahoo.com"),
            "https://api.example.com/v?email=a%40yahoo.com"
        );
        assert_eq!(
            yahoo_request_url("https://api.example.com/check/", "a@yahoo.com"),
            "https://api.example.com/check"
        );
    }
}
