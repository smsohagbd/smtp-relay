//! Pre-send recipient checks via Stalwart's delivery-test API.
//!
//! Each configured Stalwart server is asked `GET /api/live/delivery/{email}`
//! (Manage → Troubleshoot → Email Delivery). The stream reports MX / TLS /
//! SMTP stages and ends with `completed`. A mailbox is accepted only when
//! some server reports `rcptToSuccess`. `rcptToError` means skip that
//! address so it never hits the upstream SMTP pool.

use std::time::Duration;

use futures_util::StreamExt;
use serde_json::Value;

use crate::config::{ValidationConfig, ValidationServer};

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

/// Filters `recipients` to those the Stalwart probes will accept.
pub async fn filter_recipients(
    config: &ValidationConfig,
    recipients: &[String],
) -> Vec<RecipientCheck> {
    if !config.enabled || config.usable().next().is_none() {
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
    futures_util::future::join_all(
        recipients
            .iter()
            .map(|address| check_recipient(&client, config, address, timeout)),
    )
    .await
}

async fn check_recipient(
    client: &reqwest::Client,
    config: &ValidationConfig,
    address: &str,
    timeout: Duration,
) -> RecipientCheck {
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
}
