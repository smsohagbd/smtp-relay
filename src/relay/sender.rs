//! Outbound SMTP client.
//!
//! One `AsyncSmtpTransport` is built per relay and reused for the lifetime of
//! the configuration generation, which lets lettre keep connections pooled
//! instead of paying the TCP + TLS + AUTH cost on every message.

use std::time::{Duration, Instant};

use lettre::address::Envelope;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls as SmtpTls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::transport::smtp::Error as SmtpError;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

use crate::config::{RelayConfig, TlsMode};
use crate::error::DeliveryError;
use crate::relay::pool::RelayRuntime;
use crate::relay::Transport;
use crate::util::{rfc5322_date_now, truncate};

/// Constructs the reusable transport for a relay. `fallback_timeout_seconds`
/// is `server.timeout_seconds`, used when the relay does not set its own.
pub fn build_transport(
    config: &RelayConfig,
    fallback_timeout_seconds: u64,
) -> Result<Transport, String> {
    if config.host.trim().is_empty() {
        return Err("host must not be empty".to_string());
    }

    let timeout = Duration::from_secs(
        config
            .timeout_seconds
            .unwrap_or(fallback_timeout_seconds)
            .max(1),
    );

    // `builder_dangerous` only means "do not assume TLS"; the TLS mode is set
    // explicitly below, which keeps all four modes on one code path.
    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
        .port(config.port)
        .timeout(Some(timeout))
        .tls(build_tls(config)?);

    if let Some(helo) = &config.helo_name {
        if !helo.trim().is_empty() {
            builder = builder.hello_name(ClientId::Domain(helo.trim().to_string()));
        }
    }

    if let Some(auth) = &config.auth {
        builder = builder
            .credentials(Credentials::new(
                auth.username.clone(),
                auth.password.clone(),
            ))
            .authentication(mechanisms_for(auth.mechanism.as_deref()));
    }

    Ok(builder.build())
}

fn mechanisms_for(requested: Option<&str>) -> Vec<Mechanism> {
    match requested.map(|m| m.to_ascii_lowercase()).as_deref() {
        Some("plain") => vec![Mechanism::Plain],
        Some("login") => vec![Mechanism::Login],
        Some("xoauth2") => vec![Mechanism::Xoauth2],
        // Offer PLAIN first, then LOGIN: between them they cover essentially
        // every hosted relay, and lettre picks whatever the server advertises.
        _ => vec![Mechanism::Plain, Mechanism::Login],
    }
}

fn build_tls(config: &RelayConfig) -> Result<SmtpTls, String> {
    if config.tls == TlsMode::None {
        return Ok(SmtpTls::None);
    }

    let mut parameters = TlsParameters::builder(config.host.trim().to_string());
    if config.allow_invalid_certs {
        parameters = parameters
            .dangerous_accept_invalid_certs(true)
            .dangerous_accept_invalid_hostnames(true);
    }

    #[cfg(feature = "tls-native")]
    let parameters = parameters
        .build()
        .map_err(|error| format!("could not initialise TLS: {error}"))?;

    #[cfg(all(feature = "tls-rustls", not(feature = "tls-native")))]
    let parameters = parameters
        .build_rustls()
        .map_err(|error| format!("could not initialise TLS: {error}"))?;

    #[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
    let parameters: TlsParameters = {
        let _ = parameters;
        return Err(
            "this binary was built without a TLS backend; enable the `tls-native` or `tls-rustls` feature"
                .to_string(),
        );
    };

    Ok(match config.tls {
        TlsMode::StartTls => SmtpTls::Required(parameters),
        TlsMode::Tls => SmtpTls::Wrapper(parameters),
        TlsMode::Opportunistic => SmtpTls::Opportunistic(parameters),
        TlsMode::None => SmtpTls::None,
    })
}

/// A successful upstream handoff.
#[derive(Debug, Clone)]
pub struct DeliveryReport {
    pub latency: Duration,
    /// Upstream response line, e.g. `250 2.0.0 OK 1a2b3c`.
    pub response: String,
}

/// Hands `raw` to the relay with an envelope aligned to the relay's identity.
///
/// `envelope_from` is deliberately a parameter rather than read from the
/// message: SPF checks the envelope, not the header, so the caller must pass
/// the relay's own address.
pub async fn deliver(
    relay: &RelayRuntime,
    envelope_from: &str,
    recipients: &[String],
    raw: &[u8],
) -> Result<DeliveryReport, DeliveryError> {
    let envelope = build_envelope(envelope_from, recipients)?;
    let started = Instant::now();

    match relay.transport().send_raw(&envelope, raw).await {
        Ok(response) => Ok(DeliveryReport {
            latency: started.elapsed(),
            response: describe_response(&response),
        }),
        Err(error) => Err(classify(&error)),
    }
}

fn build_envelope(
    envelope_from: &str,
    recipients: &[String],
) -> Result<Envelope, DeliveryError> {
    if recipients.is_empty() {
        return Err(DeliveryError::permanent("message has no recipients"));
    }

    let from: Address = envelope_from.parse().map_err(|error| {
        DeliveryError::permanent(format!(
            "relay from_address `{envelope_from}` is not a valid envelope sender: {error}"
        ))
    })?;

    let mut to = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let address: Address = recipient.parse().map_err(|error| {
            DeliveryError::permanent(format!("recipient `{recipient}` is invalid: {error}"))
        })?;
        to.push(address);
    }

    Envelope::new(Some(from), to)
        .map_err(|error| DeliveryError::permanent(format!("invalid envelope: {error}")))
}

/// Connects, greets and disconnects, without sending mail.
pub async fn probe(relay: &RelayRuntime) -> Result<Duration, DeliveryError> {
    let started = Instant::now();
    match relay.transport().test_connection().await {
        Ok(true) => Ok(started.elapsed()),
        Ok(false) => Err(DeliveryError::transient(
            "relay did not accept the connection test",
        )),
        Err(error) => Err(classify(&error)),
    }
}

fn describe_response(response: &lettre::transport::smtp::response::Response) -> String {
    let text = response.message().collect::<Vec<&str>>().join(" ");
    let code = response.code();
    let rendered = format!("{code} {text}");
    truncate(rendered.trim(), 300)
}

/// Maps a lettre SMTP error onto a retry decision.
fn classify(error: &SmtpError) -> DeliveryError {
    let message = truncate(&error.to_string(), 400);
    let code = extract_status_code(&message);

    let mut delivery_error = if error.is_permanent() {
        DeliveryError::permanent(message)
    } else {
        // Transport-level problems (DNS, TCP, TLS, timeout) are not marked
        // permanent by lettre and are exactly the case retries exist for.
        DeliveryError::transient(message)
    };

    if let Some(code) = code {
        delivery_error = delivery_error.with_status(code);
    }
    delivery_error
}

/// Pulls a leading three-digit SMTP status code out of an error string.
fn extract_status_code(message: &str) -> Option<u16> {
    let bytes = message.as_bytes();
    for window in 0..bytes.len().saturating_sub(2) {
        let candidate = &bytes[window..window + 3];
        if candidate.iter().all(|b| b.is_ascii_digit()) {
            let leading_ok = window == 0 || !bytes[window - 1].is_ascii_alphanumeric();
            let trailing_ok = window + 3 >= bytes.len() || !bytes[window + 3].is_ascii_digit();
            if leading_ok && trailing_ok {
                let code: u16 = message[window..window + 3].parse().ok()?;
                if (200..=599).contains(&code) {
                    return Some(code);
                }
            }
        }
    }
    None
}

/// Builds a small, valid test message for the dashboard's "send test" action.
pub fn build_test_message(
    relay: &RelayConfig,
    hostname: &str,
    recipient: &str,
    subject: &str,
    body: &str,
    queue_id: &str,
) -> Vec<u8> {
    let from_address = relay.effective_from_address();
    let from = crate::util::format_mailbox("SMTP Relay", &from_address);
    let domain = crate::util::address_domain(&from_address);

    let mut out = String::with_capacity(body.len() + 512);
    out.push_str(&format!("From: {from}\r\n"));
    out.push_str(&format!("To: <{recipient}>\r\n"));
    out.push_str(&format!(
        "Subject: {}\r\n",
        crate::util::encode_display_name(subject).trim_matches('"')
    ));
    out.push_str(&format!("Date: {}\r\n", rfc5322_date_now()));
    out.push_str(&format!("Message-ID: <{queue_id}@{domain}>\r\n"));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    out.push_str("Auto-Submitted: auto-generated\r\n");
    out.push_str(&format!("X-Relay-Node: {}\r\n", relay.id));
    out.push_str(&format!("X-Relay-Origin: {hostname}\r\n"));
    out.push_str("\r\n");

    // Dot-stuffing is handled by the SMTP client, but normalising line endings
    // here keeps the message well formed regardless of what the API sent.
    for line in body.split('\n') {
        out.push_str(line.trim_end_matches('\r'));
        out.push_str("\r\n");
    }

    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;

    fn relay_config() -> RelayConfig {
        RelayConfig {
            id: "relay_node_1".to_string(),
            host: "smtp.domain1.com".to_string(),
            port: 587,
            from_address: "noreply@domain1.com".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn transports_build_for_every_tls_mode() {
        for mode in [
            TlsMode::None,
            TlsMode::StartTls,
            TlsMode::Tls,
            TlsMode::Opportunistic,
        ] {
            let config = RelayConfig {
                tls: mode,
                ..relay_config()
            };
            assert!(
                build_transport(&config, 30).is_ok(),
                "failed to build for {:?}",
                mode
            );
        }
    }

    #[test]
    fn transport_builds_with_credentials_and_helo() {
        let config = RelayConfig {
            auth: Some(AuthConfig {
                username: "mailer@domain1.com".to_string(),
                password: "secret".to_string(),
                mechanism: Some("login".to_string()),
            }),
            helo_name: Some("proxy.acme.io".to_string()),
            ..relay_config()
        };
        assert!(build_transport(&config, 30).is_ok());
    }

    #[test]
    fn empty_host_is_rejected() {
        let config = RelayConfig {
            host: "  ".to_string(),
            ..relay_config()
        };
        assert!(build_transport(&config, 30).is_err());
    }

    #[test]
    fn mechanism_selection_maps_config_values() {
        assert_eq!(mechanisms_for(Some("plain")), vec![Mechanism::Plain]);
        assert_eq!(mechanisms_for(Some("LOGIN")), vec![Mechanism::Login]);
        assert_eq!(mechanisms_for(Some("xoauth2")), vec![Mechanism::Xoauth2]);
        assert_eq!(
            mechanisms_for(None),
            vec![Mechanism::Plain, Mechanism::Login]
        );
    }

    #[test]
    fn envelope_requires_recipients_and_valid_addresses() {
        assert!(build_envelope("a@b.io", &[]).is_err());
        assert!(build_envelope("not-an-address", &["a@b.io".to_string()]).is_err());
        assert!(build_envelope("a@b.io", &["nope".to_string()]).is_err());
        assert!(build_envelope("a@b.io", &["c@d.io".to_string()]).is_ok());
    }

    #[test]
    fn status_codes_are_extracted_from_error_text() {
        assert_eq!(
            extract_status_code("permanent error (550): 5.7.1 relay denied"),
            Some(550)
        );
        assert_eq!(extract_status_code("transient error: 421 too busy"), Some(421));
        assert_eq!(extract_status_code("connection refused"), None);
        assert_eq!(extract_status_code("timed out after 30000 ms"), None);
    }

    #[test]
    fn test_message_is_well_formed() {
        let config = relay_config();
        let raw = build_test_message(
            &config,
            "smtp-proxy.local",
            "ops@example.org",
            "Relay check",
            "line one\nline two",
            "q42",
        );
        let text = String::from_utf8(raw).unwrap();

        assert!(text.starts_with("From: SMTP Relay <noreply@domain1.com>\r\n"));
        assert!(text.contains("To: <ops@example.org>\r\n"));
        assert!(text.contains("Subject: Relay check\r\n"));
        assert!(text.contains("Message-ID: <q42@domain1.com>\r\n"));
        assert!(text.contains("\r\n\r\nline one\r\nline two\r\n"));

        // It must survive our own parser, which is what proves it is valid.
        let parsed = crate::message::headers::Message::parse(text.as_bytes()).unwrap();
        assert_eq!(parsed.value("x-relay-node").unwrap(), "relay_node_1");
    }
}
