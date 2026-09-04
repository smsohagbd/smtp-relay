//! Header rewriting for relay identity.
//!
//! Everything here operates on the header block only. The body is moved from
//! input to output as an opaque byte range, so HTML, tracking pixels, tracking
//! links, MIME boundaries and transfer encodings are bit-for-bit identical.
//!
//! By default the only mutation is the `From` *address*. The original display
//! name and DKIM/ARC signatures stay as they arrived. When the relay sends as
//! its SMTP username (`from_same_as_username`) or `align_envelope` is on,
//! `MAIL FROM` is rewritten to that same address so providers that reject
//! foreign envelope senders (cPanel / Exim `501 5.5.4`) accept the mail.
//! `Sender` and `Return-Path` follow the rewritten From when present.

use std::net::IpAddr;

use crate::config::{RelayConfig, RewriteConfig};
use crate::error::MessageError;
use crate::message::headers::{parse_mailbox, Mailbox, Message};
use crate::util::{format_mailbox, looks_like_email, rfc5322_date_now};

/// Signature headers invalidated by any header mutation.
const SIGNATURE_HEADERS: &[&str] = &[
    "DKIM-Signature",
    "DomainKey-Signature",
    "X-Google-DKIM-Signature",
];

/// Trace headers added by receiving systems that would be misleading here.
const ARC_HEADERS: &[&str] = &["Authentication-Results", "X-Original-Authentication-Results"];

/// Inputs for a single rewrite pass.
pub struct RewriteContext<'a> {
    pub rewrite: &'a RewriteConfig,
    pub relay: &'a RelayConfig,
    /// `server.hostname`, used in the `Received` header.
    pub hostname: &'a str,
    /// Queue id assigned by the inbound session.
    pub queue_id: &'a str,
    pub client_ip: Option<IpAddr>,
    /// EHLO/HELO name the client announced.
    pub client_helo: &'a str,
    /// Envelope sender the client used in `MAIL FROM`.
    pub original_sender: &'a str,
}

/// Result of a rewrite pass: the bytes to transmit plus everything the
/// dashboard and logs want to know about what changed.
#[derive(Debug, Clone)]
pub struct Rewritten {
    /// Full RFC 5322 message ready for `DATA`.
    pub raw: Vec<u8>,
    /// Value to use for `MAIL FROM`. Matches the rewritten From address when
    /// the relay sends as its SMTP username or `align_envelope` is on.
    pub envelope_from: String,
    /// Mailbox found in the inbound `From`, if any. The activity log records
    /// this before the rewrite runs, so only the tests read it back here.
    #[allow(dead_code)]
    pub original_from: Option<Mailbox>,
    /// The `From` header actually transmitted.
    pub from_header: String,
    /// The `Reply-To` header on the outgoing message, if there is one.
    pub reply_to: Option<String>,
    /// Decoded subject, for display only.
    #[allow(dead_code)]
    pub subject: Option<String>,
    pub message_id: Option<String>,
    /// Human-readable list of applied transformations.
    pub notes: Vec<String>,
}

/// Applies the configured transformations to `raw` for the chosen `relay`.
pub fn rewrite(raw: &[u8], ctx: &RewriteContext<'_>) -> Result<Rewritten, MessageError> {
    let mut message = Message::parse(raw)?;
    let mut notes: Vec<String> = Vec::new();

    let original_from_raw = message.value("from");
    let original_from = original_from_raw.as_deref().and_then(parse_mailbox);

    // -- 1. Reply-To ------------------------------------------------------
    // Must run before `From` is replaced, so the original address is still
    // available. An existing Reply-To is never overwritten: the submitting
    // application knows better than we do where replies should land.
    let mut reply_to = message.value("reply-to").filter(|v| !v.trim().is_empty());
    if reply_to.is_none() && ctx.rewrite.inject_reply_to {
        let candidate = original_from
            .as_ref()
            .filter(|mailbox| looks_like_email(&mailbox.address))
            .map(|mailbox| format_mailbox(&mailbox.display_name, &mailbox.address))
            .or_else(|| {
                ctx.rewrite
                    .reply_to_fallback
                    .as_ref()
                    .map(|address| format!("<{address}>"))
            });

        if let Some(value) = candidate {
            message.set("Reply-To", &value);
            notes.push(format!("injected Reply-To {value}"));
            reply_to = Some(value);
        }
    } else if reply_to.is_some() {
        notes.push("kept existing Reply-To".to_string());
    }

    // -- 2. From ----------------------------------------------------------
    // Only the address is rewritten. The original display name is kept unless
    // `preserve_display_name` is off; there is no per-relay name override.
    let identity = ctx.relay.effective_from_address();
    let display_name = if ctx.rewrite.preserve_display_name {
        original_from
            .as_ref()
            .map(|mailbox| mailbox.display_name.clone())
            .unwrap_or_default()
    } else {
        String::new()
    };

    let from_header = if ctx.rewrite.rewrite_from {
        let rewritten = format_mailbox(&display_name, &identity);
        message.set("From", &rewritten);

        match &original_from {
            Some(mailbox) if mailbox.address != identity => notes.push(format!(
                "rewrote From {} -> {}",
                mailbox.address, identity
            )),
            Some(_) => notes.push("From already matched relay identity".to_string()),
            None => notes.push(format!("synthesised From {identity}")),
        }
        rewritten
    } else {
        original_from_raw.clone().unwrap_or_default()
    };

    // Most authenticated SMTP hosts refuse MAIL FROM that is not the login.
    // Sending-as-username therefore always rewrites the envelope. The
    // align_envelope checkbox covers the custom-From case. Off + custom From
    // keeps the client's MAIL FROM (bounce path stays with the submitter).
    let align_envelope = ctx.rewrite.rewrite_from
        && (ctx.relay.align_envelope || ctx.relay.from_same_as_username);
    let envelope_from = if align_envelope {
        notes.push(format!("aligned MAIL FROM to {identity}"));
        identity.clone()
    } else if !ctx.original_sender.is_empty() && looks_like_email(ctx.original_sender) {
        ctx.original_sender.to_string()
    } else {
        identity.clone()
    };

    if ctx.rewrite.rewrite_from {
        if message.has("sender") {
            let sender = format!("<{identity}>");
            message.set("Sender", &sender);
            notes.push(format!("rewrote Sender to {identity}"));
        }
        if message.has("return-path") {
            message.set("Return-Path", format!("<{identity}>"));
            notes.push(format!("rewrote Return-Path to {identity}"));
        }
        if message.has("x-sender") {
            message.set("X-Sender", &identity);
            notes.push(format!("rewrote X-Sender to {identity}"));
        }
    }

    // -- 3. Signatures ----------------------------------------------------
    if ctx.rewrite.strip_dkim {
        let mut stripped = 0;
        for name in SIGNATURE_HEADERS {
            stripped += message.remove_all(name);
        }
        if stripped > 0 {
            notes.push(format!("stripped {stripped} inherited signature header(s)"));
        }
    }
    if ctx.rewrite.strip_arc {
        let mut stripped = message.remove_prefix("arc-");
        for name in ARC_HEADERS {
            stripped += message.remove_all(name);
        }
        if stripped > 0 {
            notes.push(format!("stripped {stripped} ARC/authentication header(s)"));
        }
    }

    // -- 4. Privacy and hygiene -------------------------------------------
    if ctx.rewrite.strip_bcc_header && message.remove_all("Bcc") > 0 {
        notes.push("stripped Bcc header (envelope recipients unchanged)".to_string());
    }
    if ctx.rewrite.strip_received {
        let removed = message.remove_all("Received");
        if removed > 0 {
            notes.push(format!("stripped {removed} inbound Received header(s)"));
        }
    }

    for name in &ctx.rewrite.remove_headers {
        if message.remove_all(name) > 0 {
            notes.push(format!("removed {name}"));
        }
    }

    // -- 5. Required headers ----------------------------------------------
    if ctx.rewrite.ensure_date && !message.has("date") {
        message.set("Date", rfc5322_date_now());
        notes.push("added missing Date".to_string());
    }

    let mut message_id = message.value("message-id").filter(|v| !v.trim().is_empty());
    if ctx.rewrite.ensure_message_id && message_id.is_none() {
        let domain = crate::util::address_domain(&identity);
        let generated = format!("<{}@{}>", ctx.queue_id, domain);
        message.set("Message-ID", &generated);
        notes.push(format!("added Message-ID {generated}"));
        message_id = Some(generated);
    }

    if let Some(mailer) = &ctx.rewrite.x_mailer {
        message.set("X-Mailer", mailer);
    }

    // -- 6. Diagnostics ----------------------------------------------------
    if ctx.rewrite.add_relay_headers {
        message.append("X-Relay-Node", &ctx.relay.id);
        message.append("X-Relay-Queue-Id", ctx.queue_id);
        if let Some(mailbox) = &original_from {
            message.append(
                "X-Original-From",
                format_mailbox(&mailbox.display_name, &mailbox.address),
            );
        }
        if !ctx.original_sender.is_empty() {
            message.append("X-Original-Envelope-From", ctx.original_sender);
        }
    }

    for rule in &ctx.rewrite.extra_headers {
        if rule.name.trim().is_empty() {
            continue;
        }
        message.set(&rule.name, &rule.value);
    }

    // -- 7. Trace ----------------------------------------------------------
    // Added last so it ends up as the topmost header, per RFC 5321 section 4.4.
    if ctx.rewrite.add_received_header {
        let helo = if ctx.client_helo.is_empty() {
            "unknown"
        } else {
            ctx.client_helo
        };
        let source = match ctx.client_ip {
            Some(ip) => format!("{helo} ([{ip}])"),
            None => format!("{helo} (local)"),
        };
        message.prepend(
            "Received",
            format!(
                "from {source}\r\n\tby {} (smtp-relay) with ESMTPA id {}\r\n\tfor relay {}; {}",
                ctx.hostname,
                ctx.queue_id,
                ctx.relay.id,
                rfc5322_date_now()
            ),
        );
    }

    let subject = message
        .value("subject")
        .map(|value| super::decode_encoded_words(&value));

    Ok(Rewritten {
        raw: message.to_bytes(),
        envelope_from,
        original_from,
        from_header,
        reply_to,
        subject,
        message_id,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HeaderRule, RewriteConfig};
    use crate::message::headers::Message;

    fn relay() -> RelayConfig {
        RelayConfig {
            id: "relay_node_1".to_string(),
            host: "smtp.domain1.com".to_string(),
            from_address: "noreply@domain1.com".to_string(),
            ..Default::default()
        }
    }

    fn context<'a>(
        rewrite_cfg: &'a RewriteConfig,
        relay_cfg: &'a RelayConfig,
    ) -> RewriteContext<'a> {
        RewriteContext {
            rewrite: rewrite_cfg,
            relay: relay_cfg,
            hostname: "smtp-proxy.local",
            queue_id: "q1234",
            client_ip: Some("10.1.2.3".parse().unwrap()),
            client_helo: "mautic.local",
            original_sender: "campaigns@acme-mautic.io",
        }
    }

    /// A realistic Mautic multipart message with tracking pixel and links.
    const MAUTIC: &[u8] = b"From: Acme Marketing <campaigns@acme-mautic.io>\r\n\
To: Lead One <lead@example.org>\r\n\
Cc: watcher@example.org\r\n\
Bcc: archive@acme-mautic.io\r\n\
Subject: =?UTF-8?Q?Your_September_Offer?=\r\n\
Date: Mon, 01 Sep 2026 10:00:00 +0000\r\n\
Message-ID: <abc123@acme-mautic.io>\r\n\
MIME-Version: 1.0\r\n\
List-Unsubscribe: <https://acme-mautic.io/unsubscribe/xyz>\r\n\
DKIM-Signature: v=1; a=rsa-sha256; d=acme-mautic.io; h=from:to;\r\n\
\x20b=SIGNATUREDATA/1234+abc==\r\n\
ARC-Seal: i=1; a=rsa-sha256; s=arc; d=example.net; b=zzz\r\n\
Content-Type: multipart/alternative; boundary=\"--_NmP-boundary-Part_1\"\r\n\
\r\n\
----_NmP-boundary-Part_1\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Hello =E2=80=94 see https://acme-mautic.io/r/abc123 for details.\r\n\
----_NmP-boundary-Part_1\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
PGh0bWw+PGJvZHk+PGEgaHJlZj0iaHR0cHM6Ly9hY21lLW1hdXRpYy5pby9yL2FiYzEyMyI+Q2xp\r\n\
Y2s8L2E+PGltZyBzcmM9Imh0dHBzOi8vYWNtZS1tYXV0aWMuaW8vZW1haWwvYWJjMTIzLmdpZiIg\r\n\
Lz48L2JvZHk+PC9odG1sPg==\r\n\
----_NmP-boundary-Part_1--\r\n";

    #[test]
    fn body_is_never_modified() {
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let before = Message::parse(MAUTIC).unwrap();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert_eq!(
            before.body(),
            after.body(),
            "body bytes must survive the rewrite unchanged"
        );

        // Spot-check the payloads the marketing platform depends on.
        let body = String::from_utf8_lossy(after.body());
        assert!(body.contains("https://acme-mautic.io/r/abc123"));
        assert!(body.contains("PGh0bWw+PGJvZHk+PGEgaHJlZj0iaHR0cHM6Ly9hY21lLW1hdXRpYy5pby9yL2FiYzEyMyI+Q2xp"));
        assert!(body.contains("Hello =E2=80=94"));
        assert!(body.contains("----_NmP-boundary-Part_1--"));
    }

    #[test]
    fn from_is_rewritten_and_display_name_preserved() {
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert_eq!(
            after.value("from").unwrap(),
            "Acme Marketing <noreply@domain1.com>"
        );
        assert_eq!(
            result.envelope_from, "noreply@domain1.com",
            "from_same_as_username defaults on, so MAIL FROM follows From"
        );
        assert_eq!(
            result.original_from.as_ref().unwrap().address,
            "campaigns@acme-mautic.io"
        );
    }

    #[test]
    fn reply_to_routes_back_to_the_original_sender() {
        let cfg = RewriteConfig {
            inject_reply_to: true,
            ..Default::default()
        };
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert_eq!(
            after.value("reply-to").unwrap(),
            "Acme Marketing <campaigns@acme-mautic.io>"
        );
    }

    #[test]
    fn existing_reply_to_is_left_alone() {
        let raw = b"From: A <a@orig.io>\r\nReply-To: support@orig.io\r\nSubject: x\r\n\r\nbody"
            as &[u8];
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let result = rewrite(raw, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert_eq!(after.value("reply-to").unwrap(), "support@orig.io");
        assert_eq!(after.count("reply-to"), 1);
    }

    #[test]
    fn incoming_signatures_are_kept_by_default() {
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert!(after.has("dkim-signature"));
        assert!(after.has("arc-seal"));
        assert!(after.has("list-unsubscribe"));
    }

    #[test]
    fn signatures_and_arc_can_be_stripped() {
        let cfg = RewriteConfig {
            strip_dkim: true,
            strip_arc: true,
            ..Default::default()
        };
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert!(!after.has("dkim-signature"));
        assert!(!after.has("arc-seal"));
        // ...but the body-level content and unrelated headers stay.
        assert!(after.has("list-unsubscribe"));
        assert!(after.has("content-type"));
    }

    #[test]
    fn recipient_and_content_headers_are_untouched() {
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert_eq!(after.value("to").unwrap(), "Lead One <lead@example.org>");
        assert_eq!(after.value("cc").unwrap(), "watcher@example.org");
        assert_eq!(after.value("bcc").unwrap(), "archive@acme-mautic.io");
        assert_eq!(
            after.value("subject").unwrap(),
            "=?UTF-8?Q?Your_September_Offer?="
        );
        assert_eq!(after.value("message-id").unwrap(), "<abc123@acme-mautic.io>");
        assert_eq!(
            after.value("date").unwrap(),
            "Mon, 01 Sep 2026 10:00:00 +0000"
        );
        assert!(after
            .value("content-type")
            .unwrap()
            .contains("boundary=\"--_NmP-boundary-Part_1\""));
    }

    #[test]
    fn subject_is_decoded_for_display_only() {
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        assert_eq!(result.subject.as_deref(), Some("Your September Offer"));
    }

    #[test]
    fn bcc_can_be_stripped_for_privacy() {
        let cfg = RewriteConfig {
            strip_bcc_header: true,
            ..Default::default()
        };
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();
        assert!(!after.has("bcc"));
        assert!(after.has("to"));
    }

    #[test]
    fn received_header_is_prepended() {
        let cfg = RewriteConfig {
            add_received_header: true,
            ..Default::default()
        };
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert_eq!(after.headers()[0].name_lower(), "received");
        let received = after.value("received").unwrap();
        assert!(received.contains("mautic.local"));
        assert!(received.contains("10.1.2.3"));
        assert!(received.contains("q1234"));
    }

    #[test]
    fn missing_from_is_synthesised() {
        let raw = b"To: lead@example.org\r\nSubject: x\r\n\r\nbody" as &[u8];
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let result = rewrite(raw, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert_eq!(after.value("from").unwrap(), "<noreply@domain1.com>");
        assert!(result.original_from.is_none());
        assert!(after.value("reply-to").is_none());
    }

    #[test]
    fn reply_to_fallback_applies_when_from_is_unusable() {
        let raw = b"From: undisclosed-recipients\r\nSubject: x\r\n\r\nbody" as &[u8];
        let cfg = RewriteConfig {
            inject_reply_to: true,
            reply_to_fallback: Some("support@acme.io".to_string()),
            ..Default::default()
        };
        let relay_cfg = relay();
        let result = rewrite(raw, &context(&cfg, &relay_cfg)).unwrap();
        assert_eq!(result.reply_to.as_deref(), Some("<support@acme.io>"));
    }

    #[test]
    fn missing_date_and_message_id_are_generated() {
        let raw = b"From: A <a@orig.io>\r\nSubject: x\r\n\r\nbody" as &[u8];
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let result = rewrite(raw, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert!(after.has("date"));
        assert_eq!(
            after.value("message-id").unwrap(),
            "<q1234@domain1.com>",
            "generated Message-ID should use the relay domain"
        );
    }

    #[test]
    fn display_name_is_never_overridden() {
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();
        assert_eq!(
            after.value("from").unwrap(),
            "Acme Marketing <noreply@domain1.com>"
        );
    }

    #[test]
    fn envelope_stays_original_only_for_custom_from_without_alignment() {
        let cfg = RewriteConfig::default();
        let mut relay_cfg = relay();
        relay_cfg.from_same_as_username = false;
        relay_cfg.align_envelope = false;
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        assert_eq!(result.envelope_from, "campaigns@acme-mautic.io");

        relay_cfg.align_envelope = true;
        let aligned = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        assert_eq!(aligned.envelope_from, "noreply@domain1.com");
    }

    #[test]
    fn sending_as_username_rewrites_envelope_even_when_align_is_off() {
        let cfg = RewriteConfig::default();
        let mut relay_cfg = relay();
        relay_cfg.from_same_as_username = true;
        relay_cfg.align_envelope = false;
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        assert_eq!(result.envelope_from, "noreply@domain1.com");
        assert_eq!(
            Message::parse(&result.raw).unwrap().value("from").unwrap(),
            "Acme Marketing <noreply@domain1.com>"
        );
    }

    #[test]
    fn sender_and_return_path_follow_rewritten_from() {
        let raw = b"From: A <a@orig.io>\r\nSender: a@orig.io\r\nReturn-Path: <a@orig.io>\r\nX-Sender: a@orig.io\r\nSubject: x\r\n\r\nbody"
            as &[u8];
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let result = rewrite(raw, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();
        assert_eq!(after.value("sender").unwrap(), "<noreply@domain1.com>");
        assert_eq!(after.value("return-path").unwrap(), "<noreply@domain1.com>");
        assert_eq!(after.value("x-sender").unwrap(), "noreply@domain1.com");
    }

    #[test]
    fn display_name_with_specials_is_quoted() {
        let raw = b"From: Acme, Inc. <a@orig.io>\r\nSubject: x\r\n\r\nbody" as &[u8];
        let cfg = RewriteConfig::default();
        let relay_cfg = relay();
        let result = rewrite(raw, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();
        // `Acme, Inc.` must be quoted or the comma would split the mailbox list.
        assert_eq!(
            after.value("from").unwrap(),
            "\"Acme, Inc.\" <noreply@domain1.com>"
        );
    }

    #[test]
    fn custom_header_rules_are_applied() {
        let cfg = RewriteConfig {
            remove_headers: vec!["List-Unsubscribe".to_string()],
            extra_headers: vec![HeaderRule {
                name: "X-Campaign".to_string(),
                value: "september".to_string(),
            }],
            x_mailer: Some("smtp-relay/1.0".to_string()),
            ..Default::default()
        };
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert!(!after.has("list-unsubscribe"));
        assert_eq!(after.value("x-campaign").unwrap(), "september");
        assert_eq!(after.value("x-mailer").unwrap(), "smtp-relay/1.0");
    }

    #[test]
    fn rewriting_can_be_disabled_entirely() {
        let cfg = RewriteConfig {
            rewrite_from: false,
            inject_reply_to: false,
            strip_dkim: false,
            strip_arc: false,
            add_received_header: false,
            add_relay_headers: false,
            ..Default::default()
        };
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        assert_eq!(result.raw, MAUTIC, "pass-through mode must be byte exact");
    }

    #[test]
    fn diagnostic_headers_record_the_original_identity() {
        let cfg = RewriteConfig {
            add_relay_headers: true,
            ..Default::default()
        };
        let relay_cfg = relay();
        let result = rewrite(MAUTIC, &context(&cfg, &relay_cfg)).unwrap();
        let after = Message::parse(&result.raw).unwrap();

        assert_eq!(after.value("x-relay-node").unwrap(), "relay_node_1");
        assert_eq!(after.value("x-relay-queue-id").unwrap(), "q1234");
        assert_eq!(
            after.value("x-original-from").unwrap(),
            "Acme Marketing <campaigns@acme-mautic.io>"
        );
    }
}
