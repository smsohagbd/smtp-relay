//! Inbound ESMTP session state machine.
//!
//! Implements the submission subset an application like Mautic needs:
//! `EHLO/HELO`, `AUTH PLAIN|LOGIN`, `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`,
//! `NOOP`, `VRFY`, `HELP` and `QUIT`, with SIZE, PIPELINING, 8BITMIME and
//! ENHANCEDSTATUSCODES.
//!
//! Message bytes are reassembled exactly as sent, with only SMTP transparency
//! (leading-dot stuffing) undone, so nothing in the MIME payload is altered.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::config::Config;
use crate::dispatch::{self, InboundMessage, SubmitOutcome};
use crate::smtp::command::{self, Command};
use crate::smtp::lines::{LineReader, ReadLine};
use crate::state::AppState;
use crate::util::{b64_decode, b64_encode, looks_like_email, new_queue_id, secret_eq};

/// RFC 5321 allows 512 octets per command line; accept more so long AUTH
/// responses and generous parameter lists do not break, but stay bounded.
const MAX_COMMAND_LINE: usize = 4_096;
/// Cap on `RSET`-less protocol errors before the connection is dropped, which
/// stops a broken or malicious client from spinning forever.
const MAX_PROTOCOL_ERRORS: u32 = 12;

/// Why a session ended, for the log line emitted on close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disconnect {
    Quit,
    ClientClosed,
    Timeout,
    ProtocolAbuse,
    WriteFailed,
    ReadFailed,
    ServerShutdown,
}

impl Disconnect {
    fn as_str(self) -> &'static str {
        match self {
            Disconnect::Quit => "client sent QUIT",
            Disconnect::ClientClosed => "client closed the connection",
            Disconnect::Timeout => "idle timeout",
            Disconnect::ProtocolAbuse => "too many protocol errors",
            Disconnect::WriteFailed => "write failed",
            Disconnect::ReadFailed => "read failed",
            Disconnect::ServerShutdown => "server shutting down",
        }
    }
}

pub struct Session {
    state: Arc<AppState>,
    config: Arc<Config>,
    reader: LineReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    peer: SocketAddr,

    helo_name: String,
    esmtp: bool,
    authenticated: bool,
    auth_user: Option<String>,

    /// `Some` once `MAIL FROM` has been accepted.
    envelope_sender: Option<String>,
    recipients: Vec<String>,

    accepted_messages: u32,
    protocol_errors: u32,
}

impl Session {
    pub fn new(state: Arc<AppState>, stream: tokio::net::TcpStream, peer: SocketAddr) -> Self {
        let config = state.config();
        let (read_half, write_half) = stream.into_split();
        Self {
            state,
            config,
            reader: LineReader::new(read_half),
            writer: write_half,
            peer,
            helo_name: String::new(),
            esmtp: false,
            authenticated: false,
            auth_user: None,
            envelope_sender: None,
            recipients: Vec::new(),
            accepted_messages: 0,
            protocol_errors: 0,
        }
    }

    fn command_timeout(&self) -> Duration {
        Duration::from_secs(self.config.server.timeout_seconds.max(1))
    }

    fn max_message_size(&self) -> usize {
        self.config.max_message_size_bytes()
    }

    /// True when inbound AUTH should be offered and honoured.
    fn auth_available(&self) -> bool {
        !self.config.server.auth_users.is_empty()
    }

    /// Drives the session until the client disconnects.
    pub async fn run(mut self) {
        let banner = match &self.config.server.greeting {
            Some(text) => text.clone(),
            None => format!(
                "{} ESMTP smtp-relay {} ready",
                self.config.server.hostname,
                crate::state::VERSION
            ),
        };

        if self.reply(220, None, &banner).await.is_err() {
            self.state.metrics.connection_closed();
            return;
        }

        let reason = self.command_loop().await;

        tracing::debug!(
            peer = %self.peer,
            messages = self.accepted_messages,
            reason = reason.as_str(),
            "session ended"
        );
        let _ = self.writer.shutdown().await;
        self.state.metrics.connection_closed();
    }

    async fn command_loop(&mut self) -> Disconnect {
        loop {
            if self.state.is_shutting_down() {
                let _ = self
                    .reply(421, Some("4.3.2"), "server is shutting down, please retry")
                    .await;
                return Disconnect::ServerShutdown;
            }

            let line = match tokio::time::timeout(
                self.command_timeout(),
                self.reader.read_line(MAX_COMMAND_LINE),
            )
            .await
            {
                Err(_elapsed) => {
                    self.state
                        .metrics
                        .inc(&self.state.metrics.counters.sessions_timed_out);
                    let _ = self
                        .reply(421, Some("4.4.2"), "timeout waiting for command")
                        .await;
                    return Disconnect::Timeout;
                }
                Ok(Err(error)) => {
                    tracing::debug!(peer = %self.peer, %error, "read error");
                    return Disconnect::ReadFailed;
                }
                Ok(Ok(ReadLine::Eof)) => return Disconnect::ClientClosed,
                Ok(Ok(ReadLine::TooLong)) => {
                    if self
                        .protocol_error(500, "5.5.2", "command line too long")
                        .await
                        .is_err()
                    {
                        return Disconnect::WriteFailed;
                    }
                    if self.protocol_errors >= MAX_PROTOCOL_ERRORS {
                        return Disconnect::ProtocolAbuse;
                    }
                    continue;
                }
                Ok(Ok(ReadLine::Line(line))) => line,
            };

            let command = match command::parse(&line) {
                Ok(command) => command,
                Err(error) => {
                    if self
                        .protocol_error(error.code, error.enhanced, &error.message)
                        .await
                        .is_err()
                    {
                        return Disconnect::WriteFailed;
                    }
                    if self.protocol_errors >= MAX_PROTOCOL_ERRORS {
                        return Disconnect::ProtocolAbuse;
                    }
                    continue;
                }
            };

            match self.handle(command).await {
                Ok(true) => continue,
                Ok(false) => return Disconnect::Quit,
                Err(_) => return Disconnect::WriteFailed,
            }
        }
    }

    /// Handles one command. `Ok(false)` means the session should close.
    async fn handle(&mut self, command: Command) -> std::io::Result<bool> {
        match command {
            Command::Empty => {
                self.protocol_error(500, "5.5.2", "empty command").await?;
            }
            Command::Ehlo(domain) => {
                self.helo_name = domain;
                self.esmtp = true;
                self.reset_transaction();
                self.send_ehlo_response().await?;
            }
            Command::Helo(domain) => {
                self.helo_name = domain;
                self.esmtp = false;
                self.reset_transaction();
                let greeting = format!("{} Hello {}", self.config.server.hostname, self.helo_name);
                self.reply(250, None, &greeting).await?;
            }
            Command::Auth {
                mechanism,
                initial,
            } => {
                self.handle_auth(&mechanism, initial).await?;
            }
            Command::Mail { address, size } => {
                self.handle_mail(address, size).await?;
            }
            Command::Rcpt { address } => {
                self.handle_rcpt(address).await?;
            }
            Command::Data => {
                self.handle_data().await?;
            }
            Command::Rset => {
                self.reset_transaction();
                self.reply(250, Some("2.0.0"), "flushed").await?;
            }
            Command::Noop => {
                self.reply(250, Some("2.0.0"), "OK").await?;
            }
            Command::Quit => {
                let farewell = format!("{} closing connection", self.config.server.hostname);
                self.reply(221, Some("2.0.0"), &farewell).await?;
                return Ok(false);
            }
            // This proxy does not enumerate mailboxes: it has none.
            Command::Vrfy => {
                self.reply(
                    252,
                    Some("2.5.2"),
                    "cannot verify recipients, but will attempt delivery",
                )
                .await?;
            }
            Command::Expn => {
                self.reply(502, Some("5.5.1"), "EXPN is not supported").await?;
            }
            Command::Help => {
                self.reply(
                    214,
                    Some("2.0.0"),
                    "supported: EHLO HELO AUTH MAIL RCPT DATA RSET NOOP VRFY QUIT",
                )
                .await?;
            }
            Command::StartTls => {
                // Deliberately not advertised: inbound TLS termination is left
                // to a loopback bind or a TLS-terminating proxy.
                self.reply(
                    454,
                    Some("4.7.0"),
                    "STARTTLS is not available on this listener",
                )
                .await?;
            }
            Command::Unimplemented(verb) => {
                self.protocol_error(502, "5.5.1", &format!("{verb} is not implemented"))
                    .await?;
            }
            Command::Unknown(verb) => {
                self.protocol_error(500, "5.5.1", &format!("unrecognised command `{verb}`"))
                    .await?;
            }
        }
        Ok(true)
    }

    async fn send_ehlo_response(&mut self) -> std::io::Result<()> {
        let mut extensions: Vec<String> = vec![
            format!("SIZE {}", self.max_message_size()),
            "8BITMIME".to_string(),
            "PIPELINING".to_string(),
            "ENHANCEDSTATUSCODES".to_string(),
        ];
        if self.auth_available() {
            extensions.push("AUTH PLAIN LOGIN".to_string());
        }
        extensions.push("HELP".to_string());

        let greeting = format!(
            "{} Hello {} [{}]",
            self.config.server.hostname,
            self.helo_name,
            self.peer.ip()
        );

        let mut payload = String::with_capacity(256);
        payload.push_str(&format!("250-{greeting}\r\n"));
        for (index, extension) in extensions.iter().enumerate() {
            let last = index + 1 == extensions.len();
            payload.push_str(&format!(
                "250{}{extension}\r\n",
                if last { " " } else { "-" }
            ));
        }
        self.write_raw(payload.as_bytes()).await
    }

    // -- AUTH --------------------------------------------------------------

    async fn handle_auth(
        &mut self,
        mechanism: &str,
        initial: Option<String>,
    ) -> std::io::Result<()> {
        if !self.auth_available() {
            return self
                .reply(503, Some("5.5.1"), "authentication is not enabled")
                .await;
        }
        if self.authenticated {
            return self
                .reply(503, Some("5.5.1"), "already authenticated")
                .await;
        }
        if self.envelope_sender.is_some() {
            return self
                .reply(503, Some("5.5.1"), "AUTH is not allowed during a transaction")
                .await;
        }

        let credentials = match mechanism {
            "PLAIN" => self.collect_plain(initial).await?,
            "LOGIN" => self.collect_login(initial).await?,
            other => {
                return self
                    .reply(
                        504,
                        Some("5.5.4"),
                        &format!("mechanism `{other}` is not supported, use PLAIN or LOGIN"),
                    )
                    .await;
            }
        };

        let Some((username, password)) = credentials else {
            // The client cancelled or sent something undecodable.
            self.state
                .metrics
                .inc(&self.state.metrics.counters.auth_failure);
            return self
                .reply(501, Some("5.5.2"), "could not decode the AUTH response")
                .await;
        };

        let matched = self
            .config
            .server
            .auth_users
            .iter()
            .any(|user| user.username == username && secret_eq(&user.password, &password));

        if matched {
            self.authenticated = true;
            self.auth_user = Some(username.clone());
            self.state
                .metrics
                .inc(&self.state.metrics.counters.auth_success);
            tracing::debug!(peer = %self.peer, user = %username, "authenticated");
            self.reply(235, Some("2.7.0"), "authentication successful")
                .await
        } else {
            self.state
                .metrics
                .inc(&self.state.metrics.counters.auth_failure);
            tracing::warn!(
                peer = %self.peer,
                user = %crate::util::truncate(&username, 64),
                "authentication failed"
            );
            self.reply(535, Some("5.7.8"), "authentication credentials invalid")
                .await
        }
    }

    /// `AUTH PLAIN` carries `\0username\0password`, base64 encoded.
    async fn collect_plain(
        &mut self,
        initial: Option<String>,
    ) -> std::io::Result<Option<(String, String)>> {
        let encoded = match initial {
            Some(value) => value,
            None => {
                self.write_raw(b"334 \r\n").await?;
                match self.read_auth_line().await? {
                    Some(line) => line,
                    None => return Ok(None),
                }
            }
        };

        let Some(decoded) = b64_decode(&encoded) else {
            return Ok(None);
        };
        let mut parts = decoded.split(|&byte| byte == 0);
        let _authzid = parts.next();
        let username = parts.next().map(|b| String::from_utf8_lossy(b).into_owned());
        let password = parts.next().map(|b| String::from_utf8_lossy(b).into_owned());

        Ok(match (username, password) {
            (Some(username), Some(password)) => Some((username, password)),
            _ => None,
        })
    }

    /// `AUTH LOGIN` is a two-step base64 challenge exchange.
    async fn collect_login(
        &mut self,
        initial: Option<String>,
    ) -> std::io::Result<Option<(String, String)>> {
        let username = match initial {
            Some(value) => value,
            None => {
                self.write_raw(format!("334 {}\r\n", b64_encode(b"Username:")).as_bytes())
                    .await?;
                match self.read_auth_line().await? {
                    Some(line) => line,
                    None => return Ok(None),
                }
            }
        };

        self.write_raw(format!("334 {}\r\n", b64_encode(b"Password:")).as_bytes())
            .await?;
        let password = match self.read_auth_line().await? {
            Some(line) => line,
            None => return Ok(None),
        };

        let (Some(username), Some(password)) = (b64_decode(&username), b64_decode(&password))
        else {
            return Ok(None);
        };

        Ok(Some((
            String::from_utf8_lossy(&username).into_owned(),
            String::from_utf8_lossy(&password).into_owned(),
        )))
    }

    /// Reads one base64 continuation line. `None` means cancel or failure.
    async fn read_auth_line(&mut self) -> std::io::Result<Option<String>> {
        let line = match tokio::time::timeout(
            self.command_timeout(),
            self.reader.read_line(MAX_COMMAND_LINE),
        )
        .await
        {
            Ok(Ok(ReadLine::Line(line))) => line,
            Ok(Ok(_)) | Err(_) => return Ok(None),
            Ok(Err(error)) => return Err(error),
        };

        let text = String::from_utf8_lossy(&line).trim().to_string();
        // A bare `*` cancels the exchange.
        if text == "*" || text.is_empty() {
            return Ok(None);
        }
        Ok(Some(text))
    }

    // -- envelope ----------------------------------------------------------

    async fn handle_mail(&mut self, address: String, size: Option<u64>) -> std::io::Result<()> {
        if self.helo_name.is_empty() {
            return self
                .reply(503, Some("5.5.1"), "send EHLO or HELO first")
                .await;
        }
        if self.config.server.require_auth && !self.authenticated {
            return self
                .reply(530, Some("5.7.0"), "authentication required")
                .await;
        }
        if self.envelope_sender.is_some() {
            return self
                .reply(503, Some("5.5.1"), "nested MAIL command; send RSET first")
                .await;
        }
        if !address.is_empty() && !looks_like_email(&address) {
            return self
                .reply(
                    553,
                    Some("5.1.7"),
                    &format!("`{}` is not a valid sender address", crate::util::truncate(&address, 120)),
                )
                .await;
        }

        if let Some(declared) = size {
            let limit = self.max_message_size() as u64;
            if declared > limit {
                self.state
                    .metrics
                    .inc(&self.state.metrics.counters.messages_rejected);
                return self
                    .reply(
                        552,
                        Some("5.3.4"),
                        &format!("message size {declared} exceeds the {limit} byte limit"),
                    )
                    .await;
            }
        }

        self.envelope_sender = Some(address);
        self.recipients.clear();
        self.reply(250, Some("2.1.0"), "sender OK").await
    }

    async fn handle_rcpt(&mut self, address: String) -> std::io::Result<()> {
        if self.envelope_sender.is_none() {
            return self
                .reply(503, Some("5.5.1"), "send MAIL FROM first")
                .await;
        }
        if !looks_like_email(&address) {
            return self
                .reply(
                    553,
                    Some("5.1.3"),
                    &format!(
                        "`{}` is not a valid recipient address",
                        crate::util::truncate(&address, 120)
                    ),
                )
                .await;
        }
        if self.recipients.len() >= self.config.server.max_recipients_per_message {
            return self
                .reply(
                    452,
                    Some("4.5.3"),
                    &format!(
                        "too many recipients (limit {})",
                        self.config.server.max_recipients_per_message
                    ),
                )
                .await;
        }
        if self
            .recipients
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&address))
        {
            // Silently de-duplicate rather than sending twice.
            return self
                .reply(250, Some("2.1.5"), "recipient OK (duplicate ignored)")
                .await;
        }

        self.recipients.push(address);
        self.reply(250, Some("2.1.5"), "recipient OK").await
    }

    // -- DATA ---------------------------------------------------------------

    async fn handle_data(&mut self) -> std::io::Result<()> {
        if self.envelope_sender.is_none() {
            return self
                .reply(503, Some("5.5.1"), "send MAIL FROM first")
                .await;
        }
        if self.recipients.is_empty() {
            return self
                .reply(503, Some("5.5.1"), "no valid recipients; send RCPT TO first")
                .await;
        }

        self.reply(354, None, "start mail input; end with <CRLF>.<CRLF>")
            .await?;

        let limit = self.max_message_size();
        let timeout = self.command_timeout();

        match read_body(&mut self.reader, limit, timeout).await? {
            BodyResult::Complete(raw) => self.dispatch_message(raw).await,
            BodyResult::TooLarge { limit } => {
                self.state
                    .metrics
                    .inc(&self.state.metrics.counters.messages_rejected);
                self.reset_transaction();
                tracing::warn!(peer = %self.peer, limit, "rejected an over-sized message");
                self.reply(
                    552,
                    Some("5.3.4"),
                    &format!("message exceeds the {limit} byte limit"),
                )
                .await
            }
            BodyResult::Aborted { timed_out } => {
                if timed_out {
                    self.state
                        .metrics
                        .inc(&self.state.metrics.counters.sessions_timed_out);
                }
                self.reset_transaction();
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    if timed_out {
                        "timed out during DATA"
                    } else {
                        "client disconnected during DATA"
                    },
                ))
            }
        }
    }

    async fn dispatch_message(&mut self, raw: Vec<u8>) -> std::io::Result<()> {
        let sender = self.envelope_sender.clone().unwrap_or_default();
        let recipients = std::mem::take(&mut self.recipients);
        let queue_id = new_queue_id();

        let inbound = InboundMessage {
            id: queue_id.clone(),
            sender: sender.clone(),
            recipients: recipients.clone(),
            raw,
            client_ip: Some(self.peer.ip()),
            helo: self.helo_name.clone(),
        };

        tracing::info!(
            id = %queue_id,
            peer = %self.peer,
            from = %sender,
            recipients = recipients.len(),
            bytes = inbound.raw.len(),
            "accepted message"
        );

        let outcome = dispatch::submit(&self.state, inbound).await;
        self.reset_transaction();

        match outcome {
            SubmitOutcome::Delivered { relay_id, response } => {
                self.accepted_messages += 1;
                tracing::debug!(
                    id = %queue_id,
                    relay = %relay_id,
                    "upstream accepted the message: {response}"
                );
                self.reply(
                    250,
                    Some("2.0.0"),
                    &format!("OK: relayed via {relay_id} as {queue_id}"),
                )
                .await
            }
            SubmitOutcome::Queued => {
                self.accepted_messages += 1;
                self.reply(250, Some("2.0.0"), &format!("OK: queued as {queue_id}"))
                    .await
            }
            SubmitOutcome::Rejected {
                code,
                enhanced,
                message,
            } => {
                self.state
                    .metrics
                    .inc(&self.state.metrics.counters.messages_rejected);
                tracing::warn!(id = %queue_id, code, "refused message: {message}");
                self.reply(code, Some(enhanced), &message).await
            }
        }
    }

    // -- helpers ------------------------------------------------------------

    fn reset_transaction(&mut self) {
        self.envelope_sender = None;
        self.recipients.clear();
    }

    async fn protocol_error(
        &mut self,
        code: u16,
        enhanced: &'static str,
        message: &str,
    ) -> std::io::Result<()> {
        self.protocol_errors += 1;
        tracing::debug!(peer = %self.peer, code, "protocol error: {message}");
        self.reply(code, Some(enhanced), message).await
    }

    async fn reply(
        &mut self,
        code: u16,
        enhanced: Option<&str>,
        message: &str,
    ) -> std::io::Result<()> {
        // Enhanced status codes are only meaningful to ESMTP clients.
        let line = match enhanced.filter(|_| self.esmtp) {
            Some(status) => format!("{code} {status} {}\r\n", sanitize(message)),
            None => format!("{code} {}\r\n", sanitize(message)),
        };
        self.write_raw(line.as_bytes()).await
    }

    async fn write_raw(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(bytes).await?;
        self.writer.flush().await
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BodyResult {
    Complete(Vec<u8>),
    TooLarge { limit: usize },
    Aborted { timed_out: bool },
}

/// Reads a `DATA` payload up to the `<CRLF>.<CRLF>` terminator, undoing SMTP
/// dot-stuffing and nothing else.
///
/// Generic over the reader so the exact code the daemon runs is what the tests
/// exercise. An over-sized message is drained to the terminator rather than
/// abandoned, which keeps the connection usable for the next transaction.
async fn read_body<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut LineReader<R>,
    limit: usize,
    timeout: Duration,
) -> std::io::Result<BodyResult> {
    // A single body line may be as long as the whole message budget: HTML
    // campaign bodies are sometimes emitted without any line folding.
    let line_limit = limit.saturating_add(MAX_COMMAND_LINE);
    let mut raw: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut over_size = false;

    loop {
        let line = match tokio::time::timeout(timeout, reader.read_line(line_limit)).await {
            Ok(Ok(ReadLine::Line(line))) => line,
            Ok(Ok(ReadLine::TooLong)) => {
                over_size = true;
                continue;
            }
            Ok(Ok(ReadLine::Eof)) => return Ok(BodyResult::Aborted { timed_out: false }),
            Ok(Err(error)) => return Err(error),
            Err(_elapsed) => return Ok(BodyResult::Aborted { timed_out: true }),
        };

        // Checked before un-stuffing, so a body line containing a single dot
        // (sent as `..`) is never mistaken for the terminator.
        if line == b"." {
            break;
        }

        if over_size {
            continue;
        }

        let payload = match line.first() {
            Some(b'.') => &line[1..],
            _ => &line[..],
        };

        if raw.len() + payload.len() + 2 > limit {
            over_size = true;
            // Release the partial copy immediately; it will not be used.
            raw = Vec::new();
            continue;
        }
        raw.extend_from_slice(payload);
        raw.extend_from_slice(b"\r\n");
    }

    if over_size {
        Ok(BodyResult::TooLarge { limit })
    } else {
        Ok(BodyResult::Complete(raw))
    }
}

/// Keeps a reply on one line: an embedded CRLF would forge a protocol response.
fn sanitize(message: &str) -> String {
    let mut cleaned = String::with_capacity(message.len());
    // A CRLF collapses to a single space rather than one per character, so the
    // sanitised text still reads like a sentence.
    let mut pending_space = false;

    for ch in message.chars() {
        match ch {
            '\r' | '\n' => pending_space = true,
            _ if ch.is_control() => {}
            _ => {
                if pending_space && !cleaned.is_empty() {
                    cleaned.push(' ');
                }
                pending_space = false;
                cleaned.push(ch);
            }
        }
    }

    crate::util::truncate(cleaned.trim(), 400)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the real `read_body` over an in-memory stream.
    async fn read(wire: &[u8], limit: usize) -> BodyResult {
        let mut reader = LineReader::new(std::io::Cursor::new(wire.to_vec()));
        read_body(&mut reader, limit, Duration::from_secs(5))
            .await
            .expect("no io error")
    }

    async fn body(wire: &[u8], limit: usize) -> Option<Vec<u8>> {
        match read(wire, limit).await {
            BodyResult::Complete(raw) => Some(raw),
            _ => None,
        }
    }

    #[tokio::test]
    async fn reads_a_simple_body() {
        let raw = body(b"Subject: hi\r\n\r\nhello\r\n.\r\n", 1_000)
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&raw),
            "Subject: hi\r\n\r\nhello\r\n"
        );
    }

    #[tokio::test]
    async fn undoes_dot_stuffing() {
        // `..` on the wire is a literal `.` in the message, and a line that
        // merely starts with a dot must keep its remaining text.
        let raw = body(b"a\r\n..\r\n...stuff\r\nb\r\n.\r\n", 1_000)
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&raw), "a\r\n.\r\n..stuff\r\nb\r\n");
    }

    #[tokio::test]
    async fn a_body_line_of_dot_is_not_the_terminator() {
        let raw = body(b"before\r\n..\r\nafter\r\n.\r\n", 1_000).await.unwrap();
        assert!(String::from_utf8_lossy(&raw).contains("before\r\n.\r\nafter"));
    }

    #[tokio::test]
    async fn mime_payloads_survive_byte_for_byte() {
        let wire = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=\"--_b\"\r\n\
\r\n\
----_b\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
PGh0bWw+PGltZyBzcmM9Imh0dHBzOi8veC5pby9wLmdpZiIvPjwvaHRtbD4=\r\n\
----_b--\r\n\
.\r\n";
        let raw = body(wire, 100_000).await.unwrap();
        let text = String::from_utf8_lossy(&raw);

        assert!(text.contains("boundary=\"--_b\""));
        assert!(text.contains("PGh0bWw+PGltZyBzcmM9Imh0dHBzOi8veC5pby9wLmdpZiIvPjwvaHRtbD4="));
        assert!(text.ends_with("----_b--\r\n"));
        assert!(!text.contains("\r\n.\r\n"), "terminator must not be kept");
    }

    #[tokio::test]
    async fn empty_body_is_allowed() {
        let raw = body(b".\r\n", 1_000).await.unwrap();
        assert!(raw.is_empty());
    }

    #[tokio::test]
    async fn oversize_bodies_are_rejected_but_fully_drained() {
        let big = "x".repeat(5_000);
        let wire = format!("{big}\r\n.\r\nQUIT\r\n");
        let mut reader = LineReader::new(std::io::Cursor::new(wire.into_bytes()));

        let result = read_body(&mut reader, 1_000, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, BodyResult::TooLarge { limit: 1_000 });

        // The terminator was consumed, so the session can carry on.
        assert_eq!(
            reader.read_line(512).await.unwrap(),
            ReadLine::Line(b"QUIT".to_vec())
        );
    }

    #[tokio::test]
    async fn oversize_is_detected_across_many_small_lines() {
        let mut wire = String::new();
        for _ in 0..200 {
            wire.push_str("0123456789\r\n");
        }
        wire.push_str(".\r\n");
        assert_eq!(
            read(wire.as_bytes(), 500).await,
            BodyResult::TooLarge { limit: 500 }
        );
    }

    #[tokio::test]
    async fn truncated_data_is_reported() {
        assert_eq!(
            read(b"no terminator here\r\n", 1_000).await,
            BodyResult::Aborted { timed_out: false }
        );
    }

    #[tokio::test]
    async fn a_message_at_exactly_the_limit_is_accepted() {
        // "abc\r\n" is five bytes.
        assert!(body(b"abc\r\n.\r\n", 5).await.is_some());
        assert_eq!(read(b"abcd\r\n.\r\n", 5).await, BodyResult::TooLarge { limit: 5 });
    }

    #[test]
    fn replies_cannot_be_forged_through_injection() {
        let forged = sanitize("ok\r\n250 injected");
        assert!(!forged.contains('\r'));
        assert!(!forged.contains('\n'));
        assert_eq!(forged, "ok 250 injected");
    }

    #[test]
    fn reply_text_is_bounded() {
        assert!(sanitize(&"y".repeat(1_000)).chars().count() <= 400);
    }
}
