//! Byte-exact RFC 5322 header codec.
//!
//! The body is never parsed, decoded or re-encoded: it is carried as an opaque
//! byte slice from the moment `DATA` ends until the message is handed to the
//! upstream relay. That is what guarantees MIME boundaries, base64 and
//! quoted-printable payloads, and Mautic's tracking pixels and links survive
//! the rewrite untouched.
//!
//! Header *values* are also stored verbatim, including their original folding,
//! so headers we do not modify are reproduced bit for bit.

use crate::error::MessageError;

/// A single header field with its raw, still-folded value.
#[derive(Debug, Clone)]
pub struct Header {
    /// Field name exactly as it appeared on the wire (`Content-Type`).
    pub name: String,
    /// Lowercased field name, for case-insensitive lookups.
    lower: String,
    /// Everything after the colon, including the leading space and any
    /// CRLF + whitespace folding, but excluding the final CRLF.
    pub raw_value: Vec<u8>,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl AsRef<str>) -> Self {
        let name = name.into();
        let lower = name.to_ascii_lowercase();
        let mut raw_value = Vec::with_capacity(value.as_ref().len() + 1);
        raw_value.push(b' ');
        raw_value.extend_from_slice(value.as_ref().as_bytes());
        Self {
            name,
            lower,
            raw_value,
        }
    }

    fn from_parts(name: String, raw_value: Vec<u8>) -> Self {
        let lower = name.to_ascii_lowercase();
        Self {
            name,
            lower,
            raw_value,
        }
    }

    // Part of the codec surface; currently only the tests need it.
    #[allow(dead_code)]
    pub fn name_lower(&self) -> &str {
        &self.lower
    }

    /// The value with folding collapsed into single spaces and invalid UTF-8
    /// replaced, suitable for parsing or logging.
    pub fn unfolded(&self) -> String {
        unfold(&self.raw_value)
    }
}

/// Collapses RFC 5322 folding whitespace into single spaces.
pub fn unfold(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for ch in text.chars() {
        match ch {
            '\r' | '\n' => pending_space = true,
            ' ' | '\t' => pending_space = true,
            _ => {
                if pending_space && !out.is_empty() {
                    out.push(' ');
                }
                pending_space = false;
                out.push(ch);
            }
        }
    }
    out
}

/// A parsed message: an ordered header list plus an untouched body.
#[derive(Debug, Clone)]
pub struct Message {
    headers: Vec<Header>,
    body: Vec<u8>,
    /// True when the source used bare LF line endings; output is always CRLF.
    pub was_lf_only: bool,
}

impl Message {
    /// Splits `raw` at the first empty line and parses the header block.
    ///
    /// A message with no empty line is treated as header-only rather than
    /// rejected, which is what real submission clients occasionally produce.
    pub fn parse(raw: &[u8]) -> Result<Self, MessageError> {
        if raw.is_empty() {
            return Err(MessageError::NoHeaderSeparator);
        }

        let (header_block, body, was_lf_only) = split_header_block(raw);
        let headers = parse_header_block(header_block);

        Ok(Self {
            headers,
            body: body.to_vec(),
            was_lf_only,
        })
    }

    // These three read-only views exist so the tests can assert byte
    // preservation; the daemon itself only ever mutates and re-serialises.
    #[allow(dead_code)]
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    #[allow(dead_code)]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn get(&self, name: &str) -> Option<&Header> {
        let needle = name.to_ascii_lowercase();
        self.headers.iter().find(|h| h.lower == needle)
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Unfolded value of the first matching header.
    pub fn value(&self, name: &str) -> Option<String> {
        self.get(name).map(|h| h.unfolded())
    }

    #[allow(dead_code)]
    pub fn count(&self, name: &str) -> usize {
        let needle = name.to_ascii_lowercase();
        self.headers.iter().filter(|h| h.lower == needle).count()
    }

    /// Removes every instance of `name`, returning how many were dropped.
    pub fn remove_all(&mut self, name: &str) -> usize {
        let needle = name.to_ascii_lowercase();
        let before = self.headers.len();
        self.headers.retain(|h| h.lower != needle);
        before - self.headers.len()
    }

    /// Removes every header whose lowercased name starts with `prefix`.
    pub fn remove_prefix(&mut self, prefix: &str) -> usize {
        let needle = prefix.to_ascii_lowercase();
        let before = self.headers.len();
        self.headers.retain(|h| !h.lower.starts_with(&needle));
        before - self.headers.len()
    }

    /// Replaces the first instance in place (preserving header order) and drops
    /// any duplicates. Appends when the header is absent.
    pub fn set(&mut self, name: &str, value: impl AsRef<str>) {
        let needle = name.to_ascii_lowercase();
        let replacement = Header::new(name.to_string(), value);

        match self.headers.iter().position(|h| h.lower == needle) {
            Some(index) => {
                self.headers[index] = replacement;
                let mut seen = false;
                self.headers.retain(|h| {
                    if h.lower != needle {
                        return true;
                    }
                    if seen {
                        false
                    } else {
                        seen = true;
                        true
                    }
                });
            }
            None => self.headers.push(replacement),
        }
    }

    /// Inserts at the very top of the header block (used for `Received`).
    pub fn prepend(&mut self, name: &str, value: impl AsRef<str>) {
        self.headers.insert(0, Header::new(name.to_string(), value));
    }

    /// Appends without touching existing instances (used for trace headers).
    pub fn append(&mut self, name: &str, value: impl AsRef<str>) {
        self.headers.push(Header::new(name.to_string(), value));
    }

    /// Re-serialises the message with canonical CRLF line endings.
    pub fn to_bytes(&self) -> Vec<u8> {
        let estimated = self
            .headers
            .iter()
            .map(|h| h.name.len() + h.raw_value.len() + 3)
            .sum::<usize>()
            + self.body.len()
            + 2;
        let mut out = Vec::with_capacity(estimated);

        for header in &self.headers {
            out.extend_from_slice(header.name.as_bytes());
            out.push(b':');
            if self.was_lf_only {
                out.extend_from_slice(&normalize_crlf(&header.raw_value));
            } else {
                out.extend_from_slice(&header.raw_value);
            }
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");

        if self.was_lf_only {
            out.extend_from_slice(&normalize_crlf(&self.body));
        } else {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

/// Locates the blank line separating headers from body.
fn split_header_block(raw: &[u8]) -> (&[u8], &[u8], bool) {
    if let Some(index) = find(raw, b"\r\n\r\n") {
        return (&raw[..index + 2], &raw[index + 4..], false);
    }
    if let Some(index) = find(raw, b"\n\n") {
        return (&raw[..index + 1], &raw[index + 2..], true);
    }
    // Header-only message: keep everything as headers.
    let lf_only = !raw.windows(2).any(|w| w == b"\r\n") && raw.contains(&b'\n');
    (raw, &[], lf_only)
}

fn parse_header_block(block: &[u8]) -> Vec<Header> {
    let mut headers: Vec<Header> = Vec::with_capacity(24);
    let mut current: Option<(String, Vec<u8>)> = None;

    for line in split_lines(block) {
        if line.is_empty() {
            continue;
        }

        let is_continuation = matches!(line[0], b' ' | b'\t');
        if is_continuation {
            if let Some((_, value)) = current.as_mut() {
                value.extend_from_slice(b"\r\n");
                value.extend_from_slice(line);
                continue;
            }
            // Continuation with no preceding field: drop the malformed line.
            continue;
        }

        if let Some((name, value)) = current.take() {
            headers.push(Header::from_parts(name, value));
        }

        match line.iter().position(|&b| b == b':') {
            Some(colon) if colon > 0 => {
                let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
                let value = line[colon + 1..].to_vec();
                current = Some((name, value));
            }
            // A line with no colon is not a header field; ignore it rather
            // than corrupting the following fields.
            _ => current = None,
        }
    }

    if let Some((name, value)) = current.take() {
        headers.push(Header::from_parts(name, value));
    }

    headers
}

/// Yields lines without their trailing CR/LF, tolerating both endings.
fn split_lines(block: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    while index < block.len() {
        if block[index] == b'\n' {
            let mut end = index;
            if end > start && block[end - 1] == b'\r' {
                end -= 1;
            }
            lines.push(&block[start..end]);
            start = index + 1;
        }
        index += 1;
    }
    if start < block.len() {
        lines.push(&block[start..]);
    }
    lines
}

fn normalize_crlf(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 32);
    let mut previous = 0u8;
    for &byte in input {
        if byte == b'\n' && previous != b'\r' {
            out.push(b'\r');
        }
        out.push(byte);
        previous = byte;
    }
    out
}

/// Reads one header value straight out of a raw message without copying the
/// body.
///
/// Used on the hot path where only the `From` or `Subject` is needed: a full
/// [`Message::parse`] would clone the entire body, which is wasteful for a
/// 25 MB campaign send.
pub fn peek(raw: &[u8], name: &str) -> Option<String> {
    let (block, _, _) = split_header_block(raw);
    let needle = name.to_ascii_lowercase();
    let mut current: Option<Vec<u8>> = None;

    for line in split_lines(block) {
        if line.is_empty() {
            break;
        }
        let is_continuation = matches!(line[0], b' ' | b'\t');

        if is_continuation {
            if let Some(value) = current.as_mut() {
                value.extend_from_slice(b"\r\n");
                value.extend_from_slice(line);
            }
            continue;
        }
        if let Some(value) = current.take() {
            return Some(unfold(&value));
        }

        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let field = String::from_utf8_lossy(&line[..colon]);
            if field.trim().to_ascii_lowercase() == needle {
                current = Some(line[colon + 1..].to_vec());
            }
        }
    }

    current.map(|value| unfold(&value))
}

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Mailbox (address) parsing
// ---------------------------------------------------------------------------

/// A `Display Name <local@domain>` pair.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mailbox {
    pub display_name: String,
    pub address: String,
}

impl Mailbox {
    #[allow(dead_code)]
    pub fn domain(&self) -> &str {
        crate::util::address_domain(&self.address)
    }
}

/// Parses the first mailbox out of a header value.
///
/// Handles `Name <a@b>`, `<a@b>`, `a@b`, `"Quoted, Name" <a@b>` and values
/// carrying RFC 5322 comments. Returns `None` when no `@` is present.
pub fn parse_mailbox(value: &str) -> Option<Mailbox> {
    let trimmed = value.trim();
    let first = split_address_list(trimmed).into_iter().next()?;

    // A first entry with no `@` means the commas were inside an unquoted
    // display name (`Acme, Inc. <a@x.io>`), which senders emit often enough
    // that splitting there would throw the name away. Anything else is a real
    // mailbox list, where only the first entry matters.
    if first.contains('@') {
        parse_single_mailbox(&first)
    } else {
        parse_single_mailbox(trimmed)
    }
}

/// Parses a comma-separated mailbox list (`To`, `Cc`, `Bcc`). Recipient lists
/// come from the envelope rather than the headers, so nothing on the hot path
/// needs this yet.
#[allow(dead_code)]
pub fn parse_mailbox_list(value: &str) -> Vec<Mailbox> {
    split_address_list(value)
        .iter()
        .filter_map(|entry| parse_single_mailbox(entry))
        .collect()
}

fn parse_single_mailbox(entry: &str) -> Option<Mailbox> {
    let text = entry.trim();
    if text.is_empty() {
        return None;
    }

    if let Some((open, close)) = find_angle_addr(text) {
        let address = text[open + 1..close].trim().to_string();
        let address = strip_source_route(&address);
        let display = strip_comments(&text[..open]);
        let display_name = unquote(display.trim());
        if address.is_empty() {
            return None;
        }
        return Some(Mailbox {
            display_name,
            address,
        });
    }

    // Bare addr-spec, possibly followed by a comment: `a@b.io (Real Name)`.
    let comment = extract_comment(text);
    let bare = strip_comments(text).trim().to_string();
    let token = bare
        .split_whitespace()
        .find(|t| t.contains('@'))
        .unwrap_or(bare.as_str());
    if !token.contains('@') {
        return None;
    }
    Some(Mailbox {
        display_name: comment.unwrap_or_default(),
        address: strip_source_route(token),
    })
}

/// Finds the outermost `<...>` pair that sits outside any quoted string.
fn find_angle_addr(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut open: Option<usize> = None;
    let mut close: Option<usize> = None;

    for (index, &byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if in_quotes => escaped = true,
            b'"' => in_quotes = !in_quotes,
            b'<' if !in_quotes => open = Some(index),
            b'>' if !in_quotes => {
                if let Some(start) = open {
                    if index > start {
                        close = Some(index);
                    }
                }
            }
            _ => {}
        }
    }

    match (open, close) {
        (Some(o), Some(c)) if c > o => Some((o, c)),
        _ => None,
    }
}

/// Drops the obsolete source-route prefix (`@relay:user@host` -> `user@host`).
fn strip_source_route(address: &str) -> String {
    let trimmed = address.trim();
    if trimmed.starts_with('@') {
        if let Some((_, rest)) = trimmed.split_once(':') {
            return rest.trim().to_string();
        }
    }
    trimmed.to_string()
}

fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in text.chars() {
        if escaped {
            if depth == 0 {
                out.push(ch);
            }
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
                if depth == 0 {
                    out.push(ch);
                }
            }
            '"' => {
                in_quotes = !in_quotes;
                out.push(ch);
            }
            '(' if !in_quotes => depth += 1,
            ')' if !in_quotes && depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

fn extract_comment(text: &str) -> Option<String> {
    let start = text.find('(')?;
    let end = text.rfind(')')?;
    if end <= start + 1 {
        return None;
    }
    let comment = text[start + 1..end].trim();
    if comment.is_empty() {
        None
    } else {
        Some(comment.to_string())
    }
}

/// Removes surrounding quotes and unescapes a quoted-string display name.
fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut escaped = false;
        for ch in inner.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        out.trim().to_string()
    } else {
        trimmed.to_string()
    }
}

/// Splits a mailbox list on commas that are not inside quotes, angle brackets
/// or comments.
fn split_address_list(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut angle_depth = 0usize;
    let mut comment_depth = 0usize;

    for ch in value.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
                current.push(ch);
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            '<' if !in_quotes => {
                angle_depth += 1;
                current.push(ch);
            }
            '>' if !in_quotes => {
                angle_depth = angle_depth.saturating_sub(1);
                current.push(ch);
            }
            '(' if !in_quotes => {
                comment_depth += 1;
                current.push(ch);
            }
            ')' if !in_quotes => {
                comment_depth = comment_depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if !in_quotes && angle_depth == 0 && comment_depth == 0 => {
                if !current.trim().is_empty() {
                    parts.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"From: Acme Marketing <campaigns@acme-mautic.io>\r\n\
To: lead@example.org\r\n\
Subject: =?UTF-8?B?SGVsbG8=?=\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=\"__b__\"\r\n\
DKIM-Signature: v=1; a=rsa-sha256; d=acme-mautic.io;\r\n\
\x20b=abcdef/12345+xyz==\r\n\
\r\n\
--__b__\r\n\
Content-Type: text/plain\r\n\
\r\n\
Hello there\r\n\
--__b__--\r\n";

    #[test]
    fn parses_headers_and_keeps_body_bytes() {
        let message = Message::parse(SAMPLE).unwrap();
        assert_eq!(message.headers().len(), 6);
        assert_eq!(message.value("subject").unwrap(), "=?UTF-8?B?SGVsbG8=?=");
        assert!(message.body().starts_with(b"--__b__\r\n"));
        assert!(message.body().ends_with(b"--__b__--\r\n"));
    }

    #[test]
    fn folded_headers_are_preserved_and_unfoldable() {
        let message = Message::parse(SAMPLE).unwrap();
        let dkim = message.get("dkim-signature").unwrap();
        assert!(dkim.raw_value.windows(2).any(|w| w == b"\r\n"));
        assert_eq!(
            dkim.unfolded(),
            "v=1; a=rsa-sha256; d=acme-mautic.io; b=abcdef/12345+xyz=="
        );
    }

    #[test]
    fn round_trip_is_byte_identical() {
        let message = Message::parse(SAMPLE).unwrap();
        assert_eq!(message.to_bytes(), SAMPLE);
    }

    #[test]
    fn header_mutation_keeps_position_and_body() {
        let mut message = Message::parse(SAMPLE).unwrap();
        assert_eq!(message.remove_all("DKIM-Signature"), 1);
        message.set("From", "Acme Marketing <noreply@relay1.com>");
        message.prepend("Received", "from client by proxy; now");

        let output = message.to_bytes();
        let text = String::from_utf8_lossy(&output);
        assert!(text.starts_with("Received: from client by proxy; now\r\n"));
        assert!(!text.contains("DKIM-Signature"));
        assert!(text.contains("From: Acme Marketing <noreply@relay1.com>\r\n"));
        // Body is still exactly what arrived.
        let message = Message::parse(&output).unwrap();
        assert!(message.body().starts_with(b"--__b__\r\n"));
        assert!(message.body().ends_with(b"--__b__--\r\n"));
    }

    #[test]
    fn set_collapses_duplicate_headers() {
        let raw = b"From: a@x.io\r\nFrom: b@x.io\r\nSubject: hi\r\n\r\nbody" as &[u8];
        let mut message = Message::parse(raw).unwrap();
        assert_eq!(message.count("from"), 2);
        message.set("From", "c@x.io");
        assert_eq!(message.count("from"), 1);
        assert_eq!(message.value("from").unwrap(), "c@x.io");
        // The replacement kept the original slot, ahead of Subject.
        assert_eq!(message.headers()[0].name_lower(), "from");
    }

    #[test]
    fn lf_only_input_is_normalised_to_crlf() {
        let raw = b"From: a@x.io\nSubject: hi\n\nline1\nline2\n" as &[u8];
        let message = Message::parse(raw).unwrap();
        assert!(message.was_lf_only);
        let out = message.to_bytes();
        assert_eq!(
            String::from_utf8_lossy(&out),
            "From: a@x.io\r\nSubject: hi\r\n\r\nline1\r\nline2\r\n"
        );
    }

    #[test]
    fn header_only_message_is_accepted() {
        let raw = b"From: a@x.io\r\nSubject: hi\r\n" as &[u8];
        let message = Message::parse(raw).unwrap();
        assert_eq!(message.headers().len(), 2);
        assert!(message.body().is_empty());
    }

    #[test]
    fn remove_prefix_strips_arc_chain() {
        let raw = b"ARC-Seal: i=1\r\nARC-Message-Signature: i=1\r\nFrom: a@x.io\r\n\r\nx" as &[u8];
        let mut message = Message::parse(raw).unwrap();
        assert_eq!(message.remove_prefix("arc-"), 2);
        assert_eq!(message.headers().len(), 1);
    }

    #[test]
    fn peek_reads_single_headers_without_full_parse() {
        assert_eq!(
            peek(SAMPLE, "From").unwrap(),
            "Acme Marketing <campaigns@acme-mautic.io>"
        );
        assert_eq!(peek(SAMPLE, "subject").unwrap(), "=?UTF-8?B?SGVsbG8=?=");
        // Folded values are unfolded, and the body is never examined.
        assert_eq!(
            peek(SAMPLE, "DKIM-Signature").unwrap(),
            "v=1; a=rsa-sha256; d=acme-mautic.io; b=abcdef/12345+xyz=="
        );
        assert!(peek(SAMPLE, "Reply-To").is_none());
        assert!(peek(b"no headers here", "From").is_none());
    }

    #[test]
    fn peek_ignores_body_lines_that_look_like_headers() {
        // The body of the sample contains `Content-Type: text/plain`, which
        // must not be mistaken for a top-level header.
        let value = peek(SAMPLE, "Content-Type").unwrap();
        assert!(value.contains("multipart/alternative"));
    }

    #[test]
    fn mailboxes_parse_across_shapes() {
        let cases = [
            ("Acme <a@x.io>", "Acme", "a@x.io"),
            ("<a@x.io>", "", "a@x.io"),
            ("a@x.io", "", "a@x.io"),
            ("\"Acme, Inc. <hq>\" <a@x.io>", "Acme, Inc. <hq>", "a@x.io"),
            ("a@x.io (Real Name)", "Real Name", "a@x.io"),
            ("=?UTF-8?B?QQ==?= <a@x.io>", "=?UTF-8?B?QQ==?=", "a@x.io"),
            ("  Spaced   <a@x.io>  ", "Spaced", "a@x.io"),
        ];
        for (input, name, address) in cases {
            let mailbox = parse_mailbox(input).unwrap_or_else(|| panic!("failed: {input}"));
            assert_eq!(mailbox.display_name, name, "name for {input}");
            assert_eq!(mailbox.address, address, "address for {input}");
        }
        assert!(parse_mailbox("undisclosed-recipients").is_none());
        assert!(parse_mailbox("").is_none());
    }

    #[test]
    fn mailbox_lists_split_on_real_commas_only() {
        let list = parse_mailbox_list("\"Doe, John\" <j@x.io>, jane@y.io, Bob <b@z.io>");
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].display_name, "Doe, John");
        assert_eq!(list[1].address, "jane@y.io");
        assert_eq!(list[2].address, "b@z.io");
    }

    #[test]
    fn first_mailbox_wins_for_from() {
        let mailbox = parse_mailbox("A <a@x.io>, B <b@x.io>").unwrap();
        assert_eq!(mailbox.address, "a@x.io");
    }

    #[test]
    fn domain_is_extracted() {
        let mailbox = parse_mailbox("A <a@sub.x.io>").unwrap();
        assert_eq!(mailbox.domain(), "sub.x.io");
    }
}
