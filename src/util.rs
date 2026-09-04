//! Small self-contained helpers: CIDR matching, RFC 5322/2047 encoding,
//! identifier generation and human-readable formatting.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

// ---------------------------------------------------------------------------
// CIDR / IP allow-listing
// ---------------------------------------------------------------------------

/// An IPv4 or IPv6 network in CIDR notation.
///
/// A bare address (`10.0.0.5`) is treated as a host route (`/32` or `/128`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(input: &str) -> Result<Self, String> {
        let text = input.trim();
        if text.is_empty() {
            return Err("empty CIDR entry".to_string());
        }

        let (addr_part, prefix_part) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };

        let base: IpAddr = addr_part
            .parse()
            .map_err(|_| format!("`{addr_part}` is not a valid IP address"))?;
        let base = normalize_ip(base);

        let max_prefix = if base.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => p
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("`{p}` is not a valid prefix length"))?,
            None => max_prefix,
        };

        if prefix > max_prefix {
            return Err(format!(
                "prefix /{prefix} is out of range for this address family (max /{max_prefix})"
            ));
        }

        Ok(Self { base, prefix })
    }

    /// Returns true when `ip` falls inside this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        match (self.base, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                prefix_match(&net.octets(), &candidate.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                prefix_match(&net.octets(), &candidate.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.base, self.prefix)
    }
}

/// Collapses IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) to plain IPv4 so
/// that an allow-list written in IPv4 notation still matches clients that
/// arrive over a dual-stack listener.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

fn prefix_match(net: &[u8], candidate: &[u8], prefix: u8) -> bool {
    let full_bytes = (prefix / 8) as usize;
    let remaining_bits = prefix % 8;

    if net[..full_bytes] != candidate[..full_bytes] {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remaining_bits);
    net[full_bytes] & mask == candidate[full_bytes] & mask
}

/// True when the address is loopback (used to relax admin auth locally).
pub fn is_loopback(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Generates a short, monotonically increasing, collision-resistant queue id
/// such as `1r8k2m-0004`. Used as the SMTP queue id and dashboard message key.
/// Unpredictable enough for admin session cookies. Not a CSPRNG, but the
/// values are long, unique per process, and never leave the host.
pub fn new_session_token() -> String {
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u128)
        .unwrap_or(0);
    let mix = nanos
        ^ ((seq as u128) << 48)
        ^ (std::process::id() as u128)
        ^ (std::ptr::addr_of!(SEQUENCE) as u128);
    format!("{mix:032x}{seq:08x}")
}

pub fn new_queue_id() -> String {
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    format!("{}-{:04x}", base36(millis), seq & 0xffff)
}

fn base36(mut value: u64) -> String {
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if value == 0 {
        return "0".to_string();
    }
    let mut out = Vec::with_capacity(13);
    while value > 0 {
        out.push(ALPHABET[(value % 36) as usize]);
        value /= 36;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Header encoding helpers
// ---------------------------------------------------------------------------

/// Formats the current time as an RFC 5322 `Date` header value.
pub fn rfc5322_date_now() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S +0000")
        .to_string()
}

const SPECIALS: &[char] = &[
    '(', ')', '<', '>', '[', ']', ':', ';', '@', '\\', ',', '.', '"',
];

/// Renders a display name so that it is safe to place in front of an angle-addr.
///
/// * Pure-ASCII names containing `specials` are quoted and escaped.
/// * Names that already are RFC 2047 encoded-words are passed through verbatim.
/// * Names containing non-ASCII bytes are re-encoded as a base64 encoded-word,
///   which keeps UTF-8 sender names intact for receivers that do not announce
///   SMTPUTF8.
pub fn encode_display_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Already an encoded-word (possibly several) - leave it exactly as it is.
    if trimmed.starts_with("=?") && trimmed.ends_with("?=") {
        return trimmed.to_string();
    }

    // Already a quoted-string - trust the original quoting.
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        return trimmed.to_string();
    }

    if !trimmed.is_ascii() {
        return format!("=?UTF-8?B?{}?=", B64.encode(trimmed.as_bytes()));
    }

    let needs_quoting = trimmed.chars().any(|c| SPECIALS.contains(&c) || c.is_control());
    if needs_quoting {
        let mut quoted = String::with_capacity(trimmed.len() + 4);
        quoted.push('"');
        for ch in trimmed.chars() {
            if ch == '"' || ch == '\\' {
                quoted.push('\\');
            }
            if !ch.is_control() {
                quoted.push(ch);
            }
        }
        quoted.push('"');
        quoted
    } else {
        trimmed.to_string()
    }
}

/// Builds a `Display Name <addr@example.com>` mailbox, omitting the display
/// part when there is nothing to show.
pub fn format_mailbox(display_name: &str, address: &str) -> String {
    let encoded = encode_display_name(display_name);
    if encoded.is_empty() {
        format!("<{address}>")
    } else {
        format!("{encoded} <{address}>")
    }
}

/// Extracts the domain part of an address, defaulting to `localhost`.
pub fn address_domain(address: &str) -> &str {
    match address.rsplit_once('@') {
        Some((_, domain)) if !domain.is_empty() => domain,
        _ => "localhost",
    }
}

/// Very permissive syntactic check: exactly one `@`, non-empty local and
/// domain parts, a dot-containing domain and no whitespace or angle brackets.
pub fn looks_like_email(address: &str) -> bool {
    let addr = address.trim();
    if addr.is_empty() || addr.len() > 320 {
        return false;
    }
    if addr.chars().any(|c| c.is_whitespace() || c == '<' || c == '>' || c == ',') {
        return false;
    }
    let Some((local, domain)) = addr.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    !domain.contains('@')
}

// ---------------------------------------------------------------------------
// Base64 (inbound SMTP AUTH)
// ---------------------------------------------------------------------------

pub fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn b64_decode(data: &str) -> Option<Vec<u8>> {
    B64.decode(data.trim()).ok()
}

// ---------------------------------------------------------------------------
// Human-readable formatting (dashboard + logs)
// ---------------------------------------------------------------------------

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn human_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let secs = seconds % 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

/// Constant-time-ish comparison for admin tokens.
pub fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Truncates a string for log/dashboard display without splitting a codepoint.
pub fn truncate(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut out: String = input.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matches_ipv4_networks() {
        let net = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(net.contains("10.4.5.6".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));

        let host = Cidr::parse("192.168.1.7").unwrap();
        assert!(host.contains("192.168.1.7".parse().unwrap()));
        assert!(!host.contains("192.168.1.8".parse().unwrap()));

        let all = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn cidr_matches_partial_bytes() {
        let net = Cidr::parse("192.168.16.0/20").unwrap();
        assert!(net.contains("192.168.31.255".parse().unwrap()));
        assert!(!net.contains("192.168.32.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6_is_folded() {
        let net = Cidr::parse("127.0.0.0/8").unwrap();
        assert!(net.contains("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_loopback("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn display_names_are_encoded_safely() {
        assert_eq!(encode_display_name("Acme Marketing"), "Acme Marketing");
        assert_eq!(encode_display_name("Acme, Inc."), "\"Acme, Inc.\"");
        assert_eq!(encode_display_name("=?UTF-8?B?QQ==?="), "=?UTF-8?B?QQ==?=");
        assert_eq!(encode_display_name("Café"), "=?UTF-8?B?Q2Fmw6k=?=");
        assert_eq!(encode_display_name("  "), "");
    }

    #[test]
    fn mailboxes_render_with_and_without_names() {
        assert_eq!(format_mailbox("Bob", "b@x.io"), "Bob <b@x.io>");
        assert_eq!(format_mailbox("", "b@x.io"), "<b@x.io>");
    }

    #[test]
    fn email_shape_is_validated() {
        assert!(looks_like_email("a@b.io"));
        assert!(!looks_like_email("a@@b.io"));
        assert!(!looks_like_email("no-at-sign"));
        assert!(!looks_like_email("a b@c.io"));
        assert!(!looks_like_email(""));
    }
}
