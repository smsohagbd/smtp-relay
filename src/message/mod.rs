//! Message parsing and rewriting.

pub mod headers;
pub mod rewrite;
pub mod rotation;

pub use headers::parse_mailbox;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// Decodes RFC 2047 encoded-words for **display purposes only**.
///
/// This is used for the dashboard and log lines; the header transmitted
/// upstream is always the original encoded form, so no information is lost and
/// no re-encoding bugs can reach the wire.
pub fn decode_encoded_words(input: &str) -> String {
    if !input.contains("=?") {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    // Tracks whether the previous token was an encoded-word, because RFC 2047
    // says whitespace between two adjacent encoded-words is not significant.
    let mut previous_was_encoded = false;

    while let Some(start) = rest.find("=?") {
        let (before, tail) = rest.split_at(start);

        match parse_encoded_word(tail) {
            Some((decoded, consumed)) => {
                if !(previous_was_encoded && before.trim().is_empty() && !before.is_empty()) {
                    out.push_str(before);
                }
                out.push_str(&decoded);
                rest = &tail[consumed..];
                previous_was_encoded = true;
            }
            None => {
                // Not a real encoded-word; emit the marker and continue.
                out.push_str(before);
                out.push_str("=?");
                rest = &tail[2..];
                previous_was_encoded = false;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Parses one `=?charset?enc?text?=` token, returning the decoded text and how
/// many bytes of `input` it occupied.
fn parse_encoded_word(input: &str) -> Option<(String, usize)> {
    let body = input.strip_prefix("=?")?;
    let end = body.find("?=")?;
    let token = &body[..end];
    let consumed = 2 + end + 2;

    let mut parts = token.splitn(3, '?');
    let charset = parts.next()?.to_ascii_lowercase();
    let encoding = parts.next()?.to_ascii_lowercase();
    let text = parts.next()?;
    if text.contains('?') {
        return None;
    }

    let bytes = match encoding.as_str() {
        "b" => B64.decode(text).ok()?,
        "q" => decode_quoted_printable_word(text),
        _ => return None,
    };

    let decoded = match charset.as_str() {
        "utf-8" | "utf8" | "us-ascii" | "ascii" => String::from_utf8_lossy(&bytes).into_owned(),
        // Latin-1 family: each byte maps directly onto the matching codepoint.
        _ => bytes.iter().map(|&b| b as char).collect(),
    };
    Some((decoded, consumed))
}

/// Q-encoding: `_` means space and `=XX` is a hex escape.
fn decode_quoted_printable_word(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'_' => {
                out.push(b' ');
                index += 1;
            }
            b'=' if index + 2 < bytes.len() => {
                match hex_pair(bytes[index + 1], bytes[index + 2]) {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(b'=');
                        index += 1;
                    }
                }
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    out
}

fn hex_pair(high: u8, low: u8) -> Option<u8> {
    Some((hex_digit(high)? << 4) | hex_digit(low)?)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_passes_through() {
        assert_eq!(decode_encoded_words("Hello world"), "Hello world");
    }

    #[test]
    fn base64_words_are_decoded() {
        assert_eq!(
            decode_encoded_words("=?UTF-8?B?SGVsbG8gd29ybGQ=?="),
            "Hello world"
        );
    }

    #[test]
    fn quoted_printable_words_are_decoded() {
        assert_eq!(
            decode_encoded_words("=?UTF-8?Q?Your_September_Offer?="),
            "Your September Offer"
        );
        assert_eq!(decode_encoded_words("=?UTF-8?Q?Caf=C3=A9?="), "Café");
    }

    #[test]
    fn mixed_content_keeps_literal_parts() {
        assert_eq!(
            decode_encoded_words("Re: =?UTF-8?B?SGVsbG8=?= (urgent)"),
            "Re: Hello (urgent)"
        );
    }

    #[test]
    fn adjacent_words_join_without_separator() {
        assert_eq!(
            decode_encoded_words("=?UTF-8?Q?Caf=C3=A9?= =?UTF-8?Q?_Bar?="),
            "Café Bar"
        );
    }

    #[test]
    fn malformed_words_are_left_intact() {
        assert_eq!(decode_encoded_words("=?broken"), "=?broken");
        assert_eq!(
            decode_encoded_words("=?UTF-8?X?unknown?="),
            "=?UTF-8?X?unknown?="
        );
    }

    #[test]
    fn latin1_charsets_are_mapped() {
        assert_eq!(
            decode_encoded_words("=?ISO-8859-1?Q?Caf=E9?="),
            "Café"
        );
    }
}
