//! Content rotation: swap subject/body while keeping inbound tracking links.
//!
//! The inbound HTML is scanned in document order. The first `<a href>` becomes
//! `{{link1}}`, the second `{{link2}}`, and so on. Open-tracking pixels are
//! copied onto the new HTML so opens still count.

use crate::config::ContentTemplate;
use crate::message::headers::Message;
use crate::util::encode_display_name;

const PLACEHOLDER: &str = "{{link";

/// Tracking extracted from the inbound message.
#[derive(Debug, Clone, Default)]
pub struct ExtractedTracking {
    pub links: Vec<String>,
    pub pixels: Vec<String>,
    pub unsubscribe: Option<String>,
}

/// Applies one template to an already-parsed message. Headers other than
/// Subject / Content-Type / MIME-Version / Content-Transfer-Encoding stay.
pub fn apply_template(
    message: &mut Message,
    original_raw: &[u8],
    template: &ContentTemplate,
    notes: &mut Vec<String>,
) {
    let tracking = extract_tracking(original_raw);
    let mut html = if template.body.trim().is_empty() {
        extract_html(original_raw).unwrap_or_else(|| String::from_utf8_lossy(message.body()).into_owned())
    } else {
        template.body.clone()
    };
    html = replace_placeholders(&html, &tracking);
    html = inject_pixels(&html, &tracking.pixels);

    if !template.subject.trim().is_empty() {
        let subject = replace_placeholders(template.subject.trim(), &tracking);
        message.set("Subject", encode_display_name(&subject).trim_matches('"'));
    }

    let boundary = format!("----=_sr-rot-{}", crate::util::new_session_token());
    let plain = html_to_text(&html);
    let body = build_alternative(&boundary, &plain, &html);
    message.set("MIME-Version", "1.0");
    message.set(
        "Content-Type",
        format!("multipart/alternative; boundary=\"{boundary}\""),
    );
    message.remove_all("Content-Transfer-Encoding");
    message.set_body(body);

    notes.push(format!(
        "content rotation `{}` ({} tracked link(s), {} pixel(s))",
        if template.id.trim().is_empty() {
            "unnamed"
        } else {
            template.id.trim()
        },
        tracking.links.len(),
        tracking.pixels.len()
    ));
}

pub fn extract_tracking(raw: &[u8]) -> ExtractedTracking {
    let html = extract_html(raw).unwrap_or_default();
    let mut links = extract_hrefs(&html);
    if links.is_empty() {
        if let Some(text) = extract_text(raw) {
            links = extract_bare_urls(&text);
        }
    }
    let pixels = extract_pixels(&html);
    let unsubscribe = extract_unsubscribe(raw);
    if let Some(url) = unsubscribe.as_ref() {
        if !links.iter().any(|existing| existing == url) {
            links.push(url.clone());
        }
    }
    ExtractedTracking {
        links,
        pixels,
        unsubscribe,
    }
}

/// True when this template is meant for the inbound Subject.
pub fn template_matches(template: &ContentTemplate, inbound_subject: &str) -> bool {
    let needle = normalize_subject(&template.match_subject);
    !needle.is_empty() && needle == normalize_subject(inbound_subject)
}

pub fn normalize_subject(value: &str) -> String {
    crate::message::decode_encoded_words(value)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn extract_unsubscribe(raw: &[u8]) -> Option<String> {
    let message = Message::parse(raw).ok()?;
    let value = message.value("list-unsubscribe")?;
    list_unsubscribe_https(&value)
}

fn list_unsubscribe_https(value: &str) -> Option<String> {
    let mut rest = value;
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        let end = rest.find('>')?;
        let inner = rest[..end].trim();
        rest = &rest[end + 1..];
        if keep_url(inner) {
            return Some(inner.to_string());
        }
    }
    value
        .split([',', ' ', '\t'])
        .map(|token| token.trim_matches(['<', '>', '"', '\'']))
        .find(|token| keep_url(token))
        .map(ToString::to_string)
}

fn extract_html(raw: &[u8]) -> Option<String> {
    let message = Message::parse(raw).ok()?;
    let content_type = message.value("content-type").unwrap_or_default();
    if content_type.to_ascii_lowercase().contains("multipart") {
        if let Some(boundary) = content_type_param(&content_type, "boundary") {
            for part in split_multipart(message.body(), &boundary) {
                if part_is(&part, "text/html") {
                    return Some(decode_part_body(&part));
                }
            }
        }
    }
    if content_type.to_ascii_lowercase().contains("text/html") {
        return Some(decode_body(message.body(), &message.value("content-transfer-encoding").unwrap_or_default()));
    }
    let lossy = String::from_utf8_lossy(message.body());
    if lossy.contains("<html") || lossy.contains("<a ") || lossy.contains("<img") {
        return Some(lossy.into_owned());
    }
    None
}

fn extract_text(raw: &[u8]) -> Option<String> {
    let message = Message::parse(raw).ok()?;
    let content_type = message.value("content-type").unwrap_or_default();
    if content_type.to_ascii_lowercase().contains("multipart") {
        if let Some(boundary) = content_type_param(&content_type, "boundary") {
            for part in split_multipart(message.body(), &boundary) {
                if part_is(&part, "text/plain") {
                    return Some(decode_part_body(&part));
                }
            }
        }
    }
    if content_type.to_ascii_lowercase().contains("text/plain") {
        return Some(decode_body(
            message.body(),
            &message.value("content-transfer-encoding").unwrap_or_default(),
        ));
    }
    None
}

fn content_type_param(header: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let lower = header.to_ascii_lowercase();
    let start = lower.find(&needle)? + needle.len();
    let rest = header[start..].trim();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        return Some(stripped[..end].to_string());
    }
    let end = rest
        .find(|c: char| c == ';' || c.is_whitespace())
        .unwrap_or(rest.len());
    Some(rest[..end].trim_matches('"').to_string())
}

fn split_multipart(body: &[u8], boundary: &str) -> Vec<Vec<u8>> {
    let marker = format!("--{boundary}");
    let text = String::from_utf8_lossy(body);
    let mut parts = Vec::new();
    for chunk in text.split(&marker) {
        let chunk = chunk.trim_start_matches("\r\n").trim_start_matches('\n');
        if chunk.is_empty() || chunk.starts_with("--") {
            continue;
        }
        parts.push(chunk.as_bytes().to_vec());
    }
    parts
}

fn part_is(part: &[u8], mime: &str) -> bool {
    let text = String::from_utf8_lossy(part).to_ascii_lowercase();
    let headers = text.split("\r\n\r\n").next().unwrap_or(&text);
    let headers = headers.split("\n\n").next().unwrap_or(headers);
    headers.contains(mime)
}

fn decode_part_body(part: &[u8]) -> String {
    let text = String::from_utf8_lossy(part);
    let (header_block, body) = split_part(&text);
    let mut encoding = String::new();
    for line in header_block.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-transfer-encoding:") {
            encoding = value.trim().to_string();
        }
    }
    decode_body(body.as_bytes(), &encoding)
}

fn split_part(part: &str) -> (&str, &str) {
    if let Some(index) = part.find("\r\n\r\n") {
        (&part[..index], &part[index + 4..])
    } else if let Some(index) = part.find("\n\n") {
        (&part[..index], &part[index + 2..])
    } else {
        ("", part)
    }
}

fn decode_body(body: &[u8], encoding: &str) -> String {
    let encoding = encoding.trim().to_ascii_lowercase();
    let bytes = if encoding == "base64" {
        let flat: String = String::from_utf8_lossy(body)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, flat)
            .unwrap_or_else(|_| body.to_vec())
    } else if encoding == "quoted-printable" {
        decode_quoted_printable(body)
    } else {
        body.to_vec()
    };
    String::from_utf8_lossy(&bytes).into_owned()
}

fn decode_quoted_printable(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'=' && index + 1 < input.len() {
            if input[index + 1] == b'\r' || input[index + 1] == b'\n' {
                index += 1;
                if index < input.len() && input[index] == b'\r' {
                    index += 1;
                }
                if index < input.len() && input[index] == b'\n' {
                    index += 1;
                }
                continue;
            }
            if index + 2 < input.len() {
                if let (Some(high), Some(low)) = (hex(input[index + 1]), hex(input[index + 2])) {
                    out.push((high << 4) | low);
                    index += 3;
                    continue;
                }
            }
        }
        out.push(input[index]);
        index += 1;
    }
    out
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn extract_hrefs(html: &str) -> Vec<String> {
    let mut links = Vec::new();
    let lower = html.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut search = 0;
    while let Some(rel) = find_subslice(&bytes[search..], b"href") {
        let start = search + rel + 4;
        let rest = html[start..].trim_start();
        let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
        let url = if let Some(quoted) = rest.strip_prefix('"') {
            quoted.split('"').next().unwrap_or("")
        } else if let Some(quoted) = rest.strip_prefix('\'') {
            quoted.split('\'').next().unwrap_or("")
        } else {
            rest.split(|c: char| c.is_whitespace() || c == '>')
                .next()
                .unwrap_or("")
        };
        search = start + 1;
        if keep_url(url) && !links.iter().any(|existing| existing == url) {
            links.push(url.to_string());
        }
    }
    links
}

fn extract_bare_urls(text: &str) -> Vec<String> {
    let mut links = Vec::new();
    for token in text.split_whitespace() {
        let token = token.trim_end_matches(['.', ',', ')', ']']);
        if keep_url(token) && !links.iter().any(|existing| existing == token) {
            links.push(token.to_string());
        }
    }
    links
}

fn extract_pixels(html: &str) -> Vec<String> {
    let mut pixels = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut search = 0;
    while let Some(rel) = lower[search..].find("<img") {
        let start = search + rel;
        let end = lower[start..].find('>').map(|i| start + i + 1).unwrap_or(lower.len());
        let tag = &html[start..end];
        search = end;
        if let Some(src) = attr(tag, "src") {
            if looks_like_pixel(tag, &src) && !pixels.iter().any(|existing| existing == &src) {
                pixels.push(src);
            }
        }
    }
    pixels
}

fn looks_like_pixel(tag: &str, src: &str) -> bool {
    let tag = tag.to_ascii_lowercase();
    let src = src.to_ascii_lowercase();
    tag.contains("width=\"1\"")
        || tag.contains("width='1'")
        || tag.contains("height=\"1\"")
        || tag.contains("height='1'")
        || src.contains("/email/")
        || src.contains("tracking")
        || src.contains("pixel")
        || src.contains("/open")
        || src.ends_with(".gif")
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{name}=");
    let pos = lower.find(&needle)?;
    let rest = tag[pos + needle.len()..].trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        return Some(quoted.split('"').next()?.to_string());
    }
    if let Some(quoted) = rest.strip_prefix('\'') {
        return Some(quoted.split('\'').next()?.to_string());
    }
    Some(
        rest.split(|c: char| c.is_whitespace() || c == '>')
            .next()?
            .to_string(),
    )
}

fn keep_url(url: &str) -> bool {
    let url = url.trim();
    if url.is_empty() || url.starts_with('#') || url.starts_with("{{") {
        return false;
    }
    let lower = url.to_ascii_lowercase();
    (lower.starts_with("http://") || lower.starts_with("https://"))
        && !lower.starts_with("mailto:")
        && !lower.starts_with("javascript:")
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|window| window == needle)
}

pub fn replace_placeholders(input: &str, tracking: &ExtractedTracking) -> String {
    let mut out = replace_link_placeholders(input, &tracking.links);
    if let Some(url) = tracking.unsubscribe.as_deref() {
        for token in ["{{unsubscribe}}", "{{UNSUBSCRIBE}}", "{{ unsubscribe }}"] {
            out = replace_ci(&out, token, url);
        }
    }
    out
}

pub fn replace_link_placeholders(input: &str, links: &[String]) -> String {
    let mut out = input.to_string();
    if !out.contains(PLACEHOLDER) && !out.to_ascii_lowercase().contains("{{link") {
        return out;
    }
    for (index, link) in links.iter().enumerate() {
        let n = index + 1;
        for token in [
            format!("{{{{link{n}}}}}"),
            format!("{{{{LINK{n}}}}}"),
            format!("{{{{ link{n} }}}}"),
        ] {
            out = out.replace(&token, link);
        }
    }
    out
}

fn inject_pixels(html: &str, pixels: &[String]) -> String {
    if pixels.is_empty() {
        return html.to_string();
    }
    if html.to_ascii_lowercase().contains("{{pixel}}") {
        let tags = pixels
            .iter()
            .map(|src| format!("<img src=\"{src}\" width=\"1\" height=\"1\" alt=\"\" />"))
            .collect::<Vec<_>>()
            .join("");
        return replace_ci(html, "{{pixel}}", &tags);
    }
    let tags = pixels
        .iter()
        .map(|src| format!("<img src=\"{src}\" width=\"1\" height=\"1\" alt=\"\" />"))
        .collect::<Vec<_>>()
        .join("");
    if let Some(index) = html.to_ascii_lowercase().rfind("</body>") {
        let mut out = String::with_capacity(html.len() + tags.len());
        out.push_str(&html[..index]);
        out.push_str(&tags);
        out.push_str(&html[index..]);
        out
    } else {
        format!("{html}{tags}")
    }
}

fn replace_ci(input: &str, needle: &str, replacement: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    if let Some(index) = lower.find(&needle) {
        let mut out = String::new();
        out.push_str(&input[..index]);
        out.push_str(replacement);
        out.push_str(&input[index + needle.len()..]);
        out
    } else {
        input.to_string()
    }
}

fn html_to_text(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn build_alternative(boundary: &str, plain: &str, html: &str) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    out.push_str(&encode_quoted_printable(plain));
    out.push_str("\r\n");
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/html; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    out.push_str(&encode_quoted_printable(html));
    out.push_str("\r\n");
    out.push_str(&format!("--{boundary}--\r\n"));
    out.into_bytes()
}

fn encode_quoted_printable(input: &str) -> String {
    let mut line = String::new();
    let mut out = String::new();
    for byte in input.as_bytes() {
        let encoded = match *byte {
            b'\n' => {
                out.push_str(&line);
                out.push_str("\r\n");
                line.clear();
                continue;
            }
            b'\r' => continue,
            b' ' | b'\t' | 33..=60 | 62..=126 => {
                (*byte as char).to_string()
            }
            _ => format!("={byte:02X}"),
        };
        if line.len() + encoded.len() > 73 {
            out.push_str(&line);
            out.push_str("=\r\n");
            line.clear();
        }
        line.push_str(&encoded);
    }
    out.push_str(&line);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"From: A <a@x.io>\r\n\
Subject: Offer\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=\"--_NmP-boundary-Part_1\"\r\n\
\r\n\
----_NmP-boundary-Part_1\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
See https://track.example/r/aaa\r\n\
----_NmP-boundary-Part_1\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<html><body><p>Hi</p>\
<a href=\"https://track.example/r/one\">One</a>\
<a href=\"https://track.example/r/two\">Two</a>\
<img src=\"https://track.example/email/open.gif\" width=\"1\" height=\"1\" />\
</body></html>\r\n\
----_NmP-boundary-Part_1--\r\n";

    #[test]
    fn extracts_links_in_document_order() {
        let tracking = extract_tracking(SAMPLE);
        assert_eq!(
            tracking.links,
            vec![
                "https://track.example/r/one".to_string(),
                "https://track.example/r/two".to_string()
            ]
        );
        assert_eq!(tracking.pixels.len(), 1);
        assert!(tracking.pixels[0].contains("/email/open.gif"));
    }

    #[test]
    fn placeholders_map_to_original_links_and_pixel_is_kept() {
        let template = ContentTemplate {
            id: "v1".to_string(),
            match_subject: "Offer".to_string(),
            subject: "Fresh subject".to_string(),
            body: "<html><body><p>New words</p><a href=\"{{link1}}\">Go</a> <a href=\"{{link2}}\">More</a></body></html>"
                .to_string(),
        };
        let mut message = Message::parse(SAMPLE).unwrap();
        let mut notes = Vec::new();
        apply_template(&mut message, SAMPLE, &template, &mut notes);
        let raw = message.to_bytes();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("Fresh subject"));
        let applied = extract_tracking(&raw);
        assert_eq!(
            applied.links,
            vec![
                "https://track.example/r/one".to_string(),
                "https://track.example/r/two".to_string()
            ]
        );
        assert!(applied.pixels.iter().any(|src| src.contains("open.gif")));
        assert!(!extract_html(&raw).unwrap_or_default().contains("{{link1}}"));
        assert!(notes.iter().any(|n| n.contains("content rotation")));
    }

    /// Wire shape SwiftMailer builds from a Mautic spool `Swift_Message`
    /// (multipart/alternative, QP HTML, click `/r/` + open `.gif` + header unsub).
    fn mautic_spool_wire() -> Vec<u8> {
        let html = "<p>hi&nbsp;<a href=\"https://email.superfeelsapp.com/r/98bb587bd6bdd8257d65dfe85?ct=YTo0OntzOjY6InNvdXJjZSI7YTowOnt9czo1OiJlbWFpbCI7TjtzOjQ6InN0YXQiO3M6MjI6IjZhOWM1MDdjOTMxZjMyMjU5NTY0NDciO3M6NDoibGVhZCI7czo0OiIzMzgwIjt9\">https://mail.google.com/</a></p><img height=\"1\" width=\"1\" src=\"https://email.superfeelsapp.com/email/6a9c507c931f3225956447.gif\" alt=\"\" />";
        let plain = "hi  https://email.superfeelsapp.com/r/98bb587bd6bdd8257d65dfe85?ct=dummy";
        let boundary = "_=_swift_1788629116_e5d4eeb0e1dfb7f3058378c25e3e1240_=_";
        format!(
            "From: Super Feels <info@superfeelsapp.com>\r\n\
Subject: sohagbdmt@gmail.com\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\
List-Unsubscribe: <https://email.superfeelsapp.com/email/unsubscribe/6a9c507c931f3225956447>\r\n\
List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
{}\r\n\
--{boundary}\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
{}\r\n\
--{boundary}--\r\n",
            encode_quoted_printable(plain),
            encode_quoted_printable(html)
        )
        .into_bytes()
    }

    #[test]
    fn mautic_spool_message_maps_click_pixel_and_unsubscribe() {
        let raw = mautic_spool_wire();
        let tracking = extract_tracking(&raw);
        assert_eq!(
            tracking.links[0],
            "https://email.superfeelsapp.com/r/98bb587bd6bdd8257d65dfe85?ct=YTo0OntzOjY6InNvdXJjZSI7YTowOnt9czo1OiJlbWFpbCI7TjtzOjQ6InN0YXQiO3M6MjI6IjZhOWM1MDdjOTMxZjMyMjU5NTY0NDciO3M6NDoibGVhZCI7czo0OiIzMzgwIjt9"
        );
        assert_eq!(
            tracking.unsubscribe.as_deref(),
            Some("https://email.superfeelsapp.com/email/unsubscribe/6a9c507c931f3225956447")
        );
        assert_eq!(tracking.links[1], tracking.unsubscribe.clone().unwrap());
        assert!(tracking.pixels.iter().any(|src| src.ends_with("6a9c507c931f3225956447.gif")));

        let template = ContentTemplate {
            id: "v1".to_string(),
            match_subject: "sohagbdmt@gmail.com".to_string(),
            subject: "A new daily ritual".to_string(),
            body: "<p>New words</p><p><a href=\"{{link1}}\">Open</a></p><p><a href=\"{{unsubscribe}}\">Leave</a></p>".to_string(),
        };
        let mut message = Message::parse(&raw).unwrap();
        let mut notes = Vec::new();
        apply_template(&mut message, &raw, &template, &mut notes);
        let out = message.to_bytes();
        let applied = extract_tracking(&out);
        assert_eq!(applied.links[0], tracking.links[0]);
        assert!(applied.pixels.iter().any(|src| src.contains("6a9c507c931f3225956447.gif")));
        assert!(message.value("list-unsubscribe").unwrap().contains("/email/unsubscribe/"));
    }

    #[test]
    fn subject_match_is_case_and_whitespace_insensitive() {
        let template = ContentTemplate {
            id: "e1".to_string(),
            match_subject: "Email 1".to_string(),
            subject: "Alt".to_string(),
            body: "<p>x</p>".to_string(),
        };
        assert!(template_matches(&template, "Email 1"));
        assert!(template_matches(&template, "  email   1  "));
        assert!(template_matches(&template, "EMAIL 1"));
        assert!(!template_matches(&template, "Email 2"));
        let empty = ContentTemplate {
            match_subject: String::new(),
            subject: "Alt".to_string(),
            body: "<p>x</p>".to_string(),
            ..Default::default()
        };
        assert!(!template_matches(&empty, "Email 1"));
    }
}
