//! Minimal HTTP/1.1 server for the admin API and dashboard.
//!
//! Hand-rolled rather than pulling in a web framework: the surface is a
//! handful of JSON routes plus one server-sent-events stream, and keeping it
//! dependency-free means the daemon builds to a single small binary with no
//! HTTP stack to keep patched.
//!
//! Supported: keep-alive, `Content-Length` request bodies, query strings,
//! percent-decoding, and `text/event-stream` responses. Not supported (and not
//! needed): chunked request bodies, HTTP/2, compression, TLS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};

use crate::smtp::lines::{LineReader, ReadLine};
use crate::state::AppState;

/// Longest accepted request line or header line.
const MAX_LINE: usize = 8 * 1024;
/// Largest accepted request body (config uploads are the biggest realistic
/// payload).
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_HEADERS: usize = 100;
/// Idle time allowed between keep-alive requests.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(60);
/// SSE comment interval, which also detects a vanished client.
const SSE_HEARTBEAT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// Percent-decoded path, without the query string.
    pub path: String,
    /// Path split on `/`, with empty segments removed.
    pub segments: Vec<String>,
    pub query: HashMap<String, String>,
    /// Header names lowercased.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub peer: SocketAddr,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|value| value.as_str())
    }

    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(|value| value.as_str())
    }

    /// Parses a query parameter, ignoring values that do not parse.
    pub fn query_as<T: std::str::FromStr>(&self, name: &str) -> Option<T> {
        self.query_param(name).and_then(|value| value.parse().ok())
    }

    /// First matching cookie, if present.
    pub fn cookie(&self, name: &str) -> Option<&str> {
        let header = self.header("cookie")?;
        for part in header.split(';') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                if key.trim() == name {
                    return Some(value.trim());
                }
            }
        }
        None
    }

    pub fn body_json<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        if self.body.is_empty() {
            return Err("a JSON request body is required".to_string());
        }
        serde_json::from_slice(&self.body).map_err(|error| format!("invalid JSON body: {error}"))
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: content_type.to_string(),
            headers: Vec::new(),
            body,
        }
    }

    pub fn json_value(status: u16, value: &serde_json::Value) -> Self {
        Self::new(
            status,
            "application/json; charset=utf-8",
            serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
        )
    }

    pub fn json<T: serde::Serialize>(status: u16, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => Self::new(status, "application/json; charset=utf-8", body),
            Err(error) => Self::error(500, &format!("could not serialise the response: {error}")),
        }
    }

    /// Uniform error envelope: `{"error": "..."}`.
    pub fn error(status: u16, message: &str) -> Self {
        Self::json_value(
            status,
            &serde_json::json!({ "error": message, "status": status }),
        )
    }

    pub fn ok_message(message: &str) -> Self {
        Self::json_value(200, &serde_json::json!({ "ok": true, "message": message }))
    }

    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self::new(
            status,
            "text/plain; charset=utf-8",
            body.into().into_bytes(),
        )
    }

    pub fn html(body: &str) -> Self {
        Self::new(200, "text/html; charset=utf-8", body.as_bytes().to_vec())
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    fn serialize(&self, keep_alive: bool) -> Vec<u8> {
        let mut head = String::with_capacity(256);
        head.push_str(&format!(
            "HTTP/1.1 {} {}\r\n",
            self.status,
            status_text(self.status)
        ));
        head.push_str(&format!("Content-Type: {}\r\n", self.content_type));
        head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        head.push_str(if keep_alive {
            "Connection: keep-alive\r\n"
        } else {
            "Connection: close\r\n"
        });
        head.push_str("X-Content-Type-Options: nosniff\r\n");
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");

        let mut out = head.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

/// What a route decided to do.
pub enum Reply {
    /// A normal buffered response.
    Complete(Response),
    /// Hand the socket to the server-sent-events streamer.
    EventStream,
}

impl From<Response> for Reply {
    fn from(response: Response) -> Self {
        Reply::Complete(response)
    }
}

/// Boxed handler future. Routes are async because some of them (relay probes,
/// test sends) talk to upstream relays.
pub type HandlerFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Reply> + Send>>;

/// Route handler signature.
pub type Handler = fn(Arc<AppState>, Request) -> HandlerFuture;

/// Binds the admin listener and serves until shutdown.
pub async fn serve(state: Arc<AppState>, handler: Handler) -> std::io::Result<()> {
    let config = state.config();
    let address: SocketAddr = config.admin.bind_address.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "admin.bind_address `{}` is not a valid socket address",
                config.admin.bind_address
            ),
        )
    })?;

    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| std::io::Error::new(error.kind(), format!("could not bind {address}: {error}")))?;
    let mut shutdown = state.subscribe_shutdown();

    tracing::info!(
        %address,
        dashboard = config.admin.dashboard_enabled,
        token_required = !config.admin.api_token.is_empty(),
        "admin API ready"
    );
    if config.admin.api_token.is_empty() {
        tracing::warn!(
            "admin.api_token is empty: only loopback clients will be able to reach the API"
        );
    }

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("admin API stopping");
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(error) = serve_connection(state, handler, stream, peer).await {
                                tracing::debug!(%peer, %error, "admin connection ended");
                            }
                        });
                    }
                    Err(error) => {
                        tracing::warn!(%error, "admin accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn serve_connection(
    state: Arc<AppState>,
    handler: Handler,
    stream: TcpStream,
    peer: SocketAddr,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = LineReader::new(read_half);

    loop {
        let request = match tokio::time::timeout(
            KEEPALIVE_TIMEOUT,
            read_request(&mut reader, peer),
        )
        .await
        {
            Ok(Ok(Ok(Some(request)))) => request,
            // Clean close between keep-alive requests, an idle timeout, or a
            // socket error: all three just end the connection.
            Ok(Ok(Ok(None))) | Ok(Err(_)) | Err(_) => return Ok(()),
            Ok(Ok(Err(error))) => {
                let response = Response::error(400, &error);
                let _ = write_half.write_all(&response.serialize(false)).await;
                let _ = write_half.flush().await;
                return Ok(());
            }
        };

        let keep_alive = wants_keep_alive(&request);

        match handler(Arc::clone(&state), request).await {
            Reply::Complete(response) => {
                write_half.write_all(&response.serialize(keep_alive)).await?;
                write_half.flush().await?;
                if !keep_alive {
                    return Ok(());
                }
            }
            Reply::EventStream => {
                // The stream owns the connection until the client goes away.
                stream_events(&state, &mut write_half).await;
                return Ok(());
            }
        }
    }
}

/// Reads one request. `Ok(None)` means the peer closed cleanly.
async fn read_request<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut LineReader<R>,
    peer: SocketAddr,
) -> std::io::Result<Result<Option<Request>, String>> {
    let request_line = match reader.read_line(MAX_LINE).await? {
        ReadLine::Line(line) => line,
        ReadLine::Eof => return Ok(Ok(None)),
        ReadLine::TooLong => return Ok(Err("request line too long".to_string())),
    };
    if request_line.is_empty() {
        return Ok(Ok(None));
    }

    let line = String::from_utf8_lossy(&request_line).to_string();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    if method.is_empty() {
        return Ok(Err("malformed request line".to_string()));
    }

    let mut headers = HashMap::new();
    loop {
        match reader.read_line(MAX_LINE).await? {
            ReadLine::Line(line) if line.is_empty() => break,
            ReadLine::Line(line) => {
                if headers.len() >= MAX_HEADERS {
                    return Ok(Err("too many headers".to_string()));
                }
                let text = String::from_utf8_lossy(&line);
                if let Some((name, value)) = text.split_once(':') {
                    headers.insert(
                        name.trim().to_ascii_lowercase(),
                        value.trim().to_string(),
                    );
                }
            }
            ReadLine::Eof => return Ok(Err("connection closed mid-request".to_string())),
            ReadLine::TooLong => return Ok(Err("header line too long".to_string())),
        }
    }

    let mut body = Vec::new();
    if let Some(length) = headers.get("content-length") {
        let length: usize = match length.parse() {
            Ok(value) => value,
            Err(_) => return Ok(Err("invalid Content-Length".to_string())),
        };
        if length > MAX_BODY {
            return Ok(Err(format!(
                "request body of {length} bytes exceeds the {MAX_BODY} byte limit"
            )));
        }
        if length > 0 {
            match reader.read_exact_bytes(length).await? {
                Some(bytes) => body = bytes,
                None => return Ok(Err("request body was truncated".to_string())),
            }
        }
    } else if headers.contains_key("transfer-encoding") {
        return Ok(Err(
            "chunked request bodies are not supported; send Content-Length".to_string(),
        ));
    }

    let (raw_path, raw_query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target.as_str(), None),
    };
    let path = percent_decode(raw_path);
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.to_string())
        .collect();

    Ok(Ok(Some(Request {
        method,
        path,
        segments,
        query: raw_query.map(parse_query).unwrap_or_default(),
        headers,
        body,
        peer,
    })))
}

fn wants_keep_alive(request: &Request) -> bool {
    match request.header("connection") {
        Some(value) => !value.eq_ignore_ascii_case("close"),
        None => true,
    }
}

/// Streams events until the client disconnects or the daemon shuts down.
async fn stream_events(state: &Arc<AppState>, writer: &mut OwnedWriteHalf) {
    let head = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/event-stream; charset=utf-8\r\n",
        "Cache-Control: no-cache, no-store\r\n",
        "Connection: keep-alive\r\n",
        "X-Accel-Buffering: no\r\n",
        "\r\n",
    );
    if writer.write_all(head.as_bytes()).await.is_err() {
        return;
    }

    let mut receiver = state.events.subscribe();
    let mut shutdown = state.subscribe_shutdown();

    // Immediately confirm the stream is live so the dashboard can show it.
    if writer
        .write_all(b": connected\n\n")
        .await
        .is_err()
    {
        return;
    }

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            event = receiver.recv() => {
                match event {
                    Ok(event) => {
                        let payload = match serde_json::to_string(&event) {
                            Ok(payload) => payload,
                            Err(_) => continue,
                        };
                        let frame = format!("event: {}\ndata: {}\n\n", event.kind.as_str(), payload);
                        if writer.write_all(frame.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    // A slow client missed events; tell it so it can refetch.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        let frame = format!("event: lagged\ndata: {{\"skipped\":{skipped}}}\n\n");
                        if writer.write_all(frame.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = tokio::time::sleep(SSE_HEARTBEAT) => {
                if writer.write_all(b": ping\n\n").await.is_err() {
                    break;
                }
            }
        }
    }

    let _ = writer.flush().await;
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

pub fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (percent_decode(key), percent_decode(value)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

/// Decodes `%XX` escapes and `+` as space.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match u8::from_str_radix(&input[index + 1..index + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "127.0.0.1:5555".parse().unwrap()
    }

    async fn parse(wire: &[u8]) -> Result<Option<Request>, String> {
        let mut reader = LineReader::new(std::io::Cursor::new(wire.to_vec()));
        read_request(&mut reader, peer()).await.unwrap()
    }

    #[tokio::test]
    async fn parses_a_get_with_query_parameters() {
        let request = parse(b"GET /api/messages?limit=50&status=delivered HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/messages");
        assert_eq!(request.segments, vec!["api", "messages"]);
        assert_eq!(request.query_param("status"), Some("delivered"));
        assert_eq!(request.query_as::<usize>("limit"), Some(50));
        assert_eq!(request.header("host"), Some("x"));
        assert!(request.body.is_empty());
    }

    #[tokio::test]
    async fn header_names_are_case_insensitive() {
        let request = parse(b"GET / HTTP/1.1\r\nAUTHORIZATION: Bearer abc\r\n\r\n")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.header("authorization"), Some("Bearer abc"));
    }

    #[tokio::test]
    async fn reads_a_json_body_exactly() {
        let body = r#"{"ids":["relay_node_1"],"active":true}"#;
        let wire = format!(
            "POST /api/relays/bulk HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let request = parse(wire.as_bytes()).await.unwrap().unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(String::from_utf8_lossy(&request.body), body);

        #[derive(serde::Deserialize)]
        struct Payload {
            ids: Vec<String>,
            active: bool,
        }
        let parsed: Payload = request.body_json().unwrap();
        assert_eq!(parsed.ids, vec!["relay_node_1".to_string()]);
        assert!(parsed.active);
    }

    #[tokio::test]
    async fn reads_a_multi_line_json_body() {
        // Pretty-printed JSON exercises the body reassembly path.
        let body = "{\n  \"strategy\": \"weighted\"\n}";
        let wire = format!(
            "PUT /api/routing HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let request = parse(wire.as_bytes()).await.unwrap().unwrap();
        assert_eq!(String::from_utf8_lossy(&request.body), body);
        let value: serde_json::Value = request.body_json().unwrap();
        assert_eq!(value["strategy"], "weighted");
    }

    #[tokio::test]
    async fn percent_encoded_paths_are_decoded() {
        let request = parse(b"GET /api/relays/relay%20one HTTP/1.1\r\n\r\n")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.segments, vec!["api", "relays", "relay one"]);
    }

    #[tokio::test]
    async fn a_closed_connection_is_not_an_error() {
        assert!(parse(b"").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_bodies_are_refused() {
        let wire = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        let error = parse(wire.as_bytes()).await.unwrap_err();
        assert!(error.contains("exceeds"), "{error}");
    }

    #[tokio::test]
    async fn chunked_bodies_are_refused_clearly() {
        let error = parse(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap_err();
        assert!(error.contains("Content-Length"), "{error}");
    }

    #[tokio::test]
    async fn truncated_bodies_are_refused() {
        let error = parse(b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort")
            .await
            .unwrap_err();
        assert!(error.contains("truncated"), "{error}");
    }

    #[test]
    fn query_strings_decode_plus_and_escapes() {
        let query = parse_query("q=hello+world&to=a%40b.io&flag");
        assert_eq!(query["q"], "hello world");
        assert_eq!(query["to"], "a@b.io");
        assert_eq!(query["flag"], "");
    }

    #[test]
    fn responses_include_length_and_connection() {
        let response = Response::ok_message("done");
        let wire = String::from_utf8(response.serialize(true)).unwrap();

        assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire.contains("Content-Type: application/json; charset=utf-8\r\n"));
        assert!(wire.contains("Connection: keep-alive\r\n"));
        assert!(wire.contains(&format!("Content-Length: {}\r\n", response.body.len())));
        assert!(wire.ends_with("{\"message\":\"done\",\"ok\":true}"));
    }

    #[test]
    fn error_responses_use_a_uniform_envelope() {
        let response = Response::error(404, "no such relay");
        assert_eq!(response.status, 404);
        let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["error"], "no such relay");
        assert_eq!(value["status"], 404);
    }
}
