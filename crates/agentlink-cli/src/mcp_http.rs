//! Streamable HTTP transport for the MCP server.
//!
//! `POST /mcp` carries one JSON-RPC message and returns JSON.
//! `GET /mcp` is a server-sent-event stream of keepalive comments.
//! `DELETE /mcp` drops the session named by `Mcp-Session-Id`.
//!
//! Every request needs `Authorization: Bearer <token>`. When `Origin` is
//! present it must be localhost. This is not a public endpoint.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

use crate::mcp::{self, Mcp, McpConfig};

const MAX_HTTP_HEADERS_BYTES: usize = 64 * 1024;
const MAX_HTTP_BODY_BYTES: usize = mcp::MAX_MCP_MESSAGE_BYTES;
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_MCP_HTTP_SESSIONS: usize = 64;
const MCP_SESSION_IDLE_TTL: Duration = Duration::from_secs(3600);
const MAX_CONCURRENT_MCP_CONNS: usize = 64;
const MAX_CONCURRENT_MCP_SSE: usize = 16;
const MIN_MCP_TOKEN_LEN: usize = 16;
const MIN_MCP_TOKEN_DISTINCT_CHARS: usize = 6;
const AUTH_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const AUTH_RATE_LIMIT_MAX_FAILURES: usize = 10;

struct SessionSlot {
    mcp: Arc<Mutex<Mcp>>,
    last_used: Instant,
}

#[derive(Default)]
struct AuthRateLimiter {
    failures: HashMap<IpAddr, VecDeque<Instant>>,
}

impl AuthRateLimiter {
    fn is_blocked(&mut self, ip: IpAddr, now: Instant) -> bool {
        let Some(queue) = self.failures.get_mut(&ip) else {
            return false;
        };
        while let Some(&ts) = queue.front() {
            if now.duration_since(ts) >= AUTH_RATE_LIMIT_WINDOW {
                queue.pop_front();
            } else {
                break;
            }
        }
        if queue.is_empty() {
            self.failures.remove(&ip);
            return false;
        }
        queue.len() >= AUTH_RATE_LIMIT_MAX_FAILURES
    }

    fn record_failure(&mut self, ip: IpAddr, now: Instant) -> bool {
        let queue = self.failures.entry(ip).or_default();
        while let Some(&ts) = queue.front() {
            if now.duration_since(ts) >= AUTH_RATE_LIMIT_WINDOW {
                queue.pop_front();
            } else {
                break;
            }
        }
        queue.push_back(now);
        let exceeded = queue.len() > AUTH_RATE_LIMIT_MAX_FAILURES;
        // Cap table size against IP-spoof memory growth.
        if self.failures.len() > 1024 {
            self.failures.retain(|_, q| {
                q.back()
                    .is_some_and(|&ts| now.duration_since(ts) < AUTH_RATE_LIMIT_WINDOW)
            });
        }
        exceeded
    }
}

pub fn validate_mcp_token(token: &str) -> Result<()> {
    if token.len() < MIN_MCP_TOKEN_LEN {
        anyhow::bail!(
            "MCP HTTP token must be at least {MIN_MCP_TOKEN_LEN} characters long (got {})",
            token.len()
        );
    }
    if token.trim() != token || token.chars().any(|c| c.is_control() || c.is_whitespace()) {
        anyhow::bail!("MCP HTTP token must not contain whitespace or control characters");
    }
    let distinct: HashSet<char> = token.chars().collect();
    if distinct.len() < MIN_MCP_TOKEN_DISTINCT_CHARS {
        anyhow::bail!(
            "MCP HTTP token has too little entropy (at least {MIN_MCP_TOKEN_DISTINCT_CHARS} distinct characters required)"
        );
    }
    Ok(())
}

pub fn validate_bind_addr(bind: SocketAddr, allow_remote_http: bool) -> Result<()> {
    if !bind.ip().is_loopback() && !allow_remote_http {
        anyhow::bail!(
            "refusing to bind plaintext MCP HTTP server to non-loopback address {bind}; pass --allow-remote-http to override (not recommended without a TLS reverse proxy)"
        );
    }
    Ok(())
}

pub async fn serve(
    config: McpConfig,
    bind: SocketAddr,
    token: String,
    allow_remote_http: bool,
) -> Result<()> {
    validate_bind_addr(bind, allow_remote_http)?;
    validate_mcp_token(&token)?;
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    eprintln!("mcp http listening on http://{addr}/mcp");
    let _ = std::io::stderr().flush();
    let sessions: Arc<Mutex<HashMap<String, SessionSlot>>> = Arc::new(Mutex::new(HashMap::new()));
    let rate_limiter: Arc<Mutex<AuthRateLimiter>> =
        Arc::new(Mutex::new(AuthRateLimiter::default()));
    let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_MCP_CONNS));
    let sse_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_MCP_SSE));
    let token = Arc::new(token);
    loop {
        let (mut socket, peer) = listener.accept().await?;
        let Ok(conn_permit) = conn_sem.clone().try_acquire_owned() else {
            tokio::spawn(async move {
                let _ = write_response(
                    &mut socket,
                    503,
                    "application/json",
                    None,
                    br#"{"error":"too many connections"}"#,
                )
                .await;
            });
            continue;
        };
        let sessions = sessions.clone();
        let rate_limiter = rate_limiter.clone();
        let sse_sem = sse_sem.clone();
        let config = config.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _permit = conn_permit;
            if let Err(err) = handle_conn(
                socket,
                peer.ip(),
                sessions,
                rate_limiter,
                sse_sem,
                config,
                token,
                allow_remote_http,
            )
            .await
            {
                tracing::debug!(error = %err, "mcp http connection ended");
            }
        });
    }
}

enum ReadRequestError {
    PayloadTooLarge,
    BadRequest,
    Io(anyhow::Error),
}

#[allow(clippy::too_many_arguments)]
async fn handle_conn(
    mut socket: TcpStream,
    peer_ip: IpAddr,
    sessions: Arc<Mutex<HashMap<String, SessionSlot>>>,
    rate_limiter: Arc<Mutex<AuthRateLimiter>>,
    sse_sem: Arc<Semaphore>,
    config: McpConfig,
    token: Arc<String>,
    allow_remote_http: bool,
) -> Result<()> {
    let req = match tokio::time::timeout(REQUEST_READ_TIMEOUT, read_request(&mut socket)).await {
        Ok(Ok(req)) => req,
        Ok(Err(ReadRequestError::PayloadTooLarge)) => {
            return write_response(
                &mut socket,
                413,
                "application/json",
                None,
                br#"{"error":"payload too large"}"#,
            )
            .await;
        }
        Ok(Err(ReadRequestError::BadRequest)) => {
            return write_response(
                &mut socket,
                400,
                "application/json",
                None,
                br#"{"error":"bad request"}"#,
            )
            .await;
        }
        Ok(Err(ReadRequestError::Io(err))) => return Err(err),
        Err(_) => return Err(anyhow!("mcp http request read timed out")),
    };
    if let Some(host) = header(&req.headers, "host") {
        if !host_ok(host, allow_remote_http) {
            return write_response(
                &mut socket,
                403,
                "application/json",
                None,
                br#"{"error":"host"}"#,
            )
            .await;
        }
    } else {
        return write_response(
            &mut socket,
            400,
            "application/json",
            None,
            br#"{"error":"missing host"}"#,
        )
        .await;
    }
    if let Some(origin) = header(&req.headers, "origin") {
        if !origin_ok(origin) {
            return write_response(
                &mut socket,
                403,
                "application/json",
                None,
                br#"{"error":"origin"}"#,
            )
            .await;
        }
    }
    if !authorized(&req, &token) {
        let now = Instant::now();
        let blocked = {
            let mut limiter = rate_limiter.lock().await;
            let already_blocked = limiter.is_blocked(peer_ip, now);
            let exceeded = limiter.record_failure(peer_ip, now);
            already_blocked || exceeded
        };
        if blocked {
            return write_response_with_extra(
                &mut socket,
                429,
                "application/json",
                None,
                &[("Retry-After", "60")],
                br#"{"error":"too many authentication failures"}"#,
            )
            .await;
        }
        return write_response(
            &mut socket,
            401,
            "application/json",
            None,
            br#"{"error":"unauthorized"}"#,
        )
        .await;
    }
    let path = req.path.split('?').next().unwrap_or(req.path.as_str());
    if path != "/mcp" {
        return write_response(
            &mut socket,
            404,
            "application/json",
            None,
            br#"{"error":"not found"}"#,
        )
        .await;
    }
    match req.method.as_str() {
        "POST" => {
            let body_slice = req
                .body
                .strip_prefix(&[0xEF, 0xBB, 0xBF])
                .unwrap_or(&req.body);
            let message: Value = serde_json::from_slice(body_slice).unwrap_or(Value::Null);
            let session_id = match resolve_session_id(&req.headers) {
                Some(id) => id,
                None => {
                    return write_response(
                        &mut socket,
                        400,
                        "application/json",
                        None,
                        br#"{"error":"invalid session id"}"#,
                    )
                    .await;
                }
            };
            let state = get_or_insert_session(&sessions, &session_id, &config).await;
            let response = {
                let mut state = state.lock().await;
                mcp::handle(&mut state, message).await
            };
            match response {
                Some(value) => {
                    let body = serde_json::to_vec(&value)?;
                    write_response(
                        &mut socket,
                        200,
                        "application/json",
                        Some(&session_id),
                        &body,
                    )
                    .await
                }
                None => {
                    write_response(
                        &mut socket,
                        202,
                        "application/json",
                        Some(&session_id),
                        b"",
                    )
                    .await
                }
            }
        }
        "GET" => {
            let Ok(_sse_permit) = sse_sem.try_acquire_owned() else {
                return write_response(
                    &mut socket,
                    503,
                    "application/json",
                    None,
                    br#"{"error":"too many sse streams"}"#,
                )
                .await;
            };
            let session_id = match resolve_session_id(&req.headers) {
                Some(id) => id,
                None => {
                    return write_response(
                        &mut socket,
                        400,
                        "application/json",
                        None,
                        br#"{"error":"invalid session id"}"#,
                    )
                    .await;
                }
            };
            let _ = get_or_insert_session(&sessions, &session_id, &config).await;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nMcp-Session-Id: {session_id}\r\n\r\n"
            );
            socket.write_all(header.as_bytes()).await?;
            loop {
                if socket.write_all(b": keepalive\n\n").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            Ok(())
        }
        "DELETE" => {
            if let Some(id) = header(&req.headers, "mcp-session-id") {
                sessions.lock().await.remove(id);
            }
            write_response(&mut socket, 204, "application/json", None, b"").await
        }
        _ => {
            write_response(
                &mut socket,
                405,
                "application/json",
                None,
                br#"{"error":"method"}"#,
            )
            .await
        }
    }
}

fn resolve_session_id(headers: &[(String, String)]) -> Option<String> {
    let Some(raw) = header(headers, "mcp-session-id") else {
        return Some(uuid_like());
    };
    if raw.is_empty() || raw.len() > 128 {
        return None;
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(raw.to_string())
}

async fn get_or_insert_session(
    sessions: &Arc<Mutex<HashMap<String, SessionSlot>>>,
    session_id: &str,
    config: &McpConfig,
) -> Arc<Mutex<Mcp>> {
    let mut map = sessions.lock().await;
    let now = Instant::now();
    if let Some(slot) = map.get_mut(session_id) {
        slot.last_used = now;
        return slot.mcp.clone();
    }
    if map.len() >= MAX_MCP_HTTP_SESSIONS {
        map.retain(|_, slot| now.duration_since(slot.last_used) < MCP_SESSION_IDLE_TTL);
        if map.len() >= MAX_MCP_HTTP_SESSIONS {
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, slot)| slot.last_used)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }
    }
    let mcp = Arc::new(Mutex::new(mcp::new_state_from_config(config.clone())));
    map.insert(
        session_id.to_string(),
        SessionSlot {
            mcp: mcp.clone(),
            last_used: now,
        },
    );
    mcp
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn read_chunked_body(
    socket: &mut TcpStream,
    initial: &[u8],
) -> std::result::Result<Vec<u8>, ReadRequestError> {
    let mut pending = initial.to_vec();
    let mut out = Vec::new();
    let mut tmp = [0u8; 4096];

    loop {
        // Read chunk size line terminated by CRLF.
        let line_end = loop {
            if let Some(pos) = pending.windows(2).position(|w| w == b"\r\n") {
                break pos;
            }
            if pending.len() > 256 {
                return Err(ReadRequestError::BadRequest);
            }
            let n = socket
                .read(&mut tmp)
                .await
                .map_err(|e| ReadRequestError::Io(e.into()))?;
            if n == 0 {
                return Err(ReadRequestError::Io(anyhow!("truncated chunked body")));
            }
            pending.extend_from_slice(&tmp[..n]);
        };
        let size_line = std::str::from_utf8(&pending[..line_end])
            .map_err(|_| ReadRequestError::BadRequest)?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_hex, 16)
            .map_err(|_| ReadRequestError::BadRequest)?;
        pending.drain(..line_end + 2);

        if chunk_len == 0 {
            // Consume trailing headers until CRLF (or immediate CRLF for no trailers).
            loop {
                if pending.starts_with(b"\r\n") {
                    break;
                }
                if pending.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if pending.len() > MAX_HTTP_HEADERS_BYTES {
                    return Err(ReadRequestError::BadRequest);
                }
                let n = socket
                    .read(&mut tmp)
                    .await
                    .map_err(|e| ReadRequestError::Io(e.into()))?;
                if n == 0 {
                    // Some HTTP clients omit the final empty line after 0\r\n.
                    break;
                }
                pending.extend_from_slice(&tmp[..n]);
            }
            return Ok(out);
        }

        if out.len().saturating_add(chunk_len) > MAX_HTTP_BODY_BYTES {
            return Err(ReadRequestError::PayloadTooLarge);
        }
        let need = chunk_len + 2; // chunk bytes + trailing CRLF
        while pending.len() < need {
            let n = socket
                .read(&mut tmp)
                .await
                .map_err(|e| ReadRequestError::Io(e.into()))?;
            if n == 0 {
                return Err(ReadRequestError::Io(anyhow!("truncated chunked body")));
            }
            pending.extend_from_slice(&tmp[..n]);
        }
        if &pending[chunk_len..need] != b"\r\n" {
            return Err(ReadRequestError::BadRequest);
        }
        out.extend_from_slice(&pending[..chunk_len]);
        pending.drain(..need);
    }
}

async fn read_request(socket: &mut TcpStream) -> std::result::Result<Request, ReadRequestError> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = socket
            .read(&mut tmp)
            .await
            .map_err(|e| ReadRequestError::Io(e.into()))?;
        if n == 0 {
            return Err(ReadRequestError::Io(anyhow!("client closed")));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > MAX_HTTP_HEADERS_BYTES {
            return Err(ReadRequestError::BadRequest);
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let te_values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k == "transfer-encoding")
        .map(|(_, v)| v.as_str())
        .collect();
    let is_chunked = if te_values.is_empty() {
        false
    } else if te_values.len() == 1 && te_values[0].eq_ignore_ascii_case("chunked") {
        true
    } else {
        return Err(ReadRequestError::BadRequest);
    };

    let mut content_len: Option<usize> = None;
    for (k, v) in &headers {
        if k == "content-length" {
            let parsed = v
                .parse::<usize>()
                .map_err(|_| ReadRequestError::BadRequest)?;
            if parsed > MAX_HTTP_BODY_BYTES {
                return Err(ReadRequestError::PayloadTooLarge);
            }
            if let Some(prev) = content_len {
                if prev != parsed {
                    return Err(ReadRequestError::BadRequest);
                }
            }
            content_len = Some(parsed);
        }
    }
    if is_chunked && content_len.is_some() {
        // RFC 9112: reject ambiguous TE + CL to prevent request smuggling.
        return Err(ReadRequestError::BadRequest);
    }

    let initial = &buf[header_end + 4..];
    let body = if is_chunked {
        read_chunked_body(socket, initial).await?
    } else {
        let length = content_len.unwrap_or(0);
        let mut body = Vec::with_capacity(length.min(64 * 1024).max(initial.len().min(length)));
        body.extend_from_slice(&initial[..initial.len().min(length)]);
        while body.len() < length {
            let want = (length - body.len()).min(tmp.len());
            let n = socket
                .read(&mut tmp[..want])
                .await
                .map_err(|e| ReadRequestError::Io(e.into()))?;
            if n == 0 {
                return Err(ReadRequestError::Io(anyhow!(
                    "truncated http request body"
                )));
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body
    };
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let max = a.len().max(b.len());
    for i in 0..max {
        let xa = a.get(i).copied().unwrap_or(0);
        let xb = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(xa ^ xb);
    }
    diff == 0
}

fn authorized(req: &Request, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let Some(value) = header(&req.headers, "authorization") else {
        return false;
    };
    let raw = value.as_bytes();
    if raw.len() < 7 || !raw[..7].eq_ignore_ascii_case(b"bearer ") {
        return false;
    }
    // `raw[..7]` is pure ASCII ("bearer "), so byte index 7 is guaranteed to
    // lie on a valid UTF-8 character boundary.
    let got = value[7..].trim();
    if got.is_empty() {
        return false;
    }
    constant_time_eq(got.as_bytes(), token.as_bytes())
}

fn is_loopback_host_str(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<Ipv4Addr>() == Ok(Ipv4Addr::LOCALHOST)
        || host.parse::<Ipv6Addr>() == Ok(Ipv6Addr::LOCALHOST)
}

fn host_ok(raw_host: &str, allow_remote: bool) -> bool {
    let trimmed = raw_host.trim();
    if trimmed.is_empty() {
        return false;
    }
    let candidate = format!("http://{trimmed}");
    let Ok(parsed) = url::Url::parse(&candidate) else {
        return false;
    };
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return false;
    }
    if allow_remote {
        return parsed.host().is_some();
    }
    match parsed.host() {
        Some(url::Host::Domain(d)) => is_loopback_host_str(d),
        Some(url::Host::Ipv4(v4)) => v4 == Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(v6)) => v6 == Ipv6Addr::LOCALHOST,
        None => false,
    }
}

fn origin_ok(origin: &str) -> bool {
    let Ok(parsed) = url::Url::parse(origin.trim()) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Domain(d)) => is_loopback_host_str(d),
        Some(url::Host::Ipv4(v4)) => v4 == Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(v6)) => v6 == Ipv6Addr::LOCALHOST,
        None => false,
    }
}

async fn write_response(
    socket: &mut TcpStream,
    status: u16,
    content_type: &str,
    session: Option<&str>,
    body: &[u8],
) -> Result<()> {
    write_response_with_extra(socket, status, content_type, session, &[], body).await
}

async fn write_response_with_extra(
    socket: &mut TcpStream,
    status: u16,
    content_type: &str,
    session: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(session) = session {
        head.push_str(&format!("Mcp-Session-Id: {session}\r\n"));
    }
    for (k, v) in extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(body).await?;
    Ok(())
}

fn uuid_like() -> String {
    agentlink_core::util::random_hex(16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentlink_core::ClientSettings;

    const TEST_TOKEN: &str = "mcp-secret-test-token-012345";

    async fn connect_when_up(addr: SocketAddr) -> TcpStream {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match TcpStream::connect(addr).await {
                Ok(socket) => return socket,
                Err(err)
                    if err.kind() == std::io::ErrorKind::ConnectionRefused
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(err) => panic!("connect {addr}: {err}"),
            }
        }
    }

    async fn exchange(addr: SocketAddr, raw: &str) -> String {
        let mut socket = connect_when_up(addr).await;
        socket.write_all(raw.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        let n = socket.read(&mut tmp).await.unwrap();
        buf.extend_from_slice(&tmp[..n]);
        String::from_utf8_lossy(&buf).to_string()
    }

    #[test]
    fn bind_addr_requires_loopback_unless_explicitly_allowed() {
        let any_v4: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert!(validate_bind_addr(any_v4, false).is_err());
        assert!(validate_bind_addr(any_v4, true).is_ok());
        let lo_v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(validate_bind_addr(lo_v4, false).is_ok());
        let lo_v6: SocketAddr = "[::1]:8080".parse().unwrap();
        assert!(validate_bind_addr(lo_v6, false).is_ok());
    }

    #[test]
    fn token_validation_enforces_length_and_entropy() {
        assert!(validate_mcp_token("short").is_err());
        assert!(validate_mcp_token("aaaaaaaaaaaaaaaaaaaa").is_err());
        assert!(validate_mcp_token("abcde12345 67890xyz").is_err());
        assert!(validate_mcp_token(TEST_TOKEN).is_ok());
    }

    #[tokio::test]
    async fn http_requires_a_token_and_answers_initialize() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let settings = ClientSettings {
            relay: "wss://127.0.0.1:1".into(),
            token: "unused".into(),
            fingerprint: "sha256:00".into(),
            trust: None,
        };
        let identity =
            std::env::temp_dir().join(format!("agentlink-mcp-http-{}.json", uuid_like()));
        let cfg = McpConfig::from_settings(settings, identity);
        tokio::spawn(serve(cfg, addr, TEST_TOKEN.into(), false));

        let denied = exchange(
            addr,
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");

        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#;
        let raw = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TEST_TOKEN}\r\nOrigin: http://127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let ok = exchange(addr, &raw).await;
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains("Mcp-Session-Id:"), "{ok}");
        assert!(ok.contains("agentlink"), "{ok}");

        // JSON-RPC notifications return 202 Accepted with empty body.
        let note_body = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let note_req = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TEST_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{note_body}",
            note_body.len()
        );
        let note_resp = exchange(addr, &note_req).await;
        assert!(note_resp.starts_with("HTTP/1.1 202"), "{note_resp}");

        // Transfer-Encoding: chunked is decoded properly.
        let ping_part1 = r#"{"jsonrpc":"2.0","id":9,"#;
        let ping_part2 = r#""method":"ping"}"#;
        let chunked = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TEST_TOKEN}\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{ping_part1}\r\n{:x}\r\n{ping_part2}\r\n0\r\n\r\n",
            ping_part1.len(),
            ping_part2.len()
        );
        let chunked_resp = exchange(addr, &chunked).await;
        assert!(chunked_resp.starts_with("HTTP/1.1 200"), "{chunked_resp}");
        assert!(chunked_resp.contains("\"id\":9"), "{chunked_resp}");

        let foreign = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TEST_TOKEN}\r\nOrigin: https://evil.example\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let blocked = exchange(addr, &foreign).await;
        assert!(blocked.starts_with("HTTP/1.1 403"), "{blocked}");

        // Subdomain & query substring Origin bypasses MUST be rejected with 403.
        for spoof_origin in [
            "https://localhost.evil.example",
            "https://evil.example/?next=http://127.0.0.1",
            "http://127.0.0.1.evil.example",
        ] {
            let spoof = format!(
                "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TEST_TOKEN}\r\nOrigin: {spoof_origin}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let resp = exchange(addr, &spoof).await;
            assert!(
                resp.starts_with("HTTP/1.1 403"),
                "Origin {spoof_origin} bypassed check: {resp}"
            );
        }

        // DNS-rebinding Host header without Origin MUST be rejected with 403.
        let rebind = format!(
            "POST /mcp HTTP/1.1\r\nHost: rebind.attacker.example:8080\r\nAuthorization: Bearer {TEST_TOKEN}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let rebind_resp = exchange(addr, &rebind).await;
        assert!(
            rebind_resp.starts_with("HTTP/1.1 403"),
            "DNS-rebinding Host accepted: {rebind_resp}"
        );

        // Query-string ?token= MUST NOT authenticate.
        let query_tok = format!(
            "POST /mcp?token={TEST_TOKEN} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let query_resp = exchange(addr, &query_tok).await;
        assert!(
            query_resp.starts_with("HTTP/1.1 401"),
            "query token should be rejected: {query_resp}"
        );

        // Oversized Content-Length MUST return 413 immediately without hanging/OOM.
        let huge = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TEST_TOKEN}\r\nContent-Length: 67108864\r\n\r\n{{}}"
        );
        let huge_resp = exchange(addr, &huge).await;
        assert!(
            huge_resp.starts_with("HTTP/1.1 413"),
            "oversized body should return 413: {huge_resp}"
        );

        // RFC 9110 case-insensitive `bearer ` scheme prefix MUST be accepted,
        // and non-ASCII UTF-8 / truncated / invalid Authorization headers MUST
        // cleanly return 401 without panicking on UTF-8 char boundaries!
        for upper_or_mixed in [
            format!("bearer {TEST_TOKEN}"),
            format!("BEARER {TEST_TOKEN}"),
            format!("BeArEr {TEST_TOKEN}"),
        ] {
            let req = format!(
                "POST /mcp HTTP/1.1\r\nHost: [::1]:8080\r\nAuthorization: {upper_or_mixed}\r\nOrigin: http://[::1]:8080\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let resp = exchange(addr, &req).await;
            assert!(
                resp.starts_with("HTTP/1.1 200"),
                "case-insensitive {upper_or_mixed} should succeed: {resp}"
            );
        }
        for bad_auth in [
            "🔥🔥🔥",
            "🔥Bearer mcp-secret",
            "Bearer 🔥secret",
            "Be",
            "Bearer",
            "Bearer ",
            "Basic dXNlcjpwYXNz",
        ] {
            let req = format!(
                "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {bad_auth}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
            );
            let resp = exchange(addr, &req).await;
            assert!(
                resp.starts_with("HTTP/1.1 401"),
                "invalid Authorization '{bad_auth}' must return 401 without panicking, got: {resp:?}"
            );
        }

        // Exhausting concurrent GET /mcp SSE streams (16) MUST return 503 on the 17th SSE
        // while keeping POST /mcp responsive!
        let mut held_sse = Vec::new();
        for _ in 0..16 {
            let mut s = connect_when_up(addr).await;
            let req = format!(
                "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TEST_TOKEN}\r\n\r\n"
            );
            s.write_all(req.as_bytes()).await.unwrap();
            let mut head_buf = [0u8; 256];
            let n = s.read(&mut head_buf).await.unwrap();
            let head_str = String::from_utf8_lossy(&head_buf[..n]);
            assert!(head_str.starts_with("HTTP/1.1 200"), "{head_str}");
            held_sse.push(s);
        }
        let sse_overflow = exchange(
            addr,
            &format!(
                "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TEST_TOKEN}\r\n\r\n"
            ),
        )
        .await;
        assert!(
            sse_overflow.starts_with("HTTP/1.1 503"),
            "17th concurrent SSE stream should return 503: {sse_overflow}"
        );
        let post_still_works = exchange(addr, &raw).await;
        assert!(
            post_still_works.starts_with("HTTP/1.1 200"),
            "POST /mcp must remain available while SSE cap is full: {post_still_works}"
        );
        drop(held_sse);
    }

    #[tokio::test]
    async fn repeated_auth_failures_return_429() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let settings = ClientSettings {
            relay: "wss://127.0.0.1:1".into(),
            token: "unused".into(),
            fingerprint: "sha256:00".into(),
            trust: None,
        };
        let identity =
            std::env::temp_dir().join(format!("agentlink-mcp-rate-{}.json", uuid_like()));
        let cfg = McpConfig::from_settings(settings, identity);
        tokio::spawn(serve(cfg, addr, TEST_TOKEN.into(), false));

        let bad = "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer wrong-token-value-123\r\nContent-Length: 2\r\n\r\n{}";
        for i in 0..AUTH_RATE_LIMIT_MAX_FAILURES {
            let resp = exchange(addr, bad).await;
            assert!(
                resp.starts_with("HTTP/1.1 401"),
                "attempt {i} expected 401, got: {resp}"
            );
        }
        let throttled = exchange(addr, bad).await;
        assert!(
            throttled.starts_with("HTTP/1.1 429"),
            "expected 429 after {AUTH_RATE_LIMIT_MAX_FAILURES} failures, got: {throttled}"
        );
        assert!(throttled.contains("Retry-After:"), "{throttled}");
    }

    #[tokio::test]
    async fn session_table_caps_at_max_sessions() {
        let sessions: Arc<Mutex<HashMap<String, SessionSlot>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let settings = ClientSettings {
            relay: "wss://127.0.0.1:1".into(),
            token: "unused".into(),
            fingerprint: "sha256:00".into(),
            trust: None,
        };
        let identity =
            std::env::temp_dir().join(format!("agentlink-mcp-cap-{}.json", uuid_like()));
        let cfg = McpConfig::from_settings(settings, identity);
        for idx in 0..(MAX_MCP_HTTP_SESSIONS + 16) {
            let _ = get_or_insert_session(&sessions, &format!("sess-{idx}"), &cfg).await;
        }
        assert_eq!(sessions.lock().await.len(), MAX_MCP_HTTP_SESSIONS);
    }
}
