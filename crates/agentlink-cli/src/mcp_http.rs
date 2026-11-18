//! Streamable HTTP transport for the MCP server.
//!
//! `POST /mcp` carries one JSON-RPC message and returns JSON.
//! `GET /mcp` is a server-sent-event stream of keepalive comments.
//! `DELETE /mcp` drops the session named by `Mcp-Session-Id`.
//!
//! Every request needs `Authorization: Bearer <token>`. When `Origin` is
//! present it must be localhost. This is not a public endpoint.

use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agentlink_core::ClientSettings;
use anyhow::{anyhow, Result};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

use crate::mcp::{self, Mcp};

const MAX_HTTP_HEADERS_BYTES: usize = 64 * 1024;
const MAX_HTTP_BODY_BYTES: usize = mcp::MAX_MCP_MESSAGE_BYTES;
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_MCP_HTTP_SESSIONS: usize = 64;
const MCP_SESSION_IDLE_TTL: Duration = Duration::from_secs(3600);
const MAX_CONCURRENT_MCP_CONNS: usize = 64;
const MAX_CONCURRENT_MCP_SSE: usize = 16;

struct SessionSlot {
    mcp: Arc<Mutex<Mcp>>,
    last_used: Instant,
}

pub async fn serve(
    settings: ClientSettings,
    bind: SocketAddr,
    token: String,
    identity_path: PathBuf,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    eprintln!("mcp http listening on http://{addr}/mcp");
    let _ = std::io::stderr().flush();
    let sessions: Arc<Mutex<HashMap<String, SessionSlot>>> = Arc::new(Mutex::new(HashMap::new()));
    let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_MCP_CONNS));
    let sse_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_MCP_SSE));
    let token = Arc::new(token);
    loop {
        let (mut socket, _) = listener.accept().await?;
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
        let sse_sem = sse_sem.clone();
        let settings = settings.clone();
        let token = token.clone();
        let identity_path = identity_path.clone();
        tokio::spawn(async move {
            let _permit = conn_permit;
            if let Err(err) =
                handle_conn(socket, sessions, sse_sem, settings, token, identity_path).await
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

async fn handle_conn(
    mut socket: TcpStream,
    sessions: Arc<Mutex<HashMap<String, SessionSlot>>>,
    sse_sem: Arc<Semaphore>,
    settings: ClientSettings,
    token: Arc<String>,
    identity_path: PathBuf,
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
        if !host_ok(host) {
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
            let message: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
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
            let state =
                get_or_insert_session(&sessions, &session_id, &settings, &identity_path).await;
            let response = {
                let mut state = state.lock().await;
                mcp::handle(&mut state, message).await
            };
            let body = match response {
                Some(value) => serde_json::to_vec(&value)?,
                None => b"{}".to_vec(),
            };
            write_response(
                &mut socket,
                200,
                "application/json",
                Some(&session_id),
                &body,
            )
            .await
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
            let _ = get_or_insert_session(&sessions, &session_id, &settings, &identity_path).await;
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
    settings: &ClientSettings,
    identity_path: &std::path::Path,
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
    let mcp = Arc::new(Mutex::new(mcp::new_state(
        settings.clone(),
        identity_path.to_path_buf(),
    )));
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
    if header(&headers, "transfer-encoding").is_some() {
        return Err(ReadRequestError::BadRequest);
    }
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
    let length = content_len.unwrap_or(0);
    let initial = &buf[header_end + 4..];
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

fn host_ok(raw_host: &str) -> bool {
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
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
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
        tokio::spawn(serve(settings, addr, "mcp-secret".into(), identity));

        let denied = exchange(
            addr,
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");

        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#;
        let raw = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer mcp-secret\r\nOrigin: http://127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let ok = exchange(addr, &raw).await;
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains("Mcp-Session-Id:"), "{ok}");
        assert!(ok.contains("agentlink"), "{ok}");

        let foreign = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer mcp-secret\r\nOrigin: https://evil.example\r\nContent-Length: {}\r\n\r\n{body}",
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
                "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer mcp-secret\r\nOrigin: {spoof_origin}\r\nContent-Length: {}\r\n\r\n{body}",
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
            "POST /mcp HTTP/1.1\r\nHost: rebind.attacker.example:8080\r\nAuthorization: Bearer mcp-secret\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let rebind_resp = exchange(addr, &rebind).await;
        assert!(
            rebind_resp.starts_with("HTTP/1.1 403"),
            "DNS-rebinding Host accepted: {rebind_resp}"
        );

        // Query-string ?token= MUST NOT authenticate.
        let query_tok = format!(
            "POST /mcp?token=mcp-secret HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let query_resp = exchange(addr, &query_tok).await;
        assert!(
            query_resp.starts_with("HTTP/1.1 401"),
            "query token should be rejected: {query_resp}"
        );

        // Oversized Content-Length MUST return 413 immediately without hanging/OOM.
        let huge = "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer mcp-secret\r\nContent-Length: 67108864\r\n\r\n{}";
        let huge_resp = exchange(addr, huge).await;
        assert!(
            huge_resp.starts_with("HTTP/1.1 413"),
            "oversized body should return 413: {huge_resp}"
        );

        // RFC 9110 case-insensitive `bearer ` scheme prefix MUST be accepted,
        // and non-ASCII UTF-8 / truncated / invalid Authorization headers MUST
        // cleanly return 401 without panicking on UTF-8 char boundaries!
        for upper_or_mixed in ["bearer mcp-secret", "BEARER mcp-secret", "BeArEr mcp-secret"] {
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
            s.write_all(
                b"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer mcp-secret\r\n\r\n",
            )
            .await
            .unwrap();
            let mut head_buf = [0u8; 256];
            let n = s.read(&mut head_buf).await.unwrap();
            let head_str = String::from_utf8_lossy(&head_buf[..n]);
            assert!(head_str.starts_with("HTTP/1.1 200"), "{head_str}");
            held_sse.push(s);
        }
        let sse_overflow = exchange(
            addr,
            "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer mcp-secret\r\n\r\n",
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
        for idx in 0..(MAX_MCP_HTTP_SESSIONS + 16) {
            let _ =
                get_or_insert_session(&sessions, &format!("sess-{idx}"), &settings, &identity)
                    .await;
        }
        assert_eq!(sessions.lock().await.len(), MAX_MCP_HTTP_SESSIONS);
    }
}
