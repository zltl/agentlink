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
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use agentlink_core::ClientSettings;
use anyhow::{anyhow, Result};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::mcp::{self, Mcp};

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
    let sessions: Arc<Mutex<HashMap<String, Arc<Mutex<Mcp>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let token = Arc::new(token);
    loop {
        let (socket, _) = listener.accept().await?;
        let sessions = sessions.clone();
        let settings = settings.clone();
        let token = token.clone();
        let identity_path = identity_path.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_conn(socket, sessions, settings, token, identity_path).await {
                tracing::debug!(error = %err, "mcp http connection ended");
            }
        });
    }
}

async fn handle_conn(
    mut socket: TcpStream,
    sessions: Arc<Mutex<HashMap<String, Arc<Mutex<Mcp>>>>>,
    settings: ClientSettings,
    token: Arc<String>,
    identity_path: PathBuf,
) -> Result<()> {
    let req = read_request(&mut socket).await?;
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
            let session_id = header(&req.headers, "mcp-session-id")
                .map(str::to_string)
                .unwrap_or_else(|| uuid_like());
            let state = {
                let mut map = sessions.lock().await;
                map.entry(session_id.clone())
                    .or_insert_with(|| {
                        Arc::new(Mutex::new(mcp::new_state(settings, identity_path.clone())))
                    })
                    .clone()
            };
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
            let session_id = header(&req.headers, "mcp-session-id")
                .map(str::to_string)
                .unwrap_or_else(|| uuid_like());
            {
                let mut map = sessions.lock().await;
                map.entry(session_id.clone()).or_insert_with(|| {
                    Arc::new(Mutex::new(mcp::new_state(settings, identity_path.clone())))
                });
            }
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nMcp-Session-Id: {session_id}\r\n\r\n"
            );
            socket.write_all(header.as_bytes()).await?;
            loop {
                if socket.write_all(b": keepalive\n\n").await.is_err() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
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

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn read_request(socket: &mut TcpStream) -> Result<Request> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = socket.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("client closed"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > 1024 * 1024 {
            return Err(anyhow!("headers too large"));
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
    let length = header(&headers, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < length {
        let n = socket.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(length);
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

fn authorized(req: &Request, token: &str) -> bool {
    if let Some(value) = header(&req.headers, "authorization") {
        if let Some(got) = value.strip_prefix("Bearer ") {
            return got == token;
        }
    }
    req.path
        .split_once('?')
        .map(|(_, query)| {
            query
                .split('&')
                .any(|pair| pair == format!("token={token}"))
        })
        .unwrap_or(false)
}

fn origin_ok(origin: &str) -> bool {
    let lower = origin.to_ascii_lowercase();
    lower.contains("://localhost") || lower.contains("://127.0.0.1") || lower.contains("://[::1]")
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
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
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
    }
}
