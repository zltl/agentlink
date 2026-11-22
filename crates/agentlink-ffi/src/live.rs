//! Phone-side offerer for `webrtc_signal`.
//!
//! Signaling uses the client runtime. The peer connection and the RTP
//! depacketizer live on `agentlink-view`'s own runtime, so a blocking
//! `open_live` does not stall the two client threads on themselves.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentlink_core::protocol::Op;
use agentlink_core::{
    parse_relay_url, tls, Client, ClientSettings, PHASE3_WEBRTC_SIGNAL,
};
use agentlink_view::{LiveOptions, Signal, Viewer};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::LinkError;

const ICE_FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const ICE_MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(uniffi::Record)]
pub struct LiveInfo {
    pub session_id: String,
    pub codec: String,
    pub encoder: String,
    pub hardware: bool,
    pub width: u32,
    pub height: u32,
    pub src_width: u32,
    pub src_height: u32,
    pub control: bool,
    pub cursor_presentation: String,
}

#[derive(uniffi::Record)]
pub struct LiveFrame {
    pub annex_b: Vec<u8>,
    pub keyframe: bool,
    pub captured_unix_ms: i64,
    pub width: u32,
    pub height: u32,
}

#[derive(uniffi::Record)]
pub struct LiveCursor {
    pub x: i32,
    pub y: i32,
    pub shape: String,
    pub visible: bool,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
}

#[derive(uniffi::Record)]
pub struct LiveStats {
    pub frames: u64,
    pub bytes: u64,
    pub loss: f64,
    pub latency_ms: i64,
}

#[derive(uniffi::Record)]
pub struct LiveClipboard {
    pub text: String,
    pub truncated: bool,
}

struct ClientSignal {
    client: Arc<Client>,
    handle: tokio::runtime::Handle,
    node: String,
}

impl Signal for ClientSignal {
    fn signal(&self, payload: &Value) -> Result<Value, String> {
        let client = Arc::clone(&self.client);
        let node = self.node.clone();
        let payload = payload.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.handle.spawn(async move {
            let result = tokio::time::timeout(
                Duration::from_secs(25),
                client.call_op(
                    &node,
                    Op::Extension {
                        name: PHASE3_WEBRTC_SIGNAL.to_string(),
                        payload,
                    },
                ),
            )
            .await;
            let mapped = match result {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(err)) => Err(err.to_string()),
                Err(_) => Err("webrtc_signal timed out".into()),
            };
            let _ = tx.send(mapped);
        });
        rx.recv()
            .map_err(|_| "client runtime stopped".to_string())?
    }
}

#[derive(uniffi::Object)]
pub struct DesktopLive {
    viewer: Mutex<Option<Arc<Viewer>>>,
}

pub(crate) fn open(
    client: Arc<Client>,
    handle: tokio::runtime::Handle,
    node: String,
    max_fps: u32,
    bitrate: u32,
    monitor: u32,
    ice_servers: Vec<Value>,
    ice_refresh: Option<Arc<dyn Fn() -> Vec<Value> + Send + Sync>>,
) -> Result<Arc<DesktopLive>, LinkError> {
    let signal = Arc::new(ClientSignal {
        client,
        handle,
        node,
    });
    let viewer = Viewer::connect(
        signal,
        LiveOptions {
            max_fps,
            bitrate,
            monitor,
            viewer: "android".into(),
            ice_servers,
            control: true,
            // Native pixels. The node clamps anything outside 0.25..=1.
            scale: 1.0,
            ice_refresh,
            ..LiveOptions::default()
        },
    )
    .map_err(|detail| LinkError::Fail { detail })?;
    Ok(Arc::new(DesktopLive {
        viewer: Mutex::new(Some(Arc::new(viewer))),
    }))
}

#[uniffi::export]
impl DesktopLive {
    pub fn info(&self) -> LiveInfo {
        self.viewer()
            .map(|viewer| info_of(viewer.info()))
            .unwrap_or_else(empty_info)
    }

    pub fn poll_frame(&self, timeout_ms: u32) -> Option<LiveFrame> {
        let viewer = self.viewer()?;
        viewer
            .poll_frame(Duration::from_millis(u64::from(timeout_ms)))
            .map(|frame| LiveFrame {
                annex_b: frame.annex_b,
                keyframe: frame.keyframe,
                captured_unix_ms: frame.captured_unix_ms,
                width: frame.width,
                height: frame.height,
            })
    }

    pub fn poll_cursor(&self) -> Option<LiveCursor> {
        let viewer = self.viewer()?;
        viewer.poll_cursor().map(|cursor| LiveCursor {
            x: cursor.x,
            y: cursor.y,
            shape: cursor.shape,
            visible: cursor.visible,
            hotspot_x: cursor.hotspot_x,
            hotspot_y: cursor.hotspot_y,
        })
    }

    pub fn poll_clipboard(&self) -> Option<LiveClipboard> {
        let viewer = self.viewer()?;
        viewer.poll_clipboard().map(|clip| LiveClipboard {
            text: clip.text,
            truncated: clip.truncated,
        })
    }

    pub fn send_clipboard(&self, text: String) -> bool {
        let Some(viewer) = self.viewer() else {
            return false;
        };
        let payload = json!({
            "type": "clipboard",
            "text": text,
        })
        .to_string();
        viewer.send_control(&payload)
    }

    pub fn stats(&self) -> LiveStats {
        self.viewer()
            .map(|viewer| {
                let stats = viewer.stats();
                LiveStats {
                    frames: stats.frames,
                    bytes: stats.bytes,
                    loss: stats.loss,
                    latency_ms: stats.latency_ms,
                }
            })
            .unwrap_or(LiveStats {
                frames: 0,
                bytes: 0,
                loss: 0.0,
                latency_ms: 0,
            })
    }

    pub fn send_control(&self, json: String) -> bool {
        self.viewer()
            .map(|viewer| viewer.send_control(&json))
            .unwrap_or(false)
    }

    pub fn request_keyframe(&self) {
        if let Some(viewer) = self.viewer() {
            viewer.request_keyframe();
        }
    }

    /// `true` after the peer connection fails or closes on its own.
    pub fn failed(&self) -> bool {
        self.viewer().map(|viewer| viewer.failed()).unwrap_or(true)
    }

    /// Stop the peer and tell the node to close the session.
    pub fn shutdown(&self) {
        let viewer = self
            .viewer
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take();
        if let Some(viewer) = viewer {
            viewer.close();
        }
    }
}

impl Drop for DesktopLive {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl DesktopLive {
    fn viewer(&self) -> Option<Arc<Viewer>> {
        self.viewer
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .as_ref()
            .cloned()
    }
}

/// Best-effort fetch of relay ICE/TURN servers using the client's pinned TLS
/// configuration. Tries authenticated `POST /api/ice` first, then falls back
/// to `GET /view/config.json`.
pub(crate) async fn fetch_ice_servers(settings: &ClientSettings) -> Vec<Value> {
    if !settings.token.trim().is_empty() {
        if let Some(body) = relay_https_json(
            settings,
            "POST",
            "/api/ice",
            Some(settings.token.trim()),
            Some(b"{}"),
        )
        .await
        {
            let servers = parse_ice_document(&body);
            if !servers.is_empty() {
                return servers;
            }
        }
    }
    if let Some(body) = relay_https_json(settings, "GET", "/view/config.json", None, None).await {
        return parse_ice_document(&body);
    }
    Vec::new()
}

pub(crate) fn parse_ice_document(value: &Value) -> Vec<Value> {
    if let Some(arr) = value.as_array() {
        return arr
            .iter()
            .filter(|item| {
                item.get("urls")
                    .and_then(Value::as_array)
                    .is_some_and(|urls| !urls.is_empty())
            })
            .cloned()
            .collect();
    }
    if let Some(arr) = value.get("ice_servers").and_then(Value::as_array) {
        let direct: Vec<Value> = arr
            .iter()
            .filter(|item| {
                item.get("urls")
                    .and_then(Value::as_array)
                    .is_some_and(|urls| !urls.is_empty())
            })
            .cloned()
            .collect();
        if !direct.is_empty() {
            return direct;
        }
    }
    let mut out = Vec::new();
    if let Some(stun) = value.get("stun").and_then(Value::as_array) {
        let urls: Vec<Value> = stun
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| json!(s))
            .collect();
        if !urls.is_empty() {
            out.push(json!({ "urls": urls }));
        }
    }
    if let Some(turn) = value.get("turn").and_then(Value::as_array) {
        for item in turn {
            if item
                .get("urls")
                .and_then(Value::as_array)
                .is_some_and(|urls| !urls.is_empty())
            {
                out.push(item.clone());
            }
        }
    }
    out
}

async fn relay_https_json(
    settings: &ClientSettings,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&[u8]>,
) -> Option<Value> {
    let mut relay_url = settings.relay.clone();
    let mut trust_opt = settings.trust.clone();
    crate::apply_mobile_relay_defaults(&mut relay_url, &settings.fingerprint, &mut trust_opt);
    let relay = parse_relay_url(&relay_url).ok()?;
    let trust = tls::RelayTrust::parse(&settings.fingerprint, trust_opt.as_deref()).ok()?;
    let tcp = timeout(
        ICE_FETCH_TIMEOUT,
        TcpStream::connect((relay.host.as_str(), relay.port)),
    )
    .await
    .ok()?
    .ok()?;
    let adopt = tls::adopt_loopback_leaf(&relay.host, tcp.peer_addr().ok());
    let dial = tls::client_config_for_dial(&trust, adopt).ok()?;
    let connector = tokio_rustls::TlsConnector::from(dial.config);
    let server_name = tls::server_name(&relay.host, &trust).ok()?;
    let mut tls_stream = timeout(ICE_FETCH_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .ok()?
        .ok()?;
    let payload = body.unwrap_or(&[]);
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nConnection: close\r\n",
        relay.bracket_host(),
        relay.port
    );
    if let Some(token) = bearer {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if !payload.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    req.push_str("\r\n");
    timeout(ICE_FETCH_TIMEOUT, tls_stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;
    if !payload.is_empty() {
        timeout(ICE_FETCH_TIMEOUT, tls_stream.write_all(payload))
            .await
            .ok()?
            .ok()?;
    }
    let _ = timeout(ICE_FETCH_TIMEOUT, tls_stream.flush()).await;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let read_res = timeout(ICE_FETCH_TIMEOUT, async {
        loop {
            let n = tls_stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            if raw.len() + n > ICE_MAX_RESPONSE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "response too large",
                ));
            }
            raw.extend_from_slice(&chunk[..n]);
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    if read_res.is_err() {
        return None;
    }
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..split]).ok()?;
    let status_line = head.lines().next()?;
    let status_code = status_line.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    if !(200..300).contains(&status_code) {
        return None;
    }
    serde_json::from_slice::<Value>(&raw[split + 4..]).ok()
}

fn info_of(info: agentlink_view::LiveInfo) -> LiveInfo {
    LiveInfo {
        session_id: info.session_id,
        codec: info.codec,
        encoder: info.encoder,
        hardware: info.hardware,
        width: info.width,
        height: info.height,
        src_width: info.src_width,
        src_height: info.src_height,
        control: info.control,
        cursor_presentation: info.cursor_presentation,
    }
}

fn empty_info() -> LiveInfo {
    LiveInfo {
        session_id: String::new(),
        codec: String::new(),
        encoder: String::new(),
        hardware: false,
        width: 0,
        height: 0,
        src_width: 0,
        src_height: 0,
        control: false,
        cursor_presentation: "legacy".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ice_document_extracts_stun_and_turn_servers() {
        let doc = json!({
            "stun": ["stun:stun.l.google.com:19302"],
            "turn": [{
                "urls": ["turn:turn.example:3478"],
                "username": "u1",
                "credential": "p1"
            }]
        });
        let servers = parse_ice_document(&doc);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0]["urls"][0], "stun:stun.l.google.com:19302");
        assert_eq!(servers[1]["username"], "u1");
        assert_eq!(servers[1]["credential"], "p1");

        let arr = json!([{ "urls": ["turns:turn.example:5349"], "username": "u", "credential": "c" }]);
        let from_arr = parse_ice_document(&arr);
        assert_eq!(from_arr.len(), 1);
        assert_eq!(from_arr[0]["urls"][0], "turns:turn.example:5349");
    }
}
