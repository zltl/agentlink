//! Phone-side offerer for `webrtc_signal`.
//!
//! Signaling uses the client runtime. The peer connection and the RTP
//! depacketizer live on `agentlink-view`'s own runtime, so a blocking
//! `open_live` does not stall the two client threads on themselves.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentlink_core::protocol::Op;
use agentlink_core::{Client, PHASE3_WEBRTC_SIGNAL};
use agentlink_view::{LiveOptions, Signal, Viewer};
use serde_json::Value;

use crate::LinkError;

#[derive(uniffi::Record)]
pub struct LiveInfo {
    pub session_id: String,
    pub codec: String,
    pub encoder: String,
    pub hardware: bool,
    pub width: u32,
    pub height: u32,
    pub control: bool,
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
}

#[derive(uniffi::Record)]
pub struct LiveStats {
    pub frames: u64,
    pub bytes: u64,
    pub loss: f64,
    pub latency_ms: i64,
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
    viewer: Mutex<Option<Viewer>>,
}

pub(crate) fn open(
    client: Arc<Client>,
    handle: tokio::runtime::Handle,
    node: String,
    max_fps: u32,
    bitrate: u32,
    monitor: u32,
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
            ice_servers: Vec::new(),
            control: true,
            // Native pixels. The node clamps anything outside 0.25..=1.
            scale: 1.0,
        },
    )
    .map_err(|detail| LinkError::Fail { detail })?;
    Ok(Arc::new(DesktopLive {
        viewer: Mutex::new(Some(viewer)),
    }))
}

#[uniffi::export]
impl DesktopLive {
    pub fn info(&self) -> LiveInfo {
        self.with(|viewer| info_of(viewer.info()))
            .unwrap_or_else(empty_info)
    }

    pub fn poll_frame(&self, timeout_ms: u32) -> Option<LiveFrame> {
        self.with(|viewer| {
            viewer
                .poll_frame(Duration::from_millis(u64::from(timeout_ms)))
                .map(|frame| LiveFrame {
                    annex_b: frame.annex_b,
                    keyframe: frame.keyframe,
                    captured_unix_ms: frame.captured_unix_ms,
                    width: frame.width,
                    height: frame.height,
                })
        })
        .flatten()
    }

    pub fn poll_cursor(&self) -> Option<LiveCursor> {
        self.with(|viewer| {
            viewer.poll_cursor().map(|cursor| LiveCursor {
                x: cursor.x,
                y: cursor.y,
                shape: cursor.shape,
            })
        })
        .flatten()
    }

    pub fn stats(&self) -> LiveStats {
        self.with(|viewer| {
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
        self.with(|viewer| viewer.send_control(&json))
            .unwrap_or(false)
    }

    pub fn request_keyframe(&self) {
        if let Some(viewer) = self
            .viewer
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .as_ref()
        {
            viewer.request_keyframe();
        }
    }

    /// `true` after the peer connection fails or closes on its own.
    pub fn failed(&self) -> bool {
        self.with(|viewer| viewer.failed()).unwrap_or(true)
    }

    /// Stop the peer and tell the node to close the session.
    pub fn shutdown(&self) {
        if let Some(viewer) = self
            .viewer
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take()
        {
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
    fn with<T>(&self, f: impl FnOnce(&Viewer) -> T) -> Option<T> {
        let guard = self.viewer.lock().unwrap_or_else(|err| err.into_inner());
        guard.as_ref().map(f)
    }
}

fn info_of(info: agentlink_view::LiveInfo) -> LiveInfo {
    LiveInfo {
        session_id: info.session_id,
        codec: info.codec,
        encoder: info.encoder,
        hardware: info.hardware,
        width: info.width,
        height: info.height,
        control: info.control,
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
        control: false,
    }
}
