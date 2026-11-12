//! One WebRTC peer per viewer. The node answers. Media is RTP; input, cursor
//! shape, and frame timestamps ride data channels the offerer opens.
//!
//! The browser page and `agentlink-view` (the Android client) are both
//! offerers on this contract. Neither one invents a second media protocol.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use agentlink_core::NodePolicy;
use bytes::Bytes;
use rtc::media::Sample;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use serde_json::{json, Value};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::media_stream::track_local::static_sample::TrackLocalStaticSample;
use webrtc::media_stream::track_local::TrackLocal;
use webrtc::media_stream::{MediaStreamTrack, Track};
use webrtc::peer_connection::{
    register_default_interceptors, MediaEngine, PeerConnection, PeerConnectionBuilder,
    PeerConnectionEventHandler, RTCConfigurationBuilder, RTCIceGatheringState, RTCIceServer,
    RTCIceTransportPolicy, RTCPeerConnectionIceEvent, RTCPeerConnectionState,
    RTCSessionDescription, Registry,
};
use webrtc::rtp_transceiver::RtpSender;
use webrtc::runtime::default_runtime;

use crate::capture::{CaptureRequest, CaptureTarget};
use crate::control_indicator;
use crate::error::{msg, Result};
use crate::input::{InputAction, MouseButton};
use crate::Desktop;

use super::audio::{ulaw, AudioCapture};
use super::encode::{open_encoder, Codec, EncoderRequest};
use super::handler::StreamAudit;
use super::pipeline::{Pump, PumpControl};
use super::tap::{self, StreamTapEvent};
use super::StreamShared;

pub struct SessionManager {
    desktop: Arc<Desktop>,
    shared: Arc<StreamShared>,
    sessions: Mutex<Vec<LiveSession>>,
}

struct LiveSession {
    id: String,
    stop: Arc<AtomicBool>,
    control: PumpControl,
    peer: Mutex<Option<Arc<dyn IcePeer>>>,
    started: Instant,
    viewer: String,
    peer_id: String,
    /// Set while this session still holds a control-indicator ref.
    control_held: Arc<AtomicBool>,
    /// ICE ufrag from the current remote offer. Compared to trickle
    /// `usernameFragment` when present; never logged.
    remote_ufrag: Mutex<Option<String>>,
}

struct Built {
    answer: Value,
    peer: Arc<dyn IcePeer>,
    stop: Arc<AtomicBool>,
    control: PumpControl,
    channels: Arc<Mutex<ChannelSet>>,
    started: Instant,
    allow_control: bool,
}

/// Methods the session table needs after negotiation. `PeerConnection` is a
/// sealed trait, so the concrete connection stays inside [`OwnedPeer`].
#[async_trait::async_trait]
trait IcePeer: Send + Sync {
    async fn add_ice_candidate(
        &self,
        candidate: rtc::peer_connection::transport::RTCIceCandidateInit,
    ) -> std::result::Result<(), String>;
    async fn renegotiate(
        &self,
        offer_sdp: &str,
    ) -> std::result::Result<(String, Vec<Value>), String>;
    fn gathered_candidates(&self) -> Vec<Value>;
    fn gather_done(&self) -> bool;
    fn push_gathered_candidate(&self, candidate: Value);
    async fn close(&self);
}

struct OwnedPeer<P> {
    inner: P,
    /// Dropping the sender stops RTP even if the peer connection still exists.
    _sender: Mutex<Vec<Arc<dyn RtpSender>>>,
    candidates: Arc<Mutex<Vec<Value>>>,
    gather_done: Arc<AtomicBool>,
    gather_wait: Duration,
    want_typ: Option<String>,
}

#[async_trait::async_trait]
impl<P> IcePeer for OwnedPeer<P>
where
    P: PeerConnection,
{
    async fn add_ice_candidate(
        &self,
        candidate: rtc::peer_connection::transport::RTCIceCandidateInit,
    ) -> std::result::Result<(), String> {
        PeerConnection::add_ice_candidate(&self.inner, candidate)
            .await
            .map_err(|err| err.to_string())
    }

    async fn renegotiate(
        &self,
        offer_sdp: &str,
    ) -> std::result::Result<(String, Vec<Value>), String> {
        self.gather_done.store(false, Ordering::Relaxed);
        if let Ok(mut candidates) = self.candidates.lock() {
            candidates.clear();
        }
        let offer =
            RTCSessionDescription::offer(offer_sdp.to_string()).map_err(|err| err.to_string())?;
        PeerConnection::set_remote_description(&self.inner, offer)
            .await
            .map_err(|err| err.to_string())?;
        let answer = PeerConnection::create_answer(&self.inner, None)
            .await
            .map_err(|err| err.to_string())?;
        PeerConnection::set_local_description(&self.inner, answer)
            .await
            .map_err(|err| err.to_string())?;
        let deadline = Instant::now() + self.gather_wait;
        while Instant::now() < deadline {
            if self.gather_done.load(Ordering::Relaxed) {
                break;
            }
            if self
                .want_typ
                .as_deref()
                .is_some_and(|typ| candidates_have_typ(&self.candidates, typ))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let local = PeerConnection::local_description(&self.inner)
            .await
            .ok_or_else(|| "local description was not set".to_string())?;
        let candidates = self
            .candidates
            .lock()
            .map(|candidates| candidates.clone())
            .unwrap_or_default();
        Ok((local.sdp, candidates))
    }

    fn gathered_candidates(&self) -> Vec<Value> {
        self.candidates
            .lock()
            .map(|candidates| candidates.clone())
            .unwrap_or_default()
    }

    fn gather_done(&self) -> bool {
        self.gather_done.load(Ordering::Relaxed)
    }

    fn push_gathered_candidate(&self, candidate: Value) {
        if let Ok(mut candidates) = self.candidates.lock() {
            candidates.push(candidate);
        }
    }

    async fn close(&self) {
        let _ = PeerConnection::close(&self.inner).await;
    }
}

struct ChannelSet {
    cursor: Option<Arc<dyn DataChannel>>,
    meta: Option<Arc<dyn DataChannel>>,
}

/// AIMD bitrate adaptation state shared with the input data-channel handler.
#[derive(Clone)]
struct AimdState {
    /// Instant of the last feedback sample with loss > 2%.
    last_loss_at: Arc<Mutex<Option<Instant>>>,
    /// Instant when the current "no loss" streak began.
    quiet_since: Arc<Mutex<Option<Instant>>>,
}

impl AimdState {
    fn new() -> Self {
        Self {
            last_loss_at: Arc::new(Mutex::new(None)),
            quiet_since: Arc::new(Mutex::new(None)),
        }
    }
}

/// Depth-2 encode→RTP outbox. Full = drop oldest (never block the capture thread).
struct FrameOutbox {
    slots: Mutex<VecDeque<(super::encode::EncodedAccessUnit, Instant)>>,
    notify: Condvar,
    cap: usize,
    dropped: AtomicU64,
}

impl FrameOutbox {
    fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            slots: Mutex::new(VecDeque::with_capacity(cap.max(1))),
            notify: Condvar::new(),
            cap: cap.max(1),
            dropped: AtomicU64::new(0),
        })
    }

    fn push(&self, unit: super::encode::EncodedAccessUnit) {
        let mut q = self.slots.lock().unwrap_or_else(|err| err.into_inner());
        while q.len() >= self.cap {
            q.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back((unit, Instant::now()));
        self.notify.notify_one();
    }

    fn pop_timeout(
        &self,
        timeout: Duration,
    ) -> Option<(super::encode::EncodedAccessUnit, Duration)> {
        let mut q = self.slots.lock().unwrap_or_else(|err| err.into_inner());
        let deadline = Instant::now() + timeout;
        while q.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, wait) = self
                .notify
                .wait_timeout(q, deadline.saturating_duration_since(now))
                .unwrap_or_else(|err| err.into_inner());
            q = guard;
            if wait.timed_out() && q.is_empty() {
                return None;
            }
        }
        let (unit, enqueued_at) = q.pop_front()?;
        Some((unit, enqueued_at.elapsed()))
    }
}

#[derive(Clone)]
struct Handler {
    candidates: Arc<Mutex<Vec<Value>>>,
    gather_done: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    channels: Arc<Mutex<ChannelSet>>,
    desktop: Arc<Desktop>,
    policy: Arc<RwLock<NodePolicy>>,
    control: PumpControl,
    shared: Arc<StreamShared>,
    peer: String,
    session_id: String,
    /// From the node-injected `_allow_control` flag. A view-only grant stays
    /// false even when the node ceiling allows remote control.
    allow_control: bool,
    /// Set once ICE and DTLS are both up, which is when the SRTP contexts exist.
    media_ready: Arc<AtomicBool>,
    /// Drop delta frames until an IDR is actually written. The first IDR is
    /// often encoded while SRTP is still empty and the stack discards it.
    wait_idr: Arc<AtomicBool>,
    aimd: AimdState,
}

static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn manager(desktop: Arc<Desktop>, shared: Arc<StreamShared>) -> SessionManager {
    SessionManager {
        desktop,
        shared,
        sessions: Mutex::new(Vec::new()),
    }
}

impl SessionManager {
    pub async fn handle(&self, peer: &str, payload: &Value) -> std::result::Result<Value, String> {
        let action = payload.get("action").and_then(Value::as_str).unwrap_or("");
        match action {
            "list_monitors" => self.list_monitors(),
            "offer" => self.offer(peer, payload).await,
            "ice_restart" => self.ice_restart(payload).await,
            "ice" => self.ice(payload).await,
            "ice_pull" => self.ice_pull(payload),
            "keyframe" => self.keyframe(payload),
            "close" => self.close(payload).await,
            other => Err(format!("unknown webrtc_signal action '{other}'")),
        }
    }

    fn list_monitors(&self) -> std::result::Result<Value, String> {
        let monitors = self
            .desktop
            .capture
            .list_monitors()
            .map_err(|err| err.to_string())?;
        let state = self.desktop.capture.capturable_state();
        let monitors: Vec<Value> = monitors
            .into_iter()
            .map(|mon| {
                let mut value = serde_json::to_value(mon).unwrap_or_else(|_| json!({}));
                if let Some(obj) = value.as_object_mut() {
                    obj.insert("capturable".into(), json!(state.capturable));
                }
                value
            })
            .collect();
        Ok(json!({
            "monitors": monitors,
            "cursor": self.desktop.capture.cursor(),
            "capturable": state.capturable,
            "reason": state.reason,
        }))
    }

    async fn offer(&self, peer: &str, payload: &Value) -> std::result::Result<Value, String> {
        let policy = *self
            .shared
            .policy
            .read()
            .unwrap_or_else(|err| err.into_inner());
        if !policy.allows_remote_view() {
            return Err("remote_view is not allowed on this node".into());
        }
        let viewer = payload
            .get("viewer")
            .and_then(Value::as_str)
            .unwrap_or(peer)
            .to_string();
        let session_hint = format!("pending-{peer}");
        // Account ticket already granted control — do not wait on a human
        // allow/deny file (ConsentMode::Prompt). Notify still fires.
        let mut consent = *self
            .shared
            .consent
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if consent == super::consent::ConsentMode::Prompt
            && session_allows_control(payload, &policy)
        {
            consent = super::consent::ConsentMode::Notify;
        }
        super::consent::approve(
            consent,
            &self
                .shared
                .audit_path
                .read()
                .unwrap_or_else(|e| e.into_inner()),
            &viewer,
            &session_hint,
        )?;
        let built = build_answer(self.desktop.clone(), self.shared.clone(), peer, payload)
            .await
            .map_err(|err| err.to_string())?;
        let id = built.answer["session_id"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let monitor = payload.get("monitor").and_then(Value::as_u64).unwrap_or(0) as u32;
        audit_event(
            &self.shared,
            "stream_start",
            &format!("viewer={viewer} session={id}"),
            true,
            peer,
            json!({"viewer": viewer, "session": id, "monitor": monitor}),
            None,
            Duration::ZERO,
        );
        tap::emit(StreamTapEvent::Started {
            session_id: id.clone(),
            viewer: viewer.clone(),
            monitor,
            codec: built.answer["codec"].as_str().unwrap_or("h264").to_string(),
            encoder: built.answer["encoder"].as_str().unwrap_or("").to_string(),
        });
        spawn_cursor(
            self.desktop.clone(),
            built.channels.clone(),
            built.stop.clone(),
        );
        spawn_capturable(
            self.desktop.clone(),
            built.channels,
            built.stop.clone(),
            built.control.clone(),
        );
        let control_held = Arc::new(AtomicBool::new(false));
        if built.allow_control {
            control_held.store(true, Ordering::SeqCst);
            control_indicator::note_control_session(true);
        }
        // When the peer fails/closes, drop the indicator even if the viewer
        // never sends webrtc_signal close (common after ICE failure).
        {
            let stop = built.stop.clone();
            let held = control_held.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                if held.swap(false, Ordering::SeqCst) {
                    control_indicator::note_control_session(false);
                }
            });
        }
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(LiveSession {
                id,
                stop: built.stop,
                control: built.control,
                peer: Mutex::new(Some(built.peer)),
                started: built.started,
                viewer,
                peer_id: peer.to_string(),
                control_held,
                remote_ufrag: Mutex::new(sdp_ice_ufrag(
                    payload.get("sdp").and_then(Value::as_str).unwrap_or(""),
                )),
            });
        let _ = self.started_cleanup();
        Ok(built.answer)
    }

    fn started_cleanup(&self) -> bool {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|session| {
            let alive = !session.stop.load(Ordering::Relaxed);
            if !alive {
                if session.control_held.swap(false, Ordering::SeqCst) {
                    control_indicator::note_control_session(false);
                }
            }
            alive
        });
        true
    }

    async fn ice_restart(&self, payload: &Value) -> std::result::Result<Value, String> {
        let id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let sdp = payload.get("sdp").and_then(Value::as_str).unwrap_or("");
        if sdp.is_empty() {
            return Err("ice_restart requires an offer sdp".into());
        }
        let peer = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions
                .iter()
                .find(|session| session.id == id)
                .and_then(|session| {
                    session
                        .peer
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone()
                })
        };
        let Some(peer) = peer else {
            return Err("unknown stream session".into());
        };
        let (answer, candidates) = peer.renegotiate(sdp).await?;
        {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(session) = sessions.iter().find(|session| session.id == id) {
                *session
                    .remote_ufrag
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = sdp_ice_ufrag(sdp);
            }
        }
        Ok(json!({
            "session_id": id,
            "sdp": answer,
            "candidates": candidates,
            "ice_pull": true,
        }))
    }

    /// Safe typ inventory of candidates gathered for a live session, including
    /// any that arrived after the answer was returned. No ufrag or password.
    pub fn gathered_candidates(&self, session_id: &str) -> Option<Vec<Value>> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .iter()
            .find(|session| session.id == session_id)
            .and_then(|session| {
                session
                    .peer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|peer| peer.gathered_candidates())
            })
    }

    /// Append a candidate that arrived after the answer was serialized.
    /// Fixture / tests only; production signaling never calls this.
    pub fn inject_gathered_candidate(
        &self,
        session_id: &str,
        candidate: Value,
    ) -> std::result::Result<(), String> {
        let peer = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions
                .iter()
                .find(|session| session.id == session_id && !session.stop.load(Ordering::Relaxed))
                .and_then(|session| {
                    session
                        .peer
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone()
                })
        };
        let Some(peer) = peer else {
            return Err("unknown stream session".into());
        };
        peer.push_gathered_candidate(candidate);
        Ok(())
    }

    fn ice_pull(&self, payload: &Value) -> std::result::Result<Value, String> {
        let id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let after = payload.get("after").and_then(Value::as_u64).unwrap_or(0) as usize;
        let (candidates, gather_done, closed) = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            match sessions.iter().find(|session| session.id == id) {
                Some(session) if session.stop.load(Ordering::Relaxed) => (Vec::new(), true, true),
                Some(session) => session
                    .peer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|peer| (peer.gathered_candidates(), peer.gather_done(), false))
                    .unwrap_or((Vec::new(), true, true)),
                None => return Err("unknown stream session".into()),
            }
        };
        if closed {
            return Err("unknown stream session".into());
        }
        let tail = if after >= candidates.len() {
            Vec::new()
        } else {
            candidates[after..].to_vec()
        };
        let typ_list: Vec<&str> = tail
            .iter()
            .map(|value| {
                candidate_typ_hint(value.get("candidate").and_then(Value::as_str).unwrap_or(""))
            })
            .collect();
        eprintln!(
            "agentlink live-webrtc: ice_pull after={after} new={} gather_done={gather_done} typ={}",
            tail.len(),
            typ_list.join(",")
        );
        Ok(json!({
            "ok": true,
            "ice_pull": true,
            "gather_done": gather_done,
            "after": candidates.len(),
            "candidates": tail,
        }))
    }

    async fn ice(&self, payload: &Value) -> std::result::Result<Value, String> {
        let id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let candidate = payload.get("candidate").cloned().unwrap_or(Value::Null);
        let typ_hint = candidate
            .get("candidate")
            .and_then(Value::as_str)
            .map(candidate_typ_hint)
            .unwrap_or("unknown");
        eprintln!("agentlink live-webrtc: ice recv typ={typ_hint}");
        let (peer, remote_ufrag, closed) = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            match sessions.iter().find(|session| session.id == id) {
                Some(session) if session.stop.load(Ordering::Relaxed) => (None, None, true),
                Some(session) => (
                    session
                        .peer
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone(),
                    session
                        .remote_ufrag
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone(),
                    false,
                ),
                None => return Err("unknown stream session".into()),
            }
        };
        if closed {
            return Err("unknown stream session".into());
        }
        let Some(peer) = peer else {
            return Err("unknown stream session".into());
        };
        let init = parse_trickle_candidate(&candidate).map_err(|err| {
            eprintln!("agentlink live-webrtc: ice parse rejected typ={typ_hint}");
            err
        })?;
        if !ice_ufrag_matches(remote_ufrag.as_deref(), init.username_fragment.as_deref()) {
            eprintln!("agentlink live-webrtc: ice rejected stale generation typ={typ_hint}");
            return Err("stale ice generation".into());
        }
        let typ = candidate_typ_hint(&init.candidate);
        let mid_empty = init.sdp_mid.as_deref().unwrap_or("").is_empty();
        let mline = init.sdp_mline_index;
        peer.add_ice_candidate(init)
            .await
            .map_err(|err| err.to_string())?;
        // typ / mid emptiness / m-line only — never ufrag, password, or token.
        eprintln!(
            "agentlink live-webrtc: ice added typ={typ} sdpMid_empty={mid_empty} sdpMLineIndex={mline:?}"
        );
        Ok(json!({"ok": true, "added": true}))
    }

    fn keyframe(&self, payload: &Value) -> std::result::Result<Value, String> {
        let id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = sessions.iter().find(|session| session.id == id) {
            session.control.keyframe.store(true, Ordering::Relaxed);
        }
        Ok(json!({"ok": true}))
    }

    async fn close(&self, payload: &Value) -> std::result::Result<Value, String> {
        let id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let session = {
            let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            let index = sessions.iter().position(|session| session.id == id);
            index.map(|index| sessions.remove(index))
        };
        if let Some(session) = session {
            session.stop.store(true, Ordering::Relaxed);
            if session.control_held.swap(false, Ordering::SeqCst) {
                control_indicator::note_control_session(false);
            }
            if let Some(peer) = session
                .peer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                peer.close().await;
            }
            let duration_ms = session.started.elapsed().as_millis() as u64;
            let frames_sent = session.control.frames_sent.load(Ordering::Relaxed);
            let bytes_sent = session.control.bytes_sent.load(Ordering::Relaxed);
            let encoded_frames = session.control.encoded_frames.load(Ordering::Relaxed);
            let dropped_frames = session.control.dropped_frames.load(Ordering::Relaxed);
            let encode_ms = session.control.encode_ms();
            let encoder = session.control.encoder();
            let encode_error = session
                .control
                .last_error
                .lock()
                .map(|err| err.clone())
                .unwrap_or_default();
            let fps = if duration_ms > 0 {
                encoded_frames as f64 * 1000.0 / duration_ms as f64
            } else {
                0.0
            };
            tracing::info!(
                session = %id,
                encoder = %encoder,
                fps = format!("{fps:.2}"),
                encode_ms = format!("{encode_ms:.2}"),
                encoded_frames,
                dropped_frames,
                "stream session stats"
            );
            let detail = if encode_error.is_empty() {
                format!(
                    "session={id} duration_ms={duration_ms} frames={frames_sent} bytes={bytes_sent} encoder={encoder} fps={fps:.2} encode_ms={encode_ms:.2} dropped={dropped_frames}"
                )
            } else {
                format!(
                    "session={id} duration_ms={duration_ms} frames={frames_sent} bytes={bytes_sent} encoder={encoder} error={encode_error}"
                )
            };
            audit_event(
                &self.shared,
                "stream_stop",
                &detail,
                encode_error.is_empty() || frames_sent > 0,
                &session.peer_id,
                json!({
                    "session": id,
                    "viewer": session.viewer,
                    "duration_ms": duration_ms,
                    "frames": frames_sent,
                    "bytes": bytes_sent,
                    "encoder": encoder,
                    "encoded_frames": encoded_frames,
                    "dropped_frames": dropped_frames,
                    "encode_ms": encode_ms,
                    "fps": fps,
                    "error": encode_error,
                }),
                if encode_error.is_empty() {
                    None
                } else {
                    Some(encode_error)
                },
                session.started.elapsed(),
            );
            tap::emit(StreamTapEvent::Stopped {
                session_id: id.to_string(),
                viewer: session.viewer,
                duration_ms,
                frames_sent,
                bytes_sent,
            });
        }
        Ok(json!({"ok": true}))
    }
}

async fn build_answer(
    desktop: Arc<Desktop>,
    shared: Arc<StreamShared>,
    peer_id: &str,
    payload: &Value,
) -> Result<Built> {
    let sdp = payload
        .get("sdp")
        .and_then(Value::as_str)
        .ok_or_else(|| msg("offer is missing sdp"))?
        .to_string();
    let codec = Codec::parse(
        payload
            .get("codec")
            .and_then(Value::as_str)
            .unwrap_or("h264"),
    );
    let fps = payload
        .get("max_fps")
        .and_then(Value::as_u64)
        .unwrap_or(30)
        .clamp(1, 60) as u32;
    let bitrate = payload
        .get("bitrate")
        .and_then(Value::as_u64)
        .unwrap_or(2_000_000)
        .clamp(100_000, 12_000_000) as u32;
    let monitor = payload.get("monitor").and_then(Value::as_u64).unwrap_or(0) as u32;
    let scale_specified = payload.get("scale").is_some();
    let mut scale = payload
        .get("scale")
        .and_then(Value::as_f64)
        .unwrap_or(1.0)
        .clamp(0.05, 1.0) as f32;
    // Always keep encode width ≤ ENCODE_WIDTH_CAP on wide panels so the pixel
    // path stays realtime (even if the client asked for a larger scale).
    let mut native_w = 0u32;
    let mut native_h = 0u32;
    if let Ok(monitors) = desktop.capture.list_monitors() {
        let chosen = if payload.get("monitor").is_some() {
            monitors
                .iter()
                .find(|m| m.index == monitor)
                .or_else(|| monitors.first())
        } else {
            monitors.iter().max_by_key(|m| m.width)
        };
        if let Some(m) = chosen {
            native_w = m.width;
            native_h = m.height;
        }
        if let Some(capped) = default_scale_for_width(native_w, false) {
            if scale > capped + f32::EPSILON {
                tracing::info!(
                    native_width = native_w,
                    requested_scale = scale,
                    scale = capped,
                    cap = ENCODE_WIDTH_CAP,
                    "clamping scale so encode width ≤ cap"
                );
                scale = capped;
            } else if !scale_specified {
                scale = capped;
                tracing::info!(
                    native_width = native_w,
                    scale,
                    cap = ENCODE_WIDTH_CAP,
                    "capture wider than encode cap and scale unset; defaulting scale = cap/width"
                );
            }
        }
    }
    let audio = payload
        .get("audio")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let session_id = format!(
        "{peer_id}-{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        SESSION_SEQ.fetch_add(1, Ordering::Relaxed)
    );

    // Target encode size from the (possibly capped) scale. Capture-side
    // downsample feeds ffmpeg at this size so -vf scale is skipped.
    let want_encode_w = if native_w > 0 {
        super::encode::align_mb(((native_w as f32) * scale).round().max(1.0) as u32)
    } else {
        0
    };
    let want_encode_h = if native_h > 0 {
        super::encode::align_mb(((native_h as f32) * scale).round().max(1.0) as u32)
    } else {
        0
    };
    let capture_max_width = stream_capture_max_width(want_encode_w);
    let capture_request = CaptureRequest {
        target: if payload.get("monitor").is_some() {
            CaptureTarget::Monitor(monitor)
        } else {
            CaptureTarget::FullScreen
        },
        scale: 1.0,
        max_fps: fps as f32,
        max_width: capture_max_width,
    };
    let probe = desktop.capture.capture(&capture_request)?;
    let capture_w = probe.width;
    let capture_h = probe.height;
    let (encode_w, encode_h, src_w, src_h) = if capture_max_width > 0 {
        // Already downsampled in PipeWire — stdin size == encode size.
        let ew = super::encode::align_mb(capture_w);
        let eh = super::encode::align_mb(capture_h);
        (ew, eh, ew, eh)
    } else if want_encode_w > 0 {
        (want_encode_w, want_encode_h.max(2), capture_w, capture_h)
    } else {
        let ew = super::encode::align_mb(((capture_w as f32) * scale).round().max(1.0) as u32);
        let eh = super::encode::align_mb(((capture_h as f32) * scale).round().max(1.0) as u32);
        (ew, eh, capture_w, capture_h)
    };
    tracing::info!(
        capture_w,
        capture_h,
        encode_w,
        encode_h,
        src_w,
        src_h,
        scale,
        capture_max_width,
        fps,
        bitrate,
        "stream size capture_w/h -> encode_w/h (capture-side downsample when max_width>0)"
    );
    let encoder = open_encoder(&EncoderRequest {
        codec,
        width: encode_w,
        height: encode_h,
        src_width: src_w,
        src_height: src_h,
        fps,
        bitrate,
    })?;
    let info = encoder.info();
    let (mut pump, control) = Pump::start(
        desktop.capture.open_session(&capture_request)?,
        encoder,
        session_id.clone(),
        bitrate,
    );
    control.capture_w.store(capture_w, Ordering::Relaxed);
    control.capture_h.store(capture_h, Ordering::Relaxed);
    control.encode_w.store(encode_w, Ordering::Relaxed);
    control.encode_h.store(encode_h, Ordering::Relaxed);
    let width = encode_w;
    let height = encode_h;
    let _ = probe;

    let runtime = default_runtime().ok_or_else(|| msg("tokio runtime is required for WebRTC"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let channels = Arc::new(Mutex::new(ChannelSet {
        cursor: None,
        meta: None,
    }));
    let policy_now = *shared.policy.read().unwrap_or_else(|err| err.into_inner());
    let handler = Arc::new(Handler {
        candidates: Arc::new(Mutex::new(Vec::new())),
        gather_done: Arc::new(AtomicBool::new(false)),
        stop: stop.clone(),
        channels: channels.clone(),
        desktop: desktop.clone(),
        policy: shared.policy.clone(),
        control: control.clone(),
        shared: shared.clone(),
        peer: peer_id.to_string(),
        session_id: session_id.clone(),
        allow_control: session_allows_control(payload, &policy_now),
        media_ready: Arc::new(AtomicBool::new(false)),
        wait_idr: Arc::new(AtomicBool::new(true)),
        aimd: AimdState::new(),
    });
    let mut media = MediaEngine::default();
    media
        .register_codec(video_codec(&info.codec), RtpCodecKind::Video)
        .map_err(|err| msg(err.to_string()))?;
    let audio_capture = if audio { AudioCapture::start() } else { None };
    if audio_capture.is_some() {
        media
            .register_codec(pcmu_codec(), RtpCodecKind::Audio)
            .map_err(|err| msg(err.to_string()))?;
    }
    let registry = register_default_interceptors(Registry::new(), &mut media)
        .map_err(|err| msg(err.to_string()))?;
    let ice = ice_servers(payload);
    let policy = ice_transport_policy(payload);
    let gather_for = gather_budget(payload, policy);
    let want = wanted_typ(payload).map(str::to_string);
    let pc = PeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(ice)
                .with_ice_transport_policy(policy)
                .build(),
        )
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .with_handler(handler.clone() as Arc<dyn PeerConnectionEventHandler>)
        .with_runtime(runtime)
        .with_udp_addrs(vec!["0.0.0.0:0".to_string()])
        .build()
        .await
        .map_err(|err| msg(err.to_string()))?;

    let ssrc = rand_ssrc();
    let track = Arc::new(
        TrackLocalStaticSample::new(
            Instant::now(),
            MediaStreamTrack::new(
                "agentlink".into(),
                format!("video-{session_id}"),
                "agentlink-screen".into(),
                RtpCodecKind::Video,
                vec![RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        ssrc: Some(ssrc),
                        ..Default::default()
                    },
                    codec: video_codec(&info.codec).rtp_codec,
                    ..Default::default()
                }],
            ),
        )
        .map_err(|err| msg(err.to_string()))?,
    );
    let sender = pc
        .add_track(Arc::clone(&track) as Arc<dyn TrackLocal>)
        .await
        .map_err(|err| msg(err.to_string()))?;
    if audio_capture.is_some() {
        let audio_track = Arc::new(
            TrackLocalStaticSample::new(
                Instant::now(),
                MediaStreamTrack::new(
                    "agentlink-audio".into(),
                    format!("audio-{session_id}"),
                    "agentlink-audio".into(),
                    RtpCodecKind::Audio,
                    vec![RTCRtpEncodingParameters {
                        rtp_coding_parameters: RTCRtpCodingParameters {
                            ssrc: Some(rand_ssrc()),
                            ..Default::default()
                        },
                        codec: pcmu_codec().rtp_codec,
                        ..Default::default()
                    }],
                ),
            )
            .map_err(|err| msg(err.to_string()))?,
        );
        let _ = pc
            .add_track(Arc::clone(&audio_track) as Arc<dyn TrackLocal>)
            .await;
        if let Some(mut capture) = audio_capture {
            let audio_stop = stop.clone();
            let audio_track = audio_track;
            let audio_ready = handler.media_ready.clone();
            tokio::spawn(async move {
                let mut pcm = [0i16; 160];
                loop {
                    if audio_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let read = tokio::task::spawn_blocking(move || {
                        let n = capture.read_pcm(&mut pcm);
                        (capture, n, pcm)
                    })
                    .await;
                    let Ok((returned, n, pcm)) = read else { break };
                    capture = returned;
                    if n.is_none() {
                        break;
                    }
                    if !audio_ready.load(Ordering::Acquire) {
                        continue;
                    }
                    let encoded: Vec<u8> = pcm.iter().copied().map(ulaw).collect();
                    let ssrcs = audio_track.ssrcs().await;
                    let Some(ssrc) = ssrcs.first().copied() else {
                        continue;
                    };
                    let sample = Sample {
                        data: Bytes::from(encoded),
                        duration: Duration::from_millis(20),
                        ..Sample::new(Instant::now())
                    };
                    if let Err(err) = audio_track
                        .sample_writer(ssrc, 0)
                        .write_sample(&sample)
                        .await
                    {
                        tracing::debug!(error = %err, "audio sample was not sent");
                    }
                }
            });
        }
    }

    let offer = RTCSessionDescription::offer(sdp).map_err(|err| msg(err.to_string()))?;
    pc.set_remote_description(offer)
        .await
        .map_err(|err| msg(err.to_string()))?;
    let answer = pc
        .create_answer(None)
        .await
        .map_err(|err| msg(err.to_string()))?;
    pc.set_local_description(answer)
        .await
        .map_err(|err| msg(err.to_string()))?;
    let deadline = Instant::now() + gather_for;
    while Instant::now() < deadline {
        if handler.gather_done.load(Ordering::Relaxed) {
            break;
        }
        if want
            .as_deref()
            .is_some_and(|typ| candidates_have_typ(&handler.candidates, typ))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let local = pc
        .local_description()
        .await
        .ok_or_else(|| msg("local description was not set"))?;
    let payload_type = sender
        .get_parameters()
        .await
        .ok()
        .and_then(|params| {
            params
                .rtp_parameters
                .codecs
                .first()
                .map(|codec| codec.payload_type)
        })
        .unwrap_or(102);
    let candidates = handler
        .candidates
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .clone();

    let stop_thread = stop.clone();
    // Depth 1: new frame overwrites old under backpressure (drop-old).
    let outbox = FrameOutbox::new(1);
    let outbox_prod = outbox.clone();
    let control_prod = control.clone();
    std::thread::Builder::new()
        .name("agentlink-stream".into())
        .spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match pump.next(Duration::from_secs(2)) {
                    Ok(Some(unit)) => {
                        outbox_prod.push(unit);
                        let dropped = outbox_prod.dropped.swap(0, Ordering::Relaxed);
                        if dropped > 0 {
                            control_prod
                                .dropped_frames
                                .fetch_add(dropped, Ordering::Relaxed);
                        }
                    }
                    Ok(None) => continue,
                    Err(err) => {
                        tracing::warn!(error = %err, "stream pump stopped");
                        break;
                    }
                }
            }
            stop_thread.store(true, Ordering::Relaxed);
        })
        .map_err(|err| msg(format!("stream thread: {err}")))?;

    let track_loop = track.clone();
    let stop_loop = stop.clone();
    let meta_channels = channels.clone();
    let media_ready = handler.media_ready.clone();
    let wait_idr = handler.wait_idr.clone();
    let keyframe = control.keyframe.clone();
    let control_rtp = control.clone();
    let session_log = session_id.clone();
    let outbox_cons = outbox;
    tokio::spawn(async move {
        // ICE Connected is not SRTP. The driver drops RTP written before
        // DTLS installs the contexts (`local_srtp_context is not set yet`)
        // and still reports the write as success. The pump's only IDR is in
        // that window on a slow TURN path, and emitting it clears the
        // keyframe flag. A quiet desktop then produces no further access
        // unit, so the viewer stays at frames=0. Holding that sample re-arms
        // the flag; the next encode after Connected is an IDR that is
        // actually written.
        // `empty server_config` in the same logs is the SCTP endpoint (this
        // node is the DTLS client) refusing the browser's simultaneous-open
        // INIT. It is not the video key.
        tracing::info!(
            session = %session_log,
            payload_type,
            "negotiated video payload type"
        );
        loop {
            if stop_loop.load(Ordering::Relaxed) {
                break;
            }
            let Some((unit, queued_for)) = tokio::task::spawn_blocking({
                let outbox_cons = outbox_cons.clone();
                move || outbox_cons.pop_timeout(Duration::from_millis(200))
            })
            .await
            .ok()
            .flatten() else {
                continue;
            };
            control_rtp.note_queue_wait(queued_for);
            if stop_loop.load(Ordering::Relaxed) {
                break;
            }
            let ready = media_ready.load(Ordering::Acquire);
            let waiting = wait_idr.load(Ordering::Acquire);
            let unit_keyframe = unit.keyframe;
            let nbytes = unit.bytes.len();
            if hold_sample(ready, waiting, unit_keyframe, &keyframe) {
                if !ready {
                    tracing::info!(
                        session = %session_log,
                        keyframe = unit_keyframe,
                        "holding video sample until SRTP is ready; re-armed keyframe"
                    );
                }
                continue;
            }
            let sample = Sample {
                data: Bytes::from(unit.bytes),
                duration: Duration::from_millis((1000 / fps.max(1)) as u64),
                ..Sample::new(Instant::now())
            };
            if let Err(err) = track_loop
                .sample_writer(ssrc, payload_type)
                .write_sample(&sample)
                .await
            {
                tracing::warn!(error = %err, "video sample was not sent; requesting another IDR");
                wait_idr.store(true, Ordering::Release);
                keyframe.store(true, Ordering::Release);
                continue;
            }
            // Per-frame INFO logging was costing measurable wall time on the
            // RTP task; keep this at debug for smoothness benches.
            tracing::debug!(
                session = %session_log,
                keyframe = unit_keyframe,
                payload_type,
                bytes = nbytes,
                queue_ms = format!("{:.2}", queued_for.as_secs_f64() * 1000.0),
                "wrote video RTP sample"
            );
            if unit_keyframe {
                wait_idr.store(false, Ordering::Release);
            }
            let meta = meta_channels
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .meta
                .clone();
            if let Some(meta) = meta {
                let text = json!({"t": unit.captured_unix_ms}).to_string();
                let _ = meta.send_text(&text).await;
            }
        }
        stop_loop.store(true, Ordering::Relaxed);
    });

    Ok(Built {
        answer: json!({
            "session_id": session_id,
            "sdp": local.sdp,
            "candidates": candidates,
            "codec": info.codec.as_str(),
            "encoder": info.name,
            "hardware": info.hardware,
            "width": width,
            "height": height,
            "scale": scale,
            "encoded_frames": 0,
            "dropped_frames": 0,
            "encode_ms": 0.0,
            "audio": audio,
            // Session grant (`_allow_control` ∩ ceiling), not the node ceiling.
            "control": answer_control_field(handler.allow_control),
            // Viewer may bounded-pull candidates gathered after this answer.
            // Absent on older nodes; a new viewer must not retry-storm then.
            "ice_pull": true,
        }),
        peer: Arc::new(OwnedPeer {
            inner: pc,
            _sender: Mutex::new(vec![sender]),
            candidates: handler.candidates.clone(),
            gather_done: handler.gather_done.clone(),
            gather_wait: gather_for,
            want_typ: want,
        }),
        stop,
        control,
        channels,
        started: Instant::now(),
        allow_control: handler.allow_control,
    })
}

fn spawn_cursor(desktop: Arc<Desktop>, channels: Arc<Mutex<ChannelSet>>, stop: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut last = String::new();
        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let cursor = desktop.capture.cursor();
            let Some(cursor) = cursor else { continue };
            let visible = desktop.capture.cursor_visible();
            let text = json!({
                "x": cursor.x,
                "y": cursor.y,
                "shape": cursor.shape,
                "visible": visible,
            })
            .to_string();
            if text == last {
                continue;
            }
            last = text.clone();
            let channel = channels
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .cursor
                .clone();
            if let Some(channel) = channel {
                let _ = channel.send_text(&text).await;
            }
        }
    });
}

fn spawn_capturable(
    desktop: Arc<Desktop>,
    channels: Arc<Mutex<ChannelSet>>,
    stop: Arc<AtomicBool>,
    control: PumpControl,
) {
    tokio::spawn(async move {
        let mut last_cap = String::new();
        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let state = desktop.capture.capturable_state();
            let cap_text = json!({
                "type": "state",
                "capturable": state.capturable,
                "reason": state.reason,
            })
            .to_string();
            let mut perf = control.perf_json();
            if let Some(obj) = perf.as_object_mut() {
                obj.insert("type".into(), json!("perf"));
                obj.insert("capturable".into(), json!(state.capturable));
                obj.insert("reason".into(), json!(state.reason));
            }
            let perf_text = perf.to_string();
            let meta = channels
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .meta
                .clone();
            if let Some(meta) = meta {
                // Perf every 500ms (sliding averages — no per-frame logs).
                let _ = meta.send_text(&perf_text).await;
                if cap_text != last_cap {
                    last_cap = cap_text.clone();
                    let _ = meta.send_text(&cap_text).await;
                }
            }
        }
    });
}

/// Encode-width target for panels wider than 1920 (Retina). 1280 keeps the
/// BGRA capture→scale path near realtime; ≤1920 native is left alone.
const ENCODE_WIDTH_CAP: f32 = 1280.0;

/// Capture-side max width for the live stream. `0` disables downsample (full
/// ScreenCast + ffmpeg `-vf scale`). Default is `min(encode_w, env/1600)`.
fn stream_capture_max_width(encode_w: u32) -> u32 {
    #[cfg(pipewire_headers)]
    {
        let env_cap = super::pipewire::default_stream_max_width();
        if env_cap == 0 || encode_w == 0 {
            return 0;
        }
        encode_w.min(env_cap).max(2)
    }
    #[cfg(not(pipewire_headers))]
    {
        let _ = encode_w;
        0
    }
}

/// When `scale` was omitted and native width exceeds 1920, return `cap/width`.
/// Callers that always clamp pass `scale_specified=false`.
pub(crate) fn default_scale_for_width(native_width: u32, scale_specified: bool) -> Option<f32> {
    if scale_specified || native_width <= 1920 {
        return None;
    }
    Some((ENCODE_WIDTH_CAP / native_width as f32).clamp(0.05, 1.0))
}

/// Whether one encoded access unit may be written onto the RTP track.
///
/// `srtp_ready` is the peer connection reaching `connected` (ICE and DTLS).
/// Until then the SRTP contexts are empty and the stack drops the packet.
/// `waiting_for_idr` stays set across that gap so a delta whose IDR was
/// dropped is not the first thing the viewer tries to decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SampleAdmit {
    Hold,
    Send,
}

fn admit_sample(srtp_ready: bool, waiting_for_idr: bool, keyframe: bool) -> SampleAdmit {
    if srtp_ready && (!waiting_for_idr || keyframe) {
        SampleAdmit::Send
    } else {
        SampleAdmit::Hold
    }
}

/// `true` when this access unit must not be written.
///
/// A hold before SRTP re-arms `keyframe`. The pump clears that flag as soon
/// as it emits the access unit, and a quiet desktop will not emit another
/// one. The sample stays unwritten until Connected, which is the #33 gate.
fn hold_sample(
    srtp_ready: bool,
    waiting_for_idr: bool,
    unit_keyframe: bool,
    keyframe: &AtomicBool,
) -> bool {
    if admit_sample(srtp_ready, waiting_for_idr, unit_keyframe) != SampleAdmit::Hold {
        return false;
    }
    if !srtp_ready {
        keyframe.store(true, Ordering::Release);
    }
    true
}

/// Update the sender gate from a peer-connection state change.
///
/// Returns true on the rising edge of `connected`, which is the moment to
/// force a new IDR. A later `disconnected` closes the gate again so a TURN
/// path that renegotiates does not keep sending deltas with no picture.
fn media_gate_on_state(
    ready: &mut bool,
    waiting_for_idr: &mut bool,
    state: RTCPeerConnectionState,
) -> bool {
    match state {
        RTCPeerConnectionState::Connected => {
            if *ready {
                return false;
            }
            *ready = true;
            *waiting_for_idr = true;
            true
        }
        RTCPeerConnectionState::Disconnected
        | RTCPeerConnectionState::Failed
        | RTCPeerConnectionState::Closed => {
            *ready = false;
            false
        }
        _ => false,
    }
}

fn video_codec(codec: &Codec) -> RTCRtpCodecParameters {
    let (fmtp, pt) = match codec {
        Codec::H265 => ("", 96u8),
        Codec::Av1 => ("", 97),
        Codec::Vp9 => ("profile-id=0", 98),
        Codec::H264 => (
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
            102,
        ),
    };
    let mime = codec.mime();
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime.into(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: fmtp.into(),
            rtcp_feedback: Vec::new(),
        },
        payload_type: pt,
    }
}

fn pcmu_codec() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: "audio/PCMU".into(),
            clock_rate: 8000,
            channels: 1,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: Vec::new(),
        },
        payload_type: 0,
    }
}

fn ice_servers(payload: &Value) -> Vec<RTCIceServer> {
    let mut servers = Vec::new();
    if let Some(list) = payload.get("ice_servers").and_then(Value::as_array) {
        for entry in list {
            let urls = entry
                .get("urls")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if urls.is_empty() {
                continue;
            }
            servers.push(RTCIceServer {
                urls,
                username: entry
                    .get("username")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                credential: entry
                    .get("credential")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    // An explicit ice_path means the viewer chose this attempt's servers,
    // including an empty list for host-only. Do not add default STUN on top.
    if servers.is_empty() && payload.get("ice_path").is_none() {
        let urls = agentlink_core::stun_urls_from_env();
        if !urls.is_empty() {
            servers.push(RTCIceServer {
                urls,
                username: String::new(),
                credential: String::new(),
            });
        }
    }
    servers
}

fn ice_transport_policy(payload: &Value) -> RTCIceTransportPolicy {
    match payload
        .get("ice_transport_policy")
        .and_then(Value::as_str)
        .map(str::trim)
    {
        Some("relay") => RTCIceTransportPolicy::Relay,
        _ => RTCIceTransportPolicy::All,
    }
}

fn gather_budget(payload: &Value, policy: RTCIceTransportPolicy) -> Duration {
    let default_ms = if policy == RTCIceTransportPolicy::Relay {
        5_000
    } else {
        1_500
    };
    let ms = payload
        .get("gather_ms")
        .and_then(Value::as_u64)
        .unwrap_or(default_ms);
    Duration::from_millis(ms.clamp(200, 8_000))
}

fn wanted_typ(payload: &Value) -> Option<&'static str> {
    match payload.get("ice_path").and_then(Value::as_str) {
        Some("host") => Some("host"),
        Some("srflx") => Some("srflx"),
        Some("relay-udp") | Some("relay-tcp") => Some("relay"),
        _ => None,
    }
}

fn candidates_have_typ(candidates: &Mutex<Vec<Value>>, typ: &str) -> bool {
    let needle = format!(" typ {typ}");
    candidates
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .iter()
        .any(|value| {
            value
                .get("candidate")
                .and_then(Value::as_str)
                .unwrap_or("")
                .contains(&needle)
        })
}

/// Parse the trickle `candidate` object the viewer sends. A bare SDP string,
/// null, or a foreign JSON shape is an error so the audit cannot report
/// `ok` for a candidate that was never added.
fn parse_trickle_candidate(
    candidate: &Value,
) -> std::result::Result<rtc::peer_connection::transport::RTCIceCandidateInit, String> {
    serde_json::from_value(candidate.clone())
        .map_err(|err| format!("ice candidate is not a valid RTCIceCandidateInit ({err})"))
}

/// typ only, for logs and tests. The candidate attribute does not carry a
/// ufrag; still do not print the address line.
/// ICE ufrag from an SDP. Compared to trickle `usernameFragment`; never logged.
fn sdp_ice_ufrag(sdp: &str) -> Option<String> {
    for line in sdp.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("a=ice-ufrag:") {
            let value = trimmed[trimmed.len() - rest.len()..].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// When the trickle carries a usernameFragment, it must match the current
/// remote offer ufrag. A missing fragment (webrtc-0.21 `to_json`) is admitted
/// and isolated by `session_id` instead. The ufrag value is never logged.
fn ice_ufrag_matches(remote_ufrag: Option<&str>, fragment: Option<&str>) -> bool {
    match (remote_ufrag, fragment) {
        (Some(want), Some(got)) if !got.is_empty() => want == got,
        _ => true,
    }
}

fn candidate_typ_hint(line: &str) -> &'static str {
    let lower = line.to_ascii_lowercase();
    if lower.contains("typ srflx") {
        "srflx"
    } else if lower.contains("typ relay") {
        "relay"
    } else if lower.contains("typ prflx") {
        "prflx"
    } else if lower.contains("typ host") {
        "host"
    } else {
        "unknown"
    }
}

fn rand_ssrc() -> u32 {
    let tick = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1);
    tick | 1
}

fn audit_event(
    shared: &StreamShared,
    op: &str,
    detail: &str,
    ok: bool,
    peer: &str,
    args: Value,
    error: Option<String>,
    duration: Duration,
) {
    let client_id = if peer.is_empty() {
        "local".to_string()
    } else {
        peer.to_string()
    };
    let hook = shared
        .on_audit
        .read()
        .unwrap_or_else(|err| err.into_inner())
        .clone();
    if let Some(hook) = hook {
        hook(&StreamAudit {
            action: op.to_string(),
            client_id,
            detail: detail.to_string(),
            args,
            ok,
            error,
            duration,
        });
        return;
    }
    let path = shared
        .audit_path
        .read()
        .unwrap_or_else(|err| err.into_inner())
        .clone();
    if path.as_os_str().is_empty() {
        return;
    }
    let line = json!({
        "ts": chrono_stamp(),
        "op": op,
        "detail": detail,
        "ok": ok,
        "peer": peer,
    });
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = writeln!(file, "{line}");
    }
}

fn chrono_stamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        if let Ok(init) = event.candidate.to_json() {
            if let Ok(value) = serde_json::to_value(&init) {
                self.candidates
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .push(value);
            }
        }
    }

    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            self.gather_done.store(true, Ordering::Relaxed);
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        // Disconnected is often a brief ICE blip. The viewer restarts ICE on
        // this same peer connection. Closed is the end of the session.
        // Connected means ICE and DTLS, so the SRTP contexts are installed.
        // Ask for a fresh IDR; anything encoded before this was discarded.
        let mut ready = self.media_ready.load(Ordering::Acquire);
        let mut waiting = self.wait_idr.load(Ordering::Acquire);
        let request = media_gate_on_state(&mut ready, &mut waiting, state);
        self.wait_idr.store(waiting, Ordering::Release);
        if request {
            self.control.keyframe.store(true, Ordering::Release);
            tracing::info!(
                session = %self.session_id,
                "peer connected; next video sample will be an encrypted IDR"
            );
        }
        self.media_ready.store(ready, Ordering::Release);
        if matches!(
            state,
            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
        ) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        let label = channel.label().await.unwrap_or_default();
        match label.as_str() {
            "cursor" => {
                self.channels
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .cursor = Some(channel.clone());
            }
            "meta" => {
                self.channels.lock().unwrap_or_else(|e| e.into_inner()).meta =
                    Some(channel.clone());
            }
            _ => {}
        }
        let policy = self.policy.clone();
        let desktop = self.desktop.clone();
        let control = self.control.clone();
        let shared = self.shared.clone();
        let peer = self.peer.clone();
        let session_id = self.session_id.clone();
        let allow_control = self.allow_control;
        let aimd = self.aimd.clone();
        let input = label == "input" || label.is_empty();
        tokio::spawn(async move {
            loop {
                match channel.poll().await {
                    Some(DataChannelEvent::OnMessage(message)) => {
                        if !input {
                            continue;
                        }
                        let text = String::from_utf8_lossy(&message.data).to_string();
                        handle_input(
                            &text,
                            &desktop,
                            &policy,
                            &control,
                            &channel,
                            &shared,
                            &peer,
                            &session_id,
                            allow_control,
                            &aimd,
                        )
                        .await;
                    }
                    Some(DataChannelEvent::OnClose) | None => break,
                    _ => {}
                }
            }
        });
    }
}

async fn handle_input(
    text: &str,
    desktop: &Desktop,
    policy: &RwLock<NodePolicy>,
    control: &PumpControl,
    channel: &Arc<dyn DataChannel>,
    shared: &StreamShared,
    peer: &str,
    session_id: &str,
    allow_control: bool,
    aimd: &AimdState,
) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
    if kind == "feedback" {
        if let Some(loss) = value.get("loss").and_then(Value::as_f64) {
            // Simple AIMD: loss > 2% → −20% + keyframe; 2s quiet → +10%.
            // Floor 800 kbps / ceiling 8 Mbps.
            let current = control.bitrate.load(Ordering::Relaxed);
            let mut next = current;
            if loss > 0.02 {
                next = (current as f32 * 0.8) as u32;
                control.keyframe.store(true, Ordering::Release);
                if let Ok(mut slot) = aimd.last_loss_at.lock() {
                    *slot = Some(Instant::now());
                }
                if let Ok(mut slot) = aimd.quiet_since.lock() {
                    *slot = None;
                }
            } else {
                let quiet_for = {
                    let mut quiet = aimd.quiet_since.lock().unwrap_or_else(|e| e.into_inner());
                    let since = quiet.get_or_insert_with(Instant::now);
                    since.elapsed()
                };
                if quiet_for >= Duration::from_secs(2) {
                    next = (current as f32 * 1.1) as u32;
                    if let Ok(mut slot) = aimd.quiet_since.lock() {
                        *slot = Some(Instant::now());
                    }
                }
            }
            control
                .bitrate
                .store(next.clamp(800_000, 8_000_000), Ordering::Relaxed);
        }
        return;
    }
    if kind == "keyframe" {
        control.keyframe.store(true, Ordering::Relaxed);
        return;
    }
    let allowed = policy
        .read()
        .map(|policy| allow_control && input_allowed(&policy, kind))
        .unwrap_or(false);
    let (detail, mut args) = input_audit(kind, &value);
    if let Some(obj) = args.as_object_mut() {
        obj.insert("session".into(), json!(session_id));
    }
    if !allowed {
        audit_event(
            shared,
            kind,
            &detail,
            false,
            peer,
            args,
            Some("remote_control is not allowed".into()),
            Duration::ZERO,
        );
        let _ = channel
            .send_text("{\"type\":\"error\",\"error\":\"remote_control is not allowed\"}")
            .await;
        return;
    }
    audit_event(
        shared,
        kind,
        &detail,
        true,
        peer,
        args,
        None,
        Duration::ZERO,
    );
    let action = match kind {
        "mouse" => mouse_action(desktop, &value),
        "key" => value.get("keys").map(|keys| {
            key_input_action(
                string_list(keys),
                value.get("down").and_then(Value::as_bool),
            )
        }),
        "type" => value
            .get("text")
            .and_then(Value::as_str)
            .map(|text| InputAction::Type {
                text: text.chars().take(8000).collect(),
            }),
        "clipboard" => {
            match value.get("text").and_then(Value::as_str) {
                Some(text) => {
                    let text = text.to_string();
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::clipboard::write_clipboard(&text)
                    })
                    .await;
                }
                None => {
                    let read = tokio::task::spawn_blocking(crate::clipboard::read_clipboard).await;
                    if let Ok(Ok(clip)) = read {
                        let mut body = json!({
                            "type": "clipboard",
                            "text": clip.text,
                            "chars": clip.text.chars().count(),
                        });
                        if clip.truncated {
                            body.as_object_mut()
                                .unwrap()
                                .insert("truncated".into(), json!(true));
                        }
                        let _ = channel.send_text(&body.to_string()).await;
                    }
                }
            }
            None
        }
        _ => None,
    };
    if let Some(action) = action {
        let desktop = desktop.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let result = desktop.hid.inject(&action);
            if result.is_ok() {
                control_indicator::note_inject_input();
            }
            result
        })
        .await;
    }
}

pub(crate) fn input_allowed(policy: &NodePolicy, kind: &str) -> bool {
    matches!(kind, "feedback" | "keyframe") || policy.allows_remote_control()
}

/// The answer `control` bit is the session grant already stored on the
/// handler. The node policy ceiling must not set it by itself: a view-only
/// ticket on a control-capable node stays `false`.
pub(crate) fn answer_control_field(session_allow_control: bool) -> bool {
    session_allow_control
}

/// Honor a node-injected `_allow_control` flag. Absent means the ceiling.
/// An explicit false keeps a view-only grant from driving a control-capable node.
pub(crate) fn session_allows_control(payload: &Value, policy: &NodePolicy) -> bool {
    if !policy.allows_remote_control() {
        return false;
    }
    payload
        .get("_allow_control")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

/// Character count and a 12-character preview. The full string stays out of the log.
pub(crate) fn input_audit(kind: &str, value: &Value) -> (String, Value) {
    match kind {
        "type" | "clipboard" => {
            let text = value.get("text").and_then(Value::as_str);
            let Some(text) = text else {
                return (format!("{kind} get"), json!({"kind": kind, "op": "get"}));
            };
            let count = text.chars().count();
            let mut preview: String = text.chars().take(12).collect();
            preview = preview.replace(['\n', '\r'], " ");
            let detail = if count > preview.chars().count() {
                format!("{kind} {count} chars \"{preview}…\"")
            } else {
                format!("{kind} {count} chars \"{preview}\"")
            };
            (detail, json!({"kind": kind, "chars": count}))
        }
        "key" => {
            let keys = key_text(value.get("keys"));
            if keys.chars().count() > 12 {
                let count = keys.chars().count();
                let preview: String = keys.chars().take(12).collect();
                (
                    format!("key {count} chars \"{preview}…\""),
                    json!({"kind": "key", "chars": count}),
                )
            } else {
                (format!("key {keys}"), json!({"kind": "key", "keys": keys}))
            }
        }
        "mouse" => {
            let action = value
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("move");
            (
                format!("mouse {action}"),
                json!({"kind": "mouse", "action": action}),
            )
        }
        other => (other.to_string(), json!({"kind": other})),
    }
}

fn key_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("+"),
        Some(Value::String(text)) => text.clone(),
        _ => String::new(),
    }
}

fn mouse_action(desktop: &Desktop, value: &Value) -> Option<InputAction> {
    let action = value
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("move");
    // Same fraction/absolute + optional monitor mapping as inject_input.
    let resolved = crate::handlers::resolve_input_coords(desktop, action, value).ok()?;
    let x = resolved.get("x").and_then(Value::as_i64).unwrap_or(0) as i32;
    let y = resolved.get("y").and_then(Value::as_i64).unwrap_or(0) as i32;
    let button = MouseButton::parse(
        value
            .get("button")
            .and_then(Value::as_str)
            .unwrap_or("left"),
    )
    .ok()?;
    Some(match action {
        "down" => InputAction::Button {
            x,
            y,
            button,
            down: true,
        },
        "up" => InputAction::Button {
            x,
            y,
            button,
            down: false,
        },
        "click" => InputAction::Click {
            x,
            y,
            button,
            count: value.get("count").and_then(Value::as_u64).unwrap_or(1) as u32,
        },
        "scroll" => InputAction::Scroll {
            x: Some(x),
            y: Some(y),
            dx: value.get("dx").and_then(Value::as_i64).unwrap_or(0) as i32,
            dy: value.get("dy").and_then(Value::as_i64).unwrap_or(0) as i32,
        },
        _ => InputAction::Move { x, y },
    })
}

/// `down` missing keeps the tap (keydown then keyup). An explicit bool is
/// one edge, so the viewer can release a held modifier without typing again.
pub(crate) fn key_input_action(keys: Vec<String>, down: Option<bool>) -> InputAction {
    match down {
        Some(down) => InputAction::KeyEdge { keys, down },
        None => InputAction::Key { keys },
    }
}

fn string_list(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Value::String(text) => text
            .split('+')
            .map(|part| part.trim().to_string())
            .collect(),
        _ => Vec::new(),
    }
}

#[allow(dead_code)]
fn _started(built: &Built) -> Duration {
    built.started.elapsed()
}

#[cfg(test)]
mod tests {
    use super::input_allowed;
    use crate::input::InputAction;
    use agentlink_core::NodePolicy;
    use serde_json::{json, Value};

    #[test]
    fn default_scale_caps_wide_panels_only_when_unset() {
        assert_eq!(
            super::default_scale_for_width(2736, false),
            Some(1280.0 / 2736.0)
        );
        assert_eq!(super::default_scale_for_width(1920, false), None);
        assert_eq!(super::default_scale_for_width(2736, true), None);
        assert_eq!(super::default_scale_for_width(1280, false), None);
    }

    #[test]
    fn video_is_held_until_srtp_and_the_next_frame_is_an_idr() {
        assert_eq!(
            super::admit_sample(false, true, true),
            super::SampleAdmit::Hold,
            "an IDR encoded before DTLS is not written"
        );
        assert_eq!(
            super::admit_sample(true, true, false),
            super::SampleAdmit::Hold,
            "a delta after a dropped IDR is not the first picture"
        );
        assert_eq!(
            super::admit_sample(true, true, true),
            super::SampleAdmit::Send
        );
        assert_eq!(
            super::admit_sample(true, false, false),
            super::SampleAdmit::Send
        );

        let mut ready = false;
        let mut waiting = true;
        assert!(!super::media_gate_on_state(
            &mut ready,
            &mut waiting,
            super::RTCPeerConnectionState::Connecting
        ));
        assert!(!ready);
        assert!(super::media_gate_on_state(
            &mut ready,
            &mut waiting,
            super::RTCPeerConnectionState::Connected
        ));
        assert!(ready && waiting);
        assert!(!super::media_gate_on_state(
            &mut ready,
            &mut waiting,
            super::RTCPeerConnectionState::Connected
        ));
        waiting = false;
        assert!(!super::media_gate_on_state(
            &mut ready,
            &mut waiting,
            super::RTCPeerConnectionState::Disconnected
        ));
        assert!(!ready);
        assert!(super::media_gate_on_state(
            &mut ready,
            &mut waiting,
            super::RTCPeerConnectionState::Connected
        ));
        assert!(waiting, "ICE coming back asks for a new IDR");
    }

    #[test]
    fn held_presrtp_idr_is_rearmed_and_written_after_connected() {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        use crate::capture::{Frame, FrameSource, StreamMode};
        use crate::stream::encode::{Codec, EncodedAccessUnit, EncoderInfo, VideoEncoder};
        use crate::stream::pipeline::Pump;

        struct Quiet {
            frames: Vec<Frame>,
        }

        impl FrameSource for Quiet {
            fn next_frame(&mut self, _: Duration) -> crate::error::Result<Option<Frame>> {
                if self.frames.is_empty() {
                    return Ok(None);
                }
                Ok(Some(self.frames.remove(0)))
            }
            fn mode(&self) -> StreamMode {
                StreamMode::Surface {
                    backend: "quiet".into(),
                }
            }
        }

        struct Stamp;
        impl VideoEncoder for Stamp {
            fn info(&self) -> EncoderInfo {
                EncoderInfo {
                    name: "stamp".into(),
                    codec: Codec::H264,
                    hardware: false,
                }
            }
            fn encode(
                &mut self,
                frame: &Frame,
                force_keyframe: bool,
            ) -> crate::error::Result<EncodedAccessUnit> {
                Ok(EncodedAccessUnit {
                    codec: Codec::H264,
                    bytes: vec![0, 0, 0, 1, if force_keyframe { 0x65 } else { 0x41 }],
                    keyframe: force_keyframe,
                    width: frame.width,
                    height: frame.height,
                    captured_unix_ms: frame.captured_unix_ms,
                })
            }
            fn set_bitrate(&mut self, _: u32) {}
        }

        let raw = vec![4u8; 16 * 16 * 4];
        let frame = Frame::from_bgra(16, 16, 64, &raw, "quiet").unwrap();
        let mut still = frame.clone();
        still.mark_unchanged();
        let (mut pump, control) = Pump::start(
            Box::new(Quiet {
                frames: vec![frame, still.clone(), still.clone(), still.clone(), still],
            }),
            Box::new(Stamp),
            "quiet".into(),
            200_000,
        );
        let keyframe = control.keyframe.clone();

        let first = pump.next(Duration::from_millis(1)).unwrap().unwrap();
        assert!(first.keyframe, "the pump's first picture is an IDR");
        assert!(
            !keyframe.load(Ordering::Acquire),
            "emitting the IDR clears the request"
        );
        // The quiet desktop would now stay silent. That is the frames=0 hole.
        assert!(pump.next(Duration::from_millis(1)).unwrap().is_none());

        let mut ready = false;
        let mut waiting = true;
        assert!(
            super::hold_sample(ready, waiting, first.keyframe, &keyframe),
            "the pre-SRTP IDR is held, not written"
        );
        assert!(
            keyframe.load(Ordering::Acquire),
            "holding that IDR re-arms the pump"
        );

        let second = pump
            .next(Duration::from_millis(1))
            .unwrap()
            .expect("re-arm forces another IDR on an unchanged desktop");
        assert!(second.keyframe);
        assert!(
            super::hold_sample(ready, waiting, second.keyframe, &keyframe),
            "still held until the peer is connected"
        );

        assert!(super::media_gate_on_state(
            &mut ready,
            &mut waiting,
            super::RTCPeerConnectionState::Connected
        ));
        assert!(ready && waiting);
        let idr = pump.next(Duration::from_millis(1)).unwrap().unwrap();
        assert!(idr.keyframe);
        let mut written = Vec::new();
        if !super::hold_sample(ready, waiting, idr.keyframe, &keyframe) {
            written.push(idr.keyframe);
            if idr.keyframe {
                waiting = false;
            }
        }
        assert_eq!(written, vec![true], "the IDR after Connected is written");
        assert!(
            super::hold_sample(true, true, false, &keyframe),
            "a delta is still held while the sender is waiting for an IDR"
        );
        assert!(!waiting);
    }

    #[test]
    fn host_path_does_not_add_default_stun() {
        let servers = super::ice_servers(&json!({
            "ice_path": "host",
            "ice_servers": []
        }));
        assert!(servers.is_empty());
        assert_eq!(
            super::ice_transport_policy(&json!({"ice_transport_policy": "all"})),
            webrtc::peer_connection::RTCIceTransportPolicy::All
        );
    }

    #[test]
    fn relay_path_uses_offered_turn_and_relay_policy() {
        let payload = json!({
            "ice_path": "relay-udp",
            "ice_transport_policy": "relay",
            "gather_ms": 5000,
            "ice_servers": [{
                "urls": ["turn:192.0.2.10:3478"],
                "username": "agentlink",
                "credential": "replace-me"
            }]
        });
        let servers = super::ice_servers(&payload);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].urls, vec!["turn:192.0.2.10:3478".to_string()]);
        assert_eq!(
            super::ice_transport_policy(&payload),
            webrtc::peer_connection::RTCIceTransportPolicy::Relay
        );
        assert_eq!(super::wanted_typ(&payload), Some("relay"));
        assert_eq!(
            super::gather_budget(&payload, super::ice_transport_policy(&payload)).as_millis(),
            5000
        );
    }

    #[test]
    fn empty_offer_uses_the_process_stun_list() {
        let servers = super::ice_servers(&json!({}));
        let expected = agentlink_core::stun_urls_from_env();
        if expected.is_empty() {
            assert!(servers.is_empty());
        } else {
            assert_eq!(servers.len(), 1);
            assert_eq!(servers[0].urls, expected);
        }
    }

    #[test]
    fn offer_ice_servers_win_over_the_environment() {
        let servers = super::ice_servers(&json!({
            "ice_servers": [{
                "urls": ["stun:turn.example:3478"],
                "username": "agentlink",
                "credential": "replace-me"
            }]
        }));
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].urls, vec!["stun:turn.example:3478".to_string()]);
        assert_eq!(servers[0].username, "agentlink");
        assert_eq!(servers[0].credential, "replace-me");
    }

    #[test]
    fn view_only_rejects_pointer_and_keeps_session_signals() {
        let view = NodePolicy::remote_view();
        assert!(input_allowed(&view, "feedback"));
        assert!(input_allowed(&view, "keyframe"));
        assert!(!input_allowed(&view, "mouse"));
        assert!(!input_allowed(&view, "key"));
        assert!(!input_allowed(&view, "clipboard"));
        let control = NodePolicy::remote_control();
        assert!(input_allowed(&control, "mouse"));
        assert!(input_allowed(&control, "key"));
    }

    #[test]
    fn answer_control_follows_the_session_grant_not_the_ceiling() {
        let ceiling = NodePolicy::remote_control();
        assert!(ceiling.allows_remote_control());
        let view_only = super::session_allows_control(&json!({"_allow_control": false}), &ceiling);
        assert!(!view_only);
        assert!(!super::answer_control_field(view_only));
        assert!(super::answer_control_field(super::session_allows_control(
            &json!({"_allow_control": true}),
            &ceiling
        )));
        assert!(!super::answer_control_field(false));
    }

    #[test]
    fn key_down_false_is_a_release_not_another_tap() {
        let down = super::key_input_action(vec!["shift".into()], Some(true));
        let up = super::key_input_action(vec!["shift".into()], Some(false));
        let tap = super::key_input_action(vec!["a".into()], None);
        assert!(matches!(down, InputAction::KeyEdge { down: true, .. }));
        assert!(matches!(up, InputAction::KeyEdge { down: false, .. }));
        assert!(matches!(tap, InputAction::Key { .. }));
    }

    #[test]
    fn view_grant_flag_blocks_control_on_a_control_ceiling() {
        let ceiling = NodePolicy::remote_control();
        assert!(!super::session_allows_control(
            &json!({"_allow_control": false}),
            &ceiling
        ));
        assert!(super::session_allows_control(
            &json!({"_allow_control": true}),
            &ceiling
        ));
        assert!(!super::session_allows_control(
            &json!({"_allow_control": true}),
            &NodePolicy::remote_view()
        ));
        assert!(super::session_allows_control(&json!({}), &ceiling));
    }

    #[test]
    fn input_audit_keeps_a_short_preview() {
        let (detail, args) = super::input_audit("type", &json!({"text": "secret-password-value"}));
        assert!(!detail.contains("secret-password-value"));
        assert!(detail.contains("chars"));
        assert!(args.get("text").is_none());
        assert_eq!(args["chars"], 21);
        let (clip, clip_args) =
            super::input_audit("clipboard", &json!({"text": "clipboard-secret-value"}));
        assert!(!clip.contains("clipboard-secret-value"));
        assert!(clip_args.get("text").is_none());
        assert!(!format!("{clip_args}").contains("sdp"));
    }

    #[test]
    fn trickle_ice_init_parses_the_viewer_to_json_shape() {
        // webrtc-0.21 `RTCIceCandidate::to_json` uses camelCase, empty
        // `sdpMid`, m-line 0, and no usernameFragment. That is the live
        // viewer trickle shape. The library's add_remote_candidate ignores
        // mid/ufrag and only parses the candidate attribute.
        let value = json!({
            "candidate": "candidate:1 1 udp 2130706431 192.0.2.1 9 typ host",
            "sdpMid": "",
            "sdpMLineIndex": 0,
            "usernameFragment": null
        });
        let init = super::parse_trickle_candidate(&value).expect("viewer shape");
        assert_eq!(init.sdp_mid.as_deref(), Some(""));
        assert_eq!(init.sdp_mline_index, Some(0));
        assert!(init.username_fragment.is_none());
        assert_eq!(super::candidate_typ_hint(&init.candidate), "host");
    }

    #[test]
    fn trickle_ice_bare_string_or_null_is_a_parse_error() {
        // The previous ice() handler swallowed this and returned `{ok: true}`.
        let bare = json!("candidate:1 1 udp 2130706431 192.0.2.1 9 typ host");
        let err = super::parse_trickle_candidate(&bare).unwrap_err();
        assert!(
            err.contains("RTCIceCandidateInit"),
            "unexpected parse error: {err}"
        );
        let err = super::parse_trickle_candidate(&Value::Null).unwrap_err();
        assert!(
            err.contains("RTCIceCandidateInit"),
            "unexpected parse error: {err}"
        );
    }

    #[test]
    fn sdp_ice_ufrag_reads_the_attribute_and_ice_ufrag_matches_isolates_generations() {
        let sdp = "v=0\r\na=ice-ufrag:genA\r\na=ice-pwd:secret-must-not-matter\r\n";
        let ufrag = super::sdp_ice_ufrag(sdp).expect("ufrag");
        assert_eq!(ufrag, "genA");
        assert!(super::ice_ufrag_matches(Some("genA"), None));
        assert!(super::ice_ufrag_matches(Some("genA"), Some("")));
        assert!(super::ice_ufrag_matches(Some("genA"), Some("genA")));
        assert!(!super::ice_ufrag_matches(Some("genA"), Some("genB")));
        assert!(super::ice_ufrag_matches(None, Some("genB")));
    }
}
