//! One WebRTC peer per viewer. The node answers. Media is RTP; input, cursor
//! shape, and frame timestamps ride data channels the offerer opens.
//!
//! The browser page and `agentlink-view` (the Android client) are both
//! offerers on this contract. Neither one invents a second media protocol.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use agentlink_core::{
    prefer_on_link_hosts_in_candidate, prefer_on_link_hosts_in_sdp, NodePolicy,
    HOST_ACCEPTANCE_MIN_WAIT,
};
use bytes::Bytes;
use rtc::media::Sample;
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RtpCodecKind,
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
    RTCSessionDescription, Registry, SettingEngineBuilder,
};
use webrtc::rtp_transceiver::RtpSender;
use webrtc::runtime::default_runtime;

use crate::capture::{CaptureRequest, CaptureTarget, CursorCaptureMode, StreamMode};
use crate::control_indicator;
use crate::error::{msg, Result};
use crate::input::{InputAction, MouseButton};
use crate::CursorPresentation;
use crate::Desktop;

use super::audio::{ulaw, AudioCapture};
use super::encode::{open_encoder, Codec, EncoderRequest};
use super::handler::StreamAudit;
use super::pipeline::{Pump, PumpControl};
use super::tap::{self, StreamTapEvent};
use super::StreamShared;

pub const MAX_LIVE_STREAMS: usize = 4;
pub const MAX_INPUT_DC_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

pub struct SessionManager {
    desktop: Arc<Desktop>,
    shared: Arc<StreamShared>,
    sessions: Mutex<Vec<LiveSession>>,
}

struct LiveSession {
    id: String,
    stop: Arc<AtomicBool>,
    control: PumpControl,
    peer: Arc<Mutex<Option<Arc<dyn IcePeer>>>>,
    started: Instant,
    viewer: String,
    peer_id: String,
    /// Set while this session still holds a control-indicator ref.
    control_held: Arc<AtomicBool>,
    /// Keys and mouse buttons currently held by this viewer so teardown can
    /// synthesize releases if the viewer disconnects mid-chord or mid-drag.
    held_inputs: Arc<Mutex<HeldInputState>>,
    /// ICE ufrag from the current remote offer. Compared to trickle
    /// `usernameFragment` when present; never logged.
    remote_ufrag: Mutex<Option<String>>,
    /// Verified grant jti stamped by the node. Empty in direct handler tests
    /// that never went through fill_stream_grant_flags.
    grant_jti: String,
    /// Unix expiry of that grant, when known.
    grant_exp_unix: Option<i64>,
}

struct Built {
    answer: Value,
    peer: Arc<dyn IcePeer>,
    stop: Arc<AtomicBool>,
    control: PumpControl,
    channels: Arc<Mutex<ChannelSet>>,
    held_inputs: Arc<Mutex<HeldInputState>>,
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
        PeerConnection::add_ice_candidate(&self.inner, prefer_remote_ice(candidate))
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
        let offer_sdp = prefer_on_link_hosts_in_sdp(offer_sdp);
        let offer = RTCSessionDescription::offer(offer_sdp).map_err(|err| err.to_string())?;
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
        record_gathered_candidate(self.candidates.as_ref(), candidate);
    }

    async fn close(&self) {
        let _ = PeerConnection::close(&self.inner).await;
    }
}

struct ChannelSet {
    cursor: Option<Arc<dyn DataChannel>>,
    meta: Option<Arc<dyn DataChannel>>,
    input: Option<Arc<dyn DataChannel>>,
    clipboard: Arc<Mutex<crate::clipboard::ClipboardWatchState>>,
}

const AIMD_IDR_COOLDOWN: Duration = Duration::from_secs(1);
const MONITOR_CACHE_TTL: Duration = Duration::from_secs(2);
const INJECT_ERROR_COOLDOWN: Duration = Duration::from_secs(1);

/// AIMD bitrate adaptation state shared with the input data-channel handler.
#[derive(Clone)]
struct AimdState {
    /// Minimum bitrate floor derived from the offer bitrate so low-bitrate
    /// mobile offers (< 800 kbps) are never clamped upward on packet loss.
    min_bitrate: u32,
    max_bitrate: u32,
    /// Instant of the last feedback sample with loss > 2%.
    last_loss_at: Arc<Mutex<Option<Instant>>>,
    /// Instant of the last AIMD-triggered IDR request (throttled to >= 1s).
    last_idr_at: Arc<Mutex<Option<Instant>>>,
    /// Instant when the current "no loss" streak began.
    quiet_since: Arc<Mutex<Option<Instant>>>,
}

impl AimdState {
    fn new(offer_bitrate: u32) -> Self {
        let min_bitrate = (offer_bitrate / 2).clamp(100_000, 800_000);
        let max_bitrate = offer_bitrate.clamp(8_000_000, 12_000_000);
        Self {
            min_bitrate,
            max_bitrate,
            last_loss_at: Arc::new(Mutex::new(None)),
            last_idr_at: Arc::new(Mutex::new(None)),
            quiet_since: Arc::new(Mutex::new(None)),
        }
    }
}

fn apply_aimd_feedback(
    aimd: &AimdState,
    current: u32,
    loss: f64,
    now: Instant,
) -> (u32, bool) {
    let mut next = current;
    let mut request_idr = false;
    if loss > 0.02 {
        next = (current as f32 * 0.8) as u32;
        if let Ok(mut slot) = aimd.last_loss_at.lock() {
            *slot = Some(now);
        }
        if let Ok(mut slot) = aimd.quiet_since.lock() {
            *slot = None;
        }
        if let Ok(mut last_idr) = aimd.last_idr_at.lock() {
            let can_idr = last_idr
                .map(|t| now.saturating_duration_since(t) >= AIMD_IDR_COOLDOWN)
                .unwrap_or(true);
            if can_idr {
                *last_idr = Some(now);
                request_idr = true;
            }
        }
    } else {
        let quiet_for = {
            let mut quiet = aimd.quiet_since.lock().unwrap_or_else(|e| e.into_inner());
            let since = quiet.get_or_insert(now);
            now.saturating_duration_since(*since)
        };
        if quiet_for >= Duration::from_secs(2) {
            next = (current as f32 * 1.1) as u32;
            if let Ok(mut slot) = aimd.quiet_since.lock() {
                *slot = Some(now);
            }
        }
    }
    (next.clamp(aimd.min_bitrate, aimd.max_bitrate), request_idr)
}

/// Depth-2 encode→RTP outbox that preserves unsent IDRs and intact P-frame
/// chains under backpressure.
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

    /// Returns `true` when a non-IDR frame had to be dropped due to backpressure
    /// so the caller should re-arm a keyframe for the next encoded picture.
    fn push(&self, unit: super::encode::EncodedAccessUnit) -> bool {
        let mut q = self.slots.lock().unwrap_or_else(|err| err.into_inner());
        let mut needs_keyframe = false;
        if unit.keyframe {
            // A fresh IDR supersedes every older queued frame cleanly.
            let stale = q.len() as u64;
            if stale > 0 {
                q.clear();
                self.dropped.fetch_add(stale, Ordering::Relaxed);
            }
            q.push_back((unit, Instant::now()));
        } else if q.len() >= self.cap {
            // Never evict an unsent IDR or break an already-queued reference
            // chain for a newer delta; drop the incoming delta and request an
            // IDR so the next frame starts a clean reference chain.
            self.dropped.fetch_add(1, Ordering::Relaxed);
            needs_keyframe = true;
        } else {
            q.push_back((unit, Instant::now()));
        }
        self.notify.notify_one();
        needs_keyframe
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

/// Tracks keys and mouse buttons currently held down by one remote control
/// session so disconnect/close/revocation never leaves stuck host inputs.
#[derive(Default)]
struct HeldInputState {
    keys: Vec<String>,
    buttons: Vec<MouseButton>,
    last_pos: (i32, i32),
}

impl HeldInputState {
    fn record(&mut self, action: &InputAction) {
        match action {
            InputAction::KeyEdge { keys, down: true } => {
                for key in keys {
                    if !key.is_empty()
                        && !self.keys.iter().any(|k| k.eq_ignore_ascii_case(key))
                    {
                        self.keys.push(key.clone());
                    }
                }
            }
            InputAction::KeyEdge { keys, down: false } => {
                for key in keys {
                    self.keys.retain(|k| !k.eq_ignore_ascii_case(key));
                }
            }
            InputAction::Button {
                x,
                y,
                button,
                down: true,
            } => {
                self.last_pos = (*x, *y);
                if !self.buttons.contains(button) {
                    self.buttons.push(*button);
                }
            }
            InputAction::Button {
                x,
                y,
                button,
                down: false,
            } => {
                self.last_pos = (*x, *y);
                self.buttons.retain(|b| b != button);
            }
            InputAction::Move { x, y } | InputAction::Click { x, y, .. } => {
                self.last_pos = (*x, *y);
            }
            _ => {}
        }
    }

    fn drain_release_actions(&mut self) -> Vec<InputAction> {
        let (x, y) = self.last_pos;
        let mut out = Vec::with_capacity(self.buttons.len() + self.keys.len());
        for button in self.buttons.drain(..) {
            out.push(InputAction::Button {
                x,
                y,
                button,
                down: false,
            });
        }
        while let Some(key) = self.keys.pop() {
            out.push(InputAction::KeyEdge {
                keys: vec![key],
                down: false,
            });
        }
        out
    }
}

fn release_held_inputs(desktop: &Arc<Desktop>, held: &Arc<Mutex<HeldInputState>>) {
    let actions = {
        let mut guard = held.lock().unwrap_or_else(|e| e.into_inner());
        guard.drain_release_actions()
    };
    if actions.is_empty() {
        return;
    }
    let desktop = desktop.clone();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn_blocking(move || {
            for action in actions {
                let _ = desktop.hid.inject(&action);
            }
        });
    } else {
        for action in actions {
            let _ = desktop.hid.inject(&action);
        }
    }
}

#[derive(Default)]
struct MonitorCache {
    cached: Mutex<Option<(Instant, Vec<crate::capture::MonitorInfo>)>>,
}

impl MonitorCache {
    fn get_or_refresh(&self, desktop: &Desktop) -> Vec<crate::capture::MonitorInfo> {
        let now = Instant::now();
        {
            let guard = self.cached.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, monitors)) = guard.as_ref() {
                if now.saturating_duration_since(*at) < MONITOR_CACHE_TTL {
                    return monitors.clone();
                }
            }
        }
        let monitors = desktop.capture.list_monitors().unwrap_or_default();
        if !monitors.is_empty() {
            let mut guard = self.cached.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some((now, monitors.clone()));
        }
        monitors
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
    /// Explicit monitor index selected by the offer, if any; used as the
    /// default monitor for fractional pointer coordinates that omit `monitor`.
    default_monitor: Option<u32>,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
    /// Set once ICE and DTLS are both up, which is when the SRTP contexts exist.
    media_ready: Arc<AtomicBool>,
    /// Drop delta frames until an IDR is actually written. The first IDR is
    /// often encoded while SRTP is still empty and the stack discards it.
    wait_idr: Arc<AtomicBool>,
    aimd: AimdState,
    clipboard: Arc<Mutex<crate::clipboard::ClipboardWatchState>>,
    held_inputs: Arc<Mutex<HeldInputState>>,
    monitor_cache: Arc<MonitorCache>,
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
            "ice_restart" => self.ice_restart(peer, payload).await,
            "ice" => self.ice(peer, payload).await,
            "ice_pull" => self.ice_pull(peer, payload),
            "keyframe" => self.keyframe(peer, payload),
            "close" => self.close(peer, payload).await,
            other => Err(format!("unknown webrtc_signal action '{other}'")),
        }
    }

    fn require_remote_view(&self) -> std::result::Result<(), String> {
        let policy = *self
            .shared
            .policy
            .read()
            .map_err(|_| "node policy is unavailable".to_string())?;
        if !policy.allows_remote_view() {
            return Err("remote_view is not allowed on this node".into());
        }
        Ok(())
    }

    /// Peer ownership plus verified grant jti/expiry. Ceiling is still
    /// required. A revoked or expired grant stops the session even when the
    /// node ceiling is still `full`.
    fn require_session_grant(
        &self,
        peer: &str,
        session_id: &str,
        stop_if_dead: bool,
    ) -> std::result::Result<(), String> {
        self.require_remote_view()?;
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let Some(index) = sessions.iter().position(|session| session.id == session_id) else {
            return Err("unknown stream session".into());
        };
        if sessions[index].peer_id != peer || sessions[index].stop.load(Ordering::Relaxed) {
            return Err("unknown stream session".into());
        }
        let err = session_grant_error(&self.shared, &sessions[index], peer);
        if let Some(err) = err {
            if stop_if_dead {
                sessions[index].stop.store(true, Ordering::Relaxed);
            }
            return Err(err);
        }
        Ok(())
    }

    /// Close every live session whose grant jti is on the deny-list.
    pub async fn close_sessions_for_jti(&self, jti: &str) -> usize {
        let jti = jti.trim();
        if jti.is_empty() {
            return 0;
        }
        let ids: Vec<String> = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions
                .iter()
                .filter(|session| session.grant_jti.trim().eq_ignore_ascii_case(jti))
                .map(|session| session.id.clone())
                .collect()
        };
        let n = ids.len();
        for id in ids {
            let _ = self.close_owned(&json!({"session_id": id}), None).await;
        }
        n
    }

    pub async fn close_expired_sessions(&self) -> usize {
        let now = agentlink_core::util::unix_now();
        let ids: Vec<String> = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions
                .iter()
                .filter(|session| session.grant_exp_unix.is_some_and(|exp| now >= exp))
                .map(|session| session.id.clone())
                .collect()
        };
        let n = ids.len();
        for id in ids {
            let _ = self.close_owned(&json!({"session_id": id}), None).await;
        }
        n
    }

    /// Walk live sessions by stored grant metadata (jti/expiry + hook), not
    /// by an inflight-RPC index. Revoking one jti leaves other grants up.
    pub async fn close_inactive_sessions(&self) -> usize {
        let ids: Vec<String> = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions
                .iter()
                .filter(|session| {
                    session_grant_error(&self.shared, session, &session.peer_id).is_some()
                })
                .map(|session| session.id.clone())
                .collect()
        };
        let n = ids.len();
        for id in ids {
            let _ = self.close_owned(&json!({"session_id": id}), None).await;
        }
        n
    }

    /// Stop every live media session. Used when the relay link drops so a
    /// media pump cannot outlive the node session.
    pub async fn close_all_sessions(&self) -> usize {
        let ids: Vec<String> = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions.iter().map(|session| session.id.clone()).collect()
        };
        let n = ids.len();
        for id in ids {
            let _ = self.close_owned(&json!({"session_id": id}), None).await;
        }
        n
    }

    /// Test helper: record a live session with grant metadata so the
    /// production grant watcher can close it without a real SDP offer.
    pub fn insert_test_grant_session(&self, id: &str, peer: &str, jti: &str, exp: Option<i64>) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.push(LiveSession {
            id: id.to_string(),
            stop: Arc::new(AtomicBool::new(false)),
            control: crate::stream::pipeline::PumpControl::default(),
            peer: Arc::new(Mutex::new(None)),
            started: std::time::Instant::now(),
            viewer: "viewer".into(),
            peer_id: peer.to_string(),
            control_held: Arc::new(AtomicBool::new(false)),
            held_inputs: Arc::new(Mutex::new(HeldInputState::default())),
            remote_ufrag: Mutex::new(None),
            grant_jti: jti.to_string(),
            grant_exp_unix: exp,
        });
    }

    pub fn test_session_is_live(&self, id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.iter().any(|session| {
            session.id == id && !session.stop.load(std::sync::atomic::Ordering::SeqCst)
        })
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
            .map_err(|_| "node policy is unavailable".to_string())?;
        if !policy.allows_remote_view() {
            return Err("remote_view is not allowed on this node".into());
        }
        let _ = self.started_cleanup();
        {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            if sessions.len() >= MAX_LIVE_STREAMS {
                return Err(format!(
                    "too many concurrent desktop stream sessions (limit {MAX_LIVE_STREAMS})"
                ));
            }
        }
        let viewer = payload
            .get("viewer")
            .and_then(Value::as_str)
            .unwrap_or(peer)
            .to_string();
        let session_hint = super::consent::offer_consent_id(peer);
        let consent = super::consent::read_consent_mode(&self.shared.consent)?;
        let audit_path = self
            .shared
            .audit_path
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        super::consent::approve_async(consent, &audit_path, &viewer, &session_hint).await?;
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
            built.channels.clone(),
            built.stop.clone(),
            built.control.clone(),
        );
        if built.allow_control {
            spawn_clipboard(built.channels, built.stop.clone());
        }
        let control_held = Arc::new(AtomicBool::new(false));
        if built.allow_control {
            control_held.store(true, Ordering::SeqCst);
            control_indicator::note_control_session(true);
        }
        // When the peer fails/closes, drop the indicator and release any held
        // inputs even if the viewer never sends webrtc_signal close.
        {
            let stop = built.stop.clone();
            let held = control_held.clone();
            let desktop = self.desktop.clone();
            let held_inputs = built.held_inputs.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                release_held_inputs(&desktop, &held_inputs);
                if held.swap(false, Ordering::SeqCst) {
                    control_indicator::note_control_session(false);
                }
            });
        }
        let overflow_peer = {
            let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions.retain(|session| {
                let alive = !session.stop.load(Ordering::Relaxed);
                if !alive {
                    release_held_inputs(&self.desktop, &session.held_inputs);
                    if session.control_held.swap(false, Ordering::SeqCst) {
                        control_indicator::note_control_session(false);
                    }
                }
                alive
            });
            if sessions.len() >= MAX_LIVE_STREAMS {
                built.stop.store(true, Ordering::Relaxed);
                release_held_inputs(&self.desktop, &built.held_inputs);
                if control_held.swap(false, Ordering::SeqCst) {
                    control_indicator::note_control_session(false);
                }
                Some(built.peer)
            } else {
                sessions.push(LiveSession {
                    id,
                    stop: built.stop,
                    control: built.control,
                    peer: Arc::new(Mutex::new(Some(built.peer))),
                    started: built.started,
                    viewer,
                    peer_id: peer.to_string(),
                    control_held,
                    held_inputs: built.held_inputs,
                    remote_ufrag: Mutex::new(sdp_ice_ufrag(
                        payload.get("sdp").and_then(Value::as_str).unwrap_or(""),
                    )),
                    grant_jti: payload_grant_jti(payload),
                    grant_exp_unix: payload_grant_exp(payload),
                });
                None
            }
        };
        if let Some(peer_to_close) = overflow_peer {
            peer_to_close.close().await;
            return Err(format!(
                "too many concurrent desktop stream sessions (limit {MAX_LIVE_STREAMS})"
            ));
        }
        // Re-check after insert: a revoke/expiry that landed while the answer
        // was being built must still tear the session down.
        if let Some(err) = grant_still_active(
            &self.shared,
            &payload_grant_jti(payload),
            payload_grant_exp(payload),
            peer,
        ) {
            let _ = self
                .close_owned(&json!({"session_id": built.answer["session_id"]}), None)
                .await;
            return Err(err);
        }
        let _ = self.started_cleanup();
        Ok(built.answer)
    }

    fn started_cleanup(&self) -> bool {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|session| {
            let alive = !session.stop.load(Ordering::Relaxed);
            if !alive {
                release_held_inputs(&self.desktop, &session.held_inputs);
                if session.control_held.swap(false, Ordering::SeqCst) {
                    control_indicator::note_control_session(false);
                }
            }
            alive
        });
        true
    }

    async fn ice_restart(&self, peer: &str, payload: &Value) -> std::result::Result<Value, String> {
        let id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let sdp = payload.get("sdp").and_then(Value::as_str).unwrap_or("");
        if sdp.is_empty() {
            return Err("ice_restart requires an offer sdp".into());
        }
        self.require_session_grant(peer, id, true)?;
        let ice_peer = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions
                .iter()
                .find(|session| session.id == id && session.peer_id == peer)
                .and_then(|session| {
                    session
                        .peer
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone()
                })
        };
        let Some(peer) = ice_peer else {
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

    fn ice_pull(&self, peer: &str, payload: &Value) -> std::result::Result<Value, String> {
        let id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        self.require_session_grant(peer, id, true)?;
        let after = payload.get("after").and_then(Value::as_u64).unwrap_or(0) as usize;
        // Closed, unknown, and other-peer sessions all look the same so a
        // caller cannot inventory someone else's candidate list.
        let (candidates, gather_done, closed) = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            match sessions.iter().find(|session| session.id == id) {
                Some(session) if session.stop.load(Ordering::Relaxed) => (Vec::new(), true, true),
                Some(session) if session.peer_id != peer => {
                    return Err("unknown stream session".into());
                }
                Some(session) => session
                    .peer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|ice| (ice.gathered_candidates(), ice.gather_done(), false))
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

    async fn ice(&self, peer: &str, payload: &Value) -> std::result::Result<Value, String> {
        let id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        self.require_session_grant(peer, id, true)?;
        let candidate = payload.get("candidate").cloned().unwrap_or(Value::Null);
        let typ_hint = candidate
            .get("candidate")
            .and_then(Value::as_str)
            .map(candidate_typ_hint)
            .unwrap_or("unknown");
        eprintln!("agentlink live-webrtc: ice recv typ={typ_hint}");
        let (ice, remote_ufrag, closed) = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            match sessions.iter().find(|session| session.id == id) {
                Some(session) if session.stop.load(Ordering::Relaxed) => (None, None, true),
                Some(session) if session.peer_id != peer => {
                    return Err("unknown stream session".into());
                }
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
        let Some(ice) = ice else {
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
        ice.add_ice_candidate(init)
            .await
            .map_err(|err| err.to_string())?;
        // typ / mid emptiness / m-line only — never ufrag, password, or token.
        eprintln!(
            "agentlink live-webrtc: ice added typ={typ} sdpMid_empty={mid_empty} sdpMLineIndex={mline:?}"
        );
        Ok(json!({"ok": true, "added": true}))
    }

    fn keyframe(&self, peer: &str, payload: &Value) -> std::result::Result<Value, String> {
        let id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        self.require_session_grant(peer, id, true)?;
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = sessions
            .iter()
            .find(|session| session.id == id && session.peer_id == peer)
        {
            session.control.keyframe.store(true, Ordering::Relaxed);
        }
        Ok(json!({"ok": true}))
    }

    async fn close(&self, peer: &str, payload: &Value) -> std::result::Result<Value, String> {
        self.close_owned(payload, Some(peer)).await
    }

    async fn close_owned(
        &self,
        payload: &Value,
        peer: Option<&str>,
    ) -> std::result::Result<Value, String> {
        let id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Some(peer) = peer {
            // Revoke/expiry teardown uses close_owned(..., None) and does not
            // re-check the (already revoked) grant.
            self.require_session_grant(peer, id, true)?;
        }
        let session = {
            let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            let index = sessions.iter().position(|session| {
                session.id == id && peer.map(|peer| session.peer_id == peer).unwrap_or(true)
            });
            index.map(|index| sessions.remove(index))
        };
        if let Some(session) = session {
            session.stop.store(true, Ordering::Relaxed);
            release_held_inputs(&self.desktop, &session.held_inputs);
            if session.control_held.swap(false, Ordering::SeqCst) {
                control_indicator::note_control_session(false);
            }
            let peer_to_close = {
                session
                    .peer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
            };
            if let Some(peer) = peer_to_close {
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

/// Production stream session id. Always a random UUID v4, never a peer
/// name, timestamp, or client-supplied request id.
pub(crate) fn new_stream_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
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
    let default_monitor = payload
        .get("monitor")
        .and_then(Value::as_u64)
        .map(|m| m as u32);
    let monitor = default_monitor.unwrap_or(0);
    let scale_specified = payload.get("scale").is_some();
    let mut scale = payload
        .get("scale")
        .and_then(Value::as_f64)
        .unwrap_or(1.0)
        .clamp(0.05, 1.0) as f32;
    // Cap default scale on wide (>1920px) panels when the viewer omitted `scale`,
    // while honoring any explicit scale requested by the client.
    let mut native_w = 0u32;
    let mut native_h = 0u32;
    if let Ok(monitors) = desktop.capture.list_monitors() {
        let chosen = if default_monitor.is_some() {
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
        if let Some(capped) = default_scale_for_width(native_w, scale_specified) {
            scale = capped;
            tracing::info!(
                native_width = native_w,
                scale,
                cap = ENCODE_WIDTH_CAP,
                "capture wider than encode cap and scale unset; defaulting scale = cap/width"
            );
        }
    }
    let audio = payload
        .get("audio")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let session_id = new_stream_session_id();
    let _ = (peer_id, &SESSION_SEQ);

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
    let viewer_wants_metadata = payload
        .get("cursor_mode")
        .and_then(Value::as_str)
        .map(|m| m.eq_ignore_ascii_case("metadata"))
        .unwrap_or(false);
    let exclude_capable = desktop.capture.cursor_exclude_supported();
    let capture_request = CaptureRequest {
        target: if payload.get("monitor").is_some() {
            CaptureTarget::Monitor(monitor)
        } else {
            CaptureTarget::FullScreen
        },
        scale: 1.0,
        max_fps: fps as f32,
        max_width: capture_max_width,
        // Open a per-session Mutter metadata stream only when the viewer asks
        // and the backend can exclude. Failure falls back to embedded below.
        cursor_mode: if viewer_wants_metadata && exclude_capable {
            CursorCaptureMode::Metadata
        } else {
            CursorCaptureMode::Embedded
        },
    };
    let probe = desktop.capture.capture(&CaptureRequest {
        cursor_mode: CursorCaptureMode::Embedded,
        ..capture_request.clone()
    })?;
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
    let frame_source = desktop.capture.open_session(&capture_request)?;
    let session_cursor_excluded = matches!(
        frame_source.mode(),
        StreamMode::PipeWire {
            cursor_excluded: true,
            ..
        }
    );
    let (mut pump, control) = Pump::start(frame_source, encoder, session_id.clone(), bitrate);
    control.capture_w.store(capture_w, Ordering::Relaxed);
    control.capture_h.store(capture_h, Ordering::Relaxed);
    control.encode_w.store(encode_w, Ordering::Relaxed);
    control.encode_h.store(encode_h, Ordering::Relaxed);
    let width = encode_w;
    let height = encode_h;
    let _ = probe;

    let runtime = default_runtime().ok_or_else(|| msg("tokio runtime is required for WebRTC"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let clipboard = Arc::new(Mutex::new(crate::clipboard::ClipboardWatchState::new()));
    let channels = Arc::new(Mutex::new(ChannelSet {
        cursor: None,
        meta: None,
        input: None,
        clipboard: clipboard.clone(),
    }));
    let policy_now = *shared
        .policy
        .read()
        .map_err(|_| msg("node policy is unavailable"))?;
    let held_inputs = Arc::new(Mutex::new(HeldInputState::default()));
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
        default_monitor,
        grant_jti: payload_grant_jti(payload),
        grant_exp_unix: payload_grant_exp(payload),
        media_ready: Arc::new(AtomicBool::new(false)),
        wait_idr: Arc::new(AtomicBool::new(true)),
        aimd: AimdState::new(bitrate),
        clipboard: clipboard.clone(),
        held_inputs: held_inputs.clone(),
        monitor_cache: Arc::new(MonitorCache::default()),
    });
    let audio_capture = if audio { AudioCapture::start() } else { None };
    let ice = resolve_ice_servers(payload).await;
    let policy = ice_transport_policy(payload);
    let gather_for = gather_budget(payload, policy);
    let want = wanted_typ(payload).map(str::to_string);
    let mut pc_opt = None;
    let mut bind_err = None;
    for udp_addrs in [
        vec!["[::]:0".to_string(), "0.0.0.0:0".to_string()],
        vec!["0.0.0.0:0".to_string()],
    ] {
        let mut media = MediaEngine::default();
        media
            .register_codec(video_codec(&info.codec), RtpCodecKind::Video)
            .map_err(|err| msg(err.to_string()))?;
        if audio_capture.is_some() {
            media
                .register_codec(pcmu_codec(), RtpCodecKind::Audio)
                .map_err(|err| msg(err.to_string()))?;
        }
        let registry = register_default_interceptors(Registry::new(), &mut media)
            .map_err(|err| msg(err.to_string()))?;
        let setting_engine = SettingEngineBuilder::new()
            .with_host_acceptance_min_wait(Some(HOST_ACCEPTANCE_MIN_WAIT))
            .build();
        match PeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(ice.clone())
                    .with_ice_transport_policy(policy)
                    .build(),
            )
            .with_setting_engine(setting_engine)
            .with_media_engine(media)
            .with_interceptor_registry(registry)
            .with_handler(handler.clone() as Arc<dyn PeerConnectionEventHandler>)
            .with_runtime(runtime.clone())
            .with_udp_addrs(udp_addrs.clone())
            .build()
            .await
        {
            Ok(built) => {
                pc_opt = Some(built);
                break;
            }
            Err(err) => {
                tracing::debug!(
                    ?udp_addrs,
                    error = %err,
                    "peer connection UDP bind failed; trying fallback address set"
                );
                bind_err = Some(err);
            }
        }
    }
    let pc = pc_opt.ok_or_else(|| {
        msg(bind_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "failed to build peer connection".into()))
    })?;

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

    let sdp = prefer_on_link_hosts_in_sdp(&sdp);
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
    // Depth 2: preserve unsent IDRs and intact P-frame chains under backpressure.
    let outbox = FrameOutbox::new(2);
    let outbox_prod = outbox.clone();
    let control_prod = control.clone();
    std::thread::Builder::new()
        .name("agentlink-stream".into())
        .spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match pump.next(Duration::from_secs(2)) {
                    Ok(Some(unit)) => {
                        let needs_keyframe = outbox_prod.push(unit);
                        if needs_keyframe {
                            control_prod.keyframe.store(true, Ordering::Release);
                        }
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

    // Cursor presentation: default legacy. Metadata only when the viewer asked
    // AND this session actually opened an exclude/metadata capture stream —
    // never advertise Metadata on a warn-only double-cursor path.
    // Caps.exclude reflects backend capability (Mutter can open mode 2);
    // presentation reflects the live session outcome.
    let cursor_caps = crate::CursorCaps {
        shape: true,
        visible: true,
        hotspot: true,
        exclude: exclude_capable,
    };
    // Reality gate: Metadata only after an exclude stream is live for *this*
    // session. caps.exclude may still be true (Mutter can open mode 2) so the
    // next offer can retry; presentation must not lie about the current peer.
    let cursor_presentation = if viewer_wants_metadata && session_cursor_excluded {
        CursorPresentation::Metadata
    } else {
        CursorPresentation::Legacy
    };

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
            // True content size before macroblock pad (viewer hotspot / fraction).
            "src_width": src_w,
            "src_height": src_h,
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
            "cursor_caps": cursor_caps,
            "cursor_presentation": cursor_presentation,
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
        held_inputs,
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
            // Additive fields only — old viewers that read x/y(/shape) keep working.
            let mut payload = json!({
                "x": cursor.x,
                "y": cursor.y,
                "shape": cursor.shape,
                "visible": visible,
                "hotspot_x": cursor.hotspot_x,
                "hotspot_y": cursor.hotspot_y,
            });
            if let Some(rgba) = cursor.bitmap_rgba.as_ref() {
                if cursor.bitmap_w > 0
                    && cursor.bitmap_h > 0
                    && crate::bitmap_within_bound(cursor.bitmap_w, cursor.bitmap_h)
                {
                    use base64::Engine;
                    payload["bitmap_w"] = json!(cursor.bitmap_w);
                    payload["bitmap_h"] = json!(cursor.bitmap_h);
                    payload["bitmap_rgba_b64"] =
                        json!(base64::engine::general_purpose::STANDARD.encode(rgba));
                }
            }
            let text = payload.to_string();
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

fn spawn_clipboard(channels: Arc<Mutex<ChannelSet>>, stop: Arc<AtomicBool>) {
    tokio::spawn(async move {
        // Seed clipboard baseline on session start so pre-existing clipboard
        // contents (passwords, OTPs) are never pushed automatically on connect.
        let initial_clip = {
            let set = channels.lock().unwrap_or_else(|err| err.into_inner());
            set.clipboard.clone()
        };
        let _ = tokio::task::spawn_blocking(move || {
            let mut state = initial_clip.lock().unwrap_or_else(|err| err.into_inner());
            state.seed_from_os();
        })
        .await;

        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(crate::clipboard::CLIPBOARD_POLL_INTERVAL).await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let (clip_state, input) = {
                let set = channels.lock().unwrap_or_else(|err| err.into_inner());
                (set.clipboard.clone(), set.input.clone())
            };
            let Some(input) = input else {
                continue;
            };
            let poll_state = clip_state.clone();
            let outgoing = tokio::task::spawn_blocking(move || {
                let mut state = poll_state.lock().unwrap_or_else(|err| err.into_inner());
                state.poll_outgoing()
            })
            .await
            .ok()
            .flatten();
            let Some(clip) = outgoing else {
                continue;
            };
            let body = crate::clipboard::set_payload(&clip).to_string();
            if input.send_text(&body).await.is_err() {
                if let Ok(mut state) = clip_state.lock() {
                    state.send_failed();
                }
            }
        }
    });
}

/// Encode-width target for panels wider than 1920 (Retina/4K) when the viewer
/// omits `scale`. Explicit `scale` values are honored; <=1920 native is left alone.
const ENCODE_WIDTH_CAP: f32 = 1920.0;

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
/// Any hold — whether before SRTP is ready or while waiting for an IDR after
/// Connected/write-error — re-arms `keyframe` so a quiet desktop does not stay
/// stuck waiting for an IDR forever.
fn hold_sample(
    srtp_ready: bool,
    waiting_for_idr: bool,
    unit_keyframe: bool,
    keyframe: &AtomicBool,
) -> bool {
    if admit_sample(srtp_ready, waiting_for_idr, unit_keyframe) != SampleAdmit::Hold {
        return false;
    }
    keyframe.store(true, Ordering::Release);
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
            rtcp_feedback: vec![
                RTCPFeedback {
                    typ: "nack".into(),
                    parameter: String::new(),
                },
                RTCPFeedback {
                    typ: "nack".into(),
                    parameter: "pli".into(),
                },
                RTCPFeedback {
                    typ: "ccm".into(),
                    parameter: "fir".into(),
                },
            ],
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

fn parse_offered_ice_servers(payload: &Value) -> Vec<RTCIceServer> {
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
    servers
}

#[cfg(test)]
fn ice_servers(payload: &Value) -> Vec<RTCIceServer> {
    let mut servers = parse_offered_ice_servers(payload);
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

async fn resolve_ice_servers(payload: &Value) -> Vec<RTCIceServer> {
    let mut servers = parse_offered_ice_servers(payload);
    // An explicit ice_path means the viewer chose this attempt's servers,
    // including an empty list for host-only. Do not add default STUN on top.
    if servers.is_empty() && payload.get("ice_path").is_none() {
        let urls = tokio::task::spawn_blocking(agentlink_core::stun_urls_ready_for_ice)
            .await
            .unwrap_or_else(|_| agentlink_core::stun_urls_from_env());
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

/// Raise on-link physical LAN host priority on a remote ICE candidate string.
/// Overlay/`100.x`/srflx/relay stay present — preference only, never a filter.
fn prefer_remote_ice(
    mut init: rtc::peer_connection::transport::RTCIceCandidateInit,
) -> rtc::peer_connection::transport::RTCIceCandidateInit {
    if !init.candidate.is_empty() {
        init.candidate = prefer_on_link_hosts_in_candidate(&init.candidate);
    }
    init
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
// Bound: a missing usernameFragment is admitted so current viewers that omit
// ufrag still attach to the session they already own. Isolation is peer +
// session_id, not ufrag alone. A later generation with a different ufrag is
// rejected when both sides present one.
fn ice_ufrag_matches(remote_ufrag: Option<&str>, fragment: Option<&str>) -> bool {
    match (remote_ufrag, fragment) {
        (Some(want), Some(got)) if !got.is_empty() => want == got,
        _ => true,
    }
}

/// Upper bound on remembered local candidates for one session.
/// Typical gathers here are around a dozen host+srflx lines; this caps
/// inject/retry growth. It is not a network or NAT claim.
pub(crate) const MAX_GATHERED_CANDIDATES: usize = 32;

fn record_gathered_candidate(candidates: &std::sync::Mutex<Vec<Value>>, value: Value) {
    let line = value
        .get("candidate")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let typ = candidate_typ_hint(&line);
    let mut queue = candidates.lock().unwrap_or_else(|err| err.into_inner());
    if !line.is_empty()
        && queue.iter().any(|existing| {
            existing.get("candidate").and_then(Value::as_str) == Some(line.as_str())
        })
    {
        return;
    }
    if queue.len() >= MAX_GATHERED_CANDIDATES {
        eprintln!("agentlink live-webrtc: gathered candidate queue full typ={typ}");
        return;
    }
    queue.push(value);
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
                record_gathered_candidate(self.candidates.as_ref(), value);
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
            RTCPeerConnectionState::Disconnected
                | RTCPeerConnectionState::Failed
                | RTCPeerConnectionState::Closed
        ) {
            release_held_inputs(&self.desktop, &self.held_inputs);
        }
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
            "input" => {
                self.channels
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .input = Some(channel.clone());
            }
            _ => {
                if label.is_empty() {
                    self.channels
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .input = Some(channel.clone());
                }
            }
        }
        let policy = self.policy.clone();
        let desktop = self.desktop.clone();
        let control = self.control.clone();
        let shared = self.shared.clone();
        let peer = self.peer.clone();
        let session_id = self.session_id.clone();
        let allow_control = self.allow_control;
        let default_monitor = self.default_monitor;
        let grant_jti = self.grant_jti.clone();
        let grant_exp_unix = self.grant_exp_unix;
        let aimd = self.aimd.clone();
        let stop = self.stop.clone();
        let clipboard = self.clipboard.clone();
        let held_inputs = self.held_inputs.clone();
        let monitor_cache = self.monitor_cache.clone();
        let last_inject_err = Arc::new(Mutex::new(None::<Instant>));
        let input = label == "input" || label.is_empty();
        tokio::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match channel.poll().await {
                    Some(DataChannelEvent::OnMessage(message)) => {
                        if !input || message.data.len() > MAX_INPUT_DC_MESSAGE_BYTES {
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
                            default_monitor,
                            &grant_jti,
                            grant_exp_unix,
                            &aimd,
                            &stop,
                            &clipboard,
                            &held_inputs,
                            &monitor_cache,
                            &last_inject_err,
                        )
                        .await;
                    }
                    Some(DataChannelEvent::OnClose) | None => break,
                    _ => {}
                }
            }
            if input {
                release_held_inputs(&desktop, &held_inputs);
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_input(
    text: &str,
    desktop: &Arc<Desktop>,
    policy: &RwLock<NodePolicy>,
    control: &PumpControl,
    channel: &Arc<dyn DataChannel>,
    shared: &StreamShared,
    peer: &str,
    session_id: &str,
    allow_control: bool,
    default_monitor: Option<u32>,
    grant_jti: &str,
    grant_exp_unix: Option<i64>,
    aimd: &AimdState,
    stop: &AtomicBool,
    clipboard: &Arc<Mutex<crate::clipboard::ClipboardWatchState>>,
    held_inputs: &Arc<Mutex<HeldInputState>>,
    monitor_cache: &Arc<MonitorCache>,
    last_inject_err: &Arc<Mutex<Option<Instant>>>,
) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };
    if let Some(err) = grant_still_active(shared, grant_jti, grant_exp_unix, peer) {
        // Same teardown as a revoked/expired signaling call: release any held
        // inputs and stop the media pump.
        release_held_inputs(desktop, held_inputs);
        stop.store(true, Ordering::Relaxed);
        let body = json!({"type": "error", "error": err}).to_string();
        let _ = channel.send_text(&body).await;
        return;
    }
    let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
    if kind == "feedback" {
        if let Some(loss) = value.get("loss").and_then(Value::as_f64) {
            let current = control.bitrate.load(Ordering::Relaxed);
            let (next, request_idr) = apply_aimd_feedback(aimd, current, loss, Instant::now());
            control.bitrate.store(next, Ordering::Relaxed);
            if request_idr {
                control.keyframe.store(true, Ordering::Release);
            }
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
    if !allowed {
        let (detail, mut args) = input_audit(kind, &value);
        if let Some(obj) = args.as_object_mut() {
            obj.insert("session".into(), json!(session_id));
        }
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
    if should_audit_input(kind, &value) {
        let (detail, mut args) = input_audit(kind, &value);
        if let Some(obj) = args.as_object_mut() {
            obj.insert("session".into(), json!(session_id));
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
    }
    let action = match kind {
        "mouse" => mouse_action(desktop, monitor_cache, default_monitor, &value),
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
                    let clipboard = clipboard.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let result = crate::clipboard::write_clipboard(&text);
                        if result.is_ok() {
                            if let Ok(mut state) = clipboard.lock() {
                                state.note_applied(&text);
                            }
                        }
                        result
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
        if let Ok(mut held) = held_inputs.lock() {
            held.record(&action);
        }
        let desktop = desktop.clone();
        // WebRTC control sessions already hold a control_indicator refcount for
        // the session's lifetime; do NOT call note_inject_input() here so the
        // banner disappears immediately when the session closes.
        let result = tokio::task::spawn_blocking(move || desktop.hid.inject(&action)).await;
        if let Ok(Err(err)) = result {
            let err_text = err.to_string();
            tracing::warn!(session = %session_id, error = %err_text, "remote input inject failed");
            let should_send = {
                let now = Instant::now();
                let mut slot = last_inject_err.lock().unwrap_or_else(|e| e.into_inner());
                let due = slot
                    .map(|t| now.saturating_duration_since(t) >= INJECT_ERROR_COOLDOWN)
                    .unwrap_or(true);
                if due {
                    *slot = Some(now);
                }
                due
            };
            if should_send {
                let body = json!({
                    "type": "error",
                    "code": "inject_failed",
                    "error": err_text,
                })
                .to_string();
                let _ = channel.send_text(&body).await;
            }
        }
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

/// Honor a node-injected `_allow_control` flag. Only an explicit `true`
/// plus a control-capable ceiling grants control. A missing flag does not
/// inherit the ceiling.
pub(crate) fn session_allows_control(payload: &Value, policy: &NodePolicy) -> bool {
    if !policy.allows_remote_control() {
        return false;
    }
    // Only an explicit true from the node-stamped grant is control. A missing
    // flag or a client-supplied default must not inherit the ceiling.
    payload.get("_allow_control").and_then(Value::as_bool) == Some(true)
}

fn payload_grant_jti(payload: &Value) -> String {
    payload
        .get("_grant_jti")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

fn payload_grant_exp(payload: &Value) -> Option<i64> {
    payload.get("_grant_exp").and_then(Value::as_i64)
}

fn session_grant_error(
    shared: &super::StreamShared,
    session: &LiveSession,
    peer: &str,
) -> Option<String> {
    if session.peer_id != peer {
        return Some("unknown stream session".into());
    }
    grant_still_active(shared, &session.grant_jti, session.grant_exp_unix, peer)
}

fn grant_still_active(
    shared: &super::StreamShared,
    jti: &str,
    exp: Option<i64>,
    peer: &str,
) -> Option<String> {
    if let Some(exp) = exp {
        if agentlink_core::util::unix_now() >= exp {
            return Some("grant expired".into());
        }
    }
    let hook = match shared.grant_active.read() {
        Ok(guard) => guard,
        Err(_) => return Some("node policy is unavailable".into()),
    };
    match hook.as_ref() {
        None => None,
        Some(hook) => {
            let jti = jti.trim();
            if jti.is_empty() {
                return Some("grant is required".into());
            }
            if !hook(jti, peer) {
                Some("grant was revoked".into())
            } else {
                None
            }
        }
    }
}

/// High-frequency `mouse move` events (60Hz+) are skipped from the audit log
/// when allowed so the audit file is not flooded with megabytes of noise.
pub(crate) fn should_audit_input(kind: &str, value: &Value) -> bool {
    if kind == "mouse" {
        let action = value
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("move");
        return action != "move";
    }
    true
}

/// Sanitized input audit entry: logs only action metadata (kind, length/count),
/// never plaintext typed/clipboard characters or key names that could leak
/// passwords, OTPs, or secrets.
pub(crate) fn input_audit(kind: &str, value: &Value) -> (String, Value) {
    match kind {
        "type" | "clipboard" => {
            let text = value.get("text").and_then(Value::as_str);
            let Some(text) = text else {
                return (format!("{kind} get"), json!({"kind": kind, "op": "get"}));
            };
            let count = text.chars().count();
            (
                format!("{kind} {count} chars"),
                json!({"kind": kind, "chars": count}),
            )
        }
        "key" => {
            let count = value.get("keys").map(string_list).map(|v| v.len()).unwrap_or(0);
            let edge = match value.get("down").and_then(Value::as_bool) {
                Some(true) => "down",
                Some(false) => "up",
                None => "tap",
            };
            (
                format!("key {edge} count={count}"),
                json!({"kind": "key", "edge": edge, "count": count}),
            )
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

fn mouse_action(
    desktop: &Desktop,
    monitor_cache: &MonitorCache,
    default_monitor: Option<u32>,
    value: &Value,
) -> Option<InputAction> {
    let action = value
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("move");
    let effective = if value.get("monitor").is_none() {
        if let Some(mon) = default_monitor {
            let mut cloned = value.clone();
            if let Some(obj) = cloned.as_object_mut() {
                obj.insert("monitor".into(), json!(mon));
            }
            Some(cloned)
        } else {
            None
        }
    } else {
        None
    };
    let payload = effective.as_ref().unwrap_or(value);
    let monitors = monitor_cache.get_or_refresh(desktop);
    // Same fraction/absolute + optional monitor mapping as inject_input.
    let resolved =
        crate::handlers::resolve_input_coords_with_monitors(&monitors, action, payload).ok()?;
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
            dx: crate::handlers::parse_scroll_delta(value.get("dx")),
            dy: crate::handlers::parse_scroll_delta(value.get("dy")),
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
        Value::String(text) => crate::keys::parse_combo(text).unwrap_or_else(|_| {
            text.split('+')
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect()
        }),
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn default_scale_caps_wide_panels_only_when_unset() {
        assert_eq!(
            super::default_scale_for_width(2736, false),
            Some(1920.0 / 2736.0)
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
        assert!(input_allowed(&control, "clipboard"));
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
        assert!(!super::session_allows_control(&json!({}), &ceiling));
    }

    #[test]
    fn input_audit_omits_plaintext_previews_and_key_names() {
        let (detail, args) = super::input_audit("type", &json!({"text": "secret-password-value"}));
        assert!(!detail.contains("secret"));
        assert!(!detail.contains("password"));
        assert!(detail.contains("chars"));
        assert!(args.get("text").is_none());
        assert_eq!(args["chars"], 21);

        let (clip, clip_args) =
            super::input_audit("clipboard", &json!({"text": "clipboard-secret-value"}));
        assert!(!clip.contains("clipboard-se"));
        assert!(clip.contains("22 chars"));
        assert!(clip_args.get("text").is_none());
        assert!(!format!("{clip_args}").contains("sdp"));

        let (key_detail, key_args) =
            super::input_audit("key", &json!({"keys": ["p", "a", "s"], "down": true}));
        assert!(!key_detail.contains("p+a+s"));
        assert!(key_args.get("keys").is_none());
        assert_eq!(key_args["count"], 3);
        assert_eq!(key_args["edge"], "down");

        assert!(!super::should_audit_input("mouse", &json!({"action": "move"})));
        assert!(!super::should_audit_input("mouse", &json!({})));
        assert!(super::should_audit_input("mouse", &json!({"action": "click"})));
        assert!(super::should_audit_input("key", &json!({"keys": "a"})));
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

    #[test]
    fn gathered_candidate_queue_dedups_and_stays_bounded() {
        let queue = std::sync::Mutex::new(Vec::new());
        let make = |n: u16| {
            json!({
                "candidate": format!("candidate:{n} 1 udp 2130706431 192.0.2.1 {n} typ host"),
                "sdpMid": "",
                "sdpMLineIndex": 0
            })
        };
        super::record_gathered_candidate(&queue, make(1));
        super::record_gathered_candidate(&queue, make(1));
        assert_eq!(
            queue.lock().unwrap().len(),
            1,
            "duplicate candidate line must be dropped"
        );
        for n in 2..=40 {
            super::record_gathered_candidate(&queue, make(n));
        }
        let len = queue.lock().unwrap().len();
        assert_eq!(
            len,
            super::MAX_GATHERED_CANDIDATES,
            "queue must cap at {}, got {len}",
            super::MAX_GATHERED_CANDIDATES
        );
    }

    fn dummy_control() -> super::super::pipeline::PumpControl {
        use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
        use std::sync::{Arc, Mutex};
        super::super::pipeline::PumpControl {
            bitrate: Arc::new(AtomicU32::new(0)),
            keyframe: Arc::new(AtomicBool::new(false)),
            frames_sent: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            encoded_frames: Arc::new(AtomicU64::new(0)),
            dropped_frames: Arc::new(AtomicU64::new(0)),
            encode_us_ema: Arc::new(AtomicU64::new(0)),
            capture_us_ema: Arc::new(AtomicU64::new(0)),
            convert_us_ema: Arc::new(AtomicU64::new(0)),
            queue_us_ema: Arc::new(AtomicU64::new(0)),
            keyframes: Arc::new(AtomicU64::new(0)),
            capture_w: Arc::new(AtomicU32::new(0)),
            capture_h: Arc::new(AtomicU32::new(0)),
            encode_w: Arc::new(AtomicU32::new(0)),
            encode_h: Arc::new(AtomicU32::new(0)),
            encoder_name: Arc::new(Mutex::new(String::new())),
            last_error: Arc::new(Mutex::new(String::new())),
        }
    }

    fn dummy_session(id: &str, peer: &str, jti: &str, exp: Option<i64>) -> super::LiveSession {
        super::LiveSession {
            id: id.to_string(),
            stop: Arc::new(AtomicBool::new(false)),
            control: dummy_control(),
            peer: Arc::new(Mutex::new(None)),
            started: std::time::Instant::now(),
            viewer: "viewer".into(),
            peer_id: peer.to_string(),
            control_held: Arc::new(AtomicBool::new(false)),
            held_inputs: Arc::new(Mutex::new(super::HeldInputState::default())),
            remote_ufrag: Mutex::new(None),
            grant_jti: jti.to_string(),
            grant_exp_unix: exp,
        }
    }

    fn test_manager() -> super::SessionManager {
        use crate::stream::handler::StreamShared;
        super::SessionManager {
            desktop: crate::Desktop::mock(),
            shared: Arc::new(StreamShared {
                policy: Arc::new(std::sync::RwLock::new(NodePolicy::remote_control())),
                audit_path: std::sync::RwLock::new(std::path::PathBuf::new()),
                consent: std::sync::RwLock::new(crate::stream::consent::ConsentMode::Auto),
                on_audit: std::sync::RwLock::new(None),
                grant_active: std::sync::RwLock::new(None),
            }),
            sessions: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn client_preset_allow_control_is_ignored_until_node_stamps_true() {
        let ceiling = NodePolicy::remote_control();
        // A view-only (or attacker-supplied) true is not enough by itself once
        // the node overwrites the flag. This helper is what the session uses
        // after that overwrite; a missing flag is also deny.
        assert!(!super::session_allows_control(
            &json!({"_allow_control": true, "_allow_view": true}),
            &NodePolicy::remote_view()
        ));
        assert!(!super::session_allows_control(&json!({}), &ceiling));
        assert!(!super::session_allows_control(
            &json!({"_allow_control": false}),
            &ceiling
        ));
        assert!(super::session_allows_control(
            &json!({"_allow_control": true}),
            &ceiling
        ));
    }

    #[test]
    fn forged_peer_cannot_keyframe_or_close_another_session() {
        let mgr = test_manager();
        mgr.sessions
            .lock()
            .unwrap()
            .push(dummy_session("sess-a", "alice", "jti-a", None));
        let err = mgr
            .keyframe("bob", &json!({"session_id": "sess-a"}))
            .unwrap_err();
        assert!(err.contains("unknown stream session"), "{err}");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = runtime
            .block_on(mgr.close("bob", &json!({"session_id": "sess-a"})))
            .unwrap_err();
        assert!(err.contains("unknown stream session"), "{err}");
        assert_eq!(mgr.sessions.lock().unwrap().len(), 1);
        assert!(!mgr.sessions.lock().unwrap()[0].stop.load(Ordering::Relaxed));
    }

    #[test]
    fn revoke_of_one_jti_closes_media_while_ceiling_stays_full() {
        let mgr = test_manager();
        {
            let mut hook = mgr.shared.grant_active.write().unwrap();
            *hook = Some(Arc::new(|jti: &str, _peer: &str| jti != "revoked"));
        }
        mgr.sessions.lock().unwrap().extend([
            dummy_session("live-revoked", "alice", "revoked", None),
            dummy_session("live-ok", "alice", "still-good", None),
        ]);
        // With the ceiling still full, a later action on the revoked jti fails
        // and marks the session stopped.
        let err = mgr
            .keyframe("alice", &json!({"session_id": "live-revoked"}))
            .unwrap_err();
        assert!(err.contains("revoked"), "{err}");
        assert!(mgr
            .sessions
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.id == "live-revoked")
            .unwrap()
            .stop
            .load(Ordering::Relaxed));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let closed = runtime.block_on(mgr.close_sessions_for_jti("revoked"));
        assert_eq!(closed, 1);
        let left: Vec<_> = mgr
            .sessions
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.id.clone())
            .collect();
        assert_eq!(left, vec!["live-ok".to_string()]);
        // Legitimate remaining grant still works.
        mgr.keyframe("alice", &json!({"session_id": "live-ok"}))
            .expect("active grant must still keyframe");
    }

    #[test]
    fn expired_grant_closes_even_when_ceiling_is_full() {
        let mgr = test_manager();
        let past = agentlink_core::util::unix_now() - 10;
        mgr.sessions
            .lock()
            .unwrap()
            .push(dummy_session("old", "alice", "jti-exp", Some(past)));
        let err = mgr
            .keyframe("alice", &json!({"session_id": "old"}))
            .unwrap_err();
        assert!(err.contains("expired"), "{err}");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(runtime.block_on(mgr.close_expired_sessions()), 1);
        assert!(mgr.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn production_stream_session_ids_are_uuid_v4_and_not_peer_derived() {
        let a = super::new_stream_session_id();
        let b = super::new_stream_session_id();
        assert_ne!(a, b);
        let parsed = uuid::Uuid::parse_str(&a).expect("production id must be a uuid");
        assert_eq!(parsed.get_version(), Some(uuid::Version::Random));
        assert!(!a.contains("alice") && !a.contains("bob"));
    }

    #[test]
    fn handler_rejects_forged_client_id_even_when_the_session_uuid_is_known() {
        let mgr = test_manager();
        let session_id = super::new_stream_session_id();
        mgr.sessions
            .lock()
            .unwrap()
            .push(dummy_session(&session_id, "bob", "jti-bob", None));
        // Alice knows Bob's session UUID and presents Bob's client_id as the
        // caller. The handler peer is the seal identity, not that field.
        let err = mgr
            .keyframe(
                "alice",
                &json!({"session_id": session_id, "client_id": "bob"}),
            )
            .unwrap_err();
        assert!(err.contains("unknown stream session"), "{err}");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = runtime
            .block_on(mgr.close(
                "alice",
                &json!({"session_id": session_id, "client_id": "bob"}),
            ))
            .unwrap_err();
        assert!(err.contains("unknown stream session"), "{err}");
        let sessions = mgr.sessions.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, session_id);
        assert!(!sessions[0].stop.load(Ordering::Relaxed));
        drop(sessions);
        mgr.keyframe("bob", &json!({"session_id": session_id}))
            .expect("owner must still be able to keyframe");
    }

    #[test]
    fn inactive_sweep_uses_session_grant_metadata_not_an_rpc_index() {
        let mgr = test_manager();
        {
            let mut hook = mgr.shared.grant_active.write().unwrap();
            *hook = Some(Arc::new(|jti: &str, _peer: &str| jti != "revoked"));
        }
        let revoked_id = super::new_stream_session_id();
        let ok_id = super::new_stream_session_id();
        mgr.sessions.lock().unwrap().extend([
            dummy_session(&revoked_id, "alice", "revoked", None),
            dummy_session(&ok_id, "alice", "still-good", None),
        ]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // No prior keyframe / grant_sessions entry: the sweep must still see
        // the stored jti on the live session.
        let closed = runtime.block_on(mgr.close_inactive_sessions());
        assert_eq!(closed, 1);
        let left: Vec<_> = mgr
            .sessions
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.id.clone())
            .collect();
        assert_eq!(left, vec![ok_id.clone()]);
        mgr.keyframe("alice", &json!({"session_id": ok_id}))
            .expect("surviving grant must still keyframe");
    }

    #[test]
    fn close_all_sessions_stops_media_when_the_relay_drops() {
        let mgr = test_manager();
        mgr.sessions.lock().unwrap().extend([
            dummy_session("a", "alice", "jti-a", None),
            dummy_session("b", "bob", "jti-b", None),
        ]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(runtime.block_on(mgr.close_all_sessions()), 2);
        assert!(mgr.sessions.lock().unwrap().is_empty());
    }

    struct LockProbePeer {
        unlocked_during_close: Arc<AtomicBool>,
        slot: Arc<Mutex<Option<Arc<dyn super::IcePeer>>>>,
    }

    #[async_trait::async_trait]
    impl super::IcePeer for LockProbePeer {
        async fn add_ice_candidate(
            &self,
            _candidate: rtc::peer_connection::transport::RTCIceCandidateInit,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn renegotiate(
            &self,
            _offer_sdp: &str,
        ) -> std::result::Result<(String, Vec<Value>), String> {
            Ok((String::new(), Vec::new()))
        }
        fn gathered_candidates(&self) -> Vec<Value> {
            Vec::new()
        }
        fn gather_done(&self) -> bool {
            true
        }
        fn push_gathered_candidate(&self, _candidate: Value) {}
        async fn close(&self) {
            tokio::task::yield_now().await;
            if self.slot.try_lock().is_ok() {
                self.unlocked_during_close.store(true, Ordering::SeqCst);
            }
        }
    }

    #[tokio::test]
    async fn close_owned_drops_peer_mutex_before_await_and_offer_enforces_live_stream_cap() {
        let mgr = test_manager();
        let session = dummy_session("probe-close", "alice", "jti-1", None);
        let probe_flag = Arc::new(AtomicBool::new(false));
        let peer_obj: Arc<dyn super::IcePeer> = Arc::new(LockProbePeer {
            unlocked_during_close: probe_flag.clone(),
            slot: session.peer.clone(),
        });
        *session.peer.lock().unwrap() = Some(peer_obj);
        mgr.sessions.lock().unwrap().push(session);
        mgr.close_owned(&json!({"session_id": "probe-close"}), Some("alice"))
            .await
            .expect("close_owned");
        assert!(probe_flag.load(Ordering::SeqCst));

        // Fill active live stream slots to capacity (4) and verify a 5th concurrent offer is refused.
        for idx in 0..4 {
            mgr.sessions.lock().unwrap().push(dummy_session(
                &format!("live-{idx}"),
                "alice",
                &format!("jti-{idx}"),
                None,
            ));
        }
        let fifth = mgr
            .offer("alice", &json!({"sdp": "v=0\r\n", "viewer": "alice"}))
            .await;
        let err = fifth.expect_err("5th concurrent stream offer must be refused");
        assert!(
            err.contains("too many") || err.contains("stream"),
            "expected stream cap error, got: {err}"
        );
    }

    #[tokio::test]
    async fn consent_prompt_is_not_downgraded_for_control_offers() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager();
        *mgr.shared.audit_path.write().unwrap() = dir.path().join("audit.jsonl");
        *mgr.shared.consent.write().unwrap() = crate::stream::consent::ConsentMode::Prompt;

        let consent_dir = dir.path().join("stream-consent");
        let watcher = tokio::spawn(async move {
            for _ in 0..100 {
                if let Ok(entries) = std::fs::read_dir(&consent_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().and_then(|e| e.to_str()) == Some("request") {
                            let decision = p.with_extension("deny");
                            std::fs::write(&decision, "denied by test\n").unwrap();
                            return Some(p.file_name().unwrap().to_string_lossy().to_string());
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            None
        });

        // `_allow_control: true` must STILL enforce ConsentMode::Prompt and NOT downgrade to Notify.
        let err = mgr
            .offer(
                "alice",
                &json!({"sdp": "v=0\r\n", "viewer": "alice", "_allow_control": true}),
            )
            .await
            .expect_err("ConsentMode::Prompt must wait for human decision even with _allow_control");
        assert!(err.contains("denied"), "expected consent denial, got: {err}");
        let req_name = watcher.await.unwrap().expect("request file must have been created");
        assert!(
            req_name.starts_with("pending-alice-") && req_name.len() > "pending-alice-.request".len(),
            "expected per-offer UUID filename, got: {req_name}"
        );
    }

    #[test]
    fn frame_outbox_preserves_unsent_idr_and_rearms_keyframe_on_delta_drop() {
        use crate::stream::encode::{Codec, EncodedAccessUnit};
        use std::time::Duration;

        let make = |keyframe: bool, tag: u8| EncodedAccessUnit {
            codec: Codec::H264,
            bytes: vec![0, 0, 0, 1, tag],
            keyframe,
            width: 64,
            height: 64,
            captured_unix_ms: tag as i64,
        };

        let outbox = super::FrameOutbox::new(2);
        assert!(!outbox.push(make(true, 1)));
        assert!(!outbox.push(make(false, 2)));
        // Queue is full [IDR(1), P(2)]; pushing P(3) must NOT evict IDR(1)
        // and must signal needs_keyframe=true.
        assert!(outbox.push(make(false, 3)));
        assert_eq!(outbox.dropped.load(Ordering::Relaxed), 1);

        let (first, _) = outbox.pop_timeout(Duration::from_millis(10)).unwrap();
        assert!(first.keyframe && first.bytes[4] == 1, "unsent IDR must be preserved");
        let (second, _) = outbox.pop_timeout(Duration::from_millis(10)).unwrap();
        assert!(!second.keyframe && second.bytes[4] == 2);

        // Fresh IDR cleanly supersedes stale frames.
        assert!(!outbox.push(make(false, 4)));
        assert!(!outbox.push(make(false, 5)));
        assert!(!outbox.push(make(true, 6)));
        let (latest, _) = outbox.pop_timeout(Duration::from_millis(10)).unwrap();
        assert!(latest.keyframe && latest.bytes[4] == 6);
    }

    #[test]
    fn hold_sample_rearms_keyframe_when_srtp_ready_and_waiting_for_idr() {
        let keyframe = AtomicBool::new(false);
        assert!(super::hold_sample(true, true, false, &keyframe));
        assert!(
            keyframe.load(Ordering::Acquire),
            "holding a delta while waiting for an IDR must re-arm keyframe"
        );
    }

    #[test]
    fn aimd_respects_low_offer_bitrate_and_throttles_idr_requests() {
        use std::time::{Duration, Instant};

        let aimd = super::AimdState::new(400_000);
        let t0 = Instant::now();
        // 5% loss on a 400 kbps mobile offer must drop to 320 kbps, NOT clamp up to 800 kbps.
        let (b1, idr1) = super::apply_aimd_feedback(&aimd, 400_000, 0.05, t0);
        assert_eq!(b1, 320_000);
        assert!(idr1, "first loss event triggers IDR");

        // Second loss packet 200ms later drops bitrate further but throttles IDR.
        let (b2, idr2) =
            super::apply_aimd_feedback(&aimd, b1, 0.05, t0 + Duration::from_millis(200));
        assert_eq!(b2, 256_000);
        assert!(!idr2, "burst loss within 1s must not spam IDRs");

        // Repeated loss hits the offer-derived floor (200_000), never above offer.
        let (b3, idr3) =
            super::apply_aimd_feedback(&aimd, b2, 0.05, t0 + Duration::from_secs(2));
        assert_eq!(b3, 204_800);
        assert!(idr3, "after 1s cooldown, IDR is allowed again");
        let (b4, _) =
            super::apply_aimd_feedback(&aimd, b3, 0.05, t0 + Duration::from_secs(3));
        assert_eq!(b4, 200_000);
    }

    #[test]
    fn video_codec_advertises_nack_pli_and_fir_rtcp_feedback() {
        let params = super::video_codec(&crate::stream::encode::Codec::H264);
        let fbs = &params.rtp_codec.rtcp_feedback;
        assert!(fbs.iter().any(|f| f.typ == "nack" && f.parameter.is_empty()));
        assert!(fbs.iter().any(|f| f.typ == "nack" && f.parameter == "pli"));
        assert!(fbs.iter().any(|f| f.typ == "ccm" && f.parameter == "fir"));
    }

    #[test]
    fn held_input_state_releases_buttons_and_keys_on_disconnect() {
        let mut held = super::HeldInputState::default();
        held.record(&InputAction::KeyEdge {
            keys: vec!["ctrl".into(), "shift".into()],
            down: true,
        });
        held.record(&InputAction::Button {
            x: 120,
            y: 240,
            button: crate::input::MouseButton::Left,
            down: true,
        });
        held.record(&InputAction::Move { x: 300, y: 400 });
        let releases = held.drain_release_actions();
        assert_eq!(releases.len(), 3);
        assert!(matches!(
            &releases[0],
            InputAction::Button {
                x: 300,
                y: 400,
                button: crate::input::MouseButton::Left,
                down: false
            }
        ));
        assert!(matches!(
            &releases[1],
            InputAction::KeyEdge { keys, down: false } if keys == &vec!["shift".to_string()]
        ));
        assert!(matches!(
            &releases[2],
            InputAction::KeyEdge { keys, down: false } if keys == &vec!["ctrl".to_string()]
        ));
        assert!(held.drain_release_actions().is_empty());
    }
}
