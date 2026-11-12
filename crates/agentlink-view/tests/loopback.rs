//! Offer against the in-memory desktop and read one H.264 IDR back.
//!
//! This is the same `webrtc_signal` contract the phone uses. No display and
//! no Android emulator: the node is `Desktop::mock()`, consent is auto, and
//! the policy is remote control so the input channel is honored.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentlink_core::{NodeExtension, NodePolicy};
use agentlink_desktop::{ConsentMode, Desktop, StreamHandler, StreamSettings};
use agentlink_view::{access_unit_is_idr, LiveOptions, Signal, Viewer};
use serde_json::Value;

struct NodeSignal {
    handler: Arc<StreamHandler>,
}

impl Signal for NodeSignal {
    fn signal(&self, payload: &Value) -> Result<Value, String> {
        self.handler.handle_peer(payload, "android-test")
    }
}

#[test]
fn mock_desktop_delivers_an_idr_and_a_mouse() {
    let audits = Arc::new(Mutex::new(Vec::new()));
    let recorded = audits.clone();
    let handler = Arc::new(StreamHandler::new(Desktop::mock()));
    handler.configure(StreamSettings {
        policy: NodePolicy::remote_control(),
        audit_path: std::env::temp_dir().join("agentlink-view-loopback.log"),
        consent: ConsentMode::Auto,
        on_audit: Some(Arc::new(move |event| {
            recorded
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .push(event.action.clone());
        })),
    });

    let viewer = Viewer::connect(
        Arc::new(NodeSignal { handler }),
        LiveOptions {
            viewer: "android-test".into(),
            ..LiveOptions::default()
        },
    )
    .expect("offer");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut idr = false;
    while Instant::now() < deadline {
        if viewer.failed() {
            break;
        }
        if let Some(frame) = viewer.poll_frame(Duration::from_millis(200)) {
            if frame.keyframe && access_unit_is_idr(&frame.annex_b) {
                idr = true;
                assert!(frame.width > 0 && frame.height > 0);
                break;
            }
        }
    }
    assert!(
        idr,
        "no Annex-B IDR (failed={}, stats={:?}, audits={:?})",
        viewer.failed(),
        viewer.stats(),
        audits.lock().unwrap_or_else(|err| err.into_inner())
    );

    // Selected ICE pair, not the answer SDP inventory. Addresses on this
    // machine may be loopback or private (bridge/VPN/routed). That is not
    // a public NAT traversal result and not automatically "same LAN".
    let path_deadline = Instant::now() + Duration::from_secs(5);
    let mut snap = viewer.transport();
    while snap.is_none() && Instant::now() < path_deadline {
        std::thread::sleep(Duration::from_millis(50));
        snap = viewer.transport();
    }
    let snap = snap.expect("selected ICE pair was not observed after an IDR");
    eprintln!(
        "agentlink live-path loopback: path={} local={} {} remote={} {} proto={} inventory={} note={}",
        snap.path,
        snap.local_typ,
        snap.local_addr,
        snap.remote_typ,
        snap.remote_addr,
        snap.protocol,
        snap.sdp_inventory,
        snap.note
    );
    assert!(
        matches!(snap.path.as_str(), "loopback" | "private" | "host"),
        "same-host typ host should be loopback, private, or public host, got {snap:?}"
    );
    assert_eq!(viewer.info().path, snap.path);
    assert_ne!(snap.path, "tailscale");
    assert_ne!(snap.path, "cgnat");
    if snap.path == "host" {
        assert!(
            snap.note
                .to_ascii_lowercase()
                .contains("not a claim of public nat"),
            "public typ host must not be reported as NAT success: {snap:?}"
        );
    }
    // Inventory is log-only. A host inventory is not itself the media path.
    assert!(
        !snap.sdp_inventory.is_empty(),
        "expected the answer SDP inventory to be recorded, got {snap:?}"
    );
    let local_is_loop = snap.local_addr.starts_with("127.")
        || snap.local_addr.starts_with("[::1]")
        || snap.local_addr.starts_with("::1");
    let remote_is_loop = snap.remote_addr.starts_with("127.")
        || snap.remote_addr.starts_with("[::1]")
        || snap.remote_addr.starts_with("::1");
    assert!(
        local_is_loop
            || remote_is_loop
            || snap.note.contains("loopback")
            || snap.note.contains("private")
            || snap.path == "private",
        "expected loopback or private typ host facts, got {snap:?}"
    );
    assert_ne!(
        snap.path, "relay",
        "must not label a host ICE pair as relay"
    );

    let input_deadline = Instant::now() + Duration::from_secs(5);
    let mut sent = false;
    while Instant::now() < input_deadline {
        if viewer.send_control(r#"{"type":"mouse","action":"move","x":12,"y":8}"#) {
            sent = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    assert!(sent, "input channel did not open");

    let audit_deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < audit_deadline {
        let actions = audits.lock().unwrap_or_else(|err| err.into_inner());
        if actions.iter().any(|action| action == "mouse") {
            break;
        }
        drop(actions);
        std::thread::sleep(Duration::from_millis(40));
    }
    let close_started = Instant::now();
    viewer.close();
    let close_wait = close_started.elapsed();
    assert!(
        close_wait <= Duration::from_secs(3),
        "Viewer::close must finish within the 2s wait plus slack, got {close_wait:?}"
    );
    let stop_deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < stop_deadline {
        let actions = audits.lock().unwrap_or_else(|err| err.into_inner());
        if actions.iter().any(|action| action == "stream_stop") {
            break;
        }
        drop(actions);
        std::thread::sleep(Duration::from_millis(40));
    }
    let actions = audits.lock().unwrap_or_else(|err| err.into_inner()).clone();
    assert!(
        actions.iter().any(|action| action == "mouse"),
        "mouse audit missing: {actions:?}"
    );
    assert!(
        actions.iter().any(|action| action == "stream_stop"),
        "stream_stop missing: {actions:?}"
    );
}

struct DenySignal;

impl Signal for DenySignal {
    fn signal(&self, _payload: &Value) -> Result<Value, String> {
        Err("not allowed: missing grant".into())
    }
}

struct ScreenshotFallbackSignal;

impl Signal for ScreenshotFallbackSignal {
    fn signal(&self, _payload: &Value) -> Result<Value, String> {
        Ok(serde_json::json!({
            "status": "unavailable",
            "fallback": "screenshot"
        }))
    }
}

#[test]
fn webrtc_offer_without_a_grant_is_rejected() {
    let err = match Viewer::connect(
        Arc::new(DenySignal),
        LiveOptions {
            viewer: "desktop".into(),
            control: false,
            ..LiveOptions::default()
        },
    ) {
        Ok(_) => panic!("missing grant must not open a live session"),
        Err(err) => err,
    };
    let lower = err.to_ascii_lowercase();
    assert!(
        lower.contains("not allowed") || lower.contains("grant"),
        "unexpected reject: {err}"
    );
}

#[test]
fn screenshot_fallback_does_not_look_like_p2p() {
    let err = match Viewer::connect(
        Arc::new(ScreenshotFallbackSignal),
        LiveOptions {
            viewer: "desktop".into(),
            control: false,
            ..LiveOptions::default()
        },
    ) {
        Ok(_) => panic!("screenshot fallback must not return a Viewer"),
        Err(err) => err,
    };
    assert!(
        err.contains("fallback screenshot") || err.contains("live video is not available"),
        "unexpected fallback: {err}"
    );
}

fn view_handler() -> Arc<StreamHandler> {
    let handler = Arc::new(StreamHandler::new(Desktop::mock()));
    handler.configure(StreamSettings {
        policy: NodePolicy::remote_view(),
        audit_path: std::env::temp_dir().join("agentlink-view-loopback-ice.log"),
        consent: ConsentMode::Auto,
        on_audit: None,
    });
    handler
}

/// Records offer/ice outcomes on the real StreamHandler path. May hold ICE
/// until a delay after the answer so tests can prove late `add_ice_candidate`
/// still forms a selected pair. Does not log ufrag, passwords, or tokens.
struct ProtocolSignal {
    handler: Arc<StreamHandler>,
    events: Arc<Mutex<Vec<String>>>,
    ice_delay: Duration,
    rewrite_gather_ms: Option<u64>,
    /// When set, the offer SDP is sent without `a=candidate` lines so the
    /// node cannot form a pair from the offer alone. Remote candidates then
    /// arrive only as delayed `ice` trickle — the sequence that matters
    /// after `pingAllCandidates` has already run with an empty list.
    strip_offer_candidates: bool,
    omit_answer_candidates: bool,
    pretend_old_node: bool,
    /// Answer still advertises ice_pull, but the action itself is unknown
    /// (mixed / half-upgraded node). Viewer must log once and stop.
    reject_ice_pull: bool,
    answer_at: Mutex<Option<Instant>>,
    answer_candidates: Mutex<usize>,
    session_id: Mutex<String>,
}

impl ProtocolSignal {
    fn new(
        handler: Arc<StreamHandler>,
        ice_delay: Duration,
        rewrite_gather_ms: Option<u64>,
        strip_offer_candidates: bool,
        omit_answer_candidates: bool,
        pretend_old_node: bool,
    ) -> Self {
        Self {
            handler,
            events: Arc::new(Mutex::new(Vec::new())),
            ice_delay,
            rewrite_gather_ms,
            strip_offer_candidates,
            omit_answer_candidates,
            pretend_old_node,
            reject_ice_pull: false,
            answer_at: Mutex::new(None),
            answer_candidates: Mutex::new(0),
            session_id: Mutex::new(String::new()),
        }
    }

    fn push(&self, event: String) {
        self.events
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push(event);
    }

    fn events(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }
}

fn strip_sdp_ice_candidates(sdp: &str) -> (String, usize) {
    let crlf = sdp.contains("\r\n");
    let sep = if crlf { "\r\n" } else { "\n" };
    let mut dropped = 0usize;
    let text = sdp
        .lines()
        .filter(|line| {
            if line.trim().to_ascii_lowercase().starts_with("a=candidate") {
                dropped += 1;
                false
            } else {
                true
            }
        })
        .collect::<Vec<_>>()
        .join(sep);
    let text = if sdp.ends_with('\n') && !text.ends_with('\n') {
        format!("{text}{sep}")
    } else {
        text
    };
    (text, dropped)
}

fn typ_hint(line: &str) -> &'static str {
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

impl Signal for ProtocolSignal {
    fn signal(&self, payload: &Value) -> Result<Value, String> {
        let action = payload.get("action").and_then(Value::as_str).unwrap_or("");
        let mut body = payload.clone();
        if action == "offer" {
            if let Some(ms) = self.rewrite_gather_ms {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("gather_ms".into(), serde_json::json!(ms));
                }
            }
            if self.strip_offer_candidates {
                if let Some(sdp) = body.get("sdp").and_then(Value::as_str) {
                    let (stripped, dropped) = strip_sdp_ice_candidates(sdp);
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert("sdp".into(), Value::String(stripped));
                    }
                    self.push(format!("offer stripped {dropped} SDP candidates"));
                }
            }
        }
        if action == "ice" && !self.ice_delay.is_zero() {
            let start = Instant::now();
            loop {
                if let Some(answered) =
                    *self.answer_at.lock().unwrap_or_else(|err| err.into_inner())
                {
                    let ready = answered + self.ice_delay;
                    while Instant::now() < ready {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    break;
                }
                if start.elapsed() > Duration::from_secs(8) {
                    self.push("ice applied before answer was observed".into());
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if action == "ice_pull" && (self.pretend_old_node || self.reject_ice_pull) {
            self.push("ice_pull rejected as unsupported".into());
            return Err("unknown webrtc_signal action 'ice_pull'".into());
        }
        let mut result = self.handler.handle_peer(&body, "protocol-test");
        if action == "offer" {
            if let Ok(answer) = result.as_mut() {
                if self.omit_answer_candidates {
                    if let Some(sdp) = answer.get("sdp").and_then(Value::as_str) {
                        let (stripped, dropped) = strip_sdp_ice_candidates(sdp);
                        if let Some(obj) = answer.as_object_mut() {
                            obj.insert("sdp".into(), Value::String(stripped));
                            obj.insert("candidates".into(), serde_json::json!([]));
                        }
                        self.push(format!(
                            "answer omitted {dropped} SDP candidates for ice_pull"
                        ));
                    }
                }
                if self.pretend_old_node {
                    if let Some(obj) = answer.as_object_mut() {
                        obj.remove("ice_pull");
                    }
                    self.push("answer hid ice_pull (old node)".into());
                }
            }
        }
        match (action, &result) {
            ("offer", Ok(answer)) => {
                let session = answer
                    .get("session_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                *self
                    .session_id
                    .lock()
                    .unwrap_or_else(|err| err.into_inner()) = session.clone();
                *self.answer_at.lock().unwrap_or_else(|err| err.into_inner()) =
                    Some(Instant::now());
                let batched = answer
                    .get("candidates")
                    .and_then(Value::as_array)
                    .map(|arr| arr.len())
                    .unwrap_or(0);
                *self
                    .answer_candidates
                    .lock()
                    .unwrap_or_else(|err| err.into_inner()) = batched;
                self.push(format!(
                    "offer ok session_set={} batched_candidates={batched}",
                    !session.is_empty()
                ));
            }
            ("ice", Ok(value)) => {
                let added = value.get("added").and_then(Value::as_bool).unwrap_or(false);
                let cand = payload.get("candidate").cloned().unwrap_or(Value::Null);
                let mid = cand.get("sdpMid").and_then(Value::as_str);
                let mline = cand.get("sdpMLineIndex").and_then(Value::as_u64);
                let typ = typ_hint(cand.get("candidate").and_then(Value::as_str).unwrap_or(""));
                let mid_empty = mid.map(|s| s.is_empty()).unwrap_or(true);
                // mid emptiness and typ only — do not record usernameFragment.
                self.push(format!(
                    "ice ok added={added} typ={typ} sdpMid_empty={mid_empty} sdpMLineIndex={mline:?}"
                ));
            }
            ("ice", Err(err)) => {
                self.push(format!("ice err {err}"));
            }
            ("ice_pull", Ok(value)) => {
                let n = value
                    .get("candidates")
                    .and_then(Value::as_array)
                    .map(|arr| arr.len())
                    .unwrap_or(0);
                let done = value
                    .get("gather_done")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                self.push(format!("ice_pull ok new={n} gather_done={done}"));
            }
            ("ice_pull", Err(err)) => {
                self.push(format!("ice_pull err {err}"));
            }
            (other, Err(err)) => {
                self.push(format!("{other} err {err}"));
            }
            _ => {}
        }
        result
    }
}

fn wait_for_idr(viewer: &Viewer) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if viewer.failed() {
            return false;
        }
        if let Some(frame) = viewer.poll_frame(Duration::from_millis(200)) {
            if frame.keyframe && access_unit_is_idr(&frame.annex_b) {
                return true;
            }
        }
    }
    false
}

fn wait_for_selected_pair(viewer: &Viewer) -> Option<agentlink_view::TransportSnapshot> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut snap = viewer.transport();
    while snap.is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        snap = viewer.transport();
    }
    snap
}

#[test]
fn ice_before_session_is_rejected_and_is_not_ok() {
    let handler = view_handler();
    let err = handler
        .handle_peer(
            &serde_json::json!({
                "action": "ice",
                "session_id": "pending-not-started",
                "candidate": {
                    "candidate": "candidate:1 1 udp 2130706431 192.0.2.1 9 typ host",
                    "sdpMid": "",
                    "sdpMLineIndex": 0,
                    "usernameFragment": null
                }
            }),
            "protocol-test",
        )
        .unwrap_err();
    assert!(
        err.contains("unknown stream session"),
        "ice before offer must fail, got {err}"
    );
}

#[test]
fn delayed_trickle_still_selects_a_pair_and_delivers_h264() {
    let handler = view_handler();
    let signal = Arc::new(ProtocolSignal::new(
        handler.clone(),
        Duration::from_millis(400),
        None,
        true,
        false,
        false,
    ));
    let viewer = Viewer::connect(
        signal.clone(),
        LiveOptions {
            viewer: "protocol-test".into(),
            control: false,
            ..LiveOptions::default()
        },
    )
    .expect("offer");

    let idr = wait_for_idr(&viewer);
    let snap = wait_for_selected_pair(&viewer);
    let ice_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < ice_deadline
        && !signal
            .events()
            .iter()
            .any(|event| event.starts_with("ice ok added=true"))
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    let events = signal.events();
    let ice_ok = events
        .iter()
        .filter(|event| event.starts_with("ice ok added=true"))
        .count();
    let ice_err = events
        .iter()
        .filter(|event| event.starts_with("ice err"))
        .count();
    let stripped = events
        .iter()
        .any(|event| event.contains("offer stripped") && !event.contains("stripped 0 "));
    eprintln!(
        "agentlink live-protocol: delayed trickle ice_ok={ice_ok} ice_err={ice_err} stripped={stripped} idr={idr} pair={snap:?} events={events:?}"
    );
    assert!(
        stripped,
        "offer SDP candidates must be omitted so the pair depends on late ice: {events:?}"
    );
    assert!(
        idr,
        "delayed trickle must still deliver H.264, events={events:?}"
    );
    let snap = snap.expect("delayed trickle must still select an ICE pair");
    assert!(
        matches!(snap.path.as_str(), "loopback" | "private" | "host"),
        "unexpected path after delayed trickle: {snap:?}"
    );
    assert!(
        ice_ok >= 1,
        "expected at least one added=true trickle, events={events:?}"
    );
    assert_eq!(
        ice_err, 0,
        "trickle after a real session must not fail, events={events:?}"
    );
    assert!(
        events.iter().any(|event| event.contains("sdpMid_empty=true")),
        "viewer to_json is expected to send an empty sdpMid; library still adds the candidate: {events:?}"
    );

    let session = viewer.info().session_id.clone();
    let answer_n = *signal
        .answer_candidates
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    std::thread::sleep(Duration::from_millis(1500));
    let later = handler.gathered_candidates(&session).unwrap_or_default();
    eprintln!(
        "agentlink live-protocol: answer batched={answer_n} node gathered later={} typ={}",
        later.len(),
        later
            .iter()
            .map(|value| typ_hint(value.get("candidate").and_then(Value::as_str).unwrap_or("")))
            .collect::<Vec<_>>()
            .join(",")
    );
    // Production waits up to 4s or gather complete before returning the
    // answer. After a complete gather, trailing candidates may still appear
    // but this loopback does not treat that as a reason to invent ice_pull.
    viewer.close();
}

#[test]
fn malformed_trickle_after_answer_is_not_acked_ok() {
    let handler = view_handler();
    let signal = Arc::new(ProtocolSignal::new(
        handler.clone(),
        Duration::ZERO,
        None,
        false,
        false,
        false,
    ));
    let viewer = Viewer::connect(
        signal.clone(),
        LiveOptions {
            viewer: "protocol-test".into(),
            control: false,
            ..LiveOptions::default()
        },
    )
    .expect("offer");
    let session = viewer.info().session_id.clone();
    let err = handler
        .handle_peer(
            &serde_json::json!({
                "action": "ice",
                "session_id": session,
                "candidate": "candidate:1 1 udp 2130706431 192.0.2.1 9 typ host"
            }),
            "protocol-test",
        )
        .unwrap_err();
    assert!(
        err.contains("RTCIceCandidateInit"),
        "bare candidate string must not be acked ok, got {err}"
    );
    // A malformed trickle must not be enough to keep H.264 from a valid
    // offer/answer plus real added candidates.
    assert!(
        wait_for_idr(&viewer),
        "valid trickle path should still deliver H.264 after a rejected malformed ice"
    );
    viewer.close();
}

#[test]
fn short_gather_late_node_candidates_are_observed_without_claiming_nat() {
    let handler = view_handler();
    let signal = Arc::new(ProtocolSignal::new(
        handler.clone(),
        Duration::ZERO,
        Some(20),
        false,
        false,
        false,
    ));
    let viewer = Viewer::connect(
        signal.clone(),
        LiveOptions {
            viewer: "protocol-test".into(),
            control: false,
            ..LiveOptions::default()
        },
    )
    .expect("offer");
    let session = viewer.info().session_id.clone();
    let answer_n = *signal
        .answer_candidates
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let idr = wait_for_idr(&viewer);
    let snap = wait_for_selected_pair(&viewer);
    std::thread::sleep(Duration::from_millis(2000));
    let later = handler.gathered_candidates(&session).unwrap_or_default();
    let late = later.len().saturating_sub(answer_n);
    let late_typs: Vec<&str> = later
        .iter()
        .skip(answer_n)
        .map(|value| typ_hint(value.get("candidate").and_then(Value::as_str).unwrap_or("")))
        .collect();
    eprintln!(
        "agentlink live-protocol: short gather_ms=20 answer={answer_n} later={} late={late} late_typs={late_typs:?} idr={idr} path={:?}",
        later.len(),
        snap.as_ref().map(|s| s.path.clone())
    );
    assert!(
        idr && snap.is_some(),
        "same-host host candidates in the answer should still be enough without ice_pull"
    );
    viewer.close();
}

#[test]
fn ice_pull_delivers_candidates_omitted_from_the_answer() {
    let handler = view_handler();
    let signal = Arc::new(ProtocolSignal::new(
        handler.clone(),
        Duration::ZERO,
        None,
        false,
        true,
        false,
    ));
    let viewer = Viewer::connect(
        signal.clone(),
        LiveOptions {
            viewer: "protocol-test".into(),
            control: false,
            ..LiveOptions::default()
        },
    )
    .expect("offer");
    let idr = wait_for_idr(&viewer);
    let snap = wait_for_selected_pair(&viewer);
    let events = signal.events();
    let pulled = events
        .iter()
        .any(|event| event.starts_with("ice_pull ok") && !event.contains("new=0"));
    eprintln!(
        "agentlink live-protocol: ice_pull omitted-answer pulled={pulled} idr={idr} path={:?} events={events:?}",
        snap.as_ref().map(|s| s.path.clone())
    );
    assert!(
        events.iter().any(|event| event.contains("answer omitted")),
        "answer must omit candidates so pull is required: {events:?}"
    );
    assert!(
        pulled,
        "ice_pull must return the omitted candidates: {events:?}"
    );
    assert!(idr, "H.264 must arrive via pulled candidates: {events:?}");
    assert!(
        snap.is_some(),
        "selected pair required after ice_pull: {events:?}"
    );
    viewer.close();
}

#[test]
fn ice_pull_skipped_on_old_node_still_selects_a_pair() {
    let handler = view_handler();
    let signal = Arc::new(ProtocolSignal::new(
        handler.clone(),
        Duration::ZERO,
        None,
        false,
        false,
        true,
    ));
    let viewer = Viewer::connect(
        signal.clone(),
        LiveOptions {
            viewer: "protocol-test".into(),
            control: false,
            ..LiveOptions::default()
        },
    )
    .expect("offer");
    let idr = wait_for_idr(&viewer);
    let snap = wait_for_selected_pair(&viewer);
    let events = signal.events();
    eprintln!(
        "agentlink live-protocol: old-node ice_pull idr={idr} path={:?} events={events:?}",
        snap.as_ref().map(|s| s.path.clone())
    );
    assert!(
        events
            .iter()
            .any(|event| event.contains("answer hid ice_pull")),
        "old node must hide ice_pull: {events:?}"
    );
    let pull_attempts = events
        .iter()
        .filter(|event| event.contains("ice_pull"))
        .count();
    assert!(
        pull_attempts <= 1,
        "unsupported ice_pull must not retry-storm, events={events:?}"
    );
    assert!(
        idr && snap.is_some(),
        "answer candidates must still work: {events:?}"
    );
    viewer.close();
}

#[test]
fn advertised_but_unsupported_ice_pull_degrades_without_a_retry_storm() {
    let handler = view_handler();
    let signal = ProtocolSignal::new(handler.clone(), Duration::ZERO, None, false, false, false);
    // Keep ice_pull:true in the answer, but reject the action itself.
    let mut signal = signal;
    signal.reject_ice_pull = true;
    let signal = Arc::new(signal);
    let viewer = Viewer::connect(
        signal.clone(),
        LiveOptions {
            viewer: "protocol-test".into(),
            control: false,
            ..LiveOptions::default()
        },
    )
    .expect("offer");
    let idr = wait_for_idr(&viewer);
    let snap = wait_for_selected_pair(&viewer);
    let events = signal.events();
    eprintln!(
        "agentlink live-protocol: unsupported ice_pull advertised idr={idr} path={:?} events={events:?}",
        snap.as_ref().map(|s| s.path.clone())
    );
    let unsupported = events
        .iter()
        .filter(|event| {
            event.contains("ice_pull rejected as unsupported")
                || event.contains("ice_pull err unknown")
        })
        .count();
    assert!(
        unsupported >= 1,
        "unknown ice_pull must be observed, events={events:?}"
    );
    let pull_attempts = events
        .iter()
        .filter(|event| event.contains("ice_pull"))
        .count();
    assert!(
        pull_attempts <= 2,
        "unsupported ice_pull must not retry-storm, events={events:?}"
    );
    assert!(
        idr && snap.is_some(),
        "batched answer candidates must still form a pair: {events:?}"
    );
    viewer.close();
}

#[test]
fn stale_session_ice_is_rejected_and_a_new_generation_recovers_h264() {
    let handler = view_handler();
    let first = Arc::new(ProtocolSignal::new(
        handler.clone(),
        Duration::ZERO,
        None,
        false,
        false,
        false,
    ));
    let viewer = Viewer::connect(
        first.clone(),
        LiveOptions {
            viewer: "protocol-test".into(),
            control: false,
            ..LiveOptions::default()
        },
    )
    .expect("offer");
    assert!(wait_for_idr(&viewer), "first generation must get H.264");
    let old_session = viewer.info().session_id.clone();
    let stale = handler
        .handle_peer(
            &serde_json::json!({
                "action": "ice",
                "session_id": old_session,
                "candidate": {
                    "candidate": "candidate:1 1 udp 2130706431 192.0.2.1 9 typ host",
                    "sdpMid": "",
                    "sdpMLineIndex": 0,
                    "usernameFragment": "stale-generation"
                }
            }),
            "protocol-test",
        )
        .unwrap_err();
    assert!(
        stale.contains("stale ice generation"),
        "foreign ufrag must be rejected, got {stale}"
    );
    viewer.close();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let err = handler.handle_peer(
            &serde_json::json!({
                "action": "ice",
                "session_id": old_session,
                "candidate": {
                    "candidate": "candidate:1 1 udp 2130706431 192.0.2.1 9 typ host",
                    "sdpMid": "",
                    "sdpMLineIndex": 0,
                    "usernameFragment": null
                }
            }),
            "protocol-test",
        );
        if err
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("unknown stream session"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    let closed = handler
        .handle_peer(
            &serde_json::json!({
                "action": "ice",
                "session_id": old_session,
                "candidate": {
                    "candidate": "candidate:1 1 udp 2130706431 192.0.2.1 9 typ host",
                    "sdpMid": "",
                    "sdpMLineIndex": 0,
                    "usernameFragment": null
                }
            }),
            "protocol-test",
        )
        .unwrap_err();
    assert!(
        closed.contains("unknown stream session"),
        "closed session must not accept ice, got {closed}"
    );

    let second = Arc::new(ProtocolSignal::new(
        handler.clone(),
        Duration::ZERO,
        None,
        false,
        false,
        false,
    ));
    let viewer = Viewer::connect(
        second.clone(),
        LiveOptions {
            viewer: "protocol-test".into(),
            control: false,
            ..LiveOptions::default()
        },
    )
    .expect("second offer");
    let new_session = viewer.info().session_id.clone();
    assert_ne!(
        old_session, new_session,
        "recovery must use a new session id"
    );
    assert!(
        wait_for_idr(&viewer),
        "new generation must deliver H.264 after the previous session closed"
    );
    assert!(wait_for_selected_pair(&viewer).is_some());
    viewer.close();
}
