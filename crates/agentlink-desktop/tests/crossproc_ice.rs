//! Cross-process webrtc_signal fixture: parent runs Viewer, child runs the
//! real StreamHandler. Same machine, isolated mock desktop, no production
//! identity or grant. This is not a public-network P2P result.

use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use agentlink_view::{access_unit_is_idr, LiveOptions, Signal, Viewer};
use serde_json::{json, Value};

struct Fixture {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Fixture {
    fn rpc(&mut self, payload: &Value) -> Result<Value, String> {
        let line = serde_json::to_string(payload).map_err(|err| err.to_string())?;
        self.stdin
            .write_all(line.as_bytes())
            .map_err(|err| err.to_string())?;
        self.stdin.write_all(b"\n").map_err(|err| err.to_string())?;
        self.stdin.flush().map_err(|err| err.to_string())?;
        let mut reply = String::new();
        self.stdout
            .read_line(&mut reply)
            .map_err(|err| err.to_string())?;
        let value: Value = serde_json::from_str(&reply).map_err(|err| err.to_string())?;
        if value.get("ok").and_then(Value::as_bool) == Some(true) {
            Ok(value.get("result").cloned().unwrap_or(json!(true)))
        } else {
            Err(value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("fixture error")
                .to_string())
        }
    }
}

struct FixtureSignal {
    inner: Mutex<Fixture>,
}

impl Signal for FixtureSignal {
    fn signal(&self, payload: &Value) -> Result<Value, String> {
        self.inner
            .lock()
            .map_err(|err| err.to_string())?
            .rpc(payload)
    }
}

fn spawn_fixture() -> (std::process::Child, FixtureSignal) {
    let exe = env!("CARGO_BIN_EXE_agentlink-stream-fixture");
    let mut child = Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fixture");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let signal = FixtureSignal {
        inner: Mutex::new(Fixture {
            stdin,
            stdout: BufReader::new(stdout),
        }),
    };
    (child, signal)
}

#[test]
fn cross_process_fixture_selects_a_pair_and_delivers_h264() {
    let (mut child, signal) = spawn_fixture();
    let signal = std::sync::Arc::new(signal);
    let viewer = Viewer::connect(
        signal.clone(),
        LiveOptions {
            viewer: "fixture".into(),
            control: false,
            ..LiveOptions::default()
        },
    )
    .expect("offer");
    assert!(
        viewer.info().session_id.contains('-'),
        "session id should be unique, got {}",
        viewer.info().session_id
    );

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut idr = false;
    while Instant::now() < deadline {
        if viewer.failed() {
            break;
        }
        if let Some(frame) = viewer.poll_frame(Duration::from_millis(200)) {
            if frame.keyframe && access_unit_is_idr(&frame.annex_b) {
                idr = true;
                break;
            }
        }
    }
    let mut snap = viewer.transport();
    let path_deadline = Instant::now() + Duration::from_secs(5);
    while snap.is_none() && Instant::now() < path_deadline {
        std::thread::sleep(Duration::from_millis(50));
        snap = viewer.transport();
    }
    eprintln!(
        "agentlink live-protocol: cross-process idr={idr} pair={snap:?} ice={}",
        viewer.ice_checks()
    );
    assert!(idr, "cross-process fixture must deliver an H.264 IDR");
    let snap = snap.expect("selected ICE pair required");
    assert!(
        matches!(snap.path.as_str(), "loopback" | "private" | "host"),
        "unexpected path {snap:?}"
    );
    assert_ne!(snap.path, "relay");
    let session = viewer.info().session_id.clone();
    viewer.close();

    let stale = signal.signal(&json!({
        "action": "ice",
        "session_id": session,
        "candidate": {
            "candidate": "candidate:1 1 udp 2130706431 192.0.2.1 9 typ host",
            "sdpMid": "",
            "sdpMLineIndex": 0,
            "usernameFragment": null
        }
    }));
    assert!(
        stale
            .as_ref()
            .err()
            .is_some_and(|err| err.contains("unknown stream session")),
        "closed fixture session must reject ice, got {stale:?}"
    );
    drop(signal);
    let _ = child.wait();
}
