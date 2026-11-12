//! Isolated webrtc_signal fixture for local protocol tests.
//!
//! JSON lines on stdin, JSON lines on stdout. Uses `Desktop::mock()`,
//! auto consent, and a throwaway audit file. It does not load production
//! identity, sign grants, or listen on a network port.
//!
//! This binary is a test helper, not the production node or Controller
//! entrypoint. `ConsentMode::Auto` is set only here (and in in-process
//! test harnesses). The production node default in `node_cfg` is
//! `notify`. `StreamHandler::new` starts at `Deny`. `fixture_inject_late`
//! is implemented in this bin only; it is not a `webrtc_signal` action.

use std::io::{self, BufRead, Write};
use std::sync::Arc;

use agentlink_core::{NodeExtension, NodePolicy};
use agentlink_desktop::{ConsentMode, Desktop, StreamHandler, StreamSettings};
use serde_json::{json, Value};

fn main() {
    let handler = Arc::new(StreamHandler::new(Desktop::mock()));
    handler.configure(StreamSettings {
        policy: NodePolicy::remote_view(),
        audit_path: std::env::temp_dir().join("agentlink-stream-fixture-audit.log"),
        consent: ConsentMode::Auto,
        on_audit: None,
    
            grant_active: None,
        });

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) if !line.trim().is_empty() => line,
            Ok(_) => continue,
            Err(_) => break,
        };
        let payload: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(err) => {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({"ok": false, "error": format!("invalid json ({err})")})
                );
                let _ = stdout.flush();
                continue;
            }
        };
        let action = payload.get("action").and_then(Value::as_str).unwrap_or("");
        let reply = if action == "fixture_inject_late" {
            let session = payload
                .get("session_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let candidate = payload.get("candidate").cloned().unwrap_or(Value::Null);
            match handler.inject_gathered_candidate(session, candidate) {
                Ok(()) => json!({"ok": true}),
                Err(err) => json!({"ok": false, "error": err}),
            }
        } else {
            match handler.handle_peer(&payload, "fixture") {
                Ok(result) => json!({"ok": true, "result": result}),
                Err(err) => json!({"ok": false, "error": err}),
            }
        };
        let _ = writeln!(stdout, "{reply}");
        let _ = stdout.flush();
    }
}
