//! Cross-platform PTY sessions via portable-pty.
//!
//! The CLI drives a raw local terminal. This module owns the remote process,
//! captures a size-capped transcript, and writes one `pty_session` audit record
//! when the process exits. Keystrokes are not logged.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::audit::{self, Origin};
#[cfg(not(windows))]
use crate::ops::shell_parts;
use crate::ops::Responder;
use crate::pipeline::AuditService;
use crate::proc::push_capped;
use agentlink_core::util;
use agentlink_core::{Error, Result};
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};

struct LivePty {
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    owner_peer: String,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
}

pub type PtyGrantHook = Arc<dyn Fn(&str) -> bool + Send + Sync>;

#[derive(Clone, Default)]
pub struct PtyManager {
    sessions: Arc<Mutex<HashMap<String, LivePty>>>,
    grant_active: Arc<RwLock<Option<PtyGrantHook>>>,
}

impl PtyManager {
    pub fn set_grant_active(&self, hook: Option<PtyGrantHook>) {
        if let Ok(mut slot) = self.grant_active.write() {
            *slot = hook;
        }
    }

    fn grant_hook(&self) -> Option<PtyGrantHook> {
        self.grant_active
            .read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open(
        &self,
        command: Option<String>,
        cwd: Option<PathBuf>,
        rows: u16,
        cols: u16,
        resp: Responder,
        origin: Origin,
        agent: Option<String>,
        service: Arc<AuditService>,
        owner_peer: &str,
        grant_jti: &str,
        grant_exp_unix: Option<i64>,
    ) -> Result<String> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let owner_peer = owner_peer.to_string();
        let grant_jti = grant_jti.trim().to_string();
        let (rows, cols) = normalize_pty_size(rows, cols);
        let started = Instant::now();
        let command_line = command.clone().unwrap_or_else(default_shell);
        let cwd_display = cwd.as_ref().map(|path| path.display().to_string());
        let system = native_pty_system();
        let pair = system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| Error::Message(format!("openpty: {e}")))?;

        #[allow(unused_mut)]
        let mut windows_pty_script: Option<PathBuf> = None;
        let mut cmd = match command {
            Some(line) => {
                #[cfg(windows)]
                {
                    // portable-pty has no raw_arg; argv quoting would mangle user
                    // quotes. Run the line from a temp .cmd instead.
                    let bat = windows_pty_script_path(&session_id);
                    std::fs::write(&bat, format!("{line}\r\n"))
                        .map_err(|e| Error::Message(format!("pty script: {e}")))?;
                    windows_pty_script = Some(bat.clone());
                    let mut cmd = CommandBuilder::new("cmd.exe");
                    cmd.arg("/D");
                    cmd.arg("/C");
                    cmd.arg(&bat);
                    cmd
                }
                #[cfg(not(windows))]
                {
                    let (program, args) = shell_parts(&line);
                    let mut cmd = CommandBuilder::new(program);
                    for arg in args {
                        cmd.arg(arg);
                    }
                    cmd
                }
            }
            None => CommandBuilder::new(default_shell()),
        };
        if let Some(dir) = cwd {
            cmd.cwd(dir);
        }
        apply_interactive_term(&mut cmd);
        cmd.env("AGENTLINK_REMOTE_EXEC", "1");

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| Error::Message(format!("pty spawn: {e}")))?;
        drop(pair.slave);

        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| Error::Message(format!("pty reader: {e}")))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| Error::Message(format!("pty writer: {e}")))?;
        let killer = child.clone_killer();
        let master: Arc<Mutex<Box<dyn MasterPty + Send>>> = Arc::new(Mutex::new(pair.master));

        {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| Error::Message("pty map poisoned".into()))?;
            sessions.insert(
                session_id.to_string(),
                LivePty {
                    master,
                    writer: Arc::new(Mutex::new(writer)),
                    killer,
                    owner_peer: owner_peer.clone(),
                    grant_jti: grant_jti.clone(),
                    grant_exp_unix,
                },
            );
        }

        // Queue the ack before any output frame. The child may already have
        // exited; its bytes sit in the PTY buffer until the reader starts.
        if let Err(err) = resp
            .ack(serde_json::json!({
                "session_id": session_id,
                "rows": rows,
                "cols": cols,
            }))
            .await
        {
            self.close(&session_id, None).ok();
            tokio::task::spawn_blocking(move || {
                let _ = child.wait();
            });
            return Err(err);
        }

        // Re-check after the session is visible: a revoke that landed during
        // spawn must still close it.
        if let Err(err) = self.check_session(&session_id, Some(&owner_peer)) {
            self.close(&session_id, None).ok();
            tokio::task::spawn_blocking(move || {
                let _ = child.wait();
            });
            return Err(err);
        }

        let request_id = resp.request_id.clone();
        let resp_reader = resp.clone();
        let transcript = Arc::new(Mutex::new(Vec::<u8>::new()));
        let capture = transcript.clone();
        // Finish reading the PTY before the exit event. `child.wait` can
        // return while the last bytes are still in the master buffer, and the
        // client stops on exit. A dead relay socket does not stop the read:
        // frames stay in the replay ring until the node redials.
        let reader_done = tokio::task::spawn_blocking(move || {
            let mut reader = reader;
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        push_capped(&capture, &buf[..n], audit::OUTPUT_CAP);
                        if let Ok(mut extra) = resp_reader.extra.lock() {
                            extra.push_stream("pty", &buf[..n]);
                        }
                        let env = agentlink_core::Envelope::Chunk {
                            request_id: request_id.clone(),
                            stream: "pty".into(),
                            data_b64: util::b64_encode(&buf[..n]),
                            seq: 0,
                        };
                        resp_reader.emit_blocking(&env);
                    }
                }
            }
        });

        let sessions = self.sessions.clone();
        let id = session_id.to_string();
        tokio::spawn(async move {
            let status = tokio::task::spawn_blocking(move || child.wait()).await;
            // ConPTY often keeps the master readable open after the child exits,
            // so the reader never sees EOF and `shell --command` hangs forever.
            // Dropping the live session closes the master/writer and unblocks it.
            {
                if let Ok(mut map) = sessions.lock() {
                    map.remove(&id);
                }
            }
            if let Some(bat) = windows_pty_script {
                let _ = std::fs::remove_file(bat);
            }
            let _ = reader_done.await;
            let (code, error) = match status {
                Ok(Ok(status)) => (Some(status.exit_code() as i32), None),
                Ok(Err(err)) => (None, Some(err.to_string())),
                Err(err) => (None, Some(err.to_string())),
            };
            let bytes = transcript.lock().map(|buf| buf.clone()).unwrap_or_default();
            let _ = origin;
            let mut event = audit::event_for(
                "pty",
                "pty_session",
                agent.as_deref().unwrap_or(""),
                &command_line,
                serde_json::json!({
                    "command": &command_line,
                    "cwd": &cwd_display,
                    "detail": &command_line,
                }),
                error.is_none(),
                error.clone(),
                started.elapsed(),
            );
            event.command = Some(command_line);
            event.cwd = cwd_display;
            event.exit_code = code;
            event.transcript = Some(bytes);
            event.session_id = Some(id.clone());
            service.submit(event);
            let _ = resp.end(code, error).await;
        });
        Ok(session_id)
    }

    pub fn write(&self, session_id: &str, data: &[u8], peer: &str) -> Result<()> {
        let writer = {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_| Error::Message("pty map poisoned".into()))?;
            let live = sessions
                .get(session_id)
                .ok_or_else(|| Error::NotFound(format!("pty session {session_id}")))?;
            require_pty_access(live, Some(peer), self.grant_hook().as_deref())?;
            live.writer.clone()
        };
        let mut guard = writer
            .lock()
            .map_err(|_| Error::Message("pty writer poisoned".into()))?;
        guard.write_all(data)?;
        guard.flush()?;
        Ok(())
    }

    pub fn resize(&self, session_id: &str, rows: u16, cols: u16, peer: &str) -> Result<()> {
        let master = {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_| Error::Message("pty map poisoned".into()))?;
            let live = sessions
                .get(session_id)
                .ok_or_else(|| Error::NotFound(format!("pty session {session_id}")))?;
            require_pty_access(live, Some(peer), self.grant_hook().as_deref())?;
            live.master.clone()
        };
        let guard = master
            .lock()
            .map_err(|_| Error::Message("pty master poisoned".into()))?;
        guard
            .resize(PtySize {
                rows: rows.max(1),
                cols: cols.max(1),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| Error::Message(format!("pty resize: {e}")))?;
        Ok(())
    }

    pub fn close(&self, session_id: &str, peer: Option<&str>) -> Result<()> {
        let mut live = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| Error::Message("pty map poisoned".into()))?;
            if let Some(existing) = sessions.get(session_id) {
                // Owner may tear down after expiry or revoke; those states
                // still deny write/resize. A mismatched peer cannot close.
                require_pty_owner(&existing.owner_peer, peer)?;
            }
            sessions.remove(session_id)
        };
        if let Some(live) = live.as_mut() {
            live.killer.kill().ok();
        }
        Ok(())
    }

    pub fn close_for_jti(&self, jti: &str) -> usize {
        let jti = jti.trim();
        if jti.is_empty() {
            return 0;
        }
        let victims = {
            let mut sessions = match self.sessions.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let ids: Vec<String> = sessions
                .iter()
                .filter(|(_, live)| live.grant_jti.trim().eq_ignore_ascii_case(jti))
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| sessions.remove(&id))
                .collect::<Vec<_>>()
        };
        let n = victims.len();
        for mut live in victims {
            live.killer.kill().ok();
        }
        n
    }

    pub fn close_expired(&self) -> usize {
        let now = agentlink_core::util::unix_now();
        let victims = {
            let mut sessions = match self.sessions.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let ids: Vec<String> = sessions
                .iter()
                .filter(|(_, live)| live.grant_exp_unix.is_some_and(|exp| now >= exp))
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| sessions.remove(&id))
                .collect::<Vec<_>>()
        };
        let n = victims.len();
        for mut live in victims {
            live.killer.kill().ok();
        }
        n
    }

    fn check_session(&self, session_id: &str, peer: Option<&str>) -> Result<()> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| Error::Message("pty map poisoned".into()))?;
        let live = sessions
            .get(session_id)
            .ok_or_else(|| Error::NotFound(format!("pty session {session_id}")))?;
        require_pty_access(live, peer, self.grant_hook().as_deref())
    }

    /// Close sessions whose stored grant is revoked or expired, without
    /// consulting an inflight-RPC index.
    pub fn close_inactive(&self, revoked: &std::collections::BTreeSet<String>) -> usize {
        let hook = self.grant_hook();
        let now = agentlink_core::util::unix_now();
        let victims = {
            let mut sessions = match self.sessions.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let ids: Vec<String> = sessions
                .iter()
                .filter(|(_, live)| pty_session_inactive(live, revoked, hook.as_deref(), now))
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| sessions.remove(&id))
                .collect::<Vec<_>>()
        };
        let n = victims.len();
        for mut live in victims {
            live.killer.kill().ok();
        }
        n
    }

    pub fn has_session(&self, id: &str) -> bool {
        let sessions = match self.sessions.lock() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        sessions.contains_key(id)
    }

    pub fn close_all(&self) {
        let sessions = match self.sessions.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(poison) => std::mem::take(&mut *poison.into_inner()),
        };
        for (_, mut live) in sessions {
            live.killer.kill().ok();
        }
    }
}

fn require_pty_owner(owner_peer: &str, peer: Option<&str>) -> Result<()> {
    if let Some(peer) = peer {
        if owner_peer != peer {
            return Err(Error::NotFound(
                "pty session not found for this peer".into(),
            ));
        }
    }
    Ok(())
}

fn require_pty_access(
    live: &LivePty,
    peer: Option<&str>,
    hook: Option<&(dyn Fn(&str) -> bool + Send + Sync)>,
) -> Result<()> {
    require_pty_owner(&live.owner_peer, peer)?;
    pty_access_error(
        &live.owner_peer,
        &live.grant_jti,
        live.grant_exp_unix,
        None, // owner already checked
        hook,
    )
}

fn pty_session_inactive(
    live: &LivePty,
    revoked: &std::collections::BTreeSet<String>,
    hook: Option<&(dyn Fn(&str) -> bool + Send + Sync)>,
    now: i64,
) -> bool {
    if live.grant_exp_unix.is_some_and(|exp| now >= exp) {
        return true;
    }
    let jti = live.grant_jti.trim();
    if !jti.is_empty()
        && revoked
            .iter()
            .any(|item| item.trim().eq_ignore_ascii_case(jti))
    {
        return true;
    }
    if let Some(hook) = hook {
        if jti.is_empty() || !hook(jti) {
            return true;
        }
    }
    false
}

fn pty_access_error(
    owner_peer: &str,
    grant_jti: &str,
    grant_exp_unix: Option<i64>,
    peer: Option<&str>,
    hook: Option<&(dyn Fn(&str) -> bool + Send + Sync)>,
) -> Result<()> {
    if let Some(peer) = peer {
        if owner_peer != peer {
            return Err(Error::NotFound(
                "pty session not found for this peer".into(),
            ));
        }
    }
    if let Some(exp) = grant_exp_unix {
        if agentlink_core::util::unix_now() >= exp {
            return Err(Error::Auth("grant expired".into()));
        }
    }
    if let Some(hook) = hook {
        let jti = grant_jti.trim();
        if jti.is_empty() {
            return Err(Error::Auth("grant is required".into()));
        }
        if !hook(jti) {
            return Err(Error::Auth("grant was revoked".into()));
        }
    }
    Ok(())
}

/// Windows temp script name uses only a UUID stem. Client request ids, path
/// separators, and `..` never reach `temp_dir().join`.
fn windows_pty_script_path(session_id: &str) -> PathBuf {
    let stem = safe_pty_script_stem(session_id);
    std::env::temp_dir().join(format!("agentlink-pty-{stem}.cmd"))
}

fn safe_pty_script_stem(session_id: &str) -> String {
    let trimmed = session_id.trim();
    if uuid::Uuid::parse_str(trimmed).is_ok() {
        return trimmed.to_ascii_lowercase();
    }
    uuid::Uuid::new_v4().to_string()
}

fn default_shell() -> String {
    if cfg!(windows) {
        "cmd.exe".into()
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
    }
}

/// Dashboard / xterm.js clients need a real terminal type. Daemons often inherit
/// `TERM=dumb` (or none) from systemd/service managers; interactive apps like
/// `top` then refuse to draw. Keep any already-useful TERM the parent set.
fn apply_interactive_term(cmd: &mut CommandBuilder) {
    let current = cmd
        .get_env("TERM")
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if needs_default_term(current) {
        cmd.env("TERM", "xterm-256color");
    }
}

fn needs_default_term(term: &str) -> bool {
    term.is_empty() || term.eq_ignore_ascii_case("dumb")
}

/// `pty_open` historically floored missing sizes to 1×1, which breaks full-screen
/// apps. Treat 0/1 as "unset" and use a classic 24×80 default.
fn normalize_pty_size(rows: u16, cols: u16) -> (u16, u16) {
    let rows = if rows <= 1 { 24 } else { rows };
    let cols = if cols <= 1 { 80 } else { cols };
    (rows, cols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_term_when_missing_or_dumb() {
        assert!(needs_default_term(""));
        assert!(needs_default_term("dumb"));
        assert!(needs_default_term("DUMB"));
        assert!(!needs_default_term("xterm-256color"));
        assert!(!needs_default_term("xterm"));
        assert!(!needs_default_term("screen-256color"));
        assert!(!needs_default_term("vt100"));
    }

    #[test]
    fn apply_interactive_term_sets_xterm_when_base_is_dumb() {
        let mut cmd = CommandBuilder::new("sh");
        cmd.env("TERM", "dumb");
        apply_interactive_term(&mut cmd);
        cmd.env("AGENTLINK_REMOTE_EXEC", "1");
        assert_eq!(
            cmd.get_env("TERM").and_then(|v| v.to_str()),
            Some("xterm-256color")
        );
    }

    #[test]
    fn apply_interactive_term_preserves_real_term() {
        let mut cmd = CommandBuilder::new("sh");
        cmd.env("TERM", "screen-256color");
        apply_interactive_term(&mut cmd);
        cmd.env("AGENTLINK_REMOTE_EXEC", "1");
        assert_eq!(
            cmd.get_env("TERM").and_then(|v| v.to_str()),
            Some("screen-256color")
        );
    }

    #[test]
    fn normalize_size_replaces_missing_or_one() {
        assert_eq!(normalize_pty_size(0, 0), (24, 80));
        assert_eq!(normalize_pty_size(1, 1), (24, 80));
        assert_eq!(normalize_pty_size(0, 120), (24, 120));
        assert_eq!(normalize_pty_size(40, 1), (40, 80));
        assert_eq!(normalize_pty_size(30, 100), (30, 100));
    }

    #[test]
    fn windows_pty_script_path_rejects_traversal_and_uses_uuid() {
        let id = uuid::Uuid::new_v4().to_string();
        let path = windows_pty_script_path(&id);
        assert_eq!(path.parent(), Some(std::env::temp_dir().as_path()));
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("agentlink-pty-"));
        assert!(path.extension().and_then(|e| e.to_str()) == Some("cmd"));
        let bad = windows_pty_script_path("..\\..\\evil");
        assert_eq!(bad.parent(), Some(std::env::temp_dir().as_path()));
        let name = bad.file_name().unwrap().to_string_lossy();
        assert!(!name.contains("evil"), "{name}");
        assert!(!name.contains(".."), "{name}");
        assert!(uuid::Uuid::parse_str(
            name.trim_start_matches("agentlink-pty-")
                .trim_end_matches(".cmd")
        )
        .is_ok());
    }

    #[test]
    fn alice_cannot_access_bobs_pty_record() {
        let err = pty_access_error("bob", "jti-b", None, Some("alice"), None).unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
        pty_access_error("bob", "jti-b", None, Some("bob"), None).unwrap();
        pty_access_error("bob", "jti-b", None, None, None).unwrap();
        let err = pty_access_error(
            "bob",
            "jti-b",
            Some(agentlink_core::util::unix_now() - 5),
            Some("bob"),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        let hook = |jti: &str| jti != "revoked";
        let err = pty_access_error("bob", "revoked", None, Some("bob"), Some(&hook)).unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");
        pty_access_error("bob", "still-good", None, Some("bob"), Some(&hook)).unwrap();
    }

    fn test_responder() -> (crate::ops::Responder, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let resp = crate::ops::Responder {
            socket: std::sync::Arc::new(crate::resume::SocketSlot::default()),
            request_id: uuid::Uuid::new_v4().to_string(),
            seal: None,
            extra: std::sync::Arc::new(std::sync::Mutex::new(
                crate::pipeline::AuditExtra::default(),
            )),
            log: std::sync::Arc::new(crate::resume::ReplayLog::default()),
        };
        (resp, dir)
    }

    #[tokio::test]
    async fn real_pty_entry_enforces_owner_and_revoked_grant() {
        let mgr = PtyManager::default();
        mgr.set_grant_active(Some(std::sync::Arc::new(|jti: &str| jti != "revoked")));
        let (resp, dir) = test_responder();
        let service = crate::pipeline::AuditService::open_quiet(dir.path(), "node", "box");
        let origin = crate::audit::Origin {
            path: dir.path().join("audit.log"),
            node: "box".into(),
            node_id: "node".into(),
        };
        let bob = mgr
            .open(
                Some("cat".into()),
                None,
                24,
                80,
                resp,
                origin,
                Some("bob".into()),
                service,
                "bob",
                "jti-bob",
                None,
            )
            .await
            .expect("bob open");
        assert!(uuid::Uuid::parse_str(&bob).is_ok(), "{bob}");
        let err = mgr.write(&bob, b"x", "alice").unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
        mgr.write(&bob, b"from-bob\n", "bob").expect("owner write");
        mgr.resize(&bob, 30, 100, "bob").expect("owner resize");
        let err = mgr.resize(&bob, 30, 100, "alice").unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");

        let (resp2, dir2) = test_responder();
        let service2 = crate::pipeline::AuditService::open_quiet(dir2.path(), "node", "box");
        let origin2 = crate::audit::Origin {
            path: dir2.path().join("audit.log"),
            node: "box".into(),
            node_id: "node".into(),
        };
        let revoked = mgr
            .open(
                Some("cat".into()),
                None,
                24,
                80,
                resp2,
                origin2,
                Some("bob".into()),
                service2,
                "bob",
                "revoked",
                None,
            )
            .await;
        assert!(revoked.is_err(), "open must re-check a revoked grant");

        // A session that becomes revoked after open is closed by metadata sweep.
        let mut revoked_set = std::collections::BTreeSet::new();
        revoked_set.insert("jti-bob".into());
        assert_eq!(mgr.close_inactive(&revoked_set), 1);
        let err = mgr.write(&bob, b"x", "bob").unwrap_err();
        assert!(
            err.to_string().contains("not found") || err.to_string().contains("pty session"),
            "{err}"
        );
    }

    fn pty_transcript(resp: &crate::ops::Responder) -> String {
        let extra = resp.extra.lock().unwrap_or_else(|err| err.into_inner());
        String::from_utf8_lossy(&extra.transcript).replace('\r', "")
    }

    fn pty_exit(resp: &crate::ops::Responder) -> Option<i32> {
        resp.extra
            .lock()
            .ok()
            .and_then(|extra| extra.exit_code)
            .or_else(|| {
                resp.log
                    .snapshot()
                    .into_iter()
                    .rev()
                    .find_map(|env| match env {
                        agentlink_core::Envelope::End { exit_code, .. } => exit_code,
                        _ => None,
                    })
            })
    }

    async fn wait_transcript_contains(
        resp: &crate::ops::Responder,
        needle: &str,
        timeout: std::time::Duration,
    ) -> String {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let text = pty_transcript(resp);
            if text.contains(needle) {
                return text;
            }
            if std::time::Instant::now() >= deadline {
                return text;
            }
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        }
    }

    async fn wait_exit(resp: &crate::ops::Responder, timeout: std::time::Duration) -> Option<i32> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(code) = pty_exit(resp) {
                return Some(code);
            }
            if std::time::Instant::now() >= deadline {
                return pty_exit(resp);
            }
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        }
    }

    #[tokio::test]
    async fn real_pty_emits_unicode_output() {
        let mgr = PtyManager::default();
        let (resp, dir) = test_responder();
        let service = crate::pipeline::AuditService::open_quiet(dir.path(), "node", "box");
        let origin = crate::audit::Origin {
            path: dir.path().join("audit.log"),
            node: "box".into(),
            node_id: "node".into(),
        };
        let sid = mgr
            .open(
                Some("cat".into()),
                None,
                24,
                80,
                resp.clone(),
                origin,
                Some("alice".into()),
                service,
                "alice",
                "jti-unicode",
                None,
            )
            .await
            .expect("open cat pty");
        mgr.write(&sid, "你好\n".as_bytes(), "alice")
            .expect("write unicode");
        let text = wait_transcript_contains(&resp, "你好", std::time::Duration::from_secs(3)).await;
        let _ = mgr.close(&sid, Some("alice"));
        assert!(
            text.contains("你好"),
            "PTY must emit the UTF-8 written to the session, got {text:?}"
        );
    }

    /// Drop CSI / ESC sequences so a wait or parse cannot treat a host-side
    /// `ESC[8;30;100t` resize advertisement as the child's reported size.
    fn strip_csi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' && chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() || d == '@' {
                        break;
                    }
                }
            } else if c != '\u{1b}' {
                out.push(c);
            } else if chars.peek() == Some(&']') {
                chars.next();
                while let Some(d) = chars.next() {
                    if d == '\u{7}' {
                        break;
                    }
                    if d == '\\' {
                        continue;
                    }
                    if d == '\u{1b}' {
                        let _ = chars.next();
                        break;
                    }
                }
            } else {
                let _ = chars.next();
            }
        }
        out
    }

    fn transcript_lines_from(raw: &str) -> Vec<String> {
        strip_csi(raw)
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect()
    }

    fn has_sentinel_line(lines: &[String], sentinel: &str) -> bool {
        lines
            .iter()
            .any(|line| line == sentinel || line.starts_with(&format!("{sentinel} ")))
    }

    async fn wait_transcript_sentinel(
        resp: &crate::ops::Responder,
        sentinel: &str,
        timeout: std::time::Duration,
    ) -> String {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let raw = pty_transcript(resp);
            if has_sentinel_line(&transcript_lines_from(&raw), sentinel) {
                return raw;
            }
            if std::time::Instant::now() >= deadline {
                return raw;
            }
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ChildSize {
        buf_cols: Option<i32>,
        buf_rows: Option<i32>,
        win_cols: i32,
        win_rows: i32,
    }

    fn parse_tagged_i32(line: &str, key: &str) -> Option<i32> {
        let token = format!("{key}=");
        let start = line.find(&token)?;
        let rest = &line[start + token.len()..];
        let value = rest.split_whitespace().next().unwrap_or(rest);
        value.parse().ok()
    }

    fn parse_size_report(raw: &str, tag: &str) -> Option<ChildSize> {
        let line = transcript_lines_from(raw)
            .into_iter()
            .find(|line| line.starts_with(tag))?;
        let win_cols = parse_tagged_i32(&line, "srWindow.cols")
            .or_else(|| parse_tagged_i32(&line, "winsize.cols"))?;
        let win_rows = parse_tagged_i32(&line, "srWindow.rows")
            .or_else(|| parse_tagged_i32(&line, "winsize.rows"))?;
        Some(ChildSize {
            buf_cols: parse_tagged_i32(&line, "dwSize.X"),
            buf_rows: parse_tagged_i32(&line, "dwSize.Y"),
            win_cols,
            win_rows,
        })
    }

    /// Windows child: a tiny rustc program that calls GetConsoleScreenBufferInfo
    /// and prints dwSize / srWindow separately. Avoids `mode con` localization
    /// and cmd.exe script echo/redraw loops.
    const WINDOWS_SIZE_REPORTER_SRC: &str = r#"
use std::io::{Read, Write};

#[repr(C)]
struct Coord { x: i16, y: i16 }
#[repr(C)]
struct SmallRect { left: i16, top: i16, right: i16, bottom: i16 }
#[repr(C)]
struct ConsoleScreenBufferInfo {
    dw_size: Coord,
    dw_cursor_position: Coord,
    w_attributes: u16,
    sr_window: SmallRect,
    dw_maximum_window_size: Coord,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetStdHandle(nstdhandle: i32) -> *mut core::ffi::c_void;
    fn GetConsoleScreenBufferInfo(
        hconsoleoutput: *mut core::ffi::c_void,
        lpconsolescreenbufferinfo: *mut ConsoleScreenBufferInfo,
    ) -> i32;
}

const STD_OUTPUT_HANDLE: i32 = -11;

fn invalid_handle(h: *mut core::ffi::c_void) -> bool {
    h.is_null() || h as isize == -1
}

fn report(tag: &str) {
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut info = std::mem::zeroed();
        if invalid_handle(h) || GetConsoleScreenBufferInfo(h, &mut info) == 0 {
            let _ = writeln!(std::io::stdout(), "{tag} ERR GetConsoleScreenBufferInfo");
            let _ = std::io::stdout().flush();
            return;
        }
        let win_cols = i32::from(info.sr_window.right - info.sr_window.left + 1);
        let win_rows = i32::from(info.sr_window.bottom - info.sr_window.top + 1);
        let _ = writeln!(
            std::io::stdout(),
            "{tag} dwSize.X={} dwSize.Y={} srWindow.cols={} srWindow.rows={}",
            info.dw_size.x,
            info.dw_size.y,
            win_cols,
            win_rows
        );
        let _ = std::io::stdout().flush();
    }
}

fn main() {
    report("AL_SIZE_BEFORE");
    let _ = writeln!(std::io::stdout(), "AL_READY");
    let _ = std::io::stdout().flush();
    // Wait for Enter. Windows cooked input typically delivers CR; Unix LF.
    let mut byte = [0u8; 1];
    loop {
        match std::io::stdin().read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) if byte[0] == b'\r' || byte[0] == b'\n' => break,
            Ok(_) => {}
        }
    }
    report("AL_SIZE_AFTER");
    let _ = writeln!(std::io::stdout(), "AL_DONE");
    let _ = std::io::stdout().flush();
}
"#;

    fn compile_windows_size_reporter(dir: &std::path::Path) -> String {
        let src = dir.join("report_con_size.rs");
        let exe = dir.join("report_con_size.exe");
        std::fs::write(&src, WINDOWS_SIZE_REPORTER_SRC).expect("write size reporter source");
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| std::ffi::OsString::from("rustc"));
        let out = std::process::Command::new(&rustc)
            .args(["--edition", "2021", "-O", "-o"])
            .arg(&exe)
            .arg(&src)
            .output()
            .unwrap_or_else(|err| panic!("spawn rustc ({rustc:?}) for size reporter: {err}"));
        assert!(
            out.status.success(),
            "rustc size reporter failed: status={:?} stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        format!("\"{}\"", exe.display())
    }

    fn unix_size_reporter(dir: &std::path::Path) -> String {
        let path = dir.join("report-size.sh");
        std::fs::write(
            &path,
            "#!/bin/sh\n\
set -e\n\
report() {\n\
  tag=$1\n\
  # stty size prints \"rows cols\". There is no separate dwSize; report the\n\
  # same TIOCGWINSZ as winsize.* (the Unix equivalent of srWindow).\n\
  size=$(stty size)\n\
  rows=${size% *}\n\
  cols=${size#* }\n\
  printf '%s winsize.cols=%s winsize.rows=%s\\n' \"$tag\" \"$cols\" \"$rows\"\n\
}\n\
report AL_SIZE_BEFORE\n\
printf 'AL_READY\\n'\n\
IFS= read -r _\n\
report AL_SIZE_AFTER\n\
printf 'AL_DONE\\n'\n",
        )
        .expect("write unix size reporter");
        format!("sh '{}'", path.display())
    }

    #[tokio::test]
    async fn real_pty_resize_changes_child_winsize() {
        let mgr = PtyManager::default();
        let (resp, dir) = test_responder();
        let service = crate::pipeline::AuditService::open_quiet(dir.path(), "node", "box");
        let origin = crate::audit::Origin {
            path: dir.path().join("audit.log"),
            node: "box".into(),
            node_id: "node".into(),
        };
        // Do not use `mode con` (localized) or wait for a bare "30", which is
        // satisfied by ConPTY's host-side CSI `ESC[8;30;100t` and is not a
        // child GetConsoleScreenBufferInfo / TIOCGWINSZ reading.
        let script = if cfg!(windows) {
            compile_windows_size_reporter(dir.path())
        } else {
            unix_size_reporter(dir.path())
        };
        let sid = mgr
            .open(
                Some(script),
                None,
                24,
                80,
                resp.clone(),
                origin,
                Some("alice".into()),
                service,
                "alice",
                "jti-resize",
                None,
            )
            .await
            .expect("open size pty");
        let ready =
            wait_transcript_sentinel(&resp, "AL_READY", std::time::Duration::from_secs(8)).await;
        assert!(
            has_sentinel_line(&transcript_lines_from(&ready), "AL_READY"),
            "child did not print the AL_READY sentinel, got {ready:?}"
        );
        let before = parse_size_report(&ready, "AL_SIZE_BEFORE").unwrap_or_else(|| {
            panic!("child must report structured size before resize, got {ready:?}")
        });
        assert_eq!(
            (before.win_cols, before.win_rows),
            (80, 24),
            "srWindow/winsize before resize, dwSize={:?}x{:?}, got {ready:?}",
            before.buf_cols,
            before.buf_rows
        );
        mgr.resize(&sid, 30, 100, "alice").expect("resize");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // Windows cooked console input completes a line on CR (Enter).
        // A bare LF is not a reliable wake there and must not be used as
        // the handshake. Unix line reads still use LF.
        let wake: &[u8] = if cfg!(windows) { b"\r\n" } else { b"\n" };
        mgr.write(&sid, wake, "alice")
            .expect("signal after resize");
        let text =
            wait_transcript_sentinel(&resp, "AL_DONE", std::time::Duration::from_secs(8)).await;
        let _ = mgr.close(&sid, Some("alice"));
        assert!(
            has_sentinel_line(&transcript_lines_from(&text), "AL_DONE"),
            "child did not finish the size handshake, got {text:?}"
        );
        let after = parse_size_report(&text, "AL_SIZE_AFTER").unwrap_or_else(|| {
            panic!("child must report structured size after resize, got {text:?}")
        });
        assert_eq!(
            (after.win_cols, after.win_rows),
            (100, 30),
            "srWindow/winsize after resize must be the new size (not a host CSI), dwSize={:?}x{:?}, got {text:?}",
            after.buf_cols,
            after.buf_rows
        );
    }

    #[tokio::test]
    async fn real_pty_reports_nonzero_exit_code() {
        let mgr = PtyManager::default();
        let (resp, dir) = test_responder();
        let service = crate::pipeline::AuditService::open_quiet(dir.path(), "node", "box");
        let origin = crate::audit::Origin {
            path: dir.path().join("audit.log"),
            node: "box".into(),
            node_id: "node".into(),
        };
        let command = if cfg!(windows) {
            "exit /b 9".to_string()
        } else {
            "exit 9".to_string()
        };
        let sid = mgr
            .open(
                Some(command),
                None,
                24,
                80,
                resp.clone(),
                origin,
                Some("alice".into()),
                service,
                "alice",
                "jti-exit",
                None,
            )
            .await
            .expect("open exit pty");
        let code = wait_exit(&resp, std::time::Duration::from_secs(3)).await;
        let _ = mgr.close(&sid, Some("alice"));
        assert_eq!(
            code,
            Some(9),
            "PTY child exit code must be reported, transcript={:?}",
            pty_transcript(&resp)
        );
    }
}
