//! Cross-platform PTY sessions via portable-pty.
//!
//! The CLI drives a raw local terminal. This module owns the remote process,
//! captures a size-capped transcript, and writes one `pty_session` audit record
//! when the process exits. Keystrokes are not logged.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::audit::{self, Origin};
use crate::ops::Responder;
#[cfg(not(windows))]
use crate::ops::shell_parts;
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

#[derive(Clone, Default)]
pub struct PtyManager {
    sessions: Arc<Mutex<HashMap<String, LivePty>>>,
}

impl PtyManager {
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
                    std::fs::write(&bat, format!("{line}\r\n")).map_err(|e| {
                        Error::Message(format!("pty script: {e}"))
                    })?;
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
            require_pty_access(live, Some(peer))?;
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
            require_pty_access(live, Some(peer))?;
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
                require_pty_access(existing, peer)?;
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

fn require_pty_access(live: &LivePty, peer: Option<&str>) -> Result<()> {
    pty_access_error(&live.owner_peer, live.grant_exp_unix, peer)
}

fn pty_access_error(owner_peer: &str, grant_exp_unix: Option<i64>, peer: Option<&str>) -> Result<()> {
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
            name
                .trim_start_matches("agentlink-pty-")
                .trim_end_matches(".cmd")
        )
        .is_ok());
    }

    #[test]
    fn alice_cannot_access_bobs_pty_record() {
        let err = pty_access_error("bob", None, Some("alice")).unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
        pty_access_error("bob", None, Some("bob")).unwrap();
        pty_access_error("bob", None, None).unwrap();
        let err = pty_access_error(
            "bob",
            Some(agentlink_core::util::unix_now() - 5),
            Some("bob"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }
}
