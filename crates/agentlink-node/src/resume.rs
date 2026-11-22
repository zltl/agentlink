//! Output retained across a relay restart.
//!
//! Each request gets a sequence number and a bounded ring of plaintext
//! envelopes. A duplicate invoke does not run again. The node replays the
//! ring on the new socket, and the client drops sequences it already applied.
//! PTY and background processes stay in their own managers. This log is only
//! the bytes those processes already produced.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentlink_core::ws::Outbound;
use agentlink_core::Envelope;
use tokio::sync::mpsc;

const MAX_FRAMES: usize = 1024;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_RETAINED_SESSIONS: usize = 256;
const MAX_ACTIVE_PINNED_SESSIONS: usize = 1024;
const MAX_RETAINED_CURSORS: usize = 1024;

/// The live socket. Replaced on every dial. Senders clone it at send time.
#[derive(Default)]
pub struct SocketSlot {
    tx: Mutex<Option<mpsc::Sender<Outbound>>>,
    generation: AtomicU64,
}

impl SocketSlot {
    pub fn attach(self: &Arc<Self>, tx: mpsc::Sender<Outbound>) -> u64 {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(mut slot) = self.tx.lock() {
            *slot = Some(tx);
        }
        generation
    }

    pub fn detach(&self, generation: u64) {
        if self.generation.load(Ordering::SeqCst) != generation {
            return;
        }
        if let Ok(mut slot) = self.tx.lock() {
            *slot = None;
        }
    }

    pub fn current(&self) -> Option<mpsc::Sender<Outbound>> {
        self.tx.lock().ok().and_then(|slot| slot.clone())
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
}

/// Identity and grant binding for a retained replay log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayOwner {
    pub owner_peer: String,
    pub grant_jti: String,
    pub grant_exp_unix: Option<i64>,
}

impl ReplayOwner {
    pub fn is_valid_for(
        &self,
        peer: &str,
        revoked: &BTreeSet<String>,
        now_unix: i64,
    ) -> bool {
        if self.owner_peer.is_empty() || self.owner_peer != peer {
            return false;
        }
        if self.grant_exp_unix.is_some_and(|exp| now_unix >= exp) {
            return false;
        }
        let jti = self.grant_jti.trim();
        if !jti.is_empty()
            && revoked
                .iter()
                .any(|item| item.trim().eq_ignore_ascii_case(jti))
        {
            return false;
        }
        true
    }
}

#[derive(Default)]
pub struct ReplayLog {
    owner: ReplayOwner,
    frames: Mutex<VecDeque<Envelope>>,
    next: AtomicU64,
    bytes: AtomicU64,
    finished: AtomicBool,
}

impl ReplayLog {
    pub fn with_owner(owner: ReplayOwner) -> Self {
        Self {
            owner,
            frames: Mutex::new(VecDeque::new()),
            next: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            finished: AtomicBool::new(false),
        }
    }

    pub fn owner(&self) -> &ReplayOwner {
        &self.owner
    }

    pub fn push(&self, mut env: Envelope) -> Envelope {
        if env.seq() == 0 {
            let seq = self.next.fetch_add(1, Ordering::Relaxed) + 1;
            env.set_seq(seq);
        }
        let terminal = env.is_terminal_frame();
        if let Ok(mut frames) = self.frames.lock() {
            let size = envelope_size(&env);
            frames.push_back(env.clone());
            self.bytes.fetch_add(size, Ordering::Relaxed);
            while frames.len() > MAX_FRAMES || self.bytes.load(Ordering::Relaxed) > MAX_BYTES as u64
            {
                if let Some(old) = frames.pop_front() {
                    let old_size = envelope_size(&old);
                    self.bytes.fetch_sub(old_size, Ordering::Relaxed);
                } else {
                    break;
                }
            }
        }
        if terminal {
            self.finished.store(true, Ordering::Release);
        }
        env
    }

    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    pub fn snapshot(&self) -> Vec<Envelope> {
        self.frames
            .lock()
            .map(|frames| frames.iter().cloned().collect())
            .unwrap_or_default()
    }
}

fn envelope_size(env: &Envelope) -> u64 {
    match env {
        Envelope::Chunk { data_b64, .. } => data_b64.len() as u64,
        _ => 64,
    }
}

#[derive(Default)]
struct SessionTable {
    logs: HashMap<String, Arc<ReplayLog>>,
    order: VecDeque<String>,
}

#[derive(Default)]
struct CursorTable {
    seq: HashMap<(String, String), u64>,
    order: VecDeque<(String, String)>,
}

#[derive(Default)]
pub struct Sessions {
    table: Mutex<SessionTable>,
    cursors: Mutex<CursorTable>,
}

impl Sessions {
    /// `None` when this request is already running or finished.
    #[cfg(test)]
    pub fn begin(&self, request_id: &str) -> Option<Arc<ReplayLog>> {
        self.begin_for(request_id, ReplayOwner::default())
    }

    /// Begin tracking a request bound to `(owner_peer, grant_jti, grant_exp_unix)`.
    /// Returns `None` when this request is already running or finished.
    pub fn begin_for(&self, request_id: &str, owner: ReplayOwner) -> Option<Arc<ReplayLog>> {
        let mut evicted: Vec<(String, String)> = Vec::new();
        let log = {
            let Ok(mut table) = self.table.lock() else {
                return None;
            };
            if table.logs.contains_key(request_id) {
                return None;
            }
            let log = Arc::new(ReplayLog::with_owner(owner));
            table.logs.insert(request_id.to_string(), log.clone());
            table.order.push_back(request_id.to_string());
            if table.logs.len() > MAX_RETAINED_SESSIONS {
                let mut kept = VecDeque::with_capacity(table.order.len());
                while let Some(id) = table.order.pop_front() {
                    let can_evict = table.logs.len() > MAX_RETAINED_SESSIONS
                        && id != request_id
                        && (table
                            .logs
                            .get(&id)
                            .is_some_and(|entry| entry.is_finished())
                            || table.logs.len() > MAX_ACTIVE_PINNED_SESSIONS);
                    if can_evict {
                        if let Some(removed) = table.logs.remove(&id) {
                            evicted.push((removed.owner().owner_peer.clone(), id));
                        }
                    } else {
                        kept.push_back(id);
                    }
                }
                table.order = kept;
            }
            log
        };
        if !evicted.is_empty() {
            if let Ok(mut cursors) = self.cursors.lock() {
                for key in &evicted {
                    cursors.seq.remove(key);
                }
            }
        }
        Some(log)
    }

    pub fn existing(&self, request_id: &str) -> Option<Arc<ReplayLog>> {
        self.table
            .lock()
            .ok()
            .and_then(|table| table.logs.get(request_id).cloned())
    }

    /// Remove replay logs whose grant has been revoked or expired.
    pub fn drop_inactive(&self, revoked: &BTreeSet<String>, now_unix: i64) -> usize {
        let mut dropped: Vec<(String, String)> = Vec::new();
        if let Ok(mut table) = self.table.lock() {
            table.logs.retain(|id, log| {
                let owner = log.owner();
                let expired = owner.grant_exp_unix.is_some_and(|exp| now_unix >= exp);
                let jti = owner.grant_jti.trim();
                let is_revoked = !jti.is_empty()
                    && revoked
                        .iter()
                        .any(|item| item.trim().eq_ignore_ascii_case(jti));
                if expired || is_revoked {
                    dropped.push((owner.owner_peer.clone(), id.clone()));
                    false
                } else {
                    true
                }
            });
            if !dropped.is_empty() {
                let dropped_ids: HashSet<&str> =
                    dropped.iter().map(|(_, id)| id.as_str()).collect();
                table.order.retain(|id| !dropped_ids.contains(id.as_str()));
            }
        }
        if !dropped.is_empty() {
            if let Ok(mut cursors) = self.cursors.lock() {
                for key in &dropped {
                    cursors.seq.remove(key);
                }
            }
        }
        dropped.len()
    }

    #[cfg(test)]
    pub fn note_cursors(&self, cursors: &[(String, u64)]) {
        self.note_cursors_unchecked("", cursors);
    }

    /// Record cursors sent inside an authenticated E2E `Envelope::Session`.
    /// Only updates cursors for requests belonging to `owner_peer` with a live
    /// (non-expired, non-revoked) grant.
    pub fn note_cursors_for(
        &self,
        owner_peer: &str,
        cursors: &[(String, u64)],
        revoked: &BTreeSet<String>,
        now_unix: i64,
    ) {
        if owner_peer.is_empty() || cursors.is_empty() {
            return;
        }
        let filtered: Vec<(String, u64)> = {
            let Ok(table) = self.table.lock() else {
                return;
            };
            cursors
                .iter()
                .filter(|(id, _)| {
                    table
                        .logs
                        .get(id)
                        .is_some_and(|log| log.owner().is_valid_for(owner_peer, revoked, now_unix))
                })
                .cloned()
                .collect()
        };
        if !filtered.is_empty() {
            self.note_cursors_unchecked(owner_peer, &filtered);
        }
    }

    fn note_cursors_unchecked(&self, owner_peer: &str, cursors: &[(String, u64)]) {
        if cursors.is_empty() {
            return;
        }
        let over_cap = {
            let Ok(mut table) = self.cursors.lock() else {
                return;
            };
            for (id, seq) in cursors {
                let key = (owner_peer.to_string(), id.clone());
                if let Some(slot) = table.seq.get_mut(&key) {
                    if *seq > *slot {
                        *slot = *seq;
                    }
                } else {
                    table.seq.insert(key.clone(), *seq);
                    table.order.push_back(key);
                }
            }
            table.seq.len() > MAX_RETAINED_CURSORS
        };
        if !over_cap {
            return;
        }
        let live_keys: HashSet<(String, String)> = self
            .table
            .lock()
            .map(|t| {
                t.logs
                    .iter()
                    .map(|(id, log)| (log.owner().owner_peer.clone(), id.clone()))
                    .collect()
            })
            .unwrap_or_default();
        if let Ok(mut table) = self.cursors.lock() {
            let mut scanned = 0usize;
            let bound = table.order.len();
            while table.seq.len() > MAX_RETAINED_CURSORS && scanned < bound {
                scanned += 1;
                let Some(oldest) = table.order.pop_front() else {
                    break;
                };
                if live_keys.contains(&oldest) {
                    table.order.push_back(oldest);
                } else {
                    table.seq.remove(&oldest);
                }
            }
        }
    }

    #[cfg(test)]
    pub fn cursor(&self, request_id: &str) -> u64 {
        self.cursor_for("", request_id)
    }

    pub fn cursor_for(&self, owner_peer: &str, request_id: &str) -> u64 {
        self.cursors
            .lock()
            .ok()
            .and_then(|table| {
                table
                    .seq
                    .get(&(owner_peer.to_string(), request_id.to_string()))
                    .copied()
            })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_streaming_session_survives_unary_keystroke_churn_and_evicts_fifo_after_end() {
        let sessions = Sessions::default();
        let pty_log = sessions.begin("pty-open-live").expect("begin pty");
        // `result_ack` has `terminal: false` and `Chunk` is non-terminal: log stays pinned!
        pty_log.push(Envelope::result_ack(
            "pty-open-live".to_string(),
            serde_json::json!({"session_id": "s1"}),
        ));
        pty_log.push(Envelope::Chunk {
            request_id: "pty-open-live".into(),
            stream: "pty".into(),
            data_b64: "cHJvbXB0JCA=".into(),
            seq: 0,
        });
        sessions.note_cursors(&[("pty-open-live".into(), 2)]);
        assert!(!pty_log.is_finished());

        // Simulate 600 unary `PtyInput` keystrokes (`result_ok` -> `terminal: true`).
        for i in 0..600 {
            let id = format!("pty-input-{i}");
            let ulog = sessions.begin(&id).expect("begin unary");
            ulog.push(Envelope::result_ok(id, serde_json::json!({"bytes": 1})));
            assert!(ulog.is_finished());
        }

        // The active PTY stream MUST still exist with its cursor intact!
        assert!(
            sessions.existing("pty-open-live").is_some(),
            "active streaming PtyOpen was evicted by unary PtyInput churn!"
        );
        assert_eq!(sessions.cursor("pty-open-live"), 2);
        // Oldest finished unary entries rotated out in FIFO order; newest remain.
        assert!(sessions.existing("pty-input-0").is_none());
        assert!(sessions.existing("pty-input-599").is_some());

        // Once the shell exits (`Envelope::End` is terminal), a subsequent 300
        // unary ops rotate it out cleanly without leaking.
        pty_log.push(Envelope::End {
            request_id: "pty-open-live".into(),
            exit_code: Some(0),
            error: None,
            seq: 0,
        });
        assert!(pty_log.is_finished());
        for i in 600..900 {
            let id = format!("pty-input-{i}");
            let ulog = sessions.begin(&id).expect("begin unary");
            ulog.push(Envelope::result_ok(id, serde_json::json!({"bytes": 1})));
        }
        assert!(sessions.existing("pty-open-live").is_none());
        assert_eq!(sessions.cursor("pty-open-live"), 0);
    }

    #[test]
    fn replay_log_and_cursors_enforce_owner_and_grant_lifecycle() {
        let sessions = Sessions::default();
        let owner = ReplayOwner {
            owner_peer: "alice".into(),
            grant_jti: "jti-1".into(),
            grant_exp_unix: Some(1_000),
        };
        let log = sessions.begin_for("req-1", owner).expect("begin");
        let empty = BTreeSet::new();
        assert!(log.owner().is_valid_for("alice", &empty, 500));
        assert!(!log.owner().is_valid_for("bob", &empty, 500));
        assert!(!log.owner().is_valid_for("alice", &empty, 1_000));

        // Bob cannot poison Alice's cursor.
        sessions.note_cursors_for("bob", &[("req-1".into(), 99)], &empty, 500);
        assert_eq!(sessions.cursor_for("alice", "req-1"), 0);
        assert_eq!(sessions.cursor_for("bob", "req-1"), 0);

        // Alice can update her own cursor while grant is valid.
        sessions.note_cursors_for("alice", &[("req-1".into(), 7)], &empty, 500);
        assert_eq!(sessions.cursor_for("alice", "req-1"), 7);

        // Revoked grant rejects validation and drops the replay log + cursor.
        let mut revoked = BTreeSet::new();
        revoked.insert("jti-1".into());
        assert!(!log.owner().is_valid_for("alice", &revoked, 500));
        assert_eq!(sessions.drop_inactive(&revoked, 500), 1);
        assert!(sessions.existing("req-1").is_none());
        assert_eq!(sessions.cursor_for("alice", "req-1"), 0);
    }
}
