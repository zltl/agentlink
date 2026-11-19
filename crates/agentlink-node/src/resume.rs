//! Output retained across a relay restart.
//!
//! Each request gets a sequence number and a bounded ring of plaintext
//! envelopes. A duplicate invoke does not run again. The node replays the
//! ring on the new socket, and the client drops sequences it already applied.
//! PTY and background processes stay in their own managers. This log is only
//! the bytes those processes already produced.

use std::collections::{HashMap, VecDeque};
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

#[derive(Default)]
pub struct ReplayLog {
    frames: Mutex<VecDeque<Envelope>>,
    next: AtomicU64,
    bytes: AtomicU64,
    finished: AtomicBool,
}

impl ReplayLog {
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
    seq: HashMap<String, u64>,
    order: VecDeque<String>,
}

#[derive(Default)]
pub struct Sessions {
    table: Mutex<SessionTable>,
    cursors: Mutex<CursorTable>,
}

impl Sessions {
    /// `None` when this request is already running or finished.
    pub fn begin(&self, request_id: &str) -> Option<Arc<ReplayLog>> {
        let mut evicted = Vec::new();
        let log = {
            let Ok(mut table) = self.table.lock() else {
                return None;
            };
            if table.logs.contains_key(request_id) {
                return None;
            }
            let log = Arc::new(ReplayLog::default());
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
                        table.logs.remove(&id);
                        evicted.push(id);
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
                for id in &evicted {
                    cursors.seq.remove(id);
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

    pub fn note_cursors(&self, cursors: &[(String, u64)]) {
        if cursors.is_empty() {
            return;
        }
        let over_cap = {
            let Ok(mut table) = self.cursors.lock() else {
                return;
            };
            for (id, seq) in cursors {
                if let Some(slot) = table.seq.get_mut(id) {
                    if *seq > *slot {
                        *slot = *seq;
                    }
                } else {
                    table.seq.insert(id.clone(), *seq);
                    table.order.push_back(id.clone());
                }
            }
            table.seq.len() > MAX_RETAINED_CURSORS
        };
        if !over_cap {
            return;
        }
        let live_ids: std::collections::HashSet<String> = self
            .table
            .lock()
            .map(|t| t.logs.keys().cloned().collect())
            .unwrap_or_default();
        if let Ok(mut table) = self.cursors.lock() {
            let mut scanned = 0usize;
            let bound = table.order.len();
            while table.seq.len() > MAX_RETAINED_CURSORS && scanned < bound {
                scanned += 1;
                let Some(oldest) = table.order.pop_front() else {
                    break;
                };
                if live_ids.contains(&oldest) {
                    table.order.push_back(oldest);
                } else {
                    table.seq.remove(&oldest);
                }
            }
        }
    }

    pub fn cursor(&self, request_id: &str) -> u64 {
        self.cursors
            .lock()
            .ok()
            .and_then(|table| table.seq.get(request_id).copied())
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
}
