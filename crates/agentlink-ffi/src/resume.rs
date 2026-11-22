//! Output retained across a relay restart.
//!
//! Each request gets a sequence number and a bounded ring of plaintext
//! envelopes. A duplicate invoke does not run again. The node replays the
//! ring on the new socket, and the client drops sequences it already applied.
//! This is the phone-side copy of the desktop node's resume log. The phone
//! crate cannot depend on `agentlink-node`.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentlink_core::Envelope;

const MAX_FRAMES: usize = 1024;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_RETAINED_SESSIONS: usize = 256;
const MAX_ACTIVE_PINNED_SESSIONS: usize = 1024;
const MAX_RETAINED_CURSORS: usize = 1024;

/// The live socket. Replaced on every dial. Senders clone it at send time.
#[derive(Default)]
pub struct SocketSlot {
    tx: Mutex<Option<tokio::sync::mpsc::Sender<agentlink_core::ws::Outbound>>>,
    generation: AtomicU64,
}

impl SocketSlot {
    pub fn attach(
        self: &Arc<Self>,
        tx: tokio::sync::mpsc::Sender<agentlink_core::ws::Outbound>,
    ) -> u64 {
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

    pub fn current(&self) -> Option<tokio::sync::mpsc::Sender<agentlink_core::ws::Outbound>> {
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
    owner_peer: String,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
}

impl ReplayLog {
    pub fn new(owner_peer: String, grant_jti: String, grant_exp_unix: Option<i64>) -> Self {
        Self {
            frames: Mutex::new(VecDeque::new()),
            next: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            finished: AtomicBool::new(false),
            owner_peer,
            grant_jti: grant_jti.trim().to_string(),
            grant_exp_unix,
        }
    }

    pub fn owner_peer(&self) -> &str {
        &self.owner_peer
    }

    pub fn is_authorized_for(
        &self,
        peer: &str,
        revoked_jtis: &BTreeSet<String>,
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
            && revoked_jtis
                .iter()
                .any(|item| item.trim().eq_ignore_ascii_case(jti))
        {
            return false;
        }
        true
    }

    pub fn mark_finished(&self) {
        self.finished.store(true, Ordering::Release);
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
    pub fn begin(
        &self,
        request_id: &str,
        owner_peer: &str,
        grant_jti: &str,
        grant_exp_unix: Option<i64>,
    ) -> Option<Arc<ReplayLog>> {
        if owner_peer.trim().is_empty() {
            return None;
        }
        let mut evicted: Vec<(String, String)> = Vec::new();
        let log = {
            let Ok(mut table) = self.table.lock() else {
                return None;
            };
            if table.logs.contains_key(request_id) {
                return None;
            }
            let log = Arc::new(ReplayLog::new(
                owner_peer.to_string(),
                grant_jti.to_string(),
                grant_exp_unix,
            ));
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
                            evicted.push((removed.owner_peer().to_string(), id));
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

    pub fn purge_inactive(&self, revoked_jtis: &BTreeSet<String>, now_unix: i64) {
        let mut evicted: Vec<(String, String)> = Vec::new();
        if let Ok(mut table) = self.table.lock() {
            let mut kept = VecDeque::with_capacity(table.order.len());
            while let Some(id) = table.order.pop_front() {
                let remove = table.logs.get(&id).is_some_and(|log| {
                    !log.is_authorized_for(log.owner_peer(), revoked_jtis, now_unix)
                });
                if remove {
                    if let Some(removed) = table.logs.remove(&id) {
                        evicted.push((removed.owner_peer().to_string(), id));
                    }
                } else {
                    kept.push_back(id);
                }
            }
            table.order = kept;
        }
        if !evicted.is_empty() {
            if let Ok(mut cursors) = self.cursors.lock() {
                for key in &evicted {
                    cursors.seq.remove(key);
                }
            }
        }
    }

    pub fn note_cursors(&self, owner_peer: &str, cursors: &[(String, u64)]) {
        if owner_peer.trim().is_empty() || cursors.is_empty() {
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
                    .map(|(id, log)| (log.owner_peer().to_string(), id.clone()))
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

    pub fn cursor(&self, owner_peer: &str, request_id: &str) -> u64 {
        if owner_peer.trim().is_empty() {
            return 0;
        }
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
    use agentlink_core::Envelope;

    #[test]
    fn frames_are_sequenced_and_a_second_begin_is_rejected() {
        let sessions = Sessions::default();
        let log = sessions
            .begin("req", "peer-alice", "jti-1", Some(10_000))
            .expect("first begin");
        assert!(sessions.begin("req", "peer-alice", "jti-1", Some(10_000)).is_none());
        let chunk = log.push(Envelope::Chunk {
            request_id: "req".into(),
            stream: "pty".into(),
            data_b64: "YQ==".into(),
            seq: 0,
        });
        let end = log.push(Envelope::End {
            request_id: "req".into(),
            exit_code: Some(0),
            error: None,
            seq: 0,
        });
        assert_eq!(chunk.seq(), 1);
        assert_eq!(end.seq(), 2);
        // Another peer's cursor update must not advance Alice's cursor.
        sessions.note_cursors("peer-eve", &[("req".into(), 99)]);
        assert_eq!(sessions.cursor("peer-alice", "req"), 0);
        sessions.note_cursors("peer-alice", &[("req".into(), 1)]);
        assert_eq!(sessions.cursor("peer-alice", "req"), 1);
        let pending: Vec<_> = log
            .snapshot()
            .into_iter()
            .filter(|env| env.seq() > sessions.cursor("peer-alice", "req"))
            .collect();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].seq(), 2);

        // Ownership, expiry, and revocation checks on ReplayLog.
        let empty = BTreeSet::new();
        assert!(log.is_authorized_for("peer-alice", &empty, 5_000));
        assert!(!log.is_authorized_for("peer-eve", &empty, 5_000));
        assert!(!log.is_authorized_for("peer-alice", &empty, 10_000));
        let revoked = BTreeSet::from(["JTI-1".to_string()]);
        assert!(!log.is_authorized_for("peer-alice", &revoked, 5_000));
    }
}
