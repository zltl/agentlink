//! Output retained across a relay restart.
//!
//! Each request gets a sequence number and a bounded ring of plaintext
//! envelopes. A duplicate invoke does not run again. The node replays the
//! ring on the new socket, and the client drops sequences it already applied.
//! PTY and background processes stay in their own managers. This log is only
//! the bytes those processes already produced.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentlink_core::ws::Outbound;
use agentlink_core::Envelope;
use tokio::sync::mpsc;

const MAX_FRAMES: usize = 1024;
const MAX_BYTES: usize = 4 * 1024 * 1024;

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
}

impl ReplayLog {
    pub fn push(&self, mut env: Envelope) -> Envelope {
        if env.seq() == 0 {
            let seq = self.next.fetch_add(1, Ordering::Relaxed) + 1;
            env.set_seq(seq);
        }
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
        env
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
pub struct Sessions {
    logs: Mutex<HashMap<String, Arc<ReplayLog>>>,
    cursors: Mutex<HashMap<String, u64>>,
}

impl Sessions {
    /// `None` when this request is already running or finished.
    pub fn begin(&self, request_id: &str) -> Option<Arc<ReplayLog>> {
        let Ok(mut logs) = self.logs.lock() else {
            return None;
        };
        if logs.contains_key(request_id) {
            return None;
        }
        let log = Arc::new(ReplayLog::default());
        logs.insert(request_id.to_string(), log.clone());
        if logs.len() > 256 {
            let keep = request_id.to_string();
            let extra = logs.len() - 256;
            let stale: Vec<String> = logs
                .keys()
                .filter(|id| *id != &keep)
                .take(extra)
                .cloned()
                .collect();
            for id in stale {
                logs.remove(&id);
            }
        }
        Some(log)
    }

    pub fn existing(&self, request_id: &str) -> Option<Arc<ReplayLog>> {
        self.logs
            .lock()
            .ok()
            .and_then(|logs| logs.get(request_id).cloned())
    }

    pub fn note_cursors(&self, cursors: &[(String, u64)]) {
        if let Ok(mut map) = self.cursors.lock() {
            for (id, seq) in cursors {
                let slot = map.entry(id.clone()).or_insert(0);
                if *seq > *slot {
                    *slot = *seq;
                }
            }
        }
    }

    pub fn cursor(&self, request_id: &str) -> u64 {
        self.cursors
            .lock()
            .ok()
            .and_then(|map| map.get(request_id).copied())
            .unwrap_or(0)
    }
}
