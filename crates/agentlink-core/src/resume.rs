//! Reconnect timing and per-request sequence cursors.
//!
//! A relay restart drops the socket. Callers keep waiting. The first retry is
//! about 200ms, then exponential up to 10s, with jitter. After about 60s with
//! no socket, the wait fails. Sequence numbers let a node replay output the
//! client has not applied yet, without duplicating what already arrived.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::protocol::{Envelope, SessionCursor};

pub const RECONNECT_FLOOR: Duration = Duration::from_millis(200);
pub const RECONNECT_CAP: Duration = Duration::from_secs(10);
pub const RECONNECT_GIVE_UP: Duration = Duration::from_secs(60);
/// How long [`crate::client::Client::online_id`] waits when the node is already
/// listed offline. Long enough for a mid-reconnect race, short enough that
/// `exec`/`ls`/`cp` against a dead machine fail in about a second instead of
/// burning the full [`RECONNECT_GIVE_UP`] budget. In-flight copy resume still
/// retries `Offline` up to [`RECONNECT_GIVE_UP`] in `copy.rs`.
pub const OFFLINE_GRACE: Duration = Duration::from_secs(2);

/// Jittered exponential delay. `next` grows the base; `reset` returns to the floor.
#[derive(Debug, Clone)]
pub struct Backoff {
    current: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Backoff {
    pub fn new() -> Self {
        Self {
            current: RECONNECT_FLOOR,
        }
    }

    pub fn reset(&mut self) {
        self.current = RECONNECT_FLOOR;
    }

    /// Delay to sleep before the next dial, then advance the base.
    pub fn next_delay(&mut self) -> Duration {
        let base = self.current;
        let doubled = base.saturating_mul(2);
        self.current = if doubled > RECONNECT_CAP {
            RECONNECT_CAP
        } else {
            doubled
        };
        base + jitter(base)
    }
}

fn jitter(base: Duration) -> Duration {
    let span = (base.as_millis() as u64 / 2).max(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    Duration::from_millis(nanos % span)
}

/// Reorders sequenced frames and drops ones the caller has already applied.
#[derive(Debug, Default)]
pub struct Cursors {
    /// Next sequence to deliver, per request. Missing means 1.
    next: HashMap<String, u64>,
    pending: HashMap<String, BTreeMap<u64, Envelope>>,
}

impl Cursors {
    pub fn push(&mut self, env: Envelope) -> Vec<Envelope> {
        let seq = env.seq();
        if seq == 0 {
            return vec![env];
        }
        let Some(id) = env.request_id().map(|id| id.to_string()) else {
            return vec![env];
        };
        let expected = self.next.entry(id.clone()).or_insert(1);
        if seq < *expected {
            return Vec::new();
        }
        self.pending.entry(id.clone()).or_default().insert(seq, env);
        let mut ready = Vec::new();
        let queue = self.pending.entry(id.clone()).or_default();
        while let Some(env) = queue.remove(expected) {
            ready.push(env);
            *expected += 1;
        }
        if queue.is_empty() {
            self.pending.remove(&id);
        }
        ready
    }

    pub fn export(&self) -> Vec<SessionCursor> {
        self.next
            .iter()
            .filter(|(_, next)| **next > 1)
            .map(|(request_id, next)| SessionCursor {
                request_id: request_id.clone(),
                seq: next - 1,
            })
            .collect()
    }

    pub fn applied(&self, request_id: &str) -> u64 {
        self.next
            .get(request_id)
            .copied()
            .map(|next| next.saturating_sub(1))
            .unwrap_or(0)
    }
}

pub fn is_transient_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("node offline")
        || lower.contains("connection closed")
        || lower.contains("going away")
        || lower.contains("e2e session reset")
        || lower.contains("transfer closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Envelope;

    fn chunk(id: &str, seq: u64) -> Envelope {
        Envelope::Chunk {
            request_id: id.into(),
            stream: "stdout".into(),
            data_b64: String::new(),
            seq,
        }
    }

    #[test]
    fn backoff_starts_near_200ms_and_caps_at_10s() {
        let mut backoff = Backoff::new();
        let first = backoff.next_delay();
        assert!(first >= Duration::from_millis(200), "{first:?}");
        assert!(first < Duration::from_millis(400), "{first:?}");
        for _ in 0..8 {
            let delay = backoff.next_delay();
            assert!(delay <= Duration::from_secs(15), "{delay:?}");
        }
        let capped = backoff.next_delay();
        assert!(capped >= Duration::from_secs(10), "{capped:?}");
        assert!(capped < Duration::from_secs(15), "{capped:?}");
    }

    #[test]
    fn cursors_drop_duplicates_and_reorder() {
        let mut cursors = Cursors::default();
        assert!(cursors.push(chunk("a", 1)).len() == 1);
        assert!(cursors.push(chunk("a", 1)).is_empty());
        assert!(cursors.push(chunk("a", 3)).is_empty());
        let ready = cursors.push(chunk("a", 2));
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].seq(), 2);
        assert_eq!(ready[1].seq(), 3);
        assert_eq!(cursors.applied("a"), 3);
        let exported = cursors.export();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].seq, 3);
    }

    #[test]
    fn offline_grace_is_much_shorter_than_reconnect_give_up() {
        assert!(OFFLINE_GRACE < RECONNECT_GIVE_UP);
        assert!(OFFLINE_GRACE >= RECONNECT_FLOOR);
        // Product requirement: fresh ops against a dead node must not burn ~60s.
        assert!(OFFLINE_GRACE <= Duration::from_secs(5));
    }
}
