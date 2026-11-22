//! Shallow queue of access units.
//!
//! A live picture should not buffer. If the phone falls behind, drop deltas
//! and ask for a keyframe instead of showing stale frames.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Queued {
    pub bytes: Vec<u8>,
    pub keyframe: bool,
    pub captured_unix_ms: i64,
}

struct State {
    items: VecDeque<Queued>,
    cap: usize,
    dropped: u64,
    shown: u64,
    /// True whenever the H.264 reference chain is incomplete (before the first
    /// IDR, after queue overflow, after RTP loss/corruption, or after draining
    /// skipped deltas). Cleared ONLY when an actual IDR arrives.
    drop_until_idr: bool,
    /// One-shot flag consumed by [`FrameBus::take_feedback`] so the caller
    /// sends a keyframe request without clearing `drop_until_idr`.
    needs_keyframe: bool,
    /// Tracks whether `take_feedback` already emitted a request for the
    /// current `drop_until_idr` episode, avoiding spamming `needs = true` on
    /// every subsequent dropped P-frame.
    keyframe_requested: bool,
    saw_keyframe: bool,
    last_push: Option<Instant>,
}

pub struct FrameBus {
    state: Mutex<State>,
    cv: Condvar,
}

impl FrameBus {
    pub fn new(cap: usize) -> Self {
        Self {
            state: Mutex::new(State {
                items: VecDeque::new(),
                cap: cap.max(1),
                dropped: 0,
                shown: 0,
                drop_until_idr: true,
                needs_keyframe: false,
                keyframe_requested: false,
                saw_keyframe: false,
                last_push: None,
            }),
            cv: Condvar::new(),
        }
    }

    pub fn push(&self, unit: Queued) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        state.last_push = Some(Instant::now());
        if unit.keyframe {
            state.dropped += state.items.len() as u64;
            state.items.clear();
            state.items.push_back(unit);
            state.drop_until_idr = false;
            state.needs_keyframe = false;
            state.keyframe_requested = false;
            state.saw_keyframe = true;
        } else if state.drop_until_idr {
            state.dropped += 1;
            if !state.keyframe_requested {
                state.needs_keyframe = true;
            }
        } else if state.items.len() >= state.cap {
            state.drop_until_idr = true;
            state.needs_keyframe = true;
            state.keyframe_requested = false;
            state.dropped += state.items.len() as u64 + 1;
            state.items.clear();
        } else {
            state.items.push_back(unit);
        }
        self.cv.notify_one();
    }

    /// Signal RTP packet loss or depacketizer corruption. Drops all subsequent
    /// delta frames until a fresh IDR arrives and requests a keyframe.
    pub fn mark_loss(&self) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        state.drop_until_idr = true;
        state.needs_keyframe = true;
        state.keyframe_requested = false;
    }

    /// True while deltas are being dropped awaiting an IDR.
    pub fn is_dropping_until_idr(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .drop_until_idr
    }

    pub fn pop(&self, timeout: Duration) -> Option<Queued> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let deadline = Instant::now() + timeout;
        while state.items.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, wait) = self
                .cv
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|err| err.into_inner());
            state = guard;
            if wait.timed_out() && state.items.is_empty() {
                return None;
            }
        }
        let item = state.items.pop_front();
        if item.is_some() {
            state.shown += 1;
        }
        item
    }

    /// Drop stale queued frames safely without ever breaking the H.264 DPB.
    ///
    /// - If the queue contains an IDR, drops everything before the newest IDR,
    ///   returns that IDR, and preserves any newer deltas that depend on it.
    /// - If the queue has a single delta (zero frames skipped), returns it
    ///   directly since the reference chain is intact.
    /// - If the queue has multiple deltas and no IDR, drops all of them, arms
    ///   `drop_until_idr` + `needs_keyframe`, and returns `None` instead of
    ///   emitting an orphaned later P-frame.
    pub fn drain_keep_latest(&self) -> Option<Queued> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if state.items.is_empty() {
            return None;
        }
        if let Some(idr_idx) = state.items.iter().rposition(|item| item.keyframe) {
            for _ in 0..idr_idx {
                state.items.pop_front();
                state.dropped += 1;
            }
            let idr = state.items.pop_front();
            if idr.is_some() {
                state.shown += 1;
            }
            return idr;
        }
        if state.items.len() == 1 {
            let single = state.items.pop_front();
            if single.is_some() {
                state.shown += 1;
            }
            return single;
        }
        // Multiple deltas without an IDR: never drop earlier P-frames and emit
        // an orphaned later P-frame. Drop the backlog and wait for a fresh IDR.
        state.dropped += state.items.len() as u64;
        state.items.clear();
        state.drop_until_idr = true;
        state.needs_keyframe = true;
        state.keyframe_requested = false;
        None
    }

    /// Milliseconds since the last successful `push`, or `None` if empty forever.
    #[allow(dead_code)]
    pub fn ms_since_push(&self) -> Option<u64> {
        let state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        state.last_push.map(|at| at.elapsed().as_millis() as u64)
    }

    /// Counters since the previous call. `needs_keyframe` is cleared so the
    /// caller sends one keyframe request, not one per dropped frame.
    /// `drop_until_idr` is NOT cleared here — it stays armed until an IDR arrives.
    pub fn take_feedback(&self) -> (u64, u64, bool) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let dropped = state.dropped;
        let shown = state.shown;
        let needs = state.needs_keyframe;
        state.dropped = 0;
        state.shown = 0;
        if needs {
            state.needs_keyframe = false;
            state.keyframe_requested = true;
        }
        (dropped, shown, needs)
    }

    pub fn saw_keyframe(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .saw_keyframe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delta(n: u8) -> Queued {
        Queued {
            bytes: vec![n],
            keyframe: false,
            captured_unix_ms: 0,
        }
    }

    fn idr(n: u8) -> Queued {
        Queued {
            bytes: vec![n],
            keyframe: true,
            captured_unix_ms: n as i64,
        }
    }

    #[test]
    fn overflow_drops_deltas_until_a_keyframe() {
        let bus = FrameBus::new(2);
        bus.push(idr(0));
        assert_eq!(bus.pop(Duration::from_millis(10)).unwrap().bytes, vec![0]);

        bus.push(delta(1));
        bus.push(delta(2));
        bus.push(delta(3));
        let (dropped, _, needs) = bus.take_feedback();
        assert!(dropped >= 1);
        assert!(needs);
        assert!(bus.is_dropping_until_idr());
        assert!(bus.pop(Duration::from_millis(10)).is_none());

        // Subsequent deltas after take_feedback() MUST still be dropped until an IDR arrives.
        bus.push(delta(4));
        bus.push(delta(5));
        assert!(bus.pop(Duration::from_millis(10)).is_none());
        let (dropped_after, _, needs_again) = bus.take_feedback();
        assert_eq!(dropped_after, 2);
        assert!(
            !needs_again,
            "take_feedback must not spam needs=true on every dropped delta"
        );
        assert!(bus.is_dropping_until_idr());

        bus.push(Queued {
            bytes: vec![9],
            keyframe: true,
            captured_unix_ms: 4,
        });
        assert!(!bus.is_dropping_until_idr());
        let frame = bus.pop(Duration::from_millis(20)).unwrap();
        assert_eq!(frame.bytes, vec![9]);
        assert!(frame.keyframe);
    }

    #[test]
    fn deltas_before_first_idr_are_dropped_and_request_keyframe() {
        let bus = FrameBus::new(3);
        assert!(bus.is_dropping_until_idr());
        bus.push(delta(1));
        bus.push(delta(2));
        assert!(bus.pop(Duration::from_millis(10)).is_none());
        let (dropped, shown, needs) = bus.take_feedback();
        assert_eq!(dropped, 2);
        assert_eq!(shown, 0);
        assert!(needs);
        assert!(bus.is_dropping_until_idr());

        // Still drops after take_feedback until IDR arrives.
        bus.push(delta(3));
        assert!(bus.pop(Duration::from_millis(10)).is_none());

        bus.push(idr(10));
        assert!(!bus.is_dropping_until_idr());
        assert!(bus.saw_keyframe());
        assert_eq!(bus.pop(Duration::from_millis(10)).unwrap().bytes, vec![10]);
        bus.push(delta(11));
        assert_eq!(bus.pop(Duration::from_millis(10)).unwrap().bytes, vec![11]);
    }

    #[test]
    fn drain_keep_latest_never_emits_orphaned_p_frame() {
        let bus = FrameBus::new(4);
        bus.push(idr(1));
        assert_eq!(bus.pop(Duration::from_millis(10)).unwrap().bytes, vec![1]);

        // Multiple deltas without an IDR: must drop all, arm drop_until_idr + keyframe, return None.
        bus.push(delta(2));
        bus.push(delta(3));
        bus.push(delta(4));
        assert!(bus.drain_keep_latest().is_none());
        assert!(bus.is_dropping_until_idr());
        let (dropped, _, needs) = bus.take_feedback();
        assert_eq!(dropped, 3);
        assert!(needs);

        // Next delta after take_feedback must still be dropped until IDR arrives.
        bus.push(delta(5));
        assert!(bus.pop(Duration::from_millis(10)).is_none());

        // Single unskipped delta after IDR is safe to emit directly.
        bus.push(idr(6));
        assert_eq!(bus.pop(Duration::from_millis(10)).unwrap().bytes, vec![6]);
        bus.push(delta(7));
        let single = bus.drain_keep_latest().expect("single unskipped delta");
        assert_eq!(single.bytes, vec![7]);
        assert!(!bus.is_dropping_until_idr());
    }

    #[test]
    fn drain_keep_latest_jumps_to_newest_idr_and_preserves_following_deltas() {
        let bus = FrameBus::new(6);
        bus.push(idr(1));
        assert_eq!(bus.pop(Duration::from_millis(10)).unwrap().bytes, vec![1]);

        bus.push(delta(2));
        bus.push(delta(3));
        // Push an IDR (note push(idr) already clears stale pre-IDR items), then deltas after it.
        bus.push(idr(10));
        bus.push(delta(11));
        bus.push(delta(12));

        let frame = bus.drain_keep_latest().expect("idr returned");
        assert_eq!(frame.bytes, vec![10]);
        assert!(frame.keyframe);
        assert!(!bus.is_dropping_until_idr());
        // Following deltas that depend on IDR 10 remain intact in order.
        assert_eq!(bus.pop(Duration::from_millis(10)).unwrap().bytes, vec![11]);
        assert_eq!(bus.pop(Duration::from_millis(10)).unwrap().bytes, vec![12]);
    }

    #[test]
    fn mark_loss_arms_drop_until_idr_across_take_feedback() {
        let bus = FrameBus::new(4);
        bus.push(idr(1));
        assert_eq!(bus.pop(Duration::from_millis(10)).unwrap().bytes, vec![1]);

        bus.mark_loss();
        let (_, _, needs) = bus.take_feedback();
        assert!(needs);
        assert!(bus.is_dropping_until_idr());

        // P-frame after loss is dropped even though take_feedback already ran.
        bus.push(delta(2));
        assert!(bus.pop(Duration::from_millis(10)).is_none());

        // Fresh IDR recovers immediately.
        bus.push(idr(3));
        assert!(!bus.is_dropping_until_idr());
        assert_eq!(bus.pop(Duration::from_millis(10)).unwrap().bytes, vec![3]);
    }
}
