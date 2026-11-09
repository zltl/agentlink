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
    needs_keyframe: bool,
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
                needs_keyframe: false,
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
            state.needs_keyframe = false;
            state.saw_keyframe = true;
        } else if state.needs_keyframe || state.items.len() >= state.cap {
            state.needs_keyframe = true;
            state.dropped += state.items.len() as u64 + 1;
            state.items.clear();
        } else {
            state.items.push_back(unit);
        }
        self.cv.notify_one();
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

    /// Drop queued deltas and keep only the newest unit (prefer a keyframe).
    /// Used when decode overran the frame budget so the UI stays on the latest picture.
    pub fn drain_keep_latest(&self) -> Option<Queued> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if state.items.is_empty() {
            return None;
        }
        let mut latest = None;
        while let Some(item) = state.items.pop_front() {
            if item.keyframe {
                state.dropped += state.items.len() as u64;
                state.items.clear();
                latest = Some(item);
                break;
            }
            state.dropped += 1;
            latest = Some(item);
        }
        if latest.is_some() {
            state.shown += 1;
        }
        latest
    }

    /// Milliseconds since the last successful `push`, or `None` if empty forever.
    pub fn ms_since_push(&self) -> Option<u64> {
        let state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        state.last_push.map(|at| at.elapsed().as_millis() as u64)
    }

    /// Counters since the previous call. `needs_keyframe` is cleared so the
    /// caller sends one keyframe request, not one per dropped frame.
    pub fn take_feedback(&self) -> (u64, u64, bool) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let dropped = state.dropped;
        let shown = state.shown;
        let needs = state.needs_keyframe;
        state.dropped = 0;
        state.shown = 0;
        state.needs_keyframe = false;
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

    #[test]
    fn overflow_drops_deltas_until_a_keyframe() {
        let bus = FrameBus::new(2);
        bus.push(delta(1));
        bus.push(delta(2));
        bus.push(delta(3));
        let (dropped, _, needs) = bus.take_feedback();
        assert!(dropped >= 1);
        assert!(needs);
        assert!(bus.pop(Duration::from_millis(10)).is_none());
        bus.push(Queued {
            bytes: vec![9],
            keyframe: true,
            captured_unix_ms: 4,
        });
        let frame = bus.pop(Duration::from_millis(20)).unwrap();
        assert_eq!(frame.bytes, vec![9]);
        assert!(frame.keyframe);
    }
}
