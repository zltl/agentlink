//! STD-only ordered control enqueue policy for live input.
//!
//! Barriers (clicks/keys/wheel/text) must never route-switch to a second
//! transport when the live queue is saturated — that reorders a later click
//! ahead of a queued RTC down. Moves may coalesce with an adjacent pending
//! move or drop under saturation.
//!
//! `rustc --test` without workspace Cargo.

use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlKind {
    /// Coalescable mouse move.
    Move,
    /// Click / key / wheel / text / release — must preserve order.
    Barrier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnqueueError {
    /// Barrier could not fit — caller must wait / apply backpressure.
    /// Must **not** fall back to another route.
    BarrierBlocked,
    /// Move dropped or coalesced-away under saturation (not an error for UX).
    MoveDropped,
    /// Queue was marked closed / stopping.
    Closed,
}

#[derive(Clone, Debug)]
pub struct OrderedControlQueue<T = String> {
    cap: usize,
    closed: bool,
    q: VecDeque<(ControlKind, T)>,
}

impl<T> OrderedControlQueue<T> {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            closed: false,
            q: VecDeque::new(),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.q.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    #[cfg(test)]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Enqueue one control payload. Barriers never displace earlier barriers;
    /// adjacent moves at the tail coalesce to the latest body.
    pub fn enqueue(&mut self, kind: ControlKind, body: T) -> Result<(), EnqueueError> {
        if self.closed {
            return Err(EnqueueError::Closed);
        }
        match kind {
            ControlKind::Move => {
                if let Some((ControlKind::Move, slot)) = self.q.back_mut() {
                    *slot = body;
                    return Ok(());
                }
                if self.q.len() >= self.cap {
                    return Err(EnqueueError::MoveDropped);
                }
                self.q.push_back((ControlKind::Move, body));
                Ok(())
            }
            ControlKind::Barrier => {
                if self.q.len() >= self.cap {
                    return Err(EnqueueError::BarrierBlocked);
                }
                self.q.push_back((ControlKind::Barrier, body));
                Ok(())
            }
        }
    }

    /// Pop the next payload in order (simulates the RTC consumer).
    pub fn pop(&mut self) -> Option<(ControlKind, T)> {
        self.q.pop_front()
    }

    /// Wait-style helper for tests: retry barrier until space (after pops).
    #[cfg(test)]
    pub fn enqueue_barrier_with_space(
        &mut self,
        body: T,
        make_space: impl FnOnce(&mut Self),
    ) -> Result<(), EnqueueError>
    where
        T: Clone,
    {
        match self.enqueue(ControlKind::Barrier, body.clone()) {
            Ok(()) => Ok(()),
            Err(EnqueueError::BarrierBlocked) => {
                make_space(self);
                self.enqueue(ControlKind::Barrier, body)
            }
            Err(other) => Err(other),
        }
    }
}

/// Live path chosen: never fall back to Extension on saturation/closed.
pub fn should_extension_fallback(live_viewer_present: bool, _err: &EnqueueError) -> bool {
    !live_viewer_present
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_moves_coalesce_under_cap() {
        let mut q = OrderedControlQueue::<String>::new(2);
        q.enqueue(ControlKind::Move, "m1".into()).unwrap();
        q.enqueue(ControlKind::Move, "m2".into()).unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(q.pop(), Some((ControlKind::Move, "m2".into())));
    }

    #[test]
    fn barrier_blocked_does_not_reorder_via_second_route() {
        let mut q = OrderedControlQueue::<String>::new(1);
        q.enqueue(ControlKind::Barrier, "down".into()).unwrap();
        let err = q
            .enqueue(ControlKind::Barrier, "up".into())
            .expect_err("full");
        assert_eq!(err, EnqueueError::BarrierBlocked);
        // Live viewer present ⇒ no Extension fallback.
        assert!(!should_extension_fallback(true, &err));
        // Drain then enqueue preserves order.
        assert_eq!(q.pop().unwrap().1, "down");
        q.enqueue(ControlKind::Barrier, "up".into()).unwrap();
        assert_eq!(q.pop().unwrap().1, "up");
    }

    #[test]
    fn saturation_keeps_earlier_down_before_later_click() {
        let mut q = OrderedControlQueue::<String>::new(2);
        q.enqueue(ControlKind::Barrier, "down-a".into()).unwrap();
        q.enqueue(ControlKind::Move, "move".into()).unwrap();
        // Queue full of [down-a, move]. Later click must block, not skip ahead.
        assert_eq!(
            q.enqueue(ControlKind::Barrier, "down-b".into()),
            Err(EnqueueError::BarrierBlocked)
        );
        // Coalesce move in place still leaves down-a first.
        q.enqueue(ControlKind::Move, "move2".into()).unwrap();
        assert_eq!(q.pop().unwrap().1, "down-a");
        assert_eq!(q.pop().unwrap().1, "move2");
        q.enqueue(ControlKind::Barrier, "down-b".into()).unwrap();
        assert_eq!(q.pop().unwrap().1, "down-b");
    }

    #[test]
    fn closed_queue_rejects_without_extension_when_live() {
        let mut q = OrderedControlQueue::<String>::new(4);
        q.close();
        let err = q
            .enqueue(ControlKind::Barrier, "x".into())
            .expect_err("closed");
        assert_eq!(err, EnqueueError::Closed);
        assert!(!should_extension_fallback(true, &err));
        assert!(should_extension_fallback(false, &err));
    }

    #[test]
    fn move_dropped_when_full_of_barriers() {
        let mut q = OrderedControlQueue::<String>::new(1);
        q.enqueue(ControlKind::Barrier, "down".into()).unwrap();
        assert_eq!(
            q.enqueue(ControlKind::Move, "m".into()),
            Err(EnqueueError::MoveDropped)
        );
        assert_eq!(q.pop().unwrap().1, "down");
    }
}
