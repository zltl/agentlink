//! Bounded waiter queue for client request/PTY envelopes.
//!
//! The historical `mpsc::unbounded_channel` on `ClientInner.pending` could
//! grow without limit when a PTY consumer was slower than incoming chunks.
//! This queue caps both event count and total payload bytes, never drops a
//! queued data envelope, and applies backpressure to the socket receive
//! task that calls [`PendingSender::send`]. There is no remote PTY
//! pause/ack protocol: pausing that task stops reading the local socket
//! (TCP window) only. Kernel, relay, and the node's 256-slot outbound
//! channel / replay ring remain residual buffers.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::protocol::Envelope;

/// High watermark: max queued envelopes, including a reserved terminal slot.
pub const PENDING_MAX_EVENTS: usize = 512;
/// High watermark: max queued payload bytes, including reserved terminal bytes.
pub const PENDING_MAX_BYTES: usize = 256 * 1024;
/// Resume sending only after both watermarks are at or below these lows.
pub const PENDING_LOW_EVENTS: usize = 128;
pub const PENDING_LOW_BYTES: usize = 64 * 1024;
const RESERVED_TERMINAL_EVENTS: usize = 1;
const RESERVED_TERMINAL_BYTES: usize = 1024;

/// Bytes charged to the budget for one envelope.
pub fn envelope_bytes(env: &Envelope) -> usize {
    match env {
        Envelope::Chunk { data_b64, .. } => data_b64.len(),
        other => other.request_id().map(|id| id.len()).unwrap_or(0).max(64),
    }
}

/// True when this frame may use the reserved terminal slot.
pub fn is_reserved_terminal(env: &Envelope) -> bool {
    matches!(
        env,
        Envelope::End { .. } | Envelope::Result { ok: false, .. }
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrySend {
    Queued,
    WouldBlock,
    Overflow,
    Closed,
}

#[derive(Debug)]
pub enum SendError {
    Closed,
    Overflow(Envelope),
}

struct Inner {
    queue: Mutex<Queue>,
    recv_ready: Notify,
    send_ready: Notify,
    closed: AtomicBool,
    events: AtomicUsize,
    bytes: AtomicUsize,
    max_events: usize,
    max_bytes: usize,
    low_events: usize,
    low_bytes: usize,
}

struct Queue {
    items: VecDeque<Envelope>,
    paused: bool,
}

#[derive(Clone)]
pub struct PendingSender {
    inner: Arc<Inner>,
}

pub struct PendingReceiver {
    inner: Arc<Inner>,
}

pub fn channel() -> (PendingSender, PendingReceiver) {
    channel_with_limits(
        PENDING_MAX_EVENTS,
        PENDING_MAX_BYTES,
        PENDING_LOW_EVENTS,
        PENDING_LOW_BYTES,
    )
}

pub fn channel_with_limits(
    max_events: usize,
    max_bytes: usize,
    low_events: usize,
    low_bytes: usize,
) -> (PendingSender, PendingReceiver) {
    let max_events = max_events.max(RESERVED_TERMINAL_EVENTS + 1);
    let max_bytes = max_bytes.max(2);
    let inner = Arc::new(Inner {
        queue: Mutex::new(Queue {
            items: VecDeque::new(),
            paused: false,
        }),
        recv_ready: Notify::new(),
        send_ready: Notify::new(),
        closed: AtomicBool::new(false),
        events: AtomicUsize::new(0),
        bytes: AtomicUsize::new(0),
        max_events,
        max_bytes,
        low_events: low_events.min(max_events.saturating_sub(RESERVED_TERMINAL_EVENTS)),
        low_bytes: low_bytes.min(max_bytes.saturating_sub(RESERVED_TERMINAL_BYTES)),
    });
    (
        PendingSender {
            inner: inner.clone(),
        },
        PendingReceiver { inner },
    )
}

impl Inner {
    fn reserve_events(&self) -> usize {
        RESERVED_TERMINAL_EVENTS
            .min(self.max_events.saturating_sub(1))
            .max(1)
    }

    fn reserve_bytes(&self) -> usize {
        let quarter = (self.max_bytes / 4).max(1);
        RESERVED_TERMINAL_BYTES.min(quarter).max(1)
    }

    fn data_event_cap(&self) -> usize {
        self.max_events.saturating_sub(self.reserve_events())
    }

    fn data_byte_cap(&self) -> usize {
        self.max_bytes.saturating_sub(self.reserve_bytes())
    }

    fn try_push(&self, env: Envelope) -> Result<(), (TrySend, Envelope)> {
        if self.closed.load(Ordering::SeqCst) {
            return Err((TrySend::Closed, env));
        }
        let terminal = is_reserved_terminal(&env);
        let add = envelope_bytes(&env);
        if !terminal && add > self.data_byte_cap() {
            return Err((TrySend::Overflow, env));
        }
        if terminal && add > self.max_bytes {
            return Err((TrySend::Overflow, env));
        }
        let Ok(mut q) = self.queue.lock() else {
            return Err((TrySend::Closed, env));
        };
        if self.closed.load(Ordering::SeqCst) {
            return Err((TrySend::Closed, env));
        }
        let used_bytes = self.bytes.load(Ordering::SeqCst);
        let (event_cap, byte_cap) = if terminal {
            (self.max_events, self.max_bytes)
        } else {
            (self.data_event_cap(), self.data_byte_cap())
        };
        if !terminal && q.paused {
            return Err((TrySend::WouldBlock, env));
        }
        if q.items.len() >= event_cap || used_bytes.saturating_add(add) > byte_cap {
            if !terminal {
                q.paused = true;
            }
            return Err((TrySend::WouldBlock, env));
        }
        q.items.push_back(env);
        self.events.store(q.items.len(), Ordering::SeqCst);
        self.bytes
            .store(used_bytes.saturating_add(add), Ordering::SeqCst);
        self.recv_ready.notify_one();
        Ok(())
    }

    fn pop(&self) -> Option<Envelope> {
        let Ok(mut q) = self.queue.lock() else {
            return None;
        };
        let env = q.items.pop_front()?;
        let add = envelope_bytes(&env);
        let used_bytes = self.bytes.load(Ordering::SeqCst).saturating_sub(add);
        self.bytes.store(used_bytes, Ordering::SeqCst);
        self.events.store(q.items.len(), Ordering::SeqCst);
        if q.paused && q.items.len() <= self.low_events && used_bytes <= self.low_bytes {
            q.paused = false;
            self.send_ready.notify_waiters();
        } else if !q.paused {
            self.send_ready.notify_waiters();
        }
        Some(env)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.recv_ready.notify_waiters();
        self.send_ready.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn len(&self) -> usize {
        self.events.load(Ordering::SeqCst)
    }

    fn byte_len(&self) -> usize {
        self.bytes.load(Ordering::SeqCst)
    }
}

impl PendingSender {
    pub async fn send(&self, mut env: Envelope) -> Result<(), SendError> {
        loop {
            match self.inner.try_push(env) {
                Ok(()) => return Ok(()),
                Err((TrySend::Closed, _)) => return Err(SendError::Closed),
                Err((TrySend::Overflow, env)) => return Err(SendError::Overflow(env)),
                Err((TrySend::WouldBlock, returned)) => {
                    env = returned;
                    if self.inner.is_closed() {
                        return Err(SendError::Closed);
                    }
                    self.inner.send_ready.notified().await;
                }
                Err((TrySend::Queued, _)) => unreachable!("queued is Ok"),
            }
        }
    }

    pub fn try_send(&self, env: Envelope) -> TrySend {
        match self.inner.try_push(env) {
            Ok(()) => TrySend::Queued,
            Err((status, _)) => status,
        }
    }

    pub fn try_send_error(&self, request_id: &str, message: &str) -> TrySend {
        self.try_send(Envelope::result_err(
            request_id.to_string(),
            message.to_string(),
        ))
    }

    pub fn close(&self) {
        self.inner.close();
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn byte_len(&self) -> usize {
        self.inner.byte_len()
    }
}

impl PendingReceiver {
    pub async fn recv(&self) -> Option<Envelope> {
        loop {
            if let Some(env) = self.inner.pop() {
                return Some(env);
            }
            if self.inner.is_closed() {
                return self.inner.pop();
            }
            self.inner.recv_ready.notified().await;
        }
    }

    pub fn try_recv(&self) -> Option<Envelope> {
        self.inner.pop()
    }

    pub fn close(&self) {
        self.inner.close();
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn byte_len(&self) -> usize {
        self.inner.byte_len()
    }
}

impl Drop for PendingReceiver {
    fn drop(&mut self) {
        self.inner.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn chunk(id: &str, data: &[u8]) -> Envelope {
        Envelope::Chunk {
            request_id: id.into(),
            stream: "pty".into(),
            data_b64: crate::util::b64_encode(data),
            seq: 0,
        }
    }

    fn end(id: &str, code: i32) -> Envelope {
        Envelope::End {
            request_id: id.into(),
            exit_code: Some(code),
            error: None,
            seq: 0,
        }
    }

    #[test]
    fn default_caps_bound_count_and_bytes() {
        let (tx, _rx) = channel();
        let mut blocked = 0;
        for i in 0..PENDING_MAX_EVENTS {
            match tx.try_send(chunk("s", &[i as u8])) {
                TrySend::Queued => {}
                TrySend::WouldBlock => blocked += 1,
                other => panic!("unexpected {other:?} at {i}"),
            }
        }
        assert!(blocked > 0, "count cap must stop the producer");
        assert!(tx.len() <= PENDING_MAX_EVENTS);
        assert_eq!(tx.try_send(end("s", 0)), TrySend::Queued);
    }

    #[test]
    fn byte_cap_blocks_before_event_cap() {
        let (tx, _rx) = channel_with_limits(32, 256, 8, 64);
        let payload = vec![b'x'; 40];
        let mut queued = 0;
        loop {
            match tx.try_send(chunk("s", &payload)) {
                TrySend::Queued => queued += 1,
                TrySend::WouldBlock => break,
                TrySend::Overflow => panic!("40-byte payload must fit the data cap"),
                TrySend::Closed => panic!("open"),
            }
            if queued > 32 {
                panic!("byte cap did not fire");
            }
        }
        assert!(queued < 32, "bytes, not events, should have been the cap");
        assert!(tx.byte_len() <= 256);
        assert_eq!(tx.try_send(end("s", 3)), TrySend::Queued);
    }

    #[test]
    fn oversized_chunk_is_overflow_and_does_not_evict() {
        let (tx, _rx) = channel_with_limits(8, 128, 2, 32);
        assert_eq!(tx.try_send(chunk("s", b"ok")), TrySend::Queued);
        let huge = vec![b'z'; 512];
        assert_eq!(tx.try_send(chunk("s", &huge)), TrySend::Overflow);
        assert_eq!(tx.len(), 1);
        assert_eq!(tx.try_send(end("s", 1)), TrySend::Queued);
    }

    #[tokio::test]
    async fn slow_consumer_receives_more_than_512_in_order() {
        let (tx, rx) = channel();
        let n = 600u32;
        let producer = tokio::spawn({
            let tx = tx.clone();
            async move {
                tx.send(chunk("s", &[0xe4])).await.unwrap();
                tx.send(chunk("s", &[0xbd, 0xa0])).await.unwrap();
                tx.send(chunk("s", b"\x1b[2;3H")).await.unwrap();
                tx.send(chunk("s", b"Z")).await.unwrap();
                for i in 0..n {
                    tx.send(chunk("s", &[(i % 251) as u8])).await.unwrap();
                }
                tx.send(end("s", 7)).await.unwrap();
            }
        });
        let mut got = Vec::new();
        let exit;
        loop {
            tokio::task::yield_now().await;
            match rx.recv().await {
                Some(Envelope::Chunk { data_b64, .. }) => {
                    got.extend(crate::util::b64_decode(&data_b64).unwrap());
                }
                Some(Envelope::End { exit_code, .. }) => {
                    exit = exit_code;
                    break;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        producer.await.unwrap();
        assert_eq!(got[0], 0xe4);
        assert_eq!(&got[1..3], &[0xbd, 0xa0]);
        assert_eq!(&got[3..9], b"\x1b[2;3H");
        assert_eq!(got[9], b'Z');
        let rest = &got[10..];
        assert_eq!(rest.len(), n as usize);
        for (i, b) in rest.iter().enumerate() {
            assert_eq!(*b, (i % 251) as u8, "byte {i}");
        }
        assert_eq!(exit, Some(7));
    }

    #[tokio::test]
    async fn send_unblocks_when_receiver_is_dropped() {
        let (tx, rx) = channel_with_limits(4, 64, 1, 16);
        while tx.try_send(chunk("s", b"ab")) == TrySend::Queued {}
        let send = tokio::spawn(async move { tx.send(chunk("s", b"cd")).await });
        tokio::time::sleep(Duration::from_millis(5)).await;
        drop(rx);
        let result = tokio::time::timeout(Duration::from_secs(1), send)
            .await
            .expect("drop must not deadlock a blocked send")
            .unwrap();
        assert!(matches!(result, Err(SendError::Closed)));
    }

    #[tokio::test]
    async fn error_uses_reserved_slot_when_data_is_full() {
        let (tx, rx) = channel_with_limits(4, 1024, 1, 64);
        while tx.try_send(chunk("s", b"x")) == TrySend::Queued {}
        assert_eq!(
            tx.try_send_error("s", "stopped"),
            TrySend::Queued,
            "reserved slot must take the error"
        );
        let mut saw_err = false;
        while let Some(env) = rx.try_recv() {
            if matches!(env, Envelope::Result { ok: false, .. }) {
                saw_err = true;
            }
        }
        assert!(saw_err);
    }
}
