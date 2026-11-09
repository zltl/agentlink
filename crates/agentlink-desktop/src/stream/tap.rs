//! Fan-out of stream frames for an audit `ScreenRecorder`.
//!
//! The recorder registers a channel. Streaming copies the [`Frame`] (the
//! pixels stay behind an `Arc`) into every live subscriber. A full channel
//! drops that one event so capture does not wait on the recorder.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};

use crate::capture::{Frame, Rect};

static NEXT: AtomicU64 = AtomicU64::new(1);

pub type TapId = u64;

#[derive(Clone, Debug)]
pub enum StreamTapEvent {
    Started {
        session_id: String,
        viewer: String,
        monitor: u32,
        codec: String,
        encoder: String,
    },
    Frame {
        session_id: String,
        frame: Frame,
        dirty: Vec<Rect>,
    },
    Stopped {
        session_id: String,
        viewer: String,
        duration_ms: u64,
        frames_sent: u64,
        bytes_sent: u64,
    },
}

struct Sink {
    id: TapId,
    tx: mpsc::Sender<StreamTapEvent>,
}

fn sinks() -> &'static Mutex<Vec<Sink>> {
    static SINKS: OnceLock<Mutex<Vec<Sink>>> = OnceLock::new();
    SINKS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn register_frame_tap(tx: mpsc::Sender<StreamTapEvent>) -> TapId {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut guard = sinks().lock().unwrap_or_else(|err| err.into_inner());
    guard.push(Sink { id, tx });
    id
}

pub fn unregister_frame_tap(id: TapId) {
    let mut guard = sinks().lock().unwrap_or_else(|err| err.into_inner());
    guard.retain(|sink| sink.id != id);
}

pub(crate) fn emit(event: StreamTapEvent) {
    let mut guard = sinks().lock().unwrap_or_else(|err| err.into_inner());
    guard.retain(|sink| sink.tx.send(event.clone()).is_ok());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subscriber_sees_start_and_stop() {
        let (tx, rx) = mpsc::channel();
        let id = register_frame_tap(tx);
        emit(StreamTapEvent::Started {
            session_id: "s".into(),
            viewer: "ada".into(),
            monitor: 0,
            codec: "h264".into(),
            encoder: "minih264".into(),
        });
        match rx.recv().unwrap() {
            StreamTapEvent::Started { viewer, .. } => assert_eq!(viewer, "ada"),
            other => panic!("unexpected {other:?}"),
        }
        unregister_frame_tap(id);
        emit(StreamTapEvent::Stopped {
            session_id: "s".into(),
            viewer: "ada".into(),
            duration_ms: 1,
            frames_sent: 0,
            bytes_sent: 0,
        });
        assert!(rx.try_recv().is_err());
    }
}
