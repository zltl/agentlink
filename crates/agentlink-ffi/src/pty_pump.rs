//! Input-first PTY pump used by [`super::client::PtyHandle`].
//!
//! The receive future is pinned across write/resize so a ready output chunk is
//! not dropped when `select!` prefers a keystroke. Writes go through a send
//! handle that does not borrow `recv`.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentlink_core::PtyEvent;
use serde_json::{json, Value};
use tokio::sync::mpsc;

/// Drop the oldest *data* event once the client poll queue reaches this many
/// items. Exit and error events are kept. This is local backpressure only; it
/// does not pause the remote PTY (no flow-control protocol in this change).
pub const EVENT_QUEUE_CAP: usize = 512;

/// Idle wait used by the previous `try_recv` + `timeout` loop. Tests compare
/// that baseline with the input-first pump on the same mock. Not a claim
/// about end-to-end phone latency.
pub const LEGACY_RECV_TIMEOUT: Duration = Duration::from_millis(40);

pub(crate) enum PtyCmd {
    Write(Vec<u8>),
    Resize(u16, u16),
    Close,
}

pub(crate) fn push_event(queue: &Mutex<VecDeque<String>>, value: Value) {
    let Ok(mut queue) = queue.lock() else {
        return;
    };
    if queue.len() >= EVENT_QUEUE_CAP {
        if let Some(idx) = queue
            .iter()
            .position(|item| item.contains("\"event\":\"data\""))
        {
            queue.remove(idx);
        } else {
            return;
        }
    }
    queue.push_back(value.to_string());
}

pub(crate) fn apply_event(queue: &Mutex<VecDeque<String>>, ev: Result<PtyEvent, String>) -> bool {
    match ev {
        Ok(PtyEvent::Data(bytes)) => {
            push_event(
                queue,
                json!({
                    "event": "data",
                    "data_b64": agentlink_core::util::b64_encode(&bytes),
                }),
            );
            false
        }
        Ok(PtyEvent::Exit(code)) => {
            push_event(queue, json!({"event":"exit","code": code}));
            true
        }
        Ok(PtyEvent::Error(message)) | Err(message) => {
            push_event(queue, json!({"event":"error","message": message}));
            true
        }
    }
}

/// Input-first pump. `recv_fut` is kept across command branches so a ready
/// output value is not discarded when a write also becomes ready.
#[cfg(test)]
pub(crate) async fn pump_input_first<W, RecvFut, RecvFn>(
    mut cmd_rx: mpsc::UnboundedReceiver<PtyCmd>,
    mut make_recv: RecvFn,
    writer: W,
    queue: Arc<Mutex<VecDeque<String>>>,
) where
    W: PtyWrite,
    RecvFn: FnMut() -> RecvFut,
    RecvFut: Future<Output = Result<PtyEvent, String>>,
{
    loop {
        let mut recv_fut = std::pin::pin!(make_recv());
        let mut stop = false;
        let mut recv_done = false;
        loop {
            tokio::select! {
                biased;
                command = cmd_rx.recv() => {
                    match command {
                        Some(PtyCmd::Write(data)) => {
                            if writer.write(&data).await.is_err() {
                                push_event(
                                    &queue,
                                    json!({"event":"error","message":"write failed"}),
                                );
                                stop = true;
                            }
                        }
                        Some(PtyCmd::Resize(rows, cols)) => {
                            let _ = writer.resize(rows, cols).await;
                        }
                        Some(PtyCmd::Close) | None => stop = true,
                    }
                    if stop {
                        break;
                    }
                }
                ev = &mut recv_fut => {
                    if apply_event(&queue, ev) {
                        stop = true;
                    }
                    recv_done = true;
                    break;
                }
            }
        }
        if stop {
            break;
        }
        // Completed recv future is dropped here before the next session.recv().
        let _ = recv_done;
    }
}

/// Previous loop: handle a pending command, otherwise wait up to 40ms for
/// output. A keystroke that arrives during that wait sits in the channel
/// until the timeout fires or a chunk arrives.
#[cfg(test)]
pub(crate) async fn pump_legacy_timeout<W, RecvFut, RecvFn>(
    mut cmd_rx: mpsc::UnboundedReceiver<PtyCmd>,
    mut make_recv: RecvFn,
    writer: W,
    queue: Arc<Mutex<VecDeque<String>>>,
) where
    W: PtyWrite,
    RecvFn: FnMut() -> RecvFut,
    RecvFut: Future<Output = Result<PtyEvent, String>>,
{
    loop {
        if let Ok(command) = cmd_rx.try_recv() {
            match command {
                PtyCmd::Write(data) => {
                    if writer.write(&data).await.is_err() {
                        push_event(&queue, json!({"event":"error","message":"write failed"}));
                        break;
                    }
                }
                PtyCmd::Resize(rows, cols) => {
                    let _ = writer.resize(rows, cols).await;
                }
                PtyCmd::Close => break,
            }
            continue;
        }
        match tokio::time::timeout(LEGACY_RECV_TIMEOUT, make_recv()).await {
            Ok(ev) => {
                if apply_event(&queue, ev) {
                    break;
                }
            }
            Err(_) => {}
        }
    }
}

pub(crate) async fn pump_session(
    mut cmd_rx: mpsc::UnboundedReceiver<PtyCmd>,
    mut session: agentlink_core::PtySession,
    writer: agentlink_core::PtyWriter,
    queue: Arc<Mutex<VecDeque<String>>>,
) {
    loop {
        let mut recv_fut = std::pin::pin!(session.recv());
        let mut stop = false;
        let mut recv_done = false;
        loop {
            tokio::select! {
                biased;
                command = cmd_rx.recv() => {
                    match command {
                        Some(PtyCmd::Write(data)) => {
                            if writer.write(&data).await.is_err() {
                                push_event(
                                    &queue,
                                    json!({"event":"error","message":"write failed"}),
                                );
                                stop = true;
                            }
                        }
                        Some(PtyCmd::Resize(rows, cols)) => {
                            let _ = writer.resize(rows, cols).await;
                        }
                        Some(PtyCmd::Close) | None => stop = true,
                    }
                    if stop {
                        break;
                    }
                }
                ev = &mut recv_fut => {
                    let ev = ev.map_err(|err| err.to_string());
                    if apply_event(&queue, ev) {
                        stop = true;
                    }
                    recv_done = true;
                    break;
                }
            }
        }
        if stop {
            break;
        }
        let _ = recv_done;
    }
}

#[cfg(test)]
pub(crate) trait PtyWrite {
    fn write(&self, data: &[u8]) -> impl Future<Output = Result<(), String>> + Send;
    fn resize(&self, rows: u16, cols: u16) -> impl Future<Output = Result<(), String>> + Send;
}

#[cfg(test)]
impl PtyWrite for agentlink_core::PtyWriter {
    async fn write(&self, data: &[u8]) -> Result<(), String> {
        agentlink_core::PtyWriter::write(self, data)
            .await
            .map_err(|err| err.to_string())
    }

    async fn resize(&self, rows: u16, cols: u16) -> Result<(), String> {
        agentlink_core::PtyWriter::resize(self, rows, cols)
            .await
            .map_err(|err| err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    #[derive(Clone)]
    struct RecordingWriter {
        writes: Arc<Mutex<Vec<(Instant, Vec<u8>)>>>,
        count: Arc<AtomicUsize>,
    }

    impl RecordingWriter {
        fn new() -> Self {
            Self {
                writes: Arc::new(Mutex::new(Vec::new())),
                count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl PtyWrite for RecordingWriter {
        async fn write(&self, data: &[u8]) -> Result<(), String> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.writes
                .lock()
                .unwrap()
                .push((Instant::now(), data.to_vec()));
            Ok(())
        }

        async fn resize(&self, _rows: u16, _cols: u16) -> Result<(), String> {
            Ok(())
        }
    }

    fn pending_recv() -> impl Future<Output = Result<PtyEvent, String>> {
        std::future::pending()
    }

    fn scripted_recv(
        items: Arc<Mutex<VecDeque<Result<PtyEvent, String>>>>,
    ) -> impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = Result<PtyEvent, String>> + Send>>
    {
        move || {
            let items = items.clone();
            Box::pin(async move {
                loop {
                    if let Some(ev) = items.lock().unwrap().pop_front() {
                        return ev;
                    }
                    tokio::task::yield_now().await;
                }
            })
        }
    }

    async fn wait_writes(writes: &Mutex<Vec<(Instant, Vec<u8>)>>, n: usize, ms: u64) {
        let deadline = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < deadline {
            if writes.lock().unwrap().len() >= n {
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn input_first_writes_while_recv_is_idle() {
        let (cmd, cmd_rx) = mpsc::unbounded_channel();
        let writer = RecordingWriter::new();
        let writes = writer.writes.clone();
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let pump = tokio::spawn(pump_input_first(cmd_rx, pending_recv, writer, queue));
        let sent = Instant::now();
        cmd.send(PtyCmd::Write(b"a".to_vec())).unwrap();
        wait_writes(&writes, 1, 20).await;
        let lag = writes.lock().unwrap()[0].0.saturating_duration_since(sent);
        cmd.send(PtyCmd::Close).unwrap();
        pump.await.unwrap();
        eprintln!("latency candidate (input-first, isolated idle recv): {lag:?}");
        assert!(
            lag < Duration::from_millis(20),
            "input-first write lag under idle recv was {lag:?}, expected well under the old 40ms wait"
        );
    }

    #[tokio::test]
    async fn legacy_timeout_parks_a_keystroke_behind_idle_recv() {
        let (cmd, cmd_rx) = mpsc::unbounded_channel();
        let writer = RecordingWriter::new();
        let writes = writer.writes.clone();
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let pump = tokio::spawn(pump_legacy_timeout(cmd_rx, pending_recv, writer, queue));
        // Let the pump enter the 40ms recv wait with an empty command queue.
        tokio::time::sleep(Duration::from_millis(5)).await;
        let sent = Instant::now();
        cmd.send(PtyCmd::Write(b"a".to_vec())).unwrap();
        wait_writes(&writes, 1, 80).await;
        let lag = writes.lock().unwrap()[0].0.saturating_duration_since(sent);
        cmd.send(PtyCmd::Close).unwrap();
        pump.await.unwrap();
        eprintln!("latency baseline (legacy 40ms timeout, isolated idle recv): {lag:?}");
        assert!(
            lag >= Duration::from_millis(20),
            "legacy baseline should park the keystroke behind the remaining idle timeout, lag was {lag:?}"
        );
        assert!(
            lag < Duration::from_millis(80),
            "lag {lag:?} unexpectedly high"
        );
    }

    #[tokio::test]
    async fn input_first_keeps_ready_output_when_a_write_is_also_ready() {
        let (cmd, cmd_rx) = mpsc::unbounded_channel();
        let writer = RecordingWriter::new();
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let items = Arc::new(Mutex::new(VecDeque::from([
            Ok(PtyEvent::Data(b"out".to_vec())),
            Ok(PtyEvent::Exit(0)),
        ])));
        cmd.send(PtyCmd::Write(b"in".to_vec())).unwrap();
        pump_input_first(cmd_rx, scripted_recv(items), writer.clone(), queue.clone()).await;
        let events: Vec<String> = queue
            .lock()
            .unwrap()
            .iter()
            .map(|s| {
                if s.contains("\"data\"") {
                    "data".into()
                } else if s.contains("\"exit\"") {
                    "exit".into()
                } else {
                    s.clone()
                }
            })
            .collect();
        assert_eq!(events, vec!["data".to_string(), "exit".to_string()]);
        assert_eq!(writer.writes.lock().unwrap()[0].1, b"in");
    }

    #[tokio::test]
    async fn input_first_preserves_write_order_and_drains_output() {
        let (cmd, cmd_rx) = mpsc::unbounded_channel();
        let writer = RecordingWriter::new();
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut chunks = VecDeque::new();
        for i in 0..32u8 {
            chunks.push_back(Ok(PtyEvent::Data(vec![i])));
        }
        chunks.push_back(Ok(PtyEvent::Exit(0)));
        let items = Arc::new(Mutex::new(chunks));
        for b in [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()] {
            cmd.send(PtyCmd::Write(b)).unwrap();
        }
        pump_input_first(cmd_rx, scripted_recv(items), writer.clone(), queue.clone()).await;
        let got: Vec<Vec<u8>> = writer
            .writes
            .lock()
            .unwrap()
            .iter()
            .map(|(_, bytes)| bytes.clone())
            .collect();
        assert_eq!(
            got,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );
        let data = queue
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.contains("\"data\""))
            .count();
        assert_eq!(data, 32);
        assert!(queue.lock().unwrap().back().unwrap().contains("exit"));
    }

    #[tokio::test]
    async fn event_queue_drops_oldest_data_but_keeps_exit() {
        let queue = Mutex::new(VecDeque::new());
        for i in 0..(EVENT_QUEUE_CAP + 8) {
            apply_event(&queue, Ok(PtyEvent::Data(vec![i as u8])));
        }
        assert_eq!(queue.lock().unwrap().len(), EVENT_QUEUE_CAP);
        apply_event(&queue, Ok(PtyEvent::Exit(7)));
        let q = queue.lock().unwrap();
        assert_eq!(q.len(), EVENT_QUEUE_CAP);
        assert!(q.back().unwrap().contains("\"exit\""));
        assert!(q.back().unwrap().contains("7"));
    }
}
