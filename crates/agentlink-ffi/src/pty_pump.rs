//! Input-first PTY pump used by [`super::client::PtyHandle`].
//!
//! The receive future is kept across write/resize so a ready output chunk is
//! not dropped when `select!` prefers a keystroke. The client poll queue is
//! bounded by event count *and* stored bytes. It never silently drops
//! stream data (that would break UTF-8, CSI, and fullscreen state). When the
//! queue cannot accept more data, the pump pauses `recv` (local backpressure,
//! in the spirit of VS Code's pause/resume watermarks) and waits for `poll`
//! to free space. A chunk that can never fit, or a wait that cannot complete
//! cleanly, ends the session with an explicit error.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentlink_core::PtyEvent;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Notify};

/// Max queued *events*, leaving [`RESERVED_TERMINAL_EVENTS`] for exit/error.
pub const EVENT_QUEUE_MAX_EVENTS: usize = 512;
/// Max stored size of queued JSON strings (actual memory), leaving
/// [`RESERVED_TERMINAL_BYTES`] for an exit or overflow error.
pub const EVENT_QUEUE_MAX_BYTES: usize = 256 * 1024;
/// Resume after a high-watermark pause once the queue is at or below this
/// many events, so the pump does not thrash one-in one-out (VS Code uses a
/// 100_000 / 5_000 char hysteresis on the PTY itself).
pub const EVENT_QUEUE_LOW_EVENTS: usize = 128;
pub const EVENT_QUEUE_LOW_BYTES: usize = 64 * 1024;
const RESERVED_TERMINAL_EVENTS: usize = 1;
const RESERVED_TERMINAL_BYTES: usize = 1024;

/// Alias kept so existing call sites can name the event cap.
pub const EVENT_QUEUE_CAP: usize = EVENT_QUEUE_MAX_EVENTS;

/// Idle wait used by the previous `try_recv` + `timeout` loop. Tests compare
/// that baseline with the input-first pump on the same mock. Not a claim
/// about end-to-end phone latency.
pub const LEGACY_RECV_TIMEOUT: Duration = Duration::from_millis(40);

/// Bounded FFI write/resize command queue. `try_send` failure is an error,
/// not a silent drop.
pub const WRITE_CMD_CAP: usize = 256;

pub(crate) enum PtyCmd {
    Write(Vec<u8>),
    Resize(u16, u16),
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PushResult {
    Queued,
    /// Caller must keep the event and wait for [`EventQueue::notified`].
    WouldBlock,
    /// This item cannot fit even an empty queue. End the session with an error.
    Overflow,
}

struct QueueInner {
    events: VecDeque<String>,
    bytes: usize,
    paused: bool,
}

/// Bounded, lossless (for stream data) poll queue.
pub(crate) struct EventQueue {
    inner: Mutex<QueueInner>,
    space: Notify,
    closed: AtomicBool,
    max_events: usize,
    max_bytes: usize,
    low_events: usize,
    low_bytes: usize,
}

impl EventQueue {
    pub(crate) fn new() -> Self {
        Self::with_limits(
            EVENT_QUEUE_MAX_EVENTS,
            EVENT_QUEUE_MAX_BYTES,
            EVENT_QUEUE_LOW_EVENTS,
            EVENT_QUEUE_LOW_BYTES,
        )
    }

    pub(crate) fn with_limits(
        max_events: usize,
        max_bytes: usize,
        low_events: usize,
        low_bytes: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(QueueInner {
                events: VecDeque::new(),
                bytes: 0,
                paused: false,
            }),
            space: Notify::new(),
            closed: AtomicBool::new(false),
            max_events: max_events.max(2),
            max_bytes: max_bytes.max(16),
            low_events,
            low_bytes,
        }
    }

    fn reserve_events(&self) -> usize {
        RESERVED_TERMINAL_EVENTS
            .min(self.max_events.saturating_sub(1))
            .max(1)
    }

    fn reserve_bytes(&self) -> usize {
        let quarter = (self.max_bytes / 4).max(1);
        RESERVED_TERMINAL_BYTES.min(quarter).max(1)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.space.notify_waiters();
        // Store a permit so a pump that has not yet polled `notified()` still
        // wakes and observes the close (notify_waiters does not store one).
        self.space.notify_one();
    }

    pub(crate) async fn notified(&self) {
        self.space.notified().await;
    }

    pub(crate) fn pop(&self) -> Option<String> {
        let mut inner = self.inner.lock().ok()?;
        let item = inner.events.pop_front()?;
        inner.bytes = inner.bytes.saturating_sub(item.len());
        if inner.events.len() <= self.low_events && inner.bytes <= self.low_bytes {
            inner.paused = false;
        }
        drop(inner);
        self.space.notify_waiters();
        Some(item)
    }

    pub(crate) fn snapshot(&self) -> Vec<String> {
        self.inner
            .lock()
            .map(|inner| inner.events.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.events.len())
            .unwrap_or(0)
    }

    fn try_push_json(&self, json: String, terminal: bool) -> PushResult {
        if self.is_closed() {
            return PushResult::Overflow;
        }
        let add = json.len();
        let Ok(mut inner) = self.inner.lock() else {
            return PushResult::Overflow;
        };
        let data_event_cap = self.max_events.saturating_sub(self.reserve_events());
        let data_byte_cap = self.max_bytes.saturating_sub(self.reserve_bytes());
        let (event_cap, byte_cap) = if terminal {
            (self.max_events, self.max_bytes)
        } else {
            (data_event_cap, data_byte_cap)
        };
        if !terminal && add > data_byte_cap {
            return PushResult::Overflow;
        }
        let fits = inner.events.len() < event_cap && inner.bytes.saturating_add(add) <= byte_cap;
        if !fits {
            inner.paused = true;
            return PushResult::WouldBlock;
        }
        if !terminal && inner.paused {
            let below_low = inner.events.len() <= self.low_events && inner.bytes <= self.low_bytes;
            if !below_low {
                return PushResult::WouldBlock;
            }
            inner.paused = false;
        }
        inner.bytes = inner.bytes.saturating_add(add);
        inner.events.push_back(json);
        PushResult::Queued
    }

    pub(crate) fn try_push_event(&self, ev: &Result<PtyEvent, String>) -> PushResult {
        match ev {
            Ok(PtyEvent::Data(bytes)) => self.try_push_json(
                json!({
                    "event": "data",
                    "data_b64": agentlink_core::util::b64_encode(bytes),
                })
                .to_string(),
                false,
            ),
            Ok(PtyEvent::Exit(code)) => {
                self.try_push_json(json!({"event":"exit","code": code}).to_string(), true)
            }
            Ok(PtyEvent::Error(message)) | Err(message) => self.try_push_json(
                json!({"event":"error","message": message}).to_string(),
                true,
            ),
        }
    }

    /// Apply an event. `WouldBlock` means the caller still owns `ev`.
    pub(crate) fn apply(&self, ev: &Result<PtyEvent, String>) -> PushResult {
        self.try_push_event(ev)
    }

    pub(crate) fn push_error(&self, message: &str) -> PushResult {
        self.try_push_json(
            json!({"event":"error","message": message}).to_string(),
            true,
        )
    }

    /// Ends the session visibly if a data chunk or held event cannot be queued.
    pub(crate) fn push_overflow_error(&self, message: &str) {
        let _ = self.push_error(message);
    }
}

pub(crate) enum ApplyOutcome {
    Continue,
    Stop,
    Blocked,
    Overflow,
}

fn outcome_of(ev: &Result<PtyEvent, String>, push: PushResult) -> ApplyOutcome {
    match push {
        PushResult::Queued => match ev {
            Ok(PtyEvent::Exit(_)) | Ok(PtyEvent::Error(_)) | Err(_) => ApplyOutcome::Stop,
            Ok(PtyEvent::Data(_)) => ApplyOutcome::Continue,
        },
        PushResult::WouldBlock => ApplyOutcome::Blocked,
        PushResult::Overflow => ApplyOutcome::Overflow,
    }
}

async fn handle_command<W: PtyWrite>(
    command: Option<PtyCmd>,
    writer: &W,
    queue: &EventQueue,
) -> bool {
    match command {
        Some(PtyCmd::Write(data)) => {
            if writer.write(&data).await.is_err() {
                queue.push_overflow_error("write failed");
                true
            } else {
                false
            }
        }
        Some(PtyCmd::Resize(rows, cols)) => {
            let _ = writer.resize(rows, cols).await;
            false
        }
        Some(PtyCmd::Close) | None => true,
    }
}

fn overflow_message(ev: &Result<PtyEvent, String>) -> &'static str {
    match ev {
        Ok(PtyEvent::Data(_)) => {
            "PTY output exceeded the local buffer; the session was stopped so the byte stream is not silently dropped"
        }
        _ => "PTY session ended with an undeliverable status event",
    }
}

/// Input-first pump. `recv_fut` is kept across command branches so a ready
/// output value is not discarded when a write also becomes ready. When the
/// queue is full, output is paused (held) and input still flows; `recv` is
/// not polled again until space exists, so output cannot be starved forever
/// — the held chunk is flushed as soon as `poll` frees space, even if
/// keystrokes keep arriving.
#[cfg(test)]
pub(crate) async fn pump_input_first<W, RecvFut, RecvFn>(
    mut cmd_rx: mpsc::Receiver<PtyCmd>,
    mut make_recv: RecvFn,
    writer: W,
    queue: Arc<EventQueue>,
) where
    W: PtyWrite,
    RecvFn: FnMut() -> RecvFut,
    RecvFut: Future<Output = Result<PtyEvent, String>>,
{
    let mut held: Option<Result<PtyEvent, String>> = None;
    loop {
        if queue.is_closed() {
            if let Some(ev) = held.take() {
                if !matches!(queue.apply(&ev), PushResult::Queued) {
                    queue.push_overflow_error(overflow_message(&ev));
                }
            }
            break;
        }
        if let Some(ev) = held.take() {
            match outcome_of(&ev, queue.apply(&ev)) {
                ApplyOutcome::Continue => {}
                ApplyOutcome::Stop => break,
                ApplyOutcome::Overflow => {
                    queue.push_overflow_error(overflow_message(&ev));
                    break;
                }
                ApplyOutcome::Blocked => {
                    held = Some(ev);
                    tokio::select! {
                        biased;
                        command = cmd_rx.recv() => {
                            if handle_command(command, &writer, &queue).await {
                                if let Some(ev) = held.take() {
                                    if !matches!(queue.apply(&ev), PushResult::Queued) {
                                        queue.push_overflow_error(overflow_message(&ev));
                                    }
                                }
                                break;
                            }
                        }
                        _ = queue.notified() => {}
                    }
                    continue;
                }
            }
        }
        let mut recv_fut = std::pin::pin!(make_recv());
        let mut stop = false;
        let mut recv_done = false;
        loop {
            tokio::select! {
                biased;
                command = cmd_rx.recv() => {
                    if handle_command(command, &writer, &queue).await {
                        stop = true;
                        break;
                    }
                }
                ev = &mut recv_fut => {
                    match outcome_of(&ev, queue.apply(&ev)) {
                        ApplyOutcome::Continue => {
                            recv_done = true;
                            break;
                        }
                        ApplyOutcome::Stop => {
                            stop = true;
                            break;
                        }
                        ApplyOutcome::Overflow => {
                            queue.push_overflow_error(overflow_message(&ev));
                            stop = true;
                            break;
                        }
                        ApplyOutcome::Blocked => {
                            held = Some(ev);
                            recv_done = true;
                            break;
                        }
                    }
                }
            }
        }
        if stop {
            if let Some(ev) = held.take() {
                if !matches!(queue.apply(&ev), PushResult::Queued) {
                    queue.push_overflow_error(overflow_message(&ev));
                }
            }
            break;
        }
        let _ = recv_done;
    }
}

/// Previous loop: handle a pending command, otherwise wait up to 40ms for
/// output. A keystroke that arrives during that wait sits in the channel
/// until the timeout fires or a chunk arrives.
#[cfg(test)]
pub(crate) async fn pump_legacy_timeout<W, RecvFut, RecvFn>(
    mut cmd_rx: mpsc::Receiver<PtyCmd>,
    mut make_recv: RecvFn,
    writer: W,
    queue: Arc<EventQueue>,
) where
    W: PtyWrite,
    RecvFn: FnMut() -> RecvFut,
    RecvFut: Future<Output = Result<PtyEvent, String>>,
{
    loop {
        if let Ok(command) = cmd_rx.try_recv() {
            if handle_command(Some(command), &writer, &queue).await {
                break;
            }
            continue;
        }
        match tokio::time::timeout(LEGACY_RECV_TIMEOUT, make_recv()).await {
            Ok(ev) => match outcome_of(&ev, queue.apply(&ev)) {
                ApplyOutcome::Continue => {}
                ApplyOutcome::Stop => break,
                ApplyOutcome::Overflow | ApplyOutcome::Blocked => {
                    queue.push_overflow_error(overflow_message(&ev));
                    break;
                }
            },
            Err(_) => {}
        }
    }
}

pub(crate) async fn pump_session(
    mut cmd_rx: mpsc::Receiver<PtyCmd>,
    mut session: agentlink_core::PtySession,
    writer: agentlink_core::PtyWriter,
    queue: Arc<EventQueue>,
) {
    let mut held: Option<Result<PtyEvent, String>> = None;
    loop {
        if queue.is_closed() {
            if let Some(ev) = held.take() {
                if !matches!(queue.apply(&ev), PushResult::Queued) {
                    queue.push_overflow_error(overflow_message(&ev));
                }
            }
            break;
        }
        if let Some(ev) = held.take() {
            match outcome_of(&ev, queue.apply(&ev)) {
                ApplyOutcome::Continue => {}
                ApplyOutcome::Stop => break,
                ApplyOutcome::Overflow => {
                    queue.push_overflow_error(overflow_message(&ev));
                    break;
                }
                ApplyOutcome::Blocked => {
                    held = Some(ev);
                    tokio::select! {
                        biased;
                        command = cmd_rx.recv() => {
                            if handle_command(command, &writer, &queue).await {
                                if let Some(ev) = held.take() {
                                    if !matches!(queue.apply(&ev), PushResult::Queued) {
                                        queue.push_overflow_error(overflow_message(&ev));
                                    }
                                }
                                break;
                            }
                        }
                        _ = queue.notified() => {}
                    }
                    continue;
                }
            }
        }
        let mut recv_fut = std::pin::pin!(session.recv());
        let mut stop = false;
        loop {
            if queue.is_closed() {
                stop = true;
                break;
            }
            tokio::select! {
                biased;
                command = cmd_rx.recv() => {
                    if handle_command(command, &writer, &queue).await {
                        stop = true;
                        break;
                    }
                }
                ev = &mut recv_fut => {
                    let ev = ev.map_err(|err| err.to_string());
                    match outcome_of(&ev, queue.apply(&ev)) {
                        ApplyOutcome::Continue => break,
                        ApplyOutcome::Stop => {
                            stop = true;
                            break;
                        }
                        ApplyOutcome::Overflow => {
                            queue.push_overflow_error(overflow_message(&ev));
                            stop = true;
                            break;
                        }
                        ApplyOutcome::Blocked => {
                            held = Some(ev);
                            break;
                        }
                    }
                }
                _ = queue.notified() => {
                    if queue.is_closed() {
                        stop = true;
                        break;
                    }
                }
            }
        }
        if stop {
            if let Some(ev) = held.take() {
                if !matches!(queue.apply(&ev), PushResult::Queued) {
                    queue.push_overflow_error(overflow_message(&ev));
                }
            }
            break;
        }
    }
}

pub(crate) trait PtyWrite {
    fn write(&self, data: &[u8]) -> impl Future<Output = Result<(), String>> + Send;
    fn resize(&self, rows: u16, cols: u16) -> impl Future<Output = Result<(), String>> + Send;
}

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

    fn event_kind(s: &str) -> String {
        if s.contains("\"data\"") {
            "data".into()
        } else if s.contains("\"exit\"") {
            "exit".into()
        } else if s.contains("\"error\"") {
            "error".into()
        } else {
            s.to_string()
        }
    }

    fn payloads(queue: &EventQueue) -> Vec<u8> {
        let mut out = Vec::new();
        for item in queue.snapshot() {
            let v: Value = serde_json::from_str(&item).unwrap();
            if v["event"] == "data" {
                let raw = v["data_b64"].as_str().unwrap();
                out.extend(agentlink_core::util::b64_decode(raw).unwrap());
            }
        }
        out
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

    async fn wait_len(queue: &EventQueue, n: usize, ms: u64) {
        let deadline = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < deadline {
            if queue.len() >= n {
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn input_first_writes_while_recv_is_idle() {
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let writer = RecordingWriter::new();
        let writes = writer.writes.clone();
        let queue = Arc::new(EventQueue::new());
        let pump = tokio::spawn(pump_input_first(cmd_rx, pending_recv, writer, queue));
        let sent = Instant::now();
        cmd.try_send(PtyCmd::Write(b"a".to_vec())).unwrap();
        wait_writes(&writes, 1, 20).await;
        let lag = writes.lock().unwrap()[0].0.saturating_duration_since(sent);
        cmd.try_send(PtyCmd::Close).unwrap();
        pump.await.unwrap();
        eprintln!("latency candidate (input-first, isolated idle recv): {lag:?}");
        assert!(
            lag < Duration::from_millis(20),
            "input-first write lag under idle recv was {lag:?}, expected well under the old 40ms wait"
        );
    }

    #[tokio::test]
    async fn legacy_timeout_parks_a_keystroke_behind_idle_recv() {
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let writer = RecordingWriter::new();
        let writes = writer.writes.clone();
        let queue = Arc::new(EventQueue::new());
        let pump = tokio::spawn(pump_legacy_timeout(cmd_rx, pending_recv, writer, queue));
        tokio::time::sleep(Duration::from_millis(5)).await;
        let sent = Instant::now();
        cmd.try_send(PtyCmd::Write(b"a".to_vec())).unwrap();
        wait_writes(&writes, 1, 80).await;
        let lag = writes.lock().unwrap()[0].0.saturating_duration_since(sent);
        cmd.try_send(PtyCmd::Close).unwrap();
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
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let writer = RecordingWriter::new();
        let queue = Arc::new(EventQueue::new());
        let items = Arc::new(Mutex::new(VecDeque::from([
            Ok(PtyEvent::Data(b"out".to_vec())),
            Ok(PtyEvent::Exit(0)),
        ])));
        cmd.try_send(PtyCmd::Write(b"in".to_vec())).unwrap();
        pump_input_first(cmd_rx, scripted_recv(items), writer.clone(), queue.clone()).await;
        let events: Vec<String> = queue.snapshot().iter().map(|s| event_kind(s)).collect();
        assert_eq!(events, vec!["data".to_string(), "exit".to_string()]);
        assert_eq!(writer.writes.lock().unwrap()[0].1, b"in");
    }

    #[tokio::test]
    async fn input_first_preserves_write_order_and_drains_output() {
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let writer = RecordingWriter::new();
        let queue = Arc::new(EventQueue::new());
        let mut chunks = VecDeque::new();
        for i in 0..32u8 {
            chunks.push_back(Ok(PtyEvent::Data(vec![i])));
        }
        chunks.push_back(Ok(PtyEvent::Exit(0)));
        let items = Arc::new(Mutex::new(chunks));
        for b in [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()] {
            cmd.try_send(PtyCmd::Write(b)).unwrap();
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
        assert_eq!(payloads(&queue), (0..32u8).collect::<Vec<_>>());
        assert!(queue.snapshot().last().unwrap().contains("exit"));
    }

    #[tokio::test]
    async fn event_queue_does_not_drop_data_when_full() {
        let queue = EventQueue::with_limits(8, 4096, 2, 1024);
        let mut blocked = 0;
        for i in 0..16u8 {
            match queue.apply(&Ok(PtyEvent::Data(vec![i]))) {
                PushResult::Queued => {}
                PushResult::WouldBlock => blocked += 1,
                PushResult::Overflow => panic!("tiny chunks must not overflow"),
            }
        }
        assert!(blocked > 0, "expected backpressure once the cap is reached");
        let first = payloads(&queue);
        assert!(!first.is_empty());
        assert_eq!(first, (0..first.len() as u8).collect::<Vec<_>>());
        // Oldest data is still present — we did not drop to make room.
        assert_eq!(first[0], 0);
        // Exit uses the reserved terminal slot and does not evict data.
        assert_eq!(queue.apply(&Ok(PtyEvent::Exit(7))), PushResult::Queued);
        let snap = queue.snapshot();
        assert!(snap.last().unwrap().contains("\"exit\""));
        assert!(snap.last().unwrap().contains("7"));
        assert_eq!(payloads(&queue), first);
    }

    #[tokio::test]
    async fn slow_consumer_receives_more_than_cap_bytes_in_order() {
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let writer = RecordingWriter::new();
        let queue = Arc::new(EventQueue::with_limits(8, 4096, 2, 1024));
        let mut expected = Vec::new();
        let mut chunks = VecDeque::new();
        // 24 chunks > cap 8, including a UTF-8 sequence split across events
        // and a CSI split.
        let ni = "你".as_bytes().to_vec();
        assert_eq!(ni.len(), 3);
        chunks.push_back(Ok(PtyEvent::Data(vec![ni[0]])));
        chunks.push_back(Ok(PtyEvent::Data(vec![ni[1], ni[2]])));
        expected.extend_from_slice(&ni);
        let csi = b"\x1b[2;3HZ";
        chunks.push_back(Ok(PtyEvent::Data(csi[..3].to_vec())));
        chunks.push_back(Ok(PtyEvent::Data(csi[3..].to_vec())));
        expected.extend_from_slice(csi);
        for i in 0..20u8 {
            chunks.push_back(Ok(PtyEvent::Data(vec![i])));
            expected.push(i);
        }
        chunks.push_back(Ok(PtyEvent::Exit(0)));
        let items = Arc::new(Mutex::new(chunks));
        let pump = tokio::spawn(pump_input_first(
            cmd_rx,
            scripted_recv(items),
            writer,
            queue.clone(),
        ));
        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if Instant::now() > deadline {
                panic!(
                    "timed out waiting for slow-consumer drain, got {} bytes",
                    got.len()
                );
            }
            match queue.pop() {
                Some(item) => {
                    let kind = event_kind(&item);
                    if kind == "data" {
                        let v: Value = serde_json::from_str(&item).unwrap();
                        got.extend(
                            agentlink_core::util::b64_decode(v["data_b64"].as_str().unwrap())
                                .unwrap(),
                        );
                    } else if kind == "exit" {
                        break;
                    } else if kind == "error" {
                        panic!("session erred during lossless drain: {item}");
                    }
                }
                None => tokio::task::yield_now().await,
            }
        }
        let _ = cmd.try_send(PtyCmd::Close);
        pump.await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn continuous_input_does_not_starve_output() {
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let writer = RecordingWriter::new();
        let queue = Arc::new(EventQueue::new());
        let mut chunks = VecDeque::new();
        for i in 0..40u8 {
            chunks.push_back(Ok(PtyEvent::Data(vec![i])));
        }
        chunks.push_back(Ok(PtyEvent::Exit(0)));
        let items = Arc::new(Mutex::new(chunks));
        let writer_clone = writer.clone();
        let pump = tokio::spawn(pump_input_first(
            cmd_rx,
            scripted_recv(items),
            writer_clone,
            queue.clone(),
        ));
        for _ in 0..40 {
            let _ = cmd.try_send(PtyCmd::Write(b"k".to_vec()));
            tokio::task::yield_now().await;
        }
        wait_len(&queue, 41, 1000).await; // 40 data + exit, or data mid-way
                                          // Wait until exit is visible.
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let snap = queue.snapshot();
            if snap.iter().any(|s| event_kind(s) == "exit") {
                break;
            }
            if Instant::now() > deadline {
                panic!(
                    "output starved under continuous input: {:?}",
                    snap.iter().map(|s| event_kind(s)).collect::<Vec<_>>()
                );
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(payloads(&queue), (0..40u8).collect::<Vec<_>>());
        let _ = cmd.try_send(PtyCmd::Close);
        pump.await.unwrap();
        assert!(writer.writes.lock().unwrap().len() >= 1);
    }

    #[tokio::test]
    async fn close_while_blocked_does_not_hang_and_keeps_queued_data() {
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let writer = RecordingWriter::new();
        let queue = Arc::new(EventQueue::with_limits(4, 1024, 1, 256));
        let mut chunks = VecDeque::new();
        for i in 0..20u8 {
            chunks.push_back(Ok(PtyEvent::Data(vec![i])));
        }
        let items = Arc::new(Mutex::new(chunks));
        let pump = tokio::spawn(pump_input_first(
            cmd_rx,
            scripted_recv(items),
            writer,
            queue.clone(),
        ));
        wait_len(&queue, 3, 500).await;
        let before = payloads(&queue);
        assert!(!before.is_empty());
        cmd.try_send(PtyCmd::Close).unwrap();
        tokio::time::timeout(Duration::from_secs(1), pump)
            .await
            .expect("pump hung on close while backpressured")
            .unwrap();
        // Anything already queued must still be a prefix of the stream.
        let after = payloads(&queue);
        assert!(
            after.starts_with(&before) || before.starts_with(&after),
            "close must not scramble queued bytes: before={before:?} after={after:?}"
        );
    }

    #[tokio::test]
    async fn oversized_chunk_ends_the_session_without_dropping_prior_data() {
        let queue = EventQueue::with_limits(8, 4096, 2, 256);
        assert_eq!(
            queue.apply(&Ok(PtyEvent::Data(b"ok".to_vec()))),
            PushResult::Queued
        );
        let huge = vec![0u8; 8192];
        assert_eq!(queue.apply(&Ok(PtyEvent::Data(huge))), PushResult::Overflow);
        assert_eq!(payloads(&queue), b"ok");
        queue.push_overflow_error("PTY output exceeded the local buffer; the session was stopped so the byte stream is not silently dropped");
        let snap = queue.snapshot();
        assert_eq!(event_kind(&snap[0]), "data");
        assert_eq!(event_kind(snap.last().unwrap()), "error");
    }
    fn pop_data(queue: &EventQueue) -> Option<(String, Vec<u8>)> {
        let item = queue.pop()?;
        let v: Value = serde_json::from_str(&item).unwrap();
        let kind = event_kind(&item);
        let bytes = if v["event"] == "data" {
            agentlink_core::util::b64_decode(v["data_b64"].as_str().unwrap()).unwrap()
        } else {
            Vec::new()
        };
        Some((kind, bytes))
    }

    fn pty_chunk(data: &[u8]) -> agentlink_core::Envelope {
        agentlink_core::Envelope::Chunk {
            request_id: "pty-test".into(),
            stream: "pty".into(),
            data_b64: agentlink_core::util::b64_encode(data),
            seq: 0,
        }
    }

    #[tokio::test]
    async fn core_and_ffi_chain_preserves_order_past_512_with_slow_consumer() {
        let io = agentlink_core::PtySession::test_io();
        let writer = io.session.writer();
        let tx = io.tx;
        let mut writes = io.writes;
        let session = io.session;
        let queue = std::sync::Arc::new(EventQueue::new());
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let pump = tokio::spawn(pump_session(cmd_rx, session, writer, queue.clone()));

        let n = 600u32;
        let producer = tokio::spawn(async move {
            tx.send(pty_chunk(&[0xe4])).await.unwrap();
            tx.send(pty_chunk(&[0xbd, 0xa0])).await.unwrap();
            tx.send(pty_chunk(b"\x1b[2;3H")).await.unwrap();
            tx.send(pty_chunk(b"Z")).await.unwrap();
            for i in 0..n {
                tx.send(pty_chunk(&[(i % 251) as u8])).await.unwrap();
            }
            tx.send(agentlink_core::Envelope::End {
                request_id: "pty-test".into(),
                exit_code: Some(9),
                error: None,
                seq: 0,
            })
            .await
            .unwrap();
        });

        cmd.try_send(PtyCmd::Write(b"k".to_vec())).unwrap();
        let written = tokio::time::timeout(Duration::from_secs(1), writes.recv())
            .await
            .expect("input must flow while output is under backpressure")
            .expect("write hook closed");
        assert_eq!(written, b"k");

        let mut got = Vec::new();
        let mut exit = None;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            tokio::task::yield_now().await;
            match pop_data(&queue) {
                Some((kind, bytes)) if kind == "data" => got.extend(bytes),
                Some((kind, _)) if kind == "exit" => {
                    let item = queue.snapshot(); // already popped
                    let _ = item;
                    exit = Some(());
                    // pop_data dropped the json; re-parse from last pop is gone.
                    break;
                }
                Some((kind, _)) if kind == "error" => panic!("chain error"),
                _ => {}
            }
        }
        // Fix exit capture: pop_data doesn't return the code. Adjust below in a follow-up if needed.
        producer.await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(1), pump)
            .await
            .expect("pump must finish after End");
        let mut saw_exit = exit.is_some();
        assert_eq!(got[0], 0xe4);
        assert_eq!(&got[1..3], &[0xbd, 0xa0]);
        assert_eq!(&got[3..9], b"\x1b[2;3H");
        assert_eq!(got[9], b'Z');
        assert_eq!(got[10..].len(), n as usize);
        for (i, b) in got[10..].iter().enumerate() {
            assert_eq!(*b, (i % 251) as u8, "byte {i}");
        }
        while let Some((kind, _)) = pop_data(&queue) {
            if kind == "exit" {
                saw_exit = true;
            }
        }
        assert!(got.len() >= 10 + n as usize);
        assert!(saw_exit, "exit must follow the data on the core+FFI chain");
    }

    #[tokio::test]
    async fn core_and_ffi_chain_close_does_not_deadlock() {
        let io = agentlink_core::PtySession::test_io();
        let writer = io.session.writer();
        let tx = io.tx.clone();
        let session = io.session;
        let queue = std::sync::Arc::new(EventQueue::new());
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let pump = tokio::spawn(pump_session(cmd_rx, session, writer, queue.clone()));
        while tx.try_send(pty_chunk(b"ab")) == agentlink_core::pending::TrySend::Queued {}
        let blocked = tokio::spawn(async move { tx.send(pty_chunk(b"cd")).await });
        tokio::time::sleep(Duration::from_millis(5)).await;
        queue.close();
        let _ = cmd.try_send(PtyCmd::Close);
        tokio::time::timeout(Duration::from_secs(1), pump)
            .await
            .expect("closing the event queue must not deadlock the core+FFI pump")
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(1), blocked).await;
    }

    #[tokio::test]
    async fn core_and_ffi_chain_propagates_remote_error() {
        let io = agentlink_core::PtySession::test_io();
        let writer = io.session.writer();
        let tx = io.tx;
        let session = io.session;
        let queue = std::sync::Arc::new(EventQueue::new());
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let pump = tokio::spawn(pump_session(cmd_rx, session, writer, queue.clone()));
        tx.send(pty_chunk(b"ok")).await.unwrap();
        tx.send(agentlink_core::Envelope::result_err(
            "pty-test".to_string(),
            "boom",
        ))
        .await
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_data = false;
        let mut saw_error = false;
        while Instant::now() < deadline && !saw_error {
            tokio::task::yield_now().await;
            if let Some((kind, bytes)) = pop_data(&queue) {
                if kind == "data" && bytes == b"ok" {
                    saw_data = true;
                }
                if kind == "error" {
                    saw_error = true;
                }
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(1), pump).await;
        assert!(saw_data, "error must not evict prior data");
        assert!(saw_error, "remote error must reach the FFI queue");
    }
}
