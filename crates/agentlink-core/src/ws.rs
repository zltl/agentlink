//! WebSocket framing helpers shared by the client, relay, and node.

use std::time::Duration;

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use crate::protocol::Envelope;

/// How long the relay keeps a node in the online map after its last inbound frame.
///
/// `agentlink nodes` and the dashboard treat anything older as offline, even
/// while the TCP socket is still in the table.
pub const RELAY_STALE_AFTER: Duration = Duration::from_secs(75);

/// How often a node should send [`Envelope::Ping`] after `HelloOk`.
///
/// The relay advertises `heartbeat_secs` (20 today). Honor that, and never
/// wait so long that one quiet interval plus a single missed beat crosses
/// [`RELAY_STALE_AFTER`].
pub fn heartbeat_interval(heartbeat_secs: u64) -> Duration {
    const DEFAULT_SECS: u64 = 20;
    const MAX_SECS: u64 = 30;
    let secs = if heartbeat_secs == 0 {
        DEFAULT_SECS
    } else {
        heartbeat_secs
    };
    Duration::from_secs(secs.clamp(1, MAX_SECS))
}

/// Inbound silence after which the peer is treated as gone.
///
/// Two heartbeat intervals plus a short grace: one delayed pong is not a dead
/// socket, and a second miss is. The cap stays under a TCP retransmit timeout
/// (minutes to hours) so a half-open session cannot sit there all afternoon.
/// With the usual 20s advertisement this is 50s, which is before the relay
/// drops the online bit at [`RELAY_STALE_AFTER`].
pub fn silence_limit(heartbeat_secs: u64) -> Duration {
    let interval = heartbeat_interval(heartbeat_secs);
    let limit = interval.saturating_mul(2) + Duration::from_secs(10);
    limit.clamp(Duration::from_secs(15), Duration::from_secs(70))
}

/// What [`wait_for_frame`] observed.
pub enum FrameWait {
    Message(Message),
    /// No inbound frame within the silence budget. TCP may still look established.
    Silent,
    /// The write half returned. The read half can stay pending after that.
    WriterStopped,
    Shutdown,
    Eof,
}

/// Read one websocket message, or report that the link is no longer alive.
///
/// `writer_stopped` must be cancelled when the write task exits. A split
/// socket does not always surface a write failure on the read half, and a
/// middlebox can ACK bytes without the relay ever seeing them.
pub async fn wait_for_frame<S>(
    stream: &mut S,
    silence: Duration,
    shutdown: &CancellationToken,
    writer_stopped: &CancellationToken,
) -> Result<FrameWait>
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let silent = tokio::time::sleep(silence);
    tokio::pin!(silent);
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(FrameWait::Shutdown),
        msg = stream.next() => match msg {
            None => Ok(FrameWait::Eof),
            Some(Ok(msg)) => Ok(FrameWait::Message(msg)),
            Some(Err(err)) => Err(Error::Ws(err.to_string())),
        },
        _ = writer_stopped.cancelled() => Ok(FrameWait::WriterStopped),
        _ = &mut silent => Ok(FrameWait::Silent),
    }
}

/// Write half of a split socket. Dropping it aborts a send that is stuck
/// behind a full TCP window so the daemon can dial again.
pub struct WriterTask {
    handle: tokio::task::JoinHandle<()>,
    stopped: CancellationToken,
}

impl WriterTask {
    pub fn spawn<S>(sink: S, rx: mpsc::Receiver<Outbound>, shutdown: CancellationToken) -> Self
    where
        S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin + Send + 'static,
    {
        let stopped = CancellationToken::new();
        let flag = stopped.clone();
        let handle = tokio::spawn(async move {
            let _flag = CancelFlag(flag);
            tokio::select! {
                _ = shutdown.cancelled() => {}
                _ = run_writer(sink, rx) => {}
            }
        });
        Self { handle, stopped }
    }

    pub fn stopped(&self) -> &CancellationToken {
        &self.stopped
    }
}

impl Drop for WriterTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

struct CancelFlag(CancellationToken);

impl Drop for CancelFlag {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Bound how long transmitted data may sit unacknowledged, and turn on
/// keepalive probes. A proxy that ACKs but never delivers application bytes
/// still needs the heartbeat deadline; this only shortens the path that
/// used to surface as `os error 110` after hours.
pub fn arm_tcp_liveness(tcp: &tokio::net::TcpStream) {
    let sock = socket2::SockRef::from(tcp);
    let mut keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(45));
    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "windows",
    ))]
    {
        keepalive = keepalive.with_interval(Duration::from_secs(15));
    }
    if let Err(err) = sock.set_tcp_keepalive(&keepalive) {
        tracing::debug!(%err, "tcp keepalive was not enabled");
    }
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Err(err) = sock.set_tcp_user_timeout(Some(Duration::from_secs(45))) {
        tracing::debug!(%err, "tcp user timeout was not set");
    }
}

pub enum Outbound {
    Text(String),
    Binary(Vec<u8>),
    Pong(Vec<u8>),
}

pub enum Incoming {
    Env(Envelope),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Closed,
    Ignore,
}

pub fn parse_incoming(msg: Message) -> Result<Incoming> {
    match msg {
        Message::Text(t) => {
            let env = serde_json::from_str(t.as_ref())
                .map_err(|e| Error::Protocol(format!("json: {e}")))?;
            Ok(Incoming::Env(env))
        }
        Message::Ping(p) => Ok(Incoming::Ping(p.to_vec())),
        Message::Close(_) => Ok(Incoming::Closed),
        Message::Binary(bytes) => Ok(Incoming::Binary(bytes.to_vec())),
        Message::Pong(_) | Message::Frame(_) => Ok(Incoming::Ignore),
    }
}

pub fn encode(env: &Envelope) -> Result<Outbound> {
    Ok(Outbound::Text(serde_json::to_string(env)?))
}

pub async fn run_writer<S>(mut sink: S, mut rx: mpsc::Receiver<Outbound>)
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    while let Some(out) = rx.recv().await {
        if !send_outbound(&mut sink, out).await {
            break;
        }
    }
}

/// Write until `cancel`, flushing frames already queued.
///
/// Device revocation enqueues `session revoked` and then cancels the socket.
/// Aborting the writer on that cancel dropped the error frame, so the peer
/// only saw a close and kept retrying until its own request timed out.
pub async fn run_writer_until_cancel<S>(
    mut sink: S,
    mut rx: mpsc::Receiver<Outbound>,
    cancel: tokio_util::sync::CancellationToken,
) where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    loop {
        tokio::select! {
            biased;
            out = rx.recv() => {
                let Some(out) = out else { break };
                if !send_outbound(&mut sink, out).await {
                    return;
                }
            }
            _ = cancel.cancelled() => break,
        }
    }
    while let Ok(out) = rx.try_recv() {
        if !send_outbound(&mut sink, out).await {
            return;
        }
    }
    let _ = sink.close().await;
}

async fn send_outbound<S>(sink: &mut S, out: Outbound) -> bool
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let msg = match out {
        Outbound::Text(s) => Message::Text(s.into()),
        Outbound::Binary(b) => Message::Binary(b.into()),
        Outbound::Pong(p) => Message::Pong(p.into()),
    };
    sink.send(msg).await.is_ok()
}

pub fn ws_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    let mut config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    // Binary file frames are capped at [`crate::frame::MAX_FRAME`] (8 MiB).
    // A screenshot is one JSON text frame: the encoded image is capped at 8 MiB
    // and base64 expands it by about 4/3, so the socket limit sits above both.
    let limit = crate::frame::MAX_FRAME.max(16 * 1024 * 1024);
    config.max_message_size = Some(limit);
    config.max_frame_size = Some(limit);
    config
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;

    /// One frame, then a socket that never speaks again.
    struct OnceThenPending {
        msg: Option<std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>,
    }

    impl Stream for OnceThenPending {
        type Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if let Some(msg) = self.msg.take() {
                Poll::Ready(Some(msg))
            } else {
                Poll::Pending
            }
        }
    }

    fn tokens() -> (CancellationToken, CancellationToken) {
        (CancellationToken::new(), CancellationToken::new())
    }

    #[test]
    fn silence_budget_tolerates_one_missed_heartbeat() {
        assert_eq!(heartbeat_interval(20), Duration::from_secs(20));
        assert_eq!(heartbeat_interval(0), Duration::from_secs(20));
        assert_eq!(heartbeat_interval(5), Duration::from_secs(5));
        assert_eq!(heartbeat_interval(1), Duration::from_secs(1));
        assert_eq!(heartbeat_interval(120), Duration::from_secs(30));

        assert_eq!(silence_limit(20), Duration::from_secs(50));
        assert_eq!(silence_limit(0), Duration::from_secs(50));
        assert_eq!(silence_limit(5), Duration::from_secs(20));
        assert_eq!(silence_limit(1), Duration::from_secs(15));
        assert_eq!(silence_limit(120), Duration::from_secs(70));
        assert!(silence_limit(20) > heartbeat_interval(20) * 2);
        assert!(silence_limit(20) < RELAY_STALE_AFTER);
        assert!(silence_limit(120) < Duration::from_secs(120));
    }

    #[tokio::test]
    async fn missed_pong_expires_a_silent_socket() {
        let (shutdown, writer) = tokens();
        let mut stream = futures_util::stream::pending::<
            std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        >();
        let started = std::time::Instant::now();
        let got = wait_for_frame(&mut stream, Duration::from_millis(80), &shutdown, &writer)
            .await
            .unwrap();
        assert!(matches!(got, FrameWait::Silent));
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(50), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[tokio::test]
    async fn a_pong_arriving_before_the_deadline_is_not_silence() {
        let (shutdown, writer) = tokens();
        let mut stream = OnceThenPending {
            msg: Some(Ok(Message::Pong(Vec::<u8>::new().into()))),
        };
        let got = wait_for_frame(&mut stream, Duration::from_millis(400), &shutdown, &writer)
            .await
            .unwrap();
        assert!(matches!(got, FrameWait::Message(Message::Pong(_))));
        let again = wait_for_frame(&mut stream, Duration::from_millis(80), &shutdown, &writer)
            .await
            .unwrap();
        assert!(matches!(again, FrameWait::Silent));
    }

    #[tokio::test]
    async fn writer_exit_unblocks_a_read_that_never_completes() {
        let (shutdown, writer) = tokens();
        writer.cancel();
        let mut stream = futures_util::stream::pending::<
            std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        >();
        let got = wait_for_frame(&mut stream, Duration::from_secs(30), &shutdown, &writer)
            .await
            .unwrap();
        assert!(matches!(got, FrameWait::WriterStopped));
    }

    #[tokio::test]
    async fn shutdown_wins_over_a_stopped_writer() {
        let (shutdown, writer) = tokens();
        shutdown.cancel();
        writer.cancel();
        let mut stream = futures_util::stream::pending::<
            std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        >();
        let got = wait_for_frame(&mut stream, Duration::from_secs(30), &shutdown, &writer)
            .await
            .unwrap();
        assert!(matches!(got, FrameWait::Shutdown));
    }
}
