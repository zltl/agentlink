//! Client used by the CLI and the MCP server.
//!
//! One WebSocket, many in-flight requests. Short CLI commands connect, perform
//! a single operation, and exit. The MCP server keeps the same connection and
//! reconnects if the relay drops it.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, Stream, StreamExt};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedSender};

use crate::pending::{self, PendingSender, SendError as PendingSendError};
use tokio::sync::Notify;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use crate::config::ClientSettings;
use crate::error::{Error, Result};
use crate::permissions::NodePolicy;
use crate::protocol::{
    resolve_node, DeviceInfo, DirEntry, Envelope, FileStat, NodeInfo, Op, Role, PROTOCOL_VERSION,
};
use crate::tls::{self, client_config_for};
use crate::util::{self, FILE_CHUNK, READ_WINDOW};
use crate::ws::{self, Incoming, Outbound};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UNARY_TIMEOUT: Duration = Duration::from_secs(120);
/// Initial dial retry budget. Short enough that a CLI command does not sit
/// through the full post-connect [`crate::resume::RECONNECT_GIVE_UP`], long
/// enough to ride out a transient relay TLS handshake flap.
const INITIAL_CONNECT_GIVE_UP: Duration = Duration::from_secs(5);

struct PendingGuard {
    map: Arc<Mutex<HashMap<String, PendingSender>>>,
    routes: Arc<Mutex<HashMap<String, String>>>,
    id: String,
}

impl PendingGuard {
    /// Track a pending request id until this guard drops, also clearing any
    /// unary `routes` entry noted during seal/protect.
    fn new(inner: &ClientInner, id: String) -> Self {
        Self {
            map: inner.pending.clone(),
            routes: inner.routes.clone(),
            id,
        }
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.map.lock() {
            map.remove(&self.id);
        }
        // Unary invoke routes were noted in `protect` / `seal_now` and must
        // not accumulate across tens of thousands of short requests.
        if let Ok(mut routes) = self.routes.lock() {
            routes.remove(&self.id);
        }
    }
}

/// One transfer's control text and file bytes, in WebSocket arrival order.
///
/// Control JSON and file chunks are different WebSocket frame types. They
/// share a queue because merging two channels with `select` can deliver a
/// chunk before the `StreamReady` that was sent ahead of it.
#[derive(Debug)]
pub(crate) enum TransferInbound {
    Env(Envelope),
    Frame(Vec<u8>),
}

#[derive(Clone, Debug)]
pub(crate) struct ActivePtyStream {
    pub(crate) session_id: String,
    pub(crate) node_id: String,
    pub(crate) client_id: String,
}

pub(crate) struct ClientInner {
    pub(crate) tx: mpsc::Sender<Outbound>,
    pub(crate) pending: Arc<Mutex<HashMap<String, PendingSender>>>,
    /// Per-request queue shared by transfer control messages and binary frames.
    pub(crate) binary: Arc<Mutex<HashMap<String, UnboundedSender<TransferInbound>>>>,
    pub(crate) alive: Arc<AtomicBool>,
    pub(crate) socket_gen: std::sync::atomic::AtomicU64,
    pub(crate) shutdown: CancellationToken,
    pub(crate) relay_addr: Option<SocketAddr>,
    pub(crate) direct_id: OnceLock<crate::identity::Identity>,
    pub(crate) quic: Mutex<Option<Arc<crate::p2p::QuicPeer>>>,
    pub(crate) e2e: crate::e2e::Endpoint,
    pub(crate) routes: Arc<Mutex<HashMap<String, String>>>,
    pub(crate) gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Stable across relay restarts. Paired with per-request cursors.
    session_id: String,
    inflight: Mutex<HashMap<String, Envelope>>,
    cursors: Mutex<crate::resume::Cursors>,
    pty_streams: Mutex<HashMap<String, ActivePtyStream>>,
    /// Transfer request ids. A socket drop fails only these waiters.
    pub(crate) transfers: Arc<Mutex<HashSet<String>>>,
    /// Config directory holding `grants/<node_id>.json`.
    pub(crate) grant_dir: Arc<Mutex<Option<std::path::PathBuf>>>,
    /// Config directory holding `config.json` (`refresh_token` / `access_expires_unix`)
    /// so long-lived clients can rotate expiring access tokens under `lock_session`.
    pub(crate) session_dir: Arc<Mutex<Option<std::path::PathBuf>>>,
    resend: Notify,
    fast: AtomicBool,
    /// Sticky first transport end cause (sanitized categories only).
    pub(crate) transport: crate::transport_status::TransportObserver,
    /// First-seen timestamp for transient `"node offline"` replies per request
    /// so `take_ready` stops swallowing offline replies after `OFFLINE_GRACE`.
    offline_since: Mutex<HashMap<String, Instant>>,
    /// Test hook: PTY writes skip E2E and land here. Production stays None.
    write_hook: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
}

impl ClientInner {
    pub(crate) fn note_route(&self, request_id: &str, node_id: &str) {
        if let Ok(mut map) = self.routes.lock() {
            map.insert(request_id.to_string(), node_id.to_string());
        }
    }

    pub(crate) fn forget_pty_stream(&self, request_id: &str) {
        if let Ok(mut map) = self.pty_streams.lock() {
            map.remove(request_id);
        }
        if let Ok(mut map) = self.inflight.lock() {
            map.remove(request_id);
        }
        if let Ok(mut map) = self.offline_since.lock() {
            map.remove(request_id);
        }
        if let Ok(mut map) = self.routes.lock() {
            map.remove(request_id);
        }
    }

    /// Load the grant this client attaches for `node_id`.
    ///
    /// Missing means the caller has not issued one. This does not mint a grant.
    pub(crate) fn authz_for(&self, node_id: &str) -> Result<Option<crate::grant::SignedGrant>> {
        let dir = self.grant_dir.lock().ok().and_then(|slot| slot.clone());
        crate::grant::load_grant_for(dir.as_deref(), node_id, self.e2e.peer_id())
    }
}

/// A connected admin client.
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
    pub(crate) client_id: String,
    pin_dir: Mutex<Option<std::path::PathBuf>>,
    pin_warnings: Mutex<Vec<String>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.inner.shutdown.cancel();
    }
}

/// A command to run on a node.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub timeout: Option<Duration>,
    pub shell: bool,
    /// Bytes written to the remote process stdin, then EOF. `None` = `/dev/null`.
    pub stdin: Option<Vec<u8>>,
}

impl ExecRequest {
    pub fn shell(line: impl Into<String>, timeout: Option<Duration>) -> Self {
        Self {
            program: line.into(),
            args: Vec::new(),
            cwd: None,
            env: Vec::new(),
            timeout,
            shell: true,
            stdin: None,
        }
    }

    fn into_op(self) -> Op {
        Op::Exec {
            program: self.program,
            args: self.args,
            cwd: self.cwd,
            env: self.env,
            timeout_ms: self.timeout.map(|d| d.as_millis() as u64),
            shell: self.shell,
            stdin_b64: self.stdin.map(|bytes| {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(bytes)
            }),
        }
    }
}

/// Captured command output.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
}

/// Events from an interactive PTY.
#[derive(Debug)]
pub enum PtyEvent {
    Data(Vec<u8>),
    Exit(i32),
    Error(String),
}

/// One live PTY. Dropping it asks the node to close the session.
pub struct PtySession {
    pub session_id: String,
    node_id: String,
    client_id: String,
    inner: Arc<ClientInner>,
    rx: crate::pending::PendingReceiver,
    finished: Option<std::result::Result<i32, String>>,
    close_sent: bool,
    _guard: PendingGuard,
}

/// Bytes read from a PTY without blocking for the whole session.
#[derive(Debug, Clone)]
pub struct PtyRead {
    pub data: Vec<u8>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
}

impl Drop for PtySession {
    fn drop(&mut self) {
        self.inner.forget_pty_stream(&self._guard.id);
        if self.close_sent {
            return;
        }
        self.close_sent = true;
        let env = Envelope::Invoke {
            request_id: uuid::Uuid::new_v4().to_string(),
            node_id: self.node_id.clone(),
            client_id: self.client_id.clone(),
            op: Op::PtyClose {
                session_id: self.session_id.clone(),
            },
            grant: None,
            authz: self.inner.authz_for(&self.node_id).ok().flatten(),
            user: None,
            device_id: None,
        };
        if let Ok(out) = seal_now(&self.inner, &self.node_id, &self.client_id, &env) {
            let _ = self.inner.tx.try_send(out);
        }
    }
}

impl PtySession {
    pub fn is_client_alive(&self) -> bool {
        self.inner.alive.load(Ordering::SeqCst)
    }

    pub fn socket_generation(&self) -> u64 {
        self.inner.socket_gen.load(Ordering::SeqCst)
    }

    /// Lightweight roundtrip check that the remote PTY session and its grant
    /// still exist on the node (`TIOCSWINSZ` with unchanged dimensions is a
    /// kernel no-op on live PTYs).
    pub async fn probe_alive(&self, rows: u16, cols: u16) -> Result<()> {
        self.resize(rows, cols).await
    }

    /// Re-announce the stream cursor and inflight `PtyOpen` frame on the active
    /// socket so an un-upgraded relay whose node-side `detach()` dropped the
    /// stream route re-binds `request_id` and replays buffered output chunks
    /// without opening a duplicate shell when `live.sessions` still holds it.
    pub async fn rebind_stream(&self) -> Result<()> {
        if !self.is_client_alive() {
            return Err(Error::Message("connection closed".into()));
        }
        let req_id = self._guard.id.clone();
        let maybe_env = {
            let mut map = self
                .inner
                .inflight
                .lock()
                .map_err(|_| Error::Message("client lock poisoned".into()))?;
            if let Some(env) = map.get_mut(&req_id) {
                if let Envelope::Invoke { authz, .. } = env {
                    if let Ok(fresh) = self.inner.authz_for(&self.node_id) {
                        *authz = fresh;
                    }
                }
                Some(env.clone())
            } else {
                None
            }
        };
        let Some(env) = maybe_env else {
            return Ok(());
        };
        ensure_e2e(&self.inner, &self.node_id, &self.client_id).await?;
        let applied = self
            .inner
            .cursors
            .lock()
            .map(|c| c.applied(&req_id))
            .unwrap_or(0);
        let cursors = if applied > 0 {
            vec![crate::protocol::SessionCursor {
                request_id: req_id.clone(),
                seq: applied,
            }]
        } else {
            Vec::new()
        };
        let session_env = Envelope::Session {
            session_id: self.inner.session_id.clone(),
            node_id: self.node_id.clone(),
            cursors,
        };
        self.inner
            .tx
            .send(ws::encode(&session_env)?)
            .await
            .map_err(|_| Error::Message("connection closed".into()))?;
        let out = seal_now(&self.inner, &self.node_id, &self.client_id, &env)?;
        self.inner
            .tx
            .send(out)
            .await
            .map_err(|_| Error::Message("connection closed".into()))
    }

    pub async fn recv(&mut self) -> Result<PtyEvent> {
        loop {
            let env = self
                .rx
                .recv()
                .await
                .ok_or_else(|| Error::Message("connection closed".into()))?;
            match env {
                Envelope::Chunk { data_b64, .. } => {
                    return Ok(PtyEvent::Data(util::b64_decode(&data_b64)?));
                }
                Envelope::End {
                    exit_code, error, ..
                } => {
                    self.close_sent = true;
                    self.inner.forget_pty_stream(&self._guard.id);
                    if let Some(err) = error {
                        self.finished = Some(Err(err.clone()));
                        return Ok(PtyEvent::Error(err));
                    }
                    let code = exit_code.unwrap_or(0);
                    self.finished = Some(Ok(code));
                    return Ok(PtyEvent::Exit(code));
                }
                Envelope::Result {
                    ok: false, error, ..
                } => {
                    self.close_sent = true;
                    self.inner.forget_pty_stream(&self._guard.id);
                    let err = error.unwrap_or_else(|| "pty failed".into());
                    self.finished = Some(Err(err.clone()));
                    return Ok(PtyEvent::Error(err));
                }
                _ => continue,
            }
        }
    }

    pub async fn write(&self, data: &[u8]) -> Result<()> {
        self.send_op(Op::PtyInput {
            session_id: self.session_id.clone(),
            data_b64: util::b64_encode(data),
        })
        .await
    }

    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.send_op(Op::PtyResize {
            session_id: self.session_id.clone(),
            rows,
            cols,
        })
        .await
    }

    /// Send `PtyClose` over the reliable outbound channel and suppress the
    /// `Drop` `try_send` so a follow-up `open_pty` is not racing a lost close.
    pub async fn close(mut self) -> Result<()> {
        if self.close_sent || self.finished.is_some() {
            self.close_sent = true;
            return Ok(());
        }
        self.close_sent = true;
        self.send_op(Op::PtyClose {
            session_id: self.session_id.clone(),
        })
        .await
    }

    /// Read whatever the PTY has produced, waiting up to `wait` for the first byte.
    pub async fn read_available(&mut self, wait: Duration, max_bytes: usize) -> Result<PtyRead> {
        if let Some(done) = &self.finished {
            return match done {
                Ok(code) => Ok(PtyRead {
                    data: Vec::new(),
                    exit_code: Some(*code),
                    error: None,
                }),
                Err(err) => Ok(PtyRead {
                    data: Vec::new(),
                    exit_code: None,
                    error: Some(err.clone()),
                }),
            };
        }
        let mut data = Vec::new();
        let deadline = Instant::now() + wait;
        loop {
            if max_bytes > 0 && data.len() >= max_bytes {
                break;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match timeout(left, self.rx.recv()).await {
                Err(_) => break,
                Ok(None) => return Err(Error::Message("connection closed".into())),
                Ok(Some(Envelope::Chunk { data_b64, .. })) => {
                    let bytes = util::b64_decode(&data_b64)?;
                    let room = if max_bytes == 0 {
                        bytes.len()
                    } else {
                        max_bytes.saturating_sub(data.len())
                    };
                    data.extend_from_slice(&bytes[..room.min(bytes.len())]);
                }
                Ok(Some(Envelope::End {
                    exit_code, error, ..
                })) => {
                    self.close_sent = true;
                    self.inner.forget_pty_stream(&self._guard.id);
                    if let Some(err) = error {
                        self.finished = Some(Err(err.clone()));
                        return Ok(PtyRead {
                            data,
                            exit_code: None,
                            error: Some(err),
                        });
                    }
                    let code = exit_code.unwrap_or(0);
                    self.finished = Some(Ok(code));
                    return Ok(PtyRead {
                        data,
                        exit_code: Some(code),
                        error: None,
                    });
                }
                Ok(Some(Envelope::Result {
                    ok: false, error, ..
                })) => {
                    self.close_sent = true;
                    self.inner.forget_pty_stream(&self._guard.id);
                    let err = error.unwrap_or_else(|| "pty failed".into());
                    self.finished = Some(Err(err.clone()));
                    return Ok(PtyRead {
                        data,
                        exit_code: None,
                        error: Some(err),
                    });
                }
                Ok(Some(_)) => continue,
            }
        }
        Ok(PtyRead {
            data,
            exit_code: None,
            error: None,
        })
    }

    /// Line-oriented shell: stdin lines go to the PTY, output goes to stdout.
    pub async fn interact_lines(&mut self) -> Result<i32> {
        let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                match stdin.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if input_tx.send(line.as_bytes().to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let mut stdin_open = true;
        loop {
            tokio::select! {
                biased;
                env = self.rx.recv() => {
                    match env {
                        Some(Envelope::Chunk { data_b64, .. }) => {
                            let data = util::b64_decode(&data_b64)?;
                            let mut out = std::io::stdout();
                            out.write_all(&data).ok();
                            out.flush().ok();
                        }
                        Some(Envelope::End { exit_code, error, .. }) => {
                            self.close_sent = true;
                            self.inner.forget_pty_stream(&self._guard.id);
                            if let Some(err) = error {
                                eprintln!("\n{err}");
                                return Err(Error::Message(err));
                            }
                            let code = exit_code.unwrap_or(0);
                            eprintln!("\n[exited {code}]");
                            return Ok(code);
                        }
                        Some(Envelope::Result { ok: false, error, .. }) => {
                            self.close_sent = true;
                            self.inner.forget_pty_stream(&self._guard.id);
                            return Err(Error::Message(error.unwrap_or_else(|| "pty failed".into())));
                        }
                        None => return Err(Error::Message("connection closed".into())),
                        _ => {}
                    }
                }
                input = input_rx.recv(), if stdin_open => {
                    match input {
                        Some(bytes) => self.write(&bytes).await?,
                        // A closed stdin used to win the race and return 0
                        // before a `--command` PTY printed anything. Keep
                        // reading until the remote process exits — but send
                        // EOT so the line discipline delivers EOF (otherwise
                        // an interactive shell sits at the prompt forever).
                        None => {
                            stdin_open = false;
                            let _ = self.write(&[0x04]).await;
                        }
                    }
                }
            }
        }
    }

    async fn send_op(&self, op: Op) -> Result<()> {
        self.writer().send_op(op).await
    }

    /// Write/resize handle that does not borrow the receive half, so a PTY
    /// pump can pin `recv()` across keystroke writes without losing a ready
    /// output chunk when `select!` prefers input.
    pub fn writer(&self) -> PtyWriter {
        PtyWriter {
            session_id: self.session_id.clone(),
            node_id: self.node_id.clone(),
            client_id: self.client_id.clone(),
            inner: self.inner.clone(),
        }
    }
}

/// A [`PtySession`] fed by tests, plus a hook that records writes.
pub struct PtyTestIo {
    pub tx: PendingSender,
    pub session: PtySession,
    pub writes: mpsc::Receiver<Vec<u8>>,
}

impl PtySession {
    /// Local session whose output comes from [`PtyTestIo::tx`].
    ///
    /// Used to pressure-test the core pending queue together with the FFI
    /// pump. Drop does not contact a relay: the close frame is tried on a
    /// detached outbound channel and ignored if that channel is closed.
    pub fn test_io() -> PtyTestIo {
        let (app_tx, _app_rx) = mpsc::channel(8);
        let (hook_tx, hook_rx) = mpsc::channel(256);
        let pending: std::sync::Arc<Mutex<HashMap<String, PendingSender>>> =
            std::sync::Arc::new(Mutex::new(HashMap::new()));
        let identity = crate::identity::Identity::generate();
        let inner = std::sync::Arc::new(ClientInner {
            tx: app_tx,
            pending: pending.clone(),
            binary: std::sync::Arc::new(Mutex::new(HashMap::new())),
            alive: std::sync::Arc::new(AtomicBool::new(true)),
            socket_gen: std::sync::atomic::AtomicU64::new(1),
            shutdown: CancellationToken::new(),
            relay_addr: None,
            direct_id: OnceLock::new(),
            quic: Mutex::new(None),
            e2e: crate::e2e::Endpoint::new(identity),
            routes: std::sync::Arc::new(Mutex::new(HashMap::new())),
            gates: Mutex::new(HashMap::new()),
            session_id: "test-session".into(),
            inflight: Mutex::new(HashMap::new()),
            cursors: Mutex::new(crate::resume::Cursors::default()),
            pty_streams: Mutex::new(HashMap::new()),
            transfers: std::sync::Arc::new(Mutex::new(HashSet::new())),
            grant_dir: std::sync::Arc::new(Mutex::new(None)),
            session_dir: std::sync::Arc::new(Mutex::new(None)),
            resend: Notify::new(),
            fast: AtomicBool::new(false),
            transport: crate::transport_status::TransportObserver::new(),
            offline_since: Mutex::new(HashMap::new()),
            write_hook: Mutex::new(Some(hook_tx)),
        });
        let session_id = "pty-test".to_string();
        let (wait_tx, rx) = pending::channel();
        pending
            .lock()
            .expect("pending test map")
            .insert(session_id.clone(), wait_tx.clone());
        let routes = inner.routes.clone();
        let session = PtySession {
            session_id: session_id.clone(),
            node_id: "test-node".into(),
            client_id: "test-client".into(),
            inner,
            rx,
            finished: None,
            close_sent: false,
            _guard: PendingGuard {
                map: pending,
                routes,
                id: session_id,
            },
        };
        PtyTestIo {
            tx: wait_tx,
            session,
            writes: hook_rx,
        }
    }
}

/// Send side of a [`PtySession`]. Safe to clone; does not own `recv`.
#[derive(Clone)]
pub struct PtyWriter {
    session_id: String,
    node_id: String,
    client_id: String,
    inner: Arc<ClientInner>,
}

impl PtyWriter {
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        self.send_op(Op::PtyInput {
            session_id: self.session_id.clone(),
            data_b64: util::b64_encode(data),
        })
        .await
    }

    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.send_op(Op::PtyResize {
            session_id: self.session_id.clone(),
            rows,
            cols,
        })
        .await
    }

    async fn send_op(&self, op: Op) -> Result<()> {
        let hooked = self
            .inner
            .write_hook
            .lock()
            .ok()
            .and_then(|slot| slot.clone());
        if let Some(hook) = hooked {
            match &op {
                Op::PtyInput { data_b64, .. } => {
                    let bytes = util::b64_decode(data_b64)?;
                    hook.send(bytes)
                        .await
                        .map_err(|_| Error::Message("connection closed".into()))?;
                    return Ok(());
                }
                Op::PtyResize { .. } | Op::PtyClose { .. } => return Ok(()),
                _ => {}
            }
        }
        let idempotent = matches!(op, Op::PtyResize { .. } | Op::PtyClose { .. });
        let wait_limit = if matches!(op, Op::PtyClose { .. }) {
            Duration::from_secs(3)
        } else {
            Duration::from_secs(10)
        };
        for attempt in 0..2 {
            if !self.inner.alive.load(Ordering::SeqCst) {
                return Err(Error::Message("connection closed".into()));
            }
            let start_gen = self.inner.socket_gen.load(Ordering::SeqCst);
            ensure_e2e(&self.inner, &self.node_id, &self.client_id).await?;
            let request_id = uuid::Uuid::new_v4().to_string();
            let (wait_tx, rx) = pending::channel();
            {
                let mut map = self
                    .inner
                    .pending
                    .lock()
                    .map_err(|_| Error::Message("client lock poisoned".into()))?;
                map.insert(request_id.clone(), wait_tx);
            }
            let _guard = PendingGuard::new(&self.inner, request_id.clone());
            let env = Envelope::Invoke {
                request_id,
                node_id: self.node_id.clone(),
                client_id: self.client_id.clone(),
                op: op.clone(),
                grant: None,
                authz: self.inner.authz_for(&self.node_id)?,
                user: None,
                device_id: None,
            };
            let out = seal_now(&self.inner, &self.node_id, &self.client_id, &env)?;
            self.inner
                .tx
                .send(out)
                .await
                .map_err(|_| Error::Message("connection closed".into()))?;
            let recv_res = timeout(wait_limit, rx.recv()).await;
            let reply = match recv_res {
                Ok(Some(env)) => env,
                Ok(None) => return Err(Error::Message("connection closed".into())),
                Err(_) => {
                    if idempotent
                        && attempt == 0
                        && self.inner.alive.load(Ordering::SeqCst)
                        && self.inner.socket_gen.load(Ordering::SeqCst) != start_gen
                    {
                        continue;
                    }
                    return Err(Error::Timeout);
                }
            };
            match reply {
                Envelope::Result { ok: true, .. } => return Ok(()),
                Envelope::Result {
                    ok: false, error, ..
                } => {
                    let msg = error.unwrap_or_else(|| "pty operation failed".into());
                    let lower = msg.to_ascii_lowercase();
                    if attempt == 0 && self.inner.alive.load(Ordering::SeqCst) {
                        if lower.contains("e2e session reset") {
                            self.inner.e2e.forget(&self.node_id);
                            continue;
                        }
                        if lower.trim() == "session revoked"
                            || lower.trim() == "session expired"
                        {
                            // Un-upgraded relays reject frames on an aged access token
                            // in `handle_client` right before closing the socket (never
                            // routed to the node); wait for `supervise` to redial on
                            // the rotated token, then send once.
                            if wait_for_socket_rotation(&self.inner, start_gen, Duration::from_millis(2500)).await {
                                continue;
                            }
                        }
                        if idempotent
                            && (lower.contains("connection closed")
                                || lower.contains("going away")
                                || lower.contains("node disconnected"))
                        {
                            let _ = wait_for_socket_rotation(
                                &self.inner,
                                start_gen,
                                Duration::from_millis(1000),
                            )
                            .await;
                            if self.inner.alive.load(Ordering::SeqCst) {
                                continue;
                            }
                        }
                    }
                    return Err(Error::Message(msg));
                }
                other => return Err(Error::Protocol(format!("unexpected {}", kind(&other)))),
            }
        }
        Err(Error::Message("pty operation retry exhausted".into()))
    }
}

async fn wait_for_socket_rotation(
    inner: &ClientInner,
    start_gen: u64,
    max_wait: Duration,
) -> bool {
    let deadline = Instant::now() + max_wait;
    while Instant::now() < deadline {
        if !inner.alive.load(Ordering::SeqCst) {
            return false;
        }
        if inner.socket_gen.load(Ordering::SeqCst) != start_gen {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    inner.alive.load(Ordering::SeqCst) && inner.socket_gen.load(Ordering::SeqCst) != start_gen
}

#[derive(Debug, Clone)]
pub struct PairingInfo {
    pub token: String,
    pub name: String,
    pub expires_unix: i64,
    pub policy: NodePolicy,
    pub id: String,
    pub uses: u32,
}

impl Client {
    pub async fn connect(settings: &ClientSettings) -> Result<Self> {
        Self::connect_as(settings, "client").await
    }

    pub async fn connect_as(settings: &ClientSettings, _client_id: &str) -> Result<Self> {
        Self::connect_identity(settings, crate::identity::Identity::generate(), true).await
    }

    /// Connect as a registered agent. The relay challenges `identity` and does
    /// not accept the admin token on this socket.
    pub async fn connect_agent(
        settings: &ClientSettings,
        identity: crate::identity::Identity,
    ) -> Result<Self> {
        Self::connect_identity(settings, identity, false).await
    }

    pub async fn connect_identity(
        settings: &ClientSettings,
        identity: crate::identity::Identity,
        use_token: bool,
    ) -> Result<Self> {
        Self::connect_identity_observed(settings, identity, use_token)
            .await
            .map_err(|err| err.error)
    }

    /// Like [`Self::connect_identity`], but preserves the sticky typed transport
    /// status when the first dial / Hello fails before a usable `Client` handle
    /// would otherwise be returned (observer would be dropped with the inner).
    pub async fn connect_identity_observed(
        settings: &ClientSettings,
        identity: crate::identity::Identity,
        use_token: bool,
    ) -> std::result::Result<Self, ObservedConnectError> {
        let client_id = identity.public_hex().to_string();
        let relay = crate::relay_url::parse_relay_url(&settings.relay).map_err(|error| {
            ObservedConnectError {
                error,
                status: crate::transport_status::TransportStatus::default(),
            }
        })?;
        let relay_addr = (relay.host.as_str(), relay.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next());
        let (tx, app_rx) = mpsc::channel(64);
        let pending: Arc<Mutex<HashMap<String, PendingSender>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let binary: Arc<Mutex<HashMap<String, UnboundedSender<TransferInbound>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let shutdown = CancellationToken::new();
        let alive = Arc::new(AtomicBool::new(true));
        let endpoint = crate::e2e::Endpoint::new(identity.clone());
        let inner = Arc::new(ClientInner {
            tx,
            pending,
            binary,
            alive,
            socket_gen: std::sync::atomic::AtomicU64::new(0),
            shutdown,
            relay_addr,
            direct_id: OnceLock::new(),
            quic: Mutex::new(None),
            e2e: endpoint,
            routes: Arc::new(Mutex::new(HashMap::new())),
            gates: Mutex::new(HashMap::new()),
            session_id: uuid::Uuid::new_v4().to_string(),
            inflight: Mutex::new(HashMap::new()),
            cursors: Mutex::new(crate::resume::Cursors::default()),
            pty_streams: Mutex::new(HashMap::new()),
            transfers: Arc::new(Mutex::new(HashSet::new())),
            grant_dir: Arc::new(Mutex::new(None)),
            session_dir: Arc::new(Mutex::new(None)),
            resend: Notify::new(),
            fast: AtomicBool::new(false),
            transport: crate::transport_status::TransportObserver::new(),
            offline_since: Mutex::new(HashMap::new()),
            write_hook: Mutex::new(None),
        });
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let supervised = inner.clone();
        let settings = settings.clone();
        tokio::spawn(async move {
            supervise(
                supervised,
                app_rx,
                settings,
                identity,
                use_token,
                Some(ready_tx),
            )
            .await;
        });
        match ready_rx.await {
            Ok(Ok(())) => Ok(Client {
                inner,
                client_id,
                pin_dir: Mutex::new(None),
                pin_warnings: Mutex::new(Vec::new()),
            }),
            Ok(Err(error)) => {
                let status = inner.transport.snapshot();
                Err(ObservedConnectError { error, status })
            }
            Err(_) => {
                use crate::transport_status::ClosureCategory;
                if inner.transport.snapshot().is_empty() {
                    let _ = inner
                        .transport
                        .note_first(ClosureCategory::ReadyDropped, None);
                }
                Err(ObservedConnectError {
                    error: Error::Message("connection closed".into()),
                    status: inner.transport.snapshot(),
                })
            }
        }
    }

    pub fn public_id(&self) -> &str {
        &self.client_id
    }

    pub fn is_alive(&self) -> bool {
        self.inner.alive.load(Ordering::SeqCst) && !self.inner.shutdown.is_cancelled()
    }

    /// First recorded transport end cause for this Client (sticky).
    pub fn transport_status(&self) -> crate::transport_status::TransportStatus {
        self.inner.transport.snapshot()
    }

    /// Persist first-closure events as they happen (sink runs outside the
    /// observer mutex). Replaces any previous sink.
    pub fn set_transport_sink(&self, sink: Option<crate::transport_status::ClosureSink>) {
        self.inner.transport.set_sink(sink);
    }

    /// Pin node name → ed25519 id under `dir` (usually the config directory).
    pub fn remember_node_pins(&self, dir: impl Into<std::path::PathBuf>) {
        if let Ok(mut slot) = self.pin_dir.lock() {
            *slot = Some(dir.into());
        }
    }

    /// Sign a full grant with the node data dir's local issuer and remember it.
    ///
    /// The file stays on disk next to that data dir. The relay is not asked.
    pub fn install_local_grant(&self, node_data: &std::path::Path, node_id: &str) -> Result<()> {
        let grant = crate::grant::issue_local_grant(node_data, node_id, self.public_id())?;
        let dir = self
            .inner
            .grant_dir
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .unwrap_or_else(|| {
                let prefix: String = self.public_id().chars().take(16).collect();
                node_data.join(format!("controller-grants-{prefix}"))
            });
        let path = crate::grant::save_grant(&dir, &grant)?;
        self.remember_grants(&dir);
        let _ = path;
        Ok(())
    }

    /// Look for grants in `dir/grants/<node_id>.json` (usually the config dir).
    pub fn remember_grants(&self, dir: impl Into<std::path::PathBuf>) {
        if let Ok(mut slot) = self.inner.grant_dir.lock() {
            *slot = Some(dir.into());
        }
    }

    /// Track `dir/config.json` so a long-lived client refreshes an expiring
    /// device access token in the background and before reconnects without
    /// losing to concurrent CLI rotations. Revoked sessions still fail closed.
    pub fn remember_session(&self, dir: impl Into<std::path::PathBuf>) {
        if let Ok(mut slot) = self.inner.session_dir.lock() {
            *slot = Some(dir.into());
        }
    }

    /// Grant this client would attach for `node_id`, validating node, grantee,
    /// and validity window. `None` means no grant file is stored for this client.
    pub fn load_grant_for_node(&self, node_id: &str) -> Result<Option<crate::grant::SignedGrant>> {
        self.inner.authz_for(node_id)
    }

    /// Warnings from the last [`Self::list_nodes`] call. A mismatch does not
    /// rewrite the pin. Commands to that name fail in [`Self::online_id`].
    pub fn node_pin_warnings(&self) -> Vec<String> {
        self.pin_warnings
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn observe_pins(&self, nodes: &[NodeInfo]) {
        let Some(dir) = self.pin_dir.lock().ok().and_then(|guard| guard.clone()) else {
            return;
        };
        let mut warnings = Vec::new();
        for node in nodes {
            if node.name.is_empty() || node.id.is_empty() {
                continue;
            }
            match crate::node_pin::observe(&dir, &node.name, &node.id) {
                Ok(crate::node_pin::PinStatus::Mismatch { previous }) => {
                    warnings.push(format!(
                        "node '{}' id changed from {previous} to {}. The saved pin was kept. Commands to that name are refused until node-pins.json is updated on purpose.",
                        node.name, node.id
                    ));
                }
                Ok(_) => {}
                Err(err) => warnings.push(err.to_string()),
            }
        }
        if let Ok(mut slot) = self.pin_warnings.lock() {
            *slot = warnings;
        }
    }

    fn pin_blocks(&self, name: &str, id: &str) -> Result<()> {
        let Some(dir) = self.pin_dir.lock().ok().and_then(|guard| guard.clone()) else {
            return Ok(());
        };
        if name.is_empty() || id.is_empty() {
            return Ok(());
        }
        match crate::node_pin::observe(&dir, name, id)? {
            crate::node_pin::PinStatus::Mismatch { previous } => Err(Error::Auth(format!(
                "node '{name}' id changed from {previous} to {id}. Refusing the new key. The saved pin was kept."
            ))),
            _ => Ok(()),
        }
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeInfo>> {
        let env = self
            .roundtrip(
                |id| Envelope::ListNodes { request_id: id },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::NodeList { nodes, .. } => {
                self.observe_pins(&nodes);
                Ok(nodes)
            }
            Envelope::Result { error, .. } => Err(Error::Message(
                error.unwrap_or_else(|| "list failed".into()),
            )),
            other => Err(Error::Protocol(format!("unexpected {}", kind(&other)))),
        }
    }

    pub async fn create_pairing_token(
        &self,
        name: &str,
        policy: NodePolicy,
        ttl_secs: u64,
    ) -> Result<PairingInfo> {
        self.create_enrollment_token(name, policy, ttl_secs, 1)
            .await
    }

    pub async fn create_enrollment_token(
        &self,
        name: &str,
        policy: NodePolicy,
        ttl_secs: u64,
        uses: u32,
    ) -> Result<PairingInfo> {
        let env = self
            .roundtrip(
                |id| Envelope::CreatePairingToken {
                    request_id: id,
                    name: name.to_string(),
                    policy,
                    ttl_secs,
                    uses,
                },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::PairingToken {
                token,
                name,
                expires_unix,
                policy,
                id,
                uses,
                ..
            } => Ok(PairingInfo {
                token,
                name,
                expires_unix,
                policy,
                id,
                uses,
            }),
            Envelope::Result { error, .. } => Err(Error::Message(
                error.unwrap_or_else(|| "pairing failed".into()),
            )),
            other => Err(Error::Protocol(format!("unexpected {}", kind(&other)))),
        }
    }

    pub async fn set_policy(&self, node: &str, policy: NodePolicy) -> Result<NodePolicy> {
        let env = self
            .roundtrip(
                |id| Envelope::SetPolicy {
                    request_id: id,
                    node_id: node.to_string(),
                    policy,
                },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::Result {
                ok: true,
                body: Some(body),
                ..
            } => Ok(serde_json::from_value(body)?),
            Envelope::Result { error, .. } => Err(Error::Message(
                error.unwrap_or_else(|| "set policy failed".into()),
            )),
            other => Err(Error::Protocol(format!("unexpected {}", kind(&other)))),
        }
    }

    pub async fn stat(&self, node: &str, path: &str) -> Result<FileStat> {
        let id = self.online_id(node).await?;
        let body = self.unary(&id, Op::Stat { path: path.into() }).await?;
        Ok(serde_json::from_value(body)?)
    }

    pub async fn list_dir(&self, node: &str, path: &str) -> Result<Vec<DirEntry>> {
        let id = self.online_id(node).await?;
        let body = self.unary(&id, Op::ListDir { path: path.into() }).await?;
        Ok(serde_json::from_value(body)?)
    }

    /// Legacy 64 KiB base64 read, kept for the ignored benchmark.
    ///
    /// `cat` and MCP `read_file` use `stream_download`.
    pub async fn read_file(
        &self,
        node: &str,
        path: &str,
        offset: u64,
        max_bytes: u32,
    ) -> Result<Vec<u8>> {
        let id = self.online_id(node).await?;
        let mut out = Vec::new();
        self.stream_op(
            &id,
            Op::ReadFile {
                path: path.into(),
                offset,
                max_bytes,
            },
            Duration::from_secs(120),
            |stream, data| {
                if stream == "file" {
                    out.extend_from_slice(data);
                }
                true
            },
        )
        .await?;
        Ok(out)
    }

    /// Legacy base64 read of a whole file. Prefer `stream_download`.
    pub async fn read_file_to<W: std::io::Write>(
        &self,
        node: &str,
        path: &str,
        mut writer: W,
    ) -> Result<u64> {
        let id = self.online_id(node).await?;
        let mut offset = 0u64;
        loop {
            let mut got = Vec::new();
            self.stream_op(
                &id,
                Op::ReadFile {
                    path: path.into(),
                    offset,
                    max_bytes: READ_WINDOW,
                },
                Duration::from_secs(180),
                |stream, data| {
                    if stream == "file" {
                        got.extend_from_slice(data);
                    }
                    true
                },
            )
            .await?;
            if got.is_empty() {
                break;
            }
            writer.write_all(&got)?;
            offset += got.len() as u64;
            if (got.len() as u32) < READ_WINDOW {
                break;
            }
        }
        Ok(offset)
    }

    /// Legacy 64 KiB base64 write, kept for the ignored benchmark.
    ///
    /// `write` and MCP `write_file` use `stream_upload`.
    pub async fn write_file(&self, node: &str, path: &str, data: &[u8]) -> Result<()> {
        let id = self.online_id(node).await?;
        self.write_all_id(&id, path, data).await
    }

    /// Legacy base64 upload. Prefer `stream_upload`.
    pub async fn write_file_from<R: std::io::Read>(
        &self,
        node: &str,
        path: &str,
        mut reader: R,
    ) -> Result<u64> {
        let id = self.online_id(node).await?;
        let mut buf = vec![0u8; FILE_CHUNK];
        let mut offset = 0u64;
        let mut first = true;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                if first {
                    self.write_at_id(&id, path, 0, &[], true).await?;
                }
                break;
            }
            self.write_at_id(&id, path, offset, &buf[..n], first)
                .await?;
            first = false;
            offset += n as u64;
        }
        Ok(offset)
    }

    pub async fn mkdir(&self, node: &str, path: &str, recursive: bool) -> Result<()> {
        let id = self.online_id(node).await?;
        self.unary(
            &id,
            Op::Mkdir {
                path: path.into(),
                recursive,
            },
        )
        .await?;
        Ok(())
    }

    pub async fn remove(&self, node: &str, path: &str, recursive: bool) -> Result<()> {
        let id = self.online_id(node).await?;
        self.unary(
            &id,
            Op::Remove {
                path: path.into(),
                recursive,
            },
        )
        .await?;
        Ok(())
    }

    pub async fn search(
        &self,
        node: &str,
        path: &str,
        pattern: &str,
        literal: bool,
        include: Vec<String>,
        exclude: Vec<String>,
        gitignore: bool,
        include_hidden: bool,
        case_insensitive: bool,
        before: u32,
        after: u32,
        offset: u32,
        limit: u32,
    ) -> Result<Value> {
        self.call_op(
            node,
            Op::Search {
                path: path.into(),
                pattern: pattern.into(),
                literal,
                include,
                exclude,
                gitignore,
                include_hidden,
                case_insensitive,
                before,
                after,
                offset,
                limit,
            },
        )
        .await
    }

    pub async fn find(
        &self,
        node: &str,
        path: &str,
        pattern: &str,
        regex: bool,
        gitignore: bool,
        include_hidden: bool,
        case_insensitive: bool,
        offset: u32,
        limit: u32,
    ) -> Result<Value> {
        self.call_op(
            node,
            Op::Find {
                path: path.into(),
                pattern: pattern.into(),
                regex,
                gitignore,
                include_hidden,
                case_insensitive,
                offset,
                limit,
            },
        )
        .await
    }

    pub async fn replace(
        &self,
        node: &str,
        path: &str,
        old: &str,
        new: &str,
        replace_all: bool,
    ) -> Result<Value> {
        self.call_op(
            node,
            Op::Replace {
                path: path.into(),
                old: old.into(),
                new: new.into(),
                replace_all,
            },
        )
        .await
    }

    pub async fn edit_lines(
        &self,
        node: &str,
        path: &str,
        start_line: u32,
        end_line: u32,
        content: &str,
    ) -> Result<Value> {
        self.call_op(
            node,
            Op::EditLines {
                path: path.into(),
                start_line,
                end_line,
                content: content.into(),
            },
        )
        .await
    }

    pub async fn apply_patch(&self, node: &str, root: &str, patch: &str) -> Result<Value> {
        self.call_op(
            node,
            Op::ApplyPatch {
                root: root.into(),
                patch: patch.into(),
            },
        )
        .await
    }

    pub async fn watch_start(&self, node: &str, path: &str, recursive: bool) -> Result<Value> {
        self.call_op(
            node,
            Op::WatchStart {
                path: path.into(),
                recursive,
            },
        )
        .await
    }

    pub async fn watch_poll(
        &self,
        node: &str,
        watch_id: &str,
        cursor: u64,
        timeout_ms: u64,
        limit: u32,
    ) -> Result<Value> {
        self.call_op(
            node,
            Op::WatchPoll {
                watch_id: watch_id.into(),
                cursor,
                timeout_ms,
                limit,
            },
        )
        .await
    }

    pub async fn watch_stop(&self, node: &str, watch_id: &str) -> Result<Value> {
        self.call_op(
            node,
            Op::WatchStop {
                watch_id: watch_id.into(),
            },
        )
        .await
    }

    pub async fn bg_start(
        &self,
        node: &str,
        program: &str,
        args: Vec<String>,
        cwd: Option<String>,
        env: Vec<(String, String)>,
        shell: bool,
        stdin: Option<Vec<u8>>,
    ) -> Result<Value> {
        self.call_op(
            node,
            Op::BgStart {
                program: program.into(),
                args,
                cwd,
                env,
                shell,
                stdin_b64: stdin.map(|bytes| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                }),
            },
        )
        .await
    }

    pub async fn bg_list(&self, node: &str) -> Result<Value> {
        self.call_op(node, Op::BgList).await
    }

    pub async fn bg_output(
        &self,
        node: &str,
        id: &str,
        stdout_cursor: u64,
        stderr_cursor: u64,
        max_bytes: u32,
    ) -> Result<Value> {
        self.call_op(
            node,
            Op::BgOutput {
                id: id.into(),
                stdout_cursor,
                stderr_cursor,
                max_bytes,
            },
        )
        .await
    }

    pub async fn bg_status(&self, node: &str, id: &str) -> Result<Value> {
        self.call_op(node, Op::BgStatus { id: id.into() }).await
    }

    pub async fn bg_kill(&self, node: &str, id: &str) -> Result<Value> {
        self.call_op(node, Op::BgKill { id: id.into() }).await
    }

    pub async fn sysinfo(&self, node: &str) -> Result<Value> {
        self.call_op(node, Op::SysInfo).await
    }

    /// Add a grant jti to the target node's deny-list over a sealed E2E
    /// session. The node verifies `revoke` against its own trusted issuers;
    /// a local grant is not attached (and cannot block a revoke even if it
    /// has expired).
    pub async fn revoke_grant(
        &self,
        node: &str,
        revoke: &crate::grant::SignedRevoke,
    ) -> Result<Value> {
        let id = self.online_id(node).await?;
        self.unary_with_authz(
            &id,
            Op::RevokeGrant {
                revoke: revoke.clone(),
            },
            None,
        )
        .await
    }

    pub async fn rename(&self, node: &str, from: &str, to: &str) -> Result<Value> {
        // Body includes the resolved `to` after Unix into-directory rules
        // (basename appended when the destination is an existing directory).
        self.call_op(
            node,
            Op::Rename {
                from: from.into(),
                to: to.into(),
            },
        )
        .await
    }

    /// Run a command, streaming each chunk to `on_chunk`.
    ///
    /// Return `false` from the callback to cancel the remote process.
    pub async fn exec_streaming<F>(
        &self,
        node: &str,
        req: ExecRequest,
        mut on_chunk: F,
    ) -> Result<Option<i32>>
    where
        F: FnMut(&str, &[u8]) -> bool,
    {
        let id = self.online_id(node).await?;
        let timeout = req
            .timeout
            .map(|d| d + Duration::from_secs(15))
            .unwrap_or(Duration::from_secs(24 * 60 * 60));
        let op = req.into_op();
        self.stream_op(&id, op, timeout, |stream, data| on_chunk(stream, data))
            .await
    }

    pub async fn exec_collect(
        &self,
        node: &str,
        req: ExecRequest,
        max_output: Option<usize>,
    ) -> Result<ExecOutput> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut truncated = false;
        let exit_code = self
            .exec_streaming(node, req, |stream, data| {
                let used = stdout.len() + stderr.len();
                let room = match max_output {
                    Some(max) if used >= max => {
                        truncated = true;
                        return false;
                    }
                    Some(max) => max - used,
                    None => data.len(),
                };
                let take = data.len().min(room);
                if stream == "stderr" {
                    stderr.extend_from_slice(&data[..take]);
                } else {
                    stdout.extend_from_slice(&data[..take]);
                }
                if take < data.len() {
                    truncated = true;
                    return false;
                }
                true
            })
            .await?;
        Ok(ExecOutput {
            exit_code,
            stdout,
            stderr,
            truncated,
        })
    }

    /// Server-issued PTY id from the open ack. The client's `request_id` is
    /// only the stream route for later chunks; it is never the session key.
    fn pty_open_session_id(body: Option<&Value>) -> Result<String> {
        let id = body
            .and_then(|value| value.get("session_id"))
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::Protocol("pty open missing session_id".into()))?;
        uuid::Uuid::parse_str(id)
            .map_err(|_| Error::Protocol("pty open session_id is not a uuid".into()))?;
        Ok(id.to_string())
    }

    pub async fn open_pty(
        &self,
        node: &str,
        command: Option<String>,
        cwd: Option<String>,
        rows: u16,
        cols: u16,
    ) -> Result<PtySession> {
        let node_id = self.online_id(node).await?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let (wait_tx, rx) = pending::channel();
        {
            let mut map = self
                .inner
                .pending
                .lock()
                .map_err(|_| Error::Message("client lock poisoned".into()))?;
            map.insert(request_id.clone(), wait_tx);
        }
        let guard = PendingGuard::new(&self.inner, request_id.clone());
        self.send(&Envelope::Invoke {
            request_id: request_id.clone(),
            node_id: node_id.clone(),
            client_id: self.client_id.clone(),
            op: Op::PtyOpen {
                command,
                cwd,
                rows,
                cols,
            },
            grant: None,
            authz: self.inner.authz_for(&node_id)?,
            user: None,
            device_id: None,
        })
        .await?;
        let first = timeout(Duration::from_secs(30), rx.recv())
            .await
            .map_err(|_| Error::Timeout)?
            .ok_or_else(|| Error::Message("connection closed".into()))?;
        match first {
            Envelope::Result { ok: true, body, .. } => {
                let session_id = Self::pty_open_session_id(body.as_ref())?;
                if let Ok(mut map) = self.inner.pty_streams.lock() {
                    map.insert(
                        request_id,
                        ActivePtyStream {
                            session_id: session_id.clone(),
                            node_id: node_id.clone(),
                            client_id: self.client_id.clone(),
                        },
                    );
                }
                Ok(PtySession {
                    session_id,
                    node_id,
                    client_id: self.client_id.clone(),
                    inner: self.inner.clone(),
                    rx,
                    finished: None,
                    close_sent: false,
                    _guard: guard,
                })
            }
            Envelope::Result {
                ok: false, error, ..
            } => Err(Error::Message(error.unwrap_or_else(|| "pty failed".into()))),
            other => Err(Error::Protocol(format!("unexpected {}", kind(&other)))),
        }
    }

    /// Invoke a unary operation by name or id. Streaming ops should use the dedicated methods.
    pub async fn call_op(&self, node: &str, op: Op) -> Result<Value> {
        self.call_op_timeout(node, op, UNARY_TIMEOUT).await
    }

    /// Unary invoke with an explicit wait (used for official window capture
    /// so the client wait matches `AGENTLINK_PORTAL_PICKER_TIMEOUT_SECS`).
    pub async fn call_op_timeout(&self, node: &str, op: Op, limit: Duration) -> Result<Value> {
        let id = self.online_id(node).await?;
        let authz = self.inner.authz_for(&id)?;
        self.unary_with_authz_limit(&id, op, authz, limit).await
    }

    async fn write_all_id(&self, node_id: &str, path: &str, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return self.write_at_id(node_id, path, 0, &[], true).await;
        }
        let mut offset = 0;
        let mut first = true;
        while offset < data.len() {
            let end = (offset + FILE_CHUNK).min(data.len());
            self.write_at_id(node_id, path, offset as u64, &data[offset..end], first)
                .await?;
            first = false;
            offset = end;
        }
        Ok(())
    }

    async fn write_at_id(
        &self,
        node_id: &str,
        path: &str,
        offset: u64,
        data: &[u8],
        truncate: bool,
    ) -> Result<()> {
        self.unary(
            node_id,
            Op::WriteFile {
                path: path.into(),
                offset,
                data_b64: util::b64_encode(data),
                truncate,
            },
        )
        .await?;
        Ok(())
    }

    /// Resolve `node` to a live id.
    ///
    /// When the relay lists the node as offline, only wait [`crate::resume::OFFLINE_GRACE`]
    /// (a mid-reconnect race), then return [`Error::Offline`]. Waiting the full
    /// reconnect budget here made every fresh `exec`/`ls`/`cp` hang ~60s on a
    /// known-dead machine. Relay socket blips still retry up to
    /// [`crate::resume::RECONNECT_GIVE_UP`]. Callers that need a longer node wait
    /// (copy resume) already retry `Offline` themselves.
    pub(crate) async fn online_id(&self, node: &str) -> Result<String> {
        let relay_deadline = Instant::now() + crate::resume::RECONNECT_GIVE_UP;
        let mut offline_deadline: Option<Instant> = None;
        loop {
            match self.list_nodes().await {
                Ok(nodes) => {
                    let info = resolve_node(&nodes, node)?;
                    self.pin_blocks(&info.name, &info.id)?;
                    if info.online {
                        return Ok(info.id.clone());
                    }
                    if !self.is_alive() {
                        return Err(Error::Offline(info.name.clone()));
                    }
                    let until = *offline_deadline
                        .get_or_insert_with(|| Instant::now() + crate::resume::OFFLINE_GRACE);
                    if Instant::now() >= until {
                        return Err(Error::Offline(info.name.clone()));
                    }
                }
                Err(err)
                    if err.is_retryable() && self.is_alive() && Instant::now() < relay_deadline =>
                {
                    // Relay blip — do not burn the short offline grace on this.
                    offline_deadline = None;
                }
                Err(err) => return Err(err),
            }
            tokio::time::sleep(crate::resume::RECONNECT_FLOOR).await;
        }
    }

    async fn unary(&self, node_id: &str, op: Op) -> Result<Value> {
        let authz = self.inner.authz_for(node_id)?;
        self.unary_with_authz_limit(node_id, op, authz, UNARY_TIMEOUT)
            .await
    }

    async fn unary_with_authz(
        &self,
        node_id: &str,
        op: Op,
        authz: Option<crate::grant::SignedGrant>,
    ) -> Result<Value> {
        self.unary_with_authz_limit(node_id, op, authz, UNARY_TIMEOUT)
            .await
    }

    async fn unary_with_authz_limit(
        &self,
        node_id: &str,
        op: Op,
        authz: Option<crate::grant::SignedGrant>,
        limit: Duration,
    ) -> Result<Value> {
        let client_id = self.client_id.clone();
        let node_id = node_id.to_string();
        let request_id = uuid::Uuid::new_v4().to_string();
        let (wait_tx, rx) = pending::channel();
        {
            let mut map = self
                .inner
                .pending
                .lock()
                .map_err(|_| Error::Message("client lock poisoned".into()))?;
            map.insert(request_id.clone(), wait_tx);
        }
        let _guard = PendingGuard::new(&self.inner, request_id.clone());
        self.send(&Envelope::Invoke {
            request_id: request_id.clone(),
            node_id: node_id.clone(),
            client_id,
            op,
            grant: None,
            authz,
            user: None,
            device_id: None,
        })
        .await?;
        let deadline = Instant::now() + limit;
        let mut seen_approvals = HashSet::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let _ = self.cancel(&node_id, &request_id).await;
                return Err(Error::Timeout);
            }
            let env = match timeout(left, rx.recv()).await {
                Ok(Some(env)) => env,
                Ok(None) => return Err(Error::Message("connection closed".into())),
                Err(_) => {
                    let _ = self.cancel(&node_id, &request_id).await;
                    return Err(Error::Timeout);
                }
            };
            match env {
                Envelope::ApprovalRequest {
                    approval_id,
                    summary,
                    expires_unix,
                    ..
                } => {
                    if seen_approvals.insert(approval_id.clone()) {
                        eprintln!(
                            "waiting for approval {approval_id}: {summary} (expires {expires_unix}); run `agentlink approve list` then `agentlink approve allow {approval_id} <node>`"
                        );
                    }
                }
                Envelope::Result { ok: true, body, .. } => {
                    return Ok(body.unwrap_or(Value::Null));
                }
                Envelope::Result { error, .. } => {
                    return Err(Error::Message(
                        error.unwrap_or_else(|| "remote error".into()),
                    ));
                }
                other => {
                    return Err(Error::Protocol(format!("unexpected {}", kind(&other))));
                }
            }
        }
    }

    async fn stream_op<F>(
        &self,
        node_id: &str,
        op: Op,
        overall: Duration,
        mut on_chunk: F,
    ) -> Result<Option<i32>>
    where
        F: FnMut(&str, &[u8]) -> bool,
    {
        let request_id = uuid::Uuid::new_v4().to_string();
        let authz = self.inner.authz_for(node_id)?;
        let (wait_tx, rx) = pending::channel();
        {
            let mut map = self
                .inner
                .pending
                .lock()
                .map_err(|_| Error::Message("client lock poisoned".into()))?;
            map.insert(request_id.clone(), wait_tx);
        }
        let _guard = PendingGuard::new(&self.inner, request_id.clone());
        self.send(&Envelope::Invoke {
            request_id: request_id.clone(),
            node_id: node_id.to_string(),
            client_id: self.client_id.clone(),
            op,
            grant: None,
            authz,
            user: None,
            device_id: None,
        })
        .await?;

        let deadline = Instant::now() + overall;
        let mut seen_approvals = HashSet::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let _ = self.cancel(node_id, &request_id).await;
                return Err(Error::Timeout);
            }
            let env = timeout(left, rx.recv())
                .await
                .map_err(|_| Error::Timeout)?
                .ok_or_else(|| Error::Message("connection closed".into()))?;
            match env {
                Envelope::Chunk {
                    stream, data_b64, ..
                } => {
                    let data = util::b64_decode(&data_b64)?;
                    if !on_chunk(&stream, &data) {
                        let _ = self.cancel(node_id, &request_id).await;
                        return Ok(None);
                    }
                }
                Envelope::End {
                    exit_code, error, ..
                } => {
                    if let Some(err) = error {
                        return Err(Error::Message(err));
                    }
                    return Ok(exit_code);
                }
                Envelope::Result {
                    ok: false, error, ..
                } => {
                    return Err(Error::Message(
                        error.unwrap_or_else(|| "remote error".into()),
                    ));
                }
                Envelope::Result { ok: true, .. } => continue,
                Envelope::ApprovalRequest {
                    approval_id,
                    summary,
                    expires_unix,
                    ..
                } => {
                    if seen_approvals.insert(approval_id.clone()) {
                        eprintln!(
                            "waiting for approval {approval_id}: {summary} (expires {expires_unix}); run `agentlink approve list` then `agentlink approve allow {approval_id} <node>`"
                        );
                    }
                }
                _ => continue,
            }
        }
    }

    async fn cancel(&self, node_id: &str, request_id: &str) -> Result<()> {
        self.send(&Envelope::Cancel {
            request_id: request_id.to_string(),
            node_id: node_id.to_string(),
        })
        .await?;
        // Queueing Cancel on the app channel is not enough: the CLI can exit
        // and drop the writer before the frame reaches the relay. Flush the
        // websocket so the node actually receives Cancel and can Close the
        // official ScreenCast picker.
        self.flush_out().await
    }

    async fn flush_out(&self) -> Result<()> {
        let (done, rx) = tokio::sync::oneshot::channel();
        self.inner
            .tx
            .send(ws::Outbound::Flush(done))
            .await
            .map_err(|_| Error::Message("connection closed".into()))?;
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Message("connection closed".into()))
    }

    async fn roundtrip<F>(&self, build: F, limit: Duration) -> Result<Envelope>
    where
        F: FnOnce(String) -> Envelope,
    {
        if !self.is_alive() {
            return Err(Error::Message("connection closed".into()));
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let (wait_tx, rx) = pending::channel();
        {
            let mut map = self
                .inner
                .pending
                .lock()
                .map_err(|_| Error::Message("client lock poisoned".into()))?;
            map.insert(request_id.clone(), wait_tx);
        }
        let _guard = PendingGuard::new(&self.inner, request_id.clone());
        self.send(&build(request_id)).await?;
        timeout(limit, rx.recv())
            .await
            .map_err(|_| Error::Timeout)?
            .ok_or_else(|| Error::Message("connection closed".into()))
    }

    async fn send_raw(&self, env: &Envelope) -> Result<()> {
        self.inner
            .tx
            .send(ws::encode(env)?)
            .await
            .map_err(|_| Error::Message("connection closed".into()))
    }

    async fn send(&self, env: &Envelope) -> Result<()> {
        if replayable(env) {
            if let Some(id) = env.request_id() {
                if let Ok(mut map) = self.inner.inflight.lock() {
                    map.insert(id.to_string(), env.clone());
                }
            }
        }
        let protected = match self.protect(env).await {
            Ok(env) => env,
            Err(err) => {
                forget_inflight(&self.inner, env);
                return Err(err);
            }
        };
        if let Err(err) = self.send_raw(&protected).await {
            forget_inflight(&self.inner, env);
            return Err(err);
        }
        Ok(())
    }

    async fn protect(&self, env: &Envelope) -> Result<Envelope> {
        let node_id = match env {
            Envelope::Invoke { node_id, .. }
            | Envelope::Cancel { node_id, .. }
            | Envelope::Transfer { node_id, .. } => node_id.clone(),
            _ => return Ok(env.clone()),
        };
        self.ensure_e2e(&node_id).await?;
        if let Some(id) = env.request_id() {
            self.inner.note_route(id, &node_id);
        }
        match crate::e2e::seal_envelope(&self.inner.e2e, &node_id, &node_id, &self.client_id, env) {
            Err(Error::Protocol(msg)) if msg.contains("counter exhausted") => {
                self.inner.e2e.forget(&node_id);
                self.ensure_e2e(&node_id).await?;
                crate::e2e::seal_envelope(&self.inner.e2e, &node_id, &node_id, &self.client_id, env)
            }
            other => other,
        }
    }

    pub(crate) async fn ensure_e2e(&self, node_id: &str) -> Result<()> {
        ensure_e2e(&self.inner, node_id, &self.client_id).await
    }

    pub async fn register_client(&self, name: &str, public_key: &str) -> Result<Value> {
        let env = self
            .roundtrip(
                |id| Envelope::RegisterClient {
                    request_id: id,
                    name: name.to_string(),
                    public_key: public_key.to_string(),
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env)
    }

    pub async fn set_client_grant(
        &self,
        client_id: &str,
        node_id: &str,
        policy: NodePolicy,
    ) -> Result<()> {
        let env = self
            .roundtrip(
                |id| Envelope::SetClientGrant {
                    request_id: id,
                    client_id: client_id.to_string(),
                    node_id: node_id.to_string(),
                    policy,
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn revoke_client(&self, client_id: &str) -> Result<()> {
        let env = self
            .roundtrip(
                |id| Envelope::RevokeClient {
                    request_id: id,
                    client_id: client_id.to_string(),
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn list_clients(&self) -> Result<Vec<crate::protocol::ClientInfo>> {
        let env = self
            .roundtrip(
                |id| Envelope::ListClients { request_id: id },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::ClientList { clients, .. } => Ok(clients),
            other => result_value(other).map(|_| Vec::new()),
        }
    }

    pub async fn list_approvals(&self) -> Result<Vec<crate::protocol::ApprovalInfo>> {
        let env = self
            .roundtrip(
                |id| Envelope::ListApprovals { request_id: id },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::ApprovalList { items, .. } => Ok(items),
            other => result_value(other).map(|_| Vec::new()),
        }
    }

    pub async fn resolve_approval(
        &self,
        approval_id: &str,
        node_id: &str,
        allow: bool,
    ) -> Result<()> {
        let env = self
            .roundtrip(
                |id| Envelope::ResolveApproval {
                    request_id: id,
                    approval_id: approval_id.to_string(),
                    node_id: node_id.to_string(),
                    allow,
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn query_audit(&self, filter: Value) -> Result<Vec<Value>> {
        let env = self
            .roundtrip(
                |id| Envelope::QueryAudit {
                    request_id: id,
                    filter,
                },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::AuditPage { records, .. } => Ok(records),
            other => result_value(other).map(|_| Vec::new()),
        }
    }

    pub async fn set_audit_policy(
        &self,
        node_id: &str,
        agent_id: Option<String>,
        toml: &str,
    ) -> Result<()> {
        let env = self
            .roundtrip(
                |id| Envelope::SetAuditPolicy {
                    request_id: id,
                    node_id: node_id.to_string(),
                    agent_id,
                    toml: toml.to_string(),
                    user: None,
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    /// Short-lived browser credential for this agent's grant on `node`.
    /// The caller must be connected as that agent, not with the admin token.
    /// The ticket is view-only. [`Self::issue_view_ticket_with`] asks for input.
    pub async fn issue_view_ticket(&self, node: &str) -> Result<(String, String)> {
        self.issue_view_ticket_with(node, false).await
    }

    /// Same as [`Self::issue_view_ticket`]. `control` is honored only when the
    /// account grant already includes remote control.
    pub async fn issue_view_ticket_with(
        &self,
        node: &str,
        control: bool,
    ) -> Result<(String, String)> {
        let env = self
            .roundtrip(
                |id| Envelope::IssueViewTicket {
                    request_id: id,
                    node_id: node.to_string(),
                    control,
                },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::ViewTicket {
                ticket, node_id, ..
            } => Ok((ticket, node_id)),
            other => result_value(other).map(|_| (String::new(), String::new())),
        }
    }

    pub async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let env = self
            .roundtrip(
                |id| Envelope::ListDevices { request_id: id },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::DeviceList { devices, .. } => Ok(devices),
            other => result_value(other).map(|_| Vec::new()),
        }
    }

    pub async fn revoke_device(&self, device_id: &str) -> Result<()> {
        let env = self
            .roundtrip(
                |id| Envelope::RevokeDevice {
                    request_id: id,
                    device_id: device_id.to_string(),
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn logout_session(&self, refresh_token: Option<String>) -> Result<()> {
        let env = self
            .roundtrip(
                |id| Envelope::Logout {
                    request_id: id,
                    refresh_token,
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    /// Enroll this key as a node owned by the logged-in user. No pairing token.
    pub async fn enroll_self(
        &self,
        name: &str,
        identity: &crate::identity::Identity,
        policy: Option<NodePolicy>,
    ) -> Result<Value> {
        let public_key = identity.public_hex();
        let env = self
            .roundtrip(
                |id| {
                    let message = format!("agentlink-enroll-v1:{id}:{public_key}");
                    let signature = identity.sign_message(message.as_bytes());
                    Envelope::EnrollSelf {
                        request_id: id,
                        name: name.to_string(),
                        public_key: public_key.to_string(),
                        signature,
                        policy,
                        hostname: None,
                        os: Some("client".into()),
                        arch: None,
                        version: None,
                    }
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env)
    }

    pub async fn share_node(&self, node: &str, username: &str, policy: NodePolicy) -> Result<()> {
        let env = self
            .roundtrip(
                |id| Envelope::ShareNode {
                    request_id: id,
                    node_id: node.to_string(),
                    username: username.to_string(),
                    policy,
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn unshare_node(&self, node: &str, username: &str) -> Result<()> {
        let env = self
            .roundtrip(
                |id| Envelope::UnshareNode {
                    request_id: id,
                    node_id: node.to_string(),
                    username: username.to_string(),
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn list_enrollment_tokens(&self) -> Result<Vec<crate::protocol::TokenInfo>> {
        let env = self
            .roundtrip(
                |id| Envelope::ListEnrollmentTokens { request_id: id },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::EnrollmentTokenList { tokens, .. } => Ok(tokens),
            Envelope::Result { error, .. } => Err(Error::Message(
                error.unwrap_or_else(|| "list tokens failed".into()),
            )),
            other => Err(Error::Protocol(format!("unexpected {}", kind(&other)))),
        }
    }

    pub async fn revoke_enrollment_token(&self, id: &str) -> Result<()> {
        let env = self
            .roundtrip(
                |request_id| Envelope::RevokeEnrollmentToken {
                    request_id,
                    id: id.to_string(),
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn user_add(&self, username: &str, password: &str, admin: bool) -> Result<Value> {
        let env = self
            .roundtrip(
                |request_id| Envelope::UserAdd {
                    request_id,
                    username: username.to_string(),
                    password: password.to_string(),
                    role: if admin { "admin".into() } else { "user".into() },
                    admin,
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env)
    }

    pub async fn user_list(&self) -> Result<Vec<crate::protocol::UserInfo>> {
        let env = self
            .roundtrip(
                |request_id| Envelope::UserList { request_id },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::UserListed { users, .. } => Ok(users),
            Envelope::Result { error, .. } => Err(Error::Message(
                error.unwrap_or_else(|| "list users failed".into()),
            )),
            other => Err(Error::Protocol(format!("unexpected {}", kind(&other)))),
        }
    }

    pub async fn user_passwd(&self, username: &str, password: &str) -> Result<()> {
        let env = self
            .roundtrip(
                |request_id| Envelope::UserPasswd {
                    request_id,
                    username: username.to_string(),
                    password: password.to_string(),
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn user_set_disabled(&self, username: &str, disabled: bool) -> Result<()> {
        let env = self
            .roundtrip(
                |request_id| Envelope::UserSetDisabled {
                    request_id,
                    username: username.to_string(),
                    disabled,
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn user_remove(&self, username: &str) -> Result<()> {
        let env = self
            .roundtrip(
                |request_id| Envelope::UserRemove {
                    request_id,
                    username: username.to_string(),
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn user_set_role(&self, username: &str, role: &str) -> Result<()> {
        let env = self
            .roundtrip(
                |request_id| Envelope::UserSetRole {
                    request_id,
                    username: username.to_string(),
                    role: role.to_string(),
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn totp_begin(&self) -> Result<(String, String)> {
        let env = self
            .roundtrip(
                |request_id| Envelope::TotpBegin { request_id },
                Duration::from_secs(30),
            )
            .await?;
        match env {
            Envelope::TotpPending { secret, url, .. } => Ok((secret, url)),
            Envelope::Result { error, .. } => Err(Error::Message(
                error.unwrap_or_else(|| "totp begin failed".into()),
            )),
            other => Err(Error::Protocol(format!("unexpected {}", kind(&other)))),
        }
    }

    pub async fn totp_confirm(&self, code: &str) -> Result<()> {
        let env = self
            .roundtrip(
                |request_id| Envelope::TotpConfirm {
                    request_id,
                    code: code.to_string(),
                },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }

    pub async fn totp_disable(&self) -> Result<()> {
        let env = self
            .roundtrip(
                |request_id| Envelope::TotpDisable { request_id },
                Duration::from_secs(30),
            )
            .await?;
        result_value(env).map(|_| ())
    }
}

fn result_value(env: Envelope) -> Result<Value> {
    match env {
        Envelope::Result { ok: true, body, .. } => Ok(body.unwrap_or(Value::Null)),
        Envelope::Result { error, .. } => Err(Error::Message(
            error.unwrap_or_else(|| "remote error".into()),
        )),
        other => Err(Error::Protocol(format!("unexpected {}", kind(&other)))),
    }
}

pub(crate) async fn ensure_e2e(
    inner: &Arc<ClientInner>,
    node_id: &str,
    client_id: &str,
) -> Result<()> {
    if inner.e2e.has(node_id) {
        return Ok(());
    }
    tracing::debug!(%node_id, "starting e2e handshake");
    let gate = {
        let mut gates = inner
            .gates
            .lock()
            .map_err(|_| Error::Message("e2e gate poisoned".into()))?;
        gates
            .entry(node_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _guard = gate.lock().await;
    if inner.e2e.has(node_id) {
        return Ok(());
    }
    let pending_hello = inner.e2e.client_hello(node_id)?;
    let request_id = uuid::Uuid::new_v4().to_string();
    let (wait_tx, rx) = pending::channel();
    {
        let mut map = inner
            .pending
            .lock()
            .map_err(|_| Error::Message("client lock poisoned".into()))?;
        map.insert(request_id.clone(), wait_tx);
    }
    let _drop = PendingGuard::new(inner, request_id.clone());
    let hello = Envelope::E2eHello {
        request_id: request_id.clone(),
        node_id: node_id.to_string(),
        message_b64: crate::util::b64_encode(crate::e2e::Endpoint::hello_bytes(&pending_hello)),
    };
    let _ = client_id;
    inner
        .tx
        .send(ws::encode(&hello)?)
        .await
        .map_err(|_| Error::Message("connection closed".into()))?;
    let welcome = timeout(Duration::from_secs(15), rx.recv())
        .await
        .map_err(|_| Error::Timeout)?
        .ok_or_else(|| Error::Message("connection closed".into()))?;
    match welcome {
        Envelope::E2eWelcome { message_b64, .. } => {
            let bytes = crate::util::b64_decode(&message_b64)?;
            inner.e2e.complete(pending_hello, &bytes)?;
            tracing::debug!(%node_id, "e2e handshake complete");
            Ok(())
        }
        Envelope::Result {
            ok: false, error, ..
        } => Err(Error::Message(
            error.unwrap_or_else(|| "e2e handshake failed".into()),
        )),
        other => Err(Error::Protocol(format!(
            "expected e2e welcome, got {}",
            kind(&other)
        ))),
    }
}

fn seal_now(
    inner: &ClientInner,
    node_id: &str,
    client_id: &str,
    env: &Envelope,
) -> Result<Outbound> {
    if let Some(id) = env.request_id() {
        inner.note_route(id, node_id);
    }
    if inner.e2e.has(node_id) {
        let wrapped = crate::e2e::seal_envelope(&inner.e2e, node_id, node_id, client_id, env)?;
        return ws::encode(&wrapped);
    }
    ws::encode(env)
}

fn unwrap_client(endpoint: &crate::e2e::Endpoint, env: Envelope) -> Envelope {
    let Envelope::E2e { node_id, .. } = &env else {
        return env;
    };
    let peer = node_id.clone();
    match crate::e2e::open_sealed(endpoint, &peer, env) {
        Ok(inner) => inner,
        Err(err) => {
            tracing::warn!(error = %err, "e2e open failed");
            Envelope::Ping
        }
    }
}

async fn dispatch(
    pending: &Mutex<HashMap<String, PendingSender>>,
    transfers: &Mutex<HashMap<String, UnboundedSender<TransferInbound>>>,
    env: Envelope,
    shutdown: &CancellationToken,
) {
    let Some(id) = env.request_id().map(|s| s.to_string()) else {
        return;
    };
    if let Ok(map) = transfers.lock() {
        if let Some(tx) = map.get(&id) {
            let _ = tx.send(TransferInbound::Env(env));
            return;
        }
    }
    let tx = {
        let Ok(map) = pending.lock() else {
            return;
        };
        map.get(&id).cloned()
    };
    let Some(tx) = tx else {
        return;
    };
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => {}
        result = tx.send(env) => {
            if let Err(PendingSendError::Overflow(env)) = result {
                let id = env
                    .request_id()
                    .unwrap_or("pty")
                    .to_string();
                let _ = tx.try_send_error(
                    &id,
                    "remote output chunk exceeds the client pending buffer",
                );
                tx.close();
            }
        }
    }
}

fn dispatch_binary(
    transfers: &Mutex<HashMap<String, UnboundedSender<TransferInbound>>>,
    bytes: Vec<u8>,
) {
    let Some(id) = crate::frame::request_id(&bytes) else {
        return;
    };
    let Ok(map) = transfers.lock() else {
        return;
    };
    if let Some(tx) = map.get(&id) {
        let _ = tx.send(TransferInbound::Frame(bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::TransferMsg;

    #[test]
    fn pending_guard_drop_clears_unary_routes() {
        let pending: Arc<Mutex<HashMap<String, PendingSender>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let routes: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
        let id = "req-unary".to_string();
        {
            let (tx, _rx) = pending::channel();
            pending.lock().unwrap().insert(id.clone(), tx);
            routes
                .lock()
                .unwrap()
                .insert(id.clone(), "node-a".into());
            let _guard = PendingGuard {
                map: pending.clone(),
                routes: routes.clone(),
                id: id.clone(),
            };
            assert!(routes.lock().unwrap().contains_key(&id));
        }
        assert!(
            !routes.lock().unwrap().contains_key(&id),
            "unary route must be removed when PendingGuard drops"
        );
        assert!(!pending.lock().unwrap().contains_key(&id));
    }

    #[tokio::test]
    async fn transfer_inbox_keeps_stream_ready_ahead_of_its_chunk() {
        let mut frame = vec![0u8; crate::frame::HEADER_LEN];
        frame[0] = crate::frame::FRAME_VERSION;
        frame[1] = crate::frame::KIND_DATA;
        let id = uuid::Uuid::new_v4();
        frame[12..28].copy_from_slice(id.as_bytes());
        let request_id = crate::frame::request_id(&frame).unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let transfers = Mutex::new(HashMap::from([(request_id.clone(), tx)]));
        let pending = Mutex::new(HashMap::new());
        let ready = Envelope::Transfer {
            request_id,
            node_id: "node".into(),
            client_id: "client".into(),
            terminal: false,
            msg: TransferMsg::StreamReady {
                start: 0,
                end: 4,
                file_size: 4,
            },
            authz: None,
        };
        let shutdown = CancellationToken::new();
        dispatch(&pending, &transfers, ready, &shutdown).await;
        dispatch_binary(&transfers, frame);
        match rx.try_recv() {
            Ok(TransferInbound::Env(Envelope::Transfer {
                msg: TransferMsg::StreamReady { .. },
                ..
            })) => {}
            other => panic!("stream ready was reordered: {other:?}"),
        }
        assert!(matches!(rx.try_recv(), Ok(TransferInbound::Frame(_))));
    }

    #[tokio::test]
    async fn device_list_reaches_the_waiter_instead_of_timing_out() {
        let (tx, rx) = pending::channel();
        let pending = Mutex::new(HashMap::from([("dev-1".to_string(), tx)]));
        let transfers = Mutex::new(HashMap::new());
        let env = Envelope::DeviceList {
            request_id: "dev-1".into(),
            devices: vec![crate::protocol::DeviceInfo {
                id: "ab".repeat(32),
                user: "operator".into(),
                name: "phone".into(),
                created_unix: 1,
                last_seen_unix: 2,
                revoked: false,
            }],
        };
        assert_eq!(env.request_id(), Some("dev-1"));
        let shutdown = CancellationToken::new();
        dispatch(&pending, &transfers, env, &shutdown).await;
        match rx.try_recv() {
            Some(Envelope::DeviceList {
                request_id,
                devices,
            }) => {
                assert_eq!(request_id, "dev-1");
                assert_eq!(devices.len(), 1);
                assert_eq!(devices[0].id, "ab".repeat(32));
                assert!(!devices[0].revoked);
            }
            other => panic!("device list was dropped: {other:?}"),
        }
    }

    fn pty_test_chunk(data: &[u8]) -> Envelope {
        Envelope::Chunk {
            request_id: "pty-test".into(),
            stream: "pty".into(),
            data_b64: crate::util::b64_encode(data),
            seq: 0,
        }
    }

    fn pty_test_end(code: i32) -> Envelope {
        Envelope::End {
            request_id: "pty-test".into(),
            exit_code: Some(code),
            error: None,
            seq: 0,
        }
    }

    #[tokio::test]
    async fn pending_dispatch_backs_up_the_receive_task_without_dropping_bytes() {
        let io = PtySession::test_io();
        let mut session = io.session;
        let mut writes = io.writes;
        let tx = io.tx;
        let pending = Mutex::new(HashMap::from([("pty-test".to_string(), tx)]));
        let transfers: Mutex<HashMap<String, UnboundedSender<TransferInbound>>> =
            Mutex::new(HashMap::new());
        let shutdown = CancellationToken::new();
        let n = 600u32;
        let producer = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                dispatch(&pending, &transfers, pty_test_chunk(&[0xe4]), &shutdown).await;
                dispatch(
                    &pending,
                    &transfers,
                    pty_test_chunk(&[0xbd, 0xa0]),
                    &shutdown,
                )
                .await;
                dispatch(
                    &pending,
                    &transfers,
                    pty_test_chunk(b"\x1b[2;3H"),
                    &shutdown,
                )
                .await;
                dispatch(&pending, &transfers, pty_test_chunk(b"Z"), &shutdown).await;
                for i in 0..n {
                    dispatch(
                        &pending,
                        &transfers,
                        pty_test_chunk(&[(i % 251) as u8]),
                        &shutdown,
                    )
                    .await;
                }
                dispatch(&pending, &transfers, pty_test_end(7), &shutdown).await;
            }
        });
        // Prove writes still flow while output is backing up.
        session.writer().write(b"k").await.unwrap();
        let written = tokio::time::timeout(std::time::Duration::from_secs(1), writes.recv())
            .await
            .expect("write hook should accept input while output is queued")
            .expect("write hook closed");
        assert_eq!(written, b"k");

        let mut got = Vec::new();
        let exit;
        loop {
            tokio::task::yield_now().await;
            match session.recv().await.unwrap() {
                PtyEvent::Data(bytes) => got.extend(bytes),
                PtyEvent::Exit(code) => {
                    exit = Some(code);
                    break;
                }
                PtyEvent::Error(err) => panic!("unexpected error {err}"),
            }
        }
        producer.await.unwrap();
        assert_eq!(got[0], 0xe4);
        assert_eq!(&got[1..3], &[0xbd, 0xa0]);
        assert_eq!(&got[3..9], b"\x1b[2;3H");
        assert_eq!(got[9], b'Z');
        assert_eq!(got[10..].len(), n as usize);
        for (i, b) in got[10..].iter().enumerate() {
            assert_eq!(*b, (i % 251) as u8, "byte {i}");
        }
        assert_eq!(exit, Some(7));
    }

    #[tokio::test]
    async fn dropping_a_pty_session_unblocks_a_full_pending_send() {
        let io = PtySession::test_io();
        let tx = io.tx.clone();
        while tx.try_send(pty_test_chunk(b"ab")) == crate::pending::TrySend::Queued {}
        let blocked = tokio::spawn(async move { tx.send(pty_test_chunk(b"cd")).await });
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        drop(io.session);
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), blocked)
            .await
            .expect("session drop must not deadlock a blocked dispatch send")
            .unwrap();
        assert!(matches!(result, Err(crate::pending::SendError::Closed)));
    }

    /// close() is async and safe on a runtime; Drop after close must not
    /// block_on or send a second close. A follow-up session can start.
    /// This does not cover the GUI Quit/X path.
    #[tokio::test]
    async fn close_then_drop_allows_a_second_session_to_start() {
        let first = PtySession::test_io();
        let _ = first.session.close().await;
        drop(first.tx);
        let second = PtySession::test_io();
        let _ = second.session.close().await;
    }

    #[test]
    fn pty_open_uses_the_server_uuid_and_rejects_a_request_id_standin() {
        let server = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({"session_id": server, "rows": 24, "cols": 80});
        assert_eq!(Client::pty_open_session_id(Some(&body)).unwrap(), server);
        assert!(Client::pty_open_session_id(None).is_err());
        assert!(Client::pty_open_session_id(Some(&serde_json::json!({}))).is_err());
        assert!(Client::pty_open_session_id(Some(&serde_json::json!({"session_id": ""}))).is_err());
        // Client request ids and path fragments must not become the session key.
        assert!(Client::pty_open_session_id(Some(&serde_json::json!({
            "session_id": "not-a-uuid"
        })))
        .is_err());
        assert!(Client::pty_open_session_id(Some(&serde_json::json!({
            "session_id": "../evil"
        })))
        .is_err());
        assert!(Client::pty_open_session_id(Some(&serde_json::json!({
            "session_id": "pty-test"
        })))
        .is_err());
    }

    #[tokio::test]
    async fn drop_without_close_does_not_panic_inside_the_runtime() {
        let io = PtySession::test_io();
        drop(io.session);
    }
}

async fn next_env<S>(
    stream: &mut S,
    transport: &crate::transport_status::TransportObserver,
) -> Result<Envelope>
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    use crate::transport_status::ClosureCategory;
    loop {
        let msg = match stream.next().await {
            None => {
                let _ = transport.note_first(ClosureCategory::WsStreamEnd, None);
                return Err(Error::Ws("connection closed during handshake".into()));
            }
            Some(Err(_)) => {
                let _ = transport.note_first(ClosureCategory::WsStreamError, None);
                return Err(Error::Ws("connection closed during handshake".into()));
            }
            Some(Ok(msg)) => msg,
        };
        match ws::parse_incoming(msg)? {
            Incoming::Env(env) => return Ok(env),
            Incoming::Ping(_) | Incoming::Ignore | Incoming::Binary(_) => continue,
            Incoming::Closed { code } => {
                let _ = transport.note_first(ClosureCategory::WsClose, code);
                return Err(Error::Ws("connection closed during handshake".into()));
            }
        }
    }
}

/// Connect failure that keeps the sticky typed transport status that lived on
/// the discarded inner Client (so bootstrap diagnostics can persist categories
/// without logging raw server strings).
#[derive(Debug)]
pub struct ObservedConnectError {
    pub error: Error,
    pub status: crate::transport_status::TransportStatus,
}

type ClientSocket = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

enum SocketEnd {
    Gone,
    GoingAway,
    Shutdown,
}

async fn supervise(
    inner: Arc<ClientInner>,
    mut app_rx: mpsc::Receiver<Outbound>,
    mut settings: ClientSettings,
    identity: crate::identity::Identity,
    use_token: bool,
    mut ready: Option<tokio::sync::oneshot::Sender<Result<()>>>,
) {
    use crate::transport_status::ClosureCategory;
    let mut backoff = crate::resume::Backoff::new();
    let mut connected_once = false;
    let mut down_since: Option<Instant> = None;
    let mut heartbeat = false;
    let live_token = Arc::new(Mutex::new(settings.token.clone()));
    loop {
        if inner.shutdown.is_cancelled() {
            let _ = inner.transport.bump_attempt();
            inner.transport.note_first(ClosureCategory::Shutdown, None);
            if let Some(tx) = ready.take() {
                let _ = tx.send(Err(Error::Message("connection closed".into())));
            }
            fail_waiters(&inner);
            break;
        }
        if connected_once && use_token {
            if let Ok(latest) = live_token.lock() {
                if !latest.is_empty() {
                    settings.token = latest.clone();
                }
            }
            let session_dir = inner.session_dir.lock().ok().and_then(|slot| slot.clone());
            if let Some(dir) = session_dir {
                if let Ok(Some(fresh)) =
                    refresh_or_adopt_for_client(&dir, &identity, &settings.token, false).await
                {
                    settings.token = fresh.token.clone();
                    if let Ok(mut slot) = live_token.lock() {
                        *slot = fresh.token;
                    }
                }
            }
        }
        let _ = inner.transport.bump_attempt();
        let mut dial_res = dial_client(&settings, &identity, use_token, &inner.transport).await;
        if connected_once
            && use_token
            && matches!(
                &dial_res,
                Err(Error::Auth(msg)) if msg.contains("session expired or revoked")
            )
        {
            // One-shot refresh if the cached access token expired (e.g. relay
            // dropped the socket at access_expires + skew, or clock skew hid
            // local staleness). True revocation rejects refresh_user and falls
            // straight through to AuthRejected below.
            let session_dir = inner.session_dir.lock().ok().and_then(|slot| slot.clone());
            if let Some(dir) = session_dir {
                match refresh_or_adopt_for_client(&dir, &identity, &settings.token, true).await {
                    Ok(Some(fresh)) => {
                        if fresh.token != settings.token && !fresh.token.is_empty() {
                            settings.token = fresh.token.clone();
                            if let Ok(mut slot) = live_token.lock() {
                                *slot = fresh.token;
                            }
                            let _ = inner.transport.bump_attempt();
                            dial_res =
                                dial_client(&settings, &identity, use_token, &inner.transport)
                                    .await;
                        }
                    }
                    Ok(None) => {}
                    Err(refresh_err) if refresh_err.is_retryable() => {
                        // Do not kill the Client on a transient network/TLS flap while
                        // rotating an expired access token: treat as retryable backoff.
                        dial_res = Err(refresh_err);
                    }
                    Err(_) => {}
                }
            }
        }
        match dial_res {
            Err(err) => {
                if !connected_once {
                    // A first-dial TLS/IO flap should not fail a CLI command
                    // outright. Retry briefly; trust and auth failures still
                    // surface immediately.
                    if !err.is_retryable() {
                        if matches!(err, Error::Auth(_)) {
                            inner
                                .transport
                                .note_first(ClosureCategory::AuthRejected, None);
                        } else {
                            inner
                                .transport
                                .note_first(ClosureCategory::InitialDialGiveUp, None);
                        }
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(Err(err));
                        }
                        inner.alive.store(false, Ordering::SeqCst);
                        break;
                    }
                    let since = *down_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= INITIAL_CONNECT_GIVE_UP {
                        inner
                            .transport
                            .note_first(ClosureCategory::InitialDialGiveUp, None);
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(Err(err));
                        }
                        inner.alive.store(false, Ordering::SeqCst);
                        break;
                    }
                    tracing::debug!(error = %err, "initial relay dial failed; retrying");
                    let delay = next_reconnect_delay(&inner, &mut backoff);
                    tokio::select! {
                        _ = inner.shutdown.cancelled() => {
                            inner
                                .transport
                                .note_first(ClosureCategory::Shutdown, None);
                            if let Some(tx) = ready.take() {
                                let _ = tx.send(Err(Error::Message("connection closed".into())));
                            }
                            fail_waiters(&inner);
                            break;
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                    continue;
                }
                // A rejected credential will not start working on the next dial.
                // Surface it to in-flight calls instead of retrying for a minute.
                if let Error::Auth(message) = &err {
                    tracing::warn!(error = %message, "relay rejected the session; not retrying");
                    inner
                        .transport
                        .note_first(ClosureCategory::AuthRejected, None);
                    fail_waiters_with(&inner, Some(message));
                    break;
                }
                let since = *down_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= crate::resume::RECONNECT_GIVE_UP {
                    tracing::warn!("relay stayed down; giving up on the session");
                    inner
                        .transport
                        .note_first(ClosureCategory::DialGiveUp, None);
                    fail_waiters(&inner);
                    break;
                }
                let delay = next_reconnect_delay(&inner, &mut backoff);
                tokio::select! {
                    _ = inner.shutdown.cancelled() => {
                        inner
                            .transport
                            .note_first(ClosureCategory::Shutdown, None);
                        fail_waiters(&inner);
                        break;
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            Ok(ws) => {
                connected_once = true;
                inner.socket_gen.fetch_add(1, Ordering::SeqCst);
                backoff.reset();
                if let Some(tx) = ready.take() {
                    let _ = tx.send(Ok(()));
                }
                if !heartbeat {
                    heartbeat = true;
                    let beat_tx = inner.tx.clone();
                    let beat_shutdown = inner.shutdown.clone();
                    let beat_inner = inner.clone();
                    let beat_identity = identity.clone();
                    let beat_token = live_token.clone();
                    tokio::spawn(async move {
                        let mut ticker = tokio::time::interval(Duration::from_secs(20));
                        ticker.tick().await;
                        loop {
                            tokio::select! {
                                _ = beat_shutdown.cancelled() => break,
                                _ = ticker.tick() => {
                                    if use_token {
                                        let dir = beat_inner
                                            .session_dir
                                            .lock()
                                            .ok()
                                            .and_then(|slot| slot.clone());
                                        if let Some(dir) = dir {
                                            let cur = beat_token
                                                .lock()
                                                .ok()
                                                .map(|s| s.clone())
                                                .unwrap_or_default();
                                            if let Ok(Some(fresh)) = refresh_or_adopt_for_client(
                                                &dir,
                                                &beat_identity,
                                                &cur,
                                                false,
                                            )
                                            .await
                                            {
                                                if let Ok(mut slot) = beat_token.lock() {
                                                    *slot = fresh.token;
                                                }
                                            }
                                        }
                                    }
                                    let Ok(out) = ws::encode(&Envelope::Ping) else { break };
                                    if beat_tx.send(out).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
                let started = Instant::now();
                let end = run_socket(&inner, ws, &mut app_rx).await;
                fail_transfers(&inner);
                if matches!(end, SocketEnd::Shutdown) || inner.shutdown.is_cancelled() {
                    inner.transport.note_first(ClosureCategory::Shutdown, None);
                    fail_waiters(&inner);
                    break;
                }
                down_since = Some(Instant::now());
                if started.elapsed() > Duration::from_secs(5) {
                    backoff.reset();
                }
                if matches!(end, SocketEnd::GoingAway) {
                    inner.transport.note_first(ClosureCategory::GoingAway, None);
                    inner.fast.store(true, Ordering::SeqCst);
                }
                let delay = next_reconnect_delay(&inner, &mut backoff);
                tokio::select! {
                    _ = inner.shutdown.cancelled() => {
                        inner
                            .transport
                            .note_first(ClosureCategory::Shutdown, None);
                        fail_waiters(&inner);
                        break;
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
    inner.alive.store(false, Ordering::SeqCst);
    if ready.is_some() {
        inner
            .transport
            .note_first(ClosureCategory::ReadyDropped, None);
    }
}

fn next_reconnect_delay(inner: &ClientInner, backoff: &mut crate::resume::Backoff) -> Duration {
    if inner.fast.swap(false, Ordering::SeqCst) {
        backoff.reset();
        Duration::from_millis(200)
    } else {
        backoff.next_delay()
    }
}

async fn dial_client(
    settings: &ClientSettings,
    identity: &crate::identity::Identity,
    use_token: bool,
    transport: &crate::transport_status::TransportObserver,
) -> Result<ClientSocket> {
    use crate::transport_status::ClosureCategory;
    let relay = crate::relay_url::parse_relay_url(&settings.relay)?;
    let trust = tls::RelayTrust::parse(&settings.fingerprint, settings.trust.as_deref())?;
    let addr = relay.dial_label();
    let client_id = identity.public_hex().to_string();
    let tcp = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((relay.host.as_str(), relay.port)),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Message(format!("connect {addr}: {e}")))?;
    tcp.set_nodelay(true).ok();
    let connector = tokio_rustls::TlsConnector::from(client_config_for(&trust)?);
    let server_name = tls::server_name(&relay.host, &trust)?;
    let tls = timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Tls(e.to_string()))?;
    let ws_url = format!("ws://{}:{}{}", relay.bracket_host(), relay.port, relay.path);
    let (mut ws, _resp) = timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::client_async_with_config(ws_url, tls, Some(ws::ws_config())),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Ws(e.to_string()))?;
    let hello = Envelope::Hello {
        role: Role::Client,
        protocol: PROTOCOL_VERSION,
        token: if use_token {
            Some(settings.token.clone())
        } else {
            None
        },
        node_id: None,
        public_key: Some(client_id),
        name: Some(if use_token {
            "admin".into()
        } else {
            "agent".into()
        }),
        pairing_token: None,
        hostname: None,
        os: None,
        arch: None,
        version: None,
        ceiling: None,
        has_display: None,
    };
    ws.send(Message::Text(serde_json::to_string(&hello)?.into()))
        .await
        .map_err(|e| Error::Ws(e.to_string()))?;
    match next_env(&mut ws, transport).await? {
        Envelope::HelloOk { .. } => Ok(ws),
        Envelope::Challenge { nonce } => {
            let signature = identity.sign_nonce(&nonce);
            ws.send(Message::Text(
                serde_json::to_string(&Envelope::Authenticate { signature })?.into(),
            ))
            .await
            .map_err(|e| Error::Ws(e.to_string()))?;
            match next_env(&mut ws, transport).await? {
                Envelope::HelloOk { .. } => Ok(ws),
                Envelope::HelloErr { message, .. } => {
                    // Typed category only for diagnostics; UI may still see `message`.
                    let _ = transport.note_first(ClosureCategory::AuthRejected, None);
                    Err(Error::Auth(message))
                }
                other => Err(Error::Protocol(format!(
                    "expected hello_ok, got {}",
                    kind(&other)
                ))),
            }
        }
        Envelope::HelloErr { message, .. } => {
            let _ = transport.note_first(ClosureCategory::AuthRejected, None);
            Err(Error::Auth(message))
        }
        other => Err(Error::Protocol(format!(
            "expected hello_ok, got {}",
            kind(&other)
        ))),
    }
}

async fn run_socket(
    inner: &Arc<ClientInner>,
    ws: ClientSocket,
    app_rx: &mut mpsc::Receiver<Outbound>,
) -> SocketEnd {
    use crate::transport_status::ClosureCategory;
    let (sink, mut stream) = ws.split();
    let (sock_tx, sock_rx) = mpsc::channel(64);
    let writer_shutdown = inner.shutdown.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = writer_shutdown.cancelled() => {}
            _ = ws::run_writer(sink, sock_rx) => {}
        }
    });
    for env in session_frames(inner) {
        let Ok(out) = ws::encode(&env) else { continue };
        if sock_tx.send(out).await.is_err() {
            inner
                .transport
                .note_first(ClosureCategory::WsStreamEnd, None);
            return SocketEnd::Gone;
        }
    }
    let mut resend_wait = std::pin::pin!(inner.resend.notified());
    let _ = resend_wait.as_mut().enable();
    resend_inflight(inner, &sock_tx).await;
    loop {
        tokio::select! {
            biased;
            _ = inner.shutdown.cancelled() => return SocketEnd::Shutdown,
            _ = &mut resend_wait => {
                resend_wait.set(inner.resend.notified());
                let _ = resend_wait.as_mut().enable();
                tokio::time::sleep(crate::resume::RECONNECT_FLOOR).await;
                resend_inflight(inner, &sock_tx).await;
            }
            outgoing = app_rx.recv() => {
                let Some(outgoing) = outgoing else { return SocketEnd::Shutdown };
                if sock_tx.send(outgoing).await.is_err() {
                    inner
                        .transport
                        .note_first(ClosureCategory::WsStreamEnd, None);
                    return SocketEnd::Gone;
                }
            }
            msg = stream.next() => {
                match msg {
                    None => {
                        inner
                            .transport
                            .note_first(ClosureCategory::WsStreamEnd, None);
                        return SocketEnd::Gone;
                    }
                    Some(Err(_)) => {
                        inner
                            .transport
                            .note_first(ClosureCategory::WsStreamError, None);
                        return SocketEnd::Gone;
                    }
                    Some(Ok(msg)) => match ws::parse_incoming(msg) {
                        Ok(Incoming::Env(Envelope::GoingAway { .. })) => {
                            tracing::info!("relay is going away; reconnecting");
                            return SocketEnd::GoingAway;
                        }
                        Ok(Incoming::Env(Envelope::Session { .. } | Envelope::Pong | Envelope::Ping)) => {}
                        Ok(Incoming::Env(env)) => {
                            for env in take_ready(inner, env) {
                                dispatch(&inner.pending, &inner.binary, env, &inner.shutdown).await;
                            }
                        }
                        Ok(Incoming::Binary(bytes)) => {
                            let id = crate::frame::request_id(&bytes);
                            let peer = id.as_ref().and_then(|id| {
                                inner.routes.lock().ok().and_then(|map| map.get(id).cloned())
                            });
                            match peer {
                                Some(peer) => {
                                    match crate::e2e::open_bound_frame(&inner.e2e, &peer, &bytes) {
                                        Ok(opened) => dispatch_binary(&inner.binary, opened),
                                        Err(err) => {
                                            if let Some(id) = id {
                                                dispatch(
                                                    &inner.pending,
                                                    &inner.binary,
                                                    Envelope::result_err(id, err.to_string()),
                                                    &inner.shutdown,
                                                ).await;
                                            }
                                        }
                                    }
                                }
                                None => {
                                    if let Some(id) = id {
                                        dispatch(
                                            &inner.pending,
                                            &inner.binary,
                                            Envelope::result_err(
                                                id,
                                                "file frame has no end-to-end peer",
                                            ),
                                            &inner.shutdown,
                                        ).await;
                                    }
                                }
                            }
                        }
                        Ok(Incoming::Ping(payload)) => {
                            let _ = sock_tx.try_send(Outbound::Pong(payload));
                        }
                        Ok(Incoming::Closed { code }) => {
                            inner
                                .transport
                                .note_first(ClosureCategory::WsClose, code);
                            return SocketEnd::Gone;
                        }
                        Ok(Incoming::Ignore) => {}
                        Err(err) => tracing::warn!(error = %err, "ignoring malformed frame"),
                    },
                }
            }
        }
    }
}

fn session_frames(inner: &ClientInner) -> Vec<Envelope> {
    let cursors = inner
        .cursors
        .lock()
        .map(|cursors| cursors.export())
        .unwrap_or_default();
    let routes = inner
        .routes
        .lock()
        .map(|routes| routes.clone())
        .unwrap_or_default();
    let mut by_node: HashMap<String, Vec<crate::protocol::SessionCursor>> = HashMap::new();
    for cursor in cursors {
        let Some(node) = routes.get(&cursor.request_id) else {
            continue;
        };
        by_node.entry(node.clone()).or_default().push(cursor);
    }
    if let Ok(inflight) = inner.inflight.lock() {
        for env in inflight.values() {
            if let Some(node) = node_id_of(env) {
                by_node.entry(node).or_default();
            }
        }
    }
    by_node
        .into_iter()
        .map(|(node_id, cursors)| Envelope::Session {
            session_id: inner.session_id.clone(),
            node_id,
            cursors,
        })
        .collect()
}

async fn resend_inflight(inner: &Arc<ClientInner>, sock_tx: &mpsc::Sender<Outbound>) {
    let pending: Vec<Envelope> = inner
        .inflight
        .lock()
        .map(|mut map| {
            for env in map.values_mut() {
                if let Envelope::Invoke { node_id, authz, .. } = env {
                    if let Ok(fresh) = inner.authz_for(node_id) {
                        *authz = fresh;
                    }
                }
            }
            map.values().cloned().collect()
        })
        .unwrap_or_default();
    let mut handshake = Vec::new();
    for env in pending {
        let Some(node) = node_id_of(&env) else {
            if let Ok(out) = ws::encode(&env) {
                if sock_tx.send(out).await.is_err() {
                    return;
                }
            }
            continue;
        };
        if !inner.e2e.has(&node) {
            handshake.push(node);
            continue;
        }
        match crate::e2e::seal_envelope(&inner.e2e, &node, &node, inner.e2e.peer_id(), &env) {
            Ok(wrapped) => {
                if let Some(id) = wrapped.request_id() {
                    inner.note_route(id, &node);
                }
                let Ok(out) = ws::encode(&wrapped) else {
                    continue;
                };
                if sock_tx.send(out).await.is_err() {
                    return;
                }
            }
            Err(_) => handshake.push(node),
        }
    }
    handshake.sort();
    handshake.dedup();
    for node in handshake {
        let inner = inner.clone();
        tokio::spawn(async move {
            let client_id = inner.e2e.peer_id().to_string();
            if ensure_e2e(&inner, &node, &client_id).await.is_ok() {
                inner.resend.notify_waiters();
            }
        });
    }
}

fn close_orphan_pty_best_effort(
    inner: &Arc<ClientInner>,
    node_id: String,
    client_id: String,
    session_ids: Vec<String>,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let inner = inner.clone();
    handle.spawn(async move {
        for sid in session_ids {
            if sid.is_empty() {
                continue;
            }
            let writer = PtyWriter {
                session_id: sid,
                node_id: node_id.clone(),
                client_id: client_id.clone(),
                inner: inner.clone(),
            };
            let _ = writer
                .send_op(Op::PtyClose {
                    session_id: writer.session_id.clone(),
                })
                .await;
        }
    });
}

fn take_ready(inner: &Arc<ClientInner>, env: Envelope) -> Vec<Envelope> {
    let env = unwrap_client(&inner.e2e, env);
    if let Envelope::Result {
        ok: false,
        error: Some(message),
        request_id,
        ..
    } = &env
    {
        if crate::resume::is_transient_message(message) {
            let lower = message.to_ascii_lowercase();
            if lower.contains("e2e session reset") {
                if let Some(node) = inner
                    .routes
                    .lock()
                    .ok()
                    .and_then(|routes| routes.get(request_id).cloned())
                {
                    inner.e2e.forget(&node);
                }
            }
            let is_inflight = !request_id.is_empty()
                && inner
                    .inflight
                    .lock()
                    .ok()
                    .is_some_and(|map| map.contains_key(request_id));
            if is_inflight {
                let is_offline =
                    lower.contains("node offline") || lower.contains("node disconnected");
                if is_offline {
                    let expired = inner
                        .offline_since
                        .lock()
                        .ok()
                        .map(|mut map| {
                            let first = *map.entry(request_id.clone()).or_insert_with(Instant::now);
                            if first.elapsed() >= crate::resume::OFFLINE_GRACE {
                                map.remove(request_id);
                                true
                            } else {
                                false
                            }
                        })
                        .unwrap_or(true);
                    if !expired {
                        inner.resend.notify_waiters();
                        return Vec::new();
                    }
                } else {
                    inner.resend.notify_waiters();
                    return Vec::new();
                }
            } else {
                // Non-inflight unary calls (e.g. `PtyWriter::send_op`) will not
                // be resent by `resend_inflight`: deliver the transient error
                // immediately so the caller can decide (or fail fast).
                return vec![env];
            }
        }
    }
    if let Some(id) = env.request_id() {
        if let Ok(mut map) = inner.offline_since.lock() {
            map.remove(id);
        }
    }
    if let Envelope::Result {
        request_id,
        ok,
        body,
        error,
        ..
    } = &env
    {
        let already_acked = inner
            .cursors
            .lock()
            .map(|c| c.applied(request_id) >= 1)
            .unwrap_or(false);
        if already_acked {
            let active = inner
                .pty_streams
                .lock()
                .ok()
                .and_then(|map| map.get(request_id).cloned());
            if let Some(active) = active {
                if !*ok {
                    inner.forget_pty_stream(request_id);
                    return vec![Envelope::result_err(
                        request_id.clone(),
                        error
                            .clone()
                            .unwrap_or_else(|| "remote shell session ended".into()),
                    )];
                }
                if let Some(replayed_sid) = body
                    .as_ref()
                    .and_then(|v| v.get("session_id"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    if replayed_sid != active.session_id {
                        // An un-upgraded node evicted `request_id` from its
                        // 256-entry `live.sessions` map (or restarted) and
                        // executed `PtyOpen` again at `seq = 1` instead of
                        // replaying the original shell's ring. Close both
                        // shells best-effort and surface a clean session end
                        // rather than dropping `seq = 1 < expected` into a
                        // zombie prompt.
                        inner.forget_pty_stream(request_id);
                        close_orphan_pty_best_effort(
                            inner,
                            active.node_id,
                            active.client_id,
                            vec![replayed_sid.to_string(), active.session_id],
                        );
                        return vec![Envelope::result_err(
                            request_id.clone(),
                            "Remote shell session lost its replay slot across reconnect; reopen shell to continue.",
                        )];
                    }
                }
            }
        }
    }
    let ready = inner
        .cursors
        .lock()
        .map(|mut cursors| cursors.push(env))
        .unwrap_or_default();
    if let Ok(mut inflight) = inner.inflight.lock() {
        for env in &ready {
            if env.is_terminal_frame() {
                if let Some(id) = env.request_id() {
                    inflight.remove(id);
                    if let Ok(mut streams) = inner.pty_streams.lock() {
                        streams.remove(id);
                    }
                }
            }
        }
    }
    ready
}

fn fail_transfers(inner: &ClientInner) {
    let ids: Vec<String> = inner
        .transfers
        .lock()
        .map(|set| set.iter().cloned().collect())
        .unwrap_or_default();
    let mut pending = inner.pending.lock().ok();
    let mut binary = inner.binary.lock().ok();
    for id in ids {
        if let Some(map) = pending.as_mut() {
            map.remove(&id);
        }
        // Dropping the sender closes the transfer link, so a socket drop
        // does not leave serve_push waiting on ciphertext or a live route.
        if let Some(map) = binary.as_mut() {
            map.remove(&id);
        }
    }
}

fn fail_waiters(inner: &ClientInner) {
    fail_waiters_with(inner, None);
}

fn fail_waiters_with(inner: &ClientInner, message: Option<&str>) {
    inner.alive.store(false, Ordering::SeqCst);
    let waiters = if let Ok(mut map) = inner.pending.lock() {
        map.drain().collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    for (id, tx) in waiters {
        if let Some(message) = message {
            let _ = tx.try_send_error(&id, message);
        }
        tx.close();
    }
    if let Ok(mut map) = inner.binary.lock() {
        map.clear();
    }
}

fn replayable(env: &Envelope) -> bool {
    match env {
        Envelope::Invoke { .. } | Envelope::E2eHello { .. } => true,
        Envelope::Transfer { .. }
        | Envelope::Cancel { .. }
        | Envelope::DirectOffer { .. }
        | Envelope::DirectAnswer { .. }
        | Envelope::Session { .. }
        | Envelope::CreatePairingToken { .. } => false,
        other => other.request_id().is_some(),
    }
}

fn forget_inflight(inner: &ClientInner, env: &Envelope) {
    let Some(id) = env.request_id() else { return };
    if let Ok(mut map) = inner.inflight.lock() {
        map.remove(id);
    }
}

fn node_id_of(env: &Envelope) -> Option<String> {
    match env {
        Envelope::Invoke { node_id, .. }
        | Envelope::Cancel { node_id, .. }
        | Envelope::Transfer { node_id, .. }
        | Envelope::E2eHello { node_id, .. }
        | Envelope::E2e { node_id, .. } => Some(node_id.clone()),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct UserSession {
    pub user: String,
    pub role: String,
    pub device_id: String,
    pub access_token: String,
    pub access_expires_unix: i64,
    pub refresh_token: String,
    pub refresh_expires_unix: i64,
}

/// Inputs for a session refresh under the config-dir advisory lock.
#[derive(Debug, Clone)]
pub struct SessionRefreshRequest {
    pub relay: String,
    pub fingerprint: String,
    pub trust: Option<String>,
    pub refresh_token: String,
}

/// Refresh a saved access token when it expires within a minute.
///
/// Single-writer: takes `config.json.lock`, re-loads the file under the lock,
/// skips refresh when the access token is still fresh, otherwise refreshes and
/// atomically saves. If refresh fails because another process already rotated
/// the token, re-loads and adopts that session when it is usable.
///
/// Returns `Ok(None)` when there is no refresh token, relay/trust is missing,
/// or the access token is still fresh (no write needed).
pub async fn maintain_session(
    dir: &std::path::Path,
    identity: &crate::identity::Identity,
) -> Result<Option<crate::config::ClientSettings>> {
    maintain_session_skew(dir, identity, 60).await
}

/// Like [`maintain_session`], with an explicit early-refresh window `skew_secs`
/// before `access_expires_unix`. Long-lived interactive sessions pass a wider
/// window at bootstrap so they do not open a socket on a nearly spent token.
pub async fn maintain_session_skew(
    dir: &std::path::Path,
    identity: &crate::identity::Identity,
    skew_secs: i64,
) -> Result<Option<crate::config::ClientSettings>> {
    let identity = identity.clone();
    maintain_session_with_skew(dir, &identity, skew_secs, |req, identity| {
        let SessionRefreshRequest {
            relay,
            fingerprint,
            trust,
            refresh_token,
        } = req;
        let identity = identity.clone();
        async move {
            refresh_user(
                &relay,
                &fingerprint,
                trust.as_deref(),
                &identity,
                &refresh_token,
            )
            .await
        }
    })
    .await
}

fn in_process_session_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn lock_session_async(dir: &std::path::Path) -> Result<crate::config::ConfigSessionLock> {
    let owned = dir.to_path_buf();
    tokio::task::spawn_blocking(move || crate::config::lock_session(&owned))
        .await
        .map_err(|err| Error::Message(format!("session lock join: {err}")))?
}

/// Adopt a token rotated by a sibling CLI/GUI process sharing `dir`, or rotate
/// the refresh token under `lock_session` when within 120s of expiry (or when
/// `force_refresh` is set after the relay rejected `current_token` as expired).
async fn refresh_or_adopt_for_client(
    dir: &std::path::Path,
    identity: &crate::identity::Identity,
    current_token: &str,
    force_refresh: bool,
) -> Result<Option<crate::config::ClientSettings>> {
    let file_probe = crate::config::load_file(dir).unwrap_or_default();
    let now = crate::util::unix_now();
    let probe_tok = file_probe.token.as_deref().unwrap_or("");
    if !force_refresh
        && probe_tok == current_token
        && crate::config::access_token_is_fresh(&file_probe, now, 120)
    {
        return Ok(None);
    }

    let _async_guard = in_process_session_gate().lock().await;
    let _lock = lock_session_async(dir).await?;
    let file = crate::config::load_file(dir).unwrap_or_default();
    let relay = file.relay.clone().unwrap_or_default();
    let fingerprint = file.fingerprint.clone().unwrap_or_default();
    let trust = file.trust.clone().filter(|value| !value.trim().is_empty());
    if relay.is_empty() || (fingerprint.is_empty() && trust.is_none()) {
        return Ok(None);
    }
    let disk_token = file.token.clone().unwrap_or_default();
    let now = crate::util::unix_now();
    if !disk_token.trim().is_empty()
        && disk_token != current_token
        && crate::config::access_token_is_fresh(&file, now, 0)
    {
        return Ok(Some(crate::config::ClientSettings {
            relay,
            token: disk_token,
            fingerprint,
            trust,
        }));
    }
    if !force_refresh && crate::config::access_token_is_fresh(&file, now, 120) {
        return Ok(None);
    }
    let Some(refresh) = file
        .refresh_token
        .clone()
        .filter(|token| !token.trim().is_empty())
    else {
        return Ok(None);
    };
    match refresh_user(
        &relay,
        &fingerprint,
        trust.as_deref(),
        identity,
        &refresh,
    )
    .await
    {
        Ok(session) => {
            let settings = crate::config::ClientSettings {
                relay,
                token: session.access_token.clone(),
                fingerprint,
                trust,
            };
            crate::config::save_session_unlocked(
                dir,
                &settings,
                &session.user,
                &session.refresh_token,
                session.access_expires_unix,
            )?;
            Ok(Some(settings))
        }
        Err(err) => {
            let again = crate::config::load_file(dir).unwrap_or_default();
            let now = crate::util::unix_now();
            if crate::config::access_token_is_fresh(&again, now, 0) {
                let token = again.token.unwrap_or_default();
                if !token.is_empty() && token != current_token {
                    return Ok(Some(crate::config::ClientSettings {
                        relay: again.relay.unwrap_or(relay),
                        token,
                        fingerprint: again.fingerprint.unwrap_or(fingerprint),
                        trust: again.trust.filter(|v| !v.trim().is_empty()).or(trust),
                    }));
                }
            }
            Err(err)
        }
    }
}

/// Like [`maintain_session`], but the refresh step is injectable for hermetic
/// tests. Never copies a production session file.
pub async fn maintain_session_with<F, Fut>(
    dir: &std::path::Path,
    identity: &crate::identity::Identity,
    refresh_fn: F,
) -> Result<Option<crate::config::ClientSettings>>
where
    F: FnOnce(SessionRefreshRequest, &crate::identity::Identity) -> Fut,
    Fut: std::future::Future<Output = Result<UserSession>>,
{
    maintain_session_with_skew(dir, identity, 60, refresh_fn).await
}

pub async fn maintain_session_with_skew<F, Fut>(
    dir: &std::path::Path,
    identity: &crate::identity::Identity,
    skew_secs: i64,
    refresh_fn: F,
) -> Result<Option<crate::config::ClientSettings>>
where
    F: FnOnce(SessionRefreshRequest, &crate::identity::Identity) -> Fut,
    Fut: std::future::Future<Output = Result<UserSession>>,
{
    let _async_guard = in_process_session_gate().lock().await;
    let _lock = lock_session_async(dir).await?;
    let file = crate::config::load_file(dir).unwrap_or_default();
    let Some(refresh) = file
        .refresh_token
        .clone()
        .filter(|token| !token.trim().is_empty())
    else {
        return Ok(None);
    };
    let relay = file.relay.clone().unwrap_or_default();
    let fingerprint = file.fingerprint.clone().unwrap_or_default();
    let trust = file.trust.clone().filter(|value| !value.trim().is_empty());
    if relay.is_empty() || (fingerprint.is_empty() && trust.is_none()) {
        return Ok(None);
    }
    let now = crate::util::unix_now();
    if crate::config::access_token_is_fresh(&file, now, skew_secs) {
        return Ok(None);
    }
    let req = SessionRefreshRequest {
        relay: relay.clone(),
        fingerprint: fingerprint.clone(),
        trust: trust.clone(),
        refresh_token: refresh,
    };
    match refresh_fn(req, identity).await {
        Ok(session) => {
            let settings = crate::config::ClientSettings {
                relay,
                token: session.access_token.clone(),
                fingerprint,
                trust,
            };
            crate::config::save_session_unlocked(
                dir,
                &settings,
                &session.user,
                &session.refresh_token,
                session.access_expires_unix,
            )?;
            Ok(Some(settings))
        }
        Err(err) => {
            // Another process may have won the rotation. Re-read under the
            // same lock and adopt a usable session instead of burning again.
            let again = crate::config::load_file(dir).unwrap_or_default();
            let now = crate::util::unix_now();
            if crate::config::access_token_is_fresh(&again, now, 0) {
                let relay = again.relay.unwrap_or_default();
                let fingerprint = again.fingerprint.unwrap_or_default();
                let trust = again.trust.filter(|value| !value.trim().is_empty());
                let token = again.token.unwrap_or_default();
                if !relay.is_empty() && !token.is_empty() {
                    return Ok(Some(crate::config::ClientSettings {
                        relay,
                        token,
                        fingerprint,
                        trust,
                    }));
                }
            }
            Err(err)
        }
    }
}

/// Username/password login. The device key is `identity`. The returned access
/// token is what later `connect_identity` calls send as `Hello.token`.
pub async fn login_user(
    relay: &str,
    fingerprint: &str,
    trust: Option<&str>,
    identity: &crate::identity::Identity,
    username: &str,
    password: &str,
    totp: Option<&str>,
    device_name: &str,
) -> Result<UserSession> {
    let mut ws = dial_relay(relay, fingerprint, trust).await?;
    let request_id = uuid::Uuid::new_v4().to_string();
    send_ws(
        &mut ws,
        &Envelope::Login {
            request_id: request_id.clone(),
            username: username.to_string(),
            password: password.to_string(),
            totp: totp.map(|code| code.to_string()),
            public_key: identity.public_hex().to_string(),
            device_name: Some(device_name.to_string()),
        },
    )
    .await?;
    finish_login(&mut ws, identity, &request_id).await
}

pub async fn refresh_user(
    relay: &str,
    fingerprint: &str,
    trust: Option<&str>,
    identity: &crate::identity::Identity,
    refresh_token: &str,
) -> Result<UserSession> {
    let mut ws = dial_relay(relay, fingerprint, trust).await?;
    let request_id = uuid::Uuid::new_v4().to_string();
    send_ws(
        &mut ws,
        &Envelope::RefreshSession {
            request_id: request_id.clone(),
            refresh_token: refresh_token.to_string(),
            public_key: identity.public_hex().to_string(),
        },
    )
    .await?;
    finish_login(&mut ws, identity, &request_id).await
}

async fn finish_login(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>,
    identity: &crate::identity::Identity,
    request_id: &str,
) -> Result<UserSession> {
    // Hermetic observer: account login helpers are not Client sessions, but
    // next_env requires a TransportObserver after sticky first-cause wiring.
    let transport = crate::transport_status::TransportObserver::new();
    loop {
        match next_env(ws, &transport).await? {
            Envelope::Challenge { nonce } => {
                send_ws(
                    ws,
                    &Envelope::Authenticate {
                        signature: identity.sign_nonce(&nonce),
                    },
                )
                .await?;
            }
            Envelope::LoginOk {
                request_id: id,
                user,
                role,
                device_id,
                access_token,
                access_expires_unix,
                refresh_token,
                refresh_expires_unix,
            } if id == request_id => {
                return Ok(UserSession {
                    user,
                    role,
                    device_id,
                    access_token,
                    access_expires_unix,
                    refresh_token,
                    refresh_expires_unix,
                });
            }
            Envelope::LoginErr { message, .. } => return Err(Error::Auth(message)),
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected {} during login",
                    kind(&other)
                )));
            }
        }
    }
}

async fn dial_relay(
    relay: &str,
    fingerprint: &str,
    trust: Option<&str>,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>> {
    let relay = crate::relay_url::parse_relay_url(relay)?;
    let trust = tls::RelayTrust::parse(fingerprint, trust)?;
    let addr = relay.dial_label();
    let tcp = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((relay.host.as_str(), relay.port)),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Message(format!("connect {addr}: {e}")))?;
    tcp.set_nodelay(true).ok();
    let connector = tokio_rustls::TlsConnector::from(client_config_for(&trust)?);
    let server_name = tls::server_name(&relay.host, &trust)?;
    let tls = timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Tls(e.to_string()))?;
    let ws_url = format!("ws://{}:{}{}", relay.bracket_host(), relay.port, relay.path);
    let (ws, _resp) = timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::client_async_with_config(ws_url, tls, Some(ws::ws_config())),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Ws(e.to_string()))?;
    Ok(ws)
}

async fn send_ws(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>,
    env: &Envelope,
) -> Result<()> {
    ws.send(Message::Text(serde_json::to_string(env)?.into()))
        .await
        .map_err(|e| Error::Ws(e.to_string()))
}

fn kind(env: &Envelope) -> &'static str {
    match env {
        Envelope::Hello { .. } => "hello",
        Envelope::Challenge { .. } => "challenge",
        Envelope::Authenticate { .. } => "authenticate",
        Envelope::HelloOk { .. } => "hello_ok",
        Envelope::HelloErr { .. } => "hello_err",
        Envelope::Ping => "ping",
        Envelope::Pong => "pong",
        Envelope::CreatePairingToken { .. } => "create_pairing_token",
        Envelope::PairingToken { .. } => "pairing_token",
        Envelope::SetPolicy { .. } => "set_policy",
        Envelope::ListNodes { .. } => "list_nodes",
        Envelope::NodeList { .. } => "node_list",
        Envelope::Invoke { .. } => "invoke",
        Envelope::Cancel { .. } => "cancel",
        Envelope::Result { .. } => "result",
        Envelope::Chunk { .. } => "chunk",
        Envelope::End { .. } => "end",
        Envelope::PolicyUpdate { .. } => "policy_update",
        Envelope::Transfer { .. } => "transfer",
        Envelope::DirectOffer { .. } => "direct_offer",
        Envelope::DirectAnswer { .. } => "direct_answer",
        Envelope::E2eHello { .. } => "e2e_hello",
        Envelope::E2eWelcome { .. } => "e2e_welcome",
        Envelope::E2e { .. } => "e2e",
        Envelope::RegisterClient { .. } => "register_client",
        Envelope::SetClientGrant { .. } => "set_client_grant",
        Envelope::RevokeClient { .. } => "revoke_client",
        Envelope::ListClients { .. } => "list_clients",
        Envelope::ClientList { .. } => "client_list",
        Envelope::ApprovalRequest { .. } => "approval_request",
        Envelope::ListApprovals { .. } => "list_approvals",
        Envelope::ApprovalList { .. } => "approval_list",
        Envelope::ResolveApproval { .. } => "resolve_approval",
        Envelope::ApprovalDecision { .. } => "approval_decision",
        Envelope::AuditBatch { .. } => "audit_batch",
        Envelope::QueryAudit { .. } => "query_audit",
        Envelope::AuditPage { .. } => "audit_page",
        Envelope::SetAuditPolicy { .. } => "set_audit_policy",
        Envelope::AuditPolicyPush { .. } => "audit_policy_push",
        Envelope::IssueViewTicket { .. } => "issue_view_ticket",
        Envelope::ViewTicket { .. } => "view_ticket",
        Envelope::Login { .. } => "login",
        Envelope::LoginOk { .. } => "login_ok",
        Envelope::LoginErr { .. } => "login_err",
        Envelope::RefreshSession { .. } => "refresh_session",
        Envelope::Signup { .. } => "signup",
        Envelope::Logout { .. } => "logout",
        Envelope::ListDevices { .. } => "list_devices",
        Envelope::DeviceList { .. } => "device_list",
        Envelope::RevokeDevice { .. } => "revoke_device",
        Envelope::UserAdd { .. } => "user_add",
        Envelope::UserList { .. } => "user_list",
        Envelope::UserListed { .. } => "user_listed",
        Envelope::UserPasswd { .. } => "user_passwd",
        Envelope::UserSetDisabled { .. } => "user_set_disabled",
        Envelope::UserRemove { .. } => "user_remove",
        Envelope::UserSetRole { .. } => "user_set_role",
        Envelope::TotpBegin { .. } => "totp_begin",
        Envelope::TotpPending { .. } => "totp_pending",
        Envelope::TotpConfirm { .. } => "totp_confirm",
        Envelope::TotpDisable { .. } => "totp_disable",
        Envelope::ShareNode { .. } => "share_node",
        Envelope::UnshareNode { .. } => "unshare_node",
        Envelope::ListEnrollmentTokens { .. } => "list_enrollment_tokens",
        Envelope::EnrollmentTokenList { .. } => "enrollment_token_list",
        Envelope::RevokeEnrollmentToken { .. } => "revoke_enrollment_token",
        Envelope::EnrollSelf { .. } => "enroll_self",
        Envelope::SetUserAudit { .. } => "set_user_audit",
        Envelope::GoingAway { .. } => "going_away",
        Envelope::Session { .. } => "session",
    }
}

#[cfg(test)]
mod session_maintain_tests {
    use super::*;
    use crate::config::{load_file, save_session, ClientSettings};
    use crate::identity::Identity;

    fn dummy_identity() -> Identity {
        Identity::from_seed(&[7u8; 32]).unwrap()
    }

    fn dummy_settings() -> ClientSettings {
        ClientSettings {
            relay: "wss://relay.example:7443".into(),
            token: "access-old".into(),
            fingerprint: format!("sha256:{}", "ab".repeat(32)),
            trust: None,
        }
    }

    fn dummy_session(access: &str, refresh: &str, exp: i64) -> UserSession {
        UserSession {
            user: "alice".into(),
            role: "user".into(),
            device_id: "dev1".into(),
            access_token: access.into(),
            access_expires_unix: exp,
            refresh_token: refresh.into(),
            refresh_expires_unix: exp + 86_400,
        }
    }

    #[tokio::test]
    async fn missing_refresh_token_returns_none_without_calling_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = called.clone();
        let out = maintain_session_with(dir.path(), &dummy_identity(), |_req, _id| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            async { Ok(dummy_session("a", "r", 9_999)) }
        })
        .await
        .unwrap();
        assert!(out.is_none());
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn skips_refresh_when_access_token_is_still_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let settings = dummy_settings();
        let far = crate::util::unix_now() + 3_600;
        save_session(dir.path(), &settings, "alice", "refresh-old", far).unwrap();
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = called.clone();
        let out = maintain_session_with(dir.path(), &dummy_identity(), |_req, _id| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            async { Ok(dummy_session("access-new", "refresh-new", far)) }
        })
        .await
        .unwrap();
        assert!(out.is_none());
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        let loaded = load_file(dir.path()).unwrap();
        assert_eq!(loaded.token.as_deref(), Some("access-old"));
        assert_eq!(loaded.refresh_token.as_deref(), Some("refresh-old"));
    }

    #[tokio::test]
    async fn refreshes_under_lock_and_saves_new_session() {
        let dir = tempfile::tempdir().unwrap();
        let settings = dummy_settings();
        save_session(dir.path(), &settings, "alice", "refresh-old", 1).unwrap();
        let out = maintain_session_with(dir.path(), &dummy_identity(), |req, _id| {
            assert_eq!(req.refresh_token, "refresh-old");
            async {
                Ok(dummy_session(
                    "access-new",
                    "refresh-new",
                    crate::util::unix_now() + 3_600,
                ))
            }
        })
        .await
        .unwrap()
        .expect("refreshed");
        assert_eq!(out.token, "access-new");
        let loaded = load_file(dir.path()).unwrap();
        assert_eq!(loaded.token.as_deref(), Some("access-new"));
        assert_eq!(loaded.refresh_token.as_deref(), Some("refresh-new"));
        assert_eq!(loaded.user.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn stale_refresh_failure_adopts_winner_session() {
        let dir = tempfile::tempdir().unwrap();
        let settings = dummy_settings();
        save_session(dir.path(), &settings, "alice", "refresh-old", 1).unwrap();
        let winner = ClientSettings {
            token: "access-winner".into(),
            ..dummy_settings()
        };
        let dir_for_fn = dir.path().to_path_buf();
        let out = maintain_session_with(dir.path(), &dummy_identity(), move |_req, _id| {
            let dir_for_fn = dir_for_fn.clone();
            let winner = winner.clone();
            async move {
                // Simulate the other process winning the rotation and saving
                // under a separate lock after this caller has already decided
                // to refresh (file already loaded). The unlock/re-lock path is
                // the save itself; we write the winner file then fail.
                crate::config::save_session_unlocked(
                    &dir_for_fn,
                    &winner,
                    "alice",
                    "refresh-winner",
                    crate::util::unix_now() + 3_600,
                )
                .unwrap();
                Err(Error::Auth("refresh token already used".into()))
            }
        })
        .await
        .unwrap()
        .expect("adopted winner");
        assert_eq!(out.token, "access-winner");
        let loaded = load_file(dir.path()).unwrap();
        assert_eq!(loaded.token.as_deref(), Some("access-winner"));
        assert_eq!(loaded.refresh_token.as_deref(), Some("refresh-winner"));
    }

    #[test]
    fn take_ready_surfaces_node_offline_after_grace_instead_of_swallowing_forever() {
        let (tx, _rx) = mpsc::channel(4);
        let inner = Arc::new(ClientInner {
            tx,
            pending: Arc::new(Mutex::new(HashMap::new())),
            binary: Arc::new(Mutex::new(HashMap::new())),
            alive: Arc::new(AtomicBool::new(true)),
            socket_gen: std::sync::atomic::AtomicU64::new(1),
            shutdown: CancellationToken::new(),
            relay_addr: None,
            direct_id: OnceLock::new(),
            quic: Mutex::new(None),
            e2e: crate::e2e::Endpoint::new(crate::identity::Identity::generate()),
            routes: Arc::new(Mutex::new(HashMap::new())),
            gates: Mutex::new(HashMap::new()),
            session_id: "sess-1".into(),
            inflight: Mutex::new(HashMap::new()),
            cursors: Mutex::new(crate::resume::Cursors::default()),
            pty_streams: Mutex::new(HashMap::new()),
            transfers: Arc::new(Mutex::new(std::collections::HashSet::new())),
            grant_dir: Arc::new(Mutex::new(None)),
            session_dir: Arc::new(Mutex::new(None)),
            resend: Notify::new(),
            fast: AtomicBool::new(false),
            transport: crate::transport_status::TransportObserver::new(),
            offline_since: Mutex::new(HashMap::new()),
            write_hook: Mutex::new(None),
        });
        let req = "pty-open-1";
        inner.inflight.lock().unwrap().insert(
            req.to_string(),
            Envelope::Ping,
        );
        let offline = Envelope::result_err(req.to_string(), "node offline: sufa");
        // Initial offline reply within OFFLINE_GRACE is retried transiently for inflight ops.
        assert!(take_ready(&inner, offline.clone()).is_empty());
        // Non-inflight unary ops (e.g. PtyWriter::send_op) must receive transient errors immediately.
        let non_inflight = Envelope::result_err("pty-input-1".into(), "node offline: sufa");
        assert_eq!(take_ready(&inner, non_inflight).len(), 1);
        // Once OFFLINE_GRACE has elapsed, take_ready MUST deliver the real error
        // rather than swallowing it for 30s until Error::Timeout!
        std::thread::sleep(crate::resume::OFFLINE_GRACE + Duration::from_millis(80));
        let delivered = take_ready(&inner, offline);
        assert_eq!(
            delivered.len(),
            1,
            "node offline stayed swallowed past OFFLINE_GRACE, causing 30s PtyOpen timeout!"
        );
    }

    #[tokio::test]
    async fn take_ready_catches_bc97_evicted_pty_open_phantom_shell_and_seq1_error() {
        let (tx, mut out_rx) = mpsc::channel(16);
        let node_ep = crate::e2e::Endpoint::new(crate::identity::Identity::generate());
        let client_id_ident = crate::identity::Identity::generate();
        let client_ep = crate::e2e::Endpoint::new(client_id_ident.clone());
        let node_id = node_ep.peer_id().to_string();
        let pending_hello = client_ep.client_hello(&node_id).unwrap();
        let (_, welcome) = node_ep
            .accept(crate::e2e::Endpoint::hello_bytes(&pending_hello))
            .unwrap();
        client_ep.complete(pending_hello, &welcome).unwrap();

        let inner = Arc::new(ClientInner {
            tx,
            pending: Arc::new(Mutex::new(HashMap::new())),
            binary: Arc::new(Mutex::new(HashMap::new())),
            alive: Arc::new(AtomicBool::new(true)),
            socket_gen: std::sync::atomic::AtomicU64::new(1),
            shutdown: CancellationToken::new(),
            relay_addr: None,
            direct_id: OnceLock::new(),
            quic: Mutex::new(None),
            e2e: client_ep,
            routes: Arc::new(Mutex::new(HashMap::new())),
            gates: Mutex::new(HashMap::new()),
            session_id: "sess-bc97".into(),
            inflight: Mutex::new(HashMap::new()),
            cursors: Mutex::new(crate::resume::Cursors::default()),
            pty_streams: Mutex::new(HashMap::new()),
            transfers: Arc::new(Mutex::new(std::collections::HashSet::new())),
            grant_dir: Arc::new(Mutex::new(None)),
            session_dir: Arc::new(Mutex::new(None)),
            resend: Notify::new(),
            fast: AtomicBool::new(false),
            transport: crate::transport_status::TransportObserver::new(),
            offline_since: Mutex::new(HashMap::new()),
            write_hook: Mutex::new(None),
        });

        let req = "r-open-2".to_string();
        inner
            .inflight
            .lock()
            .unwrap()
            .insert(req.clone(), Envelope::Ping);
        inner.pty_streams.lock().unwrap().insert(
            req.clone(),
            ActivePtyStream {
                session_id: "sid-orig".into(),
                node_id: node_id.clone(),
                client_id: client_id_ident.public_hex().to_string(),
            },
        );
        // Simulate initial ack (seq=1) + 3 output chunks (seq=2..=4) so expected == 5.
        let mut ack1 = Envelope::result_ack(
            req.clone(),
            serde_json::json!({"session_id": "sid-orig", "rows": 24, "cols": 80}),
        );
        ack1.set_seq(1);
        assert_eq!(take_ready(&inner, ack1.clone()).len(), 1);
        for seq in 2..=4 {
            assert_eq!(
                take_ready(
                    &inner,
                    Envelope::Chunk {
                        request_id: req.clone(),
                        stream: "pty".into(),
                        data_b64: "b2s=".into(),
                        seq,
                    }
                )
                .len(),
                1
            );
        }

        // 1. Legitimate duplicate ack of the SAME session_id at seq=1 is deduplicated cleanly.
        assert!(take_ready(&inner, ack1).is_empty());
        assert!(inner.pty_streams.lock().unwrap().contains_key(&req));

        // 2. Un-upgraded bc97 node evicted `r-open-2` from its 256-entry `live.sessions`
        // and spawned phantom `sid-phantom` at `seq = 1 < 5`. `take_ready` MUST surface a
        // terminal error (seq=0) AND dispatch best-effort `PtyClose` for both sessions!
        let mut phantom_ack = Envelope::result_ack(
            req.clone(),
            serde_json::json!({"session_id": "sid-phantom", "rows": 24, "cols": 80}),
        );
        phantom_ack.set_seq(1);
        let out = take_ready(&inner, phantom_ack);
        assert_eq!(out.len(), 1, "phantom seq=1 replay was swallowed!");
        assert!(
            matches!(&out[0], Envelope::Result { ok: false, error: Some(msg), .. } if msg.contains("lost its replay slot")),
            "unexpected frame: {:?}",
            out[0]
        );
        assert!(!inner.pty_streams.lock().unwrap().contains_key(&req));
        assert!(!inner.inflight.lock().unwrap().contains_key(&req));

        // Verify best-effort PtyClose frames were queued on `tx` for cleanup.
        let close_1 = tokio::time::timeout(Duration::from_secs(1), out_rx.recv())
            .await
            .expect("close 1 timeout")
            .expect("close 1 frame");
        let _ = close_1;

        // 3. Also verify a `seq = 1 < expected` fatal `Result { ok: false }` on another
        // active stream is surfaced instead of swallowed by `Cursors::push`!
        let req2 = "r-open-3".to_string();
        inner
            .inflight
            .lock()
            .unwrap()
            .insert(req2.clone(), Envelope::Ping);
        inner.pty_streams.lock().unwrap().insert(
            req2.clone(),
            ActivePtyStream {
                session_id: "sid-2".into(),
                node_id,
                client_id: client_id_ident.public_hex().to_string(),
            },
        );
        let mut ack2 = Envelope::result_ack(req2.clone(), serde_json::json!({"session_id": "sid-2"}));
        ack2.set_seq(1);
        assert_eq!(take_ready(&inner, ack2).len(), 1);
        let mut err_seq1 = Envelope::result_err(req2.clone(), "too many concurrent pty sessions");
        err_seq1.set_seq(1);
        let out2 = take_ready(&inner, err_seq1);
        assert_eq!(out2.len(), 1, "seq=1 fatal Result on active PTY was dropped!");
        assert!(matches!(
            &out2[0],
            Envelope::Result { ok: false, error: Some(msg), .. } if msg.contains("too many concurrent pty sessions")
        ));
    }
}
