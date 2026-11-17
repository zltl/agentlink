//! Accept loop, handshake, and request routing.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use agentlink_core::accounts;
use agentlink_core::protocol::{
    ApprovalInfo, DeviceInfo, Envelope, NodeInfo, Role, TokenInfo, TransferMsg, UserInfo,
    PROTOCOL_VERSION, WS_PATH, WS_WEBRTC_PATH, WS_WEB_PATH,
};
use agentlink_core::util::{self, unix_now};
use agentlink_core::ws::{self, Incoming, Outbound};
use agentlink_core::{Error, NodePolicy, Op, Result, PHASE3_WEBRTC_SIGNAL};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use crate::db::{Database, OpenOptions};
use crate::models::{self, Caller, EnrolledNode, NodeMeta};

const STALE_AFTER: Duration = agentlink_core::ws::RELAY_STALE_AFTER;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

static STALE_OVERRIDE_MS: AtomicU64 = AtomicU64::new(0);

/// Shorten the stale-socket reaper for tests. `None` restores 75s.
///
/// The online bit still uses [`STALE_AFTER`]. This only changes how soon a
/// quiet node socket is closed so the daemon can observe the drop.
#[doc(hidden)]
pub fn set_stale_after_for_test(stale: Option<Duration>) {
    STALE_OVERRIDE_MS.store(
        stale.map(|d| d.as_millis() as u64).unwrap_or(0),
        Ordering::SeqCst,
    );
}

fn stale_after() -> Duration {
    let ms = STALE_OVERRIDE_MS.load(Ordering::SeqCst);
    if ms == 0 {
        STALE_AFTER
    } else {
        Duration::from_millis(ms)
    }
}

fn reap_period() -> Duration {
    (stale_after() / 3).clamp(Duration::from_millis(200), Duration::from_secs(5))
}

type RelaySocket =
    tokio_tungstenite::WebSocketStream<Replay<tokio_rustls::server::TlsStream<TcpStream>>>;

pub struct RelayConfig {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    /// When set, every forwarded envelope and binary frame is copied here.
    pub capture: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
    /// `postgres://` or `postgresql://`. Empty uses SQLite at `<data_dir>/relay.db`.
    pub database_url: Option<String>,
    /// Accept `Signup` envelopes. Off unless the operator opts in.
    pub allow_signup: bool,
    /// Create user `admin` with a random password when the user table is empty.
    pub bootstrap_admin: bool,
    /// Postgres schema for tests. Production leaves this empty.
    pub db_schema: Option<String>,
    /// CIDRs whose TCP connections may set X-Forwarded-For and X-Real-IP.
    /// A bare IP is one host. Empty means those headers are ignored.
    pub trust_proxy: Vec<String>,
    /// Print the admin token even when it was created by an earlier start.
    pub print_admin_token: bool,
    /// When set, overrides `AGENTLINK_LEGACY_ADMIN` / `_TTL_SECS` for this
    /// instance only (tests). Production leaves this `None`.
    pub legacy_admin_override: Option<(bool, Option<i64>)>,
}

pub struct RelayHandle {
    pub local_addr: SocketAddr,
    pub fingerprint: String,
    pub admin_token: String,
    /// True only on the start that generated the admin token.
    pub admin_token_created: bool,
    pub data_dir: PathBuf,
    pub bootstrap_password: Option<String>,
    shutdown: CancellationToken,
    kick: Arc<Mutex<Vec<CancellationToken>>>,
    hub: Arc<Hub>,
}

impl RelayHandle {
    pub async fn spawn(config: RelayConfig) -> Result<Self> {
        util::ensure_dir(&config.data_dir)?;
        let trust_proxy = parse_proxy_cidrs(&config.trust_proxy)?;
        let cert = agentlink_core::tls::RelayCert::load_or_create(&config.data_dir)?;
        let (legacy_enabled, legacy_ttl) = config
            .legacy_admin_override
            .unwrap_or_else(|| (legacy_admin_enabled(), legacy_admin_ttl()));
        let mint_legacy_admin = legacy_enabled && legacy_ttl.is_some_and(|ttl| ttl > 0);
        let opened = Database::open(OpenOptions {
            data_dir: &config.data_dir,
            database_url: config.database_url.as_deref(),
            schema: config.db_schema.as_deref(),
            bootstrap_admin: config.bootstrap_admin,
            mint_legacy_admin,
        })
        .await?;
        let admin_token = opened.db.admin_token().to_string();
        let admin_token_created = opened.admin_token_created;
        let admin_token_created_unix = opened.db.admin_token_created_unix();
        let bootstrap_password = opened.bootstrap_password;
        util::write_secret(
            &config.data_dir.join("fingerprint.txt"),
            cert.fingerprint.as_bytes(),
        )?;

        let listener = bind_listener(config.bind)?;
        let local_addr = listener.local_addr()?;
        util::write_secret(
            &config.data_dir.join("listen_addr.txt"),
            local_addr.to_string().as_bytes(),
        )?;

        let shutdown = CancellationToken::new();
        let kick = Arc::new(Mutex::new(Vec::new()));
        let hub = Arc::new(Hub {
            db: opened.db,
            online: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
            punch: Mutex::new(HashMap::new()),
            kick: kick.clone(),
            generation: AtomicU64::new(1),
            admins: Mutex::new(Vec::new()),
            clients: Mutex::new(Vec::new()),
            capture: config.capture.clone(),
            audit_path: config.data_dir.join("audit.jsonl"),
            data_dir: config.data_dir.clone(),
            admin_token: admin_token.clone(),
            admin_token_created_unix,
            legacy_admin_enabled: legacy_enabled,
            legacy_admin_ttl: legacy_ttl,
            view_tickets: Mutex::new(HashMap::new()),
            allow_signup: config.allow_signup,
            login_windows: Mutex::new(HashMap::new()),
            trust_proxy,
            connect_log: config.data_dir.join("connect.jsonl"),
        });
        let udp_hub = hub.clone();
        let udp_shutdown = shutdown.clone();
        match UdpSocket::bind(local_addr).await {
            Ok(udp) => {
                tokio::spawn(async move {
                    punch_loop(udp, udp_hub, udp_shutdown).await;
                });
            }
            Err(err) => {
                tracing::warn!(error = %err, "direct-path punch socket unavailable");
            }
        }
        let acceptor = TlsAcceptor::from(cert.server_config);
        let loop_shutdown = shutdown.clone();
        let accept_hub = hub.clone();
        tokio::spawn(async move {
            accept_loop(listener, acceptor, accept_hub, loop_shutdown).await;
        });
        let reap_hub = hub.clone();
        let reap_shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                let period = reap_period();
                tokio::select! {
                    _ = reap_shutdown.cancelled() => break,
                    _ = tokio::time::sleep(period) => reap_stale_nodes(&reap_hub),
                }
            }
        });

        Ok(RelayHandle {
            local_addr,
            fingerprint: cert.fingerprint,
            admin_token,
            admin_token_created,
            data_dir: config.data_dir,
            bootstrap_password,
            shutdown,
            kick,
            hub,
        })
    }
}

pub async fn serve(config: RelayConfig) -> Result<()> {
    RelayHandle::serve(config).await
}

impl RelayHandle {
    pub async fn serve(config: RelayConfig) -> Result<()> {
        let print_token = config.print_admin_token;
        let handle = Self::spawn(config).await?;
        print_banner(&handle, print_token);
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = wait_for_terminate() => {}
        }
        handle.going_away().await;
        Ok(())
    }

    /// Tell every peer to reconnect, then close the listener.
    ///
    /// Enrollment, grants, and the approval queue stay in the data directory.
    /// The next process binds the same port with `SO_REUSEPORT` or the socket
    /// systemd already handed it.
    pub async fn going_away(&self) {
        let notice = Envelope::GoingAway {
            retry_after_ms: 200,
        };
        let mut targets = Vec::new();
        if let Ok(online) = self.hub.online.lock() {
            targets.extend(online.values().map(|live| live.tx.clone()));
        }
        if let Ok(clients) = self.hub.clients.lock() {
            targets.extend(clients.iter().map(|client| client.tx.clone()));
        }
        for tx in targets {
            let _ = send_out(&tx, &notice).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(mut clients) = self.hub.clients.lock() {
            for client in clients.drain(..) {
                client.cancel.cancel();
            }
        }
        self.disconnect_nodes();
        self.shutdown.cancel();
    }

    /// Close every live node socket so daemons reconnect.
    ///
    /// Cancelling the kick token drops the write half even while a route
    /// still holds a sender clone. The daemon redials only once that close
    /// is visible on its read.
    pub fn disconnect_nodes(&self) {
        let tokens = match self.kick.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(poison) => std::mem::take(&mut *poison.into_inner()),
        };
        for token in tokens {
            token.cancel();
        }
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        // Close live sockets first. Cancelling only the accept loop leaves
        // node tasks running against the old hub, so daemons never redial
        // the replacement relay.
        self.disconnect_nodes();
        self.shutdown.cancel();
    }
}

struct LiveClient {
    tx: mpsc::Sender<Outbound>,
    cancel: CancellationToken,
}

fn bind_listener(addr: SocketAddr) -> Result<TcpListener> {
    if let Some(listener) = inherited_listener() {
        return Ok(listener);
    }
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        None,
    )
    .map_err(Error::Io)?;
    socket.set_reuse_address(true).map_err(Error::Io)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket.set_reuse_port(true).map_err(Error::Io)?;
    socket.set_nonblocking(true).map_err(Error::Io)?;
    socket.bind(&addr.into()).map_err(Error::Io)?;
    socket.listen(1024).map_err(Error::Io)?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener).map_err(Error::Io)
}

/// fd 3 when systemd socket activation started this process.
#[cfg(unix)]
#[allow(unsafe_code)]
fn inherited_listener() -> Option<TcpListener> {
    let fds: i32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if fds < 1 {
        return None;
    }
    let expected: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    if expected != std::process::id() {
        return None;
    }
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDNAMES");
    // SAFETY: systemd set LISTEN_PID to this process and LISTEN_FDS >= 1.
    // File descriptor 3 is the first listening socket. This process takes
    // exclusive ownership and must not close it anywhere else.
    unsafe {
        use std::os::fd::FromRawFd;
        let listener = std::net::TcpListener::from_raw_fd(3);
        listener.set_nonblocking(true).ok()?;
        TcpListener::from_std(listener).ok()
    }
}

#[cfg(not(unix))]
fn inherited_listener() -> Option<TcpListener> {
    None
}

async fn wait_for_terminate() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            terminate.recv().await;
        }
    }
    #[cfg(not(unix))]
    std::future::pending::<()>().await;
}

impl Hub {
    pub(crate) fn db(&self) -> &Database {
        &self.db
    }

    pub(crate) fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    pub(crate) fn audit_path(&self) -> &PathBuf {
        &self.audit_path
    }
}

pub(crate) struct Hub {
    db: Database,
    online: Mutex<HashMap<String, Online>>,
    routes: Mutex<HashMap<String, Route>>,
    punch: Mutex<HashMap<String, SocketAddr>>,
    kick: Arc<Mutex<Vec<CancellationToken>>>,
    generation: AtomicU64,
    admins: Mutex<Vec<LiveOperator>>,
    clients: Mutex<Vec<LiveClient>>,
    capture: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
    audit_path: PathBuf,
    data_dir: PathBuf,
    admin_token: String,
    admin_token_created_unix: i64,
    legacy_admin_enabled: bool,
    legacy_admin_ttl: Option<i64>,
    view_tickets: Mutex<HashMap<String, ViewTicketRecord>>,
    allow_signup: bool,
    login_windows: Mutex<HashMap<String, (i64, u32)>>,
    trust_proxy: Vec<ipnet::IpNet>,
    connect_log: PathBuf,
}

#[derive(Clone)]
struct LiveOperator {
    user: String,
    admin: bool,
    tx: mpsc::Sender<Outbound>,
}

#[derive(Clone)]
struct ViewTicketRecord {
    owner: String,
    client_id: String,
    node_id: String,
    grant: NodePolicy,
    expires_unix: i64,
    /// Set on the first websocket redeem. The bare ticket is then rejected.
    session: Option<String>,
}

/// A browser session minted for one agent grant. It is not an admin.
#[derive(Clone)]
struct ViewScope {
    node_id: String,
    grant: NodePolicy,
}

#[derive(Clone)]
struct Principal {
    admin: bool,
    /// Logged-in user session, as opposed to a legacy admin token or an agent key.
    operator: bool,
    legacy: bool,
    user: String,
    /// Kept so an operator session still records whether the account is an admin.
    #[allow(dead_code)]
    role: String,
    device_id: String,
    access_hash: String,
    client_id: String,
    name: String,
    view: Option<ViewScope>,
    /// Dashboard cookie session. Files and a PTY only; no enrollment or policy.
    web: bool,
    /// Raw `agentlink_session` cookie, so logout closes the socket.
    web_token: String,
    /// Returned once, on the redeem that binds a view ticket.
    view_session: Option<String>,
}

fn caller_of(principal: &Principal) -> Caller {
    Caller {
        user: if principal.user.is_empty() {
            "admin".into()
        } else {
            principal.user.clone()
        },
        admin: principal.admin,
    }
}

fn stamp_actor(
    principal: Option<&Principal>,
    user: &mut Option<String>,
    device_id: &mut Option<String>,
) {
    let Some(principal) = principal else {
        return;
    };
    if !principal.user.is_empty() {
        *user = Some(principal.user.clone());
    }
    if !principal.device_id.is_empty() {
        *device_id = Some(principal.device_id.clone());
    }
}

fn legacy_admin(name: String, client_id: String) -> Principal {
    Principal {
        admin: true,
        operator: false,
        legacy: true,
        user: "admin".into(),
        role: "admin".into(),
        device_id: String::new(),
        access_hash: String::new(),
        client_id,
        name,
        view: None,
        web: false,
        web_token: String::new(),
        view_session: None,
    }
}

struct Route {
    origin_tx: mpsc::Sender<Outbound>,
    target_tx: mpsc::Sender<Outbound>,
    /// `None` when the origin is an admin client.
    origin_node: Option<String>,
    #[allow(dead_code)]
    target_node: String,
}

struct Online {
    generation: u64,
    tx: mpsc::Sender<Outbound>,
    last_seen: Instant,
    cancel: CancellationToken,
}

struct Router {
    audit_path: PathBuf,
    admin_token: String,
    admin_token_created_unix: i64,
    legacy_admin_enabled: bool,
    legacy_admin_ttl: Option<i64>,
}

impl Callback for Router {
    fn on_request(
        self,
        request: &Request,
        response: Response,
    ) -> std::result::Result<Response, ErrorResponse> {
        match request.uri().path() {
            WS_PATH | WS_WEBRTC_PATH | WS_WEB_PATH => Ok(response),
            "/audit" => Err(html_response(audit_page())),
            "/audit/records" => {
                if !self.authorized(request) {
                    return Err(plain(401, "admin token required"));
                }
                let records = read_audit_values(&self.audit_path);
                let body = serde_json::to_string(&records).unwrap_or_else(|_| "[]".into());
                Err(Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Some(body))
                    .expect("static response"))
            }
            _ => Err(plain(404, "not found")),
        }
    }
}

impl Router {
    fn authorized(&self, request: &Request) -> bool {
        if let Some(header) = request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
        {
            if let Some(token) = header
                .strip_prefix("Bearer ")
                .or_else(|| header.strip_prefix("bearer "))
            {
                if self.accept_legacy(token.trim()) {
                    return true;
                }
            }
        }
        let Some(query) = request.uri().query() else {
            return false;
        };
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("token=") {
                if self.accept_legacy(value) {
                    return true;
                }
            }
        }
        false
    }

    fn accept_legacy(&self, presented: &str) -> bool {
        if presented.is_empty() || !util::ct_eq(presented, &self.admin_token) {
            return false;
        }
        match legacy_gate_at(self.legacy_admin_enabled, self.legacy_admin_ttl, self.admin_token_created_unix, unix_now()) {
            Ok(()) => {
                note_legacy_use(&self.audit_path, true, "");
                true
            }
            Err(reason) => {
                note_legacy_use(&self.audit_path, false, reason);
                false
            }
        }
    }
}

fn print_banner(handle: &RelayHandle, force_token: bool) {
    let mut out = std::io::stderr();
    let _ = writeln!(out, "agentlink relay");
    let _ = writeln!(out, "  listen:       {}", handle.local_addr);
    let _ = writeln!(out, "  fingerprint:  {}", handle.fingerprint);
    if handle.admin_token.is_empty() {
        let _ = writeln!(
            out,
            "  admin token:  not issued (legacy admin is off; set AGENTLINK_LEGACY_ADMIN=1 and AGENTLINK_LEGACY_ADMIN_TTL_SECS to mint one)"
        );
    } else if force_token || handle.admin_token_created {
        let _ = writeln!(out, "  admin token:  {}", handle.admin_token);
    } else {
        let _ = writeln!(
            out,
            "  admin token:  {}",
            handle.data_dir.join("admin.token").display()
        );
    }
    let _ = writeln!(out, "  data dir:     {}", handle.data_dir.display());
    if let Some(password) = &handle.bootstrap_password {
        let _ = writeln!(out, "  bootstrap:    user admin password {password}");
        let _ = writeln!(
            out,
            "  change it with `agentlink relay user passwd admin`. That deletes bootstrap.password."
        );
        let _ = writeln!(
            out,
            "  if the file is still there, delete it. Do not leave the password on disk."
        );
    }
    if force_token || handle.admin_token_created {
        let _ = writeln!(
            out,
            "  prefer an account and TOTP. admin.token is disabled by default. To enable automation access, set AGENTLINK_LEGACY_ADMIN=1 and AGENTLINK_LEGACY_ADMIN_TTL_SECS."
        );
    }
    let _ = writeln!(
        out,
        "nodes enroll with a pairing token from `agentlink pair`."
    );
    let _ = out.flush();
}

fn parse_proxy_cidrs(values: &[String]) -> Result<Vec<ipnet::IpNet>> {
    values.iter().map(|value| parse_proxy_cidr(value)).collect()
}

fn parse_proxy_cidr(value: &str) -> Result<ipnet::IpNet> {
    let value = value.trim();
    if let Ok(net) = value.parse::<ipnet::IpNet>() {
        return Ok(net);
    }
    let ip: IpAddr = value.parse().map_err(|_| {
        Error::Message(format!(
            "--trust-proxy `{value}` is not an IP address or CIDR"
        ))
    })?;
    Ok(ipnet::IpNet::from(ip))
}

/// Client address recorded for audit. Forwarded headers count only when the
/// TCP peer is inside `--trust-proxy`. The walk starts at the right of
/// X-Forwarded-For and skips addresses that are themselves trusted proxies.
fn resolve_audit_peer(tcp: SocketAddr, head: &str, trust: &[ipnet::IpNet]) -> IpAddr {
    if trust.is_empty() || !ip_trusted(tcp.ip(), trust) {
        return tcp.ip();
    }
    let forwarded = header_values(head, "x-forwarded-for");
    let mut chain = Vec::new();
    for value in &forwarded {
        for part in value.split(',') {
            if let Some(ip) = parse_forwarded_ip(part) {
                chain.push(ip);
            }
        }
    }
    if !chain.is_empty() {
        for ip in chain.iter().rev() {
            if !ip_trusted(*ip, trust) {
                return *ip;
            }
        }
        return chain[0];
    }
    for value in header_values(head, "x-real-ip") {
        if let Some(ip) = parse_forwarded_ip(&value) {
            if !ip_trusted(ip, trust) {
                return ip;
            }
        }
    }
    tcp.ip()
}

fn ip_trusted(ip: IpAddr, trust: &[ipnet::IpNet]) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    };
    trust.iter().any(|net| net.contains(&ip))
}

fn header_values(head: &str, name: &str) -> Vec<String> {
    head.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.trim().eq_ignore_ascii_case(name) {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .collect()
}

fn parse_forwarded_ip(token: &str) -> Option<IpAddr> {
    let token = token.trim().trim_matches('"');
    if token.is_empty() {
        return None;
    }
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(addr) = token.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    if let Some(rest) = token.strip_prefix('[') {
        let host = rest.split_once(']')?.0;
        return host.parse().ok();
    }
    None
}

fn record_connect(
    path: &std::path::Path,
    role: &str,
    id: &str,
    name: &str,
    tcp: SocketAddr,
    peer: IpAddr,
) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let line = serde_json::json!({
        "ts": agentlink_core::util::unix_now(),
        "role": role,
        "id": id,
        "name": name,
        "peer": peer.to_string(),
        "tcp_peer": tcp.to_string(),
    });
    let _ = writeln!(file, "{line}");
}

fn plain(status: u16, body: &str) -> ErrorResponse {
    Response::builder()
        .status(status)
        .body(Some(body.to_string()))
        .expect("static response")
}

fn html_response(body: String) -> ErrorResponse {
    Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .body(Some(body))
        .expect("static response")
}

async fn read_http_head<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let n = timeout(HANDSHAKE_TIMEOUT, stream.read(&mut tmp))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::Ws(e.to_string()))?;
        if n == 0 {
            return Err(Error::Ws("connection closed".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > 64 * 1024 {
            return Err(Error::Ws("http headers too large".into()));
        }
    }
}

async fn serve_plain_http<S>(stream: &mut S, head: &[u8], hub: &Hub, peer: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    if length > 64 * 1024 {
        let body = b"body too large";
        let header = format!(
            "HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).await.ok();
        stream.write_all(body).await.ok();
        return Ok(());
    }
    let header_end = head
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(head.len());
    let mut body_bytes = head[header_end..].to_vec();
    if body_bytes.len() < length {
        let start = body_bytes.len();
        body_bytes.resize(length, 0);
        stream
            .read_exact(&mut body_bytes[start..])
            .await
            .map_err(|e| Error::Ws(e.to_string()))?;
    } else {
        body_bytes.truncate(length);
    }
    if let Some(outcome) =
        crate::web::handle(hub, method, path, &headers, &body_bytes, peer).await?
    {
        match outcome {
            crate::web::WebOutcome::Reply(reply) => {
                stream
                    .write_all(&reply.encode_for_method(method))
                    .await
                    .map_err(|e| Error::Ws(e.to_string()))?;
                stream.flush().await.ok();
            }
            crate::web::WebOutcome::Events { user, admin } => {
                let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
                stream
                    .write_all(header.as_bytes())
                    .await
                    .map_err(|e| Error::Ws(e.to_string()))?;
                for _ in 0..12 {
                    let payload = crate::web::dashboard(hub, &user, admin).await?;
                    let event = format!("data: {payload}\n\n");
                    stream
                        .write_all(event.as_bytes())
                        .await
                        .map_err(|e| Error::Ws(e.to_string()))?;
                    stream.flush().await.ok();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        return Ok(());
    }
    let web_session = crate::web::session_from(hub, &headers).await?;
    let head = method.eq_ignore_ascii_case("HEAD");
    let method_eff = if head { "GET" } else { method };
    let (status, reason, content_type, body) = match (method_eff, path) {
        ("GET", "/audit") => (200, "OK", "text/html; charset=utf-8", audit_page()),
        ("GET", WS_WEBRTC_PATH) => (
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            "webrtc signaling is a websocket".into(),
        ),
        ("GET", "/audit/records") => {
            let records = read_audit_values(&hub.audit_path);
            if http_authorized(hub, &headers, query) {
                (
                    200,
                    "OK",
                    "application/json",
                    serde_json::to_string(&records).unwrap_or_else(|_| "[]".into()),
                )
            } else if let Some(session) = web_session.as_ref() {
                let visible: Vec<_> = if session.role == "admin" {
                    records
                } else {
                    let user = session.user.as_str();
                    records
                        .into_iter()
                        .filter(|row| {
                            row.get("user").and_then(|value| value.as_str()) == Some(user)
                        })
                        .collect()
                };
                (
                    200,
                    "OK",
                    "application/json",
                    serde_json::to_string(&visible).unwrap_or_else(|_| "[]".into()),
                )
            } else {
                (
                    401,
                    "Unauthorized",
                    "text/plain; charset=utf-8",
                    "admin token required".into(),
                )
            }
        }
        _ => (
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            "not found".into(),
        ),
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| Error::Ws(e.to_string()))?;
    if !head {
        stream
            .write_all(body.as_bytes())
            .await
            .map_err(|e| Error::Ws(e.to_string()))?;
    }
    stream.flush().await.ok();
    Ok(())
}

fn http_authorized(hub: &Hub, headers: &[(String, String)], query: &str) -> bool {
    if let Some((_, value)) = headers.iter().find(|(name, _)| name == "authorization") {
        if let Some(got) = value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
        {
            if presented_legacy(hub, got.trim()) {
                return true;
            }
        }
    }
    query.split('&').any(|pair| {
        pair.strip_prefix("token=")
            .map(|value| presented_legacy(hub, value))
            .unwrap_or(false)
    })
}

fn presented_legacy(hub: &Hub, presented: &str) -> bool {
    if presented.is_empty() || !util::ct_eq(presented, &hub.admin_token) {
        return false;
    }
    match legacy_gate_at(hub.legacy_admin_enabled, hub.legacy_admin_ttl, hub.admin_token_created_unix, unix_now()) {
        Ok(()) => {
            note_legacy_use(&hub.audit_path, true, "");
            true
        }
        Err(reason) => {
            note_legacy_use(&hub.audit_path, false, reason);
            false
        }
    }
}

struct Replay<S> {
    buffered: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.buffered.len() {
            let rest = &self.buffered[self.pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    hub: Arc<Hub>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((tcp, peer)) = accepted else { continue };
                tcp.set_nodelay(true).ok();
                agentlink_core::ws::arm_tcp_liveness(&tcp);
                let acceptor = acceptor.clone();
                let hub = hub.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(tcp, peer, acceptor, hub).await {
                        tracing::debug!(%peer, error = %err, "connection closed");
                    }
                });
            }
        }
    }
}

async fn handle_connection(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    hub: Arc<Hub>,
) -> Result<()> {
    let mut tls = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Tls(e.to_string()))?;
    let head = read_http_head(&mut tls).await?;
    if let Some(response) = std::str::from_utf8(&head).ok().and_then(|request| {
        crate::view::response_for(request).or_else(|| crate::operate::response_for(request))
    }) {
        tls.write_all(&response).await?;
        let _ = tls.shutdown().await;
        return Ok(());
    }
    let head_text = String::from_utf8_lossy(&head).into_owned();
    let audit_ip = resolve_audit_peer(peer, &head_text, &hub.trust_proxy);
    let preview = head_text.to_ascii_lowercase();
    let (_, path, _) = request_line(&head_text);
    if path == WS_WEB_PATH && preview.contains("upgrade: websocket") {
        if !rate_allow(&hub, "ws", audit_ip, 300, 60) {
            return reject_upgrade(&mut tls, 429, "Too Many Requests", "too many connections")
                .await;
        }
        return serve_web_socket(tls, head, &head_text, hub, peer, audit_ip).await;
    }
    if !preview.contains("upgrade: websocket") {
        return serve_plain_http(&mut tls, &head, &hub, peer).await;
    }
    if !rate_allow(&hub, "ws", audit_ip, 300, 60) {
        return reject_upgrade(&mut tls, 429, "Too Many Requests", "too many connections").await;
    }
    let stream = Replay {
        buffered: head,
        pos: 0,
        inner: tls,
    };
    let mut ws = timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::accept_hdr_async_with_config(
            stream,
            Router {
                audit_path: hub.audit_path.clone(),
                admin_token: hub.admin_token.clone(),
                admin_token_created_unix: hub.admin_token_created_unix,
                legacy_admin_enabled: hub.legacy_admin_enabled,
                legacy_admin_ttl: hub.legacy_admin_ttl,
            },
            Some(ws::ws_config()),
        ),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Ws(e.to_string()))?;

    let hello = timeout(HANDSHAKE_TIMEOUT, next_env(&mut ws))
        .await
        .map_err(|_| Error::Timeout)??;
    if matches!(
        hello,
        Envelope::Login { .. } | Envelope::RefreshSession { .. } | Envelope::Signup { .. }
    ) {
        return session_preamble(ws, &hub, peer, audit_ip, hello).await;
    }
    let Envelope::Hello {
        role,
        protocol,
        token,
        node_id,
        public_key,
        name,
        pairing_token,
        hostname,
        os,
        arch,
        version,
        ceiling,
        has_display,
    } = hello
    else {
        send_env(
            &mut ws,
            &Envelope::HelloErr {
                message: "expected hello".into(),
                fatal: true,
            },
        )
        .await?;
        return Err(Error::Protocol("expected hello".into()));
    };
    if protocol != PROTOCOL_VERSION {
        send_env(
            &mut ws,
            &Envelope::HelloErr {
                message: format!("protocol {protocol} is not supported"),
                fatal: true,
            },
        )
        .await?;
        return Err(Error::Protocol("protocol mismatch".into()));
    }

    match role {
        Role::Client => {
            let principal = match client_principal(&mut ws, &hub, token, public_key, name).await {
                Ok(principal) => principal,
                Err(err) => return Err(err),
            };
            send_env(
                &mut ws,
                &Envelope::HelloOk {
                    node_id: None,
                    policy: None,
                    protocol: PROTOCOL_VERSION,
                    heartbeat_secs: 20,
                    view_session: principal.view_session.clone(),
                },
            )
            .await?;
            tracing::info!(peer = %audit_ip, tcp_peer = %peer, admin = principal.admin, client = %principal.client_id, name = %principal.name, "client connected");
            record_connect(
                &hub.connect_log,
                "client",
                &principal.client_id,
                &principal.name,
                peer,
                audit_ip,
            );
            client_loop(ws, hub, peer, audit_ip, principal).await
        }
        Role::Node => {
            node_handshake(
                ws,
                hub,
                peer,
                audit_ip,
                NodeHello {
                    node_id,
                    public_key,
                    name,
                    pairing_token,
                    hostname,
                    os,
                    arch,
                    version,
                    ceiling,
                    has_display,
                },
            )
            .await
        }
    }
}

struct NodeHello {
    node_id: Option<String>,
    public_key: Option<String>,
    name: Option<String>,
    pairing_token: Option<String>,
    hostname: Option<String>,
    os: Option<String>,
    arch: Option<String>,
    version: Option<String>,
    ceiling: Option<NodePolicy>,
    has_display: Option<bool>,
}

async fn node_handshake(
    mut ws: RelaySocket,
    hub: Arc<Hub>,
    peer: SocketAddr,
    audit_ip: IpAddr,
    hello: NodeHello,
) -> Result<()> {
    let public_key = hello
        .public_key
        .ok_or_else(|| Error::Auth("node hello is missing a public key".into()))?
        .to_ascii_lowercase();
    if let Some(id) = &hello.node_id {
        if id.to_ascii_lowercase() != public_key {
            send_env(
                &mut ws,
                &Envelope::HelloErr {
                    message: "node id does not match public key".into(),
                    fatal: true,
                },
            )
            .await?;
            return Err(Error::Auth("node id mismatch".into()));
        }
    }
    let nonce = util::random_hex(32);
    send_env(
        &mut ws,
        &Envelope::Challenge {
            nonce: nonce.clone(),
        },
    )
    .await?;
    let auth = timeout(HANDSHAKE_TIMEOUT, next_env(&mut ws))
        .await
        .map_err(|_| Error::Timeout)??;
    let signature = match auth {
        Envelope::Authenticate { signature } => signature,
        Envelope::HelloErr { message, .. } => return Err(Error::Auth(message)),
        _ => {
            send_env(
                &mut ws,
                &Envelope::HelloErr {
                    message: "expected authenticate".into(),
                    fatal: true,
                },
            )
            .await?;
            return Err(Error::Protocol("expected authenticate".into()));
        }
    };
    if let Err(err) = agentlink_core::identity::verify_nonce(&public_key, &nonce, &signature) {
        send_env(
            &mut ws,
            &Envelope::HelloErr {
                message: err.to_string(),
                fatal: true,
            },
        )
        .await?;
        return Err(err);
    }

    let meta = NodeMeta {
        name: hello.name.unwrap_or_default(),
        hostname: hello.hostname.unwrap_or_default(),
        os: hello.os.unwrap_or_else(|| "unknown".into()),
        arch: hello.arch.unwrap_or_else(|| "unknown".into()),
        version: hello.version.unwrap_or_default(),
        ceiling: hello.ceiling.unwrap_or_else(NodePolicy::phase1_ceiling),
        has_display: hello.has_display,
    };
    let enrolled = hub
        .db
        .enroll(hello.pairing_token.as_deref(), &public_key, meta)
        .await;
    let enrolled = match enrolled {
        Ok(node) => node,
        Err(err) => {
            let fatal = err.is_fatal() || matches!(err, Error::Auth(_));
            send_env(
                &mut ws,
                &Envelope::HelloErr {
                    message: err.to_string(),
                    fatal,
                },
            )
            .await?;
            return Err(err);
        }
    };
    send_env(
        &mut ws,
        &Envelope::HelloOk {
            node_id: Some(enrolled.id.clone()),
            policy: Some(enrolled.effective()),
            protocol: PROTOCOL_VERSION,
            heartbeat_secs: 20,
            view_session: None,
        },
    )
    .await?;
    let pushed = hub.db.audit_for_node(&enrolled.id).await?;
    if let Some(toml) = pushed {
        send_env(&mut ws, &Envelope::AuditPolicyPush { toml }).await?;
    }
    tracing::info!(peer = %audit_ip, tcp_peer = %peer, node = %enrolled.name, id = %enrolled.id, "node connected");
    record_connect(
        &hub.connect_log,
        "node",
        &enrolled.id,
        &enrolled.name,
        peer,
        audit_ip,
    );
    node_loop(ws, hub, enrolled.id).await
}

fn request_line(head: &str) -> (String, String, String) {
    let request = head.split("\r\n").next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    (method, path.to_string(), query.to_string())
}

fn header_map(head: &str) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for line in head.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    headers
}

fn query_value(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn reject_upgrade<S>(stream: &mut S, status: u16, reason: &str, message: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = message.as_bytes();
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| Error::Ws(e.to_string()))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| Error::Ws(e.to_string()))?;
    stream.flush().await.ok();
    let _ = stream.shutdown().await;
    Ok(())
}

/// Dashboard socket. The browser has no device key; the session cookie is the
/// credential, and the CSRF value travels in the query because a browser
/// WebSocket cannot set `X-CSRF-Token`.
async fn serve_web_socket(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    head: Vec<u8>,
    head_text: &str,
    hub: Arc<Hub>,
    peer: SocketAddr,
    audit_ip: IpAddr,
) -> Result<()> {
    let (method, _, query) = request_line(head_text);
    if method != "GET" {
        return reject_upgrade(&mut tls, 405, "Method Not Allowed", "use GET").await;
    }
    let headers = header_map(head_text);
    let Some(session) = crate::web::session_from(&hub, &headers).await? else {
        return reject_upgrade(&mut tls, 401, "Unauthorized", "login required").await;
    };
    let header_csrf = headers
        .iter()
        .find(|(name, _)| name == "x-csrf-token")
        .map(|(_, value)| value.as_str())
        .unwrap_or("");
    let query_csrf = query_value(&query, "csrf").unwrap_or_default();
    let presented = if !header_csrf.is_empty() {
        header_csrf
    } else {
        query_csrf.as_str()
    };
    if presented.is_empty() || !util::ct_eq(presented, &session.csrf) {
        return reject_upgrade(&mut tls, 403, "Forbidden", "csrf token rejected").await;
    }
    let Some(token) = crate::web::session_cookie(&headers) else {
        return reject_upgrade(&mut tls, 401, "Unauthorized", "login required").await;
    };
    let stream = Replay {
        buffered: head,
        pos: 0,
        inner: tls,
    };
    let mut ws = timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::accept_hdr_async_with_config(
            stream,
            Router {
                audit_path: hub.audit_path.clone(),
                admin_token: hub.admin_token.clone(),
                admin_token_created_unix: hub.admin_token_created_unix,
                legacy_admin_enabled: hub.legacy_admin_enabled,
                legacy_admin_ttl: hub.legacy_admin_ttl,
            },
            Some(ws::ws_config()),
        ),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Ws(e.to_string()))?;
    let principal = web_principal(&session, &token);
    send_env(
        &mut ws,
        &Envelope::HelloOk {
            node_id: None,
            policy: None,
            protocol: PROTOCOL_VERSION,
            heartbeat_secs: 20,
            view_session: None,
        },
    )
    .await?;
    tracing::info!(peer = %audit_ip, tcp_peer = %peer, user = %principal.user, "web dashboard connected");
    record_connect(
        &hub.connect_log,
        "web",
        &principal.client_id,
        &principal.name,
        peer,
        audit_ip,
    );
    client_loop(ws, hub, peer, audit_ip, principal).await
}

fn web_principal(session: &crate::models::WebSession, token: &str) -> Principal {
    let id = format!("web:{}", session.user);
    Principal {
        admin: session.role == "admin",
        operator: true,
        legacy: false,
        user: session.user.clone(),
        role: session.role.clone(),
        device_id: id.clone(),
        access_hash: String::new(),
        client_id: id,
        name: session.user.clone(),
        view: None,
        web: true,
        web_token: token.to_string(),
        view_session: None,
    }
}

fn web_message_allowed(env: &Envelope) -> std::result::Result<(), String> {
    match env {
        Envelope::Ping | Envelope::Cancel { .. } => Ok(()),
        Envelope::Invoke { .. } => Err(
            "browser control is disabled: that path is plaintext at the relay, and a web login is not a node-local grant"
                .into(),
        ),
        _ => Err(
            "browser control is disabled: that path is plaintext at the relay, and a web login is not a node-local grant"
                .into(),
        ),
    }
}

async fn client_principal(
    ws: &mut RelaySocket,
    hub: &Hub,
    token: Option<String>,
    public_key: Option<String>,
    name: Option<String>,
) -> Result<Principal> {
    let presented = token.unwrap_or_default();
    if let Some(ticket_id) = presented.strip_prefix("view.") {
        return redeem_view_ticket(ws, hub, ticket_id).await;
    }
    if !presented.is_empty() {
        let admin = hub.db.admin_token().to_string();
        if util::ct_eq(&presented, &admin) {
            return match legacy_gate_at(hub.legacy_admin_enabled, hub.legacy_admin_ttl, hub.admin_token_created_unix, unix_now()) {
                Ok(()) => {
                    note_legacy_use(&hub.audit_path, true, "");
                    Ok(legacy_admin(
                        name.unwrap_or_else(|| "admin".into()),
                        public_key.unwrap_or_default().to_ascii_lowercase(),
                    ))
                }
                Err(reason) => {
                    note_legacy_use(&hub.audit_path, false, reason);
                    send_env(
                        ws,
                        &Envelope::HelloErr {
                            message: reason.into(),
                            fatal: true,
                        },
                    )
                    .await?;
                    Err(Error::Auth(reason.into()))
                }
            };
        }
        if let Some(session) = hub.db.access_session(&presented).await? {
            return access_hello(ws, hub, session, public_key, &presented).await;
        }
        let message = if presented.starts_with("atk.") {
            "session expired or revoked"
        } else {
            "invalid admin token"
        };
        send_env(
            ws,
            &Envelope::HelloErr {
                message: message.into(),
                fatal: true,
            },
        )
        .await?;
        return Err(Error::Auth(message.into()));
    }
    let Some(public_key) = public_key else {
        send_env(
            ws,
            &Envelope::HelloErr {
                message: "invalid admin token".into(),
                fatal: true,
            },
        )
        .await?;
        return Err(Error::Auth("invalid admin token".into()));
    };
    let public_key = public_key.to_ascii_lowercase();
    let nonce = util::random_hex(32);
    send_env(
        ws,
        &Envelope::Challenge {
            nonce: nonce.clone(),
        },
    )
    .await?;
    let auth = timeout(HANDSHAKE_TIMEOUT, next_env(ws))
        .await
        .map_err(|_| Error::Timeout)??;
    let signature = match auth {
        Envelope::Authenticate { signature } => signature,
        Envelope::HelloErr { message, .. } => return Err(Error::Auth(message)),
        _ => {
            send_env(
                ws,
                &Envelope::HelloErr {
                    message: "expected authenticate".into(),
                    fatal: true,
                },
            )
            .await?;
            return Err(Error::Protocol("expected authenticate".into()));
        }
    };
    if let Err(err) = agentlink_core::identity::verify_nonce(&public_key, &nonce, &signature) {
        send_env(
            ws,
            &Envelope::HelloErr {
                message: err.to_string(),
                fatal: true,
            },
        )
        .await?;
        return Err(err);
    }
    let record = match hub.db.client_record(&public_key).await? {
        Some(record) => Ok(record),
        None => Err(Error::NotFound(format!("client '{public_key}'"))),
    };
    let record = match record {
        Ok(record) if !record.revoked => record,
        Ok(_) => {
            send_env(
                ws,
                &Envelope::HelloErr {
                    message: "client is revoked".into(),
                    fatal: true,
                },
            )
            .await?;
            return Err(Error::Auth("client is revoked".into()));
        }
        Err(err) => {
            send_env(
                ws,
                &Envelope::HelloErr {
                    message: err.to_string(),
                    fatal: true,
                },
            )
            .await?;
            return Err(Error::Auth("client is not registered".into()));
        }
    };
    Ok(Principal {
        admin: false,
        operator: false,
        legacy: false,
        user: record.owner.clone(),
        role: "agent".into(),
        device_id: String::new(),
        access_hash: String::new(),
        client_id: record.id,
        name: record.name,
        view: None,
        web: false,
        web_token: String::new(),
        view_session: None,
    })
}

fn split_view_token(ticket_id: &str) -> (&str, Option<&str>) {
    match ticket_id.split_once('.') {
        Some((id, session)) if !id.is_empty() && !session.is_empty() => (id, Some(session)),
        _ => (ticket_id, None),
    }
}

/// First bare redeem binds a session and returns it. A second bare redeem fails.
/// The bound session can reconnect until the ticket expires.
#[cfg(test)]
fn bind_view_ticket(
    record: &mut ViewTicketRecord,
    presented_session: Option<&str>,
    now: i64,
    new_session: &str,
) -> std::result::Result<Option<String>, &'static str> {
    if record.expires_unix <= now {
        return Err("invalid view ticket");
    }
    match (&record.session, presented_session) {
        (Some(bound), Some(got)) if util::ct_eq(bound, got) => Ok(None),
        (Some(_), _) => Err("view ticket already used"),
        (None, Some(_)) => Err("invalid view ticket"),
        (None, None) => {
            record.session = Some(new_session.to_string());
            Ok(Some(new_session.to_string()))
        }
    }
}

/// ICE mint does not consume the ticket. After it is bound, only the session works.
fn ticket_allows_ice(record: &ViewTicketRecord, presented_session: Option<&str>, now: i64) -> bool {
    if record.expires_unix <= now {
        return false;
    }
    match &record.session {
        None => presented_session.is_none(),
        Some(bound) => presented_session
            .map(|got| util::ct_eq(bound, got))
            .unwrap_or(false),
    }
}

/// Fields `/api/view-ticket` may show the caller. They follow the clipped
/// grant, not the `control` bit that was requested.
#[cfg(test)]
pub(crate) fn web_ticket_fields(grant: &NodePolicy) -> (bool, &'static str) {
    let control = grant.allows_remote_control();
    let access = if control {
        "remote-control"
    } else if grant.allows_remote_view() {
        "remote-view"
    } else {
        "none"
    };
    (control, access)
}

/// Shareable and desktop links are view-only unless `control` is explicit and
/// the account grant already includes remote control. Write and exec stay off.
#[cfg(test)]
fn clip_desktop_grant(access: NodePolicy, control: bool) -> NodePolicy {
    if !access.allows_remote_view() {
        return NodePolicy::none();
    }
    let control = control && access.allows_remote_control();
    NodePolicy {
        allow_read: false,
        allow_write: false,
        allow_exec: false,
        allow_desktop: control,
        allow_desktop_stream: true,
        allow_remote_view: true,
        allow_remote_control: control,
    }
}

async fn redeem_view_ticket(ws: &mut RelaySocket, hub: &Hub, ticket_id: &str) -> Result<Principal> {
    let _ = (hub, ticket_id);
    let message = "browser view is not available; use a sealed client with a node-local grant";
    send_env(
        ws,
        &Envelope::HelloErr {
            message: message.into(),
            fatal: true,
        },
    )
    .await?;
    return Err(Error::Auth(message.into()));
}


/// Refuse minting a desktop viewer ticket when the node last reported no
/// graphical session. `None` (never reported) still allows the ticket — the
/// node/desktop layer will fail the stream if there really is no display.
#[cfg(test)]
fn headless_view_error(node_name: &str, has_display: Option<bool>) -> Option<String> {
    if has_display == Some(false) {
        Some(format!(
            "{node_name} is headless (no desktop session). Use shell or files instead of view."
        ))
    } else {
        None
    }
}

#[cfg(test)]
fn offline_view_error(node_name: &str, online: bool) -> Option<String> {
    if !online {
        Some(format!("node offline: {node_name}"))
    } else {
        None
    }
}

async fn issue_view_ticket(
    hub: &Hub,
    tx: &mpsc::Sender<Outbound>,
    principal: &Principal,
    request_id: String,
    node_id: String,
    control: bool,
    audit_ip: IpAddr,
) -> Result<()> {
    let _ = (hub, principal, node_id, control, audit_ip);
    return send_out(
        tx,
        &Envelope::result_err(
            request_id,
            "browser view is not available; use a sealed client with a node-local grant",
        ),
    )
    .await;
}


pub(crate) fn online_flags(hub: &Hub) -> HashMap<String, bool> {
    let Ok(online) = lock_online(hub) else {
        return HashMap::new();
    };
    online
        .iter()
        .map(|(id, live)| (id.clone(), live.last_seen.elapsed() < STALE_AFTER))
        .collect()
}

pub(crate) struct IssuedWebTicket {
    pub ticket: String,
    pub node_id: String,
    pub expires_unix: i64,
    /// `clip_desktop_grant` result, not the requested bit.
    pub control: bool,
    pub access: &'static str,
}

pub(crate) async fn issue_web_ticket(
    hub: &Hub,
    user: &str,
    admin: bool,
    node_id: &str,
    control: bool,
) -> Result<IssuedWebTicket> {
    let _ = (hub, user, admin, node_id, control);
    return Err(Error::Message(
        "browser view is not available; use a sealed client with a node-local grant".into(),
    ));
}


pub(crate) fn revoke_view_tickets(
    hub: &Hub,
    user: &str,
    admin: bool,
    ticket: Option<&str>,
    node: Option<&str>,
) -> Result<u32> {
    if ticket.is_none() && node.is_none() {
        return Err(Error::Message("ticket or node is required".into()));
    }
    let mut tickets = hub
        .view_tickets
        .lock()
        .map_err(|_| Error::Message("view tickets poisoned".into()))?;
    let before = tickets.len();
    tickets.retain(|id, record| {
        let ticket_hit = match ticket {
            Some(wanted) => {
                let wanted = wanted.trim().trim_start_matches("view.");
                let wanted = wanted.split_once('.').map(|(id, _)| id).unwrap_or(wanted);
                wanted == id
            }
            None => true,
        };
        let node_hit = match node {
            Some(wanted) => wanted == record.node_id,
            None => true,
        };
        let owned = admin || record.owner == user;
        !(ticket_hit && node_hit && owned)
    });
    Ok((before - tickets.len()) as u32)
}

/// Subject for a TURN REST username. Does not consume the ticket.
pub(crate) fn turn_subject_for_ticket(hub: &Hub, presented: &str) -> Result<String> {
    let rest = presented.trim().trim_start_matches("view.");
    let (id, session) = split_view_token(rest);
    let mut tickets = hub
        .view_tickets
        .lock()
        .map_err(|_| Error::Message("view tickets poisoned".into()))?;
    let now = unix_now();
    tickets.retain(|_, ticket| ticket.expires_unix > now);
    let Some(record) = tickets.get(id) else {
        return Err(Error::Auth("invalid view ticket".into()));
    };
    if !ticket_allows_ice(record, session, now) {
        return Err(Error::Auth("invalid view ticket".into()));
    }
    Ok(format!("view:{}", record.owner))
}

/// Browser view tickets are not a control channel. Every op is refused.
fn view_ticket_may_invoke(op: &Op) -> bool {
    let _ = op;
    false
}

fn stamp_stream_flags(op: Op, grant: &NodePolicy) -> Op {
    let Op::Extension { name, mut payload } = op else {
        return op;
    };
    if name == PHASE3_WEBRTC_SIGNAL {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "_allow_view".into(),
                serde_json::json!(grant.allows_remote_view()),
            );
            obj.insert(
                "_allow_control".into(),
                serde_json::json!(grant.allows_remote_control()),
            );
        }
    }
    Op::Extension { name, payload }
}

async fn client_loop(
    ws: RelaySocket,
    hub: Arc<Hub>,
    peer: SocketAddr,
    audit_ip: IpAddr,
    principal: Principal,
) -> Result<()> {
    let (sink, mut stream) = ws.split();
    let (tx, rx) = mpsc::channel(64);
    let session_id = if principal.client_id.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        principal.client_id.clone()
    };
    let cancel = CancellationToken::new();
    if let Ok(mut clients) = hub.clients.lock() {
        clients.push(LiveClient {
            tx: tx.clone(),
            cancel: cancel.clone(),
        });
    }
    if (principal.admin || principal.operator) && !principal.web {
        if let Ok(mut admins) = hub.admins.lock() {
            admins.push(LiveOperator {
                user: principal.user.clone(),
                admin: principal.admin,
                tx: tx.clone(),
            });
        }
    }
    let writer_cancel = cancel.clone();
    tokio::spawn(async move {
        ws::run_writer_until_cancel(sink, rx, writer_cancel).await;
    });
    loop {
        let msg = tokio::select! {
            _ = cancel.cancelled() => break,
            msg = stream.next() => match msg {
                Some(Ok(msg)) => msg,
                _ => break,
            },
        };
        match ws::parse_incoming(msg)? {
            Incoming::Env(env) => {
                if let Err(err) =
                    handle_client(&hub, &tx, &session_id, &principal, env, audit_ip).await
                {
                    tracing::debug!(%peer, error = %err, "client message failed");
                    if matches!(err, Error::Auth(_)) {
                        break;
                    }
                }
            }
            Incoming::Ping(payload) => {
                let _ = tx.try_send(Outbound::Pong(payload));
            }
            Incoming::Binary(bytes) => {
                if let Err(err) = route_binary(&hub, None, bytes).await {
                    tracing::debug!(%peer, error = %err, "binary forward failed");
                }
            }
            Incoming::Closed { .. } => break,
            Incoming::Ignore => {}
        }
    }
    release_client(&hub, &tx).await;
    cancel.cancel();
    if let Ok(mut clients) = hub.clients.lock() {
        clients.retain(|client| !client.cancel.is_cancelled());
    }
    tracing::info!(peer = %audit_ip, tcp_peer = %peer, "client disconnected");
    Ok(())
}

/// Drop in-flight routes owned by a client socket and tell the other end.
///
/// Without this, a node `serve_push` stays blocked after the client goes
/// away, and the partial file never becomes a resume journal.
async fn release_client(hub: &Hub, tx: &mpsc::Sender<Outbound>) {
    if let Ok(mut admins) = hub.admins.lock() {
        admins.retain(|admin| !admin.tx.same_channel(tx));
    }
    let mut notify = Vec::new();
    if let Ok(mut routes) = lock_routes(hub) {
        let ids: Vec<String> = routes
            .iter()
            .filter(|(_, route)| {
                route.origin_tx.same_channel(tx) || route.target_tx.same_channel(tx)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let Some(route) = routes.remove(&id) else {
                continue;
            };
            let (dest, node_id) = if route.origin_tx.same_channel(tx) {
                (route.target_tx, route.target_node)
            } else {
                (
                    route.origin_tx,
                    route
                        .origin_node
                        .unwrap_or_else(|| route.target_node.clone()),
                )
            };
            notify.push((dest, id, node_id));
        }
    }
    for (dest, id, node_id) in notify {
        let _ = fail_transfer(&dest, id, node_id, "client disconnected".into()).await;
    }
}

async fn handle_client(
    hub: &Hub,
    tx: &mpsc::Sender<Outbound>,
    session_id: &str,
    principal: &Principal,
    env: Envelope,
    audit_ip: IpAddr,
) -> Result<()> {
    if principal.web {
        match hub.db.web_session(&principal.web_token).await {
            Ok(Some(session)) if session.user == principal.user => {}
            _ => {
                let _ = send_out(
                    tx,
                    &Envelope::result_err(
                        env.request_id().unwrap_or("").to_string(),
                        "session expired",
                    ),
                )
                .await;
                return Err(Error::Auth("session expired".into()));
            }
        }
        if let Err(why) = web_message_allowed(&env) {
            return send_out(
                tx,
                &Envelope::result_err(env.request_id().unwrap_or("").to_string(), why),
            )
            .await;
        }
    }
    if principal.operator && !principal.access_hash.is_empty() {
        match hub.db.session_by_hash(&principal.access_hash).await {
            Ok(Some(_)) => {}
            _ => {
                let _ = send_out(
                    tx,
                    &Envelope::result_err(
                        env.request_id().unwrap_or("").to_string(),
                        "session revoked",
                    ),
                )
                .await;
                return Err(Error::Auth("session revoked".into()));
            }
        }
    }
    if principal.view.is_some()
        && !matches!(
            env,
            Envelope::Ping | Envelope::Invoke { .. } | Envelope::Cancel { .. }
        )
    {
        return send_out(
            tx,
            &Envelope::result_err(
                env.request_id().unwrap_or("").to_string(),
                "view ticket can only signal a desktop stream",
            ),
        )
        .await;
    }
    match env {
        Envelope::Ping => send_out(tx, &Envelope::Pong).await,
        Envelope::ListNodes { request_id } => {
            let nodes = snapshot_nodes(hub, principal).await;
            send_out(tx, &Envelope::NodeList { request_id, nodes }).await
        }
        Envelope::CreatePairingToken {
            request_id,
            name,
            policy,
            ttl_secs,
            uses,
        } => {
            if !principal.admin && !principal.operator {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "login or admin token required"),
                )
                .await;
            }
            let owner = if principal.user.is_empty() {
                "admin"
            } else {
                principal.user.as_str()
            };
            let uses = if uses == 0 { 1 } else { uses };
            let issued = hub
                .db
                .create_token(owner, &name, policy, ttl_secs, uses)
                .await;
            match issued {
                Ok(info) => {
                    audit_auth(&hub.audit_path, "token.create", owner, &info.id, true, "");
                    send_out(
                        tx,
                        &Envelope::PairingToken {
                            request_id,
                            token: info.token,
                            name: info.name,
                            expires_unix: info.expires_unix,
                            policy: info.policy,
                            id: info.id,
                            uses: info.uses,
                        },
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::SetPolicy {
            request_id,
            node_id,
            policy,
        } => {
            let updated = hub
                .db
                .set_node_policy(&caller_of(principal), &node_id, policy)
                .await;
            match updated {
                Ok(node) => {
                    push_policy(hub, &node.id, node.effective()).await;
                    let body = serde_json::to_value(&node.policy)?;
                    send_out(tx, &Envelope::result_ok(request_id, body)).await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::Invoke {
            request_id,
            node_id,
            op,
            ..
        } => {
            if principal.web || principal.view.is_some() {
                return send_out(
                    tx,
                    &Envelope::result_err(
                        request_id,
                        "browser and view-ticket control is disabled: that path is plaintext at the relay, and a web login is not a node-local grant",
                    ),
                )
                .await;
            }
            let resolved = if principal.operator || principal.admin {
                hub.db
                    .access_to(&caller_of(principal), &node_id)
                    .await
                    .map(|visible| visible.node)
            } else {
                hub.db.resolve_node(&node_id).await
            };
            let node = match resolved {
                Ok(node) => node,
                Err(err) => {
                    return send_out(tx, &Envelope::result_err(request_id, err.to_string())).await;
                }
            };
            let (op, grant) = if let Some(view) = &principal.view {
                if node.id != view.node_id {
                    return send_out(
                        tx,
                        &Envelope::result_err(request_id, "view ticket is for a different node"),
                    )
                    .await;
                }
                if !view_ticket_may_invoke(&op) {
                    return send_out(
                        tx,
                        &Envelope::result_err(
                            request_id,
                            "browser view is not available; use a sealed client with a node-local grant",
                        ),
                    )
                    .await;
                }
                let grant = view.grant.intersect(node.effective());
                if let Err(why) = grant.allows(&op) {
                    return send_out(tx, &Envelope::result_err(request_id, why)).await;
                }
                (stamp_stream_flags(op, &grant), Some(grant))
            } else if principal.operator || principal.admin {
                let visible = match hub.db.access_to(&caller_of(principal), &node.id).await {
                    Ok(visible) => visible,
                    Err(err) => {
                        return send_out(tx, &Envelope::result_err(request_id, err.to_string()))
                            .await;
                    }
                };
                let grant = if visible.relation == models::Relation::Shared {
                    Some(visible.access)
                } else {
                    None
                };
                let cap = grant.unwrap_or_else(|| node.effective());
                if let Err(why) = cap.allows(&op) {
                    return send_out(tx, &Envelope::result_err(request_id, why)).await;
                }
                (op, grant)
            } else {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "agents must use the end-to-end channel"),
                )
                .await;
            };
            let online_tx = {
                let online = lock_online(hub)?;
                match online.get(&node.id) {
                    Some(live) if live.last_seen.elapsed() < STALE_AFTER => Some(live.tx.clone()),
                    _ => None,
                }
            };
            let Some(node_tx) = online_tx else {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, format!("node offline: {}", node.name)),
                )
                .await;
            };
            let target_node = node.id.clone();
            {
                let mut routes = lock_routes(hub)?;
                routes.insert(
                    request_id.clone(),
                    Route {
                        origin_tx: tx.clone(),
                        target_tx: node_tx.clone(),
                        origin_node: None,
                        target_node: target_node.clone(),
                    },
                );
            }
            let forward = Envelope::Invoke {
                request_id,
                node_id: target_node,
                client_id: if principal.client_id.is_empty() {
                    session_id.to_string()
                } else {
                    principal.client_id.clone()
                },
                op,
                grant,
                // Dashboard/view-ticket invokes stay on the plaintext path; E2E
                // clients attach authz inside the sealed body instead.
                authz: None,
                user: if principal.user.is_empty() {
                    None
                } else {
                    Some(principal.user.clone())
                },
                device_id: if principal.device_id.is_empty() {
                    None
                } else {
                    Some(principal.device_id.clone())
                },
            };
            if send_out(&node_tx, &forward).await.is_err() {
                let request_id = forward.request_id().unwrap_or("").to_string();
                lock_routes(hub)?.remove(&request_id);
                return send_out(tx, &Envelope::result_err(request_id, "node disconnected")).await;
            }
            Ok(())
        }
        Envelope::IssueViewTicket {
            request_id,
            node_id,
            control,
        } => issue_view_ticket(hub, tx, principal, request_id, node_id, control, audit_ip).await,
        Envelope::Transfer {
            request_id,
            node_id,
            client_id,
            msg,
            terminal,
            authz: _,
        } => {
            if !principal.admin && !principal.operator {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "agents must use the end-to-end channel"),
                )
                .await;
            }
            if principal.operator && !principal.admin {
                let visible = match hub.db.access_to(&caller_of(principal), &node_id).await {
                    Ok(visible) => visible,
                    Err(err) => {
                        return send_out(tx, &Envelope::result_err(request_id, err.to_string()))
                            .await;
                    }
                };
                if let TransferMsg::PeerCopy { dst_node, .. } = &msg {
                    // Peer copy reads the addressed node and writes the destination.
                    if !visible.access.allow_read {
                        return send_out(
                            tx,
                            &Envelope::result_err(request_id, "read is not allowed"),
                        )
                        .await;
                    }
                    let dst = match hub.db.access_to(&caller_of(principal), dst_node).await {
                        Ok(dst) => dst,
                        Err(err) => {
                            return send_out(
                                tx,
                                &Envelope::result_err(request_id, err.to_string()),
                            )
                            .await;
                        }
                    };
                    if !dst.access.allow_write {
                        return send_out(
                            tx,
                            &Envelope::result_err(request_id, "write is not allowed"),
                        )
                        .await;
                    }
                } else {
                    if msg.needs_write() && !visible.access.allow_write {
                        return send_out(
                            tx,
                            &Envelope::result_err(request_id, "write is not allowed"),
                        )
                        .await;
                    }
                    if msg.needs_read() && !visible.access.allow_read {
                        return send_out(
                            tx,
                            &Envelope::result_err(request_id, "read is not allowed"),
                        )
                        .await;
                    }
                }
            }
            open_or_forward(hub, None, tx, request_id, node_id, client_id, msg, terminal).await
        }
        Envelope::DirectOffer {
            request_id,
            node_id,
            public_key,
            cert_fp,
            cert_sig,
            local_addrs,
            reflexive,
        } => {
            open_direct(
                hub,
                None,
                Some(principal),
                tx,
                request_id,
                node_id,
                public_key,
                cert_fp,
                cert_sig,
                local_addrs,
                reflexive,
            )
            .await
        }
        Envelope::E2eHello { .. } | Envelope::E2e { .. } => {
            route_e2e(hub, None, tx, Some(principal), env).await
        }
        Envelope::RegisterClient {
            request_id,
            name,
            public_key,
        } => {
            if !principal.admin && !principal.operator {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            let owner = if principal.user.is_empty() {
                "admin"
            } else {
                principal.user.as_str()
            };
            let registered = hub.db.register_client(owner, &name, &public_key).await;
            match registered {
                Ok(record) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(
                            request_id,
                            serde_json::json!({
                                "id": record.id,
                                "name": record.name,
                            }),
                        ),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::SetClientGrant {
            request_id,
            client_id,
            node_id,
            policy,
        } => {
            if !principal.admin && !principal.operator {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            let granted = hub
                .db
                .set_grant(&caller_of(principal), &client_id, &node_id, policy)
                .await;
            match granted {
                Ok(record) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(
                            request_id,
                            serde_json::to_value(record.info()).unwrap_or_default(),
                        ),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::RevokeClient {
            request_id,
            client_id,
        } => {
            if !principal.admin && !principal.operator {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            let revoked = hub
                .db
                .revoke_client(&caller_of(principal), &client_id)
                .await;
            match revoked {
                Ok(_) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::ListClients { request_id } => {
            if !principal.admin && !principal.operator {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            let owner = if principal.admin {
                None
            } else {
                Some(principal.user.as_str())
            };
            let clients = hub
                .db
                .list_clients(owner)
                .await?
                .into_iter()
                .map(|record| record.info())
                .collect();
            send_out(
                tx,
                &Envelope::ClientList {
                    request_id,
                    clients,
                },
            )
            .await
        }
        Envelope::ListApprovals { request_id } => {
            if !principal.admin && !principal.operator {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            let items = hub.db.list_approvals().await.unwrap_or_default();
            let items = if principal.admin {
                items
            } else {
                let owned: Vec<String> = hub
                    .db
                    .visible(&caller_of(principal))
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|node| node.relation == models::Relation::Owner)
                    .map(|node| node.node.id)
                    .collect();
                items
                    .into_iter()
                    .filter(|item| owned.iter().any(|id| id == &item.node_id))
                    .collect()
            };
            send_out(tx, &Envelope::ApprovalList { request_id, items }).await
        }
        Envelope::ResolveApproval {
            request_id,
            approval_id,
            node_id,
            allow,
        } => {
            if !principal.admin && !principal.operator {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            let resolved = hub.db.access_to(&caller_of(principal), &node_id).await;
            let node = match resolved {
                Ok(visible) if visible.relation != models::Relation::Shared || principal.admin => {
                    visible.node
                }
                Ok(_) => {
                    return send_out(
                        tx,
                        &Envelope::result_err(request_id, "only the node owner can approve"),
                    )
                    .await;
                }
                Err(err) => {
                    return send_out(tx, &Envelope::result_err(request_id, err.to_string())).await
                }
            };
            let _ = hub.db.remove_approval(&approval_id).await;
            let node_tx = lock_online(hub)?.get(&node.id).map(|live| live.tx.clone());
            if let Some(node_tx) = node_tx {
                let _ = send_out(
                    &node_tx,
                    &Envelope::ApprovalDecision {
                        approval_id: approval_id.clone(),
                        allow,
                    },
                )
                .await;
            }
            send_out(
                tx,
                &Envelope::result_ok(
                    request_id,
                    serde_json::json!({"allow": allow, "approval_id": approval_id}),
                ),
            )
            .await
        }
        Envelope::QueryAudit { request_id, filter } => {
            if !principal.admin && !principal.operator {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            let parsed: agentlink_core::audit::AuditFilter =
                serde_json::from_value(filter).unwrap_or_default();
            let mut records = agentlink_core::audit::select(&read_audit(&hub.audit_path), &parsed);
            if !principal.admin {
                let visible = hub
                    .db
                    .visible(&caller_of(principal))
                    .await
                    .unwrap_or_default();
                let node_ids: Vec<String> =
                    visible.iter().map(|node| node.node.id.clone()).collect();
                let agents = hub
                    .db
                    .list_clients(Some(principal.user.as_str()))
                    .await
                    .unwrap_or_default();
                let agent_ids: Vec<String> = agents.into_iter().map(|client| client.id).collect();
                records.retain(|record| {
                    record_visible(
                        record,
                        &principal.user,
                        &node_ids,
                        &agent_ids,
                        &principal.device_id,
                    )
                });
            }
            let records = records
                .into_iter()
                .filter_map(|record| serde_json::to_value(record).ok())
                .collect();
            send_out(
                tx,
                &Envelope::AuditPage {
                    request_id,
                    records,
                },
            )
            .await
        }
        Envelope::SetAuditPolicy {
            request_id,
            node_id,
            toml,
            user,
            ..
        } => {
            if !principal.admin && !principal.operator {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            if let Err(err) = agentlink_core::audit::AuditPolicy::parse(&toml) {
                return send_out(tx, &Envelope::result_err(request_id, err.to_string())).await;
            }
            if let Some(username) = user.filter(|name| !name.is_empty()) {
                if !principal.admin && username != principal.user {
                    return send_out(tx, &Envelope::result_err(request_id, "not found")).await;
                }
                if let Err(err) = hub.db.set_user_audit(&username, &toml).await {
                    return send_out(tx, &Envelope::result_err(request_id, err.to_string())).await;
                }
                return send_out(
                    tx,
                    &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                )
                .await;
            }
            let node = match hub.db.access_to(&caller_of(principal), &node_id).await {
                Ok(visible) if visible.relation != models::Relation::Shared => visible.node,
                Ok(_) => {
                    return send_out(
                        tx,
                        &Envelope::result_err(
                            request_id,
                            "only the node owner can set audit policy",
                        ),
                    )
                    .await;
                }
                Err(err) => {
                    return send_out(tx, &Envelope::result_err(request_id, err.to_string())).await;
                }
            };
            if let Err(err) = hub.db.set_node_audit(&node.id, &toml).await {
                return send_out(tx, &Envelope::result_err(request_id, err.to_string())).await;
            }
            let node_tx = lock_online(hub)?.get(&node.id).map(|live| live.tx.clone());
            if let Some(node_tx) = node_tx {
                let _ = send_out(&node_tx, &Envelope::AuditPolicyPush { toml }).await;
            }
            send_out(
                tx,
                &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
            )
            .await
        }
        Envelope::Session {
            session_id,
            node_id,
            cursors,
        } => {
            let Ok(node) = hub.db.resolve_node(&node_id).await else {
                return Ok(());
            };
            let node_tx = lock_online(hub)?.get(&node.id).map(|live| live.tx.clone());
            if let Some(node_tx) = node_tx {
                let _ = send_out(
                    &node_tx,
                    &Envelope::Session {
                        session_id,
                        node_id: node.id,
                        cursors,
                    },
                )
                .await;
            }
            Ok(())
        }
        Envelope::Cancel {
            request_id,
            node_id,
        } => {
            let resolved = hub.db.resolve_node(&node_id).await;
            let Ok(node) = resolved else {
                return Ok(());
            };
            let node_tx = {
                let online = lock_online(hub)?;
                online.get(&node.id).map(|n| n.tx.clone())
            };
            if let Some(node_tx) = node_tx {
                let _ = send_out(
                    &node_tx,
                    &Envelope::Cancel {
                        request_id,
                        node_id: node.id,
                    },
                )
                .await;
            }
            Ok(())
        }
        other => handle_account(hub, tx, principal, other).await,
    }
}

async fn node_loop(ws: RelaySocket, hub: Arc<Hub>, node_id: String) -> Result<()> {
    let (sink, mut stream) = ws.split();
    let (tx, rx) = mpsc::channel(256);
    let cancel = CancellationToken::new();
    if let Ok(mut kick) = hub.kick.lock() {
        kick.push(cancel.clone());
    }
    let generation = hub.generation.fetch_add(1, Ordering::SeqCst);
    if let Some(previous) = lock_online(&hub)?.insert(
        node_id.clone(),
        Online {
            generation,
            tx: tx.clone(),
            last_seen: Instant::now(),
            cancel: cancel.clone(),
        },
    ) {
        previous.cancel.cancel();
    }
    // Routes clone `tx` for the life of a request. The write half has to
    // close on kick anyway, or the daemon stays blocked in `stream.next`
    // and never redials.
    let writer_cancel = cancel.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = writer_cancel.cancelled() => {}
            _ = ws::run_writer(sink, rx) => {}
        }
    });

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            msg = stream.next() => {
                let Some(msg) = msg else { break };
                let msg = match msg {
                    Ok(msg) => msg,
                    Err(_) => break,
                };
                match ws::parse_incoming(msg)? {
                    Incoming::Env(env) => {
                        mark_seen(&hub, &node_id).await;
                        if let Err(err) = handle_node(&hub, &node_id, &tx, env).await {
                            tracing::debug!(node = %node_id, error = %err, "node message failed");
                        }
                    }
                    Incoming::Binary(bytes) => {
                        mark_seen(&hub, &node_id).await;
                        if let Err(err) = route_binary(&hub, Some(&node_id), bytes).await {
                            tracing::debug!(node = %node_id, error = %err, "binary forward failed");
                        }
                    }
                    Incoming::Ping(payload) => {
                        mark_seen(&hub, &node_id).await;
                        let _ = tx.try_send(Outbound::Pong(payload));
                    }
                    Incoming::Closed { .. } => break,
                    Incoming::Ignore => {}
                }
            }
        }
    }

    cancel.cancel();
    detach(&hub, &node_id, generation, &tx);
    tracing::info!(node = %node_id, "node disconnected");
    Ok(())
}

async fn handle_node(
    hub: &Hub,
    node_id: &str,
    node_tx: &mpsc::Sender<Outbound>,
    env: Envelope,
) -> Result<()> {
    match env {
        Envelope::Ping => {
            let tx = lock_online(hub)?.get(node_id).map(|n| n.tx.clone());
            if let Some(tx) = tx {
                send_out(&tx, &Envelope::Pong).await?;
            }
            Ok(())
        }
        Envelope::Transfer {
            request_id,
            node_id: target,
            client_id,
            msg,
            terminal,
            authz: _,
        } => {
            open_or_forward(
                hub,
                Some(node_id),
                node_tx,
                request_id,
                target,
                client_id,
                msg,
                terminal,
            )
            .await
        }
        Envelope::DirectOffer {
            request_id,
            node_id: target,
            public_key,
            cert_fp,
            cert_sig,
            local_addrs,
            reflexive,
        } => {
            open_direct(
                hub,
                Some(node_id),
                None,
                node_tx,
                request_id,
                target,
                public_key,
                cert_fp,
                cert_sig,
                local_addrs,
                reflexive,
            )
            .await
        }
        Envelope::E2eHello { .. } | Envelope::E2e { .. } => {
            route_e2e(hub, Some(node_id), node_tx, None, env).await
        }
        Envelope::E2eWelcome { .. } => {
            let Some(id) = env.request_id().map(|s| s.to_string()) else {
                return Ok(());
            };
            forward_existing(hub, Some(node_id), &id, env, true).await
        }
        Envelope::ApprovalRequest {
            request_id,
            approval_id,
            node_id: origin,
            client_id,
            category,
            summary,
            expires_unix,
        } => {
            let info = ApprovalInfo {
                approval_id: approval_id.clone(),
                node_id: origin,
                client_id,
                category,
                summary,
                expires_unix,
            };
            let _ = hub.db.put_approval(&info).await;
            let note = Envelope::ApprovalRequest {
                request_id: request_id.clone(),
                approval_id,
                node_id: info.node_id.clone(),
                client_id: info.client_id.clone(),
                category: info.category.clone(),
                summary: info.summary.clone(),
                expires_unix,
            };
            // Deliver to the waiting invoke client (needed when that client is
            // not in the admin fanout set, and so dispatch can match request_id).
            if !request_id.is_empty() {
                let _ = forward_existing(hub, Some(node_id), &request_id, note.clone(), false).await;
            }
            fanout_admins(hub, &note).await;
            Ok(())
        }
        Envelope::AuditBatch { records, .. } => {
            append_audit(&hub.audit_path, &records);
            Ok(())
        }
        other => {
            let Some(id) = other.request_id().map(|s| s.to_string()) else {
                tracing::debug!(node = %node_id, kind = kind_name(&other), "ignoring node envelope");
                return Ok(());
            };
            let terminal = match &other {
                Envelope::End { .. } | Envelope::DirectAnswer { .. } => true,
                Envelope::Result { terminal, .. } => *terminal,
                Envelope::E2e { terminal, .. } => *terminal,
                Envelope::E2eWelcome { .. } => true,
                _ => false,
            };
            forward_existing(hub, Some(node_id), &id, other, terminal).await
        }
    }
}

async fn route_e2e(
    hub: &Hub,
    from_node: Option<&str>,
    from_tx: &mpsc::Sender<Outbound>,
    principal: Option<&Principal>,
    mut env: Envelope,
) -> Result<()> {
    let (request_id, node_id, class) = match &env {
        Envelope::E2eHello {
            request_id,
            node_id,
            ..
        } => (request_id.clone(), node_id.clone(), "meta".to_string()),
        Envelope::E2e {
            request_id,
            node_id,
            class,
            ..
        } => (request_id.clone(), node_id.clone(), class.clone()),
        _ => return Ok(()),
    };
    if route_exists(hub, &request_id)? && !matches!(env, Envelope::E2eHello { .. }) {
        let Some(bound) = route_target(hub, &request_id)? else {
            return send_out(
                from_tx,
                &Envelope::result_err(request_id, "request route missing"),
            )
            .await;
        };
        // Authorization stays on the node that opened the route. A later frame
        // must not name a different machine and reuse that route.
        if !node_names_target(hub, &node_id, &bound).await? {
            return send_out(
                from_tx,
                &Envelope::result_err(request_id, "node does not match the open request"),
            )
            .await;
        }
        if let Envelope::E2e {
            node_id,
            relay_admin,
            relay_grant,
            client_id,
            user,
            device_id,
            ..
        } = &mut env
        {
            *node_id = bound.clone();
            apply_e2e_auth(
                hub,
                from_node,
                principal,
                &bound,
                relay_admin,
                relay_grant,
                client_id,
            )
            .await?;
            stamp_actor(principal, user, device_id);
        }
        let terminal = matches!(env, Envelope::E2e { terminal: true, .. });
        return forward_existing(hub, from_node, &request_id, env, terminal).await;
    }
    let resolved = hub.db.resolve_node(&node_id).await;
    let node = match resolved {
        Ok(node) => node,
        Err(err) => {
            return send_out(from_tx, &Envelope::result_err(request_id, err.to_string())).await;
        }
    };
    let allowed = if principal.map(|p| p.admin).unwrap_or(false) {
        node.effective()
    } else if let Some(from_id) = from_node {
        // A compromised node must not open E2E onto another account's machine.
        match hub.db.resolve_node(from_id).await {
            Ok(from) if peer_nodes_allowed(&from, &node) => node.effective(),
            _ => {
                return send_out(
                    from_tx,
                    &Envelope::result_err(request_id, "node peer access denied"),
                )
                .await;
            }
        }
    } else if let Some(principal) = principal {
        if principal.operator {
            hub.db
                .access_to(&caller_of(principal), &node.id)
                .await
                .map(|visible| visible.access)
                .unwrap_or_else(|_| NodePolicy::none())
        } else {
            match hub.db.client_record(&principal.client_id).await {
                Ok(Some(record)) if !record.revoked => record
                    .grants
                    .get(&node.id)
                    .copied()
                    .unwrap_or_else(NodePolicy::none)
                    .intersect(node.effective()),
                _ => NodePolicy::none(),
            }
        }
    } else {
        NodePolicy::none()
    };
    // A caller who cannot address the node must not create a route. The
    // operation class is not a grant: the node accepts or rejects the sealed
    // body. A relay preset must not be the thing that allows exec.
    if !agentlink_core::e2e::class_allowed(allowed, "meta")
        && !agentlink_core::e2e::class_allowed(allowed, &class)
    {
        let message = "this login cannot route to that node".to_string();
        return send_out(from_tx, &Envelope::result_err(request_id, message)).await;
    }
    let online_tx = {
        let online = lock_online(hub)?;
        match online.get(&node.id) {
            Some(live) if live.last_seen.elapsed() < STALE_AFTER => Some(live.tx.clone()),
            _ => None,
        }
    };
    let Some(node_tx) = online_tx else {
        return send_out(
            from_tx,
            &Envelope::result_err(request_id, format!("node offline: {}", node.name)),
        )
        .await;
    };
    {
        let mut routes = lock_routes(hub)?;
        routes.insert(
            request_id.clone(),
            Route {
                origin_tx: from_tx.clone(),
                target_tx: node_tx.clone(),
                origin_node: from_node.map(|id| id.to_string()),
                target_node: node.id.clone(),
            },
        );
    }
    match &mut env {
        Envelope::E2eHello { node_id, .. } => *node_id = node.id.clone(),
        Envelope::E2e {
            node_id,
            relay_admin,
            relay_grant,
            client_id,
            user,
            device_id,
            ..
        } => {
            *node_id = node.id.clone();
            apply_e2e_auth(
                hub,
                from_node,
                principal,
                node_id,
                relay_admin,
                relay_grant,
                client_id,
            )
            .await?;
            stamp_actor(principal, user, device_id);
        }
        _ => {}
    }
    remember(hub, &env);
    if send_out(&node_tx, &env).await.is_err() {
        lock_routes(hub)?.remove(&request_id);
        return send_out(
            from_tx,
            &Envelope::result_err(request_id, "node disconnected"),
        )
        .await;
    }
    Ok(())
}

async fn apply_e2e_auth(
    hub: &Hub,
    from_node: Option<&str>,
    principal: Option<&Principal>,
    node_id: &str,
    relay_admin: &mut bool,
    relay_grant: &mut Option<NodePolicy>,
    client_id: &mut String,
) -> Result<()> {
    if let Some(from_node) = from_node {
        *relay_admin = false;
        if client_id.is_empty() {
            *client_id = from_node.to_string();
        }
        let from = hub.db.resolve_node(from_node).await?;
        let target = hub.db.resolve_node(node_id).await?;
        let policy = if peer_nodes_allowed(&from, &target) {
            target.effective()
        } else {
            NodePolicy::none()
        };
        *relay_grant = Some(policy);
        return Ok(());
    }
    let Some(principal) = principal else {
        *relay_admin = false;
        *relay_grant = Some(NodePolicy::none());
        return Ok(());
    };
    if !principal.client_id.is_empty() {
        *client_id = principal.client_id.clone();
    }
    if principal.operator && !principal.admin {
        let access = hub
            .db
            .access_to(&caller_of(principal), node_id)
            .await
            .map(|visible| visible.access)
            .unwrap_or_else(|_| NodePolicy::none());
        *relay_admin = false;
        *relay_grant = Some(access);
        return Ok(());
    }
    *relay_admin = principal.admin;
    if principal.admin {
        *relay_grant = None;
        return Ok(());
    }
    let grant = hub
        .db
        .client_record(&principal.client_id)
        .await?
        .and_then(|record| record.grants.get(node_id).copied())
        .unwrap_or_else(NodePolicy::none);
    *relay_grant = Some(grant);
    Ok(())
}

async fn fanout_admins(hub: &Hub, env: &Envelope) {
    let node_id = match env {
        Envelope::ApprovalRequest { node_id, .. } => node_id.clone(),
        _ => String::new(),
    };
    let owner = hub
        .db
        .resolve_node(&node_id)
        .await
        .map(|node| node.owner)
        .unwrap_or_default();
    let txs = hub
        .admins
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    for live in txs {
        if live.admin || (!owner.is_empty() && live.user == owner) {
            let _ = send_out(&live.tx, env).await;
        }
    }
}

fn read_audit(path: &std::path::Path) -> Vec<agentlink_core::audit::AuditRecord> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn read_audit_values(path: &std::path::Path) -> Vec<serde_json::Value> {
    read_audit(path)
        .into_iter()
        .filter_map(|record| serde_json::to_value(record).ok())
        .collect()
}

fn append_chained_auth(
    path: &std::path::Path,
    op: &str,
    user: &str,
    device: &str,
    ok: bool,
    error: &str,
) {
    use agentlink_core::audit::{assign_chain, AuditRecord};
    static CHAIN: Mutex<()> = Mutex::new(());
    let Ok(_guard) = CHAIN.lock() else {
        return;
    };
    let prior = read_audit(path);
    let mut seq = 0u64;
    let mut prev = "0".repeat(64);
    for record in &prior {
        if record.hash == "off" {
            continue;
        }
        seq = record.seq;
        prev = record.hash.clone();
    }
    let mut record = AuditRecord {
        seq: 0,
        ts: chrono_now(),
        node_id: "relay".into(),
        node_name: "relay".into(),
        client_id: device.into(),
        client_name: None,
        session_id: None,
        category: "auth".into(),
        op: op.into(),
        args: serde_json::json!({"user": user}),
        result: if ok { "ok" } else { "error" }.into(),
        error: if error.is_empty() {
            None
        } else {
            Some(error.into())
        },
        duration_ms: 0,
        transfer: None,
        before_hash: None,
        after_hash: None,
        diff_ref: None,
        output_ref: None,
        exit_code: None,
        prev_hash: String::new(),
        hash: String::new(),
        user: Some(user.into()),
        device_id: Some(device.into()),
    };
    assign_chain(&mut record, seq.saturating_add(1), &prev, true);
    if let Ok(value) = serde_json::to_value(&record) {
        append_audit(path, &[value]);
    }
}

fn append_audit(path: &std::path::Path, records: &[serde_json::Value]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    for record in records {
        let _ = std::io::Write::write_all(&mut file, record.to_string().as_bytes());
        let _ = std::io::Write::write_all(&mut file, b"\n");
    }
}

fn remember(hub: &Hub, env: &Envelope) {
    let Some(capture) = &hub.capture else {
        return;
    };
    if let Ok(bytes) = serde_json::to_vec(env) {
        if let Ok(mut guard) = capture.lock() {
            guard.push(bytes);
        }
    }
}

fn audit_page() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>agentlink audit</title>
<style>
body { font: 14px/1.4 ui-sans-serif, sans-serif; margin: 24px; color: #1c1917; background: #fafaf9; }
h1 { font-size: 20px; }
label { margin-right: 12px; }
input { margin-right: 8px; }
table { border-collapse: collapse; width: 100%; background: white; }
th, td { border: 1px solid #e7e5e4; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f5f5f4; }
code { font-size: 12px; }
</style>
</head>
<body>
<h1>agentlink audit</h1>
<p>Read-only view of records the nodes uploaded to this relay. End-to-end payloads are not on this page.</p>
<form id="filters">
<label>token <input id="token" type="password" autocomplete="current-password"></label>
<label>node <input id="node"></label>
<label>agent <input id="agent"></label>
<label>op <input id="op"></label>
<label>text <input id="text"></label>
<button type="submit">load</button>
</form>
<p id="status"></p>
<table>
<thead><tr><th>time</th><th>node</th><th>agent</th><th>op</th><th>result</th><th>hash</th></tr></thead>
<tbody id="rows"></tbody>
</table>
<script>
const tokenBox = document.getElementById("token");
tokenBox.value = sessionStorage.getItem("agentlink-audit-token") || "";
document.getElementById("filters").addEventListener("submit", async (event) => {
  event.preventDefault();
  sessionStorage.setItem("agentlink-audit-token", tokenBox.value);
  const status = document.getElementById("status");
  status.textContent = "loading";
  const response = await fetch("/audit/records?token=" + encodeURIComponent(tokenBox.value));
  if (!response.ok) { status.textContent = "rejected (" + response.status + ")"; return; }
  const records = await response.json();
  const node = document.getElementById("node").value.trim();
  const agent = document.getElementById("agent").value.trim();
  const op = document.getElementById("op").value.trim();
  const text = document.getElementById("text").value.trim().toLowerCase();
  const rows = document.getElementById("rows");
  rows.innerHTML = "";
  let shown = 0;
  for (const record of records) {
    const blob = JSON.stringify(record).toLowerCase();
    if (node && record.node_id !== node && record.node_name !== node) continue;
    if (agent && record.client_id !== agent && record.client_name !== agent) continue;
    if (op && record.op !== op && record.category !== op) continue;
    if (text && !blob.includes(text)) continue;
    const tr = document.createElement("tr");
    for (const value of [record.ts, record.node_name || record.node_id, record.client_id, record.op, record.result, (record.hash || "").slice(0, 12)]) {
      const td = document.createElement("td");
      td.textContent = value || "";
      tr.appendChild(td);
    }
    rows.appendChild(tr);
    shown += 1;
  }
  status.textContent = shown + " records";
});
</script>
</body>
</html>
"#
    .to_string()
}

async fn open_or_forward(
    hub: &Hub,
    from_node: Option<&str>,
    from_tx: &mpsc::Sender<Outbound>,
    request_id: String,
    node_id: String,
    client_id: String,
    msg: TransferMsg,
    terminal: bool,
) -> Result<()> {
    if route_exists(hub, &request_id)? {
        let Some(bound) = route_target(hub, &request_id)? else {
            return fail_transfer(
                from_tx,
                request_id,
                node_id,
                "request route missing".into(),
            )
            .await;
        };
        if !node_names_target(hub, &node_id, &bound).await? {
            return fail_transfer(
                from_tx,
                request_id,
                bound,
                "node does not match the open request".into(),
            )
            .await;
        }
        let env = Envelope::Transfer {
            request_id: request_id.clone(),
            node_id: bound,
            client_id,
            msg,
            terminal,
            authz: None,
        };
        return forward_existing(hub, from_node, &request_id, env, terminal).await;
    }
    let resolved = hub.db.resolve_node(&node_id).await;
    let node = match resolved {
        Ok(node) => node,
        Err(err) => {
            return fail_transfer(from_tx, request_id, node_id, err.to_string()).await;
        }
    };
    if let Err(why) = transfer_allowed(hub, &node, from_node, &msg).await {
        return fail_transfer(from_tx, request_id, node.name, why).await;
    }
    let online_tx = {
        let online = lock_online(hub)?;
        match online.get(&node.id) {
            Some(live) if live.last_seen.elapsed() < STALE_AFTER => Some(live.tx.clone()),
            _ => None,
        }
    };
    let Some(target_tx) = online_tx else {
        return fail_transfer(
            from_tx,
            request_id,
            node.name.clone(),
            format!("node offline: {}", node.name),
        )
        .await;
    };
    {
        let mut routes = lock_routes(hub)?;
        routes.insert(
            request_id.clone(),
            Route {
                origin_tx: from_tx.clone(),
                target_tx: target_tx.clone(),
                origin_node: from_node.map(|id| id.to_string()),
                target_node: node.id.clone(),
            },
        );
    }
    let target_id = node.id.clone();
    let env = Envelope::Transfer {
        request_id: request_id.clone(),
        node_id: target_id.clone(),
        client_id,
        terminal,
        msg,
        authz: None,
    };
    if send_out(&target_tx, &env).await.is_err() {
        lock_routes(hub)?.remove(&request_id);
        return fail_transfer(
            from_tx,
            request_id,
            target_id,
            "node disconnected".to_string(),
        )
        .await;
    }
    Ok(())
}


/// Node-to-node traffic (E2E, transfer, DirectOffer) is same-owner only.
/// A share lets a *user* reach a node; it does not let one account's node
/// open a peer session onto another account's machine.
fn peer_nodes_allowed(from: &EnrolledNode, target: &EnrolledNode) -> bool {
    from.owner == target.owner
}

async fn transfer_allowed(
    hub: &Hub,
    target: &EnrolledNode,
    from_node: Option<&str>,
    msg: &TransferMsg,
) -> std::result::Result<(), String> {
    if let Some(from_id) = from_node {
        let from = hub
            .db
            .resolve_node(from_id)
            .await
            .map_err(|e| e.to_string())?;
        if !peer_nodes_allowed(&from, target) {
            return Err("node peer access denied".into());
        }
    }
    match msg {
        TransferMsg::Push { .. } | TransferMsg::PushDir { .. } | TransferMsg::PushStream { .. } => {
            if target.effective().allow_write {
                Ok(())
            } else {
                Err("write is not allowed on this node".into())
            }
        }
        TransferMsg::Pull { .. } | TransferMsg::PullDir { .. } | TransferMsg::PullStream { .. } => {
            if target.effective().allow_read {
                Ok(())
            } else {
                Err("read is not allowed on this node".into())
            }
        }
        TransferMsg::PeerCopy { dst_node, .. } => {
            if !target.effective().allow_read {
                return Err("read is not allowed on the source node".into());
            }
            let dst = hub
                .db
                .resolve_node(dst_node)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(from_id) = from_node {
                let from = hub
                    .db
                    .resolve_node(from_id)
                    .await
                    .map_err(|e| e.to_string())?;
                if !peer_nodes_allowed(&from, &dst) {
                    return Err("node peer access denied".into());
                }
            }
            if dst.effective().allow_write {
                Ok(())
            } else {
                Err("write is not allowed on the destination node".into())
            }
        }
        _ => Ok(()),
    }
}

async fn open_direct(
    hub: &Hub,
    from_node: Option<&str>,
    principal: Option<&Principal>,
    from_tx: &mpsc::Sender<Outbound>,
    request_id: String,
    node_id: String,
    public_key: String,
    cert_fp: String,
    cert_sig: String,
    local_addrs: Vec<String>,
    reflexive: Option<String>,
) -> Result<()> {
    if route_exists(hub, &request_id)? {
        let env = Envelope::DirectOffer {
            request_id: request_id.clone(),
            node_id,
            public_key,
            cert_fp,
            cert_sig,
            local_addrs,
            reflexive,
        };
        return forward_existing(hub, from_node, &request_id, env, false).await;
    }
    let resolved = hub.db.resolve_node(&node_id).await;
    let node = match resolved {
        Ok(node) => node,
        Err(err) => return Err(err),
    };
    if let Some(from_id) = from_node {
        let from = hub.db.resolve_node(from_id).await?;
        if !peer_nodes_allowed(&from, &node) {
            return Err(Error::PermissionDenied("node peer access denied".into()));
        }
    } else {
        let Some(principal) = principal else {
            return Err(Error::PermissionDenied("direct offer requires a session".into()));
        };
        if !principal.admin {
            if principal.operator {
                hub.db
                    .access_to(&caller_of(principal), &node.id)
                    .await
                    .map_err(|_| Error::PermissionDenied("no access to this node".into()))?;
            } else {
                let grant = hub
                    .db
                    .client_record(&principal.client_id)
                    .await?
                    .filter(|record| !record.revoked)
                    .and_then(|record| record.grants.get(&node.id).copied());
                if grant.is_none() {
                    return Err(Error::PermissionDenied(
                        "this login cannot route to that node".into(),
                    ));
                }
            }
        }
    }
    let online_tx = {
        let online = lock_online(hub)?;
        match online.get(&node.id) {
            Some(live) if live.last_seen.elapsed() < STALE_AFTER => Some(live.tx.clone()),
            _ => None,
        }
    };
    let Some(target_tx) = online_tx else {
        return Err(Error::Message(format!("node offline: {}", node.name)));
    };
    let reflexive = reflexive.or_else(|| punch_of(hub, &public_key));
    {
        let mut routes = lock_routes(hub)?;
        routes.insert(
            request_id.clone(),
            Route {
                origin_tx: from_tx.clone(),
                target_tx: target_tx.clone(),
                origin_node: from_node.map(|id| id.to_string()),
                target_node: node.id.clone(),
            },
        );
    }
    let env = Envelope::DirectOffer {
        request_id,
        node_id: node.id,
        public_key,
        cert_fp,
        cert_sig,
        local_addrs,
        reflexive,
    };
    send_out(&target_tx, &env).await
}

async fn forward_existing(
    hub: &Hub,
    from_node: Option<&str>,
    request_id: &str,
    mut env: Envelope,
    terminal: bool,
) -> Result<()> {
    if let Envelope::DirectAnswer {
        public_key,
        reflexive,
        ..
    } = &mut env
    {
        if reflexive.is_none() {
            *reflexive = punch_of(hub, public_key);
        }
    }
    let tx = {
        let routes = lock_routes(hub)?;
        routes
            .get(request_id)
            .map(|route| dest_tx(route, from_node))
    };
    if terminal {
        lock_routes(hub)?.remove(request_id);
    }
    if let Some(tx) = tx {
        remember(hub, &env);
        send_out(&tx, &env).await?;
    }
    Ok(())
}

fn dest_tx(route: &Route, from_node: Option<&str>) -> mpsc::Sender<Outbound> {
    let from_origin = match (&route.origin_node, from_node) {
        (None, None) => true,
        (Some(origin), Some(from)) if origin == from => true,
        _ => false,
    };
    if from_origin {
        route.target_tx.clone()
    } else {
        route.origin_tx.clone()
    }
}

fn route_exists(hub: &Hub, request_id: &str) -> Result<bool> {
    Ok(lock_routes(hub)?.contains_key(request_id))
}

fn route_target(hub: &Hub, request_id: &str) -> Result<Option<String>> {
    Ok(lock_routes(hub)?
        .get(request_id)
        .map(|route| route.target_node.clone()))
}

/// True when `named` resolves to the node id stored on the route.
async fn node_names_target(hub: &Hub, named: &str, bound: &str) -> Result<bool> {
    if named == bound {
        return Ok(true);
    }
    match hub.db.resolve_node(named).await {
        Ok(node) => Ok(node.id == bound),
        Err(Error::NotFound(_)) | Err(Error::Ambiguous(_)) => Ok(false),
        Err(err) => Err(err),
    }
}

async fn route_binary(hub: &Hub, from_node: Option<&str>, bytes: Vec<u8>) -> Result<()> {
    let Some(request_id) = agentlink_core::frame::request_id(&bytes) else {
        return Ok(());
    };
    let tx = {
        let routes = lock_routes(hub)?;
        routes
            .get(&request_id)
            .map(|route| dest_tx(route, from_node))
    };
    if let Some(tx) = tx {
        if let Some(capture) = &hub.capture {
            if let Ok(mut guard) = capture.lock() {
                guard.push(bytes.clone());
            }
        }
        tx.send(Outbound::Binary(bytes))
            .await
            .map_err(|_| Error::Message("connection closed".into()))?;
    }
    Ok(())
}

async fn fail_transfer(
    tx: &mpsc::Sender<Outbound>,
    request_id: String,
    node_id: String,
    message: String,
) -> Result<()> {
    send_out(
        tx,
        &Envelope::Transfer {
            request_id,
            node_id,
            client_id: String::new(),
            msg: TransferMsg::Failed { message },
            terminal: true,
            authz: None,
        },
    )
    .await
}

fn punch_of(hub: &Hub, public_key: &str) -> Option<String> {
    hub.punch
        .lock()
        .ok()
        .and_then(|map| map.get(public_key).map(|addr| addr.to_string()))
}

async fn punch_loop(udp: UdpSocket, hub: Arc<Hub>, shutdown: CancellationToken) {
    let mut buf = vec![0u8; 2048];
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            recvd = udp.recv_from(&mut buf) => {
                let Ok((n, src)) = recvd else { continue };
                let Ok(id) = agentlink_core::p2p::decode_punch(&buf[..n]) else { continue };
                if let Ok(mut map) = hub.punch.lock() {
                    map.insert(id, src);
                }
            }
        }
    }
}

async fn push_policy(hub: &Hub, node_id: &str, policy: NodePolicy) {
    let tx = lock_online(hub)
        .ok()
        .and_then(|online| online.get(node_id).map(|n| n.tx.clone()));
    if let Some(tx) = tx {
        let _ = send_out(&tx, &Envelope::PolicyUpdate { policy }).await;
    }
}

async fn snapshot_nodes(hub: &Hub, principal: &Principal) -> Vec<NodeInfo> {
    let fresh = {
        let Ok(online) = lock_online(hub) else {
            return Vec::new();
        };
        online
            .iter()
            .map(|(id, live)| (id.clone(), live.last_seen.elapsed() < STALE_AFTER))
            .collect::<HashMap<_, _>>()
    };
    if let Some(view) = &principal.view {
        let Ok(node) = hub.db.resolve_node(&view.node_id).await else {
            return Vec::new();
        };
        let mut info = enrolled_to_info(&node, None);
        info.online = fresh.get(&node.id).copied().unwrap_or(false);
        info.relation = "view".into();
        info.access = view.grant.preset_name().to_string();
        info.effective = view.grant.intersect(node.effective());
        return vec![info];
    }
    if principal.operator || principal.admin {
        let Ok(nodes) = hub.db.visible(&caller_of(principal)).await else {
            return Vec::new();
        };
        return nodes
            .into_iter()
            .map(|visible| {
                let online = fresh.get(&visible.node.id).copied().unwrap_or(false);
                visible.info(online)
            })
            .collect();
    }
    let Ok(Some(record)) = hub.db.client_record(&principal.client_id).await else {
        return Vec::new();
    };
    let caller = Caller {
        user: principal.user.clone(),
        admin: false,
    };
    let Ok(nodes) = hub.db.visible(&caller).await else {
        return Vec::new();
    };
    nodes
        .into_iter()
        .filter_map(|visible| {
            let grant = record.grants.get(&visible.node.id).copied()?;
            let online = fresh.get(&visible.node.id).copied().unwrap_or(false);
            let mut info = visible.info(online);
            let access = grant.intersect(visible.access);
            info.effective = access;
            info.access = access.preset_name().to_string();
            info.relation = "grant".into();
            Some(info)
        })
        .collect()
}

fn enrolled_to_info(node: &EnrolledNode, live: Option<&Online>) -> NodeInfo {
    let fresh = live
        .map(|live| live.last_seen.elapsed() < STALE_AFTER)
        .unwrap_or(false);
    NodeInfo {
        id: node.id.clone(),
        name: node.name.clone(),
        hostname: node.hostname.clone(),
        os: node.os.clone(),
        arch: node.arch.clone(),
        version: node.version.clone(),
        online: fresh,
        policy: node.policy,
        effective: node.effective(),
        owner: node.owner.clone(),
        relation: String::new(),
        access: node.effective().preset_name().to_string(),
        has_display: node.has_display,
    }
}

fn reap_stale_nodes(hub: &Hub) {
    let stale_after = stale_after();
    let Ok(online) = lock_online(hub) else {
        return;
    };
    for (id, live) in online.iter() {
        if live.last_seen.elapsed() >= stale_after && !live.cancel.is_cancelled() {
            tracing::info!(
                node = %id,
                secs = stale_after.as_secs(),
                "node heartbeat stale; closing socket"
            );
            live.cancel.cancel();
        }
    }
}

async fn mark_seen(hub: &Hub, node_id: &str) {
    if let Ok(mut online) = lock_online(hub) {
        if let Some(live) = online.get_mut(node_id) {
            live.last_seen = Instant::now();
        }
    }
    let _ = hub.db.touch_node(node_id).await;
}

fn detach(hub: &Hub, node_id: &str, generation: u64, tx: &mpsc::Sender<Outbound>) {
    if let Ok(mut online) = lock_online(hub) {
        if online.get(node_id).map(|n| n.generation) == Some(generation) {
            online.remove(node_id);
        }
    }
    // A replacement connection has its own channel. Only routes still
    // pointing at this socket should go away with it.
    if let Ok(mut routes) = lock_routes(hub) {
        routes.retain(|_, route| {
            !route.target_tx.same_channel(tx) && !route.origin_tx.same_channel(tx)
        });
    }
    let _ = unix_now();
}

fn lock_online(hub: &Hub) -> Result<std::sync::MutexGuard<'_, HashMap<String, Online>>> {
    hub.online
        .lock()
        .map_err(|_| Error::Message("relay online map poisoned".into()))
}

fn lock_routes(hub: &Hub) -> Result<std::sync::MutexGuard<'_, HashMap<String, Route>>> {
    hub.routes
        .lock()
        .map_err(|_| Error::Message("relay route map poisoned".into()))
}

async fn send_env<S>(socket: &mut S, env: &Envelope) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let text = serde_json::to_string(env)?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|e| Error::Ws(e.to_string()))
}

async fn next_env<S>(socket: &mut S) -> Result<Envelope>
where
    S: futures_util::Stream<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    loop {
        let msg = socket
            .next()
            .await
            .ok_or_else(|| Error::Ws("connection closed".into()))?
            .map_err(|e| Error::Ws(e.to_string()))?;
        match ws::parse_incoming(msg)? {
            Incoming::Env(env) => return Ok(env),
            Incoming::Closed { .. } => return Err(Error::Ws("connection closed".into())),
            Incoming::Ping(_) | Incoming::Ignore | Incoming::Binary(_) => continue,
        }
    }
}

async fn send_out(tx: &mpsc::Sender<Outbound>, env: &Envelope) -> Result<()> {
    tx.send(ws::encode(env)?)
        .await
        .map_err(|_| Error::Message("connection closed".into()))
}

fn kind_name(env: &Envelope) -> &'static str {
    match env {
        Envelope::Ping => "ping",
        Envelope::Pong => "pong",
        Envelope::Invoke { .. } => "invoke",
        _ => "other",
    }
}

fn operator_principal(
    user: String,
    role: String,
    device_id: String,
    access_hash: String,
) -> Principal {
    Principal {
        admin: role == "admin",
        operator: true,
        legacy: false,
        name: user.clone(),
        user,
        role,
        device_id: device_id.clone(),
        access_hash,
        client_id: device_id,
        view: None,
        web: false,
        web_token: String::new(),
        view_session: None,
    }
}

pub(crate) fn login_allowed(hub: &Hub, peer: SocketAddr) -> bool {
    rate_allow(hub, "login", peer.ip(), 30, 60)
}

/// Per-IP counter. `limit` events are allowed in each `window_secs` window.
pub(crate) fn rate_allow(
    hub: &Hub,
    bucket: &str,
    ip: IpAddr,
    limit: u32,
    window_secs: i64,
) -> bool {
    let Ok(mut windows) = hub.login_windows.lock() else {
        return false;
    };
    let now = unix_now();
    let key = format!("{bucket}:{ip}");
    let entry = windows.entry(key).or_insert((now, 0));
    if now.saturating_sub(entry.0) >= window_secs {
        *entry = (now, 0);
    }
    entry.1 = entry.1.saturating_add(1);
    entry.1 <= limit
}

fn legacy_admin_enabled() -> bool {
    match std::env::var("AGENTLINK_LEGACY_ADMIN") {
        Ok(value) => {
            let value = value.trim().to_ascii_lowercase();
            matches!(value.as_str(), "1" | "true" | "on" | "yes" | "enable" | "enabled")
        }
        Err(_) => false,
    }
}

fn legacy_admin_ttl() -> Option<i64> {
    std::env::var("AGENTLINK_LEGACY_ADMIN_TTL_SECS")
        .ok()
        .and_then(|value| value.trim().parse().ok())
}

fn legacy_gate_at(
    enabled: bool,
    ttl: Option<i64>,
    created_unix: i64,
    now: i64,
) -> std::result::Result<(), &'static str> {
    if !enabled {
        return Err("legacy admin token is disabled");
    }
    let Some(ttl) = ttl else {
        return Err("legacy admin token requires AGENTLINK_LEGACY_ADMIN_TTL_SECS");
    };
    if created_unix <= 0 {
        return Err("legacy admin token has no recorded creation time");
    }
    if ttl <= 0 || now > created_unix.saturating_add(ttl) {
        return Err("legacy admin token expired");
    }
    Ok(())
}

fn note_legacy_use(path: &std::path::Path, ok: bool, error: &str) {
    append_chained_auth(path, "legacy.admin", "admin", "token", ok, error);
}

pub(crate) fn audit_auth(
    path: &std::path::Path,
    op: &str,
    user: &str,
    device: &str,
    ok: bool,
    error: &str,
) {
    let record = serde_json::json!({
        "seq": 0,
        "ts": chrono_now(),
        "node_id": "relay",
        "node_name": "relay",
        "client_id": device,
        "category": "auth",
        "op": op,
        "args": {"user": user},
        "result": if ok { "ok" } else { "error" },
        "error": if error.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(error.into()) },
        "duration_ms": 0,
        "prev_hash": "off",
        "hash": "off",
        "user": user,
        "device_id": device,
    });
    append_audit(path, &[record]);
}

fn chrono_now() -> String {
    agentlink_core::util::unix_now().to_string()
}

fn record_visible(
    record: &agentlink_core::audit::AuditRecord,
    user: &str,
    node_ids: &[String],
    agent_ids: &[String],
    device_id: &str,
) -> bool {
    record.user.as_deref() == Some(user)
        || node_ids.iter().any(|id| id == &record.node_id)
        || agent_ids.iter().any(|id| id == &record.client_id)
        || (!device_id.is_empty() && record.client_id == device_id)
        || record.device_id.as_deref() == Some(device_id)
}

async fn access_hello(
    ws: &mut RelaySocket,
    hub: &Hub,
    session: crate::models::AccessSession,
    public_key: Option<String>,
    presented: &str,
) -> Result<Principal> {
    let Some(public_key) = public_key else {
        send_env(
            ws,
            &Envelope::HelloErr {
                message: "device key required".into(),
                fatal: true,
            },
        )
        .await?;
        return Err(Error::Auth("device key required".into()));
    };
    let public_key = public_key.to_ascii_lowercase();
    if public_key != session.device_id {
        send_env(
            ws,
            &Envelope::HelloErr {
                message: "device key does not match the session".into(),
                fatal: true,
            },
        )
        .await?;
        return Err(Error::Auth("device key does not match the session".into()));
    }
    if let Err(err) = challenge_device(ws, &public_key).await {
        send_env(
            ws,
            &Envelope::HelloErr {
                message: err.to_string(),
                fatal: true,
            },
        )
        .await?;
        return Err(err);
    }
    let hash = accounts::token_hash(presented);
    let Some(fresh) = hub.db.session_by_hash(&hash).await? else {
        send_env(
            ws,
            &Envelope::HelloErr {
                message: "session expired or revoked".into(),
                fatal: true,
            },
        )
        .await?;
        return Err(Error::Auth("session expired or revoked".into()));
    };
    let _ = hub.db.touch_device(&fresh.device_id).await;
    Ok(operator_principal(
        fresh.user,
        fresh.role,
        fresh.device_id,
        hash,
    ))
}

async fn challenge_device(ws: &mut RelaySocket, public_key: &str) -> Result<()> {
    let nonce = util::random_hex(32);
    send_env(
        ws,
        &Envelope::Challenge {
            nonce: nonce.clone(),
        },
    )
    .await?;
    let auth = timeout(HANDSHAKE_TIMEOUT, next_env(ws))
        .await
        .map_err(|_| Error::Timeout)??;
    let signature = match auth {
        Envelope::Authenticate { signature } => signature,
        Envelope::HelloErr { message, .. } => return Err(Error::Auth(message)),
        _ => return Err(Error::Protocol("expected authenticate".into())),
    };
    agentlink_core::identity::verify_nonce(public_key, &nonce, &signature)
}

async fn session_preamble(
    mut ws: RelaySocket,
    hub: &Arc<Hub>,
    peer: SocketAddr,
    audit_ip: IpAddr,
    env: Envelope,
) -> Result<()> {
    match env {
        Envelope::Login {
            request_id,
            username,
            password,
            totp,
            public_key,
            device_name,
        } => {
            login_and_enter(
                ws,
                hub,
                peer,
                audit_ip,
                request_id,
                username,
                password,
                totp,
                public_key,
                device_name.unwrap_or_default(),
                false,
            )
            .await
        }
        Envelope::Signup {
            request_id,
            username,
            password,
            public_key,
            device_name,
        } => {
            if !rate_allow(hub, "signup", audit_ip, 10, 60) {
                let _ = send_env(
                    &mut ws,
                    &Envelope::LoginErr {
                        request_id,
                        message: "too many login attempts".into(),
                    },
                )
                .await;
                return Ok(());
            }
            if !hub.allow_signup {
                let _ = send_env(
                    &mut ws,
                    &Envelope::LoginErr {
                        request_id,
                        message: "signup is disabled".into(),
                    },
                )
                .await;
                return Ok(());
            }
            if let Err(err) = hub.db.create_user(&username, &password, "user").await {
                let _ = send_env(
                    &mut ws,
                    &Envelope::LoginErr {
                        request_id: request_id.clone(),
                        message: err.to_string(),
                    },
                )
                .await;
                return Ok(());
            }
            login_and_enter(
                ws,
                hub,
                peer,
                audit_ip,
                request_id,
                username,
                password,
                None,
                public_key,
                device_name.unwrap_or_default(),
                true,
            )
            .await
        }
        Envelope::RefreshSession {
            request_id,
            refresh_token,
            public_key,
        } => {
            refresh_and_enter(
                ws,
                hub,
                peer,
                audit_ip,
                request_id,
                refresh_token,
                public_key,
            )
            .await
        }
        _ => Ok(()),
    }
}

async fn login_and_enter(
    mut ws: RelaySocket,
    hub: &Arc<Hub>,
    peer: SocketAddr,
    audit_ip: IpAddr,
    request_id: String,
    username: String,
    password: String,
    totp: Option<String>,
    public_key: String,
    device_name: String,
    already_checked: bool,
) -> Result<()> {
    if !login_allowed(hub, peer) {
        audit_auth(
            &hub.audit_path,
            "login",
            &username,
            "",
            false,
            "rate limited",
        );
        let _ = send_env(
            &mut ws,
            &Envelope::LoginErr {
                request_id,
                message: "too many login attempts".into(),
            },
        )
        .await;
        return Ok(());
    }
    let account = if already_checked {
        match hub.db.account(&username).await? {
            Some(account) => account,
            None => {
                let _ = send_env(
                    &mut ws,
                    &Envelope::LoginErr {
                        request_id,
                        message: "invalid username or password".into(),
                    },
                )
                .await;
                return Ok(());
            }
        }
    } else {
        match hub
            .db
            .check_login(&username, &password, totp.as_deref())
            .await
        {
            Ok(account) => account,
            Err(err) => {
                audit_auth(
                    &hub.audit_path,
                    "login",
                    &username,
                    "",
                    false,
                    &err.to_string(),
                );
                let _ = send_env(
                    &mut ws,
                    &Envelope::LoginErr {
                        request_id,
                        message: err.to_string(),
                    },
                )
                .await;
                return Ok(());
            }
        }
    };
    if let Err(err) = challenge_device(&mut ws, &public_key).await {
        if !already_checked {
            let _ = hub.db.note_failure(&account.username).await;
        }
        audit_auth(
            &hub.audit_path,
            "login",
            &account.username,
            &public_key,
            false,
            &err.to_string(),
        );
        let _ = send_env(
            &mut ws,
            &Envelope::LoginErr {
                request_id,
                message: err.to_string(),
            },
        )
        .await;
        return Ok(());
    }
    let session = match hub
        .db
        .issue_session(&account.username, &public_key, &device_name)
        .await
    {
        Ok(session) => session,
        Err(err) => {
            let _ = send_env(
                &mut ws,
                &Envelope::LoginErr {
                    request_id,
                    message: err.to_string(),
                },
            )
            .await;
            return Ok(());
        }
    };
    let _ = hub.db.note_success(&account.username).await;
    audit_auth(
        &hub.audit_path,
        "login",
        &session.user,
        &session.device_id,
        true,
        "",
    );
    send_env(
        &mut ws,
        &Envelope::LoginOk {
            request_id,
            user: session.user.clone(),
            role: session.role.clone(),
            device_id: session.device_id.clone(),
            access_token: session.access_token.clone(),
            access_expires_unix: session.access_expires_unix,
            refresh_token: session.refresh_token.clone(),
            refresh_expires_unix: session.refresh_expires_unix,
        },
    )
    .await?;
    let principal = operator_principal(
        session.user,
        session.role,
        session.device_id,
        accounts::token_hash(&session.access_token),
    );
    client_loop(ws, hub.clone(), peer, audit_ip, principal).await
}

async fn refresh_and_enter(
    mut ws: RelaySocket,
    hub: &Arc<Hub>,
    peer: SocketAddr,
    audit_ip: IpAddr,
    request_id: String,
    refresh_token: String,
    public_key: String,
) -> Result<()> {
    if !rate_allow(hub, "refresh", audit_ip, 60, 60) {
        let _ = send_env(
            &mut ws,
            &Envelope::LoginErr {
                request_id,
                message: "too many login attempts".into(),
            },
        )
        .await;
        return Ok(());
    }
    if let Err(err) = challenge_device(&mut ws, &public_key).await {
        let _ = send_env(
            &mut ws,
            &Envelope::LoginErr {
                request_id,
                message: err.to_string(),
            },
        )
        .await;
        return Ok(());
    }
    let session = match hub.db.rotate_refresh(&refresh_token, &public_key).await {
        Ok(session) => session,
        Err(err) => {
            audit_auth(
                &hub.audit_path,
                "refresh",
                "",
                &public_key,
                false,
                &err.to_string(),
            );
            let _ = send_env(
                &mut ws,
                &Envelope::LoginErr {
                    request_id,
                    message: err.to_string(),
                },
            )
            .await;
            return Ok(());
        }
    };
    audit_auth(
        &hub.audit_path,
        "refresh",
        &session.user,
        &session.device_id,
        true,
        "",
    );
    send_env(
        &mut ws,
        &Envelope::LoginOk {
            request_id,
            user: session.user.clone(),
            role: session.role.clone(),
            device_id: session.device_id.clone(),
            access_token: session.access_token.clone(),
            access_expires_unix: session.access_expires_unix,
            refresh_token: session.refresh_token,
            refresh_expires_unix: session.refresh_expires_unix,
        },
    )
    .await?;
    let principal = operator_principal(
        session.user,
        session.role,
        session.device_id,
        accounts::token_hash(&session.access_token),
    );
    client_loop(ws, hub.clone(), peer, audit_ip, principal).await
}

async fn handle_account(
    hub: &Hub,
    tx: &mpsc::Sender<Outbound>,
    principal: &Principal,
    env: Envelope,
) -> Result<()> {
    let require_login = |request_id: &str| {
        if principal.operator || principal.admin {
            None
        } else {
            Some(request_id.to_string())
        }
    };
    match env {
        Envelope::Logout {
            request_id,
            refresh_token,
        } => {
            if let Some(id) = require_login(&request_id) {
                return send_out(tx, &Envelope::result_err(id, "login required")).await;
            }
            let _ = hub
                .db
                .end_session(&principal.access_hash, refresh_token.as_deref())
                .await;
            audit_auth(
                &hub.audit_path,
                "logout",
                &principal.user,
                &principal.device_id,
                true,
                "",
            );
            send_out(
                tx,
                &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
            )
            .await?;
            Err(Error::Auth("logged out".into()))
        }
        Envelope::ListDevices { request_id } => {
            if let Some(id) = require_login(&request_id) {
                return send_out(tx, &Envelope::result_err(id, "login required")).await;
            }
            let owner = if principal.admin && !principal.operator {
                None
            } else if principal.admin {
                None
            } else {
                Some(principal.user.as_str())
            };
            let devices = hub.db.list_devices(owner).await?;
            let devices = devices
                .into_iter()
                .map(|device| DeviceInfo {
                    id: device.id,
                    user: device.user,
                    name: device.name,
                    created_unix: device.created_unix,
                    last_seen_unix: device.last_seen_unix,
                    revoked: device.revoked,
                })
                .collect();
            send_out(
                tx,
                &Envelope::DeviceList {
                    request_id,
                    devices,
                },
            )
            .await
        }
        Envelope::RevokeDevice {
            request_id,
            device_id,
        } => {
            if let Some(id) = require_login(&request_id) {
                return send_out(tx, &Envelope::result_err(id, "login required")).await;
            }
            let owner = if principal.admin {
                None
            } else {
                Some(principal.user.as_str())
            };
            match hub.db.revoke_device(&device_id, owner).await {
                Ok(device) => {
                    audit_auth(
                        &hub.audit_path,
                        "device.revoke",
                        &device.user,
                        &device.id,
                        true,
                        "",
                    );
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::ShareNode {
            request_id,
            node_id,
            username,
            policy,
        } => {
            if let Some(id) = require_login(&request_id) {
                return send_out(tx, &Envelope::result_err(id, "login required")).await;
            }
            match hub
                .db
                .share(&caller_of(principal), &node_id, &username, policy)
                .await
            {
                Ok(()) => {
                    audit_auth(
                        &hub.audit_path,
                        "share",
                        &principal.user,
                        &node_id,
                        true,
                        &username,
                    );
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::UnshareNode {
            request_id,
            node_id,
            username,
        } => {
            if let Some(id) = require_login(&request_id) {
                return send_out(tx, &Envelope::result_err(id, "login required")).await;
            }
            match hub
                .db
                .unshare(&caller_of(principal), &node_id, &username)
                .await
            {
                Ok(()) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::ListEnrollmentTokens { request_id } => {
            if let Some(id) = require_login(&request_id) {
                return send_out(tx, &Envelope::result_err(id, "login required")).await;
            }
            let owner = if principal.admin {
                None
            } else {
                Some(principal.user.as_str())
            };
            let tokens = hub.db.list_tokens(owner).await?;
            let now = unix_now();
            let tokens = tokens
                .into_iter()
                .map(|token| TokenInfo {
                    state: token.state(now).to_string(),
                    id: token.id,
                    name: token.name,
                    owner: token.owner,
                    policy: token.policy,
                    created_unix: token.created_unix,
                    expires_unix: token.expires_unix,
                    max_uses: token.max_uses,
                    uses_remaining: token.uses_remaining,
                    revoked: token.revoked,
                })
                .collect();
            send_out(tx, &Envelope::EnrollmentTokenList { request_id, tokens }).await
        }
        Envelope::RevokeEnrollmentToken { request_id, id } => {
            if let Some(request) = require_login(&request_id) {
                return send_out(tx, &Envelope::result_err(request, "login required")).await;
            }
            let owner = if principal.admin {
                None
            } else {
                Some(principal.user.as_str())
            };
            match hub.db.revoke_token(&id, owner).await {
                Ok(_) => {
                    audit_auth(
                        &hub.audit_path,
                        "token.revoke",
                        &principal.user,
                        &id,
                        true,
                        "",
                    );
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::EnrollSelf {
            request_id,
            name,
            public_key,
            signature,
            policy,
            hostname,
            os,
            arch,
            version,
        } => {
            if !principal.operator {
                return send_out(tx, &Envelope::result_err(request_id, "login required")).await;
            }
            let message = format!("agentlink-enroll-v1:{request_id}:{public_key}");
            if agentlink_core::identity::verify_message(&public_key, message.as_bytes(), &signature)
                .is_err()
            {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "invalid enroll signature"),
                )
                .await;
            }
            let meta = NodeMeta {
                name: name.clone(),
                hostname: hostname.unwrap_or_default(),
                os: os.unwrap_or_else(|| "android".into()),
                arch: arch.unwrap_or_default(),
                version: version.unwrap_or_default(),
                ceiling: policy.unwrap_or_else(NodePolicy::read_only),
                has_display: None,
            };
            match hub
                .db
                .enroll_self(
                    &principal.user,
                    &public_key,
                    &name,
                    policy.unwrap_or_else(NodePolicy::read_only),
                    meta,
                )
                .await
            {
                Ok(node) => {
                    audit_auth(
                        &hub.audit_path,
                        "enroll_self",
                        &principal.user,
                        &node.id,
                        true,
                        "",
                    );
                    send_out(
                        tx,
                        &Envelope::result_ok(
                            request_id,
                            serde_json::json!({"id": node.id, "name": node.name, "owner": node.owner}),
                        ),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::UserAdd {
            request_id,
            username,
            password,
            role,
            admin,
        } => {
            if !principal.admin {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            let role = if admin || role == "admin" {
                "admin"
            } else {
                "user"
            };
            match hub.db.create_user(&username, &password, role).await {
                Ok(user) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(
                            request_id,
                            serde_json::json!({"username": user.username, "role": user.role}),
                        ),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::UserList { request_id } => {
            if !principal.admin {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            let users = hub.db.list_users().await?;
            let users = users
                .into_iter()
                .map(|user| UserInfo {
                    username: user.username,
                    role: user.role,
                    disabled: user.disabled,
                    created_unix: user.created_unix,
                    totp_enabled: user.totp_enabled,
                })
                .collect();
            send_out(tx, &Envelope::UserListed { request_id, users }).await
        }
        Envelope::UserPasswd {
            request_id,
            username,
            password,
        } => {
            if !principal.admin && username != principal.user {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            match hub.db.set_password(&username, &password).await {
                Ok(()) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::UserSetDisabled {
            request_id,
            username,
            disabled,
        } => {
            if !principal.admin {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            match hub.db.set_disabled(&username, disabled).await {
                Ok(()) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::UserRemove {
            request_id,
            username,
        } => {
            if !principal.admin {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            match hub.db.remove_user(&username).await {
                Ok(()) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::UserSetRole {
            request_id,
            username,
            role,
        } => {
            if !principal.admin {
                return send_out(
                    tx,
                    &Envelope::result_err(request_id, "admin token required"),
                )
                .await;
            }
            match hub.db.set_role(&username, &role).await {
                Ok(()) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::TotpBegin { request_id } => {
            if !principal.operator {
                return send_out(tx, &Envelope::result_err(request_id, "login required")).await;
            }
            match hub.db.begin_totp(&principal.user).await {
                Ok((secret, url)) => {
                    send_out(
                        tx,
                        &Envelope::TotpPending {
                            request_id,
                            secret,
                            url,
                        },
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::TotpConfirm { request_id, code } => {
            if !principal.operator {
                return send_out(tx, &Envelope::result_err(request_id, "login required")).await;
            }
            match hub.db.confirm_totp(&principal.user, &code).await {
                Ok(()) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::TotpDisable { request_id } => {
            if !principal.operator {
                return send_out(tx, &Envelope::result_err(request_id, "login required")).await;
            }
            match hub.db.disable_totp(&principal.user).await {
                Ok(()) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        Envelope::SetUserAudit {
            request_id,
            username,
            toml,
        } => {
            if !principal.operator && !principal.admin {
                return send_out(tx, &Envelope::result_err(request_id, "login required")).await;
            }
            let username = username.unwrap_or_else(|| principal.user.clone());
            if !principal.admin && username != principal.user {
                return send_out(tx, &Envelope::result_err(request_id, "not found")).await;
            }
            if let Err(err) = agentlink_core::audit::AuditPolicy::parse(&toml) {
                return send_out(tx, &Envelope::result_err(request_id, err.to_string())).await;
            }
            match hub.db.set_user_audit(&username, &toml).await {
                Ok(()) => {
                    send_out(
                        tx,
                        &Envelope::result_ok(request_id, serde_json::json!({"ok": true})),
                    )
                    .await
                }
                Err(err) => send_out(tx, &Envelope::result_err(request_id, err.to_string())).await,
            }
        }
        other => {
            tracing::debug!(
                kind = kind_name(&other),
                "ignoring unexpected client envelope"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod view_ticket_tests {
    use super::*;
    use agentlink_core::{PHASE2_INJECT_INPUT, PHASE2_SCREENSHOT};

    #[test]
    fn headless_nodes_cannot_mint_view_tickets() {
        assert!(headless_view_error("box", Some(true)).is_none());
        assert!(headless_view_error("box", None).is_none());
        let err = headless_view_error("example", Some(false)).expect("refused");
        assert!(err.contains("headless"), "{err}");
        assert!(err.contains("example"), "{err}");
        assert!(err.contains("shell") || err.contains("files"), "{err}");
    }

    #[test]
    fn offline_nodes_cannot_mint_view_tickets() {
        assert!(offline_view_error("box", true).is_none());
        let err = offline_view_error("probe", false).expect("refused");
        assert!(err.contains("offline"), "{err}");
        assert!(err.contains("probe"), "{err}");
    }

    fn ext(name: &str) -> Op {
        Op::Extension {
            name: name.into(),
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn view_ticket_can_signal_screenshot_or_input_and_the_grant_still_applies() {
        assert!(!view_ticket_may_invoke(&ext(PHASE3_WEBRTC_SIGNAL)));
        assert!(!view_ticket_may_invoke(&ext(PHASE2_SCREENSHOT)));
        assert!(!view_ticket_may_invoke(&ext(PHASE2_INJECT_INPUT)));
        assert!(!view_ticket_may_invoke(&Op::SysInfo));

        let view = NodePolicy::remote_view();
        assert!(view.allows(&ext(PHASE2_SCREENSHOT)).is_ok());
        assert!(view.allows(&ext(PHASE3_WEBRTC_SIGNAL)).is_ok());
        assert!(view.allows(&ext(PHASE2_INJECT_INPUT)).is_err());

        let control = NodePolicy::remote_control();
        assert!(control.allows(&ext(PHASE2_INJECT_INPUT)).is_ok());

        let shell = NodePolicy::exec();
        assert!(
            shell.allows(&ext(PHASE2_SCREENSHOT)).is_err(),
            "a grant without desktop or remote view still cannot screenshot"
        );
        assert!(shell.allows(&ext(PHASE3_WEBRTC_SIGNAL)).is_err());
    }

    fn record(session: Option<&str>) -> ViewTicketRecord {
        ViewTicketRecord {
            owner: "alice".into(),
            client_id: "web:alice".into(),
            node_id: "node".into(),
            grant: NodePolicy::remote_view(),
            expires_unix: 1_000,
            session: session.map(str::to_string),
        }
    }

    #[test]
    fn bare_ticket_is_single_use_and_the_bound_session_reconnects() {
        let mut ticket = record(None);
        let first = bind_view_ticket(&mut ticket, None, 500, "session-a").unwrap();
        assert_eq!(first.as_deref(), Some("session-a"));
        assert_eq!(
            bind_view_ticket(&mut ticket, None, 500, "session-b").unwrap_err(),
            "view ticket already used"
        );
        assert!(bind_view_ticket(&mut ticket, Some("session-a"), 500, "nope").is_ok());
        assert_eq!(
            bind_view_ticket(&mut ticket, Some("other"), 500, "nope").unwrap_err(),
            "view ticket already used"
        );
        assert!(!ticket_allows_ice(&ticket, None, 500));
        assert!(ticket_allows_ice(&ticket, Some("session-a"), 500));
        assert!(!ticket_allows_ice(&ticket, Some("session-a"), 1_000));

        let mut fresh = record(None);
        assert!(ticket_allows_ice(&fresh, None, 500));
        assert!(!ticket_allows_ice(&fresh, Some("early"), 500));
        let _ = bind_view_ticket(&mut fresh, None, 500, "s").unwrap();
    }

    #[test]
    fn desktop_links_default_to_view_only() {
        let full = clip_desktop_grant(NodePolicy::full(), false);
        assert!(full.allows_remote_view());
        assert!(!full.allows_remote_control());
        assert!(!full.allow_exec);
        assert!(!full.allow_write);
        assert!(full.allows(&ext(PHASE2_SCREENSHOT)).is_ok());
        assert!(full
            .allows(&ext(agentlink_core::PHASE2_INJECT_INPUT))
            .is_err());

        let control = clip_desktop_grant(NodePolicy::full(), true);
        assert!(control.allows_remote_control());
        assert!(control
            .allows(&ext(agentlink_core::PHASE2_INJECT_INPUT))
            .is_ok());
        assert!(!control.allow_exec);

        let view = clip_desktop_grant(NodePolicy::remote_view(), true);
        assert!(!view.allows_remote_control());
    }

    #[test]
    fn view_ticket_response_reports_the_clipped_grant() {
        let requested = clip_desktop_grant(NodePolicy::remote_view(), true);
        let (control, access) = web_ticket_fields(&requested);
        assert!(!control, "a view-only grant must not echo control:true");
        assert_eq!(access, "remote-view");

        let watch = clip_desktop_grant(NodePolicy::full(), false);
        let (control, access) = web_ticket_fields(&watch);
        assert!(!control);
        assert_eq!(access, "remote-view");

        let owned = clip_desktop_grant(NodePolicy::full(), true);
        let (control, access) = web_ticket_fields(&owned);
        assert!(control);
        assert_eq!(access, "remote-control");

        let none = clip_desktop_grant(NodePolicy::desktop(), true);
        let (control, access) = web_ticket_fields(&none);
        assert!(!control);
        assert_eq!(access, "none");
    }

    #[test]
    fn legacy_token_can_be_disabled_or_expired() {
        assert_eq!(
            legacy_gate_at(true, None, 10, 100).unwrap_err(),
            "legacy admin token requires AGENTLINK_LEGACY_ADMIN_TTL_SECS"
        );
        assert_eq!(
            legacy_gate_at(false, None, 10, 100).unwrap_err(),
            "legacy admin token is disabled"
        );
        assert!(legacy_gate_at(true, Some(30), 10, 40).is_ok());
        assert_eq!(
            legacy_gate_at(true, Some(30), 10, 41).unwrap_err(),
            "legacy admin token expired"
        );
        assert_eq!(
            legacy_gate_at(true, Some(0), 10, 10).unwrap_err(),
            "legacy admin token expired"
        );
        // A pre-existing token with no recorded mint time must not start a
        // new TTL window at "now".
        assert_eq!(
            legacy_gate_at(true, Some(86_400), 0, 1_700_000_000).unwrap_err(),
            "legacy admin token has no recorded creation time"
        );
    }

    #[test]
    fn legacy_admin_use_is_appended_to_the_hash_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        note_legacy_use(&path, true, "");
        note_legacy_use(&path, false, "legacy admin token is disabled");
        let records = read_audit(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].op, "legacy.admin");
        assert_eq!(records[1].op, "legacy.admin");
        assert_ne!(records[0].hash, "off");
        assert_eq!(records[1].prev_hash, records[0].hash);
        assert_eq!(records[1].result, "error");
        agentlink_core::audit::verify_chain(&records).unwrap();
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    fn net(cidr: &str) -> ipnet::IpNet {
        parse_proxy_cidr(cidr).unwrap()
    }

    fn peer(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    #[test]
    fn forwarded_headers_apply_only_from_a_trusted_proxy() {
        let trust = vec![net("127.0.0.1/32")];
        let tcp = peer("127.0.0.1:50000");
        let head = "GET /v1/connect HTTP/1.1\r\nX-Forwarded-For: 203.0.113.9\r\nX-Real-IP: 203.0.113.9\r\n\r\n";
        assert_eq!(
            resolve_audit_peer(tcp, head, &trust),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );

        let spoofed = peer("198.51.100.4:50000");
        assert_eq!(
            resolve_audit_peer(spoofed, head, &trust),
            spoofed.ip(),
            "an untrusted client cannot choose its audit address"
        );
        assert_eq!(resolve_audit_peer(tcp, head, &[]), tcp.ip());
    }

    #[test]
    fn forwarded_for_walks_past_trusted_proxies() {
        let trust = vec![net("127.0.0.0/8"), net("10.0.0.0/8")];
        let tcp = peer("127.0.0.1:1");
        let head = "GET / HTTP/1.1\r\nX-Forwarded-For: 203.0.113.8, 10.1.2.3\r\n\r\n";
        assert_eq!(
            resolve_audit_peer(tcp, head, &trust),
            "203.0.113.8".parse::<IpAddr>().unwrap()
        );

        let real = "GET / HTTP/1.1\r\nx-real-ip: 192.0.2.20\r\n\r\n";
        assert_eq!(
            resolve_audit_peer(tcp, real, &trust),
            "192.0.2.20".parse::<IpAddr>().unwrap()
        );

        let mapped = peer("[::ffff:127.0.0.1]:9");
        assert_eq!(
            resolve_audit_peer(mapped, head, &trust),
            "203.0.113.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn bare_ip_is_a_single_host_cidr() {
        let net = parse_proxy_cidr("127.0.0.1").unwrap();
        assert!(net.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!net.contains(&"127.0.0.2".parse::<IpAddr>().unwrap()));
        assert!(parse_proxy_cidr("not-a-cidr").is_err());
    }
}


#[cfg(test)]
mod peer_authz_tests {
    use super::peer_nodes_allowed;
    use crate::models::EnrolledNode;
    use agentlink_core::NodePolicy;

    fn node(owner: &str) -> EnrolledNode {
        EnrolledNode {
            id: format!("id-{owner}"),
            name: owner.into(),
            public_key_hex: "aa".repeat(32),
            policy: NodePolicy::full(),
            ceiling: NodePolicy::full(),
            hostname: "host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            version: "test".into(),
            enrolled_unix: 1,
            last_seen_unix: None,
            owner: owner.into(),
            has_display: None,
        }
    }

    #[test]
    fn peer_nodes_require_the_same_owner() {
        assert!(peer_nodes_allowed(&node("alice"), &node("alice")));
        assert!(!peer_nodes_allowed(&node("alice"), &node("bob")));
        assert!(peer_nodes_allowed(&node(""), &node("")));
        assert!(!peer_nodes_allowed(&node(""), &node("alice")));
    }
}

#[cfg(test)]
mod route_rebind_tests {
    use super::*;
    use crate::models::Caller;

    fn principal(user: &str) -> Principal {
        Principal {
            admin: false,
            operator: true,
            legacy: false,
            user: user.into(),
            role: "user".into(),
            device_id: "device".into(),
            access_hash: String::new(),
            client_id: format!("client-{user}"),
            name: "phone".into(),
            view: None,
            web: false,
            web_token: String::new(),
            view_session: None,
        }
    }

    fn meta(name: &str) -> NodeMeta {
        NodeMeta {
            name: name.into(),
            hostname: "host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            version: "test".into(),
            ceiling: NodePolicy::full(),
            has_display: None,
        }
    }

    fn e2e(request_id: &str, node_id: &str) -> Envelope {
        Envelope::E2e {
            request_id: request_id.into(),
            node_id: node_id.into(),
            client_id: String::new(),
            class: "exec".into(),
            terminal: false,
            body_b64: "aa".into(),
            user: None,
            device_id: None,
            relay_admin: true,
            relay_grant: Some(NodePolicy::full()),
        }
    }

    #[tokio::test]
    async fn existing_route_rejects_a_different_node() {
        let dir = tempfile::tempdir().unwrap();
        let relay = RelayHandle::spawn(RelayConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.path().join("relay"),
            capture: None,
            database_url: None,
            allow_signup: false,
            bootstrap_admin: false,
            db_schema: None,
            trust_proxy: Vec::new(),
            print_admin_token: false,
            legacy_admin_override: Some((true, Some(86_400))),
        })
        .await
        .unwrap();
        let hub = &relay.hub;
        hub.db
            .create_user("alice", "password-alice", "user")
            .await
            .unwrap();
        hub.db
            .create_user("bob", "password-bob", "user")
            .await
            .unwrap();
        let alice = hub
            .db
            .enroll_self(
                "alice",
                agentlink_core::Identity::generate().public_hex(),
                "alice-box",
                NodePolicy::full(),
                meta("alice-box"),
            )
            .await
            .unwrap();
        let bob = hub
            .db
            .enroll_self(
                "bob",
                agentlink_core::Identity::generate().public_hex(),
                "bob-box",
                NodePolicy::full(),
                meta("bob-box"),
            )
            .await
            .unwrap();
        hub.db
            .share(
                &Caller {
                    user: "bob".into(),
                    admin: false,
                },
                &bob.id,
                "alice",
                NodePolicy::read_only(),
            )
            .await
            .unwrap();

        let request_id = "req-existing".to_string();
        let (origin_tx, mut origin_rx) = mpsc::channel(4);
        let (target_tx, mut target_rx) = mpsc::channel(4);
        {
            let mut routes = lock_routes(hub).unwrap();
            routes.insert(
                request_id.clone(),
                Route {
                    origin_tx: origin_tx.clone(),
                    target_tx: target_tx.clone(),
                    origin_node: None,
                    target_node: bob.id.clone(),
                },
            );
        }

        route_e2e(
            hub,
            None,
            &origin_tx,
            Some(&principal("alice")),
            e2e(&request_id, &alice.id),
        )
        .await
        .unwrap();
        let denied = tokio::time::timeout(Duration::from_secs(2), origin_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let Outbound::Text(text) = denied else {
            panic!("expected a text refusal");
        };
        let env: Envelope = serde_json::from_str(&text).unwrap();
        match env {
            Envelope::Result {
                ok: false, error, ..
            } => {
                let error = error.unwrap_or_default();
                assert!(
                    error.contains("does not match"),
                    "rebinding must be rejected while the route still exists: {error}"
                );
                assert!(
                    !error.contains("no grant"),
                    "a no-grant result means the route was already gone: {error}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(
            target_rx.try_recv().is_err(),
            "the bound node must not receive a frame that names a different machine"
        );
        assert_eq!(
            route_target(hub, &request_id).unwrap().as_deref(),
            Some(bob.id.as_str())
        );

        route_e2e(
            hub,
            None,
            &origin_tx,
            Some(&principal("alice")),
            e2e(&request_id, &bob.id),
        )
        .await
        .unwrap();
        let forwarded = tokio::time::timeout(Duration::from_secs(2), target_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let Outbound::Text(text) = forwarded else {
            panic!("expected a forwarded frame");
        };
        let env: Envelope = serde_json::from_str(&text).unwrap();
        match env {
            Envelope::E2e {
                node_id,
                relay_admin,
                relay_grant,
                ..
            } => {
                assert_eq!(node_id, bob.id);
                assert!(!relay_admin, "the client-supplied admin bit must be cleared");
                assert_eq!(relay_grant, Some(NodePolicy::full()));
            }
            other => panic!("share should forward on the open route, got {other:?}"),
        }
        assert!(origin_rx.try_recv().is_err());

        route_e2e(
            hub,
            None,
            &origin_tx,
            Some(&principal("bob")),
            e2e(&request_id, &bob.name),
        )
        .await
        .unwrap();
        let owner = tokio::time::timeout(Duration::from_secs(2), target_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let Outbound::Text(text) = owner else {
            panic!("expected the owner frame");
        };
        let env: Envelope = serde_json::from_str(&text).unwrap();
        match env {
            Envelope::E2e {
                node_id,
                relay_grant,
                ..
            } => {
                assert_eq!(node_id, bob.id);
                assert_eq!(relay_grant, Some(NodePolicy::full()));
            }
            other => panic!("owner name should resolve to the bound node, got {other:?}"),
        }
    }
}
