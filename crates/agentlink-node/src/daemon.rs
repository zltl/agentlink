//! Outbound connection loop.

use std::collections::{BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use agentlink_core::confirm::{ConfirmPolicy, ConfirmRule};
use agentlink_core::e2e::Endpoint;
use agentlink_core::p2p::QuicPeer;
use agentlink_core::protocol::{Envelope, Op, Role, TransferMsg, PROTOCOL_VERSION};
use agentlink_core::sandbox::CommandPolicy;
use agentlink_core::tls;
use agentlink_core::ws::{self, Incoming, Outbound};
use agentlink_core::{Error, Identity, NodeExtension, NodePolicy, Result};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::pipeline::{self, AuditService};
use crate::proc::ProcManager;
use crate::watch::WatchManager;
use futures_util::{SinkExt, Stream, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use crate::audit;
use crate::ops::{dispatch, OpContext, Responder};
use crate::pty_session::PtyManager;
use crate::resume::{ReplayLog, ReplayOwner, Sessions, SocketSlot};
use crate::status::{self, LinkState};
use crate::transfer::{self, TransferHost, TunnelRegistry};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

static TEST_PING_MS: AtomicU64 = AtomicU64::new(0);
static TEST_DEAD_MS: AtomicU64 = AtomicU64::new(0);

/// Shorten the heartbeat and silence deadline for tests.
///
/// `None` restores the production values from [`agentlink_core::ws::heartbeat_interval`]
/// and [`agentlink_core::ws::silence_limit`]. Not read from `node.json`.
#[doc(hidden)]
pub fn set_liveness_for_test(ping_every: Option<Duration>, dead_after: Option<Duration>) {
    let millis = |value: Option<Duration>| value.map(|d| d.as_millis() as u64).unwrap_or(0);
    TEST_PING_MS.store(millis(ping_every), Ordering::SeqCst);
    TEST_DEAD_MS.store(millis(dead_after), Ordering::SeqCst);
}

fn override_duration(slot: &AtomicU64) -> Option<Duration> {
    let ms = slot.load(Ordering::SeqCst);
    if ms == 0 {
        None
    } else {
        Some(Duration::from_millis(ms))
    }
}

pub struct NodeConfig {
    pub relay_url: String,
    pub fingerprint: String,
    /// `system` or `webpki` when public roots are used in addition to, or
    /// instead of, [`Self::fingerprint`].
    pub trust: Option<String>,
    pub data_dir: PathBuf,
    pub name: String,
    pub pairing_token: Option<String>,
    pub root: Option<PathBuf>,
    pub max_policy: NodePolicy,
    pub version: String,
    pub extensions: Vec<Arc<dyn NodeExtension>>,
    /// Called with the effective policy after hello and after each policy update.
    pub policy_hook: Option<Arc<dyn Fn(NodePolicy) + Send + Sync>>,
    /// Shared with the desktop handlers. The recorder opens a session on it.
    pub capture: Option<Arc<dyn agentlink_desktop::ScreenCapture>>,
}

pub async fn run_until_signal(config: NodeConfig) -> Result<()> {
    let shutdown = CancellationToken::new();
    let cancel = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        cancel.cancel();
    });
    run(config, shutdown).await
}

pub async fn run(mut config: NodeConfig, shutdown: CancellationToken) -> Result<()> {
    agentlink_core::util::ensure_dir(&config.data_dir)?;
    // A second process on this data dir would dial with the same identity and
    // kick this socket. Hold the lock until `run` returns.
    let _node_lock = crate::lock::acquire_node_lock(&config.data_dir)?;
    if let Some(root) = &config.root {
        if !root.exists() {
            return Err(Error::Message(format!(
                "sandbox root does not exist: {}",
                root.display()
            )));
        }
    }
    persist_config(&config);
    let identity = Identity::load_or_create(&config.data_dir.join("identity.json"))?;
    tracing::info!(node_id = identity.node_id(), name = %config.name, "node identity ready");
    let endpoint = Endpoint::new(identity.clone());
    let service = AuditService::open(&config.data_dir, identity.node_id(), &config.name);
    match agentlink_core::grant::bootstrap_issuer_with_mode(&config.data_dir) {
        Ok(Some(issuer)) => tracing::info!(
            issuer = issuer.public_hex(),
            path = %config.data_dir.join(agentlink_core::grant::GRANT_ISSUER_FILE).display(),
            "created grant issuer; this node now requires owner-signed grants"
        ),
        Ok(None) => {}
        Err(err) => tracing::warn!(error = %err, "could not bootstrap grant issuer"),
    }
    let owner_keys = agentlink_core::grant::refresh_owner_keys(
        &config.data_dir,
        &std::collections::BTreeSet::new(),
    );
    if !owner_keys.is_empty() {
        tracing::info!(
            issuers = owner_keys.len(),
            "owner keys loaded; remote control needs a grant signed by one of them"
        );
    }
    let revoked_cache = Arc::new(RevokedJtiCache::new(config.data_dir.clone()));
    let revoked_initial = revoked_cache.current();
    if !revoked_initial.is_empty() {
        tracing::info!(
            jtis = revoked_initial.len(),
            "revoked grant jtis loaded; matching grants are rejected"
        );
    }
    let live = Arc::new(Live {
        endpoint,
        node_id: identity.node_id().to_string(),
        node_name: config.name.clone(),
        service: service.clone(),
        data_dir: config.data_dir.clone(),
        owner_keys: RwLock::new(owner_keys),
        revoked_cache,
        commands: load_commands(&config.data_dir),
        confirm: load_confirm(&config.data_dir),
        pending: Arc::new(Mutex::new(HashMap::new())),
        approvals: Arc::new(Mutex::new(HashMap::new())),
        procs: ProcManager::new(),
        watches: WatchManager::default(),
        tunnels: Arc::new(TunnelRegistry::default()),
        socket: Arc::new(SocketSlot::default()),
        sessions: Arc::new(Sessions::default()),
        pty: PtyManager::default(),
        cancels: Arc::new(Mutex::new(HashMap::new())),
        grant_sessions: Arc::new(Mutex::new(HashMap::new())),
        extensions: config.extensions.clone(),
    });
    wire_grant_hooks(&live);
    pipeline::spawn_recorder(service.clone(), config.capture.clone());

    // `--max-access` is this machine's ceiling. A grant cannot raise it,
    // and a relay policy update cannot either.
    let policy = Arc::new(RwLock::new(config.max_policy));
    let allowed = Arc::new(Mutex::new(HashMap::new()));
    // Direct offers are disabled (SEC-19 / DESK-24): do not bind or spawn the
    // dormant unauthenticated `0.0.0.0:0` QUIC listener.
    let quic: Option<Arc<QuicPeer>> = None;

    let mut backoff = agentlink_core::resume::Backoff::new();
    let mut fast = false;
    let node_id = identity.node_id().to_string();
    loop {
        if shutdown.is_cancelled() {
            publish_link(&config, &node_id, LinkState::Stopped, "", false);
            return Ok(());
        }
        publish_link(&config, &node_id, LinkState::Connecting, "", false);
        let started = Instant::now();
        match connect_once(
            &mut config,
            &identity,
            &shutdown,
            policy.clone(),
            allowed.clone(),
            quic.clone(),
            live.clone(),
        )
        .await
        {
            Ok(()) => {
                if shutdown.is_cancelled() {
                    publish_link(&config, &node_id, LinkState::Stopped, "", false);
                    return Ok(());
                }
                publish_link(
                    &config,
                    &node_id,
                    LinkState::Offline,
                    "connection closed",
                    false,
                );
            }
            // A handshake this process already dropped can still consume the
            // pairing token. The relay then has the node, so the next dial
            // should continue instead of stopping the daemon.
            Err(err) if err.is_fatal() && !err.to_string().contains("already used") => {
                publish_link(
                    &config,
                    &node_id,
                    LinkState::Offline,
                    &err.to_string(),
                    false,
                );
                return Err(err);
            }
            Err(err) => {
                if err.to_string().contains("going away") {
                    fast = true;
                }
                tracing::warn!(error = %err, "node connection ended; reconnecting");
                publish_link(
                    &config,
                    &node_id,
                    LinkState::Offline,
                    &err.to_string(),
                    false,
                );
            }
        }
        if started.elapsed() > Duration::from_secs(5) {
            backoff.reset();
        }
        let delay = if fast {
            fast = false;
            backoff.reset();
            Duration::from_millis(200)
        } else {
            backoff.next_delay()
        };
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

fn persist_config(config: &NodeConfig) {
    if let Err(err) = save_node_config(config) {
        tracing::warn!(error = %err, "could not write node.json");
    }
}

struct CancelEntry {
    token: CancellationToken,
    owner_peer: String,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
}

struct GrantSessionEntry {
    request_id: String,
    token: CancellationToken,
    grant_exp_unix: Option<i64>,
}

struct CachedRevoked {
    jtis: BTreeSet<String>,
    mtime: Option<SystemTime>,
    len: Option<u64>,
    last_check: Instant,
}

/// Cached view of `revoked-grants.json` backed by an `RwLock`, file metadata
/// (`mtime` + `len`), and an optional `notify` watcher. Avoids per-keystroke
/// disk reads and preserves the last-known-good set across transient Windows
/// replace-lock errors so live shells are never killed by a transient read error.
struct RevokedJtiCache {
    data_dir: PathBuf,
    state: RwLock<CachedRevoked>,
    dirty: Arc<AtomicBool>,
    _watcher: Option<RecommendedWatcher>,
}

impl RevokedJtiCache {
    const CHECK_INTERVAL: Duration = Duration::from_millis(250);

    fn new(data_dir: PathBuf) -> Self {
        let path = data_dir.join(agentlink_core::grant::REVOKED_GRANTS_FILE);
        let (mtime, len) = file_sig(&path);
        let initial =
            agentlink_core::grant::refresh_revoked_jtis(&data_dir, &BTreeSet::new());
        let dirty = Arc::new(AtomicBool::new(false));
        let dirty_cb = dirty.clone();
        let watcher = notify::recommended_watcher(
            move |res: std::result::Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    let relevant = event.paths.is_empty()
                        || event.paths.iter().any(|p| {
                            p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                                n.eq_ignore_ascii_case(agentlink_core::grant::REVOKED_GRANTS_FILE)
                                    || n.contains("revoked-grants")
                            })
                        });
                    if relevant {
                        dirty_cb.store(true, Ordering::Release);
                    }
                }
            },
        )
        .ok()
        .and_then(|mut w| {
            w.watch(&data_dir, RecursiveMode::NonRecursive).ok()?;
            Some(w)
        });
        Self {
            data_dir,
            state: RwLock::new(CachedRevoked {
                jtis: initial,
                mtime,
                len,
                last_check: Instant::now(),
            }),
            dirty,
            _watcher: watcher,
        }
    }

    fn current(&self) -> BTreeSet<String> {
        self.refresh(false)
    }

    fn current_forced(&self) -> BTreeSet<String> {
        self.refresh(true)
    }

    fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    fn is_active(&self, jti: &str) -> bool {
        let jti = jti.trim();
        if jti.is_empty() {
            return false;
        }
        if !self.dirty.load(Ordering::Acquire) {
            if let Ok(guard) = self.state.read() {
                if guard.last_check.elapsed() < Self::CHECK_INTERVAL {
                    return !guard
                        .jtis
                        .iter()
                        .any(|item| item.trim().eq_ignore_ascii_case(jti));
                }
            }
        }
        let revoked = self.refresh(false);
        !revoked
            .iter()
            .any(|item| item.trim().eq_ignore_ascii_case(jti))
    }

    fn refresh(&self, force: bool) -> BTreeSet<String> {
        let was_dirty = self.dirty.swap(false, Ordering::AcqRel);
        if !force && !was_dirty {
            if let Ok(guard) = self.state.read() {
                if guard.last_check.elapsed() < Self::CHECK_INTERVAL {
                    return guard.jtis.clone();
                }
            }
        }
        let path = self
            .data_dir
            .join(agentlink_core::grant::REVOKED_GRANTS_FILE);
        let (mtime, len) = file_sig(&path);
        if !force && !was_dirty {
            if let Ok(guard) = self.state.read() {
                if guard.mtime == mtime && guard.len == len {
                    let snapshot = guard.jtis.clone();
                    drop(guard);
                    if let Ok(mut w) = self.state.write() {
                        w.last_check = Instant::now();
                    }
                    return snapshot;
                }
            }
        }
        match agentlink_core::grant::load_revoked_jtis(&self.data_dir) {
            Ok(fresh) => {
                if let Ok(mut w) = self.state.write() {
                    w.jtis = fresh.clone();
                    w.mtime = mtime;
                    w.len = len;
                    w.last_check = Instant::now();
                }
                fresh
            }
            Err(_) => {
                // Transient Windows replace lock or partial write: keep last-good
                // set and mark dirty so the next check retries without killing
                // live shells.
                self.dirty.store(true, Ordering::Release);
                self.state
                    .read()
                    .map(|g| g.jtis.clone())
                    .unwrap_or_default()
            }
        }
    }
}

fn file_sig(path: &Path) -> (Option<SystemTime>, Option<u64>) {
    match std::fs::metadata(path) {
        Ok(meta) => (meta.modified().ok(), Some(meta.len())),
        Err(_) => (None, None),
    }
}

fn wire_grant_hooks(live: &Live) {
    let cache = live.revoked_cache.clone();
    let hook: Arc<dyn Fn(&str) -> bool + Send + Sync> =
        Arc::new(move |jti: &str| cache.is_active(jti));
    live.pty.set_grant_active(Some(hook.clone()));
    live.procs.set_grant_active(Some(hook.clone()));
    live.watches.set_grant_active(Some(hook.clone()));
    live.tunnels.set_grant_active(Some(hook));
}

struct Live {
    endpoint: Endpoint,
    node_id: String,
    node_name: String,
    service: Arc<AuditService>,
    /// Node data dir. Owner keys are reloaded from here before each authz
    /// decision so `grant trust-owner` applies without a restart.
    data_dir: PathBuf,
    /// Local issuer keys. Remote control is denied until one of these keys
    /// has signed a grant for the end-to-end peer. Relay stamps are not read.
    owner_keys: RwLock<BTreeSet<String>>,
    /// Cached revoked-jti deny-list with mtime + filesystem watcher.
    revoked_cache: Arc<RevokedJtiCache>,
    commands: CommandPolicy,
    confirm: ConfirmPolicy,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<Envelope>>>>,
    approvals: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    procs: ProcManager,
    watches: WatchManager,
    tunnels: Arc<TunnelRegistry>,
    socket: Arc<SocketSlot>,
    sessions: Arc<Sessions>,
    pty: PtyManager,
    cancels: Arc<Mutex<HashMap<String, CancelEntry>>>,
    /// jti -> in-flight request entries. Pruned on completion and cancelled on
    /// local revoke or expiry.
    grant_sessions: Arc<Mutex<HashMap<String, Vec<GrantSessionEntry>>>>,
    extensions: Vec<Arc<dyn NodeExtension>>,
}

impl Live {
    /// Reload `owner-keys.json` and update the cache. Falls back to the last
    /// good set when the file is unreadable.
    fn current_owner_keys(&self) -> BTreeSet<String> {
        let cached = self
            .owner_keys
            .read()
            .map(|keys| keys.clone())
            .unwrap_or_default();
        let fresh = agentlink_core::grant::refresh_owner_keys(&self.data_dir, &cached);
        if let Ok(mut guard) = self.owner_keys.write() {
            *guard = fresh.clone();
        }
        fresh
    }

    /// Return the cached revoked-jti set, refreshing on mtime/watcher changes
    /// while preserving last-good entries on transient lock errors.
    fn current_revoked_jtis(&self) -> BTreeSet<String> {
        self.revoked_cache.current()
    }
}

struct ApprovalGuard {
    approvals: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    approval_id: String,
}

impl Drop for ApprovalGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.approvals.lock() {
            map.remove(&self.approval_id);
        }
    }
}

struct GrantSessionGuard {
    grant_sessions: Arc<Mutex<HashMap<String, Vec<GrantSessionEntry>>>>,
    jti: Option<String>,
    request_id: String,
}

impl Drop for GrantSessionGuard {
    fn drop(&mut self) {
        let Some(ref jti) = self.jti else {
            return;
        };
        if let Ok(mut map) = self.grant_sessions.lock() {
            if let Some(entries) = map.get_mut(jti) {
                entries.retain(|entry| entry.request_id != self.request_id);
                if entries.is_empty() {
                    map.remove(jti);
                }
            }
        }
    }
}

struct CancelGuard {
    cancels: Arc<Mutex<HashMap<String, CancelEntry>>>,
    request_id: String,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.cancels.lock() {
            map.remove(&self.request_id);
        }
    }
}

/// Write `node.json`. The pairing token stays here, mode 0600, until enrollment
/// succeeds. Service units point at `--data-dir` and do not embed the token.
pub fn save_node_config(config: &NodeConfig) -> Result<()> {
    #[derive(serde::Serialize)]
    struct Disk<'a> {
        name: &'a str,
        relay_url: &'a str,
        fingerprint: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        trust: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        root: Option<&'a std::path::Path>,
        max_policy: NodePolicy,
        #[serde(skip_serializing_if = "Option::is_none")]
        pairing_token: Option<&'a str>,
    }
    let disk = Disk {
        name: &config.name,
        relay_url: &config.relay_url,
        fingerprint: &config.fingerprint,
        trust: config.trust.as_deref().filter(|value| !value.is_empty()),
        root: config.root.as_deref(),
        max_policy: config.max_policy,
        pairing_token: config
            .pairing_token
            .as_deref()
            .filter(|token| !token.is_empty()),
    };
    let path = config.data_dir.join("node.json");
    agentlink_core::util::write_secret(&path, serde_json::to_string_pretty(&disk)?.as_bytes())?;
    Ok(())
}

fn publish_link(
    config: &NodeConfig,
    node_id: &str,
    state: LinkState,
    detail: &str,
    just_enrolled: bool,
) {
    let previous = status::read_status(&config.data_dir).ok();
    let token_pending = config
        .pairing_token
        .as_deref()
        .is_some_and(|token| !token.trim().is_empty());
    let enrolled = if token_pending && !just_enrolled {
        false
    } else {
        just_enrolled || previous.as_ref().is_some_and(|status| status.enrolled)
    };
    let mut detail = detail.to_string();
    if detail.chars().count() > 400 {
        detail = detail.chars().take(400).collect();
        detail.push('…');
    }
    let status = status::LinkStatus {
        state,
        detail,
        relay_url: config.relay_url.clone(),
        name: config.name.clone(),
        node_id: node_id.to_string(),
        enrolled,
        pid: std::process::id(),
        updated_unix: status::unix_now(),
    };
    if let Err(err) = status::write_status(&config.data_dir, &status) {
        tracing::debug!(error = %err, "could not write status.json");
    }
}

/// Persist a loopback leaf the relay presented in place of the stored pin.
fn note_adopted_leaf(config: &mut NodeConfig, adopted: Option<&tls::AdoptedLeaf>) {
    let Some(pin) = adopted.and_then(tls::AdoptedLeaf::get) else {
        return;
    };
    apply_refreshed_fingerprint(config, &pin);
}

fn apply_refreshed_fingerprint(config: &mut NodeConfig, pin: &str) {
    if pin == config.fingerprint || tls::parse_fingerprint(pin).is_err() {
        return;
    }
    tracing::warn!(
        relay = %config.relay_url,
        old = %config.fingerprint,
        new = %pin,
        "loopback relay certificate changed; stored leaf pin updated. The connection stays on this machine, so the node adopts the presented certificate instead of staying offline. Remote relays are left unchanged"
    );
    config.fingerprint = pin.to_string();
    if let Err(err) = save_node_config(config) {
        tracing::warn!(error = %err, "could not write the refreshed fingerprint to node.json");
    }
}

fn clear_saved_pairing_token(data_dir: &std::path::Path) -> Result<()> {
    let path = data_dir.join("node.json");
    let text = std::fs::read_to_string(&path)?;
    let mut value: serde_json::Value = serde_json::from_str(&text)?;
    let Some(obj) = value.as_object_mut() else {
        return Ok(());
    };
    if obj.remove("pairing_token").is_none() {
        return Ok(());
    }
    agentlink_core::util::write_secret(&path, serde_json::to_string_pretty(&value)?.as_bytes())?;
    Ok(())
}

async fn connect_once(
    config: &mut NodeConfig,
    identity: &Identity,
    shutdown: &CancellationToken,
    policy: Arc<RwLock<NodePolicy>>,
    allowed: Arc<Mutex<HashMap<String, Instant>>>,
    quic: Option<Arc<QuicPeer>>,
    live: Arc<Live>,
) -> Result<()> {
    let relay = agentlink_core::parse_relay_url(&config.relay_url)?;
    let trust = tls::RelayTrust::parse(&config.fingerprint, config.trust.as_deref())?;
    let addr = relay.dial_label();
    let tcp = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((relay.host.as_str(), relay.port)),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Message(format!("connect relay {addr}: {e}")))?;
    tcp.set_nodelay(true).ok();
    ws::arm_tcp_liveness(&tcp);
    // A stale leaf pin on loopback used to fail every handshake. The process
    // stayed up and the link stayed offline. Adopt the presented leaf only
    // when both the configured host and this socket's peer are loopback.
    let adopt = tls::adopt_loopback_leaf(&relay.host, tcp.peer_addr().ok());
    let dial = tls::client_config_for_dial(&trust, adopt)?;
    let connector = tokio_rustls::TlsConnector::from(dial.config);
    let server_name = tls::server_name(&relay.host, &trust)?;
    let tls = timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Tls(e.to_string()))?;
    note_adopted_leaf(config, dial.adopted_leaf.as_deref());

    let ws_url = format!("ws://{}:{}{}", relay.bracket_host(), relay.port, relay.path);
    let (mut ws, _) = timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::client_async_with_config(ws_url, tls, Some(ws::ws_config())),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Ws(e.to_string()))?;

    let hello = Envelope::Hello {
        role: Role::Node,
        protocol: PROTOCOL_VERSION,
        token: None,
        node_id: Some(identity.node_id().to_string()),
        public_key: Some(identity.public_hex().to_string()),
        name: Some(config.name.clone()),
        pairing_token: config.pairing_token.clone(),
        hostname: Some(host_name()),
        os: Some(std::env::consts::OS.to_string()),
        arch: Some(std::env::consts::ARCH.to_string()),
        version: Some(config.version.clone()),
        ceiling: Some(config.max_policy),
        has_display: Some(agentlink_desktop::has_display()),
    };
    ws.send(Message::Text(serde_json::to_string(&hello)?.into()))
        .await
        .map_err(|e| Error::Ws(e.to_string()))?;

    let challenge = next_env(&mut ws).await?;
    let nonce = match challenge {
        Envelope::Challenge { nonce } => nonce,
        Envelope::HelloErr { message, fatal } => {
            return if fatal {
                Err(Error::Auth(message))
            } else {
                Err(Error::Message(message))
            };
        }
        other => {
            return Err(Error::Protocol(format!(
                "expected challenge, got {other:?}"
            )));
        }
    };
    let signature = identity.sign_nonce(&nonce);
    ws.send(Message::Text(
        serde_json::to_string(&Envelope::Authenticate { signature })?.into(),
    ))
    .await
    .map_err(|e| Error::Ws(e.to_string()))?;

    let welcome = next_env(&mut ws).await?;
    let (policy_now, heartbeat_secs) = match welcome {
        Envelope::HelloOk {
            policy,
            heartbeat_secs,
            ..
        } => {
            // The relay's stored preset is not a cap and cannot raise the
            // local ceiling.
            let _pushed = policy;
            (config.max_policy, heartbeat_secs)
        }
        Envelope::HelloErr { message, fatal } => {
            return if fatal {
                Err(Error::Auth(message))
            } else {
                Err(Error::Message(message))
            };
        }
        other => {
            return Err(Error::Protocol(format!("expected hello_ok, got {other:?}")));
        }
    };
    if let Ok(mut guard) = policy.write() {
        *guard = policy_now;
    }
    if let Some(hook) = &config.policy_hook {
        hook(policy_now);
    }

    tracing::info!(
        name = %config.name,
        access = policy_now.preset_name(),
        "node online"
    );
    // Enrollment succeeded. Drop the one-time token so a later restart does
    // not keep it on disk, and so this process does not present it again.
    config.pairing_token = None;
    if let Err(err) = clear_saved_pairing_token(&config.data_dir) {
        tracing::warn!(error = %err, "could not clear pairing token from node.json");
    }
    publish_link(config, identity.node_id(), LinkState::Online, "", true);
    live.service.submit(audit::event_for(
        "auth",
        "connect",
        identity.node_id(),
        &config.relay_url,
        serde_json::json!({"detail": config.relay_url}),
        true,
        None,
        Duration::ZERO,
    ));

    let (sink, mut stream) = ws.split();
    let (tx, rx) = mpsc::channel(256);
    let generation = live.socket.attach(tx.clone());
    spawn_grant_watch(live.clone(), generation);
    // The write task used to be detached. If it stopped, or if a proxy ACKed
    // bytes the relay never saw, `stream.next` waited forever and the process
    // stayed "online" in its own log while the relay had already dropped it.
    let writer = ws::WriterTask::spawn(sink, rx, shutdown.clone());
    let dead_after = silence_after(heartbeat_secs);
    // The relay marks a node offline when it has not received a frame for
    // `RELAY_STALE_AFTER` (75s), even if this WebSocket is still established.
    // `Envelope::Ping` keeps that bit fresh. `dead_after` is the other
    // direction: no inbound frame (including the relay's `Pong`) means the
    // session is half-dead and we redial.
    let _heartbeat = StopHeartbeat(spawn_presence_heartbeat(
        tx.clone(),
        shutdown,
        heartbeat_secs,
    ));

    let cancels = live.cancels.clone();
    let pty = live.pty.clone();
    let extensions = config.extensions.clone();
    live.service.set_tx(Some(tx.clone()));
    let host = Arc::new(TransferHost {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        direct_wait: Arc::new(Mutex::new(HashMap::new())),
        allowed,
        quic,
        tx: tx.clone(),
        policy: policy.clone(),
        max_policy: config.max_policy,
        root: config.root.clone(),
        e2e: live.endpoint.clone(),
        node_id: live.node_id.clone(),
        seals: Arc::new(Mutex::new(HashMap::new())),
        pending: live.pending.clone(),
        audit: live.service.clone(),
        tunnels: live.tunnels.clone(),
    });

    let end = loop {
        match ws::wait_for_frame(&mut stream, dead_after, shutdown, writer.stopped()).await {
            Err(err) => break SessionEnd::Dead(err),
            Ok(ws::FrameWait::Shutdown) => break SessionEnd::Shutdown,
            Ok(ws::FrameWait::Silent) => {
                break SessionEnd::Dead(Error::Message(format!(
                    "websocket silent for {}s; relay heartbeat was not answered",
                    dead_after.as_secs().max(1)
                )));
            }
            Ok(ws::FrameWait::WriterStopped) => {
                break SessionEnd::Dead(Error::Message(
                    "websocket writer stopped; connection is no longer usable".into(),
                ));
            }
            Ok(ws::FrameWait::Eof) => break SessionEnd::Closed,
            Ok(ws::FrameWait::Message(msg)) => match ws::parse_incoming(msg) {
                Err(err) => break SessionEnd::Dead(err),
                Ok(Incoming::Env(Envelope::GoingAway { .. })) => {
                    break SessionEnd::Dead(Error::Message("relay going away".into()));
                }
                Ok(Incoming::Env(env)) => {
                    handle_env(
                        env,
                        &tx,
                        &policy,
                        &cancels,
                        &pty,
                        config,
                        &extensions,
                        &host,
                        &live,
                    )
                    .await;
                }
                Ok(Incoming::Binary(bytes)) => transfer::on_binary(&host, bytes),
                Ok(Incoming::Ping(payload)) => {
                    let _ = tx.try_send(Outbound::Pong(payload));
                }
                Ok(Incoming::Closed { .. }) => break SessionEnd::Closed,
                Ok(Incoming::Ignore) => {}
            },
        }
    };
    match end {
        SessionEnd::Shutdown => {
            cancel_all(&cancels);
            stop_live_sessions(&live);
            Ok(())
        }
        SessionEnd::Closed => {
            stop_live_sessions(&live);
            release_link(&live, generation);
            Ok(())
        }
        SessionEnd::Dead(err) => {
            stop_live_sessions(&live);
            release_link(&live, generation);
            Err(err)
        }
    }
}

enum SessionEnd {
    Shutdown,
    Closed,
    Dead(Error),
}

fn release_link(live: &Arc<Live>, generation: u64) {
    live.socket.detach(generation);
    live.service.set_tx(None);
    schedule_idle_cleanup(live.clone(), generation);
}

fn schedule_idle_cleanup(live: Arc<Live>, generation: u64) {
    let cancels = live.cancels.clone();
    let socket = live.socket.clone();
    tokio::spawn(async move {
        tokio::time::sleep(agentlink_core::resume::RECONNECT_GIVE_UP).await;
        if socket.generation() == generation {
            stop_live_sessions(&live);
            cancel_all(&cancels);
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn handle_env(
    env: Envelope,
    tx: &mpsc::Sender<Outbound>,
    policy: &Arc<RwLock<NodePolicy>>,
    cancels: &Arc<Mutex<HashMap<String, CancelEntry>>>,
    pty: &PtyManager,
    config: &NodeConfig,
    extensions: &[Arc<dyn NodeExtension>],
    host: &Arc<TransferHost>,
    live: &Arc<Live>,
) {
    if live.revoked_cache.is_dirty() {
        enforce_live_grants(live, false);
    }
    if let Envelope::E2eWelcome { request_id, .. } = &env {
        if let Some(waiter) = live
            .pending
            .lock()
            .ok()
            .and_then(|mut map| map.remove(request_id))
        {
            let _ = waiter.send(env);
            return;
        }
    }
    let (env, seal, relay_admin, relay_grant) = match env {
        Envelope::E2eHello {
            request_id,
            message_b64,
            ..
        } => {
            let Ok(bytes) = agentlink_core::util::b64_decode(&message_b64) else {
                return;
            };
            match live.endpoint.accept(&bytes) {
                Ok((_, welcome)) => {
                    let env = Envelope::E2eWelcome {
                        request_id,
                        node_id: live.node_id.clone(),
                        message_b64: agentlink_core::util::b64_encode(&welcome),
                    };
                    if let Ok(out) = ws::encode(&env) {
                        let _ = tx.send(out).await;
                    }
                }
                Err(err) => {
                    tracing::debug!(error = %err, "e2e hello rejected");
                }
            }
            return;
        }
        Envelope::E2e {
            client_id,
            node_id: e2e_node_id,
            body_b64,
            request_id,
            relay_admin,
            relay_grant,
            user,
            device_id,
            ..
        } => {
            let Ok(bytes) = agentlink_core::util::b64_decode(&body_b64) else {
                return;
            };
            // Prefer client_id (client→node). Fall back to node_id so a node that
            // initiated PeerCopy e2e can decrypt the peer's sealed Accept/frames.
            let (opened, session, peer) = match live.endpoint.open_routed(
                &client_id,
                &e2e_node_id,
                request_id.as_bytes(),
                &bytes,
            ) {
                Ok(triple) => triple,
                Err(err) => {
                    tracing::warn!(error = %err, "e2e open failed");
                    let reset = Envelope::result_err(request_id, "e2e session reset");
                    if let Ok(out) = ws::encode(&reset) {
                        let _ = tx.send(out).await;
                    }
                    return;
                }
            };
            let Ok(mut inner) = serde_json::from_slice::<Envelope>(&opened) else {
                return;
            };
            if let Envelope::Invoke {
                client_id: client_slot,
                user: slot,
                device_id: device_slot,
                ..
            } = &mut inner
            {
                // The inner client_id is writable by the sealed peer. Always
                // overwrite it with the key that opened the body.
                *client_slot = peer.clone();
                if slot.is_none() {
                    *slot = user;
                }
                if device_slot.is_none() {
                    *device_slot = device_id;
                }
            }
            (
                inner,
                Some(crate::ops::ResponseSeal {
                    peer,
                    node_id: live.node_id.clone(),
                    session,
                }),
                relay_admin,
                relay_grant,
            )
        }
        other => (other, None, true, None),
    };
    match env {
        Envelope::Ping => {
            let _ = tx.try_send(Outbound::Text(
                serde_json::to_string(&Envelope::Pong).unwrap_or_default(),
            ));
        }
        Envelope::Pong => {}
        Envelope::AuditPolicyPush { toml } => {
            let current = live.service.policy();
            match current.apply_untrusted_relay_push(&toml) {
                Ok(None) => {
                    tracing::info!("ignoring relay audit policy because lock_local is set");
                }
                Ok(Some(sanitized)) => {
                    match sanitized.to_toml() {
                        Ok(clean_toml) => {
                            if let Err(err) =
                                std::fs::write(config.data_dir.join("audit.toml"), clean_toml)
                            {
                                tracing::warn!(error = %err, "could not save pushed audit policy");
                            }
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "could not serialize pushed audit policy");
                        }
                    }
                    live.service.replace_policy(sanitized, true);
                }
                Err(err) => tracing::warn!(error = %err, "rejected relay audit policy push"),
            }
        }
        Envelope::ApprovalDecision { approval_id, allow } => {
            if let Some(waiter) = live
                .approvals
                .lock()
                .ok()
                .and_then(|mut map| map.remove(&approval_id))
            {
                let _ = waiter.send(allow);
            }
        }
        Envelope::PolicyUpdate { policy: next } => {
            let _pushed = next;
            let effective = config.max_policy;
            if let Ok(mut guard) = policy.write() {
                *guard = effective;
            }
            if let Some(hook) = &config.policy_hook {
                hook(effective);
            }
            tracing::info!(access = effective.preset_name(), "policy updated");
        }
        Envelope::Session { cursors, .. } => {
            // SEC-01: Only accept session cursor updates from an authenticated
            // E2E peer, bound to that peer's own requests with live grants.
            let Some(seal_ref) = seal.as_ref() else {
                tracing::debug!("ignoring unsealed plaintext Session cursor update");
                return;
            };
            let pairs: Vec<(String, u64)> = cursors
                .into_iter()
                .map(|cursor| (cursor.request_id, cursor.seq))
                .collect();
            let revoked = live.current_revoked_jtis();
            let now = agentlink_core::util::unix_now();
            live.sessions
                .note_cursors_for(&seal_ref.peer, &pairs, &revoked, now);
        }
        Envelope::Cancel { request_id, .. } => {
            // SEC-01 / SEC-08: Reject unsealed Cancel and verify owner + live
            // grant before cancelling an op or aborting portal ScreenCast pickers.
            let Some(seal_ref) = seal.as_ref() else {
                tracing::warn!(%request_id, "ignoring unsealed plaintext Cancel");
                return;
            };
            let revoked = live.current_revoked_jtis();
            let now = agentlink_core::util::unix_now();
            let known = if let Ok(map) = cancels.lock() {
                if let Some(entry) = map.get(&request_id) {
                    let owner_ok = entry.owner_peer == seal_ref.peer;
                    let expired = entry.grant_exp_unix.is_some_and(|exp| now >= exp);
                    let jti = entry.grant_jti.trim();
                    let is_revoked = !jti.is_empty()
                        && revoked
                            .iter()
                            .any(|item| item.trim().eq_ignore_ascii_case(jti));
                    if owner_ok && !expired && !is_revoked {
                        entry.token.cancel();
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };
            if known {
                tracing::info!(
                    %request_id,
                    "received authenticated Cancel; aborting op and closing live portal ScreenCast handles"
                );
                agentlink_desktop::abort_live_portal_pickers();
            } else {
                tracing::debug!(%request_id, "ignoring Cancel with no matching owner entry");
            }
        }
        Envelope::Invoke {
            request_id,
            op,
            client_id,
            grant,
            authz,
            user,
            device_id,
            ..
        } => {
            // SEC-01: Reject unsealed plaintext Invoke BEFORE touching
            // `sessions.existing()`, `sessions.begin()`, or `cancels`.
            let Some(seal_ref) = seal.as_ref() else {
                let deny = Envelope::result_err(
                    request_id,
                    "control requires an end-to-end session; plaintext relay invokes are disabled",
                );
                if let Ok(out) = ws::encode(&deny) {
                    let _ = tx.send(out).await;
                }
                return;
            };
            // The deny-list is a file on this machine. A remote revoke, even
            // inside a sealed session, would let a controller edit that list.
            if let Op::RevokeGrant { .. } = &op {
                send_sealed_err(
                    seal_ref,
                    request_id,
                    "grant list is local to this node; revoke on the node host",
                    tx,
                )
                .await;
                return;
            }
            // The peer is the key that opened the sealed body, not the
            // client_id the relay wrote on the outer envelope.
            let grantee = seal_ref.peer.clone();
            let _relay_says = (&client_id, relay_admin, relay_grant);
            let ceiling = policy.read().ok().map(|g| *g);
            let Some(ceiling) = ceiling else {
                send_sealed_err(seal_ref, request_id, "node policy is unavailable", tx).await;
                return;
            };
            let now = agentlink_core::util::unix_now();
            let owner_keys = live.current_owner_keys();
            let revoked_jtis = live.current_revoked_jtis();
            // SEC-01: Check replay BEFORE starting a new session, but ONLY
            // after verifying `seal.is_some()`, `seal.peer == owner_peer`, and
            // live grant validity (both stored grant and current authz).
            if let Some(log) = live.sessions.existing(&request_id) {
                if !log.owner().is_valid_for(&grantee, &revoked_jtis, now) {
                    tracing::warn!(
                        %request_id,
                        peer = %grantee,
                        "replay log access rejected: owner mismatch or inactive grant"
                    );
                    send_sealed_err(
                        seal_ref,
                        request_id,
                        "replay denied: peer mismatch or grant inactive",
                        tx,
                    )
                    .await;
                    return;
                }
                if let Err(err) = agentlink_core::grant::resolve_e2e_policy(
                    &owner_keys,
                    &revoked_jtis,
                    authz.as_ref(),
                    &live.node_id,
                    &grantee,
                    now,
                    ceiling,
                    false,
                    None,
                    grant,
                ) {
                    tracing::warn!(
                        error = %err,
                        %request_id,
                        peer = %grantee,
                        "replay log authz rejected"
                    );
                    send_sealed_err(seal_ref, request_id, err.to_string(), tx).await;
                    return;
                }
                replay_log(
                    &log,
                    live.sessions.cursor_for(&grantee, &request_id),
                    seal_ref,
                    tx,
                )
                .await;
                return;
            }
            let policy_now = match agentlink_core::grant::resolve_e2e_policy(
                &owner_keys,
                &revoked_jtis,
                authz.as_ref(),
                &live.node_id,
                &grantee,
                now,
                ceiling,
                false,
                None,
                grant,
            ) {
                Ok(policy) => policy.intersect(config.max_policy),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        client_id = %client_id,
                        node_id = %live.node_id,
                        "e2e authz rejected"
                    );
                    send_sealed_err(seal_ref, request_id, err.to_string(), tx).await;
                    return;
                }
            };
            let grant_jti = authz.as_ref().map(|g| g.jti.clone());
            let grant_exp_unix = authz.as_ref().and_then(|g| g.effective_exp_unix());
            let owner = ReplayOwner {
                owner_peer: grantee.clone(),
                grant_jti: grant_jti.clone().unwrap_or_default(),
                grant_exp_unix,
            };
            let Some(log) = live.sessions.begin_for(&request_id, owner) else {
                return;
            };
            live.service.touch();
            if matches!(
                op,
                Op::Extension { ref name, .. }
                    if name == "screenshot" || name == "inject_input"
            ) {
                // JPEG fallback stays on this invoke. An agent session seals it.
                // WebRTC picture bytes are DTLS-SRTP and are a different path.
                live.service.touch_gui();
            }
            let token = CancellationToken::new();
            if let Ok(mut map) = cancels.lock() {
                map.insert(
                    request_id.clone(),
                    CancelEntry {
                        token: token.clone(),
                        owner_peer: grantee.clone(),
                        grant_jti: grant_jti.clone().unwrap_or_default(),
                        grant_exp_unix,
                    },
                );
            }
            if let Some(ref jti) = grant_jti {
                if let Ok(mut sessions) = live.grant_sessions.lock() {
                    sessions
                        .entry(jti.clone())
                        .or_default()
                        .push(GrantSessionEntry {
                            request_id: request_id.clone(),
                            token: token.clone(),
                            grant_exp_unix,
                        });
                }
            }
            let extra = Arc::new(Mutex::new(pipeline::AuditExtra::default()));
            let resp = Responder {
                socket: live.socket.clone(),
                request_id: request_id.clone(),
                seal: Some(seal_ref.clone()),
                extra,
                log,
            };
            let confirm_hit = confirm_match_op(&live.confirm, &op, config.root.as_deref());
            let confirm_wait = confirm_hit.map(|(category, raw_summary)| {
                let approval_id = Uuid::new_v4().to_string();
                let (wait_tx, wait_rx) = oneshot::channel();
                if let Ok(mut map) = live.approvals.lock() {
                    map.insert(approval_id.clone(), wait_tx);
                }
                let summary = live.service.policy().redact.apply(&raw_summary);
                let expires = agentlink_core::util::unix_now() + live.confirm.timeout_secs as i64;
                let note = Envelope::ApprovalRequest {
                    request_id: request_id.clone(),
                    approval_id: approval_id.clone(),
                    node_id: live.node_id.clone(),
                    client_id: client_id.clone(),
                    category,
                    summary,
                    expires_unix: expires,
                };
                let timeout_secs = live.confirm.timeout_secs.max(1);
                (approval_id, note, wait_rx, timeout_secs)
            });

            // DESK-20: Pre-enqueue PtyInput / PtyResize synchronously in wire
            // arrival order into the bounded per-session channel when no
            // approval wait is pending, so concurrent `tokio::spawn` scheduling
            // can never scramble keystrokes or resizes.
            let pre_enqueued_pty = if confirm_wait.is_none() && policy_now.allows(&op).is_ok() {
                match &op {
                    Op::PtyInput {
                        session_id,
                        data_b64,
                    } => agentlink_core::util::b64_decode(data_b64)
                        .ok()
                        .and_then(|bytes| pty.enqueue_write(session_id, bytes, &grantee).ok()),
                    Op::PtyResize {
                        session_id,
                        rows,
                        cols,
                    } => pty.enqueue_resize(session_id, *rows, *cols, &grantee).ok(),
                    _ => None,
                }
            } else {
                None
            };

            let root = config.root.clone();
            let audit_path = config.data_dir.join("audit.log");
            let pty = pty.clone();
            let extensions = extensions.to_vec();
            let cancels = cancels.clone();
            let grant_sessions = live.grant_sessions.clone();
            let approvals_map = live.approvals.clone();
            let commands = live.commands.clone();
            let procs = live.procs.clone();
            let watches = live.watches.clone();
            let node_name = live.node_name.clone();
            let node_id = live.node_id.clone();
            let audit = live.service.clone();
            let peer_id = grantee;
            let tx = tx.clone();
            tokio::spawn(async move {
                let _cancel_guard = CancelGuard {
                    cancels,
                    request_id: request_id.clone(),
                };
                let _grant_guard = GrantSessionGuard {
                    grant_sessions,
                    jti: grant_jti.clone(),
                    request_id: request_id.clone(),
                };
                if let Some((approval_id, note, wait_rx, timeout_secs)) = confirm_wait {
                    let _approval_guard = ApprovalGuard {
                        approvals: approvals_map,
                        approval_id: approval_id.clone(),
                    };
                    if let Ok(out) = ws::encode(&note) {
                        let _ = tx.send(out).await;
                    }
                    let allowed = tokio::select! {
                        _ = token.cancelled() => false,
                        res = tokio::time::timeout(
                            std::time::Duration::from_secs(timeout_secs),
                            wait_rx,
                        ) => matches!(res, Ok(Ok(true))),
                    };
                    if !allowed {
                        let _ = resp.err("approval denied or timed out").await;
                        audit.submit(audit::event_for(
                            "approval",
                            "approval",
                            &client_id,
                            &approval_id,
                            serde_json::json!({"detail": approval_id, "allow": false}),
                            false,
                            Some("denied or timed out".into()),
                            Duration::ZERO,
                        ));
                        return;
                    }
                }
                dispatch(
                    op,
                    resp,
                    token,
                    OpContext {
                        root: root.as_deref(),
                        policy: policy_now,
                        extensions: &extensions,
                        pty: &pty,
                        procs: &procs,
                        watches: &watches,
                        audit_path: &audit_path,
                        client_id: &client_id,
                        node_name: &node_name,
                        node_id: &node_id,
                        commands: &commands,
                        audit: audit.clone(),
                        user: user.clone(),
                        device_id: device_id.clone(),
                        peer_id: &peer_id,
                        grant_jti: grant_jti.as_deref(),
                        grant_exp_unix,
                        pty_ticket: pre_enqueued_pty,
                    },
                )
                .await;
            });
        }
        Envelope::Result {
            request_id,
            ok: false,
            error,
            ..
        } => {
            transfer::fail_session(
                host,
                &request_id,
                error.unwrap_or_else(|| "transfer rejected".into()),
            );
        }
        Envelope::Transfer {
            request_id,
            client_id,
            msg,
            authz,
            ..
        } => {
            let Some(seal_ref) = seal.as_ref() else {
                let deny = Envelope::result_err(
                    request_id,
                    "control requires an end-to-end session; plaintext relay transfers are disabled",
                );
                if let Ok(out) = ws::encode(&deny) {
                    let _ = tx.send(out).await;
                }
                return;
            };
            let session = Some(seal_ref.session.clone());
            let grantee = seal_ref.peer.clone();
            let _relay_says = (&client_id, relay_admin, relay_grant);
            let owner_keys = live.current_owner_keys();
            let policy_now = {
                let Some(ceiling) = policy.read().ok().map(|g| *g) else {
                    tracing::error!("node policy lock poisoned; denying transfer");
                    return;
                };
                let revoked_jtis = live.current_revoked_jtis();
                match agentlink_core::grant::resolve_e2e_policy(
                    &owner_keys,
                    &revoked_jtis,
                    authz.as_ref(),
                    &live.node_id,
                    &grantee,
                    agentlink_core::util::unix_now(),
                    ceiling,
                    false,
                    None,
                    None,
                ) {
                    Ok(policy) => Some(policy.intersect(config.max_policy)),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            client_id = %client_id,
                            node_id = %live.node_id,
                            "e2e transfer authz rejected"
                        );
                        send_sealed_err(seal_ref, request_id, err.to_string(), tx).await;
                        return;
                    }
                }
            };
            let grant_jti = authz
                .as_ref()
                .map(|g| g.jti.clone())
                .unwrap_or_default();
            let grant_exp_unix = authz.as_ref().and_then(|g| g.effective_exp_unix());

            // SEC-10: Evaluate `confirm.toml` uniformly on Transfer writes
            // (`Push`, `PushStream`, `PushDir`) before starting the transfer.
            let is_existing_session = host
                .sessions
                .lock()
                .ok()
                .is_some_and(|map| map.contains_key(&request_id));
            let confirm_hit = if is_existing_session {
                None
            } else {
                confirm_match_transfer(&live.confirm, &msg, config.root.as_deref())
            };
            if let Some((category, raw_summary)) = confirm_hit {
                let approval_id = Uuid::new_v4().to_string();
                let (wait_tx, wait_rx) = oneshot::channel();
                if let Ok(mut map) = live.approvals.lock() {
                    map.insert(approval_id.clone(), wait_tx);
                }
                let summary = live.service.policy().redact.apply(&raw_summary);
                let timeout_secs = live.confirm.timeout_secs.max(1);
                let expires = agentlink_core::util::unix_now() + timeout_secs as i64;
                let note = Envelope::ApprovalRequest {
                    request_id: request_id.clone(),
                    approval_id: approval_id.clone(),
                    node_id: live.node_id.clone(),
                    client_id: client_id.clone(),
                    category,
                    summary,
                    expires_unix: expires,
                };
                let token = CancellationToken::new();
                if let Ok(mut map) = cancels.lock() {
                    map.insert(
                        request_id.clone(),
                        CancelEntry {
                            token: token.clone(),
                            owner_peer: grantee.clone(),
                            grant_jti: grant_jti.clone(),
                            grant_exp_unix,
                        },
                    );
                }
                let tracked_jti = (!grant_jti.is_empty()).then(|| grant_jti.clone());
                if let Some(ref jti) = tracked_jti {
                    if let Ok(mut sessions) = live.grant_sessions.lock() {
                        sessions
                            .entry(jti.clone())
                            .or_default()
                            .push(GrantSessionEntry {
                                request_id: request_id.clone(),
                                token: token.clone(),
                                grant_exp_unix,
                            });
                    }
                }
                let approvals_map = live.approvals.clone();
                let cancels_bg = cancels.clone();
                let grant_sessions = live.grant_sessions.clone();
                let audit = live.service.clone();
                let host_bg = host.clone();
                let tx_bg = tx.clone();
                let seal_owned = seal_ref.clone();
                tokio::spawn(async move {
                    let _cancel_guard = CancelGuard {
                        cancels: cancels_bg,
                        request_id: request_id.clone(),
                    };
                    let _grant_guard = GrantSessionGuard {
                        grant_sessions,
                        jti: tracked_jti,
                        request_id: request_id.clone(),
                    };
                    let _approval_guard = ApprovalGuard {
                        approvals: approvals_map,
                        approval_id: approval_id.clone(),
                    };
                    if let Ok(out) = ws::encode(&note) {
                        let _ = tx_bg.send(out).await;
                    }
                    let allowed = tokio::select! {
                        _ = token.cancelled() => false,
                        res = tokio::time::timeout(
                            std::time::Duration::from_secs(timeout_secs),
                            wait_rx,
                        ) => matches!(res, Ok(Ok(true))),
                    };
                    if !allowed {
                        let failed = Envelope::Transfer {
                            request_id: request_id.clone(),
                            node_id: seal_owned.node_id.clone(),
                            client_id: client_id.clone(),
                            terminal: true,
                            msg: TransferMsg::Failed {
                                message: "approval denied or timed out".into(),
                            },
                            authz: None,
                        };
                        if let Ok(wrapped) = agentlink_core::e2e::seal_envelope_session(
                            &seal_owned.session,
                            &seal_owned.node_id,
                            &client_id,
                            &failed,
                        ) {
                            if let Ok(out) = ws::encode(&wrapped) {
                                let _ = tx_bg.send(out).await;
                            }
                        }
                        audit.submit(audit::event_for(
                            "approval",
                            "approval",
                            &client_id,
                            &approval_id,
                            serde_json::json!({"detail": approval_id, "allow": false}),
                            false,
                            Some("denied or timed out".into()),
                            Duration::ZERO,
                        ));
                        return;
                    }
                    transfer::on_transfer(
                        host_bg,
                        request_id,
                        client_id,
                        grantee,
                        msg,
                        session,
                        policy_now,
                        grant_jti,
                        grant_exp_unix,
                    )
                    .await;
                });
                return;
            }
            transfer::on_transfer(
                host.clone(),
                request_id,
                client_id,
                grantee,
                msg,
                session,
                policy_now,
                grant_jti,
                grant_exp_unix,
            )
            .await;
        }
        offer @ Envelope::DirectOffer { .. } => transfer::on_direct_offer(host, offer).await,
        answer @ Envelope::DirectAnswer { .. } => transfer::on_direct_answer(host, answer),
        other => {
            tracing::debug!(?other, "ignoring envelope");
        }
    }
}

async fn send_sealed_err(
    seal: &crate::ops::ResponseSeal,
    request_id: String,
    message: impl Into<String>,
    tx: &mpsc::Sender<Outbound>,
) {
    let deny = Envelope::result_err(request_id, message);
    let encoded = match agentlink_core::e2e::seal_envelope_session(
        &seal.session,
        &seal.node_id,
        &seal.peer,
        &deny,
    ) {
        Ok(wrapped) => ws::encode(&wrapped),
        Err(_) => return,
    };
    if let Ok(out) = encoded {
        let _ = tx.send(out).await;
    }
}

fn spawn_grant_watch(live: Arc<Live>, generation: u64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if live.socket.generation() != generation {
                break;
            }
            enforce_live_grants(&live, true);
        }
    });
}

fn stop_live_sessions(live: &Live) {
    live.pty.close_all();
    live.procs.close_all();
    live.watches.close_all();
    live.tunnels.close_all();
    let _ = agentlink_desktop::close_all_streams(&live.extensions);
    if let Ok(mut sessions) = live.grant_sessions.lock() {
        for (_jti, inflight) in sessions.drain() {
            for entry in inflight {
                entry.token.cancel();
            }
        }
    }
}

/// Walk live WebRTC/PTY/Proc/Watch/Tunnel sessions by the grant metadata they
/// stored at creation. This is not keyed off the inflight RPC index, so a
/// session inserted after a jti is dropped from `grant_sessions` is still
/// closed, and a disconnect with no further inbound frames still tears down
/// every grant-scoped resource on the independent watcher.
fn enforce_live_grants(live: &Live, force_refresh: bool) {
    let revoked = if force_refresh {
        live.revoked_cache.current_forced()
    } else {
        live.current_revoked_jtis()
    };
    let now = agentlink_core::util::unix_now();
    live.pty.close_inactive(&revoked);
    live.pty.close_expired();
    live.procs.close_inactive(&revoked);
    live.procs.close_expired();
    live.watches.close_inactive(&revoked);
    live.watches.close_expired();
    live.tunnels.close_inactive(&revoked);
    live.tunnels.close_expired();
    live.sessions.drop_inactive(&revoked, now);
    let _ = agentlink_desktop::close_inactive_streams(&live.extensions);
    let _ = agentlink_desktop::close_expired_streams(&live.extensions);
    if let Ok(mut sessions) = live.grant_sessions.lock() {
        sessions.retain(|jti, inflight| {
            let jti_revoked = revoked
                .iter()
                .any(|item| item.trim().eq_ignore_ascii_case(jti.trim()));
            if jti_revoked {
                for entry in inflight.drain(..) {
                    entry.token.cancel();
                }
                return false;
            }
            inflight.retain(|entry| {
                let expired = entry.grant_exp_unix.is_some_and(|exp| now >= exp);
                if expired {
                    entry.token.cancel();
                    false
                } else {
                    true
                }
            });
            !inflight.is_empty()
        });
    }
}

/// Replay retained frames for an authenticated E2E session. Plaintext replay
/// is intentionally impossible by construction (`seal` is non-optional).
async fn replay_log(
    log: &ReplayLog,
    cursor: u64,
    seal: &crate::ops::ResponseSeal,
    tx: &mpsc::Sender<Outbound>,
) {
    for env in log.snapshot() {
        if env.seq() != 0 && env.seq() <= cursor {
            continue;
        }
        let wrapped = match agentlink_core::e2e::seal_envelope_session(
            &seal.session,
            &seal.node_id,
            &seal.peer,
            &env,
        ) {
            Ok(wrapped) => wrapped,
            Err(err) => {
                tracing::debug!(error = %err, "replay seal failed");
                continue;
            }
        };
        if let Ok(out) = ws::encode(&wrapped) {
            if tx.send(out).await.is_err() {
                break;
            }
        }
    }
}

fn cancel_all(cancels: &Mutex<HashMap<String, CancelEntry>>) {
    if let Ok(map) = cancels.lock() {
        for entry in map.values() {
            entry.token.cancel();
        }
    }
}

/// Normalize a path lexically (resolving `.` and `..` and standardizing slashes)
/// against optional sandbox `root` so `confirm.toml` `outside = "/work"` cannot
/// be bypassed with `/work/../etc/passwd`.
fn normalize_confirm_path(root: Option<&Path>, raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let resolved = agentlink_core::paths::resolve_lexical(root, trimmed)
        .unwrap_or_else(|_| PathBuf::from(trimmed));
    let mut clean = PathBuf::new();
    for comp in resolved.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                clean.pop();
            }
            other => clean.push(other),
        }
    }
    agentlink_core::paths::normalize_path_text(&clean.to_string_lossy())
}

fn confirm_path_inside(root: Option<&Path>, prefix: &str, path: &str) -> bool {
    let norm_prefix = normalize_confirm_path(root, prefix)
        .trim_end_matches('/')
        .to_string();
    let norm_path = normalize_confirm_path(root, path);
    if norm_prefix.is_empty() || norm_path.is_empty() {
        return false;
    }
    if cfg!(windows) {
        norm_path.eq_ignore_ascii_case(&norm_prefix)
            || norm_path
                .to_ascii_lowercase()
                .starts_with(&format!("{}/", norm_prefix.to_ascii_lowercase()))
    } else {
        norm_path == norm_prefix || norm_path.starts_with(&format!("{norm_prefix}/"))
    }
}

/// Evaluate `confirm.toml` on an `Op`, covering `Replace`, `EditLines`,
/// `ApplyPatch`, both `Rename` endpoints, and normalized `outside` paths in
/// addition to `ConfirmPolicy::matching`.
fn confirm_match_op(
    policy: &ConfirmPolicy,
    op: &Op,
    root: Option<&Path>,
) -> Option<(String, String)> {
    if matches!(op, Op::RevokeGrant { .. }) {
        return None;
    }
    if let Some(rule) = policy.matching(op) {
        return Some((rule.category.clone(), ConfirmPolicy::summary(op)));
    }
    let summary = match op {
        Op::Replace { path, .. } => format!("replace {path}"),
        Op::EditLines { path, .. } => format!("edit_lines {path}"),
        Op::ApplyPatch { root: patch_root, .. } => format!("apply_patch {patch_root}"),
        _ => ConfirmPolicy::summary(op),
    };
    let paths_for_op: Vec<&str> = match op {
        Op::WriteFile { path, .. }
        | Op::Mkdir { path, .. }
        | Op::Remove { path, .. }
        | Op::Replace { path, .. }
        | Op::EditLines { path, .. } => vec![path.as_str()],
        Op::ApplyPatch { root: patch_root, .. } => vec![patch_root.as_str()],
        Op::Rename { from, to } => vec![from.as_str(), to.as_str()],
        Op::Exec { cwd: Some(c), .. } | Op::BgStart { cwd: Some(c), .. } => vec![c.as_str()],
        _ => Vec::new(),
    };
    let is_write = matches!(
        op,
        Op::WriteFile { .. }
            | Op::Mkdir { .. }
            | Op::Rename { .. }
            | Op::Replace { .. }
            | Op::EditLines { .. }
            | Op::ApplyPatch { .. }
    );
    let is_remove = matches!(op, Op::Remove { .. });
    let is_recursive_remove = matches!(op, Op::Remove { recursive: true, .. });
    for rule in &policy.rules {
        let cat = rule.category.to_ascii_lowercase();
        let cat_ok = cat == "any"
            || (is_write && cat == "write")
            || (is_remove && (cat == "remove" || cat == "delete"));
        if !cat_ok {
            continue;
        }
        if rule.recursive && !is_recursive_remove {
            continue;
        }
        if let Some(prefix) = &rule.outside {
            if paths_for_op.is_empty()
                || paths_for_op
                    .iter()
                    .all(|p| confirm_path_inside(root, prefix, p))
            {
                continue;
            }
        }
        if rule.pattern.is_empty() || agentlink_core::sandbox::glob_match(&rule.pattern, &summary) {
            return Some((rule.category.clone(), summary));
        }
    }
    None
}

/// Evaluate `confirm.toml` on write-mutating `Envelope::Transfer` messages
/// (`Push`, `PushStream`, `PushDir`, and `PeerCopy`).
fn confirm_match_transfer(
    policy: &ConfirmPolicy,
    msg: &TransferMsg,
    root: Option<&Path>,
) -> Option<(String, String)> {
    let (summary, target_path) = match msg {
        TransferMsg::Push { path, .. } => (format!("push {path}"), path.as_str()),
        TransferMsg::PushStream { path, .. } => (format!("push_stream {path}"), path.as_str()),
        TransferMsg::PushDir { dest, .. } => (format!("push_dir {dest}"), dest.as_str()),
        TransferMsg::PeerCopy { dst_path, .. } => (format!("peer_copy {dst_path}"), dst_path.as_str()),
        _ => return None,
    };
    for rule in &policy.rules {
        if transfer_rule_matches(rule, &summary, target_path, root) {
            return Some((rule.category.clone(), summary));
        }
    }
    None
}

fn transfer_rule_matches(
    rule: &ConfirmRule,
    summary: &str,
    target_path: &str,
    root: Option<&Path>,
) -> bool {
    let cat = rule.category.to_ascii_lowercase();
    if !matches!(cat.as_str(), "any" | "write" | "transfer") {
        return false;
    }
    if rule.recursive {
        return false;
    }
    if let Some(prefix) = &rule.outside {
        if target_path.is_empty() || confirm_path_inside(root, prefix, target_path) {
            return false;
        }
    }
    rule.pattern.is_empty() || agentlink_core::sandbox::glob_match(&rule.pattern, summary)
}

async fn next_env<S>(stream: &mut S) -> Result<Envelope>
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let msg = timeout(Duration::from_secs(10), async {
        loop {
            let msg = stream
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
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(msg)
}

fn load_commands(dir: &std::path::Path) -> CommandPolicy {
    let Ok(text) = std::fs::read_to_string(dir.join("limits.json")) else {
        return CommandPolicy::baseline();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return CommandPolicy::baseline();
    };
    let list = |key: &str| {
        value
            .get(key)
            .and_then(|item| item.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    CommandPolicy {
        allow: list("allow"),
        deny: list("deny"),
    }
}

fn load_confirm(dir: &std::path::Path) -> ConfirmPolicy {
    let path = dir.join("confirm.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ConfirmPolicy::baseline();
    };
    let mut policy = toml::from_str(&text).unwrap_or_else(|_| ConfirmPolicy::baseline());
    let mut changed = agentlink_core::confirm::migrate_broad_dev_patterns(&mut policy);
    changed |= agentlink_core::confirm::migrate_rm_split_flag_patterns(&mut policy);
    if changed {
        if let Ok(serialized) = toml::to_string_pretty(&policy) {
            let _ = std::fs::write(&path, serialized.as_bytes());
        }
    }
    policy
}

fn host_name() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into())
}

/// How often to send [`Envelope::Ping`] after `HelloOk`.
///
/// Tests can shorten this. Production follows [`ws::heartbeat_interval`].
fn presence_interval(heartbeat_secs: u64) -> Duration {
    override_duration(&TEST_PING_MS).unwrap_or_else(|| ws::heartbeat_interval(heartbeat_secs))
}

/// How long to wait for any inbound frame before redialing.
fn silence_after(heartbeat_secs: u64) -> Duration {
    override_duration(&TEST_DEAD_MS).unwrap_or_else(|| ws::silence_limit(heartbeat_secs))
}

fn spawn_presence_heartbeat(
    tx: mpsc::Sender<Outbound>,
    shutdown: &CancellationToken,
    heartbeat_secs: u64,
) -> CancellationToken {
    let stop = CancellationToken::new();
    let beat_stop = stop.clone();
    let beat_shutdown = shutdown.clone();
    let period = presence_interval(heartbeat_secs);
    tracing::debug!(secs = period.as_secs(), "node presence heartbeat");
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick completes immediately. Connect just refreshed presence.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = beat_stop.cancelled() => break,
                _ = beat_shutdown.cancelled() => break,
                _ = ticker.tick() => {
                    let Ok(out) = ws::encode(&Envelope::Ping) else { break };
                    if tx.send(out).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    stop
}

struct StopHeartbeat(CancellationToken);

impl Drop for StopHeartbeat {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_token_is_removed_after_clear() {
        let dir = tempfile::tempdir().unwrap();
        let config = NodeConfig {
            relay_url: "wss://relay.example:7443".into(),
            fingerprint: "sha256:ab".into(),
            trust: None,
            data_dir: dir.path().to_path_buf(),
            name: "box".into(),
            pairing_token: Some("sekret".into()),
            root: None,
            max_policy: NodePolicy::exec(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        };
        save_node_config(&config).unwrap();
        let text = std::fs::read_to_string(dir.path().join("node.json")).unwrap();
        assert!(text.contains("sekret"), "{text}");
        clear_saved_pairing_token(dir.path()).unwrap();
        let text = std::fs::read_to_string(dir.path().join("node.json")).unwrap();
        assert!(!text.contains("sekret"), "{text}");
        assert!(text.contains("box"), "{text}");
    }

    #[test]
    fn status_file_sticks_enrolled_and_omits_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig {
            relay_url: "wss://relay.example.com".into(),
            fingerprint: String::new(),
            trust: Some("system+webpki".into()),
            data_dir: dir.path().to_path_buf(),
            name: "laptop".into(),
            pairing_token: Some("sekret".into()),
            root: None,
            max_policy: NodePolicy::exec(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        };
        publish_link(&config, "node-id", LinkState::Connecting, "", false);
        let status = status::read_status(dir.path()).unwrap();
        assert!(!status.enrolled);
        assert_eq!(status.state, LinkState::Connecting);
        let text = std::fs::read_to_string(dir.path().join("status.json")).unwrap();
        assert!(!text.contains("sekret"), "{text}");
        config.pairing_token = None;
        publish_link(&config, "node-id", LinkState::Online, "", true);
        let status = status::read_status(dir.path()).unwrap();
        assert!(status.enrolled);
        assert_eq!(status.state, LinkState::Online);
        publish_link(&config, "node-id", LinkState::Offline, "reset", false);
        let status = status::read_status(dir.path()).unwrap();
        assert!(status.enrolled);
        assert_eq!(status.state, LinkState::Offline);
        assert_eq!(status.detail, "reset");
    }

    #[test]
    fn presence_interval_follows_hello_ok_and_stays_inside_the_stale_window() {
        assert_eq!(presence_interval(20), Duration::from_secs(20));
        assert_eq!(presence_interval(0), Duration::from_secs(20));
        assert_eq!(presence_interval(5), Duration::from_secs(5));
        assert_eq!(presence_interval(1), Duration::from_secs(1));
        // Relay STALE_AFTER is 75s. A longer advertisement still refreshes sooner.
        assert_eq!(presence_interval(120), Duration::from_secs(30));
        assert!(presence_interval(20) < Duration::from_secs(75));
        assert_eq!(silence_after(20), Duration::from_secs(50));
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                set_liveness_for_test(None, None);
            }
        }
        let _reset = Reset;
        set_liveness_for_test(
            Some(Duration::from_millis(200)),
            Some(Duration::from_secs(1)),
        );
        assert_eq!(presence_interval(20), Duration::from_millis(200));
        assert_eq!(silence_after(20), Duration::from_secs(1));
    }

    #[test]
    fn refreshed_loopback_pin_is_written_and_a_bad_pin_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig {
            relay_url: "wss://127.0.0.1:7443".into(),
            fingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
            trust: None,
            data_dir: dir.path().to_path_buf(),
            name: "example".into(),
            pairing_token: Some("sekret".into()),
            root: None,
            max_policy: NodePolicy::exec(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        };
        save_node_config(&config).unwrap();
        apply_refreshed_fingerprint(&mut config, "not-a-fingerprint");
        let text = std::fs::read_to_string(dir.path().join("node.json")).unwrap();
        assert!(text.contains("sha256:bbbb"), "{text}");
        assert!(text.contains("sekret"), "{text}");
        let fresh = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        apply_refreshed_fingerprint(&mut config, fresh);
        assert_eq!(config.fingerprint, fresh);
        let text = std::fs::read_to_string(dir.path().join("node.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["fingerprint"], fresh);
        assert_eq!(value["name"], "example");
        assert_eq!(value["pairing_token"], "sekret");
        apply_refreshed_fingerprint(&mut config, fresh);
        assert_eq!(config.fingerprint, fresh);
    }

    #[test]
    fn node_dials_the_scheme_default_port() {
        let url = agentlink_core::parse_relay_url("wss://relay.example.com").unwrap();
        assert_eq!(url.port, 443);
        let explicit = agentlink_core::parse_relay_url("wss://relay.example.com:443").unwrap();
        assert_eq!(explicit.port, 443);
        let bare = agentlink_core::parse_relay_url("relay.example.com").unwrap();
        assert_eq!(bare.port, 7443);
    }

    fn test_live(dir: &std::path::Path, extensions: Vec<Arc<dyn NodeExtension>>) -> Arc<Live> {
        let identity = Identity::generate();
        let live = Arc::new(Live {
            endpoint: Endpoint::new(identity.clone()),
            node_id: identity.node_id().to_string(),
            node_name: "box".into(),
            service: AuditService::open_quiet(dir, identity.node_id(), "box"),
            data_dir: dir.to_path_buf(),
            owner_keys: RwLock::new(Default::default()),
            revoked_cache: Arc::new(RevokedJtiCache::new(dir.to_path_buf())),
            commands: CommandPolicy::baseline(),
            confirm: ConfirmPolicy::baseline(),
            pending: Arc::new(Mutex::new(HashMap::new())),
            approvals: Arc::new(Mutex::new(HashMap::new())),
            procs: ProcManager::new(),
            watches: WatchManager::default(),
            tunnels: Arc::new(TunnelRegistry::default()),
            socket: Arc::new(SocketSlot::default()),
            sessions: Arc::new(Sessions::default()),
            pty: PtyManager::default(),
            cancels: Arc::new(Mutex::new(HashMap::new())),
            grant_sessions: Arc::new(Mutex::new(HashMap::new())),
            extensions,
        });
        wire_grant_hooks(&live);
        live
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_grant_watch_stops_pty_and_stream_within_one_second() {
        let dir = tempfile::tempdir().unwrap();
        let stream = Arc::new(agentlink_desktop::StreamHandler::new(
            agentlink_desktop::Desktop::mock(),
        ));
        {
            let data = dir.path().to_path_buf();
            stream.set_grant_active(Some(Arc::new(move |jti: &str, _peer: &str| {
                match agentlink_core::grant::load_revoked_jtis(&data) {
                    Ok(revoked) => !revoked
                        .iter()
                        .any(|item| item.trim().eq_ignore_ascii_case(jti.trim())),
                    Err(_) => false,
                }
            })));
        }
        let live = test_live(
            dir.path(),
            vec![stream.clone() as Arc<dyn NodeExtension>],
        );
        live.pty.set_grant_active(Some({
            let data = dir.path().to_path_buf();
            Arc::new(move |jti: &str| {
                match agentlink_core::grant::load_revoked_jtis(&data) {
                    Ok(revoked) => !revoked
                        .iter()
                        .any(|item| item.trim().eq_ignore_ascii_case(jti.trim())),
                    Err(_) => false,
                }
            })
        }));

        let (resp, _hold) = {
            let resp = Responder {
                socket: live.socket.clone(),
                request_id: Uuid::new_v4().to_string(),
                seal: None,
                extra: Arc::new(Mutex::new(crate::pipeline::AuditExtra::default())),
                log: Arc::new(ReplayLog::default()),
            };
            (resp, dir.path().to_path_buf())
        };
        let origin = crate::audit::Origin {
            path: dir.path().join("audit.log"),
            node: "box".into(),
            node_id: live.node_id.clone(),
        };
        let sid = live
            .pty
            .open(
                Some("cat".into()),
                None,
                24,
                80,
                resp,
                origin,
                Some("alice".into()),
                live.service.clone(),
                "alice",
                "jti-watch",
                None,
            )
            .await
            .expect("open cat pty");
        assert!(live.pty.has_session(&sid));
        stream
            .insert_test_grant_session("stream-1", "alice", "jti-watch", None)
            .expect("inject stream");
        assert!(stream.test_session_is_live("stream-1"));
        assert!(
            live.grant_sessions
                .lock()
                .map(|map| map.is_empty())
                .unwrap_or(false),
            "this coverage must not use the inflight RPC index"
        );

        // Production timer: first tick is immediate (sessions still valid),
        // later ticks are 1s. No further inbound frames.
        spawn_grant_watch(live.clone(), live.socket.generation());
        let mut revoked = std::collections::BTreeSet::new();
        revoked.insert("jti-watch".into());
        agentlink_core::grant::save_revoked_jtis(dir.path(), &revoked).unwrap();

        let started = Instant::now();
        let deadline = started + Duration::from_millis(1500);
        loop {
            let pty_live = live.pty.has_session(&sid);
            let stream_live = stream.test_session_is_live("stream-1");
            if !pty_live && !stream_live {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "grant watch must stop the PTY and stream within 1s without an RPC index (pty_live={pty_live}, stream_live={stream_live}, elapsed={:?})",
                    started.elapsed()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            started.elapsed() <= Duration::from_millis(1500),
            "elapsed {:?}",
            started.elapsed()
        );

        // Post-create race: a session opened under a just-revoked jti is
        // either rejected by the open re-check or closed by the same watcher
        // without a new inbound frame.
        let (resp2, _dir2_keep) = {
            let resp = Responder {
                socket: live.socket.clone(),
                request_id: Uuid::new_v4().to_string(),
                seal: None,
                extra: Arc::new(Mutex::new(crate::pipeline::AuditExtra::default())),
                log: Arc::new(ReplayLog::default()),
            };
            (resp, ())
        };
        let origin2 = crate::audit::Origin {
            path: dir.path().join("audit.log"),
            node: "box".into(),
            node_id: live.node_id.clone(),
        };
        let opened = live
            .pty
            .open(
                Some("cat".into()),
                None,
                24,
                80,
                resp2,
                origin2,
                Some("alice".into()),
                live.service.clone(),
                "alice",
                "jti-watch",
                None,
            )
            .await;
        match opened {
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("revoked") || msg.contains("not found"),
                    "post-create re-check must fail closed, got {msg}"
                );
            }
            Ok(sid2) => {
                let started = Instant::now();
                let deadline = started + Duration::from_millis(1500);
                while live.pty.has_session(&sid2) {
                    if Instant::now() >= deadline {
                        panic!(
                            "post-create revoked PTY must be closed by the production watch within 1s"
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        let _ = live.pty.close_all();
    }

    #[tokio::test]
    async fn plaintext_and_cross_peer_replay_oracle_and_cancel_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let live = test_live(dir.path(), Vec::new());
        let issuer = Identity::generate();
        let mut owners = BTreeSet::new();
        owners.insert(issuer.public_hex().to_string());
        agentlink_core::grant::save_owner_keys(dir.path(), &owners).unwrap();
        *live.owner_keys.write().unwrap() = owners;

        let alice_id = Identity::generate();
        let alice_ep = Endpoint::new(alice_id.clone());
        let pending_a = alice_ep.client_hello_v2(&live.node_id).unwrap();
        let (_, welcome_a) = live
            .endpoint
            .accept(Endpoint::hello_bytes(&pending_a))
            .unwrap();
        alice_ep.complete(pending_a, &welcome_a).unwrap();

        let bob_id = Identity::generate();
        let bob_ep = Endpoint::new(bob_id.clone());
        let pending_b = bob_ep.client_hello(&live.node_id).unwrap();
        let (_, welcome_b) = live
            .endpoint
            .accept(Endpoint::hello_bytes(&pending_b))
            .unwrap();
        bob_ep.complete(pending_b, &welcome_b).unwrap();

        // Seed a retained replay log containing sensitive E2E output owned by Alice.
        let req_id = Uuid::new_v4().to_string();
        let now = agentlink_core::util::unix_now();
        let log = live
            .sessions
            .begin_for(
                &req_id,
                ReplayOwner {
                    owner_peer: alice_id.public_hex().to_string(),
                    grant_jti: "jti-alice".into(),
                    grant_exp_unix: Some(now + 600),
                },
            )
            .expect("begin_for");
        log.push(Envelope::Chunk {
            request_id: req_id.clone(),
            stream: "stdout".into(),
            data_b64: agentlink_core::util::b64_encode(b"TOP_SECRET_E2E_STDOUT"),
            seq: 0,
        });
        log.push(Envelope::End {
            request_id: req_id.clone(),
            exit_code: Some(0),
            error: None,
            seq: 0,
        });

        let cancel_tok = CancellationToken::new();
        live.cancels.lock().unwrap().insert(
            req_id.clone(),
            CancelEntry {
                token: cancel_tok.clone(),
                owner_peer: alice_id.public_hex().to_string(),
                grant_jti: "jti-alice".into(),
                grant_exp_unix: Some(now + 600),
            },
        );

        let (tx, mut rx) = mpsc::channel(16);
        let policy = Arc::new(RwLock::new(NodePolicy::full()));
        let config = NodeConfig {
            relay_url: "wss://127.0.0.1:7443".into(),
            fingerprint: String::new(),
            trust: None,
            data_dir: dir.path().to_path_buf(),
            name: "box".into(),
            pairing_token: None,
            root: None,
            max_policy: NodePolicy::full(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        };
        let host = Arc::new(TransferHost {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            direct_wait: Arc::new(Mutex::new(HashMap::new())),
            allowed: Arc::new(Mutex::new(HashMap::new())),
            quic: None,
            tx: tx.clone(),
            policy: policy.clone(),
            max_policy: NodePolicy::full(),
            root: None,
            e2e: live.endpoint.clone(),
            node_id: live.node_id.clone(),
            seals: Arc::new(Mutex::new(HashMap::new())),
            pending: live.pending.clone(),
            audit: live.service.clone(),
            tunnels: live.tunnels.clone(),
        });

        // 1. Plaintext Invoke replay-log oracle attack MUST NOT leak any frame.
        let spoofed_plain = Envelope::Invoke {
            request_id: req_id.clone(),
            node_id: live.node_id.clone(),
            client_id: alice_id.public_hex().to_string(),
            op: Op::SysInfo,
            grant: None,
            authz: None,
            user: None,
            device_id: None,
        };
        handle_env(
            spoofed_plain,
            &tx,
            &policy,
            &live.cancels,
            &live.pty,
            &config,
            &[],
            &host,
            &live,
        )
        .await;
        let out = rx.try_recv().expect("error reply");
        let text = match out {
            Outbound::Text(s) => s,
            _ => panic!("expected Outbound::Text"),
        };
        assert!(!text.contains("TOP_SECRET_E2E_STDOUT"), "plaintext oracle leaked replay: {text}");
        assert!(text.contains("end-to-end"), "expected plaintext rejection, got {text}");
        assert!(rx.try_recv().is_err(), "no extra frames should be replayed");

        // 2. Cross-peer sealed Invoke (Bob replaying Alice's request_id) MUST fail.
        let bob_inner = Envelope::Invoke {
            request_id: req_id.clone(),
            node_id: live.node_id.clone(),
            client_id: bob_id.public_hex().to_string(),
            op: Op::SysInfo,
            grant: None,
            authz: None,
            user: None,
            device_id: None,
        };
        let bob_sealed = agentlink_core::e2e::seal_envelope(
            &bob_ep,
            &live.node_id,
            &live.node_id,
            bob_id.public_hex(),
            &bob_inner,
        )
        .unwrap();
        handle_env(
            bob_sealed,
            &tx,
            &policy,
            &live.cancels,
            &live.pty,
            &config,
            &[],
            &host,
            &live,
        )
        .await;
        let out = rx.try_recv().expect("sealed deny");
        let text = match out {
            Outbound::Text(s) => s,
            _ => panic!("expected Outbound::Text"),
        };
        let env: Envelope = serde_json::from_str(&text).unwrap();
        match env {
            Envelope::E2e { body_b64, request_id: rid, .. } => {
                let bytes = agentlink_core::util::b64_decode(&body_b64).unwrap();
                let opened = bob_ep.open(&live.node_id, rid.as_bytes(), &bytes).unwrap();
                let inner: Envelope = serde_json::from_slice(&opened).unwrap();
                assert!(
                    matches!(inner, Envelope::Result { ok: false, .. }),
                    "cross-peer replay must return error, got {inner:?}"
                );
            }
            other => panic!("expected sealed error envelope, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "cross-peer replay must not emit log frames");

        // 3. Plaintext Cancel and Bob's sealed Cancel MUST NOT cancel Alice's op.
        handle_env(
            Envelope::Cancel {
                request_id: req_id.clone(),
                node_id: live.node_id.clone(),
            },
            &tx,
            &policy,
            &live.cancels,
            &live.pty,
            &config,
            &[],
            &host,
            &live,
        )
        .await;
        assert!(!cancel_tok.is_cancelled(), "plaintext Cancel cancelled Alice's op");

        let bob_cancel = agentlink_core::e2e::seal_envelope(
            &bob_ep,
            &live.node_id,
            &live.node_id,
            bob_id.public_hex(),
            &Envelope::Cancel {
                request_id: req_id.clone(),
                node_id: live.node_id.clone(),
            },
        )
        .unwrap();
        handle_env(
            bob_cancel,
            &tx,
            &policy,
            &live.cancels,
            &live.pty,
            &config,
            &[],
            &host,
            &live,
        )
        .await;
        assert!(!cancel_tok.is_cancelled(), "cross-peer Cancel cancelled Alice's op");

        // 4. Plaintext Session and Bob's sealed Session MUST NOT trim Alice's replay log,
        //    while Alice's E2E-sealed Session (via `seal_control_envelope`) DOES trim it.
        let session_cursor = agentlink_core::protocol::SessionCursor {
            request_id: req_id.clone(),
            seq: 1,
        };
        handle_env(
            Envelope::Session {
                session_id: "sess-plain".into(),
                node_id: live.node_id.clone(),
                cursors: vec![session_cursor.clone()],
            },
            &tx,
            &policy,
            &live.cancels,
            &live.pty,
            &config,
            &[],
            &host,
            &live,
        )
        .await;
        assert_eq!(
            live.sessions.cursor_for(alice_id.public_hex(), &req_id),
            0,
            "plaintext Session must not advance cursor"
        );

        let bob_session = agentlink_core::e2e::seal_control_envelope(
            &bob_ep,
            &live.node_id,
            &live.node_id,
            bob_id.public_hex(),
            "ctrl-bob-sess",
            &Envelope::Session {
                session_id: "sess-bob".into(),
                node_id: live.node_id.clone(),
                cursors: vec![session_cursor.clone()],
            },
        )
        .unwrap();
        handle_env(
            bob_session,
            &tx,
            &policy,
            &live.cancels,
            &live.pty,
            &config,
            &[],
            &host,
            &live,
        )
        .await;
        assert_eq!(
            live.sessions.cursor_for(alice_id.public_hex(), &req_id),
            0,
            "cross-peer sealed Session must not advance Alice's cursor"
        );
        assert_eq!(
            live.sessions.cursor_for(bob_id.public_hex(), &req_id),
            0,
            "cross-peer sealed Session must not store cursor for unowned request"
        );

        let alice_session = agentlink_core::e2e::seal_control_envelope(
            &alice_ep,
            &live.node_id,
            &live.node_id,
            alice_id.public_hex(),
            "ctrl-alice-sess",
            &Envelope::Session {
                session_id: "sess-alice".into(),
                node_id: live.node_id.clone(),
                cursors: vec![session_cursor],
            },
        )
        .unwrap();
        handle_env(
            alice_session,
            &tx,
            &policy,
            &live.cancels,
            &live.pty,
            &config,
            &[],
            &host,
            &live,
        )
        .await;
        assert_eq!(
            live.sessions.cursor_for(alice_id.public_hex(), &req_id),
            1,
            "owner's sealed Session must advance replay cursor to seq=1"
        );

        // 5. When Alice replays her Invoke for `req_id`, only frames with seq > 1
        //    (`Envelope::End { seq: 2 }`) are re-sent — seq=1 Chunk is trimmed!
        let alice_grant = agentlink_core::grant::SignedGrant::sign(
            &issuer,
            alice_id.public_hex(),
            &live.node_id,
            NodePolicy::full(),
            now - 10,
            now + 600,
            "jti-alice",
        )
        .unwrap();
        let alice_replay = agentlink_core::e2e::seal_envelope(
            &alice_ep,
            &live.node_id,
            &live.node_id,
            alice_id.public_hex(),
            &Envelope::Invoke {
                request_id: req_id.clone(),
                node_id: live.node_id.clone(),
                client_id: alice_id.public_hex().to_string(),
                op: Op::SysInfo,
                grant: None,
                authz: Some(alice_grant),
                user: None,
                device_id: None,
            },
        )
        .unwrap();
        handle_env(
            alice_replay,
            &tx,
            &policy,
            &live.cancels,
            &live.pty,
            &config,
            &[],
            &host,
            &live,
        )
        .await;
        let out = rx.try_recv().expect("trimmed replay frame");
        let text = match out {
            Outbound::Text(s) => s,
            _ => panic!("expected Outbound::Text"),
        };
        let env: Envelope = serde_json::from_str(&text).unwrap();
        match env {
            Envelope::E2e {
                body_b64,
                request_id: rid,
                ..
            } => {
                let bytes = agentlink_core::util::b64_decode(&body_b64).unwrap();
                let opened = alice_ep.open(&live.node_id, rid.as_bytes(), &bytes).unwrap();
                let inner: Envelope = serde_json::from_slice(&opened).unwrap();
                assert!(
                    matches!(inner, Envelope::End { seq: 2, .. }),
                    "expected trimmed replay to start at seq=2 End, got {inner:?}"
                );
            }
            other => panic!("expected sealed replay frame, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "no already-acknowledged seq<=1 frames should be replayed"
        );
    }

    #[test]
    fn confirm_policy_covers_transfers_edits_and_normalized_outside_paths() {
        let policy = ConfirmPolicy {
            timeout_secs: 10,
            rules: vec![ConfirmRule {
                category: "write".into(),
                pattern: String::new(),
                outside: Some("/work".into()),
                recursive: false,
            }],
        };
        // Traversal outside `/work` MUST trigger confirmation!
        let traversal_push = TransferMsg::Push {
            path: "/work/../etc/cron.d/pwn".into(),
            size: 10,
            hash: String::new(),
            chunk_size: 4096,
            compress: agentlink_core::protocol::CompressPref::Auto,
            resume: false,
            mode: None,
            mtime_unix: None,
        };
        assert!(confirm_match_transfer(&policy, &traversal_push, None).is_some());

        let inside_push = TransferMsg::Push {
            path: "/work/sub/ok.txt".into(),
            size: 10,
            hash: String::new(),
            chunk_size: 4096,
            compress: agentlink_core::protocol::CompressPref::Auto,
            resume: false,
            mode: None,
            mtime_unix: None,
        };
        assert!(confirm_match_transfer(&policy, &inside_push, None).is_none());

        let push_stream = TransferMsg::PushStream {
            path: "/etc/hosts".into(),
            chunk_size: 4096,
            window: 4,
            compress: agentlink_core::protocol::CompressPref::Auto,
        };
        assert!(confirm_match_transfer(&policy, &push_stream, None).is_some());

        let push_dir = TransferMsg::PushDir {
            dest: "/etc/app".into(),
            manifest_hash: String::new(),
            entries: Vec::new(),
            chunk_size: 4096,
            compress: agentlink_core::protocol::CompressPref::Auto,
        };
        assert!(confirm_match_transfer(&policy, &push_dir, None).is_some());

        // Replace / EditLines / ApplyPatch / Rename.from outside `/work` MUST trigger!
        assert!(confirm_match_op(
            &policy,
            &Op::Replace {
                path: "/work/../etc/shadow".into(),
                old: "a".into(),
                new: "b".into(),
                replace_all: false,
            },
            None,
        )
        .is_some());
        assert!(confirm_match_op(
            &policy,
            &Op::EditLines {
                path: "/etc/hosts".into(),
                start_line: 1,
                end_line: 1,
                content: "x".into(),
            },
            None,
        )
        .is_some());
        assert!(confirm_match_op(
            &policy,
            &Op::ApplyPatch {
                root: "/etc".into(),
                patch: String::new(),
            },
            None,
        )
        .is_some());
        assert!(confirm_match_op(
            &policy,
            &Op::Rename {
                from: "/etc/passwd".into(),
                to: "/work/copied".into(),
            },
            None,
        )
        .is_some());
    }

    #[test]
    fn revoked_cache_retains_last_good_set_on_transient_corrupt_or_locked_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut initial = BTreeSet::new();
        initial.insert("jti-revoked".into());
        agentlink_core::grant::save_revoked_jtis(dir.path(), &initial).unwrap();

        let cache = RevokedJtiCache::new(dir.path().to_path_buf());
        assert!(!cache.is_active("jti-revoked"));
        assert!(cache.is_active("jti-good"));

        // Simulate transient partial write / lock error by writing corrupt JSON.
        std::fs::write(
            dir.path().join(agentlink_core::grant::REVOKED_GRANTS_FILE),
            b"{partial-write",
        )
        .unwrap();
        let _ = cache.current_forced();
        // Good grant MUST stay active (never kill live shells on transient error!),
        // and previously revoked grant MUST stay revoked.
        assert!(cache.is_active("jti-good"));
        assert!(!cache.is_active("jti-revoked"));
    }

    #[test]
    fn approval_and_grant_session_guards_clean_up_entries_on_drop() {
        let approvals: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (tx, _rx) = oneshot::channel();
        approvals.lock().unwrap().insert("ap-1".into(), tx);
        {
            let _guard = ApprovalGuard {
                approvals: approvals.clone(),
                approval_id: "ap-1".into(),
            };
            assert_eq!(approvals.lock().unwrap().len(), 1);
        }
        assert!(approvals.lock().unwrap().is_empty());

        let gs: Arc<Mutex<HashMap<String, Vec<GrantSessionEntry>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        gs.lock().unwrap().entry("jti-1".into()).or_default().push(
            GrantSessionEntry {
                request_id: "req-1".into(),
                token: CancellationToken::new(),
                grant_exp_unix: None,
            },
        );
        {
            let _guard = GrantSessionGuard {
                grant_sessions: gs.clone(),
                jti: Some("jti-1".into()),
                request_id: "req-1".into(),
            };
            assert_eq!(gs.lock().unwrap().len(), 1);
        }
        assert!(gs.lock().unwrap().is_empty());
    }
}
