//! Outbound connection loop.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use agentlink_core::confirm::ConfirmPolicy;
use agentlink_core::e2e::Endpoint;
use agentlink_core::p2p::QuicPeer;
use agentlink_core::protocol::{Envelope, Role, PROTOCOL_VERSION};
use agentlink_core::sandbox::CommandPolicy;
use agentlink_core::tls;
use agentlink_core::ws::{self, Incoming, Outbound};
use agentlink_core::{Error, Identity, NodeExtension, NodePolicy, Result};
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
use crate::resume::{ReplayLog, Sessions, SocketSlot};
use crate::status::{self, LinkState};
use crate::transfer::{self, TransferHost};

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
    if agentlink_core::grant::legacy_relay_auth_enabled() {
        tracing::warn!(
            "AGENTLINK_LEGACY_RELAY_AUTH is set: the relay's grant stamps authorize node\
             operations. Unset it to require owner-signed grants"
        );
    } else {
        match agentlink_core::grant::bootstrap_issuer_with_mode(&config.data_dir, false) {
            Ok(Some(issuer)) => tracing::info!(
                issuer = issuer.public_hex(),
                path = %config.data_dir.join(agentlink_core::grant::GRANT_ISSUER_FILE).display(),
                "created grant issuer; this node now requires owner-signed grants"
            ),
            Ok(None) => {}
            Err(err) => tracing::warn!(error = %err, "could not bootstrap grant issuer"),
        }
    }
    let owner_keys = agentlink_core::grant::refresh_owner_keys(
        &config.data_dir,
        &std::collections::BTreeSet::new(),
    );
    if !owner_keys.is_empty() {
        tracing::info!(
            issuers = owner_keys.len(),
            "owner keys loaded; account owner and admin sessions are full access"
        );
    }
    let revoked_jtis = agentlink_core::grant::refresh_revoked_jtis(
        &config.data_dir,
        &std::collections::BTreeSet::new(),
    );
    if !revoked_jtis.is_empty() {
        tracing::info!(
            jtis = revoked_jtis.len(),
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
        revoked_jtis: RwLock::new(revoked_jtis),
        commands: load_commands(&config.data_dir),
        confirm: load_confirm(&config.data_dir),
        pending: Arc::new(Mutex::new(HashMap::new())),
        approvals: Arc::new(Mutex::new(HashMap::new())),
        procs: ProcManager::new(),
        watches: WatchManager::default(),
        socket: Arc::new(SocketSlot::default()),
        sessions: Arc::new(Sessions::default()),
        pty: PtyManager::default(),
        cancels: Arc::new(Mutex::new(HashMap::new())),
    });
    pipeline::spawn_recorder(service.clone(), config.capture.clone());

    // Connected owners are not clipped by a saved --max-access preset.
    let policy = Arc::new(RwLock::new(NodePolicy::full()));
    let allowed = Arc::new(Mutex::new(HashMap::new()));
    let relay_udp = agentlink_core::p2p::relay_addr_from_url(&config.relay_url).ok();
    let quic = match QuicPeer::bind(&identity, relay_udp) {
        Ok(peer) => {
            let peer = Arc::new(peer);
            transfer::spawn_accept(
                peer.clone(),
                allowed.clone(),
                policy.clone(),
                config.max_policy,
                config.root.clone(),
                service.clone(),
                shutdown.clone(),
            );
            Some(peer)
        }
        Err(err) => {
            tracing::warn!(error = %err, "direct path unavailable");
            None
        }
    };

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

struct Live {
    endpoint: Endpoint,
    node_id: String,
    node_name: String,
    service: Arc<AuditService>,
    /// Node data dir. Owner keys are reloaded from here before each authz
    /// decision so `grant trust-owner` applies without a restart.
    data_dir: PathBuf,
    /// Last good trusted owner issuer keys. Non-empty requires a signed grant
    /// only when the relay did not authenticate an account session for this
    /// node. A relay-authenticated owner, admin, share, or same-owner peer is
    /// full access (`relay_grant` / `relay_admin`). That stamp is trusted
    /// because the relay binds it to the node on the open route.
    owner_keys: RwLock<std::collections::BTreeSet<String>>,
    /// Last good revoked-jti deny-list, reloaded from the data dir before each
    /// authz decision so `grant revoke --data-dir` applies without a restart.
    revoked_jtis: RwLock<std::collections::BTreeSet<String>>,
    commands: CommandPolicy,
    confirm: ConfirmPolicy,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<Envelope>>>>,
    approvals: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    procs: ProcManager,
    watches: WatchManager,
    socket: Arc<SocketSlot>,
    sessions: Arc<Sessions>,
    pty: PtyManager,
    cancels: Arc<Mutex<HashMap<String, CancellationToken>>>,
}

impl Live {
    /// Reload `owner-keys.json` and update the cache. Falls back to the last
    /// good set when the file is unreadable.
    fn current_owner_keys(&self) -> std::collections::BTreeSet<String> {
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

    /// Reload `revoked-grants.json` and update the cache. Falls back to the
    /// last good set when the file is unreadable.
    fn current_revoked_jtis(&self) -> std::collections::BTreeSet<String> {
        let cached = self
            .revoked_jtis
            .read()
            .map(|jtis| jtis.clone())
            .unwrap_or_default();
        let fresh = agentlink_core::grant::refresh_revoked_jtis(&self.data_dir, &cached);
        if let Ok(mut guard) = self.revoked_jtis.write() {
            *guard = fresh.clone();
        }
        fresh
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
            // The relay's stored preset is not a cap. A connected session is full.
            let _pushed = policy;
            (NodePolicy::full(), heartbeat_secs)
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
                Ok(Incoming::Closed) => break SessionEnd::Closed,
                Ok(Incoming::Ignore) => {}
            },
        }
    };
    match end {
        SessionEnd::Shutdown => {
            cancel_all(&cancels);
            pty.close_all();
            Ok(())
        }
        SessionEnd::Closed => {
            release_link(&live, generation);
            Ok(())
        }
        SessionEnd::Dead(err) => {
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
    let pty = live.pty.clone();
    let cancels = live.cancels.clone();
    let socket = live.socket.clone();
    tokio::spawn(async move {
        tokio::time::sleep(agentlink_core::resume::RECONNECT_GIVE_UP).await;
        if socket.generation() == generation {
            pty.close_all();
            cancel_all(&cancels);
        }
    });
}

async fn handle_env(
    env: Envelope,
    tx: &mpsc::Sender<Outbound>,
    policy: &Arc<RwLock<NodePolicy>>,
    cancels: &Arc<Mutex<HashMap<String, CancellationToken>>>,
    pty: &PtyManager,
    config: &NodeConfig,
    extensions: &[Arc<dyn NodeExtension>],
    host: &Arc<TransferHost>,
    live: &Arc<Live>,
) {
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
                user: slot,
                device_id: device_slot,
                ..
            } = &mut inner
            {
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
            if live.service.policy().lock_local {
                tracing::info!("ignoring relay audit policy because lock_local is set");
                return;
            }
            match agentlink_core::audit::AuditPolicy::parse(&toml) {
                Ok(policy) => {
                    if let Err(err) = std::fs::write(config.data_dir.join("audit.toml"), &toml) {
                        tracing::warn!(error = %err, "could not save pushed audit policy");
                    }
                    live.service.replace_policy(policy, true);
                }
                Err(err) => tracing::warn!(error = %err, "pushed audit policy is invalid"),
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
            let effective = NodePolicy::full();
            if let Ok(mut guard) = policy.write() {
                *guard = effective;
            }
            if let Some(hook) = &config.policy_hook {
                hook(effective);
            }
            tracing::info!(access = effective.preset_name(), "policy updated");
        }
        Envelope::Session { cursors, .. } => {
            let pairs: Vec<(String, u64)> = cursors
                .into_iter()
                .map(|cursor| (cursor.request_id, cursor.seq))
                .collect();
            live.sessions.note_cursors(&pairs);
        }
        Envelope::Cancel { request_id, .. } => {
            if let Ok(map) = cancels.lock() {
                if let Some(token) = map.get(&request_id) {
                    token.cancel();
                }
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
            if let Some(log) = live.sessions.existing(&request_id) {
                replay_log(&log, live.sessions.cursor(&request_id), seal.as_ref(), tx).await;
                return;
            }
            let Some(log) = live.sessions.begin(&request_id) else {
                return;
            };
            live.service.touch();
            if matches!(
                op,
                agentlink_core::protocol::Op::Extension { ref name, .. }
                    if name == "screenshot" || name == "inject_input"
            ) {
                // JPEG fallback stays on this invoke. An agent session seals it.
                // WebRTC picture bytes are DTLS-SRTP and are a different path.
                live.service.touch_gui();
            }
            let token = CancellationToken::new();
            if let Ok(mut map) = cancels.lock() {
                map.insert(request_id.clone(), token.clone());
            }
            let extra = Arc::new(Mutex::new(pipeline::AuditExtra::default()));
            let resp = Responder {
                socket: live.socket.clone(),
                request_id: request_id.clone(),
                seal: seal.clone(),
                extra,
                log,
            };
            // Remote grant revoke is authenticated by the issuer-signed
            // SignedRevoke itself, not by the caller's grant policy. Handle it
            // before resolve_e2e_policy / confirm so a narrow authz cannot
            // block an owner revoke.
            if let agentlink_core::protocol::Op::RevokeGrant { revoke } = &op {
                if seal.is_none() {
                    let _ = resp.err("revoke_grant requires an E2E session").await;
                    if let Ok(mut map) = cancels.lock() {
                        map.remove(&request_id);
                    }
                    return;
                }
                // Reload owner-keys.json so `grant trust-owner` applies here too.
                let owner_keys = live.current_owner_keys();
                if let Err(err) =
                    revoke.authorize(&owner_keys, &live.node_id, agentlink_core::util::unix_now())
                {
                    tracing::warn!(error = %err, "e2e revoke rejected");
                    let _ = resp.err(err.to_string()).await;
                    if let Ok(mut map) = cancels.lock() {
                        map.remove(&request_id);
                    }
                    return;
                }
                match agentlink_core::grant::add_revoked_jti_until(
                    &live.data_dir,
                    &revoke.jti,
                    revoke.grant_exp_unix,
                ) {
                    Ok(jtis) => {
                        if let Ok(mut guard) = live.revoked_jtis.write() {
                            *guard = jtis;
                        }
                        live.service.submit(audit::event_for(
                            "permission",
                            "grant",
                            &client_id,
                            &revoke.jti,
                            serde_json::json!({"detail": revoke.jti, "revoke": "grant"}),
                            true,
                            None,
                            Duration::ZERO,
                        ));
                        let _ = resp
                            .ok(serde_json::json!({
                                "revoked": true,
                                "jti": revoke.jti.trim().to_ascii_lowercase(),
                            }))
                            .await;
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "could not persist revoked grant");
                        let _ = resp
                            .err(format!("could not update the node deny-list: {err}"))
                            .await;
                    }
                }
                if let Ok(mut map) = cancels.lock() {
                    map.remove(&request_id);
                }
                return;
            }
            let ceiling = policy.read().map(|g| *g).unwrap_or(NodePolicy::full());
            // Account owner/admin/share sessions are full. A signed grant is
            // required only when owner keys are set and the relay did not
            // authenticate the caller. Reload owner keys so trust-owner applies
            // without a restart. A per-call grant (view ticket) can still narrow.
            let owner_keys = live.current_owner_keys();
            let revoked_jtis = live.current_revoked_jtis();
            let policy_now = match agentlink_core::grant::resolve_e2e_policy(
                &owner_keys,
                &revoked_jtis,
                authz.as_ref(),
                &live.node_id,
                &client_id,
                agentlink_core::util::unix_now(),
                ceiling,
                relay_admin,
                relay_grant,
                grant,
            ) {
                Ok(policy) => policy,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        client_id = %client_id,
                        node_id = %live.node_id,
                        "e2e authz rejected"
                    );
                    let deny = Envelope::result_err(request_id.clone(), err.to_string());
                    if let Ok(out) = ws::encode(&deny) {
                        let _ = tx.send(out).await;
                    }
                    return;
                }
            };
            let confirm_category = live.confirm.matching(&op).map(|rule| rule.category.clone());
            let root = config.root.clone();
            let audit_path = config.data_dir.join("audit.log");
            let pty = pty.clone();
            let extensions = extensions.to_vec();
            let cancels = cancels.clone();
            let commands = live.commands.clone();
            let procs = live.procs.clone();
            let watches = live.watches.clone();
            let node_name = live.node_name.clone();
            let node_id = live.node_id.clone();
            let audit = live.service.clone();
            let confirm_wait = confirm_category.map(|category| {
                let approval_id = Uuid::new_v4().to_string();
                let (wait_tx, wait_rx) = oneshot::channel();
                if let Ok(mut map) = live.approvals.lock() {
                    map.insert(approval_id.clone(), wait_tx);
                }
                let summary = live.service.policy().redact.apply(
                    &agentlink_core::confirm::ConfirmPolicy::summary(&op),
                );
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
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Some((approval_id, note, wait_rx, timeout_secs)) = confirm_wait {
                    if let Ok(out) = ws::encode(&note) {
                        let _ = tx.send(out).await;
                    }
                    let timeout =
                        tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), wait_rx)
                            .await;
                    let allowed = matches!(timeout, Ok(Ok(true)));
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
                        if let Ok(mut map) = cancels.lock() {
                            map.remove(&request_id);
                        }
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
                    },
                )
                .await;
                if let Ok(mut map) = cancels.lock() {
                    map.remove(&request_id);
                }
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
            let session = seal.as_ref().map(|s| s.session.clone());
            // Account sessions are full without a grant file. A sealed transfer
            // from a caller the relay did not authenticate still needs a signed
            // grant when owner keys are set. Reload keys so trust-owner is live.
            let owner_keys = live.current_owner_keys();
            let policy_now = if seal.is_some() && !owner_keys.is_empty() {
                let ceiling = policy.read().map(|g| *g).unwrap_or(NodePolicy::full());
                let revoked_jtis = live.current_revoked_jtis();
                match agentlink_core::grant::resolve_e2e_policy(
                    &owner_keys,
                    &revoked_jtis,
                    authz.as_ref(),
                    &live.node_id,
                    &client_id,
                    agentlink_core::util::unix_now(),
                    ceiling,
                    relay_admin,
                    relay_grant,
                    None,
                ) {
                    Ok(policy) => Some(policy),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            client_id = %client_id,
                            node_id = %live.node_id,
                            "e2e transfer authz rejected"
                        );
                        let deny = Envelope::result_err(request_id, err.to_string());
                        if let Ok(out) = ws::encode(&deny) {
                            let _ = tx.send(out).await;
                        }
                        return;
                    }
                }
            } else {
                None
            };
            transfer::on_transfer(
                host.clone(),
                request_id,
                client_id,
                msg,
                session,
                policy_now,
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

async fn replay_log(
    log: &ReplayLog,
    cursor: u64,
    seal: Option<&crate::ops::ResponseSeal>,
    tx: &mpsc::Sender<Outbound>,
) {
    for env in log.snapshot() {
        if env.seq() != 0 && env.seq() <= cursor {
            continue;
        }
        let encoded = if let Some(seal) = seal {
            match agentlink_core::e2e::seal_envelope_session(
                &seal.session,
                &seal.node_id,
                &seal.peer,
                &env,
            ) {
                Ok(wrapped) => ws::encode(&wrapped),
                Err(err) => {
                    tracing::debug!(error = %err, "replay seal failed");
                    continue;
                }
            }
        } else {
            ws::encode(&env)
        };
        if let Ok(out) = encoded {
            if tx.send(out).await.is_err() {
                break;
            }
        }
    }
}

fn cancel_all(cancels: &Mutex<HashMap<String, CancellationToken>>) {
    if let Ok(map) = cancels.lock() {
        for token in map.values() {
            token.cancel();
        }
    }
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
                Incoming::Closed => return Err(Error::Ws("connection closed".into())),
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
}
