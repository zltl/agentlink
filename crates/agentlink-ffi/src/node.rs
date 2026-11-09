//! Outbound node loop for the phone.
//!
//! The connection, certificate trust, ed25519 handshake, reconnect, permission
//! ceiling, session resume, and audit log match the desktop node. File bytes
//! for bulk copy use the fast-transfer engine. Commands, screenshots, and
//! input are performed by the Android host. A dropped relay keeps the PTY
//! and replays sequenced output when the client redials.

#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use agentlink_core::e2e::{self, Endpoint};
use agentlink_core::p2p::QuicPeer;
use agentlink_core::protocol::{Envelope, Op, Role, PROTOCOL_VERSION};
use agentlink_core::tls;
use agentlink_core::util::{self, FILE_CHUNK};
use agentlink_core::ws::{self, Incoming, Outbound};
use agentlink_core::{
    apply_relay_defaults, parse_relay_url, Error, Identity, NodePolicy, Result,
    PHASE3_WEBRTC_SIGNAL,
};
use futures_util::{SinkExt, Stream, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use crate::audit::{self, AuditHub};
use crate::files;
use crate::host::{self, NodeHost};
use crate::paths::{self, Roots};
use crate::pty::{PhonePty, PtyPoll};
use crate::resume::{ReplayLog, Sessions, SocketSlot};
use crate::tools::{self, ToolState};
use crate::transfer::{self, PathMap, TransferHost};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ServeConfig {
    pub relay_url: String,
    pub fingerprint: String,
    /// `system`, `webpki`, or both, when public roots are used in addition to
    /// or instead of [`Self::fingerprint`].
    pub trust: Option<String>,
    pub data_dir: PathBuf,
    pub files_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub storage_dir: Option<PathBuf>,
    pub name: String,
    pub pairing_token: Option<String>,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub ceiling: NodePolicy,
}

pub struct NodeIo {
    pub status: Arc<Mutex<String>>,
    pub node_id: Arc<Mutex<String>>,
}

struct PhoneLive {
    socket: Arc<SocketSlot>,
    sessions: Arc<Sessions>,
    cancels: Arc<Mutex<HashMap<String, CancellationToken>>>,
    shells: Arc<PhonePty>,
    /// Node data dir. Owner keys are reloaded from here before each authz
    /// decision so `grant trust-owner` applies without a restart.
    data_dir: PathBuf,
    /// Last good trusted owner issuer keys. Non-empty enables signed-grant authz.
    owner_keys: RwLock<std::collections::BTreeSet<String>>,
    /// Last good revoked-jti deny-list, reloaded from the data dir before each
    /// authz decision so `grant revoke --data-dir` applies without a restart.
    revoked_jtis: RwLock<std::collections::BTreeSet<String>>,
    node_id: String,
}

impl PhoneLive {
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

pub async fn serve_node(
    mut config: ServeConfig,
    host: Arc<dyn NodeHost>,
    shutdown: CancellationToken,
    io: NodeIo,
) -> Result<()> {
    config.relay_url = normalized_relay(&config.relay_url, &config.fingerprint).0;
    agentlink_core::util::ensure_dir(&config.data_dir)?;
    std::fs::create_dir_all(&config.files_dir)?;
    std::fs::create_dir_all(&config.cache_dir)?;
    let identity = Identity::load_or_create(&config.data_dir.join("identity.json"))?;
    let node_id = identity.node_id().to_string();
    if let Ok(mut id) = io.node_id.lock() {
        *id = node_id.clone();
    }
    let audit = Arc::new(AuditHub::open(&config.data_dir, &node_id, &config.name));
    let roots = Roots {
        files: config.files_dir.clone(),
        cache: config.cache_dir.clone(),
        storage: config.storage_dir.clone(),
        audit: config.data_dir.join("audit.log"),
    };
    let paths = Arc::new(PathMap {
        roots,
        host: host.clone(),
    });
    let policy = Arc::new(RwLock::new(config.ceiling));
    let allowed = Arc::new(Mutex::new(HashMap::new()));
    let relay_udp = agentlink_core::p2p::relay_addr_from_url(&config.relay_url).ok();
    let quic = match QuicPeer::bind(&identity, relay_udp) {
        Ok(peer) => {
            let peer = Arc::new(peer);
            transfer::spawn_accept(
                peer.clone(),
                allowed.clone(),
                policy.clone(),
                config.ceiling,
                paths.clone(),
                audit.clone(),
                shutdown.clone(),
            );
            Some(peer)
        }
        Err(err) => {
            tracing::warn!(error = %err, "direct path unavailable; transfers stay on the relay");
            None
        }
    };
    let endpoint = Endpoint::new(identity);
    let token = Arc::new(Mutex::new(config.pairing_token.clone()));
    let tools = Arc::new(ToolState::default());
    let owner_keys = agentlink_core::grant::refresh_owner_keys(
        &config.data_dir,
        &std::collections::BTreeSet::new(),
    );
    let revoked_jtis = agentlink_core::grant::refresh_revoked_jtis(
        &config.data_dir,
        &std::collections::BTreeSet::new(),
    );
    let live = PhoneLive {
        socket: Arc::new(SocketSlot::default()),
        sessions: Arc::new(Sessions::default()),
        cancels: Arc::new(Mutex::new(HashMap::new())),
        shells: Arc::new(PhonePty::default()),
        data_dir: config.data_dir.clone(),
        owner_keys: RwLock::new(owner_keys),
        revoked_jtis: RwLock::new(revoked_jtis),
        node_id: node_id.clone(),
    };
    publish(
        &host,
        &io,
        "connecting",
        &node_id,
        config.ceiling,
        "dialing the relay",
    );

    let mut delay = Duration::from_millis(200);
    loop {
        if shutdown.is_cancelled() {
            tools.shutdown();
            live.shells.close_all();
            publish(&host, &io, "stopped", &node_id, config.ceiling, "stopped");
            return Ok(());
        }
        let started = Instant::now();
        match connect_once(
            &mut config,
            &endpoint,
            &audit,
            &shutdown,
            &host,
            &io,
            policy.clone(),
            allowed.clone(),
            quic.clone(),
            paths.clone(),
            token.clone(),
            tools.clone(),
            &live,
        )
        .await
        {
            Ok(()) => {}
            Err(err) if err.is_fatal() && !err.to_string().contains("already used") => {
                tools.shutdown();
                live.shells.close_all();
                publish(
                    &host,
                    &io,
                    "fatal",
                    &node_id,
                    config.ceiling,
                    &err.to_string(),
                );
                return Err(err);
            }
            Err(err) if err.to_string().contains("relay url") => {
                tools.shutdown();
                live.shells.close_all();
                publish(
                    &host,
                    &io,
                    "fatal",
                    &node_id,
                    config.ceiling,
                    &err.to_string(),
                );
                return Err(err);
            }
            Err(err) => {
                tracing::warn!(error = %err, "node connection ended; reconnecting");
                publish(
                    &host,
                    &io,
                    "reconnecting",
                    &node_id,
                    config.ceiling,
                    &err.to_string(),
                );
            }
        }
        if started.elapsed() > Duration::from_secs(5) {
            delay = Duration::from_millis(200);
        }
        tokio::select! {
            _ = shutdown.cancelled() => {
                tools.shutdown();
                live.shells.close_all();
                publish(&host, &io, "stopped", &node_id, config.ceiling, "stopped");
                return Ok(());
            }
            _ = tokio::time::sleep(delay) => {}
        }
        delay = (delay * 2).min(Duration::from_secs(15));
    }
}

#[allow(clippy::too_many_arguments)]
async fn connect_once(
    config: &mut ServeConfig,
    endpoint: &Endpoint,
    audit_hub: &Arc<AuditHub>,
    shutdown: &CancellationToken,
    host_cb: &Arc<dyn NodeHost>,
    io: &NodeIo,
    policy: Arc<RwLock<NodePolicy>>,
    allowed: Arc<Mutex<HashMap<String, Instant>>>,
    quic: Option<Arc<QuicPeer>>,
    paths: Arc<PathMap>,
    pairing_token: Arc<Mutex<Option<String>>>,
    tools: Arc<ToolState>,
    live: &PhoneLive,
) -> Result<()> {
    let mut relay_url = config.relay_url.clone();
    let mut trust = config.trust.clone();
    apply_relay_defaults(&mut relay_url, &config.fingerprint, &mut trust);
    let relay = parse_relay_url(&relay_url)?;
    let trust = tls::RelayTrust::parse(&config.fingerprint, trust.as_deref())?;
    let tcp = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((relay.host.as_str(), relay.port)),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Message(format!("connect relay: {e}")))?;
    tcp.set_nodelay(true).ok();
    ws::arm_tcp_liveness(&tcp);
    let adopt = tls::adopt_loopback_leaf(&relay.host, tcp.peer_addr().ok());
    let dial = tls::client_config_for_dial(&trust, adopt)?;
    let connector = tokio_rustls::TlsConnector::from(dial.config);
    let server_name = tls::server_name(&relay.host, &trust)?;
    let tls = timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Tls(e.to_string()))?;
    if let Some(pin) = dial.adopted_leaf.as_deref().and_then(tls::AdoptedLeaf::get) {
        if pin != config.fingerprint && tls::parse_fingerprint(&pin).is_ok() {
            tracing::warn!(
                relay = %relay_url,
                old = %config.fingerprint,
                new = %pin,
                "loopback relay certificate changed; using the presented leaf pin for this process. Remote relays are left unchanged"
            );
            config.fingerprint = pin;
        }
    }
    let ws_url = format!("ws://{}:{}{}", relay.bracket_host(), relay.port, relay.path);
    let (mut ws, _) = timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::client_async_with_config(ws_url, tls, Some(ws::ws_config())),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Ws(e.to_string()))?;

    let token = pairing_token.lock().ok().and_then(|g| g.clone());
    let hello = Envelope::Hello {
        role: Role::Node,
        protocol: PROTOCOL_VERSION,
        token: None,
        node_id: Some(endpoint.identity().node_id().to_string()),
        public_key: Some(endpoint.identity().public_hex().to_string()),
        name: Some(config.name.clone()),
        pairing_token: token,
        hostname: Some(config.hostname.clone()),
        os: Some(config.os.clone()),
        arch: Some(config.arch.clone()),
        version: Some(config.version.clone()),
        ceiling: Some(config.ceiling),
        // A phone has a screen. The desktop node reports its own session.
        has_display: Some(true),
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
    let signature = endpoint.identity().sign_nonce(&nonce);
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
            if let Ok(mut token) = pairing_token.lock() {
                *token = None;
            }
            (
                policy.unwrap_or(config.ceiling).intersect(config.ceiling),
                heartbeat_secs,
            )
        }
        Envelope::HelloErr { message, fatal } => {
            return if fatal {
                Err(Error::Auth(message))
            } else {
                Err(Error::Message(message))
            };
        }
        other => return Err(Error::Protocol(format!("expected hello_ok, got {other:?}"))),
    };
    if let Ok(mut guard) = policy.write() {
        *guard = policy_now;
    }
    publish(
        host_cb,
        io,
        "online",
        endpoint.identity().node_id(),
        policy_now,
        "paired",
    );
    audit::submit_op(
        audit_hub,
        "connect",
        endpoint.identity().node_id(),
        &config.relay_url,
        true,
        None,
    );

    let (sink, mut stream) = ws.split();
    let (tx, rx) = mpsc::channel(256);
    let generation = live.socket.attach(tx.clone());
    let writer = ws::WriterTask::spawn(sink, rx, shutdown.clone());
    let dead_after = ws::silence_limit(heartbeat_secs);
    let ping_tx = tx.clone();
    let ping_shutdown = shutdown.clone();
    let beat_stop = CancellationToken::new();
    let beat = beat_stop.clone();
    let period = ws::heartbeat_interval(heartbeat_secs);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = beat.cancelled() => break,
                _ = ping_shutdown.cancelled() => break,
                _ = ticker.tick() => {
                    let Ok(out) = ws::encode(&Envelope::Ping) else { break };
                    if ping_tx.send(out).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let _stop_beat = StopBeat(beat_stop);

    audit_hub.set_tx(Some(tx.clone()));
    let transfer_host = Arc::new(TransferHost {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        direct_wait: Arc::new(Mutex::new(HashMap::new())),
        allowed,
        quic,
        tx: tx.clone(),
        policy: policy.clone(),
        max_policy: config.ceiling,
        paths,
        e2e: endpoint.clone(),
        node_id: endpoint.identity().node_id().to_string(),
        seals: Arc::new(Mutex::new(HashMap::new())),
        audit: audit_hub.clone(),
    });

    let end = loop {
        match ws::wait_for_frame(&mut stream, dead_after, shutdown, writer.stopped()).await {
            Err(err) => break Err(err),
            Ok(ws::FrameWait::Shutdown) => {
                live.socket.detach(generation);
                cancel_all(&live.cancels);
                live.shells.close_all();
                audit_hub.set_tx(None);
                return Ok(());
            }
            Ok(ws::FrameWait::Silent) => {
                break Err(Error::Message(format!(
                    "websocket silent for {}s; relay heartbeat was not answered",
                    dead_after.as_secs().max(1)
                )));
            }
            Ok(ws::FrameWait::WriterStopped) => {
                break Err(Error::Message(
                    "websocket writer stopped; connection is no longer usable".into(),
                ));
            }
            Ok(ws::FrameWait::Eof) => break Err(Error::Ws("connection closed".into())),
            Ok(ws::FrameWait::Message(msg)) => {
                let incoming = match ws::parse_incoming(msg) {
                    Ok(incoming) => incoming,
                    Err(err) => break Err(err),
                };
                match incoming {
                    Incoming::Env(Envelope::GoingAway { .. }) => {
                        break Err(Error::Message("relay going away".into()));
                    }
                    Incoming::Env(env) => {
                        handle_env(
                            env,
                            &tx,
                            &policy,
                            config,
                            host_cb,
                            io,
                            &transfer_host,
                            &tools,
                            endpoint,
                            audit_hub,
                            live,
                        )
                        .await;
                    }
                    Incoming::Binary(bytes) => transfer::on_binary(&transfer_host, bytes),
                    Incoming::Ping(payload) => {
                        let _ = tx.try_send(Outbound::Pong(payload));
                    }
                    Incoming::Closed => break Err(Error::Ws("connection closed".into())),
                    Incoming::Ignore => {}
                }
            }
        }
    };
    drop_link(live, generation, audit_hub);
    end
}

struct StopBeat(CancellationToken);

impl Drop for StopBeat {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn handle_env(
    env: Envelope,
    tx: &mpsc::Sender<Outbound>,
    policy: &Arc<RwLock<NodePolicy>>,
    config: &ServeConfig,
    host_cb: &Arc<dyn NodeHost>,
    io: &NodeIo,
    transfer_host: &Arc<TransferHost>,
    tools: &Arc<ToolState>,
    endpoint: &Endpoint,
    audit_hub: &Arc<AuditHub>,
    live: &PhoneLive,
) {
    let (env, seal, relay_admin, relay_grant) = match env {
        Envelope::E2eHello {
            request_id,
            message_b64,
            ..
        } => {
            let Ok(bytes) = util::b64_decode(&message_b64) else {
                return;
            };
            match endpoint.accept(&bytes) {
                Ok((_, welcome)) => {
                    let reply = Envelope::E2eWelcome {
                        request_id,
                        node_id: endpoint.identity().node_id().to_string(),
                        message_b64: util::b64_encode(&welcome),
                    };
                    if let Ok(out) = ws::encode(&reply) {
                        let _ = tx.send(out).await;
                    }
                }
                Err(err) => tracing::debug!(error = %err, "e2e hello rejected"),
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
            ..
        } => {
            let Ok(bytes) = util::b64_decode(&body_b64) else {
                return;
            };
            let (opened, session, peer) = match endpoint.open_routed(
                &client_id,
                &e2e_node_id,
                request_id.as_bytes(),
                &bytes,
            ) {
                Ok(triple) => triple,
                Err(err) => {
                    tracing::warn!(error = %err, "e2e open failed");
                    return;
                }
            };
            let Ok(inner) = serde_json::from_slice::<Envelope>(&opened) else {
                return;
            };
            (
                inner,
                Some(PhoneSeal {
                    endpoint: endpoint.clone(),
                    peer,
                    node_id: endpoint.identity().node_id().to_string(),
                    session,
                }),
                relay_admin,
                relay_grant,
            )
        }
        Envelope::AuditPolicyPush { toml } => {
            match agentlink_core::audit::AuditPolicy::parse(&toml) {
                Ok(next) => {
                    if let Err(err) = std::fs::write(config.data_dir.join("audit.toml"), &toml) {
                        tracing::warn!(error = %err, "could not save pushed audit policy");
                    }
                    audit_hub.replace_policy(next);
                }
                Err(err) => tracing::warn!(error = %err, "pushed audit policy is invalid"),
            }
            return;
        }
        other => (other, None, true, None),
    };
    match env {
        Envelope::Ping => {
            let _ = tx.try_send(Outbound::Text(
                serde_json::to_string(&Envelope::Pong).unwrap_or_default(),
            ));
        }
        Envelope::PolicyUpdate { policy: next } => {
            let effective = next.intersect(config.ceiling);
            if let Ok(mut guard) = policy.write() {
                *guard = effective;
            }
            publish(host_cb, io, "online", "", effective, "policy updated");
        }
        Envelope::Session { cursors, .. } => {
            let pairs: Vec<(String, u64)> = cursors
                .into_iter()
                .map(|cursor| (cursor.request_id, cursor.seq))
                .collect();
            live.sessions.note_cursors(&pairs);
        }
        Envelope::Cancel { request_id, .. } => {
            if let Ok(map) = live.cancels.lock() {
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
            ..
        } => {
            if let Some(log) = live.sessions.existing(&request_id) {
                replay_log(&log, live.sessions.cursor(&request_id), seal.as_ref(), tx).await;
                return;
            }
            let Some(log) = live.sessions.begin(&request_id) else {
                return;
            };
            let token = CancellationToken::new();
            if let Ok(mut map) = live.cancels.lock() {
                map.insert(request_id.clone(), token.clone());
            }
            let resp = Responder {
                socket: live.socket.clone(),
                request_id: request_id.clone(),
                seal: seal.clone(),
                log,
            };
            if let agentlink_core::protocol::Op::RevokeGrant { .. } = &op {
                let _ = resp
                    .err("grant list is local to this node; revoke on the node host")
                    .await;
                return;
            }
            let Some(seal_ref) = seal.as_ref() else {
                let deny = Envelope::result_err(
                    request_id.clone(),
                    "control requires an end-to-end session; plaintext relay invokes are disabled",
                );
                if let Ok(out) = ws::encode(&deny) {
                    let _ = tx.send(out).await;
                }
                return;
            };
            let grantee = seal_ref.peer.clone();
            let _relay_says = (&client_id, relay_admin, relay_grant);
            let ceiling = policy.read().map(|g| *g).unwrap_or(config.ceiling);
            let owner_keys = live.current_owner_keys();
            let revoked_jtis = live.current_revoked_jtis();
            let policy_now = match agentlink_core::grant::resolve_e2e_policy(
                &owner_keys,
                &revoked_jtis,
                authz.as_ref(),
                &live.node_id,
                &grantee,
                agentlink_core::util::unix_now(),
                ceiling,
                false,
                None,
                grant,
            ) {
                // Phone consent (the local ceiling) still caps this device.
                Ok(policy) => policy.intersect(config.ceiling),
                Err(err) => {
                    tracing::warn!(error = %err, "e2e authz rejected");
                    let deny = Envelope::result_err(request_id.clone(), err.to_string());
                    if let Ok(out) = ws::encode(&deny) {
                        let _ = tx.send(out).await;
                    }
                    return;
                }
            };
            let paths = transfer_host.paths.clone();
            let host_cb = host_cb.clone();
            let cancels = live.cancels.clone();
            let shells = live.shells.clone();
            let tools = tools.clone();
            let audit_hub = audit_hub.clone();
            tokio::spawn(async move {
                dispatch(
                    op, resp, token, policy_now, &paths, &audit_hub, &client_id, &host_cb, &shells,
                    &tools,
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
                transfer_host,
                &request_id,
                error.unwrap_or_else(|| "transfer rejected".into()),
            );
        }
        Envelope::Transfer {
            request_id,
            client_id,
            msg,
            ..
        } => transfer::on_transfer(transfer_host.clone(), request_id, client_id, msg, seal.as_ref().map(|s| s.session.clone())).await,
        offer @ Envelope::DirectOffer { .. } => {
            transfer::on_direct_offer(transfer_host, offer).await
        }
        answer @ Envelope::DirectAnswer { .. } => transfer::on_direct_answer(transfer_host, answer),
        other => {
            tracing::debug!(?other, "ignoring envelope");
        }
    }
}

#[derive(Clone)]
struct PhoneSeal {
    endpoint: Endpoint,
    peer: String,
    node_id: String,
    session: std::sync::Arc<agentlink_core::e2e::Direction>,
}

struct Responder {
    socket: Arc<SocketSlot>,
    request_id: String,
    seal: Option<PhoneSeal>,
    log: Arc<ReplayLog>,
}

impl Responder {
    /// Stamp a sequence number and try to send. A dead socket is not an error:
    /// the ring still has the frame for the next dial.
    async fn send(&self, env: &Envelope) -> Result<()> {
        let stamped = self.log.push(env.clone());
        let encoded = if let Some(seal) = &self.seal {
            let wrapped = e2e::seal_envelope_session(
                &seal.session,
                &seal.node_id,
                &seal.peer,
                &stamped,
            )?;
            ws::encode(&wrapped)?
        } else {
            ws::encode(&stamped)?
        };
        if let Some(tx) = self.socket.current() {
            let _ = tx.send(encoded).await;
        }
        Ok(())
    }
    async fn ok(&self, body: Value) -> Result<()> {
        self.send(&Envelope::result_ok(self.request_id.clone(), body))
            .await
    }
    async fn err(&self, message: impl Into<String>) -> Result<()> {
        self.send(&Envelope::result_err(self.request_id.clone(), message))
            .await
    }
    async fn ack(&self, body: Value) -> Result<()> {
        self.send(&Envelope::result_ack(self.request_id.clone(), body))
            .await
    }
    async fn chunk(&self, stream: &str, data: &[u8]) -> Result<()> {
        // Zero means this frame is not sequenced. The phone drops a PTY when
        // the relay socket ends, so there is no replay ring to stamp.
        self.send(&Envelope::Chunk {
            request_id: self.request_id.clone(),
            stream: stream.to_string(),
            data_b64: util::b64_encode(data),
            seq: 0,
        })
        .await
    }
    async fn end(&self, exit_code: Option<i32>, error: Option<String>) -> Result<()> {
        self.send(&Envelope::End {
            request_id: self.request_id.clone(),
            exit_code,
            error,
            seq: 0,
        })
        .await
    }
}

async fn dispatch(
    op: Op,
    resp: Responder,
    cancel: CancellationToken,
    policy: NodePolicy,
    paths: &PathMap,
    audit_hub: &AuditHub,
    client_id: &str,
    host: &Arc<dyn NodeHost>,
    shells: &PhonePty,
    tools: &ToolState,
) {
    let kind = op.kind();
    let detail = op.audit_detail();
    if cancel.is_cancelled() {
        let _ = resp.err("cancelled").await;
        audit::submit_op(
            audit_hub,
            &kind,
            client_id,
            &detail,
            false,
            Some("cancelled".into()),
        );
        return;
    }
    if let Err(why) = policy.allows(&op) {
        let _ = resp.err(why.clone()).await;
        audit::submit_op(audit_hub, &kind, client_id, &detail, false, Some(why));
        return;
    }
    let audit_this = !matches!(op, Op::PtyInput { .. });
    let result = perform(&op, &resp, &cancel, paths, host, shells, tools, policy).await;
    if audit_this {
        match &result {
            Ok(()) => audit::submit_op(audit_hub, &kind, client_id, &detail, true, None),
            Err(err) => {
                audit::submit_op(
                    audit_hub,
                    &kind,
                    client_id,
                    &detail,
                    false,
                    Some(err.to_string()),
                );
            }
        }
    }
    if let Err(err) = result {
        let _ = resp.err(err.to_string()).await;
    }
}

async fn perform(
    op: &Op,
    resp: &Responder,
    cancel: &CancellationToken,
    paths: &PathMap,
    host: &Arc<dyn NodeHost>,
    shells: &PhonePty,
    tools: &ToolState,
    policy: NodePolicy,
) -> Result<()> {
    match op {
        Op::Stat { path } => {
            let stat = files::stat_guest(&paths.roots, host, path)?;
            resp.ok(serde_json::to_value(stat)?).await?;
        }
        Op::ListDir { path } => {
            let entries = files::list_guest(&paths.roots, host, path)?;
            resp.ok(serde_json::to_value(entries)?).await?;
        }
        Op::ReadFile {
            path,
            offset,
            max_bytes,
        } => {
            read_chunks(resp, cancel, paths, host, path, *offset, *max_bytes).await?;
        }
        Op::WriteFile {
            path,
            offset,
            data_b64,
            truncate,
        } => {
            let data = util::b64_decode(data_b64)?;
            let n = files::write_guest(&paths.roots, host, path, *offset, &data, *truncate)?;
            resp.ok(json!({"path": path, "offset": offset, "bytes": n}))
                .await?;
        }
        Op::Mkdir { path, recursive } => {
            files::mkdir_guest(&paths.roots, host, path, *recursive)?;
            resp.ok(json!({"path": path})).await?;
        }
        Op::Remove { path, recursive } => {
            files::remove_guest(&paths.roots, host, path, *recursive)?;
            resp.ok(json!({"removed": path})).await?;
        }
        Op::Rename { from, to } => {
            files::rename_guest(&paths.roots, host, from, to)?;
            resp.ok(json!({"from": from, "to": to})).await?;
        }
        Op::Exec {
            program,
            args,
            cwd,
            env,
            timeout_ms,
            shell,
            stdin_b64,
        } => {
            run_exec(
                resp,
                cancel,
                paths,
                host,
                program,
                args,
                cwd.as_deref(),
                env,
                *timeout_ms,
                *shell,
                stdin_b64.as_deref(),
            )
            .await?;
        }
        Op::PtyOpen {
            command,
            cwd,
            rows,
            cols,
        } => {
            run_pty(
                resp,
                cancel,
                paths,
                shells,
                command.as_deref(),
                cwd.as_deref(),
                *rows,
                *cols,
            )
            .await?;
        }
        Op::Search {
            path,
            pattern,
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
        } => {
            let value = tools::content_search(
                paths.roots.clone(),
                tools::ContentQuery {
                    path: path.clone(),
                    pattern: pattern.clone(),
                    literal: *literal,
                    include: include.clone(),
                    exclude: exclude.clone(),
                    gitignore: *gitignore,
                    include_hidden: *include_hidden,
                    case_insensitive: *case_insensitive,
                    before: *before,
                    after: *after,
                    offset: *offset,
                    limit: *limit,
                },
            )
            .await?;
            resp.ok(value).await?;
        }
        Op::Find {
            path,
            pattern,
            regex,
            gitignore,
            include_hidden,
            case_insensitive,
            offset,
            limit,
        } => {
            let value = tools::filename_search(
                paths.roots.clone(),
                tools::NameQuery {
                    path: path.clone(),
                    pattern: pattern.clone(),
                    regex: *regex,
                    gitignore: *gitignore,
                    include_hidden: *include_hidden,
                    case_insensitive: *case_insensitive,
                    offset: *offset,
                    limit: *limit,
                },
            )
            .await?;
            resp.ok(value).await?;
        }
        Op::Replace {
            path,
            old,
            new,
            replace_all,
        } => {
            let value = tools::replace(
                paths.roots.clone(),
                path.clone(),
                old.clone(),
                new.clone(),
                *replace_all,
            )
            .await?;
            resp.ok(value).await?;
        }
        Op::EditLines {
            path,
            start_line,
            end_line,
            content,
        } => {
            let value = tools::edit_lines(
                paths.roots.clone(),
                path.clone(),
                *start_line,
                *end_line,
                content.clone(),
            )
            .await?;
            resp.ok(value).await?;
        }
        Op::ApplyPatch { root, patch } => {
            let value =
                tools::apply_patch(paths.roots.clone(), root.clone(), patch.clone()).await?;
            resp.ok(value).await?;
        }
        Op::WatchStart { path, recursive } => {
            resp.ok(tools::watch_start(tools, &paths.roots, path, *recursive)?)
                .await?;
        }
        Op::WatchPoll {
            watch_id,
            cursor,
            timeout_ms,
            limit,
        } => {
            resp.ok(tools::watch_poll(tools, watch_id, *cursor, *timeout_ms, *limit).await?)
                .await?;
        }
        Op::WatchStop { watch_id } => {
            resp.ok(tools::watch_stop(tools, watch_id)?).await?;
        }
        Op::BgStart {
            program,
            args,
            cwd,
            env,
            shell,
            stdin_b64,
        } => {
            resp.ok(tools::bg_start(
                tools,
                &paths.roots,
                program,
                args,
                cwd.as_deref(),
                env,
                *shell,
                stdin_b64.as_deref(),
            )?)
            .await?;
        }
        Op::BgList => {
            resp.ok(tools::bg_list(tools)?).await?;
        }
        Op::BgOutput {
            id,
            stdout_cursor,
            stderr_cursor,
            max_bytes,
        } => {
            resp.ok(tools::bg_output(
                tools,
                id,
                *stdout_cursor,
                *stderr_cursor,
                *max_bytes,
            )?)
            .await?;
        }
        Op::BgStatus { id } => {
            resp.ok(tools::bg_status(tools, id)?).await?;
        }
        Op::BgKill { id } => {
            resp.ok(tools::bg_kill(tools, id)?).await?;
        }
        Op::SysInfo => {
            resp.ok(tools::system_info().await?).await?;
        }
        Op::PtyInput {
            session_id,
            data_b64,
        } => {
            let data = util::b64_decode(data_b64)?;
            shells.write(session_id, &data)?;
            resp.ok(json!({"bytes": data.len()})).await?;
        }
        Op::PtyResize {
            session_id,
            rows,
            cols,
        } => {
            shells.resize(session_id, *rows, *cols)?;
            resp.ok(json!({"rows": rows, "cols": cols})).await?;
        }
        Op::PtyClose { session_id } => {
            shells.close(session_id)?;
            resp.ok(json!({"closed": session_id})).await?;
        }
        Op::RevokeGrant { .. } => {
            return Err(Error::Message(
                "revoke_grant is only handled by the E2E node daemon".into(),
            ));
        }
        Op::Extension { name, payload } => {
            let mut payload = payload.clone();
            // Keep a relay-stamped session grant. Only default from the ceiling
            // when the flag is absent (agent sessions without stamp_stream_flags).
            if name == PHASE3_WEBRTC_SIGNAL {
                if let Some(obj) = payload.as_object_mut() {
                    obj.entry("_allow_view".to_string())
                        .or_insert_with(|| json!(policy.allows_remote_view()));
                    obj.entry("_allow_control".to_string())
                        .or_insert_with(|| json!(policy.allows_remote_control()));
                }
            }
            let body =
                host::call_unary(host, "extension", json!({"name": name, "payload": payload}))
                    .await?;
            let encoded = serde_json::to_string(&body)?;
            if encoded.len() > 6_000_000 {
                return Err(Error::Message(
                    "extension response exceeds the relay frame limit; capture a smaller image"
                        .into(),
                ));
            }
            resp.ok(body).await?;
        }
    }
    Ok(())
}

async fn read_chunks(
    resp: &Responder,
    cancel: &CancellationToken,
    paths: &PathMap,
    host: &Arc<dyn NodeHost>,
    path: &str,
    mut offset: u64,
    max_bytes: u32,
) -> Result<()> {
    if max_bytes > 32 * 1024 * 1024 {
        return Err(Error::Message("max_bytes exceeds the 32 MiB limit".into()));
    }
    let mut left = max_bytes as usize;
    while left > 0 {
        if cancel.is_cancelled() {
            resp.end(None, Some("cancelled".into())).await?;
            return Ok(());
        }
        let ask = left.min(FILE_CHUNK) as u32;
        let bytes = files::read_guest(&paths.roots, host, path, offset, ask)?;
        if bytes.is_empty() {
            break;
        }
        resp.chunk("file", &bytes).await?;
        offset += bytes.len() as u64;
        left -= bytes.len();
        if (bytes.len() as u32) < ask {
            break;
        }
    }
    resp.end(None, None).await?;
    Ok(())
}

async fn run_exec(
    resp: &Responder,
    cancel: &CancellationToken,
    paths: &PathMap,
    host: &Arc<dyn NodeHost>,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    env: &[(String, String)],
    timeout_ms: Option<u64>,
    shell: bool,
    stdin_b64: Option<&str>,
) -> Result<()> {
    if program.is_empty() {
        return Err(Error::Message("command is empty".into()));
    }
    for (key, value) in env {
        if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
            return Err(Error::Message(format!("rejected env var '{key}'")));
        }
    }
    let cwd = map_cwd(&paths.roots, cwd)?.or_else(|| Some(paths.roots.files.display().to_string()));
    let session_id = resp.request_id.clone();
    let payload = json!({
        "session_id": session_id,
        "program": program,
        "args": args,
        "cwd": cwd,
        "env": env,
        "timeout_ms": timeout_ms,
        "shell": shell,
        "stdin_b64": stdin_b64,
    });
    let body = open_session(host, "exec", payload).await?;
    let session_id = body
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&session_id)
        .to_string();
    poll_until_end(resp, cancel, host, &session_id, timeout_ms, "stdout").await
}

async fn run_pty(
    resp: &Responder,
    cancel: &CancellationToken,
    paths: &PathMap,
    shells: &PhonePty,
    command: Option<&str>,
    cwd: Option<&str>,
    rows: u16,
    cols: u16,
) -> Result<()> {
    let session_id = resp.request_id.clone();
    let rows = rows.max(1);
    let cols = cols.max(1);
    let dir = match cwd {
        Some(path) if !path.is_empty() => paths::real_target(&paths.roots, path, false)?,
        _ => paths.roots.files.clone(),
    };
    shells.open(&session_id, command, rows, cols, &dir)?;
    if let Err(err) = resp
        .ack(json!({
            "session_id": session_id,
            "rows": rows,
            "cols": cols,
        }))
        .await
    {
        shells.close(&session_id).ok();
        return Err(err);
    }
    loop {
        if cancel.is_cancelled() {
            shells.close(&session_id).ok();
            resp.end(None, Some("cancelled".into())).await?;
            return Ok(());
        }
        match shells.poll(&session_id) {
            PtyPoll::Pending => tokio::time::sleep(Duration::from_millis(20)).await,
            PtyPoll::Chunk(bytes) => resp.chunk("pty", &bytes).await?,
            PtyPoll::Exit(code) => {
                shells.close(&session_id).ok();
                resp.end(Some(code), None).await?;
                return Ok(());
            }
        }
    }
}

async fn open_session(host: &Arc<dyn NodeHost>, kind: &str, payload: Value) -> Result<Value> {
    let kind = kind.to_string();
    let payload = payload.to_string();
    let host = host.clone();
    let raw = tokio::task::spawn_blocking(move || host.open_session(kind, payload))
        .await
        .map_err(|e| Error::Message(format!("host task: {e}")))?;
    host::parse_host(&raw)
}

async fn poll_until_end(
    resp: &Responder,
    cancel: &CancellationToken,
    host: &Arc<dyn NodeHost>,
    session_id: &str,
    timeout_ms: Option<u64>,
    default_stream: &str,
) -> Result<()> {
    let started = Instant::now();
    loop {
        if cancel.is_cancelled() {
            close_quiet(host, session_id).await;
            resp.end(None, Some("cancelled".into())).await?;
            return Ok(());
        }
        if let Some(ms) = timeout_ms {
            if started.elapsed() >= Duration::from_millis(ms) {
                close_quiet(host, session_id).await;
                resp.end(None, Some("timed out".into())).await?;
                return Ok(());
            }
        }
        let host = host.clone();
        let sid = session_id.to_string();
        let raw = tokio::task::spawn_blocking(move || host.poll_session(sid))
            .await
            .map_err(|e| Error::Message(format!("host task: {e}")))?;
        let body = host::parse_host(&raw)?;
        let event = body.get("event").and_then(|v| v.as_str()).unwrap_or("");
        match event {
            "pending" => tokio::time::sleep(Duration::from_millis(20)).await,
            "chunk" => {
                let stream = body
                    .get("stream")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_stream);
                let data =
                    util::b64_decode(body.get("data_b64").and_then(|v| v.as_str()).unwrap_or(""))?;
                resp.chunk(stream, &data).await?;
            }
            "exit" => {
                let code = body.get("code").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                resp.end(Some(code), None).await?;
                return Ok(());
            }
            _ => {
                return Err(Error::Message(format!("host session event '{event}'")));
            }
        }
    }
}

async fn close_quiet(host: &Arc<dyn NodeHost>, session_id: &str) {
    let host = host.clone();
    let sid = session_id.to_string();
    let _ = tokio::task::spawn_blocking(move || host.close_session(sid)).await;
}

fn map_cwd(roots: &Roots, cwd: Option<&str>) -> Result<Option<String>> {
    let Some(cwd) = cwd else {
        return Ok(None);
    };
    match paths::classify(roots, cwd, false)? {
        paths::GuestTarget::Real(path) => Ok(Some(path.display().to_string())),
        paths::GuestTarget::AppRoot => Ok(Some(roots.files.display().to_string())),
        _ => Err(Error::Message(
            "cwd must be an app or storage directory".into(),
        )),
    }
}

fn publish(
    host: &Arc<dyn NodeHost>,
    io: &NodeIo,
    state: &str,
    node_id: &str,
    policy: NodePolicy,
    detail: &str,
) {
    let id = if node_id.is_empty() {
        io.node_id.lock().map(|g| g.clone()).unwrap_or_default()
    } else {
        node_id.to_string()
    };
    let body = json!({
        "state": state,
        "node_id": id,
        "preset": policy.preset_name(),
        "detail": detail,
        "allow_read": policy.allow_read,
        "allow_write": policy.allow_write,
        "allow_exec": policy.allow_exec,
        "allow_desktop": policy.allow_desktop,
        "allow_desktop_stream": policy.allow_desktop_stream,
        "allow_remote_view": policy.allow_remote_view,
        "allow_remote_control": policy.allow_remote_control,
    })
    .to_string();
    if let Ok(mut slot) = io.status.lock() {
        *slot = body.clone();
    }
    host.on_status(body);
}

fn cancel_all(cancels: &Mutex<HashMap<String, CancellationToken>>) {
    if let Ok(map) = cancels.lock() {
        for token in map.values() {
            token.cancel();
        }
    }
}

fn normalized_relay(relay_url: &str, fingerprint: &str) -> (String, Option<String>) {
    let mut relay_url = relay_url.to_string();
    let mut trust = None;
    apply_relay_defaults(&mut relay_url, fingerprint, &mut trust);
    (relay_url, trust)
}

fn drop_link(live: &PhoneLive, generation: u64, audit: &AuditHub) {
    live.socket.detach(generation);
    schedule_idle_cleanup(live, generation);
    audit.set_tx(None);
}

fn schedule_idle_cleanup(live: &PhoneLive, generation: u64) {
    let shells = live.shells.clone();
    let cancels = live.cancels.clone();
    let socket = live.socket.clone();
    tokio::spawn(async move {
        tokio::time::sleep(agentlink_core::resume::RECONNECT_GIVE_UP).await;
        if socket.generation() == generation {
            shells.close_all();
            cancel_all(&cancels);
        }
    });
}

async fn replay_log(
    log: &ReplayLog,
    cursor: u64,
    seal: Option<&PhoneSeal>,
    tx: &mpsc::Sender<Outbound>,
) {
    for env in log.snapshot() {
        if env.seq() != 0 && env.seq() <= cursor {
            continue;
        }
        let encoded = if let Some(seal) = seal {
            match e2e::seal_envelope_session(&seal.session, &seal.node_id, &seal.peer, &env) {
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
