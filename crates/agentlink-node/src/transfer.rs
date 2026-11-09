//! Bulk transfers and the direct QUIC accept loop.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use agentlink_core::e2e::{self, Direction, Endpoint};
use agentlink_core::engine::{self, Link, Wire, XferOpts};
use agentlink_core::frame;
use agentlink_core::p2p::{self, QuicPeer};
use agentlink_core::protocol::{Envelope, TransferMsg, TransferStats};
use agentlink_core::ws::{self, Outbound};
use agentlink_core::{paths, Error, NodePolicy, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::audit;
use crate::pipeline::AuditService;

pub struct DirectReply {
    pub public_key: String,
    pub cert_fp: String,
    pub cert_sig: String,
    pub local_addrs: Vec<String>,
    pub reflexive: Option<String>,
}

#[derive(Clone)]
pub struct SealTarget {
    pub peer: String,
    pub node_id: String,
    pub client_id: String,
    /// Bound at open time so replies survive a later handshake for this peer.
    pub session: Option<std::sync::Arc<Direction>>,
}

pub struct TransferHost {
    pub sessions: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Wire>>>>,
    pub direct_wait: Arc<Mutex<HashMap<String, oneshot::Sender<DirectReply>>>>,
    pub allowed: Arc<Mutex<HashMap<String, Instant>>>,
    pub quic: Option<Arc<QuicPeer>>,
    pub tx: mpsc::Sender<Outbound>,
    pub policy: Arc<RwLock<NodePolicy>>,
    pub max_policy: NodePolicy,
    pub root: Option<PathBuf>,
    pub e2e: Endpoint,
    pub node_id: String,
    pub seals: Arc<Mutex<HashMap<String, SealTarget>>>,
    pub pending: Arc<Mutex<HashMap<String, oneshot::Sender<Envelope>>>>,
    pub audit: Arc<AuditService>,
}

pub fn spawn_accept(
    peer: Arc<QuicPeer>,
    allowed: Arc<Mutex<HashMap<String, Instant>>>,
    policy: Arc<RwLock<NodePolicy>>,
    max_policy: NodePolicy,
    root: Option<PathBuf>,
    audit: Arc<AuditService>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = peer.accept_one(&allowed) => {
                    match accepted {
                        Ok(link) => {
                            let policy = policy.clone();
                            let max_policy = max_policy;
                            let root = root.clone();
                            let audit = audit.clone();
                            tokio::spawn(async move {
                                if let Err(err) = serve_quic(link, &policy, max_policy, root.as_deref(), &audit).await {
                                    tracing::debug!(error = %err, "direct transfer ended");
                                }
                            });
                        }
                        Err(Error::Timeout) => {}
                        Err(Error::Auth(_)) => {}
                        Err(err) => {
                            tracing::debug!(error = %err, "quic accept ended");
                            if shutdown.is_cancelled() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    });
}

pub async fn on_transfer(
    host: Arc<TransferHost>,
    request_id: String,
    client_id: String,
    msg: TransferMsg,
    session: Option<std::sync::Arc<Direction>>,
    policy: Option<NodePolicy>,
) {
    if let Some(tx) = host
        .sessions
        .lock()
        .ok()
        .and_then(|map| map.get(&request_id).cloned())
    {
        let _ = tx.send(Wire::Msg(msg));
        return;
    }
    if let Ok(mut seals) = host.seals.lock() {
        seals.insert(
            request_id.clone(),
            SealTarget {
                peer: client_id.clone(),
                node_id: host.node_id.clone(),
                client_id: client_id.clone(),
                session,
            },
        );
    }
    let reply_node = request_id.clone();
    match msg {
        TransferMsg::Push {
            path,
            size,
            hash,
            chunk_size: _,
            compress: _,
            resume,
            mode,
            mtime_unix,
        } => {
            let mut link = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                let outcome = async {
                    ensure(&host, policy, true)?;
                    let dest = paths::resolve_lexical(host.root.as_deref(), &path)?;
                    engine::serve_push(
                        &dest,
                        Path::new(&path),
                        size,
                        hash,
                        0,
                        agentlink_core::protocol::CompressPref::Auto,
                        resume,
                        &mut link,
                        "relay",
                        mode,
                        mtime_unix,
                    )
                    .await
                }
                .await;
                finish(&host, &client_id, "push", &path, outcome, &mut link).await;
            });
        }
        TransferMsg::Pull {
            path,
            have_hash,
            have_ranges,
            chunk_size,
            compress,
            sigs,
        } => {
            let mut link = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                let outcome = async {
                    ensure(&host, policy, false)?;
                    let src = paths::resolve_lexical(host.root.as_deref(), &path)?;
                    let opts = xfer_opts(chunk_size, 8, 4, compress, "relay");
                    engine::serve_pull(
                        &src,
                        have_hash,
                        have_ranges,
                        sigs,
                        &mut link,
                        &request_id,
                        &opts,
                    )
                    .await
                }
                .await;
                finish(&host, &client_id, "pull", &path, outcome, &mut link).await;
            });
        }
        TransferMsg::PushDir {
            dest,
            manifest_hash: _,
            entries,
            chunk_size: _,
            compress: _,
        } => {
            let mut link = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                let outcome = async {
                    ensure(&host, policy, true)?;
                    let path = paths::resolve_lexical(host.root.as_deref(), &dest)?;
                    engine::serve_push_dir(&path, entries, &mut link, "relay").await
                }
                .await;
                finish(&host, &client_id, "push_dir", &dest, outcome, &mut link).await;
            });
        }
        TransferMsg::PullDir {
            path,
            have,
            chunk_size,
            compress,
        } => {
            let mut link = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                let outcome = async {
                    ensure(&host, policy, false)?;
                    let src = paths::resolve_lexical(host.root.as_deref(), &path)?;
                    let opts = xfer_opts(chunk_size, 8, 4, compress, "relay");
                    engine::serve_pull_dir(&src, have, &mut link, &request_id, &opts).await
                }
                .await;
                finish(&host, &client_id, "pull_dir", &path, outcome, &mut link).await;
            });
        }
        TransferMsg::PushStream { path, .. } => {
            let mut link = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                let outcome = async {
                    ensure(&host, policy, true)?;
                    if paths::path_trailing_sep(&path) {
                        return Err(Error::Message(format!(
                            "write destination `{path}` ends with a slash; pass a file path (use mkdir if you need a directory)"
                        )));
                    }
                    let dest = paths::resolve_lexical(host.root.as_deref(), &path)?;
                    engine::serve_push_stream(&dest, &mut link, "relay").await
                }
                .await;
                finish(&host, &client_id, "push_stream", &path, outcome, &mut link).await;
            });
        }
        TransferMsg::PullStream {
            path,
            offset,
            max_bytes,
            chunk_size,
            window,
            compress,
        } => {
            let mut link = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                let outcome = async {
                    ensure(&host, policy, false)?;
                    let src = paths::resolve_lexical(host.root.as_deref(), &path)?;
                    engine::serve_pull_stream(
                        &src,
                        offset,
                        max_bytes,
                        chunk_size,
                        window,
                        compress,
                        &mut link,
                        &request_id,
                        "relay",
                    )
                    .await
                }
                .await;
                finish(&host, &client_id, "pull_stream", &path, outcome, &mut link).await;
            });
        }
        TransferMsg::PeerCopy {
            dst_node,
            src_path,
            dst_path,
            chunk_size,
            window,
            parallel,
            compress,
            direct,
        } => {
            let client_link = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                let detail = format!("{src_path} -> {dst_node}:{dst_path}");
                let outcome = peer_copy(
                    &host, &src_path, &dst_node, &dst_path, chunk_size, window, parallel, compress,
                    direct, policy,
                )
                .await;
                match outcome {
                    Ok(stats) => {
                        note_transfer(
                            &host,
                            &client_id,
                            "peer_copy",
                            &detail,
                            true,
                            None,
                            Some(&stats),
                            &host.node_id,
                            &src_path,
                            &dst_node,
                            &dst_path,
                            "upload",
                        );
                        let _ = client_link.send_msg(TransferMsg::Done { stats }).await;
                    }
                    Err(err) => {
                        note_transfer(
                            &host,
                            &client_id,
                            "peer_copy",
                            &detail,
                            false,
                            Some(&err.to_string()),
                            None,
                            &host.node_id,
                            &src_path,
                            &dst_node,
                            &dst_path,
                            "upload",
                        );
                        let _ = client_link
                            .send_msg(TransferMsg::Failed {
                                message: err.to_string(),
                            })
                            .await;
                    }
                }
            });
        }

        TransferMsg::TunnelDial { host: remote_host, port: remote_port } => {
            let mut link = attach(&host, &request_id, &reply_node);
            let req = request_id.clone();
            tokio::spawn(async move {
                let detail = format!("{remote_host}:{remote_port}");
                let outcome = async {
                    ensure_exec(&host, policy)?;
                    let addr = format!("{remote_host}:{remote_port}");
                    let stream = TcpStream::connect(&addr).await.map_err(|err| {
                        Error::Message(format!("tunnel dial {addr}: {err}"))
                    })?;
                    link.send_msg(TransferMsg::TunnelReady).await?;
                    agentlink_core::tunnel::pump(stream, link, &req).await?;
                    Ok::<(), Error>(())
                }
                .await;
                if let Err(err) = outcome {
                    note_transfer(
                        &host, &client_id, "tunnel_dial", &detail, false, Some(&err.to_string()), None,
                        &host.node_id, &detail, "", "", "tunnel",
                    );
                } else {
                    note_transfer(
                        &host, &client_id, "tunnel_dial", &detail, true, None, None,
                        &host.node_id, &detail, "", "", "tunnel",
                    );
                }
            });
        }
        TransferMsg::TunnelBind { port } => {
            let mut control = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                if let Err(err) = run_tunnel_bind(&host, policy, port, &mut control, &client_id).await {
                    let _ = control
                        .send_msg(TransferMsg::Failed {
                            message: err.to_string(),
                        })
                        .await;
                    note_transfer(
                        &host, &client_id, "tunnel_bind", &format!("127.0.0.1:{port}"), false,
                        Some(&err.to_string()), None, &host.node_id, "", "", "", "tunnel",
                    );
                }
            });
        }
        TransferMsg::TunnelAccept { token } => {
            let mut link = attach(&host, &request_id, &reply_node);
            let req = request_id.clone();
            tokio::spawn(async move {
                let outcome = async {
                    ensure_exec(&host, policy)?;
                    let stream = take_waiting_stream(&token)?;
                    link.send_msg(TransferMsg::TunnelReady).await?;
                    agentlink_core::tunnel::pump(stream, link, &req).await?;
                    Ok::<(), Error>(())
                }
                .await;
                if let Err(err) = outcome {
                    note_transfer(
                        &host, &client_id, "tunnel_accept", &token, false, Some(&err.to_string()), None,
                        &host.node_id, &token, "", "", "tunnel",
                    );
                }
            });
        }

        other => {
            tracing::debug!(?other, "transfer message had no session");
        }
    }
}



fn waiting_streams() -> &'static Mutex<HashMap<String, TcpStream>> {
    static MAP: OnceLock<Mutex<HashMap<String, TcpStream>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn take_waiting_stream(token: &str) -> Result<TcpStream> {
    waiting_streams()
        .lock()
        .map_err(|_| Error::Message("tunnel wait poisoned".into()))?
        .remove(token)
        .ok_or_else(|| Error::Message(format!("unknown tunnel token {token}")))
}

fn ensure_exec(host: &TransferHost, policy: Option<NodePolicy>) -> Result<()> {
    let current = match policy {
        Some(p) => p,
        None => host
            .policy
            .read()
            .map(|g| *g)
            .unwrap_or(host.max_policy),
    };
    if current.allow_exec {
        Ok(())
    } else {
        Err(Error::Message(
            "exec is not allowed on this node (needed for port mapping)".into(),
        ))
    }
}

async fn run_tunnel_bind(
    host: &Arc<TransferHost>,
    policy: Option<NodePolicy>,
    port: u16,
    control: &mut Link,
    client_id: &str,
) -> Result<()> {
    ensure_exec(host, policy)?;
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|err| Error::Message(format!("tunnel bind 127.0.0.1:{port}: {err}")))?;
    let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    control
        .send_msg(TransferMsg::TunnelBound { port: bound })
        .await?;
    note_transfer(
        host,
        client_id,
        "tunnel_bind",
        &format!("127.0.0.1:{bound}"),
        true,
        None,
        None,
        &host.node_id,
        "",
        "",
        "",
        "tunnel",
    );
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|err| Error::Message(format!("tunnel accept: {err}")))?;
        let token = Uuid::new_v4().to_string();
        waiting_streams()
            .lock()
            .map_err(|_| Error::Message("tunnel wait poisoned".into()))?
            .insert(token.clone(), stream);
        if control
            .send_msg(TransferMsg::TunnelIncoming {
                token: token.clone(),
            })
            .await
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

/// Deliver a relay rejection to a transfer that is still waiting.
pub fn fail_session(host: &TransferHost, request_id: &str, message: String) {
    let Some(tx) = host
        .sessions
        .lock()
        .ok()
        .and_then(|map| map.get(request_id).cloned())
    else {
        return;
    };
    let _ = tx.send(Wire::Msg(TransferMsg::Failed { message }));
}

pub fn on_binary(host: &TransferHost, bytes: Vec<u8>) {
    let id = frame::request_id(&bytes);
    let bytes = if frame::is_e2e(&bytes) {
        let peer = id.as_ref().and_then(|id| {
            host.seals
                .lock()
                .ok()
                .and_then(|map| map.get(id).map(|seal| seal.peer.clone()))
        });
        let opened = e2e::open_frame_any(&host.e2e, peer.as_deref(), &bytes);
        // A second handshake for the same identity rotates keys. Dropping the
        // ciphertext makes serve_push wait forever; fail the transfer instead.
        if frame::is_e2e(&opened) {
            if let Some(id) = id {
                fail_session(host, &id, "e2e frame could not be opened".into());
            }
            return;
        }
        opened
    } else {
        bytes
    };
    let Some(id) = frame::request_id(&bytes) else {
        return;
    };
    if let Some(tx) = host
        .sessions
        .lock()
        .ok()
        .and_then(|map| map.get(&id).cloned())
    {
        let _ = tx.send(Wire::Frame(bytes));
    }
}

pub async fn on_direct_offer(host: &TransferHost, env: Envelope) {
    let Envelope::DirectOffer {
        request_id,
        public_key,
        ..
    } = env
    else {
        return;
    };
    if let Ok(mut allowed) = host.allowed.lock() {
        allowed.insert(public_key, Instant::now());
    }
    let Some(peer) = &host.quic else {
        return;
    };
    let answer = Envelope::DirectAnswer {
        request_id,
        public_key: peer.public_key.clone(),
        cert_fp: peer.cert_fp.clone(),
        cert_sig: peer.cert_sig.clone(),
        local_addrs: peer.local_addrs(None),
        reflexive: None,
    };
    if let Ok(out) = ws::encode(&answer) {
        let _ = host.tx.send(out).await;
    }
}

pub fn on_direct_answer(host: &TransferHost, env: Envelope) {
    let Envelope::DirectAnswer {
        request_id,
        public_key,
        cert_fp,
        cert_sig,
        local_addrs,
        reflexive,
    } = env
    else {
        return;
    };
    let tx = host
        .direct_wait
        .lock()
        .ok()
        .and_then(|mut map| map.remove(&request_id));
    if let Some(tx) = tx {
        let _ = tx.send(DirectReply {
            public_key,
            cert_fp,
            cert_sig,
            local_addrs,
            reflexive,
        });
    }
}

fn attach(host: &TransferHost, request_id: &str, reply_node: &str) -> Link {
    let (worker, mut adapter) = Link::pair(64);
    let (tx, mut rx) = mpsc::unbounded_channel();
    if let Ok(mut map) = host.sessions.lock() {
        map.insert(request_id.to_string(), tx);
    }
    let sessions = host.sessions.clone();
    let host_fwd = Arc::new(ForwardCtx {
        tx: host.tx.clone(),
        e2e: host.e2e.clone(),
        seals: host.seals.clone(),
    });
    let request_id = request_id.to_string();
    let reply_node = reply_node.to_string();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                incoming = rx.recv() => {
                    match incoming {
                        Some(wire) => {
                            if adapter.out.send(wire).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                outgoing = adapter.inp.recv() => {
                    let Some(wire) = outgoing else { break };
                    if forward_wire(host_fwd.as_ref(), &request_id, &reply_node, wire).await.is_err() {
                        break;
                    }
                }
            }
        }
        if let Ok(mut map) = sessions.lock() {
            map.remove(&request_id);
        }
    });
    worker
}

struct ForwardCtx {
    tx: mpsc::Sender<Outbound>,
    e2e: Endpoint,
    seals: Arc<Mutex<HashMap<String, SealTarget>>>,
}

async fn forward_wire(
    ctx: &ForwardCtx,
    request_id: &str,
    reply_node: &str,
    wire: Wire,
) -> Result<()> {
    let seal = ctx
        .seals
        .lock()
        .ok()
        .and_then(|map| map.get(request_id).cloned());
    let out = match wire {
        Wire::Msg(msg) => {
            let env = Envelope::Transfer {
                request_id: request_id.to_string(),
                node_id: seal
                    .as_ref()
                    .map(|seal| seal.node_id.clone())
                    .unwrap_or_else(|| reply_node.to_string()),
                client_id: seal
                    .as_ref()
                    .map(|seal| seal.client_id.clone())
                    .unwrap_or_else(|| "node".into()),
                terminal: msg.is_terminal(),
                msg,
                authz: None,
            };
            if let Some(seal) = seal.filter(|seal| ctx.e2e.has(&seal.peer)) {
                let wrapped = if let Some(session) = &seal.session {
                    e2e::seal_envelope_session(session, &seal.node_id, &seal.client_id, &env)?
                } else {
                    e2e::seal_envelope(
                        &ctx.e2e,
                        &seal.peer,
                        &seal.node_id,
                        &seal.client_id,
                        &env,
                    )?
                };
                ws::encode(&wrapped)?
            } else {
                ws::encode(&env)?
            }
        }
        Wire::Frame(bytes) => {
            if let Some(seal) = seal.filter(|seal| ctx.e2e.has(&seal.peer)) {
                let sealed = if let Some(session) = &seal.session {
                    session.seal_frame(&bytes).unwrap_or(bytes)
                } else {
                    ctx.e2e.seal_frame(&seal.peer, &bytes).unwrap_or(bytes)
                };
                Outbound::Binary(sealed)
            } else {
                Outbound::Binary(bytes)
            }
        }
    };
    ctx.tx
        .send(out)
        .await
        .map_err(|_| Error::Message("connection closed".into()))
}

fn note_transfer(
    host: &TransferHost,
    client_id: &str,
    op: &str,
    detail: &str,
    ok: bool,
    error: Option<&str>,
    stats: Option<&TransferStats>,
    src_node: &str,
    src_path: &str,
    dst_node: &str,
    dst_path: &str,
    direction: &str,
) {
    let blake3 = agentlink_core::delta::hash_file(Path::new(src_path))
        .or_else(|_| agentlink_core::delta::hash_file(Path::new(dst_path)))
        .unwrap_or_default();
    let mut extra = crate::pipeline::AuditExtra::default();
    extra.paths = vec![src_path.to_string(), dst_path.to_string()];
    let mut event = audit::event_for(
        agentlink_core::audit::category_for_action(op),
        op,
        client_id,
        detail,
        serde_json::json!({"detail": detail}),
        ok,
        error.map(str::to_string),
        std::time::Duration::ZERO,
    );
    event.paths = extra.paths;
    event.transfer = Some(agentlink_core::audit::TransferMeta {
        src_node: src_node.to_string(),
        src_path: src_path.to_string(),
        dst_node: dst_node.to_string(),
        dst_path: dst_path.to_string(),
        size: stats.map(|stats| stats.logical_bytes).unwrap_or(0),
        blake3,
        direction: direction.to_string(),
        path: stats
            .map(|stats| stats.transport.clone())
            .unwrap_or_else(|| "relay".into()),
        result: if ok { "ok".into() } else { "error".into() },
    });
    host.audit.submit(event);
}

async fn finish(
    host: &TransferHost,
    client_id: &str,
    op: &str,
    detail: &str,
    outcome: Result<TransferStats>,
    link: &mut Link,
) {
    let direction = if op.starts_with("pull") {
        "download"
    } else {
        "upload"
    };
    match outcome {
        Ok(stats) => {
            note_transfer(
                host,
                client_id,
                op,
                detail,
                true,
                None,
                Some(&stats),
                &host.node_id,
                detail,
                &host.node_id,
                detail,
                direction,
            );
        }
        Err(err) => {
            note_transfer(
                host,
                client_id,
                op,
                detail,
                false,
                Some(&err.to_string()),
                None,
                &host.node_id,
                detail,
                &host.node_id,
                detail,
                direction,
            );
            let _ = link
                .send_msg(TransferMsg::Failed {
                    message: err.to_string(),
                })
                .await;
        }
    }
}

async fn ensure_peer(host: &TransferHost, dst_node: &str) -> Result<()> {
    if host.e2e.has(dst_node) {
        return Ok(());
    }
    let pending = host.e2e.client_hello(dst_node)?;
    let request_id = Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel();
    host.pending
        .lock()
        .map_err(|_| Error::Message("e2e waiters poisoned".into()))?
        .insert(request_id.clone(), tx);
    let hello = Envelope::E2eHello {
        request_id: request_id.clone(),
        node_id: dst_node.to_string(),
        message_b64: agentlink_core::util::b64_encode(Endpoint::hello_bytes(&pending)),
    };
    if host.tx.send(ws::encode(&hello)?).await.is_err() {
        host.pending
            .lock()
            .ok()
            .map(|mut map| map.remove(&request_id));
        return Err(Error::Message("connection closed".into()));
    }
    // Keep this well under the client PeerCopy budget (12s) so a failed peer
    // handshake still leaves time for cleartext push or the download bridge.
    let welcome = tokio::time::timeout(Duration::from_secs(3), rx).await;
    let welcome = match welcome {
        Ok(Ok(env)) => env,
        _ => {
            host.pending
                .lock()
                .ok()
                .map(|mut map| map.remove(&request_id));
            return Err(Error::Message(
                "e2e handshake with the other node failed".into(),
            ));
        }
    };
    match welcome {
        Envelope::E2eWelcome { message_b64, .. } => {
            let bytes = agentlink_core::util::b64_decode(&message_b64)?;
            host.e2e.complete(pending, &bytes)?;
            Ok(())
        }
        Envelope::Result { error, .. } => Err(Error::Message(
            error.unwrap_or_else(|| "e2e handshake rejected".into()),
        )),
        _ => Err(Error::Protocol("expected an e2e welcome".into())),
    }
}

async fn peer_copy(
    host: &TransferHost,
    src_path: &str,
    dst_node: &str,
    dst_path: &str,
    chunk_size: u32,
    window: usize,
    parallel: usize,
    compress: agentlink_core::protocol::CompressPref,
    direct: bool,
    policy: Option<NodePolicy>,
) -> Result<TransferStats> {
    ensure(host, policy, false)?;
    let src = paths::resolve_lexical(host.root.as_deref(), src_path)?;
    let dir = src.is_dir();
    // Directories stay allowed; a FIFO/socket/device would block perform_push
    // (or std::fs::copy for same-node) forever on open/read.
    if !dir {
        engine::ensure_pullable_file(&src)?;
    }
    // Same-node peer copy must not bounce through the relay: the Push would be
    // delivered back into the sender's transfer session and hang or confuse the client.
    if dst_node == host.node_id {
        ensure(host, policy, true)?;
        let dest = paths::resolve_lexical(host.root.as_deref(), dst_path)?;
        return local_fs_copy(&src, &dest);
    }
    if direct {
        if let Ok(mut link) = negotiate(host, dst_node).await {
            let opts = xfer_opts(chunk_size, window, parallel, compress, "quic");
            let id = Uuid::new_v4().to_string();
            return if dir {
                engine::perform_push_dir(&src, dst_path, &mut link, &id, &opts, &None).await
            } else {
                engine::perform_push(&src, dst_path, &mut link, &id, &opts, &None).await
            };
        }
    }
    let request_id = Uuid::new_v4().to_string();
    // Best-effort node-to-node e2e. A failure must not block the copy: the relay
    // can forward plaintext Transfer frames between same-owner nodes.
    if let Err(err) = ensure_peer(host, dst_node).await {
        tracing::warn!(error = %err, peer = %dst_node, "peer e2e unavailable; using relay cleartext");
    }
    if let Ok(mut seals) = host.seals.lock() {
        seals.insert(
            request_id.clone(),
            SealTarget {
                peer: dst_node.to_string(),
                node_id: dst_node.to_string(),
                client_id: host.node_id.clone(),
                session: None,
            },
        );
    }
    let mut link = attach(host, &request_id, dst_node);
    let opts = xfer_opts(chunk_size, window, parallel, compress, "relay");
    if dir {
        engine::perform_push_dir(&src, dst_path, &mut link, &request_id, &opts, &None).await
    } else {
        engine::perform_push(&src, dst_path, &mut link, &request_id, &opts, &None).await
    }
}

fn local_fs_copy(src: &Path, dest: &Path) -> Result<TransferStats> {
    let (logical, files) = copy_tree(src, dest)?;
    Ok(TransferStats {
        logical_bytes: logical,
        payload_bytes: logical,
        skipped: false,
        files,
        files_skipped: 0,
        compressed: false,
        transport: "local".into(),
        delta_copy_bytes: 0,
        resumed_bytes: 0,
    })
}

fn copy_tree(src: &Path, dest: &Path) -> Result<(u64, u32)> {
    if src.is_dir() {
        agentlink_core::util::create_dir_all_as_dir(dest)?;
        let mut logical = 0u64;
        let mut files = 0u32;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let (b, f) = copy_tree(&entry.path(), &dest.join(entry.file_name()))?;
            logical = logical.saturating_add(b);
            files = files.saturating_add(f);
        }
        Ok((logical, files))
    } else {
        engine::ensure_pullable_file(src)?;
        if let Some(parent) = dest.parent() {
            agentlink_core::util::create_dir_all_parent(parent)?;
        }
        let n = std::fs::copy(src, dest)?;
        Ok((n, 1))
    }
}

async fn negotiate(host: &TransferHost, dst_node: &str) -> Result<Link> {
    let peer = host
        .quic
        .clone()
        .ok_or_else(|| Error::Message("direct path is not bound".into()))?;
    let request_id = Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel();
    host.direct_wait
        .lock()
        .map_err(|_| Error::Message("direct waiters poisoned".into()))?
        .insert(request_id.clone(), tx);
    let offer = Envelope::DirectOffer {
        request_id: request_id.clone(),
        node_id: dst_node.to_string(),
        public_key: peer.public_key.clone(),
        cert_fp: peer.cert_fp.clone(),
        cert_sig: peer.cert_sig.clone(),
        local_addrs: peer.local_addrs(None),
        reflexive: None,
    };
    if host.tx.send(ws::encode(&offer)?).await.is_err() {
        let _ = host
            .direct_wait
            .lock()
            .map(|mut map| map.remove(&request_id));
        return Err(Error::Message("connection closed".into()));
    }
    let reply = tokio::time::timeout(Duration::from_secs(2), rx).await;
    let reply = match reply {
        Ok(Ok(reply)) => reply,
        _ => {
            let _ = host
                .direct_wait
                .lock()
                .map(|mut map| map.remove(&request_id));
            return Err(Error::Timeout);
        }
    };
    let addrs = p2p::parse_addrs(&reply.local_addrs, reply.reflexive.as_deref());
    peer.dial(&addrs, &reply.cert_fp, &reply.public_key, &reply.cert_sig)
        .await
}

async fn serve_quic(
    mut link: Link,
    policy: &RwLock<NodePolicy>,
    max_policy: NodePolicy,
    root: Option<&Path>,
    audit: &AuditService,
) -> Result<()> {
    let first = link.recv().await?;
    let Wire::Msg(msg) = first else {
        return Err(Error::Protocol(
            "direct transfer must start with a control message".into(),
        ));
    };
    let id = Uuid::new_v4().to_string();
    let outcome = match msg {
        TransferMsg::Push {
            path,
            size,
            hash,
            resume,
            mode,
            mtime_unix,
            ..
        } => {
            ensure_policy(policy, max_policy, true)?;
            let dest = paths::resolve_lexical(root, &path)?;
            let result = engine::serve_push(
                &dest,
                Path::new(&path),
                size,
                hash,
                0,
                agentlink_core::protocol::CompressPref::Auto,
                resume,
                &mut link,
                "quic",
                mode,
                mtime_unix,
            )
            .await;
            audit_result(audit, "push", &path, &result);
            result.map(|_| ())
        }
        TransferMsg::PushDir { dest, entries, .. } => {
            ensure_policy(policy, max_policy, true)?;
            let path = paths::resolve_lexical(root, &dest)?;
            let result = engine::serve_push_dir(&path, entries, &mut link, "quic").await;
            audit_result(audit, "push_dir", &dest, &result);
            result.map(|_| ())
        }
        TransferMsg::Pull {
            path,
            have_hash,
            have_ranges,
            chunk_size,
            compress,
            sigs,
        } => {
            ensure_policy(policy, max_policy, false)?;
            let src = paths::resolve_lexical(root, &path)?;
            let opts = xfer_opts(chunk_size, 8, 4, compress, "quic");
            let result =
                engine::serve_pull(&src, have_hash, have_ranges, sigs, &mut link, &id, &opts).await;
            audit_result(audit, "pull", &path, &result);
            result.map(|_| ())
        }
        TransferMsg::PullDir {
            path,
            have,
            chunk_size,
            compress,
        } => {
            ensure_policy(policy, max_policy, false)?;
            let src = paths::resolve_lexical(root, &path)?;
            let opts = xfer_opts(chunk_size, 8, 4, compress, "quic");
            let result = engine::serve_pull_dir(&src, have, &mut link, &id, &opts).await;
            audit_result(audit, "pull_dir", &path, &result);
            result.map(|_| ())
        }
        TransferMsg::PushStream { path, .. } => {
            ensure_policy(policy, max_policy, true)?;
            if paths::path_trailing_sep(&path) {
                return Err(Error::Message(format!(
                    "write destination `{path}` ends with a slash; pass a file path (use mkdir if you need a directory)"
                )));
            }
            let dest = paths::resolve_lexical(root, &path)?;
            let result = engine::serve_push_stream(&dest, &mut link, "quic").await;
            audit_result(audit, "push_stream", &path, &result);
            result.map(|_| ())
        }
        TransferMsg::PullStream {
            path,
            offset,
            max_bytes,
            chunk_size,
            window,
            compress,
        } => {
            ensure_policy(policy, max_policy, false)?;
            let src = paths::resolve_lexical(root, &path)?;
            let result = engine::serve_pull_stream(
                &src, offset, max_bytes, chunk_size, window, compress, &mut link, &id, "quic",
            )
            .await;
            audit_result(audit, "pull_stream", &path, &result);
            result.map(|_| ())
        }
        other => Err(Error::Protocol(format!(
            "direct path cannot start with {other:?}"
        ))),
    };
    if let Err(err) = outcome {
        let _ = link
            .send_msg(TransferMsg::Failed {
                message: err.to_string(),
            })
            .await;
    }
    Ok(())
}

fn audit_result(audit: &AuditService, op: &str, detail: &str, result: &Result<TransferStats>) {
    let (ok, error) = match result {
        Ok(_) => (true, None),
        Err(err) => (false, Some(err.to_string())),
    };
    let mut event = audit::event_for(
        agentlink_core::audit::category_for_action(op),
        op,
        "",
        detail,
        serde_json::json!({"detail": detail, "transport": "quic"}),
        ok,
        error,
        std::time::Duration::ZERO,
    );
    event.paths = vec![detail.to_string()];
    event.transfer = Some(agentlink_core::audit::TransferMeta {
        src_node: String::new(),
        src_path: detail.to_string(),
        dst_node: String::new(),
        dst_path: detail.to_string(),
        size: result
            .as_ref()
            .map(|stats| stats.logical_bytes)
            .unwrap_or(0),
        blake3: String::new(),
        direction: if op.starts_with("pull") {
            "download".into()
        } else {
            "upload".into()
        },
        path: "quic".into(),
        result: if ok { "ok".into() } else { "error".into() },
    });
    audit.submit(event);
}

fn ensure(host: &TransferHost, policy: Option<NodePolicy>, write: bool) -> Result<()> {
    match policy {
        Some(current) => policy_allows(current, write),
        None => ensure_policy(&host.policy, host.max_policy, write),
    }
}

fn policy_allows(current: NodePolicy, write: bool) -> Result<()> {
    if write && !current.allow_write {
        return Err(Error::PermissionDenied(
            "write is not allowed on this node".into(),
        ));
    }
    if !write && !current.allow_read {
        return Err(Error::PermissionDenied(
            "read is not allowed on this node".into(),
        ));
    }
    Ok(())
}

fn ensure_policy(policy: &RwLock<NodePolicy>, fallback: NodePolicy, write: bool) -> Result<()> {
    let current = policy.read().map(|guard| *guard).unwrap_or(fallback);
    policy_allows(current, write)
}

fn xfer_opts(
    chunk_size: u32,
    window: usize,
    parallel: usize,
    compress: agentlink_core::protocol::CompressPref,
    transport: &str,
) -> XferOpts {
    XferOpts {
        chunk_size: chunk_size as usize,
        window,
        parallel,
        compress,
        resume: true,
        transport: transport.into(),
    }
    .normalized()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn copy_tree_refuses_fifo_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("tree");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("ok.txt"), b"ok").unwrap();
        let fifo = src.join("pipe");
        let status = agentlink_core::process::hidden("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());

        let err = copy_tree(&src, &dir.path().join("dest"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn local_fs_copy_refuses_char_device() {
        let dir = tempfile::tempdir().unwrap();
        let err = local_fs_copy(Path::new("/dev/null"), &dir.path().join("dest"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a regular file"), "{err}");
    }
}
