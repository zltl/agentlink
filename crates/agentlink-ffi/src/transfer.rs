//! Fast transfer on the phone.
//!
//! This is the same engine the desktop node uses: binary frames, a sliding
//! window, BLAKE3 skip, block delta, zstd, and QUIC with relay fallback.
//! Guest paths are mapped onto real files first. A SAF folder is staged into
//! the cache by the Android host. The copy back into that folder finishes
//! before the client is told the transfer is done.

#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use agentlink_core::e2e::{self, Direction, Endpoint};
use agentlink_core::engine::{self, Link, Wire, XferOpts};
use agentlink_core::frame;
use agentlink_core::p2p::{self, QuicPeer};
use agentlink_core::protocol::{CompressPref, Envelope, TransferMsg, TransferStats};
use agentlink_core::ws::{self, Outbound};
use agentlink_core::{Error, NodePolicy, Result};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::audit::AuditHub;
use crate::files;
use crate::host::{self, NodeHost};
use crate::paths::{self, GuestTarget, Roots};

pub struct DirectReply {
    pub public_key: String,
    pub cert_fp: String,
    pub cert_sig: String,
    pub local_addrs: Vec<String>,
    pub reflexive: Option<String>,
}

pub(crate) struct Staged {
    real: PathBuf,
    publish: bool,
    guest: String,
}

pub struct PathMap {
    pub roots: Roots,
    pub host: Arc<dyn NodeHost>,
}

impl PathMap {
    pub async fn stage(&self, guest: &str, write: bool) -> Result<Staged> {
        match paths::classify(&self.roots, guest, write)? {
            GuestTarget::Real(real) => Ok(Staged {
                real,
                publish: false,
                guest: guest.to_string(),
            }),
            GuestTarget::Audit if !write => Ok(Staged {
                real: self.roots.audit.clone(),
                publish: false,
                guest: guest.to_string(),
            }),
            GuestTarget::Device if !write => {
                let host = self.host.clone();
                let bytes = tokio::task::spawn_blocking(move || files::device_bytes(&host))
                    .await
                    .map_err(|e| Error::Message(format!("host task: {e}")))??;
                let real = self.roots.cache.join(".agentlink-device.json");
                if let Some(parent) = real.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&real, bytes)?;
                Ok(Staged {
                    real,
                    publish: false,
                    guest: guest.to_string(),
                })
            }
            GuestTarget::Saf(path) => {
                let host = self.host.clone();
                let asked = path.clone();
                let body = tokio::task::spawn_blocking(move || {
                    host::parse_host(&host.prepare_path(asked, write))
                })
                .await
                .map_err(|e| Error::Message(format!("host task: {e}")))??;
                let real =
                    PathBuf::from(body.get("real_path").and_then(|v| v.as_str()).unwrap_or(""));
                if real.as_os_str().is_empty() {
                    return Err(Error::Message(
                        "host did not stage a filesystem path".into(),
                    ));
                }
                paths::ensure_inside(&self.roots, &real)?;
                Ok(Staged {
                    real,
                    publish: write,
                    guest: path,
                })
            }
            _ => Err(Error::Message(format!(
                "{guest} cannot be transferred; copy app:/files, app:/cache, or storage:/"
            ))),
        }
    }

    pub async fn publish(&self, staged: &Staged) -> Result<()> {
        if !staged.publish {
            return Ok(());
        }
        let host = self.host.clone();
        let guest = staged.guest.clone();
        let real = staged.real.display().to_string();
        tokio::task::spawn_blocking(move || host::parse_host(&host.publish_path(guest, real)))
            .await
            .map_err(|e| Error::Message(format!("host task: {e}")))??;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SealTarget {
    pub peer: String,
    pub node_id: String,
    pub client_id: String,
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
    pub paths: Arc<PathMap>,
    pub e2e: Endpoint,
    pub node_id: String,
    pub seals: Arc<Mutex<HashMap<String, SealTarget>>>,
    pub audit: Arc<AuditHub>,
}

pub fn spawn_accept(
    peer: Arc<QuicPeer>,
    allowed: Arc<Mutex<HashMap<String, Instant>>>,
    policy: Arc<RwLock<NodePolicy>>,
    max_policy: NodePolicy,
    paths: Arc<PathMap>,
    audit: Arc<AuditHub>,
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
                            let paths = paths.clone();
                            let audit = audit.clone();
                            tokio::spawn(async move {
                                if let Err(err) = serve_quic(link, &policy, max_policy, &paths, &audit).await {
                                    tracing::debug!(error = %err, "direct transfer ended");
                                }
                            });
                        }
                        Err(Error::Timeout) | Err(Error::Auth(_)) => {}
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

pub async fn on_transfer(
    host: Arc<TransferHost>,
    request_id: String,
    client_id: String,
    msg: TransferMsg,
    session: Option<std::sync::Arc<Direction>>,
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
            resume,
            mode,
            mtime_unix,
            ..
        } => {
            let mut link = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                let outcome = async {
                    ensure(&host, true)?;
                    let staged = host.paths.stage(&path, true).await?;
                    push_file(
                        host.paths.as_ref(),
                        &mut link,
                        &staged,
                        &path,
                        size,
                        hash,
                        resume,
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
                    ensure(&host, false)?;
                    let staged = host.paths.stage(&path, false).await?;
                    let opts = xfer_opts(chunk_size, 8, 4, compress, "relay");
                    engine::serve_pull(
                        &staged.real,
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
        TransferMsg::PushDir { dest, entries, .. } => {
            let mut link = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                let outcome = async {
                    ensure(&host, true)?;
                    let staged = host.paths.stage(&dest, true).await?;
                    push_dir(host.paths.as_ref(), &mut link, &staged, entries, "relay").await
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
                    ensure(&host, false)?;
                    let staged = host.paths.stage(&path, false).await?;
                    let opts = xfer_opts(chunk_size, 8, 4, compress, "relay");
                    engine::serve_pull_dir(&staged.real, have, &mut link, &request_id, &opts).await
                }
                .await;
                finish(&host, &client_id, "pull_dir", &path, outcome, &mut link).await;
            });
        }
        TransferMsg::PushStream { path, .. } => {
            let mut link = attach(&host, &request_id, &reply_node);
            tokio::spawn(async move {
                let outcome = async {
                    ensure(&host, true)?;
                    let staged = host.paths.stage(&path, true).await?;
                    push_stream(host.paths.as_ref(), &mut link, &staged, "relay").await
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
                    ensure(&host, false)?;
                    let staged = host.paths.stage(&path, false).await?;
                    engine::serve_pull_stream(
                        &staged.real,
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
                    direct,
                )
                .await;
                match outcome {
                    Ok(stats) => {
                        crate::audit::submit_op(
                            &host.audit,
                            "peer_copy",
                            &client_id,
                            &detail,
                            true,
                            None,
                        );
                        let _ = client_link.send_msg(TransferMsg::Done { stats }).await;
                    }
                    Err(err) => {
                        crate::audit::submit_op(
                            &host.audit,
                            "peer_copy",
                            &client_id,
                            &detail,
                            false,
                            Some(err.to_string()),
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
        other => {
            tracing::debug!(?other, "transfer message had no session");
        }
    }
}

pub fn on_binary(host: &TransferHost, bytes: Vec<u8>) {
    let id = frame::request_id(&bytes);
    let peer = id.as_ref().and_then(|id| {
        host.seals
            .lock()
            .ok()
            .and_then(|map| map.get(id).map(|seal| seal.peer.clone()))
    });
    let bytes = e2e::open_frame_any(&host.e2e, peer.as_deref(), &bytes);
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
    let ctx = ForwardCtx {
        tx: host.tx.clone(),
        e2e: host.e2e.clone(),
        seals: host.seals.clone(),
    };
    let sessions = host.sessions.clone();
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
                    if forward_wire(&ctx, &request_id, &reply_node, wire).await.is_err() {
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

async fn push_file(
    paths: &PathMap,
    link: &mut Link,
    staged: &Staged,
    guest: &str,
    size: u64,
    hash: String,
    resume: bool,
    transport: &str,
    mode: Option<u32>,
    mtime_unix: Option<u64>,
) -> Result<TransferStats> {
    let real = staged.real.clone();
    let label = PathBuf::from(guest);
    if !staged.publish {
        return engine::serve_push(
            &real,
            &label,
            size,
            hash,
            0,
            CompressPref::Auto,
            resume,
            link,
            transport,
            mode,
            mtime_unix,
        )
        .await;
    }
    let (mut engine, hold) = hold_done(link);
    let served = engine::serve_push(
        &real,
        &label,
        size,
        hash,
        0,
        CompressPref::Auto,
        resume,
        &mut engine,
        transport,
        mode,
        mtime_unix,
    )
    .await;
    drop(engine);
    publish_then_release(paths, staged, hold, served).await
}

async fn push_dir(
    paths: &PathMap,
    link: &mut Link,
    staged: &Staged,
    entries: Vec<agentlink_core::protocol::ManifestEntry>,
    transport: &str,
) -> Result<TransferStats> {
    let real = staged.real.clone();
    if !staged.publish {
        return engine::serve_push_dir(&real, entries, link, transport).await;
    }
    let (mut engine, hold) = hold_done(link);
    let served = engine::serve_push_dir(&real, entries, &mut engine, transport).await;
    drop(engine);
    publish_then_release(paths, staged, hold, served).await
}

async fn push_stream(
    paths: &PathMap,
    link: &mut Link,
    staged: &Staged,
    transport: &str,
) -> Result<TransferStats> {
    let real = staged.real.clone();
    if !staged.publish {
        return engine::serve_push_stream(&real, link, transport).await;
    }
    let (mut engine, hold) = hold_done(link);
    let served = engine::serve_push_stream(&real, &mut engine, transport).await;
    drop(engine);
    publish_then_release(paths, staged, hold, served).await
}

async fn publish_staged(paths: &PathMap, staged: &Staged) -> Result<()> {
    paths
        .publish(&Staged {
            real: staged.real.clone(),
            publish: true,
            guest: staged.guest.clone(),
        })
        .await
}

enum Release {
    Forward,
    Fail(String),
}

struct DoneHold {
    pump: tokio::task::JoinHandle<bool>,
    gate_tx: oneshot::Sender<Release>,
}

/// Copy the staged file back, then let the held `Done` through.
/// A failed transfer is not published. A failed copy-back becomes `Failed`
/// instead of a `Done` the client would treat as success.
async fn publish_then_release(
    paths: &PathMap,
    staged: &Staged,
    hold: DoneHold,
    served: Result<TransferStats>,
) -> Result<TransferStats> {
    let published = if served.is_ok() {
        publish_staged(paths, staged).await
    } else {
        Ok(())
    };
    release_after_publish(hold, served, published).await
}

/// Messages other than `Done` pass through. `Done` waits until [`release_after_publish`].
fn hold_done(link: &mut Link) -> (Link, DoneHold) {
    let (engine_tx, mut from_engine) = mpsc::channel(64);
    let (to_engine_tx, engine_rx) = mpsc::channel(64);
    let engine_link = Link {
        out: engine_tx,
        inp: engine_rx,
    };
    let orig_out = link.out.clone();
    let (dummy_tx, dummy_rx) = mpsc::channel(1);
    drop(dummy_tx);
    let mut orig_in = std::mem::replace(&mut link.inp, dummy_rx);
    let (gate_tx, gate_rx) = oneshot::channel::<Release>();
    let pump = tokio::spawn(async move {
        let mut forwarded = false;
        loop {
            tokio::select! {
                biased;
                wire = from_engine.recv() => {
                    match wire {
                        Some(Wire::Msg(TransferMsg::Done { stats })) => {
                            forwarded = match gate_rx.await {
                                Ok(Release::Forward) => orig_out
                                    .send(Wire::Msg(TransferMsg::Done { stats }))
                                    .await
                                    .is_ok(),
                                Ok(Release::Fail(message)) => orig_out
                                    .send(Wire::Msg(TransferMsg::Failed { message }))
                                    .await
                                    .is_ok(),
                                Err(_) => false,
                            };
                            break;
                        }
                        Some(other) => {
                            if orig_out.send(other).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                incoming = orig_in.recv() => {
                    match incoming {
                        Some(wire) => {
                            if to_engine_tx.send(wire).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        forwarded
    });
    (engine_link, DoneHold { pump, gate_tx })
}

async fn release_after_publish(
    hold: DoneHold,
    served: Result<TransferStats>,
    published: Result<()>,
) -> Result<TransferStats> {
    let stats = match served {
        Ok(stats) => stats,
        Err(err) => {
            let _ = hold.gate_tx.send(Release::Fail(err.to_string()));
            let _ = hold.pump.await;
            return Err(err);
        }
    };
    match published {
        Ok(()) => {
            let _ = hold.gate_tx.send(Release::Forward);
            let forwarded = hold.pump.await.unwrap_or(false);
            if !forwarded {
                return Err(Error::Message(
                    "transfer ended before the done message was delivered".into(),
                ));
            }
            Ok(stats)
        }
        Err(err) => {
            let _ = hold.gate_tx.send(Release::Fail(err.to_string()));
            let _ = hold.pump.await;
            Err(err)
        }
    }
}

async fn finish(
    host: &TransferHost,
    client_id: &str,
    op: &str,
    detail: &str,
    outcome: Result<TransferStats>,
    link: &mut Link,
) {
    match outcome {
        Ok(_) => crate::audit::submit_op(&host.audit, op, client_id, detail, true, None),
        Err(err) => {
            crate::audit::submit_op(
                &host.audit,
                op,
                client_id,
                detail,
                false,
                Some(err.to_string()),
            );
            let _ = link
                .send_msg(TransferMsg::Failed {
                    message: err.to_string(),
                })
                .await;
        }
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
    compress: CompressPref,
    direct: bool,
) -> Result<TransferStats> {
    ensure(host, false)?;
    let staged = host.paths.stage(src_path, false).await?;
    let dir = staged.real.is_dir();
    if direct {
        if let Ok(mut link) = negotiate(host, dst_node).await {
            let opts = xfer_opts(chunk_size, window, parallel, compress, "quic");
            let id = Uuid::new_v4().to_string();
            return if dir {
                engine::perform_push_dir(&staged.real, dst_path, &mut link, &id, &opts, &None).await
            } else {
                engine::perform_push(&staged.real, dst_path, &mut link, &id, &opts, &None).await
            };
        }
    }
    let request_id = Uuid::new_v4().to_string();
    let mut link = attach(host, &request_id, dst_node);
    let opts = xfer_opts(chunk_size, window, parallel, compress, "relay");
    if dir {
        engine::perform_push_dir(&staged.real, dst_path, &mut link, &request_id, &opts, &None).await
    } else {
        engine::perform_push(&staged.real, dst_path, &mut link, &request_id, &opts, &None).await
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
    paths: &PathMap,
    audit: &AuditHub,
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
            let staged = paths.stage(&path, true).await?;
            let result =
                push_file(paths, &mut link, &staged, &path, size, hash, resume, "quic", mode, mtime_unix).await;
            audit_result(audit, "push", &path, &result);
            result.map(|_| ())
        }
        TransferMsg::PushDir { dest, entries, .. } => {
            ensure_policy(policy, max_policy, true)?;
            let staged = paths.stage(&dest, true).await?;
            let result = push_dir(paths, &mut link, &staged, entries, "quic").await;
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
            let staged = paths.stage(&path, false).await?;
            let opts = xfer_opts(chunk_size, 8, 4, compress, "quic");
            let result = engine::serve_pull(
                &staged.real,
                have_hash,
                have_ranges,
                sigs,
                &mut link,
                &id,
                &opts,
            )
            .await;
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
            let staged = paths.stage(&path, false).await?;
            let opts = xfer_opts(chunk_size, 8, 4, compress, "quic");
            let result = engine::serve_pull_dir(&staged.real, have, &mut link, &id, &opts).await;
            audit_result(audit, "pull_dir", &path, &result);
            result.map(|_| ())
        }
        TransferMsg::PushStream { path, .. } => {
            ensure_policy(policy, max_policy, true)?;
            let staged = paths.stage(&path, true).await?;
            let result = push_stream(paths, &mut link, &staged, "quic").await;
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
            let staged = paths.stage(&path, false).await?;
            let result = engine::serve_pull_stream(
                &staged.real,
                offset,
                max_bytes,
                chunk_size,
                window,
                compress,
                &mut link,
                &id,
                "quic",
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

fn audit_result(hub: &AuditHub, op: &str, detail: &str, result: &Result<TransferStats>) {
    match result {
        Ok(_) => crate::audit::submit_op(hub, op, "quic", detail, true, None),
        Err(err) => crate::audit::submit_op(hub, op, "quic", detail, false, Some(err.to_string())),
    }
}

fn ensure(host: &TransferHost, write: bool) -> Result<()> {
    ensure_policy(&host.policy, host.max_policy, write)
}

fn ensure_policy(policy: &RwLock<NodePolicy>, fallback: NodePolicy, write: bool) -> Result<()> {
    let current = policy.read().map(|guard| *guard).unwrap_or(fallback);
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use agentlink_core::protocol::AcceptMode;

    use super::*;

    fn sample_stats() -> TransferStats {
        TransferStats {
            logical_bytes: 4,
            payload_bytes: 4,
            skipped: false,
            files: 1,
            files_skipped: 0,
            compressed: false,
            transport: "relay".into(),
            delta_copy_bytes: 0,
            resumed_bytes: 0,
        }
    }

    #[tokio::test]
    async fn done_is_held_until_publish_finishes() {
        let (mut client, mut server) = Link::pair(8);
        let (engine, hold) = hold_done(&mut server);
        let copied = Arc::new(AtomicBool::new(false));
        let sender = tokio::spawn(async move {
            engine
                .send_msg(TransferMsg::Accept {
                    mode: AcceptMode::Skip,
                })
                .await
                .unwrap();
            engine
                .send_msg(TransferMsg::Done {
                    stats: sample_stats(),
                })
                .await
                .unwrap();
        });

        match client.recv().await.unwrap() {
            Wire::Msg(TransferMsg::Accept {
                mode: AcceptMode::Skip,
            }) => {}
            other => panic!("expected accept, got {other:?}"),
        }
        let early = tokio::time::timeout(Duration::from_millis(150), client.recv()).await;
        assert!(early.is_err(), "done arrived before publish: {early:?}");
        copied.store(true, Ordering::SeqCst);
        let forwarded = {
            let _ = hold.gate_tx.send(Release::Forward);
            hold.pump.await.unwrap_or(false)
        };
        assert!(forwarded);
        match tokio::time::timeout(Duration::from_secs(2), client.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Wire::Msg(TransferMsg::Done { .. }) => {}
            other => panic!("expected done, got {other:?}"),
        }
        assert!(copied.load(Ordering::SeqCst));
        sender.await.unwrap();
    }
}

fn xfer_opts(
    chunk_size: u32,
    window: usize,
    parallel: usize,
    compress: CompressPref,
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
