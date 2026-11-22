//! Bulk transfers and the direct QUIC accept loop.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use agentlink_core::e2e::{self, Direction, Endpoint};
use agentlink_core::engine::{self, Link, Wire, XferOpts};
use agentlink_core::frame;
use agentlink_core::p2p::QuicPeer;
use agentlink_core::protocol::{Envelope, ManifestEntry, TransferMsg, TransferStats};
use agentlink_core::ws::{self, Outbound};
use agentlink_core::{paths, Error, NodePolicy, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::audit;
use crate::pipeline::AuditService;

const MAX_WAITING_STREAMS: usize = 128;
const WAITING_STREAM_TTL: Duration = Duration::from_secs(30);

pub type TunnelGrantHook = Arc<dyn Fn(&str) -> bool + Send + Sync>;

struct TunnelSession {
    #[allow(dead_code)]
    owner_peer: String,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
    cancel: CancellationToken,
}

struct WaitingStream {
    stream: TcpStream,
    owner_peer: String,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
    bind_request_id: String,
    created_at: Instant,
}

#[derive(Default)]
pub struct TunnelRegistry {
    sessions: Mutex<HashMap<String, TunnelSession>>,
    waiting: Mutex<HashMap<String, WaitingStream>>,
    grant_active: RwLock<Option<TunnelGrantHook>>,
}

impl TunnelRegistry {
    pub fn set_grant_active(&self, hook: Option<TunnelGrantHook>) {
        if let Ok(mut slot) = self.grant_active.write() {
            *slot = hook;
        }
    }

    fn grant_hook(&self) -> Option<TunnelGrantHook> {
        self.grant_active
            .read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn check_grant(&self, grant_jti: &str, grant_exp_unix: Option<i64>) -> Result<()> {
        if let Some(exp) = grant_exp_unix {
            if agentlink_core::util::unix_now() >= exp {
                return Err(Error::Auth("grant expired".into()));
            }
        }
        if let Some(hook) = self.grant_hook() {
            let jti = grant_jti.trim();
            if jti.is_empty() {
                return Err(Error::Auth("grant is required".into()));
            }
            if !hook(jti) {
                return Err(Error::Auth("grant was revoked".into()));
            }
        }
        Ok(())
    }

    pub fn register(
        &self,
        request_id: &str,
        owner_peer: &str,
        grant_jti: &str,
        grant_exp_unix: Option<i64>,
    ) -> Result<CancellationToken> {
        self.check_grant(grant_jti, grant_exp_unix)?;
        let token = CancellationToken::new();
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Error::Message("tunnel registry poisoned".into()))?;
        sessions.insert(
            request_id.to_string(),
            TunnelSession {
                owner_peer: owner_peer.to_string(),
                grant_jti: grant_jti.trim().to_string(),
                grant_exp_unix,
                cancel: token.clone(),
            },
        );
        Ok(token)
    }

    pub fn unregister(&self, request_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            if let Some(session) = sessions.remove(request_id) {
                session.cancel.cancel();
            }
        }
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.retain(|_, item| item.bind_request_id != request_id);
        }
    }

    pub fn insert_waiting(
        &self,
        token: String,
        stream: TcpStream,
        owner_peer: &str,
        grant_jti: &str,
        grant_exp_unix: Option<i64>,
        bind_request_id: &str,
    ) -> Result<()> {
        let now = Instant::now();
        let mut map = self
            .waiting
            .lock()
            .map_err(|_| Error::Message("tunnel wait poisoned".into()))?;
        map.retain(|_, item| now.saturating_duration_since(item.created_at) < WAITING_STREAM_TTL);
        if map.len() >= MAX_WAITING_STREAMS {
            return Err(Error::Message(format!(
                "too many pending tunnel connections (limit {MAX_WAITING_STREAMS})"
            )));
        }
        map.insert(
            token,
            WaitingStream {
                stream,
                owner_peer: owner_peer.to_string(),
                grant_jti: grant_jti.trim().to_string(),
                grant_exp_unix,
                bind_request_id: bind_request_id.to_string(),
                created_at: now,
            },
        );
        Ok(())
    }

    pub fn take_waiting(&self, token: &str, peer: &str) -> Result<TcpStream> {
        let now = Instant::now();
        let entry = {
            let mut map = self
                .waiting
                .lock()
                .map_err(|_| Error::Message("tunnel wait poisoned".into()))?;
            map.retain(|_, item| {
                now.saturating_duration_since(item.created_at) < WAITING_STREAM_TTL
            });
            let Some(existing) = map.get(token) else {
                return Err(Error::Message(format!("unknown tunnel token {token}")));
            };
            if existing.owner_peer != peer {
                return Err(Error::Message(format!("unknown tunnel token {token}")));
            }
            map.remove(token)
        };
        let Some(entry) = entry else {
            return Err(Error::Message(format!("unknown tunnel token {token}")));
        };
        self.check_grant(&entry.grant_jti, entry.grant_exp_unix)?;
        Ok(entry.stream)
    }

    pub fn close_all(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            for (_, session) in sessions.drain() {
                session.cancel.cancel();
            }
        }
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.clear();
        }
    }

    pub fn close_inactive(&self, revoked: &BTreeSet<String>) -> usize {
        let hook = self.grant_hook();
        let now_unix = agentlink_core::util::unix_now();
        let now_inst = Instant::now();
        let mut closed = 0usize;
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, session| {
                let inactive = tunnel_grant_inactive(
                    &session.grant_jti,
                    session.grant_exp_unix,
                    revoked,
                    hook.as_deref(),
                    now_unix,
                );
                if inactive {
                    session.cancel.cancel();
                    closed += 1;
                    false
                } else {
                    true
                }
            });
        }
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.retain(|_, item| {
                now_inst.saturating_duration_since(item.created_at) < WAITING_STREAM_TTL
                    && !tunnel_grant_inactive(
                        &item.grant_jti,
                        item.grant_exp_unix,
                        revoked,
                        hook.as_deref(),
                        now_unix,
                    )
            });
        }
        closed
    }

    pub fn close_expired(&self) -> usize {
        let now_unix = agentlink_core::util::unix_now();
        let now_inst = Instant::now();
        let mut closed = 0usize;
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, session| {
                if session.grant_exp_unix.is_some_and(|exp| now_unix >= exp) {
                    session.cancel.cancel();
                    closed += 1;
                    false
                } else {
                    true
                }
            });
        }
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.retain(|_, item| {
                now_inst.saturating_duration_since(item.created_at) < WAITING_STREAM_TTL
                    && !item.grant_exp_unix.is_some_and(|exp| now_unix >= exp)
            });
        }
        closed
    }

    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.sessions.lock().map(|m| m.len()).unwrap_or(0)
    }

    #[cfg(test)]
    pub fn waiting_count(&self) -> usize {
        self.waiting.lock().map(|m| m.len()).unwrap_or(0)
    }
}

fn tunnel_grant_inactive(
    grant_jti: &str,
    grant_exp_unix: Option<i64>,
    revoked: &BTreeSet<String>,
    hook: Option<&(dyn Fn(&str) -> bool + Send + Sync)>,
    now_unix: i64,
) -> bool {
    if grant_exp_unix.is_some_and(|exp| now_unix >= exp) {
        return true;
    }
    let jti = grant_jti.trim();
    if !jti.is_empty()
        && revoked
            .iter()
            .any(|item| item.trim().eq_ignore_ascii_case(jti))
    {
        return true;
    }
    if let Some(hook) = hook {
        if jti.is_empty() || !hook(jti) {
            return true;
        }
    }
    false
}

struct TunnelGuard {
    registry: Arc<TunnelRegistry>,
    request_id: String,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        self.registry.unregister(&self.request_id);
    }
}

#[allow(dead_code)]
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

const SESSION_WIRE_BOUND: usize = 256;

pub struct TransferHost {
    pub sessions: Arc<Mutex<HashMap<String, mpsc::Sender<Wire>>>>,
    pub direct_wait: Arc<Mutex<HashMap<String, oneshot::Sender<DirectReply>>>>,
    #[allow(dead_code)]
    pub allowed: Arc<Mutex<HashMap<String, Instant>>>,
    #[allow(dead_code)]
    pub quic: Option<Arc<QuicPeer>>,
    pub tx: mpsc::Sender<Outbound>,
    pub policy: Arc<RwLock<NodePolicy>>,
    #[allow(dead_code)]
    pub max_policy: NodePolicy,
    pub root: Option<PathBuf>,
    pub e2e: Endpoint,
    pub node_id: String,
    pub seals: Arc<Mutex<HashMap<String, SealTarget>>>,
    pub pending: Arc<Mutex<HashMap<String, oneshot::Sender<Envelope>>>>,
    pub audit: Arc<AuditService>,
    pub tunnels: Arc<TunnelRegistry>,
}

#[allow(dead_code)]
pub fn spawn_accept(
    peer: Arc<QuicPeer>,
    allowed: Arc<Mutex<HashMap<String, Instant>>>,
    policy: Arc<RwLock<NodePolicy>>,
    max_policy: NodePolicy,
    root: Option<PathBuf>,
    audit: Arc<AuditService>,
    shutdown: CancellationToken,
) {
    let _ = (peer, allowed, policy, max_policy, root, audit, shutdown);
}

#[allow(clippy::too_many_arguments)]
pub async fn on_transfer(
    host: Arc<TransferHost>,
    request_id: String,
    client_id: String,
    peer: String,
    msg: TransferMsg,
    session: Option<std::sync::Arc<Direction>>,
    policy: Option<NodePolicy>,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
) {
    let effective_peer = if peer.is_empty() {
        client_id.clone()
    } else {
        peer.clone()
    };
    if let Some(tx) = host
        .sessions
        .lock()
        .ok()
        .and_then(|map| map.get(&request_id).cloned())
    {
        // Only the peer that opened this transfer session may feed control messages.
        let owner_matches = host
            .seals
            .lock()
            .ok()
            .and_then(|seals| seals.get(&request_id).map(|s| s.peer == effective_peer))
            .unwrap_or(false);
        if !owner_matches {
            tracing::warn!(%request_id, "ignoring cross-peer transfer message for existing session");
            return;
        }
        if tx.try_send(Wire::Msg(msg)).is_err() {
            if let Ok(mut map) = host.sessions.lock() {
                map.remove(&request_id);
            }
        }
        return;
    }
    if let Ok(mut seals) = host.seals.lock() {
        seals.insert(
            request_id.clone(),
            SealTarget {
                peer: effective_peer.clone(),
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
                    let dest =
                        paths::ensure_path_stays_in_sandbox_at_sink(host.root.as_deref(), &dest)?;
                    ensure_no_symlink_partial(host.root.as_deref(), &dest)?;
                    if let Some(parent) = dest.parent() {
                        crate::ops::create_dir_all_confined(host.root.as_deref(), parent)?;
                    }
                    let safe_mode = mode.map(|m| m & 0o777);
                    engine::serve_push_confined(
                        host.root.as_deref(),
                        &dest,
                        Path::new(&path),
                        size,
                        hash,
                        0,
                        agentlink_core::protocol::CompressPref::Auto,
                        resume,
                        &mut link,
                        "relay",
                        safe_mode,
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
                    let src = paths::resolve_path(host.root.as_deref(), &path)?;
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
                    let path =
                        paths::ensure_path_stays_in_sandbox_at_sink(host.root.as_deref(), &path)?;
                    validate_push_dir_manifest(host.root.as_deref(), &path, &entries)?;
                    crate::ops::create_dir_all_confined(host.root.as_deref(), &path)?;
                    if let Some(sandbox_root) = host.root.as_deref() {
                        ensure_no_symlink_tar_partials(&path)?;
                        serve_push_dir_sandboxed(sandbox_root, &path, entries, &mut link, "relay")
                            .await
                    } else {
                        engine::serve_push_dir(&path, entries, &mut link, "relay").await
                    }
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
                    let src = paths::resolve_path(host.root.as_deref(), &path)?;
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
                    let dest =
                        paths::ensure_path_stays_in_sandbox_at_sink(host.root.as_deref(), &dest)?;
                    ensure_no_symlink_partial(host.root.as_deref(), &dest)?;
                    if let Some(parent) = dest.parent() {
                        crate::ops::create_dir_all_confined(host.root.as_deref(), parent)?;
                    }
                    engine::serve_push_stream_confined(
                        host.root.as_deref(),
                        &dest,
                        &mut link,
                        "relay",
                    )
                    .await
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
                    let src = paths::resolve_path(host.root.as_deref(), &path)?;
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

        TransferMsg::TunnelDial {
            host: remote_host,
            port: remote_port,
        } => {
            let link = attach(&host, &request_id, &reply_node);
            let req = request_id.clone();
            tokio::spawn(async move {
                let detail = format!("{remote_host}:{remote_port}");
                let outcome = async {
                    ensure_exec(&host, policy)?;
                    let cancel = host.tunnels.register(
                        &req,
                        &effective_peer,
                        &grant_jti,
                        grant_exp_unix,
                    )?;
                    let _guard = TunnelGuard {
                        registry: host.tunnels.clone(),
                        request_id: req.clone(),
                    };
                    let addr = format!("{remote_host}:{remote_port}");
                    let stream = tokio::select! {
                        _ = cancel.cancelled() => return Err(Error::Auth("tunnel closed by grant lifecycle".into())),
                        conn = TcpStream::connect(&addr) => conn.map_err(|err| {
                            Error::Message(format!("tunnel dial {addr}: {err}"))
                        })?,
                    };
                    link.send_msg(TransferMsg::TunnelReady).await?;
                    tokio::select! {
                        _ = cancel.cancelled() => Ok::<(), Error>(()),
                        res = agentlink_core::tunnel::pump(stream, link, &req) => res,
                    }
                }
                .await;
                if let Err(err) = outcome {
                    note_transfer(
                        &host,
                        &client_id,
                        "tunnel_dial",
                        &detail,
                        false,
                        Some(&err.to_string()),
                        None,
                        &host.node_id,
                        &detail,
                        "",
                        "",
                        "tunnel",
                    );
                } else {
                    note_transfer(
                        &host,
                        &client_id,
                        "tunnel_dial",
                        &detail,
                        true,
                        None,
                        None,
                        &host.node_id,
                        &detail,
                        "",
                        "",
                        "tunnel",
                    );
                }
            });
        }
        TransferMsg::TunnelBind { port } => {
            let mut control = attach(&host, &request_id, &reply_node);
            let req = request_id.clone();
            tokio::spawn(async move {
                if let Err(err) = run_tunnel_bind(
                    &host,
                    policy,
                    port,
                    &mut control,
                    &client_id,
                    &req,
                    &effective_peer,
                    &grant_jti,
                    grant_exp_unix,
                )
                .await
                {
                    let _ = control
                        .send_msg(TransferMsg::Failed {
                            message: err.to_string(),
                        })
                        .await;
                    note_transfer(
                        &host,
                        &client_id,
                        "tunnel_bind",
                        &format!("127.0.0.1:{port}"),
                        false,
                        Some(&err.to_string()),
                        None,
                        &host.node_id,
                        "",
                        "",
                        "",
                        "tunnel",
                    );
                }
            });
        }
        TransferMsg::TunnelAccept { token } => {
            let link = attach(&host, &request_id, &reply_node);
            let req = request_id.clone();
            tokio::spawn(async move {
                let outcome = async {
                    ensure_exec(&host, policy)?;
                    let cancel = host.tunnels.register(
                        &req,
                        &effective_peer,
                        &grant_jti,
                        grant_exp_unix,
                    )?;
                    let _guard = TunnelGuard {
                        registry: host.tunnels.clone(),
                        request_id: req.clone(),
                    };
                    let stream = host.tunnels.take_waiting(&token, &effective_peer)?;
                    link.send_msg(TransferMsg::TunnelReady).await?;
                    tokio::select! {
                        _ = cancel.cancelled() => Ok::<(), Error>(()),
                        res = agentlink_core::tunnel::pump(stream, link, &req) => res,
                    }
                }
                .await;
                if let Err(err) = outcome {
                    note_transfer(
                        &host,
                        &client_id,
                        "tunnel_accept",
                        &token,
                        false,
                        Some(&err.to_string()),
                        None,
                        &host.node_id,
                        &token,
                        "",
                        "",
                        "tunnel",
                    );
                }
            });
        }

        other => {
            tracing::debug!(?other, "transfer message had no session");
        }
    }
}

fn ensure_exec(host: &TransferHost, policy: Option<NodePolicy>) -> Result<()> {
    let current = match policy {
        Some(p) => p,
        None => live_transfer_policy(&host.policy)?,
    };
    if current.allow_exec {
        Ok(())
    } else {
        Err(Error::Message(
            "exec is not allowed on this node (needed for port mapping)".into(),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tunnel_bind(
    host: &Arc<TransferHost>,
    policy: Option<NodePolicy>,
    port: u16,
    control: &mut Link,
    client_id: &str,
    request_id: &str,
    owner_peer: &str,
    grant_jti: &str,
    grant_exp_unix: Option<i64>,
) -> Result<()> {
    ensure_exec(host, policy)?;
    let cancel = host
        .tunnels
        .register(request_id, owner_peer, grant_jti, grant_exp_unix)?;
    let _guard = TunnelGuard {
        registry: host.tunnels.clone(),
        request_id: request_id.to_string(),
    };
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
        tokio::select! {
            _ = cancel.cancelled() => break,
            ctrl = control.recv() => {
                match ctrl {
                    Ok(Wire::Msg(TransferMsg::Failed { .. })) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|err| Error::Message(format!("tunnel accept: {err}")))?;
                let token = Uuid::new_v4().to_string();
                if let Err(err) = host.tunnels.insert_waiting(
                    token.clone(),
                    stream,
                    owner_peer,
                    grant_jti,
                    grant_exp_unix,
                    request_id,
                ) {
                    tracing::warn!(error = %err, "dropping incoming tunnel connection");
                    continue;
                }
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
        }
    }
    Ok(())
}

/// Refuse pre-existing symlink partial/journal files inside a sandboxed write
/// destination (blocks SEC-04 `.x.agentlink-partial -> hop/../../../../outside`
/// symlink planting even before `serve_push_confined` opens the partial path).
fn ensure_no_symlink_partial(root: Option<&Path>, dest: &Path) -> Result<()> {
    if root.is_none() {
        return Ok(());
    }
    let (partial, journal) = engine::partial_paths(dest);
    for candidate in [partial, journal] {
        if let Ok(meta) = std::fs::symlink_metadata(&candidate) {
            if paths::is_link_entry(&meta) {
                return Err(Error::PermissionDenied(format!(
                    "refusing to write through symlink partial file: {}",
                    candidate.display()
                )));
            }
        }
    }
    Ok(())
}

fn ensure_no_symlink_tar_partials(dest: &Path) -> Result<()> {
    for name in [".agentlink-tar.partial", ".agentlink-tar.partial.json"] {
        let candidate = dest.join(name);
        if let Ok(meta) = std::fs::symlink_metadata(&candidate) {
            if paths::is_link_entry(&meta) {
                return Err(Error::PermissionDenied(format!(
                    "refusing to write through symlink tar partial: {}",
                    candidate.display()
                )));
            }
        }
    }
    Ok(())
}

/// Validate `PushDir` manifest entries (including multi-hop symlink chains)
/// against `sandbox_root` before accepting the tar payload.
fn validate_push_dir_manifest(
    sandbox_root: Option<&Path>,
    dest: &Path,
    entries: &[ManifestEntry],
) -> Result<()> {
    let mut symlink_map: HashMap<PathBuf, PathBuf> = HashMap::new();
    for entry in entries {
        if entry.rel.is_empty() || entry.rel.contains('\0') {
            return Err(Error::PermissionDenied("invalid manifest path".into()));
        }
        let rel = Path::new(&entry.rel);
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
        {
            return Err(Error::PermissionDenied(format!(
                "manifest path escapes directory: {}",
                entry.rel
            )));
        }
        if let Some(target) = &entry.symlink {
            let t = Path::new(target);
            if t.is_absolute()
                || t.components()
                    .any(|c| matches!(c, Component::RootDir | Component::Prefix(_)))
            {
                return Err(Error::PermissionDenied(format!(
                    "symlink target escapes directory: {target}"
                )));
            }
            let norm_rel = clean_rel_path(rel);
            symlink_map.insert(norm_rel, t.to_path_buf());
        }
    }
    let Some(root) = sandbox_root else {
        return Ok(());
    };
    let root_c = paths::strip_verbatim_prefix(&std::fs::canonicalize(root)?);
    let dest_base = paths::ensure_path_stays_in_sandbox_at_sink(Some(root), dest)?;
    for (link_rel, raw_target) in &symlink_map {
        // Resolve component-by-component without prematurely collapsing `sym/..`,
        // matching kernel symlink traversal (`namei`) so chained symlinks like
        // `d1/d2/d3/hop -> ../../..` + `d1/d2/d3/x -> hop/../../../../outside`
        // are caught before accepting the tar payload.
        let mut cur: Vec<std::ffi::OsString> = link_rel
            .parent()
            .map(|p| {
                p.components()
                    .filter_map(|c| match c {
                        Component::Normal(s) => Some(s.to_os_string()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut queue: VecDeque<Component<'_>> = raw_target.components().collect();
        let mut owned_targets: Vec<PathBuf> = Vec::new();
        let mut queue_tokens: VecDeque<ManifestPathTok> = queue
            .drain(..)
            .map(ManifestPathTok::from_component)
            .collect();
        let mut hops = 0usize;
        while let Some(tok) = queue_tokens.pop_front() {
            match tok {
                ManifestPathTok::RootOrPrefix => {
                    return Err(Error::PermissionDenied(format!(
                        "manifest symlink escapes sandbox: {} -> {}",
                        link_rel.display(),
                        raw_target.display()
                    )));
                }
                ManifestPathTok::CurDir => {}
                ManifestPathTok::ParentDir => {
                    if cur.pop().is_none() {
                        return Err(Error::PermissionDenied(format!(
                            "manifest symlink escapes sandbox: {} -> {}",
                            link_rel.display(),
                            raw_target.display()
                        )));
                    }
                }
                ManifestPathTok::Normal(name) => {
                    cur.push(name);
                    let probe: PathBuf = cur.iter().collect();
                    if let Some(next_target) = symlink_map.get(&probe) {
                        hops += 1;
                        if hops > paths::MAX_SYMLINK_HOPS {
                            return Err(Error::PermissionDenied(format!(
                                "too many symlink hops in manifest: {}",
                                link_rel.display()
                            )));
                        }
                        cur.pop();
                        let next_toks: Vec<ManifestPathTok> = next_target
                            .components()
                            .map(ManifestPathTok::from_component)
                            .collect();
                        for t in next_toks.into_iter().rev() {
                            queue_tokens.push_front(t);
                        }
                        continue;
                    }
                    let disk_path = dest_base.join(&probe);
                    if let Ok(meta) = std::fs::symlink_metadata(&disk_path) {
                        if paths::is_link_entry(&meta) {
                            hops += 1;
                            if hops > paths::MAX_SYMLINK_HOPS {
                                return Err(Error::PermissionDenied(format!(
                                    "too many symlink hops in manifest: {}",
                                    link_rel.display()
                                )));
                            }
                            let disk_target = std::fs::read_link(&disk_path)?;
                            owned_targets.push(disk_target);
                            let last = owned_targets.last().expect("pushed");
                            cur.pop();
                            let next_toks: Vec<ManifestPathTok> = last
                                .components()
                                .map(ManifestPathTok::from_component)
                                .collect();
                            for t in next_toks.into_iter().rev() {
                                queue_tokens.push_front(t);
                            }
                        }
                    }
                }
            }
        }
        let final_rel: PathBuf = cur.iter().collect();
        let final_path = dest_base.join(&final_rel);
        if !paths::is_inside_root(&root_c, &final_path)
            || !paths::is_inside_root(&dest_base, &final_path)
        {
            return Err(Error::PermissionDenied(format!(
                "manifest symlink escapes sandbox: {} -> {}",
                link_rel.display(),
                raw_target.display()
            )));
        }
        paths::ensure_path_stays_in_sandbox_at_sink(Some(root), &final_path)?;
    }
    Ok(())
}

enum ManifestPathTok {
    RootOrPrefix,
    CurDir,
    ParentDir,
    Normal(std::ffi::OsString),
}

impl ManifestPathTok {
    fn from_component(comp: Component<'_>) -> Self {
        match comp {
            Component::Prefix(_) | Component::RootDir => Self::RootOrPrefix,
            Component::CurDir => Self::CurDir,
            Component::ParentDir => Self::ParentDir,
            Component::Normal(s) => Self::Normal(s.to_os_string()),
        }
    }
}

fn clean_rel_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        if let Component::Normal(c) = comp {
            out.push(c);
        }
    }
    out
}

/// Run `engine::serve_push_dir` while holding back `TransferMsg::Done` until
/// every unpacked symlink is verified canonically against `sandbox_root` (and
/// scrubbing any escaping multi-hop symlink chain + masking modes `& 0o777`).
async fn serve_push_dir_sandboxed(
    sandbox_root: &Path,
    dest: &Path,
    entries: Vec<ManifestEntry>,
    real_link: &mut Link,
    transport: &str,
) -> Result<TransferStats> {
    let (mut inner_link, mut proxy) = Link::pair(64);
    let mut held_done: Option<TransferMsg> = None;
    let dest_buf = dest.to_path_buf();
    let transport_s = transport.to_string();
    let mut serve_fut = std::pin::pin!(async move {
        engine::serve_push_dir(&dest_buf, entries, &mut inner_link, &transport_s).await
    });
    let serve_result = loop {
        tokio::select! {
            res = &mut serve_fut => break res,
            from_client = real_link.inp.recv() => {
                match from_client {
                    Some(wire) => {
                        if proxy.out.send(wire).await.is_err() {
                            break serve_fut.await;
                        }
                    }
                    None => {
                        drop(proxy.out);
                        break serve_fut.await;
                    }
                }
            }
            from_server = proxy.inp.recv() => {
                match from_server {
                    Some(Wire::Msg(done @ TransferMsg::Done { .. })) => {
                        held_done = Some(done);
                    }
                    Some(wire) => {
                        if real_link.out.send(wire).await.is_err() {
                            break Err(Error::Message("connection closed".into()));
                        }
                    }
                    None => {}
                }
            }
        }
    };
    while let Ok(wire) = proxy.inp.try_recv() {
        match wire {
            Wire::Msg(done @ TransferMsg::Done { .. }) => held_done = Some(done),
            other => {
                let _ = real_link.out.send(other).await;
            }
        }
    }
    let stats = serve_result?;
    verify_and_harden_unpacked_dir(sandbox_root, dest)?;
    if let Some(done) = held_done {
        real_link.send_msg(done).await?;
    }
    Ok(stats)
}

/// Verify every unpacked symlink stays inside `sandbox_root` (following chains),
/// immediately scrub any escaping symlink, and strip special mode bits (`& 0o777`).
fn verify_and_harden_unpacked_dir(sandbox_root: &Path, dir: &Path) -> Result<()> {
    let mut escaped: Vec<PathBuf> = Vec::new();
    walk_verify_and_mask(sandbox_root, dir, &mut escaped)?;
    if !escaped.is_empty() {
        return Err(Error::PermissionDenied(format!(
            "pushed directory contained {} symlink(s) escaping sandbox",
            escaped.len()
        )));
    }
    Ok(())
}

fn walk_verify_and_mask(sandbox_root: &Path, dir: &Path, escaped: &mut Vec<PathBuf>) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        if paths::is_link_entry(&meta) {
            if paths::ensure_moved_symlinks_stay_inside(Some(sandbox_root), &path, &path).is_err() {
                let _ = paths::remove_link_entry(&path, &meta);
                escaped.push(path);
            }
        } else if meta.is_dir() {
            mask_special_mode_bits(&path, &meta);
            walk_verify_and_mask(sandbox_root, &path, escaped)?;
        } else {
            mask_special_mode_bits(&path, &meta);
        }
    }
    Ok(())
}

fn mask_special_mode_bits(path: &Path, meta: &std::fs::Metadata) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        let clean = mode & 0o777;
        if (mode & 0o7777) != clean {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(clean));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, meta);
    }
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
    let _ = tx.try_send(Wire::Msg(TransferMsg::Failed { message }));
}

pub fn on_binary(host: &TransferHost, bytes: Vec<u8>) {
    let Some(id) = frame::request_id(&bytes) else {
        return;
    };
    let peer = host
        .seals
        .lock()
        .ok()
        .and_then(|map| map.get(&id).map(|seal| seal.peer.clone()));
    let Some(peer) = peer.filter(|peer| !peer.is_empty()) else {
        fail_session(
            host,
            &id,
            "file frame has no end-to-end peer".into(),
        );
        return;
    };
    // Only the handshake peer for this request. A relay cannot strip the
    // flag, swap the request id, or present another session's ciphertext.
    match e2e::open_bound_frame(&host.e2e, &peer, &bytes) {
        Ok(opened) => {
            if let Some(tx) = host
                .sessions
                .lock()
                .ok()
                .and_then(|map| map.get(&id).cloned())
            {
                if tx.try_send(Wire::Frame(opened)).is_err() {
                    if let Ok(mut map) = host.sessions.lock() {
                        map.remove(&id);
                    }
                }
            }
        }
        Err(err) => fail_session(host, &id, err.to_string()),
    }
}

pub async fn on_direct_offer(host: &TransferHost, env: Envelope) {
    // The offer is cleartext and carries no node-local grant. Accepting it
    // would let the relay introduce a peer. File bytes stay on the sealed path.
    let Envelope::DirectOffer { request_id, .. } = env else {
        return;
    };
    let _ = (host, request_id);
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
    let (tx, mut rx) = mpsc::channel(SESSION_WIRE_BOUND);
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
            let Some(seal) = seal.filter(|seal| ctx.e2e.has(&seal.peer)) else {
                return Err(Error::Message(
                    "transfer control has no end-to-end session".into(),
                ));
            };
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
        }
        Wire::Frame(bytes) => {
            let Some(seal) = seal.filter(|seal| ctx.e2e.has(&seal.peer)) else {
                return Err(Error::Message(
                    "file frame has no end-to-end session".into(),
                ));
            };
            let sealed = if let Some(session) = &seal.session {
                session.seal_frame(&bytes)?
            } else {
                ctx.e2e.seal_frame(&seal.peer, &bytes)?
            };
            Outbound::Binary(sealed)
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
    let src = paths::resolve_path(host.root.as_deref(), src_path)?;
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
        return local_fs_copy_confined(host.root.as_deref(), &src, &dest);
    }
    let _direct = direct;
    let request_id = Uuid::new_v4().to_string();
    // Node-to-node bytes stay sealed. Fail closed if the peer handshake fails.
    ensure_peer(host, dst_node).await?;
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

#[cfg(test)]
fn local_fs_copy(src: &Path, dest: &Path) -> Result<TransferStats> {
    local_fs_copy_confined(None, src, dest)
}

fn local_fs_copy_confined(root: Option<&Path>, src: &Path, dest: &Path) -> Result<TransferStats> {
    let (logical, files) = copy_tree(root, src, dest)?;
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

fn copy_tree(root: Option<&Path>, src: &Path, dest: &Path) -> Result<(u64, u32)> {
    let src_checked = paths::ensure_path_stays_in_sandbox_at_sink(root, src)?;
    let dst_checked = paths::ensure_path_stays_in_sandbox_at_sink(root, dest)?;
    if src_checked.is_dir() {
        agentlink_core::util::create_dir_all_as_dir(&dst_checked)?;
        let mut logical = 0u64;
        let mut files = 0u32;
        for entry in std::fs::read_dir(&src_checked)? {
            let entry = entry?;
            let (b, f) = copy_tree(root, &entry.path(), &dst_checked.join(entry.file_name()))?;
            logical = logical.saturating_add(b);
            files = files.saturating_add(f);
        }
        Ok((logical, files))
    } else {
        engine::ensure_pullable_file(&src_checked)?;
        if let Some(parent) = dst_checked.parent() {
            agentlink_core::util::create_dir_all_parent(parent)?;
        }
        let mut src_f = std::fs::File::open(&src_checked)?;
        let mut dst_f = paths::open_write_file(&dst_checked, true, true, root.is_some())?;
        let n = std::io::copy(&mut src_f, &mut dst_f)?;
        Ok((n, 1))
    }
}



#[allow(dead_code)]
async fn serve_quic(
    link: Link,
    policy: &RwLock<NodePolicy>,
    max_policy: NodePolicy,
    root: Option<&Path>,
    audit: &AuditService,
) -> Result<()> {
    drop(link);
    let _ = (policy, max_policy, root, audit);
    Err(Error::Message(
        "direct file transfer is disabled; file bytes stay on the sealed relay session".into(),
    ))
}

#[allow(dead_code)]
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
        None => ensure_policy(&host.policy, write),
    }
}

fn live_transfer_policy(policy: &RwLock<NodePolicy>) -> Result<NodePolicy> {
    policy
        .read()
        .map(|guard| *guard)
        .map_err(|_| Error::Message("node policy is unavailable".into()))
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

fn ensure_policy(policy: &RwLock<NodePolicy>, write: bool) -> Result<()> {
    policy_allows(live_transfer_policy(policy)?, write)
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
    use tokio::sync::mpsc;

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

        let err = copy_tree(None, &src, &dir.path().join("dest"))
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

    fn plaintext_frame(request_id: &str, payload: &[u8]) -> Vec<u8> {
        frame::encode(&frame::DataFrame {
            request_id: request_id.to_string(),
            offset: 0,
            raw_len: payload.len() as u32,
            compressed: false,
            hole: false,
            tar: false,
            payload: payload.to_vec(),
        })
        .unwrap()
    }

    #[test]
    fn relay_plaintext_tamper_replay_and_wrong_peer_are_refused() {
        let client_key = agentlink_core::identity::Identity::generate();
        let node_key = agentlink_core::identity::Identity::generate();
        let client = Endpoint::new(client_key.clone());
        let node = Endpoint::new(node_key.clone());
        let pending = client.client_hello(node.peer_id()).unwrap();
        let (_peer, welcome) = node.accept(Endpoint::hello_bytes(&pending)).unwrap();
        client.complete(pending, &welcome).unwrap();

        let request_id = Uuid::new_v4().to_string();
        let (session_tx, mut rx) = mpsc::channel(SESSION_WIRE_BOUND);
        let (out_tx, _out_rx) = mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let host = TransferHost {
            sessions: Arc::new(Mutex::new(HashMap::from([(
                request_id.clone(),
                session_tx.clone(),
            )]))),
            direct_wait: Arc::new(Mutex::new(HashMap::new())),
            allowed: Arc::new(Mutex::new(HashMap::new())),
            quic: None,
            tx: out_tx,
            policy: Arc::new(RwLock::new(NodePolicy::full())),
            max_policy: NodePolicy::full(),
            root: None,
            e2e: node,
            node_id: node_key.public_hex().to_string(),
            seals: Arc::new(Mutex::new(HashMap::from([(
                request_id.clone(),
                SealTarget {
                    peer: client_key.public_hex().to_string(),
                    node_id: node_key.public_hex().to_string(),
                    client_id: client_key.public_hex().to_string(),
                    session: None,
                },
            )]))),
            pending: Arc::new(Mutex::new(HashMap::new())),
            audit: crate::pipeline::AuditService::open_quiet(dir.path(), "node", "node"),
            tunnels: Arc::new(TunnelRegistry::default()),
        };
        std::mem::forget(dir);

        on_binary(&host, plaintext_frame(&request_id, b"PLAINTEXT-BYTES"));
        match rx.try_recv() {
            Ok(Wire::Msg(TransferMsg::Failed { message })) => {
                assert!(
                    message.contains("not end-to-end") || message.contains("plaintext"),
                    "{message}"
                );
            }
            other => panic!("plaintext frame was accepted: {other:?}"),
        }

        let raw = plaintext_frame(&request_id, b"FILEBYTES-secret");
        let sealed = client.seal_frame(node_key.public_hex(), &raw).unwrap();
        assert!(!sealed.windows(12).any(|window| window == b"FILEBYTES-se"));
        on_binary(&host, sealed.clone());
        match rx.try_recv() {
            Ok(Wire::Frame(opened)) => {
                assert_eq!(frame::decode(&opened).unwrap().payload, b"FILEBYTES-secret");
            }
            other => panic!("legitimate frame was refused: {other:?}"),
        }

        on_binary(&host, sealed);
        match rx.try_recv() {
            Ok(Wire::Msg(TransferMsg::Failed { message })) => {
                assert!(message.contains("replay"), "{message}");
            }
            other => panic!("replayed frame was accepted: {other:?}"),
        }

        let mut tampered = client.seal_frame(node_key.public_hex(), &raw).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x5a;
        on_binary(&host, tampered);
        match rx.try_recv() {
            Ok(Wire::Msg(TransferMsg::Failed { message })) => {
                assert!(message.contains("open") || message.contains("e2e"), "{message}");
            }
            other => panic!("tampered frame was accepted: {other:?}"),
        }

        let mut swapped = client.seal_frame(node_key.public_hex(), &raw).unwrap();
        let other_id = Uuid::new_v4();
        swapped[12..28].copy_from_slice(other_id.as_bytes());
        let bound = host.seals.lock().unwrap().get(&request_id).unwrap().clone();
        host.seals.lock().unwrap().insert(other_id.to_string(), bound);
        host.sessions
            .lock()
            .unwrap()
            .insert(other_id.to_string(), session_tx);
        on_binary(&host, swapped);
        match rx.try_recv() {
            Ok(Wire::Msg(TransferMsg::Failed { message })) => {
                assert!(message.contains("open") || message.contains("e2e"), "{message}");
            }
            other => panic!("request id swap was accepted: {other:?}"),
        }
    }

    fn poison_policy(policy: &Arc<RwLock<NodePolicy>>) {
        let lock = policy.clone();
        let _ = std::thread::spawn(move || {
            let _guard = lock.write().unwrap();
            panic!("poison the transfer policy lock");
        })
        .join();
    }

    fn host_with_policy(policy: NodePolicy) -> (TransferHost, tempfile::TempDir) {
        let (out_tx, _out_rx) = mpsc::channel(1);
        let dir = tempfile::tempdir().unwrap();
        let node_key = agentlink_core::identity::Identity::generate();
        let host = TransferHost {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            direct_wait: Arc::new(Mutex::new(HashMap::new())),
            allowed: Arc::new(Mutex::new(HashMap::new())),
            quic: None,
            tx: out_tx,
            policy: Arc::new(RwLock::new(policy)),
            max_policy: NodePolicy::full(),
            root: None,
            e2e: Endpoint::new(node_key.clone()),
            node_id: node_key.public_hex().to_string(),
            seals: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            audit: crate::pipeline::AuditService::open_quiet(dir.path(), "node", "node"),
            tunnels: Arc::new(TunnelRegistry::default()),
        };
        (host, dir)
    }

    #[test]
    fn poisoned_policy_lock_fails_closed_on_ensure_and_ensure_exec() {
        let (host, _dir) = host_with_policy(NodePolicy::full());
        ensure(&host, None, false).unwrap();
        ensure_exec(&host, None).unwrap();
        // An explicit policy still wins when the lock is healthy.
        let mut no_exec = NodePolicy::full();
        no_exec.allow_exec = false;
        assert!(ensure_exec(&host, Some(no_exec)).is_err());
        poison_policy(&host.policy);
        let err = ensure(&host, None, true).unwrap_err();
        assert!(
            err.to_string().contains("unavailable"),
            "ensure (policy=None) must not fall back to max_policy, got {err}"
        );
        let err = ensure_exec(&host, None).unwrap_err();
        assert!(
            err.to_string().contains("unavailable"),
            "ensure_exec (policy=None) must not fall back to max_policy, got {err}"
        );
        // A provided policy still does not read the poisoned lock.
        ensure(&host, Some(NodePolicy::full()), false).unwrap();
        ensure_exec(&host, Some(NodePolicy::full())).unwrap();
    }

    #[test]
    fn push_dir_manifest_rejects_multi_hop_symlink_chain_escape() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = dir.path().join("sandbox");
        let dest = sandbox.join("up");
        std::fs::create_dir_all(&dest).unwrap();
        let entries = vec![
            ManifestEntry {
                rel: "d1/d2/d3/hop".into(),
                size: 0,
                hash: String::new(),
                dir: false,
                symlink: Some("../../..".into()),
            },
            ManifestEntry {
                rel: "d1/d2/d3/.x.agentlink-partial".into(),
                size: 0,
                hash: String::new(),
                dir: false,
                symlink: Some("hop/../../../../outside/target".into()),
            },
        ];
        let err = validate_push_dir_manifest(Some(&sandbox), &dest, &entries)
            .unwrap_err()
            .to_string();
        assert!(err.contains("escapes"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn push_refuses_preexisting_symlink_partial_file_under_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = dir.path().join("sandbox");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let dest = sandbox.join("x");
        let (partial, _) = engine::partial_paths(&dest);
        std::os::unix::fs::symlink(outside.join("target"), &partial).unwrap();
        let err = ensure_no_symlink_partial(Some(&sandbox), &dest)
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");
    }

    #[tokio::test]
    async fn tunnel_registry_enforces_peer_ownership_revoke_and_bind_drop() {
        let reg = Arc::new(TunnelRegistry::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (c_res, a_res) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let _client = c_res.unwrap();
        let (server_stream, _) = a_res.unwrap();

        reg.insert_waiting(
            "tok-1".into(),
            server_stream,
            "alice",
            "jti-t1",
            None,
            "bind-1",
        )
        .unwrap();
        assert_eq!(reg.waiting_count(), 1);
        // Bob cannot steal Alice's waiting stream.
        assert!(reg.take_waiting("tok-1", "bob").is_err());
        assert_eq!(reg.waiting_count(), 1);
        // Revoking Alice's grant drops the waiting stream and cancels the tunnel.
        let tok = reg.register("dial-1", "alice", "jti-t1", None).unwrap();
        assert!(!tok.is_cancelled());
        let mut revoked = BTreeSet::new();
        revoked.insert("jti-t1".into());
        assert_eq!(reg.close_inactive(&revoked), 1);
        assert!(tok.is_cancelled());
        assert_eq!(reg.waiting_count(), 0);
        assert_eq!(reg.active_count(), 0);

        // Dropping control link immediately terminates `run_tunnel_bind` and frees the port.
        let (host, _dir) = host_with_policy(NodePolicy::full());
        let host = Arc::new(host);
        let (mut ctrl_server, mut ctrl_client) = Link::pair(8);
        let host_bg = host.clone();
        let bind_task = tokio::spawn(async move {
            run_tunnel_bind(
                &host_bg,
                Some(NodePolicy::full()),
                0,
                &mut ctrl_server,
                "alice",
                "req-bind",
                "alice",
                "jti-b1",
                None,
            )
            .await
        });
        let bound_port = match tokio::time::timeout(Duration::from_secs(3), ctrl_client.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Wire::Msg(TransferMsg::TunnelBound { port }) => port,
            other => panic!("expected TunnelBound, got {other:?}"),
        };
        assert!(bound_port > 0);
        assert_eq!(host.tunnels.active_count(), 1);
        drop(ctrl_client);
        let res = tokio::time::timeout(Duration::from_secs(3), bind_task)
            .await
            .expect("run_tunnel_bind must exit when control drops")
            .expect("join");
        assert!(res.is_ok(), "{res:?}");
        assert_eq!(host.tunnels.active_count(), 0);
    }
}
