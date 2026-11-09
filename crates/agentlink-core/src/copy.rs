//! Client-side bulk copy over the relay, with a direct QUIC attempt first.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::{self, UnboundedSender};
use uuid::Uuid;

use crate::client::{Client, ClientInner, TransferInbound};
use crate::engine::{self, Link, Wire, XferOpts};
use crate::error::{Error, Result};
use crate::protocol::{Envelope, TransferMsg, TransferStats};
use crate::ws::{self, Outbound};

type Progress = Option<Arc<dyn Fn(u64, u64) + Send + Sync>>;

/// Map one phase of a two-hop bridge onto a single 0..2*total range.
fn scale_bridge_progress(progress: Progress, phase: u64) -> Progress {
    let hook = progress?;
    Some(Arc::new(move |sent, total| {
        let span = total.saturating_mul(2);
        let done = total.saturating_mul(phase).saturating_add(sent);
        hook(done.min(span), span);
    }))
}

impl Client {
    pub async fn copy_upload(
        &self,
        node: &str,
        remote: &str,
        local: &Path,
        opts: &XferOpts,
        progress: Progress,
    ) -> Result<TransferStats> {
        let mut opts = opts.clone();
        opts.resume = true;
        // A local FIFO/socket/device would block File::open forever inside
        // perform_push/send_blob. Refuse before dialing the node.
        if !local.is_dir() {
            engine::ensure_pullable_file(local)?;
        }
        // Fail fast when the destination is already offline. The retry loop
        // below still covers a node that drops after the transfer starts.
        let _ = self.online_id(node).await?;
        let deadline = std::time::Instant::now() + crate::resume::RECONNECT_GIVE_UP;
        let mut backoff = crate::resume::Backoff::new();
        loop {
            let result = match self.open_data_link(node, &opts).await {
                Ok((mut link, request_id, opts)) if local.is_dir() => {
                    engine::perform_push_dir(
                        local,
                        remote,
                        &mut link,
                        &request_id,
                        &opts,
                        &progress,
                    )
                    .await
                }
                Ok((mut link, request_id, opts)) => {
                    engine::perform_push(local, remote, &mut link, &request_id, &opts, &progress)
                        .await
                }
                Err(err) => Err(err),
            };
            match result {
                Ok(stats) => return Ok(stats),
                Err(err) if err.is_retryable() && std::time::Instant::now() < deadline => {
                    tokio::time::sleep(backoff.next_delay()).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    pub async fn copy_download(
        &self,
        node: &str,
        remote: &str,
        local: &Path,
        opts: &XferOpts,
        progress: Progress,
    ) -> Result<TransferStats> {
        let mut opts = opts.clone();
        opts.resume = true;
        // Fail fast when the source is already offline. Resume retries below
        // still cover a node that drops after the transfer starts.
        let _ = self.online_id(node).await?;
        let deadline = std::time::Instant::now() + crate::resume::RECONNECT_GIVE_UP;
        let mut backoff = crate::resume::Backoff::new();
        loop {
            let (dir, mode, mtime_unix) = match self.stat(node, remote).await {
                Ok(stat) => {
                    if !stat.is_dir && !stat.is_file && !stat.is_symlink {
                        return Err(crate::error::Error::Message(format!(
                            "{remote} is not a regular file (refusing fifo/socket/device)"
                        )));
                    }
                    let mtime = stat
                        .modified_unix_ms
                        .map(|ms| (ms / 1000) as u64);
                    (stat.is_dir, stat.mode, mtime)
                }
                Err(err) if err.is_retryable() && std::time::Instant::now() < deadline => {
                    tokio::time::sleep(backoff.next_delay()).await;
                    continue;
                }
                Err(_) => (false, None, None),
            };
            let result = match self.open_data_link(node, &opts).await {
                Ok((mut link, request_id, opts)) => {
                    if dir {
                        engine::perform_pull_dir(
                            remote,
                            local,
                            &mut link,
                            &request_id,
                            &opts,
                            &progress,
                        )
                        .await
                    } else {
                        engine::perform_pull(
                            remote,
                            local,
                            &mut link,
                            &request_id,
                            &opts,
                            &progress,
                        )
                        .await
                    }
                }
                Err(err) => Err(err),
            };
            match result {
                Ok(stats) => {
                    if !dir {
                        engine::apply_mode_mtime(local, mode, mtime_unix);
                    }
                    return Ok(stats);
                }
                Err(err) if err.is_retryable() && std::time::Instant::now() < deadline => {
                    tokio::time::sleep(backoff.next_delay()).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Ask `src_node` to copy one of its paths onto `dst_node`.
    ///
    /// Same-node copies bridge through a local temp file (the peer path cannot
    /// loop a Push back onto the sender). Cross-node uses PeerCopy first, then
    /// falls back to the same bridge if the peer path errors or stalls.
    /// `progress` follows the bridge (download, then upload, as one overall
    /// bar). A successful peer copy does not see the file bytes.
    pub async fn copy_node_to_node(
        &self,
        src_node: &str,
        src_path: &str,
        dst_node: &str,
        dst_path: &str,
        opts: &XferOpts,
        direct: bool,
        progress: Progress,
    ) -> Result<TransferStats> {
        let src_id = self.online_id(src_node).await?;
        let dst_id = self.online_id(dst_node).await?;
        // PeerCopy would hand a FIFO/device to perform_push, whose File::open
        // blocks forever. Gate at the source before choosing peer or bridge.
        let stat = self.stat(src_node, src_path).await?;
        if !stat.is_dir && !stat.is_file && !stat.is_symlink {
            return Err(Error::Message(format!(
                "{src_path} is not a regular file (refusing fifo/socket/device)"
            )));
        }
        if src_id == dst_id {
            return self
                .copy_node_bridge(src_node, src_path, dst_node, dst_path, opts, progress)
                .await;
        }
        match tokio::time::timeout(
            Duration::from_secs(12),
            self.peer_copy_once(&src_id, src_path, &dst_id, dst_path, opts, direct),
        )
        .await
        {
            Ok(Ok(stats)) => Ok(stats),
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "peer copy failed; bridging via local temp");
                self.copy_node_bridge(src_node, src_path, dst_node, dst_path, opts, progress)
                    .await
            }
            Err(_) => {
                tracing::warn!("peer copy timed out; bridging via local temp");
                self.copy_node_bridge(src_node, src_path, dst_node, dst_path, opts, progress)
                    .await
            }
        }
    }

    async fn peer_copy_once(
        &self,
        src_id: &str,
        src_path: &str,
        dst_id: &str,
        dst_path: &str,
        opts: &XferOpts,
        direct: bool,
    ) -> Result<TransferStats> {
        let request_id = Uuid::new_v4().to_string();
        let mut link = open_relay_link(&self.inner, src_id, &request_id).await?;
        link.send_msg(TransferMsg::PeerCopy {
            dst_node: dst_id.to_string(),
            src_path: src_path.to_string(),
            dst_path: dst_path.to_string(),
            chunk_size: opts.chunk_size as u32,
            window: opts.window,
            parallel: opts.parallel,
            compress: opts.compress,
            direct,
        })
        .await?;
        match link.recv().await? {
            Wire::Msg(TransferMsg::Done { stats }) => Ok(stats),
            Wire::Msg(TransferMsg::Failed { message }) => Err(Error::Message(message)),
            other => Err(Error::Protocol(format!(
                "expected peer copy result, got {other:?}"
            ))),
        }
    }

    /// Download from `src_node` into a temp path, then upload onto `dst_node`.
    async fn copy_node_bridge(
        &self,
        src_node: &str,
        src_path: &str,
        dst_node: &str,
        dst_path: &str,
        opts: &XferOpts,
        progress: Progress,
    ) -> Result<TransferStats> {
        let tmp_root = std::env::temp_dir().join(format!("agentlink-bridge-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_root).map_err(Error::Io)?;
        let is_dir = self
            .stat(src_node, src_path)
            .await
            .map(|stat| stat.is_dir)
            .unwrap_or(false);
        let local = if is_dir {
            tmp_root.join("tree")
        } else {
            let name = Path::new(src_path)
                .file_name()
                .map(|s| s.to_os_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| std::ffi::OsString::from("blob"));
            tmp_root.join(name)
        };
        // One overall bar: the download is the first half, the upload the second.
        // Peer copy never sees the bytes, so only this bridge reports progress.
        let download_progress = scale_bridge_progress(progress.clone(), 0);
        let upload_progress = scale_bridge_progress(progress, 1);
        let result = async {
            let _ = self
                .copy_download(src_node, src_path, &local, opts, download_progress)
                .await?;
            self.copy_upload(dst_node, dst_path, &local, opts, upload_progress)
                .await
        }
        .await;
        let _ = std::fs::remove_dir_all(&tmp_root);
        result
    }

    pub(crate) async fn open_data_link(
        &self,
        node: &str,
        opts: &XferOpts,
    ) -> Result<(Link, String, XferOpts)> {
        let node = self.online_id(node).await?;
        let mut opts = opts.clone().normalized();
        // Direct QUIC offers are cleartext and carry no grant. File bytes
        // stay on the sealed relay session.
        opts.transport = "relay".into();
        let request_id = Uuid::new_v4().to_string();
        let link = open_relay_link(&self.inner, &node, &request_id).await?;
        opts.transport = "relay".into();
        Ok((link, request_id, opts))
    }

    /// Upload from `reader` without knowing the length first.
    ///
    /// Reads are capped at one chunk and gated by `opts.window`, so a pipe is
    /// not buffered. zstd follows the remote path's extension. Bytes stay on
    /// the sealed relay session.
    pub async fn stream_upload<R: std::io::Read>(
        &self,
        node: &str,
        remote: &str,
        reader: &mut R,
        opts: &XferOpts,
    ) -> Result<TransferStats> {
        let (mut link, request_id, opts) = self.open_data_link(node, opts).await?;
        engine::perform_push_stream(reader, remote, &mut link, &request_id, &opts).await
    }

    /// Download `[offset, offset + max_bytes)` into `writer`.
    ///
    /// `max_bytes: None` reads through EOF. Chunks are written in order. The
    /// reorder buffer holds at most `opts.window` chunks.
    pub async fn stream_download<W: std::io::Write>(
        &self,
        node: &str,
        remote: &str,
        offset: u64,
        max_bytes: Option<u64>,
        writer: &mut W,
        opts: &XferOpts,
    ) -> Result<engine::StreamRead> {
        let (mut link, request_id, opts) = self.open_data_link(node, opts).await?;
        engine::perform_pull_stream(
            remote,
            offset,
            max_bytes,
            writer,
            &mut link,
            &request_id,
            &opts,
        )
        .await
    }
}

pub(crate) async fn open_relay_link(
    inner: &Arc<ClientInner>,
    node_id: &str,
    request_id: &str,
) -> Result<Link> {
    let client_id = inner.e2e.peer_id().to_string();
    crate::client::ensure_e2e(inner, node_id, &client_id).await?;
    let authz = inner.authz_for(node_id)?;
    inner.note_route(request_id, node_id);
    let (worker, mut adapter) = Link::pair(64);
    // Control messages and chunks share one queue. The WebSocket reader
    // pushes them in arrival order; a `select` over two channels would let a
    // data frame overtake StreamReady when the runtime is busy.
    let (in_tx, mut in_rx) = mpsc::unbounded_channel();
    register(inner, request_id, in_tx)?;
    let tx = inner.tx.clone();
    let binary = inner.binary.clone();
    let transfers = inner.transfers.clone();
    let endpoint = inner.e2e.clone();
    let request_id = request_id.to_string();
    let node_id = node_id.to_string();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                incoming = in_rx.recv() => {
                    let Some(incoming) = incoming else { break };
                    match incoming {
                        TransferInbound::Env(Envelope::Transfer { msg, .. }) => {
                            let terminal = msg.is_terminal();
                            if adapter.out.send(Wire::Msg(msg)).await.is_err() {
                                break;
                            }
                            if terminal {
                                break;
                            }
                        }
                        // The relay rejects a coarse class before the node sees
                        // the ciphertext. Surface that as a transfer failure
                        // instead of waiting for a Done that will never arrive.
                        TransferInbound::Env(Envelope::Result { ok: false, error, .. }) => {
                            let message = error.unwrap_or_else(|| "transfer rejected".into());
                            let _ = adapter
                                .out
                                .send(Wire::Msg(TransferMsg::Failed { message }))
                                .await;
                            break;
                        }
                        TransferInbound::Env(_) => {}
                        TransferInbound::Frame(bytes) => {
                            if adapter.out.send(Wire::Frame(bytes)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                outgoing = adapter.inp.recv() => {
                    let Some(wire) = outgoing else { break };
                    let encoded = match wire {
                        Wire::Msg(msg) => {
                            let env = Envelope::Transfer {
                                request_id: request_id.clone(),
                                node_id: node_id.clone(),
                                client_id: client_id.clone(),
                                terminal: msg.is_terminal(),
                                msg,
                                authz: authz.clone(),
                            };
                            let wrapped = match crate::e2e::seal_envelope(
                                &endpoint,
                                &node_id,
                                &node_id,
                                &client_id,
                                &env,
                            ) {
                                Ok(env) => env,
                                Err(_) => break,
                            };
                            match ws::encode(&wrapped) {
                                Ok(out) => out,
                                Err(_) => break,
                            }
                        }
                        Wire::Frame(bytes) => {
                            let sealed = match endpoint.seal_frame(&node_id, &bytes) {
                                Ok(sealed) => sealed,
                                Err(err) => {
                                    tracing::warn!(error = %err, "refusing to send a plaintext file frame");
                                    break;
                                }
                            };
                            Outbound::Binary(sealed)
                        }
                    };
                    if tx.send(encoded).await.is_err() {
                        break;
                    }
                }
            }
        }
        if let Ok(mut map) = binary.lock() {
            map.remove(&request_id);
        }
        if let Ok(mut set) = transfers.lock() {
            set.remove(&request_id);
        }
    });
    Ok(worker)
}

fn register(
    inner: &ClientInner,
    request_id: &str,
    inbound: UnboundedSender<TransferInbound>,
) -> Result<()> {
    inner
        .binary
        .lock()
        .map_err(|_| Error::Message("client binary map poisoned".into()))?
        .insert(request_id.to_string(), inbound);
    inner
        .transfers
        .lock()
        .map_err(|_| Error::Message("client transfer set poisoned".into()))?
        .insert(request_id.to_string());
    Ok(())
}

#[cfg(test)]
mod bridge_progress_tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn bridge_progress_is_overall_across_download_then_upload() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let slot = seen.clone();
        let hook: Progress = Some(Arc::new(move |sent, total| {
            slot.lock().expect("seen").push((sent, total));
        }));
        scale_bridge_progress(hook.clone(), 0).expect("download")(50, 100);
        let upload = scale_bridge_progress(hook, 1).expect("upload");
        upload(50, 100);
        upload(100, 100);
        assert_eq!(
            *seen.lock().expect("seen"),
            vec![(50, 200), (150, 200), (200, 200)]
        );
    }
}
