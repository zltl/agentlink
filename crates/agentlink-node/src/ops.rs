//! File, command, and extension operations.

use std::fs;
use std::io::{self, ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentlink_core::e2e::{self, Direction};
use agentlink_core::extensions::{dispatch_extension_as, NodeExtension};
use agentlink_core::engine::sweep_stale_partials;
use agentlink_core::paths::{resolve_lexical, resolve_path};
use agentlink_core::protocol::{DirEntry, Envelope, FileStat, Op};
use agentlink_core::sandbox::CommandPolicy;
use agentlink_core::util::{
    self, first_nondir_ancestor, is_not_a_directory, path_component_not_dir_error, FILE_CHUNK,
};
use agentlink_core::ws::{self, Outbound};
use agentlink_core::{Error, NodePolicy, Result};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::audit::{self, Origin, Outcome, ProcessAudit};
use crate::pipeline::{AuditExtra, AuditService};
use crate::proc::{self, ProcManager};
use crate::pty_session::PtyManager;
use crate::resume::{ReplayLog, SocketSlot};
use crate::search::{self, ContentQuery, NameQuery};
use crate::watch::WatchManager;

const MAX_READ: u32 = 32 * 1024 * 1024;
const MAX_WRITE: usize = 1024 * 1024;

#[derive(Clone)]
pub struct ResponseSeal {
    pub peer: String,
    pub node_id: String,
    /// Session that opened the request. Replies must use these keys.
    pub session: std::sync::Arc<Direction>,
}

#[derive(Clone)]
pub struct Responder {
    pub socket: Arc<SocketSlot>,
    pub request_id: String,
    pub seal: Option<ResponseSeal>,
    pub extra: Arc<Mutex<AuditExtra>>,
    pub log: Arc<ReplayLog>,
}

impl Responder {
    pub async fn ok(&self, body: serde_json::Value) -> Result<()> {
        self.send(&Envelope::result_ok(self.request_id.clone(), body))
            .await
    }

    pub async fn err(&self, message: impl Into<String>) -> Result<()> {
        self.send(&Envelope::result_err(self.request_id.clone(), message))
            .await
    }

    pub async fn ack(&self, body: serde_json::Value) -> Result<()> {
        self.send(&Envelope::result_ack(self.request_id.clone(), body))
            .await
    }

    pub async fn chunk(&self, stream: &str, data: &[u8]) -> Result<()> {
        if let Ok(mut extra) = self.extra.lock() {
            extra.push_stream(stream, data);
        }
        self.send(&Envelope::Chunk {
            request_id: self.request_id.clone(),
            stream: stream.to_string(),
            data_b64: util::b64_encode(data),
            seq: 0,
        })
        .await
    }

    pub async fn end(&self, exit_code: Option<i32>, error: Option<String>) -> Result<()> {
        if let Ok(mut extra) = self.extra.lock() {
            extra.exit_code = exit_code;
        }
        self.send(&Envelope::End {
            request_id: self.request_id.clone(),
            exit_code,
            error,
            seq: 0,
        })
        .await
    }

    pub fn encode_env(&self, env: &Envelope) -> Result<Outbound> {
        if let Some(seal) = &self.seal {
            let wrapped = e2e::seal_envelope_session(
                &seal.session,
                &seal.node_id,
                &seal.peer,
                env,
            )?;
            return ws::encode(&wrapped);
        }
        ws::encode(env)
    }

    /// Record the frame and try to send it. A dead socket is not an error:
    /// the ring still has the frame for the next dial.
    pub fn emit_blocking(&self, env: &Envelope) {
        let stamped = self.log.push(env.clone());
        let Ok(out) = self.encode_env(&stamped) else {
            return;
        };
        if let Some(tx) = self.socket.current() {
            let _ = tx.blocking_send(out);
        }
    }

    async fn send(&self, env: &Envelope) -> Result<()> {
        let stamped = self.log.push(env.clone());
        let out = self.encode_env(&stamped)?;
        if let Some(tx) = self.socket.current() {
            let _ = tx.send(out).await;
        }
        Ok(())
    }
}

pub struct OpContext<'a> {
    pub root: Option<&'a Path>,
    pub policy: NodePolicy,
    pub extensions: &'a [Arc<dyn NodeExtension>],
    pub pty: &'a PtyManager,
    pub procs: &'a ProcManager,
    pub watches: &'a WatchManager,
    pub audit_path: &'a Path,
    pub client_id: &'a str,
    pub node_name: &'a str,
    pub node_id: &'a str,
    pub commands: &'a CommandPolicy,
    pub audit: Arc<AuditService>,
    pub user: Option<String>,
    pub device_id: Option<String>,
    /// End-to-end peer (grantee), not the relay's outer client_id.
    pub peer_id: &'a str,
    pub grant_jti: Option<&'a str>,
    pub grant_exp_unix: Option<i64>,
}

struct Finished {
    outcome: Outcome,
    /// The handler already wrote the client response.
    sent: bool,
}

fn already(outcome: Outcome) -> Finished {
    Finished {
        outcome,
        sent: true,
    }
}

fn ready(outcome: Outcome) -> Finished {
    Finished {
        outcome,
        sent: false,
    }
}

pub async fn dispatch(op: Op, resp: Responder, cancel: CancellationToken, ctx: OpContext<'_>) {
    let started = Instant::now();
    let kind = op.kind();
    let category = audit::category_of(&op);
    let detail = op.audit_detail();
    let args = audit::args_from_op(&op);
    // PTY keystrokes are high volume and are not logged.
    let audit_this = !matches!(op, Op::PtyInput { .. });
    if cancel.is_cancelled() {
        let _ = resp.err("cancelled").await;
        commit_outcome(
            &ctx,
            &kind,
            category,
            &detail,
            &args,
            started.elapsed(),
            &Outcome::fail("cancelled"),
            &resp,
        );
        return;
    }
    if let Err(why) = ctx.policy.allows(&op) {
        let _ = resp.err(why.clone()).await;
        commit_outcome(
            &ctx,
            &kind,
            category,
            &detail,
            &args,
            started.elapsed(),
            &Outcome::fail(why),
            &resp,
        );
        return;
    }

    // ReadFile and WriteFile are the legacy 64 KiB base64 RPCs. cat, write, and
    // the MCP file tools use the streamed transfer messages. These ops stay so
    // the ignored benchmark can still time the old path.
    let result = match op {
        Op::Stat { path } => stat_op(&resp, ctx.root, &path)
            .await
            .map(|()| already(Outcome::ok(Value::Null))),
        Op::ListDir { path } => list_op(&resp, ctx.root, &path)
            .await
            .map(|()| already(Outcome::ok(Value::Null))),
        Op::ReadFile {
            path,
            offset,
            max_bytes,
        } => read_op(&resp, &cancel, ctx.root, &path, offset, max_bytes)
            .await
            .map(|()| already(Outcome::ok(Value::Null))),
        Op::WriteFile {
            path,
            offset,
            data_b64,
            truncate,
        } => write_op(&resp, ctx.root, &path, offset, &data_b64, truncate)
            .await
            .map(|()| already(Outcome::ok(Value::Null))),
        Op::Mkdir { path, recursive } => mkdir_op(&resp, ctx.root, &path, recursive)
            .await
            .map(|()| already(Outcome::ok(Value::Null))),
        Op::Remove { path, recursive } => remove_op(&resp, ctx.root, &path, recursive)
            .await
            .map(|()| already(Outcome::ok(Value::Null))),
        Op::Rename { from, to } => rename_op(&resp, ctx.root, &from, &to)
            .await
            .map(|()| already(Outcome::ok(Value::Null))),
        Op::Exec {
            program,
            args,
            cwd,
            env,
            timeout_ms,
            shell,
            stdin_b64,
        } => {
            exec_op(
                &resp,
                &cancel,
                ctx.root,
                ctx.commands,
                &program,
                &args,
                cwd.as_deref(),
                &env,
                timeout_ms,
                shell,
                stdin_b64.as_deref(),
            )
            .await
        }
        Op::PtyOpen {
            command,
            cwd,
            rows,
            cols,
        } => pty_open(&resp, &ctx, command, cwd, rows, cols).await,
        Op::PtyInput {
            session_id,
            data_b64,
        } => pty_input(&resp, ctx.pty, ctx.peer_id, &session_id, &data_b64)
            .await
            .map(|()| already(Outcome::ok(Value::Null))),
        Op::PtyResize {
            session_id,
            rows,
            cols,
        } => pty_resize(&resp, ctx.pty, ctx.peer_id, &session_id, rows, cols)
            .await
            .map(|()| already(Outcome::ok(Value::Null))),
        Op::PtyClose { session_id } => pty_close(&resp, ctx.pty, ctx.peer_id, &session_id)
            .await
            .map(|()| already(Outcome::ok(Value::Null))),
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
        } => search::content_search(
            ctx.root,
            ContentQuery {
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
            },
        )
        .await
        .map(|value| ready(Outcome::ok(value))),
        Op::Find {
            path,
            pattern,
            regex,
            gitignore,
            include_hidden,
            case_insensitive,
            offset,
            limit,
        } => search::filename_search(
            ctx.root,
            NameQuery {
                path,
                pattern,
                regex,
                gitignore,
                include_hidden,
                case_insensitive,
                offset,
                limit,
            },
        )
        .await
        .map(|value| ready(Outcome::ok(value))),
        Op::Replace {
            path,
            old,
            new,
            replace_all,
        } => crate::edit::replace(ctx.root, &path, &old, &new, replace_all)
            .await
            .map(|(value, edit)| ready(Outcome::ok(value).with_edit(edit))),
        Op::EditLines {
            path,
            start_line,
            end_line,
            content,
        } => crate::edit::edit_lines(ctx.root, &path, start_line, end_line, &content)
            .await
            .map(|(value, edit)| ready(Outcome::ok(value).with_edit(edit))),
        Op::ApplyPatch { root, patch } => crate::edit::apply_patch(ctx.root, &root, &patch)
            .await
            .map(|(value, edit)| ready(Outcome::ok(value).with_edit(edit))),
        Op::WatchStart { path, recursive } => watch_start(&ctx, &path, recursive).map(ready),
        Op::WatchPoll {
            watch_id,
            cursor,
            timeout_ms,
            limit,
        } => ctx
            .watches
            .poll(&watch_id, cursor, timeout_ms, limit)
            .await
            .map(|value| ready(Outcome::ok(value))),
        Op::WatchStop { watch_id } => ctx
            .watches
            .stop(&watch_id)
            .map(|value| ready(Outcome::ok(value))),
        Op::BgStart {
            program,
            args,
            cwd,
            env,
            shell,
            stdin_b64,
        } => bg_start(&ctx, &program, &args, cwd, &env, shell, stdin_b64.as_deref()).await,
        Op::BgList => ctx.procs.list().map(|value| ready(Outcome::ok(value))),
        Op::BgOutput {
            id,
            stdout_cursor,
            stderr_cursor,
            max_bytes,
        } => ctx
            .procs
            .output(&id, stdout_cursor, stderr_cursor, max_bytes)
            .map(|(value, process)| ready(Outcome::ok(value).with_process(process))),
        Op::BgStatus { id } => ctx
            .procs
            .status(&id)
            .map(|(value, process)| ready(Outcome::ok(value).with_process(process))),
        Op::BgKill { id } => ctx
            .procs
            .kill(&id)
            .await
            .map(|(value, process)| ready(Outcome::ok(value).with_process(process))),
        Op::SysInfo => crate::system::system_info()
            .await
            .map(|value| ready(Outcome::ok(value))),
        Op::RevokeGrant { .. } => Err(Error::Message(
            "revoke_grant is handled by the E2E daemon path".into(),
        )),
        Op::Extension { name, mut payload } => {
            if name == agentlink_core::PHASE3_WEBRTC_SIGNAL {
                fill_stream_grant_flags(
                    &mut payload,
                    ctx.policy,
                    ctx.grant_jti,
                    ctx.grant_exp_unix,
                );
            }
            extension_op(&resp, ctx.extensions, &name, &payload, ctx.peer_id)
                .await
                .map(|()| already(Outcome::ok(Value::Null)))
        }
    };

    match result {
        Ok(finished) => {
            if audit_this {
                commit_outcome(
                    &ctx,
                    &kind,
                    category,
                    &detail,
                    &args,
                    started.elapsed(),
                    &finished.outcome,
                    &resp,
                );
            }
            if !finished.sent {
                if finished.outcome.ok {
                    let _ = resp.ok(finished.outcome.result).await;
                } else if let Some(error) = finished.outcome.error {
                    let _ = resp.err(error).await;
                } else {
                    let _ = resp.err("failed").await;
                }
            }
        }
        Err(err) => {
            if audit_this {
                commit_outcome(
                    &ctx,
                    &kind,
                    category,
                    &detail,
                    &args,
                    started.elapsed(),
                    &Outcome::fail(err.to_string()),
                    &resp,
                );
            }
            let _ = resp.err(err.to_string()).await;
        }
    }
}

fn commit_outcome(
    ctx: &OpContext<'_>,
    action: &str,
    category: &str,
    detail: &str,
    args: &Value,
    duration: Duration,
    outcome: &Outcome,
    resp: &Responder,
) {
    let _ = ctx.audit_path;
    let mut event = audit::event_for(
        category,
        action,
        ctx.client_id,
        detail,
        args.clone(),
        outcome.ok,
        outcome.error.clone(),
        duration,
    );
    event.user = ctx.user.clone();
    event.device_id = ctx.device_id.clone();
    if let Some(process) = &outcome.process {
        event.command = Some(process.command.clone());
        event.cwd = process.cwd.clone();
        event.exit_code = process.exit_code;
        if let Some(cwd) = &process.cwd {
            if !event.paths.iter().any(|path| path == cwd) {
                event.paths.push(cwd.clone());
            }
        }
    }
    if let Ok(extra) = resp.extra.lock() {
        if !extra.stdout.is_empty() {
            event.stdout = Some(extra.stdout.clone());
        }
        if !extra.stderr.is_empty() {
            event.stderr = Some(extra.stderr.clone());
        }
        if !extra.transcript.is_empty() {
            event.transcript = Some(extra.transcript.clone());
        }
        if event.command.is_none() {
            event.command = extra.command.clone();
        }
        if event.cwd.is_none() {
            event.cwd = extra.cwd.clone();
        }
        if extra.exit_code.is_some() {
            event.exit_code = extra.exit_code;
        }
        if !extra.env.is_empty() {
            event.env = extra.env.clone();
        }
        if event.paths.is_empty() {
            event.paths = extra.paths.clone();
        }
        if extra.before.is_some() {
            event.before = extra.before.clone();
        }
        if extra.after.is_some() {
            event.after = extra.after.clone();
        }
    }
    if let Some(stdout) = &outcome.stdout {
        if event.stdout.is_none() {
            event.stdout = Some(stdout.clone());
        }
    }
    if let Some(stderr) = &outcome.stderr {
        if event.stderr.is_none() {
            event.stderr = Some(stderr.clone());
        }
    }
    if let Some(edit) = &outcome.edit {
        if edit.files.is_empty() {
            ctx.audit.submit(event);
            return;
        }
        for file in &edit.files {
            let mut one = event.clone();
            one.paths = vec![file.path.clone()];
            one.before = Some(file.before.as_bytes().to_vec());
            one.after = Some(file.after.as_bytes().to_vec());
            ctx.audit.submit(one);
        }
        return;
    }
    ctx.audit.submit(event);
}

fn allow_command(
    commands: &CommandPolicy,
    program: &str,
    args: &[String],
    shell: bool,
) -> Result<()> {
    let shell_line = if shell { Some(program) } else { None };
    commands.allows(program, args, shell_line)?;
    if shell {
        let (bin, bin_args) = shell_parts(program);
        commands.allows(&bin, &bin_args, shell_line)?;
    }
    Ok(())
}

/// A missing working directory uses `--root` when one is set, and every
/// directory is resolved inside that root. This is working-directory
/// confinement, not an OS sandbox.
///
/// When the caller omits `cwd` and there is no `--root`, default to
/// `$HOME` / `%USERPROFILE%`, then `/tmp`, then `/`. Never inherit the
/// node daemon's process directory — that is often a systemd
/// `WorkingDirectory` or a leftover installer/agent `/tmp` path, which is
/// a poor default for interactive `exec` / `shell` / `pty`.
fn confine_cwd(
    root: Option<&Path>,
    cwd: Option<&str>,
) -> Result<(Option<PathBuf>, Option<String>)> {
    let chosen = match (cwd, root) {
        (Some(cwd), _) => Some(cwd.to_string()),
        (None, Some(root)) => Some(root.display().to_string()),
        (None, None) => default_omit_cwd(),
    };
    let path = match chosen.as_deref() {
        Some(dir) => Some(resolve_path(root, dir)?),
        None => None,
    };
    let display = path.as_ref().map(|path| path.display().to_string());
    Ok((path, display))
}

fn default_omit_cwd() -> Option<String> {
    fallback_cwd().map(|path| path.display().to_string())
}

fn fallback_cwd() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|path| path.is_dir())
        .or_else(|| {
            let tmp = PathBuf::from("/tmp");
            tmp.is_dir().then_some(tmp)
        })
        .or_else(|| Some(PathBuf::from("/")))
}

fn origin_of(ctx: &OpContext<'_>) -> Origin {
    Origin {
        path: ctx.audit_path.to_path_buf(),
        node: ctx.node_name.to_string(),
        node_id: ctx.node_id.to_string(),
    }
}

async fn stat_op(resp: &Responder, root: Option<&Path>, path: &str) -> Result<()> {
    let full = resolve_path(root, path)?;
    let stat = tokio::task::spawn_blocking(move || file_stat(&full))
        .await
        .map_err(|err| Error::Message(format!("stat task: {err}")))??;
    resp.ok(serde_json::to_value(stat)?).await?;
    Ok(())
}

/// Follow directory symlinks like Unix `ls`. Reject files and broken links.
fn directory_for_list(full: &Path, path_display: &str) -> Result<PathBuf> {
    match fs::metadata(full) {
        Ok(meta) if meta.is_dir() => Ok(full.to_path_buf()),
        Ok(_) => Err(Error::Message(format!(
            "{path_display} is a file, not a directory; use `cat` to print it"
        ))),
        Err(err) => {
            if let Ok(sm) = fs::symlink_metadata(full) {
                if sm.file_type().is_symlink() {
                    return Err(Error::Message(format!(
                        "{path_display} is a broken symbolic link"
                    )));
                }
            }
            if err.kind() == ErrorKind::NotFound {
                return Err(missing_path_error("ls", path_display));
            }
            if is_not_a_directory(&err) {
                if let Some(tip) = path_component_not_dir_error(full) {
                    return Err(tip);
                }
            }
            Err(err.into())
        }
    }
}

fn missing_path_error(operation: &str, path_display: &str) -> Error {
    Error::Message(format!(
        "{operation}: path `{path_display}` does not exist"
    ))
}

async fn list_op(resp: &Responder, root: Option<&Path>, path: &str) -> Result<()> {
    let full = resolve_path(root, path)?;
    let path_display = path.to_string();
    let entries = tokio::task::spawn_blocking(move || list_dir_entries(full, path_display))
        .await
        .map_err(|err| Error::Message(format!("list task: {err}")))??;
    resp.ok(serde_json::to_value(entries)?).await?;
    Ok(())
}

fn list_dir_entries(full: PathBuf, path_display: String) -> Result<Vec<DirEntry>> {
    let full = directory_for_list(&full, &path_display)?;
    // Drop abandoned resume litter so `ls` does not keep showing multi-day
    // `.*.agentlink-partial` junk left after interrupted copies.
    let _ = sweep_stale_partials(&full);
    let mut entries = Vec::new();
    for item in fs::read_dir(&full)? {
        let item = item?;
        let name = item.file_name().to_string_lossy().to_string();
        let meta = match fs::symlink_metadata(item.path()) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        // is_dir/is_file follow the target so `cp`/`ls` treat junctions and
        // symlink-to-dir like Unix directory roots; is_symlink stays true.
        let (is_dir, is_file) = entry_dir_file(&meta, &item.path());
        entries.push(DirEntry {
            name,
            is_dir,
            is_file,
            is_symlink: meta.file_type().is_symlink(),
            size: meta.len(),
            modified_unix_ms: modified_ms(&meta),
            mode: unix_mode(&meta),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

async fn read_op(
    resp: &Responder,
    cancel: &CancellationToken,
    root: Option<&Path>,
    path: &str,
    offset: u64,
    max_bytes: u32,
) -> Result<()> {
    if max_bytes > MAX_READ {
        return Err(Error::Message(format!(
            "max_bytes {max_bytes} exceeds the {MAX_READ} byte limit"
        )));
    }
    let full = resolve_path(root, path)?;
    let mut file = tokio::fs::File::open(&full)
        .await
        .map_err(|err| diagnose_read_io(&full, err))?;
    if offset > 0 {
        file.seek(SeekFrom::Start(offset)).await?;
    }
    let mut left = max_bytes as usize;
    let mut buf = vec![0u8; FILE_CHUNK.min(left.max(1))];
    while left > 0 {
        if cancel.is_cancelled() {
            resp.end(None, Some("cancelled".into())).await?;
            return Ok(());
        }
        let cap = left.min(buf.len());
        let n = file.read(&mut buf[..cap]).await?;
        if n == 0 {
            break;
        }
        resp.chunk("file", &buf[..n]).await?;
        left -= n;
    }
    resp.end(None, None).await?;
    Ok(())
}

async fn write_op(
    resp: &Responder,
    root: Option<&Path>,
    path: &str,
    offset: u64,
    data_b64: &str,
    truncate: bool,
) -> Result<()> {
    if agentlink_core::paths::path_trailing_sep(path) {
        return Err(Error::Message(format!(
            "write destination `{path}` ends with a slash; pass a file path (use mkdir if you need a directory)"
        )));
    }
    let data = util::b64_decode(data_b64)?;
    if data.len() > MAX_WRITE {
        return Err(Error::Message("write chunk is larger than 1 MiB".into()));
    }
    let full = resolve_path(root, path)?;
    let full = agentlink_core::paths::ensure_path_stays_in_sandbox_at_sink(root, &full)?;
    let before = audit_before_snapshot(&full).await;
    let nofollow = root.is_some();
    let open_path = full.clone();
    let std_file = tokio::task::spawn_blocking(move || {
        agentlink_core::paths::open_write_file(&open_path, true, truncate, nofollow)
    })
    .await
    .map_err(|err| Error::Message(format!("write open task: {err}")))??;
    let mut file = tokio::fs::File::from_std(std_file);
    if !truncate || offset > 0 {
        file.seek(SeekFrom::Start(offset)).await?;
    }
    file.write_all(&data).await?;
    file.flush().await?;
    let after = audit_after_snapshot(&full).await;
    if let Ok(mut extra) = resp.extra.lock() {
        extra.before = before;
        extra.after = after;
        extra.paths = vec![full_display(&full)];
    }
    resp.ok(serde_json::json!({
        "path": full_display(&full),
        "offset": offset,
        "bytes": data.len(),
    }))
    .await?;
    Ok(())
}

/// Audit snapshot taken before a write. Missing or unreadable files yield
/// `None`; files over the audit cap are skipped without being read.
async fn audit_before_snapshot(path: &Path) -> Option<Vec<u8>> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    if meta.len() > MAX_WRITE as u64 {
        return None;
    }
    tokio::fs::read(path).await.ok()
}

/// Audit snapshot taken after a write: read first, then drop over-cap files.
async fn audit_after_snapshot(path: &Path) -> Option<Vec<u8>> {
    tokio::fs::read(path)
        .await
        .ok()
        .filter(|bytes| bytes.len() <= MAX_WRITE)
}

async fn mkdir_op(
    resp: &Responder,
    root: Option<&Path>,
    path: &str,
    recursive: bool,
) -> Result<()> {
    let full = if recursive {
        resolve_lexical(root, path)?
    } else {
        resolve_path(root, path)?
    };
    let create_path = full.clone();
    tokio::task::spawn_blocking(move || {
        let created = if recursive {
            fs::create_dir_all(&create_path)
        } else {
            fs::create_dir(&create_path)
        };
        created.map_err(|err| diagnose_mkdir_io(&create_path, recursive, err))
    })
    .await
    .map_err(|err| Error::Message(format!("mkdir task: {err}")))??;
    resp.ok(serde_json::json!({"path": full_display(&full)}))
        .await?;
    Ok(())
}

/// Clarify bare EEXIST / ENOTDIR from mkdir / create_dir_all.
/// Keep Unix semantics: non-recursive still fails when the path exists.
fn diagnose_mkdir_io(path: &Path, recursive: bool, err: io::Error) -> Error {
    let already = err.kind() == ErrorKind::AlreadyExists || err.raw_os_error() == Some(17);
    let enotdir = is_not_a_directory(&err);
    if !already && !enotdir {
        return err.into();
    }

    if already {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => match fs::metadata(path) {
                Ok(m) if m.is_dir() => {
                    if !recursive {
                        return Error::Message(format!(
                            "mkdir `{}` already exists as a directory",
                            path.display()
                        ));
                    }
                }
                // Symlink to file, or dangling: not a directory.
                _ => {
                    return Error::Message(mkdir_not_dir_message(path, recursive));
                }
            },
            Ok(meta) if meta.is_dir() => {
                if !recursive {
                    return Error::Message(format!(
                        "mkdir `{}` already exists as a directory",
                        path.display()
                    ));
                }
            }
            Ok(_) => {
                return Error::Message(mkdir_not_dir_message(path, recursive));
            }
            Err(_) => {}
        }
    }

    if let Some(blocker) = first_nondir_ancestor(path) {
        return Error::Message(format!(
            "path component `{}` exists but is not a directory; `-p`/`--parents` cannot fix that — pick a different path or remove the blocking file",
            blocker.display()
        ));
    }
    err.into()
}

fn mkdir_not_dir_message(path: &Path, recursive: bool) -> String {
    if recursive {
        format!(
            "mkdir `{}` exists but is not a directory; `-p`/`--parents` cannot replace a file with a directory",
            path.display()
        )
    } else {
        format!("mkdir `{}` exists but is not a directory", path.display())
    }
}


async fn remove_op(
    resp: &Responder,
    root: Option<&Path>,
    path: &str,
    recursive: bool,
) -> Result<()> {
    let full = agentlink_core::paths::resolve_path_no_follow(root, path)?;
    let rm_path = full.clone();
    let path_display = path.to_string();
    tokio::task::spawn_blocking(move || {
        remove_path(&rm_path, recursive)
            .map_err(|err| diagnose_remove_io(&path_display, &rm_path, err))
    })
    .await
    .map_err(|err| Error::Message(format!("remove task: {err}")))??;
    resp.ok(serde_json::json!({"removed": full_display(&full)}))
        .await?;
    Ok(())
}

fn diagnose_remove_io(path_display: &str, full: &Path, err: Error) -> Error {
    match err {
        Error::Io(ioerr) if ioerr.kind() == ErrorKind::NotFound => {
            missing_path_error("rm", path_display)
        }
        Error::Io(ioerr) if is_not_a_directory(&ioerr) => {
            path_component_not_dir_error(full).unwrap_or(Error::Io(ioerr))
        }
        other => other,
    }
}

fn diagnose_read_io(full: &Path, err: io::Error) -> Error {
    if is_not_a_directory(&err) {
        if let Some(tip) = path_component_not_dir_error(full) {
            return tip;
        }
    }
    err.into()
}

/// Remove a path. Symlinks (including Windows junctions / symlink_dir) drop
/// only the link — never the target tree — even when `recursive` is set.
fn remove_path(full: &Path, recursive: bool) -> Result<()> {
    let meta = fs::symlink_metadata(full)?;
    if meta.file_type().is_symlink() {
        remove_symlink(full, &meta)?;
        return Ok(());
    }
    if meta.is_dir() {
        if recursive {
            fs::remove_dir_all(full)?;
        } else {
            fs::remove_dir(full)?;
        }
    } else {
        fs::remove_file(full)?;
    }
    Ok(())
}

fn remove_symlink(full: &Path, meta: &fs::Metadata) -> Result<()> {
    // Unix: unlink(2) works for file and directory symlinks.
    // Windows: DeleteFile fails on directory reparse points (junctions /
    // symlink_dir) with ERROR_ACCESS_DENIED; RemoveDirectory removes the
    // link and leaves the target intact.
    #[cfg(windows)]
    {
        if meta.is_dir() {
            fs::remove_dir(full)?;
            return Ok(());
        }
        match fs::remove_file(full) {
            Ok(()) => Ok(()),
            Err(err) if err.raw_os_error() == Some(5) => {
                // Access denied: treat as a directory reparse that did not
                // advertise FILE_ATTRIBUTE_DIRECTORY on the link metadata.
                let _ = err;
                fs::remove_dir(full)?;
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = meta;
        fs::remove_file(full)?;
        Ok(())
    }
}

async fn rename_op(resp: &Responder, root: Option<&Path>, from: &str, to: &str) -> Result<()> {
    let from_full = agentlink_core::paths::resolve_path_no_follow(root, from)?;
    let trailing = agentlink_core::paths::path_trailing_sep(to);
    let to_trimmed = agentlink_core::paths::trim_trailing_sep(to);
    // Follow `to_trimmed` when it names an existing directory (so `mv a dir_link`
    // moves `a` into the linked directory inside `--root`), otherwise keep the
    // destination entry un-dereferenced so renaming onto an existing symlink
    // replaces the symlink entry rather than escaping through a dangling target.
    let to_base = match resolve_path(root, to_trimmed) {
        Ok(resolved) if resolved.is_dir() => resolved,
        _ => agentlink_core::paths::resolve_path_no_follow(root, to_trimmed)?,
    };
    let to_full = agentlink_core::paths::rename_destination(&from_full, &to_base, trailing)?;
    agentlink_core::paths::ensure_moved_symlinks_stay_inside(root, &from_full, &to_full)?;
    let (from_full, to_full) = tokio::task::spawn_blocking(move || {
        fs::rename(&from_full, &to_full)
            .map_err(|err| diagnose_rename_io(&from_full, &to_full, err))?;
        Ok::<_, Error>((from_full, to_full))
    })
    .await
    .map_err(|err| Error::Message(format!("rename task: {err}")))??;
    resp.ok(serde_json::json!({
        "from": full_display(&from_full),
        "to": full_display(&to_full),
    }))
    .await?;
    Ok(())
}

/// Clarify bare ENOENT/ENOTDIR/EINVAL from `rename(2)`: missing source vs
/// missing / non-dir parent vs moving a directory onto a file vs moving a
/// directory into itself.
/// Unlike `write`/`cp`, `mv` never creates destination parents.
fn diagnose_rename_io(from: &Path, to: &Path, err: io::Error) -> Error {
    let enoent = err.kind() == ErrorKind::NotFound;
    let enotdir = is_not_a_directory(&err);
    let einval = err.kind() == ErrorKind::InvalidInput
        || err.raw_os_error() == Some(22)
        || err.to_string().contains("Invalid argument");
    // rename(dir, dir/child) → EINVAL on Linux; other EINVAL stays passthrough.
    if einval && from.is_dir() && path_is_inside(to, from) {
        return Error::Message(format!(
            "cannot move directory `{}` into itself (`{}` is inside it)",
            from.display(),
            to.display()
        ));
    }
    if !enoent && !enotdir {
        return err.into();
    }
    if enoent && !from.exists() {
        return Error::Message(format!(
            "mv source `{}` does not exist",
            from.display()
        ));
    }
    // rename(dir, file) → ENOTDIR on Linux; parent checks below would miss it.
    if enotdir && path_is_nondir(to) && from.is_dir() {
        return Error::Message(format!(
            "mv destination `{}` exists but is not a directory; cannot move directory `{}` onto a file",
            to.display(),
            from.display()
        ));
    }
    match to.parent() {
        Some(parent) if !parent.as_os_str().is_empty() && !parent.exists() => Error::Message(
            format!(
                "mv destination parent `{}` does not exist; create it with mkdir -p first (unlike write/cp, mv does not create parents)",
                parent.display()
            ),
        ),
        Some(parent) if parent.exists() && !parent.is_dir() => Error::Message(format!(
            "mv destination parent `{}` exists but is not a directory",
            parent.display()
        )),
        _ => err.into(),
    }
}

fn path_is_nondir(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            // symlink-to-dir is a directory; symlink-to-file or dangling → nondir.
            fs::metadata(path).map(|m| !m.is_dir()).unwrap_or(true)
        }
        Ok(meta) => !meta.is_dir(),
        Err(_) => false,
    }
}

/// True when `inner` resolves under directory `outer` (and is not `outer` itself).
/// `inner` may be missing; walks to the nearest existing ancestor then rejoins.
fn path_is_inside(inner: &Path, outer: &Path) -> bool {
    let Ok(outer_c) = fs::canonicalize(outer) else {
        return false;
    };
    if !outer_c.is_dir() {
        return false;
    }
    let Some(inner_c) = canonicalize_allow_missing_local(inner) else {
        return false;
    };
    inner_c.starts_with(&outer_c) && inner_c != outer_c
}

fn canonicalize_allow_missing_local(path: &Path) -> Option<PathBuf> {
    if let Ok(c) = fs::canonicalize(path) {
        return Some(c);
    }
    let mut suffix = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        if let Ok(c) = fs::canonicalize(&cur) {
            let mut out = c;
            for comp in suffix.iter().rev() {
                out.push(comp);
            }
            return Some(out);
        }
        let name = cur.file_name()?.to_os_string();
        suffix.push(name);
        cur = cur.parent()?.to_path_buf();
        if cur.as_os_str().is_empty() {
            return None;
        }
    }
}


fn decode_stdin_b64(b64: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    const MAX_STDIN: usize = 16 * 1024 * 1024;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|err| Error::Message(format!("stdin_b64: {err}")))?;
    if bytes.len() > MAX_STDIN {
        return Err(Error::Message(format!(
            "stdin is {} bytes; max is {MAX_STDIN}. Write a file and exec that path instead.",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
async fn exec_op(
    resp: &Responder,
    cancel: &CancellationToken,
    root: Option<&Path>,
    commands: &CommandPolicy,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    env: &[(String, String)],
    timeout_ms: Option<u64>,
    shell: bool,
    stdin_b64: Option<&str>,
) -> Result<Finished> {
    let display = proc::command_line(program, args, shell);
    allow_command(commands, program, args, shell)?;
    let (cwd_path, cwd_display) = confine_cwd(root, cwd)?;
    let stdin_bytes = match stdin_b64 {
        Some(b64) => Some(decode_stdin_b64(b64)?),
        None => None,
    };
    let mut cmd = if shell {
        // Policy still sees cmd.exe via allow_command → shell_parts.
        proc::prepare_shell_command(program, cwd_path.as_deref(), env)?
    } else {
        proc::prepare_command(program, args, cwd_path.as_deref(), env)?
    };
    if stdin_bytes.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    let mut grouped = proc::spawn_grouped_program(program, &mut cmd)?;
    if let Some(bytes) = stdin_bytes {
        let mut stdin = grouped
            .child
            .inner()
            .stdin
            .take()
            .ok_or_else(|| Error::Message("stdin missing".into()))?;
        use tokio::io::AsyncWriteExt;
        stdin.write_all(&bytes).await.map_err(Error::Io)?;
        stdin.shutdown().await.map_err(Error::Io)?;
    }
    let mut stdout = grouped
        .child
        .inner()
        .stdout
        .take()
        .ok_or_else(|| Error::Message("stdout missing".into()))?;
    let mut stderr = grouped
        .child
        .inner()
        .stderr
        .take()
        .ok_or_else(|| Error::Message("stderr missing".into()))?;
    let out_buf = Arc::new(Mutex::new(Vec::new()));
    let err_buf = Arc::new(Mutex::new(Vec::new()));

    let out_resp = resp.clone();
    let out_cancel = cancel.clone();
    let out_cap = out_buf.clone();
    let out_task = tokio::spawn(async move {
        pump(&mut stdout, &out_resp, "stdout", &out_cancel, &out_cap).await;
    });
    let err_resp = resp.clone();
    let err_cancel = cancel.clone();
    let err_cap = err_buf.clone();
    let err_task = tokio::spawn(async move {
        pump(&mut stderr, &err_resp, "stderr", &err_cancel, &err_cap).await;
    });

    let stopped = tokio::select! {
        _ = cancel.cancelled() => Some("cancelled"),
        _ = async {
            if let Some(ms) = timeout_ms {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            } else {
                std::future::pending::<()>().await;
            }
        } => Some("timed out"),
        status = grouped.child.wait() => {
            let _ = out_task.await;
            let _ = err_task.await;
            let code = status?.code();
            resp.end(code, None).await?;
            return Ok(already(process_outcome(
                &display, cwd_display, code, &out_buf, &err_buf, None,
            )));
        }
    };
    proc::kill_group(&mut grouped.child).await;
    let _ = out_task.await;
    let _ = err_task.await;
    let why = stopped.unwrap_or("cancelled");
    resp.end(None, Some(why.into())).await?;
    Ok(already(process_outcome(
        &display,
        cwd_display,
        None,
        &out_buf,
        &err_buf,
        Some(why),
    )))
}

fn process_outcome(
    command: &str,
    cwd: Option<String>,
    exit_code: Option<i32>,
    stdout: &Mutex<Vec<u8>>,
    stderr: &Mutex<Vec<u8>>,
    error: Option<&str>,
) -> Outcome {
    let out = stdout.lock().map(|buf| buf.clone()).unwrap_or_default();
    let err = stderr.lock().map(|buf| buf.clone()).unwrap_or_default();
    let process = ProcessAudit::new(command, cwd, exit_code, &audit::combine_output(&out, &err));
    let body = serde_json::json!({"exit_code": exit_code});
    let outcome = match error {
        Some(error) => {
            let mut failed = Outcome::fail(error);
            failed.result = body;
            failed
        }
        None => Outcome::ok(body),
    };
    outcome.with_process(process)
}

async fn pump(
    reader: &mut (impl AsyncRead + Unpin),
    resp: &Responder,
    stream: &str,
    cancel: &CancellationToken,
    capture: &Mutex<Vec<u8>>,
) {
    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            read = reader.read(&mut buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        proc::push_capped(capture, &buf[..n], audit::OUTPUT_CAP);
                        if resp.chunk(stream, &buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn watch_start(ctx: &OpContext<'_>, path: &str, recursive: bool) -> Result<Outcome> {
    let full = resolve_path(ctx.root, path)?;
    let value = ctx.watches.start(&full, recursive)?;
    Ok(Outcome::ok(value))
}

async fn bg_start(
    ctx: &OpContext<'_>,
    program: &str,
    args: &[String],
    cwd: Option<String>,
    env: &[(String, String)],
    shell: bool,
    stdin_b64: Option<&str>,
) -> Result<Finished> {
    allow_command(ctx.commands, program, args, shell)?;
    let (cwd_path, cwd_display) = confine_cwd(ctx.root, cwd.as_deref())?;
    let stdin_bytes = match stdin_b64 {
        Some(b64) => Some(decode_stdin_b64(b64)?),
        None => None,
    };
    let (value, process) = ctx
        .procs
        .start(
            &origin_of(ctx),
            ctx.audit.clone(),
            Some(ctx.client_id.to_string()),
            program,
            args,
            cwd_path.as_deref(),
            cwd_display,
            env,
            shell,
            stdin_bytes.as_deref(),
        )
        .await?;
    Ok(ready(Outcome::ok(value).with_process(process)))
}

async fn pty_open(
    resp: &Responder,
    ctx: &OpContext<'_>,
    command: Option<String>,
    cwd: Option<String>,
    rows: u16,
    cols: u16,
) -> Result<Finished> {
    let command_line = command.clone().unwrap_or_else(|| default_shell_name());
    let (program, args) = shell_parts(&command_line);
    allow_command(ctx.commands, &program, &args, command.is_some())?;
    let (cwd_path, cwd_display) = confine_cwd(ctx.root, cwd.as_deref())?;
    let session_id = ctx
        .pty
        .open(
            command,
            cwd_path,
            rows,
            cols,
            resp.clone(),
            origin_of(ctx),
            Some(ctx.client_id.to_string()),
            ctx.audit.clone(),
            ctx.peer_id,
            ctx.grant_jti.unwrap_or(""),
            ctx.grant_exp_unix,
        )
        .await?;
    Ok(already(
        Outcome::ok(serde_json::json!({"session_id": session_id})).with_process(ProcessAudit::new(
            command_line,
            cwd_display,
            None,
            "",
        )),
    ))
}

fn default_shell_name() -> String {
    if cfg!(windows) {
        "cmd.exe".into()
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
    }
}

async fn pty_input(
    resp: &Responder,
    pty: &PtyManager,
    peer: &str,
    session_id: &str,
    data_b64: &str,
) -> Result<()> {
    let data = util::b64_decode(data_b64)?;
    pty.write(session_id, &data, peer)?;
    resp.ok(serde_json::json!({"bytes": data.len()})).await?;
    Ok(())
}

async fn pty_resize(
    resp: &Responder,
    pty: &PtyManager,
    peer: &str,
    session_id: &str,
    rows: u16,
    cols: u16,
) -> Result<()> {
    pty.resize(session_id, rows, cols, peer)?;
    resp.ok(serde_json::json!({"rows": rows, "cols": cols}))
        .await?;
    Ok(())
}

async fn pty_close(resp: &Responder, pty: &PtyManager, peer: &str, session_id: &str) -> Result<()> {
    pty.close(session_id, Some(peer))?;
    resp.ok(serde_json::json!({"closed": session_id})).await?;
    Ok(())
}

async fn extension_op(
    resp: &Responder,
    extensions: &[Arc<dyn NodeExtension>],
    name: &str,
    payload: &serde_json::Value,
    peer: &str,
) -> Result<()> {
    let value = dispatch_extension_as(extensions, name, payload, peer).map_err(Error::Message)?;
    resp.ok(value).await?;
    Ok(())
}

pub fn shell_parts(line: &str) -> (String, Vec<String>) {
    if cfg!(windows) {
        ("cmd.exe".into(), vec!["/C".into(), line.to_string()])
    } else {
        ("sh".into(), vec!["-c".into(), line.to_string()])
    }
}

fn file_stat(path: &Path) -> Result<FileStat> {
    let meta = fs::symlink_metadata(path)?;
    let kind = meta.file_type();
    // Follow for is_dir/is_file so copy_download routes symlink-to-dir (and
    // Windows junctions) through PullDir instead of the file path that rejects
    // them with "use directory copy". Link metadata stays on size/mode/mtime.
    let (is_dir, is_file) = entry_dir_file(&meta, path);
    Ok(FileStat {
        path: full_display(path),
        is_dir,
        is_file,
        is_symlink: kind.is_symlink(),
        size: meta.len(),
        modified_unix_ms: modified_ms(&meta),
        readonly: meta.permissions().readonly(),
        mode: unix_mode(&meta),
    })
}

/// Directory/file flags for listing and stat. Symlinks report the target's
/// kind when it resolves; broken links stay non-dir/non-file with is_symlink.
fn entry_dir_file(meta: &fs::Metadata, path: &Path) -> (bool, bool) {
    if meta.file_type().is_symlink() {
        match fs::metadata(path) {
            Ok(target) => (target.is_dir(), target.is_file()),
            Err(_) => (false, false),
        }
    } else {
        (meta.is_dir(), meta.is_file())
    }
}

fn modified_ms(meta: &fs::Metadata) -> Option<i64> {
    let modified = meta.modified().ok()?;
    let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(dur.as_millis() as i64)
}

#[cfg(unix)]
fn unix_mode(meta: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode())
}

#[cfg(not(unix))]
fn unix_mode(_meta: &fs::Metadata) -> Option<u32> {
    None
}

fn full_display(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

/// Overwrite view/control flags from the verified grant (clipped by the node
/// ceiling). Client-supplied `_allow_*` and `_grant_*` fields are discarded.
pub(crate) fn fill_stream_grant_flags(
    payload: &mut Value,
    policy: NodePolicy,
    grant_jti: Option<&str>,
    grant_exp_unix: Option<i64>,
) {
    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    obj.insert(
        "_allow_view".to_string(),
        serde_json::json!(policy.allows_remote_view()),
    );
    obj.insert(
        "_allow_control".to_string(),
        serde_json::json!(policy.allows_remote_control()),
    );
    obj.remove("_grant_jti");
    obj.remove("_grant_exp");
    if let Some(jti) = grant_jti.map(str::trim).filter(|s| !s.is_empty()) {
        obj.insert("_grant_jti".to_string(), serde_json::json!(jti));
    }
    if let Some(exp) = grant_exp_unix {
        obj.insert("_grant_exp".to_string(), serde_json::json!(exp));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shell_wraps_for_this_os() {
        let (program, args) = shell_parts("echo hi");
        if cfg!(windows) {
            assert_eq!(program, "cmd.exe");
            assert_eq!(args[0], "/C");
        } else {
            assert_eq!(program, "sh");
            assert_eq!(args, vec!["-c".to_string(), "echo hi".to_string()]);
        }
    }

    #[test]
    fn fallback_cwd_prefers_existing_home_or_tmp() {
        let path = fallback_cwd().expect("fallback cwd");
        assert!(path.is_dir(), "{path:?}");
    }

    #[test]
    fn confine_cwd_without_root_defaults_to_fallback_home() {
        let expected = fallback_cwd().expect("fallback cwd");
        let (path, display) = confine_cwd(None, None).unwrap();
        assert_eq!(path.as_deref(), Some(expected.as_path()));
        assert_eq!(
            display.as_deref().map(PathBuf::from).as_deref(),
            Some(expected.as_path())
        );
    }

    #[test]
    fn confine_cwd_explicit_cwd_and_root_still_win() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("work");
        fs::create_dir(&nested).unwrap();
        let (path, display) = confine_cwd(None, Some(nested.to_str().unwrap())).unwrap();
        assert!(
            agentlink_core::paths::paths_equivalent(path.as_deref().unwrap(), nested.as_path()),
            "path {path:?} vs {nested:?}"
        );
        assert!(
            agentlink_core::paths::paths_equivalent(
                Path::new(display.as_deref().unwrap()),
                nested.as_path()
            ),
            "display {display:?} vs {nested:?}"
        );

        let (path, display) = confine_cwd(Some(dir.path()), None).unwrap();
        assert!(
            agentlink_core::paths::paths_equivalent(path.as_deref().unwrap(), dir.path()),
            "sandbox cwd {path:?} vs {}; canonical prefixes must not leak",
            dir.path().display()
        );
        assert!(
            agentlink_core::paths::paths_equivalent(
                Path::new(display.as_deref().unwrap()),
                dir.path()
            ),
            "display {display:?} vs {}",
            dir.path().display()
        );
        let shown = display.unwrap();
        assert!(
            !shown.contains(r"\\?\") && !shown.contains(r"//?/"),
            "cwd display must not use a verbatim prefix: {shown}"
        );
    }

    #[test]
    fn diagnose_rename_io_missing_source() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("missing-src.txt");
        let to = dir.path().join("dst.txt");
        let err = io::Error::new(ErrorKind::NotFound, "os error 2");
        let msg = diagnose_rename_io(&from, &to, err).to_string();
        assert!(msg.contains("mv source"), "{msg}");
        assert!(msg.contains("does not exist"), "{msg}");
        assert!(!msg.contains("destination parent"), "{msg}");
    }

    #[test]
    fn diagnose_rename_io_missing_parent() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("src.txt");
        fs::write(&from, b"x").unwrap();
        let to = dir.path().join("no-parent").join("dst.txt");
        let err = io::Error::new(ErrorKind::NotFound, "os error 2");
        let msg = diagnose_rename_io(&from, &to, err).to_string();
        assert!(msg.contains("destination parent"), "{msg}");
        assert!(msg.contains("mkdir -p"), "{msg}");
        assert!(msg.contains("does not create parents"), "{msg}");
        assert!(from.exists(), "source must remain");
    }

    #[test]
    fn diagnose_rename_io_parent_is_file() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("src.txt");
        fs::write(&from, b"x").unwrap();
        let parent = dir.path().join("file-as-parent");
        fs::write(&parent, b"not a dir").unwrap();
        let to = parent.join("dst.txt");
        let err = fs::rename(&from, &to).unwrap_err();
        let msg = diagnose_rename_io(&from, &to, err).to_string();
        assert!(msg.contains("not a directory"), "{msg}");
        assert!(from.exists(), "source must remain");
    }

    #[test]
    fn diagnose_rename_io_dest_is_file_synthetic() {
        // Portable: Windows rename(dir, file) is ACCESS_DENIED/AlreadyExists, not ENOTDIR.
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("srcdir");
        fs::create_dir(&from).unwrap();
        let to = dir.path().join("destfile");
        fs::write(&to, b"keep").unwrap();
        let err = io::Error::new(ErrorKind::NotADirectory, "Not a directory (os error 20)");
        let msg = diagnose_rename_io(&from, &to, err).to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains("cannot move directory"), "{msg}");
        assert!(msg.contains("onto a file"), "{msg}");
        assert!(from.is_dir(), "source dir must remain");
        assert_eq!(fs::read_to_string(&to).unwrap(), "keep");
    }

    #[test]
    #[cfg(unix)]
    fn diagnose_rename_io_dest_is_file_live() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("srcdir");
        fs::create_dir(&from).unwrap();
        fs::write(from.join("a.txt"), b"x").unwrap();
        let to = dir.path().join("destfile");
        fs::write(&to, b"keep").unwrap();
        let err = fs::rename(&from, &to).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotADirectory, "{err}");
        let msg = diagnose_rename_io(&from, &to, err).to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains("cannot move directory"), "{msg}");
        assert!(msg.contains("onto a file"), "{msg}");
        assert!(from.is_dir(), "source dir must remain");
        assert_eq!(fs::read_to_string(&to).unwrap(), "keep");
    }

    #[test]
    fn diagnose_rename_io_into_self_synthetic() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("srcdir");
        fs::create_dir(&from).unwrap();
        let child = from.join("sub");
        fs::create_dir(&child).unwrap();
        let err = io::Error::new(ErrorKind::InvalidInput, "Invalid argument (os error 22)");
        let msg = diagnose_rename_io(&from, &child, err).to_string();
        assert!(msg.contains("into itself"), "{msg}");
        assert!(msg.contains("is inside it"), "{msg}");
        assert!(from.is_dir(), "source must remain");
    }

    #[test]
    fn diagnose_rename_io_into_self_missing_nested_synthetic() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("srcdir");
        fs::create_dir(&from).unwrap();
        let child = from.join("sub");
        fs::create_dir(&child).unwrap();
        let nested = child.join("nested");
        let err = io::Error::new(ErrorKind::InvalidInput, "Invalid argument (os error 22)");
        let msg = diagnose_rename_io(&from, &nested, err).to_string();
        assert!(msg.contains("into itself"), "{msg}");
        assert!(msg.contains("is inside it"), "{msg}");
    }

    #[test]
    fn diagnose_rename_io_einval_unrelated_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("a");
        fs::create_dir(&from).unwrap();
        let to = dir.path().join("b");
        fs::create_dir(&to).unwrap();
        let err = io::Error::new(ErrorKind::InvalidInput, "Invalid argument (os error 22)");
        let msg = diagnose_rename_io(&from, &to, err).to_string();
        assert!(!msg.contains("into itself"), "{msg}");
        assert!(
            msg.contains("Invalid argument") || msg.contains("os error 22"),
            "{msg}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn diagnose_rename_io_into_self_live() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("srcdir");
        fs::create_dir(&from).unwrap();
        let child = from.join("sub");
        fs::create_dir(&child).unwrap();
        fs::write(from.join("a.txt"), b"x").unwrap();
        let err = fs::rename(&from, &child).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err}");
        let msg = diagnose_rename_io(&from, &child, err).to_string();
        assert!(msg.contains("into itself"), "{msg}");
        assert!(msg.contains("is inside it"), "{msg}");
        assert!(from.is_dir(), "source must remain");
        assert!(child.is_dir(), "child must remain");
        assert_eq!(fs::read_to_string(from.join("a.txt")).unwrap(), "x");
    }

    #[test]
    fn diagnose_rename_io_file_from_enotdir_passthrough() {
        // from.is_dir() guard must not misdiagnose file→file ENOTDIR as dir-onto-file.
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("src.txt");
        fs::write(&from, b"x").unwrap();
        let to = dir.path().join("destfile");
        fs::write(&to, b"keep").unwrap();
        let err = io::Error::new(ErrorKind::NotADirectory, "Not a directory (os error 20)");
        let msg = diagnose_rename_io(&from, &to, err).to_string();
        assert!(!msg.contains("cannot move directory"), "{msg}");
        assert!(!msg.contains("onto a file"), "{msg}");
        assert!(
            msg.contains("Not a directory") || msg.contains("os error 20"),
            "{msg}"
        );
    }

    #[test]
    fn diagnose_rename_io_non_enoent_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("a");
        let to = dir.path().join("b");
        let err = io::Error::new(ErrorKind::PermissionDenied, "os error 13");
        let msg = diagnose_rename_io(&from, &to, err).to_string();
        assert!(msg.contains("os error 13") || msg.contains("Permission"), "{msg}");
        assert!(!msg.contains("mkdir -p"), "{msg}");
    }

    #[test]
    fn diagnose_mkdir_io_existing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("already");
        fs::create_dir(&path).unwrap();
        let err = io::Error::new(ErrorKind::AlreadyExists, "File exists");
        let msg = diagnose_mkdir_io(&path, false, err).to_string();
        assert!(msg.contains("already exists as a directory"), "{msg}");
        assert!(msg.contains("already"), "{msg}");
    }

    #[test]
    fn diagnose_mkdir_io_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        fs::write(&path, b"x").unwrap();
        let err = io::Error::new(ErrorKind::AlreadyExists, "File exists");
        let msg = diagnose_mkdir_io(&path, false, err).to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(!msg.contains("already exists as a directory"), "{msg}");
        let msg_p = diagnose_mkdir_io(&path, true, io::Error::new(ErrorKind::AlreadyExists, "File exists")).to_string();
        assert!(msg_p.contains("cannot replace a file"), "{msg_p}");
    }

    #[test]
    fn diagnose_mkdir_io_file_as_intermediate() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("child");
        let err = io::Error::new(ErrorKind::NotADirectory, "Not a directory");
        let msg = diagnose_mkdir_io(&path, true, err).to_string();
        assert!(msg.contains("path component"), "{msg}");
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains("blocker"), "{msg}");
    }


    #[test]
    fn stream_grant_flags_overwrite_client_fields_from_verified_grant() {
        let ceiling = NodePolicy::full();
        // Attacker / view-only client pre-sets control true: the node overwrites
        // from the verified grant (here a view-only policy).
        let mut stamped = json!({
            "_allow_view": true,
            "_allow_control": true,
            "_grant_jti": "forged",
            "_grant_exp": 9999999999i64
        });
        fill_stream_grant_flags(&mut stamped, NodePolicy::remote_view(), Some("real-jti"), Some(42));
        assert_eq!(stamped["_allow_control"], json!(false));
        assert_eq!(stamped["_allow_view"], json!(true));
        assert_eq!(stamped["_grant_jti"], json!("real-jti"));
        assert_eq!(stamped["_grant_exp"], json!(42));

        let mut bare = json!({"action": "offer", "_grant_jti": "forged"});
        fill_stream_grant_flags(&mut bare, ceiling, Some("ok"), None);
        assert_eq!(bare["_allow_control"], json!(true));
        assert_eq!(bare["_allow_view"], json!(true));
        assert_eq!(bare["_grant_jti"], json!("ok"));
        assert!(bare.get("_grant_exp").is_none());

        let mut no_grant = json!({"_allow_control": true, "_grant_jti": "forged"});
        fill_stream_grant_flags(&mut no_grant, ceiling, None, None);
        assert_eq!(no_grant["_allow_control"], json!(true));
        assert!(no_grant.get("_grant_jti").is_none());
    }

    #[test]
    fn stream_grant_flags_missing_client_flags_do_not_stay_true_on_view_only() {
        let mut bare = json!({"action": "offer"});
        fill_stream_grant_flags(&mut bare, NodePolicy::remote_view(), Some("j"), None);
        assert_eq!(bare["_allow_control"], json!(false));
        assert_eq!(bare["_allow_view"], json!(true));
    }

    #[test]
    #[cfg(unix)]
    fn directory_for_list_follows_symlink_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("f.txt"), b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let listed = directory_for_list(&link, "link").unwrap();
        assert_eq!(listed, link);
        let names: Vec<_> = fs::read_dir(&listed)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "f.txt"), "{names:?}");
    }

    #[test]
    fn path_component_not_dir_error_finds_file_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        fs::write(&file, b"x").unwrap();
        let child = file.join("child");
        let msg = path_component_not_dir_error(&child).unwrap().to_string();
        assert!(msg.contains("path component"), "{msg}");
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains("file.txt"), "{msg}");
    }

    #[test]
    fn directory_for_list_child_of_file_synthetic() {
        // Portable: Windows intermediate-file paths are NotFound, not ENOTDIR.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        fs::write(&file, b"x").unwrap();
        let child = file.join("child");
        // Force the ENOTDIR branch by calling the tip helper used by directory_for_list.
        let tip = path_component_not_dir_error(&child).unwrap().to_string();
        assert!(tip.contains("path component"), "{tip}");
        assert!(tip.contains("file.txt"), "{tip}");
    }

    #[test]
    #[cfg(unix)]
    fn directory_for_list_child_of_file_live() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        fs::write(&file, b"x").unwrap();
        let child = file.join("child");
        let err = directory_for_list(&child, child.to_str().unwrap()).unwrap_err().to_string();
        assert!(err.contains("path component"), "{err}");
        assert!(err.contains("exists but is not a directory"), "{err}");
        assert!(err.contains("file.txt"), "{err}");
    }

    #[test]
    fn diagnose_remove_io_child_of_file_synthetic() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        fs::write(&file, b"x").unwrap();
        let child = file.join("child");
        let err = Error::Io(io::Error::new(ErrorKind::NotADirectory, "Not a directory (os error 20)"));
        let msg = diagnose_remove_io(child.to_str().unwrap(), &child, err).to_string();
        assert!(msg.contains("path component"), "{msg}");
        assert!(msg.contains("file.txt"), "{msg}");
        assert!(file.is_file(), "blocking file must remain");
    }

    #[test]
    #[cfg(unix)]
    fn diagnose_remove_io_child_of_file_live() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        fs::write(&file, b"x").unwrap();
        let child = file.join("child");
        let err = remove_path(&child, false).unwrap_err();
        let msg = diagnose_remove_io(child.to_str().unwrap(), &child, err).to_string();
        assert!(msg.contains("path component"), "{msg}");
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains("file.txt"), "{msg}");
        assert!(file.is_file(), "blocking file must remain");
    }

    #[test]
    fn diagnose_read_io_child_of_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        fs::write(&file, b"x").unwrap();
        let child = file.join("child");
        let err = io::Error::new(ErrorKind::NotADirectory, "Not a directory (os error 20)");
        let msg = diagnose_read_io(&child, err).to_string();
        assert!(msg.contains("path component"), "{msg}");
        assert!(msg.contains("file.txt"), "{msg}");
        let missing = dir.path().join("nope");
        let err = io::Error::new(ErrorKind::NotFound, "No such file or directory");
        let msg = diagnose_read_io(&missing, err).to_string();
        assert!(!msg.contains("path component"), "{msg}");
    }

    #[test]
    #[cfg(unix)]
    fn diagnose_read_io_child_of_file_live_open() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        fs::write(&file, b"x").unwrap();
        let child = file.join("child");
        let err = fs::File::open(&child).unwrap_err();
        eprintln!("LIVE kind={:?} raw={:?} display={}", err.kind(), err.raw_os_error(), err);
        let msg = diagnose_read_io(&child, err).to_string();
        assert!(msg.contains("path component"), "{msg}");
        assert!(msg.contains("file.txt"), "{msg}");
    }

    #[test]
    fn missing_path_error_wording() {
        let msg = missing_path_error("rm", "/tmp/nope").to_string();
        assert_eq!(msg, "rm: path `/tmp/nope` does not exist");
        let msg = missing_path_error("ls", "/tmp/nope").to_string();
        assert_eq!(msg, "ls: path `/tmp/nope` does not exist");
    }

    #[test]
    fn diagnose_remove_io_missing() {
        let err = Error::Io(io::Error::new(ErrorKind::NotFound, "No such file or directory"));
        let full = Path::new("/tmp/nope");
        let msg = diagnose_remove_io("/tmp/nope", full, err).to_string();
        assert_eq!(msg, "rm: path `/tmp/nope` does not exist");
        let err = Error::Io(io::Error::new(ErrorKind::PermissionDenied, "os error 13"));
        let msg = diagnose_remove_io("/tmp/nope", full, err).to_string();
        assert!(msg.contains("os error 13") || msg.contains("Permission"), "{msg}");
        assert!(!msg.contains("does not exist"), "{msg}");
    }

    #[test]
    fn directory_for_list_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let err = directory_for_list(&missing, "/tmp/nope").unwrap_err().to_string();
        assert_eq!(err, "ls: path `/tmp/nope` does not exist");
    }

    #[test]
    fn remove_path_missing_surfaces_io_notfound() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let err = remove_path(&missing, false).unwrap_err();
        match err {
            Error::Io(ioerr) => assert_eq!(ioerr.kind(), ErrorKind::NotFound),
            other => panic!("expected Io NotFound, got {other}"),
        }
        let tipped = diagnose_remove_io("nope", &missing, remove_path(&missing, true).unwrap_err()).to_string();
        assert_eq!(tipped, "rm: path `nope` does not exist");
    }

    #[test]
    #[cfg(unix)]
    fn directory_for_list_rejects_broken_symlink_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("broken");
        std::os::unix::fs::symlink(dir.path().join("missing"), &broken).unwrap();
        let err = directory_for_list(&broken, "broken").unwrap_err().to_string();
        assert!(err.contains("broken symbolic link"), "{err}");

        let file = dir.path().join("file.txt");
        fs::write(&file, b"x").unwrap();
        let err = directory_for_list(&file, "file.txt").unwrap_err().to_string();
        assert!(err.contains("is a file"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn file_stat_symlink_to_dir_reports_is_dir() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("f.txt"), b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let stat = file_stat(&link).unwrap();
        assert!(stat.is_symlink, "{stat:?}");
        assert!(stat.is_dir, "symlink-to-dir must be is_dir for PullDir routing: {stat:?}");
        assert!(!stat.is_file, "{stat:?}");
    }

    #[test]
    #[cfg(unix)]
    fn file_stat_symlink_to_file_reports_is_file() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.txt");
        fs::write(&real, b"x").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let stat = file_stat(&link).unwrap();
        assert!(stat.is_symlink, "{stat:?}");
        assert!(stat.is_file, "{stat:?}");
        assert!(!stat.is_dir, "{stat:?}");
    }

    #[test]
    #[cfg(unix)]
    fn file_stat_broken_symlink_is_neither_dir_nor_file() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("broken");
        std::os::unix::fs::symlink(dir.path().join("missing"), &link).unwrap();
        let stat = file_stat(&link).unwrap();
        assert!(stat.is_symlink, "{stat:?}");
        assert!(!stat.is_dir && !stat.is_file, "{stat:?}");
    }

    #[test]
    #[cfg(unix)]
    fn remove_path_drops_symlink_to_dir_not_target() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("keep.txt"), b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        remove_path(&link, false).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
        assert!(real.join("keep.txt").is_file(), "target must survive");
    }

    #[test]
    #[cfg(unix)]
    fn remove_path_recursive_still_only_drops_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("keep.txt"), b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        remove_path(&link, true).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
        assert!(real.join("keep.txt").is_file());
    }

    #[test]
    #[cfg(windows)]
    fn remove_path_drops_junction_not_target() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("keep.txt"), b"x").unwrap();
        let link = dir.path().join("junc");
        std::os::windows::fs::symlink_dir(&real, &link).unwrap();

        remove_path(&link, false).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
        assert!(real.join("keep.txt").is_file(), "junction target must survive");
    }

    #[tokio::test]
    async fn audit_before_snapshot_reads_small_file_and_skips_large() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("small.txt");
        tokio::fs::write(&small, b"before").await.unwrap();
        assert_eq!(
            audit_before_snapshot(&small).await.as_deref(),
            Some(&b"before"[..])
        );

        let missing = dir.path().join("missing.txt");
        assert!(audit_before_snapshot(&missing).await.is_none());

        let large = dir.path().join("large.txt");
        tokio::fs::write(&large, vec![b'a'; MAX_WRITE + 1])
            .await
            .unwrap();
        assert!(audit_before_snapshot(&large).await.is_none());
    }

    #[tokio::test]
    async fn audit_after_snapshot_reads_small_file_and_filters_large() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("small.txt");
        tokio::fs::write(&small, b"after").await.unwrap();
        assert_eq!(
            audit_after_snapshot(&small).await.as_deref(),
            Some(&b"after"[..])
        );

        let missing = dir.path().join("missing.txt");
        assert!(audit_after_snapshot(&missing).await.is_none());

        let large = dir.path().join("large.txt");
        tokio::fs::write(&large, vec![b'a'; MAX_WRITE + 1])
            .await
            .unwrap();
        assert!(audit_after_snapshot(&large).await.is_none());

        let at_cap = dir.path().join("at_cap.txt");
        tokio::fs::write(&at_cap, vec![b'a'; MAX_WRITE])
            .await
            .unwrap();
        assert_eq!(
            audit_after_snapshot(&at_cap).await.map(|bytes| bytes.len()),
            Some(MAX_WRITE)
        );
    }

    fn test_responder() -> Responder {
        Responder {
            socket: Arc::new(SocketSlot::default()),
            request_id: "req-test".into(),
            seal: None,
            extra: Arc::new(Mutex::new(AuditExtra::default())),
            log: Arc::new(ReplayLog::default()),
        }
    }

    fn ok_result_body(resp: &Responder) -> Value {
        resp.log
            .snapshot()
            .iter()
            .find_map(|env| match env {
                Envelope::Result { ok: true, body, .. } => body.clone(),
                _ => None,
            })
            .expect("ok result body")
    }

    #[tokio::test]
    async fn list_op_lists_entries_sorted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("alpha.txt"), b"a").unwrap();
        fs::create_dir(dir.path().join("beta")).unwrap();
        let resp = test_responder();

        list_op(&resp, Some(dir.path()), ".").await.unwrap();

        let body = ok_result_body(&resp);
        let entries = body.as_array().expect("entries array");
        let names: Vec<_> = entries
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["alpha.txt", "beta"]);
        assert_eq!(entries[0]["is_file"], json!(true));
        assert_eq!(entries[0]["is_dir"], json!(false));
        assert_eq!(entries[0]["size"], json!(1));
        assert_eq!(entries[1]["is_dir"], json!(true));
        assert_eq!(entries[1]["is_file"], json!(false));
    }

    #[tokio::test]
    async fn stat_op_reports_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("doc.txt"), b"hello").unwrap();
        let resp = test_responder();

        stat_op(&resp, Some(dir.path()), "doc.txt").await.unwrap();

        let body = ok_result_body(&resp);
        assert_eq!(body["is_file"], json!(true));
        assert_eq!(body["is_dir"], json!(false));
        assert_eq!(body["is_symlink"], json!(false));
        assert_eq!(body["size"], json!(5));
    }

    #[tokio::test]
    async fn list_op_rejects_file_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("doc.txt"), b"x").unwrap();
        let resp = test_responder();

        let err = list_op(&resp, Some(dir.path()), "doc.txt")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("is a file"), "{err}");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn list_op_surfaces_broken_symlink_tip() {
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("broken");
        std::os::unix::fs::symlink(dir.path().join("missing"), &broken).unwrap();
        let resp = test_responder();

        let err = list_op(&resp, Some(dir.path()), "broken")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("broken symbolic link"), "{err}");
    }

    #[tokio::test]
    async fn mkdir_op_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let resp = test_responder();

        mkdir_op(&resp, Some(dir.path()), "newdir", false)
            .await
            .unwrap();

        assert!(dir.path().join("newdir").is_dir());
        let body = ok_result_body(&resp);
        assert!(body["path"].as_str().unwrap().ends_with("newdir"));
    }

    #[tokio::test]
    async fn mkdir_op_through_file_component_tips_not_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("blocker"), b"x").unwrap();
        let resp = test_responder();

        let err = mkdir_op(&resp, Some(dir.path()), "blocker/child", true)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("exists but is not a directory"), "{err}");
    }

    #[tokio::test]
    async fn remove_op_deletes_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("doc.txt");
        fs::write(&file, b"x").unwrap();
        let resp = test_responder();

        remove_op(&resp, Some(dir.path()), "doc.txt", false)
            .await
            .unwrap();

        assert!(!file.exists());
        let body = ok_result_body(&resp);
        assert!(body["removed"].as_str().unwrap().ends_with("doc.txt"));
    }

    #[tokio::test]
    async fn rename_op_moves_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("old.txt"), b"x").unwrap();
        let resp = test_responder();

        rename_op(&resp, Some(dir.path()), "old.txt", "new.txt")
            .await
            .unwrap();

        assert!(!dir.path().join("old.txt").exists());
        assert!(dir.path().join("new.txt").exists());
        let body = ok_result_body(&resp);
        assert!(body["from"].as_str().unwrap().ends_with("old.txt"));
        assert!(body["to"].as_str().unwrap().ends_with("new.txt"));
    }

    #[tokio::test]
    async fn write_op_captures_after_snapshot_for_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let resp = test_responder();
        write_op(
            &resp,
            Some(dir.path()),
            "doc.txt",
            0,
            &util::b64_encode(b"new"),
            true,
        )
        .await
        .unwrap();

        let extra = resp.extra.lock().unwrap();
        assert!(extra.before.is_none(), "new file has no prior contents");
        assert_eq!(extra.after.as_deref(), Some(&b"new"[..]));
    }

    #[tokio::test]
    async fn write_op_audits_previous_contents_on_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("doc.txt"), b"old").unwrap();
        let resp = test_responder();
        write_op(
            &resp,
            Some(dir.path()),
            "doc.txt",
            0,
            &util::b64_encode(b"new"),
            true,
        )
        .await
        .unwrap();

        let extra = resp.extra.lock().unwrap();
        assert_eq!(extra.before.as_deref(), Some(&b"old"[..]));
        assert_eq!(extra.after.as_deref(), Some(&b"new"[..]));
    }

    #[tokio::test]
    async fn write_op_skips_oversized_audit_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        fs::write(&path, vec![b'a'; MAX_WRITE + 1]).unwrap();
        let resp = test_responder();
        write_op(
            &resp,
            Some(dir.path()),
            "big.bin",
            0,
            &util::b64_encode(b"x"),
            false,
        )
        .await
        .unwrap();

        let extra = resp.extra.lock().unwrap();
        assert!(extra.before.is_none(), "over-cap file must not be read");
        assert!(extra.after.is_none(), "over-cap file must be filtered");
        assert_eq!(fs::metadata(&path).unwrap().len(), (MAX_WRITE + 1) as u64);
    }

    struct RecordingExt {
        peer: std::sync::Mutex<Option<String>>,
        payload_client_id: std::sync::Mutex<Option<String>>,
    }

    impl agentlink_core::NodeExtension for RecordingExt {
        fn name(&self) -> &'static str {
            agentlink_core::PHASE3_WEBRTC_SIGNAL
        }
        fn handle(&self, payload: &serde_json::Value) -> std::result::Result<serde_json::Value, String> {
            self.handle_peer(payload, "")
        }
        fn handle_peer(
            &self,
            payload: &serde_json::Value,
            peer: &str,
        ) -> std::result::Result<serde_json::Value, String> {
            *self.peer.lock().unwrap() = Some(peer.to_string());
            *self.payload_client_id.lock().unwrap() = payload
                .get("client_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            if payload.get("action").and_then(serde_json::Value::as_str) == Some("keyframe") {
                if peer != "alice" {
                    // The production handler would also deny; record the peer
                    // and reject so the test proves dispatch used seal.peer.
                }
            }
            Ok(serde_json::json!({"peer": peer}))
        }
    }

    #[tokio::test]
    async fn webrtc_extension_uses_seal_peer_not_inner_client_id() {
        let ext = Arc::new(RecordingExt {
            peer: std::sync::Mutex::new(None),
            payload_client_id: std::sync::Mutex::new(None),
        });
        let extensions: Vec<Arc<dyn agentlink_core::NodeExtension>> = vec![ext.clone()];
        let pty = crate::pty_session::PtyManager::default();
        let procs = crate::proc::ProcManager::new();
        let watches = crate::watch::WatchManager::default();
        let dir = tempfile::tempdir().unwrap();
        let audit = crate::pipeline::AuditService::open_quiet(dir.path(), "node", "box");
        let commands = agentlink_core::sandbox::CommandPolicy::baseline();
        let resp = test_responder();
        let session = uuid::Uuid::new_v4().to_string();
        let payload = serde_json::json!({
            "action": "keyframe",
            "session_id": session,
            "client_id": "bob",
        });
        let ctx = OpContext {
            root: None,
            policy: agentlink_core::NodePolicy::full(),
            extensions: &extensions,
            pty: &pty,
            procs: &procs,
            watches: &watches,
            audit_path: dir.path(),
            client_id: "bob", // forged inner / outer client_id
            node_name: "box",
            node_id: "node",
            commands: &commands,
            audit,
            user: None,
            device_id: None,
            peer_id: "alice",
            grant_jti: Some("jti-alice"),
            grant_exp_unix: None,
        };
        dispatch(
            Op::Extension {
                name: agentlink_core::PHASE3_WEBRTC_SIGNAL.to_string(),
                payload,
            },
            resp,
            CancellationToken::new(),
            ctx,
        )
        .await;
        assert_eq!(ext.peer.lock().unwrap().as_deref(), Some("alice"));
        assert_eq!(
            ext.payload_client_id.lock().unwrap().as_deref(),
            Some("bob"),
            "forged client_id may still ride in the payload; the handler peer must be the seal identity"
        );
    }
}
