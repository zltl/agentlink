//! Process groups and background commands.
//!
//! Children are started in a new process group on Unix and a job object on
//! Windows (`command-group`). Killing the group reaps grandchildren, which
//! killing only the direct child does not.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentlink_core::util;
use agentlink_core::{Error, Result};
use command_group::{AsyncCommandGroup, AsyncGroupChild};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::oneshot;

use crate::audit::{self, Origin, ProcessAudit};
use crate::pipeline::AuditService;

const MAX_PROCS: usize = 32;
const OUTPUT_MEM: usize = 1024 * 1024;
const KEEP_EXITED: Duration = Duration::from_secs(30 * 60);

pub struct GroupChild {
    pub child: AsyncGroupChild,
    pub pid: u32,
}

pub fn validate_env(key: &str, value: &str) -> Result<()> {
    if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
        return Err(Error::Message(format!("rejected env var '{key}'")));
    }
    Ok(())
}

pub fn prepare_command(
    program: &str,
    args: &[String],
    cwd: Option<&std::path::Path>,
    env: &[(String, String)],
) -> Result<tokio::process::Command> {
    // Whitespace-only used to reach posix_spawn and look like a missing binary
    // (ENOENT). Match shell --command: refuse blank before spawn. Do not trim
    // the program passed to Command::new — only use trim as an emptiness check.
    if program.trim().is_empty() {
        return Err(Error::Message("command is empty".into()));
    }
    // Flags for no-window are applied in spawn_grouped (command-group
    // overwrites creation_flags on the Command itself).
    let mut cmd = tokio::process::Command::new(program); // no-window-reviewed
    cmd.args(args);
    finish_command(&mut cmd, cwd, env)?;
    Ok(cmd)
}

fn finish_command(
    cmd: &mut tokio::process::Command,
    cwd: Option<&std::path::Path>,
    env: &[(String, String)],
) -> Result<()> {
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    if let Some(cwd) = cwd {
        // Fail before spawn so agents see "cwd …" instead of opaque ENOENT
        // (posix_spawn/CreateProcess also use ENOENT when the program is missing).
        let meta = std::fs::metadata(cwd).map_err(|err| {
            Error::Message(format!("cwd {}: {err}", cwd.display()))
        })?;
        if !meta.is_dir() {
            return Err(Error::Message(format!(
                "cwd {}: Not a directory",
                cwd.display()
            )));
        }
        cmd.current_dir(cwd);
    }
    for (key, value) in env {
        validate_env(key, value)?;
        cmd.env(key, value);
    }
    Ok(())
}

/// Spawn a platform shell running `line` (`sh -c` / `cmd /S /C`).
///
/// On Windows, `std`'s argv quoting turns user quotes into `\"`, so
/// `echo "hi"` prints `\"hi\"` and `dir "%TEMP%"` is a syntax error.
/// `raw_arg` + `cmd /S /C "line"` passes the line through intact.
pub fn prepare_shell_command(
    line: &str,
    cwd: Option<&std::path::Path>,
    env: &[(String, String)],
) -> Result<tokio::process::Command> {
    #[cfg(windows)]
    {
        // Hiding is applied in spawn_grouped via the job-object builder.
        let mut cmd = tokio::process::Command::new("cmd.exe"); // no-window-reviewed
        // /D skips AutoRun; /S makes cmd strip the wrapping quotes around the
        // /C argument so the caller's own quotes stay meaningful.
        cmd.arg("/D");
        cmd.arg("/S");
        cmd.raw_arg(windows_cmd_c_raw(line));
        finish_command(&mut cmd, cwd, env)?;
        Ok(cmd)
    }
    #[cfg(not(windows))]
    {
        prepare_command("sh", &["-c".into(), line.to_string()], cwd, env)
    }
}

/// Command-line fragment used for Windows `cmd /S /C` via [`prepare_shell_command`].
#[cfg(windows)]
pub fn windows_cmd_c_raw(line: &str) -> String {
    format!("/C \"{line}\"")
}

pub fn spawn_grouped(cmd: &mut tokio::process::Command) -> Result<GroupChild> {
    spawn_grouped_program("", cmd)
}

/// Spawn a process group, naming `program` on failure.
///
/// posix_spawn reports a missing binary as bare ENOENT (`spawn: No such file
/// or directory (os error 2)`), indistinguishable from other failures, so a
/// `NotFound` error gets a tip naming the program instead.
///
/// On Windows, `command-group` replaces any `creation_flags` already set on
/// the `Command` (it ORs `CREATE_SUSPENDED` onto the builder flags). The
/// no-window bit has to be set on the group builder or `cmd.exe` and every
/// other console-subsystem child of the tray node flashes a console.
pub fn spawn_grouped_program(program: &str, cmd: &mut tokio::process::Command) -> Result<GroupChild> {
    let child = spawn_group(cmd).map_err(|err| diagnose_spawn(program, err))?;
    let pid = child.id().unwrap_or(0);
    Ok(GroupChild { child, pid })
}

fn spawn_group(cmd: &mut tokio::process::Command) -> std::io::Result<AsyncGroupChild> {
    #[cfg(windows)]
    {
        cmd.group()
            .creation_flags(agentlink_core::process::WINDOWS_NO_WINDOW)
            .spawn()
    }
    #[cfg(not(windows))]
    {
        cmd.group_spawn()
    }
}

pub fn diagnose_spawn(program: &str, err: std::io::Error) -> Error {
    let not_found = err.kind() == std::io::ErrorKind::NotFound
        || err.to_string().contains("No such file");
    if !not_found {
        return Error::Message(format!("spawn: {err}"));
    }
    let detail = err.to_string();
    let path_like = program.contains('/') || program.contains('\\');
    if path_like {
        Error::Message(format!("program '{program}' not found ({detail})"))
    } else {
        Error::Message(format!("program '{program}' not found on PATH ({detail})"))
    }
}

/// Kill the process group (Unix) or job object (Windows), then wait.
pub async fn kill_group(child: &mut AsyncGroupChild) {
    match child.kill().await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {}
        Err(err) => tracing::debug!(error = %err, "process group kill"),
    }
}

pub fn command_line(program: &str, args: &[String], shell: bool) -> String {
    if shell || args.is_empty() {
        return program.to_string();
    }
    let mut parts = Vec::with_capacity(1 + args.len());
    parts.push(shell_quote(program));
    for arg in args {
        parts.push(shell_quote(arg));
    }
    parts.join(" ")
}

/// Quote one argv for display so spaces and metacharacters survive a copy/paste.
fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".into();
    }
    if arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | '@' | '+'))
    {
        return arg.to_string();
    }
    let mut out = String::from('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

pub fn push_capped(buf: &Mutex<Vec<u8>>, data: &[u8], cap: usize) {
    if let Ok(mut guard) = buf.lock() {
        let room = cap.saturating_sub(guard.len());
        if room > 0 {
            let n = room.min(data.len());
            guard.extend_from_slice(&data[..n]);
        }
    }
}

struct OutputBuf {
    data: Vec<u8>,
    start: u64,
}

impl OutputBuf {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            start: 0,
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
        if self.data.len() > OUTPUT_MEM {
            let drop_n = self.data.len() - OUTPUT_MEM;
            self.data.drain(..drop_n);
            self.start += drop_n as u64;
        }
    }

    fn read_from(&self, cursor: u64, max: usize) -> (u64, Vec<u8>, bool) {
        if cursor < self.start {
            let end = self.data.len().min(max);
            return (self.start + end as u64, self.data[..end].to_vec(), true);
        }
        let offset = (cursor - self.start) as usize;
        if offset >= self.data.len() {
            return (cursor, Vec::new(), false);
        }
        let end = (offset + max).min(self.data.len());
        (
            self.start + end as u64,
            self.data[offset..end].to_vec(),
            false,
        )
    }

    fn end(&self) -> u64 {
        self.start + self.data.len() as u64
    }

    fn tail(&self, max: usize) -> Vec<u8> {
        let start = self.data.len().saturating_sub(max);
        self.data[start..].to_vec()
    }
}

struct ProcShared {
    id: String,
    command: String,
    cwd: Option<String>,
    pid: u32,
    started_unix_ms: i64,
    started: Instant,
    stdout: Arc<Mutex<OutputBuf>>,
    stderr: Arc<Mutex<OutputBuf>>,
    exit_code: Mutex<Option<i32>>,
    running: AtomicBool,
    killed: AtomicBool,
    #[allow(dead_code)]
    origin: Origin,
    agent: Option<String>,
    audit: Arc<AuditService>,
}

struct Slot {
    shared: Arc<ProcShared>,
    kill: Mutex<Option<oneshot::Sender<()>>>,
}

struct ProcState {
    slots: HashMap<String, Slot>,
}

impl Drop for ProcState {
    fn drop(&mut self) {
        for (_, slot) in self.slots.drain() {
            slot.shared.killed.store(true, Ordering::SeqCst);
            if let Ok(mut kill) = slot.kill.lock() {
                if let Some(tx) = kill.take() {
                    let _ = tx.send(());
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct ProcManager {
    state: Arc<Mutex<ProcState>>,
}

impl Default for ProcManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ProcState {
                slots: HashMap::new(),
            })),
        }
    }

    pub async fn start(
        &self,
        origin: &Origin,
        audit: Arc<AuditService>,
        agent: Option<String>,
        program: &str,
        args: &[String],
        cwd: Option<&std::path::Path>,
        cwd_display: Option<String>,
        env: &[(String, String)],
        shell: bool,
        stdin: Option<&[u8]>,
    ) -> Result<(Value, ProcessAudit)> {
        self.reap();
        {
            let guard = self.lock()?;
            let running = guard
                .slots
                .values()
                .filter(|slot| slot.shared.running.load(Ordering::SeqCst))
                .count();
            if running >= MAX_PROCS {
                return Err(Error::Message(format!(
                    "this node already has {MAX_PROCS} background processes"
                )));
            }
        }
        let command = command_line(program, args, shell);
        let mut cmd = if shell {
            prepare_shell_command(program, cwd, env)?
        } else {
            prepare_command(program, args, cwd, env)?
        };
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let mut grouped = spawn_grouped_program(program, &mut cmd)?;
        if let Some(bytes) = stdin {
            let mut child_stdin = grouped
                .child
                .inner()
                .stdin
                .take()
                .ok_or_else(|| Error::Message("stdin missing".into()))?;
            use tokio::io::AsyncWriteExt;
            child_stdin.write_all(bytes).await.map_err(Error::Io)?;
            child_stdin.shutdown().await.map_err(Error::Io)?;
        }
        let stdout = grouped
            .child
            .inner()
            .stdout
            .take()
            .ok_or_else(|| Error::Message("stdout missing".into()))?;
        let stderr = grouped
            .child
            .inner()
            .stderr
            .take()
            .ok_or_else(|| Error::Message("stderr missing".into()))?;
        let id = self.alloc_id()?;
        let stdout_buf = Arc::new(Mutex::new(OutputBuf::new()));
        let stderr_buf = Arc::new(Mutex::new(OutputBuf::new()));
        let shared = Arc::new(ProcShared {
            id: id.clone(),
            command: command.clone(),
            cwd: cwd_display.clone(),
            pid: grouped.pid,
            started_unix_ms: now_ms(),
            started: Instant::now(),
            stdout: stdout_buf.clone(),
            stderr: stderr_buf.clone(),
            exit_code: Mutex::new(None),
            running: AtomicBool::new(true),
            killed: AtomicBool::new(false),
            origin: origin.clone(),
            agent,
            audit,
        });
        spawn_reader(stdout, stdout_buf);
        spawn_reader(stderr, stderr_buf);
        let (kill_tx, kill_rx) = oneshot::channel();
        {
            let mut guard = self.lock()?;
            guard.slots.insert(
                id.clone(),
                Slot {
                    shared: shared.clone(),
                    kill: Mutex::new(Some(kill_tx)),
                },
            );
        }
        let task_shared = shared.clone();
        tokio::spawn(async move {
            let code = tokio::select! {
                _ = kill_rx => {
                    // kill() already waits; read the cached status so agents see
                    // a real exit_code instead of permanent null.
                    kill_group(&mut grouped.child).await;
                    match grouped.child.wait().await {
                        Ok(status) => exit_code_from_status(status),
                        Err(_) => Some(137),
                    }
                }
                result = grouped.child.wait() => {
                    result.ok().and_then(exit_code_from_status)
                }
            };
            if let Ok(mut slot) = task_shared.exit_code.lock() {
                if slot.is_none() {
                    *slot = code;
                }
            }
            task_shared.running.store(false, Ordering::SeqCst);
            if !task_shared.killed.load(Ordering::SeqCst) {
                log_natural_exit(&task_shared, code);
            }
        });
        let body = describe(&shared);
        let audit = ProcessAudit::new(command, cwd_display, None, "");
        Ok((body, audit))
    }

    pub fn list(&self) -> Result<Value> {
        let guard = self.lock()?;
        let mut processes: Vec<_> = guard
            .slots
            .values()
            .map(|slot| describe(&slot.shared))
            .collect();
        processes.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        Ok(json!({"processes": processes}))
    }

    pub fn output(
        &self,
        id: &str,
        stdout_cursor: u64,
        stderr_cursor: u64,
        max_bytes: u32,
    ) -> Result<(Value, ProcessAudit)> {
        let max = if max_bytes == 0 {
            65_536
        } else {
            (max_bytes as usize).min(1024 * 1024)
        };
        let guard = self.lock()?;
        let slot = guard
            .slots
            .get(id)
            .ok_or_else(|| Error::NotFound(format!("background process {id}")))?;
        let (stdout_next, stdout, stdout_gap) =
            lock_buf(&slot.shared.stdout)?.read_from(stdout_cursor, max);
        let (stderr_next, stderr, stderr_gap) =
            lock_buf(&slot.shared.stderr)?.read_from(stderr_cursor, max);
        let running = slot.shared.running.load(Ordering::SeqCst);
        let exit_code = *lock_exit(&slot.shared)?;
        let body = json!({
            "id": id,
            "running": running,
            "exit_code": exit_code,
            "stdout": decode_text(&stdout),
            "stderr": decode_text(&stderr),
            "stdout_cursor": stdout_next,
            "stderr_cursor": stderr_next,
            "stdout_gap": stdout_gap,
            "stderr_gap": stderr_gap,
        });
        let process = ProcessAudit::new(
            slot.shared.command.clone(),
            slot.shared.cwd.clone(),
            exit_code,
            &audit::combine_output(&stdout, &stderr),
        );
        Ok((body, process))
    }

    pub fn status(&self, id: &str) -> Result<(Value, ProcessAudit)> {
        let guard = self.lock()?;
        let slot = guard
            .slots
            .get(id)
            .ok_or_else(|| Error::NotFound(format!("background process {id}")))?;
        let body = describe(&slot.shared);
        let (stdout, stderr, exit_code) = snapshot_tail(&slot.shared)?;
        let process = ProcessAudit::new(
            slot.shared.command.clone(),
            slot.shared.cwd.clone(),
            exit_code,
            &audit::combine_output(&stdout, &stderr),
        );
        Ok((body, process))
    }

    pub async fn kill(&self, id: &str) -> Result<(Value, ProcessAudit)> {
        let (shared, kill_tx) = {
            let guard = self.lock()?;
            let slot = guard
                .slots
                .get(id)
                .ok_or_else(|| Error::NotFound(format!("background process {id}")))?;
            let tx = slot
                .kill
                .lock()
                .map_err(|_| Error::Message("kill lock poisoned".into()))?
                .take();
            (slot.shared.clone(), tx)
        };
        shared.killed.store(true, Ordering::SeqCst);
        if let Some(tx) = kill_tx {
            let _ = tx.send(());
            let deadline = Instant::now() + Duration::from_secs(5);
            while shared.running.load(Ordering::SeqCst) && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        let (stdout, stderr, exit_code) = snapshot_tail(&shared)?;
        let body = describe(&shared);
        let process = ProcessAudit::new(
            shared.command.clone(),
            shared.cwd.clone(),
            exit_code,
            &audit::combine_output(&stdout, &stderr),
        );
        Ok((body, process))
    }

    fn alloc_id(&self) -> Result<String> {
        let guard = self.lock()?;
        for _ in 0..8 {
            let candidate = util::random_hex(4);
            if !guard.slots.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(Error::Message("could not allocate a process id".into()))
    }

    fn reap(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.slots.retain(|_, slot| {
                slot.shared.running.load(Ordering::SeqCst)
                    || slot.shared.started.elapsed() < KEEP_EXITED
            });
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ProcState>> {
        self.state
            .lock()
            .map_err(|_| Error::Message("process map poisoned".into()))
    }
}

fn spawn_reader<R>(mut reader: R, buf: Arc<Mutex<OutputBuf>>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut tmp = [0u8; 8192];
        loop {
            match reader.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut guard) = buf.lock() {
                        guard.append(&tmp[..n]);
                    }
                }
            }
        }
    });
}

fn describe(shared: &ProcShared) -> Value {
    let exit_code = shared.exit_code.lock().ok().and_then(|guard| *guard);
    let stdout_end = shared.stdout.lock().map(|buf| buf.end()).unwrap_or(0);
    let stderr_end = shared.stderr.lock().map(|buf| buf.end()).unwrap_or(0);
    json!({
        "id": shared.id,
        "pid": shared.pid,
        "command": shared.command,
        "cwd": shared.cwd,
        "running": shared.running.load(Ordering::SeqCst),
        "killed": shared.killed.load(Ordering::SeqCst),
        "exit_code": exit_code,
        "started_unix_ms": shared.started_unix_ms,
        "stdout_cursor": stdout_end,
        "stderr_cursor": stderr_end,
    })
}

/// Map an OS exit status to an i32 agents can poll.
///
/// Unix signal deaths have no `code()`; use the conventional `128 + signal`
/// (e.g. SIGKILL → 137) so `bg kill` does not leave `exit_code: null`.
fn exit_code_from_status(status: std::process::ExitStatus) -> Option<i32> {
    if let Some(code) = status.code() {
        return Some(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Some(128 + sig);
        }
    }
    None
}

fn snapshot_tail(shared: &ProcShared) -> Result<(Vec<u8>, Vec<u8>, Option<i32>)> {
    let stdout = lock_buf(&shared.stdout)?.tail(audit::OUTPUT_CAP);
    let stderr = lock_buf(&shared.stderr)?.tail(audit::OUTPUT_CAP);
    let exit_code = *lock_exit(shared)?;
    Ok((stdout, stderr, exit_code))
}

fn lock_buf(buf: &Mutex<OutputBuf>) -> Result<std::sync::MutexGuard<'_, OutputBuf>> {
    buf.lock()
        .map_err(|_| Error::Message("output lock poisoned".into()))
}

fn lock_exit(shared: &ProcShared) -> Result<std::sync::MutexGuard<'_, Option<i32>>> {
    shared
        .exit_code
        .lock()
        .map_err(|_| Error::Message("exit lock poisoned".into()))
}

fn decode_text(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => json!({"encoding": "utf-8", "text": text}),
        Err(_) => json!({
            "encoding": "base64",
            "base64": agentlink_core::util::b64_encode(bytes),
        }),
    }
}

fn log_natural_exit(shared: &ProcShared, code: Option<i32>) {
    let stdout = shared
        .stdout
        .lock()
        .map(|buf| buf.tail(audit::OUTPUT_CAP))
        .unwrap_or_default();
    let stderr = shared
        .stderr
        .lock()
        .map(|buf| buf.tail(audit::OUTPUT_CAP))
        .unwrap_or_default();
    let mut event = audit::event_for(
        "background",
        "bg_exit",
        shared.agent.as_deref().unwrap_or(""),
        &shared.command,
        json!({
            "id": shared.id,
            "command": shared.command,
            "detail": shared.command,
            "pid": shared.pid,
        }),
        true,
        None,
        shared.started.elapsed(),
    );
    event.command = Some(shared.command.clone());
    event.cwd = shared.cwd.clone();
    event.exit_code = code;
    event.stdout = Some(stdout);
    event.stderr = Some(stderr);
    shared.audit.submit(event);
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_command_rejects_whitespace_only() {
        let err = prepare_command("   ", &[], None, &[]).unwrap_err().to_string();
        assert!(err.contains("command is empty"), "{err}");
        let err = prepare_command("\t\n ", &[], None, &[]).unwrap_err().to_string();
        assert!(err.contains("command is empty"), "{err}");
        let err = prepare_command("", &[], None, &[]).unwrap_err().to_string();
        assert!(err.contains("command is empty"), "{err}");
        assert!(prepare_command("sh", &["-c".into(), "true".into()], None, &[]).is_ok());
    }


    #[test]
    fn grouped_spawn_uses_create_no_window_not_detached() {
        // command-group ORs CREATE_SUSPENDED onto this value. DETACHED_PROCESS
        // must stay clear or Windows drops CREATE_NO_WINDOW.
        assert_eq!(agentlink_core::process::WINDOWS_NO_WINDOW, 0x0800_0000);
        assert_eq!(agentlink_core::process::WINDOWS_NO_WINDOW & 0x8, 0);
    }

    #[test]
    fn finish_command_rejects_missing_cwd() {
        let mut cmd = tokio::process::Command::new("true"); // no-window-reviewed
        let err = finish_command(&mut cmd, Some(std::path::Path::new("/no/such/agentlink-cwd")), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("cwd /no/such/agentlink-cwd"), "{err}");
        assert!(
            err.contains("No such file") || err.contains("os error 2") || err.contains("cannot find"),
            "{err}"
        );
    }

    #[test]
    fn diagnose_spawn_names_missing_path_like_program() {
        let err = diagnose_spawn(
            "./missing-relative",
            std::io::Error::from(std::io::ErrorKind::NotFound),
        )
        .to_string();
        assert!(err.contains("./missing-relative"), "{err}");
        assert!(err.contains("not found"), "{err}");
        assert!(!err.contains("on PATH"), "{err}");

        let err = diagnose_spawn(
            "C:\\tools\\missing.exe",
            std::io::Error::from(std::io::ErrorKind::NotFound),
        )
        .to_string();
        assert!(err.contains("C:\\tools\\missing.exe"), "{err}");
        assert!(err.contains("not found"), "{err}");
        assert!(!err.contains("on PATH"), "{err}");
    }

    #[test]
    fn diagnose_spawn_names_missing_bare_program_on_path() {
        let err = diagnose_spawn(
            "definitely-not-a-real-bin-xyz",
            std::io::Error::from(std::io::ErrorKind::NotFound),
        )
        .to_string();
        assert!(err.contains("definitely-not-a-real-bin-xyz"), "{err}");
        assert!(err.contains("not found on PATH"), "{err}");
    }

    #[test]
    fn diagnose_spawn_keeps_spawn_prefix_for_other_errors() {
        let err = diagnose_spawn(
            "sh",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        )
        .to_string();
        assert!(err.starts_with("spawn: "), "{err}");
        assert!(!err.contains("not found on PATH"), "{err}");
    }

    #[tokio::test]
    async fn spawn_grouped_program_tips_missing_binary() {
        let mut cmd = tokio::process::Command::new("definitely-not-a-real-bin-xyz"); // no-window-reviewed
        let err = spawn_grouped_program("definitely-not-a-real-bin-xyz", &mut cmd)
            .err()
            .expect("spawn of a missing binary must fail")
            .to_string();
        assert!(err.contains("not found on PATH"), "{err}");
    }

    #[test]
    fn command_line_quotes_args_with_spaces() {
        let line = command_line(
            "bash",
            &["-lc".into(), "echo HELLO; sleep 1".into()],
            false,
        );
        assert_eq!(line, "bash -lc 'echo HELLO; sleep 1'");
    }

    #[test]
    fn command_line_leaves_simple_argv_unquoted() {
        let line = command_line("/bin/echo", &["quoted-ok".into()], false);
        assert_eq!(line, "/bin/echo quoted-ok");
    }

    #[test]
    fn output_cursor_reports_a_gap_after_truncation() {
        let mut buf = OutputBuf::new();
        buf.append(&vec![b'a'; OUTPUT_MEM + 10]);
        assert!(buf.start > 0);
        let (cursor, data, gap) = buf.read_from(0, 4);
        assert!(gap);
        assert_eq!(data.len(), 4);
        assert_eq!(cursor, buf.start + 4);
    }

    #[test]
    #[cfg(windows)]
    fn windows_cmd_c_raw_preserves_user_quotes() {
        assert_eq!(
            windows_cmd_c_raw(r#"echo "hello""#),
            r#"/C "echo "hello"""#
        );
        assert_eq!(
            windows_cmd_c_raw(r#"dir "%TEMP%""#),
            r#"/C "dir "%TEMP%"""#
        );
    }

    #[tokio::test]
    async fn bg_kill_records_exit_code_and_killed_flag() {
        let dir = tempfile::tempdir().unwrap();
        let audit = crate::pipeline::AuditService::open(dir.path(), "local", "local");
        let mgr = ProcManager::new();
        let origin = crate::audit::Origin {
            path: dir.path().to_path_buf(),
            node: "test".into(),
            node_id: "test".into(),
        };
        let (body, _) = mgr
            .start(
                &origin,
                audit,
                Some("agent".into()),
                "sleep",
                &["30".into()],
                None,
                None,
                &[],
                false,
                None,
            )
            .await
            .unwrap();
        let id = body["id"].as_str().unwrap().to_string();
        assert_eq!(body["running"], true);

        let (killed_body, _) = mgr.kill(&id).await.unwrap();
        assert_eq!(killed_body["running"], false, "{killed_body}");
        assert_eq!(killed_body["killed"], true, "{killed_body}");
        assert!(
            killed_body["exit_code"].as_i64().is_some(),
            "exit_code must be set after kill, got {killed_body}"
        );

        let (status_body, _) = mgr.status(&id).unwrap();
        assert_eq!(status_body["killed"], true);
        assert!(status_body["exit_code"].as_i64().is_some(), "{status_body}");
    }

    #[test]
    #[cfg(unix)]
    fn exit_code_from_status_maps_success() {
        assert_eq!(
            exit_code_from_status(std::process::Command::new("/bin/true").status().unwrap()), // no-window-reviewed
            Some(0)
        );
        assert_eq!(
            exit_code_from_status(std::process::Command::new("/bin/false").status().unwrap()), // no-window-reviewed
            Some(1)
        );
    }

    async fn kill_group_stops_grandchildren() {

        let dir = tempfile::tempdir().unwrap();
        let started = dir.path().join("started");
        let leaked = dir.path().join("leaked");
        let mut cmd = grandchild_command(&started, &leaked);
        let mut child = spawn_grouped(&mut cmd).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !started.exists() {
            if Instant::now() > deadline {
                kill_group(&mut child.child).await;
                panic!("grandchild never started");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        kill_group(&mut child.child).await;
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(
            !leaked.exists(),
            "grandchild kept running after the process group was killed"
        );
    }

    fn grandchild_command(
        started: &std::path::Path,
        leaked: &std::path::Path,
    ) -> tokio::process::Command {
        #[cfg(unix)]
        {
            let script = format!(
                "(echo started > '{}'; sleep 3; echo leaked > '{}') & sleep 30",
                started.display(),
                leaked.display()
            );
            let mut cmd = tokio::process::Command::new("sh"); // no-window-reviewed
            cmd.arg("-c").arg(script);
            cmd
        }
        #[cfg(windows)]
        {
            let child = started.parent().unwrap().join("child.bat");
            let parent = started.parent().unwrap().join("parent.bat");
            std::fs::write(
                &child,
                format!(
                    "@echo off\r\necho started> \"{}\"\r\nping -n 6 127.0.0.1 >NUL\r\necho leaked> \"{}\"\r\n",
                    started.display(),
                    leaked.display()
                ),
            )
            .unwrap();
            std::fs::write(
                &parent,
                format!(
                    "@echo off\r\nstart \"\" /b cmd /c \"{}\"\r\nping -n 30 127.0.0.1 >NUL\r\n",
                    child.display()
                ),
            )
            .unwrap();
            let mut cmd = tokio::process::Command::new("cmd"); // no-window-reviewed
            cmd.arg("/C").arg(&parent);
            cmd
        }
    }
}
