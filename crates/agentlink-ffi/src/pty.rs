//! App-sandbox shell on a real PTY.
//!
//! Unix, including Android, calls `openpty` from libc (the NDK libc on a
//! phone). The child is a session leader with `TERM=xterm-256color`, and
//! `TIOCSWINSZ` updates the size. Shizuku and `su` stay on the one-shot exec
//! path: those processes are started outside this address space and do not
//! inherit this master.
//!
//! `portable-pty` is not used here. Its `termios` dependency does not compile
//! for `target_os = "android"`.

use std::collections::BTreeSet;
#[cfg(unix)]
use std::collections::{HashMap, VecDeque};
use std::path::Path;
#[cfg(unix)]
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};

use agentlink_core::{Error, Result};

pub type PtyGrantHook = Arc<dyn Fn(&str) -> bool + Send + Sync>;

#[allow(dead_code)]
pub enum PtyPoll {
    Pending,
    Chunk(Vec<u8>),
    Exit(i32),
    Error(String),
}

#[cfg(unix)]
struct Session {
    live: unix::Live,
    owner_peer: String,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
}

#[derive(Default)]
pub struct PhonePty {
    #[cfg(unix)]
    sessions: Mutex<HashMap<String, Session>>,
    grant_active: Arc<RwLock<Option<PtyGrantHook>>>,
}

impl PhonePty {
    pub fn set_grant_active(&self, hook: Option<PtyGrantHook>) {
        if let Ok(mut slot) = self.grant_active.write() {
            *slot = hook;
        }
    }

    #[cfg(unix)]
    fn grant_hook(&self) -> Option<PtyGrantHook> {
        self.grant_active.read().ok().and_then(|guard| guard.clone())
    }

    pub fn open(
        &self,
        command: Option<&str>,
        rows: u16,
        cols: u16,
        cwd: &Path,
        owner_peer: &str,
        grant_jti: &str,
        grant_exp_unix: Option<i64>,
    ) -> Result<String> {
        let session_id = uuid::Uuid::new_v4().to_string();
        #[cfg(unix)]
        {
            let live = unix::spawn(command, rows.max(1), cols.max(1), cwd)?;
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| Error::Message("pty map poisoned".into()))?;
            if let Some(previous) = sessions.insert(
                session_id.clone(),
                Session {
                    live,
                    owner_peer: owner_peer.to_string(),
                    grant_jti: grant_jti.trim().to_string(),
                    grant_exp_unix,
                },
            ) {
                unix::kill_live(previous.live);
            }
            Ok(session_id)
        }
        #[cfg(not(unix))]
        {
            let _ = (command, rows, cols, cwd, owner_peer, grant_jti, grant_exp_unix);
            let _ = session_id;
            Err(Error::Message("pty is only built for unix".into()))
        }
    }

    pub fn check_session(&self, session_id: &str, peer: Option<&str>) -> Result<()> {
        #[cfg(unix)]
        {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_| Error::Message("pty map poisoned".into()))?;
            let live = sessions
                .get(session_id)
                .ok_or_else(|| Error::NotFound(format!("pty session {session_id}")))?;
            require_pty_access(live, peer, self.grant_hook().as_deref())
        }
        #[cfg(not(unix))]
        {
            let _ = (session_id, peer);
            Err(Error::Message("pty is only built for unix".into()))
        }
    }

    pub fn poll(&self, session_id: &str) -> PtyPoll {
        #[cfg(unix)]
        {
            unix::poll(&self.sessions, session_id)
        }
        #[cfg(not(unix))]
        {
            let _ = session_id;
            PtyPoll::Exit(-1)
        }
    }

    pub fn write(&self, session_id: &str, data: &[u8], peer: Option<&str>) -> Result<()> {
        #[cfg(unix)]
        {
            self.check_session(session_id, peer)?;
            unix::write(&self.sessions, session_id, data)
        }
        #[cfg(not(unix))]
        {
            let _ = (session_id, data, peer);
            Err(Error::Message("pty is only built for unix".into()))
        }
    }

    pub fn resize(&self, session_id: &str, rows: u16, cols: u16, peer: Option<&str>) -> Result<()> {
        #[cfg(unix)]
        {
            self.check_session(session_id, peer)?;
            unix::resize(&self.sessions, session_id, rows.max(1), cols.max(1))
        }
        #[cfg(not(unix))]
        {
            let _ = (session_id, rows, cols, peer);
            Err(Error::Message("pty is only built for unix".into()))
        }
    }

    pub fn close(&self, session_id: &str, peer: Option<&str>) -> Result<()> {
        #[cfg(unix)]
        {
            let removed = {
                let mut sessions = self
                    .sessions
                    .lock()
                    .map_err(|_| Error::Message("pty map poisoned".into()))?;
                if let Some(existing) = sessions.get(session_id) {
                    require_pty_owner(&existing.owner_peer, peer)?;
                }
                sessions.remove(session_id)
            };
            if let Some(session) = removed {
                unix::kill_live(session.live);
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (session_id, peer);
            Ok(())
        }
    }

    /// Close sessions whose stored grant is expired or revoked. Walks live
    /// metadata; this is not keyed off an inflight RPC index.
    pub fn close_inactive(&self, revoked: &BTreeSet<String>) -> usize {
        #[cfg(unix)]
        {
            let hook = self.grant_hook();
            let now = agentlink_core::util::unix_now();
            let victims = {
                let mut sessions = match self.sessions.lock() {
                    Ok(guard) => guard,
                    Err(_) => return 0,
                };
                let ids: Vec<String> = sessions
                    .iter()
                    .filter(|(_, session)| {
                        pty_session_inactive(session, revoked, hook.as_deref(), now)
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                ids.into_iter()
                    .filter_map(|id| sessions.remove(&id))
                    .collect::<Vec<_>>()
            };
            let n = victims.len();
            for session in victims {
                unix::kill_live(session.live);
            }
            n
        }
        #[cfg(not(unix))]
        {
            let _ = revoked;
            0
        }
    }

    pub fn close_all(&self) {
        #[cfg(unix)]
        {
            let sessions = match self.sessions.lock() {
                Ok(mut guard) => std::mem::take(&mut *guard),
                Err(poison) => std::mem::take(&mut *poison.into_inner()),
            };
            for (_, session) in sessions {
                unix::kill_live(session.live);
            }
        }
    }
}

#[cfg(unix)]
fn require_pty_owner(owner_peer: &str, peer: Option<&str>) -> Result<()> {
    if let Some(peer) = peer {
        if owner_peer != peer {
            return Err(Error::NotFound(
                "pty session not found for this peer".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_pty_access(
    session: &Session,
    peer: Option<&str>,
    hook: Option<&(dyn Fn(&str) -> bool + Send + Sync)>,
) -> Result<()> {
    require_pty_owner(&session.owner_peer, peer)?;
    if let Some(exp) = session.grant_exp_unix {
        if agentlink_core::util::unix_now() >= exp {
            return Err(Error::Auth("grant expired".into()));
        }
    }
    if let Some(hook) = hook {
        let jti = session.grant_jti.trim();
        if jti.is_empty() {
            return Err(Error::Auth("grant is required".into()));
        }
        if !hook(jti) {
            return Err(Error::Auth("grant was revoked".into()));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn pty_session_inactive(
    session: &Session,
    revoked: &BTreeSet<String>,
    hook: Option<&(dyn Fn(&str) -> bool + Send + Sync)>,
    now: i64,
) -> bool {
    if session.grant_exp_unix.is_some_and(|exp| now >= exp) {
        return true;
    }
    let jti = session.grant_jti.trim();
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

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Condvar;

    const MAX_QUEUE_BYTES: usize = 2 * 1024 * 1024;
    const DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
    const BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(5);
    const SIGHUP_GRACE: Duration = Duration::from_millis(400);

    struct ChunkQueue {
        chunks: VecDeque<Vec<u8>>,
        bytes: usize,
        overflowed: bool,
    }

    pub struct Live {
        master: Arc<Mutex<File>>,
        writer: Arc<Mutex<File>>,
        pid: i32,
        queue: Arc<(Mutex<ChunkQueue>, Condvar)>,
        exit_code: Arc<Mutex<Option<i32>>>,
        closed: Arc<AtomicBool>,
        reap_state: Arc<(Mutex<bool>, Condvar)>,
    }

    pub fn spawn(command: Option<&str>, rows: u16, cols: u16, cwd: &Path) -> Result<Live> {
        let shell = default_shell();
        let program = CString::new(shell.clone())
            .map_err(|_| Error::Message("shell path contains a null".into()))?;
        let mut owned = vec![program.clone()];
        if let Some(line) = command.map(str::trim).filter(|line| !line.is_empty()) {
            owned.push(CString::new("-c").unwrap());
            owned.push(
                CString::new(line).map_err(|_| Error::Message("command contains a null".into()))?,
            );
        }
        let mut argv: Vec<*const libc::c_char> = owned.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());
        let env_owned = env_block()?;
        let mut envp: Vec<*const libc::c_char> = env_owned.iter().map(|s| s.as_ptr()).collect();
        envp.push(std::ptr::null());
        let cwd_c = c_path(cwd)?;

        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;
        let mut size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // macOS declares the termios argument as `*mut`; Linux declares it as
        // `*const`. A null `*mut` coerces to `*const`.
        let termios: *mut libc::termios = std::ptr::null_mut();
        let rc = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                termios,
                &mut size,
            )
        };
        if rc != 0 {
            return Err(Error::Message(format!(
                "openpty: {}",
                std::io::Error::last_os_error()
            )));
        }
        // Set FD_CLOEXEC immediately after openpty so concurrent forks in other
        // threads never inherit master_fd or slave_fd. In the child, login_tty
        // dup2s slave_fd to 0/1/2 (clearing CLOEXEC on 0/1/2) and closes slave_fd.
        unsafe {
            libc::fcntl(master_fd, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(slave_fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
        let close_limit = if max_fd > 3 {
            (max_fd as libc::c_int).min(4096)
        } else {
            1024
        };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe {
                libc::close(master_fd);
                libc::close(slave_fd);
            }
            return Err(Error::Message(format!(
                "pty fork: {}",
                std::io::Error::last_os_error()
            )));
        }
        if pid == 0 {
            unsafe {
                libc::close(master_fd);
                if libc::login_tty(slave_fd) != 0 {
                    libc::_exit(127);
                }
                for fd in 3..close_limit {
                    libc::close(fd);
                }
                if libc::chdir(cwd_c.as_ptr()) != 0 {
                    libc::_exit(127);
                }
                libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        unsafe {
            libc::close(slave_fd);
        }
        let master_file = unsafe { File::from_raw_fd(master_fd) };
        let reader = master_file
            .try_clone()
            .map_err(|e| Error::Message(format!("pty reader: {e}")))?;
        let writer = master_file
            .try_clone()
            .map_err(|e| Error::Message(format!("pty writer: {e}")))?;
        let queue = Arc::new((
            Mutex::new(ChunkQueue {
                chunks: VecDeque::new(),
                bytes: 0,
                overflowed: false,
            }),
            Condvar::new(),
        ));
        let exit_code = Arc::new(Mutex::new(None));
        let reader_done = Arc::new(AtomicBool::new(false));
        let closed = Arc::new(AtomicBool::new(false));
        let reap_state = Arc::new((Mutex::new(false), Condvar::new()));
        {
            let queue = queue.clone();
            let reader_done = reader_done.clone();
            let closed = closed.clone();
            thread::Builder::new()
                .name("agentlink-pty-read".into())
                .spawn(move || {
                    let mut reader = reader;
                    let mut buf = [0u8; 4096];
                    loop {
                        if closed.load(Ordering::SeqCst) {
                            break;
                        }
                        match reader.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let (lock, cvar) = &*queue;
                                let mut guard = match lock.lock() {
                                    Ok(g) => g,
                                    Err(_) => break,
                                };
                                let deadline = Instant::now() + BACKPRESSURE_TIMEOUT;
                                while guard.bytes.saturating_add(n) > MAX_QUEUE_BYTES
                                    && !closed.load(Ordering::SeqCst)
                                {
                                    let Some(rem) =
                                        deadline.checked_duration_since(Instant::now())
                                    else {
                                        guard.overflowed = true;
                                        break;
                                    };
                                    guard = match cvar.wait_timeout(guard, rem) {
                                        Ok((g, _)) => g,
                                        Err(poison) => {
                                            let mut g = poison.into_inner().0;
                                            g.overflowed = true;
                                            g
                                        }
                                    };
                                    if guard.overflowed {
                                        break;
                                    }
                                }
                                if closed.load(Ordering::SeqCst) || guard.overflowed {
                                    break;
                                }
                                guard.bytes = guard.bytes.saturating_add(n);
                                guard.chunks.push_back(buf[..n].to_vec());
                            }
                        }
                    }
                    reader_done.store(true, Ordering::SeqCst);
                })
                .map_err(|e| Error::Message(format!("pty reader thread: {e}")))?;
        }
        {
            let exit_code = exit_code.clone();
            let closed = closed.clone();
            let reap_state = reap_state.clone();
            thread::Builder::new()
                .name("agentlink-pty-wait".into())
                .spawn(move || {
                    let code = loop {
                        let mut status: libc::c_int = 0;
                        let (lock, cvar) = &*reap_state;
                        let mut reaped = match lock.lock() {
                            Ok(g) => g,
                            Err(p) => p.into_inner(),
                        };
                        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                        if waited > 0 {
                            *reaped = true;
                            cvar.notify_all();
                            break if libc::WIFEXITED(status) {
                                libc::WEXITSTATUS(status)
                            } else {
                                -1
                            };
                        }
                        if waited < 0 {
                            *reaped = true;
                            cvar.notify_all();
                            break -1;
                        }
                        let _ = cvar.wait_timeout(reaped, Duration::from_millis(20));
                    };
                    let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
                    while !reader_done.load(Ordering::SeqCst)
                        && !closed.load(Ordering::SeqCst)
                        && Instant::now() < drain_deadline
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    if let Ok(mut slot) = exit_code.lock() {
                        *slot = Some(code);
                    }
                })
                .map_err(|e| Error::Message(format!("pty wait thread: {e}")))?;
        }
        Ok(Live {
            master: Arc::new(Mutex::new(master_file)),
            writer: Arc::new(Mutex::new(writer)),
            pid,
            queue,
            exit_code,
            closed,
            reap_state,
        })
    }

    pub fn poll(sessions: &Mutex<HashMap<String, Session>>, session_id: &str) -> PtyPoll {
        let Ok(sessions) = sessions.lock() else {
            return PtyPoll::Exit(-1);
        };
        let Some(session) = sessions.get(session_id) else {
            return PtyPoll::Exit(-1);
        };
        let (lock, cvar) = &*session.live.queue;
        if let Ok(mut queue) = lock.lock() {
            if let Some(chunk) = queue.chunks.pop_front() {
                queue.bytes = queue.bytes.saturating_sub(chunk.len());
                cvar.notify_all();
                return PtyPoll::Chunk(chunk);
            }
            if queue.overflowed {
                return PtyPoll::Error("pty output queue exceeded limit".into());
            }
        }
        if let Ok(slot) = session.live.exit_code.lock() {
            if let Some(code) = *slot {
                return PtyPoll::Exit(code);
            }
        }
        PtyPoll::Pending
    }

    pub fn write(
        sessions: &Mutex<HashMap<String, Session>>,
        session_id: &str,
        data: &[u8],
    ) -> Result<()> {
        let writer = {
            let sessions = sessions
                .lock()
                .map_err(|_| Error::Message("pty map poisoned".into()))?;
            sessions
                .get(session_id)
                .map(|session| session.live.writer.clone())
                .ok_or_else(|| Error::NotFound(format!("pty session {session_id}")))?
        };
        let mut guard = writer
            .lock()
            .map_err(|_| Error::Message("pty writer poisoned".into()))?;
        guard.write_all(data)?;
        guard.flush()?;
        Ok(())
    }

    pub fn resize(
        sessions: &Mutex<HashMap<String, Session>>,
        session_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<()> {
        let master = {
            let sessions = sessions
                .lock()
                .map_err(|_| Error::Message("pty map poisoned".into()))?;
            sessions
                .get(session_id)
                .map(|session| session.live.master.clone())
                .ok_or_else(|| Error::NotFound(format!("pty session {session_id}")))?
        };
        let guard = master
            .lock()
            .map_err(|_| Error::Message("pty master poisoned".into()))?;
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let rc = unsafe {
            libc::ioctl(
                std::os::fd::AsRawFd::as_raw_fd(&*guard),
                libc::TIOCSWINSZ,
                &size,
            )
        };
        if rc != 0 {
            return Err(Error::Message(format!(
                "pty resize: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    pub fn kill_live(live: Live) {
        live.closed.store(true, Ordering::SeqCst);
        live.queue.1.notify_all();
        let pid = live.pid;
        let reap_state = live.reap_state.clone();
        // Drop master/writer so the child observes EOF/hangup on the PTY.
        drop(live.master);
        drop(live.writer);
        let needs_escalation = {
            let (lock, cvar) = &*reap_state;
            let reaped = match lock.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if *reaped {
                false
            } else {
                unsafe {
                    libc::kill(-(pid as libc::pid_t), libc::SIGHUP);
                }
                cvar.notify_all();
                true
            }
        };
        if needs_escalation {
            let _ = thread::Builder::new()
                .name("agentlink-pty-kill".into())
                .spawn(move || {
                    let (lock, cvar) = &*reap_state;
                    let mut reaped = match lock.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    let deadline = Instant::now() + SIGHUP_GRACE;
                    while !*reaped {
                        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                            break;
                        };
                        reaped = match cvar.wait_timeout(reaped, rem) {
                            Ok((g, _)) => g,
                            Err(p) => p.into_inner().0,
                        };
                    }
                    if !*reaped {
                        unsafe {
                            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                            libc::kill(pid as libc::pid_t, libc::SIGKILL);
                        }
                        cvar.notify_all();
                    }
                });
        }
    }

    fn default_shell() -> String {
        if cfg!(target_os = "android") {
            "/system/bin/sh".into()
        } else {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
        }
    }

    fn env_block() -> Result<Vec<CString>> {
        let mut pairs: Vec<(String, String)> = std::env::vars()
            .filter(|(key, value)| !key.is_empty() && !key.contains('\0') && !value.contains('\0'))
            .collect();
        pairs.retain(|(key, _)| key != "TERM" && key != "LANG");
        pairs.push(("TERM".into(), "xterm-256color".into()));
        pairs.push(("LANG".into(), "C.UTF-8".into()));
        pairs
            .into_iter()
            .map(|(key, value)| {
                CString::new(format!("{key}={value}"))
                    .map_err(|_| Error::Message(format!("rejected env var '{key}'")))
            })
            .collect()
    }

    fn c_path(path: &Path) -> Result<CString> {
        let bytes = OsStr::from_bytes(path.as_os_str().as_bytes());
        CString::new(bytes.as_bytes())
            .map_err(|_| Error::Message("working directory contains a null".into()))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn echo_and_winsize_use_a_real_pty() {
        let dir = tempfile::tempdir().unwrap();
        let pty = PhonePty::default();
        let sid = pty
            .open(
                Some("echo hello-pty; stty size"),
                30,
                90,
                dir.path(),
                "owner",
                "jti-test",
                None,
            )
            .unwrap();
        assert!(uuid::Uuid::parse_str(&sid).is_ok(), "{sid}");
        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let code = loop {
            match pty.poll(&sid) {
                PtyPoll::Chunk(bytes) => out.extend(bytes),
                PtyPoll::Exit(code) => break code,
                PtyPoll::Error(err) => panic!("pty error: {err}"),
                PtyPoll::Pending => {
                    assert!(
                        Instant::now() < deadline,
                        "pty timed out: {}",
                        String::from_utf8_lossy(&out)
                    );
                    thread::sleep(Duration::from_millis(20));
                }
            }
        };
        let text = String::from_utf8_lossy(&out);
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("hello-pty"), "{text}");
        assert!(text.contains("30 90"), "winsize was not applied: {text}");
        pty.close(&sid, Some("owner")).unwrap();
    }

    #[test]
    fn real_pty_entry_enforces_owner_and_revoked_grant() {
        let dir = tempfile::tempdir().unwrap();
        let pty = PhonePty::default();
        let revoked = Arc::new(Mutex::new(BTreeSet::<String>::new()));
        let hook_set = revoked.clone();
        pty.set_grant_active(Some(Arc::new(move |jti: &str| {
            !hook_set
                .lock()
                .map(|set| set.iter().any(|item| item.eq_ignore_ascii_case(jti)))
                .unwrap_or(true)
        })));

        let bob = pty
            .open(
                Some("cat"),
                24,
                80,
                dir.path(),
                "bob",
                "jti-bob",
                Some(agentlink_core::util::unix_now() + 60),
            )
            .unwrap();
        let alice = pty
            .open(
                Some("cat"),
                24,
                80,
                dir.path(),
                "alice",
                "jti-alice",
                Some(agentlink_core::util::unix_now() + 60),
            )
            .unwrap();
        assert!(pty.write(&bob, b"x", Some("alice")).is_err());
        assert!(pty.resize(&bob, 20, 20, Some("alice")).is_err());
        assert!(pty.close(&bob, Some("alice")).is_err());
        pty.write(&bob, b"ok\n", Some("bob")).unwrap();
        pty.write(&alice, b"ok\n", Some("alice")).unwrap();

        revoked.lock().unwrap().insert("jti-bob".into());
        let err = pty.write(&bob, b"no\n", Some("bob")).unwrap_err();
        assert!(
            err.to_string().contains("revoked"),
            "expected revoked grant, got {err}"
        );
        // A revoke of Bob's jti must not take Alice's session with it.
        pty.write(&alice, b"still\n", Some("alice")).unwrap();
        assert_eq!(pty.close_inactive(&BTreeSet::from(["jti-bob".into()])), 1);
        assert!(pty.write(&bob, b"x", Some("bob")).is_err());
        pty.close(&alice, Some("alice")).unwrap();

        let expired = pty
            .open(
                Some("cat"),
                24,
                80,
                dir.path(),
                "bob",
                "jti-exp",
                Some(1),
            )
            .unwrap();
        let err = pty.write(&expired, b"x", Some("bob")).unwrap_err();
        assert!(
            err.to_string().contains("expired"),
            "expected expired grant, got {err}"
        );
        // Expiry is enforced on write; the metadata sweep, not a grant-skipping
        // close, tears the session down.
        assert_eq!(pty.close_inactive(&BTreeSet::new()), 1);
    }
}

