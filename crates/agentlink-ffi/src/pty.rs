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

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use agentlink_core::{Error, Result};

pub type PtyGrantHook = Arc<dyn Fn(&str) -> bool + Send + Sync>;

pub enum PtyPoll {
    Pending,
    Chunk(Vec<u8>),
    Exit(i32),
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

    pub struct Live {
        master: Arc<Mutex<File>>,
        writer: Arc<Mutex<File>>,
        pid: i32,
        chunks: Arc<Mutex<VecDeque<Vec<u8>>>>,
        exit_code: Arc<Mutex<Option<i32>>>,
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
                if libc::chdir(cwd_c.as_ptr()) != 0 {
                    libc::_exit(127);
                }
                libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        unsafe {
            libc::close(slave_fd);
            libc::fcntl(master_fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        let master_file = unsafe { File::from_raw_fd(master_fd) };
        let reader = master_file
            .try_clone()
            .map_err(|e| Error::Message(format!("pty reader: {e}")))?;
        let writer = master_file
            .try_clone()
            .map_err(|e| Error::Message(format!("pty writer: {e}")))?;
        let chunks = Arc::new(Mutex::new(VecDeque::new()));
        let exit_code = Arc::new(Mutex::new(None));
        let reader_done = Arc::new(AtomicBool::new(false));
        {
            let chunks = chunks.clone();
            let reader_done = reader_done.clone();
            thread::Builder::new()
                .name("agentlink-pty-read".into())
                .spawn(move || {
                    let mut reader = reader;
                    let mut buf = [0u8; 4096];
                    loop {
                        match reader.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if let Ok(mut queue) = chunks.lock() {
                                    queue.push_back(buf[..n].to_vec());
                                }
                            }
                        }
                    }
                    reader_done.store(true, Ordering::SeqCst);
                })
                .map_err(|e| Error::Message(format!("pty reader thread: {e}")))?;
        }
        {
            let exit_code = exit_code.clone();
            thread::Builder::new()
                .name("agentlink-pty-wait".into())
                .spawn(move || {
                    let mut status: libc::c_int = 0;
                    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
                    let code = if waited < 0 {
                        -1
                    } else if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else {
                        -1
                    };
                    while !reader_done.load(Ordering::SeqCst) {
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
            chunks,
            exit_code,
        })
    }

    pub fn poll(sessions: &Mutex<HashMap<String, Session>>, session_id: &str) -> PtyPoll {
        let Ok(sessions) = sessions.lock() else {
            return PtyPoll::Exit(-1);
        };
        let Some(session) = sessions.get(session_id) else {
            return PtyPoll::Exit(-1);
        };
        if let Ok(mut queue) = session.live.chunks.lock() {
            if let Some(chunk) = queue.pop_front() {
                return PtyPoll::Chunk(chunk);
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
        unsafe {
            libc::kill(-live.pid, libc::SIGHUP);
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

