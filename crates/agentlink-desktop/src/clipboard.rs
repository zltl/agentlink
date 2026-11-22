//! Cross-platform clipboard read/write for remote control.
//!
//! Windows uses the Win32 clipboard API (no `clip.exe`, so no console flash).
//! macOS keeps `pbcopy` / `pbpaste`. Linux keeps `wl-copy`/`wl-paste` with an
//! `xclip` fallback — no native Wayland/X dependency in this crate.
//!
//! Remote desktop sessions sync Unicode text both ways, like RDP clipboard
//! redirection: a local copy is written on the node, a remote copy is written
//! on the controller. Image and HTML formats are not advertised or forged.
//! Sharing requires an active remote-control grant in both directions.
//! View-only sessions never inject the controller clipboard into the node,
//! and never write the node's clipboard onto the controller.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::error::{msg, Result};

/// Soft ceiling for a remote clipboard payload. Longer text is truncated.
pub const CLIPBOARD_MAX_CHARS: usize = 1_048_576;

/// Auto-sync skips payloads larger than this many UTF-8 bytes so a huge
/// clipboard cannot saturate the input data channel.
pub const CLIPBOARD_AUTO_MAX_BYTES: usize = 256 * 1024;

/// How often a session may poll the local clipboard for changes.
pub const CLIPBOARD_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Minimum gap between automatic clipboard pushes.
pub const CLIPBOARD_MIN_SEND_INTERVAL: Duration = Duration::from_millis(350);

/// After we write the clipboard, ignore local "changes" for this long so
/// the write does not echo back over the session.
pub const CLIPBOARD_ECHO_SUPPRESS: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardText {
    pub text: String,
    pub truncated: bool,
}

impl ClipboardText {
    pub fn capped(mut text: String) -> Self {
        let truncated = text.chars().count() > CLIPBOARD_MAX_CHARS;
        if truncated {
            text = text.chars().take(CLIPBOARD_MAX_CHARS).collect();
        }
        Self { text, truncated }
    }

    pub fn fingerprint(&self) -> u64 {
        fingerprint(&self.text)
    }

    /// True when auto-sync should refuse to push this payload.
    pub fn too_large_for_auto(&self) -> bool {
        self.text.len() > CLIPBOARD_AUTO_MAX_BYTES
    }
}

pub fn fingerprint(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

pub fn read_clipboard() -> Result<ClipboardText> {
    let text = platform_read()?;
    Ok(ClipboardText::capped(text))
}

pub fn write_clipboard(text: &str) -> Result<()> {
    let capped = ClipboardText::capped(text.to_string());
    platform_write(&capped.text)
}

/// Cheap generation token when the platform can report one without opening
/// the clipboard. `None` means the watcher must read the contents to compare.
pub fn platform_generation() -> Option<u64> {
    #[cfg(target_os = "windows")]
    {
        windows_clip::sequence()
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

/// JSON body pushed on the `input` data channel for a clipboard set.
pub fn set_payload(clip: &ClipboardText) -> Value {
    let mut body = json!({
        "type": "clipboard",
        "text": clip.text,
        "chars": clip.text.chars().count(),
        "fp": format!("{:016x}", clip.fingerprint()),
    });
    if clip.truncated {
        body.as_object_mut()
            .expect("clipboard object")
            .insert("truncated".into(), json!(true));
    }
    body
}

/// Parse a clipboard *set* (or a get-reply that carries text) from the
/// existing `{"type":"clipboard","text":...}` contract. Get requests with no
/// text return `None` so the caller can ignore them on the viewer.
pub fn parse_set_message(value: &Value) -> Option<ClipboardText> {
    let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
    if kind != "clipboard" {
        return None;
    }
    let text = value.get("text").and_then(Value::as_str)?;
    Some(ClipboardText::capped(text.to_string()))
}

/// Loop-suppressing watcher used on both the node and the controller.
#[derive(Debug)]
pub struct ClipboardWatchState {
    last_fp: u64,
    last_sent_fp: u64,
    last_applied_fp: u64,
    last_generation: Option<u64>,
    last_sent_at: Option<Instant>,
    suppress_until: Option<Instant>,
    /// Remember a change we delayed because of the send rate limit.
    pending: bool,
    /// False until the initial local clipboard contents have been observed and
    /// recorded as a baseline. Prevents auto-sync from exfiltrating pre-existing
    /// clipboard secrets (passwords/OTPs/SSH keys) on session connect.
    seeded: bool,
}

impl Default for ClipboardWatchState {
    fn default() -> Self {
        Self::new()
    }
}

impl ClipboardWatchState {
    pub fn new() -> Self {
        Self {
            last_fp: fingerprint(""),
            last_sent_fp: fingerprint(""),
            last_applied_fp: fingerprint(""),
            last_generation: None,
            last_sent_at: None,
            suppress_until: None,
            pending: false,
            seeded: false,
        }
    }

    /// Create a watcher already seeded with the current OS clipboard so
    /// pre-existing secrets are never pushed on connect; only subsequent local
    /// copies will sync.
    pub fn seeded() -> Self {
        let mut state = Self::new();
        state.seed_from_os();
        state
    }

    /// Snapshot the current OS clipboard as the connect-time baseline without
    /// pushing it to the peer.
    pub fn seed_from_os(&mut self) {
        let gen = platform_generation();
        let current = read_clipboard().ok();
        self.seed(current.as_ref().map(|c| c.text.as_str()), gen);
    }

    /// Record the current local clipboard as the connect-time baseline without
    /// pushing it to the peer.
    pub fn seed(&mut self, text: Option<&str>, generation: Option<u64>) {
        if let Some(text) = text {
            self.last_fp = fingerprint(text);
        }
        self.last_generation = generation;
        self.pending = false;
        self.seeded = true;
    }

    /// Record a clipboard we just wrote so the next poll does not echo it.
    pub fn note_applied(&mut self, text: &str) {
        let fp = fingerprint(text);
        self.last_applied_fp = fp;
        self.last_fp = fp;
        self.last_generation = platform_generation();
        self.suppress_until = Some(Instant::now() + CLIPBOARD_ECHO_SUPPRESS);
        self.pending = false;
        self.seeded = true;
    }

    /// Read the local clipboard if it may have changed and return a payload
    /// worth sending. Unchanged, echoed, oversized, or too-frequent updates
    /// are skipped.
    ///
    /// If the watcher was constructed with [`Self::new`] and not yet seeded,
    /// the first poll records the existing clipboard as the baseline and
    /// returns `None` so pre-existing clipboard contents are never leaked on
    /// connect.
    pub fn poll_outgoing(&mut self) -> Option<ClipboardText> {
        self.poll_outgoing_with(Instant::now(), platform_generation, read_clipboard)
    }

    pub(crate) fn poll_outgoing_with<G, R>(
        &mut self,
        now: Instant,
        mut get_gen: G,
        mut read: R,
    ) -> Option<ClipboardText>
    where
        G: FnMut() -> Option<u64>,
        R: FnMut() -> Result<ClipboardText>,
    {
        if !self.seeded {
            let gen = get_gen();
            let current = read().ok();
            self.seed(current.as_ref().map(|c| c.text.as_str()), gen);
            return None;
        }
        // Do NOT advance `last_generation` while echo-suppression is active:
        // a real local copy made during the 500ms suppress window must remain
        // visible to the first poll after `suppress_until` expires.
        if self.suppress_until.is_some_and(|until| now < until) {
            return None;
        }
        if let Some(gen) = get_gen() {
            if self.last_generation == Some(gen) && !self.pending {
                return None;
            }
        }
        let observed = match read() {
            Ok(clip) => Some(clip),
            Err(_) => {
                // Image-only or empty clipboards are not text; remember the
                // generation so we do not spin OpenClipboard / xclip.
                self.last_generation = get_gen();
                None
            }
        };
        if let Some(gen) = get_gen() {
            self.last_generation = Some(gen);
        }
        self.take_outgoing(now, observed)
    }

    pub fn take_outgoing(
        &mut self,
        now: Instant,
        observed: Option<ClipboardText>,
    ) -> Option<ClipboardText> {
        let Some(clip) = observed else {
            return None;
        };
        let fp = clip.fingerprint();
        let unchanged = fp == self.last_fp || fp == self.last_applied_fp || fp == self.last_sent_fp;
        if unchanged && !self.pending {
            self.last_fp = fp;
            return None;
        }
        if self.suppress_until.is_some_and(|until| now < until) {
            return None;
        }
        if clip.too_large_for_auto() {
            self.last_fp = fp;
            self.pending = false;
            return None;
        }
        if let Some(sent_at) = self.last_sent_at {
            if now.duration_since(sent_at) < CLIPBOARD_MIN_SEND_INTERVAL {
                self.pending = true;
                self.last_fp = fp;
                return None;
            }
        }
        self.last_fp = fp;
        self.last_sent_fp = fp;
        self.last_sent_at = Some(now);
        self.pending = false;
        Some(clip)
    }

    /// The last outgoing payload was not sent (channel closed or not yet
    /// open). Keep it pending so the next poll retries after the rate limit.
    pub fn send_failed(&mut self) {
        self.last_sent_fp = fingerprint("");
        self.pending = true;
    }
}

/// Both sides of clipboard sharing require a live remote-control session.
/// A view-only ticket must not inject the controller clipboard into the
/// node, and must not write the node's clipboard onto the controller.
pub fn share_allowed(requested_control: bool, session_control: bool) -> bool {
    requested_control && session_control
}

#[cfg(target_os = "windows")]
fn platform_read() -> Result<String> {
    windows_clip::read()
}

#[cfg(target_os = "windows")]
fn platform_write(text: &str) -> Result<()> {
    windows_clip::write(text)
}

#[cfg(target_os = "macos")]
fn platform_read() -> Result<String> {
    if let Ok(text) = arboard_read() {
        return Ok(text);
    }
    read_stdout("pbpaste", &[])
}

#[cfg(target_os = "macos")]
fn platform_write(text: &str) -> Result<()> {
    if arboard_write(text).is_ok() {
        return Ok(());
    }
    write_stdin("pbcopy", &[], text)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn platform_read() -> Result<String> {
    if let Ok(text) = arboard_read() {
        return Ok(text);
    }
    if let Ok(text) = read_stdout("wl-paste", &["--no-newline"]) {
        return Ok(text);
    }
    read_stdout("xclip", &["-selection", "clipboard", "-o"])
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn platform_write(text: &str) -> Result<()> {
    if arboard_write(text).is_ok() {
        return Ok(());
    }
    if write_stdin("wl-copy", &[], text).is_ok() {
        return Ok(());
    }
    write_stdin("xclip", &["-selection", "clipboard", "-i"], text)
}

/// Process-lifetime clipboard handle so a set_text is not dropped (and
/// cleared) when the write call returns. X11/Wayland require the owner
/// to keep serving the selection.
#[cfg(not(target_os = "windows"))]
fn arboard_slot() -> std::sync::MutexGuard<'static, Option<arboard::Clipboard>> {
    static CLIP: std::sync::Mutex<Option<arboard::Clipboard>> = std::sync::Mutex::new(None);
    CLIP.lock().unwrap_or_else(|err| err.into_inner())
}

#[cfg(not(target_os = "windows"))]
fn arboard_read() -> Result<String> {
    let mut slot = arboard_slot();
    if slot.is_none() {
        *slot = Some(arboard::Clipboard::new().map_err(|err| msg(format!("clipboard: {err}")))?);
    }
    match slot.as_mut().expect("clipboard slot").get_text() {
        Ok(text) => Ok(text),
        Err(err) => {
            // Reset stale display/clipboard handle so display restarts recover.
            *slot = None;
            Err(msg(format!("clipboard get: {err}")))
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn arboard_write(text: &str) -> Result<()> {
    let mut slot = arboard_slot();
    if slot.is_none() {
        *slot = Some(arboard::Clipboard::new().map_err(|err| msg(format!("clipboard: {err}")))?);
    }
    match slot
        .as_mut()
        .expect("clipboard slot")
        .set_text(text.to_string())
    {
        Ok(()) => Ok(()),
        Err(err) => {
            *slot = None;
            Err(msg(format!("clipboard set: {err}")))
        }
    }
}

#[cfg(not(target_os = "windows"))]
const SUBPROCESS_CLIPBOARD_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(not(target_os = "windows"))]
fn wait_child_bounded(
    child: &mut std::process::Child,
    program: &str,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(msg(format!("{program} timed out")));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(msg(format!("{program} wait: {err}"))),
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn write_stdin(program: &str, args: &[&str], text: &str) -> Result<()> {
    use std::io::Write;
    let mut child = agentlink_core::process::hidden(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|err| msg(format!("{program}: {err}")))?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(msg(format!("{program}: no stdin")));
    };
    let write_res = stdin.write_all(text.as_bytes());
    drop(stdin);
    if let Err(err) = write_res {
        let _ = child.kill();
        let _ = child.wait();
        return Err(msg(format!("{program} write: {err}")));
    }
    let status = wait_child_bounded(&mut child, program, SUBPROCESS_CLIPBOARD_TIMEOUT)?;
    if status.success() {
        Ok(())
    } else {
        Err(msg(format!("{program} exited with {status}")))
    }
}

#[cfg(not(target_os = "windows"))]
fn read_stdout(program: &str, args: &[&str]) -> Result<String> {
    use std::io::Read;
    let mut child = agentlink_core::process::hidden(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|err| msg(format!("{program}: {err}")))?;
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(msg(format!("{program}: no stdout")));
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("agentlink-clip-read".into())
        .spawn(move || {
            let mut buf = Vec::new();
            let res = stdout.read_to_end(&mut buf).map(|_| buf);
            let _ = tx.send(res);
        });
    let status = wait_child_bounded(&mut child, program, SUBPROCESS_CLIPBOARD_TIMEOUT)?;
    let bytes = rx
        .recv_timeout(Duration::from_millis(500))
        .map_err(|_| msg(format!("{program} stdout timed out")))?
        .map_err(|err| msg(format!("{program} read: {err}")))?;
    if !status.success() {
        return Err(msg(format!("{program} exited with {status}")));
    }
    String::from_utf8(bytes).map_err(|err| msg(format!("{program} utf8: {err}")))
}

#[cfg(target_os = "windows")]
mod windows_clip {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::thread;
    use std::time::Duration;

    use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
        OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
    };
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    pub fn sequence() -> Option<u64> {
        // SAFETY: GetClipboardSequenceNumber has no preconditions and does
        // not open the clipboard.
        Some(u64::from(unsafe { GetClipboardSequenceNumber() }))
    }

    fn open_clipboard() -> Result<()> {
        let mut delay = Duration::from_millis(5);
        let mut last = None;
        for _ in 0..12 {
            // SAFETY: OpenClipboard with no owner HWND is the documented way
            // to access the clipboard from a background thread briefly.
            let result = unsafe { OpenClipboard(None) };
            match result {
                Ok(()) => return Ok(()),
                Err(err) => {
                    last = Some(err);
                    thread::sleep(delay);
                    delay = (delay * 2).min(Duration::from_millis(40));
                }
            }
        }
        Err(msg(format!(
            "OpenClipboard: {}",
            last.map(|err| err.to_string())
                .unwrap_or_else(|| "CLIPBRD_E_CANT_OPEN".into())
        )))
    }

    pub fn read() -> Result<String> {
        unsafe {
            open_clipboard()?;
            let result = (|| {
                let handle = GetClipboardData(CF_UNICODETEXT.0 as u32)
                    .map_err(|err| msg(format!("GetClipboardData: {err}")))?;
                if handle.is_invalid() {
                    return Ok(String::new());
                }
                let hglobal = HGLOBAL(handle.0);
                let byte_size = GlobalSize(hglobal);
                if byte_size < 2 {
                    return Ok(String::new());
                }
                let ptr = GlobalLock(hglobal);
                if ptr.is_null() {
                    return Err(msg("GlobalLock failed for clipboard"));
                }
                // Bounds-check against GlobalSize so a missing NUL terminator
                // can never walk past the clipboard allocation.
                let max_u16 = byte_size / 2;
                let units = std::slice::from_raw_parts(ptr as *const u16, max_u16);
                let end = units.iter().position(|&u| u == 0).unwrap_or(max_u16);
                let text = String::from_utf16_lossy(&units[..end]);
                let _ = GlobalUnlock(hglobal);
                Ok(text)
            })();
            let _ = CloseClipboard();
            result
        }
    }

    pub fn write(text: &str) -> Result<()> {
        let mut wide: Vec<u16> = OsStr::new(text).encode_wide().collect();
        wide.push(0);
        let bytes = wide.len() * 2;
        unsafe {
            open_clipboard()?;
            let result = (|| {
                EmptyClipboard().map_err(|err| msg(format!("EmptyClipboard: {err}")))?;
                let hglobal = GlobalAlloc(GMEM_MOVEABLE, bytes)
                    .map_err(|err| msg(format!("GlobalAlloc: {err}")))?;
                let ptr = GlobalLock(hglobal);
                if ptr.is_null() {
                    let _ = GlobalFree(Some(hglobal));
                    return Err(msg("GlobalLock failed for clipboard write"));
                }
                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr as *mut u16, wide.len());
                let _ = GlobalUnlock(hglobal);
                if let Err(err) =
                    SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(hglobal.0)))
                {
                    let _ = GlobalFree(Some(hglobal));
                    return Err(msg(format!("SetClipboardData: {err}")));
                }
                // Ownership of hglobal transferred to the clipboard.
                Ok(())
            })();
            let _ = CloseClipboard();
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_long_text_and_marks_truncated() {
        let long = "a".repeat(CLIPBOARD_MAX_CHARS + 10);
        let capped = ClipboardText::capped(long);
        assert!(capped.truncated);
        assert_eq!(capped.text.chars().count(), CLIPBOARD_MAX_CHARS);
    }

    #[test]
    fn short_text_is_not_truncated() {
        let capped = ClipboardText::capped("hi".into());
        assert!(!capped.truncated);
        assert_eq!(capped.text, "hi");
    }

    #[test]
    fn set_payload_omits_nothing_of_the_text_but_parse_round_trips() {
        let clip = ClipboardText::capped("hello 剪贴板".into());
        let value = set_payload(&clip);
        assert_eq!(value["type"], "clipboard");
        assert_eq!(value["chars"], 9);
        let parsed = parse_set_message(&value).expect("set");
        assert_eq!(parsed.text, clip.text);
        assert!(parse_set_message(&json!({"type": "clipboard"})).is_none());
        assert!(parse_set_message(&json!({"type": "error", "text": "x"})).is_none());
    }

    #[test]
    fn watcher_skips_echo_of_applied_text() {
        let mut state = ClipboardWatchState::new();
        let t0 = Instant::now();
        state.note_applied("same");
        let again = ClipboardText::capped("same".into());
        assert!(state
            .take_outgoing(t0 + Duration::from_millis(20), Some(again))
            .is_none());
    }

    #[test]
    fn watcher_sends_a_new_copy_after_suppress_window() {
        let mut state = ClipboardWatchState::new();
        let t0 = Instant::now();
        state.note_applied("old");
        state.suppress_until = Some(t0);
        let next = ClipboardText::capped("new-unique-text".into());
        let sent = state
            .take_outgoing(t0 + Duration::from_millis(1), Some(next.clone()))
            .expect("send");
        assert_eq!(sent.text, "new-unique-text");
        // Same content must not be pushed again.
        assert!(state
            .take_outgoing(t0 + Duration::from_secs(2), Some(next))
            .is_none());
    }

    #[test]
    fn watcher_rate_limits_then_sends_the_latest() {
        let mut state = ClipboardWatchState::new();
        let t0 = Instant::now();
        let first = state
            .take_outgoing(t0, Some(ClipboardText::capped("one".into())))
            .expect("first");
        assert_eq!(first.text, "one");
        assert!(state
            .take_outgoing(
                t0 + Duration::from_millis(50),
                Some(ClipboardText::capped("two".into()))
            )
            .is_none());
        let later = state
            .take_outgoing(
                t0 + CLIPBOARD_MIN_SEND_INTERVAL + Duration::from_millis(1),
                Some(ClipboardText::capped("two".into())),
            )
            .expect("rate-limited send");
        assert_eq!(later.text, "two");
    }

    #[test]
    fn watcher_drops_oversized_auto_payloads() {
        let mut state = ClipboardWatchState::new();
        let huge = "x".repeat(CLIPBOARD_AUTO_MAX_BYTES + 8);
        assert!(ClipboardText::capped(huge.clone()).too_large_for_auto());
        assert!(state
            .take_outgoing(Instant::now(), Some(ClipboardText::capped(huge)))
            .is_none());
    }

    #[test]
    fn initial_empty_clipboard_is_not_a_copy() {
        let mut state = ClipboardWatchState::new();
        assert!(state
            .take_outgoing(Instant::now(), Some(ClipboardText::capped(String::new())))
            .is_none());
    }

    #[test]
    fn fingerprints_are_stable_for_the_same_text() {
        assert_eq!(fingerprint("abc"), fingerprint("abc"));
        assert_ne!(fingerprint("abc"), fingerprint("abd"));
    }

    #[test]
    fn share_allowed_requires_control_on_both_sides() {
        assert!(share_allowed(true, true));
        assert!(!share_allowed(true, false));
        assert!(!share_allowed(false, true));
        assert!(!share_allowed(false, false));
    }

    #[test]
    fn failed_send_is_retried_after_the_rate_limit() {
        let mut state = ClipboardWatchState::new();
        let t0 = Instant::now();
        let first = state
            .take_outgoing(t0, Some(ClipboardText::capped("payload".into())))
            .expect("first");
        assert_eq!(first.text, "payload");
        state.send_failed();
        assert!(state
            .take_outgoing(t0 + Duration::from_millis(10), Some(first.clone()))
            .is_none());
        let retried = state
            .take_outgoing(
                t0 + CLIPBOARD_MIN_SEND_INTERVAL + Duration::from_millis(1),
                Some(ClipboardText::capped("payload".into())),
            )
            .expect("retry");
        assert_eq!(retried.text, "payload");
    }

    #[test]
    fn native_clipboard_roundtrip_when_a_display_is_available() {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return;
        }
        let marker = format!(
            "agentlink-t506-clip-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        );
        if let Err(err) = write_clipboard(&marker) {
            eprintln!("clipboard write skipped: {err}");
            return;
        }
        let got = read_clipboard().expect("read clipboard after write");
        assert_eq!(got.text, marker, "native/tool clipboard roundtrip");
    }

    #[test]
    fn first_poll_seeds_without_exfiltrating_preexisting_secret() {
        let mut state = ClipboardWatchState::new();
        let t0 = Instant::now();
        // Pre-existing password on clipboard before connecting must NEVER be sent.
        let on_connect = state.poll_outgoing_with(
            t0,
            || Some(42),
            || Ok(ClipboardText::capped("pre-existing-ssh-key".into())),
        );
        assert!(
            on_connect.is_none(),
            "first poll must seed baseline and not leak pre-existing secret"
        );
        // Same generation/content later is still not pushed.
        let again = state.poll_outgoing_with(
            t0 + Duration::from_secs(1),
            || Some(42),
            || Ok(ClipboardText::capped("pre-existing-ssh-key".into())),
        );
        assert!(again.is_none());
        // A new local copy AFTER connect IS pushed.
        let copied = state.poll_outgoing_with(
            t0 + Duration::from_secs(2),
            || Some(43),
            || Ok(ClipboardText::capped("fresh-copy".into())),
        );
        assert_eq!(copied.expect("fresh copy").text, "fresh-copy");
    }

    #[test]
    fn copy_during_echo_suppress_is_not_lost_on_generation_platforms() {
        let mut state = ClipboardWatchState::new();
        let t0 = Instant::now();
        state.seed(Some("initial"), Some(10));
        // Incoming sync applied at gen 11; suppress until t0 + 500ms.
        state.note_applied("from-peer");
        state.last_generation = Some(11);
        state.suppress_until = Some(t0 + CLIPBOARD_ECHO_SUPPRESS);

        // User copies a new secret at +150ms (gen 12) while still suppressed.
        let during = state.poll_outgoing_with(
            t0 + Duration::from_millis(150),
            || Some(12),
            || Ok(ClipboardText::capped("user-copy-during-suppress".into())),
        );
        assert!(during.is_none(), "must remain suppressed inside window");
        assert_eq!(
            state.last_generation,
            Some(11),
            "last_generation must not advance while suppressed"
        );

        // After suppress window expires, the user's copy at gen 12 MUST sync!
        let after = state.poll_outgoing_with(
            t0 + CLIPBOARD_ECHO_SUPPRESS + Duration::from_millis(10),
            || Some(12),
            || Ok(ClipboardText::capped("user-copy-during-suppress".into())),
        );
        assert_eq!(
            after.expect("copy made during suppress must not be lost").text,
            "user-copy-during-suppress"
        );
    }
}
