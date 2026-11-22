//! Local consent before a viewer is allowed to attach.
//!
//! `auto` records the session and continues. `notify` does the same and tries
//! a desktop notification. `prompt` waits until the operator drops an allow
//! or deny file next to the audit log. `deny` rejects every offer.
//!
//! Notification text is never interpolated into a shell, AppleScript, or
//! PowerShell command string. macOS uses a quoted AppleScript literal;
//! Windows passes the body only through an environment variable; Linux uses
//! argv. Changing the default consent mode is not the fix.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentMode {
    Auto,
    Notify,
    Prompt,
    Deny,
}

impl ConsentMode {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "auto" | "allow" => Ok(Self::Auto),
            "notify" | "notification" => Ok(Self::Notify),
            "prompt" | "ask" => Ok(Self::Prompt),
            "deny" | "off" => Ok(Self::Deny),
            other => Err(format!(
                "unknown stream consent '{other}' (expected auto, notify, prompt, or deny)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Notify => "notify",
            Self::Prompt => "prompt",
            Self::Deny => "deny",
        }
    }
}

/// Fail closed when the consent lock is poisoned. A torn Auto/Notify
/// value must not let a viewer attach.
pub fn read_consent_mode(
    lock: &std::sync::RwLock<ConsentMode>,
) -> std::result::Result<ConsentMode, String> {
    lock.read()
        .map(|guard| *guard)
        .map_err(|_| "stream consent is unavailable".into())
}

/// Unique per-offer consent identifier so concurrent or retried offers from
/// the same peer never collide on `.request`/`.allow`/`.deny` files.
pub fn offer_consent_id(peer: &str) -> String {
    let safe_peer: String = peer
        .chars()
        .take(32)
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect();
    let suffix = uuid::Uuid::new_v4();
    if safe_peer.is_empty() {
        format!("pending-{suffix}")
    } else {
        format!("pending-{safe_peer}-{suffix}")
    }
}

#[allow(dead_code)]
pub fn approve(
    mode: ConsentMode,
    audit_path: &Path,
    viewer: &str,
    session_id: &str,
) -> Result<(), String> {
    match mode {
        ConsentMode::Deny => Err("remote desktop streaming is denied on this node".into()),
        ConsentMode::Auto => Ok(()),
        ConsentMode::Notify => {
            notify(viewer, session_id);
            Ok(())
        }
        ConsentMode::Prompt => prompt(audit_path, viewer, session_id),
    }
}

/// Async consent check for use on the `agentlink-rtc` Tokio runtime.
///
/// Unlike [`approve`], `ConsentMode::Prompt` awaits with `tokio::time::sleep`
/// instead of blocking a Tokio worker thread for 30s with `thread::sleep`.
pub async fn approve_async(
    mode: ConsentMode,
    audit_path: &Path,
    viewer: &str,
    session_id: &str,
) -> Result<(), String> {
    match mode {
        ConsentMode::Deny => Err("remote desktop streaming is denied on this node".into()),
        ConsentMode::Auto => Ok(()),
        ConsentMode::Notify => {
            notify(viewer, session_id);
            Ok(())
        }
        ConsentMode::Prompt => {
            prompt_async_with_timeout(audit_path, viewer, session_id, Duration::from_secs(30)).await
        }
    }
}

/// A parameterized notification command. The untrusted body is never placed
/// inside a script or shell string; it is either an argv element, a quoted
/// AppleScript literal, or a Windows environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyPlan {
    pub program: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
}

pub const NOTIFY_BODY_ENV: &str = "AGENTLINK_NOTIFY_BODY";

pub fn notification_body(viewer: &str, session_id: &str) -> String {
    format!("agentlink remote desktop: {viewer} ({session_id})")
}

/// Quote a string as an AppleScript string literal. The result is always one
/// literal; quote and backslash characters are escaped so they cannot close
/// the string or start a new statement.
pub fn applescript_string_literal(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Unicode line/paragraph separators can end an AppleScript
            // statement if copied raw into the source. Fold them into the
            // same escaped newline the ASCII case uses.
            '\u{0085}' | '\u{2028}' | '\u{2029}' | '\u{000b}' | '\u{000c}' => {
                out.push_str("\\n")
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub fn macos_notification_script(body: &str) -> String {
    format!(
        "display notification {} with title \"agentlink\"",
        applescript_string_literal(body)
    )
}

/// PowerShell source that shows a notification using built-in Windows APIs
/// (WinRT ToastNotificationManager with a System.Windows.Forms.NotifyIcon
/// fallback — no third-party BurntToast module required).
///
/// The untrusted body is read solely from [`NOTIFY_BODY_ENV`] and XML-escaped
/// before building the toast payload; this source must never embed viewer text.
pub fn windows_notification_script() -> &'static str {
    concat!(
        "$body = [string]$env:AGENTLINK_NOTIFY_BODY; ",
        "try { ",
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; ",
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null; ",
        "$esc = [System.Security.SecurityElement]::Escape($body); ",
        "$xml = New-Object Windows.Data.Xml.Dom.XmlDocument; ",
        "$xml.LoadXml('<toast><visual><binding template=\"ToastText02\"><text id=\"1\">agentlink</text><text id=\"2\">' + $esc + '</text></binding></visual></toast>'); ",
        "$toast = New-Object Windows.UI.Notifications.ToastNotification $xml; ",
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('agentlink').Show($toast); ",
        "} catch { ",
        "try { ",
        "Add-Type -AssemblyName System.Windows.Forms; ",
        "$n = New-Object System.Windows.Forms.NotifyIcon; ",
        "$n.Icon = [System.Drawing.SystemIcons]::Information; ",
        "$n.BalloonTipTitle = 'agentlink'; ",
        "$n.BalloonTipText = $body; ",
        "$n.Visible = $true; ",
        "$n.ShowBalloonTip(5000); ",
        "Start-Sleep -Milliseconds 500; ",
        "$n.Dispose(); ",
        "} catch {} }"
    )
}

/// Build the platform notification plan. `os` is `linux`, `macos`, or `windows`.
/// Unknown OS values produce a linux-style argv plan so tests can name a host.
pub fn notify_plan(os: &str, viewer: &str, session_id: &str) -> NotifyPlan {
    let body = notification_body(viewer, session_id);
    match os {
        "macos" => NotifyPlan {
            program: "osascript".into(),
            args: vec!["-e".into(), macos_notification_script(&body)],
            env: HashMap::new(),
        },
        "windows" => NotifyPlan {
            program: "powershell".into(),
            args: vec![
                "-NoProfile".into(),
                "-Command".into(),
                windows_notification_script().into(),
            ],
            env: HashMap::from([(NOTIFY_BODY_ENV.into(), body)]),
        },
        _ => NotifyPlan {
            program: "notify-send".into(),
            args: vec!["agentlink".into(), body],
            env: HashMap::new(),
        },
    }
}

fn current_notify_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

fn notify(viewer: &str, session_id: &str) {
    let plan = notify_plan(current_notify_os(), viewer, session_id);
    let mut cmd = agentlink_core::process::hidden(&plan.program);
    cmd.args(&plan.args);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for (key, value) in &plan.env {
        cmd.env(key, value);
    }
    if let Ok(mut child) = cmd.spawn() {
        // Reap the notification child in the background so Unix systems do not
        // accumulate zombie processes over long daemon lifetimes.
        let _ = thread::Builder::new()
            .name("agentlink-notify-reap".into())
            .spawn(move || {
                let _ = child.wait();
            });
    }
    if cfg!(target_os = "windows") {
        tracing::info!("remote desktop session starting");
    }
    tracing::info!(
        viewer_chars = viewer.chars().count(),
        session_chars = session_id.chars().count(),
        "remote desktop viewer notified"
    );
}

struct PromptFiles {
    request: PathBuf,
    allow: PathBuf,
    deny: PathBuf,
}

fn prepare_prompt_files(
    audit_path: &Path,
    viewer: &str,
    session_id: &str,
) -> Result<PromptFiles, String> {
    let dir = consent_dir(audit_path);
    if let Err(err) = fs::create_dir_all(&dir) {
        return Err(format!("consent directory: {err}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let safe: String = session_id
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect();
    let request = dir.join(format!("{safe}.request"));
    let allow = dir.join(format!("{safe}.allow"));
    let deny = dir.join(format!("{safe}.deny"));
    let _ = fs::remove_file(&allow);
    let _ = fs::remove_file(&deny);
    let note = format!(
        "viewer={viewer}\nsession={session_id}\nallow={}\ndeny={}\n",
        allow.display(),
        deny.display()
    );
    fs::write(&request, note).map_err(|err| format!("consent request: {err}"))?;
    tracing::warn!(
        path = %allow.display(),
        "waiting for stream consent; create the allow file or the deny file"
    );
    Ok(PromptFiles {
        request,
        allow,
        deny,
    })
}

fn check_prompt_decision(files: &PromptFiles) -> Option<Result<(), String>> {
    if files.allow.exists() {
        let _ = fs::remove_file(&files.request);
        let _ = fs::remove_file(&files.allow);
        return Some(Ok(()));
    }
    if files.deny.exists() {
        let _ = fs::remove_file(&files.request);
        let _ = fs::remove_file(&files.deny);
        return Some(Err("the operator denied this remote desktop session".into()));
    }
    None
}

#[allow(dead_code)]
fn prompt(audit_path: &Path, viewer: &str, session_id: &str) -> Result<(), String> {
    let files = prepare_prompt_files(audit_path, viewer, session_id)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(decision) = check_prompt_decision(&files) {
            return decision;
        }
        thread::sleep(Duration::from_millis(200));
    }
    let _ = fs::remove_file(&files.request);
    Err("remote desktop consent timed out".into())
}

async fn prompt_async_with_timeout(
    audit_path: &Path,
    viewer: &str,
    session_id: &str,
    timeout: Duration,
) -> Result<(), String> {
    let audit_owned = audit_path.to_path_buf();
    let viewer_owned = viewer.to_string();
    let session_owned = session_id.to_string();
    let files = tokio::task::spawn_blocking(move || {
        prepare_prompt_files(&audit_owned, &viewer_owned, &session_owned)
    })
    .await
    .map_err(|err| format!("consent prepare task: {err}"))??;
    // Alert the operator at the seat that a consent decision is pending.
    if !cfg!(test) {
        notify(viewer, session_id);
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(decision) = check_prompt_decision(&files) {
            return decision;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = fs::remove_file(&files.request);
    Err("remote desktop consent timed out".into())
}

pub(crate) fn consent_dir(audit_path: &Path) -> PathBuf {
    if !audit_path.as_os_str().is_empty() {
        if let Some(parent) = audit_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            return parent.join("stream-consent");
        }
    }
    agentlink_core::config::default_data_dir("node")
        .ok()
        .unwrap_or_else(|| std::env::temp_dir().join("agentlink"))
        .join("stream-consent")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BREAKOUT_VIEWER: &str = r#""; do shell script "id"; display notification "x"#;
    const BREAKOUT_SESSION: &str = r#"'; calc.exe; $env:foo='" "#;
    const PS_BREAKOUT: &str = "'; Start-Process calc; '";

    /// Every `"` inside an AppleScript literal, other than the wrapping pair,
    /// must be escaped as `\"`.
    fn applescript_literal_is_closed(literal: &str) -> bool {
        let bytes = literal.as_bytes();
        if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
            return false;
        }
        let mut escaped = false;
        for (i, &b) in bytes.iter().enumerate() {
            if i == 0 {
                continue;
            }
            if i == bytes.len() - 1 {
                return !escaped;
            }
            if escaped {
                escaped = false;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                continue;
            }
            if b == b'"' {
                return false;
            }
        }
        false
    }

    fn assert_no_code_breakout(plan: &NotifyPlan, viewer: &str, session_id: &str) {
        if plan.program == "powershell" {
            assert!(
                !plan.args.iter().any(|arg| arg.contains(viewer)
                    || arg.contains(session_id)
                    || arg.contains("Start-Process")
                    || arg.contains("calc.exe")
                    || arg.contains("calc")),
                "PowerShell -Command must not contain untrusted text: {:?}",
                plan.args
            );
            assert_eq!(
                plan.env.get(NOTIFY_BODY_ENV).map(String::as_str),
                Some(notification_body(viewer, session_id).as_str())
            );
            assert_eq!(
                plan.args.last().map(String::as_str),
                Some(windows_notification_script())
            );
            assert!(windows_notification_script().contains("$env:AGENTLINK_NOTIFY_BODY"));
            assert!(!windows_notification_script().contains(viewer));
        }
        if plan.program == "osascript" {
            let script = plan.args.last().expect("osascript -e script");
            let body = notification_body(viewer, session_id);
            let literal = applescript_string_literal(&body);
            assert!(applescript_literal_is_closed(&literal), "{literal}");
            let prefix = "display notification ";
            let suffix = " with title \"agentlink\"";
            assert!(
                script.starts_with(prefix) && script.ends_with(suffix),
                "unexpected script shape: {script}"
            );
            let mid = &script[prefix.len()..script.len() - suffix.len()];
            assert_eq!(mid, literal);
        }
        if plan.program == "notify-send" {
            assert_eq!(
                plan.args,
                vec![
                    "agentlink".to_string(),
                    notification_body(viewer, session_id)
                ]
            );
        }
    }

    #[test]
    fn names_parse() {
        assert_eq!(ConsentMode::parse("prompt").unwrap(), ConsentMode::Prompt);
        assert!(ConsentMode::parse("sometimes").is_err());
    }

    #[test]
    fn deny_rejects_and_auto_allows() {
        assert!(approve(ConsentMode::Deny, Path::new("audit.log"), "a", "s").is_err());
        assert!(approve(ConsentMode::Auto, Path::new("audit.log"), "a", "s").is_ok());
    }

    #[test]
    fn applescript_literal_escapes_quotes_and_backslashes() {
        let literal = applescript_string_literal(BREAKOUT_VIEWER);
        assert!(applescript_literal_is_closed(&literal), "{literal}");
        assert_eq!(
            literal,
            r#""\"; do shell script \"id\"; display notification \"x""#
        );
        let script = macos_notification_script(BREAKOUT_VIEWER);
        let prefix = "display notification ";
        let suffix = " with title \"agentlink\"";
        let mid = &script[prefix.len()..script.len() - suffix.len()];
        assert_eq!(mid, literal);
    }

    #[test]
    fn notify_plan_does_not_turn_viewer_into_code_on_any_os() {
        for os in ["linux", "macos", "windows"] {
            let plan = notify_plan(os, BREAKOUT_VIEWER, BREAKOUT_SESSION);
            assert_no_code_breakout(&plan, BREAKOUT_VIEWER, BREAKOUT_SESSION);
            let ps = notify_plan(os, PS_BREAKOUT, "sess");
            assert_no_code_breakout(&ps, PS_BREAKOUT, "sess");
        }
    }

    #[test]
    fn applescript_literal_escapes_unicode_line_separators() {
        // Coverage of the literal API and notify_plan shape only. Not a real macOS run.
        let seps = ['\n', '\r', '\u{0085}', '\u{2028}', '\u{2029}', '\u{000b}', '\u{000c}'];
        for sep in seps {
            let viewer = format!("eve{sep}id");
            let plan = notify_plan("macos", &viewer, "sess-1");
            assert_no_code_breakout(&plan, &viewer, "sess-1");
            let script = plan.args.last().expect("script");
            assert!(!script.contains('\u{2028}'), "{script}");
            assert!(!script.contains('\u{2029}'), "{script}");
            assert!(!script.contains('\u{0085}'), "{script}");
            let literal = applescript_string_literal(&notification_body(&viewer, "sess-1"));
            assert!(applescript_literal_is_closed(&literal), "{literal}");
            assert!(!literal.contains('\u{2028}'));
            assert!(!literal.contains('\u{2029}'));
        }
    }

    #[test]
    fn poisoned_consent_lock_is_fail_closed() {
        use std::sync::{Arc, RwLock};
        let lock = Arc::new(RwLock::new(ConsentMode::Auto));
        assert_eq!(read_consent_mode(&lock).unwrap(), ConsentMode::Auto);
        let poison = lock.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison.write().unwrap();
            panic!("poison the consent lock");
        })
        .join();
        let err = read_consent_mode(&lock).unwrap_err();
        assert!(
            err.contains("unavailable"),
            "poisoned consent must not into_inner, got {err}"
        );
    }

    #[test]
    fn windows_notification_uses_builtin_winrt_not_burnt_toast() {
        let script = windows_notification_script();
        assert!(
            !script.contains("New-BurntToastNotification"),
            "must not depend on third-party BurntToast module"
        );
        assert!(script.contains("ToastNotificationManager"));
        assert!(script.contains("NotifyIcon"));
        assert!(script.contains("$env:AGENTLINK_NOTIFY_BODY"));
        assert!(script.contains("SecurityElement]::Escape"));
    }

    #[test]
    fn offer_consent_ids_are_unique_per_offer() {
        let a = offer_consent_id("alice");
        let b = offer_consent_id("alice");
        assert_ne!(a, b);
        assert!(a.starts_with("pending-alice-"));
        assert!(b.starts_with("pending-alice-"));
    }

    #[test]
    fn consent_dir_never_falls_back_to_cwd_when_audit_path_empty_or_bare() {
        let empty = consent_dir(Path::new(""));
        assert_ne!(empty, PathBuf::from("./stream-consent"));
        assert_ne!(empty, PathBuf::from("stream-consent"));
        assert!(empty.is_absolute() || empty.components().count() >= 2);
        let bare = consent_dir(Path::new("audit.log"));
        assert_ne!(bare, PathBuf::from("./stream-consent"));
        assert_ne!(bare, PathBuf::from("stream-consent"));
        let explicit = consent_dir(Path::new("/tmp/agentlink-node/audit.log"));
        assert_eq!(
            explicit,
            PathBuf::from("/tmp/agentlink-node").join("stream-consent")
        );
    }

    #[tokio::test]
    async fn prompt_async_approves_and_denies_without_blocking_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.log");
        let allow_id = offer_consent_id("alice");
        let allow_file = consent_dir(&audit_path).join(format!("{allow_id}.allow"));

        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            let _ = fs::create_dir_all(allow_file.parent().unwrap());
            fs::write(&allow_file, "ok").unwrap();
        });
        let res = prompt_async_with_timeout(&audit_path, "alice", &allow_id, Duration::from_secs(2))
            .await;
        writer.await.unwrap();
        assert!(res.is_ok(), "expected allow, got {res:?}");

        let deny_id = offer_consent_id("bob");
        let deny_file = consent_dir(&audit_path).join(format!("{deny_id}.deny"));
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            fs::write(&deny_file, "no").unwrap();
        });
        let res = prompt_async_with_timeout(&audit_path, "bob", &deny_id, Duration::from_secs(2))
            .await;
        writer.await.unwrap();
        assert!(res.is_err(), "expected deny error");
    }
}
