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

/// PowerShell source that shows a notification. The body is read from
/// [`NOTIFY_BODY_ENV`]; this source must not contain the untrusted text.
pub fn windows_notification_script() -> &'static str {
    "New-BurntToastNotification -Text 'agentlink', [string]$env:AGENTLINK_NOTIFY_BODY"
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
    for (key, value) in &plan.env {
        cmd.env(key, value);
    }
    let _ = cmd.spawn();
    if cfg!(target_os = "windows") {
        tracing::info!("remote desktop session starting");
    }
    tracing::info!(
        viewer_chars = viewer.chars().count(),
        session_chars = session_id.chars().count(),
        "remote desktop viewer notified"
    );
}

fn prompt(audit_path: &Path, viewer: &str, session_id: &str) -> Result<(), String> {
    let dir = consent_dir(audit_path);
    if let Err(err) = fs::create_dir_all(&dir) {
        return Err(format!("consent directory: {err}"));
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
    let note = format!("viewer={viewer}\nsession={session_id}\n");
    fs::write(&request, note).map_err(|err| format!("consent request: {err}"))?;
    tracing::warn!(
        path = %allow.display(),
        "waiting for stream consent; create the allow file or the deny file"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if allow.exists() {
            let _ = fs::remove_file(&request);
            return Ok(());
        }
        if deny.exists() {
            let _ = fs::remove_file(&request);
            return Err("the operator denied this remote desktop session".into());
        }
        thread::sleep(Duration::from_millis(200));
    }
    let _ = fs::remove_file(&request);
    Err("remote desktop consent timed out".into())
}

fn consent_dir(audit_path: &Path) -> PathBuf {
    audit_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
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
}
