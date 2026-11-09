//! Local consent before a viewer is allowed to attach.
//!
//! `auto` records the session and continues. `notify` does the same and tries
//! a desktop notification. `prompt` waits until the operator drops an allow
//! or deny file next to the audit log. `deny` rejects every offer.

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

fn notify(viewer: &str, session_id: &str) {
    let body = format!("agentlink remote desktop: {viewer} ({session_id})");
    #[cfg(target_os = "linux")]
    {
        let _ = agentlink_core::process::hidden("notify-send")
            .args(["agentlink", &body])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!("display notification \"{body}\" with title \"agentlink\"");
        let _ = agentlink_core::process::hidden("osascript")
            .args(["-e", &script])
            .spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = agentlink_core::process::hidden("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("New-BurntToastNotification -Text 'agentlink','{body}'"),
            ])
            .spawn();
        tracing::info!(%body, "remote desktop session starting");
    }
    tracing::info!(viewer, session_id, "remote desktop viewer notified");
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
}
