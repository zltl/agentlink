//! Official GNOME / xdg-desktop-portal identity and restore-token storage.
//!
//! A restore token is OS consent only. It never issues or widens an agentlink
//! grant. Tokens are stored mode 0600 in a 0700 directory on the node host,
//! bound to the window query and any source identity the portal disclosed.
//! A token is not reused when the query differs, the source identity is
//! missing (would become silent any-window access), or the next Start
//! discloses a different window.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{msg, Result};

/// Freedesktop application id used with `org.freedesktop.portal.Registry`.
pub const PORTAL_APP_ID: &str = "org.agentlink.Node";

/// `SelectSources` persist_mode: keep permission until the user revokes it.
pub const PERSIST_UNTIL_REVOKED: u32 = 2;

const RESTORE_FILE: &str = "screencast-window.json";
const RESTORE_SUBDIR: &str = "portal-restore";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopRestoreRecord {
    /// Opaque portal token. Never log this value.
    pub token: String,
    pub portal_app_id: String,
    pub kind: String,
    pub created_unix: i64,
}

fn desktop_restore_path(data_dir: &Path, kind: &str) -> PathBuf {
    let safe: String = kind
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
        .collect();
    restore_dir(data_dir).join(format!("desktop-{safe}.json"))
}

pub fn store_desktop_restore(
    data_dir: &Path,
    kind: &str,
    token: &str,
    now_unix: i64,
) -> Result<Option<PathBuf>> {
    if !persist_enabled() {
        return Ok(None);
    }
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    let dir = restore_dir(data_dir);
    agentlink_core::util::ensure_dir(&dir).map_err(|err| msg(err.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let record = DesktopRestoreRecord {
        token: token.to_string(),
        portal_app_id: PORTAL_APP_ID.to_string(),
        kind: norm(kind),
        created_unix: now_unix,
    };
    let path = desktop_restore_path(data_dir, kind);
    agentlink_core::util::write_secret(
        &path,
        serde_json::to_string_pretty(&record)
            .map_err(|err| msg(err.to_string()))?
            .as_bytes(),
    )
    .map_err(|err| msg(err.to_string()))?;
    Ok(Some(path))
}

pub fn load_desktop_restore(data_dir: &Path, kind: &str) -> Result<Option<String>> {
    if !persist_enabled() {
        return Ok(None);
    }
    let path = desktop_restore_path(data_dir, kind);
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)
        .map_err(|err| msg(format!("read desktop portal restore token: {err}")))?;
    let record: DesktopRestoreRecord = serde_json::from_str(&text)
        .map_err(|err| msg(format!("desktop portal restore token {}: {err}", path.display())))?;
    let token = record.token.trim();
    if token.is_empty() || record.portal_app_id != PORTAL_APP_ID {
        return Ok(None);
    }
    Ok(Some(token.to_string()))
}

pub fn clear_desktop_restore(data_dir: &Path, kind: &str) -> Result<()> {
    let path = desktop_restore_path(data_dir, kind);
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|err| msg(format!("clear desktop portal restore token: {err}")))?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRecord {
    /// Opaque portal token. Never log this value.
    pub token: String,
    pub portal_app_id: String,
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub created_unix: i64,
}

impl RestoreRecord {
    pub fn has_source_identity(&self) -> bool {
        disclosed_identity(
            self.source_title.as_deref(),
            self.source_app_id.as_deref(),
            self.source_id.as_deref(),
        )
    }
}

fn norm(s: &str) -> String {
    s.trim().to_string()
}

/// True when the portal disclosed a window identity that is not an opaque "0".
pub fn disclosed_identity(title: Option<&str>, app_id: Option<&str>, id: Option<&str>) -> bool {
    let meaningful = |s: Option<&str>| {
        s.map(str::trim)
            .filter(|s| !s.is_empty() && *s != "0")
            .is_some()
    };
    meaningful(title) || meaningful(app_id) || meaningful(id)
}

pub fn persist_enabled() -> bool {
    match std::env::var("AGENTLINK_PORTAL_PERSIST") {
        Ok(value) => {
            let v = value.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "0" | "false" | "no" | "off")
        }
        Err(_) => true,
    }
}

pub fn restore_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(RESTORE_SUBDIR)
}

fn restore_path(data_dir: &Path) -> PathBuf {
    restore_dir(data_dir).join(RESTORE_FILE)
}

pub fn default_persist_data_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("AGENTLINK_PORTAL_PERSIST_DIR") {
        let dir = PathBuf::from(dir);
        if !dir.as_os_str().is_empty() {
            return Some(dir);
        }
    }
    agentlink_core::config::default_data_dir("node").ok()
}

pub fn clear_restore(data_dir: &Path) -> Result<()> {
    let path = restore_path(data_dir);
    if path.exists() {
        fs::remove_file(&path).map_err(|err| msg(format!("clear portal restore token: {err}")))?;
    }
    Ok(())
}

/// Store a token only when the portal disclosed a real window identity.
pub fn store_restore(
    data_dir: &Path,
    token: &str,
    query: &str,
    source_title: Option<&str>,
    source_app_id: Option<&str>,
    source_id: Option<&str>,
    now_unix: i64,
) -> Result<Option<PathBuf>> {
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    if !disclosed_identity(source_title, source_app_id, source_id) {
        return Ok(None);
    }
    let dir = restore_dir(data_dir);
    agentlink_core::util::ensure_dir(&dir).map_err(|err| msg(err.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let record = RestoreRecord {
        token: token.to_string(),
        portal_app_id: PORTAL_APP_ID.to_string(),
        query: norm(query),
        source_title: source_title.map(norm).filter(|s| !s.is_empty()),
        source_app_id: source_app_id.map(norm).filter(|s| !s.is_empty()),
        source_id: source_id.map(norm).filter(|s| !s.is_empty() && s != "0"),
        created_unix: now_unix,
    };
    let path = restore_path(data_dir);
    agentlink_core::util::write_secret(
        &path,
        serde_json::to_string_pretty(&record)
            .map_err(|err| msg(err.to_string()))?
            .as_bytes(),
    )
    .map_err(|err| msg(err.to_string()))?;
    Ok(Some(path))
}

pub fn load_restore(data_dir: &Path) -> Result<Option<RestoreRecord>> {
    let path = restore_path(data_dir);
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)
        .map_err(|err| msg(format!("read portal restore token: {err}")))?;
    let record: RestoreRecord = serde_json::from_str(&text)
        .map_err(|err| msg(format!("portal restore token {}: {err}", path.display())))?;
    if record.token.trim().is_empty() || record.portal_app_id != PORTAL_APP_ID {
        return Ok(None);
    }
    Ok(Some(record))
}

/// A stored token may be offered to SelectSources only for the same query
/// and only when it is bound to a disclosed window identity.
pub fn reusable_token<'a>(record: &'a RestoreRecord, query: &str) -> Option<&'a str> {
    if !persist_enabled() {
        return None;
    }
    if norm(&record.query) != norm(query) {
        return None;
    }
    if !record.has_source_identity() {
        return None;
    }
    let token = record.token.trim();
    (!token.is_empty()).then_some(token)
}

/// After Start, the restored stream must still be the bound window.
pub fn restored_source_matches(
    record: &RestoreRecord,
    source_title: Option<&str>,
    source_app_id: Option<&str>,
    source_id: Option<&str>,
) -> bool {
    if !record.has_source_identity() {
        return false;
    }
    let same = |expected: &Option<String>, got: Option<&str>| match (expected, got) {
        (Some(exp), Some(got)) if !exp.is_empty() => norm(exp) == norm(got),
        (Some(_), None) => false,
        _ => true,
    };
    same(&record.source_title, source_title)
        && same(&record.source_app_id, source_app_id)
        && same(&record.source_id, source_id)
}

pub fn desktop_file_body(exec: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=agentlink\n\
         Comment=agentlink node (xdg-desktop-portal identity)\n\
         Exec={exec}\n\
         Icon=computer\n\
         Terminal=false\n\
         StartupNotify=false\n\
         NoDisplay=true\n\
         DBusActivatable=false\n"
    )
}

/// Install a per-user desktop file for [PORTAL_APP_ID] if one is not already present.
pub fn ensure_user_desktop_file() -> Result<Option<PathBuf>> {
    let Some(data_home) = user_data_home() else {
        return Ok(None);
    };
    let apps = data_home.join("applications");
    agentlink_core::util::ensure_dir(&apps).map_err(|err| msg(err.to_string()))?;
    let path = apps.join(format!("{PORTAL_APP_ID}.desktop"));
    if path.is_file() {
        return Ok(Some(path));
    }
    let exec = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| "agentlink".into());
    // Quote nothing exotic; path from current_exe is local.
    let body = desktop_file_body(&exec);
    fs::write(&path, body).map_err(|err| msg(format!("write {PORTAL_APP_ID}.desktop: {err}")))?;
    Ok(Some(path))
}

fn user_data_home() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        let dir = PathBuf::from(dir);
        if !dir.as_os_str().is_empty() {
            return Some(dir);
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_stored_only_with_source_identity_and_bound_to_query() {
        let dir = tempfile::tempdir().unwrap();
        assert!(store_restore(
            dir.path(),
            "tok-secret",
            "t417-iso-editor-wMn95K.txt",
            Some("t417-iso-editor-wMn95K.txt"),
            Some("org.gnome.TextEditor"),
            Some("0x123"),
            10,
        )
        .unwrap()
        .is_some());
        let rec = load_restore(dir.path()).unwrap().unwrap();
        assert_eq!(rec.portal_app_id, PORTAL_APP_ID);
        assert!(reusable_token(&rec, "t417-iso-editor-wMn95K.txt").is_some());
        assert!(reusable_token(&rec, "other-window").is_none());
        assert!(restored_source_matches(
            &rec,
            Some("t417-iso-editor-wMn95K.txt"),
            Some("org.gnome.TextEditor"),
            Some("0x123"),
        ));
        assert!(!restored_source_matches(
            &rec,
            Some("unrelated"),
            Some("org.gnome.TextEditor"),
            Some("0x123"),
        ));
        let mode = std::fs::metadata(restore_path(dir.path()))
            .unwrap()
            .permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(mode.mode() & 0o777, 0o600);
            let dir_mode = std::fs::metadata(restore_dir(dir.path()))
                .unwrap()
                .permissions();
            assert_eq!(dir_mode.mode() & 0o777, 0o700);
        }
        clear_restore(dir.path()).unwrap();
        assert!(load_restore(dir.path()).unwrap().is_none());
    }

    #[test]
    fn omitted_source_identity_is_not_stored() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            store_restore(dir.path(), "tok", "Editor", None, None, Some("0"), 1)
                .unwrap()
                .is_none()
        );
        assert!(load_restore(dir.path()).unwrap().is_none());
    }

    #[test]
    fn desktop_file_body_names_official_app() {
        let body = desktop_file_body("/opt/agentlink");
        assert!(body.contains("Exec=/opt/agentlink"));
        assert!(body.contains("NoDisplay=true"));
        assert!(body.contains("Name=agentlink"));
    }

    #[test]
    fn desktop_restore_token_roundtrips_and_clears_by_kind() {
        let dir = tempfile::tempdir().unwrap();
        assert!(store_desktop_restore(dir.path(), "screencast", "tok-sc-1", 100)
            .unwrap()
            .is_some());
        assert!(store_desktop_restore(dir.path(), "remote-desktop", "tok-rd-2", 101)
            .unwrap()
            .is_some());
        assert_eq!(
            load_desktop_restore(dir.path(), "screencast").unwrap().as_deref(),
            Some("tok-sc-1")
        );
        assert_eq!(
            load_desktop_restore(dir.path(), "remote-desktop")
                .unwrap()
                .as_deref(),
            Some("tok-rd-2")
        );
        clear_desktop_restore(dir.path(), "screencast").unwrap();
        assert!(load_desktop_restore(dir.path(), "screencast").unwrap().is_none());
        assert_eq!(
            load_desktop_restore(dir.path(), "remote-desktop")
                .unwrap()
                .as_deref(),
            Some("tok-rd-2")
        );
    }
}
