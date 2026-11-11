//! Local client configuration.
//!
//! Flags and environment variables override `config.json`. The MCP server and
//! the CLI read the same file, so `agentlink login` is enough for both.
//!
//! Session refresh (token rotation) takes an advisory lock on
//! `config.json.lock` so two processes cannot each burn a stale refresh
//! token. Writes use [`util::write_secret`] (unique tmp + rename).

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util;

/// Trust mode for a public CA: the OS store plus Mozilla WebPKI roots.
/// Applied only when the caller sets it. There is no built-in relay host.
pub const DEFAULT_RELAY_TRUST: &str = "system+webpki";

/// Always false. Kept so older callers can ask; nothing is treated as a
/// hosted default that skips a certificate pin.
pub fn is_public_relay(_relay: &str) -> bool {
    false
}

/// Trim `relay`. Does not fill in a host or a trust mode.
///
/// Set `--relay` / `AGENTLINK_RELAY` and a fingerprint or `--trust`. A saved
/// config file is left unchanged.
pub fn apply_relay_defaults(relay: &mut String, _fingerprint: &str, _trust: &mut Option<String>) {
    *relay = relay.trim().to_string();
}

#[derive(Debug, Clone)]
pub struct ClientSettings {
    pub relay: String,
    pub token: String,
    /// Pin (`sha256:…`, `spki:sha256:…`, `intermediate:sha256:…`) or a root
    /// mode (`system`, `webpki`). Empty when [`Self::trust`] carries the mode.
    pub fingerprint: String,
    /// `system` or `webpki` when public roots are used, including in addition
    /// to a pin.
    pub trust: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub relay: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// `system` or `webpki`. Combined with [`Self::fingerprint`] when both are set.
    #[serde(default)]
    pub trust: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub access_expires_unix: Option<i64>,
    #[serde(default)]
    pub user: Option<String>,
}

pub fn default_config_dir() -> Result<PathBuf> {
    directories::ProjectDirs::from("dev", "Agentlink", "agentlink")
        .map(|d| d.config_dir().to_path_buf())
        .ok_or_else(|| Error::Message("could not resolve a config directory".into()))
}

pub fn default_data_dir(kind: &str) -> Result<PathBuf> {
    directories::ProjectDirs::from("dev", "Agentlink", "agentlink")
        .map(|d| d.data_dir().join(kind))
        .ok_or_else(|| Error::Message("could not resolve a data directory".into()))
}

pub fn config_path(dir: &Path) -> PathBuf {
    dir.join("config.json")
}

/// Advisory lock beside `config.json` for session refresh / save.
pub fn session_lock_path(dir: &Path) -> PathBuf {
    dir.join("config.json.lock")
}

/// Held for the critical section that re-reads, refreshes, and saves a session.
///
/// Dropping releases the lock. The lock is blocking so a second refresher
/// waits and then re-reads under the lock instead of racing the first.
#[derive(Debug)]
pub struct ConfigSessionLock {
    _file: File,
}

/// Acquire an exclusive advisory lock on `config.json.lock`.
///
/// Creates the config directory when needed. Callers must re-load
/// `config.json` under this lock before deciding to refresh.
pub fn lock_session(dir: &Path) -> Result<ConfigSessionLock> {
    if !dir.as_os_str().is_empty() {
        util::ensure_secret_parent(dir)?;
    }
    let path = session_lock_path(dir);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)?;
    file.lock().map_err(|err| {
        Error::Message(format!("could not lock {}: {err}", path.display()))
    })?;
    Ok(ConfigSessionLock { _file: file })
}

/// True when a stored access token is present and not within `skew_secs` of expiry.
pub fn access_token_is_fresh(file: &FileConfig, now_unix: i64, skew_secs: i64) -> bool {
    let token = file.token.as_deref().unwrap_or("");
    if token.trim().is_empty() {
        return false;
    }
    file.access_expires_unix.unwrap_or(0) > now_unix + skew_secs
}


pub fn load_file(dir: &Path) -> Result<FileConfig> {
    let path = config_path(dir);
    if !path.exists() {
        return Ok(FileConfig::default());
    }
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn save_settings(dir: &std::path::Path, settings: &ClientSettings) -> Result<()> {
    let mut file = load_file(dir).unwrap_or_default();
    file.relay = Some(settings.relay.clone());
    file.token = Some(settings.token.clone());
    file.fingerprint = Some(settings.fingerprint.clone()).filter(|value| !value.is_empty());
    file.trust = settings
        .trust
        .clone()
        .filter(|value| !value.trim().is_empty());
    file.refresh_token = None;
    file.access_expires_unix = None;
    file.user = None;
    write_file(dir, &file)
}

/// Store a username session. `settings.token` is the short-lived access token.
///
/// Takes [`lock_session`] so a concurrent refresher cannot interleave.
pub fn save_session(
    dir: &Path,
    settings: &ClientSettings,
    user: &str,
    refresh_token: &str,
    access_expires_unix: i64,
) -> Result<()> {
    let _lock = lock_session(dir)?;
    save_session_unlocked(dir, settings, user, refresh_token, access_expires_unix)
}

/// Like [`save_session`], but the caller already holds [`lock_session`].
pub fn save_session_unlocked(
    dir: &Path,
    settings: &ClientSettings,
    user: &str,
    refresh_token: &str,
    access_expires_unix: i64,
) -> Result<()> {
    let file = FileConfig {
        relay: Some(settings.relay.clone()),
        token: Some(settings.token.clone()),
        fingerprint: Some(settings.fingerprint.clone()).filter(|value| !value.is_empty()),
        trust: settings
            .trust
            .clone()
            .filter(|value| !value.trim().is_empty()),
        refresh_token: Some(refresh_token.to_string()),
        access_expires_unix: Some(access_expires_unix),
        user: Some(user.to_string()),
    };
    write_file(dir, &file)
}

fn write_file(dir: &std::path::Path, file: &FileConfig) -> Result<()> {
    util::write_secret(
        config_path(dir).as_path(),
        serde_json::to_string_pretty(&file)?.as_bytes(),
    )?;
    Ok(())
}

/// Merge explicit overrides with the config file. Empty strings count as missing.
pub fn load_settings(
    config_dir: &std::path::Path,
    relay: Option<String>,
    token: Option<String>,
    fingerprint: Option<String>,
    trust: Option<String>,
) -> Result<ClientSettings> {
    let file = load_file(config_dir).unwrap_or_default();
    let mut relay = nonempty(relay).or(nonempty(file.relay)).unwrap_or_default();
    let token = nonempty(token).or(nonempty(file.token)).ok_or_else(|| {
        Error::Message(
            "admin token missing (pass --token, set AGENTLINK_TOKEN, or run `agentlink login`)"
                .into(),
        )
    })?;
    let fingerprint = relay_pin_source(
        nonempty(fingerprint),
        nonempty(std::env::var("AGENTLINK_RELAY_PIN").ok()),
        nonempty(file.fingerprint),
    );
    let mut trust = nonempty(trust).or(nonempty(file.trust));
    apply_relay_defaults(&mut relay, &fingerprint, &mut trust);
    if relay.is_empty() {
        return Err(Error::Message(
            "relay URL missing (pass --relay or set AGENTLINK_RELAY; there is no built-in relay)"
                .into(),
        ));
    }
    if fingerprint.is_empty() && trust.is_none() {
        return Err(Error::Message(
            "certificate trust missing (pass --fingerprint sha256:<hex>, --fingerprint system, or --trust webpki)"
                .into(),
        ));
    }
    Ok(ClientSettings {
        relay,
        token,
        fingerprint,
        trust,
    })
}

/// CLI pin, then `AGENTLINK_RELAY_PIN`, then the saved file.
///
/// The value is a leaf (`sha256:`), an SPKI (`spki:sha256:`), or an
/// intermediate pin. Nothing is hardcoded for a particular host.
pub fn relay_pin_source(
    explicit: Option<String>,
    env_pin: Option<String>,
    file_pin: Option<String>,
) -> String {
    nonempty(explicit)
        .or(nonempty(env_pin))
        .or(nonempty(file_pin))
        .unwrap_or_default()
}

/// True when the relay is checked only by a public CA, with no leaf or SPKI pin.
pub fn ca_only_trust(fingerprint: &str, trust: Option<&str>) -> bool {
    if !fingerprint.trim().is_empty() {
        return false;
    }
    matches!(
        trust.map(str::trim),
        Some("system") | Some("webpki") | Some("system+webpki") | Some("webpki+system")
    )
}

/// Warning for a CA-only relay. Node-id pins still have to be checked separately.
pub fn ca_only_warning(fingerprint: &str, trust: Option<&str>) -> Option<String> {
    if !ca_only_trust(fingerprint, trust) {
        return None;
    }
    Some(
        "relay trust is CA-only (no leaf or SPKI pin). Node ids are pinned after the first successful connect. Set AGENTLINK_RELAY_PIN=spki:sha256:<hex>, or pass --fingerprint, to also pin the relay key. A CA check does not bind a node name to its ed25519 id."
            .into(),
    )
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_relay_is_rejected_and_explicit_relay_is_kept() {
        assert!(!is_public_relay("wss://relay.example:443"));
        let trust = crate::RelayTrust::parse("", Some(DEFAULT_RELAY_TRUST)).unwrap();
        assert!(trust.uses_webpki());
        assert!(trust.checks_hostname());
        assert_eq!(trust.trust_value().as_deref(), Some(DEFAULT_RELAY_TRUST));

        let dir = tempfile::tempdir().unwrap();
        let missing = load_settings(dir.path(), None, Some("token".into()), None, None);
        assert!(missing.is_err(), "empty relay must not pick a built-in host");

        let pinned = load_settings(
            dir.path(),
            Some("wss://relay.example:7443".into()),
            Some("token".into()),
            Some(format!("sha256:{}", "ab".repeat(32))),
            None,
        )
        .unwrap();
        assert_eq!(pinned.relay, "wss://relay.example:7443");
        assert!(pinned.trust.is_none());
        assert!(pinned.fingerprint.starts_with("sha256:"));
    }

    #[test]
    fn relay_pin_env_fills_an_empty_fingerprint_and_does_not_override_a_flag() {
        let leaf = format!("sha256:{}", "ab".repeat(32));
        let spki = format!("spki:sha256:{}", "cd".repeat(32));
        assert_eq!(relay_pin_source(None, Some(spki.clone()), None), spki);
        assert_eq!(
            relay_pin_source(Some(leaf.clone()), Some(spki.clone()), None),
            leaf
        );
        assert_eq!(relay_pin_source(None, None, Some(leaf.clone())), leaf);
        assert!(ca_only_trust("", Some("system+webpki")));
        assert!(!ca_only_trust(&spki, Some("webpki")));
        assert!(ca_only_warning("", Some("webpki"))
            .unwrap()
            .contains("CA-only"));
        assert!(ca_only_warning(&leaf, Some("webpki")).is_none());
    }

    #[test]
    fn access_token_freshness_and_refresh_presence() {
        let mut file = FileConfig::default();
        assert!(!access_token_is_fresh(&file, 100, 60));
        file.token = Some("access-dummy".into());
        file.access_expires_unix = Some(200);
        // Remaining life is 100s; skew of 60s still leaves the token fresh.
        assert!(access_token_is_fresh(&file, 100, 60));
        // Within the skew window (200 is not greater than 150+60).
        assert!(!access_token_is_fresh(&file, 150, 60));
        assert!(access_token_is_fresh(&file, 100, 0));
        file.token = Some("   ".into());
        assert!(!access_token_is_fresh(&file, 100, 0));
    }

    #[test]
    fn session_lock_serializes_two_writers() {
        use std::sync::{Arc, Barrier};
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(2));
        let first = {
            let barrier = barrier.clone();
            let dir_path = dir_path.clone();
            std::thread::spawn(move || {
                let lock = lock_session(&dir_path).unwrap();
                barrier.wait();
                std::thread::sleep(Duration::from_millis(80));
                drop(lock);
                "first"
            })
        };
        let waited = {
            let barrier = barrier.clone();
            let dir_path = dir_path.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let started = std::time::Instant::now();
                let _lock = lock_session(&dir_path).unwrap();
                started.elapsed()
            })
        };
        assert_eq!(first.join().unwrap(), "first");
        let waited = waited.join().unwrap();
        assert!(
            waited >= Duration::from_millis(50),
            "second lock returned too early: {waited:?}"
        );
        assert!(session_lock_path(dir.path()).is_file());
    }

    #[test]
    fn save_session_writes_atomically_under_lock() {
        let dir = tempfile::tempdir().unwrap();
        let settings = ClientSettings {
            relay: "wss://relay.example:7443".into(),
            token: "access-dummy".into(),
            fingerprint: format!("sha256:{}", "ab".repeat(32)),
            trust: None,
        };
        save_session(dir.path(), &settings, "alice", "refresh-dummy", 9_999).unwrap();
        let loaded = load_file(dir.path()).unwrap();
        assert_eq!(loaded.user.as_deref(), Some("alice"));
        assert_eq!(loaded.token.as_deref(), Some("access-dummy"));
        assert_eq!(loaded.refresh_token.as_deref(), Some("refresh-dummy"));
        assert_eq!(loaded.access_expires_unix, Some(9_999));
        // Never assert or print token values beyond equality above.
        assert!(session_lock_path(dir.path()).is_file());
    }
}
