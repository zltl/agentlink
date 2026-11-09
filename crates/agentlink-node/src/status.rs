//! Relay link status for the Windows tray and `agentlink tray status`.
//!
//! `status.json` lives in the node data directory. It records whether the
//! process is dialing, online, retrying, or stopped. It does not contain
//! tokens.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const STATUS_FILE: &str = "status.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    Connecting,
    Online,
    Offline,
    Stopped,
}

impl LinkState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connecting => "Connecting",
            Self::Online => "Online",
            Self::Offline => "Offline",
            Self::Stopped => "Stopped",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkStatus {
    pub state: LinkState,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub relay_url: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub node_id: String,
    /// True after a successful hello, and kept across later reconnects.
    #[serde(default)]
    pub enrolled: bool,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub updated_unix: i64,
}

pub fn status_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STATUS_FILE)
}

pub fn write_status(data_dir: &Path, status: &LinkStatus) -> io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let text = serde_json::to_string_pretty(status)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let path = status_path(data_dir);
    let tmp = data_dir.join("status.json.tmp");
    std::fs::write(&tmp, &text)?;
    if std::fs::rename(&tmp, &path).is_err() {
        // Windows cannot replace a file that is still open for reading.
        std::fs::write(&path, &text)?;
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(())
}

pub fn read_status(data_dir: &Path) -> io::Result<LinkStatus> {
    let text = std::fs::read_to_string(status_path(data_dir))?;
    serde_json::from_str(&text).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trip_keeps_the_link_fields() {
        let dir = tempfile::tempdir().unwrap();
        let status = LinkStatus {
            state: LinkState::Online,
            detail: String::new(),
            relay_url: "wss://relay.example.com".into(),
            name: "laptop".into(),
            node_id: "abc".into(),
            enrolled: true,
            pid: 42,
            updated_unix: 1_700_000_000,
        };
        write_status(dir.path(), &status).unwrap();
        let loaded = read_status(dir.path()).unwrap();
        assert_eq!(loaded, status);
        let text = std::fs::read_to_string(status_path(dir.path())).unwrap();
        assert!(text.contains("\"online\""), "{text}");
        assert!(!text.contains("token"), "{text}");
    }
}
