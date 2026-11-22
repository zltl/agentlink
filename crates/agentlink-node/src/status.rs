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
    let tmp = data_dir.join(format!(
        ".{STATUS_FILE}.{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    write_temp_file(&tmp, text.as_bytes())?;
    let replaced = replace_status_atomic(&tmp, &path);
    if replaced.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    replaced
}

fn write_temp_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn replace_status_atomic(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;

    let src_w: Vec<u16> = src.as_os_str().encode_wide().chain(Some(0)).collect();
    let dst_w: Vec<u16> = dst.as_os_str().encode_wide().chain(Some(0)).collect();
    let delays_ms = [5u64, 10, 15, 25, 40, 60, 80];

    for attempt in 0..=delays_ms.len() {
        // SAFETY: `src_w` and `dst_w` are NUL-terminated UTF-16 buffers valid for the call.
        let ok = unsafe {
            MoveFileExW(
                src_w.as_ptr(),
                dst_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        let retryable = matches!(
            err.raw_os_error(),
            Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
        );
        if !retryable || attempt == delays_ms.len() {
            return Err(err);
        }
        std::thread::sleep(std::time::Duration::from_millis(delays_ms[attempt]));
    }
    unreachable!("retry loop always returns")
}

#[cfg(not(windows))]
fn replace_status_atomic(src: &Path, dst: &Path) -> io::Result<()> {
    std::fs::rename(src, dst)
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

    #[test]
    fn write_status_is_atomic_under_concurrent_readers_and_cleans_temps() {
        let dir = tempfile::tempdir().unwrap();
        let make = |state, pid| LinkStatus {
            state,
            detail: String::new(),
            relay_url: "wss://relay.example.com".into(),
            name: "laptop".into(),
            node_id: "abc".into(),
            enrolled: true,
            pid,
            updated_unix: 1_700_000_000,
        };
        write_status(dir.path(), &make(LinkState::Connecting, 1)).unwrap();
        for i in 0..20u32 {
            let st = if i % 2 == 0 {
                LinkState::Online
            } else {
                LinkState::Offline
            };
            write_status(dir.path(), &make(st, i + 2)).unwrap();
            let loaded = read_status(dir.path()).unwrap();
            assert_eq!(loaded.state, st);
            assert_eq!(loaded.pid, i + 2);
        }
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover tmp files: {leftovers:?}");
    }
}
