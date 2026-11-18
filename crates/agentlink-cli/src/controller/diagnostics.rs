//! Bounded, sanitized Controller diagnostics for tray launches with null stdout.
//!
//! Manifest path: `{config_dir}/controller-diagnostics.jsonl`
//! Rotate sibling: `{config_dir}/controller-diagnostics.jsonl.1`
//! Cap: 256 KiB active + 256 KiB rotated (never unbounded).
//!
//! Whitelist fields only — no tokens, credential files, SDP, screen/pixels,
//! user text, URL queries, or raw server error strings.
//!
//! All writers serialize through one process-local mutex so concurrent
//! command-loop + first-closure sink emits cannot race past the bound.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use agentlink_core::transport_status::{ClosureCategory, TransportStatus};
use serde::Serialize;

/// Active JSONL file name under the Controller config directory.
pub const DIAG_FILE_NAME: &str = "controller-diagnostics.jsonl";
/// Rotated sibling (one generation).
pub const DIAG_ROTATE_NAME: &str = "controller-diagnostics.jsonl.1";
/// Per-file byte cap (active and rotated each).
pub const DIAG_MAX_BYTES: u64 = 256 * 1024;

/// Whitelisted keys written into each JSONL record.
pub const DIAG_WHITELIST_KEYS: &[&str] = &[
    "ts_unix_ms",
    "pid",
    "build",
    "stage",
    "cmd",
    "config_dir",
    "identity_fp",
    "client_alive",
    "closure_category",
    "ws_close_code",
    "attempt",
    "rebootstrap",
];

#[derive(Clone, Debug, Default)]
pub struct DiagEvent {
    pub stage: &'static str,
    pub cmd: Option<&'static str>,
    pub config_dir: PathBuf,
    pub identity_fp: Option<String>,
    pub client_alive: Option<bool>,
    pub closure: Option<TransportStatus>,
    pub rebootstrap: Option<bool>,
}

#[derive(Serialize)]
struct DiagLine<'a> {
    ts_unix_ms: u64,
    pid: u32,
    build: &'a str,
    stage: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cmd: Option<&'a str>,
    config_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_fp: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_alive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    closure_category: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ws_close_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rebootstrap: Option<bool>,
}

fn diag_mutex() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

/// Absolute path of the active diagnostics JSONL for `config_dir`.
pub fn diagnostics_path(config_dir: &Path) -> PathBuf {
    config_dir.join(DIAG_FILE_NAME)
}

pub fn rotate_path(config_dir: &Path) -> PathBuf {
    config_dir.join(DIAG_ROTATE_NAME)
}

/// Public identity fingerprint for logs: first 16 hex chars of the public id.
pub fn identity_fingerprint(public_hex: &str) -> String {
    let trimmed = public_hex.trim();
    trimmed.chars().take(16).collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn build_line(event: &DiagEvent) -> DiagLine<'_> {
    let (closure_category, ws_close_code, attempt) = match &event.closure {
        Some(status) if status.category != ClosureCategory::None => (
            Some(status.category.as_str()),
            status.ws_close_code,
            Some(status.attempt),
        ),
        _ => (None, None, None),
    };
    DiagLine {
        ts_unix_ms: now_ms(),
        pid: std::process::id(),
        build: crate::version::current(),
        stage: event.stage,
        cmd: event.cmd,
        config_dir: event.config_dir.display().to_string(),
        identity_fp: event.identity_fp.as_deref(),
        client_alive: event.client_alive,
        closure_category,
        ws_close_code,
        attempt,
        rebootstrap: event.rebootstrap,
    }
}

/// Serialize a whitelist-only JSON object (one line, no trailing secrets).
pub fn serialize_event(event: &DiagEvent) -> Result<String, String> {
    let line = build_line(event);
    let raw = serde_json::to_string(&line).map_err(|err| err.to_string())?;
    assert_whitelisted_keys(&raw)?;
    Ok(raw)
}

fn assert_whitelisted_keys(raw: &str) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|err| format!("diag json: {err}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "diag json must be an object".to_string())?;
    for key in obj.keys() {
        if !DIAG_WHITELIST_KEYS.contains(&key.as_str()) {
            return Err(format!("diag key not whitelisted: {key}"));
        }
    }
    for (key, val) in obj {
        if let Some(text) = val.as_str() {
            reject_forbidden_value(key, text)?;
        }
    }
    Ok(())
}

fn reject_forbidden_value(key: &str, text: &str) -> Result<(), String> {
    let lower = text.to_ascii_lowercase();
    if text.contains('?') && (lower.contains("http://") || lower.contains("https://")) {
        return Err(format!("diag forbids URL queries in {key}"));
    }
    for needle in [
        "access_token",
        "refresh_token",
        "authorization:",
        "\"sdp\"",
        "credential",
        "password=",
        "bearer ",
    ] {
        if lower.contains(needle) {
            return Err(format!("diag forbids sensitive marker in {key}"));
        }
    }
    Ok(())
}

fn file_len(path: &Path) -> Result<u64, String> {
    match fs::metadata(path) {
        Ok(meta) => Ok(meta.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err.to_string()),
    }
}

/// Move `path` into `rotate`, never leaving either file above [`DIAG_MAX_BYTES`].
/// Oversized active content keeps only its trailing cap bytes in `.1`.
fn rotate_capped(path: &Path, rotate: &Path) -> Result<(), String> {
    let len = file_len(path)?;
    if len == 0 {
        return Ok(());
    }
    let _ = fs::remove_file(rotate);
    if len <= DIAG_MAX_BYTES {
        fs::rename(path, rotate).map_err(|err| err.to_string())?;
        return Ok(());
    }
    // Oversized preexisting: copy the trailing cap into `.1`, drop the rest.
    let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
    let skip = len - DIAG_MAX_BYTES;
    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(skip))
        .map_err(|err| err.to_string())?;
    let mut buf = Vec::with_capacity(DIAG_MAX_BYTES as usize);
    file.take(DIAG_MAX_BYTES)
        .read_to_end(&mut buf)
        .map_err(|err| err.to_string())?;
    if buf.len() as u64 > DIAG_MAX_BYTES {
        buf.truncate(DIAG_MAX_BYTES as usize);
    }
    fs::write(rotate, &buf).map_err(|err| err.to_string())?;
    let _ = fs::remove_file(path);
    Ok(())
}

fn prepare_append(path: &Path, rotate: &Path, line_with_newline: u64) -> Result<(), String> {
    if line_with_newline > DIAG_MAX_BYTES {
        return Err("diag line exceeds bound".into());
    }
    let len = file_len(path)?;
    // Rotate before write whenever the next append would exceed the hard cap
    // (including the near-cap case where len < cap but len + line > cap).
    if len.saturating_add(line_with_newline) > DIAG_MAX_BYTES {
        rotate_capped(path, rotate)?;
    }
    // After rotate, active must be absent or empty enough for this line.
    let after = file_len(path)?;
    if after.saturating_add(line_with_newline) > DIAG_MAX_BYTES {
        return Err("diag active still over capacity after rotate".into());
    }
    Ok(())
}

fn assert_bounds(path: &Path, rotate: &Path) -> Result<(), String> {
    let active = file_len(path)?;
    let rotated = file_len(rotate)?;
    if active > DIAG_MAX_BYTES {
        return Err(format!("diag active exceeds bound: {active}"));
    }
    if rotated > DIAG_MAX_BYTES {
        return Err(format!("diag rotated exceeds bound: {rotated}"));
    }
    Ok(())
}

/// Append one sanitized event. Creates `config_dir` if needed. Best-effort:
/// failures are ignored by callers so diagnostics never break View.
pub fn emit(event: &DiagEvent) -> Result<(), String> {
    let _guard = diag_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    fs::create_dir_all(&event.config_dir).map_err(|err| err.to_string())?;
    let path = diagnostics_path(&event.config_dir);
    let rotated = rotate_path(&event.config_dir);
    let line = serialize_event(event)?;
    let line_with_newline = (line.len() as u64).saturating_add(1);
    prepare_append(&path, &rotated, line_with_newline)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|err| err.to_string())?;
    writeln!(file, "{line}").map_err(|err| err.to_string())?;
    file.flush().map_err(|err| err.to_string())?;
    drop(file);
    // Defense in depth: never leave an oversize active (should be unreachable).
    if file_len(&path)? > DIAG_MAX_BYTES {
        rotate_capped(&path, &rotated)?;
    }
    assert_bounds(&path, &rotated)?;
    Ok(())
}

/// Best-effort emit used by the worker (never surfaces to UI).
pub fn emit_lossy(event: DiagEvent) {
    let _ = emit(&event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentlink_core::transport_status::TransportStatus;
    use std::sync::Arc;
    use std::thread;
    use tempfile::TempDir;

    fn sample_event(config: &Path, stage: &'static str) -> DiagEvent {
        DiagEvent {
            stage,
            cmd: Some("Monitors"),
            config_dir: config.to_path_buf(),
            identity_fp: Some(identity_fingerprint("abcdef0123456789deadbeef")),
            client_alive: Some(true),
            closure: Some(TransportStatus {
                category: ClosureCategory::WsClose,
                ws_close_code: Some(1000),
                attempt: 2,
            }),
            rebootstrap: Some(false),
        }
    }

    #[test]
    fn manifest_path_and_whitelist_redaction() {
        let tmp = TempDir::new().expect("tmpdir");
        let config = tmp.path().join("config");
        assert_eq!(
            diagnostics_path(&config),
            config.join("controller-diagnostics.jsonl")
        );
        assert_eq!(
            rotate_path(&config),
            config.join("controller-diagnostics.jsonl.1")
        );
        let raw = serialize_event(&sample_event(&config, "bootstrap")).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        let obj = value.as_object().expect("object");
        for key in obj.keys() {
            assert!(
                DIAG_WHITELIST_KEYS.contains(&key.as_str()),
                "unexpected key {key}"
            );
        }
        assert!(!raw.contains("token"));
        assert!(!raw.contains("sdp"));
        assert!(!raw.contains("password"));
        assert_eq!(
            obj.get("identity_fp").and_then(|v| v.as_str()),
            Some("abcdef0123456789")
        );
        assert_eq!(
            obj.get("closure_category").and_then(|v| v.as_str()),
            Some("ws_close")
        );
    }

    #[test]
    fn forbidden_markers_rejected() {
        let tmp = TempDir::new().expect("tmpdir");
        let event = DiagEvent {
            stage: "bootstrap",
            cmd: None,
            config_dir: tmp.path().to_path_buf(),
            identity_fp: Some("access_token=secret".into()),
            client_alive: None,
            closure: None,
            rebootstrap: None,
        };
        let err = serialize_event(&event).expect_err("must reject");
        assert!(err.contains("sensitive") || err.contains("forbid"));
    }

    #[test]
    fn near_cap_rotates_before_append_keeps_hard_bound() {
        let tmp = TempDir::new().expect("tmpdir");
        let config = tmp.path().join("config");
        fs::create_dir_all(&config).expect("mkdir");
        let path = diagnostics_path(&config);
        let event = sample_event(&config, "cmd");
        let line = serialize_event(&event).expect("line");
        let need = (line.len() as u64) + 1;
        // Seed active to cap - need + 1 so one more append would overflow.
        let seed_len = (DIAG_MAX_BYTES - need + 1) as usize;
        fs::write(&path, vec![b'x'; seed_len]).expect("seed");
        assert!(seed_len as u64 + need > DIAG_MAX_BYTES);
        assert!((seed_len as u64) < DIAG_MAX_BYTES);
        emit(&event).expect("emit");
        let active = file_len(&path).expect("active");
        let rotated = file_len(&rotate_path(&config)).expect("rotated");
        assert!(active <= DIAG_MAX_BYTES, "active={active}");
        assert!(rotated <= DIAG_MAX_BYTES, "rotated={rotated}");
        assert!(rotated > 0, "must have rotated near-cap file");
    }

    #[test]
    fn half_line_room_still_rotates() {
        let tmp = TempDir::new().expect("tmpdir");
        let config = tmp.path().join("config");
        fs::create_dir_all(&config).expect("mkdir");
        let path = diagnostics_path(&config);
        let event = sample_event(&config, "cmd");
        let line = serialize_event(&event).expect("line");
        let need = (line.len() as u64) + 1;
        let half = need / 2;
        assert!(half > 0);
        fs::write(&path, vec![b'y'; (DIAG_MAX_BYTES - half) as usize]).expect("seed");
        emit(&event).expect("emit");
        assert!(file_len(&path).expect("a") <= DIAG_MAX_BYTES);
        assert!(file_len(&rotate_path(&config)).expect("r") <= DIAG_MAX_BYTES);
    }

    #[test]
    fn oversized_preexisting_rotated_file_is_capped() {
        let tmp = TempDir::new().expect("tmpdir");
        let config = tmp.path().join("config");
        fs::create_dir_all(&config).expect("mkdir");
        let path = diagnostics_path(&config);
        let oversized = DIAG_MAX_BYTES as usize + 4096;
        fs::write(&path, vec![b'z'; oversized]).expect("seed");
        emit(&sample_event(&config, "cmd")).expect("emit");
        let active = file_len(&path).expect("active");
        let rotated = file_len(&rotate_path(&config)).expect("rotated");
        assert!(active <= DIAG_MAX_BYTES, "active={active}");
        assert!(rotated <= DIAG_MAX_BYTES, "rotated={rotated}");
    }

    #[test]
    fn repeated_rotations_never_exceed_two_capped_files() {
        let tmp = TempDir::new().expect("tmpdir");
        let config = tmp.path().join("config");
        for i in 0..200 {
            let stage = if i % 2 == 0 { "cmd" } else { "retry" };
            emit(&sample_event(&config, stage)).expect("emit");
            assert!(file_len(&diagnostics_path(&config)).expect("a") <= DIAG_MAX_BYTES);
            assert!(file_len(&rotate_path(&config)).expect("r") <= DIAG_MAX_BYTES);
        }
    }

    #[test]
    fn concurrent_writers_serialize_and_keep_bounds() {
        let tmp = TempDir::new().expect("tmpdir");
        let config = Arc::new(tmp.path().join("config"));
        fs::create_dir_all(config.as_path()).expect("mkdir");
        let mut handles = Vec::new();
        for t in 0..8 {
            let config = Arc::clone(&config);
            handles.push(thread::spawn(move || {
                for i in 0..40 {
                    let stage = if (t + i) % 3 == 0 {
                        "first_closure"
                    } else {
                        "cmd"
                    };
                    emit(&sample_event(config.as_path(), stage)).expect("emit");
                }
            }));
        }
        for h in handles {
            h.join().expect("join");
        }
        assert!(file_len(&diagnostics_path(&config)).expect("a") <= DIAG_MAX_BYTES);
        assert!(file_len(&rotate_path(&config)).expect("r") <= DIAG_MAX_BYTES);
    }

    #[test]
    fn bootstrap_auth_rejected_category_serializes_without_raw_error() {
        let tmp = TempDir::new().expect("tmpdir");
        let config = tmp.path().join("config");
        let event = DiagEvent {
            stage: "bootstrap_err",
            cmd: Some("Bootstrap"),
            config_dir: config,
            identity_fp: Some("abcd".into()),
            client_alive: Some(false),
            closure: Some(TransportStatus {
                category: ClosureCategory::AuthRejected,
                ws_close_code: None,
                attempt: 1,
            }),
            rebootstrap: None,
        };
        let raw = serialize_event(&event).expect("serialize");
        assert!(raw.contains("auth_rejected"));
        assert!(!raw.contains("invalid token"));
        assert!(!raw.contains("HelloErr"));
    }
}
