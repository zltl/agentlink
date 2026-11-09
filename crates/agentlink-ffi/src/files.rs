//! File operations on mapped guest paths.
//!
//! App storage and granted external storage stay in Rust so the same paths
//! back the fast-transfer engine. SAF folders and live device info go through
//! the Android host.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use agentlink_core::protocol::{DirEntry, FileStat};
use agentlink_core::util::{self, FILE_CHUNK};
use agentlink_core::{Error, Result};
use serde_json::Value;

use crate::host::{self, NodeHost};
use crate::paths::{self, GuestTarget, Roots};

const MAX_READ: u32 = 32 * 1024 * 1024;
const MAX_WRITE: usize = 1024 * 1024;

pub fn stat_guest(roots: &Roots, host: &Arc<dyn NodeHost>, guest: &str) -> Result<FileStat> {
    match paths::classify(roots, guest, false)? {
        GuestTarget::AppRoot => Ok(dir_stat(guest)),
        GuestTarget::Audit => stat_real(&roots.audit, guest),
        GuestTarget::Device => {
            let bytes = device_bytes(host)?;
            Ok(FileStat {
                path: guest.to_string(),
                is_dir: false,
                is_file: true,
                is_symlink: false,
                size: bytes.len() as u64,
                modified_unix_ms: None,
                readonly: true,
                mode: None,
            })
        }
        GuestTarget::Saf(path) => saf_stat(host, &path),
        GuestTarget::Real(path) => stat_real(&path, guest),
    }
}

pub fn list_guest(roots: &Roots, host: &Arc<dyn NodeHost>, guest: &str) -> Result<Vec<DirEntry>> {
    match paths::classify(roots, guest, false)? {
        GuestTarget::AppRoot => {
            let mut entries = vec![
                dir_entry("files"),
                dir_entry("cache"),
                file_entry(
                    "audit.log",
                    fs::metadata(&roots.audit).map(|m| m.len()).unwrap_or(0),
                ),
                file_entry("device.json", device_bytes(host)?.len() as u64),
            ];
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(entries)
        }
        GuestTarget::Audit | GuestTarget::Device => {
            Err(Error::Message(format!("{guest} is not a directory")))
        }
        GuestTarget::Saf(path) => saf_list(host, &path),
        GuestTarget::Real(path) => list_real(&path),
    }
}

pub fn read_guest(
    roots: &Roots,
    host: &Arc<dyn NodeHost>,
    guest: &str,
    offset: u64,
    max_bytes: u32,
) -> Result<Vec<u8>> {
    if max_bytes > MAX_READ {
        return Err(Error::Message(format!(
            "max_bytes {max_bytes} exceeds the {MAX_READ} byte limit"
        )));
    }
    let bytes = match paths::classify(roots, guest, false)? {
        GuestTarget::Audit => fs::read(&roots.audit)?,
        GuestTarget::Device => device_bytes(host)?,
        GuestTarget::Saf(path) => return saf_read(host, &path, offset, max_bytes),
        GuestTarget::AppRoot => {
            return Err(Error::Message("app:/ is a directory".into()));
        }
        GuestTarget::Real(path) => {
            let mut file = fs::File::open(&path)?;
            if offset > 0 {
                file.seek(SeekFrom::Start(offset))?;
            }
            let mut buf = vec![0u8; max_bytes as usize];
            let n = file.read(&mut buf)?;
            buf.truncate(n);
            return Ok(buf);
        }
    };
    let start = offset.min(bytes.len() as u64) as usize;
    let end = (start + max_bytes as usize).min(bytes.len());
    Ok(bytes[start..end].to_vec())
}

pub fn write_guest(
    roots: &Roots,
    host: &Arc<dyn NodeHost>,
    guest: &str,
    offset: u64,
    data: &[u8],
    truncate: bool,
) -> Result<u64> {
    if data.len() > MAX_WRITE {
        return Err(Error::Message("write chunk is larger than 1 MiB".into()));
    }
    match paths::classify(roots, guest, true)? {
        GuestTarget::Saf(path) => {
            let body = host_blocking(
                host,
                "write_file",
                serde_json::json!({
                    "path": path,
                    "offset": offset,
                    "data_b64": util::b64_encode(data),
                    "truncate": truncate,
                }),
            )?;
            Ok(body
                .get("bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(data.len() as u64))
        }
        GuestTarget::Real(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    return Err(Error::NotFound(format!(
                        "parent directory does not exist: {}",
                        parent.display()
                    )));
                }
            }
            let mut file = if truncate {
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&path)?
            } else {
                OpenOptions::new().create(true).write(true).open(&path)?
            };
            if !truncate || offset > 0 {
                file.seek(SeekFrom::Start(offset))?;
            }
            file.write_all(data)?;
            file.flush()?;
            Ok(data.len() as u64)
        }
        GuestTarget::AppRoot | GuestTarget::Audit | GuestTarget::Device => {
            Err(Error::Message("that path is not writable".into()))
        }
    }
}

pub fn mkdir_guest(
    roots: &Roots,
    host: &Arc<dyn NodeHost>,
    guest: &str,
    recursive: bool,
) -> Result<()> {
    match paths::classify(roots, guest, true)? {
        GuestTarget::Saf(path) => {
            host_blocking(
                host,
                "mkdir",
                serde_json::json!({"path": path, "recursive": recursive}),
            )?;
            Ok(())
        }
        GuestTarget::Real(path) => {
            if recursive {
                fs::create_dir_all(&path)?;
            } else {
                fs::create_dir(&path)?;
            }
            Ok(())
        }
        _ => Err(Error::Message("that path is not writable".into())),
    }
}

pub fn remove_guest(
    roots: &Roots,
    host: &Arc<dyn NodeHost>,
    guest: &str,
    recursive: bool,
) -> Result<()> {
    match paths::classify(roots, guest, true)? {
        GuestTarget::Saf(path) => {
            host_blocking(
                host,
                "remove",
                serde_json::json!({"path": path, "recursive": recursive}),
            )?;
            Ok(())
        }
        GuestTarget::Real(path) => {
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() && !meta.file_type().is_symlink() {
                if recursive {
                    fs::remove_dir_all(&path)?;
                } else {
                    fs::remove_dir(&path)?;
                }
            } else {
                fs::remove_file(&path)?;
            }
            Ok(())
        }
        _ => Err(Error::Message("that path is not writable".into())),
    }
}

pub fn rename_guest(roots: &Roots, host: &Arc<dyn NodeHost>, from: &str, to: &str) -> Result<()> {
    let left_saf = matches!(paths::classify(roots, from, true)?, GuestTarget::Saf(_));
    let right = paths::classify(roots, to, true)?;
    let right_saf = matches!(right, GuestTarget::Saf(_));
    if left_saf || right_saf {
        if !(left_saf && right_saf) {
            return Err(Error::Message("cross-store rename is not supported".into()));
        }
        host_blocking(host, "rename", serde_json::json!({"from": from, "to": to}))?;
        return Ok(());
    }
    let from_real = match paths::classify(roots, from, true)? {
        GuestTarget::Real(path) => path,
        _ => return Err(Error::Message("that path is not writable".into())),
    };
    let trailing = agentlink_core::paths::path_trailing_sep(to);
    let to_trimmed = agentlink_core::paths::trim_trailing_sep(to);
    let to_base = match paths::classify(roots, to_trimmed, true)? {
        GuestTarget::Real(path) => path,
        _ => return Err(Error::Message("that path is not writable".into())),
    };
    let to_real = agentlink_core::paths::rename_destination(&from_real, &to_base, trailing)?;
    fs::rename(&from_real, &to_real)?;
    Ok(())
}

pub fn device_bytes(host: &Arc<dyn NodeHost>) -> Result<Vec<u8>> {
    let body = host_blocking(host, "device_info", serde_json::json!({}))?;
    Ok(serde_json::to_vec_pretty(&body)?)
}

fn saf_stat(host: &Arc<dyn NodeHost>, path: &str) -> Result<FileStat> {
    let body = host_blocking(host, "stat", serde_json::json!({"path": path}))?;
    let mut stat: FileStat = serde_json::from_value(body)?;
    stat.path = path.to_string();
    Ok(stat)
}

fn saf_list(host: &Arc<dyn NodeHost>, path: &str) -> Result<Vec<DirEntry>> {
    let body = host_blocking(host, "list_dir", serde_json::json!({"path": path}))?;
    let mut entries: Vec<DirEntry> = serde_json::from_value(body)?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn saf_read(host: &Arc<dyn NodeHost>, path: &str, offset: u64, max_bytes: u32) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = offset;
    let mut left = max_bytes as usize;
    while left > 0 {
        let ask = left.min(FILE_CHUNK);
        let body = host_blocking(
            host,
            "read_file",
            serde_json::json!({"path": path, "offset": at, "max_bytes": ask}),
        )?;
        let data = util::b64_decode(body.get("data_b64").and_then(|v| v.as_str()).unwrap_or(""))?;
        if data.is_empty() {
            break;
        }
        let n = data.len().min(left);
        out.extend_from_slice(&data[..n]);
        at += n as u64;
        left -= n;
        let eof = body.get("eof").and_then(|v| v.as_bool()).unwrap_or(false);
        if eof || data.len() < ask {
            break;
        }
    }
    Ok(out)
}

fn host_blocking(host: &Arc<dyn NodeHost>, kind: &str, payload: Value) -> Result<Value> {
    host::parse_host(&host.unary(kind.to_string(), payload.to_string()))
}

fn stat_real(path: &Path, display: &str) -> Result<FileStat> {
    let meta = fs::symlink_metadata(path)?;
    let followed = fs::metadata(path).unwrap_or_else(|_| meta.clone());
    Ok(FileStat {
        path: display.to_string(),
        is_dir: followed.is_dir(),
        is_file: followed.is_file(),
        is_symlink: meta.file_type().is_symlink(),
        size: followed.len(),
        modified_unix_ms: modified_ms(&followed),
        readonly: followed.permissions().readonly(),
        mode: unix_mode(&followed),
    })
}

fn list_real(path: &Path) -> Result<Vec<DirEntry>> {
    // Follow directory symlinks like Unix `ls` (and agentlink-node list_op).
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Err(Error::Message(format!(
                "{} is a file, not a directory; use `cat` to print it",
                path.display()
            )));
        }
        Err(err) => {
            if let Ok(sm) = fs::symlink_metadata(path) {
                if sm.file_type().is_symlink() {
                    return Err(Error::Message(format!(
                        "{} is a broken symbolic link",
                        path.display()
                    )));
                }
            }
            return Err(err.into());
        }
    }
    let mut entries = Vec::new();
    for item in fs::read_dir(path)? {
        let item = item?;
        let name = item.file_name().to_string_lossy().to_string();
        let Ok(meta) = item.metadata() else { continue };
        let symlink = item.file_type().map(|t| t.is_symlink()).unwrap_or(false);
        entries.push(DirEntry {
            name,
            is_dir: meta.is_dir(),
            is_file: meta.is_file(),
            is_symlink: symlink,
            size: meta.len(),
            modified_unix_ms: modified_ms(&meta),
            mode: unix_mode(&meta),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn dir_stat(display: &str) -> FileStat {
    FileStat {
        path: display.to_string(),
        is_dir: true,
        is_file: false,
        is_symlink: false,
        size: 0,
        modified_unix_ms: None,
        readonly: true,
        mode: None,
    }
}

fn dir_entry(name: &str) -> DirEntry {
    DirEntry {
        name: name.to_string(),
        is_dir: true,
        is_file: false,
        is_symlink: false,
        size: 0,
        modified_unix_ms: None,
        mode: None,
    }
}

fn file_entry(name: &str, size: u64) -> DirEntry {
    DirEntry {
        name: name.to_string(),
        is_dir: false,
        is_file: true,
        is_symlink: false,
        size,
        modified_unix_ms: None,
        mode: None,
    }
}

fn modified_ms(meta: &fs::Metadata) -> Option<i64> {
    let modified = meta.modified().ok()?;
    let dur = modified.duration_since(UNIX_EPOCH).ok()?;
    Some(dur.as_millis() as i64)
}

#[cfg(unix)]
fn unix_mode(meta: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode())
}

#[cfg(not(unix))]
fn unix_mode(_meta: &fs::Metadata) -> Option<u32> {
    None
}
