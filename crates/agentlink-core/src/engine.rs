//! Sliding-window transfer of files and directory tar streams.
//!
//! The sender keeps `window` chunks in flight and stripes those chunks across
//! file ranges so a large file is not transferred as a single stop-and-wait
//! sequence. Each chunk carries its own offset, which is what resume and
//! out-of-order delivery need.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use crate::compress::{allow_compression, compress_if_smaller, decompress};
use crate::delta::{self, plan_worth, Plan};
use crate::error::{Error, Result};
use crate::util;
use crate::frame::{self, DataFrame};
use crate::sparse::{self, Piece};
use crate::protocol::{
    AcceptMode, ByteRange, CompressPref, ManifestEntry, PlanOp, TransferMsg, TransferStats,
};

/// Pause after each outbound transfer frame, in milliseconds.
///
/// Production leaves this at zero. Tests set it so a relay restart lands
/// while a large copy is still in flight.
pub static TRANSFER_FRAME_PAUSE_MS: AtomicU64 = AtomicU64::new(0);

pub const TAR_PARTIAL_NAME: &str = ".agentlink-tar.partial";

#[derive(Debug)]
pub enum Wire {
    Msg(TransferMsg),
    Frame(Vec<u8>),
}

pub struct Link {
    pub out: mpsc::Sender<Wire>,
    pub inp: mpsc::Receiver<Wire>,
}

impl Link {
    pub fn pair(bound: usize) -> (Self, Self) {
        let (a_tx, b_rx) = mpsc::channel(bound);
        let (b_tx, a_rx) = mpsc::channel(bound);
        (
            Link {
                out: a_tx,
                inp: a_rx,
            },
            Link {
                out: b_tx,
                inp: b_rx,
            },
        )
    }

    pub async fn send_msg(&self, msg: TransferMsg) -> Result<()> {
        self.out
            .send(Wire::Msg(msg))
            .await
            .map_err(|_| Error::Message("transfer closed".into()))
    }

    pub async fn send_frame(&self, bytes: Vec<u8>) -> Result<()> {
        self.out
            .send(Wire::Frame(bytes))
            .await
            .map_err(|_| Error::Message("transfer closed".into()))
    }

    pub async fn recv(&mut self) -> Result<Wire> {
        self.inp
            .recv()
            .await
            .ok_or_else(|| Error::Message("transfer closed".into()))
    }
}

#[derive(Debug, Clone)]
pub struct XferOpts {
    pub chunk_size: usize,
    pub window: usize,
    pub parallel: usize,
    pub compress: CompressPref,
    pub resume: bool,
    pub transport: String,
}

impl Default for XferOpts {
    fn default() -> Self {
        Self {
            chunk_size: frame::DEFAULT_CHUNK,
            window: frame::DEFAULT_WINDOW,
            parallel: frame::DEFAULT_PARALLEL,
            compress: CompressPref::Auto,
            resume: true,
            transport: "relay".into(),
        }
    }
}

impl XferOpts {
    pub fn normalized(mut self) -> Self {
        self.chunk_size = frame::clamp_chunk(self.chunk_size);
        self.window = self.window.clamp(1, 64);
        self.parallel = self.parallel.clamp(1, 32);
        self
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    hash: String,
    size: u64,
    ranges: Vec<ByteRange>,
}

pub fn partial_paths(dest: &Path) -> (PathBuf, PathBuf) {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let dir = dest.parent().unwrap_or_else(|| Path::new("."));
    (
        dir.join(format!(".{name}.agentlink-partial")),
        dir.join(format!(".{name}.agentlink-partial.json")),
    )
}

/// Where a finished partial should land.
///
/// Unix writers follow a symbolic link and overwrite the target. Replacing
/// `dest` with `remove_file` + `rename` would delete the link itself and leave
/// the old target untouched. Resolve symlinks (bounded by `MAX_SYMLINK_HOPS`)
/// and, when `sandbox_root` is set, re-verify the resolved path stays inside
/// the sandbox right at commit time.
fn finalize_dest_path_in_sandbox(dest: &Path, sandbox_root: Option<&Path>) -> Result<PathBuf> {
    if let Some(root) = sandbox_root {
        let resolved = crate::paths::ensure_path_stays_in_sandbox_at_sink(Some(root), dest)?;
        if resolved.is_dir() {
            return Err(Error::Message(format!(
                "{} resolves to a directory",
                dest.display()
            )));
        }
        return Ok(resolved);
    }
    let mut current = dest.to_path_buf();
    for _ in 0..crate::paths::MAX_SYMLINK_HOPS {
        let meta = match fs::symlink_metadata(&current) {
            Ok(meta) => meta,
            Err(err) if err.kind() == ErrorKind::NotFound => break,
            Err(err) => return Err(err.into()),
        };
        if !meta.file_type().is_symlink() {
            break;
        }
        let target = fs::read_link(&current)?;
        current = if target.is_absolute() {
            target
        } else {
            current
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target)
        };
    }
    if fs::symlink_metadata(&current)
        .ok()
        .is_some_and(|m| m.file_type().is_symlink())
    {
        return Err(Error::Message(format!(
            "too many levels of symbolic links: {}",
            dest.display()
        )));
    }
    if current.is_dir() {
        return Err(Error::Message(format!(
            "{} is a symbolic link to a directory",
            dest.display()
        )));
    }
    Ok(current)
}

#[cfg(test)]
fn finalize_dest_path(dest: &Path) -> Result<PathBuf> {
    finalize_dest_path_in_sandbox(dest, None)
}

/// Atomically install `partial` at `dest`, following a symlink destination only
/// when it stays inside `sandbox_root`.
///
/// When `dest` (or its symlink target) already exists, require that it is
/// writable — same gate as `OpenOptions::write(true).open` — before replacing
/// it. Unix `remove_file` only needs directory write permission, so skipping
/// this check let `write`/`cp` replace mode `0444` files and drop their mode
/// bits. After a successful replace, restore the previous permissions.
fn install_partial_at_dest_in_sandbox(
    partial: &Path,
    dest: &Path,
    sandbox_root: Option<&Path>,
) -> Result<()> {
    let final_path = finalize_dest_path_in_sandbox(dest, sandbox_root)?;
    if let Some(parent) = final_path.parent() {
        if let Some(root) = sandbox_root {
            let _ = crate::paths::ensure_path_stays_in_sandbox_at_sink(Some(root), parent)?;
        }
        util::create_dir_all_parent(parent)?;
        if let Some(root) = sandbox_root {
            let _ = crate::paths::ensure_path_stays_in_sandbox_at_sink(Some(root), parent)?;
        }
    }
    let nofollow = sandbox_root.is_some();
    let prev_perms = match fs::symlink_metadata(&final_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(Error::PermissionDenied(format!(
                "refusing to write through unvalidated symbolic link: {}",
                final_path.display()
            )));
        }
        Ok(meta) => {
            crate::paths::open_write_file(&final_path, false, false, nofollow)?;
            Some(meta.permissions())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => return Err(err.into()),
    };
    match fs::rename(partial, &final_path) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::CrossesDevices || is_exdev(&err) => {
            let mut src = File::open(partial)?;
            let mut dst = crate::paths::open_write_file(&final_path, true, true, nofollow)?;
            io::copy(&mut src, &mut dst)?;
            dst.flush()?;
            drop(dst);
            let _ = fs::remove_file(partial);
        }
        Err(_) if final_path.exists() => {
            fs::remove_file(&final_path)?;
            fs::rename(partial, &final_path)?;
        }
        Err(err) => return Err(err.into()),
    }
    if let Some(perms) = prev_perms {
        fs::set_permissions(&final_path, perms)?;
    }
    Ok(())
}

#[cfg(test)]
fn install_partial_at_dest(partial: &Path, dest: &Path) -> Result<()> {
    install_partial_at_dest_in_sandbox(partial, dest, None)
}

fn is_exdev(err: &io::Error) -> bool {
    // Linux EXDEV is 18; keep a raw check for older Rust without CrossesDevices.
    err.raw_os_error() == Some(18)
}

fn persist_partial(path: &Path, hash: &str, size: u64, have: &[ByteRange]) {
    if have.is_empty() {
        return;
    }
    let _ = save_journal(
        path,
        &Journal {
            hash: hash.to_string(),
            size,
            ranges: have.to_vec(),
        },
    );
}

fn load_journal(path: &Path) -> Option<Journal> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Partials older than this are discarded instead of resumed. Live resumes
/// finish within minutes; multi-day litter is abandoned junk that fills `/tmp`.
pub const STALE_PARTIAL_MAX_AGE: Duration = Duration::from_secs(24 * 3600);

fn clear_partial(partial: &Path, journal: &Path) {
    let _ = fs::remove_file(partial);
    let _ = fs::remove_file(journal);
}

fn journal_age(path: &Path) -> Option<Duration> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    modified.elapsed().ok()
}

/// Resume ranges for `hash`/`size`, or clear junk journals/partials.
///
/// Clears when the journal is missing/corrupt, hash/size disagree, the partial
/// blob is gone, or the journal is older than [`STALE_PARTIAL_MAX_AGE`].
fn take_resume_ranges(partial: &Path, journal_path: &Path, hash: &str, size: u64) -> Vec<ByteRange> {
    let Some(journal) = load_journal(journal_path) else {
        if partial.exists() {
            let _ = fs::remove_file(partial);
        }
        return Vec::new();
    };
    let stale = journal_age(journal_path).is_none_or(|age| age > STALE_PARTIAL_MAX_AGE);
    let matches = journal.hash == hash && journal.size == size && (size == 0 || partial.exists());
    if stale || !matches {
        clear_partial(partial, journal_path);
        return Vec::new();
    }
    journal.ranges
}

/// Drop abandoned `.*.agentlink-partial` (+ `.json`) under `dir` (not recursive).
///
/// Clears journals older than [`STALE_PARTIAL_MAX_AGE`], orphan partial blobs
/// (no journal) of that age, and journals whose partial blob is already gone.
/// Fresh in-flight resumes are left alone. Returns how many partials were removed.
pub fn sweep_stale_partials(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut cleared = 0usize;
    let mut journals = Vec::new();
    let mut orphans = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let path = entry.path();
        if name.starts_with('.') && name.ends_with(".agentlink-partial.json") {
            journals.push(path);
        } else if name.starts_with('.') && name.ends_with(".agentlink-partial") {
            orphans.push(path);
        }
    }
    for journal in &journals {
        // `.{name}.agentlink-partial.json` → `.{name}.agentlink-partial`
        let partial = PathBuf::from(journal.to_string_lossy().trim_end_matches(".json"));
        let stale = journal_age(journal).is_none_or(|age| age > STALE_PARTIAL_MAX_AGE);
        let blob_missing = !partial.exists();
        if stale || blob_missing {
            clear_partial(&partial, journal);
            cleared += 1;
        }
        orphans.retain(|p| p != &partial);
    }
    for partial in orphans {
        let age = fs::metadata(&partial)
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|t| t.elapsed().ok());
        if age.is_none_or(|age| age > STALE_PARTIAL_MAX_AGE) {
            let _ = fs::remove_file(&partial);
            cleared += 1;
        }
    }
    cleared
}

fn save_journal(path: &Path, journal: &Journal) -> Result<()> {
    if let Some(parent) = path.parent() {
        util::create_dir_all_parent(parent)?;
    }
    let text = serde_json::to_string(journal)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)?;
    Ok(())
}


/// Normalize a symlink/junction target for the wire: `/` separators, strip
/// Windows `\\?\` / `\??\` prefixes, collapse `C:////` → `C:/`, squeeze
/// duplicate separators, and trim a trailing separator. Idempotent.
fn normalize_link_target_str(raw: &str) -> String {
    let mut s = raw.replace('\\', "/");
    for prefix in ["//?/", "/??/", "//./"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
            break;
        }
    }
    // Extended-length UNC (`\\?\UNC\server\share`) becomes `//server/share`
    // without inventing a drive.
    if s.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("UNC/")) {
        s = format!("//{}", &s[4..]);
    }

    let bytes = s.as_bytes();
    // `C:`, `c:`, `D:` … drive prefix: collapse extra slashes after the colon
    // and trim the trailing separator, keeping a bare `C:/` root.
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let drive = &s[..2];
        let rest = collapse_slashes(&s[2..]);
        let rest = rest.trim_start_matches('/').trim_end_matches('/');
        return if rest.is_empty() {
            format!("{drive}/")
        } else {
            format!("{drive}/{rest}")
        };
    }

    // No drive: keep one leading `/` (or two for a UNC `//server/share`) and
    // leave relative targets like `../inner` untouched apart from `//`.
    let lead = bytes.iter().take_while(|&&b| b == b'/').count();
    let (prefix, body) = match lead {
        0 => ("", &s[..]),
        1 => ("/", &s[1..]),
        _ => ("//", &s[lead..]),
    };
    let body = collapse_slashes(body);
    let body = body.trim_end_matches('/');
    format!("{prefix}{body}")
}

/// Collapse runs of `/` to a single separator.
fn collapse_slashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_slash = false;
    for ch in s.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    out
}

/// Relative path from directory `from` (relative to copy root, may be empty) to
/// `to` (also relative to copy root). Both use `/` separators.
fn relative_from_to(from_dir: &str, to: &str) -> String {
    let from: Vec<&str> = from_dir.split('/').filter(|s| !s.is_empty()).collect();
    let to_parts: Vec<&str> = to.split('/').filter(|s| !s.is_empty()).collect();
    let mut i = 0;
    while i < from.len() && i < to_parts.len() && from[i] == to_parts[i] {
        i += 1;
    }
    let mut out: Vec<&str> = Vec::new();
    for _ in i..from.len() {
        out.push("..");
    }
    for p in &to_parts[i..] {
        out.push(p);
    }
    if out.is_empty() {
        ".".into()
    } else {
        out.join("/")
    }
}

/// True when `path` is `prefix` or a descendant (`prefix/...`), not a sibling
/// that merely shares a string prefix (`prefix-extra`).
fn path_has_root_prefix(path: &str, prefix: &str) -> Option<String> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() {
        return Some(String::new());
    }
    let rest = rest.strip_prefix('/')?;
    Some(rest.to_string())
}

/// Prefer a path relative to the link when the target sits inside the copy root.
/// Absolute Windows junctions otherwise break after a tree is copied elsewhere
/// (and become useless on Linux). Outside-root targets stay normalized absolute.
///
/// Root membership uses a path-component boundary so `…/al-treej-tgt` is not
/// treated as under `…/al-treej` (string `strip_prefix` alone would yield `-tgt`).
fn symlink_target_for_manifest(root: &Path, link_path: &Path, raw: &Path) -> String {
    let parent = link_path.parent().unwrap_or_else(|| Path::new("."));
    let abs_target = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        parent.join(raw)
    };
    let root_s = normalize_link_target_str(&root.to_string_lossy());
    let abs_s = normalize_link_target_str(&abs_target.to_string_lossy());
    let parent_s = normalize_link_target_str(&parent.to_string_lossy());

    #[cfg(windows)]
    let (root_cmp, abs_cmp, parent_cmp) = (
        root_s.to_ascii_lowercase(),
        abs_s.to_ascii_lowercase(),
        parent_s.to_ascii_lowercase(),
    );
    #[cfg(not(windows))]
    let (root_cmp, abs_cmp, parent_cmp) = (root_s.clone(), abs_s.clone(), parent_s.clone());

    if let Some(under) = path_has_root_prefix(&abs_cmp, &root_cmp) {
        if !under.is_empty() {
            let parent_under = path_has_root_prefix(&parent_cmp, &root_cmp)
                .unwrap_or_default();
            return relative_from_to(&parent_under, &under);
        }
    }
    // Outside the root: ship the resolved, normalized absolute form rather
    // than re-deriving from `raw`, so junction substitute names and explicit
    // absolutes share one clean shape (no `C:///` or trailing separators).
    abs_s
}

pub fn walk_manifest(root: &Path) -> Result<Vec<ManifestEntry>> {
    let mut out = Vec::new();
    if !root.is_dir() {
        return Err(Error::Message(format!(
            "{} is not a directory",
            root.display()
        )));
    }
    walk_rec(root, root, &mut out)?;
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

fn walk_rec(root: &Path, dir: &Path, out: &mut Vec<ManifestEntry>) -> Result<()> {
    let mut kids: Vec<_> = fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    kids.sort_by_key(|entry| entry.file_name());
    for entry in kids {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        if meta.file_type().is_symlink() {
            let raw = fs::read_link(&path)?;
            let target = symlink_target_for_manifest(root, &path, &raw);
            out.push(ManifestEntry {
                hash: delta::hash_bytes(format!("symlink:{rel}->{target}").as_bytes()),
                rel,
                size: 0,
                dir: false,
                symlink: Some(target),
            });
            continue;
        }
        if meta.is_dir() {
            out.push(ManifestEntry {
                hash: delta::hash_bytes(format!("dir:{rel}").as_bytes()),
                rel,
                size: 0,
                dir: true,
                symlink: None,
            });
            walk_rec(root, &path, out)?;
        } else if meta.is_file() {
            out.push(ManifestEntry {
                hash: delta::hash_file(&path)?,
                rel,
                size: meta.len(),
                dir: false,
                symlink: None,
            });
        }
    }
    Ok(())
}



pub fn manifest_hash(entries: &[ManifestEntry]) -> String {
    let text = serde_json::to_string(entries).unwrap_or_default();
    delta::hash_bytes(text.as_bytes())
}

fn needed_entries(dest: &Path, entries: &[ManifestEntry]) -> Result<Vec<String>> {
    let mut needed = Vec::new();
    for entry in entries {
        let path = safe_join(dest, &entry.rel)?;
        if entry.dir {
            if !path.is_dir() {
                needed.push(entry.rel.clone());
            }
            continue;
        }
        if let Some(target) = &entry.symlink {
            match fs::read_link(&path) {
                Ok(have) if have.to_string_lossy().replace('\\', "/") == *target => {}
                _ => needed.push(entry.rel.clone()),
            }
            continue;
        }
        match delta::hash_file(&path) {
            Ok(hash) if hash == entry.hash => {}
            _ => needed.push(entry.rel.clone()),
        }
    }
    Ok(needed)
}



fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() || rel.contains('\0') {
        return Err(Error::PermissionDenied(format!("bad relative path: {rel}")));
    }
    let rel_path = Path::new(rel);
    if rel_path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(Error::PermissionDenied(format!(
            "path escapes directory: {rel}"
        )));
    }
    Ok(root.join(rel_path))
}

/// Refuse to create or write through a symlink that points outside `root`.
///
/// `safe_join` is lexical. `File::create` follows an existing symlink, so a
/// tar entry `link/pwned` with `dest/link -> /outside` would otherwise land
/// outside the destination.
fn lexical_absolute(path: &Path) -> Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut out = PathBuf::new();
    for component in abs.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

/// `raw` is the symlink target as stored in the archive, relative to `link`.
fn ensure_link_target_inside(root: &Path, link: &Path, raw: &Path) -> Result<()> {
    if raw
        .components()
        .any(|component| matches!(component, Component::RootDir | Component::Prefix(_)))
        || raw.is_absolute()
    {
        return Err(Error::PermissionDenied(format!(
            "symlink target escapes directory: {}",
            raw.display()
        )));
    }
    let parent = link.parent().unwrap_or(root);
    let lexical = lexical_absolute(&parent.join(raw))?;
    let root_lex = lexical_absolute(root)?;
    if lexical != root_lex && !lexical.starts_with(&root_lex) {
        return Err(Error::PermissionDenied(format!(
            "symlink target escapes directory: {}",
            raw.display()
        )));
    }
    Ok(())
}

fn ensure_unpacked_stays_inside(root: &Path, target: &Path) -> Result<()> {
    let root_c = crate::paths::strip_verbatim_prefix(&fs::canonicalize(root)?);
    let rel = target.strip_prefix(root).map_err(|_| {
        Error::PermissionDenied(format!("path escapes directory: {}", target.display()))
    })?;
    let mut cursor = root.to_path_buf();
    for component in rel.components() {
        cursor.push(component);
        let meta = match fs::symlink_metadata(&cursor) {
            Ok(meta) => meta,
            Err(err) if err.kind() == ErrorKind::NotFound => break,
            Err(err) => return Err(err.into()),
        };
        if meta.file_type().is_symlink() {
            return Err(Error::PermissionDenied(format!(
                "refusing to follow a symlink while unpacking: {}",
                target.display()
            )));
        }
        let canon = crate::paths::strip_verbatim_prefix(&fs::canonicalize(&cursor)?);
        if !crate::paths::is_inside_root(&root_c, &canon) {
            return Err(Error::PermissionDenied(format!(
                "path escapes directory: {}",
                target.display()
            )));
        }
    }
    Ok(())
}


fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        let target_str = target.to_string_lossy();
        let looks_dir = target_str.ends_with('/')
            || target_str.ends_with('\\')
            || link
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target)
                .metadata()
                .map(|m| m.is_dir())
                .unwrap_or(false);
        let result = if looks_dir {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        };
        result.map_err(|e| Error::Message(format!("symlink: {e}")))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(Error::Message(
            "symlink not supported on this platform".into(),
        ))
    }
}


fn mode_mtime_of(path: &Path) -> (Option<u32>, Option<u64>) {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(_) => return (None, None),
    };
    let mode = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Some(meta.permissions().mode())
        }
        #[cfg(not(unix))]
        {
            None
        }
    };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    (mode, mtime)
}

/// Apply Unix mode bits and/or mtime. Best-effort: errors are ignored so a
/// transfer that wrote bytes still succeeds on a filesystem that rejects chmod.
pub fn apply_mode_mtime(path: &Path, mode: Option<u32>, mtime_unix: Option<u64>) {
    if let Some(mode) = mode {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
        }
    }
    if let Some(secs) = mtime_unix {
        let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
        if let Ok(file) = OpenOptions::new().write(true).open(path) {
            let _ = file.set_modified(when);
        } else if let Ok(file) = File::open(path) {
            let _ = file.set_modified(when);
        }
    }
}

pub fn write_tar(
    tar_path: &Path,
    root: &Path,
    entries: &[ManifestEntry],
    needed: &[String],
) -> Result<()> {
    let needed: std::collections::HashSet<&str> = needed.iter().map(String::as_str).collect();
    let mut selected: Vec<_> = entries
        .iter()
        .filter(|entry| needed.contains(entry.rel.as_str()))
        .collect();
    // Dirs first so Windows `symlink_dir` can see the target; then files;
    // symlinks last (junctions/symlink-to-dir need the destination to exist).
    selected.sort_by(|a, b| {
        let rank = |e: &&ManifestEntry| -> u8 {
            if e.dir {
                0
            } else if e.symlink.is_some() {
                2
            } else {
                1
            }
        };
        rank(a).cmp(&rank(b)).then_with(|| a.rel.cmp(&b.rel))
    });
    if let Some(parent) = tar_path.parent() {
        util::create_dir_all_parent(parent)?;
    }
    let file = File::create(tar_path)?;
    let mut builder = tar::Builder::new(file);
    for entry in selected {
        let mut header = tar::Header::new_gnu();
        if entry.dir {
            header.set_entry_type(tar::EntryType::Directory);
            header
                .set_path(format!("{}/", entry.rel))
                .map_err(|e| Error::Message(format!("tar path: {e}")))?;
            header.set_size(0);
            let (mode, mtime) = mode_mtime_of(&root.join(&entry.rel));
            header.set_mode(mode.unwrap_or(0o755));
            header.set_mtime(mtime.unwrap_or(0));
            header.set_cksum();
            builder
                .append(&header, std::io::empty())
                .map_err(|e| Error::Message(format!("tar: {e}")))?;
        } else if let Some(target) = &entry.symlink {
            header.set_entry_type(tar::EntryType::Symlink);
            header
                .set_path(&entry.rel)
                .map_err(|e| Error::Message(format!("tar path: {e}")))?;
            header
                .set_link_name(target)
                .map_err(|e| Error::Message(format!("tar link: {e}")))?;
            header.set_size(0);
            let (mode, mtime) = mode_mtime_of(&root.join(&entry.rel));
            header.set_mode(mode.unwrap_or(0o777));
            header.set_mtime(mtime.unwrap_or(0));
            header.set_cksum();
            builder
                .append(&header, std::io::empty())
                .map_err(|e| Error::Message(format!("tar: {e}")))?;
        } else {
            header
                .set_path(&entry.rel)
                .map_err(|e| Error::Message(format!("tar path: {e}")))?;
            header.set_size(entry.size);
            let src_path = root.join(&entry.rel);
            let (mode, mtime) = mode_mtime_of(&src_path);
            header.set_mode(mode.unwrap_or(0o644));
            header.set_mtime(mtime.unwrap_or(0));
            header.set_cksum();
            let mut file = File::open(&src_path)?;
            builder
                .append(&header, &mut file)
                .map_err(|e| Error::Message(format!("tar: {e}")))?;
        }
    }
        builder
        .finish()
        .map_err(|e| Error::Message(format!("tar: {e}")))?;
    Ok(())
}

pub fn unpack_tar(tar_path: &Path, dest: &Path) -> Result<u32> {
    util::create_dir_all_as_dir(dest)?;
    let file = File::open(tar_path)?;
    let mut archive = tar::Archive::new(file);
    let mut files = 0u32;
    let entries = archive
        .entries()
        .map_err(|e| Error::Message(format!("tar: {e}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| Error::Message(format!("tar: {e}")))?;
        let rel = entry
            .path()
            .map_err(|e| Error::Message(format!("tar path: {e}")))?
            .to_string_lossy()
            .trim_end_matches('/')
            .to_string();
        if rel.is_empty() {
            continue;
        }
        let out = safe_join(dest, &rel)?;
        ensure_unpacked_stays_inside(dest, &out)?;
        let mode = entry.header().mode().ok();
        let mtime = entry.header().mtime().ok();
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            util::create_dir_all_as_dir(&out)?;
            apply_mode_mtime(&out, mode, mtime);
        } else if entry_type.is_symlink() {
            if let Some(parent) = out.parent() {
                util::create_dir_all_parent(parent)?;
                ensure_unpacked_stays_inside(dest, parent)?;
            }
            let target = entry
                .link_name()
                .map_err(|e| Error::Message(format!("tar link: {e}")))?
                .ok_or_else(|| Error::Message(format!("tar symlink missing target: {rel}")))?;
            // Re-normalize wire targets so an older peer's `C:///` or
            // trailing `/` is not written to disk as-is.
            let target = PathBuf::from(normalize_link_target_str(&target.to_string_lossy()));
            // Absolute targets and `..` that leave dest would let chmod follow
            // the new link onto a file outside the unpack root.
            ensure_link_target_inside(dest, &out, &target)?;
            if out.symlink_metadata().is_ok() {
                let _ = fs::remove_file(&out);
            }
            create_symlink(&target, &out)?;
            // Do not chmod or utimens through the link.
            files += 1;
        } else if entry_type.is_file() || entry_type == tar::EntryType::Continuous {
            if let Some(parent) = out.parent() {
                util::create_dir_all_parent(parent)?;
                ensure_unpacked_stays_inside(dest, parent)?;
            }
            if fs::symlink_metadata(&out)
                .ok()
                .is_some_and(|m| m.file_type().is_symlink())
            {
                fs::remove_file(&out)?;
            }
            let mut file = crate::paths::open_write_file(&out, true, true, true)?;
            std::io::copy(&mut entry, &mut file)?;
            drop(file);
            apply_mode_mtime(&out, mode, mtime);
            files += 1;
        } else {
            return Err(Error::Protocol(format!(
                "unsupported tar entry type {:?} for {}",
                entry_type, rel
            )));
        }
    }
    Ok(files)
}

fn read_at(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut file = open_pullable_file(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_at(path: &Path, offset: u64, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    // All-zero payload is a hole. Writing it would densify a sparse file
    // (agentlink cp of a 100MiB truncate turned 64KiB of real data into 100MiB
    // on disk). Punch / leave the gap instead — same as `rsync --sparse`
    // receive. On Windows this also FSCTL_SET_SPARSE so NTFS does not allocate.
    // BLAKE3 still sees zeroes when hashing.
    if !data.is_empty() && data.iter().all(|&b| b == 0) {
        sparse::punch_hole(&file, offset, data.len() as u64)?;
        return Ok(());
    }
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)?;
    Ok(())
}

/// Mark `[offset, offset+len)` as present zeros without allocating or densifying.
fn write_hole(path: &Path, offset: u64, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    let file = OpenOptions::new().write(true).open(path)?;
    sparse::punch_hole(&file, offset, len)?;
    Ok(())
}



fn stripe_pieces(chunks: Vec<Piece>, parallel: usize) -> Vec<Vec<Piece>> {
    let n = parallel.max(1);
    let mut groups = vec![Vec::new(); n];
    for (i, chunk) in chunks.into_iter().enumerate() {
        groups[i % n].push(chunk);
    }
    groups.retain(|group| !group.is_empty());
    groups
}

fn release(inflight: &Mutex<HashMap<u64, OwnedSemaphorePermit>>, ranges: &[ByteRange]) {
    let Ok(mut map) = inflight.lock() else {
        return;
    };
    map.retain(|off, _| {
        !ranges
            .iter()
            .any(|range| *off >= range.start && *off < range.end)
    });
}

struct PumpStats {
    payload_bytes: u64,
    compressed: bool,
}

/// Bytes already present (`total - scheduled`) plus bytes handed to the wire
/// in this call, capped at `total`. `scheduled` is the logical length of the
/// ranges this call will send.
fn transfer_progress(total: u64, scheduled: u64, sent_this_call: u64) -> u64 {
    let baseline = total.saturating_sub(scheduled);
    baseline.saturating_add(sent_this_call).min(total)
}

async fn send_blob(
    link: &mut Link,
    path: &Path,
    ranges: &[ByteRange],
    request_id: &str,
    chunk: usize,
    window: usize,
    parallel: usize,
    compress: bool,
    tar: bool,
    progress: &Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
    total: u64,
) -> Result<PumpStats> {
    // SEEK_DATA / SEEK_HOLE so sparse files skip reading and wiring holes.
    // Filesystems without the seeks fall back to all-data pieces.
    let pieces = sparse::partition(path, ranges).unwrap_or_else(|_| {
        ranges
            .iter()
            .filter(|r| r.end > r.start)
            .map(|r| Piece {
                start: r.start,
                end: r.end,
                hole: false,
            })
            .collect()
    });
    let chunks = sparse::chunk_pieces(&pieces, chunk, sparse::FILE_MAX_HOLE);
    let payload = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let any_compressed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let try_compress = Arc::new(std::sync::atomic::AtomicBool::new(compress));
    let inflight: Arc<Mutex<HashMap<u64, OwnedSemaphorePermit>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let sem = Arc::new(Semaphore::new(window.max(1)));
    let mut workers: Vec<JoinHandle<Result<()>>> = Vec::new();
    // stripe expects (off,end); keep hole flag alongside via parallel index.
    // Report cumulative logical bytes, not the latest chunk offset. Parallel
    // workers finish out of order; an offset would make percent jump backward.
    let scheduled: u64 = chunks
        .iter()
        .map(|piece| piece.end.saturating_sub(piece.start))
        .sum();
    let logical_sent = Arc::new(AtomicU64::new(0));
    let striped = stripe_pieces(chunks, parallel);
    for group in striped {
        let path = path.to_path_buf();
        let request_id = request_id.to_string();
        let out = link.out.clone();
        let inflight = inflight.clone();
        let sem = sem.clone();
        let payload = payload.clone();
        let any_compressed = any_compressed.clone();
        let try_compress = try_compress.clone();
        let progress = progress.clone();
        let logical_sent = logical_sent.clone();
        workers.push(tokio::spawn(async move {
            for piece in group {
                let off = piece.start;
                let end = piece.end;
                let permit = sem
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| Error::Message("transfer window closed".into()))?;
                let raw_len = (end - off) as u32;
                let frame = if piece.hole {
                    DataFrame {
                        request_id: request_id.clone(),
                        offset: off,
                        raw_len,
                        compressed: false,
                        hole: true,
                        tar,
                        payload: Vec::new(),
                    }
                } else {
                    let data = read_at(&path, off, (end - off) as usize)?;
                    // Even without SEEK_HOLE (or when the FS lied), all-zero
                    // chunks become hole frames so compress-off stays cheap.
                    if !data.is_empty() && data.iter().all(|&b| b == 0) {
                        DataFrame {
                            request_id: request_id.clone(),
                            offset: off,
                            raw_len,
                            compressed: false,
                            hole: true,
                            tar,
                            payload: Vec::new(),
                        }
                    } else {
                        let compressed_payload =
                            if try_compress.load(std::sync::atomic::Ordering::Relaxed) {
                                compress_if_smaller(&data)
                            } else {
                                None
                            };
                        let (bytes, is_zstd) = if let Some(c) = compressed_payload {
                            any_compressed.store(true, std::sync::atomic::Ordering::Relaxed);
                            (c, true)
                        } else {
                            // A short tail often fails the size check. Only incompressible
                            // chunks turn compression off for the rest of the file.
                            if data.len() >= 4096 {
                                try_compress.store(false, std::sync::atomic::Ordering::Relaxed);
                            }
                            (data, false)
                        };
                        DataFrame {
                            request_id: request_id.clone(),
                            offset: off,
                            raw_len,
                            compressed: is_zstd,
                            hole: false,
                            tar,
                            payload: bytes,
                        }
                    }
                };
                let encoded = frame::encode(&frame)?;
                payload.fetch_add(
                    frame.payload.len() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                {
                    let mut map = inflight
                        .lock()
                        .map_err(|_| Error::Message("window lock poisoned".into()))?;
                    map.insert(off, permit);
                }
                out.send(Wire::Frame(encoded))
                    .await
                    .map_err(|_| Error::Message("transfer closed".into()))?;
                let pause = TRANSFER_FRAME_PAUSE_MS.load(Ordering::Relaxed);
                if pause > 0 {
                    tokio::time::sleep(Duration::from_millis(pause)).await;
                }
                let n = u64::from(raw_len);
                let sent_this_call = logical_sent
                    .fetch_add(n, Ordering::Relaxed)
                    .saturating_add(n);
                if let Some(hook) = &progress {
                    hook(transfer_progress(total, scheduled, sent_this_call), total);
                }
            }
            Ok(())
        }));
    }

    let mut workers_done = workers.is_empty();
    let joined = futures_util::future::join_all(workers);
    let mut joined = std::pin::pin!(joined);
    let mut finish_sent = false;
    let mut done = None;
    // Zero-byte files (and any Accept with no missing ranges) spawn no
    // workers. The select below only wakes on inbound Acks/Done, so without
    // an immediate Finish the peer stalls forever waiting for frames that
    // never come — live `agentlink cp` of an empty file hung on relay.
    if workers_done {
        link.send_msg(TransferMsg::Finish).await?;
        finish_sent = true;
    }
    loop {
        tokio::select! {
            incoming = link.inp.recv() => {
                match incoming {
                    Some(Wire::Msg(TransferMsg::Ack { ranges })) => release(&inflight, &ranges),
                    Some(Wire::Msg(TransferMsg::Done { stats })) => done = Some(stats),
                    Some(Wire::Msg(TransferMsg::Failed { message })) => {
                        return Err(Error::Message(message));
                    }
                    Some(_) => {}
                    None => return Err(Error::Message("transfer closed".into())),
                }
            }
            results = &mut joined, if !workers_done => {
                workers_done = true;
                for result in results {
                    result.map_err(|e| Error::Message(format!("transfer task: {e}")))??;
                }
            }
        }
        let inflight_empty = inflight.lock().map(|map| map.is_empty()).unwrap_or(true);
        if workers_done && inflight_empty && !finish_sent {
            link.send_msg(TransferMsg::Finish).await?;
            finish_sent = true;
        }
        if finish_sent {
            if let Some(stats) = done {
                return Ok(PumpStats {
                    payload_bytes: payload.load(std::sync::atomic::Ordering::Relaxed),
                    compressed: any_compressed.load(std::sync::atomic::Ordering::Relaxed)
                        || stats.compressed,
                });
            }
        }
    }
}

async fn recv_blob(
    link: &mut Link,
    partial: &Path,
    journal_path: &Path,
    size: u64,
    expect_hash: &str,
    have: Vec<ByteRange>,
    final_dest: &Path,
    tar: bool,
    progress: &Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
) -> Result<(u64, bool)> {
    recv_blob_in_sandbox(
        link,
        partial,
        journal_path,
        size,
        expect_hash,
        have,
        final_dest,
        None,
        tar,
        progress,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn recv_blob_in_sandbox(
    link: &mut Link,
    partial: &Path,
    journal_path: &Path,
    size: u64,
    expect_hash: &str,
    mut have: Vec<ByteRange>,
    final_dest: &Path,
    sandbox_root: Option<&Path>,
    tar: bool,
    progress: &Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
) -> Result<(u64, bool)> {
    if size > 0 {
        if let Some(parent) = partial.parent() {
            util::create_dir_all_parent(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(partial)?;
        // Mark sparse BEFORE extending so NTFS does not allocate the full logical size.
        sparse::prepare_sparse_len(&file, size)?;
    } else if !partial.exists() {
        if let Some(parent) = partial.parent() {
            util::create_dir_all_parent(parent)?;
        }
        File::create(partial)?;
    }
    let mut payload = 0u64;
    let mut compressed = false;
    let mut since_save = 0u64;
    loop {
        let incoming = match link.recv().await {
            Ok(msg) => msg,
            Err(err) => {
                persist_partial(journal_path, expect_hash, size, &have);
                return Err(err);
            }
        };
        match incoming {
            Wire::Frame(bytes) => {
                let frame = match frame::decode(&bytes) {
                    Ok(frame) => frame,
                    Err(err) => {
                        persist_partial(journal_path, expect_hash, size, &have);
                        return Err(err);
                    }
                };
                // Wire payload bytes (compressed or hole header), not logical raw_len.
                payload += frame.payload.len() as u64;
                let Some(chunk_end) = frame.offset.checked_add(u64::from(frame.raw_len)) else {
                    persist_partial(journal_path, expect_hash, size, &have);
                    return Err(Error::Protocol("chunk offset overflow".into()));
                };
                if chunk_end > size {
                    persist_partial(journal_path, expect_hash, size, &have);
                    return Err(Error::Protocol(format!(
                        "chunk range {}..{} exceeds declared blob size {}",
                        frame.offset, chunk_end, size
                    )));
                }
                if frame.hole {
                    if !frame.payload.is_empty() {
                        persist_partial(journal_path, expect_hash, size, &have);
                        return Err(Error::Message("hole frame must have empty payload".into()));
                    }
                    if u64::from(frame.raw_len) > sparse::FILE_MAX_HOLE {
                        persist_partial(journal_path, expect_hash, size, &have);
                        return Err(Error::Protocol(format!(
                            "hole frame {} exceeds {} byte cap",
                            frame.raw_len,
                            sparse::FILE_MAX_HOLE
                        )));
                    }
                    if size == 0 {
                        continue;
                    }
                    // Extend with zeros without densifying (no payload alloc).
                    write_hole(partial, frame.offset, u64::from(frame.raw_len))?;
                } else {
                    if (frame.raw_len as usize) > frame::MAX_CHUNK {
                        persist_partial(journal_path, expect_hash, size, &have);
                        return Err(Error::Protocol(format!(
                            "chunk raw_len {} exceeds {} byte cap",
                            frame.raw_len,
                            frame::MAX_CHUNK
                        )));
                    }
                    let raw = if frame.compressed {
                        match decompress(&frame.payload, frame.raw_len as usize) {
                            Ok(raw) => {
                                compressed = true;
                                raw
                            }
                            Err(err) => {
                                persist_partial(journal_path, expect_hash, size, &have);
                                return Err(err);
                            }
                        }
                    } else {
                        frame.payload
                    };
                    if raw.len() as u32 != frame.raw_len {
                        persist_partial(journal_path, expect_hash, size, &have);
                        return Err(Error::Message("uncompressed chunk length mismatch".into()));
                    }
                    if size == 0 {
                        continue;
                    }
                    write_at(partial, frame.offset, &raw)?;
                }
                have.push(ByteRange {
                    start: frame.offset,
                    end: chunk_end,
                });
                have = delta::merge_ranges(have);
                since_save += frame.raw_len as u64;
                if since_save >= 4 * 1024 * 1024 {
                    save_journal(
                        journal_path,
                        &Journal {
                            hash: expect_hash.to_string(),
                            size,
                            ranges: have.clone(),
                        },
                    )?;
                    since_save = 0;
                }
                if let Err(err) = link
                    .send_msg(TransferMsg::Ack {
                        ranges: vec![ByteRange {
                            start: frame.offset,
                            end: frame.offset + u64::from(frame.raw_len),
                        }],
                    })
                    .await
                {
                    persist_partial(journal_path, expect_hash, size, &have);
                    return Err(err);
                }
                if let Some(hook) = progress {
                    let filled: u64 = have.iter().map(|range| range.len()).sum();
                    hook(filled.min(size), size);
                }
            }
            Wire::Msg(TransferMsg::Finish) => {
                let missing = delta::missing_ranges(size, &have);
                if !missing.is_empty() {
                    persist_partial(journal_path, expect_hash, size, &have);
                    let message = format!("incomplete transfer, {} ranges missing", missing.len());
                    let _ = link
                        .send_msg(TransferMsg::Failed {
                            message: message.clone(),
                        })
                        .await;
                    return Err(Error::Message(message));
                }
                if size > 0 || partial.exists() {
                    let got = delta::hash_file(partial)?;
                    if got != expect_hash {
                        return Err(Error::Message(
                            "transferred bytes failed the BLAKE3 check".into(),
                        ));
                    }
                }
                if tar {
                    // Caller unpacks and sends Done.
                    let _ = final_dest;
                    return Ok((payload, compressed));
                }
                install_partial_at_dest_in_sandbox(partial, final_dest, sandbox_root)?;
                fs::remove_file(journal_path).ok();
                return Ok((payload, compressed));
            }
            Wire::Msg(TransferMsg::Failed { message }) => {
                persist_partial(journal_path, expect_hash, size, &have);
                return Err(Error::Message(message));
            }
            Wire::Msg(_) => {}
        }
    }
}

fn done_stats(
    logical: u64,
    payload: u64,
    skipped: bool,
    files: u32,
    files_skipped: u32,
    compressed: bool,
    transport: &str,
    delta_copy: u64,
    resumed: u64,
) -> TransferStats {
    TransferStats {
        logical_bytes: logical,
        payload_bytes: payload,
        skipped,
        files,
        files_skipped,
        compressed,
        transport: transport.into(),
        delta_copy_bytes: delta_copy,
        resumed_bytes: resumed,
    }
}

async fn send_done(link: &Link, stats: TransferStats) -> Result<TransferStats> {
    link.send_msg(TransferMsg::Done {
        stats: stats.clone(),
    })
    .await?;
    Ok(stats)
}

fn resumed_bytes(size: u64, missing: &[ByteRange]) -> u64 {
    let missing: u64 = missing.iter().map(|r| r.len()).sum();
    size.saturating_sub(missing)
}

pub async fn perform_push(
    local: &Path,
    remote: &str,
    link: &mut Link,
    request_id: &str,
    opts: &XferOpts,
    progress: &Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
) -> Result<TransferStats> {
    let opts = opts.clone().normalized();
    ensure_pullable_file(local)?;
    let size = local.metadata()?.len();
    let hash = if size == 0 {
        delta::hash_bytes(b"")
    } else {
        delta::hash_file(local)?
    };
    let (mode, mtime_unix) = mode_mtime_of(local);
    link.send_msg(TransferMsg::Push {
        path: remote.to_string(),
        size,
        hash: hash.clone(),
        chunk_size: opts.chunk_size as u32,
        compress: opts.compress,
        resume: opts.resume,
        mode,
        mtime_unix,
    })
    .await?;
    respond_as_source(local, link, request_id, &hash, size, &opts, progress, false).await
}

async fn respond_as_source(
    local: &Path,
    link: &mut Link,
    request_id: &str,
    hash: &str,
    size: u64,
    opts: &XferOpts,
    progress: &Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
    tar: bool,
) -> Result<TransferStats> {
    loop {
        match link.recv().await? {
            Wire::Msg(TransferMsg::Accept { mode }) => match mode {
                AcceptMode::Skip => {
                    return match link.recv().await? {
                        Wire::Msg(TransferMsg::Done { stats }) => Ok(stats),
                        other => Err(Error::Protocol(format!("expected done, got {other:?}"))),
                    };
                }
                AcceptMode::Full { missing } => {
                    let resumed = resumed_bytes(size, &missing);
                    let pumped = send_blob(
                        link,
                        local,
                        &missing,
                        request_id,
                        opts.chunk_size,
                        opts.window,
                        opts.parallel,
                        allow_compression(opts.compress, local),
                        tar,
                        progress,
                        size,
                    )
                    .await?;
                    return Ok(done_stats(
                        size,
                        pumped.payload_bytes,
                        false,
                        1,
                        0,
                        pumped.compressed,
                        &opts.transport,
                        0,
                        resumed,
                    ));
                }
                AcceptMode::Files { .. } => {
                    return Err(Error::Protocol(
                        "file transfer received a directory accept".into(),
                    ));
                }
            },
            Wire::Msg(TransferMsg::Sigs { table }) => {
                if size > 256 * 1024 * 1024 {
                    link.send_msg(TransferMsg::PreferFull).await?;
                    continue;
                }
                let mut data = Vec::new();
                File::open(local)?.read_to_end(&mut data)?;
                let plan = delta::plan(&data, &table);
                if !plan_worth(&plan, size) {
                    link.send_msg(TransferMsg::PreferFull).await?;
                    continue;
                }
                link.send_msg(TransferMsg::Plan {
                    out_size: size,
                    out_hash: hash.to_string(),
                    ops: plan.ops.clone(),
                })
                .await?;
                let literals: Vec<ByteRange> = plan
                    .ops
                    .iter()
                    .filter_map(|op| match op {
                        PlanOp::Lit { new, len } => Some(ByteRange {
                            start: *new,
                            end: *new + *len,
                        }),
                        PlanOp::Copy { .. } => None,
                    })
                    .collect();
                let pumped = send_blob(
                    link,
                    local,
                    &literals,
                    request_id,
                    opts.chunk_size,
                    opts.window,
                    opts.parallel,
                    allow_compression(opts.compress, local),
                    false,
                    progress,
                    size,
                )
                .await?;
                return Ok(done_stats(
                    size,
                    pumped.payload_bytes,
                    false,
                    1,
                    0,
                    pumped.compressed,
                    &opts.transport,
                    plan.copy_bytes,
                    0,
                ));
            }
            Wire::Msg(TransferMsg::Done { stats }) => return Ok(stats),
            Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected transfer message: {other:?}"
                )))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_push(
    dest: &Path,
    remote_label: &Path,
    size: u64,
    hash: String,
    chunk_hint: u32,
    compress: CompressPref,
    resume: bool,
    link: &mut Link,
    transport: &str,
    mode: Option<u32>,
    mtime_unix: Option<u64>,
) -> Result<TransferStats> {
    serve_push_confined(
        None,
        dest,
        remote_label,
        size,
        hash,
        chunk_hint,
        compress,
        resume,
        link,
        transport,
        mode,
        mtime_unix,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_push_confined(
    sandbox_root: Option<&Path>,
    dest: &Path,
    remote_label: &Path,
    size: u64,
    hash: String,
    chunk_hint: u32,
    compress: CompressPref,
    resume: bool,
    link: &mut Link,
    transport: &str,
    mode: Option<u32>,
    mtime_unix: Option<u64>,
) -> Result<TransferStats> {
    let _ = (chunk_hint, compress);
    let dest_checked = crate::paths::ensure_path_stays_in_sandbox_at_sink(sandbox_root, dest)?;
    let dest = dest_checked.as_path();
    if dest.is_file() {
        let existing = if dest.metadata()?.len() == 0 {
            delta::hash_bytes(b"")
        } else {
            delta::hash_file(dest)?
        };
        if existing == hash {
            apply_mode_mtime(dest, mode, mtime_unix);
            let stats = done_stats(size, 0, true, 1, 1, false, transport, 0, size);
            link.send_msg(TransferMsg::Accept {
                mode: AcceptMode::Skip,
            })
            .await?;
            return send_done(link, stats).await;
        }
    }
    let (partial, journal_path) = partial_paths(dest);
    let have = if resume {
        take_resume_ranges(&partial, &journal_path, &hash, size)
    } else {
        clear_partial(&partial, &journal_path);
        Vec::new()
    };
    if have.is_empty()
        && dest.is_file()
        && size >= delta::DELTA_MIN_SIZE
        && dest.metadata()?.len() >= delta::DELTA_MIN_SIZE
    {
        let table = delta::signatures_file(dest, delta::DEFAULT_BLOCK)?;
        link.send_msg(TransferMsg::Sigs {
            table: table.clone(),
        })
        .await?;
        match link.recv().await? {
            Wire::Msg(TransferMsg::PreferFull) => {}
            Wire::Msg(TransferMsg::Plan {
                out_size,
                out_hash,
                ops,
            }) => {
                apply_copies(dest, &partial, out_size, &ops)?;
                let mut ranges = Vec::new();
                let mut copy_bytes = 0u64;
                for op in &ops {
                    if let PlanOp::Copy { new, len, .. } = op {
                        ranges.push(ByteRange {
                            start: *new,
                            end: *new + *len,
                        });
                        copy_bytes += *len;
                    }
                }
                save_journal(
                    &journal_path,
                    &Journal {
                        hash: out_hash.clone(),
                        size: out_size,
                        ranges: ranges.clone(),
                    },
                )?;
                let (payload, compressed) = recv_blob_in_sandbox(
                    link,
                    &partial,
                    &journal_path,
                    out_size,
                    &out_hash,
                    ranges,
                    dest,
                    sandbox_root,
                    false,
                    &None,
                )
                .await?;
                apply_mode_mtime(dest, mode, mtime_unix);
                let stats = done_stats(
                    out_size, payload, false, 1, 0, compressed, transport, copy_bytes, 0,
                );
                return send_done(link, stats).await;
            }
            Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
            other => {
                return Err(Error::Protocol(format!(
                    "expected a delta plan, got {other:?}"
                )))
            }
        }
    }
    let missing = delta::missing_ranges(size, &have);
    let resumed = resumed_bytes(size, &missing);
    link.send_msg(TransferMsg::Accept {
        mode: AcceptMode::Full { missing },
    })
    .await?;
    let (payload, compressed) = recv_blob_in_sandbox(
        link,
        &partial,
        &journal_path,
        size,
        &hash,
        have,
        dest,
        sandbox_root,
        false,
        &None,
    )
    .await?;
    let _ = remote_label;
    apply_mode_mtime(dest, mode, mtime_unix);
    let stats = done_stats(
        size, payload, false, 1, 0, compressed, transport, 0, resumed,
    );
    send_done(link, stats).await
}

fn apply_copies(old: &Path, partial: &Path, out_size: u64, ops: &[PlanOp]) -> Result<()> {
    if let Some(parent) = partial.parent() {
        util::create_dir_all_parent(parent)?;
    }
    let mut out = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(partial)?;
    sparse::prepare_sparse_len(&out, out_size)?;
    let mut src = File::open(old)?;
    for op in ops {
        if let PlanOp::Copy { old: at, new, len } = op {
            src.seek(SeekFrom::Start(*at))?;
            let mut buf = vec![0u8; *len as usize];
            src.read_exact(&mut buf)?;
            out.seek(SeekFrom::Start(*new))?;
            out.write_all(&buf)?;
        }
    }
    Ok(())
}

pub async fn perform_pull(
    remote: &str,
    local: &Path,
    link: &mut Link,
    _request_id: &str,
    opts: &XferOpts,
    progress: &Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
) -> Result<TransferStats> {
    let opts = opts.clone().normalized();
    let (have_hash, sigs, have_ranges) = if local.is_file() {
        let hash = delta::hash_file(local).ok();
        let size = local.metadata().map(|m| m.len()).unwrap_or(0);
        let sigs = if size >= delta::DELTA_MIN_SIZE {
            delta::signatures_file(local, delta::DEFAULT_BLOCK).ok()
        } else {
            None
        };
        (hash, sigs, Vec::new())
    } else {
        (None, None, Vec::new())
    };
    link.send_msg(TransferMsg::Pull {
        path: remote.to_string(),
        have_hash,
        have_ranges,
        chunk_size: opts.chunk_size as u32,
        compress: opts.compress,
        sigs,
    })
    .await?;
    receive_from_source(local, link, &opts, progress).await
}

async fn receive_from_source(
    local: &Path,
    link: &mut Link,
    opts: &XferOpts,
    progress: &Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
) -> Result<TransferStats> {
    match link.recv().await? {
        Wire::Msg(TransferMsg::Accept {
            mode: AcceptMode::Skip,
        }) => match link.recv().await? {
            Wire::Msg(TransferMsg::Done { stats }) => Ok(stats),
            other => Err(Error::Protocol(format!("expected done, got {other:?}"))),
        },
        Wire::Msg(TransferMsg::Accept {
            mode: AcceptMode::Full { missing: _ },
        }) => {
            // The source sends the bytes next; the hash and size arrive implicitly
            // via the file the source is sending. We learn them from Blob or from
            // the Done message. Full pulls are preceded by nothing else, so the
            // source's send_blob writes frames and the sink must know size and hash.
            Err(Error::Protocol(
                "pull source must announce the blob before full ranges".into(),
            ))
        }
        Wire::Msg(TransferMsg::Blob { size, hash, tar }) => {
            let (partial, journal) = if tar {
                let dir = local.parent().unwrap_or_else(|| Path::new("."));
                (
                    dir.join(TAR_PARTIAL_NAME),
                    dir.join(".agentlink-tar.partial.json"),
                )
            } else {
                partial_paths(local)
            };
            let missing = delta::missing_ranges(size, &[]);
            // Tell the source which ranges we still need, then read them.
            link.send_msg(TransferMsg::Accept {
                mode: AcceptMode::Full {
                    missing: missing.clone(),
                },
            })
            .await?;
            let (payload, compressed) = recv_blob(
                link,
                &partial,
                &journal,
                size,
                &hash,
                Vec::new(),
                local,
                tar,
                progress,
            )
            .await?;
            let files = if tar {
                let n = unpack_tar(&partial, local)?;
                fs::remove_file(&partial).ok();
                fs::remove_file(&journal).ok();
                n
            } else {
                1
            };
            let stats = done_stats(
                size,
                payload,
                false,
                files,
                0,
                compressed,
                &opts.transport,
                0,
                0,
            );
            send_done(link, stats).await
        }
        Wire::Msg(TransferMsg::Plan {
            out_size,
            out_hash,
            ops,
        }) => {
            let (partial, journal) = partial_paths(local);
            if local.is_file() {
                apply_copies(local, &partial, out_size, &ops)?;
            }
            let have: Vec<_> = ops
                .iter()
                .filter_map(|op| match op {
                    PlanOp::Copy { new, len, .. } => Some(ByteRange {
                        start: *new,
                        end: *new + *len,
                    }),
                    PlanOp::Lit { .. } => None,
                })
                .collect();
            let copy_bytes = have.iter().map(|r| r.len()).sum();
            let (payload, compressed) = recv_blob(
                link, &partial, &journal, out_size, &out_hash, have, local, false, progress,
            )
            .await?;
            let stats = done_stats(
                out_size,
                payload,
                false,
                1,
                0,
                compressed,
                &opts.transport,
                copy_bytes,
                0,
            );
            send_done(link, stats).await
        }
        Wire::Msg(TransferMsg::Done { stats }) => Ok(stats),
        Wire::Msg(TransferMsg::Failed { message }) => Err(Error::Message(message)),
        other => Err(Error::Protocol(format!("unexpected pull reply: {other:?}"))),
    }
}


/// Open a path for pull/cat. On Unix use O_NONBLOCK so a missed type check
/// cannot stall the async runtime: socket open fails with ENXIO; FIFO open
/// succeeds but reads return EOF without blocking. Harmless for regular files.
///
/// The fd is fstat'ed after open: `ensure_pullable_file` ran on the path
/// earlier, so a raced swap to a FIFO/device would otherwise slip through.
fn open_pullable_file(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(err) if err.raw_os_error() == Some(libc::ENXIO) => {
                return Err(Error::Message(format!(
                    "{} is not a regular file (refusing fifo/socket/device)",
                    path.display()
                )));
            }
            Err(err) => return Err(err.into()),
        };
        let meta = file.metadata()?;
        if meta.is_dir() {
            return Err(Error::Message(format!(
                "{} is a directory, not a file; use `ls` to list it",
                path.display()
            )));
        }
        let ft = meta.file_type();
        if ft.is_fifo() || ft.is_socket() || ft.is_char_device() || ft.is_block_device() {
            return Err(Error::Message(format!(
                "{} is not a regular file (refusing fifo/socket/device)",
                path.display()
            )));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let file = File::open(path)?;
        if file.metadata()?.is_dir() {
            return Err(Error::Message(format!(
                "{} is a directory, not a file; use `ls` to list it",
                path.display()
            )));
        }
        Ok(file)
    }
}

/// Refuse fifo/socket/device (and symlink-to-dir) before any open/hash that
/// would block forever on a reader-less pipe. Shared by pull/cat and push:
/// opening a FIFO (or device whose read never ends) stalls a worker forever.
pub fn ensure_pullable_file(src: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(src) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(Error::Message(format!(
                "{}: No such file or directory",
                src.display()
            )));
        }
        Err(err) => return Err(crate::util::diagnose_enotdir_component(src, err)),
    };
    if meta.is_dir() && !meta.file_type().is_symlink() {
        return Err(Error::Message(format!(
            "{} is a directory, not a file; use `ls` to list it",
            src.display()
        )));
    }
    // Reject special files before any open(). Opening a FIFO/socket without
    // O_NONBLOCK blocks the worker thread and hangs `cat` forever.
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let ft = meta.file_type();
        if ft.is_fifo() || ft.is_socket() || ft.is_char_device() || ft.is_block_device() {
            return Err(Error::Message(format!(
                "{} is not a regular file (refusing fifo/socket/device)",
                src.display()
            )));
        }
    }
    if meta.is_file() {
        return Ok(());
    }
    if meta.file_type().is_symlink() {
        let target_meta = fs::metadata(src)
            .map_err(|err| Error::Message(format!("{}: {}", src.display(), err)))?;
        if target_meta.is_dir() {
            return Err(Error::Message(format!(
                "{} is a symlink to a directory, not a file; use directory copy",
                src.display()
            )));
        }
        if target_meta.is_file() {
            return Ok(());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            let ft = target_meta.file_type();
            if ft.is_fifo() || ft.is_socket() || ft.is_char_device() || ft.is_block_device() {
                return Err(Error::Message(format!(
                    "{} is not a regular file (refusing fifo/socket/device)",
                    src.display()
                )));
            }
        }
    }
    Err(Error::Message(format!(
        "{} is not a regular file (refusing fifo/socket/device)",
        src.display()
    )))
}


/// Files under `/proc` and `/sys` (and similar) often report `st_size == 0`
/// while still yielding bytes on read. Cap how much we materialize for those.
const ZERO_SIZE_READ_CAP: u64 = 32 * 1024 * 1024;

/// Read `[offset, offset+max)` from a size-0 file until EOF or the cap.
///
/// Returns the bytes actually read (may be empty for a true empty file).
fn read_zero_size_file(path: &Path, offset: u64, max_bytes: Option<u64>) -> Result<Vec<u8>> {
    let mut file = open_pullable_file(path)?;
    if offset > 0 {
        file.seek(SeekFrom::Start(offset))?;
    }
    let cap = max_bytes
        .unwrap_or(ZERO_SIZE_READ_CAP)
        .min(ZERO_SIZE_READ_CAP);
    // Read one past the cap so we can distinguish "exact cap" from overflow.
    let mut buf = Vec::new();
    let got = file.take(cap.saturating_add(1)).read_to_end(&mut buf)?;
    if got as u64 > cap {
        return Err(Error::Message(format!(
            "{} reports size 0 but exceeds the {cap} byte read cap for virtual files",
            path.display()
        )));
    }
    Ok(buf)
}

pub async fn serve_pull(
    src: &Path,
    have_hash: Option<String>,
    have_ranges: Vec<ByteRange>,
    sigs: Option<crate::protocol::SigTable>,
    link: &mut Link,
    request_id: &str,
    opts: &XferOpts,
) -> Result<TransferStats> {
    let opts = opts.clone().normalized();
    ensure_pullable_file(src)?;
    let meta_size = src.metadata()?.len();
    // Keep a temp path alive when we materialize a size-0 virtual file for cp.
    let mut zero_size_tmp: Option<PathBuf> = None;
    let (src_buf, size, hash) = if meta_size == 0 {
        let data = read_zero_size_file(src, 0, None)?;
        if data.is_empty() {
            (src.to_path_buf(), 0u64, delta::hash_bytes(b""))
        } else {
            let tmp = std::env::temp_dir().join(format!(
                "agentlink-zero-size-{request_id}-{}.bin",
                std::process::id()
            ));
            std::fs::write(&tmp, &data)?;
            let hash = delta::hash_bytes(&data);
            zero_size_tmp = Some(tmp.clone());
            (tmp, data.len() as u64, hash)
        }
    } else {
        (src.to_path_buf(), meta_size, delta::hash_file(src)?)
    };
    let src = src_buf.as_path();
    struct RemoveOnDrop(Option<PathBuf>);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                let _ = fs::remove_file(path);
            }
        }
    }
    let _keep_tmp = RemoveOnDrop(zero_size_tmp);
    if have_hash.as_deref() == Some(hash.as_str()) {
        let stats = done_stats(size, 0, true, 1, 1, false, &opts.transport, 0, size);
        link.send_msg(TransferMsg::Accept {
            mode: AcceptMode::Skip,
        })
        .await?;
        return send_done(link, stats).await;
    }
    if let Some(table) = sigs {
        if size <= 256 * 1024 * 1024 && size >= delta::DELTA_MIN_SIZE {
            let mut data = Vec::new();
            File::open(src)?.read_to_end(&mut data)?;
            let plan: Plan = delta::plan(&data, &table);
            if plan_worth(&plan, size) {
                link.send_msg(TransferMsg::Plan {
                    out_size: size,
                    out_hash: hash.clone(),
                    ops: plan.ops.clone(),
                })
                .await?;
                let literals: Vec<_> = plan
                    .ops
                    .iter()
                    .filter_map(|op| match op {
                        PlanOp::Lit { new, len } => Some(ByteRange {
                            start: *new,
                            end: *new + *len,
                        }),
                        PlanOp::Copy { .. } => None,
                    })
                    .collect();
                let _pumped = send_blob(
                    link,
                    src,
                    &literals,
                    request_id,
                    opts.chunk_size,
                    opts.window,
                    opts.parallel,
                    allow_compression(opts.compress, src),
                    false,
                    &None,
                    size,
                )
                .await?;
                return Ok(done_stats(
                    size,
                    _pumped.payload_bytes,
                    false,
                    1,
                    0,
                    _pumped.compressed,
                    &opts.transport,
                    plan.copy_bytes,
                    0,
                ));
            }
        }
    }
    let missing = if have_ranges.is_empty() {
        vec![ByteRange {
            start: 0,
            end: size,
        }]
    } else {
        delta::missing_ranges(size, &have_ranges)
    };
    link.send_msg(TransferMsg::Blob {
        size,
        hash: hash.clone(),
        tar: false,
    })
    .await?;
    // Sink answers with the ranges it wants.
    let missing = match link.recv().await? {
        Wire::Msg(TransferMsg::Accept {
            mode: AcceptMode::Full { missing },
        }) => missing,
        Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
        other => {
            let _ = missing;
            return Err(Error::Protocol(format!(
                "expected range accept, got {other:?}"
            )));
        }
    };
    let pumped = send_blob(
        link,
        src,
        &missing,
        request_id,
        opts.chunk_size,
        opts.window,
        opts.parallel,
        allow_compression(opts.compress, src),
        false,
        &None,
        size,
    )
    .await?;
    Ok(done_stats(
        size,
        pumped.payload_bytes,
        false,
        1,
        0,
        pumped.compressed,
        &opts.transport,
        0,
        resumed_bytes(size, &missing),
    ))
}

pub async fn perform_push_dir(
    local: &Path,
    remote: &str,
    link: &mut Link,
    request_id: &str,
    opts: &XferOpts,
    progress: &Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
) -> Result<TransferStats> {
    let opts = opts.clone().normalized();
    let entries = walk_manifest(local)?;
    let manifest = manifest_hash(&entries);
    let logical: u64 = entries.iter().map(|e| e.size).sum();
    link.send_msg(TransferMsg::PushDir {
        dest: remote.to_string(),
        manifest_hash: manifest,
        entries: entries.clone(),
        chunk_size: opts.chunk_size as u32,
        compress: opts.compress,
    })
    .await?;
    let needed = match link.recv().await? {
        Wire::Msg(TransferMsg::Accept {
            mode: AcceptMode::Files { needed },
        }) => needed,
        Wire::Msg(TransferMsg::Done { stats }) => return Ok(stats),
        Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
        other => {
            return Err(Error::Protocol(format!(
                "expected file list, got {other:?}"
            )))
        }
    };
    if needed.is_empty() {
        return match link.recv().await? {
            Wire::Msg(TransferMsg::Done { stats }) => Ok(stats),
            other => Err(Error::Protocol(format!("expected done, got {other:?}"))),
        };
    }
    let tar_path = std::env::temp_dir().join(format!("agentlink-{request_id}.tar"));
    write_tar(&tar_path, local, &entries, &needed)?;
    let size = tar_path.metadata()?.len();
    let hash = delta::hash_file(&tar_path)?;
    link.send_msg(TransferMsg::Blob {
        size,
        hash: hash.clone(),
        tar: true,
    })
    .await?;
    let stats = respond_as_source(
        &tar_path, link, request_id, &hash, size, &opts, progress, true,
    )
    .await;
    let _ = fs::remove_file(&tar_path);
    let mut stats = stats?;
    stats.logical_bytes = logical;
    stats.files = entries.iter().filter(|e| !e.dir).count() as u32;
    stats.files_skipped = stats
        .files
        .saturating_sub(needed.iter().filter(|n| !n.ends_with('/')).count() as u32);
    let _ = logical;
    Ok(stats)
}

pub async fn serve_push_dir(
    dest: &Path,
    entries: Vec<ManifestEntry>,
    link: &mut Link,
    transport: &str,
) -> Result<TransferStats> {
    util::create_dir_all_as_dir(dest)?;
    let needed = needed_entries(dest, &entries)?;
    let files = entries.iter().filter(|e| !e.dir).count() as u32;
    let files_skipped = files.saturating_sub(
        needed
            .iter()
            .filter(|rel| entries.iter().any(|e| e.rel == **rel && !e.dir))
            .count() as u32,
    );
    if needed.is_empty() {
        let logical = entries.iter().map(|e| e.size).sum();
        let stats = done_stats(logical, 0, true, files, files, false, transport, 0, logical);
        link.send_msg(TransferMsg::Accept {
            mode: AcceptMode::Files { needed },
        })
        .await?;
        return send_done(link, stats).await;
    }
    link.send_msg(TransferMsg::Accept {
        mode: AcceptMode::Files {
            needed: needed.clone(),
        },
    })
    .await?;
    let (size, hash) = match link.recv().await? {
        Wire::Msg(TransferMsg::Blob {
            size,
            hash,
            tar: true,
        }) => (size, hash),
        Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
        other => return Err(Error::Protocol(format!("expected tar blob, got {other:?}"))),
    };
    let partial = dest.join(TAR_PARTIAL_NAME);
    let journal = dest.join(".agentlink-tar.partial.json");
    link.send_msg(TransferMsg::Accept {
        mode: AcceptMode::Full {
            missing: vec![ByteRange {
                start: 0,
                end: size,
            }],
        },
    })
    .await?;
    let (payload, compressed) = recv_blob(
        link,
        &partial,
        &journal,
        size,
        &hash,
        Vec::new(),
        dest,
        true,
        &None,
    )
    .await?;
    let unpacked = unpack_tar(&partial, dest)?;
    fs::remove_file(&partial).ok();
    fs::remove_file(&journal).ok();
    let logical = entries.iter().map(|e| e.size).sum();
    let stats = done_stats(
        logical,
        payload,
        false,
        files,
        files_skipped,
        compressed,
        transport,
        0,
        0,
    );
    let _ = unpacked;
    send_done(link, stats).await
}

pub async fn perform_pull_dir(
    remote: &str,
    local: &Path,
    link: &mut Link,
    _request_id: &str,
    opts: &XferOpts,
    progress: &Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
) -> Result<TransferStats> {
    let opts = opts.clone().normalized();
    // Empty remote trees send Accept::Skip with no tar. Create the dest up
    // front so `cp node://…/empty /tmp/empty` still materializes a directory
    // (push_dir already create_dir_all's on the receiver).
    util::create_dir_all_as_dir(local)?;
    let have = if local.is_dir() {
        walk_manifest(local).unwrap_or_default()
    } else {
        Vec::new()
    };
    link.send_msg(TransferMsg::PullDir {
        path: remote.to_string(),
        have,
        chunk_size: opts.chunk_size as u32,
        compress: opts.compress,
    })
    .await?;
    receive_from_source(local, link, &opts, progress).await
}

pub async fn serve_pull_dir(
    src: &Path,
    have: Vec<ManifestEntry>,
    link: &mut Link,
    request_id: &str,
    opts: &XferOpts,
) -> Result<TransferStats> {
    let opts = opts.clone().normalized();
    let entries = walk_manifest(src)?;
    let have_set: std::collections::HashSet<(String, String)> =
        have.into_iter().map(|e| (e.rel, e.hash)).collect();
    let needed: Vec<String> = entries
        .iter()
        .filter(|e| !have_set.contains(&(e.rel.clone(), e.hash.clone())))
        .map(|e| e.rel.clone())
        .collect();
    let files = entries.iter().filter(|e| !e.dir).count() as u32;
    let logical: u64 = entries.iter().map(|e| e.size).sum();
    if needed.is_empty() {
        let stats = done_stats(
            logical,
            0,
            true,
            files,
            files,
            false,
            &opts.transport,
            0,
            logical,
        );
        link.send_msg(TransferMsg::Accept {
            mode: AcceptMode::Skip,
        })
        .await?;
        return send_done(link, stats).await;
    }
    let tar_path = std::env::temp_dir().join(format!("agentlink-{request_id}.tar"));
    write_tar(&tar_path, src, &entries, &needed)?;
    let size = tar_path.metadata()?.len();
    let hash = delta::hash_file(&tar_path)?;
    link.send_msg(TransferMsg::Blob {
        size,
        hash: hash.clone(),
        tar: true,
    })
    .await?;
    let missing = match link.recv().await? {
        Wire::Msg(TransferMsg::Accept {
            mode: AcceptMode::Full { missing },
        }) => missing,
        other => {
            let _ = fs::remove_file(&tar_path);
            return Err(Error::Protocol(format!(
                "expected range accept, got {other:?}"
            )));
        }
    };
    let pumped = send_blob(
        link,
        &tar_path,
        &missing,
        request_id,
        opts.chunk_size,
        opts.window,
        opts.parallel,
        opts.compress != CompressPref::Off,
        true,
        &None,
        size,
    )
    .await;
    let _ = fs::remove_file(&tar_path);
    let pumped = pumped?;
    Ok(done_stats(
        logical,
        pumped.payload_bytes,
        false,
        files,
        files.saturating_sub(
            needed
                .iter()
                .filter(|n| entries.iter().any(|e| e.rel == **n && !e.dir))
                .count() as u32,
        ),
        pumped.compressed,
        &opts.transport,
        0,
        0,
    ))
}

/// Bytes from a streamed download, plus the remote file's full size.
#[derive(Debug, Clone)]
pub struct StreamRead {
    pub stats: TransferStats,
    pub file_size: u64,
    pub start: u64,
    pub end: u64,
}

struct PumpOut {
    logical_bytes: u64,
    payload_bytes: u64,
    compressed: bool,
    hash: String,
}

struct PartialFile {
    path: PathBuf,
    armed: bool,
}

impl Drop for PartialFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Read up to `chunk` bytes, coalescing short reads. `None` is EOF.
///
/// One chunk is the most this holds. The caller gates the next read on the
/// send window, so a pipe is not copied into memory first.
fn read_coalesced(reader: &mut dyn Read, chunk: usize) -> Result<Option<Vec<u8>>> {
    let chunk = chunk.max(1);
    let mut buf = vec![0u8; chunk];
    let mut filled = 0usize;
    while filled < chunk {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
    if filled == 0 {
        Ok(None)
    } else {
        buf.truncate(filled);
        Ok(Some(buf))
    }
}

fn compress_chunk(enabled: &mut bool, raw: Vec<u8>) -> (Vec<u8>, bool) {
    if !*enabled {
        return (raw, false);
    }
    match compress_if_smaller(&raw) {
        Some(compressed) => (compressed, true),
        None => {
            if raw.len() >= 4096 {
                *enabled = false;
            }
            (raw, false)
        }
    }
}

fn hex_hash(hasher: blake3::Hasher) -> String {
    hasher.finalize().to_hex().to_string()
}

/// Send contiguous chunks. At most `window` are in flight, and the next chunk
/// is read only after a permit is free, so a stall cannot run ahead by more
/// than one window.
async fn pump_out<F>(
    link: &mut Link,
    request_id: &str,
    mut offset: u64,
    window: usize,
    mut compress: bool,
    mut next_chunk: F,
) -> Result<PumpOut>
where
    F: FnMut() -> Result<Option<Vec<u8>>>,
{
    let sem = Arc::new(Semaphore::new(window.max(1)));
    let inflight: Arc<Mutex<HashMap<u64, OwnedSemaphorePermit>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut hasher = blake3::Hasher::new();
    let mut logical = 0u64;
    let mut payload = 0u64;
    let mut any_compressed = false;
    let mut eof = false;
    loop {
        let inflight_empty = inflight.lock().map(|map| map.is_empty()).unwrap_or(true);
        if eof && inflight_empty {
            break;
        }
        tokio::select! {
            biased;
            incoming = link.recv() => {
                match incoming? {
                    Wire::Msg(TransferMsg::Ack { ranges }) => release(&inflight, &ranges),
                    Wire::Msg(TransferMsg::Failed { message }) => {
                        return Err(Error::Message(message));
                    }
                    other => {
                        return Err(Error::Protocol(format!(
                            "unexpected message while sending a stream: {other:?}"
                        )));
                    }
                }
            }
            permit = sem.clone().acquire_owned(), if !eof => {
                let permit = permit.map_err(|_| Error::Message("transfer window closed".into()))?;
                let Some(raw) = next_chunk()? else {
                    eof = true;
                    drop(permit);
                    continue;
                };
                if raw.is_empty() {
                    eof = true;
                    drop(permit);
                    continue;
                }
                let raw_len = raw.len() as u32;
                hasher.update(&raw);
                logical += u64::from(raw_len);
                let off = offset;
                offset += u64::from(raw_len);
                let (bytes, is_zstd) = compress_chunk(&mut compress, raw);
                if is_zstd {
                    any_compressed = true;
                }
                payload += bytes.len() as u64;
                let frame = DataFrame {
                    request_id: request_id.to_string(),
                    offset: off,
                    raw_len,
                    compressed: is_zstd,
                    hole: false,
                    tar: false,
                    payload: bytes,
                };
                let encoded = frame::encode(&frame)?;
                {
                    let mut map = inflight
                        .lock()
                        .map_err(|_| Error::Message("window lock poisoned".into()))?;
                    map.insert(off, permit);
                }
                link.send_frame(encoded).await?;
            }
        }
    }
    Ok(PumpOut {
        logical_bytes: logical,
        payload_bytes: payload,
        compressed: any_compressed,
        hash: hex_hash(hasher),
    })
}

async fn wait_done_stats(link: &mut Link) -> Result<TransferStats> {
    loop {
        match link.recv().await? {
            Wire::Msg(TransferMsg::Done { stats }) => return Ok(stats),
            Wire::Msg(TransferMsg::Ack { .. }) => {}
            Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
            other => {
                return Err(Error::Protocol(format!("expected done, got {other:?}")));
            }
        }
    }
}

async fn wait_done(link: &mut Link) -> Result<()> {
    loop {
        match link.recv().await? {
            Wire::Msg(TransferMsg::Done { .. }) => return Ok(()),
            Wire::Msg(TransferMsg::Ack { .. }) => {}
            Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
            other => {
                return Err(Error::Protocol(format!("expected done, got {other:?}")));
            }
        }
    }
}

fn decoded_chunk(bytes: &[u8]) -> Result<(u64, Vec<u8>, bool, u64)> {
    let frame = frame::decode(bytes)?;
    let payload_len = frame.payload.len() as u64;
    if frame.hole {
        if !frame.payload.is_empty() {
            return Err(Error::Message("hole frame must have empty payload".into()));
        }
        // Stream writers synthesize zeros. File/tar send_blob may emit larger
        // hole frames (FILE_MAX_HOLE) but those go through write_hole, not here.
        if u64::from(frame.raw_len) > sparse::STREAM_MAX_HOLE {
            return Err(Error::Message(format!(
                "stream hole frame {} exceeds {} byte cap",
                frame.raw_len,
                sparse::STREAM_MAX_HOLE
            )));
        }
        return Ok((
            frame.offset,
            vec![0u8; frame.raw_len as usize],
            false,
            payload_len,
        ));
    }
    if frame.offset.checked_add(u64::from(frame.raw_len)).is_none() {
        return Err(Error::Protocol("stream chunk offset overflow".into()));
    }
    if (frame.raw_len as usize) > frame::MAX_CHUNK {
        return Err(Error::Protocol(format!(
            "stream chunk raw_len {} exceeds {} byte cap",
            frame.raw_len,
            frame::MAX_CHUNK
        )));
    }
    let compressed = frame.compressed;
    let raw = if compressed {
        decompress(&frame.payload, frame.raw_len as usize)?
    } else {
        frame.payload
    };
    if raw.len() as u32 != frame.raw_len {
        return Err(Error::Message("uncompressed chunk length mismatch".into()));
    }
    Ok((frame.offset, raw, compressed, payload_len))
}

/// Write an upload at chunk offsets. Chunks may arrive out of order inside the
/// window. The BLAKE3 check runs after `Commit`, streaming from the partial file.
async fn recv_file_stream(link: &mut Link, partial: &Path) -> Result<(u64, u64, bool)> {
    let mut have: Vec<ByteRange> = Vec::new();
    let mut payload = 0u64;
    let mut compressed = false;
    loop {
        match link.recv().await? {
            Wire::Frame(bytes) => {
                let (offset, raw, is_zstd, payload_len) = decoded_chunk(&bytes)?;
                if is_zstd {
                    compressed = true;
                }
                write_at(partial, offset, &raw)?;
                payload += payload_len;
                have.push(ByteRange {
                    start: offset,
                    end: offset + raw.len() as u64,
                });
                have = delta::merge_ranges(have);
                link.send_msg(TransferMsg::Ack {
                    ranges: vec![ByteRange {
                        start: offset,
                        end: offset + raw.len() as u64,
                    }],
                })
                .await?;
            }
            Wire::Msg(TransferMsg::Commit { size, hash }) => {
                if have.iter().any(|range| range.end > size) {
                    return Err(Error::Message(
                        "stream chunk past the committed size".into(),
                    ));
                }
                let missing = delta::missing_ranges(size, &have);
                if !missing.is_empty() {
                    return Err(Error::Message(format!(
                        "incomplete stream, {} ranges missing",
                        missing.len()
                    )));
                }
                let got = if size == 0 {
                    delta::hash_bytes(b"")
                } else {
                    {
                        let file = OpenOptions::new().write(true).open(partial)?;
                        sparse::ensure_sparse(&file)?;
                        file.set_len(size)?;
                    }
                    delta::hash_file(partial)?
                };
                if got != hash {
                    return Err(Error::Message("stream failed the BLAKE3 check".into()));
                }
                return Ok((size, payload, compressed));
            }
            Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
            Wire::Msg(_) => {}
        }
    }
}

/// Stream `reader` to `remote`. The size and hash are sent after EOF, so this
/// has no resume and no block delta.
pub async fn perform_push_stream<R: Read>(
    reader: &mut R,
    remote: &str,
    link: &mut Link,
    request_id: &str,
    opts: &XferOpts,
) -> Result<TransferStats> {
    let opts = opts.clone().normalized();
    link.send_msg(TransferMsg::PushStream {
        path: remote.to_string(),
        chunk_size: opts.chunk_size as u32,
        window: opts.window,
        compress: opts.compress,
    })
    .await?;
    match link.recv().await? {
        Wire::Msg(TransferMsg::Accept {
            mode: AcceptMode::Full { .. },
        }) => {}
        Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
        other => {
            return Err(Error::Protocol(format!(
                "expected stream accept, got {other:?}"
            )))
        }
    }
    let compress = allow_compression(opts.compress, Path::new(remote));
    let chunk = opts.chunk_size;
    let pumped = pump_out(link, request_id, 0, opts.window, compress, || {
        read_coalesced(reader, chunk)
    })
    .await?;
    link.send_msg(TransferMsg::Commit {
        size: pumped.logical_bytes,
        hash: pumped.hash,
    })
    .await?;
    wait_done_stats(link).await
}

pub async fn serve_push_stream(
    dest: &Path,
    link: &mut Link,
    transport: &str,
) -> Result<TransferStats> {
    serve_push_stream_confined(None, dest, link, transport).await
}

pub async fn serve_push_stream_confined(
    sandbox_root: Option<&Path>,
    dest: &Path,
    link: &mut Link,
    transport: &str,
) -> Result<TransferStats> {
    let dest_checked = crate::paths::ensure_path_stays_in_sandbox_at_sink(sandbox_root, dest)?;
    let dest = dest_checked.as_path();
    if dest.is_dir() {
        return Err(Error::Message(format!("{} is a directory", dest.display())));
    }
    let (partial, journal) = partial_paths(dest);
    if let Some(parent) = partial.parent() {
        if let Some(root) = sandbox_root {
            let _ = crate::paths::ensure_path_stays_in_sandbox_at_sink(Some(root), parent)?;
        }
        util::create_dir_all_parent(parent)?;
    }
    let _ = fs::remove_file(&journal);
    File::create(&partial)?;
    let mut cleanup = PartialFile {
        path: partial.clone(),
        armed: true,
    };
    link.send_msg(TransferMsg::Accept {
        mode: AcceptMode::Full {
            missing: Vec::new(),
        },
    })
    .await?;
    let (size, payload, compressed) = recv_file_stream(link, &partial).await?;
    install_partial_at_dest_in_sandbox(&partial, dest, sandbox_root)?;
    let _ = fs::remove_file(&journal);
    cleanup.armed = false;
    let stats = done_stats(size, payload, false, 1, 0, compressed, transport, 0, 0);
    send_done(link, stats).await
}

fn ranges_overlap(pending: &BTreeMap<u64, Vec<u8>>, offset: u64, len: u64, next: u64) -> bool {
    let end = offset + len;
    if offset < next && end > next {
        return true;
    }
    pending.iter().any(|(other, data)| {
        let other_end = other + data.len() as u64;
        offset < other_end && *other < end
    })
}

/// Reassemble a download into `writer`. Future chunks stay unacked so the
/// sender cannot run more than `window` chunks ahead of the next byte.
async fn recv_ordered<W: Write>(
    link: &mut Link,
    writer: &mut W,
    start: u64,
    end: u64,
    window: usize,
) -> Result<(u64, bool)> {
    let mut next = start;
    let mut pending: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut hasher = blake3::Hasher::new();
    let mut payload = 0u64;
    let mut compressed = false;
    let window = window.max(1);
    loop {
        match link.recv().await? {
            Wire::Frame(bytes) => {
                let (offset, raw, is_zstd, payload_len) = decoded_chunk(&bytes)?;
                if is_zstd {
                    compressed = true;
                }
                payload += payload_len;
                let len = raw.len() as u64;
                if offset < next || ranges_overlap(&pending, offset, len, next) {
                    return Err(Error::Message("overlapping stream chunk".into()));
                }
                if offset != next && pending.len() >= window {
                    return Err(Error::Message("stream reorder window exceeded".into()));
                }
                if offset == next {
                    let ack_from = next;
                    writer.write_all(&raw)?;
                    hasher.update(&raw);
                    next += len;
                    while let Some(buffered) = pending.remove(&next) {
                        writer.write_all(&buffered)?;
                        hasher.update(&buffered);
                        next += buffered.len() as u64;
                    }
                    link.send_msg(TransferMsg::Ack {
                        ranges: vec![ByteRange {
                            start: ack_from,
                            end: next,
                        }],
                    })
                    .await?;
                } else {
                    pending.insert(offset, raw);
                }
            }
            Wire::Msg(TransferMsg::Commit { size, hash }) => {
                if size != end.saturating_sub(start) || next != end || !pending.is_empty() {
                    return Err(Error::Message(
                        "incomplete stream, bytes still missing".into(),
                    ));
                }
                if hex_hash(hasher) != hash {
                    return Err(Error::Message("stream failed the BLAKE3 check".into()));
                }
                return Ok((payload, compressed));
            }
            Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
            Wire::Msg(_) => {}
        }
    }
}

pub async fn perform_pull_stream<W: Write>(
    remote: &str,
    offset: u64,
    max_bytes: Option<u64>,
    writer: &mut W,
    link: &mut Link,
    _request_id: &str,
    opts: &XferOpts,
) -> Result<StreamRead> {
    let opts = opts.clone().normalized();
    link.send_msg(TransferMsg::PullStream {
        path: remote.to_string(),
        offset,
        max_bytes,
        chunk_size: opts.chunk_size as u32,
        window: opts.window,
        compress: opts.compress,
    })
    .await?;
    let (start, end, file_size) = match link.recv().await? {
        Wire::Msg(TransferMsg::StreamReady {
            start,
            end,
            file_size,
        }) => (start, end, file_size),
        Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
        other => {
            return Err(Error::Protocol(format!(
                "expected stream ready, got {other:?}"
            )))
        }
    };
    if end < start || end > file_size {
        return Err(Error::Protocol("stream range is outside the file".into()));
    }
    let received = match recv_ordered(link, writer, start, end, opts.window).await {
        Ok(received) => received,
        Err(err) => {
            let _ = link
                .send_msg(TransferMsg::Failed {
                    message: err.to_string(),
                })
                .await;
            return Err(err);
        }
    };
    writer.flush()?;
    let (payload, compressed) = received;
    let stats = done_stats(
        end - start,
        payload,
        false,
        1,
        0,
        compressed,
        &opts.transport,
        0,
        0,
    );
    link.send_msg(TransferMsg::Done {
        stats: stats.clone(),
    })
    .await?;
    Ok(StreamRead {
        stats,
        file_size,
        start,
        end,
    })
}

pub async fn serve_pull_stream(
    src: &Path,
    offset: u64,
    max_bytes: Option<u64>,
    chunk_size: u32,
    window: usize,
    compress: CompressPref,
    link: &mut Link,
    request_id: &str,
    transport: &str,
) -> Result<TransferStats> {
    ensure_pullable_file(src)?;
    let meta_size = fs::metadata(src)?.len();
    // `/proc` and `/sys` often report st_size=0 while still yielding bytes.
    // Probe those so `cat` / stream_download is not silently empty.
    let probed = if meta_size == 0 {
        Some(read_zero_size_file(src, offset, max_bytes)?)
    } else {
        None
    };
    let (file_size, start, end) = if let Some(ref buf) = probed {
        let start = offset;
        let end = offset.saturating_add(buf.len() as u64);
        (end, start, end)
    } else {
        let file_size = meta_size;
        let start = offset.min(file_size);
        let end = match max_bytes {
            Some(max) => start.saturating_add(max).min(file_size),
            None => file_size,
        };
        (file_size, start, end)
    };
    let window = window.clamp(1, 64);
    let chunk = frame::clamp_chunk(chunk_size as usize);
    link.send_msg(TransferMsg::StreamReady {
        start,
        end,
        file_size,
    })
    .await?;
    let mut cursor = start;
    let path = src.to_path_buf();
    let probed_buf = probed;
    let compress = allow_compression(compress, src);
    let pumped = pump_out(link, request_id, start, window, compress, || {
        if cursor >= end {
            return Ok(None);
        }
        let n = ((end - cursor) as usize).min(chunk);
        let data = if let Some(ref buf) = probed_buf {
            let local = (cursor - start) as usize;
            let take = n.min(buf.len().saturating_sub(local));
            buf[local..local + take].to_vec()
        } else {
            read_at(&path, cursor, n)?
        };
        cursor += data.len() as u64;
        Ok(Some(data))
    })
    .await?;
    if pumped.logical_bytes != end - start {
        return Err(Error::Message("short read while streaming a file".into()));
    }
    link.send_msg(TransferMsg::Commit {
        size: end - start,
        hash: pumped.hash,
    })
    .await?;
    wait_done(link).await?;
    Ok(done_stats(
        end - start,
        pumped.payload_bytes,
        false,
        1,
        0,
        pumped.compressed,
        transport,
        0,
        0,
    ))
}

#[cfg(test)]
mod stream_tests {
    use std::io::{self, Cursor, Write};

    use super::*;
    use crate::delta;
    use crate::frame::{self, DataFrame};
    use crate::protocol::{CompressPref, TransferMsg};

    fn frame_bytes(offset: u64, payload: &[u8]) -> Vec<u8> {
        frame::encode(&DataFrame {
            request_id: "11111111-1111-4111-8111-111111111111".into(),
            offset,
            raw_len: payload.len() as u32,
            compressed: false,
            hole: false,
            tar: false,
            payload: payload.to_vec(),
        })
        .unwrap()
    }

    struct Parts {
        bytes: Vec<u8>,
        writes: Vec<Vec<u8>>,
    }

    impl Write for Parts {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.push(buf.to_vec());
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn push_stream_writes_out_of_order_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");
        let (mut client, mut server) = Link::pair(8);
        let serve = tokio::spawn(async move {
            serve_push_stream(&dest, &mut server, "mem")
                .await
                .map(|_| dest)
        });
        match client.recv().await.unwrap() {
            Wire::Msg(TransferMsg::Accept { .. }) => {}
            other => panic!("accept: {other:?}"),
        }
        client.send_frame(frame_bytes(4, b"efgh")).await.unwrap();
        client.send_frame(frame_bytes(0, b"abcd")).await.unwrap();
        client
            .send_msg(TransferMsg::Commit {
                size: 8,
                hash: delta::hash_bytes(b"abcdefgh"),
            })
            .await
            .unwrap();
        let dest = serve.await.unwrap().unwrap();
        assert_eq!(std::fs::read(dest).unwrap(), b"abcdefgh");
    }

    #[tokio::test]
    async fn pull_stream_reorders_before_writing() {
        let (mut client, mut server) = Link::pair(8);
        let serve = tokio::spawn(async move {
            match server.recv().await.unwrap() {
                Wire::Msg(TransferMsg::PullStream { .. }) => {}
                other => panic!("pull: {other:?}"),
            }
            server
                .send_msg(TransferMsg::StreamReady {
                    start: 0,
                    end: 6,
                    file_size: 6,
                })
                .await
                .unwrap();
            server.send_frame(frame_bytes(3, b"def")).await.unwrap();
            server.send_frame(frame_bytes(0, b"abc")).await.unwrap();
            server
                .send_msg(TransferMsg::Commit {
                    size: 6,
                    hash: delta::hash_bytes(b"abcdef"),
                })
                .await
                .unwrap();
            loop {
                match server.recv().await.unwrap() {
                    Wire::Msg(TransferMsg::Done { .. }) => break,
                    Wire::Msg(TransferMsg::Ack { .. }) => {}
                    other => panic!("server saw {other:?}"),
                }
            }
        });
        let mut out = Parts {
            bytes: Vec::new(),
            writes: Vec::new(),
        };
        let opts = XferOpts {
            window: 4,
            ..XferOpts::default()
        };
        let body = perform_pull_stream(
            "remote",
            0,
            None,
            &mut out,
            &mut client,
            "11111111-1111-4111-8111-111111111111",
            &opts,
        )
        .await
        .unwrap();
        serve.await.unwrap();
        assert_eq!(out.bytes, b"abcdef");
        assert_eq!(out.writes[0], b"abc");
        assert_eq!(body.file_size, 6);
        assert_eq!(body.stats.logical_bytes, 6);
    }

    #[tokio::test]
    async fn push_stream_from_a_short_reader() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("notes.txt");
        let (mut client, mut server) = Link::pair(8);
        let serve = tokio::spawn(async move { serve_push_stream(&dest, &mut server, "mem").await });
        let text = b"abcdef".repeat(20_000);
        let mut reader = Short {
            inner: Cursor::new(text.clone()),
            cap: 1000,
        };
        let opts = XferOpts {
            chunk_size: 64 * 1024,
            window: 2,
            compress: CompressPref::On,
            ..XferOpts::default()
        };
        let stats = perform_push_stream(
            &mut reader,
            "notes.txt",
            &mut client,
            "11111111-1111-4111-8111-111111111111",
            &opts,
        )
        .await
        .unwrap();
        serve.await.unwrap().unwrap();
        assert_eq!(std::fs::read(dir.path().join("notes.txt")).unwrap(), text);
        assert!(stats.compressed, "{stats:?}");
        assert!(stats.payload_bytes < stats.logical_bytes / 2, "{stats:?}");
        assert_eq!(stats.logical_bytes, text.len() as u64);
    }

    #[test]
    fn stale_or_mismatched_journal_is_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("blob.bin");
        let (partial, journal) = partial_paths(&dest);
        std::fs::write(&partial, vec![1u8; 64]).unwrap();
        save_journal(
            &journal,
            &Journal {
                hash: "deadbeef".into(),
                size: 64,
                ranges: vec![ByteRange { start: 0, end: 32 }],
            },
        )
        .unwrap();
        // Wrong hash → clear.
        let got = take_resume_ranges(&partial, &journal, "cafebabe", 64);
        assert!(got.is_empty());
        assert!(!partial.exists());
        assert!(!journal.exists());

        std::fs::write(&partial, vec![1u8; 64]).unwrap();
        save_journal(
            &journal,
            &Journal {
                hash: "cafebabe".into(),
                size: 64,
                ranges: vec![ByteRange { start: 0, end: 32 }],
            },
        )
        .unwrap();
        let got = take_resume_ranges(&partial, &journal, "cafebabe", 64);
        assert_eq!(got.len(), 1);
        assert!(partial.exists());
        assert!(journal.exists());
    }

    #[test]
    fn sweep_stale_partials_clears_old_and_keeps_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let old_dest = dir.path().join("old.bin");
        let (old_partial, old_journal) = partial_paths(&old_dest);
        std::fs::write(&old_partial, vec![1u8; 8]).unwrap();
        save_journal(
            &old_journal,
            &Journal {
                hash: "aa".into(),
                size: 8,
                ranges: vec![ByteRange { start: 0, end: 4 }],
            },
        )
        .unwrap();
        let old_time = std::time::SystemTime::now() - STALE_PARTIAL_MAX_AGE - std::time::Duration::from_secs(60);
        filetime_set(&old_partial, old_time);
        filetime_set(&old_journal, old_time);

        let fresh_dest = dir.path().join("fresh.bin");
        let (fresh_partial, fresh_journal) = partial_paths(&fresh_dest);
        std::fs::write(&fresh_partial, vec![2u8; 8]).unwrap();
        save_journal(
            &fresh_journal,
            &Journal {
                hash: "bb".into(),
                size: 8,
                ranges: vec![ByteRange { start: 0, end: 4 }],
            },
        )
        .unwrap();

        let orphan = dir.path().join(".orphan.agentlink-partial");
        std::fs::write(&orphan, vec![3u8; 4]).unwrap();
        filetime_set(&orphan, old_time);

        let n = sweep_stale_partials(dir.path());
        assert!(n >= 2, "cleared={n}");
        assert!(!old_partial.exists());
        assert!(!old_journal.exists());
        assert!(!orphan.exists());
        assert!(fresh_partial.exists());
        assert!(fresh_journal.exists());
    }

    fn filetime_set(path: &std::path::Path, when: std::time::SystemTime) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(when).unwrap();
    }

    #[tokio::test]
    async fn push_empty_file_completes() {
        // Zero-byte push used to deadlock in send_blob: no workers meant the
        // select never woke to send Finish, so the receiver waited forever.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("empty.txt");
        let dest = dir.path().join("dest-empty.txt");
        std::fs::write(&src, b"").unwrap();
        let (mut client, mut server) = Link::pair(8);
        let dest_task = dest.clone();
        let hash = delta::hash_bytes(b"");
        let serve = tokio::spawn(async move {
            serve_push(
                &dest_task,
                Path::new("dest-empty.txt"),
                0,
                hash,
                64 * 1024,
                CompressPref::Off,
                true,
                &mut server,
                "mem",
                None,
                None,
            )
            .await
        });
        let opts = XferOpts {
            chunk_size: 64 * 1024,
            window: 2,
            parallel: 1,
            compress: CompressPref::Off,
            resume: true,
            transport: "mem".into(),
        };
        let push = perform_push(
            &src,
            "dest-empty.txt",
            &mut client,
            "22222222-2222-4222-8222-222222222222",
            &opts,
            &None,
        );
        let stats = tokio::time::timeout(std::time::Duration::from_secs(5), push)
            .await
            .expect("empty push timed out (send_blob Finish deadlock)")
            .unwrap();
        serve.await.unwrap().unwrap();
        assert_eq!(stats.logical_bytes, 0, "{stats:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"");
    }

    #[cfg(unix)]
    fn mem_push_opts() -> XferOpts {
        XferOpts {
            chunk_size: 64 * 1024,
            window: 2,
            parallel: 1,
            compress: CompressPref::Off,
            resume: true,
            transport: "mem".into(),
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn perform_push_rejects_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let status = crate::process::hidden("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        let (mut link, _server) = Link::pair(8);
        let opts = mem_push_opts();
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            perform_push(&fifo, "remote", &mut link, "push-fifo", &opts, &None),
        )
        .await
        .expect("push of a FIFO must refuse instead of blocking on open")
        .unwrap_err()
        .to_string();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn perform_push_rejects_char_device_without_hanging() {
        let (mut link, _server) = Link::pair(8);
        let opts = mem_push_opts();
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            perform_push(
                Path::new("/dev/null"),
                "remote",
                &mut link,
                "push-devnull",
                &opts,
                &None,
            ),
        )
        .await
        .expect("push of /dev/null must refuse instead of sending an empty file")
        .unwrap_err()
        .to_string();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[tokio::test]
    async fn interrupted_push_journals_and_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dest = dir.path().join("dest.bin");
        let mut data = vec![7u8; 200_000];
        data[1000] = 9;
        std::fs::write(&src, &data).unwrap();
        let hash = delta::hash_bytes(&data);
        let (mut client, mut server) = Link::pair(8);
        let dest_task = dest.clone();
        let hash_task = hash.clone();
        let len = data.len() as u64;
        let serve = tokio::spawn(async move {
            serve_push(
                &dest_task,
                Path::new("dest.bin"),
                len,
                hash_task,
                64 * 1024,
                CompressPref::Off,
                true,
                &mut server,
                "mem",
                None,
                None,
            )
            .await
        });
        match client.recv().await.unwrap() {
            Wire::Msg(TransferMsg::Accept { .. }) => {}
            other => panic!("accept: {other:?}"),
        }
        client
            .send_frame(frame_bytes(0, &data[..100_000]))
            .await
            .unwrap();
        match client.recv().await.unwrap() {
            Wire::Msg(TransferMsg::Ack { .. }) => {}
            other => panic!("ack: {other:?}"),
        }
        drop(client);
        let err = serve.await.unwrap().unwrap_err();
        let (_partial, journal) = partial_paths(&dest);
        let text =
            std::fs::read_to_string(&journal).unwrap_or_else(|_| panic!("no journal after {err}"));
        assert!(text.contains("100000"), "{text}");

        let (mut client, mut server) = Link::pair(8);
        let dest_task = dest.clone();
        let hash_task = hash.clone();
        let serve = tokio::spawn(async move {
            serve_push(
                &dest_task,
                Path::new("dest.bin"),
                len,
                hash_task,
                64 * 1024,
                CompressPref::Off,
                true,
                &mut server,
                "mem",
                None,
                None,
            )
            .await
        });
        let opts = XferOpts {
            chunk_size: 64 * 1024,
            window: 2,
            parallel: 1,
            compress: CompressPref::Off,
            resume: true,
            transport: "mem".into(),
        };
        let stats = perform_push(
            &src,
            "dest.bin",
            &mut client,
            "11111111-1111-4111-8111-111111111111",
            &opts,
            &None,
        )
        .await
        .unwrap();
        serve.await.unwrap().unwrap();
        assert!(stats.resumed_bytes >= 100_000, "{stats:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[test]
    #[cfg(unix)]
    fn finalize_dest_path_follows_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, b"old").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let got = finalize_dest_path(&link).unwrap();
        assert_eq!(got, target);
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    #[cfg(unix)]
    fn install_partial_preserves_symlink_and_updates_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, b"old").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let partial = dir.path().join(".link.txt.agentlink-partial");
        fs::write(&partial, b"NEWDATA").unwrap();
        install_partial_at_dest(&partial, &link).unwrap();
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"NEWDATA");
        assert_eq!(fs::read(&link).unwrap(), b"NEWDATA");
        assert!(!partial.exists());
    }

    #[test]
    #[cfg(unix)]
    fn install_partial_creates_dangling_symlink_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("missing.txt");
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let partial = dir.path().join(".link.txt.agentlink-partial");
        fs::write(&partial, b"created").unwrap();
        install_partial_at_dest(&partial, &link).unwrap();
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"created");
    }

    #[test]
    #[cfg(unix)]
    fn install_partial_refuses_readonly_destination() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("ro.txt");
        fs::write(&dest, b"KEEP").unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o444)).unwrap();
        let ino_before = fs::metadata(&dest).unwrap().ino();
        let partial = dir.path().join(".ro.txt.agentlink-partial");
        fs::write(&partial, b"NEW").unwrap();
        let err = install_partial_at_dest(&partial, &dest).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Permission denied") || msg.contains("os error 13") || msg.contains("Read-only"),
            "{msg}"
        );
        assert_eq!(fs::read(&dest).unwrap(), b"KEEP");
        assert_eq!(fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o444);
        assert_eq!(fs::metadata(&dest).unwrap().ino(), ino_before);
        assert!(partial.exists(), "failed install should leave the partial");
    }

    #[test]
    #[cfg(unix)]
    fn install_partial_preserves_existing_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("mode.txt");
        fs::write(&dest, b"old").unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o640)).unwrap();
        let partial = dir.path().join(".mode.txt.agentlink-partial");
        fs::write(&partial, b"new").unwrap();
        install_partial_at_dest(&partial, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"new");
        assert_eq!(fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o640);
        assert!(!partial.exists());
    }

    #[test]
    #[cfg(unix)]
    fn install_partial_creates_missing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("fresh.txt");
        let partial = dir.path().join(".fresh.txt.agentlink-partial");
        fs::write(&partial, b"hello").unwrap();
        install_partial_at_dest(&partial, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"hello");
        assert!(!partial.exists());
    }

    #[test]
    #[cfg(unix)]
    fn write_at_all_zero_chunk_stays_sparse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse.bin");
        File::create(&path).unwrap();
        // 1 MiB hole, then 4 KiB of data, then 1 MiB hole.
        write_at(&path, 0, &vec![0u8; 1024 * 1024]).unwrap();
        write_at(&path, 1024 * 1024, &vec![0xABu8; 4096]).unwrap();
        write_at(&path, 1024 * 1024 + 4096, &vec![0u8; 1024 * 1024]).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 1024 * 1024 + 4096 + 1024 * 1024);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            // 512-byte blocks; sparse should be far under logical size.
            let allocated = meta.blocks() * 512;
            assert!(
                allocated < 256 * 1024,
                "expected sparse allocation, got {allocated} bytes for {} logical",
                meta.len()
            );
        }
        let mut mid = vec![0u8; 4096];
        let mut f = File::open(&path).unwrap();
        f.seek(SeekFrom::Start(1024 * 1024)).unwrap();
        f.read_exact(&mut mid).unwrap();
        assert_eq!(mid, vec![0xABu8; 4096]);
    }

    #[test]
    fn walk_manifest_empty_dir_has_no_entries() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let entries = walk_manifest(&empty).unwrap();
        assert!(entries.is_empty(), "{entries:?}");
        // Mirrors perform_pull_dir: create dest even when the source walk is empty.
        let dest = dir.path().join("dest-empty");
        assert!(!dest.exists());
        std::fs::create_dir_all(&dest).unwrap();
        assert!(dest.is_dir());
        assert!(walk_manifest(&dest).unwrap().is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn walk_manifest_follows_symlink_to_dir_root() {
        // copy_download routes symlink-to-dir through PullDir once FileStat
        // reports is_dir; walk must accept the link path as the tree root.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("sub")).unwrap();
        std::fs::write(real.join("sub/a.txt"), b"hello").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let entries = walk_manifest(&link).unwrap();
        let rels: Vec<_> = entries.iter().map(|e| e.rel.as_str()).collect();
        assert!(rels.contains(&"sub"), "{rels:?}");
        assert!(rels.contains(&"sub/a.txt"), "{rels:?}");
    }

    #[test]
    #[cfg(unix)]
    fn ensure_pullable_file_child_of_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        fs::write(&file, b"x").unwrap();
        let child = file.join("child");
        let err = ensure_pullable_file(&child).unwrap_err().to_string();
        assert!(err.contains("path component"), "{err}");
        assert!(err.contains("exists but is not a directory"), "{err}");
        assert!(err.contains("file.txt"), "{err}");
        let missing = dir.path().join("nope");
        let err = ensure_pullable_file(&missing).unwrap_err().to_string();
        assert!(err.contains("No such file or directory"), "{err}");
        assert!(!err.contains("path component"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn ensure_pullable_file_rejects_symlink_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = ensure_pullable_file(&link).unwrap_err().to_string();
        assert!(err.contains("symlink to a directory"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn ensure_pullable_file_rejects_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let status = crate::process::hidden("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        let err = ensure_pullable_file(&fifo).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("fifo") || msg.contains("regular file"),
            "{msg}"
        );
        let file = dir.path().join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        ensure_pullable_file(&file).unwrap();
        open_pullable_file(&file).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn ensure_pullable_file_rejects_char_device() {
        let err = ensure_pullable_file(Path::new("/dev/null")).unwrap_err().to_string();
        assert!(err.contains("not a regular file"), "{err}");
        let err = ensure_pullable_file(Path::new("/dev/zero")).unwrap_err().to_string();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[test]
    fn open_pullable_file_accepts_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f.txt");
        std::fs::write(&file, b"payload").unwrap();
        let mut opened = open_pullable_file(&file).unwrap();
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut opened, &mut buf).unwrap();
        assert_eq!(buf, "payload");
    }

    #[test]
    #[cfg(unix)]
    fn open_pullable_file_rejects_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let status = crate::process::hidden("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        // O_NONBLOCK means this open cannot hang; fstat must catch the FIFO.
        let err = open_pullable_file(&fifo).unwrap_err().to_string();
        assert!(err.contains("refusing fifo/socket/device"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn open_pullable_file_rejects_char_device() {
        let err = open_pullable_file(Path::new("/dev/null"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("refusing fifo/socket/device"), "{err}");
    }

    #[test]
    fn read_zero_size_empty_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("empty");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(read_zero_size_file(&file, 0, None).unwrap(), b"");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn read_zero_size_proc_version_has_content() {
        let path = Path::new("/proc/version");
        let meta = std::fs::metadata(path).unwrap();
        assert_eq!(meta.len(), 0, "procfs should report size 0");
        let data = read_zero_size_file(path, 0, None).unwrap();
        assert!(!data.is_empty(), "expected /proc/version bytes");
        assert!(
            std::str::from_utf8(&data).unwrap_or("").contains("Linux"),
            "{}",
            String::from_utf8_lossy(&data)
        );
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn pull_stream_reads_proc_despite_zero_size() {
        let path = Path::new("/proc/version");
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
        let expect = std::fs::read(path).unwrap();
        assert!(!expect.is_empty());
        let (mut client, mut server) = Link::pair(8);
        let serve = tokio::spawn(async move {
            match server.recv().await.unwrap() {
                Wire::Msg(TransferMsg::PullStream { .. }) => {}
                other => panic!("expected PullStream, got {other:?}"),
            }
            serve_pull_stream(
                path,
                0,
                None,
                64 * 1024,
                4,
                CompressPref::Off,
                &mut server,
                "11111111-1111-4111-8111-111111111111",
                "mem",
            )
            .await
        });
        let client_task = tokio::spawn(async move {
            let mut out = Vec::new();
            let body = perform_pull_stream(
                "/proc/version",
                0,
                None,
                &mut out,
                &mut client,
                "11111111-1111-4111-8111-111111111111",
                &XferOpts {
                    chunk_size: 64 * 1024,
                    window: 4,
                    parallel: 1,
                    compress: CompressPref::Off,
                    resume: true,
                    transport: "mem".into(),
                },
            )
            .await;
            (body, out)
        });
        let serve_res = serve.await.unwrap();
        let (body_res, out) = client_task.await.unwrap();
        if let Err(err) = &serve_res {
            panic!("serve failed: {err}");
        }
        let body = body_res.unwrap_or_else(|e| panic!("client failed: {e}"));
        assert_eq!(out, expect);
        assert_eq!(body.file_size, expect.len() as u64);
        assert_eq!(body.end - body.start, expect.len() as u64);
    }

    #[test]
    #[cfg(unix)]
    fn tar_preserves_mode_and_mtime() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        let file = src.join("sub/a.txt");
        std::fs::write(&file, b"hello").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::set_permissions(src.join("sub"), std::fs::Permissions::from_mode(0o750)).unwrap();
        let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_500_000_000);
        let f = std::fs::File::options().write(true).open(&file).unwrap();
        f.set_modified(when).unwrap();
        drop(f);
        let entries = walk_manifest(&src).unwrap();
        let needed: Vec<_> = entries.iter().map(|e| e.rel.clone()).collect();
        let tar_path = dir.path().join("tree.tar");
        write_tar(&tar_path, &src, &entries, &needed).unwrap();
        let dest = dir.path().join("dest");
        unpack_tar(&tar_path, &dest).unwrap();
        let got = std::fs::symlink_metadata(dest.join("sub/a.txt")).unwrap();
        assert_eq!(got.permissions().mode() & 0o777, 0o640);
        assert_eq!(
            got.modified().unwrap(),
            when
        );
        let sub = std::fs::symlink_metadata(dest.join("sub")).unwrap();
        assert_eq!(sub.permissions().mode() & 0o777, 0o750);
    }

    #[test]
    fn walk_and_tar_preserve_relative_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("sub/a.txt"), b"hello").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("a.txt", src.join("sub/link-a")).unwrap();
            std::os::unix::fs::symlink("sub/a.txt", src.join("root-link")).unwrap();
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file("a.txt", src.join("sub/link-a")).unwrap();
            std::os::windows::fs::symlink_file("sub/a.txt", src.join("root-link")).unwrap();
        }
        let entries = walk_manifest(&src).unwrap();
        let links: Vec<_> = entries
            .iter()
            .filter(|e| e.symlink.is_some())
            .map(|e| (e.rel.as_str(), e.symlink.as_deref().unwrap()))
            .collect();
        assert!(
            links.contains(&("sub/link-a", "a.txt")),
            "{links:?}"
        );
        assert!(
            links.contains(&("root-link", "sub/a.txt")),
            "{links:?}"
        );
        let needed: Vec<_> = entries.iter().map(|e| e.rel.clone()).collect();
        let tar_path = dir.path().join("tree.tar");
        write_tar(&tar_path, &src, &entries, &needed).unwrap();
        let dest = dir.path().join("dest");
        unpack_tar(&tar_path, &dest).unwrap();
        assert_eq!(std::fs::read(dest.join("sub/a.txt")).unwrap(), b"hello");
        assert_eq!(
            std::fs::read_link(dest.join("sub/link-a"))
                .unwrap()
                .to_string_lossy(),
            "a.txt"
        );
        assert_eq!(
            std::fs::read_link(dest.join("root-link"))
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/"),
            "sub/a.txt"
        );
        // Second apply should skip identical files and symlinks.
        let needed2 = needed_entries(&dest, &entries).unwrap();
        assert!(needed2.is_empty(), "expected no transfers, got {needed2:?}");
    }

    #[test]
    fn normalize_link_target_collapses_drive_slashes() {
        assert_eq!(
            normalize_link_target_str(r"C:\Users\ada\x"),
            "C:/Users/ada/x"
        );
        assert_eq!(
            normalize_link_target_str("C:///Users/ada/x"),
            "C:/Users/ada/x"
        );
        assert_eq!(
            normalize_link_target_str("//?/C:/Users/ada"),
            "C:/Users/ada"
        );
        assert_eq!(
            normalize_link_target_str("/??/C:/Users/ada"),
            "C:/Users/ada"
        );
        assert_eq!(
            normalize_link_target_str("//./C:/Users/ada"),
            "C:/Users/ada"
        );
        // Live dogfood shape: junction target to a temp sibling.
        assert_eq!(
            normalize_link_target_str("C:///Users/alice/AppData/Local/Temp/al-treej-tgt"),
            "C:/Users/alice/AppData/Local/Temp/al-treej-tgt"
        );
    }

    #[test]
    fn normalize_link_target_tightens_trailing_and_internal_slashes() {
        assert_eq!(normalize_link_target_str(r"\\?\C:\Users\x\"), "C:/Users/x");
        assert_eq!(
            normalize_link_target_str("C:/Users//alice/x"),
            "C:/Users/alice/x"
        );
        assert_eq!(
            normalize_link_target_str("C:\\Users\\\\alice\\x\\"),
            "C:/Users/alice/x"
        );
        // Bare drive roots keep their separator.
        assert_eq!(normalize_link_target_str(r"C:\"), "C:/");
        assert_eq!(normalize_link_target_str("C:/"), "C:/");
    }

    #[test]
    fn normalize_link_target_keeps_relatives_and_unc() {
        assert_eq!(normalize_link_target_str("../inner"), "../inner");
        assert_eq!(
            normalize_link_target_str("with-empty-child"),
            "with-empty-child"
        );
        assert_eq!(normalize_link_target_str("a//b"), "a/b");
        assert_eq!(normalize_link_target_str("./x"), "./x");
        // Traditional UNC and the extended `\\?\UNC\` form both stay UNC.
        assert_eq!(
            normalize_link_target_str(r"\\server\share\"),
            "//server/share"
        );
        assert_eq!(
            normalize_link_target_str(r"\\?\UNC\server\share\x"),
            "//server/share/x"
        );
    }

    #[test]
    fn normalize_link_target_is_idempotent() {
        for raw in [
            "C:///Users/alice/AppData/Local/Temp/al-treej-tgt",
            r"\\?\C:\Users\x\",
            "C:/Users//alice/x",
            "//?/C:/Users/ada/",
            r"\\?\UNC\server\share\x",
            "a//b",
            "../inner",
        ] {
            let once = normalize_link_target_str(raw);
            assert_eq!(
                normalize_link_target_str(&once),
                once,
                "second normalize changed {raw:?} -> {once:?}"
            );
        }
    }

    #[test]
    fn relative_from_to_handles_siblings_and_nesting() {
        assert_eq!(relative_from_to("", "with-empty-child"), "with-empty-child");
        assert_eq!(relative_from_to("sub", "sub/a.txt"), "a.txt");
        assert_eq!(relative_from_to("sub/nested", "other"), "../../other");
        assert_eq!(relative_from_to("a/b", "a/b"), ".");
    }

    #[test]
    fn path_has_root_prefix_requires_component_boundary() {
        assert_eq!(
            path_has_root_prefix("C:/tmp/al-treej/sub", "C:/tmp/al-treej").as_deref(),
            Some("sub")
        );
        assert_eq!(
            path_has_root_prefix("C:/tmp/al-treej", "C:/tmp/al-treej").as_deref(),
            Some("")
        );
        // Sibling that shares a string prefix must NOT match.
        assert_eq!(
            path_has_root_prefix("C:/tmp/al-treej-tgt", "C:/tmp/al-treej"),
            None
        );
        assert_eq!(
            path_has_root_prefix("C:/tmp/al-treejunc", "C:/tmp/al-treej"),
            None
        );
    }

    #[test]
    fn symlink_outside_root_sibling_prefix_stays_absolute() {
        // Live bug: junction …/al-treej/junc → …/al-treej-tgt became "-tgt"
        // because strip_prefix treated the sibling as under the root.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("al-treej");
        let outside = dir.path().join("al-treej-tgt");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("j.txt"), b"j").unwrap();
        let link = src.join("junc");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&outside, &link).unwrap();

        let entries = walk_manifest(&src).unwrap();
        let entry = entries.iter().find(|e| e.rel == "junc").expect("junc");
        let target = entry.symlink.as_deref().expect("symlink target");
        assert!(
            !target.starts_with('-'),
            "must not emit mangled relative like -tgt, got {target:?}"
        );
        assert!(
            !target.contains(".."),
            "outside-root sibling must stay absolute, got {target:?}"
        );
        let norm = normalize_link_target_str(&outside.to_string_lossy());
        #[cfg(windows)]
        let norm = norm.to_ascii_lowercase();
        #[cfg(windows)]
        let target_cmp = target.to_ascii_lowercase();
        #[cfg(not(windows))]
        let target_cmp = target.to_string();
        assert_eq!(target_cmp, norm, "expected absolute outside target");
    }

    #[test]
    fn walk_absolutizes_in_tree_symlink_to_relative() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("with-empty-child")).unwrap();
        std::fs::write(src.join("with-empty-child/a.txt"), b"hi").unwrap();
        let abs_target = src.join("with-empty-child");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&abs_target, src.join("junc-child")).unwrap();
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(&abs_target, src.join("junc-child")).unwrap();
        }
        let entries = walk_manifest(&src).unwrap();
        let link = entries
            .iter()
            .find(|e| e.rel == "junc-child")
            .expect("junc-child");
        assert_eq!(
            link.symlink.as_deref(),
            Some("with-empty-child"),
            "absolute in-tree target should become relative, got {:?}",
            link.symlink
        );
        let needed: Vec<_> = entries.iter().map(|e| e.rel.clone()).collect();
        let tar_path = dir.path().join("tree.tar");
        write_tar(&tar_path, &src, &entries, &needed).unwrap();
        let dest = dir.path().join("dest-elsewhere");
        unpack_tar(&tar_path, &dest).unwrap();
        assert_eq!(
            std::fs::read_link(dest.join("junc-child"))
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/"),
            "with-empty-child"
        );
        assert_eq!(
            std::fs::read(dest.join("junc-child/a.txt")).unwrap(),
            b"hi"
        );
    }

    #[test]
    fn unpack_roundtrip_and_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("sub/a.txt"), b"hello").unwrap();
        let entries = walk_manifest(&src).unwrap();
        let needed: Vec<_> = entries.iter().map(|entry| entry.rel.clone()).collect();
        let tar_path = dir.path().join("tree.tar");
        write_tar(&tar_path, &src, &entries, &needed).unwrap();
        let dest = dir.path().join("dest");
        let files = unpack_tar(&tar_path, &dest).unwrap();
        assert!(files >= 1, "{files}");
        assert_eq!(std::fs::read(dest.join("sub/a.txt")).unwrap(), b"hello");

        #[cfg(unix)]
        {
            let outside = dir.path().join("outside");
            std::fs::create_dir(&outside).unwrap();
            let escaped = dir.path().join("escaped");
            std::fs::create_dir(&escaped).unwrap();
            std::os::unix::fs::symlink(&outside, escaped.join("link")).unwrap();
            let evil = dir.path().join("evil.tar");
            let file = std::fs::File::create(&evil).unwrap();
            let mut builder = tar::Builder::new(file);
            let mut header = tar::Header::new_gnu();
            header.set_path("link/pwned").unwrap();
            header.set_size(4);
            header.set_cksum();
            builder.append(&header, &b"pwn!"[..]).unwrap();
            builder.finish().unwrap();
            let err = unpack_tar(&evil, &escaped).unwrap_err();
            assert!(err.to_string().contains("symlink"), "{err}");
            assert!(!outside.join("pwned").exists());
        }
    }

    struct Short<R> {
        inner: R,
        cap: usize,
    }

    impl<R: Read> Read for Short<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.cap);
            self.inner.read(&mut buf[..n])
        }
    }
}

#[cfg(test)]
mod transfer_progress_tests {
    use super::transfer_progress;

    #[test]
    fn fresh_transfer_counts_bytes_sent() {
        assert_eq!(transfer_progress(1_000, 1_000, 250), 250);
    }

    #[test]
    fn resume_includes_bytes_already_present() {
        assert_eq!(transfer_progress(1_000, 200, 50), 850);
    }

    #[test]
    fn progress_caps_at_total() {
        assert_eq!(transfer_progress(1_000, 1_000, 5_000), 1_000);
        assert_eq!(transfer_progress(1_000, 5_000, 10), 10);
    }
}

#[cfg(all(test, unix))]
mod symlink_unpack_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn symlink_to_an_outside_file_does_not_change_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("victim.txt");
        std::fs::write(&victim, b"keep").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;

        let tar_path = dir.path().join("escape.tar");
        {
            let file = File::create(&tar_path).unwrap();
            let mut builder = tar::Builder::new(file);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_path("link").unwrap();
            header.set_link_name(victim.to_str().unwrap()).unwrap();
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }
        let dest = dir.path().join("dest");
        let err = unpack_tar(&tar_path, &dest).unwrap_err();
        let after = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(before, after, "{err}");
        assert!(err.to_string().contains("escapes"), "{err}");
        assert!(!dest.join("link").exists());
    }

    #[test]
    fn unpack_tar_rejects_hardlink_and_fifo_entries() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("hardlink.tar");
        {
            let file = File::create(&tar_path).unwrap();
            let mut builder = tar::Builder::new(file);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_path("hard").unwrap();
            header.set_link_name("/etc/passwd").unwrap();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }
        let dest = dir.path().join("dest");
        assert!(
            unpack_tar(&tar_path, &dest).is_err(),
            "unpack_tar must reject tar hardlink entries instead of creating stub files"
        );
        assert!(!dest.join("hard").exists());
    }
}

#[cfg(test)]
mod chunk_bounds_tests {
    use super::*;

    #[tokio::test]
    async fn recv_blob_and_decoded_chunk_reject_oversized_zstd_and_out_of_bounds_hole() {
        let req_id = uuid::Uuid::new_v4().to_string();
        let bomb = zstd::bulk::compress(&vec![b'z'; 8 * 1024 * 1024], 3).unwrap();
        let raw_bomb_frame = frame::encode(&frame::DataFrame {
            request_id: req_id.clone(),
            offset: 0,
            raw_len: (8 * 1024 * 1024) as u32,
            compressed: true,
            hole: false,
            tar: false,
            payload: bomb,
        })
        .unwrap();
        assert!(
            decoded_chunk(&raw_bomb_frame).is_err(),
            "decoded_chunk must reject raw_len > frame::MAX_CHUNK"
        );

        // Out-of-bounds hole frame in recv_blob (offset + raw_len > declared blob size)
        let dir = tempfile::tempdir().unwrap();
        let partial = dir.path().join("blob.part");
        let journal = dir.path().join("blob.journal.json");
        let dest = dir.path().join("blob.final");
        let (tx_link, mut rx_link) = Link::pair(8);
        let hole_oob = frame::encode(&frame::DataFrame {
            request_id: req_id,
            offset: 512,
            raw_len: 4096,
            compressed: false,
            hole: true,
            tar: false,
            payload: Vec::new(),
        })
        .unwrap();
        tx_link.send_frame(hole_oob).await.unwrap();
        drop(tx_link);
        let res = recv_blob(
            &mut rx_link,
            &partial,
            &journal,
            1024,
            "00",
            Vec::new(),
            &dest,
            false,
            &None,
        )
        .await;
        assert!(res.is_err());
        let len_on_disk = std::fs::metadata(&partial).map(|m| m.len()).unwrap_or(0);
        assert!(
            len_on_disk <= 1024,
            "out-of-bounds hole extended partial file to {len_on_disk} > 1024"
        );
    }
}
