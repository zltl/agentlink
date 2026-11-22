//! Search, edit, watch, background processes, and system info for the phone.
//!
//! Paths stay inside `app:/files`, `app:/cache`, and `storage:/`. A `saf:/`
//! folder is not a plain directory, so these tools reject it. Watches and
//! background processes live for the life of the node process and survive a
//! relay reconnect. A watch is scanned when the client polls, which does not
//! need an inotify backend. Background commands run in the app sandbox shell.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentlink_core::process;
use agentlink_core::util;
use agentlink_core::{Error, Result};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use regex::RegexBuilder;
use serde_json::{json, Value};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

use crate::paths::{self, Roots};

const MAX_PATTERN: usize = 4 * 1024;
const MAX_FILE: u64 = 4 * 1024 * 1024;
const MAX_EDIT: usize = 8 * 1024 * 1024;
const MAX_TEXT: usize = 1024 * 1024;
const MAX_PATCH: usize = 1024 * 1024;
const MAX_SCAN: u32 = 20_000;
const MAX_OFFSET: u32 = 10_000;
const MAX_LIMIT: u32 = 500;
const MAX_CONTEXT: u32 = 20;
const MAX_WATCHES: usize = 32;
const MAX_EVENTS: usize = 1000;
const MAX_PROCS: usize = 32;
const OUTPUT_CAP: usize = 1024 * 1024;

#[derive(Clone)]
pub struct ToolState {
    watches: WatchHub,
    procs: ProcHub,
}

impl Default for ToolState {
    fn default() -> Self {
        Self {
            watches: WatchHub::default(),
            procs: ProcHub::default(),
        }
    }
}

impl ToolState {
    pub fn shutdown(&self) {
        self.procs.kill_all();
        self.watches.clear();
    }

    pub fn close_inactive(&self, revoked: &BTreeSet<String>, now_unix: i64, fail_closed: bool) {
        self.procs.close_inactive(revoked, now_unix, fail_closed);
        self.watches.close_inactive(revoked, now_unix, fail_closed);
    }
}

pub struct ContentQuery {
    pub path: String,
    pub pattern: String,
    pub literal: bool,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub gitignore: bool,
    pub include_hidden: bool,
    pub case_insensitive: bool,
    pub before: u32,
    pub after: u32,
    pub offset: u32,
    pub limit: u32,
}

pub struct NameQuery {
    pub path: String,
    pub pattern: String,
    pub regex: bool,
    pub gitignore: bool,
    pub include_hidden: bool,
    pub case_insensitive: bool,
    pub offset: u32,
    pub limit: u32,
}

pub async fn content_search(roots: Roots, query: ContentQuery) -> Result<Value> {
    tokio::task::spawn_blocking(move || content_search_blocking(&roots, &query))
        .await
        .map_err(|err| Error::Message(format!("search task: {err}")))?
}

pub async fn filename_search(roots: Roots, query: NameQuery) -> Result<Value> {
    tokio::task::spawn_blocking(move || filename_search_blocking(&roots, &query))
        .await
        .map_err(|err| Error::Message(format!("search task: {err}")))?
}

pub async fn replace(
    roots: Roots,
    path: String,
    old: String,
    new: String,
    replace_all: bool,
) -> Result<Value> {
    tokio::task::spawn_blocking(move || replace_blocking(&roots, &path, &old, &new, replace_all))
        .await
        .map_err(|err| Error::Message(format!("edit task: {err}")))?
}

pub async fn edit_lines(
    roots: Roots,
    path: String,
    start_line: u32,
    end_line: u32,
    content: String,
) -> Result<Value> {
    tokio::task::spawn_blocking(move || {
        edit_lines_blocking(&roots, &path, start_line, end_line, &content)
    })
    .await
    .map_err(|err| Error::Message(format!("edit task: {err}")))?
}

pub async fn apply_patch(roots: Roots, root: String, patch: String) -> Result<Value> {
    tokio::task::spawn_blocking(move || apply_patch_blocking(&roots, &root, &patch))
        .await
        .map_err(|err| Error::Message(format!("patch task: {err}")))?
}

pub async fn watch_start(
    state: &ToolState,
    roots: &Roots,
    path: &str,
    recursive: bool,
    owner_peer: &str,
    grant_jti: &str,
    grant_exp_unix: Option<i64>,
) -> Result<Value> {
    state
        .watches
        .start(roots, path, recursive, owner_peer, grant_jti, grant_exp_unix)
        .await
}

pub async fn watch_poll(
    state: &ToolState,
    id: &str,
    cursor: u64,
    timeout_ms: u64,
    limit: u32,
    peer: &str,
) -> Result<Value> {
    state
        .watches
        .poll(id, cursor, timeout_ms, limit, peer)
        .await
}

pub fn watch_stop(state: &ToolState, id: &str, peer: &str) -> Result<Value> {
    state.watches.stop(id, peer)
}


fn decode_stdin_b64(b64: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    const MAX_STDIN: usize = 16 * 1024 * 1024;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|err| Error::Message(format!("stdin_b64: {err}")))?;
    if bytes.len() > MAX_STDIN {
        return Err(Error::Message(format!(
            "stdin is {} bytes; max is {MAX_STDIN}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

pub async fn bg_start(
    state: &ToolState,
    roots: &Roots,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    env: &[(String, String)],
    shell: bool,
    stdin_b64: Option<&str>,
    owner_peer: &str,
    grant_jti: &str,
    grant_exp_unix: Option<i64>,
) -> Result<Value> {
    let stdin = match stdin_b64 {
        Some(b64) => Some(decode_stdin_b64(b64)?),
        None => None,
    };
    let procs = state.procs.clone();
    let roots = roots.clone();
    let program = program.to_string();
    let args = args.to_vec();
    let cwd = cwd.map(str::to_string);
    let env = env.to_vec();
    let owner_peer = owner_peer.to_string();
    let grant_jti = grant_jti.to_string();
    tokio::task::spawn_blocking(move || {
        procs.start(
            &roots,
            &program,
            &args,
            cwd.as_deref(),
            &env,
            shell,
            stdin.as_deref(),
            &owner_peer,
            &grant_jti,
            grant_exp_unix,
        )
    })
    .await
    .map_err(|err| Error::Message(format!("bg_start task: {err}")))?
}

pub fn bg_list(state: &ToolState, peer: &str) -> Result<Value> {
    state.procs.list(peer)
}

pub fn bg_output(
    state: &ToolState,
    id: &str,
    stdout_cursor: u64,
    stderr_cursor: u64,
    max_bytes: u32,
    peer: &str,
) -> Result<Value> {
    state
        .procs
        .output(id, stdout_cursor, stderr_cursor, max_bytes, peer)
}

pub fn bg_status(state: &ToolState, id: &str, peer: &str) -> Result<Value> {
    state.procs.status(id, peer)
}

pub async fn bg_kill(state: &ToolState, id: &str, peer: &str) -> Result<Value> {
    let procs = state.procs.clone();
    let id = id.to_string();
    let peer = peer.to_string();
    tokio::task::spawn_blocking(move || procs.kill(&id, &peer))
        .await
        .map_err(|err| Error::Message(format!("bg_kill task: {err}")))?
}

pub async fn system_info() -> Result<Value> {
    tokio::task::spawn_blocking(system_info_blocking)
        .await
        .map_err(|err| Error::Message(format!("system info task: {err}")))?
}

struct Located {
    real: PathBuf,
    guest: String,
}

fn locate(roots: &Roots, guest: &str, write: bool) -> Result<Located> {
    let real = paths::real_target(roots, guest, write)?;
    Ok(Located {
        real,
        guest: guest.trim().replace('\\', "/"),
    })
}

fn locate_no_follow(roots: &Roots, guest: &str, write: bool) -> Result<Located> {
    let (target, _) = paths::classify_entry_with_root(roots, guest, write, false)?;
    let real = match target {
        paths::GuestTarget::Real(path) => path,
        _ => {
            return Err(Error::Message(format!(
                "{guest} is not a writable filesystem path"
            )))
        }
    };
    Ok(Located {
        real,
        guest: guest.trim().replace('\\', "/"),
    })
}

fn ensure_not_symlink(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if agentlink_core::paths::is_link_entry(&meta) {
            return Err(Error::PermissionDenied(
                "refusing to write through a symbolic link".into(),
            ));
        }
    }
    Ok(())
}

fn guest_of(root_guest: &str, root_real: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root_real).unwrap_or(path);
    let rel = rel.to_string_lossy().replace('\\', "/");
    if rel.is_empty() || rel == "." {
        root_guest.to_string()
    } else {
        format!("{}/{}", root_guest.trim_end_matches('/'), rel)
    }
}

fn content_search_blocking(roots: &Roots, query: &ContentQuery) -> Result<Value> {
    validate_pattern(&query.pattern)?;
    check_offset(query.offset)?;
    let limit = clamp_limit(query.limit, 100);
    let before = query.before.min(MAX_CONTEXT) as usize;
    let after = query.after.min(MAX_CONTEXT) as usize;
    let located = locate(roots, &query.path, false)?;
    if !located.real.exists() {
        return Err(Error::NotFound(located.guest));
    }
    let escaped;
    let pattern = if query.literal {
        escaped = regex::escape(&query.pattern);
        escaped.as_str()
    } else {
        query.pattern.as_str()
    };
    let matcher = RegexBuilder::new(pattern)
        .case_insensitive(query.case_insensitive)
        .size_limit(1 << 20)
        .build()
        .map_err(|err| Error::Message(format!("pattern: {err}")))?;
    let include = globs(&query.include, query.case_insensitive)?;
    let exclude = globs(&query.exclude, query.case_insensitive)?;
    let mut hits: Vec<Value> = Vec::new();
    let mut seen = 0u32;
    let mut truncated = false;
    let mut scanned = 0u32;
    let mut visit = |real: &Path| -> Result<bool> {
        if scanned >= MAX_SCAN {
            truncated = true;
            return Ok(true);
        }
        let rel = real
            .strip_prefix(&located.real)
            .unwrap_or(real)
            .to_string_lossy()
            .replace('\\', "/");
        if !glob_ok(&rel, &include, &exclude) {
            return Ok(false);
        }
        let meta = fs::metadata(real)?;
        if !meta.is_file() || meta.len() > MAX_FILE || looks_binary(real) {
            return Ok(false);
        }
        scanned += 1;
        let text = fs::read_to_string(real).unwrap_or_default();
        let lines: Vec<&str> = text.split('\n').collect();
        let mut recent = VecDeque::new();
        let mut pending_after = 0usize;
        for (index, line) in lines.iter().enumerate() {
            let shown = line.trim_end_matches('\r');
            if pending_after > 0 {
                if let Some(hit) = hits.last_mut() {
                    if let Some(arr) = hit.get_mut("after").and_then(|value| value.as_array_mut()) {
                        arr.push(json!({"line": index + 1, "text": shown}));
                    }
                }
                pending_after -= 1;
            }
            if matcher.is_match(shown) {
                seen += 1;
                if seen > query.offset && (hits.len() as u32) < limit {
                    let before_json: Vec<_> = recent
                        .iter()
                        .map(|(n, text)| json!({"line": n, "text": text}))
                        .collect();
                    hits.push(json!({
                        "path": guest_of(&located.guest, &located.real, real),
                        "line": index + 1,
                        "text": shown,
                        "before": before_json,
                        "after": [],
                    }));
                    pending_after = after;
                } else if seen > query.offset {
                    truncated = true;
                    return Ok(true);
                }
            }
            recent.push_back((index + 1, shown.to_string()));
            while recent.len() > before {
                recent.pop_front();
            }
        }
        Ok(false)
    };
    if located.real.is_file() {
        visit(&located.real)?;
    } else {
        for path in walk_files(&located.real, query.gitignore, query.include_hidden)? {
            if visit(&path)? {
                break;
            }
        }
    }
    Ok(json!({
        "matches": hits,
        "truncated": truncated,
        "next_offset": query.offset + hits.len() as u32,
        "scanned_files": scanned,
    }))
}

fn filename_search_blocking(roots: &Roots, query: &NameQuery) -> Result<Value> {
    validate_pattern(&query.pattern)?;
    check_offset(query.offset)?;
    let limit = clamp_limit(query.limit, 200);
    let located = locate(roots, &query.path, false)?;
    if !located.real.exists() {
        return Err(Error::NotFound(located.guest));
    }
    let regex = if query.regex {
        Some(
            RegexBuilder::new(&query.pattern)
                .case_insensitive(query.case_insensitive)
                .size_limit(1 << 20)
                .build()
                .map_err(|err| Error::Message(format!("pattern: {err}")))?,
        )
    } else {
        None
    };
    let glob = if query.regex {
        None
    } else {
        Some(
            GlobBuilder::new(&query.pattern)
                .case_insensitive(query.case_insensitive)
                .literal_separator(false)
                .build()
                .map_err(|err| Error::Message(format!("glob: {err}")))?
                .compile_matcher(),
        )
    };
    let mut found = Vec::new();
    let mut seen = 0u32;
    let mut truncated = false;
    let mut consider = |real: &Path, is_dir: bool, is_file: bool, size: u64| -> bool {
        let rel = real
            .strip_prefix(&located.real)
            .unwrap_or(real)
            .to_string_lossy()
            .replace('\\', "/");
        let name = real
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let matched = if let Some(regex) = &regex {
            regex.is_match(&rel) || regex.is_match(&name)
        } else if let Some(glob) = &glob {
            glob.is_match(&rel) || glob.is_match(&name)
        } else {
            false
        };
        if !matched {
            return false;
        }
        seen += 1;
        if seen <= query.offset {
            return false;
        }
        if found.len() as u32 >= limit {
            truncated = true;
            return true;
        }
        found.push(json!({
            "path": guest_of(&located.guest, &located.real, real),
            "name": name,
            "is_dir": is_dir,
            "is_file": is_file,
            "size": size,
        }));
        false
    };
    if located.real.is_file() {
        let size = fs::metadata(&located.real)
            .map(|meta| meta.len())
            .unwrap_or(0);
        consider(&located.real, false, true, size);
    } else {
        let mut builder = WalkBuilder::new(&located.real);
        builder
            .standard_filters(false)
            .hidden(!query.include_hidden)
            .git_ignore(query.gitignore)
            .git_exclude(false)
            .git_global(false)
            .parents(false)
            .require_git(false)
            .follow_links(false);
        for entry in builder.build() {
            let Ok(entry) = entry else { continue };
            if entry.path() == located.real {
                continue;
            }
            let Some(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            let size = entry.metadata().map(|meta| meta.len()).unwrap_or(0);
            if consider(entry.path(), kind.is_dir(), kind.is_file(), size) {
                break;
            }
        }
    }
    found.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(json!({
        "matches": found,
        "truncated": truncated,
        "next_offset": query.offset + found.len() as u32,
    }))
}

fn replace_blocking(
    roots: &Roots,
    path: &str,
    old: &str,
    new: &str,
    replace_all: bool,
) -> Result<Value> {
    if old.is_empty() {
        return Err(Error::Message("old string is empty".into()));
    }
    if old.len() > MAX_TEXT || new.len() > MAX_TEXT {
        return Err(Error::Message("replacement text exceeds 1 MiB".into()));
    }
    let sandbox_root = paths::sandbox_root_for_guest(roots, path);
    let located = locate_no_follow(roots, path, true)?;
    ensure_not_symlink(&located.real)?;
    let before = read_text(&located.real)?;
    let count = before.matches(old).count();
    if count == 0 {
        return Err(Error::Message(format!(
            "old string was not found in {}",
            located.guest
        )));
    }
    if count > 1 && !replace_all {
        return Err(Error::Message(format!(
            "found {count} matches of the old string in {}; pass --all (CLI) or replace_all (MCP/API) to replace every match",
            located.guest
        )));
    }
    let after = if replace_all {
        before.replace(old, new)
    } else {
        before.replacen(old, new, 1)
    };
    atomic_write(sandbox_root.as_deref(), &located.real, after.as_bytes())?;
    Ok(json!({
        "path": located.guest,
        "replacements": if replace_all { count } else { 1 },
    }))
}

fn edit_lines_blocking(
    roots: &Roots,
    path: &str,
    start_line: u32,
    end_line: u32,
    content: &str,
) -> Result<Value> {
    if content.len() > MAX_TEXT {
        return Err(Error::Message("replacement text exceeds 1 MiB".into()));
    }
    if start_line == 0 || end_line == 0 {
        return Err(Error::Message("line numbers are 1-based".into()));
    }
    if end_line < start_line {
        return Err(Error::Message(format!(
            "end line {end_line} is before start line {start_line}"
        )));
    }
    let sandbox_root = paths::sandbox_root_for_guest(roots, path);
    let located = locate_no_follow(roots, path, true)?;
    ensure_not_symlink(&located.real)?;
    let before = if located.real.exists() {
        read_text(&located.real)?
    } else if start_line == 1 {
        String::new()
    } else {
        return Err(Error::NotFound(located.guest));
    };
    let trailing = before.ends_with('\n');
    let mut lines = split_lines(&before);
    let n = lines.len() as u32;
    if start_line > n + 1
        || (start_line <= n && end_line > n)
        || (start_line == n + 1 && end_line != start_line)
    {
        return Err(Error::Message(format!(
            "line range {start_line}-{end_line} is outside {} (file has {n} lines)",
            located.guest
        )));
    }
    let start_idx = (start_line - 1) as usize;
    let end_idx = if start_line == n + 1 {
        lines.len()
    } else {
        end_line as usize
    };
    let replacement = split_lines(content);
    lines.splice(start_idx..end_idx, replacement);
    let mut after = lines.join("\n");
    if trailing || content.ends_with('\n') {
        after.push('\n');
    }
    atomic_write(sandbox_root.as_deref(), &located.real, after.as_bytes())?;
    Ok(json!({
        "path": located.guest,
        "start_line": start_line,
        "end_line": end_line,
    }))
}

fn apply_patch_blocking(roots: &Roots, root: &str, patch: &str) -> Result<Value> {
    if patch.len() > MAX_PATCH {
        return Err(Error::Message("patch exceeds 1 MiB".into()));
    }
    if patch.trim().is_empty() {
        return Err(Error::Message("patch is empty".into()));
    }
    let sandbox_root = paths::sandbox_root_for_guest(roots, root);
    let located = locate(roots, root, true)?;
    if !located.real.is_dir() {
        return Err(Error::Message(format!(
            "{} is not a directory",
            located.guest
        )));
    }
    let sections = split_patch(patch)?;
    let mut planned = Vec::new();
    for section in sections {
        let target = section
            .new_path
            .clone()
            .or(section.old_path.clone())
            .ok_or_else(|| Error::Message("patch section has no path".into()))?;
        let rel = safe_relative(&target)?;
        let full = located.real.join(&rel);
        let confined = agentlink_core::paths::ensure_path_stays_in_sandbox_at_sink(
            sandbox_root.as_deref(),
            &full,
        )?;
        ensure_not_symlink(&confined)?;
        let exists = confined.is_file();
        let before = if exists {
            read_text(&confined)?
        } else {
            String::new()
        };
        let after = if section.new_path.is_none() {
            String::new()
        } else {
            match apply_diff(&before, &section.text) {
                Ok(text) => text,
                Err(err) if section.old_path.is_none() => {
                    added_lines(&section.text).ok_or_else(|| {
                        Error::Message(format!("could not apply new-file patch: {err}"))
                    })?
                }
                Err(err) => return Err(Error::Message(format!("patch {}: {err}", rel.display()))),
            }
        };
        let action = if section.new_path.is_none() {
            "delete"
        } else if !exists {
            "create"
        } else {
            "update"
        };
        planned.push((confined, rel, after, action));
    }
    let mut files = Vec::new();
    for (full, rel, after, action) in planned {
        if action == "delete" {
            let checked = agentlink_core::paths::ensure_path_stays_in_sandbox_at_sink(
                sandbox_root.as_deref(),
                &full,
            )?;
            ensure_not_symlink(&checked)?;
            if checked.exists() {
                fs::remove_file(&checked)?;
            }
        } else {
            atomic_write(sandbox_root.as_deref(), &full, after.as_bytes())?;
        }
        files.push(json!({
            "path": guest_of(&located.guest, &located.real, &full),
            "action": action,
        }));
        let _ = rel;
    }
    Ok(json!({
        "root": located.guest,
        "files": files,
    }))
}

fn walk_files(root: &Path, gitignore: bool, include_hidden: bool) -> Result<Vec<PathBuf>> {
    let mut builder = WalkBuilder::new(root);
    builder
        .standard_filters(false)
        .hidden(!include_hidden)
        .git_ignore(gitignore)
        .git_exclude(false)
        .git_global(false)
        .parents(false)
        .require_git(false)
        .follow_links(false);
    let mut out = Vec::new();
    for entry in builder.build() {
        let Ok(entry) = entry else { continue };
        let Some(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_file() && !kind.is_symlink() {
            out.push(entry.path().to_path_buf());
        }
    }
    Ok(out)
}

fn globs(patterns: &[String], case_insensitive: bool) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            GlobBuilder::new(pattern)
                .case_insensitive(case_insensitive)
                .literal_separator(false)
                .build()
                .map_err(|err| Error::Message(format!("glob: {err}")))?,
        );
    }
    Ok(Some(
        builder
            .build()
            .map_err(|err| Error::Message(format!("glob: {err}")))?,
    ))
}

fn glob_ok(rel: &str, include: &Option<GlobSet>, exclude: &Option<GlobSet>) -> bool {
    if let Some(exclude) = exclude {
        if exclude.is_match(rel) {
            return false;
        }
    }
    if let Some(include) = include {
        return include.is_match(rel);
    }
    true
}

fn looks_binary(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return true,
    };
    let mut buf = [0u8; 8192];
    let n = file.read(&mut buf).unwrap_or(0);
    buf[..n].contains(&0)
}

fn read_text(path: &Path) -> Result<String> {
    let meta = fs::metadata(path)?;
    if meta.len() > MAX_EDIT as u64 {
        return Err(Error::Message("file exceeds 8 MiB".into()));
    }
    let bytes = fs::read(path)?;
    if bytes.contains(&0) {
        return Err(Error::Message(format!(
            "{} is not a text file",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|_| Error::Message(format!("{} is not utf-8", path.display())))
}

fn open_new_nofollow(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(0x0020_0000);
    }
    opts.open(path)
}

fn atomic_write(sandbox_root: Option<&Path>, path: &Path, bytes: &[u8]) -> Result<()> {
    let target = agentlink_core::paths::ensure_path_stays_in_sandbox_at_sink(sandbox_root, path)?;
    ensure_not_symlink(&target)?;
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        agentlink_core::paths::ensure_path_stays_in_sandbox_at_sink(sandbox_root, parent)?;
        fs::create_dir_all(parent)?;
        agentlink_core::paths::ensure_path_stays_in_sandbox_at_sink(sandbox_root, parent)?;
    }
    let tmp = parent.join(format!(".agentlink-tmp-{}", util::random_hex(12)));
    let write_res = (|| -> Result<()> {
        let mut file = open_new_nofollow(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all().ok();
        drop(file);
        let checked =
            agentlink_core::paths::ensure_path_stays_in_sandbox_at_sink(sandbox_root, &target)?;
        ensure_not_symlink(&checked)?;
        agentlink_core::paths::rename_within_sandbox(sandbox_root, &tmp, &checked)?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_res
}

fn split_lines(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|line| line.trim_end_matches('\r').to_string())
        .collect();
    if text.ends_with('\n') || text.ends_with("\r\n") {
        lines.pop();
    }
    lines
}

fn apply_diff(before: &str, patch_text: &str) -> std::result::Result<String, String> {
    let patch = diffy::Patch::from_str(patch_text).map_err(|err| err.to_string())?;
    diffy::apply(before, &patch).map_err(|err| err.to_string())
}

fn added_lines(patch_text: &str) -> Option<String> {
    let mut lines = Vec::new();
    let mut in_hunk = false;
    for line in patch_text.split('\n') {
        if line.starts_with("@@") {
            in_hunk = true;
            continue;
        }
        if !in_hunk {
            continue;
        }
        if let Some(rest) = line.strip_prefix('+') {
            lines.push(rest.to_string());
        }
    }
    if lines.is_empty() {
        None
    } else {
        Some(format!("{}\n", lines.join("\n")))
    }
}

struct Section {
    old_path: Option<String>,
    new_path: Option<String>,
    text: String,
}

fn split_patch(patch: &str) -> Result<Vec<Section>> {
    let normalized = patch.replace("\r\n", "\n");
    let mut lines: Vec<&str> = normalized.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let mut headers = Vec::new();
    for index in 0..lines.len().saturating_sub(1) {
        if lines[index].starts_with("--- ") && lines[index + 1].starts_with("+++ ") {
            headers.push(index);
        }
    }
    if headers.is_empty() {
        return Err(Error::Message(
            "patch has no unified diff headers (--- / +++)".into(),
        ));
    }
    let mut sections = Vec::new();
    for (nth, start) in headers.iter().copied().enumerate() {
        let end = headers.get(nth + 1).copied().unwrap_or(lines.len());
        let old_path = parse_diff_path(&lines[start][4..]);
        let new_path = parse_diff_path(&lines[start + 1][4..]);
        let mut text = String::new();
        text.push_str(lines[start]);
        text.push('\n');
        text.push_str(lines[start + 1]);
        text.push('\n');
        for line in &lines[start + 2..end] {
            if line.starts_with("diff --git ") || line.starts_with("index ") {
                break;
            }
            if line.starts_with('\\') {
                continue;
            }
            if line.starts_with("@@")
                || line.starts_with('+')
                || line.starts_with('-')
                || line.starts_with(' ')
                || line.is_empty()
            {
                text.push_str(line);
                text.push('\n');
            }
        }
        sections.push(Section {
            old_path,
            new_path,
            text,
        });
    }
    Ok(sections)
}

fn parse_diff_path(raw: &str) -> Option<String> {
    let mut text = raw.trim();
    if let Some((path, _)) = text.split_once('\t') {
        text = path.trim();
    }
    if text == "/dev/null" || text.is_empty() {
        return None;
    }
    let text = text
        .strip_prefix("a/")
        .or_else(|| text.strip_prefix("b/"))
        .unwrap_or(text);
    if text == "/dev/null" || text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn safe_relative(raw: &str) -> Result<PathBuf> {
    if raw.is_empty() || raw.contains('\0') || raw.contains(':') {
        return Err(Error::Message(format!("invalid patch path '{raw}'")));
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(Error::Message(format!(
            "patch path must stay inside the root: {raw}"
        )));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(Error::Message(format!(
                    "patch path escapes the root: {raw}"
                )))
            }
        }
    }
    Ok(path.to_path_buf())
}

fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern.is_empty() {
        return Err(Error::Message("pattern is empty".into()));
    }
    if pattern.len() > MAX_PATTERN {
        return Err(Error::Message("pattern exceeds 4 KiB".into()));
    }
    Ok(())
}

fn check_offset(offset: u32) -> Result<()> {
    if offset > MAX_OFFSET {
        return Err(Error::Message(format!(
            "offset {offset} exceeds the {MAX_OFFSET} limit"
        )));
    }
    Ok(())
}

fn clamp_limit(limit: u32, default: u32) -> u32 {
    if limit == 0 {
        default
    } else {
        limit.min(MAX_LIMIT)
    }
}

#[derive(Clone)]
struct WatchHub {
    inner: Arc<Mutex<HashMap<String, Watch>>>,
}

impl Default for WatchHub {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct Watch {
    root: PathBuf,
    root_guest: String,
    recursive: bool,
    owner_peer: String,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
    snapshot: HashMap<PathBuf, Snap>,
    events: VecDeque<Stored>,
    next_seq: u64,
}

#[derive(Clone)]
struct Snap {
    len: u64,
    modified: Option<SystemTime>,
    is_dir: bool,
}

struct Stored {
    seq: u64,
    kind: String,
    paths: Vec<String>,
    unix_ms: i64,
}

fn grant_entry_inactive(
    grant_jti: &str,
    grant_exp_unix: Option<i64>,
    revoked: &BTreeSet<String>,
    now_unix: i64,
    fail_closed: bool,
) -> bool {
    if grant_exp_unix.is_some_and(|exp| now_unix >= exp) {
        return true;
    }
    if fail_closed {
        return true;
    }
    let jti = grant_jti.trim();
    !jti.is_empty()
        && revoked
            .iter()
            .any(|item| item.trim().eq_ignore_ascii_case(jti))
}

impl WatchHub {
    async fn start(
        &self,
        roots: &Roots,
        path: &str,
        recursive: bool,
        owner_peer: &str,
        grant_jti: &str,
        grant_exp_unix: Option<i64>,
    ) -> Result<Value> {
        let owner_peer = owner_peer.trim().to_string();
        if owner_peer.is_empty() {
            return Err(Error::Auth("watch owner is required".into()));
        }
        let located = locate(roots, path, false)?;
        if !located.real.is_dir() {
            return Err(Error::Message(format!(
                "{} is not a directory",
                located.guest
            )));
        }
        {
            let guard = self
                .inner
                .lock()
                .map_err(|_| Error::Message("watch map poisoned".into()))?;
            if guard.len() >= MAX_WATCHES {
                return Err(Error::Message(format!(
                    "this node already has {MAX_WATCHES} watches"
                )));
            }
        }
        let root_for_scan = located.real.clone();
        let snapshot = tokio::task::spawn_blocking(move || scan_dir(&root_for_scan, recursive))
            .await
            .map_err(|err| Error::Message(format!("watch scan task: {err}")))?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::Message("watch map poisoned".into()))?;
        if guard.len() >= MAX_WATCHES {
            return Err(Error::Message(format!(
                "this node already has {MAX_WATCHES} watches"
            )));
        }
        let id = util::random_hex(4);
        guard.insert(
            id.clone(),
            Watch {
                snapshot,
                root: located.real,
                root_guest: located.guest.clone(),
                recursive,
                owner_peer,
                grant_jti: grant_jti.trim().to_string(),
                grant_exp_unix,
                events: VecDeque::new(),
                next_seq: 1,
            },
        );
        Ok(json!({
            "watch_id": id,
            "path": located.guest,
            "recursive": recursive,
        }))
    }

    async fn poll(
        &self,
        id: &str,
        cursor: u64,
        timeout_ms: u64,
        limit: u32,
        peer: &str,
    ) -> Result<Value> {
        let timeout_ms = timeout_ms.min(30_000);
        let limit = if limit == 0 { 50 } else { limit.min(200) };
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            self.refresh(id, peer).await?;
            if let Some(batch) = self.drain(id, cursor, limit, false, peer)? {
                return Ok(batch);
            }
            if Instant::now() >= deadline {
                return self
                    .drain(id, cursor, limit, true, peer)?
                    .ok_or_else(|| Error::NotFound(format!("watch {id}")));
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }

    fn stop(&self, id: &str, peer: &str) -> Result<Value> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::Message("watch map poisoned".into()))?;
        let Some(existing) = guard.get(id) else {
            return Err(Error::NotFound(format!("watch {id}")));
        };
        if existing.owner_peer != peer {
            return Err(Error::NotFound(format!("watch {id}")));
        }
        guard.remove(id);
        Ok(json!({"watch_id": id, "stopped": true}))
    }

    fn clear(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.clear();
        }
    }

    fn close_inactive(&self, revoked: &BTreeSet<String>, now_unix: i64, fail_closed: bool) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.retain(|_, watch| {
                !grant_entry_inactive(
                    &watch.grant_jti,
                    watch.grant_exp_unix,
                    revoked,
                    now_unix,
                    fail_closed,
                )
            });
        }
    }

    async fn refresh(&self, id: &str, peer: &str) -> Result<()> {
        let (root, recursive) = {
            let guard = self
                .inner
                .lock()
                .map_err(|_| Error::Message("watch map poisoned".into()))?;
            let watch = guard
                .get(id)
                .filter(|w| w.owner_peer == peer)
                .ok_or_else(|| Error::NotFound(format!("watch {id}")))?;
            if watch
                .grant_exp_unix
                .is_some_and(|exp| util::unix_now() >= exp)
            {
                return Err(Error::Auth("grant expired".into()));
            }
            (watch.root.clone(), watch.recursive)
        };
        let next = tokio::task::spawn_blocking(move || scan_dir(&root, recursive))
            .await
            .map_err(|err| Error::Message(format!("watch scan task: {err}")))?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::Message("watch map poisoned".into()))?;
        let watch = guard
            .get_mut(id)
            .filter(|w| w.owner_peer == peer)
            .ok_or_else(|| Error::NotFound(format!("watch {id}")))?;
        let mut created = Vec::new();
        let mut modified = Vec::new();
        let mut removed = Vec::new();
        for (path, snap) in &next {
            let guest_path = guest_of(&watch.root_guest, &watch.root, path);
            match watch.snapshot.get(path) {
                None => created.push(guest_path),
                Some(old)
                    if old.len != snap.len
                        || old.modified != snap.modified
                        || old.is_dir != snap.is_dir =>
                {
                    modified.push(guest_path);
                }
                _ => {}
            }
        }
        for path in watch.snapshot.keys() {
            if !next.contains_key(path) {
                removed.push(guest_of(&watch.root_guest, &watch.root, path));
            }
        }
        watch.snapshot = next;
        push_kind(watch, "create", created);
        push_kind(watch, "modify", modified);
        push_kind(watch, "remove", removed);
        Ok(())
    }

    fn drain(
        &self,
        id: &str,
        cursor: u64,
        limit: u32,
        allow_empty: bool,
        peer: &str,
    ) -> Result<Option<Value>> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| Error::Message("watch map poisoned".into()))?;
        let watch = guard
            .get(id)
            .filter(|w| w.owner_peer == peer)
            .ok_or_else(|| Error::NotFound(format!("watch {id}")))?;
        let oldest = watch
            .events
            .front()
            .map(|event| event.seq)
            .unwrap_or(watch.next_seq);
        let gap = cursor + 1 < oldest && oldest > 1;
        let events: Vec<_> = watch
            .events
            .iter()
            .filter(|event| event.seq > cursor)
            .take(limit as usize)
            .map(|event| {
                json!({
                    "seq": event.seq,
                    "kind": event.kind,
                    "paths": event.paths,
                    "unix_ms": event.unix_ms,
                })
            })
            .collect();
        if events.is_empty() && !allow_empty {
            return Ok(None);
        }
        let next = events
            .last()
            .and_then(|event| event["seq"].as_u64())
            .unwrap_or(cursor);
        Ok(Some(json!({
            "watch_id": id,
            "events": events,
            "cursor": next,
            "gap": gap,
        })))
    }
}

fn push_kind(watch: &mut Watch, kind: &str, paths: Vec<String>) {
    if paths.is_empty() {
        return;
    }
    let seq = watch.next_seq;
    watch.next_seq += 1;
    watch.events.push_back(Stored {
        seq,
        kind: kind.into(),
        paths,
        unix_ms: now_ms(),
    });
    while watch.events.len() > MAX_EVENTS {
        watch.events.pop_front();
    }
}

fn scan_dir(root: &Path, recursive: bool) -> HashMap<PathBuf, Snap> {
    let mut out = HashMap::new();
    let mut builder = WalkBuilder::new(root);
    builder
        .standard_filters(false)
        .hidden(false)
        .git_ignore(false)
        .follow_links(false)
        .max_depth(if recursive { None } else { Some(1) });
    for entry in builder.build() {
        let Ok(entry) = entry else { continue };
        if entry.path() == root {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        out.insert(
            entry.path().to_path_buf(),
            Snap {
                len: meta.len(),
                modified: meta.modified().ok(),
                is_dir: meta.is_dir(),
            },
        );
    }
    out
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Clone)]
struct ProcHub {
    inner: Arc<Mutex<HashMap<String, Arc<ProcSlot>>>>,
}

impl Default for ProcHub {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct ProcChildState {
    child: Option<Child>,
    exited: bool,
    kill_requested: bool,
}

struct ProcSlot {
    id: String,
    pid: u32,
    command: String,
    cwd: String,
    owner_peer: String,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
    running: AtomicBool,
    exit_code: Mutex<Option<i32>>,
    stdout: Arc<Mutex<OutBuf>>,
    stderr: Arc<Mutex<OutBuf>>,
    state: Mutex<ProcChildState>,
    signal_cvar: Condvar,
    started_unix_ms: i64,
}

struct OutBuf {
    data: Vec<u8>,
    start: u64,
}

impl OutBuf {
    fn append(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
        if self.data.len() > OUTPUT_CAP {
            let drop_n = self.data.len() - OUTPUT_CAP;
            self.data.drain(..drop_n);
            self.start += drop_n as u64;
        }
    }

    fn end(&self) -> u64 {
        self.start + self.data.len() as u64
    }

    fn read_from(&self, cursor: u64, max: usize) -> (u64, Vec<u8>, bool) {
        let gap = cursor < self.start;
        let from = cursor.max(self.start);
        let offset = (from - self.start) as usize;
        let end = (offset + max).min(self.data.len());
        let slice = if offset < self.data.len() {
            self.data[offset..end].to_vec()
        } else {
            Vec::new()
        };
        (self.start + end as u64, slice, gap)
    }
}

/// Keeps the `spawn: {err}` shape but names `program` when it was missing,
/// so agents can tell "not found" apart from other spawn failures.
fn spawn_error(program: &str, err: std::io::Error) -> Error {
    let not_found = err.kind() == std::io::ErrorKind::NotFound
        || err.to_string().contains("No such file");
    if !not_found {
        return Error::Message(format!("spawn: {err}"));
    }
    let detail = err.to_string();
    if program.contains('/') || program.contains('\\') {
        Error::Message(format!("program '{program}' not found ({detail})"))
    } else {
        Error::Message(format!("program '{program}' not found on PATH ({detail})"))
    }
}

impl ProcHub {
    fn start(
        &self,
        roots: &Roots,
        program: &str,
        args: &[String],
        cwd: Option<&str>,
        env: &[(String, String)],
        shell: bool,
        stdin: Option<&[u8]>,
        owner_peer: &str,
        grant_jti: &str,
        grant_exp_unix: Option<i64>,
    ) -> Result<Value> {
        let owner_peer = owner_peer.trim();
        if owner_peer.is_empty() {
            return Err(Error::Auth("process owner is required".into()));
        }
        if program.is_empty() {
            return Err(Error::Message("command is empty".into()));
        }
        for (key, value) in env {
            if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
                return Err(Error::Message(format!("rejected env var '{key}'")));
            }
        }
        let dir = match cwd {
            Some(path) if !path.is_empty() => paths::real_target(roots, path, false)?,
            _ => roots.files.clone(),
        };
        let (argv0, argv) = if shell {
            shell_line(program)
        } else {
            (program.to_string(), args.to_vec())
        };
        {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| Error::Message("process map poisoned".into()))?;
            evict_exited_slots(&mut guard);
            if guard.len() >= MAX_PROCS {
                return Err(Error::Message(format!(
                    "this node already has {MAX_PROCS} background processes"
                )));
            }
        }
        let mut cmd = process::hidden(&argv0);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        cmd.args(&argv)
            .current_dir(&dir)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            cmd.env(key, value);
        }
        let mut child = cmd.spawn().map_err(|err| spawn_error(&argv0, err))?;
        if let Some(bytes) = stdin {
            let mut child_stdin = child
                .stdin
                .take()
                .ok_or_else(|| Error::Message("stdin missing".into()))?;
            child_stdin
                .write_all(bytes)
                .map_err(|err| Error::Message(format!("stdin write: {err}")))?;
            // Drop closes the pipe so the child sees EOF.
            drop(child_stdin);
        }
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let pid = child.id();
        let id = util::random_hex(4);
        let command = if shell || args.is_empty() {
            program.to_string()
        } else {
            format!("{program} {}", args.join(" "))
        };
        let slot = Arc::new(ProcSlot {
            id: id.clone(),
            pid,
            command,
            cwd: dir.display().to_string(),
            owner_peer: owner_peer.to_string(),
            grant_jti: grant_jti.trim().to_string(),
            grant_exp_unix,
            running: AtomicBool::new(true),
            exit_code: Mutex::new(None),
            stdout: Arc::new(Mutex::new(OutBuf {
                data: Vec::new(),
                start: 0,
            })),
            stderr: Arc::new(Mutex::new(OutBuf {
                data: Vec::new(),
                start: 0,
            })),
            state: Mutex::new(ProcChildState {
                child: Some(child),
                exited: false,
                kill_requested: false,
            }),
            signal_cvar: Condvar::new(),
            started_unix_ms: now_ms(),
        });
        if let Some(pipe) = stdout {
            pump(pipe, slot.stdout.clone());
        }
        if let Some(pipe) = stderr {
            pump(pipe, slot.stderr.clone());
        }
        let waited = slot.clone();
        std::thread::Builder::new()
            .name("agentlink-bg".into())
            .spawn(move || {
                reap_loop(&waited);
            })
            .map_err(|err| Error::Message(format!("process thread: {err}")))?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::Message("process map poisoned".into()))?;
        evict_exited_slots(&mut guard);
        let body = describe(&slot);
        guard.insert(id, slot);
        Ok(body)
    }

    fn list(&self, peer: &str) -> Result<Value> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| Error::Message("process map poisoned".into()))?;
        let mut processes: Vec<_> = guard
            .values()
            .filter(|slot| slot.owner_peer == peer)
            .map(|slot| describe(slot))
            .collect();
        processes.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        Ok(json!({"processes": processes}))
    }

    fn output(
        &self,
        id: &str,
        stdout_cursor: u64,
        stderr_cursor: u64,
        max_bytes: u32,
        peer: &str,
    ) -> Result<Value> {
        let max = if max_bytes == 0 {
            65_536
        } else {
            (max_bytes as usize).min(OUTPUT_CAP)
        };
        let slot = self.owned_slot(id, peer)?;
        let (stdout_next, stdout, stdout_gap) = slot
            .stdout
            .lock()
            .map_err(|_| Error::Message("output lock poisoned".into()))?
            .read_from(stdout_cursor, max);
        let (stderr_next, stderr, stderr_gap) = slot
            .stderr
            .lock()
            .map_err(|_| Error::Message("output lock poisoned".into()))?
            .read_from(stderr_cursor, max);
        Ok(json!({
            "id": id,
            "running": slot.running.load(Ordering::SeqCst),
            "exit_code": *slot.exit_code.lock().unwrap_or_else(|err| err.into_inner()),
            "stdout": decode_text(&stdout),
            "stderr": decode_text(&stderr),
            "stdout_cursor": stdout_next,
            "stderr_cursor": stderr_next,
            "stdout_gap": stdout_gap,
            "stderr_gap": stderr_gap,
        }))
    }

    fn status(&self, id: &str, peer: &str) -> Result<Value> {
        let slot = self.owned_slot(id, peer)?;
        Ok(describe(&slot))
    }

    fn kill(&self, id: &str, peer: &str) -> Result<Value> {
        let slot = self.owned_slot(id, peer)?;
        terminate_slot(&slot);
        Ok(describe(&slot))
    }

    fn close_inactive(&self, revoked: &BTreeSet<String>, now_unix: i64, fail_closed: bool) {
        let victims: Vec<Arc<ProcSlot>> = {
            let Ok(mut guard) = self.inner.lock() else {
                return;
            };
            let ids: Vec<String> = guard
                .iter()
                .filter(|(_, slot)| {
                    grant_entry_inactive(
                        &slot.grant_jti,
                        slot.grant_exp_unix,
                        revoked,
                        now_unix,
                        fail_closed,
                    )
                })
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| guard.remove(&id))
                .collect()
        };
        for slot in victims {
            terminate_slot(&slot);
        }
    }

    fn kill_all(&self) {
        let slots: Vec<Arc<ProcSlot>> = match self.inner.lock() {
            Ok(mut guard) => guard.drain().map(|(_, slot)| slot).collect(),
            Err(poison) => poison
                .into_inner()
                .drain()
                .map(|(_, slot)| slot)
                .collect(),
        };
        for slot in slots {
            terminate_slot(&slot);
        }
    }

    fn owned_slot(&self, id: &str, peer: &str) -> Result<Arc<ProcSlot>> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| Error::Message("process map poisoned".into()))?;
        guard
            .get(id)
            .filter(|slot| slot.owner_peer == peer)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("background process {id}")))
    }
}

fn evict_exited_slots(map: &mut HashMap<String, Arc<ProcSlot>>) {
    if map.len() < MAX_PROCS {
        return;
    }
    let mut exited: Vec<(i64, String)> = map
        .iter()
        .filter(|(_, slot)| !slot.running.load(Ordering::SeqCst))
        .map(|(id, slot)| (slot.started_unix_ms, id.clone()))
        .collect();
    exited.sort_by_key(|(started, _)| *started);
    for (_, id) in exited {
        map.remove(&id);
        if map.len() < MAX_PROCS {
            break;
        }
    }
}

fn reap_loop(slot: &ProcSlot) {
    let mut guard = match slot.state.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    loop {
        if guard.exited {
            return;
        }
        let waited = guard.child.as_mut().map(|child| child.try_wait());
        match waited {
            Some(Ok(Some(status))) => {
                let code = status.code().unwrap_or(-1);
                guard.child = None;
                guard.exited = true;
                if let Ok(mut exit_slot) = slot.exit_code.lock() {
                    *exit_slot = Some(code);
                }
                slot.running.store(false, Ordering::SeqCst);
                slot.signal_cvar.notify_all();
                return;
            }
            Some(Err(_)) | None => {
                guard.child = None;
                guard.exited = true;
                if let Ok(mut exit_slot) = slot.exit_code.lock() {
                    *exit_slot = Some(-1);
                }
                slot.running.store(false, Ordering::SeqCst);
                slot.signal_cvar.notify_all();
                return;
            }
            Some(Ok(None)) => {}
        }
        let (next_guard, _) = match slot
            .signal_cvar
            .wait_timeout(guard, Duration::from_millis(20))
        {
            Ok(pair) => pair,
            Err(poison) => poison.into_inner(),
        };
        guard = next_guard;
    }
}

fn terminate_slot(slot: &ProcSlot) {
    let mut guard = match slot.state.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    if guard.exited {
        return;
    }
    guard.kill_requested = true;
    #[cfg(unix)]
    unsafe {
        // Hold `slot.state` while signaling so the wait loop cannot reap and
        // allow PID reuse before `kill` runs.
        libc::kill(-(slot.pid as libc::pid_t), libc::SIGTERM);
    }
    #[cfg(not(unix))]
    if let Some(child) = guard.child.as_mut() {
        let _ = child.kill();
    }
    slot.signal_cvar.notify_all();

    let grace_deadline = Instant::now() + Duration::from_millis(300);
    while !guard.exited {
        let Some(rem) = grace_deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        let (next, _) = match slot.signal_cvar.wait_timeout(guard, rem) {
            Ok(pair) => pair,
            Err(poison) => poison.into_inner(),
        };
        guard = next;
    }
    if !guard.exited {
        #[cfg(unix)]
        unsafe {
            libc::kill(-(slot.pid as libc::pid_t), libc::SIGKILL);
        }
        if let Some(child) = guard.child.as_mut() {
            let _ = child.kill();
        }
        slot.signal_cvar.notify_all();
        let hard_deadline = Instant::now() + Duration::from_secs(2);
        while !guard.exited {
            let Some(rem) = hard_deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let (next, _) = match slot.signal_cvar.wait_timeout(guard, rem) {
                Ok(pair) => pair,
                Err(poison) => poison.into_inner(),
            };
            guard = next;
        }
    }
}

fn describe(slot: &ProcSlot) -> Value {
    let exit_code = slot.exit_code.lock().ok().and_then(|guard| *guard);
    let stdout_end = slot.stdout.lock().map(|buf| buf.end()).unwrap_or(0);
    let stderr_end = slot.stderr.lock().map(|buf| buf.end()).unwrap_or(0);
    json!({
        "id": slot.id,
        "pid": slot.pid,
        "command": slot.command,
        "cwd": slot.cwd,
        "running": slot.running.load(Ordering::SeqCst),
        "exit_code": exit_code,
        "started_unix_ms": slot.started_unix_ms,
        "stdout_cursor": stdout_end,
        "stderr_cursor": stderr_end,
    })
}

fn decode_text(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => json!({"encoding": "utf-8", "text": text}),
        Err(_) => json!({
            "encoding": "base64",
            "base64": util::b64_encode(bytes),
        }),
    }
}

fn pump(mut pipe: impl Read + Send + 'static, buf: Arc<Mutex<OutBuf>>) {
    std::thread::spawn(move || {
        let mut tmp = [0u8; 8192];
        loop {
            match pipe.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut guard) = buf.lock() {
                        guard.append(&tmp[..n]);
                    }
                }
            }
        }
    });
}

fn shell_line(command: &str) -> (String, Vec<String>) {
    if cfg!(target_os = "android") {
        ("/system/bin/sh".into(), vec!["-c".into(), command.into()])
    } else if cfg!(windows) {
        ("cmd.exe".into(), vec!["/C".into(), command.into()])
    } else {
        ("/bin/sh".into(), vec!["-c".into(), command.into()])
    }
}

fn system_info_blocking() -> Result<Value> {
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    );
    sys.refresh_cpu_frequency();
    let cpus = sys.cpus();
    let brand = cpus
        .first()
        .map(|cpu| {
            let brand = cpu.brand().trim();
            if brand.is_empty() {
                cpu.name().trim().to_string()
            } else {
                brand.to_string()
            }
        })
        .unwrap_or_default();
    let count = if cpus.is_empty() {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        cpus.len()
    };
    Ok(json!({
        "os": std::env::consts::OS,
        "os_name": System::name(),
        "os_version": System::os_version(),
        "os_long": System::long_os_version(),
        "kernel": System::kernel_version(),
        "arch": std::env::consts::ARCH,
        "hostname": System::host_name().unwrap_or_else(|| "localhost".into()),
        "cpu": {
            "count": count,
            "brand": brand,
            "frequency_mhz": cpus.iter().map(|cpu| cpu.frequency()).max().unwrap_or(0),
        },
        "memory": {
            "total_bytes": sys.total_memory().max(1),
            "available_bytes": sys.available_memory(),
            "used_bytes": sys.used_memory(),
        },
        "disks": [],
        "user": std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "unknown".into()),
        "shell": if cfg!(target_os = "android") {
            "/system/bin/sh".to_string()
        } else {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
        },
        "pid": std::process::id(),
        "cwd": std::env::current_dir().ok().map(|path| path.display().to_string()),
        "env": filter_env(),
        "tools": [],
    }))
}

fn filter_env() -> serde_json::Map<String, Value> {
    const ALLOW: &[&str] = &[
        "PATH", "HOME", "USER", "USERNAME", "LOGNAME", "SHELL", "LANG", "TERM", "TMPDIR", "PWD",
    ];
    const SECRET: &[&str] = &["SECRET", "TOKEN", "PASSWORD", "KEY", "CREDENTIAL"];
    let mut map = serde_json::Map::new();
    for (key, value) in std::env::vars() {
        let upper = key.to_ascii_uppercase();
        if !ALLOW.iter().any(|name| *name == upper) {
            continue;
        }
        if SECRET.iter().any(|part| upper.contains(part)) {
            continue;
        }
        map.insert(key, Value::String(value.chars().take(4096).collect()));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> (tempfile::TempDir, Roots) {
        let dir = tempfile::tempdir().unwrap();
        let files = dir.path().join("files");
        fs::create_dir_all(&files).unwrap();
        let roots = Roots {
            files,
            cache: dir.path().join("cache"),
            storage: None,
            audit: dir.path().join("audit.log"),
        };
        fs::create_dir_all(&roots.cache).unwrap();
        (dir, roots)
    }

    #[test]
    fn search_skips_gitignore_and_edits_stay_in_app_files() {
        let (_dir, roots) = roots();
        fs::write(roots.files.join("hello.txt"), "alpha-needle\nsecond\n").unwrap();
        fs::write(roots.files.join(".gitignore"), "secret.txt\n").unwrap();
        fs::write(roots.files.join("secret.txt"), "alpha-needle\n").unwrap();
        let found = content_search_blocking(
            &roots,
            &ContentQuery {
                path: "app:/files".into(),
                pattern: "alpha-needle".into(),
                literal: true,
                include: Vec::new(),
                exclude: Vec::new(),
                gitignore: true,
                include_hidden: false,
                case_insensitive: false,
                before: 0,
                after: 0,
                offset: 0,
                limit: 20,
            },
        )
        .unwrap();
        let matches = found["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 1, "{found}");
        assert!(matches[0]["path"].as_str().unwrap().ends_with("hello.txt"));
        let replaced = replace_blocking(
            &roots,
            "app:/files/hello.txt",
            "alpha-needle",
            "beta-needle",
            false,
        )
        .unwrap();
        assert_eq!(replaced["replacements"], 1);
        edit_lines_blocking(&roots, "app:/files/hello.txt", 2, 2, "third\n").unwrap();
        let body = fs::read_to_string(roots.files.join("hello.txt")).unwrap();
        assert!(body.contains("beta-needle"), "{body}");
        assert!(body.contains("third"), "{body}");
        let outside = paths::real_target(&roots, "/etc/passwd", false);
        assert!(outside.is_err());

        // Verify confined atomic write leaves no randomized temp files behind.
        let leftover: Vec<_> = fs::read_dir(&roots.files)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".agentlink-tmp-"))
            .collect();
        assert!(leftover.is_empty(), "leftover temp files: {leftover:?}");

        // Patch paths escaping root are rejected.
        let escape_patch = "--- a/../escape.txt\n+++ b/../escape.txt\n@@ -1 +1 @@\n-old\n+new\n";
        assert!(apply_patch_blocking(&roots, "app:/files", escape_patch).is_err());

        #[cfg(unix)]
        {
            let secret = _dir.path().join("outside-secret.txt");
            fs::write(&secret, "keep-me\n").unwrap();
            let link = roots.files.join("link.txt");
            std::os::unix::fs::symlink(&secret, &link).unwrap();
            assert!(
                replace_blocking(&roots, "app:/files/link.txt", "keep-me", "pwned", false).is_err()
            );
            let sym_patch = "--- a/link.txt\n+++ b/link.txt\n@@ -1 +1 @@\n-keep-me\n+pwned\n";
            assert!(apply_patch_blocking(&roots, "app:/files", sym_patch).is_err());
            assert_eq!(fs::read_to_string(&secret).unwrap(), "keep-me\n");
        }
    }

    #[tokio::test]
    async fn watch_and_background_echo() {
        let (_dir, roots) = roots();
        let tools = ToolState::default();
        let started = tools
            .watches
            .start(&roots, "app:/files", true, "peer-alice", "jti-a", None)
            .await
            .unwrap();
        let id = started["watch_id"].as_str().unwrap().to_string();
        fs::write(roots.files.join("created.txt"), "new\n").unwrap();
        // Peer isolation on watch_poll & watch_stop.
        assert!(tools.watches.poll(&id, 0, 20, 20, "peer-eve").await.is_err());
        assert!(tools.watches.stop(&id, "peer-eve").is_err());

        let polled = tools
            .watches
            .poll(&id, 0, 200, 20, "peer-alice")
            .await
            .unwrap();
        let events_str = polled["events"].to_string();
        assert!(
            events_str.contains("app:/files/created.txt"),
            "watch must return guest path, got {polled}"
        );
        assert!(
            !events_str.contains(&roots.files.display().to_string()),
            "watch must not leak host filesystem path: {polled}"
        );
        tools.watches.stop(&id, "peer-alice").unwrap();

        let bg = tools
            .procs
            .start(
                &roots,
                "echo bg-ok",
                &[],
                None,
                &[],
                true,
                None,
                "peer-alice",
                "jti-a",
                None,
            )
            .unwrap();
        let proc_id = bg["id"].as_str().unwrap().to_string();
        // Peer isolation on bg_*
        assert!(tools.procs.status(&proc_id, "peer-eve").is_err());
        assert!(tools.procs.output(&proc_id, 0, 0, 65_536, "peer-eve").is_err());
        assert!(tools.procs.kill(&proc_id, "peer-eve").is_err());
        assert_eq!(
            tools.procs.list("peer-eve").unwrap()["processes"]
                .as_array()
                .unwrap()
                .len(),
            0
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut text = String::new();
        while Instant::now() < deadline {
            let chunk = tools
                .procs
                .output(&proc_id, 0, 0, 65_536, "peer-alice")
                .unwrap();
            text = chunk["stdout"]["text"].as_str().unwrap_or("").to_string();
            if text.contains("bg-ok") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert!(text.contains("bg-ok"), "{text}");
        tools.procs.kill(&proc_id, "peer-alice").unwrap();
        let info = system_info_blocking().unwrap();
        assert!(info["cpu"]["count"].as_u64().unwrap_or(0) > 0, "{info}");
        assert!(
            info["memory"]["total_bytes"].as_u64().unwrap_or(0) > 0,
            "{info}"
        );
    }

    #[tokio::test]
    async fn proc_kill_does_not_deadlock_and_revocation_sweeps_procs_and_watches() {
        let (_dir, roots) = roots();
        let tools = ToolState::default();
        let sleeper = if cfg!(windows) {
            "ping -n 30 127.0.0.1 >nul"
        } else {
            "sleep 30"
        };
        let bg = bg_start(
            &tools,
            &roots,
            sleeper,
            &[],
            None,
            &[],
            true,
            None,
            "peer-alice",
            "jti-kill",
            Some(util::unix_now() + 60),
        )
        .await
        .unwrap();
        let id = bg["id"].as_str().unwrap().to_string();
        // Must complete promptly (no wait()/kill() mutex deadlock!).
        let killed = tokio::time::timeout(
            Duration::from_secs(5),
            bg_kill(&tools, &id, "peer-alice"),
        )
        .await
        .expect("bg_kill must not deadlock")
        .unwrap();
        assert_eq!(killed["running"], json!(false));

        // Revocation sweep removes both watch and running proc for revoked jti.
        let w = watch_start(
            &tools,
            &roots,
            "app:/files",
            false,
            "peer-alice",
            "jti-revoked",
            Some(util::unix_now() + 60),
        )
        .await
        .unwrap();
        let wid = w["watch_id"].as_str().unwrap().to_string();
        let bg2 = bg_start(
            &tools,
            &roots,
            sleeper,
            &[],
            None,
            &[],
            true,
            None,
            "peer-alice",
            "jti-revoked",
            Some(util::unix_now() + 60),
        )
        .await
        .unwrap();
        let pid2 = bg2["id"].as_str().unwrap().to_string();
        let revoked = BTreeSet::from(["jti-revoked".to_string()]);
        tools.close_inactive(&revoked, util::unix_now(), false);
        assert!(watch_stop(&tools, &wid, "peer-alice").is_err());
        assert!(bg_status(&tools, &pid2, "peer-alice").is_err());
    }

    #[tokio::test]
    async fn proc_hub_evicts_exited_slots_past_max_procs() {
        let (_dir, roots) = roots();
        let tools = ToolState::default();
        for i in 0..(MAX_PROCS + 2) {
            let started = bg_start(
                &tools,
                &roots,
                &format!("echo n{i}"),
                &[],
                None,
                &[],
                true,
                None,
                "peer-alice",
                "jti-evict",
                None,
            )
            .await
            .unwrap();
            let id = started["id"].as_str().unwrap().to_string();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if bg_status(&tools, &id, "peer-alice")
                    .ok()
                    .and_then(|v| v["running"].as_bool())
                    == Some(false)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        }
    }
}
