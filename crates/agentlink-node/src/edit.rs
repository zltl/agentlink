//! Exact replace, line-range edit, and unified diff apply.
//!
//! Every successful write is atomic: the new bytes go to a temporary file in
//! the same directory, are flushed, and then replace the destination.

use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use agentlink_core::paths::{
    ensure_path_stays_in_sandbox_at_sink, is_inside_root, is_link_entry, resolve_path,
    strip_verbatim_prefix,
};
use agentlink_core::{Error, Result};
use serde_json::{json, Value};

use crate::audit::EditAudit;

const MAX_FILE: usize = 8 * 1024 * 1024;
const MAX_PATCH: usize = 1024 * 1024;
const MAX_TEXT: usize = 1024 * 1024;

pub async fn replace(
    sandbox: Option<&Path>,
    path: &str,
    old: &str,
    new: &str,
    replace_all: bool,
) -> Result<(Value, EditAudit)> {
    let sandbox = sandbox.map(|path| path.to_path_buf());
    let path = path.to_string();
    let old = old.to_string();
    let new = new.to_string();
    tokio::task::spawn_blocking(move || {
        replace_blocking(sandbox.as_deref(), &path, &old, &new, replace_all)
    })
    .await
    .map_err(|err| Error::Message(format!("edit task: {err}")))?
}

pub async fn edit_lines(
    sandbox: Option<&Path>,
    path: &str,
    start_line: u32,
    end_line: u32,
    content: &str,
) -> Result<(Value, EditAudit)> {
    let sandbox = sandbox.map(|path| path.to_path_buf());
    let path = path.to_string();
    let content = content.to_string();
    tokio::task::spawn_blocking(move || {
        edit_lines_blocking(sandbox.as_deref(), &path, start_line, end_line, &content)
    })
    .await
    .map_err(|err| Error::Message(format!("edit task: {err}")))?
}

pub async fn apply_patch(
    sandbox: Option<&Path>,
    root: &str,
    patch: &str,
) -> Result<(Value, EditAudit)> {
    let sandbox = sandbox.map(|path| path.to_path_buf());
    let root = root.to_string();
    let patch = patch.to_string();
    tokio::task::spawn_blocking(move || apply_patch_blocking(sandbox.as_deref(), &root, &patch))
        .await
        .map_err(|err| Error::Message(format!("patch task: {err}")))?
}

fn replace_blocking(
    sandbox: Option<&Path>,
    path: &str,
    old: &str,
    new: &str,
    replace_all: bool,
) -> Result<(Value, EditAudit)> {
    if old.is_empty() {
        return Err(Error::Message("old string is empty".into()));
    }
    if old.len() > MAX_TEXT || new.len() > MAX_TEXT {
        return Err(Error::Message("replacement text exceeds 1 MiB".into()));
    }
    let full = resolve_path(sandbox, path)?;
    let before = read_text(&full).map_err(|err| tip_enotdir(&full, err))?;
    let count = before.matches(old).count();
    if count == 0 {
        return Err(Error::Message(format!(
            "old string was not found in {}",
            full.display()
        )));
    }
    if count > 1 && !replace_all {
        return Err(Error::Message(format!(
            "found {count} matches of the old string in {}; pass --all (CLI) or replace_all (MCP/API) to replace every match",
            full.display()
        )));
    }
    let replacements = if replace_all { count } else { 1 };
    let projected_len = if new.len() >= old.len() {
        let delta = new.len() - old.len();
        delta
            .checked_mul(replacements)
            .and_then(|growth| before.len().checked_add(growth))
    } else {
        let shrink = (old.len() - new.len()).saturating_mul(replacements);
        Some(before.len().saturating_sub(shrink))
    };
    match projected_len {
        Some(len) if len <= MAX_FILE => {}
        _ => {
            return Err(Error::Message(format!(
                "replacement output would exceed {MAX_FILE} bytes"
            )));
        }
    }
    let after = if replace_all {
        before.replace(old, new)
    } else {
        before.replacen(old, new, 1)
    };
    atomic_write_confined(sandbox, &full, after.as_bytes())?;
    let display = full.display().to_string();
    let edit = EditAudit::from_texts(vec![(display.clone(), before.as_str(), after.as_str())]);
    Ok((
        json!({"path": display, "replacements": replacements}),
        edit,
    ))
}

fn edit_lines_blocking(
    sandbox: Option<&Path>,
    path: &str,
    start_line: u32,
    end_line: u32,
    content: &str,
) -> Result<(Value, EditAudit)> {
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
    let full = resolve_path(sandbox, path)?;
    let before = if full.exists() {
        read_text(&full).map_err(|err| tip_enotdir(&full, err))?
    } else if start_line == 1 {
        if let Some(tip) = agentlink_core::util::path_component_not_dir_error(&full) {
            return Err(tip);
        }
        String::new()
    } else {
        return Err(agentlink_core::util::path_component_not_dir_error(&full)
            .unwrap_or_else(|| Error::NotFound(full.display().to_string())));
    };
    let mut doc = parse_doc(&before);
    let n = doc.lines.len() as u32;
    if start_line > n + 1
        || (start_line <= n && end_line > n)
        || (start_line == n + 1 && end_line != start_line)
    {
        return Err(Error::Message(format!(
            "line range {start_line}-{end_line} is outside {} (file has {n} lines; append with start=end={})",
            full.display(),
            n + 1
        )));
    }
    let start_idx = (start_line - 1) as usize;
    let end_idx = if start_line == n + 1 {
        doc.lines.len()
    } else {
        end_line as usize
    };
    let mut replacement = replacement_lines(content);
    if before.is_empty() && content.ends_with('\n') {
        doc.trailing = true;
    }
    doc.lines.splice(start_idx..end_idx, replacement.drain(..));
    let after = render_doc(&doc);
    if after.len() > MAX_FILE {
        return Err(Error::Message(format!(
            "edited file would exceed {MAX_FILE} bytes"
        )));
    }
    atomic_write_confined(sandbox, &full, after.as_bytes())?;
    let display = full.display().to_string();
    let edit = EditAudit::from_texts(vec![(display.clone(), before.as_str(), after.as_str())]);
    Ok((
        json!({
            "path": display,
            "start_line": start_line,
            "end_line": end_line,
        }),
        edit,
    ))
}

struct Planned {
    path: PathBuf,
    display: String,
    before: String,
    after: String,
    action: &'static str,
}

fn apply_patch_blocking(
    sandbox: Option<&Path>,
    root: &str,
    patch: &str,
) -> Result<(Value, EditAudit)> {
    if patch.len() > MAX_PATCH {
        return Err(Error::Message("patch exceeds 1 MiB".into()));
    }
    if patch.trim().is_empty() {
        return Err(Error::Message("patch is empty".into()));
    }
    let base = resolve_path(sandbox, root)?;
    if !base.is_dir() {
        return Err(Error::Message(format!(
            "{} is not a directory",
            base.display()
        )));
    }
    let sections = split_patch(patch)?;
    let mut planned = Vec::with_capacity(sections.len());
    for section in sections {
        let target = section
            .new_path
            .clone()
            .or(section.old_path.clone())
            .ok_or_else(|| Error::Message("patch section has no path".into()))?;
        let rel = safe_relative(&target)?;
        let full = resolve_joined(sandbox, &base, &rel)?;
        let exists = full.exists();
        let before = if exists {
            read_text(&full)?
        } else {
            String::new()
        };
        let after = if section.new_path.is_none() {
            apply_diff(&before, &section.text)
                .map_err(|err| Error::Message(format!("patch {}: {err}", full.display())))?;
            String::new()
        } else {
            match apply_diff(&before, &section.text) {
                Ok(text) => text,
                Err(err) if section.old_path.is_none() => {
                    added_lines(&section.text).ok_or_else(|| {
                        Error::Message(format!(
                            "could not apply new-file patch for {}: {err}",
                            full.display()
                        ))
                    })?
                }
                Err(err) => return Err(Error::Message(format!("patch {}: {err}", full.display()))),
            }
        };
        let action = if section.new_path.is_none() {
            "delete"
        } else if !exists {
            "create"
        } else {
            "update"
        };
        planned.push(Planned {
            path: full,
            display: String::new(),
            before,
            after,
            action,
        });
    }
    for item in &mut planned {
        if item.after.len() > MAX_FILE {
            return Err(Error::Message(format!(
                "patched {} would exceed {MAX_FILE} bytes",
                item.path.display()
            )));
        }
        if item.action == "delete" {
            let checked = ensure_path_stays_in_sandbox_at_sink(sandbox, &item.path)?;
            if fs::symlink_metadata(&checked).is_ok() {
                fs::remove_file(&checked)?;
            }
        } else {
            if let Some(parent) = item.path.parent() {
                crate::ops::create_dir_all_confined(sandbox, parent)?;
            }
            atomic_write_confined(sandbox, &item.path, item.after.as_bytes())?;
        }
        item.display = item.path.display().to_string();
    }
    let files = planned
        .iter()
        .map(|item| json!({"path": item.display, "action": item.action}))
        .collect::<Vec<_>>();
    let edit = EditAudit::from_texts(
        planned
            .iter()
            .map(|item| {
                (
                    item.display.clone(),
                    item.before.as_str(),
                    item.after.as_str(),
                )
            })
            .collect(),
    );
    Ok((
        json!({"root": base.display().to_string(), "files": files}),
        edit,
    ))
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
    // split leaves a trailing empty item when the patch ends in a newline.
    // That item is not a hunk line; a blank context line is a single space.
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
        let mut in_hunk = false;
        for line in &lines[start + 2..end] {
            if line.starts_with("diff --git ") || line.starts_with("index ") {
                break;
            }
            if line.starts_with('\\') {
                continue;
            }
            if line.starts_with("@@") {
                in_hunk = true;
                text.push_str(line);
                text.push('\n');
                continue;
            }
            if in_hunk
                && (line.starts_with('+')
                    || line.starts_with('-')
                    || line.starts_with(' ')
                    || line.is_empty())
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
    if let Some(rest) = text.strip_prefix('"') {
        text = rest.split('"').next().unwrap_or(rest);
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

/// Walk `base.join(rel)` verifying every existing ancestor component against
/// `sandbox` rather than falling back to `resolve_lexical` on missing parents.
fn resolve_joined(sandbox: Option<&Path>, base: &Path, rel: &Path) -> Result<PathBuf> {
    let Some(root) = sandbox else {
        return Ok(base.join(rel));
    };
    let root_c = strip_verbatim_prefix(
        &fs::canonicalize(root).map_err(|e| Error::Message(format!("sandbox root: {e}")))?,
    );
    let mut cur = strip_verbatim_prefix(&fs::canonicalize(base)?);
    if !is_inside_root(&root_c, &cur) {
        return Err(Error::PermissionDenied(format!(
            "path escapes sandbox: {}",
            base.display()
        )));
    }
    let mut missing = false;
    for comp in rel.components() {
        let Component::Normal(name) = comp else {
            return Err(Error::PermissionDenied(format!(
                "patch path escapes sandbox: {}",
                rel.display()
            )));
        };
        cur.push(name);
        if missing {
            continue;
        }
        match fs::symlink_metadata(&cur) {
            Ok(meta) if is_link_entry(&meta) => {
                // Verify the symlink resolves inside the sandbox (even if dangling).
                cur = ensure_path_stays_in_sandbox_at_sink(Some(root), &cur)?;
                if fs::symlink_metadata(&cur).is_err() {
                    missing = true;
                }
            }
            Ok(_) => {
                let canon = strip_verbatim_prefix(&fs::canonicalize(&cur)?);
                if !is_inside_root(&root_c, &canon) {
                    return Err(Error::PermissionDenied(format!(
                        "path escapes sandbox: {}",
                        cur.display()
                    )));
                }
                cur = canon;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                missing = true;
            }
            Err(err) => return Err(err.into()),
        }
    }
    if !is_inside_root(&root_c, &cur) {
        return Err(Error::PermissionDenied(format!(
            "path escapes sandbox: {}",
            cur.display()
        )));
    }
    Ok(cur)
}

struct Doc {
    lines: Vec<String>,
    newline: &'static str,
    trailing: bool,
}

fn parse_doc(text: &str) -> Doc {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let trailing = text.ends_with('\n');
    let normalized = text.replace("\r\n", "\n");
    if text.is_empty() {
        return Doc {
            lines: Vec::new(),
            newline,
            trailing: false,
        };
    }
    let body = normalized.strip_suffix('\n').unwrap_or(&normalized);
    Doc {
        lines: body.split('\n').map(|line| line.to_string()).collect(),
        newline,
        trailing,
    }
}

fn replacement_lines(content: &str) -> Vec<String> {
    if content.is_empty() {
        return Vec::new();
    }
    let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
    let body = normalized.strip_suffix('\n').unwrap_or(&normalized);
    body.split('\n').map(|line| line.to_string()).collect()
}

fn render_doc(doc: &Doc) -> String {
    if doc.lines.is_empty() {
        return String::new();
    }
    let mut text = doc.lines.join(doc.newline);
    if doc.trailing {
        text.push_str(doc.newline);
    }
    text
}

fn read_text(path: &Path) -> Result<String> {
    let meta = fs::metadata(path)?;
    if meta.len() > MAX_FILE as u64 {
        return Err(Error::Message(format!(
            "{} is larger than {MAX_FILE} bytes",
            path.display()
        )));
    }
    let file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity((meta.len() as usize).min(MAX_FILE));
    file.take((MAX_FILE as u64) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FILE {
        return Err(Error::Message(format!(
            "{} is larger than {MAX_FILE} bytes",
            path.display()
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| Error::Message(format!("{} is not UTF-8 text", path.display())))
}

fn tip_enotdir(path: &Path, err: Error) -> Error {
    match err {
        Error::Io(io) => agentlink_core::util::diagnose_enotdir_component(path, io),
        other => other,
    }
}

pub(crate) fn atomic_write_confined(
    sandbox: Option<&Path>,
    path: &Path,
    data: &[u8],
) -> Result<()> {
    let checked = ensure_path_stays_in_sandbox_at_sink(sandbox, path)?;
    let parent = match checked.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    crate::ops::create_dir_all_confined(sandbox, parent)?;
    if let Some(root) = sandbox {
        let root_c = strip_verbatim_prefix(
            &fs::canonicalize(root).map_err(|e| Error::Message(format!("sandbox root: {e}")))?,
        );
        let parent_c = strip_verbatim_prefix(&fs::canonicalize(parent)?);
        if !is_inside_root(&root_c, &parent_c) {
            return Err(Error::PermissionDenied(format!(
                "path escapes sandbox: {}",
                checked.display()
            )));
        }
    }
    let mut tmp = tempfile::Builder::new()
        .prefix(".agentlink-")
        .tempfile_in(parent)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all().ok();
    if let Ok(meta) = fs::symlink_metadata(&checked) {
        if !is_link_entry(&meta) {
            let _ = tmp.as_file().set_permissions(meta.permissions());
        }
    }
    tmp.persist(&checked)
        .map_err(|err| Error::Message(format!("atomic write {}: {}", checked.display(), err.error)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_requires_a_unique_match_unless_replace_all() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note.txt");
        fs::write(&file, "one one\n").unwrap();
        let path = file.display().to_string();
        let err = replace_blocking(None, &path, "one", "two", false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("2 matches"), "{msg}");
        assert!(msg.contains("--all"), "{msg}");
        assert!(msg.contains("replace_all"), "{msg}");
        assert_eq!(fs::read_to_string(&file).unwrap(), "one one\n");
        let (body, edit) = replace_blocking(None, &path, "one", "two", true).unwrap();
        assert_eq!(body["replacements"], 2);
        assert_eq!(fs::read_to_string(&file).unwrap(), "two two\n");
        assert_eq!(edit.files.len(), 1);
        assert_eq!(edit.files[0].before, "one one\n");
        assert_eq!(edit.files[0].after, "two two\n");
        assert!(edit.files[0].after.contains("two"));
        assert!(dir.path().read_dir().unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".agentlink-")
        }));
    }

    #[test]
    fn replace_and_edit_lines_tip_when_path_is_below_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hostname");
        fs::write(&file, "box\n").unwrap();
        let child = file.join("nope").display().to_string();
        let blocker = file.display().to_string();

        let msg = replace_blocking(None, &child, "a", "b", false)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains(&blocker), "{msg}");

        let msg = edit_lines_blocking(None, &child, 1, 1, "x\n")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains(&blocker), "{msg}");

        let msg = edit_lines_blocking(None, &child, 2, 2, "x\n")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains(&blocker), "{msg}");
    }

    #[test]
    fn line_range_replaces_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lines.txt");
        fs::write(&file, "a\nb\nc\n").unwrap();
        let path = file.display().to_string();
        edit_lines_blocking(None, &path, 2, 2, "B\n").unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "a\nB\nc\n");
        edit_lines_blocking(None, &path, 4, 4, "d\n").unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "a\nB\nc\nd\n");
        edit_lines_blocking(None, &path, 2, 3, "").unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "a\nd\n");
    }

    #[test]
    fn unified_diff_updates_and_rejects_escape() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f.txt");
        fs::write(&file, "hello\nworld\n").unwrap();
        let patch = "\
--- a/f.txt
+++ b/f.txt
@@ -1,2 +1,2 @@
 hello
-world
+agentlink
";
        let root = dir.path().display().to_string();
        let (body, edit) = apply_patch_blocking(None, &root, patch).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "hello\nagentlink\n");
        assert_eq!(body["files"][0]["action"], "update");
        assert!(edit.files[0].after.contains("agentlink"));
        assert!(edit.files[0].before.contains("world"));

        let escape = "\
--- a/../outside.txt
+++ b/../outside.txt
@@ -0,0 +1 @@
+nope
";
        let sample = "\
--- a/hello.txt
+++ b/hello.txt
@@ -1,2 +1,2 @@
-beta-needle
+gamma-needle
 third
";
        let hello = dir.path().join("hello.txt");
        fs::write(&hello, "beta-needle\nthird\n").unwrap();
        apply_patch_blocking(None, &root, sample).unwrap();
        assert_eq!(fs::read_to_string(&hello).unwrap(), "gamma-needle\nthird\n");

        let err = apply_patch_blocking(None, &root, escape).unwrap_err();
        assert!(err.to_string().contains("escapes"), "{err}");
    }

    #[test]
    fn read_text_rejects_oversized_file_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let huge = dir.path().join("sparse.txt");
        let file = fs::File::create(&huge).unwrap();
        // 1 GiB sparse file — checking metadata.len() refuses instantly without OOM.
        file.set_len(1024 * 1024 * 1024).unwrap();
        drop(file);
        let err = read_text(&huge).unwrap_err().to_string();
        assert!(err.contains("larger than"), "{err}");
    }

    #[test]
    fn replace_all_rejects_expansion_exceeding_max_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("expand.txt");
        // 100 KiB of 'a' * 100 byte replacement = ~10 MiB > MAX_FILE (8 MiB).
        fs::write(&file, "a".repeat(100 * 1024)).unwrap();
        let big = "x".repeat(100);
        let err = replace_blocking(None, &file.display().to_string(), "a", &big, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceed"), "{err}");
        // File must stay untouched.
        assert_eq!(fs::metadata(&file).unwrap().len(), 100 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn apply_patch_rejects_missing_parent_through_escaping_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = dir.path().join("sandbox");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&sandbox).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, sandbox.join("esc")).unwrap();
        let patch = "\
--- /dev/null
+++ b/esc/missing_dir/pwned.txt
@@ -0,0 +1 @@
+evil
";
        let err = apply_patch_blocking(Some(&sandbox), ".", patch)
            .unwrap_err()
            .to_string();
        assert!(err.contains("escapes"), "{err}");
        assert!(!outside.join("missing_dir").exists());
    }
}
