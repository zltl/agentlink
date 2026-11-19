//! Path resolution and symlink-safe sandbox confinement.
//!
//! # Entry points
//!
//! | Function | Use when |
//! |---|---|
//! | [`resolve_path`] | Need the final target of a path (follows the last component). |
//! | [`resolve_path_no_follow`] | Operating on the path entry itself (`rm`/`mv` of a symlink). |
//! | [`ensure_path_stays_in_sandbox_at_sink`] | Writing through a path that may be a dangling relative symlink. |
//! | [`ensure_moved_symlinks_stay_inside`] | After relocating a tree that may contain relative symlinks. |
//! | [`open_write_file`] | Creating/truncating a sandboxed file without following a final symlink. |

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// Maximum symlink hops resolved before failing with a loop error (`ELOOP`).
pub const MAX_SYMLINK_HOPS: usize = 40;
const MAX_SUBTREE_SYMLINK_SCAN: usize = 16_384;

/// Drop a Windows `\\?\` / `\\?\UNC\` prefix that `fs::canonicalize`
/// adds. Sandbox checks normalize both sides so returned paths remain
/// usable as a process cwd and comparable to user-supplied `C:\…`.
pub fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    if let Some(rest) = raw.strip_prefix("//?/UNC/") {
        return PathBuf::from(format!("//{rest}"));
    }
    if let Some(rest) = raw.strip_prefix("//?/") {
        return PathBuf::from(rest);
    }
    path.to_path_buf()
}

/// True when two paths name the same location after stripping a Windows
/// verbatim prefix. On Windows the comparison is case-insensitive.
pub fn paths_equivalent(a: &Path, b: &Path) -> bool {
    let a = strip_verbatim_prefix(a);
    let b = strip_verbatim_prefix(b);
    if a == b {
        return true;
    }
    let a = a.to_string_lossy();
    let b = b.to_string_lossy();
    if cfg!(windows) {
        a.eq_ignore_ascii_case(&b)
    } else {
        false
    }
}

/// Slash-normalize a path or glob so `C:\foo\bar` and `C:/foo/bar` compare.
pub fn normalize_path_text(value: &str) -> String {
    strip_verbatim_prefix(Path::new(value))
        .to_string_lossy()
        .replace('\\', "/")
}

/// Agents usually mean a drive root when they write `C:` (or `C:Users\…` without a
/// separator). On Windows those forms are *drive-relative* to the process cwd on that
/// volume — often `C:\Windows\System32` for a service — which is a nasty footgun for
/// remote `ls`/`write`/`cp`. Normalize to a rooted path. `C:/…` and `C:\…` are unchanged.
pub fn normalize_windows_drive_path(user_path: &str) -> std::borrow::Cow<'_, str> {
    let bytes = user_path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let rest = &user_path[2..];
        if rest.is_empty() || !(rest.starts_with('/') || rest.starts_with('\\')) {
            let mut out = String::with_capacity(user_path.len() + 1);
            out.push_str(&user_path[..2]);
            out.push('\\');
            out.push_str(rest);
            return std::borrow::Cow::Owned(out);
        }
    }
    std::borrow::Cow::Borrowed(user_path)
}

/// Resolve `user_path` and, when `root` is set, require every symlink hop
/// (including dangling final symlinks) and the final target to stay inside `root`.
/// The parent directory must already exist.
pub fn resolve_path(root: Option<&Path>, user_path: &str) -> Result<PathBuf> {
    resolve_with_options(root, user_path, true, true)
}

/// Resolve `user_path` where intermediate directories may not exist yet (`mkdir -p`,
/// `cp` / `write` auto-creating parent dirs). Existing and dangling symlinks along
/// the existing prefix or at the target are still expanded and confined to `root`.
pub fn resolve_lexical(root: Option<&Path>, user_path: &str) -> Result<PathBuf> {
    resolve_with_options(root, user_path, false, true)
}

/// Resolve the directory entry named by `user_path` without dereferencing the
/// final component when it is a symlink (`rm`, `mv` source). All ancestor
/// directories are still dereferenced and must stay inside `root`.
pub fn resolve_path_no_follow(root: Option<&Path>, user_path: &str) -> Result<PathBuf> {
    resolve_with_options(root, user_path, true, false)
}

/// Re-validate `target` against `root` immediately before committing a write or
/// atomic install so a concurrent symlink swap cannot escape the sandbox.
pub fn ensure_path_stays_in_sandbox_at_sink(root: Option<&Path>, target: &Path) -> Result<PathBuf> {
    let Some(root) = root else {
        return Ok(target.to_path_buf());
    };
    let root_c = canonical_sandbox_root(root)?;
    let display = target.to_string_lossy();
    resolve_sandboxed(&root_c, root, target, false, true, &display, 0)
}

/// Verify that moving `from_entry` to `to_entry` does not cause any relative
/// symlink (either `from_entry` itself or a symlink inside a moved directory
/// subtree) to resolve outside `root` from its new parent directory.
pub fn ensure_moved_symlinks_stay_inside(
    root: Option<&Path>,
    from_entry: &Path,
    to_entry: &Path,
) -> Result<()> {
    let Some(root) = root else {
        return Ok(());
    };
    let root_c = canonical_sandbox_root(root)?;
    let Ok(meta) = fs::symlink_metadata(from_entry) else {
        return Ok(());
    };
    if meta.file_type().is_symlink() {
        return check_relocated_symlink(&root_c, root, from_entry, to_entry);
    }
    if meta.is_dir() {
        let mut scanned = 0usize;
        check_relocated_dir_symlinks(&root_c, root, from_entry, to_entry, &mut scanned)?;
    }
    Ok(())
}

/// Open a file for writing, adding `O_NOFOLLOW` on Unix whenever `nofollow` is
/// set so a last-microsecond TOCTOU regular-file -> symlink swap fails with `ELOOP`.
pub fn open_write_file(
    path: &Path,
    create: bool,
    truncate: bool,
    nofollow: bool,
) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(create).truncate(truncate);
    #[cfg(unix)]
    if nofollow {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    if nofollow {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    ErrorKind::PermissionDenied,
                    "refusing to open symbolic link target directly",
                ));
            }
        }
    }
    opts.open(path)
}

fn check_relocated_symlink(
    root_c: &Path,
    raw_root: &Path,
    link_now: &Path,
    link_after: &Path,
) -> Result<()> {
    let raw_target = fs::read_link(link_now)?;
    let target_norm = normalize_link_target_path(&raw_target);
    let candidate = if target_norm.is_absolute() {
        target_norm
    } else {
        link_after.parent().unwrap_or(root_c).join(&target_norm)
    };
    let label = link_after.to_string_lossy();
    resolve_sandboxed(root_c, raw_root, &candidate, false, true, &label, 1).map(|_| ())
}

fn check_relocated_dir_symlinks(
    root_c: &Path,
    raw_root: &Path,
    dir_now: &Path,
    dir_after: &Path,
    scanned: &mut usize,
) -> Result<()> {
    for entry in fs::read_dir(dir_now)? {
        let entry = entry?;
        *scanned = scanned.saturating_add(1);
        if *scanned > MAX_SUBTREE_SYMLINK_SCAN {
            return Err(Error::Message(
                "directory move exceeds maximum symlink verification entries".into(),
            ));
        }
        let child_now = entry.path();
        let child_after = dir_after.join(entry.file_name());
        let meta = fs::symlink_metadata(&child_now)?;
        if meta.file_type().is_symlink() {
            check_relocated_symlink(root_c, raw_root, &child_now, &child_after)?;
        } else if meta.is_dir() {
            check_relocated_dir_symlinks(root_c, raw_root, &child_now, &child_after, scanned)?;
        }
    }
    Ok(())
}

fn normalize_link_target_path(raw: &Path) -> PathBuf {
    let text = raw.to_string_lossy();
    let norm = normalize_windows_drive_path(&text);
    PathBuf::from(norm.as_ref())
}

fn canonical_sandbox_root(root: &Path) -> Result<PathBuf> {
    let canon = fs::canonicalize(root).map_err(|e| Error::Message(format!("sandbox root: {e}")))?;
    Ok(strip_verbatim_prefix(&canon))
}

fn resolve_with_options(
    root: Option<&Path>,
    user_path: &str,
    require_parent: bool,
    follow_final: bool,
) -> Result<PathBuf> {
    if user_path.contains('\0') {
        return Err(Error::Message("path contains NUL".into()));
    }
    let trimmed = trim_trailing_sep(user_path);
    let normalized_text = normalize_windows_drive_path(trimmed);
    let raw = PathBuf::from(normalized_text.as_ref());
    let Some(root) = root else {
        let joined = join_root(None, &raw)?;
        if require_parent {
            return Ok(joined);
        }
        return Ok(normalize(&joined));
    };
    let root_c = canonical_sandbox_root(root)?;
    resolve_sandboxed(
        &root_c,
        root,
        &raw,
        require_parent,
        follow_final,
        normalized_text.as_ref(),
        0,
    )
}

#[derive(Clone, Debug)]
enum PathTok {
    Prefix(OsString),
    RootDir,
    CurDir,
    ParentDir,
    Normal(OsString),
}

fn tokenize_path(path: &Path) -> VecDeque<PathTok> {
    let mut out = VecDeque::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => out.push_back(PathTok::Prefix(p.as_os_str().to_os_string())),
            Component::RootDir => out.push_back(PathTok::RootDir),
            Component::CurDir => out.push_back(PathTok::CurDir),
            Component::ParentDir => out.push_back(PathTok::ParentDir),
            Component::Normal(n) => out.push_back(PathTok::Normal(n.to_os_string())),
        }
    }
    out
}

fn resolve_sandboxed(
    root_c: &Path,
    raw_root: &Path,
    raw_input: &Path,
    require_parent: bool,
    follow_final: bool,
    user_label: &str,
    initial_hops: usize,
) -> Result<PathBuf> {
    let raw_root_norm = normalize(&join_root(None, raw_root)?);
    let (mut cur, mut queue, mut entered_root) = if !raw_input.is_absolute() {
        (root_c.to_path_buf(), tokenize_path(raw_input), true)
    } else if let Ok(rel) = strip_prefix_os_aware(raw_input, root_c) {
        (root_c.to_path_buf(), tokenize_path(&rel), true)
    } else if let Ok(rel) = strip_prefix_os_aware(raw_input, &raw_root_norm) {
        (root_c.to_path_buf(), tokenize_path(&rel), true)
    } else {
        (PathBuf::new(), tokenize_path(raw_input), false)
    };

    let mut hops = initial_hops;
    let mut missing_depth = 0usize;

    while let Some(tok) = queue.pop_front() {
        match tok {
            PathTok::Prefix(p) => {
                cur.clear();
                cur.push(p);
                missing_depth = 0;
                entered_root = is_inside_root(root_c, &cur);
            }
            PathTok::RootDir => {
                cur.push(std::path::MAIN_SEPARATOR_STR);
                missing_depth = 0;
                entered_root = is_inside_root(root_c, &cur);
            }
            PathTok::CurDir => {}
            PathTok::ParentDir => {
                if missing_depth > 0 {
                    cur.pop();
                    missing_depth -= 1;
                } else {
                    cur.pop();
                }
                if entered_root && !is_inside_root(root_c, &cur) {
                    return Err(Error::PermissionDenied(format!(
                        "path escapes sandbox: {user_label}"
                    )));
                }
            }
            PathTok::Normal(name) => {
                let is_last = queue.iter().all(|t| matches!(t, PathTok::CurDir));
                cur.push(&name);
                if missing_depth > 0 {
                    if require_parent && !is_last {
                        let parent_disp = cur.parent().unwrap_or(&cur).display().to_string();
                        return Err(Error::NotFound(format!(
                            "parent directory does not exist: {parent_disp}"
                        )));
                    }
                    missing_depth += 1;
                    continue;
                }

                match fs::symlink_metadata(&cur) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        if is_last && !follow_final {
                            if entered_root {
                                assert_inside(root_c, &cur, user_label)?;
                            }
                            continue;
                        }
                        hops += 1;
                        if hops > MAX_SYMLINK_HOPS {
                            return Err(Error::Message(format!(
                                "too many levels of symbolic links: {user_label}"
                            )));
                        }
                        let raw_target = fs::read_link(&cur)?;
                        let target = normalize_link_target_path(&raw_target);
                        let parent = cur
                            .parent()
                            .map(Path::to_path_buf)
                            .unwrap_or_else(|| root_c.to_path_buf());
                        if entered_root {
                            // A symlink living inside the sandbox must itself
                            // resolve inside `root_c` before any trailing path
                            // components are traversed.
                            let link_base = if target.is_absolute() {
                                target
                            } else {
                                parent.join(&target)
                            };
                            cur = resolve_sandboxed(
                                root_c, raw_root, &link_base, false, true, user_label, hops,
                            )?;
                            missing_depth = if fs::symlink_metadata(&cur).is_ok() {
                                0
                            } else {
                                count_missing_tail(root_c, &cur)
                            };
                            if missing_depth > 0 && require_parent && !is_last {
                                return Err(Error::NotFound(format!(
                                    "parent directory does not exist: {}",
                                    cur.display()
                                )));
                            }
                        } else {
                            // Still above `root_c` (e.g. non-canonical symlink root
                            // such as `/var/folders -> /private/var/folders`).
                            let next_path = if target.is_absolute() {
                                target
                            } else {
                                parent.join(&target)
                            };
                            let mut front = tokenize_path(&next_path);
                            while let Some(back_tok) = front.pop_back() {
                                queue.push_front(back_tok);
                            }
                            cur.clear();
                            missing_depth = 0;
                        }
                    }
                    Ok(meta) => {
                        // Intermediate non-directories must fail with a tip
                        // before we walk into ENOTDIR on the next component.
                        if !is_last && !meta.is_dir() {
                            return Err(Error::Message(format!(
                                "path component `{}` exists but is not a directory",
                                cur.display()
                            )));
                        }
                        if let Ok(canon) = fs::canonicalize(&cur) {
                            cur = strip_verbatim_prefix(&canon);
                        }
                        if is_inside_root(root_c, &cur) {
                            entered_root = true;
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::NotFound => {
                        if require_parent && !is_last {
                            return Err(Error::NotFound(format!(
                                "parent directory does not exist: {}",
                                cur.display()
                            )));
                        }
                        missing_depth = 1;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        }
    }

    assert_inside(root_c, &cur, user_label)?;
    Ok(strip_verbatim_prefix(&cur))
}

fn count_missing_tail(root_c: &Path, path: &Path) -> usize {
    let mut probe = path.to_path_buf();
    let mut missing = 0usize;
    while probe != root_c && fs::symlink_metadata(&probe).is_err() {
        missing += 1;
        if !probe.pop() {
            break;
        }
    }
    missing
}

fn strip_prefix_os_aware(path: &Path, base: &Path) -> std::result::Result<PathBuf, ()> {
    let path_clean = strip_verbatim_prefix(path);
    let base_clean = strip_verbatim_prefix(base);
    if let Ok(rel) = path_clean.strip_prefix(&base_clean) {
        return Ok(rel.to_path_buf());
    }
    if cfg!(windows) {
        let p_comps: Vec<_> = path_clean.components().collect();
        let b_comps: Vec<_> = base_clean.components().collect();
        if p_comps.len() >= b_comps.len()
            && p_comps[..b_comps.len()]
                .iter()
                .zip(b_comps.iter())
                .all(|(a, b)| {
                    a.as_os_str()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
                })
        {
            let mut rel = PathBuf::new();
            for c in &p_comps[b_comps.len()..] {
                rel.push(c.as_os_str());
            }
            return Ok(rel);
        }
    }
    Err(())
}

pub fn is_inside_root(root_c: &Path, candidate: &Path) -> bool {
    let root_clean = strip_verbatim_prefix(root_c);
    let cand_clean = strip_verbatim_prefix(candidate);
    if cand_clean == root_clean || cand_clean.starts_with(&root_clean) {
        return true;
    }
    if cfg!(windows) {
        strip_prefix_os_aware(&cand_clean, &root_clean).is_ok()
    } else {
        false
    }
}

fn join_root(root: Option<&Path>, raw: &Path) -> Result<PathBuf> {
    Ok(match root {
        Some(root) if !raw.is_absolute() => root.join(raw),
        Some(_) => raw.to_path_buf(),
        None if raw.is_absolute() => raw.to_path_buf(),
        None => std::env::current_dir()?.join(raw),
    })
}

fn assert_inside(root: &Path, candidate: &Path, user_path: &str) -> Result<()> {
    if !is_inside_root(root, candidate) {
        return Err(Error::PermissionDenied(format!(
            "path escapes sandbox: {user_path}"
        )));
    }
    Ok(())
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Dest path for a rename/move, matching Unix `mv` into-directory rules.
///
/// When `to` names an existing directory, the source basename is appended.
/// A trailing separator on `to` that does not resolve to a directory is an error
/// (`mv a b/` must not silently create a file named `b`).
pub fn rename_destination(from: &Path, to: &Path, to_trailing_sep: bool) -> Result<PathBuf> {
    if to.is_dir() {
        let name = from
            .file_name()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Message("source path has no file name".into()))?;
        return Ok(to.join(name));
    }
    if to_trailing_sep {
        return Err(Error::Message(format!(
            "{} ends with a slash but is not a directory",
            to.display()
        )));
    }
    Ok(to.to_path_buf())
}

/// True when the user wrote a destination that ends with `/` or `\\`.
pub fn path_trailing_sep(user_path: &str) -> bool {
    user_path.ends_with('/') || user_path.ends_with('\\')
}

/// Strip one run of trailing `/` or `\\` for resolution. Keep a bare root as `/`.
pub fn trim_trailing_sep(user_path: &str) -> &str {
    let trimmed = user_path.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        if user_path.starts_with('/') {
            "/"
        } else {
            trimmed
        }
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_escape_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let err = resolve_path(Some(&root), "..").unwrap_err();
        assert!(err.to_string().contains("escapes"), "{err}");
    }

    #[test]
    fn child_path_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let resolved = resolve_lexical(Some(&root), "a/b").unwrap();
        assert!(resolved.ends_with("a/b") || resolved.ends_with(r"a\b"));
        let root_c = strip_verbatim_prefix(&std::fs::canonicalize(&root).unwrap());
        assert!(
            strip_verbatim_prefix(&resolved).starts_with(&root_c),
            "{resolved:?} not in {root_c:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn lexical_child_through_symlink_root_stays_inside() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let resolved = resolve_lexical(Some(&link), "a/b").unwrap();
        let root_c = std::fs::canonicalize(&link).unwrap();
        assert!(
            resolved.starts_with(&root_c),
            "{resolved:?} not in {root_c:?}"
        );
        assert!(resolved.ends_with("a/b"));

        let abs_via_link = format!("{}/a/b", link.display());
        let resolved_abs = resolve_lexical(Some(&link), &abs_via_link).unwrap();
        assert_eq!(resolved_abs, resolved);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_denied_for_live_dangling_missing_parent_loop_and_move() {
        let dir = tempfile::tempdir().unwrap();
        let outer = dir.path().join("outer");
        let root = outer.join("inner").join("sandbox");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        // 1. Live symlink outside root.
        std::os::unix::fs::symlink(&outside, root.join("live_escape")).unwrap();
        assert!(resolve_path(Some(&root), "live_escape/secret").is_err());
        assert!(resolve_lexical(Some(&root), "live_escape/secret").is_err());

        // 2. J-01 PoC: Dangling symlink pointing to non-existent file outside root!
        std::os::unix::fs::symlink("../../escaped_new.txt", root.join("dangling_escape")).unwrap();
        let e1 = resolve_path(Some(&root), "dangling_escape").unwrap_err();
        assert!(e1.to_string().contains("escapes"), "{e1}");
        let e2 = resolve_lexical(Some(&root), "dangling_escape").unwrap_err();
        assert!(e2.to_string().contains("escapes"), "{e2}");

        // 3. Dangling intermediate directory symlink with missing children (`mkdir -p` / `cp`).
        std::os::unix::fs::symlink("../../nonexistent_outside_dir", root.join("dangling_dir"))
            .unwrap();
        assert!(resolve_lexical(Some(&root), "dangling_dir/sub/file.txt").is_err());

        // 4. Legitimate intra-sandbox dangling symlink STILL works!
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink("sub/future.txt", root.join("valid_dangling")).unwrap();
        let ok_p = resolve_path(Some(&root), "valid_dangling").unwrap();
        assert!(ok_p.ends_with("sub/future.txt"));

        // 5. Symlink loop (`loop_a -> loop_b -> loop_a`) terminates cleanly with ELOOP error!
        std::os::unix::fs::symlink("loop_b", root.join("loop_a")).unwrap();
        std::os::unix::fs::symlink("loop_a", root.join("loop_b")).unwrap();
        let loop_err = resolve_path(Some(&root), "loop_a").unwrap_err();
        assert!(
            loop_err.to_string().contains("symbolic links"),
            "{loop_err}"
        );

        // 6. Relative symlink inside deep subdir cannot be moved to top of sandbox (`mv` escape)!
        let deep = root.join("d1").join("d2").join("d3");
        std::fs::create_dir_all(&deep).unwrap();
        let deep_sym = deep.join("sym");
        std::os::unix::fs::symlink("../../escaped_via_mv.txt", &deep_sym).unwrap();
        // Direct symlink move rejected:
        assert!(
            ensure_moved_symlinks_stay_inside(Some(&root), &deep_sym, &root.join("sym")).is_err()
        );
        // Moving parent subtree `d1/d2/d3` to `root/d3_top` (so `d3_top/sym` -> `../../` escapes `root`) ALSO rejected!
        assert!(ensure_moved_symlinks_stay_inside(
            Some(&root),
            &root.join("d1").join("d2").join("d3"),
            &root.join("d3_top")
        )
        .is_err());
        // Moving within same depth (`d1/d2/d3/sym` -> `d1/d2/d3/sym_renamed`) stays allowed:
        assert!(ensure_moved_symlinks_stay_inside(
            Some(&root),
            &deep_sym,
            &deep.join("sym_renamed")
        )
        .is_ok());

        // 7. J-03: `resolve_path_no_follow` returns the symlink entry itself without
        // following it to the target directory, while still blocking escaping parents!
        std::os::unix::fs::symlink("sub", root.join("link_to_sub")).unwrap();
        let self_entry = resolve_path_no_follow(Some(&root), "link_to_sub").unwrap();
        assert!(std::fs::symlink_metadata(&self_entry)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(resolve_path_no_follow(Some(&root), "live_escape/victim").is_err());

        // 8. TOCTOU O_NOFOLLOW guard rejects opening a symlink directly when sandboxed!
        let toctou_err =
            open_write_file(&root.join("valid_dangling"), true, true, true).unwrap_err();
        assert!(
            toctou_err.raw_os_error() == Some(libc::ELOOP),
            "{toctou_err:?}"
        );
    }

    #[test]
    fn rename_into_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("file.txt");
        std::fs::write(&src, b"x").unwrap();
        let dest_dir = dir.path().join("box");
        std::fs::create_dir(&dest_dir).unwrap();
        let got = rename_destination(&src, &dest_dir, false).unwrap();
        assert_eq!(got, dest_dir.join("file.txt"));
        let got_slash = rename_destination(&src, &dest_dir, true).unwrap();
        assert_eq!(got_slash, dest_dir.join("file.txt"));
    }

    #[test]
    fn rename_trailing_sep_requires_directory() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("file.txt");
        std::fs::write(&src, b"x").unwrap();
        let missing = dir.path().join("nope");
        let err = rename_destination(&src, &missing, true).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[test]
    fn rename_to_new_name_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("a.txt");
        std::fs::write(&src, b"x").unwrap();
        let dest = dir.path().join("b.txt");
        let got = rename_destination(&src, &dest, false).unwrap();
        assert_eq!(got, dest);
    }

    #[test]
    fn trim_trailing_sep_keeps_root() {
        assert_eq!(trim_trailing_sep("/tmp/x/"), "/tmp/x");
        assert_eq!(trim_trailing_sep("/"), "/");
        assert!(path_trailing_sep("/tmp/x/"));
        assert!(path_trailing_sep(r"C:\tmp\x\"));
        assert!(!path_trailing_sep("/tmp/x"));
    }

    #[test]
    fn windows_bare_drive_becomes_root() {
        assert_eq!(normalize_windows_drive_path("C:").as_ref(), r"C:\");
        assert_eq!(normalize_windows_drive_path("c:").as_ref(), r"c:\");
        assert_eq!(normalize_windows_drive_path("C:/").as_ref(), "C:/");
        assert_eq!(normalize_windows_drive_path(r"C:\").as_ref(), r"C:\");
        assert_eq!(
            normalize_windows_drive_path("C:/Users").as_ref(),
            "C:/Users"
        );
        assert_eq!(
            normalize_windows_drive_path(r"C:\Users").as_ref(),
            r"C:\Users"
        );
        assert_eq!(
            normalize_windows_drive_path("C:Users").as_ref(),
            r"C:\Users"
        );
        assert_eq!(
            normalize_windows_drive_path(r"C:Users\x").as_ref(),
            r"C:\Users\x"
        );
        assert_eq!(
            normalize_windows_drive_path("D:foo/bar").as_ref(),
            r"D:\foo/bar"
        );
        assert_eq!(normalize_windows_drive_path("/tmp").as_ref(), "/tmp");
        assert_eq!(
            normalize_windows_drive_path("relative").as_ref(),
            "relative"
        );
    }

    #[test]
    fn trim_then_normalize_drive_root() {
        let trimmed = trim_trailing_sep(r"C:\");
        assert_eq!(trimmed, "C:");
        assert_eq!(normalize_windows_drive_path(trimmed).as_ref(), r"C:\");
    }

    #[test]
    fn resolve_path_strips_trailing_sep_without_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f.txt");
        std::fs::write(&file, b"hi").unwrap();
        let with_slash = format!("{}/", file.display());
        let resolved = resolve_path(None, &with_slash).unwrap();
        assert_eq!(resolved, file);
        assert!(resolved.is_file());
        std::fs::remove_file(&resolved).unwrap();
    }

    #[test]
    fn resolve_path_keeps_unix_root() {
        let resolved = resolve_path(None, "/").unwrap();
        assert_eq!(resolved, PathBuf::from("/"));
    }

    #[test]
    fn strip_verbatim_prefix_drops_windows_extended_path() {
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\C:\Users\x")),
            PathBuf::from(r"C:\Users\x")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\UNC\server\share\f")),
            PathBuf::from(r"\\server\share\f")
        );
        assert!(paths_equivalent(
            Path::new(r"\\?\C:\Temp\work"),
            Path::new(r"C:\Temp\work")
        ));
        assert_eq!(normalize_path_text(r"C:\Temp\a.txt"), "C:/Temp/a.txt");
    }
}
