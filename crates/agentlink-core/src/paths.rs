//! Path resolution, including an optional sandbox root.

use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};


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

/// Resolve `user_path` and, when `root` is set, require it to stay inside the sandbox.
///
/// Existing symlinks are canonicalized, so a link that points outside the root is denied.
/// The parent directory must already exist (write, read, remove, rename).
pub fn resolve_path(root: Option<&Path>, user_path: &str) -> Result<PathBuf> {
    if user_path.contains('\0') {
        return Err(Error::Message("path contains NUL".into()));
    }
    // Agents often append a trailing slash (`rm file/`, `ls file/`). Transfers
    // already go through `resolve_lexical` → `normalize`, which drops it;
    // `resolve_path` used to keep the separator and Linux then returns ENOTDIR
    // for unlink/stat on a regular file. Trim first; bare `/` and `C:\` stay
    // roots via trim_trailing_sep + normalize_windows_drive_path.
    let user_path = trim_trailing_sep(user_path);
    let user_path = normalize_windows_drive_path(user_path);
    let raw = PathBuf::from(user_path.as_ref());
    let joined = join_root(root, &raw)?;
    let Some(root) = root else {
        return Ok(joined);
    };
    let root_c =
        std::fs::canonicalize(root).map_err(|e| Error::Message(format!("sandbox root: {e}")))?;
    let candidate = canonicalize_allow_missing(&joined)?;
    assert_inside(&root_c, &candidate, user_path.as_ref())?;
    Ok(candidate)
}

/// Lexical normalization for `mkdir -p`, where intermediate directories may not exist yet.
pub fn resolve_lexical(root: Option<&Path>, user_path: &str) -> Result<PathBuf> {
    if user_path.contains('\0') {
        return Err(Error::Message("path contains NUL".into()));
    }
    let user_path = trim_trailing_sep(user_path);
    let user_path = normalize_windows_drive_path(user_path);
    let raw = PathBuf::from(user_path.as_ref());
    let joined = join_root(root, &raw)?;
    let normalized = normalize(&joined);
    let Some(root) = root else {
        return Ok(normalized);
    };
    let root_c =
        std::fs::canonicalize(root).map_err(|e| Error::Message(format!("sandbox root: {e}")))?;
    // The nearest existing ancestor must still be inside the root, so a
    // symlink parent cannot redirect a recursive mkdir. Rebuild the missing
    // suffix on that canonical ancestor: macOS maps /var to /private/var, and
    // Windows canonicalize adds a \\?\ prefix, so the lexical path does not
    // start with the canonical root even when it is inside it.
    let ancestor = nearest_existing(&normalized)?;
    let ancestor_c = std::fs::canonicalize(&ancestor)?;
    assert_inside(&root_c, &ancestor_c, user_path.as_ref())?;
    let suffix = normalized.strip_prefix(&ancestor).map_err(|_| {
        Error::Message(format!(
            "cannot relativize {} against {}",
            normalized.display(),
            ancestor.display()
        ))
    })?;
    let candidate = normalize(&ancestor_c.join(suffix));
    assert_inside(&root_c, &candidate, user_path.as_ref())?;
    Ok(candidate)
}

fn join_root(root: Option<&Path>, raw: &Path) -> Result<PathBuf> {
    Ok(match root {
        Some(root) if !raw.is_absolute() => root.join(raw),
        Some(_) => raw.to_path_buf(),
        None if raw.is_absolute() => raw.to_path_buf(),
        None => std::env::current_dir()?.join(raw),
    })
}

fn canonicalize_allow_missing(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return Ok(std::fs::canonicalize(path)?);
    }
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if !parent.exists() {
        return Err(Error::NotFound(format!(
            "parent directory does not exist: {}",
            parent.display()
        )));
    }
    let parent_c = std::fs::canonicalize(parent)?;
    match path.file_name() {
        Some(name) => Ok(parent_c.join(name)),
        None => Ok(parent_c),
    }
}

fn nearest_existing(path: &Path) -> Result<PathBuf> {
    let mut cur = path.to_path_buf();
    loop {
        if cur.exists() {
            return Ok(cur);
        }
        if !cur.pop() {
            return Err(Error::NotFound(format!(
                "no existing ancestor for {}",
                path.display()
            )));
        }
    }
}

fn assert_inside(root: &Path, candidate: &Path, user_path: &str) -> Result<()> {
    if candidate != root && !candidate.starts_with(root) {
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
        assert!(resolved.starts_with(std::fs::canonicalize(&root).unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn lexical_child_through_symlink_root_stays_inside() {
        // Same shape as macOS /var -> /private/var and a non-canonical root.
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
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let err = resolve_path(Some(&root), "link/secret").unwrap_err();
        assert!(err.to_string().contains("escapes"), "{err}");
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
        assert_eq!(path_trailing_sep("/tmp/x/"), true);
        assert_eq!(path_trailing_sep(r"C:\tmp\x\"), true);
        assert_eq!(path_trailing_sep("/tmp/x"), false);
    }

    #[test]
    fn windows_bare_drive_becomes_root() {
        assert_eq!(normalize_windows_drive_path("C:").as_ref(), r"C:\");
        assert_eq!(normalize_windows_drive_path("c:").as_ref(), r"c:\");
        assert_eq!(normalize_windows_drive_path("C:/").as_ref(), "C:/");
        assert_eq!(normalize_windows_drive_path(r"C:\").as_ref(), r"C:\");
        assert_eq!(normalize_windows_drive_path("C:/Users").as_ref(), "C:/Users");
        assert_eq!(normalize_windows_drive_path(r"C:\Users").as_ref(), r"C:\Users");
        assert_eq!(normalize_windows_drive_path("C:Users").as_ref(), r"C:\Users");
        assert_eq!(normalize_windows_drive_path(r"C:Users\x").as_ref(), r"C:\Users\x");
        assert_eq!(normalize_windows_drive_path("D:foo/bar").as_ref(), r"D:\foo/bar");
        assert_eq!(normalize_windows_drive_path("/tmp").as_ref(), "/tmp");
        assert_eq!(normalize_windows_drive_path("relative").as_ref(), "relative");
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
        // OS-level unlink would ENOTDIR on the slash form; resolved path works.
        assert!(resolved.is_file());
        std::fs::remove_file(&resolved).unwrap();
    }

    #[test]
    fn resolve_path_keeps_unix_root() {
        let resolved = resolve_path(None, "/").unwrap();
        assert_eq!(resolved, PathBuf::from("/"));
    }
}
