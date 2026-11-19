//! Guest paths the phone exposes.
//!
//! `app:/files` and `app:/cache` are the app's private directories.
//! `storage:/` is external storage, only when the user opted into all-files
//! access. `saf:/<id>/...` is a folder the user picked; the Kotlin host
//! stages those into a real file before the transfer engine runs.
//! `app:/audit.log` and `app:/device.json` are virtual.

use std::path::{Path, PathBuf};

use agentlink_core::paths::{resolve_lexical, resolve_path, resolve_path_no_follow};
use agentlink_core::{Error, Result};

#[derive(Clone)]
pub struct Roots {
    pub files: PathBuf,
    pub cache: PathBuf,
    pub storage: Option<PathBuf>,
    pub audit: PathBuf,
}

#[derive(Debug)]
pub enum GuestTarget {
    Real(PathBuf),
    Saf(String),
    Audit,
    Device,
    /// The synthetic `app:/` directory.
    AppRoot,
}

pub fn classify(roots: &Roots, guest: &str, write: bool) -> Result<GuestTarget> {
    classify_inner(roots, guest, write, true).map(|(target, _)| target)
}

/// Like [`classify`], but keeps a final symlink un-dereferenced (used by
/// `remove_guest` and `rename_guest` source/destination entry lookup) and
/// also returns the enclosing sandbox root for relative-symlink move checks.
pub fn classify_entry_with_root(
    roots: &Roots,
    guest: &str,
    write: bool,
    follow_final: bool,
) -> Result<(GuestTarget, Option<PathBuf>)> {
    classify_inner(roots, guest, write, follow_final)
}

/// Return the sandbox root directory that confines `guest`, when `guest` maps
/// to a real filesystem root (`app:/files`, `app:/cache`, or `storage:/`).
pub fn sandbox_root_for_guest(roots: &Roots, guest: &str) -> Option<PathBuf> {
    let path = normalize(guest);
    if strip_root(&path, "app:/files").is_some() {
        return Some(roots.files.clone());
    }
    if strip_root(&path, "app:/cache").is_some() {
        return Some(roots.cache.clone());
    }
    if strip_root(&path, "storage:").is_some() {
        return roots.storage.clone();
    }
    if !path.starts_with('/') && !path.contains(':') && path != "app:" && path != "app:/" {
        return Some(roots.files.clone());
    }
    None
}

fn classify_inner(
    roots: &Roots,
    guest: &str,
    write: bool,
    follow_final: bool,
) -> Result<(GuestTarget, Option<PathBuf>)> {
    let path = normalize(guest);
    if path.contains('\0') {
        return Err(Error::Message("path contains NUL".into()));
    }
    if path.len() > 4096 {
        return Err(Error::Message("path is too long".into()));
    }
    reject_dots(&path)?;
    if is_reserved_write(&path, write) {
        return Err(Error::Message(
            "audit log and device info are read-only".into(),
        ));
    }
    if path == "app:" || path == "app:/" {
        if write {
            return Err(Error::Message("app:/ is not a writable directory".into()));
        }
        return Ok((GuestTarget::AppRoot, None));
    }
    if path == "app:/audit.log" {
        return Ok((GuestTarget::Audit, None));
    }
    if path == "app:/device.json" {
        return Ok((GuestTarget::Device, None));
    }
    if path.starts_with("saf:/") || path == "saf:" {
        return Ok((GuestTarget::Saf(path), None));
    }
    if let Some(rel) = strip_root(&path, "app:/files") {
        return Ok((
            GuestTarget::Real(under(&roots.files, rel, follow_final)?),
            Some(roots.files.clone()),
        ));
    }
    if let Some(rel) = strip_root(&path, "app:/cache") {
        return Ok((
            GuestTarget::Real(under(&roots.cache, rel, follow_final)?),
            Some(roots.cache.clone()),
        ));
    }
    if let Some(rel) = strip_root(&path, "storage:") {
        let root = roots.storage.as_ref().ok_or_else(|| {
            Error::PermissionDenied(
                "all-files access is not granted; pick a folder or allow storage".into(),
            )
        })?;
        return Ok((
            GuestTarget::Real(under(root, rel, follow_final)?),
            Some(root.clone()),
        ));
    }
    if path.starts_with('/') || path.contains(':') {
        return Err(Error::Message(format!(
            "path is outside the granted roots ({path})"
        )));
    }
    Ok((
        GuestTarget::Real(under(&roots.files, &path, follow_final)?),
        Some(roots.files.clone()),
    ))
}

/// A real path the transfer engine can open. SAF paths are not handled here.
pub fn real_target(roots: &Roots, guest: &str, write: bool) -> Result<PathBuf> {
    match classify(roots, guest, write)? {
        GuestTarget::Real(path) => Ok(path),
        GuestTarget::Audit if !write => Ok(roots.audit.clone()),
        GuestTarget::Audit | GuestTarget::Device | GuestTarget::AppRoot | GuestTarget::Saf(_) => {
            Err(Error::Message(format!(
                "{guest} is not a plain filesystem path"
            )))
        }
    }
}

fn is_reserved_write(path: &str, write: bool) -> bool {
    write && (path == "app:/audit.log" || path == "app:/device.json")
}

fn normalize(path: &str) -> String {
    let mut out = path.trim().replace('\\', "/");
    while out.contains("//") {
        out = out.replace("//", "/");
    }
    if out.ends_with('/') && out.len() > 1 && out != "app:/" {
        out.pop();
    }
    out
}

fn reject_dots(path: &str) -> Result<()> {
    for seg in path.split('/') {
        if seg == ".." {
            return Err(Error::Message("path escapes the granted root".into()));
        }
    }
    Ok(())
}

fn strip_root<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if path == prefix {
        return Some("");
    }
    let with_slash = format!("{prefix}/");
    path.strip_prefix(&with_slash)
}

fn under(root: &Path, rel: &str, follow_final: bool) -> Result<PathBuf> {
    if rel.is_empty() {
        return Ok(root.to_path_buf());
    }
    if Path::new(rel).is_absolute() {
        return Err(Error::Message("path escapes the granted root".into()));
    }
    if !follow_final {
        return resolve_path_no_follow(Some(root), rel);
    }
    // `resolve_lexical` resolves all existing and dangling symlinks along the
    // prefix and final leaf while permitting not-yet-created intermediate dirs.
    if std::fs::symlink_metadata(root.join(rel)).is_ok() {
        resolve_path(Some(root), rel)
    } else {
        resolve_lexical(Some(root), rel)
    }
}

pub fn ensure_inside(roots: &Roots, candidate: &Path) -> Result<()> {
    let mut allowed: Vec<&Path> = vec![&roots.files, &roots.cache];
    if let Some(storage) = &roots.storage {
        allowed.push(storage.as_path());
    }
    for root in allowed {
        if inside(root, candidate)? {
            return Ok(());
        }
    }
    Err(Error::Message(
        "staged path is outside the app sandbox".into(),
    ))
}

fn inside(root: &Path, candidate: &Path) -> Result<bool> {
    Ok(agentlink_core::paths::ensure_path_stays_in_sandbox_at_sink(Some(root), candidate).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> (tempfile::TempDir, Roots) {
        let dir = tempfile::tempdir().unwrap();
        let files = dir.path().join("files");
        let cache = dir.path().join("cache");
        let storage = dir.path().join("storage");
        std::fs::create_dir_all(&files).unwrap();
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir_all(&storage).unwrap();
        let roots = Roots {
            files: files.clone(),
            cache,
            storage: Some(storage),
            audit: dir.path().join("audit.log"),
        };
        (dir, roots)
    }

    #[test]
    fn maps_app_files_and_rejects_dotdot() {
        let (_dir, roots) = roots();
        let path = real_target(&roots, "app:/files/notes/a.txt", true).unwrap();
        assert!(path.ends_with("files/notes/a.txt") || path.ends_with("files\\notes\\a.txt"));
        let err = real_target(&roots, "app:/files/../../etc/passwd", false).unwrap_err();
        assert!(err.to_string().contains("escapes"), "{err}");
    }

    #[test]
    fn symlink_cannot_leave_the_root() {
        let (_dir, roots) = roots();
        let outside = _dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"nope").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, roots.files.join("link")).unwrap();
            let err = real_target(&roots, "app:/files/link/secret", false).unwrap_err();
            assert!(
                err.to_string().contains("escapes") || err.to_string().contains("sandbox"),
                "{err}"
            );
            // J-01 Android `app:/files` dangling symlink escape must ALSO be denied!
            std::os::unix::fs::symlink("../escaped_app_data.txt", roots.files.join("dangling"))
                .unwrap();
            let err_dangling = real_target(&roots, "app:/files/dangling", true).unwrap_err();
            assert!(
                err_dangling.to_string().contains("escapes")
                    || err_dangling.to_string().contains("sandbox"),
                "{err_dangling}"
            );
        }
    }

    #[test]
    fn reserved_files_are_read_only() {
        let (_dir, roots) = roots();
        assert!(matches!(
            classify(&roots, "app:/audit.log", false).unwrap(),
            GuestTarget::Audit
        ));
        assert!(classify(&roots, "app:/device.json", true).is_err());
        assert!(classify(&roots, "saf:/docs/a", true).is_ok());
    }
}
