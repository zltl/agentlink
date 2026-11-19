//! Sandbox write/rename sinks: nofollow opens, move checks, and post-rename rollback.
//!
//! These entry points are the fail-closed boundary for `--root` file mutations.
//! Path *resolution* lives in the parent module; this file only commits changes.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

use super::{canonical_sandbox_root, normalize_link_target_path, resolve_sandboxed, MAX_SUBTREE_SYMLINK_SCAN};

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

/// Open a file for writing without following a final-component symlink when
/// `nofollow` is set.
///
/// - **Unix:** `O_NOFOLLOW` so a last-microsecond regular→symlink swap fails with `ELOOP`.
/// - **Windows:** `FILE_FLAG_OPEN_REPARSE_POINT` opens the name itself; any reparse
///   point (symlink or junction) is then rejected. This closes the check-then-open
///   TOCTOU that a plain `symlink_metadata` + `open` left on Windows.
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
    #[cfg(windows)]
    if nofollow {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT — do not follow the final name.
        opts.custom_flags(0x0020_0000);
    }
    let file = opts.open(path)?;
    #[cfg(windows)]
    if nofollow {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        let meta = file.metadata()?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "refusing to open reparse point (symlink/junction) for sandboxed write",
            ));
        }
    }
    Ok(file)
}

/// Rename `from` → `to` under an optional sandbox root.
///
/// Runs [`ensure_moved_symlinks_stay_inside`] before the syscall (twice, to shrink
/// the race window), then again on the destination. If the post-check fails —
/// typically because a concurrent same-UID writer retargeted a relative symlink
/// during the window — the destination is rolled back (rename back, else unlink
/// the dest entry) and the error is returned. A successful return means the
/// destination does not currently escape `root`.
///
/// Same-UID unrestricted `exec`/`full` is out of scope; this protects `--root`
/// grant boundaries for `read-write` file ops against symlink relocation races.
pub fn rename_within_sandbox(root: Option<&Path>, from: &Path, to: &Path) -> Result<()> {
    ensure_moved_symlinks_stay_inside(root, from, to)?;
    // Second pre-check immediately before the syscall.
    ensure_moved_symlinks_stay_inside(root, from, to)?;
    fs::rename(from, to)?;
    if let Err(err) = ensure_moved_symlinks_stay_inside(root, to, to) {
        rollback_failed_sandbox_rename(from, to);
        return Err(err);
    }
    Ok(())
}

pub(crate) fn rollback_failed_sandbox_rename(from: &Path, to: &Path) {
    if fs::rename(to, from).is_ok() {
        return;
    }
    // Prefer removing the dest entry over leaving an escaping symlink in place.
    if let Ok(meta) = fs::symlink_metadata(to) {
        if meta.file_type().is_symlink() || meta.is_file() {
            let _ = fs::remove_file(to);
        } else if meta.is_dir() {
            let _ = fs::remove_dir_all(to);
        }
    }
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

