//! Sandbox write/rename sinks: nofollow opens, move checks, and post-rename rollback.
//!
//! These entry points are the fail-closed boundary for `--root` file mutations.
//! Path *resolution* lives in the parent module; this file only commits changes.

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::io::ErrorKind;

use crate::error::{Error, Result};

use super::link_meta::{is_link_entry, remove_link_entry};
use super::{
    canonical_sandbox_root, normalize_link_target_path, resolve_sandboxed, MAX_SUBTREE_SYMLINK_SCAN,
};

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
/// symlink/junction (either `from_entry` itself or a link inside a moved
/// directory subtree) to resolve outside `root` from its new parent directory.
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
    if is_link_entry(&meta) {
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
/// during the window — the destination is rolled back without destroying
/// legitimate directory trees, and the error is returned.
///
/// Same-UID unrestricted `exec`/`full` is out of scope; this protects `--root`
/// grant boundaries for `read-write` file ops against symlink relocation races.
pub fn rename_within_sandbox(root: Option<&Path>, from: &Path, to: &Path) -> Result<()> {
    ensure_moved_symlinks_stay_inside(root, from, to)?;
    // Second pre-check immediately before the syscall.
    ensure_moved_symlinks_stay_inside(root, from, to)?;
    fs::rename(from, to)?;
    if let Err(err) = ensure_moved_symlinks_stay_inside(root, to, to) {
        rollback_failed_sandbox_rename(root, from, to);
        return Err(err);
    }
    Ok(())
}

/// Undo a rename that landed outside the sandbox.
///
/// Prefer rename-back. If that fails:
/// - escaping **link** entries are unlinked (inode only);
/// - directories are walked and only escaping link leaves are removed —
///   never [`fs::remove_dir_all`], which would destroy legitimate files;
/// - after a successful scrub, rename-back is attempted again so a directory
///   whose only escape was a link leaf can return to `from`.
///
/// # Residual safety (honest assessment)
///
/// This rollback is **best-effort, not atomic**. Between `fs::rename` and the
/// post-check there is an inherent TOCTOU window under a same-UID concurrent
/// writer. Outcomes we accept:
///
/// 1. **Rename-back succeeds** — no residue; preferred path.
/// 2. **Escaping symlink/junction at `to`** — unlinked; no escape remains.
/// 3. **Directory at `to` with escaping link leaves** — those leaves are
///    scrubbed; then rename-back is retried. If rename-back still fails (e.g.
///    `from` is occupied, cross-device), a **non-escaping directory tree may
///    remain at `to`**. That residue is still under the grant root when every
///    escaping link was removed; it is **not** an escape hatch. We deliberately
///    do not `remove_dir_all` because that would destroy legitimate user data
///    that happened to be moved.
/// 4. **Plain file residual at `to`** — left in place. A post-check failure on a
///    regular file is unexpected; deleting caller bytes would be worse.
///
/// Same-UID unrestricted `exec`/`full` is out of scope for this helper; the
/// guarantee is "no sandbox escape via symlink relocation," not "no leftover
/// path names under the root after a raced rename."
pub(crate) fn rollback_failed_sandbox_rename(root: Option<&Path>, from: &Path, to: &Path) {
    if fs::rename(to, from).is_ok() {
        return;
    }
    let Ok(meta) = fs::symlink_metadata(to) else {
        return;
    };
    if is_link_entry(&meta) {
        let _ = remove_link_entry(to, &meta);
        return;
    }
    if meta.is_dir() {
        let _ = scrub_escaping_link_leaves(root, to);
        // Retry rename-back now that escaping links are gone.
        let _ = fs::rename(to, from);
        return;
    }
    // Plain files: leave in place. A postcheck failure on a regular file is
    // unexpected; deleting user bytes would be worse than a residual entry.
}

/// Remove only symlink/junction leaves under `dir` that currently escape `root`.
fn scrub_escaping_link_leaves(root: Option<&Path>, dir: &Path) -> Result<()> {
    let Some(root) = root else {
        return Ok(());
    };
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if is_link_entry(&meta) {
            if ensure_moved_symlinks_stay_inside(Some(root), &path, &path).is_err() {
                let _ = remove_link_entry(&path, &meta);
            }
        } else if meta.is_dir() {
            scrub_escaping_link_leaves(Some(root), &path)?;
        }
    }
    Ok(())
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
        if is_link_entry(&meta) {
            check_relocated_symlink(root_c, raw_root, &child_now, &child_after)?;
        } else if meta.is_dir() {
            check_relocated_dir_symlinks(root_c, raw_root, &child_now, &child_after, scanned)?;
        }
    }
    Ok(())
}
