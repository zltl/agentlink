//! Symlink / reparse-point classification for sandbox nofollow.
//!
//! On Unix, only `S_IFLNK` entries are links. On Windows, Rust's
//! `FileType::is_symlink()` is true solely for `IO_REPARSE_TAG_SYMLINK`;
//! mount-point **junctions** also redirect and must be treated as
//! nofollow entries for J-03-class `rm` / resolve / move checks.

use std::fs;

/// True when `meta` names a symbolic link or (on Windows) any reparse point
/// such as a directory junction. Used wherever the sandbox must operate on
/// the directory entry itself rather than its target.
pub fn is_link_entry(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        return meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Unlink a symlink or Windows junction/reparse entry without touching its target.
pub fn remove_link_entry(path: &std::path::Path, meta: &fs::Metadata) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        // DeleteFile fails on directory reparse points; RemoveDirectory
        // removes the link and leaves the target intact.
        if meta.is_dir() {
            return fs::remove_dir(path);
        }
    }
    let _ = meta;
    fs::remove_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn unix_symlink_is_link_entry_regular_file_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, b"x").unwrap();
        assert!(!is_link_entry(&fs::symlink_metadata(&file).unwrap()));
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(is_link_entry(&fs::symlink_metadata(&link).unwrap()));
    }
}
