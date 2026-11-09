//! Small helpers used by every crate.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Wire chunk size for file bytes before base64 encoding.
pub const FILE_CHUNK: usize = 64 * 1024;

/// How much of a file one `read_file` request pulls before the client asks again.
pub const READ_WINDOW: u32 = 8 * 1024 * 1024;

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn random_token() -> String {
    random_hex(32)
}

/// Compare two strings without short-circuiting on the first differing byte.
///
/// Both sides are hashed first so the comparison length does not leak the
/// stored token length.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let ha = Sha256::digest(a.as_bytes());
    let hb = Sha256::digest(b.as_bytes());
    let mut diff = 0u8;
    for (x, y) in ha.iter().zip(hb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn b64_decode(data: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(data.trim())
        .map_err(|e| Error::Protocol(format!("base64: {e}")))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    restrict_dir(path)?;
    Ok(())
}

/// `create_dir_all` for a write/cp destination parent.
///
/// When a path component already exists as a non-directory, Rust/Linux often
/// surfaces bare `AlreadyExists` (EEXIST). Diagnose that like mkdir's ENOTDIR
/// tip so agents are not told the destination "already exists".
pub fn create_dir_all_parent(parent: &Path) -> Result<()> {
    match fs::create_dir_all(parent) {
        Ok(()) => Ok(()),
        Err(err) => Err(diagnose_create_dir_all(parent, err)),
    }
}

/// `create_dir_all` for a directory destination (e.g. `cp` of a directory tree).
///
/// When `path` itself exists as a non-directory, surface a clear refusal instead
/// of bare EEXIST from `create_dir_all`.
pub fn create_dir_all_as_dir(path: &Path) -> Result<()> {
    match fs::create_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) => Err(diagnose_create_dir_as_dir(path, err)),
    }
}

fn path_is_nondir(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            // Follow once: symlink-to-dir is OK; symlink-to-file or dangling → nondir.
            fs::metadata(path).map(|m| !m.is_dir()).unwrap_or(true)
        }
        Ok(meta) => !meta.is_dir(),
        Err(_) => false,
    }
}

/// The nearest component of `path` (itself included) that exists but is not a
/// directory.
pub fn first_nondir_ancestor(path: &Path) -> Option<PathBuf> {
    let mut cursor = Some(path);
    while let Some(p) = cursor {
        if p.as_os_str().is_empty() {
            break;
        }
        if path_is_nondir(p) {
            return Some(p.to_path_buf());
        }
        cursor = p.parent();
    }
    None
}

/// Tip for a path whose ancestor is a file (`/etc/hostname/nope`). `exists()` is
/// false for such paths, so callers that report a missing path use this to
/// avoid masking ENOTDIR as NotFound.
pub fn path_component_not_dir_error(path: &Path) -> Option<Error> {
    first_nondir_ancestor(path).map(|blocker| {
        Error::Message(format!(
            "path component `{}` exists but is not a directory",
            blocker.display()
        ))
    })
}

/// True when `err` reports ENOTDIR, including platforms where the kind or raw
/// OS error does not round-trip.
pub fn is_not_a_directory(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotADirectory
        || err.raw_os_error() == Some(20)
        || err.to_string().contains("Not a directory")
}

/// When `err` is ENOTDIR, tip the first ancestor that exists as a non-directory.
pub fn diagnose_enotdir_component(path: &Path, err: std::io::Error) -> Error {
    if is_not_a_directory(&err) {
        if let Some(tip) = path_component_not_dir_error(path) {
            return tip;
        }
    }
    err.into()
}

fn diagnose_create_dir_as_dir(path: &Path, err: std::io::Error) -> Error {
    if path_is_nondir(path) {
        return Error::Message(format!(
            "cannot create directory `{}`: path exists but is not a directory (refusing to copy a directory onto a file)",
            path.display()
        ));
    }
    diagnose_create_dir_all(path, err)
}

fn diagnose_create_dir_all(path: &Path, err: std::io::Error) -> Error {
    let mut cursor = Some(path);
    while let Some(p) = cursor {
        if p.as_os_str().is_empty() {
            break;
        }
        if path_is_nondir(p) {
            return Error::Message(format!(
                "path component `{}` exists but is not a directory; cannot create parent directories for write/cp",
                p.display()
            ));
        }
        cursor = p.parent();
    }
    err.into()
}


pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir(parent)?;
        }
    }
    let tmp = path.with_extension("tmp");
    // The bytes are written only after the destination DACL/mode is set, so a
    // permissive inherited ACL cannot cover the secret even briefly.
    write_private_bytes(&tmp, bytes)?;
    replace_file(&tmp, path)?;
    restrict_file(path)?;
    Ok(())
}

#[cfg(not(windows))]
fn write_private_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    restrict_file(path)?;
    Ok(())
}

pub fn replace_file(tmp: &Path, dest: &Path) -> Result<()> {
    match fs::rename(tmp, dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Windows cannot rename over an existing file.
            let _ = fs::remove_file(dest);
            fs::rename(tmp, dest)?;
            Ok(())
        }
    }
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn restrict_dir(path: &Path) -> Result<()> {
    apply_private_acl(path)
}

#[cfg(not(any(unix, windows)))]
fn restrict_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn restrict_file(path: &Path) -> Result<()> {
    apply_private_acl(path)
}

#[cfg(not(any(unix, windows)))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

/// Who may read a secret directory. The Users group is never included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsAclScope {
    /// Current user and LOCAL SYSTEM. Used for per-user CLI and node files.
    User,
    /// LOCAL SYSTEM and Administrators. Used for the Windows service data dir.
    SystemService,
}

/// `ProgramData\agentlink` is the service tree. Everything else, including a
/// sibling such as `ProgramData\agentlink-other` and a profile directory, stays
/// user scope so the signed-in account can still open its own config.
pub fn windows_acl_scope(path: &Path, program_data: Option<&Path>) -> WindowsAclScope {
    let Some(root) = program_data else {
        return WindowsAclScope::User;
    };
    let base = root.join("agentlink");
    if windows_path_is_under(path, &base) {
        WindowsAclScope::SystemService
    } else {
        WindowsAclScope::User
    }
}

fn windows_path_key(path: &Path) -> String {
    let mut text = path.to_string_lossy().replace('/', "\\");
    if let Some(rest) = text.strip_prefix("\\\\?\\") {
        text = rest.to_string();
    }
    text.trim_end_matches('\\').to_ascii_lowercase()
}

fn windows_path_is_under(path: &Path, root: &Path) -> bool {
    let path = windows_path_key(path);
    let root = windows_path_key(root);
    if root.is_empty() {
        return false;
    }
    path == root || path.starts_with(&(root + "\\"))
}

/// Protected DACL (`D:P`) so a parent Users ACE is not inherited.
///
/// User scope names the caller's SID, not BU/WD/AU. Service scope is SYSTEM
/// and Administrators only.
pub fn windows_private_sddl(scope: WindowsAclScope, user_sid: &str) -> Result<String> {
    match scope {
        WindowsAclScope::SystemService => {
            Ok("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".to_string())
        }
        WindowsAclScope::User => {
            if !acceptable_user_sid(user_sid) {
                return Err(Error::Message(
                    "refusing a Windows ACL that would grant the Users group or omit the current user"
                        .into(),
                ));
            }
            Ok(format!("D:P(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)"))
        }
    }
}

fn acceptable_user_sid(sid: &str) -> bool {
    let sid = sid.trim();
    const BROAD: &[&str] = &[
        "S-1-1-0",      // Everyone
        "S-1-5-11",     // Authenticated Users
        "S-1-5-32-545", // BUILTIN\Users
        "WD",
        "BU",
        "AU",
    ];
    if BROAD.iter().any(|item| sid.eq_ignore_ascii_case(item)) {
        return false;
    }
    let Some(rest) = sid.strip_prefix("S-1-") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .chars()
            .all(|ch| ch.is_ascii_digit() || ch == '-')
        && rest.split('-').all(|part| !part.is_empty())
}

#[cfg(windows)]
fn apply_private_acl(path: &Path) -> Result<()> {
    let sddl = sddl_for_path(path)?;
    apply_sddl(path, &sddl)
}

#[cfg(windows)]
fn sddl_for_path(path: &Path) -> Result<String> {
    let program_data = std::env::var_os("ProgramData").map(std::path::PathBuf::from);
    let fallback = std::path::PathBuf::from(r"C:\ProgramData");
    let root = program_data.as_deref().unwrap_or(fallback.as_path());
    let scope = windows_acl_scope(path, Some(root));
    let sid = match scope {
        WindowsAclScope::User => current_user_sid()?,
        WindowsAclScope::SystemService => String::new(),
    };
    windows_private_sddl(scope, &sid)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn write_private_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{LocalFree, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let sddl = sddl_for_path(path)?;
    let sd = security_descriptor(&sddl)?;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let handle = unsafe {
        windows_sys::Win32::Storage::FileSystem::CreateFileW(
            wide.as_ptr(),
            0x4000_0000,
            0,
            &sa,
            2,
            0x80,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(sd as _);
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(Error::Message(format!(
            "could not create a private file at {}",
            path.display()
        )));
    }
    let mut file = unsafe { std::fs::File::from_raw_handle(handle as *mut std::ffi::c_void) };
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn security_descriptor(sddl: &str) -> Result<windows_sys::Win32::Security::PSECURITY_DESCRIPTOR> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;

    let wide: Vec<u16> = std::ffi::OsStr::new(sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || sd.is_null() {
        return Err(Error::Message(
            "could not build a private Windows ACL".into(),
        ));
    }
    Ok(sd)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn apply_sddl(path: &Path, sddl: &str) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let sd = security_descriptor(sddl)?;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let status = unsafe {
        SetFileSecurityW(
            wide.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        )
    };
    unsafe {
        LocalFree(sd as _);
    }
    if status == 0 {
        return Err(Error::Message(format!(
            "could not restrict permissions on {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn current_user_sid() -> Result<String> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 || token.is_null() {
        return Err(Error::Message(
            "could not read the current Windows user for the secret ACL".into(),
        ));
    }
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        unsafe { CloseHandle(token) };
        return Err(Error::Message(
            "could not read the current Windows user for the secret ACL".into(),
        ));
    }
    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(Error::Message(
            "could not read the current Windows user for the secret ACL".into(),
        ));
    }
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let mut sid_ptr = std::ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_ptr) };
    if converted == 0 || sid_ptr.is_null() {
        return Err(Error::Message(
            "could not read the current Windows user for the secret ACL".into(),
        ));
    }
    let mut len = 0usize;
    unsafe {
        while *sid_ptr.add(len) != 0 {
            len += 1;
        }
    }
    let text = unsafe { std::ffi::OsString::from_wide(std::slice::from_raw_parts(sid_ptr, len)) };
    unsafe { LocalFree(sid_ptr as _) };
    let sid = text.to_string_lossy().into_owned();
    if !acceptable_user_sid(&sid) {
        return Err(Error::Message(
            "refusing a Windows ACL that would grant the Users group or omit the current user"
                .into(),
        ));
    }
    Ok(sid)
}

pub fn auth_message(nonce: &str) -> Vec<u8> {
    format!("agentlink-auth-v1:{nonce}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_compare_matches_content() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
    }

    #[test]
    fn auth_message_is_domain_separated() {
        let msg = String::from_utf8(auth_message("ff")).unwrap();
        assert!(msg.starts_with("agentlink-auth-v1:"));
    }

    #[test]
    fn create_dir_all_parent_ok_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("a").join("b");
        create_dir_all_parent(&parent).unwrap();
        assert!(parent.is_dir());
    }

    #[test]
    fn create_dir_all_parent_file_component() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, b"not a dir").unwrap();
        let parent = blocker.join("nested");
        let err = create_dir_all_parent(&parent).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains("write/cp"), "{msg}");
        assert!(msg.contains(blocker.file_name().unwrap().to_str().unwrap()), "{msg}");
    }

    #[test]
    fn create_dir_all_parent_symlink_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"file").unwrap();
        let link = dir.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(not(unix))]
        {
            let _ = (target, link);
            return;
        }
        let parent = link.join("nested");
        let err = create_dir_all_parent(&parent).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
    }

    #[test]
    fn create_dir_all_as_dir_ok_missing_and_existing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("a").join("b");
        create_dir_all_as_dir(&missing).unwrap();
        assert!(missing.is_dir());
        create_dir_all_as_dir(&missing).unwrap();
    }

    #[test]
    fn create_dir_all_as_dir_refuses_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("destfile");
        fs::write(&file, b"keep-me").unwrap();
        let err = create_dir_all_as_dir(&file).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("refusing to copy a directory onto a file"), "{msg}");
        assert_eq!(fs::read_to_string(&file).unwrap(), "keep-me");
    }

    #[test]
    fn path_component_not_dir_error_finds_file_component() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hostname");
        fs::write(&file, b"box\n").unwrap();
        let child = file.join("nope");
        assert!(!child.exists());
        let tip = path_component_not_dir_error(&child)
            .expect("child of a file must yield a tip")
            .to_string();
        assert!(tip.contains("exists but is not a directory"), "{tip}");
        assert!(tip.contains(&file.display().to_string()), "{tip}");
        assert_eq!(first_nondir_ancestor(&child), Some(file.clone()));
    }

    #[test]
    fn path_component_not_dir_error_none_for_missing_and_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(path_component_not_dir_error(&dir.path().join("missing")).is_none());
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        assert!(path_component_not_dir_error(&sub.join("missing")).is_none());
    }

    #[test]
    fn is_not_a_directory_matches_kind_raw_and_message() {
        use std::io::ErrorKind;
        assert!(is_not_a_directory(&std::io::Error::new(
            ErrorKind::NotADirectory,
            "synthetic"
        )));
        assert!(is_not_a_directory(&std::io::Error::from_raw_os_error(20)));
        assert!(is_not_a_directory(&std::io::Error::new(
            ErrorKind::Other,
            "Not a directory (os error 20)"
        )));
        assert!(!is_not_a_directory(&std::io::Error::new(
            ErrorKind::NotFound,
            "No such file or directory"
        )));
    }

    #[test]
    fn diagnose_enotdir_component_names_blocker() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hostname");
        fs::write(&file, b"box\n").unwrap();
        let err = fs::read(file.join("nope")).unwrap_err();
        let msg = diagnose_enotdir_component(&file.join("nope"), err).to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains(&file.display().to_string()), "{msg}");
    }

    #[test]
    fn create_dir_all_as_dir_refuses_dangling_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("dangling");
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join("missing-target"), &link).unwrap();
        #[cfg(not(unix))]
        {
            let _ = link;
            return;
        }
        let err = create_dir_all_as_dir(&link).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains("refusing to copy a directory onto a file"), "{msg}");
    }

    #[test]
    fn windows_service_dir_is_not_the_user_profile() {
        let program_data = Path::new(r"C:\ProgramData");
        assert_eq!(
            windows_acl_scope(
                Path::new(r"C:\ProgramData\agentlink\node"),
                Some(program_data)
            ),
            WindowsAclScope::SystemService
        );
        assert_eq!(
            windows_acl_scope(
                Path::new(r"C:\ProgramData\agentlink"),
                Some(program_data)
            ),
            WindowsAclScope::SystemService
        );
        assert_eq!(
            windows_acl_scope(
                Path::new(r"C:\ProgramData\agentlink-other\node"),
                Some(program_data)
            ),
            WindowsAclScope::User
        );
        assert_eq!(
            windows_acl_scope(
                Path::new(r"C:\Users\alice\AppData\Roaming\agentlink"),
                Some(program_data)
            ),
            WindowsAclScope::User
        );
        assert_eq!(
            windows_acl_scope(Path::new(r"C:\ProgramData\agentlink\node"), None),
            WindowsAclScope::User
        );
    }

    #[test]
    fn windows_user_acl_keeps_the_caller_and_drops_users() {
        let user = windows_private_sddl(WindowsAclScope::User, "S-1-5-21-1-2-3-1001").unwrap();
        assert!(user.starts_with("D:P"), "{user}");
        assert!(user.contains("S-1-5-21-1-2-3-1001"), "{user}");
        assert!(user.contains(";;;SY"), "{user}");
        assert!(!user.contains(";;;BA"), "{user}");
        assert!(!user.contains(";;;BU"), "{user}");
        assert!(!user.contains(";;;WD"), "{user}");
        assert!(!user.contains(";;;AU"), "{user}");
        assert!(windows_private_sddl(WindowsAclScope::User, "S-1-1-0").is_err());
        assert!(windows_private_sddl(WindowsAclScope::User, "S-1-5-11").is_err());
        assert!(windows_private_sddl(WindowsAclScope::User, "S-1-5-32-545").is_err());
        assert!(windows_private_sddl(WindowsAclScope::User, "BU").is_err());
        let service = windows_private_sddl(WindowsAclScope::SystemService, "").unwrap();
        assert_eq!(service, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert!(!service.contains("BU"));
        assert!(!service.contains("WD"));
        assert!(!service.contains("AU"));
    }
}
