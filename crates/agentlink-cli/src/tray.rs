//! Windows notification-area app for the node.
//!
//! User-scope install writes `HKCU\...\Run` (or a Startup-folder script) so a
//! normal account can start the tray at sign-in. No scheduled task and no
//! administrator. The window reads `status.json` from the node data directory.
//!
//! On Windows the tray process is the user-scope node. The Run key must start
//! `tray --background` only. A second value that starts `agentlink node` for
//! the same data directory dials the relay twice; each hello replaces the
//! other socket, and the loser sees "Connection reset without closing handshake".

#![cfg_attr(not(windows), allow(dead_code))]

use std::ffi::OsString;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentlink_core::{config, parse_join_text, Client, ClientSettings, Identity, JoinText};
use agentlink_node::{save_node_config, write_status, LinkState, LinkStatus, NodeConfig};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::fmt::MakeWriter;

use crate::node_cfg::{self, NodeArgs};
use crate::{emit, version};

pub const RUN_VALUE_NAME: &str = "agentlink";
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Legacy Startup-folder batch script name. Still cleaned up on migration/uninstall;
/// production Startup-folder fallback writes [`STARTUP_SHORTCUT`] (`.lnk`) instead.
pub const STARTUP_SCRIPT: &str = "agentlink.cmd";
/// Safe Startup-folder shortcut fallback (no `cmd.exe` parsing, zero console flash).
pub const STARTUP_SHORTCUT: &str = "agentlink.lnk";

const NODE_LOCK_FILE: &str = "node.lock";
const TRAY_LOG_MAX_BYTES: u64 = 1024 * 1024;
static TRAY_LOG_INIT: OnceLock<()> = OnceLock::new();

/// `WM_APP` is `0x8000`. Posted to the tray window from a second process.
pub const TRAY_CALLBACK: u32 = 0x8000 + 1;
pub const TRAY_SHOW: u32 = 0x8000 + 2;
pub const TRAY_QUIT: u32 = 0x8000 + 3;
pub const TRAY_START: u32 = 0x8000 + 4;

#[derive(Clone, Debug)]
pub struct TrayContext {
    pub json: bool,
    pub relay: Option<String>,
    pub fingerprint: Option<String>,
    pub trust: Option<String>,
    pub config_dir: PathBuf,
    pub data_dir: Option<PathBuf>,
    pub name: Option<String>,
    pub background: bool,
    pub action: TrayAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayAction {
    Run,
    Install { dry_run: bool },
    Uninstall,
    Status,
}

#[derive(Clone, Debug)]
struct NodeLaunch {
    relay: Option<String>,
    fingerprint: Option<String>,
    trust: Option<String>,
    data_dir: PathBuf,
    name: Option<String>,
}

#[derive(Clone, Debug)]
struct NodeSnap {
    name: String,
    relay_url: String,
    pairing_pending: bool,
}

#[derive(Clone, Debug)]
struct AccountSnap {
    user: Option<String>,
    has_token: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusView {
    pub connection: String,
    pub relay: String,
    pub node_name: String,
    pub pairing: String,
    pub account: String,
    pub detail: String,
    pub running: bool,
    pub enrolled: bool,
}

pub fn dispatch(ctx: &TrayContext) -> Result<i32> {
    match ctx.action {
        TrayAction::Run => run_tray(ctx),
        TrayAction::Install { dry_run } => install_cmd(ctx, dry_run),
        TrayAction::Uninstall => uninstall_cmd(ctx),
        TrayAction::Status => status_cmd(ctx),
    }
}

fn run_tray(ctx: &TrayContext) -> Result<i32> {
    #[cfg(windows)]
    {
        match crate::tray_win::run(ctx) {
            Ok(code) => Ok(code),
            Err(err) => {
                crate::tray_win::report_error(&err.to_string());
                Err(err)
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = ctx;
        bail!(
            "the tray window ships in the Windows build. On this system run `agentlink node` or `agentlink service install`."
        );
    }
}

fn install_cmd(ctx: &TrayContext, dry_run: bool) -> Result<i32> {
    let data_dir = resolve_data_dir(ctx.data_dir.as_deref())?;
    let binary = current_binary()?;
    validate_autostart_path(&binary)?;
    validate_autostart_path(&data_dir)?;
    let plan = autostart_plan(&binary, &data_dir);
    if dry_run {
        emit(
            ctx.json,
            json!({
                "dry_run": true,
                "scope": "user",
                "autostart": "hkcu-run",
                "command": autostart_command(&binary, &data_dir),
                "data_dir": data_dir,
            }),
            || print!("{plan}"),
        );
        return Ok(0);
    }
    install_user_autostart(&binary, &data_dir)?;
    emit(
        ctx.json,
        json!({
            "ok": true,
            "scope": "user",
            "autostart": "hkcu-run",
            "data_dir": data_dir,
        }),
        || {
            eprintln!("start-on-login enabled for the current user (no administrator)");
            eprintln!("HKCU\\{RUN_KEY}");
            eprintln!("value {RUN_VALUE_NAME}");
        },
    );
    Ok(0)
}

fn uninstall_cmd(ctx: &TrayContext) -> Result<i32> {
    remove_user_autostart()?;
    emit(ctx.json, json!({"ok": true, "autostart": false}), || {
        eprintln!("start-on-login removed")
    });
    Ok(0)
}

fn status_cmd(ctx: &TrayContext) -> Result<i32> {
    let data_dir = resolve_data_dir(ctx.data_dir.as_deref())?;
    let view = load_view(&data_dir, &ctx.config_dir);
    let autostart = autostart_enabled();
    emit(ctx.json, status_json(&view, autostart, &data_dir), || {
        println!("connection: {}", view.connection);
        println!("relay: {}", view.relay);
        println!("node: {}", view.node_name);
        println!("pairing: {}", view.pairing);
        println!("account: {}", view.account);
        println!("autostart: {}", if autostart { "on" } else { "off" });
        println!("running: {}", if view.running { "yes" } else { "no" });
        if !view.detail.is_empty() {
            println!("detail: {}", view.detail);
        }
    });
    Ok(0)
}

pub fn status_json(view: &StatusView, autostart: bool, data_dir: &Path) -> Value {
    json!({
        "connection": view.connection,
        "relay": view.relay,
        "node": view.node_name,
        "pairing": view.pairing,
        "account": view.account,
        "detail": view.detail,
        "autostart": autostart,
        "running": view.running,
        "enrolled": view.enrolled,
        "data_dir": data_dir,
    })
}

pub fn load_view(data_dir: &Path, config_dir: &Path) -> StatusView {
    let link = agentlink_node::read_status(data_dir).ok();
    let alive = link
        .as_ref()
        .is_some_and(|status| status.pid != 0 && pid_alive(status.pid));
    describe(
        link.as_ref(),
        &read_node(data_dir),
        &read_account(config_dir),
        alive,
    )
}

fn describe(
    link: Option<&LinkStatus>,
    node: &NodeSnap,
    account: &AccountSnap,
    pid_alive: bool,
) -> StatusView {
    let enrolled = link.is_some_and(|status| status.enrolled);
    let process_up = pid_alive && link.is_some_and(|status| status.state != LinkState::Stopped);
    let connection = match link {
        Some(status) if process_up => status.state.label().to_string(),
        _ => "Stopped".to_string(),
    };
    let relay = link
        .map(|status| status.relay_url.trim())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let value = node.relay_url.trim();
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        })
        .unwrap_or("relay not set")
        .to_string();
    let node_name = link
        .map(|status| status.name.trim())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let value = node.name.trim();
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        })
        .unwrap_or("this computer")
        .to_string();
    let pairing = if node.pairing_pending {
        "Pairing pending"
    } else if enrolled {
        "Paired"
    } else {
        "Not paired"
    };
    let account_line = if let Some(user) = account.user.as_deref().filter(|user| !user.is_empty()) {
        format!("Signed in as {user}")
    } else if account.has_token {
        "Legacy token saved".to_string()
    } else if enrolled {
        // Node enroll/pairing is enough for agents; account sign-in is optional
        // (Android usually signs in then enrolls; Windows tray often pairs alone).
        "Paired without account sign-in".to_string()
    } else {
        "Not signed in".to_string()
    };
    let link_detail = link
        .map(|status| status.detail.trim().to_string())
        .unwrap_or_default();
    // Soft-prompt: nudge Sign in when the node is paired but there is no account
    // session (share/devices). Keep node-link detail when the relay already set one.
    let detail = if !link_detail.is_empty() {
        link_detail
    } else if enrolled
        && account.user.as_deref().filter(|u| !u.is_empty()).is_none()
        && !account.has_token
    {
        "Sign in to manage shares and devices from this PC.".to_string()
    } else {
        String::new()
    };
    StatusView {
        connection,
        relay,
        node_name,
        pairing: pairing.to_string(),
        account: account_line,
        detail,
        running: process_up,
        enrolled,
    }
}

fn read_node(data_dir: &Path) -> NodeSnap {
    let value = std::fs::read_to_string(data_dir.join("node.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .unwrap_or(Value::Null);
    let text = |key: &str| {
        value
            .get(key)
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    NodeSnap {
        name: text("name"),
        relay_url: text("relay_url"),
        pairing_pending: value
            .get("pairing_token")
            .and_then(|item| item.as_str())
            .is_some_and(|token| !token.trim().is_empty()),
    }
}

fn read_account(config_dir: &Path) -> AccountSnap {
    let file = config::load_file(config_dir).unwrap_or_default();
    AccountSnap {
        user: file.user.filter(|user| !user.trim().is_empty()),
        has_token: file
            .token
            .as_deref()
            .is_some_and(|token| !token.trim().is_empty())
            || file
                .refresh_token
                .as_deref()
                .is_some_and(|token| !token.trim().is_empty()),
    }
}

pub fn resolve_data_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = installed_data_dir() {
        return Ok(path);
    }
    config::default_data_dir("node").map_err(|err| anyhow!(err.to_string()))
}

pub fn resolve_config_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    config::default_config_dir().map_err(|err| anyhow!(err.to_string()))
}

/// Reject control characters (`\r`, `\n`, `\0`) in paths written into autostart
/// commands, registry values, or shortcuts.
pub fn validate_autostart_path(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    if text.chars().any(|ch| matches!(ch, '\r' | '\n' | '\0')) {
        bail!("autostart path contains forbidden control characters (CR, LF, or NUL)");
    }
    Ok(())
}

/// Prefer a sibling GUI-subsystem `agentlink-gui.exe` when it exists on disk
/// beside `binary` (eliminating console flashes on Windows). Synthetic paths
/// where no sibling `agentlink-gui.exe` exists are returned unchanged.
pub fn preferred_gui_binary(binary: &Path) -> PathBuf {
    if exe_is_agentlink(&binary.to_string_lossy()) {
        let sibling = binary.with_file_name("agentlink-gui.exe");
        if sibling.is_file() {
            return sibling;
        }
    }
    binary.to_path_buf()
}

/// Arguments for launching the Controller window from the tray with matching
/// `--config-dir` and `--data-dir`.
pub fn controller_launch_args(config_dir: &Path, data_dir: &Path) -> Vec<OsString> {
    vec![
        OsString::from("--config-dir"),
        config_dir.as_os_str().to_os_string(),
        OsString::from("controller"),
        OsString::from("--data-dir"),
        data_dir.as_os_str().to_os_string(),
    ]
}

fn normalize_windows_path_key(path: &Path) -> String {
    let stripped = strip_verbatim(path);
    stripped
        .to_string_lossy()
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

/// Stable 16-hex-char hash of a normalized `data_dir`, used to key single-instance
/// tray mutexes and window classes independently per data directory.
pub fn data_dir_instance_tag(data_dir: &Path) -> String {
    let key = normalize_windows_path_key(data_dir);
    let digest = Sha256::digest(key.as_bytes());
    hex::encode(&digest[..8])
}

/// Single-instance named mutex for the Windows tray scoped to `data_dir`.
pub fn tray_mutex_name(data_dir: &Path) -> String {
    format!("Local\\agentlink-tray-{}", data_dir_instance_tag(data_dir))
}

/// Per-`data_dir` Win32 window class name for the tray status window.
pub fn tray_window_class(data_dir: &Path) -> String {
    format!("AgentlinkTray-{}", data_dir_instance_tag(data_dir))
}

/// Command line stored in HKCU Run. The executable and data directory are quoted.
pub fn autostart_command(binary: &Path, data_dir: &Path) -> String {
    let exe = preferred_gui_binary(binary);
    format!(
        "{} tray --background --data-dir {}",
        quote_windows_arg(&exe.to_string_lossy()),
        quote_windows_arg(&data_dir.to_string_lossy()),
    )
}

/// Validated variant of [`autostart_command`] that rejects control characters.
pub fn try_autostart_command(binary: &Path, data_dir: &Path) -> Result<String> {
    validate_autostart_path(binary)?;
    validate_autostart_path(data_dir)?;
    Ok(autostart_command(binary, data_dir))
}

pub fn autostart_plan(binary: &Path, data_dir: &Path) -> String {
    format!(
        "\
# User-scope autostart. No administrator and no scheduled task.
# HKCU\\{RUN_KEY}
# Value name: {RUN_VALUE_NAME}
# The tray starts at sign-in and runs the node in this session.
{}
# If that registry value cannot be written, a Windows shortcut is saved as
# %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{STARTUP_SHORTCUT}
",
        autostart_command(binary, data_dir),
    )
}

/// Quote one argument using Win32 `CommandLineToArgvW` / MSVCRT rules.
///
/// Backslashes immediately preceding an embedded `"` are doubled plus one extra
/// backslash to escape the quote; trailing backslashes are doubled so they do
/// not escape the closing `"`.
pub fn quote_windows_arg(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in text.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(ch);
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Parse a Windows command line symmetrically with [`quote_windows_arg`] using
/// `CommandLineToArgvW` / MSVCRT backslash-before-quote rules.
pub fn split_windows_command(command: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut has_token = false;
    let mut in_quotes = false;
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ' ' | '\t' if !in_quotes => {
                if has_token {
                    args.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            '\\' => {
                has_token = true;
                let mut count = 1usize;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    count += 1;
                }
                if chars.peek() == Some(&'"') {
                    for _ in 0..(count / 2) {
                        current.push('\\');
                    }
                    if count % 2 == 1 {
                        chars.next();
                        current.push('"');
                    } else {
                        chars.next();
                        if in_quotes && chars.peek() == Some(&'"') {
                            chars.next();
                            current.push('"');
                        } else {
                            in_quotes = !in_quotes;
                        }
                    }
                } else {
                    for _ in 0..count {
                        current.push('\\');
                    }
                }
            }
            '"' => {
                has_token = true;
                if in_quotes && chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = !in_quotes;
                }
            }
            _ => {
                has_token = true;
                current.push(ch);
            }
        }
    }
    if has_token {
        args.push(current);
    }
    args
}

pub fn data_dir_from_command(command: &str) -> Option<PathBuf> {
    let args = split_windows_command(command);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--data-dir" {
            return iter.next().map(PathBuf::from);
        }
        if let Some(rest) = arg.strip_prefix("--data-dir=") {
            if !rest.is_empty() {
                return Some(PathBuf::from(rest));
            }
        }
    }
    None
}

/// Retained for legacy compatibility/tests. Production Startup-folder fallback
/// writes a safe `.lnk` shortcut via [`build_windows_lnk`] instead of `.cmd`.
pub fn startup_script_contents(binary: &Path, data_dir: &Path) -> String {
    format!(
        "@echo off\r\nstart \"\" {}\r\n",
        autostart_command(binary, data_dir)
    )
}

const LNK_HEADER_SIZE: u32 = 0x0000_004C;
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const LNK_FLAG_HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;
const LNK_FLAG_HAS_LINK_INFO: u32 = 0x0000_0002;
const LNK_FLAG_HAS_NAME: u32 = 0x0000_0004;
const LNK_FLAG_HAS_RELATIVE_PATH: u32 = 0x0000_0008;
const LNK_FLAG_HAS_WORKING_DIR: u32 = 0x0000_0010;
const LNK_FLAG_HAS_ARGUMENTS: u32 = 0x0000_0020;
const LNK_FLAG_HAS_ICON_LOCATION: u32 = 0x0000_0040;
const LNK_FLAG_IS_UNICODE: u32 = 0x0000_0080;
const LNK_FLAG_HAS_EXP_STRING: u32 = 0x0000_0200;
const LNK_EXP_ENV_SIG: u32 = 0xA000_0001;
const LNK_EXP_ENV_SIZE: u32 = 0x0000_0314;

/// My Computer root shell item (CLSID `{20D04FE0-3AEA-1069-A2D8-08002B30309D}`).
const MY_COMPUTER_ITEM: [u8; 20] = [
    0x14, 0x00, 0x1F, 0x50, 0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00,
    0x2B, 0x30, 0x30, 0x9D,
];

fn lnk_file_shell_item(name: &str, is_dir: bool) -> Result<Vec<u8>> {
    let mut item = Vec::new();
    item.extend_from_slice(&0u16.to_le_bytes()); // total size placeholder
    item.push(if is_dir { 0x31 } else { 0x32 });
    item.push(0x00);
    item.extend_from_slice(&0u32.to_le_bytes()); // file size
    item.extend_from_slice(&0u16.to_le_bytes()); // mod date
    item.extend_from_slice(&0u16.to_le_bytes()); // mod time
    item.extend_from_slice(&(if is_dir { 0x0010u16 } else { 0x0020u16 }).to_le_bytes()); // file attrs
    for ch in name.chars() {
        let byte = if ch.is_ascii() && (0x20..0x7F).contains(&(ch as u32)) {
            ch as u8
        } else {
            b'_'
        };
        item.push(byte);
    }
    item.push(0);
    if item.len() % 2 != 0 {
        item.push(0);
    }
    let ext_offset = u16::try_from(item.len())
        .map_err(|_| anyhow!("shortcut path component is too long"))?;

    // Windows Vista/10/11 BEEF0004 v9 extension block carrying exact UTF-16LE name.
    let mut uni_bytes = Vec::with_capacity((name.len() + 1) * 2);
    for unit in name.encode_utf16().chain(std::iter::once(0)) {
        uni_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let ext_size = u16::try_from(46 + uni_bytes.len() + 2)
        .map_err(|_| anyhow!("shortcut Unicode component is too long"))?;
    item.extend_from_slice(&ext_size.to_le_bytes());
    item.extend_from_slice(&0x0009u16.to_le_bytes()); // version 9
    item.extend_from_slice(&0xBEEF_0004u32.to_le_bytes());
    item.extend_from_slice(&0u32.to_le_bytes()); // create date/time
    item.extend_from_slice(&0u32.to_le_bytes()); // access date/time
    item.extend_from_slice(&0x0000_002Eu32.to_le_bytes()); // v9 header size (46)
    item.extend_from_slice(&[0u8; 26]); // MFT ref & reserved v9 fields
    item.extend_from_slice(&uni_bytes);
    item.extend_from_slice(&ext_offset.to_le_bytes());

    let total = u16::try_from(item.len())
        .map_err(|_| anyhow!("shortcut shell item exceeds 64 KiB"))?;
    item[0..2].copy_from_slice(&total.to_le_bytes());
    Ok(item)
}

fn build_drive_id_list(target_win: &str) -> Result<Option<Vec<u8>>> {
    let bytes = target_win.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Ok(None);
    }
    let drive = bytes[0].to_ascii_uppercase();
    let components: Vec<&str> = target_win[3..]
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect();
    if components.is_empty() {
        return Ok(None);
    }
    let mut id_list = Vec::new();
    id_list.extend_from_slice(&MY_COMPUTER_ITEM);
    let mut drive_item = [0u8; 25];
    drive_item[0] = 0x19;
    drive_item[2] = 0x2F;
    drive_item[3] = drive;
    drive_item[4] = b':';
    drive_item[5] = b'\\';
    id_list.extend_from_slice(&drive_item);
    for (idx, part) in components.iter().enumerate() {
        let is_dir = idx + 1 < components.len();
        id_list.extend_from_slice(&lnk_file_shell_item(part, is_dir)?);
    }
    id_list.extend_from_slice(&0u16.to_le_bytes()); // terminal ID
    Ok(Some(id_list))
}

fn push_lnk_unicode_string(out: &mut Vec<u8>, text: &str) -> Result<()> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let count = u16::try_from(units.len())
        .map_err(|_| anyhow!("shortcut string exceeds 65535 UTF-16 code units"))?;
    out.extend_from_slice(&count.to_le_bytes());
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

/// Build a Windows Shell Link (`.lnk`, MS-SHLLINK) binary launching the tray in
/// background mode with zero `cmd.exe` parsing and zero console flash.
pub fn build_windows_lnk(binary: &Path, data_dir: &Path) -> Result<Vec<u8>> {
    validate_autostart_path(binary)?;
    validate_autostart_path(data_dir)?;

    let target_path = strip_verbatim(&preferred_gui_binary(binary));
    let target_win = target_path.to_string_lossy().replace('/', "\\");
    let workdir_win = target_path
        .parent()
        .map(|parent| parent.to_string_lossy().replace('/', "\\"))
        .unwrap_or_default();
    let args = format!(
        "tray --background --data-dir {}",
        quote_windows_arg(&data_dir.to_string_lossy()),
    );
    let desc = "agentlink";
    let id_list = build_drive_id_list(&target_win)?;

    let mut flags = LNK_FLAG_HAS_NAME
        | LNK_FLAG_HAS_ARGUMENTS
        | LNK_FLAG_HAS_ICON_LOCATION
        | LNK_FLAG_IS_UNICODE;
    if !workdir_win.is_empty() {
        flags |= LNK_FLAG_HAS_WORKING_DIR;
    }
    if id_list.is_some() {
        flags |= LNK_FLAG_HAS_LINK_TARGET_ID_LIST;
    } else {
        flags |= LNK_FLAG_HAS_EXP_STRING;
    }

    let mut out = Vec::with_capacity(512);
    // ShellLinkHeader (76 bytes)
    out.extend_from_slice(&LNK_HEADER_SIZE.to_le_bytes());
    out.extend_from_slice(&LNK_CLSID);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0x0000_0020u32.to_le_bytes()); // FILE_ATTRIBUTE_ARCHIVE
    out.extend_from_slice(&0u64.to_le_bytes()); // CreationTime
    out.extend_from_slice(&0u64.to_le_bytes()); // AccessTime
    out.extend_from_slice(&0u64.to_le_bytes()); // WriteTime
    out.extend_from_slice(&0u32.to_le_bytes()); // FileSize
    out.extend_from_slice(&0i32.to_le_bytes()); // IconIndex
    out.extend_from_slice(&1u32.to_le_bytes()); // ShowCommand = SW_SHOWNORMAL
    out.extend_from_slice(&0u16.to_le_bytes()); // HotKey
    out.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
    debug_assert_eq!(out.len(), LNK_HEADER_SIZE as usize);

    if let Some(id_list) = id_list {
        let id_len = u16::try_from(id_list.len())
            .map_err(|_| anyhow!("shortcut IDList exceeds 64 KiB"))?;
        out.extend_from_slice(&id_len.to_le_bytes());
        out.extend_from_slice(&id_list);
    }

    // StringData (MS-SHLLINK §2.4 order: Name, WorkingDir, Arguments, IconLocation)
    push_lnk_unicode_string(&mut out, desc)?;
    if !workdir_win.is_empty() {
        push_lnk_unicode_string(&mut out, &workdir_win)?;
    }
    push_lnk_unicode_string(&mut out, &args)?;
    push_lnk_unicode_string(&mut out, &target_win)?;

    // ExtraData: fallback EnvironmentVariableDataBlock for non-drive/UNC paths.
    if flags & LNK_FLAG_HAS_EXP_STRING != 0 {
        out.extend_from_slice(&LNK_EXP_ENV_SIZE.to_le_bytes());
        out.extend_from_slice(&LNK_EXP_ENV_SIG.to_le_bytes());
        let mut ansi_buf = [0u8; 260];
        for (slot, ch) in ansi_buf.iter_mut().take(259).zip(target_win.chars()) {
            *slot = if ch.is_ascii() { ch as u8 } else { b'?' };
        }
        out.extend_from_slice(&ansi_buf);
        let mut uni_buf = [0u8; 520];
        for (i, unit) in target_win.encode_utf16().take(259).enumerate() {
            let le = unit.to_le_bytes();
            uni_buf[i * 2] = le[0];
            uni_buf[i * 2 + 1] = le[1];
        }
        out.extend_from_slice(&uni_buf);
    }

    // ExtraData TerminalBlock
    out.extend_from_slice(&0u32.to_le_bytes());
    Ok(out)
}

fn parse_lnk_id_list(data: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    let mut drive: Option<String> = None;
    let mut parts: Vec<String> = Vec::new();
    while pos + 2 <= data.len() {
        let size = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        if size == 0 {
            break;
        }
        if size < 3 || pos + size > data.len() {
            return None;
        }
        let item = &data[pos..pos + size];
        let kind = item[2];
        if (kind & 0x70) == 0x20 && item.len() >= 6 && item[4] == b':' {
            // Drive item (e.g. "C:\")
            let raw = &item[3..];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let text = String::from_utf8_lossy(&raw[..end]).to_string();
            if !text.is_empty() {
                drive = Some(text);
            }
        } else if matches!(kind & 0x70, 0x30) && item.len() >= 15 {
            // File/directory shell item; prefer BEEF0004 Unicode extension block.
            let mut extracted: Option<String> = None;
            if item.len() >= 2 {
                let ext_off = u16::from_le_bytes([item[item.len() - 2], item[item.len() - 1]])
                    as usize;
                if ext_off >= 14 && ext_off + 8 <= item.len() - 2 {
                    let ext = &item[ext_off..item.len() - 2];
                    let ext_ver = u16::from_le_bytes([ext[2], ext[3]]);
                    let sig = u32::from_le_bytes([ext[4], ext[5], ext[6], ext[7]]);
                    if sig == 0xBEEF_0004 {
                        let name_off = match ext_ver {
                            v if v >= 9 => 46,
                            v if v >= 8 => 42,
                            v if v >= 7 => 38,
                            _ => 20,
                        };
                        if name_off < ext.len() {
                            let words: Vec<u16> = ext[name_off..]
                                .chunks_exact(2)
                                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                                .take_while(|&u| u != 0)
                                .collect();
                            if !words.is_empty() {
                                extracted = Some(String::from_utf16_lossy(&words));
                            }
                        }
                    }
                }
            }
            if extracted.is_none() {
                let raw = &item[14..];
                let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                if end > 0 {
                    extracted = Some(String::from_utf8_lossy(&raw[..end]).to_string());
                }
            }
            if let Some(part) = extracted {
                parts.push(part);
            }
        }
        pos += size;
    }
    let drive = drive?;
    if parts.is_empty() {
        return None;
    }
    let mut path = drive;
    if !path.ends_with('\\') {
        path.push('\\');
    }
    path.push_str(&parts.join("\\"));
    Some(path)
}

fn read_lnk_string(bytes: &[u8], pos: &mut usize, unicode: bool) -> Option<String> {
    if *pos + 2 > bytes.len() {
        return None;
    }
    let count = u16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]) as usize;
    *pos += 2;
    if unicode {
        let byte_len = count.checked_mul(2)?;
        if *pos + byte_len > bytes.len() {
            return None;
        }
        let words: Vec<u16> = bytes[*pos..*pos + byte_len]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        *pos += byte_len;
        Some(String::from_utf16_lossy(&words))
    } else {
        if *pos + count > bytes.len() {
            return None;
        }
        let text = String::from_utf8_lossy(&bytes[*pos..*pos + count]).to_string();
        *pos += count;
        Some(text)
    }
}

/// Extract the equivalent command line (`"<target>" <arguments>`) from an
/// MS-SHLLINK `.lnk` file.
pub fn parse_windows_lnk_command(bytes: &[u8]) -> Option<String> {
    if bytes.len() < LNK_HEADER_SIZE as usize {
        return None;
    }
    let header_size = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if header_size != LNK_HEADER_SIZE || bytes[4..20] != LNK_CLSID {
        return None;
    }
    let flags = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
    let unicode = flags & LNK_FLAG_IS_UNICODE != 0;
    let mut pos = LNK_HEADER_SIZE as usize;

    let mut target: Option<String> = None;
    if flags & LNK_FLAG_HAS_LINK_TARGET_ID_LIST != 0 {
        if pos + 2 > bytes.len() {
            return None;
        }
        let id_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if pos + id_len > bytes.len() {
            return None;
        }
        target = parse_lnk_id_list(&bytes[pos..pos + id_len]);
        pos += id_len;
    }

    if flags & LNK_FLAG_HAS_LINK_INFO != 0 {
        if pos + 4 > bytes.len() {
            return None;
        }
        let info_size = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        if info_size < 4 || pos + info_size > bytes.len() {
            return None;
        }
        if target.is_none() && info_size >= 28 {
            let info = &bytes[pos..pos + info_size];
            let hdr_size = u32::from_le_bytes(info[4..8].try_into().ok()?) as usize;
            let li_flags = u32::from_le_bytes(info[8..12].try_into().ok()?);
            if li_flags & 1 != 0 {
                if hdr_size >= 0x24 && info.len() >= 32 {
                    let uni_off = u32::from_le_bytes(info[28..32].try_into().ok()?) as usize;
                    if uni_off < info.len() {
                        let words: Vec<u16> = info[uni_off..]
                            .chunks_exact(2)
                            .map(|p| u16::from_le_bytes([p[0], p[1]]))
                            .take_while(|&u| u != 0)
                            .collect();
                        if !words.is_empty() {
                            target = Some(String::from_utf16_lossy(&words));
                        }
                    }
                }
                if target.is_none() {
                    let local_off = u32::from_le_bytes(info[16..20].try_into().ok()?) as usize;
                    if local_off < info.len() {
                        let end = info[local_off..]
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(info.len() - local_off);
                        if end > 0 {
                            target = Some(
                                String::from_utf8_lossy(&info[local_off..local_off + end])
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        }
        pos += info_size;
    }

    let mut arguments = String::new();
    if flags & LNK_FLAG_HAS_NAME != 0 {
        let _ = read_lnk_string(bytes, &mut pos, unicode)?;
    }
    if flags & LNK_FLAG_HAS_RELATIVE_PATH != 0 {
        let _ = read_lnk_string(bytes, &mut pos, unicode)?;
    }
    if flags & LNK_FLAG_HAS_WORKING_DIR != 0 {
        let _ = read_lnk_string(bytes, &mut pos, unicode)?;
    }
    if flags & LNK_FLAG_HAS_ARGUMENTS != 0 {
        arguments = read_lnk_string(bytes, &mut pos, unicode)?;
    }
    if flags & LNK_FLAG_HAS_ICON_LOCATION != 0 {
        let icon = read_lnk_string(bytes, &mut pos, unicode)?;
        if target.is_none() && !icon.trim().is_empty() {
            // Keep parsing ExtraData first; icon is only last-resort fallback.
            let _ = icon;
        }
    }

    // Parse ExtraData blocks for EnvironmentVariableDataBlock if target not yet found.
    while pos + 4 <= bytes.len() {
        let block_size = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        if block_size < 4 || pos + block_size > bytes.len() {
            break;
        }
        if block_size >= 8 {
            let sig = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().ok()?);
            if sig == LNK_EXP_ENV_SIG && block_size >= LNK_EXP_ENV_SIZE as usize && target.is_none()
            {
                let uni_slice = &bytes[pos + 8 + 260..pos + 8 + 260 + 520];
                let words: Vec<u16> = uni_slice
                    .chunks_exact(2)
                    .map(|p| u16::from_le_bytes([p[0], p[1]]))
                    .take_while(|&u| u != 0)
                    .collect();
                if !words.is_empty() {
                    target = Some(String::from_utf16_lossy(&words));
                }
            }
        }
        pos += block_size;
    }

    let target = target.filter(|t| !t.trim().is_empty())?;
    let args = arguments.trim();
    if args.is_empty() {
        Some(quote_windows_arg(&target))
    } else {
        Some(format!("{} {args}", quote_windows_arg(&target)))
    }
}

/// One `HKCU\...\Run` value, or a Startup-folder entry treated as a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunValue {
    pub name: String,
    pub command: String,
}

/// Registry edits that leave a single tray launcher for one data directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutostartMigration {
    /// Command to store under [`RUN_VALUE_NAME`]. `None` leaves that value alone.
    pub write_command: Option<String>,
    /// Other Run value names to delete. [`STARTUP_SHORTCUT`] / [`STARTUP_SCRIPT`] remove those files.
    pub delete_names: Vec<String>,
}

const GLOBAL_FLAGS_WITH_VALUES: &[&str] = &[
    "--relay",
    "--token",
    "--fingerprint",
    "--trust",
    "--ca",
    "--config-dir",
    "--identity",
];

/// Compare Windows paths without requiring them to exist.
pub fn windows_paths_equal(left: &Path, right: &Path) -> bool {
    let left = normalize_windows_path_key(left);
    !left.is_empty() && left == normalize_windows_path_key(right)
}

fn exe_is_agentlink(arg: &str) -> bool {
    let file = arg.rsplit(['\\', '/']).next().unwrap_or(arg);
    let file = file.trim_matches('"');
    let lower = file.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    matches!(stem, "agentlink" | "agentlink-gui")
}

/// First positional argument after the executable and global flags.
pub fn agentlink_subcommand(command: &str) -> Option<String> {
    let args = split_windows_command(command);
    let exe = args.first()?;
    if !exe_is_agentlink(exe) {
        return None;
    }
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            return args.get(index + 1).cloned();
        }
        if let Some((flag, _)) = arg.split_once('=') {
            if flag.starts_with("--") {
                index += 1;
                continue;
            }
        }
        if GLOBAL_FLAGS_WITH_VALUES.iter().any(|flag| arg == flag) {
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(arg.clone());
    }
    None
}

fn data_dir_matches(command: &str, data_dir: &Path, missing_dir_matches: bool) -> bool {
    match data_dir_from_command(command) {
        Some(dir) => windows_paths_equal(&dir, data_dir),
        None => missing_dir_matches,
    }
}

/// `agentlink node` for this data directory. `tray` and `service run` are not.
pub fn command_is_standalone_node(
    command: &str,
    data_dir: &Path,
    missing_dir_matches: bool,
) -> bool {
    agentlink_subcommand(command).as_deref() == Some("node")
        && data_dir_matches(command, data_dir, missing_dir_matches)
}

/// The sign-in tray (`agentlink tray` / `tray --background`), not status or install.
pub fn command_launches_tray(command: &str, data_dir: &Path, missing_dir_matches: bool) -> bool {
    if agentlink_subcommand(command).as_deref() != Some("tray") {
        return false;
    }
    if !data_dir_matches(command, data_dir, missing_dir_matches) {
        return false;
    }
    let args = split_windows_command(command);
    let Some(pos) = args.iter().position(|arg| arg == "tray") else {
        return false;
    };
    let valued = ["--data-dir", "--name"];
    let mut index = pos + 1;
    while index < args.len() {
        let arg = &args[index];
        if let Some((flag, _)) = arg.split_once('=') {
            if flag == "--data-dir" || flag == "--name" {
                index += 1;
                continue;
            }
        }
        if valued.iter().any(|flag| arg == flag) {
            index += 2;
            continue;
        }
        if arg == "--background" || arg.starts_with('-') {
            index += 1;
            continue;
        }
        return false;
    }
    true
}

/// How a new tray process should behave.
///
/// Sign-in runs `tray --background`. That process is the user-scope node: it
/// dials even when nobody clicks Start. A second sign-in launch, while the
/// window is already open, asks that window to dial instead of exiting quietly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayLaunch {
    /// This process owns the window. `connect` dials without a Start click.
    Run { connect: bool },
    /// Another tray already owns the window. Post this message to it.
    Signal { message: u32 },
}

pub fn tray_launch(background: bool, already_running: bool) -> TrayLaunch {
    if already_running {
        TrayLaunch::Signal {
            message: if background { TRAY_START } else { TRAY_SHOW },
        }
    } else {
        TrayLaunch::Run {
            connect: background,
        }
    }
}

/// Status line while the embedded node is starting, stopped, or live.
///
/// A fresh sign-in can still see the previous process in `status.json`. The
/// window must not sit on Stopped once this process has started the node.
pub fn apply_supervisor_view(
    mut view: StatusView,
    running: bool,
    stop_requested: bool,
    restarting: bool,
    last_exit: Option<&str>,
) -> StatusView {
    if restarting {
        view.connection = "Connecting".into();
        view.running = true;
        if view.detail.is_empty() {
            view.detail = "Reconnecting…".into();
        }
    } else if stop_requested || !running {
        view.connection = "Stopped".into();
        view.running = false;
        if view.detail.is_empty() {
            if let Some(err) = last_exit.filter(|err| !err.is_empty()) {
                view.detail = err.to_string();
            }
        }
    } else if !view.running || view.connection == "Stopped" {
        view.connection = "Connecting".into();
        view.running = true;
        if view.detail.is_empty() {
            view.detail = "Connecting…".into();
        }
    }
    view
}

/// True when a tray launcher for this data directory is already registered.
///
/// The standalone `node` process must not dial in that case. The relay keeps
/// one socket per node id and drops the previous one without a close frame.
pub fn tray_autostart_blocks_node(
    entries: &[RunValue],
    data_dir: &Path,
    missing_dir_matches: bool,
) -> bool {
    entries
        .iter()
        .any(|entry| command_launches_tray(&entry.command, data_dir, missing_dir_matches))
}

/// Plan the Run-key edit for "Start when I sign in".
///
/// `install` always writes the tray command. A later tray launch (`install` is
/// false) rewrites the canonical value when it still starts `node`, and deletes
/// any other value that starts `node` for the same data directory. Unrelated
/// Run values are left alone. A node entry for a different directory is left
/// alone.
fn is_startup_folder_entry(name: &str) -> bool {
    name == STARTUP_SCRIPT || name == STARTUP_SHORTCUT
}

pub fn plan_run_migration(
    entries: &[RunValue],
    binary: &Path,
    data_dir: &Path,
    missing_dir_matches: bool,
    install: bool,
) -> AutostartMigration {
    let desired = autostart_command(binary, data_dir);
    let canonical = entries
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(RUN_VALUE_NAME));
    let owns = install
        || entries.iter().any(|entry| {
            command_launches_tray(&entry.command, data_dir, missing_dir_matches)
                || (entry.name.eq_ignore_ascii_case(RUN_VALUE_NAME)
                    && command_is_standalone_node(&entry.command, data_dir, missing_dir_matches))
        });
    if !owns {
        return AutostartMigration {
            write_command: None,
            delete_names: Vec::new(),
        };
    }

    let write_command = if install {
        Some(desired.clone())
    } else if let Some(canonical) = canonical {
        let is_node = command_is_standalone_node(&canonical.command, data_dir, missing_dir_matches);
        let is_tray = command_launches_tray(&canonical.command, data_dir, missing_dir_matches);
        if canonical.command.trim() == desired {
            None
        } else if is_node || is_tray {
            Some(desired.clone())
        } else {
            None
        }
    } else {
        None
    };

    let hkcu_tray = write_command.is_some()
        || entries.iter().any(|entry| {
            !is_startup_folder_entry(&entry.name)
                && command_launches_tray(&entry.command, data_dir, missing_dir_matches)
                && (write_command.is_none() || !entry.name.eq_ignore_ascii_case(RUN_VALUE_NAME))
        });

    let shortcut_tray = entries.iter().any(|entry| {
        entry.name == STARTUP_SHORTCUT
            && command_launches_tray(&entry.command, data_dir, missing_dir_matches)
    });

    let mut delete_names = Vec::new();
    for entry in entries {
        if entry.name.eq_ignore_ascii_case(RUN_VALUE_NAME) {
            continue;
        }
        if entry.name == STARTUP_SCRIPT {
            if (hkcu_tray || shortcut_tray)
                && (command_is_standalone_node(&entry.command, data_dir, missing_dir_matches)
                    || command_launches_tray(&entry.command, data_dir, missing_dir_matches))
            {
                delete_names.push(entry.name.clone());
            }
            continue;
        }
        if entry.name == STARTUP_SHORTCUT {
            if hkcu_tray
                && (command_is_standalone_node(&entry.command, data_dir, missing_dir_matches)
                    || command_launches_tray(&entry.command, data_dir, missing_dir_matches))
            {
                delete_names.push(entry.name.clone());
            }
            continue;
        }
        if command_is_standalone_node(&entry.command, data_dir, missing_dir_matches) {
            delete_names.push(entry.name.clone());
        }
    }
    AutostartMigration {
        write_command,
        delete_names,
    }
}

pub fn install_user_autostart(binary: &Path, data_dir: &Path) -> Result<()> {
    validate_autostart_path(binary)?;
    validate_autostart_path(data_dir)?;
    #[cfg(windows)]
    {
        let entries = collect_autostart_entries();
        let plan = plan_run_migration(
            &entries,
            binary,
            data_dir,
            missing_dir_matches(data_dir),
            true,
        );
        let Some(command) = plan.write_command else {
            bail!("start-on-login did not produce a tray command");
        };
        match set_run_value(&command) {
            Ok(()) => {
                let _ = remove_startup_shortcut();
                let _ = remove_startup_script();
                for name in &plan.delete_names {
                    if is_startup_folder_entry(name) {
                        continue;
                    }
                    let _ = delete_named_run_value(name);
                }
                Ok(())
            }
            Err(err) => {
                write_startup_shortcut(binary, data_dir).with_context(|| {
                    format!("HKCU Run failed ({err:#}); Startup folder fallback also failed")
                })?;
                let _ = remove_startup_script();
                for name in &plan.delete_names {
                    if is_startup_folder_entry(name) {
                        continue;
                    }
                    let _ = delete_named_run_value(name);
                }
                eprintln!(
                    "HKCU Run was not writable; saved {STARTUP_SHORTCUT} in the Startup folder"
                );
                Ok(())
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (binary, data_dir);
        bail!("Windows start-on-login is only available on Windows");
    }
}

pub fn remove_user_autostart() -> Result<()> {
    #[cfg(windows)]
    {
        let entries = collect_autostart_entries();
        let tray_dirs: Vec<PathBuf> = entries
            .iter()
            .filter(|entry| {
                entry.name.eq_ignore_ascii_case(RUN_VALUE_NAME)
                    || is_startup_folder_entry(&entry.name)
            })
            .filter_map(|entry| data_dir_from_command(&entry.command))
            .collect();
        let _ = delete_run_value();
        let _ = remove_startup_shortcut();
        let _ = remove_startup_script();
        for entry in &entries {
            if entry.name.eq_ignore_ascii_case(RUN_VALUE_NAME)
                || is_startup_folder_entry(&entry.name)
            {
                continue;
            }
            let Some(dir) = data_dir_from_command(&entry.command) else {
                continue;
            };
            if agentlink_subcommand(&entry.command).as_deref() == Some("node")
                && tray_dirs.iter().any(|tray| windows_paths_equal(tray, &dir))
            {
                let _ = delete_named_run_value(&entry.name);
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        bail!("Windows start-on-login is only available on Windows");
    }
}

/// Drop a leftover `agentlink node` Run value once the tray owns this directory.
///
/// Called when the tray process starts, so an old dual entry is removed even
/// if the user does not toggle "Start when I sign in" again.
pub fn retire_duplicate_node_autostart(binary: &Path, data_dir: &Path) {
    #[cfg(windows)]
    {
        if let Err(err) = retire_duplicate_node_autostart_windows(binary, data_dir) {
            tracing::warn!(error = %err, "could not remove a duplicate node Run entry");
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (binary, data_dir);
    }
}

/// True when another process currently holds `data_dir/node.lock`.
///
/// Matches `agentlink_node::lock::acquire_node_lock` without creating `node.lock`
/// when it does not already exist.
pub fn node_lock_held(data_dir: &Path) -> bool {
    let path = data_dir.join(NODE_LOCK_FILE);
    if !path.exists() {
        return false;
    }
    let file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return false,
        Err(err) => {
            #[cfg(windows)]
            if matches!(err.raw_os_error(), Some(32 | 33)) {
                return true;
            }
            let _ = err;
            return false;
        }
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(TryLockError::WouldBlock) => true,
        Err(TryLockError::Error(_)) => false,
    }
}

/// Why `agentlink node` must exit before dialing, if another live node or tray
/// currently holds `node.lock` for this data directory.
///
/// Checking the live lock instead of `HKCU\Run` allows manual `agentlink node`
/// when start-on-login is registered but the tray is stopped.
pub fn standalone_node_block_reason(data_dir: &Path) -> Option<String> {
    if node_lock_held(data_dir) {
        return Some(format!(
            "not dialing: another agentlink node or tray is currently running for {} (node.lock is held). Stop the running tray or node first.",
            data_dir.display()
        ));
    }
    None
}

pub fn autostart_enabled() -> bool {
    #[cfg(windows)]
    {
        read_run_value().is_some()
            || startup_shortcut_path().is_some_and(|path| path.exists())
            || startup_script_path().is_some_and(|path| path.exists())
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn installed_data_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(command) = read_run_value() {
            if let Some(dir) = data_dir_from_command(&command) {
                return Some(dir);
            }
        }
        if let Some(command) = startup_shortcut_command() {
            if let Some(dir) = data_dir_from_command(&command) {
                return Some(dir);
            }
        }
        if let Some(command) = startup_script_command() {
            if let Some(dir) = data_dir_from_command(&command) {
                return Some(dir);
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// True when this user's node loop is up (not merely the tray process).
pub fn user_node_running() -> bool {
    let dir = installed_data_dir().or_else(|| config::default_data_dir("node").ok());
    let Some(dir) = dir else {
        return false;
    };
    let Ok(status) = agentlink_node::read_status(&dir) else {
        return false;
    };
    status.state != LinkState::Stopped && status.pid != 0 && pid_alive(status.pid)
}

pub fn signal_tray(message: u32) -> bool {
    #[cfg(windows)]
    {
        let dir = installed_data_dir().or_else(|| config::default_data_dir("node").ok());
        crate::tray_win::post_for(dir.as_deref(), message)
    }
    #[cfg(not(windows))]
    {
        let _ = message;
        false
    }
}

pub fn spawn_tray(binary: &Path, data_dir: &Path) -> Result<()> {
    validate_autostart_path(binary)?;
    validate_autostart_path(data_dir)?;
    #[cfg(windows)]
    {
        let exe = preferred_gui_binary(binary);
        // CREATE_NO_WINDOW via process::detached — do not OR DETACHED_PROCESS;
        // Windows ignores CREATE_NO_WINDOW when that bit is set.
        agentlink_core::process::detached(&exe)
            .args(["tray", "--background", "--data-dir"])
            .arg(data_dir)
            .spawn()
            .context("start the tray")?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (binary, data_dir);
        bail!("the tray is only available on Windows");
    }
}

pub fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(windows)]
    {
        windows_pid_alive(pid)
    }
    #[cfg(not(windows))]
    {
        agentlink_core::process::hidden("kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

pub struct Supervisor {
    launch: NodeLaunch,
    shutdown: Option<CancellationToken>,
    thread: Option<JoinHandle<std::result::Result<(), String>>>,
    restart: bool,
    stop_requested: bool,
    pub last_exit: Option<String>,
}

impl Supervisor {
    pub fn new(ctx: &TrayContext, data_dir: PathBuf) -> Self {
        Self {
            launch: NodeLaunch {
                relay: ctx.relay.clone(),
                fingerprint: ctx.fingerprint.clone(),
                trust: ctx.trust.clone(),
                data_dir,
                name: ctx.name.clone(),
            },
            shutdown: None,
            thread: None,
            restart: false,
            stop_requested: false,
            last_exit: None,
        }
    }

    pub fn update_target(
        &mut self,
        relay: Option<String>,
        fingerprint: Option<String>,
        trust: Option<String>,
    ) {
        if let Some(relay) = relay.filter(|s| !s.trim().is_empty()) {
            self.launch.relay = Some(relay);
        }
        if fingerprint.is_some() || trust.is_some() {
            self.launch.fingerprint = fingerprint;
            self.launch.trust = trust;
        }
    }

    pub fn running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }

    pub fn stop_requested(&self) -> bool {
        self.stop_requested
    }

    pub fn restarting(&self) -> bool {
        self.restart
    }

    pub fn tick(&mut self) {
        let finished = self
            .thread
            .as_ref()
            .is_some_and(|handle| handle.is_finished());
        if !finished {
            return;
        }
        if let Some(handle) = self.thread.take() {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => self.last_exit = Some(err),
                Err(_) => self.last_exit = Some("node thread panicked".into()),
            }
        }
        self.shutdown = None;
        if self.restart {
            self.restart = false;
            self.stop_requested = false;
            self.spawn();
        } else if self.stop_requested {
            note_status(&self.launch.data_dir, "", "", LinkState::Stopped, "stopped");
        }
    }

    pub fn start(&mut self) {
        self.stop_requested = false;
        self.restart = false;
        if !self.running() {
            self.spawn();
        }
    }

    /// Initiate asynchronous node stop without blocking the UI thread.
    pub fn request_stop(&mut self) {
        self.restart = false;
        self.stop_requested = true;
        self.cancel();
        if !self.running() {
            note_status(&self.launch.data_dir, "", "", LinkState::Stopped, "stopped");
        }
    }

    /// Cancel the embedded node, wait up to 3 seconds for a clean shutdown
    /// (so PTYs terminate and audit logs flush), and record `LinkState::Stopped`.
    pub fn stop(&mut self) {
        let _ = self.stop_with_timeout(Duration::from_secs(3));
    }

    /// Bounded variant of [`Supervisor::stop`]. Returns `true` when the node
    /// thread exited cleanly before `timeout` (or was not running).
    pub fn stop_with_timeout(&mut self, timeout: Duration) -> bool {
        self.restart = false;
        self.stop_requested = true;
        self.cancel();
        let mut joined = true;
        if let Some(handle) = self.thread.take() {
            let deadline = Instant::now() + timeout;
            while !handle.is_finished() && Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                std::thread::sleep(remaining.min(Duration::from_millis(20)));
            }
            if handle.is_finished() {
                match handle.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => self.last_exit = Some(err),
                    Err(_) => self.last_exit = Some("node thread panicked".into()),
                }
            } else {
                joined = false;
                tracing::warn!(
                    timeout_ms = timeout.as_millis() as u64,
                    "embedded node thread did not finish before stop timeout"
                );
            }
        }
        self.shutdown = None;
        note_status(&self.launch.data_dir, "", "", LinkState::Stopped, "stopped");
        joined
    }

    pub fn reconnect(&mut self) {
        self.stop_requested = false;
        self.last_exit = None;
        if self.running() {
            self.restart = true;
            self.cancel();
        } else {
            self.spawn();
        }
    }

    fn cancel(&mut self) {
        if let Some(token) = &self.shutdown {
            token.cancel();
        }
    }

    fn spawn(&mut self) {
        if self.running() {
            return;
        }
        let launch = self.launch.clone();
        let config = match load_node(&launch) {
            Ok(config) => config,
            Err(err) => {
                let message = err.to_string();
                self.last_exit = Some(message.clone());
                note_status(&launch.data_dir, "", "", LinkState::Stopped, &message);
                return;
            }
        };
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        self.shutdown = Some(shutdown);
        match std::thread::Builder::new()
            .name("agentlink-node".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| err.to_string())?;
                runtime
                    .block_on(agentlink_node::run(config, token))
                    .map_err(|err| err.to_string())
            }) {
            Ok(handle) => self.thread = Some(handle),
            Err(err) => self.last_exit = Some(err.to_string()),
        }
    }
}

/// Read persisted `stream_consent` (`auto`, `notify`, `prompt`, `deny`) from
/// `data_dir/node.json`, if present.
pub fn read_stream_consent(data_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(data_dir.join("node.json")).ok()?;
    let value = serde_json::from_str::<Value>(&text).ok()?;
    value
        .get("stream_consent")
        .and_then(|item| item.as_str())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
}

/// Persist `stream_consent` (`auto`, `notify`, `prompt`, or `deny`) into
/// `data_dir/node.json`, validating the mode first.
pub fn set_stream_consent(data_dir: &Path, consent: &str) -> Result<()> {
    let trimmed = consent.trim().to_ascii_lowercase();
    agentlink_desktop::ConsentMode::parse(&trimmed).map_err(|err| anyhow!(err))?;
    let path = data_dir.join("node.json");
    let mut obj = match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str::<Value>(&text)
            .with_context(|| format!("parse {}", path.display()))?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(err) => return Err(err.into()),
    };
    let map = obj
        .as_object_mut()
        .ok_or_else(|| anyhow!("node.json must be a JSON object"))?;
    map.insert("stream_consent".into(), Value::String(trimmed));
    let bytes = serde_json::to_string_pretty(&obj)?;
    agentlink_core::util::write_secret(&path, bytes.as_bytes())
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

fn persist_node_config_with_consent(config: &NodeConfig, consent: Option<&str>) -> Result<()> {
    let effective = consent
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| read_stream_consent(&config.data_dir))
        .unwrap_or_else(|| "notify".to_string());
    agentlink_desktop::ConsentMode::parse(&effective).map_err(|err| anyhow!(err))?;
    save_node_config(config)?;
    let path = config.data_dir.join("node.json");
    let text = std::fs::read_to_string(&path)?;
    let mut obj = serde_json::from_str::<Value>(&text)?;
    if let Some(map) = obj.as_object_mut() {
        map.insert("stream_consent".into(), Value::String(effective));
        let bytes = serde_json::to_string_pretty(&obj)?;
        agentlink_core::util::write_secret(&path, bytes.as_bytes())
            .map_err(|err| anyhow!(err.to_string()))?;
    }
    Ok(())
}

fn load_node(launch: &NodeLaunch) -> Result<NodeConfig> {
    let saved_consent = read_stream_consent(&launch.data_dir);
    node_cfg::load(NodeArgs {
        relay: launch.relay.clone(),
        fingerprint: launch.fingerprint.clone(),
        trust: launch.trust.clone(),
        invite: None,
        name: launch.name.clone(),
        pairing_token: None,
        data_dir: Some(launch.data_dir.clone()),
        root: None,
        max_access: None,
        stream_consent: saved_consent,
    })
}

fn note_status(data_dir: &Path, relay: &str, name: &str, state: LinkState, detail: &str) {
    let previous = agentlink_node::read_status(data_dir).ok();
    let relay_url = if relay.is_empty() {
        previous
            .as_ref()
            .map(|status| status.relay_url.clone())
            .filter(|value| !value.is_empty())
            .unwrap_or_default()
    } else {
        relay.to_string()
    };
    let name = if name.is_empty() {
        previous
            .as_ref()
            .map(|status| status.name.clone())
            .unwrap_or_default()
    } else {
        name.to_string()
    };
    let status = LinkStatus {
        state,
        detail: detail.to_string(),
        relay_url,
        name,
        node_id: previous
            .as_ref()
            .map(|status| status.node_id.clone())
            .unwrap_or_default(),
        enrolled: previous.as_ref().is_some_and(|status| status.enrolled),
        pid: std::process::id(),
        updated_unix: agentlink_node::status::unix_now(),
    };
    let _ = write_status(data_dir, &status);
}

pub struct SignInRequest {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub relay: Option<String>,
    pub fingerprint: Option<String>,
    pub trust: Option<String>,
    pub name: Option<String>,
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
}

/// Pre-filled Relay URL & Trust/Pin fields for the Windows Sign-In dialog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInDefaults {
    pub relay: String,
    pub trust: String,
}

fn nonempty_opt(value: Option<String>) -> Option<String> {
    value
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn combine_trust_display(fingerprint: Option<&str>, trust: Option<&str>) -> String {
    let fp = fingerprint.map(str::trim).filter(|s| !s.is_empty());
    let tr = trust.map(str::trim).filter(|s| !s.is_empty());
    match (fp, tr) {
        (Some(f), Some(t)) if f.eq_ignore_ascii_case(t) => f.to_string(),
        (Some(f), Some(t)) => format!("{f}+{t}"),
        (Some(f), None) => f.to_string(),
        (None, Some(t)) => t.to_string(),
        (None, None) => String::new(),
    }
}

/// Pre-fill Relay URL and Trust/Pin for the Sign-In dialog from CLI context,
/// existing `node.json`, `config.json`, or `AGENTLINK_RELAY` / trust env vars.
pub fn prefill_sign_in_defaults(ctx: &TrayContext, data_dir: &Path) -> SignInDefaults {
    let saved_node = std::fs::read_to_string(data_dir.join("node.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let node_str = |key: &str| {
        saved_node
            .as_ref()
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let saved_cfg = config::load_file(&ctx.config_dir).unwrap_or_default();

    let relay = nonempty_opt(ctx.relay.clone())
        .or_else(|| node_str("relay_url"))
        .or_else(|| nonempty_opt(saved_cfg.relay.clone()))
        .or_else(|| nonempty_opt(std::env::var("AGENTLINK_RELAY").ok()))
        .unwrap_or_default();

    let fp = nonempty_opt(ctx.fingerprint.clone())
        .or_else(|| node_str("fingerprint"))
        .or_else(|| nonempty_opt(saved_cfg.fingerprint.clone()))
        .or_else(|| nonempty_opt(std::env::var("AGENTLINK_FINGERPRINT").ok()))
        .or_else(|| nonempty_opt(std::env::var("AGENTLINK_RELAY_PIN").ok()));
    let tr = nonempty_opt(ctx.trust.clone())
        .or_else(|| node_str("trust"))
        .or_else(|| nonempty_opt(saved_cfg.trust.clone()))
        .or_else(|| nonempty_opt(std::env::var("AGENTLINK_TRUST").ok()));
    let trust = combine_trust_display(fp.as_deref(), tr.as_deref());
    SignInDefaults { relay, trust }
}

/// Parse a user-entered Trust / Pin field (`system`, `webpki`, `sha256:...`,
/// `spki:sha256:...`, or `+`-combined expressions) into `(fingerprint, trust)`.
pub fn parse_trust_input(input: &str) -> Result<(Option<String>, Option<String>)> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok((None, None));
    }
    let parsed = agentlink_core::RelayTrust::parse(trimmed, None)
        .map_err(|err| anyhow!(err.to_string()))?;
    let fp = parsed.fingerprint_value();
    let tr = parsed.trust_value();
    Ok((if fp.is_empty() { None } else { Some(fp) }, tr))
}

/// Password login, then enroll this machine's node key under that account.
pub async fn sign_in_and_enroll(request: SignInRequest) -> Result<String> {
    let username = request.username.trim().to_string();
    if username.is_empty() {
        bail!("username is required");
    }
    if request.password.is_empty() {
        bail!("password is required");
    }
    let existing_consent = read_stream_consent(&request.data_dir);
    let explicit_fp_only = request
        .fingerprint
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && request
            .trust
            .as_deref()
            .is_none_or(|value| value.trim().is_empty());
    let launch = NodeLaunch {
        relay: request.relay.clone(),
        fingerprint: request.fingerprint.clone(),
        trust: request.trust.clone(),
        data_dir: request.data_dir.clone(),
        name: request.name.clone(),
    };
    let mut node = load_node(&launch)?;
    if explicit_fp_only {
        // An explicit pin-only entry from the Sign-In dialog overrides any
        // previously saved `trust` in `node.json`.
        node.trust = None;
    }
    let parsed = agentlink_core::RelayTrust::parse(&node.fingerprint, node.trust.as_deref())
        .map_err(|err| anyhow!(err.to_string()))?;
    node.fingerprint = parsed.fingerprint_value();
    node.trust = parsed.trust_value();
    let device = Identity::load_or_create(&request.config_dir.join("identity.json"))
        .map_err(|err| anyhow!(err.to_string()))?;
    let totp = request
        .totp
        .as_deref()
        .map(str::trim)
        .filter(|code| !code.is_empty());
    let session = agentlink_core::client::login_user(
        &node.relay_url,
        &parsed.fingerprint_value(),
        parsed.trust_value().as_deref(),
        &device,
        &username,
        &request.password,
        totp,
        "windows-tray",
    )
    .await
    .map_err(|err| anyhow!(err.to_string()))?;
    let settings = ClientSettings {
        relay: node.relay_url.clone(),
        token: session.access_token.clone(),
        fingerprint: parsed.fingerprint_value(),
        trust: parsed.trust_value(),
    };
    config::save_session(
        &request.config_dir,
        &settings,
        &session.user,
        &session.refresh_token,
        session.access_expires_unix,
    )
    .map_err(|err| anyhow!(err.to_string()))?;
    let node_identity = Identity::load_or_create(&request.data_dir.join("identity.json"))
        .map_err(|err| anyhow!(err.to_string()))?;
    let client = Client::connect_identity(&settings, device, true)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    client.remember_node_pins(request.config_dir.clone());
    client.remember_grants(request.config_dir.clone());
    let policy = node.max_policy;
    client
        .enroll_self(&node.name, &node_identity, Some(policy))
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    persist_node_config_with_consent(&node, existing_consent.as_deref())?;
    Ok(session.user)
}

fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub async fn sign_out(config_dir: &Path) -> Result<()> {
    sign_out_with(
        config_dir,
        unix_now_secs(),
        |relay, fingerprint, trust, identity, refresh| async move {
            agentlink_core::client::refresh_user(
                &relay,
                &fingerprint,
                trust.as_deref(),
                &identity,
                &refresh,
            )
            .await
            .map(|session| (session.access_token, session.refresh_token))
            .map_err(|err| anyhow!(err.to_string()))
        },
        |settings, identity, config_dir, refresh| async move {
            let client = Client::connect_identity(&settings, identity, true)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            client.remember_grants(&config_dir);
            client
                .logout_session(Some(refresh))
                .await
                .map_err(|err| anyhow!(err.to_string()))
        },
    )
    .await
}

async fn sign_out_with<RF, RFut, LF, LFut>(
    config_dir: &Path,
    now_unix: i64,
    refresh_fn: RF,
    logout_fn: LF,
) -> Result<()>
where
    RF: FnOnce(String, String, Option<String>, Identity, String) -> RFut,
    RFut: std::future::Future<Output = Result<(String, String)>>,
    LF: FnOnce(ClientSettings, Identity, PathBuf, String) -> LFut,
    LFut: std::future::Future<Output = Result<()>>,
{
    let lock_dir = config_dir.to_path_buf();
    let _session_lock = tokio::task::spawn_blocking(move || config::lock_session(&lock_dir))
        .await
        .ok()
        .and_then(|res| res.ok());

    let file = config::load_file(config_dir).unwrap_or_default();
    if let Some(refresh) = file
        .refresh_token
        .clone()
        .filter(|token| !token.trim().is_empty())
    {
        let mut relay = file.relay.clone().unwrap_or_default();
        let fingerprint = file.fingerprint.clone().unwrap_or_default();
        let mut trust = file.trust.clone();
        agentlink_core::apply_relay_defaults(&mut relay, &fingerprint, &mut trust);
        if !relay.is_empty() && (!fingerprint.is_empty() || trust.is_some()) {
            if let Ok(identity) = Identity::load_or_create(&config_dir.join("identity.json")) {
                let mut active_token = file.token.clone().unwrap_or_default();
                let mut active_refresh = refresh;
                if !config::access_token_is_fresh(&file, now_unix, 30) {
                    if let Ok((new_access, new_refresh)) = refresh_fn(
                        relay.clone(),
                        fingerprint.clone(),
                        trust.clone(),
                        identity.clone(),
                        active_refresh.clone(),
                    )
                    .await
                    {
                        if !new_access.trim().is_empty() {
                            active_token = new_access;
                        }
                        if !new_refresh.trim().is_empty() {
                            active_refresh = new_refresh;
                        }
                    }
                }
                if !active_token.trim().is_empty() {
                    let settings = ClientSettings {
                        relay,
                        token: active_token,
                        fingerprint,
                        trust,
                    };
                    let _ = logout_fn(settings, identity, config_dir.to_path_buf(), active_refresh)
                        .await;
                }
            }
        }
    }
    let cleared = ClientSettings {
        relay: file.relay.clone().unwrap_or_default(),
        token: String::new(),
        fingerprint: file.fingerprint.clone().unwrap_or_default(),
        trust: file.trust.clone(),
    };
    config::save_settings(config_dir, &cleared).map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

/// Store an invite string or a raw pairing token in `node.json`.
pub fn apply_pairing_text(
    data_dir: &Path,
    text: &str,
    relay: Option<String>,
    fingerprint: Option<String>,
    trust: Option<String>,
    name: Option<String>,
) -> Result<String> {
    let text = text.trim();
    let joined = parse_join_text(text).map_err(|err| anyhow!(err.to_string()))?;
    let (invite, pairing_token) = match joined {
        JoinText::Absent => {
            bail!("paste an invite from `agentlink pair`, or a pairing token");
        }
        JoinText::Invite(_) => (Some(text.to_string()), None),
        JoinText::Token(token) => (None, Some(token)),
    };
    let existing_consent = read_stream_consent(data_dir);
    let config = node_cfg::load(NodeArgs {
        relay,
        fingerprint,
        trust,
        invite,
        name,
        pairing_token,
        data_dir: Some(data_dir.to_path_buf()),
        root: None,
        max_access: None,
        stream_consent: existing_consent.clone(),
    })?;
    persist_node_config_with_consent(&config, existing_consent.as_deref())?;
    Ok(config.name)
}

pub fn current_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locate the running agentlink binary")?;
    let canon = std::fs::canonicalize(&exe).unwrap_or(exe);
    Ok(strip_verbatim(&canon))
}

fn strip_verbatim(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

struct RotatingLogState {
    path: PathBuf,
    backup_path: PathBuf,
    max_bytes: u64,
    file: Option<File>,
    written: u64,
}

impl RotatingLogState {
    fn new(path: PathBuf, max_bytes: u64) -> Self {
        let mut backup_os = path.as_os_str().to_os_string();
        backup_os.push(".1");
        let backup_path = PathBuf::from(backup_os);
        let written = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Self {
            path,
            backup_path,
            max_bytes: max_bytes.max(1),
            file: None,
            written,
        }
    }

    fn ensure_open(&mut self) -> Option<&mut File> {
        if self.file.is_none() {
            if let Some(parent) = self.path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(file) = OpenOptions::new().create(true).append(true).open(&self.path) {
                self.written = file.metadata().map(|m| m.len()).unwrap_or(self.written);
                self.file = Some(file);
            }
        }
        self.file.as_mut()
    }

    fn rotate(&mut self) {
        // Close handle first — Windows rejects renaming an open file.
        self.file = None;
        let _ = std::fs::remove_file(&self.backup_path);
        let _ = std::fs::rename(&self.path, &self.backup_path);
        self.written = 0;
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)
        {
            self.file = Some(file);
        }
    }

    fn write_bytes(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.written > 0 && self.written.saturating_add(buf.len() as u64) > self.max_bytes {
            self.rotate();
        }
        if self.ensure_open().is_some() {
            if self.written > 0 && self.written.saturating_add(buf.len() as u64) > self.max_bytes {
                self.rotate();
            }
            if let Some(file) = self.file.as_mut() {
                if file.write_all(buf).is_ok() {
                    self.written = self.written.saturating_add(buf.len() as u64);
                }
            }
        }
        Ok(buf.len())
    }

    fn flush_file(&mut self) -> std::io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RotatingLogMakeWriter {
    state: Arc<Mutex<RotatingLogState>>,
}

impl RotatingLogMakeWriter {
    fn new(path: PathBuf, max_bytes: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(RotatingLogState::new(path, max_bytes))),
        }
    }
}

struct RotatingLogHandle {
    state: Arc<Mutex<RotatingLogState>>,
}

impl Write for RotatingLogHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.write_bytes(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.flush_file()
    }
}

impl<'a> MakeWriter<'a> for RotatingLogMakeWriter {
    type Writer = RotatingLogHandle;

    fn make_writer(&'a self) -> Self::Writer {
        RotatingLogHandle {
            state: Arc::clone(&self.state),
        }
    }
}

pub fn init_tray_log(data_dir: &Path) {
    let mut initialized = false;
    TRAY_LOG_INIT.get_or_init(|| {
        initialized = true;
        let _ = std::fs::create_dir_all(data_dir);
        let writer = RotatingLogMakeWriter::new(data_dir.join("tray.log"), TRAY_LOG_MAX_BYTES);
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(writer)
            .try_init();
    });
    if initialized {
        tracing::info!(version = version::current(), "tray starting");
    }
}

/// Decode a Windows registry UTF-16LE byte buffer (`REG_SZ` or `REG_EXPAND_SZ`),
/// trimming only trailing NUL code units without dropping the last character
/// when the stored bytes are not NUL-terminated.
pub(crate) fn decode_reg_utf16(bytes: &[u8]) -> String {
    let mut words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    while words.last() == Some(&0) {
        words.pop();
    }
    String::from_utf16_lossy(&words)
        .trim_end_matches('\u{0}')
        .trim()
        .to_string()
}

#[cfg(windows)]
fn startup_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(|root| PathBuf::from(root).join(r"Microsoft\Windows\Start Menu\Programs\Startup"))
}

#[cfg(windows)]
fn startup_shortcut_path() -> Option<PathBuf> {
    startup_dir().map(|dir| dir.join(STARTUP_SHORTCUT))
}

#[cfg(windows)]
fn startup_script_path() -> Option<PathBuf> {
    startup_dir().map(|dir| dir.join(STARTUP_SCRIPT))
}

#[cfg(windows)]
fn write_startup_shortcut(binary: &Path, data_dir: &Path) -> Result<()> {
    let lnk = build_windows_lnk(binary, data_dir)?;
    let dir = startup_dir().context("APPDATA is not set")?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(STARTUP_SHORTCUT), lnk)?;
    let _ = remove_startup_script();
    Ok(())
}

#[cfg(windows)]
fn remove_startup_shortcut() -> Result<()> {
    if let Some(path) = startup_shortcut_path() {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn remove_startup_script() -> Result<()> {
    if let Some(path) = startup_script_path() {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn missing_dir_matches(data_dir: &Path) -> bool {
    config::default_data_dir("node")
        .map(|default| windows_paths_equal(&default, data_dir))
        .unwrap_or(false)
}

#[cfg(windows)]
fn startup_shortcut_command() -> Option<String> {
    let path = startup_shortcut_path()?;
    let bytes = std::fs::read(path).ok()?;
    parse_windows_lnk_command(&bytes)
}

#[cfg(windows)]
fn startup_script_command() -> Option<String> {
    let path = startup_script_path()?;
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("start \"\" ") {
            let rest = rest.trim();
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

#[cfg(windows)]
fn collect_autostart_entries() -> Vec<RunValue> {
    let mut entries = list_run_values().unwrap_or_default();
    if let Some(command) = startup_shortcut_command() {
        entries.push(RunValue {
            name: STARTUP_SHORTCUT.to_string(),
            command,
        });
    }
    if let Some(command) = startup_script_command() {
        entries.push(RunValue {
            name: STARTUP_SCRIPT.to_string(),
            command,
        });
    }
    entries
}

#[cfg(windows)]
fn retire_duplicate_node_autostart_windows(binary: &Path, data_dir: &Path) -> Result<()> {
    validate_autostart_path(binary)?;
    validate_autostart_path(data_dir)?;
    let entries = collect_autostart_entries();
    let plan = plan_run_migration(
        &entries,
        binary,
        data_dir,
        missing_dir_matches(data_dir),
        false,
    );
    if let Some(command) = &plan.write_command {
        set_run_value(command)?;
    }
    for name in &plan.delete_names {
        if name == STARTUP_SHORTCUT {
            let _ = remove_startup_shortcut();
        } else if name == STARTUP_SCRIPT {
            let _ = remove_startup_script();
        } else {
            let _ = delete_named_run_value(name);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn list_run_values() -> Result<Vec<RunValue>> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, HKEY_CURRENT_USER,
        KEY_QUERY_VALUE, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
    };

    const MAX_VALUE_BYTES: usize = 4 * 1024 * 1024;
    const MAX_NAME_CHARS: usize = 32_768;

    unsafe {
        let key_name = wide(RUN_KEY);
        let mut key = windows::Win32::System::Registry::HKEY::default();
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_name.as_ptr()),
            Some(0),
            KEY_QUERY_VALUE,
            &mut key,
        )
        .ok()
        .context("open HKCU Run")?;

        let mut max_name_len = 0u32;
        let mut max_value_len = 0u32;
        let _ = RegQueryInfoKeyW(
            key,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&mut max_name_len),
            Some(&mut max_value_len),
            None,
            None,
        );
        let initial_name_cap = (max_name_len as usize).saturating_add(1).clamp(256, MAX_NAME_CHARS);
        let initial_data_cap = (max_value_len as usize)
            .saturating_add(2)
            .clamp(1024, 65_536);

        let mut entries = Vec::new();
        let mut index = 0u32;
        'outer: loop {
            let mut name_cap = initial_name_cap;
            let mut data_cap = initial_data_cap;
            loop {
                let mut name_buf = vec![0u16; name_cap];
                let mut name_len = name_cap as u32;
                let mut kind = REG_VALUE_TYPE::default();
                let mut data = vec![0u8; data_cap];
                let mut data_len = data.len() as u32;
                let status = RegEnumValueW(
                    key,
                    index,
                    Some(PWSTR(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut kind.0), // windows 0.61 RegEnumValueW lpType is *mut u32
                    Some(data.as_mut_ptr()),
                    Some(&mut data_len),
                );
                if status == ERROR_NO_MORE_ITEMS {
                    break 'outer;
                }
                if status == ERROR_MORE_DATA {
                    let needed_data = (data_len as usize).saturating_add(2);
                    if needed_data > data_cap && needed_data <= MAX_VALUE_BYTES {
                        data_cap = needed_data;
                        continue;
                    }
                    if name_cap < MAX_NAME_CHARS {
                        name_cap = (name_cap * 2).min(MAX_NAME_CHARS);
                        continue;
                    }
                    // Skip unreasonably oversized unrelated entry rather than aborting enum.
                    index += 1;
                    continue 'outer;
                }
                if status.is_err() {
                    let _ = RegCloseKey(key);
                    return Err(anyhow!("enumerate HKCU Run values: {status:?}"));
                }
                index += 1;
                if (kind != REG_SZ && kind != REG_EXPAND_SZ) || name_len == 0 {
                    continue 'outer;
                }
                let name = String::from_utf16_lossy(
                    &name_buf[..(name_len as usize).min(name_buf.len())],
                );
                let bytes = &data[..(data_len as usize).min(data.len())];
                let command = decode_reg_utf16(bytes);
                if !name.is_empty() && !command.is_empty() {
                    entries.push(RunValue { name, command });
                }
                break;
            }
        }
        let _ = RegCloseKey(key);
        Ok(entries)
    }
}

#[cfg(windows)]
fn set_run_value(command: &str) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ,
    };

    if command.chars().any(|ch| matches!(ch, '\r' | '\n' | '\0')) {
        bail!("HKCU Run command contains forbidden control characters");
    }

    unsafe {
        let key_name = wide(RUN_KEY);
        let mut key = windows::Win32::System::Registry::HKEY::default();
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_name.as_ptr()),
            Some(0),
            KEY_SET_VALUE,
            &mut key,
        )
        .ok()
        .context("open HKCU Run")?;
        let name = wide(RUN_VALUE_NAME);
        let bytes = command_bytes(command);
        let result = RegSetValueExW(
            key,
            PCWSTR(name.as_ptr()),
            Some(0),
            REG_SZ,
            Some(std::slice::from_raw_parts(
                bytes.as_ptr() as *const u8,
                bytes.len() * 2,
            )),
        );
        let _ = RegCloseKey(key);
        result.ok().context("write HKCU Run value")?;
    }
    Ok(())
}

#[cfg(windows)]
fn delete_run_value() -> Result<()> {
    delete_named_run_value(RUN_VALUE_NAME)
}

#[cfg(windows)]
fn delete_named_run_value(name: &str) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, HKEY_CURRENT_USER, KEY_SET_VALUE,
    };
    unsafe {
        let key_name = wide(RUN_KEY);
        let mut key = windows::Win32::System::Registry::HKEY::default();
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_name.as_ptr()),
            Some(0),
            KEY_SET_VALUE,
            &mut key,
        )
        .ok()
        .context("open HKCU Run")?;
        let name = wide(name);
        let result = RegDeleteValueW(key, PCWSTR(name.as_ptr()));
        let _ = RegCloseKey(key);
        result.ok().context("delete HKCU Run value")?;
    }
    Ok(())
}

#[cfg(windows)]
fn read_run_value() -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_MORE_DATA;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER, KEY_QUERY_VALUE,
        REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
    };
    unsafe {
        let key_name = wide(RUN_KEY);
        let mut key = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_name.as_ptr()),
            Some(0),
            KEY_QUERY_VALUE,
            &mut key,
        )
        .is_err()
        {
            return None;
        }
        let name = wide(RUN_VALUE_NAME);
        let mut kind = REG_VALUE_TYPE::default();
        let mut len = 0u32;
        if RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut len),
        )
        .is_err()
            || (kind != REG_SZ && kind != REG_EXPAND_SZ)
            || len < 2
        {
            let _ = RegCloseKey(key);
            return None;
        }
        let mut buf = vec![0u8; (len as usize).saturating_add(2)];
        for _ in 0..4 {
            let mut cap = buf.len() as u32;
            let status = RegQueryValueExW(
                key,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut kind),
                Some(buf.as_mut_ptr()),
                Some(&mut cap),
            );
            if status == ERROR_MORE_DATA {
                let next = (cap as usize).saturating_add(2);
                if next <= 4 * 1024 * 1024 {
                    buf.resize(next, 0);
                    continue;
                }
                let _ = RegCloseKey(key);
                return None;
            }
            let _ = RegCloseKey(key);
            if status.is_err() || (kind != REG_SZ && kind != REG_EXPAND_SZ) {
                return None;
            }
            let text = decode_reg_utf16(&buf[..(cap as usize).min(buf.len())]);
            return if text.is_empty() { None } else { Some(text) };
        }
        let _ = RegCloseKey(key);
        None
    }
}

#[cfg(windows)]
fn command_bytes(command: &str) -> Vec<u16> {
    command.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn windows_pid_alive(pid: u32) -> bool {
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let mut code = 0u32;
        let ok = GetExitCodeProcess(handle, &mut code).is_ok();
        let _ = windows::Win32::Foundation::CloseHandle(handle);
        // 259 is STILL_ACTIVE.
        ok && code == 259
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_command_quotes_spaces_and_round_trips_the_data_dir() {
        let command = autostart_command(
            Path::new(r"C:\Program Files\agentlink\agentlink.exe"),
            Path::new(r"C:\Users\Ada Lovelace\AppData\Local\agentlink\node"),
        );
        assert!(
            command.contains("tray --background --data-dir"),
            "{command}"
        );
        assert!(
            command.starts_with(r#""C:\Program Files\agentlink\agentlink.exe""#),
            "{command}"
        );
        assert!(!command.contains("schtasks"), "{command}");
        let dir = data_dir_from_command(&command).unwrap();
        assert_eq!(
            dir,
            PathBuf::from(r"C:\Users\Ada Lovelace\AppData\Local\agentlink\node")
        );
        let script = startup_script_contents(
            Path::new(r"C:\Program Files\agentlink\agentlink.exe"),
            Path::new(r"C:\Users\Ada Lovelace\AppData\Local\agentlink\node"),
        );
        assert!(script.starts_with("@echo off\r\nstart \"\" "), "{script}");
        assert!(script.contains("tray --background"), "{script}");
    }

    #[test]
    fn describe_reports_pairing_account_and_a_dead_process() {
        let link = LinkStatus {
            state: LinkState::Online,
            detail: String::new(),
            relay_url: "wss://relay.example.com".into(),
            name: "laptop".into(),
            node_id: "abc".into(),
            enrolled: true,
            pid: 9,
            updated_unix: 10,
        };
        let node = NodeSnap {
            name: "laptop".into(),
            relay_url: "wss://relay.example.com".into(),
            pairing_pending: false,
        };
        let account = AccountSnap {
            user: Some("ada".into()),
            has_token: true,
        };
        let view = describe(Some(&link), &node, &account, true);
        assert_eq!(view.connection, "Online");
        assert_eq!(view.pairing, "Paired");
        assert_eq!(view.account, "Signed in as ada");
        assert!(view.running);

        let stopped = describe(Some(&link), &node, &account, false);
        assert_eq!(stopped.connection, "Stopped");
        assert!(!stopped.running);
        assert!(stopped.enrolled);

        let pending = NodeSnap {
            pairing_pending: true,
            ..node.clone()
        };
        let waiting = describe(Some(&link), &pending, &account, true);
        assert_eq!(waiting.pairing, "Pairing pending");

        let signed_out = AccountSnap {
            user: None,
            has_token: false,
        };
        let view = describe(None, &node, &signed_out, false);
        assert_eq!(view.connection, "Stopped");
        assert_eq!(view.account, "Not signed in");
        assert_eq!(view.relay, "wss://relay.example.com");
        assert_eq!(view.pairing, "Not paired");
    }

    #[test]
    fn apply_invite_writes_node_json_without_printing_the_token() {
        std::env::set_var("AGENTLINK_DESKTOP", "mock");
        let dir = tempfile::tempdir().unwrap();
        let token = "cd".repeat(32);
        let pin = format!("sha256:{}", "ab".repeat(32));
        let invite = agentlink_core::encode_invite(&agentlink_core::Invite {
            relay: "wss://relay.example:7443".into(),
            fingerprint: pin.clone(),
            trust: None,
            token: token.clone(),
            name: "box".into(),
        })
        .unwrap();
        let name = apply_pairing_text(dir.path(), &invite, None, None, None, None).unwrap();
        assert_eq!(name, "box");
        let text = std::fs::read_to_string(dir.path().join("node.json")).unwrap();
        assert!(text.contains("wss://relay.example:7443"), "{text}");
        assert!(text.contains(&token), "{text}");
        assert!(text.contains(&pin), "{text}");
        let plan = autostart_plan(Path::new(r"C:\agentlink\agentlink.exe"), dir.path());
        assert!(!plan.contains(&token), "{plan}");
        assert!(plan.contains("HKCU\\"), "{plan}");
        assert!(plan.contains("tray --background"), "{plan}");
        assert_eq!(
            agentlink_subcommand(&autostart_command(
                Path::new(r"C:\agentlink\agentlink.exe"),
                dir.path(),
            ))
            .as_deref(),
            Some("tray")
        );
    }

    #[test]
    fn short_and_damaged_invites_do_not_write_node_json() {
        let dir = tempfile::tempdir().unwrap();
        let short = apply_pairing_text(dir.path(), "123", None, None, None, None).unwrap_err();
        assert!(short.to_string().contains("too short"), "{short}");
        let empty = apply_pairing_text(dir.path(), "   ", None, None, None, None).unwrap_err();
        assert!(empty.to_string().contains("paste an invite"), "{empty}");
        let damaged = apply_pairing_text(
            dir.path(),
            "agentlink-invite:v1:%%%",
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(damaged.to_string().contains("damaged"), "{damaged}");
        assert!(!dir.path().join("node.json").exists());
    }

    fn probe_commands() -> (String, String, PathBuf) {
        let data = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\data\node");
        let exe = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\agentlink.exe");
        let node = format!(
            "{} node --data-dir {}",
            quote_windows_arg(&exe.to_string_lossy()),
            quote_windows_arg(&data.to_string_lossy()),
        );
        let tray = autostart_command(&exe, &data);
        (node, tray, data)
    }

    #[test]
    fn autostart_command_is_the_tray_and_not_a_standalone_node() {
        let exe = Path::new(r"C:\Users\probe\AppData\Local\agentlink\agentlink.exe");
        let data = Path::new(r"C:\Users\probe\AppData\Local\agentlink\data\node");
        let command = autostart_command(exe, data);
        assert!(
            command.contains("tray --background --data-dir"),
            "{command}"
        );
        assert_eq!(agentlink_subcommand(&command).as_deref(), Some("tray"));
        assert!(
            !command_is_standalone_node(&command, data, false),
            "{command}"
        );
        assert!(command_launches_tray(&command, data, false), "{command}");
        let script = startup_script_contents(exe, data);
        assert!(script.contains("tray --background"), "{script}");
        assert!(!script.contains(" node "), "{script}");
    }

    #[test]
    fn dual_run_entries_collapse_to_the_tray_for_the_same_data_dir() {
        let (node, tray, data) = probe_commands();
        let exe = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\agentlink.exe");
        let entries = vec![
            RunValue {
                name: "agentlink".into(),
                command: tray.clone(),
            },
            RunValue {
                name: "agentlink-node".into(),
                command: node.clone(),
            },
            RunValue {
                name: "OneDrive".into(),
                command: r"C:\Program Files\Microsoft OneDrive\OneDrive.exe".into(),
            },
        ];
        let plan = plan_run_migration(&entries, &exe, &data, false, false);
        assert_eq!(
            plan.write_command, None,
            "the tray value is already current"
        );
        assert_eq!(plan.delete_names, vec!["agentlink-node".to_string()]);
        assert!(tray_autostart_blocks_node(&entries, &data, false));

        let installed = plan_run_migration(&entries, &exe, &data, false, true);
        assert_eq!(installed.write_command.as_deref(), Some(tray.as_str()));
        assert_eq!(installed.delete_names, vec!["agentlink-node".to_string()]);
    }

    #[test]
    fn canonical_node_value_is_rewritten_to_the_tray() {
        let (node, tray, data) = probe_commands();
        let exe = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\agentlink.exe");
        let entries = vec![RunValue {
            name: "agentlink".into(),
            command: node,
        }];
        let plan = plan_run_migration(&entries, &exe, &data, false, false);
        assert_eq!(plan.write_command.as_deref(), Some(tray.as_str()));
        assert!(plan.delete_names.is_empty());
        assert!(!tray_autostart_blocks_node(&entries, &data, false));
    }

    #[test]
    fn a_node_entry_for_another_directory_is_kept() {
        let exe = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\agentlink.exe");
        let tray_data = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\data\node");
        let other = PathBuf::from(r"D:\other\node");
        let entries = vec![
            RunValue {
                name: "agentlink".into(),
                command: autostart_command(&exe, &tray_data),
            },
            RunValue {
                name: "agentlink-node".into(),
                command: format!(
                    "{} node --data-dir {}",
                    quote_windows_arg(&exe.to_string_lossy()),
                    quote_windows_arg(&other.to_string_lossy()),
                ),
            },
        ];
        let plan = plan_run_migration(&entries, &exe, &tray_data, false, false);
        assert!(plan.delete_names.is_empty(), "{plan:?}");
        assert!(!tray_autostart_blocks_node(&entries, &other, false));
        assert!(tray_autostart_blocks_node(&entries, &tray_data, false));
    }

    #[test]
    fn node_without_a_tray_entry_is_not_removed_or_blocked() {
        let (node, _tray, data) = probe_commands();
        let exe = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\agentlink.exe");
        let entries = vec![RunValue {
            name: "agentlink-node".into(),
            command: node,
        }];
        let plan = plan_run_migration(&entries, &exe, &data, false, false);
        assert_eq!(plan.write_command, None);
        assert!(plan.delete_names.is_empty(), "{plan:?}");
        assert!(!tray_autostart_blocks_node(&entries, &data, false));
    }

    #[test]
    fn startup_script_node_is_removed_when_hkcu_already_starts_the_tray() {
        let (node, tray, data) = probe_commands();
        let exe = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\agentlink.exe");
        let entries = vec![
            RunValue {
                name: "agentlink".into(),
                command: tray,
            },
            RunValue {
                name: STARTUP_SCRIPT.into(),
                command: node,
            },
        ];
        let plan = plan_run_migration(&entries, &exe, &data, false, false);
        assert_eq!(plan.delete_names, vec![STARTUP_SCRIPT.to_string()]);
    }

    #[test]
    fn path_spelling_and_an_exe_directory_named_node_do_not_confuse_the_subcommand() {
        let data = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\data\node");
        let exe = PathBuf::from(r"C:\agentlink node\agentlink.exe");
        let tray = format!(
            "{} tray --background --data-dir {}",
            quote_windows_arg(&exe.to_string_lossy()),
            quote_windows_arg(r"C:/Users/probe/AppData/Local/agentlink/data/node"),
        );
        assert_eq!(agentlink_subcommand(&tray).as_deref(), Some("tray"));
        assert!(command_launches_tray(&tray, &data, false), "{tray}");
        assert!(!command_is_standalone_node(&tray, &data, false), "{tray}");
        let with_global = format!(
            "{} --relay wss://relay.example.com node --data-dir {}",
            quote_windows_arg(&exe.to_string_lossy()),
            quote_windows_arg(&data.to_string_lossy()),
        );
        assert_eq!(agentlink_subcommand(&with_global).as_deref(), Some("node"));
        assert!(command_is_standalone_node(&with_global, &data, false));
        let service = format!(
            "{} service run --data-dir {}",
            quote_windows_arg(&exe.to_string_lossy()),
            quote_windows_arg(&data.to_string_lossy()),
        );
        assert!(
            !command_is_standalone_node(&service, &data, false),
            "{service}"
        );
        assert!(!command_launches_tray(&service, &data, false), "{service}");
    }

    #[test]
    fn a_missing_data_dir_matches_only_the_default_directory() {
        let data = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\data\node");
        let command = r#""C:\agentlink\agentlink.exe" node"#;
        assert!(!command_is_standalone_node(command, &data, false));
        assert!(command_is_standalone_node(command, &data, true));
        let tray = r#""C:\agentlink\agentlink.exe" tray --background"#;
        assert!(!command_launches_tray(tray, &data, false));
        assert!(command_launches_tray(tray, &data, true));
        assert!(!command_launches_tray(
            r#""C:\agentlink\agentlink.exe" tray status"#,
            &data,
            true
        ));
    }

    fn view_at(connection: &str, running: bool) -> StatusView {
        StatusView {
            connection: connection.into(),
            relay: "wss://relay.example.com".into(),
            node_name: "probe".into(),
            pairing: "Paired".into(),
            account: "Not signed in".into(),
            detail: String::new(),
            running,
            enrolled: true,
        }
    }

    #[test]
    fn sign_in_launch_dials_without_a_start_click() {
        assert_eq!(
            tray_launch(true, false),
            TrayLaunch::Run { connect: true },
            "tray --background is the user-scope node"
        );
        assert_eq!(
            tray_launch(false, false),
            TrayLaunch::Run { connect: false },
            "opening the window does not dial by itself"
        );
        assert_eq!(
            tray_launch(true, true),
            TrayLaunch::Signal {
                message: TRAY_START
            },
            "a second sign-in launch must wake the node in the open tray"
        );
        assert_eq!(
            tray_launch(false, true),
            TrayLaunch::Signal { message: TRAY_SHOW }
        );
    }

    #[test]
    fn a_live_supervisor_is_not_shown_stopped_on_a_stale_status_file() {
        let stale = view_at("Stopped", false);
        let starting = apply_supervisor_view(stale, true, false, false, None);
        assert_eq!(starting.connection, "Connecting");
        assert!(starting.running);

        let online = view_at("Online", true);
        let held = apply_supervisor_view(online, true, false, false, None);
        assert_eq!(held.connection, "Online");
        assert!(held.running);

        let mut offline = view_at("Offline", true);
        offline.detail = "websocket: reset".into();
        let shown = apply_supervisor_view(offline, true, false, false, None);
        assert_eq!(shown.connection, "Offline");
        assert_eq!(shown.detail, "websocket: reset");

        let stopped = apply_supervisor_view(view_at("Online", true), false, false, false, None);
        assert_eq!(stopped.connection, "Stopped");
        assert!(!stopped.running);

        let halted = apply_supervisor_view(view_at("Online", true), true, true, false, None);
        assert_eq!(halted.connection, "Stopped");
    }

    #[test]
    fn enrolled_without_account_is_not_alarming_not_signed_in() {
        let link = LinkStatus {
            state: LinkState::Online,
            detail: String::new(),
            relay_url: "wss://relay.example.com".into(),
            name: "probe".into(),
            node_id: "abc".into(),
            enrolled: true,
            pid: 9,
            updated_unix: 10,
        };
        let node = NodeSnap {
            name: "probe".into(),
            relay_url: "wss://relay.example.com".into(),
            pairing_pending: false,
        };
        let account = AccountSnap {
            user: None,
            has_token: false,
        };
        let view = describe(Some(&link), &node, &account, true);
        assert_eq!(view.pairing, "Paired");
        assert_eq!(view.account, "Paired without account sign-in");
        assert_eq!(
            view.detail,
            "Sign in to manage shares and devices from this PC."
        );
        assert!(view.running);
        assert!(view.enrolled);
    }

    #[test]
    fn legacy_token_account_is_distinct_from_a_username() {
        let node = NodeSnap {
            name: String::new(),
            relay_url: String::new(),
            pairing_pending: false,
        };
        let account = AccountSnap {
            user: None,
            has_token: true,
        };
        let view = describe(None, &node, &account, false);
        assert_eq!(view.account, "Legacy token saved");
        assert_eq!(view.relay, "relay not set");
        assert_eq!(view.node_name, "this computer");
    }

    #[test]
    fn autostart_paths_reject_control_characters() {
        for bad in [
            "C:\\agentlink\\node\r\nbad",
            "C:\\agentlink\\bad\npath",
            "C:\\agentlink\\bad\rpath",
            "C:\\agentlink\\bad\0path",
        ] {
            assert!(validate_autostart_path(Path::new(bad)).is_err(), "{bad:?}");
            assert!(
                try_autostart_command(Path::new(r"C:\agentlink\agentlink.exe"), Path::new(bad))
                    .is_err()
            );
            assert!(
                install_user_autostart(
                    Path::new(r"C:\agentlink\agentlink.exe"),
                    Path::new(bad)
                )
                .is_err()
            );
            assert!(
                build_windows_lnk(Path::new(r"C:\agentlink\agentlink.exe"), Path::new(bad))
                    .is_err()
            );
        }
        assert!(validate_autostart_path(Path::new(r"C:\Users\Ada Lovelace\node\")).is_ok());
    }

    #[test]
    fn windows_quoting_and_splitting_handle_trailing_backslashes_and_quotes() {
        let samples = [
            r"C:\Users\Ada Lovelace\node\",
            r"C:\Users\Ada\node\\",
            r#"C:\Users\a"b\node"#,
            r#"C:\Users\a\"b\node\"#,
            r#"plain"#,
            r"\\",
            r#"""#,
            r#"\"#,
        ];
        for sample in samples {
            let quoted = quote_windows_arg(sample);
            let parsed = split_windows_command(&quoted);
            assert_eq!(parsed, vec![sample.to_string()], "quoted={quoted}");
        }
        // Specific CommandLineToArgvW encoding checks:
        assert_eq!(
            quote_windows_arg(r"C:\agentlink\node\"),
            r#""C:\agentlink\node\\""#
        );
        assert_eq!(
            quote_windows_arg(r#"a\"b"#),
            r#""a\\\"b""#
        );

        let cmd = autostart_command(
            Path::new(r"C:\Program Files\agentlink\agentlink.exe"),
            Path::new(r"C:\agentlink\node\"),
        );
        assert_eq!(
            data_dir_from_command(&cmd),
            Some(PathBuf::from(r"C:\agentlink\node\"))
        );
        assert!(command_launches_tray(
            &cmd,
            Path::new(r"C:\agentlink\node"),
            false
        ));
    }

    #[test]
    fn windows_lnk_builder_round_trips_unicode_spaces_and_trailing_backslash() {
        let exe = Path::new(r"C:\Users\测试 Ada\agentlink\agentlink-gui.exe");
        let data = Path::new(r"C:\Users\测试 Ada\node\");
        let bytes = build_windows_lnk(exe, data).expect("build .lnk");
        assert!(bytes.len() > 76);
        assert_eq!(&bytes[0..4], &LNK_HEADER_SIZE.to_le_bytes());
        assert_eq!(&bytes[4..20], &LNK_CLSID);

        let parsed = parse_windows_lnk_command(&bytes).expect("parse .lnk");
        assert_eq!(agentlink_subcommand(&parsed).as_deref(), Some("tray"));
        assert!(command_launches_tray(&parsed, data, false), "{parsed}");
        assert_eq!(data_dir_from_command(&parsed), Some(data.to_path_buf()));

        // Plan mentions agentlink.lnk, never agentlink.cmd.
        let plan = autostart_plan(exe, data);
        assert!(plan.contains(STARTUP_SHORTCUT), "{plan}");
        assert!(!plan.contains(STARTUP_SCRIPT), "{plan}");

        // UNC / non-drive fallback path round-trips via EnvironmentVariableDataBlock.
        let unc_exe = Path::new(r"\\fileserver\tools\agentlink-gui.exe");
        let unc_bytes = build_windows_lnk(unc_exe, data).expect("build UNC .lnk");
        let unc_parsed = parse_windows_lnk_command(&unc_bytes).expect("parse UNC .lnk");
        assert_eq!(agentlink_subcommand(&unc_parsed).as_deref(), Some("tray"));
        assert_eq!(data_dir_from_command(&unc_parsed), Some(data.to_path_buf()));

        // cmd.exe metacharacters (%VAR%, &, |, ^, !) are preserved literally in .lnk.
        let meta_dir = Path::new(r"C:\Users\A&B %TEMP% ^!|node\");
        let meta_bytes = build_windows_lnk(exe, meta_dir).expect("build metachar .lnk");
        let meta_parsed = parse_windows_lnk_command(&meta_bytes).expect("parse metachar .lnk");
        assert_eq!(
            data_dir_from_command(&meta_parsed),
            Some(meta_dir.to_path_buf())
        );
    }

    #[test]
    fn preferred_gui_binary_uses_sibling_agentlink_gui_exe_when_present_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let cli = dir.path().join("agentlink.exe");
        let gui = dir.path().join("agentlink-gui.exe");
        std::fs::write(&cli, b"cli").unwrap();
        assert_eq!(preferred_gui_binary(&cli), cli);

        std::fs::write(&gui, b"gui").unwrap();
        assert_eq!(preferred_gui_binary(&cli), gui);

        let cmd = autostart_command(&cli, Path::new(r"C:\data\node"));
        assert!(cmd.contains("agentlink-gui.exe"), "{cmd}");
        assert_eq!(agentlink_subcommand(&cmd).as_deref(), Some("tray"));
        assert!(command_launches_tray(
            &cmd,
            Path::new(r"C:\data\node"),
            false
        ));

        // Synthetic non-existent path stays unchanged.
        let synthetic = Path::new(r"C:\nonexistent-agentlink-test\agentlink.exe");
        assert_eq!(preferred_gui_binary(synthetic), synthetic);

        // Controller launch args forward both --config-dir and --data-dir.
        let args = controller_launch_args(Path::new(r"C:\cfg"), Path::new(r"C:\data"));
        assert_eq!(
            args,
            vec![
                OsString::from("--config-dir"),
                OsString::from(r"C:\cfg"),
                OsString::from("controller"),
                OsString::from("--data-dir"),
                OsString::from(r"C:\data"),
            ]
        );
    }

    #[test]
    fn legacy_cmd_is_retired_when_lnk_or_hkcu_owns_tray_autostart() {
        let (node, tray, data) = probe_commands();
        let exe = PathBuf::from(r"C:\Users\probe\AppData\Local\agentlink\agentlink.exe");
        let entries = vec![
            RunValue {
                name: STARTUP_SHORTCUT.into(),
                command: tray.clone(),
            },
            RunValue {
                name: STARTUP_SCRIPT.into(),
                command: node,
            },
        ];
        let plan = plan_run_migration(&entries, &exe, &data, false, false);
        assert_eq!(plan.delete_names, vec![STARTUP_SCRIPT.to_string()]);

        // When HKCU Run has tray, both agentlink.lnk and legacy agentlink.cmd are cleaned up.
        let entries_both = vec![
            RunValue {
                name: RUN_VALUE_NAME.into(),
                command: tray.clone(),
            },
            RunValue {
                name: STARTUP_SHORTCUT.into(),
                command: tray.clone(),
            },
            RunValue {
                name: STARTUP_SCRIPT.into(),
                command: tray,
            },
        ];
        let plan_both = plan_run_migration(&entries_both, &exe, &data, false, false);
        assert_eq!(
            plan_both.delete_names,
            vec![STARTUP_SHORTCUT.to_string(), STARTUP_SCRIPT.to_string()]
        );
    }

    #[test]
    fn standalone_node_block_reason_tracks_live_node_lock() {
        let dir = tempfile::tempdir().unwrap();
        // Unlocked / absent lock: never blocks, and does not create node.lock.
        assert_eq!(standalone_node_block_reason(dir.path()), None);
        assert!(!dir.path().join(NODE_LOCK_FILE).exists());

        // Acquire exclusive lock matching agentlink_node::lock::acquire_node_lock.
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.path().join(NODE_LOCK_FILE))
            .unwrap();
        lock_file.try_lock().unwrap();

        let reason = standalone_node_block_reason(dir.path()).expect("should block while locked");
        assert!(reason.contains("node.lock"), "{reason}");

        // Once the holder exits / drops the lock, standalone node is allowed again.
        drop(lock_file);
        assert_eq!(standalone_node_block_reason(dir.path()), None);
    }

    #[test]
    fn supervisor_stop_with_timeout_joins_cleanly_and_writes_stopped_status() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = TrayContext {
            json: false,
            relay: None,
            fingerprint: None,
            trust: None,
            config_dir: dir.path().to_path_buf(),
            data_dir: Some(dir.path().to_path_buf()),
            name: None,
            background: false,
            action: TrayAction::Run,
        };
        let mut sup = Supervisor::new(&ctx, dir.path().to_path_buf());
        let token = CancellationToken::new();
        let child_token = token.clone();
        sup.shutdown = Some(token);
        sup.thread = Some(std::thread::spawn(move || {
            while !child_token.is_cancelled() {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        }));
        assert!(sup.running());
        assert!(sup.stop_with_timeout(Duration::from_secs(2)));
        assert!(!sup.running());
        let status = agentlink_node::read_status(dir.path()).expect("status.json written");
        assert_eq!(status.state, LinkState::Stopped);

        // Bounded timeout: a stuck thread does not block beyond timeout and still writes Stopped.
        let mut stuck = Supervisor::new(&ctx, dir.path().to_path_buf());
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        stuck.thread = Some(std::thread::spawn(move || {
            let _ = rx.recv_timeout(Duration::from_secs(2));
            Ok(())
        }));
        let start = Instant::now();
        assert!(!stuck.stop_with_timeout(Duration::from_millis(80)));
        assert!(start.elapsed() < Duration::from_secs(1));
        let status = agentlink_node::read_status(dir.path()).expect("status.json written");
        assert_eq!(status.state, LinkState::Stopped);
        let _ = tx.send(());
    }

    #[test]
    fn rotating_tray_log_caps_size_and_rotates_to_backup() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("tray.log");
        let backup_path = dir.path().join("tray.log.1");
        let maker = RotatingLogMakeWriter::new(log_path.clone(), 64);

        for idx in 0..8 {
            let mut writer = maker.make_writer();
            writeln!(writer, "line-{idx}-0123456789abcdef").unwrap();
            writer.flush().unwrap();
        }
        assert!(log_path.is_file(), "active tray.log must exist");
        assert!(backup_path.is_file(), "rotated tray.log.1 must exist");
        let active_len = std::fs::metadata(&log_path).unwrap().len();
        let backup_len = std::fs::metadata(&backup_path).unwrap().len();
        assert!(active_len <= 64, "active log exceeded cap: {active_len}");
        assert!(backup_len > 0 && backup_len <= 64, "backup len: {backup_len}");
    }

    #[test]
    fn decode_reg_utf16_handles_missing_and_multiple_trailing_nuls() {
        fn utf16le(s: &str) -> Vec<u8> {
            s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
        }
        // Standard NUL-terminated REG_SZ / REG_EXPAND_SZ
        assert_eq!(decode_reg_utf16(&utf16le("agentlink\0")), "agentlink");
        // Multiple trailing NULs
        assert_eq!(decode_reg_utf16(&utf16le("agentlink\0\0")), "agentlink");
        // Non-NUL-terminated REG_SZ must NOT chop the last character!
        assert_eq!(decode_reg_utf16(&utf16le("agentlink")), "agentlink");
        // Empty / NUL-only
        assert_eq!(decode_reg_utf16(&[]), "");
        assert_eq!(decode_reg_utf16(&utf16le("\0")), "");
    }

    #[test]
    fn sign_out_refreshes_expired_access_token_before_server_logout() {
        let dir = tempfile::tempdir().unwrap();
        let pin = format!("sha256:{}", "ab".repeat(32));
        let settings = ClientSettings {
            relay: "wss://relay.example.com:7443".into(),
            token: "expired-access".into(),
            fingerprint: pin.clone(),
            trust: None,
        };
        config::save_session(dir.path(), &settings, "ada", "old-refresh", 100).unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let refreshed_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let logged_out = Arc::new(Mutex::new(None::<(String, String)>));

        let r_flag = Arc::clone(&refreshed_called);
        let l_slot = Arc::clone(&logged_out);
        rt.block_on(sign_out_with(
            dir.path(),
            500, // now > access_expires_unix (100) -> expired!
            move |_relay, _fp, _trust, _id, refresh| async move {
                assert_eq!(refresh, "old-refresh");
                r_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(("fresh-access".into(), "rotated-refresh".into()))
            },
            move |settings, _id, _cfg_dir, refresh| async move {
                *l_slot.lock().unwrap() = Some((settings.token, refresh));
                Ok(())
            },
        ))
        .unwrap();

        assert!(refreshed_called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            *logged_out.lock().unwrap(),
            Some(("fresh-access".to_string(), "rotated-refresh".to_string()))
        );
        let after = config::load_file(dir.path()).unwrap();
        assert_eq!(after.token.as_deref(), Some(""));
        assert_eq!(after.refresh_token, None);
        assert_eq!(after.user, None);
        assert!(config::session_lock_path(dir.path()).exists());
    }

    #[test]
    fn sign_out_skips_refresh_when_access_token_is_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let pin = format!("sha256:{}", "ab".repeat(32));
        let settings = ClientSettings {
            relay: "wss://relay.example.com:7443".into(),
            token: "still-fresh".into(),
            fingerprint: pin,
            trust: None,
        };
        config::save_session(dir.path(), &settings, "ada", "live-refresh", 1000).unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let logged_out = Arc::new(Mutex::new(None::<(String, String)>));
        let l_slot = Arc::clone(&logged_out);
        rt.block_on(sign_out_with(
            dir.path(),
            500, // 500s remaining > 30s skew -> fresh!
            |_relay, _fp, _trust, _id, _refresh| async move {
                panic!("refresh must not be called when access token is fresh");
            },
            move |settings, _id, _cfg_dir, refresh| async move {
                *l_slot.lock().unwrap() = Some((settings.token, refresh));
                Ok(())
            },
        ))
        .unwrap();

        assert_eq!(
            *logged_out.lock().unwrap(),
            Some(("still-fresh".to_string(), "live-refresh".to_string()))
        );
        let after = config::load_file(dir.path()).unwrap();
        assert_eq!(after.refresh_token, None);
    }

    #[test]
    fn stream_consent_persists_in_node_json_and_is_honored_by_load_node() {
        std::env::set_var("AGENTLINK_DESKTOP", "mock");
        let dir = tempfile::tempdir().unwrap();
        let token = "ef".repeat(32);
        let pin = format!("sha256:{}", "cd".repeat(32));
        let invite = agentlink_core::encode_invite(&agentlink_core::Invite {
            relay: "wss://relay.example:7443".into(),
            fingerprint: pin,
            trust: None,
            token,
            name: "workstation".into(),
        })
        .unwrap();

        apply_pairing_text(dir.path(), &invite, None, None, None, None).unwrap();
        assert_eq!(read_stream_consent(dir.path()).as_deref(), Some("notify"));

        set_stream_consent(dir.path(), "prompt").unwrap();
        assert_eq!(read_stream_consent(dir.path()).as_deref(), Some("prompt"));

        // Re-applying an invite preserves the persisted stream_consent instead of clobbering it.
        apply_pairing_text(dir.path(), &invite, None, None, None, None).unwrap();
        assert_eq!(read_stream_consent(dir.path()).as_deref(), Some("prompt"));

        // Invalid consent fails closed in set_stream_consent and load_node.
        assert!(set_stream_consent(dir.path(), "bogus").is_err());
        let mut raw: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("node.json")).unwrap())
                .unwrap();
        raw["stream_consent"] = Value::String("invalid-mode".into());
        std::fs::write(dir.path().join("node.json"), raw.to_string()).unwrap();
        let launch = NodeLaunch {
            relay: None,
            fingerprint: None,
            trust: None,
            data_dir: dir.path().to_path_buf(),
            name: None,
        };
        assert!(
            load_node(&launch).is_err(),
            "load_node must honor node.json stream_consent and fail closed on invalid mode"
        );
    }

    #[test]
    fn sign_in_defaults_and_trust_parsing_work() {
        let dir = tempfile::tempdir().unwrap();
        let pin = format!("sha256:{}", "12".repeat(32));
        std::fs::write(
            dir.path().join("node.json"),
            serde_json::json!({
                "relay_url": "wss://node-relay.example.com",
                "fingerprint": pin,
                "trust": "system",
            })
            .to_string(),
        )
        .unwrap();
        let ctx = TrayContext {
            json: false,
            relay: None,
            fingerprint: None,
            trust: None,
            config_dir: dir.path().to_path_buf(),
            data_dir: Some(dir.path().to_path_buf()),
            name: None,
            background: false,
            action: TrayAction::Run,
        };
        let defaults = prefill_sign_in_defaults(&ctx, dir.path());
        assert_eq!(defaults.relay, "wss://node-relay.example.com");
        assert_eq!(defaults.trust, format!("{pin}+system"));

        assert_eq!(parse_trust_input("").unwrap(), (None, None));
        assert_eq!(
            parse_trust_input("system").unwrap(),
            (Some("system".into()), Some("system".into()))
        );
        assert_eq!(
            parse_trust_input(&pin).unwrap(),
            (Some(pin.clone()), None)
        );
        assert_eq!(
            parse_trust_input(&format!("{pin}+webpki")).unwrap(),
            (Some(pin), Some("webpki".into()))
        );
        assert!(parse_trust_input("not-a-valid-trust").is_err());
    }

    #[test]
    fn instance_tag_normalizes_same_dir_and_separates_distinct_dirs() {
        let a1 = Path::new(r"C:\Users\Ada\node");
        let a2 = Path::new(r"\\?\c:/users/ada/node\");
        let b = Path::new(r"D:\other\node");
        assert_eq!(data_dir_instance_tag(a1), data_dir_instance_tag(a2));
        assert_eq!(tray_mutex_name(a1), tray_mutex_name(a2));
        assert_eq!(tray_window_class(a1), tray_window_class(a2));
        assert_ne!(data_dir_instance_tag(a1), data_dir_instance_tag(b));
        assert!(tray_mutex_name(a1).starts_with(r"Local\agentlink-tray-"));
    }
}
