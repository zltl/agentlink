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

use std::path::{Path, PathBuf};
use std::thread::JoinHandle;

use agentlink_core::{config, Client, ClientSettings, Identity};
use agentlink_node::{save_node_config, write_status, LinkState, LinkStatus, NodeConfig};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::node_cfg::{self, NodeArgs};
use crate::{emit, version};

pub const RUN_VALUE_NAME: &str = "agentlink";
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub const STARTUP_SCRIPT: &str = "agentlink.cmd";

/// `WM_APP` is `0x8000`. Posted to the tray window from a second process.
pub const TRAY_CALLBACK: u32 = 0x8000 + 1;
pub const TRAY_SHOW: u32 = 0x8000 + 2;
pub const TRAY_QUIT: u32 = 0x8000 + 3;
pub const TRAY_START: u32 = 0x8000 + 4;

const INVITE_PREFIX: &str = "agentlink-invite:";

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
    } else if enrolled && account.user.as_deref().filter(|u| !u.is_empty()).is_none() && !account.has_token {
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

/// Command line stored in HKCU Run. The executable and data directory are quoted.
pub fn autostart_command(binary: &Path, data_dir: &Path) -> String {
    format!(
        "{} tray --background --data-dir {}",
        quote_windows_arg(&binary.to_string_lossy()),
        quote_windows_arg(&data_dir.to_string_lossy()),
    )
}

pub fn autostart_plan(binary: &Path, data_dir: &Path) -> String {
    format!(
        "\
# User-scope autostart. No administrator and no scheduled task.
# HKCU\\{RUN_KEY}
# Value name: {RUN_VALUE_NAME}
# The tray starts at sign-in and runs the node in this session.
{}
# If that registry value cannot be written, the same command is saved as
# %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{STARTUP_SCRIPT}
",
        autostart_command(binary, data_dir),
    )
}

pub fn quote_windows_arg(text: &str) -> String {
    let escaped = text.replace('"', "\\\"");
    format!("\"{escaped}\"")
}

pub fn split_windows_command(command: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' && in_quotes && chars.peek() == Some(&'"') {
            current.push('"');
            chars.next();
            continue;
        }
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
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

pub fn startup_script_contents(binary: &Path, data_dir: &Path) -> String {
    format!(
        "@echo off\r\nstart \"\" {}\r\n",
        autostart_command(binary, data_dir)
    )
}

/// One `HKCU\...\Run` value, or the Startup-folder script treated as a value.
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
    /// Other Run value names to delete. [`STARTUP_SCRIPT`] removes the file.
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
    fn norm(path: &Path) -> String {
        path.to_string_lossy()
            .trim()
            .trim_matches('"')
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    }
    let left = norm(left);
    !left.is_empty() && left == norm(right)
}

fn exe_is_agentlink(arg: &str) -> bool {
    let file = arg.rsplit(['\\', '/']).next().unwrap_or(arg);
    let file = file.trim_matches('"');
    let lower = file.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    stem == "agentlink"
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
            entry.name != STARTUP_SCRIPT
                && command_launches_tray(&entry.command, data_dir, missing_dir_matches)
                && (write_command.is_none() || !entry.name.eq_ignore_ascii_case(RUN_VALUE_NAME))
        });

    let mut delete_names = Vec::new();
    for entry in entries {
        if entry.name.eq_ignore_ascii_case(RUN_VALUE_NAME) {
            continue;
        }
        if entry.name == STARTUP_SCRIPT {
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
                let _ = remove_startup_script();
                for name in &plan.delete_names {
                    if name == STARTUP_SCRIPT {
                        continue;
                    }
                    let _ = delete_named_run_value(name);
                }
                Ok(())
            }
            Err(err) => {
                write_startup_script(binary, data_dir).with_context(|| {
                    format!("HKCU Run failed ({err:#}); Startup folder fallback also failed")
                })?;
                for name in &plan.delete_names {
                    if name == STARTUP_SCRIPT {
                        continue;
                    }
                    let _ = delete_named_run_value(name);
                }
                eprintln!(
                    "HKCU Run was not writable; saved {STARTUP_SCRIPT} in the Startup folder"
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
                entry.name.eq_ignore_ascii_case(RUN_VALUE_NAME) || entry.name == STARTUP_SCRIPT
            })
            .filter_map(|entry| data_dir_from_command(&entry.command))
            .collect();
        let _ = delete_run_value();
        let _ = remove_startup_script();
        for entry in &entries {
            if entry.name.eq_ignore_ascii_case(RUN_VALUE_NAME) || entry.name == STARTUP_SCRIPT {
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

/// Why `agentlink node` must exit before dialing, if the tray already owns this directory.
pub fn standalone_node_block_reason(data_dir: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        let entries = collect_autostart_entries();
        if tray_autostart_blocks_node(&entries, data_dir, missing_dir_matches(data_dir)) {
            return Some(
                "not dialing: Windows start-on-login already runs the tray for this data directory (`tray --background`). A second `agentlink node` resets that WebSocket. The tray is the user-scope node."
                    .into(),
            );
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = data_dir;
        None
    }
}

pub fn autostart_enabled() -> bool {
    #[cfg(windows)]
    {
        read_run_value().is_some() || startup_script_path().is_some_and(|path| path.exists())
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
        if let Some(path) = startup_script_path() {
            if let Ok(text) = std::fs::read_to_string(path) {
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(rest) = line.strip_prefix("start \"\" ") {
                        if let Some(dir) = data_dir_from_command(rest) {
                            return Some(dir);
                        }
                    }
                }
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
        crate::tray_win::post(message)
    }
    #[cfg(not(windows))]
    {
        let _ = message;
        false
    }
}

pub fn spawn_tray(binary: &Path, data_dir: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW via process::detached — do not OR DETACHED_PROCESS;
        // Windows ignores CREATE_NO_WINDOW when that bit is set.
        agentlink_core::process::detached(binary)
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
        }
    }

    pub fn start(&mut self) {
        self.stop_requested = false;
        self.restart = false;
        if !self.running() {
            self.spawn();
        }
    }

    pub fn stop(&mut self) {
        self.restart = false;
        self.stop_requested = true;
        self.cancel();
        if !self.running() {
            note_status(&self.launch.data_dir, "", "", LinkState::Stopped, "stopped");
        }
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

fn load_node(launch: &NodeLaunch) -> Result<NodeConfig> {
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
        stream_consent: Some("notify".into()),
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

/// Password login, then enroll this machine's node key under that account.
pub async fn sign_in_and_enroll(request: SignInRequest) -> Result<String> {
    let username = request.username.trim().to_string();
    if username.is_empty() {
        bail!("username is required");
    }
    if request.password.is_empty() {
        bail!("password is required");
    }
    let launch = NodeLaunch {
        relay: request.relay.clone(),
        fingerprint: request.fingerprint.clone(),
        trust: request.trust.clone(),
        data_dir: request.data_dir.clone(),
        name: request.name.clone(),
    };
    let node = load_node(&launch)?;
    let parsed = agentlink_core::RelayTrust::parse(&node.fingerprint, node.trust.as_deref())
        .map_err(|err| anyhow!(err.to_string()))?;
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
    Ok(session.user)
}

pub async fn sign_out(config_dir: &Path) -> Result<()> {
    let file = config::load_file(config_dir).unwrap_or_default();
    if let Some(refresh) = file.refresh_token.clone() {
        let mut relay = file.relay.clone().unwrap_or_default();
        let fingerprint = file.fingerprint.clone().unwrap_or_default();
        let mut trust = file.trust.clone();
        agentlink_core::apply_relay_defaults(&mut relay, &fingerprint, &mut trust);
        let token = file.token.clone().unwrap_or_default();
        if !relay.is_empty() && !token.is_empty() {
            let settings = ClientSettings {
                relay,
                token,
                fingerprint,
                trust,
            };
            if let Ok(identity) = Identity::load_or_create(&config_dir.join("identity.json")) {
                if let Ok(client) = Client::connect_identity(&settings, identity, true).await {
                    client.remember_grants(config_dir);
                    let _ = client.logout_session(Some(refresh)).await;
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
    if text.is_empty() {
        bail!("paste an invite from `agentlink pair`, or a pairing token");
    }
    let (invite, pairing_token) = if text.starts_with(INVITE_PREFIX) {
        (Some(text.to_string()), None)
    } else if text.chars().any(char::is_whitespace) {
        bail!("that text is not an invite or a pairing token");
    } else {
        (None, Some(text.to_string()))
    };
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
        stream_consent: Some("notify".into()),
    })?;
    save_node_config(&config)?;
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

pub fn init_tray_log(data_dir: &Path) {
    let _ = std::fs::create_dir_all(data_dir);
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("tray.log"))
    else {
        return;
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(move || file.try_clone().expect("tray log"))
        .try_init();
    tracing::info!(version = version::current(), "tray starting");
}

#[cfg(windows)]
fn startup_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(|root| PathBuf::from(root).join(r"Microsoft\Windows\Start Menu\Programs\Startup"))
}

#[cfg(windows)]
fn startup_script_path() -> Option<PathBuf> {
    startup_dir().map(|dir| dir.join(STARTUP_SCRIPT))
}

#[cfg(windows)]
fn write_startup_script(binary: &Path, data_dir: &Path) -> Result<()> {
    let dir = startup_dir().context("APPDATA is not set")?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join(STARTUP_SCRIPT),
        startup_script_contents(binary, data_dir),
    )?;
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
        if name == STARTUP_SCRIPT {
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
    use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY_CURRENT_USER, KEY_QUERY_VALUE, REG_SZ,
        REG_VALUE_TYPE,
    };

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
        let mut entries = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name_buf = vec![0u16; 256];
            let mut name_len = (name_buf.len() - 1) as u32;
            let mut kind = REG_VALUE_TYPE::default();
            let mut data = vec![0u8; 8192];
            let mut data_len = data.len() as u32;
            let status = RegEnumValueW(
                key,
                index,
                Some(PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut kind.0),  // windows 0.61 RegEnumValueW lpType is *mut u32
                Some(data.as_mut_ptr()),
                Some(&mut data_len),
            );
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status.is_err() {
                let _ = RegCloseKey(key);
                return Err(anyhow!("enumerate HKCU Run values: {status:?}"));
            }
            index += 1;
            if kind != REG_SZ || name_len == 0 {
                continue;
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let bytes = (data_len as usize).min(data.len());
            let wide_len = (bytes / 2).saturating_sub(1);
            let chars = data[..bytes]
                .chunks_exact(2)
                .take(wide_len)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
            let command = String::from_utf16_lossy(&chars.collect::<Vec<_>>())
                .trim_end_matches('\u{0}')
                .trim()
                .to_string();
            if !name.is_empty() && !command.is_empty() {
                entries.push(RunValue { name, command });
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
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER, KEY_QUERY_VALUE, REG_SZ,
        REG_VALUE_TYPE,
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
            || kind != REG_SZ
            || len < 2
        {
            let _ = RegCloseKey(key);
            return None;
        }
        let mut buf = vec![0u8; len as usize + 2];
        let ok = RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr()),
            Some(&mut len),
        )
        .is_ok();
        let _ = RegCloseKey(key);
        if !ok {
            return None;
        }
        let wide_len = (len as usize / 2).saturating_sub(1);
        let words = buf
            .chunks_exact(2)
            .take(wide_len)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let text = String::from_utf16_lossy(&words);
        let text = text.trim_end_matches('\u{0}').trim().to_string();
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
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
        let invite = agentlink_core::encode_invite(&agentlink_core::Invite {
            relay: "wss://relay.example:7443".into(),
            fingerprint: "sha256:ab".into(),
            trust: None,
            token: "super-secret-token".into(),
            name: "box".into(),
        })
        .unwrap();
        let name = apply_pairing_text(dir.path(), &invite, None, None, None, None).unwrap();
        assert_eq!(name, "box");
        let text = std::fs::read_to_string(dir.path().join("node.json")).unwrap();
        assert!(text.contains("wss://relay.example:7443"), "{text}");
        assert!(text.contains("super-secret-token"), "{text}");
        assert!(text.contains("sha256:ab"), "{text}");
        let plan = autostart_plan(Path::new(r"C:\agentlink\agentlink.exe"), dir.path());
        assert!(!plan.contains("super-secret-token"), "{plan}");
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
}
