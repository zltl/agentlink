//! Install the node as a background service.
//!
//! Default scope is the user session: systemd --user, a macOS LaunchAgent
//! limited to the Aqua session, or the Windows tray (HKCU Run, no
//! administrator). That is the session a desktop phase can see. System scope
//! (systemd system unit, LaunchDaemon, Windows service) starts at boot and
//! does not join the logged-in GUI.

use std::fs;
use std::path::{Path, PathBuf};

use agentlink_core::process;
use agentlink_core::{parse_access, NodePolicy};
use agentlink_node::{save_node_config, NodeConfig};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;

use crate::node_cfg;
use crate::version;

pub const NODE_NAME: &str = "agentlink-node";
pub const UPDATE_NAME: &str = "agentlink-update";
pub const LAUNCHD_NODE: &str = "dev.agentlink.node";
pub const LAUNCHD_UPDATE: &str = "dev.agentlink.update";

/// Variables a phase-2 desktop handler needs from the user's GUI session.
const GUI_ENV: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Scope {
    User,
    System,
}

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Write the service definition, remember the relay, and start the node.
    Install(InstallArgs),
    /// Remove the service definition. The node data directory stays unless `--purge`.
    Uninstall(UninstallArgs),
    /// Start the service.
    Start(ControlArgs),
    /// Stop the service.
    Stop(ControlArgs),
    /// Restart the service.
    Restart(ControlArgs),
    /// Print whether the service is running.
    Status(ControlArgs),
    /// Show recent service logs.
    Logs(LogsArgs),
    /// Windows Service Control Manager entry. Not used on other systems.
    #[command(hide = true)]
    Run {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

#[derive(Args, Debug)]
pub struct LogsArgs {
    #[arg(long, value_enum, default_value = "user")]
    pub scope: Scope,
    /// Number of trailing lines to show.
    #[arg(short = 'n', long, default_value_t = 50)]
    pub lines: usize,
    /// Stream new log lines as they are written.
    #[arg(short = 'f', long)]
    pub follow: bool,
}

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// `user` (default) joins the GUI session. `system` starts at boot and does not.
    #[arg(long, value_enum, default_value = "user")]
    pub scope: Scope,
    /// Node display name. Defaults to the hostname.
    #[arg(long)]
    pub name: Option<String>,
    /// One-time token from `agentlink pair`. Omit to mint one with `--token`.
    /// Prefer `AGENTLINK_PAIRING_TOKEN` so the secret is not visible in `ps` argv.
    #[arg(long, env = "AGENTLINK_PAIRING_TOKEN")]
    pub pairing_token: Option<String>,
    /// Invite from `agentlink pair`. Flags and `--pairing-token` override it.
    #[arg(long)]
    pub invite: Option<String>,
    /// Relay enrollment preset for the owner (`exec` by default; pass `full` for desktop/screen).
    #[arg(long, default_value = "exec")]
    pub access: String,
    /// Local node ceiling intersected with every signed grant (`exec` when omitted; pass `full` for desktop/screen).
    #[arg(long)]
    pub max_access: Option<String>,
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    #[arg(long)]
    pub root: Option<PathBuf>,
    /// Binary the service should launch. Defaults to this executable.
    #[arg(long)]
    pub binary: Option<PathBuf>,
    /// Account for `--scope system` on Linux and macOS.
    #[arg(long)]
    pub run_as: Option<String>,
    /// macOS LaunchAgent: do not limit the job to the Aqua GUI session.
    #[arg(long)]
    pub headless: bool,
    /// Install and enable, but do not start.
    #[arg(long)]
    pub no_start: bool,
    /// Also install a daily timer that runs `agentlink update --yes`.
    #[arg(long)]
    pub auto_update: bool,
    /// Print the unit and redacted node config, and write nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// Lifetime of a pairing token minted during install.
    #[arg(long, default_value_t = 30)]
    pub ttl_minutes: u64,
}

#[derive(Args, Debug)]
pub struct UninstallArgs {
    #[arg(long, value_enum, default_value = "user")]
    pub scope: Scope,
    /// Delete the node data directory after the service is removed.
    #[arg(long)]
    pub purge: bool,
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ControlArgs {
    #[arg(long, value_enum, default_value = "user")]
    pub scope: Scope,
}

#[derive(Clone, Debug)]
pub struct Env {
    pub json: bool,
    pub relay: Option<String>,
    pub token: Option<String>,
    pub fingerprint: Option<String>,
    pub trust: Option<String>,
    pub config_dir: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct NodeSpec {
    binary: PathBuf,
    data_dir: PathBuf,
    work_dir: PathBuf,
    scope: Scope,
    run_as: Option<String>,
    headless: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceKind {
    Systemd,
    Launchd,
    /// Legacy user-scope scheduled task. New installs use [`Self::WindowsRun`].
    WindowsTask,
    /// HKCU Run entry that starts the tray at sign-in. No administrator.
    WindowsRun,
    WindowsService,
}

#[derive(Clone, Debug)]
pub struct InstalledService {
    pub scope: Scope,
    pub kind: ServiceKind,
    pub active: bool,
}

pub fn run_windows_service(data_dir: Option<PathBuf>) -> i32 {
    #[cfg(windows)]
    {
        match crate::service_win::run_dispatcher(data_dir) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("error: {err:#}");
                1
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = data_dir;
        eprintln!("error: `agentlink service run` is only the Windows service entry point");
        1
    }
}

pub async fn dispatch(env: &Env, action: &Action) -> Result<i32> {
    match action {
        Action::Install(args) => install(env, args).await,
        Action::Uninstall(args) => uninstall(env, args),
        Action::Start(args) => {
            start(args.scope)?;
            emit(env.json, json!({"ok": true, "running": true}), || {
                println!("started {}", NODE_NAME);
            });
            Ok(0)
        }
        Action::Stop(args) => {
            stop(args.scope)?;
            emit(env.json, json!({"ok": true, "running": false}), || {
                println!("stopped {}", NODE_NAME);
            });
            Ok(0)
        }
        Action::Restart(args) => {
            restart(args.scope)?;
            emit(env.json, json!({"ok": true, "running": true, "restarted": true}), || {
                println!("restarted {}", NODE_NAME);
            });
            Ok(0)
        }
        Action::Status(args) => status(env, args.scope),
        Action::Logs(args) => logs(env, args),
        Action::Run { .. } => {
            bail!("`service run` is started by the Windows Service Control Manager");
        }
    }
}

async fn install(env: &Env, args: &InstallArgs) -> Result<i32> {
    ensure_scope_privileges(args.scope, args.dry_run)?;
    let binary = match &args.binary {
        Some(path) => path.clone(),
        None => current_binary()?,
    };
    let data_dir = match &args.data_dir {
        Some(path) => path.clone(),
        None => default_data_dir(args.scope)?,
    };
    let run_as = resolve_run_as(args.scope, args.run_as.clone(), args.dry_run)?;
    let spec = NodeSpec {
        binary,
        data_dir: data_dir.clone(),
        work_dir: work_dir(args.scope, &data_dir),
        scope: args.scope,
        run_as,
        headless: args.headless,
    };
    let invited = match args
        .invite
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(text) => {
            Some(agentlink_core::decode_invite(text).map_err(|err| anyhow!(err.to_string()))?)
        }
        None => None,
    };
    let name = args
        .name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            invited
                .as_ref()
                .map(|invite| invite.name.clone())
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(node_cfg::machine_name);
    let mut relay = optional_setting(
        env,
        env.relay
            .clone()
            .or_else(|| invited.as_ref().map(|invite| invite.relay.clone())),
        |file| file.relay.clone(),
    )
    .unwrap_or_default();
    let mut fingerprint = optional_setting(
        env,
        env.fingerprint.clone().or_else(|| {
            invited.as_ref().and_then(|invite| {
                let value = invite.fingerprint.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                }
            })
        }),
        |file| file.fingerprint.clone(),
    );
    let mut trust = optional_setting(
        env,
        env.trust
            .clone()
            .or_else(|| invited.as_ref().and_then(|invite| invite.trust.clone())),
        |file| file.trust.clone(),
    );
    let fingerprint_owned = fingerprint.clone().unwrap_or_default();
    agentlink_core::apply_relay_defaults(&mut relay, &fingerprint_owned, &mut trust);
    fingerprint = if fingerprint_owned.is_empty() {
        None
    } else {
        Some(fingerprint_owned)
    };
    if fingerprint.as_deref().unwrap_or("").trim().is_empty()
        && trust.as_deref().unwrap_or("").trim().is_empty()
    {
        bail!("certificate trust missing; pass --fingerprint, --trust, or --invite");
    }
    let pairing_token = if let Some(token) = args
        .pairing_token
        .clone()
        .filter(|token| !token.trim().is_empty())
        .or_else(|| invited.as_ref().map(|invite| invite.token.clone()))
    {
        Some(token)
    } else if args.dry_run && admin_token_available(env) {
        Some("<minted at install>".into())
    } else if !args.dry_run && admin_token_available(env) {
        Some(mint_pairing(env, &name, &args.access, args.ttl_minutes).await?)
    } else {
        None
    };
    let max_policy = match &args.max_access {
        Some(access) => parse_access(access)?,
        None => NodePolicy::exec(),
    };
    let node = NodeConfig {
        relay_url: relay.clone(),
        fingerprint: fingerprint.clone().unwrap_or_default(),
        trust: trust.clone(),
        data_dir: data_dir.clone(),
        name: name.clone(),
        pairing_token: pairing_token.clone(),
        root: args.root.clone(),
        max_policy,
        version: version::current().to_string(),
        extensions: Vec::new(),
        policy_hook: None,
        capture: None,
    };
    let rendered = render_node(&spec)?;
    if args.dry_run {
        let mut preview = serde_json::to_value(&preview_node(&node))?;
        if let Some(obj) = preview.as_object_mut() {
            if obj.get("pairing_token").and_then(|v| v.as_str()).is_some() {
                obj.insert("pairing_token".into(), json!("<redacted>"));
            }
        }
        let hook = graphical_hook_preview(&spec);
        let body = format!(
            "----- unit -----\n{rendered}\n{hook}----- node.json -----\n{}\n",
            serde_json::to_string_pretty(&preview)?
        );
        emit(
            env.json,
            json!({
                "dry_run": true,
                "scope": scope_name(args.scope),
                "unit": rendered,
                "node": preview,
                "graphical_hook": hook,
            }),
            || print!("{body}"),
        );
        return Ok(0);
    }
    save_node_config(&node)?;
    if let Some(user) = &spec.run_as {
        chown_tree(&data_dir, user)?;
    }
    write_node_unit(&spec, &rendered)?;
    if cfg!(target_os = "linux") {
        prepare_linux_user_session(&spec)?;
    }
    if !args.no_start {
        // Restart, rather than start, so a node that was already running
        // inherits the GUI variables just imported into the user manager.
        if cfg!(target_os = "linux") && args.scope == Scope::User && !args.headless {
            let unit = format!("{NODE_NAME}.service");
            systemctl(args.scope, &["enable", &unit])?;
            systemctl(args.scope, &["restart", &unit])?;
        } else {
            start(args.scope)?;
        }
    } else {
        enable_only(args.scope)?;
    }
    if args.auto_update {
        install_auto_timer(&spec.binary, args.scope)?;
    }
    if args.headless && cfg!(windows) {
        eprintln!(
            "note: on Windows, --headless does not remove the tray. User scope starts at sign-in from HKCU Run and does not need an administrator. Use --scope system for a session 0 service, which cannot drive the desktop."
        );
    }
    emit(
        env.json,
        json!({
            "ok": true,
            "scope": scope_name(args.scope),
            "data_dir": data_dir,
            "name": name,
            "started": !args.no_start,
            "auto_update": args.auto_update,
        }),
        || {
            eprintln!(
                "installed {NODE_NAME} ({}, data {})",
                scope_name(args.scope),
                data_dir.display()
            );
            if args.scope == Scope::User && cfg!(target_os = "linux") && !args.headless {
                eprintln!(
                    "GUI session: wanted by graphical-session.target. At graphical login, ~/.config/autostart/agentlink-node.desktop imports DISPLAY, WAYLAND_DISPLAY, XAUTHORITY, DBUS_SESSION_BUS_ADDRESS, and XDG_RUNTIME_DIR, then restarts the node."
                );
            }
            if args.scope == Scope::User && cfg!(target_os = "windows") {
                eprintln!(
                    "start-on-login is HKCU Run (no administrator). The tray icon opens the status window."
                );
            }
        },
    );
    Ok(0)
}

fn preview_node(node: &NodeConfig) -> serde_json::Value {
    json!({
        "name": node.name,
        "relay_url": node.relay_url,
        "fingerprint": node.fingerprint,
        "trust": node.trust,
        "root": node.root,
        "max_policy": node.max_policy,
        "pairing_token": node.pairing_token,
    })
}

async fn mint_pairing(env: &Env, name: &str, access: &str, ttl_minutes: u64) -> Result<String> {
    let dir = config_dir(env)?;
    let identity = agentlink_core::Identity::load_or_create(&dir.join("identity.json"))
        .map_err(|err| anyhow!(err.to_string()))?;
    if env.token.is_none() {
        let _ = agentlink_core::client::maintain_session(&dir, &identity)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
    }
    let settings = agentlink_core::load_settings(
        &dir,
        env.relay.clone(),
        env.token.clone(),
        env.fingerprint.clone(),
        env.trust.clone(),
    )
    .map_err(|err| anyhow!(err))?;
    let client = agentlink_core::Client::connect_identity(&settings, identity, true)
        .await
        .map_err(|err| anyhow!(err))?;
    client.remember_node_pins(dir.clone());
    client.remember_grants(dir);
    let policy = parse_access(access)?;
    let info = client
        .create_pairing_token(name, policy, ttl_minutes.saturating_mul(60))
        .await
        .map_err(|err| anyhow!(err))?;
    Ok(info.token)
}

fn uninstall(env: &Env, args: &UninstallArgs) -> Result<i32> {
    let _ = stop(args.scope);
    disable_and_remove(args.scope)?;
    let purged = if args.purge {
        let dir = match &args.data_dir {
            Some(path) => path.clone(),
            None => default_data_dir(args.scope)?,
        };
        if dir.exists() {
            fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))?;
        }
        Some(dir)
    } else {
        None
    };
    emit(
        env.json,
        json!({
            "ok": true,
            "scope": scope_name(args.scope),
            "purged": purged,
        }),
        || {
            eprintln!("removed {NODE_NAME} ({})", scope_name(args.scope));
            if purged.is_none() {
                eprintln!("node data was left in place; pass --purge to delete it");
            }
        },
    );
    Ok(0)
}

fn status(env: &Env, scope: Scope) -> Result<i32> {
    let active = is_active(scope).unwrap_or(false);
    let output = clarify_service_status(status_text(scope).unwrap_or_default());
    emit(
        env.json,
        json!({"running": active, "scope": scope_name(scope), "output": output}),
        || {
            println!("status: {}", if active { "running" } else { "stopped" });
            if !output.trim().is_empty() {
                print!("{}", output.trim_end());
                println!();
            }
        },
    );
    Ok(if active { 0 } else { 1 })
}

fn restart(scope: Scope) -> Result<()> {
    match std::env::consts::OS {
        "linux" => systemctl(scope, &["restart", &format!("{NODE_NAME}.service")]),
        "macos" => {
            let target = launchd_target(scope, LAUNCHD_NODE)?;
            run_ok("launchctl", &["kickstart", "-k", &target])
        }
        "windows" => {
            let _ = stop(scope);
            std::thread::sleep(std::time::Duration::from_millis(400));
            start(scope)
        }
        other => bail!("cannot restart a service on {other}"),
    }
}

fn logs(env: &Env, args: &LogsArgs) -> Result<i32> {
    match std::env::consts::OS {
        "linux" => {
            let mut cmd = process::hidden("journalctl");
            if args.scope == Scope::User {
                cmd.arg("--user");
            }
            cmd.args(["-u", &format!("{NODE_NAME}.service"), "-n"])
                .arg(args.lines.to_string())
                .arg("--no-pager");
            if args.follow {
                cmd.arg("-f");
                let status = cmd.status().context("journalctl")?;
                return Ok(status.code().unwrap_or(1));
            }
            let output = cmd.output().context("journalctl")?;
            let text = String::from_utf8_lossy(&output.stdout).into_owned();
            emit(
                env.json,
                json!({"scope": scope_name(args.scope), "lines": text.lines().collect::<Vec<_>>()}),
                || print!("{text}"),
            );
            Ok(if output.status.success() { 0 } else { 1 })
        }
        "macos" | "windows" => {
            let path = service_log_path(args.scope)?;
            if !path.is_file() {
                bail!("log file does not exist yet: {}", path.display());
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let all: Vec<&str> = content.lines().collect();
            let start = all.len().saturating_sub(args.lines);
            let tail = &all[start..];
            if env.json && !args.follow {
                println!(
                    "{}",
                    json!({"scope": scope_name(args.scope), "path": path, "lines": tail})
                );
                return Ok(0);
            }
            for line in tail {
                println!("{line}");
            }
            if args.follow {
                use std::io::{Read, Seek, SeekFrom};
                let mut file = fs::File::open(&path)?;
                let mut pos = file.seek(SeekFrom::End(0))?;
                let mut buf = Vec::new();
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                    let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(pos);
                    if len < pos {
                        file = fs::File::open(&path)?;
                        pos = 0;
                    }
                    if len > pos {
                        buf.clear();
                        file.seek(SeekFrom::Start(pos))?;
                        let n = file.read_to_end(&mut buf)?;
                        pos += n as u64;
                        print!("{}", String::from_utf8_lossy(&buf));
                    }
                }
            }
            Ok(0)
        }
        other => bail!("service logs are not implemented for {other}"),
    }
}

fn service_log_path(scope: Scope) -> Result<PathBuf> {
    match std::env::consts::OS {
        "macos" => launchd_log_path(scope, "agentlink-node.log"),
        "windows" => {
            if scope == Scope::User {
                let dir = crate::tray::installed_data_dir()
                    .map(Ok)
                    .unwrap_or_else(|| default_data_dir(Scope::User))?;
                Ok(dir.join("tray.log"))
            } else {
                Ok(default_data_dir(Scope::System)?.join("service.log"))
            }
        }
        other => bail!("no local log path for {other}"),
    }
}

/// Soften raw systemctl dbus errors into an actionable hint.
fn clarify_service_status(raw: String) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("failed to connect to user scope bus")
        || lower.contains("failed to connect to bus")
        || (lower.contains("dbus") && lower.contains("no such file or directory"))
    {
        return concat!(
            "user systemd bus is unavailable in this environment ",
            "(no session dbus / XDG_RUNTIME_DIR). ",
            "The node may still be running outside the service ",
            "(for example `agentlink-node-daemon node ...`). ",
            "Install or start with `agentlink service install` / `agentlink service start` ",
            "when a user bus is present, or run the node in the foreground."
        )
        .into();
    }
    raw
}

pub fn install_auto_timer(binary: &Path, scope: Scope) -> Result<()> {
    match std::env::consts::OS {
        "linux" => install_systemd_timer(binary, scope),
        "macos" => install_launchd_timer(binary, scope),
        "windows" => install_windows_timer(binary, scope),
        other => bail!("auto-update timer is not implemented for {other}"),
    }
}

pub fn remove_auto_timer(scope: Scope) -> Result<()> {
    match std::env::consts::OS {
        "linux" => {
            let _ = systemctl(
                scope,
                &["disable", "--now", &format!("{UPDATE_NAME}.timer")],
            );
            let dir = systemd_dir(scope)?;
            let _ = fs::remove_file(dir.join(format!("{UPDATE_NAME}.timer")));
            let _ = fs::remove_file(dir.join(format!("{UPDATE_NAME}.service")));
            let _ = systemctl(scope, &["daemon-reload"]);
            Ok(())
        }
        "macos" => {
            let _ = launchctl_bootout(scope, LAUNCHD_UPDATE);
            if let Ok(path) = launchd_path(scope, LAUNCHD_UPDATE) {
                let _ = fs::remove_file(path);
            }
            Ok(())
        }
        "windows" => {
            let _ = process::hidden("schtasks")
                .args(["/Delete", "/TN", UPDATE_NAME, "/F"])
                .status();
            Ok(())
        }
        other => bail!("auto-update timer is not implemented for {other}"),
    }
}

/// Services whose unit or task is present. `active` means the node process is up.
pub fn installed_services() -> Vec<InstalledService> {
    match std::env::consts::OS {
        "linux" => [Scope::User, Scope::System]
            .into_iter()
            .filter_map(|scope| {
                let path = systemd_dir(scope)
                    .ok()?
                    .join(format!("{NODE_NAME}.service"));
                if !path.exists() {
                    return None;
                }
                Some(InstalledService {
                    scope,
                    kind: ServiceKind::Systemd,
                    active: is_active(scope).unwrap_or(false),
                })
            })
            .collect(),
        "macos" => [Scope::User, Scope::System]
            .into_iter()
            .filter_map(|scope| {
                let path = launchd_path(scope, LAUNCHD_NODE).ok()?;
                if !path.exists() {
                    return None;
                }
                Some(InstalledService {
                    scope,
                    kind: ServiceKind::Launchd,
                    active: is_active(scope).unwrap_or(false),
                })
            })
            .collect(),
        "windows" => {
            let mut found = Vec::new();
            if crate::tray::autostart_enabled() {
                found.push(InstalledService {
                    scope: Scope::User,
                    kind: ServiceKind::WindowsRun,
                    active: windows_user_active(),
                });
            } else if windows_task_exists(NODE_NAME) {
                found.push(InstalledService {
                    scope: Scope::User,
                    kind: ServiceKind::WindowsTask,
                    active: windows_task_running(NODE_NAME),
                });
            }
            if windows_service_exists() {
                found.push(InstalledService {
                    scope: Scope::System,
                    kind: ServiceKind::WindowsService,
                    active: windows_service_running(),
                });
            }
            found
        }
        _ => Vec::new(),
    }
}

#[cfg(windows)]
#[allow(dead_code)]
pub fn stop_installed(service: &InstalledService) -> Result<()> {
    let _ = service.kind;
    stop(service.scope)
}

fn render_node(spec: &NodeSpec) -> Result<String> {
    match std::env::consts::OS {
        "linux" => render_systemd_node(spec),
        "macos" => render_launchd_node(spec),
        "windows" => {
            if spec.scope == Scope::User {
                Ok(crate::tray::autostart_plan(&spec.binary, &spec.data_dir))
            } else {
                Ok(render_windows_service_bin(spec))
            }
        }
        other => bail!("no service definition for {other}"),
    }
}

fn write_node_unit(spec: &NodeSpec, rendered: &str) -> Result<()> {
    match std::env::consts::OS {
        "linux" => {
            let path = systemd_dir(spec.scope)?.join(format!("{NODE_NAME}.service"));
            write_text(&path, rendered)?;
            systemctl(spec.scope, &["daemon-reload"])?;
            Ok(())
        }
        "macos" => {
            let path = launchd_path(spec.scope, LAUNCHD_NODE)?;
            write_text(&path, rendered)?;
            Ok(())
        }
        "windows" => {
            if spec.scope == Scope::User {
                crate::tray::install_user_autostart(&spec.binary, &spec.data_dir)?;
                let _ = process::hidden("schtasks")
                    .args(["/Delete", "/TN", NODE_NAME, "/F"])
                    .status();
                Ok(())
            } else {
                install_windows_service(&spec.binary, &spec.data_dir)
            }
        }
        other => bail!("cannot install a service on {other}"),
    }
}

fn start(scope: Scope) -> Result<()> {
    match std::env::consts::OS {
        "linux" => systemctl(scope, &["enable", "--now", &format!("{NODE_NAME}.service")]),
        "macos" => launchctl_bootstrap(scope, LAUNCHD_NODE, true),
        "windows" => {
            if scope == Scope::User {
                start_windows_user()
            } else {
                start_windows_service()
            }
        }
        other => bail!("cannot start a service on {other}"),
    }
}

fn enable_only(scope: Scope) -> Result<()> {
    match std::env::consts::OS {
        "linux" => systemctl(scope, &["enable", &format!("{NODE_NAME}.service")]),
        "macos" => {
            // bootstrap loads and, with RunAtLoad, starts. A stopped install
            // writes the plist and leaves it unloaded when --no-start is set.
            Ok(())
        }
        "windows" => Ok(()),
        other => bail!("cannot enable a service on {other}"),
    }
}

fn stop(scope: Scope) -> Result<()> {
    match std::env::consts::OS {
        "linux" => systemctl(scope, &["stop", &format!("{NODE_NAME}.service")]),
        "macos" => launchctl_bootout(scope, LAUNCHD_NODE),
        "windows" => {
            if scope == Scope::User {
                stop_windows_user()
            } else {
                stop_windows_service()
            }
        }
        other => bail!("cannot stop a service on {other}"),
    }
}

fn disable_and_remove(scope: Scope) -> Result<()> {
    match std::env::consts::OS {
        "linux" => {
            let _ = systemctl(
                scope,
                &["disable", "--now", &format!("{NODE_NAME}.service")],
            );
            let path = systemd_dir(scope)?.join(format!("{NODE_NAME}.service"));
            if path.exists() {
                fs::remove_file(&path)?;
            }
            let _ = systemctl(scope, &["daemon-reload"]);
            if scope == Scope::User {
                let _ = remove_graphical_autostart();
            }
            Ok(())
        }
        "macos" => {
            let _ = launchctl_bootout(scope, LAUNCHD_NODE);
            let path = launchd_path(scope, LAUNCHD_NODE)?;
            if path.exists() {
                fs::remove_file(path)?;
            }
            Ok(())
        }
        "windows" => {
            if scope == Scope::User {
                let _ = crate::tray::remove_user_autostart();
                let _ = process::hidden("schtasks")
                    .args(["/Delete", "/TN", NODE_NAME, "/F"])
                    .status();
                Ok(())
            } else {
                uninstall_windows_service()
            }
        }
        other => bail!("cannot remove a service on {other}"),
    }
}

fn is_active(scope: Scope) -> Result<bool> {
    match std::env::consts::OS {
        "linux" => {
            let output = systemctl_output(scope, &["is-active", &format!("{NODE_NAME}.service")])?;
            Ok(output.trim() == "active")
        }
        "macos" => {
            let domain = launchd_target(scope, LAUNCHD_NODE)?;
            Ok(process::hidden("launchctl")
                .args(["print", &domain])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false))
        }
        "windows" => {
            if scope == Scope::User {
                Ok(windows_user_active())
            } else {
                Ok(windows_service_running())
            }
        }
        _ => Ok(false),
    }
}

fn status_text(scope: Scope) -> Result<String> {
    match std::env::consts::OS {
        "linux" => systemctl_output(
            scope,
            &["status", &format!("{NODE_NAME}.service"), "--no-pager"],
        ),
        "macos" => {
            let domain = launchd_target(scope, LAUNCHD_NODE)?;
            command_text("launchctl", &["print", &domain])
        }
        "windows" => {
            if scope == Scope::User {
                windows_user_status_text()
            } else {
                command_text("sc.exe", &["query", NODE_NAME])
            }
        }
        other => bail!("no status command on {other}"),
    }
}

fn render_systemd_node(spec: &NodeSpec) -> Result<String> {
    let exec = format!(
        "{} node --data-dir {}",
        systemd_quote(&spec.binary)?,
        systemd_quote(&spec.data_dir)?
    );
    let work = systemd_quote(&spec.work_dir)?;
    let user = match &spec.run_as {
        Some(user) if spec.scope == Scope::System => {
            validate_run_as(user)?;
            format!("User={user}\n")
        }
        _ => String::new(),
    };
    let (after, part_of, pass_env, wanted, note) = if spec.scope == Scope::User && !spec.headless {
        (
            "graphical-session.target network-online.target",
            "PartOf=graphical-session.target\n",
            format!("PassEnvironment={}\n", GUI_ENV.join(" ")),
            "graphical-session.target",
            "\
# User scope. Wanted by the graphical session, and stopped when that session
# ends. PassEnvironment forwards the GUI variables once they are in the
# systemd user manager. `agentlink service install` imports any of them that
# are set in the installing shell. At the next graphical login,
# ~/.config/autostart/agentlink-node.desktop runs import-environment for
# DISPLAY, WAYLAND_DISPLAY, XAUTHORITY, DBUS_SESSION_BUS_ADDRESS, and
# XDG_RUNTIME_DIR, then restarts this service. That autostart entry also
# starts the node on desktops that never reach graphical-session.target.
#   systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR
#   systemctl --user restart agentlink-node
",
        )
    } else if spec.scope == Scope::User {
        (
            "network-online.target",
            "",
            String::new(),
            "default.target",
            "\
# User scope, headless. Wanted by default.target, with no graphical session
# and no GUI variables. Phase 2 desktop control needs the default user
# install, without --headless.
",
        )
    } else {
        (
            "network-online.target",
            "",
            String::new(),
            "multi-user.target",
            "\
# System scope. This process is not in a user GUI session. Phase 2 desktop
# control will not see the logged-in desktop; install the default user scope
# for that.
",
        )
    };
    Ok(format!(
        "\
{note}\
[Unit]
Description=agentlink node
After={after}
Wants=network-online.target
{part_of}\
[Service]
Type=simple
{user}\
WorkingDirectory={work}
ExecStart={exec}
Environment=AGENTLINK_SERVICE=1
{pass_env}\
Restart=on-failure
RestartSec=3
TimeoutStopSec=15

[Install]
WantedBy={wanted}
"
    ))
}

fn render_launchd_node(spec: &NodeSpec) -> Result<String> {
    let log = launchd_log_path(spec.scope, "agentlink-node.log")?;
    let aqua = if spec.scope == Scope::User && !spec.headless {
        "  <key>LimitLoadToSessionType</key>\n  <string>Aqua</string>\n"
    } else {
        ""
    };
    let user = match &spec.run_as {
        Some(user) if spec.scope == Scope::System => format!(
            "  <key>UserName</key>\n  <string>{}</string>\n",
            xml_escape(user)
        ),
        _ => String::new(),
    };
    let comment = if spec.scope == Scope::User && spec.headless {
        "<!-- LaunchAgent with no graphical-session limit. Phase 2 desktop control needs the default agent, which loads in the graphical session. -->\n"
    } else if spec.scope == Scope::User {
        "<!-- LaunchAgent in the Aqua GUI session. Phase 2 desktop control needs this. A LaunchDaemon is outside that session. -->\n"
    } else {
        "<!-- LaunchDaemon. It starts at boot and is not in the GUI session, so phase 2 cannot drive the desktop. -->\n"
    };
    Ok(format!(
        "\
{comment}\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_NODE}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>node</string>
    <string>--data-dir</string>
    <string>{}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>{}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
{aqua}{user}\
  <key>StandardOutPath</key>
  <string>{}</string>
  <key>StandardErrorPath</key>
  <string>{}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>AGENTLINK_SERVICE</key>
    <string>1</string>
  </dict>
</dict>
</plist>
",
        xml_escape(&spec.binary.to_string_lossy()),
        xml_escape(&spec.data_dir.to_string_lossy()),
        xml_escape(&spec.work_dir.to_string_lossy()),
        xml_escape(&log.to_string_lossy()),
        xml_escape(&log.to_string_lossy()),
    ))
}

#[derive(Clone, Copy)]
enum TaskJob {
    /// Legacy logon task. User installs use HKCU Run. Tests still render this XML.
    #[cfg_attr(not(test), allow(dead_code))]
    Node,
    Update,
}

fn render_windows_task(spec: &NodeSpec, job: TaskJob) -> Result<String> {
    let (description, trigger, args) = match job {
        TaskJob::Node => (
            "agentlink node. Runs in the signed-in user session so a later desktop phase can reach the GUI. A Windows service in session 0 cannot.",
            "\
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>",
            format!(
                "node --data-dir \"{}\"",
                spec.data_dir.to_string_lossy().replace('"', "")
            ),
        ),
        TaskJob::Update => (
            "agentlink self-update. Verifies the GitHub release checksum and signature, then replaces this binary.",
            "\
    <CalendarTrigger>
      <StartBoundary>2026-01-01T04:15:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>",
            "update --yes".to_string(),
        ),
    };
    let principal = if spec.scope == Scope::System {
        "\
    <Principal id=\"Author\">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>"
    } else {
        "\
    <Principal id=\"Author\">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>"
    };
    let restart_block = match job {
        TaskJob::Node => "\
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>\n",
        TaskJob::Update => "",
    };
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{}</Description>
  </RegistrationInfo>
  <Triggers>
{trigger}
  </Triggers>
  <Principals>
{principal}
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
{restart_block}  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
      <Arguments>{}</Arguments>
      <WorkingDirectory>{}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"#,
        xml_escape(description),
        xml_escape(&spec.binary.to_string_lossy()),
        xml_escape(&args),
        xml_escape(&spec.work_dir.to_string_lossy()),
    ))
}

fn render_windows_service_bin(spec: &NodeSpec) -> String {
    format!(
        "\"{}\" service run --data-dir \"{}\"",
        spec.binary.display(),
        spec.data_dir.display()
    )
}

fn install_systemd_timer(binary: &Path, scope: Scope) -> Result<()> {
    let exec = format!("{} update --yes", systemd_quote(binary)?);
    let service = format!(
        "\
[Unit]
Description=agentlink self-update

[Service]
Type=oneshot
ExecStart={exec}
"
    );
    let timer = "\
[Unit]
Description=agentlink self-update schedule

[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
";
    let dir = systemd_dir(scope)?;
    write_text(&dir.join(format!("{UPDATE_NAME}.service")), &service)?;
    write_text(&dir.join(format!("{UPDATE_NAME}.timer")), timer)?;
    systemctl(scope, &["daemon-reload"])?;
    systemctl(scope, &["enable", "--now", &format!("{UPDATE_NAME}.timer")])?;
    Ok(())
}

fn install_launchd_timer(binary: &Path, scope: Scope) -> Result<()> {
    let log = launchd_log_path(scope, "agentlink-update.log")?;
    let plist = format!(
        "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_UPDATE}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>update</string>
    <string>--yes</string>
  </array>
  <key>StartInterval</key>
  <integer>86400</integer>
  <key>RunAtLoad</key>
  <false/>
  <key>StandardOutPath</key>
  <string>{}</string>
  <key>StandardErrorPath</key>
  <string>{}</string>
</dict>
</plist>
",
        xml_escape(&binary.to_string_lossy()),
        xml_escape(&log.to_string_lossy()),
        xml_escape(&log.to_string_lossy()),
    );
    let path = launchd_path(scope, LAUNCHD_UPDATE)?;
    write_text(&path, &plist)?;
    launchctl_bootstrap(scope, LAUNCHD_UPDATE, false)?;
    Ok(())
}

fn install_windows_timer(binary: &Path, scope: Scope) -> Result<()> {
    let spec = NodeSpec {
        binary: binary.to_path_buf(),
        data_dir: default_data_dir(scope)?,
        work_dir: work_dir(scope, &default_data_dir(scope)?),
        scope,
        run_as: None,
        headless: true,
    };
    let xml = render_windows_task(&spec, TaskJob::Update)?;
    let path = spec.data_dir.join("agentlink-update.task.xml");
    write_text(&path, &xml)?;
    run_ok(
        "schtasks",
        &[
            "/Create",
            "/TN",
            UPDATE_NAME,
            "/XML",
            &path.to_string_lossy(),
            "/F",
        ],
    )
}

fn systemd_dir(scope: Scope) -> Result<PathBuf> {
    if scope == Scope::System {
        return Ok(PathBuf::from("/etc/systemd/system"));
    }
    Ok(xdg_config_home()?.join("systemd/user"))
}

fn xdg_config_home() -> Result<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(|| home_dir().map(|home| home.join(".config")))
        .ok_or_else(|| anyhow!("could not resolve a home directory for the user unit"))
}

fn autostart_desktop_path() -> Result<PathBuf> {
    Ok(xdg_config_home()?
        .join("autostart")
        .join("agentlink-node.desktop"))
}

fn session_import_script_path() -> Result<PathBuf> {
    Ok(xdg_config_home()?
        .join("agentlink")
        .join("import-graphical-session.sh"))
}

/// Install the login hook, or remove it for a headless user unit.
///
/// Importing the GUI variables happens before the service is started, so the
/// first process inherits them when this shell already has a session.
fn prepare_linux_user_session(spec: &NodeSpec) -> Result<()> {
    if spec.scope != Scope::User {
        return Ok(());
    }
    if spec.headless {
        remove_graphical_autostart()?;
        return Ok(());
    }
    install_graphical_autostart()?;
    import_set_gui_environment();
    Ok(())
}

fn install_graphical_autostart() -> Result<()> {
    let script_path = session_import_script_path()?;
    write_text(&script_path, &render_session_import_script())?;
    make_executable(&script_path)?;
    let desktop_path = autostart_desktop_path()?;
    write_text(&desktop_path, &render_autostart_desktop(&script_path))?;
    Ok(())
}

fn remove_graphical_autostart() -> Result<()> {
    if let Ok(path) = autostart_desktop_path() {
        if path.exists() {
            fs::remove_file(&path)?;
        }
    }
    if let Ok(path) = session_import_script_path() {
        if path.exists() {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn import_set_gui_environment() {
    let present: Vec<&str> = GUI_ENV
        .iter()
        .copied()
        .filter(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
        .collect();
    if present.is_empty() {
        eprintln!(
            "no GUI variables are set in this shell. The autostart entry imports them at the next graphical login."
        );
        return;
    }
    let mut args = vec!["import-environment"];
    args.extend(present.iter().copied());
    if let Err(err) = systemctl(Scope::User, &args) {
        eprintln!(
            "could not import the GUI environment into systemd ({err:#}). The autostart entry retries at the next graphical login."
        );
        return;
    }
    eprintln!(
        "imported {} into the systemd user manager",
        present.join(" ")
    );
}

fn graphical_hook_preview(spec: &NodeSpec) -> String {
    if std::env::consts::OS != "linux" || spec.scope != Scope::User || spec.headless {
        return String::new();
    }
    let script_path = session_import_script_path().unwrap_or_else(|_| {
        PathBuf::from("$XDG_CONFIG_HOME/agentlink/import-graphical-session.sh")
    });
    let desktop_path = autostart_desktop_path()
        .unwrap_or_else(|_| PathBuf::from("$XDG_CONFIG_HOME/autostart/agentlink-node.desktop"));
    format!(
        "----- {} -----\n{}\n----- {} -----\n{}\n",
        desktop_path.display(),
        render_autostart_desktop(&script_path),
        script_path.display(),
        render_session_import_script()
    )
}

fn render_session_import_script() -> String {
    format!(
        "\
#!/bin/sh
# Import the graphical session into the systemd user manager, then restart
# the node so it inherits those variables.
set -eu
set --
for name in {}; do
    eval \"value=\\${{$name-}}\"
    if [ -n \"$value\" ]; then
        set -- \"$@\" \"$name\"
    fi
done
if [ \"$#\" -gt 0 ]; then
    systemctl --user import-environment \"$@\"
fi
systemctl --user restart {}.service
",
        GUI_ENV.join(" "),
        NODE_NAME
    )
}

fn render_autostart_desktop(script: &Path) -> String {
    format!(
        "\
[Desktop Entry]
Type=Application
Version=1.0
Name=agentlink node
Comment=Import the GUI session into systemd and restart the agentlink node
Exec={}
X-GNOME-Autostart-enabled=true
",
        quote_desktop_exec(script)
    )
}

fn quote_desktop_exec(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\'' | '\\' | '$' | '`'))
    {
        format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        text.into_owned()
    }
}

fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).with_context(|| format!("chmod {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn launchd_path(scope: Scope, label: &str) -> Result<PathBuf> {
    let dir = if scope == Scope::System {
        PathBuf::from("/Library/LaunchDaemons")
    } else {
        home_dir()
            .ok_or_else(|| anyhow!("could not resolve a home directory for the LaunchAgent"))?
            .join("Library/LaunchAgents")
    };
    Ok(dir.join(format!("{label}.plist")))
}

fn launchd_log_path(scope: Scope, file: &str) -> Result<PathBuf> {
    if scope == Scope::System {
        Ok(PathBuf::from("/Library/Logs").join(file))
    } else {
        Ok(home_dir()
            .ok_or_else(|| anyhow!("could not resolve a home directory for logs"))?
            .join("Library/Logs")
            .join(file))
    }
}

pub(crate) fn launchd_target(scope: Scope, label: &str) -> Result<String> {
    if scope == Scope::System {
        Ok(format!("system/{label}"))
    } else {
        Ok(format!("gui/{}/{label}", user_id()?))
    }
}

fn launchctl_bootstrap(scope: Scope, label: &str, kick: bool) -> Result<()> {
    let plist = launchd_path(scope, label)?;
    let domain = if scope == Scope::System {
        "system".to_string()
    } else {
        format!("gui/{}", user_id()?)
    };
    let boot = process::hidden("launchctl")
        .args(["bootstrap", &domain, &plist.to_string_lossy()])
        .status()
        .context("launchctl bootstrap")?;
    if !boot.success() {
        let loaded = process::hidden("launchctl")
            .args(["load", "-w"])
            .arg(&plist)
            .status()
            .context("launchctl load")?;
        if !loaded.success() {
            bail!("launchctl could not load {}", plist.display());
        }
        return Ok(());
    }
    let target = format!("{domain}/{label}");
    let _ = process::hidden("launchctl").args(["enable", &target]).status();
    if kick {
        let _ = process::hidden("launchctl")
            .args(["kickstart", "-k", &target])
            .status();
    }
    Ok(())
}

fn launchctl_bootout(scope: Scope, label: &str) -> Result<()> {
    let target = launchd_target(scope, label)?;
    let status = process::hidden("launchctl")
        .args(["bootout", &target])
        .status();
    if status.map(|s| s.success()).unwrap_or(false) {
        return Ok(());
    }
    if let Ok(plist) = launchd_path(scope, label) {
        let _ = process::hidden("launchctl")
            .args(["unload", "-w"])
            .arg(plist)
            .status();
    }
    Ok(())
}

fn systemctl(scope: Scope, args: &[&str]) -> Result<()> {
    let mut cmd = process::hidden("systemctl");
    if scope == Scope::User {
        cmd.arg("--user");
    }
    let output = cmd
        .args(args)
        .output()
        .context("systemctl is not available")?;
    if !output.status.success() {
        bail!(
            "systemctl {} failed\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn systemctl_output(scope: Scope, args: &[&str]) -> Result<String> {
    let mut cmd = process::hidden("systemctl");
    if scope == Scope::User {
        cmd.arg("--user");
    }
    let output = cmd.args(args).output().context("systemctl")?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.trim().is_empty() {
        text = String::from_utf8_lossy(&output.stderr).into_owned();
    }
    Ok(text)
}

fn command_text(program: &str, args: &[&str]) -> Result<String> {
    let output = process::hidden(program).args(args).output()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.stderr.is_empty() {
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    Ok(text)
}

fn run_ok(program: &str, args: &[&str]) -> Result<()> {
    let output = process::hidden(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} {} failed\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn install_windows_service(binary: &Path, data_dir: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        crate::service_win::install_service(binary, data_dir)
    }
    #[cfg(not(windows))]
    {
        let _ = (binary, data_dir);
        bail!("the Windows service manager is only available in the Windows build");
    }
}

fn start_windows_service() -> Result<()> {
    #[cfg(windows)]
    {
        crate::service_win::start_service()
    }
    #[cfg(not(windows))]
    {
        bail!("the Windows service manager is only available in the Windows build");
    }
}

fn stop_windows_service() -> Result<()> {
    #[cfg(windows)]
    {
        crate::service_win::stop_service()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

fn uninstall_windows_service() -> Result<()> {
    #[cfg(windows)]
    {
        crate::service_win::uninstall_service()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

fn windows_service_exists() -> bool {
    #[cfg(windows)]
    {
        crate::service_win::service_exists()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn windows_service_running() -> bool {
    #[cfg(windows)]
    {
        crate::service_win::service_running()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn windows_task_exists(name: &str) -> bool {
    process::hidden("schtasks")
        .args(["/Query", "/TN", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn windows_task_running(name: &str) -> bool {
    command_text("schtasks", &["/Query", "/TN", name, "/FO", "LIST", "/V"])
        .map(|text| text.to_ascii_lowercase().contains("running"))
        .unwrap_or(false)
}

fn start_windows_user() -> Result<()> {
    let data_dir = crate::tray::installed_data_dir()
        .map(Ok)
        .unwrap_or_else(|| default_data_dir(Scope::User))?;
    if crate::tray::signal_tray(crate::tray::TRAY_START) {
        return Ok(());
    }
    if windows_task_exists(NODE_NAME) && !crate::tray::autostart_enabled() {
        return run_ok("schtasks", &["/Run", "/TN", NODE_NAME]);
    }
    let binary = crate::preferred_gui_binary(&current_binary()?);
    crate::tray::spawn_tray(&binary, &data_dir)
}

fn stop_windows_user() -> Result<()> {
    let _ = crate::tray::signal_tray(crate::tray::TRAY_QUIT);
    if windows_task_exists(NODE_NAME) {
        let _ = run_ok("schtasks", &["/End", "/TN", NODE_NAME]);
    }
    Ok(())
}

fn windows_user_active() -> bool {
    crate::tray::user_node_running() || windows_task_running(NODE_NAME)
}

fn windows_user_status_text() -> Result<String> {
    let dir = crate::tray::installed_data_dir()
        .map(Ok)
        .unwrap_or_else(|| default_data_dir(Scope::User))?;
    let config = crate::tray::resolve_config_dir(None).unwrap_or_else(|_| PathBuf::from("."));
    let view = crate::tray::load_view(&dir, &config);
    let mut text = format!(
        "connection: {}\nrelay: {}\nnode: {}\npairing: {}\naccount: {}\nautostart: {}\n",
        view.connection,
        view.relay,
        view.node_name,
        view.pairing,
        view.account,
        if crate::tray::autostart_enabled() {
            "on"
        } else {
            "off"
        },
    );
    if !view.detail.is_empty() {
        text.push_str("detail: ");
        text.push_str(&view.detail);
        text.push('\n');
    }
    if windows_task_exists(NODE_NAME) {
        if let Ok(task) = command_text(
            "schtasks",
            &["/Query", "/TN", NODE_NAME, "/FO", "LIST", "/V"],
        ) {
            text.push('\n');
            text.push_str(&task);
        }
    }
    Ok(text)
}

fn default_data_dir(scope: Scope) -> Result<PathBuf> {
    if scope == Scope::User {
        return Ok(agentlink_core::config::default_data_dir("node")?);
    }
    Ok(match std::env::consts::OS {
        "windows" => PathBuf::from(r"C:\ProgramData\agentlink\node"),
        "macos" => PathBuf::from("/Library/Application Support/agentlink/node"),
        _ => PathBuf::from("/var/lib/agentlink/node"),
    })
}

fn work_dir(scope: Scope, data_dir: &Path) -> PathBuf {
    if scope == Scope::User {
        home_dir().unwrap_or_else(|| data_dir.to_path_buf())
    } else {
        data_dir.to_path_buf()
    }
}

pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn current_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locate the running agentlink binary")?;
    let canon = fs::canonicalize(&exe).unwrap_or(exe);
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

pub(crate) fn validate_run_as(user: &str) -> Result<&str> {
    if user.is_empty()
        || user.len() > 64
        || user.starts_with('-')
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("invalid --run-as username `{user}` (allowed: ^[a-zA-Z0-9._-]+$, must not start with `-`)");
    }
    Ok(user)
}

fn resolve_run_as(
    scope: Scope,
    requested: Option<String>,
    dry_run: bool,
) -> Result<Option<String>> {
    if scope == Scope::User || std::env::consts::OS == "windows" {
        return Ok(None);
    }
    if let Some(user) = requested.filter(|s| !s.trim().is_empty()) {
        validate_run_as(&user)?;
        return Ok(Some(user));
    }
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() && user != "root" {
            validate_run_as(&user)?;
            return Ok(Some(user));
        }
    }
    if !euid_is_root() {
        if let Ok(user) = std::env::var("USER") {
            if !user.is_empty() && user != "root" {
                validate_run_as(&user)?;
                return Ok(Some(user));
            }
        }
    }
    if dry_run {
        return Ok(Some("agentlink".into()));
    }
    bail!("--scope system needs --run-as USER, the account the node should run as");
}

fn ensure_scope_privileges(scope: Scope, dry_run: bool) -> Result<()> {
    if dry_run || scope == Scope::System {
        return Ok(());
    }
    if euid_is_root() {
        bail!("install the user service as the account that should run the node, not as root. Use --scope system for a boot service outside the GUI session.");
    }
    Ok(())
}

fn euid_is_root() -> bool {
    #[cfg(unix)]
    {
        process::hidden("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|text| text.trim() == "0")
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn chown_tree(path: &Path, user: &str) -> Result<()> {
    validate_run_as(user)?;
    #[cfg(unix)]
    {
        if !euid_is_root() {
            return Ok(());
        }
        let status = process::hidden("chown")
            .args(["-R", "-h", "--", user])
            .arg(path)
            .status()
            .context("chown")?;
        if !status.success() {
            bail!("chown {user} {} failed", path.display());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, user);
    }
    Ok(())
}

fn user_id() -> Result<u32> {
    let output = process::hidden("id").arg("-u").output().context("id -u")?;
    let text = String::from_utf8(output.stdout).context("uid")?;
    text.trim().parse().context("parse uid")
}

fn admin_token_available(env: &Env) -> bool {
    if env
        .token
        .as_ref()
        .is_some_and(|token| !token.trim().is_empty())
    {
        return true;
    }
    config_dir(env)
        .ok()
        .and_then(|dir| agentlink_core::config::load_file(&dir).ok())
        .is_some_and(|file| {
            file.token.as_deref().is_some_and(|t| !t.trim().is_empty())
                || file
                    .refresh_token
                    .as_deref()
                    .is_some_and(|t| !t.trim().is_empty())
        })
}

fn config_dir(env: &Env) -> Result<PathBuf> {
    if let Some(dir) = &env.config_dir {
        return Ok(dir.clone());
    }
    Ok(agentlink_core::config::default_config_dir()?)
}

fn optional_setting(
    env: &Env,
    flag: Option<String>,
    file_value: impl FnOnce(agentlink_core::FileConfig) -> Option<String>,
) -> Option<String> {
    if let Some(value) = flag.filter(|s| !s.trim().is_empty()) {
        return Some(value);
    }
    let Ok(dir) = config_dir(env) else {
        return None;
    };
    let file = agentlink_core::config::load_file(&dir).unwrap_or_default();
    file_value(file).filter(|s| !s.trim().is_empty())
}

fn systemd_quote(path: &Path) -> Result<String> {
    let text = path.to_string_lossy().replace('%', "%%");
    if text.contains(['"', '\n', '\r']) {
        bail!("path cannot be quoted for systemd: {}", path.display());
    }
    if text.chars().any(char::is_whitespace) {
        Ok(format!("\"{text}\""))
    } else {
        Ok(text)
    }
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn write_text(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn scope_name(scope: Scope) -> &'static str {
    match scope {
        Scope::User => "user",
        Scope::System => "system",
    }
}

fn emit(json_mode: bool, value: serde_json::Value, human: impl FnOnce()) {
    if json_mode {
        println!("{value}");
    } else {
        human();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(scope: Scope, headless: bool) -> NodeSpec {
        NodeSpec {
            binary: PathBuf::from("/usr/local/bin/agentlink"),
            data_dir: PathBuf::from("/var/lib/agentlink/node"),
            work_dir: PathBuf::from("/home/ada"),
            scope,
            run_as: if scope == Scope::System {
                Some("ada".into())
            } else {
                None
            },
            headless,
        }
    }

    #[test]
    fn systemd_user_unit_follows_the_graphical_session() {
        let text = render_systemd_node(&spec(Scope::User, false)).unwrap();
        assert!(text.contains(
            "ExecStart=/usr/local/bin/agentlink node --data-dir /var/lib/agentlink/node"
        ));
        assert!(!text.contains("User="));
        assert!(text.contains("WantedBy=graphical-session.target"));
        assert!(text.contains("After=graphical-session.target network-online.target"));
        assert!(text.contains("PartOf=graphical-session.target"));
        assert!(text.contains(
            "PassEnvironment=DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR"
        ));
        assert!(text.contains("import-environment"));
        assert!(!text.contains("pairing"));
        let script = render_session_import_script();
        assert!(script.contains("systemctl --user import-environment"));
        assert!(script.contains("systemctl --user restart agentlink-node.service"));
        for name in GUI_ENV {
            assert!(script.contains(name), "{name} missing from\n{script}");
        }
        let desktop = render_autostart_desktop(Path::new(
            "/home/ada/.config/agentlink/import-graphical-session.sh",
        ));
        assert!(desktop.contains("Type=Application"));
        assert!(desktop.contains("/home/ada/.config/agentlink/import-graphical-session.sh"));
        assert!(!desktop.contains("pairing"));
        let quoted = render_autostart_desktop(Path::new("/home/ada/my config/import.sh"));
        assert!(quoted.contains("\"/home/ada/my config/import.sh\""));
        #[cfg(unix)]
        {
            let path = std::env::temp_dir().join(format!(
                "agentlink-import-{}-graphical.sh",
                std::process::id()
            ));
            fs::write(&path, &script).unwrap();
            let check = process::hidden("sh").arg("-n").arg(&path).status().unwrap();
            let _ = fs::remove_file(&path);
            assert!(
                check.success(),
                "import script rejected by sh -n:\n{script}"
            );
        }
    }

    #[test]
    fn systemd_user_headless_skips_the_graphical_session() {
        let text = render_systemd_node(&spec(Scope::User, true)).unwrap();
        assert!(text.contains("WantedBy=default.target"));
        assert!(!text.contains("graphical-session.target"));
        assert!(!text.contains("PassEnvironment="));
    }

    #[test]
    fn systemd_system_unit_names_the_account() {
        let text = render_systemd_node(&spec(Scope::System, false)).unwrap();
        assert!(text.contains("User=ada\n"));
        assert!(text.contains("not in a user GUI session"));
        assert!(!text.contains("graphical-session.target"));
    }

    #[test]
    fn systemd_quotes_spaces_and_percents() {
        let mut spec = spec(Scope::User, false);
        spec.binary = PathBuf::from("/opt/my bin/agentlink");
        spec.data_dir = PathBuf::from("/var/lib/100% agentlink");
        let text = render_systemd_node(&spec).unwrap();
        assert!(text.contains("\"/opt/my bin/agentlink\""));
        assert!(text.contains("\"/var/lib/100%% agentlink\""));
    }

    #[test]
    fn launch_agent_is_aqua_and_daemon_is_not() {
        let user = render_launchd_node(&spec(Scope::User, false)).unwrap();
        assert!(user.contains("<string>Aqua</string>"));
        assert!(user.contains(LAUNCHD_NODE));
        assert!(!user.contains("UserName"));
        let headless = render_launchd_node(&spec(Scope::User, true)).unwrap();
        assert!(!headless.contains("Aqua"));
        let system = render_launchd_node(&spec(Scope::System, false)).unwrap();
        assert!(system.contains("UserName"));
        assert!(system.contains(">ada<"));
        assert!(!system.contains("Aqua"));
        assert!(!system.contains("pairing"));
    }

    #[test]
    fn windows_user_autostart_is_hkcu_and_the_service_stays_session_zero() {
        let user = spec(Scope::User, false);
        let plan = crate::tray::autostart_plan(&user.binary, &user.data_dir);
        assert!(plan.contains("HKCU\\"), "{plan}");
        assert!(plan.contains("tray --background"), "{plan}");
        assert!(!plan.contains("schtasks"), "{plan}");
        let command = crate::tray::autostart_command(&user.binary, &user.data_dir);
        assert_eq!(
            crate::tray::agentlink_subcommand(&command).as_deref(),
            Some("tray")
        );
        assert!(!command.contains(" node "), "{command}");
        assert!(!plan.contains("pairing"), "{plan}");
        let bin = render_windows_service_bin(&spec(Scope::System, false));
        assert!(bin.contains("service run"));
        assert!(bin.contains("--data-dir"));
        let update = render_windows_task(&spec(Scope::User, true), TaskJob::Update).unwrap();
        assert!(update.contains("encoding=\"UTF-8\""), "{update}");
        assert!(!update.contains("UTF-16"), "{update}");
        assert!(!update.contains("RestartOnFailure"), "{update}");
        assert!(update.contains("update --yes"));
        assert!(update.contains("ScheduleByDay"));
        let legacy = render_windows_task(&user, TaskJob::Node).unwrap();
        assert!(legacy.contains("encoding=\"UTF-8\""), "{legacy}");
        assert!(legacy.contains("RestartOnFailure"), "{legacy}");
        assert!(legacy.contains("InteractiveToken"));
        assert!(legacy.contains("node --data-dir"));
        assert!(!legacy.contains("pairing"));
    }

    #[test]
    fn run_as_rejects_injection_and_accepts_safe_usernames() {
        for good in ["ada", "agentlink", "svc_node", "app.user-1"] {
            assert_eq!(validate_run_as(good).unwrap(), good);
        }
        for bad in ["", "-root", "ada\nExecStart=/bin/sh", "ada:wheel", "a b", "ada/x"] {
            assert!(validate_run_as(bad).is_err(), "{bad} should fail");
        }
    }
}

#[cfg(test)]
mod status_hint_tests {
    use super::clarify_service_status;

    #[test]
    fn clarify_service_status_rewrites_missing_user_bus() {
        let raw =
            "Failed to connect to user scope bus via local transport: No such file or directory\n";
        let out = clarify_service_status(raw.into());
        assert!(out.contains("user systemd bus is unavailable"), "{out}");
        assert!(out.contains("agentlink service install"), "{out}");
    }

    #[test]
    fn clarify_service_status_passes_through_other_text() {
        let raw: String = "Active: active (running)".into();
        assert_eq!(clarify_service_status(raw.clone()), raw);
    }
}
