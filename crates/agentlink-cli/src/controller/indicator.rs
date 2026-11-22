//! Linux status icon. The window still opens when a desktop has no tray.
//!
//! When this process is on a node host, the menu also lists pending grant
//! requests with Allow / Deny. Those actions sign or refuse locally; they are
//! not `approve allow/deny` and they do not send the issuer key anywhere.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use eframe::egui;

/// Shared slot populated with the `egui::Context` once `eframe::run_native`
/// constructs the window, allowing the tray thread to wake a hidden window.
pub type SharedEguiCtx = Arc<OnceLock<egui::Context>>;

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
const GRANT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub fn spawn(
    open: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
    data_dir: PathBuf,
    egui_ctx: SharedEguiCtx,
) -> bool {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        return false;
    }
    let reveal = Arc::clone(&open);
    let wake_err = Arc::clone(&egui_ctx);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    match std::thread::Builder::new()
        .name("agentlink-tray".into())
        .spawn(move || {
            if let Err(err) = run(open, quit, data_dir, egui_ctx, ready_tx) {
                tracing::warn!(error = %err, "status icon is not available");
                reveal.store(true, Ordering::Relaxed);
                if let Some(ctx) = wake_err.get() {
                    ctx.request_repaint();
                }
            }
        }) {
        Ok(_) => match ready_rx.recv_timeout(std::time::Duration::from_secs(2)) {
            // Only treat the tray as ready when ksni actually registered.
            // Returning true just because the thread started used to hide the
            // window on close with no Quit icon, leaving a background worker.
            Ok(true) => true,
            _ => false,
        },
        Err(_) => false,
    }
}

#[cfg(not(all(target_os = "linux", not(target_env = "musl"))))]
pub fn spawn(
    _open: Arc<AtomicBool>,
    _quit: Arc<AtomicBool>,
    _data_dir: PathBuf,
    _egui_ctx: SharedEguiCtx,
) -> bool {
    false
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn has_local_node(dir: &std::path::Path) -> bool {
    dir.join("node.json").is_file()
        || dir.join("identity.json").is_file()
        || dir.join("grant-issuer.json").is_file()
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn run(
    open: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
    data_dir: PathBuf,
    egui_ctx: SharedEguiCtx,
    ready_tx: std::sync::mpsc::SyncSender<bool>,
) -> Result<(), String> {
    use ksni::TrayMethods;

    let quit_flag = Arc::clone(&quit);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        let on_node = has_local_node(&data_dir);
        let spawned = AgentTray {
            open,
            quit,
            data_dir: data_dir.clone(),
            egui_ctx,
            pending: if on_node {
                load_pending(&data_dir)
            } else {
                Vec::new()
            },
            on_node,
            last_action_status: None,
        }
        .spawn()
        .await;
        let handle = match spawned {
            Ok(handle) => {
                let _ = ready_tx.send(true);
                handle
            }
            Err(err) => {
                let _ = ready_tx.send(false);
                return Err(err.to_string());
            }
        };
        while !quit_flag.load(Ordering::Relaxed) && !handle.is_closed() {
            tokio::time::sleep(GRANT_POLL_INTERVAL).await;
            let on_node = has_local_node(&data_dir);
            let pending = if on_node {
                load_pending(&data_dir)
            } else {
                Vec::new()
            };
            let _ = handle
                .update(|tray| {
                    if tray.pending != pending || tray.on_node != on_node {
                        tray.pending = pending;
                        tray.on_node = on_node;
                    }
                })
                .await;
        }
        handle.shutdown().await;
        Ok(())
    })
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
#[derive(Clone, PartialEq, Eq)]
struct PendingItem {
    request_id: String,
    label: String,
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn load_pending(dir: &std::path::Path) -> Vec<PendingItem> {
    let Ok(reqs) = agentlink_core::grant_request::list_requests(dir) else {
        return Vec::new();
    };
    if reqs.is_empty() {
        return Vec::new();
    }
    let now = agentlink_core::util::unix_now();
    // Only expire on disk when at least one request has actually crossed its deadline.
    if reqs
        .iter()
        .any(|r| r.status == agentlink_core::grant_request::RequestStatus::Pending && !r.is_pending(now))
    {
        let _ = agentlink_core::grant_request::expire_pending(dir, now);
    }
    reqs.into_iter()
        .filter(|r| r.is_pending(now))
        .map(|r| {
            let fp = agentlink_core::grant_offer::sha256_ssh_fingerprint(&r.grantee_id)
                .unwrap_or_else(|_| "SHA256:?".into());
            let ttl_label = if agentlink_core::grant::is_permanent_ttl(r.ttl_secs) {
                "permanent".to_string()
            } else {
                format!("ttl {}s", r.ttl_secs)
            };
            PendingItem {
                request_id: r.request_id,
                label: format!(
                    "{fp} — {} — {ttl_label} (signature != identity name)",
                    r.policy.capability_summary(),
                ),
            }
        })
        .collect()
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn launch_paste_ui(data_dir: &std::path::Path) -> String {
    if crate::grant_local::remote_exec_is_set() {
        tracing::warn!("{}", crate::grant_local::REMOTE_EXEC_REFUSAL);
        return crate::grant_local::REMOTE_EXEC_REFUSAL.to_string();
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(error = %err, "cannot launch grant paste-ui");
            return format!("Cannot launch grant UI: {err}");
        }
    };
    match std::process::Command::new(exe) // no-window-reviewed: Linux-only grant paste-ui; must stay visible
        .args(["grant", "paste-ui", "--data-dir"])
        .arg(data_dir)
        .spawn()
    {
        Ok(_) => "Opened grant paste window.".into(),
        Err(err) => {
            tracing::warn!(error = %err, "failed to open grant paste-ui");
            format!("Failed to open grant UI: {err}")
        }
    }
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn local_allow(dir: &std::path::Path, request_id: &str) -> String {
    if !has_local_node(dir) {
        tracing::warn!("grant allow from tray: this machine has no local node identity");
        return "Grant allow failed: no local node identity".into();
    }
    let now = agentlink_core::util::unix_now();
    match agentlink_core::grant_request::allow_request_in_dir(dir, request_id, now, None, None) {
        Ok((_req, grant)) => {
            if let Err(err) = agentlink_core::grant_request::save_issued_grant(dir, &grant) {
                tracing::warn!(error = %err, "failed to store issued grant on the node");
                return format!("Grant signed, but failed to store on node: {err}");
            }
            if let Ok(client_dir) = agentlink_core::config::default_data_dir("client") {
                let _ = agentlink_core::grant::save_grant(&client_dir, &grant);
            }
            tracing::info!(
                jti = %grant.jti,
                request_id,
                "signed grant locally from the node tray; issuer key stayed on this machine"
            );
            format!("Allowed grant request {request_id}")
        }
        Err(err) => {
            tracing::warn!(error = %err, request_id, "tray grant allow failed");
            format!("Grant allow failed: {err}")
        }
    }
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn local_deny(dir: &std::path::Path, request_id: &str) -> String {
    if !has_local_node(dir) {
        return "Grant deny failed: no local node identity".into();
    }
    let now = agentlink_core::util::unix_now();
    match agentlink_core::grant_request::deny_request(dir, request_id, now) {
        Ok(_) => {
            tracing::info!(request_id, "denied grant request from the node tray");
            format!("Denied grant request {request_id}")
        }
        Err(err) => {
            tracing::warn!(error = %err, request_id, "tray grant deny failed");
            format!("Grant deny failed: {err}")
        }
    }
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
struct AgentTray {
    open: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
    data_dir: PathBuf,
    egui_ctx: SharedEguiCtx,
    pending: Vec<PendingItem>,
    on_node: bool,
    last_action_status: Option<String>,
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
impl AgentTray {
    fn wake_window(&self) {
        if let Some(ctx) = self.egui_ctx.get() {
            ctx.request_repaint();
        }
    }
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
impl ksni::Tray for AgentTray {
    fn id(&self) -> String {
        "agentlink".into()
    }

    fn title(&self) -> String {
        if self.pending.is_empty() {
            "Agentlink".into()
        } else {
            format!(
                "Agentlink ({} grant request{})",
                self.pending.len(),
                if self.pending.len() == 1 { "" } else { "s" }
            )
        }
    }

    fn icon_name(&self) -> String {
        if !self.pending.is_empty() {
            "dialog-information".into()
        } else {
            "network-workgroup".into()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.open.store(true, Ordering::Relaxed);
        self.wake_window();
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        let mut items = Vec::new();
        if let Some(status) = &self.last_action_status {
            items.push(MenuItem::Standard(StandardItem {
                label: status.clone(),
                enabled: false,
                ..Default::default()
            }));
            items.push(MenuItem::Separator);
        }
        if self.on_node {
            items.push(MenuItem::Standard(StandardItem {
                label: "Paste controller identity code...".into(),
                activate: Box::new(|tray: &mut Self| {
                    let msg = launch_paste_ui(&tray.data_dir);
                    tray.last_action_status = Some(msg);
                }),
                ..Default::default()
            }));
            if self.pending.is_empty() {
                items.push(MenuItem::Standard(StandardItem {
                    label: "No pending grant requests".into(),
                    enabled: false,
                    ..Default::default()
                }));
            } else {
                items.push(MenuItem::Standard(StandardItem {
                    label: "Pending grant requests (local allow / deny)".into(),
                    enabled: false,
                    ..Default::default()
                }));
                for p in &self.pending {
                    let id = p.request_id.clone();
                    let deny_id = p.request_id.clone();
                    items.push(MenuItem::Standard(StandardItem {
                        label: format!("Allow {}", p.label),
                        activate: Box::new(move |tray: &mut Self| {
                            let msg = local_allow(&tray.data_dir, &id);
                            tray.last_action_status = Some(msg);
                            tray.pending = load_pending(&tray.data_dir);
                        }),
                        ..Default::default()
                    }));
                    items.push(MenuItem::Standard(StandardItem {
                        label: format!("Deny {}", p.label),
                        activate: Box::new(move |tray: &mut Self| {
                            let msg = local_deny(&tray.data_dir, &deny_id);
                            tray.last_action_status = Some(msg);
                            tray.pending = load_pending(&tray.data_dir);
                        }),
                        ..Default::default()
                    }));
                }
            }
            items.push(MenuItem::Separator);
        }
        items.push(MenuItem::Standard(StandardItem {
            label: "Open".into(),
            activate: Box::new(|tray: &mut Self| {
                tray.open.store(true, Ordering::Relaxed);
                tray.wake_window();
            }),
            ..Default::default()
        }));
        items.push(MenuItem::Standard(StandardItem {
            label: "Quit".into(),
            activate: Box::new(|tray: &mut Self| {
                tray.quit.store(true, Ordering::Relaxed);
                tray.wake_window();
            }),
            ..Default::default()
        }));
        items
    }
}
