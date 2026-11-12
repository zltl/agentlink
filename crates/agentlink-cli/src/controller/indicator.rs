//! Linux status icon. The window still opens when a desktop has no tray.
//!
//! When this process is on a node host, the menu also lists pending grant
//! requests with Allow / Deny. Those actions sign or refuse locally; they are
//! not `approve allow/deny` and they do not send the issuer key anywhere.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub fn spawn(open: Arc<AtomicBool>, quit: Arc<AtomicBool>) -> bool {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        return false;
    }
    let reveal = Arc::clone(&open);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    match std::thread::Builder::new()
        .name("agentlink-tray".into())
        .spawn(move || {
            if let Err(err) = run(open, quit, ready_tx) {
                tracing::warn!(error = %err, "status icon is not available");
                reveal.store(true, Ordering::Relaxed);
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
pub fn spawn(_open: Arc<AtomicBool>, _quit: Arc<AtomicBool>) -> bool {
    false
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn run(
    open: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
    ready_tx: std::sync::mpsc::SyncSender<bool>,
) -> Result<(), String> {
    use ksni::TrayMethods;

    let quit_flag = Arc::clone(&quit);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        let spawned = AgentTray {
            open,
            quit,
            pending: load_pending(),
            on_node: agentlink_core::grant_request::default_node_data_dir().is_some(),
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
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let pending = load_pending();
            let on_node = agentlink_core::grant_request::default_node_data_dir().is_some();
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
fn load_pending() -> Vec<PendingItem> {
    let Some(dir) = agentlink_core::grant_request::default_node_data_dir() else {
        return Vec::new();
    };
    let now = agentlink_core::util::unix_now();
    let _ = agentlink_core::grant_request::expire_pending(&dir, now);
    let Ok(reqs) = agentlink_core::grant_request::list_requests(&dir) else {
        return Vec::new();
    };
    reqs.into_iter()
        .filter(|r| r.is_pending(now))
        .map(|r| {
            let fp = agentlink_core::grant_offer::sha256_ssh_fingerprint(&r.grantee_id)
                .unwrap_or_else(|_| "SHA256:?".into());
            PendingItem {
                request_id: r.request_id,
                label: format!(
                    "{fp} — {} — ttl {}s（签名≠人员/名称）",
                    r.policy.capability_summary(),
                    r.ttl_secs
                ),
            }
        })
        .collect()
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn launch_paste_ui() {
    if crate::grant_local::remote_exec_is_set() {
        tracing::warn!("{}", crate::grant_local::REMOTE_EXEC_REFUSAL);
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(error = %err, "cannot launch grant paste-ui");
            return;
        }
    };
    match std::process::Command::new(exe) // no-window-reviewed: Linux-only grant paste-ui; must stay visible
        .args(["grant", "paste-ui"])
        .spawn()
    {
        Ok(_) => {}
        Err(err) => tracing::warn!(error = %err, "failed to open grant paste-ui"),
    }
}

fn local_allow(request_id: &str) {
    let Some(dir) = agentlink_core::grant_request::default_node_data_dir() else {
        tracing::warn!("grant allow from tray: this machine has no local node identity");
        return;
    };
    let now = agentlink_core::util::unix_now();
    match agentlink_core::grant_request::allow_request_in_dir(&dir, request_id, now, None, None) {
        Ok((_req, grant)) => {
            if let Err(err) = agentlink_core::grant_request::save_issued_grant(&dir, &grant) {
                tracing::warn!(error = %err, "failed to store issued grant on the node");
            }
            if let Ok(client_dir) = agentlink_core::config::default_data_dir("client") {
                let _ = agentlink_core::grant::save_grant(&client_dir, &grant);
            }
            tracing::info!(
                jti = %grant.jti,
                request_id,
                "signed grant locally from the node tray; issuer key stayed on this machine"
            );
        }
        Err(err) => tracing::warn!(error = %err, request_id, "tray grant allow failed"),
    }
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn local_deny(request_id: &str) {
    let Some(dir) = agentlink_core::grant_request::default_node_data_dir() else {
        return;
    };
    let now = agentlink_core::util::unix_now();
    match agentlink_core::grant_request::deny_request(&dir, request_id, now) {
        Ok(_) => tracing::info!(request_id, "denied grant request from the node tray"),
        Err(err) => tracing::warn!(error = %err, request_id, "tray grant deny failed"),
    }
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
struct AgentTray {
    open: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
    pending: Vec<PendingItem>,
    on_node: bool,
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
impl ksni::Tray for AgentTray {
    fn id(&self) -> String {
        "agentlink".into()
    }

    fn title(&self) -> String {
        if self.pending.is_empty() {
            "agentlink".into()
        } else {
            format!(
                "agentlink ({} grant request{})",
                self.pending.len(),
                if self.pending.len() == 1 { "" } else { "s" }
            )
        }
    }

    fn icon_name(&self) -> String {
        "computer".into()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.open.store(true, Ordering::Relaxed);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        let mut items = Vec::new();
        if self.on_node {
            items.push(MenuItem::Standard(StandardItem {
                label: "粘贴控制端身份码…".into(),
                activate: Box::new(|_tray: &mut Self| launch_paste_ui()),
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
                        activate: Box::new(move |_tray: &mut Self| local_allow(&id)),
                        ..Default::default()
                    }));
                    items.push(MenuItem::Standard(StandardItem {
                        label: format!("Deny {}", p.label),
                        activate: Box::new(move |_tray: &mut Self| local_deny(&deny_id)),
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
            }),
            ..Default::default()
        }));
        items.push(MenuItem::Standard(StandardItem {
            label: "Quit".into(),
            activate: Box::new(|tray: &mut Self| {
                tray.quit.store(true, Ordering::Relaxed);
            }),
            ..Default::default()
        }));
        items
    }
}
