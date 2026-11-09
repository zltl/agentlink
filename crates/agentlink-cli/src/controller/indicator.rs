//! Linux status icon. The window still opens when a desktop has no tray.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub fn spawn(open: Arc<AtomicBool>, quit: Arc<AtomicBool>) -> bool {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        return false;
    }
    let reveal = Arc::clone(&open);
    match std::thread::Builder::new()
        .name("agentlink-tray".into())
        .spawn(move || {
            if let Err(err) = run(open, quit) {
                tracing::warn!(error = %err, "status icon is not available");
                reveal.store(true, Ordering::Relaxed);
            }
        }) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[cfg(not(all(target_os = "linux", not(target_env = "musl"))))]
pub fn spawn(_open: Arc<AtomicBool>, _quit: Arc<AtomicBool>) -> bool {
    false
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn run(open: Arc<AtomicBool>, quit: Arc<AtomicBool>) -> Result<(), String> {
    use ksni::TrayMethods;

    let quit_flag = Arc::clone(&quit);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        let handle = AgentTray { open, quit }
            .spawn()
            .await
            .map_err(|err| err.to_string())?;
        while !quit_flag.load(Ordering::Relaxed) && !handle.is_closed() {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        handle.shutdown().await;
        Ok(())
    })
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
struct AgentTray {
    open: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
impl ksni::Tray for AgentTray {
    fn id(&self) -> String {
        "agentlink".into()
    }

    fn title(&self) -> String {
        "agentlink".into()
    }

    fn icon_name(&self) -> String {
        "computer".into()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.open.store(true, Ordering::Relaxed);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        vec![
            MenuItem::Standard(StandardItem {
                label: "Open".into(),
                activate: Box::new(|tray: &mut Self| {
                    tray.open.store(true, Ordering::Relaxed);
                }),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "Quit".into(),
                activate: Box::new(|tray: &mut Self| {
                    tray.quit.store(true, Ordering::Relaxed);
                }),
                ..Default::default()
            }),
        ]
    }
}
