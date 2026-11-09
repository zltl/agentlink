//! Linux graphical login entry for the controller.
//!
//! The node itself stays on `agentlink service install`. This file only opens
//! the tray window for the signed-in user.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

pub fn desktop_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
        })?;
    Some(base.join("autostart").join("agentlink-controller.desktop"))
}

pub fn desktop_file(binary: &Path, data_dir: &Path) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName=agentlink\nComment=agentlink controller\nExec={} controller --background --data-dir {}\nTerminal=false\nCategories=Network;\nStartupNotify=false\n",
        quote_exec(&binary.to_string_lossy()),
        quote_exec(&data_dir.to_string_lossy()),
    )
}

fn quote_exec(text: &str) -> String {
    if text.contains([' ', '\t', '"']) {
        format!("\"{}\"", text.replace('"', "\\\""))
    } else {
        text.to_string()
    }
}

pub fn enabled() -> bool {
    desktop_path().is_some_and(|path| path.is_file())
}

pub fn install(binary: &Path, data_dir: &Path) -> Result<()> {
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    {
        let path = desktop_path().ok_or_else(|| anyhow!("could not resolve ~/.config/autostart"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, desktop_file(binary, data_dir))?;
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", not(target_env = "musl"))))]
    {
        let _ = (binary, data_dir);
        Err(anyhow!(
            "start-on-login for the controller is an XDG autostart file on glibc Linux and HKCU Run on Windows"
        ))
    }
}

pub fn remove() -> Result<()> {
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    {
        if let Some(path) = desktop_path() {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", not(target_env = "musl"))))]
    {
        Err(anyhow!(
            "start-on-login for the controller is an XDG autostart file on glibc Linux and HKCU Run on Windows"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entry_launches_the_tray_in_the_background() {
        let text = desktop_file(
            Path::new("/usr/local/bin/agentlink"),
            Path::new("/var/lib/agentlink/node"),
        );
        assert!(text.contains("controller --background --data-dir"));
        assert!(text.contains("/usr/local/bin/agentlink"));
        assert!(text.contains("Type=Application"));
        assert!(!text.contains("schtasks"));
        let quoted = desktop_file(
            Path::new("/opt/my agentlink/agentlink"),
            Path::new("/home/ada/node data"),
        );
        assert!(quoted.contains("\"/opt/my agentlink/agentlink\""));
        assert!(quoted.contains("\"/home/ada/node data\""));
    }
}
