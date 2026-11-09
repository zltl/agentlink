//! Local system description for an agent.
//!
//! Environment variables are an allowlist. A name that looks like a secret is
//! dropped even when it is also on the allowlist.

use std::collections::BTreeMap;
use std::path::PathBuf;

use agentlink_core::{Error, Result};
use serde_json::{json, Value};
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, RefreshKind, System};

const ENV_ALLOW: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "USERNAME",
    "LOGNAME",
    "SHELL",
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TERM",
    "TMPDIR",
    "TEMP",
    "TMP",
    "PWD",
    "OS",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "COMPUTERNAME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMFILES",
    "PROGRAMDATA",
    "COMMONPROGRAMFILES",
];

const SECRET_PARTS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE",
    "SESSION",
    "COOKIE",
    "AUTH",
    "KEY",
    "PWD",
    "SIGNATURE",
    "CERT",
];

const TOOLS: &[&str] = &[
    "git",
    "rg",
    "curl",
    "wget",
    "ssh",
    "tar",
    "node",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "bun",
    "python",
    "python3",
    "pip",
    "pip3",
    "cargo",
    "rustc",
    "rustup",
    "go",
    "docker",
    "podman",
    "java",
    "javac",
    "gcc",
    "clang",
    "cc",
    "make",
    "cmake",
    "code",
    "pwsh",
    "powershell",
];

pub async fn system_info() -> Result<Value> {
    tokio::task::spawn_blocking(system_info_blocking)
        .await
        .map_err(|err| Error::Message(format!("system info task: {err}")))?
}

fn system_info_blocking() -> Result<Value> {
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    );
    // A second refresh fills CPU frequency on platforms that need a sample.
    sys.refresh_cpu_frequency();
    let cpus = sys.cpus();
    let brand = cpus
        .first()
        .map(|cpu| {
            let brand = cpu.brand().trim();
            if brand.is_empty() {
                cpu.name().trim().to_string()
            } else {
                brand.to_string()
            }
        })
        .unwrap_or_default();
    let frequency_mhz = cpus.iter().map(|cpu| cpu.frequency()).max().unwrap_or(0);
    let disks = Disks::new_with_refreshed_list();
    let disk_rows: Vec<_> = disks
        .list()
        .iter()
        .take(64)
        .map(|disk| {
            json!({
                "name": disk.name().to_string_lossy(),
                "mount": disk.mount_point().to_string_lossy(),
                "fs": disk.file_system().to_string_lossy(),
                "total_bytes": disk.total_space(),
                "available_bytes": disk.available_space(),
                "removable": disk.is_removable(),
            })
        })
        .collect();
    Ok(json!({
        "os": std::env::consts::OS,
        "os_name": System::name(),
        "os_version": System::os_version(),
        "os_long": System::long_os_version(),
        "kernel": System::kernel_version(),
        "arch": std::env::consts::ARCH,
        "hostname": System::host_name().unwrap_or_else(host_name),
        "cpu": {
            "count": cpus.len(),
            "brand": brand,
            "frequency_mhz": frequency_mhz,
        },
        "memory": {
            "total_bytes": sys.total_memory(),
            "available_bytes": sys.available_memory(),
            "used_bytes": sys.used_memory(),
        },
        "disks": disk_rows,
        "user": current_user(),
        "shell": current_shell(),
        "pid": std::process::id(),
        "cwd": std::env::current_dir().ok().map(|path| path.display().to_string()),
        "env": filter_env(),
        "tools": installed_tools(),
        "has_display": agentlink_desktop::has_display(),
    }))
}

pub fn filter_env() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (key, value) in std::env::vars() {
        if let Some(value) = allowed_env(&key, &value) {
            map.insert(key, value);
        }
    }
    map
}

fn allowed_env(key: &str, value: &str) -> Option<String> {
    let upper = key.to_ascii_uppercase();
    if !ENV_ALLOW.iter().any(|name| *name == upper) {
        return None;
    }
    if secret_key(&upper) {
        return None;
    }
    let value = if value.len() > 4096 {
        format!("{}…", &value[..4096])
    } else {
        value.to_string()
    };
    Some(value)
}

fn secret_key(upper: &str) -> bool {
    SECRET_PARTS.iter().any(|part| upper.contains(part))
}

fn current_user() -> String {
    for key in ["USER", "USERNAME", "LOGNAME"] {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                return value;
            }
        }
    }
    "unknown".into()
}

fn current_shell() -> String {
    if let Ok(shell) = std::env::var("SHELL") {
        if !shell.is_empty() {
            return shell;
        }
    }
    if let Ok(shell) = std::env::var("COMSPEC") {
        if !shell.is_empty() {
            return shell;
        }
    }
    if cfg!(windows) {
        "cmd.exe".into()
    } else {
        "/bin/sh".into()
    }
}

fn installed_tools() -> Vec<Value> {
    let mut found = Vec::new();
    for name in TOOLS {
        if let Some(path) = which(name) {
            found.push(json!({
                "name": name,
                "path": path.display().to_string(),
            }));
        }
    }
    found
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let direct = dir.join(name);
        if direct.is_file() {
            return Some(direct);
        }
        if cfg!(windows) {
            for ext in ["exe", "cmd", "bat", "ps1"] {
                let candidate = dir.join(format!("{name}.{ext}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn host_name() -> String {
    hostname::get()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_filter_keeps_path_and_drops_secrets() {
        assert!(allowed_env("PATH", "/usr/bin").is_some());
        assert!(allowed_env("HOME", "/home/me").is_some());
        assert!(allowed_env("AWS_SECRET_ACCESS_KEY", "abc").is_none());
        assert!(allowed_env("MY_TOKEN", "abc").is_none());
        assert!(allowed_env("RANDOM_INTERNAL", "abc").is_none());
        let info = system_info_blocking().unwrap();
        assert_eq!(info["os"], std::env::consts::OS);
        assert_eq!(info["arch"], std::env::consts::ARCH);
        assert!(info["memory"]["total_bytes"].as_u64().unwrap() > 0);
        assert!(info["cpu"]["count"].as_u64().unwrap() > 0);
        assert!(info["tools"].is_array());
        assert!(info["has_display"].is_boolean());
        let env = info["env"].as_object().unwrap();
        for key in env.keys() {
            let upper = key.to_ascii_uppercase();
            assert!(
                ENV_ALLOW.contains(&upper.as_str()),
                "unexpected env key {key}"
            );
            assert!(!secret_key(&upper), "{key}");
        }
    }
}
