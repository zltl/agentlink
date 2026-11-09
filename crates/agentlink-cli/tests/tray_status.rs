//! `agentlink tray status` reads node files without opening a window.

use std::process::Command;

use serde_json::Value;

#[test]
fn tray_status_reports_connection_pairing_and_account() {
    let bin = env!("CARGO_BIN_EXE_agentlink");
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("node");
    let config = root.path().join("config");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        data.join("node.json"),
        r#"{"name":"laptop","relay_url":"wss://relay.example:7443","fingerprint":"sha256:ab","max_policy":{"read":true}}"#,
    )
    .unwrap();
    let status = format!(
        r#"{{"state":"online","detail":"","relay_url":"wss://relay.example:7443","name":"laptop","node_id":"abc","enrolled":true,"pid":{},"updated_unix":10}}"#,
        std::process::id()
    );
    std::fs::write(data.join("status.json"), status).unwrap();
    std::fs::write(
        config.join("config.json"),
        r#"{"user":"ada","relay":"wss://relay.example:7443","token":"access","trust":"webpki"}"#,
    )
    .unwrap();

    let output = Command::new(bin)
        .args([
            "--json",
            "--config-dir",
            config.to_str().unwrap(),
            "tray",
            "--data-dir",
            data.to_str().unwrap(),
            "status",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stdout}\n{stderr}");
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["connection"], "Online");
    assert_eq!(value["relay"], "wss://relay.example:7443");
    assert_eq!(value["node"], "laptop");
    assert_eq!(value["pairing"], "Paired");
    assert_eq!(value["account"], "Signed in as ada");
    assert_eq!(value["running"], true);
    assert_eq!(value["enrolled"], true);
    assert!(value.get("autostart").is_some(), "{value}");
}

#[test]
fn tray_install_dry_run_prints_hkcu_without_a_token() {
    let bin = env!("CARGO_BIN_EXE_agentlink");
    let output = Command::new(bin)
        .args(["tray", "install", "--dry-run"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("HKCU\\"), "{stdout}");
    assert!(stdout.contains("tray --background"), "{stdout}");
    assert!(!stdout.contains("schtasks"), "{stdout}");
}

#[test]
fn tray_run_is_windows_only_elsewhere() {
    if cfg!(windows) {
        return;
    }
    let bin = env!("CARGO_BIN_EXE_agentlink");
    let output = Command::new(bin).args(["tray"]).output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Windows"),
        "expected a Windows-only message, got {stderr}"
    );
}
