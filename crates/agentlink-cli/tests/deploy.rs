//! Service install renders a unit without embedding the pairing token.

use std::process::Command;

#[test]
fn service_dry_run_keeps_the_token_out_of_the_unit() {
    let bin = env!("CARGO_BIN_EXE_agentlink");
    let output = Command::new(bin)
        .args([
            "--relay",
            "wss://relay.example:7443",
            "--fingerprint",
            "sha256:ab",
            "service",
            "install",
            "--dry-run",
            "--scope",
            "user",
            "--name",
            "box",
            "--pairing-token",
            "super-secret-token",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "dry-run failed\n{stdout}\n{stderr}"
    );
    assert!(
        !stdout.contains("super-secret-token"),
        "pairing token leaked into the unit:\n{stdout}"
    );
    assert!(stdout.contains("wss://relay.example:7443"), "{stdout}");
    assert!(stdout.contains("----- unit -----"), "{stdout}");
    assert!(stdout.contains("node"), "{stdout}");
}

#[test]
fn help_lists_service_and_update() {
    let bin = env!("CARGO_BIN_EXE_agentlink");
    let output = Command::new(bin).arg("--help").output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{text}");
    assert!(text.contains("service"));
    assert!(text.contains("update"));
    assert!(text.contains("tray"));
    assert!(!text.contains("sign-checksums"));
}
