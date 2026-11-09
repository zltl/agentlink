//! `agentlink controller --check` reports the window without opening it.

use std::process::Command;

#[test]
fn controller_check_does_not_open_a_window() {
    let bin = env!("CARGO_BIN_EXE_agentlink");
    let output = Command::new(bin)
        .args(["controller", "--check"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    if cfg!(target_env = "musl") {
        assert!(!output.status.success(), "{stdout}\n{stderr}");
        assert!(stderr.contains("glibc"), "{stderr}");
        return;
    }
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("controller: ready"), "{stdout}");
}
