//! Startup banner and version string.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentlink")
}

#[test]
fn version_includes_the_git_commit() {
    let output = Command::new(bin()).arg("--version").output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains(env!("AGENTLINK_SEMVER")), "{text}");
    let hash = env!("AGENTLINK_GIT_HASH");
    if !hash.is_empty() {
        assert!(text.contains(hash), "{text}");
    }
}

#[test]
fn default_start_does_not_issue_a_usable_admin_token() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("relay");
    let first = relay_banner(&data);
    assert!(first.contains("fingerprint:"), "{first}");
    assert!(
        first.contains("not issued"),
        "new deploy with legacy admin off must not mint a token\n{first}"
    );
    assert!(
        !data.join("admin.token").exists(),
        "admin.token must not be written when the token is not issued"
    );
}

#[test]
fn enabled_legacy_admin_token_is_printed_once() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("relay");
    let first = relay_banner_legacy(&data, &[]);
    let token = first
        .lines()
        .find_map(|line| line.trim().strip_prefix("admin token:"))
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    assert_eq!(
        token.len(),
        64,
        "first enabled start should print the token\n{first}"
    );
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()), "{token}");
    assert!(first.contains("fingerprint:"), "{first}");

    let second = relay_banner_legacy(&data, &[]);
    assert!(
        second.contains("admin.token"),
        "later starts should print the token path\n{second}"
    );
    assert!(
        !second.contains(&token),
        "admin token was printed again\n{second}"
    );

    let forced = relay_banner_legacy(&data, &["--print-admin-token"]);
    assert!(
        forced.contains(&token),
        "flag should print the token\n{forced}"
    );
}

fn relay_banner(data: &std::path::Path) -> String {
    relay_banner_with(data, &[], false)
}

fn relay_banner_legacy(data: &std::path::Path, extra: &[&str]) -> String {
    relay_banner_with(data, extra, true)
}

fn relay_banner_with(data: &std::path::Path, extra: &[&str], mint_legacy: bool) -> String {
    let mut cmd = Command::new(bin());
    cmd.args(["relay", "--bind", "127.0.0.1:0", "--data-dir"])
        .arg(data)
        .args(extra)
        .stderr(Stdio::piped())
        .stdout(Stdio::null());
    if mint_legacy {
        cmd.env("AGENTLINK_LEGACY_ADMIN", "1")
            .env("AGENTLINK_LEGACY_ADMIN_TTL_SECS", "86400");
    }
    let mut child = cmd.spawn().unwrap();

    let stderr = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut lines = String::new();
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            lines.push_str(&line);
            lines.push('\n');
            if lines.contains("admin token:") && lines.contains("data dir:") {
                break;
            }
        }
        lines
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let text = loop {
        if reader.is_finished() {
            break reader.join().unwrap();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("relay did not print its banner");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = child.kill();
    let _ = child.wait();
    text
}
