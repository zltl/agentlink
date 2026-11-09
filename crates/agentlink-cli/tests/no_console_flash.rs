//! Regression guard: Windows console flashes come from bare `Command::new`.
//!
//! Every runtime subprocess must go through `agentlink_core::process::hidden`
//! (or `detached`). Interactive PTY stays on portable-pty and is out of scope.

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn is_allowed(path: &Path, line: &str) -> bool {
    if path.ends_with("agentlink-core/src/process.rs") {
        return true;
    }
    if line.contains("hidden(") || line.contains("detached(") {
        return true;
    }
    if line.contains("no-window-reviewed") {
        return true;
    }
    false
}

#[test]
fn runtime_command_new_goes_through_hidden_or_detached() {
    let root = workspace_root();
    let crates = root.join("crates");
    let mut offenders = Vec::new();

    for entry in fs::read_dir(&crates).expect("crates/") {
        let entry = entry.expect("crate dir");
        let src = entry.path().join("src");
        if !src.is_dir() {
            continue;
        }
        for file in walkdir_rs(&src) {
            let text = fs::read_to_string(&file).unwrap_or_default();
            for (idx, line) in text.lines().enumerate() {
                if !line.contains("Command::new(") {
                    continue;
                }
                if is_allowed(&file, line) {
                    continue;
                }
                let rel = file
                    .strip_prefix(&root)
                    .unwrap_or(&file)
                    .display()
                    .to_string();
                offenders.push(format!(
                    "{rel}:{}: use agentlink_core::process::hidden() (or mark // no-window-reviewed)",
                    idx + 1
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "bare Command::new on Windows flashes a console:\n{}",
        offenders.join("\n")
    );
}

fn walkdir_rs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let Ok(entries) = fs::read_dir(&cur) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}
