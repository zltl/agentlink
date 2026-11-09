//! Dashboard terminal emulator regressions (Node harness).
//!
//! `top` under TERM=xterm-256color emits ESC ( B before attribute resets. The
//! web terminal used to treat that as a printable B and scramble the layout.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn dashboard_term_does_not_print_charset_designators() {
    let node = which("node");
    let Some(node) = node else {
        eprintln!("skipping: node not on PATH");
        return;
    };
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/term_emulator.mjs");
    let out = Command::new(node)
        .arg(&script)
        .output()
        .expect("spawn node term_emulator.mjs");
    assert!(
        out.status.success(),
        "term_emulator.mjs failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
