//! Offline `agentlink identity` commands.
//!
//! Identity is a local ed25519 key file. It is not a grant and not a relay
//! login. `grant offer` remains the offline controller card path.

use std::path::Path;

use agentlink_core::grant_offer;
use agentlink_core::identity::Identity;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};

pub fn show(path: &Path, json_mode: bool) -> Result<i32> {
    let id = Identity::load(path).map_err(|err| anyhow!(err.to_string()))?;
    let public_id = id.public_hex().to_string();
    let fingerprint = grant_offer::sha256_ssh_fingerprint(&public_id)
        .map_err(|err| anyhow!(err.to_string()))?;
    emit(
        json_mode,
        json!({
            "public_id": public_id,
            "fingerprint": fingerprint,
            "path": path,
            "note": "local ed25519 identity — not a grant, not a relay login",
        }),
        || {
            println!("public_id: {public_id}");
            println!("fingerprint: {fingerprint}");
            println!("path: {}", path.display());
            eprintln!("note: local ed25519 identity — not a grant, not a relay login");
        },
    );
    Ok(0)
}

/// Create only when missing; if the file exists, re-read without rotating.
/// Corrupt files fail loudly (never silently rebuild).
pub fn create_or_ensure(path: &Path, json_mode: bool, action_name: &str) -> Result<i32> {
    let existed = path.exists();
    let id = Identity::load_or_create(path).map_err(|err| anyhow!(err.to_string()))?;
    let public_id = id.public_hex().to_string();
    let fingerprint = grant_offer::sha256_ssh_fingerprint(&public_id)
        .map_err(|err| anyhow!(err.to_string()))?;
    let action = if existed { "reused" } else { "created" };
    emit(
        json_mode,
        json!({
            "action": action,
            "command": action_name,
            "public_id": public_id,
            "fingerprint": fingerprint,
            "path": path,
            "note": "local ed25519 identity — not a grant, not a relay login",
        }),
        || {
            println!("{action} identity");
            println!("public_id: {public_id}");
            println!("fingerprint: {fingerprint}");
            println!("path: {}", path.display());
            eprintln!("note: local ed25519 identity — not a grant, not a relay login");
        },
    );
    Ok(0)
}

fn emit(json_mode: bool, value: Value, human: impl FnOnce()) {
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
        );
    } else {
        human();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_errors_when_missing_without_creating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let err = show(&path, true).unwrap_err().to_string();
        assert!(
            err.contains("missing") || err.contains("not found") || err.contains("identity"),
            "{err}"
        );
        assert!(!path.exists());
    }

    #[test]
    fn create_then_ensure_does_not_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        create_or_ensure(&path, true, "create").unwrap();
        let first = Identity::load(&path).unwrap().public_hex().to_string();
        create_or_ensure(&path, true, "ensure").unwrap();
        let again = Identity::load(&path).unwrap().public_hex().to_string();
        assert_eq!(first, again);
        show(&path, true).unwrap();
    }

    #[test]
    fn corrupt_file_fails_loudly_on_create_and_show() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        std::fs::write(&path, "{not-json").unwrap();
        let err = create_or_ensure(&path, false, "create")
            .unwrap_err()
            .to_string();
        assert!(err.contains("(not regenerated)"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not-json");
        let err = show(&path, false).unwrap_err().to_string();
        assert!(err.contains("(not regenerated)"), "{err}");
    }
}
