//! Offline `agentlink status`: identity, transport, and authorization are separate.
//!
//! This command does not contact a relay. A saved relay session is not a grant.

use std::path::{Path, PathBuf};

use agentlink_core::config::{self, FileConfig};
use agentlink_core::grant;
use agentlink_core::grant_offer;
use agentlink_core::identity::Identity;
use agentlink_core::util;
use anyhow::Result;
use serde_json::{json, Value};

pub fn run(config_dir: &Path, identity_path: &Path, json_mode: bool) -> Result<i32> {
    let identity = identity_section(identity_path);
    let transport = transport_section(config_dir);
    let authorization = authorization_section(config_dir);
    let value = json!({
        "identity": identity,
        "transport": transport,
        "authorization": authorization,
        "notes": [
            "a relay device session is not a grant",
            "this command does not contact the relay",
        ],
    });
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
        );
    } else {
        print_human(&value);
    }
    Ok(0)
}

fn identity_section(path: &Path) -> Value {
    match Identity::load(path) {
        Ok(id) => {
            let public_id = id.public_hex().to_string();
            let fingerprint = grant_offer::sha256_ssh_fingerprint(&public_id)
                .unwrap_or_else(|_| "unreadable fingerprint".into());
            json!({
                "state": "ok",
                "public_id": public_id,
                "fingerprint": fingerprint,
                "path": path,
            })
        }
        Err(err) => {
            let state = if !path.exists() {
                "missing"
            } else {
                "unreadable"
            };
            json!({
                "state": state,
                "path": path,
                "error": err.to_string(),
            })
        }
    }
}

fn transport_section(config_dir: &Path) -> Value {
    let path = config::config_path(config_dir);
    if !path.exists() {
        return json!({
            "state": "missing",
            "path": path,
            "note": "a relay device session is not a grant",
        });
    }
    match config::load_file(config_dir) {
        Ok(file) => transport_from_file(&path, file),
        Err(err) => json!({
            "state": "unreadable",
            "path": path,
            "error": err.to_string(),
            "note": "a relay device session is not a grant",
        }),
    }
}

fn transport_from_file(path: &Path, file: FileConfig) -> Value {
    let has_refresh = file
        .refresh_token
        .as_deref()
        .is_some_and(|token| !token.trim().is_empty());
    let has_access = file
        .token
        .as_deref()
        .is_some_and(|token| !token.trim().is_empty());
    let now = util::unix_now();
    let expires = file.access_expires_unix;
    let state = if !has_refresh && !has_access {
        "missing"
    } else if has_access && expires.is_some_and(|exp| exp <= now) {
        "expired"
    } else if has_access {
        "ok"
    } else {
        "expired"
    };
    json!({
        "state": state,
        "user": file.user,
        "relay": file.relay,
        "access_expires_unix": expires,
        "has_refresh_token": has_refresh,
        "path": path,
        "note": "a relay device session is not a grant",
    })
}

fn authorization_section(config_dir: &Path) -> Value {
    let now = util::unix_now();
    match grant::list_stored_grants(config_dir) {
        Ok(list) if list.is_empty() => json!({
            "state": "missing",
            "grants": [],
            "note": "no local grant files in this config directory",
        }),
        Ok(list) => {
            let grants: Vec<Value> = list
                .into_iter()
                .map(|stored| {
                    let grant = stored.grant;
                    let status = if grant.exp_unix >= now {
                        "ACTIVE"
                    } else {
                        "EXPIRED"
                    };
                    json!({
                        "node_id": grant.node_id,
                        "policy": grant.policy.preset_name(),
                        "capability": grant.policy.capability_summary(),
                        "status": status,
                        "exp_unix": grant.exp_unix,
                        "jti": grant.jti,
                        "path": stored.path,
                    })
                })
                .collect();
            json!({
                "state": "present",
                "grants": grants,
                "note": "local grants only; not an isolation claim",
            })
        }
        Err(err) => json!({
            "state": "unreadable",
            "error": err.to_string(),
        }),
    }
}

fn print_human(value: &Value) {
    println!("Identity");
    print_block(&value["identity"], &[
        ("state", "state"),
        ("public_id", "public_id"),
        ("fingerprint", "fingerprint"),
        ("path", "path"),
        ("error", "error"),
    ]);
    println!();
    println!("Transport (relay session; not a grant)");
    print_block(&value["transport"], &[
        ("state", "state"),
        ("user", "user"),
        ("relay", "relay"),
        ("access_expires_unix", "access_expires_unix"),
        ("path", "path"),
        ("error", "error"),
        ("note", "note"),
    ]);
    println!();
    println!("Authorization (local grants)");
    let auth = &value["authorization"];
    if let Some(state) = auth["state"].as_str() {
        println!("  state: {state}");
    }
    if let Some(note) = auth["note"].as_str() {
        println!("  note: {note}");
    }
    if let Some(err) = auth["error"].as_str() {
        println!("  error: {err}");
    }
    match auth["grants"].as_array() {
        Some(grants) if grants.is_empty() => println!("  grants: none"),
        Some(grants) => {
            for grant in grants {
                let node = grant["node_id"].as_str().unwrap_or("-");
                let policy = grant["policy"].as_str().unwrap_or("-");
                let status = grant["status"].as_str().unwrap_or("-");
                let cap = grant["capability"].as_str().unwrap_or("-");
                println!("  - {node}  {policy}  {status}");
                println!("    {cap}");
            }
        }
        None => {}
    }
}

fn print_block(obj: &Value, keys: &[(&str, &str)]) {
    for (label, key) in keys {
        if obj.get(*key).map(Value::is_null).unwrap_or(true) {
            continue;
        }
        if let Some(s) = obj[*key].as_str() {
            println!("  {label}: {s}");
        } else {
            println!("  {label}: {}", obj[*key]);
        }
    }
}

/// Helper so tests can point at a temp identity path independently of OS defaults.
pub fn default_identity_path(config_dir: &Path) -> PathBuf {
    config_dir.join("identity.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentlink_core::identity::Identity;

    fn write_session(dir: &Path, expires: i64) {
        let settings = config::ClientSettings {
            relay: "wss://relay.example:7443".into(),
            token: "access-dummy".into(),
            fingerprint: format!("sha256:{}", "ab".repeat(32)),
            trust: None,
        };
        config::save_session(dir, &settings, "alice", "refresh-dummy", expires).unwrap();
    }

    #[test]
    fn status_without_identity_or_session_or_grant() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_identity_path(dir.path());
        assert_eq!(run(dir.path(), &path, true).unwrap(), 0);
        // function already printed; re-build sections
        let ident = identity_section(&path);
        assert_eq!(ident["state"], "missing");
        assert!(!path.exists());
        let transport = transport_section(dir.path());
        assert_eq!(transport["state"], "missing");
        let auth = authorization_section(dir.path());
        assert_eq!(auth["state"], "missing");
        assert_eq!(auth["grants"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn status_identity_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_identity_path(dir.path());
        Identity::load_or_create(&path).unwrap();
        let ident = identity_section(&path);
        assert_eq!(ident["state"], "ok");
        assert!(ident["public_id"].as_str().unwrap().len() == 64);
        assert!(ident["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
        assert!(!ident.to_string().contains("secret_hex"));
        let transport = transport_section(dir.path());
        assert_eq!(transport["state"], "missing");
    }

    #[test]
    fn status_session_without_grant_and_expired_access() {
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), util::unix_now() + 3_600);
        let transport = transport_section(dir.path());
        assert_eq!(transport["state"], "ok");
        assert_eq!(transport["user"], "alice");
        assert_eq!(transport["note"], "a relay device session is not a grant");
        assert!(!transport.to_string().contains("access-dummy"));
        assert!(!transport.to_string().contains("refresh-dummy"));
        write_session(dir.path(), util::unix_now() - 10);
        let expired = transport_section(dir.path());
        assert_eq!(expired["state"], "expired");
        let auth = authorization_section(dir.path());
        assert_eq!(auth["state"], "missing");
    }

    #[test]
    fn status_command_exit_zero_when_everything_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_identity_path(dir.path());
        assert_eq!(run(dir.path(), &path, false).unwrap(), 0);
    }
}
