//! Offline `agentlink status`: identity, transport, and authorization are separate.
//!
//! This command does not contact a relay. A saved relay session is not a grant.

use std::path::{Path, PathBuf};

use agentlink_core::config::{self, FileConfig};
use agentlink_core::grant::{self, format_relative_duration, grant_status, GrantStatus};
use agentlink_core::grant_offer;
use agentlink_core::identity::Identity;
use agentlink_core::node_pin;
use agentlink_core::util;
use anyhow::Result;
use serde_json::{json, Value};

pub fn run(config_dir: &Path, identity_path: &Path, json_mode: bool) -> Result<i32> {
    let identity = identity_section(identity_path);
    let expected_grantee = identity["public_id"].as_str();
    let transport = transport_section(config_dir);
    let authorization = authorization_section(config_dir, expected_grantee);
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
    let refreshable = has_refresh && state == "expired";
    let session_label = if refreshable {
        Some("refreshable (auto-refreshes on next command)")
    } else if state == "ok" && has_refresh {
        Some("active")
    } else {
        None
    };
    let access_expires_relative = expires.map(|exp| relative_time_label(now, exp));
    json!({
        "state": state,
        "session": session_label,
        "refreshable": refreshable,
        "user": file.user,
        "relay": file.relay,
        "default_node": file.default_node,
        "access_expires_unix": expires,
        "access_expires_relative": access_expires_relative,
        "has_refresh_token": has_refresh,
        "path": path,
        "note": "a relay device session is not a grant",
    })
}

fn relative_time_label(now_unix: i64, target_unix: i64) -> String {
    let delta = target_unix.saturating_sub(now_unix);
    if delta > 0 {
        format!("in {}", format_relative_duration(delta))
    } else if delta == 0 {
        "now".to_string()
    } else {
        format!("expired {} ago", format_relative_duration(delta))
    }
}

fn grant_expiry_label(now_unix: i64, exp_unix: i64) -> String {
    if grant::is_permanent_exp(exp_unix) {
        "permanent".to_string()
    } else {
        relative_time_label(now_unix, exp_unix)
    }
}

fn short_hex(id: &str) -> String {
    id.trim().to_ascii_lowercase().chars().take(12).collect()
}

pub(crate) fn status_label(status: GrantStatus) -> &'static str {
    match status {
        GrantStatus::Active => "ACTIVE",
        GrantStatus::Expired => "EXPIRED",
        GrantStatus::NotYetValid => "NOT YET VALID",
        GrantStatus::GranteeMismatch => "WRONG GRANTEE",
        GrantStatus::NodeMismatch => "WRONG NODE",
    }
}

fn authorization_section(config_dir: &Path, expected_grantee: Option<&str>) -> Value {
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
                    let gs = grant_status(&grant, None, expected_grantee, now);
                    let status = status_label(gs);
                    let node_name = node_pin::name_for_id(config_dir, &grant.node_id)
                        .ok()
                        .flatten();
                    let expires_relative = grant_expiry_label(now, grant.exp_unix);
                    json!({
                        "node_name": node_name,
                        "node_id": grant.node_id,
                        "node_short": short_hex(&grant.node_id),
                        "grantee_id": grant.grantee_id,
                        "grantee_matches": gs != GrantStatus::GranteeMismatch,
                        "policy": grant.policy.preset_name(),
                        "capability": grant.policy.capability_summary(),
                        "status": status,
                        "permanent": grant.is_permanent(),
                        "expires_relative": expires_relative,
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
    print_block(
        &value["identity"],
        &[
            ("state", "state"),
            ("public_id", "public_id"),
            ("fingerprint", "fingerprint"),
            ("path", "path"),
            ("error", "error"),
        ],
    );
    println!();
    println!("Transport (relay session; not a grant)");
    let transport = &value["transport"];
    if transport["refreshable"].as_bool() == Some(true) {
        if let Some(session) = transport["session"].as_str() {
            println!("  session: {session}");
        }
    } else if let Some(state) = transport["state"].as_str() {
        println!("  state: {state}");
    }
    print_block(
        transport,
        &[
            ("user", "user"),
            ("relay", "relay"),
            ("default_node", "default_node"),
            ("access_expires", "access_expires_relative"),
            ("path", "path"),
            ("error", "error"),
            ("note", "note"),
        ],
    );
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
    let local_short = value["identity"]["public_id"]
        .as_str()
        .map(short_hex)
        .unwrap_or_default();
    match auth["grants"].as_array() {
        Some(grants) if grants.is_empty() => println!("  grants: none"),
        Some(grants) => {
            for grant in grants {
                let short = grant["node_short"].as_str().unwrap_or("-");
                let node_label = match grant["node_name"].as_str() {
                    Some(name) if !name.trim().is_empty() => format!("{name} ({short}...)"),
                    _ => format!("{short}..."),
                };
                let policy = grant["policy"].as_str().unwrap_or("-");
                let status = grant["status"].as_str().unwrap_or("-");
                let rel = grant["expires_relative"].as_str().unwrap_or("");
                if status == "WRONG GRANTEE" {
                    let bound = grant["grantee_id"]
                        .as_str()
                        .map(short_hex)
                        .unwrap_or_else(|| "?".into());
                    println!(
                        "  - {node_label:<28} {policy:<12} {status} (bound to {bound}.., local {local_short}..)"
                    );
                } else if !rel.is_empty() {
                    println!("  - {node_label:<28} {policy:<12} {status} ({rel})");
                } else {
                    println!("  - {node_label:<28} {policy:<12} {status}");
                }
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
#[allow(dead_code)]
pub fn default_identity_path(config_dir: &Path) -> PathBuf {
    config_dir.join("identity.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentlink_core::identity::Identity;
    use agentlink_core::NodePolicy;

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
        let ident = identity_section(&path);
        assert_eq!(ident["state"], "missing");
        assert!(!path.exists());
        let transport = transport_section(dir.path());
        assert_eq!(transport["state"], "missing");
        let auth = authorization_section(dir.path(), None);
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
        assert_eq!(transport["refreshable"], false);
        assert_eq!(transport["user"], "alice");
        assert_eq!(transport["note"], "a relay device session is not a grant");
        assert!(!transport.to_string().contains("access-dummy"));
        assert!(!transport.to_string().contains("refresh-dummy"));
        write_session(dir.path(), util::unix_now() - 10);
        let expired = transport_section(dir.path());
        assert_eq!(expired["state"], "expired");
        assert_eq!(expired["refreshable"], true);
        assert_eq!(
            expired["session"],
            "refreshable (auto-refreshes on next command)"
        );
        let auth = authorization_section(dir.path(), None);
        assert_eq!(auth["state"], "missing");
    }

    #[test]
    fn status_flags_wrong_grantee_and_resolves_pinned_node_name() {
        let dir = tempfile::tempdir().unwrap();
        let local_id = Identity::load_or_create(&default_identity_path(dir.path())).unwrap();
        let other_device = Identity::generate();
        let issuer = Identity::generate();
        let node = Identity::generate();
        node_pin::observe(dir.path(), "sufa", node.public_hex()).unwrap();
        let now = util::unix_now();
        let foreign_grant = grant::SignedGrant::sign(
            &issuer,
            other_device.public_hex(),
            node.public_hex(),
            NodePolicy::full(),
            now - 60,
            now + 86_400 * 19,
            "jti-foreign",
        )
        .unwrap();
        grant::save_grant(dir.path(), &foreign_grant).unwrap();

        let auth = authorization_section(dir.path(), Some(local_id.public_hex()));
        let list = auth["grants"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["status"], "WRONG GRANTEE");
        assert_eq!(list[0]["grantee_matches"], false);
        assert_eq!(list[0]["node_name"], "sufa");
        assert!(list[0]["expires_relative"].as_str().unwrap().starts_with("in "));
    }

    #[test]
    fn status_command_exit_zero_when_everything_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_identity_path(dir.path());
        assert_eq!(run(dir.path(), &path, false).unwrap(), 0);
    }

    #[test]
    fn status_formats_permanent_grant_as_active_permanent() {
        let dir = tempfile::tempdir().unwrap();
        let local_id = Identity::load_or_create(&default_identity_path(dir.path())).unwrap();
        let issuer = Identity::generate();
        let node = Identity::generate();
        node_pin::observe(dir.path(), "probe", node.public_hex()).unwrap();
        let now = util::unix_now();
        let perm = grant::SignedGrant::sign_permanent(
            &issuer,
            local_id.public_hex(),
            node.public_hex(),
            NodePolicy::full(),
            now - 60,
            "jti-perm",
        )
        .unwrap();
        grant::save_grant(dir.path(), &perm).unwrap();

        let auth = authorization_section(dir.path(), Some(local_id.public_hex()));
        let list = auth["grants"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["status"], "ACTIVE");
        assert_eq!(list[0]["permanent"], true);
        assert_eq!(list[0]["expires_relative"], "permanent");
    }
}
