//! Build a [`NodeConfig`] from flags and `node.json`.

use std::path::PathBuf;
use std::sync::Arc;

use agentlink_core::{decode_invite, parse_access, NodePolicy};
use agentlink_desktop::{
    configure_stream, node_bundle, update_stream_policy, ConsentMode, StreamAudit, StreamSettings,
};
use agentlink_node::NodeConfig;
use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::version;

pub struct NodeArgs {
    pub relay: Option<String>,
    pub fingerprint: Option<String>,
    pub trust: Option<String>,
    /// `agentlink-invite:v1:...` from `agentlink pair`. Flags override it.
    pub invite: Option<String>,
    pub name: Option<String>,
    pub pairing_token: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub root: Option<PathBuf>,
    pub max_access: Option<String>,
    /// auto, notify, prompt, or deny. Default is notify.
    pub stream_consent: Option<String>,
}

pub fn load(args: NodeArgs) -> Result<NodeConfig> {
    let data_dir = match args.data_dir {
        Some(dir) => dir,
        None => agentlink_core::config::default_data_dir("node")?,
    };
    let saved = read_saved_node_json(&data_dir.join("node.json"))?;
    let invited = match args
        .invite
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(text) => Some(decode_invite(text).map_err(|err| anyhow!(err.to_string()))?),
        None => None,
    };
    let mut relay = first_string(
        args.relay,
        invited.as_ref().map(|invite| invite.relay.as_str()),
    )
    .or_else(|| {
        saved
            .as_ref()
            .and_then(|v| v["relay_url"].as_str())
            .map(str::to_string)
    })
    .unwrap_or_default();
    let fingerprint = first_string(
        args.fingerprint,
        invited.as_ref().map(|invite| invite.fingerprint.as_str()),
    )
    .or_else(|| {
        saved
            .as_ref()
            .and_then(|v| v["fingerprint"].as_str())
            .map(str::to_string)
    })
    .unwrap_or_default();
    let mut trust = first_string(
        args.trust,
        invited.as_ref().and_then(|invite| invite.trust.as_deref()),
    )
    .or_else(|| {
        saved
            .as_ref()
            .and_then(|v| v["trust"].as_str())
            .map(str::to_string)
    });
    agentlink_core::apply_relay_defaults(&mut relay, &fingerprint, &mut trust);
    if fingerprint.trim().is_empty() && trust.as_deref().unwrap_or("").trim().is_empty() {
        return Err(anyhow!(
            "certificate trust missing; pass --fingerprint, --trust, or --invite"
        ));
    }
    let name = first_string(
        args.name,
        invited.as_ref().map(|invite| invite.name.as_str()),
    )
    .or_else(|| {
        saved
            .as_ref()
            .and_then(|v| v["name"].as_str())
            .map(str::to_string)
    })
    .filter(|value| !value.trim().is_empty())
    .unwrap_or_else(machine_name);
    let root = args.root.or_else(|| {
        saved
            .as_ref()
            .and_then(|v| v["root"].as_str())
            .map(PathBuf::from)
    });
    // First-run (no saved node.json, or a pre-max_policy file with the key
    // absent) defaults to `exec` (matching `NodePolicy::exec()` least-privilege
    // enrollment; opt into desktop/full with `--max-access full`). A present
    // but unreadable `max_policy` is fail-closed: fix or remove the key, then
    // restart.
    let max_policy = if let Some(access) = args.max_access {
        parse_access(&access)?
    } else if let Some(policy) = saved.as_ref().and_then(|v| v.get("max_policy")) {
        serde_json::from_value(policy.clone()).map_err(|err| {
            anyhow!(
                "node.json max_policy is invalid ({err}); refusing to start. Repair or delete that key and restart."
            )
        })?
    } else {
        agentlink_core::NodePolicy::exec()
    };
    let pairing_token = first_string(
        args.pairing_token,
        invited.as_ref().map(|invite| invite.token.as_str()),
    )
    .or_else(|| {
        saved
            .as_ref()
            .and_then(|v| v["pairing_token"].as_str())
            .map(str::to_string)
    });
    let (extensions, capture) = node_bundle();
    let consent = ConsentMode::parse(args.stream_consent.as_deref().unwrap_or("notify"))
        .map_err(|err| anyhow!(err))?;
    configure_stream(
        &extensions,
        StreamSettings {
            policy: max_policy,
            audit_path: data_dir.join("audit.log"),
            consent,
            on_audit: Some(Arc::new(submit_stream_audit)),
            grant_active: Some({
                let dir = data_dir.clone();
                Arc::new(move |jti: &str, _peer: &str| {
                    match agentlink_core::grant::load_revoked_jtis(&dir) {
                        Ok(revoked) => !revoked
                            .iter()
                            .any(|item| item.trim().eq_ignore_ascii_case(jti.trim())),
                        Err(_) => false,
                    }
                })
            }),
        },
    );
    let hooked = extensions.clone();
    Ok(NodeConfig {
        relay_url: relay,
        fingerprint,
        trust,
        data_dir,
        name,
        pairing_token,
        root,
        max_policy,
        version: version::current().to_string(),
        extensions,
        policy_hook: Some(Arc::new(move |policy: NodePolicy| {
            update_stream_policy(&hooked, policy);
        })),
        capture: Some(capture),
    })
}

fn submit_stream_audit(event: &StreamAudit) {
    let category = match event.action.as_str() {
        "stream_start" | "stream_stop" => "desktop_stream",
        _ => "gui_input",
    };
    agentlink_node::audit::submit(agentlink_node::audit::event_for(
        category,
        &event.action,
        &event.client_id,
        &event.detail,
        event.args.clone(),
        event.ok,
        event.error.clone(),
        event.duration,
    ));
}

pub fn machine_name() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "node".into())
}

/// Missing `node.json` is a first start. A present file that cannot be
/// read or parsed must fail closed — never treated as "no config, default
/// to full".
fn read_saved_node_json(path: &std::path::Path) -> Result<Option<Value>> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map(Some).map_err(|err| {
            anyhow!(
                "node.json exists but is not valid JSON ({err}); refusing to start. Repair or replace the file and restart."
            )
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(anyhow!(
            "node.json could not be read ({err}); refusing to start."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_node_json_is_first_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.json");
        assert!(read_saved_node_json(&path).unwrap().is_none());
    }

    #[test]
    fn corrupt_node_json_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.json");
        std::fs::write(&path, "{ this is not json").unwrap();
        let err = read_saved_node_json(&path).unwrap_err().to_string();
        assert!(err.contains("refusing to start"), "{err}");
        assert!(err.contains("not valid JSON"), "{err}");
    }

    #[test]
    fn unreadable_node_json_fails_closed() {
        fn assert_unreadable(path: &std::path::Path) {
            let err = read_saved_node_json(path).unwrap_err().to_string();
            assert!(err.contains("could not be read"), "{err}");
            assert!(err.contains("refusing to start"), "{err}");
            assert!(!err.contains("not valid JSON"), "{err}");
        }

        // A directory occupying the path is a portable I/O failure (no ACL
        // changes on the operator's real files). Must not be treated as missing.
        let dir = tempfile::tempdir().unwrap();
        let as_dir = dir.path().join("node.json");
        std::fs::create_dir(&as_dir).unwrap();
        assert_unreadable(&as_dir);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.path().join("chmod000.json");
            std::fs::write(&path, r#"{"name":"box"}"#).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            let result = read_saved_node_json(&path);
            // Restore so the tempdir can be cleaned up.
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
            let err = result.unwrap_err().to_string();
            assert!(err.contains("could not be read"), "{err}");
            assert!(err.contains("refusing to start"), "{err}");
        }

        // Exclusive share lock: a second open of a well-formed node.json fails
        // with a sharing violation instead of being parsed or treated as missing.
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let path = dir.path().join("locked.json");
            std::fs::write(&path, r#"{"name":"box"}"#).unwrap();
            let _hold = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&path)
                .expect("exclusive lock on temp node.json");
            assert_unreadable(&path);
        }
    }

    #[test]
    fn valid_node_json_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.json");
        std::fs::write(&path, r#"{"name":"box","max_policy":"full"}"#).unwrap();
        let value = read_saved_node_json(&path).unwrap().unwrap();
        assert_eq!(value["name"], "box");
    }
}

fn first_string(flag: Option<String>, file: Option<&str>) -> Option<String> {
    flag.filter(|s| !s.trim().is_empty())
        .or_else(|| file.map(str::to_string).filter(|s| !s.trim().is_empty()))
}
