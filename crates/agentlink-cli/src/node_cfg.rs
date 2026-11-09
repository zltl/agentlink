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
    let saved = read_json(&data_dir.join("node.json"));
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
    let max_policy = if let Some(access) = args.max_access {
        parse_access(&access)?
    } else if let Some(policy) = saved.as_ref().and_then(|v| v.get("max_policy")) {
        serde_json::from_value(policy.clone())
            .unwrap_or_else(|_| agentlink_core::NodePolicy::full())
    } else {
        agentlink_core::NodePolicy::full()
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

fn read_json(path: &std::path::Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn first_string(flag: Option<String>, file: Option<&str>) -> Option<String> {
    flag.filter(|s| !s.trim().is_empty())
        .or_else(|| file.map(str::to_string).filter(|s| !s.trim().is_empty()))
}
