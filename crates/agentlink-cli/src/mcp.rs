//! MCP server on stdio.
//!
//! Messages are newline-delimited JSON-RPC. A `Content-Length` header is also
//! accepted because a few clients still borrow Language Server Protocol
//! framing. Nothing but protocol messages is written to stdout.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use agentlink_core::engine::XferOpts;
use agentlink_core::protocol::CompressPref;
use agentlink_core::{
    Client, ClientSettings, Error, ExecRequest, Identity, Op, PtySession, PHASE2_INJECT_INPUT,
    PHASE2_SCREENSHOT,
};
use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader};

#[derive(Clone, Debug)]
pub struct McpConfig {
    pub config_dir: PathBuf,
    pub identity_path: PathBuf,
    pub explicit_identity: bool,
    pub relay: Option<String>,
    pub token: Option<String>,
    pub fingerprint: Option<String>,
    pub trust: Option<String>,
    pub preset_settings: Option<ClientSettings>,
}

impl McpConfig {
    pub fn from_settings(settings: ClientSettings, identity_path: PathBuf) -> Self {
        let config_dir = identity_path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            config_dir,
            identity_path,
            explicit_identity: false,
            relay: None,
            token: None,
            fingerprint: None,
            trust: None,
            preset_settings: Some(settings),
        }
    }
}

pub async fn serve(config: McpConfig) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut state = new_state_from_config(config);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            incoming = read_message(&mut reader) => {
                match incoming? {
                    None => break,
                    Some(message) => {
                        if let Some(response) = handle(&mut state, message).await {
                            write_message(&response)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) struct Mcp {
    pub(crate) config: McpConfig,
    resolved_settings: Option<ClientSettings>,
    client: Option<Client>,
    terminals: HashMap<String, PtySession>,
}

pub(crate) fn new_state_from_config(config: McpConfig) -> Mcp {
    let resolved_settings = config.preset_settings.clone();
    Mcp {
        config,
        resolved_settings,
        client: None,
        terminals: HashMap::new(),
    }
}

#[allow(dead_code)]
pub(crate) fn new_state(settings: ClientSettings, identity_path: PathBuf) -> Mcp {
    new_state_from_config(McpConfig::from_settings(settings, identity_path))
}

pub(crate) async fn handle(state: &mut Mcp, message: Value) -> Option<Value> {
    if !message.is_object() {
        return Some(rpc_error(Value::Null, -32600, "invalid request"));
    }
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let has_id = message.get("id").map(|id| !id.is_null()).unwrap_or(false);
    let params = message.get("params").cloned().unwrap_or(Value::Null);

    if method.starts_with("notifications/") || !has_id {
        return None;
    }

    match method {
        "initialize" => {
            let protocol = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2024-11-05");
            Some(rpc_result(
                id,
                json!({
                    "protocolVersion": protocol,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": {
                        "name": "agentlink",
                        "version": crate::version::current(),
                    },
                    "instructions": "Call list_machines, then address a node by name or id. File tools include read_file, write_file, list_dir, stat_path, mkdir, remove_path, move_path, copy_path, search_content, search_files, replace_text, edit_lines, and apply_patch. copy_path moves whole files and directories. Every control call needs a signed grant for this client's key on the node. The node's --max-access ceiling can still narrow that grant. A relay login or client preset does not authorize the machine. terminal_* is a poll-based PTY because this server uses stdio. screenshot, click, type, key, scroll, get_ui_tree, and act_on_element also need the node ceiling to allow desktop."
                }),
            ))
        }
        "ping" => Some(rpc_result(id, json!({}))),
        "tools/list" => Some(rpc_result(id, json!({ "tools": tool_specs() }))),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            if name == "screenshot" {
                match screenshot_tool(state, &args).await {
                    Ok(value) => Some(rpc_result(id, value)),
                    Err(err) => Some(rpc_result(id, tool_err(&err))),
                }
            } else {
                match call_tool(state, name, &args).await {
                    Ok(text) => Some(rpc_result(id, tool_ok(&text))),
                    Err(err) => Some(rpc_result(id, tool_err(&err))),
                }
            }
        }
        "" => Some(rpc_error(id, -32600, "missing method")),
        other => Some(rpc_error(id, -32601, &format!("unknown method {other}"))),
    }
}

fn mcp_grant_status_str(status: agentlink_core::grant::GrantStatus) -> &'static str {
    match status {
        agentlink_core::grant::GrantStatus::Active => "active",
        agentlink_core::grant::GrantStatus::Expired => "expired",
        agentlink_core::grant::GrantStatus::NotYetValid => "not_yet_valid",
        agentlink_core::grant::GrantStatus::GranteeMismatch => "wrong_grantee",
        agentlink_core::grant::GrantStatus::NodeMismatch => "wrong_node",
    }
}

fn resolve_node_alias(state: &Mcp, raw: &str) -> String {
    let cfg = agentlink_core::config::load_file(&state.config.config_dir).unwrap_or_default();
    cfg.aliases
        .get(raw)
        .cloned()
        .unwrap_or_else(|| raw.to_string())
}

fn required_node(state: &Mcp, args: &Value, key: &str) -> std::result::Result<String, String> {
    let raw = required_str(args, key)?;
    Ok(resolve_node_alias(state, &raw))
}

fn get_status_tool(state: &Mcp) -> String {
    let now = agentlink_core::util::unix_now();
    let cfg = agentlink_core::config::load_file(&state.config.config_dir).unwrap_or_default();
    let local_identity = Identity::load(&state.config.identity_path).ok();
    let local_public_id = local_identity
        .as_ref()
        .map(|id| id.public_hex().to_string());

    let relay = state
        .config
        .relay
        .clone()
        .or_else(|| state.config.preset_settings.as_ref().map(|s| s.relay.clone()))
        .or_else(|| cfg.relay.clone());

    let has_refresh = cfg
        .refresh_token
        .as_deref()
        .is_some_and(|t| !t.trim().is_empty());
    let has_token = cfg.token.as_deref().is_some_and(|t| !t.trim().is_empty())
        || state
            .config
            .token
            .as_deref()
            .is_some_and(|t| !t.trim().is_empty())
        || state
            .config
            .preset_settings
            .as_ref()
            .is_some_and(|s| !s.token.trim().is_empty());

    let session_state = match (has_token, has_refresh, cfg.access_expires_unix) {
        (true, _, Some(exp)) if exp > now => "active",
        (_, true, _) => "refreshable",
        (true, false, Some(_)) => "expired",
        (true, false, None) => "token",
        (false, false, _) if state.config.explicit_identity => "identity_only",
        (false, false, _) => "none",
    };

    let authenticated = session_state != "none"
        && session_state != "expired"
        && relay.as_deref().is_some_and(|r| !r.trim().is_empty());
    let default_node = std::env::var("AGENTLINK_NODE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| cfg.default_node.clone());

    let stored = agentlink_core::grant::list_stored_grants(&state.config.config_dir)
        .unwrap_or_default();
    let grants: Vec<Value> = stored
        .iter()
        .map(|item| {
            let status = agentlink_core::grant::grant_status(
                &item.grant,
                Some(&item.grant.node_id),
                local_public_id.as_deref(),
                now,
            );
            let node_name =
                agentlink_core::node_pin::name_for_id(&state.config.config_dir, &item.grant.node_id)
                    .ok()
                    .flatten();
            json!({
                "node_id": item.grant.node_id,
                "node_name": node_name,
                "jti": item.grant.jti,
                "grant_status": mcp_grant_status_str(status),
                "grant_expires_in_secs": item.grant.exp_unix - now,
                "exp_unix": item.grant.exp_unix,
                "access": item.grant.policy.capability_summary(),
            })
        })
        .collect();

    pretty(&json!({
        "config_dir": state.config.config_dir.display().to_string(),
        "identity_path": state.config.identity_path.display().to_string(),
        "identity_exists": local_public_id.is_some(),
        "public_id": local_public_id,
        "relay": relay,
        "session_state": session_state,
        "authenticated": authenticated,
        "default_node": default_node,
        "aliases": cfg.aliases,
        "grants": grants,
    }))
}

async fn call_tool(
    state: &mut Mcp,
    name: &str,
    args: &Value,
) -> std::result::Result<String, String> {
    match name {
        "get_status" => Ok(get_status_tool(state)),
        "list_machines" => {
            let nodes = retry(state, |client| Box::pin(client.list_nodes())).await?;
            let now = agentlink_core::util::unix_now();
            let local_public_id = Identity::load(&state.config.identity_path)
                .ok()
                .map(|id| id.public_hex().to_string());
            let mut enriched = Vec::with_capacity(nodes.len());
            for node in nodes {
                let mut val = serde_json::to_value(&node).unwrap_or_else(|_| json!({}));
                let (grant_status_str, expires_in) = match agentlink_core::grant::load_grant(
                    &state.config.config_dir,
                    &node.id,
                ) {
                    Ok(Some(grant)) => {
                        let status = agentlink_core::grant::grant_status(
                            &grant,
                            Some(&node.id),
                            local_public_id.as_deref(),
                            now,
                        );
                        (mcp_grant_status_str(status), Some(grant.exp_unix - now))
                    }
                    _ => ("missing", None),
                };
                if let Some(obj) = val.as_object_mut() {
                    obj.insert("grant_status".into(), json!(grant_status_str));
                    obj.insert("grant_expires_in_secs".into(), json!(expires_in));
                }
                enriched.push(val);
            }
            Ok(pretty(&json!({"machines": enriched})))
        }
        "list_dir" => {
            let node = required_node(state, args, "node")?;
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or(".")
                .to_string();
            let node_label = node.clone();
            let path_label = path.clone();
            let entries = retry(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                Box::pin(async move { client.list_dir(&node, &path).await })
            })
            .await
            .map_err(|err| {
                let err = crate::decorate_list_dir_permission(&err, &node_label, &path_label);
                crate::decorate_list_dir_io_missing(&err, &node_label, &path_label)
            })?;
            Ok(pretty(&json!(entries)))
        }
        "stat_path" => {
            let node = required_node(state, args, "node")?;
            let path = required_str(args, "path")?;
            let node_label = node.clone();
            let path_label = path.clone();
            let stat = retry(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                Box::pin(async move { client.stat(&node, &path).await })
            })
            .await
            .map_err(|err| crate::decorate_stat_path_permission(&err, &node_label, &path_label))?;
            Ok(pretty(&json!(stat)))
        }
        "read_file" => read_file_tool(state, args).await,
        "write_file" => {
            let node = required_node(state, args, "node")?;
            let path = required_str(args, "path")?;
            let bytes = decode_content(args)?;
            let n = bytes.len();
            let path_out = path.clone();
            let node_out = node.clone();
            run_once(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                let bytes = bytes.clone();
                Box::pin(async move {
                    let mut cursor = std::io::Cursor::new(bytes);
                    client
                        .stream_upload(&node, &path, &mut cursor, &XferOpts::default())
                        .await
                        .map(|_| ())
                })
            })
            .await
            .map_err(|err| crate::decorate_write_dest_permission(&err, &node_out, &path_out))?;
            Ok(pretty(&json!({"path": path_out, "bytes": n})))
        }
        "mkdir" => {
            let node = required_node(state, args, "node")?;
            let path = required_str(args, "path")?;
            let parents = args.get("parents").and_then(Value::as_bool).unwrap_or(true);
            let path_out = path.clone();
            let node_out = node.to_string();
            match run_once(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                Box::pin(async move { client.mkdir(&node, &path, parents).await })
            })
            .await
            {
                Ok(()) => Ok(pretty(&json!({"path": path_out, "created": true}))),
                Err(err) => Err(crate::decorate_mkdir_missing_parent(
                    &crate::decorate_mkdir_already_exists(
                        &crate::decorate_mkdir_dest_permission(&err, &node_out, &path_out, parents),
                        &path_out,
                    ),
                    &path_out,
                    parents,
                )),
            }
        }
        "remove_path" => {
            let node = required_node(state, args, "node")?;
            let path = required_str(args, "path")?;
            let recursive = args
                .get("recursive")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let path_out = path.clone();
            let node_out = node.clone();
            match run_once(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                Box::pin(async move { client.remove(&node, &path, recursive).await })
            })
            .await
            {
                Ok(()) => Ok(pretty(&json!({"path": path_out, "removed": true}))),
                Err(err) => {
                    let err = crate::decorate_remove_dest_permission(
                        &err, &node_out, &path_out, recursive,
                    );
                    Err(if recursive {
                        err
                    } else {
                        crate::decorate_remove_not_empty(&err)
                    })
                }
            }
        }
        "move_path" => {
            let node = required_node(state, args, "node")?;
            let from = required_str(args, "from")?;
            let to = required_str(args, "to")?;
            let node_fallback = node.clone();
            let from_fallback = from.clone();
            let to_fallback = to.clone();
            let body = match run_once(state, move |client| {
                let node = node.clone();
                let from = from.clone();
                let to = to.clone();
                Box::pin(async move { client.rename(&node, &from, &to).await })
            })
            .await
            {
                Ok(body) => body,
                Err(err) => {
                    let err = crate::decorate_mv_dest_permission(
                        &err,
                        &node_fallback,
                        &from_fallback,
                        &to_fallback,
                    );
                    return Err(crate::decorate_mv_target_not_empty(
                        &err,
                        &from_fallback,
                        &to_fallback,
                    ));
                }
            };
            let from_out = body
                .get("from")
                .and_then(Value::as_str)
                .unwrap_or(&from_fallback)
                .to_string();
            let to_out = body
                .get("to")
                .and_then(Value::as_str)
                .unwrap_or(&to_fallback)
                .to_string();
            Ok(pretty(&json!({"from": from_out, "to": to_out})))
        }
        "run_command" => run_command(state, args).await,
        "search_content" => {
            let node = required_node(state, args, "node")?;
            let pattern = required_str(args, "pattern")?;
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or(".")
                .to_string();
            let literal = args
                .get("literal")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let include = string_list(args, "include");
            let exclude = string_list(args, "exclude");
            let gitignore = args
                .get("gitignore")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let include_hidden = args
                .get("include_hidden")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let case_insensitive = args
                .get("case_insensitive")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let before = number(args, "before") as u32;
            let after = number(args, "after") as u32;
            let offset = number(args, "offset") as u32;
            let limit = {
                let limit = number(args, "limit");
                if limit == 0 {
                    100
                } else {
                    limit as u32
                }
            };
            let node_label = node.clone();
            let path_label = path.clone();
            let value = retry(state, move |client| {
                let node = node.clone();
                let pattern = pattern.clone();
                let path = path.clone();
                let include = include.clone();
                let exclude = exclude.clone();
                Box::pin(async move {
                    client
                        .search(
                            &node,
                            &path,
                            &pattern,
                            literal,
                            include,
                            exclude,
                            gitignore,
                            include_hidden,
                            case_insensitive,
                            before,
                            after,
                            offset,
                            limit,
                        )
                        .await
                })
            })
            .await
            .map_err(|err| {
                crate::decorate_search_permission(&err, &node_label, &path_label)
            })?;
            Ok(pretty(&value))
        }
        "search_files" => {
            let node = required_node(state, args, "node")?;
            let pattern = required_str(args, "pattern")?;
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or(".")
                .to_string();
            let regex = args.get("regex").and_then(Value::as_bool).unwrap_or(false);
            let gitignore = args
                .get("gitignore")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let include_hidden = args
                .get("include_hidden")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let case_insensitive = args
                .get("case_insensitive")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let offset = number(args, "offset") as u32;
            let limit = {
                let limit = number(args, "limit");
                if limit == 0 {
                    200
                } else {
                    limit as u32
                }
            };
            let value = retry(state, move |client| {
                let node = node.clone();
                let pattern = pattern.clone();
                let path = path.clone();
                Box::pin(async move {
                    client
                        .find(
                            &node,
                            &path,
                            &pattern,
                            regex,
                            gitignore,
                            include_hidden,
                            case_insensitive,
                            offset,
                            limit,
                        )
                        .await
                })
            })
            .await?;
            Ok(pretty(&value))
        }
        "replace_text" => {
            let node = required_node(state, args, "node")?;
            let path = required_str(args, "path")?;
            // Don't use `required_str` here: a present-but-empty `old` must
            // reach the empty-anchor tip instead of reading as missing.
            let old = match args.get("old").and_then(Value::as_str) {
                Some(old) if !old.is_empty() => old.to_string(),
                Some(_) => return Err("old string is empty".into()),
                None => return Err("missing `old`".into()),
            };
            let new = args
                .get("new")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let replace_all = args
                .get("replace_all")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let path_out = path.clone();
            let value = run_once(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                let old = old.clone();
                let new = new.clone();
                Box::pin(async move { client.replace(&node, &path, &old, &new, replace_all).await })
            })
            .await
            .map_err(|err| crate::decorate_replace_missing_file(&err, &path_out))?;
            Ok(pretty(&value))
        }
        "edit_lines" => {
            let node = required_node(state, args, "node")?;
            let path = required_str(args, "path")?;
            let start = number(args, "start_line") as u32;
            let end = number(args, "end_line") as u32;
            let content = args
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if start == 0 || end == 0 {
                return Err("line numbers are 1-based".into());
            }
            let value = run_once(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                let content = content.clone();
                Box::pin(async move { client.edit_lines(&node, &path, start, end, &content).await })
            })
            .await?;
            Ok(pretty(&value))
        }
        "apply_patch" => {
            let node = required_node(state, args, "node")?;
            let root = args
                .get("root")
                .and_then(Value::as_str)
                .unwrap_or(".")
                .to_string();
            let patch = required_str(args, "patch")?;
            let value = run_once(state, move |client| {
                let node = node.clone();
                let root = root.clone();
                let patch = patch.clone();
                Box::pin(async move { client.apply_patch(&node, &root, &patch).await })
            })
            .await?;
            Ok(pretty(&value))
        }
        "watch_start" => {
            let node = required_node(state, args, "node")?;
            let path = required_str(args, "path")?;
            let recursive = args
                .get("recursive")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let value = run_once(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                Box::pin(async move { client.watch_start(&node, &path, recursive).await })
            })
            .await?;
            Ok(pretty(&value))
        }
        "watch_poll" => {
            let node = required_node(state, args, "node")?;
            let watch_id = required_str(args, "watch_id")?;
            let cursor = number(args, "cursor");
            let timeout_ms = {
                let value = number(args, "timeout_ms");
                if value == 0 {
                    1000
                } else {
                    value
                }
            };
            let limit = number(args, "limit") as u32;
            let value = retry(state, move |client| {
                let node = node.clone();
                let watch_id = watch_id.clone();
                Box::pin(async move {
                    client
                        .watch_poll(&node, &watch_id, cursor, timeout_ms, limit)
                        .await
                })
            })
            .await?;
            Ok(pretty(&value))
        }
        "watch_stop" => {
            let node = required_node(state, args, "node")?;
            let watch_id = required_str(args, "watch_id")?;
            let value = run_once(state, move |client| {
                let node = node.clone();
                let watch_id = watch_id.clone();
                Box::pin(async move { client.watch_stop(&node, &watch_id).await })
            })
            .await?;
            Ok(pretty(&value))
        }
        "process_start" => {
            let node = required_node(state, args, "node")?;
            let cwd = args.get("cwd").and_then(Value::as_str).map(str::to_string);
            let env = parse_env_arg(args)?;
            let stdin = parse_stdin_arg(args)?;
            let (program, argv, shell) = command_argv(args)?;
            let node_label = node.clone();
            let program_label = program.clone();
            let cwd_label = cwd.clone();
            let value = run_once(state, move |client| {
                let node = node.clone();
                let program = program.clone();
                let argv = argv.clone();
                let cwd = cwd.clone();
                let env = env.clone();
                let stdin = stdin.clone();
                Box::pin(async move {
                    client
                        .bg_start(&node, &program, argv, cwd, env, shell, stdin)
                        .await
                })
            })
            .await
            .map_err(|err| {
                crate::decorate_bg_start_exec_denied(
                    &err,
                    &node_label,
                    &program_label,
                    cwd_label.as_deref(),
                )
            })?;
            Ok(pretty(&value))
        }
        "process_list" => {
            let node = required_node(state, args, "node")?;
            let value = retry(state, move |client| {
                let node = node.clone();
                Box::pin(async move { client.bg_list(&node).await })
            })
            .await?;
            Ok(pretty(&value))
        }
        "process_output" => {
            let node = required_node(state, args, "node")?;
            let id = required_str(args, "id")?;
            let stdout_cursor = number(args, "stdout_cursor");
            let stderr_cursor = number(args, "stderr_cursor");
            let max_bytes = number(args, "max_bytes") as u32;
            let value = retry(state, move |client| {
                let node = node.clone();
                let id = id.clone();
                Box::pin(async move {
                    client
                        .bg_output(&node, &id, stdout_cursor, stderr_cursor, max_bytes)
                        .await
                })
            })
            .await?;
            Ok(pretty(&value))
        }
        "process_status" => {
            let node = required_node(state, args, "node")?;
            let id = required_str(args, "id")?;
            let value = retry(state, move |client| {
                let node = node.clone();
                let id = id.clone();
                Box::pin(async move { client.bg_status(&node, &id).await })
            })
            .await?;
            Ok(pretty(&value))
        }
        "process_kill" => {
            let node = required_node(state, args, "node")?;
            let id = required_str(args, "id")?;
            let value = run_once(state, move |client| {
                let node = node.clone();
                let id = id.clone();
                Box::pin(async move { client.bg_kill(&node, &id).await })
            })
            .await?;
            Ok(pretty(&value))
        }
        "system_info" => {
            let node = required_node(state, args, "node")?;
            let value = retry(state, move |client| {
                let node = node.clone();
                Box::pin(async move { client.sysinfo(&node).await })
            })
            .await?;
            Ok(pretty(&value))
        }
        "terminal_open" => terminal_open(state, args).await,
        "terminal_write" => terminal_write(state, args).await,
        "terminal_read" => terminal_read(state, args).await,
        "terminal_resize" => terminal_resize(state, args).await,
        "terminal_close" => terminal_close(state, args).await,
        "copy_path" => copy_path_tool(state, args).await,
        "click" => desktop_tool(state, args, click_payload(args)?, false).await,
        "type" => {
            let text = required_str(args, "text")?;
            desktop_tool(state, args, json!({"action": "type", "text": text}), false).await
        }
        "key" => {
            let keys = required_str(args, "keys")?;
            desktop_tool(state, args, json!({"action": "key", "keys": keys}), false).await
        }
        "scroll" => {
            let has_x = args.get("x").is_some_and(|value| value.is_number());
            let has_y = args.get("y").is_some_and(|value| value.is_number());
            if has_x != has_y {
                return Err("scroll needs both x and y, or neither".into());
            }
            let mut payload = json!({
                "action": "scroll",
                "dx": args.get("dx").and_then(Value::as_i64).unwrap_or(0),
                "dy": args.get("dy").and_then(Value::as_i64).unwrap_or(0),
            });
            if has_x {
                payload["x"] = args.get("x").cloned().unwrap();
                payload["y"] = args.get("y").cloned().unwrap();
            }
            desktop_tool(state, args, payload, false).await
        }
        "get_ui_tree" => {
            desktop_tool(
                state,
                args,
                json!({
                    "action": "ui_tree",
                    "max_depth": args.get("max_depth").and_then(Value::as_u64).unwrap_or(6),
                    "max_nodes": args.get("max_nodes").and_then(Value::as_u64).unwrap_or(400),
                }),
                true,
            )
            .await
        }
        "act_on_element" => {
            let id = required_str(args, "id")?;
            let op = args.get("op").and_then(Value::as_str).unwrap_or("click");
            let mut payload = json!({"action": "act", "id": id, "op": op});
            if let Some(value) = args.get("value").and_then(Value::as_str) {
                payload["value"] = json!(value);
            }
            desktop_tool(state, args, payload, false).await
        }
        other => Err(format!("unknown tool {other}")),
    }
}

const READ_FILE_DEFAULT_MAX_BYTES: u64 = 64 * 1024;
const READ_FILE_MAX_BYTES_CAP: u64 = 1024 * 1024;

fn slice_utf8_lines(
    text: &str,
    start_line: Option<u64>,
    end_line: Option<u64>,
) -> std::result::Result<(String, u64, u64, usize, bool), String> {
    if let Some(0) = start_line {
        return Err("start_line is 1-based".into());
    }
    if let Some(0) = end_line {
        return Err("end_line is 1-based".into());
    }
    let start = start_line.unwrap_or(1);
    if let Some(end) = end_line {
        if end < start {
            return Err("end_line must be >= start_line".into());
        }
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let total = lines.len();
    let start_idx = (start as usize).saturating_sub(1);
    let end_idx = end_line
        .map(|e| (e as usize).min(total))
        .unwrap_or(total);
    let sliced = if start_idx >= total || start_idx >= end_idx {
        String::new()
    } else {
        lines[start_idx..end_idx].concat()
    };
    let effective_end = end_line.unwrap_or(total as u64).min(total as u64);
    let clipped = end_idx < total;
    Ok((sliced, start, effective_end, total, clipped))
}

async fn read_file_tool(state: &mut Mcp, args: &Value) -> std::result::Result<String, String> {
    let node = required_node(state, args, "node")?;
    let path = required_str(args, "path")?;
    let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let start_line = args.get("start_line").and_then(Value::as_u64);
    let end_line = args.get("end_line").and_then(Value::as_u64);
    if let Some(0) = start_line {
        return Err("start_line is 1-based".into());
    }
    if let Some(0) = end_line {
        return Err("end_line is 1-based".into());
    }
    if let (Some(s), Some(e)) = (start_line, end_line) {
        if e < s {
            return Err("end_line must be >= start_line".into());
        }
    }
    let line_mode = start_line.is_some() || end_line.is_some();
    let default_bytes = if line_mode {
        READ_FILE_MAX_BYTES_CAP
    } else {
        READ_FILE_DEFAULT_MAX_BYTES
    };
    let max_bytes = args
        .get("max_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(default_bytes)
        .min(READ_FILE_MAX_BYTES_CAP) as u32;
    let node_label = node.clone();
    let path_label = path.clone();
    let (data, file_size, end) = {
        let node = node.clone();
        let path = path.clone();
        retry(state, move |client| {
            let node = node.clone();
            let path = path.clone();
            Box::pin(async move {
                let mut data = Vec::new();
                let body = client
                    .stream_download(
                        &node,
                        &path,
                        offset,
                        Some(u64::from(max_bytes)),
                        &mut data,
                        &XferOpts::default(),
                    )
                    .await?;
                Ok((data, body.file_size, body.end))
            })
        })
        .await
        .map_err(|err| {
            crate::decorate_read_file_permission(
                &crate::decorate_read_dangling_symlink(&crate::decorate_read_missing_file(&err)),
                &node_label,
                &path_label,
            )
        })?
    };
    let truncated = end < file_size;
    if line_mode {
        let text = std::str::from_utf8(&data)
            .map_err(|_| "start_line/end_line requires a UTF-8 text file".to_string())?;
        let (sliced, eff_start, eff_end, total_lines, clipped) =
            slice_utf8_lines(text, start_line, end_line)?;
        return Ok(pretty(&json!({
            "path": path,
            "offset": offset,
            "encoding": "utf-8",
            "content": sliced,
            "bytes": sliced.len(),
            "size": file_size,
            "start_line": eff_start,
            "end_line": eff_end,
            "total_lines": total_lines,
            "truncated": truncated || clipped,
        })));
    }
    Ok(encode_bytes(&path, offset, &data, truncated, file_size))
}

async fn copy_path_tool(state: &mut Mcp, args: &Value) -> std::result::Result<String, String> {
    let direction = required_str(args, "direction")?;
    let node = required_node(state, args, "node")?;
    let path = required_str(args, "path")?;
    let compress = match args
        .get("compress")
        .and_then(Value::as_str)
        .unwrap_or("auto")
    {
        "auto" => CompressPref::Auto,
        "on" => CompressPref::On,
        "off" => CompressPref::Off,
        other => return Err(format!("compress must be auto, on, or off, got {other}")),
    };
    let chunk = args
        .get("chunk_size")
        .and_then(Value::as_u64)
        .unwrap_or(1024 * 1024) as usize;
    let direct = args.get("direct").and_then(Value::as_bool).unwrap_or(true);
    let opts = XferOpts {
        chunk_size: chunk,
        window: 8,
        parallel: 4,
        compress,
        resume: true,
        transport: if direct {
            "relay".into()
        } else {
            "relay-only".into()
        },
    };
    let stats = match direction.as_str() {
        "upload" => {
            let local = required_str(args, "local")?;
            let local_path = std::path::PathBuf::from(&local);
            let file_name = crate::file_name_hint(&local_path)
                .map(str::to_string)
                .map_err(|e| e.to_string())?;
            run_once(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                let file_name = file_name.clone();
                let local_path = local_path.clone();
                let opts = opts.clone();
                Box::pin(async move {
                    let resolved = crate::resolve_remote_cp_dest(client, &node, &path, &file_name)
                        .await
                        .map_err(|e| Error::Message(e.to_string()))?;
                    client
                        .copy_upload(&node, &resolved, &local_path, &opts, None)
                        .await
                })
            })
            .await
            .map_err(|err| {
                crate::decorate_copy_upload_dangling_local(
                    &crate::decorate_copy_upload_missing_local(&err),
                )
            })?
        }
        "download" => {
            let local = required_str(args, "local")?;
            let local_path = crate::resolve_local_cp_dest(std::path::Path::new(&local), &path)
                .map_err(|e| e.to_string())?;
            if let Some(parent) = local_path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).ok();
                }
            }
            retry(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                let local_path = local_path.clone();
                let opts = opts.clone();
                Box::pin(async move {
                    client
                        .copy_download(&node, &path, &local_path, &opts, None)
                        .await
                })
            })
            .await
            .map_err(|err| {
                crate::decorate_read_dangling_symlink(&crate::decorate_read_missing_file(&err))
            })?
        }
        "peer" => {
            let dst_node = required_node(state, args, "dst_node")?;
            let dst_path = required_str(args, "dst_path")?;
            let src_node = node.clone();
            let src_path = path.clone();
            let dst_label = dst_node.clone();
            let dst_path_label = dst_path.clone();
            let file_name = crate::file_name_hint_str(&src_path)
                .map(str::to_string)
                .map_err(|e| e.to_string())?;
            run_once(state, move |client| {
                let node = node.clone();
                let path = path.clone();
                let dst_node = dst_node.clone();
                let dst_path = dst_path.clone();
                let file_name = file_name.clone();
                let opts = opts.clone();
                Box::pin(async move {
                    let resolved =
                        crate::resolve_remote_cp_dest(client, &dst_node, &dst_path, &file_name)
                            .await
                            .map_err(|e| Error::Message(e.to_string()))?;
                    client
                        .copy_node_to_node(&node, &path, &dst_node, &resolved, &opts, direct, None)
                        .await
                })
            })
            .await
            .map_err(|err| {
                let err = crate::decorate_copy_peer_source_missing(
                    &err,
                    &src_node,
                    &src_path,
                    &dst_label,
                    &dst_path_label,
                );
                crate::decorate_copy_peer_dangling_source(
                    &err,
                    &src_node,
                    &src_path,
                    &dst_label,
                    &dst_path_label,
                )
            })?
        }
        other => {
            return Err(format!(
                "direction must be upload, download, or peer, got {other}"
            ))
        }
    };
    Ok(pretty(&json!(stats)))
}

async fn run_command(state: &mut Mcp, args: &Value) -> std::result::Result<String, String> {
    let node = required_node(state, args, "node")?;
    let cwd = args.get("cwd").and_then(Value::as_str).map(str::to_string);
    let cwd_label = cwd.clone();
    let env = parse_env_arg(args)?;
    let timeout = args
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .map(Duration::from_millis)
        .or(Some(Duration::from_secs(60)));
    let stdin = parse_stdin_arg(args)?;
    let req = if let Some(argv) = args.get("argv").and_then(Value::as_array) {
        if argv.is_empty() {
            return Err("argv is empty".into());
        }
        let program = argv[0]
            .as_str()
            .ok_or("argv values must be strings")?
            .to_string();
        let rest = argv
            .iter()
            .skip(1)
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or("argv values must be strings")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ExecRequest {
            program,
            args: rest,
            cwd,
            env,
            timeout,
            shell: false,
            stdin,
        }
    } else {
        let command = required_str(args, "command")?;
        let mut req = ExecRequest::shell(command, timeout);
        req.cwd = cwd;
        req.env = env;
        req.stdin = stdin;
        req
    };
    let output = run_once(state, move |client| {
        let node = node.clone();
        let req = req.clone();
        Box::pin(async move { client.exec_collect(&node, req, Some(1024 * 1024)).await })
    })
    .await
    .map_err(|err| crate::decorate_exec_eacces(&err, cwd_label.as_deref()))?;
    Ok(pretty(&json!({
        "exit_code": output.exit_code,
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": String::from_utf8_lossy(&output.stderr),
        "truncated": output.truncated,
    })))
}

async fn desktop_tool(
    state: &mut Mcp,
    args: &Value,
    payload: Value,
    idempotent: bool,
) -> std::result::Result<String, String> {
    let node = required_node(state, args, "node")?;
    let value = extension_call(state, node, PHASE2_INJECT_INPUT, payload, idempotent).await?;
    Ok(pretty(&value))
}

async fn screenshot_tool(state: &mut Mcp, args: &Value) -> std::result::Result<Value, String> {
    let node = required_node(state, args, "node")?;
    let mut payload = json!({
        "target": args.get("target").and_then(Value::as_str).unwrap_or("screen"),
        "format": args.get("format").and_then(Value::as_str).unwrap_or("jpeg"),
        "quality": args.get("quality").and_then(Value::as_u64).unwrap_or(80),
        "scale": args.get("scale").and_then(Value::as_f64).unwrap_or(1.0),
    });
    for key in ["monitor", "window_id", "x", "y", "width", "height"] {
        if let Some(value) = args.get(key) {
            payload[key] = value.clone();
        }
    }
    let mut value = extension_call(state, node, PHASE2_SCREENSHOT, payload, true).await?;
    let Some(data) = value["data_b64"].as_str().map(str::to_string) else {
        return Ok(tool_ok(&pretty(&value)));
    };
    let mime = value["mime"].as_str().unwrap_or("image/jpeg").to_string();
    if let Some(object) = value.as_object_mut() {
        object.remove("data_b64");
    }
    Ok(json!({
        "content": [
            {"type": "text", "text": pretty(&value)},
            {"type": "image", "data": data, "mimeType": mime}
        ],
        "isError": false,
    }))
}

async fn extension_call(
    state: &mut Mcp,
    node: String,
    name: &'static str,
    payload: Value,
    idempotent: bool,
) -> std::result::Result<Value, String> {
    if idempotent {
        retry(state, move |client| {
            let node = node.clone();
            let payload = payload.clone();
            Box::pin(async move {
                client
                    .call_op(
                        &node,
                        Op::Extension {
                            name: name.to_string(),
                            payload,
                        },
                    )
                    .await
            })
        })
        .await
    } else {
        run_once(state, move |client| {
            let node = node.clone();
            let payload = payload.clone();
            Box::pin(async move {
                client
                    .call_op(
                        &node,
                        Op::Extension {
                            name: name.to_string(),
                            payload,
                        },
                    )
                    .await
            })
        })
        .await
    }
}

fn click_payload(args: &Value) -> std::result::Result<Value, String> {
    let x = coord_arg(args, "x")?;
    let y = coord_arg(args, "y")?;
    let button = args.get("button").and_then(Value::as_str).unwrap_or("left");
    if args
        .get("move_only")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!({"action": "move", "x": x, "y": y}));
    }
    if let (Some(to_x), Some(to_y)) = (
        args.get("to_x").filter(|value| value.is_number()),
        args.get("to_y").filter(|value| value.is_number()),
    ) {
        return Ok(json!({
            "action": "drag",
            "x": x,
            "y": y,
            "to_x": to_x,
            "to_y": to_y,
            "button": button,
        }));
    }
    let count = args.get("count").and_then(Value::as_u64).unwrap_or(1);
    Ok(json!({"action": "click", "x": x, "y": y, "button": button, "count": count}))
}

/// Accept an integer pixel or a 0–1 fraction; the node resolves fractions.
fn coord_arg(args: &Value, key: &str) -> std::result::Result<Value, String> {
    let value = args.get(key).ok_or_else(|| format!("missing `{key}`"))?;
    match value.as_f64() {
        Some(number) if number.is_finite() => Ok(value.clone()),
        _ => Err(format!("`{key}` must be a finite number")),
    }
}

/// Execute a non-idempotent RPC once. Reconnects beforehand if the cached
/// client is already dead, and drops the dead client if the transport closes
/// mid-call, but NEVER automatically re-executes the operation.
async fn run_once<T, F>(state: &mut Mcp, mut op: F) -> std::result::Result<T, String>
where
    F: for<'a> FnMut(
        &'a Client,
    ) -> Pin<Box<dyn Future<Output = agentlink_core::Result<T>> + Send + 'a>>,
{
    let result = {
        let client = ensure_client(state).await?;
        op(client).await
    };
    match result {
        Ok(value) => Ok(value),
        Err(Error::Message(msg)) if msg.contains("connection closed") => {
            state.terminals.clear();
            state.client = None;
            Err(msg)
        }
        Err(err) => Err(err.to_string()),
    }
}

async fn retry<T, F>(state: &mut Mcp, mut op: F) -> std::result::Result<T, String>
where
    F: for<'a> FnMut(
        &'a Client,
    ) -> Pin<Box<dyn Future<Output = agentlink_core::Result<T>> + Send + 'a>>,
{
    let mut last = "connection closed".to_string();
    for _ in 0..2 {
        let result = {
            let client = ensure_client(state).await?;
            op(client).await
        };
        match result {
            Ok(value) => return Ok(value),
            Err(Error::Message(msg)) if msg.contains("connection closed") => {
                state.terminals.clear();
                state.client = None;
                last = msg;
            }
            Err(err) => return Err(err.to_string()),
        }
    }
    Err(last)
}

fn friendly_settings_error(err: impl std::fmt::Display) -> String {
    let msg = err.to_string();
    if msg.contains("admin token missing") {
        "Not signed in. Run 'agentlink login --relay <url> --user <user>' (or pass --identity)"
            .to_string()
    } else {
        msg
    }
}

async fn ensure_client(state: &mut Mcp) -> std::result::Result<&Client, String> {
    let alive = state.client.as_ref().map(Client::is_alive).unwrap_or(false);
    if !alive {
        state.terminals.clear();
        let mut settings = if let Some(preset) = state.config.preset_settings.clone() {
            preset
        } else {
            agentlink_core::config::load_settings_for_identity(
                &state.config.config_dir,
                state.config.relay.clone(),
                state.config.token.clone(),
                state.config.fingerprint.clone(),
                state.config.trust.clone(),
                state.config.explicit_identity,
            )
            .map_err(friendly_settings_error)?
        };
        let identity =
            Identity::load_or_create(&state.config.identity_path).map_err(|e| e.to_string())?;
        let tokenless_identity = state.config.explicit_identity
            && state.config.token.is_none()
            && settings.token.is_empty();
        if !tokenless_identity {
            let saved_session_expired = agentlink_core::config::load_file(&state.config.config_dir)
                .ok()
                .is_some_and(|f| {
                    f.refresh_token
                        .as_deref()
                        .is_some_and(|t| !t.trim().is_empty())
                        && f.access_expires_unix
                            .is_some_and(|exp| exp <= agentlink_core::util::unix_now())
                });
            match agentlink_core::client::maintain_session(&state.config.config_dir, &identity)
                .await
            {
                Ok(Some(fresh)) => {
                    settings.token = fresh.token;
                    if !fresh.relay.is_empty() {
                        settings.relay = fresh.relay;
                    }
                    if !fresh.fingerprint.is_empty() {
                        settings.fingerprint = fresh.fingerprint;
                    }
                }
                Ok(None) => {}
                Err(err) if saved_session_expired => {
                    return Err(format!("session refresh failed: {err}"));
                }
                Err(_) => {}
            }
        }
        let use_token = !settings.token.is_empty();
        let client = Client::connect_identity(&settings, identity, use_token)
            .await
            .map_err(|e| e.to_string())?;
        client.remember_node_pins(&state.config.config_dir);
        client.remember_grants(&state.config.config_dir);
        if !tokenless_identity {
            client.remember_session(&state.config.config_dir);
        }
        if let Some(warning) = agentlink_core::config::ca_only_warning(
            &settings.fingerprint,
            settings.trust.as_deref(),
        ) {
            eprintln!("{warning}");
        }
        state.resolved_settings = Some(settings);
        state.client = Some(client);
    }
    state
        .client
        .as_ref()
        .ok_or_else(|| "connection closed".to_string())
}

async fn terminal_open(state: &mut Mcp, args: &Value) -> std::result::Result<String, String> {
    let node = required_node(state, args, "node")?;
    let command = args
        .get("command")
        .and_then(Value::as_str)
        .map(str::to_string);
    let cwd = args.get("cwd").and_then(Value::as_str).map(str::to_string);
    let rows = args
        .get("rows")
        .and_then(Value::as_u64)
        .unwrap_or(24)
        .clamp(1, 512) as u16;
    let cols = args
        .get("cols")
        .and_then(Value::as_u64)
        .unwrap_or(80)
        .clamp(1, 512) as u16;
    let session = run_once(state, move |client| {
        let node = node.clone();
        let command = command.clone();
        let cwd = cwd.clone();
        Box::pin(async move { client.open_pty(&node, command, cwd, rows, cols).await })
    })
    .await?;
    let id = session.session_id.clone();
    state.terminals.insert(id.clone(), session);
    Ok(pretty(
        &json!({"session_id": id, "rows": rows, "cols": cols}),
    ))
}

async fn terminal_write(state: &mut Mcp, args: &Value) -> std::result::Result<String, String> {
    let id = required_str(args, "session_id")?;
    let data = if let Some(text) = args.get("data").and_then(Value::as_str) {
        text.as_bytes().to_vec()
    } else if let Some(b64) = args.get("data_base64").and_then(Value::as_str) {
        STANDARD
            .decode(b64.trim())
            .map_err(|err| format!("data_base64: {err}"))?
    } else {
        return Err("terminal_write needs `data` or `data_base64`".into());
    };
    let n = data.len();
    let session = state
        .terminals
        .get(&id)
        .ok_or_else(|| format!("unknown terminal {id}"))?;
    session.write(&data).await.map_err(|err| err.to_string())?;
    Ok(pretty(&json!({"session_id": id, "bytes": n})))
}

async fn terminal_read(state: &mut Mcp, args: &Value) -> std::result::Result<String, String> {
    let id = required_str(args, "session_id")?;
    let wait_ms = {
        let value = number(args, "wait_ms");
        if value == 0 {
            1000
        } else {
            value.min(30_000)
        }
    };
    let max_bytes = {
        let value = number(args, "max_bytes");
        if value == 0 {
            65_536
        } else {
            value.min(1024 * 1024)
        }
    } as usize;
    let session = state
        .terminals
        .get_mut(&id)
        .ok_or_else(|| format!("unknown terminal {id}"))?;
    let read = session
        .read_available(Duration::from_millis(wait_ms), max_bytes)
        .await
        .map_err(|err| err.to_string())?;
    let text = String::from_utf8_lossy(&read.data).to_string();
    Ok(pretty(&json!({
        "session_id": id,
        "data": text,
        "bytes": read.data.len(),
        "exit_code": read.exit_code,
        "error": read.error,
    })))
}

async fn terminal_resize(state: &mut Mcp, args: &Value) -> std::result::Result<String, String> {
    let id = required_str(args, "session_id")?;
    let rows = number(args, "rows").clamp(1, 512) as u16;
    let cols = number(args, "cols").clamp(1, 512) as u16;
    let session = state
        .terminals
        .get(&id)
        .ok_or_else(|| format!("unknown terminal {id}"))?;
    session
        .resize(rows, cols)
        .await
        .map_err(|err| err.to_string())?;
    Ok(pretty(
        &json!({"session_id": id, "rows": rows, "cols": cols}),
    ))
}

async fn terminal_close(state: &mut Mcp, args: &Value) -> std::result::Result<String, String> {
    let id = required_str(args, "session_id")?;
    state
        .terminals
        .remove(&id)
        .ok_or_else(|| format!("unknown terminal {id}"))?;
    Ok(pretty(&json!({"session_id": id, "closed": true})))
}


fn parse_stdin_arg(args: &Value) -> std::result::Result<Option<Vec<u8>>, String> {
    const MAX_STDIN: usize = 16 * 1024 * 1024;
    let Some(v) = args.get("stdin") else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    let text = v
        .as_str()
        .ok_or_else(|| "stdin must be a string".to_string())?;
    let bytes = text.as_bytes().to_vec();
    if bytes.len() > MAX_STDIN {
        return Err(format!(
            "stdin is {} bytes; max is {MAX_STDIN}",
            bytes.len()
        ));
    }
    Ok(Some(bytes))
}

fn parse_env_arg(args: &Value) -> std::result::Result<Vec<(String, String)>, String> {
    let Some(env) = args.get("env") else {
        return Ok(Vec::new());
    };
    let obj = env
        .as_object()
        .ok_or_else(|| "env must be an object of string values".to_string())?;
    let mut out = Vec::with_capacity(obj.len());
    for (key, value) in obj {
        let value = value
            .as_str()
            .ok_or_else(|| format!("env.{key} must be a string"))?;
        if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
            return Err(format!("rejected env var '{key}'"));
        }
        out.push((key.clone(), value.to_string()));
    }
    Ok(out)
}

fn command_argv(args: &Value) -> std::result::Result<(String, Vec<String>, bool), String> {
    if let Some(argv) = args.get("argv").and_then(Value::as_array) {
        if argv.is_empty() {
            return Err("argv is empty".into());
        }
        let program = argv[0]
            .as_str()
            .ok_or("argv values must be strings")?
            .to_string();
        let rest = argv
            .iter()
            .skip(1)
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or("argv values must be strings".to_string())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        return Ok((program, rest, false));
    }
    let command = required_str(args, "command")?;
    Ok((command, Vec::new(), true))
}

fn string_list(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn number(args: &Value, key: &str) -> u64 {
    args.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn required_str(args: &Value, key: &str) -> std::result::Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing `{key}`"))
}

fn decode_content(args: &Value) -> std::result::Result<Vec<u8>, String> {
    if let Some(text) = args.get("content").and_then(Value::as_str) {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(b64) = args.get("content_base64").and_then(Value::as_str) {
        return STANDARD
            .decode(b64.trim())
            .map_err(|e| format!("content_base64: {e}"));
    }
    Err("write_file needs `content` or `content_base64`".into())
}

fn encode_bytes(path: &str, offset: u64, data: &[u8], truncated: bool, size: u64) -> String {
    let body = if let Ok(text) = std::str::from_utf8(data) {
        json!({
            "path": path,
            "offset": offset,
            "encoding": "utf-8",
            "content": text,
            "bytes": data.len(),
            "size": size,
            "truncated": truncated,
            "next_offset": offset + data.len() as u64,
        })
    } else {
        json!({
            "path": path,
            "offset": offset,
            "encoding": "base64",
            "content_base64": STANDARD.encode(data),
            "bytes": data.len(),
            "size": size,
            "truncated": truncated,
            "next_offset": offset + data.len() as u64,
        })
    };
    pretty(&body)
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn tool_ok(text: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": false,
    })
}

fn tool_err(text: &str) -> Value {
    let text = crate::decorate_sandbox_path_escape(&crate::decorate_exec_cwd_missing(
        &crate::decorate_bg_process_not_found(&crate::decorate_bg_process_limit(
            &crate::decorate_edit_lines_outside(
            &crate::decorate_edit_lines_end_before_start(&crate::decorate_edit_lines_zero_based(
                &crate::decorate_approval_unresolved(
                &crate::decorate_atspi_bus_failure(&crate::decorate_screenshot_monitor_missing(
                    &crate::decorate_screenshot_window_not_found(&crate::decorate_no_click_action(
                        &crate::decorate_pty_session_not_found(&crate::decorate_watch_target_missing(&crate::decorate_watch_inotify_limit(&crate::decorate_watch_limit(
                            &crate::decorate_watch_not_found(
                                &crate::decorate_patch_missing_headers(
                                    &crate::decorate_patch_parse(&crate::decorate_patch_too_large(
                                        &crate::decorate_replacement_text_too_large(
                                            &crate::decorate_write_target_is_directory(
                                                &crate::decorate_edit_text_not_utf8(
                                                    &crate::decorate_edit_file_too_large(
                                                        &crate::decorate_exec_enoexec(
                                                            &crate::decorate_exec_program_path_miss(
                                                                text,
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    )),
                                ),
                            ),
                        )))),
                    )),
                ),
            ))),
        )),
    ))));
    let text = crate::decorate_node_not_found(&text);
    let text = crate::decorate_ambiguous_node(&text);
    let text = crate::decorate_node_offline(&text);
    let text = crate::decorate_connection_closed(&text);
    let text = crate::decorate_relay_url_tls(&text);
    let text = crate::decorate_unsupported_relay_scheme(&text);
    let text = crate::decorate_relay_port_zero(&text);
    let text = crate::decorate_relay_invalid_port(&text);
    let text = crate::decorate_relay_empty_host(&text);
    let text = crate::decorate_relay_missing_host(&text);
    let text = crate::decorate_relay_fingerprint(&text);
    let text = crate::decorate_ls_missing(&text);
    let text = crate::decorate_mv_rm_missing(&text);
    let text = crate::decorate_windows_input_capture(&text);
    let text = crate::decorate_ui_element_stale(&text);
    // The write-dest-permission tip quotes the capability-denial form as a
    // "not this" example; don't append a grant tip to it a second time.
    let text = if text.contains(crate::WRITE_DEST_PERMISSION_TIP_MARKER) {
        text
    } else {
        crate::decorate_grant_capability(&text)
    };
    let text = crate::decorate_session_auth(&text);
    let text = crate::decorate_patch_root_not_dir(&text);
    let text = crate::decorate_patch_hunk_mismatch(&text);
    let text = crate::decorate_patch_path(&text);
    let text = crate::decorate_symlink_dir_read(&text);
    let text = crate::decorate_read_target_is_directory(&text);
    let text = crate::decorate_copy_special_file(&text);
    let text = crate::decorate_mv_cross_device(&text);
    let text = crate::decorate_search_regex(&text);
    let text = crate::decorate_search_glob(&text);
    let text = crate::decorate_env_var_rejected(&text);
    let text = crate::decorate_env_value_not_string(&text);
    let text = crate::decorate_stdin_not_string(&text);
    let text = crate::decorate_stdin_too_large(&text);
    let text = crate::decorate_copy_direction(&text);
    let text = crate::decorate_compress_value(&text);
    let text = crate::decorate_scroll_coord_pair(&text);
    let text = crate::decorate_mkdir_target_not_dir(&text);
    let text = crate::decorate_path_component_not_dir(&text);
    let text = crate::decorate_ambiguous_replace(&text);
    let text = crate::decorate_replace_empty_old(&text);
    let text = crate::decorate_edit_mismatch(&text);
    let text = crate::decorate_edit_atomic_write(&text);
    let text = crate::decorate_exec_cwd_permission(&text);
    let text = crate::decorate_exec_path_miss(&text);
    let text = crate::decorate_argv_empty(&text);
    let text = crate::decorate_argv_not_strings(&text);
    let text = crate::decorate_missing_command(&text);
    let text = crate::decorate_missing_arg(&text);
    let text = crate::decorate_write_file_needs_content(&text);
    let text = crate::decorate_content_base64(&text);
    let text = crate::decorate_terminal_write_needs_data(&text);
    let text = crate::decorate_data_base64(&text);
    let text = crate::decorate_finite_number(&text);
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": true,
    })
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tool_specs() -> Vec<Value> {
    vec![
        tool(
            "get_status",
            "Inspect local controller identity, relay/session status, aliases, and stored grant states without connecting to the relay.",
            json!({"type": "object", "properties": {}}),
        ),
        tool(
            "list_machines",
            "List paired machines, whether each is online, and each node's local grant_status (active/expired/missing/wrong_grantee) and grant_expires_in_secs.",
            json!({"type": "object", "properties": {}}),
        ),
        tool(
            "list_dir",
            "List a directory on a node.",
            obj_schema(
                &[
                    ("node", "Node name or id"),
                    ("path", "Directory path. Defaults to the node process working directory."),
                ],
                &["node"],
            ),
        ),
        tool(
            "stat_path",
            "Stat a file or directory on a node.",
            obj_schema(
                &[("node", "Node name or id"), ("path", "Path on the node")],
                &["node", "path"],
            ),
        ),
        tool(
            "read_file",
            "Read a byte range or 1-based inclusive line range. Text is returned as UTF-8 when possible, otherwise base64. Defaults to 64 KiB (up to 1 MiB).",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "path": {"type": "string"},
                    "offset": {"type": "integer"},
                    "max_bytes": {"type": "integer", "description": "Defaults to 64 KiB (max 1 MiB)"},
                    "start_line": {"type": "integer", "minimum": 1, "description": "Optional 1-based inclusive start line (UTF-8 text files)"},
                    "end_line": {"type": "integer", "minimum": 1, "description": "Optional 1-based inclusive end line (UTF-8 text files)"}
                },
                "required": ["node", "path"]
            }),
        ),
        tool(
            "write_file",
            "Create or replace a file at `path` (must not be an existing directory). Bytes are sent on the fast path. Pass content or content_base64.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "content_base64": {"type": "string"}
                },
                "required": ["node", "path"]
            }),
        ),
        tool(
            "mkdir",
            "Create a directory on a node.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "path": {"type": "string"},
                    "parents": {"type": "boolean"}
                },
                "required": ["node", "path"]
            }),
        ),
        tool(
            "remove_path",
            "Remove a file or directory on a node.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "path": {"type": "string"},
                    "recursive": {"type": "boolean"}
                },
                "required": ["node", "path"]
            }),
        ),
        tool(
            "move_path",
            "Rename or move a path on one node.",
            obj_schema(
                &[
                    ("node", "Node name or id"),
                    ("from", "Source path"),
                    ("to", "Destination path"),
                ],
                &["node", "from", "to"],
            ),
        ),
        tool(
            "copy_path",
            "Copy a file or directory between this machine and a node, or between two nodes. Uses binary frames, resume, BLAKE3 skip, and an optional direct path.",
            json!({
                "type": "object",
                "properties": {
                    "direction": {
                        "type": "string",
                        "enum": ["upload", "download", "peer"],
                        "description": "upload (local to node), download (node to local), or peer (node to node)"
                    },
                    "node": {"type": "string", "description": "Node name or id. For peer, the source node."},
                    "path": {"type": "string", "description": "Remote path. For peer, the source path."},
                    "local": {"type": "string", "description": "Local path for upload or download."},
                    "dst_node": {"type": "string", "description": "Destination node for peer copies."},
                    "dst_path": {"type": "string", "description": "Destination path for peer copies."},
                    "chunk_size": {"type": "integer", "description": "Chunk size in bytes. Default 1 MiB."},
                    "compress": {
                        "type": "string",
                        "enum": ["auto", "on", "off"],
                        "description": "auto, on, or off"
                    },
                    "direct": {"type": "boolean", "description": "Try a direct QUIC path. Default true."}
                },
                "required": ["direction", "node", "path"]
            }),
        ),
        tool(
            "screenshot",
            "Capture the node screen. Returns an image plus a short summary. Requires the desktop permission preset.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "target": {
                        "type": "string",
                        "enum": ["screen", "monitor", "region", "window", "monitors"],
                        "description": "screen, monitor, region, window, or monitors"
                    },
                    "monitor": {"type": "integer"},
                    "window_id": {"type": "string"},
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                    "width": {"type": "integer"},
                    "height": {"type": "integer"},
                    "format": {
                        "type": "string",
                        "enum": ["jpeg", "png", "webp"],
                        "description": "jpeg, png, or webp. Default jpeg."
                    },
                    "quality": {"type": "integer"},
                    "scale": {"type": "number", "description": "0.05 to 1"}
                },
                "required": ["node"]
            }),
        ),
        tool(
            "click",
            "Move, click, or drag the pointer. Coordinates are pixels, or 0–1 fractions of the primary monitor. Set move_only to move without clicking. Set to_x and to_y to drag.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "x": {"type": "number"},
                    "y": {"type": "number"},
                    "button": {
                        "type": "string",
                        "enum": ["left", "right", "middle"],
                        "description": "Mouse button (default left)"
                    },
                    "count": {"type": "integer"},
                    "to_x": {"type": "number"},
                    "to_y": {"type": "number"},
                    "move_only": {"type": "boolean"}
                },
                "required": ["node", "x", "y"]
            }),
        ),
        tool(
            "type",
            "Type Unicode text on the node.",
            obj_schema(&[("node", "Node name or id"), ("text", "Text to type")], &["node", "text"]),
        ),
        tool(
            "key",
            "Press a key combo such as ctrl+c.",
            obj_schema(&[("node", "Node name or id"), ("keys", "Combo, for example ctrl+shift+a")], &["node", "keys"]),
        ),
        tool(
            "scroll",
            "Scroll at the current pointer, or at x/y when both are set. Positive dy moves up. x/y are pixels or 0–1 fractions.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "x": {"type": "number"},
                    "y": {"type": "number"},
                    "dx": {"type": "integer"},
                    "dy": {"type": "integer"}
                },
                "required": ["node"]
            }),
        ),
        tool(
            "get_ui_tree",
            "Return a compact accessibility tree: role, name, bounds, and id.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "max_depth": {"type": "integer"},
                    "max_nodes": {"type": "integer"}
                },
                "required": ["node"]
            }),
        ),
        tool(
            "act_on_element",
            "Click, focus, or set the value of an element id from get_ui_tree.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "id": {"type": "string"},
                    "op": {
                        "type": "string",
                        "enum": ["click", "focus", "set_value"],
                        "description": "click, focus, or set_value"
                    },
                    "value": {"type": "string"}
                },
                "required": ["node", "id"]
            }),
        ),
        tool(
            "run_command",
            "Run a command on a node. `command` uses the platform shell. `argv` runs a program directly. Output is capped at 1 MiB. Prefer `env` over shell set/export — Windows cmd expands %VAR% at parse time. Optional `stdin` string is written to the process then closed (max 16 MiB).",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "command": {"type": "string"},
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "cwd": {"type": "string"},
                    "env": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Environment variables as KEY→VALUE object"
                    },
                    "stdin": {
                        "type": "string",
                        "description": "Bytes written to the remote process stdin, then EOF (max 16 MiB)"
                    },
                    "timeout_ms": {"type": "integer"}
                },
                "required": ["node"]
            }),
        ),
        tool(
            "search_content",
            "Search file contents. Respects .gitignore. `literal` turns off regex. Results are paginated with offset and limit.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "path": {"type": "string"},
                    "pattern": {"type": "string"},
                    "literal": {"type": "boolean"},
                    "include": {"type": "array", "items": {"type": "string"}},
                    "exclude": {"type": "array", "items": {"type": "string"}},
                    "gitignore": {"type": "boolean"},
                    "include_hidden": {"type": "boolean"},
                    "case_insensitive": {"type": "boolean"},
                    "before": {"type": "integer"},
                    "after": {"type": "integer"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"}
                },
                "required": ["node", "pattern"]
            }),
        ),
        tool(
            "search_files",
            "Search file names. `pattern` is a glob unless `regex` is true.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "path": {"type": "string"},
                    "pattern": {"type": "string"},
                    "regex": {"type": "boolean"},
                    "gitignore": {"type": "boolean"},
                    "include_hidden": {"type": "boolean"},
                    "case_insensitive": {"type": "boolean"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"}
                },
                "required": ["node", "pattern"]
            }),
        ),
        tool(
            "replace_text",
            "Replace an exact string in an existing file (does not create it). Fails unless the \
             match is unique or replace_all is true.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name or id"},
                    "path": {"type": "string", "description": "File path"},
                    "old": {"type": "string", "description": "Exact text to replace"},
                    "new": {"type": "string", "description": "Replacement text"},
                    "replace_all": {"type": "boolean", "description": "Replace every occurrence instead of requiring a unique match"}
                },
                "required": ["node", "path", "old"]
            }),
        ),
        tool(
            "edit_lines",
            "Replace a 1-based inclusive line range. An empty content deletes the range.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "path": {"type": "string"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                    "content": {"type": "string"}
                },
                "required": ["node", "path", "start_line", "end_line"]
            }),
        ),
        tool(
            "apply_patch",
            "Apply a unified diff relative to root. Paths must stay inside the node sandbox.",
            obj_schema(
                &[
                    ("node", "Node name or id"),
                    ("root", "Directory the patch paths are relative to"),
                    ("patch", "Unified diff text"),
                ],
                &["node", "patch"],
            ),
        ),
        tool(
            "watch_start",
            "Subscribe to filesystem changes. Poll with watch_poll and stop with watch_stop.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "path": {"type": "string"},
                    "recursive": {"type": "boolean"}
                },
                "required": ["node", "path"]
            }),
        ),
        tool(
            "watch_poll",
            "Wait up to timeout_ms for watch events after cursor.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "watch_id": {"type": "string"},
                    "cursor": {"type": "integer"},
                    "timeout_ms": {"type": "integer"},
                    "limit": {"type": "integer"}
                },
                "required": ["node", "watch_id"]
            }),
        ),
        tool(
            "watch_stop",
            "Stop a filesystem watch.",
            obj_schema(
                &[("node", "Node name or id"), ("watch_id", "Watch id from watch_start")],
                &["node", "watch_id"],
            ),
        ),
        tool(
            "process_start",
            "Start a detached command. `command` uses the shell. `argv` runs a program directly. Prefer `env` over shell set/export. Optional `stdin` string is written then closed (max 16 MiB).",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "command": {"type": "string"},
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "cwd": {"type": "string"},
                    "env": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Environment variables as KEY→VALUE object"
                    },
                    "stdin": {
                        "type": "string",
                        "description": "Bytes written to the process stdin, then EOF (max 16 MiB)"
                    }
                },
                "required": ["node"]
            }),
        ),
        tool(
            "process_list",
            "List background processes on a node.",
            obj_schema(&[("node", "Node name or id")], &["node"]),
        ),
        tool(
            "process_output",
            "Read incremental stdout and stderr from a background process.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "id": {"type": "string"},
                    "stdout_cursor": {"type": "integer"},
                    "stderr_cursor": {"type": "integer"},
                    "max_bytes": {"type": "integer"}
                },
                "required": ["node", "id"]
            }),
        ),
        tool(
            "process_status",
            "Status of one background process.",
            obj_schema(
                &[("node", "Node name or id"), ("id", "Process id")],
                &["node", "id"],
            ),
        ),
        tool(
            "process_kill",
            "Kill a background process and its process group.",
            obj_schema(
                &[("node", "Node name or id"), ("id", "Process id")],
                &["node", "id"],
            ),
        ),
        tool(
            "system_info",
            "OS, CPU, memory, disks, user, shell, filtered environment, and detected tools.",
            obj_schema(&[("node", "Node name or id")], &["node"]),
        ),
        tool(
            "terminal_open",
            "Open a PTY. Read and write it with terminal_read and terminal_write. This is poll-based because MCP uses stdio.",
            json!({
                "type": "object",
                "properties": {
                    "node": {"type": "string"},
                    "command": {"type": "string"},
                    "cwd": {"type": "string"},
                    "rows": {"type": "integer"},
                    "cols": {"type": "integer"}
                },
                "required": ["node"]
            }),
        ),
        tool(
            "terminal_write",
            "Write UTF-8 `data` or base64 `data_base64` to a PTY.",
            json!({
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "data": {"type": "string"},
                    "data_base64": {"type": "string"}
                },
                "required": ["session_id"]
            }),
        ),
        tool(
            "terminal_read",
            "Read available PTY output, waiting up to wait_ms.",
            json!({
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "wait_ms": {"type": "integer"},
                    "max_bytes": {"type": "integer"}
                },
                "required": ["session_id"]
            }),
        ),
        tool(
            "terminal_resize",
            "Resize a PTY.",
            json!({
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "rows": {"type": "integer"},
                    "cols": {"type": "integer"}
                },
                "required": ["session_id", "rows", "cols"]
            }),
        ),
        tool(
            "terminal_close",
            "Close a PTY session.",
            obj_schema(&[("session_id", "Session id from terminal_open")], &["session_id"]),
        ),
    ]
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({"name": name, "description": description, "inputSchema": schema})
}

fn obj_schema(props: &[(&str, &str)], required: &[&str]) -> Value {
    let mut properties = serde_json::Map::new();
    for (key, desc) in props {
        properties.insert(
            (*key).to_string(),
            json!({"type": "string", "description": desc}),
        );
    }
    json!({"type": "object", "properties": properties, "required": required})
}

pub const MAX_MCP_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MCP_HEADER_LINES: usize = 64;
const MAX_MCP_HEADER_LINE_BYTES: usize = 8 * 1024;

async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    cap: usize,
) -> Result<Option<String>> {
    use tokio::io::AsyncReadExt;
    let mut raw = Vec::new();
    let mut limited = reader.take((cap + 1) as u64);
    let n = limited.read_until(b'\n', &mut raw).await?;
    if n == 0 {
        return Ok(None);
    }
    if raw.len() > cap && !raw.ends_with(b"\n") {
        anyhow::bail!("MCP line exceeds {cap} byte limit");
    }
    Ok(Some(String::from_utf8(raw).map_err(|e| anyhow::anyhow!(e))?))
}

pub async fn read_message<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Value>> {
    loop {
        let Some(line) = read_bounded_line(reader, MAX_MCP_MESSAGE_BYTES).await? else {
            return Ok(None);
        };
        let trimmed = line.trim_start_matches('\u{feff}').trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            let len: usize = rest
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid Content-Length"))?;
            if len > MAX_MCP_MESSAGE_BYTES {
                anyhow::bail!(
                    "MCP Content-Length {len} exceeds {MAX_MCP_MESSAGE_BYTES} byte limit"
                );
            }
            let mut header_count = 0usize;
            loop {
                let Some(header) = read_bounded_line(reader, MAX_MCP_HEADER_LINE_BYTES).await?
                else {
                    return Ok(None);
                };
                if header.trim().is_empty() {
                    break;
                }
                header_count += 1;
                if header_count > MAX_MCP_HEADER_LINES {
                    anyhow::bail!("too many MCP header lines");
                }
            }
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            let text = String::from_utf8(buf).map_err(|e| anyhow::anyhow!(e))?;
            let text = text.trim_start_matches('\u{feff}');
            return Ok(Some(serde_json::from_str(text)?));
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(value) => return Ok(Some(value)),
            Err(_) => {
                write_message(&rpc_error(Value::Null, -32700, "parse error"))?;
            }
        }
    }
}

fn write_message(value: &Value) -> Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[test]
    fn click_payload_accepts_pixels_and_fractions() {
        let payload = click_payload(&json!({"x": 100, "y": 200})).unwrap();
        assert_eq!(
            payload,
            json!({"action": "click", "x": 100, "y": 200, "button": "left", "count": 1})
        );
        let payload = click_payload(&json!({"x": 0.5, "y": 0.25})).unwrap();
        assert_eq!(payload["x"], 0.5);
        assert_eq!(payload["y"], 0.25);
        let payload =
            click_payload(&json!({"x": 0.1, "y": 0.2, "to_x": 0.8, "to_y": 0.9})).unwrap();
        assert_eq!(payload["action"], "drag");
        assert_eq!(payload["to_x"], 0.8);
        assert_eq!(payload["to_y"], 0.9);
        assert!(click_payload(&json!({"x": "nope", "y": 1})).is_err());
    }

    #[test]
    fn tool_err_tips_missing_screenshot_monitor() {
        let value = tool_err("no monitor 3");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::SCREENSHOT_MONITOR_TIP_MARKER),
            "{text}"
        );
        assert!(text.contains("--target monitors"), "{text}");
    }

    #[test]
    fn tool_err_tips_windows_input_capture() {
        for raw in [
            "SendInput mouse failed",
            "SendInput mouse failed (5)",
            "SendInput key failed (5)",
            "SendInput unicode failed (5)",
            "GDI capture failed (6)",
            "click laptop 10 20: SendInput mouse failed (5)",
            "screenshot probe: GDI capture failed (6)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(raw), "{text}");
            assert_eq!(
                text.matches(crate::WINDOWS_INPUT_CAPTURE_TIP_MARKER)
                    .count(),
                1,
                "{text}"
            );
            assert!(
                text.contains("`click`/`type`/`key`/`scroll`/`screenshot`"),
                "{text}"
            );
            assert!(text.contains("`agentlink screenshot`"), "{text}");
        }
    }

    #[test]
    fn tool_err_windows_input_capture_does_not_shadow_siblings() {
        let stale = tool_err("element 'ax|7' is not in the last tree. Call get_ui_tree again.");
        let stale_text = stale["content"][0]["text"].as_str().unwrap();
        assert!(
            stale_text.contains(crate::UI_ELEMENT_STALE_TIP_MARKER),
            "{stale_text}"
        );
        assert!(
            !stale_text.contains(crate::WINDOWS_INPUT_CAPTURE_TIP_MARKER),
            "{stale_text}"
        );

        let atspi = tool_err("ui-tree laptop: AT-SPI desktop tree is empty");
        let atspi_text = atspi["content"][0]["text"].as_str().unwrap();
        assert!(
            atspi_text.contains(crate::ATSPI_BUS_TIP_MARKER),
            "{atspi_text}"
        );
        assert!(
            !atspi_text.contains(crate::WINDOWS_INPUT_CAPTURE_TIP_MARKER),
            "{atspi_text}"
        );

        let window = tool_err("no X11 window matches 'Terminal'");
        let window_text = window["content"][0]["text"].as_str().unwrap();
        assert!(
            window_text.contains(crate::SCREENSHOT_WINDOW_TIP_MARKER),
            "{window_text}"
        );
        assert!(
            !window_text.contains(crate::WINDOWS_INPUT_CAPTURE_TIP_MARKER),
            "{window_text}"
        );

        let monitor = tool_err("no monitor 3");
        let monitor_text = monitor["content"][0]["text"].as_str().unwrap();
        assert!(
            monitor_text.contains(crate::SCREENSHOT_MONITOR_TIP_MARKER),
            "{monitor_text}"
        );
        assert!(
            !monitor_text.contains(crate::WINDOWS_INPUT_CAPTURE_TIP_MARKER),
            "{monitor_text}"
        );

        for raw in [
            "stat_path probe /tmp/x: No such file or directory (os error 2)",
            "missing `/tmp/x`",
            "Permission denied (os error 13)",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{text}");
            assert!(
                !text.contains(crate::WINDOWS_INPUT_CAPTURE_TIP_MARKER),
                "{text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_search_glob() {
        let raw = "include glob '[a': error parsing glob '[a': unclosed character class";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(raw), "{text}");
        assert_eq!(
            text.matches(crate::SEARCH_GLOB_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert_eq!(text.matches(". tip:").count(), 1, "{text}");
    }

    #[test]
    fn tool_err_tips_search_regex() {
        let raw = "pattern: regex parse error:\n    (?:()\n    ^\nerror: unclosed group";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(raw), "{text}");
        assert_eq!(
            text.matches(crate::SEARCH_REGEX_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("'(' is treated as a regex"), "{text}");
        assert!(text.contains("--literal"), "{text}");
        assert_eq!(text.matches(". tip:").count(), 1, "{text}");
        assert_eq!(crate::decorate_search_regex(text), text);
    }

    #[test]
    fn tool_err_tips_search_regex_variants_once() {
        // `search_files` with `regex:true` uses the bare pattern (no `(?:...)`).
        let bare = "pattern: regex parse error:\n    (\n    ^\nerror: unclosed group";
        let text = tool_err(bare)["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            text.matches(crate::SEARCH_REGEX_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("'(' is treated as a regex"), "{text}");

        // Repetition and character-class diagnostics tip once each.
        for raw in [
            "pattern: regex parse error:\n    (?:*)\n       ^\nerror: repetition operator missing expression",
            "pattern: regex parse error:\n    [abc\n    ^\nerror: unclosed character class",
        ] {
            let text = tool_err(raw)["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(
                text.matches(crate::SEARCH_REGEX_TIP_MARKER).count(),
                1,
                "{raw} -> {text}"
            );
        }

        // Multi-line patterns fall back to the generic placeholder.
        let multi = "pattern: regex parse error:\n~~~\n1: (\n2: [\n~~~\nerror: unclosed group";
        let text = tool_err(multi)["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(text.contains("'<pattern>' is treated as a regex"), "{text}");

        // Wrapped content-search shape extracts the caller's pattern.
        let wrapped = "search /tmp: pattern: regex parse error:\n    (?:[abc)\n       ^\nerror: unclosed character class";
        let text = tool_err(wrapped)["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            text.matches(crate::SEARCH_REGEX_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("'[abc'"), "{text}");
    }

    #[test]
    fn tool_err_search_regex_does_not_shadow_siblings() {
        // The glob raw gets only the glob tip, never the regex one.
        let glob = "include glob '[a': error parsing glob '[a': unclosed character class";
        let text = tool_err(glob)["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(text.contains(crate::SEARCH_GLOB_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::SEARCH_REGEX_TIP_MARKER), "{text}");

        // Permission raws stay byte-identical through the flat chain.
        for raw in [
            "search /etc/shadow: Permission denied (os error 13)",
            "search C:\\ProgramData\\secrets\\app.txt: Access is denied. (os error 5)",
            "find /x: Permission denied (os error 13)",
        ] {
            let text = tool_err(raw)["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(text, raw, "{raw}");
        }

        // Non-regex search errors and already-remedied lines are untouched.
        for raw in [
            "pattern is empty",
            "pattern contains NUL",
            "pattern is longer than 4096 bytes",
            "pattern: compiled regex exceeds size limit of 1048576",
            "pattern: regex parse error:\n    (\n    ^\nerror: unclosed group — try --literal",
        ] {
            assert_eq!(crate::decorate_search_regex(raw), raw, "{raw}");
            let text = tool_err(raw)["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(text, raw, "{raw}");
        }

        // A PATH miss still gets its own exec tip and not the regex one.
        let raw = "program 'cd' not found on PATH (No such file or directory (os error 2))";
        assert_eq!(crate::decorate_search_regex(raw), raw, "{raw}");
        let text = tool_err(raw)["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!text.contains(crate::SEARCH_REGEX_TIP_MARKER), "{text}");
    }

    #[test]
    fn tool_err_tips_edit_lines_outside() {
        let value = tool_err(
            "line range 9-10 is outside /tmp/x (file has 3 lines; append with start=end=4)",
        );
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::EDIT_LINES_OUTSIDE_TIP_MARKER),
            "{text}"
        );
        assert!(text.contains("`agentlink cat <node> <path>`"), "{text}");
        assert!(text.contains("`start=end=<n+1>`"), "{text}");
    }

    #[test]
    fn tool_err_tips_edit_lines_end_before_start() {
        let value = tool_err("end line 2 is before start line 5");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::EDIT_LINES_END_BEFORE_START_TIP_MARKER),
            "{text}"
        );
        assert!(text.contains("`<start> <end>`"), "{text}");
        assert!(text.contains("`agentlink cat <node> <path>`"), "{text}");
        assert!(text.contains("`read_file`"), "{text}");
        assert!(text.contains("`agentlink replace <node> <path> <old> <new>`"), "{text}");
    }

    #[test]
    fn tool_err_tips_edit_lines_zero_based() {
        let raw = "line numbers are 1-based";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{text}");
        assert_eq!(
            text.matches(crate::EDIT_LINES_ZERO_BASED_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
        assert!(text.contains("1-based and inclusive"), "{text}");
        assert!(
            text.contains("`agentlink edit-lines <node> <path> <start> <end> <text>`"),
            "{text}"
        );
        assert_eq!(text.matches(". tip:").count(), 1, "{text}");
        assert_eq!(crate::decorate_edit_lines_zero_based(text), text);

        // The wrapped form prints the same tip exactly once.
        let wrapped = "edit-lines /tmp/x 0 2 hello: line numbers are 1-based";
        let value = tool_err(wrapped);
        let text = err_text(&value);
        assert!(text.starts_with(wrapped), "{text}");
        assert_eq!(
            text.matches(crate::EDIT_LINES_ZERO_BASED_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_edit_lines_zero_based_does_not_shadow_siblings() {
        for raw in [
            "end line 2 is before start line 5",
            "line range 9-10 is outside /tmp/x (file has 3 lines; append with start=end=4)",
            "node offline: probe",
            "io: No such file or directory (os error 2)",
            "old string was not found in /tmp/x",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::EDIT_LINES_ZERO_BASED_TIP_MARKER),
                "{raw} => {text}"
            );
        }
        // The sibling edit-lines tips still fire on their own errors.
        let value = tool_err("end line 2 is before start line 5");
        let text = err_text(&value);
        assert!(
            text.contains(crate::EDIT_LINES_END_BEFORE_START_TIP_MARKER),
            "{text}"
        );
        let value = tool_err(
            "line range 9-10 is outside /tmp/x (file has 3 lines; append with start=end=4)",
        );
        let text = err_text(&value);
        assert!(
            text.contains(crate::EDIT_LINES_OUTSIDE_TIP_MARKER),
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_ambiguous_replace() {
        let raw = "found 2 matches of the old string in /srv/app/src/main.rs; pass --all (CLI) or \
                   replace_all (MCP/API) to replace every match";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::AMBIGUOUS_REPLACE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "replace_all",
            "edit_lines",
            "replacements",
            "read_file",
            "agentlink guide <node>",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        let missing = tool_err("old string was not found in /srv/app/src.rs");
        let missing_text = missing["content"][0]["text"].as_str().unwrap();
        assert!(
            !missing_text.contains(crate::AMBIGUOUS_REPLACE_TIP_MARKER),
            "{missing}"
        );
        assert!(
            missing_text.contains(crate::EDIT_MISMATCH_TIP_MARKER),
            "{missing}"
        );
        let bare = tool_err("found 2 matches of the old string in /tmp/x");
        assert_eq!(
            bare["content"][0]["text"].as_str().unwrap(),
            "found 2 matches of the old string in /tmp/x"
        );
    }

    #[test]
    fn tool_err_tips_edit_mismatch() {
        let value = tool_err("replace_text: old string was not found in /srv/app/src/main.rs");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::EDIT_MISMATCH_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "`agentlink cat <node> <path>`",
            "`agentlink search <node> <pattern> <path>`",
            "`agentlink replace --all`",
            "`agentlink edit-lines`",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        assert_eq!(crate::decorate_edit_mismatch(text), text);
    }

    #[test]
    fn tool_err_tips_wrapped_edit_mismatch() {
        let value = tool_err("replace /tmp/x: old string was not found in /tmp/x (no such text)");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::EDIT_MISMATCH_TIP_MARKER).count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_edit_mismatch_does_not_shadow_siblings() {
        for raw in [
            "found 2 matches of the old string in /srv/app/x; pass --all (CLI) or replace_all (MCP/API) to replace every match",
            "old string is empty",
            "replacement text exceeds 1 MiB",
            "io: No such file or directory (os error 2)",
            "/srv/app/reports is a directory",
            "patch /srv/app/src.rs: error applying hunk #1",
            "old string was not found",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::EDIT_MISMATCH_TIP_MARKER),
                "{raw}: {text}"
            );
        }
        let decorated = crate::decorate_replace_missing_file(
            "io: No such file or directory (os error 2)",
            "/srv/app/notes.txt",
        );
        assert_eq!(crate::decorate_edit_mismatch(&decorated), decorated);
    }

    #[test]
    fn tool_err_tips_replace_empty_old() {
        let raw = "old string is empty";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{text}");
        assert_eq!(
            text.matches(crate::REPLACE_EMPTY_OLD_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
        assert!(text.contains("non-empty, unique anchor"), "{text}");
        assert!(
            text.contains("`agentlink write <node> <path> --content <text>`"),
            "{text}"
        );
        assert!(
            text.contains("`agentlink edit-lines <node> <path> <start> <end> <text>`"),
            "{text}"
        );
        assert_eq!(text.matches(". tip:").count(), 1, "{text}");
        assert_eq!(crate::decorate_replace_empty_old(text), text);

        // The wrapped form prints the same tip exactly once.
        let wrapped = "replace /tmp/x: old string is empty";
        let value = tool_err(wrapped);
        let text = err_text(&value);
        assert!(text.starts_with(wrapped), "{text}");
        assert_eq!(
            text.matches(crate::REPLACE_EMPTY_OLD_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
        assert_eq!(crate::decorate_replace_empty_old(text), text);
    }

    #[test]
    fn tool_err_replace_empty_old_does_not_shadow_siblings() {
        for raw in [
            "missing `old`",
            "old string was not found in /tmp/x",
            "found 2 matches of the old string in /tmp/x; pass --all (CLI) or replace_all \
             (MCP/API) to replace every match",
            "node offline: probe",
            "io: No such file or directory (os error 2)",
            "patch /tmp/x: hunk 1 does not apply",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::REPLACE_EMPTY_OLD_TIP_MARKER),
                "{raw} => {text}"
            );
        }
        // The sibling replace tips still fire on their own errors.
        let value = tool_err(
            "found 2 matches of the old string in /tmp/x; pass --all (CLI) or replace_all \
             (MCP/API) to replace every match",
        );
        let text = err_text(&value);
        assert!(
            text.contains(crate::AMBIGUOUS_REPLACE_TIP_MARKER),
            "{text}"
        );
        let value = tool_err("old string was not found in /tmp/x");
        let text = err_text(&value);
        assert!(text.contains(crate::EDIT_MISMATCH_TIP_MARKER), "{text}");
    }

    #[test]
    fn tool_err_tips_edit_file_too_large() {
        let value = tool_err(
            "patch /srv/app/src/main.rs: /srv/app/src/main.rs is larger than 8388608 bytes",
        );
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::EDIT_FILE_TOO_LARGE_TIP_MARKER),
            "{text}"
        );
        assert!(text.contains("`apply_patch`"), "{text}");
        assert!(text.contains("`run_command`"), "{text}");
        assert!(text.contains("`read_file`"), "{text}");
        assert!(text.contains("`write_file`"), "{text}");
        assert!(text.contains("`stat_path`"), "{text}");
        assert!(text.contains("`agentlink guide <node>`"), "{text}");
        assert_eq!(
            text.matches(crate::EDIT_FILE_TOO_LARGE_TIP_MARKER).count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_edit_text_not_utf8() {
        let value = tool_err("replace_text: /srv/app/config.ini is not UTF-8 text");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::EDIT_TEXT_NOT_UTF8_TIP_MARKER),
            "{text}"
        );
        for needle in [
            "`replace_text`",
            "`edit_lines`",
            "`apply_patch`",
            "`read_file`",
            "`content_base64`",
            "`write_file`",
            "`run_command`",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        assert_eq!(
            text.matches(crate::EDIT_TEXT_NOT_UTF8_TIP_MARKER).count(),
            1,
            "{text}"
        );
        let lower = tool_err("/srv/app/config.ini is not utf-8");
        let lower_text = lower["content"][0]["text"].as_str().unwrap();
        assert!(
            !lower_text.contains(crate::EDIT_TEXT_NOT_UTF8_TIP_MARKER),
            "{lower_text}"
        );
        assert!(lower_text.contains("is not utf-8"), "{lower_text}");
    }

    #[test]
    fn tool_err_tips_write_target_directory() {
        let value = tool_err("replace_text: /srv/app/reports is a directory");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::WRITE_TARGET_IS_DIRECTORY_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
        for needle in [
            "`write`",
            "`write_file`",
            "`list_dir`",
            "`stat_path`",
            "`mkdir`",
            "`remove_path`",
            "`copy_path`",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }

        let read_side =
            tool_err("/srv/app/notes.txt is a directory, not a file; use `ls` to list it");
        let read_text = read_side["content"][0]["text"].as_str().unwrap();
        assert!(
            read_text.starts_with(
                "/srv/app/notes.txt is a directory, not a file; use `ls` to list it. tip: "
            ),
            "{read_text}"
        );
        assert_eq!(
            read_text
                .matches(crate::READ_TARGET_IS_DIRECTORY_TIP_MARKER)
                .count(),
            1,
            "{read_text}"
        );
        assert!(
            !read_text.contains(crate::WRITE_TARGET_IS_DIRECTORY_TIP_MARKER),
            "{read_text}"
        );
    }

    #[test]
    fn tool_err_tips_edit_atomic_write_permission() {
        let value =
            tool_err("atomic write /srv/app/config.toml: Permission denied (os error 13)");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::EDIT_ATOMIC_WRITE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in ["replace_text", "edit_lines", "apply_patch", "config.toml"] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        assert_eq!(crate::decorate_edit_atomic_write(text), text);
    }

    #[test]
    fn tool_err_tips_edit_atomic_write_windows() {
        for raw in [
            "atomic write /srv/app/config.toml: Access is denied. (os error 5)",
            "atomic write /srv/app/config.toml: The process cannot access the file because it is being used by another process. (os error 32)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true), "{raw}");
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(raw), "{raw} => {text}");
            assert_eq!(
                text.matches(crate::EDIT_ATOMIC_WRITE_TIP_MARKER).count(),
                1,
                "{raw}: {text}"
            );
        }
    }

    #[test]
    fn tool_err_leaves_other_atomic_write_and_edit_lines_alone() {
        for raw in [
            "atomic write /tmp/x: No such file or directory (os error 2)",
            "atomic write /tmp/x: Is a directory (os error 21)",
            "atomic write /tmp/x: Input/output error (os error 5)",
            "io: Permission denied (os error 13)",
            "patch /srv/app/x: hunk mismatch",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{raw}");
            assert!(!text.contains("tip:"), "{raw}: {text}");
            assert!(
                !text.contains(crate::EDIT_ATOMIC_WRITE_TIP_MARKER),
                "{raw}: {text}"
            );
        }
    }

    #[test]
    fn tool_err_atomic_write_does_not_shadow_siblings() {
        let raw = "atomic write /srv/app/config.toml: Permission denied (os error 13)";
        let decorated = crate::decorate_edit_atomic_write(raw);
        assert_ne!(decorated, raw);
        assert_eq!(
            crate::decorate_write_dest_permission(&decorated, "builder", "/srv/app/config.toml"),
            decorated
        );
        assert_eq!(
            crate::decorate_remove_dest_permission(
                &decorated,
                "builder",
                "/srv/app/config.toml",
                false
            ),
            decorated
        );
        assert_eq!(
            crate::decorate_mkdir_dest_permission(&decorated, "builder", "/srv/app", false),
            decorated
        );
        assert_eq!(crate::decorate_patch_too_large(&decorated), decorated);
        assert_eq!(crate::decorate_edit_file_too_large(&decorated), decorated);
        assert_eq!(crate::decorate_sandbox_path_escape(&decorated), decorated);
        assert_eq!(crate::decorate_patch_hunk_mismatch(&decorated), decorated);
        assert_eq!(
            crate::decorate_write_target_is_directory(&decorated),
            decorated
        );
    }

    #[test]
    fn tool_err_tips_exec_cwd_permission() {
        let value = tool_err("cwd /home/alice/repo: Permission denied (os error 13)");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::EXEC_CWD_PERMISSION_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in ["/home/alice/repo", "run_command", "process_start"] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        assert_eq!(crate::decorate_exec_cwd_permission(text), text);
    }

    #[test]
    fn tool_err_tips_exec_cwd_permission_windows() {
        let raw = r"cwd C:\Users\Alice\repo: Access is denied. (os error 5)";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(raw), "{text}");
        assert_eq!(
            text.matches(crate::EXEC_CWD_PERMISSION_TIP_MARKER).count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_leaves_cwd_miss_spawn_and_raw_lines_alone() {
        // The cwd-permission decorator must not claim any sibling shape.
        for raw in [
            "cwd /tmp/missing: No such file or directory (os error 2)",
            "cwd /tmp/file: Not a directory",
            "spawn: Permission denied (os error 13)",
            "pty spawn: Permission denied (os error 13)",
            "io: Permission denied (os error 13)",
            "not found: parent directory does not exist: /home/alice/repo",
        ] {
            assert_eq!(crate::decorate_exec_cwd_permission(raw), raw, "{raw}");
        }

        // These lines carry no cwd-permission tip through the flat chain.
        for raw in [
            "spawn: Permission denied (os error 13)",
            "pty spawn: Permission denied (os error 13)",
            "io: Permission denied (os error 13)",
            "not found: parent directory does not exist: /home/alice/repo",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{raw}");
            assert!(
                !text.contains(crate::EXEC_CWD_PERMISSION_TIP_MARKER),
                "{raw}: {text}"
            );
        }
    }

    #[test]
    fn tool_err_cwd_permission_does_not_shadow_siblings() {
        let raw = "cwd /home/alice/repo: Permission denied (os error 13)";
        let decorated = crate::decorate_exec_cwd_permission(raw);
        assert_ne!(decorated, raw);
        assert_eq!(crate::decorate_sandbox_path_escape(&decorated), decorated);
        assert_eq!(crate::decorate_sandbox_denial(&decorated), decorated);
        assert_eq!(crate::decorate_exec_cwd_missing(&decorated), decorated);
        assert_eq!(crate::decorate_exec_eacces(&decorated, None), decorated);
        assert_eq!(crate::decorate_exec_enoexec(&decorated), decorated);
        assert_eq!(crate::decorate_missing_parent(&decorated), decorated);
        assert_eq!(crate::decorate_read_missing_file(&decorated), decorated);
    }

    #[test]
    fn tool_err_tips_write_dest_permission() {
        let decorated = crate::decorate_write_dest_permission(
            "io: Permission denied (os error 13)",
            "builder",
            "/etc/app/config.toml",
        );
        assert_eq!(
            decorated
                .matches(crate::WRITE_DEST_PERMISSION_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        for needle in [
            "builder",
            "/etc/app/config.toml",
            "stat_path",
            "chmod",
            "agentlink guide <node>",
        ] {
            assert!(decorated.contains(needle), "{needle}: {decorated}");
        }
        assert!(
            !decorated.contains(crate::SANDBOX_PATH_ESCAPE_TIP_MARKER),
            "{decorated}"
        );
        assert!(
            !decorated.contains(crate::SANDBOX_PATH_ESCAPE_NEEDLE),
            "{decorated}"
        );
        let value = tool_err(&decorated);
        assert_eq!(
            value["content"][0]["text"].as_str().unwrap(),
            decorated,
            "the decorated perm tip must not retrigger the sandbox tip"
        );

        for raw in [
            "io: Permission denied (os error 13)",
            "io: Access is denied. (os error 5)",
            "io: Read-only file system (os error 30)",
            "io: Is a directory (os error 21)",
            "io: Input/output error (os error 5)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true), "{raw}");
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "flat tool_err chain must not learn the tip");
            assert!(!text.contains("tip:"), "{raw}: {text}");
        }

        assert_eq!(
            crate::decorate_write_target_is_directory("io: Permission denied (os error 13)"),
            "io: Permission denied (os error 13)"
        );
        assert_eq!(
            crate::decorate_write_dest_permission("/srv/app is a directory", "builder", "/srv/app"),
            "/srv/app is a directory"
        );
    }

    #[test]
    fn tool_err_tips_symlink_dir_read() {
        let value = tool_err(
            "/srv/app/current is a symlink to a directory, not a file; use directory copy",
        );
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::SYMLINK_DIR_READ_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "read_file",
            "list_dir",
            "copy_path",
            "agentlink guide <node>",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }

        let read_side = "/srv/app/reports is a directory, not a file; use `ls` to list it";
        let out = tool_err(read_side);
        let read_text = out["content"][0]["text"].as_str().unwrap();
        assert!(
            !read_text.contains(crate::SYMLINK_DIR_READ_TIP_MARKER),
            "{read_text}"
        );
        assert_eq!(
            read_text
                .matches(crate::READ_TARGET_IS_DIRECTORY_TIP_MARKER)
                .count(),
            1,
            "{read_text}"
        );
    }

    #[test]
    fn tool_err_tips_read_target_directory() {
        let raw = "/srv/app/reports is a directory, not a file; use `ls` to list it";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.starts_with(&format!(
                "{raw}. tip: {} — ",
                crate::READ_TARGET_IS_DIRECTORY_TIP_MARKER
            )),
            "{text}"
        );
        assert_eq!(
            text.matches(crate::READ_TARGET_IS_DIRECTORY_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
        for needle in [
            "read_file",
            "list_dir",
            "stat_path",
            "copy_path",
            "agentlink guide <node>",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }

        let symlink = tool_err(
            "/srv/app/current is a symlink to a directory, not a file; use directory copy",
        );
        let symlink_text = symlink["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            symlink_text
                .matches(crate::SYMLINK_DIR_READ_TIP_MARKER)
                .count(),
            1,
            "{symlink_text}"
        );
        assert!(
            !symlink_text.contains(crate::READ_TARGET_IS_DIRECTORY_TIP_MARKER),
            "{symlink_text}"
        );

        let eisdir = tool_err("io: Is a directory (os error 21)");
        let eisdir_text = eisdir["content"][0]["text"].as_str().unwrap();
        assert!(
            !eisdir_text.contains(crate::READ_TARGET_IS_DIRECTORY_TIP_MARKER),
            "{eisdir_text}"
        );
    }

    #[test]
    fn tool_err_tips_copy_special_file() {
        for raw in [
            "/srv/app/run/app.sock is not a regular file (refusing fifo/socket/device)",
            "/dev/zero is not a regular file (refusing fifo/socket/device)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                text.starts_with(&format!(
                    "{raw}. tip: {} — ",
                    crate::COPY_SPECIAL_FILE_TIP_MARKER
                )),
                "{text}"
            );
            assert_eq!(
                text.matches(crate::COPY_SPECIAL_FILE_TIP_MARKER).count(),
                1,
                "{text}"
            );
            for needle in ["read_file", "copy_path", "stat_path", "run_command"] {
                assert!(text.contains(needle), "{needle}: {text}");
            }
        }

        for raw in [
            "/srv/app/reports is a directory, not a file; use `ls` to list it",
            "/srv/app/link is a symlink to a directory, not a file; use directory copy",
        ] {
            let text = tool_err(raw);
            let text = text["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::COPY_SPECIAL_FILE_TIP_MARKER),
                "{raw}: {text}"
            );
        }
    }

    #[test]
    fn tool_err_leaves_bare_io_enoent_alone() {
        // `stat_path` returns the same bare ENOENT, so `tool_err` must not
        // decorate it; only the replace call sites know the operation/path.
        let value = tool_err("io: No such file or directory (os error 2)");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "io: No such file or directory (os error 2)");
        assert!(
            !text.contains(crate::REPLACE_MISSING_FILE_TIP_MARKER),
            "{text}"
        );
        assert!(!text.contains("tip:"), "{text}");
        let decorated = crate::decorate_replace_missing_file(
            "io: No such file or directory (os error 2)",
            "/srv/app/notes.txt",
        );
        assert!(
            decorated.contains(crate::REPLACE_MISSING_FILE_TIP_MARKER),
            "{decorated}"
        );
        assert!(decorated.contains("`/srv/app/notes.txt`"), "{decorated}");
    }

    #[test]
    fn tool_err_tips_read_missing_file() {
        // The read/download call sites know the path is a node source; the
        // flat `tool_err` chain must keep both ENOENT shapes raw (a missing
        // local upload source shares the custom literal).
        let decorated =
            crate::decorate_read_missing_file("/srv/app/notes.txt: No such file or directory");
        assert_eq!(
            decorated
                .matches(crate::READ_MISSING_FILE_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        for needle in [
            "list_dir",
            "stat_path",
            "search_files",
            "write_file",
            "edit_lines",
            "`~`",
            "agentlink guide <node>",
        ] {
            assert!(decorated.contains(needle), "{needle}: {decorated}");
        }
        for raw in [
            "io: No such file or directory (os error 2)",
            "/srv/app/link: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw);
            assert!(
                !text.contains(crate::READ_MISSING_FILE_TIP_MARKER),
                "{text}"
            );
            assert!(!text.contains("tip:"), "{text}");
        }
    }

    #[test]
    fn tool_err_tips_read_dangling_symlink() {
        // Only the read/download call sites know the path is on the node; the
        // flat `tool_err` chain must stay raw because a dangling local upload
        // source produces the same literal.
        let raw = "/srv/app/current: No such file or directory (os error 2)";
        let decorated = crate::decorate_read_dangling_symlink(raw);
        assert_eq!(
            decorated
                .matches(crate::READ_DANGLING_SYMLINK_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        for needle in [
            "stat_path",
            "is_symlink: true",
            "list_dir",
            "remove_path",
            "readlink",
            "write_file",
            "target",
            "agentlink guide <node>",
        ] {
            assert!(decorated.contains(needle), "{needle}: {decorated}");
        }
        assert_eq!(crate::decorate_read_missing_file(raw), raw);
        for raw in [
            "/srv/app/current: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
            "sandbox root: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw);
            assert!(
                !text.contains(crate::READ_DANGLING_SYMLINK_TIP_MARKER),
                "{text}"
            );
            assert!(!text.contains("tip:"), "{text}");
        }
    }

    #[test]
    fn read_file_eacces_is_tipped_at_the_read_file_arm() {
        // Only the `read_file` arm knows the operation is a node-side read of
        // the caller's path; the flat `tool_err` chain must stay raw because
        // the same `io:` line is produced by every other node op.
        let decorated = crate::decorate_read_file_permission(
            "io: Permission denied (os error 13)",
            "box",
            "/etc/shadow",
        );
        assert_eq!(
            decorated
                .matches(crate::READ_FILE_PERMISSION_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        let value = tool_err(&decorated);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, decorated, "{text}");

        for raw in [
            "io: Permission denied (os error 13)",
            "io: Access is denied. (os error 5)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{text}");
            assert!(!text.contains("tip:"), "{text}");
            assert!(
                !text.contains(crate::READ_FILE_PERMISSION_TIP_MARKER),
                "{text}"
            );
        }

        assert_eq!(
            crate::decorate_read_target_is_directory(&decorated),
            decorated
        );
        assert_eq!(crate::decorate_symlink_dir_read(&decorated), decorated);
        assert_eq!(
            crate::decorate_write_target_is_directory(&decorated),
            decorated
        );
        assert_eq!(crate::decorate_mkdir_target_not_dir(&decorated), decorated);
        assert_eq!(crate::decorate_sandbox_path_escape(&decorated), decorated);
        assert_eq!(crate::decorate_ambiguous_replace(&decorated), decorated);
        assert_eq!(
            crate::decorate_list_dir_permission(&decorated, "box", "/etc/shadow"),
            decorated
        );
    }

    #[test]
    fn tool_err_tips_copy_upload_missing_local() {
        // The upload call site maps the local-source ENOENT; the flat
        // `tool_err` chain must stay raw because the node-side bare form is
        // textually identical and only the call site knows the machine.
        let decorated = crate::decorate_copy_upload_missing_local(
            "/home/me/app.tgz: No such file or directory",
        );
        assert_eq!(
            decorated
                .matches(crate::COPY_UPLOAD_LOCAL_MISSING_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        for needle in [
            "local",
            "path",
            "direction: \"download\"",
            "write_file",
            "`~`",
            "agentlink guide <node>",
        ] {
            assert!(decorated.contains(needle), "{needle}: {decorated}");
        }
        for raw in [
            "/home/me/app.tgz: No such file or directory",
            "/srv/app/notes.txt: No such file or directory",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw);
            assert!(
                !text.contains(crate::COPY_UPLOAD_LOCAL_MISSING_TIP_MARKER),
                "{text}"
            );
            assert!(!text.contains("tip:"), "{text}");
        }
        for raw in [
            "/srv/app/link: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw);
        }
    }

    #[test]
    fn tool_err_tips_copy_upload_dangling_local() {
        // The literal is identical to the node-side dangling-link message for
        // read/download, so only the upload call site decorates it; the flat
        // `tool_err` chain must stay raw.
        let raw = "/srv/app/current: No such file or directory (os error 2)";
        let decorated = crate::decorate_copy_upload_dangling_local(raw);
        assert_eq!(
            decorated
                .matches(crate::COPY_UPLOAD_DANGLING_LOCAL_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        for needle in [
            "/srv/app/current",
            "this machine",
            "symlink",
            "readlink",
            "write_file",
            "agentlink guide <node>",
        ] {
            assert!(decorated.contains(needle), "{needle}: {decorated}");
        }
        let value = tool_err(raw);
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, raw);
        assert!(!text.contains("tip:"), "{text}");
        assert_eq!(crate::decorate_copy_upload_missing_local(raw), raw);
    }

    #[test]
    fn tool_err_tips_copy_peer_source_missing() {
        // Only the peer copy call site knows this bare `io:` ENOENT is the
        // source preflight, so the flat `tool_err` chain must stay raw.
        let raw = "io: No such file or directory (os error 2)";
        let decorated = crate::decorate_copy_peer_source_missing(
            raw,
            "builder",
            "/srv/app/dist",
            "prod",
            "/srv/www",
        );
        assert_eq!(
            decorated
                .matches(crate::COPY_PEER_SOURCE_MISSING_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        for needle in [
            "builder",
            "/srv/app/dist",
            "stat_path",
            "agentlink guide <node>",
        ] {
            assert!(decorated.contains(needle), "{needle}: {decorated}");
        }
        for form in [
            "io: No such file or directory (os error 2)",
            "io: The system cannot find the file specified. (os error 2)",
            "io: The system cannot find the path specified. (os error 3)",
        ] {
            let value = tool_err(form);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, form);
            assert!(!text.contains("tip:"), "{text}");
        }
        // The other call-site copy/read decorators are disjoint from this one.
        assert_eq!(crate::decorate_copy_upload_missing_local(raw), raw);
        assert_eq!(crate::decorate_copy_upload_dangling_local(raw), raw);
        assert_eq!(crate::decorate_read_missing_file(raw), raw);
    }

    #[test]
    fn tool_err_tips_copy_peer_dangling_source() {
        // The named `(os error 2)` literal is shared with read/download and the
        // upload-local arm, so only the peer call site may decorate it.
        let raw = "/srv/app/current: No such file or directory (os error 2)";
        let decorated = crate::decorate_copy_peer_dangling_source(
            raw,
            "builder",
            "/srv/app/current",
            "prod",
            "/srv/www",
        );
        assert_eq!(
            decorated
                .matches(crate::COPY_PEER_DANGLING_SOURCE_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        for needle in [
            "builder",
            "/srv/app/current",
            "stat_path",
            "readlink",
            "agentlink guide <node>",
        ] {
            assert!(decorated.contains(needle), "{needle}: {decorated}");
        }
        assert!(
            !decorated.contains(crate::READ_DANGLING_SYMLINK_TIP_MARKER),
            "{decorated}"
        );
        for form in [
            "/srv/app/current: No such file or directory (os error 2)",
            "/srv/app/current: The system cannot find the file specified. (os error 2)",
            "/srv/app/current: The system cannot find the path specified. (os error 3)",
            "io: No such file or directory (os error 2)",
        ] {
            let value = tool_err(form);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, form);
            assert!(!text.contains("tip:"), "{text}");
        }
        // The other call-site copy/read decorators are disjoint from this one.
        let pathless = "io: No such file or directory (os error 2)";
        assert_eq!(
            crate::decorate_copy_upload_missing_local(pathless),
            pathless
        );
        assert_eq!(
            crate::decorate_copy_upload_dangling_local(pathless),
            pathless
        );
        assert_eq!(crate::decorate_read_missing_file(pathless), pathless);
        assert_eq!(
            crate::decorate_copy_peer_source_missing(
                raw,
                "builder",
                "/srv/app/current",
                "prod",
                "/srv/www"
            ),
            raw
        );
    }

    #[test]
    fn tool_err_tips_replacement_text_too_large() {
        let value = tool_err("replace_text: replacement text exceeds 1 MiB");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::REPLACEMENT_TEXT_TOO_LARGE_TIP_MARKER),
            "{text}"
        );
        assert!(text.contains("`write_file`"), "{text}");
        assert!(text.contains("`edit_lines`"), "{text}");
        assert!(text.contains("`run_command`"), "{text}");
        assert!(text.contains("`apply_patch`"), "{text}");
        assert_eq!(
            text.matches(crate::REPLACEMENT_TEXT_TOO_LARGE_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_patch_too_large() {
        let value = tool_err("apply_patch: patch exceeds 1 MiB");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::PATCH_TOO_LARGE_TIP_MARKER),
            "{text}"
        );
        assert!(text.contains("`apply_patch`"), "{text}");
        assert!(text.contains("`write_file`"), "{text}");
        assert!(text.contains("`copy_path`"), "{text}");
        assert!(text.contains("`run_command`"), "{text}");
        assert!(text.contains("`agentlink guide <node>`"), "{text}");
        assert_eq!(
            text.matches(crate::PATCH_TOO_LARGE_TIP_MARKER).count(),
            1,
            "{text}"
        );

        let value = tool_err("replace_text: replacement text exceeds 1 MiB");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            !text.contains(crate::PATCH_TOO_LARGE_TIP_MARKER),
            "{text}"
        );
        assert!(
            text.contains(crate::REPLACEMENT_TEXT_TOO_LARGE_TIP_MARKER),
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_patch_missing_headers() {
        let value = tool_err("apply_patch: patch has no unified diff headers (--- / +++)");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::PATCH_MISSING_HEADERS_TIP_MARKER),
            "{text}"
        );
        assert!(text.contains("`replace_text`"), "{text}");
        assert!(text.contains("`edit_lines`"), "{text}");
        assert!(text.contains("`apply_patch`"), "{text}");
        assert!(text.contains("`agentlink guide <node>`"), "{text}");
        assert_eq!(
            text.matches(crate::PATCH_MISSING_HEADERS_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );

        let value = tool_err("apply_patch: patch is empty");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "apply_patch: patch is empty");
        assert!(
            !text.contains(crate::PATCH_MISSING_HEADERS_TIP_MARKER),
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_patch_parse() {
        let value =
            tool_err("apply_patch: patch /srv/app/src.rs: error parsing patch: Hunks not in order or overlap");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::PATCH_PARSE_TIP_MARKER), "{text}");
        assert_eq!(
            text.matches(crate::PATCH_PARSE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("`replace_text`"), "{text}");
        assert!(text.contains("`edit_lines`"), "{text}");
        assert!(text.contains("`apply_patch`"), "{text}");
        assert!(text.contains("`agentlink guide <node>`"), "{text}");

        let value = tool_err("apply_patch: patch /srv/app/src.rs: error applying hunk #1");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains(crate::PATCH_PARSE_TIP_MARKER), "{text}");
    }

    #[test]
    fn tool_err_tips_patch_root_not_dir() {
        let value = tool_err("/srv/app/src.rs is not a directory");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::PATCH_ROOT_NOT_DIR_TIP_MARKER), "{text}");
        assert_eq!(
            text.matches(crate::PATCH_ROOT_NOT_DIR_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("pass the parent directory"), "{text}");
        assert!(text.contains("`apply_patch`"), "{text}");
        assert!(text.contains("`agentlink guide <node>`"), "{text}");

        let value = tool_err("mkdir `/srv/app` exists but is not a directory");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            !text.contains(crate::PATCH_ROOT_NOT_DIR_TIP_MARKER),
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_patch_hunk_mismatch() {
        let value = tool_err("apply_patch: patch /srv/app/src.rs: error applying hunk #1");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::PATCH_HUNK_MISMATCH_TIP_MARKER),
            "{text}"
        );
        assert_eq!(
            text.matches(crate::PATCH_HUNK_MISMATCH_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("`agentlink cat <node> <path>`"), "{text}");
        assert!(
            text.contains("`agentlink replace <node> <path> <old> <new>`"),
            "{text}"
        );
        assert!(
            text.contains("`agentlink edit-lines <node> <path> <start> <end>`"),
            "{text}"
        );
        assert!(text.contains("`agentlink guide <node>`"), "{text}");
        assert_eq!(crate::decorate_patch_hunk_mismatch(text), text);

        let value = tool_err("patch /tmp/x: error applying hunk #12 (context mismatch)");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::PATCH_HUNK_MISMATCH_TIP_MARKER).count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_patch_path() {
        let value = tool_err("patch path must stay inside the root: /etc/passwd");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::PATCH_PATH_TIP_MARKER), "{text}");
        assert_eq!(
            text.matches(crate::PATCH_PATH_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(
            text.contains("rewrite `---`/`+++` as `a/<path>` / `b/<path>`"),
            "{text}"
        );
        assert!(text.contains("strip a leading `/` or drive letter"), "{text}");
        assert!(
            text.contains("`agentlink patch <node> <root> --file <diff>`"),
            "{text}"
        );
        assert!(text.contains("`agentlink replace`"), "{text}");
        assert!(text.contains("`agentlink edit-lines`"), "{text}");
        assert!(text.contains("`agentlink guide <node>`"), "{text}");
        assert_eq!(crate::decorate_patch_path(text), text);

        for raw in [
            "apply_patch: invalid patch path '../etc/passwd'",
            "patch /srv/app: patch path must stay inside the root: /etc/passwd",
            "apply_patch: patch path escapes the root: ../outside.rs",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(
                text.matches(crate::PATCH_PATH_TIP_MARKER).count(),
                1,
                "{raw}: {text}"
            );
        }
    }

    #[test]
    fn tool_err_patch_path_does_not_shadow_siblings() {
        for raw in [
            "patch /srv/app/src.rs: error applying hunk #1",
            "error parsing patch: Hunks not in order or overlap",
            "patch has no unified diff headers (--- / +++)",
            "patch is empty",
            "patch exceeds 1 MiB",
            "/srv/app is not a directory",
            "patch section has no path",
            "old string was not found in /srv/app/x",
            "old string is empty",
            "io: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(!text.contains(crate::PATCH_PATH_TIP_MARKER), "{raw}: {text}");
        }

        let raw = "patch /srv/app/src.rs: error applying hunk #1";
        let hunk = crate::decorate_patch_hunk_mismatch(raw);
        assert!(hunk.contains(crate::PATCH_HUNK_MISMATCH_TIP_MARKER), "{hunk}");
        assert!(!hunk.contains(crate::PATCH_PATH_TIP_MARKER), "{hunk}");
        assert_eq!(crate::decorate_patch_path(&hunk), hunk);
    }

    #[test]
    fn tool_err_patch_hunk_does_not_shadow_siblings() {
        for raw in [
            "error parsing patch: Hunks not in order or overlap",
            "patch has no unified diff headers (--- / +++)",
            "patch exceeds 1 MiB",
            "/srv/app is not a directory",
            "patch /srv/app/x: hunk mismatch",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::PATCH_HUNK_MISMATCH_TIP_MARKER),
                "{raw}: {text}"
            );
        }

        // Deliberate split: path rejections carry the path tip instead.
        let value = tool_err("invalid patch path '../etc/passwd'");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::PATCH_PATH_TIP_MARKER), "{text}");
        assert!(
            !text.contains(crate::PATCH_HUNK_MISMATCH_TIP_MARKER),
            "{text}"
        );

        let raw = "could not apply new-file patch for /srv/app/new.rs: error applying hunk #1";
        let value = tool_err(raw);
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, raw);
        assert!(
            !text.contains(crate::PATCH_HUNK_MISMATCH_TIP_MARKER),
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_mkdir_target_not_dir() {
        for raw in [
            "mkdir `/srv/app/releases` exists but is not a directory",
            "mkdir `/srv/app/releases` exists but is not a directory; `-p`/`--parents` cannot \
             replace a file with a directory",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(raw), "{text}");
            assert_eq!(
                text.matches(crate::MKDIR_TARGET_NOT_DIR_TIP_MARKER).count(),
                1,
                "{text}"
            );
            for needle in [
                "`list_dir`",
                "`stat_path`",
                "`remove_path`",
                "`agentlink guide <node>`",
            ] {
                assert!(text.contains(needle), "{needle} missing from {text}");
            }
        }

        for raw in [
            "mkdir `/srv/app/releases` already exists as a directory",
            "path component `/srv/app/x` exists but is not a directory",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::MKDIR_TARGET_NOT_DIR_TIP_MARKER),
                "{text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_path_component_not_dir() {
        for raw in [
            "path component `/tmp/file` exists but is not a directory",
            "path component `/tmp/file` exists but is not a directory; cannot create parent \
             directories for write/cp",
            "mv destination parent `/srv/app` exists but is not a directory",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(raw), "{text}");
            assert_eq!(
                text.matches(crate::PATH_COMPONENT_NOT_DIR_TIP_MARKER)
                    .count(),
                1,
                "{text}"
            );
            assert!(!text.contains(crate::MKDIR_TARGET_NOT_DIR_TIP_MARKER), "{text}");
            assert!(!text.contains(crate::PATCH_ROOT_NOT_DIR_TIP_MARKER), "{text}");
            assert!(!text.contains(crate::WRITE_TARGET_IS_DIRECTORY_TIP_MARKER), "{text}");
        }
    }

    #[test]
    fn tool_err_path_component_not_dir_leaves_siblings_alone() {
        for raw in [
            "mkdir `/srv/app/releases` exists but is not a directory",
            "path component `/etc/hostname` exists but is not a directory; `-p`/`--parents` \
             cannot fix that — pick a different path or remove the blocking file",
            "mv destination `/srv/app/x` exists but is not a directory; cannot move directory \
             `/srv/app/y` onto a file",
            "mv destination parent `/srv/app` does not exist; create it with mkdir -p first \
             (unlike write/cp, mv does not create parents)",
            "/srv/app/src.rs is not a directory",
            "io: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::PATH_COMPONENT_NOT_DIR_TIP_MARKER),
                "{raw} => {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_bg_process_limit() {
        let value = tool_err("this node already has 32 background processes");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::BG_LIMIT_TIP_MARKER), "{text}");
        assert!(text.contains("agentlink bg <node> list"), "{text}");
        assert!(text.contains("agentlink bg <node> kill <id>"), "{text}");
        assert!(text.contains("process_kill"), "{text}");
        assert!(text.contains("process_list"), "{text}");
    }

    #[test]
    fn process_start_eacces_is_tipped_at_the_process_start_arm() {
        let decorated = crate::decorate_bg_start_exec_denied(
            "spawn: Permission denied (os error 13)",
            "box",
            "/tmp/run.sh",
            None,
        );
        let value = tool_err(&decorated);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, decorated, "{text}");
        assert_eq!(
            text.matches(crate::BG_START_EXEC_DENIED_TIP_MARKER).count(),
            1,
            "{text}"
        );

        let hedged = crate::decorate_bg_start_exec_denied(
            "spawn: Permission denied (os error 13)",
            "box",
            "/tmp/run.sh",
            Some("/srv/work"),
        );
        let value = tool_err(&hedged);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, hedged, "{text}");
        assert_eq!(
            text.matches(crate::BG_START_EXEC_DENIED_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for literal in ["{dir}", "{cwd}"] {
            assert!(!text.contains(literal), "{literal} literal left: {text}");
        }

        for raw in [
            "spawn: Permission denied (os error 13)",
            "spawn: Access is denied. (os error 5)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{text}");
            assert!(!text.contains("tip:"), "{text}");
            assert!(
                !text.contains(crate::BG_START_EXEC_DENIED_TIP_MARKER),
                "{text}"
            );
        }

        assert_eq!(
            crate::decorate_exec_enoexec(&decorated),
            decorated,
            "flat chain must not stack a second tip"
        );
        assert_eq!(
            crate::decorate_exec_program_path_miss(&decorated),
            decorated
        );
        assert_eq!(crate::decorate_bg_process_limit(&decorated), decorated);
    }

    #[test]
    fn run_command_spawn_eacces_is_tipped_at_the_arm() {
        let decorated =
            crate::decorate_exec_eacces("spawn: Permission denied (os error 13)", Some("/root"));
        assert_eq!(
            decorated
                .matches(crate::EXEC_NOT_EXECUTABLE_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        assert!(decorated.contains("/root"), "{decorated}");
        assert!(decorated.contains("cannot be entered"), "{decorated}");

        // The tip survives the flat chain, which must not stack a second tip.
        let value = tool_err(&decorated);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, decorated, "{text}");
        assert_eq!(
            crate::decorate_bg_start_exec_denied(&decorated, "box", "true", Some("/root")),
            decorated
        );
        assert_eq!(crate::decorate_exec_cwd_permission(&decorated), decorated);
    }

    #[test]
    fn run_command_spawn_eacces_without_cwd_has_no_hedge() {
        let raw = "spawn: Permission denied (os error 13)";
        let decorated = crate::decorate_exec_eacces(raw, None);
        assert!(decorated.starts_with(raw), "{decorated}");
        assert_eq!(
            decorated
                .matches(crate::EXEC_NOT_EXECUTABLE_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        assert!(!decorated.contains("cannot be entered"), "{decorated}");
        assert_eq!(crate::decorate_exec_eacces(&decorated, None), decorated);
    }

    #[test]
    fn list_dir_permission_is_tipped_at_the_list_dir_arm() {
        let decorated = crate::decorate_list_dir_permission(
            "io: Permission denied (os error 13)",
            "box",
            "/root",
        );
        let value = tool_err(&decorated);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, decorated, "{text}");
        assert_eq!(
            text.matches(crate::LIST_DIR_PERMISSION_TIP_MARKER).count(),
            1,
            "{text}"
        );

        for raw in [
            "io: Permission denied (os error 13)",
            "io: Access is denied. (os error 5)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{text}");
            assert!(!text.contains("tip:"), "{text}");
            assert!(
                !text.contains(crate::LIST_DIR_PERMISSION_TIP_MARKER),
                "{text}"
            );
        }

        assert_eq!(
            crate::decorate_read_target_is_directory(&decorated),
            decorated
        );
        assert_eq!(crate::decorate_symlink_dir_read(&decorated), decorated);
        assert_eq!(
            crate::decorate_write_target_is_directory(&decorated),
            decorated
        );
        assert_eq!(crate::decorate_mkdir_target_not_dir(&decorated), decorated);
        assert_eq!(crate::decorate_sandbox_path_escape(&decorated), decorated);
        assert_eq!(crate::decorate_ambiguous_replace(&decorated), decorated);
    }

    #[test]
    fn list_dir_io_missing_is_tipped_at_the_list_dir_arm() {
        for raw in [
            "io: No such file or directory (os error 2)",
            "io: The system cannot find the file specified. (os error 2)",
            "io: The system cannot find the path specified. (os error 3)",
            "io: 系统找不到指定的文件。 (os error 2)",
            "io: 系统找不到指定的路径。 (os error 3)",
        ] {
            let decorated = crate::decorate_list_dir_io_missing(raw, "probe", "C:\\nope-ls-237");
            let value = tool_err(&decorated);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, decorated, "{text}");
            assert_eq!(
                text.matches(crate::LIST_DIR_IO_MISSING_TIP_MARKER).count(),
                1,
                "{text}"
            );
            assert!(text.contains("probe"), "{text}");
            assert!(text.contains("C:\\nope-ls-237"), "{text}");
        }

        // The flat `tool_err` chain must keep the bare `io:` line RAW: the
        // same line is produced by every other node op.
        for raw in [
            "io: No such file or directory (os error 2)",
            "io: The system cannot find the file specified. (os error 2)",
            "io: The system cannot find the path specified. (os error 3)",
            "io: 系统找不到指定的文件。 (os error 2)",
            "io: 系统找不到指定的路径。 (os error 3)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{text}");
            assert!(!text.contains("tip:"), "{text}");
            assert!(
                !text.contains(crate::LIST_DIR_IO_MISSING_TIP_MARKER),
                "{text}"
            );
        }

        let decorated = crate::decorate_list_dir_io_missing(
            "io: No such file or directory (os error 2)",
            "probe",
            "/tmp/nope",
        );
        assert_eq!(
            crate::decorate_list_dir_permission(&decorated, "probe", "/tmp/nope"),
            decorated
        );
        assert_eq!(crate::decorate_ls_missing(&decorated), decorated);
        assert_eq!(crate::decorate_mv_rm_missing(&decorated), decorated);
    }

    #[test]
    fn stat_path_eacces_is_tipped_at_the_stat_path_arm() {
        // Only the `stat_path` arm knows the operation is a metadata probe of
        // the caller's path; the flat `tool_err` chain must stay raw because
        // the same `io:` line is produced by every other node op (including
        // the `copy_path` peer preflight).
        let decorated = crate::decorate_stat_path_permission(
            "io: Permission denied (os error 13)",
            "box",
            "/root/.bashrc",
        );
        assert_eq!(
            decorated
                .matches(crate::STAT_PATH_PERMISSION_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        let value = tool_err(&decorated);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, decorated, "{text}");

        for raw in [
            "io: Permission denied (os error 13)",
            "io: Access is denied. (os error 5)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{text}");
            assert!(!text.contains("tip:"), "{text}");
            assert!(
                !text.contains(crate::STAT_PATH_PERMISSION_TIP_MARKER),
                "{text}"
            );
        }

        assert_eq!(
            crate::decorate_read_file_permission(&decorated, "box", "/root/.bashrc"),
            decorated
        );
        assert_eq!(
            crate::decorate_list_dir_permission(&decorated, "box", "/root/.bashrc"),
            decorated
        );
        assert_eq!(
            crate::decorate_write_dest_permission(&decorated, "box", "/root/.bashrc"),
            decorated
        );
        assert_eq!(
            crate::decorate_mkdir_dest_permission(&decorated, "box", "/root/.bashrc", false),
            decorated
        );
        assert_eq!(
            crate::decorate_remove_dest_permission(&decorated, "box", "/root/.bashrc", false),
            decorated
        );
        assert_eq!(
            crate::decorate_mv_dest_permission(&decorated, "box", "/srv/a", "/root/.bashrc"),
            decorated
        );
        assert_eq!(crate::decorate_sandbox_path_escape(&decorated), decorated);
    }

    #[test]
    fn search_content_permission_is_tipped_at_the_search_arm() {
        let decorated = crate::decorate_search_permission(
            "search /etc/shadow: Permission denied (os error 13)",
            "box",
            "/etc/shadow",
        );
        let value = tool_err(&decorated);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, decorated, "{text}");
        assert_eq!(
            text.matches(crate::SEARCH_PERMISSION_TIP_MARKER).count(),
            1,
            "{text}"
        );

        for raw in [
            "search /etc/shadow: Permission denied (os error 13)",
            "search C:\\ProgramData\\secrets\\app.txt: Access is denied. (os error 5)",
            "find /x: Permission denied (os error 13)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{text}");
            assert!(!text.contains("tip:"), "{text}");
            assert!(
                !text.contains(crate::SEARCH_PERMISSION_TIP_MARKER),
                "{text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_exec_program_path_miss() {
        let value =
            tool_err("program './gradlew' not found (No such file or directory (os error 2))");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::EXEC_PROGRAM_PATH_MISS_TIP_MARKER),
            "{text}"
        );
        assert!(text.contains("`--cwd <dir>`"), "{text}");
        assert!(text.contains("`agentlink ls <node> <dir>`"), "{text}");
        assert!(text.contains("posix_spawn reports ENOENT"), "{text}");
        assert!(!text.contains("not on the node's PATH"), "{text}");
    }

    #[test]
    fn tool_err_tips_exec_path_miss() {
        let raw = "program 'cd' not found on PATH (No such file or directory (os error 2))";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::EXEC_PATH_MISS_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(
            text.contains("`agentlink exec <node> --shell '<cmd>'`"),
            "{text}"
        );
        assert!(text.contains("'cd' is not on the node's PATH"), "{text}");
        assert!(
            text.contains("shell builtins/aliases/pipelines need a shell"),
            "{text}"
        );
        assert_eq!(crate::decorate_exec_path_miss(text), text, "{text}");

        // Anyhow-wrapped shapes tip once and keep the raw line as a prefix.
        for raw in [
            "run_command: program 'grep' not found on PATH (No such file or directory (os error 2))",
            "exec box: program 'watch' not found on PATH (No such file or directory (os error 2))",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(raw), "{text}");
            assert_eq!(
                text.matches(crate::EXEC_PATH_MISS_TIP_MARKER).count(),
                1,
                "{text}"
            );
        }
    }

    #[test]
    fn tool_err_exec_path_miss_splits_from_program_path_miss() {
        // Path-like programs keep the path-miss tip and never the PATH tip.
        let value =
            tool_err("program './gradlew' not found (No such file or directory (os error 2))");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::EXEC_PROGRAM_PATH_MISS_TIP_MARKER),
            "{text}"
        );
        assert!(!text.contains(crate::EXEC_PATH_MISS_TIP_MARKER), "{text}");

        // Bare names keep the PATH tip and never the path-miss tip.
        let value =
            tool_err("program 'cd' not found on PATH (No such file or directory (os error 2))");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::EXEC_PATH_MISS_TIP_MARKER), "{text}");
        assert!(
            !text.contains(crate::EXEC_PROGRAM_PATH_MISS_TIP_MARKER),
            "{text}"
        );
    }

    #[test]
    fn tool_err_exec_path_miss_does_not_shadow_siblings() {
        for raw in [
            "program '/opt/missing/tool' not found (No such file or directory (os error 2))",
            "spawn: Exec format error (os error 8)",
            "spawn: Permission denied (os error 13)",
            "cwd /tmp/missing: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
            "node offline: probe",
            "patch /srv/app/src.rs: error applying hunk #1",
            "old string was not found in /srv/app/x",
            "exec bash --shell 'cd /tmp'",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::EXEC_PATH_MISS_TIP_MARKER),
                "{raw} -> {text}"
            );
        }

        assert_eq!(
            crate::decorate_exec_program_path_miss(
                "program 'cd' not found on PATH (No such file or directory (os error 2))"
            ),
            "program 'cd' not found on PATH (No such file or directory (os error 2))"
        );
    }

    #[test]
    fn tool_err_tips_exec_enoexec() {
        let value = tool_err("spawn: Exec format error (os error 8)");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::EXEC_ENOEXEC_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("run_command"), "{text}");
        assert!(text.contains("process_start"), "{text}");
        assert!(text.contains("bash <path>"), "{text}");
        assert!(text.contains("agentlink guide <node>"), "{text}");

        for raw in [
            "spawn: Permission denied (os error 13)",
            "pty spawn: Exec format error (os error 8)",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::EXEC_ENOEXEC_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_env_var_rejected() {
        let value = tool_err("rejected env var 'FOO=bar'");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::ENV_VAR_REJECTED_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("run_command"), "{text}");
        assert!(text.contains("process_start"), "{text}");
        assert!(text.contains("`\"env\": {\"FOO\": \"bar\"}`"), "{text}");

        for raw in [
            "env must be an object of string values",
            "env.FOO must be a string",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::ENV_VAR_REJECTED_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_env_value_not_string() {
        for raw in [
            "env.PORT must be a string",
            "env.DEBUG must be a string",
            "env.my-key_1 must be a string",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(raw), "{raw} -> {text}");
            assert_eq!(
                text.matches(crate::ENV_VALUE_NOT_STRING_TIP_MARKER).count(),
                1,
                "{raw} -> {text}"
            );
            for needle in [
                "JSON string",
                "`\"env\": {\"PORT\": \"8080\", \"DEBUG\": \"true\"}`",
                "`rejected env var '…'`",
                "no process started",
                "run_command",
                "process_start",
                "`agentlink guide <node>`",
            ] {
                assert!(text.contains(needle), "{needle} missing: {text}");
            }
            assert_eq!(crate::decorate_env_value_not_string(text), text);
        }
    }

    #[test]
    fn tool_err_env_value_not_string_does_not_shadow_siblings() {
        let value = tool_err("env.PORT must be a string");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::ENV_VALUE_NOT_STRING_TIP_MARKER),
            "{text}"
        );
        for marker in [
            crate::ENV_VAR_REJECTED_TIP_MARKER,
            crate::ARGV_EMPTY_TIP_MARKER,
            crate::ARGV_NOT_STRINGS_TIP_MARKER,
            crate::MISSING_ARG_TIP_MARKER,
        ] {
            assert!(!text.contains(marker), "{marker} leaked: {text}");
        }

        for raw in [
            "rejected env var 'FOO=bar'",
            "env must be an object of string values",
            "argv is empty",
            "argv values must be strings",
            "missing `command`",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::ENV_VALUE_NOT_STRING_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_stdin_not_string() {
        for raw in ["stdin must be a string", "  stdin must be a string  "] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(raw), "{raw} -> {text}");
            assert_eq!(
                text.matches(crate::STDIN_NOT_STRING_TIP_MARKER).count(),
                1,
                "{raw} -> {text}"
            );
            for needle in [
                "JSON string",
                "UTF-8 text",
                "`\"stdin\": \"hello\\n\"`",
                "Numbers, booleans, objects, and arrays",
                "`null`",
                "no stdin at all",
                "`stdin is N bytes; max is …`",
                "nothing was spawned",
                "run_command",
                "process_start",
                "`agentlink guide <node>`",
            ] {
                assert!(text.contains(needle), "{needle} missing: {text}");
            }
            assert_eq!(crate::decorate_stdin_not_string(text), text);
        }
    }

    #[test]
    fn tool_err_stdin_not_string_does_not_shadow_siblings() {
        let value = tool_err("stdin must be a string");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::STDIN_NOT_STRING_TIP_MARKER), "{text}");
        for marker in [
            crate::ENV_VALUE_NOT_STRING_TIP_MARKER,
            crate::ARGV_NOT_STRINGS_TIP_MARKER,
            crate::ARGV_EMPTY_TIP_MARKER,
            crate::MISSING_ARG_TIP_MARKER,
            crate::MISSING_COMMAND_TIP_MARKER,
        ] {
            assert!(!text.contains(marker), "{marker} leaked: {text}");
        }

        for raw in [
            "stdin is 16777217 bytes; max is 16777216",
            "env.PORT must be a string",
            "argv values must be strings",
            "argv is empty",
            "missing `command`",
            "stat_path: No such file or directory (os error 2)",
            "len `stdin`: stdin must be a string",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::STDIN_NOT_STRING_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_copy_direction() {
        let raw = "direction must be upload, download, or peer, got sideways";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::COPY_DIRECTION_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "`upload`",
            "local → node",
            "`download`",
            "node → local",
            "`peer`",
            "node → node",
            "`dst_node`",
            "`dst_path`",
            "sideways",
            "before any transfer starts",
            "not a permission, grant, sandbox, node-offline, or timeout failure",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert_eq!(crate::decorate_copy_direction(text), text);
    }

    #[test]
    fn tool_err_copy_direction_does_not_shadow_siblings() {
        let value = tool_err("direction must be upload, download, or peer, got sideways");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::COPY_DIRECTION_TIP_MARKER), "{text}");
        for marker in [
            crate::ENV_VALUE_NOT_STRING_TIP_MARKER,
            crate::MISSING_ARG_TIP_MARKER,
            crate::CONTENT_BASE64_TIP_MARKER,
            crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER,
        ] {
            assert!(!text.contains(marker), "{marker} leaked: {text}");
        }

        for raw in [
            "env.PORT must be a string",
            "missing `path`",
            "stat_path: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::COPY_DIRECTION_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_invalid_compress() {
        let raw = "compress must be auto, on, or off, got yes";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::COMPRESS_VALUE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "`copy_path`",
            "lowercase JSON strings",
            "`\"auto\"`",
            "`\"on\"`",
            "`\"off\"`",
            "already compressed",
            "not boolean `true`",
            "before direction dispatch",
            "no source was read",
            "nothing was transferred",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::COPY_DIRECTION_TIP_MARKER), "{text}");
        assert_eq!(tool_err(text), value);
    }

    #[test]
    fn tool_err_invalid_compress_does_not_shadow_siblings() {
        let value = tool_err("direction must be upload, download, or peer, got sideways");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::COPY_DIRECTION_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::COMPRESS_VALUE_TIP_MARKER), "{text}");

        for raw in [
            "compress must be auto, on, or off",
            "compress must be auto, on, or off, got ",
            "copy_path: compress must be auto, on, or off, got yes",
            "compress must be auto, on, or off, got yes\nother error",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(!text.contains(crate::COMPRESS_VALUE_TIP_MARKER), "{raw} -> {text}");
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_stdin_too_large() {
        let raw = "stdin is 16777217 bytes; max is 16777216";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::STDIN_TOO_LARGE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "UTF-8 bytes",
            "bytes, not characters",
            "copy_path",
            "write_file",
            "`prog < /tmp/input`",
            "remove_path",
            "run_command",
            "process_start",
            "nothing was spawned",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::STDIN_NOT_STRING_TIP_MARKER), "{text}");
        assert_eq!(crate::decorate_stdin_too_large(text), text);
    }

    #[test]
    fn tool_err_stdin_too_large_does_not_shadow_siblings() {
        let value = tool_err("stdin must be a string");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::STDIN_NOT_STRING_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::STDIN_TOO_LARGE_TIP_MARKER), "{text}");

        for raw in [
            "stdin is 16777216 bytes; max is 16777216",
            "stdin is 16777217 bytes; max is 16777216. Write a file and exec that path instead.",
            "stdin is 16777217 bytes; max is 16777216. Write a remote file and exec that path instead.",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(!text.contains(crate::STDIN_TOO_LARGE_TIP_MARKER), "{raw} -> {text}");
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_scroll_coord_pair() {
        let raw = "scroll needs both x and y, or neither";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::SCROLL_COORD_PAIR_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "omit both",
            "current pointer",
            "`\"x\": 640, \"y\": 480`",
            "`\"640\"`",
            "`dx`",
            "`dy`",
            "pointer did not move",
            "nothing scrolled",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert_eq!(crate::decorate_scroll_coord_pair(text), text);
    }

    #[test]
    fn tool_err_scroll_coord_pair_does_not_shadow_siblings() {
        let value = tool_err("scroll needs both x and y, or neither");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::SCROLL_COORD_PAIR_TIP_MARKER), "{text}");
        for marker in [
            crate::ENV_VALUE_NOT_STRING_TIP_MARKER,
            crate::MISSING_ARG_TIP_MARKER,
            crate::COPY_DIRECTION_TIP_MARKER,
            crate::CONTENT_BASE64_TIP_MARKER,
        ] {
            assert!(!text.contains(marker), "{marker} leaked: {text}");
        }

        for raw in [
            "`x` must be a finite number",
            "missing `node`",
            "env.PORT must be a string",
            "stat_path: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::SCROLL_COORD_PAIR_TIP_MARKER),
                "{raw} -> {text}"
            );
        }

        for raw in [
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "deliberate RAW error changed: {raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_argv_empty() {
        let value = tool_err("argv is empty");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::ARGV_EMPTY_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("run_command"), "{text}");
        assert!(text.contains("process_start"), "{text}");
        assert!(text.contains("`\"argv\": []`"), "{text}");
        assert!(text.contains("agentlink guide <node>"), "{text}");

        for raw in [
            "missing `command`",
            "argv values must be strings",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "spawn: Exec format error (os error 8)",
            "spawn: Permission denied (os error 13)",
            "rejected env var 'FOO=bar'",
            "node offline: probe",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::ARGV_EMPTY_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_argv_empty_does_not_shadow_siblings() {
        let value = tool_err("argv is empty");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::ARGV_EMPTY_TIP_MARKER), "{text}");
        for marker in [
            crate::EXEC_PATH_MISS_TIP_MARKER,
            crate::EXEC_PROGRAM_PATH_MISS_TIP_MARKER,
            crate::EXEC_ENOEXEC_TIP_MARKER,
            crate::ENV_VAR_REJECTED_TIP_MARKER,
        ] {
            assert!(!text.contains(marker), "{marker} leaked: {text}");
        }

        // The decorators are disjoint: sibling errors keep only their own tip.
        for (raw, marker) in [
            (
                "program 'cd' not found on PATH (No such file or directory (os error 2))",
                crate::EXEC_PATH_MISS_TIP_MARKER,
            ),
            (
                "spawn: Exec format error (os error 8)",
                crate::EXEC_ENOEXEC_TIP_MARKER,
            ),
            (
                "rejected env var 'FOO=bar'",
                crate::ENV_VAR_REJECTED_TIP_MARKER,
            ),
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.contains(marker), "{raw} -> {text}");
            assert!(
                !text.contains(crate::ARGV_EMPTY_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_argv_not_strings() {
        let value = tool_err("argv values must be strings");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::ARGV_NOT_STRINGS_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("run_command"), "{text}");
        assert!(text.contains("process_start"), "{text}");
        assert!(
            text.contains("`\"argv\": [\"ls\", \"-la\", \"/tmp\"]`"),
            "{text}"
        );
        assert!(text.contains("agentlink guide <node>"), "{text}");
        assert!(!text.contains(crate::ARGV_EMPTY_TIP_MARKER), "{text}");

        for raw in [
            "argv is empty",
            "missing `command`",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "spawn: Exec format error (os error 8)",
            "spawn: Permission denied (os error 13)",
            "rejected env var 'FOO=bar'",
            "node offline: probe",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::ARGV_NOT_STRINGS_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_argv_not_strings_does_not_shadow_siblings() {
        let value = tool_err("argv values must be strings");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::ARGV_NOT_STRINGS_TIP_MARKER), "{text}");
        for marker in [
            crate::ARGV_EMPTY_TIP_MARKER,
            crate::EXEC_PATH_MISS_TIP_MARKER,
            crate::EXEC_PROGRAM_PATH_MISS_TIP_MARKER,
            crate::EXEC_ENOEXEC_TIP_MARKER,
            crate::ENV_VAR_REJECTED_TIP_MARKER,
        ] {
            assert!(!text.contains(marker), "{marker} leaked: {text}");
        }

        // The decorators are disjoint: sibling errors keep only their own tip.
        for (raw, marker) in [
            ("argv is empty", crate::ARGV_EMPTY_TIP_MARKER),
            (
                "program 'cd' not found on PATH (No such file or directory (os error 2))",
                crate::EXEC_PATH_MISS_TIP_MARKER,
            ),
            (
                "spawn: Exec format error (os error 8)",
                crate::EXEC_ENOEXEC_TIP_MARKER,
            ),
            (
                "rejected env var 'FOO=bar'",
                crate::ENV_VAR_REJECTED_TIP_MARKER,
            ),
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.contains(marker), "{raw} -> {text}");
            assert!(
                !text.contains(crate::ARGV_NOT_STRINGS_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_missing_command() {
        let value = tool_err("missing `command`");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::MISSING_COMMAND_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("run_command"), "{text}");
        assert!(text.contains("process_start"), "{text}");
        assert!(
            text.contains("`\"argv\": [\"ls\", \"-la\", \"/tmp\"]`"),
            "{text}"
        );
        assert!(text.contains("`\"command\": \""), "{text}");
        assert!(text.contains("agentlink guide <node>"), "{text}");
        assert!(!text.contains(crate::ARGV_EMPTY_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::ARGV_NOT_STRINGS_TIP_MARKER), "{text}");

        for raw in [
            "missing `node`",
            "missing `keys`",
            "missing `cwd`",
            "argv is empty",
            "argv values must be strings",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "spawn: Exec format error (os error 8)",
            "spawn: Permission denied (os error 13)",
            "rejected env var 'FOO=bar'",
            "node offline: probe",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::MISSING_COMMAND_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_missing_command_does_not_shadow_siblings() {
        let value = tool_err("missing `command`");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::MISSING_COMMAND_TIP_MARKER), "{text}");
        for marker in [
            crate::ARGV_EMPTY_TIP_MARKER,
            crate::ARGV_NOT_STRINGS_TIP_MARKER,
            crate::EXEC_PATH_MISS_TIP_MARKER,
            crate::EXEC_PROGRAM_PATH_MISS_TIP_MARKER,
            crate::EXEC_ENOEXEC_TIP_MARKER,
            crate::ENV_VAR_REJECTED_TIP_MARKER,
        ] {
            assert!(!text.contains(marker), "{marker} leaked: {text}");
        }

        // The decorators are disjoint: sibling errors keep only their own tip.
        for (raw, marker) in [
            ("argv is empty", crate::ARGV_EMPTY_TIP_MARKER),
            (
                "argv values must be strings",
                crate::ARGV_NOT_STRINGS_TIP_MARKER,
            ),
            (
                "program 'cd' not found on PATH (No such file or directory (os error 2))",
                crate::EXEC_PATH_MISS_TIP_MARKER,
            ),
            (
                "spawn: Exec format error (os error 8)",
                crate::EXEC_ENOEXEC_TIP_MARKER,
            ),
            (
                "rejected env var 'FOO=bar'",
                crate::ENV_VAR_REJECTED_TIP_MARKER,
            ),
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.contains(marker), "{raw} -> {text}");
            assert!(
                !text.contains(crate::MISSING_COMMAND_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_missing_arg() {
        for key in [
            "keys", "text", "watch_id", "path", "to", "local", "dst_node",
        ] {
            let raw = format!("missing `{key}`");
            let value = tool_err(&raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(&raw), "{raw} -> {text}");
            assert_eq!(
                text.matches(crate::MISSING_ARG_TIP_MARKER).count(),
                1,
                "{raw} -> {text}"
            );
            assert!(text.contains(&format!("`{key}`")), "{raw} -> {text}");
            assert!(text.contains("non-empty JSON string"), "{text}");
            assert!(!text.contains("finite JSON number"), "{text}");
            assert!(text.contains("inputSchema"), "{text}");
            assert!(text.contains("tools/list"), "{text}");
            assert!(!text.contains(crate::MISSING_COMMAND_TIP_MARKER), "{text}");
        }

        for key in ["x", "y", "to_x", "to_y"] {
            let raw = format!("missing `{key}`");
            let value = tool_err(&raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(&raw), "{raw} -> {text}");
            assert_eq!(
                text.matches(crate::MISSING_ARG_TIP_MARKER).count(),
                1,
                "{raw} -> {text}"
            );
            assert!(text.contains(&format!("`{key}`")), "{raw} -> {text}");
            assert!(text.contains("finite JSON number"), "{text}");
            assert!(
                text.contains(&format!("`{key}` must be a finite number")),
                "{text}"
            );
            assert!(!text.contains("non-empty JSON string"), "{text}");
            assert!(text.contains("inputSchema"), "{text}");
            assert!(text.contains("tools/list"), "{text}");
            assert!(!text.contains(crate::MISSING_COMMAND_TIP_MARKER), "{text}");
        }
    }

    #[test]
    fn tool_err_missing_arg_does_not_shadow_siblings() {
        let value = tool_err("missing `keys`");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::MISSING_ARG_TIP_MARKER), "{text}");
        for marker in [
            crate::MISSING_COMMAND_TIP_MARKER,
            crate::ARGV_EMPTY_TIP_MARKER,
            crate::ARGV_NOT_STRINGS_TIP_MARKER,
            crate::NODE_NOT_FOUND_TIP_MARKER,
            crate::NODE_OFFLINE_TIP_MARKER,
        ] {
            assert!(!text.contains(marker), "{marker} leaked: {text}");
        }

        // `command` belongs to `decorate_missing_command`; paths and other
        // non-identifiers keep their raw form.
        for raw in [
            "missing `command`",
            "missing `/tmp/x`",
            "missing `Makefile`",
            "argv is empty",
            "argv values must be strings",
            "node offline: probe",
            "io: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::MISSING_ARG_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
        let value = tool_err("missing `command`");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::MISSING_COMMAND_TIP_MARKER),
            "missing command tip should still fire: {text}"
        );
    }

    #[test]
    fn tool_err_tips_finite_number() {
        for key in ["x", "y", "to_x", "to_y"] {
            let raw = format!("`{key}` must be a finite number");
            let value = tool_err(&raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(&raw), "{raw} -> {text}");
            assert_eq!(
                text.matches(crate::FINITE_NUMBER_TIP_MARKER).count(),
                1,
                "{raw} -> {text}"
            );
            assert!(text.contains(&format!("`{key}`")), "{raw} -> {text}");
            assert!(text.contains("finite JSON number"), "{text}");
            assert!(text.contains("0–1 fraction"), "{text}");
            assert!(text.contains("inputSchema"), "{text}");
            assert!(text.contains("tools/list"), "{text}");
            assert!(!text.contains(crate::MISSING_ARG_TIP_MARKER), "{text}");
        }
    }

    #[test]
    fn tool_err_finite_number_does_not_shadow_siblings() {
        let value = tool_err("`x` must be a finite number");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::FINITE_NUMBER_TIP_MARKER),
            "{text}"
        );
        for marker in [
            crate::MISSING_ARG_TIP_MARKER,
            crate::MISSING_COMMAND_TIP_MARKER,
            crate::ARGV_EMPTY_TIP_MARKER,
            crate::ARGV_NOT_STRINGS_TIP_MARKER,
            crate::NODE_NOT_FOUND_TIP_MARKER,
            crate::NODE_OFFLINE_TIP_MARKER,
        ] {
            assert!(!text.contains(marker), "{marker} leaked: {text}");
        }

        // `missing` keeps its own tip; bare ENOENT and non-UUID terminal
        // errors stay raw.
        let value = tool_err("missing `x`");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::MISSING_ARG_TIP_MARKER),
            "missing arg tip should still fire: {text}"
        );
        assert!(!text.contains(crate::FINITE_NUMBER_TIP_MARKER), "{text}");
        for raw in [
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal zzz",
            "io: No such file or directory (os error 2)",
            "`x` must be a number",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_write_file_needs_content() {
        let raw = "write_file needs `content` or `content_base64`";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.starts_with(&format!(
                "{raw}. tip: {} — ",
                crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER
            )),
            "{text}"
        );
        assert_eq!(
            text.matches(crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
        for needle in [
            "`content`",
            "`content_base64`",
            "UTF-8",
            "JSON string",
            "base64",
            "number",
            "object",
            "`null`",
            "Nothing was written",
            "inputSchema",
            "tools/list",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::MISSING_ARG_TIP_MARKER), "{text}");

        let again = tool_err(text);
        let again_text = again["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            again_text
                .matches(crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER)
                .count(),
            1,
            "{again_text}"
        );
    }

    #[test]
    fn tool_err_write_file_needs_content_does_not_shadow_siblings() {
        let value = tool_err("missing `path`");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::MISSING_ARG_TIP_MARKER), "{text}");
        assert!(
            !text.contains(crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER),
            "{text}"
        );

        let value = tool_err("/srv/app/reports is a directory");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::WRITE_TARGET_IS_DIRECTORY_TIP_MARKER),
            "{text}"
        );
        assert!(
            !text.contains(crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER),
            "{text}"
        );

        // Bare ENOENT stays raw. Base64 decode failures get their own tip
        // (separate decorator), not this one.
        for raw in [
            "stat_path: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{raw} -> {text}");
        }
        let value = tool_err("content_base64: Invalid symbol 33, offset 0");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::CONTENT_BASE64_TIP_MARKER), "{text}");
        assert!(
            !text.contains(crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER),
            "{text}"
        );
        for raw in ["unknown terminal abc", "unknown terminal zzz"] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_content_base64() {
        for raw in [
            "content_base64: Invalid symbol 33, offset 0.",
            "content_base64: Invalid symbol 33, offset 0",
            "content_base64: Invalid padding",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(raw), "{raw} -> {text}");
            assert_eq!(
                text.matches(crate::CONTENT_BASE64_TIP_MARKER).count(),
                1,
                "{raw} -> {text}"
            );
            for needle in [
                "JSON string",
                "standard Base64",
                "RFC 4648",
                "padding",
                "URL-safe",
                "raw binary",
                "`content`",
                "Nothing was written",
                "tools/list",
                "`agentlink guide <node>`",
            ] {
                assert!(text.contains(needle), "{needle} missing: {text}");
            }
            assert!(
                !text.contains(crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER),
                "{text}"
            );
        }
    }

    #[test]
    fn tool_err_content_base64_does_not_shadow_siblings() {
        let value = tool_err("content_base64: Invalid symbol 33, offset 0");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::CONTENT_BASE64_TIP_MARKER), "{text}");
        for marker in [
            crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER,
            crate::MISSING_ARG_TIP_MARKER,
            crate::FINITE_NUMBER_TIP_MARKER,
            crate::WRITE_TARGET_IS_DIRECTORY_TIP_MARKER,
        ] {
            assert!(!text.contains(marker), "{marker} leaked: {text}");
        }

        let value = tool_err("write_file needs `content` or `content_base64`");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER),
            "{text}"
        );
        assert!(!text.contains(crate::CONTENT_BASE64_TIP_MARKER), "{text}");

        for raw in [
            "stat_path: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
            "unknown terminal abc",
            "unknown terminal zzz",
            "missing `path`",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::CONTENT_BASE64_TIP_MARKER),
                "{raw} -> {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_terminal_write_needs_data() {
        let raw = "terminal_write needs `data` or `data_base64`";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::TERMINAL_WRITE_NEEDS_DATA_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
        for needle in [
            "`data`",
            "`data_base64`",
            "UTF-8",
            "standard base64",
            "takes precedence",
            "empty string is valid",
            "writes zero bytes",
            "before the terminal lookup or write",
            "no bytes were written",
            "inputSchema",
            "tools/list",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::MISSING_ARG_TIP_MARKER), "{text}");
        assert_eq!(tool_err(text), value);
    }

    #[test]
    fn tool_err_terminal_write_needs_data_does_not_shadow_siblings() {
        let value = tool_err("write_file needs `content` or `content_base64`");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::WRITE_FILE_NEEDS_CONTENT_TIP_MARKER),
            "{text}"
        );
        assert!(
            !text.contains(crate::TERMINAL_WRITE_NEEDS_DATA_TIP_MARKER),
            "{text}"
        );

        let value = tool_err("data_base64: Invalid symbol 33, offset 0.");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::DATA_BASE64_TIP_MARKER), "{text}");
        assert!(
            !text.contains(crate::TERMINAL_WRITE_NEEDS_DATA_TIP_MARKER),
            "{text}"
        );

        for raw in [
            "terminal_write: terminal_write needs `data` or `data_base64`",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains(crate::TERMINAL_WRITE_NEEDS_DATA_TIP_MARKER),
                "{raw} -> {text}"
            );
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_invalid_data_base64() {
        for raw in [
            "data_base64: Invalid symbol 33, offset 0.",
            "data_base64: Invalid padding",
            "data_base64: Invalid last symbol 66, offset 3.",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(raw), "{raw} -> {text}");
            assert_eq!(
                text.matches(crate::DATA_BASE64_TIP_MARKER).count(),
                1,
                "{text}"
            );
            for needle in [
                "`terminal_write`",
                "standard Base64",
                "RFC 4648",
                "padding where required",
                "Surrounding whitespace is trimmed",
                "URL-safe",
                "`data` takes precedence",
                "before the terminal lookup or write",
                "no bytes were written",
                "inputSchema",
                "`agentlink guide <node>`",
            ] {
                assert!(text.contains(needle), "{needle} missing: {text}");
            }
            assert!(!text.contains(crate::CONTENT_BASE64_TIP_MARKER), "{text}");
            assert_eq!(tool_err(text), value);
        }
    }

    #[test]
    fn tool_err_invalid_data_base64_does_not_shadow_siblings() {
        let value = tool_err("content_base64: Invalid symbol 33, offset 0.");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::CONTENT_BASE64_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::DATA_BASE64_TIP_MARKER), "{text}");

        let value = tool_err(crate::TERMINAL_WRITE_NEEDS_DATA_RAW);
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::TERMINAL_WRITE_NEEDS_DATA_TIP_MARKER),
            "{text}"
        );
        assert!(!text.contains(crate::DATA_BASE64_TIP_MARKER), "{text}");

        for raw in [
            "data_base64:",
            "terminal_write: data_base64: Invalid padding",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = value["content"][0]["text"].as_str().unwrap();
            assert!(!text.contains(crate::DATA_BASE64_TIP_MARKER), "{raw} -> {text}");
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_exec_cwd_missing() {
        let value = tool_err("cwd /tmp/missing: No such file or directory (os error 2)");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::EXEC_CWD_MISS_TIP_MARKER),
            "{text}"
        );
        assert!(
            text.contains("`agentlink mkdir <node> <dir> -p`"),
            "{text}"
        );
        assert!(text.contains("MCP `mkdir`"), "{text}");
        assert!(text.contains("`cd`/`--shell`"), "{text}");
        assert!(text.contains("`~` is not expanded"), "{text}");
        assert_eq!(
            text.matches(crate::EXEC_CWD_MISS_TIP_MARKER).count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_exec_cwd_not_a_directory() {
        let value = tool_err("cwd /tmp/file: Not a directory");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::EXEC_CWD_MISS_TIP_MARKER),
            "{text}"
        );
        assert!(
            text.contains("`/tmp/file` exists but is not a directory"),
            "{text}"
        );
        assert_eq!(
            text.matches(crate::EXEC_CWD_MISS_TIP_MARKER).count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_watch_limit() {
        let value = tool_err("this node already has 32 watches");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(crate::WATCH_LIMIT_TIP_MARKER), "{text}");
        assert!(text.contains("MCP `watch_stop`"), "{text}");
        assert!(text.contains("reuse a single watch"), "{text}");
        assert!(text.contains("idle watches are reaped"), "{text}");
        assert!(text.contains("agentlink guide <node>"), "{text}");
        assert!(!text.contains(crate::BG_LIMIT_TIP_MARKER), "{text}");
    }

    #[test]
    fn tool_err_tips_watch_inotify_limit() {
        let value = tool_err("watch /srv/app: inotify watch limit reached");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::WATCH_INOTIFY_LIMIT_TIP_MARKER),
            "{text}"
        );
        assert!(
            text.contains("fs.inotify.max_user_watches is exhausted"),
            "{text}"
        );
        assert!(text.contains("narrower subtree"), "{text}");
        assert!(
            text.contains("sudo sysctl fs.inotify.max_user_watches=524288"),
            "{text}"
        );
        assert!(text.contains("agentlink guide <node>"), "{text}");
        assert_eq!(
            text.matches(crate::WATCH_INOTIFY_LIMIT_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(!text.contains(crate::WATCH_LIMIT_TIP_MARKER), "{text}");
    }

    #[test]
    fn tool_err_tips_watch_target_missing() {
        let value = tool_err("watch /srv/app: No such file or directory (os error 2)");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::WATCH_TARGET_MISSING_TIP_MARKER),
            "{text}"
        );
        assert!(text.contains("agentlink mkdir -p <node> <dir>"), "{text}");
        assert!(text.contains("nearest existing parent"), "{text}");
        assert!(text.contains("`~` is not expanded"), "{text}");
        assert_eq!(
            text.matches(crate::WATCH_TARGET_MISSING_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
        assert!(
            !text.contains(crate::WATCH_INOTIFY_LIMIT_TIP_MARKER),
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_sandbox_path_escape() {
        let value = tool_err("permission denied: path escapes sandbox: /tmp/out.txt");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::SANDBOX_PATH_ESCAPE_TIP_MARKER),
            "{text}"
        );
        assert!(
            text.contains("Run `agentlink ls <node>` (no PATH; MCP `list_dir` with no `path`)"),
            "{text}"
        );
        assert!(text.contains("`sudo`/`chmod` will not help"), "{text}");
        assert!(text.contains("`exec --cwd`"), "{text}");
        assert!(text.contains("`agentlink guide <node>`"), "{text}");
        assert_eq!(
            text.matches(crate::SANDBOX_PATH_ESCAPE_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_mv_cross_device() {
        let value = tool_err("io: Invalid cross-device link (os error 18)");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::MV_CROSS_DEVICE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in ["copy_path", "remove_path", "run_command", "agentlink guide"] {
            assert!(text.contains(needle), "{needle} missing from {text}");
        }
    }

    #[test]
    fn tool_err_tips_mv_dest_permission() {
        let from = "/srv/app/build";
        let to = "/srv/releases/current";
        let decorated = crate::decorate_mv_dest_permission(
            "io: Permission denied (os error 13)",
            "builder",
            from,
            to,
        );
        assert_eq!(
            decorated
                .matches(crate::MV_DEST_PERMISSION_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );

        // The `move_path` arm owns the tip; `tool_err` must not add a second one.
        let value = tool_err(&decorated);
        assert_eq!(value["isError"], json!(true));
        assert_eq!(
            value["content"][0]["text"].as_str().unwrap(),
            decorated,
            "{decorated}"
        );

        // The flat chain must not learn this tip: every raw form passes through.
        for raw in [
            "io: Permission denied (os error 13)",
            "io: Operation not permitted (os error 1)",
            "io: Access is denied. (os error 5)",
            "io: Read-only file system (os error 30)",
            "io: The process cannot access the file because it is being used by another process. (os error 32)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{raw}");
            assert!(!text.contains("tip:"), "{text}");
            assert!(
                !text.contains(crate::MV_DEST_PERMISSION_TIP_MARKER),
                "{text}"
            );
        }

        // The mv decorators are mutually no-ops on each other's output.
        assert_eq!(
            crate::decorate_mv_dest_permission(&decorated, "builder", from, to),
            decorated
        );
        assert_eq!(
            crate::decorate_mv_target_not_empty(&decorated, from, to),
            decorated
        );
        assert_eq!(crate::decorate_mv_cross_device(&decorated), decorated);

        let not_empty = crate::decorate_mv_target_not_empty(
            "io: Directory not empty (os error 39)",
            from,
            to,
        );
        assert_eq!(
            crate::decorate_mv_dest_permission(&not_empty, "builder", from, to),
            not_empty
        );
        assert_eq!(
            crate::decorate_mv_target_not_empty(&not_empty, from, to),
            not_empty
        );

        let cross = crate::decorate_mv_cross_device("io: Invalid cross-device link (os error 18)");
        assert_eq!(
            crate::decorate_mv_dest_permission(&cross, "builder", from, to),
            cross
        );
        assert_eq!(crate::decorate_mv_cross_device(&cross), cross);

        // `tool_err` on the ENOTEMPTY and EXDEV fixtures still yields exactly
        // their own tips.
        let value = tool_err(&not_empty);
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::MV_TARGET_NOT_EMPTY_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(
            !text.contains(crate::MV_DEST_PERMISSION_TIP_MARKER),
            "{text}"
        );

        let value = tool_err(&cross);
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::MV_CROSS_DEVICE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(
            !text.contains(crate::MV_DEST_PERMISSION_TIP_MARKER),
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_remove_dest_permission() {
        let decorated = crate::decorate_remove_dest_permission(
            "io: Permission denied (os error 13)",
            "builder",
            "/srv/app/run.pid",
            false,
        );
        assert_eq!(
            decorated
                .matches(crate::REMOVE_DEST_PERMISSION_TIP_MARKER)
                .count(),
            1,
            "{decorated}"
        );
        assert!(
            decorated.contains(
                "Nothing was removed: `/srv/app/run.pid` and everything under it are unchanged."
            ),
            "{decorated}"
        );

        // The `remove_path` arm owns the tip; `tool_err` must not add a second one.
        let value = tool_err(&decorated);
        assert_eq!(value["isError"], json!(true));
        assert_eq!(
            value["content"][0]["text"].as_str().unwrap(),
            decorated,
            "{decorated}"
        );
        let text = value["content"][0]["text"].as_str().unwrap();
        for literal in ["{path}", "{node}", "{message}", "{outcome}"] {
            assert!(!text.contains(literal), "{literal} literal left: {text}");
        }

        // The flat chain must not learn this tip: every raw form passes through.
        for raw in [
            "io: Permission denied (os error 13)",
            "io: Operation not permitted (os error 1)",
            "io: Access is denied. (os error 5)",
            "io: Read-only file system (os error 30)",
            "io: The process cannot access the file because it is being used by another process. (os error 32)",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, raw, "{raw}");
            assert!(!text.contains("tip:"), "{text}");
            assert!(
                !text.contains(crate::REMOVE_DEST_PERMISSION_TIP_MARKER),
                "{text}"
            );
        }

        // The two remove decorators are mutually no-ops.
        let not_empty = crate::decorate_remove_not_empty("io: Directory not empty (os error 39)");
        assert_eq!(crate::decorate_remove_not_empty(&decorated), decorated);
        assert_eq!(
            crate::decorate_remove_dest_permission(
                &not_empty,
                "builder",
                "/srv/app/run.pid",
                false,
            ),
            not_empty
        );

        // `tool_err` on the ENOTEMPTY fixture still yields exactly that tip.
        let value = tool_err(&not_empty);
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::REMOVE_NOT_EMPTY_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(
            !text.contains(crate::REMOVE_DEST_PERMISSION_TIP_MARKER),
            "{text}"
        );
    }

    #[test]
    fn remove_not_empty_is_tipped_only_when_non_recursive() {
        let raw = "io: Directory not empty (os error 39)";
        let tipped = crate::decorate_remove_not_empty(raw);
        assert_eq!(
            tipped.matches(crate::REMOVE_NOT_EMPTY_TIP_MARKER).count(),
            1,
            "{tipped}"
        );

        // Mirrors the `remove_path` arm's error mapping.
        let map = |recursive: bool, err: &str| -> String {
            if recursive {
                err.to_string()
            } else {
                crate::decorate_remove_not_empty(err)
            }
        };
        assert_eq!(map(true, raw), raw);
        assert_eq!(map(false, raw), tipped);
    }

    #[test]
    fn move_path_target_not_empty_gets_the_tip() {
        let raw = "io: Directory not empty (os error 39)";
        let tipped = crate::decorate_mv_target_not_empty(
            raw,
            "/srv/app/build",
            "/srv/releases/current",
        );
        assert_eq!(
            tipped.matches(crate::MV_TARGET_NOT_EMPTY_TIP_MARKER).count(),
            1,
            "{tipped}"
        );
        for needle in ["move_path", "recursive: true", "agentlink guide <node>"] {
            assert!(tipped.contains(needle), "{needle} missing from {tipped}");
        }

        // `tool_err` does not re-decorate: the `move_path` arm owns the tip.
        let value = tool_err(&tipped);
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::MV_TARGET_NOT_EMPTY_TIP_MARKER).count(),
            1,
            "{text}"
        );

        let plain = tool_err(raw);
        let plain_text = plain["content"][0]["text"].as_str().unwrap();
        assert!(
            !plain_text.contains(crate::MV_TARGET_NOT_EMPTY_TIP_MARKER),
            "{plain_text}"
        );
    }

    #[test]
    fn mkdir_already_exists_is_tipped_at_the_mkdir_arm() {
        let raw = "mkdir `/srv/app/releases` already exists as a directory";
        let tipped = crate::decorate_mkdir_already_exists(raw, "/srv/app/releases");
        assert_eq!(
            tipped.matches(crate::MKDIR_ALREADY_EXISTS_TIP_MARKER).count(),
            1,
            "{tipped}"
        );
        for needle in ["`/srv/app/releases`", "`parents: false`", "`parents: true`"] {
            assert!(tipped.contains(needle), "{needle} missing from {tipped}");
        }

        // `tool_err` does not re-decorate: the `mkdir` arm owns the tip.
        let value = tool_err(&tipped);
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text.matches(crate::MKDIR_ALREADY_EXISTS_TIP_MARKER).count(),
            1,
            "{text}"
        );

        let plain = tool_err(raw);
        let plain_text = plain["content"][0]["text"].as_str().unwrap();
        assert!(
            !plain_text.contains(crate::MKDIR_ALREADY_EXISTS_TIP_MARKER),
            "{plain_text}"
        );
    }

    #[test]
    fn mkdir_dest_permission_is_tipped_at_the_mkdir_arm() {
        let node = "builder";
        let path = "/srv/app/releases/v2";
        let decorated = crate::decorate_mkdir_dest_permission(
            "io: Permission denied (os error 13)",
            node,
            path,
            false,
        );

        // The arm decoration must survive the flat `tool_err` chain unchanged.
        let value = tool_err(&decorated);
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, decorated);
        assert_eq!(
            text.matches(crate::MKDIR_DEST_PERMISSION_TIP_MARKER).count(),
            1,
            "{text}"
        );

        // The flat chain must not learn the pathless permission forms.
        for raw in crate::MKDIR_DEST_PERMISSION_FORMS {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = value["content"][0]["text"].as_str().unwrap();
            assert_eq!(text, *raw);
            assert!(!text.contains("tip:"), "{text}");
            assert!(
                !text.contains(crate::MKDIR_DEST_PERMISSION_TIP_MARKER),
                "{text}"
            );
        }

        // Sibling mkdir decorators are mutually no-ops on each other's output.
        let eexist = "mkdir `/srv/app/releases` already exists as a directory";
        let already = crate::decorate_mkdir_already_exists(eexist, path);
        assert_eq!(
            crate::decorate_mkdir_dest_permission(&already, node, path, false),
            already
        );
        assert_eq!(crate::decorate_mkdir_already_exists(&decorated, path), decorated);

        let not_dir = "mkdir `/srv/app/releases` exists but is not a directory";
        let target = crate::decorate_mkdir_target_not_dir(not_dir);
        assert_eq!(
            crate::decorate_mkdir_dest_permission(&target, node, path, false),
            target
        );
        assert_eq!(crate::decorate_mkdir_target_not_dir(&decorated), decorated);

        let enoent = "io: No such file or directory (os error 2)";
        let missing = crate::decorate_mkdir_missing_parent(enoent, path, false);
        assert_eq!(
            crate::decorate_mkdir_dest_permission(&missing, node, path, false),
            missing
        );
        assert_eq!(
            crate::decorate_mkdir_missing_parent(&decorated, path, false),
            decorated
        );
        assert_eq!(
            crate::decorate_mkdir_missing_parent(&decorated, path, true),
            decorated
        );

        // The flat chain still owns only the ENOTDIR tip; the mkdir arm owns
        // the EEXIST and ENOENT tips, so `tool_err` leaves them unchanged.
        let not_dir_text = tool_err(not_dir)["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            not_dir_text
                .matches(crate::MKDIR_TARGET_NOT_DIR_TIP_MARKER)
                .count(),
            1,
            "{not_dir_text}"
        );
        assert_eq!(
            tool_err(eexist)["content"][0]["text"].as_str().unwrap(),
            eexist
        );
        assert_eq!(
            tool_err(enoent)["content"][0]["text"].as_str().unwrap(),
            enoent
        );
    }

    #[test]
    fn mkdir_missing_parent_is_tipped_at_the_mkdir_arm() {
        let raw = "io: No such file or directory (os error 2)";
        let tipped = crate::decorate_mkdir_missing_parent(raw, "/srv/app/releases", false);
        assert_eq!(
            tipped.matches(crate::MKDIR_MISSING_PARENT_TIP_MARKER).count(),
            1,
            "{tipped}"
        );
        for needle in [
            "/srv/app/releases",
            "`parents: true`",
            "`parents: false`",
            "`create_dir`",
            "stat_path",
            "list_dir",
            "agentlink guide <node>",
        ] {
            assert!(tipped.contains(needle), "{needle} missing from {tipped}");
        }

        // `parents: true` ENOENT is a different failure (dangling symlink
        // component), not this tip.
        assert_eq!(
            crate::decorate_mkdir_missing_parent(raw, "/srv/app/releases", true),
            raw
        );

        // `tool_err` must not learn this shape: stat_path/remove share it.
        let value = tool_err(raw);
        let text = value["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, raw);
        assert!(!text.contains("tip:"), "{text}");
    }

    #[test]
    fn tool_err_leaves_other_bg_errors_alone() {
        let value = tool_err("not found: background process 7");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains(crate::BG_LIMIT_TIP_MARKER), "{text}");
        let value = tool_err("this node already has 32 background processes");
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            !text.contains(crate::BG_PROCESS_NOT_FOUND_TIP_MARKER),
            "{text}"
        );
    }

    fn err_text(value: &Value) -> &str {
        value["content"][0]["text"].as_str().unwrap()
    }

    #[test]
    fn tool_err_tips_bg_process_not_found() {
        let value = tool_err("not found: background process d5c86dab");
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(
            text.starts_with(&format!(
                "not found: background process d5c86dab. tip: {} — ",
                crate::BG_PROCESS_NOT_FOUND_TIP_MARKER
            )),
            "{text}"
        );
        assert_eq!(
            text.matches(crate::BG_PROCESS_NOT_FOUND_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("process_list"), "{text}");
        assert!(text.contains("process_start"), "{text}");
        assert_eq!(crate::decorate_bg_process_not_found(text), text);
    }

    #[test]
    fn tool_err_tips_numeric_stale_pid() {
        let value = tool_err("not found: background process 4242");
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(
            text.contains(crate::BG_PROCESS_NOT_FOUND_TIP_MARKER),
            "{text}"
        );
        assert_eq!(
            text.matches(crate::BG_PROCESS_NOT_FOUND_TIP_MARKER).count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_tips_wrapped_bg_not_found() {
        let value = tool_err("bg output box: not found: background process d5c86dab");
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(
            text.starts_with("bg output box: not found: background process d5c86dab. tip:"),
            "{text}"
        );
        assert_eq!(
            text.matches(crate::BG_PROCESS_NOT_FOUND_TIP_MARKER).count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn tool_err_leaves_other_not_found_alone() {
        // Some of these carry a sibling tip (watch/node/path), so only pin that
        // this decorator does not claim them.
        for raw in [
            "not found: watch 7a3f0c2e",
            "not found: node 'foo'",
            "not found: user 'foo'",
            "not found: client 'abc'",
            "not found: /srv/app/src",
            "not found: background process ",
            "not found: background process nothex",
            "",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::BG_PROCESS_NOT_FOUND_TIP_MARKER),
                "{text}"
            );
        }
        for raw in [
            "not found: user 'foo'",
            "not found: client 'abc'",
            "not found: background process ",
            "not found: background process nothex",
            "",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert_eq!(text, raw, "{raw}");
            assert!(!text.contains("tip:"), "{text}");
        }
    }

    #[test]
    fn tool_err_tips_node_not_found() {
        let raw = "not found: node 'boxx'";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{text}");
        assert_eq!(
            text.matches(crate::NODE_NOT_FOUND_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("tip: no node named 'boxx'"), "{text}");
        assert!(text.contains("`agentlink nodes`"), "{text}");
        assert!(text.contains("copy the exact id/name"), "{text}");
        assert!(text.contains("use the id when names collide"), "{text}");
        assert_eq!(text.matches(". tip:").count(), 1, "{text}");
        assert_eq!(crate::decorate_node_not_found(text), text);

        let value = tool_err("exec hostname: not found: node 'example-stale'");
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert_eq!(
            text.matches(crate::NODE_NOT_FOUND_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(
            text.contains("tip: no node named 'example-stale'"),
            "{text}"
        );
    }

    #[test]
    fn tool_err_node_not_found_does_not_shadow_siblings() {
        for raw in [
            "not found: node '*' (looks like a path or glob; put the machine name first — see `agentlink nodes`)",
            "not found: node ''",
            "not found: user 'foo'",
            "not found: client 'abc'",
            "not found: /srv/app/src",
            "io: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert_eq!(text, raw, "{raw}");
            assert!(!text.contains(crate::NODE_NOT_FOUND_TIP_MARKER), "{text}");
        }
        // `missing `node`` is an ordinary MCP missing argument now; it gets the
        // generic argument tip but must not be mistaken for node_not_found.
        let value = tool_err("missing `node`");
        let text = err_text(&value);
        assert!(text.contains(crate::MISSING_ARG_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::NODE_NOT_FOUND_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::NODE_OFFLINE_TIP_MARKER), "{text}");
        let value = tool_err("not found: node 'boxx'");
        let text = err_text(&value);
        for decorated in [
            crate::decorate_path_not_found(text),
            crate::decorate_node_offline(text),
            crate::decorate_bg_process_not_found(text),
        ] {
            assert_eq!(decorated, text);
        }
    }

    #[test]
    fn tool_err_tips_ambiguous_node() {
        for raw in [
            "ambiguous node name 'devbox'",
            "ls: ambiguous node name 'devbox'",
            "exec hostname: ambiguous node name 'devbox'",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = err_text(&value);
            assert!(text.starts_with(raw), "{text}");
            assert_eq!(
                text.matches(crate::AMBIGUOUS_NODE_TIP_MARKER).count(),
                1,
                "{text}"
            );
            assert!(
                text.contains("more than one paired machine is named 'devbox'"),
                "{text}"
            );
            assert!(text.contains("`agentlink nodes --json`"), "{text}");
            assert!(text.contains("full `id`"), "{text}");
            assert_eq!(text.matches(". tip:").count(), 1, "{text}");
            assert_eq!(crate::decorate_ambiguous_node(text), text, "{raw}");
        }
    }

    #[test]
    fn tool_err_ambiguous_node_does_not_shadow_siblings() {
        for raw in [
            "not found: node 'boxx'",
            "node offline: probe",
            "authentication failed: session expired or revoked",
            "authentication failed: grant has expired",
            "extension is not allowed on this node (exec)",
            "io: No such file or directory (os error 2)",
            "ambiguous node name 'devbox' (see `agentlink nodes --json` for full ids)",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::AMBIGUOUS_NODE_TIP_MARKER),
                "{raw} => {text}"
            );
        }

        let value = tool_err("not found: node 'boxx'");
        let text = err_text(&value);
        assert!(text.contains(crate::NODE_NOT_FOUND_TIP_MARKER), "{text}");
        assert_eq!(crate::decorate_ambiguous_node(text), text);

        let value = tool_err("node offline: probe");
        let text = err_text(&value);
        assert!(text.contains(crate::NODE_OFFLINE_TIP_MARKER), "{text}");

        let value = tool_err("authentication failed: session expired or revoked");
        let text = err_text(&value);
        assert!(text.contains(crate::SESSION_AUTH_TIP_MARKER), "{text}");

        let value = tool_err("authentication failed: grant has expired");
        let text = err_text(&value);
        assert!(text.contains(crate::GRANT_EXPIRED_TIP_MARKER), "{text}");
    }

    #[test]
    fn tool_err_tips_ui_element_stale() {
        let value = tool_err("element id 'ax|nope' is not an AT-SPI id. Call get_ui_tree again.");
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(
            text.starts_with("element id 'ax|nope' is not an AT-SPI id"),
            "{text}"
        );
        assert_eq!(
            text.matches(crate::UI_ELEMENT_STALE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("snapshot-scoped"), "{text}");
        assert!(text.contains("`agentlink ui-tree <node>`"), "{text}");
        assert!(text.contains("`agentlink ui-act <node> <id> --op click`"), "{text}");
        assert_eq!(text.matches(". tip:").count(), 1, "{text}");
        assert_eq!(crate::decorate_ui_element_stale(text), text);

        let value = tool_err("element id 'x' is not in the last tree");
        let text = err_text(&value);
        assert_eq!(
            text.matches(crate::UI_ELEMENT_STALE_TIP_MARKER).count(),
            1,
            "{text}"
        );

        let value = tool_err("element id 'stale|99' is not a UI Automation id");
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(
            text.starts_with("element id 'stale|99' is not a UI Automation id"),
            "{text}"
        );
        assert_eq!(
            text.matches(crate::UI_ELEMENT_STALE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("`agentlink ui-tree <node>`"), "{text}");
        assert!(text.contains("`agentlink ui-act <node> <id> --op click`"), "{text}");
        assert_eq!(text.matches(". tip:").count(), 1, "{text}");
        assert_eq!(crate::decorate_ui_element_stale(text), text);
    }

    #[test]
    fn tool_err_ui_element_stale_does_not_shadow_siblings() {
        for raw in [
            "action 'focus' is not supported on this element",
            "ls: path `/tmp/x` does not exist",
            "node offline: probe",
            "not found: node 'boxx'",
            "io: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::UI_ELEMENT_STALE_TIP_MARKER),
                "{raw} => {text}"
            );
        }
        let value = tool_err("element id 'ax|nope' is not an AT-SPI id. Call get_ui_tree again.");
        let text = err_text(&value);
        for decorated in [
            crate::decorate_ls_missing(text),
            crate::decorate_node_offline(text),
            crate::decorate_node_not_found(text),
        ] {
            assert_eq!(decorated, text);
        }

        let value = tool_err("element id 'stale|99' is not a UI Automation id");
        let text = err_text(&value);
        assert!(text.contains(crate::UI_ELEMENT_STALE_TIP_MARKER), "{text}");
        for decorated in [
            crate::decorate_ls_missing(text),
            crate::decorate_node_offline(text),
            crate::decorate_node_not_found(text),
        ] {
            assert_eq!(decorated, text);
        }
    }

    #[test]
    fn tool_err_tips_grant_capability() {
        let raw = "extension is not allowed on this node (exec)";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{text}");
        assert_eq!(
            text.matches(crate::GRANT_CAPABILITY_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("`agentlink grant list`"), "{text}");
        assert!(
            text.contains("`agentlink grant ensure --node <name> --policy exec`"),
            "{text}"
        );
        assert!(text.contains("`agentlink guide <name>`"), "{text}");
        assert_eq!(text.matches("; tip:").count(), 1, "{text}");
        assert_eq!(crate::decorate_grant_capability(text), text);

        let value = tool_err("permission denied: write is not allowed on this node");
        let text = err_text(&value);
        assert_eq!(
            text.matches(crate::GRANT_CAPABILITY_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("--policy write"), "{text}");

        let value = tool_err("authentication failed: grant has expired");
        let text = err_text(&value);
        assert_eq!(
            text.matches(crate::GRANT_EXPIRED_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(
            text.contains("`agentlink grant refresh --node <name>`"),
            "{text}"
        );

        let value = tool_err("authentication failed: grant was revoked (jti 3f2a1b4c)");
        let text = err_text(&value);
        assert_eq!(
            text.matches(crate::GRANT_REVOKED_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(
            text.contains("`agentlink grant issue --node <name>`"),
            "{text}"
        );

        let value = tool_err("signed grant required (owner keys configured)");
        let text = err_text(&value);
        assert!(text.contains("tip: also `agentlink grant list`"), "{text}");
        assert_eq!(crate::decorate_grant_capability(text), text);
    }

    #[test]
    fn tool_err_tips_grant_expired_at_unix() {
        let raw = "grant expired at unix 1793780563; run `agentlink grant refresh --node 762e3a20` (or `agentlink grant issue --node 762e3a20` to change policy)";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{text}");
        assert_eq!(
            text.matches(crate::GRANT_EXPIRED_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(
            text.contains("`agentlink grant refresh --node <name>`"),
            "{text}"
        );
        assert!(text.contains("`agentlink grant list`"), "{text}");
        assert!(text.contains("`agentlink guide <name>`"), "{text}");
        assert_eq!(text.matches("; tip:").count(), 1, "{text}");
        assert_eq!(crate::decorate_grant_capability(text), text);

        for sibling in [
            "grant is not valid until unix 1793780563; check the clock",
            "grant is for node other, not probe; run `agentlink grant issue --node probe`",
            "grant is bound to grantee alice, but this client identity is bob",
            "missing `action`",
            "io: No such file or directory (os error 2)",
            "io: Permission denied (os error 13)",
        ] {
            let value = tool_err(sibling);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::GRANT_EXPIRED_TIP_MARKER),
                "{sibling} => {text}"
            );
            assert!(!text.contains("; tip:"), "{sibling} => {text}");
        }
    }

    #[test]
    fn tool_err_grant_capability_does_not_shadow_siblings() {
        for raw in [
            "action 'focus' is not supported on this element",
            "missing `action`",
            "node offline: probe",
            "not found: node 'boxx'",
            "ls: path `/no/such/dir` does not exist",
            "io: Permission denied (os error 13)",
            "Permission denied (os error 13)",
            "permission denied: exec",
            "io: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::GRANT_CAPABILITY_TIP_MARKER),
                "{raw} => {text}"
            );
        }

        let value = tool_err("node offline: probe");
        let text = err_text(&value);
        assert!(text.contains(crate::NODE_OFFLINE_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::GRANT_CAPABILITY_TIP_MARKER), "{text}");

        let value = tool_err("not found: node 'boxx'");
        let text = err_text(&value);
        assert!(text.contains(crate::NODE_NOT_FOUND_TIP_MARKER), "{text}");
        assert_eq!(crate::decorate_grant_capability(text), text);

        let value = tool_err("ls: path `/no/such/dir` does not exist");
        let text = err_text(&value);
        assert!(text.contains(crate::LS_MISSING_TIP_MARKER), "{text}");
        assert_eq!(crate::decorate_grant_capability(text), text);

        let raw = "extension is not allowed on this node (exec)";
        let value = tool_err(raw);
        let text = err_text(&value);
        for decorated in [
            crate::decorate_node_not_found(text),
            crate::decorate_node_offline(text),
            crate::decorate_ls_missing(text),
            crate::decorate_ui_element_stale(text),
        ] {
            assert_eq!(decorated, text);
        }
    }

    #[test]
    fn tool_err_tips_session_auth() {
        for raw in [
            "authentication failed: session expired or revoked",
            "authentication failed: session expired",
            "authentication failed: session revoked",
            "authentication failed: refresh token is invalid or revoked",
            "authentication failed: client is revoked",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = err_text(&value);
            assert!(text.starts_with(raw), "{text}");
            assert_eq!(
                text.matches(crate::SESSION_AUTH_TIP_MARKER).count(),
                1,
                "{text}"
            );
            assert!(
                text.contains("`agentlink login --user <name>`"),
                "{text}"
            );
            assert!(text.contains("`--totp <code>`"), "{text}");
            assert!(text.contains("`agentlink devices`"), "{text}");
            assert_eq!(crate::decorate_session_auth(text), text, "{raw}");
        }
    }

    #[test]
    fn tool_err_session_auth_does_not_shadow_siblings() {
        let value = tool_err("authentication failed: grant has expired");
        let text = err_text(&value);
        assert!(text.contains(crate::GRANT_EXPIRED_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::SESSION_AUTH_TIP_MARKER), "{text}");

        let value = tool_err("authentication failed: grant was revoked (jti 3f2a1b4c)");
        let text = err_text(&value);
        assert!(text.contains(crate::GRANT_REVOKED_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::SESSION_AUTH_TIP_MARKER), "{text}");

        let value = tool_err("extension is not allowed on this node (exec)");
        let text = err_text(&value);
        assert!(text.contains(crate::GRANT_CAPABILITY_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::SESSION_AUTH_TIP_MARKER), "{text}");

        let value = tool_err("node offline: probe");
        let text = err_text(&value);
        assert!(text.contains(crate::NODE_OFFLINE_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::SESSION_AUTH_TIP_MARKER), "{text}");

        let value = tool_err("not found: node 'boxx'");
        let text = err_text(&value);
        assert!(text.contains(crate::NODE_NOT_FOUND_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::SESSION_AUTH_TIP_MARKER), "{text}");

        for raw in [
            "action 'focus' is not supported on this element",
            "missing `action`",
            "ls: path `/no/such/dir` does not exist",
            "io: Permission denied (os error 13)",
            "io: No such file or directory (os error 2)",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::SESSION_AUTH_TIP_MARKER),
                "{raw} => {text}"
            );
        }
    }

    #[test]
    fn tool_err_tips_ls_missing() {
        let value = tool_err("ls: path `/no/such/dir` does not exist");
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with("ls: path `/no/such/dir` does not exist"), "{text}");
        assert_eq!(
            text.matches(crate::LS_MISSING_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("is on the node, not a machine name"), "{text}");
        assert!(text.contains("`agentlink find <node> <basename>`"), "{text}");
        assert!(text.contains("`agentlink ls <node> <parent>`"), "{text}");
        assert_eq!(text.matches(". tip:").count(), 1, "{text}");
        assert_eq!(crate::decorate_ls_missing(text), text);

        let value = tool_err("ls /srv: ls: path `/srv/app/src.txt` does not exist");
        let text = err_text(&value);
        assert_eq!(
            text.matches(crate::LS_MISSING_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("'/srv/app/src.txt'"), "{text}");
    }

    #[test]
    fn tool_err_ls_missing_does_not_shadow_siblings() {
        for raw in [
            "not found: /srv/app/src",
            "rm: path `/tmp/x` does not exist",
            "mv source `/tmp/x` does not exist",
            "io: No such file or directory (os error 2)",
            "node offline: probe",
            "not found: node 'boxx'",
            "ls: path  does not exist",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::LS_MISSING_TIP_MARKER),
                "{raw} => {text}"
            );
        }
        let value = tool_err("ls: path `/no/such/dir` does not exist");
        let text = err_text(&value);
        for decorated in [
            crate::decorate_path_not_found(text),
            crate::decorate_node_offline(text),
            crate::decorate_node_not_found(text),
            crate::decorate_bg_process_not_found(text),
        ] {
            assert_eq!(decorated, text);
        }
    }

    #[test]
    fn tool_err_tips_mv_rm_missing() {
        for raw in [
            "mv source `/tmp/nope-src` does not exist",
            "rm: path `/tmp/nope-rm` does not exist",
        ] {
            let value = tool_err(raw);
            assert_eq!(value["isError"], json!(true));
            let text = err_text(&value);
            assert!(text.starts_with(raw), "{text}");
            assert_eq!(
                text.matches(crate::MV_RM_MISSING_TIP_MARKER).count(),
                1,
                "{text}"
            );
            assert!(text.contains("`agentlink find <node> <basename>`"), "{text}");
            assert!(text.contains("`agentlink ls <node> <parent>`"), "{text}");
            assert!(text.contains("MCP `search_files`"), "{text}");
            assert!(text.contains("MCP `list_dir`"), "{text}");
            assert_eq!(text.matches(". tip:").count(), 1, "{text}");
            assert_eq!(crate::decorate_mv_rm_missing(text), text);
        }
    }

    #[test]
    fn tool_err_mv_rm_missing_does_not_shadow_siblings() {
        for raw in [
            "ls: path `/tmp/x` does not exist",
            "io: No such file or directory (os error 2)",
            "node offline: probe",
            "not found: node 'boxx'",
            "extension is not allowed on this node (exec)",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::MV_RM_MISSING_TIP_MARKER),
                "{raw} => {text}"
            );
        }

        // The ls-missing sibling keeps only its own tip.
        let value = tool_err("ls: path `/no/such/dir` does not exist");
        let text = err_text(&value);
        assert!(text.contains(crate::LS_MISSING_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::MV_RM_MISSING_TIP_MARKER), "{text}");
        for decorated in [
            crate::decorate_ls_missing(text),
            crate::decorate_node_offline(text),
        ] {
            assert_eq!(decorated, text);
        }
    }

    #[test]
    fn tool_err_tips_node_offline() {
        let value = tool_err("node offline: probe");
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with("node offline: probe"), "{text}");
        assert_eq!(
            text.matches(crate::NODE_OFFLINE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(
            text.contains(
                "tip: offline: probe — wake the machine or check the agentlink-node service; then agentlink nodes"
            ),
            "{text}"
        );
        assert_eq!(text.matches(". tip:").count(), 1, "{text}");
        assert_eq!(crate::decorate_node_offline(text), text);

        let value = tool_err("exec hostname: node offline: example-stale");
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert_eq!(
            text.matches(crate::NODE_OFFLINE_TIP_MARKER).count(),
            1,
            "{text}"
        );
        assert!(text.contains("tip: offline: example-stale"), "{text}");
    }

    #[test]
    fn tool_err_node_offline_does_not_shadow_siblings() {
        for raw in [
            "not found: /srv/app/src",
            "io: No such file or directory (os error 2)",
            "node offline: ",
            "offline: probe",
            "permission denied: exec",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert_eq!(text, raw, "{raw}");
            assert!(!text.contains(crate::NODE_OFFLINE_TIP_MARKER), "{text}");
        }
        // `missing `node`` now carries the generic missing-argument tip; it is
        // neither node_not_found nor node_offline.
        let value = tool_err("missing `node`");
        let text = err_text(&value);
        assert!(text.contains(crate::MISSING_ARG_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::NODE_OFFLINE_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::NODE_NOT_FOUND_TIP_MARKER), "{text}");
        let tipped_value = tool_err("not found: node 'boxx'");
        let tipped = err_text(&tipped_value);
        assert!(tipped.contains(crate::NODE_NOT_FOUND_TIP_MARKER), "{tipped}");
        assert!(!tipped.contains(crate::NODE_OFFLINE_TIP_MARKER), "{tipped}");

        let value = tool_err("node offline: probe");
        let text = err_text(&value);
        for decorated in [
            crate::decorate_node_not_found(text),
            crate::decorate_path_not_found(text),
            crate::decorate_bg_process_not_found(text),
        ] {
            assert_eq!(decorated, text);
        }
    }

    #[test]
    fn tool_err_tips_connection_closed() {
        let raw = "connection closed";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::CONNECTION_CLOSED_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "cleared its cached terminal sessions",
            "reconnected, and retried once",
            "outcome is unknown",
            "do not assume nothing ran",
            "inspect the relevant files or processes",
            "`agentlink nodes`",
            "`terminal_open`",
            "new `session_id`",
            "transport failure",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::NODE_OFFLINE_TIP_MARKER), "{text}");
        assert_eq!(tool_err(text), value);
    }

    #[test]
    fn tool_err_connection_closed_does_not_shadow_siblings() {
        let value = tool_err("node offline: box");
        let text = err_text(&value);
        assert!(text.contains(crate::NODE_OFFLINE_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::CONNECTION_CLOSED_TIP_MARKER), "{text}");

        for raw in [
            "exec hostname: connection closed",
            "connection closed by peer",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::CONNECTION_CLOSED_TIP_MARKER),
                "{raw} -> {text}"
            );
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_insecure_relay_url() {
        let raw = "relay url must use wss:// (TLS is required)";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::RELAY_URL_TLS_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "`ws://` or `http://`",
            "not upgraded silently",
            "`--relay wss://relay.example.com`",
            "`AGENTLINK_RELAY=wss://relay.example.com`",
            "`https://` is accepted as an alias",
            "port 443",
            "explicit port is preserved",
            "defaults to port 7443",
            "before any relay connection or node operation",
            "Certificate, hostname, authentication, and connection-refused",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::CONNECTION_CLOSED_TIP_MARKER), "{text}");
        assert_eq!(tool_err(text), value);
    }

    #[test]
    fn tool_err_insecure_relay_url_does_not_shadow_siblings() {
        let value = tool_err("connection closed");
        let text = err_text(&value);
        assert!(text.contains(crate::CONNECTION_CLOSED_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::RELAY_URL_TLS_TIP_MARKER), "{text}");

        // Other unsupported schemes now have their own tip, not the ws/http
        // TLS-required tip guarded by this test.
        let value = tool_err("relay url scheme `ftp` is not supported; use wss://");
        let text = err_text(&value);
        assert!(
            text.contains(crate::UNSUPPORTED_RELAY_SCHEME_TIP_MARKER),
            "{text}"
        );
        assert!(!text.contains(crate::RELAY_URL_TLS_TIP_MARKER), "{text}");

        for raw in [
            "connect: relay url must use wss:// (TLS is required)",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "tls: tls handshake eof",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::RELAY_URL_TLS_TIP_MARKER),
                "{raw} -> {text}"
            );
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_unsupported_relay_scheme() {
        let raw = "relay url scheme `ftp` is not supported; use wss://";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::UNSUPPORTED_RELAY_SCHEME_TIP_MARKER)
                .count(),
            1,
            "{text}"
        );
        for needle in [
            "`--relay wss://relay.example.com`",
            "`AGENTLINK_RELAY=wss://relay.example.com`",
            "`https://` is accepted as an alias",
            "`wss://host[:port]`",
            "port 443 by default",
            "port 7443 by default",
            "explicit port is preserved",
            "before any relay connection or node operation",
            "separate TLS-required error",
            "certificate, hostname, authentication, and",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::RELAY_URL_TLS_TIP_MARKER), "{text}");
        assert_eq!(tool_err(text), value);
    }

    #[test]
    fn tool_err_unsupported_relay_scheme_does_not_shadow_siblings() {
        let value = tool_err("relay url must use wss:// (TLS is required)");
        let text = err_text(&value);
        assert!(text.contains(crate::RELAY_URL_TLS_TIP_MARKER), "{text}");
        assert!(
            !text.contains(crate::UNSUPPORTED_RELAY_SCHEME_TIP_MARKER),
            "{text}"
        );

        for raw in [
            "connect: relay url scheme `ftp` is not supported; use wss://",
            "relay url scheme `` is not supported; use wss://",
            "relay url: relative URL without a base",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "tls: tls handshake eof",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::UNSUPPORTED_RELAY_SCHEME_TIP_MARKER),
                "{raw} -> {text}"
            );
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_relay_port_zero() {
        let raw = "relay port must not be 0";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::RELAY_PORT_ZERO_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "port 0 cannot identify a remote relay listener",
            "Omit `:0`",
            "`--relay wss://relay.example.com`",
            "port 443",
            "bare `relay.example.com` defaults to port 7443",
            "`https://` remains an accepted",
            "`--relay wss://relay.example.com:7443`",
            "1 through 65535",
            "`relay url: invalid port number`",
            "before any relay connection or node operation",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::RELAY_URL_TLS_TIP_MARKER), "{text}");
        assert!(
            !text.contains(crate::UNSUPPORTED_RELAY_SCHEME_TIP_MARKER),
            "{text}"
        );
        assert_eq!(tool_err(text), value);
    }

    #[test]
    fn tool_err_relay_port_zero_does_not_shadow_siblings() {
        for (raw, marker) in [
            (
                "relay url must use wss:// (TLS is required)",
                crate::RELAY_URL_TLS_TIP_MARKER,
            ),
            (
                "relay url scheme `ftp` is not supported; use wss://",
                crate::UNSUPPORTED_RELAY_SCHEME_TIP_MARKER,
            ),
            (
                "relay url: invalid port number",
                crate::RELAY_INVALID_PORT_TIP_MARKER,
            ),
            (
                "relay url is missing a host",
                crate::RELAY_MISSING_HOST_TIP_MARKER,
            ),
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(text.contains(marker), "{raw} -> {text}");
            assert!(!text.contains(crate::RELAY_PORT_ZERO_TIP_MARKER), "{text}");
        }

        for raw in [
            "connect: relay port must not be 0",
            "relay port must not be 0 extra",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "tls: tls handshake eof",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::RELAY_PORT_ZERO_TIP_MARKER),
                "{raw} -> {text}"
            );
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_relay_invalid_port() {
        let raw = "relay url: invalid port number";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::RELAY_INVALID_PORT_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "decimal digits from 1 through 65535",
            "`:abc`",
            "`:65536`",
            "Remove the invalid `:port`",
            "`--relay wss://relay.example.com`",
            "port 443",
            "`--relay wss://relay.example.com:7443`",
            "bare `relay.example.com` defaults to port 7443",
            "`relay port must not be 0`",
            "before any relay connection or node operation",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::RELAY_PORT_ZERO_TIP_MARKER), "{text}");
        assert_eq!(tool_err(text), value);
    }

    #[test]
    fn tool_err_relay_invalid_port_does_not_shadow_siblings() {
        for (raw, marker) in [
            (
                "relay port must not be 0",
                crate::RELAY_PORT_ZERO_TIP_MARKER,
            ),
            (
                "relay url must use wss:// (TLS is required)",
                crate::RELAY_URL_TLS_TIP_MARKER,
            ),
            (
                "relay url scheme `ftp` is not supported; use wss://",
                crate::UNSUPPORTED_RELAY_SCHEME_TIP_MARKER,
            ),
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(text.contains(marker), "{raw} -> {text}");
            assert!(!text.contains(crate::RELAY_INVALID_PORT_TIP_MARKER), "{text}");
        }

        for raw in [
            "connect: relay url: invalid port number",
            "relay url: invalid port number extra",
            "relay url: relative URL without a base",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "tls: tls handshake eof",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::RELAY_INVALID_PORT_TIP_MARKER),
                "{raw} -> {text}"
            );
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_relay_empty_host() {
        let raw = "relay url: empty host";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::RELAY_EMPTY_HOST_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "write a DNS name or IP address after `wss://`",
            "scheme, port, or path alone is not enough",
            "`--relay wss://relay.example.com`",
            "`AGENTLINK_RELAY=wss://relay.example.com`",
            "port 443",
            "`--relay wss://relay.example.com:7443`",
            "`https://` is an accepted",
            "bare `relay.example.com` defaults to port 7443",
            "before any relay connection or node operation",
            "Empty URLs, missing-host validation, scheme/port",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::RELAY_INVALID_PORT_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::RELAY_PORT_ZERO_TIP_MARKER), "{text}");
        assert_eq!(tool_err(text), value);
    }

    #[test]
    fn tool_err_relay_empty_host_does_not_shadow_siblings() {
        for (raw, marker) in [
            (
                "relay url must use wss:// (TLS is required)",
                crate::RELAY_URL_TLS_TIP_MARKER,
            ),
            (
                "relay url scheme `ftp` is not supported; use wss://",
                crate::UNSUPPORTED_RELAY_SCHEME_TIP_MARKER,
            ),
            (
                "relay port must not be 0",
                crate::RELAY_PORT_ZERO_TIP_MARKER,
            ),
            (
                "relay url: invalid port number",
                crate::RELAY_INVALID_PORT_TIP_MARKER,
            ),
            (
                "relay url is missing a host",
                crate::RELAY_MISSING_HOST_TIP_MARKER,
            ),
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(text.contains(marker), "{raw} -> {text}");
            assert!(!text.contains(crate::RELAY_EMPTY_HOST_TIP_MARKER), "{text}");
        }

        for raw in [
            "connect: relay url: empty host",
            "relay url: empty host extra",
            "relay url is empty",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "tls: tls handshake eof",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::RELAY_EMPTY_HOST_TIP_MARKER),
                "{raw} -> {text}"
            );
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_relay_missing_host() {
        let raw = "relay url is missing a host";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::RELAY_MISSING_HOST_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "a value such as `/` supplies a path",
            "no DNS name or IP address",
            "`--relay wss://relay.example.com`",
            "`AGENTLINK_RELAY=wss://relay.example.com`",
            "port 443",
            "`--relay wss://relay.example.com:7443`",
            "`https://` is an accepted",
            "bare `relay.example.com` defaults to port 7443",
            "before any relay connection or node operation",
            "`relay url: empty host` parse error",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::RELAY_EMPTY_HOST_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::RELAY_INVALID_PORT_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::RELAY_PORT_ZERO_TIP_MARKER), "{text}");
        assert_eq!(tool_err(text), value);
    }

    #[test]
    fn tool_err_relay_missing_host_does_not_shadow_siblings() {
        for (raw, marker) in [
            (
                "relay url must use wss:// (TLS is required)",
                crate::RELAY_URL_TLS_TIP_MARKER,
            ),
            (
                "relay url scheme `ftp` is not supported; use wss://",
                crate::UNSUPPORTED_RELAY_SCHEME_TIP_MARKER,
            ),
            (
                "relay port must not be 0",
                crate::RELAY_PORT_ZERO_TIP_MARKER,
            ),
            (
                "relay url: invalid port number",
                crate::RELAY_INVALID_PORT_TIP_MARKER,
            ),
            (
                "relay url: empty host",
                crate::RELAY_EMPTY_HOST_TIP_MARKER,
            ),
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(text.contains(marker), "{raw} -> {text}");
            assert!(
                !text.contains(crate::RELAY_MISSING_HOST_TIP_MARKER),
                "{text}"
            );
        }

        for raw in [
            "connect: relay url is missing a host",
            "relay url is missing a host extra",
            "relay url is empty",
            "relay url: relative URL without a base",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "tls: tls handshake eof",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::RELAY_MISSING_HOST_TIP_MARKER),
                "{raw} -> {text}"
            );
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn tool_err_tips_relay_fingerprint() {
        let raw = "tls: fingerprint: Odd number of digits";
        let value = tool_err(raw);
        assert_eq!(value["isError"], json!(true));
        let text = err_text(&value);
        assert!(text.starts_with(raw), "{raw} -> {text}");
        assert_eq!(
            text.matches(crate::RELAY_FINGERPRINT_TIP_MARKER).count(),
            1,
            "{text}"
        );
        for needle in [
            "64 hexadecimal digits (32 bytes)",
            "not an arbitrary name or odd-length string",
            "`--fingerprint sha256:<64 hex digits>`",
            "`--fingerprint system`",
            "`--trust webpki`",
            "`web-pki` is an alias",
            "unrecognized `--trust` value",
            "valid root modes are `system` and `webpki`",
            "`system+webpki`",
            "before any relay connection or node operation",
            "Certificate mismatch, hostname failure, and connection refusal",
            "`agentlink guide <node>`",
        ] {
            assert!(text.contains(needle), "{needle} missing: {text}");
        }
        assert!(!text.contains(crate::RELAY_URL_TLS_TIP_MARKER), "{text}");
        assert!(!text.contains(crate::RELAY_EMPTY_HOST_TIP_MARKER), "{text}");
        assert_eq!(tool_err(text), value);
    }

    #[test]
    fn tool_err_relay_fingerprint_does_not_shadow_siblings() {
        for (raw, marker) in [
            (
                "relay url must use wss:// (TLS is required)",
                crate::RELAY_URL_TLS_TIP_MARKER,
            ),
            (
                "relay url scheme `ftp` is not supported; use wss://",
                crate::UNSUPPORTED_RELAY_SCHEME_TIP_MARKER,
            ),
            (
                "relay port must not be 0",
                crate::RELAY_PORT_ZERO_TIP_MARKER,
            ),
            (
                "relay url: invalid port number",
                crate::RELAY_INVALID_PORT_TIP_MARKER,
            ),
            (
                "relay url: empty host",
                crate::RELAY_EMPTY_HOST_TIP_MARKER,
            ),
            (
                "relay url is missing a host",
                crate::RELAY_MISSING_HOST_TIP_MARKER,
            ),
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(text.contains(marker), "{raw} -> {text}");
            assert!(
                !text.contains(crate::RELAY_FINGERPRINT_TIP_MARKER),
                "{text}"
            );
        }

        for raw in [
            "connect: tls: fingerprint: Odd number of digits",
            "tls: fingerprint: Odd number of digits extra",
            "tls: fingerprint: odd number of digits",
            "tls: fingerprint: Invalid character 'x' at position 0",
            "tls: fingerprint must be 32 bytes (sha256 hex)",
            "tls: certificate fingerprint mismatch",
            "tls: invalid server name",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            let value = tool_err(raw);
            let text = err_text(&value);
            assert!(
                !text.contains(crate::RELAY_FINGERPRINT_TIP_MARKER),
                "{raw} -> {text}"
            );
            assert_eq!(text, raw, "{raw} -> {text}");
        }
    }

    #[test]
    fn bg_not_found_tip_does_not_shadow_siblings() {
        let value = tool_err("not found: background process d5c86dab");
        let text = err_text(&value);
        for decorated in [
            crate::decorate_watch_not_found(text),
            crate::decorate_pty_session_not_found(text),
            crate::decorate_bg_process_limit(text),
            crate::decorate_path_not_found(text),
            crate::decorate_node_not_found(text),
        ] {
            assert_eq!(decorated, text);
        }
    }

    #[test]
    fn tool_err_tips_approval_unresolved() {
        let value = tool_err("approval denied or timed out");
        assert_eq!(value["isError"], json!(true));
        let text = value["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(crate::APPROVAL_UNRESOLVED_TIP_MARKER),
            "{text}"
        );
        assert!(text.contains("agentlink approve allow"), "{text}");
        assert!(text.contains("MCP exposes no approve tool"), "{text}");
    }

    #[tokio::test]
    async fn reads_ndjson_and_content_length() {
        let raw = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut reader = BufReader::new(raw.as_bytes());
        let msg = read_message(&mut reader).await.unwrap().unwrap();
        assert_eq!(msg["method"], "ping");

        let body = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}";
        let framed = format!("Content-Length: {}\r\n\r\n{body}", body.len());
        let mut reader = BufReader::new(framed.as_bytes());
        let msg = read_message(&mut reader).await.unwrap().unwrap();
        assert_eq!(msg["method"], "tools/list");
    }

    #[tokio::test]
    async fn initialize_and_tools_do_not_need_a_relay() {
        let mut state = new_state(
            ClientSettings {
                relay: "wss://127.0.0.1:1".into(),
                token: "t".into(),
                fingerprint: "sha256:00".into(),
                trust: None,
            },
            std::env::temp_dir().join("agentlink-mcp-test.identity.json"),
        );
        let init = handle(
            &mut state,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}),
        )
        .await
        .unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "agentlink");
        let tools = handle(
            &mut state,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .await
        .unwrap();
        let names: Vec<_> = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert!(names.contains(&"get_status"));
        assert!(names.contains(&"list_machines"));
        assert!(names.contains(&"read_file"));
        assert!(names.contains(&"write_file"));
        assert!(names.contains(&"list_dir"));
        assert!(names.contains(&"run_command"));
        assert!(names.contains(&"search_content"));
        assert!(names.contains(&"copy_path"));
        assert!(names.contains(&"system_info"));
        assert!(names.contains(&"terminal_open"));
        assert!(names.contains(&"process_start"));
        assert!(names.contains(&"screenshot"));
        assert!(names.contains(&"click"));
        assert!(names.contains(&"type"));
        assert!(names.contains(&"key"));
        assert!(names.contains(&"scroll"));
        assert!(names.contains(&"get_ui_tree"));
        assert!(names.contains(&"act_on_element"));
        let note = handle(
            &mut state,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await;
        assert!(note.is_none());
    }

    #[tokio::test]
    async fn unauthenticated_mcp_answers_initialize_tools_and_get_status_then_returns_tool_error() {
        let dir = std::env::temp_dir().join(format!(
            "agentlink-mcp-unauth-{}",
            agentlink_core::util::random_hex(8)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = new_state_from_config(McpConfig {
            config_dir: dir.clone(),
            identity_path: dir.join("identity.json"),
            explicit_identity: false,
            relay: None,
            token: None,
            fingerprint: None,
            trust: None,
            preset_settings: None,
        });
        let init = handle(
            &mut state,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}),
        )
        .await
        .unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "agentlink");

        let status = handle(
            &mut state,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_status","arguments":{}}}),
        )
        .await
        .unwrap();
        assert_eq!(status["result"]["isError"], json!(false));
        let status_body: Value =
            serde_json::from_str(status["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(status_body["authenticated"], json!(false));
        assert_eq!(status_body["identity_exists"], json!(false));

        let list = handle(
            &mut state,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_machines","arguments":{}}}),
        )
        .await
        .unwrap();
        assert_eq!(list["result"]["isError"], json!(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn read_message_strips_utf8_bom() {
        let ndjson = "\u{feff}{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut reader = BufReader::new(ndjson.as_bytes());
        let msg = read_message(&mut reader).await.unwrap().unwrap();
        assert_eq!(msg["method"], "ping");

        let body = "\u{feff}{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}";
        let framed = format!("\u{feff}Content-Length: {}\r\n\r\n{body}", body.len());
        let mut reader = BufReader::new(framed.as_bytes());
        let msg = read_message(&mut reader).await.unwrap().unwrap();
        assert_eq!(msg["method"], "tools/list");
    }

    #[test]
    fn tool_specs_include_replace_all_enums_and_line_ranges() {
        let specs = tool_specs();
        let find = |name: &str| {
            specs
                .iter()
                .find(|t| t["name"] == name)
                .expect("tool present")
        };
        let replace = find("replace_text");
        assert_eq!(
            replace["inputSchema"]["properties"]["replace_all"]["type"],
            "boolean"
        );
        let read = find("read_file");
        assert_eq!(
            read["inputSchema"]["properties"]["start_line"]["type"],
            "integer"
        );
        assert_eq!(
            read["inputSchema"]["properties"]["end_line"]["type"],
            "integer"
        );
        let copy = find("copy_path");
        assert_eq!(
            copy["inputSchema"]["properties"]["direction"]["enum"],
            json!(["upload", "download", "peer"])
        );
        assert_eq!(
            copy["inputSchema"]["properties"]["compress"]["enum"],
            json!(["auto", "on", "off"])
        );
        let shot = find("screenshot");
        assert_eq!(
            shot["inputSchema"]["properties"]["format"]["enum"],
            json!(["jpeg", "png", "webp"])
        );
        let click = find("click");
        assert_eq!(
            click["inputSchema"]["properties"]["button"]["enum"],
            json!(["left", "right", "middle"])
        );
        let act = find("act_on_element");
        assert_eq!(
            act["inputSchema"]["properties"]["op"]["enum"],
            json!(["click", "focus", "set_value"])
        );
    }

    #[test]
    fn slice_utf8_lines_handles_ranges_and_bounds() {
        let text = "one\ntwo\nthree\nfour";
        let (out, s, e, total, clipped) = slice_utf8_lines(text, Some(2), Some(3)).unwrap();
        assert_eq!(out, "two\nthree\n");
        assert_eq!((s, e, total, clipped), (2, 3, 4, true));
        assert!(slice_utf8_lines(text, Some(0), None).is_err());
        assert!(slice_utf8_lines(text, Some(4), Some(2)).is_err());
    }

    #[tokio::test]
    async fn read_message_rejects_oversized_content_length_before_allocating() {
        let oversized = b"Content-Length: 67108864\r\n\r\n{}";
        let mut reader = BufReader::new(&oversized[..]);
        let err = read_message(&mut reader).await.unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "expected Content-Length cap rejection, got: {err}"
        );
    }
}
