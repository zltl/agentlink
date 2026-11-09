//! `agentlink audit` and the local half of sink configuration.
//!
//! Query can read the node directory, the relay's forwarded chain, or an
//! S3-compatible bucket. Config and sink edits update `audit.toml` and append
//! an audit record for the change.

use std::path::{Path, PathBuf};
use std::time::Duration;

use agentlink_core::audit::{verify_chain, AuditFilter, AuditPolicy, AuditRecord, SinkSpec};
use agentlink_core::s3::S3Config;
use agentlink_core::Client;
use agentlink_node::{query_local, query_s3, record_local_change};
use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum AuditAction {
    /// Read audit records from a local node directory, the relay, or S3.
    Query {
        /// `local`, `relay`, or `s3`.
        #[arg(long, default_value = "local")]
        sink: String,
        /// Node data directory. Required for `--sink local` unless it is the default.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Node name or id.
        #[arg(long)]
        node: Option<String>,
        /// Agent (client) id.
        #[arg(long)]
        agent: Option<String>,
        /// Operation or category, for example `exec` or `file_write`.
        #[arg(long)]
        op: Option<String>,
        /// Inclusive start, unix seconds.
        #[arg(long)]
        since: Option<i64>,
        /// Inclusive end, unix seconds.
        #[arg(long)]
        until: Option<i64>,
        /// Case-insensitive substring over the JSON record.
        #[arg(long)]
        text: Option<String>,
        /// Print new records as they appear. Local and relay only.
        #[arg(long)]
        follow: bool,
        /// Check the hash chain and exit non-zero if it does not verify.
        #[arg(long)]
        verify: bool,
        /// S3 endpoint, for example `http://127.0.0.1:9000`.
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long, default_value = "us-east-1")]
        region: String,
        #[arg(long)]
        bucket: Option<String>,
        #[arg(long, default_value = "")]
        prefix: String,
        /// Use path-style URLs (MinIO, some OSS/COS gateways).
        #[arg(long)]
        path_style: bool,
        /// `env`, `file`, or `iam`.
        #[arg(long, default_value = "env")]
        credentials: String,
        #[arg(long)]
        credential_file: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Show or change the audit policy.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Add, list, or remove a storage sink. Sinks fan out.
    Sink {
        #[command(subcommand)]
        action: SinkAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Print the effective `audit.toml`.
    Show {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Set one key. Example: `capture.diff true`.
    Set {
        key: String,
        value: String,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Push the resulting policy to a live node through the relay.
        #[arg(long)]
        push: Option<String>,
    },
    /// Replace the policy with `minimal`, `standard`, `full`, or `paranoid`.
    Preset {
        name: String,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        push: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SinkAction {
    /// Add or replace a sink by name.
    Add {
        name: String,
        /// `local`, `relay`, or `s3`.
        #[arg(long)]
        kind: String,
        /// Comma-separated `logs`, `diffs`, `recordings`. Empty means all.
        #[arg(long, default_value = "")]
        data: String,
        #[arg(long)]
        retention_days: Option<u64>,
        #[arg(long)]
        max_bytes: Option<u64>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long, default_value = "us-east-1")]
        region: String,
        #[arg(long)]
        bucket: Option<String>,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long)]
        path_style: bool,
        #[arg(long, default_value = "env")]
        credentials: String,
        #[arg(long)]
        credential_file: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        /// `AES256`, `aws:kms`, or empty.
        #[arg(long, default_value = "")]
        sse: String,
        /// Env var holding a 64-character hex AES-256 key for client-side encryption.
        #[arg(long, default_value = "")]
        client_key_env: String,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        push: Option<String>,
    },
    /// List sinks in `audit.toml`.
    Ls {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Remove a sink by name.
    Rm {
        name: String,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        push: Option<String>,
    },
}

pub async fn run(action: &AuditAction, json_out: bool, client: Option<&Client>) -> Result<i32> {
    match action {
        AuditAction::Query {
            sink,
            data_dir,
            node,
            agent,
            op,
            since,
            until,
            text,
            follow,
            verify,
            endpoint,
            region,
            bucket,
            prefix,
            path_style,
            credentials,
            credential_file,
            profile,
        } => {
            let filter = AuditFilter {
                node: node.clone(),
                agent: agent.clone(),
                op: op.clone(),
                since_unix: *since,
                until_unix: *until,
                text: text.clone(),
                limit: if *follow { 10_000 } else { 200 },
                user: None,
            };
            let mut seen = 0usize;
            loop {
                let records = load_records(
                    sink,
                    data_dir.as_deref(),
                    client,
                    &filter,
                    endpoint.clone(),
                    region,
                    bucket.clone(),
                    prefix,
                    *path_style,
                    credentials,
                    credential_file.clone(),
                    profile.clone(),
                )
                .await?;
                if *verify {
                    verify_chain(&records).map_err(|err| anyhow!(err.to_string()))?;
                }
                if *follow {
                    for record in records.iter().skip(seen) {
                        println!("{}", serde_json::to_string(record)?);
                    }
                    seen = records.len();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                emit_records(json_out, &records, *verify);
                return Ok(0);
            }
        }
        AuditAction::Config { action } => match action {
            ConfigAction::Show { data_dir } => {
                let policy = load_policy_file(&node_dir(data_dir.as_deref())?)?;
                if json_out {
                    println!("{}", serde_json::to_string_pretty(&policy)?);
                } else {
                    print!("{}", policy.to_toml().map_err(|e| anyhow!(e.to_string()))?);
                }
                Ok(0)
            }
            ConfigAction::Set {
                key,
                value,
                data_dir,
                push,
            } => {
                let dir = node_dir(data_dir.as_deref())?;
                let mut policy = load_policy_file(&dir)?;
                policy
                    .set_key(key, value)
                    .map_err(|err| anyhow!(err.to_string()))?;
                save_policy(
                    &dir,
                    &policy,
                    &format!("set {key}={value}"),
                    client,
                    push.as_deref(),
                )
                .await?;
                Ok(0)
            }
            ConfigAction::Preset {
                name,
                data_dir,
                push,
            } => {
                let dir = node_dir(data_dir.as_deref())?;
                let policy = AuditPolicy::preset(name).map_err(|err| anyhow!(err.to_string()))?;
                save_policy(
                    &dir,
                    &policy,
                    &format!("preset {name}"),
                    client,
                    push.as_deref(),
                )
                .await?;
                Ok(0)
            }
        },
        AuditAction::Sink { action } => match action {
            SinkAction::Add {
                name,
                kind,
                data,
                retention_days,
                max_bytes,
                endpoint,
                region,
                bucket,
                prefix,
                path_style,
                credentials,
                credential_file,
                profile,
                sse,
                client_key_env,
                data_dir,
                push,
            } => {
                let dir = node_dir(data_dir.as_deref())?;
                let mut policy = load_policy_file(&dir)?;
                let s3 = if kind == "s3" {
                    Some(S3Config {
                        endpoint: endpoint
                            .clone()
                            .ok_or_else(|| anyhow!("--endpoint is required for s3"))?,
                        region: region.clone(),
                        bucket: bucket
                            .clone()
                            .ok_or_else(|| anyhow!("--bucket is required for s3"))?,
                        prefix: prefix.clone(),
                        path_style: *path_style,
                        credentials: credentials.clone(),
                        credential_file: credential_file.clone(),
                        profile: profile.clone(),
                        sse: sse.clone(),
                        client_key_env: client_key_env.clone(),
                    })
                } else {
                    None
                };
                let spec = SinkSpec {
                    name: name.clone(),
                    kind: kind.clone(),
                    data: split_csv(data),
                    retention_days: *retention_days,
                    max_bytes: *max_bytes,
                    s3,
                };
                policy.sinks.retain(|sink| sink.name != *name);
                policy.sinks.push(spec);
                policy.validate().map_err(|err| anyhow!(err.to_string()))?;
                save_policy(
                    &dir,
                    &policy,
                    &format!("sink add {name}"),
                    client,
                    push.as_deref(),
                )
                .await?;
                Ok(0)
            }
            SinkAction::Ls { data_dir } => {
                let policy = load_policy_file(&node_dir(data_dir.as_deref())?)?;
                if json_out {
                    println!("{}", serde_json::to_string_pretty(&policy.sinks)?);
                } else if policy.sinks.is_empty() {
                    println!("(no sinks)");
                } else {
                    for sink in &policy.sinks {
                        let data = if sink.data.is_empty() {
                            "all".into()
                        } else {
                            sink.data.join(",")
                        };
                        println!("{} {} {data}", sink.name, sink.kind);
                    }
                }
                Ok(0)
            }
            SinkAction::Rm {
                name,
                data_dir,
                push,
            } => {
                let dir = node_dir(data_dir.as_deref())?;
                let mut policy = load_policy_file(&dir)?;
                let before = policy.sinks.len();
                policy.sinks.retain(|sink| sink.name != *name);
                if policy.sinks.len() == before {
                    return Err(anyhow!("no sink named {name}"));
                }
                policy.validate().map_err(|err| anyhow!(err.to_string()))?;
                save_policy(
                    &dir,
                    &policy,
                    &format!("sink rm {name}"),
                    client,
                    push.as_deref(),
                )
                .await?;
                Ok(0)
            }
        },
    }
}

pub fn node_dir(data_dir: Option<&Path>) -> Result<PathBuf> {
    match data_dir {
        Some(dir) => Ok(dir.to_path_buf()),
        None => agentlink_core::config::default_data_dir("node").context("node data dir"),
    }
}

fn load_policy_file(dir: &Path) -> Result<AuditPolicy> {
    let path = dir.join("audit.toml");
    if path.exists() {
        let text = std::fs::read_to_string(&path)?;
        return AuditPolicy::parse(&text).map_err(|err| anyhow!(err.to_string()));
    }
    AuditPolicy::preset("standard").map_err(|err| anyhow!(err.to_string()))
}

async fn save_policy(
    dir: &Path,
    policy: &AuditPolicy,
    detail: &str,
    client: Option<&Client>,
    push: Option<&str>,
) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let text = policy.to_toml().map_err(|err| anyhow!(err.to_string()))?;
    std::fs::write(dir.join("audit.toml"), &text)?;
    record_local_change(dir, detail);
    if let Some(node) = push {
        let client = client.ok_or_else(|| anyhow!("--push needs a relay login"))?;
        client
            .set_audit_policy(node, None, &text)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
    }
    eprintln!("updated {}", dir.join("audit.toml").display());
    Ok(())
}

async fn load_records(
    sink: &str,
    data_dir: Option<&Path>,
    client: Option<&Client>,
    filter: &AuditFilter,
    endpoint: Option<String>,
    region: &str,
    bucket: Option<String>,
    prefix: &str,
    path_style: bool,
    credentials: &str,
    credential_file: Option<String>,
    profile: Option<String>,
) -> Result<Vec<AuditRecord>> {
    match sink {
        "local" => Ok(query_local(&node_dir(data_dir)?, filter)),
        "relay" => {
            let client = client.ok_or_else(|| anyhow!("relay query needs a login"))?;
            let filter = serde_json::to_value(filter)?;
            let values = client
                .query_audit(filter)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            Ok(values
                .into_iter()
                .filter_map(|value| serde_json::from_value(value).ok())
                .collect())
        }
        "s3" => {
            let config = s3_from_flags_or_file(
                data_dir,
                endpoint,
                region,
                bucket,
                prefix,
                path_style,
                credentials,
                credential_file,
                profile,
            )?;
            query_s3(config, filter).map_err(|err| anyhow!(err.to_string()))
        }
        other => Err(anyhow!("unknown sink '{other}'. Use local, relay, or s3")),
    }
}

fn s3_from_flags_or_file(
    data_dir: Option<&Path>,
    endpoint: Option<String>,
    region: &str,
    bucket: Option<String>,
    prefix: &str,
    path_style: bool,
    credentials: &str,
    credential_file: Option<String>,
    profile: Option<String>,
) -> Result<S3Config> {
    if let (Some(endpoint), Some(bucket)) = (endpoint, bucket) {
        return Ok(S3Config {
            endpoint,
            region: region.to_string(),
            bucket,
            prefix: prefix.to_string(),
            path_style,
            credentials: credentials.to_string(),
            credential_file,
            profile,
            sse: String::new(),
            client_key_env: String::new(),
        });
    }
    let policy = load_policy_file(&node_dir(data_dir)?)?;
    policy
        .sinks
        .iter()
        .find(|sink| sink.kind == "s3")
        .and_then(|sink| sink.s3.clone())
        .ok_or_else(|| anyhow!("pass --endpoint and --bucket, or configure an s3 sink"))
}

fn emit_records(json_out: bool, records: &[AuditRecord], verified: bool) {
    if json_out {
        let body = json!({
            "verified": verified,
            "records": records,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".into())
        );
        return;
    }
    if verified {
        eprintln!("hash chain verified ({} records)", records.len());
    }
    for record in records {
        println!(
            "{} {} {} {} {}",
            record.ts, record.op, record.client_id, record.result, record.node_id
        );
    }
}

fn split_csv(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}
