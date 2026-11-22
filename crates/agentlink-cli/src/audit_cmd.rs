//! `agentlink audit` and the local half of sink configuration.
//!
//! Query can read the node directory, the relay's forwarded chain, or an
//! S3-compatible bucket. Config and sink edits update `audit.toml` and append
//! an audit record for the change (unless `--push <node>` targets a remote node,
//! in which case local `audit.toml` is left untouched).

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
        /// Inclusive start: unix seconds, relative duration (e.g. `-24h`, `30m`), or ISO-8601 UTC (`2026-11-22T10:00:00Z`).
        #[arg(long, allow_hyphen_values = true)]
        since: Option<String>,
        /// Inclusive end: unix seconds, relative duration (e.g. `-1h`), or ISO-8601 UTC.
        #[arg(long, allow_hyphen_values = true)]
        until: Option<String>,
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
        /// Push the resulting policy to a live node through the relay without overwriting local `audit.toml`.
        #[arg(long)]
        push: Option<String>,
    },
    /// Replace the policy with `minimal`, `standard`, `full`, or `paranoid`.
    Preset {
        name: String,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Push the preset to a live node through the relay without overwriting local `audit.toml`.
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

/// Parse `--since` / `--until`: unix epoch seconds, relative span (`-24h`, `30m`, `7d`),
/// or ISO-8601 UTC / offset timestamp (`2026-11-22`, `2026-11-22T10:00:00Z`, `2026-11-22T10:00:00+08:00`).
pub(crate) fn parse_audit_time(raw: &str, now_unix: i64) -> Result<i64> {
    let text = raw.trim();
    if text.is_empty() {
        return Err(anyhow!("timestamp cannot be empty"));
    }
    // Plain unix timestamp (positive integer or 0)
    if let Ok(ts) = text.parse::<i64>() {
        if ts >= 0 {
            return Ok(ts);
        }
        // Negative plain integer like `-60` means 60s ago.
        return Ok(now_unix.saturating_add(ts));
    }
    // Relative duration (`-24h`, `24h`, `-30m`, `1h30m`, `7d`)
    let rel_body = text.strip_prefix('-').unwrap_or(text);
    if !rel_body.is_empty()
        && rel_body.chars().next().is_some_and(|c| c.is_ascii_digit())
        && rel_body
            .chars()
            .last()
            .is_some_and(|c| matches!(c.to_ascii_lowercase(), 's' | 'm' | 'h' | 'd' | 'w'))
    {
        if let Ok(secs) = parse_relative_duration(rel_body) {
            return Ok(now_unix.saturating_sub(secs));
        }
    }
    // ISO-8601 date (`YYYY-MM-DD`) or datetime (`YYYY-MM-DDTHH:MM:SS[Z|+HH:MM|-HH:MM]`)
    parse_iso8601_unix(text).ok_or_else(|| {
        anyhow!(
            "invalid timestamp `{raw}`; expected unix seconds, relative span (e.g. `-24h`, `30m`), or ISO-8601 (e.g. `2026-11-22T10:00:00Z`)"
        )
    })
}

fn parse_relative_duration(text: &str) -> Result<i64> {
    let mut total = 0i64;
    let mut digits = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        if digits.is_empty() {
            return Err(anyhow!("missing number before `{ch}`"));
        }
        let n: i64 = digits.parse()?;
        let mult = match ch.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return Err(anyhow!("unknown unit `{ch}`")),
        };
        total = total.saturating_add(n.saturating_mul(mult));
        digits.clear();
    }
    if !digits.is_empty() || total <= 0 {
        return Err(anyhow!("invalid relative duration"));
    }
    Ok(total)
}

fn parse_iso8601_unix(text: &str) -> Option<i64> {
    let (date_part, rest) = if let Some((d, t)) = text.split_once('T').or_else(|| text.split_once(' ')) {
        (d, Some(t))
    } else {
        (text, None)
    };
    let mut dparts = date_part.split('-');
    let year: i64 = dparts.next()?.parse().ok()?;
    let month: u32 = dparts.next()?.parse().ok()?;
    let day: u32 = dparts.next()?.parse().ok()?;
    if dparts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (hour, min, sec, tz_offset_secs) = match rest {
        None => (0u32, 0u32, 0u32, 0i64),
        Some(t) => {
            let (hms, offset) = if let Some(stripped) = t.strip_suffix('Z').or_else(|| t.strip_suffix('z')) {
                (stripped, 0i64)
            } else if let Some(pos) = t.rfind(['+', '-']) {
                let (left, tz) = t.split_at(pos);
                let sign = if tz.starts_with('-') { -1i64 } else { 1i64 };
                let tz_body = &tz[1..];
                let (th, tm) = tz_body.split_once(':')?;
                let th: i64 = th.parse().ok()?;
                let tm: i64 = tm.parse().ok()?;
                (left, sign * (th * 3600 + tm * 60))
            } else {
                (t, 0i64)
            };
            let hms = hms.split('.').next().unwrap_or(hms);
            let mut tparts = hms.split(':');
            let hour: u32 = tparts.next()?.parse().ok()?;
            let min: u32 = tparts.next()?.parse().ok()?;
            let sec: u32 = tparts.next().unwrap_or("0").parse().ok()?;
            if tparts.next().is_some() || hour > 23 || min > 59 || sec > 60 {
                return None;
            }
            (hour, min, sec.min(59), offset)
        }
    };
    let days = days_from_civil(year, month, day)?;
    Some(
        days * 86_400
            + i64::from(hour) * 3600
            + i64::from(min) * 60
            + i64::from(sec)
            - tz_offset_secs,
    )
}

/// Howard Hinnant's civil-from-days inverse: days since 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    let m = i64::from(m);
    let d = i64::from(d);
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
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
            let now = agentlink_core::util::unix_now();
            let since_unix = since
                .as_deref()
                .map(|raw| parse_audit_time(raw, now))
                .transpose()?;
            let until_unix = until
                .as_deref()
                .map(|raw| parse_audit_time(raw, now))
                .transpose()?;
            let filter = AuditFilter {
                node: node.clone(),
                agent: agent.clone(),
                op: op.clone(),
                since_unix,
                until_unix,
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
                save_or_push_policy(
                    &dir,
                    &policy,
                    &format!("set {key}={value}"),
                    client,
                    push.as_deref(),
                    json_out,
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
                save_or_push_policy(
                    &dir,
                    &policy,
                    &format!("preset {name}"),
                    client,
                    push.as_deref(),
                    json_out,
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
                save_or_push_policy(
                    &dir,
                    &policy,
                    &format!("sink add {name}"),
                    client,
                    push.as_deref(),
                    json_out,
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
                save_or_push_policy(
                    &dir,
                    &policy,
                    &format!("sink rm {name}"),
                    client,
                    push.as_deref(),
                    json_out,
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

/// Push to a remote node WITHOUT overwriting local `audit.toml` when `--push` is set;
/// otherwise update local `audit.toml` and record a local audit change entry.
async fn save_or_push_policy(
    dir: &Path,
    policy: &AuditPolicy,
    detail: &str,
    client: Option<&Client>,
    push: Option<&str>,
    json_out: bool,
) -> Result<()> {
    let text = policy.to_toml().map_err(|err| anyhow!(err.to_string()))?;
    if let Some(node) = push {
        let client = client.ok_or_else(|| anyhow!("--push needs a relay login"))?;
        client
            .set_audit_policy(node, None, &text)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
        if json_out {
            println!("{}", json!({"ok": true, "pushed": node, "detail": detail}));
        } else {
            println!("pushed audit policy ({detail}) to {node}");
        }
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    let path = dir.join("audit.toml");
    std::fs::write(&path, &text)?;
    record_local_change(dir, detail);
    if json_out {
        println!("{}", json!({"ok": true, "path": path, "detail": detail}));
    } else {
        println!("updated {}", path.display());
    }
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

fn short_id_if_hex64(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        trimmed.chars().take(12).collect()
    } else {
        trimmed.to_string()
    }
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
            record.ts,
            record.op,
            short_id_if_hex64(&record.client_id),
            record.result,
            short_id_if_hex64(&record.node_id)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_relative_and_iso8601_timestamps() {
        let now = 1_763_800_000;
        assert_eq!(parse_audit_time("1763700000", now).unwrap(), 1_763_700_000);
        assert_eq!(parse_audit_time("-24h", now).unwrap(), now - 86_400);
        assert_eq!(parse_audit_time("30m", now).unwrap(), now - 1800);
        assert_eq!(parse_audit_time("-1h30m", now).unwrap(), now - 5400);
        assert_eq!(parse_audit_time("1970-01-01T00:00:00Z", now).unwrap(), 0);
        assert_eq!(parse_audit_time("1970-01-02", now).unwrap(), 86_400);
        assert_eq!(
            parse_audit_time("1970-01-01T08:00:00+08:00", now).unwrap(),
            0
        );
        assert!(parse_audit_time("not-a-time", now).is_err());
    }

    #[tokio::test]
    async fn push_without_client_does_not_clobber_local_audit_toml() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("audit.toml");
        std::fs::write(&toml_path, "# sentinel\n").unwrap();
        let policy = AuditPolicy::preset("paranoid").unwrap();
        let err = save_or_push_policy(
            dir.path(),
            &policy,
            "preset paranoid",
            None,
            Some("remote-box"),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("--push needs a relay login"));
        assert_eq!(std::fs::read_to_string(&toml_path).unwrap(), "# sentinel\n");
    }
}
