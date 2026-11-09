//! `agentlink update` checks GitHub Releases and replaces this binary.
//!
//! Every archive is checked against `SHA256SUMS`. A minisign signature is
//! required. The key is `--pubkey`, `AGENTLINK_UPDATE_PUBKEY`, a local
//! `minisign.pub`, or the key embedded from `deploy/minisign.pub`. It is never
//! downloaded from the release host. A missing verifier or a missing signature
//! is a failure. `--checksum-only` is the explicit skip.
//! `update --check` verifies the latest release even when this binary is
//! already that version (so a configured pubkey can report `signature: true`).
//!
//! There is no built-in download mirror. Pass `--download-base` or set
//! `AGENTLINK_DOWNLOAD_BASE` to use one. A GitHub 404 does not fall back to
//! another host.

use std::cmp::Ordering;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde::Deserialize;
use serde_json::json;

use crate::fetch;
use crate::service::{self, Scope};
use crate::signature;
use crate::version;

const SUMS_NAME: &str = "SHA256SUMS";
const SIG_NAME: &str = "SHA256SUMS.minisig";

#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Report the latest release and verify it, without replacing the binary.
    #[arg(long)]
    pub check: bool,
    /// Replace the binary without a confirmation prompt.
    #[arg(long)]
    pub yes: bool,
    /// Install a daily task that runs `agentlink update --yes`.
    #[arg(long)]
    pub auto: bool,
    /// Remove the daily update task.
    #[arg(long)]
    pub disable_auto: bool,
    /// Install this version instead of the latest release. Allows a reinstall.
    #[arg(long)]
    pub version: Option<String>,
    /// GitHub repository that publishes releases.
    #[arg(long, env = "AGENTLINK_REPO", default_value = "zltl/agentlink")]
    pub repo: String,
    /// GitHub token for private repositories. Also reads `GH_TOKEN` /
    /// `GITHUB_TOKEN` when this flag/env is unset. Sent as Bearer.
    #[arg(long, env = "AGENTLINK_GITHUB_TOKEN")]
    pub github_token: Option<String>,
    /// Download mirror that serves `SHA256SUMS` and the archives.
    /// Skips GitHub. Example: `https://relay.example.com/dl`.
    /// When unset, a GitHub 404 fails. There is no built-in mirror.
    #[arg(long, env = "AGENTLINK_DOWNLOAD_BASE")]
    pub download_base: Option<String>,
    /// Minisign public key text, or a path to a public key file.
    #[arg(long, env = "AGENTLINK_UPDATE_PUBKEY")]
    pub pubkey: Option<String>,
    /// Accept a matching checksum when no signature is checked.
    ///
    /// This is a break-glass switch. A configured public key is ignored.
    #[arg(long)]
    pub checksum_only: bool,
    /// Scope of the auto-update timer. Defaults to the user session.
    #[arg(long, value_enum, default_value = "user")]
    pub scope: Scope,
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    /// API asset URL (`/repos/.../releases/assets/{id}`). Required for private
    /// repos: `browser_download_url` returns 404 even with a token; the API URL
    /// with `Accept: application/octet-stream` redirects to a signed CDN link.
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Default, serde::Serialize, Deserialize)]
struct UpdateConfig {
    #[serde(default)]
    pubkey: Option<String>,
    #[serde(default)]
    auto: bool,
}

pub async fn run(json_mode: bool, config_dir: Option<PathBuf>, args: &UpdateArgs) -> Result<i32> {
    check_repo(&args.repo)?;
    let dir = match config_dir {
        Some(dir) => dir,
        None => agentlink_core::config::default_config_dir()?,
    };
    if args.disable_auto {
        service::remove_auto_timer(args.scope)?;
        let mut saved = load_update_config(&dir);
        saved.auto = false;
        save_update_config(&dir, &saved)?;
        emit(json_mode, json!({"ok": true, "auto": false}), || {
            eprintln!("removed the daily update task");
        });
        return Ok(0);
    }
    if args.auto {
        let binary = std::env::current_exe().context("locate the running binary")?;
        service::install_auto_timer(&binary, args.scope)?;
        let mut saved = load_update_config(&dir);
        saved.auto = true;
        if let Some(key) = &args.pubkey {
            saved.pubkey = Some(key.clone());
        }
        save_update_config(&dir, &saved)?;
        emit(
            json_mode,
            json!({"ok": true, "auto": true, "scope": format!("{:?}", args.scope)}),
            || eprintln!("installed a daily `agentlink update --yes` task"),
        );
        return Ok(0);
    }

    if let Some(base) = normalize_download_base(args.download_base.as_deref()) {
        return run_from_mirror(json_mode, &dir, args, &base).await;
    }

    let authorization = github_authorization(args);
    let auth = authorization.as_deref();
    let release = match fetch_release(&args.repo, args.version.as_deref(), auth).await {
        Ok(release) => release,
        Err(err) => return Err(err),
    };
    let latest = release.tag_name.trim().trim_start_matches('v');
    let explicit = args.version.is_some();
    let current = version::semver();
    let newer = compare_versions(latest, current) == Ordering::Greater;
    // `--check` still downloads and verifies checksum/signature even when the
    // running binary already matches latest, so AGENTLINK_UPDATE_PUBKEY users
    // can confirm the release pin without forcing a reinstall.
    if !newer && !explicit && !args.check {
        emit(
            json_mode,
            json!({"ok": true, "current": current, "latest": latest, "update": false}),
            || eprintln!("{}", already_latest_line(&current)),
        );
        return Ok(0);
    }
    let names = archive_names(latest, std::env::consts::OS, std::env::consts::ARCH);
    let asset = choose_asset(&release, &names)?;
    let bytes = download_asset(asset, auth).await?;
    let sums = download_named(&args.repo, &release, SUMS_NAME, auth).await?;
    verify_checksum(&asset.name, &bytes, &sums)?;
    let pubkey = if args.checksum_only {
        None
    } else {
        resolve_pubkey(args, &dir)?
    };
    let signature_verified =
        verify_signature(&args.repo, &release, &sums, pubkey.as_ref(), auth).await?;
    if args.check {
        let daemon = node_daemon_sibling(current_exe_dir().as_deref());
        let report = CheckReport {
            current: &current,
            latest,
            asset: &asset.name,
            newer,
            explicit,
            signature_verified,
            mirror: None,
            daemon_path: daemon.as_deref(),
        };
        let value = report.json();
        emit(json_mode, value, || {
            for line in report.human_lines() {
                eprintln!("{line}");
            }
        });
        return Ok(0);
    }
    if !confirm(args.yes, latest)? {
        eprintln!("not updated");
        return Ok(0);
    }
    let binary = extract_binary(&asset.name, &bytes)?;
    let report = apply_binary(&binary)?;
    let mut value = json!({
        "ok": true,
        "current": current,
        "installed": latest,
        "asset": asset.name,
        "checksum": true,
        "signature": signature_verified,
        "applied": true,
    });
    add_apply_fields(&mut value, &report);
    emit(json_mode, value, || {
        eprintln!("updated to {latest}");
        eprintln!("checksum: ok");
        if signature_verified {
            eprintln!("signature: ok");
        } else {
            eprintln!("{}", missing_signature_tip());
        }
        for tip in &report.tips {
            eprintln!("{tip}");
        }
    });
    Ok(0)
}

fn confirm(yes: bool, latest: &str) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !io::stdin().is_terminal() {
        bail!("pass --yes to replace this binary with {latest}");
    }
    eprint!("replace this binary with {latest}? [y/N] ");
    io::stderr().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

fn normalize_download_base(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_string())
}

/// No implicit download mirror. Pass `--download-base` or `AGENTLINK_DOWNLOAD_BASE`.

/// Discover + download a release from a public mirror (no GitHub).
async fn run_from_mirror(
    json_mode: bool,
    dir: &Path,
    args: &UpdateArgs,
    base: &str,
) -> Result<i32> {
    let sums = download_mirror(&format!("{base}/{SUMS_NAME}"))
        .await
        .with_context(|| format!("download {SUMS_NAME} from {base}"))
        .map_err(decorate_mirror_download_anyhow)?;
    let sums_text = std::str::from_utf8(&sums).context("SHA256SUMS is not utf-8")?;
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let explicit = args.version.is_some();
    let latest = match args.version.as_deref() {
        Some(version) => version.trim().trim_start_matches('v').to_string(),
        None => latest_version_from_sums(sums_text, os, arch)?,
    };
    let current = version::semver();
    let newer = compare_versions(&latest, current) == Ordering::Greater;
    if !newer && !explicit && !args.check {
        emit(
            json_mode,
            json!({"ok": true, "current": current, "latest": latest, "update": false, "mirror": base}),
            || eprintln!("{}", already_latest_line(&current)),
        );
        return Ok(0);
    }
    let names = archive_names(&latest, os, arch);
    let asset_name = names
        .iter()
        .find(|name| checksum_for(sums_text, name).is_some())
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "mirror {base} has no archive for this machine (looked for {})",
                names.join(", ")
            )
        })?;
    let bytes = download_mirror(&format!("{base}/{asset_name}"))
        .await
        .with_context(|| format!("download {asset_name} from {base}"))
        .map_err(decorate_mirror_download_anyhow)?;
    verify_checksum(&asset_name, &bytes, &sums)?;
    let pubkey = if args.checksum_only {
        None
    } else {
        resolve_pubkey(args, dir)?
    };
    let signature_verified = if let Some(public) = pubkey.as_ref() {
        let sig = download_mirror(&format!("{base}/{SIG_NAME}"))
            .await
            .map_err(|err| mirror_signature_context(err, base))
            .map_err(decorate_mirror_download_anyhow)?;
        let text = String::from_utf8(sig).context("signature file is not utf-8")?;
        signature::verify(public, &sums, &text)?;
        true
    } else {
        false
    };
    if args.check {
        let daemon = node_daemon_sibling(current_exe_dir().as_deref());
        let report = CheckReport {
            current: &current,
            latest: &latest,
            asset: &asset_name,
            newer,
            explicit,
            signature_verified,
            mirror: Some(base),
            daemon_path: daemon.as_deref(),
        };
        let value = report.json();
        emit(json_mode, value, || {
            for line in report.human_lines() {
                eprintln!("{line}");
            }
        });
        return Ok(0);
    }
    if !confirm(args.yes, &latest)? {
        eprintln!("not updated");
        return Ok(0);
    }
    let binary = extract_binary(&asset_name, &bytes)?;
    let report = apply_binary(&binary)?;
    let mut value = json!({
        "ok": true,
        "current": current,
        "installed": latest,
        "asset": asset_name,
        "checksum": true,
        "signature": signature_verified,
        "applied": true,
        "mirror": base,
    });
    add_apply_fields(&mut value, &report);
    emit(json_mode, value, || {
        eprintln!("updated to {latest} via {base}");
        eprintln!("checksum: ok");
        if signature_verified {
            eprintln!("signature: ok");
        } else {
            eprintln!("{}", missing_signature_tip());
        }
        for tip in &report.tips {
            eprintln!("{tip}");
        }
    });
    Ok(0)
}

fn latest_version_from_sums(sums: &str, os: &str, arch: &str) -> Result<String> {
    let markers: Vec<String> = candidate_targets(os, arch)
        .into_iter()
        .map(|target| format!("-{target}."))
        .collect();
    if markers.is_empty() {
        bail!("unsupported OS/arch for update ({os}/{arch})");
    }
    let mut best: Option<String> = None;
    for (_, file) in parse_checksums(sums) {
        let Some(rest) = file.strip_prefix("agentlink-") else {
            continue;
        };
        let Some(ver) = markers.iter().find_map(|marker| {
            rest.find(marker.as_str())
                .map(|idx| rest[..idx].to_string())
        }) else {
            continue;
        };
        best = match best {
            None => Some(ver),
            Some(prev) if compare_versions(&ver, &prev) == Ordering::Greater => Some(ver),
            Some(prev) => Some(prev),
        };
    }
    best.ok_or_else(|| anyhow!("SHA256SUMS has no archive for this machine (os={os} arch={arch})"))
}

fn github_authorization(args: &UpdateArgs) -> Option<String> {
    let raw = args
        .github_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            for key in ["GH_TOKEN", "GITHUB_TOKEN"] {
                if let Ok(value) = std::env::var(key) {
                    let value = value.trim().to_string();
                    if !value.is_empty() {
                        return Some(value);
                    }
                }
            }
            None
        })?;
    // Accept a full header value or a bare token.
    if raw.to_ascii_lowercase().starts_with("bearer ")
        || raw.to_ascii_lowercase().starts_with("token ")
    {
        Some(raw)
    } else {
        Some(format!("Bearer {raw}"))
    }
}

async fn fetch_release(
    repo: &str,
    version: Option<&str>,
    authorization: Option<&str>,
) -> Result<Release> {
    let url = match version {
        Some(version) => {
            let tag = if version.starts_with('v') {
                version.to_string()
            } else {
                format!("v{version}")
            };
            format!("https://api.github.com/repos/{repo}/releases/tags/{tag}")
        }
        None => format!("https://api.github.com/repos/{repo}/releases/latest"),
    };
    let response = fetch::https_get_auth(&url, "application/vnd.github+json", authorization)
        .await
        .map_err(|err| annotate_release_fetch_error(err, repo, authorization.is_some()))?;
    serde_json::from_slice(&response.body).context("GitHub release JSON")
}

fn annotate_release_fetch_error(err: anyhow::Error, repo: &str, has_token: bool) -> anyhow::Error {
    let text = format!("{err:#}");
    if text.contains(" returned 404") {
        if has_token {
            return anyhow!(
                "{err}
no published release for {repo} (or this token cannot see it). Push a v* tag so release.yml publishes archives, or pass --version"
            );
        }
        return anyhow!(
            "{err}
GitHub returned 404 for {repo}. Private repos need --github-token / AGENTLINK_GITHUB_TOKEN (or GH_TOKEN), or pass --download-base / AGENTLINK_DOWNLOAD_BASE to a mirror that serves SHA256SUMS (for example https://relay.example.com/dl). Public repos need a non-prerelease v* release with archives"
        );
    }
    err
}

async fn download(url: &str, authorization: Option<&str>) -> Result<Vec<u8>> {
    let response = fetch::https_get_auth(url, "application/octet-stream", authorization).await?;
    Ok(response.body)
}

/// Attach the transient TLS tip to a download failure so `update --json` and
/// the human error both explain a relay TLS flap. Already-tipped errors are
/// returned unchanged.
fn decorate_transient_tls_anyhow(err: anyhow::Error) -> anyhow::Error {
    let message = format!("{err:#}");
    let decorated = agentlink_core::error::decorate_transient_tls(&message);
    if decorated == message {
        err
    } else {
        anyhow!(decorated)
    }
}

/// Appended to a transient mirror download failure, already prefixed for display.
const MIRROR_DOWNLOAD_TIP: &str = "tip: mirror download failed — wait a second and retry `agentlink update`; check AGENTLINK_DOWNLOAD_BASE / https://relay.example.com/dl";

const MIRROR_DOWNLOAD_MARKER: &str = "mirror download failed";

/// Connection-level flaps against a mirror, as opposed to a bad payload,
/// checksum, signature, or a missing release (which must not be retried).
fn looks_like_transient_mirror_download(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "connection refused",
        "connection reset",
        "timed out",
        "timeout",
        "broken pipe",
        "network is unreachable",
        "temporary failure",
        "connect ",
        "os error 111",
        "os error 110",
        "os error 104",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_transient_mirror_error(err: &anyhow::Error) -> bool {
    let message = format!("{err:#}");
    agentlink_core::error::is_transient_tls(&message)
        || looks_like_transient_mirror_download(&message)
}

const NO_SIGNATURE_CLAIM: &str = "no signature and a public key is configured";

const MIRROR_NO_SIGNATURE_TIP: &str = "tip: mirror has no SHA256SUMS.minisig while a pubkey is configured — use a signed mirror, pass --checksum-only, or unset the pubkey";

const RELEASE_NO_SIGNATURE_TIP: &str = "tip: release has no SHA256SUMS.minisig while a pubkey is configured — use a signed release, pass --checksum-only, or unset the pubkey";

const SIGNATURE_FLAP_TIP: &str =
    "tip: signature download flapped — retry `agentlink update` (mirror likely still signed)";

/// Only a 404/not-found means the asset is genuinely absent. A TLS flap must
/// keep the normal download context so the transient tip explains it.
fn looks_like_missing_file(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("returned 404") || lower.contains("not found")
}

fn mirror_signature_context(err: anyhow::Error, base: &str) -> anyhow::Error {
    if is_transient_mirror_error(&err) {
        return err.context(format!("download {SIG_NAME} from {base}"));
    }
    let message = format!("{err:#}");
    if looks_like_missing_file(&message) {
        anyhow!("this mirror has {NO_SIGNATURE_CLAIM}: {message}; {MIRROR_NO_SIGNATURE_TIP}")
    } else {
        err.context(format!("download {SIG_NAME} from {base}"))
    }
}

/// `download_named` already adds `download {SIG_NAME}` and the TLS tip, so a
/// transient failure needs no extra context here.
fn release_signature_context(err: anyhow::Error) -> anyhow::Error {
    if is_transient_mirror_error(&err) {
        return err;
    }
    let message = format!("{err:#}");
    if looks_like_missing_file(&message) {
        anyhow!("this release has {NO_SIGNATURE_CLAIM}: {message}; {RELEASE_NO_SIGNATURE_TIP}")
    } else {
        err
    }
}

/// Safety net if an old "no signature" context ever wraps a transient flap:
/// drop the absence claim and explain that the download itself flapped.
fn rewrite_signature_absence_claim(message: &str) -> String {
    message.replace(
        NO_SIGNATURE_CLAIM,
        "signature download failed while a public key is configured",
    )
}

/// Attach the transient TLS tip first, else the mirror download tip, so both
/// `update --json` (outer Display only) and the human error carry the cause
/// and an actionable hint. Already-tipped errors pass through unchanged.
fn decorate_mirror_download_anyhow(err: anyhow::Error) -> anyhow::Error {
    let message = format!("{err:#}");
    if message.contains(NO_SIGNATURE_CLAIM) && is_transient_mirror_error(&err) {
        let cause = agentlink_core::error::decorate_transient_tls(&message);
        let cause = if cause == message {
            format!("{message}; {MIRROR_DOWNLOAD_TIP}")
        } else {
            cause
        };
        return anyhow!(
            "{}; {SIGNATURE_FLAP_TIP}",
            rewrite_signature_absence_claim(&cause)
        );
    }
    let tls = agentlink_core::error::decorate_transient_tls(&message);
    if tls != message {
        return anyhow!(tls);
    }
    if message.contains(MIRROR_DOWNLOAD_MARKER) {
        return err;
    }
    if looks_like_transient_mirror_download(&message) {
        return anyhow!("{message}; {MIRROR_DOWNLOAD_TIP}");
    }
    err
}

const MIRROR_DOWNLOAD_ATTEMPTS: usize = 3;
const MIRROR_DOWNLOAD_BACKOFF: Duration = Duration::from_millis(300);

async fn download_mirror(url: &str) -> Result<Vec<u8>> {
    retry_transient_mirror(MIRROR_DOWNLOAD_ATTEMPTS, MIRROR_DOWNLOAD_BACKOFF, || {
        download(url, None)
    })
    .await
}

/// Retry a mirror download a few times on connection-level flaps. Permanent
/// failures (404, checksum mismatch, TLS trust) return on the first attempt.
async fn retry_transient_mirror<F, Fut>(
    attempts: usize,
    backoff: Duration,
    mut op: F,
) -> Result<Vec<u8>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(bytes) => return Ok(bytes),
            Err(err) if attempt < attempts.max(1) && is_transient_mirror_error(&err) => {
                tokio::time::sleep(backoff).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn download_named(
    repo: &str,
    release: &Release,
    name: &str,
    authorization: Option<&str>,
) -> Result<Vec<u8>> {
    if let Some(asset) = release.assets.iter().find(|asset| asset.name == name) {
        return download_asset(asset, authorization)
            .await
            .with_context(|| format!("download {name}"))
            .map_err(decorate_transient_tls_anyhow);
    }
    let url = format!(
        "https://github.com/{repo}/releases/download/{}/{name}",
        release.tag_name
    );
    download(&url, authorization)
        .await
        .with_context(|| format!("download {name}"))
        .map_err(decorate_transient_tls_anyhow)
}

async fn download_asset(asset: &Asset, authorization: Option<&str>) -> Result<Vec<u8>> {
    let url = asset_download_url(asset, authorization.is_some());
    download(&url, authorization).await
}

fn asset_download_url(asset: &Asset, authorized: bool) -> String {
    if authorized {
        if let Some(api) = asset
            .url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty() && u.starts_with("https://api.github.com/"))
        {
            return api.to_string();
        }
    }
    asset.browser_download_url.clone()
}

async fn verify_signature(
    repo: &str,
    release: &Release,
    sums: &[u8],
    pubkey: Option<&signature::PublicKey>,
    authorization: Option<&str>,
) -> Result<bool> {
    let Some(public) = pubkey else {
        return Ok(false);
    };
    let sig = download_named(repo, release, SIG_NAME, authorization)
        .await
        .map_err(release_signature_context)?;
    let text = String::from_utf8(sig).context("signature file is not utf-8")?;
    signature::verify(public, sums, &text)?;
    Ok(true)
}

fn verify_checksum(name: &str, bytes: &[u8], sums: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(sums).context("SHA256SUMS is not utf-8")?;
    let want =
        checksum_for(text, name).ok_or_else(|| anyhow!("SHA256SUMS has no entry for {name}"))?;
    let got = agentlink_core::util::sha256_hex(bytes);
    if !hex_eq(&got, &want) {
        bail!("checksum mismatch for {name}");
    }
    Ok(())
}

fn checksum_for(sums: &str, name: &str) -> Option<String> {
    for (hex, file) in parse_checksums(sums) {
        if file == name {
            return Some(hex);
        }
    }
    None
}

fn parse_checksums(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut parts = line.split_whitespace();
            let hex = parts.next()?.to_ascii_lowercase();
            let mut file = parts.next()?.to_string();
            if parts.next().is_some()
                || hex.len() != 64
                || !hex.chars().all(|c| c.is_ascii_hexdigit())
            {
                return None;
            }
            if let Some(stripped) = file.strip_prefix('*') {
                file = stripped.to_string();
            }
            Some((hex, file))
        })
        .collect()
}

fn hex_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn choose_asset<'a>(release: &'a Release, names: &[String]) -> Result<&'a Asset> {
    for name in names {
        if let Some(asset) = release.assets.iter().find(|asset| &asset.name == name) {
            return Ok(asset);
        }
    }
    let have = release
        .assets
        .iter()
        .map(|asset| asset.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "release {} has no archive for this machine (looked for {}; found {have})",
        release.tag_name,
        names.join(", ")
    )
}

fn archive_names(version: &str, os: &str, arch: &str) -> Vec<String> {
    candidate_targets(os, arch)
        .into_iter()
        .map(|target| archive_name(version, target))
        .collect()
}

fn archive_name(version: &str, target: &str) -> String {
    let ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("agentlink-{version}-{target}.{ext}")
}

fn candidate_targets(os: &str, arch: &str) -> Vec<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => vec!["x86_64-unknown-linux-musl"],
        ("linux", "aarch64") => vec!["aarch64-unknown-linux-musl"],
        ("windows", "x86_64") => vec!["x86_64-pc-windows-msvc"],
        ("windows", "aarch64") => vec!["aarch64-pc-windows-msvc"],
        ("macos", "x86_64") => vec!["universal-apple-darwin", "x86_64-apple-darwin"],
        ("macos", "aarch64") => vec!["universal-apple-darwin", "aarch64-apple-darwin"],
        _ => Vec::new(),
    }
}

/// Project pin embedded at build time. Releases are signed with the matching
/// secret key; without this fallback a fresh install would report
/// `signature: false` even though the release is signed.
const EMBEDDED_PROJECT_PUBKEY: &str = include_str!("../../../deploy/minisign.pub");

fn resolve_pubkey(args: &UpdateArgs, config_dir: &Path) -> Result<Option<signature::PublicKey>> {
    if let Some(value) = args
        .pubkey
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(Some(signature::load_public_key(value)?));
    }
    let saved = load_update_config(config_dir);
    if let Some(value) = saved.pubkey.filter(|value| !value.trim().is_empty()) {
        return Ok(Some(signature::load_public_key(&value)?));
    }
    if let Some(key) = discover_pubkey(config_dir, current_exe_dir().as_deref()) {
        return Ok(Some(key));
    }
    // Stock builds verify official releases without any local config.
    Ok(Some(embedded_project_pubkey()?))
}

/// Local files checked in order. Missing or invalid entries are skipped so the
/// next candidate (ultimately the embedded pin) still gets a chance.
fn discover_pubkey_files(config_dir: &Path, exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut files = vec![config_dir.join("minisign.pub")];
    if let Some(exe_dir) = exe_dir {
        files.push(exe_dir.join("minisign.pub"));
    }
    if let Some(data_home) = data_home_dir() {
        files.push(data_home.join("agentlink").join("minisign.pub"));
    }
    #[cfg(unix)]
    {
        files.push(PathBuf::from("/usr/local/share/agentlink/minisign.pub"));
        files.push(PathBuf::from("/etc/agentlink/minisign.pub"));
        files.push(PathBuf::from("/usr/share/agentlink/minisign.pub"));
    }
    files
}

fn data_home_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(xdg));
    }
    #[cfg(unix)]
    {
        service::home_dir().map(|home| home.join(".local").join("share"))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn current_exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
}

fn discover_pubkey(config_dir: &Path, exe_dir: Option<&Path>) -> Option<signature::PublicKey> {
    discover_pubkey_files(config_dir, exe_dir)
        .iter()
        .find_map(|file| load_pubkey_file(file))
}

fn load_pubkey_file(path: &Path) -> Option<signature::PublicKey> {
    if !path.is_file() {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    signature::PublicKey::parse(&text).ok()
}

fn embedded_project_pubkey() -> Result<signature::PublicKey> {
    signature::PublicKey::parse(EMBEDDED_PROJECT_PUBKEY)
        .context("embedded minisign project pin (deploy/minisign.pub) is invalid")
}

fn missing_signature_tip() -> &'static str {
    "signature was not checked; tip: place the project pin at ~/.config/agentlink/minisign.pub (see deploy/minisign.pub), or pass --pubkey / set AGENTLINK_UPDATE_PUBKEY"
}

const CHECK_STATUS_UP_TO_DATE: &str = "up_to_date";
const CHECK_STATUS_UPDATE_AVAILABLE: &str = "update_available";

fn already_latest_line(current: &str) -> String {
    format!("agentlink {current} is already the latest")
}

/// Shared `--check` report for the GitHub and mirror paths. Human output
/// always names current and latest, then the checksum/signature result.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckReport<'a> {
    current: &'a str,
    latest: &'a str,
    asset: &'a str,
    newer: bool,
    explicit: bool,
    signature_verified: bool,
    mirror: Option<&'a str>,
    daemon_path: Option<&'a Path>,
}

impl CheckReport<'_> {
    fn update(&self) -> bool {
        self.newer || self.explicit
    }

    fn status(&self) -> &'static str {
        if self.update() {
            CHECK_STATUS_UPDATE_AVAILABLE
        } else {
            CHECK_STATUS_UP_TO_DATE
        }
    }

    fn daemon_tip(&self) -> Option<String> {
        self.daemon_path.map(daemon_sync_tip)
    }

    fn human_lines(&self) -> Vec<String> {
        let via = self
            .mirror
            .map(|base| format!(" via {base}"))
            .unwrap_or_default();
        let mut lines = Vec::new();
        if !self.update() {
            lines.push(already_latest_line(self.current));
            lines.push(format!(
                "up to date (verified {} for {}{via})",
                self.asset, self.latest
            ));
        } else if self.newer {
            lines.push(format!(
                "{} available (current {})",
                self.latest, self.current
            ));
            lines.push(format!("verified {} for {}{via}", self.asset, self.latest));
        } else {
            lines.push(format!(
                "verified {} for {}{via} (current {})",
                self.asset, self.latest, self.current
            ));
        }
        lines.push("checksum: ok".into());
        if self.signature_verified {
            lines.push("signature: ok".into());
        } else {
            lines.push(missing_signature_tip().into());
        }
        if let Some(tip) = self.daemon_tip() {
            lines.push(tip);
        }
        lines
    }

    fn json(&self) -> serde_json::Value {
        let mut value = json!({
            "ok": true,
            "current": self.current,
            "latest": self.latest,
            "asset": self.asset,
            "checksum": true,
            "signature": self.signature_verified,
            "update": self.update(),
            "applied": false,
            "status": self.status(),
        });
        if let Some(base) = self.mirror {
            value["mirror"] = json!(base);
        }
        if let Some(tip) = self.daemon_tip() {
            value["tips"] = json!([tip]);
        }
        value
    }
}

/// Regular-file `agentlink-node-daemon` next to the running binary. A symlink
/// already follows the CLI and a missing sibling is a stock install, so both
/// are skipped (matching [`sync_node_daemon_sibling`]).
#[cfg(unix)]
fn node_daemon_sibling(dir: Option<&Path>) -> Option<PathBuf> {
    let sibling = dir?.join(NODE_DAEMON_NAME);
    let metadata = fs::symlink_metadata(&sibling).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    Some(sibling)
}

#[cfg(not(unix))]
fn node_daemon_sibling(_dir: Option<&Path>) -> Option<PathBuf> {
    None
}

fn daemon_sync_tip(path: &Path) -> String {
    format!(
        "tip: `agentlink update` will also sync {} on apply (slim-bin node unit)",
        path.display()
    )
}

fn load_update_config(dir: &Path) -> UpdateConfig {
    let path = dir.join("update.json");
    let Ok(text) = fs::read_to_string(path) else {
        return UpdateConfig::default();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

fn save_update_config(dir: &Path, config: &UpdateConfig) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(config)?;
    agentlink_core::util::write_secret(&dir.join("update.json"), &bytes)?;
    Ok(())
}

pub fn extract_binary(archive_name: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    if archive_name.ends_with(".zip") {
        extract_zip(bytes)
    } else if archive_name.ends_with(".tar.gz") || archive_name.ends_with(".tgz") {
        extract_tar_gz(bytes)
    } else {
        bail!("unknown release archive {archive_name}");
    }
}

fn extract_zip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(io::Cursor::new(bytes)).context("open zip")?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        // zip 9+: `name()` is fallible (invalid UTF-8 / encoding). Skip bad entries.
        let Ok(name) = file.name() else {
            continue;
        };
        if !is_binary_name(name.as_ref()) {
            continue;
        }
        let mut buf = Vec::new();
        io::copy(&mut file, &mut buf)?;
        if buf.len() > 128 * 1024 * 1024 {
            bail!("archive entry is too large");
        }
        return Ok(buf);
    }
    bail!("zip does not contain agentlink");
}

fn extract_tar_gz(bytes: &[u8]) -> Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().context("read tar")? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if !is_binary_name(&path.to_string_lossy()) {
            continue;
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        if buf.len() > 128 * 1024 * 1024 {
            bail!("archive entry is too large");
        }
        return Ok(buf);
    }
    bail!("archive does not contain agentlink");
}

fn is_binary_name(name: &str) -> bool {
    let name = name.replace('\\', "/");
    if name.split('/').any(|part| part == "..") {
        return false;
    }
    matches!(
        name.rsplit('/').next(),
        Some("agentlink") | Some("agentlink.exe")
    )
}

const RELAY_NAME: &str = "agentlink-relay";

/// Pass-through copy of the CLI used by slim-bin node drop-ins
/// (`ExecStart=/usr/local/bin/agentlink-node-daemon node …`). It is a regular
/// file, not a symlink, so replacing `agentlink` alone leaves the node unit on
/// the old build.
#[cfg(unix)]
const NODE_DAEMON_NAME: &str = "agentlink-node-daemon";

/// What happened during the binary swap, especially which services will be
/// bounced after this process exits.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ApplyReport {
    deferred_restart: bool,
    services: Vec<String>,
    relay_deferred: bool,
    tips: Vec<String>,
}

fn add_apply_fields(value: &mut serde_json::Value, report: &ApplyReport) {
    if let Some(object) = value.as_object_mut() {
        object.insert("deferred_restart".into(), json!(report.deferred_restart));
        object.insert("services".into(), json!(report.services));
        object.insert("tips".into(), json!(report.tips));
        if report.relay_deferred {
            object.insert("relay_deferred_restart".into(), json!(true));
        }
    }
}

fn service_label(service: &service::InstalledService) -> String {
    let base = match service.kind {
        service::ServiceKind::Launchd => service::LAUNCHD_NODE,
        _ => service::NODE_NAME,
    };
    match service.scope {
        Scope::User => base.to_string(),
        Scope::System => format!("{base} (system)"),
    }
}

fn apply_binary(bytes: &[u8]) -> Result<ApplyReport> {
    let current = std::env::current_exe().context("locate the running binary")?;
    let current = fs::canonicalize(&current).unwrap_or(current);
    let installed = service::installed_services();
    let active: Vec<_> = installed
        .iter()
        .filter(|service| service.active)
        .cloned()
        .collect();
    #[cfg(windows)]
    {
        stage_windows_replace(&current, bytes, &active)
    }
    #[cfg(not(windows))]
    {
        // Snapshot the services and relay before replacing the file. Stopping
        // a node unit from inside `agentlink update` would kill this process
        // (it often runs under `agentlink exec`/the node), so every bounce is
        // deferred to a detached helper that waits for this PID to exit.
        let service_env = std::env::var_os("AGENTLINK_SERVICE").is_some();
        let relay = plan_relay_restart(&current, service_env);
        let mut jobs: Vec<DeferredJob> = Vec::new();
        if relay.defer {
            jobs.push(DeferredJob::relay());
        }
        jobs.extend(active.iter().filter_map(DeferredJob::from_service));

        replace_unix(&current, bytes).with_context(|| {
            format!(
                "could not replace {}; the running service was not touched and the old binary was left at {}.old",
                current.display(),
                current.display()
            )
        })?;

        let mut report = ApplyReport {
            services: active.iter().map(service_label).collect(),
            ..ApplyReport::default()
        };
        match sync_node_daemon_sibling(&current, bytes) {
            Ok(Some(path)) => report.tips.push(format!(
                "also updated {} (slim-bin node unit)",
                path.display()
            )),
            Ok(None) => {}
            Err(err) => report.tips.push(format!(
                "could not update the slim-bin node daemon next to {}: {err:#}; rerun deploy/install-slim-wrappers.sh",
                current.display()
            )),
        }
        if !jobs.is_empty() {
            let log = current.with_file_name("agentlink.update.log");
            match spawn_deferred_helper(std::process::id(), &jobs, &log) {
                Ok(()) => {
                    report.deferred_restart = true;
                    report.relay_deferred = relay.defer;
                    let mut names: Vec<String> = active.iter().map(service_label).collect();
                    if relay.defer {
                        names.push(RELAY_NAME.to_string());
                    }
                    report.tips.push(format!(
                        "replaced {}; will restart {} after this process exits",
                        current.display(),
                        names.join(", ")
                    ));
                    let bounces_system = relay.defer
                        || active.iter().any(|unit| {
                            unit.kind == service::ServiceKind::Systemd
                                && unit.scope == Scope::System
                        });
                    if bounces_system {
                        report.tips.push(
                            "system-scope units are bounced with `sudo -n systemctl`; passwordless sudo for systemctl is required, or run the restart manually"
                                .into(),
                        );
                    }
                    if active.is_empty() {
                        report.tips.extend(manual_restart_tips(&installed));
                    }
                }
                Err(err) => {
                    report.tips.push(format!(
                        "replaced {}; could not schedule the post-update restart: {err:#}",
                        current.display()
                    ));
                    report.tips.extend(manual_restart_tips(&installed));
                }
            }
        } else {
            report.tips.push(format!(
                "replaced {}; no running {} service was found",
                current.display(),
                service::NODE_NAME
            ));
            report.tips.extend(manual_restart_tips(&installed));
        }
        if let Some(tip) = relay.tip {
            report.tips.push(tip);
        }
        Ok(report)
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DeferredJob {
    label: String,
    /// Command that succeeds when the unit is still running. `None` means
    /// always run `restart`.
    is_active: Option<Vec<String>>,
    restart: Vec<String>,
    start: Vec<String>,
}

#[cfg(unix)]
impl DeferredJob {
    fn from_service(service: &service::InstalledService) -> Option<Self> {
        match service.kind {
            service::ServiceKind::Systemd => {
                let unit = format!("{}.service", service::NODE_NAME);
                let base = systemctl_base(service.scope);
                let mut is_active = base.clone();
                is_active.extend(["is-active".into(), "--quiet".into(), unit.clone()]);
                let mut restart = base.clone();
                restart.extend(["restart".into(), unit.clone()]);
                let mut start = base;
                start.extend(["start".into(), unit]);
                Some(Self {
                    label: service_label(service),
                    is_active: Some(is_active),
                    restart,
                    start,
                })
            }
            service::ServiceKind::Launchd => {
                let target = service::launchd_target(service.scope, service::LAUNCHD_NODE).ok()?;
                Some(Self {
                    label: service_label(service),
                    is_active: Some(vec!["launchctl".into(), "print".into(), target.clone()]),
                    restart: vec![
                        "launchctl".into(),
                        "kickstart".into(),
                        "-k".into(),
                        target.clone(),
                    ],
                    start: vec!["launchctl".into(), "kickstart".into(), target],
                })
            }
            _ => None,
        }
    }

    fn relay() -> Self {
        let unit = format!("{RELAY_NAME}.service");
        let base = systemctl_base(Scope::System);
        let mut restart = base.clone();
        restart.extend(["restart".into(), unit.clone()]);
        let mut start = base;
        start.extend(["start".into(), unit]);
        Self {
            label: RELAY_NAME.to_string(),
            is_active: None,
            restart,
            start,
        }
    }
}

#[cfg(unix)]
fn systemctl_base(scope: Scope) -> Vec<String> {
    if scope == Scope::User {
        vec!["systemctl".into(), "--user".into()]
    } else {
        // The deferred helper runs as the updater user, not root. A
        // system-scope bounce must use non-interactive sudo or polkit rejects
        // it after the updater has already replaced the binary.
        vec!["sudo".into(), "-n".into(), "systemctl".into()]
    }
}

#[cfg(unix)]
fn manual_restart_tips(installed: &[service::InstalledService]) -> Vec<String> {
    if installed.is_empty() {
        return vec![format!(
            "start the node when ready: `systemctl --user restart {0}` or `sudo systemctl restart {0}` (system scope)",
            service::NODE_NAME
        )];
    }
    installed
        .iter()
        .map(|service| match service.kind {
            service::ServiceKind::Systemd => {
                let mut args = if service.scope == Scope::User {
                    vec!["systemctl".to_string(), "--user".into()]
                } else {
                    vec!["sudo".to_string(), "systemctl".into()]
                };
                args.extend(["restart".into(), format!("{}.service", service::NODE_NAME)]);
                format!("restart it manually when ready: `{}`", command_line(&args))
            }
            service::ServiceKind::Launchd => {
                let target = service::launchd_target(service.scope, service::LAUNCHD_NODE)
                    .unwrap_or_else(|_| service::LAUNCHD_NODE.to_string());
                format!("restart it manually when ready: `launchctl kickstart -k {target}`")
            }
            _ => format!("restart {} manually when ready", service::NODE_NAME),
        })
        .collect()
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct RelayPlan {
    defer: bool,
    tip: Option<String>,
}

#[cfg(unix)]
fn plan_relay_restart(replaced: &Path, service_env: bool) -> RelayPlan {
    let unit = format!("{RELAY_NAME}.service");
    let active = agentlink_core::process::hidden("systemctl")
        .args(["is-active", "--quiet", &unit])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    let exec = if active {
        relay_exec_binary(&unit)
    } else {
        None
    };
    relay_plan(replaced, service_env, active, exec)
}

/// Decide whether the relay is deferred. Split from [`plan_relay_restart`] so
/// the `AGENTLINK_SERVICE` gate is testable without touching the environment.
#[cfg(unix)]
fn relay_plan(
    replaced: &Path,
    service_env: bool,
    active: bool,
    exec: Option<PathBuf>,
) -> RelayPlan {
    if !active {
        return RelayPlan::default();
    }
    if service_env {
        // The updater is running under a node unit (or an `agentlink exec`
        // child of one). A shared binary may also serve a relay on another
        // host, so never bounce the local relay from here.
        return RelayPlan {
            defer: false,
            tip: Some(format!(
                "skipping relay restart (AGENTLINK_SERVICE set; restart {RELAY_NAME} manually if this binary serves the relay)"
            )),
        };
    }
    match exec {
        Some(path) if same_binary(&path, replaced) => RelayPlan {
            defer: true,
            // The main "will restart ..." tip names the relay too.
            tip: None,
        },
        Some(path) => RelayPlan {
            defer: false,
            tip: Some(format!(
                "{RELAY_NAME} runs {}; left it running (only {} was replaced)",
                path.display(),
                replaced.display()
            )),
        },
        None => {
            let tip = if replaced == Path::new("/usr/local/bin/agentlink") {
                format!(
                    "could not read {RELAY_NAME} ExecStart; run `systemctl restart {RELAY_NAME}` manually if it uses {}",
                    replaced.display()
                )
            } else {
                format!(
                    "could not read {RELAY_NAME} ExecStart; if it uses this binary, run `systemctl restart {RELAY_NAME}` manually"
                )
            };
            RelayPlan {
                defer: false,
                tip: Some(tip),
            }
        }
    }
}

#[cfg(unix)]
fn relay_exec_binary(unit: &str) -> Option<PathBuf> {
    let output = agentlink_core::process::hidden("systemctl")
        .args(["show", "--property", "ExecStart", "--value", unit])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_exec_start_path(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(unix)]
fn parse_exec_start_path(text: &str) -> Option<PathBuf> {
    let text = text.trim();
    if text.is_empty() || text == "ExecStart=" {
        return None;
    }
    if let Some(index) = text.find("path=") {
        let rest = &text[index + "path=".len()..];
        let end = rest.find([';', ' ']).unwrap_or(rest.len());
        let path = rest[..end].trim();
        return (!path.is_empty()).then(|| PathBuf::from(path));
    }
    text.split_whitespace()
        .next()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

#[cfg(unix)]
fn same_binary(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

#[cfg(unix)]
fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=".contains(c))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(unix)]
fn command_line(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build the detached helper. It waits for the updater to exit (or ~30s),
/// then restarts active units and starts inactive ones.
#[cfg(unix)]
fn build_deferred_helper_script(pid: u32, jobs: &[DeferredJob], log: &Path) -> String {
    let log = shell_quote(&log.to_string_lossy());
    let mut script = String::from("#!/bin/sh\n");
    script.push_str(&format!("log={log}\n"));
    script.push_str(
        "log_line() { printf '%s %s\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)\" \"$*\" >>\"$log\" 2>/dev/null; }\n",
    );
    script.push_str(
        "run() { orig=$*; if \"$@\" >>\"$log\" 2>&1; then log_line \"ok: $*\"; else status=$?; log_line \"failed ($status): $*\"; if [ \"$1\" = sudo ] && [ \"$2\" = -n ]; then shift 2; log_line \"tip: sudo -n failed; grant passwordless sudo for systemctl or restart manually: sudo $*\"; fi; echo \"agentlink update: failed: $orig\" >&2; fi; }\n",
    );
    script.push_str(&format!("log_line \"waiting for updater pid {pid}\"\n"));
    script.push_str(
        "n=0\nwhile kill -0 \"$pid\" 2>/dev/null; do n=$((n+1)); [ \"$n\" -ge 30 ] && break; sleep 1; done\nsleep 1\n",
    );
    for job in jobs {
        script.push_str(&format!(
            "log_line {}\n",
            shell_quote(&format!("bouncing {}", job.label))
        ));
        match &job.is_active {
            Some(check) => script.push_str(&format!(
                "if {} >/dev/null 2>&1; then\n  run {}\nelse\n  run {}\nfi\n",
                command_line(check),
                command_line(&job.restart),
                command_line(&job.start)
            )),
            None => script.push_str(&format!("run {}\n", command_line(&job.restart))),
        }
    }
    script.push_str("log_line \"deferred restart finished\"\n");
    script
}

/// Detached helper launch commands, preferred first.
///
/// `systemd-run --scope` puts the helper in its own transient scope, so a
/// `systemctl restart` that kills the node's service cgroup does not take the
/// helper down before it finishes writing the log and bouncing units. As an
/// unprivileged user the call needs polkit, so passwordless `sudo -n` goes
/// first; plain `systemd-run`, `setsid`, and a bare `sh -c` are fallbacks.
#[cfg(unix)]
fn deferred_launchers(script: &str) -> Vec<(&'static str, Vec<String>)> {
    vec![
        (
            "sudo",
            vec![
                "-n".into(),
                "systemd-run".into(),
                "--scope".into(),
                "--collect".into(),
                "--quiet".into(),
                "sh".into(),
                "-c".into(),
                script.to_string(),
            ],
        ),
        (
            "systemd-run",
            vec![
                "--scope".into(),
                "--collect".into(),
                "--quiet".into(),
                "sh".into(),
                "-c".into(),
                script.to_string(),
            ],
        ),
        ("setsid", vec!["sh".into(), "-c".into(), script.to_string()]),
        ("sh", vec!["-c".into(), script.to_string()]),
    ]
}

/// `systemd-run --scope` supervises the scope in the foreground and exits at
/// once when the bus or permissions reject it. Any exit inside the launch
/// window means the helper never started, so the caller tries the next
/// launcher.
#[cfg(unix)]
fn scope_launched(child: &mut std::process::Child) -> bool {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return false,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return false,
        }
    }
    // Still running: it is waiting for the updater pid. Dropping the handle
    // leaves it detached.
    true
}

#[cfg(unix)]
fn spawn_deferred_helper(pid: u32, jobs: &[DeferredJob], log: &Path) -> Result<()> {
    let script = build_deferred_helper_script(pid, jobs, log);
    let mut first_error: Option<io::Error> = None;
    for (program, args) in deferred_launchers(&script) {
        let spawned = agentlink_core::process::detached(program)
            .args(&args)
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(err) => {
                first_error.get_or_insert(err);
                continue;
            }
        };
        if (program == "sudo" || program == "systemd-run") && !scope_launched(&mut child) {
            continue;
        }
        return Ok(());
    }
    Err(first_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow!("could not start the update restart helper")))
}

#[cfg(unix)]
fn replace_unix(current: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = current
        .parent()
        .ok_or_else(|| anyhow!("binary path has no directory"))?;
    let name = current
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("binary name is not utf-8"))?;
    let new_path = parent.join(format!("{name}.new"));
    let old_path = parent.join(format!("{name}.old"));
    fs::write(&new_path, bytes).with_context(|| format!("write {}", new_path.display()))?;
    fs::set_permissions(&new_path, fs::Permissions::from_mode(0o755))?;
    swap_binary(current, &new_path, &old_path)
}

/// Refresh the slim-bin `agentlink-node-daemon` next to the CLI so the next
/// deferred node restart runs the tip. `agentlink-relay` is deliberately left
/// alone: that path must stay an `exec … relay` shell wrapper, and the exact
/// filename match guarantees it is never a candidate. A symlink already
/// follows the replaced file, and a missing sibling means a stock install
/// whose unit ExecStarts the CLI, so both are no-ops.
#[cfg(unix)]
fn sync_node_daemon_sibling(current: &Path, bytes: &[u8]) -> Result<Option<PathBuf>> {
    let Some(parent) = current.parent() else {
        return Ok(None);
    };
    let sibling = parent.join(NODE_DAEMON_NAME);
    let Ok(metadata) = fs::symlink_metadata(&sibling) else {
        return Ok(None);
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(None);
    }
    replace_unix(&sibling, bytes).with_context(|| format!("replace {}", sibling.display()))?;
    Ok(Some(sibling))
}

#[cfg(unix)]
fn swap_binary(current: &Path, new_path: &Path, old_path: &Path) -> Result<()> {
    let _ = fs::remove_file(old_path);
    fs::rename(current, old_path).with_context(|| format!("move aside {}", current.display()))?;
    if let Err(err) = fs::rename(new_path, current) {
        let _ = fs::rename(old_path, current);
        return Err(err).with_context(|| format!("install {}", current.display()));
    }
    Ok(())
}

#[cfg(windows)]
fn stage_windows_replace(
    current: &Path,
    bytes: &[u8],
    active: &[service::InstalledService],
) -> Result<ApplyReport> {
    for service in active {
        service::stop_installed(service)?;
    }
    let new_path = current.with_extension("exe.new");
    fs::write(&new_path, bytes).with_context(|| format!("write {}", new_path.display()))?;
    let script = current.with_extension("update.cmd");
    let mode = windows_restart_mode(active);
    let body = format!(
        "@echo off\r\n\
set TARGET={target}\r\n\
set SOURCE={source}\r\n\
for /L %%i in (1,1,30) do (\r\n\
  move /Y \"%SOURCE%\" \"%TARGET%\" >nul 2>&1 && goto :moved\r\n\
  timeout /t 1 /nobreak >nul\r\n\
)\r\n\
echo agentlink update could not replace %TARGET% >> \"%TARGET%.update.log\"\r\n\
exit /b 1\r\n\
:moved\r\n\
{restart}\r\n\
del \"%~f0\"\r\n",
        target = current.display(),
        source = new_path.display(),
        restart = mode,
    );
    fs::write(&script, body)?;
    // CREATE_NO_WINDOW only (via process::detached). DETACHED_PROCESS would
    // make Windows ignore CREATE_NO_WINDOW and flash cmd.exe. Dropping the
    // Child does not kill it; the script waits until this process exits and
    // releases the lock Windows keeps on a running executable.
    agentlink_core::process::detached("cmd")
        .arg("/C")
        .arg(&script)
        .spawn()
        .context("start the Windows update helper")?;
    Ok(ApplyReport {
        deferred_restart: true,
        services: active.iter().map(service_label).collect(),
        relay_deferred: false,
        tips: vec![format!(
            "staged {}; it replaces this file after exit",
            current.display()
        )],
    })
}

#[cfg(windows)]
fn windows_restart_mode(active: &[service::InstalledService]) -> String {
    let mut lines = Vec::new();
    for service in active {
        match service.kind {
            service::ServiceKind::WindowsTask => {
                lines.push("schtasks /Run /TN agentlink-node".to_string());
            }
            service::ServiceKind::WindowsRun => {
                let exe =
                    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agentlink.exe"));
                lines.push(format!(
                    "start \"\" \"{}\" tray --background",
                    exe.display()
                ));
            }
            service::ServiceKind::WindowsService => {
                lines.push("sc.exe start agentlink-node".to_string());
            }
            _ => {}
        }
    }
    lines.join("\r\n")
}

pub(crate) fn compare_versions(left: &str, right: &str) -> Ordering {
    let left = parse_version(left);
    let right = parse_version(right);
    match left.parts.cmp(&right.parts) {
        Ordering::Equal => compare_pre(&left.pre, &right.pre),
        other => other,
    }
}

struct ParsedVersion {
    parts: Vec<u64>,
    pre: Vec<String>,
}

fn parse_version(text: &str) -> ParsedVersion {
    let text = text.trim().trim_start_matches('v');
    let text = text.split('+').next().unwrap_or(text);
    let (num, pre) = text.split_once('-').unwrap_or((text, ""));
    let mut parts: Vec<u64> = num
        .split('.')
        .filter(|part| !part.is_empty())
        .map(|part| part.parse().unwrap_or(0))
        .collect();
    while parts.len() < 3 {
        parts.push(0);
    }
    let pre = if pre.is_empty() {
        Vec::new()
    } else {
        pre.split('.').map(str::to_string).collect()
    };
    ParsedVersion { parts, pre }
}

fn compare_pre(left: &[String], right: &[String]) -> Ordering {
    match (left.is_empty(), right.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for (a, b) in left.iter().zip(right.iter()) {
                let order = match (a.parse::<u64>(), b.parse::<u64>()) {
                    (Ok(a), Ok(b)) => a.cmp(&b),
                    _ => a.cmp(b),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
            left.len().cmp(&right.len())
        }
    }
}

fn check_repo(repo: &str) -> Result<()> {
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if parts.next().is_some() || owner.is_empty() || name.is_empty() {
        bail!("--repo must look like owner/name");
    }
    let ok = |text: &str| {
        text.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    };
    if !ok(owner) || !ok(name) {
        bail!("--repo contains unexpected characters");
    }
    Ok(())
}

fn emit(json_mode: bool, value: serde_json::Value, human: impl FnOnce()) {
    if json_mode {
        println!("{value}");
    } else {
        human();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_pubkey_from_config_dir_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("minisign.pub"), EMBEDDED_PROJECT_PUBKEY).unwrap();
        let key = discover_pubkey(dir.path(), None).expect("config-dir minisign.pub");
        assert_eq!(
            key.to_minisign(),
            embedded_project_pubkey().unwrap().to_minisign()
        );
    }

    #[test]
    fn embedded_project_pubkey_parses_without_files() {
        // No local key file: the compiled-in deploy/minisign.pub pin still
        // yields a usable key, so a stock build verifies signed releases.
        let key = embedded_project_pubkey().expect("embedded project pin should parse");
        assert!(key.to_minisign().starts_with("untrusted comment:"));
        assert!(EMBEDDED_PROJECT_PUBKEY.contains("minisign public key"));
    }

    #[test]
    fn missing_signature_tip_is_actionable() {
        let tip = missing_signature_tip();
        assert!(tip.contains("minisign.pub"), "{tip}");
        assert!(tip.contains("--pubkey"), "{tip}");
    }

    fn check_report<'a>(latest: &'a str, newer: bool, explicit: bool) -> CheckReport<'a> {
        CheckReport {
            current: "0.1.128",
            latest,
            asset: "agentlink-linux.tar.gz",
            newer,
            explicit,
            signature_verified: true,
            mirror: None,
            daemon_path: None,
        }
    }

    #[test]
    fn check_report_up_to_date_names_current_and_latest() {
        let report = check_report("0.1.128", false, false);
        let lines = report.human_lines();
        assert_eq!(lines[0], "agentlink 0.1.128 is already the latest");
        assert_eq!(
            lines[1],
            "up to date (verified agentlink-linux.tar.gz for 0.1.128)"
        );
        assert_eq!(lines[2], "checksum: ok");
        assert_eq!(lines[3], "signature: ok");
        assert!(!report.update());
        assert_eq!(report.status(), CHECK_STATUS_UP_TO_DATE);
        let value = report.json();
        assert_eq!(value["ok"], json!(true));
        assert_eq!(value["current"], json!("0.1.128"));
        assert_eq!(value["latest"], json!("0.1.128"));
        assert_eq!(value["asset"], json!("agentlink-linux.tar.gz"));
        assert_eq!(value["checksum"], json!(true));
        assert_eq!(value["signature"], json!(true));
        assert_eq!(value["update"], json!(false));
        assert_eq!(value["applied"], json!(false));
        assert_eq!(value["status"], json!("up_to_date"));
        assert!(value.get("mirror").is_none());
        assert!(value.get("tips").is_none());
    }

    #[test]
    fn check_report_marks_an_available_update() {
        let report = check_report("0.1.129", true, false);
        let lines = report.human_lines();
        assert_eq!(lines[0], "0.1.129 available (current 0.1.128)");
        assert_eq!(lines[1], "verified agentlink-linux.tar.gz for 0.1.129");
        assert!(report.update());
        assert_eq!(report.status(), CHECK_STATUS_UPDATE_AVAILABLE);
        assert_eq!(report.json()["update"], json!(true));
        assert_eq!(
            report.json()["status"],
            json!(CHECK_STATUS_UPDATE_AVAILABLE)
        );
    }

    #[test]
    fn check_report_explicit_pin_keeps_the_verified_line() {
        let report = check_report("0.1.128", false, true);
        let lines = report.human_lines();
        assert_eq!(
            lines[0],
            "verified agentlink-linux.tar.gz for 0.1.128 (current 0.1.128)"
        );
        assert!(report.update());
        assert_eq!(report.status(), CHECK_STATUS_UPDATE_AVAILABLE);
    }

    #[test]
    fn check_report_missing_signature_reuses_the_tip() {
        let mut report = check_report("0.1.128", false, false);
        report.signature_verified = false;
        let lines = report.human_lines();
        assert!(!lines.iter().any(|line| line == "signature: ok"));
        assert_eq!(lines.last().unwrap(), missing_signature_tip());
        assert_eq!(report.json()["signature"], json!(false));
    }

    #[test]
    fn check_report_includes_mirror_and_daemon_tip() {
        let daemon = Path::new("/usr/local/bin/agentlink-node-daemon");
        let mut report = check_report("0.1.129", true, false);
        report.mirror = Some("https://relay.example.com/dl");
        report.daemon_path = Some(daemon);
        let lines = report.human_lines();
        assert_eq!(
            lines[1],
            "verified agentlink-linux.tar.gz for 0.1.129 via https://relay.example.com/dl"
        );
        assert_eq!(lines[3], "signature: ok");
        assert_eq!(lines[4], daemon_sync_tip(daemon));
        let tip = daemon_sync_tip(daemon);
        assert!(tip.contains("agentlink-node-daemon"), "{tip}");
        assert!(tip.contains("on apply"), "{tip}");
        let value = report.json();
        assert_eq!(value["mirror"], json!("https://relay.example.com/dl"));
        assert_eq!(value["tips"], json!([tip]));
    }

    #[cfg(unix)]
    #[test]
    fn daemon_sibling_reports_only_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(node_daemon_sibling(Some(dir.path())), None);
        let sibling = dir.path().join(NODE_DAEMON_NAME);
        fs::write(&sibling, b"daemon").unwrap();
        assert_eq!(node_daemon_sibling(Some(dir.path())), Some(sibling.clone()));
        fs::remove_file(&sibling).unwrap();
        std::os::unix::fs::symlink(dir.path().join("agentlink"), &sibling).unwrap();
        assert_eq!(node_daemon_sibling(Some(dir.path())), None);
        fs::remove_file(&sibling).unwrap();
        fs::create_dir(&sibling).unwrap();
        assert_eq!(node_daemon_sibling(Some(dir.path())), None);
        assert_eq!(node_daemon_sibling(None), None);
    }

    #[test]
    fn versions_order_like_semver() {
        assert_eq!(compare_versions("0.2.0", "0.1.0"), Ordering::Greater);
        assert_eq!(compare_versions("v0.1.0", "0.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.1.9", "0.1.10"), Ordering::Less);
        assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0"), Ordering::Less);
        assert_eq!(
            compare_versions("1.0.0-rc.2", "1.0.0-rc.10"),
            Ordering::Less
        );
        assert_eq!(compare_versions("1.2.3+git", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn github_authorization_prefers_explicit_token() {
        let args = UpdateArgs {
            check: true,
            yes: false,
            auto: false,
            disable_auto: false,
            version: None,
            repo: "zltl/agentlink".into(),
            github_token: Some(" ghp_test ".into()),
            download_base: None,
            pubkey: None,
            checksum_only: false,
            scope: crate::service::Scope::User,
        };
        assert_eq!(
            github_authorization(&args).as_deref(),
            Some("Bearer ghp_test")
        );
        let args = UpdateArgs {
            github_token: Some("token already".into()),
            ..args
        };
        assert_eq!(
            github_authorization(&args).as_deref(),
            Some("token already")
        );
    }

    #[test]
    fn macos_prefers_the_universal_archive() {
        let names = archive_names("0.1.0", "macos", "aarch64");
        assert_eq!(names[0], "agentlink-0.1.0-universal-apple-darwin.tar.gz");
        assert_eq!(
            archive_names("0.1.0", "linux", "x86_64")[0],
            "agentlink-0.1.0-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            archive_names("0.1.0", "windows", "aarch64")[0],
            "agentlink-0.1.0-aarch64-pc-windows-msvc.zip"
        );
    }

    #[test]
    fn checksum_file_matches_gnu_format() {
        let hex = "ab".repeat(32);
        let sums = format!("{hex}  hello.tar.gz\n{hex} *other.zip\n");
        let parsed = parse_checksums(&sums);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].1, "other.zip");
        assert!(checksum_for(&sums, "hello.tar.gz").is_some());
        let bytes = b"hello";
        let got = agentlink_core::util::sha256_hex(bytes);
        let line = format!("{got}  hello.tar.gz\n");
        verify_checksum("hello.tar.gz", bytes, line.as_bytes()).unwrap();
        assert!(verify_checksum("hello.tar.gz", b"nope", line.as_bytes()).is_err());
    }

    #[test]
    fn private_assets_prefer_api_url() {
        let asset = Asset {
            name: "agentlink-0.1.2-x86_64-unknown-linux-musl.tar.gz".into(),
            browser_download_url:
                "https://github.com/zltl/agentlink/releases/download/v0.1.2/a.tar.gz".into(),
            url: Some("https://api.github.com/repos/zltl/agentlink/releases/assets/1".into()),
        };
        assert!(asset_download_url(&asset, true).starts_with("https://api.github.com/"));
        assert!(asset_download_url(&asset, false).starts_with("https://github.com/"));
    }

    #[test]
    fn chooses_the_first_matching_asset() {
        let release = Release {
            tag_name: "v0.1.0".into(),
            assets: vec![
                Asset {
                    name: "agentlink-0.1.0-aarch64-apple-darwin.tar.gz".into(),
                    browser_download_url: "https://example/arm".into(),
                    url: None,
                },
                Asset {
                    name: "agentlink-0.1.0-universal-apple-darwin.tar.gz".into(),
                    browser_download_url: "https://example/uni".into(),
                    url: None,
                },
            ],
        };
        let names = archive_names("0.1.0", "macos", "aarch64");
        let asset = choose_asset(&release, &names).unwrap();
        assert!(asset.name.contains("universal"));
    }

    #[test]
    fn tar_gz_extracts_the_binary_only() {
        let mut raw = Vec::new();
        {
            let encoder = flate2::write::GzEncoder::new(&mut raw, flate2::Compression::default());
            let mut builder = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_path("agentlink").unwrap();
            header.set_size(4);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append(&header, &b"bin!"[..]).unwrap();
            let mut other = tar::Header::new_gnu();
            other.set_path("README").unwrap();
            other.set_size(1);
            other.set_cksum();
            builder.append(&other, &b"x"[..]).unwrap();
            builder.finish().unwrap();
            builder.into_inner().unwrap().finish().unwrap();
        }
        let got = extract_binary("agentlink-0.1.0-x86_64-unknown-linux-musl.tar.gz", &raw).unwrap();
        assert_eq!(got, b"bin!");
    }

    #[test]
    fn zip_extracts_windows_binary() {
        let mut raw = io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut raw);
            let options = zip::write::SimpleFileOptions::default();
            writer.start_file("agentlink.exe", options).unwrap();
            io::Write::write_all(&mut writer, b"exe!").unwrap();
            writer.finish().unwrap();
        }
        let got =
            extract_binary("agentlink-0.1.0-x86_64-pc-windows-msvc.zip", raw.get_ref()).unwrap();
        assert_eq!(got, b"exe!");
    }

    #[test]
    fn rejects_archive_paths_that_escape() {
        assert!(!is_binary_name("../agentlink"));
        assert!(!is_binary_name("dir/../../agentlink.exe"));
        assert!(is_binary_name("agentlink"));
        assert!(is_binary_name("dist/agentlink.exe"));
    }

    #[test]
    fn mirror_sums_pick_latest_matching_archive() {
        let sums = concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  agentlink-0.1.47-x86_64-unknown-linux-musl.tar.gz\n",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  agentlink-0.1.48-x86_64-unknown-linux-musl.tar.gz\n",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  agentlink-0.1.48-x86_64-pc-windows-msvc.zip\n",
        );
        assert_eq!(
            latest_version_from_sums(sums, "linux", "x86_64").unwrap(),
            "0.1.48"
        );
        assert_eq!(
            latest_version_from_sums(sums, "windows", "x86_64").unwrap(),
            "0.1.48"
        );
        assert!(latest_version_from_sums(sums, "linux", "aarch64").is_err());
        assert_eq!(
            normalize_download_base(Some("https://relay.example.com/dl/")),
            Some("https://relay.example.com/dl".into())
        );
    }

    #[test]
    fn apply_json_fields_are_additive() {
        let report = ApplyReport {
            deferred_restart: true,
            services: vec!["agentlink-node".into()],
            relay_deferred: true,
            tips: vec![
                "also updated /usr/local/bin/agentlink-node-daemon (slim-bin node unit)".into(),
            ],
        };
        let mut value = json!({"ok": true, "applied": true});
        add_apply_fields(&mut value, &report);
        assert_eq!(value["ok"], json!(true));
        assert_eq!(value["applied"], json!(true));
        assert_eq!(value["deferred_restart"], json!(true));
        assert_eq!(value["services"], json!(["agentlink-node"]));
        assert_eq!(value["relay_deferred_restart"], json!(true));
        assert_eq!(
            value["tips"],
            json!(["also updated /usr/local/bin/agentlink-node-daemon (slim-bin node unit)"])
        );
    }

    #[test]
    fn service_labels_include_scope_when_needed() {
        let user = service::InstalledService {
            scope: Scope::User,
            kind: service::ServiceKind::Systemd,
            active: true,
        };
        assert_eq!(service_label(&user), "agentlink-node");
        let system = service::InstalledService {
            scope: Scope::System,
            ..user
        };
        assert_eq!(service_label(&system), "agentlink-node (system)");
    }

    #[test]
    fn download_failures_get_the_transient_tls_tip() {
        let tip = agentlink_core::error::TRANSIENT_TLS_TIP;
        let bare = format!(
            "{:#}",
            decorate_transient_tls_anyhow(anyhow!("tls: tls handshake eof"))
        );
        assert_eq!(bare, format!("tls: tls handshake eof; {tip}"));

        let wrapped =
            anyhow!("download SHA256SUMS from https://relay.example/dl: tls: tls handshake eof");
        let text = format!("{:#}", decorate_transient_tls_anyhow(wrapped));
        assert_eq!(
            text,
            format!(
                "download SHA256SUMS from https://relay.example/dl: tls: tls handshake eof; {tip}"
            )
        );

        // Idempotent, and unrelated errors are untouched.
        assert_eq!(
            format!("{:#}", decorate_transient_tls_anyhow(anyhow!("{text}"))),
            text
        );
        assert_eq!(
            format!(
                "{:#}",
                decorate_transient_tls_anyhow(anyhow!("checksum mismatch for agentlink.tar.gz"))
            ),
            "checksum mismatch for agentlink.tar.gz"
        );
    }

    #[test]
    fn connection_refused_download_gets_the_mirror_tip() {
        let wrapped = anyhow!(
            "download SHA256SUMS from https://127.0.0.1:1: connect 127.0.0.1:1: Connection refused (os error 111)"
        );
        let text = format!("{:#}", decorate_mirror_download_anyhow(wrapped));
        assert!(text.ends_with(MIRROR_DOWNLOAD_TIP), "{text}");
        assert!(
            text.contains("connect 127.0.0.1:1: Connection refused (os error 111)"),
            "{text}"
        );
        assert!(!text.contains("transient relay TLS flap"), "{text}");

        // A decorated error is self-contained: outer Display already carries
        // the cause + tip, so `update --json` shows them too.
        let err = decorate_mirror_download_anyhow(anyhow!(
            "download SHA256SUMS from https://127.0.0.1:1: connect 127.0.0.1:1: Connection refused (os error 111)"
        ));
        assert!(err.to_string().ends_with(MIRROR_DOWNLOAD_TIP), "{err}");
    }

    #[test]
    fn transient_mirror_download_tip_is_idempotent_and_tls_wins() {
        let once =
            anyhow!("download SHA256SUMS from https://relay.example/dl: connect relay.example:443: Connection refused (os error 111); {MIRROR_DOWNLOAD_TIP}");
        let text = format!("{:#}", decorate_mirror_download_anyhow(once));
        assert_eq!(text.matches(MIRROR_DOWNLOAD_TIP).count(), 1, "{text}");

        // TLS flaps keep the TLS tip only, never both.
        let tls = decorate_mirror_download_anyhow(anyhow!("tls: tls handshake eof"));
        let text = format!("{:#}", tls);
        assert!(
            text.ends_with(agentlink_core::error::TRANSIENT_TLS_TIP),
            "{text}"
        );
        assert!(!text.contains(MIRROR_DOWNLOAD_MARKER), "{text}");

        // Permanent failures are untouched.
        for message in [
            "checksum mismatch for agentlink.tar.gz",
            "signature verification failed",
            "GET https://mirror/dl/SHA256SUMS returned 404\nnot found",
            "SHA256SUMS has no archive for this machine (os=linux arch=x86_64)",
        ] {
            let text = format!(
                "{:#}",
                decorate_mirror_download_anyhow(anyhow!("{message}"))
            );
            assert_eq!(text, message);
            assert!(!looks_like_transient_mirror_download(message), "{message}");
        }
    }

    #[test]
    fn tls_flap_on_mirror_signature_keeps_download_context_and_tls_tip() {
        let base = "https://relay.example/dl";
        let err = mirror_signature_context(
            anyhow!("GET {base}/{SIG_NAME}: tls: tls handshake eof"),
            base,
        );
        let text = format!("{:#}", decorate_mirror_download_anyhow(err));
        assert!(
            text.starts_with(&format!("download {SIG_NAME} from {base}")),
            "{text}"
        );
        assert!(text.contains("tls handshake eof"), "{text}");
        assert!(
            text.ends_with(agentlink_core::error::TRANSIENT_TLS_TIP),
            "{text}"
        );
        assert!(!text.contains(NO_SIGNATURE_CLAIM), "{text}");
    }

    #[test]
    fn connection_refused_on_mirror_signature_gets_the_mirror_tip() {
        let base = "https://relay.example/dl";
        let err = mirror_signature_context(
            anyhow!("GET {base}/{SIG_NAME}: connect relay.example:443: Connection refused (os error 111)"),
            base,
        );
        let text = format!("{:#}", decorate_mirror_download_anyhow(err));
        assert!(
            text.starts_with(&format!("download {SIG_NAME} from {base}")),
            "{text}"
        );
        assert!(text.ends_with(MIRROR_DOWNLOAD_TIP), "{text}");
        assert!(!text.contains(NO_SIGNATURE_CLAIM), "{text}");
        assert!(!text.contains("transient relay TLS flap"), "{text}");
    }

    #[test]
    fn missing_mirror_signature_claims_absence_only_on_not_found() {
        let base = "https://relay.example/dl";
        let err = mirror_signature_context(
            anyhow!("GET {base}/{SIG_NAME} returned 404\nnot found"),
            base,
        );
        let text = format!("{:#}", decorate_mirror_download_anyhow(err));
        assert!(
            text.starts_with("this mirror has no signature and a public key is configured"),
            "{text}"
        );
        assert!(text.contains("returned 404"), "{text}");
        assert!(text.contains("--checksum-only"), "{text}");
        assert!(!text.contains("transient relay TLS flap"), "{text}");
        assert!(!text.contains(MIRROR_DOWNLOAD_MARKER), "{text}");
    }

    #[test]
    fn missing_release_signature_claims_absence_only_on_not_found() {
        let missing = release_signature_context(anyhow!(
            "download {SIG_NAME}: GET https://github.com/zltl/agentlink/releases/download/v1/{SIG_NAME} returned 404\nnot found"
        ));
        let text = format!("{:#}", missing);
        assert!(
            text.starts_with("this release has no signature and a public key is configured"),
            "{text}"
        );
        assert!(text.contains("--checksum-only"), "{text}");

        let flap =
            release_signature_context(anyhow!("download {SIG_NAME}: tls: tls handshake eof"));
        let text = format!("{:#}", flap);
        assert_eq!(text, format!("download {SIG_NAME}: tls: tls handshake eof"));
        assert!(!text.contains(NO_SIGNATURE_CLAIM), "{text}");
    }

    #[test]
    fn transient_signature_claim_is_rewritten_to_a_flap_tip() {
        let text = format!(
            "{:#}",
            decorate_mirror_download_anyhow(anyhow!(
                "this mirror has {NO_SIGNATURE_CLAIM}: tls: tls handshake eof"
            ))
        );
        assert!(!text.contains(NO_SIGNATURE_CLAIM), "{text}");
        assert!(text.contains("signature download flapped"), "{text}");
        assert!(text.ends_with(SIGNATURE_FLAP_TIP), "{text}");
        assert!(
            text.contains(agentlink_core::error::TRANSIENT_TLS_TIP),
            "{text}"
        );
    }

    #[tokio::test]
    async fn mirror_download_retries_transient_errors_then_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let out = retry_transient_mirror(3, Duration::from_millis(1), move || {
            let calls = calls.clone();
            async move {
                let attempt = calls.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                if attempt < 3 {
                    Err(anyhow!(
                        "connect 127.0.0.1:1: Connection refused (os error 111)"
                    ))
                } else {
                    Ok(b"ok".to_vec())
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(out, b"ok");
        assert_eq!(seen.load(AtomicOrdering::SeqCst), 3);
    }

    #[tokio::test]
    async fn mirror_download_does_not_retry_permanent_errors() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let err = retry_transient_mirror(3, Duration::from_millis(1), move || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, AtomicOrdering::SeqCst);
                Err(anyhow!("GET https://mirror/dl/SHA256SUMS returned 404"))
            }
        })
        .await
        .unwrap_err();
        assert_eq!(seen.load(AtomicOrdering::SeqCst), 1);
        assert!(format!("{err:#}").contains("returned 404"));
    }

    #[cfg(unix)]
    #[test]
    fn deferred_helper_waits_for_pid_and_bounces_units() {
        let user = service::InstalledService {
            scope: Scope::User,
            kind: service::ServiceKind::Systemd,
            active: true,
        };
        let system = service::InstalledService {
            scope: Scope::System,
            ..user.clone()
        };
        let jobs = vec![
            DeferredJob::from_service(&user).unwrap(),
            DeferredJob::from_service(&system).unwrap(),
            DeferredJob::from_service(&service::InstalledService {
                scope: Scope::User,
                kind: service::ServiceKind::Launchd,
                active: true,
            })
            .unwrap(),
            DeferredJob::relay(),
        ];
        let script = build_deferred_helper_script(
            4242,
            &jobs,
            Path::new("/opt/agentlink/agentlink.update.log"),
        );
        assert!(script.contains("waiting for updater pid 4242"));
        assert!(script.contains("kill -0 \"$pid\""));
        assert!(script.contains("sleep 1"));
        // user-scope jobs stay unprivileged
        assert!(script.contains("systemctl --user is-active --quiet agentlink-node.service"));
        assert!(script.contains("systemctl --user restart agentlink-node.service"));
        assert!(script.contains("systemctl --user start agentlink-node.service"));
        assert!(!script.contains("sudo -n systemctl --user"));
        // system-scope jobs and the relay must use non-interactive sudo
        assert!(script.contains("sudo -n systemctl is-active --quiet agentlink-node.service"));
        assert!(script.contains("sudo -n systemctl restart agentlink-node.service"));
        assert!(script.contains("sudo -n systemctl start agentlink-node.service"));
        assert!(script.contains("sudo -n systemctl restart agentlink-relay.service"));
        assert!(script.contains("launchctl print gui/"));
        assert!(script.contains("launchctl kickstart -k gui/"));
        assert!(script.contains("[ \"$1\" = sudo ] && [ \"$2\" = -n ]"));
        assert!(script
            .contains("sudo -n failed; grant passwordless sudo for systemctl or restart manually"));
        assert!(script.contains("agentlink.update.log"));
        assert!(script.contains(">>\"$log\" 2>&1"));
        let status = agentlink_core::process::hidden("sh")
            .args(["-n", "-c", &script])
            .status()
            .unwrap();
        assert!(status.success(), "helper script is not valid sh:\n{script}");
    }

    #[cfg(unix)]
    #[test]
    fn helper_prefers_sudo_systemd_run_scope_then_falls_back() {
        let launchers = deferred_launchers("echo hi");
        let names: Vec<&str> = launchers.iter().map(|(program, _)| *program).collect();
        assert_eq!(names, vec!["sudo", "systemd-run", "setsid", "sh"]);
        let (program, args) = &launchers[0];
        assert_eq!(*program, "sudo");
        assert_eq!(
            &args[0..5],
            ["-n", "systemd-run", "--scope", "--collect", "--quiet"]
        );
        assert_eq!(args[args.len() - 2], "-c");
        assert_eq!(args.last().unwrap(), "echo hi");
        let (program, args) = &launchers[1];
        assert_eq!(*program, "systemd-run");
        assert_eq!(&args[0..4], ["--scope", "--collect", "--quiet", "sh"]);
        assert_eq!(launchers[2].1, vec!["sh", "-c", "echo hi"]);
        assert_eq!(launchers[3].1, vec!["-c", "echo hi"]);
    }

    #[cfg(unix)]
    #[test]
    fn relay_restart_is_skipped_under_a_node_service() {
        let binary = Path::new("/usr/local/bin/agentlink");
        let matching = Some(binary.to_path_buf());

        // Unset: a relay running the replaced binary is still deferred.
        let deferred = relay_plan(binary, false, true, matching.clone());
        assert!(deferred.defer);
        assert_eq!(deferred.tip, None);

        // Set: never defer, even when the relay ExecStart matches.
        let skipped = relay_plan(binary, true, true, matching);
        assert!(!skipped.defer);
        let tip = skipped.tip.unwrap_or_default();
        assert!(tip.contains("AGENTLINK_SERVICE"));
        assert!(tip.contains("agentlink-relay"));

        // An inactive relay never schedules a restart either way.
        assert!(!relay_plan(binary, false, false, None).defer);
        assert!(!relay_plan(binary, true, false, None).defer);

        // A relay on a different binary keeps the existing "left it running" tip.
        let other = relay_plan(
            binary,
            false,
            true,
            Some(PathBuf::from("/opt/relay/agentlink")),
        );
        assert!(!other.defer);
        assert!(other.tip.unwrap().contains("left it running"));
    }

    #[cfg(unix)]
    #[test]
    fn systemctl_jobs_use_sudo_only_for_system_scope() {
        assert_eq!(systemctl_base(Scope::User).join(" "), "systemctl --user");
        assert_eq!(systemctl_base(Scope::System).join(" "), "sudo -n systemctl");

        let user = service::InstalledService {
            scope: Scope::User,
            kind: service::ServiceKind::Systemd,
            active: true,
        };
        let system = service::InstalledService {
            scope: Scope::System,
            ..user.clone()
        };
        assert_eq!(
            DeferredJob::from_service(&user).unwrap().restart.join(" "),
            "systemctl --user restart agentlink-node.service"
        );
        assert_eq!(
            DeferredJob::from_service(&system)
                .unwrap()
                .restart
                .join(" "),
            "sudo -n systemctl restart agentlink-node.service"
        );
        let relay = DeferredJob::relay();
        assert_eq!(
            relay.restart.join(" "),
            "sudo -n systemctl restart agentlink-relay.service"
        );
        assert_eq!(
            relay.start.join(" "),
            "sudo -n systemctl start agentlink-relay.service"
        );
    }

    #[cfg(unix)]
    #[test]
    fn shell_quoting_is_safe() {
        assert_eq!(
            shell_quote("/usr/local/bin/agentlink"),
            "/usr/local/bin/agentlink"
        );
        assert_eq!(shell_quote("a b'c"), "'a b'\\''c'");
    }

    #[cfg(unix)]
    #[test]
    fn parses_systemctl_exec_start_path() {
        let text = "{ path=/usr/local/bin/agentlink ; argv[]=/usr/local/bin/agentlink relay --data-dir /var/lib/agentlink ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n";
        assert_eq!(
            parse_exec_start_path(text),
            Some(PathBuf::from("/usr/local/bin/agentlink"))
        );
        assert_eq!(
            parse_exec_start_path("/opt/agentlink relay"),
            Some(PathBuf::from("/opt/agentlink"))
        );
        assert_eq!(parse_exec_start_path(""), None);
        assert_eq!(parse_exec_start_path("ExecStart="), None);
    }

    #[cfg(unix)]
    #[test]
    fn replace_unix_keeps_the_previous_binary() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("agentlink");
        fs::write(&current, b"old").unwrap();
        replace_unix(&current, b"new").unwrap();
        assert_eq!(fs::read(&current).unwrap(), b"new");
        assert_eq!(fs::read(dir.path().join("agentlink.old")).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn sync_node_daemon_updates_a_regular_sibling() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("agentlink");
        let daemon = dir.path().join(NODE_DAEMON_NAME);
        fs::write(&current, b"old-cli").unwrap();
        fs::write(&daemon, b"old-daemon").unwrap();
        replace_unix(&current, b"new-cli").unwrap();
        let updated = sync_node_daemon_sibling(&current, b"new-cli").unwrap();
        assert_eq!(updated.as_deref(), Some(daemon.as_path()));
        assert_eq!(fs::read(&current).unwrap(), b"new-cli");
        assert_eq!(fs::read(&daemon).unwrap(), b"new-cli");
        assert_eq!(
            fs::metadata(&daemon).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn sync_node_daemon_skips_a_symlink_to_the_cli() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("agentlink");
        let daemon = dir.path().join(NODE_DAEMON_NAME);
        fs::write(&current, b"old-cli").unwrap();
        std::os::unix::fs::symlink(&current, &daemon).unwrap();
        assert_eq!(
            sync_node_daemon_sibling(&current, b"new-cli").unwrap(),
            None
        );
        assert!(fs::symlink_metadata(&daemon)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&daemon).unwrap(), b"old-cli");
    }

    #[cfg(unix)]
    #[test]
    fn sync_node_daemon_tolerates_a_missing_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("agentlink");
        fs::write(&current, b"old-cli").unwrap();
        assert_eq!(
            sync_node_daemon_sibling(&current, b"new-cli").unwrap(),
            None
        );
        assert_eq!(fs::read(&current).unwrap(), b"old-cli");
    }

    #[cfg(unix)]
    #[test]
    fn sync_node_daemon_leaves_the_relay_wrapper_alone() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("agentlink");
        let relay = dir.path().join(RELAY_NAME);
        fs::write(&current, b"old-cli").unwrap();
        let wrapper = "#!/bin/sh\nexec /usr/local/bin/agentlink relay \"$@\"\n";
        fs::write(&relay, wrapper).unwrap();
        assert_eq!(
            sync_node_daemon_sibling(&current, b"new-cli").unwrap(),
            None
        );
        assert_eq!(fs::read_to_string(&relay).unwrap(), wrapper);
    }

    #[cfg(unix)]
    #[test]
    fn swap_binary_rolls_back_when_the_final_rename_fails() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("agentlink");
        let old = dir.path().join("agentlink.old");
        let missing = dir.path().join("agentlink.missing");
        fs::write(&current, b"old").unwrap();
        assert!(swap_binary(&current, &missing, &old).is_err());
        assert_eq!(fs::read(&current).unwrap(), b"old");
        assert!(!old.exists());
    }
}
