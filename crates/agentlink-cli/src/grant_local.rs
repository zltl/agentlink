//! Target-local grant paste / approve UI helpers.
//!
//! These dialogs run on the target machine as the local user. They are not
//! `approve allow/deny` (held destructive ops).
//!
//! `refuse_if_remote_exec` is only a misuse guard: the CLI refuses mutating
//! grant commands while `AGENTLINK_REMOTE_EXEC` is set (the node injects it
//! on exec/pty/shell). It is not a self-authorization boundary: after a first
//! local grant of exec/full, the same-UID controller can clear the variable,
//! read `grant-issuer.json`, and mint further grants. Revoking the original
//! grant does not undo grants or OS changes already made. The first
//! unauthenticated controller is still refused. See
//! `docs/grant-authorization-boundary.md`.

use agentlink_core::permissions::parse_access;
use anyhow::{anyhow, Result};

/// Set by the node on every exec / pty / shell it spawns.
pub const REMOTE_EXEC_ENV: &str = "AGENTLINK_REMOTE_EXEC";

pub const REMOTE_EXEC_REFUSAL: &str = "refused: AGENTLINK_REMOTE_EXEC is set. This is only a CLI misuse guard, not a self-authorization boundary. A controller with exec/full runs as the same OS user and can unset this variable, read the issuer private key, or modify the grant directory. Unapproved controllers still cannot exec. Issue grants locally on the target machine (or over an independent authorized SSH session, not via agentlink exec). See docs/grant-authorization-boundary.md. An identity card is not a bearer credential.";

pub const SIGNATURE_DISCLAIMER: &str = "A signature only proves the controller holds the matching private key; it does not verify the displayed name or person. Verify this SHA256 fingerprint out-of-band before approving.";

pub const SCOPE_NOTE: &str =
    "The requested ttl only scopes this pending request and does not force approval. The target machine may narrow the policy or shorten the ttl, but never silently enlarge it. First-time approval must happen locally on the target machine; pasting an identity card alone does not authorize access.";

/// Honest contract for exec/shell grants. Shown when the issued or requested
/// policy includes exec/shell. Do not promise that revoke undoes later grants.
pub const EXEC_POWER_NOTE: &str =
    "Issuing exec/shell (or a preset containing them such as desktop/full) gives the approved controller full control as this local OS user (local full control), including reading the issuer key and signing additional grants. Revoking this grant does not undo grants already minted from it or OS changes already made. AGENTLINK_REMOTE_EXEC is only a misuse guard, not a self-authorization boundary.";

/// Narrower presets are experimental and must not be sold as isolation.
pub const EXPERIMENTAL_SCOPE_NOTE: &str =
    "Narrower presets (such as read-only, read-write, or remote-view) are experimental and are not a security sandbox or isolation boundary. File writes can still modify code executed later.";

pub fn remote_exec_is_set() -> bool {
    std::env::var_os(REMOTE_EXEC_ENV).is_some()
}

pub fn refuse_if_remote_exec() -> Result<()> {
    if remote_exec_is_set() {
        Err(anyhow!(REMOTE_EXEC_REFUSAL))
    } else {
        Ok(())
    }
}

pub fn request_prompt_body(
    request_id: &str,
    fingerprint: &str,
    grantee_id: &str,
    access: &str,
    ttl_secs: u64,
    exp_unix: i64,
) -> String {
    let power_note = power_note_for_access(access);
    format!(
        "Agentlink local node authorization\n\n\
         Request: {request_id}\n\
         Controller key fingerprint: {fingerprint}\n\
         Controller public key: {grantee_id}\n\
         Requested access: {access}\n\
         Grant ttl if allowed: {}\n\
         Request expires unix: {exp_unix}\n\n\
         {SIGNATURE_DISCLAIMER}\n\
         {SCOPE_NOTE}\n\
         {power_note}\n\n\
         Allow signs a grant using this node's local issuer. Deny rejects the request. Neither is `agentlink approve allow` (held destructive ops). The issuer key never leaves this machine and is never printed.",
        agentlink_core::grant::format_ttl_summary(ttl_secs)
    )
}

/// EXEC power note when the access string (preset or summary) implies shell;
/// otherwise the experimental / not-isolation note.
pub fn power_note_for_access(access: &str) -> &'static str {
    if access_implies_exec(access) {
        EXEC_POWER_NOTE
    } else {
        EXPERIMENTAL_SCOPE_NOTE
    }
}

fn access_implies_exec(access: &str) -> bool {
    if let Ok(policy) = parse_access(access) {
        return policy.allow_exec;
    }
    let lower = access.to_ascii_lowercase();
    lower.contains("exec/shell")
        || lower.contains("local full control")
        || lower
            .split(|c: char| c == '(' || c == ';' || c == ',' || c.is_whitespace())
            .any(|tok| matches!(tok, "exec" | "desktop" | "full"))
}

fn display_ok() -> bool {
    std::env::var_os("DISPLAY")
        .or_else(|| std::env::var_os("WAYLAND_DISPLAY"))
        .is_some()
}

fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

/// Visible local grant dialog process (zenity / kdialog).
fn grant_ui_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    std::process::Command::new(program) // no-window-reviewed: visible Unix grant UI; do not hide
}

/// Graphical (or tty) paste box for a controller identity card.
pub fn paste_card_dialog() -> Result<String> {
    let hint = "Paste the controller identity card (agentlink-offer:v1:...) or full 64-hex public key.\n\nA public identity is not a credential, an offer card is not a grant, and the relay cannot authorize access from it.";
    if display_ok() && command_exists("zenity") {
        let out = grant_ui_command("zenity")
            .args([
                "--entry",
                "--title",
                "Paste controller identity card",
                "--width",
                "640",
                "--text",
                hint,
            ])
            .output()?;
        if !out.status.success() {
            return Err(anyhow!("paste cancelled"));
        }
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    if display_ok() && command_exists("kdialog") {
        let out = grant_ui_command("kdialog")
            .args(["--title", "Paste controller identity card", "--inputbox", hint])
            .output()?;
        if !out.status.success() {
            return Err(anyhow!("paste cancelled"));
        }
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) && !display_ok() {
        return Err(anyhow!(
            "no graphical paste dialog available (zenity/kdialog not found and stdin is not a terminal). Run `agentlink grant paste '<card>'` on the target node host."
        ));
    }
    eprint!("{hint}\nIdentity card: ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let line = line.trim().to_string();
    if line.is_empty() {
        return Err(anyhow!("identity card is empty"));
    }
    Ok(line)
}

/// Local Allow/Deny UI. Never talks to the relay.
pub fn decision_prompt(body: &str) -> Result<bool> {
    if display_ok() && command_exists("zenity") {
        let status = grant_ui_command("zenity")
            .args([
                "--question",
                "--title",
                "Verify fingerprint and approve locally",
                "--ok-label",
                "Allow",
                "--cancel-label",
                "Deny",
                "--no-wrap",
                "--width",
                "620",
                "--text",
                body,
            ])
            .status()?;
        return Ok(status.success());
    }
    if display_ok() && command_exists("kdialog") {
        let status = grant_ui_command("kdialog")
            .args([
                "--yesno",
                body,
                "--yes-label",
                "Allow",
                "--no-label",
                "Deny",
                "--title",
                "Verify fingerprint and approve locally",
            ])
            .status()?;
        return Ok(status.success());
    }
    eprint!("{body}\nType allow or deny: ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    match line.trim().to_ascii_lowercase().as_str() {
        "allow" | "a" | "yes" | "y" => Ok(true),
        "deny" | "d" | "no" | "n" => Ok(false),
        other => Err(anyhow!(
            "expected allow or deny, got `{other}`. This prompt only runs on the node host."
        )),
    }
}

/// After an Allow decision, let the local user shrink policy/ttl.
///
/// Returns `Ok(None)` if the user cancels this step (request stays pending;
/// pasting a card alone never authorizes). In headless non-interactive mode,
/// an explicit `--policy` flag (validated as a subset of the request) is honored;
/// otherwise a clear warning is printed before narrowing to the minimum policy
/// so headless callers are never silently downgraded without notice.
pub fn shrink_grant_prompt(
    requested_policy: &str,
    requested_ttl_secs: u64,
    policy_default: Option<String>,
    ttl_default: Option<String>,
) -> Result<Option<(Option<String>, Option<u64>)>> {
    let allowed = allowed_shrink_presets(requested_policy)?;
    if allowed.is_empty() {
        return Err(anyhow!(
            "requested policy `{requested_policy}` has no valid narrowed presets"
        ));
    }
    let default_policy = default_shrink_policy(requested_policy)?;
    let default_ttl = default_shrink_ttl_text(requested_ttl_secs, ttl_default.as_deref())?;
    let hint = shrink_hint(
        requested_policy,
        requested_ttl_secs,
        &default_policy,
        &default_ttl,
        &allowed,
    );

    if display_ok() && command_exists("zenity") {
        let Some(policy) = zenity_policy_buttons(&hint, &allowed, &default_policy)? else {
            return Ok(None);
        };
        let Some(ttl_raw) = zenity_ttl_entry(&default_ttl)? else {
            return Ok(None);
        };
        let ttl_secs = parse_shrink_ttl(&ttl_raw)?;
        if !confirm_issue(&policy, ttl_secs)? {
            return Ok(None);
        }
        return Ok(Some((Some(policy), Some(ttl_secs))));
    }
    if display_ok() && command_exists("kdialog") {
        let Some(policy) = kdialog_policy_radiolist(&hint, &allowed, &default_policy)? else {
            return Ok(None);
        };
        let ttl_out = grant_ui_command("kdialog")
            .args([
                "--title",
                "Shorten grant TTL",
                "--inputbox",
                "TTL (seconds or 5m/1h/7d/1y/permanent; may only be shortened)",
                &default_ttl,
            ])
            .output()?;
        if !ttl_out.status.success() {
            return Ok(None);
        }
        let ttl_raw = String::from_utf8_lossy(&ttl_out.stdout).trim().to_string();
        let ttl_field = if ttl_raw.is_empty() {
            default_ttl.clone()
        } else {
            ttl_raw
        };
        let ttl_secs = parse_shrink_ttl(&ttl_field)?;
        if !confirm_issue(&policy, ttl_secs)? {
            return Ok(None);
        }
        return Ok(Some((Some(policy), Some(ttl_secs))));
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) && !display_ok() {
        let ttl_secs = parse_shrink_ttl(&default_ttl)?;
        let chosen = if let Some(explicit) = policy_default
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !allowed.iter().any(|(n, _)| n == explicit) {
                return Err(anyhow!(
                    "policy `{explicit}` is not an allowed subset of requested `{requested_policy}`"
                ));
            }
            explicit.to_string()
        } else {
            if default_policy != requested_policy {
                eprintln!(
                    "warning: non-interactive headless prompt; narrowing requested policy `{requested_policy}` to `{default_policy}` (pass `--policy <preset>` to explicitly approve a wider allowed subset, or use `agentlink grant allow <request-id>`)"
                );
            }
            default_policy
        };
        return Ok(Some((Some(chosen), Some(ttl_secs))));
    }
    let prompt_default = policy_default
        .as_deref()
        .map(str::trim)
        .filter(|s| allowed.iter().any(|(n, _)| n == s))
        .unwrap_or(&default_policy)
        .to_string();
    eprint!("{hint}\nPolicy (Enter = {prompt_default}): ");
    let mut policy_line = String::new();
    std::io::stdin().read_line(&mut policy_line)?;
    let policy = {
        let raw = policy_line.trim();
        if raw.is_empty() {
            prompt_default
        } else {
            raw.to_string()
        }
    };
    if !allowed.iter().any(|(n, _)| n == &policy) {
        return Err(anyhow!(
            "policy `{policy}` is not in the allowed shrink list (cannot enlarge requested access)"
        ));
    }
    eprint!("TTL (Enter = {default_ttl}): ");
    let mut ttl_line = String::new();
    std::io::stdin().read_line(&mut ttl_line)?;
    let ttl_field = if ttl_line.trim().is_empty() {
        default_ttl
    } else {
        ttl_line.trim().to_string()
    };
    let ttl_secs = parse_shrink_ttl(&ttl_field)?;
    eprint!(
        "{}\nConfirm issue? (yes/no): ",
        issue_confirm_body(&policy, ttl_secs)
    );
    let mut yes = String::new();
    std::io::stdin().read_line(&mut yes)?;
    match yes.trim().to_ascii_lowercase().as_str() {
        "yes" | "y" | "ok" => Ok(Some((Some(policy), Some(ttl_secs)))),
        _ => Ok(None),
    }
}

/// Presets, narrowest first. The first entry that is a subset of the request
/// is the default (minimum allowed; never enlarges the request).
pub const SHRINK_PRESETS: &[&str] = &[
    "read-only",
    "read-write",
    "exec",
    "desktop",
    "remote-view",
    "remote-control",
    "full",
];

/// Policies the target may choose: each is a subset of the request, with a
/// human-readable capability summary (not just the short preset name).
pub fn allowed_shrink_presets(requested_policy: &str) -> Result<Vec<(String, String)>> {
    let requested = parse_access(requested_policy).map_err(|err| anyhow!(err.to_string()))?;
    let mut out = Vec::new();
    for name in SHRINK_PRESETS {
        let policy = parse_access(name).map_err(|err| anyhow!(err.to_string()))?;
        if policy.is_subset_of(requested) {
            out.push(((*name).to_string(), policy.capability_summary()));
        }
    }
    if out.is_empty() {
        let policy = parse_access(requested_policy).map_err(|err| anyhow!(err.to_string()))?;
        out.push((
            policy.preset_name().to_string(),
            policy.capability_summary(),
        ));
    }
    Ok(out)
}

/// Narrowest allowed preset (typically `read-only`). Never larger than the request.
pub fn default_shrink_policy(requested_policy: &str) -> Result<String> {
    let allowed = allowed_shrink_presets(requested_policy)?;
    Ok(allowed
        .into_iter()
        .next()
        .map(|(name, _)| name)
        .unwrap_or_else(|| requested_policy.to_string()))
}

/// Prefill the ttl field: honor a shorter CLI value, ignore any increase.
pub fn default_shrink_ttl_text(
    requested_ttl_secs: u64,
    ttl_default: Option<&str>,
) -> Result<String> {
    if let Some(raw) = ttl_default.map(str::trim).filter(|s| !s.is_empty()) {
        let secs = parse_shrink_ttl(raw)?;
        if secs > 0 && secs <= requested_ttl_secs {
            return Ok(raw.to_string());
        }
    }
    if agentlink_core::grant::is_permanent_ttl(requested_ttl_secs) {
        return Ok("permanent".to_string());
    }
    Ok(requested_ttl_secs.to_string())
}

pub fn issue_confirm_body(policy: &str, ttl_secs: u64) -> String {
    let parsed = parse_access(policy).ok();
    let summary = parsed
        .map(|p| p.capability_summary())
        .unwrap_or_else(|| policy.to_string());
    let power_note = parsed
        .map(|p| {
            if p.allow_exec {
                EXEC_POWER_NOTE
            } else {
                EXPERIMENTAL_SCOPE_NOTE
            }
        })
        .unwrap_or_else(|| power_note_for_access(policy));
    let ttl_text = agentlink_core::grant::format_ttl_summary(ttl_secs);
    format!(
        "Grant about to be signed (this final summary is authoritative):\n\n\
         Access: {summary}\n\
         TTL: {ttl_text}\n\n\
         {power_note}\n\n\
         Cancelling does not authorize access; the pending request remains. The issuer key is never printed."
    )
}

fn shrink_hint(
    requested_policy: &str,
    requested_ttl_secs: u64,
    default_policy: &str,
    default_ttl: &str,
    allowed: &[(String, String)],
) -> String {
    let requested_summary = parse_access(requested_policy)
        .map(|p| p.capability_summary())
        .unwrap_or_else(|_| requested_policy.to_string());
    let default_summary = allowed
        .iter()
        .find(|(n, _)| n == default_policy)
        .map(|(_, s)| s.clone())
        .unwrap_or_else(|| default_policy.to_string());
    let requested_ttl_text = agentlink_core::grant::format_ttl_summary(requested_ttl_secs);
    format!(
        "You may narrow access or shorten the TTL, never enlarge it.\n\
         Requested access: {requested_summary}\n\
         Requested TTL: {requested_ttl_text}\n\
         Default minimum access: {default_summary}\n\
         Default TTL: {default_ttl}\n\
         Choose the policy to issue below (verified again in the final confirmation)."
    )
}

/// Button label for a shrink-policy choice. The default (minimum) is marked
/// so the first visible action never silently enlarges the request.
pub fn policy_button_label(name: &str, is_default: bool) -> String {
    if is_default {
        format!("Select {name} (default minimum)")
    } else {
        format!("Select {name}")
    }
}

/// Parse a [`policy_button_label`] back to the preset name.
pub fn policy_from_button_label(label: &str) -> Option<String> {
    let rest = label.strip_prefix("Select ")?.trim();
    let name = rest.split(" (").next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn zenity_policy_buttons(
    hint: &str,
    allowed: &[(String, String)],
    default_policy: &str,
) -> Result<Option<String>> {
    let mut body = hint.to_string();
    body.push_str("\n\nCapabilities per preset:");
    for (_, summary) in allowed {
        body.push_str("\n- ");
        body.push_str(summary);
    }
    body.push_str("\n\nSelect the access level to sign below. Cancelling does not authorize.");

    let default_label = policy_button_label(default_policy, true);
    let mut args: Vec<String> = [
        "--question",
        "--title",
        "Narrow access before approving",
        "--ok-label",
        default_label.as_str(),
        "--cancel-label",
        "Cancel",
        "--width",
        "720",
        "--text",
        body.as_str(),
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let extra_labels: Vec<String> = allowed
        .iter()
        .filter(|(name, _)| name != default_policy)
        .map(|(name, _)| policy_button_label(name, false))
        .collect();
    for label in &extra_labels {
        args.push("--extra-button".into());
        args.push(label.clone());
    }
    let out = grant_ui_command("zenity").args(&args).output()?;
    if out.status.success() {
        return Ok(Some(default_policy.to_string()));
    }
    let got = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if got.is_empty() {
        return Ok(None);
    }
    let name = policy_from_button_label(&got).unwrap_or(got);
    if !allowed.iter().any(|(n, _)| n == &name) {
        return Err(anyhow!(
            "selected policy `{name}` is not allowed (may only narrow requested access)"
        ));
    }
    Ok(Some(name))
}

fn zenity_ttl_entry(default_ttl: &str) -> Result<Option<String>> {
    let out = grant_ui_command("zenity")
        .args([
            "--entry",
            "--title",
            "Shorten grant TTL",
            "--width",
            "480",
            "--text",
            "TTL (seconds or 5m/1h/7d/1y/permanent; may only be shortened)",
            "--entry-text",
            default_ttl,
            "--ok-label",
            "Next",
            "--cancel-label",
            "Cancel",
        ])
        .output()?;
    if !out.status.success() {
        return Ok(None);
    }
    let mut got = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if got.is_empty() {
        got = default_ttl.to_string();
    }
    Ok(Some(got))
}

fn confirm_issue(policy: &str, ttl_secs: u64) -> Result<bool> {
    let body = issue_confirm_body(policy, ttl_secs);
    if display_ok() && command_exists("zenity") {
        let status = grant_ui_command("zenity")
            .args([
                "--question",
                "--title",
                "Confirm grant signing",
                "--ok-label",
                "Confirm & Sign",
                "--cancel-label",
                "Cancel",
                "--no-wrap",
                "--width",
                "640",
                "--text",
                &body,
            ])
            .status()?;
        return Ok(status.success());
    }
    if display_ok() && command_exists("kdialog") {
        let status = grant_ui_command("kdialog")
            .args([
                "--yesno",
                &body,
                "--yes-label",
                "Confirm & Sign",
                "--no-label",
                "Cancel",
                "--title",
                "Confirm grant signing",
            ])
            .status()?;
        return Ok(status.success());
    }
    Ok(true)
}

fn kdialog_policy_radiolist(
    hint: &str,
    allowed: &[(String, String)],
    default_policy: &str,
) -> Result<Option<String>> {
    let mut args: Vec<String> = vec![
        "--title".into(),
        "Narrow access before approving".into(),
        "--radiolist".into(),
        hint.to_string(),
    ];
    for (name, summary) in allowed {
        args.push(name.clone());
        args.push(format!("{name} -- {summary}"));
        args.push(if name == default_policy {
            "on".into()
        } else {
            "off".into()
        });
    }
    let out = grant_ui_command("kdialog").args(&args).output()?;
    if !out.status.success() {
        return Ok(None);
    }
    let mut got = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if got.is_empty() {
        got = default_policy.to_string();
    }
    if !allowed.iter().any(|(n, _)| n == &got) {
        return Err(anyhow!(
            "selected policy `{got}` is not allowed (may only narrow requested access)"
        ));
    }
    Ok(Some(got))
}

/// Parse `policy|ttl` form output. Empty fields fall back to the supplied defaults.
#[allow(dead_code)]
pub fn parse_shrink_form(
    line: &str,
    default_policy: &str,
    default_ttl: &str,
) -> Result<Option<(Option<String>, Option<u64>)>> {
    let line = line.trim();
    let (policy_raw, ttl_raw) = match line.split_once('|') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (line, ""),
    };
    let policy = if policy_raw.is_empty() {
        default_policy.to_string()
    } else {
        policy_raw.to_string()
    };
    let ttl_field = if ttl_raw.is_empty() {
        default_ttl
    } else {
        ttl_raw
    };
    let ttl_secs = parse_shrink_ttl(ttl_field)?;
    Ok(Some((Some(policy), Some(ttl_secs))))
}

pub fn parse_shrink_ttl(raw: &str) -> Result<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("TTL cannot be empty"));
    }
    if matches!(
        raw.to_ascii_lowercase().as_str(),
        "permanent" | "never" | "forever"
    ) {
        return Ok(agentlink_core::grant::PERMANENT_GRANT_TTL_SECS);
    }
    if let Ok(secs) = raw.parse::<u64>() {
        return Ok(secs);
    }
    let (num, unit) = raw.split_at(raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len()));
    let n: u64 = num.parse().map_err(|_| anyhow!("could not parse TTL `{raw}`"))?;
    match unit.trim().to_ascii_lowercase().as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => Ok(n),
        "m" | "min" | "mins" | "minute" | "minutes" => Ok(n.saturating_mul(60)),
        "h" | "hr" | "hrs" | "hour" | "hours" => Ok(n.saturating_mul(3600)),
        "d" | "day" | "days" => Ok(n.saturating_mul(86400)),
        "w" | "wk" | "wks" | "week" | "weeks" => Ok(n.saturating_mul(604_800)),
        "y" | "yr" | "yrs" | "year" | "years" => Ok(n.saturating_mul(365 * 86_400)),
        _ => Err(anyhow!(
            "could not parse TTL `{raw}` (use seconds, 5m/1h/7d/1y, or permanent)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_exec_refusal_is_honest_about_the_guard() {
        assert!(REMOTE_EXEC_REFUSAL.contains("AGENTLINK_REMOTE_EXEC"));
        assert!(REMOTE_EXEC_REFUSAL.contains("not a self-authorization boundary"));
        assert!(EXEC_POWER_NOTE.contains("local full control"));
        assert!(EXEC_POWER_NOTE.contains("does not undo grants"));
        assert!(EXEC_POWER_NOTE.contains("not a self-authorization boundary"));
        assert!(EXPERIMENTAL_SCOPE_NOTE.contains("experimental"));
        assert!(EXPERIMENTAL_SCOPE_NOTE.contains("not a security sandbox"));
        assert!(SCOPE_NOTE.contains("pasting an identity card alone does not authorize"));
        let body = request_prompt_body("r", "SHA256:x", "ab", "desktop", 60, 1);
        assert!(body.contains(EXEC_POWER_NOTE));
        assert!(body.contains("pasting an identity card alone does not authorize"));
        let confirm = issue_confirm_body("exec", 300);
        assert!(confirm.contains(EXEC_POWER_NOTE));
        assert!(confirm.contains("Cancelling does not authorize"));
        assert!(confirm.contains("exec/shell"));
        assert!(confirm.contains("local full control"));
        let ro = issue_confirm_body("read-only", 60);
        assert!(ro.contains(EXPERIMENTAL_SCOPE_NOTE));
        assert!(!ro.contains(EXEC_POWER_NOTE));
        assert!(ro.contains("no exec/shell"));
        assert!(SIGNATURE_DISCLAIMER.contains("does not verify"));
        assert!(SCOPE_NOTE.contains("never silently enlarge"));
    }

    #[test]
    fn policy_button_labels_round_trip_and_mark_the_minimum() {
        assert_eq!(
            policy_button_label("read-only", true),
            "Select read-only (default minimum)"
        );
        assert_eq!(policy_button_label("exec", false), "Select exec");
        assert_eq!(
            policy_from_button_label("Select read-only (default minimum)").as_deref(),
            Some("read-only")
        );
        assert_eq!(
            policy_from_button_label("Select exec").as_deref(),
            Some("exec")
        );
        assert_eq!(policy_from_button_label("Cancel"), None);
    }

    #[test]
    fn shrink_form_defaults_and_values() {
        let got = parse_shrink_form("", "full", "3600").unwrap().unwrap();
        assert_eq!(got, (Some("full".into()), Some(3600)));
        let got = parse_shrink_form("exec|5m", "full", "3600")
            .unwrap()
            .unwrap();
        assert_eq!(got, (Some("exec".into()), Some(300)));
        let got = parse_shrink_form("|60", "exec", "300").unwrap().unwrap();
        assert_eq!(got, (Some("exec".into()), Some(60)));
    }

    #[test]
    fn allowed_presets_do_not_enlarge_the_request() {
        let exec = allowed_shrink_presets("exec").unwrap();
        let names: Vec<_> = exec.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["read-only", "read-write", "exec"]);
        assert!(exec
            .iter()
            .any(|(n, s)| n == "exec" && s.contains("exec/shell")));
        assert!(exec
            .iter()
            .any(|(n, s)| n == "read-only" && s.contains("no exec/shell")));
        assert!(!names.contains(&"desktop"));
        assert!(!names.contains(&"full"));

        let desktop = allowed_shrink_presets("desktop").unwrap();
        let dnames: Vec<_> = desktop.iter().map(|(n, _)| n.as_str()).collect();
        assert!(dnames.contains(&"read-only"));
        assert!(dnames.contains(&"exec"));
        assert!(dnames.contains(&"desktop"));
        assert!(!dnames.contains(&"full"));
        assert!(!dnames.contains(&"remote-view"));
        let desktop_sum = desktop
            .iter()
            .find(|(n, _)| n == "desktop")
            .unwrap()
            .1
            .clone();
        assert!(desktop_sum.contains("exec/shell"));
        assert!(desktop_sum.contains("screenshots, input, and accessibility"));
        assert!(desktop_sum.contains("no live desktop stream"));
    }

    #[test]
    fn default_policy_is_the_minimum_allowed_and_not_the_request() {
        assert_eq!(default_shrink_policy("desktop").unwrap(), "read-only");
        assert_eq!(default_shrink_policy("exec").unwrap(), "read-only");
        assert_eq!(default_shrink_policy("full").unwrap(), "read-only");
        assert_eq!(default_shrink_policy("read-only").unwrap(), "read-only");
    }

    #[test]
    fn default_ttl_honors_a_shorter_value_and_rejects_an_increase_as_prefill() {
        assert_eq!(default_shrink_ttl_text(3600, Some("5m")).unwrap(), "5m");
        assert_eq!(default_shrink_ttl_text(3600, Some("2h")).unwrap(), "3600");
        assert_eq!(default_shrink_ttl_text(3600, None).unwrap(), "3600");
    }

    #[test]
    fn final_confirm_body_shows_real_scope_and_ttl_and_cancel_does_not_authorize() {
        let body = issue_confirm_body("exec", 300);
        assert!(body.contains("exec ("));
        assert!(body.contains("exec/shell"));
        assert!(body.contains("no screenshots/input") || body.contains("no screenshots"));
        assert!(body.contains("300s"));
        assert!(body.contains("Cancelling does not authorize"));
        assert!(body.contains("local full control"));
        let desktop = issue_confirm_body("desktop", 120);
        assert!(desktop.contains("exec/shell"));
        assert!(desktop.contains("no live desktop stream"));
        assert!(desktop.contains(EXEC_POWER_NOTE));
        let ro = issue_confirm_body("read-only", 60);
        assert!(ro.contains("no exec/shell"));
        assert!(ro.contains("60s"));
        assert!(ro.contains("experimental"));
    }

    #[test]
    fn power_note_follows_real_capability_not_short_name_alone() {
        assert_eq!(power_note_for_access("desktop"), EXEC_POWER_NOTE);
        assert_eq!(power_note_for_access("full"), EXEC_POWER_NOTE);
        assert_eq!(power_note_for_access("read-only"), EXPERIMENTAL_SCOPE_NOTE);
        let summary = parse_access("desktop").unwrap().capability_summary();
        assert!(summary.contains("exec/shell"));
        assert_eq!(power_note_for_access(&summary), EXEC_POWER_NOTE);
    }

    #[test]
    fn shrink_ttl_supports_permanent_weeks_years_and_prefill() {
        assert_eq!(
            parse_shrink_ttl("permanent").unwrap(),
            agentlink_core::grant::PERMANENT_GRANT_TTL_SECS
        );
        assert_eq!(
            parse_shrink_ttl("never").unwrap(),
            agentlink_core::grant::PERMANENT_GRANT_TTL_SECS
        );
        assert_eq!(
            parse_shrink_ttl("forever").unwrap(),
            agentlink_core::grant::PERMANENT_GRANT_TTL_SECS
        );
        assert_eq!(parse_shrink_ttl("2w").unwrap(), 2 * 604_800);
        assert_eq!(parse_shrink_ttl("1y").unwrap(), 365 * 86_400);

        assert_eq!(
            default_shrink_ttl_text(agentlink_core::grant::PERMANENT_GRANT_TTL_SECS, None)
                .unwrap(),
            "permanent"
        );
        assert_eq!(
            default_shrink_ttl_text(
                agentlink_core::grant::PERMANENT_GRANT_TTL_SECS,
                Some("30d")
            )
            .unwrap(),
            "30d"
        );
        let confirm = issue_confirm_body(
            "full",
            agentlink_core::grant::PERMANENT_GRANT_TTL_SECS,
        );
        assert!(confirm.contains("permanent (never expires)"), "{confirm}");
    }
}
