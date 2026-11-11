//! Target-local grant paste / approve UI helpers.
//!
//! These dialogs run on the target machine as the local user. They are not
//! `approve allow/deny` (held destructive ops).
//!
//! `refuse_if_remote_exec` is only a misuse guard: the CLI refuses mutating
//! grant commands while `AGENTLINK_REMOTE_EXEC` is set (the node injects it
//! on exec/pty/shell). It is not a self-authorization boundary. On 2026-11-11
//! 08:17 (Asia/Shanghai, UTC+8) the owner chose to keep this OS user's full
//! shell: after a first local grant of exec/full, the same-UID controller can
//! clear the variable, read `grant-issuer.json`, and mint further grants.
//! That is accepted inherent power, not a bug to green-wash. Revoking the
//! original grant does not undo grants or OS changes already made. The first
//! unauthenticated controller is still refused. See
//! `docs/grant-authorization-boundary.md`.

use agentlink_core::permissions::parse_access;
use anyhow::{anyhow, Result};

/// Set by the node on every exec / pty / shell it spawns.
pub const REMOTE_EXEC_ENV: &str = "AGENTLINK_REMOTE_EXEC";

pub const REMOTE_EXEC_REFUSAL: &str = "已拒绝：检测到 AGENTLINK_REMOTE_EXEC。这只是 CLI 防误用，不是防自授权边界。已有 exec/full 的控制端与本机同 UID，可清除该变量、读取 issuer 私钥或改写 grant 目录。未获准控制端仍不能 exec。请在目标机本地（或已授权的独立 SSH/Cursor，而非 agentlink exec）签发。说明见 docs/grant-authorization-boundary.md。身份码不是 bearer。";

pub const SIGNATURE_DISCLAIMER: &str = "签名只证明控制端持有对应私钥，不证明屏幕上的名称或人员真实性。请用带外渠道核对该 SHA256 指纹后再批准。";

pub const SCOPE_NOTE: &str =
    "请求的 ttl 只约束这份待批，并不强迫目标机授权。目标机可以缩小权限或缩短有效期，不能无声加大。首次批准必须在目标机本地做出；仅粘贴身份码不授权。";

/// Honest contract after the 2026-11-11 08:17 (Asia/Shanghai, UTC+8) choice:
/// keep this OS user's full shell. Shown when the issued or requested policy
/// includes exec/shell. Do not promise that revoke undoes later grants.
pub const EXEC_POWER_NOTE: &str =
    "若签发 exec/shell 或包含它们的权限（如 desktop/full），获准后的控制端与本机同 UID，具有该用户的固有全权，包括读取 issuer 并签发其他授权。撤销本 grant 不能撤销已经据此另建的授权，也不能撤销已经做过的系统改动。AGENTLINK_REMOTE_EXEC 只是防误用，不是防自授权。不承诺不可能的隔离。";

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
    format!(
        "agentlink 目标机本地授权\n\n\
         请求: {request_id}\n\
         控制端公钥指纹: {fingerprint}\n\
         控制端公钥: {grantee_id}\n\
         请求权限: {access}\n\
         若同意，grant 有效期: {ttl_secs} 秒\n\
         请求过期 unix: {exp_unix}\n\n\
         {SIGNATURE_DISCLAIMER}\n\
         {SCOPE_NOTE}\n\
         {EXEC_POWER_NOTE}\n\n\
         Allow 使用本机 issuer 签发 grant。Deny 拒绝。都不是 `agentlink approve allow`（危险操作确认）。issuer 密钥不离开本机，也不会被打印。"
    )
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

/// Graphical (or tty) paste box for a controller identity card.
pub fn paste_card_dialog() -> Result<String> {
    let hint = "请粘贴控制端身份码（agentlink-offer:v1:…）或完整 64 位公钥。\n\n公开身份不是凭证，身份码不是 grant，relay 不能据此授权。";
    if display_ok() && command_exists("zenity") {
        let out = std::process::Command::new("zenity")
            .args([
                "--entry",
                "--title",
                "粘贴控制端身份码",
                "--width",
                "640",
                "--text",
                hint,
            ])
            .output()?;
        if !out.status.success() {
            return Err(anyhow!("已取消粘贴"));
        }
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    if display_ok() && command_exists("kdialog") {
        let out = std::process::Command::new("kdialog")
            .args(["--title", "粘贴控制端身份码", "--inputbox", hint])
            .output()?;
        if !out.status.success() {
            return Err(anyhow!("已取消粘贴"));
        }
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) && !display_ok() {
        return Err(anyhow!(
            "本机没有可用的图形粘贴入口（未找到 zenity/kdialog，且当前不是交互终端）。请安装 zenity，或在目标机本地终端运行 `agentlink grant paste '<身份码>'`。"
        ));
    }
    eprint!("{hint}\n身份码: ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let line = line.trim().to_string();
    if line.is_empty() {
        return Err(anyhow!("身份码为空"));
    }
    Ok(line)
}

/// Local Allow/Deny UI. Never talks to the relay.
pub fn decision_prompt(body: &str) -> Result<bool> {
    if display_ok() && command_exists("zenity") {
        let status = std::process::Command::new("zenity")
            .args([
                "--question",
                "--title",
                "核对指纹后本地批准",
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
        let status = std::process::Command::new("kdialog")
            .args([
                "--yesno",
                body,
                "--yes-label",
                "Allow",
                "--no-label",
                "Deny",
                "--title",
                "核对指纹后本地批准",
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
/// pasting a card alone never authorizes). The graphical path uses an
/// accessible radiolist (not a zenity combo that always starts at the first
/// item) plus a pre-filled ttl entry, then a final confirmation that shows
/// the **actual** scope and ttl about to be signed. Cancel at any of those
/// steps does not issue a grant. The allow path still rejects any increase.
pub fn shrink_grant_prompt(
    requested_policy: &str,
    requested_ttl_secs: u64,
    policy_default: Option<String>,
    ttl_default: Option<String>,
) -> Result<Option<(Option<String>, Option<u64>)>> {
    let _ = policy_default; // listed options come from the request; default is the minimum
    let allowed = allowed_shrink_presets(requested_policy)?;
    if allowed.is_empty() {
        return Err(anyhow!("请求权限 {requested_policy} 没有可签发的缩小项"));
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
        let ttl_out = std::process::Command::new("kdialog")
            .args([
                "--title",
                "缩短有效期后批准",
                "--inputbox",
                "有效期（秒或 5m/1h，只能缩短）",
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
        // Headless: honor the minimum default. Graphical issuance must go
        // through the dialogs above; tests must not skip that UI.
        let ttl_secs = parse_shrink_ttl(&default_ttl)?;
        return Ok(Some((Some(default_policy), Some(ttl_secs))));
    }
    eprint!("{hint}\n权限（回车=默认 {default_policy}）: ");
    let mut policy_line = String::new();
    std::io::stdin().read_line(&mut policy_line)?;
    let policy = {
        let raw = policy_line.trim();
        if raw.is_empty() {
            default_policy.clone()
        } else {
            raw.to_string()
        }
    };
    if !allowed.iter().any(|(n, _)| n == &policy) {
        return Err(anyhow!(
            "权限 `{policy}` 不在可缩小列表中（不能加大请求权限）"
        ));
    }
    eprint!("有效期（回车=默认 {default_ttl}）: ");
    let mut ttl_line = String::new();
    std::io::stdin().read_line(&mut ttl_line)?;
    let ttl_field = if ttl_line.trim().is_empty() {
        default_ttl
    } else {
        ttl_line.trim().to_string()
    };
    let ttl_secs = parse_shrink_ttl(&ttl_field)?;
    eprint!(
        "{}\n确认签发？(yes/no): ",
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
/// is the default (最小，且不能加大请求).
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
    Ok(requested_ttl_secs.to_string())
}

pub fn issue_confirm_body(policy: &str, ttl_secs: u64) -> String {
    let summary = parse_access(policy)
        .map(|p| p.capability_summary())
        .unwrap_or_else(|_| policy.to_string());
    format!(
        "即将签发的权限如下（以此为准，不是上一步未改动的提示）：\n\n\
         权限: {summary}\n\
         有效期: {ttl_secs} 秒\n\n\
         {EXEC_POWER_NOTE}\n\n\
         取消签发不授权，待批请求仍保留。issuer 密钥不会被打印。"
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
    format!(
        "可缩小权限或缩短有效期，不能加大。\n\
         请求权限: {requested_summary}\n\
         请求 ttl: {requested_ttl_secs} 秒\n\
         默认选用最小权限: {default_summary}\n\
         默认有效期: {default_ttl}\n\
         请点下方按钮选用要签发的权限（与最终确认必须一致）。"
    )
}

/// Button label for a shrink-policy choice. The default (minimum) is marked
/// so the first visible action never silently enlarges the request.
pub fn policy_button_label(name: &str, is_default: bool) -> String {
    if is_default {
        format!("选用 {name}（默认最小）")
    } else {
        format!("选用 {name}")
    }
}

/// Parse a [`policy_button_label`] back to the preset name.
pub fn policy_from_button_label(label: &str) -> Option<String> {
    let rest = label.strip_prefix("选用 ")?.trim();
    let name = rest.split('（').next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Accessible policy picker: one AT-SPI-clickable button per allowed preset.
///
/// zenity `--list --radiolist` rows only expose `listitem.scroll-to` and are
/// not selectable via AT-SPI. Push buttons already work in this grant UI, so
/// each allowed policy is a button. The OK button is the minimum default;
/// other presets are `--extra-button`s (stdout is the label; empty stdout is
/// cancel). The final confirm dialog still shows the actual scope and ttl.
fn zenity_policy_buttons(
    hint: &str,
    allowed: &[(String, String)],
    default_policy: &str,
) -> Result<Option<String>> {
    let mut body = hint.to_string();
    body.push_str("\n\n各权限实际能力：");
    for (_, summary) in allowed {
        body.push_str("\n• ");
        body.push_str(summary);
    }
    body.push_str("\n\n请点下方按钮选用要签发的权限。取消签发不授权。");

    let default_label = policy_button_label(default_policy, true);
    let mut args: Vec<String> = [
        "--question",
        "--title",
        "缩小权限后批准",
        "--ok-label",
        default_label.as_str(),
        "--cancel-label",
        "取消签发",
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
    let out = std::process::Command::new("zenity").args(&args).output()?;
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
            "选择了不可用的权限 `{name}`（只能缩小，不能加大请求权限）"
        ));
    }
    Ok(Some(name))
}

fn zenity_ttl_entry(default_ttl: &str) -> Result<Option<String>> {
    let out = std::process::Command::new("zenity")
        .args([
            "--entry",
            "--title",
            "缩短有效期后批准",
            "--width",
            "480",
            "--text",
            "有效期（秒或 5m/1h，只能缩短；框内为将使用的值）",
            "--entry-text",
            default_ttl,
            "--ok-label",
            "下一步",
            "--cancel-label",
            "取消签发",
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
        let status = std::process::Command::new("zenity")
            .args([
                "--question",
                "--title",
                "确认最终签发",
                "--ok-label",
                "确认签发",
                "--cancel-label",
                "取消签发",
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
        let status = std::process::Command::new("kdialog")
            .args([
                "--yesno",
                &body,
                "--yes-label",
                "确认签发",
                "--no-label",
                "取消签发",
                "--title",
                "确认最终签发",
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
        "缩小权限后批准".into(),
        "--radiolist".into(),
        hint.to_string(),
    ];
    for (name, summary) in allowed {
        args.push(name.clone());
        args.push(format!("{name} — {summary}"));
        args.push(if name == default_policy {
            "on".into()
        } else {
            "off".into()
        });
    }
    let out = std::process::Command::new("kdialog").args(&args).output()?;
    if !out.status.success() {
        return Ok(None);
    }
    let mut got = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if got.is_empty() {
        got = default_policy.to_string();
    }
    if !allowed.iter().any(|(n, _)| n == &got) {
        return Err(anyhow!(
            "选择了不可用的权限 `{got}`（只能缩小，不能加大请求权限）"
        ));
    }
    Ok(Some(got))
}

/// Parse `policy|ttl` form output. Empty fields fall back to the supplied defaults.
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
        return Err(anyhow!("有效期不能为空"));
    }
    if let Ok(secs) = raw.parse::<u64>() {
        return Ok(secs);
    }
    // 5m / 1h / 30s style, same letters the CLI accepts.
    let (num, unit) = raw.split_at(raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len()));
    let n: u64 = num.parse().map_err(|_| anyhow!("无法解析有效期 `{raw}`"))?;
    match unit.trim().to_ascii_lowercase().as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => Ok(n),
        "m" | "min" | "mins" | "minute" | "minutes" => Ok(n.saturating_mul(60)),
        "h" | "hr" | "hrs" | "hour" | "hours" => Ok(n.saturating_mul(3600)),
        "d" | "day" | "days" => Ok(n.saturating_mul(86400)),
        _ => Err(anyhow!("无法解析有效期 `{raw}`（用秒，或 5m / 1h）")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_exec_refusal_is_honest_about_the_guard() {
        assert!(REMOTE_EXEC_REFUSAL.contains("AGENTLINK_REMOTE_EXEC"));
        assert!(REMOTE_EXEC_REFUSAL.contains("不是防自授权"));
        assert!(EXEC_POWER_NOTE.contains("固有全权"));
        assert!(EXEC_POWER_NOTE.contains("不能撤销已经据此另建的授权"));
        assert!(EXEC_POWER_NOTE.contains("不是防自授权"));
        assert!(SCOPE_NOTE.contains("仅粘贴身份码不授权"));
        let body = request_prompt_body("r", "SHA256:x", "ab", "desktop", 60, 1);
        assert!(body.contains(EXEC_POWER_NOTE));
        assert!(body.contains("仅粘贴身份码不授权"));
        let confirm = issue_confirm_body("exec", 300);
        assert!(confirm.contains(EXEC_POWER_NOTE));
        assert!(confirm.contains("取消签发不授权"));
        assert!(SIGNATURE_DISCLAIMER.contains("不证明"));
        assert!(SCOPE_NOTE.contains("不能无声加大"));
    }

    #[test]
    fn policy_button_labels_round_trip_and_mark_the_minimum() {
        assert_eq!(
            policy_button_label("read-only", true),
            "选用 read-only（默认最小）"
        );
        assert_eq!(policy_button_label("exec", false), "选用 exec");
        assert_eq!(
            policy_from_button_label("选用 read-only（默认最小）").as_deref(),
            Some("read-only")
        );
        assert_eq!(
            policy_from_button_label("选用 exec").as_deref(),
            Some("exec")
        );
        assert_eq!(policy_from_button_label("取消签发"), None);
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
        assert!(!dnames.contains(&"remote-view")); // remote-view is not a subset of desktop
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
        assert!(body.contains("300 秒"));
        assert!(body.contains("取消签发不授权"));
        let ro = issue_confirm_body("read-only", 60);
        assert!(ro.contains("no exec/shell"));
        assert!(ro.contains("60 秒"));
    }
}
