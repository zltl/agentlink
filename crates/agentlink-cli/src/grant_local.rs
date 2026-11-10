//! Target-local grant paste / approve UI helpers.
//!
//! These dialogs run on the target machine as the local user. They are not
//! `approve allow/deny` (held destructive ops).
//!
//! `refuse_if_remote_exec` is only a misuse guard: the CLI refuses mutating
//! grant commands while `AGENTLINK_REMOTE_EXEC` is set (the node injects it
//! on exec/pty/shell). It is not a self-authorization boundary. A controller
//! that already has exec/full as this OS user can clear the variable, spawn
//! detached, read `grant-issuer.json`, or write grant-authority directories.
//! See `docs/grant-authorization-boundary.md`.

use anyhow::{anyhow, Result};

/// Set by the node on every exec / pty / shell it spawns.
pub const REMOTE_EXEC_ENV: &str = "AGENTLINK_REMOTE_EXEC";

pub const REMOTE_EXEC_REFUSAL: &str = "已拒绝：检测到 AGENTLINK_REMOTE_EXEC。这只是 CLI 防误用，不是防自授权边界。已有 exec/full 的控制端与本机同 UID，可清除该变量、读取 issuer 私钥或改写 grant 目录。未获准控制端仍不能 exec。请在目标机本地（或已授权的独立 SSH/Cursor，而非 agentlink exec）签发。说明见 docs/grant-authorization-boundary.md。身份码不是 bearer。";

pub const SIGNATURE_DISCLAIMER: &str = "签名只证明控制端持有对应私钥，不证明屏幕上的名称或人员真实性。请用带外渠道核对该 SHA256 指纹后再批准。";

pub const SCOPE_NOTE: &str =
    "请求的 ttl 只约束这份待批，并不强迫目标机授权。目标机可以缩小权限或缩短有效期，不能无声加大。";

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
         {SCOPE_NOTE}\n\n\
         Allow 使用本机 issuer 签发 grant。Deny 拒绝。都不是 `agentlink approve allow`（危险操作确认）。issuer 密钥不离开本机。"
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
/// pasting a card alone never authorizes). `policy`/`ttl` CLI values become
/// the form defaults; empty fields keep the requested values. The allow path
/// still rejects any silent increase.
pub fn shrink_grant_prompt(
    requested_policy: &str,
    requested_ttl_secs: u64,
    policy_default: Option<String>,
    ttl_default: Option<String>,
) -> Result<Option<(Option<String>, Option<u64>)>> {
    let default_policy = policy_default
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(requested_policy);
    let default_ttl = ttl_default
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| requested_ttl_secs.to_string());
    let hint = format!(
        "可缩小权限或缩短有效期，不能加大。\n请求权限: {requested_policy}\n请求 ttl: {requested_ttl_secs} 秒\n默认将签发: {default_policy} / {default_ttl}"
    );
    if display_ok() && command_exists("zenity") {
        let out = std::process::Command::new("zenity")
            .args([
                "--forms",
                "--title",
                "缩小权限后批准",
                "--ok-label",
                "签发",
                "--cancel-label",
                "取消签发",
                "--text",
                &hint,
                "--add-combo",
                "权限（只能缩小）",
                "--combo-values",
                "read-only|read-write|exec|desktop|remote-view|remote-control|full",
                "--add-entry",
                "有效期（秒或 5m/1h，只能缩短）",
            ])
            .output()?;
        if !out.status.success() {
            return Ok(None);
        }
        let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
        return parse_shrink_form(&line, default_policy, &default_ttl);
    }
    if display_ok() && command_exists("kdialog") {
        let policy_out = std::process::Command::new("kdialog")
            .args([
                "--title",
                "缩小权限后批准",
                "--inputbox",
                &format!("{hint}\n权限（只能缩小，默认 {default_policy}）"),
                default_policy,
            ])
            .output()?;
        if !policy_out.status.success() {
            return Ok(None);
        }
        let ttl_out = std::process::Command::new("kdialog")
            .args([
                "--title",
                "缩小权限后批准",
                "--inputbox",
                &format!("有效期（只能缩短，默认 {default_ttl}）"),
                &default_ttl,
            ])
            .output()?;
        if !ttl_out.status.success() {
            return Ok(None);
        }
        let policy_s = String::from_utf8_lossy(&policy_out.stdout)
            .trim()
            .to_string();
        let ttl_s = String::from_utf8_lossy(&ttl_out.stdout).trim().to_string();
        return parse_shrink_form(&format!("{policy_s}|{ttl_s}"), default_policy, &default_ttl);
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) && !display_ok() {
        // Headless: honor CLI defaults without a dialog. The allow path still
        // rejects increases. Graphical tests must run on the seat.
        return parse_shrink_form(
            &format!("{default_policy}|{default_ttl}"),
            default_policy,
            &default_ttl,
        );
    }
    eprint!("{hint}\n权限（回车=默认 {default_policy}）: ");
    let mut policy_line = String::new();
    std::io::stdin().read_line(&mut policy_line)?;
    eprint!("有效期（回车=默认 {default_ttl}）: ");
    let mut ttl_line = String::new();
    std::io::stdin().read_line(&mut ttl_line)?;
    parse_shrink_form(
        &format!("{}|{}", policy_line.trim(), ttl_line.trim()),
        default_policy,
        &default_ttl,
    )
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

fn parse_shrink_ttl(raw: &str) -> Result<u64> {
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
        assert!(SIGNATURE_DISCLAIMER.contains("不证明"));
        assert!(SCOPE_NOTE.contains("不能无声加大"));
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
}
