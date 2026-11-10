//! Target-local grant paste / approve UI helpers.
//!
//! These dialogs and the remote-exec guard must run on the target machine as
//! the local user. They are not `approve allow/deny` (held destructive ops)
//! and must not be reachable via `agentlink exec` / pty.

use anyhow::{anyhow, Result};

/// Set by the node on every exec / pty / shell it spawns.
pub const REMOTE_EXEC_ENV: &str = "AGENTLINK_REMOTE_EXEC";

pub const REMOTE_EXEC_REFUSAL: &str = "此 grant 操作必须在目标机由本地用户执行（本机 CLI、图形粘贴入口、或已授权的独立 SSH/Cursor 代执行本地 grant）。不能通过 agentlink exec/pty 远程代签、粘贴身份码或扩大授权。身份码不是 bearer，签名只证明私钥。";

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_exec_refusal_mentions_local_only() {
        assert!(REMOTE_EXEC_REFUSAL.contains("不能通过 agentlink exec"));
        assert!(SIGNATURE_DISCLAIMER.contains("不证明"));
        assert!(SCOPE_NOTE.contains("不能无声加大"));
    }
}
