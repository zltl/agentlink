//! Command allow and deny lists.
//!
//! These match the program name and the full command line. They are not an
//! operating-system sandbox: there is no chroot, seccomp, Seatbelt, or Job
//! Object. A shell that is itself allowed can still run anything the user
//! can run, and a child can leave the working directory. Bubblewrap, seccomp,
//! or a platform sandbox would be a separate program, not this glob list.
//!
//! An empty allow list means "anything not denied". [`baseline_deny`] is the
//! default deny list when `limits.json` is missing. A file the operator wrote
//! replaces it.

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct CommandPolicy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// Destructive commands denied when the operator has not written `limits.json`.
///
/// Allow stays empty, which is the current open-allow semantics: a command
/// runs unless a deny glob matches. This does not confine the process.
pub fn baseline_deny() -> Vec<String> {
    [
        "*mkfs*",
        "dd",
        "dd *",
        "* of=/dev/sd*",
        "* of=/dev/nvme*",
        "* of=/dev/mmcblk*",
        "* of=/dev/vd*",
        "* of=/dev/xvd*",
        "* of=/dev/disk*",
        "*of=/dev/sd*",
        "*of=/dev/nvme*",
        "*of=/dev/mmcblk*",
        "*>/dev/sd*",
        "*> /dev/sd*",
        "*>/dev/nvme*",
        "*> /dev/nvme*",
        "shutdown",
        "shutdown *",
        "*shutdown /s*",
        "*shutdown /r*",
        "*shutdown -h*",
        "*shutdown -r*",
        "*&& shutdown*",
        "*; shutdown*",
        "reboot",
        "reboot *",
        "*&& reboot*",
        "*; reboot*",
        "poweroff",
        "poweroff *",
        "halt",
        "halt *",
        "*systemctl poweroff*",
        "*systemctl reboot*",
        "*systemctl halt*",
        "*systemctl suspend*",
        "*systemctl hibernate*",
        "shred",
        "shred *",
        "*shred */dev/*",
        // Windows destructive disk / power / wipe commands.
        "format",
        "format *",
        "format.com",
        "format.com *",
        "*\\format *",
        "*/format *",
        "*&& format *",
        "*; format *",
        "*/c format *",
        "*format-volume*",
        "diskpart",
        "diskpart *",
        "*diskpart*",
        "*stop-computer*",
        "*restart-computer*",
        "*cipher /w*",
        "*cipher.exe /w*",
        "*cipher */w*",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl CommandPolicy {
    /// Empty allow, plus [`baseline_deny`].
    pub fn baseline() -> Self {
        Self {
            allow: Vec::new(),
            deny: baseline_deny(),
        }
    }

    pub fn allows(&self, program: &str, args: &[String], shell_line: Option<&str>) -> Result<()> {
        let base = program
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(program)
            .to_string();
        let joined = if args.is_empty() {
            program.to_string()
        } else {
            format!("{program} {}", args.join(" "))
        };
        let mut candidates = vec![base, joined, program.to_string()];
        if let Some(line) = shell_line {
            candidates.push(line.to_string());
        }
        for pattern in &self.deny {
            if candidates.iter().any(|text| glob_match(pattern, text)) {
                return Err(Error::PermissionDenied(format!(
                    "command denied by sandbox pattern '{pattern}'"
                )));
            }
        }
        if self.allow.is_empty() {
            return Ok(());
        }
        if candidates
            .iter()
            .any(|text| self.allow.iter().any(|pattern| glob_match(pattern, text)))
        {
            return Ok(());
        }
        Err(Error::PermissionDenied(
            "command is not on the sandbox allow list".into(),
        ))
    }
}

/// `*` and `**` match across `/` and `\` so command rules like `*rm -rf*`
/// match `/bin/rm -rf /` and `cd /tmp && rm -rf /`. `**/` and `**\` match zero
/// or more directory prefixes (so `**/.ssh/**` matches both `.ssh/id_rsa` and
/// `/home/a/.ssh/id_rsa` without matching `/home/a/x.ssh/id_rsa`). `?` matches
/// one byte. Matching is ASCII case-insensitive and runs in polynomial `O(P*T)`
/// time with no exponential backtracking.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let text = text.to_ascii_lowercase();
    glob_dp(pattern.as_bytes(), text.as_bytes())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GlobTok {
    Literal(u8),
    AnyChar,
    /// `*` or `**` — zero or more arbitrary bytes (crossing `/` and `\`).
    AnySeq,
    /// `**/` or `**\` — zero directory segments (at start or right after a
    /// path separator) or any non-empty sequence ending in `/` or `\`.
    AnyDirPrefix,
}

fn is_path_sep(b: u8) -> bool {
    b == b'/' || b == b'\\'
}

fn parse_glob_tokens(pattern: &[u8]) -> Vec<GlobTok> {
    let mut tokens = Vec::with_capacity(pattern.len());
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'*' => {
                let mut stars = 1;
                while i + stars < pattern.len() && pattern[i + stars] == b'*' {
                    stars += 1;
                }
                i += stars;
                if stars >= 2 && i < pattern.len() && is_path_sep(pattern[i]) {
                    i += 1;
                    if tokens.last() != Some(&GlobTok::AnyDirPrefix) {
                        tokens.push(GlobTok::AnyDirPrefix);
                    }
                } else if tokens.last() != Some(&GlobTok::AnySeq) {
                    tokens.push(GlobTok::AnySeq);
                }
            }
            b'?' => {
                tokens.push(GlobTok::AnyChar);
                i += 1;
            }
            b => {
                tokens.push(GlobTok::Literal(b));
                i += 1;
            }
        }
    }
    tokens
}

fn glob_dp(pattern: &[u8], text: &[u8]) -> bool {
    let tokens = parse_glob_tokens(pattern);
    let n = text.len();
    let mut dp = vec![false; n + 1];
    let mut next = vec![false; n + 1];
    dp[0] = true;

    for tok in tokens {
        next.fill(false);
        match tok {
            GlobTok::Literal(ch) => {
                for t in 0..n {
                    if dp[t] && text[t] == ch {
                        next[t + 1] = true;
                    }
                }
            }
            GlobTok::AnyChar => {
                for t in 0..n {
                    if dp[t] {
                        next[t + 1] = true;
                    }
                }
            }
            GlobTok::AnySeq => {
                let mut seen = false;
                for t in 0..=n {
                    if dp[t] {
                        seen = true;
                    }
                    if seen {
                        next[t] = true;
                    }
                }
            }
            GlobTok::AnyDirPrefix => {
                let mut seen = false;
                for t in 0..=n {
                    if dp[t] {
                        if t == 0 || is_path_sep(text[t - 1]) {
                            next[t] = true;
                        }
                        seen = true;
                    }
                    if seen && t > 0 && is_path_sep(text[t - 1]) {
                        next[t] = true;
                    }
                }
            }
        }
        std::mem::swap(&mut dp, &mut next);
    }

    dp[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_wins_and_allow_list_is_closed() {
        let policy = CommandPolicy {
            allow: vec!["echo".into(), "git *".into()],
            deny: vec!["rm*".into(), "*rm -rf*".into()],
        };
        assert!(policy.allows("echo", &[], None).is_ok());
        assert!(policy.allows("/bin/echo", &["hi".into()], None).is_ok());
        assert!(policy.allows("python3", &[], None).is_err());
        assert!(policy.allows("git", &["status".into()], None).is_ok());
        assert!(policy
            .allows("rm", &["-rf".into(), "/".into()], None)
            .is_err());
        let shell = CommandPolicy {
            allow: vec![],
            deny: vec!["*rm -rf*".into()],
        };
        assert!(shell
            .allows("sh", &["-c".into(), "rm -rf /".into()], Some("rm -rf /"))
            .is_err());
        // SEC-10: `*` crosses `/` and `\` so full paths and chained commands match.
        assert!(shell
            .allows("/bin/rm", &["-rf".into(), "/".into()], None)
            .is_err());
        assert!(shell
            .allows(
                "sh",
                &["-c".into(), "cd /tmp && rm -rf /".into()],
                Some("cd /tmp && rm -rf /")
            )
            .is_err());
    }

    #[test]
    fn baseline_denies_disk_and_power_and_still_allows_echo() {
        let policy = CommandPolicy::baseline();
        assert!(policy.allow.is_empty());
        assert!(policy.allows("echo", &["hi".into()], None).is_ok());
        assert!(policy.allows("rm", &["file.txt".into()], None).is_ok());
        assert!(policy
            .allows("git", &["log".into(), "--format=%H".into()], None)
            .is_ok());
        assert!(policy
            .allows("/sbin/mkfs.ext4", &["/dev/sda".into()], None)
            .is_err());
        assert!(policy
            .allows(
                "sh",
                &["-c".into(), "cd /tmp && dd if=/dev/zero of=/dev/sda".into()],
                Some("cd /tmp && dd if=/dev/zero of=/dev/sda")
            )
            .is_err());
        assert!(policy
            .allows("shutdown", &["-h".into(), "now".into()], None)
            .is_err());
        assert!(policy
            .allows(
                "sh",
                &["-c".into(), "cat /etc/passwd > /dev/sda".into()],
                Some("cat /etc/passwd > /dev/sda")
            )
            .is_err());
        // Windows destructive commands in baseline deny.
        assert!(policy
            .allows("format", &["D:".into(), "/fs:NTFS".into()], None)
            .is_err());
        assert!(policy
            .allows("cmd", &["/c".into(), "diskpart".into()], Some("diskpart"))
            .is_err());
        assert!(policy
            .allows(
                "powershell",
                &["-Command".into(), "Stop-Computer -Force".into()],
                Some("Stop-Computer -Force")
            )
            .is_err());
        assert!(policy
            .allows("shutdown", &["/s".into(), "/t".into(), "0".into()], None)
            .is_err());
        assert!(policy
            .allows("cipher", &["/w:C:\\".into()], None)
            .is_err());
    }

    #[test]
    fn glob_stars_and_no_exponential_backtracking() {
        assert!(glob_match("**/.ssh/**", "/home/a/.ssh/id_rsa"));
        assert!(glob_match("**/.ssh/**", ".ssh/id_rsa"));
        assert!(!glob_match("**/.ssh/**", "/home/a/x.ssh/id_rsa"));
        assert!(glob_match("*.pem", "key.pem"));
        assert!(!glob_match("*.pem", "key.pem.old"));
        assert!(glob_match("*rm -rf*", "/bin/rm -rf /"));
        assert!(glob_match("*rm -rf*", "cd /tmp && rm -rf /"));
        assert!(glob_match("*rm -rf*", "C:\\Windows\\rm -rf C:\\"));
        // Pathological pattern that would hang naive recursive glob_rec.
        let pat = "*a".repeat(32) + "*b";
        let text = "a".repeat(120);
        assert!(!glob_match(&pat, &text));
    }
}
