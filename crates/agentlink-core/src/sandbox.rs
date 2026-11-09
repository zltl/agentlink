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
        "reboot",
        "reboot *",
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

/// `*` matches within a path segment, `**` matches across segments, `?` is one
/// character. Matching is case-insensitive so `RM` and `rm` share a rule.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let text = text.to_ascii_lowercase();
    glob_rec(pattern.as_bytes(), text.as_bytes())
}

fn glob_rec(pattern: &[u8], text: &[u8]) -> bool {
    let mut p = 0;
    let mut t = 0;
    while p < pattern.len() {
        if pattern[p] == b'*' {
            let double = p + 1 < pattern.len() && pattern[p + 1] == b'*';
            let rest = if double {
                let mut next = p + 2;
                if next < pattern.len() && (pattern[next] == b'/' || pattern[next] == b'\\') {
                    next += 1;
                }
                next
            } else {
                p + 1
            };
            if rest >= pattern.len() {
                return true;
            }
            while t <= text.len() {
                if glob_rec(&pattern[rest..], &text[t..]) {
                    return true;
                }
                if t == text.len() {
                    break;
                }
                if !double && (text[t] == b'/' || text[t] == b'\\') {
                    break;
                }
                t += 1;
            }
            return false;
        }
        if t >= text.len() {
            return false;
        }
        if pattern[p] != b'?' && pattern[p] != text[t] {
            return false;
        }
        p += 1;
        t += 1;
    }
    t == text.len()
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
    }

    #[test]
    fn baseline_denies_disk_and_power_and_still_allows_echo() {
        let policy = CommandPolicy::baseline();
        assert!(policy.allow.is_empty());
        assert!(policy.allows("echo", &["hi".into()], None).is_ok());
        assert!(policy.allows("rm", &["file.txt".into()], None).is_ok());
        assert!(policy
            .allows("mkfs.ext4", &["/dev/sda".into()], None)
            .is_err());
        assert!(policy
            .allows("dd", &["if=/dev/zero".into(), "of=/dev/sda".into()], None)
            .is_err());
        assert!(policy
            .allows("shutdown", &["-h".into(), "now".into()], None)
            .is_err());
        assert!(policy
            .allows(
                "sh",
                &["-c".into(), "echo x > /dev/sda".into()],
                Some("echo x > /dev/sda")
            )
            .is_err());
    }

    #[test]
    fn glob_stars() {
        assert!(glob_match("**/.ssh/**", "/home/a/.ssh/id_rsa"));
        assert!(glob_match("*.pem", "key.pem"));
        assert!(!glob_match("*.pem", "key.pem.old"));
    }
}
