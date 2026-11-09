//! Rules that hold a dangerous operation until a person approves it.
//!
//! The summary is what a human reads. It is sent to the relay in the clear,
//! with the same secret redaction as the audit log, because someone has to
//! see it. File bytes are not included.
//!
//! [`ConfirmPolicy::baseline`] is what a node uses when `confirm.toml` is
//! missing. It asks before a few destructive command lines. It is a glob
//! check, not an operating-system sandbox: an allowed shell can still do
//! anything that user can do. A timeout denies the operation.

use serde::{Deserialize, Serialize};

use crate::protocol::Op;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmPolicy {
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub rules: Vec<ConfirmRule>,
}

fn default_timeout() -> u64 {
    60
}

impl Default for ConfirmPolicy {
    fn default() -> Self {
        Self {
            timeout_secs: 60,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmRule {
    /// `exec`, `remove`, `write`, `pty`, `transfer`, or `any`.
    pub category: String,
    /// Glob against the human summary. Empty matches every op in the category.
    #[serde(default)]
    pub pattern: String,
    /// Ask when a write or remove path is outside this prefix.
    #[serde(default)]
    pub outside: Option<String>,
    /// Match only recursive deletes.
    #[serde(default)]
    pub recursive: bool,
}

impl ConfirmPolicy {
    /// Hold destructive command lines until `agentlink approve`.
    ///
    /// `rm -rf` is held, not hard-denied, so a person can still allow a
    /// deliberate delete. Disk format, `dd` onto a disk, and power commands
    /// are also held here; the default command deny list blocks them even
    /// after an approval. Other commands are not held.
    pub fn baseline() -> Self {
        let mut rules: Vec<ConfirmRule> = baseline_exec_patterns()
            .into_iter()
            .map(|pattern| ConfirmRule {
                category: "exec".into(),
                pattern: pattern.into(),
                outside: None,
                recursive: false,
            })
            .collect();
        rules.push(ConfirmRule {
            category: "remove".into(),
            pattern: "remove -r /".into(),
            outside: None,
            recursive: true,
        });
        Self {
            timeout_secs: default_timeout(),
            rules,
        }
    }

    pub fn matching(&self, op: &Op) -> Option<&ConfirmRule> {
        let summary = summary_of(op);
        self.rules
            .iter()
            .find(|rule| rule_matches(rule, op, &summary))
    }

    pub fn summary(op: &Op) -> String {
        summary_of(op)
    }
}

/// Exec globs held by [`ConfirmPolicy::baseline`].
///
/// Disk redirects are listed by device family (same idea as
/// [`crate::sandbox::baseline_deny`]). A broad `**/dev/**` used to also match
/// everyday `2>/dev/null` and `of=/dev/zero`, which held harmless commands.
fn baseline_exec_patterns() -> Vec<&'static str> {
    vec![
        "*rm -rf*",
        "*rm -fr*",
        // Agents often split short flags: `rm -r -f` / `rm -f -r` (and -R).
        // Those do not match `*rm -rf*` / `*rm -fr*` and used to delete without hold.
        "*rm -r -f*",
        "*rm -f -r*",
        "*rm -R -f*",
        "*rm -f -R*",
        "*rm -r --force*",
        "*rm --force -r*",
        "*rm -R --force*",
        "*rm --force -R*",
        "*rm --recursive*",
        "*mkfs*",
        // `*` stops at `/`; device paths need `**`.
        "**of=/dev/sd**",
        "**of=/dev/hd**",
        "**of=/dev/vd**",
        "**of=/dev/nvme**",
        "**of=/dev/xvd**",
        "**of=/dev/mmcblk**",
        "**of=/dev/disk/**",
        "**of=/dev/mapper/**",
        "**of=/dev/dm-**",
        "**>/dev/sd**",
        "**>/dev/hd**",
        "**>/dev/vd**",
        "**>/dev/nvme**",
        "**>/dev/xvd**",
        "**>/dev/mmcblk**",
        "**>/dev/disk/**",
        "**>/dev/mapper/**",
        "**>/dev/dm-**",
        "*shutdown*",
        "*reboot*",
        "*poweroff*",
        "*systemctl poweroff*",
        "*systemctl reboot*",
        "*systemctl halt*",
        "**shred**/dev/**",
    ]
}

/// Ensure split-flag `rm -r -f` / `rm -f -r` (and `-R` / `--force`) holds exist
/// on a saved `confirm.toml` that predates those baseline globs.
pub fn migrate_rm_split_flag_patterns(policy: &mut ConfirmPolicy) -> bool {
    const NEED: &[&str] = &[
        "*rm -r -f*",
        "*rm -f -r*",
        "*rm -R -f*",
        "*rm -f -R*",
        "*rm -r --force*",
        "*rm --force -r*",
        "*rm -R --force*",
        "*rm --force -R*",
    ];
    let mut changed = false;
    for pattern in NEED {
        if policy.rules.iter().any(|rule| {
            rule.category.eq_ignore_ascii_case("exec") && rule.pattern == *pattern
        }) {
            continue;
        }
        policy.rules.push(ConfirmRule {
            category: "exec".into(),
            pattern: (*pattern).into(),
            outside: None,
            recursive: false,
        });
        changed = true;
    }
    changed
}

/// Drop the pre-0.1.50 catch-all `/dev` redirect globs from a saved
/// `confirm.toml` and put the disk-specific ones in their place.
pub fn migrate_broad_dev_patterns(policy: &mut ConfirmPolicy) -> bool {
    const BROAD: &[&str] = &["**>/dev/**", "**of=/dev/**"];
    let before = policy.rules.len();
    policy.rules.retain(|rule| {
        !(rule.category.eq_ignore_ascii_case("exec")
            && BROAD.iter().any(|pat| rule.pattern == *pat))
    });
    if policy.rules.len() == before {
        return false;
    }
    for pattern in baseline_exec_patterns() {
        if pattern.contains("/dev/")
            && !policy.rules.iter().any(|rule| {
                rule.category.eq_ignore_ascii_case("exec") && rule.pattern == pattern
            })
        {
            policy.rules.push(ConfirmRule {
                category: "exec".into(),
                pattern: pattern.into(),
                outside: None,
                recursive: false,
            });
        }
    }
    true
}

fn rule_matches(rule: &ConfirmRule, op: &Op, summary: &str) -> bool {
    // Remote grant revoke carries its own issuer signature and is handled by
    // the daemon before policy/confirm; never hold it for human approval.
    if matches!(op, Op::RevokeGrant { .. }) {
        return false;
    }
    let category = rule.category.to_ascii_lowercase();
    let category_ok = category == "any"
        || match op {
            Op::Exec { .. } | Op::BgStart { .. } => category == "exec",
            Op::PtyOpen { .. } | Op::PtyInput { .. } => category == "pty" || category == "exec",
            Op::Remove { .. } => category == "remove" || category == "delete",
            Op::WriteFile { .. } | Op::Mkdir { .. } | Op::Rename { .. } => category == "write",
            _ => false,
        };
    if !category_ok {
        return false;
    }
    if rule.recursive {
        match op {
            Op::Remove { recursive, .. } if *recursive => {}
            _ => return false,
        }
    }
    if let Some(prefix) = &rule.outside {
        let path = op_path(op);
        if path.is_empty() || path_inside(prefix, &path) {
            return false;
        }
    }
    if rule.pattern.is_empty() {
        return true;
    }
    crate::sandbox::glob_match(&rule.pattern, summary)
}

fn op_path(op: &Op) -> String {
    match op {
        Op::WriteFile { path, .. }
        | Op::Remove { path, .. }
        | Op::Mkdir { path, .. }
        | Op::Exec {
            cwd: Some(path), ..
        } => path.clone(),
        Op::Rename { to, .. } => to.clone(),
        _ => String::new(),
    }
}

fn path_inside(prefix: &str, path: &str) -> bool {
    let prefix = prefix.trim_end_matches(['/', '\\']);
    path == prefix
        || path.starts_with(&format!("{prefix}/"))
        || path.starts_with(&format!("{prefix}\\"))
}

fn summary_of(op: &Op) -> String {
    match op {
        Op::Exec {
            program,
            args,
            shell,
            cwd,
            ..
        }
        | Op::BgStart {
            program,
            args,
            shell,
            cwd,
            ..
        } => {
            let cmd = if *shell {
                program.clone()
            } else if args.is_empty() {
                program.clone()
            } else {
                format!("{program} {}", args.join(" "))
            };
            let kind = if matches!(op, Op::Exec { .. }) {
                "exec"
            } else {
                "bg"
            };
            match cwd {
                Some(dir) => format!("{kind} {cmd} (cwd {dir})"),
                None => format!("{kind} {cmd}"),
            }
        }
        Op::Remove { path, recursive } => {
            if *recursive {
                format!("remove -r {path}")
            } else {
                format!("remove {path}")
            }
        }
        Op::WriteFile { path, .. } => format!("write {path}"),
        Op::Rename { from, to } => format!("move {from} -> {to}"),
        Op::PtyOpen { command, .. } => {
            format!("pty {}", command.clone().unwrap_or_else(|| "shell".into()))
        }
        other => other.kind(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec(line: &str) -> Op {
        Op::Exec {
            program: line.into(),
            args: vec![],
            cwd: None,
            env: vec![],
            timeout_ms: None,
            shell: true,
                stdin_b64: None,
        }
    }

    #[test]
    fn rm_and_outside_write_match() {
        let policy = ConfirmPolicy {
            timeout_secs: 5,
            rules: vec![
                ConfirmRule {
                    category: "exec".into(),
                    pattern: "*rm -rf*".into(),
                    outside: None,
                    recursive: false,
                },
                ConfirmRule {
                    category: "write".into(),
                    pattern: String::new(),
                    outside: Some("/work".into()),
                    recursive: false,
                },
            ],
        };
        assert!(policy.matching(&exec("rm -rf /tmp/x")).is_some());
        assert!(policy.matching(&exec("echo hi")).is_none());
        let outside = Op::WriteFile {
            path: "/etc/passwd".into(),
            offset: 0,
            data_b64: String::new(),
            truncate: true,
        };
        assert!(policy.matching(&outside).is_some());
        let inside = Op::WriteFile {
            path: "/work/a.txt".into(),
            offset: 0,
            data_b64: String::new(),
            truncate: true,
        };
        assert!(policy.matching(&inside).is_none());
    }

    #[test]
    fn baseline_holds_destructive_lines_and_not_echo() {
        let policy = ConfirmPolicy::baseline();
        assert!(policy.matching(&exec("echo hi")).is_none());
        assert!(policy.matching(&exec("rm -rf /tmp/x")).is_some());
        assert!(
            policy.matching(&exec("rm -r -f /tmp/x")).is_some(),
            "split short flags must hold"
        );
        assert!(policy.matching(&exec("rm -f -r /tmp/x")).is_some());
        assert!(policy.matching(&exec("rm -R -f /tmp/x")).is_some());
        assert!(policy.matching(&exec("rm -f -R /tmp/x")).is_some());
        assert!(policy.matching(&exec("rm -r --force /tmp/x")).is_some());
        assert!(policy.matching(&exec("mkfs.ext4 /dev/sda")).is_some());
        assert!(policy
            .matching(&exec("dd if=/dev/zero of=/dev/sda"))
            .is_some());
        assert!(policy.matching(&exec("shutdown -h now")).is_some());
        let root = Op::Remove {
            path: "/".into(),
            recursive: true,
        };
        assert!(policy.matching(&root).is_some());
        let local = Op::Remove {
            path: "/tmp/work".into(),
            recursive: true,
        };
        assert!(
            policy.matching(&local).is_none(),
            "a recursive delete of a normal directory is not held by the default"
        );
    }

    fn exec_argv(program: &str, args: &[&str]) -> Op {
        Op::Exec {
            program: program.into(),
            args: args.iter().map(|s| (*s).into()).collect(),
            cwd: None,
            env: vec![],
            timeout_ms: None,
            shell: false,
            stdin_b64: None,
        }
    }

    #[test]
    fn baseline_holds_rm_split_flags_from_argv() {
        let policy = ConfirmPolicy::baseline();
        assert!(policy
            .matching(&exec_argv("rm", &["-r", "-f", "/tmp/x"]))
            .is_some());
        assert!(policy
            .matching(&exec_argv("rm", &["-f", "-r", "/tmp/al-fr-victim"]))
            .is_some());
    }

    fn bg(program: &str, args: &[&str], cwd: Option<&str>, shell: bool) -> Op {
        Op::BgStart {
            program: program.into(),
            args: args.iter().map(|s| (*s).into()).collect(),
            cwd: cwd.map(Into::into),
            env: vec![],
            shell,
            stdin_b64: None,
        }
    }

    #[test]
    fn baseline_holds_bg_destructive_lines_and_not_echo() {
        let policy = ConfirmPolicy::baseline();
        let shell_rm = bg("rm -rf /tmp/x", &[], None, true);
        assert!(policy.matching(&shell_rm).is_some());
        assert_eq!(ConfirmPolicy::summary(&shell_rm), "bg rm -rf /tmp/x");

        let argv_rm = bg("rm", &["-r", "-f", "/tmp/x"], Some("/tmp"), false);
        assert!(
            policy.matching(&argv_rm).is_some(),
            "split short flags in a bg command must hold"
        );
        assert_eq!(
            ConfirmPolicy::summary(&argv_rm),
            "bg rm -r -f /tmp/x (cwd /tmp)"
        );
        assert!(policy.matching(&bg("echo hi", &[], None, true)).is_none());
    }

    #[test]
    fn migrate_rm_split_flag_patterns_adds_missing() {
        let mut policy = ConfirmPolicy {
            timeout_secs: 5,
            rules: vec![ConfirmRule {
                category: "exec".into(),
                pattern: "*rm -rf*".into(),
                outside: None,
                recursive: false,
            }],
        };
        assert!(migrate_rm_split_flag_patterns(&mut policy));
        assert!(policy
            .rules
            .iter()
            .any(|r| r.pattern == "*rm -r -f*"));
        assert!(!migrate_rm_split_flag_patterns(&mut policy));
    }

    #[test]
    fn baseline_ignores_dev_null_redirects_but_holds_disk_writes() {
        let policy = ConfirmPolicy::baseline();
        assert!(
            policy
                .matching(&exec("echo safe 2>/dev/null"))
                .is_none(),
            "2>/dev/null must not trigger confirm"
        );
        assert!(policy
            .matching(&exec("dd if=/dev/zero of=/dev/null"))
            .is_none());
        assert!(policy
            .matching(&exec("cat file >/dev/stdout"))
            .is_none());
        assert!(policy
            .matching(&exec("dd if=/dev/zero of=/dev/nvme0n1"))
            .is_some());
        assert!(policy.matching(&exec("cat x >/dev/sda")).is_some());
    }

    #[test]
    fn migrate_replaces_broad_dev_globs() {
        let mut policy = ConfirmPolicy {
            timeout_secs: 60,
            rules: vec![
                ConfirmRule {
                    category: "exec".into(),
                    pattern: "**>/dev/**".into(),
                    outside: None,
                    recursive: false,
                },
                ConfirmRule {
                    category: "exec".into(),
                    pattern: "**of=/dev/**".into(),
                    outside: None,
                    recursive: false,
                },
                ConfirmRule {
                    category: "exec".into(),
                    pattern: "*rm -rf*".into(),
                    outside: None,
                    recursive: false,
                },
            ],
        };
        assert!(migrate_broad_dev_patterns(&mut policy));
        assert!(!policy.rules.iter().any(|r| r.pattern == "**>/dev/**"));
        assert!(!policy.rules.iter().any(|r| r.pattern == "**of=/dev/**"));
        assert!(policy.rules.iter().any(|r| r.pattern == "**>/dev/sd**"));
        assert!(policy.matching(&exec("echo safe 2>/dev/null")).is_none());
        assert!(policy.matching(&exec("dd of=/dev/sda")).is_some());
        assert!(!migrate_broad_dev_patterns(&mut policy));
    }
}
