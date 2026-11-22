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

use std::path::{Component, Path, PathBuf};

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
        rules.push(ConfirmRule {
            category: "remove".into(),
            pattern: "remove -r ?:\\".into(),
            outside: None,
            recursive: true,
        });
        rules.push(ConfirmRule {
            category: "remove".into(),
            pattern: "remove -r ?:/".into(),
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

    /// Match a file/directory transfer (`kind` e.g. `"push"`, `"pull"`,
    /// `"push_dir"`, `"push_stream"`) targeting `path` against `transfer`,
    /// `any`, and (for push/write transfers) `write` rules (`SEC-10`).
    pub fn matching_transfer(&self, kind: &str, path: &str) -> Option<&ConfirmRule> {
        let kind_lower = kind.trim().to_ascii_lowercase();
        let is_push_write = matches!(
            kind_lower.as_str(),
            "push" | "push_dir" | "push_stream" | "upload" | "write"
        ) || kind_lower.starts_with("push_");
        let summary = format!("transfer {kind} {path}");
        self.rules.iter().find(|rule| {
            let category = rule.category.to_ascii_lowercase();
            let category_ok = category == "transfer"
                || category == "any"
                || (is_push_write && category == "write");
            if !category_ok {
                return false;
            }
            if rule.recursive {
                return false;
            }
            if let Some(prefix) = &rule.outside {
                if path.is_empty() || path_inside(prefix, path) {
                    return false;
                }
            }
            if rule.pattern.is_empty() {
                return true;
            }
            crate::sandbox::glob_match(&rule.pattern, &summary)
                || (is_push_write
                    && category == "write"
                    && crate::sandbox::glob_match(&rule.pattern, &format!("write {path}")))
        })
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
        // Windows destructive disk, recursive delete, power, and wipe presets (LIVE-05).
        "exec format *",
        "bg format *",
        "*\\format *",
        "*/format *",
        "*&& format *",
        "*; format *",
        "*/c format *",
        "*format.com*",
        "*format-volume*",
        "*diskpart*",
        "* rd /s*",
        "* rd */s*",
        "*&&rd /s*",
        "*&&rd */s*",
        "*rd.exe */s*",
        "*rmdir /s*",
        "*rmdir */s*",
        "*remove-item*-recurse*-force*",
        "*remove-item*-force*-recurse*",
        "*stop-computer*",
        "*restart-computer*",
        "*shutdown /s*",
        "*cipher /w*",
        "*cipher.exe /w*",
        "*cipher */w*",
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
            Op::WriteFile { .. }
            | Op::Mkdir { .. }
            | Op::Rename { .. }
            | Op::Replace { .. }
            | Op::EditLines { .. }
            | Op::ApplyPatch { .. } => category == "write",
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
        let paths = op_paths(op);
        if paths.is_empty() || paths.iter().all(|path| path_inside(prefix, path)) {
            return false;
        }
    }
    if rule.pattern.is_empty() {
        return true;
    }
    crate::sandbox::glob_match(&rule.pattern, summary)
}

fn op_paths(op: &Op) -> Vec<String> {
    match op {
        Op::WriteFile { path, .. }
        | Op::Remove { path, .. }
        | Op::Mkdir { path, .. }
        | Op::Replace { path, .. }
        | Op::EditLines { path, .. }
        | Op::Exec {
            cwd: Some(path), ..
        }
        | Op::BgStart {
            cwd: Some(path), ..
        }
        | Op::PtyOpen {
            cwd: Some(path), ..
        } => vec![path.clone()],
        Op::Rename { from, to } => vec![from.clone(), to.clone()],
        Op::ApplyPatch { root, patch } => {
            let mut out = vec![root.clone()];
            for rel in patch_target_paths(patch) {
                let p = Path::new(&rel);
                if p.is_absolute() {
                    out.push(rel);
                } else {
                    out.push(Path::new(root).join(&rel).to_string_lossy().into_owned());
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

/// Extract file paths referenced in unified diff `--- ` / `+++ ` headers so an
/// `ApplyPatch` targeting `../../etc/passwd` under an in-root `root` cannot
/// slip past an `outside` confirmation rule.
fn patch_target_paths(patch: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in patch.lines() {
        let rest = if let Some(r) = line.strip_prefix("+++ ") {
            r
        } else if let Some(r) = line.strip_prefix("--- ") {
            r
        } else {
            continue;
        };
        let token = rest.split('\t').next().unwrap_or(rest).trim();
        if token.is_empty() || token == "/dev/null" {
            continue;
        }
        let cleaned = token
            .strip_prefix("a/")
            .or_else(|| token.strip_prefix("b/"))
            .unwrap_or(token);
        if !cleaned.is_empty() {
            out.push(cleaned.to_string());
        }
    }
    out
}

fn is_root_only(p: &Path) -> bool {
    let mut comps = p.components();
    matches!(
        (comps.next(), comps.next()),
        (Some(Component::RootDir), None)
    )
}

fn strip_verbatim(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return rest;
    }
    s.strip_prefix(r"\\?\").unwrap_or(s)
}

/// Normalize a path string for prefix containment checks: resolves symlinks on
/// the longest existing non-root ancestor when present on disk, and lexically
/// folds `.` and `..` so `/work/../etc/passwd` never appears inside `/work`.
fn normalize_for_inside(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let path = Path::new(trimmed);
    // Walk up from `path` to find the longest existing ancestor to canonicalize
    // symlinks (skipping bare `/` so POSIX virtual paths on Windows stay lexical).
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur: Option<&Path> = Some(path);
    let mut resolved: Option<PathBuf> = None;
    while let Some(candidate) = cur {
        if !candidate.as_os_str().is_empty() && !is_root_only(candidate) {
            if let Ok(canon) = std::fs::canonicalize(candidate) {
                let mut combined = canon;
                for part in tail.iter().rev() {
                    combined.push(part);
                }
                resolved = Some(combined);
                break;
            }
        }
        if let Some(name) = candidate.file_name() {
            tail.push(name.to_os_string());
            cur = candidate.parent();
        } else {
            break;
        }
    }
    let candidate = resolved
        .as_deref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| trimmed.to_string());
    lexical_normalize(&candidate)
}

fn lexical_normalize(raw: &str) -> String {
    let cleaned = strip_verbatim(raw).replace('\\', "/");
    // Detect Windows drive prefix like `C:` or `c:`.
    let bytes = cleaned.as_bytes();
    let (drive_prefix, rest) = if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        (
            Some(format!("{}:", (bytes[0] as char).to_ascii_lowercase())),
            &cleaned[2..],
        )
    } else {
        (None, cleaned.as_str())
    };
    let absolute = rest.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if let Some(last) = stack.last() {
                    if *last != ".." {
                        stack.pop();
                        continue;
                    }
                }
                if !absolute && drive_prefix.is_none() {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }
    let mut out = String::new();
    if let Some(drive) = drive_prefix {
        out.push_str(&drive);
    }
    if absolute {
        out.push('/');
    }
    out.push_str(&stack.join("/"));
    #[cfg(windows)]
    {
        out.make_ascii_lowercase();
    }
    out
}

fn path_inside(prefix: &str, path: &str) -> bool {
    let prefix = normalize_for_inside(prefix);
    let path = normalize_for_inside(path);
    if prefix.is_empty() || path.is_empty() {
        return false;
    }
    let prefix = if prefix == "/" || (prefix.len() == 3 && prefix.ends_with(":/")) {
        prefix.as_str()
    } else {
        prefix.trim_end_matches('/')
    };
    if path == prefix {
        return true;
    }
    if prefix.ends_with('/') {
        return path.starts_with(prefix);
    }
    path.len() > prefix.len()
        && path.starts_with(prefix)
        && path.as_bytes()[prefix.len()] == b'/'
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
        Op::Mkdir { path, .. } => format!("mkdir {path}"),
        Op::Replace { path, .. } => format!("replace {path}"),
        Op::EditLines { path, .. } => format!("edit {path}"),
        Op::ApplyPatch { root, .. } => format!("patch {root}"),
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

    #[test]
    fn sec10_rm_full_path_and_chained_shell_match_baseline() {
        let policy = ConfirmPolicy::baseline();
        assert!(policy.matching(&exec("/bin/rm -rf /")).is_some());
        assert!(policy.matching(&exec("cd /tmp && rm -rf /")).is_some());
        assert!(policy
            .matching(&exec_argv("/bin/rm", &["-rf", "/"]))
            .is_some());
    }

    #[test]
    fn sec10_write_category_covers_replace_edit_patch_rename_from_and_dotdot() {
        let policy = ConfirmPolicy {
            timeout_secs: 30,
            rules: vec![ConfirmRule {
                category: "write".into(),
                pattern: String::new(),
                outside: Some("/work".into()),
                recursive: false,
            }],
        };
        // Dot-dot traversal must NOT appear inside `/work`.
        assert!(policy
            .matching(&Op::WriteFile {
                path: "/work/../etc/passwd".into(),
                offset: 0,
                data_b64: String::new(),
                truncate: true,
            })
            .is_some());
        // Replace outside `/work` matches; inside does not.
        assert!(policy
            .matching(&Op::Replace {
                path: "/etc/hosts".into(),
                old: "a".into(),
                new: "b".into(),
                replace_all: false,
            })
            .is_some());
        assert!(policy
            .matching(&Op::Replace {
                path: "/work/app.rs".into(),
                old: "a".into(),
                new: "b".into(),
                replace_all: false,
            })
            .is_none());
        // EditLines outside `/work` matches.
        assert!(policy
            .matching(&Op::EditLines {
                path: "/work/../etc/cron.d/job".into(),
                start_line: 1,
                end_line: 1,
                content: "x".into(),
            })
            .is_some());
        // ApplyPatch with root outside or patch header escaping via `..` matches.
        assert!(policy
            .matching(&Op::ApplyPatch {
                root: "/etc".into(),
                patch: "--- a/hosts\n+++ b/hosts\n".into(),
            })
            .is_some());
        assert!(policy
            .matching(&Op::ApplyPatch {
                root: "/work".into(),
                patch: "--- a/../etc/passwd\n+++ b/../etc/passwd\n".into(),
            })
            .is_some());
        assert!(policy
            .matching(&Op::ApplyPatch {
                root: "/work".into(),
                patch: "--- a/src/lib.rs\n+++ b/src/lib.rs\n".into(),
            })
            .is_none());
        // Rename checks BOTH `from` and `to`.
        assert!(policy
            .matching(&Op::Rename {
                from: "/etc/shadow".into(),
                to: "/work/stolen".into(),
            })
            .is_some());
        assert!(policy
            .matching(&Op::Rename {
                from: "/work/a.txt".into(),
                to: "/work/b.txt".into(),
            })
            .is_none());

        // Real on-disk symlink inside prefix pointing outside must NOT count as inside.
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let link = work.join("escape");
        let linked = {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&outside, &link).unwrap();
                true
            }
            #[cfg(windows)]
            {
                match std::os::windows::fs::symlink_dir(&outside, &link) {
                    Ok(()) => true,
                    Err(e) if e.raw_os_error() == Some(1314) => false,
                    Err(e) => panic!("symlink_dir failed: {e}"),
                }
            }
        };
        if linked {
            assert!(!path_inside(
                &work.to_string_lossy(),
                &link.join("secret.txt").to_string_lossy()
            ));
        }
    }

    #[test]
    fn live05_windows_destructive_presets_held_without_false_positives() {
        let policy = ConfirmPolicy::baseline();
        // Must hold all Windows destructive presets.
        for cmd in [
            "format D: /fs:NTFS /q",
            "cmd /c format D: /q",
            "cd C:\\ && format D:",
            "C:\\Windows\\System32\\format.com D:",
            "powershell -Command Format-Volume -DriveLetter D",
            "diskpart",
            "cmd /c diskpart /s wipe.txt",
            "rd /s /q C:\\important",
            "cmd /c rd /q /s C:\\important",
            "rmdir /s /q C:\\important",
            "powershell Remove-Item C:\\important -Recurse -Force",
            "powershell Remove-Item -Force -Recurse C:\\important",
            "powershell Stop-Computer -Force",
            "shutdown /s /t 0",
            "cipher /w:C:\\",
        ] {
            assert!(
                policy.matching(&exec(cmd)).is_some(),
                "expected Windows preset to hold: {cmd}"
            );
        }
        assert!(policy
            .matching(&Op::Remove {
                path: "C:\\".into(),
                recursive: true,
            })
            .is_some());
        // Must NOT false-positive on everyday commands.
        for safe in [
            "echo hi",
            "git log --format=%H",
            "cargo fmt --check",
            "dir C:\\Users",
            "Remove-Item C:\\tmp\\one.txt",
            "echo forward /s",
        ] {
            assert!(
                policy.matching(&exec(safe)).is_none(),
                "unexpected false positive hold on: {safe}"
            );
        }
    }

    #[test]
    fn sec10_matching_transfer_enforces_write_rules_for_pushes_not_pulls() {
        let policy = ConfirmPolicy {
            timeout_secs: 30,
            rules: vec![ConfirmRule {
                category: "write".into(),
                pattern: String::new(),
                outside: Some("/work".into()),
                recursive: false,
            }],
        };

        // Push writes outside `/work` (including `..` traversal) MUST match `category = "write"`.
        for kind in ["push", "push_dir", "push_stream"] {
            assert!(
                policy.matching_transfer(kind, "/etc/passwd").is_some(),
                "expected write rule to hold {kind} outside /work"
            );
            assert!(
                policy
                    .matching_transfer(kind, "/work/../etc/passwd")
                    .is_some(),
                "expected write rule to hold {kind} dotdot traversal"
            );
            assert!(
                policy.matching_transfer(kind, "/work/ok.txt").is_none(),
                "expected write rule to allow {kind} inside /work"
            );
        }

        // Read-side pulls MUST NOT trigger `category = "write"`.
        for kind in ["pull", "pull_dir", "pull_stream"] {
            assert!(
                policy.matching_transfer(kind, "/etc/passwd").is_none(),
                "pull ({kind}) must not trigger category = write"
            );
        }

        // Explicit `transfer` rule still matches both push and pull outside `/work`.
        let xfer_policy = ConfirmPolicy {
            timeout_secs: 30,
            rules: vec![ConfirmRule {
                category: "transfer".into(),
                pattern: String::new(),
                outside: Some("/work".into()),
                recursive: false,
            }],
        };
        assert!(xfer_policy.matching_transfer("pull", "/etc/passwd").is_some());
        assert!(xfer_policy.matching_transfer("push", "/etc/passwd").is_some());
        assert!(xfer_policy.matching_transfer("pull", "/work/a.txt").is_none());
    }
}
