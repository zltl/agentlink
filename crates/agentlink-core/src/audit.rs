//! Audit events, policy, redaction, diffs, and the hash chain.
//!
//! Handlers for search, edit, watch, and background processes should build an
//! [`AuditEvent`] and pass it to [`crate`] consumers through
//! `agentlink_node::audit::submit`. This module decides what is stored. It does
//! not open files; the node and the relay do.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::sandbox::glob_match;

pub const CATEGORIES: &[&str] = &[
    "file_read",
    "file_write",
    "edit",
    "delete_move",
    "transfer",
    "search",
    "watch",
    "exec",
    "background",
    "pty",
    "gui_screenshot",
    "gui_input",
    "a11y",
    "desktop_stream",
    "sysinfo",
    "auth",
    "permission",
    "approval",
];

pub const PRESETS: &[&str] = &["minimal", "standard", "full", "paranoid"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    Off,
    Metadata,
    Args,
    Diff,
    Output,
}

impl Detail {
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "metadata" => Ok(Self::Metadata),
            "args" => Ok(Self::Args),
            "diff" => Ok(Self::Diff),
            "output" => Ok(Self::Output),
            other => Err(Error::Message(format!(
                "unknown detail '{other}' (off, metadata, args, diff, output)"
            ))),
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Metadata => 1,
            Self::Args => 2,
            Self::Diff => 3,
            Self::Output => 4,
        }
    }

    pub fn includes(self, need: Self) -> bool {
        self.rank() >= need.rank() && self != Self::Off
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CategoryPolicy {
    pub enabled: bool,
    pub detail: Detail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturePolicy {
    pub stdout_stderr: bool,
    pub stdout_cap_bytes: u64,
    pub pty_transcript: bool,
    pub pty_cap_bytes: u64,
    pub diff: bool,
    pub diff_cap_bytes: u64,
    pub hashes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactPolicy {
    pub patterns: Vec<String>,
    pub env_keys: Vec<String>,
}

impl RedactPolicy {
    /// Apply the same pattern replacement the audit log uses.
    pub fn apply(&self, input: &str) -> String {
        let mut out = input.to_string();
        for pattern in &self.patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                out = re.replace_all(&out, "[redacted]").into_owned();
            }
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathFilter {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordingPolicy {
    /// `off`, `gui` (only during GUI-control sessions), or `always`.
    pub mode: String,
    pub fps: u32,
    /// `low`, `medium`, or `high`.
    pub quality: String,
    pub per_session: bool,
    pub idle_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub log_days: u64,
    pub diff_days: u64,
    pub recording_days: u64,
    pub max_log_bytes: u64,
    pub max_diff_bytes: u64,
    pub max_recording_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardPolicy {
    pub central: bool,
    pub chain: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertRule {
    pub name: String,
    #[serde(default)]
    pub match_category: Option<String>,
    #[serde(default)]
    pub match_op: Option<String>,
    #[serde(default)]
    pub match_result: Option<String>,
    #[serde(default)]
    pub match_text: Option<String>,
    pub webhook: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SinkSpec {
    pub name: String,
    /// `local`, `relay`, or `s3`.
    pub kind: String,
    /// `logs`, `diffs`, `recordings`. Empty means all three.
    #[serde(default)]
    pub data: Vec<String>,
    #[serde(default)]
    pub retention_days: Option<u64>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    #[serde(default)]
    pub s3: Option<crate::s3::S3Config>,
}

impl SinkSpec {
    pub fn accepts(&self, kind: &str) -> bool {
        self.data.is_empty() || self.data.iter().any(|item| item == kind)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyPatch {
    #[serde(default)]
    pub categories: BTreeMap<String, CategoryPolicy>,
    #[serde(default)]
    pub capture: Option<CapturePatch>,
    #[serde(default)]
    pub recording: Option<RecordingPatch>,
    #[serde(default)]
    pub retention: Option<RetentionPatch>,
    #[serde(default)]
    pub forward: Option<ForwardPatch>,
    #[serde(default)]
    pub redact_patterns: Option<Vec<String>>,
    #[serde(default)]
    pub path_exclude: Option<Vec<String>>,
    #[serde(default)]
    pub path_include: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CapturePatch {
    #[serde(default)]
    pub stdout_stderr: Option<bool>,
    #[serde(default)]
    pub stdout_cap_bytes: Option<u64>,
    #[serde(default)]
    pub pty_transcript: Option<bool>,
    #[serde(default)]
    pub pty_cap_bytes: Option<u64>,
    #[serde(default)]
    pub diff: Option<bool>,
    #[serde(default)]
    pub diff_cap_bytes: Option<u64>,
    #[serde(default)]
    pub hashes: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RecordingPatch {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub fps: Option<u32>,
    #[serde(default)]
    pub quality: Option<String>,
    #[serde(default)]
    pub per_session: Option<bool>,
    #[serde(default)]
    pub idle_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RetentionPatch {
    #[serde(default)]
    pub log_days: Option<u64>,
    #[serde(default)]
    pub diff_days: Option<u64>,
    #[serde(default)]
    pub recording_days: Option<u64>,
    #[serde(default)]
    pub max_log_bytes: Option<u64>,
    #[serde(default)]
    pub max_diff_bytes: Option<u64>,
    #[serde(default)]
    pub max_recording_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ForwardPatch {
    #[serde(default)]
    pub central: Option<bool>,
    #[serde(default)]
    pub chain: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Overrides {
    #[serde(default)]
    pub agent: BTreeMap<String, PolicyPatch>,
    #[serde(default)]
    pub node: BTreeMap<String, PolicyPatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditPolicy {
    pub preset: String,
    #[serde(default)]
    pub lock_local: bool,
    pub categories: BTreeMap<String, CategoryPolicy>,
    pub capture: CapturePolicy,
    pub redact: RedactPolicy,
    pub paths: PathFilter,
    pub recording: RecordingPolicy,
    pub retention: RetentionPolicy,
    pub forward: ForwardPolicy,
    #[serde(default)]
    pub alerts: Vec<AlertRule>,
    #[serde(default)]
    pub overrides: Overrides,
    #[serde(default)]
    pub sinks: Vec<SinkSpec>,
}

impl AuditPolicy {
    pub fn preset(name: &str) -> Result<Self> {
        let name = name.trim().to_ascii_lowercase();
        let (
            detail_default,
            exec_detail,
            write_detail,
            pty_detail,
            capture,
            recording,
            retention,
            forward,
            redact_extra,
        ) = match name.as_str() {
            "minimal" => (
                Detail::Off,
                Detail::Args,
                Detail::Off,
                Detail::Off,
                CapturePolicy {
                    stdout_stderr: false,
                    stdout_cap_bytes: 4096,
                    pty_transcript: false,
                    pty_cap_bytes: 4096,
                    diff: false,
                    diff_cap_bytes: 4096,
                    hashes: false,
                },
                recording("off", 1, "low"),
                retention(
                    7,
                    7,
                    1,
                    256 * 1024 * 1024,
                    64 * 1024 * 1024,
                    256 * 1024 * 1024,
                ),
                ForwardPolicy {
                    central: false,
                    chain: true,
                },
                Vec::new(),
            ),
            "standard" => (
                Detail::Args,
                Detail::Output,
                Detail::Diff,
                Detail::Args,
                CapturePolicy {
                    stdout_stderr: true,
                    stdout_cap_bytes: 64 * 1024,
                    pty_transcript: false,
                    pty_cap_bytes: 64 * 1024,
                    diff: true,
                    diff_cap_bytes: 64 * 1024,
                    hashes: true,
                },
                recording("off", 2, "low"),
                retention(
                    30,
                    30,
                    7,
                    1024 * 1024 * 1024,
                    512 * 1024 * 1024,
                    10 * 1024 * 1024 * 1024,
                ),
                ForwardPolicy {
                    central: true,
                    chain: true,
                },
                Vec::new(),
            ),
            "full" => (
                Detail::Args,
                Detail::Output,
                Detail::Diff,
                Detail::Output,
                CapturePolicy {
                    stdout_stderr: true,
                    stdout_cap_bytes: 256 * 1024,
                    pty_transcript: true,
                    pty_cap_bytes: 256 * 1024,
                    diff: true,
                    diff_cap_bytes: 256 * 1024,
                    hashes: true,
                },
                recording("gui", 2, "medium"),
                retention(
                    90,
                    90,
                    30,
                    4 * 1024 * 1024 * 1024,
                    2 * 1024 * 1024 * 1024,
                    20 * 1024 * 1024 * 1024,
                ),
                ForwardPolicy {
                    central: true,
                    chain: true,
                },
                Vec::new(),
            ),
            "paranoid" => (
                Detail::Output,
                Detail::Output,
                Detail::Output,
                Detail::Output,
                CapturePolicy {
                    stdout_stderr: true,
                    stdout_cap_bytes: 1024 * 1024,
                    pty_transcript: true,
                    pty_cap_bytes: 1024 * 1024,
                    diff: true,
                    diff_cap_bytes: 1024 * 1024,
                    hashes: true,
                },
                recording("always", 4, "high"),
                retention(
                    365,
                    365,
                    90,
                    8 * 1024 * 1024 * 1024,
                    4 * 1024 * 1024 * 1024,
                    50 * 1024 * 1024 * 1024,
                ),
                ForwardPolicy {
                    central: true,
                    chain: true,
                },
                vec!["(?i)(authorization|cookie)\\s*[:=]\\s*\\S+".into()],
            ),
            other => {
                return Err(Error::Message(format!(
                    "unknown audit preset '{other}' (minimal, standard, full, paranoid)"
                )))
            }
        };
        let mut categories = BTreeMap::new();
        for name in CATEGORIES {
            let detail = match *name {
                "exec" | "background" => exec_detail,
                "file_write" | "edit" | "transfer" => write_detail,
                "pty" => pty_detail,
                "auth" | "permission" | "approval" => {
                    if detail_default == Detail::Off {
                        Detail::Metadata
                    } else {
                        Detail::Args
                    }
                }
                "gui_screenshot" | "gui_input" | "a11y" => Detail::Metadata,
                _ => detail_default,
            };
            let enabled = detail != Detail::Off;
            categories.insert(
                (*name).to_string(),
                CategoryPolicy {
                    enabled,
                    detail: if enabled { detail } else { Detail::Off },
                },
            );
        }
        // The match above uses the preset name only in the gui branch via a
        // string compare that is wrong (`name` is the category). Fix gui rows
        // explicitly.
        let gui_detail = match name.as_str() {
            "minimal" => Detail::Off,
            "standard" => Detail::Metadata,
            "full" => Detail::Args,
            "paranoid" => Detail::Output,
            _ => Detail::Metadata,
        };
        for key in ["gui_screenshot", "gui_input", "a11y", "desktop_stream"] {
            categories.insert(
                key.to_string(),
                CategoryPolicy {
                    enabled: gui_detail != Detail::Off,
                    detail: gui_detail,
                },
            );
        }
        let mut patterns = default_patterns();
        patterns.extend(redact_extra);
        let mut policy = Self {
            preset: name,
            lock_local: false,
            categories,
            capture,
            redact: RedactPolicy {
                patterns,
                env_keys: vec![
                    "*SECRET*".into(),
                    "*TOKEN*".into(),
                    "*PASSWORD*".into(),
                    "*KEY*".into(),
                    "*CREDENTIAL*".into(),
                ],
            },
            paths: PathFilter {
                include: Vec::new(),
                exclude: vec![
                    "**/.ssh/**".into(),
                    "**/*.pem".into(),
                    "**/id_rsa".into(),
                    "**/.aws/**".into(),
                    "**/.gnupg/**".into(),
                ],
            },
            recording,
            retention,
            forward,
            alerts: Vec::new(),
            overrides: Overrides::default(),
            sinks: vec![SinkSpec {
                name: "local".into(),
                kind: "local".into(),
                data: vec!["logs".into(), "diffs".into(), "recordings".into()],
                retention_days: None,
                max_bytes: None,
                s3: None,
            }],
        };
        if policy.forward.central {
            policy.sinks.push(SinkSpec {
                name: "relay".into(),
                kind: "relay".into(),
                data: vec!["logs".into()],
                retention_days: None,
                max_bytes: None,
                s3: None,
            });
        }
        policy.validate()?;
        Ok(policy)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let value: toml::Value = toml::from_str(text).map_err(|e| Error::Message(e.to_string()))?;
        let preset = value
            .get("preset")
            .and_then(|v| v.as_str())
            .unwrap_or("standard");
        let mut policy = Self::preset(preset)?;
        let table = value
            .as_table()
            .ok_or_else(|| Error::Message("audit policy must be a table".into()))?;
        if let Some(flag) = table.get("lock_local").and_then(|v| v.as_bool()) {
            policy.lock_local = flag;
        }
        if let Some(section) = table.get("categories") {
            let cats: BTreeMap<String, CategoryPolicy> =
                toml::Value::Table(section.as_table().cloned().unwrap_or_default())
                    .try_into()
                    .map_err(|e: toml::de::Error| Error::Message(e.to_string()))?;
            for (key, value) in cats {
                policy.categories.insert(key, value);
            }
        }
        merge_section(&table, "capture", |value| {
            let patch: CapturePatch = value
                .try_into()
                .map_err(|e: toml::de::Error| Error::Message(e.to_string()))?;
            apply_capture(&mut policy.capture, &patch);
            Ok(())
        })?;
        merge_section(&table, "recording", |value| {
            let patch: RecordingPatch = value
                .try_into()
                .map_err(|e: toml::de::Error| Error::Message(e.to_string()))?;
            apply_recording(&mut policy.recording, &patch);
            Ok(())
        })?;
        merge_section(&table, "retention", |value| {
            let patch: RetentionPatch = value
                .try_into()
                .map_err(|e: toml::de::Error| Error::Message(e.to_string()))?;
            apply_retention(&mut policy.retention, &patch);
            Ok(())
        })?;
        merge_section(&table, "forward", |value| {
            let patch: ForwardPatch = value
                .try_into()
                .map_err(|e: toml::de::Error| Error::Message(e.to_string()))?;
            if let Some(v) = patch.central {
                policy.forward.central = v;
            }
            if let Some(v) = patch.chain {
                policy.forward.chain = v;
            }
            Ok(())
        })?;
        if let Some(section) = table.get("redact") {
            if let Some(patterns) = section.get("patterns") {
                policy.redact.patterns = string_list(patterns)?;
            }
            if let Some(keys) = section.get("env_keys") {
                policy.redact.env_keys = string_list(keys)?;
            }
        }
        if let Some(section) = table.get("paths") {
            if let Some(include) = section.get("include") {
                policy.paths.include = string_list(include)?;
            }
            if let Some(exclude) = section.get("exclude") {
                policy.paths.exclude = string_list(exclude)?;
            }
        }
        if let Some(section) = table.get("alerts") {
            policy.alerts = section
                .clone()
                .try_into()
                .map_err(|e: toml::de::Error| Error::Message(e.to_string()))?;
        }
        if let Some(section) = table.get("sinks") {
            policy.sinks = section
                .clone()
                .try_into()
                .map_err(|e: toml::de::Error| Error::Message(e.to_string()))?;
        }
        if let Some(section) = table.get("overrides") {
            policy.overrides = section
                .clone()
                .try_into()
                .map_err(|e: toml::de::Error| Error::Message(e.to_string()))?;
        }
        policy.validate()?;
        Ok(policy)
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Message(e.to_string()))
    }

    /// Agent overrides win over node overrides, which win over the base policy.
    pub fn effective(&self, agent: Option<&str>, node: Option<&str>) -> Self {
        let mut out = self.clone();
        if let Some(node) = node {
            if let Some(patch) = self.overrides.node.get(node) {
                out.apply_patch(patch);
            }
        }
        if let Some(agent) = agent {
            if let Some(patch) = self.overrides.agent.get(agent) {
                out.apply_patch(patch);
            }
        }
        out
    }

    pub fn apply_patch(&mut self, patch: &PolicyPatch) {
        for (key, value) in &patch.categories {
            self.categories.insert(key.clone(), value.clone());
        }
        if let Some(capture) = &patch.capture {
            apply_capture(&mut self.capture, capture);
        }
        if let Some(recording) = &patch.recording {
            apply_recording(&mut self.recording, recording);
        }
        if let Some(retention) = &patch.retention {
            apply_retention(&mut self.retention, retention);
        }
        if let Some(forward) = &patch.forward {
            if let Some(v) = forward.central {
                self.forward.central = v;
            }
            if let Some(v) = forward.chain {
                self.forward.chain = v;
            }
        }
        if let Some(patterns) = &patch.redact_patterns {
            self.redact.patterns = patterns.clone();
        }
        if let Some(exclude) = &patch.path_exclude {
            self.paths.exclude = exclude.clone();
        }
        if let Some(include) = &patch.path_include {
            self.paths.include = include.clone();
        }
    }

    pub fn set_key(&mut self, key: &str, value: &str) -> Result<()> {
        let key = key.trim();
        let value = value.trim();
        if let Some(rest) = key.strip_prefix("categories.") {
            let (name, field) = rest.split_once('.').ok_or_else(|| {
                Error::Message("expected categories.<name>.enabled or .detail".into())
            })?;
            if !CATEGORIES.contains(&name) {
                return Err(Error::Message(format!("unknown category '{name}'")));
            }
            let entry = self
                .categories
                .entry(name.to_string())
                .or_insert(CategoryPolicy {
                    enabled: true,
                    detail: Detail::Metadata,
                });
            match field {
                "enabled" => entry.enabled = parse_bool(value)?,
                "detail" => entry.detail = Detail::parse(value)?,
                other => return Err(Error::Message(format!("unknown category field '{other}'"))),
            }
        } else if let Some(field) = key.strip_prefix("capture.") {
            match field {
                "stdout_stderr" => self.capture.stdout_stderr = parse_bool(value)?,
                "stdout_cap_bytes" => self.capture.stdout_cap_bytes = parse_u64(value)?,
                "pty_transcript" => self.capture.pty_transcript = parse_bool(value)?,
                "pty_cap_bytes" => self.capture.pty_cap_bytes = parse_u64(value)?,
                "diff" => self.capture.diff = parse_bool(value)?,
                "diff_cap_bytes" => self.capture.diff_cap_bytes = parse_u64(value)?,
                "hashes" => self.capture.hashes = parse_bool(value)?,
                other => return Err(Error::Message(format!("unknown capture field '{other}'"))),
            }
        } else if let Some(field) = key.strip_prefix("recording.") {
            match field {
                "mode" => self.recording.mode = value.to_string(),
                "fps" => self.recording.fps = parse_u64(value)? as u32,
                "quality" => self.recording.quality = value.to_string(),
                "per_session" => self.recording.per_session = parse_bool(value)?,
                "idle_secs" => self.recording.idle_secs = parse_u64(value)?,
                other => return Err(Error::Message(format!("unknown recording field '{other}'"))),
            }
        } else if let Some(field) = key.strip_prefix("retention.") {
            match field {
                "log_days" => self.retention.log_days = parse_u64(value)?,
                "diff_days" => self.retention.diff_days = parse_u64(value)?,
                "recording_days" => self.retention.recording_days = parse_u64(value)?,
                "max_log_bytes" => self.retention.max_log_bytes = parse_u64(value)?,
                "max_diff_bytes" => self.retention.max_diff_bytes = parse_u64(value)?,
                "max_recording_bytes" => self.retention.max_recording_bytes = parse_u64(value)?,
                other => return Err(Error::Message(format!("unknown retention field '{other}'"))),
            }
        } else if let Some(field) = key.strip_prefix("forward.") {
            match field {
                "central" => self.forward.central = parse_bool(value)?,
                "chain" => self.forward.chain = parse_bool(value)?,
                other => return Err(Error::Message(format!("unknown forward field '{other}'"))),
            }
        } else {
            match key {
                "preset" => *self = Self::preset(value)?,
                "lock_local" => self.lock_local = parse_bool(value)?,
                "redact.patterns" => self.redact.patterns = split_list(value),
                "redact.env_keys" => self.redact.env_keys = split_list(value),
                "paths.include" => self.paths.include = split_list(value),
                "paths.exclude" => self.paths.exclude = split_list(value),
                other => {
                    return Err(Error::Message(format!(
                        "unknown audit key '{other}'. See the README table."
                    )))
                }
            }
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<()> {
        if !PRESETS.contains(&self.preset.as_str()) {
            return Err(Error::Message(format!("unknown preset '{}'", self.preset)));
        }
        for key in self.categories.keys() {
            if !CATEGORIES.contains(&key.as_str()) {
                return Err(Error::Message(format!("unknown category '{key}'")));
            }
        }
        for key in CATEGORIES {
            if !self.categories.contains_key(*key) {
                return Err(Error::Message(format!("missing category '{key}'")));
            }
        }
        check_cap("stdout_cap_bytes", self.capture.stdout_cap_bytes)?;
        check_cap("pty_cap_bytes", self.capture.pty_cap_bytes)?;
        check_cap("diff_cap_bytes", self.capture.diff_cap_bytes)?;
        if !(1..=30).contains(&self.recording.fps) {
            return Err(Error::Message("recording.fps must be 1..=30".into()));
        }
        if !matches!(self.recording.mode.as_str(), "off" | "gui" | "always") {
            return Err(Error::Message(
                "recording.mode must be off, gui, or always".into(),
            ));
        }
        if !matches!(self.recording.quality.as_str(), "low" | "medium" | "high") {
            return Err(Error::Message(
                "recording.quality must be low, medium, or high".into(),
            ));
        }
        for (label, days) in [
            ("log_days", self.retention.log_days),
            ("diff_days", self.retention.diff_days),
            ("recording_days", self.retention.recording_days),
        ] {
            if days > 36500 {
                return Err(Error::Message(format!("{label} is unreasonably large")));
            }
        }
        for pattern in &self.redact.patterns {
            regex::Regex::new(pattern).map_err(|e| Error::Message(format!("redact regex: {e}")))?;
        }
        for rule in &self.alerts {
            if rule.webhook.is_empty()
                || !(rule.webhook.starts_with("https://") || rule.webhook.starts_with("http://"))
            {
                return Err(Error::Message(format!(
                    "alert '{}' needs an http(s) webhook",
                    rule.name
                )));
            }
        }
        let mut names = BTreeSet::new();
        for sink in &self.sinks {
            if !names.insert(sink.name.clone()) {
                return Err(Error::Message(format!("duplicate sink '{}'", sink.name)));
            }
            if !matches!(sink.kind.as_str(), "local" | "relay" | "s3") {
                return Err(Error::Message(format!(
                    "sink '{}' kind must be local, relay, or s3",
                    sink.name
                )));
            }
            for item in &sink.data {
                if !matches!(item.as_str(), "logs" | "diffs" | "recordings") {
                    return Err(Error::Message(format!(
                        "sink '{}' data type '{item}' is unknown",
                        sink.name
                    )));
                }
            }
            if sink.kind == "s3" {
                let Some(s3) = &sink.s3 else {
                    return Err(Error::Message(format!(
                        "s3 sink '{}' is missing an [s3] table",
                        sink.name
                    )));
                };
                s3.validate()?;
            }
        }
        Ok(())
    }

    pub fn detail_for(&self, category: &str) -> Detail {
        match self.categories.get(category) {
            Some(cat) if cat.enabled => cat.detail,
            _ => Detail::Off,
        }
    }
}

fn merge_section(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
    apply: impl FnOnce(toml::Value) -> Result<()>,
) -> Result<()> {
    if let Some(section) = table.get(key) {
        apply(section.clone())?;
    }
    Ok(())
}

fn string_list(value: &toml::Value) -> Result<Vec<String>> {
    let list: Vec<String> = value
        .clone()
        .try_into()
        .map_err(|e: toml::de::Error| Error::Message(e.to_string()))?;
    Ok(list)
}

fn apply_capture(dst: &mut CapturePolicy, patch: &CapturePatch) {
    if let Some(v) = patch.stdout_stderr {
        dst.stdout_stderr = v;
    }
    if let Some(v) = patch.stdout_cap_bytes {
        dst.stdout_cap_bytes = v;
    }
    if let Some(v) = patch.pty_transcript {
        dst.pty_transcript = v;
    }
    if let Some(v) = patch.pty_cap_bytes {
        dst.pty_cap_bytes = v;
    }
    if let Some(v) = patch.diff {
        dst.diff = v;
    }
    if let Some(v) = patch.diff_cap_bytes {
        dst.diff_cap_bytes = v;
    }
    if let Some(v) = patch.hashes {
        dst.hashes = v;
    }
}

fn apply_recording(dst: &mut RecordingPolicy, patch: &RecordingPatch) {
    if let Some(v) = &patch.mode {
        dst.mode = v.clone();
    }
    if let Some(v) = patch.fps {
        dst.fps = v;
    }
    if let Some(v) = &patch.quality {
        dst.quality = v.clone();
    }
    if let Some(v) = patch.per_session {
        dst.per_session = v;
    }
    if let Some(v) = patch.idle_secs {
        dst.idle_secs = v;
    }
}

fn apply_retention(dst: &mut RetentionPolicy, patch: &RetentionPatch) {
    if let Some(v) = patch.log_days {
        dst.log_days = v;
    }
    if let Some(v) = patch.diff_days {
        dst.diff_days = v;
    }
    if let Some(v) = patch.recording_days {
        dst.recording_days = v;
    }
    if let Some(v) = patch.max_log_bytes {
        dst.max_log_bytes = v;
    }
    if let Some(v) = patch.max_diff_bytes {
        dst.max_diff_bytes = v;
    }
    if let Some(v) = patch.max_recording_bytes {
        dst.max_recording_bytes = v;
    }
}

fn recording(mode: &str, fps: u32, quality: &str) -> RecordingPolicy {
    RecordingPolicy {
        mode: mode.into(),
        fps,
        quality: quality.into(),
        per_session: true,
        idle_secs: 30,
    }
}

fn retention(
    log_days: u64,
    diff_days: u64,
    recording_days: u64,
    max_log: u64,
    max_diff: u64,
    max_rec: u64,
) -> RetentionPolicy {
    RetentionPolicy {
        log_days,
        diff_days,
        recording_days,
        max_log_bytes: max_log,
        max_diff_bytes: max_diff,
        max_recording_bytes: max_rec,
    }
}

fn default_patterns() -> Vec<String> {
    vec![
        r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+".into(),
        r"AKIA[0-9A-Z]{16}".into(),
        r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*".into(),
        r"(?i)(aws_secret_access_key|aws_session_token)\s*[:=]\s*\S+".into(),
    ]
}

fn check_cap(name: &str, value: u64) -> Result<()> {
    const MAX: u64 = 16 * 1024 * 1024;
    if value > MAX {
        return Err(Error::Message(format!(
            "{name} exceeds the 16 MiB per-event cap"
        )));
    }
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(Error::Message(format!("expected a boolean, got '{other}'"))),
    }
}

fn parse_u64(value: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| Error::Message(format!("expected an integer, got '{value}'")))
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// What a handler knows about one operation. Search, edit, watch, and
/// background tools should fill the fields they have and leave the rest empty.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub category: String,
    pub action: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub session_id: Option<String>,
    pub args: Value,
    pub ok: bool,
    pub error: Option<String>,
    pub duration: Duration,
    pub paths: Vec<String>,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
    pub stdout: Option<Vec<u8>>,
    pub stderr: Option<Vec<u8>>,
    pub transcript: Option<Vec<u8>>,
    pub transfer: Option<TransferMeta>,
    pub exit_code: Option<i32>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub command: Option<String>,
    pub user: Option<String>,
    pub device_id: Option<String>,
}

impl Default for AuditEvent {
    fn default() -> Self {
        Self {
            category: String::new(),
            action: String::new(),
            client_id: String::new(),
            client_name: None,
            session_id: None,
            args: Value::Null,
            ok: true,
            error: None,
            duration: Duration::ZERO,
            paths: Vec::new(),
            before: None,
            after: None,
            stdout: None,
            stderr: None,
            transcript: None,
            transfer: None,
            exit_code: None,
            cwd: None,
            env: Vec::new(),
            command: None,
            user: None,
            device_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferMeta {
    pub src_node: String,
    pub src_path: String,
    pub dst_node: String,
    pub dst_path: String,
    pub size: u64,
    pub blake3: String,
    pub direction: String,
    /// `relay` or `quic`. QUIC bytes never traverse the relay.
    pub path: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub ts: String,
    pub node_id: String,
    pub node_name: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub category: String,
    pub op: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub args: Value,
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer: Option<TransferMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub prev_hash: String,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditDraft {
    pub record: AuditRecord,
    pub diff: Option<Vec<u8>>,
    pub output: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    #[serde(default)]
    pub node: Option<String>,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub op: Option<String>,
    #[serde(default)]
    pub since_unix: Option<i64>,
    #[serde(default)]
    pub until_unix: Option<i64>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub limit: usize,
    #[serde(default)]
    pub user: Option<String>,
}

/// Keep records that match, oldest first, capped at `limit` (default 200).
pub fn select(records: &[AuditRecord], filter: &AuditFilter) -> Vec<AuditRecord> {
    let mut out: Vec<_> = records
        .iter()
        .filter(|record| filter.matches(record))
        .cloned()
        .collect();
    out.sort_by_key(|record| record.seq);
    let limit = if filter.limit == 0 { 200 } else { filter.limit };
    if out.len() > limit {
        out = out.split_off(out.len() - limit);
    }
    out
}

/// POST an alert without blocking the operation that produced it.
pub fn fire_webhook(url: &str, payload: &Value) {
    let url = url.to_string();
    let body = payload.to_string();
    std::thread::spawn(move || {
        let Ok(client) = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        else {
            return;
        };
        let _ = client
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send();
    });
}

impl AuditFilter {
    pub fn matches(&self, record: &AuditRecord) -> bool {
        if let Some(node) = &self.node {
            if record.node_id != *node && record.node_name != *node {
                return false;
            }
        }
        if let Some(user) = &self.user {
            if record.user.as_deref() != Some(user.as_str()) {
                return false;
            }
        }
        if let Some(agent) = &self.agent {
            let name = record.client_name.as_deref().unwrap_or("");
            if record.client_id != *agent && name != *agent {
                return false;
            }
        }
        if let Some(op) = &self.op {
            if record.op != *op && record.category != *op {
                return false;
            }
        }
        if let Some(since) = self.since_unix {
            if record_unix(record) < since {
                return false;
            }
        }
        if let Some(until) = self.until_unix {
            if record_unix(record) > until {
                return false;
            }
        }
        if let Some(text) = &self.text {
            let hay = serde_json::to_string(record).unwrap_or_default();
            if !hay
                .to_ascii_lowercase()
                .contains(&text.to_ascii_lowercase())
            {
                return false;
            }
        }
        true
    }
}

fn record_unix(record: &AuditRecord) -> i64 {
    chrono::DateTime::parse_from_rfc3339(&record.ts)
        .map(|ts| ts.timestamp())
        .unwrap_or(0)
}

/// Apply the policy. `None` means the event is not recorded.
pub fn prepare(
    policy: &AuditPolicy,
    node_id: &str,
    node_name: &str,
    event: &AuditEvent,
) -> Option<AuditDraft> {
    let policy = policy.effective(Some(&event.client_id), Some(node_id));
    let detail = policy.detail_for(&event.category);
    if detail == Detail::Off {
        return None;
    }
    if !path_allowed(&policy.paths, &event.paths) {
        return None;
    }
    let redact = Redactor::new(&policy.redact);
    let mut args = if detail.includes(Detail::Args) {
        let value = redact.value(event.args.clone());
        if value.is_object() {
            value
        } else if value.is_null() {
            json!({})
        } else {
            json!({ "value": value })
        }
    } else {
        Value::Null
    };
    if detail.includes(Detail::Args) {
        if let Some(cmd) = &event.command {
            args["command"] = json!(redact.text(cmd));
        }
        if let Some(cwd) = &event.cwd {
            args["cwd"] = json!(cwd);
        }
        if !event.env.is_empty() {
            args["env"] = json!(redact_env(&event.env, &policy.redact, &redact));
        }
        if let Some(code) = event.exit_code {
            args["exit_code"] = json!(code);
        }
    }
    let mut before_hash = None;
    let mut after_hash = None;
    let mut diff = None;
    if policy.capture.hashes && detail.includes(Detail::Diff) {
        if let Some(before) = &event.before {
            before_hash = Some(hash_hex(before));
        }
        if let Some(after) = &event.after {
            after_hash = Some(hash_hex(after));
        }
        if policy.capture.diff {
            if let (Some(before), Some(after)) = (&event.before, &event.after) {
                diff = text_diff(
                    &event.paths.first().cloned().unwrap_or_default(),
                    before,
                    after,
                    policy.capture.diff_cap_bytes as usize,
                    &redact,
                );
            }
        }
    }
    if let Some(transfer) = &event.transfer {
        if policy.capture.hashes && detail.includes(Detail::Diff) {
            before_hash = Some(transfer.blake3.clone());
        }
        if detail.includes(Detail::Args) {
            args["transfer"] = serde_json::to_value(transfer).unwrap_or(Value::Null);
        }
    }
    let mut output = None;
    if detail.includes(Detail::Output) {
        let mut buf = Vec::new();
        if policy.capture.stdout_stderr {
            push_capped(
                &mut buf,
                b"stdout:\n",
                event.stdout.as_deref().unwrap_or(&[]),
                policy.capture.stdout_cap_bytes as usize,
            );
            push_capped(
                &mut buf,
                b"stderr:\n",
                event.stderr.as_deref().unwrap_or(&[]),
                policy.capture.stdout_cap_bytes as usize,
            );
        }
        if policy.capture.pty_transcript {
            push_capped(
                &mut buf,
                b"pty:\n",
                event.transcript.as_deref().unwrap_or(&[]),
                policy.capture.pty_cap_bytes as usize,
            );
        }
        if !buf.is_empty() {
            let text = redact.text(&String::from_utf8_lossy(&buf));
            output = Some(text.into_bytes());
        }
    }
    let diff_bytes = diff.map(|text| text.into_bytes());
    Some(AuditDraft {
        record: AuditRecord {
            seq: 0,
            ts: chrono::Utc::now().to_rfc3339(),
            node_id: node_id.to_string(),
            node_name: node_name.to_string(),
            client_id: event.client_id.clone(),
            client_name: event.client_name.clone(),
            session_id: event.session_id.clone(),
            category: event.category.clone(),
            op: event.action.clone(),
            args,
            result: if event.ok {
                "ok".into()
            } else {
                "error".into()
            },
            error: event.error.as_ref().map(|err| redact.text(err)),
            duration_ms: event.duration.as_millis() as u64,
            transfer: if detail.includes(Detail::Args) {
                event.transfer.clone()
            } else {
                None
            },
            before_hash,
            after_hash,
            diff_ref: diff_bytes.as_ref().map(|_| "diff".into()),
            output_ref: output.as_ref().map(|_| "output".into()),
            exit_code: event.exit_code,
            prev_hash: String::new(),
            hash: String::new(),
            user: event.user.clone(),
            device_id: event.device_id.clone(),
        },
        diff: diff_bytes,
        output,
    })
}

pub fn assign_chain(record: &mut AuditRecord, seq: u64, prev: &str, enabled: bool) {
    record.seq = seq;
    if enabled {
        record.prev_hash = prev.to_string();
        record.hash = chain_hash(prev, &canonical(record));
    } else {
        record.prev_hash = "off".into();
        record.hash = "off".into();
    }
}

pub fn canonical(record: &AuditRecord) -> String {
    let view = Canonical {
        seq: record.seq,
        ts: &record.ts,
        node_id: &record.node_id,
        node_name: &record.node_name,
        client_id: &record.client_id,
        client_name: record.client_name.as_deref(),
        session_id: record.session_id.as_deref(),
        category: &record.category,
        op: &record.op,
        args: &record.args,
        result: &record.result,
        error: record.error.as_deref(),
        duration_ms: record.duration_ms,
        transfer: record.transfer.as_ref(),
        before_hash: record.before_hash.as_deref(),
        after_hash: record.after_hash.as_deref(),
        diff_ref: record.diff_ref.as_deref(),
        output_ref: record.output_ref.as_deref(),
        exit_code: record.exit_code,
        prev_hash: &record.prev_hash,
        user: record.user.as_deref(),
        device_id: record.device_id.as_deref(),
    };
    serde_json::to_string(&view).unwrap_or_default()
}

pub fn chain_hash(prev: &str, canonical_json: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical_json.as_bytes());
    hasher.finalize().to_hex().to_string()
}

pub fn verify_chain(records: &[AuditRecord]) -> Result<()> {
    let mut prev = "0".repeat(64);
    for record in records {
        if record.hash == "off" {
            continue;
        }
        if record.prev_hash != prev && record.seq != 1 && prev.chars().all(|c| c == '0') {
            // A reader that starts mid-chain cannot confirm the link into the
            // first record it sees. Later records must still connect.
            prev = record.hash.clone();
            continue;
        }
        if record.prev_hash != prev && record.seq > 1 {
            return Err(Error::Message(format!(
                "audit chain broke at seq {}",
                record.seq
            )));
        }
        let expect = chain_hash(&record.prev_hash, &canonical(record));
        if expect != record.hash {
            return Err(Error::Message(format!(
                "audit hash mismatch at seq {}",
                record.seq
            )));
        }
        prev = record.hash.clone();
    }
    Ok(())
}

#[derive(Serialize)]
struct Canonical<'a> {
    seq: u64,
    ts: &'a str,
    node_id: &'a str,
    node_name: &'a str,
    client_id: &'a str,
    client_name: Option<&'a str>,
    session_id: Option<&'a str>,
    category: &'a str,
    op: &'a str,
    args: &'a Value,
    result: &'a str,
    error: Option<&'a str>,
    duration_ms: u64,
    transfer: Option<&'a TransferMeta>,
    before_hash: Option<&'a str>,
    after_hash: Option<&'a str>,
    diff_ref: Option<&'a str>,
    output_ref: Option<&'a str>,
    exit_code: Option<i32>,
    prev_hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<&'a str>,
}

pub fn hash_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn category_for_action(action: &str) -> &'static str {
    match action {
        "stat" | "list_dir" | "read" | "pull" | "pull_dir" | "pull_stream" => "file_read",
        "write" | "mkdir" | "push" | "push_dir" | "push_stream" => "file_write",
        "remove" | "rename" => "delete_move",
        "transfer" | "peer_copy" => "transfer",
        "search" | "find" => "search",
        "watch" | "watch_start" | "watch_poll" | "watch_stop" => "watch",
        "exec" => "exec",
        "background" | "spawn" | "bg_start" | "bg_list" | "bg_output" | "bg_status" | "bg_kill"
        | "bg_exit" => "background",
        "pty" | "pty_open" | "pty_input" | "pty_resize" | "pty_close" | "pty_session" => "pty",
        "edit" | "replace" | "edit_lines" | "apply_patch" => "edit",
        "screenshot" | "ext:screenshot" => "gui_screenshot",
        "stream_start" | "stream_stop" => "desktop_stream",
        "inject_input" | "ext:inject_input" => "gui_input",
        "a11y" | "ui_tree" => "a11y",
        "sys_info" | "sysinfo" => "sysinfo",
        "connect" | "login" | "register_client" | "revoke_client" => "auth",
        "set_policy" | "grant" | "audit_config" => "permission",
        "approval" => "approval",
        _ => "auth",
    }
}

struct Redactor {
    patterns: Vec<regex::Regex>,
}

impl Redactor {
    fn new(policy: &RedactPolicy) -> Self {
        let patterns = policy
            .patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();
        Self { patterns }
    }

    fn text(&self, input: &str) -> String {
        let mut out = input.to_string();
        for pattern in &self.patterns {
            out = pattern.replace_all(&out, "[redacted]").into_owned();
        }
        out
    }

    fn value(&self, value: Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.text(&text)),
            Value::Array(items) => Value::Array(items.into_iter().map(|v| self.value(v)).collect()),
            Value::Object(map) => {
                Value::Object(map.into_iter().map(|(k, v)| (k, self.value(v))).collect())
            }
            other => other,
        }
    }
}

fn redact_env(env: &[(String, String)], policy: &RedactPolicy, redact: &Redactor) -> Vec<Value> {
    env.iter()
        .map(|(key, value)| {
            let hide = policy
                .env_keys
                .iter()
                .any(|pattern| glob_match(pattern, key));
            json!({
                "key": key,
                "value": if hide { "[redacted]".to_string() } else { redact.text(value) },
            })
        })
        .collect()
}

fn path_allowed(filter: &PathFilter, paths: &[String]) -> bool {
    if paths.is_empty() {
        return true;
    }
    if paths.iter().any(|path| {
        filter
            .exclude
            .iter()
            .any(|pattern| glob_match(pattern, path))
    }) {
        return false;
    }
    if filter.include.is_empty() {
        return true;
    }
    paths.iter().any(|path| {
        filter
            .include
            .iter()
            .any(|pattern| glob_match(pattern, path))
    })
}

fn text_diff(
    path: &str,
    before: &[u8],
    after: &[u8],
    cap: usize,
    redact: &Redactor,
) -> Option<String> {
    if is_binary(before) || is_binary(after) {
        return None;
    }
    if before.len() > cap || after.len() > cap {
        return None;
    }
    let before = String::from_utf8_lossy(before);
    let after = String::from_utf8_lossy(after);
    let diff = unified(path, &before, &after);
    let diff = redact.text(&diff);
    if diff.len() > cap {
        Some(format!("{}[diff truncated]", &diff[..cap.min(diff.len())]))
    } else {
        Some(diff)
    }
}

pub fn is_binary(data: &[u8]) -> bool {
    data.contains(&0) || std::str::from_utf8(data).is_err()
}

fn unified(path: &str, before: &str, after: &str) -> String {
    let a: Vec<&str> = before.split_inclusive('\n').collect();
    let b: Vec<&str> = after.split_inclusive('\n').collect();
    let mut out = format!("--- {path}\n+++ {path}\n");
    if a.len() > 400 || b.len() > 400 {
        out.push_str("[diff omitted: too many lines]\n");
        return out;
    }
    let lcs = lcs_table(&a, &b);
    let mut i = a.len();
    let mut j = b.len();
    let mut hunks = Vec::new();
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && a[i - 1] == b[j - 1] {
            hunks.push(format!(" {}", a[i - 1]));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || lcs[i][j - 1] >= lcs[i - 1][j]) {
            hunks.push(format!("+{}", b[j - 1]));
            j -= 1;
        } else if i > 0 {
            hunks.push(format!("-{}", a[i - 1]));
            i -= 1;
        }
    }
    hunks.reverse();
    for line in hunks {
        out.push_str(&line);
        if !line.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn lcs_table(a: &[&str], b: &[&str]) -> Vec<Vec<u16>> {
    let mut table = vec![vec![0u16; b.len() + 1]; a.len() + 1];
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            table[i][j] = if a[i - 1] == b[j - 1] {
                table[i - 1][j - 1].saturating_add(1)
            } else {
                table[i - 1][j].max(table[i][j - 1])
            };
        }
    }
    table
}

fn push_capped(buf: &mut Vec<u8>, header: &[u8], data: &[u8], cap: usize) {
    if data.is_empty() || cap == 0 {
        return;
    }
    buf.extend_from_slice(header);
    let room = cap.saturating_sub(buf.len());
    let take = data.len().min(room);
    buf.extend_from_slice(&data[..take]);
    if take < data.len() {
        buf.extend_from_slice(b"\n[truncated]\n");
    }
}

pub fn alert_matches(rule: &AlertRule, record: &AuditRecord) -> bool {
    if let Some(category) = &rule.match_category {
        if record.category != *category {
            return false;
        }
    }
    if let Some(op) = &rule.match_op {
        if record.op != *op {
            return false;
        }
    }
    if let Some(result) = &rule.match_result {
        if record.result != *result {
            return false;
        }
    }
    if let Some(text) = &rule.match_text {
        let hay = serde_json::to_string(record).unwrap_or_default();
        if !hay
            .to_ascii_lowercase()
            .contains(&text.to_ascii_lowercase())
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(category: &str, action: &str) -> AuditEvent {
        AuditEvent {
            category: category.into(),
            action: action.into(),
            client_id: "agent".into(),
            paths: vec!["/work/a.txt".into()],
            command: Some("echo hi".into()),
            ok: true,
            ..AuditEvent::default()
        }
    }

    #[test]
    fn toggles_presets_and_redaction() {
        let mut policy = AuditPolicy::preset("standard").unwrap();
        assert!(prepare(&policy, "n", "box", &event("file_read", "read")).is_some());
        policy
            .set_key("categories.file_read.enabled", "false")
            .unwrap();
        assert!(prepare(&policy, "n", "box", &event("file_read", "read")).is_none());
        policy
            .set_key("categories.file_read.enabled", "true")
            .unwrap();
        policy
            .set_key("categories.file_read.detail", "metadata")
            .unwrap();
        let draft = prepare(&policy, "n", "box", &event("file_read", "read")).unwrap();
        assert!(draft.record.args.is_null());

        let mut write = event("file_write", "write");
        write.before = Some(b"hello secret=abc\n".to_vec());
        write.after = Some(b"hello secret=xyz\n".to_vec());
        policy
            .set_key("categories.file_write.detail", "diff")
            .unwrap();
        let draft = prepare(&policy, "n", "box", &write).unwrap();
        assert!(draft.record.before_hash.is_some());
        assert!(draft.record.after_hash.is_some());
        let diff = String::from_utf8(draft.diff.unwrap()).unwrap();
        assert!(diff.contains("[redacted]"), "{diff}");
        assert!(!diff.contains("secret=abc"), "{diff}");

        let mut binary = write.clone();
        binary.before = Some(b"a\0b".to_vec());
        binary.after = Some(b"a\0c".to_vec());
        let draft = prepare(&policy, "n", "box", &binary).unwrap();
        assert!(draft.diff.is_none());
        assert!(draft.record.before_hash.is_some());
    }

    #[test]
    fn chain_detects_tampering_and_path_exclude() {
        let policy = AuditPolicy::preset("minimal").unwrap();
        assert!(prepare(&policy, "n", "box", &event("file_read", "read")).is_none());
        assert!(prepare(&policy, "n", "box", &event("exec", "exec")).is_some());
        let mut hidden = event("exec", "exec");
        hidden.paths = vec!["/home/a/.ssh/id_rsa".into()];
        assert!(prepare(&policy, "n", "box", &hidden).is_none());

        let mut first = prepare(&policy, "n", "box", &event("exec", "exec"))
            .unwrap()
            .record;
        assign_chain(&mut first, 1, &"0".repeat(64), true);
        let mut second = first.clone();
        second.op = "exec".into();
        second.ts = "2026-01-01T00:00:01Z".into();
        assign_chain(&mut second, 2, &first.hash, true);
        verify_chain(&[first.clone(), second.clone()]).unwrap();
        second.result = "error".into();
        assert!(verify_chain(&[first, second]).is_err());
    }

    #[test]
    fn bad_regex_is_rejected() {
        let mut policy = AuditPolicy::preset("standard").unwrap();
        policy.redact.patterns = vec!["[".into()];
        assert!(policy.validate().is_err());
    }

    #[test]
    fn parse_roundtrip_keeps_a_toggle() {
        let mut policy = AuditPolicy::preset("full").unwrap();
        policy.set_key("forward.central", "false").unwrap();
        policy.set_key("recording.mode", "always").unwrap();
        let text = policy.to_toml().unwrap();
        let back = AuditPolicy::parse(&text).unwrap();
        assert!(!back.forward.central);
        assert_eq!(back.recording.mode, "always");
        assert_eq!(back.detail_for("pty"), Detail::Output);
    }
}
