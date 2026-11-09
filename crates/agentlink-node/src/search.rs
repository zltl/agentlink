//! Content and filename search.
//!
//! Content search is line oriented, like ripgrep: it uses the `grep` matcher
//! and the `ignore` walker, so `.gitignore` rules apply. `.` does not match a
//! newline. Binary files and files larger than 4 MiB are skipped. While walking
//! a directory, unreadable files (`PermissionDenied` / `NotFound`) are skipped
//! like `watch` — a single mode-000 lock must not fail the whole tree. A direct
//! search of one unreadable file still errors.

use std::collections::VecDeque;
use std::io;
use std::path::Path;

use agentlink_core::{Error, Result};
use grep_regex::RegexMatcherBuilder;
use grep_searcher::{
    BinaryDetection, Searcher, SearcherBuilder, Sink, SinkContext, SinkContextKind, SinkMatch,
};
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use serde_json::{json, Value};

const MAX_PATTERN: usize = 4 * 1024;
const MAX_LIMIT: u32 = 500;
const DEFAULT_CONTENT_LIMIT: u32 = 100;
const DEFAULT_NAME_LIMIT: u32 = 200;
const MAX_CONTEXT: u32 = 20;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SCAN_FILES: u32 = 20_000;
const MAX_OFFSET: u32 = 10_000;

#[derive(Debug, Clone)]
pub struct ContentQuery {
    pub path: String,
    pub pattern: String,
    pub literal: bool,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub gitignore: bool,
    pub include_hidden: bool,
    pub case_insensitive: bool,
    pub before: u32,
    pub after: u32,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Clone)]
pub struct NameQuery {
    pub path: String,
    pub pattern: String,
    pub regex: bool,
    pub gitignore: bool,
    pub include_hidden: bool,
    pub case_insensitive: bool,
    pub offset: u32,
    pub limit: u32,
}

pub async fn content_search(root: Option<&Path>, query: ContentQuery) -> Result<Value> {
    let root = root.map(|path| path.to_path_buf());
    tokio::task::spawn_blocking(move || content_search_blocking(root.as_deref(), &query))
        .await
        .map_err(|err| Error::Message(format!("search task: {err}")))?
}

pub async fn filename_search(root: Option<&Path>, query: NameQuery) -> Result<Value> {
    let root = root.map(|path| path.to_path_buf());
    tokio::task::spawn_blocking(move || filename_search_blocking(root.as_deref(), &query))
        .await
        .map_err(|err| Error::Message(format!("search task: {err}")))?
}

fn content_search_blocking(sandbox: Option<&Path>, query: &ContentQuery) -> Result<Value> {
    validate_pattern(&query.pattern)?;
    if query.offset > MAX_OFFSET {
        return Err(Error::Message(format!(
            "offset {} exceeds the {MAX_OFFSET} limit",
            query.offset
        )));
    }
    let limit = clamp_limit(query.limit, DEFAULT_CONTENT_LIMIT);
    let before = query.before.min(MAX_CONTEXT);
    let after = query.after.min(MAX_CONTEXT);
    let full = agentlink_core::paths::resolve_path(sandbox, &query.path)?;
    if !full.exists() {
        return Err(missing_root_error(&full));
    }

    let matcher = RegexMatcherBuilder::new()
        .case_insensitive(query.case_insensitive)
        .fixed_strings(query.literal)
        .size_limit(8 * 1024 * 1024)
        .dfa_size_limit(8 * 1024 * 1024)
        .build(&query.pattern)
        .map_err(|err| Error::Message(format!("pattern: {err}")))?;
    let mut searcher = SearcherBuilder::new()
        .line_number(true)
        .before_context(before as usize)
        .after_context(after as usize)
        .binary_detection(BinaryDetection::quit(b'\0'))
        .build();
    let mut collector = Collector {
        path: String::new(),
        before_n: before as usize,
        after_n: after as usize,
        offset: query.offset,
        limit,
        seen: 0,
        truncated: false,
        stop: false,
        recent_before: VecDeque::new(),
        hits: Vec::new(),
        open_after: false,
    };

    let mut scanned = 0u32;
    let mut skipped_files = 0u32;
    if full.is_file() {
        let within_size = std::fs::metadata(&full)
            .map(|meta| meta.len() <= MAX_FILE_BYTES)
            .unwrap_or(true);
        if within_size && glob_allows(&full, &full, &query.include, &query.exclude)? {
            collector.path = full.display().to_string();
            scanned = 1;
            // Direct file search: surface permission errors to the caller.
            searcher
                .search_path(&matcher, &full, Collect(&mut collector))
                .map_err(|err| Error::Message(format!("search {}: {err}", full.display())))?;
        }
    } else {
        let walk = walker(
            &full,
            query.gitignore,
            query.include_hidden,
            &query.include,
            &query.exclude,
        )?;
        for entry in walk.build() {
            if collector.stop {
                break;
            }
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                continue;
            }
            scanned += 1;
            if scanned > MAX_SCAN_FILES {
                collector.truncated = true;
                break;
            }
            collector.path = entry.path().display().to_string();
            collector.recent_before.clear();
            collector.open_after = false;
            match searcher.search_path(&matcher, entry.path(), Collect(&mut collector)) {
                Ok(()) => {}
                Err(err) if skippable_search_io(&err) => {
                    skipped_files = skipped_files.saturating_add(1);
                }
                Err(err) => {
                    return Err(Error::Message(format!(
                        "search {}: {err}",
                        entry.path().display()
                    )));
                }
            }
        }
    }

    let next_offset = query.offset + collector.hits.len() as u32;
    let matches = collector
        .hits
        .iter()
        .map(|hit| {
            json!({
                "path": hit.path,
                "line": hit.line,
                "text": hit.text,
                "before": lines_json(&hit.before),
                "after": lines_json(&hit.after),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "matches": matches,
        "truncated": collector.truncated,
        "next_offset": next_offset,
        "scanned_files": scanned,
        "skipped_files": skipped_files,
    }))
}

/// `exists()` is also false below a file component (`/etc/hostname/nope`), so
/// tip ENOTDIR instead of claiming the root is missing.
fn missing_root_error(full: &Path) -> Error {
    agentlink_core::util::path_component_not_dir_error(full)
        .unwrap_or_else(|| Error::NotFound(full.display().to_string()))
}

/// Walk-time skips for files the process cannot open (mode 000 locks, races).
fn skippable_search_io(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
    )
}

fn filename_search_blocking(sandbox: Option<&Path>, query: &NameQuery) -> Result<Value> {
    validate_pattern(&query.pattern)?;
    if query.offset > MAX_OFFSET {
        return Err(Error::Message(format!(
            "offset {} exceeds the {MAX_OFFSET} limit",
            query.offset
        )));
    }
    let limit = clamp_limit(query.limit, DEFAULT_NAME_LIMIT);
    let full = agentlink_core::paths::resolve_path(sandbox, &query.path)?;
    if !full.exists() {
        return Err(missing_root_error(&full));
    }
    let regex = if query.regex {
        Some(
            regex::RegexBuilder::new(&query.pattern)
                .case_insensitive(query.case_insensitive)
                .size_limit(1 << 20)
                .build()
                .map_err(|err| Error::Message(format!("pattern: {err}")))?,
        )
    } else {
        None
    };
    let glob = if query.regex {
        None
    } else {
        Some(
            globset::GlobBuilder::new(&query.pattern)
                .case_insensitive(query.case_insensitive)
                .literal_separator(false)
                .backslash_escape(true)
                .build()
                .map_err(|err| Error::Message(format!("glob: {err}")))?
                .compile_matcher(),
        )
    };

    let mut found = Vec::new();
    let mut seen = 0u32;
    let mut truncated = false;
    let mut consider = |path: &Path, is_dir: bool, is_file: bool, size: u64| {
        let rel = path
            .strip_prefix(&full)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        // Agents often pass an absolute path as the pattern (`find NODE /tmp/a.txt /`).
        // Match against the absolute form too, not only the root-relative strip.
        let abs = path.to_string_lossy().replace('\\', "/");
        let matched = if let Some(regex) = &regex {
            regex.is_match(&rel) || regex.is_match(&name) || regex.is_match(&abs)
        } else if let Some(glob) = &glob {
            glob.is_match(&rel) || glob.is_match(&name) || glob.is_match(&abs)
        } else {
            false
        };
        if !matched {
            return false;
        }
        seen += 1;
        if seen <= query.offset {
            return false;
        }
        if found.len() as u32 >= limit {
            truncated = true;
            return true;
        }
        found.push(json!({
            "path": path.display().to_string(),
            "name": name,
            "is_dir": is_dir,
            "is_file": is_file,
            "size": size,
        }));
        false
    };

    if full.is_file() {
        let size = std::fs::metadata(&full).map(|meta| meta.len()).unwrap_or(0);
        consider(&full, false, true, size);
    } else {
        let walk = walker(&full, query.gitignore, query.include_hidden, &[], &[])?;
        for entry in walk.build() {
            let Ok(entry) = entry else { continue };
            let Some(kind) = entry.file_type() else {
                continue;
            };
            if path_eq(entry.path(), &full) {
                continue;
            }
            if kind.is_symlink() {
                continue;
            }
            let size = entry.metadata().map(|meta| meta.len()).unwrap_or(0);
            if consider(entry.path(), kind.is_dir(), kind.is_file(), size) {
                break;
            }
        }
    }
    found.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(json!({
        "matches": found,
        "truncated": truncated,
        "next_offset": query.offset + found.len() as u32,
    }))
}

fn walker(
    root: &Path,
    gitignore: bool,
    include_hidden: bool,
    include: &[String],
    exclude: &[String],
) -> Result<WalkBuilder> {
    let mut builder = WalkBuilder::new(root);
    builder
        .follow_links(false)
        .max_filesize(Some(MAX_FILE_BYTES))
        .hidden(!include_hidden)
        .parents(false)
        .git_ignore(gitignore)
        .git_global(false)
        .git_exclude(gitignore)
        .ignore(true)
        .require_git(false);
    if !include.is_empty() || !exclude.is_empty() {
        builder.overrides(build_overrides(root, include, exclude)?);
    }
    Ok(builder)
}

fn build_overrides(
    root: &Path,
    include: &[String],
    exclude: &[String],
) -> Result<ignore::overrides::Override> {
    let mut over = OverrideBuilder::new(root);
    for glob in include {
        validate_glob(glob)?;
        over.add(glob)
            .map_err(|err| Error::Message(format!("include glob '{glob}': {err}")))?;
    }
    for glob in exclude {
        validate_glob(glob)?;
        let pattern = if glob.starts_with('!') {
            glob.to_string()
        } else {
            format!("!{glob}")
        };
        over.add(&pattern)
            .map_err(|err| Error::Message(format!("exclude glob '{glob}': {err}")))?;
    }
    over.build()
        .map_err(|err| Error::Message(format!("globs: {err}")))
}

fn glob_allows(root: &Path, file: &Path, include: &[String], exclude: &[String]) -> Result<bool> {
    if include.is_empty() && exclude.is_empty() {
        return Ok(true);
    }
    let over = build_overrides(root.parent().unwrap_or(root), include, exclude)?;
    Ok(!over.matched(file, false).is_ignore())
}

fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern.is_empty() {
        return Err(Error::Message("pattern is empty".into()));
    }
    if pattern.len() > MAX_PATTERN {
        return Err(Error::Message(format!(
            "pattern is longer than {MAX_PATTERN} bytes"
        )));
    }
    if pattern.contains('\0') {
        return Err(Error::Message("pattern contains NUL".into()));
    }
    Ok(())
}

fn validate_glob(glob: &str) -> Result<()> {
    if glob.is_empty() || glob.len() > MAX_PATTERN || glob.contains('\0') {
        return Err(Error::Message(format!("invalid glob '{glob}'")));
    }
    Ok(())
}

fn clamp_limit(limit: u32, default: u32) -> u32 {
    if limit == 0 {
        default
    } else {
        limit.min(MAX_LIMIT)
    }
}

fn path_eq(a: &Path, b: &Path) -> bool {
    a == b
}

struct LineHit {
    line: u64,
    text: String,
}

struct Hit {
    path: String,
    line: u64,
    text: String,
    before: Vec<LineHit>,
    after: Vec<LineHit>,
}

struct Collector {
    path: String,
    before_n: usize,
    after_n: usize,
    offset: u32,
    limit: u32,
    seen: u32,
    truncated: bool,
    stop: bool,
    recent_before: VecDeque<LineHit>,
    hits: Vec<Hit>,
    open_after: bool,
}

struct Collect<'a>(&'a mut Collector);

impl Sink for Collect<'_> {
    type Error = io::Error;

    fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch<'_>) -> io::Result<bool> {
        Ok(self.0.on_match(mat))
    }

    fn context(&mut self, _searcher: &Searcher, ctx: &SinkContext<'_>) -> io::Result<bool> {
        Ok(self.0.on_context(ctx))
    }

    fn context_break(&mut self, _searcher: &Searcher) -> io::Result<bool> {
        self.0.open_after = false;
        Ok(!self.0.stop)
    }
}

impl Collector {
    fn on_context(&mut self, ctx: &SinkContext<'_>) -> bool {
        if self.stop {
            return false;
        }
        let line = LineHit {
            line: ctx.line_number().unwrap_or(0),
            text: trim_line(ctx.bytes()),
        };
        match ctx.kind() {
            SinkContextKind::Before => {
                self.recent_before.push_back(line);
                while self.recent_before.len() > self.before_n {
                    self.recent_before.pop_front();
                }
            }
            SinkContextKind::After if self.open_after => {
                if let Some(hit) = self.hits.last_mut() {
                    if hit.after.len() < self.after_n {
                        hit.after.push(line);
                    }
                }
            }
            _ => {}
        }
        true
    }

    fn on_match(&mut self, mat: &SinkMatch<'_>) -> bool {
        if self.stop {
            return false;
        }
        let line_no = mat.line_number().unwrap_or(0);
        let text = trim_line(mat.bytes());
        if self
            .hits
            .last()
            .is_some_and(|hit| hit.line == line_no && hit.path == self.path && hit.text == text)
        {
            return true;
        }
        self.seen += 1;
        if self.seen <= self.offset {
            self.recent_before.clear();
            self.open_after = false;
            return true;
        }
        if self.hits.len() as u32 >= self.limit {
            self.truncated = true;
            self.stop = true;
            return false;
        }
        let before = self.recent_before.drain(..).collect();
        self.hits.push(Hit {
            path: self.path.clone(),
            line: line_no,
            text,
            before,
            after: Vec::new(),
        });
        self.open_after = self.after_n > 0;
        true
    }
}

fn trim_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.trim_end_matches(['\n', '\r']).to_string()
}

fn lines_json(lines: &[LineHit]) -> Vec<Value> {
    lines
        .iter()
        .map(|line| json!({"line": line.line, "text": line.text}))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tree(dir: &Path) {
        std::fs::write(dir.join("a.txt"), "alpha target\nsecond\n").unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("b.txt"), "one\ntarget line\nthree\n").unwrap();
        std::fs::create_dir_all(dir.join("ignored")).unwrap();
        std::fs::write(dir.join("ignored").join("c.txt"), "target hidden\n").unwrap();
        std::fs::write(dir.join(".gitignore"), "ignored/\n").unwrap();
        std::fs::write(dir.join("note.rs"), "fn main() {}\n").unwrap();
    }

    #[test]
    fn content_respects_gitignore_context_and_pages() {
        let dir = tempfile::tempdir().unwrap();
        write_tree(dir.path());
        let path = dir.path().display().to_string();
        let all = content_search_blocking(
            None,
            &ContentQuery {
                path: path.clone(),
                pattern: "target".into(),
                literal: true,
                include: vec![],
                exclude: vec![],
                gitignore: true,
                include_hidden: false,
                case_insensitive: false,
                before: 1,
                after: 1,
                offset: 0,
                limit: 20,
            },
        )
        .unwrap();
        let matches = all["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 2, "{all}");
        assert!(matches
            .iter()
            .all(|m| !m["path"].as_str().unwrap().contains("ignored")));
        let with_context = matches.iter().find(|m| m["text"] == "target line").unwrap();
        assert_eq!(with_context["before"][0]["text"], "one");
        assert_eq!(with_context["after"][0]["text"], "three");

        let page = content_search_blocking(
            None,
            &ContentQuery {
                path: path.clone(),
                pattern: "t.rget".into(),
                literal: false,
                include: vec![],
                exclude: vec![],
                gitignore: true,
                include_hidden: false,
                case_insensitive: false,
                before: 0,
                after: 0,
                offset: 1,
                limit: 1,
            },
        )
        .unwrap();
        assert_eq!(page["matches"].as_array().unwrap().len(), 1);
        assert_eq!(page["next_offset"], 2);

        let literal = content_search_blocking(
            None,
            &ContentQuery {
                path,
                pattern: "t.rget".into(),
                literal: true,
                include: vec![],
                exclude: vec![],
                gitignore: true,
                include_hidden: false,
                case_insensitive: false,
                before: 0,
                after: 0,
                offset: 0,
                limit: 10,
            },
        )
        .unwrap();
        assert!(literal["matches"].as_array().unwrap().is_empty());
    }

    #[test]
    fn include_glob_and_filename_search() {
        let dir = tempfile::tempdir().unwrap();
        write_tree(dir.path());
        let path = dir.path().display().to_string();
        let only_rs = content_search_blocking(
            None,
            &ContentQuery {
                path: path.clone(),
                pattern: "target".into(),
                literal: true,
                include: vec!["*.rs".into()],
                exclude: vec![],
                gitignore: true,
                include_hidden: false,
                case_insensitive: false,
                before: 0,
                after: 0,
                offset: 0,
                limit: 10,
            },
        )
        .unwrap();
        assert!(
            only_rs["matches"].as_array().unwrap().is_empty(),
            "{only_rs}"
        );

        let names = filename_search_blocking(
            None,
            &NameQuery {
                path,
                pattern: "*.rs".into(),
                regex: false,
                gitignore: true,
                include_hidden: false,
                case_insensitive: false,
                offset: 0,
                limit: 20,
            },
        )
        .unwrap();
        let matches = names["matches"].as_array().unwrap();
        assert!(matches.iter().any(|m| m["name"] == "note.rs"), "{names}");
        assert!(matches.iter().all(|m| m["name"] != "a.txt"));
        assert!(matches
            .iter()
            .all(|m| !m["path"].as_str().unwrap().contains("ignored")));
    }

    #[test]
    fn content_skips_binary_files() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("blob.bin");
        std::fs::write(&binary, b"target before\0target after\n").unwrap();
        let text = dir.path().join("plain.txt");
        std::fs::write(&text, "target text\n").unwrap();

        let query = |path: String| ContentQuery {
            path,
            pattern: "target".into(),
            literal: true,
            include: vec![],
            exclude: vec![],
            gitignore: false,
            include_hidden: false,
            case_insensitive: false,
            before: 0,
            after: 0,
            offset: 0,
            limit: 10,
        };

        let walked =
            content_search_blocking(None, &query(dir.path().display().to_string())).unwrap();
        let matches = walked["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 1, "{walked}");
        assert!(
            matches[0]["path"].as_str().unwrap().ends_with("plain.txt"),
            "{walked}"
        );

        let direct = content_search_blocking(None, &query(binary.display().to_string())).unwrap();
        assert!(direct["matches"].as_array().unwrap().is_empty(), "{direct}");
    }

    #[test]
    #[cfg(unix)]
    fn content_skips_permission_denied_while_walking() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let readable = dir.path().join("ok.txt");
        std::fs::write(&readable, "needle here\n").unwrap();
        let denied = dir.path().join("locked.txt");
        std::fs::write(&denied, "needle secret\n").unwrap();
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();

        let walked = content_search_blocking(
            None,
            &ContentQuery {
                path: dir.path().display().to_string(),
                pattern: "needle".into(),
                literal: true,
                include: vec![],
                exclude: vec![],
                gitignore: false,
                include_hidden: false,
                case_insensitive: false,
                before: 0,
                after: 0,
                offset: 0,
                limit: 10,
            },
        )
        .unwrap();
        let matches = walked["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 1, "{walked}");
        assert!(
            matches[0]["path"].as_str().unwrap().ends_with("ok.txt"),
            "{walked}"
        );
        assert!(
            walked["skipped_files"].as_u64().unwrap_or(0) >= 1,
            "expected skipped_files >= 1, got {walked}"
        );

        // Direct search of the locked file still fails loudly.
        let err = content_search_blocking(
            None,
            &ContentQuery {
                path: denied.display().to_string(),
                pattern: "needle".into(),
                literal: true,
                include: vec![],
                exclude: vec![],
                gitignore: false,
                include_hidden: false,
                case_insensitive: false,
                before: 0,
                after: 0,
                offset: 0,
                limit: 10,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("Permission denied") || err.contains("os error 13"),
            "{err}"
        );

        let _ = std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o644));
    }

    #[test]
    fn content_and_name_search_tip_when_root_is_below_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hostname");
        std::fs::write(&file, b"box\n").unwrap();
        let child = file.join("nope");
        assert!(!child.exists(), "precondition: child of file must not exist");

        let content_err = content_search_blocking(
            None,
            &ContentQuery {
                path: child.display().to_string(),
                pattern: "box".into(),
                literal: true,
                include: vec![],
                exclude: vec![],
                gitignore: true,
                include_hidden: false,
                case_insensitive: false,
                before: 0,
                after: 0,
                offset: 0,
                limit: 10,
            },
        )
        .unwrap_err();
        assert!(
            !matches!(content_err, Error::NotFound(_)),
            "tip, not NotFound"
        );
        let msg = content_err.to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains(&file.display().to_string()), "{msg}");

        let name_err = filename_search_blocking(
            None,
            &NameQuery {
                path: child.display().to_string(),
                pattern: "x".into(),
                regex: false,
                gitignore: true,
                include_hidden: false,
                case_insensitive: false,
                offset: 0,
                limit: 10,
            },
        )
        .unwrap_err();
        assert!(
            !matches!(name_err, Error::NotFound(_)),
            "tip, not NotFound"
        );
        let msg = name_err.to_string();
        assert!(msg.contains("exists but is not a directory"), "{msg}");
        assert!(msg.contains(&file.display().to_string()), "{msg}");
    }

    #[test]
    fn missing_root_is_still_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let err = content_search_blocking(
            None,
            &ContentQuery {
                path: missing.display().to_string(),
                pattern: "x".into(),
                literal: true,
                include: vec![],
                exclude: vec![],
                gitignore: true,
                include_hidden: false,
                case_insensitive: false,
                before: 0,
                after: 0,
                offset: 0,
                limit: 10,
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{err}");
    }

    #[test]
    fn absolute_path_pattern_matches() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("target.txt");
        std::fs::write(&file, b"x").unwrap();
        let abs = file.display().to_string();
        let root = dir.path().display().to_string();
        let names = filename_search_blocking(
            None,
            &NameQuery {
                path: root,
                pattern: abs.clone(),
                regex: false,
                gitignore: false,
                include_hidden: false,
                case_insensitive: false,
                offset: 0,
                limit: 20,
            },
        )
        .unwrap();
        let matches = names["matches"].as_array().unwrap();
        assert!(
            matches.iter().any(|m| m["path"].as_str() == Some(abs.as_str())),
            "{names}"
        );
    }
}
