//! `node://name/path` paths for `agentlink cp`.
//!
//! - Absolute remote Unix path: `node://laptop/tmp/a` -> `/tmp/a`.
//! - Relative remote path (for `--root` jailed nodes or cwd): `node://laptop/./a` -> `./a`,
//!   `node://laptop/.` -> `.`, `node://laptop/~/a` -> `~/a`.
//! - Windows drive path: `node://laptop/C:/a` -> `C:/a`.
//! - Malformed `node://` URIs (missing host or missing path, e.g. `node://laptop` or
//!   `node://laptop/`) return an explicit error instead of silently falling back to a local path.

use std::path::PathBuf;

use anyhow::{anyhow, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Local(PathBuf),
    Remote { node: String, path: String },
}

pub fn parse_endpoint(input: &str) -> Result<Endpoint> {
    let Some(rest) = input.strip_prefix("node://") else {
        return Ok(Endpoint::Local(PathBuf::from(input)));
    };
    let Some((node, path)) = rest.split_once('/') else {
        return Err(anyhow!(
            "invalid remote endpoint `{input}`: expected `node://<node>/<path>` \
             (for example `node://laptop/tmp/file` or `node://laptop/./file`)"
        ));
    };
    let node = node.trim();
    if node.is_empty() || path.is_empty() {
        return Err(anyhow!(
            "invalid remote endpoint `{input}`: both node and path are required \
             (for example `node://laptop/tmp/file` or `node://laptop/./file`)"
        ));
    }
    let remote = if looks_like_windows_drive(path) || is_explicit_relative_or_home(path) {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Ok(Endpoint::Remote {
        node: node.to_string(),
        path: remote,
    })
}

fn looks_like_windows_drive(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_explicit_relative_or_home(path: &str) -> bool {
    path == "."
        || path == ".."
        || path == "~"
        || path.starts_with("./")
        || path.starts_with("../")
        || path.starts_with("~/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_windows_relative_home_and_local() {
        assert_eq!(
            parse_endpoint("node://laptop/tmp/a").unwrap(),
            Endpoint::Remote {
                node: "laptop".into(),
                path: "/tmp/a".into(),
            }
        );
        assert_eq!(
            parse_endpoint("node://laptop/C:/Users/a.txt").unwrap(),
            Endpoint::Remote {
                node: "laptop".into(),
                path: "C:/Users/a.txt".into(),
            }
        );
        assert_eq!(
            parse_endpoint("node://alpha/./up.txt").unwrap(),
            Endpoint::Remote {
                node: "alpha".into(),
                path: "./up.txt".into(),
            }
        );
        assert_eq!(
            parse_endpoint("node://alpha/.").unwrap(),
            Endpoint::Remote {
                node: "alpha".into(),
                path: ".".into(),
            }
        );
        assert_eq!(
            parse_endpoint("node://alpha/~/notes.txt").unwrap(),
            Endpoint::Remote {
                node: "alpha".into(),
                path: "~/notes.txt".into(),
            }
        );
        assert_eq!(
            parse_endpoint("./local.txt").unwrap(),
            Endpoint::Local(PathBuf::from("./local.txt"))
        );
    }

    #[test]
    fn rejects_malformed_node_uris() {
        for bad in ["node://", "node://laptop", "node://laptop/", "node:///tmp/a"] {
            let err = parse_endpoint(bad).unwrap_err().to_string();
            assert!(err.contains("invalid remote endpoint"), "{bad} -> {err}");
        }
    }
}
