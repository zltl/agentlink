//! `node://name/path` paths for `agentlink cp`.
//!
//! A remote unix path keeps a leading slash: `node://laptop/tmp/a` is `/tmp/a`.
//! A Windows drive is detected and left intact: `node://laptop/C:/a` is `C:/a`.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Local(PathBuf),
    Remote { node: String, path: String },
}

pub fn parse_endpoint(input: &str) -> Endpoint {
    let Some(rest) = input.strip_prefix("node://") else {
        return Endpoint::Local(PathBuf::from(input));
    };
    let Some((node, path)) = rest.split_once('/') else {
        return Endpoint::Local(PathBuf::from(input));
    };
    if node.is_empty() || path.is_empty() {
        return Endpoint::Local(PathBuf::from(input));
    }
    let remote = if looks_like_windows_drive(path) {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Endpoint::Remote {
        node: node.to_string(),
        path: remote,
    }
}

fn looks_like_windows_drive(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_and_windows_and_local() {
        match parse_endpoint("node://laptop/tmp/a") {
            Endpoint::Remote { node, path } => {
                assert_eq!(node, "laptop");
                assert_eq!(path, "/tmp/a");
            }
            Endpoint::Local(_) => panic!("remote"),
        }
        match parse_endpoint("node://laptop/C:/Users/a.txt") {
            Endpoint::Remote { path, .. } => assert_eq!(path, "C:/Users/a.txt"),
            Endpoint::Local(_) => panic!("remote"),
        }
        match parse_endpoint("./local.txt") {
            Endpoint::Local(path) => assert_eq!(path, PathBuf::from("./local.txt")),
            Endpoint::Remote { .. } => panic!("local"),
        }
    }
}
