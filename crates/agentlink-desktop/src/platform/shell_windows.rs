//! GNOME Shell Introspect window list helpers (no PipeWire dependency).
//!
//! Mutter `RecordWindow` needs a numeric Shell window id (`t`). Queries from
//! `screenshot --window-id` may be that id or a case-insensitive title
//! substring — same matching rules as the X11 window path.

use crate::error::{msg, Result};

#[derive(Debug, Clone)]
pub struct ShellWindow {
    pub id: u64,
    pub title: String,
    pub hidden: bool,
}

/// Match a numeric Mutter/Shell window id, else a case-insensitive title substring.
pub fn match_window_query(query: &str, windows: &[ShellWindow]) -> Result<u64> {
    let query = query.trim();
    if query.is_empty() {
        return Err(msg("window capture needs a non-empty window_id"));
    }
    if let Ok(id) = query.parse::<u64>() {
        if windows.iter().any(|window| window.id == id && !window.hidden) {
            return Ok(id);
        }
        // Still accept a known id even if the hidden flag is stale.
        if windows.iter().any(|window| window.id == id) {
            return Ok(id);
        }
        return Err(msg(format!(
            "no window title contains '{query}' (and no Mutter window id {id})"
        )));
    }
    let needle = query.to_ascii_lowercase();
    let mut matches: Vec<&ShellWindow> = windows
        .iter()
        .filter(|window| !window.hidden)
        .filter(|window| window.title.to_ascii_lowercase().contains(&needle))
        .collect();
    if matches.is_empty() {
        matches = windows
            .iter()
            .filter(|window| window.title.to_ascii_lowercase().contains(&needle))
            .collect();
    }
    match matches.as_slice() {
        [one] => Ok(one.id),
        [] => Err(msg(format!("no window title contains '{query}'"))),
        many => Err(msg(format!(
            "window id '{query}' is ambiguous ({} matches); use the numeric Mutter window id",
            many.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows(rows: &[(u64, &str, bool)]) -> Vec<ShellWindow> {
        rows.iter()
            .map(|(id, title, hidden)| ShellWindow {
                id: *id,
                title: (*title).to_string(),
                hidden: *hidden,
            })
            .collect()
    }

    #[test]
    fn window_query_matches_id_and_title() {
        let windows = windows(&[
            (10, "Text Editor", false),
            (11, "Terminal", false),
            (12, "Hidden Notes", true),
        ]);
        assert_eq!(match_window_query("10", &windows).unwrap(), 10);
        assert_eq!(match_window_query("editor", &windows).unwrap(), 10);
        assert!(match_window_query("missing", &windows)
            .unwrap_err()
            .to_string()
            .contains("no window title contains"));
        assert!(match_window_query("99", &windows)
            .unwrap_err()
            .to_string()
            .contains("no Mutter window id 99"));
    }

    #[test]
    fn hidden_title_match_is_last_resort() {
        let windows = windows(&[(12, "Hidden Notes", true)]);
        assert_eq!(match_window_query("notes", &windows).unwrap(), 12);
    }

    #[test]
    fn ambiguous_title_requires_numeric_id() {
        let windows = windows(&[(1, "Notes A", false), (2, "Notes B", false)]);
        let err = match_window_query("notes", &windows).unwrap_err().to_string();
        assert!(err.contains("ambiguous"), "{err}");
    }
}
