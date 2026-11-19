//! Bounded JSONL audit log readers.
//!
//! Paging and chain-tip helpers stream `audit.jsonl` without buffering the
//! whole file, and refuse individual lines larger than [`MAX_AUDIT_LINE_BYTES`].

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::audit::{AuditFilter, AuditRecord};

/// Stream `audit.jsonl` and keep the newest matching records.
///
/// Memory is `O(limit)` (default 200), never the full file size. Prefer this
/// over loading the whole log into a `Vec` before filtering.
pub fn select_from_jsonl(path: &Path, filter: &AuditFilter) -> Vec<AuditRecord> {
    let limit = if filter.limit == 0 { 200 } else { filter.limit };
    page_from_jsonl(path, limit, 0, |record| filter.matches(record))
}

/// Hard ceiling for a single `audit.jsonl` line. Oversized lines are skipped
/// so a hostile/corrupt multi-megabyte record cannot force an unbounded alloc
/// through `BufRead::lines()`.
pub const MAX_AUDIT_LINE_BYTES: usize = 1024 * 1024;

/// Newest-last page over a streamed `audit.jsonl`.
///
/// Records are scanned oldest→newest. Only rows that pass `keep` enter a ring
/// of capacity `limit + offset`. The newest `offset` matches are then dropped,
/// leaving at most `limit` rows. Memory is `O(limit + offset + MAX_AUDIT_LINE_BYTES)`,
/// independent of file length — callers must clamp `offset` themselves for DoS control.
pub fn page_from_jsonl(
    path: &Path,
    limit: usize,
    offset: usize,
    mut keep: impl FnMut(&AuditRecord) -> bool,
) -> Vec<AuditRecord> {
    if limit == 0 {
        return Vec::new();
    }
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
    let cap = limit.saturating_add(offset);
    let mut ring: VecDeque<AuditRecord> = VecDeque::with_capacity(cap.min(4_096));
    for_each_bounded_line(file, |line| {
        let Ok(record) = serde_json::from_str::<AuditRecord>(line) else {
            return;
        };
        if !keep(&record) {
            return;
        }
        if ring.len() == cap {
            ring.pop_front();
        }
        ring.push_back(record);
    });
    for _ in 0..offset {
        if ring.pop_back().is_none() {
            break;
        }
    }
    ring.into_iter().collect()
}

/// Last chained audit tip (`seq`, `hash`) without buffering the full log.
/// Records with `hash == "off"` are skipped. Missing files yield the genesis tip.
pub fn chain_tip_from_jsonl(path: &Path) -> (u64, String) {
    let mut seq = 0u64;
    let mut hash = "0".repeat(64);
    let Ok(file) = File::open(path) else {
        return (seq, hash);
    };
    for_each_bounded_line(file, |line| {
        let Ok(record) = serde_json::from_str::<AuditRecord>(line) else {
            return;
        };
        if record.hash == "off" {
            return;
        }
        seq = record.seq;
        hash = record.hash.clone();
    });
    (seq, hash)
}

/// Newest-last `limit` raw UTF-8 lines (not parsed), each at most
/// [`MAX_AUDIT_LINE_BYTES`]. Oversized lines are skipped. Memory is
/// `O(limit + MAX_AUDIT_LINE_BYTES)`.
pub fn tail_bounded_lines(path: &Path, limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
    let mut ring: VecDeque<String> = VecDeque::with_capacity(limit.min(4_096));
    for_each_bounded_line(file, |line| {
        if ring.len() == limit {
            ring.pop_front();
        }
        ring.push_back(line.to_string());
    });
    ring.into_iter().collect()
}

/// Invoke `on_line` for each UTF-8 line whose encoded size is at most
/// [`MAX_AUDIT_LINE_BYTES`]. Larger lines are discarded without retaining them
/// and without consuming bytes that belong to the following line.
pub fn for_each_bounded_line(file: File, mut on_line: impl FnMut(&str)) {
    let mut reader = BufReader::new(file);
    let mut buf = Vec::with_capacity(4_096);
    loop {
        buf.clear();
        match read_bounded_line(&mut reader, &mut buf, MAX_AUDIT_LINE_BYTES) {
            Ok(BoundedLine::Eof) => break,
            Ok(BoundedLine::SkippedOversized) => continue,
            Ok(BoundedLine::Line) => {
                let text = match std::str::from_utf8(&buf) {
                    Ok(text) => text.trim_end_matches(['\r', '\n']),
                    Err(_) => continue,
                };
                if text.is_empty() {
                    continue;
                }
                on_line(text);
            }
            Err(_) => break,
        }
    }
}

enum BoundedLine {
    Line,
    SkippedOversized,
    Eof,
}

/// Read one logical line with a hard byte cap.
///
/// Discard of oversized lines uses only [`BufRead::fill_buf`]/[`BufRead::consume`]
/// so the terminating newline is consumed precisely — never a raw `Read::read`
/// that could swallow the start of the next record.
fn read_bounded_line(
    reader: &mut impl BufRead,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<BoundedLine> {
    loop {
        let available = {
            let data = reader.fill_buf()?;
            if data.is_empty() {
                return Ok(if buf.is_empty() {
                    BoundedLine::Eof
                } else if buf.len() > max {
                    BoundedLine::SkippedOversized
                } else {
                    BoundedLine::Line
                });
            }
            data
        };
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if buf.len() + pos > max {
                // Consume only through this line's newline; leave following bytes.
                reader.consume(take);
                buf.clear();
                return Ok(BoundedLine::SkippedOversized);
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            return Ok(BoundedLine::Line);
        }
        if buf.len() + available.len() > max {
            // Oversized and no newline in this buffer: drop the chunk, then
            // keep discarding with fill_buf until we see a newline (consume
            // only through that byte so the next line remains intact).
            let n = available.len();
            reader.consume(n);
            loop {
                let data = reader.fill_buf()?;
                if data.is_empty() {
                    buf.clear();
                    return Ok(BoundedLine::SkippedOversized);
                }
                if let Some(pos) = data.iter().position(|&b| b == b'\n') {
                    reader.consume(pos + 1);
                    buf.clear();
                    return Ok(BoundedLine::SkippedOversized);
                }
                let n = data.len();
                reader.consume(n);
            }
        }
        let n = available.len();
        buf.extend_from_slice(available);
        reader.consume(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn discard_path_preserves_bytes_after_oversized_newline() {
        // Force the overflow branch: fill past max with no newline in the first
        // chunks, then a large gap before `\n`, then a good record. Previously
        // `Read::read` into a fixed discard buffer could swallow the good line.
        let max = 64usize;
        let mut body = vec![b'x'; max + 50_000];
        body.push(b'\n');
        body.extend_from_slice(br#"{"op":"keep"}"#);
        body.push(b'\n');
        let mut reader = BufReader::with_capacity(32, Cursor::new(body));
        let mut buf = Vec::new();
        let skipped = read_bounded_line(&mut reader, &mut buf, max).unwrap();
        assert!(matches!(skipped, BoundedLine::SkippedOversized));
        buf.clear();
        let kept = read_bounded_line(&mut reader, &mut buf, max).unwrap();
        assert!(matches!(kept, BoundedLine::Line), "good line must survive");
        let text = std::str::from_utf8(&buf)
            .unwrap()
            .trim_end_matches(['\r', '\n']);
        assert_eq!(text, r#"{"op":"keep"}"#);
    }

    #[test]
    fn page_from_jsonl_keeps_record_after_hostile_gap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut body = vec![b'x'; MAX_AUDIT_LINE_BYTES + 50_000];
        body.push(b'\n');
        body.extend_from_slice(
            br#"{"seq":1,"ts":"t","node_id":"n","node_name":"n","client_id":"c","category":"op","op":"keep","result":"ok","duration_ms":0,"prev_hash":"0","hash":"1"}
"#,
        );
        std::fs::write(&path, &body).unwrap();
        let page = page_from_jsonl(&path, 10, 0, |_| true);
        assert_eq!(page.len(), 1, "good record after hostile gap must be kept");
        assert_eq!(page[0].op, "keep");
    }
}
