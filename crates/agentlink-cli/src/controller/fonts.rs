//! System CJK font discovery for the desktop Controller.
//!
//! Inter and JetBrains Mono (SIL OFL 1.1, bundled under `assets/`) do not
//! cover CJK, so ideographs used to render as tofu (empty boxes). We do not
//! rebundle a 19 MiB Noto CJK collection. At startup we look for a
//! correctly licensed system font and, if the file is a TrueType Collection,
//! extract a single standalone face:
//!
//! - Noto Sans / Noto Sans Mono CJK (SIL OFL 1.1,
//!   https://github.com/notofonts/noto-cjk,
//!   typically the `fonts-noto-cjk` package on Debian/Ubuntu)
//! - Droid Sans Fallback (Apache-2.0) as a last Linux resort
//! - Platform UI fonts (PingFang, Yu Gothic, Microsoft YaHei, Malgun) are
//!   loaded only from the local OS font directory for on-screen fallback.
//!   They are not redistributed with this source or the candidate build.
//!
//! Missing system fonts are not a hard error: Latin UI and the terminal
//! still work, and CJK just will not have glyphs.

use std::fs;
use std::path::{Path, PathBuf};

/// Preferred face names, most specific first.
const PREFERRED_FACES: &[&str] = &[
    "Noto Sans Mono CJK SC",
    "Noto Sans Mono CJK",
    "Noto Sans CJK SC",
    "Noto Sans CJK",
    "Noto Sans SC",
    "Noto Sans JP",
    "Source Han Sans SC",
    "Source Han Sans",
    "Droid Sans Fallback",
    "PingFang SC",
    "PingFang",
    "Hiragino Sans GB",
    "Hiragino Sans",
    "Microsoft YaHei",
    "Yu Gothic",
    "Malgun Gothic",
    "Songti SC",
    "STHeiti",
];

fn search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let linux = [
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSansCJKsc-Regular.otf",
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        "/usr/share/fonts/truetype/droid/DroidSansFallback.ttf",
        "/usr/share/fonts/opentype/source-han-sans/SourceHanSansSC-Regular.otf",
        "/usr/share/fonts/adobe-source-han-sans/SourceHanSansSC-Regular.otf",
    ];
    paths.extend(linux.iter().map(PathBuf::from));
    if let Some(home) = &home {
        paths.push(home.join(".local/share/fonts/NotoSansCJK-Regular.ttc"));
        paths.push(home.join(".fonts/NotoSansCJK-Regular.ttc"));
    }
    let windows = [
        r"C:\Windows\Fonts\NotoSansCJK-Regular.ttc",
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\msyh.ttf",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\simsun.ttc",
        r"C:\Windows\Fonts\malgun.ttf",
        r"C:\Windows\Fonts\YuGothR.ttc",
        r"C:\Windows\Fonts\YuGothM.ttc",
    ];
    paths.extend(windows.iter().map(PathBuf::from));
    let mac = [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/Hiragino Sans GB.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/System/Library/Fonts/Supplemental/NotoSansCJK-Regular.ttc",
        "/Library/Fonts/NotoSansCJK-Regular.ttc",
        "/System/Library/Fonts/Supplemental/Songti.ttc",
        "/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc",
    ];
    paths.extend(mac.iter().map(PathBuf::from));
    paths
}

/// Load one CJK-capable face as a standalone OpenType/TrueType blob.
pub fn load_cjk_face() -> Option<Vec<u8>> {
    for path in search_paths() {
        if !path.is_file() {
            continue;
        }
        if let Some(face) = load_from_path(&path) {
            return Some(face);
        }
    }
    None
}

fn load_from_path(path: &Path) -> Option<Vec<u8>> {
    let data = fs::read(path).ok()?;
    if data.len() < 12 {
        return None;
    }
    if is_ttc(&data) {
        return extract_preferred_face(&data);
    }
    if is_sfnt(&data) {
        return Some(data);
    }
    None
}

fn is_ttc(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"ttcf"
}

fn is_sfnt(data: &[u8]) -> bool {
    data.len() >= 4 && matches!(&data[0..4], b"\0\x01\0\0" | b"OTTO" | b"true" | b"typ1")
}

fn be_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)
}

fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)?
        .try_into()
        .ok()
        .map(u32::from_be_bytes)
}

fn ttc_offsets(data: &[u8]) -> Option<Vec<u32>> {
    if !is_ttc(data) {
        return None;
    }
    let n = be_u32(data, 8)? as usize;
    let mut offsets = Vec::with_capacity(n);
    for i in 0..n {
        offsets.push(be_u32(data, 12 + i * 4)?);
    }
    Some(offsets)
}

/// Rebuild a standalone sfnt from one TTC face (tables may be shared).
pub fn extract_sfnt_face(data: &[u8], font_offset: u32) -> Option<Vec<u8>> {
    let off = font_offset as usize;
    if off + 12 > data.len() {
        return None;
    }
    let num_tables = be_u16(data, off + 4)? as usize;
    let header = data.get(off..off + 12)?.to_vec();
    let records_start = off + 12;
    if records_start.checked_add(num_tables.checked_mul(16)?)? > data.len() {
        return None;
    }
    let mut tables = Vec::with_capacity(num_tables);
    for i in 0..num_tables {
        let r = records_start + i * 16;
        let tag = data.get(r..r + 4)?.to_vec();
        let checksum = be_u32(data, r + 4)?;
        let offset = be_u32(data, r + 8)? as usize;
        let length = be_u32(data, r + 12)? as usize;
        let end = offset.checked_add(length)?;
        let blob = data.get(offset..end)?.to_vec();
        tables.push((tag, checksum, blob));
    }
    let mut out = header;
    let records_pos = out.len();
    out.resize(records_pos + num_tables * 16, 0);
    let mut rewritten = Vec::with_capacity(num_tables);
    for (tag, checksum, blob) in &tables {
        while out.len() % 4 != 0 {
            out.push(0);
        }
        let new_off = out.len() as u32;
        out.extend_from_slice(blob);
        rewritten.push((tag.clone(), *checksum, new_off, blob.len() as u32));
    }
    while out.len() % 4 != 0 {
        out.push(0);
    }
    for (i, (tag, checksum, offset, length)) in rewritten.iter().enumerate() {
        let r = records_pos + i * 16;
        out[r..r + 4].copy_from_slice(tag);
        out[r + 4..r + 8].copy_from_slice(&checksum.to_be_bytes());
        out[r + 8..r + 12].copy_from_slice(&offset.to_be_bytes());
        out[r + 12..r + 16].copy_from_slice(&length.to_be_bytes());
    }
    Some(out)
}

fn table_blob_at<'a>(data: &'a [u8], font_offset: usize, wanted: &[u8; 4]) -> Option<&'a [u8]> {
    let num = be_u16(data, font_offset + 4)? as usize;
    for i in 0..num {
        let r = font_offset + 12 + i * 16;
        if data.get(r..r + 4)? != wanted {
            continue;
        }
        let offset = be_u32(data, r + 8)? as usize;
        let length = be_u32(data, r + 12)? as usize;
        return data.get(offset..offset.checked_add(length)?);
    }
    None
}

fn table_blob<'a>(sfnt: &'a [u8], wanted: &[u8; 4]) -> Option<&'a [u8]> {
    table_blob_at(sfnt, 0, wanted)
}

/// Name IDs 1 (family), 4 (full), and 6 (PostScript) from the `name` table.
pub fn font_names(sfnt: &[u8]) -> Vec<String> {
    font_names_at(sfnt, 0)
}

fn font_names_at(data: &[u8], font_offset: usize) -> Vec<String> {
    let Some(blob) = table_blob_at(data, font_offset, b"name") else {
        return Vec::new();
    };
    let Some(count) = be_u16(blob, 2).map(|n| n as usize) else {
        return Vec::new();
    };
    let Some(string_off) = be_u16(blob, 4).map(|n| n as usize) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for i in 0..count {
        let rec = 6 + i * 12;
        let Some(platform) = be_u16(blob, rec) else {
            continue;
        };
        let Some(name_id) = be_u16(blob, rec + 6) else {
            continue;
        };
        if !matches!(name_id, 1 | 4 | 6) {
            continue;
        }
        let Some(length) = be_u16(blob, rec + 8).map(|n| n as usize) else {
            continue;
        };
        let Some(soff) = be_u16(blob, rec + 10).map(|n| n as usize) else {
            continue;
        };
        let start = string_off.saturating_add(soff);
        let Some(raw) = blob.get(start..start.saturating_add(length)) else {
            continue;
        };
        let text = if platform == 0 || platform == 3 {
            String::from_utf16(
                &raw.chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>(),
            )
            .ok()
        } else {
            Some(String::from_utf8_lossy(raw).into_owned())
        };
        if let Some(text) = text {
            let text = text.trim();
            if !text.is_empty() && !names.iter().any(|n| n == text) {
                names.push(text.to_string());
            }
        }
    }
    names
}

fn face_rank(names: &[String]) -> Option<usize> {
    let lower: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
    PREFERRED_FACES.iter().position(|wanted| {
        let wanted = wanted.to_ascii_lowercase();
        lower.iter().any(|name| name.contains(&wanted))
    })
}

fn extract_preferred_face(data: &[u8]) -> Option<Vec<u8>> {
    let offsets = ttc_offsets(data)?;
    let mut best: Option<(usize, u32)> = None;
    for offset in offsets {
        let names = font_names_at(data, offset as usize);
        let rank = face_rank(&names).unwrap_or(PREFERRED_FACES.len());
        if best.as_ref().is_none_or(|(best_rank, _)| rank < *best_rank) {
            best = Some((rank, offset));
        }
        if rank == 0 {
            break;
        }
    }
    extract_sfnt_face(data, best?.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noto_cjk_collection_extracts_mono_sc_when_installed() {
        let path = Path::new("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc");
        if !path.is_file() {
            return;
        }
        let data = fs::read(path).expect("read noto ttc");
        let face = extract_preferred_face(&data).expect("extract a CJK face");
        assert!(is_sfnt(&face), "extracted face must be standalone sfnt");
        let names = font_names(&face);
        assert!(
            names.iter().any(|n| n.contains("Noto Sans Mono CJK SC")),
            "preferred face should be Mono SC, got {names:?}"
        );
        // Loading through the public helper must find the same system font.
        let loaded = load_cjk_face().expect("system CJK font should load on this box");
        assert!(is_sfnt(&loaded));
    }

    #[test]
    fn ttc_magic_is_detected() {
        assert!(is_ttc(b"ttcf\0\x01\0\0\0\0\0\0xxxx"));
        assert!(!is_ttc(b"OTTO1234"));
        assert!(is_sfnt(b"OTTO1234"));
        assert!(is_sfnt(b"\0\x01\0\0xxxx"));
    }
}
