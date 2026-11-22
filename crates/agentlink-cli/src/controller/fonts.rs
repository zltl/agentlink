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

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Maximum font file size read into memory (64 MiB).
pub const MAX_FONT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Preferred face names, monospace CJK first and most specific first.
const PREFERRED_FACES: &[&str] = &[
    "Noto Sans Mono CJK SC",
    "Noto Sans Mono CJK TC",
    "Noto Sans Mono CJK JP",
    "Noto Sans Mono CJK KR",
    "Noto Sans Mono CJK",
    "Sarasa Mono SC",
    "Sarasa Term SC",
    "Sarasa Fixed SC",
    "Sarasa Mono",
    "Source Han Mono SC",
    "Source Han Mono",
    "WenQuanYi Zen Hei Mono",
    "NSimSun",
    "MS Gothic",
    "BIZ UDGothic",
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
    "SimSun",
    "Yu Gothic",
    "Malgun Gothic",
    "Songti SC",
    "STHeiti",
];

/// Result of the last CJK fallback lookup. Used to show a missing-font
/// hint instead of silently rendering tofu on machines without Noto.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CjkFontReport {
    pub loaded: bool,
    pub source: Option<PathBuf>,
}

pub fn missing_font_hint() -> &'static str {
    missing_font_hint_for_os(std::env::consts::OS)
}

fn missing_font_hint_for_os(os: &str) -> &'static str {
    match os {
        "windows" => {
            "Chinese and other CJK characters need a font such as Noto Sans CJK (SIL OFL 1.1, https://github.com/notofonts/noto-cjk). Install a CJK font in Windows Settings, place an OFL .ttf/.otf/.ttc in %APPDATA%\\agentlink\\fonts, or set AGENTLINK_CJK_FONT. This build does not bundle the 19 MiB collection. ASCII still works."
        }
        "macos" => {
            "Chinese and other CJK characters need a font such as Noto Sans CJK (SIL OFL 1.1, https://github.com/notofonts/noto-cjk). Install Noto Sans CJK in Font Book, place an OFL .ttf/.otf/.ttc in ~/Library/Application Support/agentlink/fonts, or set AGENTLINK_CJK_FONT. This build does not bundle the 19 MiB collection. ASCII still works."
        }
        _ => {
            "Chinese and other CJK characters need a font such as Noto Sans CJK (SIL OFL 1.1, https://github.com/notofonts/noto-cjk). Install fonts-noto-cjk, place an OFL .ttf/.otf/.ttc in ~/.config/agentlink/fonts, or set AGENTLINK_CJK_FONT. This build does not bundle the 19 MiB collection. ASCII still works."
        }
    }
}

static REPORT: std::sync::OnceLock<CjkFontReport> = std::sync::OnceLock::new();

pub fn report() -> CjkFontReport {
    REPORT.get().cloned().unwrap_or(CjkFontReport {
        loaded: false,
        source: None,
    })
}

#[derive(Default)]
struct FontEnv {
    cjk_font: Option<OsString>,
    config_dir: Option<OsString>,
    xdg_config_home: Option<OsString>,
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
    appdata: Option<OsString>,
    local_appdata: Option<OsString>,
    userprofile: Option<OsString>,
    windir: Option<OsString>,
    os: &'static str,
}

impl FontEnv {
    fn from_process() -> Self {
        let non_empty = |key: &str| {
            std::env::var_os(key).filter(|v| !v.is_empty())
        };
        Self {
            cjk_font: non_empty("AGENTLINK_CJK_FONT"),
            config_dir: non_empty("AGENTLINK_CONFIG_DIR"),
            xdg_config_home: non_empty("XDG_CONFIG_HOME"),
            xdg_data_home: non_empty("XDG_DATA_HOME"),
            home: non_empty("HOME"),
            appdata: non_empty("APPDATA"),
            local_appdata: non_empty("LOCALAPPDATA"),
            userprofile: non_empty("USERPROFILE"),
            windir: non_empty("WINDIR").or_else(|| non_empty("SystemRoot")),
            os: std::env::consts::OS,
        }
    }
}

fn push_unique(list: &mut Vec<PathBuf>, path: PathBuf) {
    if !list.iter().any(|existing| existing == &path) {
        list.push(path);
    }
}

fn drop_in_dirs_from(env: &FontEnv) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = &env.config_dir {
        push_unique(&mut dirs, PathBuf::from(dir).join("fonts"));
    }
    if let Some(appdata) = &env.appdata {
        push_unique(
            &mut dirs,
            PathBuf::from(appdata).join("agentlink").join("fonts"),
        );
    }
    if let Some(local_appdata) = &env.local_appdata {
        push_unique(
            &mut dirs,
            PathBuf::from(local_appdata).join("agentlink").join("fonts"),
        );
    }
    if let Some(xdg) = &env.xdg_config_home {
        push_unique(&mut dirs, PathBuf::from(xdg).join("agentlink/fonts"));
    }
    if let Some(home) = &env.home {
        let home = PathBuf::from(home);
        if env.os == "macos" {
            push_unique(
                &mut dirs,
                home.join("Library/Application Support/agentlink/fonts"),
            );
        }
        push_unique(&mut dirs, home.join(".config/agentlink/fonts"));
        push_unique(&mut dirs, home.join(".local/share/agentlink/fonts"));
    }
    if let Some(profile) = &env.userprofile {
        push_unique(
            &mut dirs,
            PathBuf::from(profile).join(".config").join("agentlink").join("fonts"),
        );
    }
    dirs
}

fn filename_looks_mono(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.contains("mono") || name.contains("term") || name.contains("fixed")
}

fn fonts_in_dir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(ext.as_str(), "ttf" | "otf" | "ttc") {
            out.push(path);
        }
    }
    // Prefer monospace faces before proportional ones, tie-breaking alphabetically.
    out.sort_by(|a, b| {
        let a_mono = filename_looks_mono(a);
        let b_mono = filename_looks_mono(b);
        b_mono.cmp(&a_mono).then_with(|| a.cmp(b))
    });
    out
}

fn windows_candidates_in(dir: &Path) -> Vec<PathBuf> {
    const NAMES: &[&str] = &[
        // Monospace CJK faces first (clean 2:1 cell advance in terminal).
        "NotoSansMonoCJKsc-Regular.otf",
        "NotoSansMonoCJK-Regular.ttc",
        "NotoSansCJK-Regular.ttc",
        "SarasaMonoSC-Regular.ttf",
        "SarasaTermSC-Regular.ttf",
        "SarasaFixedSC-Regular.ttf",
        "sarasa-mono-sc-regular.ttf",
        "sarasa-term-sc-regular.ttf",
        "SourceHanMono-Regular.otf",
        "SourceHanMonoSC-Regular.otf",
        // Standard Windows monospace & UI CJK fallbacks.
        "simsun.ttc",
        "msgothic.ttc",
        "msyh.ttc",
        "msyh.ttf",
        "SourceHanSansSC-Regular.otf",
        "simhei.ttf",
        "malgun.ttf",
        "YuGothR.ttc",
        "YuGothM.ttc",
    ];
    NAMES.iter().map(|name| dir.join(name)).collect()
}

fn windows_search_paths(env: &FontEnv) -> Vec<PathBuf> {
    let mut out = Vec::new();
    // Per-user Windows font directory (Windows 10 1809+ / Windows 11).
    if let Some(local) = &env.local_appdata {
        let user_fonts = PathBuf::from(local)
            .join("Microsoft")
            .join("Windows")
            .join("Fonts");
        for path in windows_candidates_in(&user_fonts) {
            push_unique(&mut out, path);
        }
    }
    // System Windows font directory (`%WINDIR%\Fonts`, falling back to `C:\Windows\Fonts`).
    let sys_fonts = env
        .windir
        .as_ref()
        .map(|w| PathBuf::from(w).join("Fonts"))
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\Fonts"));
    for path in windows_candidates_in(&sys_fonts) {
        push_unique(&mut out, path);
    }
    out
}

fn linux_search_paths(env: &FontEnv) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let user_names = [
        "NotoSansMonoCJKsc-Regular.otf",
        "NotoSansMonoCJK-Regular.ttc",
        "NotoSansCJK-Regular.ttc",
        "SarasaMonoSC-Regular.ttf",
        "SourceHanMono-Regular.otf",
        "NotoSansCJKsc-Regular.otf",
        "SourceHanSansSC-Regular.otf",
    ];
    if let Some(xdg_data) = &env.xdg_data_home {
        let dir = PathBuf::from(xdg_data).join("fonts");
        for name in user_names {
            push_unique(&mut out, dir.join(name));
        }
    }
    if let Some(home) = &env.home {
        let home = PathBuf::from(home);
        for base in [home.join(".local/share/fonts"), home.join(".fonts")] {
            for name in user_names {
                push_unique(&mut out, base.join(name));
            }
        }
    }
    let system = [
        // Monospace Noto / Source Han / WenQuanYi paths first across distros
        // (Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE, NixOS).
        "/usr/share/fonts/opentype/noto/NotoSansMonoCJKsc-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSansMonoCJKsc-Regular.otf",
        "/usr/share/fonts/google-noto-cjk/NotoSansMonoCJKsc-Regular.otf",
        "/usr/share/fonts/noto-cjk/NotoSansMonoCJKsc-Regular.otf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        "/run/current-system/sw/share/X11/fonts/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/wenquanyi/wqy-zenhei/wqy-zenhei.ttc",
        // Proportional Noto / Source Han / Droid fallbacks.
        "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSansCJKsc-Regular.otf",
        "/usr/share/fonts/google-noto-cjk/NotoSansCJKsc-Regular.otf",
        "/usr/share/fonts/opentype/source-han-sans/SourceHanSansSC-Regular.otf",
        "/usr/share/fonts/adobe-source-han-sans/SourceHanSansSC-Regular.otf",
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        "/usr/share/fonts/truetype/droid/DroidSansFallback.ttf",
    ];
    for p in system {
        push_unique(&mut out, PathBuf::from(p));
    }
    out
}

fn mac_search_paths(env: &FontEnv) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = &env.home {
        let user_fonts = PathBuf::from(home).join("Library/Fonts");
        for name in [
            "NotoSansMonoCJKsc-Regular.otf",
            "NotoSansCJK-Regular.ttc",
            "SarasaMonoSC-Regular.ttf",
            "SourceHanMono-Regular.otf",
        ] {
            push_unique(&mut out, user_fonts.join(name));
        }
    }
    let system = [
        "/Library/Fonts/NotoSansMonoCJKsc-Regular.otf",
        "/Library/Fonts/NotoSansCJK-Regular.ttc",
        "/System/Library/Fonts/Supplemental/NotoSansCJK-Regular.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/Hiragino Sans GB.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/System/Library/Fonts/Supplemental/Songti.ttc",
        "/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc",
    ];
    for p in system {
        push_unique(&mut out, PathBuf::from(p));
    }
    out
}

fn search_paths_from(env: &FontEnv) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(explicit) = &env.cjk_font {
        push_unique(&mut paths, PathBuf::from(explicit));
    }
    for dir in drop_in_dirs_from(env) {
        for path in fonts_in_dir(&dir) {
            push_unique(&mut paths, path);
        }
    }
    let ordered: [&dyn Fn(&FontEnv) -> Vec<PathBuf>; 3] = match env.os {
        "windows" => [&windows_search_paths, &linux_search_paths, &mac_search_paths],
        "macos" => [&mac_search_paths, &linux_search_paths, &windows_search_paths],
        _ => [&linux_search_paths, &windows_search_paths, &mac_search_paths],
    };
    for collect in ordered {
        for path in collect(env) {
            push_unique(&mut paths, path);
        }
    }
    paths
}

fn search_paths() -> Vec<PathBuf> {
    search_paths_from(&FontEnv::from_process())
}

/// Load one CJK-capable face as a standalone OpenType/TrueType blob.
pub fn load_cjk_face() -> Option<Vec<u8>> {
    for path in search_paths() {
        if !path.is_file() {
            continue;
        }
        if let Some(face) = load_from_path(&path) {
            let _ = REPORT.set(CjkFontReport {
                loaded: true,
                source: Some(path),
            });
            return Some(face);
        }
    }
    let _ = REPORT.set(CjkFontReport {
        loaded: false,
        source: None,
    });
    None
}

fn load_from_path(path: &Path) -> Option<Vec<u8>> {
    load_from_path_with_limit(path, MAX_FONT_FILE_BYTES)
}

fn load_from_path_with_limit(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() < 12 || meta.len() > max_bytes {
        return None;
    }
    let file = File::open(path).ok()?;
    let mut data = Vec::with_capacity(meta.len().min(max_bytes) as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut data)
        .ok()?;
    if data.len() < 12 || (data.len() as u64) > max_bytes {
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
    let table_end = 12usize.checked_add(n.checked_mul(4)?)?;
    if table_end > data.len() {
        return None;
    }
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

    #[test]
    fn missing_font_hint_names_the_license_and_drop_in_path() {
        for (os, expected_path) in [
            ("windows", r"%APPDATA%\agentlink\fonts"),
            ("macos", "~/Library/Application Support/agentlink/fonts"),
            ("linux", ".config/agentlink/fonts"),
        ] {
            let hint = missing_font_hint_for_os(os);
            assert!(hint.contains("SIL OFL 1.1"), "{os}: {hint}");
            assert!(
                hint.contains("fonts-noto-cjk") || hint.contains("Noto Sans CJK"),
                "{os}: {hint}"
            );
            assert!(hint.contains("AGENTLINK_CJK_FONT"), "{os}: {hint}");
            assert!(hint.contains(expected_path), "{os}: {hint}");
            assert!(hint.contains("does not bundle"), "{os}: {hint}");
        }
        // Live OS helper must match the current target OS.
        assert_eq!(
            missing_font_hint(),
            missing_font_hint_for_os(std::env::consts::OS)
        );
    }

    #[test]
    fn search_paths_include_windir_per_user_and_drop_in_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let appdata = tmp.path().join("roaming");
        let local = tmp.path().join("local");
        let drop_dir = appdata.join("agentlink").join("fonts");
        fs::create_dir_all(&drop_dir).expect("create drop dir");
        let prop_font = drop_dir.join("aaa-proportional.ttf");
        let mono_font = drop_dir.join("zzz-cjk-mono.otf");
        fs::write(&prop_font, b"OTTO12345678").expect("write prop");
        fs::write(&mono_font, b"OTTO12345678").expect("write mono");

        let env = FontEnv {
            appdata: Some(appdata.into_os_string()),
            local_appdata: Some(local.clone().into_os_string()),
            windir: Some(OsString::from(r"D:\CustomWin")),
            home: Some(OsString::from("/home/alice")),
            xdg_config_home: Some(OsString::from("/home/alice/.xdg")),
            os: "windows",
            ..Default::default()
        };

        let drop_dirs = drop_in_dirs_from(&env);
        assert!(drop_dirs.iter().any(|d| d == &drop_dir), "{drop_dirs:?}");
        assert!(
            drop_dirs
                .iter()
                .any(|d| d == &local.join("agentlink").join("fonts")),
            "{drop_dirs:?}"
        );

        let paths = search_paths_from(&env);
        // Drop-in monospace font must rank ahead of proportional drop-in font.
        let mono_idx = paths.iter().position(|p| p == &mono_font).expect("mono drop-in");
        let prop_idx = paths.iter().position(|p| p == &prop_font).expect("prop drop-in");
        assert!(mono_idx < prop_idx, "mono font should precede proportional");

        // Per-user Windows Fonts and custom %WINDIR%\Fonts must both be probed.
        let user_noto = local
            .join("Microsoft")
            .join("Windows")
            .join("Fonts")
            .join("NotoSansMonoCJKsc-Regular.otf");
        let sys_msyh = PathBuf::from(r"D:\CustomWin").join("Fonts").join("msyh.ttc");
        let sys_mono = PathBuf::from(r"D:\CustomWin")
            .join("Fonts")
            .join("NotoSansMonoCJKsc-Regular.otf");
        let user_idx = paths.iter().position(|p| p == &user_noto).expect("user win font");
        let sys_mono_idx = paths.iter().position(|p| p == &sys_mono).expect("sys mono");
        let sys_msyh_idx = paths.iter().position(|p| p == &sys_msyh).expect("sys msyh");
        assert!(user_idx < sys_mono_idx, "per-user Windows fonts come before system");
        assert!(sys_mono_idx < sys_msyh_idx, "mono CJK comes before proportional YaHei");
    }

    #[test]
    fn monospace_cjk_faces_rank_above_proportional() {
        let mono = face_rank(&["Noto Sans Mono CJK SC".to_string()]).unwrap();
        let sarasa = face_rank(&["Sarasa Mono SC".to_string()]).unwrap();
        let nsimsun = face_rank(&["NSimSun".to_string()]).unwrap();
        let sans = face_rank(&["Noto Sans CJK SC".to_string()]).unwrap();
        let yahei = face_rank(&["Microsoft YaHei".to_string()]).unwrap();
        assert!(mono < sans);
        assert!(sarasa < sans);
        assert!(nsimsun < yahei);
    }

    #[test]
    fn load_from_path_enforces_file_size_cap_and_rejects_corrupt_ttc() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let valid = tmp.path().join("tiny.otf");
        let mut payload = b"OTTO".to_vec();
        payload.extend_from_slice(&[0u8; 64]);
        fs::write(&valid, &payload).expect("write valid sfnt");

        assert!(load_from_path_with_limit(&valid, 1024).is_some());
        assert!(
            load_from_path_with_limit(&valid, 32).is_none(),
            "font larger than cap must be rejected"
        );
        assert_eq!(MAX_FONT_FILE_BYTES, 64 * 1024 * 1024);

        // Corrupt TTC claiming 0x7FFF_FFFF faces must return None without OOM/panic.
        let mut corrupt = b"ttcf\0\x01\0\0".to_vec();
        corrupt.extend_from_slice(&0x7FFF_FFFFu32.to_be_bytes());
        corrupt.extend_from_slice(&[0u8; 16]);
        assert!(ttc_offsets(&corrupt).is_none());
    }
}
