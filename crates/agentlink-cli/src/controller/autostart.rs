//! Linux graphical login entry for the controller.
//!
//! The node itself stays on `agentlink service install`. This file only opens
//! the tray window for the signed-in user.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

/// Characters that require double-quoting in a FreeDesktop `.desktop` `Exec=`
/// argument (Desktop Entry Specification — "The Exec key").
const FREEDESKTOP_RESERVED: &[char] = &[
    ' ', '\t', '\n', '\r', '"', '\'', '\\', '>', '<', '~', '|', '&', ';', '$', '*', '?', '#', '(',
    ')', '`', '=',
];

pub fn desktop_path() -> Option<PathBuf> {
    desktop_path_from(std::env::var_os("XDG_CONFIG_HOME"), std::env::var_os("HOME"))
}

fn desktop_path_from(xdg_config_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let base = xdg_config_home
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            home.filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        })?;
    Some(base.join("autostart").join("agentlink-controller.desktop"))
}

fn validate_path(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    if text.chars().any(|ch| matches!(ch, '\r' | '\n' | '\0')) {
        return Err(anyhow!(
            "autostart path contains forbidden control characters (CR, LF, or NUL)"
        ));
    }
    Ok(())
}

/// Render the XDG `.desktop` file after validating that `binary` and `data_dir`
/// do not contain control characters (`\r`, `\n`, `\0`).
pub fn try_desktop_file(binary: &Path, data_dir: &Path) -> Result<String> {
    validate_path(binary)?;
    validate_path(data_dir)?;
    Ok(desktop_file(binary, data_dir))
}

pub fn desktop_file(binary: &Path, data_dir: &Path) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName=agentlink\nComment=agentlink controller\nExec={} controller --background --data-dir {}\nTerminal=false\nCategories=Network;\nStartupNotify=false\n",
        quote_exec(&binary.to_string_lossy()),
        quote_exec(&data_dir.to_string_lossy()),
    )
}

/// Escape one `Exec=` argument according to the FreeDesktop Desktop Entry
/// Specification:
/// - Defensively strip CR/LF/NUL so direct callers cannot inject `.desktop` keys.
/// - Escape literal `%` as `%%` so field codes (`%f`, `%u`, …) are not expanded.
/// - Quote empty arguments or any argument containing a reserved character, and
///   escape `\`, `"`, `$`, and `` ` `` inside double quotes.
fn quote_exec(text: &str) -> String {
    let clean: String = text
        .chars()
        .filter(|ch| !matches!(ch, '\r' | '\n' | '\0'))
        .collect();
    let needs_quote = clean.is_empty() || clean.contains(FREEDESKTOP_RESERVED);
    let mut out = String::with_capacity(clean.len() + 2);
    if needs_quote {
        out.push('"');
    }
    for ch in clean.chars() {
        match ch {
            '%' => out.push_str("%%"),
            '\\' if needs_quote => out.push_str(r"\\"),
            '"' if needs_quote => out.push_str(r#"\""#),
            '$' if needs_quote => out.push_str(r"\$"),
            '`' if needs_quote => out.push_str(r"\`"),
            _ => out.push(ch),
        }
    }
    if needs_quote {
        out.push('"');
    }
    out
}

pub fn enabled() -> bool {
    desktop_path().is_some_and(|path| path.is_file())
}

pub fn install(binary: &Path, data_dir: &Path) -> Result<()> {
    let contents = try_desktop_file(binary, data_dir)?;
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    {
        let path = desktop_path().ok_or_else(|| anyhow!("could not resolve ~/.config/autostart"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, contents)?;
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", not(target_env = "musl"))))]
    {
        let _ = contents;
        Err(anyhow!(
            "start-on-login for the controller is an XDG autostart file on glibc Linux and HKCU Run on Windows"
        ))
    }
}

pub fn remove() -> Result<()> {
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    {
        if let Some(path) = desktop_path() {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", not(target_env = "musl"))))]
    {
        Err(anyhow!(
            "start-on-login for the controller is an XDG autostart file on glibc Linux and HKCU Run on Windows"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entry_launches_the_tray_in_the_background() {
        let text = desktop_file(
            Path::new("/usr/local/bin/agentlink"),
            Path::new("/var/lib/agentlink/node"),
        );
        assert!(text.contains("controller --background --data-dir"));
        assert!(text.contains("/usr/local/bin/agentlink"));
        assert!(text.contains("Type=Application"));
        assert!(!text.contains("schtasks"));
        let quoted = desktop_file(
            Path::new("/opt/my agentlink/agentlink"),
            Path::new("/home/ada/node data"),
        );
        assert!(quoted.contains("\"/opt/my agentlink/agentlink\""));
        assert!(quoted.contains("\"/home/ada/node data\""));
    }

    #[test]
    fn empty_xdg_config_home_falls_back_to_home_config() {
        let fallback = desktop_path_from(Some(OsString::from("")), Some(OsString::from("/home/ada")));
        assert_eq!(
            fallback,
            Some(PathBuf::from("/home/ada").join(".config").join("autostart").join("agentlink-controller.desktop"))
        );

        let custom = desktop_path_from(
            Some(OsString::from("/xdg/cfg")),
            Some(OsString::from("/home/ada")),
        );
        assert_eq!(
            custom,
            Some(PathBuf::from("/xdg/cfg").join("autostart").join("agentlink-controller.desktop"))
        );

        let missing = desktop_path_from(Some(OsString::from("")), Some(OsString::from("")));
        assert_eq!(missing, None);
    }

    #[test]
    fn control_characters_in_paths_are_rejected() {
        for bad in [
            "/tmp/a\nb/agentlink",
            "/tmp/a\rb/agentlink",
            "/tmp/a\0b/agentlink",
        ] {
            assert!(
                try_desktop_file(Path::new(bad), Path::new("/var/lib/agentlink")).is_err(),
                "expected error for binary {bad:?}"
            );
            assert!(
                try_desktop_file(Path::new("/usr/bin/agentlink"), Path::new(bad)).is_err(),
                "expected error for data_dir {bad:?}"
            );
            assert!(
                install(Path::new("/usr/bin/agentlink"), Path::new(bad))
                    .unwrap_err()
                    .to_string()
                    .contains("control characters"),
                "install must reject control chars in {bad:?}"
            );
        }
        // Even direct desktop_file calls cannot inject a new .desktop line.
        let injected = desktop_file(
            Path::new("/usr/bin/agentlink"),
            Path::new("/tmp/x\nExec=/bin/sh"),
        );
        assert_eq!(injected.matches("\nExec=").count(), 1, "{injected}");
    }

    #[test]
    fn quote_exec_escapes_freedesktop_special_and_reserved_characters() {
        assert_eq!(quote_exec("/usr/bin/agentlink"), "/usr/bin/agentlink");
        assert_eq!(quote_exec(""), "\"\"");
        assert_eq!(quote_exec(r#"/a/b"c"#), r#""/a/b\"c""#);
        assert_eq!(quote_exec(r"/a/b\c"), r#""/a/b\\c""#);
        assert_eq!(quote_exec("/a/$HOME/node"), r#""/a/\$HOME/node""#);
        assert_eq!(quote_exec("/a/`id`/node"), r#""/a/\`id\`/node""#);
        assert_eq!(quote_exec("/a/100%f/node"), "/a/100%%f/node");
        assert_eq!(
            quote_exec("/a/x & y; $z `%u` \"q\" \\"),
            r#""/a/x & y; \$z \`%%u\` \"q\" \\""#
        );
        for reserved in [
            "a b", "a\tb", "a'b", "a>b", "a<b", "a~b", "a|b", "a&b", "a;b", "a*b", "a?b", "a#b",
            "a(b", "a)b", "a=b",
        ] {
            let escaped = quote_exec(reserved);
            assert!(
                escaped.starts_with('"') && escaped.ends_with('"'),
                "expected quotes for {reserved:?}, got {escaped:?}"
            );
        }
    }
}
