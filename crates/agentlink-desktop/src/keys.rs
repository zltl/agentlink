//! Key names shared by X11 keysyms, Windows virtual keys, and macOS keycodes.
//!
//! Wayland / portal backends consume the same X11-style keysyms via
//! [`KeyInfo::keysym`]. Numpad, media, and left/right modifiers are included
//! so chords such as `Win+L` and `volup` resolve on every platform table.

use crate::error::{msg, Result};

#[derive(Debug, Clone, Copy)]
pub struct KeyInfo {
    pub name: &'static str,
    /// X11 / portal keysym. Read by the Linux backends.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub keysym: u32,
    /// Windows virtual-key code. Read by the Windows backend and unit tests.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub vk: u16,
    /// macOS virtual keycode (`None` when macOS has no `CGKeyCode` for this key,
    /// never `0x00` which is `kVK_ANSI_A`).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub mac: Option<u16>,
}

/// True when `name` is a shifted US ANSI punctuation symbol whose physical key
/// is shared with an unshifted symbol.
#[allow(dead_code)]
pub fn key_requires_shift(name: &str) -> bool {
    matches!(
        name,
        ":" | "\""
            | "{"
            | "}"
            | "|"
            | "<"
            | ">"
            | "?"
            | "~"
            | "!"
            | "@"
            | "#"
            | "$"
            | "%"
            | "^"
            | "&"
            | "*"
            | "("
            | ")"
            | "_"
            | "+"
    )
}

/// Normalize `Ctrl`, `cmd`, `Return`, and single letters to a canonical name.
pub fn canonical(raw: &str) -> Result<String> {
    let text = raw.trim().to_ascii_lowercase().replace('_', "-");
    if text.is_empty() {
        return Err(msg("empty key name"));
    }
    let name = match text.as_str() {
        "control" | "ctrl" => "ctrl",
        "lcontrol" | "lctrl" => "lctrl",
        "rcontrol" | "rctrl" => "rctrl",
        "alt" | "option" | "opt" | "menu" => "alt",
        "lalt" | "loption" | "lopt" => "lalt",
        "ralt" | "roption" | "ropt" | "altgr" => "ralt",
        "shift" => "shift",
        "lshift" => "lshift",
        "rshift" => "rshift",
        "meta" | "super" | "cmd" | "command" | "win" | "windows" | "gui" => "meta",
        "lmeta" | "lsuper" | "lcmd" | "lwin" | "lgui" => "lgui",
        "rmeta" | "rsuper" | "rcmd" | "rwin" | "rgui" => "rgui",
        "enter" | "return" | "ret" => "enter",
        "esc" | "escape" => "escape",
        "pgup" | "pageup" | "page-up" => "pageup",
        "pgdn" | "pagedown" | "page-down" => "pagedown",
        "backspace" | "bksp" => "backspace",
        "del" | "delete" => "delete",
        "space" | "spacebar" => "space",
        "plus" => "+",
        "capslock" | "caps-lock" | "caps" => "capslock",
        "numlock" | "num-lock" => "numlock",
        "scrolllock" | "scroll-lock" | "scrlk" => "scrolllock",
        "printscreen" | "print-screen" | "print" | "sysrq" => "prtsc",
        "contextmenu" | "app" | "application" | "menu-key" => "apps",
        "volumeup" | "volume-up" => "volup",
        "volumedown" | "volume-down" => "voldown",
        "volumemute" | "volume-mute" | "mute" => "volmute",
        "mediaplaypause" | "media-play-pause" | "play" | "pause-media" => "playpause",
        "medianext" | "media-next" | "next" => "nexttrack",
        "mediaprev" | "media-prev" | "previous" | "prev" => "prevtrack",
        "mediastop" | "media-stop" => "stop",
        "media" | "launch-media" => "mediaselect",
        "browserback" | "browser_back" => "browser-back",
        "browserforward" | "browser_forward" => "browser-forward",
        "numpadenter" | "kp-enter" | "kp_enter" => "kpenter",
        "numpad0" | "kp-0" | "kp_0" => "kp0",
        "numpad1" | "kp-1" | "kp_1" => "kp1",
        "numpad2" | "kp-2" | "kp_2" => "kp2",
        "numpad3" | "kp-3" | "kp_3" => "kp3",
        "numpad4" | "kp-4" | "kp_4" => "kp4",
        "numpad5" | "kp-5" | "kp_5" => "kp5",
        "numpad6" | "kp-6" | "kp_6" => "kp6",
        "numpad7" | "kp-7" | "kp_7" => "kp7",
        "numpad8" | "kp-8" | "kp_8" => "kp8",
        "numpad9" | "kp-9" | "kp_9" => "kp9",
        "numpadadd" | "kp-add" | "kp_add" => "kp+",
        "numpadsub" | "kp-sub" | "kp_sub" | "kp-subtract" => "kp-",
        "numpadmul" | "kp-mul" | "kp_mul" | "kp-multiply" => "kp*",
        "numpaddiv" | "kp-div" | "kp_div" | "kp-divide" => "kp/",
        "numpaddot" | "kp-dot" | "kp_dot" | "kp-decimal" => "kp.",
        "comma" => ",",
        "period" | "dot" => ".",
        "slash" => "/",
        "semicolon" => ";",
        "apostrophe" | "quote" => "'",
        "bracketleft" | "leftbracket" => "[",
        "bracketright" | "rightbracket" => "]",
        "backslash" => "\\",
        "minus" | "hyphen" => "-",
        "equal" | "equals" => "=",
        "grave" | "backtick" => "`",
        "colon" => ":",
        "quotedbl" | "doublequote" => "\"",
        "braceleft" | "leftbrace" => "{",
        "braceright" | "rightbrace" => "}",
        "bar" | "pipe" => "|",
        "less" => "<",
        "greater" => ">",
        "question" => "?",
        "tilde" => "~",
        "exclam" | "bang" => "!",
        "at" => "@",
        "numbersign" | "hash" => "#",
        "dollar" => "$",
        "percent" => "%",
        "asciicircum" | "caret" => "^",
        "ampersand" => "&",
        "asterisk" => "*",
        "parenleft" | "leftparen" => "(",
        "parenright" | "rightparen" => ")",
        "underscore" => "_",
        other => other,
    };
    if key_info(name).is_none() && name.chars().count() != 1 {
        return Err(msg(format!("unknown key '{raw}'")));
    }
    if name.chars().count() == 1 {
        let ch = name.chars().next().unwrap();
        if !(ch.is_ascii_alphanumeric() || ch.is_ascii_punctuation() || ch == ' ') {
            return Err(msg(format!("unknown key '{raw}'")));
        }
    }
    Ok(name.to_string())
}

pub fn parse_combo(spec: &str) -> Result<Vec<String>> {
    let mut rest = spec.trim();
    if rest.is_empty() {
        return Err(msg("key combo is empty"));
    }
    let mut parts: Vec<&str> = Vec::new();
    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        if let Some(after) = rest.strip_prefix('+') {
            parts.push("+");
            let trimmed = after.trim_start();
            rest = trimmed.strip_prefix('+').unwrap_or(trimmed);
            continue;
        }
        if let Some(pos) = rest.find('+') {
            let token = rest[..pos].trim_end();
            let after = &rest[pos + 1..];
            if token.eq_ignore_ascii_case("kp") {
                parts.push("kp+");
                let trimmed = after.trim_start();
                rest = trimmed.strip_prefix('+').unwrap_or(trimmed);
            } else {
                if !token.is_empty() {
                    parts.push(token);
                }
                rest = after;
            }
        } else {
            let token = rest.trim_end();
            if !token.is_empty() {
                parts.push(token);
            }
            break;
        }
    }
    if parts.is_empty() {
        return Err(msg("key combo is empty"));
    }
    parts.into_iter().map(canonical).collect()
}

/// Windows Ctrl+Alt+Del is the secure attention sequence. `SendInput` and
/// the portal key path cannot open the security screen. A chord matches only
/// when ctrl, alt, and delete are all present.
pub fn is_secure_attention_sequence<S: AsRef<str>>(keys: &[S]) -> bool {
    let mut ctrl = false;
    let mut alt = false;
    let mut delete = false;
    for key in keys {
        match key.as_ref() {
            "ctrl" | "lctrl" | "rctrl" | "control" => ctrl = true,
            "alt" | "lalt" | "ralt" | "option" | "opt" => alt = true,
            "delete" | "del" => delete = true,
            _ => {}
        }
    }
    ctrl && alt && delete
}

/// Whether `SendInput` must set `KEYEVENTF_EXTENDEDKEY` (`0xE0` scan prefix)
/// for a Win32 virtual-key code so navigation, Win/Apps, right-side modifiers,
/// and numpad `/` are distinguished from numpad digits and main-block keys.
pub fn is_windows_extended_vk(vk: u16) -> bool {
    matches!(
        vk,
        0x03 // VK_CANCEL (Ctrl+Break)
        | 0x21..=0x28 // PageUp, PageDown, End, Home, Left, Up, Right, Down
        | 0x2c..=0x2e // PrintScreen, Insert, Delete
        | 0x5b..=0x5d // LWin, RWin, Apps
        | 0x6f // VK_DIVIDE (numpad /)
        | 0x90 // VK_NUMLOCK
        | 0xa3 // VK_RCONTROL
        | 0xa5 // VK_RMENU (Right Alt / AltGr)
        | 0xa6..=0xb7 // Browser & media keys
    )
}

pub fn key_info(name: &str) -> Option<KeyInfo> {
    if let Some(info) = NAMED.iter().find(|item| item.name == name).copied() {
        return Some(info);
    }
    let mut chars = name.chars();
    let ch = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    if ch.is_ascii_lowercase() {
        return Some(KeyInfo {
            name: "char",
            keysym: ch as u32,
            vk: ch.to_ascii_uppercase() as u16,
            mac: mac_letter(ch),
        });
    }
    if ch.is_ascii_digit() {
        return Some(KeyInfo {
            name: "digit",
            keysym: ch as u32,
            vk: ch as u16,
            mac: mac_digit(ch),
        });
    }
    if let Some(info) = punctuation_char(ch) {
        return Some(info);
    }
    None
}

fn punctuation_char(ch: char) -> Option<KeyInfo> {
    NAMED
        .iter()
        .find(|item| item.name.len() == 1 && item.name.starts_with(ch))
        .copied()
}

fn mac_letter(ch: char) -> Option<u16> {
    Some(match ch {
        'a' => 0x00,
        's' => 0x01,
        'd' => 0x02,
        'f' => 0x03,
        'h' => 0x04,
        'g' => 0x05,
        'z' => 0x06,
        'x' => 0x07,
        'c' => 0x08,
        'v' => 0x09,
        'b' => 0x0b,
        'q' => 0x0c,
        'w' => 0x0d,
        'e' => 0x0e,
        'r' => 0x0f,
        'y' => 0x10,
        't' => 0x11,
        'o' => 0x1f,
        'u' => 0x20,
        'i' => 0x22,
        'p' => 0x23,
        'l' => 0x25,
        'j' => 0x26,
        'k' => 0x28,
        'n' => 0x2d,
        'm' => 0x2e,
        _ => return None,
    })
}

fn mac_digit(ch: char) -> Option<u16> {
    Some(match ch {
        '1' => 0x12,
        '2' => 0x13,
        '3' => 0x14,
        '4' => 0x15,
        '5' => 0x17,
        '6' => 0x16,
        '7' => 0x1a,
        '8' => 0x1c,
        '9' => 0x19,
        '0' => 0x1d,
        _ => return None,
    })
}

// X11 XF86 multimedia keysyms (from XF86keysym.h).
const XF86_AUDIO_LOWER: u32 = 0x1008_ff11;
const XF86_AUDIO_MUTE: u32 = 0x1008_ff12;
const XF86_AUDIO_RAISE: u32 = 0x1008_ff13;
const XF86_AUDIO_PLAY: u32 = 0x1008_ff14;
const XF86_AUDIO_STOP: u32 = 0x1008_ff15;
const XF86_AUDIO_PREV: u32 = 0x1008_ff16;
const XF86_AUDIO_NEXT: u32 = 0x1008_ff17;
const XF86_AUDIO_MEDIA: u32 = 0x1008_ff32;
const XF86_BACK: u32 = 0x1008_ff26;
const XF86_FORWARD: u32 = 0x1008_ff27;

const NAMED: &[KeyInfo] = &[
    KeyInfo {
        name: "ctrl",
        keysym: 0xffe3,
        vk: 0x11,
        mac: Some(0x3b),
    },
    KeyInfo {
        name: "lctrl",
        keysym: 0xffe3,
        vk: 0xa2,
        mac: Some(0x3b),
    },
    KeyInfo {
        name: "rctrl",
        keysym: 0xffe4,
        vk: 0xa3,
        mac: Some(0x3e),
    },
    KeyInfo {
        name: "alt",
        keysym: 0xffe9,
        vk: 0x12,
        mac: Some(0x3a),
    },
    KeyInfo {
        name: "lalt",
        keysym: 0xffe9,
        vk: 0xa4,
        mac: Some(0x3a),
    },
    KeyInfo {
        name: "ralt",
        keysym: 0xffea,
        vk: 0xa5,
        mac: Some(0x3d),
    },
    KeyInfo {
        name: "shift",
        keysym: 0xffe1,
        vk: 0x10,
        mac: Some(0x38),
    },
    KeyInfo {
        name: "lshift",
        keysym: 0xffe1,
        vk: 0xa0,
        mac: Some(0x38),
    },
    KeyInfo {
        name: "rshift",
        keysym: 0xffe2,
        vk: 0xa1,
        mac: Some(0x3c),
    },
    KeyInfo {
        name: "meta",
        keysym: 0xffeb,
        vk: 0x5b,
        mac: Some(0x37),
    },
    KeyInfo {
        name: "lgui",
        keysym: 0xffeb,
        vk: 0x5b,
        mac: Some(0x37),
    },
    KeyInfo {
        name: "rgui",
        keysym: 0xffec,
        vk: 0x5c,
        mac: Some(0x36),
    },
    KeyInfo {
        name: "enter",
        keysym: 0xff0d,
        vk: 0x0d,
        mac: Some(0x24),
    },
    KeyInfo {
        name: "tab",
        keysym: 0xff09,
        vk: 0x09,
        mac: Some(0x30),
    },
    KeyInfo {
        name: "escape",
        keysym: 0xff1b,
        vk: 0x1b,
        mac: Some(0x35),
    },
    KeyInfo {
        name: "space",
        keysym: 0x0020,
        vk: 0x20,
        mac: Some(0x31),
    },
    KeyInfo {
        name: "backspace",
        keysym: 0xff08,
        vk: 0x08,
        mac: Some(0x33),
    },
    KeyInfo {
        name: "delete",
        keysym: 0xffff,
        vk: 0x2e,
        mac: Some(0x75),
    },
    KeyInfo {
        name: "insert",
        keysym: 0xff63,
        vk: 0x2d,
        mac: Some(0x72),
    },
    KeyInfo {
        name: "prtsc",
        keysym: 0xff61,
        vk: 0x2c,
        mac: Some(0x69),
    },
    KeyInfo {
        name: "pause",
        keysym: 0xff13,
        vk: 0x13,
        mac: Some(0x71),
    },
    KeyInfo {
        name: "apps",
        keysym: 0xff67,
        vk: 0x5d,
        mac: Some(0x6e),
    },
    KeyInfo {
        name: "left",
        keysym: 0xff51,
        vk: 0x25,
        mac: Some(0x7b),
    },
    KeyInfo {
        name: "up",
        keysym: 0xff52,
        vk: 0x26,
        mac: Some(0x7e),
    },
    KeyInfo {
        name: "right",
        keysym: 0xff53,
        vk: 0x27,
        mac: Some(0x7c),
    },
    KeyInfo {
        name: "down",
        keysym: 0xff54,
        vk: 0x28,
        mac: Some(0x7d),
    },
    KeyInfo {
        name: "home",
        keysym: 0xff50,
        vk: 0x24,
        mac: Some(0x73),
    },
    KeyInfo {
        name: "end",
        keysym: 0xff57,
        vk: 0x23,
        mac: Some(0x77),
    },
    KeyInfo {
        name: "pageup",
        keysym: 0xff55,
        vk: 0x21,
        mac: Some(0x74),
    },
    KeyInfo {
        name: "pagedown",
        keysym: 0xff56,
        vk: 0x22,
        mac: Some(0x79),
    },
    KeyInfo {
        name: "f1",
        keysym: 0xffbe,
        vk: 0x70,
        mac: Some(0x7a),
    },
    KeyInfo {
        name: "f2",
        keysym: 0xffbf,
        vk: 0x71,
        mac: Some(0x78),
    },
    KeyInfo {
        name: "f3",
        keysym: 0xffc0,
        vk: 0x72,
        mac: Some(0x63),
    },
    KeyInfo {
        name: "f4",
        keysym: 0xffc1,
        vk: 0x73,
        mac: Some(0x76),
    },
    KeyInfo {
        name: "f5",
        keysym: 0xffc2,
        vk: 0x74,
        mac: Some(0x60),
    },
    KeyInfo {
        name: "f6",
        keysym: 0xffc3,
        vk: 0x75,
        mac: Some(0x61),
    },
    KeyInfo {
        name: "f7",
        keysym: 0xffc4,
        vk: 0x76,
        mac: Some(0x62),
    },
    KeyInfo {
        name: "f8",
        keysym: 0xffc5,
        vk: 0x77,
        mac: Some(0x64),
    },
    KeyInfo {
        name: "f9",
        keysym: 0xffc6,
        vk: 0x78,
        mac: Some(0x65),
    },
    KeyInfo {
        name: "f10",
        keysym: 0xffc7,
        vk: 0x79,
        mac: Some(0x6d),
    },
    KeyInfo {
        name: "f11",
        keysym: 0xffc8,
        vk: 0x7a,
        mac: Some(0x67),
    },
    KeyInfo {
        name: "f12",
        keysym: 0xffc9,
        vk: 0x7b,
        mac: Some(0x6f),
    },
    KeyInfo {
        name: "f13",
        keysym: 0xffca,
        vk: 0x7c,
        mac: Some(0x69),
    },
    KeyInfo {
        name: "f14",
        keysym: 0xffcb,
        vk: 0x7d,
        mac: Some(0x6b),
    },
    KeyInfo {
        name: "f15",
        keysym: 0xffcc,
        vk: 0x7e,
        mac: Some(0x71),
    },
    KeyInfo {
        name: "f16",
        keysym: 0xffcd,
        vk: 0x7f,
        mac: Some(0x6a),
    },
    KeyInfo {
        name: "f17",
        keysym: 0xffce,
        vk: 0x80,
        mac: Some(0x40),
    },
    KeyInfo {
        name: "f18",
        keysym: 0xffcf,
        vk: 0x81,
        mac: Some(0x4f),
    },
    KeyInfo {
        name: "f19",
        keysym: 0xffd0,
        vk: 0x82,
        mac: Some(0x50),
    },
    KeyInfo {
        name: "f20",
        keysym: 0xffd1,
        vk: 0x83,
        mac: Some(0x5a),
    },
    KeyInfo {
        name: "f21",
        keysym: 0xffd2,
        vk: 0x84,
        mac: None,
    },
    KeyInfo {
        name: "f22",
        keysym: 0xffd3,
        vk: 0x85,
        mac: None,
    },
    KeyInfo {
        name: "f23",
        keysym: 0xffd4,
        vk: 0x86,
        mac: None,
    },
    KeyInfo {
        name: "f24",
        keysym: 0xffd5,
        vk: 0x87,
        mac: None,
    },
    // Unshifted punctuation (US ANSI). Shift variants share the physical VK;
    // X11 keysyms use the produced character so temporary mapping can type them.
    KeyInfo {
        name: ",",
        keysym: 0x002c,
        vk: 0xbc,
        mac: Some(0x2b),
    },
    KeyInfo {
        name: ".",
        keysym: 0x002e,
        vk: 0xbe,
        mac: Some(0x2f),
    },
    KeyInfo {
        name: "/",
        keysym: 0x002f,
        vk: 0xbf,
        mac: Some(0x2c),
    },
    KeyInfo {
        name: ";",
        keysym: 0x003b,
        vk: 0xba,
        mac: Some(0x29),
    },
    KeyInfo {
        name: "'",
        keysym: 0x0027,
        vk: 0xde,
        mac: Some(0x27),
    },
    KeyInfo {
        name: "[",
        keysym: 0x005b,
        vk: 0xdb,
        mac: Some(0x21),
    },
    KeyInfo {
        name: "]",
        keysym: 0x005d,
        vk: 0xdd,
        mac: Some(0x1e),
    },
    KeyInfo {
        name: "\\",
        keysym: 0x005c,
        vk: 0xdc,
        mac: Some(0x2a),
    },
    KeyInfo {
        name: "-",
        keysym: 0x002d,
        vk: 0xbd,
        mac: Some(0x1b),
    },
    KeyInfo {
        name: "=",
        keysym: 0x003d,
        vk: 0xbb,
        mac: Some(0x18),
    },
    KeyInfo {
        name: "`",
        keysym: 0x0060,
        vk: 0xc0,
        mac: Some(0x32),
    },
    KeyInfo {
        name: ":",
        keysym: 0x003a,
        vk: 0xba,
        mac: Some(0x29),
    },
    KeyInfo {
        name: "\"",
        keysym: 0x0022,
        vk: 0xde,
        mac: Some(0x27),
    },
    KeyInfo {
        name: "{",
        keysym: 0x007b,
        vk: 0xdb,
        mac: Some(0x21),
    },
    KeyInfo {
        name: "}",
        keysym: 0x007d,
        vk: 0xdd,
        mac: Some(0x1e),
    },
    KeyInfo {
        name: "|",
        keysym: 0x007c,
        vk: 0xdc,
        mac: Some(0x2a),
    },
    KeyInfo {
        name: "<",
        keysym: 0x003c,
        vk: 0xbc,
        mac: Some(0x2b),
    },
    KeyInfo {
        name: ">",
        keysym: 0x003e,
        vk: 0xbe,
        mac: Some(0x2f),
    },
    KeyInfo {
        name: "?",
        keysym: 0x003f,
        vk: 0xbf,
        mac: Some(0x2c),
    },
    KeyInfo {
        name: "~",
        keysym: 0x007e,
        vk: 0xc0,
        mac: Some(0x32),
    },
    KeyInfo {
        name: "!",
        keysym: 0x0021,
        vk: 0x31,
        mac: Some(0x12),
    },
    KeyInfo {
        name: "@",
        keysym: 0x0040,
        vk: 0x32,
        mac: Some(0x13),
    },
    KeyInfo {
        name: "#",
        keysym: 0x0023,
        vk: 0x33,
        mac: Some(0x14),
    },
    KeyInfo {
        name: "$",
        keysym: 0x0024,
        vk: 0x34,
        mac: Some(0x15),
    },
    KeyInfo {
        name: "%",
        keysym: 0x0025,
        vk: 0x35,
        mac: Some(0x17),
    },
    KeyInfo {
        name: "^",
        keysym: 0x005e,
        vk: 0x36,
        mac: Some(0x16),
    },
    KeyInfo {
        name: "&",
        keysym: 0x0026,
        vk: 0x37,
        mac: Some(0x1a),
    },
    KeyInfo {
        name: "*",
        keysym: 0x002a,
        vk: 0x38,
        mac: Some(0x1c),
    },
    KeyInfo {
        name: "(",
        keysym: 0x0028,
        vk: 0x39,
        mac: Some(0x19),
    },
    KeyInfo {
        name: ")",
        keysym: 0x0029,
        vk: 0x30,
        mac: Some(0x1d),
    },
    KeyInfo {
        name: "_",
        keysym: 0x005f,
        vk: 0xbd,
        mac: Some(0x1b),
    },
    KeyInfo {
        name: "+",
        keysym: 0x002b,
        vk: 0xbb,
        mac: Some(0x18),
    },
    // Numpad.
    KeyInfo {
        name: "kp0",
        keysym: 0xffb0,
        vk: 0x60,
        mac: Some(0x52),
    },
    KeyInfo {
        name: "kp1",
        keysym: 0xffb1,
        vk: 0x61,
        mac: Some(0x53),
    },
    KeyInfo {
        name: "kp2",
        keysym: 0xffb2,
        vk: 0x62,
        mac: Some(0x54),
    },
    KeyInfo {
        name: "kp3",
        keysym: 0xffb3,
        vk: 0x63,
        mac: Some(0x55),
    },
    KeyInfo {
        name: "kp4",
        keysym: 0xffb4,
        vk: 0x64,
        mac: Some(0x56),
    },
    KeyInfo {
        name: "kp5",
        keysym: 0xffb5,
        vk: 0x65,
        mac: Some(0x57),
    },
    KeyInfo {
        name: "kp6",
        keysym: 0xffb6,
        vk: 0x66,
        mac: Some(0x58),
    },
    KeyInfo {
        name: "kp7",
        keysym: 0xffb7,
        vk: 0x67,
        mac: Some(0x59),
    },
    KeyInfo {
        name: "kp8",
        keysym: 0xffb8,
        vk: 0x68,
        mac: Some(0x5b),
    },
    KeyInfo {
        name: "kp9",
        keysym: 0xffb9,
        vk: 0x69,
        mac: Some(0x5c),
    },
    KeyInfo {
        name: "kp-",
        keysym: 0xffad,
        vk: 0x6d,
        mac: Some(0x4e),
    },
    KeyInfo {
        name: "kp+",
        keysym: 0xffab,
        vk: 0x6b,
        mac: Some(0x45),
    },
    KeyInfo {
        name: "kp*",
        keysym: 0xffaa,
        vk: 0x6a,
        mac: Some(0x43),
    },
    KeyInfo {
        name: "kp/",
        keysym: 0xffaf,
        vk: 0x6f,
        mac: Some(0x4b),
    },
    KeyInfo {
        name: "kp.",
        keysym: 0xffae,
        vk: 0x6e,
        mac: Some(0x41),
    },
    KeyInfo {
        name: "kpenter",
        keysym: 0xff8d,
        vk: 0x0d,
        mac: Some(0x4c),
    },
    // Media / browser.
    KeyInfo {
        name: "volup",
        keysym: XF86_AUDIO_RAISE,
        vk: 0xaf,
        mac: Some(0x48),
    },
    KeyInfo {
        name: "voldown",
        keysym: XF86_AUDIO_LOWER,
        vk: 0xae,
        mac: Some(0x49),
    },
    KeyInfo {
        name: "volmute",
        keysym: XF86_AUDIO_MUTE,
        vk: 0xad,
        mac: Some(0x4a),
    },
    KeyInfo {
        name: "playpause",
        keysym: XF86_AUDIO_PLAY,
        vk: 0xb3,
        mac: None,
    },
    KeyInfo {
        name: "nexttrack",
        keysym: XF86_AUDIO_NEXT,
        vk: 0xb0,
        mac: None,
    },
    KeyInfo {
        name: "prevtrack",
        keysym: XF86_AUDIO_PREV,
        vk: 0xb1,
        mac: None,
    },
    KeyInfo {
        name: "stop",
        keysym: XF86_AUDIO_STOP,
        vk: 0xb2,
        mac: None,
    },
    KeyInfo {
        name: "mediaselect",
        keysym: XF86_AUDIO_MEDIA,
        vk: 0xb5,
        mac: None,
    },
    KeyInfo {
        name: "browser-back",
        keysym: XF86_BACK,
        vk: 0xa6,
        mac: None,
    },
    KeyInfo {
        name: "browser-forward",
        keysym: XF86_FORWARD,
        vk: 0xa7,
        mac: None,
    },
    // Lock keys.
    KeyInfo {
        name: "capslock",
        keysym: 0xffe5,
        vk: 0x14,
        mac: Some(0x39),
    },
    KeyInfo {
        name: "numlock",
        keysym: 0xff7f,
        vk: 0x90,
        mac: Some(0x47),
    },
    KeyInfo {
        name: "scrolllock",
        keysym: 0xff14,
        vk: 0x91,
        mac: None,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combo_normalizes_modifiers() {
        let keys = parse_combo("Ctrl+Shift+A").unwrap();
        assert_eq!(keys, vec!["ctrl", "shift", "a"]);
        assert_eq!(canonical("cmd").unwrap(), "meta");
        assert!(key_info("enter").unwrap().vk == 0x0d);
    }

    #[test]
    fn left_right_modifiers_stay_distinct() {
        assert_eq!(canonical("lctrl").unwrap(), "lctrl");
        assert_eq!(canonical("ralt").unwrap(), "ralt");
        assert_eq!(canonical("lgui").unwrap(), "lgui");
        assert_eq!(canonical("rshift").unwrap(), "rshift");
        assert_ne!(key_info("lctrl").unwrap().vk, key_info("rctrl").unwrap().vk);
    }

    #[test]
    fn win_l_combo_resolves() {
        let keys = parse_combo("Win+L").unwrap();
        assert_eq!(keys, vec!["meta", "l"]);
        assert!(key_info("meta").is_some());
        assert!(key_info("l").is_some());
    }

    /// Table-driven: every newly required name maps to a platform code.
    #[test]
    fn named_keys_map_to_platform_codes() {
        let cases: &[(&str, u16, u32)] = &[
            (",", 0xbc, 0x002c),
            (".", 0xbe, 0x002e),
            ("/", 0xbf, 0x002f),
            (";", 0xba, 0x003b),
            ("'", 0xde, 0x0027),
            ("[", 0xdb, 0x005b),
            ("]", 0xdd, 0x005d),
            ("\\", 0xdc, 0x005c),
            ("-", 0xbd, 0x002d),
            ("=", 0xbb, 0x003d),
            (":", 0xba, 0x003a),
            ("\"", 0xde, 0x0022),
            ("{", 0xdb, 0x007b),
            ("}", 0xdd, 0x007d),
            ("|", 0xdc, 0x007c),
            ("<", 0xbc, 0x003c),
            (">", 0xbe, 0x003e),
            ("?", 0xbf, 0x003f),
            ("~", 0xc0, 0x007e),
            ("!", 0x31, 0x0021),
            ("@", 0x32, 0x0040),
            ("#", 0x33, 0x0023),
            ("$", 0x34, 0x0024),
            ("%", 0x35, 0x0025),
            ("^", 0x36, 0x005e),
            ("&", 0x37, 0x0026),
            ("*", 0x38, 0x002a),
            ("(", 0x39, 0x0028),
            (")", 0x30, 0x0029),
            ("_", 0xbd, 0x005f),
            ("+", 0xbb, 0x002b),
            ("kp0", 0x60, 0xffb0),
            ("kp9", 0x69, 0xffb9),
            ("kp-", 0x6d, 0xffad),
            ("kp+", 0x6b, 0xffab),
            ("kp*", 0x6a, 0xffaa),
            ("kp/", 0x6f, 0xffaf),
            ("kp.", 0x6e, 0xffae),
            ("kpenter", 0x0d, 0xff8d),
            ("insert", 0x2d, 0xff63),
            ("prtsc", 0x2c, 0xff61),
            ("pause", 0x13, 0xff13),
            ("apps", 0x5d, 0xff67),
            ("volup", 0xaf, XF86_AUDIO_RAISE),
            ("voldown", 0xae, XF86_AUDIO_LOWER),
            ("volmute", 0xad, XF86_AUDIO_MUTE),
            ("playpause", 0xb3, XF86_AUDIO_PLAY),
            ("nexttrack", 0xb0, XF86_AUDIO_NEXT),
            ("prevtrack", 0xb1, XF86_AUDIO_PREV),
            ("stop", 0xb2, XF86_AUDIO_STOP),
            ("mediaselect", 0xb5, XF86_AUDIO_MEDIA),
            ("browser-back", 0xa6, XF86_BACK),
            ("browser-forward", 0xa7, XF86_FORWARD),
            ("lctrl", 0xa2, 0xffe3),
            ("rctrl", 0xa3, 0xffe4),
            ("lalt", 0xa4, 0xffe9),
            ("ralt", 0xa5, 0xffea),
            ("lshift", 0xa0, 0xffe1),
            ("rshift", 0xa1, 0xffe2),
            ("lgui", 0x5b, 0xffeb),
            ("rgui", 0x5c, 0xffec),
        ];
        for &(name, vk, keysym) in cases {
            let info = key_info(name).unwrap_or_else(|| panic!("missing key '{name}'"));
            assert_eq!(info.vk, vk, "vk for {name}");
            assert_eq!(info.keysym, keysym, "keysym for {name}");
            // mac field is always present (0 for keys without a CGKeyCode).
            let _ = info.mac;
        }
    }

    #[test]
    fn secure_attention_is_only_ctrl_alt_delete() {
        assert!(is_secure_attention_sequence(&["ctrl", "alt", "delete"]));
        assert!(is_secure_attention_sequence(&[
            "lctrl".to_string(),
            "ralt".into(),
            "del".into()
        ]));
        assert!(!is_secure_attention_sequence(&["ctrl", "c"]));
        assert!(!is_secure_attention_sequence(&["delete"]));
        assert!(!is_secure_attention_sequence(&["ctrl", "alt", "tab"]));
        assert!(!is_secure_attention_sequence(&["alt", "f4"]));
        assert!(!is_secure_attention_sequence::<&str>(&[]));
    }

    #[test]
    fn windows_extended_vk_flags_navigation_win_and_right_modifiers() {
        for ext in [
            "up", "down", "left", "right", "home", "end", "pageup", "pagedown", "insert",
            "delete", "prtsc", "meta", "lgui", "rgui", "apps", "rctrl", "ralt", "kp/", "volup",
        ] {
            let vk = key_info(ext).unwrap_or_else(|| panic!("missing {ext}")).vk;
            assert!(
                is_windows_extended_vk(vk),
                "{ext} (vk={vk:#x}) must carry KEYEVENTF_EXTENDEDKEY"
            );
        }
        for main_block in ["a", "0", "enter", "tab", "escape", "backspace", "ctrl", "lctrl", "shift", "lalt", "f1", "f24"] {
            let vk = key_info(main_block)
                .unwrap_or_else(|| panic!("missing {main_block}"))
                .vk;
            assert!(
                !is_windows_extended_vk(vk),
                "{main_block} (vk={vk:#x}) must not carry KEYEVENTF_EXTENDEDKEY"
            );
        }
    }

    #[test]
    fn plus_and_ctrl_plus_plus_and_lock_keys_parse() {
        assert_eq!(canonical("plus").unwrap(), "+");
        assert_eq!(parse_combo("ctrl++").unwrap(), vec!["ctrl", "+"]);
        assert_eq!(parse_combo("ctrl+shift++").unwrap(), vec!["ctrl", "shift", "+"]);
        assert_eq!(parse_combo("+").unwrap(), vec!["+"]);
        assert_eq!(parse_combo("ctrl+plus").unwrap(), vec!["ctrl", "+"]);
        assert_eq!(parse_combo("kp+").unwrap(), vec!["kp+"]);
        assert_eq!(parse_combo("ctrl+kp+").unwrap(), vec!["ctrl", "kp+"]);

        assert_eq!(canonical("capslock").unwrap(), "capslock");
        assert_eq!(canonical("caps_lock").unwrap(), "capslock");
        assert_eq!(canonical("numlock").unwrap(), "numlock");
        assert_eq!(canonical("scrolllock").unwrap(), "scrolllock");
        assert_eq!(key_info("capslock").unwrap().vk, 0x14);
        assert_eq!(key_info("numlock").unwrap().vk, 0x90);
        assert_eq!(key_info("scrolllock").unwrap().vk, 0x91);
        assert!(is_windows_extended_vk(key_info("numlock").unwrap().vk));
    }

    #[test]
    fn unmapped_mac_keys_are_none_not_k_vk_ansi_a() {
        assert_eq!(key_info("a").unwrap().mac, Some(0x00));
        for key in [
            "f21",
            "f22",
            "f23",
            "f24",
            "playpause",
            "nexttrack",
            "prevtrack",
            "stop",
            "mediaselect",
            "browser-back",
            "browser-forward",
            "scrolllock",
        ] {
            assert_eq!(
                key_info(key).unwrap().mac,
                None,
                "{key} must not map to 0x00 (kVK_ANSI_A)"
            );
        }
    }
}
