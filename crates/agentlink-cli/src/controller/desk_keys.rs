//! Desktop keyboard forwarding.
//!
//! STD-only so tests can prove event semantics without a window. Pointer
//! ordering stays in [`super::input_adapter`]. This module decides which
//! key and text events may become remote injects.
//!
//! Remote-desktop clipboard sync is a separate channel (`Cmd::Clipboard`).
//! Copy, Cut, and Paste here become key chords for the remote application.
//! They are not terminal PTY bytes and they do not write the session clipboard.
//!
//! The local operating system may swallow Alt+Tab, Alt+F4, and Super/Win
//! before this process sees them. Those chords are explicit menu actions.
//! Windows Ctrl+Alt+Del is a secure attention sequence: ordinary injection
//! cannot open the security screen, and this module never emits it.

use super::input_adapter::{FrameEvent, ModSnapshot};

/// One host event already translated out of the GUI toolkit.
#[derive(Clone, Debug, PartialEq)]
pub enum HostKey {
    Key {
        name: String,
        pressed: bool,
        repeat: bool,
        mods: ModSnapshot,
    },
    Text(String),
    /// Platform translated Ctrl/Cmd+C into a copy command and may omit Key(C).
    Copy,
    /// Platform translated Ctrl/Cmd+X into a cut command and may omit Key(X).
    Cut,
    /// Platform translated Ctrl/Cmd+V into a paste command. The clipboard
    /// text is intentionally not carried: the remote app pastes its own clipboard.
    Paste,
    ImePreedit(String),
    ImeCommit(String),
}

/// Ordered slot so pointer events keep their place relative to keys.
#[derive(Clone, Debug, PartialEq)]
pub enum Slot {
    Pointer(FrameEvent),
    Key(HostKey),
}

/// Whether a captured desktop keyboard should stay captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HoldGate {
    pub on_desktop: bool,
    pub control_granted: bool,
    pub viewport_focused: bool,
    pub exiting: bool,
}

pub fn hold_keyboard(gate: &HoldGate) -> bool {
    gate.on_desktop && gate.control_granted && gate.viewport_focused && !gate.exiting
}

/// Input failures that mean the grant no longer allows injection.
pub fn failure_revokes_input(message: &str) -> bool {
    let text = message.to_ascii_lowercase();
    text.contains("not allowed")
        || text.contains("grant")
        || text.contains("remote-control")
        || text.contains("remote control")
}

/// A chord the local OS may consume before the controller sees the keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteChord {
    pub label: &'static str,
    pub keys: &'static [&'static str],
    pub limit: &'static str,
}

pub const SECURE_ATTENTION_NOTE: &str = "Ctrl+Alt+Del is the Windows secure attention sequence. Ordinary key injection cannot open the security screen, so this app does not send it.";

pub fn explicit_remote_chords() -> &'static [RemoteChord] {
    &[
        RemoteChord {
            label: "Send Alt+Tab",
            keys: &["alt", "tab"],
            limit: "The local OS often switches windows before this app sees Alt+Tab.",
        },
        RemoteChord {
            label: "Send Alt+Shift+Tab",
            keys: &["alt", "shift", "tab"],
            limit: "The local OS often consumes Alt+Shift+Tab.",
        },
        RemoteChord {
            label: "Send Alt+F4",
            keys: &["alt", "f4"],
            limit: "The local window manager may close this window instead of delivering Alt+F4.",
        },
        RemoteChord {
            label: "Send Win",
            keys: &["meta"],
            limit: "The local Super/Win key usually opens the local shell and never arrives here.",
        },
        RemoteChord {
            label: "Send Win+D",
            keys: &["meta", "d"],
            limit: "Physical Win chords are usually consumed by the local shell.",
        },
        RemoteChord {
            label: "Send Win+E",
            keys: &["meta", "e"],
            limit: "Physical Win chords are usually consumed by the local shell.",
        },
        RemoteChord {
            label: "Send Win+R",
            keys: &["meta", "r"],
            limit: "Physical Win chords are usually consumed by the local shell.",
        },
        RemoteChord {
            label: "Send Win+L",
            keys: &["meta", "l"],
            limit: "Win+L locks the remote session when the target accepts it. The local OS usually consumes the physical chord. This is not Ctrl+Alt+Del.",
        },
    ]
}

fn shortcut_mods(mods: ModSnapshot) -> bool {
    mods.ctrl || mods.alt || mods.command
}

fn plain_ctrl(mods: ModSnapshot) -> bool {
    (mods.ctrl || mods.command) && !mods.shift && !mods.alt
}

fn chord_present(slots: &[Slot], key: &str) -> bool {
    slots.iter().any(|slot| match slot {
        Slot::Key(HostKey::Key {
            name,
            pressed: true,
            mods,
            ..
        }) => name == key && plain_ctrl(*mods),
        _ => false,
    })
}

fn composition_frame(slots: &[Slot]) -> bool {
    slots.iter().any(|slot| match slot {
        Slot::Key(HostKey::ImeCommit(text)) => !text.is_empty(),
        Slot::Key(HostKey::ImePreedit(text)) => !text.is_empty(),
        Slot::Key(HostKey::Text(text)) => text.chars().any(|ch| !ch.is_ascii()),
        _ => false,
    })
}

fn is_composition_key(name: &str) -> bool {
    matches!(name, "enter" | "backspace" | "space" | "tab")
        || (name.chars().count() == 1
            && name
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric()))
}

fn frame_has_shortcut(slots: &[Slot]) -> bool {
    slots.iter().any(|slot| match slot {
        Slot::Key(HostKey::Key {
            pressed: true, mods, ..
        }) => shortcut_mods(*mods),
        _ => false,
    })
}

fn char_keys_sent(slots: &[Slot], composed: bool) -> Vec<char> {
    let mut chars = Vec::new();
    for slot in slots {
        let Slot::Key(HostKey::Key {
            name,
            pressed: true,
            mods,
            ..
        }) = slot
        else {
            continue;
        };
        if composed && is_composition_key(name) && !shortcut_mods(*mods) {
            continue;
        }
        if shortcut_mods(*mods) {
            continue;
        }
        if name.chars().count() == 1 {
            if let Some(ch) = name.chars().next() {
                chars.push(ch.to_ascii_lowercase());
            }
        }
    }
    chars
}

fn push_ctrl_chord(out: &mut Vec<FrameEvent>, key: &str) {
    let mods = ModSnapshot {
        ctrl: true,
        ..ModSnapshot::default()
    };
    out.push(FrameEvent::Key {
        name: key.to_string(),
        pressed: true,
        repeat: false,
        mods,
    });
    out.push(FrameEvent::Key {
        name: key.to_string(),
        pressed: false,
        repeat: false,
        mods,
    });
}

fn text_is_duplicate(text: &str, chars: &[char]) -> bool {
    let mut iter = text.chars();
    match (iter.next(), iter.next()) {
        (Some(ch), None) => chars.contains(&ch.to_ascii_lowercase()),
        _ => false,
    }
}

/// Merge pointer slots with the key events that may be injected.
///
/// Read-only and missing-grant sessions (`control == false`) keep pointer
/// events only when the caller included them, and drop every key. Capture
/// off drops keys as well, so local UI and the terminal keep the keyboard.
pub fn interleave(control: bool, capture: bool, slots: &[Slot]) -> Vec<FrameEvent> {
    if !control || !capture {
        return slots
            .iter()
            .filter_map(|slot| match slot {
                Slot::Pointer(event) => Some(event.clone()),
                Slot::Key(_) => None,
            })
            .collect();
    }
    let saw_c = chord_present(slots, "c");
    let saw_x = chord_present(slots, "x");
    let saw_v = chord_present(slots, "v");
    // Copy/Cut/Paste become key chords. A toolkit Text event in the same
    // frame is the character those chords would also type.
    let clipboard_command = slots.iter().any(|slot| {
        matches!(
            slot,
            Slot::Key(HostKey::Copy | HostKey::Cut | HostKey::Paste)
        )
    });
    let composed = composition_frame(slots);
    let typed = char_keys_sent(slots, composed);
    let shortcut = frame_has_shortcut(slots);
    let mut commits: Vec<String> = Vec::new();
    let mut copy_done = false;
    let mut cut_done = false;
    let mut paste_done = false;
    let mut out = Vec::new();

    for slot in slots {
        match slot {
            Slot::Pointer(event) => out.push(event.clone()),
            Slot::Key(HostKey::ImePreedit(_)) => {}
            Slot::Key(HostKey::ImeCommit(text)) => {
                if text.is_empty() || commits.iter().any(|have| have == text) {
                    continue;
                }
                commits.push(text.clone());
                out.push(FrameEvent::Text { text: text.clone() });
            }
            Slot::Key(HostKey::Copy) => {
                if saw_c || copy_done {
                    continue;
                }
                copy_done = true;
                push_ctrl_chord(&mut out, "c");
            }
            Slot::Key(HostKey::Cut) => {
                if saw_x || cut_done {
                    continue;
                }
                cut_done = true;
                push_ctrl_chord(&mut out, "x");
            }
            Slot::Key(HostKey::Paste) => {
                if saw_v || paste_done {
                    continue;
                }
                paste_done = true;
                push_ctrl_chord(&mut out, "v");
            }
            Slot::Key(HostKey::Key {
                name,
                pressed,
                repeat,
                mods,
            }) => {
                if composed && *pressed && is_composition_key(name) && !shortcut_mods(*mods) {
                    continue;
                }
                out.push(FrameEvent::Key {
                    name: name.clone(),
                    pressed: *pressed,
                    repeat: *repeat,
                    mods: *mods,
                });
            }
            Slot::Key(HostKey::Text(text)) => {
                // A Paste event is the remote Ctrl+V chord. Do not also type
                // the clipboard payload into the desktop session.
                if text.is_empty() || clipboard_command || commits.iter().any(|have| have == text) {
                    continue;
                }
                if composed && text.chars().all(|ch| ch.is_ascii()) {
                    continue;
                }
                if shortcut && text.chars().all(|ch| ch.is_ascii()) {
                    continue;
                }
                if text_is_duplicate(text, &typed) {
                    continue;
                }
                out.push(FrameEvent::Text { text: text.clone() });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::input_adapter::{adapt_frame, AdapterState, ContentGeom};
    use super::super::input_policy::OutEvent;

    fn ctrl() -> ModSnapshot {
        ModSnapshot {
            ctrl: true,
            ..ModSnapshot::default()
        }
    }

    fn key(name: &str, pressed: bool, mods: ModSnapshot) -> Slot {
        Slot::Key(HostKey::Key {
            name: name.into(),
            pressed,
            repeat: false,
            mods,
        })
    }

    fn names(events: &[FrameEvent]) -> Vec<String> {
        events
            .iter()
            .map(|event| match event {
                FrameEvent::Key { name, pressed, .. } => {
                    format!("{name}:{}", if *pressed { "down" } else { "up" })
                }
                FrameEvent::Text { text } => format!("text:{text}"),
                FrameEvent::PointerMoved { .. } => "move".into(),
                FrameEvent::PointerButton { pressed, .. } => {
                    format!("button:{}", if *pressed { "down" } else { "up" })
                }
                FrameEvent::MouseWheel { .. } => "wheel".into(),
                FrameEvent::PointerGone => "gone".into(),
            })
            .collect()
    }

    #[test]
    fn view_only_and_uncaptured_drop_keys_and_keep_pointer() {
        let slots = [
            Slot::Pointer(FrameEvent::PointerMoved { x: 1.0, y: 2.0 }),
            key("c", true, ctrl()),
            Slot::Key(HostKey::Copy),
            Slot::Key(HostKey::Paste),
            Slot::Key(HostKey::Text("c".into())),
        ];
        assert_eq!(names(&interleave(false, true, &slots)), vec!["move".to_string()]);
        assert_eq!(names(&interleave(true, false, &slots)), vec!["move".to_string()]);
    }

    #[test]
    fn copy_without_key_c_is_one_ctrl_c_chord_not_text() {
        let out = interleave(true, true, &[Slot::Key(HostKey::Copy)]);
        assert_eq!(names(&out), vec!["c:down".to_string(), "c:up".to_string()]);
        assert!(out.iter().all(|event| !matches!(event, FrameEvent::Text { .. })));
        match &out[0] {
            FrameEvent::Key { mods, repeat, .. } => {
                assert!(mods.ctrl && !mods.shift && !mods.alt);
                assert!(!*repeat);
            }
            other => panic!("expected key, got {other:?}"),
        }
    }

    #[test]
    fn copy_plus_key_c_is_not_sent_twice() {
        let out = interleave(
            true,
            true,
            &[
                Slot::Key(HostKey::Copy),
                key("c", true, ctrl()),
                key("c", false, ctrl()),
            ],
        );
        assert_eq!(
            names(&out),
            vec!["c:down".to_string(), "c:up".to_string()]
        );
    }

    #[test]
    fn paste_is_ctrl_v_not_clipboard_text() {
        let out = interleave(
            true,
            true,
            &[Slot::Key(HostKey::Paste), Slot::Key(HostKey::Text("secret".into()))],
        );
        assert_eq!(names(&out), vec!["v:down".to_string(), "v:up".to_string()]);
    }

    #[test]
    fn copy_does_not_also_type_the_character() {
        let out = interleave(
            true,
            true,
            &[Slot::Key(HostKey::Copy), Slot::Key(HostKey::Text("c".into()))],
        );
        assert_eq!(names(&out), vec!["c:down".to_string(), "c:up".to_string()]);
    }

    #[test]
    fn cut_without_key_x_is_one_ctrl_x_chord() {
        let out = interleave(true, true, &[Slot::Key(HostKey::Cut)]);
        assert_eq!(names(&out), vec!["x:down".to_string(), "x:up".to_string()]);
    }

    #[test]
    fn escape_tab_and_function_keys_are_forwarded() {
        let mods = ModSnapshot::default();
        let out = interleave(
            true,
            true,
            &[
                key("escape", true, mods),
                key("escape", false, mods),
                key("tab", true, mods),
                key("f4", true, ctrl()),
            ],
        );
        assert_eq!(
            names(&out),
            vec![
                "escape:down".to_string(),
                "escape:up".to_string(),
                "tab:down".to_string(),
                "f4:down".to_string(),
            ]
        );
    }

    #[test]
    fn repeat_stays_a_down_without_becoming_text() {
        let out = interleave(
            true,
            true,
            &[Slot::Key(HostKey::Key {
                name: "backspace".into(),
                pressed: true,
                repeat: true,
                mods: ModSnapshot::default(),
            })],
        );
        match &out[..] {
            [FrameEvent::Key {
                name,
                pressed: true,
                repeat: true,
                ..
            }] => assert_eq!(name, "backspace"),
            other => panic!("expected one repeat down, got {other:?}"),
        }
    }

    #[test]
    fn ascii_text_is_not_sent_again_after_its_key() {
        let mods = ModSnapshot::default();
        let out = interleave(
            true,
            true,
            &[key("a", true, mods), Slot::Key(HostKey::Text("a".into()))],
        );
        assert_eq!(names(&out), vec!["a:down".to_string()]);
    }

    #[test]
    fn shortcut_suppresses_the_typed_character() {
        let out = interleave(
            true,
            true,
            &[key("c", true, ctrl()), Slot::Key(HostKey::Text("c".into()))],
        );
        assert_eq!(names(&out), vec!["c:down".to_string()]);
    }

    #[test]
    fn ime_preedit_is_dropped_and_commit_is_one_text() {
        let mods = ModSnapshot::default();
        let out = interleave(
            true,
            true,
            &[
                Slot::Key(HostKey::ImePreedit("ni".into())),
                key("n", true, mods),
                key("i", true, mods),
                Slot::Key(HostKey::ImeCommit("你".into())),
                Slot::Key(HostKey::Text("你".into())),
            ],
        );
        assert_eq!(names(&out), vec!["text:你".to_string()]);
    }

    #[test]
    fn layout_text_without_a_key_is_forwarded_once() {
        let out = interleave(true, true, &[Slot::Key(HostKey::Text("é".into()))]);
        assert_eq!(names(&out), vec!["text:é".to_string()]);
    }

    #[test]
    fn pointer_stays_before_a_following_key() {
        let out = interleave(
            true,
            true,
            &[
                Slot::Pointer(FrameEvent::PointerMoved { x: 4.0, y: 5.0 }),
                key("a", true, ModSnapshot::default()),
            ],
        );
        assert_eq!(names(&out), vec!["move".to_string(), "a:down".to_string()]);
    }

    #[test]
    fn explicit_chords_do_not_include_secure_attention() {
        for chord in explicit_remote_chords() {
            let joined = chord.keys.join("+");
            assert!(
                !agentlink_desktop::is_secure_attention_sequence(chord.keys),
                "{joined} must not be offered as an injectable secure attention sequence"
            );
            assert!(!chord.limit.is_empty());
        }
        assert!(SECURE_ATTENTION_NOTE.contains("cannot"));
        assert!(!explicit_remote_chords().is_empty());
    }

    #[test]
    fn hold_releases_on_focus_exit_view_and_off_desktop() {
        let live = HoldGate {
            on_desktop: true,
            control_granted: true,
            viewport_focused: true,
            exiting: false,
        };
        assert!(hold_keyboard(&live));
        assert!(!hold_keyboard(&HoldGate {
            viewport_focused: false,
            ..live
        }));
        assert!(!hold_keyboard(&HoldGate {
            exiting: true,
            ..live
        }));
        assert!(!hold_keyboard(&HoldGate {
            control_granted: false,
            ..live
        }));
        assert!(!hold_keyboard(&HoldGate {
            on_desktop: false,
            ..live
        }));
    }

    #[test]
    fn grant_failures_revoke_input_and_ordinary_errors_do_not() {
        assert!(failure_revokes_input("not allowed: missing grant"));
        assert!(failure_revokes_input("grant expired"));
        assert!(failure_revokes_input("remote-control is required"));
        assert!(!failure_revokes_input("connection timed out"));
        assert!(!failure_revokes_input("unknown key 'nope'"));
    }

    #[test]
    fn forwarded_ctrl_c_survives_the_adapter_as_ctrl_then_c() {
        let slots = [Slot::Key(HostKey::Copy)];
        let frame = interleave(true, true, &slots);
        let mut state = AdapterState::default();
        let out = adapt_frame(
            &mut state,
            ContentGeom::from_xywh(0.0, 0.0, 10.0, 10.0),
            &frame,
            Some(ModSnapshot::default()),
            true,
        );
        let trace: Vec<_> = out
            .iter()
            .map(|event| match event {
                OutEvent::Key { name, pressed, .. } => {
                    format!("{name}:{}", if *pressed { "down" } else { "up" })
                }
                OutEvent::Text { text } => format!("text:{text}"),
                OutEvent::Mouse { action, .. } => (*action).to_string(),
            })
            .collect();
        assert_eq!(
            trace,
            vec![
                "ctrl:down".to_string(),
                "c:down".to_string(),
                "c:up".to_string(),
                "ctrl:up".to_string(),
            ]
        );
    }
}
