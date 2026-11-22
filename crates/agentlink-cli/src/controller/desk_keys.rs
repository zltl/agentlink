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
//! Platform toolkit notes (`egui-winit 0.31`):
//! - On press, `Ctrl/Cmd+C`, `Ctrl/Cmd+X`, and `Ctrl/Cmd+V` (plus Windows
//!   `Ctrl+Insert`, `Shift+Delete`, and `Shift+Insert`) become `Event::Copy`,
//!   `Event::Cut`, or `Event::Paste`, and `egui-winit` returns before emitting
//!   a `Key` press.
//! - When `Event::Paste` is triggered while the controller's *local text*
//!   clipboard is empty (for instance, the user copied a file or image on the
//!   remote desktop), `egui-winit` drops the press completely and only emits
//!   the matching `Key` release (`V`, `Insert`, or `Paste`). [`KeyPairState`]
//!   recovers that swallowed chord on release without duplicating normal pastes.
//! - On Windows, `Shift+Delete` and `Shift+Insert` carry `shift && !ctrl && !command`,
//!   allowing us to restore `Shift+Delete` (permanent delete) and `Shift+Insert`
//!   instead of turning them into `Ctrl+X` / `Ctrl+V`. `Ctrl+Insert` shares
//!   `ctrl && !shift` with `Ctrl+C` inside `Event::Copy`; literal `Ctrl+Insert`
//!   is available in [`explicit_remote_chords`].
//! - Physical key slots pair key-up with the exact logical key name sent at
//!   key-down so releasing `Shift` before `=` still releases `"+"`.
//!
//! The local operating system may swallow Alt+Tab, Alt+F4, and Super/Win
//! before this process sees them. Those chords are explicit menu actions.
//! Windows Ctrl+Alt+Del is a secure attention sequence: ordinary injection
//! cannot open the security screen, and this module never emits it.

use std::collections::BTreeMap;

use super::input_adapter::{FrameEvent, ModSnapshot};

/// Remote node operating-system family for toolkit command-chord translation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TargetOs {
    /// Windows, Linux, and unknown nodes use `Ctrl` for Copy/Cut/Paste chords.
    #[default]
    Standard,
    /// macOS nodes use `Meta` (`Cmd`) for toolkit Copy/Cut/Paste chords.
    MacOs,
}

impl TargetOs {
    pub fn from_node_os(os: &str) -> Self {
        let lower = os.to_ascii_lowercase();
        if lower.contains("macos") || lower.contains("darwin") {
            Self::MacOs
        } else {
            Self::Standard
        }
    }
}

/// Persistent keyboard pairing and swallowed-paste state across frames.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyPairState {
    /// Maps physical slot name (or logical name when physical is absent) to
    /// the exact logical key name whose `down` edge was emitted.
    pub slot_to_injected: BTreeMap<String, String>,
    /// True once at least one frame has run while keyboard capture was active.
    /// Prevents keys held *before* clicking the canvas from firing on release.
    pub captured_active: bool,
    /// True after `HostKey::Paste` emitted a chord until its key-up arrives
    /// or modifiers clear, preventing a second chord on release.
    pub paste_sent_in_chord: bool,
    /// Remembers a clean `Ctrl`/`Cmd` hold while captured in case the user
    /// releases `Ctrl` slightly before `V` during an empty-clipboard `Ctrl+V`.
    pub ctrl_paste_armed: bool,
    /// Remembers a clean `Shift` hold while captured for empty-clipboard `Shift+Insert`.
    pub shift_paste_armed: bool,
    /// Persistent IME composition state across frames (set while non-empty
    /// `ImePreedit` is active; cleared on `ImeCommit` or empty `ImePreedit`).
    pub ime_composing: bool,
}

impl KeyPairState {
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// One host event already translated out of the GUI toolkit.
#[derive(Clone, Debug, PartialEq)]
pub enum HostKey {
    Key {
        name: String,
        /// Physical key name when reported by winit, used to pair press/release
        /// across mid-chord Shift changes without overriding layout letters.
        physical: Option<String>,
        pressed: bool,
        repeat: bool,
        mods: ModSnapshot,
    },
    Text(String),
    /// Platform translated Ctrl/Cmd+C (or Windows Ctrl+Insert) into Copy.
    Copy { mods: ModSnapshot },
    /// Platform translated Ctrl/Cmd+X (or Windows Shift+Delete) into Cut.
    Cut { mods: ModSnapshot },
    /// Platform translated Ctrl/Cmd+V (or Windows Shift+Insert) into Paste.
    /// Clipboard text is intentionally omitted: the remote app pastes its own clipboard.
    Paste { mods: ModSnapshot },
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

/// A chord the local OS or GUI toolkit may consume before raw keys arrive.
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
        RemoteChord {
            label: "Send Ctrl+Insert",
            keys: &["ctrl", "insert"],
            limit: "On Windows, the GUI toolkit folds physical Ctrl+Insert into Copy (Ctrl+C); use this item when a remote terminal needs literal Ctrl+Insert.",
        },
        RemoteChord {
            label: "Send Shift+Insert",
            keys: &["shift", "insert"],
            limit: "Sends literal Shift+Insert for remote terminals and legacy editors.",
        },
    ]
}

fn shortcut_mods(mods: ModSnapshot) -> bool {
    mods.ctrl || mods.alt || mods.command
}

fn plain_ctrl(mods: ModSnapshot) -> bool {
    (mods.ctrl || mods.command) && !mods.shift && !mods.alt
}

fn shift_only(mods: ModSnapshot) -> bool {
    mods.shift && !mods.ctrl && !mods.command && !mods.alt
}

fn primary_shortcut_mods(target: TargetOs) -> ModSnapshot {
    match target {
        TargetOs::Standard => ModSnapshot {
            ctrl: true,
            ..ModSnapshot::default()
        },
        TargetOs::MacOs => ModSnapshot {
            command: true,
            ..ModSnapshot::default()
        },
    }
}

fn shift_mods() -> ModSnapshot {
    ModSnapshot {
        shift: true,
        ..ModSnapshot::default()
    }
}

fn chord_present(slots: &[Slot], key: &str, pred: impl Fn(ModSnapshot) -> bool) -> bool {
    slots.iter().any(|slot| match slot {
        Slot::Key(HostKey::Key {
            name,
            pressed: true,
            mods,
            ..
        }) => name == key && pred(*mods),
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
                .is_some_and(|ch| ch.is_ascii_graphic()))
}

fn frame_has_shortcut(slots: &[Slot]) -> bool {
    slots.iter().any(|slot| match slot {
        Slot::Key(HostKey::Key {
            pressed: true, mods, ..
        }) => shortcut_mods(*mods),
        _ => false,
    })
}

fn char_keys_sent(slots: &[Slot], composed: bool) -> (Vec<char>, bool) {
    let mut chars = Vec::new();
    let mut saw_space = false;
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
        if matches!(name.as_str(), "copy" | "cut" | "paste") {
            continue;
        }
        if composed && is_composition_key(name) && !shortcut_mods(*mods) {
            continue;
        }
        if shortcut_mods(*mods) {
            continue;
        }
        if name == "space" {
            saw_space = true;
            continue;
        }
        if name.chars().count() == 1 {
            if let Some(ch) = name.chars().next() {
                chars.push(ch.to_ascii_lowercase());
            }
        }
    }
    (chars, saw_space)
}

fn push_chord(out: &mut Vec<FrameEvent>, key: &str, mods: ModSnapshot) {
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

/// Deduplicate single-character printable ASCII `Event::Text` against a
/// same-frame printable `Key` press so shifted symbols absent from `egui::Key`
/// (`@ # $ % ^ & * ( ) _ " ~ < >`) never double-type as both `Shift+<key>` and
/// `inject_text("<sym>")`.
fn text_is_duplicate(text: &str, chars: &[char], saw_space: bool) -> bool {
    let mut iter = text.chars();
    match (iter.next(), iter.next()) {
        (Some(' '), None) => saw_space,
        (Some(ch), None) if ch.is_ascii_graphic() => !chars.is_empty(),
        _ => false,
    }
}

/// Stateless helper used by unit tests with default (`Standard`) target OS.
#[allow(dead_code)]
pub fn interleave(control: bool, capture: bool, slots: &[Slot]) -> Vec<FrameEvent> {
    let mut state = KeyPairState {
        captured_active: capture,
        ..KeyPairState::default()
    };
    interleave_with_state(
        control,
        capture,
        TargetOs::Standard,
        &mut state,
        slots,
        ModSnapshot::default(),
    )
}

/// Merge pointer slots with the key events that may be injected, tracking
/// physical key press/release slots and swallowed empty-clipboard pastes.
///
/// Read-only and missing-grant sessions (`control == false`) keep pointer
/// events only when the caller included them, and drop every key. Capture
/// off drops keys as well, so local UI and the terminal keep the keyboard.
pub fn interleave_with_state(
    control: bool,
    capture: bool,
    target: TargetOs,
    state: &mut KeyPairState,
    slots: &[Slot],
    final_mods: ModSnapshot,
) -> Vec<FrameEvent> {
    if !control || !capture {
        state.clear();
        return slots
            .iter()
            .filter_map(|slot| match slot {
                Slot::Pointer(event) => Some(event.clone()),
                Slot::Key(_) => None,
            })
            .collect();
    }

    let was_captured = state.captured_active;
    state.captured_active = true;

    let primary_mods = primary_shortcut_mods(target);
    let saw_c = chord_present(slots, "c", plain_ctrl);
    let saw_x = chord_present(slots, "x", plain_ctrl);
    let saw_shift_del = chord_present(slots, "delete", shift_only);
    let saw_v = chord_present(slots, "v", plain_ctrl);
    let saw_shift_ins = chord_present(slots, "insert", shift_only);

    let clipboard_command = slots.iter().any(|slot| {
        matches!(
            slot,
            Slot::Key(HostKey::Copy { .. } | HostKey::Cut { .. } | HostKey::Paste { .. })
        )
    });
    let mut composed = state.ime_composing || composition_frame(slots);
    let (typed, saw_space) = char_keys_sent(slots, composed);
    let shortcut = frame_has_shortcut(slots);
    let mut commits: Vec<String> = Vec::new();
    let mut copy_done = false;
    let mut cut_done = false;
    let mut paste_done = false;
    let mut out = Vec::new();

    for slot in slots {
        match slot {
            Slot::Pointer(event) => out.push(event.clone()),
            Slot::Key(HostKey::ImePreedit(preedit)) => {
                if preedit.is_empty() {
                    state.ime_composing = false;
                } else {
                    state.ime_composing = true;
                    composed = true;
                }
            }
            Slot::Key(HostKey::ImeCommit(text)) => {
                state.ime_composing = false;
                if text.is_empty() || commits.iter().any(|have| have == text) {
                    continue;
                }
                commits.push(text.clone());
                out.push(FrameEvent::Text { text: text.clone() });
            }
            Slot::Key(HostKey::Copy { .. }) => {
                state.ctrl_paste_armed = false;
                state.shift_paste_armed = false;
                if saw_c || copy_done {
                    continue;
                }
                copy_done = true;
                push_chord(&mut out, "c", primary_mods);
            }
            Slot::Key(HostKey::Cut { mods }) => {
                state.ctrl_paste_armed = false;
                state.shift_paste_armed = false;
                if shift_only(*mods) {
                    if saw_shift_del || cut_done {
                        continue;
                    }
                    cut_done = true;
                    push_chord(&mut out, "delete", shift_mods());
                } else {
                    if saw_x || cut_done {
                        continue;
                    }
                    cut_done = true;
                    push_chord(&mut out, "x", primary_mods);
                }
            }
            Slot::Key(HostKey::Paste { mods }) => {
                state.ctrl_paste_armed = false;
                state.shift_paste_armed = false;
                state.paste_sent_in_chord = true;
                if shift_only(*mods) {
                    if saw_shift_ins || paste_done {
                        continue;
                    }
                    paste_done = true;
                    push_chord(&mut out, "insert", shift_mods());
                } else {
                    if saw_v || paste_done {
                        continue;
                    }
                    paste_done = true;
                    push_chord(&mut out, "v", primary_mods);
                }
            }
            Slot::Key(HostKey::Key {
                name,
                physical,
                pressed,
                repeat,
                mods,
            }) => {
                let slot_key = physical.as_deref().unwrap_or(name.as_str());
                if *pressed {
                    if !matches!(name.as_str(), "v" | "insert" | "paste") {
                        state.ctrl_paste_armed = false;
                        state.shift_paste_armed = false;
                    }
                    if matches!(name.as_str(), "copy" | "cut" | "paste") {
                        continue;
                    }
                    if name == "escape" && state.ime_composing {
                        state.ime_composing = false;
                        continue;
                    }
                    if composed && is_composition_key(name) && !shortcut_mods(*mods) {
                        continue;
                    }
                    if let Some(prev) = state.slot_to_injected.insert(slot_key.to_string(), name.clone())
                    {
                        if prev != *name {
                            out.push(FrameEvent::Key {
                                name: prev,
                                pressed: false,
                                repeat: false,
                                mods: *mods,
                            });
                        }
                    }
                    out.push(FrameEvent::Key {
                        name: name.clone(),
                        pressed: true,
                        repeat: *repeat,
                        mods: *mods,
                    });
                } else if let Some(injected) = state.slot_to_injected.remove(slot_key) {
                    out.push(FrameEvent::Key {
                        name: injected,
                        pressed: false,
                        repeat: false,
                        mods: *mods,
                    });
                } else if was_captured {
                    // Orphaned release: check if egui-winit swallowed a Paste
                    // press because the local controller text clipboard was empty.
                    let is_v = slot_key == "v" || name == "v";
                    let is_ins = slot_key == "insert" || name == "insert";
                    let is_paste_key = name == "paste";
                    if (is_v || is_ins || is_paste_key) && state.paste_sent_in_chord {
                        state.paste_sent_in_chord = false;
                    } else if is_v && !paste_done && (plain_ctrl(*mods) || state.ctrl_paste_armed) {
                        paste_done = true;
                        state.ctrl_paste_armed = false;
                        push_chord(&mut out, "v", primary_mods);
                    } else if is_ins
                        && !paste_done
                        && (shift_only(*mods) || state.shift_paste_armed)
                    {
                        paste_done = true;
                        state.shift_paste_armed = false;
                        push_chord(&mut out, "insert", shift_mods());
                    } else if is_paste_key && !paste_done {
                        paste_done = true;
                        push_chord(&mut out, "v", primary_mods);
                    }
                }
            }
            Slot::Key(HostKey::Text(text)) => {
                // A Paste/Copy/Cut event is a remote key chord. Do not also
                // type the clipboard payload or chord letter into the desktop.
                if text.is_empty() || clipboard_command || commits.iter().any(|have| have == text) {
                    continue;
                }
                if composed && text.chars().all(|ch| ch.is_ascii()) {
                    continue;
                }
                if shortcut && text.chars().all(|ch| ch.is_ascii()) {
                    continue;
                }
                if text_is_duplicate(text, &typed, saw_space) {
                    continue;
                }
                out.push(FrameEvent::Text { text: text.clone() });
            }
        }
    }

    if !plain_ctrl(final_mods) && !shift_only(final_mods) {
        state.paste_sent_in_chord = false;
    }
    state.ctrl_paste_armed = plain_ctrl(final_mods) && state.slot_to_injected.is_empty();
    state.shift_paste_armed = shift_only(final_mods) && state.slot_to_injected.is_empty();

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

    fn shift() -> ModSnapshot {
        ModSnapshot {
            shift: true,
            ..ModSnapshot::default()
        }
    }

    fn key(name: &str, pressed: bool, mods: ModSnapshot) -> Slot {
        Slot::Key(HostKey::Key {
            name: name.into(),
            physical: None,
            pressed,
            repeat: false,
            mods,
        })
    }

    fn key_phys(name: &str, physical: &str, pressed: bool, mods: ModSnapshot) -> Slot {
        Slot::Key(HostKey::Key {
            name: name.into(),
            physical: Some(physical.into()),
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
            Slot::Key(HostKey::Copy { mods: ctrl() }),
            Slot::Key(HostKey::Paste { mods: ctrl() }),
            Slot::Key(HostKey::Text("c".into())),
        ];
        assert_eq!(names(&interleave(false, true, &slots)), vec!["move".to_string()]);
        assert_eq!(names(&interleave(true, false, &slots)), vec!["move".to_string()]);
    }

    #[test]
    fn copy_without_key_c_is_one_ctrl_c_chord_not_text() {
        let out = interleave(true, true, &[Slot::Key(HostKey::Copy { mods: ctrl() })]);
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
    fn macos_target_maps_copy_cut_paste_to_meta_chord() {
        let mut state = KeyPairState {
            captured_active: true,
            ..KeyPairState::default()
        };
        let cmd = ModSnapshot {
            command: true,
            ..ModSnapshot::default()
        };
        let out = interleave_with_state(
            true,
            true,
            TargetOs::MacOs,
            &mut state,
            &[Slot::Key(HostKey::Copy { mods: cmd })],
            ModSnapshot::default(),
        );
        let mut adapter = AdapterState::default();
        let reduced = adapt_frame(
            &mut adapter,
            ContentGeom::from_xywh(0.0, 0.0, 10.0, 10.0),
            &out,
            Some(ModSnapshot::default()),
            true,
        );
        let trace: Vec<_> = reduced
            .iter()
            .map(|ev| match ev {
                OutEvent::Key { name, pressed, .. } => {
                    format!("{name}:{}", if *pressed { "down" } else { "up" })
                }
                _ => "other".into(),
            })
            .collect();
        assert_eq!(
            trace,
            vec![
                "meta:down".to_string(),
                "c:down".to_string(),
                "c:up".to_string(),
                "meta:up".to_string(),
            ]
        );
    }

    #[test]
    fn copy_plus_key_c_is_not_sent_twice() {
        let out = interleave(
            true,
            true,
            &[
                Slot::Key(HostKey::Copy { mods: ctrl() }),
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
    fn paste_is_ctrl_v_not_clipboard_text_and_ignores_trailing_v_release() {
        let mut state = KeyPairState {
            captured_active: true,
            ..KeyPairState::default()
        };
        let f1 = interleave_with_state(
            true,
            true,
            TargetOs::Standard,
            &mut state,
            &[
                Slot::Key(HostKey::Paste { mods: ctrl() }),
                Slot::Key(HostKey::Text("secret".into())),
            ],
            ctrl(),
        );
        assert_eq!(names(&f1), vec!["v:down".to_string(), "v:up".to_string()]);
        let f2 = interleave_with_state(
            true,
            true,
            TargetOs::Standard,
            &mut state,
            &[key_phys("v", "v", false, ctrl())],
            ctrl(),
        );
        assert!(f2.is_empty(), "trailing V release after Event::Paste must not paste twice: {f2:?}");
    }

    #[test]
    fn empty_local_clipboard_swallowed_ctrl_v_still_pastes_once_on_release() {
        let mut state = KeyPairState {
            captured_active: true,
            ..KeyPairState::default()
        };
        // Frame 1: Ctrl held, V pressed with empty local text clipboard -> egui-winit emits nothing for V!
        let f1 = interleave_with_state(true, true, TargetOs::Standard, &mut state, &[], ctrl());
        assert!(f1.is_empty());
        // Frame 2: User releases V (even if Ctrl released simultaneously or still held).
        let f2 = interleave_with_state(
            true,
            true,
            TargetOs::Standard,
            &mut state,
            &[key_phys("v", "v", false, ModSnapshot::default())],
            ModSnapshot::default(),
        );
        assert_eq!(names(&f2), vec!["v:down".to_string(), "v:up".to_string()]);
        assert!(matches!(&f2[0], FrameEvent::Key { mods, .. } if mods.ctrl));
    }

    #[test]
    fn windows_shift_delete_and_shift_insert_are_preserved_not_ctrl_x_v() {
        let cut = interleave(true, true, &[Slot::Key(HostKey::Cut { mods: shift() })]);
        assert_eq!(
            names(&cut),
            vec!["delete:down".to_string(), "delete:up".to_string()]
        );
        assert!(matches!(&cut[0], FrameEvent::Key { mods, .. } if mods.shift && !mods.ctrl));

        let paste = interleave(true, true, &[Slot::Key(HostKey::Paste { mods: shift() })]);
        assert_eq!(
            names(&paste),
            vec!["insert:down".to_string(), "insert:up".to_string()]
        );
        assert!(matches!(&paste[0], FrameEvent::Key { mods, .. } if mods.shift && !mods.ctrl));
    }

    #[test]
    fn physical_slot_releases_plus_when_shift_lifts_before_equals() {
        let mut state = KeyPairState {
            captured_active: true,
            ..KeyPairState::default()
        };
        // Shift + `=` arrives as logical `+` on physical `=`.
        let down = interleave_with_state(
            true,
            true,
            TargetOs::Standard,
            &mut state,
            &[
                key_phys("+", "=", true, shift()),
                Slot::Key(HostKey::Text("+".into())),
            ],
            shift(),
        );
        assert_eq!(names(&down), vec!["+:down".to_string()]);
        // User lifts Shift first, then lifts `=` (logical `=`, physical `=`).
        let up = interleave_with_state(
            true,
            true,
            TargetOs::Standard,
            &mut state,
            &[key_phys("=", "=", false, ModSnapshot::default())],
            ModSnapshot::default(),
        );
        assert_eq!(names(&up), vec!["+:up".to_string()]);
        assert!(state.slot_to_injected.is_empty());
    }

    #[test]
    fn copy_does_not_also_type_the_character() {
        let out = interleave(
            true,
            true,
            &[
                Slot::Key(HostKey::Copy { mods: ctrl() }),
                Slot::Key(HostKey::Text("c".into())),
            ],
        );
        assert_eq!(names(&out), vec!["c:down".to_string(), "c:up".to_string()]);
    }

    #[test]
    fn cut_without_key_x_is_one_ctrl_x_chord() {
        let out = interleave(true, true, &[Slot::Key(HostKey::Cut { mods: ctrl() })]);
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
                physical: Some("backspace".into()),
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
    fn shifted_punctuation_key_suppresses_duplicate_ascii_text() {
        let out = interleave(
            true,
            true,
            &[
                key_phys(":", ";", true, shift()),
                Slot::Key(HostKey::Text(":".into())),
            ],
        );
        assert_eq!(names(&out), vec!["::down".to_string()]);
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
    fn layout_non_ascii_on_punctuation_physical_key_sends_only_text() {
        // E.g. German QWERTZ `ü` sits on the physical `[` key: egui-winit emits
        // physical fallback Key(`[`) + Text("ü"). Only "ü" should be sent.
        let mods = ModSnapshot::default();
        let out = interleave(
            true,
            true,
            &[
                key_phys("[", "[", true, mods),
                Slot::Key(HostKey::Text("ü".into())),
            ],
        );
        assert_eq!(names(&out), vec!["text:ü".to_string()]);
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
        let slots = [Slot::Key(HostKey::Copy { mods: ctrl() })];
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

    #[test]
    fn shifted_us_symbols_do_not_double_type_with_text() {
        for (phys, sym) in [
            ("2", "@"),
            ("3", "#"),
            ("4", "$"),
            ("5", "%"),
            ("6", "^"),
            ("7", "&"),
            ("8", "*"),
            ("9", "("),
            ("0", ")"),
            ("-", "_"),
            ("'", "\""),
            ("`", "~"),
            (",", "<"),
            (".", ">"),
        ] {
            let out = interleave(
                true,
                true,
                &[
                    key_phys(phys, phys, true, shift()),
                    Slot::Key(HostKey::Text(sym.into())),
                ],
            );
            assert_eq!(
                names(&out),
                vec![format!("{phys}:down")],
                "shifted symbol {sym} on key {phys} must not emit both Key and Text: {out:?}"
            );
        }
    }

    #[test]
    fn multi_frame_ime_preedit_suppresses_raw_ascii_until_commit() {
        let mods = ModSnapshot::default();
        let mut state = KeyPairState {
            captured_active: true,
            ..KeyPairState::default()
        };
        // Frame 1: IME opens with preedit "n".
        let f1 = interleave_with_state(
            true,
            true,
            TargetOs::Standard,
            &mut state,
            &[Slot::Key(HostKey::ImePreedit("n".into())), key("n", true, mods)],
            mods,
        );
        assert!(f1.is_empty(), "frame 1 should suppress preedit key: {f1:?}");
        assert!(state.ime_composing);

        // Frame 2: next ASCII key arrives without a fresh ImePreedit in the same frame.
        let f2 = interleave_with_state(
            true,
            true,
            TargetOs::Standard,
            &mut state,
            &[key("i", true, mods), Slot::Key(HostKey::Text("i".into()))],
            mods,
        );
        assert!(
            f2.is_empty(),
            "frame 2 must suppress raw ASCII while ime_composing is active: {f2:?}"
        );
        assert!(state.ime_composing);

        // Frame 3: IME commits "你".
        let f3 = interleave_with_state(
            true,
            true,
            TargetOs::Standard,
            &mut state,
            &[
                key("space", true, mods),
                Slot::Key(HostKey::ImeCommit("你".into())),
                Slot::Key(HostKey::Text("你".into())),
            ],
            mods,
        );
        assert_eq!(names(&f3), vec!["text:你".to_string()]);
        assert!(!state.ime_composing);

        // Frame 4: normal typing resumes immediately after commit.
        let f4 = interleave_with_state(
            true,
            true,
            TargetOs::Standard,
            &mut state,
            &[key("a", true, mods), Slot::Key(HostKey::Text("a".into()))],
            mods,
        );
        assert_eq!(names(&f4), vec!["a:down".to_string()]);
    }
}
