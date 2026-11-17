//! Ordered remote-desktop input policy.
//!
//! STD-only (no egui / tokio / serde) so `rustc --edition 2021 --test` can
//! prove barrier ordering on the box without a workspace Cargo build.
//!
//! Rules (executor review of 0ffdc01):
//! - Coalesce **only** adjacent moves; a click/wheel/key is a barrier.
//! - Never reorder non-move events; never drop held-button releases.
//! - Downs require over-image; ups fire whenever the button is held
//!   (outside pane / PointerGone use last fractions).
//! - Do **not** synthesize `click count=2` on top of down/up (avoids 4 clicks).
//! - Ctrl/Shift modifiers do not suppress remote right-click.

#![allow(dead_code)]

use std::collections::BTreeSet;

/// Mouse button on the wire (`left` / `right` / `middle`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
    Middle,
}

impl Button {
    pub fn as_str(self) -> &'static str {
        match self {
            Button::Left => "left",
            Button::Right => "right",
            Button::Middle => "middle",
        }
    }
}

/// One raw input sample already mapped to content fractions (0..1).
#[derive(Clone, Debug, PartialEq)]
pub enum RawEvent {
    Move {
        x: f64,
        y: f64,
        over_image: bool,
    },
    Button {
        button: Button,
        pressed: bool,
        x: f64,
        y: f64,
        over_image: bool,
    },
    Wheel {
        x: f64,
        y: f64,
        dx: i32,
        dy: i32,
        over_image: bool,
    },
    Key {
        name: String,
        pressed: bool,
    },
    /// Non-ASCII text; barrier (never delayed past later clicks/keys).
    Text {
        text: String,
    },
    /// Ordered pointer-leave barrier — release held buttons only (not keys).
    PointerGone,
}

/// Injected / control output after reduction.
#[derive(Clone, Debug, PartialEq)]
pub enum OutEvent {
    Mouse {
        action: &'static str,
        button: &'static str,
        x: f64,
        y: f64,
        dx: i32,
        dy: i32,
    },
    Key {
        name: String,
        pressed: bool,
    },
    Text {
        text: String,
    },
}

/// Sticky held buttons + last known fractions for outside releases.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReducerState {
    pub held: BTreeSet<&'static str>,
    pub last_x: f64,
    pub last_y: f64,
}

fn flush_move(
    pending: &mut Option<(f64, f64)>,
    state: &mut ReducerState,
    out: &mut Vec<OutEvent>,
) {
    if let Some((x, y)) = pending.take() {
        state.last_x = x;
        state.last_y = y;
        out.push(OutEvent::Mouse {
            action: "move",
            button: "left",
            x,
            y,
            dx: 0,
            dy: 0,
        });
    }
}

/// Reduce an ordered raw stream into inject events.
///
/// Adjacent moves coalesce to the latest; any non-move flushes the pending
/// move first (move-before-barrier). Button downs require `over_image`; ups
/// always release a held button.
pub fn reduce(state: &mut ReducerState, events: &[RawEvent]) -> Vec<OutEvent> {
    let mut out = Vec::new();
    let mut pending_move: Option<(f64, f64)> = None;

    for ev in events {
        match ev {
            RawEvent::Move {
                x,
                y,
                over_image,
            } => {
                if *over_image || !state.held.is_empty() {
                    pending_move = Some((*x, *y));
                }
            }
            RawEvent::Button {
                button,
                pressed,
                x,
                y,
                over_image,
            } => {
                flush_move(&mut pending_move, state, &mut out);
                let name = button.as_str();
                if *pressed {
                    if *over_image {
                        state.last_x = *x;
                        state.last_y = *y;
                        state.held.insert(name);
                        out.push(OutEvent::Mouse {
                            action: "down",
                            button: name,
                            x: *x,
                            y: *y,
                            dx: 0,
                            dy: 0,
                        });
                    }
                } else if state.held.remove(name) {
                    // Prefer the release sample (already clamped/mapped); fall
                    // back to last fractions only if needed by caller.
                    state.last_x = *x;
                    state.last_y = *y;
                    out.push(OutEvent::Mouse {
                        action: "up",
                        button: name,
                        x: *x,
                        y: *y,
                        dx: 0,
                        dy: 0,
                    });
                }
            }
            RawEvent::Wheel {
                x,
                y,
                dx,
                dy,
                over_image,
            } => {
                flush_move(&mut pending_move, state, &mut out);
                if *over_image {
                    state.last_x = *x;
                    state.last_y = *y;
                    out.push(OutEvent::Mouse {
                        action: "scroll",
                        button: "left",
                        x: *x,
                        y: *y,
                        dx: *dx,
                        dy: *dy,
                    });
                }
            }
            RawEvent::Key { name, pressed } => {
                flush_move(&mut pending_move, state, &mut out);
                out.push(OutEvent::Key {
                    name: name.clone(),
                    pressed: *pressed,
                });
            }
            RawEvent::Text { text } => {
                flush_move(&mut pending_move, state, &mut out);
                if !text.is_empty() {
                    out.push(OutEvent::Text {
                        text: text.clone(),
                    });
                }
            }
            RawEvent::PointerGone => {
                flush_move(&mut pending_move, state, &mut out);
                out.extend(release_all(state));
            }
        }
    }
    flush_move(&mut pending_move, state, &mut out);
    out
}

/// Emit ups for every held button (focus loss / disconnect / PointerGone).
pub fn release_all(state: &mut ReducerState) -> Vec<OutEvent> {
    let held: Vec<&'static str> = state.held.iter().copied().collect();
    state.held.clear();
    held
        .into_iter()
        .map(|button| OutEvent::Mouse {
            action: "up",
            button,
            x: state.last_x,
            y: state.last_y,
            dx: 0,
            dy: 0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn move_to(x: f64, y: f64, over: bool) -> RawEvent {
        RawEvent::Move {
            x,
            y,
            over_image: over,
        }
    }

    fn btn(button: Button, pressed: bool, x: f64, y: f64, over: bool) -> RawEvent {
        RawEvent::Button {
            button,
            pressed,
            x,
            y,
            over_image: over,
        }
    }

    #[test]
    fn coalesce_only_adjacent_moves_before_click_barrier() {
        let mut state = ReducerState::default();
        // down at A, move to B, move to C, up at C must NOT become move(C),down(C).
        let out = reduce(
            &mut state,
            &[
                btn(Button::Left, true, 0.1, 0.1, true),
                move_to(0.2, 0.2, true),
                move_to(0.3, 0.3, true),
                btn(Button::Left, false, 0.3, 0.3, true),
            ],
        );
        assert_eq!(
            out,
            vec![
                OutEvent::Mouse {
                    action: "down",
                    button: "left",
                    x: 0.1,
                    y: 0.1,
                    dx: 0,
                    dy: 0,
                },
                OutEvent::Mouse {
                    action: "move",
                    button: "left",
                    x: 0.3,
                    y: 0.3,
                    dx: 0,
                    dy: 0,
                },
                OutEvent::Mouse {
                    action: "up",
                    button: "left",
                    x: 0.3,
                    y: 0.3,
                    dx: 0,
                    dy: 0,
                },
            ]
        );
    }

    #[test]
    fn move_before_later_click_does_not_rewrite_earlier_down() {
        let mut state = ReducerState::default();
        let out = reduce(
            &mut state,
            &[
                btn(Button::Right, true, 0.2, 0.4, true),
                move_to(0.9, 0.9, true),
                btn(Button::Right, false, 0.9, 0.9, true),
            ],
        );
        assert_eq!(out[0].mouse_xy(), Some((0.2, 0.4)));
        assert_eq!(
            out.iter().map(|e| e.action_button()).collect::<Vec<_>>(),
            vec![
                ("down", "right"),
                ("move", "left"),
                ("up", "right"),
            ]
        );
    }

    #[test]
    fn ctrl_and_shift_right_still_inject_over_image() {
        // Modifier state is orthogonal — RawEvent does not drop Ctrl/Shift right.
        let mut state = ReducerState::default();
        let out = reduce(
            &mut state,
            &[
                btn(Button::Right, true, 0.5, 0.5, true),
                btn(Button::Right, false, 0.5, 0.5, true),
            ],
        );
        assert_eq!(
            out.iter().map(|e| e.action_button()).collect::<Vec<_>>(),
            vec![("down", "right"), ("up", "right")]
        );
    }

    #[test]
    fn release_outside_image_still_ups_held_button() {
        let mut state = ReducerState::default();
        let _ = reduce(
            &mut state,
            &[btn(Button::Left, true, 0.4, 0.4, true)],
        );
        assert!(state.held.contains("left"));
        let out = reduce(
            &mut state,
            &[btn(Button::Left, false, 0.0, 0.0, false)],
        );
        assert_eq!(
            out,
            vec![OutEvent::Mouse {
                action: "up",
                button: "left",
                x: 0.0,
                y: 0.0,
                dx: 0,
                dy: 0,
            }]
        );
        assert!(state.held.is_empty());
    }

    #[test]
    fn letterbox_down_does_not_inject() {
        let mut state = ReducerState::default();
        let out = reduce(
            &mut state,
            &[btn(Button::Right, true, 0.1, 0.0, false)],
        );
        assert!(out.is_empty());
        assert!(state.held.is_empty());
    }

    #[test]
    fn key_is_barrier_and_preserves_cross_type_order() {
        let mut state = ReducerState::default();
        let out = reduce(
            &mut state,
            &[
                RawEvent::Key {
                    name: "shift".into(),
                    pressed: true,
                },
                btn(Button::Right, true, 0.5, 0.5, true),
                RawEvent::Key {
                    name: "shift".into(),
                    pressed: false,
                },
                btn(Button::Right, false, 0.5, 0.5, true),
            ],
        );
        assert_eq!(
            out,
            vec![
                OutEvent::Key {
                    name: "shift".into(),
                    pressed: true,
                },
                OutEvent::Mouse {
                    action: "down",
                    button: "right",
                    x: 0.5,
                    y: 0.5,
                    dx: 0,
                    dy: 0,
                },
                OutEvent::Key {
                    name: "shift".into(),
                    pressed: false,
                },
                OutEvent::Mouse {
                    action: "up",
                    button: "right",
                    x: 0.5,
                    y: 0.5,
                    dx: 0,
                    dy: 0,
                },
            ]
        );
    }

    #[test]
    fn double_click_is_two_down_up_pairs_not_extra_click() {
        // Production must not synthesize click(count=2) on top of down/up.
        let mut state = ReducerState::default();
        let out = reduce(
            &mut state,
            &[
                btn(Button::Left, true, 0.5, 0.5, true),
                btn(Button::Left, false, 0.5, 0.5, true),
                btn(Button::Left, true, 0.5, 0.5, true),
                btn(Button::Left, false, 0.5, 0.5, true),
            ],
        );
        let downs = out.iter().filter(|e| e.action_button() == ("down", "left")).count();
        let ups = out.iter().filter(|e| e.action_button() == ("up", "left")).count();
        let clicks = out.iter().filter(|e| matches!(e, OutEvent::Mouse { action: "click", .. })).count();
        assert_eq!(downs, 2);
        assert_eq!(ups, 2);
        assert_eq!(clicks, 0);
    }

    #[test]
    fn release_all_on_pointer_gone() {
        let mut state = ReducerState::default();
        let _ = reduce(
            &mut state,
            &[
                btn(Button::Left, true, 0.2, 0.3, true),
                btn(Button::Right, true, 0.2, 0.3, true),
            ],
        );
        let out = release_all(&mut state);
        assert_eq!(out.len(), 2);
        assert!(state.held.is_empty());
        assert!(out.iter().all(|e| matches!(
            e,
            OutEvent::Mouse {
                action: "up",
                ..
            }
        )));
    }

    #[test]
    fn wheel_and_middle_over_image() {
        let mut state = ReducerState::default();
        let out = reduce(
            &mut state,
            &[
                btn(Button::Middle, true, 0.4, 0.4, true),
                btn(Button::Middle, false, 0.4, 0.4, true),
                RawEvent::Wheel {
                    x: 0.4,
                    y: 0.4,
                    dx: 0,
                    dy: 1,
                    over_image: true,
                },
            ],
        );
        assert_eq!(
            out.iter().map(|e| e.action_button()).collect::<Vec<_>>(),
            vec![
                ("down", "middle"),
                ("up", "middle"),
                ("scroll", "left"),
            ]
        );
    }

    impl OutEvent {
        fn action_button(&self) -> (&str, &str) {
            match self {
                OutEvent::Mouse { action, button, .. } => (*action, *button),
                OutEvent::Key { .. } => ("key", ""),
                OutEvent::Text { .. } => ("text", ""),
            }
        }

        fn mouse_xy(&self) -> Option<(f64, f64)> {
            match self {
                OutEvent::Mouse { x, y, .. } => Some((*x, *y)),
                _ => None,
            }
        }
    }

    #[test]
    fn pointer_gone_in_stream_releases_before_next_down() {
        let mut state = ReducerState::default();
        let out = reduce(
            &mut state,
            &[
                btn(Button::Left, true, 0.2, 0.2, true),
                RawEvent::PointerGone,
                btn(Button::Left, true, 0.3, 0.3, true),
            ],
        );
        assert_eq!(
            out.iter().map(|e| e.action_button()).collect::<Vec<_>>(),
            vec![("down", "left"), ("up", "left"), ("down", "left")]
        );
    }

    #[test]
    fn text_barrier_stays_between_key_and_click() {
        let mut state = ReducerState::default();
        let out = reduce(
            &mut state,
            &[
                RawEvent::Key {
                    name: "a".into(),
                    pressed: true,
                },
                RawEvent::Text {
                    text: "中".into(),
                },
                btn(Button::Left, true, 0.5, 0.5, true),
            ],
        );
        assert!(matches!(out[1], OutEvent::Text { .. }));
        assert!(matches!(
            out[2],
            OutEvent::Mouse {
                action: "down",
                ..
            }
        ));
    }
}
