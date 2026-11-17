//! STD-only egui→policy adapter for remote desktop input.
//!
//! Converts a raw frame of pointer/key/text events into an ordered
//! [`crate::controller::input_policy::RawEvent`] stream. No egui types so
//! `rustc --test` can prove modifier/wheel/PointerGone/text ordering without
//! a workspace build.
//!
//! Rules (executor review of e81044f UI adapter):
//! - Per-event modifier snapshots are barriers; never prepend FINAL-frame mods.
//! - Track evolving pointer while iterating; wheel uses that position.
//! - Never invent pane.center when no pointer sample exists.
//! - `Event::Text` stays in-order (barrier), not appended after the frame.
//! - `over_image` uses a pre-clipped content rect (content ∩ pane ∩ ui clip).
//! - `PointerGone` is an in-order release barrier (buttons only; not key-ups).
//! - Honor wheel unit; accumulate fractional deltas into notches.
//! - Ctrl/Command+wheel is local-zoom only for **that** event's modifiers.

#![allow(dead_code)]

use super::input_policy::{self, Button, OutEvent, RawEvent, ReducerState};

/// Modifier snapshot attached to a single pointer/key event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModSnapshot {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub command: bool,
}

/// Mouse wheel unit (mirrors egui without depending on it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WheelUnit {
    Point,
    Line,
    Page,
}

/// One raw UI event already in egui order, with pane-pixel coordinates.
#[derive(Clone, Debug, PartialEq)]
pub enum FrameEvent {
    PointerMoved {
        x: f32,
        y: f32,
    },
    PointerButton {
        x: f32,
        y: f32,
        button: Button,
        pressed: bool,
        mods: ModSnapshot,
    },
    MouseWheel {
        /// Optional event position; when absent, adapter uses evolving pointer.
        x: Option<f32>,
        y: Option<f32>,
        delta_x: f32,
        delta_y: f32,
        unit: WheelUnit,
        mods: ModSnapshot,
    },
    PointerGone,
    Key {
        name: String,
        pressed: bool,
        /// Local typematic repeat. Forwarded as another key-down, not a second press.
        repeat: bool,
        mods: ModSnapshot,
    },
    /// Non-ASCII typed text (IME / compose). Barrier in the same stream.
    Text {
        text: String,
    },
}

/// Visible content used for hit-tests (already clipped to pane ∩ ui clip).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ContentGeom {
    pub min_x: f32,
    pub min_y: f32,
    pub max_x: f32,
    pub max_y: f32,
}

impl ContentGeom {
    pub fn from_xywh(x: f32, y: f32, w: f32, h: f32) -> Self {
        Self {
            min_x: x,
            min_y: y,
            max_x: x + w.max(0.0),
            max_y: y + h.max(0.0),
        }
    }

    /// Intersect three axis-aligned rects (content, response pane, ui clip).
    pub fn intersect3(
        a: (f32, f32, f32, f32),
        b: (f32, f32, f32, f32),
        c: (f32, f32, f32, f32),
    ) -> Self {
        let min_x = a.0.max(b.0).max(c.0);
        let min_y = a.1.max(b.1).max(c.1);
        let max_x = a.2.min(b.2).min(c.2);
        let max_y = a.3.min(b.3).min(c.3);
        Self {
            min_x,
            min_y,
            max_x: max_x.max(min_x),
            max_y: max_y.max(min_y),
        }
    }

    pub fn hit_and_frac(&self, x: f32, y: f32) -> (f64, f64, bool) {
        let w = (self.max_x - self.min_x).max(1.0e-6);
        let h = (self.max_y - self.min_y).max(1.0e-6);
        let fx = ((x - self.min_x) / w).clamp(0.0, 1.0) as f64;
        let fy = ((y - self.min_y) / h).clamp(0.0, 1.0) as f64;
        let over = self.max_x > self.min_x
            && self.max_y > self.min_y
            && x >= self.min_x
            && x < self.max_x
            && y >= self.min_y
            && y < self.max_y;
        (fx, fy, over)
    }
}

/// Sticky adapter state across frames.
#[derive(Clone, Debug, Default)]
pub struct AdapterState {
    pub mods: ModSnapshot,
    /// Last known pointer in pane pixels (seeded from previous frame).
    pub pointer: Option<(f32, f32)>,
    pub wheel_acc_x: f32,
    pub wheel_acc_y: f32,
    pub reducer: ReducerState,
}

const WHEEL_DELTA: f32 = 120.0;
const LINE_PIXELS: f32 = 40.0;
const PAGE_PIXELS: f32 = 800.0;

fn wheel_pixels(delta_x: f32, delta_y: f32, unit: WheelUnit) -> (f32, f32) {
    match unit {
        WheelUnit::Point => (delta_x, delta_y),
        WheelUnit::Line => (delta_x * LINE_PIXELS, delta_y * LINE_PIXELS),
        WheelUnit::Page => (delta_x * PAGE_PIXELS, delta_y * PAGE_PIXELS),
    }
}

/// Convert accumulated pixel deltas into whole notches; leave remainder.
pub fn drain_wheel_notches(acc: &mut f32) -> i32 {
    if acc.abs() < 1.0e-6 {
        *acc = 0.0;
        return 0;
    }
    let notches = (*acc / WHEEL_DELTA).trunc() as i32;
    if notches != 0 {
        *acc -= notches as f32 * WHEEL_DELTA;
    }
    // Tiny leftover still counts as one notch once it crosses half a step
    // toward the next notch — keep remainder for the next event instead of
    // rounding away sub-120 deltas permanently.
    notches
}

fn emit_mod_delta(state: &mut AdapterState, next: ModSnapshot, raw: &mut Vec<RawEvent>) {
    let prev = state.mods;
    for (name, was, now) in [
        ("ctrl", prev.ctrl, next.ctrl),
        ("alt", prev.alt, next.alt),
        ("shift", prev.shift, next.shift),
        ("meta", prev.command, next.command),
    ] {
        if was != now {
            raw.push(RawEvent::Key {
                name: name.to_string(),
                pressed: now,
                repeat: false,
            });
        }
    }
    state.mods = next;
}

/// Adapt one frame of UI events into inject outputs (ordered).
///
/// `final_mods` is reconciled **after** the raw stream so leftover modifier
/// edges still emit, without rewriting earlier clicks.
pub fn adapt_frame(
    state: &mut AdapterState,
    content: ContentGeom,
    events: &[FrameEvent],
    final_mods: Option<ModSnapshot>,
    capture_keys: bool,
) -> Vec<OutEvent> {
    let mut raw: Vec<RawEvent> = Vec::new();

    for ev in events {
        match ev {
            FrameEvent::PointerMoved { x, y } => {
                state.pointer = Some((*x, *y));
                let (fx, fy, over) = content.hit_and_frac(*x, *y);
                // Outside clip: still track clamped drag when a button is held.
                if over || !state.reducer.held.is_empty() {
                    raw.push(RawEvent::Move {
                        x: fx,
                        y: fy,
                        over_image: over || !state.reducer.held.is_empty(),
                    });
                }
            }
            FrameEvent::PointerButton {
                x,
                y,
                button,
                pressed,
                mods,
            } => {
                emit_mod_delta(state, *mods, &mut raw);
                state.pointer = Some((*x, *y));
                let (fx, fy, over) = content.hit_and_frac(*x, *y);
                raw.push(RawEvent::Button {
                    button: *button,
                    pressed: *pressed,
                    x: fx,
                    y: fy,
                    over_image: over,
                });
            }
            FrameEvent::MouseWheel {
                x,
                y,
                delta_x,
                delta_y,
                unit,
                mods,
            } => {
                // Local zoom only when **this** event carries Ctrl/Command.
                if mods.ctrl || mods.command {
                    continue;
                }
                emit_mod_delta(state, *mods, &mut raw);
                let pos = match (x, y, state.pointer) {
                    (Some(px), Some(py), _) => {
                        state.pointer = Some((*px, *py));
                        Some((*px, *py))
                    }
                    (_, _, Some(p)) => Some(p),
                    _ => None,
                };
                let Some((px, py)) = pos else {
                    // No pointer sample — do not invent pane.center.
                    continue;
                };
                let (fx, fy, over) = content.hit_and_frac(px, py);
                if !over && state.reducer.held.is_empty() {
                    continue;
                }
                let (px_d, py_d) = wheel_pixels(*delta_x, *delta_y, *unit);
                // egui: positive y is scroll down in some paths; invert for
                // remote "away from user" notches like the prior adapter.
                state.wheel_acc_x += px_d;
                state.wheel_acc_y += -py_d;
                let dx = drain_wheel_notches(&mut state.wheel_acc_x);
                let dy = drain_wheel_notches(&mut state.wheel_acc_y);
                if dx != 0 || dy != 0 {
                    raw.push(RawEvent::Wheel {
                        x: fx,
                        y: fy,
                        dx,
                        dy,
                        over_image: over || !state.reducer.held.is_empty(),
                    });
                }
            }
            FrameEvent::PointerGone => {
                raw.push(RawEvent::PointerGone);
                state.pointer = None;
            }
            FrameEvent::Key {
                name,
                pressed,
                repeat,
                mods,
            } => {
                if !capture_keys {
                    continue;
                }
                // Escape is a remote key. Capture is released by the toolbar,
                // focus loss, disconnect, grant revoke, or exit — not by Esc.
                emit_mod_delta(state, *mods, &mut raw);
                raw.push(RawEvent::Key {
                    name: name.clone(),
                    pressed: *pressed,
                    repeat: *repeat,
                });
            }
            FrameEvent::Text { text } => {
                if capture_keys && !text.is_empty() {
                    raw.push(RawEvent::Text { text: text.clone() });
                }
            }
        }
    }

    if let Some(final_mods) = final_mods {
        if capture_keys {
            emit_mod_delta(state, final_mods, &mut raw);
        } else {
            state.mods = final_mods;
        }
    }

    input_policy::reduce(&mut state.reducer, &raw)
}

/// Whether an outgoing inject event is a barrier (must not route-switch).
pub fn is_barrier_out(ev: &OutEvent) -> bool {
    match ev {
        OutEvent::Mouse { action, .. } => *action != "move",
        OutEvent::Key { .. } | OutEvent::Text { .. } => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geom() -> ContentGeom {
        ContentGeom::from_xywh(10.0, 10.0, 100.0, 100.0)
    }

    #[test]
    fn shift_down_right_shift_up_uses_per_event_mods_not_final() {
        let mut state = AdapterState::default();
        // Same frame: Shift down (via button mods), right down/up, then final
        // mods all false. Must emit shift edges around the click from per-event
        // snapshots — not from a final-frame prepend.
        let out = adapt_frame(
            &mut state,
            geom(),
            &[
                FrameEvent::PointerButton {
                    x: 50.0,
                    y: 50.0,
                    button: Button::Right,
                    pressed: true,
                    mods: ModSnapshot {
                        shift: true,
                        ..ModSnapshot::default()
                    },
                },
                FrameEvent::PointerButton {
                    x: 50.0,
                    y: 50.0,
                    button: Button::Right,
                    pressed: false,
                    mods: ModSnapshot {
                        shift: true,
                        ..ModSnapshot::default()
                    },
                },
            ],
            Some(ModSnapshot::default()),
            true,
        );
        let names: Vec<_> = out
            .iter()
            .map(|e| match e {
                OutEvent::Key { name, pressed, .. } => {
                    format!("{}:{}", name, if *pressed { "down" } else { "up" })
                }
                OutEvent::Mouse { action, button, .. } => format!("{action}:{button}"),
                OutEvent::Text { .. } => "text".into(),
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "shift:down".to_string(),
                "down:right".to_string(),
                "up:right".to_string(),
                "shift:up".to_string(),
            ]
        );
    }

    #[test]
    fn wheel_uses_evolving_pointer_not_final_hover() {
        let mut state = AdapterState::default();
        let out = adapt_frame(
            &mut state,
            geom(),
            &[
                FrameEvent::PointerMoved { x: 20.0, y: 20.0 }, // A → frac 0.1
                FrameEvent::MouseWheel {
                    x: None,
                    y: None,
                    delta_x: 0.0,
                    delta_y: -120.0, // one notch up after invert
                    unit: WheelUnit::Point,
                    mods: ModSnapshot::default(),
                },
                FrameEvent::PointerMoved { x: 90.0, y: 90.0 }, // B
            ],
            None,
            false,
        );
        let scroll = out
            .iter()
            .find_map(|e| match e {
                OutEvent::Mouse {
                    action: "scroll",
                    x,
                    y,
                    ..
                } => Some((*x, *y)),
                _ => None,
            })
            .expect("scroll");
        assert!((scroll.0 - 0.1).abs() < 1e-6, "wheel at A, got {scroll:?}");
        assert!((scroll.1 - 0.1).abs() < 1e-6, "wheel at A, got {scroll:?}");
    }

    #[test]
    fn wheel_without_pointer_is_skipped_not_pane_center() {
        let mut state = AdapterState::default();
        let out = adapt_frame(
            &mut state,
            geom(),
            &[FrameEvent::MouseWheel {
                x: None,
                y: None,
                delta_x: 0.0,
                delta_y: -240.0,
                unit: WheelUnit::Point,
                mods: ModSnapshot::default(),
            }],
            None,
            false,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn text_is_in_order_barrier_not_appended_late() {
        let mut state = AdapterState::default();
        let out = adapt_frame(
            &mut state,
            geom(),
            &[
                FrameEvent::Key {
                    name: "a".into(),
                    pressed: true,
                    repeat: false,
                    mods: ModSnapshot::default(),
                },
                FrameEvent::Text {
                    text: "你".into(),
                },
                FrameEvent::PointerButton {
                    x: 50.0,
                    y: 50.0,
                    button: Button::Left,
                    pressed: true,
                    mods: ModSnapshot::default(),
                },
            ],
            None,
            true,
        );
        assert!(matches!(out[0], OutEvent::Key { .. }));
        assert!(matches!(&out[1], OutEvent::Text { text } if text == "你"));
        assert!(matches!(
            &out[2],
            OutEvent::Mouse {
                action: "down",
                ..
            }
        ));
    }

    #[test]
    fn pointer_gone_in_order_between_downs() {
        let mut state = AdapterState::default();
        let out = adapt_frame(
            &mut state,
            geom(),
            &[
                FrameEvent::PointerButton {
                    x: 50.0,
                    y: 50.0,
                    button: Button::Left,
                    pressed: true,
                    mods: ModSnapshot::default(),
                },
                FrameEvent::PointerGone,
                FrameEvent::PointerButton {
                    x: 50.0,
                    y: 50.0,
                    button: Button::Left,
                    pressed: true,
                    mods: ModSnapshot::default(),
                },
            ],
            None,
            false,
        );
        let seq: Vec<_> = out
            .iter()
            .map(|e| match e {
                OutEvent::Mouse { action, .. } => *action,
                _ => "?",
            })
            .collect();
        assert_eq!(seq, vec!["down", "up", "down"]);
    }

    #[test]
    fn pointer_gone_does_not_invent_key_ups() {
        let mut state = AdapterState::default();
        let _ = adapt_frame(
            &mut state,
            geom(),
            &[FrameEvent::Key {
                name: "shift".into(),
                pressed: true,
                repeat: false,
                mods: ModSnapshot {
                    shift: true,
                    ..ModSnapshot::default()
                },
            }],
            None,
            true,
        );
        let out = adapt_frame(
            &mut state,
            geom(),
            &[FrameEvent::PointerGone],
            None,
            true,
        );
        assert!(
            out.iter().all(|e| !matches!(e, OutEvent::Key { .. })),
            "PointerGone must not synthesize key-ups: {out:?}"
        );
    }

    #[test]
    fn toolbar_outside_clip_blocks_down() {
        // Content extends under toolbar; clip excludes toolbar band y<20.
        let content = ContentGeom::intersect3(
            (0.0, 0.0, 200.0, 200.0),
            (0.0, 0.0, 200.0, 200.0),
            (0.0, 20.0, 200.0, 200.0),
        );
        let mut state = AdapterState::default();
        let out = adapt_frame(
            &mut state,
            content,
            &[FrameEvent::PointerButton {
                x: 50.0,
                y: 10.0, // in toolbar / outside clip
                button: Button::Right,
                pressed: true,
                mods: ModSnapshot::default(),
            }],
            None,
            false,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn event_ctrl_false_does_not_drop_wheel_when_final_ctrl_true() {
        let mut state = AdapterState::default();
        state.pointer = Some((50.0, 50.0));
        let out = adapt_frame(
            &mut state,
            geom(),
            &[FrameEvent::MouseWheel {
                x: None,
                y: None,
                delta_x: 0.0,
                delta_y: -120.0,
                unit: WheelUnit::Point,
                mods: ModSnapshot::default(), // event itself not ctrl
            }],
            Some(ModSnapshot {
                ctrl: true,
                ..ModSnapshot::default()
            }),
            false,
        );
        assert!(
            out.iter().any(|e| matches!(
                e,
                OutEvent::Mouse {
                    action: "scroll",
                    ..
                }
            )),
            "final-frame Ctrl must not erase a non-ctrl wheel: {out:?}"
        );
    }

    #[test]
    fn tiny_fractional_wheel_accumulates() {
        let mut state = AdapterState::default();
        state.pointer = Some((50.0, 50.0));
        let mut saw = 0i32;
        for _ in 0..3 {
            let out = adapt_frame(
                &mut state,
                geom(),
                &[FrameEvent::MouseWheel {
                    x: None,
                    y: None,
                    delta_x: 0.0,
                    delta_y: -50.0, // 50 px; need ~2.4 events for one notch
                    unit: WheelUnit::Point,
                    mods: ModSnapshot::default(),
                }],
                None,
                false,
            );
            for e in out {
                if let OutEvent::Mouse {
                    action: "scroll",
                    dy,
                    ..
                } = e
                {
                    saw += dy;
                }
            }
        }
        assert!(saw >= 1, "accumulated notches={saw}");
    }

    #[test]
    fn held_drag_outside_clip_still_moves_and_releases() {
        let content = ContentGeom::from_xywh(10.0, 10.0, 100.0, 100.0);
        let mut state = AdapterState::default();
        let _ = adapt_frame(
            &mut state,
            content,
            &[FrameEvent::PointerButton {
                x: 50.0,
                y: 50.0,
                button: Button::Left,
                pressed: true,
                mods: ModSnapshot::default(),
            }],
            None,
            false,
        );
        let out = adapt_frame(
            &mut state,
            content,
            &[
                FrameEvent::PointerMoved { x: 5.0, y: 5.0 }, // outside
                FrameEvent::PointerButton {
                    x: 5.0,
                    y: 5.0,
                    button: Button::Left,
                    pressed: false,
                    mods: ModSnapshot::default(),
                },
            ],
            None,
            false,
        );
        assert!(out.iter().any(|e| matches!(
            e,
            OutEvent::Mouse {
                action: "move",
                ..
            }
        )));
        assert!(out.iter().any(|e| matches!(
            e,
            OutEvent::Mouse {
                action: "up",
                ..
            }
        )));
    }
}
