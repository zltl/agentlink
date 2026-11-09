//! High-level pointer and keyboard actions, expanded into primitive events.

use std::thread;
use std::time::Duration;

use crate::error::{msg, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

impl MouseButton {
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "left" | "primary" | "1" => Ok(Self::Left),
            "right" | "secondary" | "2" => Ok(Self::Right),
            "middle" | "wheel" | "3" => Ok(Self::Middle),
            other => Err(msg(format!("unknown mouse button '{other}'"))),
        }
    }

    /// X11 XTest button number. Scroll is separate (buttons 4–7).
    pub fn xtest(self) -> u8 {
        match self {
            Self::Left => 1,
            Self::Middle => 2,
            Self::Right => 3,
        }
    }

    /// Linux evdev button code used by the RemoteDesktop portal.
    pub fn evdev(self) -> u32 {
        match self {
            Self::Left => 0x110,
            Self::Right => 0x111,
            Self::Middle => 0x112,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputAction {
    Move {
        x: i32,
        y: i32,
    },
    Click {
        x: i32,
        y: i32,
        button: MouseButton,
        count: u32,
    },
    Drag {
        x: i32,
        y: i32,
        to_x: i32,
        to_y: i32,
        button: MouseButton,
    },
    Scroll {
        /// When set with `y`, move here before scrolling. When both absent,
        /// scroll at the current pointer (do not teleport to 0,0).
        x: Option<i32>,
        y: Option<i32>,
        /// Horizontal scroll in **notches** (multiples of [`WHEEL_DELTA`]).
        dx: i32,
        /// Vertical scroll in **notches** (multiples of [`WHEEL_DELTA`]).
        dy: i32,
    },
    /// Press or release one button without the click helper's pause.
    Button {
        x: i32,
        y: i32,
        button: MouseButton,
        down: bool,
    },
    Type {
        text: String,
    },
    /// Modifiers first, then the key that is chorded with them.
    /// Each key is pressed and then released.
    Key {
        keys: Vec<String>,
    },
    /// One edge of a held key. `down` false releases without a second press.
    KeyEdge {
        keys: Vec<String>,
        down: bool,
    },
}

/// One Windows / USB HID wheel notch. Clients convert pixel `wheel` deltas
/// with `trunc(delta / WHEEL_DELTA)` (at least ±1); the node clamps to ±5.
pub const WHEEL_DELTA: i32 = 120;

/// Max notches accepted after normalization (about one chunky trackpad flick).
pub const SCROLL_NOTCH_LIMIT: i32 = 5;

/// Normalize a scroll axis to notches.
///
/// New clients send notches in `±1..=±5`. Legacy Android / web clients may
/// still send pixel `wheel` deltas (typically `|v| > 5`); those are converted
/// with ceil(|v|/120) away from zero, then clamped. Values inside ±5 pass
/// through as notches (including 0).
pub fn normalize_scroll_delta(raw: i32) -> i32 {
    let notches = if raw.abs() > SCROLL_NOTCH_LIMIT {
        // Legacy pixel delta → notches, rounding away from zero.
        let abs = raw.unsigned_abs().div_ceil(WHEEL_DELTA as u32).max(1) as i32;
        if raw < 0 {
            -abs
        } else {
            abs
        }
    } else {
        raw
    };
    notches.clamp(-SCROLL_NOTCH_LIMIT, SCROLL_NOTCH_LIMIT)
}

/// Client helper: convert a pixel wheel delta to notches.
///
/// `trunc(delta / 120)`, but never 0 when `delta != 0` (at least ±1).
/// Kept public so controller / tests share the same contract as the node.
#[allow(dead_code)]
pub fn pixel_delta_to_notches(delta: i32) -> i32 {
    if delta == 0 {
        return 0;
    }
    let n = delta / WHEEL_DELTA;
    if n == 0 {
        if delta > 0 {
            1
        } else {
            -1
        }
    } else {
        n
    }
}

/// Primitive events a platform backend has to implement.
///
/// [`perform`] expands clicks, drags, and chords so each OS file stays small.
pub trait Pointer {
    fn mouse_move(&mut self, x: i32, y: i32) -> Result<()>;
    fn mouse_button(&mut self, button: MouseButton, down: bool) -> Result<()>;
    /// `dx` / `dy` are scroll **notches** (see [`normalize_scroll_delta`]).
    fn scroll(&mut self, dx: i32, dy: i32) -> Result<()>;
    fn key_down(&mut self, key: &str) -> Result<()>;
    fn key_up(&mut self, key: &str) -> Result<()>;
    fn type_text(&mut self, text: &str) -> Result<()>;
}

pub fn perform(pointer: &mut dyn Pointer, action: &InputAction) -> Result<()> {
    match action {
        InputAction::Move { x, y } => pointer.mouse_move(*x, *y),
        InputAction::Click {
            x,
            y,
            button,
            count,
        } => {
            pointer.mouse_move(*x, *y)?;
            let count = (*count).clamp(1, 8);
            for _ in 0..count {
                pointer.mouse_button(*button, true)?;
                thread::sleep(Duration::from_millis(12));
                pointer.mouse_button(*button, false)?;
                thread::sleep(Duration::from_millis(12));
            }
            Ok(())
        }
        InputAction::Drag {
            x,
            y,
            to_x,
            to_y,
            button,
        } => {
            pointer.mouse_move(*x, *y)?;
            pointer.mouse_button(*button, true)?;
            let steps = 10;
            for step in 1..=steps {
                let t = step as f32 / steps as f32;
                let cx = *x + ((*to_x - *x) as f32 * t).round() as i32;
                let cy = *y + ((*to_y - *y) as f32 * t).round() as i32;
                pointer.mouse_move(cx, cy)?;
                thread::sleep(Duration::from_millis(8));
            }
            pointer.mouse_button(*button, false)?;
            Ok(())
        }
        InputAction::Button { x, y, button, down } => {
            pointer.mouse_move(*x, *y)?;
            pointer.mouse_button(*button, *down)
        }
        InputAction::Scroll { x, y, dx, dy } => {
            match (x, y) {
                (Some(x), Some(y)) => pointer.mouse_move(*x, *y)?,
                (None, None) => {}
                _ => return Err(msg("scroll needs both x and y, or neither")),
            }
            let dx = normalize_scroll_delta(*dx);
            let dy = normalize_scroll_delta(*dy);
            if dx == 0 && dy == 0 {
                return Err(msg("scroll needs a non-zero dx or dy"));
            }
            pointer.scroll(dx, dy)
        }
        InputAction::Type { text } => {
            if text.is_empty() {
                return Err(msg("type text is empty"));
            }
            if text.chars().count() > 8_000 {
                return Err(msg("type text is longer than 8000 characters"));
            }
            pointer.type_text(text)
        }
        InputAction::Key { keys } => {
            if keys.is_empty() {
                return Err(msg("key combo is empty"));
            }
            for key in keys {
                pointer.key_down(key)?;
            }
            thread::sleep(Duration::from_millis(12));
            for key in keys.iter().rev() {
                pointer.key_up(key)?;
            }
            Ok(())
        }
        InputAction::KeyEdge { keys, down } => {
            if keys.is_empty() {
                return Err(msg("key combo is empty"));
            }
            if *down {
                for key in keys {
                    pointer.key_down(key)?;
                }
            } else {
                for key in keys.iter().rev() {
                    pointer.key_up(key)?;
                }
            }
            Ok(())
        }
    }
}

/// What the node exposes to MCP and the CLI.
pub trait HidBackend: Send + Sync {
    fn backend_name(&self) -> &str;
    fn inject(&self, action: &InputAction) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_keeps_notches_inside_limit() {
        assert_eq!(normalize_scroll_delta(0), 0);
        assert_eq!(normalize_scroll_delta(1), 1);
        assert_eq!(normalize_scroll_delta(-3), -3);
        assert_eq!(normalize_scroll_delta(5), 5);
        assert_eq!(normalize_scroll_delta(-5), -5);
    }

    #[test]
    fn normalize_clamps_large_notches() {
        // |v| <= 5 is notches; values beyond the limit only appear after
        // legacy conversion, so a raw 5 stays 5.
        assert_eq!(normalize_scroll_delta(5), 5);
    }

    #[test]
    fn normalize_converts_legacy_pixels() {
        // Typical web wheel pixel deltas.
        assert_eq!(normalize_scroll_delta(100), 1);
        assert_eq!(normalize_scroll_delta(-100), -1);
        assert_eq!(normalize_scroll_delta(120), 1);
        assert_eq!(normalize_scroll_delta(121), 2);
        assert_eq!(normalize_scroll_delta(-240), -2);
        // Huge flick still caps at ±5.
        assert_eq!(normalize_scroll_delta(10_000), 5);
        assert_eq!(normalize_scroll_delta(-10_000), -5);
        // Just above the notch limit → treated as pixels.
        assert_eq!(normalize_scroll_delta(6), 1);
        assert_eq!(normalize_scroll_delta(-6), -1);
    }

    #[test]
    fn pixel_delta_to_notches_truncates_with_minimum() {
        assert_eq!(pixel_delta_to_notches(0), 0);
        assert_eq!(pixel_delta_to_notches(50), 1);
        assert_eq!(pixel_delta_to_notches(-50), -1);
        assert_eq!(pixel_delta_to_notches(120), 1);
        assert_eq!(pixel_delta_to_notches(240), 2);
        assert_eq!(pixel_delta_to_notches(-119), -1);
        assert_eq!(pixel_delta_to_notches(-240), -2);
    }

    struct Recording {
        scrolls: Vec<(i32, i32)>,
    }

    impl Pointer for Recording {
        fn mouse_move(&mut self, _: i32, _: i32) -> Result<()> {
            Ok(())
        }
        fn mouse_button(&mut self, _: MouseButton, _: bool) -> Result<()> {
            Ok(())
        }
        fn scroll(&mut self, dx: i32, dy: i32) -> Result<()> {
            self.scrolls.push((dx, dy));
            Ok(())
        }
        fn key_down(&mut self, _: &str) -> Result<()> {
            Ok(())
        }
        fn key_up(&mut self, _: &str) -> Result<()> {
            Ok(())
        }
        fn type_text(&mut self, _: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn perform_scroll_normalizes_before_dispatch() {
        let mut ptr = Recording { scrolls: vec![] };
        perform(
            &mut ptr,
            &InputAction::Scroll {
                x: None,
                y: None,
                dx: 0,
                dy: 100,
            },
        )
        .unwrap();
        assert_eq!(ptr.scrolls, vec![(0, 1)]);
    }
}
