//! Windows Terminal–style tab strip math, shortcut routing, and vector icons.
//!
//! Keeps layout and keyboard shortcut rules pure so they can be unit-tested
//! without opening a window, and paints crisp vector icons via [`egui::Painter`]
//! because bundled Inter / JetBrains Mono lack color emoji glyphs.

use eframe::egui::{self, pos2, vec2, Color32, CornerRadius, Pos2, Rect, Stroke, StrokeKind};

use super::theme;

/// Unique identifier for a workspace tab.
pub type TabId = u64;

/// Pinned Machines tab ID (never closed).
pub const MACHINES_TAB_ID: TabId = 0;

/// Icon kind rendered inside a tab or quick-connect menu item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabIcon {
    Machines,
    Terminal,
    Desktop { control: bool },
    Files,
    Settings,
}

/// Optional live status indicator dot rendered on a tab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabDot {
    None,
    Connected,
    Connecting,
    Error,
    Inactive,
}

impl TabDot {
    pub fn color(self) -> Option<Color32> {
        match self {
            Self::None => None,
            Self::Connected => Some(theme::SUCCESS),
            Self::Connecting => Some(theme::WARN),
            Self::Error => Some(theme::DANGER),
            Self::Inactive => Some(theme::TEXT_FAINT),
        }
    }
}

/// Global Windows Terminal–style tab shortcuts handled at the window level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabShortcut {
    NewTab,
    CloseTab,
    NextTab,
    PrevTab,
    GoMachines,
    OpenSettings,
}

/// Compute each closable session tab's width and whether horizontal scrolling is needed.
pub fn compute_session_tab_width(avail_w: f32, count: usize) -> (f32, bool) {
    if count == 0 {
        return (0.0, false);
    }
    let avail = avail_w.max(0.0);
    let ideal = (avail / count as f32).clamp(theme::TAB_MIN_WIDTH, theme::TAB_MAX_WIDTH);
    let needs_scroll = (count as f32) * theme::TAB_MIN_WIDTH > avail + 0.5;
    (ideal, needs_scroll)
}

/// Detect a Windows Terminal–style global tab shortcut from frame input events.
///
/// Returns the first matching event's index and [`TabShortcut`] so callers can
/// strip that exact event before passing remaining keys to the terminal PTY.
/// Never matches `Alt` combinations so European AltGr remains untouched.
pub fn detect_tab_shortcut(events: &[egui::Event]) -> Option<(usize, TabShortcut)> {
    for (idx, event) in events.iter().enumerate() {
        let egui::Event::Key {
            key,
            pressed: true,
            modifiers,
            ..
        } = event
        else {
            continue;
        };
        if modifiers.alt {
            continue;
        }
        let ctrl_or_cmd = modifiers.ctrl || modifiers.command;
        if ctrl_or_cmd && matches!(key, egui::Key::Tab) {
            let shortcut = if modifiers.shift {
                TabShortcut::PrevTab
            } else {
                TabShortcut::NextTab
            };
            return Some((idx, shortcut));
        }
        if ((modifiers.ctrl && modifiers.shift)
            || (modifiers.mac_cmd && !modifiers.ctrl && !modifiers.shift))
            && matches!(key, egui::Key::T)
        {
            return Some((idx, TabShortcut::NewTab));
        }
        if ((modifiers.ctrl && modifiers.shift)
            || (modifiers.mac_cmd && !modifiers.ctrl && !modifiers.shift))
            && matches!(key, egui::Key::W)
        {
            return Some((idx, TabShortcut::CloseTab));
        }
        if modifiers.ctrl && modifiers.shift && matches!(key, egui::Key::M) {
            return Some((idx, TabShortcut::GoMachines));
        }
        if (modifiers.ctrl || modifiers.mac_cmd)
            && !modifiers.shift
            && matches!(key, egui::Key::Comma)
        {
            return Some((idx, TabShortcut::OpenSettings));
        }
    }
    None
}

/// Append a 1-based ordinal suffix only when multiple tabs share the same base title.
pub fn disambiguated_label(base: &str, ordinal: usize, total_same: usize) -> String {
    if total_same <= 1 {
        base.to_string()
    } else {
        format!("{base} ({ordinal})")
    }
}

/// Paint a crisp vector icon inside `rect` for a tab or menu row.
pub fn paint_tab_icon(painter: &egui::Painter, rect: Rect, icon: TabIcon, color: Color32) {
    let side = rect.width().min(rect.height()).max(8.0);
    let box_rect = Rect::from_center_size(rect.center(), vec2(side, side));
    let stroke = Stroke::new(1.35_f32, color);

    match icon {
        TabIcon::Machines => {
            let gap = (side * 0.16).max(1.5);
            let cell = ((side - gap) * 0.5).max(2.5);
            let r = CornerRadius::same(1);
            let tl = box_rect.min;
            let cells = [
                Rect::from_min_size(tl, vec2(cell, cell)),
                Rect::from_min_size(pos2(tl.x + cell + gap, tl.y), vec2(cell, cell)),
                Rect::from_min_size(pos2(tl.x, tl.y + cell + gap), vec2(cell, cell)),
                Rect::from_min_size(
                    pos2(tl.x + cell + gap, tl.y + cell + gap),
                    vec2(cell, cell),
                ),
            ];
            for c in cells {
                painter.rect_stroke(c, r, stroke, StrokeKind::Inside);
            }
        }
        TabIcon::Terminal => {
            // Crisp `>_` prompt glyph
            let l = box_rect.left() + side * 0.10;
            let cy = box_rect.center().y;
            let top = cy - side * 0.24;
            let bot = cy + side * 0.14;
            let mid_x = l + side * 0.30;
            let mid_y = (top + bot) * 0.5;
            painter.line_segment([pos2(l, top), pos2(mid_x, mid_y)], stroke);
            painter.line_segment([pos2(mid_x, mid_y), pos2(l, bot)], stroke);

            let bar_y = box_rect.bottom() - side * 0.16;
            let bar_l = mid_x + side * 0.12;
            let bar_r = box_rect.right() - side * 0.08;
            painter.line_segment([pos2(bar_l, bar_y), pos2(bar_r, bar_y)], stroke);
        }
        TabIcon::Desktop { control } => {
            // Monitor bezel + neck + base stand
            let bezel = Rect::from_min_max(
                pos2(box_rect.left() + side * 0.06, box_rect.top() + side * 0.10),
                pos2(
                    box_rect.right() - side * 0.06,
                    box_rect.bottom() - side * 0.30,
                ),
            );
            painter.rect_stroke(bezel, CornerRadius::same(2), stroke, StrokeKind::Inside);
            if control {
                let inner = bezel.shrink(2.5);
                if inner.width() > 2.0 && inner.height() > 2.0 {
                    painter.rect_filled(inner, CornerRadius::same(1), color.gamma_multiply(0.28));
                }
            }
            let cx = box_rect.center().x;
            let neck_top = bezel.bottom();
            let base_y = box_rect.bottom() - side * 0.12;
            painter.line_segment([pos2(cx, neck_top), pos2(cx, base_y)], stroke);
            painter.line_segment(
                [
                    pos2(cx - side * 0.24, base_y),
                    pos2(cx + side * 0.24, base_y),
                ],
                stroke,
            );
        }
        TabIcon::Files => {
            // Folder silhouette: top left tab + body outline
            let l = box_rect.left() + side * 0.06;
            let r = box_rect.right() - side * 0.06;
            let t = box_rect.top() + side * 0.16;
            let b = box_rect.bottom() - side * 0.14;
            let tab_r = l + (r - l) * 0.42;
            let shoulder_y = t + side * 0.15;
            let pts = [
                pos2(l, t),
                pos2(tab_r, t),
                pos2(tab_r + side * 0.08, shoulder_y),
                pos2(r, shoulder_y),
                pos2(r, b),
                pos2(l, b),
                pos2(l, t),
            ];
            for win in pts.windows(2) {
                painter.line_segment([win[0], win[1]], stroke);
            }
        }
        TabIcon::Settings => {
            // Three horizontal slider tracks with circular knobs
            let l = box_rect.left() + side * 0.08;
            let r = box_rect.right() - side * 0.08;
            let ys = [
                box_rect.top() + side * 0.22,
                box_rect.center().y,
                box_rect.bottom() - side * 0.22,
            ];
            let xs = [
                l + (r - l) * 0.30,
                l + (r - l) * 0.72,
                l + (r - l) * 0.42,
            ];
            for (y, kx) in ys.into_iter().zip(xs) {
                painter.line_segment([pos2(l, y), pos2(r, y)], stroke);
                painter.circle_filled(pos2(kx, y), 1.9, color);
            }
        }
    }
}

/// Paint a crisp `×` close glyph centered in `rect`.
pub fn paint_close_glyph(painter: &egui::Painter, rect: Rect, color: Color32) {
    let half = (rect.width().min(rect.height()) * 0.28).max(3.0);
    let c = rect.center();
    let stroke = Stroke::new(1.35_f32, color);
    painter.line_segment(
        [pos2(c.x - half, c.y - half), pos2(c.x + half, c.y + half)],
        stroke,
    );
    painter.line_segment(
        [pos2(c.x + half, c.y - half), pos2(c.x - half, c.y + half)],
        stroke,
    );
}

/// Paint a crisp `+` new-tab glyph centered in `rect`.
pub fn paint_plus_glyph(painter: &egui::Painter, rect: Rect, color: Color32) {
    let half = (rect.width().min(rect.height()) * 0.26).max(4.0);
    let c = rect.center();
    let stroke = Stroke::new(1.5_f32, color);
    painter.line_segment([pos2(c.x - half, c.y), pos2(c.x + half, c.y)], stroke);
    painter.line_segment([pos2(c.x, c.y - half), pos2(c.x, c.y + half)], stroke);
}

/// Paint a crisp downward V chevron centered in `rect`.
pub fn paint_chevron_down_glyph(painter: &egui::Painter, rect: Rect, color: Color32) {
    let w = (rect.width() * 0.22).max(3.2);
    let h = (rect.height() * 0.14).max(2.0);
    let c: Pos2 = rect.center();
    let stroke = Stroke::new(1.4_f32, color);
    painter.line_segment(
        [pos2(c.x - w, c.y - h * 0.5), pos2(c.x, c.y + h)],
        stroke,
    );
    painter.line_segment(
        [pos2(c.x, c.y + h), pos2(c.x + w, c.y - h * 0.5)],
        stroke,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_event(key: egui::Key, modifiers: egui::Modifiers) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers,
        }
    }

    #[test]
    fn session_tab_width_scales_clamps_and_scrolls_on_overflow() {
        assert_eq!(compute_session_tab_width(600.0, 0), (0.0, false));
        let (w1, s1) = compute_session_tab_width(600.0, 2);
        assert!((w1 - theme::TAB_MAX_WIDTH).abs() < 0.01);
        assert!(!s1);

        let (w2, s2) = compute_session_tab_width(500.0, 4);
        assert!((w2 - 125.0).abs() < 0.01);
        assert!(!s2);

        let (w3, s3) = compute_session_tab_width(400.0, 10);
        assert!((w3 - theme::TAB_MIN_WIDTH).abs() < 0.01);
        assert!(s3);
    }

    #[test]
    fn disambiguates_duplicate_labels_only_when_needed() {
        assert_eq!(disambiguated_label("quant67", 1, 1), "quant67");
        assert_eq!(disambiguated_label("quant67", 1, 2), "quant67 (1)");
        assert_eq!(disambiguated_label("quant67", 2, 2), "quant67 (2)");
    }

    #[test]
    fn detects_windows_terminal_tab_shortcuts_without_hijacking_terminal_chords() {
        let ctrl_shift = egui::Modifiers {
            ctrl: true,
            shift: true,
            command: true,
            ..Default::default()
        };
        let ctrl_only = egui::Modifiers {
            ctrl: true,
            command: true,
            ..Default::default()
        };
        let altgr = egui::Modifiers {
            ctrl: true,
            alt: true,
            shift: true,
            command: true,
            ..Default::default()
        };
        let mac_cmd = egui::Modifiers {
            command: true,
            mac_cmd: true,
            ..Default::default()
        };

        assert_eq!(
            detect_tab_shortcut(&[key_event(egui::Key::T, ctrl_shift)]),
            Some((0, TabShortcut::NewTab))
        );
        assert_eq!(
            detect_tab_shortcut(&[key_event(egui::Key::W, ctrl_shift)]),
            Some((0, TabShortcut::CloseTab))
        );
        assert_eq!(
            detect_tab_shortcut(&[key_event(egui::Key::M, ctrl_shift)]),
            Some((0, TabShortcut::GoMachines))
        );
        assert_eq!(
            detect_tab_shortcut(&[key_event(egui::Key::Tab, ctrl_only)]),
            Some((0, TabShortcut::NextTab))
        );
        assert_eq!(
            detect_tab_shortcut(&[key_event(egui::Key::Tab, ctrl_shift)]),
            Some((0, TabShortcut::PrevTab))
        );
        assert_eq!(
            detect_tab_shortcut(&[key_event(egui::Key::Comma, ctrl_only)]),
            Some((0, TabShortcut::OpenSettings))
        );
        assert_eq!(
            detect_tab_shortcut(&[key_event(egui::Key::T, mac_cmd)]),
            Some((0, TabShortcut::NewTab))
        );
        assert_eq!(
            detect_tab_shortcut(&[key_event(egui::Key::W, mac_cmd)]),
            Some((0, TabShortcut::CloseTab))
        );
        assert_eq!(
            detect_tab_shortcut(&[key_event(egui::Key::Comma, mac_cmd)]),
            Some((0, TabShortcut::OpenSettings))
        );

        // Plain terminal chords and AltGr combinations must NOT trigger tab shortcuts.
        assert_eq!(detect_tab_shortcut(&[key_event(egui::Key::C, ctrl_only)]), None);
        assert_eq!(detect_tab_shortcut(&[key_event(egui::Key::T, ctrl_only)]), None);
        assert_eq!(detect_tab_shortcut(&[key_event(egui::Key::W, ctrl_only)]), None);
        assert_eq!(detect_tab_shortcut(&[key_event(egui::Key::T, altgr)]), None);
    }
}
