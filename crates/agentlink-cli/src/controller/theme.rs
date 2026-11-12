//! Linear-style dark design tokens for the controller window.
//!
//! This module is the **only** color / type / spacing source for egui UI code.
//! Pages must reference `theme::…` instead of hardcoding `Color32::from_rgb`.

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Shadow, Stroke,
    Style, TextStyle, Visuals,
};

/// Shared Linear dark palette + layout metrics.
#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub bg_page: Color32,
    pub bg_panel: Color32,
    pub bg_surface: Color32,
    pub bg_hover: Color32,
    pub text_primary: Color32,
    pub text_body: Color32,
    pub text_muted: Color32,
    pub text_faint: Color32,
    pub accent: Color32,
    pub accent_hover: Color32,
    pub accent_bg: Color32,
    pub success: Color32,
    pub warn: Color32,
    pub danger: Color32,
    pub border: Color32,
    pub border_subtle: Color32,
    pub overlay: Color32,
    pub overlay_strong: Color32,
    pub shadow: Color32,
    pub radius_control: u8,
    pub radius_card: u8,
    pub radius_panel: u8,
    pub space_xs: f32,
    pub space_sm: f32,
    pub space_md: f32,
    pub space_lg: f32,
    pub space_xl: f32,
    pub space_2xl: f32,
    pub btn_toolbar_h: f32,
    pub btn_primary_h: f32,
    pub btn_pad_x: f32,
    pub bar_height: f32,
    pub status_dot: f32,
    pub title_size: f32,
    pub section_size: f32,
    pub body_size: f32,
    pub secondary_size: f32,
    pub bar_size: f32,
    pub mono_size: f32,
    pub pill_size: f32,
}

impl Theme {
    pub const fn linear_dark() -> Self {
        Self {
            bg_page: BG_PAGE,
            bg_panel: BG_PANEL,
            bg_surface: BG_SURFACE,
            bg_hover: BG_HOVER,
            text_primary: TEXT_PRIMARY,
            text_body: TEXT_BODY,
            text_muted: TEXT_MUTED,
            text_faint: TEXT_FAINT,
            accent: ACCENT,
            accent_hover: ACCENT_HOVER,
            accent_bg: ACCENT_BG,
            success: SUCCESS,
            warn: WARN,
            danger: DANGER,
            border: BORDER,
            border_subtle: BORDER_SUBTLE,
            overlay: OVERLAY,
            overlay_strong: OVERLAY_STRONG,
            shadow: SHADOW,
            radius_control: RADIUS_CONTROL,
            radius_card: RADIUS_CARD,
            radius_panel: RADIUS_PANEL,
            space_xs: SPACE_XS,
            space_sm: SPACE_SM,
            space_md: SPACE_MD,
            space_lg: SPACE_LG,
            space_xl: SPACE_XL,
            space_2xl: SPACE_2XL,
            btn_toolbar_h: BTN_TOOLBAR_H,
            btn_primary_h: BTN_PRIMARY_H,
            btn_pad_x: BTN_PAD_X,
            bar_height: BAR_HEIGHT,
            status_dot: STATUS_DOT,
            title_size: TITLE_SIZE,
            section_size: SECTION_SIZE,
            body_size: BODY_SIZE,
            secondary_size: SECONDARY_SIZE,
            bar_size: BAR_SIZE,
            mono_size: MONO_SIZE,
            pill_size: PILL_SIZE,
        }
    }
}

pub const THEME: Theme = Theme::linear_dark();

// —— Colors (single source) ————————————————————————————————————————————————

pub const BG_PAGE: Color32 = Color32::from_rgb(0x08, 0x09, 0x0a);
pub const BG_PANEL: Color32 = Color32::from_rgb(0x0f, 0x10, 0x11);
pub const BG_SURFACE: Color32 = Color32::from_rgb(0x19, 0x1a, 0x1b);
pub const BG_HOVER: Color32 = Color32::from_rgb(0x28, 0x28, 0x2c);

pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(0xf7, 0xf8, 0xf8);
pub const TEXT_BODY: Color32 = Color32::from_rgb(0xd0, 0xd6, 0xe0);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x8a, 0x8f, 0x98);
pub const TEXT_FAINT: Color32 = Color32::from_rgb(0x62, 0x66, 0x6d);

pub const ACCENT: Color32 = Color32::from_rgb(0x71, 0x70, 0xff);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0x82, 0x8f, 0xff);
pub const ACCENT_BG: Color32 = Color32::from_rgb(0x5e, 0x6a, 0xd2);

pub const SUCCESS: Color32 = Color32::from_rgb(0x27, 0xa6, 0x44);
pub const WARN: Color32 = Color32::from_rgb(0xf5, 0xa6, 0x23);
pub const DANGER: Color32 = Color32::from_rgb(0xe5, 0x48, 0x4d);

/// `rgba(255,255,255,0.08)` → alpha 20 (premultiplied).
pub const BORDER: Color32 = Color32::from_rgba_premultiplied(20, 20, 20, 20);
/// `rgba(255,255,255,0.05)` → alpha 13 (premultiplied).
pub const BORDER_SUBTLE: Color32 = Color32::from_rgba_premultiplied(13, 13, 13, 13);

/// Dark scrim over the remote canvas.
pub const OVERLAY: Color32 = Color32::from_rgba_premultiplied(5, 6, 7, 170);
pub const OVERLAY_STRONG: Color32 = Color32::from_rgba_premultiplied(7, 8, 9, 220);
pub const TEXT_ON_ACCENT: Color32 = Color32::from_rgb(0xf7, 0xf8, 0xf8);
pub const WATERMARK: Color32 = Color32::from_rgba_premultiplied(114, 117, 123, 140);
pub const WATERMARK_STRONG: Color32 = Color32::from_rgba_premultiplied(180, 185, 194, 220);
pub const SHADOW: Color32 = Color32::from_black_alpha(120);

/// Danger / notice soft fills (tinted surfaces, still tokenized).
pub const DANGER_SOFT: Color32 = Color32::from_rgba_premultiplied(32, 10, 11, 36);
pub const SUCCESS_SOFT: Color32 = Color32::from_rgba_premultiplied(6, 23, 10, 36);
pub const ACCENT_SOFT: Color32 = Color32::from_rgba_premultiplied(28, 28, 63, 40);

// RGB tuples for egui-free chrome math / ConnDot.
pub const RGB_BG_PAGE: (u8, u8, u8) = (0x08, 0x09, 0x0a);
pub const RGB_BG_PANEL: (u8, u8, u8) = (0x0f, 0x10, 0x11);
pub const RGB_BG_SURFACE: (u8, u8, u8) = (0x19, 0x1a, 0x1b);
pub const RGB_BG_HOVER: (u8, u8, u8) = (0x28, 0x28, 0x2c);
pub const RGB_TEXT_PRIMARY: (u8, u8, u8) = (0xf7, 0xf8, 0xf8);
pub const RGB_TEXT_BODY: (u8, u8, u8) = (0xd0, 0xd6, 0xe0);
pub const RGB_TEXT_MUTED: (u8, u8, u8) = (0x8a, 0x8f, 0x98);
pub const RGB_ACCENT: (u8, u8, u8) = (0x71, 0x70, 0xff);
pub const RGB_SUCCESS: (u8, u8, u8) = (0x27, 0xa6, 0x44);
pub const RGB_WARN: (u8, u8, u8) = (0xf5, 0xa6, 0x23);
pub const RGB_DANGER: (u8, u8, u8) = (0xe5, 0x48, 0x4d);

// —— Shape / spacing (8px grid) ————————————————————————————————————————————

pub const RADIUS_CONTROL: u8 = 6;
pub const RADIUS_CARD: u8 = 8;
pub const RADIUS_PANEL: u8 = 12;

pub const SPACE_XS: f32 = 4.0;
pub const SPACE_SM: f32 = 8.0;
pub const SPACE_MD: f32 = 12.0;
pub const SPACE_LG: f32 = 16.0;
pub const SPACE_XL: f32 = 24.0;
pub const SPACE_2XL: f32 = 32.0;

pub const BTN_TOOLBAR_H: f32 = 28.0;
pub const BTN_PRIMARY_H: f32 = 36.0;
pub const BTN_PAD_X: f32 = 12.0;
pub const BAR_HEIGHT: f32 = 30.0;
pub const STATUS_DOT: f32 = 6.0;
pub const ICON_BTN: f32 = 28.0;

// —— Type ————————————————————————————————————————————————————————————————

pub const TITLE_SIZE: f32 = 20.0;
pub const SECTION_SIZE: f32 = 15.0;
pub const BODY_SIZE: f32 = 14.0;
pub const SECONDARY_SIZE: f32 = 13.0;
pub const BAR_SIZE: f32 = 12.0;
pub const MONO_SIZE: f32 = 13.0;
pub const PILL_SIZE: f32 = 10.0;

pub const WEIGHT_REGULAR: f32 = 400.0;
pub const WEIGHT_EMPHASIS: f32 = 510.0;
pub const WEIGHT_TITLE: f32 = 590.0;

pub fn popup_shadow() -> Shadow {
    Shadow {
        offset: [0, 4],
        blur: 16,
        spread: 0,
        color: SHADOW,
    }
}

pub fn stroke_border() -> Stroke {
    Stroke::new(1.0_f32, BORDER)
}

pub fn stroke_border_subtle() -> Stroke {
    Stroke::new(1.0_f32, BORDER_SUBTLE)
}

pub fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(BG_SURFACE)
        .stroke(stroke_border_subtle())
        .inner_margin(egui::Margin::same(SPACE_MD as i8))
        .corner_radius(CornerRadius::same(RADIUS_CARD))
}

pub fn panel_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(BG_SURFACE)
        .stroke(stroke_border())
        .shadow(popup_shadow())
        .inner_margin(egui::Margin::same(SPACE_MD as i8))
        .corner_radius(CornerRadius::same(RADIUS_PANEL))
}

pub fn title_text(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text)
        .size(TITLE_SIZE)
        .color(TEXT_PRIMARY)
        .extra_letter_spacing(-0.2)
}

pub fn section_text(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text)
        .size(SECTION_SIZE)
        .color(TEXT_PRIMARY)
}

pub fn body_text(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).size(BODY_SIZE).color(TEXT_BODY)
}

pub fn muted_text(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text)
        .size(SECONDARY_SIZE)
        .color(TEXT_MUTED)
}

pub fn bar_text(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).size(BAR_SIZE).color(TEXT_BODY)
}

pub fn mono_text(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text)
        .size(MONO_SIZE)
        .monospace()
        .color(TEXT_MUTED)
}

pub fn mono_bar_text(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text)
        .size(BAR_SIZE)
        .monospace()
        .color(TEXT_MUTED)
}

/// Apply fonts + dark visuals. Safe if font bytes are missing at compile time
/// (we ship TTFs under `assets/`; `include_bytes!` embeds them).
pub fn apply(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.style_mut(|style| {
        *style = styled(style);
    });
}

/// Honor the platform scale (Windows 150% stays 1.5). Never force a 2/3
/// shrink: if the backend reports a sub-100% `native_pixels_per_point`,
/// pin the UI at 1.0 so 14–16 pt body text stays physically readable.
///
/// Takes effect on the next egui pass. Do not call this from layout
/// tests that inject an explicit sub-1.0 scale.
pub fn apply_platform_zoom(ctx: &egui::Context) {
    let native = ctx.native_pixels_per_point().unwrap_or(1.0);
    if native > 0.0 && native < 1.0 {
        ctx.set_pixels_per_point(1.0);
    }
}

pub fn focus_stroke() -> Stroke {
    Stroke::new(2.0_f32, ACCENT)
}

fn styled(base: &Style) -> Style {
    let mut style = base.clone();
    style.spacing.interact_size = egui::vec2(BTN_PAD_X * 2.0, BTN_TOOLBAR_H);
    style.spacing.button_padding = egui::vec2(BTN_PAD_X, SPACE_XS);
    style.spacing.item_spacing = egui::vec2(SPACE_SM, SPACE_SM);
    style.spacing.window_margin = egui::Margin::same(SPACE_LG as i8);
    style.spacing.menu_margin = egui::Margin::same(SPACE_XS as i8);

    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(TITLE_SIZE, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Body,
        FontId::new(BODY_SIZE, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(BODY_SIZE, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(SECONDARY_SIZE, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(MONO_SIZE, FontFamily::Monospace),
    );

    let mut visuals = Visuals::dark();
    visuals.dark_mode = true;
    visuals.override_text_color = Some(TEXT_BODY);
    visuals.panel_fill = BG_PAGE;
    visuals.window_fill = BG_SURFACE;
    visuals.extreme_bg_color = BG_PAGE;
    visuals.faint_bg_color = BG_PANEL;
    visuals.code_bg_color = BG_SURFACE;
    visuals.window_stroke = stroke_border();
    visuals.window_corner_radius = CornerRadius::same(RADIUS_PANEL);
    visuals.menu_corner_radius = CornerRadius::same(RADIUS_PANEL);
    visuals.popup_shadow = popup_shadow();
    visuals.window_shadow = popup_shadow();
    visuals.selection.bg_fill = ACCENT_BG;
    visuals.selection.stroke = Stroke::new(2.0_f32, ACCENT);
    visuals.hyperlink_color = ACCENT;
    visuals.warn_fg_color = WARN;
    visuals.error_fg_color = DANGER;

    let r = CornerRadius::same(RADIUS_CONTROL);
    visuals.widgets.noninteractive.bg_fill = BG_PANEL;
    visuals.widgets.noninteractive.weak_bg_fill = BG_PAGE;
    visuals.widgets.noninteractive.bg_stroke = stroke_border_subtle();
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_BODY);
    visuals.widgets.noninteractive.corner_radius = r;

    visuals.widgets.inactive.bg_fill = BG_SURFACE;
    visuals.widgets.inactive.weak_bg_fill = BG_SURFACE;
    visuals.widgets.inactive.bg_stroke = Stroke::NONE;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT_BODY);
    visuals.widgets.inactive.corner_radius = r;

    visuals.widgets.hovered.bg_fill = BG_HOVER;
    visuals.widgets.hovered.weak_bg_fill = BG_HOVER;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
    visuals.widgets.hovered.corner_radius = r;

    visuals.widgets.active.bg_fill = ACCENT_BG;
    visuals.widgets.active.weak_bg_fill = ACCENT_BG;
    visuals.widgets.active.bg_stroke = Stroke::new(2.0_f32, ACCENT);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, TEXT_ON_ACCENT);
    visuals.widgets.active.corner_radius = r;

    visuals.widgets.open.bg_fill = BG_HOVER;
    visuals.widgets.open.weak_bg_fill = BG_HOVER;
    visuals.widgets.open.bg_stroke = stroke_border();
    visuals.widgets.open.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
    visuals.widgets.open.corner_radius = r;

    style.visuals = visuals;
    style
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    // Inter (OFL) — Regular / Medium / SemiBold. Missing files would fail at
    // compile time via include_bytes!; they ship under crates/agentlink-cli/assets/.
    let regular = include_bytes!("../../assets/Inter-Regular.ttf");
    let medium = include_bytes!("../../assets/Inter-Medium.ttf");
    let semibold = include_bytes!("../../assets/Inter-SemiBold.ttf");
    let mono = include_bytes!("../../assets/JetBrainsMono-Regular.ttf");

    fonts.font_data.insert(
        "Inter".into(),
        std::sync::Arc::new(FontData::from_static(regular)),
    );
    fonts.font_data.insert(
        "InterMedium".into(),
        std::sync::Arc::new(FontData::from_static(medium)),
    );
    fonts.font_data.insert(
        "InterSemiBold".into(),
        std::sync::Arc::new(FontData::from_static(semibold)),
    );
    fonts.font_data.insert(
        "JetBrainsMono".into(),
        std::sync::Arc::new(FontData::from_static(mono)),
    );

    // Prefer Inter for proportional; keep egui defaults as fallbacks.
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "Inter".into());
    // Medium/SemiBold are available by name for RichText::family if needed later.
    fonts
        .families
        .entry(FontFamily::Name("InterMedium".into()))
        .or_default()
        .insert(0, "InterMedium".into());
    fonts
        .families
        .entry(FontFamily::Name("InterSemiBold".into()))
        .or_default()
        .insert(0, "InterSemiBold".into());

    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "JetBrainsMono".into());

    // CJK glyphs are not in Inter or JetBrains Mono. Load one system face
    // (Noto Sans Mono CJK when the OFL package is installed) as a fallback
    // for both families. See fonts.rs for sources and licenses.
    if let Some(cjk) = super::fonts::load_cjk_face() {
        fonts.font_data.insert(
            "CjkFallback".into(),
            std::sync::Arc::new(FontData::from_owned(cjk)),
        );
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .push("CjkFallback".into());
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .push("CjkFallback".into());
    }

    ctx.set_fonts(fonts);
}

/// Secondary toolbar / card action button (28px).
pub fn secondary_button(label: &str) -> egui::Button<'static> {
    egui::Button::new(
        egui::RichText::new(label.to_owned())
            .size(SECONDARY_SIZE)
            .color(TEXT_BODY),
    )
    .fill(BG_SURFACE)
    .stroke(stroke_border_subtle())
    .corner_radius(CornerRadius::same(RADIUS_CONTROL))
    .min_size(egui::vec2(0.0, BTN_TOOLBAR_H))
}

/// Primary filled button (36px).
pub fn primary_button(label: &str) -> egui::Button<'static> {
    egui::Button::new(
        egui::RichText::new(label.to_owned())
            .size(BODY_SIZE)
            .color(TEXT_ON_ACCENT),
    )
    .fill(ACCENT_BG)
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(RADIUS_CONTROL))
    .min_size(egui::vec2(0.0, BTN_PRIMARY_H))
}

/// 28×28 icon/text toolbar control on the connection bar.
pub fn icon_button(label: impl Into<String>, active: bool) -> egui::Button<'static> {
    let color = if active { ACCENT } else { TEXT_BODY };
    egui::Button::new(
        egui::RichText::new(label.into())
            .size(BAR_SIZE)
            .color(color),
    )
    .fill(if active { BG_HOVER } else { BG_PANEL })
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(RADIUS_CONTROL))
    .min_size(egui::vec2(ICON_BTN, ICON_BTN))
}
