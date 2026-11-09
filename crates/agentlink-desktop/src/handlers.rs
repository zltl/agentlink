//! `Op::Extension` handlers for `screenshot` and `inject_input`.

use std::sync::Arc;

use agentlink_core::util::b64_encode;
use agentlink_core::{NodeExtension, PHASE2_INJECT_INPUT, PHASE2_SCREENSHOT};
use serde_json::{json, Value};

use crate::a11y::ElementOp;
use crate::capture::{CaptureRequest, CaptureTarget, MonitorInfo, Rect};
use crate::control_indicator;
use crate::encode::{encode_frame, ImageFormat};
use crate::error::{msg, Result};
use crate::input::{InputAction, MouseButton};
use crate::keys::parse_combo;
use crate::Desktop;

pub struct ScreenshotHandler {
    desktop: Arc<Desktop>,
}

pub struct InjectHandler {
    desktop: Arc<Desktop>,
}

impl ScreenshotHandler {
    pub fn new(desktop: Arc<Desktop>) -> Self {
        Self { desktop }
    }
}

impl InjectHandler {
    pub fn new(desktop: Arc<Desktop>) -> Self {
        Self { desktop }
    }
}

impl NodeExtension for ScreenshotHandler {
    fn name(&self) -> &'static str {
        PHASE2_SCREENSHOT
    }

    fn handle(&self, payload: &Value) -> std::result::Result<Value, String> {
        screenshot(&self.desktop, payload).map_err(|err| err.to_string())
    }
}

impl NodeExtension for InjectHandler {
    fn name(&self) -> &'static str {
        PHASE2_INJECT_INPUT
    }

    fn handle(&self, payload: &Value) -> std::result::Result<Value, String> {
        inject(&self.desktop, payload).map_err(|err| err.to_string())
    }
}

fn screenshot(desktop: &Desktop, payload: &Value) -> Result<Value> {
    if payload.get("target").and_then(Value::as_str) == Some("monitors") {
        let monitors = desktop.capture.list_monitors()?;
        let state = desktop.capture.capturable_state();
        let monitors = monitors_with_capturable(&monitors, state.capturable);
        return Ok(json!({
            "backend": desktop.capture.backend_name(),
            "monitors": monitors,
            "capturable": state.capturable,
            "reason": state.reason,
        }));
    }
    let request = parse_capture(payload)?;
    let format = payload
        .get("format")
        .and_then(Value::as_str)
        .map(ImageFormat::parse)
        .transpose()?
        .unwrap_or(ImageFormat::Jpeg);
    let quality = payload
        .get("quality")
        .and_then(Value::as_u64)
        .unwrap_or(80)
        .min(100) as u8;
    let frame = desktop.capture.capture(&request)?;
    let monitors = desktop.capture.list_monitors().unwrap_or_default();
    let encoded = encode_frame(&frame, format, quality.max(1))?;
    Ok(json!({
        "mime": encoded.mime,
        "format": encoded.format.as_str(),
        "width": encoded.width,
        "height": encoded.height,
        "scale": request.scale,
        "backend": frame.backend,
        "captured_unix_ms": frame.captured_unix_ms,
        "bytes": encoded.bytes.len(),
        "data_b64": b64_encode(&encoded.bytes),
        "monitors": monitors,
    }))
}

fn inject(desktop: &Desktop, payload: &Value) -> Result<Value> {
    let action_name = payload
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("click");
    match action_name {
        // Extension clipboard. Preferred shapes:
        //   {"action":"clipboard","op":"get"}
        //   {"action":"clipboard","text":"..."}   // set
        // Also accepts the flatter docs shape where the clipboard op is the
        // action itself once a wrapper has already selected this handler:
        //   {"action":"get"} / {"action":"set","text":"..."}
        "clipboard" => clipboard_action("clipboard", payload),
        "get" | "set" => clipboard_action(action_name, payload),
        "ui_tree" | "tree" => {
            let depth = payload
                .get("max_depth")
                .and_then(Value::as_u64)
                .unwrap_or(6)
                .clamp(1, 12) as u32;
            let nodes = payload
                .get("max_nodes")
                .and_then(Value::as_u64)
                .unwrap_or(400)
                .clamp(1, 2000) as u32;
            let tree = desktop.a11y.tree(depth, nodes)?;
            Ok(json!({
                "backend": desktop.a11y.backend_name(),
                "tree": tree,
            }))
        }
        "act" | "element" => {
            let id = required_str(payload, "id")?;
            let op = ElementOp::parse(
                payload
                    .get("op")
                    .and_then(Value::as_str)
                    .or_else(|| payload.get("element_action").and_then(Value::as_str))
                    .unwrap_or("click"),
            )?;
            let value = payload.get("value").and_then(Value::as_str);
            if op == ElementOp::SetValue && value.is_none() {
                return Err(msg("set_value needs `value`"));
            }
            desktop.a11y.act(&id, op, value)?;
            Ok(json!({
                "ok": true,
                "backend": desktop.a11y.backend_name(),
                "id": id,
                "op": op.as_str(),
            }))
        }
        other => {
            let payload = resolve_input_coords(desktop, other, payload)?;
            let action = parse_input(other, &payload)?;
            desktop.hid.inject(&action)?;
            // JPEG / extension control path — show the on-screen indicator.
            control_indicator::note_inject_input();
            Ok(json!({
                "ok": true,
                "backend": desktop.hid.backend_name(),
                "action": other,
            }))
        }
    }
}

pub fn parse_capture(payload: &Value) -> Result<CaptureRequest> {
    let target_name = payload
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("screen");
    let target = match target_name {
        "screen" | "full" | "fullscreen" => CaptureTarget::FullScreen,
        "monitor" => {
            let index = payload.get("monitor").and_then(Value::as_u64).unwrap_or(0) as u32;
            CaptureTarget::Monitor(index)
        }
        "region" => CaptureTarget::Region(parse_rect(payload)?),
        "window" => {
            let id = payload
                .get("window_id")
                .or_else(|| payload.get("window"))
                .and_then(Value::as_str)
                .ok_or_else(|| msg("window capture needs `window_id`"))?;
            CaptureTarget::Window(id.to_string())
        }
        other => {
            return Err(msg(format!(
                "unknown screenshot target '{other}' (expected screen, monitor, region, or window)"
            )))
        }
    };
    let scale = payload.get("scale").and_then(Value::as_f64).unwrap_or(1.0) as f32;
    if !scale.is_finite() || !(0.05..=1.0).contains(&scale) {
        return Err(msg("scale must be between 0.05 and 1"));
    }
    Ok(CaptureRequest {
        target,
        scale,
        max_fps: 2.0,
        // Screenshots stay full-resolution; stream sessions set max_width.
        max_width: 0,
    })
}

fn parse_rect(payload: &Value) -> Result<Rect> {
    let region = payload
        .get("region")
        .cloned()
        .unwrap_or_else(|| payload.clone());
    let x = required_i32(&region, "x")?;
    let y = required_i32(&region, "y")?;
    let width = required_u32(&region, "width")?;
    let height = required_u32(&region, "height")?;
    if width == 0 || height == 0 {
        return Err(msg("region width and height must be non-zero"));
    }
    Ok(Rect {
        x,
        y,
        width,
        height,
    })
}

/// Pointer coordinate fields for an input action, split by axis.
fn coord_fields(action: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match action {
        // Live WebRTC also sends button edges as down/up with x/y.
        "move" | "click" | "down" | "up" => (&["x"], &["y"]),
        "drag" => (&["x", "to_x"], &["y", "to_y"]),
        // Scroll deltas stay signed pixel amounts; only the pointer moves.
        "scroll" => (&["x"], &["y"]),
        _ => (&[], &[]),
    }
}

/// Rewrite fractional coordinates to virtual-screen pixels before parsing.
///
/// Android treats inject `x`/`y` as 0–1 fractions and the web viewer sends the
/// same (live data channel and JPEG fallback). Absolute integer pixels stay
/// for older clients. Optional `monitor` picks which display the fractions
/// map onto; invalid values fall back to the primary display. The field is
/// stripped before the payload reaches HID.
pub(crate) fn resolve_input_coords(
    desktop: &Desktop,
    action: &str,
    payload: &Value,
) -> Result<Value> {
    let monitors = if needs_monitor_rect(action, payload) {
        Some(desktop.capture.list_monitors()?)
    } else {
        None
    };
    resolve_input_coords_on(monitors.as_deref(), action, payload)
}

fn needs_monitor_rect(action: &str, payload: &Value) -> bool {
    let (x_fields, y_fields) = coord_fields(action);
    x_fields
        .iter()
        .chain(y_fields.iter())
        .any(|field| payload.get(*field).map(is_fraction).unwrap_or(false))
}

fn resolve_input_coords_on(
    monitors: Option<&[MonitorInfo]>,
    action: &str,
    payload: &Value,
) -> Result<Value> {
    let (x_fields, y_fields) = coord_fields(action);
    let mut out = payload.clone();
    let Some(map) = out.as_object_mut() else {
        return Ok(out);
    };
    // Lower layers do not understand `monitor`; drop it either way.
    map.remove("monitor");
    if x_fields.is_empty() {
        return Ok(out);
    }
    let monitor = if needs_monitor_rect(action, payload) {
        let list = monitors.unwrap_or(&[]);
        Some(
            select_monitor(list, payload)
                .ok_or_else(|| msg("no monitors to map coordinates onto"))?,
        )
    } else {
        None
    };
    let (origin_x, width) = monitor.as_ref().map_or((0, 0), |m| (m.x, m.width));
    let (origin_y, height) = monitor.as_ref().map_or((0, 0), |m| (m.y, m.height));
    for field in x_fields {
        if let Some(value) = payload.get(*field) {
            map.insert(
                (*field).to_string(),
                json!(resolve_coord(value, origin_x, width)?),
            );
        }
    }
    for field in y_fields {
        if let Some(value) = payload.get(*field) {
            map.insert(
                (*field).to_string(),
                json!(resolve_coord(value, origin_y, height)?),
            );
        }
    }
    Ok(out)
}

/// Pick a monitor by optional payload index; invalid/missing → primary.
fn select_monitor(monitors: &[MonitorInfo], payload: &Value) -> Option<MonitorInfo> {
    if let Some(index) = parse_monitor_index(payload.get("monitor")) {
        if let Some(found) = monitors.iter().find(|monitor| monitor.index == index) {
            return Some(found.clone());
        }
    }
    primary_monitor(monitors)
}

fn parse_monitor_index(value: Option<&Value>) -> Option<u32> {
    let value = value?;
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).ok();
    }
    if let Some(n) = value.as_i64() {
        return u32::try_from(n).ok();
    }
    None
}

fn primary_monitor(monitors: &[MonitorInfo]) -> Option<MonitorInfo> {
    monitors
        .iter()
        .find(|monitor| monitor.primary)
        .or_else(|| monitors.first())
        .cloned()
}

fn is_fraction(value: &Value) -> bool {
    value.as_i64().is_none()
        && value
            .as_f64()
            .map(|fraction| fraction.is_finite() && (0.0..=1.0).contains(&fraction))
            .unwrap_or(false)
}

/// Resolve one axis of a JSON number to pixels.
///
/// An integer JSON number is already a pixel (including `0` and `1`). A
/// non-integer in `0.0..=1.0` is a fraction of `origin..origin + span`,
/// clamped to that span; any other finite number rounds to a pixel.
fn resolve_coord(value: &Value, origin: i32, span: u32) -> Result<i32> {
    if let Some(pixel) = value.as_i64() {
        return Ok(pixel.clamp(i32::MIN as i64, i32::MAX as i64) as i32);
    }
    let fraction = value
        .as_f64()
        .ok_or_else(|| msg("coordinate must be a number"))?;
    if !fraction.is_finite() {
        return Err(msg("coordinate must be finite"));
    }
    if (0.0..=1.0).contains(&fraction) {
        let start = origin as f64;
        let end = start + span as f64;
        return Ok((start + (fraction * span as f64).round()).clamp(start, end) as i32);
    }
    Ok(fraction.round().clamp(i32::MIN as f64, i32::MAX as f64) as i32)
}

fn parse_input(action: &str, payload: &Value) -> Result<InputAction> {
    match action {
        "move" => Ok(InputAction::Move {
            x: required_i32(payload, "x")?,
            y: required_i32(payload, "y")?,
        }),
        "click" => Ok(InputAction::Click {
            x: required_i32(payload, "x")?,
            y: required_i32(payload, "y")?,
            button: button(payload)?,
            count: payload.get("count").and_then(Value::as_u64).unwrap_or(1) as u32,
        }),
        "drag" => Ok(InputAction::Drag {
            x: required_i32(payload, "x")?,
            y: required_i32(payload, "y")?,
            to_x: payload
                .get("to_x")
                .and_then(Value::as_i64)
                .ok_or_else(|| msg("drag needs `to_x`"))? as i32,
            to_y: payload
                .get("to_y")
                .and_then(Value::as_i64)
                .ok_or_else(|| msg("drag needs `to_y`"))? as i32,
            button: button(payload)?,
        }),
        "scroll" => {
            let has_x = payload.get("x").is_some();
            let has_y = payload.get("y").is_some();
            if has_x != has_y {
                return Err(msg("scroll needs both x and y, or neither"));
            }
            Ok(InputAction::Scroll {
                x: if has_x {
                    Some(required_i32(payload, "x")?)
                } else {
                    None
                },
                y: if has_y {
                    Some(required_i32(payload, "y")?)
                } else {
                    None
                },
                dx: payload.get("dx").and_then(Value::as_i64).unwrap_or(0) as i32,
                dy: payload.get("dy").and_then(Value::as_i64).unwrap_or(0) as i32,
            })
        },
        "type" => Ok(InputAction::Type {
            text: required_str(payload, "text")?,
        }),
        "key" => {
            let keys = if let Some(text) = payload.get("keys").and_then(Value::as_str) {
                parse_combo(text)?
            } else if let Some(text) = payload.get("combo").and_then(Value::as_str) {
                parse_combo(text)?
            } else if let Some(list) = payload.get("keys").and_then(Value::as_array) {
                let mut out = Vec::new();
                for item in list {
                    let text = item
                        .as_str()
                        .ok_or_else(|| msg("keys entries must be strings"))?;
                    if text.contains('+') {
                        out.extend(parse_combo(text)?);
                    } else {
                        out.push(crate::keys::canonical(text)?);
                    }
                }
                out
            } else {
                return Err(msg("key needs `keys` (\"ctrl+c\" or an array)"));
            };
            let down = payload.get("down").and_then(Value::as_bool);
            Ok(match down {
                Some(down) => InputAction::KeyEdge { keys, down },
                None => InputAction::Key { keys },
            })
        }
        other => Err(msg(format!(
            "unknown input action '{other}' (expected move, click, drag, scroll, type, key, ui_tree, or act)"
        ))),
    }
}

fn clipboard_action(action_name: &str, payload: &Value) -> Result<Value> {
    let op = payload
        .get("op")
        .and_then(Value::as_str)
        .or_else(|| payload.get("clipboard_action").and_then(Value::as_str))
        .unwrap_or(action_name);
    let wants_get = matches!(op, "get" | "read" | "clipboard")
        && payload.get("text").and_then(Value::as_str).is_none();
    if wants_get || (op == "clipboard" && payload.get("text").is_none()) {
        let clip = crate::clipboard::read_clipboard()?;
        control_indicator::note_inject_input();
        let mut out = json!({
            "ok": true,
            "text": clip.text,
            "chars": clip.text.chars().count(),
        });
        if clip.truncated {
            out.as_object_mut()
                .unwrap()
                .insert("truncated".into(), json!(true));
        }
        return Ok(out);
    }
    let text = payload
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| msg("clipboard set needs `text`"))?;
    crate::clipboard::write_clipboard(text)?;
    control_indicator::note_inject_input();
    Ok(json!({
        "ok": true,
        "chars": crate::clipboard::ClipboardText::capped(text.to_string())
            .text
            .chars()
            .count(),
    }))
}

fn monitors_with_capturable(monitors: &[MonitorInfo], capturable: bool) -> Vec<Value> {
    monitors
        .iter()
        .map(|mon| {
            let mut value = serde_json::to_value(mon).unwrap_or_else(|_| json!({}));
            if let Some(obj) = value.as_object_mut() {
                obj.insert("capturable".into(), json!(capturable));
            }
            value
        })
        .collect()
}

fn button(payload: &Value) -> Result<MouseButton> {
    payload
        .get("button")
        .and_then(Value::as_str)
        .map(MouseButton::parse)
        .transpose()
        .map(|button| button.unwrap_or(MouseButton::Left))
}

fn required_str(payload: &Value, key: &str) -> Result<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| msg(format!("missing `{key}`")))
}

fn required_i32(payload: &Value, key: &str) -> Result<i32> {
    payload
        .get(key)
        .and_then(Value::as_i64)
        .map(|value| value as i32)
        .ok_or_else(|| msg(format!("missing integer `{key}`")))
}

fn required_u32(payload: &Value, key: &str) -> Result<u32> {
    payload
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .ok_or_else(|| msg(format!("missing integer `{key}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_extensions;
    use agentlink_core::util::b64_decode;
    use image::ImageFormat as ImageGuess;

    #[test]
    fn resolve_coord_keeps_integers_as_pixels() {
        assert_eq!(resolve_coord(&json!(100), 0, 1920).unwrap(), 100);
        assert_eq!(resolve_coord(&json!(0), 0, 1920).unwrap(), 0);
        assert_eq!(resolve_coord(&json!(1), 0, 1920).unwrap(), 1);
    }

    #[test]
    fn resolve_coord_maps_fractions_onto_the_monitor() {
        // Primary monitor at the origin.
        assert_eq!(resolve_coord(&json!(0.5), 0, 1920).unwrap(), 960);
        assert_eq!(resolve_coord(&json!(0.5), 0, 1080).unwrap(), 540);
        assert_eq!(resolve_coord(&json!(0.0), 0, 1920).unwrap(), 0);
        assert_eq!(resolve_coord(&json!(1.0), 0, 1920).unwrap(), 1920);
        // A monitor to the right of the origin keeps its offset.
        assert_eq!(resolve_coord(&json!(0.5), 1920, 1280).unwrap(), 2560);
        // Offset second display: mid-point lands at origin + half span.
        assert_eq!(resolve_coord(&json!(0.5), 100, 1920).unwrap(), 1060);
        assert_eq!(resolve_coord(&json!(0.5), 100, 1080).unwrap(), 640);
        // 0/1 fractions clamp to the monitor edges (including offset).
        assert_eq!(resolve_coord(&json!(0.0), 100, 1920).unwrap(), 100);
        assert_eq!(resolve_coord(&json!(1.0), 100, 1920).unwrap(), 2020);
    }

    #[test]
    fn resolve_coord_rounds_large_non_integers() {
        assert_eq!(resolve_coord(&json!(123.6), 0, 1920).unwrap(), 124);
        assert!(resolve_coord(&json!("middle"), 0, 1920).is_err());
    }

    #[test]
    fn inject_payload_uses_primary_monitor_for_fractions() {
        let desktop = Desktop::mock();
        // Mock primary monitor is 640x480.
        let resolved =
            resolve_input_coords(&desktop, "click", &json!({"x": 0.5, "y": 0.5})).unwrap();
        assert_eq!(resolved["x"], 320);
        assert_eq!(resolved["y"], 240);

        let resolved = resolve_input_coords(
            &desktop,
            "drag",
            &json!({"x": 0.25, "y": 0.5, "to_x": 0.75, "to_y": 1.0}),
        )
        .unwrap();
        assert_eq!(resolved["x"], 160);
        assert_eq!(resolved["to_x"], 480);
        assert_eq!(resolved["to_y"], 480);

        // Absolute pixels pass through untouched, even for 0 and 1.
        let resolved = resolve_input_coords(&desktop, "click", &json!({"x": 1, "y": 0})).unwrap();
        assert_eq!(resolved["x"], 1);
        assert_eq!(resolved["y"], 0);

        // Scroll moves the pointer but leaves deltas alone.
        let resolved = resolve_input_coords(
            &desktop,
            "scroll",
            &json!({"x": 0.5, "y": 0.5, "dx": 3, "dy": 4}),
        )
        .unwrap();
        assert_eq!(resolved["x"], 320);
        assert_eq!(resolved["dx"], 3);
        assert_eq!(resolved["dy"], 4);

        // Omitting x/y leaves them absent so perform() will not move.
        let resolved = resolve_input_coords(
            &desktop,
            "scroll",
            &json!({"dx": 1, "dy": 2}),
        )
        .unwrap();
        assert!(resolved.get("x").is_none());
        assert!(resolved.get("y").is_none());
        assert_eq!(resolved["dy"], 2);
    }

    #[test]
    fn resolve_input_coords_honors_monitor_and_strips_it() {
        let monitors = [
            MonitorInfo {
                index: 0,
                name: "main".into(),
                x: 0,
                y: 0,
                width: 800,
                height: 600,
                primary: true,
            },
            MonitorInfo {
                index: 1,
                name: "right".into(),
                x: 100,
                y: 40,
                width: 1920,
                height: 1080,
                primary: false,
            },
        ];

        let resolved = resolve_input_coords_on(
            Some(&monitors),
            "click",
            &json!({"x": 0.5, "y": 0.5, "monitor": 1}),
        )
        .unwrap();
        assert_eq!(resolved["x"], 1060);
        assert_eq!(resolved["y"], 580);
        assert!(resolved.get("monitor").is_none());

        // Integers stay absolute desktop pixels even when a monitor is named.
        let resolved = resolve_input_coords_on(
            Some(&monitors),
            "move",
            &json!({"x": 42, "y": 7, "monitor": 1}),
        )
        .unwrap();
        assert_eq!(resolved["x"], 42);
        assert_eq!(resolved["y"], 7);
        assert!(resolved.get("monitor").is_none());

        // Out-of-range / non-numeric monitor falls back to primary.
        let resolved = resolve_input_coords_on(
            Some(&monitors),
            "click",
            &json!({"x": 0.5, "y": 0.5, "monitor": 99}),
        )
        .unwrap();
        assert_eq!(resolved["x"], 400);
        assert_eq!(resolved["y"], 300);

        let resolved = resolve_input_coords_on(
            Some(&monitors),
            "click",
            &json!({"x": 0.5, "y": 0.5, "monitor": "left"}),
        )
        .unwrap();
        assert_eq!(resolved["x"], 400);
        assert_eq!(resolved["y"], 300);

        // Missing monitor also uses primary.
        let resolved = resolve_input_coords_on(
            Some(&monitors),
            "click",
            &json!({"x": 0.5, "y": 0.5}),
        )
        .unwrap();
        assert_eq!(resolved["x"], 400);
        assert_eq!(resolved["y"], 300);

        // Live down/up edges map the same way.
        let resolved = resolve_input_coords_on(
            Some(&monitors),
            "down",
            &json!({"x": 0.5, "y": 0.5, "monitor": 1}),
        )
        .unwrap();
        assert_eq!(resolved["x"], 1060);
        assert_eq!(resolved["y"], 580);
    }

    #[test]
    fn resolve_input_coords_uses_mock_secondary_monitor() {
        let desktop = Desktop::mock();
        // Mock monitor 1 is at x=640, width=320.
        let resolved = resolve_input_coords(
            &desktop,
            "click",
            &json!({"x": 0.5, "y": 0.5, "monitor": 1}),
        )
        .unwrap();
        assert_eq!(resolved["x"], 800);
        assert_eq!(resolved["y"], 240);
        assert!(resolved.get("monitor").is_none());
    }

    #[test]
    fn scroll_parse_omits_pointer_when_coords_absent() {
        let action = parse_input("scroll", &json!({"dx": 1, "dy": 3})).unwrap();
        assert_eq!(
            action,
            InputAction::Scroll {
                x: None,
                y: None,
                dx: 1,
                dy: 3
            }
        );
        let action = parse_input("scroll", &json!({"x": 10, "y": 20, "dy": 1})).unwrap();
        assert_eq!(
            action,
            InputAction::Scroll {
                x: Some(10),
                y: Some(20),
                dx: 0,
                dy: 1
            }
        );
        assert!(parse_input("scroll", &json!({"x": 10, "dy": 1})).is_err());
    }

    #[test]
    fn mock_screenshot_region_and_tree() {
        let exts = mock_extensions();
        let shot = exts.iter().find(|ext| ext.name() == "screenshot").unwrap();
        let value = shot
            .handle(&json!({
                "target": "region",
                "x": 0,
                "y": 0,
                "width": 20,
                "height": 10,
                "scale": 0.5,
                "format": "png",
                "quality": 80
            }))
            .unwrap();
        assert_eq!(value["backend"], "mock");
        assert_eq!(value["width"], 10);
        assert_eq!(value["height"], 5);
        let bytes = b64_decode(value["data_b64"].as_str().unwrap()).unwrap();
        let image = image::load_from_memory_with_format(&bytes, ImageGuess::Png).unwrap();
        assert_eq!((image.width(), image.height()), (10, 5));

        let inject = exts
            .iter()
            .find(|ext| ext.name() == "inject_input")
            .unwrap();
        inject
            .handle(&json!({"action":"click","x":4,"y":5,"button":"left"}))
            .unwrap();
        inject
            .handle(&json!({"action":"type","text":"héllo"}))
            .unwrap();
        inject
            .handle(&json!({"action":"key","keys":"ctrl+c"}))
            .unwrap();
        let tree = inject
            .handle(&json!({"action":"ui_tree","max_depth":4}))
            .unwrap();
        assert_eq!(tree["tree"]["children"][0]["id"], "mock:ok");
        inject
            .handle(&json!({"action":"act","id":"mock:title","op":"set_value","value":"updated"}))
            .unwrap();
        let tree = inject.handle(&json!({"action":"ui_tree"})).unwrap();
        assert_eq!(tree["tree"]["children"][1]["value"], "updated");
    }
}
