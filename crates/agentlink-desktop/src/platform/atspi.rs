//! Linux accessibility over AT-SPI (D-Bus).
//!
//! The registry is reached through the session bus (`org.a11y.Bus.GetAddress`).
//! Element ids are `atspi|{bus-name}|{object-path}` and can be used until the
//! next tree request. Click, focus, and set-value call Action, Component, and
//! EditableText on that object.
//!
//! Desktop root: libatspi's `atspi_get_desktop(0)` is **not** a D-Bus
//! `Registry.GetDesktop` call (that method does not exist on modern
//! `org.a11y.atspi.Registry`). It is a client-side alias for the registry
//! accessible at `/org/a11y/atspi/accessible/root`.

use std::collections::HashMap;

use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

use crate::a11y::UiNode;
use crate::capture::Rect;
use crate::error::{msg, Result};

const ATSPI_REGISTRY_BUS: &str = "org.a11y.atspi.Registry";
const ATSPI_ROOT_PATH: &str = "/org/a11y/atspi/accessible/root";
const ATSPI_STATE_EDITABLE: u32 = 7;
const ATSPI_STATE_FOCUSED: u32 = 12;

struct ObjectRef {
    bus: String,
    path: String,
}

pub async fn tree(max_depth: u32, max_nodes: u32) -> Result<UiNode> {
    let conn = atspi_bus().await?;
    let root = desktop_root(&conn).await?;
    let mut budget = max_nodes.max(1);
    walk(&conn, &root, max_depth.max(1), &mut budget)
        .await?
        .ok_or_else(|| msg("AT-SPI desktop tree is empty"))
}

/// Insert `text` at the caret of the focused editable accessible, if any.
/// Used by Linux `type` so committed text bypasses the session IME.
pub async fn insert_text_at_focus(text: &str) -> Result<()> {
    let conn = atspi_bus().await?;
    let root = desktop_root(&conn).await?;
    let mut budget = 400u32;
    let focused = find_focused_editable(&conn, &root, &mut budget)
        .await?
        .ok_or_else(|| {
            msg("AT-SPI capability: no focused editable text field for InsertText")
        })?;
    let caret = caret_offset(&conn, &focused).await.unwrap_or(0);
    let proxy = Proxy::new(
        &conn,
        focused.bus.as_str(),
        focused.path.as_str(),
        "org.a11y.atspi.EditableText",
    )
    .await
    .map_err(|err| msg(format!("AT-SPI EditableText: {err}")))?;
    // AT-SPI InsertText `length` is a character count, not UTF-8 bytes.
    // Passing text.len() worked for ASCII and silently failed for CJK.
    let length = insert_text_length(text);
    let ok: bool = proxy
        .call("InsertText", &(caret, text, length))
        .await
        .map_err(|err| msg(format!("AT-SPI InsertText: {err}")))?;
    if !ok {
        return Err(msg("AT-SPI InsertText returned false"));
    }
    Ok(())
}

pub async fn act(id: &str, op: crate::a11y::ElementOp, value: Option<&str>) -> Result<()> {
    let conn = atspi_bus().await?;
    let object = parse_id(id)?;
    match op {
        crate::a11y::ElementOp::Focus => {
            let proxy = component(&conn, &object).await?;
            let ok: bool = proxy
                .call("GrabFocus", &())
                .await
                .map_err(|err| msg(format!("AT-SPI focus: {err}")))?;
            if !ok {
                return Err(msg(format!("AT-SPI could not focus {id}")));
            }
            Ok(())
        }
        crate::a11y::ElementOp::Click => {
            if do_named_action(&conn, &object, "click").await? {
                return Ok(());
            }
            // Fall back to the first action, which is "click" for most buttons.
            let proxy = action(&conn, &object).await?;
            let ok: bool = proxy
                .call("DoAction", &(0i32,))
                .await
                .map_err(|err| msg(format!("AT-SPI click: {err}")))?;
            if !ok {
                return Err(msg(format!("AT-SPI element {id} has no click action")));
            }
            Ok(())
        }
        crate::a11y::ElementOp::SetValue => {
            let text = value.unwrap_or("");
            let proxy = Proxy::new(
                &conn,
                object.bus.as_str(),
                object.path.as_str(),
                "org.a11y.atspi.EditableText",
            )
            .await
            .map_err(|err| msg(err.to_string()))?;
            proxy
                .call::<_, _, ()>("SetTextContents", &(text,))
                .await
                .map_err(|err| {
                    msg(format!(
                        "AT-SPI set_value: {err}. The element may not be editable."
                    ))
                })?;
            Ok(())
        }
    }
}

async fn atspi_bus() -> Result<Connection> {
    let session = Connection::session().await.map_err(|err| {
        msg(format!(
            "AT-SPI capability missing: session bus unavailable ({err}). \
             Export DBUS_SESSION_BUS_ADDRESS from the interactive user session."
        ))
    })?;
    let launcher = Proxy::new(&session, "org.a11y.Bus", "/org/a11y/bus", "org.a11y.Bus")
        .await
        .map_err(|err| {
            msg(format!(
                "AT-SPI capability missing: accessibility bus launcher unreachable ({err}). \
                 Install at-spi2-core and run the node in the interactive user session."
            ))
        })?;
    let address: String = launcher.call("GetAddress", &()).await.map_err(|err| {
        msg(format!(
            "AT-SPI capability missing: GetAddress failed ({err}). \
             Enable toolkit accessibility and ensure the session a11y bus is running."
        ))
    })?;
    zbus::connection::Builder::address(address.as_str())
        .map_err(|err| msg(err.to_string()))?
        .build()
        .await
        .map_err(|err| {
            msg(format!(
                "AT-SPI capability missing: could not connect to accessibility bus ({err})"
            ))
        })
}

async fn desktop_root(conn: &Connection) -> Result<ObjectRef> {
    // Match libatspi `atspi_get_desktop(0)`: ref the registry accessible root.
    // Do not call Registry.GetDesktop — that method is not on the D-Bus API.
    let root = ObjectRef {
        bus: ATSPI_REGISTRY_BUS.to_string(),
        path: ATSPI_ROOT_PATH.to_string(),
    };
    // Probe ChildCount so a missing registry yields a clear capability error
    // instead of an empty walk later.
    match prop_i32(conn, &root, "ChildCount").await {
        Ok(_) => Ok(root),
        Err(err) => Err(msg(format!(
            "AT-SPI capability missing: desktop root {ATSPI_ROOT_PATH} is unreachable ({err})"
        ))),
    }
}

async fn walk(
    conn: &Connection,
    object: &ObjectRef,
    depth: u32,
    budget: &mut u32,
) -> Result<Option<UiNode>> {
    if *budget == 0 {
        return Ok(None);
    }
    *budget -= 1;
    let name = prop_string(conn, object, "Name").await.unwrap_or_default();
    let role_id = role_of(conn, object).await.unwrap_or(67);
    let bounds = extents(conn, object).await.unwrap_or(Rect {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    });
    let focused = state_has(&states_of(conn, object).await.unwrap_or_default(), ATSPI_STATE_FOCUSED);
    let mut node = UiNode {
        id: format!("atspi|{}|{}", object.bus, object.path),
        role: role_name(role_id).to_string(),
        name,
        bounds,
        value: String::new(),
        focused,
        children: Vec::new(),
    };
    if depth <= 1 {
        return Ok(Some(node));
    }
    let count = prop_i32(conn, object, "ChildCount").await.unwrap_or(0);
    let count = count.clamp(0, 64);
    for index in 0..count {
        if *budget == 0 {
            break;
        }
        let child = match child_at(conn, object, index).await {
            Ok(child) => child,
            Err(_) => continue,
        };
        if let Some(child) = Box::pin(walk(conn, &child, depth - 1, budget)).await? {
            node.children.push(child);
        }
    }
    Ok(Some(node))
}

async fn child_at(conn: &Connection, object: &ObjectRef, index: i32) -> Result<ObjectRef> {
    let proxy = accessible(conn, object).await?;
    let (bus, path): (String, OwnedObjectPath) = proxy
        .call("GetChildAtIndex", &(index,))
        .await
        .map_err(|err| msg(err.to_string()))?;
    Ok(ObjectRef {
        bus,
        path: path.to_string(),
    })
}

async fn extents(conn: &Connection, object: &ObjectRef) -> Result<Rect> {
    let proxy = component(conn, object).await?;
    // 0 = ATSPI_COORD_TYPE_SCREEN.
    let (x, y, width, height): (i32, i32, i32, i32) = proxy
        .call("GetExtents", &(0u32,))
        .await
        .map_err(|err| msg(err.to_string()))?;
    Ok(Rect {
        x,
        y,
        width: width.max(0) as u32,
        height: height.max(0) as u32,
    })
}

async fn do_named_action(conn: &Connection, object: &ObjectRef, name: &str) -> Result<bool> {
    let proxy = action(conn, object).await?;
    let actions: Vec<(String, String, String)> = match proxy.call("GetActions", &()).await {
        Ok(actions) => actions,
        Err(_) => return Ok(false),
    };
    if let Some(index) = actions
        .iter()
        .position(|action| action.0.eq_ignore_ascii_case(name))
    {
        let ok: bool = proxy
            .call("DoAction", &(index as i32,))
            .await
            .unwrap_or(false);
        return Ok(ok);
    }
    Ok(false)
}

async fn accessible<'a>(conn: &'a Connection, object: &'a ObjectRef) -> Result<Proxy<'a>> {
    Proxy::new(
        conn,
        object.bus.as_str(),
        object.path.as_str(),
        "org.a11y.atspi.Accessible",
    )
    .await
    .map_err(|err| msg(err.to_string()))
}

async fn component<'a>(conn: &'a Connection, object: &'a ObjectRef) -> Result<Proxy<'a>> {
    Proxy::new(
        conn,
        object.bus.as_str(),
        object.path.as_str(),
        "org.a11y.atspi.Component",
    )
    .await
    .map_err(|err| msg(err.to_string()))
}

async fn action<'a>(conn: &'a Connection, object: &'a ObjectRef) -> Result<Proxy<'a>> {
    Proxy::new(
        conn,
        object.bus.as_str(),
        object.path.as_str(),
        "org.a11y.atspi.Action",
    )
    .await
    .map_err(|err| msg(err.to_string()))
}

async fn find_focused_editable(
    conn: &Connection,
    object: &ObjectRef,
    budget: &mut u32,
) -> Result<Option<ObjectRef>> {
    if *budget == 0 {
        return Ok(None);
    }
    *budget -= 1;
    let states = states_of(conn, object).await.unwrap_or_default();
    let focused = state_has(&states, ATSPI_STATE_FOCUSED);
    let editable = state_has(&states, ATSPI_STATE_EDITABLE);
    if focused && editable {
        return Ok(Some(ObjectRef {
            bus: object.bus.clone(),
            path: object.path.clone(),
        }));
    }
    let count = prop_i32(conn, object, "ChildCount").await.unwrap_or(0);
    let count = count.clamp(0, 128);
    for index in 0..count {
        if *budget == 0 {
            break;
        }
        let child = match child_at(conn, object, index).await {
            Ok(child) => child,
            Err(_) => continue,
        };
        if let Some(found) = Box::pin(find_focused_editable(conn, &child, budget)).await? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

async fn caret_offset(conn: &Connection, object: &ObjectRef) -> Result<i32> {
    let value = dbus_prop(conn, object, "org.a11y.atspi.Text", "CaretOffset").await?;
    match &*value {
        Value::I32(number) => Ok(*number),
        Value::U32(number) => Ok(*number as i32),
        _ => Err(msg("AT-SPI CaretOffset is not an integer")),
    }
}

async fn role_of(conn: &Connection, object: &ObjectRef) -> Result<u32> {
    let proxy = accessible(conn, object).await?;
    let role: u32 = proxy
        .call("GetRole", &())
        .await
        .map_err(|err| msg(format!("AT-SPI GetRole: {err}")))?;
    Ok(role)
}

async fn states_of(conn: &Connection, object: &ObjectRef) -> Result<Vec<u32>> {
    let proxy = accessible(conn, object).await?;
    let states: Vec<u32> = proxy
        .call("GetState", &())
        .await
        .map_err(|err| msg(format!("AT-SPI GetState: {err}")))?;
    Ok(states)
}

/// `GetState` historically returns two uint32 bitfields; some stacks return a
/// list of state enum values. Accept either encoding.
pub fn state_has(states: &[u32], state: u32) -> bool {
    if states.iter().any(|value| *value == state) && states.len() > 2 {
        return true;
    }
    if states.len() <= 4 {
        let bit = state;
        let index = (bit / 32) as usize;
        let shift = bit % 32;
        if let Some(word) = states.get(index) {
            return (word & (1u32 << shift)) != 0;
        }
    }
    states.iter().any(|value| *value == state)
}

async fn prop_string(conn: &Connection, object: &ObjectRef, name: &str) -> Result<String> {
    let value = dbus_prop(conn, object, "org.a11y.atspi.Accessible", name).await?;
    match &*value {
        Value::Str(text) => Ok(text.to_string()),
        _ => Ok(String::new()),
    }
}

async fn prop_i32(conn: &Connection, object: &ObjectRef, name: &str) -> Result<i32> {
    let value = dbus_prop(conn, object, "org.a11y.atspi.Accessible", name).await?;
    match &*value {
        Value::I32(number) => Ok(*number),
        Value::U32(number) => Ok(*number as i32),
        _ => Err(msg("AT-SPI property is not an integer")),
    }
}

async fn dbus_prop(
    conn: &Connection,
    object: &ObjectRef,
    interface: &str,
    name: &str,
) -> Result<OwnedValue> {
    let proxy = Proxy::new(
        conn,
        object.bus.as_str(),
        object.path.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .map_err(|err| msg(err.to_string()))?;
    proxy
        .call("Get", &(interface, name))
        .await
        .map_err(|err| msg(format!("AT-SPI property {name}: {err}")))
}

fn parse_id(id: &str) -> Result<ObjectRef> {
    let mut parts = id.splitn(3, '|');
    let kind = parts.next().unwrap_or("");
    let bus = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if kind != "atspi" || bus.is_empty() || !path.starts_with('/') {
        return Err(msg(format!(
            "element id '{id}' is not an AT-SPI id. Call get_ui_tree again."
        )));
    }
    // Validate the path so a bad id fails before D-Bus does.
    ObjectPath::try_from(path).map_err(|_| msg(format!("bad AT-SPI path in '{id}'")))?;
    Ok(ObjectRef {
        bus: bus.to_string(),
        path: path.to_string(),
    })
}

fn role_name(role: u32) -> &'static str {
    match role {
        7 => "checkbox",
        11 => "combobox",
        14 => "desktop",
        16 => "dialog",
        23 => "frame",
        29 => "label",
        31 => "list",
        32 => "listitem",
        33 => "menu",
        35 => "menuitem",
        39 => "panel",
        43 => "button",
        44 => "radio",
        55 => "table",
        61 => "text",
        63 => "toolbar",
        65 => "tree",
        69 => "window",
        75 => "application",
        79 => "entry",
        88 => "link",
        91 => "treeitem",
        _ => "unknown",
    }
}

#[allow(dead_code)]
fn _map_unused(map: HashMap<String, String>) -> usize {
    map.len()
}


/// AT-SPI EditableText.InsertText length is Unicode scalar values (BMP
/// CJK equals UTF-16 units). Never use UTF-8 byte length here.
pub fn insert_text_length(text: &str) -> i32 {
    i32::try_from(text.chars().count()).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn desktop_root_paths_match_libatspi() {
        assert_eq!(ATSPI_REGISTRY_BUS, "org.a11y.atspi.Registry");
        assert_eq!(ATSPI_ROOT_PATH, "/org/a11y/atspi/accessible/root");
    }

    #[test]
    fn state_bitfield_detects_focused_and_editable() {
        // Two-word bitfield encoding used by classic at-spi2.
        let mut words = [0u32; 2];
        words[(ATSPI_STATE_FOCUSED / 32) as usize] |= 1 << (ATSPI_STATE_FOCUSED % 32);
        words[(ATSPI_STATE_EDITABLE / 32) as usize] |= 1 << (ATSPI_STATE_EDITABLE % 32);
        assert!(state_has(&words, ATSPI_STATE_FOCUSED));
        assert!(state_has(&words, ATSPI_STATE_EDITABLE));
        assert!(!state_has(&words, 0));
    }

    #[test]
    fn state_list_encoding_is_accepted() {
        let states = vec![ATSPI_STATE_EDITABLE, ATSPI_STATE_FOCUSED, 25, 26, 30];
        assert!(state_has(&states, ATSPI_STATE_FOCUSED));
        assert!(state_has(&states, ATSPI_STATE_EDITABLE));
    }

    #[test]
    fn insert_text_length_uses_unicode_scalars_not_utf8_bytes() {
        assert_eq!(insert_text_length("ABC"), 3);
        let cjk = "中文输入测试：你好。";
        assert_eq!(cjk.chars().count(), 10);
        assert!(cjk.len() > 10, "the CJK fixture must be multi-byte UTF-8");
        assert_eq!(insert_text_length(cjk), 10);
    }
}
