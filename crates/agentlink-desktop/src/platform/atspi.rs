//! Linux accessibility over AT-SPI (D-Bus).
//!
//! The registry is reached through the session bus (`org.a11y.Bus.GetAddress`).
//! Element ids are `atspi|{bus-name}|{object-path}` and can be used until the
//! next tree request. Click, focus, and set-value call Action, Component, and
//! EditableText on that object.

use std::collections::HashMap;

use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

use crate::a11y::UiNode;
use crate::capture::Rect;
use crate::error::{msg, Result};

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
    let session = Connection::session()
        .await
        .map_err(|err| msg(format!("session bus: {err}")))?;
    let launcher = Proxy::new(&session, "org.a11y.Bus", "/org/a11y/bus", "org.a11y.Bus")
        .await
        .map_err(|err| {
            msg(format!(
                "AT-SPI bus launcher: {err}. Install at-spi2-core and start the session accessibility bus."
            ))
        })?;
    let address: String = launcher
        .call("GetAddress", &())
        .await
        .map_err(|err| msg(format!("AT-SPI GetAddress: {err}")))?;
    zbus::connection::Builder::address(address.as_str())
        .map_err(|err| msg(err.to_string()))?
        .build()
        .await
        .map_err(|err| msg(format!("AT-SPI bus: {err}")))
}

async fn desktop_root(conn: &Connection) -> Result<ObjectRef> {
    let registry = Proxy::new(
        conn,
        "org.a11y.atspi.Registry",
        "/org/a11y/atspi/registry",
        "org.a11y.atspi.Registry",
    )
    .await
    .map_err(|err| msg(format!("AT-SPI registry: {err}")))?;
    let (bus, path): (String, OwnedObjectPath) = registry
        .call("GetDesktop", &(0i32,))
        .await
        .map_err(|err| msg(format!("AT-SPI GetDesktop: {err}")))?;
    Ok(ObjectRef {
        bus,
        path: path.to_string(),
    })
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
    let role_id = prop_u32(conn, object, "Role").await.unwrap_or(67);
    let bounds = extents(conn, object).await.unwrap_or(Rect {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    });
    let mut node = UiNode {
        id: format!("atspi|{}|{}", object.bus, object.path),
        role: role_name(role_id).to_string(),
        name,
        bounds,
        value: String::new(),
        focused: false,
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

async fn prop_string(conn: &Connection, object: &ObjectRef, name: &str) -> Result<String> {
    let value = dbus_prop(conn, object, "org.a11y.atspi.Accessible", name).await?;
    match &*value {
        Value::Str(text) => Ok(text.to_string()),
        _ => Ok(String::new()),
    }
}

async fn prop_u32(conn: &Connection, object: &ObjectRef, name: &str) -> Result<u32> {
    let value = dbus_prop(conn, object, "org.a11y.atspi.Accessible", name).await?;
    match &*value {
        Value::U32(number) => Ok(*number),
        Value::U16(number) => Ok(*number as u32),
        _ => Err(msg(format!("AT-SPI property {name} is not an integer"))),
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
