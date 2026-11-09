//! Compact accessibility trees.
//!
//! Nodes carry a role, a name, bounds, and an id. Ids are backend-specific
//! and stay valid until the next [`A11yBackend::tree`] call, which refreshes
//! the cache the backend uses for [`A11yBackend::act`].

use serde::{Deserialize, Serialize};

use crate::capture::Rect;
use crate::error::{msg, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementOp {
    Click,
    Focus,
    SetValue,
}

impl ElementOp {
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "click" => Ok(Self::Click),
            "focus" => Ok(Self::Focus),
            "set_value" | "setvalue" | "value" => Ok(Self::SetValue),
            other => Err(msg(format!(
                "unknown element action '{other}' (expected click, focus, or set_value)"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Click => "click",
            Self::Focus => "focus",
            Self::SetValue => "set_value",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiNode {
    pub id: String,
    pub role: String,
    pub name: String,
    pub bounds: Rect,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub focused: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<UiNode>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub trait A11yBackend: Send + Sync {
    fn backend_name(&self) -> &str;
    fn tree(&self, max_depth: u32, max_nodes: u32) -> Result<UiNode>;
    fn act(&self, id: &str, op: ElementOp, value: Option<&str>) -> Result<()>;
}

/// Drop children past `max_depth` and stop after `max_nodes` nodes.
pub fn limit_tree(node: UiNode, max_depth: u32, max_nodes: u32) -> UiNode {
    let mut budget = max_nodes.max(1);
    limit_rec(node, max_depth.max(1), &mut budget).unwrap_or_else(|| UiNode {
        id: "empty".into(),
        role: "none".into(),
        name: String::new(),
        bounds: Rect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        },
        value: String::new(),
        focused: false,
        children: Vec::new(),
    })
}

fn limit_rec(mut node: UiNode, depth_left: u32, budget: &mut u32) -> Option<UiNode> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    if depth_left <= 1 {
        node.children.clear();
        return Some(node);
    }
    let children = std::mem::take(&mut node.children);
    for child in children {
        if *budget == 0 {
            break;
        }
        if let Some(child) = limit_rec(child, depth_left - 1, budget) {
            node.children.push(child);
        }
    }
    Some(node)
}
