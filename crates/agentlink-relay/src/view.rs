//! Retired browser desktop viewer notice page (`GET /view`).
//!
//! Control from the browser is disabled. This module only serves a static
//! explanation; it does not mint tickets, open WebRTC, or inject input.

use serde_json::json;

const PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>agentlink</title>
</head>
<body>
  <main>
    <h1>Browser control is not available</h1>
    <p>This page does not open a shell, files, or a desktop. The relay would see that traffic, and a web login is not a grant on the machine.</p>
    <p>Use a sealed client after the node operator has issued a grant for that client's key.</p>
  </main>
</body>
</html>
"#;

pub fn response_for(head: &str) -> Option<Vec<u8>> {
    let mut lines = head.lines();
    let request = lines.next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/").split('?').next().unwrap_or("/");
    let head = method.eq_ignore_ascii_case("HEAD");
    if method != "GET" && !head {
        return None;
    }
    let (content_type, body) = match path {
        "/view" | "/view/" | "/view/index.html" => {
            ("text/html; charset=utf-8", PAGE.as_bytes().to_vec())
        }
        "/view/config.json" => ("application/json", config_json().into_bytes()),
        _ => return None,
    };
    Some(http_ok_for(content_type, &body, head))
}

/// Public ICE document. STUN and TURN URLs only. Never a username or credential.
pub fn public_config_json() -> String {
    let turn_urls = split_env("AGENTLINK_TURN_URLS");
    let secret = std::env::var("AGENTLINK_TURN_SECRET").unwrap_or_default();
    let turn_auth = turn_auth_name(&turn_urls, secret.trim().is_empty(), false);
    config_from(
        std::env::var("AGENTLINK_STUN_URLS").ok(),
        turn_urls,
        String::new(),
        String::new(),
        turn_auth,
    )
}

fn config_json() -> String {
    public_config_json()
}

/// ICE document for a caller who already presented a view ticket or a session.
///
/// When `AGENTLINK_TURN_SECRET` is set, the TURN entry carries a REST
/// credential that expires in about ten minutes (clamped to 5–15). The static
/// `AGENTLINK_TURN_PASSWORD` is never copied into the response.
pub fn session_config_json(user_id: &str) -> String {
    let turn_urls = split_env("AGENTLINK_TURN_URLS");
    let secret = std::env::var("AGENTLINK_TURN_SECRET").unwrap_or_default();
    let ttl = std::env::var("AGENTLINK_TURN_TTL_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(agentlink_core::turn::DEFAULT_TURN_TTL_SECS);
    let (username, credential, turn_auth) = if turn_urls.is_empty() {
        (String::new(), String::new(), "none")
    } else if secret.trim().is_empty() {
        (String::new(), String::new(), "unconfigured")
    } else {
        match agentlink_core::turn::mint(
            secret.trim(),
            user_id,
            agentlink_core::util::unix_now(),
            ttl,
        ) {
            Ok((username, credential, _)) => (username, credential, "rest"),
            Err(_) => (String::new(), String::new(), "unconfigured"),
        }
    };
    config_from(
        std::env::var("AGENTLINK_STUN_URLS").ok(),
        turn_urls,
        username,
        credential,
        turn_auth,
    )
}

fn turn_auth_name(turn_urls: &[String], secret_empty: bool, minted: bool) -> &'static str {
    if turn_urls.is_empty() {
        "none"
    } else if minted || !secret_empty {
        "rest"
    } else {
        "unconfigured"
    }
}

fn config_from(
    stun_env: Option<String>,
    turn_urls: Vec<String>,
    username: String,
    credential: String,
    turn_auth: &str,
) -> String {
    let stun = agentlink_core::stun_urls(stun_env.as_deref());
    let include_secret = !username.is_empty() && !credential.is_empty();
    let turn = if turn_urls.is_empty() {
        Vec::new()
    } else if include_secret {
        vec![json!({
            "urls": turn_urls,
            "username": username,
            "credential": credential,
        })]
    } else {
        vec![json!({ "urls": turn_urls })]
    };
    let attempt_user = if include_secret {
        username.as_str()
    } else {
        ""
    };
    let attempt_cred = if include_secret {
        credential.as_str()
    } else {
        ""
    };
    let attempts: Vec<_> =
        agentlink_core::ice_attempts(&stun, &turn_urls, attempt_user, attempt_cred)
            .iter()
            .map(agentlink_core::IceAttempt::to_json)
            .collect();
    json!({
        "protocol": agentlink_core::protocol::PROTOCOL_VERSION,
        "media": "dtls-srtp",
        "stun": stun,
        "turn": turn,
        "turn_auth": turn_auth,
        "attempts": attempts,
    })
    .to_string()
}

fn split_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn http_ok_for(content_type: &str, body: &[u8], head: bool) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = header.into_bytes();
    if !head {
        out.extend_from_slice(body);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_page_does_not_offer_control() {
        let bytes = response_for("GET /view HTTP/1.1").unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Browser control is not available"));
        assert!(text.contains("grant for that client's key"));
        assert!(!text.contains("login-pass"));
        assert!(!text.contains("screenshot"));
        assert!(!text.contains("/v1/webrtc"));
        assert!(response_for("GET /view/pointer.js HTTP/1.1").is_none());
    }

    #[test]
    fn unset_stun_defaults_and_turn_stays_empty() {
        let text = config_from(None, Vec::new(), String::new(), String::new(), "none");
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let stun: Vec<String> = value["stun"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            stun,
            agentlink_core::DEFAULT_STUN_URLS
                .iter()
                .map(|url| (*url).to_string())
                .collect::<Vec<_>>()
        );
        assert!(value["turn"].as_array().unwrap().is_empty());
        let attempts = value["attempts"].as_array().unwrap();
        assert_eq!(attempts[0]["id"], "host");
        assert_eq!(attempts[0]["banner"], "via host");
        assert!(attempts.iter().any(|item| item["id"] == "srflx"
            && item["banner"] == "via STUN"
            && item["gather_ms"] == 2500));
        assert!(attempts
            .iter()
            .all(|item| item["ice_transport_policy"] != "relay"));
    }

    #[test]
    fn explicit_stun_and_turn_replace_the_defaults() {
        let text = config_from(
            Some(String::new()),
            vec!["turn:turn.example:3478".into()],
            String::new(),
            String::new(),
            "rest",
        );
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(value["stun"].as_array().unwrap().is_empty());
        assert_eq!(value["turn"][0]["urls"][0], "turn:turn.example:3478");
        assert!(value["turn"][0].get("username").is_none());
        assert!(value["turn"][0].get("credential").is_none());
        assert_eq!(value["turn_auth"], "rest");
        assert_eq!(value["media"], "dtls-srtp");
        let leaked = text.contains("replace-me");
        assert!(!leaked);

        let authed = config_from(
            Some(String::new()),
            vec!["turns:turn.example:443?transport=tcp".into()],
            "1700000600:web:alice".into(),
            "c2VjcmV0".into(),
            "rest",
        );
        let authed: serde_json::Value = serde_json::from_str(&authed).unwrap();
        assert_eq!(authed["turn"][0]["username"], "1700000600:web:alice");
        assert_eq!(authed["turn"][0]["credential"], "c2VjcmV0");
        assert!(authed["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["id"] == "relay-tcp")
            .all(|item| item["ice_servers"][0]["credential"] == "c2VjcmV0"));

        let custom = config_from(
            Some("stun:turn.example:3478".into()),
            Vec::new(),
            String::new(),
            String::new(),
            "none",
        );
        let value: serde_json::Value = serde_json::from_str(&custom).unwrap();
        assert_eq!(value["stun"][0], "stun:turn.example:3478");
    }

    #[test]
    fn unknown_path_is_not_a_viewer() {
        assert!(response_for("GET /v1/connect HTTP/1.1").is_none());
    }
}
