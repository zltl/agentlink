//! Browser login, the machine dashboard, and enrollment.
//!
//! `GET /` is the management UI. `GET /view` stays the desktop viewer.
//! `GET /v1/web` upgrades a dashboard session into a file and terminal socket.
//! Both pages use the same local accounts as the CLI and the Android app. The
//! browser keeps an HttpOnly session cookie; device-bound access and refresh
//! tokens stay on the CLI and the phone. Nothing on the page is loaded from a CDN.

use agentlink_core::accounts::WEB_TTL_SECS;
use agentlink_core::util::{self, unix_now};
use agentlink_core::{
    parse_access, Error, Result, WS_WEB_PATH,
};
use serde_json::{json, Value};

use crate::models::{Caller, WebSession};
use crate::server::{self, Hub};

pub struct HttpReply {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    /// When set, advertised Content-Length (HEAD of a large `/dl` file without
    /// loading bytes into `body`).
    pub content_length: Option<usize>,
}

impl HttpReply {
    pub fn encode(&self) -> Vec<u8> {
        self.encode_for_method("GET")
    }

    /// RFC 9110: HEAD returns the same headers as GET with an empty body.
    /// Content-Length still reflects the would-be entity size.
    pub fn encode_for_method(&self, method: &str) -> Vec<u8> {
        let length = self.content_length.unwrap_or_else(|| self.body.len());
        let mut header = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.content_type,
            length
        );
        for (name, value) in &self.headers {
            header.push_str(name);
            header.push_str(": ");
            header.push_str(value);
            header.push_str("\r\n");
        }
        header.push_str("\r\n");
        let mut out = header.into_bytes();
        if !method.eq_ignore_ascii_case("HEAD") {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

pub enum WebOutcome {
    Reply(HttpReply),
    Events { user: String, admin: bool },
}

pub async fn handle(
    hub: &Hub,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    peer: std::net::SocketAddr,
) -> Result<Option<WebOutcome>> {
    // HEAD shares GET routing for idempotent reads (install scripts, /dl/*,
    // dashboard, APIs). Caller encodes with encode_for_method so the body is
    // omitted while Content-Length stays correct.
    let head = method.eq_ignore_ascii_case("HEAD");
    let method = if head { "GET" } else { method };
    match (method, path) {
        ("POST", "/auth/login") => Ok(Some(WebOutcome::Reply(
            login(hub, headers, body, peer).await?,
        ))),
        ("POST", "/auth/logout") => Ok(Some(WebOutcome::Reply(logout(hub, headers).await?))),
        ("GET", "/auth/session") => Ok(Some(WebOutcome::Reply(session_info(hub, headers).await?))),
        ("GET", "/api/nodes") => Ok(Some(WebOutcome::Reply(nodes(hub, headers).await?))),
        ("GET", "/api/tokens") => Ok(Some(WebOutcome::Reply(tokens(hub, headers).await?))),
        ("POST", "/api/tokens") => Ok(Some(WebOutcome::Reply(
            create_token(hub, headers, body).await?,
        ))),
        ("POST", "/api/tokens/revoke") => Ok(Some(WebOutcome::Reply(
            revoke_token(hub, headers, body).await?,
        ))),
        ("POST", "/api/view-ticket") => Ok(Some(WebOutcome::Reply(
            view_ticket(hub, headers, body, peer).await?,
        ))),
        ("POST", "/api/view-ticket/revoke") => Ok(Some(WebOutcome::Reply(
            revoke_view_ticket(hub, headers, body).await?,
        ))),
        ("POST", "/api/ice") => Ok(Some(WebOutcome::Reply(
            ice_config(hub, headers, body, peer).await?,
        ))),
        ("POST", "/api/qr") => Ok(Some(WebOutcome::Reply(qr(hub, headers, body).await?))),
        ("GET", "/view/events") => {
            if head {
                // SSE is not meaningful for HEAD; advertise the stream exists.
                return Ok(Some(WebOutcome::Reply(text(200, "OK", ""))));
            }
            match gate(hub, headers, false).await? {
                Gate::In(session) => Ok(Some(WebOutcome::Events {
                    user: session.user,
                    admin: session.role == "admin",
                })),
                Gate::Out(reply) => Ok(Some(WebOutcome::Reply(reply))),
            }
        }
        ("GET", "/install.sh") => Ok(Some(WebOutcome::Reply(install_sh(hub, headers)))),
        ("GET", "/install.ps1") => Ok(Some(WebOutcome::Reply(install_ps1(hub, headers)))),
        ("GET", "/") | ("GET", "/index.html") | ("GET", "/dashboard") | ("GET", "/dashboard/") => {
            Ok(Some(WebOutcome::Reply(dashboard_page())))
        }
        ("GET", WS_WEB_PATH) => Ok(Some(WebOutcome::Reply(text(
            426,
            "Upgrade Required",
            "terminal and files use a websocket",
        )))),
        ("GET", path) if path.starts_with("/dl/") => Ok(Some(download(hub, path, headers, head))),
        _ => Ok(None),
    }
}

fn dashboard_page() -> HttpReply {
    HttpReply {
        status: 200,
        reason: "OK",
        content_type: "text/html; charset=utf-8",
        body: include_str!("dashboard.html").as_bytes().to_vec(),
        headers: Vec::new(),
        content_length: None,
    }
}

pub async fn dashboard(hub: &Hub, user: &str, admin: bool) -> Result<String> {
    let caller = Caller {
        user: user.to_string(),
        admin,
    };
    let online = server::online_flags(hub);
    let nodes = hub.db().visible(&caller).await?;
    let tokens = hub
        .db()
        .list_tokens(if admin { None } else { Some(user) })
        .await?;
    let now = unix_now();
    Ok(json!({
        "nodes": nodes.into_iter().map(|node| {
            let info = node.info(online.get(&node.node.id).copied().unwrap_or(false));
            json!({
                "id": info.id,
                "name": info.name,
                "hostname": info.hostname,
                "owner": info.owner,
                "relation": info.relation,
                "access": info.access,
                "allow_read": info.effective.allow_read,
                "allow_write": info.effective.allow_write,
                "allow_exec": info.effective.allow_exec,
                "allow_desktop": info.effective.allow_desktop,
                "allow_remote_view": info.effective.allows_remote_view(),
                "allow_remote_control": info.effective.allows_remote_control(),
                "online": info.online,
                "os": info.os,
                "arch": info.arch,
                "version": info.version,
                "last_seen_unix": node.node.last_seen_unix,
                "has_display": info.has_display,
                "effective": info.effective.preset_name(),
            })
        }).collect::<Vec<_>>(),
        "tokens": tokens.into_iter().map(|token| json!({
            "id": token.id,
            "name": token.name,
            "owner": token.owner,
            "access": token.policy.preset_name(),
            "expires_unix": token.expires_unix,
            "uses_remaining": token.uses_remaining,
            "max_uses": token.max_uses,
            "state": token.state(now),
        })).collect::<Vec<_>>(),
    })
    .to_string())
}

pub async fn session_from(hub: &Hub, headers: &[(String, String)]) -> Result<Option<WebSession>> {
    let Some(token) = cookie(headers, "agentlink_session") else {
        return Ok(None);
    };
    hub.db().web_session(&token).await
}

pub fn session_cookie(headers: &[(String, String)]) -> Option<String> {
    cookie(headers, "agentlink_session")
}

async fn login(
    hub: &Hub,
    headers: &[(String, String)],
    body: &[u8],
    peer: std::net::SocketAddr,
) -> Result<HttpReply> {
    if let Some(reply) = login_origin_rejected(headers) {
        return Ok(reply);
    }
    if !server::login_allowed(hub, peer) {
        return Ok(text(429, "Too Many Requests", "too many login attempts"));
    }
    let payload: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let username = payload["username"].as_str().unwrap_or("").trim();
    let password = payload["password"].as_str().unwrap_or("");
    let totp = payload["totp"]
        .as_str()
        .map(str::trim)
        .filter(|code| !code.is_empty());
    match hub.db().check_login(username, password, totp).await {
        Ok(account) => {
            hub.db().note_success(&account.username).await?;
            let (token, session) = hub.db().create_web_session(&account.username).await?;
            server::audit_auth(
                hub.audit_path(),
                "web.login",
                &account.username,
                "web",
                true,
                "",
            );
            let mut reply = json_reply(
                200,
                json!({"ok": true, "user": session.user, "role": session.role}),
            );
            reply
                .headers
                .extend(session_cookies(&token, &session.csrf, WEB_TTL_SECS));
            Ok(reply)
        }
        Err(err) => {
            server::audit_auth(
                hub.audit_path(),
                "web.login",
                username,
                "web",
                false,
                &err.to_string(),
            );
            Ok(text(401, "Unauthorized", &err.to_string()))
        }
    }
}

async fn logout(hub: &Hub, headers: &[(String, String)]) -> Result<HttpReply> {
    let session = match gate(hub, headers, true).await? {
        Gate::Out(reply) => return Ok(reply),
        Gate::In(session) => session,
    };
    if let Some(token) = cookie(headers, "agentlink_session") {
        hub.db().delete_web_session(&token).await?;
    }
    server::audit_auth(
        hub.audit_path(),
        "web.logout",
        &session.user,
        "web",
        true,
        "",
    );
    let mut reply = json_reply(200, json!({"ok": true}));
    reply.headers.extend(session_cookies("", "", 0));
    Ok(reply)
}

async fn session_info(hub: &Hub, headers: &[(String, String)]) -> Result<HttpReply> {
    match gate(hub, headers, false).await? {
        Gate::In(session) => Ok(json_reply(
            200,
            json!({"user": session.user, "role": session.role}),
        )),
        Gate::Out(reply) => Ok(reply),
    }
}

async fn nodes(hub: &Hub, headers: &[(String, String)]) -> Result<HttpReply> {
    let session = match gate(hub, headers, false).await? {
        Gate::Out(reply) => return Ok(reply),
        Gate::In(session) => session,
    };
    let body = dashboard(hub, &session.user, session.role == "admin").await?;
    Ok(HttpReply {
        status: 200,
        reason: "OK",
        content_type: "application/json",
        body: body.into_bytes(),
        headers: Vec::new(),
        content_length: None,
    })
}

async fn tokens(hub: &Hub, headers: &[(String, String)]) -> Result<HttpReply> {
    nodes(hub, headers).await
}

async fn create_token(hub: &Hub, headers: &[(String, String)], body: &[u8]) -> Result<HttpReply> {
    let session = match gate(hub, headers, true).await? {
        Gate::Out(reply) => return Ok(reply),
        Gate::In(session) => session,
    };
    let payload: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let name = payload["name"].as_str().unwrap_or("").trim();
    let access = payload["access"].as_str().unwrap_or("full");
    let ttl = payload["ttl_secs"].as_u64().unwrap_or(15 * 60);
    let uses = payload["uses"].as_u64().unwrap_or(1) as u32;
    let policy = match parse_access(access) {
        Ok(policy) => policy,
        Err(err) => return Ok(text(400, "Bad Request", &err.to_string())),
    };
    let issued = match hub
        .db()
        .create_token(&session.user, name, policy, ttl, uses)
        .await
    {
        Ok(issued) => issued,
        Err(err) => return Ok(text(400, "Bad Request", &err.to_string())),
    };
    server::audit_auth(
        hub.audit_path(),
        "token.create",
        &session.user,
        &issued.id,
        true,
        "",
    );
    let target = enroll_target(&host_header(headers), &fingerprint_of(hub));
    let access = issued.policy.preset_name();
    let android = format!(
        "agentlink://enroll?relay={}&fingerprint={}&token={}&name={}&access={}",
        url_encode(&target.relay),
        url_encode(&target.fingerprint),
        url_encode(&issued.token),
        url_encode(&issued.name),
        url_encode(access),
    );
    let linux = unix_install_command(&target.origin, &issued.token, &issued.name, access);
    let windows = windows_install_command(&target.origin, &issued.token, &issued.name, access);
    let qr_svg = match qr_svg(&android) {
        Ok(svg) => svg,
        Err(err) => return Ok(text(500, "Internal Server Error", &err.to_string())),
    };
    Ok(json_reply(
        200,
        json!({
            "id": issued.id,
            "token": issued.token,
            "name": issued.name,
            "expires_unix": issued.expires_unix,
            "uses": issued.uses,
            "access": issued.policy.preset_name(),
            "command": linux,
            "linux": linux,
            "windows": windows,
            "android": android,
            "qr_svg": qr_svg,
            "relay": target.relay,
            "trust": target.trust,
        }),
    ))
}

async fn revoke_token(hub: &Hub, headers: &[(String, String)], body: &[u8]) -> Result<HttpReply> {
    let session = match gate(hub, headers, true).await? {
        Gate::Out(reply) => return Ok(reply),
        Gate::In(session) => session,
    };
    let payload: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let id = payload["id"].as_str().unwrap_or("");
    let owner = if session.role == "admin" {
        None
    } else {
        Some(session.user.as_str())
    };
    match hub.db().revoke_token(id, owner).await {
        Ok(_) => {
            server::audit_auth(
                hub.audit_path(),
                "token.revoke",
                &session.user,
                id,
                true,
                "",
            );
            Ok(json_reply(200, json!({"ok": true})))
        }
        Err(err) => Ok(text(404, "Not Found", &err.to_string())),
    }
}

async fn view_ticket(
    hub: &Hub,
    headers: &[(String, String)],
    body: &[u8],
    peer: std::net::SocketAddr,
) -> Result<HttpReply> {
    if !server::rate_allow(hub, "ticket", peer.ip(), 30, 60) {
        let mut reply = text(429, "Too Many Requests", "too many view tickets");
        reply.headers.push(("Retry-After".into(), "60".into()));
        return Ok(reply);
    }
    let session = match gate(hub, headers, true).await? {
        Gate::Out(reply) => return Ok(reply),
        Gate::In(session) => session,
    };
    let payload: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let node = payload["node"].as_str().unwrap_or("");
    let control = payload["control"].as_bool().unwrap_or(false);
    match server::issue_web_ticket(hub, &session.user, session.role == "admin", node, control).await
    {
        Ok(issued) => Ok(json_reply(
            200,
            json!({
                "ticket": issued.ticket,
                "node": issued.node_id,
                "expires_unix": issued.expires_unix,
                "control": issued.control,
                "access": issued.access,
            }),
        )),
        Err(err) => Ok(text(403, "Forbidden", &err.to_string())),
    }
}

async fn revoke_view_ticket(
    hub: &Hub,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<HttpReply> {
    let session = match gate(hub, headers, true).await? {
        Gate::Out(reply) => return Ok(reply),
        Gate::In(session) => session,
    };
    let payload: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let ticket = payload["ticket"].as_str().filter(|value| !value.is_empty());
    let node = payload["node"].as_str().filter(|value| !value.is_empty());
    match server::revoke_view_tickets(hub, &session.user, session.role == "admin", ticket, node) {
        Ok(0) => Ok(text(404, "Not Found", "view ticket not found")),
        Ok(removed) => {
            server::audit_auth(
                hub.audit_path(),
                "view.ticket.revoke",
                &session.user,
                ticket.unwrap_or(node.unwrap_or("")),
                true,
                "",
            );
            Ok(json_reply(200, json!({"ok": true, "revoked": removed})))
        }
        Err(err) => Ok(text(400, "Bad Request", &err.to_string())),
    }
}

async fn ice_config(
    hub: &Hub,
    headers: &[(String, String)],
    body: &[u8],
    peer: std::net::SocketAddr,
) -> Result<HttpReply> {
    if !server::rate_allow(hub, "ice", peer.ip(), 60, 60) {
        return Ok(text(429, "Too Many Requests", "too many ice requests"));
    }
    let payload: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let ticket = payload["ticket"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| bearer_token(headers));
    let bound = payload["session"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let presented = match (ticket, bound) {
        (Some(ticket), Some(session)) if !ticket.contains('.') => {
            Some(format!("{ticket}.{session}"))
        }
        (Some(ticket), _) => Some(ticket),
        _ => None,
    };
    if let Some(presented) = presented.as_deref() {
        match server::turn_subject_for_ticket(hub, presented) {
            Ok(subject) => {
                server::audit_auth(hub.audit_path(), "ice.mint", &subject, "ticket", true, "");
                return Ok(ice_reply(&subject));
            }
            Err(err) => {
                return Ok(text(401, "Unauthorized", &err.to_string()));
            }
        }
    }
    let session = match gate(hub, headers, true).await? {
        Gate::Out(reply) => return Ok(reply),
        Gate::In(session) => session,
    };
    let subject = format!("web:{}", session.user);
    server::audit_auth(hub.audit_path(), "ice.mint", &subject, "session", true, "");
    Ok(ice_reply(&subject))
}

fn ice_reply(subject: &str) -> HttpReply {
    let body = crate::view::session_config_json(subject);
    HttpReply {
        status: 200,
        reason: "OK",
        content_type: "application/json",
        body: body.into_bytes(),
        headers: Vec::new(),
        content_length: None,
    }
}

fn bearer_token(headers: &[(String, String)]) -> Option<String> {
    headers.iter().find_map(|(name, value)| {
        if name != "authorization" {
            return None;
        }
        value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty())
    })
}

async fn qr(hub: &Hub, headers: &[(String, String)], body: &[u8]) -> Result<HttpReply> {
    if let Gate::Out(reply) = gate(hub, headers, true).await? {
        return Ok(reply);
    }
    let payload: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let text_value = payload["text"].as_str().unwrap_or("");
    if text_value.is_empty() || text_value.len() > 2048 {
        return Ok(text(400, "Bad Request", "text is required"));
    }
    match qr_svg(text_value) {
        Ok(svg) => Ok(HttpReply {
            status: 200,
            reason: "OK",
            content_type: "image/svg+xml",
            body: svg.into_bytes(),
            headers: Vec::new(),
            content_length: None,
        }),
        Err(err) => Ok(text(400, "Bad Request", &err.to_string())),
    }
}

fn install_sh(hub: &Hub, headers: &[(String, String)]) -> HttpReply {
    let target = enroll_target(&host_header(headers), &fingerprint_of(hub));
    let mut body = script_prelude(&target).into_bytes();
    body.extend_from_slice(include_bytes!("../../../install.sh"));
    HttpReply {
        status: 200,
        reason: "OK",
        content_type: "text/x-shellscript; charset=utf-8",
        body,
        headers: Vec::new(),
        content_length: None,
    }
}

fn install_ps1(hub: &Hub, headers: &[(String, String)]) -> HttpReply {
    let target = enroll_target(&host_header(headers), &fingerprint_of(hub));
    let relay = target.relay.replace('"', "");
    let fingerprint = target.fingerprint.replace('"', "");
    let download = target.download.replace('"', "");
    let mut text = include_str!("../../../install.ps1").to_string();
    text = text.replacen(
        "$AgentlinkServeRelay = \"\"",
        &format!("$AgentlinkServeRelay = \"{relay}\""),
        1,
    );
    text = text.replacen(
        "$AgentlinkServeFingerprint = \"\"",
        &format!("$AgentlinkServeFingerprint = \"{fingerprint}\""),
        1,
    );
    text = text.replacen(
        "$AgentlinkServeDownload = \"\"",
        &format!("$AgentlinkServeDownload = \"{download}\""),
        1,
    );
    text = text.replacen(
        "$AgentlinkServeEnroll = \"0\"",
        "$AgentlinkServeEnroll = \"1\"",
        1,
    );
    HttpReply {
        status: 200,
        reason: "OK",
        content_type: "text/plain; charset=utf-8",
        body: text.into_bytes(),
        headers: Vec::new(),
        content_length: None,
    }
}

fn download(hub: &Hub, path: &str, headers: &[(String, String)], head_only: bool) -> WebOutcome {
    let name = path.trim_start_matches("/dl/");
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return WebOutcome::Reply(text(400, "Bad Request", "invalid file name"));
    }
    // AGENTLINK_DOWNLOAD_BASE defaults to `{origin}/dl`. Agents and docs often
    // fetch `$DOWNLOAD_BASE/install.sh` (or .ps1). Those are not release assets —
    // they are the enroll-aware scripts also served at `/install.sh`. Serving them
    // here avoids a 302 to RELEASE_MIRROR/.../install.sh which 404s.
    if name == "install.sh" {
        return WebOutcome::Reply(install_sh(hub, headers));
    }
    if name == "install.ps1" {
        return WebOutcome::Reply(install_ps1(hub, headers));
    }
    let local = hub.data_dir().join("dist").join(name);
    if local.is_file() {
        let disposition = (
            "Content-Disposition".into(),
            format!("attachment; filename=\"{name}\""),
        );
        if head_only {
            let len = std::fs::metadata(&local)
                .map(|meta| meta.len() as usize)
                .unwrap_or(0);
            return WebOutcome::Reply(HttpReply {
                status: 200,
                reason: "OK",
                content_type: "application/octet-stream",
                body: Vec::new(),
                headers: vec![disposition],
                content_length: Some(len),
            });
        }
        let bytes = std::fs::read(&local).unwrap_or_default();
        return WebOutcome::Reply(HttpReply {
            status: 200,
            reason: "OK",
            content_type: "application/octet-stream",
            body: bytes,
            headers: vec![disposition],
            content_length: None,
        });
    }
    let location = release_download_url(name);
    WebOutcome::Reply(HttpReply {
        status: 302,
        reason: "Found",
        content_type: "text/plain; charset=utf-8",
        body: Vec::new(),
        headers: vec![("Location".into(), location)],
        content_length: None,
    })
}

/// Where `/dl/{name}` redirects when `data-dir/dist` does not have the file.
///
/// Private GitHub repos 404 for anonymous `releases/latest/download/...` fetches,
/// which breaks `install.sh` enroll. Set `AGENTLINK_RELEASE_MIRROR` to a public
/// base such as `https://relay.example/download` that serves the same asset
/// names, or keep the default GitHub URL for public repos.
fn release_download_url(name: &str) -> String {
    let mirror = std::env::var("AGENTLINK_RELEASE_MIRROR")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty());
    release_download_url_with_mirror(name, mirror.as_deref())
}

fn release_download_url_with_mirror(name: &str, mirror: Option<&str>) -> String {
    match mirror.map(str::trim).filter(|value| !value.is_empty()) {
        Some(base) => format!("{}/{name}", base.trim_end_matches('/')),
        None => format!("https://github.com/zltl/agentlink/releases/latest/download/{name}"),
    }
}

enum Gate {
    In(WebSession),
    Out(HttpReply),
}

async fn gate(hub: &Hub, headers: &[(String, String)], csrf: bool) -> Result<Gate> {
    let Some(session) = session_from(hub, headers).await? else {
        return Ok(Gate::Out(text(401, "Unauthorized", "login required")));
    };
    if csrf {
        let presented = header(headers, "x-csrf-token").unwrap_or("");
        if presented.is_empty() || !util::ct_eq(presented, &session.csrf) {
            return Ok(Gate::Out(text(403, "Forbidden", "csrf token rejected")));
        }
    }
    Ok(Gate::In(session))
}

fn session_cookies(token: &str, csrf: &str, max_age: i64) -> Vec<(String, String)> {
    let session = if max_age <= 0 { "" } else { token };
    let csrf_value = if max_age <= 0 { "" } else { csrf };
    vec![
        (
            "Set-Cookie".into(),
            format!(
                "agentlink_session={session}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"
            ),
        ),
        (
            "Set-Cookie".into(),
            format!(
                "agentlink_csrf={csrf_value}; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"
            ),
        ),
    ]
}

fn json_reply(status: u16, value: Value) -> HttpReply {
    let reason = if status == 200 { "OK" } else { "Error" };
    HttpReply {
        status,
        reason,
        content_type: "application/json",
        body: value.to_string().into_bytes(),
        headers: Vec::new(),
        content_length: None,
    }
}

fn text(status: u16, reason: &'static str, message: &str) -> HttpReply {
    HttpReply {
        status,
        reason,
        content_type: "text/plain; charset=utf-8",
        body: message.as_bytes().to_vec(),
        headers: Vec::new(),
        content_length: None,
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Browsers can forge a cross-site login with `text/plain` form bodies.
/// Require JSON, and reject an explicit cross-site Origin or Sec-Fetch-Site.
///
/// The relay accepts this request only on its TLS listener, so the connection
/// scheme is `https`. The browser's `Host` is what nginx forwards (`Host
/// $host`). `X-Forwarded-Host` and `X-Forwarded-Proto` are not consulted: a
/// client that can reach the relay directly must not pick the origin.
fn login_origin_rejected(headers: &[(String, String)]) -> Option<HttpReply> {
    let ctype = header(headers, "content-type").unwrap_or("");
    let mime = ctype.split(';').next().unwrap_or("").trim();
    if !mime.eq_ignore_ascii_case("application/json") {
        return Some(text(
            415,
            "Unsupported Media Type",
            "login requires Content-Type: application/json",
        ));
    }
    if let Some(site) = header(headers, "sec-fetch-site") {
        if site.eq_ignore_ascii_case("cross-site") {
            return Some(text(403, "Forbidden", "cross-site login is not allowed"));
        }
    }
    if let Some(origin) = header(headers, "origin") {
        if !origins_equivalent(origin, header(headers, "host").unwrap_or(""), "https") {
            return Some(text(403, "Forbidden", "cross-origin login is not allowed"));
        }
    }
    None
}

/// True when `origin` is the same scheme, host, and effective port as the
/// request. Default ports are 443 for https and 80 for http. A missing port
/// on either side uses that default; it is not taken from the socket or from
/// a forwarded header.
fn origins_equivalent(origin: &str, host_header: &str, connection_scheme: &str) -> bool {
    let connection_scheme = connection_scheme.trim().to_ascii_lowercase();
    if connection_scheme != "https" && connection_scheme != "http" {
        return false;
    }
    let Some((origin_scheme, origin_host, origin_port)) = parse_origin_parts(origin) else {
        return false;
    };
    if origin_scheme != connection_scheme {
        return false;
    }
    let Some((host, host_port)) = split_host_port(host_header.trim()) else {
        return false;
    };
    if host.is_empty() || !origin_host.eq_ignore_ascii_case(&host) {
        return false;
    }
    let origin_port = origin_port.unwrap_or_else(|| default_http_port(&origin_scheme));
    let host_port = host_port.unwrap_or_else(|| default_http_port(&connection_scheme));
    origin_port != 0 && origin_port == host_port
}

fn default_http_port(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else {
        80
    }
}

fn parse_origin_parts(origin: &str) -> Option<(String, String, Option<u16>)> {
    let origin = origin.trim();
    if origin.is_empty() || origin.eq_ignore_ascii_case("null") {
        return None;
    }
    let (scheme, rest) = origin.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    if hostport.is_empty() || hostport.contains('@') {
        return None;
    }
    let (host, port) = split_host_port(hostport)?;
    Some((scheme, host, port))
}

fn split_host_port(hostport: &str) -> Option<(String, Option<u16>)> {
    if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        let host = hostport[1..end].to_string();
        if host.is_empty() {
            return None;
        }
        let rest = &hostport[end + 1..];
        if rest.is_empty() {
            return Some((host, None));
        }
        let port = rest.strip_prefix(':')?.parse::<u16>().ok()?;
        if port == 0 {
            return None;
        }
        return Some((host, Some(port)));
    }
    if let Some((host, port)) = hostport.rsplit_once(':') {
        if !host.is_empty()
            && !host.contains(':')
            && port.chars().all(|ch| ch.is_ascii_digit())
        {
            let port = port.parse::<u16>().ok()?;
            if port == 0 {
                return None;
            }
            return Some((host.to_string(), Some(port)));
        }
    }
    if hostport.is_empty() {
        None
    } else {
        Some((hostport.to_string(), None))
    }
}

fn cookie(headers: &[(String, String)], name: &str) -> Option<String> {
    let raw = header(headers, "cookie")?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{name}=")) {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn host_header(headers: &[(String, String)]) -> String {
    let host = header(headers, "host").unwrap_or("localhost");
    if host.is_empty()
        || !host
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '-' | '[' | ']'))
    {
        return "localhost".into();
    }
    host.to_string()
}

struct EnrollTarget {
    relay: String,
    fingerprint: String,
    trust: String,
    origin: String,
    download: String,
}

/// Every host is self-hosted. The install command pins that host's leaf
/// certificate. There is no implicit public relay.
fn enroll_target(host: &str, leaf_fingerprint: &str) -> EnrollTarget {
    let origin = format!("https://{host}");
    EnrollTarget {
        relay: format!("wss://{host}"),
        fingerprint: leaf_fingerprint.to_string(),
        trust: String::new(),
        origin: origin.clone(),
        download: format!("{origin}/dl"),
    }
}

fn unix_install_command(origin: &str, token: &str, name: &str, access: &str) -> String {
    format!(
        "curl -fsSL {origin}/install.sh | sh -s -- --token {} --name {} --access {} --max-access {}",
        shell_single(token),
        shell_single(name),
        shell_single(access),
        shell_single(access),
    )
}

fn windows_install_command(origin: &str, token: &str, name: &str, access: &str) -> String {
    format!(
        "& ([scriptblock]::Create((irm {origin}/install.ps1))) -Token {} -Name {} -Access {} -MaxAccess {}",
        ps_single(token),
        ps_single(name),
        ps_single(access),
        ps_single(access),
    )
}

fn shell_single(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn ps_single(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

fn script_prelude(target: &EnrollTarget) -> String {
    let mut prelude = export_default("AGENTLINK_RELAY", &target.relay);
    if !target.fingerprint.is_empty() {
        prelude.push_str(&export_default(
            "AGENTLINK_FINGERPRINT",
            &target.fingerprint,
        ));
    }
    if !target.trust.is_empty() {
        prelude.push_str(&export_default("AGENTLINK_TRUST", &target.trust));
    }
    prelude.push_str(&export_default("AGENTLINK_ENROLL", "1"));
    prelude.push_str(&export_default("AGENTLINK_DOWNLOAD_BASE", &target.download));
    prelude
}

fn export_default(name: &str, value: &str) -> String {
    format!(
        "export {name}=\"${{{name}:-{}}}\"\n",
        sanitize_export(value)
    )
}

fn sanitize_export(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '-' | '+' | '/' | '_'))
        .collect()
}

fn fingerprint_of(hub: &Hub) -> String {
    std::fs::read_to_string(hub.data_dir().join("fingerprint.txt"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn url_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn qr_svg(text: &str) -> Result<String> {
    let code =
        qrcode::QrCode::new(text.as_bytes()).map_err(|err| Error::Message(format!("qr: {err}")))?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_page_is_self_contained() {
        let page = dashboard_page();
        let text = String::from_utf8(page.body).unwrap();
        assert_eq!(page.status, 200);
        assert!(text.contains("id=\"login-user\""));
        assert!(text.contains("id=\"login-pass\""));
        assert!(text.contains("id=\"login-totp-field\" hidden"));
        assert!(text.contains("id=\"login-totp\""));
        assert!(!text.contains("admin.token is only for automation"));
        assert!(text.contains("id=\"install-command\""));
        assert!(text.contains("not available in the browser"));
        assert!(!text.contains("id=\"machine-access\""));
        assert!(!text.contains("No preset to pick"));
        assert!(!text.contains("openSession(\"terminal\""));
        assert!(!text.contains("openSession(\"files\""));
        assert!(!text.contains("desktop-mode"));
        assert!(!text.contains("data-mode"));
        assert!(!text.contains(">View<"));
        assert!(!text.contains(">Control<"));
        assert!(text.contains("control: false"));
        assert!(text.contains("start=watch"));
        assert!(text.contains("View only"));
        assert!(text.contains("仅观看"));
        assert!(text.contains("Screenshots only"));
        assert!(text.contains("aria-pressed"));
        assert!(!text.contains("type = \"checkbox\""));
        assert!(!text.contains("type=\"checkbox\""));
        assert!(text.contains("has_display"));
        assert!(text.contains("id=\"refresh-btn\""));
        assert!(text.contains("Terminal"));
        assert!(text.contains("Files"));
        assert!(text.contains("/v1/web"));
        assert!(text.contains("id=\"session-view\""));
        assert!(text.contains("overscroll-behavior: contain"));
        assert!(text.contains("touch-action: pan-x pan-y"));
        assert!(text.contains("const SCROLLBACK = 1000"));
        // Dashboard term must consume charset designators (ESC ( B); otherwise
        // procps `top` prints a literal B on every attribute reset and looks broken.
        assert!(text.contains("esc-int"));
        assert!(text.contains("()*+-.%/"));
        assert!(text.contains("view.reverse"));
        assert!(text.contains(r#"code === "7""#));
        assert!(text.contains("/download/agentlink.apk"));
        assert!(text.contains("viewport-fit=cover"));
        assert!(text.contains("safe-area-inset"));
        assert!(text.contains("prefers-reduced-motion"));
        assert!(text.contains("rel=\"icon\""));
        assert!(text.contains("id=\"octopus\""));
        assert!(text.contains("min-height: var(--tap)"));
        assert!(text.contains("--tap: 48px"));
        assert!(!text.contains("<script src"));
        let without_svg_ns = text.replace("http://www.w3.org/2000/svg", "");
        assert!(
            !without_svg_ns.contains("http://"),
            "dashboard must not load insecure http URLs"
        );
    }

    #[test]
    fn dl_install_scripts_are_not_mirror_redirects() {
        // Names that must be handled before release_download_url_with_mirror.
        assert_ne!(
            release_download_url_with_mirror("install.sh", Some("https://relay.example/download")),
            "https://relay.example/install.sh"
        );
        // Guard: mirror URL for install.sh is the broken path we must not 302 to
        // from /dl/install.sh when the embedded script should be returned instead.
        assert_eq!(
            release_download_url_with_mirror(
                "install.sh",
                Some("https://relay.example.com/download")
            ),
            "https://relay.example.com/download/install.sh"
        );
        assert_eq!(
            release_download_url_with_mirror(
                "install.ps1",
                Some("https://relay.example.com/download")
            ),
            "https://relay.example.com/download/install.ps1"
        );
    }

    #[test]
    fn release_download_url_prefers_mirror() {
        assert_eq!(
            release_download_url_with_mirror(
                "agentlink-0.1.3-x86_64-unknown-linux-musl.tar.gz",
                None
            ),
            "https://github.com/zltl/agentlink/releases/latest/download/agentlink-0.1.3-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            release_download_url_with_mirror(
                "agentlink.apk",
                Some("https://relay.example.com/download/")
            ),
            "https://relay.example.com/download/agentlink.apk"
        );
    }

    #[test]
    fn every_host_enrolls_against_itself() {
        let public = enroll_target("relay.example.com", "sha256:dead");
        assert_eq!(public.relay, "wss://relay.example.com");
        assert!(public.trust.is_empty());
        assert_eq!(public.fingerprint, "sha256:dead");
        assert_eq!(public.origin, "https://relay.example.com");
        assert_eq!(public.download, "https://relay.example.com/dl");
        let command = unix_install_command(&public.origin, "abc", "lab top", "desktop");
        assert_eq!(
            command,
            "curl -fsSL https://relay.example.com/install.sh | sh -s -- --token 'abc' --name 'lab top' --access 'desktop' --max-access 'desktop'"
        );
        let quoted = unix_install_command(&public.origin, "abc", "o'brien", "read-only");
        assert!(quoted.contains("--name 'o'\\''brien'"), "{quoted}");
        let windows = windows_install_command(&public.origin, "abc", "o'brien", "exec");
        assert!(windows.contains("-Name 'o''brien'"), "{windows}");
        assert!(
            windows.contains("https://relay.example.com/install.ps1"),
            "{windows}"
        );
        let prelude = script_prelude(&public);
        assert!(prelude.contains("wss://relay.example.com"), "{prelude}");
        assert!(prelude.contains("sha256:dead"), "{prelude}");
        assert!(!prelude.contains("AGENTLINK_TRUST"), "{prelude}");

        let local = enroll_target("127.0.0.1:7443", "sha256:beef");
        assert_eq!(local.relay, "wss://127.0.0.1:7443");
        assert_eq!(local.fingerprint, "sha256:beef");
        assert!(local.trust.is_empty());
        let local_prelude = script_prelude(&local);
        assert!(local_prelude.contains("sha256:beef"), "{local_prelude}");
        assert!(
            !local_prelude.contains("AGENTLINK_TRUST"),
            "{local_prelude}"
        );
    }

    #[test]
    fn head_encode_omits_body_keeps_length() {
        let reply = HttpReply {
            status: 200,
            reason: "OK",
            content_type: "text/plain; charset=utf-8",
            body: b"hello-install".to_vec(),
            headers: Vec::new(),
            content_length: None,
        };
        let get = reply.encode_for_method("GET");
        let head = reply.encode_for_method("HEAD");
        let get_text = String::from_utf8_lossy(&get);
        let head_text = String::from_utf8_lossy(&head);
        assert!(get_text.contains("Content-Length: 13"));
        assert!(head_text.contains("Content-Length: 13"));
        assert!(get_text.ends_with("hello-install"));
        assert!(!head_text.contains("hello-install"));
        assert!(head.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn head_content_length_override_without_body() {
        let reply = HttpReply {
            status: 200,
            reason: "OK",
            content_type: "application/octet-stream",
            body: Vec::new(),
            headers: Vec::new(),
            content_length: Some(13_000_000),
        };
        let encoded = reply.encode_for_method("HEAD");
        let head = String::from_utf8_lossy(&encoded);
        assert!(head.contains("Content-Length: 13000000"), "{head}");
        assert!(encoded.ends_with(b"\r\n\r\n"));
    }

    fn login_headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn login_origin_binds_scheme_host_and_effective_port() {
        let allow = |pairs: &[(&str, &str)]| login_origin_rejected(&login_headers(pairs)).is_none();
        let json = ("content-type", "application/json");
        assert!(allow(&[
            json,
            ("host", "relay.example.com"),
            ("origin", "https://relay.example.com"),
        ]));
        assert!(
            allow(&[
                json,
                ("host", "relay.example.com"),
                ("origin", "https://relay.example.com:443"),
            ]),
            "explicit 443 matches a host header without a port"
        );
        assert!(allow(&[
            json,
            ("host", "127.0.0.1:7443"),
            ("origin", "https://127.0.0.1:7443"),
        ]));
        assert!(allow(&[
            json,
            ("host", "[::1]:7443"),
            ("origin", "https://[::1]:7443"),
        ]));
        assert!(!allow(&[
            json,
            ("host", "relay.example.com"),
            ("origin", "http://relay.example.com"),
        ]));
        assert!(!allow(&[
            json,
            ("host", "relay.example.com:7443"),
            ("origin", "https://relay.example.com"),
        ]));
        assert!(!allow(&[
            json,
            ("host", "relay.example.com"),
            ("origin", "https://relay.example.com.evil"),
        ]));
        assert!(!allow(&[
            json,
            ("host", "127.0.0.1:7443"),
            ("origin", "https://evil.example"),
            ("x-forwarded-host", "evil.example"),
            ("x-forwarded-proto", "https"),
        ]));
        assert!(
            allow(&[
                json,
                ("host", "relay.example.com"),
                ("origin", "https://relay.example.com"),
                ("x-forwarded-host", "evil.example"),
                ("x-forwarded-proto", "http"),
            ]),
            "a forwarded header must not override a matching Host"
        );
        assert!(allow(&[json, ("host", "relay.example.com")]));
    }
}
