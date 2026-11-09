//! Static `/operate` page. The node metadata lives in the URL fragment and is
//! decoded by the browser. The relay never sees the fragment, and the page
//! mints nothing: no grant, ticket, session, or pairing token.

const PAGE: &str = include_str!("operate.html");

pub fn response_for(head: &str) -> Option<Vec<u8>> {
    let mut lines = head.lines();
    let request = lines.next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/").split('?').next().unwrap_or("/");
    let head_only = method.eq_ignore_ascii_case("HEAD");
    if method != "GET" && !head_only {
        return None;
    }
    match path {
        "/operate" | "/operate/" | "/operate/index.html" => {}
        _ => return None,
    }
    let body = PAGE.as_bytes();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = header.into_bytes();
    if !head_only {
        out.extend_from_slice(body);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_for(request: &str) -> String {
        String::from_utf8(response_for(request).unwrap()).unwrap()
    }

    #[test]
    fn operate_page_is_served_for_get_and_head() {
        for path in ["/operate", "/operate/", "/operate/index.html"] {
            let get = text_for(&format!("GET {path} HTTP/1.1"));
            assert!(get.contains("200 OK"), "{path}");
            assert!(get.contains("text/html"), "{path}");
            assert!(
                get.contains("Documentation only — this link does not grant access."),
                "{path}"
            );
            assert!(get.contains("Copy page URL"), "{path}");
            assert!(get.contains("SignedGrant"), "{path}");
            assert!(get.contains("agentlink guide"), "{path}");
            assert!(get.contains("port forward"), "{path}");

            let head = text_for(&format!("HEAD {path} HTTP/1.1"));
            assert!(head.contains("200 OK"), "{path}");
            assert!(head.contains("Content-Length:"), "{path}");
            assert!(!head.contains("<!doctype html>"), "{path}");
        }
    }

    #[test]
    fn operate_page_shows_pasteable_guide_and_trust_owner_rows() {
        let page = text_of_page();
        assert!(page.contains("agentlink guide &lt;node&gt; --print-only"));
        assert!(page.contains("agentlink guide --local --print-only"));
        assert!(page.contains("dashboard <strong>Guide</strong>"));
        assert!(page.contains(
            "agentlink grant trust-owner <issuer-hex> --data-dir ~/.local/share/agentlink/node"
        ));
        assert!(page.contains("agentlink grant show --node "));
    }

    #[test]
    fn operate_page_does_not_mint_or_embed_credentials() {
        let page = text_of_page();
        assert!(page.contains("this link does not grant access"));
        assert!(!page.contains("/api/view-ticket"));
        assert!(!page.contains("agentlink_session"));
        assert!(!page.contains("refresh_token"));
        assert!(!page.contains("pairing_token"));
        assert!(!page.contains("<script src"));
        assert!(!page.contains("<link rel=\"stylesheet\""));
    }

    fn text_of_page() -> String {
        String::from_utf8(PAGE.as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn other_paths_are_not_the_operate_page() {
        assert!(response_for("GET /view HTTP/1.1").is_none());
        assert!(response_for("POST /operate HTTP/1.1").is_none());
        assert!(response_for("GET /operate/other HTTP/1.1").is_none());
    }
}
