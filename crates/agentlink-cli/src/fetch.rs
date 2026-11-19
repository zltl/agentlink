//! Small HTTPS GET client for GitHub Releases.
//!
//! Uses the same rustls ring provider as the relay pin. GitHub's certificate
//! comes from the webpki root set, which is separate from the relay pin: the
//! release host is a public site, and the bytes are still checksummed.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::Url;

const MAX_BODY: usize = 128 * 1024 * 1024;
const HEADER_LIMIT: usize = 64 * 1024;

#[allow(dead_code)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub final_url: String,
}

#[allow(dead_code)]
pub async fn https_get(url: &str, accept: &str) -> Result<Response> {
    https_get_auth(url, accept, None).await
}

/// HTTPS GET with an optional `Authorization` header (for private GitHub
/// Releases). Callers pass the full header value, for example `Bearer <token>`.
pub async fn https_get_auth(
    url: &str,
    accept: &str,
    authorization: Option<&str>,
) -> Result<Response> {
    https_get_redirects(url, accept, authorization, 5).await
}

async fn https_get_redirects(
    url: &str,
    accept: &str,
    authorization: Option<&str>,
    left: u8,
) -> Result<Response> {
    if left == 0 {
        bail!("too many redirects fetching {url}");
    }
    let parsed = Url::parse(url).with_context(|| format!("url {url}"))?;
    if parsed.scheme() != "https" {
        bail!("refusing non-https URL {url}");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("URL {url} has no host"))?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let response = timeout(
        Duration::from_secs(120),
        fetch_once(&parsed, &host, port, accept, authorization),
    )
    .await
    .map_err(|_| anyhow!("timed out fetching {url}"))??;
    if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
        let location = response
            .location
            .ok_or_else(|| anyhow!("redirect from {url} has no Location"))?;
        let next = parsed
            .join(&location)
            .with_context(|| format!("redirect location {location}"))?;
        // Keep the token on GitHub API/origin only. CDN hosts
        // (*.githubusercontent.com) use signed URLs; forwarding Authorization
        // there conflicts with the pre-signed query and can yield 400/401.
        let next_auth = redirect_authorization(next.host_str(), authorization);
        return Box::pin(https_get_redirects(next.as_str(), accept, next_auth, left - 1)).await;
    }
    if !(200..300).contains(&response.status) {
        let snippet = String::from_utf8_lossy(&response.body);
        let snippet = snippet.chars().take(200).collect::<String>();
        bail!("GET {url} returned {}\n{snippet}", response.status);
    }
    Ok(Response {
        status: response.status,
        body: response.body,
        final_url: url.to_string(),
    })
}

fn redirect_authorization<'a>(host: Option<&str>, authorization: Option<&'a str>) -> Option<&'a str> {
    match host {
        Some("api.github.com") | Some("github.com") => authorization,
        _ => None,
    }
}

struct RawResponse {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

async fn fetch_once(
    url: &Url,
    host: &str,
    port: u16,
    accept: &str,
    authorization: Option<&str>,
) -> Result<RawResponse> {
    agentlink_core::tls::install_ring();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("invalid TLS name {host}"))?;
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connect {host}:{port}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("tls {host}"))?;

    let path = request_path(url);
    let host_header = if port == 443 {
        host.to_string()
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let version = crate::version::current();
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: agentlink/{version}\r\nAccept: {accept}\r\n"
    );
    if let Some(auth) = authorization {
        if auth.chars().any(|c| c == '\r' || c == '\n') {
            bail!("authorization header must be a single line");
        }
        request.push_str("Authorization: ");
        request.push_str(auth);
        request.push_str("\r\n");
    }
    request.push_str("Connection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await?;

    let mut buf = Vec::new();
    let header_end = read_headers(&mut tls, &mut buf).await?;
    let header_text = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| anyhow!("response headers are not utf-8"))?;
    let (status, headers) = parse_headers(header_text)?;
    let body = read_body(&mut tls, &mut buf, header_end, &headers).await?;
    let location = header_value(&headers, "location").map(str::to_string);
    Ok(RawResponse {
        status,
        location,
        body,
    })
}

fn request_path(url: &Url) -> String {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path = "/".into();
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

async fn read_headers(
    stream: &mut (impl AsyncReadExt + Unpin),
    buf: &mut Vec<u8>,
) -> Result<usize> {
    let mut tmp = [0u8; 8192];
    loop {
        if let Some(pos) = find_header_end(buf) {
            return Ok(pos);
        }
        if buf.len() > HEADER_LIMIT {
            bail!("response headers are too large");
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("connection closed before HTTP headers");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_headers(text: &str) -> Result<(u16, Vec<(String, String)>)> {
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| anyhow!("empty HTTP status"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| anyhow!("bad HTTP status line: {status_line}"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Ok((status, headers))
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

async fn read_body(
    stream: &mut (impl AsyncReadExt + Unpin),
    buf: &mut Vec<u8>,
    header_end: usize,
    headers: &[(String, String)],
) -> Result<Vec<u8>> {
    let encoding = header_value(headers, "transfer-encoding").unwrap_or("");
    if encoding.to_ascii_lowercase().contains("chunked") {
        return read_chunked(stream, buf, header_end).await;
    }
    if let Some(length) = header_value(headers, "content-length") {
        let length: usize = length
            .parse()
            .with_context(|| format!("content-length {length}"))?;
        if length > MAX_BODY {
            bail!("response is larger than {MAX_BODY} bytes");
        }
        while buf.len() < header_end + length {
            let mut tmp = [0u8; 8192];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                bail!("connection closed before the body finished");
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > header_end + MAX_BODY {
                bail!("response is larger than {MAX_BODY} bytes");
            }
        }
        return Ok(buf[header_end..header_end + length].to_vec());
    }
    let mut tmp = [0u8; 8192];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > header_end + MAX_BODY {
            bail!("response is larger than {MAX_BODY} bytes");
        }
    }
    Ok(buf[header_end..].to_vec())
}

async fn read_chunked(
    stream: &mut (impl AsyncReadExt + Unpin),
    buf: &mut Vec<u8>,
    mut pos: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = read_until_crlf(stream, buf, pos).await?;
        let line = std::str::from_utf8(&buf[pos..line_end])
            .map_err(|_| anyhow!("chunk size is not utf-8"))?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("chunk size {size_hex}"))?;
        pos = line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        if size > MAX_BODY || out.len() + size > MAX_BODY {
            bail!("response is larger than {MAX_BODY} bytes");
        }
        while buf.len() < pos + size + 2 {
            let mut tmp = [0u8; 8192];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                bail!("connection closed in a chunk");
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        out.extend_from_slice(&buf[pos..pos + size]);
        if &buf[pos + size..pos + size + 2] != b"\r\n" {
            bail!("chunk is missing its trailing CRLF");
        }
        pos += size + 2;
    }
}

async fn read_until_crlf(
    stream: &mut (impl AsyncReadExt + Unpin),
    buf: &mut Vec<u8>,
    start: usize,
) -> Result<usize> {
    loop {
        if let Some(rel) = buf[start..].windows(2).position(|w| w == b"\r\n") {
            return Ok(start + rel);
        }
        if buf.len() > start + HEADER_LIMIT {
            bail!("HTTP chunk header is too large");
        }
        let mut tmp = [0u8; 1024];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("connection closed while reading a chunk header");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_and_headers() {
        let (status, headers) =
            parse_headers("HTTP/1.1 302 Found\r\nLocation: https://example/a\r\n\r\n").unwrap();
        assert_eq!(status, 302);
        assert_eq!(
            header_value(&headers, "location"),
            Some("https://example/a")
        );
    }

    #[test]
    fn finds_header_terminator() {
        let buf = b"HTTP/1.1 200 OK\r\n\r\nhello";
        assert_eq!(find_header_end(buf), Some(19));
    }

    #[test]
    fn redirect_keeps_authorization_only_on_github_origin() {
        let auth = Some("Bearer ghp_test");
        assert_eq!(
            redirect_authorization(Some("api.github.com"), auth),
            auth
        );
        assert_eq!(redirect_authorization(Some("github.com"), auth), auth);
        assert_eq!(
            redirect_authorization(Some("objects.githubusercontent.com"), auth),
            None,
            "CDN redirects must drop Authorization"
        );
        assert_eq!(
            redirect_authorization(Some("release-assets.githubusercontent.com"), auth),
            None
        );
        assert_eq!(redirect_authorization(Some("example.com"), auth), None);
        assert_eq!(redirect_authorization(None, auth), None);
    }
}
