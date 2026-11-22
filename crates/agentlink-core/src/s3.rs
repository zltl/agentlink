//! Minimal S3 client for audit sinks.
//!
//! Speaks path-style or virtual-hosted HTTPS (or HTTP, for MinIO) with AWS
//! Signature Version 4. Credentials come from the environment, a shared
//! credentials file, or the instance metadata service. Server-side encryption
//! is a request header. Client-side encryption is AES-256-GCM with a key from
//! an environment variable, applied before the bytes leave the process.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    pub endpoint: String,
    #[serde(default = "default_region")]
    pub region: String,
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub path_style: bool,
    /// `env`, `file`, or `iam`.
    #[serde(default = "default_creds")]
    pub credentials: String,
    #[serde(default)]
    pub credential_file: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    /// `AES256`, `aws:kms`, or empty.
    #[serde(default)]
    pub sse: String,
    /// Name of an env var that holds a 64-character hex AES-256 key.
    #[serde(default)]
    pub client_key_env: String,
}

fn default_region() -> String {
    "us-east-1".into()
}

fn default_creds() -> String {
    "env".into()
}

impl S3Config {
    pub fn validate(&self) -> Result<()> {
        if self.bucket.is_empty() {
            return Err(Error::Message("s3 bucket is required".into()));
        }
        if self.endpoint.is_empty() {
            return Err(Error::Message("s3 endpoint is required".into()));
        }
        if !matches!(self.credentials.as_str(), "env" | "file" | "iam") {
            return Err(Error::Message(
                "s3 credentials must be env, file, or iam".into(),
            ));
        }
        if !self.sse.is_empty() && !matches!(self.sse.as_str(), "AES256" | "aws:kms") {
            return Err(Error::Message(
                "s3 sse must be AES256, aws:kms, or empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

impl Credentials {
    pub fn resolve(config: &S3Config) -> Result<Self> {
        match config.credentials.as_str() {
            "env" => from_env(),
            "file" => from_file(
                config.credential_file.as_deref(),
                config.profile.as_deref().unwrap_or("default"),
            ),
            "iam" => from_iam(),
            other => Err(Error::Message(format!("unknown credentials '{other}'"))),
        }
    }
}

fn from_env() -> Result<Credentials> {
    let access_key = std::env::var("AWS_ACCESS_KEY_ID")
        .map_err(|_| Error::Message("AWS_ACCESS_KEY_ID is not set".into()))?;
    let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
        .map_err(|_| Error::Message("AWS_SECRET_ACCESS_KEY is not set".into()))?;
    let session_token = std::env::var("AWS_SESSION_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    Ok(Credentials {
        access_key,
        secret_key,
        session_token,
    })
}

fn from_file(path: Option<&str>, profile: &str) -> Result<Credentials> {
    let path = match path {
        Some(path) => std::path::PathBuf::from(path),
        None => {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .map_err(|_| {
                    Error::Message("cannot locate a home directory for AWS credentials".into())
                })?;
            std::path::PathBuf::from(home)
                .join(".aws")
                .join("credentials")
        }
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Error::Message(format!("read {}: {e}", path.display())))?;
    let mut current = String::new();
    let mut access = None;
    let mut secret = None;
    let mut token = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            current = name.trim().to_string();
            continue;
        }
        if current != profile {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "aws_access_key_id" => access = Some(value.trim().to_string()),
                "aws_secret_access_key" => secret = Some(value.trim().to_string()),
                "aws_session_token" => token = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    Ok(Credentials {
        access_key: access
            .ok_or_else(|| Error::Message(format!("profile {profile} has no access key")))?,
        secret_key: secret
            .ok_or_else(|| Error::Message(format!("profile {profile} has no secret key")))?,
        session_token: token.filter(|s| !s.is_empty()),
    })
}

fn from_iam() -> Result<Credentials> {
    if let Ok(relative) = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
        let url = format!("http://169.254.170.2{relative}");
        return iam_json(&url, None);
    }
    let token = ureq_get(
        "http://169.254.169.254/latest/api/token",
        &[("X-aws-ec2-metadata-token-ttl-seconds", "60")],
        "PUT",
    )?;
    let role = ureq_get(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        &[("X-aws-ec2-metadata-token", token.trim())],
        "GET",
    )?;
    let role = role.lines().next().unwrap_or("").trim();
    if role.is_empty() {
        return Err(Error::Message(
            "instance metadata returned no IAM role".into(),
        ));
    }
    let url = format!("http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}");
    iam_json(&url, Some(token.trim()))
}

fn iam_json(url: &str, token: Option<&str>) -> Result<Credentials> {
    let mut headers = Vec::new();
    if let Some(token) = token {
        headers.push(("X-aws-ec2-metadata-token", token));
    }
    let body = ureq_get(url, &headers, "GET")?;
    let value: serde_json::Value = serde_json::from_str(&body)?;
    Ok(Credentials {
        access_key: value["AccessKeyId"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        secret_key: value["SecretAccessKey"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        session_token: value["Token"].as_str().map(|s| s.to_string()),
    })
}

fn ureq_get(url: &str, headers: &[(&str, &str)], method: &str) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| Error::Message(e.to_string()))?;
    let mut req = match method {
        "PUT" => client.put(url),
        _ => client.get(url),
    };
    for (key, value) in headers {
        req = req.header(*key, *value);
    }
    let response = req
        .send()
        .map_err(|e| Error::Message(format!("iam metadata: {e}")))?;
    if !response.status().is_success() {
        return Err(Error::Message(format!(
            "iam metadata status {}",
            response.status()
        )));
    }
    response
        .text()
        .map_err(|e| Error::Message(format!("iam metadata: {e}")))
}

#[derive(Debug, Clone)]
pub struct S3Object {
    pub key: String,
    pub body: Vec<u8>,
}

pub struct S3Client {
    config: S3Config,
    creds: Credentials,
    http: reqwest::blocking::Client,
}

impl S3Client {
    pub fn new(config: S3Config) -> Result<Self> {
        config.validate()?;
        let creds = Credentials::resolve(&config)?;
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Message(e.to_string()))?;
        Ok(Self {
            config,
            creds,
            http,
        })
    }

    pub fn put(&self, key: &str, body: &[u8], content_type: &str) -> Result<()> {
        let key = full_key(&self.config, key);
        let body = maybe_encrypt(&self.config, &key, body)?;
        let (url, host, canonical_uri) = self.location(&key)?;
        let payload_hash = sha256_hex(&body);
        let now = amz_now();
        let mut headers = signed_headers(
            &self.config,
            &self.creds,
            "PUT",
            &canonical_uri,
            &host,
            &payload_hash,
            &now,
            content_type,
        );
        headers.insert("content-type".into(), content_type.into());
        let auth = headers.remove("authorization").unwrap_or_default();
        let mut req = self.http.put(url).header("authorization", auth);
        for (key, value) in &headers {
            req = req.header(key, value);
        }
        let response = req
            .body(body)
            .send()
            .map_err(|e| Error::Message(format!("s3 put: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            return Err(Error::Message(format!("s3 put {status}: {text}")));
        }
        Ok(())
    }

    /// Create the configured bucket. An "already exists" response is success.
    pub fn create_bucket(&self) -> Result<()> {
        let endpoint = self.config.endpoint.trim_end_matches('/');
        let url_base = reqwest::Url::parse(endpoint)
            .map_err(|e| Error::Message(format!("s3 endpoint: {e}")))?;
        let host = url_base
            .host_str()
            .ok_or_else(|| Error::Message("s3 endpoint has no host".into()))?
            .to_string();
        let port = url_base.port();
        let host_header = match port {
            Some(port) if port != 80 && port != 443 => format!("{host}:{port}"),
            _ => host.clone(),
        };
        let (url, host_header, canonical) = if self.config.path_style {
            let canonical = format!("/{}", self.config.bucket);
            (format!("{endpoint}{canonical}"), host_header, canonical)
        } else {
            let scheme = url_base.scheme();
            let url = match port {
                Some(port) => format!("{scheme}://{}.{host}:{port}/", self.config.bucket),
                None => format!("{scheme}://{}.{host}/", self.config.bucket),
            };
            (
                url,
                format!("{}.{}", self.config.bucket, host_header),
                "/".into(),
            )
        };
        let payload_hash = EMPTY_HASH.to_string();
        let now = amz_now();
        let headers = signed_headers(
            &self.config,
            &self.creds,
            "PUT",
            &canonical,
            &host_header,
            &payload_hash,
            &now,
            "",
        );
        let auth = headers.get("authorization").cloned().unwrap_or_default();
        let mut req = self.http.put(url).header("authorization", auth);
        for (key, value) in &headers {
            if key != "authorization" {
                req = req.header(key, value);
            }
        }
        let response = req
            .body(Vec::<u8>::new())
            .send()
            .map_err(|e| Error::Message(format!("s3 create bucket: {e}")))?;
        if response.status().is_success() || response.status().as_u16() == 409 {
            return Ok(());
        }
        let status = response.status();
        let text = response.text().unwrap_or_default();
        Err(Error::Message(format!("s3 create bucket {status}: {text}")))
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        let key = full_key(&self.config, key);
        let (url, host, canonical_uri) = self.location(&key)?;
        let payload_hash = EMPTY_HASH.to_string();
        let now = amz_now();
        let headers = signed_headers(
            &self.config,
            &self.creds,
            "GET",
            &canonical_uri,
            &host,
            &payload_hash,
            &now,
            "",
        );
        let auth = headers.get("authorization").cloned().unwrap_or_default();
        let mut req = self.http.get(url).header("authorization", auth);
        for (key, value) in &headers {
            if key == "authorization" {
                continue;
            }
            req = req.header(key, value);
        }
        let response = req
            .send()
            .map_err(|e| Error::Message(format!("s3 get: {e}")))?;
        if !response.status().is_success() {
            return Err(Error::Message(format!("s3 get {}", response.status())));
        }
        let bytes = response
            .bytes()
            .map_err(|e| Error::Message(format!("s3 get: {e}")))?
            .to_vec();
        maybe_decrypt(&self.config, &key, &bytes)
    }

    pub fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let prefix = full_key(&self.config, prefix);
        let mut keys = Vec::new();
        let mut token = String::new();
        loop {
            let mut query = format!("list-type=2&prefix={}", aws_encode(&prefix));
            if !token.is_empty() {
                query.push_str("&continuation-token=");
                query.push_str(&aws_encode(&token));
            }
            let (url, host, canonical_uri) = self.location("")?;
            let payload_hash = EMPTY_HASH.to_string();
            let now = amz_now();
            let headers = signed_headers_query(
                &self.config,
                &self.creds,
                "GET",
                &canonical_uri,
                &query,
                &host,
                &payload_hash,
                &now,
            );
            let auth = headers.get("authorization").cloned().unwrap_or_default();
            let mut req = self
                .http
                .get(format!("{url}?{query}"))
                .header("authorization", auth);
            for (key, value) in &headers {
                if key != "authorization" {
                    req = req.header(key, value);
                }
            }
            let response = req
                .send()
                .map_err(|e| Error::Message(format!("s3 list: {e}")))?;
            if !response.status().is_success() {
                return Err(Error::Message(format!("s3 list {}", response.status())));
            }
            let text = response
                .text()
                .map_err(|e| Error::Message(format!("s3 list: {e}")))?;
            keys.extend(xml_tags(&text, "Key"));
            if xml_tags(&text, "IsTruncated").first().map(String::as_str) == Some("true") {
                token = xml_tags(&text, "NextContinuationToken")
                    .into_iter()
                    .next()
                    .unwrap_or_default();
                if token.is_empty() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(keys)
    }

    pub fn delete(&self, key: &str) -> Result<()> {
        let key = full_key(&self.config, key);
        let (url, host, canonical_uri) = self.location(&key)?;
        let payload_hash = EMPTY_HASH.to_string();
        let now = amz_now();
        let headers = signed_headers(
            &self.config,
            &self.creds,
            "DELETE",
            &canonical_uri,
            &host,
            &payload_hash,
            &now,
            "",
        );
        let auth = headers.get("authorization").cloned().unwrap_or_default();
        let mut req = self.http.delete(url).header("authorization", auth);
        for (key, value) in &headers {
            if key != "authorization" {
                req = req.header(key, value);
            }
        }
        let response = req
            .send()
            .map_err(|e| Error::Message(format!("s3 delete: {e}")))?;
        if !response.status().is_success() && response.status().as_u16() != 404 {
            return Err(Error::Message(format!("s3 delete {}", response.status())));
        }
        Ok(())
    }

    fn location(&self, key: &str) -> Result<(String, String, String)> {
        let endpoint = self.config.endpoint.trim_end_matches('/');
        let url_base = reqwest::Url::parse(endpoint)
            .map_err(|e| Error::Message(format!("s3 endpoint: {e}")))?;
        let host = url_base
            .host_str()
            .ok_or_else(|| Error::Message("s3 endpoint has no host".into()))?
            .to_string();
        let port = url_base.port();
        let host_header = match port {
            Some(port) if port != 80 && port != 443 => format!("{host}:{port}"),
            _ => host.clone(),
        };
        let key = key.trim_start_matches('/');
        if self.config.path_style {
            let canonical = format!("/{}/{}", self.config.bucket, aws_encode_path(key));
            let url = format!("{endpoint}{canonical}");
            Ok((url, host_header, canonical))
        } else {
            let canonical = format!("/{}", aws_encode_path(key));
            let scheme = url_base.scheme();
            let url = match port {
                Some(port) => format!("{scheme}://{}.{host}:{port}{canonical}", self.config.bucket),
                None => format!("{scheme}://{}.{host}{canonical}", self.config.bucket),
            };
            Ok((
                url,
                format!("{}.{}", self.config.bucket, host_header),
                canonical,
            ))
        }
    }
}

pub fn object_key(node_id: &str, day: &str, kind: &str, name: &str) -> String {
    let day = day.replace('-', "/");
    format!("{node_id}/{day}/{kind}/{name}")
}

fn full_key(config: &S3Config, key: &str) -> String {
    let prefix = config.prefix.trim_matches('/');
    if prefix.is_empty() {
        key.trim_start_matches('/').to_string()
    } else {
        format!("{prefix}/{}", key.trim_start_matches('/'))
    }
}

const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn signed_headers(
    config: &S3Config,
    creds: &Credentials,
    method: &str,
    canonical_uri: &str,
    host: &str,
    payload_hash: &str,
    amz_date: &str,
    content_type: &str,
) -> BTreeMap<String, String> {
    let mut headers = base_headers(config, creds, method, host, payload_hash, amz_date);
    if !content_type.is_empty() {
        headers.insert("content-type".into(), content_type.into());
    }
    let auth = sign(
        creds,
        &config.region,
        method,
        canonical_uri,
        "",
        &headers,
        payload_hash,
        amz_date,
    );
    headers.insert("authorization".into(), auth);
    headers
}

fn base_headers(
    config: &S3Config,
    creds: &Credentials,
    method: &str,
    host: &str,
    payload_hash: &str,
    amz_date: &str,
) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    headers.insert("host".into(), host.to_string());
    headers.insert("x-amz-content-sha256".into(), payload_hash.to_string());
    headers.insert("x-amz-date".into(), amz_date.to_string());
    if !config.sse.is_empty() && method != "GET" && method != "DELETE" {
        headers.insert("x-amz-server-side-encryption".into(), config.sse.clone());
    }
    if let Some(token) = &creds.session_token {
        headers.insert("x-amz-security-token".into(), token.clone());
    }
    headers
}

fn signed_headers_query(
    config: &S3Config,
    creds: &Credentials,
    method: &str,
    canonical_uri: &str,
    query: &str,
    host: &str,
    payload_hash: &str,
    amz_date: &str,
) -> BTreeMap<String, String> {
    let mut headers = base_headers(config, creds, method, host, payload_hash, amz_date);
    let signed = sign(
        creds,
        config.region.as_str(),
        method,
        canonical_uri,
        query,
        &headers,
        payload_hash,
        amz_date,
    );
    headers.insert("authorization".into(), signed);
    headers
}

pub fn sign(
    creds: &Credentials,
    region: &str,
    method: &str,
    canonical_uri: &str,
    query: &str,
    headers: &BTreeMap<String, String>,
    payload_hash: &str,
    amz_date: &str,
) -> String {
    let date = &amz_date[..8];
    let mut names = Vec::new();
    let mut canonical_headers = String::new();
    let mut filtered: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in headers {
        let key = key.to_ascii_lowercase();
        if key == "authorization" {
            continue;
        }
        filtered.insert(key, value.trim().to_string());
    }
    for (key, value) in &filtered {
        names.push(key.clone());
        canonical_headers.push_str(key);
        canonical_headers.push(':');
        canonical_headers.push_str(value);
        canonical_headers.push('\n');
    }
    let signed_headers = names.join(";");
    let canonical = format!(
        "{method}\n{canonical_uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let k_date = hmac_sha256(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key
    )
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn amz_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    chrono_stamp(secs)
}

fn chrono_stamp(secs: u64) -> String {
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap());
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}

fn aws_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn aws_encode_path(path: &str) -> String {
    path.split('/')
        .map(aws_encode)
        .collect::<Vec<_>>()
        .join("/")
}

fn xml_tags(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        if let Some(end) = after.find(&close) {
            out.push(after[..end].to_string());
            rest = &after[end + close.len()..];
        } else {
            break;
        }
    }
    out
}

const CSE_MAGIC: &[u8] = b"AGLKCSE1";

fn cse_aad(bucket: &str, full_key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(bucket.len() + 1 + full_key.len());
    aad.extend_from_slice(bucket.as_bytes());
    aad.push(b'/');
    aad.extend_from_slice(full_key.as_bytes());
    aad
}

fn zeroize_key(key: &mut [u8; 32]) {
    for b in key.iter_mut() {
        *b = std::hint::black_box(0);
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn maybe_encrypt(config: &S3Config, full_key: &str, body: &[u8]) -> Result<Vec<u8>> {
    let Some(mut key) = client_key(config)? else {
        return Ok(body.to_vec());
    };
    let cipher = Aes256Gcm::new((&key).into());
    zeroize_key(&mut key);
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = cse_aad(&config.bucket, full_key);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: body,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Message("client-side encryption failed".into()))?;
    let mut out = Vec::with_capacity(CSE_MAGIC.len() + 12 + ct.len());
    out.extend_from_slice(CSE_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn maybe_decrypt(config: &S3Config, full_key: &str, body: &[u8]) -> Result<Vec<u8>> {
    let Some(mut key) = client_key(config)? else {
        return Ok(body.to_vec());
    };
    if body.len() < CSE_MAGIC.len() + 12 + 16 || !body.starts_with(CSE_MAGIC) {
        zeroize_key(&mut key);
        return Err(Error::Message(
            "client-side decryption failed: missing or truncated AGLKCSE1 envelope".into(),
        ));
    }
    let nonce = Nonce::from_slice(&body[CSE_MAGIC.len()..CSE_MAGIC.len() + 12]);
    let cipher = Aes256Gcm::new((&key).into());
    zeroize_key(&mut key);
    let aad = cse_aad(&config.bucket, full_key);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &body[CSE_MAGIC.len() + 12..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::Message("client-side decryption failed".into()))
}

fn client_key(config: &S3Config) -> Result<Option<[u8; 32]>> {
    if config.client_key_env.is_empty() {
        return Ok(None);
    }
    let raw = std::env::var(&config.client_key_env).map_err(|_| {
        Error::Message(format!(
            "{} is not set for client-side encryption",
            config.client_key_env
        ))
    })?;
    let bytes =
        hex::decode(raw.trim()).map_err(|e| Error::Message(format!("s3 client key: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Message("s3 client key must be 32 bytes".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(Some(key))
}

/// Signing entry used by tests and by a mock that wants to check a header.
pub fn authorization_signature(header: &str) -> Option<&str> {
    header.split("Signature=").nth(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn official_sigv4_get_object_vector() {
        let creds = Credentials {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let mut headers = BTreeMap::new();
        headers.insert("host".into(), "examplebucket.s3.amazonaws.com".into());
        headers.insert("range".into(), "bytes=0-9".into());
        headers.insert("x-amz-content-sha256".into(), EMPTY_HASH.into());
        headers.insert("x-amz-date".into(), "20130524T000000Z".into());
        let header = sign(
            &creds,
            "us-east-1",
            "GET",
            "/test.txt",
            "",
            &headers,
            EMPTY_HASH,
            "20130524T000000Z",
        );
        assert_eq!(
            authorization_signature(&header),
            Some("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
        );
    }

    #[test]
    fn mock_put_get_list_delete_and_client_side_encryption() {
        let store = Arc::new(Mutex::new(BTreeMap::<String, Vec<u8>>::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let store_task = store.clone();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { continue };
                let _ = handle_mock(&mut conn, &store_task);
            }
        });
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIATEST");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "secret-test-key");
        std::env::set_var(
            "AGENTLINK_TEST_S3_KEY",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        let config = S3Config {
            endpoint: format!("http://{addr}"),
            region: "us-east-1".into(),
            bucket: "audit".into(),
            prefix: "pfx".into(),
            path_style: true,
            credentials: "env".into(),
            credential_file: None,
            profile: None,
            sse: "AES256".into(),
            client_key_env: "AGENTLINK_TEST_S3_KEY".into(),
        };
        let client = S3Client::new(config).unwrap();
        client
            .put(
                "node/2026/10/22/logs/a.jsonl.gz",
                b"hello-audit",
                "application/gzip",
            )
            .unwrap();
        let got = client.get("node/2026/10/22/logs/a.jsonl.gz").unwrap();
        assert_eq!(got, b"hello-audit");
        let stored = store.lock().unwrap();
        let raw = stored.values().next().cloned().unwrap();
        drop(stored);
        assert!(raw.starts_with(CSE_MAGIC));
        assert!(!raw.windows(11).any(|w| w == b"hello-audit"));
        let listed = client.list("node/").unwrap();
        assert!(
            listed.iter().any(|k| k.contains("a.jsonl.gz")),
            "{listed:?}"
        );
        client.delete("node/2026/10/22/logs/a.jsonl.gz").unwrap();
        assert!(client.list("node/").unwrap().is_empty());
    }

    fn handle_mock(
        conn: &mut std::net::TcpStream,
        store: &Mutex<BTreeMap<String, Vec<u8>>>,
    ) -> std::io::Result<()> {
        conn.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut filled = 0;
        loop {
            let n = conn.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
            if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                let header_end = buf[..filled]
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let header = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while filled < header_end + length {
                    let n = conn.read(&mut buf[filled..])?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                let body = buf[header_end..header_end + length].to_vec();
                let response = mock_response(&header, &body, store);
                conn.write_all(&response)?;
                return Ok(());
            }
        }
        Ok(())
    }

    fn mock_response(
        header: &str,
        body: &[u8],
        store: &Mutex<BTreeMap<String, Vec<u8>>>,
    ) -> Vec<u8> {
        let mut lines = header.lines();
        let request = lines.next().unwrap_or("");
        let mut parts = request.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("/");
        let path = target.split('?').next().unwrap_or("/");
        let has_auth = header
            .to_ascii_lowercase()
            .contains("authorization: aws4-hmac-sha256");
        let has_sse = header
            .to_ascii_lowercase()
            .contains("x-amz-server-side-encryption: aes256")
            || method == "GET"
            || method == "DELETE"
            || target.contains("list-type");
        if !has_auth || (method == "PUT" && !has_sse) {
            return http(403, "missing signature or sse");
        }
        let key = path.trim_start_matches("/audit/").to_string();
        match method {
            "PUT" => {
                store.lock().unwrap().insert(key, body.to_vec());
                http(200, "")
            }
            "GET" if target.contains("list-type=2") => {
                let prefix = target
                    .split("prefix=")
                    .nth(1)
                    .unwrap_or("")
                    .split('&')
                    .next()
                    .unwrap_or("")
                    .replace("%2F", "/");
                let mut xml = String::from(
                    "<?xml version=\"1.0\"?><ListBucketResult><IsTruncated>false</IsTruncated>",
                );
                for key in store.lock().unwrap().keys() {
                    if key.starts_with(&prefix) {
                        xml.push_str(&format!("<Contents><Key>{key}</Key></Contents>"));
                    }
                }
                xml.push_str("</ListBucketResult>");
                http(200, &xml)
            }
            "GET" => {
                if let Some(bytes) = store.lock().unwrap().get(&key) {
                    http_bytes(200, bytes)
                } else {
                    http(404, "missing")
                }
            }
            "DELETE" => {
                store.lock().unwrap().remove(&key);
                http(204, "")
            }
            _ => http(405, "no"),
        }
    }

    fn http(status: u16, body: &str) -> Vec<u8> {
        http_bytes(status, body.as_bytes())
    }

    #[test]
    fn minio_put_get_when_endpoint_is_set() {
        let endpoint = match std::env::var("AGENTLINK_S3_ENDPOINT") {
            Ok(value) if !value.is_empty() => value,
            _ => return,
        };
        let access =
            std::env::var("AGENTLINK_S3_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".into());
        let secret =
            std::env::var("AGENTLINK_S3_SECRET_KEY").unwrap_or_else(|_| "minioadmin".into());
        let bucket =
            std::env::var("AGENTLINK_S3_BUCKET").unwrap_or_else(|_| "agentlink-audit".into());
        let dir = tempfile::tempdir().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::write(
            &creds,
            format!("[default]\naws_access_key_id = {access}\naws_secret_access_key = {secret}\n"),
        )
        .unwrap();
        let config = S3Config {
            endpoint,
            region: "us-east-1".into(),
            bucket,
            prefix: "agentlink-test".into(),
            path_style: true,
            credentials: "file".into(),
            credential_file: Some(creds.display().to_string()),
            profile: Some("default".into()),
            sse: String::new(),
            client_key_env: String::new(),
        };
        let client = S3Client::new(config).unwrap();
        client.create_bucket().unwrap();
        let key = "node/2026/10/22/logs/session/1.jsonl.gz";
        let body = b"{\"op\":\"exec\",\"ok\":true}\n";
        client.put(key, body, "application/gzip").unwrap();
        let got = client.get(key).unwrap();
        assert_eq!(got, body);
        let listed = client.list("node/").unwrap();
        assert!(
            listed.iter().any(|item| item.contains("1.jsonl.gz")),
            "{listed:?}"
        );
        client.delete(key).unwrap();
    }

    fn http_bytes(status: u16, body: &[u8]) -> Vec<u8> {
        let head = format!(
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let mut out = head.into_bytes();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn sec17_cse_fails_closed_on_plaintext_and_binds_bucket_and_key_in_aad() {
        std::env::set_var(
            "AGENTLINK_TEST_S3_SEC17_KEY",
            "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        );
        let config = S3Config {
            endpoint: "http://127.0.0.1:9".into(),
            region: "us-east-1".into(),
            bucket: "audit-bucket".into(),
            prefix: "pfx".into(),
            path_style: true,
            credentials: "env".into(),
            credential_file: None,
            profile: None,
            sse: String::new(),
            client_key_env: "AGENTLINK_TEST_S3_SEC17_KEY".into(),
        };

        // 1. Plaintext downgrade (no AGLKCSE1 magic) must fail closed.
        let err = maybe_decrypt(&config, "pfx/logs/a.jsonl", b"forged plaintext audit").unwrap_err();
        assert!(err.to_string().contains("AGLKCSE1"), "{err}");

        // 2. Truncated AGLKCSE1 payload must fail closed.
        let err = maybe_decrypt(&config, "pfx/logs/a.jsonl", b"AGLKCSE1short").unwrap_err();
        assert!(err.to_string().contains("AGLKCSE1"), "{err}");

        // 3. Ciphertext encrypted under key A succeeds for key A, fails for key B (object swap).
        let ct = maybe_encrypt(&config, "pfx/logs/a.jsonl", b"secret-audit-line").unwrap();
        assert_eq!(
            maybe_decrypt(&config, "pfx/logs/a.jsonl", &ct).unwrap(),
            b"secret-audit-line"
        );
        assert!(
            maybe_decrypt(&config, "pfx/logs/b.jsonl", &ct).is_err(),
            "swapping ciphertext to a different S3 key must fail AAD authentication"
        );

        // 4. Ciphertext moved to a different bucket must also fail AAD authentication.
        let mut other_bucket = config.clone();
        other_bucket.bucket = "other-bucket".into();
        assert!(
            maybe_decrypt(&other_bucket, "pfx/logs/a.jsonl", &ct).is_err(),
            "swapping ciphertext to a different bucket must fail AAD authentication"
        );
    }
}
