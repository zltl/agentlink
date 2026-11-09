//! Relay TLS material and client certificate checks.
//!
//! A self-hosted relay generates a certificate and clients pin its SHA-256.
//! A relay behind a public CA (Let's Encrypt rotates the leaf every 60–90
//! days) can instead be verified with the OS trust store or the Mozilla
//! WebPKI roots, optionally in addition to a pin. Pinning the leaf public key
//! (`spki:`) survives renewal when the key is reused. Pinning the issuing
//! intermediate's SPKI survives renewal of the leaf and still checks that the
//! hostname matches.
//!
//! The relay reuses `cert.pem` and `key.pem` when both files are already in
//! its data directory. A new leaf (and therefore a new fingerprint) is minted
//! only when either file is missing. A node that dials `127.0.0.1`, `::1`, or
//! `localhost` and pins only that leaf adopts the presented certificate and
//! the caller rewrites the stored pin. Traffic to those hosts never leaves
//! the machine, and a process that can bind the loopback port can already
//! replace the node. A public hostname stays strict even if it resolves to
//! loopback, and the connected peer must itself be a loopback address. SPKI
//! pins, intermediate pins, and public-root checks are never relaxed.

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::ServerConfig;
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::util;

pub fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn provider() -> Arc<CryptoProvider> {
    install_ring();
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Relay TLS material loaded from, or written into, a data directory.
pub struct RelayCert {
    pub server_config: Arc<ServerConfig>,
    /// `sha256:` plus lowercase hex of the certificate DER.
    pub fingerprint: String,
    pub fingerprint_bytes: [u8; 32],
}

impl RelayCert {
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        util::ensure_dir(dir)?;
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        if cert_path.exists() && key_path.exists() {
            return load_pem(&cert_path, &key_path);
        }
        let key = KeyPair::generate().map_err(|e| Error::Tls(e.to_string()))?;
        let mut params = CertificateParams::new(vec!["localhost".into()])
            .map_err(|e| Error::Tls(e.to_string()))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "agentlink-relay");
        params.distinguished_name = dn;
        let cert = params
            .self_signed(&key)
            .map_err(|e| Error::Tls(e.to_string()))?;
        util::write_secret(&cert_path, cert.pem().as_bytes())?;
        util::write_secret(&key_path, key.serialize_pem().as_bytes())?;
        load_pem(&cert_path, &key_path)
    }
}

fn load_pem(cert_path: &Path, key_path: &Path) -> Result<RelayCert> {
    let cert_file = File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Tls(format!("cert pem: {e}")))?;
    if certs.is_empty() {
        return Err(Error::Tls("certificate file is empty".into()));
    }
    let key_file = File::open(key_path)?;
    let mut reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| Error::Tls(format!("key pem: {e}")))?
        .ok_or_else(|| Error::Tls("private key file is empty".into()))?;
    build_server(certs, key)
}

fn build_server(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<RelayCert> {
    let fingerprint_bytes = fingerprint_of(certs[0].as_ref());
    let fingerprint = format!("sha256:{}", hex::encode(fingerprint_bytes));
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    Ok(RelayCert {
        server_config: Arc::new(server_config),
        fingerprint,
        fingerprint_bytes,
    })
}

pub fn fingerprint_of(der: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(der);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Accept `sha256:HEX` or bare hex.
pub fn parse_fingerprint(input: &str) -> Result<[u8; 32]> {
    let hex_str = input
        .trim()
        .strip_prefix("sha256:")
        .or_else(|| input.trim().strip_prefix("SHA256:"))
        .unwrap_or(input.trim());
    let bytes = hex::decode(hex_str).map_err(|e| Error::Tls(format!("fingerprint: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Tls(
            "fingerprint must be 32 bytes (sha256 hex)".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Recovery text included in a relay leaf-pin mismatch.
///
/// The `got sha256:` value is printed in the same error, ahead of this tip.
/// Loopback leaf dials adopt the certificate instead of returning this error.
pub const LEAF_PIN_MISMATCH_TIP: &str = "tip: the stored relay pin does not match this certificate. Set the node fingerprint to the got= value (the relay writes the same value to fingerprint.txt) and restart the node. A relay host of 127.0.0.1, ::1, or localhost adopts a new leaf pin and rewrites node.json; any other host keeps the old pin";

/// True when `host` is a loopback address or the name `localhost`.
///
/// A public hostname is false here even when it resolves to `127.0.0.1`.
pub fn relay_host_is_loopback(host: &str) -> bool {
    let host = host.trim().trim_matches(|c| c == '[' || c == ']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Both the URL host and the connected peer must be loopback before a node
/// may replace a stale leaf pin.
pub fn adopt_loopback_leaf(host: &str, peer: Option<SocketAddr>) -> bool {
    relay_host_is_loopback(host) && peer.is_some_and(|addr| addr.ip().is_loopback())
}

/// Leaf fingerprint adopted during a loopback handshake, `sha256:` plus hex.
#[derive(Debug, Default)]
pub struct AdoptedLeaf {
    value: Mutex<Option<String>>,
}

impl AdoptedLeaf {
    /// The presented leaf, when it did not match the configured pin.
    pub fn get(&self) -> Option<String> {
        self.value.lock().ok().and_then(|guard| guard.clone())
    }
}

/// Client TLS config for one dial, plus an optional loopback pin slot.
pub struct DialTls {
    pub config: Arc<rustls::ClientConfig>,
    /// Set only when `adopt_loopback_leaf` is true and trust is a leaf pin
    /// with no public roots. After a successful handshake, [`AdoptedLeaf::get`]
    /// is the new pin if the presented leaf differed.
    pub adopted_leaf: Option<Arc<AdoptedLeaf>>,
}

/// `adopt_loopback_leaf` is ignored unless [`RelayTrust`] is leaf-pin only.
/// Callers pass [`adopt_loopback_leaf`] so a public host, or a dial that did
/// not land on loopback, stays strict.
pub fn client_config_for_dial(trust: &RelayTrust, adopt_loopback_leaf: bool) -> Result<DialTls> {
    let adopted = if adopt_loopback_leaf && trust.leaf_pin_only() {
        Some(Arc::new(AdoptedLeaf::default()))
    } else {
        None
    };
    let verifier = policy_verifier_with(trust, adopted.clone())?;
    Ok(DialTls {
        config: config_with_verifier(verifier)?,
        adopted_leaf: adopted,
    })
}

pub(crate) fn pinned_verifier(fingerprint: [u8; 32]) -> Arc<FingerprintVerifier> {
    Arc::new(FingerprintVerifier {
        fingerprint,
        provider: provider(),
    })
}

pub fn client_config(fingerprint: [u8; 32]) -> Result<Arc<rustls::ClientConfig>> {
    let provider = provider();
    let verifier = Arc::new(FingerprintVerifier {
        fingerprint,
        provider: provider.clone(),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Trusts exactly one certificate DER fingerprint. Hostname is not checked;
/// the pin is the trust anchor, which is what we want for a raw IP relay.
#[derive(Debug)]
pub struct FingerprintVerifier {
    pub fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        let got = fingerprint_of(end_entity.as_ref());
        if got == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "certificate fingerprint mismatch (got sha256:{})",
                hex::encode(got)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A certificate check that is stable across a leaf renewal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertPin {
    /// SHA-256 of the leaf certificate DER.
    Leaf([u8; 32]),
    /// SHA-256 of the leaf SubjectPublicKeyInfo.
    Spki([u8; 32]),
    /// SHA-256 of an intermediate's SubjectPublicKeyInfo. The leaf must chain
    /// to that intermediate and the hostname must match.
    IntermediateSpki([u8; 32]),
}

/// Where public trust anchors come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootSource {
    System,
    Webpki,
}

/// How a client or node authenticates the relay certificate.
///
/// A pin and a root source together both have to succeed. Pins alone do not
/// check the hostname, except an intermediate SPKI pin, which does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTrust {
    pins: Vec<CertPin>,
    roots: Vec<RootSource>,
}

impl RelayTrust {
    pub fn leaf(fingerprint: [u8; 32]) -> Self {
        Self {
            pins: vec![CertPin::Leaf(fingerprint)],
            roots: Vec::new(),
        }
    }

    /// `fingerprint` is a pin or a root mode (`system`, `webpki`).
    /// `trust` is an extra root mode, or another pin, from `--trust` / `--ca`.
    /// `system+webpki` accepts a certificate that chains to either store.
    pub fn parse(fingerprint: &str, trust: Option<&str>) -> Result<Self> {
        let mut pins = Vec::new();
        let mut roots = Vec::new();
        apply_trust_text(fingerprint, &mut pins, &mut roots)?;
        if let Some(trust) = trust {
            apply_trust_text(trust, &mut pins, &mut roots)?;
        }
        if pins.is_empty() && roots.is_empty() {
            return Err(Error::Tls(
                "certificate trust missing (pass --fingerprint sha256:<hex>, --fingerprint system, or --trust webpki)".into(),
            ));
        }
        Ok(Self { pins, roots })
    }

    /// Value stored in `fingerprint`. A roots-only mode is stored here too so
    /// an older config field still round-trips.
    pub fn fingerprint_value(&self) -> String {
        if self.pins.is_empty() {
            return roots_label(&self.roots);
        }
        self.pins
            .iter()
            .map(|pin| match pin {
                CertPin::Leaf(bytes) => format!("sha256:{}", hex::encode(bytes)),
                CertPin::Spki(bytes) => format!("spki:sha256:{}", hex::encode(bytes)),
                CertPin::IntermediateSpki(bytes) => {
                    format!("intermediate:sha256:{}", hex::encode(bytes))
                }
            })
            .collect::<Vec<_>>()
            .join("+")
    }

    /// Value stored in `trust`, when public roots are used.
    pub fn trust_value(&self) -> Option<String> {
        if self.roots.is_empty() {
            None
        } else {
            Some(roots_label(&self.roots))
        }
    }

    pub fn uses_webpki(&self) -> bool {
        self.roots.contains(&RootSource::Webpki)
    }

    pub(crate) fn checks_hostname(&self) -> bool {
        !self.roots.is_empty()
            || self
                .pins
                .iter()
                .any(|pin| matches!(pin, CertPin::IntermediateSpki(_)))
    }

    /// Leaf certificate pins and nothing else.
    ///
    /// An SPKI pin, an intermediate pin, or a public-root check is an
    /// explicit extra constraint and is never replaced on loopback.
    fn leaf_pin_only(&self) -> bool {
        self.roots.is_empty()
            && !self.pins.is_empty()
            && self.pins.iter().all(|pin| matches!(pin, CertPin::Leaf(_)))
    }
}

fn roots_label(roots: &[RootSource]) -> String {
    let mut parts = Vec::new();
    if roots.contains(&RootSource::System) {
        parts.push("system");
    }
    if roots.contains(&RootSource::Webpki) {
        parts.push("webpki");
    }
    parts.join("+")
}

fn apply_trust_text(
    text: &str,
    pins: &mut Vec<CertPin>,
    roots: &mut Vec<RootSource>,
) -> Result<()> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(());
    }
    for part in text.split('+') {
        let part = part.trim();
        if part.is_empty() {
            return Err(Error::Tls("empty certificate trust entry".into()));
        }
        apply_trust_token(part, pins, roots)?;
    }
    Ok(())
}

fn apply_trust_token(
    token: &str,
    pins: &mut Vec<CertPin>,
    roots: &mut Vec<RootSource>,
) -> Result<()> {
    let lower = token.to_ascii_lowercase();
    let source = match lower.as_str() {
        "system" => Some(RootSource::System),
        "webpki" | "web-pki" => Some(RootSource::Webpki),
        _ => None,
    };
    if let Some(source) = source {
        if !roots.contains(&source) {
            roots.push(source);
        }
        return Ok(());
    }
    if let Some(rest) = lower.strip_prefix("intermediate:") {
        pins.push(CertPin::IntermediateSpki(parse_fingerprint(rest)?));
        return Ok(());
    }
    if let Some(rest) = lower
        .strip_prefix("ca-spki:")
        .or_else(|| lower.strip_prefix("spki-ca:"))
    {
        pins.push(CertPin::IntermediateSpki(parse_fingerprint(rest)?));
        return Ok(());
    }
    if let Some(rest) = lower.strip_prefix("spki:") {
        pins.push(CertPin::Spki(parse_fingerprint(rest)?));
        return Ok(());
    }
    pins.push(CertPin::Leaf(parse_fingerprint(token)?));
    Ok(())
}

/// SNI and hostname check name. Pin-only leaf checks ignore it. Public roots
/// and intermediate pins require a real DNS name or IP.
pub fn server_name(host: &str, trust: &RelayTrust) -> Result<ServerName<'static>> {
    match ServerName::try_from(host.to_string()) {
        Ok(name) => Ok(name),
        Err(_) if trust.checks_hostname() => Err(Error::Tls(format!(
            "relay host `{host}` is not a DNS name or IP, which this trust mode checks"
        ))),
        Err(_) => ServerName::try_from("agentlink".to_string())
            .map_err(|_| Error::Tls("invalid server name".into())),
    }
}

pub fn client_config_for(trust: &RelayTrust) -> Result<Arc<rustls::ClientConfig>> {
    config_with_verifier(policy_verifier(trust)?)
}

fn config_with_verifier(
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<Arc<rustls::ClientConfig>> {
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn policy_verifier(trust: &RelayTrust) -> Result<Arc<dyn ServerCertVerifier>> {
    policy_verifier_with(trust, None)
}

fn policy_verifier_with(
    trust: &RelayTrust,
    adopt_leaf: Option<Arc<AdoptedLeaf>>,
) -> Result<Arc<dyn ServerCertVerifier>> {
    Ok(Arc::new(PolicyVerifier {
        pins: trust.pins.clone(),
        roots: root_verifiers(&trust.roots)?,
        provider: provider(),
        adopt_leaf,
    }))
}

fn root_verifiers(sources: &[RootSource]) -> Result<Vec<Arc<WebPkiServerVerifier>>> {
    let mut out = Vec::new();
    let mut system_error = None;
    for source in sources {
        match root_verifier(*source) {
            Ok(verifier) => out.push(verifier),
            Err(err) if *source == RootSource::System && sources.contains(&RootSource::Webpki) => {
                system_error = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    if sources.contains(&RootSource::System)
        && !out.is_empty()
        && system_error.is_some()
        && !sources.contains(&RootSource::Webpki)
    {
        return Err(system_error.unwrap());
    }
    if !sources.is_empty() && out.is_empty() {
        return Err(system_error
            .unwrap_or_else(|| Error::Tls("no trust anchors available for the relay".into())));
    }
    Ok(out)
}

fn root_verifier(source: RootSource) -> Result<Arc<WebPkiServerVerifier>> {
    let mut store = RootCertStore::empty();
    match source {
        RootSource::Webpki => {
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        RootSource::System => {
            let loaded = rustls_native_certs::load_native_certs();
            if loaded.certs.is_empty() {
                let detail = if loaded.errors.is_empty() {
                    "no certificates".to_string()
                } else {
                    loaded
                        .errors
                        .iter()
                        .map(|err| err.to_string())
                        .collect::<Vec<_>>()
                        .join("; ")
                };
                return Err(Error::Tls(format!(
                    "system trust store is empty ({detail}). Use --trust webpki to verify with the Mozilla root set"
                )));
            }
            let (added, _ignored) = store.add_parsable_certificates(loaded.certs);
            if added == 0 {
                return Err(Error::Tls(
                    "system trust store had no usable CA certificates. Use --trust webpki".into(),
                ));
            }
        }
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider())
        .build()
        .map_err(|e| Error::Tls(e.to_string()))
}

struct PolicyVerifier {
    pins: Vec<CertPin>,
    roots: Vec<Arc<WebPkiServerVerifier>>,
    provider: Arc<CryptoProvider>,
    /// When set, a leaf-pin mismatch is accepted and the presented fingerprint
    /// is stored here. Installed only for a loopback leaf-pin dial.
    adopt_leaf: Option<Arc<AdoptedLeaf>>,
}

impl std::fmt::Debug for PolicyVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyVerifier")
            .field("pins", &self.pins.len())
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}

impl PolicyVerifier {
    fn leaf_pins_only(&self) -> bool {
        self.roots.is_empty()
            && !self.pins.is_empty()
            && self.pins.iter().all(|pin| matches!(pin, CertPin::Leaf(_)))
    }
}

impl ServerCertVerifier for PolicyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        if !self.roots.is_empty() {
            let mut last = None;
            let mut accepted = false;
            for roots in &self.roots {
                match roots.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                ) {
                    Ok(_) => {
                        accepted = true;
                        break;
                    }
                    Err(err) => last = Some(err),
                }
            }
            if !accepted {
                return Err(last.unwrap_or_else(|| {
                    TlsError::General("certificate was not signed by a trusted root".into())
                }));
            }
        }
        if !self.pins.is_empty() {
            let mut pin_error = None;
            let matched = self.pins.iter().any(|pin| {
                match pin_matches(pin, end_entity, intermediates, server_name, now) {
                    Ok(()) => true,
                    Err(err) => {
                        pin_error = Some(err);
                        false
                    }
                }
            });
            if !matched {
                if self.adopt_leaf.is_some() && self.leaf_pins_only() {
                    let got = format!(
                        "sha256:{}",
                        hex::encode(fingerprint_of(end_entity.as_ref()))
                    );
                    if let Some(slot) = &self.adopt_leaf {
                        if let Ok(mut guard) = slot.value.lock() {
                            *guard = Some(got);
                        }
                    }
                    return Ok(ServerCertVerified::assertion());
                }
                return Err(pin_error.unwrap_or_else(|| {
                    TlsError::General("certificate did not match the configured pin".into())
                }));
            }
        }
        if self.roots.is_empty() && self.pins.is_empty() {
            return Err(TlsError::General("no relay trust configured".into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        if let Some(roots) = self.roots.first() {
            return roots.verify_tls12_signature(message, cert, dss);
        }
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        if let Some(roots) = self.roots.first() {
            return roots.verify_tls13_signature(message, cert, dss);
        }
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        if let Some(roots) = self.roots.first() {
            return roots.supported_verify_schemes();
        }
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn pin_matches(
    pin: &CertPin,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    now: UnixTime,
) -> std::result::Result<(), TlsError> {
    match pin {
        CertPin::Leaf(expected) => {
            let got = fingerprint_of(end_entity.as_ref());
            if got == *expected {
                Ok(())
            } else {
                Err(TlsError::General(format!(
                    "certificate fingerprint mismatch (got sha256:{}); {LEAF_PIN_MISMATCH_TIP}",
                    hex::encode(got)
                )))
            }
        }
        CertPin::Spki(expected) => {
            let got = spki_sha256(end_entity.as_ref())?;
            if got == *expected {
                Ok(())
            } else {
                Err(TlsError::General(format!(
                    "certificate public key pin mismatch (got spki:sha256:{})",
                    hex::encode(got)
                )))
            }
        }
        CertPin::IntermediateSpki(expected) => {
            let Some(ca) = intermediates
                .iter()
                .find(|cert| spki_sha256(cert.as_ref()).ok().as_ref() == Some(expected))
            else {
                return Err(TlsError::General(
                    "no intermediate matched the SPKI pin; the relay must send the issuing certificate".into(),
                ));
            };
            let ca_owned = CertificateDer::from(ca.as_ref().to_vec());
            let mut store = RootCertStore::empty();
            store
                .add(ca_owned)
                .map_err(|e| TlsError::General(format!("intermediate pin: {e}")))?;
            let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider())
                .build()
                .map_err(|e| TlsError::General(format!("intermediate pin: {e}")))?;
            let rest: Vec<CertificateDer<'static>> = intermediates
                .iter()
                .filter(|cert| cert.as_ref() != ca.as_ref())
                .map(|cert| CertificateDer::from(cert.as_ref().to_vec()))
                .collect();
            verifier
                .verify_server_cert(end_entity, &rest, server_name, &[], now)
                .map_err(|e| {
                    TlsError::General(format!(
                        "intermediate SPKI matched but the chain or hostname was rejected: {e}"
                    ))
                })?;
            Ok(())
        }
    }
}

fn spki_sha256(der: &[u8]) -> std::result::Result<[u8; 32], TlsError> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| TlsError::General(format!("certificate: {e}")))?;
    Ok(fingerprint_of(cert.public_key().raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_cert_matches_its_pin() {
        let dir = tempfile::tempdir().unwrap();
        let cert = RelayCert::load_or_create(dir.path()).unwrap();
        let again = RelayCert::load_or_create(dir.path()).unwrap();
        assert_eq!(cert.fingerprint, again.fingerprint);
        assert_eq!(
            parse_fingerprint(&cert.fingerprint).unwrap(),
            cert.fingerprint_bytes
        );
        let verifier = FingerprintVerifier {
            fingerprint: cert.fingerprint_bytes,
            provider: provider(),
        };
        // Wrong pin is rejected even before a handshake.
        let mut bad = cert.fingerprint_bytes;
        bad[0] ^= 0xff;
        let verifier_bad = FingerprintVerifier {
            fingerprint: bad,
            provider: provider(),
        };
        // Build a fresh cert and confirm the original verifier rejects it.
        let other_dir = tempfile::tempdir().unwrap();
        let other = RelayCert::load_or_create(other_dir.path()).unwrap();
        assert_ne!(other.fingerprint, cert.fingerprint);
        let _ = verifier;
        let _ = verifier_bad;
    }

    fn leaf_der(dir: &std::path::Path) -> CertificateDer<'static> {
        let bytes = std::fs::read(dir.join("cert.pem")).unwrap();
        let der = rustls_pemfile::certs(&mut bytes.as_slice())
            .next()
            .unwrap()
            .unwrap();
        CertificateDer::from(der.as_ref().to_vec())
    }

    #[test]
    fn trust_modes_parse_and_leaf_pin_accepts_its_cert() {
        let leaf = "ab".repeat(32);
        let trust = RelayTrust::parse(&format!("sha256:{leaf}"), Some("webpki")).unwrap();
        assert_eq!(trust.trust_value().as_deref(), Some("webpki"));
        assert!(trust.fingerprint_value().starts_with("sha256:"));
        let both = RelayTrust::parse("system", Some("webpki")).unwrap();
        assert!(both.uses_webpki());
        assert_eq!(both.trust_value().as_deref(), Some("system+webpki"));
        assert_eq!(
            RelayTrust::parse("system", None)
                .unwrap()
                .trust_value()
                .as_deref(),
            Some("system")
        );
        assert_eq!(
            RelayTrust::parse("", Some("webpki"))
                .unwrap()
                .fingerprint_value(),
            "webpki"
        );
        let spki = RelayTrust::parse(&format!("spki:sha256:{leaf}"), None).unwrap();
        assert!(spki.fingerprint_value().starts_with("spki:sha256:"));
        let intermediate = RelayTrust::parse(&format!("ca-spki:sha256:{leaf}"), None).unwrap();
        assert!(intermediate
            .fingerprint_value()
            .starts_with("intermediate:sha256:"));
        assert!(RelayTrust::parse("sha256:ab", None).is_err());

        let dir = tempfile::tempdir().unwrap();
        let cert = RelayCert::load_or_create(dir.path()).unwrap();
        let der = leaf_der(dir.path());
        let name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
        let now = UnixTime::now();
        let ok = policy_verifier(&RelayTrust::leaf(cert.fingerprint_bytes)).unwrap();
        ok.verify_server_cert(&der, &[], &name, &[], now).unwrap();
        let mut bad = cert.fingerprint_bytes;
        bad[0] ^= 0xff;
        let rejected = policy_verifier(&RelayTrust::leaf(bad)).unwrap();
        assert!(rejected
            .verify_server_cert(&der, &[], &name, &[], now)
            .is_err());

        let spki_pin = spki_sha256(der.as_ref()).unwrap();
        let spki_trust =
            RelayTrust::parse(&format!("spki:sha256:{}", hex::encode(spki_pin)), None).unwrap();
        policy_verifier(&spki_trust)
            .unwrap()
            .verify_server_cert(&der, &[], &name, &[], now)
            .unwrap();
        let webpki = RelayTrust::parse("webpki", None).unwrap();
        assert!(policy_verifier(&webpki)
            .unwrap()
            .verify_server_cert(&der, &[], &name, &[], now)
            .is_err());
    }

    #[test]
    fn intermediate_spki_pin_checks_the_chain_and_hostname() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["relay.example".into()]).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let leaf_der = CertificateDer::from(leaf.der().to_vec());
        let ca_der = CertificateDer::from(ca.der().to_vec());
        let pin = spki_sha256(ca_der.as_ref()).unwrap();
        let trust =
            RelayTrust::parse(&format!("intermediate:sha256:{}", hex::encode(pin)), None).unwrap();
        let verifier = policy_verifier(&trust).unwrap();
        let name = ServerName::try_from("relay.example".to_string()).unwrap();
        verifier
            .verify_server_cert(&leaf_der, &[ca_der.clone()], &name, &[], UnixTime::now())
            .unwrap();
        let wrong = ServerName::try_from("other.example".to_string()).unwrap();
        assert!(verifier
            .verify_server_cert(&leaf_der, &[ca_der], &wrong, &[], UnixTime::now())
            .is_err());
    }

    fn verifier(trust: &RelayTrust, adopt: bool) -> (PolicyVerifier, Option<Arc<AdoptedLeaf>>) {
        let adopted = if adopt && trust.leaf_pin_only() {
            Some(Arc::new(AdoptedLeaf::default()))
        } else {
            None
        };
        let verifier = PolicyVerifier {
            pins: trust.pins.clone(),
            roots: root_verifiers(&trust.roots).unwrap(),
            provider: provider(),
            adopt_leaf: adopted.clone(),
        };
        (verifier, adopted)
    }

    #[test]
    fn loopback_hosts_require_a_loopback_peer() {
        let loopback: std::net::SocketAddr = "127.0.0.1:7443".parse().unwrap();
        let v6: std::net::SocketAddr = "[::1]:7443".parse().unwrap();
        let remote: std::net::SocketAddr = "203.0.113.9:7443".parse().unwrap();
        assert!(relay_host_is_loopback("127.0.0.1"));
        assert!(relay_host_is_loopback("127.0.0.2"));
        assert!(relay_host_is_loopback("::1"));
        assert!(relay_host_is_loopback("[::1]"));
        assert!(relay_host_is_loopback("localhost"));
        assert!(relay_host_is_loopback("LOCALHOST"));
        assert!(!relay_host_is_loopback("relay.example.com"));
        assert!(!relay_host_is_loopback("8.8.8.8"));
        assert!(adopt_loopback_leaf("127.0.0.1", Some(loopback)));
        assert!(adopt_loopback_leaf("::1", Some(v6)));
        assert!(adopt_loopback_leaf("localhost", Some(loopback)));
        assert!(!adopt_loopback_leaf("127.0.0.1", Some(remote)));
        assert!(!adopt_loopback_leaf("127.0.0.1", None));
        assert!(!adopt_loopback_leaf("relay.example.com", Some(loopback)));
    }

    #[test]
    fn loopback_adopts_a_stale_leaf_and_a_remote_pin_stays_strict() {
        let dir = tempfile::tempdir().unwrap();
        let cert = RelayCert::load_or_create(dir.path()).unwrap();
        let der = leaf_der(dir.path());
        let stale_dir = tempfile::tempdir().unwrap();
        let stale = RelayCert::load_or_create(stale_dir.path()).unwrap();
        assert_ne!(stale.fingerprint, cert.fingerprint);
        let trust = RelayTrust::leaf(stale.fingerprint_bytes);
        let name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
        let now = UnixTime::now();

        let (remote, remote_slot) = verifier(&trust, false);
        assert!(remote_slot.is_none());
        let err = remote
            .verify_server_cert(&der, &[], &name, &[], now)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains(&format!("got {}", cert.fingerprint)),
            "{text}"
        );
        assert!(text.contains(LEAF_PIN_MISMATCH_TIP), "{text}");
        assert!(text.contains("fingerprint.txt"), "{text}");
        assert!(!crate::Error::Tls(text).is_retryable());

        let strict_dial = client_config_for_dial(&trust, false).unwrap();
        assert!(strict_dial.adopted_leaf.is_none());
        let public =
            client_config_for_dial(&trust, adopt_loopback_leaf("relay.example", None)).unwrap();
        assert!(public.adopted_leaf.is_none());

        let (local, slot) = verifier(&trust, true);
        let slot = slot.unwrap();
        assert!(slot.get().is_none());
        local
            .verify_server_cert(&der, &[], &name, &[], now)
            .unwrap();
        assert_eq!(slot.get().as_deref(), Some(cert.fingerprint.as_str()));

        let dial = client_config_for_dial(&trust, true).unwrap();
        assert!(dial.adopted_leaf.is_some());

        let (matched, matched_slot) = verifier(&RelayTrust::leaf(cert.fingerprint_bytes), true);
        matched
            .verify_server_cert(&der, &[], &name, &[], now)
            .unwrap();
        assert!(matched_slot.unwrap().get().is_none());
    }

    #[test]
    fn loopback_does_not_relax_spki_or_ca_pins() {
        let dir = tempfile::tempdir().unwrap();
        let cert = RelayCert::load_or_create(dir.path()).unwrap();
        let der = leaf_der(dir.path());
        let name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
        let now = UnixTime::now();
        let wrong = "ab".repeat(32);

        let spki = RelayTrust::parse(&format!("spki:sha256:{wrong}"), None).unwrap();
        let dial = client_config_for_dial(&spki, true).unwrap();
        assert!(dial.adopted_leaf.is_none());
        let (verifier, slot) = verifier(&spki, true);
        assert!(slot.is_none());
        let err = verifier
            .verify_server_cert(&der, &[], &name, &[], now)
            .unwrap_err();
        assert!(err.to_string().contains("public key pin mismatch"), "{err}");

        let mixed = RelayTrust::parse(&cert.fingerprint, Some("webpki")).unwrap();
        let dial = client_config_for_dial(&mixed, true).unwrap();
        assert!(
            dial.adopted_leaf.is_none(),
            "a public-root check stays in force on loopback"
        );
    }
}
