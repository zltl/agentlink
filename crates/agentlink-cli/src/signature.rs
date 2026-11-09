//! Minisign-compatible signatures for `SHA256SUMS`.
//!
//! The file layout matches minisign (`Ed` / `ED` algorithms, key id, and a
//! global signature over the raw signature plus the trusted comment). The
//! signing key this binary accepts is a 32-byte ed25519 seed in hex
//! (`AGENTLINK_SIGNING_KEY`), not an encrypted minisign secret file. Public
//! keys and signatures are ordinary minisign text, so `minisign -V` can check
//! a release signed here.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Args, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[derive(Subcommand, Debug)]
pub enum InternalAction {
    /// Write `SHA256SUMS.minisig` using `AGENTLINK_SIGNING_KEY` (32-byte hex seed).
    SignChecksums(SignArgs),
    /// Print the minisign public key for `AGENTLINK_SIGNING_KEY`.
    Pubkey,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    /// File to sign, usually `SHA256SUMS`.
    pub file: std::path::PathBuf,
    /// Trusted comment. Defaults to a timestamp and the file name.
    #[arg(long)]
    pub trusted_comment: Option<String>,
    /// Also write the public key here.
    #[arg(long)]
    pub pubkey_out: Option<std::path::PathBuf>,
}

pub fn dispatch(action: &InternalAction) -> Result<()> {
    match action {
        InternalAction::Pubkey => {
            let signing = signing_key_from_env()?;
            let public = public_from_signing(&signing);
            print!("{}", public.to_minisign());
            Ok(())
        }
        InternalAction::SignChecksums(args) => {
            let _ = sign_file(
                &args.file,
                args.trusted_comment.as_deref(),
                args.pubkey_out.as_deref(),
            )?;
            Ok(())
        }
    }
}

const SIG_ALG: &[u8; 2] = b"Ed";
const SIG_ALG_HASHED: &[u8; 2] = b"ED";
const COMMENT_PREFIX: &str = "untrusted comment: ";
const TRUSTED_PREFIX: &str = "trusted comment: ";

#[derive(Clone)]
pub struct PublicKey {
    key_id: [u8; 8],
    verify: VerifyingKey,
}

impl PublicKey {
    pub fn parse(text: &str) -> Result<Self> {
        let line = text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with("untrusted comment:"))
            .ok_or_else(|| anyhow!("public key is empty"))?;
        let raw = STANDARD
            .decode(line)
            .context("public key is not minisign base64")?;
        if raw.len() != 42 {
            bail!(
                "public key must be 42 bytes after base64, got {}",
                raw.len()
            );
        }
        if &raw[0..2] != SIG_ALG {
            bail!("unsupported public key algorithm");
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&raw[2..10]);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw[10..42]);
        let verify = VerifyingKey::from_bytes(&pk).map_err(|err| anyhow!("public key: {err}"))?;
        Ok(Self { key_id, verify })
    }

    pub fn to_minisign(&self) -> String {
        let mut raw = [0u8; 42];
        raw[0..2].copy_from_slice(SIG_ALG);
        raw[2..10].copy_from_slice(&self.key_id);
        raw[10..42].copy_from_slice(self.verify.as_bytes());
        format!(
            "{COMMENT_PREFIX}minisign public key\n{}\n",
            STANDARD.encode(raw)
        )
    }
}

/// Verify `message` against a minisign signature file.
///
/// Hashed signatures (`ED`, the minisign default) cover a BLAKE2b-512 of the
/// message. Legacy raw signatures (`Ed`) cover the message bytes.
pub fn verify(public: &PublicKey, message: &[u8], signature_text: &str) -> Result<()> {
    let parsed = parse_signature(signature_text)?;
    if parsed.key_id != public.key_id {
        bail!("signature key id does not match the public key");
    }
    let signed = signed_message(parsed.hashed, message)?;
    public
        .verify
        .verify(&signed, &parsed.signature)
        .map_err(|_| anyhow!("signature verification failed"))?;
    let mut global_message = Vec::with_capacity(64 + parsed.trusted_comment.len());
    global_message.extend_from_slice(&parsed.signature.to_bytes());
    global_message.extend_from_slice(parsed.trusted_comment.as_bytes());
    public
        .verify
        .verify(&global_message, &parsed.global_signature)
        .map_err(|_| anyhow!("trusted comment verification failed"))?;
    Ok(())
}

fn signed_message(hashed: bool, message: &[u8]) -> Result<Vec<u8>> {
    if hashed {
        use blake2::Digest;
        Ok(blake2::Blake2b512::digest(message).to_vec())
    } else {
        Ok(message.to_vec())
    }
}

struct ParsedSig {
    hashed: bool,
    key_id: [u8; 8],
    signature: Signature,
    trusted_comment: String,
    global_signature: Signature,
}

fn parse_signature(text: &str) -> Result<ParsedSig> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let first = lines
        .next()
        .ok_or_else(|| anyhow!("signature file is empty"))?;
    if !first.starts_with(COMMENT_PREFIX) {
        bail!("signature must start with an untrusted comment");
    }
    let sig_b64 = lines
        .next()
        .ok_or_else(|| anyhow!("signature is missing the signature line"))?;
    let trusted_line = lines
        .next()
        .ok_or_else(|| anyhow!("signature is missing the trusted comment"))?;
    let global_b64 = lines
        .next()
        .ok_or_else(|| anyhow!("signature is missing the comment signature"))?;
    if !trusted_line.starts_with(TRUSTED_PREFIX) {
        bail!("trusted comment must start with \"{TRUSTED_PREFIX}\"");
    }
    let trusted_comment = trusted_line[TRUSTED_PREFIX.len()..].to_string();
    let sig_raw = STANDARD
        .decode(sig_b64)
        .context("signature line is not base64")?;
    if sig_raw.len() != 74 {
        bail!("signature line must be 74 bytes, got {}", sig_raw.len());
    }
    let hashed = if &sig_raw[0..2] == SIG_ALG_HASHED {
        true
    } else if &sig_raw[0..2] == SIG_ALG {
        false
    } else {
        bail!("unsupported signature algorithm");
    };
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&sig_raw[2..10]);
    let signature =
        Signature::from_slice(&sig_raw[10..74]).map_err(|err| anyhow!("signature bytes: {err}"))?;
    let global_raw = STANDARD
        .decode(global_b64)
        .context("comment signature is not base64")?;
    if global_raw.len() != 64 {
        bail!("comment signature must be 64 bytes");
    }
    let global_signature =
        Signature::from_slice(&global_raw).map_err(|err| anyhow!("comment signature: {err}"))?;
    Ok(ParsedSig {
        hashed,
        key_id,
        signature,
        trusted_comment,
        global_signature,
    })
}

pub fn signing_key_from_env() -> Result<SigningKey> {
    let hex_key =
        std::env::var("AGENTLINK_SIGNING_KEY").context("AGENTLINK_SIGNING_KEY is not set")?;
    let bytes = hex::decode(hex_key.trim()).context("AGENTLINK_SIGNING_KEY is not hex")?;
    if bytes.len() != 32 {
        bail!("AGENTLINK_SIGNING_KEY must be 32 bytes (64 hex chars)");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

pub fn public_from_signing(signing: &SigningKey) -> PublicKey {
    let id_source = std::env::var("AGENTLINK_SIGNING_KEY_ID").ok();
    let key_id = match id_source
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(hex_id) => {
            let bytes = hex::decode(hex_id).unwrap_or_default();
            let mut id = [0u8; 8];
            if bytes.len() == 8 {
                id.copy_from_slice(&bytes);
                id
            } else {
                derived_key_id(signing.verifying_key().as_bytes())
            }
        }
        None => derived_key_id(signing.verifying_key().as_bytes()),
    };
    PublicKey {
        key_id,
        verify: signing.verifying_key(),
    }
}

fn derived_key_id(public: &[u8; 32]) -> [u8; 8] {
    let hash = agentlink_core::util::sha256_hex(public);
    let bytes = hex::decode(&hash).unwrap_or_default();
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes[..8]);
    id
}

/// Sign `message` and write a minisign signature next to it (prehashed).
pub fn sign_file(
    path: &Path,
    trusted_comment: Option<&str>,
    pubkey_out: Option<&Path>,
) -> Result<PublicKey> {
    let signing = signing_key_from_env()?;
    let public = public_from_signing(&signing);
    let message = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let comment = trusted_comment
        .map(str::to_string)
        .unwrap_or_else(|| default_trusted_comment(&message_name(path)));
    if comment.chars().any(|c| c == '\n' || c == '\r') {
        bail!("trusted comment must be one line");
    }
    let signature_text = sign_prehashed(&signing, &public, &message, &comment)?;
    let sig_path = minisig_path(path);
    std::fs::write(&sig_path, signature_text)
        .with_context(|| format!("write {}", sig_path.display()))?;
    if let Some(out) = pubkey_out {
        std::fs::write(out, public.to_minisign())
            .with_context(|| format!("write {}", out.display()))?;
    }
    eprintln!("wrote {}", sig_path.display());
    Ok(public)
}

fn minisig_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "message".into());
    name.push_str(".minisig");
    path.with_file_name(name)
}

fn message_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "message".into())
}

fn default_trusted_comment(file_name: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("timestamp:{ts}\tfile:{file_name}\thashed")
}

fn sign_prehashed(
    signing: &SigningKey,
    public: &PublicKey,
    message: &[u8],
    trusted_comment: &str,
) -> Result<String> {
    use blake2::Digest;
    let hash = blake2::Blake2b512::digest(message);
    let signature = signing.sign(&hash);
    let mut sig_raw = [0u8; 74];
    sig_raw[0..2].copy_from_slice(SIG_ALG_HASHED);
    sig_raw[2..10].copy_from_slice(&public.key_id);
    sig_raw[10..74].copy_from_slice(&signature.to_bytes());
    let mut global_message = Vec::with_capacity(64 + trusted_comment.len());
    global_message.extend_from_slice(&signature.to_bytes());
    global_message.extend_from_slice(trusted_comment.as_bytes());
    let global = signing.sign(&global_message);
    Ok(format!(
        "{COMMENT_PREFIX}signature from agentlink\n{}\n{TRUSTED_PREFIX}{trusted_comment}\n{}\n",
        STANDARD.encode(sig_raw),
        STANDARD.encode(global.to_bytes())
    ))
}

/// Load a public key from a minisign line, a whole key file's text, or a path.
pub fn load_public_key(text_or_path: &str) -> Result<PublicKey> {
    let trimmed = text_or_path.trim();
    let path = Path::new(trimmed);
    if path.is_file() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read public key {}", path.display()))?;
        return PublicKey::parse(&text);
    }
    PublicKey::parse(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prehashed_signature_round_trip() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let public = PublicKey {
            key_id: derived_key_id(signing.verifying_key().as_bytes()),
            verify: signing.verifying_key(),
        };
        let message = b"abc  file\n";
        let text = sign_prehashed(
            &signing,
            &public,
            message,
            "timestamp:1\tfile:SHA256SUMS\thashed",
        )
        .unwrap();
        verify(&public, message, &text).unwrap();
        let err = verify(&public, b"tampered", &text).unwrap_err();
        assert!(err.to_string().contains("signature"), "{err}");
    }

    #[test]
    fn legacy_raw_signature_verifies() {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let public = PublicKey {
            key_id: [1, 2, 3, 4, 5, 6, 7, 8],
            verify: signing.verifying_key(),
        };
        let message = b"hello";
        let signature = signing.sign(message);
        let mut sig_raw = [0u8; 74];
        sig_raw[0..2].copy_from_slice(SIG_ALG);
        sig_raw[2..10].copy_from_slice(&public.key_id);
        sig_raw[10..74].copy_from_slice(&signature.to_bytes());
        let trusted = "timestamp:2\tfile:x";
        let mut global_message = signature.to_bytes().to_vec();
        global_message.extend_from_slice(trusted.as_bytes());
        let global = signing.sign(&global_message);
        let text = format!(
            "{COMMENT_PREFIX}test\n{}\n{TRUSTED_PREFIX}{trusted}\n{}\n",
            STANDARD.encode(sig_raw),
            STANDARD.encode(global.to_bytes())
        );
        verify(&public, message, &text).unwrap();
    }

    #[test]
    fn key_id_mismatch_is_rejected() {
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let public = PublicKey {
            key_id: [9; 8],
            verify: signing.verifying_key(),
        };
        let other = PublicKey {
            key_id: [8; 8],
            verify: signing.verifying_key(),
        };
        let text = sign_prehashed(&signing, &public, b"m", "comment").unwrap();
        assert!(verify(&other, b"m", &text).is_err());
    }
}
