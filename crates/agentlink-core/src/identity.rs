//! Ed25519 node identity.
//!
//! The node id is the hex-encoded public key, so enrollment is bound to the
//! key the node can sign with. The secret is stored in the node data dir.

use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util::{self, auth_message};

#[derive(Debug, Serialize, Deserialize)]
struct IdentityFile {
    secret_hex: String,
    public_hex: String,
}

#[derive(Clone)]
enum Secret {
    Local(SigningKey),
    /// Hex signature of the given message. Used when the private key stays in
    /// the Android Keystore and only a callback can sign.
    External(Arc<dyn Fn(&[u8]) -> String + Send + Sync>),
}

#[derive(Clone)]
pub struct Identity {
    secret: Secret,
    public_hex: String,
}

impl Identity {
    /// Read an existing identity file. Missing or corrupt files fail; nothing
    /// is created or rewritten.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::Message(format!(
                "身份文件不存在，未重新生成：{}",
                path.display()
            )));
        }
        Self::load_existing(path)
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                util::ensure_secret_parent(parent)?;
            }
        }
        if path.exists() {
            return Self::load_existing(path);
        }
        let signing = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing.verifying_key().to_bytes());
        let file = IdentityFile {
            secret_hex: hex::encode(signing.to_bytes()),
            public_hex: public_hex.clone(),
        };
        let bytes = serde_json::to_string_pretty(&file)?;
        if util::write_secret_exclusive(path, bytes.as_bytes())? {
            return Ok(Self {
                secret: Secret::Local(signing),
                public_hex,
            });
        }
        // Another process created the file first. Load that identity; never
        // overwrite or keep a private key that is not on disk.
        Self::load_existing(path)
    }

    fn load_existing(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|err| {
            Error::Message(format!("身份文件无法读取，未重新生成：{err}"))
        })?;
        let file: IdentityFile = serde_json::from_str(&text).map_err(|err| {
            Error::Message(format!(
                "身份文件已损坏或不是有效 JSON，未重新生成：{err}"
            ))
        })?;
        let bytes = hex::decode(file.secret_hex.trim()).map_err(|err| {
            Error::Message(format!("身份密钥无法解码，未重新生成：{err}"))
        })?;
        if bytes.len() != 32 {
            return Err(Error::Message(
                "身份密钥必须是 32 字节，未重新生成".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let signing = SigningKey::from_bytes(&arr);
        let public_hex = hex::encode(signing.verifying_key().to_bytes());
        if public_hex != file.public_hex.trim() {
            return Err(Error::Message(
                "身份文件已损坏：公钥与私钥不匹配，未重新生成。请检查或从备份恢复。".into(),
            ));
        }
        Ok(Self {
            secret: Secret::Local(signing),
            public_hex,
        })
    }

    /// A key whose secret stays outside this process. `sign` returns a hex signature.
    pub fn from_external(
        public_hex: impl Into<String>,
        sign: Arc<dyn Fn(&[u8]) -> String + Send + Sync>,
    ) -> Self {
        Self {
            secret: Secret::External(sign),
            public_hex: public_hex.into().trim().to_ascii_lowercase(),
        }
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != 32 {
            return Err(Error::Message("identity key must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        let signing = SigningKey::from_bytes(&arr);
        let public_hex = hex::encode(signing.verifying_key().to_bytes());
        Ok(Self {
            secret: Secret::Local(signing),
            public_hex,
        })
    }

    pub fn node_id(&self) -> &str {
        &self.public_hex
    }

    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }

    pub fn sign_nonce(&self, nonce: &str) -> String {
        self.sign_message(&auth_message(nonce))
    }

    /// A fresh key that is not written to disk. Direct-path clients use one
    /// per process; the relay introduction binds it to an authenticated session.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing.verifying_key().to_bytes());
        Self {
            secret: Secret::Local(signing),
            public_hex,
        }
    }

    pub fn sign_message(&self, message: &[u8]) -> String {
        match &self.secret {
            Secret::Local(signing) => hex::encode(signing.sign(message).to_bytes()),
            Secret::External(sign) => sign(message),
        }
    }
}

pub fn verify_message(public_hex: &str, message: &[u8], signature_hex: &str) -> Result<()> {
    let pk_bytes =
        hex::decode(public_hex.trim()).map_err(|e| Error::Auth(format!("public key: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(Error::Auth("public key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let verifying =
        VerifyingKey::from_bytes(&pk_arr).map_err(|e| Error::Auth(format!("public key: {e}")))?;
    let sig_bytes =
        hex::decode(signature_hex.trim()).map_err(|e| Error::Auth(format!("signature: {e}")))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| Error::Auth(format!("signature: {e}")))?;
    verifying
        .verify(message, &sig)
        .map_err(|_| Error::Auth("signature rejected".into()))
}

pub fn public_bytes(public_hex: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(public_hex.trim()).map_err(|e| Error::Auth(format!("public key: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Auth("public key must be 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn verify_nonce(public_hex: &str, nonce: &str, signature_hex: &str) -> Result<()> {
    let pk_bytes =
        hex::decode(public_hex.trim()).map_err(|e| Error::Auth(format!("public key: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(Error::Auth("public key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let verifying =
        VerifyingKey::from_bytes(&pk_arr).map_err(|e| Error::Auth(format!("public key: {e}")))?;
    let sig_bytes =
        hex::decode(signature_hex.trim()).map_err(|e| Error::Auth(format!("signature: {e}")))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| Error::Auth(format!("signature: {e}")))?;
    verifying
        .verify(&auth_message(nonce), &sig)
        .map_err(|_| Error::Auth("signature rejected".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let id = Identity::load_or_create(&path).unwrap();
        let again = Identity::load_or_create(&path).unwrap();
        assert_eq!(id.node_id(), again.node_id());
        let sig = id.sign_nonce("abc");
        verify_nonce(id.public_hex(), "abc", &sig).unwrap();
        assert!(verify_nonce(id.public_hex(), "abd", &sig).is_err());
    }

    #[test]
    fn rfc8032_seed_matches_the_published_vector() {
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let id = Identity::from_seed(&seed).unwrap();
        assert_eq!(
            id.public_hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            id.sign_message(b""),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn external_signer_verifies_like_a_local_key() {
        let local = Identity::generate();
        let public_hex = local.public_hex().to_string();
        let delegated = local.clone();
        let bytes = Identity::from_external(
            public_hex,
            Arc::new(move |message| delegated.sign_message(message)),
        );
        let sig = bytes.sign_nonce("nonce");
        verify_nonce(local.public_hex(), "nonce", &sig).unwrap();
    }

    #[test]
    fn load_or_create_keeps_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let first = Identity::load_or_create(&path).unwrap();
        let again = Identity::load_or_create(&path).unwrap();
        assert_eq!(first.public_hex(), again.public_hex());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(file_mode, 0o600);
            let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
            // tempdir is not necessarily 0700; we must not have failed, and we
            // must not have required chmod of a pre-existing parent.
            let _ = dir_mode;
        }
    }

    #[test]
    fn load_errors_when_missing_and_does_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let err = match Identity::load(&path) {
            Ok(_) => panic!("expected a missing identity file to fail"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("不存在"), "{err}");
        assert!(!path.exists());
    }

    #[test]
    fn load_or_create_ensure_rereads_without_rotating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let first = Identity::load_or_create(&path).unwrap().public_hex().to_string();
        let again = Identity::load_or_create(&path).unwrap().public_hex().to_string();
        assert_eq!(first, again);
        assert_eq!(Identity::load(&path).unwrap().public_hex(), first);
    }

    #[test]
    fn damaged_identity_is_not_silently_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let first = Identity::load_or_create(&path).unwrap();
        let original = first.public_hex().to_string();
        std::fs::write(&path, "{not-json").unwrap();
        let err = match Identity::load_or_create(&path) {
            Ok(_) => panic!("damaged json must not load"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("未重新生成"), "{err}");
        assert!(err.contains("损坏") || err.contains("JSON"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not-json");

        std::fs::write(
            &path,
            r#"{
  "secret_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "public_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}"#,
        )
        .unwrap();
        let err = match Identity::load_or_create(&path) {
            Ok(_) => panic!("mismatched identity must not load"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("未重新生成"), "{err}");
        assert!(err.contains("不匹配"), "{err}");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("bbbbbbbb"), "must not replace the damaged file");
        assert!(!text.contains(&original));
    }

    #[test]
    fn concurrent_first_create_converges_on_one_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let workers = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(workers));
        let path = std::sync::Arc::new(path);
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    Identity::load_or_create(&path).map(|id| id.public_hex().to_string())
                })
            })
            .collect();
        let ids: Vec<String> = handles
            .into_iter()
            .map(|h| h.join().unwrap().expect("load_or_create"))
            .collect();
        let disk = Identity::load_or_create(&path).unwrap().public_hex().to_string();
        assert!(ids.iter().all(|id| id == &disk), "got {ids:?} disk {disk}");
    }
}
