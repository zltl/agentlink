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
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let text = std::fs::read_to_string(path)?;
            let file: IdentityFile = serde_json::from_str(&text)?;
            let bytes = hex::decode(file.secret_hex.trim())
                .map_err(|e| Error::Message(format!("identity key: {e}")))?;
            if bytes.len() != 32 {
                return Err(Error::Message("identity key must be 32 bytes".into()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let signing = SigningKey::from_bytes(&arr);
            let public_hex = hex::encode(signing.verifying_key().to_bytes());
            if public_hex != file.public_hex.trim() {
                return Err(Error::Message(
                    "identity public key does not match the secret".into(),
                ));
            }
            return Ok(Self {
                secret: Secret::Local(signing),
                public_hex,
            });
        }
        let signing = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing.verifying_key().to_bytes());
        let file = IdentityFile {
            secret_hex: hex::encode(signing.to_bytes()),
            public_hex: public_hex.clone(),
        };
        util::write_secret(path, serde_json::to_string_pretty(&file)?.as_bytes())?;
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
}
