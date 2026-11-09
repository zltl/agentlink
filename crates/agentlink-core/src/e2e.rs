//! End-to-end channel between a client and a node.
//!
//! The handshake is a Noise-style ephemeral Diffie-Hellman (X25519) with both
//! long-term ed25519 identities signed into the transcript. After the
//! handshake, payloads use ChaCha20-Poly1305. The relay forwards the
//! ciphertext and a coarse class (`read`, `write`, `exec`, `desktop`, `meta`).
//! It does not see paths, command lines, or file bytes.
//!
//! A malicious relay that lies about which ed25519 key belongs to a node name
//! can still introduce a substitute peer. Pin the node id (the public key)
//! to prevent that. The relay cannot forge a signature for a key it does not
//! hold, so it cannot sit in the middle of a session bound to a known node id.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::error::{Error, Result};
use crate::identity::{self, Identity};
use crate::protocol::{Envelope, Op, TransferMsg};

const INFO: &[u8] = b"agentlink-e2e-v1";
const REPLAY_WINDOW: usize = 4096;

/// Keys for one direction pair after a finished handshake.
pub struct Direction {
    encrypt: [u8; 32],
    decrypt: [u8; 32],
    send_n: AtomicU64,
    seen: Mutex<VecDeque<u64>>,
}

impl Direction {
    /// Seal a plaintext with this session's send counter.
    pub fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        let n = self.send_n.fetch_add(1, Ordering::Relaxed);
        aead_seal(&self.encrypt, n, aad, plain)
    }

    fn open_one(&self, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        let (n, plain) = aead_open(&self.decrypt, aad, blob)?;
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| Error::Message("e2e replay lock poisoned".into()))?;
        if seen.contains(&n) {
            return Err(Error::Protocol("replayed e2e frame".into()));
        }
        seen.push_back(n);
        if seen.len() > REPLAY_WINDOW {
            seen.pop_front();
        }
        Ok(plain)
    }

    /// Encrypt a binary file frame's payload with this session.
    pub fn seal_frame(&self, frame: &[u8]) -> Result<Vec<u8>> {
        let decoded = crate::frame::decode(frame)?;
        let aad = frame_aad(&decoded.request_id, decoded.offset);
        let sealed = self.seal(&aad, &decoded.payload)?;
        crate::frame::replace_payload(frame, &sealed, true)
    }
}

/// In-progress client handshake. Holds the ephemeral secret until welcome.
pub struct PendingHello {
    secret: EphemeralSecret,
    node_id: String,
    hello: Vec<u8>,
}

/// How many handshakes to keep per peer ed25519 id.
///
/// Several CLI processes often share one saved client identity. Each dials its
/// own e2e handshake. Replacing the only session made an in-flight `cp` fail
/// to decrypt replies after another command shook hands.
const MAX_SESSIONS_PER_PEER: usize = 8;

/// Sessions this process has completed, keyed by the peer's ed25519 id.
///
/// Each peer may hold several live [`Direction`] values (newest at the back).
#[derive(Clone)]
pub struct Endpoint {
    identity: Arc<Identity>,
    peers: Arc<Mutex<HashMap<String, VecDeque<Arc<Direction>>>>>,
}

impl Endpoint {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity: Arc::new(identity),
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn peer_id(&self) -> &str {
        self.identity.public_hex()
    }

    pub fn has(&self, peer: &str) -> bool {
        self.peers
            .lock()
            .map(|map| map.contains_key(peer))
            .unwrap_or(false)
    }

    /// Drop a session so the next payload starts a fresh handshake.
    pub fn forget(&self, peer: &str) {
        if let Ok(mut map) = self.peers.lock() {
            map.remove(peer);
        }
    }

    pub fn client_hello(&self, node_id: &str) -> Result<PendingHello> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let eph = public.to_bytes();
        let message = sign_message("client", &eph, node_id, &self.identity)?;
        let mut hello = Vec::with_capacity(32 + 32 + 64);
        hello.extend_from_slice(&eph);
        hello.extend_from_slice(&identity::public_bytes(self.identity.public_hex())?);
        hello.extend_from_slice(&message);
        Ok(PendingHello {
            secret,
            node_id: node_id.to_string(),
            hello,
        })
    }

    pub fn hello_bytes(pending: &PendingHello) -> &[u8] {
        &pending.hello
    }

    /// Node side. Verifies the client, stores the session under the client id,
    /// and returns the welcome message to send back.
    pub fn accept(&self, hello: &[u8]) -> Result<(String, Vec<u8>)> {
        if hello.len() != 128 {
            return Err(Error::Protocol("e2e hello has the wrong length".into()));
        }
        let mut client_eph = [0u8; 32];
        client_eph.copy_from_slice(&hello[..32]);
        let mut client_pk = [0u8; 32];
        client_pk.copy_from_slice(&hello[32..64]);
        let sig = &hello[64..128];
        let client_id = hex::encode(client_pk);
        let signed = transcript("client", &client_eph, self.identity.public_hex());
        identity::verify_message(&client_id, signed.as_bytes(), &hex::encode(sig))?;

        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let node_eph = public.to_bytes();
        let shared = secret.diffie_hellman(&PublicKey::from(client_eph));
        let (c2n, n2c) = derive(shared.as_bytes(), &client_eph, &node_eph);
        self.insert(
            &client_id,
            Direction {
                encrypt: n2c,
                decrypt: c2n,
                send_n: AtomicU64::new(1),
                seen: Mutex::new(VecDeque::new()),
            },
        )?;
        let message = sign_raw("node", &client_eph, &node_eph, &client_id, &self.identity)?;
        let mut welcome = Vec::with_capacity(32 + 64);
        welcome.extend_from_slice(&node_eph);
        welcome.extend_from_slice(&message);
        Ok((client_id, welcome))
    }

    pub fn complete(&self, pending: PendingHello, welcome: &[u8]) -> Result<()> {
        if welcome.len() != 96 {
            return Err(Error::Protocol("e2e welcome has the wrong length".into()));
        }
        let mut node_eph = [0u8; 32];
        node_eph.copy_from_slice(&welcome[..32]);
        let sig = &welcome[32..96];
        let client_eph = PublicKey::from(&pending.secret).to_bytes();
        let signed = transcript_node(&client_eph, &node_eph, self.identity.public_hex());
        identity::verify_message(&pending.node_id, signed.as_bytes(), &hex::encode(sig))?;
        let shared = pending.secret.diffie_hellman(&PublicKey::from(node_eph));
        let (c2n, n2c) = derive(shared.as_bytes(), &client_eph, &node_eph);
        self.insert(
            &pending.node_id,
            Direction {
                encrypt: c2n,
                decrypt: n2c,
                send_n: AtomicU64::new(1),
                seen: Mutex::new(VecDeque::new()),
            },
        )?;
        Ok(())
    }

    pub fn seal(&self, peer: &str, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        self.direction(peer)?.seal(aad, plain)
    }

    pub fn open(&self, peer: &str, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        self.open_matched(peer, aad, blob).map(|(plain, _)| plain)
    }

    /// Open ciphertext, trying every live session for `peer`.
    ///
    /// Returns the session that matched so replies can be sealed with the same
    /// keys even when another CLI process just completed a new handshake.
    pub fn open_matched(
        &self,
        peer: &str,
        aad: &[u8],
        blob: &[u8],
    ) -> Result<(Vec<u8>, Arc<Direction>)> {
        let sessions = self.sessions_for(peer)?;
        let mut last_err = Error::Protocol(format!("no e2e session for {peer}"));
        for keys in sessions.iter().rev() {
            match keys.open_one(aad, blob) {
                Ok(plain) => return Ok((plain, Arc::clone(keys))),
                Err(err) => last_err = err,
            }
        }
        Err(last_err)
    }

    /// Open ciphertext for a routed E2E envelope.
    ///
    /// Client→node traffic stores the session under `client_id` on the node, so
    /// the acceptor opens with that field. Node→node PeerCopy flips the roles:
    /// the initiator keyed the session under the peer `node_id`, and replies
    /// still carry `client_id` = initiator. Trying only `client_id` then yields
    /// `no e2e session for <self>` and the Accept never reaches `perform_push`.
    /// Try `client_id` first (common case), then `node_id` when it differs.
    /// Returns the peer key that matched so replies seal with the same session.
    pub fn open_routed(
        &self,
        client_id: &str,
        node_id: &str,
        aad: &[u8],
        blob: &[u8],
    ) -> Result<(Vec<u8>, Arc<Direction>, String)> {
        match self.open_matched(client_id, aad, blob) {
            Ok((plain, session)) => Ok((plain, session, client_id.to_string())),
            Err(err) if node_id != client_id && !node_id.is_empty() => self
                .open_matched(node_id, aad, blob)
                .map(|(plain, session)| (plain, session, node_id.to_string()))
                .map_err(|_| err),
            Err(err) => Err(err),
        }
    }

    /// Encrypt a binary file frame's payload. The 40-byte header, including
    /// the request id the relay routes on, stays readable. The offset stays
    /// readable too; the bytes do not.
    pub fn seal_frame(&self, peer: &str, frame: &[u8]) -> Result<Vec<u8>> {
        self.direction(peer)?.seal_frame(frame)
    }

    pub fn open_frame(&self, peer: &str, frame: &[u8]) -> Result<Vec<u8>> {
        if !crate::frame::is_e2e(frame) {
            return Ok(frame.to_vec());
        }
        let decoded = crate::frame::decode(frame)?;
        let aad = frame_aad(&decoded.request_id, decoded.offset);
        let plain = self.open(peer, &aad, &decoded.payload)?;
        crate::frame::replace_payload(frame, &plain, false)
    }

    fn insert(&self, peer: &str, direction: Direction) -> Result<()> {
        let mut map = self
            .peers
            .lock()
            .map_err(|_| Error::Message("e2e session lock poisoned".into()))?;
        let entry = map.entry(peer.to_string()).or_default();
        entry.push_back(Arc::new(direction));
        while entry.len() > MAX_SESSIONS_PER_PEER {
            entry.pop_front();
        }
        Ok(())
    }

    /// Newest session for `peer` (used when this process seals as the initiator).
    fn direction(&self, peer: &str) -> Result<Arc<Direction>> {
        let sessions = self.sessions_for(peer)?;
        sessions
            .back()
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("no e2e session for {peer}")))
    }

    fn sessions_for(&self, peer: &str) -> Result<VecDeque<Arc<Direction>>> {
        self.peers
            .lock()
            .map_err(|_| Error::Message("e2e session lock poisoned".into()))?
            .get(peer)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("no e2e session for {peer}")))
    }

    pub fn peer_ids(&self) -> Vec<String> {
        self.peers
            .lock()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Wrap `env` so the relay can route it without reading it.
///
/// `peer` is the ed25519 id the session was stored under. `node_id` and
/// `client_id` are the cleartext routing fields. The receiver opens with
/// whichever of those ids it stored the session under.
pub fn seal_envelope(
    endpoint: &Endpoint,
    peer: &str,
    node_id: &str,
    client_id: &str,
    env: &Envelope,
) -> Result<Envelope> {
    let request_id = env
        .request_id()
        .ok_or_else(|| Error::Protocol("e2e envelope needs a request id".into()))?
        .to_string();
    let plain = serde_json::to_vec(env)?;
    let blob = endpoint.seal(peer, request_id.as_bytes(), &plain)?;
    Ok(Envelope::E2e {
        request_id,
        node_id: node_id.to_string(),
        client_id: client_id.to_string(),
        class: coarse_class(env).to_string(),
        terminal: envelope_terminal(env),
        body_b64: crate::util::b64_encode(&blob),
        user: None,
        device_id: None,
        relay_admin: false,
        relay_grant: None,
    })
}

/// Seal with an explicit session (the one that opened the request).
pub fn seal_envelope_session(
    session: &Direction,
    node_id: &str,
    client_id: &str,
    env: &Envelope,
) -> Result<Envelope> {
    let request_id = env
        .request_id()
        .ok_or_else(|| Error::Protocol("e2e envelope needs a request id".into()))?
        .to_string();
    let plain = serde_json::to_vec(env)?;
    let blob = session.seal(request_id.as_bytes(), &plain)?;
    Ok(Envelope::E2e {
        request_id,
        node_id: node_id.to_string(),
        client_id: client_id.to_string(),
        class: coarse_class(env).to_string(),
        terminal: envelope_terminal(env),
        body_b64: crate::util::b64_encode(&blob),
        user: None,
        device_id: None,
        relay_admin: false,
        relay_grant: None,
    })
}

/// Decrypt an [`Envelope::E2e`]. Any other envelope is returned unchanged.
pub fn open_sealed(endpoint: &Endpoint, peer: &str, env: Envelope) -> Result<Envelope> {
    let Envelope::E2e {
        request_id,
        body_b64,
        ..
    } = env
    else {
        return Ok(env);
    };
    let blob = crate::util::b64_decode(&body_b64)?;
    let plain = endpoint.open(peer, request_id.as_bytes(), &blob)?;
    Ok(serde_json::from_slice(&plain)?)
}

/// Open a binary frame, trying `prefer` and then every session.
pub fn open_frame_any(endpoint: &Endpoint, prefer: Option<&str>, frame: &[u8]) -> Vec<u8> {
    if !crate::frame::is_e2e(frame) {
        return frame.to_vec();
    }
    let mut peers = Vec::new();
    if let Some(peer) = prefer {
        peers.push(peer.to_string());
    }
    for peer in endpoint.peer_ids() {
        if !peers.iter().any(|have| have == &peer) {
            peers.push(peer);
        }
    }
    for peer in peers {
        if let Ok(opened) = endpoint.open_frame(&peer, frame) {
            return opened;
        }
    }
    frame.to_vec()
}

fn frame_aad(request_id: &str, offset: u64) -> Vec<u8> {
    let mut aad = b"frame".to_vec();
    aad.extend_from_slice(&offset.to_le_bytes());
    aad.extend_from_slice(request_id.as_bytes());
    aad
}

fn transcript(role: &str, eph: &[u8], other: &str) -> String {
    format!("{INFO:?}|{role}|{}|{other}", hex::encode(eph))
}

fn transcript_node(client_eph: &[u8], node_eph: &[u8], client_id: &str) -> String {
    format!(
        "{INFO:?}|node|{}|{}|{client_id}",
        hex::encode(client_eph),
        hex::encode(node_eph)
    )
}

fn sign_message(role: &str, eph: &[u8], other: &str, identity: &Identity) -> Result<Vec<u8>> {
    let text = transcript(role, eph, other);
    decode_sig(&identity.sign_message(text.as_bytes()))
}

fn sign_raw(
    role: &str,
    client_eph: &[u8],
    node_eph: &[u8],
    client_id: &str,
    identity: &Identity,
) -> Result<Vec<u8>> {
    let _ = role;
    let text = transcript_node(client_eph, node_eph, client_id);
    decode_sig(&identity.sign_message(text.as_bytes()))
}

fn decode_sig(hex_sig: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(hex_sig).map_err(|e| Error::Protocol(format!("signature: {e}")))?;
    if bytes.len() != 64 {
        return Err(Error::Protocol("signature length".into()));
    }
    Ok(bytes)
}

fn derive(shared: &[u8], client_eph: &[u8], node_eph: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(client_eph);
    salt.extend_from_slice(node_eph);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 64];
    hk.expand(INFO, &mut okm)
        .expect("hkdf expand length is valid");
    let mut c2n = [0u8; 32];
    let mut n2c = [0u8; 32];
    c2n.copy_from_slice(&okm[..32]);
    n2c.copy_from_slice(&okm[32..]);
    (c2n, n2c)
}

fn aead_seal(key: &[u8; 32], n: u64, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = nonce(n);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plain, aad })
        .map_err(|_| Error::Protocol("e2e seal failed".into()))?;
    let mut out = Vec::with_capacity(8 + ct.len());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aead_open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<(u64, Vec<u8>)> {
    if blob.len() < 8 + 16 {
        return Err(Error::Protocol("e2e blob is short".into()));
    }
    let n = u64::from_le_bytes(blob[..8].try_into().unwrap());
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = nonce(n);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &blob[8..],
                aad,
            },
        )
        .map_err(|_| Error::Protocol("e2e open failed".into()))?;
    Ok((n, plain))
}

fn nonce(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

/// Coarse class the relay is allowed to see. Paths and arguments stay inside
/// the ciphertext.
pub fn coarse_class(env: &Envelope) -> &'static str {
    match env {
        Envelope::Invoke { op, .. } => match op {
            Op::Stat { .. }
            | Op::ListDir { .. }
            | Op::ReadFile { .. }
            | Op::Search { .. }
            | Op::Find { .. }
            | Op::WatchStart { .. }
            | Op::WatchPoll { .. }
            | Op::WatchStop { .. }
            | Op::SysInfo => "read",
            Op::WriteFile { .. }
            | Op::Mkdir { .. }
            | Op::Remove { .. }
            | Op::Rename { .. }
            | Op::Replace { .. }
            | Op::EditLines { .. }
            | Op::ApplyPatch { .. } => "write",
            Op::Exec { .. }
            | Op::PtyOpen { .. }
            | Op::PtyInput { .. }
            | Op::PtyResize { .. }
            | Op::PtyClose { .. }
            | Op::BgStart { .. }
            | Op::BgList
            | Op::BgOutput { .. }
            | Op::BgStatus { .. }
            | Op::BgKill { .. } => "exec",
            Op::RevokeGrant { .. } => "meta",
            Op::Extension { name, .. } => {
                if crate::extensions::permission_for_extension(name)
                    == crate::extensions::ExtensionPerm::Desktop
                    || crate::extensions::permission_for_extension(name)
                        == crate::extensions::ExtensionPerm::DesktopStream
                {
                    "desktop"
                } else {
                    "meta"
                }
            }
        },
        Envelope::Transfer { msg, .. } => transfer_class(msg),
        _ => "meta",
    }
}

/// Coarse permission class of a transfer control message. Shared with the node
/// so per-request grants can be checked before a transfer starts.
pub fn transfer_class(msg: &TransferMsg) -> &'static str {
    match msg {
        TransferMsg::Push { .. }
        | TransferMsg::PushDir { .. }
        | TransferMsg::PushStream { .. }
        | TransferMsg::PeerCopy { .. } => "write",
        TransferMsg::Pull { .. }
        | TransferMsg::PullDir { .. }
        | TransferMsg::PullStream { .. } => "read",
        TransferMsg::TunnelDial { .. }
        | TransferMsg::TunnelBind { .. }
        | TransferMsg::TunnelBound { .. }
        | TransferMsg::TunnelIncoming { .. }
        | TransferMsg::TunnelAccept { .. }
        | TransferMsg::TunnelReady
        | TransferMsg::TunnelClose => "exec",
        _ => "meta",
    }
}

pub fn class_allowed(policy: crate::permissions::NodePolicy, class: &str) -> bool {
    match class {
        "read" => policy.allow_read,
        "write" => policy.allow_write,
        "exec" => policy.allow_exec,
        "desktop" => policy.allow_desktop || policy.allows_remote_view(),
        "meta" => {
            policy.allow_read || policy.allow_write || policy.allow_exec || policy.allow_desktop
        }
        _ => false,
    }
}

pub fn envelope_terminal(env: &Envelope) -> bool {
    match env {
        Envelope::Result { terminal, .. } => *terminal,
        Envelope::End { .. } => true,
        Envelope::Transfer { msg, terminal, .. } => *terminal || msg.is_terminal(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_hides_plaintext_and_rejects_a_swap() {
        let client = Endpoint::new(Identity::generate());
        let node = Endpoint::new(Identity::generate());
        let pending = client.client_hello(node.peer_id()).unwrap();
        let (client_id, welcome) = node.accept(Endpoint::hello_bytes(&pending)).unwrap();
        assert_eq!(client_id, client.peer_id());
        client.complete(pending, &welcome).unwrap();

        let secret = b"path=/etc/shadow command=rm -rf /";
        let blob = client.seal(node.peer_id(), b"req-1", secret).unwrap();
        assert!(!blob.windows(secret.len()).any(|w| w == secret));
        let opened = node.open(client.peer_id(), b"req-1", &blob).unwrap();
        assert_eq!(opened, secret);
        assert!(node.open(client.peer_id(), b"req-2", &blob).is_err());
        assert!(node.open(client.peer_id(), b"req-1", &blob).is_err());

        let back = node
            .seal(client.peer_id(), b"req-1", b"stdout-secret")
            .unwrap();
        assert_eq!(
            client.open(node.peer_id(), b"req-1", &back).unwrap(),
            b"stdout-secret"
        );
    }

    #[test]
    fn frame_payload_is_ciphertext_and_request_id_stays() {
        let client = Endpoint::new(Identity::generate());
        let node = Endpoint::new(Identity::generate());
        let pending = client.client_hello(node.peer_id()).unwrap();
        let (_, welcome) = node.accept(Endpoint::hello_bytes(&pending)).unwrap();
        client.complete(pending, &welcome).unwrap();

        let id = uuid::Uuid::new_v4().to_string();
        let frame = crate::frame::DataFrame {
            request_id: id.clone(),
            offset: 4096,
            raw_len: 4,
            compressed: false,
            hole: false,
            tar: false,
            payload: b"FILEBYTES-secret".to_vec(),
        };
        let raw = crate::frame::encode(&frame).unwrap();
        let sealed = client.seal_frame(node.peer_id(), &raw).unwrap();
        assert!(crate::frame::is_e2e(&sealed));
        assert_eq!(
            crate::frame::request_id(&sealed).as_deref(),
            Some(id.as_str())
        );
        assert!(!sealed.windows(16).any(|w| w == b"FILEBYTES-secret"));
        let opened = node.open_frame(client.peer_id(), &sealed).unwrap();
        let decoded = crate::frame::decode(&opened).unwrap();
        assert_eq!(decoded.payload, b"FILEBYTES-secret");
        assert_eq!(decoded.offset, 4096);
    }

    #[test]
    fn two_clients_same_identity_keep_independent_sessions() {
        let identity = Identity::generate();
        let client_a = Endpoint::new(identity.clone());
        let client_b = Endpoint::new(identity);
        let node = Endpoint::new(Identity::generate());

        let pending_a = client_a.client_hello(node.peer_id()).unwrap();
        let (id_a, welcome_a) = node.accept(Endpoint::hello_bytes(&pending_a)).unwrap();
        client_a.complete(pending_a, &welcome_a).unwrap();

        let pending_b = client_b.client_hello(node.peer_id()).unwrap();
        let (id_b, welcome_b) = node.accept(Endpoint::hello_bytes(&pending_b)).unwrap();
        client_b.complete(pending_b, &welcome_b).unwrap();
        assert_eq!(id_a, id_b);

        let blob_a = client_a.seal(node.peer_id(), b"req-a", b"from-a").unwrap();
        let blob_b = client_b.seal(node.peer_id(), b"req-b", b"from-b").unwrap();

        let (plain_a, session_a) = node.open_matched(&id_a, b"req-a", &blob_a).unwrap();
        let (plain_b, session_b) = node.open_matched(&id_b, b"req-b", &blob_b).unwrap();
        assert_eq!(plain_a, b"from-a");
        assert_eq!(plain_b, b"from-b");

        let back_a = seal_envelope_session(
            &session_a,
            node.peer_id(),
            &id_a,
            &Envelope::result_ok("req-a".into(), serde_json::json!({"ok": true})),
        )
        .unwrap();
        let back_b = seal_envelope_session(
            &session_b,
            node.peer_id(),
            &id_b,
            &Envelope::result_ok("req-b".into(), serde_json::json!({"ok": true})),
        )
        .unwrap();

        let opened_a = open_sealed(&client_a, node.peer_id(), back_a).unwrap();
        let opened_b = open_sealed(&client_b, node.peer_id(), back_b).unwrap();
        assert!(matches!(opened_a, Envelope::Result { ok: true, .. }));
        assert!(matches!(opened_b, Envelope::Result { ok: true, .. }));

        // Cross-sealing with the wrong session must not open on the other client.
        let cross = seal_envelope_session(
            &session_b,
            node.peer_id(),
            &id_a,
            &Envelope::result_ok("req-a2".into(), serde_json::json!({})),
        )
        .unwrap();
        assert!(open_sealed(&client_a, node.peer_id(), cross).is_err());
    }

    #[test]
    fn node_to_node_reply_opens_with_peer_node_id() {
        // Initiator A completes a handshake toward acceptor B, then B seals a
        // reply the way PeerCopy does (client_id = A, node_id = B). A must open
        // via open_routed falling back to B — not client_id alone (A's own id).
        let a = Endpoint::new(Identity::generate());
        let b = Endpoint::new(Identity::generate());
        let pending = a.client_hello(b.peer_id()).unwrap();
        let (initiator_id, welcome) = b.accept(Endpoint::hello_bytes(&pending)).unwrap();
        assert_eq!(initiator_id, a.peer_id());
        a.complete(pending, &welcome).unwrap();

        let push = Envelope::Transfer {
            request_id: "peer-1".into(),
            node_id: b.peer_id().to_string(),
            client_id: a.peer_id().to_string(),
            terminal: false,
            msg: TransferMsg::Accept {
                mode: crate::protocol::AcceptMode::Full { missing: Vec::new() },
            },
            authz: None,
        };
        // B seals a "reply" addressed like an acceptor: session under A.
        let reply = seal_envelope(&b, a.peer_id(), b.peer_id(), a.peer_id(), &push).unwrap();
        let Envelope::E2e {
            client_id,
            node_id,
            body_b64,
            request_id,
            ..
        } = &reply
        else {
            panic!("expected E2e");
        };
        assert_eq!(client_id, a.peer_id());
        assert_eq!(node_id, b.peer_id());
        let blob = crate::util::b64_decode(body_b64).unwrap();
        // Bug shape: opening only with client_id looks up A's session on A.
        assert!(a.open_matched(client_id, request_id.as_bytes(), &blob).is_err());
        let (plain, _session, peer) = a
            .open_routed(client_id, node_id, request_id.as_bytes(), &blob)
            .unwrap();
        assert_eq!(peer, b.peer_id());
        let opened: Envelope = serde_json::from_slice(&plain).unwrap();
        assert!(matches!(opened, Envelope::Transfer { .. }));
    }
}
