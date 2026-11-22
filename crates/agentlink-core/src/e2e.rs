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

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

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
/// Trailing capability tag on v2 hello (132 bytes) and v2 welcome (100 bytes)
/// that cryptographically negotiates [`frame_aad_v2`] via the Ed25519
/// handshake transcript while keeping 128-byte v1 handshakes interoperable
/// with older nodes during rolling upgrades.
const HELLO_V2_MAGIC: [u8; 4] = *b"FV2\x01";
const REPLAY_WINDOW_BITS: u64 = 4096;
const REPLAY_WORDS: usize = (REPLAY_WINDOW_BITS as usize) / 64;
const MAX_SESSION_COUNTER: u64 = u64::MAX - 1;

fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    std::hint::black_box(buf);
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

struct ReplayWindow {
    max_seen: Option<u64>,
    /// Bit `d` (`0 <= d < 4096`) is set iff counter `(max_seen - d)` was accepted.
    bitmap: [u64; REPLAY_WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            max_seen: None,
            bitmap: [0u64; REPLAY_WORDS],
        }
    }
}

impl ReplayWindow {
    fn accept(&mut self, n: u64) -> Result<()> {
        if n > MAX_SESSION_COUNTER {
            return Err(Error::Protocol("invalid e2e frame counter".into()));
        }
        let Some(max) = self.max_seen else {
            self.max_seen = Some(n);
            self.bitmap[0] = 1;
            return Ok(());
        };
        if n > max {
            let shift = n - max;
            if shift >= REPLAY_WINDOW_BITS {
                self.bitmap = [0u64; REPLAY_WORDS];
            } else {
                let word_shift = (shift / 64) as usize;
                let bit_shift = (shift % 64) as u32;
                for i in (0..REPLAY_WORDS).rev() {
                    if i < word_shift {
                        self.bitmap[i] = 0;
                    } else if bit_shift == 0 {
                        self.bitmap[i] = self.bitmap[i - word_shift];
                    } else {
                        let hi = self.bitmap[i - word_shift] << bit_shift;
                        let lo = if i > word_shift {
                            self.bitmap[i - word_shift - 1] >> (64 - bit_shift)
                        } else {
                            0
                        };
                        self.bitmap[i] = hi | lo;
                    }
                }
            }
            self.bitmap[0] |= 1;
            self.max_seen = Some(n);
            return Ok(());
        }
        let delta = max - n;
        if delta >= REPLAY_WINDOW_BITS {
            return Err(Error::Protocol("replayed or expired e2e frame".into()));
        }
        let word = (delta / 64) as usize;
        let mask = 1u64 << ((delta % 64) as u32);
        if (self.bitmap[word] & mask) != 0 {
            return Err(Error::Protocol("replayed e2e frame".into()));
        }
        self.bitmap[word] |= mask;
        Ok(())
    }
}

/// Keys for one direction pair after a finished handshake.
///
/// Both [`ChaCha20Poly1305`] instances implement `ZeroizeOnDrop`; `Drop` also
/// scrubs ephemeral metadata buffers.
pub struct Direction {
    encrypt: ChaCha20Poly1305,
    decrypt: ChaCha20Poly1305,
    frame_aad_v2: bool,
    send_n: AtomicU64,
    seen: Mutex<ReplayWindow>,
    epoch: Instant,
    last_active_ms: AtomicU64,
    received_any: AtomicBool,
    client_eph: Option<[u8; 32]>,
    cached_welcome: Option<Vec<u8>>,
}

impl Drop for Direction {
    fn drop(&mut self) {
        if let Some(eph) = self.client_eph.as_mut() {
            zeroize_bytes(eph);
        }
        if let Some(welcome) = self.cached_welcome.as_mut() {
            zeroize_bytes(welcome);
        }
        // `self.encrypt` and `self.decrypt` are `ChaCha20Poly1305`, whose
        // `Drop` calls `zeroize::Zeroize` on the 32-byte key material.
    }
}

impl Direction {
    fn new(
        mut encrypt_key: [u8; 32],
        mut decrypt_key: [u8; 32],
        frame_aad_v2: bool,
        epoch: Instant,
        now_ms: u64,
        client_eph: Option<[u8; 32]>,
        cached_welcome: Option<Vec<u8>>,
    ) -> Self {
        let encrypt = ChaCha20Poly1305::new((&encrypt_key).into());
        let decrypt = ChaCha20Poly1305::new((&decrypt_key).into());
        zeroize_bytes(&mut encrypt_key);
        zeroize_bytes(&mut decrypt_key);
        Self {
            encrypt,
            decrypt,
            frame_aad_v2,
            send_n: AtomicU64::new(1),
            seen: Mutex::new(ReplayWindow::default()),
            epoch,
            last_active_ms: AtomicU64::new(now_ms),
            received_any: AtomicBool::new(false),
            client_eph,
            cached_welcome,
        }
    }

    pub fn uses_frame_aad_v2(&self) -> bool {
        self.frame_aad_v2
    }

    fn touch(&self) {
        let ms = self.epoch.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        self.last_active_ms.store(ms, Ordering::Relaxed);
    }

    /// Seal a plaintext with this session's send counter.
    pub fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        let mut cur = self.send_n.load(Ordering::Relaxed);
        let n = loop {
            if cur > MAX_SESSION_COUNTER {
                return Err(Error::Protocol(
                    "e2e session counter exhausted; re-handshake required".into(),
                ));
            }
            match self.send_n.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(prev) => break prev,
                Err(actual) => cur = actual,
            }
        };
        let out = aead_seal(&self.encrypt, n, aad, plain)?;
        self.touch();
        Ok(out)
    }

    fn open_one(&self, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        let (n, plain) = aead_open(&self.decrypt, aad, blob)?;
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| Error::Message("e2e replay lock poisoned".into()))?;
        seen.accept(n)?;
        drop(seen);
        self.received_any.store(true, Ordering::Release);
        self.touch();
        Ok(plain)
    }

    fn aad_for_frame(&self, frame: &[u8], decoded: &crate::frame::DataFrame) -> Result<Vec<u8>> {
        if self.frame_aad_v2 {
            let (version, kind, non_e2e_flags, offset, raw_len, request_id) =
                crate::frame::header_fields(frame)?;
            Ok(frame_aad_v2(
                version,
                kind,
                non_e2e_flags,
                offset,
                raw_len,
                &request_id,
            ))
        } else {
            Ok(frame_aad(&decoded.request_id, decoded.offset))
        }
    }

    /// Encrypt a binary file frame's payload with this session.
    pub fn seal_frame(&self, frame: &[u8]) -> Result<Vec<u8>> {
        let decoded = crate::frame::decode(frame)?;
        let aad = self.aad_for_frame(frame, &decoded)?;
        let sealed = self.seal(&aad, &decoded.payload)?;
        crate::frame::replace_payload(frame, &sealed, true)
    }

    /// Decrypt a binary file frame's payload with this session.
    pub fn open_frame(&self, frame: &[u8]) -> Result<Vec<u8>> {
        if !crate::frame::is_e2e(frame) {
            return Err(Error::Protocol(
                "file frame is not end-to-end; plaintext file bytes are refused".into(),
            ));
        }
        let decoded = crate::frame::decode(frame)?;
        let aad = self.aad_for_frame(frame, &decoded)?;
        let plain = self.open_one(&aad, &decoded.payload)?;
        if decoded.hole && !plain.is_empty() {
            return Err(Error::Protocol(
                "hole frame must have empty payload".into(),
            ));
        }
        crate::frame::replace_payload(frame, &plain, false)
    }
}

/// In-progress client handshake. Holds the ephemeral secret until welcome.
pub struct PendingHello {
    secret: EphemeralSecret,
    node_id: String,
    hello: Vec<u8>,
    frame_aad_v2: bool,
}

/// How many handshakes to keep per peer ed25519 id.
///
/// Several CLI processes often share one saved client identity. Each dials its
/// own e2e handshake. Replacing the only session made an in-flight `cp` fail
/// to decrypt replies after another command shook hands.
const MAX_SESSIONS_PER_PEER: usize = 8;
const MAX_STAGED_PER_PEER: usize = 4;
const MAX_RETIRED_PER_PEER: usize = 64;
pub const MAX_TRACKED_PEERS: usize = 1024;
pub const IDLE_PEER_TTL_MS: u64 = 15 * 60 * 1000;
/// Separate bounded LRU for unverified `E2eHello` handshakes so spoofed hellos
/// can never fill `MAX_TRACKED_PEERS` and lock out legitimate controllers.
pub const MAX_STAGED_PEERS: usize = 64;
pub const STAGED_PEER_TTL_MS: u64 = 30 * 1000;
const MAX_PRUNED_RETIRED_HELLOS: usize = 4096;

type DirectionRing = VecDeque<Arc<Direction>>;

struct StagedSession {
    direction: Arc<Direction>,
    created_ms: u64,
}

#[derive(Default)]
struct StagedPeerEntry {
    sessions: VecDeque<StagedSession>,
}

impl StagedPeerEntry {
    fn prune_expired(&mut self, now_ms: u64) {
        self.sessions
            .retain(|s| now_ms.saturating_sub(s.created_ms) < STAGED_PEER_TTL_MS);
    }

    fn push(&mut self, direction: Arc<Direction>, now_ms: u64) {
        self.sessions.push_back(StagedSession {
            direction,
            created_ms: now_ms,
        });
        while self.sessions.len() > MAX_STAGED_PER_PEER {
            let _ = self.sessions.pop_front();
        }
    }
}

#[derive(Default)]
struct PeerEntry {
    /// Sessions proven live (locally completed via `complete`, or acceptor
    /// sessions that decrypted at least one authenticated AEAD frame).
    verified: DirectionRing,
    retired_order: VecDeque<[u8; 32]>,
    retired_set: HashSet<[u8; 32]>,
}

impl PeerEntry {
    fn retire_eph(&mut self, eph: [u8; 32]) {
        if self.retired_set.insert(eph) {
            self.retired_order.push_back(eph);
            while self.retired_order.len() > MAX_RETIRED_PER_PEER {
                if let Some(oldest) = self.retired_order.pop_front() {
                    self.retired_set.remove(&oldest);
                }
            }
        }
    }

    fn newest_activity_ms(&self) -> u64 {
        self.verified
            .iter()
            .map(|dir| dir.last_active_ms.load(Ordering::Relaxed))
            .max()
            .unwrap_or(0)
    }

    fn push_verified(&mut self, direction: Arc<Direction>) {
        self.verified.push_back(direction);
        while self.verified.len() > MAX_SESSIONS_PER_PEER {
            let evict_idx = self
                .verified
                .iter()
                .enumerate()
                .min_by_key(|(_, dir)| dir.last_active_ms.load(Ordering::Relaxed))
                .map(|(idx, _)| idx)
                .unwrap_or(0);
            if let Some(evicted) = self.verified.remove(evict_idx) {
                if let Some(eph) = evicted.client_eph {
                    self.retire_eph(eph);
                }
            }
        }
    }
}

#[derive(Default)]
struct EndpointState {
    /// Verified active peers only (capped at `MAX_TRACKED_PEERS`).
    peers: HashMap<String, PeerEntry>,
    /// Unverified staged handshakes isolated in a separate bounded LRU
    /// (`MAX_STAGED_PEERS` slots, `STAGED_PEER_TTL_MS` TTL).
    staged: HashMap<String, StagedPeerEntry>,
    staged_lru: VecDeque<String>,
    pruned_retired_order: VecDeque<[u8; 32]>,
    pruned_retired_set: HashSet<[u8; 32]>,
}

impl EndpointState {
    fn retire_pruned_eph(&mut self, eph: [u8; 32]) {
        if self.pruned_retired_set.insert(eph) {
            self.pruned_retired_order.push_back(eph);
            while self.pruned_retired_order.len() > MAX_PRUNED_RETIRED_HELLOS {
                if let Some(oldest) = self.pruned_retired_order.pop_front() {
                    self.pruned_retired_set.remove(&oldest);
                }
            }
        }
    }

    fn retire_peer_entry(&mut self, entry: PeerEntry) {
        for eph in entry.retired_order {
            self.retire_pruned_eph(eph);
        }
        for dir in entry.verified {
            if let Some(eph) = dir.client_eph {
                self.retire_pruned_eph(eph);
            }
        }
    }

    fn prune_expired_staged(&mut self, now_ms: u64) {
        let mut empty = Vec::new();
        for (peer, entry) in self.staged.iter_mut() {
            entry.prune_expired(now_ms);
            if entry.sessions.is_empty() {
                empty.push(peer.clone());
            }
        }
        for key in empty {
            self.staged.remove(&key);
            self.staged_lru.retain(|k| k != &key);
        }
    }

    fn push_staged(&mut self, peer: String, direction: Arc<Direction>, now_ms: u64) {
        self.prune_expired_staged(now_ms);
        if let Some(entry) = self.staged.get_mut(&peer) {
            entry.push(direction, now_ms);
            self.staged_lru.retain(|k| k != &peer);
            self.staged_lru.push_back(peer);
            return;
        }
        while self.staged.len() >= MAX_STAGED_PEERS {
            let Some(oldest) = self.staged_lru.pop_front() else {
                break;
            };
            self.staged.remove(&oldest);
        }
        let mut entry = StagedPeerEntry::default();
        entry.push(direction, now_ms);
        self.staged.insert(peer.clone(), entry);
        self.staged_lru.push_back(peer);
    }

    fn prune_idle_peers(&mut self, now_ms: u64, idle_ttl_ms: u64) {
        let stale_keys: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, entry)| now_ms.saturating_sub(entry.newest_activity_ms()) >= idle_ttl_ms)
            .map(|(peer, _)| peer.clone())
            .collect();
        for key in stale_keys {
            if let Some(removed) = self.peers.remove(&key) {
                self.retire_peer_entry(removed);
            }
        }
    }
}

/// Sessions this process has completed, keyed by the peer's ed25519 id.
///
/// Each peer may hold several live [`Direction`] values (newest at the back).
#[derive(Clone)]
pub struct Endpoint {
    identity: Arc<Identity>,
    epoch: Instant,
    state: Arc<Mutex<EndpointState>>,
}

impl Endpoint {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity: Arc::new(identity),
            epoch: Instant::now(),
            state: Arc::new(Mutex::new(EndpointState::default())),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn peer_id(&self) -> &str {
        self.identity.public_hex()
    }

    pub fn has(&self, peer: &str) -> bool {
        let now_ms = self.now_ms();
        self.state
            .lock()
            .map(|state| {
                state.peers.contains_key(peer)
                    || state.staged.get(peer).is_some_and(|s| {
                        s.sessions
                            .iter()
                            .any(|item| now_ms.saturating_sub(item.created_ms) < STAGED_PEER_TTL_MS)
                    })
            })
            .unwrap_or(false)
    }

    /// True when the newest active session for `peer` negotiated `frame_aad_v2`.
    pub fn peer_uses_frame_aad_v2(&self, peer: &str) -> bool {
        self.direction(peer)
            .map(|d| d.uses_frame_aad_v2())
            .unwrap_or(false)
    }

    /// Drop a session so the next payload starts a fresh handshake.
    pub fn forget(&self, peer: &str) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(removed) = state.peers.remove(peer) {
                state.retire_peer_entry(removed);
            }
            if let Some(staged) = state.staged.remove(peer) {
                state.staged_lru.retain(|k| k != peer);
                for item in staged.sessions {
                    if let Some(eph) = item.direction.client_eph {
                        state.retire_pruned_eph(eph);
                    }
                }
            }
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
            frame_aad_v2: false,
        })
    }

    /// Client hello that cryptographically negotiates `frame_aad_v2` (binding
    /// binary frame header fields `version`, `kind`, non-E2E `flags`, `offset`,
    /// `raw_len`, and `request_id` into ChaCha20-Poly1305 AAD).
    pub fn client_hello_v2(&self, node_id: &str) -> Result<PendingHello> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let eph = public.to_bytes();
        let message = sign_message_v2("client", &eph, node_id, &self.identity)?;
        let mut hello = Vec::with_capacity(32 + 32 + 64 + HELLO_V2_MAGIC.len());
        hello.extend_from_slice(&eph);
        hello.extend_from_slice(&identity::public_bytes(self.identity.public_hex())?);
        hello.extend_from_slice(&message);
        hello.extend_from_slice(&HELLO_V2_MAGIC);
        Ok(PendingHello {
            secret,
            node_id: node_id.to_string(),
            hello,
            frame_aad_v2: true,
        })
    }

    pub fn hello_bytes(pending: &PendingHello) -> &[u8] {
        &pending.hello
    }

    /// Node side. Verifies the client, stores the staged session under the
    /// client id in the bounded staged LRU, and returns the welcome message.
    /// Accepts both 128-byte v1 hellos (older clients) and 132-byte v2 hellos
    /// negotiating `frame_aad_v2`.
    pub fn accept(&self, hello: &[u8]) -> Result<(String, Vec<u8>)> {
        let frame_aad_v2 = match hello.len() {
            128 => false,
            132 if hello[128..132] == HELLO_V2_MAGIC => true,
            _ => return Err(Error::Protocol("e2e hello has the wrong length".into())),
        };
        let mut client_eph = [0u8; 32];
        client_eph.copy_from_slice(&hello[..32]);
        let mut client_pk = [0u8; 32];
        client_pk.copy_from_slice(&hello[32..64]);
        let sig = &hello[64..128];
        let client_id = hex::encode(client_pk);
        let signed = if frame_aad_v2 {
            transcript_v2("client", &client_eph, self.identity.public_hex())
        } else {
            transcript("client", &client_eph, self.identity.public_hex())
        };
        identity::verify_message(&client_id, signed.as_bytes(), &hex::encode(sig))?;

        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let node_eph = public.to_bytes();
        let shared = secret.diffie_hellman(&PublicKey::from(client_eph));
        if !shared.was_contributory() {
            return Err(Error::Protocol(
                "non-contributory x25519 peer public key".into(),
            ));
        }
        let (c2n, n2c) = derive(shared.as_bytes(), &client_eph, &node_eph);
        let message = if frame_aad_v2 {
            sign_raw_v2("node", &client_eph, &node_eph, &client_id, &self.identity)?
        } else {
            sign_raw("node", &client_eph, &node_eph, &client_id, &self.identity)?
        };
        let mut welcome = Vec::with_capacity(
            32 + 64 + if frame_aad_v2 { HELLO_V2_MAGIC.len() } else { 0 },
        );
        welcome.extend_from_slice(&node_eph);
        welcome.extend_from_slice(&message);
        if frame_aad_v2 {
            welcome.extend_from_slice(&HELLO_V2_MAGIC);
        }
        let now_ms = self.now_ms();
        let candidate = Arc::new(Direction::new(
            n2c,
            c2n,
            frame_aad_v2,
            self.epoch,
            now_ms,
            Some(client_eph),
            Some(welcome.clone()),
        ));

        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Message("e2e session lock poisoned".into()))?;
        state.prune_expired_staged(now_ms);
        if state.pruned_retired_set.contains(&client_eph) {
            return Err(Error::Protocol("replayed e2e hello".into()));
        }
        if let Some(peer_entry) = state.peers.get(&client_id) {
            if peer_entry.retired_set.contains(&client_eph)
                || peer_entry
                    .verified
                    .iter()
                    .any(|dir| dir.client_eph == Some(client_eph))
            {
                return Err(Error::Protocol("replayed e2e hello".into()));
            }
        } else if state.peers.len() >= MAX_TRACKED_PEERS {
            state.prune_idle_peers(now_ms, IDLE_PEER_TTL_MS);
            if state.peers.len() >= MAX_TRACKED_PEERS {
                return Err(Error::Protocol(format!(
                    "e2e peer table at capacity ({MAX_TRACKED_PEERS} active peers)"
                )));
            }
        }
        if let Some(staged_entry) = state.staged.get(&client_id) {
            if let Some(existing) = staged_entry
                .sessions
                .iter()
                .find(|s| s.direction.client_eph == Some(client_eph))
            {
                if !existing.direction.received_any.load(Ordering::Acquire) {
                    if let Some(cached) = &existing.direction.cached_welcome {
                        // Do NOT refresh TTL or touch activity on unauthenticated replays.
                        return Ok((client_id, cached.clone()));
                    }
                }
                return Err(Error::Protocol("replayed e2e hello".into()));
            }
        }
        state.push_staged(client_id.clone(), candidate, now_ms);
        Ok((client_id, welcome))
    }

    pub fn complete(&self, pending: PendingHello, welcome: &[u8]) -> Result<()> {
        let expect_len = if pending.frame_aad_v2 { 100 } else { 96 };
        if welcome.len() != expect_len {
            return Err(Error::Protocol("e2e welcome has the wrong length".into()));
        }
        if pending.frame_aad_v2 && welcome[96..100] != HELLO_V2_MAGIC {
            return Err(Error::Protocol(
                "e2e welcome missing frame_aad_v2 capability tag".into(),
            ));
        }
        let mut node_eph = [0u8; 32];
        node_eph.copy_from_slice(&welcome[..32]);
        let sig = &welcome[32..96];
        let client_eph = PublicKey::from(&pending.secret).to_bytes();
        let signed = if pending.frame_aad_v2 {
            transcript_node_v2(&client_eph, &node_eph, self.identity.public_hex())
        } else {
            transcript_node(&client_eph, &node_eph, self.identity.public_hex())
        };
        identity::verify_message(&pending.node_id, signed.as_bytes(), &hex::encode(sig))?;
        let shared = pending.secret.diffie_hellman(&PublicKey::from(node_eph));
        if !shared.was_contributory() {
            return Err(Error::Protocol(
                "non-contributory x25519 peer public key".into(),
            ));
        }
        let (c2n, n2c) = derive(shared.as_bytes(), &client_eph, &node_eph);
        let now_ms = self.now_ms();
        self.insert_verified_with_now(
            &pending.node_id,
            Direction::new(
                c2n,
                n2c,
                pending.frame_aad_v2,
                self.epoch,
                now_ms,
                Some(client_eph),
                None,
            ),
            now_ms,
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
        let (verified, staged) = self.sessions_for(peer)?;
        let mut last_err = Error::Protocol(format!("no e2e session for {peer}"));
        for keys in verified.iter().rev() {
            match keys.open_one(aad, blob) {
                Ok(plain) => return Ok((plain, Arc::clone(keys))),
                Err(err) => last_err = err,
            }
        }
        for keys in staged.iter().rev() {
            match keys.open_one(aad, blob) {
                Ok(plain) => {
                    self.promote_staged(peer, keys)?;
                    return Ok((plain, Arc::clone(keys)));
                }
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
            return Err(Error::Protocol(
                "file frame is not end-to-end; plaintext file bytes are refused".into(),
            ));
        }
        // Fail fast on malformed headers / oversized hole frames before trying keys.
        let _ = crate::frame::decode(frame)?;
        let (verified, staged) = self.sessions_for(peer)?;
        let mut last_err = Error::Protocol(format!("no e2e session for {peer}"));
        for keys in verified.iter().rev() {
            match keys.open_frame(frame) {
                Ok(opened) => return Ok(opened),
                Err(err) => last_err = err,
            }
        }
        for keys in staged.iter().rev() {
            match keys.open_frame(frame) {
                Ok(opened) => {
                    self.promote_staged(peer, keys)?;
                    return Ok(opened);
                }
                Err(err) => last_err = err,
            }
        }
        Err(last_err)
    }

    fn promote_staged(&self, peer: &str, matched: &Arc<Direction>) -> Result<()> {
        let now_ms = self.now_ms();
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Message("e2e session lock poisoned".into()))?;
        if let Some(staged_entry) = state.staged.get_mut(peer) {
            if let Some(pos) = staged_entry
                .sessions
                .iter()
                .position(|cand| Arc::ptr_eq(&cand.direction, matched))
            {
                let _ = staged_entry.sessions.remove(pos);
            }
            if staged_entry.sessions.is_empty() {
                state.staged.remove(peer);
                state.staged_lru.retain(|k| k != peer);
            }
        }
        if !state.peers.contains_key(peer) && state.peers.len() >= MAX_TRACKED_PEERS {
            state.prune_idle_peers(now_ms, IDLE_PEER_TTL_MS);
            if state.peers.len() >= MAX_TRACKED_PEERS {
                return Err(Error::Protocol(format!(
                    "e2e peer table at capacity ({MAX_TRACKED_PEERS} active peers)"
                )));
            }
        }
        let entry = state.peers.entry(peer.to_string()).or_default();
        if !entry
            .verified
            .iter()
            .any(|cand| Arc::ptr_eq(cand, matched))
        {
            entry.push_verified(Arc::clone(matched));
        }
        Ok(())
    }

    fn insert_verified_with_now(&self, peer: &str, direction: Direction, now_ms: u64) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Message("e2e session lock poisoned".into()))?;
        if !state.peers.contains_key(peer) && state.peers.len() >= MAX_TRACKED_PEERS {
            state.prune_idle_peers(now_ms, IDLE_PEER_TTL_MS);
            if state.peers.len() >= MAX_TRACKED_PEERS {
                return Err(Error::Protocol(format!(
                    "e2e peer table at capacity ({MAX_TRACKED_PEERS} active peers)"
                )));
            }
        }
        state
            .peers
            .entry(peer.to_string())
            .or_default()
            .push_verified(Arc::new(direction));
        Ok(())
    }

    /// Newest session for `peer` (used when this process seals as the initiator).
    fn direction(&self, peer: &str) -> Result<Arc<Direction>> {
        let (verified, staged) = self.sessions_for(peer)?;
        verified
            .back()
            .or_else(|| staged.back())
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("no e2e session for {peer}")))
    }

    fn sessions_for(&self, peer: &str) -> Result<(DirectionRing, DirectionRing)> {
        let now_ms = self.now_ms();
        let guard = self
            .state
            .lock()
            .map_err(|_| Error::Message("e2e session lock poisoned".into()))?;
        let verified = guard
            .peers
            .get(peer)
            .map(|e| e.verified.clone())
            .unwrap_or_default();
        let staged: DirectionRing = guard
            .staged
            .get(peer)
            .map(|e| {
                e.sessions
                    .iter()
                    .filter(|s| now_ms.saturating_sub(s.created_ms) < STAGED_PEER_TTL_MS)
                    .map(|s| Arc::clone(&s.direction))
                    .collect()
            })
            .unwrap_or_default();
        if verified.is_empty() && staged.is_empty() {
            return Err(Error::Protocol(format!("no e2e session for {peer}")));
        }
        Ok((verified, staged))
    }

    pub fn peer_ids(&self) -> Vec<String> {
        let now_ms = self.now_ms();
        self.state
            .lock()
            .map(|state| {
                let mut set: HashSet<String> = state.peers.keys().cloned().collect();
                for (peer, entry) in &state.staged {
                    if entry
                        .sessions
                        .iter()
                        .any(|s| now_ms.saturating_sub(s.created_ms) < STAGED_PEER_TTL_MS)
                    {
                        set.insert(peer.clone());
                    }
                }
                set.into_iter().collect()
            })
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
        .ok_or_else(|| Error::Protocol("e2e envelope needs a request id".into()))?;
    seal_control_envelope(endpoint, peer, node_id, client_id, request_id, env)
}

/// Wrap a control envelope (such as [`Envelope::Session`], which carries no
/// inner `request_id`) using an explicit outer `request_id` for relay routing
/// and ChaCha20-Poly1305 associated data.
pub fn seal_control_envelope(
    endpoint: &Endpoint,
    peer: &str,
    node_id: &str,
    client_id: &str,
    request_id: &str,
    env: &Envelope,
) -> Result<Envelope> {
    if request_id.is_empty() {
        return Err(Error::Protocol(
            "e2e control envelope needs a request id".into(),
        ));
    }
    let plain = serde_json::to_vec(env)?;
    let blob = endpoint.seal(peer, request_id.as_bytes(), &plain)?;
    Ok(Envelope::E2e {
        request_id: request_id.to_string(),
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

/// Open a file frame only with the peer bound to this transfer.
///
/// A missing flag, a tag failure, a replay, or a request id that does not
/// match the ciphertext is an error. The frame is not accepted as plaintext,
/// and another live session is not tried.
pub fn open_bound_frame(endpoint: &Endpoint, peer: &str, frame: &[u8]) -> Result<Vec<u8>> {
    if peer.is_empty() {
        return Err(Error::Protocol(
            "file frame has no end-to-end peer".into(),
        ));
    }
    endpoint.open_frame(peer, frame)
}

fn frame_aad(request_id: &str, offset: u64) -> Vec<u8> {
    let mut aad = b"frame".to_vec();
    aad.extend_from_slice(&offset.to_le_bytes());
    aad.extend_from_slice(request_id.as_bytes());
    aad
}

fn frame_aad_v2(
    version: u8,
    kind: u8,
    non_e2e_flags: u16,
    offset: u64,
    raw_len: u32,
    request_id: &str,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 1 + 1 + 2 + 8 + 4 + request_id.len());
    aad.extend_from_slice(b"frame-v2");
    aad.push(version);
    aad.push(kind);
    aad.extend_from_slice(&non_e2e_flags.to_le_bytes());
    aad.extend_from_slice(&offset.to_le_bytes());
    aad.extend_from_slice(&raw_len.to_le_bytes());
    aad.extend_from_slice(request_id.as_bytes());
    aad
}

fn transcript(role: &str, eph: &[u8], other: &str) -> String {
    format!("{INFO:?}|{role}|{}|{other}", hex::encode(eph))
}

fn transcript_v2(role: &str, eph: &[u8], other: &str) -> String {
    format!("{INFO:?}|v2|frame-aad-v2|{role}|{}|{other}", hex::encode(eph))
}

fn transcript_node(client_eph: &[u8], node_eph: &[u8], client_id: &str) -> String {
    format!(
        "{INFO:?}|node|{}|{}|{client_id}",
        hex::encode(client_eph),
        hex::encode(node_eph)
    )
}

fn transcript_node_v2(client_eph: &[u8], node_eph: &[u8], client_id: &str) -> String {
    format!(
        "{INFO:?}|v2|frame-aad-v2|node|{}|{}|{client_id}",
        hex::encode(client_eph),
        hex::encode(node_eph)
    )
}

fn sign_message(role: &str, eph: &[u8], other: &str, identity: &Identity) -> Result<Vec<u8>> {
    let text = transcript(role, eph, other);
    decode_sig(&identity.sign_message(text.as_bytes()))
}

fn sign_message_v2(role: &str, eph: &[u8], other: &str, identity: &Identity) -> Result<Vec<u8>> {
    let text = transcript_v2(role, eph, other);
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

fn sign_raw_v2(
    role: &str,
    client_eph: &[u8],
    node_eph: &[u8],
    client_id: &str,
    identity: &Identity,
) -> Result<Vec<u8>> {
    let _ = role;
    let text = transcript_node_v2(client_eph, node_eph, client_id);
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
    zeroize_bytes(&mut okm);
    (c2n, n2c)
}

fn aead_seal(cipher: &ChaCha20Poly1305, n: u64, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
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

fn aead_open(cipher: &ChaCha20Poly1305, aad: &[u8], blob: &[u8]) -> Result<(u64, Vec<u8>)> {
    if blob.len() < 8 + 16 {
        return Err(Error::Protocol("e2e blob is short".into()));
    }
    let n = u64::from_le_bytes(blob[..8].try_into().unwrap());
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
        Envelope::Session { .. } => true,
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

    #[test]
    fn old_frame_beyond_4096_window_stays_permanently_rejected_and_out_of_order_works() {
        let client = Endpoint::new(Identity::generate());
        let node = Endpoint::new(Identity::generate());
        let pending = client.client_hello(node.peer_id()).unwrap();
        let (_, welcome) = node.accept(Endpoint::hello_bytes(&pending)).unwrap();
        client.complete(pending, &welcome).unwrap();

        let first = client.seal(node.peer_id(), b"req", b"m1").unwrap();
        assert_eq!(node.open(client.peer_id(), b"req", &first).unwrap(), b"m1");

        // Advance past the 4096-frame sliding window.
        let mut hold_recent = Vec::new();
        for idx in 0..4105u32 {
            let ct = client
                .seal(node.peer_id(), b"req", &idx.to_le_bytes())
                .unwrap();
            if idx == 4100 || idx == 4101 {
                // Hold two in-window packets to deliver out-of-order after 4104.
                hold_recent.push((idx, ct));
            } else {
                assert_eq!(
                    node.open(client.peer_id(), b"req", &ct).unwrap(),
                    idx.to_le_bytes()
                );
            }
        }

        // Replaying the very first ciphertext after >4096 packets MUST still fail!
        assert!(
            node.open(client.peer_id(), b"req", &first).is_err(),
            "frame older than 4096-packet window was accepted again on replay!"
        );

        // Out-of-order frames inside the 4096-bit window open once and reject second time.
        for (idx, ct) in hold_recent.into_iter().rev() {
            assert_eq!(
                node.open(client.peer_id(), b"req", &ct).unwrap(),
                idx.to_le_bytes()
            );
            assert!(node.open(client.peer_id(), b"req", &ct).is_err());
        }
    }

    #[test]
    fn replayed_hello_cannot_evict_active_peer_sessions() {
        let shared_id = Identity::generate();
        let active_client = Endpoint::new(shared_id.clone());
        let replay_source = Endpoint::new(shared_id);
        let node = Endpoint::new(Identity::generate());

        let p_active = active_client.client_hello(node.peer_id()).unwrap();
        let (_, w_active) = node.accept(Endpoint::hello_bytes(&p_active)).unwrap();
        active_client.complete(p_active, &w_active).unwrap();
        let ct0 = active_client
            .seal(node.peer_id(), b"r0", b"alive-0")
            .unwrap();
        assert_eq!(
            node.open(active_client.peer_id(), b"r0", &ct0).unwrap(),
            b"alive-0"
        );

        // Relay captures one valid hello and replays it 16 times trying to churn MAX_SESSIONS_PER_PEER.
        let p_captured = replay_source.client_hello(node.peer_id()).unwrap();
        let captured_hello = Endpoint::hello_bytes(&p_captured).to_vec();
        let (_, w_first) = node.accept(&captured_hello).unwrap();
        // Before first ciphertext: idempotent welcome (reconnect safety), no extra slot churn.
        for _ in 0..12 {
            let _ = node.accept(&captured_hello);
        }
        // Active session MUST still be alive and decrypting!
        let ct1 = active_client
            .seal(node.peer_id(), b"r1", b"alive-1")
            .unwrap();
        assert_eq!(
            node.open(active_client.peer_id(), b"r1", &ct1).unwrap(),
            b"alive-1"
        );

        // Once the second session sends traffic, replaying its E2eHello is hard-rejected.
        replay_source.complete(p_captured, &w_first).unwrap();
        let ct_b = replay_source.seal(node.peer_id(), b"rb", b"used").unwrap();
        assert_eq!(
            node.open(replay_source.peer_id(), b"rb", &ct_b).unwrap(),
            b"used"
        );
        assert!(
            node.accept(&captured_hello).is_err(),
            "replayed E2eHello for an already-used session must be rejected"
        );
    }

    #[test]
    fn counter_exhaustion_fails_closed_without_nonce_wrap() {
        let client = Endpoint::new(Identity::generate());
        let node = Endpoint::new(Identity::generate());
        let pending = client.client_hello(node.peer_id()).unwrap();
        let (_, welcome) = node.accept(Endpoint::hello_bytes(&pending)).unwrap();
        client.complete(pending, &welcome).unwrap();

        let dir = client.direction(node.peer_id()).unwrap();
        dir.send_n.store(MAX_SESSION_COUNTER, Ordering::SeqCst);
        let last_ok = client.seal(node.peer_id(), b"aad", b"penultimate").unwrap();
        assert_eq!(
            node.open(client.peer_id(), b"aad", &last_ok).unwrap(),
            b"penultimate"
        );
        let exhausted = client.seal(node.peer_id(), b"aad", b"overflow");
        assert!(exhausted.is_err(), "counter must fail closed at u64::MAX");
        assert_eq!(dir.send_n.load(Ordering::SeqCst), u64::MAX);
    }

    #[test]
    fn peer_table_cap_prunes_only_idle_peers_and_never_evicts_active_sessions() {
        let node = Endpoint::new(Identity::generate());
        let active = Endpoint::new(Identity::generate());
        let p0 = active.client_hello(node.peer_id()).unwrap();
        let (_, w0) = node.accept(Endpoint::hello_bytes(&p0)).unwrap();
        active.complete(p0, &w0).unwrap();
        // Send one authenticated frame so `active` promotes from staged LRU to verified `peers`.
        let init_ct = active.seal(node.peer_id(), b"init", b"hi").unwrap();
        assert_eq!(node.open(active.peer_id(), b"init", &init_ct).unwrap(), b"hi");

        // Fill remaining MAX_TRACKED_PEERS - 1 slots with synthetic verified peers.
        {
            let mut state = node.state.lock().unwrap();
            for i in 1..MAX_TRACKED_PEERS {
                let mut pe = PeerEntry::default();
                pe.push_verified(Arc::new(Direction::new(
                    [1u8; 32],
                    [2u8; 32],
                    true,
                    node.epoch,
                    1_000_000,
                    Some([i as u8; 32]),
                    None,
                )));
                state.peers.insert(format!("peer-{i}"), pe);
            }
            // Mark active peer fresh too.
            let active_pe = state.peers.get(active.peer_id()).unwrap();
            for dir in active_pe.verified.iter() {
                dir.last_active_ms.store(1_000_000, Ordering::SeqCst);
            }
        }

        // When all 1024 verified peers are active within IDLE_PEER_TTL_MS, a 1025th peer is refused
        // rather than evicting any active session.
        let newcomer = Endpoint::new(Identity::generate());
        let p_new = newcomer.client_hello(node.peer_id()).unwrap();
        assert!(node.accept(Endpoint::hello_bytes(&p_new)).is_err());

        // Active peer still decrypts cleanly.
        let ct = active.seal(node.peer_id(), b"r", b"still-live").unwrap();
        assert_eq!(
            node.open(active.peer_id(), b"r", &ct).unwrap(),
            b"still-live"
        );

        // Once one synthetic peer exceeds IDLE_PEER_TTL_MS, pruning frees its slot while
        // retiring its hello and keeping active peers intact.
        {
            let mut state = node.state.lock().unwrap();
            state.peers.get("peer-1").unwrap().verified[0]
                .last_active_ms
                .store(0, Ordering::SeqCst);
            state.prune_idle_peers(IDLE_PEER_TTL_MS + 10, IDLE_PEER_TTL_MS);
            assert!(!state.peers.contains_key("peer-1"));
            assert!(state.pruned_retired_set.contains(&[1u8; 32]));
        }
        assert!(node.accept(Endpoint::hello_bytes(&p_new)).is_ok());
    }

    #[test]
    fn cross_peer_churn_ancient_replays_and_concurrent_identical_hellos_preserve_active_sessions() {
        // 1. Concurrent identical first-time E2eHellos across 8 threads must be atomic & idempotent.
        let node = Endpoint::new(Identity::generate());
        let client = Endpoint::new(Identity::generate());
        let pending = client.client_hello(node.peer_id()).unwrap();
        let hello_bytes = Endpoint::hello_bytes(&pending).to_vec();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let n = node.clone();
            let h = hello_bytes.clone();
            let b = barrier.clone();
            handles.push(std::thread::spawn(move || {
                b.wait();
                n.accept(&h).unwrap().1
            }));
        }
        let welcomes: Vec<Vec<u8>> = handles.into_iter().map(|t| t.join().unwrap()).collect();
        for w in &welcomes[1..] {
            assert_eq!(
                w, &welcomes[0],
                "concurrent identical E2eHellos returned divergent node_eph welcomes!"
            );
        }
        client.complete(pending, &welcomes[0]).unwrap();
        let ct = client.seal(node.peer_id(), b"c0", b"atomic-ok").unwrap();
        assert_eq!(node.open(client.peer_id(), b"c0", &ct).unwrap(), b"atomic-ok");

        // 2. Ancient historical E2eHello replays (even past per-peer retired cap and cross-peer churn)
        // must NEVER evict a verified active session or allow old ciphertext replay.
        let victim = Endpoint::new(Identity::generate());
        let mut ancient_hellos = Vec::new();
        let mut ancient_ct = Vec::new();
        for idx in 0..80 {
            let p = victim.client_hello(node.peer_id()).unwrap();
            let h = Endpoint::hello_bytes(&p).to_vec();
            let (_, w) = node.accept(&h).unwrap();
            victim.complete(p, &w).unwrap();
            let c = victim.seal(node.peer_id(), b"old", b"payload").unwrap();
            assert_eq!(node.open(victim.peer_id(), b"old", &c).unwrap(), b"payload");
            if idx < 12 {
                if idx == 0 {
                    ancient_ct = c;
                }
                ancient_hellos.push(h);
            }
        }
        // Victim establishes its current verified live session:
        let p_live = victim.client_hello(node.peer_id()).unwrap();
        let (_, w_live) = node.accept(Endpoint::hello_bytes(&p_live)).unwrap();
        victim.complete(p_live, &w_live).unwrap();
        let live1 = victim.seal(node.peer_id(), b"l1", b"live-1").unwrap();
        assert_eq!(node.open(victim.peer_id(), b"l1", &live1).unwrap(), b"live-1");

        // Simulate >MAX_PRUNED_RETIRED_HELLOS cross-peer churn without spending 60s on debug Ed25519:
        {
            let mut st = node.state.lock().unwrap();
            for i in 0..9000u32 {
                let mut eph = [0u8; 32];
                eph[..4].copy_from_slice(&i.to_le_bytes());
                eph[31] = 0xff;
                st.retire_pruned_eph(eph);
            }
        }

        // Relay replays all 12 ancient victim E2eHellos (which fell past the 64-entry retired ring):
        for h in &ancient_hellos {
            let _ = node.accept(h);
        }
        // Old ciphertext MUST still fail AEAD authentication:
        assert!(node.open(victim.peer_id(), b"old", &ancient_ct).is_err());
        // Victim's verified live session MUST still be intact and decrypting!
        let live2 = victim.seal(node.peer_id(), b"l2", b"live-2").unwrap();
        assert_eq!(
            node.open(victim.peer_id(), b"l2", &live2).unwrap(),
            b"live-2",
            "replayed ancient E2eHellos evicted an active verified session!"
        );
    }

    #[test]
    fn sec07_frame_aad_v2_authenticates_header_fields_and_keeps_v1_interop() {
        let client = Endpoint::new(Identity::generate());
        let node = Endpoint::new(Identity::generate());
        let pending = client.client_hello_v2(node.peer_id()).unwrap();
        assert_eq!(Endpoint::hello_bytes(&pending).len(), 132);
        let (_, welcome) = node.accept(Endpoint::hello_bytes(&pending)).unwrap();
        assert_eq!(welcome.len(), 100);
        client.complete(pending, &welcome).unwrap();
        assert!(client.peer_uses_frame_aad_v2(node.peer_id()));

        let id = uuid::Uuid::new_v4().to_string();
        let frame = crate::frame::DataFrame {
            request_id: id.clone(),
            offset: 4096,
            raw_len: 16,
            compressed: false,
            hole: false,
            tar: false,
            payload: b"FILEBYTES-secret".to_vec(),
        };
        let raw = crate::frame::encode(&frame).unwrap();

        // Tampering with kind (KIND_DATA -> KIND_TAR) must fail AEAD!
        let mut tampered_kind = client.seal_frame(node.peer_id(), &raw).unwrap();
        tampered_kind[1] = crate::frame::KIND_TAR;
        assert!(node.open_frame(client.peer_id(), &tampered_kind).is_err());

        // Tampering with FLAG_ZSTD must fail AEAD!
        let mut tampered_zstd = client.seal_frame(node.peer_id(), &raw).unwrap();
        let flags = u16::from_le_bytes([tampered_zstd[2], tampered_zstd[3]]) | crate::frame::FLAG_ZSTD;
        tampered_zstd[2..4].copy_from_slice(&flags.to_le_bytes());
        assert!(node.open_frame(client.peer_id(), &tampered_zstd).is_err());

        // Tampering with FLAG_HOLE must fail AEAD!
        let mut tampered_hole = client.seal_frame(node.peer_id(), &raw).unwrap();
        let flags = u16::from_le_bytes([tampered_hole[2], tampered_hole[3]]) | crate::frame::FLAG_HOLE;
        tampered_hole[2..4].copy_from_slice(&flags.to_le_bytes());
        assert!(node.open_frame(client.peer_id(), &tampered_hole).is_err());

        // Tampering with raw_len on a legitimate hole frame must fail AEAD!
        let hole_frame = crate::frame::DataFrame {
            request_id: id.clone(),
            offset: 0,
            raw_len: 4096,
            compressed: false,
            hole: true,
            tar: false,
            payload: Vec::new(),
        };
        let raw_hole = crate::frame::encode(&hole_frame).unwrap();
        let mut tampered_raw_len = client.seal_frame(node.peer_id(), &raw_hole).unwrap();
        tampered_raw_len[28..32].copy_from_slice(&(65536u32).to_le_bytes());
        assert!(node.open_frame(client.peer_id(), &tampered_raw_len).is_err());

        // Oversized FLAG_HOLE raw_len (> FILE_MAX_HOLE) is rejected outright!
        let mut huge_hole = client.seal_frame(node.peer_id(), &raw_hole).unwrap();
        huge_hole[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(node.open_frame(client.peer_id(), &huge_hole).is_err());

        // Untampered v2 hole and data frames open cleanly!
        let good_hole = client.seal_frame(node.peer_id(), &raw_hole).unwrap();
        let opened_hole = node.open_frame(client.peer_id(), &good_hole).unwrap();
        let decoded_hole = crate::frame::decode(&opened_hole).unwrap();
        assert!(decoded_hole.hole);
        assert_eq!(decoded_hole.raw_len, 4096);
        assert!(decoded_hole.payload.is_empty());

        let good_data = client.seal_frame(node.peer_id(), &raw).unwrap();
        let opened_data = node.open_frame(client.peer_id(), &good_data).unwrap();
        assert_eq!(crate::frame::decode(&opened_data).unwrap().payload, b"FILEBYTES-secret");

        // Downgrade attempt: a v1 96-byte welcome cannot complete a v2 pending hello!
        let pending_v2 = client.client_hello_v2(node.peer_id()).unwrap();
        let fake_v1_welcome = vec![0u8; 96];
        assert!(client.complete(pending_v2, &fake_v1_welcome).is_err());

        // Rolling upgrade interop: a v1 client (128-byte hello) still connects to the same upgraded node.
        let legacy_client = Endpoint::new(Identity::generate());
        let p_v1 = legacy_client.client_hello(node.peer_id()).unwrap();
        assert_eq!(Endpoint::hello_bytes(&p_v1).len(), 128);
        let (_, w_v1) = node.accept(Endpoint::hello_bytes(&p_v1)).unwrap();
        assert_eq!(w_v1.len(), 96);
        legacy_client.complete(p_v1, &w_v1).unwrap();
        assert!(!legacy_client.peer_uses_frame_aad_v2(node.peer_id()));
        let legacy_sealed = legacy_client.seal_frame(node.peer_id(), &raw).unwrap();
        let legacy_opened = node.open_frame(legacy_client.peer_id(), &legacy_sealed).unwrap();
        assert_eq!(crate::frame::decode(&legacy_opened).unwrap().payload, b"FILEBYTES-secret");
    }

    #[test]
    fn sec11_spoofed_hello_flood_isolated_in_staged_lru_and_replay_does_not_refresh_ttl() {
        let node = Endpoint::new(Identity::generate());

        // Blast 1,200 spoofed random-identity E2eHello handshakes (exceeding MAX_TRACKED_PEERS = 1024).
        // None send a valid AEAD frame, so they stay isolated in the 64-slot staged LRU.
        for _ in 0..(MAX_TRACKED_PEERS + 176) {
            let spoof = Endpoint::new(Identity::generate());
            let p = spoof.client_hello_v2(node.peer_id()).unwrap();
            let _ = node.accept(Endpoint::hello_bytes(&p)).unwrap();
        }
        {
            let state = node.state.lock().unwrap();
            assert_eq!(state.peers.len(), 0, "unverified staged hellos must never fill verified peers");
            assert!(
                state.staged.len() <= MAX_STAGED_PEERS,
                "staged LRU grew past {MAX_STAGED_PEERS}: {}",
                state.staged.len()
            );
        }

        // A legitimate controller MUST still be accepted and promoted cleanly!
        let legit = Endpoint::new(Identity::generate());
        let p_legit = legit.client_hello_v2(node.peer_id()).unwrap();
        let (_, w_legit) = node.accept(Endpoint::hello_bytes(&p_legit)).unwrap();
        legit.complete(p_legit, &w_legit).unwrap();
        let ct = legit.seal(node.peer_id(), b"ok", b"hello-legit").unwrap();
        assert_eq!(node.open(legit.peer_id(), b"ok", &ct).unwrap(), b"hello-legit");

        // Replaying an unused staged E2eHello must NOT refresh its created_ms / TTL.
        let peer_ttl = Endpoint::new(Identity::generate());
        let p_ttl = peer_ttl.client_hello_v2(node.peer_id()).unwrap();
        let h_ttl = Endpoint::hello_bytes(&p_ttl).to_vec();
        let (_, w1) = node.accept(&h_ttl).unwrap();
        let initial_created = {
            let mut state = node.state.lock().unwrap();
            let entry = state.staged.get_mut(peer_ttl.peer_id()).unwrap();
            entry.sessions[0].created_ms = 5;
            entry.sessions[0].created_ms
        };
        let (_, w2) = node.accept(&h_ttl).unwrap();
        assert_eq!(w1, w2);
        {
            let state = node.state.lock().unwrap();
            let entry = state.staged.get(peer_ttl.peer_id()).unwrap();
            assert_eq!(
                entry.sessions[0].created_ms, initial_created,
                "unauthenticated E2eHello replay must not refresh staged TTL"
            );
        }
        // Once past STAGED_PEER_TTL_MS, pruning evicts the stale staged entry.
        {
            let mut state = node.state.lock().unwrap();
            state.prune_expired_staged(initial_created + STAGED_PEER_TTL_MS + 1);
            assert!(!state.staged.contains_key(peer_ttl.peer_id()));
        }
    }

    #[test]
    fn sec20_non_contributory_x25519_key_is_rejected() {
        let client_id = Identity::generate();
        let node = Endpoint::new(Identity::generate());
        // Low-order all-zero X25519 public key produces all-zero shared secret!
        let bad_eph = [0u8; 32];
        let sig = sign_message("client", &bad_eph, node.peer_id(), &client_id).unwrap();
        let mut hello = Vec::with_capacity(128);
        hello.extend_from_slice(&bad_eph);
        hello.extend_from_slice(&identity::public_bytes(client_id.public_hex()).unwrap());
        hello.extend_from_slice(&sig);
        let err = node.accept(&hello).unwrap_err().to_string();
        assert!(err.contains("non-contributory"), "{err}");

        // Same check on client side (`complete`) with low-order node_eph:
        let client = Endpoint::new(client_id);
        let pending = client.client_hello(node.peer_id()).unwrap();
        let client_eph = PublicKey::from(&pending.secret).to_bytes();
        let node_sig = sign_raw(
            "node",
            &client_eph,
            &bad_eph,
            client.peer_id(),
            node.identity(),
        )
        .unwrap();
        let mut welcome = Vec::with_capacity(96);
        welcome.extend_from_slice(&bad_eph);
        welcome.extend_from_slice(&node_sig);
        let err = client.complete(pending, &welcome).unwrap_err().to_string();
        assert!(err.contains("non-contributory"), "{err}");
    }

    #[test]
    fn seal_control_envelope_roundtrips_session_cursor_update() {
        let client = Endpoint::new(Identity::generate());
        let node = Endpoint::new(Identity::generate());
        let pending = client.client_hello_v2(node.peer_id()).unwrap();
        let (_cid, welcome) = node.accept(Endpoint::hello_bytes(&pending)).unwrap();
        client.complete(pending, &welcome).unwrap();

        let session = Envelope::Session {
            session_id: "sess-1".into(),
            node_id: node.peer_id().to_string(),
            cursors: vec![crate::protocol::SessionCursor {
                request_id: "req-42".into(),
                seq: 7,
            }],
        };
        assert!(
            seal_envelope(&client, node.peer_id(), node.peer_id(), client.peer_id(), &session)
                .is_err(),
            "seal_envelope still requires an inner request_id"
        );
        let wrapped = seal_control_envelope(
            &client,
            node.peer_id(),
            node.peer_id(),
            client.peer_id(),
            "ctrl-req-1",
            &session,
        )
        .unwrap();
        let Envelope::E2e {
            request_id,
            node_id,
            client_id,
            class,
            terminal,
            body_b64,
            ..
        } = wrapped
        else {
            panic!("expected Envelope::E2e");
        };
        assert_eq!(request_id, "ctrl-req-1");
        assert_eq!(class, "meta");
        assert!(terminal);
        let blob = crate::util::b64_decode(&body_b64).unwrap();
        let (opened, _dir, peer) = node
            .open_routed(&client_id, &node_id, request_id.as_bytes(), &blob)
            .unwrap();
        assert_eq!(peer, client.peer_id());
        let inner: Envelope = serde_json::from_slice(&opened).unwrap();
        match inner {
            Envelope::Session {
                session_id,
                cursors,
                ..
            } => {
                assert_eq!(session_id, "sess-1");
                assert_eq!(cursors.len(), 1);
                assert_eq!(cursors[0].request_id, "req-42");
                assert_eq!(cursors[0].seq, 7);
            }
            other => panic!("expected Session, got {other:?}"),
        }
    }
}
