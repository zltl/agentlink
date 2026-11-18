//! Direct QUIC path with relay-coordinated NAT hole punching.
//!
//! Each peer binds one UDP socket, punches that socket at the relay so the
//! relay learns the external address, then exchanges candidates over the
//! authenticated WebSocket. The dialer connects with QUIC. The server
//! certificate fingerprint is signed by the node's ed25519 key, and the dialer
//! signs the transcript with its own ed25519 key, so the relay cannot read or
//! replace the byte stream.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::engine::{Link, Wire};
use crate::error::{Error, Result};
use crate::identity::{self, Identity};
use crate::tls::{self, fingerprint_of};

pub const PUNCH_MAGIC: &[u8] = b"ALK1";

#[derive(Clone)]
pub struct QuicPeer {
    endpoint: quinn::Endpoint,
    pub cert_fp: String,
    pub cert_sig: String,
    pub public_key: String,
    identity: Arc<Identity>,
    /// `set_default_client_config` mutates the shared endpoint.
    dial_gate: Arc<std::sync::Mutex<()>>,
}

impl QuicPeer {
    pub fn bind(identity: &Identity, relay: Option<SocketAddr>) -> Result<Self> {
        tls::install_ring();
        let (cert_der, key_der, fp_bytes) = mint_cert()?;
        let cert_fp = hex::encode(fp_bytes);
        let cert_sig = identity.sign_message(&quic_binding(&fp_bytes));
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(tls_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| Error::Tls(e.to_string()))?;
        server_crypto.alpn_protocols = vec![b"agentlink".to_vec()];
        server_crypto.max_early_data_size = 0;
        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| Error::Tls(e.to_string()))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        server.transport_config(wide_transport());

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;
        if let Some(relay) = relay {
            let packet = encode_punch(identity);
            let _ = socket.send_to(&packet, relay);
        }
        let runtime = Arc::new(quinn::TokioRuntime);
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server),
            socket,
            runtime,
        )?;
        Ok(Self {
            endpoint,
            cert_fp,
            cert_sig,
            public_key: identity.public_hex().to_string(),
            identity: Arc::new(identity.clone()),
            dial_gate: Arc::new(std::sync::Mutex::new(())),
        })
    }

    pub fn port(&self) -> Result<u16> {
        Ok(self.endpoint.local_addr()?.port())
    }

    pub fn punch(&self, _relay: SocketAddr) {
        // The UDP socket belongs to the endpoint after bind. The initial punch
        // in `bind` opens the mapping; QUIC initials keep it warm.
    }

    pub fn local_addrs(&self, relay: Option<SocketAddr>) -> Vec<String> {
        let Ok(port) = self.port() else {
            return Vec::new();
        };
        let mut addrs = vec![SocketAddr::from(([127, 0, 0, 1], port)).to_string()];
        if let Some(relay) = relay {
            if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                if sock.connect(relay).is_ok() {
                    if let Ok(addr) = sock.local_addr() {
                        let cand = SocketAddr::new(addr.ip(), port);
                        let text = cand.to_string();
                        if !addrs.contains(&text) {
                            addrs.push(text);
                        }
                    }
                }
            }
        }
        addrs
    }

    /// Dial `addrs` and return a link whose first bytes are already authenticated.
    pub async fn dial(
        &self,
        addrs: &[SocketAddr],
        expect_fp: &str,
        expect_key: &str,
        expect_sig: &str,
    ) -> Result<Link> {
        let fp_bytes = hex::decode(expect_fp.trim().trim_start_matches("sha256:"))
            .map_err(|e| Error::Tls(format!("fingerprint: {e}")))?;
        if fp_bytes.len() != 32 {
            return Err(Error::Tls("fingerprint must be 32 bytes".into()));
        }
        identity::verify_message(expect_key, &quic_binding(&fp_bytes), expect_sig)?;
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&fp_bytes);
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(tls_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(tls::pinned_verifier(fp))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"agentlink".to_vec()];
        client_crypto.enable_early_data = false;
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| Error::Tls(e.to_string()))?;
        let mut client = quinn::ClientConfig::new(Arc::new(quic_client));
        client.transport_config(wide_transport());

        let mut last_err = Error::Message("no candidate addresses".into());
        for addr in addrs {
            let connecting = {
                let _guard = self
                    .dial_gate
                    .lock()
                    .map_err(|_| Error::Message("quic dial lock poisoned".into()))?;
                let mut endpoint = self.endpoint.clone();
                endpoint.set_default_client_config(client.clone());
                endpoint.connect(*addr, "agentlink")
            };
            match connecting {
                Ok(connecting) => {
                    match tokio::time::timeout(Duration::from_secs(2), connecting).await {
                        Ok(Ok(conn)) => {
                            let (mut send, recv) =
                                tokio::time::timeout(Duration::from_secs(3), conn.open_bi())
                                    .await
                                    .map_err(|_| Error::Timeout)?
                                    .map_err(|e| Error::Message(format!("quic stream: {e}")))?;
                            write_auth(&mut send, &self.identity, &self.cert_fp, expect_key)
                                .await?;
                            return Ok(link_from_streams(conn, send, recv));
                        }
                        Ok(Err(err)) => last_err = Error::Message(format!("quic: {err}")),
                        Err(_) => last_err = Error::Timeout,
                    }
                }
                Err(err) => last_err = Error::Message(format!("quic dial {addr}: {err}")),
            }
        }
        Err(last_err)
    }

    pub async fn accept_one(
        &self,
        allowed: &std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    ) -> Result<Link> {
        let incoming = tokio::time::timeout(Duration::from_secs(3), self.endpoint.accept())
            .await
            .map_err(|_| Error::Timeout)?
            .ok_or_else(|| Error::Message("quic endpoint closed".into()))?;
        let conn = incoming
            .await
            .map_err(|e| Error::Message(format!("quic accept: {e}")))?;
        let (send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| Error::Message(format!("quic stream: {e}")))?;
        // `conn` is moved into the link after auth so the streams stay open.
        let auth = read_json(&mut recv).await?;
        let public_key = auth
            .get("public_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let signature = auth.get("signature").and_then(|v| v.as_str()).unwrap_or("");
        let cert_fp = auth.get("cert_fp").and_then(|v| v.as_str()).unwrap_or("");
        let fp_bytes = hex::decode(cert_fp).unwrap_or_default();
        identity::verify_message(
            &public_key,
            &p2p_binding(&self.public_key, &fp_bytes),
            signature,
        )?;
        let fresh = allowed
            .lock()
            .ok()
            .and_then(|map| map.get(&public_key).copied())
            .map(|at| at.elapsed() < Duration::from_secs(30))
            .unwrap_or(false);
        if !fresh {
            return Err(Error::Auth("direct path peer was not introduced".into()));
        }
        Ok(link_from_streams(conn, send, recv))
    }
}

fn tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    tls::install_ring();
    Arc::new(rustls::crypto::ring::default_provider())
}

fn wide_transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(quinn::VarInt::from_u32(8 * 1024 * 1024));
    transport.receive_window(quinn::VarInt::from_u32(16 * 1024 * 1024));
    Arc::new(transport)
}

fn mint_cert() -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
    [u8; 32],
)> {
    let key = rcgen::KeyPair::generate().map_err(|e| Error::Tls(e.to_string()))?;
    let mut params = rcgen::CertificateParams::new(vec!["agentlink".into()])
        .map_err(|e| Error::Tls(e.to_string()))?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "agentlink-p2p");
    params.distinguished_name = dn;
    let cert = params
        .self_signed(&key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    let der = cert.der().to_vec();
    let fp = fingerprint_of(&der);
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der())
        .map_err(|e| Error::Tls(e.to_string()))?;
    Ok((der.into(), key_der, fp))
}

pub fn quic_binding(fp: &[u8]) -> Vec<u8> {
    let mut msg = b"agentlink-quic-v1:".to_vec();
    msg.extend_from_slice(fp);
    msg
}

fn p2p_binding(server_key_hex: &str, client_fp: &[u8]) -> Vec<u8> {
    let mut msg = b"agentlink-p2p-v1:".to_vec();
    msg.extend_from_slice(server_key_hex.as_bytes());
    msg.extend_from_slice(client_fp);
    msg
}

pub fn encode_punch(identity: &Identity) -> Vec<u8> {
    let id = identity.public_hex().as_bytes();
    let mut msg = Vec::with_capacity(4 + id.len());
    msg.extend_from_slice(PUNCH_MAGIC);
    msg.extend_from_slice(id);
    let sig = hex::decode(identity.sign_message(&msg)).unwrap_or_default();
    msg.extend_from_slice(&sig);
    msg
}

pub fn decode_punch(packet: &[u8]) -> Result<String> {
    if packet.len() < 4 + 64 || &packet[..4] != PUNCH_MAGIC {
        return Err(Error::Protocol("not a punch packet".into()));
    }
    let sig = &packet[packet.len() - 64..];
    let id_bytes = &packet[4..packet.len() - 64];
    let id = std::str::from_utf8(id_bytes)
        .map_err(|_| Error::Protocol("punch id is not utf-8".into()))?;
    let mut msg = Vec::with_capacity(4 + id_bytes.len());
    msg.extend_from_slice(PUNCH_MAGIC);
    msg.extend_from_slice(id_bytes);
    identity::verify_message(id, &msg, &hex::encode(sig))?;
    Ok(id.to_string())
}

pub fn parse_addrs(local: &[String], reflexive: Option<&str>) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for text in local {
        if let Ok(addr) = text.parse() {
            out.push(addr);
        }
    }
    if let Some(text) = reflexive {
        if let Ok(addr) = text.parse() {
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

async fn write_auth(
    send: &mut quinn::SendStream,
    identity: &Identity,
    cert_fp: &str,
    server_key: &str,
) -> Result<()> {
    let fp = hex::decode(cert_fp).unwrap_or_default();
    let signature = identity.sign_message(&p2p_binding(server_key, &fp));
    let body = serde_json::json!({
        "public_key": identity.public_hex(),
        "signature": signature,
        "cert_fp": cert_fp,
    });
    write_tagged(send, 1, &serde_json::to_vec(&body)?).await
}

async fn read_json(recv: &mut quinn::RecvStream) -> Result<serde_json::Value> {
    let (tag, bytes) = read_tagged(recv).await?;
    if tag != 1 {
        return Err(Error::Protocol(
            "expected auth json on the direct path".into(),
        ));
    }
    serde_json::from_slice(&bytes).map_err(Error::from)
}

fn link_from_streams(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Link {
    let (out_tx, mut out_rx) = mpsc::channel(64);
    let (inp_tx, inp_rx) = mpsc::channel(64);
    let conn_read = conn.clone();
    tokio::spawn(async move {
        let _conn = conn;
        while let Some(wire) = out_rx.recv().await {
            if write_wire(&mut send, &wire).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let _conn = conn_read;
        loop {
            match read_wire(&mut recv).await {
                Ok(wire) => {
                    if inp_tx.send(wire).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    Link {
        out: out_tx,
        inp: inp_rx,
    }
}

async fn write_wire(send: &mut quinn::SendStream, wire: &Wire) -> Result<()> {
    match wire {
        Wire::Msg(msg) => write_tagged(send, 1, &serde_json::to_vec(msg)?).await,
        Wire::Frame(bytes) => write_tagged(send, 2, bytes).await,
    }
}

async fn read_wire(recv: &mut quinn::RecvStream) -> Result<Wire> {
    let (tag, bytes) = read_tagged(recv).await?;
    match tag {
        1 => Ok(Wire::Msg(serde_json::from_slice(&bytes)?)),
        2 => Ok(Wire::Frame(bytes)),
        _ => Err(Error::Protocol("unknown direct-path tag".into())),
    }
}

async fn write_tagged(send: &mut quinn::SendStream, tag: u8, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| Error::Protocol("frame too large".into()))?;
    let mut hdr = [0u8; 5];
    hdr[0] = tag;
    hdr[1..].copy_from_slice(&len.to_be_bytes());
    send.write_all(&hdr)
        .await
        .map_err(|e| Error::Message(format!("quic write: {e}")))?;
    send.write_all(bytes)
        .await
        .map_err(|e| Error::Message(format!("quic write: {e}")))?;
    Ok(())
}

async fn read_tagged(recv: &mut quinn::RecvStream) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    recv.read_exact(&mut hdr)
        .await
        .map_err(|e| Error::Message(format!("quic read: {e}")))?;
    let len = u32::from_be_bytes(hdr[1..].try_into().unwrap()) as usize;
    if len > crate::frame::MAX_FRAME {
        return Err(Error::Protocol("direct frame exceeds limit".into()));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| Error::Message(format!("quic read: {e}")))?;
    Ok((hdr[0], buf))
}

pub fn relay_addr_from_url(url: &str) -> Result<SocketAddr> {
    let endpoint = crate::relay_url::parse_relay_url(url)?;
    let mut iter =
        std::net::ToSocketAddrs::to_socket_addrs(&(endpoint.host.as_str(), endpoint.port))
            .map_err(|e| Error::Message(format!("resolve relay: {e}")))?;
    iter.next()
        .ok_or_else(|| Error::Message("relay host did not resolve".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punch_roundtrip() {
        let id = Identity::generate();
        let packet = encode_punch(&id);
        let back = decode_punch(&packet).unwrap();
        assert_eq!(back, id.public_hex());
        let mut bad = packet.clone();
        bad[10] ^= 0xff;
        assert!(decode_punch(&bad).is_err());
    }

    #[test]
    fn rendezvous_port_follows_the_relay_url() {
        assert_eq!(relay_addr_from_url("wss://127.0.0.1").unwrap().port(), 443);
        assert_eq!(
            relay_addr_from_url("wss://127.0.0.1:443").unwrap().port(),
            443
        );
        assert_eq!(
            relay_addr_from_url("wss://127.0.0.1:7443").unwrap().port(),
            7443
        );
        assert_eq!(relay_addr_from_url("127.0.0.1").unwrap().port(), 7443);
        assert_eq!(relay_addr_from_url("127.0.0.1:9").unwrap().port(), 9);
    }
}
