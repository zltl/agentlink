//! TCP tunnelling over a transfer [`Link`].
//!
//! Each tunnelled TCP connection owns one relay transfer request. Control
//! messages (`TunnelDial`, `TunnelReady`, …) start the link; byte frames then
//! carry the TCP payload. The relay only sees the request id and the sealed
//! `exec` class.

use std::net::Ipv6Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::engine::{Link, Wire};
use crate::error::{Error, Result};
use crate::frame::{self, DataFrame};
use crate::protocol::TransferMsg;

/// Payload bytes per tunnel frame. Kept below the WebSocket frame limit after
/// headers and AEAD overhead.
pub const TUNNEL_CHUNK: usize = 64 * 1024;

/// Parse `host:port`, `[v6]:port`. A bare host is rejected; forwarding always
/// needs an explicit remote port.
pub fn parse_target(text: &str) -> Result<(String, u16)> {
    let text = text.trim();
    if text.is_empty() {
        return Err(Error::Message("target is empty".into()));
    }
    if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| Error::Message(format!("target {text}: missing ']'")))?;
        let port = tail.strip_prefix(':').ok_or_else(|| {
            Error::Message(format!(
                "target {text}: missing :port; did you mean [{host}]:8080?"
            ))
        })?;
        let port = parse_port(port, text)?;
        return Ok((host.to_string(), port));
    }
    let (host, port) = text.rsplit_once(':').ok_or_else(|| {
        if !text.is_empty() && text.chars().all(|ch| ch.is_ascii_digit()) {
            Error::Message(format!("target {text}: use host:port"))
        } else {
            Error::Message(format!(
                "target {text}: use host:port; did you mean {text}:<PORT>? (e.g. {text}:443)"
            ))
        }
    })?;
    if host.contains(':') {
        return Err(Error::Message(format!(
            "target {text}: bracket an IPv6 address like [::1]:8080"
        )));
    }
    Ok((host.to_string(), parse_port(port, text)?))
}

/// Parse the local side of `port reverse`: `port`, `host:port`, or `[v6]:port`.
/// A bare port means `127.0.0.1`.
pub fn parse_local_target(text: &str) -> Result<(String, u16)> {
    let text = text.trim();
    if text.is_empty() {
        return Err(Error::Message("local target is empty".into()));
    }
    if text.chars().all(|ch| ch.is_ascii_digit()) {
        return Ok(("127.0.0.1".into(), parse_port(text, text)?));
    }
    parse_target(text)
}

fn parse_port(text: &str, whole: &str) -> Result<u16> {
    text.trim()
        .parse::<u16>()
        .map_err(|err| Error::Message(format!("target {whole}: port: {err}")))
}

/// Suggest a loopback target when `port forward` got a bare port.
///
/// `forward` always needs `host:port`; only `reverse` accepts a bare port
/// (meaning `127.0.0.1`).
pub fn forward_bare_port_hint(text: &str) -> Option<String> {
    let text = text.trim();
    if !text.is_empty() && text.chars().all(|ch| ch.is_ascii_digit()) {
        Some(format!("did you mean 127.0.0.1:{text}?"))
    } else {
        None
    }
}

/// True when a bind error means the address or port is already taken.
pub fn is_addr_in_use(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("address already in use")
        || lower.contains("addrinuse")
        || lower.contains("os error 10048")
        || lower.contains("only one usage of each socket address")
}

/// Render `host:port`, bracketing IPv6 literals.
pub fn format_target(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Human status line printed once a `port forward` listener binds.
pub fn forward_status_line(
    local_port: u16,
    node: &str,
    remote_host: &str,
    remote_port: u16,
) -> String {
    format!(
        "forward: listening on 127.0.0.1:{local_port} (loopback) -> {node}:{}",
        format_target(remote_host, remote_port)
    )
}

/// Human status line printed once the node binds a `port reverse` listener.
pub fn reverse_status_line(bound_port: u16, local_host: &str, local_port: u16) -> String {
    format!(
        "reverse: node listening on 127.0.0.1:{bound_port} (loopback) -> {}",
        format_target(local_host, local_port)
    )
}

/// Two follow-up tips for a forward map: lifetime, then the reverse command.
pub fn forward_tips(node: &str) -> [String; 2] {
    map_tips(
        "reverse",
        &format!("agentlink port reverse {node} <REMOTE_PORT> <LOCAL>"),
        node,
    )
}

/// Two follow-up tips for a reverse map: lifetime, then the forward command.
pub fn reverse_tips(node: &str) -> [String; 2] {
    map_tips(
        "forward",
        &format!("agentlink port forward {node} <LOCAL_PORT> <REMOTE>"),
        node,
    )
}

fn map_tips(other_direction: &str, usage: &str, node: &str) -> [String; 2] {
    [
        "tip: the map stays up until Ctrl-C; both listeners bind loopback (127.0.0.1) only"
            .into(),
        format!(
            "tip: {other_direction} direction: `{usage}`; node panel: `agentlink guide {node}`"
        ),
    ]
}

/// Copy bytes in both directions until both sides close.
///
/// `request_id` must be the id of the transfer that carries this tunnel so
/// binary frames route back to the same link.
pub async fn pump(stream: TcpStream, link: Link, request_id: &str) -> Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let Link { out, mut inp } = link;
    let request_id = request_id.to_string();

    let sender = async move {
        let mut buf = vec![0u8; TUNNEL_CHUNK];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = out.send(Wire::Msg(TransferMsg::TunnelClose)).await;
                    break;
                }
                Ok(n) => n,
                Err(err) => {
                    let _ = out
                        .send(Wire::Msg(TransferMsg::Failed {
                            message: format!("tunnel read: {err}"),
                        }))
                        .await;
                    return Err(Error::Message(format!("tunnel read: {err}")));
                }
            };
            let bytes = frame::encode(&DataFrame {
                request_id: request_id.clone(),
                offset: 0,
                raw_len: n as u32,
                compressed: false,
                hole: false,
                tar: false,
                payload: buf[..n].to_vec(),
            })?;
            if out.send(Wire::Frame(bytes)).await.is_err() {
                break;
            }
        }
        Ok::<(), Error>(())
    };

    let receiver = async move {
        loop {
            match inp.recv().await {
                Some(Wire::Frame(bytes)) => {
                    let data = frame::decode(&bytes)?;
                    writer
                        .write_all(&data.payload)
                        .await
                        .map_err(|err| Error::Message(format!("tunnel write: {err}")))?;
                }
                Some(Wire::Msg(TransferMsg::TunnelClose)) => {
                    let _ = writer.shutdown().await;
                    break;
                }
                Some(Wire::Msg(TransferMsg::Failed { message })) => {
                    return Err(Error::Message(message));
                }
                // TunnelReady is consumed before pumping; stale control frames
                // (Ack, Done) are harmless here.
                Some(Wire::Msg(_)) => continue,
                None => break,
            }
        }
        Ok::<(), Error>(())
    };

    tokio::try_join!(sender, receiver)?;
    Ok(())
}


use crate::client::Client;
use crate::engine::XferOpts;
use tokio::net::TcpListener;

impl Client {
    /// Listen on `127.0.0.1:local_port` and forward each TCP connection to
    /// `remote_host:remote_port` on `node`.
    pub async fn port_forward(
        &self,
        node: &str,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", local_port))
            .await
            .map_err(|err| Error::Message(format!("listen 127.0.0.1:{local_port}: {err}")))?;
        eprintln!(
            "{}",
            forward_status_line(local_port, node, remote_host, remote_port)
        );
        for tip in forward_tips(node) {
            eprintln!("{tip}");
        }
        let mut opts = XferOpts::default();
        // QUIC direct links expect file-transfer control first; tunnels use the relay path.
        opts.transport = "relay-only".into();
        loop {
            let (stream, peer) = listener
                .accept()
                .await
                .map_err(|err| Error::Message(format!("accept: {err}")))?;
            eprintln!("forward {peer} opened");
            let (mut link, request_id, _) = self.open_data_link(node, &opts).await?;
            link.send_msg(TransferMsg::TunnelDial {
                host: remote_host.to_string(),
                port: remote_port,
            })
            .await?;
            match link.recv().await? {
                Wire::Msg(TransferMsg::TunnelReady) => {}
                Wire::Msg(TransferMsg::Failed { message }) => {
                    return Err(Error::Message(message));
                }
                other => {
                    return Err(Error::Protocol(format!(
                        "expected TunnelReady, got {other:?}"
                    )));
                }
            }
            // One connection at a time for the MVP (keeps Client !Clone).
            if let Err(err) = pump(stream, link, &request_id).await {
                eprintln!("forward {peer} closed: {err}");
            } else {
                eprintln!("forward {peer} closed");
            }
        }
    }

    /// Ask `node` to listen on `127.0.0.1:remote_port` and forward each accepted
    /// connection to `local_host:local_port` on this machine.
    pub async fn port_reverse(
        &self,
        node: &str,
        remote_port: u16,
        local_host: &str,
        local_port: u16,
    ) -> Result<()> {
        let mut opts = XferOpts::default();
        opts.transport = "relay-only".into();
        let (mut control, _req, _) = self.open_data_link(node, &opts).await?;
        control
            .send_msg(TransferMsg::TunnelBind { port: remote_port })
            .await?;
        let bound = match control.recv().await? {
            Wire::Msg(TransferMsg::TunnelBound { port }) => port,
            Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
            other => {
                return Err(Error::Protocol(format!(
                    "expected TunnelBound, got {other:?}"
                )));
            }
        };
        eprintln!("{}", reverse_status_line(bound, local_host, local_port));
        for tip in reverse_tips(node) {
            eprintln!("{tip}");
        }
        loop {
            let token = match control.recv().await? {
                Wire::Msg(TransferMsg::TunnelIncoming { token }) => token,
                Wire::Msg(TransferMsg::Failed { message }) => return Err(Error::Message(message)),
                Wire::Msg(TransferMsg::Done { .. }) | Wire::Msg(TransferMsg::TunnelClose) => break,
                Wire::Msg(_) | Wire::Frame(_) => continue,
            };
            let addr = format_target(local_host, local_port);
            let stream = match TcpStream::connect((local_host, local_port)).await {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("reverse dial {addr}: {err}");
                    continue;
                }
            };
            let (mut link, request_id, _) = self.open_data_link(node, &opts).await?;
            link.send_msg(TransferMsg::TunnelAccept {
                token: token.clone(),
            })
            .await?;
            match link.recv().await? {
                Wire::Msg(TransferMsg::TunnelReady) => {}
                Wire::Msg(TransferMsg::Failed { message }) => {
                    eprintln!("reverse claim failed: {message}");
                    continue;
                }
                other => {
                    eprintln!("reverse unexpected: {other:?}");
                    continue;
                }
            }
            if let Err(err) = pump(stream, link, &request_id).await {
                eprintln!("reverse {token} closed: {err}");
            } else {
                eprintln!("reverse {token} closed");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::TransferMsg;
    use std::time::Duration;

    #[test]
    fn targets_parse_and_render() {
        assert_eq!(
            parse_target("example.com:443").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(parse_target("[::1]:8080").unwrap(), ("::1".into(), 8080));
        assert!(parse_target("example.com").is_err());
        assert!(parse_target("::1:80").is_err());
        assert_eq!(
            parse_local_target("8080").unwrap(),
            ("127.0.0.1".into(), 8080)
        );
        assert_eq!(
            parse_local_target("10.0.0.2:22").unwrap(),
            ("10.0.0.2".into(), 22)
        );
        assert_eq!(format_target("::1", 80), "[::1]:80");
        assert_eq!(format_target("127.0.0.1", 80), "127.0.0.1:80");
    }

    #[test]
    fn bare_host_targets_suggest_host_port() {
        let err = parse_target("example.com").unwrap_err().to_string();
        assert!(err.contains("host:port"), "{err}");
        assert!(err.contains("example.com:"), "{err}");

        let err = parse_target("[::1]").unwrap_err().to_string();
        assert!(err.contains("[::1]:"), "{err}");

        let err = parse_local_target("example.com").unwrap_err().to_string();
        assert!(err.contains("host:port"), "{err}");
        assert!(err.contains("example.com:"), "{err}");
    }

    #[test]
    fn bare_numeric_target_is_port_not_hostname() {
        let err = parse_target("8080").unwrap_err().to_string();
        assert_eq!(err, "target 8080: use host:port");
        assert!(!err.contains("8080:<PORT>"), "{err}");
        assert!(!err.contains("8080:443"), "{err}");
    }

    #[test]
    fn bare_forward_port_suggests_loopback_host() {
        assert_eq!(
            forward_bare_port_hint("8080").as_deref(),
            Some("did you mean 127.0.0.1:8080?")
        );
        assert!(forward_bare_port_hint(" 22 ").is_some());
        assert!(forward_bare_port_hint("127.0.0.1:8080").is_none());
        assert!(forward_bare_port_hint("example.com:443").is_none());
        assert!(forward_bare_port_hint("").is_none());
    }

    #[test]
    fn addr_in_use_detection_covers_unix_and_windows_messages() {
        assert!(is_addr_in_use(
            "listen 127.0.0.1:8080: Address already in use (os error 98)"
        ));
        assert!(is_addr_in_use(
            "Only one usage of each socket address is normally permitted. (os error 10048)"
        ));
        assert!(!is_addr_in_use(
            "grant issuer abc is not trusted; run `agentlink grant trust-owner`"
        ));
    }

    #[test]
    fn status_lines_label_direction_and_loopback() {
        assert_eq!(
            forward_status_line(18080, "box", "127.0.0.1", 80),
            "forward: listening on 127.0.0.1:18080 (loopback) -> box:127.0.0.1:80"
        );
        assert_eq!(
            forward_status_line(18080, "box", "::1", 443),
            "forward: listening on 127.0.0.1:18080 (loopback) -> box:[::1]:443"
        );
        assert_eq!(
            reverse_status_line(8080, "127.0.0.1", 3000),
            "reverse: node listening on 127.0.0.1:8080 (loopback) -> 127.0.0.1:3000"
        );
        assert_eq!(
            reverse_status_line(8080, "::1", 3000),
            "reverse: node listening on 127.0.0.1:8080 (loopback) -> [::1]:3000"
        );
    }

    #[test]
    fn tips_name_lifetime_other_direction_and_node() {
        let forward = forward_tips("box");
        assert!(forward[0].contains("Ctrl-C"), "{}", forward[0]);
        assert!(forward[0].contains("loopback"), "{}", forward[0]);
        assert!(
            forward[1].contains("agentlink port reverse box <REMOTE_PORT> <LOCAL>"),
            "{}",
            forward[1]
        );
        assert!(forward[1].contains("agentlink guide box"), "{}", forward[1]);

        let reverse = reverse_tips("box");
        assert!(reverse[0].contains("Ctrl-C"), "{}", reverse[0]);
        assert!(
            reverse[1].contains("agentlink port forward box <LOCAL_PORT> <REMOTE>"),
            "{}",
            reverse[1]
        );
        assert!(reverse[1].contains("agentlink guide box"), "{}", reverse[1]);
    }

    #[test]
    fn tunnel_messages_serde_roundtrip() {
        let messages = [
            TransferMsg::TunnelDial {
                host: "127.0.0.1".into(),
                port: 5432,
            },
            TransferMsg::TunnelBind { port: 0 },
            TransferMsg::TunnelBound { port: 9000 },
            TransferMsg::TunnelIncoming {
                token: "tok".into(),
            },
            TransferMsg::TunnelAccept {
                token: "tok".into(),
            },
            TransferMsg::TunnelReady,
            TransferMsg::TunnelClose,
        ];
        for msg in messages {
            let text = serde_json::to_string(&msg).unwrap();
            let back: TransferMsg = serde_json::from_str(&text).unwrap();
            assert_eq!(
                serde_json::to_string(&back).unwrap(),
                text,
                "roundtrip {text}"
            );
        }
    }

    #[tokio::test]
    async fn pump_carries_bytes_in_both_directions() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (worker, mut network) = Link::pair(16);
        let request_id = uuid::Uuid::new_v4().to_string();

        let server_id = request_id.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            pump(stream, worker, &server_id).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"hello").await.unwrap();

        let frame = match tokio::time::timeout(Duration::from_secs(5), network.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Wire::Frame(bytes) => frame::decode(&bytes).unwrap(),
            other => panic!("expected frame, got {other:?}"),
        };
        assert_eq!(frame.payload, b"hello");

        let reply = frame::encode(&DataFrame {
            request_id: request_id.clone(),
            offset: 0,
            raw_len: 5,
            compressed: false,
            hole: false,
            tar: false,
            payload: b"world".to_vec(),
        })
        .unwrap();
        network.send_frame(reply).await.unwrap();
        network.send_msg(TransferMsg::TunnelClose).await.unwrap();

        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, b"world");
        drop(client);
        timeout_join(server).await;
    }

    async fn timeout_join(handle: tokio::task::JoinHandle<()>) {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }
}