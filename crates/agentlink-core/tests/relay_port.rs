//! The client, not only the parser, dials the port from the relay URL.
//!
//! `wss://127.0.0.1` and `wss://127.0.0.1:443` must not open port 7443.
//! QUIC rendezvous uses the same address.

use std::net::UdpSocket;
use std::time::Duration;

use agentlink_core::{parse_relay_url, Client, ClientSettings};
use tokio::net::TcpListener;
use tokio::time::timeout;

fn settings(relay: &str) -> ClientSettings {
    ClientSettings {
        relay: relay.into(),
        token: "token".into(),
        fingerprint: format!("sha256:{}", "ab".repeat(32)),
        trust: None,
    }
}

#[tokio::test]
async fn client_dials_the_explicit_port_and_not_7443_for_default_wss() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let relay = format!("wss://127.0.0.1:{port}");
    assert_eq!(parse_relay_url(&relay).unwrap().port, port);

    let dial = settings(&relay);
    tokio::spawn(async move {
        let _ = Client::connect(&dial).await;
    });
    let accepted = timeout(Duration::from_secs(3), listener.accept())
        .await
        .expect("client did not dial the explicit port");
    assert!(accepted.is_ok());

    let trap = TcpListener::bind("127.0.0.1:7443").await.ok();
    let default_url = settings("wss://127.0.0.1");
    let err = match Client::connect(&default_url).await {
        Err(err) => err,
        Ok(_) => panic!("wss://127.0.0.1 connected"),
    };
    let message = err.to_string();
    assert!(
        message.contains("127.0.0.1:443") || message.contains("[127.0.0.1]:443"),
        "{message}"
    );
    assert!(!message.contains(":7443"), "{message}");
    let explicit_443 = settings("wss://127.0.0.1:443");
    let err = match Client::connect(&explicit_443).await {
        Err(err) => err,
        Ok(_) => panic!("wss://127.0.0.1:443 connected"),
    };
    let message = err.to_string();
    assert!(
        message.contains(":443"),
        "explicit :443 was not dialed: {message}"
    );
    assert!(!message.contains(":7443"), "{message}");
    if let Some(trap) = trap {
        let hit = timeout(Duration::from_millis(200), trap.accept()).await;
        assert!(hit.is_err(), "wss default port dialed 7443");
    }
}

#[test]
fn quic_rendezvous_uses_443_for_wss_and_7443_only_when_asked() {
    let trap = UdpSocket::bind("127.0.0.1:7443").ok();
    let default = agentlink_core::p2p::relay_addr_from_url("wss://127.0.0.1").unwrap();
    assert_eq!(default.port(), 443);
    let explicit = agentlink_core::p2p::relay_addr_from_url("wss://127.0.0.1:443").unwrap();
    assert_eq!(explicit.port(), 443);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let _ = socket.send_to(b"ALK1", default);
    if let Some(trap) = &trap {
        trap.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 16];
        assert!(
            trap.recv_from(&mut buf).is_err(),
            "wss://127.0.0.1 punched UDP 7443"
        );
    }

    if let Some(trap) = trap {
        let asked = agentlink_core::p2p::relay_addr_from_url("wss://127.0.0.1:7443").unwrap();
        assert_eq!(asked.port(), 7443);
        socket.send_to(b"punch", asked).unwrap();
        trap.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = trap.recv_from(&mut buf).unwrap();
        assert!(n > 0);
    }

    let bare = agentlink_core::p2p::relay_addr_from_url("127.0.0.1").unwrap();
    assert_eq!(bare.port(), 7443);
}
