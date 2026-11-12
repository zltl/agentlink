//! Half-dead relay sessions.
//!
//! A proxy can keep the node's TCP connection ESTABLISHED and even ACK bytes
//! after the relay has stopped seeing the node. The daemon has to notice the
//! missing heartbeat and dial again within seconds, not hours. A second case
//! drops only relay-to-node bytes (missed pongs) while the relay still
//! receives pings. A third case is the relay closing a socket it no longer
//! considers fresh; the node must observe that close and redial.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agentlink_core::{Client, ClientSettings, NodePolicy};
use agentlink_node::{run, set_liveness_for_test, NodeConfig};
use agentlink_relay::{set_stale_after_for_test, RelayConfig, RelayHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

const MODE_BLACKHOLE: u8 = 1;
const MODE_DROP_DOWN: u8 = 2;

struct ResetHooks;

impl Drop for ResetHooks {
    fn drop(&mut self) {
        set_liveness_for_test(None, None);
        set_stale_after_for_test(None);
    }
}

struct ProxyCtrl {
    next_epoch: AtomicU64,
    freeze_before: AtomicU64,
    mode: AtomicU8,
}

impl ProxyCtrl {
    fn freeze(&self, mode: u8) {
        let cut = self.next_epoch.load(Ordering::SeqCst);
        self.mode.store(mode, Ordering::SeqCst);
        self.freeze_before.store(cut, Ordering::SeqCst);
    }

    fn fate(&self, epoch: u64) -> u8 {
        let mode = self.mode.load(Ordering::SeqCst);
        let cut = self.freeze_before.load(Ordering::SeqCst);
        if mode != 0 && epoch < cut {
            mode
        } else {
            0
        }
    }
}

#[derive(Clone, Copy)]
enum Dir {
    Up,
    Down,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn half_dead_socket_reconnects() {
    let result = tokio::time::timeout(Duration::from_secs(90), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("liveness test timed out"),
    }
}

async fn flow() -> anyhow::Result<()> {
    let _reset = ResetHooks;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    // Production silence is 50s. The test keeps the same rule (a few missed
    // beats) on a short clock so a black-holed socket cannot pass by waiting.
    set_liveness_for_test(
        Some(Duration::from_millis(300)),
        Some(Duration::from_secs(2)),
    );
    set_stale_after_for_test(None);

    let dir = tempfile::tempdir()?;
    let relay = RelayHandle::spawn(RelayConfig {
        bind: "127.0.0.1:0".parse()?,
        data_dir: dir.path().join("relay"),
        capture: None,
        database_url: None,
        allow_signup: false,
        bootstrap_admin: false,
        db_schema: None,
        trust_proxy: Vec::new(),
        print_admin_token: false,
        legacy_admin_override: Some((true, Some(86_400))),
    })
    .await?;
    let proxy = spawn_proxy(relay.local_addr).await?;
    let via_proxy = format!("wss://{}/v1/connect", proxy.addr);
    let direct = format!("wss://{}/v1/connect", relay.local_addr);
    let admin = Client::connect(&ClientSettings {
        relay: direct,
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await?;
    let pairing = admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let stop = CancellationToken::new();
    let node = tokio::spawn(run(
        NodeConfig {
            relay_url: via_proxy,
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: dir.path().join("node"),
            name: "box".into(),
            pairing_token: Some(pairing.token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        stop.clone(),
    ));

    wait_online(&admin, &node).await;
    let baseline = node_connects(&relay);
    tokio::time::sleep(Duration::from_secs(2)).await;
    ensure_running(&node);
    assert_eq!(
        node_connects(&relay),
        baseline,
        "healthy socket reconnected on its own: {}",
        connect_log(&relay)
    );

    proxy.ctrl.freeze(MODE_BLACKHOLE);
    let started = Instant::now();
    wait_connects(&relay, &node, baseline + 1, Duration::from_secs(12)).await;
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "silent peer was not detected quickly: {:?}",
        started.elapsed()
    );
    wait_online(&admin, &node).await;

    let after_blackhole = node_connects(&relay);
    tokio::time::sleep(Duration::from_secs(2)).await;
    ensure_running(&node);
    assert_eq!(
        node_connects(&relay),
        after_blackhole,
        "socket kept flapping after the blackhole reconnect: {}",
        connect_log(&relay)
    );

    proxy.ctrl.freeze(MODE_DROP_DOWN);
    let started = Instant::now();
    wait_connects(&relay, &node, after_blackhole + 1, Duration::from_secs(12)).await;
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "missed pongs were not detected quickly: {:?}",
        started.elapsed()
    );
    wait_online(&admin, &node).await;

    // The relay, not the silence timer, closes the socket. The running
    // connection captured the fast heartbeat, so kick it after installing
    // a deadline longer than this test. The next dial must notice the
    // relay's close and come back, then the reaper closes that quiet socket
    // and the node dials once more.
    set_liveness_for_test(
        Some(Duration::from_secs(3600)),
        Some(Duration::from_secs(3600)),
    );
    set_stale_after_for_test(Some(Duration::from_millis(800)));
    let before_kick = node_connects(&relay);
    relay.disconnect_nodes();
    wait_connects(&relay, &node, before_kick + 2, Duration::from_secs(15)).await;

    stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), node).await;
    Ok(())
}

struct Proxy {
    addr: std::net::SocketAddr,
    ctrl: Arc<ProxyCtrl>,
}

async fn spawn_proxy(relay: std::net::SocketAddr) -> anyhow::Result<Proxy> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let ctrl = Arc::new(ProxyCtrl {
        next_epoch: AtomicU64::new(0),
        freeze_before: AtomicU64::new(0),
        mode: AtomicU8::new(0),
    });
    let accept_ctrl = ctrl.clone();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                break;
            };
            let ctrl = accept_ctrl.clone();
            tokio::spawn(async move {
                bridge(client, relay, ctrl).await;
            });
        }
    });
    Ok(Proxy { addr, ctrl })
}

async fn bridge(client: TcpStream, relay: std::net::SocketAddr, ctrl: Arc<ProxyCtrl>) {
    let Ok(server) = TcpStream::connect(relay).await else {
        return;
    };
    client.set_nodelay(true).ok();
    server.set_nodelay(true).ok();
    let epoch = ctrl.next_epoch.fetch_add(1, Ordering::SeqCst);
    let (cr, cw) = client.into_split();
    let (sr, sw) = server.into_split();
    let up_ctrl = ctrl.clone();
    let up = tokio::spawn(async move {
        pump(cr, sw, up_ctrl, epoch, Dir::Up).await;
    });
    let down = tokio::spawn(async move {
        pump(sr, cw, ctrl, epoch, Dir::Down).await;
    });
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

async fn pump(
    mut read: tokio::net::tcp::OwnedReadHalf,
    mut write: tokio::net::tcp::OwnedWriteHalf,
    ctrl: Arc<ProxyCtrl>,
    epoch: u64,
    dir: Dir,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let fate = ctrl.fate(epoch);
        if fate == MODE_BLACKHOLE {
            std::future::pending::<()>().await;
        }
        if fate == MODE_DROP_DOWN && matches!(dir, Dir::Down) {
            match read.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => continue,
            }
        }
        let n = match read.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let fate = ctrl.fate(epoch);
        if fate == MODE_BLACKHOLE {
            std::future::pending::<()>().await;
        }
        if fate == MODE_DROP_DOWN && matches!(dir, Dir::Down) {
            continue;
        }
        if write.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

fn connect_log(relay: &RelayHandle) -> String {
    std::fs::read_to_string(relay.data_dir.join("connect.jsonl")).unwrap_or_default()
}

fn node_connects(relay: &RelayHandle) -> usize {
    connect_log(relay)
        .lines()
        .filter(|line| line.contains("\"role\":\"node\"") && line.contains("\"name\":\"box\""))
        .count()
}

fn ensure_running(node: &tokio::task::JoinHandle<agentlink_core::Result<()>>) {
    if node.is_finished() {
        panic!("node exited while the relay session was under test");
    }
}

async fn wait_online(admin: &Client, node: &tokio::task::JoinHandle<agentlink_core::Result<()>>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        ensure_running(node);
        let online = admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|info| info.name == "box" && info.online))
            .unwrap_or(false);
        if online {
            return;
        }
        if Instant::now() > deadline {
            panic!("node did not come online");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_connects(
    relay: &RelayHandle,
    node: &tokio::task::JoinHandle<agentlink_core::Result<()>>,
    want: usize,
    budget: Duration,
) {
    let deadline = Instant::now() + budget;
    loop {
        ensure_running(node);
        let got = node_connects(relay);
        if got >= want {
            return;
        }
        if Instant::now() > deadline {
            panic!(
                "wanted at least {want} node connects, saw {got}: {}",
                connect_log(relay)
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
