//! Bulk transfer: binary frames, resume, BLAKE3 skip, delta, zstd, tar, QUIC.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use agentlink_core::delta;
use agentlink_core::engine::{self, XferOpts};
use agentlink_core::protocol::CompressPref;
use agentlink_core::{Client, ClientSettings, NodePolicy};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fast_transfer_features() {
    let result = tokio::time::timeout(Duration::from_secs(120), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("transfer test timed out"),
    }
}

async fn flow() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

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
    let relay_url = format!("wss://{}/v1/connect", relay.local_addr);
    let admin = Client::connect(&ClientSettings {
        relay: relay_url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await?;

    let box_token = admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let other_token = admin
        .create_pairing_token("other", NodePolicy::exec(), 600)
        .await?;
    let ro_token = admin
        .create_pairing_token("ro", NodePolicy::read_only(), 600)
        .await?;

    let box_stop = CancellationToken::new();
    let other_stop = CancellationToken::new();
    let ro_stop = CancellationToken::new();
    let box_task = spawn_node(
        &relay_url,
        &relay.fingerprint,
        &dir.path().join("box"),
        "box",
        &box_token.token,
        box_stop.clone(),
    );
    let other_task = spawn_node(
        &relay_url,
        &relay.fingerprint,
        &dir.path().join("other"),
        "other",
        &other_token.token,
        other_stop.clone(),
    );
    let ro_task = spawn_node(
        &relay_url,
        &relay.fingerprint,
        &dir.path().join("ro"),
        "ro",
        &ro_token.token,
        ro_stop.clone(),
    );
    wait_online(&admin, &["box", "other", "ro"]).await;
    for (name, data) in [
        ("box", dir.path().join("box")),
        ("other", dir.path().join("other")),
        ("ro", dir.path().join("ro")),
    ] {
        let id = admin
            .list_nodes()
            .await?
            .into_iter()
            .find(|node| node.name == name)
            .unwrap()
            .id;
        admin.install_local_grant(&data, &id)?;
    }

    let opts = XferOpts {
        chunk_size: 64 * 1024,
        window: 4,
        parallel: 2,
        compress: CompressPref::Auto,
        resume: true,
        transport: "relay".into(),
    };

    let local = dir.path().join("payload.bin");
    write_pattern(&local, 300_000, 1)?;
    let remote = dir.path().join("remote-payload.bin");
    let remote_s = remote.to_string_lossy().to_string();
    let up = admin
        .copy_upload("box", &remote_s, &local, &opts, None)
        .await?;
    assert_eq!(
        up.transport, "relay",
        "direct offer is not a sealed grant path: {up:?}"
    );
    assert_eq!(std::fs::read(&remote)?, std::fs::read(&local)?);
    assert!(up.payload_bytes > 0);

    let again = admin
        .copy_upload("box", &remote_s, &local, &opts, None)
        .await?;
    assert!(again.skipped, "{again:?}");
    assert_eq!(again.payload_bytes, 0);

    write_pattern(&local, 300_000, 1)?;
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&local)?;
        file.seek(std::io::SeekFrom::Start(80_000))?;
        file.write_all(&[0x5a; 40])?;
    }
    let delta = admin
        .copy_upload("box", &remote_s, &local, &opts, None)
        .await?;
    assert!(
        delta.delta_copy_bytes > 150_000,
        "expected a block delta, got {delta:?}"
    );
    assert!(delta.payload_bytes < delta.logical_bytes / 2, "{delta:?}");
    assert_eq!(std::fs::read(&remote)?, std::fs::read(&local)?);

    let resume_local = dir.path().join("resume.bin");
    write_pattern(&resume_local, 200_000, 9)?;
    let resume_remote = dir.path().join("remote-resume.bin");
    let (partial, journal) = engine::partial_paths(&resume_remote);
    let hash = delta::hash_file(&resume_local)?;
    let bytes = std::fs::read(&resume_local)?;
    std::fs::write(&partial, &bytes[..100_000])?;
    let partial_file = std::fs::OpenOptions::new().write(true).open(&partial)?;
    partial_file.set_len(200_000)?;
    std::fs::write(
        &journal,
        serde_json::json!({
            "hash": hash,
            "size": 200_000,
            "ranges": [{"start": 0, "end": 100_000}]
        })
        .to_string(),
    )?;
    let resumed = admin
        .copy_upload(
            "box",
            &resume_remote.to_string_lossy(),
            &resume_local,
            &opts,
            None,
        )
        .await?;
    assert!(
        resumed.resumed_bytes >= 100_000,
        "resume did not keep the first half: {resumed:?}"
    );
    assert!(resumed.payload_bytes < 150_000, "{resumed:?}");
    assert_eq!(std::fs::read(&resume_remote)?, bytes);

    let text_local = dir.path().join("notes.txt");
    std::fs::write(&text_local, "agentlink ".repeat(20_000))?;
    let text_remote = dir.path().join("remote-notes.txt");
    let text = admin
        .copy_upload(
            "box",
            &text_remote.to_string_lossy(),
            &text_local,
            &opts,
            None,
        )
        .await?;
    assert!(text.compressed, "{text:?}");
    assert!(text.payload_bytes < text.logical_bytes / 2, "{text:?}");

    let zip_local = dir.path().join("blob.zip");
    write_pattern(&zip_local, 32 * 1024, 3)?;
    let zip_remote = dir.path().join("remote-blob.zip");
    let zip = admin
        .copy_upload(
            "box",
            &zip_remote.to_string_lossy(),
            &zip_local,
            &opts,
            None,
        )
        .await?;
    assert!(!zip.compressed, "zip should skip zstd: {zip:?}");
    assert_eq!(zip.payload_bytes, zip.logical_bytes);

    let mut relay_opts = opts.clone();
    relay_opts.transport = "relay-only".into();
    let relayed_local = dir.path().join("relayed.bin");
    write_pattern(&relayed_local, 80_000, 4)?;
    let relayed_remote = dir.path().join("remote-relayed.bin");
    let relayed = admin
        .copy_upload(
            "box",
            &relayed_remote.to_string_lossy(),
            &relayed_local,
            &relay_opts,
            None,
        )
        .await?;
    assert_eq!(relayed.transport, "relay", "{relayed:?}");
    assert_eq!(
        std::fs::read(&relayed_remote)?,
        std::fs::read(&relayed_local)?
    );

    let down_local = dir.path().join("downloaded.bin");
    let down = admin
        .copy_download("box", &remote_s, &down_local, &relay_opts, None)
        .await?;
    assert_eq!(std::fs::read(&down_local)?, std::fs::read(&local)?);
    assert_eq!(down.transport, "relay");

    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("sub"))?;
    for i in 0..10 {
        std::fs::write(tree.join(format!("f{i}.txt")), format!("file {i}\n"))?;
    }
    std::fs::write(tree.join("sub/nested.txt"), b"nested")?;
    let remote_tree = dir.path().join("remote-tree");
    let pushed = admin
        .copy_upload("box", &remote_tree.to_string_lossy(), &tree, &opts, None)
        .await?;
    assert!(pushed.files >= 11, "{pushed:?}");
    assert_eq!(
        std::fs::read(remote_tree.join("sub/nested.txt"))?,
        b"nested"
    );
    assert_eq!(std::fs::read(remote_tree.join("f3.txt"))?, b"file 3\n");
    let pushed_again = admin
        .copy_upload("box", &remote_tree.to_string_lossy(), &tree, &opts, None)
        .await?;
    assert_eq!(pushed_again.payload_bytes, 0, "{pushed_again:?}");

    let pulled = dir.path().join("pulled-tree");
    admin
        .copy_download(
            "box",
            &remote_tree.to_string_lossy(),
            &pulled,
            &relay_opts,
            None,
        )
        .await?;
    assert_eq!(std::fs::read(pulled.join("f3.txt"))?, b"file 3\n");

    let src_for_peer = dir.path().join("on-box.txt");
    std::fs::write(&src_for_peer, b"from box to other")?;
    let dst_for_peer = dir.path().join("on-other.txt");
    // Relay peer path (direct=false) exercises node↔node e2e seal/open. A
    // regression that only opens with client_id leaves Accept undecrypted on
    // the initiator and stalls until the client bridge timeout.
    let peer = admin
        .copy_node_to_node(
            "box",
            &src_for_peer.to_string_lossy(),
            "other",
            &dst_for_peer.to_string_lossy(),
            &opts,
            false,
            None,
        )
        .await?;
    assert_eq!(std::fs::read(&dst_for_peer)?, b"from box to other");
    assert_eq!(peer.transport, "relay", "{peer:?}");

    admin
        .copy_upload("ro", &remote_s, &local, &relay_opts, None)
        .await?;

    stream_round_trip(&admin, dir.path(), &opts, &relay_opts).await?;

    box_stop.cancel();
    other_stop.cancel();
    ro_stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), box_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), other_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), ro_task).await;
    let _ = Instant::now();
    Ok(())
}

fn spawn_node(
    relay_url: &str,
    fingerprint: &str,
    data_dir: &Path,
    name: &str,
    token: &str,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<agentlink_core::Result<()>> {
    let relay_url = relay_url.to_string();
    let fingerprint = fingerprint.to_string();
    let data_dir = data_dir.to_path_buf();
    let name = name.to_string();
    let token = token.to_string();
    tokio::spawn(run(
        NodeConfig {
            relay_url,
            fingerprint,
            trust: None,
            data_dir,
            name,
            pairing_token: Some(token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        shutdown,
    ))
}

async fn wait_online(admin: &Client, names: &[&str]) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let ready = admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| {
                names
                    .iter()
                    .all(|name| nodes.iter().any(|node| node.name == *name && node.online))
            })
            .unwrap_or(false);
        if ready {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for nodes {names:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn stream_round_trip(
    admin: &Client,
    dir: &Path,
    opts: &XferOpts,
    relay_opts: &XferOpts,
) -> anyhow::Result<()> {
    let raw = {
        let tmp = dir.join("stream-src.bin");
        write_pattern(&tmp, 200_000, 7)?;
        std::fs::read(tmp)?
    };
    let remote = dir.join("remote-streamed.bin");
    let mut reader = ShortRead {
        inner: std::io::Cursor::new(raw.clone()),
        cap: 1000,
    };
    let up = admin
        .stream_upload("box", &remote.to_string_lossy(), &mut reader, opts)
        .await?;
    assert_eq!(
        up.transport, "relay",
        "stream upload stays on the sealed relay path: {up:?}"
    );
    assert_eq!(up.logical_bytes, raw.len() as u64);
    assert_eq!(std::fs::read(&remote)?, raw);

    let mut downloaded = CountWrite {
        inner: Vec::new(),
        writes: 0,
    };
    let down = admin
        .stream_download(
            "box",
            &remote.to_string_lossy(),
            0,
            None,
            &mut downloaded,
            opts,
        )
        .await?;
    assert_eq!(down.stats.transport, "relay", "{down:?}");
    assert_eq!(downloaded.inner, raw);
    assert!(
        downloaded.writes >= 2,
        "stdout path should write more than one chunk, got {}",
        downloaded.writes
    );
    assert_eq!(down.file_size, raw.len() as u64);

    let mut ranged = Vec::new();
    let range = admin
        .stream_download(
            "box",
            &remote.to_string_lossy(),
            1_000,
            Some(40),
            &mut ranged,
            opts,
        )
        .await?;
    assert_eq!(ranged, raw[1_000..1_040]);
    assert_eq!(range.file_size, raw.len() as u64);
    assert!(range.end < range.file_size);

    let empty_remote = dir.join("remote-empty.bin");
    let empty = admin
        .stream_upload(
            "box",
            &empty_remote.to_string_lossy(),
            &mut std::io::empty(),
            opts,
        )
        .await?;
    assert_eq!(empty.logical_bytes, 0, "{empty:?}");
    assert!(std::fs::read(&empty_remote)?.is_empty());

    let text = "agentlink ".repeat(20_000);
    let text_remote = dir.join("remote-stream-notes.txt");
    let text_up = admin
        .stream_upload(
            "box",
            &text_remote.to_string_lossy(),
            &mut std::io::Cursor::new(text.as_bytes()),
            opts,
        )
        .await?;
    assert!(text_up.compressed, "{text_up:?}");
    assert!(
        text_up.payload_bytes < text_up.logical_bytes / 2,
        "{text_up:?}"
    );
    assert_eq!(std::fs::read(&text_remote)?, text.as_bytes());

    let zip_bytes = {
        let tmp = dir.join("stream-blob.zip");
        write_pattern(&tmp, 80_000, 3)?;
        std::fs::read(tmp)?
    };
    let zip_remote = dir.join("remote-stream.zip");
    let zip = admin
        .stream_upload(
            "box",
            &zip_remote.to_string_lossy(),
            &mut std::io::Cursor::new(zip_bytes.clone()),
            opts,
        )
        .await?;
    assert!(!zip.compressed, "zip stream should skip zstd: {zip:?}");
    assert_eq!(zip.payload_bytes, zip.logical_bytes);
    assert_eq!(std::fs::read(&zip_remote)?, zip_bytes);

    let relayed_remote = dir.join("remote-stream-relay.bin");
    let relayed = admin
        .stream_upload(
            "box",
            &relayed_remote.to_string_lossy(),
            &mut std::io::Cursor::new(raw[..8000].to_vec()),
            relay_opts,
        )
        .await?;
    assert_eq!(relayed.transport, "relay", "{relayed:?}");
    assert_eq!(std::fs::read(&relayed_remote)?, &raw[..8000]);

    admin
        .stream_upload(
            "ro",
            &remote.to_string_lossy(),
            &mut std::io::Cursor::new(b"nope".as_slice()),
            relay_opts,
        )
        .await?;
    admin
        .stream_upload(
            "ro",
            &remote.to_string_lossy(),
            &mut std::io::Cursor::new(b"nope".as_slice()),
            opts,
        )
        .await?;
    Ok(())
}

struct ShortRead<R> {
    inner: R,
    cap: usize,
}

impl<R: Read> Read for ShortRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.cap);
        self.inner.read(&mut buf[..n])
    }
}

struct CountWrite {
    inner: Vec<u8>,
    writes: usize,
}

impl Write for CountWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writes += 1;
        self.inner.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_pattern(path: &Path, len: usize, seed: u8) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    let mut buf = vec![0u8; 8192];
    let mut left = len;
    let mut n = seed as u64;
    while left > 0 {
        for byte in &mut buf {
            n = n.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (n >> 33) as u8;
        }
        let take = left.min(buf.len());
        file.write_all(&buf[..take])?;
        left -= take;
    }
    Ok(())
}

trait SeekExt {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64>;
}
impl SeekExt for std::fs::File {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        std::io::Seek::seek(self, pos)
    }
}
