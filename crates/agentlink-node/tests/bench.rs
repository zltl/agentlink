//! Throughput comparison. Not part of CI.
//!
//! ```text
//! cargo test --release -p agentlink-node --test bench -- --ignored --nocapture
//! ```

use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};

use agentlink_core::engine::XferOpts;
use agentlink_core::protocol::CompressPref;
use agentlink_core::{Client, ClientSettings, NodePolicy};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_transfer() {
    let result = tokio::time::timeout(Duration::from_secs(60 * 30), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("benchmark timed out"),
    }
}

async fn flow() -> anyhow::Result<()> {
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
    let pairing = admin
        .create_pairing_token("bench", NodePolicy::exec(), 3600)
        .await?;
    let stop = CancellationToken::new();
    let node = tokio::spawn(run(
        NodeConfig {
            relay_url: relay_url.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: dir.path().join("node"),
            name: "bench".into(),
            pairing_token: Some(pairing.token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "bench".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        stop.clone(),
    ));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let online = admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|node| node.name == "bench" && node.online));
        if online == Some(true) {
            break;
        }
        if Instant::now() > deadline {
            panic!("node did not come online");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let gib = 1024 * 1024 * 1024;
    let big = dir.path().join("1gib.bin");
    write_pattern(&big, gib, 7)?;
    let remote_old = dir.path().join("old-1gib.bin");
    let remote_new = dir.path().join("new-1gib.bin");
    let remote_direct = dir.path().join("direct-1gib.bin");

    let old_start = Instant::now();
    let old_bytes = {
        let file = File::open(&big)?;
        admin
            .write_file_from("bench", &remote_old.to_string_lossy(), file)
            .await?
    };
    let old_secs = old_start.elapsed().as_secs_f64();

    let relay_opts = XferOpts {
        chunk_size: 1024 * 1024,
        window: 8,
        parallel: 4,
        compress: CompressPref::Off,
        resume: false,
        transport: "relay-only".into(),
    };
    let new_start = Instant::now();
    let new_stats = admin
        .copy_upload(
            "bench",
            &remote_new.to_string_lossy(),
            &big,
            &relay_opts,
            None,
        )
        .await?;
    let new_secs = new_start.elapsed().as_secs_f64();

    let mut direct_opts = relay_opts.clone();
    direct_opts.transport = "relay".into();
    let direct_start = Instant::now();
    let direct_stats = admin
        .copy_upload(
            "bench",
            &remote_direct.to_string_lossy(),
            &big,
            &direct_opts,
            None,
        )
        .await?;
    let direct_secs = direct_start.elapsed().as_secs_f64();

    let many = dir.path().join("many");
    std::fs::create_dir_all(&many)?;
    for i in 0..10_000 {
        std::fs::write(many.join(format!("{i}.txt")), format!("n{i:05}"))?;
    }
    let old_many_start = Instant::now();
    for i in 0..10_000 {
        let name = format!("{i}.txt");
        let bytes = std::fs::read(many.join(&name))?;
        let remote = dir.path().join("old-many").join(&name);
        if let Some(parent) = remote.parent() {
            std::fs::create_dir_all(parent)?;
        }
        admin
            .write_file("bench", &remote.to_string_lossy(), &bytes)
            .await?;
    }
    let old_many_secs = old_many_start.elapsed().as_secs_f64();

    let new_many = dir.path().join("new-many");
    let new_many_start = Instant::now();
    let many_stats = admin
        .copy_upload(
            "bench",
            &new_many.to_string_lossy(),
            &many,
            &relay_opts,
            None,
        )
        .await?;
    let new_many_secs = new_many_start.elapsed().as_secs_f64();

    println!(
        "bench 1GiB old_bytes={old_bytes} old_secs={old_secs:.2} old_mib_s={:.1} new_relay_secs={new_secs:.2} new_relay_mib_s={:.1} new_relay_transport={} new_direct_secs={direct_secs:.2} new_direct_mib_s={:.1} new_direct_transport={}",
        mib_s(old_bytes, old_secs),
        mib_s(new_stats.logical_bytes, new_secs),
        new_stats.transport,
        mib_s(direct_stats.logical_bytes, direct_secs),
        direct_stats.transport,
    );
    println!(
        "bench 10k old_secs={old_many_secs:.2} new_secs={new_many_secs:.2} new_files={} new_payload={}",
        many_stats.files, many_stats.payload_bytes
    );

    stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), node).await;
    Ok(())
}

fn mib_s(bytes: u64, secs: f64) -> f64 {
    (bytes as f64 / secs) / (1024.0 * 1024.0)
}

fn write_pattern(path: &std::path::Path, len: usize, seed: u8) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    let mut buf = vec![0u8; 1024 * 1024];
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
