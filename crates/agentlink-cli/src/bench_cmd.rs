//! `agentlink bench`: loopback transfer throughput, exec and MCP latency, idle
//! node memory, and a local scp/rsync comparison. Prints one markdown table.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use agentlink_core::engine::XferOpts;
use agentlink_core::process;
use agentlink_core::protocol::CompressPref;
use agentlink_core::{Client, ClientSettings, ExecRequest};
use anyhow::{anyhow, Context, Result};
use sysinfo::{Pid, ProcessesToUpdate, System};

pub async fn run(quick: bool, out: Option<&Path>) -> Result<i32> {
    let bin = std::env::current_exe().context("current executable")?;
    let root = tempfile::tempdir().context("bench temp dir")?;
    let relay_dir = root.path().join("relay");
    let node_dir = root.path().join("node");
    let work = root.path().join("work");
    std::fs::create_dir_all(&work)?;

    let relay = spawn(
        &bin,
        &[
            "relay",
            "--bind",
            "127.0.0.1:0",
            "--data-dir",
            relay_dir.to_str().unwrap(),
        ],
        &root.path().join("relay.log"),
    )?;
    let addr = wait_file(&relay_dir.join("listen_addr.txt"))?;
    let fingerprint = wait_file(&relay_dir.join("fingerprint.txt"))?;
    let token = wait_file(&relay_dir.join("admin.token"))?;
    let relay_url = format!("wss://{addr}");

    let client = Client::connect(&ClientSettings {
        relay: relay_url.clone(),
        token: token.clone(),
        fingerprint: fingerprint.clone(),
        trust: None,
    })
    .await
    .map_err(|err| anyhow!(err.to_string()))?;
    let paired = client
        .create_pairing_token("bench", agentlink_core::NodePolicy::exec(), 3600)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    let node = spawn(
        &bin,
        &[
            "--relay",
            &relay_url,
            "--fingerprint",
            &fingerprint,
            "node",
            "--name",
            "bench",
            "--pairing-token",
            &paired.token,
            "--data-dir",
            node_dir.to_str().unwrap(),
            "--root",
            work.to_str().unwrap(),
        ],
        &root.path().join("node.log"),
    )?;
    wait_online(&client).await?;
    let idle = sample_idle(node.0.id());

    let mut rows = Vec::new();
    rows.push(("idle node RSS".into(), format!("{:.1} MiB", idle.0)));
    rows.push(("idle node CPU".into(), format!("{:.1}%", idle.1)));

    let small_count = if quick { 200 } else { 2_000 };
    let exec_n = if quick { 24 } else { 40 };
    let mcp_n = if quick { 16 } else { 24 };
    let mut sizes = vec![1024 * 1024];
    if !quick {
        sizes.push(100 * 1024 * 1024);
        sizes.push(1024 * 1024 * 1024);
    }

    for size in sizes {
        let label = human_size(size);
        let sparse = size >= 1024 * 1024 * 1024;
        let src = work.join(format!("src-{size}.bin"));
        if sparse {
            let file = std::fs::File::create(&src)?;
            file.set_len(size as u64)?;
        } else {
            write_pattern(&src, size)?;
        }
        for (name, transport) in [("relay", "relay-only"), ("quic", "relay")] {
            let dest = work.join(format!("dst-{size}-{name}.bin"));
            let started = Instant::now();
            let stats = client
                .copy_upload(
                    "bench",
                    &dest.display().to_string(),
                    &src,
                    &xfer(transport),
                    None,
                )
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            let secs = started.elapsed().as_secs_f64().max(1e-9);
            let mib_s = (stats.logical_bytes as f64) / secs / (1024.0 * 1024.0);
            rows.push((
                format!("{label} via {name}"),
                format!(
                    "{mib_s:.1} MiB/s in {secs:.3}s ({}, {} bytes)",
                    stats.transport, stats.logical_bytes
                ),
            ));
        }
        if size == 1024 * 1024 {
            if let Some(secs) = time_local(
                "rsync",
                &[
                    "-a",
                    src.to_str().unwrap(),
                    work.join("rsync-dst.bin").to_str().unwrap(),
                ],
            ) {
                rows.push((
                    "rsync 1 MiB loopback".into(),
                    format!("{:.1} MiB/s", 1.0 / secs),
                ));
            } else {
                rows.push(("rsync 1 MiB loopback".into(), "not available".into()));
            }
            if let Some(secs) = time_local(
                "scp",
                &[
                    "-q",
                    src.to_str().unwrap(),
                    work.join("scp-dst.bin").to_str().unwrap(),
                ],
            ) {
                rows.push((
                    "scp 1 MiB loopback".into(),
                    format!("{:.1} MiB/s", 1.0 / secs),
                ));
            } else {
                rows.push(("scp 1 MiB loopback".into(), "not available".into()));
            }
        }
    }

    let many = work.join("many");
    std::fs::create_dir_all(&many)?;
    for index in 0..small_count {
        std::fs::write(many.join(format!("f{index:05}.txt")), vec![b'x'; 128])?;
    }
    let many_dest = work.join("many-out");
    let started = Instant::now();
    let stats = client
        .copy_upload(
            "bench",
            &many_dest.display().to_string(),
            &many,
            &xfer("relay-only"),
            None,
        )
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    let secs = started.elapsed().as_secs_f64().max(1e-9);
    rows.push((
        format!("{small_count} small files"),
        format!(
            "{:.0} files/s, {:.1} MiB/s ({} files)",
            f64::from(stats.files) / secs,
            (stats.logical_bytes as f64) / secs / (1024.0 * 1024.0),
            stats.files
        ),
    ));

    let mut exec_ms = Vec::with_capacity(exec_n);
    for _ in 0..exec_n {
        let started = Instant::now();
        let output = client
            .exec_collect(
                "bench",
                ExecRequest::shell(echo_ok(), Some(Duration::from_secs(10))),
                None,
            )
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
        if output.exit_code != Some(0) {
            return Err(anyhow!("bench exec failed: {output:?}"));
        }
        exec_ms.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    rows.push((
        "exec round trip".into(),
        format!(
            "p50 {:.2} ms, p99 {:.2} ms (n={exec_n})",
            percentile(&mut exec_ms, 0.50),
            percentile(&mut exec_ms, 0.99)
        ),
    ));

    let mcp_ms = mcp_latency(&bin, &relay_url, &token, &fingerprint, mcp_n).await?;
    let mut mcp_ms = mcp_ms;
    rows.push((
        "MCP list_machines".into(),
        format!(
            "p50 {:.2} ms, p99 {:.2} ms (n={})",
            percentile(&mut mcp_ms, 0.50),
            percentile(&mut mcp_ms, 0.99),
            mcp_ms.len()
        ),
    ));

    let table = render(&rows, quick);
    print!("{table}");
    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        std::fs::write(path, &table)?;
    }

    drop(client);
    drop(node);
    drop(relay);
    Ok(0)
}

fn render(rows: &[(String, String)], quick: bool) -> String {
    let mut out = String::new();
    let mode = if quick { "quick" } else { "full" };
    out.push_str(&format!("# agentlink bench ({mode})\n\n"));
    out.push_str("Transfers use compression off. `quic` is the direct path with relay fallback; the parenthetical name is the transport that actually moved the bytes. scp and rsync copy the same 1 MiB file on the local machine when those tools exist.\n\n");
    out.push_str("| measurement | value |\n| --- | --- |\n");
    for (name, value) in rows {
        out.push_str(&format!("| {name} | {value} |\n"));
    }
    out
}

fn xfer(transport: &str) -> XferOpts {
    XferOpts {
        compress: CompressPref::Off,
        transport: transport.into(),
        ..XferOpts::default()
    }
}

fn human_size(size: usize) -> String {
    if size >= 1024 * 1024 * 1024 {
        "1 GiB sparse".into()
    } else if size >= 100 * 1024 * 1024 {
        "100 MiB".into()
    } else {
        "1 MiB".into()
    }
}

fn echo_ok() -> &'static str {
    if cfg!(windows) {
        "echo ok"
    } else {
        "echo ok"
    }
}

fn write_pattern(path: &Path, len: usize) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    let chunk = vec![0x5Au8; 64 * 1024];
    let mut left = len;
    while left > 0 {
        let n = left.min(chunk.len());
        file.write_all(&chunk[..n])?;
        left -= n;
    }
    Ok(())
}

fn percentile(samples: &mut [f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((samples.len() - 1) as f64 * p).round() as usize;
    samples[idx.min(samples.len() - 1)]
}

fn sample_idle(pid: u32) -> (f64, f64) {
    let mut sys = System::new();
    let id = Pid::from_u32(pid);
    sys.refresh_processes(ProcessesToUpdate::Some(&[id]), true);
    std::thread::sleep(Duration::from_millis(400));
    sys.refresh_processes(ProcessesToUpdate::Some(&[id]), true);
    match sys.process(id) {
        Some(process) => (
            process.memory() as f64 / (1024.0 * 1024.0),
            f64::from(process.cpu_usage()),
        ),
        None => (0.0, 0.0),
    }
}

fn time_local(program: &str, args: &[&str]) -> Option<f64> {
    let started = Instant::now();
    let status = process::hidden(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if status.success() {
        Some(started.elapsed().as_secs_f64().max(1e-9))
    } else {
        None
    }
}

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(bin: &Path, args: &[&str], log_path: &Path) -> Result<Guard> {
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let log = std::fs::File::create(log_path)?;
    let child = process::hidden(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .with_context(|| format!("spawn {}", args.first().unwrap_or(&"agentlink")))?;
    Ok(Guard(child))
}

fn wait_file(path: &Path) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            let text = text.trim().to_string();
            if !text.is_empty() {
                return Ok(text);
            }
        }
        if Instant::now() > deadline {
            return Err(anyhow!("timed out waiting for {}", path.display()));
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

async fn wait_online(client: &Client) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        if let Ok(nodes) = client.list_nodes().await {
            if nodes.iter().any(|node| node.name == "bench" && node.online) {
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            return Err(anyhow!("bench node did not come online"));
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
}

async fn mcp_latency(
    bin: &Path,
    relay: &str,
    token: &str,
    fingerprint: &str,
    samples: usize,
) -> Result<Vec<f64>> {
    let log_dir = std::env::temp_dir().join(format!("agentlink-mcp-bench-{}", std::process::id()));
    std::fs::create_dir_all(&log_dir)?;
    let err_path = log_dir.join("mcp.err");
    let err = std::fs::File::create(&err_path)?;
    let child = Guard(
        process::hidden(bin)
            .args([
                "--relay",
                relay,
                "--token",
                token,
                "--fingerprint",
                fingerprint,
                "mcp",
                "--http",
                "127.0.0.1:0",
                "--mcp-token",
                "bench-mcp",
            ])
            .env("AGENTLINK_CONFIG_DIR", &log_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(err))
            .spawn()
            .context("spawn mcp")?,
    );
    let line = wait_line(&err_path, "mcp http listening on ")?;
    let url = line
        .split_whitespace()
        .find(|part| part.starts_with("http://"))
        .ok_or_else(|| anyhow!("mcp listen line: {line}"))?;
    let addr = url.trim_start_matches("http://").trim_end_matches("/mcp");
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        let body = mcp_post(addr, "bench-mcp")?;
        if !body.contains("bench") {
            return Err(anyhow!("mcp list_machines missed the node: {body}"));
        }
        out.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    drop(child);
    Ok(out)
}

fn wait_line(path: &Path, needle: &str) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Some(line) = text.lines().find(|line| line.contains(needle)) {
                return Ok(line.to_string());
            }
        }
        if Instant::now() > deadline {
            let seen = std::fs::read_to_string(path).unwrap_or_default();
            return Err(anyhow!("timed out waiting for {needle} in {seen}"));
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn mcp_post(addr: &str, token: &str) -> Result<String> {
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_machines","arguments":{}}}"#;
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = std::net::TcpStream::connect(addr).context("mcp connect")?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_string();
    if !text.contains("200") {
        return Err(anyhow!("mcp http failed: {text}"));
    }
    Ok(text)
}
