//! Black-box CLI and MCP flow: relay, pair, node, exec, write/read, tools/list, tools/call.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

struct Guard(std::process::Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn cli_and_mcp_round_trip() {
    let bin = env!("CARGO_BIN_EXE_agentlink");
    let root = tempfile::tempdir().unwrap();
    let relay_dir = root.path().join("relay");
    let node_dir = root.path().join("node");
    let config_dir = root.path().join("config");
    let log_dir = root.path().join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();

    let relay_log = std::fs::File::create(log_dir.join("relay.log")).unwrap();
    let relay = Guard(
        Command::new(bin)
            .args([
                "relay",
                "--bind",
                "127.0.0.1:0",
                "--data-dir",
                relay_dir.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::from(relay_log))
            .spawn()
            .unwrap(),
    );

    let addr = wait_file(&relay_dir.join("listen_addr.txt"));
    let fingerprint = wait_file(&relay_dir.join("fingerprint.txt"));
    let token = wait_file(&relay_dir.join("admin.token"));
    let relay_url = format!("wss://{addr}");

    let base = vec![
        "--config-dir".to_string(),
        config_dir.to_str().unwrap().to_string(),
        "--relay".to_string(),
        relay_url.clone(),
        "--token".to_string(),
        token.clone(),
        "--fingerprint".to_string(),
        fingerprint.clone(),
        "--json".to_string(),
    ];

    let paired = run(bin, &base, &["pair", "--name", "smoke", "--access", "exec"]);
    assert!(paired.status.success(), "pair failed: {}", stderr(&paired));
    let pairing: Value = serde_json::from_slice(&paired.stdout).expect("pair json");
    let pairing_token = pairing["pairing_token"].as_str().unwrap();

    let node_log = std::fs::File::create(log_dir.join("node.log")).unwrap();
    let node = Guard(
        Command::new(bin)
            .args([
                "--relay",
                &relay_url,
                "--fingerprint",
                &fingerprint,
                "node",
                "--name",
                "smoke",
                "--pairing-token",
                pairing_token,
                "--data-dir",
                node_dir.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::from(node_log))
            .spawn()
            .unwrap(),
    );

    let listed = wait_until(|| {
        let out = run(bin, &base, &["ls"]);
        if !out.status.success() {
            return None;
        }
        let value: Value = serde_json::from_slice(&out.stdout).ok()?;
        let online = value["nodes"]
            .as_array()?
            .iter()
            .any(|n| n["name"] == "smoke" && n["online"] == true);
        if online {
            Some(value)
        } else {
            None
        }
    });
    assert!(listed["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["name"] == "smoke"));

    // Nodes trust only grants signed by their own grant issuer (owner-keys.json),
    // so mint one from the node data dir like functional.rs; auto-grant instead
    // signs with the client identity, which the node rejects.
    mint_grant(bin, &base, "smoke", &node_dir);

    let exec = run(
        bin,
        &base,
        &["exec", "smoke", "--shell", "--", "echo", "hello-agentlink"],
    );
    assert!(exec.status.success(), "exec failed: {}", stderr(&exec));
    let exec_json: Value = serde_json::from_slice(&exec.stdout).expect("exec json");
    assert_eq!(exec_json["exit_code"], 0);
    assert!(exec_json["stdout"]
        .as_str()
        .unwrap()
        .contains("hello-agentlink"));

    let file = root.path().join("from-cli.txt");
    let file_str = file.to_str().unwrap();
    let write = run(
        bin,
        &base,
        &[
            "write",
            "smoke",
            file_str,
            "--content",
            "hello from agentlink",
        ],
    );
    assert!(write.status.success(), "write failed: {}", stderr(&write));

    let cat = command(bin)
        .args([
            "--config-dir",
            config_dir.to_str().unwrap(),
            "--relay",
            &relay_url,
            "--token",
            &token,
            "--fingerprint",
            &fingerprint,
            "cat",
            "smoke",
            file_str,
        ])
        .output()
        .unwrap();
    assert!(cat.status.success(), "cat failed: {}", stderr(&cat));
    assert_eq!(cat.stdout, b"hello from agentlink");

    let cat_json = run(bin, &base, &["cat", "smoke", file_str]);
    assert!(
        cat_json.status.success(),
        "cat --json failed: {}",
        stderr(&cat_json)
    );
    let cat_body: Value = serde_json::from_slice(&cat_json.stdout).expect("cat json");
    assert_eq!(cat_body["encoding"], "utf-8");
    assert_eq!(cat_body["content"], "hello from agentlink");
    assert_eq!(cat_body["truncated"], false);

    let piped = root.path().join("piped.txt");
    let piped_body = b"stream-me-".repeat(8_000);
    let piped_out = write_stdin(
        bin,
        &base,
        &["write", "smoke", piped.to_str().unwrap()],
        &piped_body,
    );
    assert!(
        piped_out.status.success(),
        "stdin write failed: {}",
        stderr(&piped_out)
    );
    let piped_cat = command(bin)
        .args([
            "--config-dir",
            config_dir.to_str().unwrap(),
            "--relay",
            &relay_url,
            "--token",
            &token,
            "--fingerprint",
            &fingerprint,
            "cat",
            "smoke",
            piped.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        piped_cat.status.success(),
        "cat piped failed: {}",
        stderr(&piped_cat)
    );
    assert_eq!(piped_cat.stdout, piped_body);

    let empty_remote = root.path().join("empty.txt");
    // The CLI rejects an empty stdin pipe as a likely mistake; intentional
    // empties go through `--content ''`.
    let empty_out = run(
        bin,
        &base,
        &[
            "write",
            "smoke",
            empty_remote.to_str().unwrap(),
            "--content",
            "",
        ],
    );
    assert!(
        empty_out.status.success(),
        "empty write failed: {}",
        stderr(&empty_out)
    );
    assert!(std::fs::read(&empty_remote).unwrap().is_empty());

    let local = root.path().join("upload.txt");
    std::fs::write(&local, b"copied").unwrap();
    let remote = root.path().join("copied.txt");
    let remote_url = node_url("smoke", &remote);
    let cp = run(bin, &base, &["cp", local.to_str().unwrap(), &remote_url]);
    assert!(cp.status.success(), "cp failed: {}", stderr(&cp));
    assert_eq!(std::fs::read(&remote).unwrap(), b"copied");

    let note = root.path().join("search-me.txt");
    std::fs::write(&note, "unique-smoke-token\n").unwrap();
    let searched = run(
        bin,
        &base,
        &[
            "search",
            "smoke",
            "unique-smoke-token",
            note.to_str().unwrap(),
            "--literal",
        ],
    );
    assert!(
        searched.status.success(),
        "search failed: {}",
        stderr(&searched)
    );
    let search_json: Value = serde_json::from_slice(&searched.stdout).expect("search json");
    assert!(
        search_json["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["text"]
                .as_str()
                .unwrap_or("")
                .contains("unique-smoke-token")),
        "{search_json}"
    );

    let info = run(bin, &base, &["sysinfo", "smoke"]);
    assert!(info.status.success(), "sysinfo failed: {}", stderr(&info));
    let info_json: Value = serde_json::from_slice(&info.stdout).expect("sysinfo json");
    assert!(
        info_json["cpu"]["count"].as_u64().unwrap_or(0) > 0,
        "{info_json}"
    );

    let bg = run(
        bin,
        &base,
        &["bg", "smoke", "start", "--shell", "--", "echo", "bg-smoke"],
    );
    assert!(bg.status.success(), "bg start failed: {}", stderr(&bg));
    let bg_json: Value = serde_json::from_slice(&bg.stdout).expect("bg json");
    assert!(bg_json["id"].as_str().unwrap().len() > 0, "{bg_json}");

    mcp_round_trip(bin, &relay_url, &token, &fingerprint, &config_dir);

    drop(node);
    drop(relay);
}

fn mcp_round_trip(
    bin: &str,
    relay: &str,
    token: &str,
    fingerprint: &str,
    config_dir: &std::path::Path,
) {
    let mut child = command(bin)
        .args(["--config-dir", config_dir.to_str().unwrap(), "mcp"])
        .env("AGENTLINK_RELAY", relay)
        .env("AGENTLINK_TOKEN", token)
        .env("AGENTLINK_FINGERPRINT", fingerprint)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}"#,
    );
    let init = read_json(&mut reader);
    assert_eq!(init["result"]["serverInfo"]["name"], "agentlink");

    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    );
    let tools = read_json(&mut reader);
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(names.contains(&"list_machines"));
    assert!(names.contains(&"read_file"));
    assert!(names.contains(&"write_file"));
    assert!(names.contains(&"list_dir"));
    assert!(names.contains(&"run_command"));
    assert!(names.contains(&"search_content"));
    assert!(names.contains(&"system_info"));
    assert!(names.contains(&"process_start"));
    assert!(names.contains(&"terminal_open"));

    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_machines","arguments":{}}}"#,
    );
    let listed = read_json(&mut reader);
    assert_eq!(listed["result"]["isError"], false);
    let text = listed["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("smoke"), "{text}");

    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_command","arguments":{"node":"smoke","command":"echo mcp-ok"}}}"#,
    );
    let ran = read_json(&mut reader);
    assert_eq!(ran["result"]["isError"], false, "{ran}");
    let body: Value =
        serde_json::from_str(ran["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body["exit_code"], 0);
    assert!(body["stdout"].as_str().unwrap().contains("mcp-ok"));

    let mcp_path = config_dir.join("mcp-file.txt");
    let path_json = serde_json::to_string(&mcp_path.to_string_lossy().to_string()).unwrap();
    send(
        &mut stdin,
        &format!(
            r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"write_file","arguments":{{"node":"smoke","path":{path_json},"content":"mcp-file"}}}}}}"#
        ),
    );
    let wrote = read_json(&mut reader);
    assert_eq!(wrote["result"]["isError"], false, "{wrote}");

    send(
        &mut stdin,
        &format!(
            r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"read_file","arguments":{{"node":"smoke","path":{path_json},"max_bytes":4}}}}}}"#
        ),
    );
    let read = read_json(&mut reader);
    assert_eq!(read["result"]["isError"], false, "{read}");
    let page: Value =
        serde_json::from_str(read["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(page["encoding"], "utf-8");
    assert_eq!(page["content"], "mcp-");
    assert_eq!(page["truncated"], true);
    assert_eq!(page["size"], 8);

    let bin_path = config_dir.join("mcp-bin.dat");
    let bin_json = serde_json::to_string(&bin_path.to_string_lossy().to_string()).unwrap();
    send(
        &mut stdin,
        &format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"write_file","arguments":{{"node":"smoke","path":{bin_json},"content_base64":"AP8K"}}}}}}"#
        ),
    );
    let wrote_bin = read_json(&mut reader);
    assert_eq!(wrote_bin["result"]["isError"], false, "{wrote_bin}");
    send(
        &mut stdin,
        &format!(
            r#"{{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{{"name":"read_file","arguments":{{"node":"smoke","path":{bin_json}}}}}}}"#
        ),
    );
    let read_bin = read_json(&mut reader);
    assert_eq!(read_bin["result"]["isError"], false, "{read_bin}");
    let blob: Value =
        serde_json::from_str(read_bin["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(blob["encoding"], "base64");
    assert_eq!(blob["content_base64"], "AP8K");
    assert_eq!(std::fs::read(&bin_path).unwrap(), [0, 255, 10]);

    let _ = child.kill();
    let _ = child.wait();
}

fn command(bin: &str) -> Command {
    Command::new(bin)
}

fn run(bin: &str, prefix: &[String], args: &[&str]) -> std::process::Output {
    let output = command(bin).args(prefix).args(args).output().unwrap();
    output
}

/// Sign a grant with the node's own `grant-issuer.json` so the node trusts it.
fn mint_grant(bin: &str, base: &[String], name: &str, node_dir: &std::path::Path) {
    let out = run(
        bin,
        base,
        &[
            "grant",
            "issue",
            "--node",
            name,
            "--ttl",
            "1h",
            "--policy",
            "full",
            "--issuer-data-dir",
            node_dir.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "could not mint a node-trusted grant: {}",
        stderr(&out)
    );
}

fn stderr(output: &std::process::Output) -> String {
    format!(
        "status {}\nstdout {}\nstderr {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn wait_file(path: &std::path::Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            let text = text.trim().to_string();
            if !text.is_empty() {
                return text;
            }
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_until<T>(mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(value) = probe() {
            return value;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for the node to come online");
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn node_url(node: &str, path: &std::path::Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    if let Some(rest) = text.strip_prefix('/') {
        format!("node://{node}/{rest}")
    } else {
        format!("node://{node}/{text}")
    }
}

fn write_stdin(bin: &str, prefix: &[String], args: &[&str], body: &[u8]) -> std::process::Output {
    let mut child = command(bin)
        .args(prefix)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(body).unwrap();
    }
    child.wait_with_output().unwrap()
}

fn send(stdin: &mut impl Write, line: &str) {
    writeln!(stdin, "{line}").unwrap();
    stdin.flush().unwrap();
}

fn read_json(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("mcp stdout closed");
    assert!(n > 0, "mcp produced no message");
    serde_json::from_str(line.trim()).unwrap_or_else(|err| {
        panic!("mcp json: {err}\n{line}");
    })
}
