//! Subprocess coverage for the `agentlink` binary: pairing, exec, files, the
//! path jail, transfers, search/replace, watch, background processes, a line
//! PTY, audit verify, agent registration, relay restart, and MCP over stdio
//! and streamable HTTP.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct World {
    _root: tempfile::TempDir,
    bin: &'static str,
    relay_url: String,
    token: String,
    fingerprint: String,
    config_dir: PathBuf,
    base: Vec<String>,
    _relay: Guard,
    _node: Guard,
    jail: PathBuf,
    node_dir: PathBuf,
    name: String,
}

#[test]
fn cli_drives_exec_files_transfers_and_tools() {
    let world = boot("box");
    pairing_is_single_use(&world);
    exec_covers_status_stderr_cwd_and_timeout(&world);
    files_jail_and_names(&world);
    transfers_search_watch_and_processes(&world);
    audit_and_agent_admin(&world);
}

#[test]
fn cli_mcp_stdio_and_streamable_http() {
    let world = boot("mcpbox");
    mcp_stdio(&world);
    mcp_http(&world);
}

#[test]
fn cli_node_reconnects_after_relay_restart() {
    let bin = env!("CARGO_BIN_EXE_agentlink");
    let root = tempfile::tempdir().unwrap();
    let relay_dir = root.path().join("relay");
    let node_dir = root.path().join("node");
    let config_dir = root.path().join("config");
    let mut relay = spawn_relay(bin, &relay_dir);
    let addr = wait_file(&relay_dir.join("listen_addr.txt"));
    let fingerprint = wait_file(&relay_dir.join("fingerprint.txt"));
    let token = wait_file(&relay_dir.join("admin.token"));
    let relay_url = format!("wss://{addr}");
    let base = prefix(&config_dir, &relay_url, &token, &fingerprint);
    let paired = run(bin, &base, &["pair", "--name", "again", "--access", "exec"]);
    assert!(paired.status.success(), "{}", stderr(&paired));
    let pairing: Value = serde_json::from_slice(&paired.stdout).unwrap();
    let node = spawn_node(
        bin,
        &relay_url,
        &fingerprint,
        "again",
        pairing["pairing_token"].as_str().unwrap(),
        &node_dir,
        None,
    );
    wait_online(bin, &base, "again");
    mint_grant(bin, &base, "again", &node_dir);

    drop(relay);
    std::thread::sleep(Duration::from_millis(200));
    relay = restart_relay(bin, &relay_dir, &addr);
    let _ = relay;
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let exec = run(
            bin,
            &base,
            &[
                "exec",
                "again",
                "--timeout-secs",
                "5",
                "--shell",
                "--",
                "echo",
                "reconnected",
            ],
        );
        if exec.status.success() && String::from_utf8_lossy(&exec.stdout).contains("reconnected") {
            break;
        }
        if Instant::now() > deadline {
            panic!("node did not reconnect: {}", stderr(&exec));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    drop(node);
}

fn boot(name: &str) -> World {
    let bin = env!("CARGO_BIN_EXE_agentlink");
    let root = tempfile::tempdir().unwrap();
    let relay_dir = root.path().join("relay");
    let node_dir = root.path().join("node");
    let config_dir = root.path().join("config");
    let jail = root.path().join("jail");
    std::fs::create_dir_all(&jail).unwrap();
    let relay = spawn_relay(bin, &relay_dir);
    let addr = wait_file(&relay_dir.join("listen_addr.txt"));
    let fingerprint = wait_file(&relay_dir.join("fingerprint.txt"));
    let token = wait_file(&relay_dir.join("admin.token"));
    let relay_url = format!("wss://{addr}");
    let base = prefix(&config_dir, &relay_url, &token, &fingerprint);
    let paired = run(bin, &base, &["pair", "--name", name, "--access", "exec"]);
    assert!(paired.status.success(), "{}", stderr(&paired));
    let pairing: Value = serde_json::from_slice(&paired.stdout).unwrap();
    let node = spawn_node(
        bin,
        &relay_url,
        &fingerprint,
        name,
        pairing["pairing_token"].as_str().unwrap(),
        &node_dir,
        Some(&jail),
    );
    // Keep the token around so the single-use check can reuse it.
    std::fs::write(
        root.path().join("pairing.token"),
        pairing["pairing_token"].as_str().unwrap(),
    )
    .unwrap();
    wait_online(bin, &base, name);
    mint_grant(bin, &base, name, &node_dir);
    World {
        _root: root,
        bin,
        relay_url,
        token,
        fingerprint,
        config_dir,
        base,
        _relay: relay,
        _node: node,
        jail,
        node_dir,
        name: name.to_string(),
    }
}

fn pairing_is_single_use(world: &World) {
    let token = std::fs::read_to_string(world._root.path().join("pairing.token")).unwrap();
    let intruder_dir = world._root.path().join("intruder");
    let intruder = spawn_node(
        world.bin,
        &world.relay_url,
        &world.fingerprint,
        "intruder",
        token.trim(),
        &intruder_dir,
        None,
    );
    std::thread::sleep(Duration::from_secs(2));
    let listed = run(world.bin, &world.base, &["ls"]);
    assert!(listed.status.success(), "{}", stderr(&listed));
    let value: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(
        !value["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["name"] == "intruder" && node["online"] == true),
        "a used pairing token enrolled a second node: {value}"
    );
    drop(intruder);
}

fn exec_covers_status_stderr_cwd_and_timeout(world: &World) {
    let code = run(
        world.bin,
        &world.base,
        &["exec", &world.name, "--shell", "--", "exit", "9"],
    );
    assert_eq!(code.status.code(), Some(9), "{}", stderr(&code));

    let shell = if cfg!(windows) {
        "echo out-line& echo err-line 1>&2"
    } else {
        "echo out-line; echo err-line 1>&2"
    };
    let streams = run(
        world.bin,
        &world.base,
        &["exec", &world.name, "--shell", "--", shell],
    );
    assert!(streams.status.success(), "{}", stderr(&streams));
    let streams_json: Value = serde_json::from_slice(&streams.stdout).unwrap();
    assert!(
        streams_json["stdout"]
            .as_str()
            .unwrap_or("")
            .contains("out-line"),
        "{streams_json}"
    );
    assert!(
        streams_json["stderr"]
            .as_str()
            .unwrap_or("")
            .contains("err-line"),
        "{streams_json}"
    );

    let cwd = run(
        world.bin,
        &world.base,
        &[
            "exec",
            &world.name,
            "--cwd",
            world.jail.to_str().unwrap(),
            "--shell",
            "--",
            pwd_line(),
        ],
    );
    assert!(cwd.status.success(), "{}", stderr(&cwd));
    let printed = String::from_utf8_lossy(&cwd.stdout);
    assert!(
        path_mentioned(&printed, &world.jail),
        "cwd {printed} is not {}",
        world.jail.display()
    );

    let escaped = world.jail.parent().unwrap().to_str().unwrap();
    let outside = run(
        world.bin,
        &world.base,
        &[
            "exec",
            &world.name,
            "--cwd",
            escaped,
            "--shell",
            "--",
            pwd_line(),
        ],
    );
    assert!(
        !outside.status.success(),
        "cwd escaped the jail: {}",
        stderr(&outside)
    );

    let slow = if cfg!(windows) {
        "ping -n 20 127.0.0.1"
    } else {
        "sleep 30"
    };
    let timed = run(
        world.bin,
        &world.base,
        &[
            "exec",
            &world.name,
            "--timeout-secs",
            "1",
            "--shell",
            "--",
            slow,
        ],
    );
    assert!(!timed.status.success(), "sleep was not timed out");
    let combined = stderr(&timed);
    assert!(combined.contains("timed out"), "{combined}");
}

fn files_jail_and_names(world: &World) {
    let name = world.name.as_str();
    let nested = world.jail.join("sub").join("empty.txt");
    let made = run(
        world.bin,
        &world.base,
        &[
            "mkdir",
            name,
            world.jail.join("sub").to_str().unwrap(),
            "--parents",
        ],
    );
    assert!(made.status.success(), "{}", stderr(&made));
    let empty = run(
        world.bin,
        &world.base,
        &["write", name, nested.to_str().unwrap(), "--content", ""],
    );
    assert!(empty.status.success(), "{}", stderr(&empty));
    assert!(std::fs::read(&nested).unwrap().is_empty());

    let binary = world.jail.join("bin.dat");
    let bytes = b"\0\xffhello\0".to_vec();
    let wrote = write_stdin(
        world.bin,
        &world.base,
        &["write", name, binary.to_str().unwrap()],
        &bytes,
    );
    assert!(wrote.status.success(), "{}", stderr(&wrote));
    assert_eq!(std::fs::read(&binary).unwrap(), bytes);

    let unicode = world.jail.join("文件-café.txt");
    let wrote = run(
        world.bin,
        &world.base,
        &[
            "write",
            name,
            unicode.to_str().unwrap(),
            "--content",
            "unicode",
        ],
    );
    assert!(wrote.status.success(), "{}", stderr(&wrote));
    let listed = run(
        world.bin,
        &world.base,
        &["ls", name, world.jail.to_str().unwrap()],
    );
    assert!(listed.status.success(), "{}", stderr(&listed));
    let entries: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(entries
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["name"] == "文件-café.txt"));

    let renamed = world.jail.join("renamed.txt");
    let moved = run(
        world.bin,
        &world.base,
        &[
            "mv",
            name,
            unicode.to_str().unwrap(),
            renamed.to_str().unwrap(),
        ],
    );
    assert!(moved.status.success(), "{}", stderr(&moved));
    let removed = run(
        world.bin,
        &world.base,
        &["rm", name, renamed.to_str().unwrap()],
    );
    assert!(removed.status.success(), "{}", stderr(&removed));
    assert!(!renamed.exists());

    let outside = world._root.path().join("outside.txt");
    let denied = run(
        world.bin,
        &world.base,
        &["write", name, outside.to_str().unwrap(), "--content", "no"],
    );
    assert!(!denied.status.success(), "wrote outside the jail");
    assert!(!outside.exists());
    let dotted = world.jail.join("..").join("dotted.txt");
    let denied = run(
        world.bin,
        &world.base,
        &["write", name, dotted.to_str().unwrap(), "--content", "no"],
    );
    assert!(!denied.status.success(), "wrote through ..");

    #[cfg(unix)]
    {
        let link = world.jail.join("escape-link");
        let target = world._root.path().join("linked-outside");
        std::fs::create_dir_all(&target).unwrap();
        if std::os::unix::fs::symlink(&target, &link).is_ok() {
            let pwned = link.join("pwned.txt");
            let denied = run(
                world.bin,
                &world.base,
                &["write", name, pwned.to_str().unwrap(), "--content", "no"],
            );
            assert!(!denied.status.success(), "wrote through a symlink");
            assert!(!target.join("pwned.txt").exists());
        }
        if world.jail.starts_with("/var") || world.jail.starts_with("/private/var") {
            let marker = world.jail.join("var-alias.txt");
            let alias = swap_var_prefix(&marker);
            let wrote = run(
                world.bin,
                &world.base,
                &["write", name, alias.to_str().unwrap(), "--content", "alias"],
            );
            assert!(
                wrote.status.success(),
                "macOS /var alias: {}",
                stderr(&wrote)
            );
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "alias");
        }
    }
    #[cfg(windows)]
    {
        for path in [r"C:\Windows\win.ini", r"\\?\C:\Windows\win.ini"] {
            let denied = run(
                world.bin,
                &world.base,
                &["write", name, path, "--content", "no"],
            );
            assert!(
                !denied.status.success(),
                "windows path was not jailed: {path}"
            );
        }
    }
}

fn transfers_search_watch_and_processes(world: &World) {
    let name = world.name.as_str();
    let local = world._root.path().join("payload.bin");
    let body = vec![0x3Cu8; 256 * 1024];
    std::fs::write(&local, &body).unwrap();
    let remote = world.jail.join("payload.bin");
    let first = cp(
        world,
        &local,
        &remote,
        &["--no-direct", "--compress", "off"],
    );
    assert_eq!(first["stats"]["skipped"], false, "{first}");
    assert_eq!(first["stats"]["transport"], "relay");
    assert_eq!(first["stats"]["compressed"], false);
    assert_eq!(std::fs::read(&remote).unwrap(), body);
    let second = cp(
        world,
        &local,
        &remote,
        &["--no-direct", "--compress", "off"],
    );
    assert_eq!(second["stats"]["skipped"], true, "{second}");

    let text = world._root.path().join("repeat.txt");
    std::fs::write(&text, "abcdef".repeat(20_000)).unwrap();
    let on = world.jail.join("repeat-on.txt");
    let off = world.jail.join("repeat-off.txt");
    let compressed = cp(world, &text, &on, &["--no-direct", "--compress", "on"]);
    let plain = cp(world, &text, &off, &["--no-direct", "--compress", "off"]);
    assert_eq!(compressed["stats"]["compressed"], true, "{compressed}");
    assert!(
        compressed["stats"]["payload_bytes"].as_u64().unwrap()
            < compressed["stats"]["logical_bytes"].as_u64().unwrap()
    );
    assert_eq!(plain["stats"]["compressed"], false, "{plain}");
    assert_eq!(
        plain["stats"]["payload_bytes"],
        plain["stats"]["logical_bytes"]
    );

    let direct_local = world._root.path().join("direct.bin");
    std::fs::write(&direct_local, b"direct-bytes").unwrap();
    let direct_remote = world.jail.join("direct.bin");
    let direct = cp(world, &direct_local, &direct_remote, &[]);
    assert_eq!(direct["stats"]["transport"], "relay", "{direct}");
    assert_eq!(
        std::fs::read(&direct_remote).unwrap(),
        b"direct-bytes"
    );

    let tree = world._root.path().join("tree");
    std::fs::create_dir_all(tree.join("子")).unwrap();
    std::fs::write(tree.join("子").join("empty"), b"").unwrap();
    std::fs::write(tree.join("a.txt"), b"aaa").unwrap();
    let remote_tree = world.jail.join("tree-copy");
    let copied = cp(world, &tree, &remote_tree, &["--no-direct"]);
    assert!(copied["stats"]["files"].as_u64().unwrap() >= 2, "{copied}");
    assert_eq!(std::fs::read(remote_tree.join("a.txt")).unwrap(), b"aaa");
    assert!(std::fs::read(remote_tree.join("子").join("empty"))
        .unwrap()
        .is_empty());

    let left = world._root.path().join("left.bin");
    let right = world._root.path().join("right.bin");
    std::fs::write(&left, vec![1u8; 32 * 1024]).unwrap();
    std::fs::write(&right, vec![2u8; 32 * 1024]).unwrap();
    let left_r = world.jail.join("left.bin");
    let right_r = world.jail.join("right.bin");
    let left_cfg = world._root.path().join("cfg-left");
    let right_cfg = world._root.path().join("cfg-right");
    std::fs::create_dir_all(&left_cfg).unwrap();
    std::fs::create_dir_all(&right_cfg).unwrap();
    // Separate config dirs mean separate identities, so each needs its own grant.
    let left_base = with_config(&world.base, &left_cfg);
    let right_base = with_config(&world.base, &right_cfg);
    mint_grant(world.bin, &left_base, name, &world.node_dir);
    mint_grant(world.bin, &right_base, name, &world.node_dir);
    let mut a = Command::new(world.bin)
        .args(&left_base)
        .args([
            "cp",
            "--no-direct",
            left.to_str().unwrap(),
            &node_url(name, &left_r),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut b = Command::new(world.bin)
        .args(&right_base)
        .args([
            "cp",
            "--no-direct",
            right.to_str().unwrap(),
            &node_url(name, &right_r),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let a_status = wait_child(&mut a, 20).expect("concurrent copy of left.bin hung");
    let b_status = wait_child(&mut b, 20).expect("concurrent copy of right.bin hung");
    assert!(a_status.success(), "left copy status {a_status}");
    assert!(b_status.success(), "right copy status {b_status}");
    assert_eq!(
        std::fs::read(&left_r).unwrap(),
        std::fs::read(&left).unwrap()
    );
    assert_eq!(
        std::fs::read(&right_r).unwrap(),
        std::fs::read(&right).unwrap()
    );

    let note = world.jail.join("note.txt");
    std::fs::write(&note, "one one\nsecond\n").unwrap();
    let conflict = run(
        world.bin,
        &world.base,
        &["replace", name, note.to_str().unwrap(), "one", "two"],
    );
    assert!(!conflict.status.success(), "non-unique replace succeeded");
    assert_eq!(std::fs::read_to_string(&note).unwrap(), "one one\nsecond\n");
    let replaced = run(
        world.bin,
        &world.base,
        &[
            "replace",
            name,
            note.to_str().unwrap(),
            "one",
            "two",
            "--all",
        ],
    );
    assert!(replaced.status.success(), "{}", stderr(&replaced));
    assert_eq!(std::fs::read_to_string(&note).unwrap(), "two two\nsecond\n");

    let watched = world.jail.join("watched");
    std::fs::create_dir_all(&watched).unwrap();
    let watch = Command::new(world.bin)
        .args(&world.base)
        .args([
            "watch",
            name,
            watched.to_str().unwrap(),
            "--no-recursive",
            "--timeout-secs",
            "8",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(400));
    std::fs::write(watched.join("created.txt"), b"hi").unwrap();
    let finished = watch.wait_with_output().unwrap();
    assert!(finished.status.success(), "{}", stderr(&finished));
    let events: Value = serde_json::from_slice(&finished.stdout).unwrap();
    assert!(
        events["events"].to_string().contains("created.txt"),
        "{events}"
    );

    let sleep = if cfg!(windows) {
        "ping -n 30 127.0.0.1"
    } else {
        "sleep 30"
    };
    let started = run(
        world.bin,
        &world.base,
        &["bg", name, "start", "--shell", "--", sleep],
    );
    assert!(started.status.success(), "{}", stderr(&started));
    let started: Value = serde_json::from_slice(&started.stdout).unwrap();
    let id = started["id"].as_str().unwrap();
    let status = run(world.bin, &world.base, &["bg", name, "status", id]);
    assert!(status.status.success(), "{}", stderr(&status));
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["running"], true, "{status}");
    let killed = run(world.bin, &world.base, &["bg", name, "kill", id]);
    assert!(killed.status.success(), "{}", stderr(&killed));
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let status = run(world.bin, &world.base, &["bg", name, "status", id]);
        let value: Value = serde_json::from_slice(&status.stdout).unwrap_or(Value::Null);
        if value["running"] == false {
            break;
        }
        if Instant::now() > deadline {
            panic!("background process stayed up: {value}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let shell_line = if cfg!(windows) {
        "echo pty-line"
    } else {
        "echo pty-line"
    };
    let pty = run(
        world.bin,
        &world.base,
        &["shell", name, "--line", "--command", shell_line],
    );
    assert!(pty.status.success(), "{}", stderr(&pty));
    assert!(
        String::from_utf8_lossy(&pty.stdout).contains("pty-line"),
        "{}",
        stderr(&pty)
    );

    let info = run(world.bin, &world.base, &["sysinfo", name]);
    assert!(info.status.success(), "{}", stderr(&info));
    let info: Value = serde_json::from_slice(&info.stdout).unwrap();
    assert!(info["cpu"]["count"].as_u64().unwrap_or(0) > 0, "{info}");
    assert!(
        info["memory"]["total_bytes"].as_u64().unwrap_or(0) > 0,
        "{info}"
    );
}

fn audit_and_agent_admin(world: &World) {
    let queried = run(
        world.bin,
        &world.base,
        &[
            "audit",
            "query",
            "--sink",
            "local",
            "--data-dir",
            world.node_dir.to_str().unwrap(),
            "--verify",
        ],
    );
    assert!(queried.status.success(), "{}", stderr(&queried));
    let body: Value = serde_json::from_slice(&queried.stdout).unwrap();
    assert_eq!(body["verified"], true, "{body}");
    assert!(
        !body["records"].as_array().unwrap().is_empty(),
        "audit log was empty: {body}"
    );

    let key = world._root.path().join("bot.identity.json");
    let created = run(
        world.bin,
        &world.base,
        &["client", "create", "bot", "--out", key.to_str().unwrap()],
    );
    assert!(created.status.success(), "{}", stderr(&created));
    let created: Value = serde_json::from_slice(&created.stdout).unwrap();
    let id = created["id"].as_str().unwrap();
    let granted = run(
        world.bin,
        &world.base,
        &["client", "grant", id, &world.name, "read-only"],
    );
    assert!(granted.status.success(), "{}", stderr(&granted));
    let listed = run(world.bin, &world.base, &["client", "list"]);
    assert!(listed.status.success(), "{}", stderr(&listed));
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(listed["clients"]
        .as_array()
        .unwrap()
        .iter()
        .any(|client| client["id"] == id && client["revoked"] == false));
    let revoked = run(world.bin, &world.base, &["client", "revoke", id]);
    assert!(revoked.status.success(), "{}", stderr(&revoked));
    let listed = run(world.bin, &world.base, &["client", "list"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(listed["clients"]
        .as_array()
        .unwrap()
        .iter()
        .any(|client| client["id"] == id && client["revoked"] == true));
}

fn mcp_stdio(world: &World) {
    let mut child = Command::new(world.bin)
        .args(["--config-dir", world.config_dir.to_str().unwrap(), "mcp"])
        .env("AGENTLINK_RELAY", &world.relay_url)
        .env("AGENTLINK_TOKEN", &world.token)
        .env("AGENTLINK_FINGERPRINT", &world.fingerprint)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let framed = content_length(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fn","version":"0"}}}"#,
    );
    stdin.write_all(framed.as_bytes()).unwrap();
    stdin.flush().unwrap();
    let init = read_json(&mut reader);
    assert_eq!(init["result"]["serverInfo"]["name"], "agentlink");
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    let path = world.jail.join("mcp-stat.txt");
    std::fs::write(&path, b"stat-me").unwrap();
    let path_json = serde_json::to_string(&path.to_string_lossy().to_string()).unwrap();
    send(
        &mut stdin,
        &format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"stat_path","arguments":{{"node":"{}","path":{path_json}}}}}}}"#,
            world.name
        ),
    );
    let stat = read_json(&mut reader);
    assert_eq!(stat["result"]["isError"], false, "{stat}");
    let body: Value =
        serde_json::from_str(stat["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body["size"], 7);
    assert_eq!(body["is_file"], true);
    let _ = child.kill();
    let _ = child.wait();
}

fn mcp_http(world: &World) {
    let log = world._root.path().join("mcp.err");
    let err = std::fs::File::create(&log).unwrap();
    let child = Guard(
        Command::new(world.bin)
            .args([
                "--config-dir",
                world.config_dir.to_str().unwrap(),
                "--relay",
                &world.relay_url,
                "--token",
                &world.token,
                "--fingerprint",
                &world.fingerprint,
                "mcp",
                "--http",
                "127.0.0.1:0",
                "--mcp-token",
                "http-secret",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap(),
    );
    let line = wait_line(&log, "mcp http listening on ");
    let url = line
        .split_whitespace()
        .find(|part| part.starts_with("http://"))
        .unwrap();
    let addr = url.trim_start_matches("http://").trim_end_matches("/mcp");
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"http","version":"0"}}}"#;
    let denied = http(addr, "POST", "/mcp", None, None, init.as_bytes());
    assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");
    let origin = http(
        addr,
        "POST",
        "/mcp",
        Some("http-secret"),
        Some("https://evil.example"),
        init.as_bytes(),
    );
    assert!(origin.starts_with("HTTP/1.1 403"), "{origin}");
    let missing = http(
        addr,
        "POST",
        "/nope",
        Some("http-secret"),
        None,
        init.as_bytes(),
    );
    assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
    let ok = http(
        addr,
        "POST",
        "/mcp",
        Some("http-secret"),
        None,
        init.as_bytes(),
    );
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    let session = header_value(&ok, "Mcp-Session-Id").expect("session id");
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"list_machines","arguments":{{}}}}}}"#
    );
    let listed = http_session(
        addr,
        "POST",
        "/mcp",
        Some("http-secret"),
        Some(&session),
        call.as_bytes(),
        None,
    );
    assert!(listed.contains("200"), "{listed}");
    assert!(listed.contains(&world.name), "{listed}");
    let stream = http(addr, "GET", "/mcp", Some("http-secret"), None, b"");
    assert!(stream.contains("text/event-stream"), "{stream}");
    assert!(
        stream.contains("keepalive") || stream.contains("Mcp-Session-Id"),
        "{stream}"
    );
    let deleted = http_session(
        addr,
        "DELETE",
        "/mcp",
        Some("http-secret"),
        Some(&session),
        b"",
        None,
    );
    assert!(deleted.starts_with("HTTP/1.1 204"), "{deleted}");
    drop(child);
}

fn cp(world: &World, local: &Path, remote: &Path, extra: &[&str]) -> Value {
    let mut args = vec!["cp"];
    args.extend_from_slice(extra);
    args.push(local.to_str().unwrap());
    let url = node_url(&world.name, remote);
    args.push(&url);
    let out = run(world.bin, &world.base, &args);
    assert!(out.status.success(), "{}", stderr(&out));
    serde_json::from_str(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .rev()
            .find(|line| line.contains("\"done\""))
            .unwrap_or(""),
    )
    .unwrap_or_else(|err| panic!("{err}: {}", stderr(&out)))
}

fn with_config(base: &[String], dir: &Path) -> Vec<String> {
    let mut out = base.to_vec();
    if let Some(pos) = out.iter().position(|arg| arg == "--config-dir") {
        out[pos + 1] = dir.to_str().unwrap().to_string();
    }
    out
}

fn prefix(config: &Path, relay: &str, token: &str, fingerprint: &str) -> Vec<String> {
    vec![
        "--config-dir".into(),
        config.to_str().unwrap().into(),
        "--relay".into(),
        relay.into(),
        "--token".into(),
        token.into(),
        "--fingerprint".into(),
        fingerprint.into(),
        "--json".into(),
    ]
}

fn spawn_relay(bin: &str, data_dir: &Path) -> Guard {
    std::fs::create_dir_all(data_dir).ok();
    Guard(
        Command::new(bin)
            .env("AGENTLINK_LEGACY_ADMIN", "1")
            .env("AGENTLINK_LEGACY_ADMIN_TTL_SECS", "86400")
            .args([
                "relay",
                "--bind",
                "127.0.0.1:0",
                "--data-dir",
                data_dir.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn restart_relay(bin: &str, data_dir: &Path, addr: &str) -> Guard {
    for _ in 0..20 {
        let mut child = Guard(
            Command::new(bin)
                .env("AGENTLINK_LEGACY_ADMIN", "1")
                .env("AGENTLINK_LEGACY_ADMIN_TTL_SECS", "86400")
                .args([
                    "relay",
                    "--bind",
                    addr,
                    "--data-dir",
                    data_dir.to_str().unwrap(),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        std::thread::sleep(Duration::from_millis(250));
        if child_alive(&mut child.0) {
            return child;
        }
    }
    panic!("relay did not rebind {addr}");
}

fn wait_child(child: &mut Child, secs: u64) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn child_alive(child: &mut Child) -> bool {
    matches!(child.try_wait(), Ok(None))
}

fn spawn_node(
    bin: &str,
    relay: &str,
    fingerprint: &str,
    name: &str,
    token: &str,
    data_dir: &Path,
    root: Option<&Path>,
) -> Guard {
    let mut args = vec![
        "--relay".to_string(),
        relay.to_string(),
        "--fingerprint".to_string(),
        fingerprint.to_string(),
        "node".into(),
        "--name".into(),
        name.into(),
        "--pairing-token".into(),
        token.into(),
        "--data-dir".into(),
        data_dir.to_str().unwrap().into(),
        "--audit-preset".into(),
        "full".into(),
    ];
    if let Some(root) = root {
        args.push("--root".into());
        args.push(root.to_str().unwrap().into());
    }
    Guard(
        Command::new(bin)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn run(bin: &str, prefix: &[String], args: &[&str]) -> Output {
    Command::new(bin).args(prefix).args(args).output().unwrap()
}

/// Nodes bootstrap `owner-keys.json`, so CLI ops need a grant in the client
/// config dir. Sign with the node's own `grant-issuer.json`.
fn mint_grant(bin: &str, base: &[String], name: &str, node_dir: &Path) {
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
        "could not mint an E2E grant: {}",
        stderr(&out)
    );
}

fn write_stdin(bin: &str, prefix: &[String], args: &[&str], body: &[u8]) -> Output {
    let mut child = Command::new(bin)
        .args(prefix)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(body).unwrap();
    child.wait_with_output().unwrap()
}

fn stderr(output: &Output) -> String {
    format!(
        "status {:?}\nstdout {}\nstderr {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn wait_file(path: &Path) -> String {
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
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn wait_line(path: &Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Some(line) = text.lines().find(|line| line.contains(needle)) {
                return line.to_string();
            }
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {needle}");
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn wait_online(bin: &str, base: &[String], name: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let out = run(bin, base, &["ls"]);
        if out.status.success() {
            if let Ok(value) = serde_json::from_slice::<Value>(&out.stdout) {
                let online = value["nodes"].as_array().is_some_and(|nodes| {
                    nodes
                        .iter()
                        .any(|node| node["name"] == name && node["online"] == true)
                });
                if online {
                    return;
                }
            }
        }
        if Instant::now() > deadline {
            panic!("node {name} did not come online: {}", stderr(&out));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn node_url(node: &str, path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    if let Some(rest) = text.strip_prefix('/') {
        format!("node://{node}/{rest}")
    } else {
        format!("node://{node}/{text}")
    }
}

fn pwd_line() -> &'static str {
    if cfg!(windows) {
        "cd"
    } else {
        "pwd"
    }
}

fn path_mentioned(printed: &str, path: &Path) -> bool {
    let raw = path.to_string_lossy().to_string();
    if printed.contains(&raw) {
        return true;
    }
    if let Ok(canon) = path.canonicalize() {
        if printed.contains(&canon.to_string_lossy().to_string()) {
            return true;
        }
    }
    #[cfg(unix)]
    {
        let alias = swap_var_prefix(path);
        if printed.contains(&alias.to_string_lossy().to_string()) {
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn swap_var_prefix(path: &Path) -> PathBuf {
    let text = path.to_string_lossy().to_string();
    if let Some(rest) = text.strip_prefix("/private/var") {
        PathBuf::from(format!("/var{rest}"))
    } else if let Some(rest) = text.strip_prefix("/var") {
        PathBuf::from(format!("/private/var{rest}"))
    } else {
        path.to_path_buf()
    }
}

fn content_length(body: &str) -> String {
    format!("Content-Length: {}\r\n\r\n{body}", body.len())
}

fn send(stdin: &mut impl Write, line: &str) {
    writeln!(stdin, "{line}").unwrap();
    stdin.flush().unwrap();
}

fn read_json(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("mcp stdout closed");
    assert!(n > 0, "mcp produced no message");
    serde_json::from_str(line.trim()).unwrap_or_else(|err| panic!("mcp json: {err}\n{line}"))
}

fn http(
    addr: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    origin: Option<&str>,
    body: &[u8],
) -> String {
    http_session(addr, method, path, token, None, body, origin)
}

fn http_session(
    addr: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    session: Option<&str>,
    body: &[u8],
    origin: Option<&str>,
) -> String {
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(token) = token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(origin) = origin {
        head.push_str(&format!("Origin: {origin}\r\n"));
    }
    if let Some(session) = session {
        head.push_str(&format!("Mcp-Session-Id: {session}\r\n"));
    }
    head.push_str("\r\n");
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(18);
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                let text = String::from_utf8_lossy(&buf);
                if text.contains(": keepalive") {
                    break;
                }
                if response_complete(&text, buf.len()) {
                    break;
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                if Instant::now() > deadline {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn response_complete(text: &str, total: usize) -> bool {
    let Some(header_end) = text.find("\r\n\r\n") else {
        return false;
    };
    if text.contains("text/event-stream") {
        return false;
    }
    let length = text[..header_end]
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    total >= header_end + 4 + length
}

fn header_value(response: &str, name: &str) -> Option<String> {
    let want = name.to_ascii_lowercase();
    response.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.eq_ignore_ascii_case(&want) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}
