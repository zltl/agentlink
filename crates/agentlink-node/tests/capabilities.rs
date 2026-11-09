//! Search, edit, watch, background processes, sysinfo, and audit records.

use std::time::{Duration, Instant};

use agentlink_core::{Client, ClientSettings, ExecRequest, NodePolicy};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_capabilities_are_audited() {
    let result = tokio::time::timeout(Duration::from_secs(120), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("capabilities test timed out"),
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
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let node_dir = dir.path().join("node");
    std::fs::create_dir_all(&node_dir)?;
    let policy = agentlink_core::audit::AuditPolicy::preset("full")?;
    std::fs::write(node_dir.join("audit.toml"), policy.to_toml()?)?;
    let shutdown = CancellationToken::new();
    let node_task = tokio::spawn(run(
        NodeConfig {
            relay_url: relay_url.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: node_dir.clone(),
            name: "box".into(),
            pairing_token: Some(pairing.token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        shutdown.clone(),
    ));
    wait_online(&admin, "box").await;
    let box_id = admin
        .list_nodes()
        .await?
        .into_iter()
        .find(|node| node.name == "box")
        .unwrap()
        .id;
    admin.install_local_grant(&node_dir, &box_id)?;

    let tree = dir.path().join("tree");
    std::fs::create_dir(&tree)?;
    std::fs::write(tree.join("hello.txt"), "alpha-needle\nsecond\n")?;
    std::fs::write(tree.join(".gitignore"), "secret.txt\n")?;
    std::fs::write(tree.join("secret.txt"), "alpha-needle\n")?;
    let tree_s = tree.to_string_lossy().to_string();

    let found = admin
        .search(
            "box",
            &tree_s,
            "alpha-needle",
            true,
            Vec::new(),
            Vec::new(),
            true,
            false,
            false,
            0,
            0,
            0,
            20,
        )
        .await?;
    let matches = found["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1, "{found}");
    assert!(matches[0]["path"].as_str().unwrap().contains("hello.txt"));

    let names = admin
        .find("box", &tree_s, "*.txt", false, true, false, false, 0, 50)
        .await?;
    let paths: Vec<_> = names["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["path"].as_str())
        .collect();
    assert!(
        paths.iter().any(|path| path.ends_with("hello.txt")),
        "{names}"
    );
    assert!(
        paths.iter().all(|path| !path.ends_with("secret.txt")),
        "{names}"
    );

    let replaced = admin
        .replace(
            "box",
            &tree.join("hello.txt").to_string_lossy(),
            "alpha-needle",
            "beta-needle",
            false,
        )
        .await?;
    assert_eq!(replaced["replacements"], 1);
    let edited = admin
        .edit_lines(
            "box",
            &tree.join("hello.txt").to_string_lossy(),
            2,
            2,
            "third\n",
        )
        .await?;
    assert!(edited["path"].as_str().unwrap().contains("hello.txt"));
    let body = std::fs::read_to_string(tree.join("hello.txt"))?;
    assert!(body.contains("beta-needle"), "{body}");
    assert!(body.contains("third"), "{body}");

    let after = body.replacen("beta-needle", "gamma-needle", 1);
    let mut diff = diffy::DiffOptions::new();
    diff.set_original_filename("a/hello.txt");
    diff.set_modified_filename("b/hello.txt");
    let patch = diff.create_patch(&body, &after).to_string();
    let applied = admin.apply_patch("box", &tree_s, &patch).await?;
    assert!(applied["files"].as_array().unwrap().len() >= 1, "{applied}");
    let body = std::fs::read_to_string(tree.join("hello.txt"))?;
    assert!(body.contains("gamma-needle"), "{body}");

    let watch = admin.watch_start("box", &tree_s, true).await?;
    let watch_id = watch["watch_id"].as_str().unwrap().to_string();
    std::fs::write(tree.join("created.txt"), "new\n")?;
    let mut saw = false;
    for _ in 0..10 {
        let polled = admin.watch_poll("box", &watch_id, 0, 500, 50).await?;
        if polled["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event.to_string().contains("created.txt"))
        {
            saw = true;
            break;
        }
    }
    admin.watch_stop("box", &watch_id).await?;
    assert!(saw, "watch did not report created.txt");

    let bg = admin
        .bg_start(
            "box",
            "echo bg-ok",
            Vec::new(),
            None,
            Vec::new(),
            true,
            None,
        )
        .await?;
    let id = bg["id"].as_str().unwrap().to_string();
    let mut output = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let chunk = admin.bg_output("box", &id, 0, 0, 65_536).await?;
        output = chunk["stdout"]["text"].as_str().unwrap_or("").to_string();
        if output.contains("bg-ok") || chunk["running"] == false {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(output.contains("bg-ok"), "{output}");
    let _ = admin.bg_kill("box", &id).await;

    let info = admin.sysinfo("box").await?;
    assert!(info["cpu"]["count"].as_u64().unwrap_or(0) > 0, "{info}");
    assert!(
        info["memory"]["total_bytes"].as_u64().unwrap_or(0) > 0,
        "{info}"
    );
    assert!(
        info["env"]["PATH"].is_string() || info["env"]["Path"].is_string(),
        "{info}"
    );

    let ro = admin
        .create_pairing_token("reader", NodePolicy::read_only(), 600)
        .await?;
    let ro_shutdown = CancellationToken::new();
    let ro_task = tokio::spawn(run(
        NodeConfig {
            relay_url,
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: dir.path().join("reader"),
            name: "reader".into(),
            pairing_token: Some(ro.token),
            root: None,
            max_policy: NodePolicy::read_only(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        ro_shutdown.clone(),
    ));
    wait_online(&admin, "reader").await;
    let reader_id = admin
        .list_nodes()
        .await?
        .into_iter()
        .find(|node| node.name == "reader")
        .unwrap()
        .id;
    admin.install_local_grant(dir.path().join("reader").as_path(), &reader_id)?;
    // A local grant cannot raise this node's --max-access ceiling.
    let write = admin
        .replace(
            "reader",
            &tree.join("hello.txt").to_string_lossy(),
            "gamma-needle",
            "nope",
            false,
        )
        .await;
    let write_err = write.expect_err("read-only ceiling must refuse a write").to_string();
    assert!(
        write_err.contains("not allowed") && write_err.contains("read-only"),
        "{write_err}"
    );
    let started = admin
        .bg_start(
            "reader",
            "echo no",
            Vec::new(),
            None,
            Vec::new(),
            true,
            None,
        )
        .await;
    let exec_err = started.expect_err("read-only ceiling must refuse exec").to_string();
    assert!(
        exec_err.contains("not allowed") && exec_err.contains("read-only"),
        "{exec_err}"
    );

    kill_grandchild(&admin, &dir.path().join("leak")).await?;

    let mut session = admin
        .open_pty("box", Some("echo pty-audit".into()), None, 24, 80)
        .await?;
    let _ = tokio::time::timeout(Duration::from_secs(10), session.recv()).await;
    drop(session);

    let logs = node_dir.join("audit").join("logs");
    let deadline = Instant::now() + Duration::from_secs(10);
    let audit = loop {
        let text = read_audit_tree(&node_dir);
        if text.contains("\"op\":\"pty_session\"") && text.contains("pty-audit") {
            break text;
        }
        if Instant::now() > deadline {
            panic!("pty_session audit missing:\n{text}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let _ = logs;
    for op in [
        "search",
        "replace",
        "edit_lines",
        "apply_patch",
        "watch_start",
        "bg_start",
        "sys_info",
        "pty_open",
    ] {
        assert!(
            audit.contains(&format!("\"op\":\"{op}\"")),
            "missing {op}\n{audit}"
        );
    }
    assert!(audit.contains("before_hash"), "{audit}");
    assert!(audit.contains("\"node_name\":\"box\""), "{audit}");
    assert!(
        audit.contains("gamma-needle") || audit.contains("+gamma"),
        "{audit}"
    );
    let pty = audit
        .lines()
        .find(|line| line.contains("\"op\":\"pty_session\""))
        .unwrap_or("");
    assert!(pty.contains("pty-audit"), "{pty}");
    assert!(
        pty.contains("output"),
        "pty session audit should keep capped output: {pty}"
    );
    let search = audit
        .lines()
        .find(|line| line.contains("\"op\":\"search\""))
        .expect("search audit");
    let search: serde_json::Value = serde_json::from_str(search).unwrap();
    let agent = search["client_id"].as_str().unwrap_or("");
    assert_eq!(agent.len(), 64, "{search}");
    assert!(agent.chars().all(|c| c.is_ascii_hexdigit()), "{agent}");
    assert_ne!(agent, "cli");
    assert_ne!(agent, "mcp");

    shutdown.cancel();
    ro_shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), node_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), ro_task).await;
    Ok(())
}

async fn kill_grandchild(admin: &Client, dir: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let started = dir.join("started");
    let leaked = dir.join("leaked");
    let script = grandchild_script(&started, &leaked);
    let err = admin
        .exec_collect(
            "box",
            ExecRequest::shell(script, Some(Duration::from_millis(1500))),
            None,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("timed out"), "{err}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !started.exists() {
        if Instant::now() > deadline {
            anyhow::bail!("grandchild never wrote {}", started.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        !leaked.exists(),
        "grandchild kept running after exec timeout"
    );
    Ok(())
}

fn grandchild_script(started: &std::path::Path, leaked: &std::path::Path) -> String {
    #[cfg(unix)]
    {
        format!(
            "(echo started > '{}'; sleep 3; echo leaked > '{}') & sleep 30",
            started.display(),
            leaked.display()
        )
    }
    #[cfg(windows)]
    {
        let child = started.parent().unwrap().join("child.bat");
        let parent = started.parent().unwrap().join("parent.bat");
        std::fs::write(
            &child,
            format!(
                "@echo off\r\necho started> \"{}\"\r\nping -n 6 127.0.0.1 >NUL\r\necho leaked> \"{}\"\r\n",
                started.display(),
                leaked.display()
            ),
        )
        .unwrap();
        std::fs::write(
            &parent,
            format!(
                "@echo off\r\nstart \"\" /b cmd /c \"{}\"\r\nping -n 30 127.0.0.1 >NUL\r\n",
                child.display()
            ),
        )
        .unwrap();
        parent.display().to_string()
    }
}

fn read_audit_tree(node_dir: &std::path::Path) -> String {
    let mut out = String::new();
    for sub in ["logs", "blobs"] {
        let Ok(entries) = std::fs::read_dir(node_dir.join("audit").join(sub)) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                out.push_str(&text);
                out.push('\n');
            }
        }
    }
    out
}

async fn wait_online(client: &Client, name: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|node| node.name == name && node.online))
            .unwrap_or(false)
        {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {name}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
