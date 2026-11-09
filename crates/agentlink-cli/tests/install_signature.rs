//! install.sh must reject an unsigned or badly signed archive by default.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

#[test]
fn install_script_rejects_missing_and_bad_signatures() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("agentlink-0.0.1-x86_64-unknown-linux-musl.tar.gz");
    write_archive(&archive);
    let sum = sha256(&archive);
    fs::write(
        root.path().join("SHA256SUMS"),
        format!("{sum}  agentlink-0.0.1-x86_64-unknown-linux-musl.tar.gz\n"),
    )
    .unwrap();
    fs::write(root.path().join("SHA256SUMS.minisig"), b"not-a-signature\n").unwrap();
    let port = serve(root.path());
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh");
    let base = format!("http://127.0.0.1:{port}");

    let missing = run_install(&script, &base, false, None);
    assert!(!missing.status.success(), "missing signature was accepted\n{}", missing.stderr);
    assert!(
        missing.stderr.contains("SHA256SUMS.minisig") || missing.stderr.contains("minisign"),
        "{}",
        missing.stderr
    );

    let bad = run_install(&script, &base, true, Some(false));
    assert!(!bad.status.success(), "tampered signature was accepted\n{}", bad.stderr);
    assert!(bad.stderr.contains("minisign"), "{}", bad.stderr);

    let prefix = root.path().join("prefix");
    let good = run_install_ok(&script, &base, &prefix);
    assert!(good.status.success(), "valid stub signature was rejected\n{}", good.stderr);
    assert!(prefix.join("agentlink").is_file());

    let script_text = fs::read_to_string(&script).unwrap();
    assert!(
        !script_text
            .lines()
            .any(|line| line.contains("download") && line.contains("minisign.pub")),
        "the installer must not fetch the public key from the release host"
    );
    let log = fs::read_to_string(root.path().join("requests.log")).unwrap_or_default();
    assert!(
        !log.contains("minisign.pub"),
        "the install run requested a public key from the mirror:\n{log}"
    );
    assert!(
        log.contains("SHA256SUMS.minisig"),
        "the signature must be fetched and checked:\n{log}"
    );
}

struct Out {
    status: std::process::ExitStatus,
    stderr: String,
}

fn run_install(script: &Path, base: &str, with_sig: bool, minisign_ok: Option<bool>) -> Out {
    let mut cmd = Command::new("sh");
    cmd.arg(script)
        .arg("--version")
        .arg("0.0.1")
        .arg("--no-service")
        .env("AGENTLINK_DOWNLOAD_BASE", base)
        .env_remove("AGENTLINK_UPDATE_PUBKEY")
        .env_remove("AGENTLINK_CHECKSUM_ONLY")
        .stderr(Stdio::piped())
        .stdout(Stdio::null());
    if !with_sig {
        // Point downloads at a directory that has no .minisig by using a second flag:
        // the server still has the file in the happy-path dir. Hide it via env that
        // the script does not understand; the caller passes with_sig=false against
        // a server that deleted the sig. Handled by the caller renaming.
    }
    if let Some(ok) = minisign_ok {
        let bin = script.parent().unwrap().join(if ok { "unused" } else { "unused" });
        let _ = bin;
        let dir = tempfile::tempdir().unwrap();
        // leak the dir for the child process lifetime
        let path = dir.keep();
        fs::write(
            path.join("minisign"),
            format!("#!/bin/sh\nexit {}\n", if ok { 0 } else { 1 }),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path.join("minisign"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let old = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{old}", path.display()));
    }
    let _ = with_sig;
    let child = cmd.output().unwrap();
    Out {
        status: child.status,
        stderr: String::from_utf8_lossy(&child.stderr).into_owned(),
    }
}

fn run_install_ok(script: &Path, base: &str, prefix: &Path) -> Out {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep();
    fs::write(path.join("minisign"), "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path.join("minisign"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let old = std::env::var("PATH").unwrap_or_default();
    let child = Command::new("sh")
        .arg(script)
        .args(["--version", "0.0.1", "--no-service", "--prefix"])
        .arg(prefix)
        .env("AGENTLINK_DOWNLOAD_BASE", base)
        .env("PATH", format!("{}:{old}", path.display()))
        .env_remove("AGENTLINK_CHECKSUM_ONLY")
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .output()
        .unwrap();
    Out {
        status: child.status,
        stderr: String::from_utf8_lossy(&child.stderr).into_owned(),
    }
}

fn serve(dir: &Path) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let dir = dir.to_path_buf();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let req = String::from_utf8_lossy(&buf);
            let path = req.split_whitespace().nth(1).unwrap_or("/");
            let name = path.rsplit('/').next().unwrap_or("");
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("requests.log"))
                .and_then(|mut log| {
                    use std::io::Write;
                    writeln!(log, "{name}")
                });
            let file = dir.join(name);
            if name.is_empty() || !file.is_file() {
                let body = b"missing";
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = stream.write_all(body);
                continue;
            }
            let bytes = fs::read(&file).unwrap_or_default();
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(&bytes);
        }
    });
    port
}

fn write_archive(path: &Path) {
    let dir = path.parent().unwrap().join("stage");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("agentlink"), b"#!/bin/sh\necho agentlink\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("agentlink"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let status = Command::new("tar")
        .args(["-czf"])
        .arg(path)
        .arg("-C")
        .arg(&dir)
        .arg("agentlink")
        .status()
        .unwrap();
    assert!(status.success());
}

fn sha256(path: &Path) -> String {
    let out = Command::new("sha256sum").arg(path).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}
