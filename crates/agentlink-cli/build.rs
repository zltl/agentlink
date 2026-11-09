include!("../agentlink-desktop/swift_rpath.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=AGENTLINK_RELEASE_VERSION");
    emit_version();
    link_swift_runtime();
    // OpenH264's static build asks for libstdc++. rustc 1.99 links with lld,
    // which does not search GCC's private directory for that library.
    link_libstdcxx();
    // Clap walks the whole command tree on the main thread. The default
    // 1 MiB Windows stack overflows once desktop tools and the node
    // commands share this binary. 8 MiB matches the usual Unix default.
    // The Windows service dispatcher still runs on this thread.
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os != "windows" {
        return;
    }
    embed_windows_manifest();
    match std::env::var("CARGO_CFG_TARGET_ENV")
        .unwrap_or_default()
        .as_str()
    {
        "msvc" => println!("cargo:rustc-link-arg=/STACK:8388608"),
        "gnu" => println!("cargo:rustc-link-arg=-Wl,--stack,8388608"),
        _ => {}
    }
}

fn link_libstdcxx() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "linux" || env == "musl" {
        return;
    }
    let Ok(output) = std::process::Command::new("g++")
        .arg("-print-file-name=libstdc++.so")
        .output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let text = String::from_utf8(output.stdout).unwrap_or_default();
    let printed = text.trim();
    if printed.is_empty() || printed == "libstdc++.so" {
        return;
    }
    if let Some(dir) = std::path::Path::new(printed).parent() {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
}

fn embed_windows_manifest() {
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let tool = if env == "gnu" { "windres" } else { "rc" };
    let found = std::process::Command::new(tool)
        .arg(if env == "gnu" { "--version" } else { "/?" })
        .output()
        .is_ok();
    if !found {
        println!(
            "cargo:warning=skipping the Windows common-controls manifest; {tool} was not found"
        );
        return;
    }
    let mut res = winres::WindowsResource::new();
    let icon = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .join("assets")
        .join("agentlink.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    if icon.is_file() {
        if let Some(path) = icon.to_str() {
            res.set_icon(path);
        }
    }
    res.set_manifest(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
    </windowsSettings>
  </application>
</assembly>
"#,
    );
    if let Err(err) = res.compile() {
        println!("cargo:warning=Windows manifest was not embedded: {err}");
    }
}

fn emit_version() {
    let semver = std::env::var("AGENTLINK_RELEASE_VERSION")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into()));
    let hash = git_commit();
    let full = match &hash {
        Some(hash) => format!("{semver} ({hash})"),
        None => semver.clone(),
    };
    println!("cargo:rustc-env=AGENTLINK_SEMVER={semver}");
    println!("cargo:rustc-env=AGENTLINK_VERSION={full}");
    println!(
        "cargo:rustc-env=AGENTLINK_GIT_HASH={}",
        hash.unwrap_or_default()
    );
}

fn git_commit() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let hash = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if hash.len() < 7 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| !output.stdout.iter().all(|byte| byte.is_ascii_whitespace()))
        .unwrap_or(false);
    if dirty {
        Some(format!("{hash}-dirty"))
    } else {
        Some(hash)
    }
}
