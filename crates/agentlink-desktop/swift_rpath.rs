/// `screencapturekit` (and `apple-cf`) print `-rpath` for the Swift runtime,
/// but Cargo does not pass `cargo:rustc-link-arg` from a dependency through
/// to the crate that actually links. The Swift bridge targets macOS 13 and
/// loads `@rpath/libswift_Concurrency.dylib`. Every binary and test that
/// links this crate has to record the rpath itself.
fn link_swift_runtime() {
    if std::env::var("CARGO_CFG_TARGET_OS").ok().as_deref() != Some("macos") {
        return;
    }
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    let Ok(output) = std::process::Command::new("xcode-select").arg("-p").output() else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let xcode_path = String::from_utf8_lossy(&output.stdout);
    let xcode_path = xcode_path.trim();
    if xcode_path.is_empty() {
        return;
    }
    let swift_lib =
        format!("{xcode_path}/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{swift_lib}");
}
