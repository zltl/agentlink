include!("../agentlink-desktop/swift_rpath.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Integration tests link agentlink-desktop, which pulls in ScreenCaptureKit.
    link_swift_runtime();
}
