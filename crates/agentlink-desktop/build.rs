fn add_videotoolbox(build: &mut cc::Build) {
    if std::env::var("CARGO_CFG_TARGET_OS").ok().as_deref() != Some("macos") {
        return;
    }
    // cc 1.2+ dropped `Build::framework`. The system headers are on the
    // default SDK path; rustc still has to link the frameworks.
    build.file("src/stream/native/videotoolbox_encode.c");
    for framework in ["VideoToolbox", "CoreMedia", "CoreVideo", "CoreFoundation"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}

include!("swift_rpath.rs");

fn main() {
    link_swift_runtime();
    println!("cargo::rustc-check-cfg=cfg(pipewire_headers)");
    let mut build = cc::Build::new();
    build
        .file("src/stream/native/minih264_glue.c")
        .include("vendor")
        .define("H264E_MAX_THREADS", "1")
        // spa/pipewire headers rely on GNU/POSIX extensions (locale_t, ssize_t).
        .flag_if_supported("-std=gnu99")
        .flag_if_supported("-O2")
        .flag_if_supported("-fno-strict-aliasing")
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-variable")
        .flag_if_supported("-w");
    if std::env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("windows") {
        build.flag_if_supported("/O2");
    }
    add_videotoolbox(&mut build);
    match pkg_config::probe_library("libpipewire-0.3") {
        Ok(lib) => {
            // pkg-config only emits link flags here; the cc::Build needs the
            // -I paths (e.g. /usr/include/pipewire-0.3, /usr/include/spa-0.2)
            // or pipewire/pipewire.h cannot be found.
            for path in &lib.include_paths {
                build.include(path);
            }
            for (name, value) in &lib.defines {
                build.define(name, value.as_deref());
            }
            build.file("src/stream/native/pipewire_capture.c");
            build.define("HAVE_PIPEWIRE", None);
            println!("cargo:rustc-cfg=pipewire_headers");
        }
        Err(_) => {
            println!("cargo:warning=libpipewire-0.3 not found; Wayland streaming falls back to the screenshot portal");
        }
    }
    build.compile("agentlink_stream_native");
    println!("cargo:rerun-if-changed=src/stream/native/minih264_glue.c");
    println!("cargo:rerun-if-changed=src/stream/native/pipewire_capture.c");
    println!("cargo:rerun-if-changed=vendor/minih264e.h");
}
