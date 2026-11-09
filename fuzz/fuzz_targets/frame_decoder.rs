//! Frame decoder fuzz target.
//!
//! `cargo build --manifest-path fuzz/Cargo.toml` feeds a few seeds through
//! `exercise` and does not link libFuzzer.
//! `cargo fuzz build` (or `cargo build --manifest-path fuzz/Cargo.toml` with
//! `--cfg fuzzing` and `-C link-arg=-fsanitize=fuzzer`) exports
//! `LLVMFuzzerTestOneInput` and lets libFuzzer own `main`.

#![cfg_attr(fuzzing, no_main)]

fn exercise(data: &[u8]) {
    // Never decompress here. A hostile `raw_len` would ask zstd for a huge buffer.
    let _ = agentlink_core::frame::request_id(data);
    let _ = agentlink_core::frame::is_e2e(data);
    if let Ok(frame) = agentlink_core::frame::decode(data) {
        if let Ok(encoded) = agentlink_core::frame::encode(&frame) {
            if let Ok(again) = agentlink_core::frame::decode(&encoded) {
                let _ = again.request_id.len();
            }
        }
    }
}

#[cfg(fuzzing)]
#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    if data.is_null() {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, size) };
    exercise(bytes);
    0
}

#[cfg(not(fuzzing))]
fn main() {
    let seeds: &[&[u8]] = &[
        b"",
        &[0u8; 8],
        &[1u8; 40],
        &[1u8; 80],
        b"\x01\x01\x00\x00not-a-frame",
    ];
    for seed in seeds {
        exercise(seed);
    }
}
