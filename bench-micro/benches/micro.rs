//! Framing, BLAKE3, block-delta, and zstd microbenchmarks.
//!
//! `cargo bench --manifest-path bench-micro/Cargo.toml` runs Criterion.
//! `cargo bench --manifest-path bench-micro/Cargo.toml -- --guard --baseline ../benches/baseline.json`
//! prints median MiB/s and exits non-zero when a metric falls below 75% of the
//! committed baseline. `--write-baseline` replaces that file with the medians
//! just measured.

use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use agentlink_core::compress::{self, decompress};
use agentlink_core::delta::{self, Plan};
use agentlink_core::frame::{self, DataFrame};
use criterion::{Criterion, Throughput};
use uuid::Uuid;

const MIB: usize = 1024 * 1024;

fn payload() -> Vec<u8> {
    let pattern = b"agentlink-bench-block-0123456789abcdef";
    let mut data = Vec::with_capacity(MIB);
    while data.len() < MIB {
        data.extend_from_slice(pattern);
    }
    data.truncate(MIB);
    data
}

fn frame_roundtrip(data: &[u8]) {
    let frame = DataFrame {
        request_id: Uuid::nil().to_string(),
        offset: 0,
        raw_len: data.len() as u32,
        compressed: false,
        tar: false,
        payload: data.to_vec(),
    };
    let encoded = frame::encode(&frame).expect("encode");
    let decoded = frame::decode(&encoded).expect("decode");
    black_box(decoded.payload.len());
}

fn blake3_hash(data: &[u8]) {
    black_box(delta::hash_bytes(data));
}

fn delta_plan(old: &[u8], new_data: &[u8]) -> Plan {
    let table = delta::signatures(old, 64 * 1024);
    black_box(delta::plan(new_data, &table))
}

fn zstd_roundtrip(data: &[u8]) {
    let compressed = compress::compress_if_smaller(data).expect("fixture should shrink");
    let raw = decompress(&compressed, data.len()).expect("decompress");
    black_box(raw.len());
}

fn median_mib_s(bytes: usize, mut op: impl FnMut()) -> f64 {
    for _ in 0..2 {
        op();
    }
    let mut samples = Vec::with_capacity(7);
    for _ in 0..7 {
        let started = Instant::now();
        let iters = 8u32;
        for _ in 0..iters {
            op();
        }
        let secs = started.elapsed().as_secs_f64().max(1e-9);
        samples.push((bytes as f64 * f64::from(iters)) / secs / (1024.0 * 1024.0));
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn guard(args: &[String]) -> i32 {
    let baseline_path = args
        .iter()
        .position(|arg| arg == "--baseline")
        .and_then(|idx| args.get(idx + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("benches/baseline.json"));
    let write = args.iter().any(|arg| arg == "--write-baseline");
    let data = payload();
    let mut changed = data.clone();
    changed[80_000] ^= 0xff;
    let metrics = [
        (
            "frame_roundtrip_mib_s",
            median_mib_s(MIB, || frame_roundtrip(&data)),
        ),
        ("blake3_mib_s", median_mib_s(MIB, || blake3_hash(&data))),
        (
            "delta_plan_mib_s",
            median_mib_s(MIB, || {
                let _ = delta_plan(&data, &changed);
            }),
        ),
        (
            "zstd_roundtrip_mib_s",
            median_mib_s(MIB, || zstd_roundtrip(&data)),
        ),
    ];
    let mut object = serde_json::Map::new();
    println!("| metric | MiB/s |");
    println!("| --- | ---: |");
    for (name, value) in metrics {
        println!("| {name} | {value:.1} |");
        object.insert(name.to_string(), serde_json::json!(round1(value)));
    }
    if write {
        if let Some(parent) = baseline_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let body = serde_json::to_string_pretty(&object).unwrap() + "\n";
        std::fs::write(&baseline_path, body).unwrap_or_else(|err| {
            panic!("write {}: {err}", baseline_path.display());
        });
        println!("wrote {}", baseline_path.display());
        return 0;
    }
    let text = std::fs::read_to_string(&baseline_path).unwrap_or_else(|err| {
        panic!("read {}: {err}", baseline_path.display());
    });
    let baseline: serde_json::Value = serde_json::from_str(&text).expect("baseline json");
    let mut failed = false;
    for (name, value) in metrics {
        let floor = baseline[name].as_f64().unwrap_or(0.0) * 0.75;
        if value < floor {
            eprintln!("{name}: {value:.1} MiB/s is below 75% of the baseline ({floor:.1})");
            failed = true;
        }
    }
    if failed {
        1
    } else {
        println!(
            "microbenchmarks stayed within 25% of {}",
            baseline_path.display()
        );
        0
    }
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn criterion_benches() {
    let data = payload();
    let mut changed = data.clone();
    changed[80_000] ^= 0xff;
    let mut criterion = Criterion::default().configure_from_args();
    let mut group = criterion.benchmark_group("agentlink");
    group.throughput(Throughput::Bytes(MIB as u64));
    group.bench_function("frame_roundtrip", |bencher| {
        bencher.iter(|| frame_roundtrip(black_box(&data)));
    });
    group.bench_function("blake3", |bencher| {
        bencher.iter(|| blake3_hash(black_box(&data)));
    });
    group.bench_function("delta_plan", |bencher| {
        bencher.iter(|| delta_plan(black_box(&data), black_box(&changed)));
    });
    group.bench_function("zstd_roundtrip", |bencher| {
        bencher.iter(|| zstd_roundtrip(black_box(&data)));
    });
    group.finish();
    criterion.final_summary();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--guard") {
        std::process::exit(guard(&args));
    }
    criterion_benches();
}
