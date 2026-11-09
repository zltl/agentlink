# Testing and benchmarks

Functional tests run on Ubuntu, Windows, and macOS in `.github/workflows/ci.yml`. Benchmarks live in a separate workflow so a normal pull request does not spend time on them.

## Functional tests

```bash
cargo test --workspace --locked
```

The new suites are:

- `crates/agentlink-core/tests/properties.rs` — proptest for framing, the block delta, path normalisation, and config parsing.
- `crates/agentlink-cli/tests/tray_status.rs` checks `agentlink tray status` against `node.json`, `status.json`, and the saved account, and checks that `tray install --dry-run` prints an HKCU Run command. The window and the registry write are Windows-only; the Windows CI job compiles them. Unit tests in `tray.rs` check that the generated Run command is `tray --background` and that a second `node` value for the same data directory is removed.
- `crates/agentlink-cli/tests/tray_icon.rs` checks that `assets/agentlink.ico` contains 32-bit 16 and 32 pixel sticker frames (transparent corner, teal body) so the tray icon stays crisp at notification-area sizes.
- `crates/agentlink-cli/tests/controller.rs` runs `agentlink controller --check`. That exits without a window. On glibc it prints `controller: ready`. The window itself is `eframe` and is omitted from musl release builds. Linux CI installs the X11, Wayland, and GL headers so the glibc controller links. The dashboard test in `agentlink-relay` checks that machine cards use the View/Control buttons and contain no `<input type="checkbox">`.
- `crates/agentlink-cli/tests/functional.rs` — the `agentlink` binary as a subprocess, plus MCP on stdio (newline JSON and `Content-Length`) and streamable HTTP (401, 403, 404, session id, SSE, DELETE).
- `crates/agentlink-desktop/tests/x11_roundtrip.rs` — a real screenshot and an XTest pointer move checked with `query_pointer`.

A transfer of a few mebibytes is the largest file these tests move. The 1 GiB case belongs to `agentlink bench`.

### Desktop on Linux CI

The Linux test job starts Xvfb and sets `AGENTLINK_X11_INPUT=1`:

```bash
xvfb-run -a -s "-screen 0 1280x720x24 -ac +extension MIT-SHM +extension XTEST" \
  env AGENTLINK_X11_INPUT=1 cargo test --workspace --locked
```

Without `DISPLAY` the desktop tests print a skip line and pass. Windows and macOS do not run the X11 test.

### What is covered from the security work

Per-agent identity, end-to-end sealed command and file bytes, and the audit chain (including `agentlink audit query --verify`) are exercised by the suites above. Android login, the node service, and the client UI live in `android/`. `./gradlew testDebugUnitTest` runs the Robolectric cases, including username login. The device-key case installs a Keystore provider that rejects Ed25519 and checks that sign-in still creates an Ed25519 key and seals the seed with AES-GCM. The cargo suite does not start an emulator.

### Live desktop on a phone

`cargo test -p agentlink-view` depacketizes RTP H.264 and, in `tests/loopback.rs`, offers a session at `Desktop::mock()` (consent auto, remote control). The test waits for an Annex-B IDR and for a mouse move to show up on the stream audit hook. No display and no emulator.

On a device or emulator, pair the phone client with a desktop node whose ceiling includes `remote-view` or `remote-control` (`agentlink perm`, and `--max-access` on the node). Open Desktop. The picture should move without a new JPEG every 700 ms, and a static desktop should go quiet after the first frame. The button says "Request keyframe" while the stream is up and "Retry live view" after it drops. A phone node, or a desktop preset with live video off, stays on screenshots. `adb logcat` does not need a special tag. A decoder failure is the banner text, then JPEG if screenshots are allowed.

```bash
cargo test -p agentlink-view
cd android && ./gradlew testDebugUnitTest --tests app.agentlink.model.LiveControlTest
```

## Property tests

proptest is a dev-dependency of `agentlink-core`, so `cargo test --workspace` runs it. To burn more cases:

```bash
PROPTEST_CASES=1000 cargo test -p agentlink-core --test properties
```

## Fuzzing

`fuzz/` is its own Cargo workspace. It is not a member of the main workspace and CI does not run it.

Build the seed harness, which does not link libFuzzer:

```bash
cargo build --manifest-path fuzz/Cargo.toml
```

`cargo fuzz build` compiles the same target with `--cfg fuzzing`. That build exports `LLVMFuzzerTestOneInput` and expects libFuzzer on the link line (`-fsanitize=fuzzer`), which is what cargo-fuzz supplies. The target only decodes and re-encodes frames. It does not decompress, because a hostile `raw_len` would allocate a huge buffer.

## Microbenchmarks

`bench-micro/` is also outside the workspace, so `cargo test` does not compile Criterion.

```bash
cargo bench --manifest-path bench-micro/Cargo.toml
```

The regression guard measures median throughput for frame encode/decode, BLAKE3, delta planning, and a zstd round trip. It fails when a metric drops more than 25% below `benches/baseline.json`. Cargo runs the bench with its working directory set to `bench-micro/`, so the baseline path is relative to that directory:

```bash
cargo bench --manifest-path bench-micro/Cargo.toml -- --guard --baseline ../benches/baseline.json
```

Replace the baseline only from a quiet machine, after a real run:

```bash
cargo bench --manifest-path bench-micro/Cargo.toml -- --guard --write-baseline --baseline ../benches/baseline.json
```

End-to-end throughput is not part of this guard. Loopback numbers move around too much to fail a pull request.

The numbers in `benches/baseline.json` were measured on a Linux x86_64 cloud VM (1 MiB payload, median of 7 trials). Refresh them on the machine that runs the bench workflow if that host is materially slower.

## End-to-end bench

```bash
cargo build --release -p agentlink-cli
./target/release/agentlink bench --quick --out bench-results.md
./target/release/agentlink bench --out bench-results.md
```

`--quick` copies 1 MiB over the relay and over QUIC, a couple of hundred small files, and short exec and MCP samples. The full command adds 100 MiB and a sparse 1 GiB file. Compression is off. The table names the transport that actually carried the bytes (`quic` or `relay`). When `scp` and `rsync` are on `PATH` it also times a local 1 MiB copy. Idle RSS and CPU are sampled from the node process before the copies start.

`agentlink bench` is not invoked from `cargo test`.

## Benchmark workflow

`.github/workflows/bench.yml` runs on `workflow_dispatch`, every Monday at 06:00 UTC, and on a pull request that carries the `perf` label. Other pull requests skip the job.

The job runs the microbenchmark guard, then `agentlink bench --quick` for a labelled pull request and the full bench for a schedule or a manual run. It uploads `bench-results.md` and writes the same markdown into the GitHub job summary.

The guard compares against the committed baseline. A labelled pull request can fail that guard. It does not fail because end-to-end throughput moved.
