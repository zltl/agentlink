# Contributing to Agentlink

By contributing to Agentlink, you agree that your contributions will be dual-licensed under `MIT OR Apache-2.0` (see `LICENSE-MIT`, `LICENSE-APACHE`, and `NOTICE`).

## Toolchain and Prerequisites

- **Rust**: `1.99.1` (pinned in `rust-toolchain.toml`).
- **Linux desktop / controller builds (`glibc`)**:
  - Standard X11/Wayland libraries for `eframe`/`winit`.
  - Optional (recommended for GNOME/Wayland ScreenCast streaming and custom Mutter capture): `pkg-config` and `libpipewire-0.3-dev` (Debian/Ubuntu) or `pipewire-devel` (Fedora). Without PipeWire headers, `agentlink-desktop` falls back to the XDG Screenshot portal at build time.
- **Linux static node/CLI builds (`musl`)**:
  - `musl` targets omit the `eframe` GUI controller window so static binaries stay self-contained.
- **Windows (`x86_64-pc-windows-msvc` / `aarch64-pc-windows-msvc`)**:
  - Visual Studio C++ Build Tools (Windows SDK + MSVC).
- **Android (experimental, `android/`)**:
  - JDK 17, Android SDK (`compileSdk = 35`), Android NDK r27 (`27.2.12479018`), and `cargo-ndk`.
  - Build native libraries and Kotlin UniFFI bindings first with `./android/build-native.sh` before packaging a device APK.

## Pinned Dependencies (`sqlx` & `THIRD_PARTY.md`)

- Always pass `--locked` to `cargo build` and `cargo test` unless intentionally updating dependencies.
- `Cargo.toml` currently pins `launchbadge/sqlx` to official merge commit `10462fa4414c6c7f1ed1d39bb31678e3b726878c` (PR #4502) alongside crates.io `libsqlite3-sys =0.39.1` (SQLite `3.54.1`, fixing `RUSTSEC-2026-0459`). For offline builds, run `cargo vendor` beforehand.
- Whenever `Cargo.lock`, `crates/agentlink-desktop/vendor/`, font assets, or `android/app/build.gradle.kts` changes, regenerate and verify `THIRD_PARTY.md`:

```bash
python3 scripts/generate-third-party-licenses.py
python3 scripts/generate-third-party-licenses.py --check
```

## Running Tests

All unit and integration tests must pass on Rust's default 2 MiB test thread stack without requiring `RUST_MIN_STACK`:

```bash
cargo test --locked --workspace
```

Useful targeted suites during development:

```bash
cargo test --locked -p agentlink-core --lib
cargo test --locked -p agentlink-relay --lib
cargo test --locked -p agentlink-node --lib
cargo test --locked -p agentlink-node --test security
cargo test --locked -p agentlink-desktop --lib
cargo test --locked -p agentlink-ffi --lib
cargo test --locked -p agentlink-view --lib --test loopback
cargo test --locked -p agentlink-cli --bin agentlink controller::
```

Note that automated unit tests do **not** replace real GUI acceptance on Windows and Linux (X11 / Wayland / GNOME Mutter) when modifying desktop capture, cursor, clipboard, or keyboard input; follow [docs/desktop-shortcuts-acceptance.md](docs/desktop-shortcuts-acceptance.md).

## Security and Privacy Rules for Contributions

- **Never weaken end-to-end authorization**: relay authentication is not node authorization. Never bypass `SignedGrant` verification, `owner-keys.json`, `revoked-grants.json`, E2E peer binding, or `--max-access` ceilings.
- **No secrets or host PII in commits**: never commit tokens, keys, certificates, runtime `config.json` / `node.json` backups, local usernames, internal hostnames, or real public/LAN/VPN IP addresses. Use RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 6598 (`100.64.0.0/10`), and `relay.example` / `workstation` in tests and documentation.
- **Process spawning on Windows**: new `std::process::Command::new` call sites must use the shared hidden-console helper or carry a justified `no-window-reviewed` annotation so `cargo test --locked -p agentlink-cli --test no_console_flash` continues to pass.
