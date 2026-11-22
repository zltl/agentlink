<div align="center">

# agentlink

**Self-hosted, end-to-end encrypted remote access, MCP server, and live desktop control for AI agents and humans — behind NAT, with zero port forwarding.**

[![Rust](https://img.shields.io/badge/Rust-1.99.1-orange?logo=rust)](rust-toolchain.toml)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-blue)](LICENSE-MIT)
[![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20Windows%20%7C%20macOS%20%7C%20Android-lightgrey)](#installation)
[![Protocol](https://img.shields.io/badge/Security-E2E%20Encrypted%20%2B%20SignedGrants-brightgreen)](#security--audit)

[Features](#features) · [Quickstart](#quickstart) · [Installation](#installation) · [MCP Integration](#mcp-for-ai-agents) · [CLI & Transfer](#cli--fast-transfer) · [Remote Desktop](#desktop-controller--remote-desktop) · [Android](#android) · [Security](#security--audit) · [Docs](#documentation)

</div>

---

**agentlink** lets an AI agent — or you — operate Linux, Windows, macOS, and Android machines sitting behind NAT or firewalls. Each machine runs a lightweight daemon that dials outbound to a relay you self-host. The relay is the only process that listens on a port; nodes and clients never need open inbound ports.

On Linux and macOS, a single `agentlink` binary serves as the relay, node daemon, CLI, desktop controller, and MCP server. On Windows, `agentlink.exe` provides the console CLI/daemon/relay alongside `agentlink-gui.exe` for zero-console-flash Tray and Desktop Controller windows.

<p align="center">
  <img src="docs/images/architecture.svg" alt="Agentlink architecture: clients and nodes dial the relay outbound; bulk file bytes travel as E2E-encrypted frames over WebSocket" width="760">
</p>

---

## Features

- **Native MCP Server for AI Agents** — Drop-in stdio or loopback Bearer HTTP MCP server for Cursor, Claude Desktop, and custom agents with 30+ tools for files, search, atomic patches, shell/PTY, background jobs, screenshots, accessibility trees, and GUI input.
- **Fail-Closed End-to-End Security** — All commands, PTYs, file transfers, and desktop control are sealed with `X25519` + `ed25519` + `ChaCha20-Poly1305`. Relay login only discovers and routes; every node operation requires a node-verified `SignedGrant` intersected with the node's local `--max-access` ceiling.
- **Fast Remote Files, Search & PTY** — Full interactive PTY (`portable-pty` / Windows ConPTY with `~.` escape), process-group cancellation, ripgrep-style content search, atomic unified-diff patching, filesystem watches, and resumable `zstd` + `BLAKE3` rsync-delta transfers (`agentlink cp`).
- **Live P2P Remote Desktop (WebRTC)** — Hardware-accelerated H.264/H.265/AV1 streaming (DXGI, ScreenCaptureKit, XShm, PipeWire) over WebRTC DTLS-SRTP with node consent controls (`notify`, `prompt`, `auto`, `deny`), clipboard sync, and automatic TURN credential refresh.
- **Native Desktop Controller & Windows Tray** — Built-in desktop app (`agentlink controller`) with Alacritty-core terminal, file browser/editor, live desktop viewer, and grant status badges — plus a Windows system tray (`agentlink tray`).
- **Tamper-Evident Audit Logging** — BLAKE3 hash-chained JSONL logs on-node (`0600`), with optional isolated relay and S3-compatible sinks (including fail-closed AES-256-GCM client-side encryption).
- **Android Support (Experimental)** — One app acts as either a remote node or a mobile controller (terminal, file browser, live H.264 desktop viewer) via UniFFI.

---

## Quickstart

Get a self-hosted relay, a paired node, and an end-to-end authorized command running in three steps.

### 1. Start the Relay

**With Docker Compose (recommended for headless servers):**

```bash
docker compose up -d
# Rotate the one-time bootstrap admin password immediately:
docker compose exec relay agentlink relay --data-dir /var/lib/agentlink user passwd admin
```

**Or run the binary directly:**

```bash
agentlink relay --bind 0.0.0.0:7443 --data-dir /var/lib/agentlink
# In another shell, rotate the bootstrap password (deletes bootstrap.password):
agentlink relay --data-dir /var/lib/agentlink user passwd admin
```

First start generates `cert.pem`, `key.pem`, `fingerprint.txt` (`sha256:...`), and a one-time `bootstrap.password`. The relay exposes `GET /healthz` for health checks, defaults to SQLite (or PostgreSQL via `AGENTLINK_DATABASE_URL`), and supports public TLS certificates via `--trust webpki` / `--fingerprint system` (see [docs/deploy.md](docs/deploy.md)).

### 2. Sign In & Pair a Node

On your **operator / controller** machine:

```bash
FP=$(cat /path/to/fingerprint.txt)
agentlink login --relay wss://relay.example:7443 --fingerprint "$FP" --user admin

# Mint a one-time invite bundling relay URL, certificate pin, and pairing token:
agentlink pair --name laptop --access exec
```

On the **target machine** (`laptop`):

```bash
agentlink node --invite 'agentlink-invite:v1:...' --name laptop
```

> **Tip:** To install the node directly as a background service instead of running it in the foreground, use `install.sh` / `install.ps1` or `agentlink service install --invite ...`.

### 3. Authorize with a Node-Local `SignedGrant`

A relay login **never** authorizes command execution or desktop access. Trust your controller's ed25519 identity on the node once, then issue time-bounded grants:

```bash
# 1. On the controller: display your public identity hex
agentlink identity show

# 2. On the node host (laptop): trust that controller key (hot-reloaded, no restart)
agentlink grant trust-owner <controller-public-id-hex>

# 3. Back on the controller: issue a time-bounded grant and run a command
agentlink grant issue laptop --policy exec --ttl 1h
agentlink exec laptop -- uname -a
```

> For interactive approval without trusting the controller as an issuer, use `agentlink grant offer` on the controller and `agentlink grant paste` on the node. See [docs/e2e-auth.md](docs/e2e-auth.md) and [docs/grant-offer.md](docs/grant-offer.md).

---

## Installation

Installers verify `SHA256SUMS.minisig` against the pinned signing key before downloading archives and default to least-privilege `--access exec --max-access exec`.

**Linux & macOS:**

```bash
curl -fsSL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/zltl/agentlink/main/install.sh | \
  env AGENTLINK_INVITE="agentlink-invite:v1:..." sh -s -- --name laptop
```

- Pass `--desktop` on Linux to install the glibc GUI build (with `agentlink controller`), or `--headless` for the static musl build.

**Windows (PowerShell):**

```powershell
$env:AGENTLINK_INVITE = "agentlink-invite:v1:..."
irm https://raw.githubusercontent.com/zltl/agentlink/main/install.ps1 | iex
```

- Installs `agentlink.exe` and `agentlink-gui.exe` to `%LOCALAPPDATA%\agentlink`, adds it to User `PATH`, and registers start-on-login with zero console flash.

**Background Services & Self-Updates:**

```bash
agentlink service install --invite 'agentlink-invite:v1:...' --name laptop
agentlink service status | start | stop | restart | logs | uninstall

# In-process signature-verified updates (no external minisign needed):
agentlink update --check
agentlink update --yes
```

- **Linux**: `systemd --user` unit (`graphical-session.target`, or `default.target` with `--headless`).
- **macOS**: Aqua `LaunchAgent` (or `LaunchDaemon` with `--scope system`).
- **Windows**: Notification-area tray (`agentlink tray`) via `HKCU\...\Run` launching `agentlink-gui.exe` (or Session 0 service with `--scope system`).

---

## MCP for AI Agents

`agentlink mcp` exposes your paired nodes over newline-delimited JSON-RPC on stdio (Windows UTF-8 BOM safe; `initialize` and `tools/list` succeed even before login).

**Cursor** (`~/.cursor/mcp.json`) or **Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agentlink": {
      "command": "/absolute/path/to/agentlink",
      "args": ["mcp"]
    }
  }
}
```

**Streamable HTTP (loopback-only by default, Bearer auth + Origin checks):**

```bash
agentlink mcp --http 127.0.0.1:7337 --mcp-token "$AGENTLINK_MCP_TOKEN"
```

> For headless/bot agents, register a tokenless ed25519 identity (`agentlink client create bot --out bot.identity.json`), issue a scoped grant, and pass `AGENTLINK_RELAY`, `AGENTLINK_FINGERPRINT`, and `AGENTLINK_IDENTITY` in `"env"`.

<details>
<summary><strong>Full MCP Tool Reference (30+ tools)</strong></summary>

| Category | Tools | Required Policy |
| --- | --- | --- |
| **Fleet & Status** | `get_status`, `list_machines`, `system_info` | `read` |
| **Files & Transfer** | `list_dir`, `stat_path`, `read_file`, `write_file`, `mkdir`, `remove_path`, `move_path`, `copy_path` | `read` / `write` |
| **Search & Edits** | `search_content`, `search_files`, `replace_text`, `edit_lines`, `apply_patch` | `read` / `write` |
| **Watches** | `watch_start`, `watch_poll`, `watch_stop` | `read` |
| **Exec & Processes** | `run_command`, `process_start`, `process_list`, `process_output`, `process_status`, `process_kill` | `exec` |
| **Interactive PTY** | `terminal_open`, `terminal_write`, `terminal_read`, `terminal_resize`, `terminal_close` | `exec` |
| **Desktop & UI** | `screenshot`, `get_ui_tree`, `click`, `type`, `key`, `scroll`, `act_on_element` | `remote-view` / `remote-control` / `desktop` |

Mutating tools (`run_command`, `write_file`, `remove_path`, `move_path`, `apply_patch`, `replace_text`, `edit_lines`, `click`, `type`, `key`, `process_start`, `act_on_element`) are never blindly auto-retried on disconnect.

</details>

---

## CLI & Fast Transfer

Primary output goes to `stdout`; warnings and progress go to `stderr`. Pass `--json` for structured machine-readable output. Nodes can be addressed by exact ID, unique ≥8-char ID prefix, case-insensitive name, or local alias.

```bash
# Fleet & node addressing
agentlink ls                              # list paired machines
agentlink status                          # session state, node TTLs, grantee checks
agentlink use laptop                      # set default node (or AGENTLINK_NODE)
agentlink alias set l laptop              # local short alias
agentlink pin list                        # inspect TOFU node key pins (pin rm <node> to reset)
agentlink exec --all --online -- uname -a # fan out across online nodes

# Grant management
agentlink grant ensure --all --policy exec --ttl 1h
agentlink grant refresh --all
agentlink grant list && agentlink grant prune
agentlink grant revoke laptop --data-dir <node-data-dir>   # run on node host

# Files, search, edits, shell & background jobs
agentlink exec laptop --shell -- 'echo hi && uname -a'
agentlink shell laptop                    # raw PTY (~. disconnects)
agentlink search laptop 'fn main' . --include '*.rs'
agentlink replace laptop note.txt 'old' 'new'
agentlink patch laptop /tmp --file change.diff
agentlink bg laptop start --shell -- ./long-job.sh
agentlink watch laptop /tmp --timeout-secs 30

# Desktop & accessibility
agentlink screenshot laptop --out screen.jpg
agentlink ui-tree laptop
agentlink click laptop 100 200 && agentlink type laptop "hello"
```

### Fast Transfer (`agentlink cp`)

```bash
agentlink cp ./project node://laptop/tmp/project                # upload directory
agentlink cp node://laptop/tmp/project ./project                # download directory
agentlink cp node://laptop/tmp/a.bin node://desktop/tmp/a.bin   # node-to-node copy
```

<p align="center">
  <img src="docs/images/transfer.svg" alt="E2E-encrypted WebSocket binary frame transfer flow" width="720">
</p>

- **E2E Binary Frames**: Bulk bytes stream as E2E-encrypted WebSocket binary frames (1 MiB chunks, sliding window of 8, 4 parallel ranges) with AAD v2 authenticating the full 40-byte frame header.
- **Smart Delta & Compression**: BLAKE3 skips identical files; changed files (128 KiB–256 MiB) send streaming rsync-style block deltas; adaptive `zstd` automatically skips already-compressed formats.
- **Confined & Resumable**: Supports partial-file resume and confined tar unpacking (`O_NOFOLLOW` + canonical symlink-chain checks). `cat` and `write` share this same binary fast path.

---

## Desktop Controller & Remote Desktop

Windows (`agentlink-gui.exe`), macOS, and glibc Linux (`install.sh --desktop`) builds include a native desktop controller:

```bash
agentlink controller                # open controller window
agentlink controller --background   # detached launch (no console flash on Windows)
agentlink controller --check        # verify desktop controller is compiled in
```

Each connected machine provides four integrated views:
- **Terminal**: Alacritty-core VT emulator with bracketed-paste ESC/C1-CSI sanitization, `Ctrl+Shift+C/V`, and opt-in `OSC 52`.
- **Files**: Breadcrumb/path navigation, native upload/download, unsaved-changes guard, and safe read-only preview for binary or >256 KiB files.
- **Desktop**: Live H.264 over WebRTC with automatic `POST /api/ice` TURN credential refresh, View↔Control toggle, connect-seeded clipboard sync, explicit ungrab chord (`Right Ctrl` / `Ctrl+Alt+Shift`), and sealed JPEG fallback while ICE negotiates.
- **Grants**: Live `SignedGrant` status, TTL badges, identity viewer, and grant import.

<p align="center">
  <img src="docs/stream.svg" alt="Desktop capture, tile damage detection, hardware encode, and WebRTC DTLS-SRTP streaming" width="720">
</p>

### Capture, Encode & Consent

| Platform | Capture Backend | Hardware Encode (Auto Fallback) |
| --- | --- | --- |
| **Windows** | DXGI Desktop Duplication (GDI fallback for one-shot) | Media Foundation (NVENC / Quick Sync / AMF) |
| **macOS** | ScreenCaptureKit (CoreGraphics fallback) | VideoToolbox |
| **Linux X11** | XShm + XDamage + XFixes | ffmpeg (NVENC / QSV / VAAPI / AMF when device exists) |
| **Linux Wayland** | PipeWire ScreenCast (`libpipewire-0.3`) or XDG Portal | ffmpeg hardware → `libx264` → in-process `minih264` |

Nodes enforce `--stream-consent` before answering a WebRTC offer: `notify` (default, non-blocking OS notification), `prompt` (explicit `.allow`/`.deny` wait up to 30s), `auto`, or `deny`. Audio is optional G.711 µ-law (8 kHz mono via `pw-record`/`parecord` on Linux). Browser desktop viewing is intentionally disabled (`GET /view` serves a static notice).

<details>
<summary><strong>NAT / coturn TURN Configuration</strong></summary>

LAN connections work directly with host candidates (dual-stack IPv6/IPv4, preferring physical interfaces over VPN overlays). Across symmetric NAT, run [coturn](https://github.com/coturn/coturn) with `use-auth-secret` and configure the relay:

```bash
AGENTLINK_STUN_URLS=stun:turn.example:3478
AGENTLINK_TURN_URLS=turns:turn.example:443?transport=tcp
AGENTLINK_TURN_SECRET=replace-with-coturn-static-auth-secret
AGENTLINK_TURN_TTL_SECS=600   # clamped 5–15 minutes
```

Both `agentlink controller` and the Android app automatically mint and refresh short-lived HMAC-SHA1 TURN credentials via `POST /api/ice`.

</details>

<details>
<summary><strong>Synthetic Stream Cost (640×360 BGRA, software minih264)</strong></summary>

Measured with `cargo test --release -p agentlink-desktop --lib stream::bench` (damage detection + encode, no GPU):

| Scene | Encoded Frames | Bytes | Effective Bitrate | CPU Time | First Access Unit |
| --- | --- | --- | --- | --- | --- |
| Static desktop (30 frames) | 1 | 977 B | ~7 kbps | 10 ms (~1%) | 1 ms |
| Typing (30 frames, 1 px delta) | 30 | 1,976 B | ~15 kbps | 20 ms (~2%) | 1 ms |
| Noisy video (20 frames) | 20 | 408,358 B | ~4.9 Mbps | 30 ms (~4%) | 1 ms |

</details>

---

## Android

The `android/` app (experimental) speaks protocol v2 via `agentlink-ffi` (UniFFI + `cargo-ndk` for `arm64-v8a`, `armeabi-v7a`, `x86_64`) and can operate as either a **Node** or a **Client**.

<p align="center">
  <img src="docs/images/android-roles.svg" alt="Android app can act as either a node or a controller client" width="640">
</p>

- **As a Node**: Runs an Android 15-compatible foreground service (`remoteMessaging`), exposes isolated `app:/` storage plus opt-in SAF folders (`saf:/`), enforces E2E `SignedGrant` + `owner-keys.json` + consent ceilings, and runs the hash-chained audit pipeline.
- **As a Client**: Full machine hub, OS-aware file browser & server search, persistent TrueColor PTY terminal, TOFU pin/grant management, and fullscreen hardware `MediaCodec` H.264 desktop viewer with gestures and clipboard sync.

```bash
./android/build-native.sh   # or android/build-native.ps1 on Windows
cd android && ./gradlew testDebugUnitTest assembleDebug assembleRelease
```

---

## Security & Audit

See [SECURITY.md](SECURITY.md) and [docs/e2e-auth.md](docs/e2e-auth.md) for the complete threat model and intentional boundaries.

- **Relay Pinning & TOFU**: TLS 1.2+ (`rustls`) with SHA-256 leaf/SPKI pin or system/WebPKI roots. First-seen `node_name -> ed25519_id` bindings are pinned in `node-pins.json` and fail closed on mismatch.
- **Fail-Closed E2E**: Control invokes, cancels, replay cursors, and binary transfer frames are sealed (`X25519` + `ed25519` transcript + `ChaCha20-Poly1305`). Unsealed or cross-node frames are dropped.
- **Node-Authoritative Grants**: Every op and session (PTY, background process, watch, tunnel, desktop stream) is bound to `(owner_peer, grant_jti, grant_exp_unix)` and torn down immediately on expiry or node-local revocation.
- **Path Confinement**: `--root` confines all file, edit, and transfer operations via canonical symlink-chain checks and `O_NOFOLLOW`/reparse guards. Note that `--root`, `limits.json`, and `confirm.toml` are operational guardrails — not an OS container or kernel sandbox once `exec`/`full` is granted.
- **Tamper-Evident Audit Sinks**: Every handler emits hash-chained BLAKE3 records (`agentlink audit query --verify`) across configurable sinks:

| Sink | Storage & Properties |
| --- | --- |
| `local` | `data_dir/audit/logs/YYYY-MM-DD.jsonl`, diffs, and recordings (mode `0700`/`0600`) |
| `relay` | Gzipped, rate-capped batches in isolated `node-audit.jsonl` (viewable at `https://<relay>/audit`) |
| `s3` | Any S3-compatible store (AWS, MinIO, R2, OSS, COS) with optional fail-closed AES-256-GCM CSE (`client_key_env`) |

---

## Building from Source

Requires **Rust 1.99.1** (pinned in [rust-toolchain.toml](rust-toolchain.toml)). On Linux desktop builds, install `pkg-config` and `libpipewire-0.3-dev` for PipeWire Wayland ScreenCast support.

```bash
# Desktop release build (includes GUI controller; builds agentlink.exe + agentlink-gui.exe on Windows)
cargo build --locked --release -p agentlink-cli

# Headless release build (servers, containers, relay-only — omits GUI, OpenH264, and libstdc++6)
cargo build --locked --release -p agentlink-cli --no-default-features

# Full test & verification suite
cargo test --locked --workspace
sh scripts/verify.sh
```

<details>
<summary><strong>Workspace Layout</strong></summary>

| Crate | Responsibility |
| --- | --- |
| `agentlink-core` | Protocol v2, E2E framing/AAD v2, permissions, TLS pinning, ICE/TURN fetch, transfer engine, client |
| `agentlink-relay` | Typed principals, accounts/TOTP, connection-bound routing, `/healthz`, `/api/ice`, web dashboard |
| `agentlink-node` | Confined file/search/edit/watch/exec/PTY/tunnel handlers, grant lifecycle, audit pipeline |
| `agentlink-desktop` | Capture, hardware/software encode, consent, clipboard, input, accessibility, WebRTC sender |
| `agentlink-view` | WebRTC receiver, H.264 depacketizer/FrameBus, ICE/TURN refresh |
| `agentlink-cli` | `agentlink` console binary (optional `controller` feature) + Windows `agentlink-gui` launcher |
| `agentlink-ffi` | UniFFI node and client bindings for the Android app |

</details>

---

## Documentation

| Document | Topic |
| --- | --- |
| [docs/deploy.md](docs/deploy.md) | Production deployment, reverse proxies, TLS, PostgreSQL, systemd, and Docker |
| [docs/multi-user.md](docs/multi-user.md) | Accounts, TOTP, device login, sharing, and browser Add-Machine enrollment |
| [docs/e2e-auth.md](docs/e2e-auth.md) | End-to-end encryption, `SignedGrant` lifecycle, and multi-node grant management |
| [docs/grant-authorization-boundary.md](docs/grant-authorization-boundary.md) | Exact trust boundary between relay routing and node-local authorization |
| [docs/grant-offer.md](docs/grant-offer.md) | Interactive `grant offer` / `grant paste` approval workflow |
| [docs/operate-guide.md](docs/operate-guide.md) | Day-2 operations, troubleshooting, and fleet administration |
| [docs/testing.md](docs/testing.md) | Test suites, smoke tests, and verification scripts |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, supported targets, and security boundaries |

---

## Limitations & Roadmap

**Current limitations:**
- Direct QUIC P2P file transfer is disabled until E2E-sealed direct P2P lands; bulk transfers currently use the E2E-encrypted relay WebSocket path.
- `--root`, `limits.json`, and `confirm.toml` are guardrails, not an OS sandbox — run nodes under a dedicated unprivileged account or VM if isolation from host secrets is required.
- Live desktop streams do not dynamically change resolution mid-session; Windows/macOS release binaries are not yet Authenticode-signed or Apple-notarized.
- The relay Docker container runs as non-root `agentlink` (ensure mounted `/var/lib/agentlink` volumes are writable).

**Planned:**
1. E2E-sealed direct QUIC P2P file transfer with TLS channel binding and verified peer grant enforcement.
2. In-process `libei` input client for Wayland sessions.
3. Mid-session adaptive resolution scaling under sustained packet loss.

---

## Contributing & License

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, testing guidelines, and `THIRD_PARTY.md` license checks.

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option. See [NOTICE](NOTICE) and [THIRD_PARTY.md](THIRD_PARTY.md) for third-party attributions (including OpenH264 `BSD-2-Clause` in desktop builds).
