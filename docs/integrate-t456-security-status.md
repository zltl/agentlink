# t456 security integration status

Recorded 2026-11-12 21:00 CST (Asia/Shanghai). Local candidate only; this step did not push.

- Continuation worktree: `/workspace/agentlink-integrate-t456-cont`
- Frozen 912 review tree (untouched, still clean): `/workspace/agentlink-integrate-t456` at `9122522b23846b2b6c31c640ef2928cb053dd994`
- Branch: `integrate/security-main-t456`
- Baseline: `feat/controller-p2p-observe-t449` (`ebfb6f22cef5509fce923e77c5494a44a5d7d9f4`)
- Remote `main` (`602887281932d254d3d8ee1d57f8e3a305ab9bd6`) is a strict ancestor
- Frozen t452 controller bin left in place under `/workspace/agentlink-t427-recovery/20261112-1341-t452-controller-p2p/`
- Dirty source worktrees were not touched
- Repo visibility unchanged (private); no release; no GitHub Actions; no production deploy; no production token was changed

Trust model is unchanged: a full current-user shell with a grant may read the same-UID issuer and countersign. The first request without a grant is still denied. Relay login is not target authorization. Public NAT P2P remains unproven. Same-account grant bypass is not restored.

This revision addresses the independent review of `9122522`. Confirmed-good direction (parameterized notifications, flag overwrite, desktop owner UUID, legacy default off, QR client DOM filtering, license/no Actions) was kept and not reverted.

## Review items after the 912 follow-up

1. **P0 notification injection — kept.** `NotifyPlan` still parameterizes every OS path. `applescript_string_literal` also folds U+0085 / U+2028 / U+2029 / VT / FF into `\\n`. Coverage is the real API plus a literal unit test; this is not a real macOS run.

2. **P0 grant flags — kept and completed on FFI.** `fill_stream_grant_flags` / `stamp_verified_grant` overwrite `_allow_view` / `_allow_control` from the verified policy and replace client `_grant_jti` / `_grant_exp` with the node-checked grant. FFI no longer strips those stamps.

3. **P1 live WebRTC / PTY teardown — fixed.** Sweeps walk stored grant metadata on live WebRTC and PTY sessions, not the inflight RPC/`grant_sessions` index. An independent 1s watcher is keyed on the socket generation (not a heartbeat). After offer/PTY open completes, the grant is re-checked and a revoked/expired session is closed. Revoking one jti leaves other valid jtis up. Relay drop (`close_all_sessions` / FFI `drop_link`) stops media and PTY immediately; there is no reconnect grace that leaves a pump running. Datachannel grant failure sets the media stop flag and returns a JSON error; a view-only control reject still does not stop media. PTY write/resize/close check owner, expiry, and the revoked hook. Close after revoke/expiry is allowed for the owner or for internal teardown; a mismatched peer still cannot close.

4. **P1/P2 signaling peer — fixed.** `extension_op` uses `ctx.peer_id` (seal.peer). The inner Invoke `client_id` is overwritten with seal.peer. A real handler test forges Alice as Bob's `client_id` with a known session UUID and is rejected; production stream ids come from `new_stream_session_id()` (UUID v4).

5. **P2 FFI / Android PTY owner — fixed.** `PhonePty` stores owner + grant jti/exp, has a fail-closed `grant_active` hook, and re-checks after open. Write/resize/close take the caller. A unix integration test opens a real `cat` PTY. `ShellSessions` records `_owner_peer` from the open payload and requires the caller on input/resize/close. UniFFI `NodeHost` signatures are unchanged; the ID-only `sessionInput` path is fail-closed, and in-process `closeSession` remains cleanup. No phone or emulator run.

6. **P2 node.json and poisoned locks — fixed.** `read_saved_node_json` is a tri-state: missing file is first start; a present but corrupt or unreadable file fails closed. FFI policy lock poison denies the invoke/transfer (no ceiling fallback). Desktop WebRTC offer poison also fails closed (`node policy is unavailable`). Tests cover each path, including a unix unreadable-file case.

7. **P2 legacy admin mint — fixed.** New deploys with legacy off do not mint a usable token and do not write `admin.token`. Existing tokens are not rotated or deleted. Explicit `AGENTLINK_LEGACY_ADMIN=1` plus a positive TTL still mints. A token with `created_unix <= 0` (no recorded creation time) is rejected; migration does not default the timestamp to now. Docs in `docs/deploy.md` match this. CLI functional/smoke spawners set the enable+TTL env so they still exercise a token; production `legacy_admin_override` stays `None`.

8. **P2 tests use real entry points.** Production UUID generation (`new_stream_session_id`) and the WebRTC/PTY/ops handlers are the tests, not a test-local UUID plus an unused `build_answer` assertion. PTY isolation tests open a real session.

9. **P3 branch matrix — updated.** Live remote heads were re-listed from the GitHub API (`list_branches` page size 100, `list_tags` empty). Cached `origin/*` that are not on the live remote are listed separately. `origin/cursor/owner-full-access-c6ef` `4f11573` (“Give connected owners full access without grant paste”, merge-base NONE) is explicitly excluded and must not come back. Other cached `origin/fix/*` and `origin/tip/v0.1.233-mcp-grant-capability` with no merge-base are listed by category in `docs/integrate-t456-branch-matrix.md`.

10. **P3 licenses — fixed.** `NOTICE` points at `THIRD_PARTY.md`, generated by `scripts/generate-third-party-licenses.py` from `cargo metadata` (772 third-party crates, 0 undeclared) plus the in-tree Inter and JetBrains Mono OFL files. Licenses are copied from metadata; nothing was invented. Android/Gradle libraries are declared in `build.gradle.kts` but are not in this cargo inventory.

11. **P3 QR SVG — fixed.** Server `safe_qr_svg` is a strict element/attribute allowlist, not a `script` / `foreignObject` / `onerror=` blocklist. It rejects comments, `on*` attributes including spaced `onerror`, and `href`. This is not described as a complete HTML sanitizer. Client `setTrustedSvg` DOM filtering remains.

## cargo-audit (isolated, 2026-11-12 21:00 CST, Asia/Shanghai)

Installed `cargo-audit 0.23.0` under `CARGO_HOME=/tmp/agentlink-audit-home`. Advisory DB: 1471 advisories. `Cargo.lock` has 779 crate dependencies. Exit code **1** (not ignored).

**Fixed in this candidate (including earlier 912 commits):**
- `zstd` 0.13.3 → 0.13.4 (`RUSTSEC-2026-0391`)
- `zstd-safe` 7.3.0 → 7.4.0 (`RUSTSEC-2026-0398` and related)
- `rustix` 1.1.5 → 1.1.6 (`RUSTSEC-2026-0486`, unsound zero-length xattr buffer). Compatible patch; crate fetched and `agentlink-core` lib tests re-run (271 passed). After this bump, cargo-audit reports 12 unmaintained warnings and no longer lists rustix.

**Not upgraded (no compatible released patch in this tree):**
- `libsqlite3-sys` 0.30.1 — `RUSTSEC-2026-0459` (bundled SQLite before 3.54.0; local, UI:P, CVSS 6.8). Patched crate versions are `>=0.39.0`. Workspace `sqlx` 0.8.6 (and current stable 0.9.0) still require `<0.38`. Unreleased sqlx main would allow 0.39 but was not used. The workspace also depends on `libsqlite3-sys` 0.30.1 with `bundled` directly, so this is a real default-build exposure. System SQLite was not substituted as a silent policy change. **This remains an open vulnerability in the lock and in the compile tree** (`cargo tree -i libsqlite3-sys` reaches `agentlink-relay`).
- `rsa` 0.9.10 — `RUSTSEC-2023-0071` (Marvin). Patched in `>=0.10.0`. Present in `Cargo.lock` via optional `sqlx-mysql`. Workspace sqlx features do not enable mysql. `cargo tree -i rsa` prints nothing for the default tree and for `--all-features` (workspace crates do not enable `sqlx/mysql`). Lockfile presence is not “vulnerability fully solved”; cargo-audit on the full lock still fails because of it.

Unmaintained warnings (not treated as vulns, no compatible forced rewrite): `basic-toml` (`RUSTSEC-2026-0374`), `paste` (`RUSTSEC-2024-0436`), `pin-utils` (`RUSTSEC-2026-0441`), `rustls-pemfile` (`RUSTSEC-2025-0134`), `serial` (`RUSTSEC-2017-0008`), `ttf-parser` (`RUSTSEC-2026-0192`), and zbus 3.x/4.x / zvariant / zvariant_derive unmaintained advisories (`RUSTSEC-2026-0370/0371/0372`). `paste` remains lock-only for the default tree.

## Secret scan

Previously scanned the worktree and reachable blobs from the 912 freeze. This follow-up did not rewrite history and did not add credentials. Hits remain the AWS example fixtures in `crates/agentlink-core/src/s3.rs` only. Did not read `~/.config` or verify live credentials, and this report does not print secret values.

## Tests run (this machine, rustc 1.99.1, Asia/Shanghai)

Not claimed as Windows or macOS real-device verification. Android unit/source changes were not run on a phone or emulator.

| Command | Result |
| --- | --- |
| `cargo test -p agentlink-desktop --lib` | 112 passed (includes notification parameterization, Unicode AppleScript literals, grant-flag, forged client_id + known UUID handler, metadata sweep, relay-drop close, production UUID v4 ids, offer poison fail-closed) |
| `cargo test -p agentlink-node --lib` | 101 passed (includes grant-flag overwrite, PTY real `cat` owner/revoke entry, Alice cannot access Bob) |
| `cargo test -p agentlink-relay --lib` | 42 passed (legacy mint/gate/`created_unix=0`; QR allowlist including onclick/onload/spaced onerror) |
| `cargo test -p agentlink-ffi --lib` | 26 passed (real PTY UUID open; owner/revoke/expiry entry; poisoned policy; webrtc grant stamp) |
| `cargo test -p agentlink-core --lib` | 271 passed (after rustix 1.1.6; includes PTY open session UUID parsing) |
| `cargo test -p agentlink-view --lib` | 16 passed |
| `cargo test -p agentlink-view --test loopback` | 16 passed |
| `cargo test -p agentlink-node --test security` | 1 passed, exit 0 |
| `cargo test -p agentlink-node --test functional` | 6 passed (pairing/files/jail, PTY/search/edit/watch, transfers, two-client upload, desktop screenshot on this display) |
| `cargo test -p agentlink-cli --test relay_startup` | 3 passed (default start issues no admin token; enabled+TTL still mints) |
| `cargo test -p agentlink-cli --bin agentlink node_cfg` | 4 passed (missing vs corrupt vs unreadable vs valid `node.json`) |
| `cargo test -p agentlink-cli --test functional` | 3 passed |
| `cargo test -p agentlink-cli --test smoke` | 1 passed |
| `cargo test -p agentlink-cli --test controller_debug` | 6 passed (Terminal/Files/layout debug surface) |
| `cargo audit` on the full lock | exit 1; 2 vulnerabilities (libsqlite3-sys, rsa) and 12 unmaintained warnings |

`cargo test -p agentlink-cli --tests` as a single process aborted in `cp_progress_tests::cp_help_documents_progress` with a stack overflow (unrelated to these security changes). The targeted suites above still passed.

**Android:** JDK 17 (`/home/box/jdk/jdk-17.0.20.1+1`) and the SDK tree exist. `./gradlew testDebugUnitTest --offline` downloaded Gradle 8.11.1 but failed because Android Gradle Plugin 8.7.3 was not in the offline plugin cache. No phone or emulator was used. The Kotlin owner test is `android/app/src/test/java/app/agentlink/node/ShellSessionsOwnerTest.kt`.

## Untested / honest bounds

- Public NAT / cross-network P2P: still unproven.
- Windows and macOS: no real device in this step. AppleScript Unicode coverage is a strict literal/API unit test only.
- Android: no phone/emulator; Gradle plugin cache missing, so JVM unit tests were not executed here.
- Browser control remains disabled; not re-enabled.
- ICE LAN/VPN host candidates remain accepted on purpose.
- Bundled SQLite `RUSTSEC-2026-0459` and lockfile `rsa` `RUSTSEC-2023-0071` remain as described above.

## Parent next step

Stop here for the same independent reviewer. Do not push `main` from this step. After the quality gate, the parent may push this branch onto `main` as a normal fast-forward/merge of a candidate that already contains sealed `main` + t447 + t449 + these fixes.
