# t456 security integration status

Recorded 2026-11-13 13:54 CST (Asia/Shanghai). Independent review of
SQLite candidate `ea69145` completed with **no source block**. User
t461 authorized an ordinary fast-forward of private source `main`
onto this line — not Actions, not a visibility change, not a
release, not a deploy, and not a production-machine upgrade. This
is not a full security or platform sign-off.

- Current worktree: `<workspace>/repo`
- Branch: `integrate/security-main-t456` at `ea6914525566f14e1a842fb301b32ac17adfc0e6`
  (fast-forwarded from previous live `main` `f4a336ee`; 667 merge
  parents `4fef74f7` and `79f3d63b` remain ancestors)
- Frozen 912 review tree (untouched): `<workspace>/repo` at `9122522b23846b2b6c31c640ef2928cb053dd994`
- Historical continuation worktree (not the current tip): `<workspace>/repo`
- Baseline: `feat/controller-p2p-observe-t449` (`ebfb6f22cef5509fce923e77c5494a44a5d7d9f4`)
- Live remote `main` re-verified 2026-11-13 13:54 CST (Asia/Shanghai) via
  `gh api repos/zltl/agentlink/git/ref/heads/main`:
  `f4a336ee1dcae1d55fa47fbe1512d9aa66f9edf8`, a strict parent of
  `ea69145`. A leftover `refs/remotes/origin/main` was not used as
  the live value. Earlier sealed `60288728` remains an ancestor.
- Repo visibility re-verified the same minute: **private**. `pushed_at`
  was still `2026-11-12T16:38:15Z` (2026-11-13 00:38:15 Asia/Shanghai).
- Frozen t452 controller bin left in place under `<workspace>/repo`
- UI source repo and the 7142 Linux GUI freeze were not modified in this
  docs step; no new GUI binary was built.
- No production machine was upgraded. No GitHub Actions. Not public. No
  release. No deploy. No production token was changed.

Trust model is unchanged: a full current-user shell with a grant may read the same-UID issuer and countersign. The first request without a grant is still denied. Relay login is not target authorization. Public NAT P2P remains unproven. Same-account grant bypass is not restored.

This revision addresses the independent review of `9122522`. Confirmed-good direction (parameterized notifications, flag overwrite, desktop owner UUID, legacy default off, QR client DOM filtering, license/no Actions) was kept and not reverted.

## Current tip `ea69145` — what is and is not claimed

This is a status snapshot of the fast-forwarded integrate tip
(`ea6914525566f14e1a842fb301b32ac17adfc0e6`, parent `f4a336ee`).
It does **not** declare security or platform work complete. The
`6674388` / `f4a336ee` notes below remain historical except where
this section updates them.

**UI (product through `7142d936`, four real-window rounds).** The last
two defects — Details focus rings and machine-row clip — passed on a
real window. 721 / 1024 / 1080 and max action cards at 2×2 did not
clip. Preview isolation and permission behavior matched the isolation
contract. Enter, mock View, Back, and exit passed. computerUse is
**partial**: preview has no Advanced tab to inspect; the complete Tab
order was not walked; different DPI and real (non-preview) sessions
were not tested. This is not a full GUI acceptance. Screenshots already
went to the user. Local evidence only (not an external URL):

- `<workspace>/repo`
  (durable copy of 352 webp captures, 2026-11-12 22:27–23:42 Asia/Shanghai)
- `/tmp/computer-use/` (original ephemeral path)
- Linux freeze used for that run:
  `<workspace>/repo`
  (also under `<workspace>/repo`)

`/tmp/t460-ui-inspect/user-controller-screenshot.png` is an earlier
`abf86f1` product shot, not the 7142 acceptance set.

**Workspace regression at `ea69145` (already recorded, not re-run for a later docs SHA).**
The same explicit 16 MiB command
`RUST_MIN_STACK=16777216 cargo +1.99.1 test --locked --offline --workspace --no-fail-fast -- --test-threads=1`
on the isolated candidate: **1550 passed, 0 failed, 2 pre-existing ignored**
(the 1548 recorded on `6674388` plus two new SQLite version / WAL /
old-schema tests). This is **not** a default test-thread green and
is **not** a full retest of a subsequent docs-only commit.

**Historical workspace regression at `6674388` (2026-11-13 00:24–00:29 Asia/Shanghai).**
The same command on an independent target: **1548 passed, 0 failed, 2 pre-existing ignored**
(`bench_transfer`, `agentlink-desktop` doc-test `capture.rs:11`),
`workspace_exit=0`. This is **not** a default test-thread green.
The default rustc test-thread stack (~2 MiB) still overflows in
`cp_progress_tests::cp_help_documents_progress` (`Cli::command` /
long help). The 7142 product binary
`<workspace>/repo`,
`ulimit -s=8192` (8 MiB OS main stack), `RUST_MIN_STACK` unset:
`agentlink --help`, `cp --help`, `help cp`, `exec --help`, and `-h`
all exited 0 with empty stderr. Product thread stacks were not raised
to 16 MiB; the help test source was not changed for a numeric green.

**Reconnect (`4fef74f7`, still on this tip).** Relay drop still stops
old shells, media, and inflight grant RPCs immediately (`stop_live_sessions`,
grant watcher, revoke). Those gates were not disabled. After the node
redials, a grant-checked fresh exec/PTY/MCP/watch can run, and
journaled `copy_upload`/`copy_download` may retry a `cancelled` result
only as a **new** grant-checked `open_data_link` while the client is
still alive. `Error::is_retryable` stays false for `cancelled`, so
exec/PTY are not silently rerun. A client without a grant, and a
revoked jti, stay denied after reconnect. Independent read-only
review of this copy-retry completed 2026-11-13 (Asia/Shanghai) with
no new block. Scope actually reviewed: 60s / backoff boundary;
retry only while alive, as a fresh request id with authorization
checks; journaled resume preserved; drop teardown still in place;
auth errors not retried; merge is the full union of both parents.
This is not a claim that Windows visual noflash, different DPI, a
full Tab-order walk, Android full build or phone, cross-network NAT
P2P, or cargo-audit findings are complete.

**no_console_flash (`4e677c86` + docs `79f3d63b`).** Static review
passed (13 sites classified, guard not relaxed; helper stays a visible
grant; no permission change). The merged workspace run of
`-p agentlink-cli --test no_console_flash` passed on Linux. Windows
visual “no console flash” behavior was **not** tested.

**Android / UniFFI.** Official `uniffi-bindgen` regeneration of
`android/app/src/main/java/uniffi/agentlink_ffi/agentlink_ffi.kt`
against the 8143 `libagentlink_ffi.so`, plus signature/type checks,
already landed (`8df767aa` and follow-ups). That work is done in
source. An Android **full build** and a **phone/emulator** run were
not done. This is not a bindgen deferral, and it is not an Android
device sign-off.

**Windows ConPTY resize / Enter handshake** (`40f551c`, `ac33c12` and
follow-ups) still waits for an offline Windows probe retest. Linux
passing is not Windows evidence.

**NAT P2P** has not been proven across a real NAT / public network.

**SQLite `RUSTSEC-2026-0459` on this tip.** Product commit `ea69145`
pins official unpublished `launchbadge/sqlx` at merge commit
`10462fa4414c6c7f1ed1d39bb31678e3b726878c` (#4502) and crates.io
`libsqlite3-sys` `=0.39.1` (bundled SQLite 3.54.1; not 0.40.0; SQLCipher
not enabled). Independent review found no source block:
`AssertSqlSafe` is used only after literal placeholder `adapt()` and
after `validate_schema`. Isolated synthetic-db tests (not a production
database) checked `sqlite_version() == 3.54.1` and the official
e5bf1198 amalgamation `memset(pOut+sz, 0, nOut-sz)` in
`sqlite3WalReadFrame`. A fresh cargo-audit (advisory-db
`af7b3ec3`, 2026-11-12) exit 0 no longer lists `RUSTSEC-2026-0459`.
This is **not** a claim that crates.io sqlx 0.9.0 already allows
0.39 (it still does not). The tip depends on that unpublished official
git rev. `rsa` / `RUSTSEC-2023-0071` is absent from this lock because
sqlx 0.9 no longer pulls it via mysql — that is not a patch of a
remaining `rsa` crate. cargo-audit still reports **12 unmaintained
warnings** (not a full-green audit). Real Postgres, Windows, and
Android were not tested. Mitigations of file mode are not the fix;
the fix is the 3.54.1 amalgamation.

Production machines were not upgraded. No Actions, no public repo, no
release, no deploy. A later docs-only SHA is not a product retest.

Trust model is unchanged: a full current-user shell with a grant may
read the same-UID issuer and countersign. The first request without a
grant is still denied. Relay login is not target authorization.
Same-account grant bypass is not restored.

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
- `libsqlite3-sys` 0.30.1 — `RUSTSEC-2026-0459` (bundled SQLite before 3.54.0; local, UI:P, CVSS 6.8). This was the state of the 912 / `f4a336ee` line. **Superseded on current tip `ea69145`** (official sqlx #4502 git rev + `libsqlite3-sys` 0.39.1 / SQLite 3.54.1). See the current-tip SQLite section. crates.io sqlx 0.9.0 still requires `<0.38` and was not the path used.
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

**Android:** JDK 17 (`<sdk-home>`) and the SDK tree exist. `./gradlew testDebugUnitTest --offline` downloaded Gradle 8.11.1 but failed because Android Gradle Plugin 8.7.3 was not in the offline plugin cache. No phone or emulator was used. The Kotlin owner test is `android/app/src/test/java/app/agentlink/node/ShellSessionsOwnerTest.kt`.

## Untested / honest bounds

- Public NAT / cross-network P2P: still unproven.
- Windows: a later probe built frozen `cd30c9e` in-tree (debug) and ran `agentlink-node --lib` (81 pass / 4 fail of 85), `agentlink-desktop --lib` (75), `agentlink-ffi --lib` (24), `security` (1), `functional` (5 pass / 1 skip true-desktop), CLI controller (75), `node_cfg` (4, but `unreadable_node_json_fails_closed` was a Unix-only no-op). The four lib failures (`\\?\` cwd, locale `os error 3` path tips, absolute filename pattern with backslashes) are addressed in the residual delta below and need a Windows re-run of that new freeze; they were not marked green by relaxing assertions. macOS was not run. AppleScript Unicode coverage is a strict literal/API unit test only.
- Android: no phone/emulator; Gradle plugin cache missing, so JVM unit tests were not executed here.
- Browser control remains disabled; not re-enabled.
- ICE LAN/VPN host candidates remain accepted on purpose.
- Bundled SQLite `RUSTSEC-2026-0459` and lockfile `rsa` `RUSTSEC-2023-0071` remain as described above.

## Parent next step

Stop here for the same independent reviewer. Do not push `main` from this step. After the quality gate, the parent may push this branch onto `main` as a normal fast-forward/merge of a candidate that already contains sealed `main` + t447 + t449 + these fixes.

## Post-cd30 residual delta (`8143d2ee`, not a rewrite of `cd30c9e`)

Incremental work on `integrate/security-main-t456` after the second review confirmed the core P1 fixes in `cd30c9e`. This commit is a small follow-up; `cd30c9e` is not amended.

- Transfer `ensure` / `ensure_exec` (node and FFI) and desktop `offer()` consent: a poisoned policy/consent lock is fail-closed (`node policy is unavailable` / `stream consent is unavailable`). No `max_policy` / `into_inner` ceiling fallback. Unit tests cover both transfer entries and a poisoned consent lock.
- Public FFI `poll_session` / `session_input` / `close_session` take a trusted caller (the sealed E2E peer recorded at open). An empty caller is rejected. In-process cleanup uses a Rust-minted release token and `release_session`, not an id-only UniFFI close. Alice cannot poll, read, or close Bob's session. Kotlin `ShellSessions` / `AndroidHost` and `ShellSessionsOwnerTest` follow the same rule. Internal UI session handles (`handle.poll()`) are unchanged.
- `spawn_grant_watch` has a production-loop integration test: a real `cat` PTY plus an injected stream session, no inflight RPC index and no new incoming, close within 1s after `revoked-grants.json` is written; a post-create revoke is either rejected on open re-check or closed by the same watcher.
- SQLite: default remains bundled `libsqlite3-sys` 0.30.1 / sqlx 0.8.6 (advisory still open; no default switch, no `--ignore`, no third-party fork). Relay data dir stays 0700; `relay.db` / `-wal` / `-shm` are restricted after open; untrusted `sqlite://` URLs stay rejected; `store.json` import is operator-local only. `rsa` remains lockfile-unreachable for the workspace feature set; cargo-audit still exits 1 with that finding plus 12 unmaintained warnings (not reported as zero).
- Windows portability (found on the `cd30c9e` probe, fixed here, not hidden): `resolve_path` / `resolve_lexical` strip the `\\?\` prefix so a sandbox cwd is comparable to `C:\…` and usable as a process directory; missing cwd and “path below a file” use structured classification that covers Windows `ERROR_PATH_NOT_FOUND` (3) and Chinese OS sentences; filename search matches an absolute pattern after slash-normalizing backslashes (literal path equality first). `node_cfg` unreadable coverage uses a directory-occupying path on every OS, plus a Windows exclusive share-lock fixture (no operator ACL changes). Real ConPTY tests cover UTF-8 session output (`你好` through the PTY, not just file I/O), child-visible resize (`stty size` / `mode con`), and a non-zero PTY exit code 9.


### Residual tests on this box (rustc 1.99.1, Asia/Shanghai, 2026-11-12)

`CARGO_TARGET_DIR=<workspace>/repo`, `CARGO_INCREMENTAL=0`, `--offline`. Not a full workspace rebuild. Not a Windows or Android run of this tree.

| Command | Result |
| --- | --- |
| `cargo test -p agentlink-core --lib` | 272 passed (includes verbatim-prefix strip, `is_not_found` / os error 3, diagnose-below-a-file) |
| `cargo test -p agentlink-node --lib` | 106 passed (was 101): the four cd30 Windows-failing tests pass here; `spawn_grant_watch` production loop; real PTY Unicode/`stty size`/exit 9; transfer poison fail-closed) |
| `cargo test -p agentlink-desktop --lib` | 113 passed (was 112): poisoned consent lock fail-closed) |
| `cargo test -p agentlink-ffi --lib` | 28 passed (was 26): Alice cannot poll/close Bob; FFI transfer poison fail-closed) |
| `cargo test -p agentlink-relay --lib` | 43 passed (was 42): `relay.db` / WAL mode 0600; `sqlite://` URL rejected) |
| `cargo test -p agentlink-cli --bin agentlink node_cfg` | not re-run here (avoid a large CLI relink). The unreadable test is no longer a Windows no-op. |
| `cargo audit` | not re-run; lock unchanged. Still expected exit 1: `libsqlite3-sys` `RUSTSEC-2026-0459`, lockfile `rsa` `RUSTSEC-2023-0071`, 12 unmaintained warnings. |

UniFFI `NodeHost` signatures changed in Rust and in hand-written Kotlin (`AndroidHost`, `ShellSessions`, owner tests) in `8143d2ee`. Generated `agentlink_ffi.kt` was still id-only in that commit (`uniffi-bindgen` was interrupted mid-compile of the `cli` binary; NDK was not the blocker). Regeneration is recorded in the follow-up section below. The Rust `HostSessionRegistry` (sealed peer + release token) is the authoritative gate.

No controller / desktop UI files were changed in `8143d2ee`. A separate worker is doing the t460 layout redo from `cd30c9e` in an isolated worktree.

Windows probe should re-run the `8143d2ee` freeze (not `cd30c9e`) against the existing Windows target. Production `abf86f1` was not touched. The Android binding follow-up does not change Windows sources, so that 8143 regression boundary stays valid.

Do not push `main` from this executor step. The parent will do a read-only delta review and a normal push after the UI worker lands and the final gate.

## Post-8143 UniFFI Kotlin regenerate (this commit, not a rewrite of `8143d2ee`)

Official path from `android/build-native.sh` lines 21–26, **without** the NDK `cargo ndk` half (lines 28–34). Kotlin generation does not need a phone or NDK: it is `uniffi-bindgen generate --library <host debug libagentlink_ffi.so> --language kotlin --no-format --out-dir android/app/src/main/java`. The previous bindgen attempt stopped because `cargo run -p agentlink-ffi --features cli --bin uniffi-bindgen` was interrupted after ~14s while still compiling `uniffi_bindgen` / clap; no `uniffi-bindgen` binary had been produced yet.

The existing `<workspace>/repo` (mtime 2026-11-12 21:17:03 CST, Asia/Shanghai, 273 MiB) was verified against 8143 before generate: it is linked from `<workspace>/repo`, newer than all `crates/agentlink-ffi/src/*.rs` on that tree, exports `release_session`, and its UniFFI checksums were read from the `.so` (`poll_session` 44778, `close_session` 24950, `session_input` 4154, `release_session` 47851, `open_session` 63923). Those differ from the stale generated file (`poll_session` 29093, no `releaseSession`). After building only the missing `uniffi-bindgen` binary (`cargo build -p agentlink-ffi --offline --features cli --bin uniffi-bindgen`, 26s, reused `CARGO_TARGET_DIR`, no ffi lib rebuild — `.so` mtime unchanged), official generate wrote `agentlink_ffi.kt`. All 57 generated checksum comparisons match the same `.so`. The generated file was not hand-edited.

Hand-written call sites already matched the new trait; no Kotlin/Rust call-site edits in this commit:

- `NodeHost.pollSession(sessionId, caller)` / `sessionInput(..., caller)` / `closeSession(..., caller)` / `releaseSession(sessionId, release)`
- `AndroidHost` overrides those exact signatures and forwards `caller` / `release` into `ShellSessions`
- `ShellSessions` records `_owner_peer` at open (required; empty rejected), gates poll/input/resize/close with `requireOwner`, and `release()` only accepts the Rust-minted token — not an owner-string bypass
- Trusted caller is `seal.peer` after E2E policy resolution in `node.rs` dispatch (`peer = grantee`); `run_exec` stamps `_owner_peer` and a Rust-minted `release` into the host open payload; `poll_until_end` calls `HostSessionRegistry::authorize_caller` before `poll_session`; in-process cleanup uses `take_release` then `release_session`. Public poll/close are not UI-writable owner strings. Interactive PTY input/resize/close stay on the Rust `PhonePty` path with `Some(peer)`. Internal UI session handles (`handle.poll()`) are unchanged.

Typecheck / unit status (Asia/Shanghai, 2026-11-12):

- Standalone `kotlinc` (Gradle 8.11.1 already-cached `kotlin-compiler-embeddable` 2.0.20 + stdlib, JDK 17) compiled an extracted `NodeHost` interface plus `AndroidHost` override stubs: exit 0. This checks signature sync only, not the full generated JNA file or Android SDK types.
- AGP 8.7.3 and `org.jetbrains.kotlin.android` 2.0.21 are **not** in `<sdk-home>`. `./gradlew` test/compile would need a large plugin + AndroidX/Robolectric download; that was not started (disk ~15G free). Robolectric `ShellSessionsOwnerTest` was not executed here. Android compile of the full app is therefore **untested** on this box.
- No known inevitable Kotlin compile error remains between the generated trait and hand-written implementors/tests.

No Windows sources changed; the 8143 Windows retest does not need a full re-run for this commit. Controller/UI was not touched. SQLite `RUSTSEC-2026-0459` remains accurately documented; cargo-audit is still expected exit 1 (bundled `libsqlite3-sys`, lockfile `rsa`, 12 unmaintained warnings). This executor does not push `main`.

## Post-8df ConPTY resize test (this commit, not a rewrite of `8df767a` or `8143d2ee`)

Windows verification of `8143d2ee` (logs at `<win-workspace>\verify.log`) went green on the four earlier lib failures, Unicode ConPTY, exit code 9, desktop 76, ffi 26, node 89/1 fail, security 1, functional 5 (1 skip true-desktop), controller 75, and nodecfg 4. The remaining main-gate failure is `real_pty_resize_changes_child_winsize` (not skipped).

Source diagnosis from the reported transcript, before any production change: after `READY`, the host transcript contained `ESC[8;30;100t` (ConPTY/xterm window-resize advertisement on the **host** pipe). `wait_transcript_contains(..., "30")` can return on that CSI alone. `mode con` on Chinese Windows does not print English `Lines`/`Columns`, and cmd prompt redraws (script path, a second `READY`, many `ESC[K`) are not a child size reading. Production `PtyManager::resize` already calls `portable-pty` `MasterPty::resize` → `ResizePseudoConsole` (`portable-pty` 0.8.1). This commit does **not** change that production path; Linux passing is not Windows evidence that the child window actually changed.

The test now:

- Waits for complete sentinels `AL_READY` / `AL_DONE` as whole lines after stripping CSI (never a bare `"30"`).
- Snapshots a structured **before** size at `AL_READY`, then resizes, then waits for `AL_DONE` and parses **after**.
- On Windows, compiles a tiny `GetConsoleScreenBufferInfo` helper (`rustc` of an in-test source) and prints `dwSize.X/Y` and `srWindow.cols/rows` separately. No `mode con`, no cmd `set /p` script loop.
- On Unix, `stty size` (TIOCGWINSZ) is printed as `winsize.cols/rows` (no separate buffer).
- Asserts window/winsize is `80x24` before and `100x30` after. Host CSI is not accepted as proof.

Linux (this box, rustc 1.99.1, Asia/Shanghai, 2026-11-12, reused target, `--offline`): `cargo test -p agentlink-node --lib --offline real_pty_` → 4 passed (resize, unicode, exit 9, owner/revoke entry), 0 failed, 102 filtered. Windows must re-run this freeze on the existing Windows target; if it fails, the assertion text should include the `AL_SIZE_BEFORE` / `AL_SIZE_AFTER` lines (and any `ERR GetConsoleScreenBufferInfo`).

`8df767a` generated Kotlin is unchanged. Controller/UI and production `abf86f1` were not touched. The review finding that `poll_until_end` does not `close_quiet` on a normal `"exit"` (registry / Android `ShellSessions` map can remain) is still open: it is FFI host-session lifecycle, not this ConPTY test, and was left out of this small delta.

SQLite `RUSTSEC-2026-0459` remains accurately documented; cargo-audit is still expected exit 1. This executor does not push `main`.

## Post-40f551c ConPTY Enter handshake (this commit, not a rewrite of `40f551c`)

Windows probe of `40f551c` compiled the size helper and printed `AL_SIZE_BEFORE` 80x24 plus `AL_READY`. After resize the host transcript had `ESC[8;30;100t` and a redraw of the old BEFORE/READY lines, but no `AL_SIZE_AFTER` / `AL_DONE` (`wait_transcript_sentinel` timed out at 8s). The test wrote a bare LF; Windows cooked console input completes a line on CR (Enter).

This commit does not change production resize. On Windows the handshake write is `\r\n`; Unix stays `\n`. The Windows helper waits for CR or LF before reading `GetConsoleScreenBufferInfo` again. Assertions are unchanged: window/winsize must be `80x24` before and `100x30` after, with `AL_DONE`. Not run on this box (no rustc 1.99). Windows worker retest is required.

## Post-6674388 status snapshot

Historical. The product merge tip after UI / reconnect / noflash was
`6674388`, then docs `f4a336ee` became live `main`. See **Current tip
`ea69145`** for the live snapshot.

## Post-ea69145 status snapshot

The product tip is `ea6914525566f14e1a842fb301b32ac17adfc0e6` (parent
`f4a336ee`). Later docs-only commits record status and are not a full
product retest. Independent review found no source block. Existing
16 MiB workspace tests on `ea69145` are 1550 / 0 / 2 ignored. GUI
computerUse remains partial; Windows visual noflash, Windows AC
resize, Android full build and phone, cross-network NAT P2P, and a
real Postgres run were not tested. cargo-audit on this lock is exit 0
for `RUSTSEC-2026-0459` but still has 12 unmaintained warnings; rsa
is absent from this lock (not a residual-rsa patch). Production
machines were not upgraded; no Actions, not public, no release, no
deploy. User t461 authorized an ordinary private source-main
fast-forward only.

