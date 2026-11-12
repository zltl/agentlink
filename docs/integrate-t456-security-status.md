# t456 security integration status

Recorded 2026-11-12 (Asia/Shanghai). Local candidate only; this step did not push.

- Worktree: `/workspace/agentlink-integrate-t456`
- Branch: `integrate/security-main-t456`
- Baseline: `feat/controller-p2p-observe-t449` (`ebfb6f22cef5509fce923e77c5494a44a5d7d9f4`)
- Remote `main` (`602887281932d254d3d8ee1d57f8e3a305ab9bd6`) is a strict ancestor
- Frozen t452 controller bin left in place under `/workspace/agentlink-t427-recovery/20261112-1341-t452-controller-p2p/`
- Dirty source worktrees were not touched
- Repo visibility unchanged (private); no release; no GitHub Actions; no production deploy

Trust model is unchanged: a full current-user shell with a grant may read the same-UID issuer and countersign. The first request without a grant is still denied. Relay login is not target authorization. Public NAT P2P remains unproven.

## Review items

1. **P0 notification injection — fixed.** `consent.rs` builds a `NotifyPlan`. macOS uses a closed AppleScript string literal; Windows PowerShell reads `AGENTLINK_NOTIFY_BODY` from the environment and does not interpolate viewer/session into `-Command`; Linux uses argv. Unit tests (`notify_plan_does_not_turn_viewer_into_code_on_any_os` and quote/backslash cases) prove viewer text cannot form code. Consent default was not used as the only “fix”.

2. **P0 grant flags — fixed.** `fill_stream_grant_flags` (node and FFI) overwrites `_allow_view` / `_allow_control` from the verified grant/policy and strips client `_grant_jti` / `_grant_exp`. Missing `_allow_control` is no longer treated as true against a control ceiling. `session_allows_control` requires an explicit `true` plus a control-capable ceiling. Node stamps `_grant_jti` / `_grant_exp` from the verified grant.

3. **P1 live WebRTC revoke/expiry — fixed.** `LiveSession` records peer, grant jti, and expiry. `grant_active` is wired from `revoked-grants.json`. Revoke/expiry closes media and the datachannel (`close_sessions_for_jti` / `close_expired_sessions`), not merely in-flight RPCs or a test `NodePolicy::none()`. Later signaling and datachannel input re-check the grant. A single jti revoke leaves other sessions and a still-`full` ceiling alone.

4. **P1 PTY owner and session id — fixed.** Server generates a UUID session id (client request id is not the session file name). Write/resize/close are bound to the creator peer (E2E grantee, not the relay client_id). Windows temp `.cmd` names use only a UUID stem under `temp_dir()`. Android `ShellSessions` and FFI `PhonePty` also ignore client session ids and always allocate a UUID. `close_for_jti` / `close_expired` run from the daemon sweep.

5. **P1 signaling peer + unguessable ids — fixed.** `ice_restart`, `keyframe`, and `close` take the calling peer and call `require_session_grant`. New WebRTC session ids are UUID v4, not `{peer}-{millis}-{seq}`.

6. **P1 fail-closed policy/config — fixed.** Poisoned node policy lock denies the invoke/transfer (does not fall back to `NodePolicy::full()`). A present but invalid `node.json` `max_policy` refuses to start. A missing key (first run or a pre-`max_policy` file) still defaults to `full`, documented in `node_cfg.rs`.

7. **P1 legacy admin — fixed.** Disabled unless `AGENTLINK_LEGACY_ADMIN=1` (or `true`/`on`/`yes`/`enable`/`enabled`) **and** a positive `AGENTLINK_LEGACY_ADMIN_TTL_SECS` is set. Enabling without a TTL is rejected. Existing `admin.token` files are not rotated or rewritten. Integration tests pass an explicit `legacy_admin_override` on `RelayConfig` so they do not depend on process environment.

8. **P2 / release bounds**
   - **ICE address vs LAN:** host / RFC1918 candidates are still admitted so LAN and VPN paths work. This is not a claim that ICE spoofing is solved on untrusted networks.
   - **Missing ufrag:** a missing `usernameFragment` is still admitted so current viewers attach to the session they already own. Isolation is peer + session_id; a later generation is rejected when both sides present a ufrag.
   - **`qr_svg` innerHTML:** server output must pass `safe_qr_svg`; the dashboard uses `setTrustedSvg` (DOMParser, SVG namespace only, no script / `foreignObject` / event handlers). XML declarations from the qrcode crate are allowed.
   - **Disabled browser control:** the existing hard disable in the relay is unchanged.
   - **LICENSE:** `LICENSE-MIT`, `LICENSE-APACHE` (official Apache-2.0 text), and `NOTICE` match Cargo `MIT OR Apache-2.0`. Copyright line is “the Agentlink contributors”; no individual copyright holder was invented.

## cargo-audit (isolated, 2026-11-12)

Installed `cargo-audit 0.23.0` under `CARGO_HOME=/tmp/agentlink-audit-home` (not the user cargo config). Advisory DB loaded from rustsec (1471 advisories). `Cargo.lock` had 779 crate dependencies.

**Fixed in this candidate:**
- `zstd` 0.13.3 → 0.13.4 (`RUSTSEC-2026-0391`)
- `zstd-safe` 7.3.0 → 7.4.0 (`RUSTSEC-2026-0398`, `RUSTSEC-2026-0403`, and the related unsound 7.3.0 advisories that patch in `^7.4.0`)

Workspace `zstd = "0.13"` already allowed the compatible 0.13.4 bump. Core lib tests were re-run after the upgrade (270 passed).

**Not upgraded (API / tree break or no patch):**
- `libsqlite3-sys` 0.30.1 — `RUSTSEC-2026-0459`. Patched versions are `>=0.39.0`. It is pulled by `sqlx` 0.8.6 (`sqlx-sqlite`). A 0.39 bump is not a compatible upgrade of this sqlx line. Left unchanged.
- `rsa` 0.9.10 — `RUSTSEC-2023-0071` (Marvin). Patched in `>=0.10.0` (semver-incompatible). Present in `Cargo.lock` via `sqlx-mysql`. Workspace `sqlx` features do not enable mysql (`runtime-tokio`, `postgres`, `sqlite`, `migrate`, `macros`, `derive`); `cargo tree -i rsa` is empty for the default tree. Not bumped to 0.10.

Unmaintained / no-fix warnings observed (not silently treated as clean): `basic-toml` (`RUSTSEC-2026-0374`), `paste` (`RUSTSEC-2024-0436`), `pin-utils` (`RUSTSEC-2026-0441`), `rustls-pemfile` (`RUSTSEC-2025-0134`), `serial` (`RUSTSEC-2017-0008`), `ttf-parser` (`RUSTSEC-2026-0192`). No compatible fixed upgrade was available. Incomplete audit coverage is not a claim of “no vulnerabilities”.

## Secret scan

Scanned the worktree and 655 reachable blobs from `HEAD` (text, ≤1 MiB). Did not read `~/.config` or verify live credentials, and this report does not print secret values.

Hits: `crates/agentlink-core/src/s3.rs` only — AWS example test fixtures (`AKIAIOSFODNN7EXAMPLE` and a test `aws_secret_access_key` assignment). No history rewrite is required.

## Tests run (this machine, rustc 1.99.1, Asia/Shanghai)

Not claimed as Windows or macOS real-device RCE re-verification. Android unit/source changes were not run on a phone.

| Command | Result |
| --- | --- |
| `cargo test -p agentlink-desktop --lib` | 108 passed (includes notification parameterization, grant-flag, forged-peer, jti revoke with ceiling still full, expiry teardown, UUID session id tests) |
| `cargo test -p agentlink-node --lib` | 99 passed (includes grant-flag overwrite, PTY traversal stem, Alice cannot access Bob PTY record) |
| `cargo test -p agentlink-relay --lib` | 43 passed (legacy admin TTL required; `qr_svg` / trusted SVG helper) |
| `cargo test -p agentlink-ffi --lib` | 23 passed (including real PTY UUID open) |
| `cargo test -p agentlink-core --lib` | 270 passed (after zstd bump; includes 7 `ice::tests`) |
| `cargo test -p agentlink-view --lib` | 16 passed |
| `cargo test -p agentlink-view --test loopback` | 16 passed (no-grant reject, withdrawn grant on ice_pull, peer isolation) |
| `cargo test -p agentlink-desktop --test crossproc_ice` | 1 passed (isolated cross-process H.264 / pair; selected path was private host, not public NAT) |
| `cargo test -p agentlink-desktop --test x11_roundtrip` | 1 passed (this Linux X11 session, not a Windows/macOS device) |
| `cargo test -p agentlink-cli controller::` | 75 passed |

Prior 217-test collection is covered and slightly larger on the desktop lib (new security tests).

**Not completed:** `cargo test -p agentlink-node --test security` failed to link twice (`ld` / lld `signal 7` Bus error) while the disk was at 100% full (later freed 16+ GiB by deleting isolated `/tmp` cargo targets, not source trees). It was not re-run after space was restored. That is an environment blocker, not a recorded test failure.

## Untested / honest bounds

- Public NAT / cross-network P2P: still unproven.
- Windows and macOS: no real device in this step. Windows PTY path safety is unit-tested (path stem), not an on-device RCE retest.
- Android: `ShellSessions` always issues a UUID; no phone/emulator run here.
- Browser control remains disabled; not re-enabled.
- ICE LAN/VPN host candidates remain accepted on purpose.

## Parent next step

Stop here for independent review. Do not push `main` from this step. After the quality gate, the parent may push this branch onto `main` as a normal fast-forward/merge of a candidate that already contains sealed `main` + t447 + t449 + these fixes.
