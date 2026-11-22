# Security Policy

## Reporting a Vulnerability

Do **not** open a public GitHub issue for suspected security vulnerabilities.

Report vulnerabilities privately through [GitHub Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository (Security → Report a vulnerability). Include:

- Affected component (`agentlink-relay`, `agentlink-node`, `agentlink-core`, `agentlink-desktop`, `agentlink-cli`, `agentlink-ffi`, or `android/`), commit SHA or version, and target OS.
- Minimal reproduction steps in an isolated environment.
- Never include real private keys, session tokens, `admin.token`, `bootstrap.password`, or unredacted production logs.

## Supported Versions

Agentlink is currently pre-1.0 (`0.1.x`). Security fixes land on `main`. Linux (`x86_64` / `aarch64`, both `gnu` desktop and `musl` headless) and Windows (`x86_64` / `aarch64`) are the primary targets; macOS and Android targets in-tree are experimental.

## Trust Model and Intentional Boundaries

Before reporting an issue, review [docs/e2e-auth.md](docs/e2e-auth.md) and [docs/grant-authorization-boundary.md](docs/grant-authorization-boundary.md). The following properties are intentional design boundaries:

1. **Relay is untrusted for sealed payloads, not for routing metadata.**
   - `Invoke`, `Cancel`, `Session` (replay cursor updates), and file-transfer control/chunks are fail-closed end-to-end encrypted (`X25519` with contributory check + `ed25519` transcript + `ChaCha20-Poly1305`, zeroized on drop). Unsealed plaintext data responses and cross-node responses are rejected on both client and node; unverified `E2eHello` handshakes are isolated in a bounded LRU table.
   - E2E frame AAD v2 authenticates full binary transfer frame headers (`version`, `kind`, non-E2E `flags`, `offset`, `raw_len`, and `request_id`). Direct QUIC P2P file transfer is disabled until E2E-sealed direct P2P lands; file bytes travel over the sealed relay WebSocket path. WebRTC desktop media uses `DTLS-SRTP`.
   - The relay enforces typed principals (`Admin`, `Operator`, `Agent`, `Web`), connection-bound routes, server-pinned `node_id` on `ApprovalRequest`/`AuditBatch`, and isolated `node-audit.jsonl` storage (mode `0600`, rotated). It observes connection metadata, coarse operation class (`read`, `write`, `exec`, `desktop`, `meta`), 40-byte binary frame headers, and (unless `forward.central` is disabled) cleartext approval summaries and forwarded audit records.
   - A relay login, admin role, or account share **never** authorizes node operations. Nodes verify an ed25519 `SignedGrant` against local `owner-keys.json` and `revoked-grants.json`, bound to the E2E peer public key and intersected with `--max-access`. Active PTYs, background processes, watches, TCP tunnels, and desktop streams are all bound to `(owner_peer, grant_jti, grant_exp_unix)` and torn down on expiry or revocation.
   - Client-side S3 audit encryption (`client_key_env`) fails closed if the `AGLKCSE1` envelope is missing and binds `{bucket}/{key}` in AES-256-GCM AAD.

2. **Node-name pinning (TOFU).**
   - Clients pin `node_name -> node_ed25519_id` on first observation (`node-pins.json`) so a compromised relay cannot silently swap a paired node's public key later. Manage pins with `agentlink pin list` / `agentlink pin rm <name-or-id>` (or in Android Settings). Verify fingerprints out of band for high-assurance setups.

3. **Same-UID full shell after an `exec` or `full` grant (accepted A2 model).**
   - Unauthenticated callers and callers without a valid `SignedGrant` for `exec`/`full` are strictly denied before any process or PTY starts.
   - Once an operator grants `exec` or `full` to a peer, commands run as the OS user hosting `agentlink node` (not inside an OS container, VM, `chroot`, or separate UID). A granted full shell inherently can read same-UID files—including `grant-issuer.json`—and issue further grants as that user.
   - `--root` confines all file, edit, tar-unpack, and transfer operations (using canonical symlink-chain checks and `O_NOFOLLOW`/reparse guards), while `limits.json` and `confirm.toml` (covering Unix and Windows destructive presets as well as transfer writes and edits) are operational guardrails against accidental misuse—**not** kernel sandboxes against an already-granted `exec` peer. Run the node under a dedicated unprivileged OS account or VM if you require isolation from host secrets.

4. **Desktop clipboard, consent, and terminal `OSC 52` / bracketed paste.**
   - Bidirectional Unicode text clipboard sharing runs only during an active `remote-control` desktop session (never in `remote-view`), is seeded at connect time to avoid leaking pre-existing clipboard contents, and is toggleable from the controller toolbar.
   - Desktop stream `ConsentMode::Prompt` is enforced without silent downgrade to `Notify`. Input audit logs redact key names and typed text previews.
   - Terminal `OSC 52` clipboard writes from remote PTY output are **disabled by default** in `agentlink controller` and bounded to 64 KiB with a visible notice if explicitly opted in by the user. Bracketed paste sanitizes all ESC (`0x1b`) and C1 CSI (`0x9b`) bytes before forwarding.

5. **Windows Secure Attention Sequence (`Ctrl+Alt+Del`).**
   - User-mode `SendInput` cannot synthesize `Ctrl+Alt+Del` to open the Windows security screen; Agentlink refuses that chord rather than claiming injection succeeded.

6. **Supply-chain, relay HTTP, and local-service hardening.**
   - `install.sh` and `install.ps1` enforce `https://` (`curl --proto '=https' --tlsv1.2` / redirect-checked URI validation), validate zip entries against zip-slip on Windows, and pre-check `minisign` before downloading archives, verifying `SHA256SUMS.minisig` against the pinned project key (`deploy/minisign.pub`). `agentlink update` verifies signatures in-process and prioritizes the build-time embedded pin over ambient disk files unless `--pubkey` is explicitly supplied.
   - Enrollment defaults to least-privilege `exec` rather than `full` desktop access. `agentlink mcp --http` binds loopback only by default (`--allow-remote-http` explicit opt-in) with Bearer auth and 401 rate limiting.
   - Relay authentication persists TOTP replay state (`last_totp_step`), revokes the device session family on refresh-token replay, supports `AGENTLINK_PUBLIC_URL` (with strict `Host` validation fallback), serves `/audit*` with full security headers (`CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`), and exposes `GET`/`HEAD /healthz` for health checks.
