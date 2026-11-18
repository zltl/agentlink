# Security Policy

## Reporting a Vulnerability

Do **not** open a public GitHub issue for suspected security vulnerabilities.

Report vulnerabilities privately through [GitHub Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository (Security → Report a vulnerability). Include:

- Affected component (`agentlink-relay`, `agentlink-node`, `agentlink-core`, `agentlink-desktop`, `agentlink-cli`, `agentlink-ffi`, or `android/`), commit SHA or version, and target OS.
- Minimal reproduction steps in an isolated environment.
- Never include real private keys, session tokens, `admin.token`, `bootstrap.password`, or unredacted production logs.

## Supported Versions

Agentlink is currently pre-1.0 (`0.1.x`). Security fixes land on `main`. Linux (`x86_64` / `aarch64`) and Windows (`x86_64` / `aarch64`) are the primary targets; macOS and Android targets in-tree are experimental.

## Trust Model and Intentional Boundaries

Before reporting an issue, review [docs/e2e-auth.md](docs/e2e-auth.md) and [docs/grant-authorization-boundary.md](docs/grant-authorization-boundary.md). The following properties are intentional design boundaries:

1. **Relay is untrusted for sealed payloads, not for routing metadata.**
   - `Invoke`, `Cancel`, and file-transfer chunks are end-to-end encrypted (`X25519` + `ed25519` transcript + `ChaCha20-Poly1305`). WebRTC media uses `DTLS-SRTP`.
   - The relay observes connection metadata, coarse operation class (`read`, `write`, `exec`, `desktop`, `meta`), 40-byte binary frame headers, and (unless `forward.central` is disabled) cleartext approval summaries and audit records.
   - A relay login, admin role, or account share **never** authorizes node operations. Nodes verify an ed25519 `SignedGrant` against local `owner-keys.json` and `revoked-grants.json`, bound to the E2E peer public key and intersected with `--max-access`.

2. **Node-name pinning (TOFU).**
   - Clients pin `node_name -> node_ed25519_id` on first observation (`node-pins.json`) so a compromised relay cannot silently swap a paired node's public key later. Verify fingerprints out of band for high-assurance setups.

3. **Same-UID full shell after an `exec` or `full` grant (accepted A2 model).**
   - Unauthenticated callers and callers without a valid `SignedGrant` for `exec`/`full` are strictly denied before any process or PTY starts.
   - Once an operator grants `exec` or `full` to a peer, commands run as the OS user hosting `agentlink node` (not inside an OS container, VM, `chroot`, or separate UID). A granted full shell inherently can read same-UID files—including `grant-issuer.json`—and issue further grants as that user.
   - `AGENTLINK_REMOTE_EXEC=1` and `--root` / command allow-deny lists are operational guardrails against accidental misuse, **not** kernel sandboxes against an already-granted `exec` peer. Run the node under a dedicated unprivileged OS account or VM if you require isolation from host secrets.

4. **Desktop clipboard and terminal `OSC 52`.**
   - Bidirectional Unicode text clipboard sharing runs only during an active `remote-control` desktop session (never in `remote-view`).
   - Terminal `OSC 52` clipboard writes from remote PTY output are **disabled by default** in `agentlink controller` and bounded to 64 KiB with a visible notice if explicitly opted in by the user.

5. **Windows Secure Attention Sequence (`Ctrl+Alt+Del`).**
   - User-mode `SendInput` cannot synthesize `Ctrl+Alt+Del` to open the Windows security screen; Agentlink refuses that chord rather than claiming injection succeeded.
