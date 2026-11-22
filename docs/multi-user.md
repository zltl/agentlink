# Accounts, sessions, and sharing

The relay keeps local accounts. A node is owned by the user who enrolled it. That user sees the node, and so does anyone they share it with. An admin sees every node. The legacy admin file token is disabled by default and is treated as the `admin` user only when `AGENTLINK_LEGACY_ADMIN=1` and `AGENTLINK_LEGACY_ADMIN_TTL_SECS` are both set. Existing token files are left in place and are not rewritten. Prefer an account and TOTP for people. Every accept and reject is written to the hash-chained audit log.

Sealed agent sessions and owner-signed grants (relay untrusted for authz) are covered in [e2e-auth.md](e2e-auth.md).

Passwords are stored as argon2id hashes. A login that fails five times locks the account for 15 minutes. The relay still runs one password check when the username does not exist, so a missing account does not return faster than a wrong password. TOTP step numbers are persisted in the database (`last_totp_step`) to prevent code replay across restarts. Every login, failure, logout, share, and enrollment-token change is appended to the relay's hash-chained `audit.jsonl` (mode `0600`, size-rotated) with the user and device id. Node-authored audit batches are isolated in `node-audit.jsonl` so a compromised node cannot corrupt the relay's auth chain or spoof another user's records.

## Create the first admin

On the relay host:

```bash
agentlink relay --data-dir /var/lib/agentlink user add admin --admin --password-stdin
```

If the user table is empty when `agentlink relay` starts, it also creates `admin`, prints a one-time bootstrap password once, and writes it to `bootstrap.password` (mode `0600`) in the data directory. Rotate that password immediately; changing it deletes `bootstrap.password`. If the file is still there after the change, delete it. Do not pass `--print-admin-token` in a systemd unit.

```bash
agentlink relay --data-dir /var/lib/agentlink user list
agentlink relay --data-dir /var/lib/agentlink user passwd admin --password-stdin
agentlink relay --data-dir /var/lib/agentlink user disable alice
agentlink relay --data-dir /var/lib/agentlink user enable alice
agentlink relay --data-dir /var/lib/agentlink user set-role alice admin
agentlink relay --data-dir /var/lib/agentlink user rm alice
```

These commands open the database directly. They do not listen on the relay port. `agentlink user ...` is the same set of operations over a logged-in admin session. Self-service password changes (`UserPasswd`) and `TotpDisable` require an operator session with current password + TOTP re-authentication (when TOTP is enabled); registered agent keys (`agentlink client create`) are blocked from changing user passwords or altering node policies. Signup from the network stays off unless the relay is started with `--allow-signup`.

## Log in

```bash
agentlink login --user alice --relay wss://relay.example.com --fingerprint sha256:...
```

The command prompts for the password (supporting terminal paste and non-TTY stdin). `--password-stdin` reads it from stdin. `--totp` sends an authenticator code when the account has one. The client keeps an ed25519 device key in the config directory. The relay binds that key to the user and returns an access token plus a refresh token. The access token expires after 15 minutes, with a few minutes of clock-skew slack so a fast relay clock does not drop the open socket. The refresh token expires after 30 days of inactivity plus two days of clock-skew slack, and every refresh slides that window forward. Refresh rotates the token. If that response never reaches the client, the same refresh token can be presented again until the replacement access token is used. Replaying an already-acknowledged or revoked refresh token revokes the entire device session family. The refresh token is stored in `config.json` with mode `0600`. Later commands send the access token and sign a challenge with the device key. When the access token is close to expiry, the CLI, controller, and MCP server refresh it automatically (`agentlink status` shows `refreshable` rather than forcing a re-login). A network failure leaves the saved refresh token in place.

```bash
agentlink logout
agentlink devices
agentlink devices --revoke <device-id>
```

Revoking a device deletes its access tokens and prevents re-use of its refresh tokens. The next request on an open socket is rejected.

```bash
agentlink user totp enable
agentlink user totp confirm 123456
agentlink user totp disable
```

## Nodes and shares

A node enrolled while the operator is logged in is owned by that user. `agentlink pair` mints a one-time enrollment token and an `agentlink-invite:v1:...` string for the logged-in user. Another user does not see the node unless it is shared with them.

**Relay ownership, admin role, and shares control discovery and routing only — they do not authorize operations on the node.** Every controller (owner, admin, sharee, or registered agent key) must present a time-bounded ed25519 `SignedGrant` verified locally by the node against its `owner-keys.json` and `revoked-grants.json`, bound to that controller's E2E device key and intersected with the node's `--max-access` ceiling. See [e2e-auth.md](e2e-auth.md).

```bash
agentlink share <node> --with bob
agentlink unshare <node> --with bob
```

A sharee sees the node in `agentlink ls` and can dial an E2E session through the relay once the node operator issues a `SignedGrant` for the sharee's controller key (`agentlink grant issue <node> --grantee <bob-pubkey-hex> --policy ...` or `grant offer` / `grant paste`). A sharee cannot share the node further. An agent identity registered with `agentlink client create` belongs to the caller, connects without an operator token (`agentlink --identity bot.identity.json ...`), and likewise requires a node-local `SignedGrant` for its public key.

The Android app (`app.agentlink`) signs in with the same username, password, and optional TOTP. The relay URL field is visible on first sign-in (starting empty — there is no built-in host). A session already saved on the phone keeps its server. After login the phone lists the user's own nodes and nodes shared with them; controlling a machine still requires a `SignedGrant` for the phone's device key (viewable and importable in Settings / Machine Hub). The Ed25519 device key is generated in software and sealed with Android Keystore AES-256-GCM outside backups; session/pairing secrets are stored using Android Keystore AES-GCM (with automatic recovery to login if a keyset is corrupted). The phone refreshes the 15-minute access token in place without tearing down active Terminal or Desktop sessions, manages TOFU node pins via Rust `node-pins.json` (with in-app pin reset and grant/device management), and automatically fetches short-lived TURN/ICE credentials from `POST /api/ice` via Bearer auth.

Act as node enrolls the phone under that user. It signs `agentlink-enroll-v1` with the phone's node key, and the relay inserts the node under that user. No pairing token is consumed. The Add-machine QR (`agentlink://enroll?...`) is a separate path: it opens the node setup screen and does use the enrollment token.

## Add a machine from the browser

`https://relay.example.com/` is the dashboard. A self-hosted relay serves the same page at `GET /`. Sign in with the account username, password, and authenticator code. The session cookie is HttpOnly, Secure, and SameSite=Strict. A second cookie carries the CSRF token, and state-changing requests send it back in `X-CSRF-Token`. The CLI and the Android app keep using access and refresh tokens bound to a device key. The dashboard does not mint those tokens and does not keep a second user table.

The machine list shows name, online or offline, OS and architecture, and last seen. Refresh asks `/api/nodes` again. It does not reload the page. Each user sees the machines they own and the ones shared with them. An admin sees every machine. Seeing a machine is not permission to control it.

Cards do not open a terminal, files, or a desktop. Those actions need a sealed client and a valid `SignedGrant` trusted by the node.

Add machine asks for a name, a lifetime, and a use count. The page then shows one install command. Linux and macOS is the default. Windows is the same token in a PowerShell one-liner. The token is not put in the page URL. Enrollment does not grant remote control. After the node connects it reports whether it has a graphical session for sealed desktop clients.

```bash
curl -fsSL --proto '=https' --tlsv1.2 https://relay.example.com/install.sh | \
  env AGENTLINK_TOKEN='<T>' sh -s -- --name 'laptop' --access 'exec' --max-access 'exec'
```

That command enforces HTTPS, pre-checks `minisign` before downloading, verifies `SHA256SUMS` + `SHA256SUMS.minisig` with the pinned project key, installs the binary (pass `--desktop` on Linux for the glibc GUI build or `--headless` for the static musl build), installs and starts the service, and enrolls with the one-time token (`AGENTLINK_ENROLL=1` in the relay-served script maps `AGENTLINK_TOKEN` to the enrollment token). `--access` and `--max-access` default to `exec` (pass `full` when desktop capture/control is desired) and never bypass node-local `SignedGrant` verification. Set `AGENTLINK_PUBLIC_URL` on the relay behind reverse proxies so generated install URLs do not rely on the `Host` header.

```powershell
$env:AGENTLINK_TOKEN='<T>'; & ([scriptblock]::Create((irm https://relay.example.com/install.ps1))) -Name 'laptop' -Access 'exec' -MaxAccess 'exec'
```

On Windows, `install.ps1` stops any running tray/service gracefully before replacing `%LOCALAPPDATA%\agentlink\agentlink.exe` (and `agentlink-gui.exe` when present), validates zip entries against zip-slip, and appends `%LOCALAPPDATA%\agentlink` to User `PATH` (`-NoPath` / `AGENTLINK_NO_PATH=1` to opt out).

You can also pass a one-time invite directly to either installer (`--invite` / `AGENTLINK_INVITE` or `-Invite` / `AGENTLINK_INVITE`) without manually copying `--relay` or `--fingerprint`.

The Android QR is `agentlink://enroll?relay=...&fingerprint=...&token=...&name=...&access=...`. A blank relay in that link stays blank. An empty fingerprint selects public-root trust only together with a relay URL you set. The relay serves `install.sh` and `install.ps1` with the relay URL and enroll mode already filled in. `--dry-run` prints a redacted plan and exits before any download. Binaries are streamed asynchronously from `<data-dir>/dist` when present, and otherwise the relay redirects to the signed GitHub release asset. The phone app itself is `/download/agentlink.apk` on that same host.

`https://<relay>/view` explains that browser control is not available. It does not open a desktop.

```bash
agentlink token create --name laptop --access read-only --ttl-minutes 15 --uses 1
agentlink token list
agentlink token revoke <id>
```

Tokens are single-use or N-use, expire, and can be revoked. They are scoped to the user who created them and to the preset on the token. The page lists pending, used, expired, and revoked tokens and updates the machine list over server-sent events.

## Audit

A user can query audit records for their own relay auth events and for nodes they own or have visibility into. An admin can query everything. Node-submitted `AuditBatch` records have `node_id` overwritten from the authenticated WebSocket identity, are stored in `node-audit.jsonl` separately from the relay's `audit.jsonl` auth chain, and are filtered strictly by visible `node_id` so one tenant's compromised node cannot inject spoofed records into another user's audit view. Per-user audit policy is stored with `SetUserAudit` and is separate from the per-node policy.
