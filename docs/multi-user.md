# Accounts, sessions, and sharing

The relay keeps local accounts. A node is owned by the user who enrolled it. That user sees the node, and so does anyone they share it with. An admin sees every node. A legacy admin token still works and is treated as the `admin` user, so existing automation keeps its access. Prefer an account and TOTP for people. Rotate `admin.token` after any exposure. `AGENTLINK_LEGACY_ADMIN=0` disables the file token, and `AGENTLINK_LEGACY_ADMIN_TTL_SECS` expires it. Every accept and reject is written to the hash-chained audit log.

Sealed agent sessions and owner-signed grants (relay untrusted for authz) are covered in [e2e-auth.md](e2e-auth.md).

Passwords are stored as argon2id hashes. A login that fails five times locks the account for 15 minutes. The relay still runs one password check when the username does not exist, so a missing account does not return faster than a wrong password. Every login, failure, logout, share, and enrollment-token change is appended to the audit log with the user and device id. The audit log stays a hash-chained JSONL file. It is not stored in the database.

## Create the first admin

On the relay host:

```bash
agentlink relay user add admin --admin --password-stdin
```

If the user table is empty when `agentlink relay` starts, it also creates `admin`, prints the password once, and writes it to `bootstrap.password` (mode 0600) in the data directory. Changing that password deletes the file. If the file is still there after the change, delete it. Do not pass `--print-admin-token` in a systemd unit.

```bash
agentlink relay user list
agentlink relay user passwd admin --password-stdin
agentlink relay user disable alice
agentlink relay user enable alice
agentlink relay user set-role alice admin
agentlink relay user rm alice
```

These commands open the database directly. They do not listen on the relay port. `agentlink user ...` is the same set of operations over a logged-in admin session. Signup from the network stays off unless the relay is started with `--allow-signup`.

## Log in

```bash
agentlink login --user alice --relay wss://relay.example.com --fingerprint sha256:...
```

The command prompts for the password. `--password-stdin` reads it from stdin. `--totp` sends an authenticator code when the account has one. The client keeps an ed25519 device key in the config directory. The relay binds that key to the user and returns an access token plus a refresh token. The access token expires after 15 minutes, with a few minutes of clock-skew slack so a fast relay clock does not drop the open socket. The refresh token expires after 30 days of inactivity plus two days of clock-skew slack, and every refresh slides that window forward. Refresh rotates the token. If that response never reaches the client, the same refresh token can be presented again until the replacement access token is used. After that, the old refresh token is rejected. The refresh token is stored in `config.json` with mode 0600. Later commands send the access token and sign a challenge with the device key. When the access token is close to expiry, the CLI and MCP server refresh it. A network failure leaves the saved refresh token in place.

```bash
agentlink logout
agentlink devices
agentlink devices --revoke <device-id>
```

Revoking a device deletes its access tokens. The next request on an open socket is rejected.

```bash
agentlink user totp enable
agentlink user totp confirm 123456
agentlink user totp disable
```

## Nodes and shares

A node enrolled while the operator is logged in is owned by that user. `agentlink pair` mints an enrollment token for the logged-in user. Another user does not see the node. The owner, an admin, and anyone the owner has shared the node with get **full** access: shell, files, and desktop. There is no read-only / exec / desktop preset to pick, and no signed grant to paste.

```bash
agentlink share <node> --with bob
agentlink unshare <node> --with bob
```

A sharee cannot share the node further. `--access` is accepted and ignored. An agent identity registered with `agentlink client` belongs to the caller.

The Android app (`app.agentlink`) signs in with the same username, password, and optional TOTP. The server field starts empty; enter the relay URL. There is no built-in host. A session already saved on the phone keeps its server. After that login, opening a machine the account owns (or an admin opening any machine) is full access, including desktop. The phone does not import a grant file. The Ed25519 device key is generated in software. The 32-byte seed is sealed with an Android Keystore AES-256-GCM key and stored outside backups. Keystore implementations often reject Ed25519 (`NoSuchAlgorithmException` for provider `AndroidKeyStore`), including on API 33 and later, so sign-in does not ask the Keystore to generate that algorithm. A phone that already has an Ed25519 key in the Keystore keeps signing with it. The refresh token stays in EncryptedSharedPreferences, and the write is flushed before the app opens a socket with the new access token. A process killed before that write retries the previous refresh token. The phone refreshes the 15-minute access token when it opens and while it is in the foreground, including after the app was idle, and it does not clear that saved sign-in when the relay is unreachable or when the handset clock is a couple of days ahead of the stored deadline. A rejected refresh token, or one that has been unused past the inactivity window, is what asks for the password again. Log out and the device list use that session. After login the phone lists the user's own nodes and nodes shared with them.

Act as node enrolls the phone under that user. It signs `agentlink-enroll-v1` with the phone's node key, and the relay inserts the node under that user. No pairing token is consumed. The Add-machine QR (`agentlink://enroll?...`) is a separate path: it opens the node setup screen and does use the enrollment token.

## Add a machine from the browser

`https://relay.example.com/` is the dashboard. A self-hosted relay serves the same page at `GET /`. Sign in with the account username, password, and authenticator code. The session cookie is HttpOnly, Secure, and SameSite=Strict. A second cookie carries the CSRF token, and state-changing requests send it back in `X-CSRF-Token`. The CLI and the Android app keep using access and refresh tokens bound to a device key. The dashboard does not mint those tokens and does not keep a second user table.

The machine list shows name, online or offline, OS and architecture, and last seen. Refresh asks `/api/nodes` again. It does not reload the page. Each user sees the machines they own and the ones shared with them. An admin sees every machine. Connected access is full.

Each card has Terminal, Files, and Desktop. Desktop opens a watch-first browser session; Take control on that page drives the pointer and keyboard. A headless machine leaves Desktop off. Nothing on the card is disabled because of a preset.

Add machine asks for a name, a lifetime, and a use count. The page then shows one install command. Linux and macOS is the default. Windows is the same token in a PowerShell one-liner. The token is not put in the page URL. The new machine is full access for its owner. After the node connects it reports whether it has a graphical session. A headless machine keeps shell and files, and Desktop is not offered.

```bash
curl -fsSL https://relay.example.com/install.sh | sh -s -- --token '<T>' --name 'laptop' --access 'full' --max-access 'full'
```

That command downloads the binary, checks the checksum and the pinned minisign signature, installs the service, starts it, and enrolls with the token. `--access` and `--max-access` are accepted for older scripts; a connected owner is full either way. The dashboard fills in the host that served the page and pins that host's leaf certificate. There is no compiled-in relay that skips the pin. Set `AGENTLINK_CHECKSUM_ONLY=1` only when you intentionally skip the signature.

```powershell
& ([scriptblock]::Create((irm https://relay.example.com/install.ps1))) -Token '<T>' -Name 'laptop' -Access 'exec' -MaxAccess 'exec'
```

The Android QR is `agentlink://enroll?relay=...&fingerprint=...&token=...&name=...&access=...`. A blank relay in that link stays blank. An empty fingerprint selects public-root trust only together with a relay URL you set. The relay serves `install.sh` and `install.ps1` with the relay URL and enroll mode already filled in. In that mode `--token` is the enrollment token. `--dry-run` prints the plan and exits before any download. Binaries are served from `<data-dir>/dist` when present, and otherwise the relay redirects to the signed GitHub release asset. The phone app itself is `/download/agentlink.apk` on that same host.

`https://<relay>/view` is the desktop viewer when the URL fragment contains a ticket. Without a ticket it links back to the dashboard.

```bash
agentlink token create --name laptop --access read-only --ttl-minutes 15 --uses 1
agentlink token list
agentlink token revoke <id>
```

Tokens are single-use or N-use, expire, and can be revoked. They are scoped to the user who created them and to the preset on the token. The page lists pending, used, expired, and revoked tokens and updates the machine list over server-sent events.

## Audit

A user can query audit records for their own user id, their nodes, and their agents. An admin can query everything. Per-user audit policy is stored with `SetUserAudit` and is separate from the per-node policy. The hash chain is unchanged: records that predate the user field still verify, because the new fields are omitted when they are empty.
