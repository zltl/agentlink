# Deploy the relay

The relay listens for TLS on one TCP port. Nodes and clients dial out to it. Nothing on the node listens. The default database is a SQLite file at `<data-dir>/relay.db` in WAL mode. Set `AGENTLINK_DATABASE_URL` or `--database-url` to a `postgres://` URL to use PostgreSQL instead. A relay you host can use PostgreSQL 18 on `127.0.0.1:5432`, database `agentlink`, role `agentlink`.

The same repository API is compiled into the binary for both engines. Migrations ship inside the binary and run on startup. An existing `store.json` is imported once and renamed to `store.json.bak`. The audit JSONL file is not imported into the database.

```bash
agentlink relay --bind 0.0.0.0:7443 --data-dir /var/lib/agentlink
```

The first start generates `cert.pem` and `key.pem`. It does not mint or write `admin.token` unless legacy admin is explicitly enabled (see [Legacy admin token](#legacy-admin-token)). When the user table is empty, the first start also prints a one-time password for the `admin` account and writes `bootstrap.password` (mode `0600`). Change it immediately:

```bash
agentlink relay --data-dir /var/lib/agentlink user passwd admin
```

That change deletes `bootstrap.password`. If the file is still there after the change, delete it. Do not leave the bootstrap password on disk.

## Health check and Docker image

The relay serves `GET /healthz` and `HEAD /healthz` over its HTTPS listener, returning `200 OK` with `{"status":"ok"}` (and security headers) for container orchestrators, reverse proxies, and uptime monitors.

The provided `Dockerfile` builds a headless relay binary with `cargo build --locked --release -p agentlink-cli --no-default-features` (omitting the default GUI `controller` feature so the runtime image has no `eframe`, OpenH264, or `libstdc++6` dependency), runs as a non-root `agentlink` user, and includes a `HEALTHCHECK` against `https://127.0.0.1:7443/healthz`. `docker-compose.yml` mirrors that health check and documents optional `AGENTLINK_PUBLIC_URL`, `AGENTLINK_DATABASE_URL`, and TURN environment variables.

## Relay data directory and SQLite

`<data-dir>` is created mode `0700` (`util::ensure_dir`). New secret files (`write_private_bytes`, `admin.token`, `bootstrap.password`, `node.json`) are created atomically with `0600` permissions (no world-readable TOCTOU window). Relay logs (`audit.jsonl`, `node-audit.jsonl`, `connect.jsonl`) are also kept `0600` with bounded size rotation (16 MiB, keeping 3 archives). After the default SQLite backend opens `<data-dir>/relay.db` in WAL mode, the relay restricts `relay.db`, `relay.db-wal`, and `relay.db-shm` to owner-only access (`0600`, or a private ACL on Windows). There is no API that imports a client-supplied SQLite file: `AGENTLINK_DATABASE_URL` / `--database-url` must be a `postgres://` (or `postgresql://`) URL, otherwise the process refuses to start. The only file import is `store.json` already in the operator data directory, which is renamed to `store.json.bak` after a one-time read. Operators should not point the data directory at a folder writable by untrusted accounts.

The default build links crates.io `libsqlite3-sys =0.39.1` (`bundled` SQLite `3.54.1`, which includes the upstream fix for `RUSTSEC-2026-0459`). Because crates.io `sqlx` (`0.8.6` / `0.9.0`) has not yet published a release allowing `libsqlite3-sys 0.39.x`, the workspace pins the official `launchbadge/sqlx` merge commit of PR #4502 (`10462fa4414c6c7f1ed1d39bb31678e3b726878c`) in `Cargo.toml` and `Cargo.lock`. That full-SHA pin keeps `cargo build --locked` reproducible, but offline or distribution builds must either run `cargo vendor` ahead of time or wait for the next crates.io `sqlx` release before publishing crates to crates.io.

## systemd

```bash
sudo useradd --system --home-dir /var/lib/agentlink --shell /usr/sbin/nologin agentlink
sudo install -d -o agentlink -g agentlink /var/lib/agentlink /etc/agentlink
sudo install -m 755 agentlink /usr/local/bin/agentlink
sudo cp deploy/agentlink-relay.service /etc/systemd/system/agentlink-relay.service
```

For PostgreSQL, write the DSN where only the service user can read it:

```bash
sudo install -m 600 -o agentlink -g agentlink deploy/db.env.example /etc/agentlink/db.env
sudoedit /etc/agentlink/db.env
```

`deploy/install-relay.sh --database-url postgres://...` writes that file with mode `0600`. The unit loads it with `EnvironmentFile=-/etc/agentlink/db.env`. The leading dash means a missing file is ignored and the relay stays on SQLite. The unit starts after `network-online.target` and `postgresql.service`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now agentlink-relay
sudo journalctl -u agentlink-relay -n 50
```

The listener uses `SO_REUSEPORT`, so a new process can bind the port before the old one has exited. `deploy/agentlink-relay.socket` is an optional systemd socket unit: when it is enabled, the process takes the inherited listening fd instead of binding. On SIGTERM the relay sends a `going_away` frame, waits briefly, and closes sockets.

The fingerprint is also in `/var/lib/agentlink/fingerprint.txt`. Clients pin a self-hosted certificate. A name terminated by nginx with a Let's Encrypt certificate can use the system trust store or Mozilla roots (`--trust webpki`). The Android app does that when the fingerprint field is left empty and a relay URL was entered. Empty does not fill in a host.

A later start that still has both `cert.pem` and `key.pem` keeps that fingerprint. A new pair is generated only when either file is missing: the first start, a wiped data directory, or a start whose `--data-dir` is not the directory that holds the existing files. Omitting `--data-dir` stores the certificate under the per-user data directory, not `/var/lib/agentlink`. The fingerprint is the SHA-256 of the leaf, so a new pair is a new pin. A node whose relay host is `127.0.0.1`, `::1`, or `localhost` adopts that leaf and rewrites `node.json`. Any other host keeps the stored pin and logs `got sha256:…` plus the value to copy from `fingerprint.txt`. SPKI pins and public-root checks are not replaced. Operator clients keep the pin on every host, including loopback.

Create another operator account if you do not want to keep only `admin`:

```bash
sudo -u agentlink agentlink relay --data-dir /var/lib/agentlink user add alice --password-stdin
```

## What is stored

SQLite or PostgreSQL holds users, devices, refresh tokens, access tokens, web sessions, TOTP replay state (`last_totp_step`), nodes and their owners, shares, agent identities and grants, enrollment tokens, the approval queue, and audit policy text. Access tokens and web sessions are rows, so a restart does not log people out. The legacy admin token (when enabled) remains one file, `admin.token`, and one row in `relay_secrets`.

Enrollment tokens, refresh tokens, access tokens, and web session cookies are stored as SHA-256 hashes. The plaintext is returned once to the client.

## Relay URL ports

`wss://host` and `wss://host:443` dial port 443. An explicit port is always kept, so `wss://host:7443` dials 7443. A bare host with no scheme (`host` or `host:9000`) is the only form that defaults to 7443 when the port is omitted.

That parsing is shared by the CLI, the node, the MCP server, the desktop controller, and `agentlink guide`. `agentlink guide` turns `wss://relay.example` into `https://relay.example/operate/#...` and `wss://relay.example:7443` into `https://relay.example:7443/operate/#...`; see [operate-guide.md](operate-guide.md). (Browser desktop viewing at `/view` is disabled; `agentlink view` does not open a browser controller.)

The install scripts pass the URL through. Do not append `:7443` to a `wss://` URL that is served on 443.

## Certificate trust

A relay that generated its own certificate is pinned:

```bash
agentlink login \
  --relay wss://relay.example:7443 \
  --user admin \
  --fingerprint "$AGENTLINK_FINGERPRINT"
```

`sha256:<hex>` is the SHA-256 of the leaf certificate. It breaks when the leaf is reissued.

Let's Encrypt rotates the leaf about every 60–90 days. For a name that has a publicly trusted certificate, verify with the Mozilla root set, or with the operating system's trust store:

```bash
agentlink login \
  --relay wss://relay.example.com \
  --user admin \
  --trust webpki

agentlink node \
  --relay wss://relay.example.com \
  --trust webpki \
  --pairing-token "$PAIRING_TOKEN" \
  --name laptop
```

`--fingerprint system` and `--ca system` use the OS trust store. `--trust webpki` and `--fingerprint webpki` use the Mozilla roots compiled into the binary. Use `webpki` when the machine has no system CA bundle (some containers). `system` fails with a message that names `webpki` when the OS store is empty.

Public-root checks require the URL host to match the certificate. SNI is that host. A raw IP still works with a leaf pin, which does not check the name.

A pin and a root mode together both have to succeed:

```bash
agentlink login \
  --relay wss://relay.example.com \
  --user admin \
  --fingerprint "spki:sha256:<hex>" \
  --trust webpki
```

`agentlink login` and `agentlink node` store `fingerprint` and `trust` in the client config and in `node.json`. `agentlink pair` prints an invite string, `agentlink-invite:v1:...`, that carries the relay URL, the trust mode, and the one-time pairing token. On the machine:

```bash
agentlink node --invite 'agentlink-invite:v1:...'
```

Or pass it straight to the installer (`install.sh --invite ...` / `install.ps1 -Invite ...`). The relay still stores only the random pairing token. The trust mode is not part of that token.

### Pins that survive renewal

| Value | What is pinned | Survives a leaf renewal |
| --- | --- | --- |
| `sha256:<hex>` | The whole leaf certificate | No |
| `spki:sha256:<hex>` | The leaf public key (SubjectPublicKeyInfo) | Yes, when the same key is reused (`certbot renew --reuse-key`, or an equivalent) |
| `intermediate:sha256:<hex>` | The issuing intermediate's public key | Yes, while that intermediate is the issuer. The hostname is checked |
| `system` / `webpki` | A public root set | Yes. The hostname is checked |

`intermediate:sha256:` and `ca-spki:sha256:` are the same check. The relay (or the reverse proxy in front of it) must send the intermediate. Put the full chain in `cert.pem`, not only the leaf. An intermediate pin without a matching hostname is rejected, so pinning a public intermediate does not accept every certificate that intermediate has signed.

## Reverse proxy

nginx can terminate a public certificate on 443 and proxy to the relay on `127.0.0.1:7443`. The relay can keep serving the same certificate: replace `cert.pem` with the full chain and `key.pem` with the private key, both mode `0600`, owned by the relay user. Restart the relay after replacing them.

Clients then use `wss://relay.example.com` (port 443) and `--trust webpki`. They see nginx's certificate, not a second hop.

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass https://127.0.0.1:7443;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        # The websocket is long-lived. Buffering would hold frames.
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        # The relay certificate's name is the public host, not 127.0.0.1.
        proxy_ssl_server_name on;
        proxy_ssl_name relay.example.com;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    }
}
```

Start the relay so it trusts that proxy, pins its canonical public origin, and records the client address:

```bash
AGENTLINK_PUBLIC_URL=https://relay.example.com \
agentlink relay \
  --bind 127.0.0.1:7443 \
  --data-dir /var/lib/agentlink \
  --trust-proxy 127.0.0.1/32
```

Set `AGENTLINK_PUBLIC_URL` (for example `https://relay.example.com`) so `/install.sh`, `/install.ps1`, and `/api/tokens` always emit the canonical origin rather than trusting request `Host` headers. When `AGENTLINK_PUBLIC_URL` is unset, the relay strictly validates the `Host` header and rejects malformed or duplicate `Host` headers with `400 Bad Request`.

`--trust-proxy` may be repeated. A bare IP means that single host. Forwarded headers are used only when the TCP peer is inside one of those CIDRs. `X-Forwarded-For` is walked from the right, skipping addresses that are themselves trusted proxies. `X-Real-IP` is used when `X-Forwarded-For` is absent. Any other client that sends those headers is logged by its TCP address.

Successful node and client handshakes append one JSON line to `connect.jsonl` (mode `0600`, rotated) in the data directory (`peer` is the audit address, `tcp_peer` is the socket). The lines are also in the process log.

## Dashboard host

The management UI is served by the relay at `GET /`. The example below terminates TLS for `relay.example.com` and proxies `/` to `127.0.0.1:7443`. No extra nginx `location` is required for the dashboard, login, machine list, enrollment, `/healthz`, `/audit`, `install.sh`, `install.ps1`, or `/dl/` when the relay itself serves them. Leave `/shell/` on ttyd and `/download/` on the APK if those already exist. Node and client WebSockets use the same host you put in `--relay`.

`proxy_buffering off` and a long `proxy_read_timeout` (the relay vhost already sets these) let the dashboard's live machine list through. A short `GET /api/nodes` still refreshes the list if buffering is left on.

If that vhost is only a bare `proxy_pass`, use the same headers as `relay.example.com`, with the public name set to the dashboard host:

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location /shell/ {
        # existing ttyd proxy; leave it in front of the relay
    }

    location /download/ {
        # existing APK files; leave them in front of the relay
    }

    location / {
        proxy_pass https://127.0.0.1:7443;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        proxy_ssl_server_name on;
        proxy_ssl_name relay.example.com;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    }
}
```

An install command minted by the dashboard downloads the script from `AGENTLINK_PUBLIC_URL` (or the validated host) and enrolls the machine at `wss://` that host, pinning the leaf certificate. There is no second public hostname and no compiled-in relay. `GET /dl/*` streams local `<data-dir>/dist` files asynchronously with bounded concurrency (`503` on saturation) and path-traversal rejection.

## File transfer transport (relay-path; direct QUIC P2P planned)

File copies (`agentlink cp`, `cat`, `write`, and MCP file tools) currently transfer bulk bytes as **end-to-end encrypted WebSocket binary frames over the relay** (with E2E frame AAD v2 authenticating the full 40-byte frame header). Direct QUIC P2P file transfer is **disabled / planned** until E2E-sealed direct P2P lands — nodes do not bind a dormant UDP QUIC listener, and no UDP port forwarding is needed on the relay for file transfers today.

WebRTC picture and audio bytes for **sealed native clients** (`agentlink controller` and Android) travel peer-to-peer over DTLS-SRTP using dual-stack IPv6/IPv4 host candidates, the STUN list in the next section, and, off the LAN, a TURN server you run yourself. The relay does not carry desktop video bytes and does not need UDP for them.

## STUN and TURN (sealed clients)

Browser control (`/v1/web`, view tickets, `/view` desktop) is **retired**. The dashboard is account/info/enroll only. STUN/TURN configuration still matters for native desktop/phone WebRTC.

`GET /view/config.json` is unauthenticated. It advertises ICE server **URLs only** (no TURN username or credential). The node uses the same STUN list when an offer arrives without `ice_servers`.

Short-lived coturn REST credentials come from `POST /api/ice`. That endpoint accepts either:

- **`Authorization: Bearer <access_token>`** (validated against an active, non-revoked user/device session; no CSRF header required), or
- a logged-in dashboard session cookie plus `X-CSRF-Token`.

Access is gated to callers who own or have share visibility into at least one node (callers with zero nodes receive `403`). The response returns `ice_servers` (STUN + TURN entries with `username` `<expiry unix>:<user id>` and `credential` `base64(HMAC-SHA1(secret, username))`) plus `ttl_secs` (clamped to 5–15 minutes, default 10 minutes). Both `agentlink controller` and the Android client **automatically fetch ICE/TURN credentials from `POST /api/ice`** on connect and refresh them automatically on `ice_restart`, while still honoring explicit client-side `AGENTLINK_TURN_URLS` / `AGENTLINK_TURN_USER` / `AGENTLINK_TURN_PASS` and `AGENTLINK_STUN_URLS` overrides.

| Variable | When it is unset |
| --- | --- |
| `AGENTLINK_STUN_URLS` | Public STUN: `stun:stun.l.google.com:19302`, `stun:stun1.l.google.com:19302`, `stun:stun.cloudflare.com:3478`. A comma-separated list replaces that. An empty value disables STUN (host candidates only). |
| `AGENTLINK_TURN_URLS` | No TURN server. Comma-separated `turn:` or `turns:` URLs. Prefer `turns:host:443?transport=tcp`. |
| `AGENTLINK_TURN_SECRET` | No TURN credential is minted. Coturn `static-auth-secret` must be this value, with `use-auth-secret`. |
| `AGENTLINK_TURN_TTL_SECS` | 600. Values outside 5–15 minutes are clamped. |
| `AGENTLINK_TURN_USERNAME` | Ignored on the relay. Not copied into any ICE document. |
| `AGENTLINK_TURN_PASSWORD` | Ignored on the relay. Not copied into any ICE document. |

Any static TURN password that was published in `/view/config.json` in older deployments is compromised. Rotate it on the coturn host, switch coturn to `use-auth-secret`, and set `AGENTLINK_TURN_SECRET` to a new secret. Do not reuse the old password as that secret.

STUN only helps the two sides learn a reflexive address. A viewer across a symmetric NAT still needs a TURN server you run (coturn is the usual one). agentlink does not embed TURN, and the relay does not terminate it. Put the variables in a systemd drop-in so a restart keeps them. `EnvironmentFile=-/etc/agentlink/db.env` is also loaded, if you would rather keep them next to the database URL.

```ini
# /etc/systemd/system/agentlink-relay.service.d/webrtc.conf
[Service]
Environment=AGENTLINK_STUN_URLS=stun:turn.example:3478
Environment=AGENTLINK_TURN_URLS=turns:turn.example:443?transport=tcp
Environment=AGENTLINK_TURN_SECRET=replace-with-the-coturn-static-auth-secret
```

```conf
# coturn, next to the shared secret
use-auth-secret
static-auth-secret=replace-with-the-coturn-static-auth-secret
realm=agentlink
# bandwidth and concurrent allocations, so a leaked short-lived credential cannot fill the host
max-bps=2000000
bps-capacity=4000000
user-quota=2
total-quota=50
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart agentlink-relay
```

Leaving `AGENTLINK_STUN_URLS` unset is enough for the public STUN defaults. An empty `stun` array in `/view/config.json` means the variable was set to an empty value, not that it was forgotten. IP addresses in `AGENTLINK_TURN_URLS` are used as written. `turn_auth` in that JSON is `rest` when a secret is configured, `unconfigured` when TURN URLs exist without a secret, and `none` when there is no TURN URL.

Live video for sealed clients is DTLS-SRTP between the client and the node. It is not the agentlink end-to-end payload cipher. A literal address in `198.18.0.0/15` is not contacted; that range is not a reachable STUN or TURN server.

`POST /api/view-ticket` and `/api/view-ticket/revoke` return **410 Gone**. `GET /v1/web` upgrades are refused. `agentlink view` does not open a browser controller. Use a sealed CLI, `agentlink controller`, or Android client after a node-local grant.

## Legacy admin token

`admin.token` is disabled by default. A new deploy with legacy admin off does not mint a usable token and does not write `admin.token`. Prefer an account plus TOTP for people. Existing deployments that already have a token file or a `relay_secrets` row are not rotated, rewritten, or deleted by a start with legacy off. To enable the token for automation, set `AGENTLINK_LEGACY_ADMIN=1` (also `true`, `on`, `yes`, `enable`, `enabled`) and a positive `AGENTLINK_LEGACY_ADMIN_TTL_SECS`. Enabling without a TTL is rejected. The TTL is measured from the recorded `created_unix` of that token. A token that has no recorded creation time (legacy rows that stored `created_unix` as 0 or omitted it) is rejected; the migration does not default the missing timestamp to “now”, which would restart the TTL. `--print-admin-token` prints an already-issued token again. Do not leave that flag in a service unit; `deploy/agentlink-relay.service` does not. After the first start, `agentlink relay` prints the path of `admin.token` when a token was issued, or a line that no token was issued when legacy admin is off. Each use, including a rejection, is appended to `audit.jsonl` as `legacy.admin` on the hash chain.

## Node name pins

Authorization that does not trust the relay (owner-signed grants inside the sealed body) is described in [e2e-auth.md](e2e-auth.md).

End-to-end sessions are bound to the node id. A relay whose certificate is only checked by a public CA can still claim that a familiar name belongs to a different key. The CLI, MCP server, desktop controller, and Android client pin the id after the first successful connect (`node-pins.json` in the config directory). Commands to a mismatched name fail closed until you intentionally clear the old pin with `agentlink pin rm <name-or-id>` (inspect pins with `agentlink pin list`, or manage pins in Android Settings). The dashboard also warns in-browser when a name changes keys. This does not pin the relay itself: set `AGENTLINK_RELAY_PIN=spki:sha256:<hex>` (or `sha256:<leaf hex>`, or pass `--fingerprint`) for a known relay. Do not treat a key published next to the binary as that pin. CA-only trust (`system` or `webpki` without a pin) prints a warning.

## Command globs

A node with no `limits.json` denies destructive disk/power commands across Unix and Windows (`mkfs`, `dd` onto disk devices, `shutdown`, `reboot`, `shred`, `format`, `diskpart`, `Stop-Computer`, `cipher /w`, etc.) and allows every other command. A node with no `confirm.toml` holds destructive commands (`rm -rf`, `rd /s`, `rmdir /s`, `Remove-Item -Recurse -Force`, disk/power commands, recursive root deletion) until `agentlink approve allow`. `confirm.toml` rules also evaluate file edits (`replace`, `edit-lines`, `apply-patch`, `rename`) and file transfer writes (`Push`, `PushStream`, `PushDir`) with normalized path containment. Glob matching uses polynomial DP where `*` matches across `/` and `\`, preventing `/bin/rm -rf /` bypasses. Both files are operational guardrails, not an operating-system sandbox. An allowed shell can still do anything that user can do. Bubblewrap, seccomp, or a platform sandbox would be a separate program.

## What the relay can read

Invoke payloads, `Cancel`, `Session` cursor updates, file transfer frames, and JPEG screenshots are sealed to the node. `forward.central` uploads the node's audit chain into the relay's isolated `node-audit.jsonl` (mode `0600`, rotated, server-pinned to the node's authenticated WS identity), and approval summaries are stored so a person can approve them. Both are readable on the relay by design. Leave `forward.central` off when the relay must not store those records. The node still writes its local chain. The read-only `/audit` and `/audit/records` HTTP endpoints enforce full security headers (`CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`) and scope non-admin views strictly to visible nodes.

## Slim-bin drop-ins (`agentlink-relay` / `agentlink-node-daemon`)

Some hosts keep a systemd drop-in such as `agentlink-relay.service.d/slim-bin.conf`:

```
[Service]
ExecStart=
ExecStart=/usr/local/bin/agentlink-relay --bind 127.0.0.1:7443 --data-dir /var/lib/agentlink
```

That argv shape matches an older relay-only binary. The current release binary is the full `agentlink` CLI and expects `agentlink relay --bind …`. **Do not copy the tip binary over `/usr/local/bin/agentlink-relay`.** That leaves `--bind` as argv1; the process exits with `unexpected argument '--bind'` and nginx returns 502 until the unit is fixed.

After installing a tip build to `/usr/local/bin/agentlink`, install the wrappers and restart:

```sh
sudo install -m 755 /path/to/agentlink /usr/local/bin/agentlink
sudo BIN=/usr/local/bin/agentlink sh deploy/install-slim-wrappers.sh
sudo systemctl restart agentlink-relay agentlink-node
```

`deploy/install-slim-wrappers.sh` writes:

- `/usr/local/bin/agentlink-relay` → `exec /usr/local/bin/agentlink relay "$@"`
- `/usr/local/bin/agentlink-node-daemon` → a pass-through copy of the CLI (node units already pass the `node` subcommand; wrapping with an extra `node` yields `node node` and fails)

`agentlink update` also refreshes `agentlink-node-daemon` next to the CLI it replaces (same release bytes, mode `0755`), so the next deferred node restart picks up the tip; the `agentlink-relay` wrapper is left alone. Hosts that still hand-install a build must rerun `deploy/install-slim-wrappers.sh` or copy the tip onto `agentlink-node-daemon`.

Stock `deploy/agentlink-relay.service` already uses `ExecStart=/usr/local/bin/agentlink relay …` and does not need the wrapper. Prefer that unit on new installs.

Do not leave `bootstrap.password` on disk after the admin password is set. Tip upgrades must not recreate it; leave any `*.rds-bootstrap.bak` backups alone.

## Sync box when GitHub is slow

`deploy/sync-box-bundle.sh` moves the current branch tip to a build box without going through GitHub: it creates a `git bundle`, copies it with `agentlink cp` to `/tmp/agentlink-bundle/`, then `agentlink exec` fetches it into `refs/remotes/bundle/<branch>` and fast-forwards the remote checkout. Use it when `git pull` on the box hangs. It does not push to GitHub and does not create a tag. Both `--node` and `--checkout` (or `TARGET_NODE` / `TARGET_CHECKOUT`) are required; there is no built-in node name or home directory.

```sh
deploy/sync-box-bundle.sh --node box --checkout /var/lib/agentlink/src --dry-run
deploy/sync-box-bundle.sh --node box --checkout /var/lib/agentlink/src
TARGET_BASE=<sha-on-box> deploy/sync-box-bundle.sh --node box --checkout /var/lib/agentlink/src
```

The working tree may be dirty; the bundle always records HEAD. Add `--require-clean` to refuse that. A merge that is not fast-forward fails instead of creating a merge commit. The bundle stays in `/tmp/agentlink-bundle/` on box and is overwritten on the next run.

## Build a release on box

`deploy/box-release-build.sh` chains the sync with a release build: it calls `deploy/sync-box-bundle.sh` (requiring `--node` and `--checkout`, with `--repo`/`--dry-run` and `TARGET_BASE` passed through) and then runs `cargo build -p agentlink-cli --release` on the box with `AGENTLINK_RELEASE_VERSION` exported. The version comes from an exact tag on HEAD, else the nearest `git describe --tags` with the `-<n>-g<sha>` suffix and leading `v` stripped (so `0.1.137-2-gaffb434` becomes `0.1.137`); pass `--version` to override it. The build runs through `agentlink exec --timeout-secs 600` and prints `./target/release/agentlink --version` plus the binary size. This is an ops helper only: it does not tag, push, or publish `/dl`.

```sh
deploy/box-release-build.sh --node box --checkout /var/lib/agentlink/src
deploy/box-release-build.sh --node box --checkout /var/lib/agentlink/src --skip-sync
deploy/box-release-build.sh --node box --checkout /var/lib/agentlink/src --dry-run
deploy/box-release-build.sh --node box --checkout /var/lib/agentlink/src --version 0.1.136
```

It fails if `agentlink` is not on PATH, the node is offline, the sync fails, or the build fails. `cargo` must be at `~/.cargo/bin` on the node.

## Release archives (arm / mac / linux / windows)

This repository does not run GitHub Actions. Do not add `.github/workflows`. Build the archives you need on the machines you already have. The archive targets recognized by `install.sh`, `install.ps1`, and `agentlink update` are:

- Linux headless (static musl): `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (`install.sh` default / `--headless`)
- Linux desktop (glibc with `controller` GUI): `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` (`install.sh --desktop`)
- Windows (dual-binary zip containing `agentlink.exe` + `agentlink-gui.exe`): `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`
- macOS: `universal-apple-darwin` (preferred) with automatic fallback to `x86_64-apple-darwin` or `aarch64-apple-darwin`

Validate the release matrix and local build hygiene with:

```sh
sh scripts/check-release-matrix.sh
sh scripts/verify.sh
```

## Install signatures

`install.sh` and `install.ps1` enforce `https://` downloads (`curl --proto '=https' --tlsv1.2` / redirect-checked URI validation; explicit `--allow-insecure-http` / `-AllowInsecureHttp` override required for non-loopback HTTP), pre-check `minisign` before downloading any archive, verify `SHA256SUMS.minisig` against the pinned project key (`deploy/minisign.pub`) before downloading the binary archive, and then verify the archive's SHA-256 checksum. On Windows, `install.ps1` extracts zips via .NET `System.IO.Compression.ZipFile` with per-entry zip-slip validation instead of `Expand-Archive`.

The scripts refuse to fetch `minisign.pub` from the release host. If `minisign` is missing, they exit immediately before downloading with package-manager install commands or recommend upgrading existing installs via `agentlink update --yes` (which verifies signatures in-process with the embedded key and does not need `minisign`). `AGENTLINK_CHECKSUM_ONLY=1` remains a break-glass override.

### `AGENTLINK_SIGNING_KEY` (release signing)

The signing key is a **32-byte ed25519 seed encoded as 64 hex characters**, not an encrypted minisign secret-key file. Public keys and `.minisig` files use the ordinary minisign text format (`minisign -V` can verify them).

Generate a seed and public key (`scripts/generate-signing-key.sh` sets `umask 077` before creating files; keep the private seed outside git):

```sh
sh scripts/generate-signing-key.sh
# default: ~/.config/agentlink/signing.key (mode 600)
#          ~/.config/agentlink/minisign.pub (mode 644)
```

On a relay host you may prefer `OUT_DIR=/etc/agentlink` (root-owned, mode `0700`). **Never commit `signing.key`.** `.gitignore` already excludes it.

Local / mirror signing (manual cuts):

```sh
export AGENTLINK_SIGNING_KEY=$(tr -d '\n' < ~/.config/agentlink/signing.key)
agentlink internal sign-checksums SHA256SUMS --pubkey-out minisign.pub
# uploads: SHA256SUMS, SHA256SUMS.minisig, minisign.pub (alongside archives)
```

### Published public key

The project pin lives at [`deploy/minisign.pub`](../deploy/minisign.pub). Prefer pinning that file (or its base64 line) out of band; treat a `minisign.pub` asset on a release host as a convenience copy, not the trust root.

Clients:

```sh
# one-shot
AGENTLINK_UPDATE_PUBKEY=/path/to/deploy/minisign.pub agentlink update --check

# persist for later updates (writes config-dir/update.json)
agentlink update --pubkey /path/to/deploy/minisign.pub --check

# install.sh
AGENTLINK_UPDATE_PUBKEY=/path/to/deploy/minisign.pub sh install.sh
```

`agentlink update` prioritizes the build-time embedded project pin (`deploy/minisign.pub`) over ambient disk files unless `--pubkey`, `AGENTLINK_UPDATE_PUBKEY`, or an explicit saved `update.json` key overrides it, preventing an unprivileged file drop next to the binary or in `$XDG_DATA_HOME` from silently swapping the verification key. `--checksum-only` is a break-glass switch that skips signature enforcement.

## Relay URL

There is no built-in relay and no `DEFAULT_RELAY_URL`. Pass `--relay` or set `AGENTLINK_RELAY`. Also pass a fingerprint (`--fingerprint sha256:<hex>`) or public-root trust (`--trust webpki`, or `--fingerprint system`). `wss://host` with no port dials 443. A bare host with no scheme dials 7443.

A `config.json` that already stores `relay` keeps that URL and its pin or trust. Installs that previously omitted `--relay` because a host was compiled in must set the relay explicitly before they dial. This build does not substitute a host for them.

`agentlink relay` still binds `0.0.0.0:7443` on the machine where you run it.

The Android login field starts empty (visible on fresh sign-in). A session already stored on the phone keeps the server it saved. A new sign-in has to enter the relay URL. An empty fingerprint means public-root trust only after that URL is set; it does not select a host. Username login on the phone follows `agentlink login --user`.

## Restart and reconnect

The relay is restarted on upgrade. Peers treat that as a short network blip. On Unix, `agentlink update` replaces the binary via an atomic temp file + single `rename` and then a detached helper restarts the node units after the updater process exits, so an update run from a live node or `agentlink exec` session does not leave the service stranded inactive. The helper prefers `sudo -n systemd-run --scope` when passwordless sudo is available, then plain `systemd-run --scope` (falling back to `setsid`, then a plain `sh -c`) so it escapes the node's service cgroup and survives the restart that tears that cgroup down. On Windows, `agentlink update` stops the running tray/service gracefully before swapping `agentlink.exe` (and `agentlink-gui.exe` when present) using `cmd /D /C`, relaunches the tray/service, and cleans up temporary `.new`/`.cmd` files.

Durable state is the SQLite or PostgreSQL database (users, devices, sessions, nodes, shares, enrollment tokens, agent grants, the approval queue, and audit policy text), plus the TLS certificate and (if enabled) the legacy admin token. The audit JSONL files (`audit.jsonl`, `node-audit.jsonl`) stay beside the database. Routing tables are memory only. They are rebuilt when nodes dial back.

On SIGTERM the relay sends a `going_away` frame, waits briefly, and closes sockets. `deploy/agentlink-relay.service` uses that signal. The listener uses `SO_REUSEPORT`, so the new process can bind the port before the old one has exited. `deploy/agentlink-relay.socket` is an optional systemd socket unit: when it is enabled, the process takes the inherited listening fd instead of binding. When the relay unit is active and its `ExecStart` uses the binary that was just replaced, `agentlink update` defers `systemctl restart agentlink-relay` to the same post-exit helper. When `AGENTLINK_SERVICE` is set (the updater runs under a node), the relay is never bounced automatically: restart it manually if the shared binary also serves the relay.

System-scope units (including the relay) are bounced from that helper with `sudo -n systemctl restart ...`, so the user running `agentlink update` needs passwordless sudo for `systemctl`; without it the helper logs a tip to `agentlink.update.log` and the units keep running the old binary.

Nodes and clients reconnect on their own. The first retry is about 200ms, then exponential up to 10s, with jitter. No new pairing is required. Each client keeps a session id, per-request sequence numbers, and a replay buffer. After the socket returns, in-flight invokes are resent and `Envelope::Session` cursor updates are sent E2E-sealed. The node dedupes them by request id (verified against `(owner_peer, grant_jti, grant_exp_unix)`), keeps PTY sessions and background processes, and replays sealed output the client has not applied. Watches keep running. Copies retry through the resume journal. End-to-end keys are reused; a reset on the node starts a new handshake without a user prompt. An MCP call waits through a blip of about 60 seconds instead of returning an error.

A WebRTC session that is already connected keeps its media during the restart, because picture bytes do not go through the relay. Native viewers reconnect only the signaling websocket; if ICE drops, they perform `ice_restart` with refreshed TURN credentials from `POST /api/ice`, and fall back to sealed JPEG screenshots if ICE cannot recover.

`relay_restart_mid_exec_pty_transfer_mcp_and_watch` (in the `agentlink` binary tests) kills the relay during a long exec, a PTY, a 100 MiB copy, an MCP `run_command`, and a watch, then asserts each one completes with no client-visible error.

## One node per data directory

A running node claims `node.lock` in its data directory until it exits. A second node started against the same `--data-dir` (for example `agentlink node` while a background service or the Windows tray already runs one) fails at startup with `another agentlink node is already using data dir …` instead of dialing. Two live processes on one identity dial the relay twice; each hello replaces the other socket and the loser sees `Connection reset without closing handshake`, so the node flaps every heartbeat.

## Tests against both databases

`cargo test -p agentlink-relay` always runs the SQLite cases. PostgreSQL runs when `AGENTLINK_TEST_DATABASE_URL` is set, or when one of these local URLs accepts a connection:

- `postgres://agentlink:agentlink@127.0.0.1:5432/agentlink`
- `postgres://agentlink@127.0.0.1:5432/agentlink`
- `postgres://postgres@127.0.0.1:5432/postgres`

`AGENTLINK_DATABASE_URL` is not used as a test database. Each PostgreSQL test creates a schema named `t_<pid>_<random>` and drops it at the end. If no server is reachable and the test URL is unset, the PostgreSQL test prints a skip line and passes.
