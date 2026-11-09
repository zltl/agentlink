# Shareable node operate guide

`agentlink guide` and the dashboard **Guide** button produce a URL that explains
how to operate one paired node. The page is documentation only.

## Threat note

The link **does not authorize anything**:

- It does not mint an E2E `SignedGrant`, view ticket, enrollment token, or web session.
- It carries no pairing token, session cookie, refresh token, issuer private key,
  or view ticket.
- The relay serves one static HTML page. Node metadata lives in the URL fragment,
  and the browser never sends a fragment to the server.
- Actual node operations still require the owner-signed grant described in
  [e2e-auth.md](e2e-auth.md). Relay login is not node authorization.

Treat the URL as public documentation. Anyone who has it can read the node name,
id, OS/arch/version, presence, display flag, and policy preset names. Do not put
secrets in `notes`.

## URL format

```text
https://<relay-origin>/operate/#v1.<base64url(json)>
```

`/operate`, `/operate/`, and `/operate/index.html` all serve the same page. The
origin follows the same rules as `/view`:

| Relay | Page origin |
| --- | --- |
| `wss://relay.example.com` | `https://relay.example.com` |
| `wss://relay.example.com:443` | `https://relay.example.com` |
| `wss://relay.example.com:7443` | `https://relay.example.com:7443` |
| `relay.example.com` (bare) | `https://relay.example.com:7443` |
| `wss://[::1]` | `https://[::1]` |

The JSON payload is versioned with `v: 1`. Only these keys are encoded:

```text
v, relay, node_id, name, os, arch, version,
online, has_display, access, effective, notes
```

`online` is omitted when unknown. `has_display` is `true`, `false`, or `null`
(not reported). `notes` is omitted when empty. Encoding refuses unknown fields and
a relay URL that carries credentials. Decoding rejects an unknown version.

## CLI

```sh
# Signed in to the relay: resolve a node, print the URL, open a browser.
agentlink guide lab-box

# Print only.
agentlink guide lab-box --print-only
agentlink guide lab-box --no-open

# JSON for scripts: { "url": "...", "guide": { ... } }
agentlink guide lab-box --json

# On the node host, without listing nodes or needing a session:
agentlink guide --local
agentlink guide --local --data-dir ~/.local/share/agentlink/node
```

`--local` reads `node.json` and `identity.json` from the node data directory.
Presence and display are unknown in that mode, so they stay omitted.

The page offers copy-paste commands for:

1. Installing or updating the CLI from the relay origin (`/install.sh`).
2. `agentlink login --user …` with `--relay` when it is not the default relay.
3. `agentlink grant issue --node <id> --ttl 1h --policy <preset>`.
   On the node host, `grant trust-owner` takes effect on the next request
   (older node binaries need a restart).
4. Listing nodes, `ls`, `cat`, `exec`, `shell`, `cp`, and `bg`.
5. `agentlink port forward` and `agentlink port reverse`.
6. `screenshot` and `view` when the node has a display; a headless note otherwise.
7. Effective policy, grant expiry, and the no-secrets rule.

If the fragment is missing or invalid, the page shows generic help and the
`agentlink guide <node>` command instead.

## Dashboard

Each machine card has a **Guide** button. It builds the same `/operate/#v1.…`
URL from the listed node fields and `location.origin`, copies the URL to the
clipboard, and opens it in a new tab. It does not call any grant or ticket API.

## Windows subprocesses (no console flash)

On Windows the CLI/node binary is a GUI-subsystem process (`windows_subsystem =
"windows"`), so it has no console. Spawning a console-subsystem helper
(`cmd.exe`, `powershell.exe`, `schtasks.exe`, `ffmpeg`, …) with a bare
`std::process::Command::new` allocates a visible console that flashes and
closes when the helper exits.

**Every runtime subprocess must go through**
`agentlink_core::process::hidden()` (short-lived helpers) or
`agentlink_core::process::detached()` (long-lived daemons with null stdio).
Do not combine `CREATE_NO_WINDOW` with `DETACHED_PROCESS`: Windows ignores
`CREATE_NO_WINDOW` when that bit is set. Interactive PTY sessions stay on
portable-pty / ConPTY and must not use these helpers.

A regression test (`cargo test -p agentlink-cli --test no_console_flash`)
scans `crates/*/src/**/*.rs` for bare `Command::new(` and fails unless the
line uses `hidden(` / `detached(` or carries `// no-window-reviewed`.

## Tests

```sh
cargo test -p agentlink-core operate_guide
cargo test -p agentlink-relay operate
cargo test -p agentlink-cli guide
cargo test -p agentlink-cli --test no_console_flash
```
