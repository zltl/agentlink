# End-to-end authorization (relay untrusted for payloads)

The payload cipher hides paths, command lines, and file bytes from the relay.
That part is unchanged: the relay routes ciphertext and does not read it.

## Current rule

Remote control is denied unless the node verifies a signed grant locally.
The grant trust root (`owner-keys.json`) and revocation deny-list
(`revoked-grants.json`) live on the node. The relay and the web dashboard
cannot add, delete, refresh, or approve entries there. A relay login, admin
role, owner row, or share is **not** a grant.

The controller proves its key inside the sealed session. The node checks that
key, the node id, the issuer, the time window, and the local revoke list.
A grant the node accepts authorizes operations up to `grant.policy ∩ node_ceiling`.
Revocation is a **strictly local node operation**: run `agentlink grant revoke --data-dir <node-data-dir>`
on the node host to append the `jti` to `<node-data-dir>/revoked-grants.json`
(whereas `agentlink grant revoke-local` / `grant clear` only removes the
controller's local copy). Remote `Op::RevokeGrant` invokes are rejected by design.
The running node caches `revoked-grants.json` with hot-reload (no restart
required): new calls fail immediately with `grant was revoked (jti <jti>)`, and
active PTYs, background processes, filesystem watches, TCP tunnels, and desktop
streams bound to that `jti` are torn down.

The dashboard and view-ticket sockets are plaintext at the relay, and the page
JavaScript is served by the relay, so an untrusted relay is not a confidential
web controller. Browser control paths are disabled (`POST /api/view-ticket`
returns `410 Gone`; `GET /view` serves a static notice). Use a native CLI,
`agentlink controller`, or Android client that seals with its device key, after
the node operator has issued a grant for that key.

A full shell (`exec` or `full` grant) runs as the OS user hosting the node and
can access same-UID node files. That is the accepted trust boundary of `exec`,
not an OS container or separate UID sandbox.

Connecting does not mint a grant. Issue one with `agentlink grant issue` or
`agentlink grant ensure`. An account session never becomes a grant.

## Findings (current code)

| Layer | What the relay sees | Trust today |
| --- | --- | --- |
| `Envelope::E2e` body | ciphertext only | session keys from X25519 (contributory check + zeroized on drop); never on the wire in clear |
| `Invoke` / `Cancel` / `Session` / `Transfer` | sealed ciphertext only | fail-closed on both client and node; unsealed plaintext data responses and cross-node responses are dropped |
| Binary file frames | 40-byte header in clear for routing + encrypted payload | E2E frame AAD v2 (`HELLO_V2_MAGIC`) authenticates `version`, `kind`, non-E2E `flags`, `offset`, `raw_len`, and `request_id` |
| `class` | coarse `read`/`write`/`exec`/`desktop`/`meta` | used for relay ACL; not a secret |
| `relay_admin` / `relay_grant` | **cleartext on the outer envelope** | Ignored by the node. They are not a grant. |
| Name → node id | listing / hello routing | TOFU pins (`node-pins.json`, managed via `agentlink pin list|rm`) stop silent key swap |
| Same-owner peer paths | relay DB `owner` + connection-bound routes | correct isolation if the relay is honest; node still verifies peer grant |
| WebRTC media | DTLS-SRTP between viewer and node | TURN sees SRTP ciphertext only; JPEG fallback is sealed invoke |
| Dashboard / web socket | plaintext HTTP/SSE | Control invokes are rejected. The page lists and enrolls machines only. |

## Threat model

| Threat | Goal | Mitigation |
| --- | --- | --- |
| Malicious relay | Decrypt sessions, tamper with frame headers, or forge responses | E2E AEAD (fail-closed `Invoke`/`Cancel`/`Session`/`Transfer`), E2E frame AAD v2, route/node binding, replay-log owner binding |
| Stolen relay DB | Impersonate users, rewrite grants | Grants are ed25519 signatures verified locally on each node; DB theft alone cannot mint a valid `SignedGrant` |
| MITM on WSS | Swap peer identity | Pin relay cert; pin node id; E2E handshake binds both ed25519 identities |
| Compromised node | Attack other accounts or spoof audit | Connection-bound relay routes, server-pinned `node_id` on `ApprovalRequest`/`AuditBatch`, isolated `node-audit.jsonl`, node ceiling |
| Stolen device / client key | Act as that grantee until revoke | Short-lived grants (`exp`); node-local `revoked-grants.json` (`grant revoke --data-dir`); refresh token family revocation on replay |
| Passive network observer | Read content | TLS 1.2+ to relay + E2E AEAD; WebRTC DTLS-SRTP |

Out of scope for this design: physical access to the node host, malicious
browser extensions on the dashboard, and side channels on TURN timing.

## Trust boundaries

```
[operator device / agent client]          [node]
  device/client ed25519                     node ed25519 identity
  owner issuer key (signs grants)           owner-keys.json (trusted issuers)
  E2E session keys (X25519)  <---AEAD--->   E2E session keys
                 \                         /
                  \    opaque ciphertext  /
                   \        + class      /
                    [relay: untrusted]
                    routes, ACL on class,
                    may lie about grant —
                    node must not care
```

- **Relay**: authentication of the TCP/WSS session (typed principals:
  `Admin`, `Operator`, `Agent`, `Web`), connection-bound routing, coarse class
  ACL, presence. Not a source of truth for node authorization.
- **Owner issuer keys**: operator devices (or the node's own `grant-issuer.json`)
  trusted in `owner-keys.json` to mint grants for that node.
- **Node ceiling** (`--max-access` / `max_policy`): local hard cap; even a valid
  grant cannot exceed it.
- **Peer E2E**: after handshake, both sides know the peer ed25519 id from the
  transcript. Authorization asks: does a trusted issuer attest that this peer
  may use this policy on this `node_id`, and is its `jti` unrevoked and within
  `[nbf, exp]`?

## Key hierarchy

1. **Node identity** — ed25519; `node_id` = public key hex. Signs enrollment and
   E2E welcome.
2. **Client / device identity** — ed25519; agent client key or logged-in device
   key. Signs E2E hello. Becomes `grantee_id` in a grant.
3. **Owner issuer keys** — ed25519 keys allowed to sign grants for a node.
   Stored on the node as `owner-keys.json` (hex public keys). The daemon
   bootstraps a local issuer on first start (`grant-issuer.json`); operators
   trust their controller/operator keys with `agentlink grant trust-owner`.
   There is no switch that restores account sessions as node authorization.
4. **Session keys** — X25519 ephemeral DH (with contributory-behavior check) →
   HKDF → ChaCha20-Poly1305 direction keys (`agentlink-e2e-v1`, with v2 frame
   AAD negotiation). Ephemeral, zeroized on drop, never leave the two endpoints.

## SignedGrant

Canonical statement (UTF-8, fixed field order, then ed25519 over the bytes):

```
agentlink-grant-v1
grantee:<hex>
node:<hex>
policy:<compact-json>
nbf:<unix>
exp:<unix>
jti:<opaque>
```

Wire form (`agentlink_core::grant::SignedGrant`):

- `grantee_id`, `node_id`, `policy`, `nbf_unix`, `exp_unix`, `jti`
- `issuer_id` (hex of signing public key)
- `sig_hex`

Verification on the node:

1. `issuer_id` ∈ `owner-keys.json`
2. signature valid
3. `node_id` matches this node
4. `grantee_id` matches the E2E peer id (the `client_id` the session was stored under)
5. `nbf <= now <= exp`
6. `jti` ∉ `revoked-grants.json`
7. effective policy = `grant.policy ∩ node_ceiling`

The grant travels **inside** the sealed `Envelope::Invoke` as `authz`, and
inside sealed `Envelope::Transfer` bodies for file transfers and TCP tunnels.
The relay never needs to parse it. Outer `relay_grant` / `relay_admin` are
ignored. Replay logs, cursors, cancels, PTYs, background processes, watches,
tunnels, and desktop streams are all bound to `(owner_peer, grant_jti, grant_exp_unix)`.

## Handshake and authz flow

1. Client and node complete `E2eHello` / `E2eWelcome` (negotiating frame AAD v2
   when both sides support it; unverified staged handshakes live in a bounded
   64-slot / 30s LRU table so floods cannot evict established peers).
2. Client seals `Invoke { …, authz: Some(grant) }` (and sealed `Session` cursor
   updates / `Cancel` / `Transfer` frames) with the session key.
3. Relay routes on connection-bound `request_id` + class and enforces coarse
   routing ACLs.
4. Node opens ciphertext before any session/replay/cancel lookup, verifies
   `authz` against `owner-keys.json`, `revoked-grants.json`, and peer id, then
   intersects with the ceiling.

"Who may control which node" is thus: **peer identity from the E2E transcript
+ owner signature over `(peer, node, policy, time)` + local deny-list check**.
The relay's DB opinion is advisory at most.

## Compatibility

| Client / node | Behavior |
| --- | --- |
| Node | Bootstraps `grant-issuer.json` when `owner-keys.json` is empty. Every remote control call and transfer needs a valid signed grant for the E2E peer. Owner, admin, and share do not authorize. |
| CLI / MCP / controller | Login discovers nodes. Control needs a grant file in `<config-dir>/grants/` matching this client's own `public_id`. `status` and `grant list` flag mismatched grantees as `WRONG GRANTEE`. |
| Android client | Shows the controller public key in Settings / Machine Hub and imports grants issued for that key. |
| Android node | Verifies the same way across invokes and transfers. The phone's own consent ceiling still caps what a remote user can do *to the phone*. |
| Dashboard / web | Login, node list, and enrollment only. Terminal, files, and desktop are not offered. |
| Node → node peer copy | The relay enforces same-owner routing; the destination node still requires a valid signed grant for the source peer key (otherwise CLI bridges via a private local temp directory). |

**Signing in does not authorize the machine.** A grant signed by a key in
`owner-keys.json`, for this node and this E2E peer, is the authorization.

## CLI workflow

```sh
# 1. On the controller machine, print its public identity hex (`public_id`):
agentlink identity show

# 2. On the node host, once: trust that operator/controller key as an issuer.
# A running node reloads owner-keys.json automatically; no restart needed.
agentlink grant trust-owner <controller-public-id-hex> --data-dir <node-data-dir>

# 3. Back on the controller machine: mint, inspect, renew, or batch-ensure grants.
# Both positional `[NODE]` and `--node <name-or-node-id>` are accepted.
# Lifetimes accept seconds (`900`), units (`15m`, `1h`, `7d`, `1y`), or `--ttl permanent` / `--permanent` (wire-compatible `9999-12-31T23:59:59Z`).
agentlink grant issue laptop --policy exec --ttl 1h [--issuer auto|operator|node] [--issuer-data-dir <dir>] [--grantee <hex>] [--out -]
agentlink grant issue --all --policy full --permanent [--issuer operator]
agentlink grant show laptop
agentlink grant list                         # resolves names, human TTLs, flags EXPIRED or WRONG GRANTEE
agentlink grant refresh laptop [--ttl 1h]    # re-signs keeping grantee, node, and policy
agentlink grant refresh --all [--ttl 1h|--permanent]     # renew stored grants across fleet
agentlink grant ensure laptop --policy exec --ttl 1h
agentlink grant ensure --all --policy exec --ttl 1h
agentlink grant prune                        # delete expired and wrong-grantee local grant files

# 4. Revocation (strictly node-local):
# On the node host, append the jti to <node-data-dir>/revoked-grants.json
# (and delete the local controller grant file if present):
agentlink grant revoke laptop --data-dir <node-data-dir> [--jti <jti>]

# Forget only the controller's local grant file (does NOT touch the node deny-list):
agentlink grant revoke-local laptop
agentlink grant clear laptop                 # alias for revoke-local
```

### Issuer selection (`--issuer auto|operator|node`)

`grant issue`, `grant refresh`, and `grant ensure` choose which signing key to
use via `--issuer`:

- `--issuer auto` (default):
  - If `--issuer-data-dir <dir>` or `AGENTLINK_ISSUER_DATA_DIR` is explicitly
    set, signs with `<dir>/grant-issuer.json` (and returns an error if that
    file does not exist — it never silently bootstraps a brand-new random key).
  - Otherwise, checks the platform default local node data directory **only
    when the target `node_id` matches that local node's own `identity.json`**.
  - For all **remote** nodes, signs with the controller's own operator
    `identity.json` (so running a local node on your workstation never hijacks
    grant signing for remote machines).
- `--issuer operator`: always sign with the controller's operator `identity.json`.
- `--issuer node`: always sign with a local node's `grant-issuer.json` (using
  `--issuer-data-dir`, `AGENTLINK_ISSUER_DATA_DIR`, or the platform default
  node data directory).

### Local revocation (`grant revoke`)

`grant revoke` is a **local node `--data-dir` operation** run on the node host:

- Pass `--data-dir <node-data-dir>` (or the platform default node data dir on
  that host) and either `--jti <jti>` or `--node <name-or-node-id>` (when a
  matching local grant file is available to read its `jti`).
- `grant revoke` appends the `jti` to `<node-data-dir>/revoked-grants.json` and
  removes the local controller grant file if present.
- The running node hot-reloads `revoked-grants.json` without a restart, rejects
  subsequent requests with `grant was revoked (jti <jti>)`, and terminates
  active sessions (PTYs, background processes, watches, TCP tunnels, desktop
  streams) tied to that `jti`.
- Remote `Op::RevokeGrant` over the wire is rejected by design — the deny-list
  never leaves the node and cannot be modified by a remote peer or relay.
- `grant revoke-local` (alias `grant clear`) deletes only the controller's
  local grant file under `<config-dir>/grants/` and does not modify
  `revoked-grants.json`.

### Batch lifecycle (`grant ensure --all`, `grant refresh --all`, `grant prune`)

- `grant ensure` reuses a valid stored grant for this controller identity,
  refreshes an expired one (keeping its policy), or issues a new one with
  `--policy`. Add `--all` to ensure grants across your online/pinned nodes in
  one step. Requesting `--permanent` / `--ttl permanent` also upgrades a finite
  stored grant to permanent.
- `grant issue --all --policy full --permanent` issues permanent grants (encoded
  as `exp_unix = 253402300799`, `9999-12-31T23:59:59Z` for wire compatibility
  with `agentlink-grant-v1` nodes) across all paired/pinned nodes. Permanent
  grants never expire automatically, but remain **locally revocable at any time**
  via `agentlink grant revoke --data-dir <node-data-dir>` (and `revoked-grants.json`
  never prunes revoked permanent entries).
- `grant refresh --all` re-signs stored grants for this controller across the
  fleet.
- `grant prune` cleans up expired or wrong-grantee `.json` files from
  `<config-dir>/grants/` so stale grants do not accumulate.
- When issuing a grant for another device (`--grantee <other-pubkey-hex>`), the
  CLI prints the exact `grant import` command to install it on the target device.

A connection with no valid grant is rejected with `signed grant required`.
A revoked `jti` fails with `grant was revoked (jti <jti>)`. An untrusted issuer
names the `grant trust-owner` command to run on the node host. Signing in to
the relay never skips any of these checks.

For a documentation-only shareable how-to link for a node, run
`agentlink guide <node>` and see [operate-guide.md](operate-guide.md).

## TURN / JPEG

- Auto path host → STUN → TURN → JPEG is unchanged.
- `POST /api/ice` accepts `Authorization: Bearer <access_token>` (for callers
  with access to at least one node) in addition to dashboard cookie+CSRF, and
  native viewers (`agentlink controller` and Android) automatically fetch and
  refresh short-lived coturn REST credentials from it.
- TURN is a media relay for DTLS-SRTP; it does not learn agentlink E2E keys.
- JPEG fallback uses sealed `screenshot` invoke and therefore the same grant
  rules as any other desktop-class op.

## Non-goals

- Replacing WSS TLS or relay login
- Making the relay unable to drop or delay traffic (availability is not
  confidentiality)
- Hiding coarse `class` or request ids from the relay (needed to route and to
  enforce a first-line ACL)
- Relay-distributed grant revocation (the deny-list stays node-local; the relay
  remains untrusted and never sees the revoke or grant list)
