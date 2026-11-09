# End-to-end authorization (relay untrusted for payloads)

The payload cipher hides paths, command lines, and file bytes from the relay.
That part is unchanged: the relay routes ciphertext and does not read it.

## Current rule

Remote control is denied unless the node has a signed grant in its own check.
The grant file and `owner-keys.json` live on the node. The relay and the web
dashboard cannot add, delete, refresh, or approve that list. A relay login,
admin bit, owner row, or share is not a grant.

The controller proves its key inside the sealed session. The node checks that
key, the node id, the issuer, the time window, and the local revoke list.
A grant the node accepts is full use of that machine. Revoke by editing the
deny-list on the node host (`agentlink grant revoke-local` removes the
controller's copy; the node deny-list is `revoked-grants.json` on the node).
A remote `revoke_grant` invoke is rejected. New calls fail as soon as the
file is visible; in-flight terminal sessions recorded for that jti are closed
on the next message the node reads.

The dashboard and view-ticket sockets send plaintext invokes. The relay can
read them, and the page JavaScript is served by the relay, so an untrusted
relay is not a confidential web controller. Those paths are disabled. Use a
CLI or phone client that seals with its device key, after the node operator
has issued a grant for that key.

A full shell on the machine can edit the grant files. That is the trust
boundary of exec, not a separate sealed store.

`AGENTLINK_AUTO_GRANT` defaults off. Set it to `1` only when this client
already holds an issuer key the node has trusted. Nothing is minted from an
account session alone.

## Findings (current code)

| Layer | What the relay sees | Trust today |
| --- | --- | --- |
| `Envelope::E2e` body | ciphertext only | session keys from X25519; never on the wire in clear |
| `class` | coarse `read`/`write`/`exec`/`desktop`/`meta` | used for relay ACL; not a secret |
| `relay_admin` / `relay_grant` | **cleartext on the outer envelope** | The node treats an authenticated owner, admin, or share as full access. These stamps are how it learns that. They are not a preset cap |
| `Invoke.grant` | cleartext on plaintext invokes; also inside sealed body if client set it | relay overwrites for view tickets; unsigned |
| Name → node id | listing / hello routing | TOFU pins (`node-pins.json`) stop silent key swap |
| Same-owner peer paths (PR #42) | relay DB `owner` | correct isolation **if** the relay is honest; a malicious relay can still lie |
| WebRTC media | DTLS-SRTP between viewer and node | TURN sees SRTP ciphertext only; JPEG fallback is sealed invoke |
| Dashboard / web socket | plaintext `Invoke` | treated as privileged (`relay_admin`-like); browser session is the auth |

Hypothesis that "the relay may still see plaintext signaling or assert peer
identity" is **confirmed** for authorization: outer `relay_*` fields and
plaintext dashboard invokes. It is **false** for sealed agent payloads and
for E2E session keys.

## Threat model

| Threat | Goal | Mitigation (target) |
| --- | --- | --- |
| Malicious relay | Decrypt sessions or read file and command bytes | Ciphertext. The relay cannot open the sealed body. It does decide which account session may reach a node, and that session is full access |
| Stolen relay DB | Impersonate users, rewrite grants | Grants are signatures, not DB rows; DB theft alone does not mint a valid `SignedGrant` |
| MITM on WSS | Swap peer identity | Pin relay cert; pin node id; handshake binds both ed25519 identities |
| Compromised node | Attack other accounts | Same-owner peer rule (PR #42); node ceiling; no cross-account grants |
| Stolen device / client key | Act as that grantee until revoke | Short-lived grants (`exp`); revoke issuer or grantee key; refresh tokens already rotate |
| Passive network observer | Read content | TLS to relay + E2E AEAD; WebRTC SRTP |

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

- **Relay**: authentication of the TCP/WSS session (login, device challenge),
  routing, coarse class ACL, presence. Not a source of truth for authorization
  once owner keys are enrolled on the node.
- **Owner issuer keys**: devices (or an account signing key) that may mint
  grants for that owner's nodes.
- **Node ceiling** (`max_policy`): local hard cap; even a valid grant cannot
  exceed it.
- **Peer E2E**: after handshake, both sides know the peer ed25519 id from the
  transcript. Authorization asks: does a trusted issuer attest that this peer
  may use this policy on this node_id?

## Key hierarchy

1. **Node identity** — ed25519; node id = public key hex. Signs enrollment and
   E2E welcome.
2. **Client / device identity** — ed25519; agent client key or logged-in device
   key. Signs E2E hello. Becomes `grantee_id` in a grant.
3. **Owner issuer keys** — ed25519 keys allowed to sign grants for a node.
   Stored on the node as `owner-keys.json` (hex public keys). The daemon
   bootstraps one on first start (`grant-issuer.json`); operators add more with
   `agentlink grant trust-owner`. `AGENTLINK_LEGACY_RELAY_AUTH=1` keeps the
   old empty-key behavior (see rollout).
4. **Session keys** — X25519 ephemeral DH → HKDF → ChaCha20-Poly1305 direction
   keys (`agentlink-e2e-v1`). Ephemeral; never leave the two endpoints.

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
4. `grantee_id` matches the E2E peer id (the client_id the session was stored under)
5. `nbf <= now <= exp`
6. effective policy = `grant.policy ∩ node_ceiling`

The grant travels **inside** the sealed `Envelope::Invoke` as `authz`, and
inside sealed `Envelope::Transfer` bodies for file transfers. The
relay never needs to parse it. Outer `relay_grant` / `relay_admin` are ignored
for E2E when `owner-keys.json` is non-empty.

## Handshake and authz flow

1. Client and node complete existing `E2eHello` / `E2eWelcome` (unchanged).
2. Client seals `Invoke { …, authz: Some(grant) }` with the session key.
3. Relay routes on request id + class; may still stamp outer `relay_*` for
   legacy peers; honest relays keep doing coarse ACL.
4. Node opens ciphertext, verifies `authz` against owner keys and peer id,
   then intersects with the ceiling. It does **not** consult outer `relay_*`
   when owner keys are configured.

"Who may control which node" is thus: **peer identity from the E2E transcript
+ owner signature over (peer, node, policy, time)**. The relay's DB opinion is
advisory at most.

## Compatibility

| Client / node | Behavior |
| --- | --- |
| Node (default) | Bootstraps `grant-issuer.json` when `owner-keys.json` is empty. A signed-in owner, admin, or share is full access with no grant file. A key that is not an account session still needs `authz`. |
| Node (legacy) | `AGENTLINK_LEGACY_RELAY_AUTH=1` skips issuer bootstrap. Account sessions are still full. |
| CLI / MCP / tray | Account login is enough. A local `grants/<node_id>.json` is optional and is ignored when it is stale, so it cannot block the session. |
| Android client | Same account session on an updated node. If the node still requires a signed grant, the phone shows its controller public key and can import a grant issued for that key. |
| Android node | Verifies the same way. The phone's own consent ceiling still caps what a remote user can do *to the phone*. |
| Dashboard / web | Cookie session. Terminal, files, and desktop are full for the owner. Desktop opens watch-first; Take control drives input. |
| Node → node peer copy | Same-owner peers are full. The relay still refuses a peer from another account. |

**Signing in as the owner or an admin is node authorization.** The account
session is full access. A signed grant is not required for that session and
does not narrow it. A key that is not an account session still needs a grant
signed by a trusted owner issuer when the node has owner keys.

Phased rollout:

1. **Done (previous PR)**: `SignedGrant` type + verify API; node honors `authz`
   when owner keys exist and ignores forged outer `relay_admin`; design doc;
   unit tests.
2. **Done (now default)**: node bootstraps a persistent issuer and enrolls it
   in `owner-keys.json`; CLI `grant issue/show/list/refresh/revoke-local/revoke/trust-owner`
   (with `clear` as an alias for `revoke-local`); clients attach `authz`
   on invokes and transfers (including TCP tunnels);
   `AGENTLINK_LEGACY_RELAY_AUTH=1` is the explicit escape hatch.
3. **Done (v0.1.105)**: node-local grant revocation deny-list keyed by `jti`
   (`revoked-grants.json` in the node data dir). `grant revoke --data-dir`
   appends the jti; the node reloads it before each authz decision.
4. **This PR (v0.1.106)**: remote revoke over the sealed E2E session. The CLI
   signs an issuer `SignedRevoke` and sends `Op::RevokeGrant`; the node verifies
   the issuer against `owner-keys.json` and appends the jti to its own
   `revoked-grants.json`. No node `--data-dir` access is required.
5. **Later**: relay-distributed opaque grants, narrow plaintext web path.

## CLI workflow

```sh
# On the node host, once: the daemon already created grant-issuer.json.
# Trust an operator device key as an additional issuer (optional).
# A running node reloads owner-keys.json before the next request; no restart.
agentlink grant trust-owner <device-pubkey-hex> --data-dir ~/.local/share/agentlink/node

# On this device: mint a one-hour exec grant for the node.
# Signs with this CLI identity unless --issuer-data-dir (or a resolved node
# issuer dir; see below) names a node data dir.
agentlink grant issue --node <name-or-node-id> --ttl 1h --policy exec \
  [--issuer-data-dir ~/.local/share/agentlink/node] [--grantee <hex>] [--out -]

agentlink grant show --node <name-or-node-id>
agentlink grant list                        # EXPIRED or time remaining per grant
agentlink grant refresh --node <name-or-node-id> [--ttl 1h] \
  [--issuer-data-dir ~/.local/share/agentlink/node] [--out -]
agentlink grant ensure --node <name-or-node-id> [--ttl 1h] [--policy exec] \
  [--issuer-data-dir ~/.local/share/agentlink/node] [--grantee <hex>]
agentlink grant revoke --node <name-or-node-id> \
  [--issuer-data-dir ~/.local/share/agentlink/node] \
  [--data-dir ~/.local/share/agentlink/node] [--jti <jti>]
agentlink grant revoke-local --node <name-or-node-id>   # forgets the local file only
agentlink grant clear --node <name-or-node-id>          # alias for revoke-local
```

`grant revoke` is the real revocation path. It takes the jti from `--jti`, or
from the stored local grant for that node, signs an issuer `SignedRevoke`
(short window), and sends `Op::RevokeGrant` over the sealed E2E session. The
relay only routes the ciphertext; the node verifies the issuer against
`owner-keys.json`, appends the jti to its local `revoked-grants.json`, and
answers `{"revoked": true, "jti": ...}`. `revoke_grant` is handled before the
caller's grant policy and confirm rules, so a narrow or expired caller grant
cannot block an owner revoke. Plaintext (unsealed) senders are rejected: remote
revoke requires an E2E session.

On success the CLI deletes the local grant file and reports that the node
deny-list was updated remotely (hot reload, no restart). Signing uses this
CLI's operator identity by default; `--issuer-data-dir <node-data-dir>` uses
the node's own `grant-issuer.json` (or a trusted key) instead.

If the remote call fails (older node that does not know `revoke_grant`, or no
connection) and `--data-dir` names the node data dir, the CLI falls back to
appending the jti to `<data-dir>/revoked-grants.json` offline and then clears
the local file. Without `--data-dir` a failed remote revoke is an error: the
local grant is left in place so the retry works, and the message suggests
`--data-dir` (offline fallback / node upgrade) or `grant revoke-local` (local
file only). The deny-list itself never leaves the node.

`grant revoke-local` (alias `grant clear`) only deletes the **local** grant
file; it does not touch the node deny-list. All of these accept a full node id,
a unique stored node-id prefix/file stem, or a relay-known name, and the prefix
form works offline from `grant list` without dialing the relay. An ambiguous
prefix asks for a longer id; no match tips `grant list`.

To verify a revocation, reuse the same grant once more: the node answers
`grant was revoked (jti <jti>)` instead of executing the op. Re-issuing the grant
produces a fresh jti and works again; old jtis stay denied.

`grant refresh` re-signs the stored grant with the same grantee, node, and
policy, keeping the workflow intact; use `grant issue` to change any of them.

`grant ensure` is the idempotent form: it reuses a valid stored grant
unchanged, refreshes an expired one (keeping the stored policy), or issues a
new one (using `--policy`) when none is usable. It prints `reused`,
`refreshed`, or `issued` plus the jti and expiry.

`grant issue`, `grant refresh`, and `grant ensure` resolve the issuer data dir
as: `--issuer-data-dir`, then `AGENTLINK_ISSUER_DATA_DIR`, then the default node
data dir (`~/.local/share/agentlink/node`) when it already contains
`grant-issuer.json` or non-empty `owner-keys.json`. Discovery never creates an
issuer; with none of these, they sign with this CLI's operator identity.

An account session does not need a local grant file. When
`auto_grant_enabled()` is on (the default), a command that is **not** an
account session can still mint a local grant. Auto-grant picks its issuer data
dir with the same precedence as `grant ensure`: `AGENTLINK_ISSUER_DATA_DIR`,
then the default node data dir when it already contains `grant-issuer.json` or
non-empty `owner-keys.json`, otherwise this CLI's operator identity. Local
discovery never creates an issuer. The relay still only routes ciphertext.
Auto-issued grants default to `full`. Set `AGENTLINK_AUTO_GRANT_POLICY` only
if a non-account key should record a different name; the node treats a valid
grant as full use. A stale grant file is ignored when it cannot be refreshed,
so it does not block the account session.

| Env var | Default | Meaning |
| --- | --- | --- |
| `AGENTLINK_AUTO_GRANT` | on | `0` / `false` / `no` / `off` disables automatic ensure/mint. |
| `AGENTLINK_AUTO_GRANT_TTL` | `3600` | Lifetime in raw seconds for auto-issued grants; invalid values fall back to 3600. |
| `AGENTLINK_AUTO_GRANT_POLICY` | `full` | Name recorded on auto-issued grants for a non-account key. Unset, empty, or invalid values fall back to `full`. The node does not clip an account session to this name. |
| `AGENTLINK_ISSUER_DATA_DIR` | unset | Node data dir whose `grant-issuer.json` signs auto-grant and `grant issue|refresh|ensure` instead of the operator key. Overrides local node discovery; when unset both use the default node data dir if it already has issuer artifacts (optional; an env/explicit dir with empty `owner-keys.json` may be bootstrapped, local discovery never is). |

A connection that is not an account session, on a node with owner keys and no
valid grant, is rejected with `signed grant required … this connection is not
signed in as the owner or an admin`. Sign in as the owner instead of pasting a
grant. A revoked jti on a non-account grant fails with `grant was revoked (jti
<jti>)`. If that grant's issuer is not trusted, the error names the issuer.

For a documentation-only shareable how-to link for a node, run
`agentlink guide <node>` and see [operate-guide.md](operate-guide.md).

## TURN / JPEG

- Auto path host → STUN → TURN → JPEG is unchanged.
- TURN is a media relay for SRTP; it does not learn agentlink session keys.
- JPEG fallback uses sealed `screenshot` invoke and therefore the same grant
  rules as any other desktop class op.

## This PR (vertical slice)

Implemented:

- `agentlink_core::grant` — bootstrap (`bootstrap_issuer_with_mode`), storage
  (`save_grant` / `load_grant` / `list_stored_grants` / `delete_grant`),
  env overrides, validation
- Node daemon: bootstraps `grant-issuer.json` and `owner-keys.json` on load;
  `AGENTLINK_LEGACY_RELAY_AUTH=1` opts out with a warning
- `Invoke.authz` and `Transfer.authz` (`Option<SignedGrant>`, sealed inside E2e)
- Node E2E path: owner keys require a valid `authz` for invokes **and**
  transfers; policy is `grant ∩ ceiling`; outer `relay_admin` / `relay_grant`
  are ignored
- Client: grant loading from `grants/` + env, attached to unary, exec/pty,
  copy, and stream links
- CLI: `grant issue/show/list/refresh/revoke/revoke-local/trust-owner`;
  `revoke-local` is also reachable as `grant clear` (local file only);
  `grant revoke` signs a `SignedRevoke` and sends `Op::RevokeGrant` over E2E,
  falling back to `--data-dir` (`revoked-grants.json`) when the node cannot be
  reached
- Node-local `revoked-grants.json` deny-list, hot-reloaded before each authz
  decision (`grant was revoked (jti <jti>)`); remote revokes update it in place
- Unit tests for TTL, serde, forge resistance, issuer bootstrap, revocation,
  and `SignedRevoke` round-trip/authorization

Deferred:

- Relay-distributed grant revocation (the deny-list stays node-local; the relay
  remains untrusted and never sees the revoke or grant list)
- Automatic node→node peer grants (operators issue them explicitly)
- Browser sessions behind grants
- Changing PR #42 relay checks (they stay as defense in depth)

## Non-goals

- Replacing WSS TLS or relay login
- Making the relay unable to drop or delay traffic (availability is not
  confidentiality)
- Hiding coarse `class` or request ids from the relay (needed to route and to
  enforce a first-line ACL)
