# Controller remote screen and P2P — t449

Worktree: `/workspace/agentlink-t449-controller-p2p`
Branch: `feat/controller-p2p-observe-t449`
Base (do not modify): `684e1adf3cd2b441a167c735be3f9d6937d3d4b7`
(`integrate/controller-android-t447` / frozen 0307 artifacts left untouched.)

Local only. Not pushed, merged, or deployed.

## Official design (ops + source)

From `/home/box/reference/agentlink-ops.md` (no secrets reproduced):

- Control-plane signaling is WebSocket (`wss://` relay).
- File `cat`/`write`/`cp` default to **direct QUIC**, then relay.
- **Desktop video is WebRTC**. Signaling goes through the relay.
- Exec/read still requires a signed grant; the account token is not the
  media path.

The desktop Controller View path is not the CLI exec QUIC path:

1. `Cmd::LiveStart` → `start_live` on `agentlink-controller`.
2. JPEG stills start immediately via the `screenshot` extension (WebSocket
   invoke). HUD for this path is `jpeg · relay`.
3. A dedicated `agentlink-desktop-view` thread runs `Viewer::connect` with
   `ClientSignal` (`webrtc_signal` extension, same contract as the phone).
4. ICE servers come from `AGENTLINK_STUN_URLS` or the public STUN defaults
   in `agentlink-core` (`stun.l.google.com` / Cloudflare). There is **no
   TURN** in the Controller offer unless the environment supplies
   `AGENTLINK_TURN_URLS` (web `/view/config.json` is the place that walks
   `ice_attempts` including TURN).
5. If WebRTC cannot start (soft failure), JPEG stills stay on. Hard
   rejects (`not allowed`, `denied`, `unauthorized`, `forbidden`,
   `offline`) stay fatal and do not fall back.

## What was wrong on `684e1ad`

`classify_media_path` looked at the **answer SDP inventory**. A normal ICE
answer lists host, srflx, and typ-relay candidates together, so the HUD
preferred `host` even when the selected pair was TURN, and it published
`h264 · host` as soon as the offer returned — while JPEG stills over the
WebSocket were still what the user was looking at.

That is exactly “showing a WebSocket relay session as P2P / host.”

`connection_label("wss://…")` already mapped to `relay`. The bug was
feeding it the SDP inventory, not a selected pair.

## What this branch changes

- Path tokens for live H.264 come from the **selected ICE pair**
  (`Viewer::transport()`), not from gathered candidates.
- Until a pair is selected, the token is `connecting`. Until the first
  decoded H.264 frame, the picture path is not advertised as a confirmed
  WebRTC path; JPEG stills remain `jpeg · relay`.
- If ICE/DTLS fails before the first H.264 frame, the session stays on
  JPEG over the relay (`Notice`, not a hard `Failed` teardown). Grant /
  policy rejects stay fatal.
- Labels:
  - `host` — ICE typ host on loopback or private/LAN (not public NAT).
  - `stun` — typ srflx/prflx (STUN-assisted; not a Tailscale tunnel).
  - `turn` — typ relay (TURN media relay; not direct P2P, and not the
    WebSocket).
  - `tailscale` — typ host in `100.64.0.0/10` or `fd7a:115c:a1e0::/48`.
    Source: [Tailscale KB 1015](https://tailscale.com/kb/1015/100.x-addresses)
    (CGNAT range and IPv6 ULA). IPv4 `100.64/10` is also generic CGNAT
    (RFC 6598); this is an overlay mark, **not** public NAT traversal,
    and it does not add a Tailscale login to identity or grant.
  - `relay` + kind `jpeg` — JPEG stills over the WebSocket. Never P2P.
- Session stats popover and debug `state.connection` expose `kind`,
  `path`, `path_note`, and `link`. Set `AGENTLINK_LIVE_PATH_LOG=1` to
  print the selected pair (types, addresses, ports, inventory, note).

## Evidence (real sockets, not mocks of the path)

### Single-machine two-peer (loopback) — passed

`cargo test -p agentlink-view --test loopback -- --nocapture`

Observed (box clock, Asia/Shanghai):

```
agentlink live-path loopback: path=host local=host 172.17.0.1:44037 remote=host 172.17.0.1:39716 proto=udp inventory=host note=WebRTC ICE typ host on a loopback or private address — same machine or LAN, not public NAT traversal (private/LAN typ host; not public NAT traversal)
```

An Annex-B IDR was received on that typ-host UDP pair. `172.17.0.1` is
the Docker/bridge address of this machine. **This is not cross-machine
public NAT traversal.** Inventory also said `host`, but the HUD/path now
requires the selected pair in addition to an IDR.

### Classification and policy tests — passed

- `selected_pair_not_the_sdp_inventory`: mixed host+TURN SDP inventory is
  still `host`, but a selected typ-relay pair is `turn`; Tailscale/CGNAT
  typ host is `tailscale`.
- `connection_labels_name_the_path`: JPEG hint is explicitly “not WebRTC
  P2P”; hard rejects vs soft ICE failure; JPEG kept when no H.264 yet.
- `webrtc_offer_without_a_grant_is_rejected`: `Viewer::connect` with
  `not allowed: missing grant` does not open a session.
- `screenshot_fallback_does_not_look_like_p2p`: the node’s screenshot
  fallback answer does not return a Viewer / host path.
- Existing Viewer close/drop-in-runtime tests still pass.
- `controller_debug` (6) and `controller` check (1) still pass.

### Not claimed

- No Controller GUI was started here (parent will retest).
- No production node/relay restart, no firewall or routing change, no
  grant create/refresh, no identity rotation, no sufa input / clipboard /
  portal, no phone/ADB.
- No live probe against sufa from this worker: `maintain_session` would
  refresh and rewrite the production session file. Existing grant for
  sufa is `full` / ACTIVE (used only as a fact; not extended).
- Direct-blocked ICE with a **real JPEG payload** on a two-node LAN or
  public NAT was not run (host candidates on one machine still succeed;
  blocking them would need a firewall or a relay-only policy plus TURN
  off). The keep-JPEG path is implemented and unit-covered.
- Cross-machine STUN / TURN / public NAT: **untested**.
- File/exec QUIC P2P was not re-verified in this workflow (out of the
  Controller View question, except to say it is a different path).

## Parent GUI path

1. Binary: build from this worktree, do **not** reuse or overwrite the
   frozen 0307 tree. Example:

   ```
   export PATH="/home/box/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu/bin:$PATH"
   export CARGO_TARGET_DIR=/tmp/agentlink-t449-target
   AGENTLINK_LIVE_PATH_LOG=1 \
     cargo run -p agentlink-cli --bin agentlink -- \
       controller --config-dir "$HOME/.config/agentlink" --data-dir <isolated-data>
   ```

   Or use a candidate under
   `/workspace/agentlink-t427-recovery/20261112-*-t449-controller-p2p/`
   once archived. Launch is for the parent computerUse worker, not this
   one.

2. Open sufa **View** (read-only). Do not send keys, mouse, or clipboard.
3. Confirm the on-screen path:
   - Session stats popover: `path  h264 · host|stun|turn|tailscale` plus
     the note, **or** `jpeg · relay` with “JPEG stills over the WebSocket
     relay — not WebRTC P2P”.
   - Debug bus `connection.path`, `connection.path_note`, `connection.link`.
   - Process stderr when `AGENTLINK_LIVE_PATH_LOG=1` shows the selected
     pair (types and addresses).
4. The path must not say `host` / P2P while JPEG stills are what is
   painted.
5. If a typ-host address is in `100.64/10` or `fd7a:115c:a1e0::/48`, it
   must be labeled `tailscale` and not reported as public NAT success.
6. A typ-host path to sufa on `192.168.1.0/24` is LAN/same-site, not
   public NAT.

## Candidate / logs

See the dated archive next to this document once created. SHA of the
binary and the source commit go there. 0307 remains immutable.
