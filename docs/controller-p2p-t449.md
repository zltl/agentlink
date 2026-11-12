# Controller remote screen and P2P — t449

Worktree: `/workspace/agentlink-t449-controller-p2p`
Branch: `feat/controller-p2p-observe-t449`
Base (do not modify): `684e1adf3cd2b441a167c735be3f9d6937d3d4b7`
(`integrate/controller-android-t447` / frozen 0307 and 0851 artifacts left untouched.)

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
   invoke). The **painted media path** for this is `jpeg · relay`.
3. A dedicated `agentlink-desktop-view` thread runs `Viewer::connect` with
   `ClientSignal` (`webrtc_signal` extension, same contract as the phone).
   Per-stage handshake is reported separately from the media path.
4. Controller ICE servers for the offer come from `LiveOptions.ice_servers`
   or `AGENTLINK_STUN_URLS` / the public STUN defaults in `agentlink-core`.
   **`offer_servers` does not load `AGENTLINK_TURN_URLS` and does not mint
   REST credentials.** Setting a TURN URL environment variable alone does
   **not** put TURN in the Controller offer. A URL list is not a username
   or credential. The web `/view/config.json` path can advertise TURN URLs
   and, if `AGENTLINK_TURN_SECRET` is configured on the relay, mint
   short-lived credentials. `AGENTLINK_TURN_USERNAME` / `PASSWORD` are
   obsolete. The node will honor `turn` URLs + username + credential when
   those fields are actually present in the offer.
5. Signal round-trips use a 25s timeout each (`list_monitors`, `offer`,
   `ice`, `keyframe`, `close`). The Controller wraps the whole
   `Viewer::connect` in a 60s deadline. Soft failures keep JPEG stills.
   Hard rejects (`not allowed`, `denied`, `unauthorized`, `forbidden`,
   `offline`) stay fatal and do not fall back.

## Handshake vs media path

Frozen 0851 (`7bac82e`, `worker.rs` ~758–769) published `h264 · connecting`
as the HUD kind/path as soon as `Viewer::connect` returned Ok, **before
the first decoded H.264 frame**. That can overwrite an already-rendered
`jpeg · relay` picture path. Session stats also had no independent
handshake / link field.

This branch:

- Never sets media `kind=h264` or `path=connecting` until a frame is
  actually decoded. JPEG stills keep `jpeg · relay` for as long as they
  are what is painted.
- Reports WebRTC negotiation in `LiveHud.handshake` (stats line
  `handshake  …`, debug `connection.handshake`). JPEG HUD updates do not
  clear it.
- Always prints `agentlink live-webrtc:` stage lines to stderr (offer
  sent/answered, timeouts, screenshot fallback, session gone). A selected
  ICE pair is logged as `agentlink live-path:` when it first appears or
  changes. `AGENTLINK_LIVE_PATH_LOG` is no longer required for these
  lines; absence of a `live-path` line means **no selected pair was
  observed**, not “ICE definitely failed” by itself (the connect may
  still be in progress, blocked, or have failed at a listed stage).

## Path tokens (selected ICE pair only)

Tokens: `turn`, `stun`, `loopback`, `private`, `cgnat`, `tailscale`,
`host`, `relay`, `connecting`, `unknown`.

- `host` — typ host on a public or unclassified address. This names the
  pair type only; it is **not** a public NAT traversal result.
- `stun` — typ srflx/prflx. Also **not** a public NAT traversal result,
  and not a Tailscale tunnel.
- `private` — typ host on RFC1918 / ULA (except the Tailscale ULA) /
  link-local. May be LAN, VPN, or routed — **not** a “same LAN” claim.
- `loopback` — typ host on a loopback address (same host).
- `cgnat` — typ host in `100.64.0.0/10` (RFC 6598). That prefix alone
  does **not** identify Tailscale.
- `tailscale` — only with extra confirmation: documented ULA
  `fd7a:115c:a1e0::/48` (Tailscale KB 1015) or a `tailscale*`
  interface/route (`/proc/net/route` on Linux). No Tailscale login is
  introduced into identity or grant. Overlay, not public NAT.
- `turn` — typ relay (TURN media). Not direct P2P, and not the WebSocket.
- `relay` + kind `jpeg` — JPEG stills over the WebSocket. Never P2P.
- `unknown` — an H.264 frame arrived before a selected pair was observed.
- `connecting` — handshake-only; must not replace a painted JPEG path.

## JPEG fallback

Shots **pause** (they do not exit) while a decoded H.264 frame is the
live picture, and **resume** when WebRTC is lost after takeover, or when
ICE cannot connect in the first place.

- Test-only `IceFault::RelayPolicyWithoutTurn` (ICE policy relay, no TURN
  server) forces a deterministic ICE failure without a firewall change.
  It is not a product default and is not read from the environment.
- If the node session is gone (`unknown stream session` on `ice_restart`),
  the viewer is marked failed so JPEG can resume. Three other
  `ice_restart` failures also end live video. As a backstop, 8 seconds
  without a decoded H.264 frame after takeover also resumes JPEG.
- Hard grant/policy rejects still stop the session. No-grant still
  rejects and does not publish a P2P path.

## 0851 frozen GUI (do not overwrite, do not mix with this source)

Archive: `/workspace/agentlink-t427-recovery/20261112-0851-t449-controller-p2p/`

- Binary SHA-256 `0d7f5e9b38ebb60088597f6a00faae9ad9debd7fd45b875ba62dab4ceaf1ec2f`
  matches the recorded 0851 bin.
- The launch script SHA is **not** the string recorded for some earlier
  notes and was not in `SHA256SUMS` as `8723222fe78332c6ac84200f7948c839a23759acec8b541313d3b6ff9c314f84`.
  Record the truly frozen artifacts; do not treat the current worktree
  source as the 0851 bin.
- Parent GUI (Asia/Shanghai): sufa View stayed `jpeg · relay` for about
  3 minutes (2736×1824 JPEG), fps/bitrate/latency 0, hint “JPEG stills
  over the WebSocket relay — not WebRTC P2P”. No H.264. Launch used
  `AGENTLINK_LIVE_PATH_LOG=1`; the terminal after the command had no
  selected-pair lines. Stats had no independent handshake field.
- That empty terminal is **not** by itself proof that ICE failed. On
  0851, `live-path` logs only after a selected pair exists. The connect
  may not have started, may have been blocked, may have timed out
  without a stage line, or may have completed signaling without ever
  selecting a pair.

## Live probe against sufa (this follow-up, existing identity only)

Readonly, Asia/Shanghai on 2026-11-12. `Identity::load` only (no new
identity). Ordinary `maintain_session` refresh of the already-authorized
client. Existing grant used as-is; not copied, not extended, no new
grant. No sufa/relay restart, no input/clipboard/portal, no deploy.

`agentlink nodes` (existing config dir):

- `sufa` **ONLINE**, `DISPLAY=desktop` (`has_display=Some(true)`),
  `linux/x86_64`, access `full`, version `0.1.0`
  (`bc97ba1050f1e186ca3ac37a7cb1b2c021db3012`).

`crates/agentlink-view/examples/t449_sufa_stage.rs` (view-only offer,
then close):

- `list_monitors` **ok in 721ms**, 1 monitor, not screenshot fallback.
- Local offer: `sdp_len=1348`, `gather_complete=false` after the 1.5s
  gather wait, **stun=3, turn=0**.
- Offer **was sent and answered**: `session_len=78`, `sdp_len=2313`,
  `encoder=ffmpeg:h264_vaapi`, `hardware=true`.
- `Viewer::connect` returned Ok in 4678ms. Media path at return is still
  `connecting` (no selected pair yet).
- **No selected ICE pair** and **no H.264 frame** in the following 8s;
  `viewer.failed()` stayed false; then the viewer was closed.

So the remote is **not** missing a desktop session, and it is **not**
missing a WebRTC/H.264 encoder (it answered with `ffmpeg:h264_vaapi`).
gstreamer is not required for that encoder. Signaling reaches
offer/answer/keyframe. What did **not** happen in the observation window
is ICE completion (no selected pair, no video). The Controller offer in
this probe included STUN only (no TURN). That is the current product
call chain, not a missing node package. Do **not** treat TURN as a
substitute for native P2P, and do **not** deploy or restart sufa/relay
from this worker. See the 0910 GUI and post-STUN-rewrite probe below
for the later diagnosis.

This still is **not** public cross-machine NAT success, and the 8s probe
window is shorter than the 3-minute 0851 GUI sit. Combined with 0851’s
three minutes and no `live-path` line, ICE completion was not observed
on this pair in that earlier window.

## 0910 frozen GUI (do not overwrite)

Parent handshake/path/fallback acceptance used the 0910 archive
`/workspace/agentlink-t427-recovery/20261112-0910-t449-controller-p2p/`
(debug bin SHA `12c3ddab8c45dc37f67b133f6b3454d370e98c663b7fba5203d99d0b381f59c6`,
SOURCE-COMMIT `b9c1704`). That tree is frozen and was not modified here.

Observed on 2026-11-12, Asia/Shanghai, then the GUI exited:

- JPEG remote clock refreshed 09:12 → 09:14. Path chip and stats stayed
  `jpeg · relay`. Hint: “JPEG stills over the WebSocket relay — not
  WebRTC P2P.”
- Offer/answer completed (`list_monitors` ok; local offer
  `sdp_len=1348`, `gather_complete=false`, stun=3, turn=0; offer ok
  2241ms, answer `sdp_len=2308`, `ffmpeg:h264_vaapi`). Then the UI
  waited for an ICE pair / video. Repeated `signal keyframe ok`, then
  `signal close`.
- No selected ICE pair, no `agentlink live-path:` line, no H.264.
- A brief notice: “WebRTC live video is not up. Showing JPEG over the
  relay.”
- Final stats `handshake` was **overwritten** by `signal close ok
  1098ms`, so the timeout/failure reason was lost.
- Session stats has **no** independent `link` line. That is not a
  missed field to add: the toolbar chip already shows `jpeg · relay`,
  the stats `path` line already names the painted media path, and debug
  JSON already has `connection.link`. Do not add a redundant stats
  `link` row.

Screenshots (workspace, not inside the frozen tree):
`t449-0910-stats.png`, `t449-0910-fallback-notice.png`,
`t449-0910-webrtc-start.png`, `t449-0910-webrtc-close.png`,
`t449-0910-link-chip.png`.

## Handshake retention and no-pair / no-frame timeout

Same authorized repair, current worktree only:

- `set_handshake` ignores cleanup/close and routine `signal ice` /
  `signal keyframe` acks (errors still go through). Those stay in the
  `agentlink live-webrtc:` log.
- `set_handshake_terminal` records the last failure or first-frame
  success and sticks until `begin_handshake` on the next live attempt.
  A later terminal failure (connection lost after video) may replace a
  previous terminal success.
- After `Viewer::connect` Ok, wait at most 12s:
  - no selected ICE pair: `webrtc: no selected ICE pair within 12s; JPEG stills remain`
  - pair but no first H.264 frame: `webrtc: no H.264 frame within 12s after a selected ICE pair; JPEG stills remain`
- JPEG stills stay available. Soft failure; no hard fail.
- Regression
  `handshake_retention_tests::close_ok_does_not_overwrite_terminal_negotiation_failure`
  replays the 0910 sequence (`signaling complete…` / keyframes /
  terminal no-pair / `signal close ok 1098ms`) and requires the close
  ack not to win.

## STUN URL rewrite (Controller-side, not TURN)

On this box, system DNS (including UDP to 8.8.8.8 / 1.1.1.1) returns
`198.18.0.1` for the default STUN hostnames in ~0–1ms. A STUN binding
to that address times out, so the 0910 / pre-fix Controller offer had
**typ host only** (private `172.30.0.2` and `172.17.0.1`),
`gather_complete=false`, and trickle ICE also carried typ host only.
Host paths to sufa’s `192.168.1.12` / `10.67.0.2` / `100.91.104.2` are
not on-net from this box.

`usable_ice_url` already skipped *literal* `198.18.0.0/15` in a URL, but
WebRTC re-resolves hostnames via system DNS, so a hostname that later
maps to 198.18 still poisons gathering.

`stun_urls_ready_for_ice()` / `rewrite_ice_urls()` now:

- skip literal RFC 2544 destinations;
- when system DNS only yields 198.18/15, look up A records over DoH
  (`https://cloudflare-dns.com/dns-query`, `https://dns.google/resolve`)
  and rewrite the ICE URL to a **literal IP** so webrtc does not
  re-resolve;
- run that lookup on a dedicated thread because `reqwest::blocking`
  cannot drop a runtime from the Viewer async context.

DoH from this box already returns usable addresses (e.g.
`74.125.250.129`, `162.159.207.0`); STUN bindings to those succeed.
This is not a new service, not TURN, and not a credentials change.
The Controller offer also sends `gather_ms: 4000` (node `bc97ba1`
already honors it). Local gather stays 1.5s; with working STUN it now
finishes complete.

## Post-rewrite readonly sufa probe (2026-11-12 09:22 CST)

Existing identity only (`Identity::load` + ordinary session refresh).
No grant change, no GUI, no deploy, no firewall/routing change, no
phone/probe SSH, 0910/0851 untouched.

- sufa still ONLINE, desktop, `ffmpeg:h264_vaapi`, 1 monitor.
- System DNS still poisons default STUN hostnames to 198.18/15; DoH
  rewrite ran; ICE URLs became literal IPs.
- Local offer: `sdp_len=2159`, **`gather_complete=true`**, stun=3,
  turn=0, **host=4 srflx=8** (public typ srflx on this box, e.g.
  `52.22.132.46`, `23.23.43.111`, `18.204.15.153`).
- Offer answered: `session_len=78`, `sdp_len=2307`, encoder
  `ffmpeg:h264_vaapi`, sufa candidates host=6 srflx=4 (same as before:
  `192.168.1.12`, `10.67.0.2`, `100.91.104.2` / `cgnat`, srflx
  `120.85.255.194`).
- Trickle viewer→node now includes typ srflx, not only typ host.
- `Viewer::connect` Ok in 5909ms, path still `connecting`.
- **No selected ICE pair and no H.264 frame in 15s**;
  `viewer.failed()` stayed false; then close. No `live-path` line.

So the missing typ srflx / incomplete gather **was** a real Controller
defect and is fixed for gathering, but it is **not sufficient** for a
selected pair on box↔sufa. Across probes and tests, this box’s STUN
xor-mapped addresses have been several distinct AWS-like public IPs
(not a single stable mapping). That is consistent with
destination-dependent SNAT on the box egress path; it is recorded as
evidence, not as a closed NAT-type certificate, and not as a reason to
deploy TURN or change firewall/routing from this worker. Further ICE
check tracing can continue in this worktree only.

TURN remains a media relay, not direct P2P. No TURN URLs or credentials
were added.

## Evidence (tests, real sockets where noted)

### Single-machine two-peer (loopback) — passed

`cargo test -p agentlink-view --test loopback -- --nocapture`

Latest observed selected pair (box clock, Asia/Shanghai): typ host
`172.30.0.2` ↔ `172.30.0.2` UDP, path token **`private`**, Annex-B IDR,
encoder `minih264`. Earlier loopback runs on this box used `172.17.0.1`.
Both are same-machine addresses. **Not cross-machine, not public NAT,
not “same LAN.”** Stages printed: `list_monitors` → gather → offer
answered → ICE pair.

### Classification, fallback harness, policy — passed

- `agentlink-view` lib tests (12), including selected-pair vs SDP
  inventory: `100.64/10` alone is `cgnat`; ULA or confirmed interface is
  `tailscale`; private typ host is `private`; public typ host is `host`.
  After the STUN rewrite, `offer_sdp_is_recvonly_h264` gathered typ
  srflx (`gather_complete=true`) on this box.
- `agentlink-core` `rewrite_skips_rfc2544_literals_and_rewrites_poisoned_hosts`.
- `handshake_retention_tests` (3), including the 0910 close-overwrites-
  failure sequence.
- `live_pipeline_tests::jpeg_stays_visible_when_ice_cannot_connect`:
  real two-process / real ICE with `IceFault::RelayPolicyWithoutTurn`;
  decoded JPEG frames keep refreshing; HUD stays `jpeg · relay`;
  handshake ends on a terminal failure reason, **not** `signal close ok`;
  **no** `h264 · connecting` media path.
  Same-host ICE fail is not public NAT evidence.
- `live_pipeline_tests::jpeg_resumes_after_h264_endpoint_disconnect`:
  H.264 arrives on a classified selected pair (`private` here), then a
  node `close` resumes JPEG over the relay without a hard fail.
- `missing_grant_is_rejected_and_does_not_show_p2p`.
- Loopback grant-deny and screenshot-fallback tests.
- `connection_labels_name_the_path`.
- `controller` check (1) and `controller_debug` (6), including the stats
  popover.

### Not claimed

- No Controller GUI was started in this follow-up (parent will retest a
  **new** candidate, not 0851).
- No production node/relay restart, no firewall or routing change, no
  grant create/extend, no identity copy or rotation, no sufa
  input / clipboard / portal, no phone/ADB, no deploy of TURN or node
  packages.
- Cross-machine STUN completing a selected pair on box↔sufa: **not
  observed**, even after typ srflx appeared on both sides.
- File/exec QUIC P2P was not re-verified (different path).

## Parent GUI path (new candidate only)

1. Use the new dated archive under
   `/workspace/agentlink-t427-recovery/20261112-*-t449-controller-p2p/`
   once created. Do **not** overwrite or mix with 0851 / 0307. Launch is
   for the parent, not this worker. Example env:
   `AGENTLINK_CONFIG_DIR` = existing config, isolated `--data-dir`.
   Stage lines now print even without `AGENTLINK_LIVE_PATH_LOG`.
2. Open sufa **View** (read-only). Do not send keys, mouse, or clipboard.
3. Confirm:
   - `path  jpeg · relay` while JPEG is painted, **even if** handshake
     shows offer/ICE in progress. Do not expect `h264 · connecting` as
     the path.
   - Independent `handshake  …` line in session stats and
     `connection.handshake` in debug JSON. After a failed negotiation,
     that line must keep the terminal reason (no selected pair vs no
     first frame), not `signal close ok`. Cleanup belongs in the log.
   - Do **not** expect a separate stats `link` row; the chip, the
     `path` line, and debug `connection.link` already name the media
     path.
   - If H.264 later takes over, `path` becomes `h264 · <selected-pair
     token>` and the hint matches that token only.
   - Stderr: `agentlink live-webrtc:` stages; `agentlink live-path:`
     only if a pair is selected.
4. A typ-host path on a private address must be `private`, not “same
   LAN”. `100.64/10` alone must be `cgnat`, not `tailscale`.
5. `host` or `stun` must not be described as public NAT success.

## Candidate / logs

See the dated archive next to this document once created. SHA of the
binary, the launch script, and the source commit go there. 0307 and 0851
remain immutable, as does 0910.
