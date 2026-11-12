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
not on-net from this box (see routability below).

`usable_ice_url` already skipped *literal* `198.18.0.0/15` in a URL, but
WebRTC re-resolves hostnames via system DNS, so a hostname that later
maps to 198.18 still poisons gathering.

The first rewrite passed **every** STUN URL (including operator
`AGENTLINK_STUN_URLS`) through system DNS and, if unusable, through
third-party DoH, then replaced the hostname with a literal IP. That is
too broad: it would force Google/Cloudflare DoH on a self-hosted STUN
and could silently rewrite a private split-horizon name.

Current policy (`prepare_stun_urls`, default
`AGENTLINK_STUN_REWRITE=defaults`):

- **Scope:** only built-in [`DEFAULT_STUN_URLS`] (scheme+host+port).
- **When:** only if system DNS for that default host is empty or only
  RFC 2544. Healthy system DNS leaves the hostname unchanged (no
  silent literal rewrite on a normal network).
- **How:** DoH A lookup (`https://cloudflare-dns.com/dns-query`,
  `https://dns.google/resolve`) on a dedicated thread, then a literal
  IP so WebRTC does not re-resolve via the poisoned resolver.
- **Operator URLs:** `AGENTLINK_STUN_URLS` is never sent to third-party
  DoH and is never rewritten to literals. Literal `198.18.0.0/15` is
  still skipped.
- **Off:** `AGENTLINK_STUN_REWRITE=off` (also `0`/`false`) disables
  default-url rewrite and DoH entirely.
- **Failure:** if a default URL cannot be rewritten, it is omitted and
  logged; the offer continues with any remaining STUN URLs (host-only
  if none remain). A poisoned hostname is not left in the list.

This is a Controller-side compatibility path for this class of
proxy/resolver, not a general DNS override, not a new service, and not
TURN. The Controller offer also sends `gather_ms: 4000`. Node
`bc97ba1` (`webrtc_session.rs` `gather_budget`) already reads
`gather_ms`, default 1500ms, clamp 200–8000, so 4000 is compatible
without a node deploy. Local viewer gather stays 1.5s; with working
STUN it now finishes complete.

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
selected pair on box↔sufa.

## typ srflx is STUN XOR-MAPPED, not a resolver or relay IP

webrtc 0.21.1 `stun_gatherer.rs` builds typ srflx only from a STUN
Binding success’s **XOR-MAPPED-ADDRESS**, with `raddr`/`rport` equal
to the local host socket (`four_tuple.local_addr`). typ relay is a
separate TURN allocation path and was **0** in every Controller offer
and sufa answer here.

Independent Binding requests from this box to the rewritten literal
STUN servers (Asia/Shanghai 2026-11-12 09:27 CST), one attempt then a
repeat, no credentials:

- `74.125.250.129:19302` (Google STUN) → Binding success (`0x101`)
  from that same peer, XOR-MAPPED `52.1.169.66:45535` then
  `54.209.17.224:43320`. No MAPPED-ADDRESS attribute.
- `162.159.207.0:3478` (Cloudflare STUN) → Binding success from that
  peer, XOR-MAPPED `54.209.17.224:33986` then `52.1.169.66:25309`.

Those mapped IPs are **not** the STUN server / DoH target IPs
(`74.125…`, `162.159…`) and **not** typ relay. Offer inventories now
print `typ:scope:addr;proto=udp;raddr=…`. typ srflx lines show
`raddr=172.30.0.2` or `raddr=172.17.0.1` (this box’s host sockets).
Sufa typ srflx is `120.85.255.194` with `raddr=192.168.1.12` (sufa’s
WLAN host). Classification is not a resolver-target or relay
mis-label.

The mapped public IPs still change, including **two binds 0.2s apart
to the same STUN server**. That is recorded only as a clue (egress
SNAT pool / per-attempt mapping), not a closed NAT-type certificate.

## Answer-candidate routability (read-only `ip route get`)

All sufa answer addresses are reached from this box via the default
gateway `172.30.0.1 dev enp0s3 src 172.30.0.2`:

- typ host `192.168.1.12`, `10.67.0.2`, typ host/cgnat `100.91.104.2`:
  not on-link. These are not a same-LAN or Tailscale path from this
  box (`100.91.104.2` is still `cgnat`, not `tailscale`).
- typ srflx `120.85.255.194`: also via the default route (has a next
  hop). That is not proof that a STUN check or reply will pass NAT.

No routing table or firewall was changed.

## 4s gather, trickle, role, retry (bc97ba1 compatible)

- `gather_ms: 4000` is honored by node `bc97ba1` as above. No node
  deploy. There is still no node→viewer trickle after the answer;
  lengthening node gather is how late node candidates get into the
  answer. Sufa srflx was already in the answer.
- Viewer→node trickle `ice` succeeded (host and typ srflx). No
  trickle signal errors were observed, so retrying trickle is not
  motivated by this evidence. Failed trickle would only be logged
  today, not retried.
- ICE role stayed `controlling` (offerer). No role-conflict signal
  was observed.
- `ice_restart` runs only after a session has been **Connected** and
  then Disconnected (1s delay, 5s throttle). The initial
  Connecting / no-pair wait does **not** ICE-restart, so it does not
  tear down a forming checklist by restart. The 12s/15s wait then
  closes the viewer; if a pair had already been selected it would be
  closed with JPEG remaining. In these box↔sufa runs no pair was
  selected first.

## ICE library stats (2026-11-12 09:33 CST, one instrumented probe)

Existing identity only, no second “just wait” hope loop after this
snapshot. Safe fields only: typ, raddr, proto, ice role/state,
nominated, request/response counts. No ufrag/pwd, certificates, or
packet payloads. Same-host loopback already showed the API working
after a selected pair (`role=controlling`, `nominated=true`,
`req_sent`/`req_recv` > 0, typ srflx with raddr).

Box↔sufa, `Viewer::connect` Ok 5941ms, then 15s:

- Offer: `gather_complete=true`, host=4 srflx=8, proto=udp, typ srflx
  `raddr` on `172.30.0.2` / `172.17.0.1`.
- Answer: `ffmpeg:h264_vaapi`, host `192.168.1.12` / `10.67.0.2` /
  `100.91.104.2`, typ srflx `120.85.255.194` with
  `raddr=192.168.1.12`. Trickle ice ok (host + srflx).
- `agentlink live-ice:` throughout: `role=controlling`
  `ice_state=checking` `selected=-` `pair_changes=0` `pairs=0`
  `succeeded=0` `failed=0` `in_progress=0` `waiting=0` `frozen=0`
  `nominated=0` `req_sent=0` `req_recv=0` `resp_sent=0` `resp_recv=0`.
  Local and remote candidates were listed; no selected pair; no
  H.264; `failed=false`.

webrtc 0.21.1 `get_stats()` only copies ICE agent
`CandidatePairStats` **for the already-selected pair**
(`peer_connection/internal.rs` `update_ice_agent_stats`). The public
`IceTransport` API exposes local/remote candidates and the selected
pair, not the full checklist. Therefore `pairs=0` / `req_sent=0` while
`ice_state=checking` does **not** prove that Binding checks to
`120.85.255.194` were never sent. It does prove the public stats
surface never observed a nominated or selected pair, and never exposed
per-pair send/recv counts for this session.

Going further would need either rtc-ice private agent internals, a
STUN packet capture (Binding checks carry ICE ufrag — not taken), or
a network/node change we are not allowed to make. Stopped here.

## What remains unverified (and is not claimed)

- Whether the ICE agent actually transmitted connectivity checks to
  sufa typ srflx `120.85.255.194:6594` / `:6600`, and whether any
  request or response was dropped by NAT.
- Whether this box’s changing XOR-MAPPED addresses would make an
  advertised typ srflx unusable toward sufa even if checks are sent.
- sufa-side check logs (readonly SSH was not expanded in this step;
  no node restart).
- Public NAT traversal success. typ srflx / `stun` is not a public
  P2P success claim. TURN would be a media relay, not direct P2P.
  typ host on `100.91.104.2` is `cgnat`, not Tailscale overlay, and
  Tailscale overlay would not be public P2P either. No TURN was
  added or deployed.

0924 stays frozen and was not overwritten.

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
- `agentlink-core` `rewrite_skips_rfc2544_literals_and_rewrites_poisoned_hosts`
  and `prepare_rewrites_only_poisoned_default_stun_hosts` (DoH/literals
  only for poisoned default STUN hosts; operator URLs untouched;
  `AGENTLINK_STUN_REWRITE=off` leaves defaults alone).
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
remain immutable, as do 0910 and 0924.

## Three evidence classes (do not mix)

1. **GUI 0924 already accepted (frozen bin, not this source).** Parent
   GUI used
   `/workspace/agentlink-t427-recovery/20261112-0924-t449-controller-p2p/`
   (debug bin SHA
   `f6497e7ab0b0f6e9186613f4cef4bb629fb6054f98e1e0b447cf5ca430d2c2f4`,
   SOURCE-COMMIT `d98f8a8`). That run showed JPEG stills continuing and
   the 12s “no selected ICE pair” terminal handshake kept after close
   (not overwritten by `signal close ok`). 0924 is frozen and was not
   overwritten.
2. **This worktree’s final code (DNS scope + ICE instrumentation +
   tests) has not had a GUI pass.** After `d98f8a8`, commit
   `a597ffe` narrowed DoH/literal rewrite and added safe ICE check
   logs; a follow-up commit adds branch tests and timed close/cleanup
   assertions. Parent should retest **once**, read-only, with the new
   dated archive — not 0924, not 0910, not 0851. Expect the same JPEG
   fallback and sticky no-pair handshake; also expect
   `AGENTLINK_STUN_REWRITE` defaults-only behavior and `live-ice:`
   lines. This is a code/instrumentation change, not a new P2P result.
3. **Actual public NAT P2P is still not passed.** Box↔sufa never
   selected an ICE pair. typ srflx is confirmed XOR-MAPPED, but that
   is not public P2P success. TURN and Tailscale overlay are not
   public P2P. No further probes, packet captures, or network/service
   changes were made after the 09:33 CST instrumented snapshot.

## Local regression actually run (2026-11-12 09:38 CST)

These commands were executed on this machine; this is not a claim
that every test in the repository is green.

- `cargo test -p agentlink-core --lib -- prepare_rewrites stun_rewrite rewrite_skips`:
  **3 passed** (healthy DNS keeps hostnames and DoH call count is 0;
  empty/RFC 2544 default hosts use DoH; operator URLs never call DoH;
  `off` never calls DoH; mode parser covers unset/empty/defaults/on/off/0/false/unknown).
- `cargo test -p agentlink-view --lib`: **13 passed**, including
  `close_off_runtime_finishes_within_deadline_and_releases_runtime`
  and the existing close/drop-on-tokio-runtime tests.
- `cargo test -p agentlink-view --test loopback`: **3 passed**,
  including `Viewer::close` finishing within the 2s wait plus slack
  and `stream_stop` audit after close. Same-host typ host / `private`
  only — not public NAT.
- `cargo test -p agentlink-cli --bin agentlink controller::`:
  **67 passed**, including `handshake_retention_tests` (3) and
  `live_pipeline_tests` (3).
- `cargo test -p agentlink-cli --test controller --test controller_debug`:
  **1 + 6 passed**.

**93 passed, 0 failed** in that set. Not run: the rest of
`agentlink-core` (267 other lib tests), other `agentlink-cli` bins
tests outside `controller::`, deploy/functional/smoke, and any GUI.

## Parent GUI path (this final candidate only)

Use
`/workspace/agentlink-t427-recovery/20261112-0938-t449-controller-p2p/`
once created. Launch is for the parent, not this worker:

`./run-controller.sh`

`AGENTLINK_CONFIG_DIR` may be set to the existing config. `--data-dir`
is isolated (`/tmp/agentlink-t449-0938-controller-data`). Do not point
it at a production node data dir. Do not mix with 0924/0910/0851/0307.

Read-only View of sufa. Confirm JPEG stills keep refreshing, handshake
keeps a no-pair (or no-first-frame) terminal reason after close, no
redundant stats `link` row, and stderr `agentlink live-ice:` / rewrite
logs. Do not expect a selected public P2P pair.


## 0938 GUI: `fps  0.0` on refreshing JPEG stills

Frozen evidence (not modified):
`/workspace/t449-0938-session-stats.png`,
`/workspace/t449-0938-terminal-stages.png`,
`/workspace/t449-0938-terminal-final.png`, and archive
`/workspace/agentlink-t427-recovery/20261112-0938-t449-controller-p2p/`
(debug bin SHA
`62ca7605f131a5f19930d8bbeab4b330fe7a25cb5bb96d1354b94888ad97bd62`).
0938 remains frozen.

### Diagnosis (read-only)

This was a **product statistics defect**, not a documented “fps means
live video only” definition in the Session stats popover.

Facts from the 0938 screenshots and this source:

- The remote clock moved 09:40→09:42 and the popover showed
  `path  jpeg · relay`, `encoder  jpeg`, resolution `2736×1824`, and
  the hint “JPEG stills over the WebSocket relay — not WebRTC P2P”.
  Stills were updating.
- The popover still printed `fps  0.0`, `bitrate  0 kbps`,
  `latency  0 ms`.
- JPEG shots are taken every 800ms in production
  (`Duration::from_millis(800)`). A counted stills rate would be
  about 1.25 Hz, not zero. This is **not** interval rounding and
  **not** a stale last-frame cache of a stalled video.
- The shot loop published `LiveHud` with `..LiveHud::default()`, so
  `fps`/`bitrate`/`latency` stayed 0. Only the H.264 decode window
  (500ms) ever computed `fps`.
- The compact connection-bar `stats_chip` / `stats_line` already
  omit fps when `fps <= 0.5` (so the bar did not claim 0 fps). The
  popover always printed `fps  0.0` with no “video only” label.
- Fallback/timeout `set_hud(LiveHud { jpeg, ..Default })` would also
  wipe a later measured rate and resolution until the next still.

`fps  0.0` on a refreshing JPEG therefore reads as a frozen video
stream. That is misleading.

### Fix (0951 candidate; does not invent numbers)

- The shot loop records actual JPEG publish timestamps over a 5s
  window. `stills_rate_hz` requires at least two samples spanning
  20ms; otherwise the value is unset.
- Session stats popover, when `kind=jpeg`:
  - measured rate → `stills  1.2 Hz` (one decimal, Hz);
  - unmeasured → `stills  n/a`;
  - never `fps  0.0`;
  - `bitrate  n/a` and `latency  n/a` (those are live-video
    metrics; they are not fabricated from stills).
- H.264 keeps `fps` / `bitrate` / `latency` as before.
- Timeout / connect-fail / disconnect fallback no longer publishes a
  default JPEG HUD that would overwrite the shot loop’s stills rate.
  Handshake, notice, and `jpeg · relay` link are unchanged.

### Tests added

- `stills_rate_hz_needs_a_real_span_and_does_not_invent_zero`
- `session_stats_jpeg_stills_are_labeled_not_zero_fps`
- `jpeg_stills_rate_is_measured_from_a_real_sequence` (injected JPEG
  every 50ms; HUD rate tracks that interval and formats as
  `stills  … Hz`)
- `negotiation_hud_stays_jpeg_through_offer_answer_wait_timeout_and_close`
  (test-only `IceFault::NoPairAfterSignaling` omits offer/answer ICE
  candidates and trickle so a pair cannot form; no network change).
  Sequence: JPEG already shown → offer → answer → waiting → 12s
  no-selected-pair → close. Painted path stays `jpeg · relay`, never
  `h264` / `connecting` / P2P. Terminal reason survives close.
  After stills, the popover line is `stills  … Hz`, not `fps  0.0`.

`IceFault::NoPairAfterSignaling` is test-only, like
`RelayPolicyWithoutTurn`. Production is `IceFault::None`.

## Local regression actually run (2026-11-12 09:51 CST)

These commands were executed on this machine; this is not a claim
that every test in the repository is green.

- `cargo test -p agentlink-core --lib -- prepare_rewrites stun_rewrite rewrite_skips`:
  **3 passed** (unchanged DNS policy tests).
- `cargo test -p agentlink-view --lib`: **14 passed**, including
  `strip_sdp_ice_candidates_keeps_ufrag_and_drops_candidates`.
- `cargo test -p agentlink-view --test loopback`: **3 passed**.
- `cargo test -p agentlink-cli --bin agentlink controller::`:
  **71 passed**, including the four new stills/HUD tests and the
  existing handshake-retention and live-pipeline cases.
- `cargo test -p agentlink-cli --test controller --test controller_debug`:
  **1 + 6 passed**.

**98 passed, 0 failed** in that set. Not run: the rest of
`agentlink-core` (267 other lib tests), other `agentlink-cli` bins
tests outside `controller::`, deploy/functional/smoke, and any GUI.
No new network probe, packet capture, or remote/service change.

## Parent GUI path (0951 candidate only)

Use
`/workspace/agentlink-t427-recovery/20261112-0951-t449-controller-p2p/`
once created. Launch is for the parent, not this worker:

`./run-controller.sh`

Do **not** reuse the 0938 binary for this stills-stats check. 0938
is frozen and was not overwritten. Isolated `--data-dir`
`/tmp/agentlink-t449-0951-controller-data`. Do not point it at a
production node data dir. Do not mix with 0938/0924/0910/0851/0307.

Read-only View of sufa. In Session stats, while JPEG stills are
refreshing, expect `stills  X.X Hz` (or `stills  n/a` only before a
second still), `bitrate  n/a`, `latency  n/a` — not `fps  0.0`.
Open stats during offer → answer → waiting → 12s timeout → close,
not only after timeout. Handshake should keep the no-pair (or
no-first-frame) terminal reason after close. Path stays
`jpeg · relay` unless a real H.264 frame arrives (do not expect a
selected public P2P pair).


## t450 — learn Tailscale, keep JPEG, retry with a bound

User t450 asked whether P2P was already fixed and how Tailscale
does it. It was **not** fixed after 0951. This section is the
official-source study and the first implementation batch: keep
JPEG up and renegotiate with a backoff budget. Public NAT P2P
on box↔sufa is still not claimed.

### Official sources (fetched 2026-11-12, not cloned)

- [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works)
  (David Anderson, 2020-08-21). The closing checklist: enumerate
  local and STUN `ip:port`s, exchange them on a side channel, *begin
  on a fallback relay*, probe all peer endpoints, transparently
  upgrade to a better path, downgrade if the active path dies.
- [NAT traversal, and how we're improving it (pt. 1)](https://tailscale.com/blog/nat-traversal-improvements-pt-1)
  (2025-10-15). “Every connection technically begins via DERP, then
  upgrades to a direct link if possible.” If traversal never
  succeeds, “traffic continues flowing over DERP for as long as
  needed.” Symmetric / “hard” NAT (mapping differs per destination)
  is called out as the usual direct-path failure. `tailscale netcheck`
  reports whether the mapping varies by destination.
- [DERP servers](https://tailscale.com/docs/reference/derp-servers)
  (docs last validated 2026-01-21). DERP is a rendezvous *and* a
  last-resort relay for already-encrypted WireGuard packets, not a
  WebRTC/TURN server.
- [What is STUN?](https://tailscale.com/docs/reference/stun-protocol)
  (docs last validated 2025-08-06). Clients STUN to *all* DERP
  relays so they can compare mapped `ip:port`s.
- [How Tailscale works](https://tailscale.com/blog/how-tailscale-works).
  DERP is described as filling the *role* of TURN, over HTTPS, using
  WireGuard keys. That is an analogy, not protocol equivalence.
- Upstream source (raw, no clone), `main` as of this fetch:
  - [`disco/disco.go`](https://raw.githubusercontent.com/tailscale/tailscale/main/disco/disco.go):
    `CallMeMaybe` is sent *only over DERP* after the sender has
    already sent UDP, asking the peer to open a path back, and
    carrying `MyNumber` endpoints (including a fresh STUN mapping).
  - [`net/netcheck/netcheck.go`](https://raw.githubusercontent.com/tailscale/tailscale/main/net/netcheck/netcheck.go):
    `MappingVariesByDestIP` is set when two IPv4 STUN replies show
    different mapped `ip:port`s.
  - [`wgengine/magicsock/endpoint.go`](https://raw.githubusercontent.com/tailscale/tailscale/main/wgengine/magicsock/endpoint.go)
    and `magicsock.go`: `heartbeatInterval = 3s`,
    `trustUDPAddrDuration = 6500ms`; `heartbeat` keeps the best UDP
    path alive and, when needed, `sendDiscoPingsLocked` plus
    `enqueueCallMeMaybe`.
  - [`derp/README.md`](https://raw.githubusercontent.com/tailscale/tailscale/main/derp/README.md):
    DERP relays disco *and* WireGuard; only the DERP-home connection
    must stay up.

### What is transferable vs not equivalent

Transferable *strategy* (and what 0951 was missing):

- A working relay path must not be torn down because direct
  negotiation missed once. In Agentlink that relay path is **JPEG
  over the existing WebSocket**, not DERP and not TURN.
- Failures must stay visible, then a **bounded** retry / candidate
  refresh may run, with backoff, instead of a single 12s wait and
  a permanent close of the live attempt.
- Upgrade to H.264 when a real frame arrives; downgrade to JPEG
  if the live path dies, then retry within the budget.

Not equivalent, and not claimed:

- WireGuard + DERP + disco is not WebRTC ICE + TURN. Shipping
  Tailscale’s overlay, or standing up DERP/TURN, is not “native
  public P2P.”
- Hard / symmetric NAT is **not** guaranteed to punch, even for
  Tailscale (their own 2025 post says two hard NATs almost always
  need a relay).
- `CallMeMaybe`, multi-DERP STUN `MappingVariesByDestIP`, and
  birthday-port probes need both peers and a side channel we do
  not have in the current node signaling. They are not copied
  here.
- The current node **batches** ICE candidates in the offer
  answer and accepts viewer trickle (`action: ice`) but does
  **not** push late answer candidates back. Prior box↔sufa
  probes already showed `gather_complete=true` and public `srflx`
  in *both* inventories, so missing trickle is a real protocol
  gap but **not** a proven root cause of the no-pair result.
  A bidirectional `ice_pull` / trickle extension can be a later
  both-sides candidate; it is **not deployed**.

### Why typ srflx still does not prove a pair (no NAT verdict)

Safe `get_stats()` snapshots (`agentlink live-ice:`) still report
`pairs=0` / `req_sent=0` when nothing is selected. The public
`webrtc-0.21.1` report is what we log; we did **not** patch
third-party crates or capture STUN Binding packets (those carry
ICE ufrag). `rtc-ice` *can* list all pairs on the Agent, but that
API is not exposed through the PeerConnection stats we already
use. Therefore “no pair despite real XOR-MAPPED srflx” remains
an open connectivity question — **not** a diagnosed symmetric-NAT
conclusion. No firewall, route, or online-node change was made
to chase it.

A fully local dual-peer experiment in this worktree: when a test
fault strips remote candidates, no pair forms and JPEG stays;
when a later attempt uses a normal same-host answer, H.264
arrives. That only proves the retry machinery and the same-host
stack, not public NAT traversal.

### What was implemented (controller only, local)

`LiveSchedule` (default: 3 attempts, 12s ICE wait, 3s then 6s
backoff, session offer budget 6). After a *soft* miss (no pair,
no first frame, connect error that is not a hard reject, or a
later live-path loss) the Viewer is closed and released, JPEG
stills continue, handshake shows the retry, and a new offer is
sent. Hard rejects (`not allowed` / grant / denied) do **not**
retry. After the budget is spent, the last reason is kept as a
terminal handshake, including `stopped after N attempts` when
N>1. A successful H.264 takeover resets the *streak* but still
consumes the session offer budget, so a flapping path cannot
hammer a node.

### Tests run (2026-11-12 12:12 CST)

This is additional coverage for the retry strategy; it is not a
claim that public P2P is done.

- `agentlink-core` rewrite/STUN tests: **3 passed**
- `agentlink-view --lib`: **14 passed**
- `agentlink-view --test loopback`: **3 passed**
- `agentlink-cli --bin agentlink controller::`: **75 passed**,
  including `live_retry_backoff_is_bounded_and_does_not_run_forever`,
  `jpeg_retries_then_recovers_h264_without_claiming_p2p_early`
  (two short no-pair attempts, third same-host attempt received
  H.264; JPEG stayed `jpeg · relay` until then; 3 offers),
  `exhausted_retries_keep_jpeg_release_viewer_and_stop`
  (3 offers, terminal “stopped after 3 attempts”, viewer slot
  released, JPEG still refreshing),
  `missing_grant_does_not_spend_retry_budget` (0 offers).
- `controller` + `controller_debug`: **1 + 6 passed**

**102 passed, 0 failed** in that set. Not run: remaining
`agentlink-core` lib tests, other bins, deploy/smoke, GUI, or any
new sufa/phone probe.

### Cross-machine P2P?

**No.** This batch did not select a public ICE pair or receive
H.264 from sufa. Same-host recovery in the harness is not public
NAT P2P. TURN and Tailscale overlay are not native public P2P.

### If a later close-the-loop needs user approval

Do **not** deploy from here. The smallest useful authorized
follow-up would be: (1) collect *safe* ICE check / candidate
inventories from the **sufa node process logs** during one
read-only View (no ufrag/password packet capture, no app
input/clip/portal), and/or (2) a reviewed both-sides trickle /
`ice_pull` deploy to a non-production node. Changing box or sufa
firewall/routes to “make P2P work” is out of scope unless the
user explicitly asks for that change and accepts the risk.

## Parent GUI path (1212 candidate only)

Use
`/workspace/agentlink-t427-recovery/20261112-1212-t449-controller-p2p/`
once created. Launch is for the parent, not this worker:

`./run-controller.sh`

**0951 is frozen** and was not overwritten (bin SHA
`5d237d80ef4ae70a8de2abd63c41f76306951dbd0a3754f769df5b1d4b7ae612`).
Isolated `--data-dir` `/tmp/agentlink-t449-1212-controller-data`.
Do not mix binaries. Read-only View of sufa. Expect JPEG to
remain through a no-pair miss, then up to two further offers
(3s / 6s backoff) rather than a single 12s-and-done live
attempt. Do not expect a selected public P2P pair.

# t450 — offer/gather/trickle lifecycle (local protocol, not a new 1212)

1212 remains frozen. This batch did not probe sufa, change log
levels, deploy, capture packets, or alter third-party crates.

## Does `live_pipeline` / loopback match the production path?

Yes, for the `webrtc_signal` contract. Both the Controller
`live_pipeline` harness and `crates/agentlink-view/tests/loopback.rs`
call `StreamHandler::handle_peer`, which is the same
`SessionManager` production uses via `dispatch_extension_as` →
`handle_peer` (node `ops.rs` only additionally stamps
`_allow_view` / `_allow_control`). They are not a two-peer
loopback that bypasses offer/answer/ice JSON.

They are **not** the production network: `Desktop::mock()`,
auto consent, isolated fixtures (no production identity or new
grant), in-process signaling rather than the relay, and both
peers on the same box. A selected `path=private` typ host pair
here is not public NAT P2P.

The deployed sufa node is still `0.1.0` / `bc97ba1`. These
tests run against the worktree node handler, which is the same
offer/ice/session contract plus the ice-ack honesty fix below.

## What the library actually does (read-only)

- `webrtc-0.21.1` `add_ice_candidate` → `rtc` `add_remote_candidate`
  requires a remote description, then parses only the candidate
  attribute. **`sdpMid`, `sdpMLineIndex`, and `usernameFragment`
  are ignored.** `RTCIceCandidate::to_json` sets `sdpMid` to `""`
  and m-line `0`. That shape still adds.
- `Agent::add_remote_candidate` pairs a new remote with every
  compatible local (`can_pair_with`: same IP family, matching
  TCP types) and requests a connectivity check. Late remotes
  after `start_connectivity_checks` are not dropped; they form
  new pairs. An early `pingAllCandidates called with no
  candidate pairs` warning is therefore not a terminal root
  cause if trickle or SDP candidates arrive afterwards.
- Host and srflx are gathered from the same bound
  `local_addrs`. The STUN gatherer does not close those
  transport sockets when a binding times out. No evidence in
  this library that a temporary gather socket is released and
  then leaves host candidates unusable.
- `get_stats()` still only reports selected / known candidates,
  not a full failed-check checklist.

## Proven gap and minimal fix

`SessionManager::ice` used to do `if let Ok(init) = serde_json::from_value(...) { add } ; Ok({ok:true})`.
A bare string, null, or foreign JSON was **acked `ok` without
`add_ice_candidate`**. The webrtc_signal audit could then show
ice ok for a candidate that was never added.

Fix: parse with `parse_trickle_candidate`, return an error on
a bad shape or unknown `session_id`, and only then
`add_ice_candidate`. Success is `{ok: true, added: true}`
(backward compatible). Logs record typ / `sdpMid` emptiness /
m-line only — no ufrag, password, or token.

The live Viewer trickle shape (`camelCase` Init, empty
`sdpMid`) **does parse**. Production's 18 ice-ok rows are
therefore not explained by this swallow, unless some payloads
were a different shape (not observed on this path). The fix is
still required so a future miss cannot hide behind `ok`.

## Protocol tests (real handler + Viewer)

- `trickle_ice_init_parses_the_viewer_to_json_shape`,
  `trickle_ice_bare_string_or_null_is_a_parse_error`
- `ice_before_session_is_rejected_and_is_not_ok` — ice before
  offer is `unknown stream session`, not `ok`
- `delayed_trickle_still_selects_a_pair_and_delivers_h264` —
  12 offer SDP candidates stripped, ICE already started, then
  delayed 400ms trickle: **6 `added=true`, 0 errors, selected
  typ host pair, H.264 IDR**. Late `add_ice_candidate` works
  on this path. Empty `sdpMid` does not prevent the add.
- `malformed_trickle_after_answer_is_not_acked_ok` — a bare
  candidate string after a real session is rejected; valid
  candidates still deliver H.264
- `short_gather_late_node_candidates_are_observed_without_claiming_nat`
  — `gather_ms=20`, answer already had 6 candidates
  (host+srflx), **0 additional candidates 2s later**. Same-host
  pair and H.264 still succeeded from the answer. **No
  `ice_pull` added**: it was not shown to be useful here.

## Still not a cross-machine P2P result

A complete-gather Viewer offer already embeds host+srflx in the
SDP, so trickle is often a duplicate of what `set_remote` has
already applied. The box↔sufa no-pair miss, after the DNS
rewrite gave both sides public typ srflx, is **not** explained
by mid/ufrag JSON mismatch, ice-before-session, or silent
parse-drop of the Viewer shape. It is also not a NAT-type
conclusion: this batch did not observe check send/receive on
the wire to sufa.

What still needs a user-authorized remote step (not done here):
safe node-side check inventories during a live View, or a
reviewed deploy of this ice-ack honesty change to a
non-production node. Do not treat TURN or Tailscale overlay as
native public P2P. Do not change firewalls or routes to force
a pair.
