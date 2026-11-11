# Terminal interactivity (t443)

Date: 2026-11-11 Asia/Shanghai
Branch: `feat/terminal-ux-t443` from `fdcbc4b`
Status: first batch implemented and tested in isolation. **Not deployed. Not production. Not a phone P95.**

Human operators (including on Android, the originating client) report the
remote shell feels laggy. This note records official sources, what the
Agentlink code actually does, evidence versus hypothesis, and the first
patch set. It does not change grant or auth boundaries.

## Official sources (fetched, not recalled)

- VS Code terminal is built on xterm.js and a Unix-style PTY stream:
  [Terminal Advanced](https://code.visualstudio.com/docs/terminal/advanced).
- VS Code **remote local echo is optional and cautious**. Official docs
  (same page, “Reducing remote input latency (Preview)”): keystrokes may be
  shown dimmed before the remote confirms; it **starts only when measured
  latency is above 30 ms** (`terminal.integrated.localEchoLatencyThreshold`);
  it **disables itself for dynamic/fullscreen programs**, default exclude
  list `vim`, `vi`, `nano`, `tmux`; it can be turned off entirely. Agentlink
  will **not** add blanket optimistic echo in this batch.
- VS Code flow control (official source, not a wiki summary):
  [`FlowControlConstants` in `terminal.ts`](https://github.com/microsoft/vscode/blob/main/src/vs/platform/terminal/common/terminal.ts)
  — pause the PTY at **100_000 unacked chars**, resume below **5_000**,
  client acks every **5_000** chars. Implemented in
  [`terminalProcess.ts`](https://github.com/microsoft/vscode/blob/main/src/vs/platform/terminal/node/terminalProcess.ts)
  (`_unacknowledgedCharCount`, `pause`/`resume`, `acknowledgeDataEvent`).
  The comment states the goal is to avoid flooding a **shared** connection,
  not to add input delay. Persistent sessions / PTY host isolation are
  documented on the same Advanced page.
- xterm.js official typings:
  [`typings/xterm.d.ts`](https://github.com/xtermjs/xterm.js/blob/master/typings/xterm.d.ts)
  — `write()` accepts raw UTF-8 bytes (streaming parse is async; a callback
  fires when the parser has consumed the chunk); `onWriteParsed` fires **at
  most once per frame**; custom parser handlers should stay synchronous so
  the parser stays fast.
- [Mosh](https://mosh.org/) and the
  [USENIX paper](https://mosh.org/mosh-paper.pdf): speculative local echo
  with **epochs**, display only after a prediction is confirmed, new tentative
  epoch on Esc / Enter / arrows, underline outstanding predictions after
  ~100 ms, recover errors within one RTT. This is a full screen-state
  protocol (SSP), not a drop-in for Agentlink’s byte stream. Useful as a
  **future** option, not the first patch.
- [Kitty keyboard protocol](https://sw.kovidgoyal.net/kitty/keyboard-protocol/)
  (also implemented by WezTerm and xterm.js): unambiguous keys, press/repeat/
  release, IME/text as UTF-8. Relevant later for shortcuts; not the first
  lag fix. VS Code has `terminal.integrated.enableKittyKeyboardProtocol`.

## Agentlink data path (Android controller, shared backend)

```
key / IME / soft key
  → TerminalView.send / onBytes
  → writePty (Kotlin)
  → PtyHandle.cmd channel → PtySession.write (Op::PtyInput, E2E)
  → node PTY
  → Envelope::Chunk back
  → PtyHandle push to event queue (poll)
  → RemotePanes LaunchedEffect poll loop
  → TerminalView.feed → TerminalScreen parser → postInvalidateOnAnimation
  → onDraw (full visible grid)
```

The web dashboard (`crates/agentlink-relay/src/dashboard.html`) applies
`chunk` from the WebSocket `onmessage` path — it does **not** use the
Android 30 ms poll loop. Fixing only the dashboard would not address the
phone client.

`Op::PtyInput` is already excluded from node audit (`audit_this = !PtyInput`).
This work must not start logging keystrokes or command text.

## Evidence (reproduced from source; not claimed as production P95)

1. **Android output poll always waits 30 ms**
   (`RemotePanes.kt` shell `LaunchedEffect`, `delay(30)` after every poll,
   including after a `data` event). Echo of a key therefore waits up to one
   extra 30 ms **after the bytes are already in the local event queue**,
   and long output is paced at ≤ ~33 chunks/s even when more is buffered.
   This is local scheduling, not network RTT.

2. **Shared `PtyHandle` event loop parks writes behind an idle 40 ms recv**
   (`crates/agentlink-ffi/src/client.rs`, pre-patch): the loop `try_recv`s a
   command then `timeout(40ms, session.recv())`. A keystroke that arrives
   *during* that wait sits in the channel until the timeout fires or a
   chunk arrives (isolated baseline ~35 ms when the write is queued 5 ms
   into the wait). Continuous output actually returns from `recv` quickly
   and then `try_recv`s again; the sharper local lag is idle-prompt
   waiting, plus the Android poll delay below. The CLI `interact_lines`
   path already uses `tokio::select!`.

3. **Per-keystroke `launch(Dispatchers.IO)`**
   `writePty` starts a new IO coroutine for every send. `Dispatchers.IO`
   does not preserve launch order, so two quick keypresses can be enqueued
   to `PtyHandle` out of order. A single unbounded `Channel` consumer
   preserves order (mutex acquire order would not).

4. **IME composition is not surfaced**
   `TerminalView` implements `commitText` / `deleteSurroundingText` /
   `sendKeyEvent` only. There is no `setComposingText`. Chinese IME
   typically composes before commit; with no local composing preview, the
   user sees nothing until the candidate is confirmed — this feels like lag
   even when the network is fine. A **local composing overlay** (not sent
   to the PTY until commit) is not the same as optimistic echo of
   password/no-echo/fullscreen input.

## Hypotheses / unmeasured (not treated as proven)

- Full-viewport `onDraw` cost on large grids (dirty-row rendering not
  measured).
- Keyboard show/hide resize storms (size is already skipped when rows/cols
  are unchanged; remaining churn unmeasured).
- Unbounded PTY chunk queues: first batch now caps the *client poll
  queue* at 512, dropping oldest *data* events only and keeping exit
  / error. This is not remote PTY pause/resume like VS Code.
- `TerminalScreen` stores CJK as **one cell** (comment in the type). That
  can mis-align the cursor for Chinese. Not changed in the first patch
  (would be a separate, well-tested width change).
- Network RTT itself. Any later latency test that inserts delay must be
  labeled as **simulation**, not a device P95.

## Design choices (first batch)

Do:

- Give **input priority** on the shared FFI PTY pump (`select!` biased:
  commands before `recv`).
- **Drain** local PTY events without the 30 ms sleep; idle only when the
  poll returns `pending`, and then only for one frame (~16 ms), not as a
  throughput debounce on keystrokes.
- **Serialize** outbound keystrokes on a channel so order matches typing.
- Show **IME composing text** locally at the cursor; send UTF-8 only on
  `commitText` / `finishComposingText`.
- Add JVM tests for UTF-8 split feeds, CSI split across chunks, backspace,
  and resize clamping — plus a helper test for the poll idle policy.

Do not (this batch):

- Fixed long input debounce.
- Blind local echo of committed keys (password, no-echo, vim/nano, undo).
- Loosening per-keystroke auth/E2E, or keystroke telemetry.
- Claiming production hand-feel or P95 numbers.
- Flow-control watermarks and CJK cell width (documented follow-ups).
- Kitty keyboard protocol / Mosh SSP (follow-ups).

Success for this batch is a **mechanism** improvement that is testable in
isolation: no 30 ms pause after already-queued data, writes not blocked
behind a 40 ms recv timeout, stable write order, composing preview, parser
tests for fragmented UTF-8 and control sequences. Timing numbers, if any,
are same-environment microbenchmarks or labeled simulations.

## Implementation (this batch)

- FFI pump (`crates/agentlink-ffi/src/pty_pump.rs`): input-first
  `select!`, receive future kept across writes via a `PtyWriter` that
  does not borrow `recv`. A completed recv is dropped only after its
  value is applied, then a new `recv()` starts — this avoids losing a
  ready output chunk when a keystroke is also ready, and avoids holding
  `&mut PtySession` across `recv_fut.set`.
- Idle output wait removed on the FFI loop. Android `RemotePanes` drains
  up to 32 non-`pending` polls without `delay`; `delay(30)` only after
  `pending`. Keystrokes go through a 256-slot `Channel` (closed when the
  pane leaves composition) so order matches typing; `trySend` failure is
  reported, not silently dropped.
- IME: `ImeComposing` preview at the cursor; `setComposingText` / cancel
  (`set("")` or `discard`) do not write the PTY; `commitText` discards
  preview and sends the committed text once; `finishComposingText` sends
  remaining preview; delete edits the preview before any backspace.
- Client poll queue cap 512 (drop oldest data, keep exit/error).

### Isolated latency (not a device measurement)

Same mock, no network, 2026-11-11 23:50s Asia/Shanghai, `cargo test -p
agentlink-ffi pty_pump`:

- Legacy baseline (write queued ~5 ms into a 40 ms idle `recv` timeout):
  **34.755118 ms**
- Input-first candidate (idle `recv`, same mock): **22.24 µs**

This shows the avoidable local queueing is gone in the pump. It does
**not** measure phone RTT, IME, or render time, and is not a claimed
hand-feel speedup.

### Tests run in this pass (not reused t427 counts)

- `agentlink-ffi --lib`: **16 passed**, 0 failed (includes 5 new
  `pty_pump` tests + 11 existing ffi tests, including a real local PTY
  echo test).
- Android `:app:testDebugUnitTest` (filtered): **13 passed**, 0 failed
  — `TerminalScreenPumpTest` 5, `ImeComposingTest` 6, plus 2 existing
  `ModelTest` terminal cases.

Untested here: real phone, real IME on a device, production E2E RTT,
CJK two-cell width, remote flow-control pause.

Code lands on `feat/terminal-ux-t443` only. Bundles go under
`/workspace/agentlink-t427-recovery/` and must not overwrite the t427
GNU candidate or `20261111-2004` artifacts. No push, merge, deploy, or
production node restart.


## Correctness patch (2026-11-12 Asia/Shanghai)

The first batch’s client poll queue (`EVENT_QUEUE_MAX_EVENTS = 512`) **did
drop the oldest `data` event** to make room, while keeping exit/error. That
is not safe for a terminal byte stream: dropping an arbitrary chunk can
split a UTF-8 sequence or a CSI, and can desync fullscreen/TUI state.
This patch removes that behavior. It does not change grant or auth
boundaries, and it is still **not deployed**.

### Official sources → mechanism → this change

Only pages actually fetched earlier; nothing is invented, and a 404 is
not treated as a source.

| Official source | Mechanism taken from it | What landed in this / the prior t443 patch |
| --- | --- | --- |
| [VS Code Terminal Advanced](https://code.visualstudio.com/docs/terminal/advanced) and [`FlowControlConstants`](https://github.com/microsoft/vscode/blob/main/src/vs/platform/terminal/common/terminal.ts) (`HighWatermarkChars=100000`, `LowWatermarkChars=5000`, `CharCountAckSize=5000`), implemented in [`terminalProcess.ts`](https://github.com/microsoft/vscode/blob/main/src/vs/platform/terminal/node/terminalProcess.ts) (`pause` / `resume` / `acknowledgeDataEvent`) | Bound outstanding output with **high/low watermarks**; pause producers instead of dropping bytes; hysteresis so the queue does not flap; the documented goal is to avoid flooding, not to delay input | Local `EventQueue`: high 512 events **and** 256 KiB total JSON bytes; low 128 events / 64 KiB; reserved 1 event + up to 1024 bytes for exit/error so a terminal event never evicts data. At cap, `push` returns `WouldBlock`, the event is **held**, and `recv` is paused until `poll()` / `pop()` notifies space. **No remote PTY pause/ack protocol** is implemented; this is client-side backpressure only. |
| Same Advanced page, “Reducing remote input latency (Preview)” | Optional local echo only above a 30 ms latency threshold; default exclude `vim` / `vi` / `nano` / `tmux` | Unchanged: **no** blanket optimistic echo of committed keys. |
| [xterm.js typings](https://github.com/xtermjs/xterm.js/blob/master/typings/xterm.d.ts) (`write()` raw UTF-8, streaming parse) | The parser consumes a **contiguous byte stream**; dropping mid-stream bytes is a correctness bug | Event queue never drops `data`. Stress tests cover order past the cap, and UTF-8 / CSI split across chunks (`你`, `\x1b[2;3HZ`). |
| [Mosh](https://mosh.org/) / [USENIX paper](https://mosh.org/mosh-paper.pdf) | Speculative echo with epochs — a full screen-state protocol, not a drop-in for this byte stream | Still **not** implemented. Cited only as a future option. |
| [Kitty keyboard protocol](https://sw.kovidgoyal.net/kitty/keyboard-protocol/) | Unambiguous keys; IME/text as UTF-8 | Not this patch. The earlier IME composing overlay (local preview until commit) already follows the “don’t send incomplete composition” idea. |
| WezTerm `multiplexing.html` | Fetch returned **404** | Not used. No WezTerm mechanism is claimed. |

### Queue and write-path rules

- **No unbounded memory queue** on the FFI poll path: caps are event
  count, per-event size (a single chunk larger than the data-byte cap is
  `Overflow`), and a total byte budget.
- **`Overflow`** (a chunk that can never fit, or a terminal error that
  cannot be reserved): keep already-queued data, enqueue an explicit
  error, and **end the session**. The pump must not keep running as if
  the stream were intact.
- **`WouldBlock`**: hold one event, wait on `Notify` from `pop()` /
  `close()`. Input (`PtyCmd`) is still selected while output is paused,
  then the held event is flushed when space returns, so continuous
  input must not permanently starve output.
- Exit / error use the reserved slot and must not evict data.
- Bounded write queues: FFI `WRITE_CMD_CAP = 256`, Android
  `WRITE_QUEUE_CAP = 256`. `try_send` / `trySend` failure
  (`Full` or `Closed`) **fail-closes** the session with an explicit
  message. It must not look like the keystroke was accepted.
- Remaining bound, documented and **not** fixed here: `PtySession.rx` in
  `agentlink-core` may still grow while the FFI side is paused. That is
  a further backpressure surface, not a claim of an end-to-end byte cap.

### Isolated latency (still not a device P95)

Same mock, no network, 2026-11-12 00:04 Asia/Shanghai, `cargo test -p
agentlink-ffi pty_pump`:

- Legacy baseline (write queued into a 40 ms idle `recv` timeout):
  **34.799202 ms**
- Input-first candidate (idle `recv`, same mock): **35.505 µs**

These numbers only show the local idle-recv wait is gone. They are not
phone RTT, IME, render time, or hand-feel.

### Tests this pass (separate from the earlier 16 + 28 + 34)

Earlier accepted counts stay historical: ffi lib 16, Android filtered 28,
`controller::` 34. This pass does not relabel them as new.

- `cargo test -p agentlink-ffi --lib`: **20 passed**, 0 failed (11
  existing ffi tests + 9 `pty_pump` tests). Of the 9: 4 first-batch pump
  tests remain; **5** are new or replaced for this correctness work:
  `event_queue_does_not_drop_data_when_full` (replaces drop-oldest),
  `slow_consumer_receives_more_than_cap_bytes_in_order`,
  `continuous_input_does_not_starve_output`,
  `close_while_blocked_does_not_hang_and_keeps_queued_data`,
  `oversized_chunk_ends_the_session_without_dropping_prior_data`.
- Android `:app:testDebugUnitTest` (same filters as before, plus the new
  class): **29 passed**, 0 failed — previous 28 plus **1** new
  `PtyWriteOfferTest`. `compileDebugKotlin` succeeded as part of this
  run (affected Compose sources compiled).
- `:app:assembleDebug`: **succeeded** 2026-11-12 00:05 Asia/Shanghai
  (`app-debug.apk`, 19M). Compose UI packaged. The APK contains
  `libjnidispatch.so` and `libandroidx.graphics.path.so` only — **no
  `libagentlink_ffi.so`**. `android/app/src/main/jniLibs` is absent;
  `ANDROID_NDK_HOME` is unset and `/home/box/Android/Sdk/ndk` is not
  present, so `android/build-native.sh` was **not** run. This is a UI
  compile, not a runnable on-device native build. The APK was **not**
  installed.

Untested still: real phone, screenshots, IME/hand-feel, production E2E
RTT, CJK two-cell width, remote PTY pause/ack, a bound on
`PtySession.rx`. Controller `::` tests were not re-run in this
correctness pass (no desktop-controller code change).


## Local-chain backpressure (2026-11-12 Asia/Shanghai)

The previous correctness patch bounded only the FFI poll `EventQueue`.
`PtySession.rx` was still `mpsc::unbounded_channel`, so a slow Android
consumer could pause FFI `recv` while the socket receive task kept
enqueueing envelopes without limit. That is **not** complete backpressure.
This follow-up bounds that waiter queue and makes the existing receive
task wait when it is full.

### Official sources (exact URLs actually fetched earlier)

Nothing new was invented, and WezTerm `multiplexing.html` remains a 404
and is not used.

| Exact URL | Mechanism | What this follow-up / earlier t443 patches changed |
| --- | --- | --- |
| https://code.visualstudio.com/docs/terminal/advanced | Persistent PTY host, flow control described with the source constants below; remote local echo is optional and cautious (30 ms threshold; default exclude `vim` / `vi` / `nano` / `tmux`) | Still no blanket optimistic echo. Flow control on the **local client chain** only. |
| https://github.com/microsoft/vscode/blob/main/src/vs/platform/terminal/common/terminal.ts (`FlowControlConstants`: `HighWatermarkChars=100000`, `LowWatermarkChars=5000`, `CharCountAckSize=5000`) | High/low watermarks and hysteresis so outstanding output is bounded | `pending` queue: high 512 events **and** 256 KiB payload bytes; low 128 events / 64 KiB. Same numbers remain on the FFI `EventQueue`. |
| https://github.com/microsoft/vscode/blob/main/src/vs/platform/terminal/node/terminalProcess.ts (`pause` / `resume` / `acknowledgeDataEvent`) | Pause the producer instead of dropping bytes; ack from the consumer | `dispatch` now **awaits** `PendingSender::send` after releasing the pending map lock, so a full queue pauses `run_socket` (it stops reading the local WebSocket). **No remote PTY pause/ack protocol was added.** |
| https://github.com/xtermjs/xterm.js/blob/master/typings/xterm.d.ts | `write()` is a contiguous UTF-8 byte stream | The waiter queue never drops a queued `Chunk`. Tests push split `你` (`0xe4` then `0xbd 0xa0`) and CSI `\x1b[2;3HZ` through core `dispatch` and the core+FFI pump. |
| https://mosh.org/ and https://mosh.org/mosh-paper.pdf | Speculative echo / screen-state protocol, not a drop-in for this byte stream | Still not implemented. |
| https://sw.kovidgoyal.net/kitty/keyboard-protocol/ | Unambiguous keys; IME as UTF-8 | Not this patch. The earlier IME composing overlay is unchanged. |

### What is bounded, and what is not

- `ClientInner.pending` (including `PtySession.rx`, unary waiters, and
  `stream_op`) uses `pending::channel`: event count + total `data_b64`
  bytes, reserved 1 event / up to 1024 bytes for `End` / `Result { ok:
  false }`, hysteresis, `WouldBlock` waits, `Overflow` (a chunk larger
  than the data-byte cap) keeps prior data, enqueues an explicit error,
  and closes that waiter.
- `dispatch` clones the sender, drops the mutex, then `select!`s the
  send against shutdown so a full queue does not deadlock
  `PendingGuard` / session drop, and shutdown does not sit forever
  inside a send.
- `fail_waiters` drains the map first, `try_send_error`s, then closes
  senders — never a blocking send under the lock.
- The FFI pump additionally `select!`s `EventQueue` close while waiting
  on `session.recv()`, so a consumer disconnect does not hang behind a
  full write command channel.
- Writes keep flowing while output is blocked (input-first; hook /
  `PtyCmd` still selected). A full write channel still fail-closes.

**Residual, not claimed as end-to-end flow control:** there is still no
application pause/ack to the node PTY. Pausing `run_socket` applies TCP
backpressure on this socket. The node's live outbound channel is already
`mpsc::channel(256)` (`emit_blocking` uses `blocking_send`). The node's
**replay ring** (`crates/agentlink-node/src/resume.rs`) is a separate
reconnect buffer that evicts oldest frames at 1024 frames or 4 MiB; this
patch does not change it. Kernel and relay buffers also sit outside the
client caps. Worst-case **client** buffering for one PTY is the pending
queue plus the FFI `EventQueue` plus one held event (each 512 events /
256 KiB class), not an unbounded process heap.

A pre-existing `read_available` path can still truncate a decoded chunk
to `max_bytes` and drop the remainder of that already-received envelope.
That API is not the interactive FFI pump and was not changed here.

### CJK cell width (existing, not changed)

`TerminalScreen` already documents and implements “CJK characters occupy
one cell”: `putChar` stores one `Char` and advances `cursorCol` by 1,
including for code points such as `你`. East Asian Width typically needs
two terminal cells, so cursor, wrap, and full-screen programs can
misalign with a real xterm. This predates t443. Recording it here is
deliberate; it is **not** fixed in this patch and is not expanded into
a terminal-emulator rewrite.

### Controller UI

Still a **first-pass hierarchy revision**, not a complete redesign. No
new screenshots were taken in this environment. No real-device hand-feel.
Do not invent figures.

### Tests this pass (separate from 16+28+34 and from the prior 20/29)

- `cargo test -p agentlink-core --lib pending::`: **6 passed** (count
  cap, byte cap, overflow without evicting, >512 order with split UTF-8
  / CSI, drop-receiver unblocks send, reserved error slot).
- Additional core tests: `pending_dispatch_backs_up_the_receive_task_without_dropping_bytes`,
  `dropping_a_pty_session_unblocks_a_full_pending_send`, plus existing
  `device_list_reaches_the_waiter_instead_of_timing_out` and
  `transfer_inbox_keeps_stream_ready_ahead_of_its_chunk` after the
  async `dispatch` change.
- Full `cargo test -p agentlink-core --lib` on this revision: **263
  passed, 1 failed**. The failure is `identity::tests::concurrent_first_create_converges_on_one_identity`
  (identity file “EOF while parsing a value”). Re-runs both passed and
  failed; it is a pre-existing flake, not a pending-queue assertion,
  and was not “fixed” as part of this change.
- `cargo test -p agentlink-ffi --lib`: **23 passed** (previous 20 plus
  3 new chain tests):
  `core_and_ffi_chain_preserves_order_past_512_with_slow_consumer`,
  `core_and_ffi_chain_close_does_not_deadlock`,
  `core_and_ffi_chain_propagates_remote_error`. These drive a real
  `PtySession::test_io` + `pump_session`, not only a mock `EventQueue`.

Native APK / official script (2026-11-12 00:21–00:22 Asia/Shanghai):

- Installed NDK `27.2.12479018` on the box with the official SDK
  manager (`sdkmanager "ndk;27.2.12479018"`), matching
  `android/build-native.sh`. Rust targets added:
  `aarch64-linux-android`, `armv7-linux-androideabi`,
  `x86_64-linux-android` on toolchain 1.99.1.
- `bash android/build-native.sh` exited 0. UniFFI Kotlin bindings were
  regenerated with `--no-format` and **did not change** (git clean).
  arm64-v8a `libagentlink_ffi.so` exports **132** `uniffi_agentlink_ffi_*`
  symbols; they are a **1:1 match** with names referenced in
  `android/app/src/main/java/uniffi/agentlink_ffi/agentlink_ffi.kt`.
- `jniLibs` (gitignored) produced:
  - `arm64-v8a` ELF64 AArch64, 21,520,632 bytes — the ABI that applies
    to current user phones
  - `armeabi-v7a` ELF32 ARM, 14,370,516 bytes
  - `x86_64` ELF64 x86-64, 23,178,376 bytes (emulator / some tablets)
  The official script does **not** build `x86` or 32-bit `armeabi`.
- `:app:assembleDebug` succeeded. `app-debug.apk` is 75M and contains
  `lib/arm64-v8a/libagentlink_ffi.so` (21,520,632),
  `lib/armeabi-v7a/libagentlink_ffi.so` (14,370,516), and
  `lib/x86_64/libagentlink_ffi.so` (23,178,376). This is a **native
  candidate**, not the earlier 19M APK that lacked the Agentlink
  library. **Not installed** on any device. No real-phone run, no
  screenshot, no hand-feel claim.

## t447 desktop terminal emulator (2026-11-12 Asia/Shanghai)

The 00:55 GUI test proved the quant67 shell was a real PTY (hostname / whoami
as root) but still **line-oriented**. The desktop Controller now uses
Alacritty’s VT/grid core and does not keep “Enter sends the line” as the
primary input.

### Official component (checked)

- [`alacritty_terminal` 0.25.1](https://crates.io/crates/alacritty_terminal)
  is the grid + VTE parser extracted from
  [Alacritty](https://github.com/alacritty/alacritty) (Apache-2.0). Docs:
  <https://docs.rs/alacritty_terminal/0.25.1/alacritty_terminal/term/struct.Term.html>.
- We feed the **remote agentlink PTY** into `Processor::advance` / `Term`.
  We do not spawn a local tty or SSH. The MIT crate `egui_term` was
  considered; its backend is a local PTY, so only the Alacritty parser/grid
  is reused. The egui painter is ours.
- VS Code / xterm.js sources already listed above still apply for
  flow-control and write-parsed framing in the shared core (t443). This
  slice is the **desktop view**: cell grid, ANSI colors, cursor, resize,
  per-key input, IME commit (preedit is not sent), Ctrl+Shift+C/V
  copy/paste, CJK double-width cells.

Tests (no window): byte order, 中 = two cells, split UTF-8 / split CSI,
SGR + cursor address, backspace + resize, key encoding. A parent GUI retest
on the new candidate is still required for focus, IME, and a full-screen TUI.

## t447 follow-up (keyboard isolation, reopen, CJK font)

0111 retest: a focused terminal must consume Enter / Backspace / arrows
so they cannot activate another machine's Terminal button in the left
rail. `Emulator::consume_focused_keys` drains those events from the egui
context before the rail is painted. Pointer events are left alone so an
explicit click can still change the session target.

Reopen stays blank when the previous `PtyClose` is only a `Drop` /
`try_send`. The worker now awaits a reliable close before the next
`open_pty`, the UI shows starting/waiting state, and `PtyDone` without
output is an error — not a hidden refresh control.

CJK tofu in the Alacritty grid was missing glyphs, not only cell width
(Alacritty already gives 中 two cells). Font fallback is documented in
`docs/controller-layout-t444.md` (Noto Sans CJK, SIL OFL 1.1; no
rebundle of the collection).

## Quit and PTY teardown (0133 follow-up)

0133's `PtySession::close` awaits `PtyClose` on the controller worker
runtime, then sets `close_sent` so `Drop` only `try_send`s if close did
not already run. That path does not `block_on` from `Drop` or from the
UI thread, so it is not a "runtime inside runtime" close. A confirmed
0111 in-terminal runtime panic was reported, but no panic log was in
the frozen 0050/0111 candidate data dirs (those launches do not write
`tray.log`). 0133 keeps the same "no block_on in Drop" rule; this is
not claimed fixed from the absence of a log. The leftover processes
after closing the window were the hide-to-tray path, which 0133 still
had and is fixed in this follow-up (visible Quit; close exits unless
`--background` and a real tray icon).

## Layout: Machines list and session rail (0133 retest)

0133's two-column Machines grid overflowed when maximized, and the
session rail clipped **View desktop** to **View d…**, which also pushed
the main column right and left a black gap. The follow-up uses a compact
single-column list, truncates long host/id lines with hover and
click-to-copy, wraps whole action labels, and draws a fixed-width rail
inside the central panel that folds below 980 px. Details and screenshot
ids are in `docs/controller-layout-t444.md`. Real IME is still unaccepted
(你好 in the 0133 retest was octal `printf`, not an IME commit).

## Viewer close must not block a tokio runtime (0111/0133 panic)

Confirmed on both 0111 and 0133: `Viewer::close` at
`session.rs:214` used `blocking_send` on `agentlink-controller-net`
(`Cmd::PtyOpen` → `stop_live`). The 0149 layout candidate does not
contain this fix and has not been GUI-tested for exit. Close/Drop now
signal without parking the current runtime; tests cover close/drop
inside a tokio context. See `docs/controller-layout-t444.md`.

## Android CJK cell width, combining marks, and IME (isolated)

This is the in-tree Android terminal, not the desktop egui window.
`CellWidth` answers how many columns a code point uses, from Unicode
16.0.0 EastAsianWidth W/F (width 2), Mn/Me plus a small format /
variation-selector set (width 0), and Ambiguous as width 1. Combining
marks attach to the preceding base cell. `TerminalView` draws wide
cells and the caret with those widths. IME preview stays local until
commit (`ImeComposing`); that is unit-tested, not a real-device IME
acceptance.

Host unit tests and a debug-signed `:app:assembleDebug` APK are the
deliverable. The APK is not installed. No phone, no ADB, no change to
the user app signing key. Native `libagentlink_ffi.so` is rebuilt with
`android/build-native.sh` for arm64-v8a, armeabi-v7a, and x86_64 so the
APK matches current ffi/core, not the 00:21 ba0eae8 objects.
