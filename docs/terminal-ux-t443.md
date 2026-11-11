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
