# T417 fix notes — desktop type / ui-tree / window screenshot

Date: 2026-11-10 (Asia/Shanghai). Branch: `fix/desktop-input-a11y-window-t417` (keeps invite fix `447fa55`).

## Root causes

1. **IME-mangled `type`**  
   Linux backends typed via `NotifyKeyboardKeysym` / XTest keysyms. With a composing IME (toolbar "中"), Latin keysyms enter the IME composition buffer (digits select candidates), so markers like `T416-ISO-…` become garbage (`Tony16-` + candidate bubble).  
   **Fix:** Prefer AT-SPI `EditableText.InsertText` on the focused editable (literal commit, no IME). If that is unavailable, temporarily switch IBus/Fcitx5 to a Latin/passthrough engine for the call and restore afterward.

2. **`ui-tree` UnknownMethod GetDesktop**  
   Code called `org.a11y.atspi.Registry.GetDesktop(i)`. That method is **not** on the modern D-Bus Registry interface. Libatspi’s `atspi_get_desktop(0)` is a client-side alias for the registry accessible at `/org/a11y/atspi/accessible/root`.  
   **Fix:** Use that root path; probe `ChildCount` for an honest “AT-SPI capability missing …” error when the session a11y bus is unreachable (no silent privilege escalation).

3. **Window screenshot**  
   Mutter path only called `RecordMonitor` and hard-errored on `CaptureTarget::Window`. Mutter ScreenCast API ≥ 2 exposes `RecordWindow` with Shell Introspect window ids — a real compositor window stream (content + geometry + occlusion), not a cropped desktop.  
   **Fix:** One-shot ScreenCast `RecordWindow` after resolving id/title via `org.gnome.Shell.Introspect.GetWindows`. If that fails on an XWayland session, fall back to the X11 window drawable (still a real window buffer, not a relabeled full-screen crop). Clear capability errors when Introspect/RecordWindow are missing.

## Files changed

- `crates/agentlink-desktop/src/platform/atspi.rs` — root path, InsertText, GetRole/GetState, capability errors
- `crates/agentlink-desktop/src/platform/ime.rs` — new; temporary IBus/Fcitx5 guard
- `crates/agentlink-desktop/src/platform/shell_windows.rs` — new; title/id matching (+ unit tests)
- `crates/agentlink-desktop/src/platform/mutter.rs` — `RecordWindow` one-shot capture
- `crates/agentlink-desktop/src/platform/linux.rs` — type path (InsertText + IME guard); window capture routing
- `crates/agentlink-desktop/src/platform/mod.rs` — module wiring
- `crates/agentlink-cli/src/main.rs` — tip needles for new capability errors

## How to retest (live node on sufa / GNOME)

Rebuild/install the node binary from this branch, restart `agentlink-node.service` as user `ltl` with the usual session env (`DISPLAY`, `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, `XAUTHORITY`).

1. **type / IME**  
   Leave Chinese IME on (toolbar "中"). Focus an isolated gnome-text-editor window.  
   `agentlink type sufa 'T416-ISO-INPUT-OK-fd0d09a3'`  
   Expect the file contents to match the marker literally. Also try a short Chinese string and a newline.

2. **ui-tree**  
   `agentlink ui-tree sufa`  
   Expect a JSON tree (not `GetDesktop` / `UnknownMethod`). If a11y is truly down, expect `AT-SPI capability missing: …`.

3. **window screenshot**  
   Discover a title via ui-tree (or a Mutter window id).  
   `agentlink screenshot sufa --target window --window-id '<title substring>'`  
   Expect a PNG whose size matches that window (not 2736×1824 full desktop). Full-screen capture should still work.

## Tests run here

- `cargo test -p agentlink-desktop --lib` — **69 passed** (includes atspi/ime/shell_windows unit tests).
- `cargo test -p agentlink-desktop --test x11_roundtrip` — passed (Xvfb/DISPLAY).
- `cargo test -p agentlink-ffi short_empty_malformed` — invite still registers only / does not grant.
- This environment has **no libpipewire headers** and **no g++**, so Mutter `RecordWindow` was not compiled here and `agentlink-cli` tip tests were not rebuilt. On a machine with `libpipewire-0.3` + Mutter/GNOME, rebuild desktop with PipeWire and retest window capture live.

### Live-only coverage (document; not automated here)

- IME guard against a real IBus/Fcitx5 Chinese engine
- AT-SPI tree against the session a11y bus from a systemd user/system unit with session env
- Mutter `RecordWindow` + Shell Introspect on GNOME Wayland

## Remaining limitations

- Portal-only Wayland (no Mutter private API) still cannot capture a single window; error stays capability-clear.
- IME bypass via engine switch needs `ibus` or `fcitx5-remote` on PATH; otherwise keysyms may still compose if AT-SPI InsertText also fails (e.g. non-editable focus).
- X11 window fallback does not show Wayland-native occlusion over that window.
- Invite behavior unchanged: invite enrolls only; control still requires a node-local grant.

## Follow-up after live sufa retest (21:00–21:03 Asia/Shanghai)

Live isolated node `sufa-t417-9bf95e3-test` on 127.0.0.1:18443, binary
`0.1.0 (9bf95e332fb97b275e2e8e405d59f7166826da4d)` linked to libpipewire-0.3
(sha256 ea70ef3f73e30f4ed0901637f5daf57c1b7b13daa6d0e44eff8dc71e050d1d61).

- **ui-tree**: PASS. `backend: atspi`, JSON tree, no GetDesktop/UnknownMethod.
  System-scope/SSH-started node with session bus env attaches to the user a11y bus.
- **type / IME**: With IBus engine `libpinyin` (toolbar 中) left on, ASCII, punctuation,
  and newlines committed literally into an isolated gnome-text-editor
  (`T417-ISO-INPUT-OK-9bf95e3` / `Hello, world! 123; --path=/tmp`). IME remained
  `libpinyin` afterward. CJK `中文输入测试：你好。` reported "typed 11 characters"
  but did not appear. Cause: `InsertText` passed `text.len()` (UTF-8 bytes) as the
  AT-SPI character `length` (10 scalars vs 30 bytes). ASCII was accidentally correct.
  Fixed to `text.chars().count()`.
- **window screenshot**: Full-screen capture still works (2736×1824). Window capture
  returns an honest capability error: `Shell.GetWindows` is AccessDenied to regular
  clients (confirmed with session `gdbus` and `systemd-run --user`).
  `org.gnome.Shell.Screenshot.ScreenshotWindow` is also AccessDenied. The isolated
  editor is Wayland-native; `xlsclients` only shows `ibus-x11` and `mutter-x11-frames`,
  so the X11 drawable fallback cannot capture it. AT-SPI `GetExtents(SCREEN)` reports
  `0,0` for that frame (Wayland clients do not have global coordinates), so a
  cropped full-desktop region would be the wrong pixels and is not used.
  No GNOME desktop policy was loosened. Error text now also reports the failed
  X11 fallback.

`cargo test --release -p agentlink-desktop --lib` on sufa (PipeWire): 69 passed.

## Follow-up: CJK still missing after length fix (21:14 Asia/Shanghai)

Live log on the 15b4475-code binary (sha256 02616989…, version string still
cached as 9bf95e3): `AT-SPI InsertText unavailable; no focused editable text
field`. The CLI then fell back to keysyms with a temporary Latin IME guard.
ASCII/punctuation/newlines can be typed that way; CJK cannot, but the CLI
still reported "typed N characters".

Cause: `find_focused_editable` DFS from the desktop root spent its budget in
the large GNOME Shell/registry tree before reaching application buses (the
isolated editor is on a `:1.13` TextEditor bus).

Change (15ac65a): search application buses first; if needed, GrabFocus an
editable in an active/focused frame; do not report keysym success for
non-ASCII when InsertText failed.

## Follow-up: InsertText true but CJK still missing (21:24–21:35 Asia/Shanghai)

After 15ac65a (sha256 60cd72f9…), CJK `中文输入测试：你好。` returned
`typed 11 characters` with **no** InsertText-failure log, IBus stayed
`libpinyin`, and the visible editor still lacked the CJK. Editor stderr:

`gtk_text_buffer_emit_insert: assertion 'g_utf8_validate (text, len, NULL)' failed`

**Real cause:** AT-SPI `EditableText.InsertText` `length` is the UTF-8 **byte**
count to consume from `text` (libatspi: “number of characters … in bytes”).
Commit 15b4475/15ac65a passed `text.chars().count()` (10 scalars for the
fixture, 30 UTF-8 bytes). GTK validated/inserted only 10 bytes, mid-sequence
UTF-8 failed, **InsertText still returned true**, and nothing landed. The
earlier “byte length was wrong” diagnosis was inverted; byte length failed
then because the editor bus was never reached.

Live probe on the focused GtkSourceView (`:1.13`, EditableText):
- `InsertText(..., length=10)` → D-Bus `true`, `GetText` unchanged, GTK critical
- `InsertText(..., length=30)` → D-Bus `true`, `GetText` contains the CJK
- `length=-1` also inserts the full string

**Fix:**
1. `insert_text_length` uses `text.len()` (UTF-8 bytes).
2. After InsertText returns true, `GetText` must show the inserted scalars at
   the pre-insert caret — RPC true alone is not success.
3. Negative: if there is no focused editable, `type` errors and does **not**
   fall through to keysyms (ASCII or otherwise). A focused non-editable
   (button/label/toolbar) must not redirect into another window’s editor via
   the old “any active frame” fallback; only focused container roles
   (window/frame/…) may search a descendant editable, else an ACTIVE
   application frame when nothing is focused.
4. Keysym+IME-guard remains only when a field exists but InsertText/verify
   failed and the payload is ASCII.

### How to verify actual widget text (not just CLI success)

1. Leave IBus `libpinyin` on. Focus the isolated gnome-text-editor.
2. `agentlink type … '中文输入测试：你好。'` — expect exit 0.
3. Confirm via AT-SPI `Text.GetText` on the focused EditableText **or** save
   the buffer / full-screen screenshot of the editor — CLI “typed N” is not
   enough.
4. Mixed / ASCII / newlines the same way. IME engine should still be
   `libpinyin` afterward (temporary Latin switch only on keysym fallback).
5. Negative: focus a non-editable UI (or no window); `type` must error with
   `no focused editable text field`.

### Window-capture capability limits (unchanged)

On this GNOME session, `org.gnome.Shell.Introspect.GetWindows` and
`ScreenshotWindow` are AccessDenied to regular clients. The test editor is
Wayland-native (no X11 drawable). Mutter `RecordWindow` needs Introspect ids.
xdg-desktop-portal Screenshot is full-session only here — not a silent
single-window path. Do not crop a full desktop and call it a window. The
client gets a clear capability error; full-screen/monitor capture still works.
No GNOME security policy was loosened.

`cargo test -p agentlink-desktop --lib`: 73 passed locally (includes
byte-length + landed-text + no-editable classifier tests).
