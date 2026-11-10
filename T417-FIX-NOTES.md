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
  AT-SPI character `length` (11 scalars vs 33 bytes). ASCII was accidentally correct.
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
