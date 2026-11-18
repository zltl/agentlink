# Desktop shortcut acceptance

This is the coordinator checklist for a build that contains the desktop
keyboard and terminal clipboard work. Unit tests do not replace it. Do not
treat a green `cargo test` as GUI acceptance.

The candidate tree (cursor, right-click, Mutter cursor metadata, session
cleanup, Unicode clipboard under a control grant) stays. Mutter capture is
unchanged. Nothing here deploys a node, changes a grant, or touches identity
files.

## What the controller does

Keyboard capture starts only after the user clicks the live control picture
or the Keys button. View-only sessions and sessions whose grant no longer
allows input never inject keys, mouse, or clipboard text.

While capture is on and the window is focused:

- Letters, digits, Tab, Esc, arrows, Home/End, Page Up/Down, Backspace,
  Delete, Insert, shifted punctuation (`: ? ! | { } + =`), and F1–F24 are
  sent as key edges, paired by physical key slot so lifting Shift before `=`
  still releases `+`.
- On Windows nodes, `SendInput` sets `KEYEVENTF_EXTENDEDKEY` and hardware
  scan codes for navigation keys, Win/Apps, PrintScreen, numpad `/`, and
  right-side Ctrl/Alt.
- Ctrl/Shift/Alt/Super are sent as press and release, including repeats of
  the non-modifier key. A repeat is another key-down, not a second press.
- Ctrl+C/X/V/A/Z/Y are key chords on the remote desktop (`Meta` on macOS
  targets, `Ctrl` on Windows/Linux targets). They are not the terminal PTY
  and they are not a second copy of the clipboard-sync channel.
- If the toolkit emits Copy, Cut, or Paste instead of the letter key, the
  controller sends one chord and does not also type the clipboard text.
- If the controller's local text clipboard is empty when the user presses
  `Ctrl+V` or `Shift+Insert` (for example after copying a file or image on
  the remote desktop), `egui-winit` swallows the key-down; the controller
  recovers and injects one paste chord on key-up without duplicating normal
  pastes.
- On Windows controllers, `Shift+Delete` and `Shift+Insert` stay
  `Shift+Delete` (permanent delete) and `Shift+Insert` instead of turning
  into `Ctrl+X` / `Ctrl+V`.
- IME preedit is not sent. A commit is sent once as text. The same commit
  is not also sent as keystrokes (including non-ASCII characters mapped onto
  punctuation keys such as German QWERTZ `ü`).
- ASCII text that already went out as a key is not sent again.

Capture and every held key are released when the window loses focus
(`WindowFocused(false)` or unfocused viewport), hides to the tray on close,
disconnects, loses its grant, leaves the desktop, or exits. Esc and captured
F11 are sent to the remote; release is the Keys button or leaving focus.

## System-reserved and toolkit-folded keys

The local OS or GUI toolkit may consume these before raw keys arrive. The
toolbar **Send** menu injects them on the remote and states the limit:

| Action | Remote chord | Limit |
| --- | --- | --- |
| Send Alt+Tab | alt+tab | Local OS often switches windows first |
| Send Alt+Shift+Tab | alt+shift+tab | Local OS often consumes it |
| Send Alt+F4 | alt+f4 | Local window manager may close this window |
| Send Win | meta | Local Super/Win usually opens the local shell |
| Send Win+D / E / R / L | meta+letter | Physical Win chords usually stay local |
| Send Ctrl+Insert | ctrl+insert | On Windows, `egui-winit` folds physical Ctrl+Insert into Copy (`Ctrl+C`) |
| Send Shift+Insert | shift+insert | Literal Shift+Insert for remote terminals and legacy editors |

Win+L locks the remote session only if the target accepts a normal meta+L.
It is not a secure-attention substitute.

**Ctrl+Alt+Del is not sent.** On Windows it is the secure attention sequence.
`SendInput` and the Linux portal key path cannot open the Windows security
screen. The menu says so and does not inject the chord. A Windows node that
still receives the combo returns an error instead of reporting success.

## Terminal, separate from the desktop clipboard

In a focused terminal:

- Ctrl+C or a native Copy event with a selection copies that selection.
- Ctrl+C or a native Copy event with no selection sends a single `^C`
  (interrupt). Copy plus Key(C) in one frame still sends one `^C`.
- Ctrl+V / Ctrl+Shift+V paste into the PTY (bracketed when the shell asks).
  That paste is not the desktop clipboard-sync channel.
- A plain click clears the selection. A drag does not.
- Remote `OSC 52` clipboard-store sequences are **denied by default** so
  terminal output cannot silently overwrite the operator's clipboard. An
  explicit session opt-in in Settings caps `OSC 52` writes at 64 KiB and
  shows a visible notice whenever a copy occurs.

Re-test the no-selection interrupt on a fresh terminal. Do not reuse a
terminal that still has a selection, and do not stage the clipboard with
`sleep 30` before the copy tests (Ctrl+C would replace it).

## Windows GUI matrix

Install the candidate build yourself. Do not change grants. Use an already
authorized control session.

1. Open the remote desktop in control mode. Before clicking the picture,
   type locally and press F11; confirm keys stay local.
2. Open the same node as view-only. Click the picture, type, right-click,
   and use Send. Nothing is injected and clipboard text is not shared.
3. In control mode, click the picture. Type `abc`, shifted symbols
   `: ? ! | { } + =` (including lifting Shift before `=`), hold Backspace,
   press Tab, Esc, arrows, Home/End/Delete, and F5/F11. Confirm no stuck `+`.
4. In a remote text field, Ctrl+A, Ctrl+C, Ctrl+V, Ctrl+X, Ctrl+Z, Ctrl+Y.
5. Clear the controller's local clipboard (or copy a file/image on the
   remote desktop), then press physical `Ctrl+V` on the remote desktop and
   confirm the remote paste still executes. Confirm `Shift+Delete` on a
   remote test file prompts for permanent delete rather than cutting.
6. Open Send and use Alt+Tab, Alt+F4, Win, and Ctrl+Insert. Confirm the
   note, and confirm Ctrl+Alt+Del is not claimed as sent.
7. While holding Shift on the remote, click outside the controller window
   (and test closing to the tray when `--background` / tray is active).
   Shift must be up on the target immediately afterward.
8. Disconnect with keys held. No key stays down.
9. Terminal, fresh session, no selection: paste `sleep 30`, Enter, Ctrl+C
   within a few seconds. The prompt must return before 30 seconds.
10. Terminal selection & OSC 52: Ctrl+C and Ctrl+Shift+C copy; plain click
    clears the selection; `printf '\033]52;c;dGVzdA==\a'` leaves the local
    clipboard unchanged while OSC 52 is off in Settings.

## Linux GUI matrix

Use an existing GNOME Mutter session. Do not replace a custom Mutter node or
restart `gnome-shell`.

1. Repeat Windows steps 1–6 and 7–8 against the Linux desktop, including
   typing `: ? ! | { } + =` into a remote terminal window that has no
   AT-SPI editable text widget. Alt+Tab and Super may be grabbed by the
   local compositor; the Send menu is the supported path.
2. Ctrl+Alt+Del is still not offered as a working inject.
3. Terminal interrupt (step 9) and selection / OSC 52 default-deny (step 10)
   on the Linux controller as well.
4. IME: compose a non-ASCII word, confirm the remote receives the commit
   once and does not also receive the spelling keys.
5. After disconnect (and after any failed connect), confirm no leftover
   Mutter RemoteDesktop or ScreenCast session remains on the session bus.

## Not covered by automated unit tests

- Real Windows GUI and real Mutter GUI (covered by the checklists above).
- Secure attention (`Ctrl+Alt+Del`) on Windows — ordinary injection cannot do it.
- Image or HTML clipboard — Unicode text only.
- macOS and Android device runs.
