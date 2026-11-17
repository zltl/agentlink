# Desktop shortcut acceptance

This is the coordinator checklist for a build that contains the desktop
keyboard work. Unit tests do not replace it. Do not treat a green `cargo test`
as GUI acceptance.

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
  Delete, Insert, and F1–F12 are sent as key edges.
- Ctrl/Shift/Alt/Super are sent as press and release, including repeats of
  the non-modifier key. A repeat is another key-down, not a second press.
- Ctrl+C/X/V/A/Z/Y are key chords on the remote desktop. They are not the
  terminal PTY and they are not a second copy of the clipboard-sync channel.
- If the toolkit emits Copy, Cut, or Paste instead of the letter key, the
  controller still sends one Ctrl+C, Ctrl+X, or Ctrl+V. It does not also
  type the clipboard text.
- IME preedit is not sent. A commit is sent once as text. The same commit
  is not also sent as keystrokes.
- ASCII text that already went out as a key is not sent again.

Capture and every held key are released when the window loses focus, the
session disconnects, the grant is rejected, the user leaves the desktop, or
the controller exits. Esc is sent to the remote. Release is the Keys button
or leaving focus, not Esc.

## System-reserved keys

The local OS may consume these before the process sees them. The toolbar
**Send** menu injects them on the remote and states the limit:

| Action | Remote chord | Limit |
| --- | --- | --- |
| Send Alt+Tab | alt+tab | Local OS often switches windows first |
| Send Alt+Shift+Tab | alt+shift+tab | Local OS often consumes it |
| Send Alt+F4 | alt+f4 | Local window manager may close this window |
| Send Win | meta | Local Super/Win usually opens the local shell |
| Send Win+D / E / R / L | meta+letter | Physical Win chords usually stay local |

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

Re-test the no-selection interrupt on a fresh terminal. Do not reuse a
terminal that still has a selection, and do not stage the clipboard with
`sleep 30` before the copy tests (Ctrl+C would replace it).

## Windows GUI matrix

Install the candidate build yourself. Do not change grants. Use an already
authorized control session.

1. Open the remote desktop in control mode. Before clicking the picture,
   type locally and confirm the remote does not receive it.
2. Open the same node as view-only. Click the picture, type, and use Send.
   Nothing is injected.
3. In control mode, click the picture. Type `abc`, hold Backspace, press
   Tab, Esc, arrows, and F5. Each arrives once on the target except the
   Backspace repeat.
4. In a remote text field, Ctrl+A, Ctrl+C, Ctrl+V, Ctrl+X, Ctrl+Z, Ctrl+Y.
5. Open Send and use Alt+Tab, Alt+F4, and Win. Confirm the note, and confirm
   the physical chord may still be swallowed locally.
6. Confirm the UI does not claim Ctrl+Alt+Del was sent, and the Windows
   security screen does not appear from the menu.
7. While holding Shift on the remote, click outside the controller window.
   Shift must be up on the target afterward.
8. Disconnect, and again leave the window, with keys held. No key stays down.
9. Terminal, fresh session, no selection: paste `sleep 30`, Enter, Ctrl+C
   within a few seconds. The prompt must return before 30 seconds.
10. Terminal with a selection: Ctrl+C and Ctrl+Shift+C copy; Ctrl+V and
    Ctrl+Shift+V paste. A click with no drag clears the selection.

## Linux GUI matrix

Use a sufa Mutter session. Do not replace the Mutter node or restart
gnome-shell.

1. Repeat Windows steps 1–5 and 7–8 against the Linux desktop. Alt+Tab and
   Super may be grabbed by the local compositor; the Send menu is the
   supported path.
2. Ctrl+Alt+Del is still not offered as a working inject. A logged-in
   session shortcut, if the compositor has one, is outside this client.
3. Terminal interrupt (step 9) and selection copy/paste (step 10) on the
   Linux controller as well.
4. IME: compose a non-ASCII word, confirm the remote receives the commit
   once and does not also receive the spelling keys.
5. After disconnect, confirm no leftover Mutter capture session remains
   (existing cleanup). Do not remove that path.

## Not covered here

- Real Windows GUI and real Mutter GUI. Those are this matrix.
- Secure attention on Windows. Ordinary injection cannot do it.
- Image or HTML clipboard. The candidate shares Unicode text only.
- macOS controller shortcuts beyond the shared key names.
