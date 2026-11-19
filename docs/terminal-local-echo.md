# Desktop terminal local echo (safe default)

## Status

**Speculative faint local echo (t537) is not shipped.** The agentlink PTY
protocol does not expose host `termios` ECHO (or any equivalent per-keystroke
“safe to predict” bit). Without that, painting unconfirmed glyphs after a
previous echo — or promoting a remaining expect queue after a partial confirm —
can disclose password / `stty -echo` / `sudo` / `read -s` input (E1b).

## Shipped policy

- Keystrokes are dispatched to the remote PTY immediately (unchanged
  authorization and wire path).
- The Controller **waits for remote echo** for visible characters.
- `term_local_echo` may keep expect/reconcile bookkeeping for a future
  protocol, but **`overlay_cells` is always empty** and `note_outbound`
  never returns a paint signal.
- There is **no** silent opt-in to risky prediction.

## What would be required for true speculative echo

An end-to-end signal that establishes authoritative safety for the *next*
keystroke (for example, an explicit ECHO/mode channel that cannot race
in-flight with typed bytes). Telemetry snapshots alone do not close the race.

## Latency without prediction

Immediate input dispatch, local repaint scheduling, and write coalescing remain
valid. They do not imply predicted glyphs on screen.
