# Controller layout (t444)

Date: 2026-11-11 Asia/Shanghai
Branch: `feat/terminal-ux-t443` (same client workflow as t443; **separate commits**)
Status: first Android layout slice implemented and tested. Desktop login row aligned. **Not deployed. No real device screenshots.**

The user asked to fix an ugly, messy Agentlink controller. This note names
the actual UIs, what is wrong in the source (and one historical screenshot),
and the layout plan. It does not change grant issuance, auth, or ops.

## Which “Controller” this is

The message came from Android but did not name a surface. These are the
**real** controller UIs in this repo (not a fourth unrelated app):

1. **Android client (priority)** — Compose app the phone uses to control
   paired machines: `ClientApp.kt`, `AppShell.kt` (bottom nav: Machines /
   This phone / Settings), `MachinesScreen.kt`, `MachineHub.kt`,
   `RemotePanes.kt` (terminal / files / desktop), `Components.kt`, `Theme.kt`,
   `MachineUx.kt`. Isolated previews: `android/app/src/debug/.../Previews.kt`
   (360×1100 machines, 360×900 hub, light/dark login, desktop portrait /
   landscape). Existing JVM UI tests: `MachineUxTest.kt`, `ShellNavTest.kt`.
2. **Desktop `agentlink controller`** — egui app in
   `crates/agentlink-cli/src/controller/` (`ui.rs` ~3671 lines, `theme.rs`,
   `chrome.rs`). Login, machine list, then terminal / files / desktop each
   replace the central panel (no persistent list+detail). Historical
   screenshot: `/workspace/uploads/pr37/controller-login.png` (may predate
   the current tide/navy Android theme; still shows the desktop login
   hierarchy problem).
3. **Relay web dashboard** — `crates/agentlink-relay/src/dashboard.html`
   (~2521 lines), a third visual language (machines, terminal, files).
   Share spacing/copy patterns where it is the same product; do not only
   restyle the dashboard and claim the phone is fixed.

Grant *configuration / probe / ops* stays in another workflow. This work
may only clarify **already computed** status and permission *copy*.

## What is messy (evidence)

### Flat typography and stacked metadata

`Theme.kt` defines color roles (tide navy, WCAG comments, light/dark) but
**no type scale**. Almost every secondary line uses `bodyLarge`: hostname,
platform (`os · arch · preset`), capability string, offline sentence, action
details. On a 360 dp card that is several similar-weight lines with no
clear title → status → meta hierarchy. That matches “排版也很乱” better
than a missing accent color.

### Machine cards are noisy and not honest about access

`MachineCard` shows: icon, name, hostname, Online/Offline, platform +
preset, then `capabilityLabels`, then another offline sentence. When
online, `capabilityLabels` is hard-coded `"Files · Terminal · Upload · Desktop"`
and ignores `allowRead` / `allowExec` / desktop flags
(`MachineUx.kt`). `machineActions` likewise calls `line(true, …)` for
Terminal/Files/Transfer/Audit, so the blocked copy (“Needs exec
permission”) is dead. Contrast:

- `hubOpensEnabledFilesAndExplainsDisabledShell` expects the hub to show
  **“Needs exec permission”** when `exec = false`.
- `offlineMachinesDisableActionsAndOnlineOnesAreFull` expects Terminal
  **enabled** when `exec = false`.

Those tests disagree. The implementation matches the second. The first
would fail if run. Layout work must **align display with existing flags**
and fix the contradictory test — not change who is granted access.

### Navigation and primary actions

Android: list → hub (summary + action list) → pane. Primary “Pair a
machine” sits under the list; empty state is clearer than a populated
list (header “Machines” can duplicate the bottom tab). “This phone”
(node role) sits in the same tab bar as the controller, which is
intentional but competes for attention.

Desktop controller: single `CentralPanel`, header wordmark + relay pill +
user/refresh/logout on one row. The historical login screenshot shows a
cramped or clipped “your machines” label beside the wordmark, a peach
primary button, and a password row whose “Show” control does not share
height/alignment with the field. Wide screens leave a large empty band
under a narrow form; there is no machine-list sidebar once a session
opens (the list disappears).

### Phone constraints

Bottom `NavigationBar` plus hub/list padding is fine in principle.
Terminal space is already a t443 concern (IME composing, poll delay);
layout must not steal vertical space with extra cards or a second
toolbar. Action rows already use ~14 dp vertical padding (near 48 dp
with icon). Avoid multi-column machine grids on narrow width. Watch
horizontal overflow: `FontFamily` monospace ids, long hostnames, chip
rows in RemotePanes (Keyboard / Copy / Reconnect / Esc / Tab / Ctrl-C
are in a horizontal scroller — acceptable if clearly scrollable, not if
they push the terminal).

### Dark/light and a11y

Android schemes already aim at AA contrast and 48 dp buttons. Do not
throw that away for a new palette. Desktop theme tokens live separately
in `controller/theme.rs` and do not match the Android tide/navy language
(screenshot). Unify *roles* (title, meta, status, danger) rather than
inventing a third brand.

## Design (implementation next, not this milestone)

**Information hierarchy.** One title (machine name or screen name). One
status (Online / Offline / grant or permission missing / expired session)
as a short label, not a paragraph repeated twice. Meta (host, os, preset)
is secondary typography. Actions are a short list of verbs; disabled
actions stay visible with the *real* reason (offline vs no exec vs no
read). Do not advertise Terminal if `allowExec` is false.

**Spacing and type.** Introduce a small scale used on all three surfaces
where practical: space 4/8/12/16/24; title / body / meta / label roles.
Reuse `Components.kt` (and desktop `theme.rs` buttons) instead of new
card stacks. Default list is a single column on width < 600 dp; desktop
and wide web may use list + detail (list stays visible).

**States.** Offline, empty list, load, relay error, and “signed grant
required” already have banners/dialogs — keep wording, do not soften
security meaning. Make the same states visually consistent (icon + one
line + one action). Expired session already routes through
`looksLikeSessionExpiry`; show it as a sign-in state, not a generic
error toast only.

**Out of scope.** Grant probe, issuing grants, production deploy, real
phones. No typography-only “theme” PR that leaves the dead
`line(true, …)` in place. No optimistic access. t443 terminal *feel*
stays in its own commits; this work only ensures the chrome around the
terminal leaves enough height and does not overflow.

## First implementation slice (after this note)

1. Android: type roles + quieter machine rows; `machineActions` /
   `capabilityLabels` honor `allowExec` / `allowRead` / desktop flags;
   reconcile `MachineUxTest`.
2. Android hub/list: keep one column, 48 dp targets, no duplicate offline
   paragraphs.
3. Desktop controller: header/login alignment, type roles, optional
   list+detail on wide frames — only after Android list/hub is consistent.
4. Web dashboard: align labels and status chips with the same copy, not a
   full visual rewrite in the first commit.

## Verification plan

- Run existing `MachineUxTest` / `ShellNavTest` and any new layout tests
  (narrow 360 dp, disabled exec, offline).
- Compose previews (light/dark, 360 and 800 wide) — screenshots from
  previews are allowed if actually captured; do not invent after-shots.
- Desktop controller has a debug layout path; headless layout probes if
  already present. GNU CLI candidate stays in the t427 recovery dir and
  is not overwritten.
- **No real device, no production install.** Phone hand-feel and live
  dashboard pixels remain untested until a later isolated preview.

## Relation to t443

Same branch, same worktree `/workspace/agentlink-t443`. Terminal
interactivity commits stay separate (`docs/terminal-ux-t443.md` + code).
Controller layout commits reference this file. No grant/ops changes in
either series.


## Implementation (this slice, after t443)

Landed as a **separate commit** on the same branch. Grant issuance,
`pairFlags()`, probe/ops, and security checks are unchanged. Display and
enabled state now follow `node.effective` as mapped by `MachineInfo.toRow()`
(`NativeBridge.kt`): the same bits `NodePolicy::allows` uses.

- Terminal enabled only when `allowExec` (matches `Op::PtyOpen` / existing
  `TerminalPane` gate).
- Files and Audit enabled only when `allowRead`.
- Transfer enabled when `allowRead` or `allowWrite`, with copy that says
  which side is on.
- Desktop uses the Rust helpers: screenshots = `allow_desktop ||
  allows_remote_view()`; input = `allow_desktop || allow_remote_control`;
  live = `allow_remote_view || allow_desktop_stream`. The hub no longer
  advertises “Live view and input are allowed” when those bits are off.

The contradictory tests were not “picked” at random: the one that expected
Terminal enabled with `exec=false` contradicted the backend and
`hubOpensEnabledFilesAndExplainsDisabledShell`. That expectation was
replaced with `actionsFollowEffectivePolicyFlags` and
`desktopCapabilityMatchesNodePolicyHelpers`.

Android typography: `AgentTypography` (title / body / meta / label).
Machine cards dropped the second offline paragraph; name stays the title,
status is the chip, host/platform/capabilities are meta. Still a single
column. Action rows unchanged in meaning, disabled rows stay visible with
the real reason.

Desktop controller: Sign-in password field and Show/Hide share
`BTN_PRIMARY_H` and a fixed 72px control width so the row does not
misalign. No list+detail rewrite in this slice. Web dashboard already
derives a preset from flags; it was not restyled here.

### Tests (this pass; not t427 counts)

`:app:testDebugUnitTest` filtered: **28 passed**, 0 failed — MachineUxTest
8, ShellNavTest 9, TerminalScreenPumpTest 5, ImeComposingTest 6.

Compose previews in `Previews.kt` still exist (360dp machines/hub, light
and dark). No new screenshots were captured in this environment. No real
phone. Desktop login change needs a controller build / screenshot to
visually confirm.

If a box-browser preview is needed later, start an isolated preview
server and give the parent the localhost URL plus the Machines / Hub
entry; do not open a browser from this executor.


## Scope reminder and later compile (2026-11-12 Asia/Shanghai)

This Controller work is a **first-pass hierarchy revision**, not a
complete visual redesign: typography, quieter machine cards, honest
`node.effective` action flags, and a desktop login-row alignment. It
does not restyle the web dashboard, does not rewrite list+detail
layouts, and does not change grant semantics.

A later correctness pass (terminal backpressure, same branch) ran
`:app:assembleDebug` successfully and compiled the affected Compose
sources. That is a compile result, not a visual or device acceptance
of this UI slice. No new screenshots. No real phone. The debug APK
was not installed.
