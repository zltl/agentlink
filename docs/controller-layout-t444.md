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

## t447 desktop Controller — real GUI acceptance (2026-11-12 00:55 Asia/Shanghai)

The 0050 candidate was `ba0eae8`, binary at
`/workspace/agentlink-t427-recovery/20261112-0050-t446-controller-candidate/`.
Parent computerUse tested the **desktop** window, not the Android typography
pass. Source in that build already had `action_button` labels `Terminal`,
`Files`, and `Desktop`, plus a `View`/`Control` **mode toggle**. The live
window did not match a naive reading of those names.

Evidence (read-only screenshots, not driven from this worker):

- List: `/tmp/computer-use/sand-subagent-92852702-680e-7005-f8ec-719909f8daac.9d3e7161-36b7-4756-bf2f-dc8310a62ac0.webp`
  — visible card actions were **Terminal / Control / View**. Files and Desktop
  were not on screen. Cards sat in two columns with large vertical gaps
  between rows. Headless nodes (quant67, tc-cn, tc-external) still showed
  Control/View. Signed in as ltl without a password (the earlier Sign in
  flash was bootstrap, not a confirmed session-read defect).
- Terminal: `...88f0fa95-8460-439f-aeab-1411ddcfe979.webp` — quant67 hostname
  and whoami worked as root. The pane was a **line box** (“Enter sends the
  line”), not a cell-grid emulator.
- Control: `...9daa52c0-4ee1-40ea-8a03-cf56c1fff608.webp` — quant67 Control
  became selected and stayed on Machines. No sub-page, no error.
- sufa View: `...b9e541dc-454d-4842-92e4-2eedef685f4e.webp` — click stayed
  on the list. No picture, no error, no portal prompt, no input capture.
  Selecting View is **not** a desktop session.

Cause, checked against `ba0eae8` source and that GUI:

- `Control`/`View` were only `segmented_control` writing `self.control`.
  They never called `open_desktop`. The real start button was the `Desktop`
  action, which lived on the same horizontal row and was clipped, so testers
  only saw Terminal plus the mode toggle.
- `desktop_allowed(policy)` still drew the toggle on **headless** nodes.

This revision is desktop Controller work, not an Android typography tweak:

- Cards show wrapped **start** actions: `Terminal`, `Files`, and, when the
  node is not headless, `View desktop` / `Control desktop`. Those last two
  call `open_desktop` immediately (view-only vs keyboard+mouse). Headless
  nodes do not get a fake desktop entry.
- Card rows size to content so the leftover panel height is not turned into
  huge gaps.
- Saved session starts on **Restoring session…**, not a flashing Sign in
  form. Ready with a user goes to Machines; failure goes to Sign in with
  the error.
- Terminal and Files keep a **Back to machines** button. Wide windows also
  keep a left machine rail so a session does not swallow the list.
- Files shows loading / empty states, directory listing, create folder, and
  **New file**. The worker path (`Cmd::List` / `Read` / `Write` / `Mkdir`)
  was already wired; the list entry was the missing piece.
- Opening desktop still uses the existing connecting / failed chrome. The
  mode toggle is gone, so a selected chip can no longer be mistaken for a
  live session.

Unit tests cover the visible button set. They do not replace a GUI retest
of the new candidate.

## t447 GUI retest (0111) and follow-up fixes (2026-11-12 Asia/Shanghai)

The 0111 candidate confirmed real progress: quant67 `hostname` / `whoami` (root)
/ `printf` worked; Files could create a folder and `probe.txt`, save, close,
reopen with matching content, and delete the file and empty folder through the
UI; sufa View showed a read-only remote desktop (no portal, input not
captured). Five defects remained and are addressed in this revision:

- **C (first).** Enter in a focused quant67 terminal could open another node's
  Terminal (sufa). Keyboard, IME, and clipboard events are now consumed
  at the start of the frame, before the machine rail or any default button
  is drawn. Card and rail actions have unique ids, do not wrap label
  letters, and surrender focus so they are click-only. Switching nodes
  requires an explicit click. The current session is labeled
  `{name} · terminal` and the matching rail card shows **This session**.
- **D.** Reopening a Terminal no longer just drops the previous PTY sender
  (`try_send` close could be lost, and a second `open_pty` can wait on the
  30s client timeout with a blank grid). The worker now awaits
  `PtySession::close` before `open_pty`. Clicking Terminal on the already
  open node keeps the session. The pane shows **Starting shell…**, and after
  8s without output a waiting message — not a silent refresh. A `PtyDone`
  with no output becomes a visible error.
- **A.** The main Machines list uses a content-sized grid (two columns when
  the list is ≥ 860 px). Action buttons have a minimum width and
  `TextWrapMode::Extend`, so labels stay on one line. The session rail
  already laid out correctly and is unchanged in that respect.
- **B.** Inter and JetBrains Mono (both SIL OFL 1.1, bundled under
  `crates/agentlink-cli/assets/`) have no CJK coverage, so `printf` of
  中文 showed tofu boxes even when cell width was correct. The Controller
  now loads a system CJK face as a fallback for both families. Preferred
  source: Noto Sans Mono CJK (SIL OFL 1.1,
  <https://github.com/notofonts/noto-cjk>, typically the `fonts-noto-cjk`
  Debian/Ubuntu package). TrueType Collections are unpacked to a single
  standalone face at runtime. The 19 MiB collection is **not** rebundled.
  Platform UI fonts (PingFang, YaHei, Yu Gothic) are used only when present
  on the local OS, and are not redistributed.
- **E.** Deleting the open file (or its folder) clears the editor, a leftover
  **Saved** notice, and the stale selection as soon as Delete is clicked,
  and again when the refreshed directory listing no longer contains that
  path.

A new candidate directory will be built for parent GUI retest. Unit tests
do not replace that retest. Android CJK typography is intentionally not
part of this desktop pass.

## Close / Quit and leftover Controller processes (2026-11-12 Asia/Shanghai)

Closing the 0050 and 0111 windows left those candidate processes running
(PIDs later confirmed by `/proc/exe` and SIGTERM'd as test processes, not
production). `controller` always passed `tray: true`. The status-icon
thread was treated as ready as soon as it started, even if ksni never
registered, and a ready tray cancelled the window close (hide only). Quit
lived only in that icon menu, which was easy to miss or missing entirely.
The header had Log out and Refresh, but no Quit.

0133 used the same close-to-tray path. A normal foreground window now
quits when the title-bar close button or the header **Quit** control is
used. Hide-on-close happens only with `--background` *and* a status icon
that actually registered. The tray menu still has Quit for that
autostart case.

## CJK font availability (not only this box)

The desktop terminal still uses a system / drop-in CJK face as an egui
fallback (Noto Sans CJK, SIL OFL 1.1). The 19 MiB collection is not
rebundled. Search order:

1. `AGENTLINK_CJK_FONT` (a `.ttf`, `.otf`, or `.ttc` path)
2. Fonts in `$AGENTLINK_CONFIG_DIR/fonts`, `~/.config/agentlink/fonts`,
   or `~/.local/share/agentlink/fonts` (font files only; identity files
   in those trees are not read)
3. Packaged OS fonts (Noto CJK, Droid Sans Fallback, PingFang, Yu Gothic,
   Microsoft YaHei, Malgun)

When none of those are present, the window shows a visible hint. ASCII
still works. Operators can drop an OFL font into the fonts directory or
install `fonts-noto-cjk`.

## 0133 GUI retest — list and rail overflow (2026-11-12 Asia/Shanghai)

Parent computerUse retested the 0133 candidate (`c77b0a3`). C, D, E, and
glyph rendering of 你好 passed. Real IME input was **not** accepted: the
你好 text came from `printf` with octal bytes, which only proves the CJK
fallback face is loaded.

**A failed**, and the session rail failed with it. Screenshots (read-only):

- Maximized Machines (`4b1ea262-…webp`): short full-width card bars,
  overlapping hostname / id / “Headless. Shell and files only.”, and a
  second column (sufa, tc-external, probe) clipped off the right edge.
- Session (`cff5c06a-…webp`): sufa **View desktop** clipped to **View d…**
  past the 260 px rail, plus a wide black gap between the gray rail and
  the terminal.

Cause, from those frames and the 0133 source:

- The Machines list used a two-column `Grid`. Each card called
  `set_min_width(ui.available_width())`. Inside a Grid cell that width is
  often the leftover CentralPanel, so column 1 became the full window
  width and column 2 overflowed.
- `action_button` used `min_size(88, …)` and `TextWrapMode::Extend`.
  `horizontal_wrapped` parked “View desktop” in the leftover rail width
  (narrower than the label) and clipped it letter-by-letter.
- `SidePanel::left` placed the main column at the overflowing button
  response rect, not at the 260 px frame, which is the black gap.

This follow-up (not a constant-only tweak):

- Machines is a compact **single column**. Long hostname / os / version /
  id text truncates on one line; hover shows the full string, click copies
  it. Title and status pill no longer use a right-to-left row.
- Action buttons measure the whole label plus padding and keep
  `Extend`, so `horizontal_wrapped` moves a complete button to the next
  line instead of clipping mid-word. The same helper is used on the list
  and the rail.
- The session rail is painted inside the CentralPanel at a fixed
  `MACHINE_RAIL_WIDTH` (260). It is hidden below `MACHINE_RAIL_SHOW_AT`
  (980); **Back to machines** remains. The main column starts at that
  fixed width, so a clipped child cannot open a gap.

Unit tests record the single-column policy and the rail visibility
threshold. They do not replace a parent GUI retest on a new candidate,
on both a maximized / 1280×800 window and a narrow window, covering the
Machines list **and** the session rail. Do not treat the rail as already
visually passing. 0133 is frozen and must not be overwritten.

