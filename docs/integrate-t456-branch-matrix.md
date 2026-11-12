# t456 branch matrix

Recorded 2026-11-13 00:33 CST (Asia/Shanghai).

This integration starts from `feat/controller-p2p-observe-t449`
(`ebfb6f22cef5509fce923e77c5494a44a5d7d9f4`). Live remote `main`
(`602887281932d254d3d8ee1d57f8e3a305ab9bd6`) is a strict ancestor
(42 commits through `integrate/controller-android-t447` =
`684e1adf3cd2b441a167c735be3f9d6937d3d4b7`, then 10 P2P commits,
then the local t456/UI/reconnect/noflash line below).
Original branches and frozen t452 artifacts were not moved or overwritten.

Remote heads were re-verified read-only on 2026-11-13 00:31 CST
(Asia/Shanghai) with `gh api repos/zltl/agentlink/git/ref/heads/main`,
`repos/zltl/agentlink` (visibility), and `repos/zltl/agentlink/branches?per_page=100&page=1`
plus `list_tags` page size 100. That is a live list of every remote
head, not a leftover `refs/remotes/origin/main` or any other cached
remote value treated as current. An HTTPS `git fetch` of all heads
still needs credentials; this check did not use fetch, tokens, or
internal APIs. The repository remains **private** (`visibility=private`).
`pushed_at` on the GitHub API was `2026-11-12T00:40:25Z`
(2026-11-12 08:40:25 Asia/Shanghai). This branch is a local candidate
and is **not pushed**. Independent review of `6674388` (copy-retry
safety and tests) is in progress and is not treated as passed.

## Live remote heads (GitHub API)

These are the only branches currently on `zltl/agentlink`. There are
no tags (`list_tags` returned an empty page).

| Ref | Tip | Notes |
| --- | --- | --- |
| `main` | `602887281932d254d3d8ee1d57f8e3a305ab9bd6` | Sealed integration baseline. |
| `integrate/controller-android-t447` | `684e1adf3cd2b441a167c735be3f9d6937d3d4b7` | Already an ancestor of the t449 baseline. |
| `cursor/android-invite-crash-6d47` | `447fa55e96a1114e8e97ab7ef574a2f32a4a92f1` | Already an ancestor of t447 / t449. |

## Current local candidate (not pushed, review in progress)

Local branch `integrate/security-main-t456` in
`/workspace/agentlink-recovery-20261112/unpacked/40f551c/repo` was
fast-forwarded (`merge --ff-only`, after a normal fetch of the
reconnect worktree) from `7142d936874484b15a543d99b0ac105f317fb7dd`
to merge tip `6674388027224441327d771e1d3e3adab0ec42f8`. The
fast-forward keeps complete ancestry, including both merge parents:

| Commit | Subject | Role |
| --- | --- | --- |
| `7142d936874484b15a543d99b0ac105f317fb7dd` | `ui(controller): paint inset focus rings on Details and machine rows` | Previous integrate tip; UI round-4 product. |
| `4fef74f763b6c208c8701e80f8378fafb7befb5e` | `fix: keep relay-drop session teardown and recover via a fresh grant` | Parent 1 of the merge. Reconnect/copy. |
| `4e677c864719809f0cb1edb917ca46e2623bacc8` | `fix(process): route leftover Command::new through hidden or reviewed exceptions` | noflash product; parent of `79f3d63`. |
| `79f3d63bc857d6eae16ceee5128c8ec9c4baf6c5` | `docs(grant_local): correct grant_ui_command notes on hidden()` | Parent 2 of the merge. noflash docs only. |
| `6674388027224441327d771e1d3e3adab0ec42f8` | merge of the two children of `7142d936` | Current integrate tip. |

Earlier UI commits already on this line (also ancestors of `7142d936`):
`156f49ba` (preview isolation), `5d13dfd9`, `fd033c7f`, `25eda068`.
The UI source repo and the 7142 Linux GUI freeze were not modified in
this docs step, and no new GUI binary was built.

Independent review of `6674388` is running (copy retry safety and
tests). A later block from that review is not auto-fixed here. Do
not push until the parent confirms.

## Cached `origin/*` not on the live remote — do not merge

These refs exist only in the local cache (`/workspace/agentlink-control-plane/.git`).
`get_branch` for `cursor/owner-full-access-c6ef` returns 404. Each has
merge-base **NONE** with live `origin/main` (old history). Keep the
original ref; do not reattach it onto main. **Never restore same-account
grant bypass.**

| Cached ref | Tip | Subject / reason to exclude |
| --- | --- | --- |
| `origin/cursor/owner-full-access-c6ef` | `4f115731904d22a4e96671c8667b7755996f71d6` | “Give connected owners full access without grant paste.” Skips the grant for a connected owner. Explicitly excluded. Must not come back. |
| `origin/fix/mv-into-directory` | `ed7516e4bda705e2b5bca14b955b067dab5708f0` | “fix(mv): move into existing directory like Unix mv”. No merge-base with sealed main. |
| `origin/fix/peercopy-e2e-open-routed` | `0f2322a2e8ef34697c00a7237b1ed1927d6ea588` | “fix(cp): open node↔node e2e replies with peer node_id”. No merge-base with sealed main. |
| `origin/fix/v0.1.145-node-not-found-tip` | `d8e5116fec49ba75f86a0478548d793bac319b70` | “fix(cli): tip when node name is not found”. No merge-base with sealed main. Pre-seal tip history. |
| `origin/tip/v0.1.233-mcp-grant-capability` | `f7ad9853334ca30b5e693574419195cbbd626ce4` | “fix(mcp): tip when a grant capability is denied”. No merge-base with sealed main. Pre-seal tip history (`v0.1.233`). |

Those five cached tips, plus the broader local `feat/grant-*` / `tip/v0.1.*` set already listed below, stay off this integration.

Public NAT P2P is still unproven. That fact is not changed in product docs.

## Include (already on the t449 tip, so already on this baseline)

| Ref | Tip | Why |
| --- | --- | --- |
| `origin/main` / sealed main | `60288728` | Integration baseline; already an ancestor. |
| `integrate/controller-android-t447` | `684e1ad` | Terminal, CJK, layout, Android, controller session title. Already pushed. Ancestor of t449. |
| `cursor/android-invite-crash-6d47` (remote) | `447fa55` | Ancestor of t447. No unique commits versus t449. |
| `feat/status-session-grant-ux-t427` | `fdcbc4b` | Ancestor of t449. |
| `fix/controller-layout-t447` | `c6dfba2` | Ancestor of t449. |
| `fix/desktop-input-a11y-window-t417` | `bc97ba1` | Ancestor of t449. Worktree has untracked milestone notes only; left untouched. |
| `fix/identity-loader-t424` | `5d6f78c` | Ancestor of t449. |
| `feat/controller-p2p-observe-t449` | `ebfb6f2` | JPEG fallback, bounded ICE retry/pull, grant+peer isolation for ice/ice_pull, honest HUD. Not pushed before this integration. |

## Equivalent work already present (keep the original ref, do not merge history)

| Ref | Tip | Why not merged |
| --- | --- | --- |
| `feat/terminal-ux-t443` | `62b71b1` | Three unique commits versus t449 are patch-id identical to `55095f7`, `9a94573`, and `b1ac43f` already on t447. |

## Do not merge (divergent / pre-seal history). Keep the original ref.

These tips share no merge-base with current sealed `main` / t449
(old root `da5c34c Initial commit` versus snapshot `ac24a9d`). A merge
would reattach pre-seal history. The user-visible work is already in
the sealed line, or is superseded.

| Ref | Notes |
| --- | --- |
| local `main` `cc3123d` | Stale local name. Live remote main is `60288728` (history was force-updated earlier). |
| `feat/windows-hide-cmd-flash` `376b270` | Different root. `CREATE_NO_WINDOW` / no `DETACHED_PROCESS` already lives in t449 (`crates/agentlink-core/src/process.rs`, tray, update, proc). Worktree is dirty (deleted `.cargo/config.toml`); left untouched. |
| `feat/grant-*` and related grant-refresh/revoke/auto-grant branches (`65db67b`, `103a2f8`, `8fa146b`, `d25f154`, `bd747af`, `83802eb`, …) | No merge-base with sealed main. `resolve_e2e_policy`, revoked-jti files, and related grant code are already on t449. |
| `tip/v0.1.*` and older `fix/*` on the pre-seal line | Hundreds of unique SHAs versus t449 because of the clean-history rewrite; the tip text is already represented on sealed main/t447. |

## This branch adds

Security repairs from the t454 review (notification injection, grant-flag overwrite, live WebRTC revoke/expiry, PTY owner + server session ids, signaling peer checks, fail-closed policy, legacy admin default off, selected P2 items, MIT OR Apache-2.0 license files) plus tests. See the commits on `integrate/security-main-t456`.

## Integration candidate (this step)

The historical continuation worktree
`/workspace/agentlink-integrate-t456-cont` and the frozen 9122522 tree
were not rewritten. Current integrate work is
`/workspace/agentlink-recovery-20261112/unpacked/40f551c/repo` at
`6674388` (see the current-candidate section above). See
`docs/integrate-t456-security-status.md`. Still not pushed.

## Post-cd30 residual (local, not pushed)

The continuation worktree `/workspace/agentlink-integrate-t456-cont` on `integrate/security-main-t456` adds one incremental commit after frozen `cd30c9ed5233764567ea88da102776cbb67c69b2`. The 912 tree and `cd30c9e` are not rewritten. Windows probe of `cd30c9e` stays on its own tree and target; this delta is a later source package the Windows worker can build against the existing target. Live remote `main` remains `602887281932d254d3d8ee1d57f8e3a305ab9bd6` until the parent pushes. Cached `origin/cursor/owner-full-access-c6ef` (`4f115731`) stays excluded.

## Post-8143 UniFFI Kotlin regenerate (local, not pushed)

A second incremental commit on the same branch regenerates `android/app/src/main/java/uniffi/agentlink_ffi/agentlink_ffi.kt` with official `uniffi-bindgen` against the verified 8143 `libagentlink_ffi.so`. `8143d2ee` and `cd30c9e` are not rewritten. No Windows/Rust behavior change; the Windows 8143 retest boundary stays valid. Still not pushed; wait for the isolated UI worker and the parent’s final gate.

## Post-8df ConPTY resize test (local, not pushed)

A third incremental commit on the same branch fixes `real_pty_resize_changes_child_winsize` (structured GetConsoleScreenBufferInfo / `stty size` handshake; no production resize-path change). `8df767a`, `8143d2ee`, and `cd30c9e` are not rewritten. Generated Kotlin from `8df767a` is kept. Windows worker should re-run this freeze only for this test (plus any chosen regression slice); not pushed.

## Post-40f551c ConPTY Enter handshake (local, not pushed)

A further incremental commit on the same branch wakes the Windows size-helper handshake with CR/LF (`\r\n` on Windows, `\n` on Unix). `40f551c`, `8df767a`, and `8143d2ee` are not rewritten. Production resize is unchanged. Still not pushed.

## Post-6674388 docs snapshot (local, not pushed)

After `7142d936`, the integrate branch was fast-forwarded to
`6674388027224441327d771e1d3e3adab0ec42f8` (parents `4fef74f7` and
`79f3d63b`; noflash reviewed statically, reconnect independently
reviewed but that review is still running). The preceding
Post-40f551c / Post-8df / Post-8143 notes remain historical and
are not the current tip. See the current-candidate section at the
top and `docs/integrate-t456-security-status.md`. Still not pushed.

