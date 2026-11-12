# t456 branch matrix

Recorded 2026-11-12 19:55 CST (Asia/Shanghai).

This integration starts from `feat/controller-p2p-observe-t449`
(`ebfb6f22cef5509fce923e77c5494a44a5d7d9f4`). Remote `main`
(`602887281932d254d3d8ee1d57f8e3a305ab9bd6`) is a strict ancestor
(42 commits through `integrate/controller-android-t447` =
`684e1adf3cd2b441a167c735be3f9d6937d3d4b7`, then 10 P2P commits).
Original branches and frozen t452 artifacts were not moved or overwritten.

Remote heads were verified read-only (GitHub API). An HTTPS `git fetch`
of all heads failed for lack of an interactive credential; cached
`origin/main` already matched the live SHA. The repository remains private.
This branch is a local candidate and is not pushed in this step.

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

Local branch `integrate/security-main-t456` in worktree
`/workspace/agentlink-integrate-t456`. Security fixes, licenses, and the
zstd advisory upgrades landed on this branch after the matrix above was
written. See `docs/integrate-t456-security-status.md`. Still not pushed.
