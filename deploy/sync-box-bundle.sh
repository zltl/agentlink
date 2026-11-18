#!/usr/bin/env bash
# Push the current tip to box over agentlink when `git pull` on box→GitHub
# hangs. Runs on the box (or any host with one checkout and a logged-in
# `agentlink` CLI). The box keeps the single checkout
# <workspace>/repo; box keeps its own checkout.
#
# How it works: `git bundle create` records the branch tip locally, `agentlink
# cp` copies the bundle to `/tmp/agentlink-bundle/` on the node, and
# `agentlink exec` fetches it into `refs/remotes/bundle/<branch>` and does a
# fast-forward-only merge. Nothing is pushed to GitHub and no tag is created.
#
# Usage (from the repo root, or anywhere with --repo):
#   deploy/sync-box-bundle.sh                  # complete bundle, apply on box
#   deploy/sync-box-bundle.sh --dry-run        # bundle locally, print commands
#   deploy/sync-box-bundle.sh --node box --checkout /var/lib/agentlink/src
#   TARGET_BASE=<sha> deploy/sync-box-bundle.sh  # incremental bundle (base must exist on box)
#
# Complete bundles need a full clone (`git fetch --unshallow`); incremental
# bundles with TARGET_BASE work on a shallow clone as long as the base is present.
#
# Environment: REPO_DIR, TARGET_NODE, TARGET_CHECKOUT, TARGET_STAGE, TARGET_BASE.
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=${REPO_DIR:-$(CDPATH= cd -- "$script_dir/.." && pwd)}
TARGET_NODE=${TARGET_NODE:-}
TARGET_CHECKOUT=${TARGET_CHECKOUT:-}
TARGET_STAGE=${TARGET_STAGE:-/tmp/agentlink-bundle}
TARGET_BASE=${TARGET_BASE:-}
DRY_RUN=0
REQUIRE_CLEAN=0

usage() {
    cat <<'EOF'
Push the current tip to box over agentlink when `git pull` on box→GitHub hangs.

Usage:
  deploy/sync-box-bundle.sh                  # complete bundle, apply on box
  deploy/sync-box-bundle.sh --dry-run        # bundle locally, print commands
  deploy/sync-box-bundle.sh --repo DIR --node NAME --checkout REMOTE_PATH
  TARGET_BASE=<sha> deploy/sync-box-bundle.sh  # incremental bundle (base must exist on box)

Complete bundles need a full clone (`git fetch --unshallow`); incremental
bundles with TARGET_BASE work on a shallow clone as long as the base is present.

Flags:
  --dry-run        Create the bundle, print the cp/exec commands, change nothing
  --repo DIR       Local checkout (default: repo root above deploy/)
  --node NAME      agentlink node name (default: box)
  --checkout PATH  Remote checkout (default: /var/lib/agentlink/src)
  --require-clean  Refuse to bundle when the working tree is dirty
  --force-dirty    Bundle HEAD even when dirty (the default)

Environment: REPO_DIR, TARGET_NODE, TARGET_CHECKOUT, TARGET_STAGE, TARGET_BASE.
EOF
}

die() {
    printf 'sync-box-bundle: %s\n' "$*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --repo) REPO_DIR=${2:?--repo needs a directory}; shift ;;
        --node) TARGET_NODE=${2:?--node needs a name}; shift ;;
        --checkout) TARGET_CHECKOUT=${2:?--checkout needs a path}; shift ;;
        --require-clean) REQUIRE_CLEAN=1 ;;
        --force-dirty) REQUIRE_CLEAN=0 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

[ -n "$TARGET_NODE" ] || die "pass --node or set TARGET_NODE"
[ -n "$TARGET_CHECKOUT" ] || die "pass --checkout or set TARGET_CHECKOUT"

TARGET_STAGE=${TARGET_STAGE%/}
case "$TARGET_STAGE" in
    /*) ;;
    *) TARGET_STAGE="/$TARGET_STAGE" ;;
esac
REMOTE_BUNDLE="$TARGET_STAGE/tip.bundle"

git -C "$REPO_DIR" rev-parse --git-dir >/dev/null 2>&1 \
    || die "not a git checkout: $REPO_DIR"
IS_SHALLOW=$(git -C "$REPO_DIR" rev-parse --is-shallow-repository)
if [ "$IS_SHALLOW" = true ] && [ -z "$TARGET_BASE" ]; then
    die "$REPO_DIR is a shallow clone; complete bundles need full history (git fetch --unshallow), or set TARGET_BASE=<sha> for an incremental bundle (e.g. TARGET_BASE=\$(agentlink exec $TARGET_NODE --shell 'git -C $TARGET_CHECKOUT rev-parse HEAD'))"
fi

BRANCH=$(git -C "$REPO_DIR" symbolic-ref --short -q HEAD) \
    || die "$REPO_DIR is on a detached HEAD; check out a branch first"
HEAD_SHA=$(git -C "$REPO_DIR" rev-parse --verify "refs/heads/$BRANCH")
HEAD_SHORT=$(git -C "$REPO_DIR" rev-parse --short "$HEAD_SHA")
HEAD_DESC=$(git -C "$REPO_DIR" describe --tags --always "$HEAD_SHA")

DIRTY_COUNT=$(git -C "$REPO_DIR" status --porcelain | wc -l | tr -d ' ')
if [ "$DIRTY_COUNT" -gt 0 ]; then
    if [ "$REQUIRE_CLEAN" -eq 1 ]; then
        die "$REPO_DIR has $DIRTY_COUNT uncommitted change(s); --require-clean forbids this"
    fi
    printf 'note: %s has %s uncommitted change(s); bundling HEAD only (%s)\n' \
        "$REPO_DIR" "$DIRTY_COUNT" "$HEAD_DESC"
fi

if [ -n "$TARGET_BASE" ]; then
    git -C "$REPO_DIR" rev-parse --verify --quiet "$TARGET_BASE^{commit}" >/dev/null \
        || die "TARGET_BASE=$TARGET_BASE is not a commit in $REPO_DIR"
    git -C "$REPO_DIR" merge-base --is-ancestor "$TARGET_BASE" "$HEAD_SHA" \
        || die "TARGET_BASE=$TARGET_BASE is not an ancestor of $BRANCH ($HEAD_SHORT)"
    if [ "$(git -C "$REPO_DIR" rev-list --count "$TARGET_BASE..$HEAD_SHA")" -eq 0 ]; then
        printf 'already up to date: %s is %s (no commits after %s)\n' \
            "$BRANCH" "$HEAD_DESC" "$TARGET_BASE"
        exit 0
    fi
fi

command -v agentlink >/dev/null 2>&1 || die "agentlink not found on PATH"

umask 077
BUNDLE=$(mktemp "${TMPDIR:-/tmp}/agentlink-sync-XXXXXX.bundle")
cleanup() { [ "$DRY_RUN" -eq 1 ] || rm -f -- "$BUNDLE"; }
trap cleanup EXIT

if [ -n "$TARGET_BASE" ]; then
    git -C "$REPO_DIR" bundle create "$BUNDLE" "refs/heads/$BRANCH" "^$TARGET_BASE"
    MODE="incremental ($TARGET_BASE..$HEAD_SHORT)"
else
    git -C "$REPO_DIR" bundle create "$BUNDLE" "refs/heads/$BRANCH"
    MODE="complete"
fi
BUNDLE_SIZE=$(du -h "$BUNDLE" | cut -f1)
printf 'bundle: %s (%s, %s)\n' "$BUNDLE" "$BUNDLE_SIZE" "$MODE"
printf 'tip:    %s %s (%s)\n' "$BRANCH" "$HEAD_DESC" "$HEAD_SHORT"

REMOTE_SCRIPT='
set -eu
CHECKOUT=$1
[ -n "$CHECKOUT" ] && [ -d "$CHECKOUT/.git" ] || { echo "sync: no git checkout at $1" >&2; exit 3; }
BRANCH=$2
BUNDLE=$3
cd "$CHECKOUT"
current=$(git symbolic-ref --short -q HEAD || true)
[ "$current" = "$BRANCH" ] || { echo "sync: $CHECKOUT is on ${current:-a detached HEAD}, expected $BRANCH" >&2; exit 4; }
describe() { git describe --tags --exact-match 2>/dev/null || git describe --tags --always; }
echo "remote before: $(git rev-parse --short HEAD) $(describe) ($CHECKOUT)"
git fetch --no-tags "$BUNDLE" "refs/heads/$BRANCH:refs/remotes/bundle/$BRANCH"
git merge --ff-only "refs/remotes/bundle/$BRANCH"
echo "remote after:  $(git rev-parse --short HEAD) $(describe)"
git rev-parse HEAD
'

CP_CMD=(agentlink cp "$BUNDLE" "node://$TARGET_NODE$REMOTE_BUNDLE")
EXEC_CMD=(agentlink exec --timeout-secs 300 "$TARGET_NODE" sh -c "$REMOTE_SCRIPT" sh "$TARGET_CHECKOUT" "$BRANCH" "$REMOTE_BUNDLE")
MKDIR_CMD=(agentlink exec --timeout-secs 30 "$TARGET_NODE" mkdir -p "$TARGET_STAGE")

if [ "$DRY_RUN" -eq 1 ]; then
    printf '\ndry run; would run:\n'
    printf '  '; printf '%q ' "${MKDIR_CMD[@]}"; printf '\n'
    printf '  '; printf '%q ' "${CP_CMD[@]}"; printf '\n'
    printf '  '; printf '%q ' "${EXEC_CMD[@]}"; printf '\n'
    printf '\nbundle kept at %s\n' "$BUNDLE"
    exit 0
fi

agentlink exec --timeout-secs 20 "$TARGET_NODE" true >/dev/null 2>&1 \
    || die "node '$TARGET_NODE' is unreachable; check \`agentlink nodes\` and that the node is online"

"${MKDIR_CMD[@]}"
"${CP_CMD[@]}"

REMOTE_OUT=$("${EXEC_CMD[@]}")
printf '%s\n' "$REMOTE_OUT"
AFTER_SHA=$(printf '%s\n' "$REMOTE_OUT" | tail -n 1)
[ -n "$AFTER_SHA" ] || die "remote apply produced no SHA; check the output above"
printf 'synced %s: %s -> %s\n' "$TARGET_NODE" "$HEAD_SHORT" "$(printf '%s' "$AFTER_SHA" | cut -c1-12)"
