#!/usr/bin/env bash
# Sync the current tip to box (via deploy/sync-box-bundle.sh) and build a
# release CLI there with AGENTLINK_RELEASE_VERSION taken from the local
# tag/describe. Ops helper only: it never creates a tag, never pushes to
# GitHub, and never publishes /dl.
#
# Usage (from the repo root, or anywhere with --repo):
#   deploy/box-release-build.sh                 # sync tip, then release build
#   deploy/box-release-build.sh --skip-sync     # build the tip already on box
#   deploy/box-release-build.sh --dry-run       # bundle locally, print commands
#   deploy/box-release-build.sh --version 0.1.136
#   TARGET_BASE=<sha-on-box> deploy/box-release-build.sh
#
# Version: exact tag on HEAD, else the tag from `git describe --tags` with the
# `-<n>-g<sha>` suffix and leading `v` stripped (so `0.1.137-2-gaffb434`
# becomes `0.1.137`). --version overrides it (also `v`-stripped). The value
# is exported on the node as AGENTLINK_RELEASE_VERSION.
#
# Environment: REPO_DIR, TARGET_NODE, TARGET_CHECKOUT, TARGET_BASE.
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=${REPO_DIR:-$(CDPATH= cd -- "$script_dir/.." && pwd)}
TARGET_NODE=${TARGET_NODE:-}
TARGET_CHECKOUT=${TARGET_CHECKOUT:-}
VERSION_OVERRIDE=
DRY_RUN=0
SKIP_SYNC=0
BUILD_TIMEOUT=600

usage() {
    cat <<'EOF'
Sync the current tip to box, then build a release CLI there.

Usage:
  deploy/box-release-build.sh                 # sync tip, then release build
  deploy/box-release-build.sh --skip-sync     # build the tip already on box
  deploy/box-release-build.sh --dry-run       # bundle locally, print commands
  deploy/box-release-build.sh --version 0.1.136
  TARGET_BASE=<sha-on-box> deploy/box-release-build.sh

Flags:
  --dry-run        Create the bundle, print the sync/build commands, change nothing
  --skip-sync      Do not sync; build whatever checkout is already on the node
  --version VER    Override the version (default: tag on HEAD, else git describe)
  --repo DIR       Local checkout (default: repo root above deploy/)
  --node NAME      agentlink node name (default: box)
  --checkout PATH  Remote checkout (default: /var/lib/agentlink/src)

Environment: REPO_DIR, TARGET_NODE, TARGET_CHECKOUT, TARGET_BASE.
EOF
}

die() {
    printf 'box-release-build: %s\n' "$*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --skip-sync) SKIP_SYNC=1 ;;
        --version) VERSION_OVERRIDE=${2:?--version needs a value}; shift ;;
        --repo) REPO_DIR=${2:?--repo needs a directory}; shift ;;
        --node) TARGET_NODE=${2:?--node needs a name}; shift ;;
        --checkout) TARGET_CHECKOUT=${2:?--checkout needs a path}; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

git -C "$REPO_DIR" rev-parse --git-dir >/dev/null 2>&1 \
    || die "not a git checkout: $REPO_DIR"

if [ -n "$VERSION_OVERRIDE" ]; then
    VERSION=${VERSION_OVERRIDE#v}
elif EXACT_TAG=$(git -C "$REPO_DIR" describe --tags --exact-match 2>/dev/null); then
    VERSION=${EXACT_TAG#v}
elif NEAREST_TAG=$(git -C "$REPO_DIR" describe --tags 2>/dev/null); then
    # `git describe` after a tag appends `-<count>-g<sha>`; the release
    # version is the nearest tag itself.
    if [[ $NEAREST_TAG =~ ^(.*)-[0-9]+-g[0-9a-f]+$ ]]; then
        VERSION=${BASH_REMATCH[1]#v}
    else
        VERSION=${NEAREST_TAG#v}
    fi
else
    die "cannot determine version: HEAD has no exact tag and git describe found no tag; pass --version X.Y.Z"
fi
[ -n "$VERSION" ] || die "version resolved to an empty string; pass --version X.Y.Z"
case "$VERSION" in
    *[[:space:]]*) die "version contains whitespace: '$VERSION'" ;;
esac

REMOTE_SCRIPT='
set -eu
CHECKOUT=$1
VERSION=$2
cd "$CHECKOUT" || { echo "build: no checkout at $CHECKOUT" >&2; exit 3; }
export PATH="$HOME/.cargo/bin:$PATH"
export AGENTLINK_RELEASE_VERSION="$VERSION"
echo "build: $(git rev-parse --short HEAD) $(git describe --tags --always 2>/dev/null || true) in $CHECKOUT"
echo "build: AGENTLINK_RELEASE_VERSION=$AGENTLINK_RELEASE_VERSION"
cargo build -p agentlink-cli --release
./target/release/agentlink --version
ls -lh ./target/release/agentlink
'

EXEC_CMD=(agentlink exec --timeout-secs "$BUILD_TIMEOUT" "$TARGET_NODE" sh -c "$REMOTE_SCRIPT" sh "$TARGET_CHECKOUT" "$VERSION")
SYNC_SCRIPT="$script_dir/sync-box-bundle.sh"

printf 'version: %s\n' "$VERSION"

if [ "$DRY_RUN" -eq 1 ]; then
    if [ "$SKIP_SYNC" -eq 1 ]; then
        printf 'sync:    skipped (--skip-sync)\n'
    else
        [ -x "$SYNC_SCRIPT" ] || die "sync helper is missing or not executable: $SYNC_SCRIPT"
        printf '\n# sync (dry run)\n'
        "$SYNC_SCRIPT" --repo "$REPO_DIR" --node "$TARGET_NODE" --checkout "$TARGET_CHECKOUT" --dry-run
    fi
    printf '\n# release build (dry run); would run:\n  '
    printf '%q ' "${EXEC_CMD[@]}"
    printf '\n'
    exit 0
fi

command -v agentlink >/dev/null 2>&1 || die "agentlink not found on PATH"

if [ "$SKIP_SYNC" -eq 0 ]; then
    [ -x "$SYNC_SCRIPT" ] || die "sync helper is missing or not executable: $SYNC_SCRIPT"
    printf 'syncing tip to %s ...\n' "$TARGET_NODE"
    "$SYNC_SCRIPT" --repo "$REPO_DIR" --node "$TARGET_NODE" --checkout "$TARGET_CHECKOUT" \
        || die "sync to '$TARGET_NODE' failed; fix the sync before building"
fi

agentlink exec --timeout-secs 20 "$TARGET_NODE" true >/dev/null 2>&1 \
    || die "node '$TARGET_NODE' is unreachable; check \`agentlink nodes\` and that the node is online"

printf 'building release on %s ...\n' "$TARGET_NODE"
if ! "${EXEC_CMD[@]}"; then
    die "release build failed on '$TARGET_NODE'; see the output above"
fi
printf 'done: %s %s -> %s/target/release/agentlink\n' "$TARGET_NODE" "$VERSION" "$TARGET_CHECKOUT"
