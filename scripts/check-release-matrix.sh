#!/bin/sh
# Ensure deploy/github-release.yml (canonical Release workflow) publishes every archive agentlink update / install.sh may request.
# Run from repo root: sh scripts/check-release-matrix.sh
# Canonical workflow copy: deploy/github-release.yml
# Sync into .github/workflows/release.yml with a token that has the `workflow` scope.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
yml="$root/deploy/github-release.yml"
update_rs="$root/crates/agentlink-cli/src/update.rs"
install_sh="$root/install.sh"

test -f "$yml"
test -f "$update_rs"

# Targets the updater knows about (plus universal, which is lipo'd).
expected="
aarch64-apple-darwin
aarch64-pc-windows-msvc
aarch64-unknown-linux-musl
universal-apple-darwin
x86_64-apple-darwin
x86_64-pc-windows-msvc
x86_64-unknown-linux-musl
"

missing=0
for t in $expected; do
  if ! grep -q "$t" "$yml"; then
    echo "deploy/github-release.yml missing target/archive mention: $t" >&2
    missing=1
  fi
done

# update.rs candidate_targets must mention each non-universal triple.
for t in aarch64-apple-darwin aarch64-pc-windows-msvc aarch64-unknown-linux-musl \
         x86_64-apple-darwin x86_64-pc-windows-msvc x86_64-unknown-linux-musl \
         universal-apple-darwin; do
  if ! grep -q "$t" "$update_rs"; then
    echo "update.rs missing target: $t" >&2
    missing=1
  fi
done

# install.sh prefers universal on macOS and musl on Linux.
if ! grep -q 'universal-apple-darwin' "$install_sh"; then
  echo "install.sh missing universal-apple-darwin" >&2
  missing=1
fi
if ! grep -q 'unknown-linux-musl' "$install_sh"; then
  echo "install.sh missing linux musl asset pattern" >&2
  missing=1
fi

# required= block in the checksums step should list all seven archives once.
req_count=$(awk '/required="/,/^[[:space:]]*"[[:space:]]*$/' "$yml" | grep -c 'agentlink-\${version}-' || true)
if [ "$req_count" -ne 7 ]; then
  echo "deploy/github-release.yml required archive entries expected 7, got $req_count" >&2
  missing=1
fi

if [ "$missing" -ne 0 ]; then
  exit 1
fi
echo "OK: deploy/github-release.yml matrix/required list matches update.rs + install.sh ($req_count required lines)"
