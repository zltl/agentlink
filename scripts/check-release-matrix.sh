#!/bin/sh
# Check that update.rs and install.sh name the same release archives.
# Run from repo root: sh scripts/check-release-matrix.sh
# Do not add a GitHub Actions workflow to publish them.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
update_rs="$root/crates/agentlink-cli/src/update.rs"
install_sh="$root/install.sh"

test -f "$update_rs"
test -f "$install_sh"

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
count=0
for t in $expected; do
  count=$((count + 1))
  if ! grep -q "$t" "$update_rs"; then
    echo "update.rs missing target: $t" >&2
    missing=1
  fi
done

if ! grep -q 'universal-apple-darwin' "$install_sh"; then
  echo "install.sh missing universal-apple-darwin" >&2
  missing=1
fi
if ! grep -q 'unknown-linux-musl' "$install_sh"; then
  echo "install.sh missing linux musl asset pattern" >&2
  missing=1
fi

if [ "$count" -ne 7 ]; then
  echo "expected 7 archives, got $count" >&2
  missing=1
fi

if [ "$missing" -ne 0 ]; then
  exit 1
fi
echo "OK: update.rs and install.sh name the same $count archives"
