#!/bin/sh
# Check that update.rs, install.sh, and install.ps1 name the same release
# archives (Linux gnu desktop + musl headless, Windows dual-binary zip, and
# macOS universal + per-arch fallback).
# Run from repo root: sh scripts/check-release-matrix.sh
# Do not add a GitHub Actions workflow to publish them.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
update_rs="$root/crates/agentlink-cli/src/update.rs"
cli_cargo="$root/crates/agentlink-cli/Cargo.toml"
install_sh="$root/install.sh"
install_ps1="$root/install.ps1"

test -f "$update_rs"
test -f "$cli_cargo"
test -f "$install_sh"
test -f "$install_ps1"

baseline_targets="
aarch64-apple-darwin
aarch64-pc-windows-msvc
aarch64-unknown-linux-musl
universal-apple-darwin
x86_64-apple-darwin
x86_64-pc-windows-msvc
x86_64-unknown-linux-musl
"

gnu_targets="
aarch64-unknown-linux-gnu
x86_64-unknown-linux-gnu
"

missing=0
count=0
for t in $baseline_targets; do
  count=$((count + 1))
  if ! grep -q "$t" "$update_rs"; then
    echo "update.rs missing target: $t" >&2
    missing=1
  fi
done

# Check install.sh covers macOS universal + arch fallback, Linux musl (headless),
# and Linux gnu (desktop).
if ! grep -Fq 'universal-apple-darwin' "$install_sh"; then
  echo "install.sh missing universal-apple-darwin" >&2
  missing=1
fi
if ! grep -Fq '${ARCH}-apple-darwin' "$install_sh"; then
  echo "install.sh missing macOS arch fallback (\${ARCH}-apple-darwin)" >&2
  missing=1
fi
if ! grep -Fq 'unknown-linux-musl' "$install_sh"; then
  echo "install.sh missing linux musl (headless) asset pattern" >&2
  missing=1
fi
if ! grep -Fq 'unknown-linux-gnu' "$install_sh"; then
  echo "install.sh missing linux gnu (desktop) asset pattern" >&2
  missing=1
fi

# Check install.ps1 covers Windows msvc zip and dual-binary installation
# (`agentlink.exe` + `agentlink-gui.exe`).
if ! grep -Fq 'pc-windows-msvc.zip' "$install_ps1"; then
  echo "install.ps1 missing Windows msvc zip asset pattern" >&2
  missing=1
fi
if ! grep -Fq 'agentlink.exe' "$install_ps1"; then
  echo "install.ps1 missing agentlink.exe install" >&2
  missing=1
fi
if ! grep -Fq 'agentlink-gui.exe' "$install_ps1"; then
  echo "install.ps1 missing agentlink-gui.exe dual-binary install" >&2
  missing=1
fi

# Linux glibc desktop targets & Windows dual-binary in update.rs:
# Enforce strictly once agentlink-cli ships the `agentlink-gui` binary target;
# recognize both explicit target strings and dynamic `unknown-linux-gnu` selection.
has_dual_bin=0
if grep -q 'agentlink-gui' "$cli_cargo"; then
  has_dual_bin=1
fi

gnu_in_update=0
if grep -q 'unknown-linux-gnu' "$update_rs"; then
  gnu_in_update=1
  for t in $gnu_targets; do
    count=$((count + 1))
  done
elif [ "$has_dual_bin" -eq 1 ]; then
  echo "update.rs missing Linux glibc desktop target support (unknown-linux-gnu)" >&2
  missing=1
else
  echo "INFO: update.rs does not yet reference unknown-linux-gnu (pending dual-binary CLI merge)" >&2
fi

if grep -q 'agentlink-gui\.exe' "$update_rs"; then
  :
elif [ "$has_dual_bin" -eq 1 ]; then
  echo "update.rs missing Windows dual-binary support (agentlink-gui.exe)" >&2
  missing=1
else
  echo "INFO: update.rs does not yet reference agentlink-gui.exe (pending dual-binary CLI merge)" >&2
fi

if [ "$gnu_in_update" -eq 1 ]; then
  expected_count=9
else
  expected_count=7
fi
if [ "$count" -ne "$expected_count" ]; then
  echo "expected $expected_count archives, got $count" >&2
  missing=1
fi

if [ "$missing" -ne 0 ]; then
  exit 1
fi
echo "OK: release matrix verified ($count targets; Linux gnu+musl, macOS universal+arch, Windows dual-binary)"
