#!/bin/sh
# Cross-platform local verification helper for agentlink.
# Runs shell/PowerShell syntax checks, release matrix verification, workspace
# Cargo tests, optional UniFFI Kotlin binding drift check, and optional cargo-audit.
#
# Usage:
#   sh scripts/verify.sh
#   sh scripts/verify.sh --skip-tests
#   CARGO_TEST_ARGS="--lib" sh scripts/verify.sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

SKIP_TESTS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-tests) SKIP_TESTS=1; shift ;;
    -h|--help)
      echo "usage: sh scripts/verify.sh [--skip-tests]" >&2
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

passed=0
skipped=0
failed=0

run_step() {
  label=$1
  shift
  printf '==> %s\n' "$label"
  if "$@"; then
    passed=$((passed + 1))
  else
    printf 'FAIL: %s\n' "$label" >&2
    failed=$((failed + 1))
  fi
}

skip_step() {
  label=$1
  reason=$2
  printf '==> %s [SKIP: %s]\n' "$label" "$reason"
  skipped=$((skipped + 1))
}

# 1. Shell script syntax checks (POSIX /bin/sh vs bash)
run_step "POSIX shell syntax check (sh -n)" \
  sh -n install.sh scripts/check-release-matrix.sh scripts/generate-signing-key.sh scripts/verify.sh
if command -v bash >/dev/null 2>&1; then
  run_step "Bash syntax check (bash -n scripts/smoke.sh)" \
    bash -n scripts/smoke.sh
else
  skip_step "Bash syntax check (bash -n scripts/smoke.sh)" "bash not found on PATH"
fi

# 2. PowerShell syntax check for install.ps1 (if pwsh or powershell is available)
ps_bin=""
if command -v pwsh >/dev/null 2>&1; then
  ps_bin="pwsh"
elif command -v powershell >/dev/null 2>&1; then
  ps_bin="powershell"
fi
if [ -n "$ps_bin" ]; then
  run_step "PowerShell syntax check (install.ps1)" \
    "$ps_bin" -NoProfile -Command '
      $errors = $null
      $tokens = $null
      $full = (Resolve-Path "install.ps1").Path
      [void][System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$errors)
      if ($errors -and $errors.Count -gt 0) {
        $errors | ForEach-Object { Write-Error $_.ToString() }
        exit 1
      }
      Write-Output "OK: install.ps1 parsed with 0 syntax errors"
    '
else
  skip_step "PowerShell syntax check (install.ps1)" "neither pwsh nor powershell found on PATH"
fi

# 3. Release matrix check
run_step "Release matrix check (scripts/check-release-matrix.sh)" \
  sh scripts/check-release-matrix.sh

# 4. Workspace build & tests
if [ "$SKIP_TESTS" -eq 1 ]; then
  skip_step "Workspace check & tests" "--skip-tests specified"
else
  run_step "Cargo workspace check (--all-targets)" \
    cargo check --workspace --all-targets
  if [ -n "${CARGO_TEST_ARGS:-}" ]; then
    # shellcheck disable=SC2086
    run_step "Cargo workspace tests ($CARGO_TEST_ARGS)" \
      cargo test --workspace $CARGO_TEST_ARGS
  else
    run_step "Cargo workspace tests (--workspace)" \
      cargo test --workspace
  fi
fi

# 5. UniFFI Kotlin binding drift check (when uniffi-bindgen and compiled FFI lib exist)
ffi_lib=""
for cand in \
  target/debug/libagentlink_ffi.so \
  target/debug/libagentlink_ffi.dylib \
  target/debug/agentlink_ffi.dll \
  target/release/libagentlink_ffi.so \
  target/release/libagentlink_ffi.dylib \
  target/release/agentlink_ffi.dll; do
  if [ -f "$cand" ]; then
    ffi_lib=$cand
    break
  fi
done

committed_kt="android/app/src/main/java/uniffi/agentlink_ffi/agentlink_ffi.kt"
if [ -n "$ffi_lib" ] && [ -f "$committed_kt" ] && command -v uniffi-bindgen >/dev/null 2>&1; then
  check_uniffi_drift() {
    tmp_kt=$(mktemp -d)
    trap 'rm -rf "$tmp_kt"' EXIT
    uniffi-bindgen generate --library "$ffi_lib" --language kotlin --no-format --out-dir "$tmp_kt"
    diff -u "$committed_kt" "$tmp_kt/uniffi/agentlink_ffi/agentlink_ffi.kt"
    rm -rf "$tmp_kt"
    trap - EXIT
  }
  run_step "UniFFI Kotlin binding drift check ($ffi_lib)" check_uniffi_drift
elif [ ! -f "$committed_kt" ]; then
  skip_step "UniFFI Kotlin binding drift check" "committed Kotlin binding not found"
elif ! command -v uniffi-bindgen >/dev/null 2>&1; then
  skip_step "UniFFI Kotlin binding drift check" "uniffi-bindgen not installed"
else
  skip_step "UniFFI Kotlin binding drift check" "agentlink-ffi library not built yet (run: cargo build -p agentlink-ffi --lib)"
fi

# 6. Cargo audit (root + optional sub-lockfiles)
if command -v cargo-audit >/dev/null 2>&1; then
  run_step "cargo audit (root Cargo.lock)" cargo audit
  for sublock in bench-micro/Cargo.lock fuzz/Cargo.lock; do
    if [ -f "$sublock" ]; then
      run_step "cargo audit ($sublock)" cargo audit --file "$sublock"
    fi
  done
else
  skip_step "cargo audit" "cargo-audit not installed (install via: cargo install cargo-audit)"
fi

printf '\nSummary: %d passed, %d skipped, %d failed\n' "$passed" "$skipped" "$failed"
if [ "$failed" -ne 0 ]; then
  exit 1
fi
