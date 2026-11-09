#!/usr/bin/env bash
# Build libagentlink_ffi.so for the phone and refresh the Kotlin bindings.
# Release LTO is disabled here so a CI runner can link three ABIs.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  if [[ -n "${ANDROID_HOME:-}" && -d "$ANDROID_HOME/ndk/27.2.12479018" ]]; then
    export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.2.12479018"
  else
    echo "Set ANDROID_NDK_HOME to an NDK r27+ install" >&2
    exit 1
  fi
fi

export CARGO_PROFILE_RELEASE_LTO="${CARGO_PROFILE_RELEASE_LTO:-off}"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-16}"

cargo build -p agentlink-ffi
cargo run -p agentlink-ffi --features cli --bin uniffi-bindgen -- generate \
  --library target/debug/libagentlink_ffi.so \
  --language kotlin \
  --no-format \
  --out-dir android/app/src/main/java

mkdir -p android/app/src/main/jniLibs
cargo ndk \
  -t arm64-v8a \
  -t armeabi-v7a \
  -t x86_64 \
  -o android/app/src/main/jniLibs \
  build -p agentlink-ffi --release
