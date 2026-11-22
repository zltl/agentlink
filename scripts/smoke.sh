#!/usr/bin/env bash
# Manual end-to-end CLI & MCP smoke test using the modern account login +
# node-local SignedGrant flow (no disabled legacy admin.token required).
# `cargo test -p agentlink-cli --test smoke` covers the automated test suite.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -z "${BIN:-}" ]]; then
  if [[ -x "$ROOT/target/debug/agentlink" ]]; then
    BIN="$ROOT/target/debug/agentlink"
  elif [[ -x "$ROOT/target/debug/agentlink.exe" ]]; then
    BIN="$ROOT/target/debug/agentlink.exe"
  else
    BIN="$ROOT/target/debug/agentlink"
  fi
fi
if [[ ! -x "$BIN" ]]; then
  (cd "$ROOT" && cargo build -p agentlink-cli)
  if [[ ! -x "$BIN" && -x "${BIN}.exe" ]]; then
    BIN="${BIN}.exe"
  fi
fi

WORK="$(mktemp -d)"
RELAY_PID=""
NODE_PID=""
cleanup() {
  [[ -n "$NODE_PID" ]] && kill "$NODE_PID" 2>/dev/null || true
  [[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2>/dev/null || true
  [[ -n "$NODE_PID" ]] && wait "$NODE_PID" 2>/dev/null || true
  [[ -n "$RELAY_PID" ]] && wait "$RELAY_PID" 2>/dev/null || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

"$BIN" relay --bind 127.0.0.1:0 --data-dir "$WORK/relay" >"$WORK/relay.out" 2>&1 &
RELAY_PID=$!
for _ in $(seq 1 100); do
  [[ -s "$WORK/relay/listen_addr.txt" && -s "$WORK/relay/fingerprint.txt" ]] && break
  sleep 0.1
done
if [[ ! -s "$WORK/relay/listen_addr.txt" || ! -s "$WORK/relay/fingerprint.txt" ]]; then
  echo "smoke: relay failed to start" >&2
  cat "$WORK/relay.out" >&2 || true
  exit 1
fi

ADDR="$(tr -d '[:space:]' <"$WORK/relay/listen_addr.txt")"
FP="$(tr -d '[:space:]' <"$WORK/relay/fingerprint.txt")"
RELAY="wss://$ADDR"

# Verify /healthz endpoint when curl is available.
if command -v curl >/dev/null 2>&1; then
  curl -fsSk --max-time 5 "https://$ADDR/healthz" | grep -q '"status":"ok"'
fi

# Rotate the one-time bootstrap admin password (deletes bootstrap.password)
# and sign in with the modern device-bound account flow.
SMOKE_PASS="smoke-pass-$(od -An -tx1 -N12 /dev/urandom 2>/dev/null | tr -d ' \n' || echo "$$-agentlink")"
printf '%s\n' "$SMOKE_PASS" | "$BIN" relay --data-dir "$WORK/relay" user passwd admin --password-stdin
if [[ -e "$WORK/relay/bootstrap.password" ]]; then
  echo "smoke: bootstrap.password was not removed after password rotation" >&2
  exit 1
fi

printf '%s\n' "$SMOKE_PASS" | "$BIN" --config-dir "$WORK/config" login \
  --relay "$RELAY" --fingerprint "$FP" --user admin --password-stdin

COMMON=(--config-dir "$WORK/config" --json)

PAIR="$("$BIN" "${COMMON[@]}" pair --name smoke --access exec)"
PAIR_TOKEN="$(printf '%s' "$PAIR" | sed -n 's/.*"pairing_token":"\([^"]*\)".*/\1/p')"
if [[ -z "$PAIR_TOKEN" ]]; then
  echo "smoke: failed to extract pairing_token from: $PAIR" >&2
  exit 1
fi

"$BIN" --relay "$RELAY" --fingerprint "$FP" node \
  --name smoke --pairing-token "$PAIR_TOKEN" --data-dir "$WORK/node" \
  >"$WORK/node.out" 2>&1 &
NODE_PID=$!

ONLINE=0
for _ in $(seq 1 50); do
  if "$BIN" "${COMMON[@]}" ls | grep -q '"online":true'; then
    ONLINE=1
    break
  fi
  sleep 0.2
done
if [[ "$ONLINE" -ne 1 ]]; then
  echo "smoke: node failed to come online" >&2
  cat "$WORK/node.out" >&2 || true
  exit 1
fi

# Issue a node-local SignedGrant so E2E operations on the node succeed.
"$BIN" "${COMMON[@]}" grant issue --node smoke --policy exec --ttl 10m --issuer-data-dir "$WORK/node" </dev/null

"$BIN" "${COMMON[@]}" exec smoke --shell -- echo hello-agentlink </dev/null
FILE="$WORK/hello.txt"
"$BIN" "${COMMON[@]}" write smoke "$FILE" --content "hello from agentlink" </dev/null
"$BIN" --config-dir "$WORK/config" cat smoke "$FILE" </dev/null
printf '\n'

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_machines","arguments":{}}}' \
  | "$BIN" --config-dir "$WORK/config" mcp
