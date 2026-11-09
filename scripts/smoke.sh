#!/usr/bin/env bash
# Manual version of the CLI smoke test. `cargo test` covers the same flow.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/target/debug/agentlink}"
if [[ ! -x "$BIN" ]]; then
  (cd "$ROOT" && cargo build -p agentlink-cli)
fi

WORK="$(mktemp -d)"
trap 'kill "$RELAY_PID" "$NODE_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

"$BIN" relay --bind 127.0.0.1:0 --data-dir "$WORK/relay" >"$WORK/relay.out" 2>&1 &
RELAY_PID=$!
for _ in $(seq 1 50); do
  [[ -s "$WORK/relay/listen_addr.txt" ]] && break
  sleep 0.1
done

ADDR="$(tr -d '[:space:]' <"$WORK/relay/listen_addr.txt")"
FP="$(tr -d '[:space:]' <"$WORK/relay/fingerprint.txt")"
TOKEN="$(tr -d '[:space:]' <"$WORK/relay/admin.token")"
RELAY="wss://$ADDR"
COMMON=(--config-dir "$WORK/config" --relay "$RELAY" --token "$TOKEN" --fingerprint "$FP" --json)

PAIR="$("$BIN" "${COMMON[@]}" pair --name smoke --access exec)"
PAIR_TOKEN="$(printf '%s' "$PAIR" | sed -n 's/.*"pairing_token":"\([^"]*\)".*/\1/p')"

"$BIN" --relay "$RELAY" --fingerprint "$FP" node \
  --name smoke --pairing-token "$PAIR_TOKEN" --data-dir "$WORK/node" \
  >"$WORK/node.out" 2>&1 &
NODE_PID=$!

for _ in $(seq 1 50); do
  if "$BIN" "${COMMON[@]}" ls | grep -q '"online":true'; then
    break
  fi
  sleep 0.2
done

"$BIN" "${COMMON[@]}" exec smoke --shell -- echo hello-agentlink
FILE="$WORK/hello.txt"
"$BIN" "${COMMON[@]}" write smoke "$FILE" --content "hello from agentlink"
"$BIN" --config-dir "$WORK/config" --relay "$RELAY" --token "$TOKEN" --fingerprint "$FP" \
  cat smoke "$FILE"

printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_machines","arguments":{}}}' \
  | AGENTLINK_RELAY="$RELAY" AGENTLINK_TOKEN="$TOKEN" AGENTLINK_FINGERPRINT="$FP" \
    "$BIN" --config-dir "$WORK/config" mcp
