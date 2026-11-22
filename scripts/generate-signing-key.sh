#!/bin/sh
# Generate an agentlink release signing seed (AGENTLINK_SIGNING_KEY) and
# matching minisign public key. Never commit the private seed.
#
# Default layout (chmod 700 dir, 600 seed):
#   ~/.config/agentlink/signing.key      # 64 hex chars (32-byte ed25519 seed)
#   ~/.config/agentlink/minisign.pub     # minisign public key text
#
# Usage:
#   sh scripts/generate-signing-key.sh
#   AGENTLINK_BIN=/path/to/agentlink OUT_DIR=/etc/agentlink sh scripts/generate-signing-key.sh
#
# Then:
#   - Put the seed in CI/release secret AGENTLINK_SIGNING_KEY (hex only).
#   - Publish/pin minisign.pub out of band (and optionally copy to deploy/minisign.pub).
#   - Clients: AGENTLINK_UPDATE_PUBKEY=/path/to/minisign.pub agentlink update --check
set -eu
# Restrict file creation permissions immediately so private key material is
# never created world-readable (prevents TOCTOU permission race, SEC-12).
umask 077

OUT_DIR="${OUT_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/agentlink}"
SEED_FILE="${SEED_FILE:-$OUT_DIR/signing.key}"
PUB_FILE="${PUB_FILE:-$OUT_DIR/minisign.pub}"
AGENTLINK_BIN="${AGENTLINK_BIN:-agentlink}"

if [ -L "$SEED_FILE" ]; then
  echo "refusing to write through symlink: $SEED_FILE" >&2
  exit 1
fi
if [ -e "$SEED_FILE" ] && [ "${FORCE:-0}" != 1 ]; then
  echo "refusing to overwrite $SEED_FILE (set FORCE=1 to replace)" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

# 32 cryptographically random bytes as lowercase hex (ed25519 seed).
rm -f "$SEED_FILE"
python3 - <<'PY' >"$SEED_FILE"
import secrets, sys
sys.stdout.write(secrets.token_hex(32) + "\n")
PY
chmod 600 "$SEED_FILE"

if ! command -v "$AGENTLINK_BIN" >/dev/null 2>&1 && [ ! -x "$AGENTLINK_BIN" ]; then
  echo "generated $SEED_FILE (mode 600)"
  echo "install agentlink to derive the public key, then run:" >&2
  echo "  AGENTLINK_SIGNING_KEY=\$(tr -d '\\n' < \"$SEED_FILE\") $AGENTLINK_BIN internal pubkey > \"$PUB_FILE\"" >&2
  exit 0
fi

AGENTLINK_SIGNING_KEY=$(tr -d '\n' <"$SEED_FILE")
export AGENTLINK_SIGNING_KEY
"$AGENTLINK_BIN" internal pubkey >"$PUB_FILE"
chmod 644 "$PUB_FILE"

echo "wrote $SEED_FILE (mode 600) and $PUB_FILE (mode 644)"
echo "next:"
echo "  1) Release secret AGENTLINK_SIGNING_KEY = \$(cat $SEED_FILE)"
echo "  2) Pin $PUB_FILE for clients (AGENTLINK_UPDATE_PUBKEY)"
echo "  3) Optional: cp $PUB_FILE deploy/minisign.pub && commit only the public file"
echo "  4) Sign: AGENTLINK_SIGNING_KEY=\$(tr -d '\\n' <$SEED_FILE) agentlink internal sign-checksums SHA256SUMS --pubkey-out minisign.pub"
