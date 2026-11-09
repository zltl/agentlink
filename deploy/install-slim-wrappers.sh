#!/bin/sh
# Install argv helpers for hosts that keep a slim-bin drop-in.
#
# Relay drop-in (a local reverse proxy):
#   ExecStart=/usr/local/bin/agentlink-relay --bind 127.0.0.1:7443 --data-dir …
# The full `agentlink` CLI needs the `relay` subcommand. Overwriting
# `agentlink-relay` with the tip binary makes systemd pass `--bind` as argv1
# and the process exits: unexpected argument '--bind'. This wrapper restores
# the slim shape: agentlink-relay --bind … → agentlink relay --bind ….
#
# Node drop-in:
#   ExecStart=/usr/local/bin/agentlink-node-daemon node --data-dir …
# needs a pass-through copy of the CLI (the unit already supplies `node`).
# Do NOT wrap that path as `exec agentlink node "$@"` or you get `node node`.
#
# Usage (as root, after installing the tip binary):
#   BIN=/usr/local/bin/agentlink sh deploy/install-slim-wrappers.sh
#   systemctl restart agentlink-relay agentlink-node
#
# Stock `deploy/agentlink-relay.service` already runs
# `agentlink relay --bind …` and does not need this wrapper.
set -eu
BIN="${BIN:-/usr/local/bin/agentlink}"
RELAY_WRAP="${RELAY_WRAP:-/usr/local/bin/agentlink-relay}"
NODE_BIN="${NODE_BIN:-/usr/local/bin/agentlink-node-daemon}"

if [ ! -x "$BIN" ]; then
  echo "missing executable BIN=$BIN" >&2
  exit 1
fi

umask 022
cat > "$RELAY_WRAP" <<WRAP
#!/bin/sh
exec ${BIN} relay "\$@"
WRAP
chmod 755 "$RELAY_WRAP"

install -m 755 "$BIN" "$NODE_BIN"

echo "installed $RELAY_WRAP (wrapper → $BIN relay) and $NODE_BIN (pass-through from $BIN)"
echo "restart with: systemctl restart agentlink-relay agentlink-node"
