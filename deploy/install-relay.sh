#!/bin/sh
# Install the relay unit and, when --database-url is set, /etc/agentlink/db.env.
set -eu
DATABASE_URL=""
BIN="${BIN:-/usr/local/bin/agentlink}"
while [ $# -gt 0 ]; do
    case "$1" in
        --database-url) DATABASE_URL=$2; shift 2 ;;
        --bin) BIN=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done
install -d -o agentlink -g agentlink /var/lib/agentlink /etc/agentlink
install -m 755 "$BIN" /usr/local/bin/agentlink
if [ -n "$DATABASE_URL" ]; then
    umask 077
    printf 'AGENTLINK_DATABASE_URL=%s\n' "$DATABASE_URL" > /etc/agentlink/db.env
    chown agentlink:agentlink /etc/agentlink/db.env
    chmod 600 /etc/agentlink/db.env
fi
install -m 644 deploy/agentlink-relay.service /etc/systemd/system/agentlink-relay.service
systemctl daemon-reload
echo "enable with: systemctl enable --now agentlink-relay"
echo "if a slim-bin drop-in runs agentlink-relay --bind …, also run: sh deploy/install-slim-wrappers.sh"
