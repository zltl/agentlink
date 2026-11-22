# Relay image. The binary is the same CLI a node runs; the entrypoint is the relay.
# Built headless (`--no-default-features`) without the default GUI `controller`
# feature so the container stays lean with zero eframe/OpenH264/libstdc++6 bloat.
#
# First start writes `cert.pem`, `key.pem`, `fingerprint.txt`, and (when the user
# table is empty) a one-time `bootstrap.password` for `admin` in `/var/lib/agentlink`.
# Rotate that password immediately (`agentlink relay --data-dir /var/lib/agentlink
# user passwd admin`), which removes `bootstrap.password`. Legacy `admin.token` is
# disabled by default unless AGENTLINK_LEGACY_ADMIN=1 and a TTL are set.
# Set AGENTLINK_PUBLIC_URL=https://relay.example.com when behind a reverse proxy.

FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p agentlink-cli --no-default-features

FROM debian:bookworm-slim
# ca-certificates: HTTPS egress (S3, webhooks, GitHub) needs the system CA bundle.
# curl: used by HEALTHCHECK against the relay's local /healthz endpoint.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/agentlink --shell /usr/sbin/nologin agentlink \
    && mkdir -p /var/lib/agentlink \
    && chown agentlink:agentlink /var/lib/agentlink
COPY --from=build /src/target/release/agentlink /usr/local/bin/agentlink
USER agentlink
EXPOSE 7443
VOLUME /var/lib/agentlink
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsSk --max-time 4 https://127.0.0.1:7443/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/agentlink", "relay", "--bind", "0.0.0.0:7443", "--data-dir", "/var/lib/agentlink"]
