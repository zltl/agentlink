# Relay image. The binary is the same one a node runs; the entrypoint is the relay.
# First start writes `cert.pem`, `key.pem`, `fingerprint.txt`, and (when the user
# table is empty) a one-time `bootstrap.password` for `admin` in `/var/lib/agentlink`.
# Rotate that password immediately (`agentlink relay --data-dir /var/lib/agentlink
# user passwd admin`), which removes `bootstrap.password`. Legacy `admin.token` is
# disabled by default unless AGENTLINK_LEGACY_ADMIN=1 and a TTL are set.

FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p agentlink-cli

FROM debian:bookworm-slim
RUN useradd --system --create-home --home-dir /var/lib/agentlink --shell /usr/sbin/nologin agentlink \
    && mkdir -p /var/lib/agentlink \
    && chown agentlink:agentlink /var/lib/agentlink
COPY --from=build /src/target/release/agentlink /usr/local/bin/agentlink
USER agentlink
EXPOSE 7443
VOLUME /var/lib/agentlink
ENTRYPOINT ["/usr/local/bin/agentlink", "relay", "--bind", "0.0.0.0:7443", "--data-dir", "/var/lib/agentlink"]
