# Relay image. The binary is the same one a node runs; the entrypoint is the relay.
# The first start prints the admin token and certificate fingerprint in the logs
# and stores them in the data volume.

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
