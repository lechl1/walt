# waltd — build-only image. The install does `docker buildx build --target
# builder` then copies /app/target/release/waltd onto the host and runs it as a
# root systemd service (it manages a vault tree under a user's home and binds a
# host port, so it runs host-native, not in a container). All deps are pure
# Rust (axum/tokio + the Ansible-Vault crypto crates), so no TLS/openssl.

FROM rust:1.88-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release
