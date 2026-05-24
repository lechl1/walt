# walt CLI — build-only image. The install copies /app/target/release/walt onto
# the host. Talks to waltd over plain HTTP on loopback, so no TLS backend is
# needed (reqwest is built with default-features off, blocking + json only).

FROM rust:1.88-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release
