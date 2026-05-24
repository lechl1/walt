# syntax=docker/dockerfile:1
# Reproducible release build of the `walt` binary, driven by `just install`
# via `docker buildx`. The final `export` stage contains only the binary so
# that `--output type=local` writes just `walt` to the host.

FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Cache the cargo registry and target dir across builds. The target dir is a
# cache mount (not persisted in the image), so copy the binary out of it in the
# same RUN to a plain path the next stage can read.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p walt --bin walt && \
    cp target/release/walt /walt

FROM scratch AS export
COPY --from=build /walt /walt
