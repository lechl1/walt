build:
    cargo build --release -p walt --bin walt

test:
    cargo test -p walt

# Build the release binary in a reproducible container via docker buildx,
# auto-detecting the host architecture, and export it to ./target/docker/walt
docker-build:
    #!/usr/bin/env bash
    set -euo pipefail
    case "$(uname -m)" in
        x86_64 | amd64)  platform=linux/amd64 ;;
        aarch64 | arm64) platform=linux/arm64 ;;
        armv7l)          platform=linux/arm/v7 ;;
        *) echo "walt: unsupported host architecture '$(uname -m)'" >&2; exit 1 ;;
    esac
    echo "walt: building for ${platform}"
    docker buildx build --platform "${platform}" --target export --output type=local,dest=target/docker .

install: docker-build
    sudo install -m 755 target/docker/walt /usr/local/bin/walt

uninstall:
    sudo rm -f /usr/local/bin/walt

dev:
    cargo run -p walt --bin walt -- --help
