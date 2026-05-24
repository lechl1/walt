# walt — Ansible-Vault file manager + local SSH-key manager, as a host daemon.
#
#   waltd   the engine (REST + WS on :8470; see openapi.yaml / asyncapi.yaml)
#   walt    a thin CLI client of waltd (WALT_URL, default http://127.0.0.1:8470)
#   gui/    a SvelteKit SPA that waltd serves at /
#
# Each component builds in a throwaway `docker buildx` image (host architecture
# auto-detected) and is exported under ./target/docker/.

# uname -m → docker --platform. Single source of truth for arch detection;
# evaluated once at parse time. Fails loudly on an unsupported arch.
_platform := `case "$(uname -m)" in x86_64|amd64) echo linux/amd64 ;; aarch64|arm64) echo linux/arm64 ;; *) echo "walt: unsupported host architecture '$(uname -m)'" >&2; exit 1 ;; esac`

default:
    @just --list

# Build waltd, walt, and the GUI in one-shot buildx images, then copy the
# artifacts out to ./target/docker/{waltd,walt,gui}.
build:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! docker buildx version >/dev/null 2>&1; then
        echo "walt: docker buildx is required — install the buildx plugin and retry." >&2
        exit 1
    fi
    platform="{{_platform}}"
    echo "walt: building for ${platform}"
    mkdir -p target/docker
    ctrs=()
    trap '{ for c in "${ctrs[@]:-}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done; }' EXIT
    extract() {  # extract <context> <target|''> <tag> <src-in-image> <dest>
        local ctx="$1" target="$2" tag="$3" src="$4" dest="$5" c
        local targ=()
        [ -n "${target}" ] && targ=(--target "${target}")
        docker buildx build --load --platform "${platform}" "${targ[@]}" -t "${tag}" "${ctx}"
        c="$(docker create "${tag}")"; ctrs+=("${c}")
        rm -rf "${dest}"
        docker cp "${c}:${src}" "${dest}"
    }
    extract daemon builder waltd-build:local     /app/target/release/waltd target/docker/waltd
    extract cli    builder walt-build:local       /app/target/release/walt  target/docker/walt
    extract gui    ""      walt-gui-build:local    /app/build                target/docker/gui
    echo "walt: built → target/docker/{waltd,walt,gui}"

# Install the daemon + CLI to /usr/local/bin and the GUI to
# /usr/local/share/walt/gui (sudo for the system paths).
install: build
    #!/usr/bin/env bash
    set -euo pipefail
    sudo install -d -m 0755 /usr/local/bin /usr/local/share/walt
    sudo install -m 0755 target/docker/waltd /usr/local/bin/waltd
    sudo install -m 0755 target/docker/walt  /usr/local/bin/walt
    sudo rm -rf /usr/local/share/walt/gui
    sudo cp -a target/docker/gui /usr/local/share/walt/gui
    echo "walt: installed waltd + walt + GUI. Start waltd (binds :8470), then e.g. 'walt projects'."

uninstall:
    sudo rm -f /usr/local/bin/waltd /usr/local/bin/walt
    sudo rm -rf /usr/local/share/walt

# Unit tests (needs cargo on PATH). The vault crypto lives in the daemon.
test:
    cd daemon && cargo test
    cd cli && cargo test
