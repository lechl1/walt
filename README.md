# walt

Ansible-Vault file manager + local SSH-key manager, packaged as a small host
daemon with a web console.

- **waltd** — the engine. A Rust (axum) daemon exposing a REST + WebSocket API
  (`openapi.yaml` / `asyncapi.yaml`) on `:8470`. It does the Ansible-Vault 1.1
  (AES256) crypto (`daemon/src/vault.rs`) and serves the GUI. Runs host-native:
  it manages a vault tree under your home and chowns files back to you.
- **walt** — a thin CLI client of waltd (`WALT_URL`, default
  `http://127.0.0.1:8470`). Vault projects/environments/files, plus SSH keypair,
  host-key, and `authorized_keys` management.
- **gui/** — a SvelteKit SPA (CodeMirror 6 + shadcn-svelte, bundled by Vite —
  the browser loads nothing from any CDN) that waltd serves at `/`.

Files written by waltd stay wire-compatible with `ansible-vault`, and vice-versa.

## Build & install

Each component builds in a throwaway `docker buildx` image (host architecture
auto-detected) and is exported to `./target/docker/`:

```sh
just build      # → target/docker/{waltd,walt,gui}
just install    # → /usr/local/bin/{waltd,walt} + /usr/local/share/walt/gui (sudo)
```

Then start `waltd` (binds `:8470`), open <http://localhost:8470/>, and use the
`walt` CLI — e.g. `walt projects`, `walt keys list`.

## Layout

```
cli/                         walt  — HTTP client of waltd
daemon/                      waltd — engine + Ansible-Vault crypto (src/vault.rs)
gui/                         SvelteKit console
openapi.yaml / asyncapi.yaml the waltd API contract
```
