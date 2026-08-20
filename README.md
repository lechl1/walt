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
- **eso** — waltd can also host a vault environment as a remote secret store for
  the Kubernetes [External Secrets Operator](https://external-secrets.io)
  (`daemon/src/eso.rs`). Off by default; see below.
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

## Kubernetes (External Secrets Operator)

ESO has no walt-native provider, so waltd speaks the contract that lets any HTTP
service act as a store: the **webhook provider**. ESO `GET`s waltd, waltd
decrypts the vault file, and ESO writes the result into a `Secret`.

These routes serve *decrypted* secrets, so they are **disabled unless
`WALT_ESO_TOKEN` is set** (503 otherwise), and every request must carry
`Authorization: Bearer $WALT_ESO_TOKEN`. waltd speaks plain HTTP — terminate TLS
in front of it, or keep the listener on a network only the cluster can reach.

```sh
export WALT_ESO_TOKEN=$(openssl rand -hex 32)      # waltd + the CLI read this
export WALT_ESO_URL=https://walt.example.com        # waltd as the cluster sees it

walt eso get acme prod --file secrets.yml           # what ESO would pull
walt eso manifest acme prod --namespace apps \
  --file secrets.yml | kubectl apply -f -           # SecretStore + ExternalSecret
```

The manifest expects the token in a `Secret` alongside it (the generated header
comment spells out the `kubectl create secret` line).

A YAML mapping becomes one `Secret` entry per leaf, nested keys joined with `.`
(`db: {host: …}` → `db.host`); sequences are JSON-encoded; a file that is not a
mapping — a PEM key, a kubeconfig — becomes a single entry keyed by its file
name. Keys are sanitized to `[-._a-zA-Z0-9]`.

| route | serves |
| --- | --- |
| `GET /api/eso/{project}/{env}` | every file in the env, merged |
| `GET /api/eso/{project}/{env}/{file}` | one file (`?property=KEY` adds `value`) |
| `GET /api/eso/manifest/{project}/{env}` | generated SecretStore + ExternalSecret |

## Layout

```
cli/                         walt  — HTTP client of waltd
daemon/                      waltd — engine + Ansible-Vault crypto (src/vault.rs)
                             + ESO webhook-provider backend (src/eso.rs)
gui/                         SvelteKit console
openapi.yaml / asyncapi.yaml the waltd API contract
```
