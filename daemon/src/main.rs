//! waltd — walt's daemon. Two backends behind one HTTP service:
//!
//!  1. **vault** — the Ansible-Vault file-management engine. Manages a vault
//!     tree at `${WALT_ROOT}/.vault/<project>/<env>/<file>` (the layout walt's
//!     CLI creates), encrypting/decrypting files with the per-env password.
//!  2. **ssh keys** — merged from the former `arthur` daemon: manages SSH
//!     keypairs and per-user authorized_keys **on the local machine only**.
//!
//! REST + WS surface (the contract — see ../openapi.yaml / ../asyncapi.yaml):
//!   GET    /healthz                                       liveness probe
//!   --- vault ---
//!   GET    /api/projects                                  list projects + envs
//!   POST   /api/projects                                  init a project
//!   GET    /api/projects/{project}/envs                   list environments
//!   POST   /api/projects/{project}/envs                   create an environment
//!   GET    /api/projects/{project}/envs/{env}/files       list files
//!   POST   /api/projects/{project}/envs/{env}/files       add a file (encrypts)
//!   GET    .../files/{file}                               decrypted content
//!   PUT    .../files/{file}                               save content (encrypts)
//!   DELETE .../files/{file}                               delete a file
//!   POST   .../{env}/encrypt | /decrypt                   bulk (en|de)crypt
//!   --- ssh keys ---
//!   GET    /api/keys                                      list managed keypairs
//!   POST   /api/keys                                      generate a keypair
//!   DELETE /api/keys/{id}                                 delete a keypair
//!   GET    /api/host-keys                                 pre-existing host SSH keys
//!   GET    /api/authorized?user=U                         list a user's authorized_keys
//!   POST   /api/authorized                                add a key {user,key}
//!   DELETE /api/authorized                                remove a key {user,key}
//!   --- gui + events ---
//!   GET    /ws/events                                     mutation broadcast
//!   GET    /*                                             prebuilt SvelteKit SPA
//!
//! Runs as root (systemd) so it can manage a vault tree under any user's home
//! and read/write any local user's ~/.ssh/authorized_keys.

mod vault;

use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone)]
struct AppState {
    /// Vault tree lives at `${root}/.vault`.
    root: PathBuf,
    /// Managed SSH keypairs (WALT_KEYS_DIR).
    keys_dir: PathBuf,
    /// Unprivileged user that should own files waltd creates (chown target).
    owner: String,
    events: broadcast::Sender<String>,
}

impl AppState {
    fn vault_base(&self) -> PathBuf {
        self.root.join(".vault")
    }
    fn project_dir(&self, project: &str) -> PathBuf {
        self.vault_base().join(project)
    }
    fn env_dir(&self, project: &str, env: &str) -> PathBuf {
        self.project_dir(project).join(env)
    }
    /// Best-effort chown a path tree back to the owner (waltd runs as root).
    fn chown(&self, path: &FsPath) {
        if self.owner.is_empty() || self.owner == "root" {
            return;
        }
        let _ = Command::new("chown")
            .args(["-R", &format!("{}:", self.owner)])
            .arg(path)
            .status();
    }
    fn emit(&self, value: serde_json::Value) {
        let _ = self.events.send(value.to_string());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind: SocketAddr = std::env::var("WALT_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8470".into())
        .parse()
        .context("parsing WALT_ADDR")?;

    let owner = std::env::var("WALT_OWNER").unwrap_or_default();
    let owner_home = home_of(&owner)
        .unwrap_or_else(|| PathBuf::from("/root"));
    let owner = if owner.is_empty() {
        owner_home
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("root")
            .to_string()
    } else {
        owner
    };

    // WALT_ROOT defaults to the owner's home; the vault tree is ${root}/.vault.
    let root = std::env::var("WALT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| owner_home.clone());
    std::fs::create_dir_all(root.join(".vault"))
        .with_context(|| format!("mkdir {}/.vault", root.display()))?;

    // Managed SSH keypairs (ssh-key backend).
    let keys_dir = PathBuf::from(
        std::env::var("WALT_KEYS_DIR").unwrap_or_else(|_| "/var/lib/walt/keys".into()),
    );
    std::fs::create_dir_all(&keys_dir)
        .with_context(|| format!("mkdir {}", keys_dir.display()))?;

    let (events, _rx) = broadcast::channel(256);
    let state = AppState {
        root,
        keys_dir,
        owner,
        events,
    };
    state.chown(&state.vault_base());

    // The GUI is the prebuilt SvelteKit SPA (modules/walt/gui → ${WALT_GUI_DIR}).
    // Unmatched routes serve static assets; unknown paths fall back to the SPA
    // shell so client-side routing works. API routes below take precedence.
    let gui_dir =
        std::env::var("WALT_GUI_DIR").unwrap_or_else(|_| "/usr/local/share/walt/gui".into());
    let spa = ServeDir::new(&gui_dir).fallback(ServeFile::new(format!("{gui_dir}/index.html")));

    let app = Router::new()
        .route("/healthz", get(healthz))
        // vault backend
        .route("/api/projects", get(list_projects).post(create_project))
        .route(
            "/api/projects/{project}/envs",
            get(list_envs).post(create_env),
        )
        .route(
            "/api/projects/{project}/envs/{env}/files",
            get(list_files).post(add_file),
        )
        .route(
            "/api/projects/{project}/envs/{env}/files/{file}",
            get(get_file).put(put_file).delete(delete_file),
        )
        .route("/api/projects/{project}/envs/{env}/encrypt", post(encrypt_env))
        .route("/api/projects/{project}/envs/{env}/decrypt", post(decrypt_env))
        // ssh-key backend (merged from arthur)
        .route("/api/keys", get(list_keys).post(generate_key))
        .route("/api/keys/{id}", delete(delete_key))
        .route("/api/host-keys", get(list_host_keys))
        .route(
            "/api/authorized",
            get(list_authorized).post(add_authorized).delete(remove_authorized),
        )
        .route("/ws/events", get(ws_handler))
        .layer(CorsLayer::permissive())
        .fallback_service(spa)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "waltd listening");
    axum::serve(listener, app).await.context("serving")?;
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

// ==========================================================================
// vault backend
// ==========================================================================

#[derive(Serialize)]
struct Project {
    name: String,
    environments: Vec<String>,
}

async fn list_projects(State(st): State<AppState>) -> Json<serde_json::Value> {
    let mut projects = Vec::new();
    if let Ok(entries) = std::fs::read_dir(st.vault_base()) {
        for ent in entries.flatten() {
            let path = ent.path();
            if !path.is_dir() {
                continue;
            }
            let name = ent.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            projects.push(Project {
                environments: list_subdirs(&path),
                name,
            });
        }
    }
    projects.sort_by(|a, b| a.name.cmp(&b.name));
    Json(serde_json::json!({ "projects": projects }))
}

#[derive(Deserialize)]
struct CreateProject {
    name: String,
    #[serde(default)]
    environments: Vec<String>,
    #[serde(default)]
    password: Option<String>,
}

async fn create_project(State(st): State<AppState>, Json(req): Json<CreateProject>) -> Response {
    let Some(name) = safe_seg(&req.name) else {
        return bad("invalid project name");
    };
    let mut envs: Vec<String> = req.environments.iter().filter_map(|e| safe_seg(e)).collect();
    if envs.is_empty() {
        envs = vec!["dev".into(), "test".into(), "prod".into()];
    }
    let project_dir = st.project_dir(&name);
    if let Err(e) = std::fs::create_dir_all(&project_dir) {
        return err(format!("mkdir project: {e}"));
    }
    for env in &envs {
        let env_dir = project_dir.join(env);
        if let Err(e) = std::fs::create_dir_all(&env_dir) {
            return err(format!("mkdir env: {e}"));
        }
        let pw_path = env_dir.join(vault::PASSWORD_FILE);
        if !pw_path.exists() {
            let pw = if env == vault::DEV_ENV {
                req.password.clone().unwrap_or_else(|| vault::DEV_PASSWORD.into())
            } else {
                vault::random_password()
            };
            if let Err(e) = write_0600(&pw_path, pw.as_bytes()) {
                return err(format!("write password: {e}"));
            }
        }
    }
    st.chown(&project_dir);
    st.emit(serde_json::json!({ "kind": "project", "op": "added", "project": name }));
    (
        StatusCode::CREATED,
        Json(Project { name, environments: envs }),
    )
        .into_response()
}

#[derive(Serialize)]
struct EnvInfo {
    name: String,
    file_count: usize,
    has_password: bool,
}

async fn list_envs(State(st): State<AppState>, Path(project): Path<String>) -> Response {
    let Some(project) = safe_seg(&project) else {
        return bad("invalid project");
    };
    let dir = st.project_dir(&project);
    if !dir.is_dir() {
        return not_found("unknown project");
    }
    let mut envs = Vec::new();
    for env in list_subdirs(&dir) {
        let env_dir = dir.join(&env);
        envs.push(EnvInfo {
            file_count: list_files_in(&env_dir).len(),
            has_password: env_dir.join(vault::PASSWORD_FILE).is_file(),
            name: env,
        });
    }
    Json(serde_json::json!({ "environments": envs })).into_response()
}

#[derive(Deserialize)]
struct CreateEnv {
    name: String,
    #[serde(default)]
    password: Option<String>,
}

async fn create_env(
    State(st): State<AppState>,
    Path(project): Path<String>,
    Json(req): Json<CreateEnv>,
) -> Response {
    let (Some(project), Some(env)) = (safe_seg(&project), safe_seg(&req.name)) else {
        return bad("invalid project or environment");
    };
    if !st.project_dir(&project).is_dir() {
        return not_found("unknown project");
    }
    let env_dir = st.env_dir(&project, &env);
    if let Err(e) = std::fs::create_dir_all(&env_dir) {
        return err(format!("mkdir env: {e}"));
    }
    let pw_path = env_dir.join(vault::PASSWORD_FILE);
    if !pw_path.exists() {
        let pw = if env == vault::DEV_ENV {
            req.password.clone().unwrap_or_else(|| vault::DEV_PASSWORD.into())
        } else {
            req.password.clone().unwrap_or_else(vault::random_password)
        };
        if let Err(e) = write_0600(&pw_path, pw.as_bytes()) {
            return err(format!("write password: {e}"));
        }
    }
    st.chown(&env_dir);
    st.emit(serde_json::json!({ "kind": "env", "op": "added", "project": project, "env": env }));
    StatusCode::CREATED.into_response()
}

#[derive(Serialize)]
struct FileInfo {
    name: String,
    encrypted: bool,
    size: u64,
}

async fn list_files(
    State(st): State<AppState>,
    Path((project, env)): Path<(String, String)>,
) -> Response {
    let (Some(project), Some(env)) = (safe_seg(&project), safe_seg(&env)) else {
        return bad("invalid path");
    };
    let env_dir = st.env_dir(&project, &env);
    if !env_dir.is_dir() {
        return not_found("unknown environment");
    }
    let files = list_files_in(&env_dir);
    Json(serde_json::json!({ "files": files })).into_response()
}

#[derive(Deserialize)]
struct AddFile {
    name: String,
    #[serde(default)]
    content: String,
}

async fn add_file(
    State(st): State<AppState>,
    Path((project, env)): Path<(String, String)>,
    Json(req): Json<AddFile>,
) -> Response {
    let (Some(project), Some(env), Some(file)) =
        (safe_seg(&project), safe_seg(&env), safe_file(&req.name))
    else {
        return bad("invalid path or file name");
    };
    let env_dir = st.env_dir(&project, &env);
    if !env_dir.is_dir() {
        return not_found("unknown environment");
    }
    let path = env_dir.join(&file);
    if path.exists() {
        return (StatusCode::CONFLICT, "file already exists").into_response();
    }
    match write_encrypted(&st, &env_dir, &env, &path, req.content.as_bytes()) {
        Ok(()) => {
            st.emit(serde_json::json!({
                "kind": "file", "op": "added", "project": project, "env": env, "file": file
            }));
            (StatusCode::CREATED, Json(FileInfo { name: file, encrypted: true, size: 0 }))
                .into_response()
        }
        Err(resp) => resp,
    }
}

async fn get_file(
    State(st): State<AppState>,
    Path((project, env, file)): Path<(String, String, String)>,
) -> Response {
    let (Some(project), Some(env), Some(file)) =
        (safe_seg(&project), safe_seg(&env), safe_file(&file))
    else {
        return bad("invalid path");
    };
    let env_dir = st.env_dir(&project, &env);
    let path = env_dir.join(&file);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return not_found("no such file");
    };
    let encrypted = vault::is_encrypted(&raw);
    let content = if encrypted {
        let pw = match vault::env_password(&env_dir, &env) {
            Ok(pw) => pw,
            Err(e) => return err(e),
        };
        match vault::decrypt(&raw, &pw) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(e) => return err(e),
        }
    } else {
        raw
    };
    Json(serde_json::json!({ "name": file, "content": content, "encrypted": encrypted }))
        .into_response()
}

#[derive(Deserialize)]
struct PutFile {
    #[serde(default)]
    content: String,
}

async fn put_file(
    State(st): State<AppState>,
    Path((project, env, file)): Path<(String, String, String)>,
    Json(req): Json<PutFile>,
) -> Response {
    let (Some(project), Some(env), Some(file)) =
        (safe_seg(&project), safe_seg(&env), safe_file(&file))
    else {
        return bad("invalid path");
    };
    let env_dir = st.env_dir(&project, &env);
    if !env_dir.is_dir() {
        return not_found("unknown environment");
    }
    let path = env_dir.join(&file);
    match write_encrypted(&st, &env_dir, &env, &path, req.content.as_bytes()) {
        Ok(()) => {
            st.emit(serde_json::json!({
                "kind": "file", "op": "updated", "project": project, "env": env, "file": file
            }));
            StatusCode::NO_CONTENT.into_response()
        }
        Err(resp) => resp,
    }
}

async fn delete_file(
    State(st): State<AppState>,
    Path((project, env, file)): Path<(String, String, String)>,
) -> Response {
    let (Some(project), Some(env), Some(file)) =
        (safe_seg(&project), safe_seg(&env), safe_file(&file))
    else {
        return bad("invalid path");
    };
    let _ = std::fs::remove_file(st.env_dir(&project, &env).join(&file));
    st.emit(serde_json::json!({
        "kind": "file", "op": "removed", "project": project, "env": env, "file": file
    }));
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct BulkReq {
    #[serde(default)]
    file: Option<String>,
}

async fn encrypt_env(
    State(st): State<AppState>,
    Path((project, env)): Path<(String, String)>,
    Json(req): Json<BulkReq>,
) -> Response {
    transform_env(&st, &project, &env, req.file, true).await
}

async fn decrypt_env(
    State(st): State<AppState>,
    Path((project, env)): Path<(String, String)>,
    Json(req): Json<BulkReq>,
) -> Response {
    transform_env(&st, &project, &env, req.file, false).await
}

/// Encrypt-or-decrypt files in an env in place (one if `only` is set, else all).
async fn transform_env(
    st: &AppState,
    project: &str,
    env: &str,
    only: Option<String>,
    encrypt: bool,
) -> Response {
    let (Some(project), Some(env)) = (safe_seg(project), safe_seg(env)) else {
        return bad("invalid path");
    };
    let env_dir = st.env_dir(&project, &env);
    if !env_dir.is_dir() {
        return not_found("unknown environment");
    }
    let pw = match vault::env_password(&env_dir, &env) {
        Ok(pw) => pw,
        Err(e) => return err(e),
    };
    let targets: Vec<String> = match only.and_then(|f| safe_file(&f)) {
        Some(f) => vec![f],
        None => list_files_in(&env_dir).into_iter().map(|f| f.name).collect(),
    };
    let mut changed = 0usize;
    for name in &targets {
        let path = env_dir.join(name);
        let Ok(raw) = std::fs::read_to_string(&path) else { continue };
        let already = vault::is_encrypted(&raw);
        if encrypt && !already {
            if let Err(resp) = write_encrypted(st, &env_dir, &env, &path, raw.as_bytes()) {
                return resp;
            }
            changed += 1;
        } else if !encrypt && already {
            match vault::decrypt(&raw, &pw) {
                Ok(bytes) => {
                    if let Err(e) = std::fs::write(&path, &bytes) {
                        return err(format!("write {}: {e}", path.display()));
                    }
                    st.chown(&path);
                    changed += 1;
                }
                Err(e) => return err(e),
            }
        }
    }
    st.emit(serde_json::json!({
        "kind": "file",
        "op": if encrypt { "encrypted" } else { "decrypted" },
        "project": project, "env": env, "count": changed
    }));
    StatusCode::NO_CONTENT.into_response()
}

/// Encrypt `bytes` with the env password and write to `path` (then chown).
fn write_encrypted(
    st: &AppState,
    env_dir: &FsPath,
    env: &str,
    path: &FsPath,
    bytes: &[u8],
) -> Result<(), Response> {
    let pw = vault::env_password(env_dir, env).map_err(err)?;
    let envelope = vault::encrypt(bytes, &pw);
    std::fs::write(path, envelope).map_err(|e| err(format!("write {}: {e}", path.display())))?;
    st.chown(path);
    Ok(())
}

fn list_subdirs(dir: &FsPath) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for ent in entries.flatten() {
            if ent.path().is_dir() {
                let n = ent.file_name().to_string_lossy().to_string();
                if !n.starts_with('.') {
                    out.push(n);
                }
            }
        }
    }
    out.sort();
    out
}

fn list_files_in(env_dir: &FsPath) -> Vec<FileInfo> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(env_dir) {
        for ent in entries.flatten() {
            let path = ent.path();
            if !path.is_file() {
                continue;
            }
            let name = ent.file_name().to_string_lossy().to_string();
            if name == vault::PASSWORD_FILE {
                continue;
            }
            let size = ent.metadata().map(|m| m.len()).unwrap_or(0);
            let encrypted = std::fs::read_to_string(&path)
                .map(|s| vault::is_encrypted(&s))
                .unwrap_or(false);
            out.push(FileInfo { name, encrypted, size });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn write_0600(path: &FsPath, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// A project/env path segment: alphanumerics, `-`, `_`, `.`; never `.`/`..` or
/// path separators. Returns None if nothing safe remains.
fn safe_seg(s: &str) -> Option<String> {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(64)
        .collect();
    let trimmed = cleaned.trim_matches('.');
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// A filename inside an env. Like `safe_seg` but keeps a leading dot (so
/// `.env` is allowed) while still blocking traversal and the password file.
fn safe_file(s: &str) -> Option<String> {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(128)
        .collect();
    if cleaned.is_empty()
        || cleaned == "."
        || cleaned == ".."
        || cleaned.contains("..")
        || cleaned == vault::PASSWORD_FILE
    {
        return None;
    }
    Some(cleaned)
}

fn bad(msg: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, msg).into_response()
}
fn not_found(msg: &'static str) -> Response {
    (StatusCode::NOT_FOUND, msg).into_response()
}
fn err(msg: String) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
}

// ==========================================================================
// ssh-key backend (merged from arthur)
// ==========================================================================

#[derive(Debug, Serialize)]
struct KeyInfo {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    fingerprint: String,
    comment: String,
    public_key: String,
}

async fn list_keys(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "keys": scan_keys(&st.keys_dir) }))
}

fn scan_keys(dir: &FsPath) -> Vec<KeyInfo> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pub") {
            continue;
        }
        let Ok(pubkey) = std::fs::read_to_string(&path) else {
            continue;
        };
        let pubkey = pubkey.trim().to_string();
        let mut parts = pubkey.splitn(3, ' ');
        let kind = parts.next().unwrap_or("").to_string();
        let _b64 = parts.next().unwrap_or("");
        let comment = parts.next().unwrap_or("").to_string();
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        out.push(KeyInfo {
            fingerprint: fingerprint_of(&path),
            id,
            kind,
            comment,
            public_key: pubkey,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn fingerprint_of(pub_path: &FsPath) -> String {
    Command::new("ssh-keygen")
        .args(["-lf"])
        .arg(pub_path)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_default()
}

#[derive(Debug, Deserialize)]
struct GenReq {
    name: String,
    #[serde(default)]
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    comment: Option<String>,
}

async fn generate_key(State(st): State<AppState>, Json(req): Json<GenReq>) -> Response {
    let name = sanitize(&req.name);
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }
    let kind = req.kind.unwrap_or_else(|| "ed25519".into());
    if !matches!(kind.as_str(), "ed25519" | "rsa" | "ecdsa") {
        return (StatusCode::BAD_REQUEST, "unsupported key type").into_response();
    }
    let comment = req.comment.unwrap_or_else(|| format!("walt:{name}"));
    let path = st.keys_dir.join(&name);
    if path.exists() {
        return (StatusCode::CONFLICT, "key already exists").into_response();
    }
    let out = Command::new("ssh-keygen")
        .args(["-t", &kind, "-N", "", "-C", &comment, "-f"])
        .arg(&path)
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let info = scan_keys(&st.keys_dir).into_iter().find(|k| k.id == name);
            st.emit(serde_json::json!({ "kind": "key", "op": "added", "id": name }));
            (StatusCode::CREATED, Json(info)).into_response()
        }
        Ok(o) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("ssh-keygen: {}", String::from_utf8_lossy(&o.stderr)),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("ssh-keygen spawn: {e}")).into_response(),
    }
}

async fn delete_key(State(st): State<AppState>, Path(id): Path<String>) -> Response {
    let name = sanitize(&id);
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "invalid id").into_response();
    }
    let _ = std::fs::remove_file(st.keys_dir.join(&name));
    let _ = std::fs::remove_file(st.keys_dir.join(format!("{name}.pub")));
    st.emit(serde_json::json!({ "kind": "key", "op": "removed", "id": name }));
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Debug, Serialize)]
struct HostKey {
    scope: String,
    owner: String,
    path: String,
    #[serde(rename = "type")]
    kind: String,
    fingerprint: String,
    comment: String,
    public_key: String,
}

async fn list_host_keys() -> Json<serde_json::Value> {
    let keys = tokio::task::spawn_blocking(scan_host_keys)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "keys": keys }))
}

fn scan_host_keys() -> Vec<HostKey> {
    let mut out = Vec::new();
    for (user, home) in real_users() {
        let ssh = home.join(".ssh");
        let Ok(entries) = std::fs::read_dir(&ssh) else {
            continue;
        };
        for ent in entries.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) == Some("pub") {
                if let Some(hk) = read_pub(&p, "user", &user) {
                    out.push(hk);
                }
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir("/etc/ssh") {
        for ent in entries.flatten() {
            let p = ent.path();
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.starts_with("ssh_host_") && name.ends_with("_key.pub") {
                if let Some(hk) = read_pub(&p, "host", "system") {
                    out.push(hk);
                }
            }
        }
    }
    out.sort_by(|a, b| (&a.scope, &a.owner, &a.path).cmp(&(&b.scope, &b.owner, &b.path)));
    out
}

fn read_pub(path: &FsPath, scope: &str, owner: &str) -> Option<HostKey> {
    let content = std::fs::read_to_string(path).ok()?;
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())?
        .to_string();
    let mut parts = line.splitn(3, ' ');
    let kind = parts.next().unwrap_or("").to_string();
    let _b64 = parts.next();
    let comment = parts.next().unwrap_or("").to_string();
    Some(HostKey {
        scope: scope.to_string(),
        owner: owner.to_string(),
        path: path.display().to_string(),
        kind,
        fingerprint: fingerprint_of(path),
        comment,
        public_key: line,
    })
}

/// Real login users (root + uid in [1000,65534)) with a /home or /root home.
fn real_users() -> Vec<(String, PathBuf)> {
    let mut v = Vec::new();
    let Ok(out) = Command::new("getent").arg("passwd").output() else {
        return v;
    };
    let Ok(s) = String::from_utf8(out.stdout) else {
        return v;
    };
    for line in s.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let (user, home, shell) = (f[0], f[5], f[6]);
        let uid: u32 = f[2].parse().unwrap_or(u32::MAX);
        let is_login = !(shell.ends_with("nologin") || shell.ends_with("/false"));
        let real_home = home.starts_with("/home/") || home == "/root";
        if (uid == 0 || (1000..65534).contains(&uid)) && is_login && real_home {
            v.push((user.to_string(), PathBuf::from(home)));
        }
    }
    v
}

#[derive(Debug, Deserialize)]
struct AuthQuery {
    user: String,
}

async fn list_authorized(Query(q): Query<AuthQuery>) -> Response {
    let Some(home) = home_of(&q.user) else {
        return (StatusCode::NOT_FOUND, "unknown user").into_response();
    };
    let ak = home.join(".ssh/authorized_keys");
    let keys: Vec<String> = std::fs::read_to_string(&ak)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    Json(serde_json::json!({ "user": q.user, "keys": keys })).into_response()
}

#[derive(Debug, Deserialize)]
struct AuthMutation {
    user: String,
    key: String,
}

async fn add_authorized(State(st): State<AppState>, Json(req): Json<AuthMutation>) -> Response {
    let Some(home) = home_of(&req.user) else {
        return (StatusCode::NOT_FOUND, "unknown user").into_response();
    };
    let key = req.key.trim().to_string();
    if key.split_whitespace().count() < 2 {
        return (StatusCode::BAD_REQUEST, "not a valid public key").into_response();
    }
    let ssh_dir = home.join(".ssh");
    if let Err(e) = std::fs::create_dir_all(&ssh_dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("mkdir .ssh: {e}")).into_response();
    }
    let ak = ssh_dir.join("authorized_keys");
    let mut current = std::fs::read_to_string(&ak).unwrap_or_default();
    if current.lines().any(|l| l.trim() == key) {
        return (StatusCode::OK, "already present").into_response();
    }
    if !current.is_empty() && !current.ends_with('\n') {
        current.push('\n');
    }
    current.push_str(&key);
    current.push('\n');
    if let Err(e) = std::fs::write(&ak, &current) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("write authorized_keys: {e}")).into_response();
    }
    fix_ssh_ownership(&req.user, &ssh_dir, &ak);
    st.emit(serde_json::json!({ "kind": "authorized", "op": "added", "user": req.user }));
    StatusCode::NO_CONTENT.into_response()
}

async fn remove_authorized(State(st): State<AppState>, Json(req): Json<AuthMutation>) -> Response {
    let Some(home) = home_of(&req.user) else {
        return (StatusCode::NOT_FOUND, "unknown user").into_response();
    };
    let ak = home.join(".ssh/authorized_keys");
    let Ok(current) = std::fs::read_to_string(&ak) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let target = req.key.trim();
    let kept: Vec<&str> = current.lines().filter(|l| l.trim() != target).collect();
    let mut body = kept.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    let _ = std::fs::write(&ak, body);
    st.emit(serde_json::json!({ "kind": "authorized", "op": "removed", "user": req.user }));
    StatusCode::NO_CONTENT.into_response()
}

/// Resolve a user's home dir via getent passwd (field 6).
fn home_of(user: &str) -> Option<PathBuf> {
    let u = sanitize_user(user);
    if u.is_empty() {
        return None;
    }
    let out = Command::new("getent").args(["passwd", &u]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8(out.stdout).ok()?;
    line.trim().split(':').nth(5).map(PathBuf::from)
}

/// Best-effort chown the .ssh dir + authorized_keys back to the user and lock
/// down perms (sshd refuses group/world-writable authorized_keys).
fn fix_ssh_ownership(user: &str, ssh_dir: &FsPath, ak: &FsPath) {
    let u = sanitize_user(user);
    let _ = Command::new("chown").args(["-R", &format!("{u}:")]).arg(ssh_dir).status();
    let _ = Command::new("chmod").arg("700").arg(ssh_dir).status();
    let _ = Command::new("chmod").arg("600").arg(ak).status();
}

/// Allow only filename-safe chars in a key name.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(64)
        .collect::<String>()
        .trim_matches('.')
        .to_string()
}

/// Allow only valid-ish unix usernames.
fn sanitize_user(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(32)
        .collect()
}

// ==========================================================================
// websocket
// ==========================================================================

async fn ws_handler(ws: WebSocketUpgrade, State(st): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| ws_stream(socket, st.events.subscribe()))
}

async fn ws_stream(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    loop {
        match rx.recv().await {
            Ok(msg) => {
                if socket.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}
