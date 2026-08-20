//! ESO backend — hosting walt's vault tree as a remote secret store for the
//! Kubernetes [External Secrets Operator](https://external-secrets.io).
//!
//! ESO has no walt-native provider, so waltd speaks the one contract that lets
//! an arbitrary HTTP service act as a store: the **webhook provider**. ESO
//! `GET`s a templated URL, applies `result.jsonPath` to the JSON body, and
//! writes what falls out into a Kubernetes `Secret`. Everything here is
//! therefore read-only and shaped to be JSONPath-friendly:
//!
//!   GET /api/eso/{project}/{env}            all files in the env, merged
//!   GET /api/eso/{project}/{env}/{file}     one file
//!       ?property=KEY                       ...plus `value` for that one key
//!   GET /api/eso/manifest/{project}/{env}   generated SecretStore + ExternalSecret
//!
//! The three data routes answer `{"data": {KEY: VALUE, ...}}`, so a store uses
//! `jsonPath: "$.data"` with `dataFrom.extract` (whole file → whole Secret) or
//! `"$.data.KEY"` / `"$.value"` for a single entry. Values are plaintext: ESO
//! does the base64 when it builds the Secret.
//!
//! **These routes serve decrypted secrets, so they are off unless
//! `WALT_ESO_TOKEN` is set** (503 otherwise) and every request must carry
//! `Authorization: Bearer $WALT_ESO_TOKEN`. waltd speaks plain HTTP — terminate
//! TLS in front of it, or keep the listener on a network only the cluster can
//! reach.

use std::collections::BTreeMap;
use std::path::Path as FsPath;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

use crate::{list_files_in, safe_file, safe_seg, vault, AppState};

/// Env var holding the bearer token ESO must present. Unset ⇒ backend disabled.
pub const TOKEN_VAR: &str = "WALT_ESO_TOKEN";

// ==========================================================================
// auth
// ==========================================================================

/// Fail closed: no configured token ⇒ 503; wrong/absent bearer ⇒ 401.
fn authorize(headers: &HeaderMap) -> Result<(), Response> {
    let Ok(expected) = std::env::var(TOKEN_VAR) else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("eso backend disabled: set {TOKEN_VAR} to enable it"),
        )
            .into_response());
    };
    if expected.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("eso backend disabled: {TOKEN_VAR} is empty"),
        )
            .into_response());
    }
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if ct_eq(presented.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "invalid or missing bearer token").into_response())
    }
}

/// Length-revealing but content-constant-time comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// ==========================================================================
// handlers
// ==========================================================================

#[derive(Deserialize)]
pub struct PropertyQuery {
    /// A single key within the file — ESO's `remoteRef.property`.
    #[serde(default)]
    property: Option<String>,
}

/// Every file in an environment, merged into one flat map. Later files win on
/// a key collision; `sources` reports which file each key came from so a clash
/// is visible rather than silent.
pub async fn get_env(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((project, env)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = authorize(&headers) {
        return resp;
    }
    let (Some(project), Some(env)) = (safe_seg(&project), safe_seg(&env)) else {
        return (StatusCode::BAD_REQUEST, "invalid path").into_response();
    };
    let env_dir = st.env_dir(&project, &env);
    if !env_dir.is_dir() {
        return (StatusCode::NOT_FOUND, "unknown environment").into_response();
    }

    let mut data: BTreeMap<String, String> = BTreeMap::new();
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    for info in list_files_in(&env_dir) {
        let plaintext = match read_plaintext(&env_dir, &env, &info.name) {
            Ok(text) => text,
            Err(resp) => return resp,
        };
        for (k, v) in entries_of(&info.name, &plaintext) {
            sources.insert(k.clone(), info.name.clone());
            data.insert(k, v);
        }
    }
    Json(serde_json::json!({
        "project": project, "env": env, "data": data, "sources": sources
    }))
    .into_response()
}

/// One file's entries. With `?property=KEY`, `value` carries just that key so a
/// store can use `jsonPath: "$.value"` for single-key `remoteRef`s.
pub async fn get_file(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((project, env, file)): Path<(String, String, String)>,
    Query(q): Query<PropertyQuery>,
) -> Response {
    if let Err(resp) = authorize(&headers) {
        return resp;
    }
    let (Some(project), Some(env), Some(file)) =
        (safe_seg(&project), safe_seg(&env), safe_file(&file))
    else {
        return (StatusCode::BAD_REQUEST, "invalid path").into_response();
    };
    let env_dir = st.env_dir(&project, &env);
    if !env_dir.join(&file).is_file() {
        return (StatusCode::NOT_FOUND, "no such file").into_response();
    }
    let plaintext = match read_plaintext(&env_dir, &env, &file) {
        Ok(text) => text,
        Err(resp) => return resp,
    };
    let data = entries_of(&file, &plaintext);

    let mut body = serde_json::json!({
        "project": project, "env": env, "file": file, "data": data
    });
    if let Some(prop) = q.property.filter(|p| !p.is_empty()) {
        let Some(value) = data.get(&prop) else {
            return (StatusCode::NOT_FOUND, format!("no such property: {prop}")).into_response();
        };
        body["value"] = serde_json::Value::String(value.clone());
    }
    Json(body).into_response()
}

#[derive(Deserialize)]
pub struct ManifestQuery {
    /// Namespace for the generated objects.
    #[serde(default)]
    namespace: Option<String>,
    /// Name of the Kubernetes Secret to materialize.
    #[serde(default)]
    secret: Option<String>,
    /// waltd base URL *as reachable from the cluster* (default: WALT_ESO_URL).
    #[serde(default)]
    url: Option<String>,
    /// Vault file to pull; omit to merge the whole environment.
    #[serde(default)]
    file: Option<String>,
    /// ESO API version — "v1" (default) or "v1beta1" for older operators.
    #[serde(default)]
    api_version: Option<String>,
    /// ESO resync interval.
    #[serde(default)]
    refresh_interval: Option<String>,
}

/// Emit a ready-to-apply `SecretStore` + `ExternalSecret` pair wired to this
/// daemon. Nothing here is persisted — it is a rendering of what the cluster
/// side needs, so the operator half of the setup is not hand-written YAML.
pub async fn get_manifest(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((project, env)): Path<(String, String)>,
    Query(q): Query<ManifestQuery>,
) -> Response {
    if let Err(resp) = authorize(&headers) {
        return resp;
    }
    let (Some(project), Some(env)) = (safe_seg(&project), safe_seg(&env)) else {
        return (StatusCode::BAD_REQUEST, "invalid path").into_response();
    };
    if !st.env_dir(&project, &env).is_dir() {
        return (StatusCode::NOT_FOUND, "unknown environment").into_response();
    }
    let file = match q.file.as_deref().map(safe_file) {
        Some(None) => return (StatusCode::BAD_REQUEST, "invalid file name").into_response(),
        Some(Some(f)) => Some(f),
        None => None,
    };

    let api_version = match q.api_version.as_deref() {
        None | Some("v1") => "external-secrets.io/v1",
        Some("v1beta1") => "external-secrets.io/v1beta1",
        Some(other) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("unsupported api_version '{other}' (want v1 or v1beta1)"),
            )
                .into_response()
        }
    };
    let namespace = k8s_name(q.namespace.as_deref().unwrap_or("default"));
    let store = k8s_name(&format!("walt-{project}-{env}"));
    let secret = k8s_name(
        &q.secret
            .unwrap_or_else(|| format!("{project}-{env}")),
    );
    let refresh = q.refresh_interval.as_deref().unwrap_or("1h");
    let base = q
        .url
        .or_else(|| std::env::var("WALT_ESO_URL").ok())
        .unwrap_or_else(|| "http://waltd.walt.svc.cluster.local:8470".into());
    let base = base.trim_end_matches('/');

    // The webhook URL is templated per remoteRef when pulling a named file, and
    // fixed at the env when merging — ESO substitutes `{{ .remoteRef.key }}`.
    let (url, pull) = match &file {
        Some(f) => (
            format!("{base}/api/eso/{project}/{env}/{{{{ .remoteRef.key }}}}"),
            format!("  dataFrom:\n    - extract:\n        key: {f}\n"),
        ),
        None => (
            // No template: this store always returns the whole environment, so
            // `key` below is only a label — ESO requires one, waltd ignores it.
            format!("{base}/api/eso/{project}/{env}"),
            format!("  dataFrom:\n    - extract:\n        key: {project}/{env}\n"),
        ),
    };

    let yaml = format!(
        "# Generated by waltd for vault {project}/{env}.\n\
         #\n\
         # 1. Create the token Secret ESO uses to authenticate to waltd:\n\
         #      kubectl -n {namespace} create secret generic walt-eso-token \\\n\
         #        --from-literal=token=\"$WALT_ESO_TOKEN\"\n\
         # 2. kubectl apply -f this-file\n\
         ---\n\
         apiVersion: {api_version}\n\
         kind: SecretStore\n\
         metadata:\n\
         \x20 name: {store}\n\
         \x20 namespace: {namespace}\n\
         spec:\n\
         \x20 provider:\n\
         \x20   webhook:\n\
         \x20     url: \"{url}\"\n\
         \x20     headers:\n\
         \x20       Authorization: \"Bearer {{{{ .waltToken }}}}\"\n\
         \x20     secrets:\n\
         \x20       - name: waltToken\n\
         \x20         secretRef:\n\
         \x20           name: walt-eso-token\n\
         \x20           key: token\n\
         \x20     result:\n\
         \x20       jsonPath: \"$.data\"\n\
         ---\n\
         apiVersion: {api_version}\n\
         kind: ExternalSecret\n\
         metadata:\n\
         \x20 name: {secret}\n\
         \x20 namespace: {namespace}\n\
         spec:\n\
         \x20 refreshInterval: {refresh}\n\
         \x20 secretStoreRef:\n\
         \x20   name: {store}\n\
         \x20   kind: SecretStore\n\
         \x20 target:\n\
         \x20   name: {secret}\n\
         \x20   creationPolicy: Owner\n\
         {pull}"
    );

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/yaml")],
        yaml,
    )
        .into_response()
}

// ==========================================================================
// vault → Secret data
// ==========================================================================

/// Read a vault file, decrypting with the env password when it is encrypted.
fn read_plaintext(env_dir: &FsPath, env: &str, file: &str) -> Result<String, Response> {
    let path = env_dir.join(file);
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| (StatusCode::NOT_FOUND, format!("read {file}: {e}")).into_response())?;
    if !vault::is_encrypted(&raw) {
        return Ok(raw);
    }
    let pw = vault::env_password(env_dir, env)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e).into_response())?;
    let bytes = vault::decrypt(&raw, &pw)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e).into_response())?;
    String::from_utf8(bytes)
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, format!("{file} is not UTF-8")).into_response())
}

/// Turn a decrypted file into Secret entries.
///
/// A YAML mapping becomes one entry per leaf, nested keys joined with `.`
/// (`db.password` → `db.password`) and non-scalar leaves JSON-encoded, since a
/// Secret value is just bytes. Anything that is not a mapping — a PEM key, a
/// kubeconfig, a plain blob — becomes a single entry keyed by the file name.
fn entries_of(file: &str, plaintext: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match serde_norway::from_str::<serde_norway::Value>(plaintext) {
        Ok(serde_norway::Value::Mapping(map)) => {
            flatten(&serde_norway::Value::Mapping(map), "", &mut out);
        }
        _ => {
            out.insert(k8s_key(file), plaintext.to_string());
        }
    }
    out
}

fn flatten(value: &serde_norway::Value, prefix: &str, out: &mut BTreeMap<String, String>) {
    use serde_norway::Value;
    match value {
        Value::Mapping(map) => {
            for (k, v) in map {
                let key = scalar(k).unwrap_or_else(|| "?".into());
                let path = if prefix.is_empty() {
                    key
                } else {
                    format!("{prefix}.{key}")
                };
                match v {
                    Value::Mapping(_) => flatten(v, &path, out),
                    _ => {
                        out.insert(k8s_key(&path), scalar(v).unwrap_or_else(|| json_of(v)));
                    }
                }
            }
        }
        other => {
            out.insert(k8s_key(prefix), scalar(other).unwrap_or_else(|| json_of(other)));
        }
    }
}

/// Render a YAML scalar the way a Secret consumer expects: the string itself,
/// numbers/bools unquoted, null as empty. Non-scalars return None.
fn scalar(v: &serde_norway::Value) -> Option<String> {
    use serde_norway::Value;
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some(String::new()),
        _ => None,
    }
}

/// Sequences and tagged nodes have no flat text form — JSON keeps them lossless.
fn json_of(v: &serde_norway::Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// Kubernetes Secret keys allow only `[-._a-zA-Z0-9]`; anything else becomes `_`.
fn k8s_key(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "_".into()
    } else {
        cleaned
    }
}

/// RFC 1123 subdomain-ish: lowercase alphanumerics and `-`, trimmed.
fn k8s_name(s: &str) -> String {
    let cleaned: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    let mut name: String = trimmed.chars().take(253).collect();
    if name.is_empty() {
        name.push_str("walt");
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_yaml_becomes_one_entry_per_key() {
        let e = entries_of("secrets.yml", "db_user: admin\ndb_pass: s3cret\nport: 5432\n");
        assert_eq!(e["db_user"], "admin");
        assert_eq!(e["db_pass"], "s3cret");
        assert_eq!(e["port"], "5432");
    }

    #[test]
    fn nested_keys_join_with_a_dot() {
        let e = entries_of("secrets.yml", "db:\n  user: admin\n  pass: s3cret\n");
        assert_eq!(e["db.user"], "admin");
        assert_eq!(e["db.pass"], "s3cret");
    }

    #[test]
    fn sequences_and_odd_keys_survive() {
        let e = entries_of("s.yml", "hosts:\n  - a\n  - b\nweird key: v\n");
        assert_eq!(e["hosts"], r#"["a","b"]"#);
        assert_eq!(e["weird_key"], "v");
    }

    #[test]
    fn non_mapping_files_key_off_the_file_name() {
        let pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n";
        let e = entries_of("id_ed25519.pem", pem);
        assert_eq!(e["id_ed25519.pem"], pem);
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn empty_and_null_values_are_empty_strings() {
        let e = entries_of("s.yml", "a:\nb: \"\"\n");
        assert_eq!(e["a"], "");
        assert_eq!(e["b"], "");
    }

    #[test]
    fn names_are_sanitized_for_kubernetes() {
        assert_eq!(k8s_name("Walt_Proj/Prod"), "walt-proj-prod");
        assert_eq!(k8s_key("db/pass word"), "db_pass_word");
    }

    #[test]
    fn bearer_comparison_rejects_mismatches() {
        assert!(ct_eq(b"token", b"token"));
        assert!(!ct_eq(b"token", b"toke"));
        assert!(!ct_eq(b"token", b"tokeN"));
        assert!(!ct_eq(b"", b"token"));
    }
}
