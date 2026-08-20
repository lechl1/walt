//! walt — CLI for the walt daemon (waltd). Mirrors the daemon's openapi.yaml
//! surface: an Ansible-Vault file manager (projects/environments/files) plus
//! local SSH-key management (keypairs, host keys, authorized_keys — merged in
//! from the former `arthur` CLI), plus the ESO backend that hosts a vault
//! environment for the Kubernetes External Secrets Operator. Talks to waltd
//! over HTTP (WALT_URL, default http://127.0.0.1:8470).

use std::io::Read;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "walt", about = "walt — ansible-vault + ssh-key manager (waltd client)")]
struct Cli {
    /// Daemon base URL. Overrides WALT_URL.
    #[arg(long, env = "WALT_URL", default_value = "http://127.0.0.1:8470")]
    url: String,
    /// Bearer token for the eso routes — must match waltd's WALT_ESO_TOKEN.
    #[arg(long, env = "WALT_ESO_TOKEN")]
    eso_token: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    // --- vault ---
    /// List vault projects and their environments.
    Projects,
    /// Initialize a project with the given environments.
    Init {
        name: String,
        /// Environments, comma-separated.
        #[arg(long, default_value = "dev,test,prod")]
        env: String,
    },
    /// List a project's environments.
    Envs { project: String },
    /// Create an environment in a project.
    EnvAdd { project: String, name: String },
    /// List files in an environment.
    Files { project: String, env: String },
    /// Add a new file from stdin (encrypted on write).
    Add { project: String, env: String, file: String },
    /// Print a file's decrypted contents to stdout.
    Cat { project: String, env: String, file: String },
    /// Replace a file's contents from stdin (re-encrypted on write).
    Put { project: String, env: String, file: String },
    /// Delete a file.
    Rm { project: String, env: String, file: String },
    /// Encrypt every file in an environment.
    Encrypt { project: String, env: String },
    /// Decrypt every file in an environment.
    Decrypt { project: String, env: String },

    // --- ssh keys (merged from arthur) ---
    /// Manage walt-held SSH keypairs.
    #[command(subcommand)]
    Keys(KeyCmd),
    /// Manage a user's authorized_keys.
    #[command(subcommand)]
    Authorized(AuthCmd),
    /// List SSH keys already present on the host (not walt-managed).
    HostKeys,

    // --- kubernetes (external secrets operator) ---
    /// Inspect what waltd serves to the External Secrets Operator.
    #[command(subcommand)]
    Eso(EsoCmd),
}

#[derive(Subcommand)]
enum EsoCmd {
    /// Print the Secret entries ESO would pull (KEY=VALUE per line).
    Get {
        project: String,
        env: String,
        /// One vault file; omit to merge every file in the environment.
        #[arg(long)]
        file: Option<String>,
    },
    /// Print a SecretStore + ExternalSecret manifest wired to this daemon.
    Manifest {
        project: String,
        env: String,
        /// Vault file to pull; omit to merge the whole environment.
        #[arg(long)]
        file: Option<String>,
        /// Namespace for the generated objects.
        #[arg(long, default_value = "default")]
        namespace: String,
        /// Name of the Kubernetes Secret to materialize.
        #[arg(long)]
        secret: Option<String>,
        /// waltd base URL as reachable from the cluster.
        #[arg(long)]
        cluster_url: Option<String>,
        /// ESO API version: v1 or v1beta1.
        #[arg(long, default_value = "v1")]
        api_version: String,
        /// ESO resync interval.
        #[arg(long, default_value = "1h")]
        refresh_interval: String,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// List managed keypairs.
    List,
    /// Generate a keypair.
    Gen {
        name: String,
        #[arg(long, default_value = "ed25519")]
        r#type: String,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Delete a keypair by id (its name).
    Rm { id: String },
}

#[derive(Subcommand)]
enum AuthCmd {
    /// List a user's authorized_keys.
    List { user: String },
    /// Add a public key to a user's authorized_keys.
    Add { user: String, key: String },
    /// Remove a public key from a user's authorized_keys.
    Rm { user: String, key: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let base = cli.url.trim_end_matches('/').to_string();
    let http = reqwest::blocking::Client::new();
    let envp = |p: &str, e: &str| format!("{base}/api/projects/{p}/envs/{e}");

    match cli.cmd {
        // ---- vault ----
        Cmd::Projects => {
            let v: serde_json::Value = http.get(format!("{base}/api/projects")).send()?.json()?;
            for p in v["projects"].as_array().cloned().unwrap_or_default() {
                let envs: Vec<&str> = p["environments"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|e| e.as_str()).collect())
                    .unwrap_or_default();
                println!("{:<24} {}", p["name"].as_str().unwrap_or(""), envs.join(", "));
            }
        }
        Cmd::Init { name, env } => {
            let environments: Vec<&str> = env.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
            let body = serde_json::json!({ "name": name, "environments": environments });
            let r = http.post(format!("{base}/api/projects")).json(&body).send()?;
            ensure_ok(r, "init project")?;
            println!("initialized project '{name}' ({})", environments.join(", "));
        }
        Cmd::Envs { project } => {
            let v: serde_json::Value =
                http.get(format!("{base}/api/projects/{project}/envs")).send()?.json()?;
            for e in v["environments"].as_array().cloned().unwrap_or_default() {
                println!(
                    "{:<16} files={:<4} password={}",
                    e["name"].as_str().unwrap_or(""),
                    e["file_count"].as_u64().unwrap_or(0),
                    e["has_password"].as_bool().unwrap_or(false)
                );
            }
        }
        Cmd::EnvAdd { project, name } => {
            let body = serde_json::json!({ "name": name });
            let r = http.post(format!("{base}/api/projects/{project}/envs")).json(&body).send()?;
            ensure_ok(r, "create environment")?;
            println!("created environment '{name}' in '{project}'");
        }
        Cmd::Files { project, env } => {
            let v: serde_json::Value = http.get(format!("{}/files", envp(&project, &env))).send()?.json()?;
            for f in v["files"].as_array().cloned().unwrap_or_default() {
                println!(
                    "{:<32} {:<10} {}",
                    f["name"].as_str().unwrap_or(""),
                    if f["encrypted"].as_bool().unwrap_or(false) { "encrypted" } else { "plaintext" },
                    f["size"].as_u64().unwrap_or(0)
                );
            }
        }
        Cmd::Add { project, env, file } => {
            let content = read_stdin()?;
            let body = serde_json::json!({ "name": file, "content": content });
            let r = http.post(format!("{}/files", envp(&project, &env))).json(&body).send()?;
            ensure_ok(r, "add file")?;
            println!("added & encrypted '{file}'");
        }
        Cmd::Cat { project, env, file } => {
            let r = http.get(format!("{}/files/{file}", envp(&project, &env))).send()?;
            let r = ensure_body(r, "read file")?;
            let v: serde_json::Value = serde_json::from_str(&r)?;
            print!("{}", v["content"].as_str().unwrap_or(""));
        }
        Cmd::Put { project, env, file } => {
            let content = read_stdin()?;
            let body = serde_json::json!({ "content": content });
            let r = http.put(format!("{}/files/{file}", envp(&project, &env))).json(&body).send()?;
            ensure_ok(r, "put file")?;
            println!("saved & encrypted '{file}'");
        }
        Cmd::Rm { project, env, file } => {
            let r = http.delete(format!("{}/files/{file}", envp(&project, &env))).send()?;
            ensure_ok(r, "delete file")?;
            println!("deleted '{file}'");
        }
        Cmd::Encrypt { project, env } => {
            let r = http.post(format!("{}/encrypt", envp(&project, &env))).json(&serde_json::json!({})).send()?;
            ensure_ok(r, "encrypt")?;
            println!("encrypted all files in '{project}/{env}'");
        }
        Cmd::Decrypt { project, env } => {
            let r = http.post(format!("{}/decrypt", envp(&project, &env))).json(&serde_json::json!({})).send()?;
            ensure_ok(r, "decrypt")?;
            println!("decrypted all files in '{project}/{env}'");
        }

        // ---- ssh keys ----
        Cmd::Keys(KeyCmd::List) => {
            let v: serde_json::Value = http.get(format!("{base}/api/keys")).send()?.json()?;
            for k in v["keys"].as_array().cloned().unwrap_or_default() {
                println!(
                    "{:<24} {:<10} {:<50} {}",
                    k["id"].as_str().unwrap_or(""),
                    k["type"].as_str().unwrap_or(""),
                    k["fingerprint"].as_str().unwrap_or(""),
                    k["comment"].as_str().unwrap_or("")
                );
            }
        }
        Cmd::Keys(KeyCmd::Gen { name, r#type, comment }) => {
            let body = serde_json::json!({ "name": name, "type": r#type, "comment": comment });
            let r = http.post(format!("{base}/api/keys")).json(&body).send()?;
            ensure_ok(r, "generate key")?;
            println!("generated key '{name}'");
        }
        Cmd::Keys(KeyCmd::Rm { id }) => {
            let r = http.delete(format!("{base}/api/keys/{id}")).send()?;
            ensure_ok(r, "delete key")?;
            println!("deleted key '{id}'");
        }
        Cmd::Authorized(AuthCmd::List { user }) => {
            let v: serde_json::Value = http
                .get(format!("{base}/api/authorized"))
                .query(&[("user", &user)])
                .send()?
                .json()?;
            for k in v["keys"].as_array().cloned().unwrap_or_default() {
                println!("{}", k.as_str().unwrap_or(""));
            }
        }
        Cmd::Authorized(AuthCmd::Add { user, key }) => {
            let body = serde_json::json!({ "user": user, "key": key });
            let r = http.post(format!("{base}/api/authorized")).json(&body).send()?;
            ensure_ok(r, "add authorized key")?;
            println!("added key for '{user}'");
        }
        Cmd::Authorized(AuthCmd::Rm { user, key }) => {
            let body = serde_json::json!({ "user": user, "key": key });
            let r = http
                .request(reqwest::Method::DELETE, format!("{base}/api/authorized"))
                .json(&body)
                .send()?;
            ensure_ok(r, "remove authorized key")?;
            println!("removed key for '{user}'");
        }
        Cmd::Eso(EsoCmd::Get { project, env, file }) => {
            let url = match &file {
                Some(f) => format!("{base}/api/eso/{project}/{env}/{f}"),
                None => format!("{base}/api/eso/{project}/{env}"),
            };
            let r = eso_auth(http.get(url), &cli.eso_token).send()?;
            let v: serde_json::Value = serde_json::from_str(&ensure_body(r, "eso get")?)?;
            for (k, val) in v["data"].as_object().cloned().unwrap_or_default() {
                println!("{k}={}", val.as_str().unwrap_or(""));
            }
        }
        Cmd::Eso(EsoCmd::Manifest {
            project, env, file, namespace, secret, cluster_url, api_version, refresh_interval,
        }) => {
            let mut q: Vec<(&str, String)> = vec![
                ("namespace", namespace),
                ("api_version", api_version),
                ("refresh_interval", refresh_interval),
            ];
            if let Some(f) = file {
                q.push(("file", f));
            }
            if let Some(s) = secret {
                q.push(("secret", s));
            }
            if let Some(u) = cluster_url {
                q.push(("url", u));
            }
            let req = http.get(format!("{base}/api/eso/manifest/{project}/{env}")).query(&q);
            let r = eso_auth(req, &cli.eso_token).send()?;
            print!("{}", ensure_body(r, "eso manifest")?);
        }
        Cmd::HostKeys => {
            let v: serde_json::Value = http.get(format!("{base}/api/host-keys")).send()?.json()?;
            for k in v["keys"].as_array().cloned().unwrap_or_default() {
                println!(
                    "{:<6} {:<16} {:<10} {:<50} {}",
                    k["scope"].as_str().unwrap_or(""),
                    k["owner"].as_str().unwrap_or(""),
                    k["type"].as_str().unwrap_or(""),
                    k["fingerprint"].as_str().unwrap_or(""),
                    k["path"].as_str().unwrap_or("")
                );
            }
        }
    }
    Ok(())
}

/// The eso routes are bearer-authenticated; waltd 401s without this header.
fn eso_auth(
    req: reqwest::blocking::RequestBuilder,
    token: &Option<String>,
) -> reqwest::blocking::RequestBuilder {
    match token {
        Some(t) => req.bearer_auth(t),
        None => req,
    }
}

fn read_stdin() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).context("read stdin")?;
    Ok(buf)
}

fn ensure_ok(r: reqwest::blocking::Response, what: &str) -> Result<()> {
    let status = r.status();
    if status.is_success() {
        return Ok(());
    }
    let body = r.text().context("read error body")?;
    bail!("{what} failed: {status} {body}");
}

fn ensure_body(r: reqwest::blocking::Response, what: &str) -> Result<String> {
    let status = r.status();
    let body = r.text().context("read body")?;
    if status.is_success() {
        Ok(body)
    } else {
        bail!("{what} failed: {status} {body}")
    }
}
