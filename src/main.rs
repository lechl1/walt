use aes::Aes256;
use clap::{Parser, Subcommand};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;
use zeroize::Zeroizing;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const VAULT_HEADER: &str = "$ANSIBLE_VAULT;1.1;AES256";
const PBKDF2_ITERATIONS: u32 = 10000;
const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;
const SALT_LENGTH: usize = 32;

#[derive(Parser)]
#[command(name = "walt", about = "Ansible Vault compatible encrypt/decrypt tool")]
struct Cli {
    /// Vault name (uses .vault/<name>/)
    #[arg(short = 'n', long = "name", global = true)]
    name: Option<String>,
    /// Environment (uses .vault/<name>/<env>/)
    #[arg(short = 'e', long = "env", global = true)]
    env: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file (or all vault files recursively if no file given)
    Encrypt {
        /// File path (or filename to search recursively)
        file: Option<String>,
        /// Fail if the file is already encrypted
        #[arg(long)]
        strict: bool,
    },
    /// Decrypt a file (or all vault files recursively if no file given)
    Decrypt {
        /// File path (or filename to search recursively)
        file: Option<String>,
        /// Fail if the file is already decrypted
        #[arg(long)]
        strict: bool,
    },
    /// Decrypt, open in $EDITOR, re-encrypt on save
    Edit {
        /// File paths (or filenames to search recursively)
        files: Vec<String>,
    },
    /// Manage vault password encryption
    Password {
        #[command(subcommand)]
        action: PasswordAction,
    },
}

#[derive(Subcommand)]
enum PasswordAction {
    /// Encrypt the .vault-password file with a master password
    Encrypt,
    /// Print the decrypted vault password to stdout
    Decrypt,
}

fn main() {
    let cli = Cli::parse();
    install_pre_commit_hook();

    match cli.command {
        Commands::Password { action } => {
            handle_password_command(&cli.name, &cli.env, action);
        }
        Commands::Encrypt { file, strict } => match file {
            Some(f) => {
                let password = load_password(&cli.name, &cli.env);
                let path = resolve_file(&f, &cli.name, &cli.env);
                if path.is_dir() {
                    encrypt_dir(&path, &password);
                } else {
                    encrypt_file(&path, &password, strict);
                    println!("Encrypted {}", path.display());
                }
            }
            None => encrypt_all(&cli.name, &cli.env),
        },
        Commands::Decrypt { file, strict } => match file {
            Some(f) => {
                let password = load_password(&cli.name, &cli.env);
                let path = resolve_file(&f, &cli.name, &cli.env);
                if path.is_dir() {
                    decrypt_dir(&path, &password);
                } else {
                    decrypt_file(&path, &password, strict);
                    println!("Decrypted {}", path.display());
                }
            }
            None => decrypt_all(&cli.name, &cli.env),
        },
        Commands::Edit { files } => {
            let password = load_password(&cli.name, &cli.env);
            let paths: Vec<PathBuf> = if files.is_empty() {
                let vault_dir = find_vault_dir(&cli.name, &cli.env).unwrap_or_else(|| {
                    eprintln!("Error: no vault directory found");
                    std::process::exit(1);
                });
                WalkDir::new(&vault_dir)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file() && !is_vault_password_file(e.path()))
                    .map(|e| e.into_path())
                    .collect()
            } else {
                files
                    .iter()
                    .map(|f| resolve_file(f, &cli.name, &cli.env))
                    .collect()
            };
            if paths.is_empty() {
                println!("No files to edit.");
                return;
            }
            if paths.len() == 1 {
                edit_file(&paths[0], &password);
            } else {
                edit_files(&paths, &password);
            }
        }
    }
}

fn load_password(name: &Option<String>, env: &Option<String>) -> Zeroizing<String> {
    find_vault_password(name, env).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    })
}

// --- Password commands ---

fn handle_password_command(
    name: &Option<String>,
    env: &Option<String>,
    action: PasswordAction,
) {
    let password_path = find_vault_password_path(name, env);

    match action {
        PasswordAction::Encrypt => {
            let content = fs::read_to_string(&password_path).unwrap_or_else(|e| {
                eprintln!("Error reading {}: {}", password_path.display(), e);
                std::process::exit(1);
            });
            if content.starts_with(VAULT_HEADER) {
                eprintln!("Error: {} is already encrypted", password_path.display());
                std::process::exit(1);
            }
            let master_password = Zeroizing::new(
                rpassword::prompt_password("Enter master password: ").unwrap_or_else(|e| {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }),
            );
            let master_confirm = Zeroizing::new(
                rpassword::prompt_password("Confirm master password: ").unwrap_or_else(|e| {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }),
            );
            if *master_password != *master_confirm {
                eprintln!("Error: passwords do not match");
                std::process::exit(1);
            }
            let encrypted = vault_encrypt(content.trim().as_bytes(), &master_password);
            fs::write(&password_path, &encrypted).unwrap_or_else(|e| {
                eprintln!("Error writing {}: {}", password_path.display(), e);
                std::process::exit(1);
            });
            println!("Encrypted {}", password_path.display());
        }
        PasswordAction::Decrypt => {
            let content = fs::read_to_string(&password_path).unwrap_or_else(|e| {
                eprintln!("Error reading {}: {}", password_path.display(), e);
                std::process::exit(1);
            });
            if !content.starts_with(VAULT_HEADER) {
                print!("{}", content.trim());
                return;
            }
            let master_password = Zeroizing::new(
                rpassword::prompt_password("Enter master password: ").unwrap_or_else(|e| {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }),
            );
            let decrypted_bytes = vault_decrypt(&content, &master_password);
            let vault_password = String::from_utf8(decrypted_bytes).unwrap_or_else(|_| {
                eprintln!("Error: decrypted password is not valid UTF-8");
                std::process::exit(1);
            });
            print!("{}", vault_password.trim());
        }
    }
}

fn find_vault_password_path(name: &Option<String>, env: &Option<String>) -> PathBuf {
    if let Some(vault_dir) = find_vault_dir(name, env) {
        let path = vault_dir.join(".vault-password");
        if path.is_file() {
            return path;
        }
    }
    if let Ok(mut dir) = std::env::current_dir() {
        loop {
            let candidate = dir.join(".vault").join(".vault-password");
            if candidate.is_file() {
                return candidate;
            }
            let candidate = dir.join(".vault-password");
            if candidate.is_file() {
                return candidate;
            }
            if !dir.pop() {
                break;
            }
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let candidate = PathBuf::from(home).join(".vault-password");
        if candidate.is_file() {
            return candidate;
        }
    }
    eprintln!("Error: no .vault-password file found");
    std::process::exit(1);
}

// --- Password discovery ---

fn read_and_maybe_decrypt_password(path: &Path) -> Result<Zeroizing<String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    if content.trim().is_empty() {
        return Err(format!("Password file is empty: {}", path.display()));
    }

    if content.starts_with(VAULT_HEADER) {
        let master_password = Zeroizing::new(
            rpassword::prompt_password(format!(
                "Enter master password for {}: ",
                path.display()
            ))
            .map_err(|e| format!("Failed to read password: {}", e))?,
        );
        let decrypted_bytes = vault_decrypt(&content, &master_password);
        let vault_password = String::from_utf8(decrypted_bytes)
            .map_err(|_| "Decrypted password is not valid UTF-8".to_string())?;
        let trimmed = vault_password.trim().to_string();
        if trimmed.is_empty() {
            return Err("Decrypted password is empty".to_string());
        }
        Ok(Zeroizing::new(trimmed))
    } else {
        Ok(Zeroizing::new(content.trim().to_string()))
    }
}

fn find_vault_password(
    name: &Option<String>,
    env: &Option<String>,
) -> Result<Zeroizing<String>, String> {
    // Named vault: look in the specific vault directory
    if name.is_some() || env.is_some() {
        let vault_dir = find_vault_dir(name, env).ok_or_else(|| {
            format!(
                "Vault directory not found for name={:?} env={:?}",
                name, env
            )
        })?;
        let password_path = vault_dir.join(".vault-password");
        if password_path.is_file() {
            return read_and_maybe_decrypt_password(&password_path);
        }
        return Err(format!(
            "No .vault-password found at {}",
            password_path.display()
        ));
    }

    // Legacy: walk up directories
    let mut dir = std::env::current_dir().map_err(|e| e.to_string())?;
    loop {
        let vault_password_path = dir.join(".vault").join(".vault-password");
        if vault_password_path.is_file() {
            return read_and_maybe_decrypt_password(&vault_password_path);
        }
        let candidate = dir.join(".vault-password");
        if candidate.is_file() {
            return read_and_maybe_decrypt_password(&candidate);
        }
        if !dir.pop() {
            break;
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        let candidate = PathBuf::from(home).join(".vault-password");
        if candidate.is_file() {
            return read_and_maybe_decrypt_password(&candidate);
        }
    }

    Err("No .vault-password file found in current/parent directories or $HOME".to_string())
}

// --- Vault directory discovery ---

fn find_vault_dir(name: &Option<String>, env: &Option<String>) -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let mut candidate = dir.join(".vault");
        if candidate.is_dir() {
            if let Some(n) = name {
                candidate = candidate.join(n);
            }
            if let Some(e) = env {
                candidate = candidate.join(e);
            }
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

// --- File resolution ---

fn resolve_file(name: &str, vault_name: &Option<String>, vault_env: &Option<String>) -> PathBuf {
    let path = PathBuf::from(name);
    if path.exists() {
        return path;
    }
    if let Some(vault_dir) = find_vault_dir(vault_name, vault_env) {
        let vault_path = vault_dir.join(name);
        if vault_path.exists() {
            return vault_path;
        }
    }
    if name.contains('/') || name.contains('\\') {
        eprintln!("Error: {} not found", name);
        std::process::exit(1);
    }
    for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Some(fname) = entry.path().file_name() {
                if fname == name.as_ref() as &std::ffi::OsStr {
                    return entry.into_path();
                }
            }
        }
    }
    eprintln!("Error: {} not found recursively", name);
    std::process::exit(1);
}

// --- Encrypt / Decrypt directory ---

fn encrypt_dir(dir: &Path, password: &str) {
    let mut count = 0;
    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if is_vault_password_file(path) {
            continue;
        }
        if let Ok(content) = fs::read_to_string(path) {
            if content.starts_with(VAULT_HEADER) {
                continue;
            }
        }
        if is_binary_file(path) {
            continue;
        }
        encrypt_file(path, password, false);
        println!("Encrypted {}", path.display());
        count += 1;
    }
    println!("Encrypted {} files in {}", count, dir.display());
}

fn decrypt_dir(dir: &Path, password: &str) {
    let mut count = 0;
    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if is_vault_password_file(path) {
            continue;
        }
        if let Ok(content) = fs::read_to_string(path) {
            if content.starts_with(VAULT_HEADER) {
                decrypt_file(path, password, false);
                println!("Decrypted {}", path.display());
                count += 1;
            }
        }
    }
    println!("Decrypted {} files in {}", count, dir.display());
}

// --- Encrypt / Decrypt all ---

fn encrypt_all(name: &Option<String>, env: &Option<String>) {
    if name.is_some() || env.is_some() {
        let vault_dir = find_vault_dir(name, env).unwrap_or_else(|| {
            eprintln!("Error: vault directory not found");
            std::process::exit(1);
        });
        let password = load_password(name, env);
        encrypt_dir(&vault_dir, &password);
        return;
    }

    // Auto mode: find .vault/ root and discover named vaults by .vault-password files
    let vault_root = find_vault_dir(&None, &None).unwrap_or_else(|| {
        eprintln!("Error: no .vault directory found");
        std::process::exit(1);
    });

    let mut named_vault_dirs: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(&vault_root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() && is_vault_password_file(entry.path()) {
            if let Some(parent) = entry.path().parent() {
                if parent != vault_root {
                    named_vault_dirs.push(parent.to_path_buf());
                }
            }
        }
    }

    if named_vault_dirs.is_empty() {
        // Legacy flat vault
        let password = find_vault_password(&None, &None).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });
        encrypt_dir(&vault_root, &password);
    } else {
        for vault_dir in &named_vault_dirs {
            let password_path = vault_dir.join(".vault-password");
            match read_and_maybe_decrypt_password(&password_path) {
                Ok(password) => encrypt_dir(vault_dir, &password),
                Err(e) => eprintln!("Warning: skipping {}: {}", vault_dir.display(), e),
            }
        }
    }
}

fn decrypt_all(name: &Option<String>, env: &Option<String>) {
    if name.is_some() || env.is_some() {
        let vault_dir = find_vault_dir(name, env).unwrap_or_else(|| {
            eprintln!("Error: vault directory not found");
            std::process::exit(1);
        });
        let password = load_password(name, env);
        decrypt_dir(&vault_dir, &password);
        return;
    }

    let vault_root = find_vault_dir(&None, &None).unwrap_or_else(|| {
        eprintln!("Error: no .vault directory found");
        std::process::exit(1);
    });

    let mut named_vault_dirs: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(&vault_root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() && is_vault_password_file(entry.path()) {
            if let Some(parent) = entry.path().parent() {
                if parent != vault_root {
                    named_vault_dirs.push(parent.to_path_buf());
                }
            }
        }
    }

    if named_vault_dirs.is_empty() {
        let password = find_vault_password(&None, &None).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });
        decrypt_dir(&vault_root, &password);
    } else {
        for vault_dir in &named_vault_dirs {
            let password_path = vault_dir.join(".vault-password");
            match read_and_maybe_decrypt_password(&password_path) {
                Ok(password) => decrypt_dir(vault_dir, &password),
                Err(e) => eprintln!("Warning: skipping {}: {}", vault_dir.display(), e),
            }
        }
    }
}

// --- Pre-commit hook installation ---

const HOOK_MARKER: &str = "# walt pre-commit hook";
const HOOK_MARKER_LEGACY: &str = "# rv pre-commit hook";
const HOOK_SCRIPT: &str = r#"# walt pre-commit hook
# Re-encrypt .vault files and .env files (excluding local/dev) before committing
if command -v walt >/dev/null 2>&1; then
    walt encrypt
    # Encrypt .env files that don't have "local" or "dev" in the filename
    find . \( -name target -o -name node_modules -o -name build -o -name dist \) -prune -o \( -name '*.env' -o -name '.env' -o -name '.env.*' \) -print | while read -r f; do
        case "$(basename "$f")" in
            *local*|*dev*) continue ;;
        esac
        head -1 "$f" 2>/dev/null | grep -q '^\$ANSIBLE_VAULT' && continue
        walt encrypt "$f" 2>/dev/null && echo "Encrypted $f"
    done
    git add -u
fi
# end walt pre-commit hook"#;

fn install_pre_commit_hook() {
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output();
    let git_dir = match output {
        Ok(o) if o.status.success() => {
            PathBuf::from(String::from_utf8_lossy(&o.stdout).trim().to_string())
        }
        _ => return,
    };

    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir).ok();
    let hook_path = hooks_dir.join("pre-commit");

    if hook_path.exists() {
        let content = fs::read_to_string(&hook_path).unwrap_or_default();
        if content.contains(HOOK_SCRIPT) {
            return;
        }
        // Check for current or legacy marker
        let active_marker = if content.contains(HOOK_MARKER) {
            Some((HOOK_MARKER, "# end walt pre-commit hook"))
        } else if content.contains(HOOK_MARKER_LEGACY) {
            Some((HOOK_MARKER_LEGACY, "# end rv pre-commit hook"))
        } else {
            None
        };

        if let Some((marker, end_marker)) = active_marker {
            if let (Some(start), Some(end_pos)) =
                (content.find(marker), content.find(end_marker))
            {
                let before = &content[..start];
                let after = &content[end_pos + end_marker.len()..];
                let updated = format!(
                    "{}{}{}{}",
                    before.trim_end(),
                    if before.trim_end().is_empty() {
                        ""
                    } else {
                        "\n\n"
                    },
                    HOOK_SCRIPT,
                    after
                );
                fs::write(&hook_path, format!("{}\n", updated.trim_end())).unwrap_or_else(
                    |e| {
                        eprintln!("Error writing {}: {}", hook_path.display(), e);
                        std::process::exit(1);
                    },
                );
            }
            return;
        }
        // No marker present — append to existing hook.
        let updated = format!("{}\n\n{}\n", content.trim_end(), HOOK_SCRIPT);
        fs::write(&hook_path, updated).unwrap_or_else(|e| {
            eprintln!("Error writing {}: {}", hook_path.display(), e);
            std::process::exit(1);
        });
    } else {
        let content = format!("#!/bin/sh\n\n{}\n", HOOK_SCRIPT);
        fs::write(&hook_path, content).unwrap_or_else(|e| {
            eprintln!("Error writing {}: {}", hook_path.display(), e);
            std::process::exit(1);
        });
        println!("Created walt pre-commit hook at {}", hook_path.display());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms).ok();
    }

    ensure_gitignore_entry(&git_dir);
}

fn ensure_gitignore_entry(git_dir: &Path) {
    let repo_root = git_dir.parent().unwrap_or(Path::new("."));
    let gitignore_path = repo_root.join(".gitignore");
    let entry = ".vault-password";

    let content = fs::read_to_string(&gitignore_path).unwrap_or_default();
    if !content.lines().any(|l| l.trim() == entry) {
        let updated = if content.is_empty() || content.ends_with('\n') {
            format!("{}{}\n", content, entry)
        } else {
            format!("{}\n{}\n", content, entry)
        };
        fs::write(&gitignore_path, updated).ok();
    }

    // Unstage .vault-password files if staged.
    for pattern in &[entry, ".vault/.vault-password", ".vault/**/.vault-password"] {
        Command::new("git")
            .args(["rm", "--cached", "-rf", pattern])
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .ok();
    }
}

fn is_binary_file(path: &Path) -> bool {
    if let Ok(bytes) = fs::read(path) {
        let check_len = bytes.len().min(8192);
        bytes[..check_len].contains(&0)
    } else {
        false
    }
}

// --- Edit ---

fn edit_file(path: &Path, password: &str) {
    let content = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {}", path.display(), e);
        std::process::exit(1);
    });

    let was_encrypted = content.starts_with(VAULT_HEADER);
    let plaintext = if was_encrypted {
        vault_decrypt(&content, password)
    } else {
        content.into_bytes()
    };

    let tmp_path = path.with_extension("vault-edit.tmp");
    fs::write(&tmp_path, &plaintext).unwrap_or_else(|e| {
        eprintln!("Error writing temp file: {}", e);
        std::process::exit(1);
    });

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = Command::new(&editor)
        .arg(&tmp_path)
        .status()
        .unwrap_or_else(|e| {
            fs::remove_file(&tmp_path).ok();
            eprintln!("Error launching editor '{}': {}", editor, e);
            std::process::exit(1);
        });

    if !status.success() {
        fs::remove_file(&tmp_path).ok();
        eprintln!("Editor exited with error, file unchanged.");
        std::process::exit(1);
    }

    let edited = fs::read(&tmp_path).unwrap_or_else(|e| {
        eprintln!("Error reading edited file: {}", e);
        std::process::exit(1);
    });
    fs::remove_file(&tmp_path).ok();

    if edited == plaintext {
        println!("No changes made.");
        return;
    }

    let encrypted = vault_encrypt(&edited, password);
    fs::write(path, encrypted).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {}", path.display(), e);
        std::process::exit(1);
    });
    println!("Saved and encrypted {}", path.display());
}

const FILE_SEPARATOR_PREFIX: &str = "# ===== rs-vault: ";
const FILE_SEPARATOR_SUFFIX: &str = " =====";

fn edit_files(paths: &[PathBuf], password: &str) {
    let mut entries: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for path in paths {
        let content = fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("Error reading {}: {}", path.display(), e);
            std::process::exit(1);
        });
        let plaintext = if content.starts_with(VAULT_HEADER) {
            vault_decrypt(&content, password)
        } else {
            content.into_bytes()
        };
        entries.push((path.clone(), plaintext));
    }

    let mut combined = String::new();
    for (path, plaintext) in &entries {
        combined.push_str(FILE_SEPARATOR_PREFIX);
        combined.push_str(&path.display().to_string());
        combined.push_str(FILE_SEPARATOR_SUFFIX);
        combined.push('\n');
        combined.push_str(&String::from_utf8_lossy(plaintext));
        if !plaintext.ends_with(b"\n") {
            combined.push('\n');
        }
    }

    let tmp_path = std::env::temp_dir().join("rs-vault-multi-edit.tmp");
    fs::write(&tmp_path, &combined).unwrap_or_else(|e| {
        eprintln!("Error writing temp file: {}", e);
        std::process::exit(1);
    });

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = Command::new(&editor)
        .arg(&tmp_path)
        .status()
        .unwrap_or_else(|e| {
            fs::remove_file(&tmp_path).ok();
            eprintln!("Error launching editor '{}': {}", editor, e);
            std::process::exit(1);
        });

    if !status.success() {
        fs::remove_file(&tmp_path).ok();
        eprintln!("Editor exited with error, files unchanged.");
        std::process::exit(1);
    }

    let edited = fs::read_to_string(&tmp_path).unwrap_or_else(|e| {
        eprintln!("Error reading edited file: {}", e);
        std::process::exit(1);
    });
    fs::remove_file(&tmp_path).ok();

    let mut sections: Vec<(String, String)> = Vec::new();
    let mut current_path: Option<String> = None;
    let mut current_content = String::new();

    for line in edited.lines() {
        if line.starts_with(FILE_SEPARATOR_PREFIX) && line.ends_with(FILE_SEPARATOR_SUFFIX) {
            if let Some(p) = current_path.take() {
                sections.push((p, std::mem::take(&mut current_content)));
            }
            let path_str = &line
                [FILE_SEPARATOR_PREFIX.len()..line.len() - FILE_SEPARATOR_SUFFIX.len()];
            current_path = Some(path_str.to_string());
            current_content.clear();
        } else if current_path.is_some() {
            if !current_content.is_empty() {
                current_content.push('\n');
            }
            current_content.push_str(line);
        }
    }
    if let Some(p) = current_path {
        sections.push((p, current_content));
    }

    let original_map: std::collections::HashMap<String, &[u8]> = entries
        .iter()
        .map(|(p, c)| (p.display().to_string(), c.as_slice()))
        .collect();

    for (path_str, content) in &sections {
        let content_bytes = content.as_bytes();
        if let Some(original) = original_map.get(path_str) {
            if content_bytes == *original {
                println!("No changes: {}", path_str);
                continue;
            }
        }
        let encrypted = vault_encrypt(content_bytes, password);
        fs::write(path_str, encrypted).unwrap_or_else(|e| {
            eprintln!("Error writing {}: {}", path_str, e);
            std::process::exit(1);
        });
        println!("Saved and encrypted {}", path_str);
    }
}

// --- Encrypt file ---

fn is_vault_password_file(path: &Path) -> bool {
    path.file_name()
        .map(|f| f == ".vault-password")
        .unwrap_or(false)
}

fn encrypt_file(path: &Path, password: &str, strict: bool) {
    if is_vault_password_file(path) {
        eprintln!(
            "Refusing to encrypt .vault-password file: {}",
            path.display()
        );
        std::process::exit(1);
    }

    let content = fs::read(path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {}", path.display(), e);
        std::process::exit(1);
    });

    let text = String::from_utf8_lossy(&content);
    if text.starts_with(VAULT_HEADER) {
        if strict {
            eprintln!("{} is already encrypted.", path.display());
            std::process::exit(1);
        }
        return;
    }

    let encrypted = vault_encrypt(&content, password);
    fs::write(path, encrypted).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {}", path.display(), e);
        std::process::exit(1);
    });
}

// --- Decrypt file ---

fn decrypt_file(path: &Path, password: &str, strict: bool) {
    if is_vault_password_file(path) {
        eprintln!(
            "Refusing to decrypt .vault-password file: {}",
            path.display()
        );
        std::process::exit(1);
    }

    let content = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {}", path.display(), e);
        std::process::exit(1);
    });

    if !content.starts_with(VAULT_HEADER) {
        if strict {
            eprintln!("{} is not an encrypted vault file.", path.display());
            std::process::exit(1);
        }
        return;
    }

    let plaintext = vault_decrypt(&content, password);
    fs::write(path, &plaintext).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {}", path.display(), e);
        std::process::exit(1);
    });
}

// --- Ansible Vault 1.1 crypto ---

struct DerivedKey {
    cipher_key: [u8; KEY_LENGTH],
    hmac_key: [u8; KEY_LENGTH],
    iv: [u8; IV_LENGTH],
}

fn derive_key(password: &str, salt: &[u8]) -> DerivedKey {
    let mut derived = [0u8; KEY_LENGTH * 2 + IV_LENGTH];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut derived);

    let mut cipher_key = [0u8; KEY_LENGTH];
    let mut hmac_key = [0u8; KEY_LENGTH];
    let mut iv = [0u8; IV_LENGTH];

    cipher_key.copy_from_slice(&derived[..KEY_LENGTH]);
    hmac_key.copy_from_slice(&derived[KEY_LENGTH..KEY_LENGTH * 2]);
    iv.copy_from_slice(&derived[KEY_LENGTH * 2..]);

    DerivedKey {
        cipher_key,
        hmac_key,
        iv,
    }
}

fn vault_encrypt(plaintext: &[u8], password: &str) -> String {
    // Deterministic salt: HMAC-SHA256(password, plaintext) so same content always
    // produces the same encrypted output.
    let mut mac = HmacSha256::new_from_slice(password.as_bytes()).unwrap();
    mac.update(plaintext);
    let salt: [u8; SALT_LENGTH] = mac.finalize().into_bytes().into();

    let keys = derive_key(password, &salt);

    // PKCS7 padding.
    let block_size = 16;
    let pad_len = block_size - (plaintext.len() % block_size);
    let mut padded = plaintext.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

    // AES-256-CTR encrypt.
    let mut ciphertext = padded;
    let mut cipher = Aes256Ctr::new(&keys.cipher_key.into(), &keys.iv.into());
    cipher.apply_keystream(&mut ciphertext);

    // HMAC-SHA256 over ciphertext.
    let mut mac = HmacSha256::new_from_slice(&keys.hmac_key).unwrap();
    mac.update(&ciphertext);
    let hmac_result = mac.finalize().into_bytes();

    let payload = format!(
        "{}\n{}\n{}",
        hex::encode(salt),
        hex::encode(hmac_result),
        hex::encode(&ciphertext)
    );
    let payload_hex = hex::encode(payload.as_bytes());
    let wrapped = wrap_hex(&payload_hex, 80);

    format!("{}\n{}\n", VAULT_HEADER, wrapped)
}

fn vault_decrypt(content: &str, password: &str) -> Vec<u8> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() || !lines[0].starts_with("$ANSIBLE_VAULT;") {
        eprintln!("Error: not a valid vault file");
        std::process::exit(1);
    }

    let hex_body: String = lines[1..].iter().map(|l| l.trim()).collect();
    let payload_bytes = hex::decode(&hex_body).unwrap_or_else(|e| {
        eprintln!("Error decoding vault hex: {}", e);
        std::process::exit(1);
    });

    let payload = String::from_utf8(payload_bytes).unwrap_or_else(|e| {
        eprintln!("Error decoding vault payload: {}", e);
        std::process::exit(1);
    });

    let parts: Vec<&str> = payload.splitn(3, '\n').collect();
    if parts.len() != 3 {
        eprintln!("Error: malformed vault payload");
        std::process::exit(1);
    }

    let salt = hex::decode(parts[0]).unwrap_or_else(|e| {
        eprintln!("Error decoding salt: {}", e);
        std::process::exit(1);
    });
    let expected_hmac = hex::decode(parts[1]).unwrap_or_else(|e| {
        eprintln!("Error decoding HMAC: {}", e);
        std::process::exit(1);
    });
    let ciphertext = hex::decode(parts[2]).unwrap_or_else(|e| {
        eprintln!("Error decoding ciphertext: {}", e);
        std::process::exit(1);
    });

    let keys = derive_key(password, &salt);

    let mut mac = HmacSha256::new_from_slice(&keys.hmac_key).unwrap();
    mac.update(&ciphertext);
    if mac.verify_slice(&expected_hmac).is_err() {
        eprintln!("Error: HMAC verification failed — wrong password or corrupted file");
        std::process::exit(1);
    }

    let mut plaintext = ciphertext;
    let mut cipher = Aes256Ctr::new(&keys.cipher_key.into(), &keys.iv.into());
    cipher.apply_keystream(&mut plaintext);

    if let Some(&pad_len) = plaintext.last() {
        let pad_len = pad_len as usize;
        if pad_len > 0 && pad_len <= 16 && plaintext.len() >= pad_len {
            let valid = plaintext[plaintext.len() - pad_len..]
                .iter()
                .all(|&b| b == pad_len as u8);
            if valid {
                plaintext.truncate(plaintext.len() - pad_len);
            }
        }
    }

    plaintext
}

fn wrap_hex(s: &str, width: usize) -> String {
    s.as_bytes()
        .chunks(width)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let password = "test-password-123";
        let original = b"Hello, this is secret data!\nLine two.";
        let encrypted = vault_encrypt(original, password);
        assert!(encrypted.starts_with(VAULT_HEADER));
        let decrypted = vault_decrypt(&encrypted, password);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_roundtrip_empty() {
        let password = "pw";
        let original = b"";
        let encrypted = vault_encrypt(original, password);
        let decrypted = vault_decrypt(&encrypted, password);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_roundtrip_exact_block() {
        let password = "pw";
        let original = [0x41u8; 16];
        let encrypted = vault_encrypt(&original, password);
        let decrypted = vault_decrypt(&encrypted, password);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_deterministic() {
        let password = "deterministic-test";
        let original = b"same content every time";
        let enc1 = vault_encrypt(original, password);
        let enc2 = vault_encrypt(original, password);
        assert_eq!(
            enc1, enc2,
            "encrypting same content twice should produce identical output"
        );
    }

    #[test]
    fn test_wrap_hex() {
        let s = "a".repeat(200);
        let wrapped = wrap_hex(&s, 80);
        let lines: Vec<&str> = wrapped.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].len(), 80);
        assert_eq!(lines[1].len(), 80);
        assert_eq!(lines[2].len(), 40);
    }

    #[test]
    fn test_password_encrypt_decrypt_roundtrip() {
        let vault_password = "my-secret-vault-password";
        let master_password = "master-key-123";

        // Encrypt the vault password with the master password
        let encrypted = vault_encrypt(vault_password.as_bytes(), master_password);
        assert!(encrypted.starts_with(VAULT_HEADER));

        // Decrypt it back
        let decrypted_bytes = vault_decrypt(&encrypted, master_password);
        let decrypted = String::from_utf8(decrypted_bytes).unwrap();
        assert_eq!(decrypted, vault_password);
    }
}
