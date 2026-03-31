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

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const VAULT_HEADER: &str = "$ANSIBLE_VAULT;1.1;AES256";
const PBKDF2_ITERATIONS: u32 = 10000;
const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;
const SALT_LENGTH: usize = 32;

#[derive(Parser)]
#[command(name = "rv", about = "Ansible Vault compatible encrypt/decrypt tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file (or all files recursively if no file given)
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
    /// Install a git pre-commit hook that encrypts all vaults before committing
    Init,
}

fn main() {
    let cli = Cli::parse();

    // Init doesn't need a password.
    if let Commands::Init = &cli.command {
        install_pre_commit_hook();
        return;
    }

    let password = find_vault_password().unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    match cli.command {
        Commands::Encrypt { file, strict } => match file {
            Some(f) => {
                let path = resolve_file(&f);
                encrypt_file(&path, &password, strict);
                println!("Encrypted {}", path.display());
            }
            None => encrypt_all(&password),
        },
        Commands::Decrypt { file, strict } => match file {
            Some(f) => {
                let path = resolve_file(&f);
                decrypt_file(&path, &password, strict);
                println!("Decrypted {}", path.display());
            }
            None => decrypt_all(&password),
        },
        Commands::Edit { files } => {
            let paths: Vec<PathBuf> = if files.is_empty() {
                // No args: edit all files in .vault directory.
                let vault_dir = find_vault_dir().unwrap_or_else(|| {
                    eprintln!("Error: no .vault directory found");
                    std::process::exit(1);
                });
                WalkDir::new(&vault_dir)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file() && !is_vault_password_file(e.path()))
                    .map(|e| e.into_path())
                    .collect()
            } else {
                files.iter().map(|f| resolve_file(f)).collect()
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
        Commands::Init => unreachable!(),
    }
}

// --- Password discovery ---

fn read_password_file(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let pw = content.trim().to_string();
    if pw.is_empty() { None } else { Some(pw) }
}

fn find_vault_password() -> Result<String, String> {
    let mut dir = std::env::current_dir().map_err(|e| e.to_string())?;
    loop {
        // Check .vault/.vault-password first.
        let vault_dir_candidate = dir.join(".vault").join(".vault-password");
        if let Some(pw) = read_password_file(&vault_dir_candidate) {
            return Ok(pw);
        }
        // Then check .vault-password in the directory itself.
        let candidate = dir.join(".vault-password");
        if let Some(pw) = read_password_file(&candidate) {
            return Ok(pw);
        }
        if !dir.pop() {
            break;
        }
    }

    // Fall back to $HOME/.vault-password.
    if let Some(home) = std::env::var_os("HOME") {
        let candidate = PathBuf::from(home).join(".vault-password");
        if candidate.is_file() {
            let content = fs::read_to_string(&candidate)
                .map_err(|e| format!("Failed to read {}: {}", candidate.display(), e))?;
            let password = content.trim().to_string();
            if !password.is_empty() {
                return Ok(password);
            }
        }
    }

    Err("No .vault-password file found in current/parent directories or $HOME".to_string())
}

// --- File resolution ---

fn resolve_file(name: &str) -> PathBuf {
    let path = PathBuf::from(name);

    // If it exists relative to cwd, use it directly.
    if path.exists() {
        return path;
    }

    // Try relative to the .vault directory.
    if let Some(vault_dir) = find_vault_dir() {
        let vault_path = vault_dir.join(name);
        if vault_path.exists() {
            return vault_path;
        }
    }

    // If it's an explicit path (contains separator), don't search further.
    if name.contains('/') || name.contains('\\') {
        eprintln!("Error: {} not found", name);
        std::process::exit(1);
    }

    // It's just a filename — search recursively from cwd.
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

// --- Encrypt / Decrypt all (only files in .vault directories) ---

/// Find the nearest .vault directory by searching cwd and parents.
fn find_vault_dir() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".vault");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

fn encrypt_all(password: &str) {
    let vault_dir = find_vault_dir().unwrap_or_else(|| {
        eprintln!("Error: no .vault directory found");
        std::process::exit(1);
    });
    let mut count = 0;
    for entry in WalkDir::new(&vault_dir)
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
    println!("Encrypted {} files in {}", count, vault_dir.display());
}

fn decrypt_all(password: &str) {
    let vault_dir = find_vault_dir().unwrap_or_else(|| {
        eprintln!("Error: no .vault directory found");
        std::process::exit(1);
    });
    let mut count = 0;
    for entry in WalkDir::new(&vault_dir)
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
    println!("Decrypted {} files in {}", count, vault_dir.display());
}

// --- Pre-commit hook installation ---

const HOOK_MARKER: &str = "# rv pre-commit hook";
const HOOK_SCRIPT: &str = r#"# rv pre-commit hook
# Re-encrypt .vault files and .env files (excluding local/dev) before committing
if command -v rv >/dev/null 2>&1; then
    rv encrypt
    # Encrypt .env files that don't have "local" or "dev" in the filename
    find . \( -name target -o -name node_modules -o -name build -o -name dist \) -prune -o \( -name '*.env' -o -name '.env' -o -name '.env.*' \) -print | while read -r f; do
        case "$(basename "$f")" in
            *local*|*dev*) continue ;;
        esac
        head -1 "$f" 2>/dev/null | grep -q '^\$ANSIBLE_VAULT' && continue
        rv encrypt "$f" 2>/dev/null && echo "Encrypted $f"
    done
    git add -u
fi
# end rv pre-commit hook"#;

fn install_pre_commit_hook() {
    // Find git dir.
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output();
    let git_dir = match output {
        Ok(o) if o.status.success() => {
            PathBuf::from(String::from_utf8_lossy(&o.stdout).trim().to_string())
        }
        _ => {
            eprintln!("Error: not a git repository");
            std::process::exit(1);
        }
    };

    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir).ok();
    let hook_path = hooks_dir.join("pre-commit");

    if hook_path.exists() {
        // Check if our hook is already installed.
        let content = fs::read_to_string(&hook_path).unwrap_or_default();
        if content.contains(HOOK_MARKER) {
            println!("rv pre-commit hook already installed in {}", hook_path.display());
            return;
        }
        // Append to existing hook.
        let updated = format!("{}\n\n{}\n", content.trim_end(), HOOK_SCRIPT);
        fs::write(&hook_path, updated).unwrap_or_else(|e| {
            eprintln!("Error writing {}: {}", hook_path.display(), e);
            std::process::exit(1);
        });
        println!("Appended rv pre-commit hook to {}", hook_path.display());
    } else {
        // Create new hook.
        let content = format!("#!/bin/sh\n\n{}\n", HOOK_SCRIPT);
        fs::write(&hook_path, content).unwrap_or_else(|e| {
            eprintln!("Error writing {}: {}", hook_path.display(), e);
            std::process::exit(1);
        });
        println!("Created rv pre-commit hook at {}", hook_path.display());
    }

    // Make executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms).ok();
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
    // Decrypt all files and collect their contents.
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

    // Build a combined temp file with separators.
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

    // Parse the edited content back into per-file sections.
    let mut sections: Vec<(String, String)> = Vec::new();
    let mut current_path: Option<String> = None;
    let mut current_content = String::new();

    for line in edited.lines() {
        if line.starts_with(FILE_SEPARATOR_PREFIX) && line.ends_with(FILE_SEPARATOR_SUFFIX) {
            // Save previous section.
            if let Some(p) = current_path.take() {
                sections.push((p, std::mem::take(&mut current_content)));
            }
            let path_str = &line[FILE_SEPARATOR_PREFIX.len()..line.len() - FILE_SEPARATOR_SUFFIX.len()];
            current_path = Some(path_str.to_string());
            current_content.clear();
        } else {
            if current_path.is_some() {
                if !current_content.is_empty() {
                    current_content.push('\n');
                }
                current_content.push_str(line);
            }
        }
    }
    // Save last section.
    if let Some(p) = current_path {
        sections.push((p, current_content));
    }

    // Re-encrypt and write each file.
    let original_map: std::collections::HashMap<String, &[u8]> = entries
        .iter()
        .map(|(p, c)| (p.display().to_string(), c.as_slice()))
        .collect();

    for (path_str, content) in &sections {
        let content_bytes = content.as_bytes();
        // Check if content changed.
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
        eprintln!("Refusing to encrypt .vault-password file: {}", path.display());
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
        eprintln!("Refusing to decrypt .vault-password file: {}", path.display());
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

    // Ansible vault format: hex(salt)\nhex(hmac)\nhex(ciphertext), then hex-encode the whole thing.
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

    // Join all hex lines after the header.
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

    // Verify HMAC.
    let mut mac = HmacSha256::new_from_slice(&keys.hmac_key).unwrap();
    mac.update(&ciphertext);
    if mac.verify_slice(&expected_hmac).is_err() {
        eprintln!("Error: HMAC verification failed — wrong password or corrupted file");
        std::process::exit(1);
    }

    // Decrypt.
    let mut plaintext = ciphertext;
    let mut cipher = Aes256Ctr::new(&keys.cipher_key.into(), &keys.iv.into());
    cipher.apply_keystream(&mut plaintext);

    // Remove PKCS7 padding.
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
        let original = [0x41u8; 16]; // Exactly one block.
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
        assert_eq!(enc1, enc2, "encrypting same content twice should produce identical output");
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
}
