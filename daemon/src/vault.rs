//! Ansible Vault 1.1 (AES256) crypto + vault-tree helpers, ported verbatim
//! from the `walt` CLI repo (github.com/lechl1/walt, src/main.rs). waltd is the
//! daemonised engine: the CLI and GUI never touch this code directly — they go
//! through the HTTP API (../openapi.yaml). Keeping the wire format identical to
//! walt's means files written here decrypt with `ansible-vault` and vice-versa.

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub const VAULT_HEADER: &str = "$ANSIBLE_VAULT;1.1;AES256";
const PBKDF2_ITERATIONS: u32 = 10000;
const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;
const SALT_LENGTH: usize = 32;

/// The conventional unencrypted password filename inside every env dir.
pub const PASSWORD_FILE: &str = ".vault-password";
/// The dev environment uses a fixed master password ("dev"), matching the
/// walt CLI, so waltd can transparently read a vault-encrypted dev password.
pub const DEV_ENV: &str = "dev";
pub const DEV_PASSWORD: &str = "dev";

/// True if the bytes look like an Ansible Vault payload.
pub fn is_encrypted(content: &str) -> bool {
    content.starts_with(VAULT_HEADER)
}

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

    DerivedKey { cipher_key, hmac_key, iv }
}

/// Encrypt plaintext into the Ansible-Vault text envelope. Deterministic: the
/// salt is HMAC(password, plaintext) so identical content re-encrypts to an
/// identical file (keeps git diffs clean — same invariant as walt).
pub fn encrypt(plaintext: &[u8], password: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(password.as_bytes()).unwrap();
    mac.update(plaintext);
    let salt: [u8; SALT_LENGTH] = mac.finalize().into_bytes().into();

    let keys = derive_key(password, &salt);

    // PKCS7 padding.
    let block_size = 16;
    let pad_len = block_size - (plaintext.len() % block_size);
    let mut padded = plaintext.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

    // AES-256-CTR.
    let mut ciphertext = padded;
    let mut cipher = Aes256Ctr::new(&keys.cipher_key.into(), &keys.iv.into());
    cipher.apply_keystream(&mut ciphertext);

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

/// Decrypt an Ansible-Vault envelope. Returns an error string instead of
/// exiting (the CLI port called std::process::exit; a daemon must not).
pub fn decrypt(content: &str, password: &str) -> Result<Vec<u8>, String> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() || !lines[0].starts_with("$ANSIBLE_VAULT;") {
        return Err("not a valid vault file".into());
    }
    let hex_body: String = lines[1..].iter().map(|l| l.trim()).collect();
    let payload_bytes = hex::decode(&hex_body).map_err(|e| format!("decoding vault hex: {e}"))?;
    let payload = String::from_utf8(payload_bytes).map_err(|e| format!("decoding payload: {e}"))?;

    let parts: Vec<&str> = payload.splitn(3, '\n').collect();
    if parts.len() != 3 {
        return Err("malformed vault payload".into());
    }
    let salt = hex::decode(parts[0]).map_err(|e| format!("decoding salt: {e}"))?;
    let expected_hmac = hex::decode(parts[1]).map_err(|e| format!("decoding HMAC: {e}"))?;
    let ciphertext = hex::decode(parts[2]).map_err(|e| format!("decoding ciphertext: {e}"))?;

    let keys = derive_key(password, &salt);
    let mut mac = HmacSha256::new_from_slice(&keys.hmac_key).unwrap();
    mac.update(&ciphertext);
    if mac.verify_slice(&expected_hmac).is_err() {
        return Err("HMAC verification failed — wrong password or corrupted file".into());
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
    Ok(plaintext)
}

fn wrap_hex(s: &str, width: usize) -> String {
    s.as_bytes()
        .chunks(width)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The password protecting an environment. Reads `<env>/.vault-password`:
/// plaintext is used as-is; a vault-encrypted password is only auto-readable
/// for the dev env (fixed "dev" master, matching walt). Other encrypted
/// password files would need an interactive master prompt the daemon can't do.
pub fn env_password(env_dir: &Path, env_name: &str) -> Result<String, String> {
    let path = env_dir.join(PASSWORD_FILE);
    let content = std::fs::read_to_string(&path)
        .map_err(|_| format!("no {} for environment '{}'", PASSWORD_FILE, env_name))?;
    if content.trim().is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    if is_encrypted(&content) {
        if env_name == DEV_ENV {
            let bytes = decrypt(&content, DEV_PASSWORD)?;
            return String::from_utf8(bytes)
                .map(|s| s.trim().to_string())
                .map_err(|_| "decrypted password is not UTF-8".into());
        }
        return Err(format!(
            "{} is vault-encrypted; decrypt it with `walt password` so waltd can read it",
            path.display()
        ));
    }
    Ok(content.trim().to_string())
}

/// A walt-compatible random password for non-dev environments at init time.
pub fn random_password() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(
        "{:08x}{:08x}",
        nanos,
        nanos.wrapping_mul(2654435761).rotate_right(16)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let pw = "test-password-123";
        let original = b"Hello, this is secret data!\nLine two.";
        let enc = encrypt(original, pw);
        assert!(enc.starts_with(VAULT_HEADER));
        assert_eq!(decrypt(&enc, pw).unwrap(), original);
    }

    #[test]
    fn deterministic() {
        let pw = "deterministic-test";
        let original = b"same content every time";
        assert_eq!(encrypt(original, pw), encrypt(original, pw));
    }

    #[test]
    fn wrong_password_fails() {
        let enc = encrypt(b"secret", "right");
        assert!(decrypt(&enc, "wrong").is_err());
    }
}
