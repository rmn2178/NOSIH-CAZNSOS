//! First-run CSPRNG generation (`getrandom`) of local key (`sk-nosih-...`),
//! admin token (`adm-...`), and dedicated 256-bit vault/signing master key (`master.key`).

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::plane1::crypto::secrets::KeyMaterial;
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Zeroizing wrapper for local API key or admin token.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LocalSecretToken(String);

impl LocalSecretToken {
    /// Borrow inner token string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn gen_hex_32() -> AppResult<String> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| AppError::Internal(format!("getrandom: {e}")))?;
    Ok(hex::encode(buf))
}

fn set_owner_only_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn load_or_create(path: &Path, prefix: &str) -> AppResult<(LocalSecretToken, bool)> {
    if path.exists() {
        let raw = fs::read_to_string(path).map_err(|e| AppError::Internal(e.to_string()))?;
        let trimmed = raw.trim().to_string();
        if !trimmed.is_empty() {
            return Ok((LocalSecretToken(trimmed), false));
        }
    }
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let tok = format!("{prefix}{}", gen_hex_32()?);
    fs::write(path, &tok).map_err(|e| AppError::Internal(e.to_string()))?;
    set_owner_only_perms(path);
    Ok((LocalSecretToken(tok), true))
}

/// Ensure `~/.nosih/local_key` exists (`0600`), returning `(token, created_now)`.
pub fn ensure_local_key(data_dir: &Path) -> AppResult<(LocalSecretToken, bool)> {
    load_or_create(&data_dir.join("local_key"), "sk-nosih-")
}

/// Ensure `~/.nosih/admin_token` exists (`0600`), returning `(token, created_now)`.
pub fn ensure_admin_token(data_dir: &Path) -> AppResult<(LocalSecretToken, bool)> {
    load_or_create(&data_dir.join("admin_token"), "adm-")
}

/// Ensure a dedicated 256-bit `~/.nosih/master.key` exists (`0600`), completely decoupled
/// from client-facing `local_key`. Never printed or shared with IDE/SDK clients.
pub fn ensure_master_key(data_dir: &Path) -> AppResult<(KeyMaterial, bool)> {
    let path = data_dir.join("master.key");
    if path.exists() {
        let raw = fs::read_to_string(&path).map_err(|e| AppError::Internal(e.to_string()))?;
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let decoded = hex::decode(trimmed)
                .map_err(|_| AppError::Internal("corrupt_master_key_hex".into()))?;
            if decoded.len() != 32 {
                return Err(AppError::Internal("corrupt_master_key_len".into()));
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&decoded);
            return Ok((KeyMaterial::from_bytes(bytes), false));
        }
    }
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let key = KeyMaterial::try_generate()
        .map_err(|e| AppError::Internal(format!("getrandom_master_key: {e}")))?;
    fs::write(&path, hex::encode(key.as_bytes())).map_err(|e| AppError::Internal(e.to_string()))?;
    set_owner_only_perms(&path);
    Ok((key, true))
}
