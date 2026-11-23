//! AES-256-GCM encrypted upstream provider API key vault backed by SQLite WAL.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::plane1::crypto::secrets::KeyMaterial;
use crate::storage::SqliteStorage;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rusqlite::params;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Metadata for an uploaded upstream provider key (secret is always masked).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskedKeyRecord {
    /// Unique key identifier.
    pub id: String,
    /// Provider kind (`openai`, `anthropic`, `gemini`, `groq`, `ollama`, `openai_compatible`, etc.).
    pub provider: String,
    /// Optional human-readable label.
    pub label: String,
    /// Masked key preview (`sk-...abcd`).
    pub masked_key: String,
    /// Optional custom base URL for OpenAI-compatible or Azure endpoints.
    pub base_url: Option<String>,
    /// Daily USD spending ceiling.
    pub max_usd_per_day: String,
    /// Hourly request ceiling.
    pub max_requests_per_hour: u32,
    /// Optional allowlisted model names.
    pub allowed_models: Vec<String>,
}

/// Decrypted runtime credential (wrapped in `SecretString` so it zeroizes on drop).
#[derive(Clone)]
pub struct DecryptedProviderKey {
    /// Key record ID.
    pub id: String,
    /// Provider identifier.
    pub provider: String,
    /// Secret API key.
    pub api_key: SecretString,
    /// Optional base URL override.
    pub base_url: Option<String>,
    /// Allowed models.
    pub allowed_models: Vec<String>,
}

/// Input payload when uploading a new upstream API key.
#[derive(Debug, Clone, Deserialize)]
pub struct UploadKeyInput {
    /// Provider name.
    pub provider: String,
    /// Raw API key string.
    pub api_key: String,
    /// Optional friendly label.
    #[serde(default)]
    pub label: Option<String>,
    /// Optional custom base URL.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Optional daily USD limit (string decimal).
    #[serde(default)]
    pub max_usd_per_day: Option<String>,
    /// Optional hourly request limit.
    #[serde(default)]
    pub max_requests_per_hour: Option<u32>,
    /// Optional allowed model list.
    #[serde(default)]
    pub allowed_models: Vec<String>,
}

/// Encrypted SQLite-backed provider key vault.
pub struct SecretVault {
    storage: Arc<SqliteStorage>,
    master_key: KeyMaterial,
}

impl SecretVault {
    /// Create a new vault using an AES-256 master key.
    pub fn new(storage: Arc<SqliteStorage>, master_key: KeyMaterial) -> Self {
        Self { storage, master_key }
    }

    /// Mask an API key as `prefix...last4`.
    pub fn mask_key(raw: &str) -> String {
        let len = raw.len();
        if len <= 8 {
            return "***".to_string();
        }
        let prefix: String = raw.chars().take(4).collect();
        let suffix: String = raw.chars().skip(len.saturating_sub(4)).collect();
        format!("{prefix}...{suffix}")
    }

    fn encrypt(&self, plaintext: &str) -> AppResult<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new_from_slice(self.master_key.as_bytes())
            .map_err(|_| AppError::Internal("invalid_vault_key".into()))?;
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| AppError::Internal(format!("csprng_error: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| AppError::Internal("aes_gcm_encrypt_failed".into()))?;
        Ok((nonce_bytes.to_vec(), ct))
    }

    fn decrypt(&self, nonce_bytes: &[u8], ct: &[u8]) -> AppResult<SecretString> {
        let cipher = Aes256Gcm::new_from_slice(self.master_key.as_bytes())
            .map_err(|_| AppError::Internal("invalid_vault_key".into()))?;
        if nonce_bytes.len() != 12 {
            return Err(AppError::Internal("corrupt_nonce_len".into()));
        }
        let nonce = Nonce::from_slice(nonce_bytes);
        let pt = cipher
            .decrypt(nonce, ct)
            .map_err(|_| AppError::Internal("aes_gcm_decrypt_failed".into()))?;
        let s = String::from_utf8(pt)
            .map_err(|_| AppError::Internal("corrupt_utf8_secret".into()))?;
        Ok(SecretString::from(s))
    }

    /// Encrypt and persist a provider key in SQLite WAL.
    pub fn insert_key(&self, input: &UploadKeyInput) -> AppResult<MaskedKeyRecord> {
        let id = format!("key-{}", Uuid::new_v4());
        let label = input.label.clone().unwrap_or_else(|| input.provider.clone());
        let max_usd = input.max_usd_per_day.clone().unwrap_or_else(|| "25.00".into());
        let max_rph = input.max_requests_per_hour.unwrap_or(600);
        let allowed_json = serde_json::to_string(&input.allowed_models)
            .unwrap_or_else(|_| "[]".to_string());
        let masked = Self::mask_key(&input.api_key);
        let (nonce, ct) = self.encrypt(&input.api_key)?;

        let conn = self.storage.get_conn()?;
        conn.execute(
            "INSERT INTO provider_keys
             (id, provider, label, masked_key, base_url, nonce, ciphertext, max_usd_per_day, max_requests_per_hour, allowed_models)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);",
            params![
                id,
                input.provider.to_lowercase(),
                label,
                masked,
                input.base_url,
                nonce,
                ct,
                max_usd,
                max_rph as i64,
                allowed_json
            ],
        )
        .map_err(|e| AppError::Storage(e.to_string()))?;

        Ok(MaskedKeyRecord {
            id,
            provider: input.provider.to_lowercase(),
            label,
            masked_key: masked,
            base_url: input.base_url.clone(),
            max_usd_per_day: max_usd,
            max_requests_per_hour: max_rph,
            allowed_models: input.allowed_models.clone(),
        })
    }

    /// List all stored keys with secrets masked.
    pub fn list_masked(&self) -> AppResult<Vec<MaskedKeyRecord>> {
        let conn = self.storage.get_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, provider, label, masked_key, base_url, max_usd_per_day, max_requests_per_hour, allowed_models
                 FROM provider_keys ORDER BY rowid DESC;",
            )
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| {
                let allowed_str: String = r.get(7)?;
                let allowed: Vec<String> = serde_json::from_str(&allowed_str).unwrap_or_default();
                Ok(MaskedKeyRecord {
                    id: r.get(0)?,
                    provider: r.get(1)?,
                    label: r.get(2)?,
                    masked_key: r.get(3)?,
                    base_url: r.get(4)?,
                    max_usd_per_day: r.get(5)?,
                    max_requests_per_hour: r.get::<_, i64>(6)? as u32,
                    allowed_models: allowed,
                })
            })
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Delete a stored key by ID.
    pub fn delete_key(&self, id: &str) -> AppResult<bool> {
        let conn = self.storage.get_conn()?;
        let n = conn
            .execute("DELETE FROM provider_keys WHERE id = ?1;", params![id])
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(n > 0)
    }

    /// Atomically rotate a stored key's ciphertext.
    pub fn rotate_key(&self, id: &str, new_secret: &str) -> AppResult<bool> {
        let (nonce, ct) = self.encrypt(new_secret)?;
        let masked = Self::mask_key(new_secret);
        let conn = self.storage.get_conn()?;
        let n = conn
            .execute(
                "UPDATE provider_keys SET nonce = ?1, ciphertext = ?2, masked_key = ?3 WHERE id = ?4;",
                params![nonce, ct, masked, id],
            )
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(n > 0)
    }

    /// Resolve the first decrypted key matching a provider kind (or fallback to env var).
    pub fn resolve_for_provider(&self, provider: &str) -> AppResult<Option<DecryptedProviderKey>> {
        let conn = self.storage.get_conn()?;
        let res = conn.query_row(
            "SELECT id, provider, base_url, nonce, ciphertext, allowed_models
             FROM provider_keys WHERE provider = ?1 ORDER BY rowid DESC LIMIT 1;",
            params![provider.to_lowercase()],
            |r| {
                let id: String = r.get(0)?;
                let prov: String = r.get(1)?;
                let base_url: Option<String> = r.get(2)?;
                let nonce: Vec<u8> = r.get(3)?;
                let ct: Vec<u8> = r.get(4)?;
                let allowed_s: String = r.get(5)?;
                Ok((id, prov, base_url, nonce, ct, allowed_s))
            },
        );
        match res {
            Ok((id, prov, base_url, nonce, ct, allowed_s)) => {
                let secret = self.decrypt(&nonce, &ct)?;
                let allowed: Vec<String> = serde_json::from_str(&allowed_s).unwrap_or_default();
                Ok(Some(DecryptedProviderKey {
                    id,
                    provider: prov,
                    api_key: secret,
                    base_url,
                    allowed_models: allowed,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let env_name = match provider.to_lowercase().as_str() {
                    "openai" => "OPENAI_API_KEY",
                    "anthropic" => "ANTHROPIC_API_KEY",
                    "gemini" => "GEMINI_API_KEY",
                    "groq" => "GROQ_API_KEY",
                    "mistral" => "MISTRAL_API_KEY",
                    "together" => "TOGETHER_API_KEY",
                    "openrouter" => "OPENROUTER_API_KEY",
                    _ => return Ok(None),
                };
                if let Ok(v) = std::env::var(env_name) {
                    if !v.trim().is_empty() {
                        return Ok(Some(DecryptedProviderKey {
                            id: format!("env:{env_name}"),
                            provider: provider.to_lowercase(),
                            api_key: SecretString::from(v),
                            base_url: None,
                            allowed_models: Vec::new(),
                        }));
                    }
                }
                Ok(None)
            }
            Err(e) => Err(AppError::Storage(e.to_string())),
        }
    }

    /// Expose a decrypted key by ID for admin 1-token testing.
    pub fn resolve_by_id(&self, id: &str) -> AppResult<Option<DecryptedProviderKey>> {
        let conn = self.storage.get_conn()?;
        let res = conn.query_row(
            "SELECT id, provider, base_url, nonce, ciphertext, allowed_models
             FROM provider_keys WHERE id = ?1;",
            params![id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
        );
        match res {
            Ok((id, prov, base_url, nonce, ct, allowed_s)) => {
                let secret = self.decrypt(&nonce, &ct)?;
                let allowed: Vec<String> = serde_json::from_str(&allowed_s).unwrap_or_default();
                let _ = secret.expose_secret();
                Ok(Some(DecryptedProviderKey {
                    id,
                    provider: prov,
                    api_key: secret,
                    base_url,
                    allowed_models: allowed,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Storage(e.to_string())),
        }
    }
}
