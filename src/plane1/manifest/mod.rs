//! Out-of-band HMAC-SHA256 signed boot manifest & mid-session schema rug-pull detector.

use crate::plane1::crypto::hmac::{ct_eq, hmac_sha256_hex};
use crate::plane1::crypto::secrets::KeyMaterial;
use crate::plane1::jcs::canonical::jcs_sha256;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const MANIFEST_DOMAIN: &[u8] = b"NOSIH-CAZNSOS-MANIFEST-V1\x00";

/// Boot-pinned tool schema guard preventing Day-0 TOFU and mid-session rug pulls.
pub struct ManifestGuard {
    hmac_key: KeyMaterial,
    pinned: BTreeMap<String, String>,
    signature_hex: String,
}

impl ManifestGuard {
    /// Construct a default boot-signed manifest covering standard OpenAI tool schemas.
    pub fn new_default(hmac_key: KeyMaterial) -> Self {
        let mut pinned = BTreeMap::new();
        let default_schema = json!({"type": "chat.completion", "version": "v1"});
        if let Ok(d) = jcs_sha256(&default_schema) {
            pinned.insert("chat.completions".to_string(), d);
        }
        let body = serde_json::to_vec(&pinned).unwrap_or_default();
        let sig = hmac_sha256_hex(hmac_key.as_bytes(), MANIFEST_DOMAIN, &body);
        Self {
            hmac_key,
            pinned,
            signature_hex: sig,
        }
    }

    /// Verify boot manifest signature integrity.
    pub fn verify_self(&self) -> bool {
        let body = serde_json::to_vec(&self.pinned).unwrap_or_default();
        let expected = hmac_sha256_hex(self.hmac_key.as_bytes(), MANIFEST_DOMAIN, &body);
        ct_eq(expected.as_bytes(), self.signature_hex.as_bytes())
    }

    /// Verify a runtime schema digest against the boot-pinned digest.
    pub fn verify_tool(&self, name: &str, schema: &Value) -> Result<String, String> {
        let expected = self
            .pinned
            .get(name)
            .ok_or_else(|| format!("UNPINNED_TOOL:{name}"))?;
        let actual = jcs_sha256(schema).map_err(|e| e.to_string())?;
        if !ct_eq(actual.as_bytes(), expected.as_bytes()) {
            return Err(format!("RUG_PULL_DETECTED:{name}"));
        }
        Ok(actual)
    }
}
