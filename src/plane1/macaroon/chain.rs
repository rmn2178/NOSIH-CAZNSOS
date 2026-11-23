//! Macaroon minting, offline monotonic attenuation, and single construction site of `Authorized<ProviderCall>`.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::plane1::budget::BudgetLedger;
use crate::plane1::crypto::hkdf::hkdf_sha256_32;
use crate::plane1::crypto::hmac::{ct_eq, hmac_sha256_hex};
use crate::plane1::crypto::secrets::KeyMaterial;
use crate::plane1::jcs::canonical::jcs_bytes;
use crate::plane1::macaroon::caveat::Caveat;
use crate::plane1::replay::JtiReplayStore;
use crate::types::authorized::{Authorized, ProviderCall};
use crate::types::decimal::ExactDecimal;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const ROOT_DOMAIN: &[u8] = b"NOSIH-V3-ROOT\x00";
const CAV_DOMAIN: &[u8] = b"NOSIH-V3-CAV\x00";
const HKDF_INFO: &[u8] = b"NOSIH-V3-CAP-ROOT";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Offline-attenuable Macaroon capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacaroonToken {
    /// Unique capability ID.
    pub cap_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Session scope.
    pub session_id: String,
    /// Issuance unix seconds.
    pub issued_at: i64,
    /// Hard expiration unix seconds.
    pub max_expires_at: i64,
    /// Ordered monotonic caveat chain.
    pub caveats: Vec<Caveat>,
    /// Chained HMAC-SHA256 authentication tag.
    pub tag_hex: String,
}

impl MacaroonToken {
    fn header_json(&self) -> serde_json::Value {
        json!({
            "cap_id": self.cap_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "issued_at": self.issued_at,
            "max_expires_at": self.max_expires_at,
        })
    }

    /// Offline monotonic attenuation (requires NO root secret).
    pub fn attenuate(&self, caveat: Caveat) -> AppResult<Self> {
        let prev = hex::decode(&self.tag_hex)
            .map_err(|_| AppError::CapabilityDenied("corrupt_macaroon_tag".into()))?;
        let cav_bytes = jcs_bytes(&caveat.to_json())?;
        let next_tag = hmac_sha256_hex(&prev, CAV_DOMAIN, &cav_bytes);
        let mut next = self.clone();
        next.caveats.push(caveat);
        next.tag_hex = next_tag;
        Ok(next)
    }
}

/// Authority that mints root Macaroons and is the **ONLY** constructor of `Authorized<ProviderCall>`.
pub struct MacaroonAuthority {
    root_secret: KeyMaterial,
    replay: Arc<JtiReplayStore>,
    budget: Arc<BudgetLedger>,
}

impl MacaroonAuthority {
    /// Construct a new Macaroon authority.
    pub fn new(
        root_secret: KeyMaterial,
        replay: Arc<JtiReplayStore>,
        budget: Arc<BudgetLedger>,
    ) -> Self {
        Self {
            root_secret,
            replay,
            budget,
        }
    }

    fn derive_session_key(&self, tenant_id: &str, session_id: &str) -> [u8; 32] {
        let salt = format!("{tenant_id}:{session_id}");
        hkdf_sha256_32(self.root_secret.as_bytes(), salt.as_bytes(), HKDF_INFO)
    }

    /// Mint a root Macaroon scoped to `(tenant_id, session_id)`.
    pub fn mint_root(
        &self,
        tenant_id: &str,
        session_id: &str,
        ttl_secs: i64,
    ) -> AppResult<MacaroonToken> {
        let now = now_unix();
        let cap_id = crate::types::ids::JtiNonce::try_generate()
            .map_err(|e| AppError::Internal(format!("csprng_cap_id_failed: {e}")))?
            .0;
        let k_su = self.derive_session_key(tenant_id, session_id);
        let mut tok = MacaroonToken {
            cap_id,
            tenant_id: tenant_id.to_string(),
            session_id: session_id.to_string(),
            issued_at: now,
            max_expires_at: now + ttl_secs.max(1),
            caveats: Vec::new(),
            tag_hex: String::new(),
        };
        let hdr = jcs_bytes(&tok.header_json())?;
        tok.tag_hex = hmac_sha256_hex(&k_su, ROOT_DOMAIN, &hdr);
        Ok(tok)
    }

    /// Verify the full HMAC caveat chain, consume single-use JTI in SQLite WAL,
    /// atomically debit linear USD budget, and mint `Authorized<ProviderCall>`.
    pub fn verify_and_authorize(
        &self,
        token: &MacaroonToken,
        provider: &str,
        model: &str,
        request_id: &str,
        estimated_cost: ExactDecimal,
    ) -> AppResult<Authorized<ProviderCall>> {
        let now = now_unix();
        if now > token.max_expires_at {
            return Err(AppError::CapabilityDenied("capability_expired".into()));
        }

        // 1. Recompute full HMAC chain from K_{s,u}
        let k_su = self.derive_session_key(&token.tenant_id, &token.session_id);
        let hdr = jcs_bytes(&token.header_json())?;
        let mut running = hmac_sha256_hex(&k_su, ROOT_DOMAIN, &hdr);
        for cav in &token.caveats {
            let prev = hex::decode(&running)
                .map_err(|_| AppError::Internal("hex_decode_err".into()))?;
            let cav_bytes = jcs_bytes(&cav.to_json())?;
            running = hmac_sha256_hex(&prev, CAV_DOMAIN, &cav_bytes);
        }
        if !ct_eq(running.as_bytes(), token.tag_hex.as_bytes()) {
            return Err(AppError::CapabilityDenied("invalid_macaroon_signature".into()));
        }

        // 2. Evaluate caveats
        let mut jti_opt: Option<String> = None;
        for cav in &token.caveats {
            match cav.kind.as_str() {
                "provider" => {
                    if cav.params.as_str() != Some(provider) {
                        return Err(AppError::CapabilityDenied("provider_caveat_mismatch".into()));
                    }
                }
                "model" => {
                    if cav.params.as_str() != Some(model) {
                        return Err(AppError::CapabilityDenied("model_caveat_mismatch".into()));
                    }
                }
                "max_usd" => {
                    let lim_s = cav.params.as_str().unwrap_or("0");
                    let lim = ExactDecimal::parse_str(lim_s)
                        .map_err(|_| AppError::CapabilityDenied("invalid_max_usd_caveat".into()))?;
                    if estimated_cost > lim {
                        return Err(AppError::CapabilityDenied("cost_exceeds_caveat".into()));
                    }
                }
                "ttl_max" => {
                    let exp = cav.params.as_i64().unwrap_or(0);
                    if now > exp {
                        return Err(AppError::CapabilityDenied("caveat_ttl_expired".into()));
                    }
                }
                "jti_single_use" => {
                    jti_opt = cav.params.as_str().map(String::from);
                }
                _ => {}
            }
        }

        // 3. Consume single-use JTI atomically
        let jti = jti_opt
            .ok_or_else(|| AppError::CapabilityDenied("missing_jti_single_use_caveat".into()))?;
        if !self.replay.consume_jti(&jti, request_id, token.max_expires_at)? {
            return Err(AppError::CapabilityDenied("jti_replay_detected".into()));
        }

        // 4. Debit exact-decimal linear budget if positive
        if estimated_cost.is_positive() {
            let _ = self.budget.ensure_and_debit(&token.tenant_id, estimated_cost)?;
        }

        Ok(Authorized::mint_verified(ProviderCall {
            provider: provider.to_string(),
            model: model.to_string(),
            request_id: request_id.to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SqliteStorage;
    use tempfile::tempdir;

    #[test]
    fn tampered_caveat_rejected_and_replay_blocked() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(SqliteStorage::open(&dir.path().join("t.db")).unwrap());
        let auth = MacaroonAuthority::new(
            KeyMaterial::generate(),
            Arc::new(JtiReplayStore::new(Arc::clone(&storage))),
            Arc::new(BudgetLedger::new(Arc::clone(&storage))),
        );
        let root = auth.mint_root("t1", "s1", 60).unwrap();
        let jti = crate::types::ids::JtiNonce::generate().0;
        let tok = root
            .attenuate(Caveat::new("provider", json!("openai")))
            .unwrap()
            .attenuate(Caveat::new("model", json!("gpt-4o")))
            .unwrap()
            .attenuate(Caveat::new("max_usd", json!("1.00")))
            .unwrap()
            .attenuate(Caveat::new("jti_single_use", json!(jti)))
            .unwrap();

        let mut tampered = tok.clone();
        tampered.caveats[2].params = json!("999.00");
        assert!(auth.verify_and_authorize(&tampered, "openai", "gpt-4o", "r1", ExactDecimal::ZERO).is_err());

        assert!(auth.verify_and_authorize(&tok, "openai", "gpt-4o", "r1", ExactDecimal::ZERO).is_ok());
        assert!(auth.verify_and_authorize(&tok, "openai", "gpt-4o", "r1", ExactDecimal::ZERO).is_err());
    }
}
