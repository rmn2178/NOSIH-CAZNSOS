//! Canonical JCS + BLAKE3 provenance partition key (`ProvenanceScopeKey`).

use crate::plane1::jcs::canonical::jcs_bytes;
use crate::types::integrity::IntegrityRank;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Cryptographic partition scope preventing cross-tenant & cross-epoch semantic cache poisoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceScopeKey {
    /// Tenant identifier.
    pub tenant_id: String,
    /// Model tier or alias.
    pub model_class: String,
    /// Policy epoch string.
    pub policy_epoch: String,
    /// Origin integrity rank.
    pub origin_integrity: IntegrityRank,
    /// Schema digest.
    pub schema_digest: String,
}

impl ProvenanceScopeKey {
    /// Compute BLAKE3 digest over RFC 8785 canonical JSON scope fields.
    pub fn digest_hex(&self) -> String {
        let val = json!({
            "tenant_id": self.tenant_id,
            "model_class": self.model_class,
            "policy_epoch": self.policy_epoch,
            "origin_integrity": self.origin_integrity.rank(),
            "schema_digest": self.schema_digest,
        });
        let bytes = jcs_bytes(&val).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }
}
