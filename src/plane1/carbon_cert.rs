//! Cryptographic Carbon-Attested Execution Certificates (CCEC).
//!
//! Honest scope: `accounting_mode` is always `PROXY_ESTIMATE` and `host_digest` is
//! `blake3(host_os || arch || family)` (host-TCB fingerprint, not hardware TEE attestation).

use crate::error::result::AppResult;
use crate::plane1::merkle::MerkleLog;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Merkle-committed Scope-2 carbon execution receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarbonAuditReceipt {
    /// Canonical certificate JSON body.
    pub certificate: Value,
    /// Merkle leaf index.
    pub leaf_index: usize,
    /// Merkle tree size at commit time.
    pub tree_size: usize,
    /// Merkle root hex.
    pub root_hash_hex: String,
    /// STH HMAC signature hex.
    pub sth_signature_hex: String,
}

/// Authority issuing CCEC leaves into `MTLog`.
pub struct CarbonCertificateAuthority {
    merkle: Arc<MerkleLog>,
    host_digest: String,
}

impl CarbonCertificateAuthority {
    /// Construct a new CCEC authority with a `blake3` host-TCB fingerprint.
    pub fn new(merkle: Arc<MerkleLog>) -> Self {
        let host_str = format!(
            "{}||{}||{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::env::consts::FAMILY
        );
        let host_digest = blake3::hash(host_str.as_bytes()).to_hex().to_string();
        Self { merkle, host_digest }
    }

    /// Borrow host fingerprint digest.
    pub fn host_digest(&self) -> &str {
        &self.host_digest
    }

    /// Commit a Scope-2 proxy certificate into `MTLog`.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        request_id: &str,
        provider_kind: &str,
        model_id: &str,
        tier: &str,
        energy_wh_proxy: f64,
        grid_carbon_g_per_kwh: f64,
        co2_g_proxy: f64,
        cost_usd: &str,
    ) -> AppResult<CarbonAuditReceipt> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let cert = json!({
            "cert_type": "NOSIH_CCEC_PROXY_V1",
            "request_id": request_id,
            "provider_kind": provider_kind,
            "model_id": model_id,
            "tier": tier,
            "energy_wh_proxy": (energy_wh_proxy * 1e6).round() / 1e6,
            "grid_carbon_g_per_kwh": (grid_carbon_g_per_kwh * 1e2).round() / 1e2,
            "co2_g_proxy": (co2_g_proxy * 1e6).round() / 1e6,
            "cost_usd": cost_usd,
            "accounting_mode": "PROXY_ESTIMATE",
            "host_digest": self.host_digest,
            "ts": ts,
        });
        let (leaf_index, _, sth) = self.merkle.append(&cert)?;
        Ok(CarbonAuditReceipt {
            certificate: cert,
            leaf_index,
            tree_size: sth.tree_size,
            root_hash_hex: sth.root_hash_hex,
            sth_signature_hex: sth.signature_hex,
        })
    }
}
