//! RFC 6962 / RFC 9162 Domain-Separated Binary Merkle Transparency Log (`MTLog`).
//!
//! Compile-time domain separation: [`LeafHash`] (`0x00 || data`) and [`NodeHash`] (`0x01 || L || R`)
//! are distinct newtypes with NO `From` conversion between them.

pub mod proof;

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::plane1::crypto::hmac::hmac_sha256_hex;
use crate::plane1::crypto::secrets::KeyMaterial;
use crate::plane1::jcs::canonical::jcs_bytes;
use crate::plane1::merkle::proof::{audit_path, largest_pow2_lt};
use crate::storage::SqliteStorage;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;
const STH_DOMAIN: &[u8] = b"NOSIH-V3-STH\x00";

/// Domain-separated Merkle leaf hash (`SHA256(0x00 || payload)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafHash(pub [u8; 32]);

/// Domain-separated Merkle tree/node hash (`SHA256(0x01 || left || right)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeHash(pub [u8; 32]);

impl LeafHash {
    /// Compute RFC 6962 leaf digest with `0x00` domain prefix.
    pub fn compute(canonical_bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update([LEAF_PREFIX]);
        h.update(canonical_bytes);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        Self(out)
    }

    /// Hex-encode digest.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl NodeHash {
    /// Compute RFC 6962 interior node digest with `0x01` domain prefix.
    pub fn combine(left: [u8; 32], right: [u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update([NODE_PREFIX]);
        h.update(left);
        h.update(right);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        Self(out)
    }

    /// Hex-encode digest.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

/// Signed Tree Head (STH) authenticated with HMAC-SHA256.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// Number of leaves committed.
    pub tree_size: usize,
    /// UTC timestamp in seconds.
    pub timestamp_utc: i64,
    /// Root hash in lowercase hex.
    pub root_hash_hex: String,
    /// HMAC-SHA256 STH signature.
    pub signature_hex: String,
}

/// SQLite WAL-backed Binary Merkle Transparency Log.
pub struct MerkleLog {
    storage: Arc<SqliteStorage>,
    sth_key: KeyMaterial,
}

impl MerkleLog {
    /// Create a Merkle log over shared SQLite storage.
    pub fn new(storage: Arc<SqliteStorage>, sth_key: KeyMaterial) -> Self {
        Self { storage, sth_key }
    }

    /// Compute Merkle Tree Hash (`MTH`) over leaf digests.
    pub fn mth(leaves: &[LeafHash]) -> NodeHash {
        let raw: Vec<[u8; 32]> = leaves.iter().map(|l| l.0).collect();
        NodeHash(Self::mth_raw(&raw))
    }

    pub(crate) fn mth_raw(hashes: &[[u8; 32]]) -> [u8; 32] {
        let n = hashes.len();
        if n == 0 {
            let d = Sha256::digest(b"");
            let mut out = [0u8; 32];
            out.copy_from_slice(&d);
            return out;
        }
        if n == 1 {
            return hashes[0];
        }
        let k = largest_pow2_lt(n);
        NodeHash::combine(Self::mth_raw(&hashes[..k]), Self::mth_raw(&hashes[k..])).0
    }

    /// Atomically append a JSON event, returning `(leaf_index, LeafHash, SignedTreeHead)`.
    pub fn append(&self, event: &Value) -> AppResult<(usize, LeafHash, SignedTreeHead)> {
        let payload = jcs_bytes(event)?;
        let lhash = LeafHash::compute(&payload);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let conn = self.storage.get_conn()?;
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| AppError::Storage(e.to_string()))?;

        let idx: usize = conn
            .query_row("SELECT COUNT(*) FROM merkle_leaves;", [], |r| r.get::<_, i64>(0))
            .map_err(|e| {
                let _ = conn.execute_batch("ROLLBACK;");
                AppError::Storage(e.to_string())
            })? as usize;

        if let Err(e) = conn.execute(
            "INSERT INTO merkle_leaves (leaf_index, created_at, payload_jcs, leaf_hash) VALUES (?1, ?2, ?3, ?4);",
            params![idx as i64, now, payload, lhash.0.as_slice()],
        ) {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(AppError::Storage(e.to_string()));
        }

        let all_hashes = self.load_hashes(&conn)?;
        let tree_size = all_hashes.len();
        let root_hex = hex::encode(Self::mth_raw(&all_hashes));
        let sig_body = jcs_bytes(&json!({
            "tree_size": tree_size,
            "timestamp_utc": now,
            "root_hash_hex": root_hex,
        }))?;
        let sig_hex = hmac_sha256_hex(self.sth_key.as_bytes(), STH_DOMAIN, &sig_body);

        let _ = conn.execute(
            "INSERT INTO merkle_sths (tree_size, timestamp_utc, root_hash_hex, signature_hex) VALUES (?1, ?2, ?3, ?4);",
            params![tree_size as i64, now, root_hex, sig_hex],
        );

        conn.execute_batch("COMMIT;")
            .map_err(|e| AppError::Storage(e.to_string()))?;

        Ok((
            idx,
            lhash,
            SignedTreeHead {
                tree_size,
                timestamp_utc: now,
                root_hash_hex: root_hex,
                signature_hex: sig_hex,
            },
        ))
    }

    fn load_hashes(&self, conn: &rusqlite::Connection) -> AppResult<Vec<[u8; 32]>> {
        let mut stmt = conn
            .prepare("SELECT leaf_hash FROM merkle_leaves ORDER BY leaf_index ASC;")
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for b in rows.filter_map(Result::ok) {
            if b.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                out.push(arr);
            }
        }
        Ok(out)
    }

    /// Generate an `O(log N)` inclusion proof for `leaf_index`.
    pub fn inclusion_proof(&self, leaf_index: usize) -> AppResult<(Vec<String>, SignedTreeHead, Vec<u8>)> {
        let conn = self.storage.get_conn()?;
        let hashes = self.load_hashes(&conn)?;
        if leaf_index >= hashes.len() {
            return Err(AppError::NotFound(format!("merkle_leaf:{leaf_index}")));
        }
        let payload: Vec<u8> = conn
            .query_row(
                "SELECT payload_jcs FROM merkle_leaves WHERE leaf_index = ?1;",
                params![leaf_index as i64],
                |r| r.get(0),
            )
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let sth = self.latest_sth()?;
        let path: Vec<String> = audit_path(leaf_index, &hashes)
            .into_iter()
            .map(hex::encode)
            .collect();
        Ok((path, sth, payload))
    }

    /// Retrieve the latest Signed Tree Head.
    pub fn latest_sth(&self) -> AppResult<SignedTreeHead> {
        let conn = self.storage.get_conn()?;
        conn.query_row(
            "SELECT tree_size, timestamp_utc, root_hash_hex, signature_hex FROM merkle_sths ORDER BY tree_size DESC LIMIT 1;",
            [],
            |r| {
                Ok(SignedTreeHead {
                    tree_size: r.get::<_, i64>(0)? as usize,
                    timestamp_utc: r.get(1)?,
                    root_hash_hex: r.get(2)?,
                    signature_hex: r.get(3)?,
                })
            },
        )
        .map_err(|_| AppError::NotFound("merkle_sth_empty".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane1::merkle::proof::verify_inclusion_hex;
    use tempfile::tempdir;

    #[test]
    fn inclusion_proof_roundtrip_and_tamper_rejected() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(SqliteStorage::open(&dir.path().join("m.db")).unwrap());
        let log = MerkleLog::new(storage, KeyMaterial::generate());
        for i in 0..32 {
            let _ = log.append(&json!({"i": i})).unwrap();
        }
        let (proof, sth, payload) = log.inclusion_proof(11).unwrap();
        assert!(verify_inclusion_hex(&payload, 11, sth.tree_size, &proof, &sth.root_hash_hex));
        assert!(!verify_inclusion_hex(b"{\"i\":999}", 11, sth.tree_size, &proof, &sth.root_hash_hex));
    }
}
