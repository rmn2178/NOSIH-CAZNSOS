//! POST-W++ Commutative Provenance Semiring over Integrity x Confidentiality.

use crate::types::confidentiality::{ConfidentialityRank, intersect_readers};
use crate::types::integrity::IntegrityRank;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Runtime semiring label `tau(v) = (integrity, conf, readers, deriv_hash)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemiringLabel {
    /// Integrity rank (`0..=6`).
    pub integrity: IntegrityRank,
    /// Confidentiality tier (`0..=3`).
    pub confidentiality: ConfidentialityRank,
    /// Authorized reader principals (`"*"` = universal).
    pub readers: BTreeSet<String>,
    /// Commutative derivation digest.
    pub deriv_hash: String,
}

impl SemiringLabel {
    /// Multiplicative identity `1 = (HUMAN, PUBLIC, {*})`.
    pub fn one() -> Self {
        let mut readers = BTreeSet::new();
        readers.insert("*".to_string());
        Self {
            integrity: IntegrityRank::HumanApproval,
            confidentiality: ConfidentialityRank::Public,
            readers,
            deriv_hash: hex::encode(Sha256::digest(b"NOSIH-SEMIRING-ONE")),
        }
    }

    /// Absorber `0 = (UNTRUSTED, RESTRICTED_PII, {})`.
    pub fn zero() -> Self {
        Self {
            integrity: IntegrityRank::Untrusted,
            confidentiality: ConfidentialityRank::RestrictedPii,
            readers: BTreeSet::new(),
            deriv_hash: hex::encode(Sha256::digest(b"NOSIH-SEMIRING-ZERO")),
        }
    }

    /// Construct from origin integrity and confidentiality.
    pub fn from_origin(integrity: IntegrityRank, confidentiality: ConfidentialityRank) -> Self {
        let mut readers = BTreeSet::new();
        readers.insert("*".to_string());
        let seed = format!("{}:{}", integrity.rank(), confidentiality as u8);
        Self {
            integrity,
            confidentiality,
            readers,
            deriv_hash: hex::encode(Sha256::digest(seed.as_bytes())),
        }
    }

    /// Commutative & associative semiring join (`mul` / tensor composition).
    pub fn join(&self, other: &Self) -> Self {
        let (a, b) = if self.deriv_hash <= other.deriv_hash {
            (&self.deriv_hash, &other.deriv_hash)
        } else {
            (&other.deriv_hash, &self.deriv_hash)
        };
        let mut h = Sha256::new();
        h.update(b"JOIN\x00");
        h.update(a.as_bytes());
        h.update(b.as_bytes());
        Self {
            integrity: self.integrity.join(other.integrity),
            confidentiality: self.confidentiality.join(other.confidentiality),
            readers: intersect_readers(&self.readers, &other.readers),
            deriv_hash: hex::encode(h.finalize()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_is_commutative_and_untrusted_absorbs() {
        let a = SemiringLabel::from_origin(IntegrityRank::SignedErp, ConfidentialityRank::ConfidentialFin);
        let b = SemiringLabel::from_origin(IntegrityRank::Untrusted, ConfidentialityRank::Public);
        assert_eq!(a.join(&b), b.join(&a));
        assert_eq!(a.join(&b).integrity, IntegrityRank::Untrusted);
        assert_eq!(a.join(&b).confidentiality, ConfidentialityRank::ConfidentialFin);
    }
}
