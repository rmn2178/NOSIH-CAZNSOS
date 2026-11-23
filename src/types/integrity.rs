//! Compile-time and runtime Integrity Lattice (`HUMAN(0) < ... < UNTRUSTED(6)`).

use serde::{Deserialize, Serialize};

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::HumanApproval {}
    impl Sealed for super::VerifiedGovApi {}
    impl Sealed for super::SignedErp {}
    impl Sealed for super::SystemPolicy {}
    impl Sealed for super::UserDirect {}
    impl Sealed for super::DerivedDet {}
    impl Sealed for super::Untrusted {}
}

/// Sealed compile-time integrity marker trait.
pub trait IntegrityLevel: sealed::Sealed + Copy + Send + Sync + 'static {
    /// Numeric lattice rank (0 = highest integrity, 6 = UNTRUSTED).
    const RANK: u8;
    /// Runtime enum equivalent.
    const RUNTIME: IntegrityRank;
}

/// Rank 0: Human approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanApproval;
impl IntegrityLevel for HumanApproval {
    const RANK: u8 = 0;
    const RUNTIME: IntegrityRank = IntegrityRank::HumanApproval;
}

/// Rank 1: Verified government API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedGovApi;
impl IntegrityLevel for VerifiedGovApi {
    const RANK: u8 = 1;
    const RUNTIME: IntegrityRank = IntegrityRank::VerifiedGovApi;
}

/// Rank 2: Signed ERP ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedErp;
impl IntegrityLevel for SignedErp {
    const RANK: u8 = 2;
    const RUNTIME: IntegrityRank = IntegrityRank::SignedErp;
}

/// Rank 3: System policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemPolicy;
impl IntegrityLevel for SystemPolicy {
    const RANK: u8 = 3;
    const RUNTIME: IntegrityRank = IntegrityRank::SystemPolicy;
}

/// Rank 4: Direct authenticated user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserDirect;
impl IntegrityLevel for UserDirect {
    const RANK: u8 = 4;
    const RUNTIME: IntegrityRank = IntegrityRank::UserDirect;
}

/// Rank 5: Deterministically derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedDet;
impl IntegrityLevel for DerivedDet {
    const RANK: u8 = 5;
    const RUNTIME: IntegrityRank = IntegrityRank::DerivedDet;
}

/// Rank 6: Untrusted external input (absorber).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Untrusted;
impl IntegrityLevel for Untrusted {
    const RANK: u8 = 6;
    const RUNTIME: IntegrityRank = IntegrityRank::Untrusted;
}

/// Runtime integrity rank mirror (lower = more trusted; join = max).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IntegrityRank {
    /// Rank 0.
    HumanApproval = 0,
    /// Rank 1.
    VerifiedGovApi = 1,
    /// Rank 2.
    SignedErp = 2,
    /// Rank 3.
    SystemPolicy = 3,
    /// Rank 4.
    UserDirect = 4,
    /// Rank 5.
    DerivedDet = 5,
    /// Rank 6.
    Untrusted = 6,
}

impl IntegrityRank {
    /// Parse from a verified `X-NOSIH-Origin` header value.
    pub fn from_origin(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "human" | "human_approval" => Self::HumanApproval,
            "gov" | "verified_gov_api" => Self::VerifiedGovApi,
            "erp" | "signed_erp" => Self::SignedErp,
            "policy" | "system_policy" => Self::SystemPolicy,
            "user" | "user_direct" => Self::UserDirect,
            "det" | "derived_det" => Self::DerivedDet,
            _ => Self::Untrusted,
        }
    }

    /// Parse an unauthenticated/client-asserted `X-NOSIH-Origin`, capping trust at `UserDirect`.
    pub fn from_unverified_origin(s: &str) -> Self {
        Self::from_origin(s).join(Self::UserDirect)
    }

    /// Lattice join (`max`).
    pub fn join(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }

    /// Numeric rank in `0..=6`.
    pub fn rank(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverified_origin_cannot_escalate_above_user_direct() {
        assert_eq!(
            IntegrityRank::from_unverified_origin("human"),
            IntegrityRank::UserDirect
        );
        assert_eq!(
            IntegrityRank::from_unverified_origin("erp"),
            IntegrityRank::UserDirect
        );
        assert_eq!(
            IntegrityRank::from_unverified_origin("untrusted"),
            IntegrityRank::Untrusted
        );
    }
}
