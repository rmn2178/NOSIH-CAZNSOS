//! Compile-time and runtime Confidentiality Lattice (`PUBLIC(0) < ... < RESTRICTED_PII(3)`).

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Public {}
    impl Sealed for super::Internal {}
    impl Sealed for super::ConfidentialFin {}
    impl Sealed for super::RestrictedPii {}
}

/// Sealed compile-time confidentiality marker trait.
pub trait ConfidentialityLevel: sealed::Sealed + Copy + Send + Sync + 'static {
    /// Numeric sensitivity tier (0 = public, 3 = restricted PII).
    const TIER: u8;
    /// Runtime enum equivalent.
    const RUNTIME: ConfidentialityRank;
}

/// Tier 0: Public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Public;
impl ConfidentialityLevel for Public {
    const TIER: u8 = 0;
    const RUNTIME: ConfidentialityRank = ConfidentialityRank::Public;
}

/// Tier 1: Internal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Internal;
impl ConfidentialityLevel for Internal {
    const TIER: u8 = 1;
    const RUNTIME: ConfidentialityRank = ConfidentialityRank::Internal;
}

/// Tier 2: Confidential Financial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfidentialFin;
impl ConfidentialityLevel for ConfidentialFin {
    const TIER: u8 = 2;
    const RUNTIME: ConfidentialityRank = ConfidentialityRank::ConfidentialFin;
}

/// Tier 3: Restricted PII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestrictedPii;
impl ConfidentialityLevel for RestrictedPii {
    const TIER: u8 = 3;
    const RUNTIME: ConfidentialityRank = ConfidentialityRank::RestrictedPii;
}

/// Runtime confidentiality tier (join = max).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConfidentialityRank {
    /// Tier 0.
    Public = 0,
    /// Tier 1.
    Internal = 1,
    /// Tier 2.
    ConfidentialFin = 2,
    /// Tier 3.
    RestrictedPii = 3,
}

impl ConfidentialityRank {
    /// Lattice join (`max`).
    pub fn join(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }
}

/// Reader-set intersection helper where `"*"` represents universal readers `U`.
pub fn intersect_readers(a: &BTreeSet<String>, b: &BTreeSet<String>) -> BTreeSet<String> {
    if a.contains("*") {
        return b.clone();
    }
    if b.contains("*") {
        return a.clone();
    }
    a.intersection(b).cloned().collect()
}
