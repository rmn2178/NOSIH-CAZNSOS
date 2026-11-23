//! Deterministic energy proxy (`EnergyWh`) for model classes and connection warmups.

use serde::{Deserialize, Serialize};

/// Energy quantity in Watt-hours (`Wh`).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default, Serialize, Deserialize)]
pub struct EnergyWh(pub f64);

/// Execution tier class mapped from NOSIH paper tiers `{T0a, T0b, T1, T2, T3}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelTier {
    /// T0a: Provenance-scoped semantic cache (`PS-RCSC`).
    Cache,
    /// T0b: CPU-only symbolic engines (`SafeDecimalAST` / TF-IDF RAG).
    Symbolic,
    /// T1: Small fast model (`nosih-small`).
    Small,
    /// T2: Medium balanced model (`nosih-medium`).
    Medium,
    /// T3: Large frontier model (`nosih-large`).
    Large,
}

impl ModelTier {
    /// Canonical tier name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "T0a_CACHE",
            Self::Symbolic => "T0b_SYMBOLIC",
            Self::Small => "T1_SMALL",
            Self::Medium => "T2_MEDIUM",
            Self::Large => "T3_LARGE",
        }
    }

    /// Arm index for CA-DPD-LinUCB bandit.
    pub fn arm_index(self) -> usize {
        match self {
            Self::Cache => 0,
            Self::Symbolic => 1,
            Self::Small => 2,
            Self::Medium => 3,
            Self::Large => 4,
        }
    }

    /// Construct from bandit arm index.
    pub fn from_arm(idx: usize) -> Self {
        match idx {
            0 => Self::Cache,
            1 => Self::Symbolic,
            2 => Self::Small,
            3 => Self::Medium,
            _ => Self::Large,
        }
    }

    /// Published proxy Wh per 1,000 tokens for deterministic Scope-2 estimation.
    pub fn proxy_wh_per_1k_tokens(self) -> f64 {
        match self {
            Self::Cache => 0.0005,
            Self::Symbolic => 0.0012,
            Self::Small => 0.045,
            Self::Medium => 0.140,
            Self::Large => 0.380,
        }
    }

    /// Normalized relative power weight (`P_a / P_T3`) used by PCSP.
    pub fn power_weight_norm(self) -> f64 {
        match self {
            Self::Cache => 0.014,
            Self::Symbolic => 0.026,
            Self::Small => 0.297,
            Self::Medium => 0.657,
            Self::Large => 1.000,
        }
    }
}

impl EnergyWh {
    /// Convert Watt-hours to kilowatt-hours (`kWh`).
    pub fn to_kwh(self) -> f64 {
        self.0 / 1000.0
    }

    /// Convert Joules to Watt-hours (`Wh`).
    pub fn from_joules(j: f64) -> Self {
        Self(j / 3600.0)
    }
}
