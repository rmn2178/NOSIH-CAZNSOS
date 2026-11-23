//! Unified 7-Stage Closed-Loop NOSIH Kernel orchestrating Planes I, II, and III.

pub mod request;
pub mod stage1_ingress;
pub mod stage2_cache;
pub mod stage3_dispatch;
pub mod stage4_verify;
pub mod stage5_mint;
pub mod stage6_execute;
pub mod stage7_update;
pub mod trace;

use crate::plane1::budget::BudgetLedger;
use crate::plane1::carbon_cert::CarbonCertificateAuthority;
use crate::plane1::macaroon::chain::MacaroonAuthority;
use crate::plane1::manifest::ManifestGuard;
use crate::plane1::merkle::MerkleLog;
use crate::plane2::bandit::linucb::CaDpdLinUcb;
use crate::plane2::cache::store::ProvenanceCache;
use crate::plane2::carbon::forecaster::DiurnalCarbonForecaster;
use crate::plane2::conformal::pid::ConformalPidGate;
use crate::plane2::pcsp::PcspPricer;
use crate::plane3::power::controller::ProviderPowerManager;
use crate::telemetry::log_ring::LogRing;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Unified Tri-Plane NOSIH Kernel.
pub struct NosihKernel {
    /// Plane I Macaroon capability authority.
    pub macaroon: Arc<MacaroonAuthority>,
    /// Plane I RFC 6962/9162 Merkle transparency log.
    pub merkle: Arc<MerkleLog>,
    /// Plane I CCEC carbon certificate authority.
    pub ccec: Arc<CarbonCertificateAuthority>,
    /// Plane I boot-signed manifest guard.
    pub manifest: Arc<ManifestGuard>,
    /// Plane I exact-decimal budget ledger.
    pub budget: Arc<BudgetLedger>,
    /// Plane II PS-RCSC semantic cache.
    pub cache: Arc<RwLock<ProvenanceCache>>,
    /// Plane II CA-DPD-LinUCB bandit.
    pub bandit: Arc<RwLock<CaDpdLinUcb>>,
    /// Plane II Dual-Channel Conformal PID gate.
    pub conformal: Arc<RwLock<ConformalPidGate>>,
    /// Plane II diurnal carbon forecaster.
    pub forecaster: Arc<RwLock<DiurnalCarbonForecaster>>,
    /// Plane II PCSP cross-plane pricer.
    pub pcsp: Arc<RwLock<PcspPricer>>,
    /// Plane III PA-PCS-PMC provider warm-state manager.
    pub power: Arc<RwLock<ProviderPowerManager>>,
    /// Telemetry ring buffer + SSE broadcaster.
    pub log_ring: Arc<LogRing>,
}
