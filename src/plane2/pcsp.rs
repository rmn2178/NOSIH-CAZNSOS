//! PCSP: Provenance-Coupled Carbon-Security Pricing (Cross-Plane Primitive #1).

use crate::types::carbon::CarbonIntensity;
use crate::types::energy::ModelTier;
use crate::types::integrity::IntegrityRank;

/// Cross-plane pricer injecting Plane I taint into Plane II's carbon-routing Lagrangian.
#[derive(Debug, Clone)]
pub struct PcspPricer {
    /// Coupling weight `lambda_sec` (default `2.5`).
    pub lambda_sec: f64,
    /// Reference grid carbon intensity `C_ref` (default `340.0`).
    pub carbon_ref: f64,
    /// Cumulative C-DoW mitigations applied.
    pub cdow_mitigations: u64,
}

impl PcspPricer {
    /// Create with paper default parameters.
    pub fn new_default() -> Self {
        Self {
            lambda_sec: 2.5,
            carbon_ref: 340.0,
            cdow_mitigations: 0,
        }
    }

    /// Compute `Phi_PCSP(iota, a, C(t)) = lambda_sec * (iota/6) * (P_a/P_T3) * (C(t)/C_ref)`.
    pub fn penalty(&self, integrity: IntegrityRank, tier: ModelTier, carbon: CarbonIntensity) -> f64 {
        let rho = (integrity.rank() as f64 / 6.0).clamp(0.0, 1.0);
        let p_norm = tier.power_weight_norm();
        let c_mult = (carbon.gco2_per_kwh / self.carbon_ref.max(1.0)).max(0.5);
        self.lambda_sec * rho * p_norm * c_mult
    }

    /// Compute 5-arm penalty vector for `CA-DPD-LinUCB`.
    pub fn penalty_vector(&self, integrity: IntegrityRank, carbon: CarbonIntensity) -> [f64; 5] {
        [
            self.penalty(integrity, ModelTier::Cache, carbon),
            self.penalty(integrity, ModelTier::Symbolic, carbon),
            self.penalty(integrity, ModelTier::Small, carbon),
            self.penalty(integrity, ModelTier::Medium, carbon),
            self.penalty(integrity, ModelTier::Large, carbon),
        ]
    }

    /// Arbitrate proposed tier: hard-caps unauthenticated `Untrusted` callers at `Small` or `Symbolic`.
    pub fn arbitrate(
        &mut self,
        proposed: ModelTier,
        integrity: IntegrityRank,
        carbon: CarbonIntensity,
        has_symbolic: bool,
    ) -> (ModelTier, bool) {
        if integrity == IntegrityRank::Untrusted
            && matches!(proposed, ModelTier::Medium | ModelTier::Large)
        {
            self.cdow_mitigations += 1;
            let safe = if has_symbolic {
                ModelTier::Symbolic
            } else {
                ModelTier::Small
            };
            return (safe, true);
        }
        if integrity >= IntegrityRank::UserDirect
            && proposed == ModelTier::Large
            && carbon.gco2_per_kwh > 440.0
        {
            return (ModelTier::Medium, false);
        }
        (proposed, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::carbon::CarbonSource;

    #[test]
    fn untrusted_capped_at_small() {
        let mut p = PcspPricer::new_default();
        let c = CarbonIntensity { gco2_per_kwh: 490.0, source: CarbonSource::Forecast };
        let (tier, mitigated) = p.arbitrate(ModelTier::Large, IntegrityRank::Untrusted, c, false);
        assert!(mitigated);
        assert_eq!(tier, ModelTier::Small);
    }
}
