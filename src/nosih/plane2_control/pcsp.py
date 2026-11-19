"""Provenance-Coupled Carbon-Security Pricer (PCSP) for NOSIH.

Couples Plane I Provenance Semiring integrity levels directly into Plane II
CA-DPD-LinUCB routing and Dual-Channel Conformal PID risk control to defeat
Carbon-Denial-of-Wallet (C-DoW) adversarial amplification attacks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from ..plane1_security.postw_v3 import IntegrityLevel


# Relative tier power weights (normalized against T3_LARGE = 175W)
TIER_POWER_NORM: Dict[str, float] = {
    "T0a_CACHE": 0.014,
    "T0b_SYMBOLIC": 0.026,
    "T1_SMALL": 0.297,
    "T2_MEDIUM": 0.657,
    "T3_LARGE": 1.000,
}


@dataclass(frozen=True)
class PCSPDecision:
    selected_tier: str
    was_cdow_mitigated: bool
    taint_penalty: float
    effective_alpha: float
    reason: str


class ProvenanceCoupledCarbonSecurityPricer:
    """Enforces cross-plane coupling between Plane I taint and Plane II carbon/energy routing.

    Key Invariant (Carbon-Denial-of-Wallet Defense):
      Untrusted inputs (IntegrityLevel.UNTRUSTED) without an explicit cryptographic
      escalation capability cannot trigger speculative T2/T3 GPU escalation. If symbolic
      cues are present, they are quarantined onto <5W CPU symbolic operators; otherwise
      they are capped at T1_SMALL with tightened conformal risk alpha_eff = alpha / 2.
    """

    def __init__(
        self,
        lambda_sec: float = 2.5,
        carbon_ref_gco2_kwh: float = 340.0,
        base_alpha: float = 0.05,
    ) -> None:
        self.lambda_sec = lambda_sec
        self.carbon_ref = carbon_ref_gco2_kwh
        self.base_alpha = base_alpha
        self.cdow_mitigations: int = 0

    def taint_risk_factor(self, integrity: IntegrityLevel) -> float:
        """Map IntegrityLevel rank (0=highest trust .. 6=UNTRUSTED) to [0.0, 1.0]."""
        return min(1.0, max(0.0, float(integrity.value) / float(IntegrityLevel.UNTRUSTED.value)))

    def tier_penalty(
        self,
        integrity: IntegrityLevel,
        tier: str,
        carbon_gco2_kwh: float,
    ) -> float:
        """Cross-plane Lagrangian penalty: lambda_sec * rho_taint(iota) * P_norm(tier) * (C(t)/C_ref)."""
        rho = self.taint_risk_factor(integrity)
        p_norm = TIER_POWER_NORM.get(tier, 1.0)
        c_mult = max(0.5, carbon_gco2_kwh / max(1.0, self.carbon_ref))
        return round(self.lambda_sec * rho * p_norm * c_mult, 6)

    def effective_conformal_alpha(self, integrity: IntegrityLevel) -> float:
        """Tighten selective risk budget under untrusted provenance."""
        if integrity == IntegrityLevel.UNTRUSTED:
            return round(self.base_alpha * 0.5, 4)
        if integrity.value >= IntegrityLevel.DERIVED_DET.value:
            return round(self.base_alpha * 0.75, 4)
        return self.base_alpha

    def arbitrate_tier(
        self,
        proposed_tier: str,
        integrity: IntegrityLevel,
        carbon_gco2_kwh: float,
        has_escalation_capability: bool = False,
        has_symbolic_fallback: bool = False,
    ) -> PCSPDecision:
        """Arbitrate proposed neural/symbolic tier under Plane I provenance & Plane II carbon."""
        eff_alpha = self.effective_conformal_alpha(integrity)
        pen = self.tier_penalty(integrity, proposed_tier, carbon_gco2_kwh)

        # C-DoW Invariant: block unauthenticated untrusted escalation to high-wattage GPUs
        if (
            integrity == IntegrityLevel.UNTRUSTED
            and not has_escalation_capability
            and proposed_tier in ("T2_MEDIUM", "T3_LARGE")
        ):
            self.cdow_mitigations += 1
            safe_tier = "T0b_SYMBOLIC" if has_symbolic_fallback else "T1_SMALL"
            return PCSPDecision(
                selected_tier=safe_tier,
                was_cdow_mitigated=True,
                taint_penalty=pen,
                effective_alpha=eff_alpha,
                reason=f"cdow_cap_untrusted:{proposed_tier}->{safe_tier}",
            )

        # Carbon-peak soft de-escalation for derived/medium-trust T3 requests
        if (
            integrity.value >= IntegrityLevel.USER_DIRECT.value
            and proposed_tier == "T3_LARGE"
            and carbon_gco2_kwh > 440.0
            and not has_escalation_capability
        ):
            return PCSPDecision(
                selected_tier="T2_MEDIUM",
                was_cdow_mitigated=False,
                taint_penalty=pen,
                effective_alpha=eff_alpha,
                reason="carbon_peak_lagrangian_downshift",
            )

        return PCSPDecision(
            selected_tier=proposed_tier,
            was_cdow_mitigated=False,
            taint_penalty=pen,
            effective_alpha=eff_alpha,
            reason="approved",
        )
