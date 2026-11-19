"""Tests for NOSIH's 3 Deep Cross-Plane Novelties:
1. PCSP (Provenance-Coupled Carbon-Security Pricing & Carbon-Denial-of-Wallet defense)
2. CCEC (Cryptographic Carbon-Attested Execution Certificates on RFC 6962/9162 MTLog)
3. PA-PCS-PMC (Authorization-Gated Sleep-Thrashing DoS defense & Carbon-Modulated Hysteresis)
"""
import secrets
import tempfile
import unittest
from pathlib import Path

from nosih.plane1_security.carbon_cert import CarbonAuditReceipt, CarbonCertificateAuthority
from nosih.plane1_security.merkle_log import MerkleTransparencyLog
from nosih.plane1_security.postw_v3 import IntegrityLevel
from nosih.plane2_control.pcsp import ProvenanceCoupledCarbonSecurityPricer
from nosih.plane3_execution.hardware_probe import probe_hardware_environment
from nosih.plane3_execution.power_carbon import (
    DEFAULT_TIER_PROFILES,
    PowerState,
    PredictivePowerController,
)


class TestCrossPlaneNovelties(unittest.TestCase):
    def test_pcsp_blocks_untrusted_carbon_denial_of_wallet_escalation(self):
        pcsp = ProvenanceCoupledCarbonSecurityPricer()
        # Untrusted input attempting to force T3_LARGE during evening fossil peak (490 gCO2/kWh)
        dec_no_sym = pcsp.arbitrate_tier(
            proposed_tier="T3_LARGE",
            integrity=IntegrityLevel.UNTRUSTED,
            carbon_gco2_kwh=490.0,
            has_escalation_capability=False,
            has_symbolic_fallback=False,
        )
        self.assertTrue(dec_no_sym.was_cdow_mitigated)
        self.assertEqual(dec_no_sym.selected_tier, "T1_SMALL")
        self.assertEqual(dec_no_sym.effective_alpha, 0.025)

        # Untrusted input with symbolic cues quarantined directly to <5W CPU symbolic tier
        dec_sym = pcsp.arbitrate_tier(
            proposed_tier="T3_LARGE",
            integrity=IntegrityLevel.UNTRUSTED,
            carbon_gco2_kwh=490.0,
            has_escalation_capability=False,
            has_symbolic_fallback=True,
        )
        self.assertTrue(dec_sym.was_cdow_mitigated)
        self.assertEqual(dec_sym.selected_tier, "T0b_SYMBOLIC")

        # Cryptographically authorized request is permitted on T3_LARGE
        dec_auth = pcsp.arbitrate_tier(
            proposed_tier="T3_LARGE",
            integrity=IntegrityLevel.SIGNED_ERP,
            carbon_gco2_kwh=490.0,
            has_escalation_capability=True,
        )
        self.assertFalse(dec_auth.was_cdow_mitigated)
        self.assertEqual(dec_auth.selected_tier, "T3_LARGE")

    def test_ccec_merkle_carbon_certificate_tamper_detection_and_honesty(self):
        with tempfile.TemporaryDirectory() as td:
            key = secrets.token_bytes(32)
            mt = MerkleTransparencyLog(Path(td) / "ccec.db", sth_signing_key=key)
            hw = probe_hardware_environment()
            ca = CarbonCertificateAuthority(mt, hw)
            receipt = ca.issue_certificate(
                request_id="req-ccec-1",
                tenant_id="tenant-alpha",
                tier_executed="T0b_SYMBOLIC",
                integrity_level="DERIVED_DET",
                accounting_mode="HYBRID_CPU_TDP",
                execution_mode="CALIBRATED_TRACE_SIM",
                energy_kwh=0.000000005,
                grid_carbon_gco2_kwh=210.0,
                co2_g=0.000001,
                cost_usd=0.0,
                provenance_digest="abc123",
            )
            ok, msg = CarbonCertificateAuthority.verify_receipt(receipt, ca.hardware_attestation_digest)
            self.assertTrue(ok, msg)

            # Strict hardware-only ESG audit must reject simulated accounting_mode honestly
            ok_strict, msg_strict = CarbonCertificateAuthority.verify_receipt(
                receipt, ca.hardware_attestation_digest, require_hardware_metering=True
            )
            self.assertFalse(ok_strict)
            self.assertIn("simulated_accounting_rejected", msg_strict)

            # Tampering with reported CO2 invalidates O(log N) Merkle inclusion proof
            tampered_cert = dict(receipt.certificate)
            tampered_cert["co2_g"] = 0.0
            bad_receipt = CarbonAuditReceipt(
                certificate=tampered_cert,
                leaf_index=receipt.leaf_index,
                tree_size=receipt.tree_size,
                root_hash_hex=receipt.root_hash_hex,
                sth_signature_hex=receipt.sth_signature_hex,
                inclusion_proof=receipt.inclusion_proof,
            )
            ok_bad, _ = CarbonCertificateAuthority.verify_receipt(bad_receipt)
            self.assertFalse(ok_bad)

    def test_pa_pcs_pmc_blocks_sleep_thrashing_dos_and_modulates_by_carbon(self):
        # 1. Sleep-Thrashing DoS: unauthorized requests must NOT wake a DEEP_SLEEP GPU (0.0 J wasted)
        pmc = PredictivePowerController(DEFAULT_TIER_PROFILES["T3_LARGE"])
        pmc.state = PowerState.DEEP_SLEEP
        for i in range(20):
            wlat, wj = pmc.on_authorized_request_arrival(100.0 + i, authorized=False)
            self.assertEqual(wlat, 0.0)
            self.assertEqual(wj, 0.0)
            self.assertEqual(pmc.state, PowerState.DEEP_SLEEP)
        self.assertEqual(pmc.blocked_unauthorized_wakeups, 20)
        self.assertAlmostEqual(pmc.saved_unauthorized_wake_j, 20 * 175.0, places=2)

        # 2. Carbon-Modulated Hysteresis: fossil peak (500 gCO2/kWh) demotes faster than solar valley (190 gCO2/kWh)
        pmc_peak = PredictivePowerController(DEFAULT_TIER_PROFILES["T3_LARGE"])
        pmc_solar = PredictivePowerController(DEFAULT_TIER_PROFILES["T3_LARGE"])
        # Advance both to an intermediate idle window where peak demotes but solar stays ACTIVE
        t_probe = 1.4
        st_peak = pmc_peak.evaluate_idle_transition(t_probe, carbon_gco2_kwh=500.0)
        st_solar = pmc_solar.evaluate_idle_transition(t_probe, carbon_gco2_kwh=190.0)
        self.assertEqual(st_peak, PowerState.WARM_STANDBY)
        self.assertEqual(st_solar, PowerState.ACTIVE)


if __name__ == "__main__":
    unittest.main()
