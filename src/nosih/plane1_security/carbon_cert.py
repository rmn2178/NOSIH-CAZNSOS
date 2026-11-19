"""Cryptographic Carbon-Attested Execution Certificates (CCEC) for NOSIH.

Binds Plane III physical/simulated energy & Scope-2 carbon accounting directly into
Plane I's RFC 8785 JCS canonicalization and RFC 6962/9162 Binary Merkle Transparency Log
for O(log N) tamper-evident ESG auditability.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from .jcs_v3 import jcs_dumps
from .merkle_log import MerkleTransparencyLog, SignedTreeHead


@dataclass(frozen=True)
class CarbonAuditReceipt:
    certificate: Dict[str, Any]
    leaf_index: int
    tree_size: int
    root_hash_hex: str
    sth_signature_hex: str
    inclusion_proof: List[str]


class CarbonCertificateAuthority:
    """Issues and verifies tamper-evident Scope-2 Carbon Execution Certificates on MTLog."""

    def __init__(
        self,
        merkle_log: MerkleTransparencyLog,
        hardware_env: Dict[str, Any],
    ) -> None:
        self.merkle_log = merkle_log
        self.hardware_attestation_digest = hashlib.sha256(
            jcs_dumps(hardware_env).encode("utf-8")
        ).hexdigest()

    def issue_certificate(
        self,
        request_id: str,
        tenant_id: str,
        tier_executed: str,
        integrity_level: str,
        accounting_mode: str,
        execution_mode: str,
        energy_kwh: float,
        grid_carbon_gco2_kwh: float,
        co2_g: float,
        cost_usd: float,
        provenance_digest: str,
    ) -> CarbonAuditReceipt:
        """Append a canonical RFC 8785 JCS carbon certificate to MTLog and return O(log N) receipt."""
        cert = {
            "cert_type": "NOSIH_CCEC_V1",
            "request_id": request_id,
            "tenant_id": tenant_id,
            "tier_executed": tier_executed,
            "integrity_level": integrity_level,
            "accounting_mode": accounting_mode,
            "execution_mode": execution_mode,
            "energy_kwh": round(float(energy_kwh), 9),
            "grid_carbon_gco2_kwh": round(float(grid_carbon_gco2_kwh), 3),
            "co2_g": round(float(co2_g), 6),
            "cost_usd": round(float(cost_usd), 8),
            "hardware_attestation_digest": self.hardware_attestation_digest,
            "provenance_digest": provenance_digest,
            "issued_at_unix": round(time.time(), 3),
        }
        leaf_idx, _, sth = self.merkle_log.append(cert)
        proof = self.merkle_log.inclusion_proof(leaf_idx, sth.tree_size)
        return CarbonAuditReceipt(
            certificate=cert,
            leaf_index=leaf_idx,
            tree_size=sth.tree_size,
            root_hash_hex=sth.root_hash_hex,
            sth_signature_hex=sth.signature_hex,
            inclusion_proof=proof,
        )

    @staticmethod
    def verify_receipt(
        receipt: CarbonAuditReceipt,
        expected_hardware_digest: str | None = None,
        require_hardware_metering: bool = False,
    ) -> Tuple[bool, str]:
        """Verify O(log N) Merkle inclusion and accounting-mode honesty for an ESG auditor."""
        cert = receipt.certificate
        if require_hardware_metering and cert.get("accounting_mode") != "HARDWARE_NVML_RAPL":
            return False, "simulated_accounting_rejected_under_strict_hardware_audit"
        if expected_hardware_digest and cert.get("hardware_attestation_digest") != expected_hardware_digest:
            return False, "hardware_attestation_digest_mismatch"
        canonical_bytes = jcs_dumps(cert).encode("utf-8")
        ok = MerkleTransparencyLog.verify_inclusion(
            canonical_bytes,
            receipt.leaf_index,
            receipt.tree_size,
            receipt.inclusion_proof,
            receipt.root_hash_hex,
        )
        return (True, "verified") if ok else (False, "merkle_inclusion_failed")
