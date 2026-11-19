"""Authenticated CSDD Shadow-Sink Deception backed by MTLog Merkle inclusion proofs."""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any, Dict, List

from .jcs_v3 import jcs_bytes
from .merkle_log import MerkleTransparencyLog, SignedTreeHead


RECEIPT_DOMAIN = b"NOSIH-V3-SHADOW-RECEIPT\x00"


@dataclass(frozen=True)
class AuthenticatedShadowReceipt:
    receipt_body: Dict[str, Any]
    leaf_index: int
    sth: SignedTreeHead
    inclusion_proof: List[str]
    receipt_mac_hex: str


class CSDDShadowSinkV3:
    """Quarantines unauthorized sink calls and issues Merkle-anchored, MAC-authenticated receipts."""

    def __init__(self, merkle_log: MerkleTransparencyLog, receipt_key: bytes) -> None:
        if len(receipt_key) < 32:
            raise ValueError("Shadow receipt key must be >= 32 bytes")
        self.merkle_log = merkle_log
        self._key = bytes(receipt_key)

    def _compute_mac(self, body: Dict[str, Any], leaf_index: int, root_hash_hex: str) -> str:
        msg = jcs_bytes({"body": body, "leaf_index": leaf_index, "root_hash_hex": root_hash_hex})
        return hmac.new(self._key, RECEIPT_DOMAIN + msg, hashlib.sha256).hexdigest()

    def quarantine(
        self,
        tenant_id: str,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        reason: str,
        witness_digest: str,
    ) -> AuthenticatedShadowReceipt:
        body = {
            "event_type": "CSDD_SHADOW_QUARANTINE",
            "tenant_id": tenant_id,
            "session_id": session_id,
            "tool_name": tool_name,
            "reason": reason,
            "witness_digest": witness_digest,
            "nosih_quarantined": True,
            "real_effect_executed": False,
            "timestamp_utc": round(time.time(), 6),
            "suggested_policy_diff": f"DENY {tool_name} WHEN {reason} (requires human review)",
        }
        leaf_index, _, sth = self.merkle_log.append(body)
        proof = self.merkle_log.inclusion_proof(leaf_index, sth.tree_size)
        mac = self._compute_mac(body, leaf_index, sth.root_hash_hex)
        return AuthenticatedShadowReceipt(
            receipt_body=body,
            leaf_index=leaf_index,
            sth=sth,
            inclusion_proof=proof,
            receipt_mac_hex=mac,
        )

    def verify_receipt(self, receipt: AuthenticatedShadowReceipt) -> bool:
        expected_mac = self._compute_mac(
            receipt.receipt_body, receipt.leaf_index, receipt.sth.root_hash_hex
        )
        if not hmac.compare_digest(expected_mac, receipt.receipt_mac_hex):
            return False
        if not self.merkle_log.verify_sth_signature(receipt.sth):
            return False
        return MerkleTransparencyLog.verify_inclusion(
            leaf_payload_jcs=jcs_bytes(receipt.receipt_body),
            leaf_index=receipt.leaf_index,
            tree_size=receipt.sth.tree_size,
            proof_hex=receipt.inclusion_proof,
            expected_root_hex=receipt.sth.root_hash_hex,
        )
