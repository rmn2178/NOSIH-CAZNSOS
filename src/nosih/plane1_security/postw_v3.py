"""POST-W++: Algebraic Provenance Semiring & Confidentiality x Integrity IFC Lattice.

Closes prior orchestrators defects F-06, F-08, F-09, F-10, F-11:
- Commutative provenance semiring (K, +, *, 0, 1) over Integrity x Confidentiality product lattice
- Policy-bound origin assignment (never trusts server response 'origin' field)
- Exact Decimal arithmetic + SQLite WAL atomic linear monetary budgets (stops multi-payout & concurrent split-payout double-spend)
- Confidentiality-aware egress guard defending against plaintext, URL-safe/standard Base64, hex, and high-entropy exfiltration
- Value-committed witness_digest
"""
from __future__ import annotations

import base64
import hashlib
import math
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from .jcs_v3 import jcs_sha256


class IntegrityLevel(IntEnum):
    """Total order: lower integer = higher integrity; join = max."""
    HUMAN_APPROVAL = 0
    VERIFIED_GOV_API = 1
    SIGNED_ERP = 2
    SYSTEM_POLICY = 3
    USER_DIRECT = 4
    DERIVED_DET = 5
    UNTRUSTED = 6


class ConfidentialityTier(IntEnum):
    """Lower integer = less sensitive; join = max."""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL_FIN = 2
    RESTRICTED_PII = 3


@dataclass(frozen=True)
class WitnessAtom:
    server_id: str
    tool_name: str
    record_id: str
    field_name: str
    value_hash: str
    policy_origin: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "record_id": self.record_id,
            "field_name": self.field_name,
            "value_hash": self.value_hash,
            "policy_origin": self.policy_origin,
        }


@dataclass(frozen=True)
class ProvenanceLabel:
    """Semiring element tau(v) = (integrity, conf_tier, readers, witnesses, deriv_hash)."""
    integrity: IntegrityLevel
    conf_tier: ConfidentialityTier
    readers: FrozenSet[str]  # frozenset({"*"}) represents universal reader set U
    witnesses: FrozenSet[WitnessAtom]
    deriv_hash: str

    @classmethod
    def one(cls) -> "ProvenanceLabel":
        return cls(
            integrity=IntegrityLevel.HUMAN_APPROVAL,
            conf_tier=ConfidentialityTier.PUBLIC,
            readers=frozenset({"*"}),
            witnesses=frozenset(),
            deriv_hash=hashlib.sha256(b"NOSIH-V3-SEMIRING-ONE").hexdigest(),
        )

    @classmethod
    def zero(cls) -> "ProvenanceLabel":
        return cls(
            integrity=IntegrityLevel.UNTRUSTED,
            conf_tier=ConfidentialityTier.RESTRICTED_PII,
            readers=frozenset(),
            witnesses=frozenset(),
            deriv_hash=hashlib.sha256(b"NOSIH-V3-SEMIRING-ZERO").hexdigest(),
        )

    @staticmethod
    def _join_readers(r1: FrozenSet[str], r2: FrozenSet[str]) -> FrozenSet[str]:
        if "*" in r1:
            return r2
        if "*" in r2:
            return r1
        return r1.intersection(r2)

    def mul(self, other: "ProvenanceLabel") -> "ProvenanceLabel":
        """Semiring conjunctive composition (tensor / multi-input derivation)."""
        a, b = sorted((self.deriv_hash, other.deriv_hash))
        dh = hashlib.sha256(b"MUL\x00" + a.encode() + b.encode()).hexdigest()
        return ProvenanceLabel(
            integrity=IntegrityLevel(max(int(self.integrity), int(other.integrity))),
            conf_tier=ConfidentialityTier(max(int(self.conf_tier), int(other.conf_tier))),
            readers=self._join_readers(self.readers, other.readers),
            witnesses=self.witnesses.union(other.witnesses),
            deriv_hash=dh,
        )

    def add(self, other: "ProvenanceLabel") -> "ProvenanceLabel":
        """Semiring disjunctive composition (branch merge / fallback aggregation)."""
        a, b = sorted((self.deriv_hash, other.deriv_hash))
        dh = hashlib.sha256(b"ADD\x00" + a.encode() + b.encode()).hexdigest()
        return ProvenanceLabel(
            integrity=IntegrityLevel(max(int(self.integrity), int(other.integrity))),
            conf_tier=ConfidentialityTier(max(int(self.conf_tier), int(other.conf_tier))),
            readers=self._join_readers(self.readers, other.readers),
            witnesses=self.witnesses.union(other.witnesses),
            deriv_hash=dh,
        )

    def flows_to_clearance(self, max_tier: ConfidentialityTier, endpoint_readers: FrozenSet[str]) -> bool:
        """Check l_C <= clear(e): tier <= max_tier AND endpoint_readers subset of authorized readers."""
        if int(self.conf_tier) > int(max_tier):
            return False
        if "*" in self.readers:
            return True
        return bool(endpoint_readers) and endpoint_readers.issubset(self.readers)

    def value_committed_digest(self, tool_name: str) -> str:
        sorted_w = sorted((w.to_dict() for w in self.witnesses), key=lambda d: (d["record_id"], d["field_name"], d["value_hash"]))
        return jcs_sha256({
            "tool": tool_name,
            "integrity": int(self.integrity),
            "conf_tier": int(self.conf_tier),
            "readers": sorted(self.readers),
            "deriv_hash": self.deriv_hash,
            "witnesses": sorted_w,
        })


@dataclass(frozen=True)
class ProvenanceValue:
    value: Any
    label: ProvenanceLabel


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class POSTWPlusEngine:
    """POST-W++ Algebraic Provenance + Atomic Linear Monetary Budgets + Egress IFC Guard."""

    def __init__(
        self,
        db_path: str | Path,
        tool_origin_policy: Dict[str, Dict[str, Any]],
        allowlisted_endpoints: Dict[str, Dict[str, Any]],
    ) -> None:
        self.db_path = str(db_path)
        self.tool_origin_policy = tool_origin_policy
        self.allowlisted_endpoints = allowlisted_endpoints
        self._lock = threading.RLock()
        self._secret_literals: Dict[Tuple[str, str], List[str]] = {}
        self._trusted_fields: Dict[Tuple[str, str, str], Dict[str, ProvenanceValue]] = {}
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=FULL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS witness_budgets (
                        tenant_id TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        witness_id TEXT NOT NULL,
                        field_name TEXT NOT NULL,
                        initial_amount TEXT NOT NULL,
                        remaining_amount TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        PRIMARY KEY (tenant_id, session_id, witness_id, field_name)
                    );
                    """
                )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def ingest_tool_output(
        self,
        tenant_id: str,
        session_id: str,
        server_id: str,
        tool_name: str,
        record_id: str,
        fields: Dict[str, Any],
        ttl_seconds: float = 900.0,
    ) -> Dict[str, ProvenanceValue]:
        """Policy-bound origin assignment (ignores any server-supplied 'origin' field!)."""
        policy_key = f"{server_id}:{tool_name}"
        pol = self.tool_origin_policy.get(policy_key)
        if pol is None:
            # Fail-closed default: unknown server/tool is UNTRUSTED
            integrity = IntegrityLevel.UNTRUSTED
            conf_tier = ConfidentialityTier.PUBLIC
            readers = frozenset({"*"})
            origin_name = "UNTRUSTED_UNKNOWN_TOOL"
        else:
            integrity = IntegrityLevel(int(pol["integrity"]))
            conf_tier = ConfidentialityTier(int(pol["conf_tier"]))
            readers = frozenset(pol["readers"])
            origin_name = f"POLICY:{policy_key}:{integrity.name}"

        wrapped: Dict[str, ProvenanceValue] = {}
        now = time.time()
        exp = now + ttl_seconds
        witness_id = f"{tool_name}:{record_id}"

        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                for fname, fval in fields.items():
                    if fname == "origin":
                        continue  # Explicitly ignore server-asserted origin
                    vhash = jcs_sha256({"v": fval})
                    atom = WitnessAtom(
                        server_id=server_id,
                        tool_name=tool_name,
                        record_id=record_id,
                        field_name=fname,
                        value_hash=vhash,
                        policy_origin=origin_name,
                    )
                    lbl = ProvenanceLabel(
                        integrity=integrity,
                        conf_tier=conf_tier,
                        readers=readers,
                        witnesses=frozenset({atom}),
                        deriv_hash=vhash,
                    )
                    wrapped[fname] = ProvenanceValue(value=fval, label=lbl)

                    # Register confidential literals for egress leak detection
                    if int(conf_tier) >= int(ConfidentialityTier.CONFIDENTIAL_FIN) and isinstance(fval, str) and len(fval) >= 6:
                        self._secret_literals.setdefault((tenant_id, session_id), []).append(fval)

                    # Register linear monetary budgets for verified financial fields
                    if fname in ("approved_amount_inr", "eligible_itc_inr") and int(integrity) <= int(IntegrityLevel.SIGNED_ERP):
                        if not isinstance(fval, bool):
                            amt_dec = Decimal(str(fval))
                            if amt_dec > Decimal("0"):
                                conn.execute(
                                    """
                                    INSERT OR IGNORE INTO witness_budgets
                                    (tenant_id, session_id, witness_id, field_name, initial_amount, remaining_amount, expires_at)
                                    VALUES (?, ?, ?, ?, ?, ?, ?);
                                    """,
                                    (tenant_id, session_id, witness_id, fname, str(amt_dec), str(amt_dec), exp),
                                )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

            self._trusted_fields[(tenant_id, session_id, witness_id)] = wrapped
        return wrapped

    def consume_linear_budget(
        self,
        tenant_id: str,
        session_id: str,
        witness_ids: List[str],
        field_name: str,
        requested_amount: Any,
        now: Optional[float] = None,
    ) -> Tuple[bool, str, Decimal]:
        """Atomically verify and decrement exact Decimal budget across one or more witnesses."""
        if isinstance(requested_amount, bool):
            return False, "invalid_amount_type_bool", Decimal("0")
        try:
            req = Decimal(str(requested_amount))
        except InvalidOperation:
            return False, "invalid_amount_decimal", Decimal("0")
        if req <= Decimal("0"):
            return False, "non_positive_amount", Decimal("0")

        ts = time.time() if now is None else now
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                available: List[Tuple[str, Decimal]] = []
                total_rem = Decimal("0")
                for wid in witness_ids:
                    row = conn.execute(
                        """
                        SELECT remaining_amount, expires_at FROM witness_budgets
                        WHERE tenant_id = ? AND session_id = ? AND witness_id = ? AND field_name = ?;
                        """,
                        (tenant_id, session_id, wid, field_name),
                    ).fetchone()
                    if not row:
                        conn.execute("ROLLBACK;")
                        return False, f"missing_witness_budget:{wid}", Decimal("0")
                    if ts > float(row[1]):
                        conn.execute("ROLLBACK;")
                        return False, f"expired_witness_budget:{wid}", Decimal("0")
                    rem = Decimal(str(row[0]))
                    available.append((wid, rem))
                    total_rem += rem

                if req > total_rem:
                    conn.execute("ROLLBACK;")
                    return False, "insufficient_witness_budget", total_rem

                to_deduct = req
                for wid, rem in available:
                    if to_deduct <= Decimal("0"):
                        break
                    take = min(rem, to_deduct)
                    new_rem = rem - take
                    conn.execute(
                        """
                        UPDATE witness_budgets SET remaining_amount = ?
                        WHERE tenant_id = ? AND session_id = ? AND witness_id = ? AND field_name = ?;
                        """,
                        (str(new_rem), tenant_id, session_id, wid, field_name),
                    )
                    to_deduct -= take

                conn.execute("COMMIT;")
                return True, "ok", total_rem - req
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()


    def rollback_linear_budget(
        self,
        tenant_id: str,
        session_id: str,
        witness_id: str,
        field_name: str,
        restore_amount: Any,
    ) -> Tuple[bool, Decimal]:
        """Atomically restore exact Decimal budget on downstream sink failure (capped at initial_amount)."""
        req = Decimal(str(restore_amount))
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                row = conn.execute(
                    "SELECT initial_amount, remaining_amount FROM witness_budgets WHERE tenant_id=? AND session_id=? AND witness_id=? AND field_name=?;",
                    (tenant_id, session_id, witness_id, field_name),
                ).fetchone()
                if not row:
                    conn.execute("ROLLBACK;")
                    return False, Decimal("0")
                init_amt = Decimal(str(row[0]))
                rem_amt = Decimal(str(row[1]))
                new_rem = min(init_amt, rem_amt + req)
                conn.execute(
                    "UPDATE witness_budgets SET remaining_amount=? WHERE tenant_id=? AND session_id=? AND witness_id=? AND field_name=?;",
                    (str(new_rem), tenant_id, session_id, witness_id, field_name),
                )
                conn.execute("COMMIT;")
                return True, new_rem
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def _scan_egress_leaks(self, tenant_id: str, session_id: str, payload_str: str) -> Optional[str]:
        """Defense-in-depth egress scanner for confidential literals, URL-safe/std Base64, hex, and high-entropy chunks."""
        secrets_list = self._secret_literals.get((tenant_id, session_id), [])
        compact = re.sub(r"[\s\-_.:/]+", "", payload_str).lower()
        for sec in secrets_list:
            sec_compact = re.sub(r"[\s\-_.:/]+", "", sec).lower()
            if sec.lower() in payload_str.lower() or (len(sec_compact) >= 6 and sec_compact in compact):
                return "egress_secret_leak:literal"
            # Standard & URL-safe Base64 and Hex encodings (including stripped padding / chunked)
            b_sec = sec.encode("utf-8")
            for enc in (
                base64.b64encode(b_sec).decode("ascii").rstrip("="),
                base64.urlsafe_b64encode(b_sec).decode("ascii").rstrip("="),
                b_sec.hex(),
            ):
                if len(enc) >= 8 and (enc in payload_str or enc in compact):
                    return "egress_secret_leak:encoded"
                # Check 12-char overlapping slices for chunked exfiltration
                if len(enc) >= 16:
                    for i in range(0, len(enc) - 11, 6):
                        if enc[i : i + 12] in payload_str:
                            return "egress_secret_leak:chunked_encoded"

        # High-entropy encoded token heuristic (URL-safe Base64 / hex >= 20 chars)
        for token in re.findall(r"[A-Za-z0-9+/\-_]{20,}={0,2}", payload_str):
            if _shannon_entropy(token) > 4.2:
                return "egress_secret_leak:high_entropy_token"
        return None

    def evaluate_sink_call(
        self,
        tenant_id: str,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        arg_labels: Optional[Dict[str, ProvenanceLabel]] = None,
    ) -> Tuple[bool, str, str]:
        """Evaluate POST-W++ provenance, lattice, linear budget, and egress rules.

        Returns (allowed, reason, value_committed_witness_digest).
        """
        labels = arg_labels or {}
        combined = ProvenanceLabel.one()
        for lbl in labels.values():
            combined = combined.mul(lbl)

        if tool_name == "execute_neft_payout":
            if int(combined.integrity) > int(IntegrityLevel.SIGNED_ERP):
                return False, "integrity_violation:untrusted_taint_in_payout", combined.value_committed_digest(tool_name)
            inv_ids = arguments.get("invoice_ids") or ([arguments["invoice_id"]] if "invoice_id" in arguments else [])
            if not inv_ids:
                return False, "missing_invoice_witness", combined.value_committed_digest(tool_name)
            wids = [f"get_vendor_invoice:{iid}" for iid in inv_ids]
            # Verify beneficiary account matches trusted ERP record
            acct = arguments.get("beneficiary_account")
            if acct is not None:
                matched_acct = False
                for wid in wids:
                    rec = self._trusted_fields.get((tenant_id, session_id, wid), {})
                    if "beneficiary_account" in rec and rec["beneficiary_account"].value == acct:
                        matched_acct = True
                        break
                if not matched_acct:
                    return False, "beneficiary_account_mismatch", combined.value_committed_digest(tool_name)
            ok, reason, _ = self.consume_linear_budget(
                tenant_id, session_id, wids, "approved_amount_inr", arguments.get("amount_inr")
            )
            return ok, reason, combined.value_committed_digest(tool_name)

        if tool_name == "file_gstr3b_offset":
            if int(combined.integrity) > int(IntegrityLevel.VERIFIED_GOV_API):
                return False, "integrity_violation:gstr3b_requires_gov_api", combined.value_committed_digest(tool_name)
            rec_id = arguments.get("reconciliation_id")
            if not rec_id:
                return False, "missing_gstr2b_witness", combined.value_committed_digest(tool_name)
            ok, reason, _ = self.consume_linear_budget(
                tenant_id, session_id, [f"fetch_gstr2b_reconciliation:{rec_id}"], "eligible_itc_inr", arguments.get("itc_offset_inr")
            )
            return ok, reason, combined.value_committed_digest(tool_name)

        if tool_name == "modify_erp_bank_master":
            if int(combined.integrity) != int(IntegrityLevel.HUMAN_APPROVAL):
                return False, "integrity_violation:requires_human_approval", combined.value_committed_digest(tool_name)
            return True, "ok", combined.value_committed_digest(tool_name)

        if tool_name == "send_external_webhook":
            endpoint = str(arguments.get("approved_endpoint", ""))
            ep_pol = self.allowlisted_endpoints.get(endpoint)
            if ep_pol is None:
                return False, "egress_endpoint_not_allowlisted", combined.value_committed_digest(tool_name)
            max_tier = ConfidentialityTier(int(ep_pol["max_tier"]))
            ep_readers = frozenset(ep_pol["readers"])
            if not combined.flows_to_clearance(max_tier, ep_readers):
                return False, "confidentiality_lattice_violation", combined.value_committed_digest(tool_name)
            payload_str = str(arguments.get("payload", ""))
            leak_reason = self._scan_egress_leaks(tenant_id, session_id, payload_str)
            if leak_reason is not None:
                return False, leak_reason, combined.value_committed_digest(tool_name)
            return True, "ok", combined.value_committed_digest(tool_name)

        return True, "ok", combined.value_committed_digest(tool_name)
