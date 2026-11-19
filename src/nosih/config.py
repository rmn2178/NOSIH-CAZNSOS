"""Fail-closed typed configuration and policy loader for NOSIH."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


class PolicyLoadError(RuntimeError):
    """Raised whenever configuration or security policy fails validation (fail-closed)."""


FORBIDDEN_RUNTIME_KEYS = frozenset({
    "ground_truth",
    "private_label",
    "expected_answer",
    "expected_arm",
    "expected_freq_hz",
    "expected_bbox",
    "benchmark_category",
    "task_hint",
    "query_class",
    "gold_doc_ids",
})


@dataclass(frozen=True)
class NOSIHConfig:
    tenant_id: str = "default_tenant"
    corpus_version: str = "NOSIH.0"
    model_version: str = "nosih-v3-hybrid"
    policy_epoch: str = "2026-11-v3"
    # Plane II DPD-LinUCB parameters
    bandit_dim: int = 10
    bandit_num_arms: int = 6
    bandit_gamma: float = 0.992
    bandit_lambda_reg: float = 1.0
    bandit_alpha_scale: float = 0.65
    bandit_latency_budget_ms: float = 40.0
    bandit_cost_budget: float = 0.35
    bandit_dual_lr: float = 0.08
    bandit_dual_max: float = 5.0
    # Plane II Online ACI / CRC parameters
    aci_route_target_alpha: float = 0.05
    aci_route_lr: float = 0.05
    aci_route_ki: float = 0.02
    aci_window_size: int = 200
    aci_cache_target_alpha: float = 0.02
    aci_cache_lr: float = 0.04
    aci_cache_audit_prob: float = 0.10
    # Plane II PS-RCSC parameters
    cache_dim: int = 320
    cache_max_entries_per_bucket: int = 2048
    cache_overhead_ms: float = 0.12
    # Plane I Security Policy
    allowlisted_egress_endpoints: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "https://triage.internal.nosih.local/alerts": {
            "max_tier": 1,  # INTERNAL
            "readers": ["internal_ops", "secops"],
        },
        "https://audit.internal.nosih.local/events": {
            "max_tier": 2,  # CONFIDENTIAL_FIN
            "readers": ["finance_audit", "secops"],
        },
    })
    tool_origin_policy: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "erp_server:get_vendor_invoice": {
            "integrity": 2,      # SIGNED_ERP
            "conf_tier": 2,      # CONFIDENTIAL_FIN
            "readers": ["finance_audit", "erp_payout", "secops"],
        },
        "gst_server:fetch_gstr2b_reconciliation": {
            "integrity": 1,      # VERIFIED_GOV_API
            "conf_tier": 2,      # CONFIDENTIAL_FIN
            "readers": ["finance_audit", "gst_filing", "secops"],
        },
        "approval_server:verify_human_approval": {
            "integrity": 0,      # HUMAN_APPROVAL
            "conf_tier": 1,      # INTERNAL
            "readers": ["finance_audit", "erp_payout", "secops"],
        },
        "mail_server:read_vendor_email": {
            "integrity": 6,      # UNTRUSTED
            "conf_tier": 0,      # PUBLIC
            "readers": ["*"],
        },
    })


def load_config_fail_closed(path: Optional[str | Path]) -> NOSIHConfig:
    """Load JSON policy/config strictly fail-closed; never silently falls back."""
    if path is None:
        return NOSIHConfig()
    p = Path(path)
    if not p.exists():
        raise PolicyLoadError(f"Policy file does not exist: {p}")
    try:
        raw = p.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as exc:
        raise PolicyLoadError(f"Failed to parse policy file {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyLoadError("Policy file root must be a JSON object")
    allowed_fields = set(NOSIHConfig.__dataclass_fields__.keys())
    unknown = set(data.keys()) - allowed_fields
    if unknown:
        raise PolicyLoadError(f"Unknown policy fields rejected (fail-closed): {sorted(unknown)}")
    try:
        return NOSIHConfig(**data)
    except Exception as exc:
        raise PolicyLoadError(f"Invalid policy configuration values: {exc}") from exc


def assert_no_forbidden_keys(payload: Dict[str, Any], context: str = "runtime_input") -> None:
    """Enforce strict runtime-evaluator isolation (zero ground-truth leakage)."""
    if not isinstance(payload, dict):
        return
    found = FORBIDDEN_RUNTIME_KEYS.intersection(payload.keys())
    if found:
        raise ValueError(
            f"Forbidden private/evaluator key(s) detected in {context}: {sorted(found)}"
        )
