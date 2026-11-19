"""NOSIH Wire-Level JSON-RPC 2.0 MCP Security Proxy (CAT-PLM).

Closes prior orchestrators defects F-03, F-04, F-05, F-06, F-07:
- Out-of-band signed boot manifest (eliminates Day-0 TOFU pinning)
- Continuous tools/list interception & rug-pull stripping before LLM context exposure
- Zero self-minting: every tools/call MUST supply an externally minted & attenuated SPCCE-Macaroon capability
- Strict raw-bytes JSON parsing (rejects duplicate keys & lone surrogates) + jsonschema validation
- POST-W++ algebraic provenance, linear budget enforcement, and MTLog Merkle auditing
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

import jsonschema

from .jcs_v3 import JCSValidationError, jcs_bytes, jcs_sha256, parse_json_strict
from .merkle_log import MerkleTransparencyLog
from .postw_v3 import POSTWPlusEngine, ProvenanceLabel
from .shadow_v3 import AuthenticatedShadowReceipt, CSDDShadowSinkV3
from .spcce_v3 import AttenuatedCapability, SPCCEMacaroonAuthority


MANIFEST_DOMAIN = b"NOSIH-V3-MANIFEST\x00"


class ManifestVerificationError(RuntimeError):
    """Raised when an MCP server fails signed boot manifest verification."""


@dataclass(frozen=True)
class SignedToolManifest:
    server_id: str
    tools: Dict[str, Dict[str, Any]]  # tool_name -> full tool descriptor (name, description, inputSchema)
    signature_hex: str

    @classmethod
    def sign(cls, server_id: str, tools: Dict[str, Dict[str, Any]], manifest_key: bytes) -> "SignedToolManifest":
        if len(manifest_key) < 32:
            raise ValueError("Manifest key must be >= 32 bytes")
        sig = hmac.new(
            manifest_key,
            MANIFEST_DOMAIN + jcs_bytes({"server_id": server_id, "tools": tools}),
            hashlib.sha256,
        ).hexdigest()
        return cls(server_id=server_id, tools=tools, signature_hex=sig)

    def verify(self, manifest_key: bytes) -> bool:
        expected = hmac.new(
            manifest_key,
            MANIFEST_DOMAIN + jcs_bytes({"server_id": self.server_id, "tools": self.tools}),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, self.signature_hex)

    def tool_digest(self, tool_name: str) -> str:
        return jcs_sha256(self.tools[tool_name])


class NOSIHMCPProxyV3:
    """Zero-trust JSON-RPC 2.0 MCP proxy enforcing CAT-PLM end-to-end."""

    CONTROL_SINKS = frozenset({
        "execute_neft_payout",
        "file_gstr3b_offset",
        "modify_erp_bank_master",
        "send_external_webhook",
    })

    def __init__(
        self,
        server_id: str,
        server_dispatch: Callable[[Dict[str, Any]], Dict[str, Any]],
        signed_manifest: SignedToolManifest,
        manifest_key: bytes,
        authority: SPCCEMacaroonAuthority,
        postw: POSTWPlusEngine,
        merkle_log: MerkleTransparencyLog,
        shadow_sink: CSDDShadowSinkV3,
    ) -> None:
        if not signed_manifest.verify(manifest_key):
            raise ManifestVerificationError("Signed boot manifest MAC verification failed")
        if signed_manifest.server_id != server_id:
            raise ManifestVerificationError("Manifest server_id mismatch")

        self.server_id = server_id
        self.server_dispatch = server_dispatch
        self.manifest = signed_manifest
        self.authority = authority
        self.postw = postw
        self.merkle_log = merkle_log
        self.shadow_sink = shadow_sink

        # Boot-time cross-check against live server tools/list (eliminates Day-0 TOFU!)
        live_resp = self.server_dispatch({"jsonrpc": "2.0", "id": "boot_verify", "method": "tools/list", "params": {}})
        live_tools = {t["name"]: t for t in live_resp.get("result", {}).get("tools", []) if isinstance(t, dict) and "name" in t}
        for tname, pinned_desc in self.manifest.tools.items():
            if tname not in live_tools:
                raise ManifestVerificationError(f"Boot manifest tool missing on live server: {tname}")
            if jcs_sha256(live_tools[tname]) != jcs_sha256(pinned_desc):
                raise ManifestVerificationError(f"Day-0 poisoned schema/description detected on tool: {tname}")

    def _audit(self, event_type: str, details: Dict[str, Any]) -> int:
        leaf_idx, _, _ = self.merkle_log.append({
            "event_type": event_type,
            "server_id": self.server_id,
            "timestamp_utc": round(time.time(), 6),
            **details,
        })
        return leaf_idx

    def _verify_live_tools(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        live_resp = self.server_dispatch({"jsonrpc": "2.0", "id": "live_pin", "method": "tools/list", "params": {}})
        live_tools = live_resp.get("result", {}).get("tools", [])
        clean: List[Dict[str, Any]] = []
        poisoned: List[str] = []
        for t in live_tools:
            if not isinstance(t, dict) or "name" not in t:
                continue
            tname = t["name"]
            if tname not in self.manifest.tools:
                poisoned.append(tname)
                continue
            if jcs_sha256(t) != self.manifest.tool_digest(tname):
                poisoned.append(tname)
                continue
            clean.append(t)
        return clean, poisoned

    def intercept_raw_jsonrpc(
        self,
        raw_frame: str | bytes,
        tenant_id: str,
        session_id: str,
        dag_id: str,
        hop_id: str,
        capability: Optional[AttenuatedCapability] = None,
        arg_labels: Optional[Dict[str, ProvenanceLabel]] = None,
    ) -> Dict[str, Any]:
        """Intercept raw JSON-RPC 2.0 wire bytes with fail-closed CAT-PLM checks."""
        try:
            req = parse_json_strict(raw_frame)
        except JCSValidationError as exc:
            leaf = self._audit("DENY_FAIL_CLOSED", {"reason": f"jcs_parse_error:{exc}"})
            return {"decision": "DENY_FAIL_CLOSED", "reason": str(exc), "merkle_leaf": leaf}

        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or "method" not in req:
            leaf = self._audit("DENY_FAIL_CLOSED", {"reason": "malformed_jsonrpc"})
            return {"decision": "DENY_FAIL_CLOSED", "reason": "malformed_jsonrpc", "merkle_leaf": leaf}

        method = req["method"]

        # Continuous tools/list pinning (blocks mid-session description poisoning!)
        if method == "tools/list":
            clean, poisoned = self._verify_live_tools()
            if poisoned:
                leaf = self._audit("RUG_PULL_DETECTED", {"method": "tools/list", "poisoned_tools": poisoned})
                return {
                    "decision": "DENY_FAIL_CLOSED",
                    "reason": f"rug_pull_detected:{','.join(poisoned)}",
                    "clean_tools": clean,
                    "merkle_leaf": leaf,
                }
            return {"decision": "ALLOW", "result": {"tools": clean}}

        if method != "tools/call":
            leaf = self._audit("DENY_FAIL_CLOSED", {"reason": f"unsupported_method:{method}"})
            return {"decision": "DENY_FAIL_CLOSED", "reason": f"unsupported_method:{method}", "merkle_leaf": leaf}

        params = req.get("params", {})
        if not isinstance(params, dict):
            leaf = self._audit("DENY_FAIL_CLOSED", {"reason": "invalid_params"})
            return {"decision": "DENY_FAIL_CLOSED", "reason": "invalid_params", "merkle_leaf": leaf}

        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool_name, str) or tool_name not in self.manifest.tools:
            leaf = self._audit("DENY_FAIL_CLOSED", {"reason": f"unknown_tool:{tool_name}"})
            return {"decision": "DENY_FAIL_CLOSED", "reason": "unknown_tool", "merkle_leaf": leaf}

        # Re-pin live tool schema before dispatch (prevents mid-session rug pull)
        clean, poisoned = self._verify_live_tools()
        if tool_name in poisoned or not any(t["name"] == tool_name for t in clean):
            leaf = self._audit("RUG_PULL_DETECTED", {"tool_name": tool_name})
            return {"decision": "DENY_FAIL_CLOSED", "reason": "schema_rug_pull", "merkle_leaf": leaf}

        # JSON Schema validation
        schema = self.manifest.tools[tool_name].get("inputSchema", {"type": "object"})
        try:
            jsonschema.validate(instance=arguments, schema=schema)
        except jsonschema.ValidationError as exc:
            leaf = self._audit("DENY_FAIL_CLOSED", {"tool_name": tool_name, "reason": f"schema_violation:{exc.message}"})
            return {"decision": "DENY_FAIL_CLOSED", "reason": "jsonschema_validation_failed", "merkle_leaf": leaf}

        # Strict external capability enforcement (ZERO self-minting!)
        if capability is None:
            leaf = self._audit("DENY_FAIL_CLOSED", {"tool_name": tool_name, "reason": "missing_capability"})
            return {"decision": "DENY_FAIL_CLOSED", "reason": "missing_capability", "merkle_leaf": leaf}

        is_sink = tool_name in self.CONTROL_SINKS
        schema_digest = self.manifest.tool_digest(tool_name)

        # Evaluate POST-W++ provenance, lattice & linear budget rules for control sinks
        witness_digest = ""
        if is_sink:
            postw_ok, postw_reason, witness_digest = self.postw.evaluate_sink_call(
                tenant_id=tenant_id,
                session_id=session_id,
                tool_name=tool_name,
                arguments=arguments,
                arg_labels=arg_labels,
            )
            if not postw_ok:
                receipt: AuthenticatedShadowReceipt = self.shadow_sink.quarantine(
                    tenant_id=tenant_id,
                    session_id=session_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    reason=postw_reason,
                    witness_digest=witness_digest,
                )
                return {
                    "decision": "SHADOW_DIVERT",
                    "reason": postw_reason,
                    "shadow_receipt": receipt,
                    "merkle_leaf": receipt.leaf_index,
                }

        cap_ctx = {
            "tenant_id": tenant_id,
            "session_id": session_id,
            "dag_id": dag_id,
            "hop_id": hop_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "schema_digest": schema_digest,
            "witness_digest": witness_digest,
        }
        cap_ok, cap_reason = self.authority.verify_and_consume(
            capability, cap_ctx, require_sink_caveats=is_sink
        )
        if not cap_ok:
            leaf = self._audit("DENY_FAIL_CLOSED", {"tool_name": tool_name, "reason": cap_reason})
            return {"decision": "DENY_FAIL_CLOSED", "reason": cap_reason, "merkle_leaf": leaf}

        # Dispatch to live MCP server
        server_resp = self.server_dispatch(req)
        result_obj = server_resp.get("result", {})

        # Policy-bound ingestion of read tool outputs (NEVER trusts server-supplied 'origin'!)
        wrapped_output = None
        if isinstance(result_obj, dict) and not is_sink:
            rec_id = str(result_obj.get("record_id") or arguments.get("invoice_id") or arguments.get("reconciliation_id") or hop_id)
            wrapped_output = self.postw.ingest_tool_output(
                tenant_id=tenant_id,
                session_id=session_id,
                server_id=self.server_id,
                tool_name=tool_name,
                record_id=rec_id,
                fields=result_obj,
            )

        leaf = self._audit("ALLOW_EXECUTED", {
            "tenant_id": tenant_id,
            "session_id": session_id,
            "dag_id": dag_id,
            "hop_id": hop_id,
            "tool_name": tool_name,
            "schema_digest": schema_digest,
            "witness_digest": witness_digest,
        })
        return {
            "decision": "ALLOW",
            "reason": "ok",
            "result": result_obj,
            "provenance_fields": wrapped_output,
            "merkle_leaf": leaf,
        }
