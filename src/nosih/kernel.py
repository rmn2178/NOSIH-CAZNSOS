"""Unified ZeroTrustKernel for NOSIH.

Fuses all three planes into the explicit 7-stage closed-loop request lifecycle:
  Stage 1: Leakage Isolation (rejects forbidden private/evaluator keys)
  Stage 2: 10D Anti-Spoofing CPU Profiling
  Stage 3: Provenance-Scoped Risk-Controlled Semantic Cache (PS-RCSC)
  Stage 4: Carbon-Aware Primal-Dual Routing (CA-DPD-LinUCB + DiurnalCarbonForecaster)
  Stage 5: Static Kahn + IFC DAG Verification & Root SPCCE-Macaroon Minting
  Stage 6: Capability-Gated Async Execution + PCS-PMC Power Control + Replay Journaling
  Stage 7: Dual-Channel Online Conformal PID & Closed-Loop Telemetry Feedback
"""
from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import NOSIHConfig, assert_no_forbidden_keys
from .plane1_security.carbon_cert import CarbonCertificateAuthority
from .plane1_security.merkle_log import MerkleTransparencyLog
from .plane1_security.postw_v3 import IntegrityLevel, POSTWPlusEngine, ProvenanceLabel, ProvenanceValue
from .plane1_security.shadow_v3 import CSDDShadowSinkV3
from .plane1_security.spcce_v3 import AtomicJTIReplayStore, SPCCEMacaroonAuthority, StrictSecretProvider
from .plane2_control.online_conformal import DualChannelACIGate
from .plane2_control.pcsp import ProvenanceCoupledCarbonSecurityPricer
from .plane2_control.primal_dual_bandit import DPDLinUCBRouter
from .plane2_control.profiler_v3 import ComplexityProfiler10D
from .plane2_control.provenance_cache import ProvenanceScope, ProvenanceScopedSemanticCache
from .plane3_execution.dag_executor import CapabilityGatedDAGExecutor, DAGNode, DAGPlan
from .plane3_execution.hardware_probe import probe_hardware_environment
from .plane3_execution.power_carbon import (
    DEFAULT_TIER_PROFILES,
    DiurnalCarbonForecaster,
    PredictivePowerController,
    TransparentEnergyAccountant,
)
from .plane3_execution.providers import BaseLLMProvider, OllamaProviderV3, ProviderFailoverChain
from .plane3_execution.replay_engine import JournalStore, ReplayMode
from .plane3_execution.tools import DeterministicRAGRetriever, SafeDecimalASTEvaluator, SignalFFTSobelExtractor


ARM_NAMES = {
    0: "A0_SMALL_LLM",
    1: "A1_DECIMAL_AST",
    2: "A2_TFIDF_RAG",
    3: "A3_LARGE_LLM",
    4: "A4_SIGNAL_FFT_SOBEL",
    5: "A5_VERIFIED_PARALLEL_DAG",
}

ARM_TO_POWER_TIER = {
    0: "T1_SMALL",
    1: "T0b_SYMBOLIC",
    2: "T0b_SYMBOLIC",
    3: "T3_LARGE",
    4: "T0b_SYMBOLIC",
    5: "T0b_SYMBOLIC",
}


class ZeroTrustKernel:
    """Single unified orchestration kernel across Planes I, II, and III."""

    def __init__(
        self,
        state_dir: str | Path,
        config: Optional[NOSIHConfig] = None,
        documents: Optional[List[Dict[str, str]]] = None,
        providers: Optional[List[BaseLLMProvider]] = None,
        secret_provider: Optional[StrictSecretProvider] = None,
        key_id: str = "k1",
    ) -> None:
        self.config = config or NOSIHConfig()
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.key_id = key_id

        # Plane I: Zero-Trust Security (CAT-PLM)
        self.secrets = secret_provider or StrictSecretProvider.ephemeral(key_id)
        root_key = self.secrets.get_key(key_id)
        self.replay_store = AtomicJTIReplayStore(self.state_dir / "jti_replay.db")
        self.authority = SPCCEMacaroonAuthority(self.secrets, self.replay_store)
        self.merkle_log = MerkleTransparencyLog(self.state_dir / "merkle_audit.db", sth_signing_key=root_key)
        self.shadow_sink = CSDDShadowSinkV3(self.merkle_log, receipt_key=root_key)
        self.postw = POSTWPlusEngine(
            db_path=self.state_dir / "postw_budgets.db",
            tool_origin_policy=self.config.tool_origin_policy,
            allowlisted_endpoints=self.config.allowlisted_egress_endpoints,
        )

        # Plane II: Carbon-Conformal Control
        self.profiler = ComplexityProfiler10D()
        self.carbon_forecaster = DiurnalCarbonForecaster()
        self.router = DPDLinUCBRouter(
            num_arms=self.config.bandit_num_arms,
            dim=self.config.bandit_dim,
            gamma=self.config.bandit_gamma,
            lambda_reg=self.config.bandit_lambda_reg,
            alpha_scale=self.config.bandit_alpha_scale,
            budgets=(min(1.0, self.config.bandit_latency_budget_ms / 200.0), self.config.bandit_cost_budget),
            dual_lr=self.config.bandit_dual_lr,
            dual_max=self.config.bandit_dual_max,
        )
        self.aci_gate = DualChannelACIGate(
            route_target_alpha=self.config.aci_route_target_alpha,
            route_lr=self.config.aci_route_lr,
            route_ki=self.config.aci_route_ki,
            window_size=self.config.aci_window_size,
            cache_target_alpha=self.config.aci_cache_target_alpha,
            cache_lr=self.config.aci_cache_lr,
            cache_audit_prob=self.config.aci_cache_audit_prob,
        )
        self.cache = ProvenanceScopedSemanticCache(
            aci_gate=self.aci_gate,
            dim=self.config.cache_dim,
            max_entries_per_bucket=self.config.cache_max_entries_per_bucket,
            cache_overhead_ms=self.config.cache_overhead_ms,
        )

        # Plane III: Durable Execution, Power Control & Replay
        self.ast_tool = SafeDecimalASTEvaluator()
        self.rag_tool = DeterministicRAGRetriever(documents or [])
        self.signal_tool = SignalFFTSobelExtractor()
        self.power_controllers = {
            tid: PredictivePowerController(DEFAULT_TIER_PROFILES[tid])
            for tid in ("T1_SMALL", "T2_MEDIUM", "T3_LARGE")
        }
        self.energy_accountant = TransparentEnergyAccountant()
        self.pcsp = ProvenanceCoupledCarbonSecurityPricer()
        self.carbon_ca = CarbonCertificateAuthority(self.merkle_log, probe_hardware_environment())
        self.provider_chain = ProviderFailoverChain(providers if providers is not None else [OllamaProviderV3()])
        self.journal_store = JournalStore(self.state_dir / "replay_journal.db")
        self.dag_executor = CapabilityGatedDAGExecutor(self.authority, self.merkle_log, self.journal_store)

    def _feasible_arms(self, prof) -> List[int]:
        arms = [0, 3, 5]
        if prof.has_math_expr:
            arms.append(1)
        if prof.has_rag_cue:
            arms.append(2)
        if prof.has_multimodal_payload:
            arms.append(4)
        return sorted(arms)

    def _build_dag_for_arm(self, dag_id: str, arm_idx: int) -> DAGPlan:
        if arm_idx == 1:
            return DAGPlan(dag_id, (DAGNode("n_ast", "ast_decimal", timeout_seconds=1.0, output_integrity_hint=IntegrityLevel.DERIVED_DET),))
        if arm_idx == 2:
            return DAGPlan(dag_id, (DAGNode("n_rag", "tfidf_rag", timeout_seconds=1.0, output_integrity_hint=IntegrityLevel.DERIVED_DET),))
        if arm_idx == 4:
            return DAGPlan(dag_id, (DAGNode("n_sig", "signal_fft_sobel", timeout_seconds=2.0, output_integrity_hint=IntegrityLevel.DERIVED_DET),))
        if arm_idx == 5:
            return DAGPlan(
                dag_id,
                (
                    DAGNode("n_rag", "tfidf_rag", timeout_seconds=1.0, output_integrity_hint=IntegrityLevel.DERIVED_DET),
                    DAGNode("n_ast", "ast_decimal", timeout_seconds=1.0, output_integrity_hint=IntegrityLevel.DERIVED_DET),
                    DAGNode("n_merge", "verify_merge", dependencies=("n_rag", "n_ast"), timeout_seconds=1.0, output_integrity_hint=IntegrityLevel.DERIVED_DET),
                ),
            )
        tier = "small" if arm_idx == 0 else "large"
        return DAGPlan(dag_id, (DAGNode("n_llm", "llm_generate", timeout_seconds=5.0, output_integrity_hint=IntegrityLevel.DERIVED_DET, metadata={"tier": tier}),))

    async def execute_request(
        self,
        request: Dict[str, Any],
        session_id: str = "sess_default",
        origin_integrity: IntegrityLevel = IntegrityLevel.USER_DIRECT,
        local_hour: float = 13.0,
        explore: bool = True,
        replay_mode: ReplayMode = ReplayMode.RECORD,
        replay_source_run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute an end-to-end zero-trust request through all 7 lifecycle stages."""
        stage_trace: List[str] = []
        t0 = time.perf_counter()

        # Stage 1: Leakage Isolation
        assert_no_forbidden_keys(request, context="ZeroTrustKernel.execute_request")
        stage_trace.append("stage1_leakage_isolation")

        prompt = str(request["prompt"])
        raw_payload = request.get("raw_payload")
        tenant_id = str(request.get("tenant_id", self.config.tenant_id))
        run_id = str(request.get("run_id") or f"run_{secrets.token_hex(8)}")

        # Stage 2: 10D Anti-Spoofing Profiling
        prof = self.profiler.profile(prompt, raw_payload)
        feasible = self._feasible_arms(prof)
        stage_trace.append("stage2_10d_profiler")

        # Stage 3: Provenance-Scoped Semantic Cache (PS-RCSC)
        scope = ProvenanceScope(
            tenant_id=tenant_id,
            corpus_version=self.config.corpus_version,
            model_version=self.config.model_version,
            policy_epoch=self.config.policy_epoch,
            origin_integrity=origin_integrity,
        )
        min_pred_ms = 0.05 if any(a in feasible for a in (1, 2, 4)) else 25.0
        hit, cached_ans, cache_meta = self.cache.lookup(
            prompt=prompt,
            scope=scope,
            risk_score=prof.risk_score,
            predicted_min_exec_ms=min_pred_ms,
        )
        stage_trace.append("stage3_ps_rcsc_cache")
        if hit:
            c_t = self.carbon_forecaster.deterministic_intensity(local_hour)
            wall_s = time.perf_counter() - t0
            fp = self.energy_accountant.compute_query_footprint(DEFAULT_TIER_PROFILES["T0a_CACHE"], wall_s, c_t, tokens_total=0)
            return {
                "run_id": run_id,
                "answer": cached_ans,
                "ok": True,
                "arm": "CACHE_HIT",
                "confidence": cache_meta.get("confidence", 0.99),
                "conformal_accepted": True,
                "cache_meta": cache_meta,
                "carbon_intensity_g_per_kwh": round(c_t, 2),
                "energy_footprint": fp,
                "stage_trace": stage_trace,
                "wall_ms": round(wall_s * 1000.0, 4),
            }

        # Stage 4: Carbon-Aware Primal-Dual Routing
        c_t = self.carbon_forecaster.step_intensity(local_hour)
        arm_idx, bandit_meta = self.router.select_arm(prof.vector, feasible, explore=explore)
        dag_id = f"dag_{run_id}"
        plan = self._build_dag_for_arm(dag_id, arm_idx)
        stage_trace.append("stage4_carbon_primal_dual_routing")

        # Stage 5: Static DAG Verification & Root Capability Minting
        self.dag_executor.verify_plan_static(plan)
        root_cap = self.authority.mint_root(
            key_id=self.key_id,
            tenant_id=tenant_id,
            session_id=session_id,
            dag_id=dag_id,
            dag_plan_digest=plan.plan_digest(),
            ttl_seconds=120.0,
        )
        stage_trace.append("stage5_static_dag_and_root_cap")

        # Stage 6: Capability-Gated Async Execution + PCS-PMC Power Control
        power_tier = ARM_TO_POWER_TIER[arm_idx]
        wake_lat_s, wake_j = 0.0, 0.0
        if power_tier in self.power_controllers:
            wake_lat_s, wake_j = self.power_controllers[power_tier].on_request_arrival(time.time())

        async def _h_ast(node: DAGNode, deps, cap):
            expr = self.ast_tool.extract_expression(prompt)
            if not expr:
                return ProvenanceValue({"ok": False, "answer": None, "confidence": 0.0, "reason": "no_math_expr"}, ProvenanceLabel.one())
            ok, val, reason = self.ast_tool.evaluate(expr)
            return ProvenanceValue(
                {"ok": ok, "answer": str(val) if ok else None, "confidence": 1.0 if ok else 0.0, "reason": reason},
                ProvenanceLabel.one(),
            )

        async def _h_rag(node: DAGNode, deps, cap):
            ok, hits, score = self.rag_tool.retrieve(prompt, top_k=3)
            ans = hits[0]["content"] if ok and hits else None
            return ProvenanceValue(
                {"ok": ok, "answer": ans, "hits": hits, "confidence": min(1.0, 0.75 + 0.25 * score) if ok else score},
                ProvenanceLabel.one(),
            )

        async def _h_sig(node: DAGNode, deps, cap):
            wf = raw_payload.get("waveform") if raw_payload else None
            img = raw_payload.get("image") if raw_payload else None
            extracted = self.signal_tool.extract(waveform=wf, image=img)
            return ProvenanceValue({"ok": bool(extracted), "answer": extracted, "confidence": 1.0 if extracted else 0.0}, ProvenanceLabel.one())

        async def _h_llm(node: DAGNode, deps, cap):
            tier = str(node.metadata.get("tier", "small"))
            resp = await self.provider_chain.generate(prompt, tier=tier, timeout_s=node.timeout_seconds)
            return ProvenanceValue(
                {
                    "ok": resp.ok,
                    "answer": resp.text if resp.ok else None,
                    "confidence": resp.confidence,
                    "execution_mode": resp.execution_mode,
                    "provider": resp.provider_name,
                    "cost_norm": resp.cost_norm,
                    "error": resp.error,
                },
                ProvenanceLabel.one(),
            )

        async def _h_merge(node: DAGNode, deps, cap):
            rag_v = deps["n_rag"].value
            ast_v = deps["n_ast"].value
            parts, confs = [], []
            if rag_v.get("ok"):
                parts.append(str(rag_v["answer"]))
                confs.append(float(rag_v["confidence"]))
            if ast_v.get("ok"):
                parts.append(str(ast_v["answer"]))
                confs.append(float(ast_v["confidence"]))
            ok = bool(parts)
            return ProvenanceValue(
                {"ok": ok, "answer": " | ".join(parts) if ok else None, "confidence": min(confs) if confs else 0.0},
                ProvenanceLabel.one(),
            )

        handlers = {
            "ast_decimal": _h_ast,
            "tfidf_rag": _h_rag,
            "signal_fft_sobel": _h_sig,
            "llm_generate": _h_llm,
            "verify_merge": _h_merge,
        }

        node_outputs, dag_meta = await self.dag_executor.execute(
            plan=plan,
            handlers=handlers,
            root_cap=root_cap,
            tenant_id=tenant_id,
            session_id=session_id,
            run_id=run_id,
            replay_mode=replay_mode,
            replay_source_run_id=replay_source_run_id,
        )
        stage_trace.append("stage6_capability_gated_execution")

        # Stage 7: Online Conformal PID & Closed-Loop Telemetry Feedback
        terminal_node_id = dag_meta["topo_order"][-1]
        term_out = node_outputs[terminal_node_id].value
        confidence = float(term_out.get("confidence", 0.0))
        conformal_accepted, nonconf_score, tau_route = self.aci_gate.should_accept_route(confidence)

        if term_out.get("ok") and conformal_accepted:
            self.cache.store(
                prompt=prompt,
                scope=scope,
                answer=term_out["answer"],
                confidence=confidence,
                conformal_accepted=True,
            )

        wall_s = time.perf_counter() - t0
        fp = self.energy_accountant.compute_query_footprint(
            DEFAULT_TIER_PROFILES[power_tier],
            exec_latency_s=wall_s,
            carbon_intensity_g_per_kwh=c_t,
            tokens_total=0 if power_tier.startswith("T0") else 256,
            wake_energy_j=wake_j,
        )
        stage_trace.append("stage7_conformal_pid_and_feedback")

        return {
            "run_id": run_id,
            "answer": term_out.get("answer") if conformal_accepted else None,
            "ok": bool(term_out.get("ok")),
            "arm": ARM_NAMES[arm_idx],
            "arm_idx": arm_idx,
            "power_tier": power_tier,
            "carbon_intensity_g_per_kwh": round(c_t, 2),
            "energy_footprint": fp,
            "wakeup_latency_s": wake_lat_s,
            "confidence": confidence,
            "conformal_accepted": conformal_accepted,
            "nonconformity_score": round(nonconf_score, 4),
            "aci_threshold": round(tau_route, 4),
            "bandit_meta": bandit_meta,
            "cache_meta": cache_meta,
            "dag_meta": dag_meta,
            "stage_trace": stage_trace,
            "wall_ms": round(wall_s * 1000.0, 4),
        }
