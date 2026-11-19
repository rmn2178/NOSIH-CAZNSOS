"""Layer 5: Static IFC DAG Verifier, Hard Async Cancellation, Deterministic Replay & Chaos CircuitBreaker."""
import asyncio
import secrets
import tempfile
import time
import unittest
from pathlib import Path

from nosih.plane1_security.merkle_log import MerkleTransparencyLog
from nosih.plane1_security.postw_v3 import IntegrityLevel, ProvenanceLabel, ProvenanceValue
from nosih.plane1_security.spcce_v3 import AtomicJTIReplayStore, SPCCEMacaroonAuthority, StrictSecretProvider
from nosih.plane3_execution.dag_executor import CapabilityGatedDAGExecutor, DAGNode, DAGPlan, StaticIFCError
from nosih.plane3_execution.providers import (
    CalibratedTraceProvider,
    CircuitState,
    LLMResponse,
    ProviderFailoverChain,
)
from nosih.plane3_execution.replay_engine import JournalStore, NonDeterminismError, ReplayMode


class TestLayer5DAGReplayAndChaos(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        key = secrets.token_bytes(32)
        self.auth = SPCCEMacaroonAuthority(
            StrictSecretProvider({"k1": key}),
            AtomicJTIReplayStore(self.td / "replay.db"),
        )
        self.mtlog = MerkleTransparencyLog(self.td / "mtlog.db", sth_signing_key=key)
        self.journal = JournalStore(self.td / "journal.db")
        self.executor = CapabilityGatedDAGExecutor(self.auth, self.mtlog, self.journal)

    def tearDown(self):
        self._td.cleanup()

    def test_static_cycle_and_ifc_violation_blocked_pre_execution(self):
        # Cycle rejected
        cyclic = DAGPlan("d_cyc", (DAGNode("a", "t", dependencies=("b",)), DAGNode("b", "t", dependencies=("a",))))
        with self.assertRaises(StaticIFCError):
            CapabilityGatedDAGExecutor.verify_plan_static(cyclic)

        # UNTRUSTED -> control_sink rejected statically!
        bad_ifc = DAGPlan(
            "d_ifc",
            (
                DAGNode("n_mail", "read_mail", output_integrity_hint=IntegrityLevel.UNTRUSTED),
                DAGNode(
                    "n_pay",
                    "execute_payout",
                    dependencies=("n_mail",),
                    is_control_sink=True,
                    required_max_integrity=IntegrityLevel.SIGNED_ERP,
                ),
            ),
        )
        with self.assertRaises(StaticIFCError):
            CapabilityGatedDAGExecutor.verify_plan_static(bad_ifc)

    async def test_hard_timeout_cancellation_single_and_multi_node_no_zombie_threads(self):
        plan = DAGPlan("d_to", (DAGNode("n_slow", "slow_tool", timeout_seconds=0.08),))
        root_cap = self.auth.mint_root("k1", "t1", "s1", "d_to", plan.plan_digest())

        async def _slow_handler(node, deps, cap):
            await asyncio.sleep(30.0)
            return ProvenanceValue("never", ProvenanceLabel.one())

        t0 = time.perf_counter()
        res, meta = await self.executor.execute(plan, {"slow_tool": _slow_handler}, root_cap, "t1", "s1", "run_to")
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.35)
        self.assertEqual(meta["node_statuses"]["n_slow"], "timeout_cancelled")
        self.assertEqual(res["n_slow"].value["error"], "node_timeout")

    async def test_deterministic_replay_bit_identity_and_divergence_detection(self):
        plan = DAGPlan(
            "d_rep",
            (
                DAGNode("n1", "step1", metadata={"x": 10}),
                DAGNode("n2", "step2", dependencies=("n1",), metadata={"mul": 3}),
            ),
        )
        calls = {"n1": 0, "n2": 0}

        async def _h1(node, deps, cap):
            calls["n1"] += 1
            return ProvenanceValue({"val": node.metadata["x"] + 5}, ProvenanceLabel.one())

        async def _h2(node, deps, cap):
            calls["n2"] += 1
            return ProvenanceValue({"val": deps["n1"].value["val"] * node.metadata["mul"]}, ProvenanceLabel.one())

        root_cap = self.auth.mint_root("k1", "t1", "s1", "d_rep", plan.plan_digest())
        out_rec, _ = await self.executor.execute(
            plan, {"step1": _h1, "step2": _h2}, root_cap, "t1", "s1", "run_orig", ReplayMode.RECORD
        )
        self.assertEqual(out_rec["n2"].value["val"], 45)
        self.assertEqual(calls, {"n1": 1, "n2": 1})

        # REPLAY mode: handlers must NOT re-execute, output must be bit-identical
        out_rep, meta_rep = await self.executor.execute(
            plan,
            {"step1": _h1, "step2": _h2},
            root_cap,
            "t1",
            "s1",
            "run_replay_1",
            ReplayMode.REPLAY,
            replay_source_run_id="run_orig",
        )
        self.assertEqual(out_rep["n2"].value["val"], 45)
        self.assertEqual(calls, {"n1": 1, "n2": 1})  # Zero live tool re-execution!
        self.assertEqual(meta_rep["node_statuses"]["n2"], "replayed:REPLAY")

        # Altered input during strict REPLAY raises NonDeterminismError
        mutated_plan = DAGPlan(
            "d_rep",
            (
                DAGNode("n1", "step1", metadata={"x": 999}),
                DAGNode("n2", "step2", dependencies=("n1",), metadata={"mul": 3}),
            ),
        )
        with self.assertRaises(NonDeterminismError):
            await self.executor.execute(
                mutated_plan,
                {"step1": _h1, "step2": _h2},
                root_cap,
                "t1",
                "s1",
                "run_replay_bad",
                ReplayMode.REPLAY,
                replay_source_run_id="run_orig",
            )

    async def test_chaos_circuit_breaker_failover_and_recovery(self):
        fail_count = {"n": 0}

        def _flaky_primary(prompt, tier):
            fail_count["n"] += 1
            if fail_count["n"] <= 3:
                return LLMResponse(False, "", 0.0, 5.0, 0.0, "primary_flaky", "PROVIDER_UNAVAILABLE", "http_503")
            return LLMResponse(True, "primary_recovered", 0.9, 10.0, 0.2, "primary_flaky", "CALIBRATED_TRACE_SIM")

        p1 = CalibratedTraceProvider("primary_flaky", handler=_flaky_primary)
        p2 = CalibratedTraceProvider(
            "secondary_backup",
            handler=lambda pr, tr: LLMResponse(True, "backup_ok", 0.85, 12.0, 0.3, "secondary_backup", "CALIBRATED_TRACE_SIM"),
        )
        chain = ProviderFailoverChain([p1, p2], failure_threshold=2, recovery_timeout_s=0.05)

        # Call 1 & 2: primary fails -> fails over seamlessly to backup; after 2 failures primary circuit OPENS
        r1 = await chain.generate("hello")
        r2 = await chain.generate("hello")
        self.assertTrue(r1.ok and r1.provider_name == "secondary_backup")
        self.assertTrue(r2.ok and r2.provider_name == "secondary_backup")
        self.assertEqual(chain.breakers["primary_flaky"].state, CircuitState.OPEN)

        # Wait recovery timeout -> HALF_OPEN probe fails once (call 3), then succeeds after another timeout
        await asyncio.sleep(0.06)
        r3 = await chain.generate("hello")
        self.assertEqual(r3.provider_name, "secondary_backup")
        await asyncio.sleep(0.06)
        r4 = await chain.generate("hello")
        self.assertEqual(r4.provider_name, "primary_flaky")
        self.assertEqual(chain.breakers["primary_flaky"].state, CircuitState.CLOSED)


if __name__ == "__main__":
    unittest.main()
