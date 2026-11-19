"""Checklist Security Hardening Tests: RFC 8785 Vectors, DB Restart Recovery, Cross-Tenant/Session, Rollback & Replay Safety."""
import secrets
import tempfile
import time
import unittest
from decimal import Decimal
from pathlib import Path

from nosih.config import NOSIHConfig
from nosih.plane1_security.jcs_v3 import jcs_dumps
from nosih.plane1_security.merkle_log import MerkleTransparencyLog
from nosih.plane1_security.postw_v3 import IntegrityLevel, POSTWPlusEngine, ProvenanceLabel, ProvenanceValue
from nosih.plane1_security.spcce_v3 import (
    AtomicJTIReplayStore,
    Caveat,
    SPCCEMacaroonAuthority,
    StrictSecretProvider,
)
from nosih.plane3_execution.dag_executor import CapabilityGatedDAGExecutor, DAGNode, DAGPlan
from nosih.plane3_execution.replay_engine import JournalStore, ReplayMode


class TestChecklistSecurityHardening(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.key = secrets.token_bytes(32)
        self.secrets = StrictSecretProvider({"k1": self.key})
        self.replay_path = self.td / "replay.db"
        self.auth = SPCCEMacaroonAuthority(self.secrets, AtomicJTIReplayStore(self.replay_path))
        self.cfg = NOSIHConfig()

    def tearDown(self):
        self._td.cleanup()

    def test_independent_rfc8785_test_vectors(self):
        # RFC 8785 Section 3.2.2.3 & Section 3.2.3 UTF-16 code-unit key ordering
        self.assertEqual(jcs_dumps({"numbers": [333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001]}),
                         '{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}')
        self.assertEqual(jcs_dumps({"\r": "Carriage Return", "1": "One", "\u0080": "Control", "\ufb33": "Hebrew", "\U0001f600": "Emoji"}),
                         '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\U0001f600":"Emoji","\ufb33":"Hebrew"}')

    def test_cross_tenant_cross_session_and_db_restart_recovery(self):
        jti = secrets.token_hex(16)
        cap = (
            self.auth.mint_root("k1", "tenant_A", "sess_1", "dag_1", "pd1", ttl_seconds=60.0)
            .attenuate(Caveat("tool_allowlist", {"tools": ["execute_neft_payout"]}))
            .attenuate(Caveat("hop_bind", {"dag_id": "dag_1", "hop_id": "h1"}))
            .attenuate(Caveat("schema_pin", {"schema_digest": "sd1"}))
            .attenuate(Caveat("ttl_max", {"expires_at": time.time() + 30.0}))
            .attenuate(Caveat("jti_single_use", {"jti": jti}))
        )
        base_ctx = {
            "tenant_id": "tenant_A", "session_id": "sess_1", "dag_id": "dag_1",
            "hop_id": "h1", "tool_name": "execute_neft_payout", "arguments": {}, "schema_digest": "sd1",
        }
        # Cross-tenant denied
        ok_t, r_t = self.auth.verify_and_consume(cap, {**base_ctx, "tenant_id": "tenant_B"})
        self.assertFalse(ok_t)
        self.assertEqual(r_t, "tenant_mismatch")

        # Cross-session denied
        ok_s, r_s = self.auth.verify_and_consume(cap, {**base_ctx, "session_id": "sess_2"})
        self.assertFalse(ok_s)
        self.assertEqual(r_s, "session_mismatch")

        # Legitimate first use succeeds
        ok_1, _ = self.auth.verify_and_consume(cap, base_ctx)
        self.assertTrue(ok_1)

        # Simulate process/database restart by opening a fresh AtomicJTIReplayStore from the same SQLite file!
        restarted_auth = SPCCEMacaroonAuthority(self.secrets, AtomicJTIReplayStore(self.replay_path))
        ok_after_restart, reason_r = restarted_auth.verify_and_consume(cap, base_ctx)
        self.assertFalse(ok_after_restart)
        self.assertEqual(reason_r, "replay_duplicate_jti")

    def test_atomic_budget_rollback_on_partial_failure(self):
        pw = POSTWPlusEngine(self.td / "pw.db", self.cfg.tool_origin_policy, self.cfg.allowlisted_egress_endpoints)
        pw.ingest_tool_output("t1", "s1", "erp_server", "get_vendor_invoice", "INV-900", {"approved_amount_inr": 10000})
        ok, _, rem = pw.consume_linear_budget("t1", "s1", ["get_vendor_invoice:INV-900"], "approved_amount_inr", 6000)
        self.assertTrue(ok)
        self.assertEqual(rem, Decimal("4000"))

        # Simulate downstream bank API failure -> atomic rollback restores 6000 (capped at 10000)
        rb_ok, new_rem = pw.rollback_linear_budget("t1", "s1", "get_vendor_invoice:INV-900", "approved_amount_inr", 6000)
        self.assertTrue(rb_ok)
        self.assertEqual(new_rem, Decimal("10000"))

        # Attempting to rollback more than initial_amount is safely capped at initial_amount
        rb_ok2, capped_rem = pw.rollback_linear_budget("t1", "s1", "get_vendor_invoice:INV-900", "approved_amount_inr", 999999)
        self.assertTrue(rb_ok2)
        self.assertEqual(capped_rem, Decimal("10000"))

    async def test_replay_never_repeats_real_financial_side_effects(self):
        mtlog = MerkleTransparencyLog(self.td / "mt.db", sth_signing_key=self.key)
        journal = JournalStore(self.td / "journal.db")
        executor = CapabilityGatedDAGExecutor(self.auth, mtlog, journal)
        plan = DAGPlan("d_fin", (DAGNode("n_pay", "neft_sink", metadata={"amt": 5000}),))
        root_cap = self.auth.mint_root("k1", "t1", "s1", "d_fin", plan.plan_digest())

        live_payouts = []

        async def _sink(node, deps, cap):
            live_payouts.append(node.metadata["amt"])
            return ProvenanceValue({"tx": "TXN-1", "amt": node.metadata["amt"]}, ProvenanceLabel.one())

        await executor.execute(plan, {"neft_sink": _sink}, root_cap, "t1", "s1", "run_fin_1", ReplayMode.RECORD)
        self.assertEqual(len(live_payouts), 1)

        # Replay 3 times -> live financial side effect count MUST remain 1!
        for k in range(3):
            out, _ = await executor.execute(
                plan, {"neft_sink": _sink}, root_cap, "t1", "s1", f"run_fin_rep_{k}", ReplayMode.REPLAY, "run_fin_1"
            )
            self.assertEqual(out["n_pay"].value["tx"], "TXN-1")
        self.assertEqual(len(live_payouts), 1)


if __name__ == "__main__":
    unittest.main()
