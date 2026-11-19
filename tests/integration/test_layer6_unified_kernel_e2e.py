"""Layer 6: Unified ZeroTrustKernel End-to-End Integration Tests across Planes I, II, and III."""
import tempfile
import unittest
from pathlib import Path

import numpy as np

from nosih.kernel import ZeroTrustKernel
from nosih.plane3_execution.providers import CalibratedTraceProvider


SAMPLE_DOCS = [
    {"id": "DOC-101", "title": "GST Compliance SLA", "content": "Section 16(2)(aa) requires GSTR-2B matching for eligible ITC claims."},
    {"id": "DOC-102", "title": "NEFT Payout Policy", "content": "All vendor NEFT payouts above 50000 INR require dual verification."},
]


class TestLayer6UnifiedKernelE2E(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.kernel = ZeroTrustKernel(
            state_dir=Path(self._td.name),
            documents=SAMPLE_DOCS,
            providers=[CalibratedTraceProvider("sim_llm")],
        )

    def tearDown(self):
        self._td.cleanup()

    async def test_e2e_ast_rag_signal_and_merkle_audit_trail(self):
        # Train router lightly on deterministic arms so it selects them directly
        p_math = self.kernel.profiler.profile("Calculate (125 + 75) * 4")
        self.kernel.router.update(1, p_math.vector, 1.0, (0.01, 0.01))
        res_math = await self.kernel.execute_request({"prompt": "Calculate (125 + 75) * 4"}, explore=False)
        self.assertTrue(res_math["ok"])
        self.assertEqual(res_math["answer"], "800")
        self.assertEqual(res_math["arm"], "A1_DECIMAL_AST")

        # RAG query
        p_rag = self.kernel.profiler.profile("What does GST compliance policy say about GSTR-2B ITC claims?")
        self.kernel.router.update(2, p_rag.vector, 1.0, (0.01, 0.01))
        res_rag = await self.kernel.execute_request(
            {"prompt": "What does GST compliance policy say about GSTR-2B ITC claims?"}, explore=False
        )
        self.assertTrue(res_rag["ok"])
        self.assertIn("GSTR-2B", res_rag["answer"])

        # Raw 1024-pt 8192Hz FFT waveform (exact 512 Hz tone)
        t = np.arange(1024) / 8192.0
        wf = np.sin(2.0 * np.pi * 512.0 * t).astype(np.float32)
        p_sig = self.kernel.profiler.profile("Extract dominant frequency from sensor waveform", {"waveform": wf})
        self.kernel.router.update(4, p_sig.vector, 1.0, (0.02, 0.01))
        res_sig = await self.kernel.execute_request(
            {"prompt": "Extract dominant frequency from sensor waveform", "raw_payload": {"waveform": wf}},
            explore=False,
        )
        self.assertTrue(res_sig["ok"])
        self.assertAlmostEqual(res_sig["answer"]["dominant_freq_hz"], 512.0, delta=1.0)

        # Verify every execution was anchored in MTLog with valid O(log N) inclusion proofs
        tree_sz = self.kernel.merkle_log.size()
        self.assertGreaterEqual(tree_sz, 3)
        sth = self.kernel.merkle_log.get_sth(tree_sz)
        self.assertTrue(self.kernel.merkle_log.verify_sth_signature(sth))
        for i in range(tree_sz):
            payload, _ = self.kernel.merkle_log.get_leaf(i)
            proof = self.kernel.merkle_log.inclusion_proof(i, tree_sz)
            self.assertTrue(self.kernel.merkle_log.verify_inclusion(payload, i, tree_sz, proof, sth.root_hash_hex))

    async def test_e2e_rejects_ground_truth_leakage(self):
        with self.assertRaises(ValueError):
            await self.kernel.execute_request({"prompt": "Calculate 2 + 2", "ground_truth": "4"})


if __name__ == "__main__":
    unittest.main()
