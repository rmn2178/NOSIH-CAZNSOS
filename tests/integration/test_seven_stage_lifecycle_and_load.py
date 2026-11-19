"""Checklist Integration Tests: 7-Stage Lifecycle Order, 10/50/100 Concurrent Load & Hardware Probe."""
import asyncio
import tempfile
import time
import unittest
from pathlib import Path

from nosih.kernel import ZeroTrustKernel
from nosih.plane3_execution.hardware_probe import probe_hardware_environment
from nosih.plane3_execution.providers import CalibratedTraceProvider


SAMPLE_DOCS = [
    {"id": "DOC-1", "title": "GST Policy", "content": "Section 16(2)(aa) requires GSTR-2B matching for ITC claims."},
]


class TestSevenStageLifecycleAndLoad(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.kernel = ZeroTrustKernel(
            state_dir=Path(self._td.name),
            documents=SAMPLE_DOCS,
            providers=[CalibratedTraceProvider("sim_llm")],
        )

    def tearDown(self):
        self._td.cleanup()

    async def test_exact_seven_stage_lifecycle_order_and_cache_short_circuit(self):
        # Train arm 1 lightly so deterministic math goes to AST
        prof = self.kernel.profiler.profile("Calculate (40 + 60) * 3")
        self.kernel.router.update(1, prof.vector, 1.0, (0.01, 0.01))

        res = await self.kernel.execute_request({"prompt": "Calculate (40 + 60) * 3"}, local_hour=13.0, explore=False)
        self.assertTrue(res["ok"])
        self.assertEqual(res["answer"], "300")
        self.assertEqual(
            res["stage_trace"],
            [
                "stage1_leakage_isolation",
                "stage2_10d_profiler",
                "stage3_ps_rcsc_cache",
                "stage4_carbon_primal_dual_routing",
                "stage5_static_dag_and_root_cap",
                "stage6_capability_gated_execution",
                "stage7_conformal_pid_and_feedback",
            ],
        )
        self.assertIn("energy_footprint", res)
        self.assertGreaterEqual(res["carbon_intensity_g_per_kwh"], 180.0)

        # Second identical request hits PS-RCSC cache and short-circuits cleanly at Stage 3!
        res_hit = await self.kernel.execute_request({"prompt": "Calculate (40 + 60) * 3"}, local_hour=13.0, explore=False)
        self.assertEqual(res_hit["arm"], "CACHE_HIT")
        self.assertEqual(res_hit["answer"], "300")
        self.assertEqual(
            res_hit["stage_trace"],
            ["stage1_leakage_isolation", "stage2_10d_profiler", "stage3_ps_rcsc_cache"],
        )

    async def test_concurrency_load_10_50_100_async_requests(self):
        prof = self.kernel.profiler.profile("Calculate 10 + 20")
        self.kernel.router.update(1, prof.vector, 1.0, (0.01, 0.01))

        for batch_size in (10, 50, 100):
            t0 = time.perf_counter()
            tasks = [
                self.kernel.execute_request(
                    {"prompt": f"Calculate ({i} + 5) * 2", "run_id": f"load_{batch_size}_{i}"},
                    explore=False,
                )
                for i in range(batch_size)
            ]
            results = await asyncio.gather(*tasks)
            elapsed = time.perf_counter() - t0
            self.assertEqual(len(results), batch_size)
            self.assertTrue(all(r["ok"] for r in results))
            self.assertGreater(batch_size / max(1e-6, elapsed), 5.0)

    def test_honest_hardware_environment_probe(self):
        hw = probe_hardware_environment()
        self.assertIn("os", hw)
        self.assertIn("python_version", hw)
        self.assertIn("rapl_available", hw)
        self.assertIn("nvml_available", hw)
        self.assertIn(hw["energy_accounting_mode"], ("MEASURED_HW", "HYBRID_CPU_TDP"))


if __name__ == "__main__":
    unittest.main()
