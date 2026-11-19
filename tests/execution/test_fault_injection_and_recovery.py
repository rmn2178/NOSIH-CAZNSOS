import sqlite3
import tempfile
import unittest
from pathlib import Path

from nosih.plane1_security.postw_v3 import IntegrityLevel
from nosih.plane2_control.online_conformal import DualChannelACIGate
from nosih.plane2_control.provenance_cache import ProvenanceScope, ProvenanceScopedSemanticCache
from nosih.plane3_execution.providers import CalibratedTraceProvider, ProviderFailoverChain
from nosih.plane3_execution.replay_engine import JournalStore


class TestFaultInjectionAndRecovery(unittest.IsolatedAsyncioTestCase):
    """Checklist reliability tests: corrupted journal detection, stale cache expiry, and provider failover."""

    def test_corrupted_replay_journal_raises_clean_sqlite_error(self):
        with tempfile.TemporaryDirectory() as td:
            jpath = Path(td) / "corrupt_journal.db"
            store = JournalStore(jpath)
            store.append_event("r1", "n1", "TOOL_CALL", {"q": 1}, {"v": 42})
            events = store.load_run("r1")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].node_id, "n1")
            # Corrupt the SQLite header bytes to simulate unrecoverable disk corruption
            jpath.write_bytes(b"CORRUPTED_NON_SQLITE_HEADER_BYTES" * 16)
            with self.assertRaises(sqlite3.DatabaseError):
                JournalStore(jpath).load_run("r1")

    def test_cache_ttl_expiry_and_policy_epoch_invalidation(self):
        gate = DualChannelACIGate()
        cache = ProvenanceScopedSemanticCache(aci_gate=gate, default_ttl_seconds=10.0)
        scope_e1 = ProvenanceScope(
            tenant_id="tenant-a",
            corpus_version="c1",
            model_version="m1",
            policy_epoch="epoch-1",
            origin_integrity=IntegrityLevel.USER_DIRECT,
        )
        scope_e2 = ProvenanceScope(
            tenant_id="tenant-a",
            corpus_version="c1",
            model_version="m1",
            policy_epoch="epoch-2",
            origin_integrity=IntegrityLevel.USER_DIRECT,
        )
        stored = cache.store(
            prompt="What is the capital of France?",
            scope=scope_e1,
            answer="Paris",
            confidence=0.98,
            conformal_accepted=True,
            ttl_seconds=10.0,
            now=1000.0,
        )
        self.assertTrue(stored)
        hit, val, _ = cache.lookup(
            "What is the capital of France?",
            scope_e1,
            risk_score=0.01,
            predicted_min_exec_ms=50.0,
            now=1005.0,
        )
        self.assertTrue(hit)
        self.assertEqual(val, "Paris")
        # Policy epoch bump immediately isolates & invalidates cache hit
        hit_e2, _, _ = cache.lookup(
            "What is the capital of France?",
            scope_e2,
            risk_score=0.01,
            predicted_min_exec_ms=50.0,
            now=1005.0,
        )
        self.assertFalse(hit_e2)
        # TTL expiry invalidates stale cache entry
        hit_expired, _, _ = cache.lookup(
            "What is the capital of France?",
            scope_e1,
            risk_score=0.01,
            predicted_min_exec_ms=50.0,
            now=1015.0,
        )
        self.assertFalse(hit_expired)

    async def test_provider_failover_recovers_from_primary_fault(self):
        def failing_handler(prompt: str, tier: str):
            raise RuntimeError("injected upstream 503 fault")

        primary = CalibratedTraceProvider(name="primary-faulty", handler=failing_handler)
        backup = CalibratedTraceProvider(name="backup-healthy")
        chain = ProviderFailoverChain([primary, backup], failure_threshold=1, recovery_timeout_s=5.0)
        resp = await chain.generate("Summarize status", tier="small")
        self.assertEqual(resp.provider_name, "backup-healthy")
        self.assertTrue(resp.ok)


if __name__ == "__main__":
    unittest.main()
