"""Layer 2: SPCCE-Macaroon Capability Attenuation, Concurrent JTI Replay & RFC 6962/9162 Merkle Proofs."""
import concurrent.futures
import secrets
import tempfile
import time
import unittest
from pathlib import Path

from nosih.plane1_security.jcs_v3 import jcs_bytes
from nosih.plane1_security.merkle_log import MerkleTransparencyLog
from nosih.plane1_security.shadow_v3 import AuthenticatedShadowReceipt, CSDDShadowSinkV3
from nosih.plane1_security.spcce_v3 import (
    AtomicJTIReplayStore,
    AttenuatedCapability,
    Caveat,
    MissingSecretError,
    SPCCEMacaroonAuthority,
    StrictSecretProvider,
)


class TestLayer2CryptoAndMerkle(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.key = secrets.token_bytes(32)
        self.secrets = StrictSecretProvider({"k1": self.key})
        self.replay = AtomicJTIReplayStore(self.td / "replay.db")
        self.auth = SPCCEMacaroonAuthority(self.secrets, self.replay)
        self.mtlog = MerkleTransparencyLog(self.td / "mtlog.db", sth_signing_key=self.key)
        self.shadow = CSDDShadowSinkV3(self.mtlog, receipt_key=self.key)

    def tearDown(self):
        self._td.cleanup()

    def _base_sink_cap(self, max_amt: str, dag_id="dag_1", hop_id="hop_1", jti=None):
        root = self.auth.mint_root("k1", "t1", "s1", dag_id, "plan_digest_1", ttl_seconds=60.0)
        return (
            root
            .attenuate(Caveat("tool_allowlist", {"tools": ["execute_neft_payout"]}))
            .attenuate(Caveat("arg_max_decimal", {"field": "amount_inr", "max_value": "50000"}))
            .attenuate(Caveat("arg_max_decimal", {"field": "amount_inr", "max_value": max_amt}))
            .attenuate(Caveat("hop_bind", {"dag_id": dag_id, "hop_id": hop_id}))
            .attenuate(Caveat("schema_pin", {"schema_digest": "sd_1"}))
            .attenuate(Caveat("ttl_max", {"expires_at": time.time() + 30.0}))
            .attenuate(Caveat("jti_single_use", {"jti": jti or secrets.token_hex(16)}))
        )

    def _ctx(self, amount, dag_id="dag_1", hop_id="hop_1"):
        return {
            "tenant_id": "t1",
            "session_id": "s1",
            "dag_id": dag_id,
            "hop_id": hop_id,
            "tool_name": "execute_neft_payout",
            "arguments": {"amount_inr": amount},
            "schema_digest": "sd_1",
        }

    def test_t08_t09_t10_t11_t12_macaroon_attenuation_and_security(self):
        # T-08: Valid 2-hop attenuation (50000 -> 10000): 8000 allowed, 15000 denied
        c_ok = self._base_sink_cap("10000")
        ok, reason = self.auth.verify_and_consume(c_ok, self._ctx(8000))
        self.assertTrue(ok, reason)

        c_hi = self._base_sink_cap("10000")
        ok, reason = self.auth.verify_and_consume(c_hi, self._ctx(15000))
        self.assertFalse(ok)
        self.assertIn("arg_max_decimal", reason)

        # T-09: Caveat stripping attack
        c_strip = AttenuatedCapability(
            cap_id=c_hi.cap_id,
            key_id=c_hi.key_id,
            tenant_id=c_hi.tenant_id,
            session_id=c_hi.session_id,
            dag_id=c_hi.dag_id,
            dag_plan_digest=c_hi.dag_plan_digest,
            issued_at=c_hi.issued_at,
            max_expires_at=c_hi.max_expires_at,
            caveats=c_hi.caveats[:-1],
            tag_hex=c_hi.tag_hex,
        )
        ok, reason = self.auth.verify_and_consume(c_strip, self._ctx(8000))
        self.assertFalse(ok)
        self.assertEqual(reason, "invalid_capability_mac")

        # T-10: Privilege escalation attempt (appending wider limit cannot override narrower limit)
        c_esc = self._base_sink_cap("10000").attenuate(
            Caveat("arg_max_decimal", {"field": "amount_inr", "max_value": "999999"})
        )
        ok, reason = self.auth.verify_and_consume(c_esc, self._ctx(50000))
        self.assertFalse(ok)
        self.assertIn("arg_max_decimal", reason)

        # T-11: Cross-DAG / cross-hop replay
        c_hop = self._base_sink_cap("10000", dag_id="dag_A", hop_id="node_1")
        ok, reason = self.auth.verify_and_consume(c_hop, self._ctx(5000, dag_id="dag_B", hop_id="node_1"))
        self.assertFalse(ok)
        self.assertEqual(reason, "dag_mismatch")

        # T-12: Unknown key_id fails closed (zero fallback)
        c_bad_kid = AttenuatedCapability(**{**c_hop.__dict__, "key_id": "k999"})
        ok, reason = self.auth.verify_and_consume(c_bad_kid, self._ctx(5000, dag_id="dag_A", hop_id="node_1"))
        self.assertFalse(ok)
        self.assertIn("unknown_key_id", reason)

        # Weak key rejected at init
        with self.assertRaises(MissingSecretError):
            StrictSecretProvider({"k_weak": b"too_short_16byte"})

    def test_t13_t14_t15_concurrent_jti_replay_parallel_dag_and_pruning(self):
        # T-13: 16-thread concurrent identical JTI race -> exactly 1/16 allowed
        shared_cap = self._base_sink_cap("10000", jti=secrets.token_hex(16))
        ctx = self._ctx(5000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            futs = [pool.submit(self.auth.verify_and_consume, shared_cap, ctx) for _ in range(16)]
            outcomes = [f.result()[0] for f in futs]
        self.assertEqual(sum(outcomes), 1)

        # T-14: 8 parallel legitimate DAG branches with distinct JTIs completing out-of-order -> 8/8 allowed
        caps_and_ctxs = [
            (self._base_sink_cap("10000", dag_id="dag_par", hop_id=f"branch_{i}"), self._ctx(1000, dag_id="dag_par", hop_id=f"branch_{i}"))
            for i in range(8)
        ]
        # Submit in reverse order concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(self.auth.verify_and_consume, c, x) for c, x in reversed(caps_and_ctxs)]
            outcomes = [f.result()[0] for f in futs]
        self.assertEqual(sum(outcomes), 8)

        # T-15: Expired JTI pruning keeps replay store bounded
        past = time.time() - 500.0
        for i in range(50):
            self.replay.consume_jti(f"expired_jti_{i:016d}", "dag_old", "h", expires_at=past, now=past)
        deleted = self.replay.prune_expired(now=time.time(), grace_seconds=60.0)
        self.assertEqual(deleted, 50)

    def test_t21_t22_t23_t24_merkle_proofs_concurrency_and_shadow_receipt(self):
        # T-21 & T-22: Build 128-leaf Merkle tree, verify O(log N) inclusion & consistency proofs + tamper detection
        sths = {}
        for i in range(128):
            idx, _, sth = self.mtlog.append({"seq": i, "action": "tool_call"})
            self.assertEqual(idx, i)
            self.assertTrue(self.mtlog.verify_sth_signature(sth))
            if i + 1 in (1, 16, 37, 64, 100, 128):
                sths[i + 1] = sth

        # Verify inclusion for multiple leaves at size 128 (proof length <= 7)
        for leaf_idx in (0, 1, 36, 63, 99, 127):
            payload, _ = self.mtlog.get_leaf(leaf_idx)
            proof = self.mtlog.inclusion_proof(leaf_idx, 128)
            self.assertLessEqual(len(proof), 7)
            self.assertTrue(
                MerkleTransparencyLog.verify_inclusion(payload, leaf_idx, 128, proof, sths[128].root_hash_hex)
            )
            # 1-byte tamper fails verification
            tampered = payload[:-1] + b"X"
            self.assertFalse(
                MerkleTransparencyLog.verify_inclusion(tampered, leaf_idx, 128, proof, sths[128].root_hash_hex)
            )

        # Verify consistency proofs across historical STH pairs
        for old_sz, new_sz in ((1, 16), (16, 64), (37, 100), (64, 128), (100, 128)):
            cproof = self.mtlog.consistency_proof(old_sz, new_sz)
            self.assertTrue(
                MerkleTransparencyLog.verify_consistency(
                    old_sz, new_sz, sths[old_sz].root_hash_hex, sths[new_sz].root_hash_hex, cproof
                )
            )
            # Fake rewritten old root fails consistency check
            fake_old = "00" * 32
            self.assertFalse(
                MerkleTransparencyLog.verify_consistency(
                    old_sz, new_sz, fake_old, sths[new_sz].root_hash_hex, cproof
                )
            )

        # T-23: 16-thread concurrent audit log appends -> zero forks, contiguous indices
        mt_conc = MerkleTransparencyLog(self.td / "mtlog_conc.db", sth_signing_key=self.key)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            futs = [pool.submit(mt_conc.append, {"worker": i}) for i in range(32)]
            indices = sorted(f.result()[0] for f in futs)
        self.assertEqual(indices, list(range(32)))
        final_sth = mt_conc.get_sth(32)
        for i in (0, 15, 31):
            p_bytes, _ = mt_conc.get_leaf(i)
            self.assertTrue(
                MerkleTransparencyLog.verify_inclusion(p_bytes, i, 32, mt_conc.inclusion_proof(i, 32), final_sth.root_hash_hex)
            )

        # T-24: Authenticated ShadowQuarantineReceipt tamper detection
        receipt = self.shadow.quarantine("t1", "s1", "execute_neft_payout", {"amount_inr": 999999}, "insufficient_budget", "wd_1")
        self.assertTrue(self.shadow.verify_receipt(receipt))
        tampered_body = {**receipt.receipt_body, "real_effect_executed": True}
        bad_receipt = AuthenticatedShadowReceipt(
            receipt_body=tampered_body,
            leaf_index=receipt.leaf_index,
            sth=receipt.sth,
            inclusion_proof=receipt.inclusion_proof,
            receipt_mac_hex=receipt.receipt_mac_hex,
        )
        self.assertFalse(self.shadow.verify_receipt(bad_receipt))


if __name__ == "__main__":
    unittest.main()
