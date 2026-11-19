"""Layer 1: Strict RFC 8785 JCS, Fail-Closed Policy, Provenance Semiring PBT & AST Fuzzing."""
import math
import random
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from nosih.config import PolicyLoadError, assert_no_forbidden_keys, load_config_fail_closed
from nosih.plane1_security.jcs_v3 import (
    DuplicateKeyError,
    JCSValidationError,
    jcs_dumps,
    jcs_sha256,
    parse_json_strict,
)
from nosih.plane1_security.postw_v3 import (
    ConfidentialityTier,
    IntegrityLevel,
    ProvenanceLabel,
    WitnessAtom,
)
from nosih.plane3_execution.tools import SafeDecimalASTEvaluator


class TestLayer1JCSAndPBT(unittest.TestCase):
    def test_t01_rfc8785_float_boundaries(self):
        obj = {"a": 1e-5, "b": 1e-6, "c": 1e-7, "d": -0.0, "e": 1e20, "f": 1e21}
        out = jcs_dumps(obj)
        self.assertEqual(
            out,
            '{"a":0.00001,"b":0.000001,"c":1e-7,"d":0,"e":100000000000000000000,"f":1e+21}',
        )

    def test_t02_lone_utf16_surrogates_fail_closed(self):
        with self.assertRaises(JCSValidationError):
            jcs_dumps({"\ud800": 1})
        with self.assertRaises(JCSValidationError):
            jcs_dumps({"a": "\udfff"})

    def test_t03_duplicate_json_keys_rejected(self):
        raw = '{"amount_inr": 100, "amount_inr": 999999}'
        with self.assertRaises(DuplicateKeyError):
            parse_json_strict(raw)

    def test_jcs_nan_infinity_and_safe_int_rejected(self):
        with self.assertRaises(JCSValidationError):
            jcs_dumps({"x": float("nan")})
        with self.assertRaises(JCSValidationError):
            jcs_dumps({"x": float("inf")})
        with self.assertRaises(JCSValidationError):
            jcs_dumps({"x": (1 << 53)})

    def test_jcs_key_permutation_invariance_pbt(self):
        rng = random.Random(42)
        base_keys = [f"key_{i}" for i in range(12)] + ["\u00e9", "\u20ac", "A", "a"]
        base_obj = {k: rng.randint(-1000, 1000) for k in base_keys}
        ref_hash = jcs_sha256(base_obj)
        for _ in range(50):
            keys = list(base_keys)
            rng.shuffle(keys)
            perm_obj = {k: base_obj[k] for k in keys}
            self.assertEqual(jcs_sha256(perm_obj), ref_hash)

    def test_t07_fail_closed_policy_loader(self):
        with tempfile.TemporaryDirectory() as td:
            bad_path = Path(td) / "corrupt.json"
            bad_path.write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(PolicyLoadError):
                load_config_fail_closed(bad_path)
            unknown_path = Path(td) / "unknown.json"
            unknown_path.write_text('{"nonexistent_knob": true}', encoding="utf-8")
            with self.assertRaises(PolicyLoadError):
                load_config_fail_closed(unknown_path)
            with self.assertRaises(PolicyLoadError):
                load_config_fail_closed(Path(td) / "missing.json")

    def test_provenance_semiring_algebraic_laws_pbt(self):
        rng = random.Random(1337)
        pool = []
        for i in range(20):
            atom = WitnessAtom("srv", "tool", f"R{i}", "f", f"h{i}", "POL")
            pool.append(
                ProvenanceLabel(
                    integrity=IntegrityLevel(rng.randint(0, 6)),
                    conf_tier=ConfidentialityTier(rng.randint(0, 3)),
                    readers=frozenset(rng.sample(["r1", "r2", "r3", "r4"], rng.randint(1, 3))),
                    witnesses=frozenset({atom}),
                    deriv_hash=f"dh_{i}",
                )
            )
        for _ in range(100):
            a, b, c = rng.sample(pool, 3)
            # Commutativity of mul and add
            self.assertEqual(a.mul(b), b.mul(a))
            self.assertEqual(a.add(b), b.add(a))
            # Monotonicity: integrity & conf_tier never decrease (never upgrade trust or downgrade sensitivity)
            ab = a.mul(b)
            self.assertGreaterEqual(int(ab.integrity), max(int(a.integrity), int(b.integrity)))
            self.assertGreaterEqual(int(ab.conf_tier), max(int(a.conf_tier), int(b.conf_tier)))
            self.assertTrue(ab.readers.issubset(a.readers))
            self.assertTrue(ab.readers.issubset(b.readers))
            # Absorbing UNTRUSTED top element
            untrusted = ProvenanceLabel.zero()
            self.assertEqual(a.mul(untrusted).integrity, IntegrityLevel.UNTRUSTED)

    def test_ast_sandbox_fuzzing_and_injection_rejection(self):
        ev = SafeDecimalASTEvaluator()
        rng = random.Random(99)
        for _ in range(100):
            x = rng.randint(1, 500)
            y = rng.randint(1, 500)
            z = rng.randint(1, 50)
            expr = f"({x} + {y}) * {z}"
            ok, val, _ = ev.evaluate(expr)
            self.assertTrue(ok)
            self.assertEqual(val, Decimal(x + y) * Decimal(z))

        for bad in (
            "__import__('os').system('id')",
            "open('/etc/passwd').read()",
            "(1).__class__.__mro__",
            "10 / 0",
            "2 ** 100000",
            "True + 1",
        ):
            ok, val, _ = ev.evaluate(bad)
            self.assertFalse(ok, f"Should reject unsafe expression: {bad}")
            self.assertIsNone(val)

    def test_forbidden_runtime_keys_rejected(self):
        with self.assertRaises(ValueError):
            assert_no_forbidden_keys({"prompt": "hi", "ground_truth": "42"})
        with self.assertRaises(ValueError):
            assert_no_forbidden_keys({"prompt": "hi", "task_hint": "V3"})


if __name__ == "__main__":
    unittest.main()
