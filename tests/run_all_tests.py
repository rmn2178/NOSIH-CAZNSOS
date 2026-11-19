"""Master test runner for the structured 7-layer NOSIH verification suite."""
import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

LAYERS = ["unit", "crypto", "security", "control", "execution", "integration", "power"]


def main() -> int:
    t0 = time.perf_counter()
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for layer in LAYERS:
        layer_dir = ROOT / "tests" / layer
        if layer_dir.exists():
            suite.addTests(loader.discover(start_dir=str(layer_dir), pattern="test_*.py", top_level_dir=str(ROOT / "tests")))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    elapsed_s = round(time.perf_counter() - t0, 3)

    summary = {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "passed": result.wasSuccessful(),
        "elapsed_seconds": elapsed_s,
        "layers": LAYERS,
    }
    out_path = ROOT / "results" / "tests" / "test_suite_summary.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\n=== NOSIH STRUCTURED 7-LAYER TEST SUITE SUMMARY ===")
    print(json.dumps(summary, indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
