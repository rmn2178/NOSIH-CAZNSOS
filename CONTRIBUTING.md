# Contributing to NOSIH

Thank you for your interest in contributing to **NOSIH**! Contributions that strengthen cryptographic verification, carbon-aware routing, conformal risk calibration, power modeling, or reproducibility are warmly welcome.

## Development Setup

```bash
git clone https://github.com/gpraveenraj/nosih.git
cd nosih
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"
```

## Verification Checklist

Before opening a pull request, ensure the entire verification pipeline passes cleanly:

```bash
make all
```

Specifically:
1. **Test Suite (`python3 tests/run_all_tests.py`):** All unit, cryptographic, security, control, execution, integration, and power tests must pass with zero failures or errors.
2. **Benchmarks (`python3 experiments/run_nosih_evaluation.py`):** Any change affecting routing, caching, power states, or security overhead must regenerate and verify benchmark metrics.
3. **Claim Integrity (`python3 experiments/verify_nosih_claims.py`):** All automated claim checks must pass with zero violations.

## Coding Standards

- Target **Python 3.11+** with clear type annotations and deterministic seeds for all stochastic experiments.
- Use exact `decimal.Decimal` arithmetic for all monetary budgets and linear resource invariants—never floating-point approximations.
- Keep Plane I security enforcement non-bypassable: every external tool invocation must traverse RFC 8785 JCS canonicalization, manifest verification, capability checking, provenance semiring validation, and Merkle logging.
- Add targeted regression tests under the matching `tests/<category>/` directory for every bug fix or new capability.

## Submitting a Pull Request

1. Fork the repository and create a focused feature branch (`git checkout -b feat/<short-name>`).
2. Commit concise, logically grouped changes with clear commit messages.
3. Run `make all` locally and include a brief summary of your changes and test output in the PR description.
4. For questions or design discussions, contact G Praveenraj at `gpraveenraj03@gmail.com`.
