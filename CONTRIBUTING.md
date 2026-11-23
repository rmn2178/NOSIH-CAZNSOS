# Contributing to NOSIH-CAZNSOS

Thank you for contributing to **NOSIH-CAZNSOS**. Please follow the architectural invariants below before opening a pull request.

## Non-Negotiable Repository Invariants

- **Exact 100 Rust Source Files in `src/`**: `find src -name '*.rs' | wc -l` must equal `100`. Add new logic to existing domain modules rather than adding or removing `.rs` files under `src/`.
- **Zero Warnings & Zero Unsafe**: All code must compile cleanly under `#![forbid(unsafe_code)]` and `cargo clippy --all-targets -- -D warnings`.
- **No `std::sync::Mutex` in `src/`**: Use `tokio::sync::RwLock` / `tokio::sync::Mutex` or lock-free atomics.
- **No `println!` outside `src/main.rs`**: Emit structured telemetry via `tracing` or `KernelEvent`.
- **No `f64` in Money Paths**: Keep `src/types/decimal.rs` and `src/plane1/budget/` strictly on `rust_decimal`.
- **No Node.js Build Step**: Embedded UI assets in `src/ui/embedded/` must remain plain HTML/CSS/JS compatible with `default-src 'self'` CSP.

## Running Local Verification Gates

```bash
# Run all local audit, clippy, test, and self-test gates
bash scripts/run_gates.sh

# Run standalone Merkle proof verifier example
cargo run --example verify_merkle
```

## Release Workflow

1. Ensure `audit.yml` and `build.yml` are green on `main`.
2. Tag a semantic version release:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. GitHub Actions will automatically build `nosih-caznsos.exe` (Windows x86_64) and `nosih-caznsos` (Linux x86_64), generate `sha.txt`, and publish them to the GitHub Release page.
