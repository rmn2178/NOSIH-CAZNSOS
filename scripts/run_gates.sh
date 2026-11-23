#!/usr/bin/env bash
# scripts/run_gates.sh — Local audit gate runner for nosih-caznsos (NOSIH-CAZNSOS)
set -euo pipefail
g() { echo "===== GATE $1 ====="; shift; "$@"; }

g A1  cargo build --release
g A2  bash -c '! grep -rn "unsafe " src/'
g A3  cargo fmt --all -- --check
g A4  cargo clippy --all-targets -- -D warnings
g A5  cargo test
g A6  cargo test --doc
g A8  bash -c 'test "$(find src -name "*.rs" | wc -l)" -eq 100'
g A12 bash -c '! grep -n "pub fn new" src/types/authorized.rs'
g A14 bash -c '! grep -rn "f64" src/plane1/budget/ src/types/decimal.rs'
g A16 bash -c '! grep -rn "println!" src/ --exclude=main.rs'
g A17 bash -c '! grep -rn "std::sync::Mutex" src/'
g A31 ./target/release/nosih-caznsos --self-test --stub-provider

echo "ALL LOCAL GATES PASSED"
