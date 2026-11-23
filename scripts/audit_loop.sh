#!/usr/bin/env bash
# scripts/audit_loop.sh — 7-Iteration Recursive Audit Driver
set -euo pipefail
mkdir -p audit
for i in $(seq 1 7); do
  echo "=== NOSIH-CAZNSOS AUDIT ITERATION $i ==="
  ./scripts/run_gates.sh 2>&1 | tee "audit/iter_${i}_gates.log"
done
echo "ALL 7 AUDIT ITERATIONS COMPLETED"
