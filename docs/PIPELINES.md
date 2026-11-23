# NOSIH-CAZNSOS Pipelines Guide

This document details the four operational pipelines inside **NOSIH-CAZNSOS**:

1. [7-Stage Tri-Plane Request Pipeline](#1-7-stage-tri-plane-request-pipeline)
2. [Zero-Trust Key & Security Pipeline](#2-zero-trust-key--security-pipeline)
3. [Telemetry, Pure-Rust Visualization & 11-Format Export Pipeline](#3-telemetry-pure-rust-visualization--11-format-export-pipeline)
4. [GitHub Actions CI/CD Build & Audit Pipeline](#4-github-actions-cicd-build--audit-pipeline)

---

## 1. 7-Stage Tri-Plane Request Pipeline

Every `POST /v1/chat/completions` call traverses seven deterministic stages orchestrated by `src/kernel/`:

| Stage | Module | Plane | Responsibility |
| :--- | :--- | :--- | :--- |
| **Stage 1: Ingress** | `src/kernel/stage1_ingress.rs` | Plane I | Validates JSON payload, canonicalizes via RFC 8785 JCS, binds caller origin (`USER_DIRECT`, `SIGNED_ERP`, `UNTRUSTED`) into `ProvenanceValue<T, I, C>`, and computes a 10-dimensional CPU request feature vector. |
| **Stage 2: Semantic Cache** | `src/kernel/stage2_cache.rs` | Plane II | Embeds the prompt into a deterministic 320D signed feature-hash vector and queries the Provenance-Scoped Semantic Cache (`PS-RCSC`). Cache hits return immediately with `0g CO2` and skip upstream calls. |
| **Stage 3: Carbon-Conformal Dispatch** | `src/kernel/stage3_dispatch.rs` | Plane II + III | Queries the 24h diurnal grid carbon forecaster `C(t)`, updates the PID conformal prediction band, runs the LinUCB contextual bandit, applies PCSP C-DoW tier capping for untrusted origins, and short-circuits math/policy queries to CPU-only `nosih-symbolic` (`SafeDecimalAST` deterministic arithmetic). |
| **Stage 4: Static DAG + IFC Verify** | `src/kernel/stage4_verify.rs` | Plane III | Runs Kahn's topological sort and Information-Flow Control (IFC) lattice checks to prevent cycles or taint escalation before any upstream capability is minted. |
| **Stage 5: Capability Minting** | `src/kernel/stage5_mint.rs` | Plane I | Mints, attenuates, and verifies an HMAC-chained SPCCE-Macaroon (`CAT-PLM`) carrying exact `rust_decimal` budget bounds, returning the opaque compile-time token `Authorized<ProviderCall>`. |
| **Stage 6: Warmup & Execution** | `src/kernel/stage6_execute.rs` | Plane III | Pre-authorizes connection pool warmup (`PA-PCS-PMC` via `Authorized<ProviderWarmup>`), decrypts the provider key inside `SecretString` (zeroized on drop), and streams SSE/JSON from the selected upstream provider. |
| **Stage 7: CCEC & MTLog Commit** | `src/kernel/stage7_update.rs` | Kernel | Estimates Scope-2 energy/carbon (`PROXY_ESTIMATE`), updates the exact decimal budget ledger, appends a canonical leaf to the RFC 6962/9162 Merkle Tree (`MTLog`) with HMAC-SHA256 Signed Tree Head, and emits redacted events to the ring buffer, SQLite WAL, and live SSE stream. |

---

## 2. Zero-Trust Key & Security Pipeline

```text
  Key Upload (JSON / Array / JSONL / .env)
        │
        ▼  POST /admin/keys  (loopback-only + X-NOSIH-Admin CSRF header)
  SecretVault (src/config/secrets.rs)
        │  AES-256-GCM encrypt (HKDF subkey derived from dedicated 256-bit master.key, 0600)
        ▼
  SQLite Encrypted Vault (WAL mode, capped at 200 MB)
        │  Runtime resolve -> SecretString (Zeroize on drop, never cloned to plain String)
        ▼
  ProviderChain::call(Authorized<ProviderCall>, req)
        │  Secret Redactor intercepts any sk- / sk-ant- / AIza / gsk_ / Bearer token
        ▼
  Logs, SSE Stream & Exports receive only <REDACTED:sha256-prefix>
```

---

## 3. Telemetry, Pure-Rust Visualization & 11-Format Export Pipeline

1. **Event Capture**: Every stage emits a structured `KernelEvent` (`ts`, `request_id`, `stage`, `plane`, `severity`, `latency_us`, `tokens_in`, `tokens_out`, `cost_usd`, `co2_g`, `integrity`, `confidentiality`, `decision`) into the bounded in-memory ring buffer (`10,000` events) and batched SQLite WAL writer.
2. **4-Card Overview Telemetry (`GET /admin/metrics/cards`)**: Aggregates events over `15m`, `60m`, or `24h` into 48 time buckets per card across two carousel views:
   - **API View**: `CHAT COMPLETIONS`, `ROUTER & CACHE`, `AUTH & SECURITY`, `STORAGE & MTLOG`.
   - **Tri-Plane View**: `PLANE I · ZERO-TRUST`, `PLANE II · CARBON ROUTER`, `PLANE III · PROVIDERS`, `STORAGE & MTLOG`.
3. **Pure-Rust SVG Engine (`GET /admin/viz/svg`)**: Renders zero-dependency vector charts directly in Rust (`all`, `carbon`, `latency`, `planes`) supporting both `dark` and `light` monochrome palettes.
4. **Universal 11-Format Exporter (`GET/POST /admin/export`)**: Serializes redacted telemetry, carbon curves, and Merkle proofs into `json`, `jsonl`, `csv`, `tsv`, `md`, `txt`, `xml`, `otel`, `merkle`, `svg`, or standalone `html` — supporting both `~/Downloads/` disk save (`save_to_disk=true`) and direct browser download (`download=true`).

---

## 4. GitHub Actions CI/CD Build & Audit Pipeline

| Workflow | Trigger | Jobs & Verification |
| :--- | :--- | :--- |
| **`.github/workflows/audit.yml`** | Push, PR, weekly cron, manual dispatch | **Static & Security Invariants** (`clippy -D warnings`, exact 100 `src/*.rs` files, zero `unsafe`, private `Authorized<T>`, zero `f64` in money path, zero `println!` outside `main.rs`, zero `std::sync::Mutex`) + **Cross-Platform Test Matrix** (`ubuntu-latest`, `windows-latest`, `macos-latest` running `cargo test` and `--self-test --stub-provider`). |
| **`.github/workflows/build.yml`** | Push, PR, `v*` tags, manual dispatch | **Windows x86_64** (`cargo test --all-targets`, release `nosih-caznsos.exe`, smoke test, SHA-256 `sha.txt`, artifact upload, GitHub Release on `v*` tags), **Linux x86_64** (release binary, smoke test, artifact/release), and **Clippy & Tests** (`clippy -D warnings`, unit/integration/doc tests). |
