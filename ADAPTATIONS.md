# ADAPTATIONS.md

> **What this file is.** The NOSIH paper (`paper/nosih_paper.tex` and `docs/FORMAL_PROOFS.md`)
> targets GPU-orchestration semantics. `nosih-caznsos` (`NOSIH-CAZNSOS`) is a single-binary,
> desktop OpenAI-compatible multi-provider LLM proxy in pure Rust. This file documents every
> mapping between a paper novelty and its proxy equivalent, states **what is genuinely enforced**
> vs. what is approximated, and pins the honest scope of each claim.

## 0. Reading Guide

- **Enforced** = violated at *compile time* or rejected by an automated test in this repository.
- **Approximated** = implemented with a documented proxy model where hardware or network inputs differ from the paper's GPU simulation.
- **Deferred** = explicitly out of scope for `v0.1.x` (tracked in §4).

## 1. Core Cross-Plane Adaptations

### 1.1 Plane I — Zero-Trust Reference Monitor (`CAT-PLM`)
- **Paper §:** §4 (Plane I), Theorem 1
- **Proxy mapping:** Every upstream provider call traverses `kernel::stage4_verify` -> `plane1::macaroon::chain::verify` -> `plane1::budget` atomic debit -> `Authorized<ProviderCall>` construction.
- **Files:** `src/types/authorized.rs`, `src/plane1/macaroon/chain.rs`, `src/plane3/providers/chain.rs`, `src/kernel/stage4_verify.rs`
- **Enforced:** `Authorized<T>` has a private inner field and zero `pub fn new()` constructors. `plane3::providers::chain::ProviderChain::call` requires `Authorized<ProviderCall>`.
- **Verification:** `cargo test plane1::macaroon::chain::tests`

### 1.2 SPCCE-Macaroon — Offline-Attenuable Per-Request Capabilities
- **Paper §:** §4 (Plane I)
- **Proxy mapping:** Per-request capability scoped to `(provider, model, max_usd, ttl_secs, jti)` with HKDF-SHA256 session derivation and chained HMAC-SHA256 caveat attenuation.
- **Files:** `src/plane1/macaroon/{mod,caveat,chain}.rs`, `src/plane1/crypto/{hmac,hkdf,secrets}.rs`
- **Enforced:** Attenuation only appends caveats; tampering any caveat fails constant-time `subtle::ConstantTimeEq` verification.
- **Verification:** `cargo test plane1::macaroon::chain::tests::tampered_caveat_rejected`

### 1.3 POST-W++ — Integrity × Confidentiality Semiring
- **Paper §:** §4 (Plane I), Theorem 1 & Theorem 3
- **Proxy mapping:** `ProvenanceValue<T, I: IntegrityLevel, C: ConfidentialityLevel>` carries lattice levels as compile-time phantom types alongside runtime semiring joins `(max, reader_intersection)`.
- **Files:** `src/types/{integrity,confidentiality,provenance}.rs`, `src/plane1/semiring/mod.rs`
- **Enforced:** Privileged sinks bounded on `SignedErp` do not compile with `Untrusted` values; semiring associativity/commutativity verified in `plane1::semiring::tests`.

### 1.4 PS-RCSC — Provenance-Scoped Semantic Cache
- **Paper §:** §4 (Plane II, C2)
- **Proxy mapping:** Partitioned by `blake3(JCS({tenant, model_class, policy_epoch, integrity, schema_digest}))` with polarity/numeric guards, cost-aware bypass, and normalized float32 cosine search.
- **Files:** `src/plane2/cache/{mod,key,store,search}.rs`
- **Enforced:** Untrusted origins are unconditionally refused (`bypass_untrusted_origin`); cross-tenant keys never collide.

### 1.5 CA-DPD-LinUCB + Dual-Channel Conformal PID
- **Paper §:** §4 (Plane II, C3), Theorem 4
- **Proxy mapping:** Discounted LinUCB over arms `{Cache, Symbolic, Small, Medium, Large}` with online projected dual ascent over latency, cost, and carbon constraints, paired with Conformal PID ($\alpha = 0.05$).
- **Files:** `src/plane2/bandit/{mod,linucb}.rs`, `src/plane2/conformal/{mod,pid}.rs`
- **Enforced:** Numerical P-only telescoping bound verified across 10,000 rounds in `plane2::conformal::pid::tests::p_only_telescoping_bound_holds`.

### 1.6 10D Anti-Spoofing CPU Profiler
- **Paper §:** §4 (Plane II, C2)
- **Proxy mapping:** Extracts length, symbolic math/RAG cues, risk density, lexical uniqueness, and token/character Shannon entropy, flagging repetition stuffing (`n > 15 && u < 0.55`) and unique-filler DoW (`n > 25 && u > 0.85 && risk_density < 0.06`).
- **Files:** `src/plane2/profiler/{mod,features}.rs`

### 1.7 PCSP — Provenance-Coupled Carbon-Security Pricing
- **Paper §:** §4 (Plane II, C6.1), Theorem 5
- **Proxy mapping:** Injects $\Phi_{\text{PCSP}}(\iota, a, C(t)) = \lambda_{\text{sec}} (\iota / 6)(P_a / P_{T_3})(C(t) / C_{\text{ref}})$ into routing costs and hard-caps unauthenticated `Untrusted` callers at `Small` (or `Symbolic`).
- **Files:** `src/plane2/pcsp.rs`

### 1.8 PCS-PMC + PA-PCS-PMC — Pre-Authorized Provider Warm-State Control
- **Paper §:** §4 (Plane III, C5, C6.2), Theorem 5
- **Proxy mapping:** Manages per-provider connection pools across `ACTIVE`, `WARM`, and `DEEP` using EWMA-hysteresis demotion scaled by $M_C(t) = \text{clip}(C_{\text{ref}}/C(t), 0.65, 1.35)$. Calling warmup requires `Authorized<ProviderWarmup>`, constructible only from a verified `Authorized<ProviderCall>`.
- **Files:** `src/plane3/power/{mod,state,controller,accountant,pa_pcs_pmc}.rs`

### 1.9 CCEC + MTLog — RFC 6962/9162 Binary Merkle Carbon Audit
- **Paper §:** §4 (Plane I, C6.3), Theorem 3
- **Proxy mapping:** Commits RFC 8785 JCS Scope-2 proxy certificates into SQLite WAL `MTLog` with `0x00`/`0x01` domain separation and distinct `LeafHash` / `NodeHash` newtypes.
- **Files:** `src/plane1/carbon_cert.rs`, `src/plane1/merkle/{mod,proof}.rs`, `examples/verify_merkle.rs`

## 2. Compile-Time Invariants

| Invariant | Type | Enforcement Site |
| :--- | :--- | :--- |
| Provider call requires auth | `Authorized<ProviderCall>` | `src/types/authorized.rs`, `src/plane3/providers/chain.rs` |
| Provider warmup requires auth | `Authorized<ProviderWarmup>` | `src/plane3/power/pa_pcs_pmc.rs` |
| Integrity × Confidentiality lattice | `ProvenanceValue<T, I, C>` | `src/types/provenance.rs` |
| Merkle domain separation | `LeafHash` vs `NodeHash` | `src/plane1/merkle/mod.rs` |
| Exact decimal money | `ExactDecimal` (zero `f64`) | `src/types/decimal.rs`, `src/plane1/budget/mod.rs` |
| Zero unsafe Rust | `#![forbid(unsafe_code)]` | `src/lib.rs`, `src/main.rs` |

## 3. Honest Scope Boundaries

1. **Hardware Telemetry:** All energy figures are deterministic `PROXY_ESTIMATE` calculations from token counts × published Wh/token tier constants and TLS/TCP warmup proxies (`0.8 J` TLS, `1.5 J` OAuth, `0.2 J` TCP). Certificates never claim `HARDWARE_NVML_RAPL`.
2. **Host Fingerprint (Not TEE Attestation):** `host_digest = blake3(host_os || arch || family)`. This is a host-TCB fingerprint, not hardware TEE attestation.
3. **Grid Carbon:** Uses the built-in diurnal solar-trough / evening-peak forecaster ($C_{\text{det}}(h) \in [180, 520]\text{ gCO}_2\text{eq/kWh}$) when no optional ElectricityMaps API key is configured, and clearly labels `forecast` vs `observed`.

## 4. Deferred (`v0.1.x`)

| Feature | Reason Deferred |
| :--- | :--- |
| Physical NVML / RAPL wattmeter integration | Requires GPU host; CI runs on CPU-only Windows/Linux runners |
| vLLM / Ollama internal KV-cache sleep RPC | Proxy communicates over standard HTTP APIs |
| Hardware TEE attestation (TDX/SEV/NVIDIA CC) | Requires confidential-computing hardware |
