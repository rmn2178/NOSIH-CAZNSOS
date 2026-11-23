# Security Policy — NOSIH-CAZNSOS

## Security Architecture & Enforced Invariants

**NOSIH-CAZNSOS** treats local LLM key management and multi-provider routing as a zero-trust boundary enforced at both compile time and runtime:

1. **Zero Unsafe Rust (`#![forbid(unsafe_code)]`)**: Enforced at crate root (`src/lib.rs`) and verified in CI (`audit.yml`).
2. **Non-Bypassable Capability Tokens**: `Authorized<ProviderCall>` and `Authorized<ProviderWarmup>` in `src/types/authorized.rs` have private inner fields and no public `new()` constructor. Upstream HTTP dispatch (`ProviderChain::call`) and connection pool warmup (`PA-PCS-PMC`) cannot compile without passing through Plane I `CAT-PLM` verification.
3. **Encrypted Key Vault & Memory Zeroization**:
   - Upstream provider keys are encrypted at rest with **AES-256-GCM** using an HKDF-SHA256 subkey derived from a dedicated 256-bit `~/.nosih/master.key` (`0600`, completely decoupled from the client-facing `local_key`).
   - Resolved secrets stay inside `secrecy::SecretString` (`zeroize` on drop) and are never cloned into long-lived plain `String`s.
4. **Automatic Secret Redaction**: Any string matching common provider key patterns (`sk-`, `sk-ant-`, `AIza`, `gsk_`, `Bearer ...`) is replaced with `<REDACTED:sha256-prefix>` before hitting the in-memory log ring, SQLite WAL audit table, live SSE stream, or any of the 11 export formats.
5. **Exact Financial Arithmetic**: Monetary budgets and cost calculations in `src/types/decimal.rs` and `src/plane1/budget/` strictly forbid IEEE 754 `f64`, using `rust_decimal` fixed-point arithmetic exclusively.
6. **Network & Browser Hardening**:
   - Binds to `127.0.0.1:8787` by default (`--public` required for non-loopback).
   - Admin endpoints enforce loopback origin checks plus the `X-NOSIH-Admin` header to prevent cross-site request forgery (CSRF).
   - Embedded UI assets serve with `Content-Security-Policy: default-src 'self'` and use safe DOM `textContent` rendering (no inline event handlers or raw HTML interpolation of model output).
7. **Zero Outbound Telemetry**: No analytics, crash reporting, or phone-home traffic is ever sent.

## Reporting a Vulnerability

If you discover a security issue in NOSIH-CAZNSOS, please open a private security advisory on GitHub rather than a public issue, including reproduction steps and affected file paths.
