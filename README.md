# NOSIH-CAZNSOS (`nosih-caznsos`)

> **Single-Binary, 100-File Pure-Rust Zero-Trust, Carbon-Aware Multi-Provider OpenAI-Compatible LLM Proxy**

[![Build Status](https://img.shields.io/badge/CI-GitHub%20Actions-black?style=flat-square)](#github-actions-cicd-pipeline)
[![Rust](https://img.shields.io/badge/Rust-Stable%20%7C%20Zero%20Unsafe-black?style=flat-square)](SECURITY.md)
[![License](https://img.shields.io/badge/License-MIT-black?style=flat-square)](LICENSE)
[![Source Files](https://img.shields.io/badge/src%2F*.rs-Exactly%20100-black?style=flat-square)](docs/PIPELINES.md)

**NOSIH-CAZNSOS** unifies 10+ LLM providers (OpenAI, Anthropic, Gemini, Groq, Mistral, Together, OpenRouter, Cohere, Ollama, Azure OpenAI, and custom OpenAI-compatible servers) behind **one local OpenAI-compatible endpoint (`http://127.0.0.1:8787/v1`)** and **one locally generated API key (`sk-nosih-...`)**.

Built as a single dependency-free Rust executable (`nosih-caznsos.exe` on Windows, `nosih-caznsos` on Linux/macOS), it ships an embedded Light/Dark monochrome operations dashboard, a 4-card stacked-bar API telemetry view, a pure-Rust SVG graphing engine, an 11-format audit exporter, AES-256-GCM encrypted key storage, and the full **NOSIH Tri-Plane Kernel** with compile-time non-bypassable security invariants.

---

## Architecture & 7-Stage Request Pipeline

```text
  IDE / SDK / Built-in Chat UI  ──►  POST http://127.0.0.1:8787/v1/chat/completions
                                            │
    ┌───────────────────────────────────────▼───────────────────────────────────────┐
    │  STAGE 1 · Ingress & Provenance (Plane I)                                     │
    │  RFC 8785 JCS canonicalization · Origin lattice tagging · 10D CPU profiling   │
    ├───────────────────────────────────────┬───────────────────────────────────────┤
    │  STAGE 2 · PS-RCSC Semantic Cache (Plane II)                                  │
    │  320D signed feature hash · Provenance-scoped hit -> instant 0g CO2 response  │
    ├───────────────────────────────────────┬───────────────────────────────────────┤
    │  STAGE 3 · Carbon-Conformal Dispatch & PCSP (Plane II + III)                  │
    │  Diurnal grid carbon C(t) + PID conformal band + LinUCB bandit                │
    │  CPU Symbolic short-circuit (SafeDecimalAST math / TF-IDF policy RAG) -> $0   │
    ├───────────────────────────────────────┬───────────────────────────────────────┤
    │  STAGE 4 · Static Kahn + IFC DAG Verification (Plane III)                     │
    │  Acyclic graph check · Information-Flow Control integrity/confidentiality     │
    ├───────────────────────────────────────┬───────────────────────────────────────┤
    │  STAGE 5 · SPCCE-Macaroon Capability Minting (Plane I · CAT-PLM)              │
    │  Mint, attenuate & verify HMAC caveats -> Authorized<ProviderCall> (private)  │
    ├───────────────────────────────────────┬───────────────────────────────────────┤
    │  STAGE 6 · PA-PCS-PMC Warmup & Streaming Upstream Execution (Plane III)       │
    │  Authorized<ProviderWarmup> · AES-256-GCM vault decrypt (Zeroize on drop)     │
    ├───────────────────────────────────────┬───────────────────────────────────────┤
    │  STAGE 7 · CCEC + RFC 6962/9162 MTLog Commit & Redacted Telemetry (Kernel)    │
    │  Scope-2 CO2 certificate · Ed25519 Signed Tree Head · Live SSE + SQLite WAL   │
    └───────────────────────────────────────┴───────────────────────────────────────┘
```

---

## Core Features

| Category | Capabilities |
| :--- | :--- |
| **OpenAI-Compatible Surface** | `POST /v1/chat/completions` (streaming SSE & non-streaming), `GET /v1/models`, `POST /v1/embeddings`, `GET /v1/health`. Virtual models: `nosih-auto`, `nosih-symbolic`, `nosih-small`, `nosih-medium`, `nosih-large`. |
| **Zero-Trust Security (Plane I)** | `#![forbid(unsafe_code)]`, private `Authorized<ProviderCall>` & `Authorized<ProviderWarmup>` tokens, SPCCE-Macaroon capability caveats, AES-256-GCM key vault, `zeroize` on drop, automatic secret redaction (`<REDACTED:sha256-prefix>`), loopback binding, CSRF `X-NOSIH-Admin` header, strict CSP. |
| **Carbon-Conformal Router (Plane II)** | 24h diurnal grid carbon forecaster, PID conformal prediction band, LinUCB contextual bandit, Provenance-Scoped Semantic Cache (PS-RCSC), and PCSP untrusted-origin C-DoW tier capping. |
| **Neuro-Symbolic & Multi-Provider (Plane III)** | Deterministic CPU-only `SafeDecimalAST` math + TF-IDF policy RAG (`nosih-symbolic`), Kahn + IFC DAG verifier, `PA-PCS-PMC` connection warmer, and 10+ upstream providers. |
| **Embedded Web UI (Zero Node.js)** | Compiled into the binary via `rust-embed`. Includes Light & Dark monochrome theme toggle, 4-card 48-bucket stacked-bar API/Tri-Plane Overview dashboard, Chat, Multi-Key Upload (JSON / array / JSONL / `.env`), Config editor, Live SSE Log Viewer, Pure-Rust SVG Graphs, and Export tab. |
| **Pure-Rust Visuals & 11-Format Export** | Zero-dependency Rust SVG chart renderer (`all`, `carbon`, `latency`, `planes` in Dark/Light palettes) and export to `json`, `jsonl`, `csv`, `tsv`, `md`, `txt`, `xml`, `otel`, `merkle`, `svg`, and standalone `html`. |
| **Cryptographic Auditability** | CCEC Scope-2 carbon/cost ledger backed by an append-only RFC 6962/9162 Merkle Tree (`MTLog`) with distinct `LeafHash`/`NodeHash` newtypes and standalone `examples/verify_merkle.rs` verifier. |

---

## 3-Step Quickstart

1. **Download or build the binary**
   - Download `nosih-caznsos.exe` from GitHub Releases, or build from source:
     ```bash
     cargo build --release
     ```
2. **Start the proxy**
   ```bash
   ./target/release/nosih-caznsos
   ```
   On first run, `nosih-caznsos` generates your `Local API Key` (`sk-nosih-...`) and `Admin Token` (`adm-...`), prints them once, stores the local key at `~/.nosih/local_key` (`0600`), and serves the dashboard at `http://127.0.0.1:8787/`.
3. **Upload keys & connect your IDE**
   - Open `http://127.0.0.1:8787/`, paste your `Admin Token`, and upload upstream keys in the **Keys** tab (single key, JSON array, JSONL, or `.env`).
   - Point Cursor, Cline, Continue, Roo Code, Aider, or any OpenAI SDK to `http://127.0.0.1:8787/v1`.

---

## IDE & SDK Configuration

### Cursor / Cline / Roo Code
- **Base URL:** `http://127.0.0.1:8787/v1`
- **API Key:** `sk-nosih-YOUR-LOCAL-KEY`
- **Model:** `nosih-auto` (or `nosih-symbolic`, `nosih-small`, `nosih-medium`, `nosih-large`)

### Continue.dev (`~/.continue/config.json`)
```json
{
  "models": [
    {
      "title": "NOSIH-CAZNSOS Auto",
      "provider": "openai",
      "model": "nosih-auto",
      "apiBase": "http://127.0.0.1:8787/v1",
      "apiKey": "sk-nosih-YOUR-LOCAL-KEY"
    }
  ]
}
```

### Python (`openai` SDK)
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8787/v1",
    api_key="sk-nosih-YOUR-LOCAL-KEY",
)
resp = client.chat.completions.create(
    model="nosih-auto",
    messages=[{"role": "user", "content": "Compute (50000 * 0.18) + 1000"}],
)
print(resp.choices[0].message.content)
```

---

## GitHub Actions CI/CD Pipeline

Every push to `main`/`master` or pull request runs two automated workflows:

- **`.github/workflows/build.yml`** — Compiles release binaries on `windows-latest` (`nosih-caznsos.exe` + `sha.txt`) and `ubuntu-latest` (`nosih-caznsos`), runs `--self-test --stub-provider`, runs strict `cargo clippy --all-targets -- -D warnings` + `cargo test`, uploads build artifacts, and publishes GitHub Releases automatically on `v*` tags.
- **`.github/workflows/audit.yml`** — Enforces all static and structural security invariants (exact 100 `src/*.rs` files, zero `unsafe`, private `Authorized<T>`, zero `f64` in money paths, zero `println!` outside `main.rs`, zero `std::sync::Mutex`) plus a cross-platform `ubuntu`/`windows`/`macos` test matrix.

---

## Documentation Index

- [**`docs/PIPELINES.md`**](docs/PIPELINES.md) — End-to-end breakdown of the Request, Security, Telemetry/Visualization/Export, and CI/CD pipelines.
- [**`docs/API_REFERENCE.md`**](docs/API_REFERENCE.md) — Full HTTP API documentation for `/v1/*` and `/admin/*` endpoints.
- [**`SECURITY.md`**](SECURITY.md) — Threat model, compile-time invariants, encryption at rest, and secret redaction.
- [**`CONTRIBUTING.md`**](CONTRIBUTING.md) — Development workflow, 100-file architecture rule, local gate runner, and release steps.
- [**`ADAPTATIONS.md`**](ADAPTATIONS.md) — Mapping from the NOSIH GPU-orchestration research paper to desktop LLM proxy semantics.
- [**`AUDIT_REPORT.md`**](AUDIT_REPORT.md) — Latest audit summary and gate verification log.
