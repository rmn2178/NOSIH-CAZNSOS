# NOSIH-CAZNSOS HTTP API Reference

Base URL (default loopback binding): `http://127.0.0.1:8787`

## Authentication Headers

| Surface | Required Header | Scope |
| :--- | :--- | :--- |
| `/v1/*` (OpenAI API) | `Authorization: Bearer sk-nosih-...` (or `x-api-key: sk-nosih-...`) | Token-bucket rate-limited LLM inference & embeddings |
| `/admin/*` (Management) | `X-NOSIH-Admin: adm-...` | Loopback-only (unless allowlisted), CSRF-protected admin controls |

---

## OpenAI-Compatible Surface (`/v1`)

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/v1/chat/completions` | Streaming (`stream: true`) and non-streaming chat completions through the 7-stage NOSIH kernel. Optional `X-NOSIH-Origin: user\|det\|untrusted` header sets ingress provenance (privileged origins such as `human`, `gov`, `erp`, `policy` require a valid `X-NOSIH-Origin-Sig` HMAC-SHA256 signature or `X-NOSIH-Admin` token; unverified requests are capped at `UserDirect`). Returns `x-nosih-tier`, `x-nosih-co2-g`, and `x-nosih-merkle-leaf` response headers. |
| `GET` | `/v1/models` | Lists virtual models (`nosih-auto`, `nosih-symbolic`, `nosih-small`, `nosih-medium`, `nosih-large`) and configured upstream models. |
| `POST` | `/v1/embeddings` | Deterministic 320D signed feature-hash local embeddings (OpenAI response schema). |
| `GET` | `/v1/health` | Unauthenticated liveness probe returning live grid carbon intensity (`carbon_gco2_per_kwh`) and `merkle_tree_size`. |

---

## Admin, Telemetry, Visualization & Export Surface (`/admin`)

| Method | Path | Query / Body | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/admin/keys` | Single JSON, JSON array, JSONL, or `.env` text | Encrypts and stores upstream provider API key(s) with AES-256-GCM. |
| `GET` | `/admin/keys` | — | Lists stored keys with secrets masked (`sk-...abcd`). |
| `DELETE` | `/admin/keys/:id` | — | Deletes a stored provider key. |
| `POST` | `/admin/keys/:id/rotate` | `{"api_key": "..."}` | Atomically re-encrypts and rotates an existing key. |
| `POST` | `/admin/keys/:id/test` | — | Fires a lightweight provider probe (supports OpenAI Bearer & Anthropic `x-api-key`) and returns `{ok, provider, latency_ms, detail}`. |
| `GET` | `/admin/config` | — | Returns current runtime router, tier, and carbon settings. |
| `PUT` / `POST` | `/admin/config` | Settings JSON | Updates runtime configuration live and persists it to `config.toml`. |
| `GET` | `/admin/logs/stream` | `?plane=plane1\|plane2\|plane3\|kernel` | Live redacted Server-Sent Events (SSE) stream of kernel stage executions. |
| `GET` | `/admin/metrics/cards` | `?window_mins=15\|60\|1440&view=api\|planes` | Returns KPI totals (`total_requests`, `success_rate`) and 4 cards × 48 stacked `ok`/`warn`/`err` buckets. |
| `GET` | `/admin/viz/svg` | `?chart=all\|carbon\|latency\|planes&theme=dark\|light` | Returns pure-Rust zero-dependency `image/svg+xml` charts. |
| `GET` / `POST` | `/admin/export` | `?format=json\|jsonl\|csv\|tsv\|md\|txt\|xml\|otel\|merkle\|svg\|html&save_to_disk=bool&download=bool&theme=dark\|light&request_id=...` | Exports redacted audit data, Merkle proofs, or visual reports to `~/Downloads/` or as a direct download attachment. |

---

## Quick `curl` Examples

```bash
# 1. Chat completion (CPU symbolic math -> $0, 0g CO2)
curl -s http://127.0.0.1:8787/v1/chat/completions \
  -H "Authorization: Bearer $LOCAL_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"nosih-auto","messages":[{"role":"user","content":"(50000 * 0.18) + 1000"}]}'

# 2. Fetch Pure-Rust Light-Mode SVG Dashboard
curl -s "http://127.0.0.1:8787/admin/viz/svg?chart=all&theme=light" \
  -H "X-NOSIH-Admin: $ADMIN_TOKEN" -o dashboard.svg

# 3. Export OpenTelemetry Spans
curl -s "http://127.0.0.1:8787/admin/export?format=otel&download=true" \
  -H "X-NOSIH-Admin: $ADMIN_TOKEN" -o traces.otel.json
```
