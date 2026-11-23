//! Axum HTTP server exposing `/v1/*` OpenAI-compatible surface, `/admin/*`, SSE logs, and embedded UI.

pub mod admin;
pub mod logs_sse;
pub mod openai;
pub mod router;
