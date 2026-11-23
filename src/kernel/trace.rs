//! Structured kernel stage trace events emitted to the SSE log stream and SQLite.

use serde::{Deserialize, Serialize};

/// Structured telemetry event emitted by every kernel stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelEvent {
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// Request identifier.
    pub request_id: String,
    /// Stage label (`stage1_ingress` .. `stage7_update`).
    pub stage: String,
    /// Plane tag (`plane1`, `plane2`, `plane3`, `kernel`).
    pub plane: String,
    /// Severity (`info`, `warn`, `error`).
    pub severity: String,
    /// Redacted human-readable summary.
    pub summary: String,
    /// Stage latency in microseconds.
    pub latency_us: u64,
    /// Optional input tokens.
    pub tokens_in: Option<u64>,
    /// Optional output tokens.
    pub tokens_out: Option<u64>,
    /// Optional USD cost estimate.
    pub cost_usd: Option<String>,
    /// Optional Scope-2 CO2 grams proxy.
    pub co2_g: Option<f64>,
    /// Integrity rank label.
    pub integrity: String,
    /// Confidentiality tier label.
    pub confidentiality: String,
    /// Routing or security decision tag.
    pub decision: String,
}
