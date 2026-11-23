//! Three-state provider warm-pool FSM (`ACTIVE`, `WARM`, `DEEP`).

use serde::{Deserialize, Serialize};

/// Provider connection keep-warm state adapted from PCS-PMC 3-state GPU sleep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WarmState {
    /// TCP pool + active auth token warm.
    Active,
    /// Pooled TCP warm, auth token refresh required on next call.
    Warm,
    /// Pool closed; full TCP+TLS+auth handshake required.
    Deep,
}
