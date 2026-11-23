//! Typed Macaroon caveats (provider, model, exact-decimal max USD, TTL, single-use JTI).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A single monotonic restriction appended to a Macaroon capability chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caveat {
    /// Caveat type (`provider`, `model`, `max_usd`, `ttl_max`, `jti_single_use`).
    pub kind: String,
    /// Canonical parameters.
    pub params: Value,
}

impl Caveat {
    /// Create a new caveat.
    pub fn new(kind: impl Into<String>, params: Value) -> Self {
        Self {
            kind: kind.into(),
            params,
        }
    }

    /// Canonical JSON representation for JCS HMAC chaining.
    pub fn to_json(&self) -> Value {
        json!({ "kind": self.kind, "params": self.params })
    }
}
