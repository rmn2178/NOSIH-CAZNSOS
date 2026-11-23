//! Strongly-typed identifiers for requests, sessions, tenants, and JTIs.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique request identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub String);

impl RequestId {
    /// Generate a new UUIDv4-backed request identifier.
    pub fn generate() -> Self {
        Self(format!("req-{}", Uuid::new_v4()))
    }

    /// Borrow inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Unique tenant identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

/// Unique single-use capability nonce (128-bit CSPRNG hex).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JtiNonce(pub String);

impl JtiNonce {
    /// Generate a fresh 128-bit CSPRNG JTI nonce.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        let _ = getrandom::getrandom(&mut bytes);
        Self(hex::encode(bytes))
    }
}
