//! Local key management and async token-bucket rate limiter.

pub mod local_key;

use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::RwLock;

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Async token-bucket rate limiter (uses `tokio::sync::RwLock`, async-native locking).
pub struct RateLimiter {
    rpm: u32,
    buckets: RwLock<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// Create a rate limiter with `rpm` requests per minute.
    pub fn new(rpm: u32) -> Self {
        Self {
            rpm,
            buckets: RwLock::new(HashMap::new()),
        }
    }

    /// Consume 1 token for `key`, returning `true` if permitted.
    pub async fn allow(&self, key: &str) -> bool {
        if self.rpm == 0 {
            return true;
        }
        let cap = self.rpm as f64;
        let rate = cap / 60.0;
        let now = Instant::now();
        let mut map = self.buckets.write().await;
        let b = map.entry(key.to_string()).or_insert(Bucket {
            tokens: cap,
            last: now,
        });
        let dt = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + dt * rate).min(cap);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
