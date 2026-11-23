//! SQLite WAL single-use `jti` replay protection store.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::storage::SqliteStorage;
use rusqlite::params;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Atomic SQLite WAL `jti` nonce replay store.
pub struct JtiReplayStore {
    storage: Arc<SqliteStorage>,
}

impl JtiReplayStore {
    /// Construct over shared SQLite pool.
    pub fn new(storage: Arc<SqliteStorage>) -> Self {
        Self { storage }
    }

    /// Atomically consume a JTI inside `BEGIN IMMEDIATE`; returns `Ok(true)` iff first use.
    pub fn consume_jti(&self, jti: &str, request_id: &str, expires_at: i64) -> AppResult<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let conn = self.storage.get_conn()?;
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let res = conn.execute(
            "INSERT INTO consumed_jtis (jti, request_id, consumed_at, expires_at) VALUES (?1, ?2, ?3, ?4);",
            params![jti, request_id, now, expires_at],
        );
        match res {
            Ok(_) => {
                conn.execute_batch("COMMIT;")
                    .map_err(|e| AppError::Storage(e.to_string()))?;
                Ok(true)
            }
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                let _ = conn.execute_batch("ROLLBACK;");
                Ok(false)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(AppError::Storage(e.to_string()))
            }
        }
    }
}
