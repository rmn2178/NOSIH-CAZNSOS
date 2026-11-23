//! Pooled SQLite WAL storage layer (`r2d2_sqlite`).

pub mod migrations;

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::storage::migrations::apply_migrations;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use std::path::Path;

/// Connection-pooled SQLite WAL storage.
pub struct SqliteStorage {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteStorage {
    /// Open or create the SQLite WAL database and run schema migrations.
    pub fn open(path: &Path) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let manager = SqliteConnectionManager::file(path).with_init(|c| {
            c.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA mmap_size=67108864;
                 PRAGMA busy_timeout=15000;",
            )
        });
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| AppError::Storage(e.to_string()))?;

        {
            let conn = pool.get().map_err(|e| AppError::Storage(e.to_string()))?;
            apply_migrations(&conn)?;
        }
        Ok(Self { pool })
    }

    /// Acquire a pooled SQLite connection (never hold across `.await`).
    pub fn get_conn(&self) -> AppResult<PooledConnection<SqliteConnectionManager>> {
        self.pool.get().map_err(|e| AppError::Storage(e.to_string()))
    }

    /// Checkpoint SQLite WAL cleanly during graceful shutdown.
    pub fn checkpoint_wal(&self) {
        if let Ok(conn) = self.pool.get() {
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }
    }
}
