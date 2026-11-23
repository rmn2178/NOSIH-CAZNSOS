//! Pooled SQLite WAL storage layer (`r2d2_sqlite`).

pub mod migrations;

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::storage::migrations::apply_migrations;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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

    /// Prune expired `consumed_jtis` and, if the database exceeds `max_db_mb`, trim the oldest
    /// 25% of `events` rows and checkpoint WAL. Returns `(pruned_jtis, pruned_events)`.
    pub fn prune_to_budget(&self, max_db_mb: u64) -> AppResult<(usize, usize)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let conn = self.get_conn()?;

        let pruned_jtis = conn
            .execute(
                "DELETE FROM consumed_jtis WHERE expires_at < ?1;",
                params![now],
            )
            .map_err(|e| AppError::Storage(e.to_string()))?;

        let page_count: u64 = conn
            .query_row("PRAGMA page_count;", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0)
            .max(0) as u64;
        let page_size: u64 = conn
            .query_row("PRAGMA page_size;", [], |r| r.get::<_, i64>(0))
            .unwrap_or(4096)
            .max(0) as u64;
        let db_bytes = page_count.saturating_mul(page_size);
        let max_bytes = max_db_mb.max(1).saturating_mul(1024 * 1024);

        let mut pruned_events = 0usize;
        if db_bytes > max_bytes {
            let total_events: i64 = conn
                .query_row("SELECT COUNT(*) FROM events;", [], |r| r.get(0))
                .unwrap_or(0);
            let to_delete = (total_events / 4).max(100);
            if total_events > 0 {
                pruned_events = conn
                    .execute(
                        "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?1);",
                        params![to_delete],
                    )
                    .map_err(|e| AppError::Storage(e.to_string()))?;
            }
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
        }

        Ok((pruned_jtis, pruned_events))
    }

    /// Checkpoint SQLite WAL cleanly during graceful shutdown.
    pub fn checkpoint_wal(&self) {
        if let Ok(conn) = self.pool.get() {
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }
    }
}
