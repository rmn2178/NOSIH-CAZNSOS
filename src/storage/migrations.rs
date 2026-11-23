//! Idempotent SQLite WAL schema migrations for keys, JTIs, budgets, Merkle log, and audit events.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use rusqlite::Connection;

/// Apply all SQLite schema tables and indices.
pub fn apply_migrations(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS provider_keys (
             id TEXT PRIMARY KEY,
             provider TEXT NOT NULL,
             label TEXT NOT NULL,
             masked_key TEXT NOT NULL,
             base_url TEXT,
             nonce BLOB NOT NULL,
             ciphertext BLOB NOT NULL,
             max_usd_per_day TEXT NOT NULL,
             max_requests_per_hour INTEGER NOT NULL,
             allowed_models TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS consumed_jtis (
             jti TEXT PRIMARY KEY,
             request_id TEXT NOT NULL,
             consumed_at INTEGER NOT NULL,
             expires_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_consumed_jtis_expires_at
             ON consumed_jtis (expires_at);
         CREATE TABLE IF NOT EXISTS linear_budgets (
             account_id TEXT PRIMARY KEY,
             initial_usd TEXT NOT NULL,
             remaining_usd TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS merkle_leaves (
             leaf_index INTEGER PRIMARY KEY,
             created_at INTEGER NOT NULL,
             payload_jcs BLOB NOT NULL,
             leaf_hash BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS merkle_frontier (
             height INTEGER PRIMARY KEY,
             hash BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS merkle_sths (
             tree_size INTEGER PRIMARY KEY,
             timestamp_utc INTEGER NOT NULL,
             root_hash_hex TEXT NOT NULL,
             signature_hex TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS events (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             ts TEXT NOT NULL,
             request_id TEXT NOT NULL,
             stage TEXT NOT NULL,
             plane TEXT NOT NULL,
             severity TEXT NOT NULL,
             summary TEXT NOT NULL,
             latency_us INTEGER NOT NULL,
             decision TEXT NOT NULL
         );",
    )
    .map_err(|e| AppError::Storage(e.to_string()))?;
    Ok(())
}
