//! SQLite WAL exact-decimal linear monetary budget ledger (zero floating-point math).

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::storage::SqliteStorage;
use crate::types::decimal::ExactDecimal;
use rusqlite::params;
use std::sync::Arc;

/// Atomic SQLite WAL `BEGIN IMMEDIATE` linear monetary budget ledger.
pub struct BudgetLedger {
    storage: Arc<SqliteStorage>,
}

impl BudgetLedger {
    /// Create a budget ledger over the shared SQLite pool.
    pub fn new(storage: Arc<SqliteStorage>) -> Self {
        Self { storage }
    }

    /// Initialize or reset a tenant's linear USD budget ceiling.
    pub fn set_budget(&self, account_id: &str, amount: ExactDecimal) -> AppResult<()> {
        let conn = self.storage.get_conn()?;
        let amt = amount.to_string();
        conn.execute(
            "INSERT OR REPLACE INTO linear_budgets (account_id, initial_usd, remaining_usd)
             VALUES (?1, ?2, ?3);",
            params![account_id, amt, amt],
        )
        .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Atomically debit `amount` inside `BEGIN IMMEDIATE`, initializing a default $100 ceiling if absent.
    pub fn ensure_and_debit(&self, account_id: &str, amount: ExactDecimal) -> AppResult<ExactDecimal> {
        let conn = self.storage.get_conn()?;
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| AppError::Storage(e.to_string()))?;

        let existing: Result<String, _> = conn.query_row(
            "SELECT remaining_usd FROM linear_budgets WHERE account_id = ?1;",
            params![account_id],
            |r| r.get(0),
        );

        let current = match existing {
            Ok(s) => ExactDecimal::parse_str(&s)
                .map_err(|e| AppError::Internal(format!("corrupt_budget: {e}")))?,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let def = ExactDecimal::from_i64_with_scale(10000, 2);
                let ds = def.to_string();
                let _ = conn.execute(
                    "INSERT INTO linear_budgets (account_id, initial_usd, remaining_usd) VALUES (?1, ?2, ?3);",
                    params![account_id, ds, ds],
                );
                def
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(AppError::Storage(e.to_string()));
            }
        };

        let Some(next) = current.checked_sub_nonneg(amount) else {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(AppError::CapabilityDenied("linear_budget_exhausted".into()));
        };

        if let Err(e) = conn.execute(
            "UPDATE linear_budgets SET remaining_usd = ?1 WHERE account_id = ?2;",
            params![next.to_string(), account_id],
        ) {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(AppError::Storage(e.to_string()));
        }

        conn.execute_batch("COMMIT;")
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(next)
    }

    /// Roll back a debited amount if downstream execution fails.
    pub fn refund(&self, account_id: &str, amount: ExactDecimal) -> AppResult<ExactDecimal> {
        let conn = self.storage.get_conn()?;
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let cur_s: String = conn
            .query_row(
                "SELECT remaining_usd FROM linear_budgets WHERE account_id = ?1;",
                params![account_id],
                |r| r.get(0),
            )
            .map_err(|e| {
                let _ = conn.execute_batch("ROLLBACK;");
                AppError::Storage(e.to_string())
            })?;
        let cur = ExactDecimal::parse_str(&cur_s)
            .map_err(AppError::Internal)?;
        let restored = cur
            .checked_add(amount)
            .ok_or_else(|| AppError::Internal("budget_overflow".into()))?;
        conn.execute(
            "UPDATE linear_budgets SET remaining_usd = ?1 WHERE account_id = ?2;",
            params![restored.to_string(), account_id],
        )
        .map_err(|e| {
            let _ = conn.execute_batch("ROLLBACK;");
            AppError::Storage(e.to_string())
        })?;
        conn.execute_batch("COMMIT;")
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(restored)
    }
}
