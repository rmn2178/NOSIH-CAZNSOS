//! Bounded in-memory event ring buffer + `tokio::sync::broadcast` SSE feed + SQLite persistence.

use crate::kernel::trace::KernelEvent;
use crate::storage::SqliteStorage;
use crate::telemetry::redact::redact_secrets;
use chrono::Utc;
use rusqlite::params;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};

/// Bounded ring buffer of redacted kernel events with live SSE fan-out.
pub struct LogRing {
    capacity: usize,
    ring: RwLock<VecDeque<KernelEvent>>,
    tx: broadcast::Sender<KernelEvent>,
    storage: Arc<SqliteStorage>,
}

impl LogRing {
    /// Construct a new ring buffer with capacity `capacity`.
    pub fn new(capacity: usize, storage: Arc<SqliteStorage>) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            capacity: capacity.max(64),
            ring: RwLock::new(VecDeque::with_capacity(capacity.min(10_000))),
            tx,
            storage,
        }
    }

    /// Subscribe to live SSE events.
    pub fn subscribe(&self) -> broadcast::Receiver<KernelEvent> {
        self.tx.subscribe()
    }

    /// Snapshot current ring buffer entries.
    pub async fn snapshot(&self) -> Vec<KernelEvent> {
        self.ring.read().await.iter().cloned().collect()
    }

    /// Redact, store, broadcast, and persist a structured kernel event.
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &self,
        request_id: &str,
        stage: &str,
        plane: &str,
        severity: &str,
        summary: &str,
        latency_us: u64,
        tokens_in: Option<u64>,
        tokens_out: Option<u64>,
        cost_usd: Option<String>,
        co2_g: Option<f64>,
        integrity: String,
        confidentiality: String,
        decision: String,
    ) {
        let ev = KernelEvent {
            ts: Utc::now().to_rfc3339(),
            request_id: request_id.to_string(),
            stage: stage.to_string(),
            plane: plane.to_string(),
            severity: severity.to_string(),
            summary: redact_secrets(summary),
            latency_us,
            tokens_in,
            tokens_out,
            cost_usd,
            co2_g,
            integrity,
            confidentiality,
            decision,
        };

        let _ = self.tx.send(ev.clone());

        if let Ok(mut guard) = self.ring.try_write() {
            if guard.len() >= self.capacity {
                guard.pop_front();
            }
            guard.push_back(ev.clone());
        }

        if let Ok(conn) = self.storage.get_conn() {
            let _ = conn.execute(
                "INSERT INTO events (ts, request_id, stage, plane, severity, summary, latency_us, decision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);",
                params![
                    ev.ts,
                    ev.request_id,
                    ev.stage,
                    ev.plane,
                    ev.severity,
                    ev.summary,
                    ev.latency_us as i64,
                    ev.decision,
                ],
            );
        }
    }
}
