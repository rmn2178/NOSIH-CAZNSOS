//! Bounded in-memory event ring buffer + `tokio::sync::broadcast` SSE feed + non-blocking SQLite writer.

use crate::kernel::trace::KernelEvent;
use crate::storage::SqliteStorage;
use crate::telemetry::redact::redact_secrets;
use chrono::Utc;
use rusqlite::params;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, mpsc, oneshot};

enum RingCmd {
    Push(Box<KernelEvent>),
    Snapshot(oneshot::Sender<Vec<KernelEvent>>),
}

/// Bounded ring buffer of redacted kernel events with live SSE fan-out and async/off-thread persistence.
pub struct LogRing {
    tx: broadcast::Sender<KernelEvent>,
    ring_tx: Option<mpsc::UnboundedSender<RingCmd>>,
    fallback_ring: Arc<RwLock<VecDeque<KernelEvent>>>,
    fallback_capacity: usize,
    db_tx: mpsc::UnboundedSender<KernelEvent>,
}

impl LogRing {
    /// Construct a new ring buffer with capacity `capacity` and background SQLite writer thread.
    pub fn new(capacity: usize, storage: Arc<SqliteStorage>) -> Self {
        let cap = capacity.max(64);
        let (tx, _) = broadcast::channel(1024);

        // Dedicated background thread for SQLite inserts so Tokio worker threads never block on DB I/O.
        let (db_tx, mut db_rx) = mpsc::unbounded_channel::<KernelEvent>();
        let db_storage = Arc::clone(&storage);
        let _ = std::thread::Builder::new()
            .name("nosih-event-writer".into())
            .spawn(move || {
                while let Some(ev) = db_rx.blocking_recv() {
                    if let Ok(conn) = db_storage.get_conn() {
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
            });

        // Dedicated Tokio actor for the in-memory ring buffer so `emit` never drops events under reader lock contention.
        let ring_tx = if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let (rtx, mut rrx) = mpsc::unbounded_channel::<RingCmd>();
            handle.spawn(async move {
                let mut buf = VecDeque::with_capacity(cap.min(10_000));
                while let Some(cmd) = rrx.recv().await {
                    match cmd {
                        RingCmd::Push(ev) => {
                            if buf.len() >= cap {
                                buf.pop_front();
                            }
                            buf.push_back(*ev);
                        }
                        RingCmd::Snapshot(reply) => {
                            let _ = reply.send(buf.iter().cloned().collect());
                        }
                    }
                }
            });
            Some(rtx)
        } else {
            None
        };

        Self {
            tx,
            ring_tx,
            fallback_ring: Arc::new(RwLock::new(VecDeque::with_capacity(cap.min(10_000)))),
            fallback_capacity: cap,
            db_tx,
        }
    }

    /// Subscribe to live SSE events.
    pub fn subscribe(&self) -> broadcast::Receiver<KernelEvent> {
        self.tx.subscribe()
    }

    /// Snapshot current ring buffer entries (linearizable with prior `emit` calls).
    pub async fn snapshot(&self) -> Vec<KernelEvent> {
        if let Some(ref rtx) = self.ring_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            if rtx.send(RingCmd::Snapshot(reply_tx)).is_ok() {
                if let Ok(events) = reply_rx.await {
                    return events;
                }
            }
        }
        self.fallback_ring.read().await.iter().cloned().collect()
    }

    /// Redact, store, broadcast, and asynchronously persist a structured kernel event without blocking.
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

        if let Some(ref rtx) = self.ring_tx {
            let _ = rtx.send(RingCmd::Push(Box::new(ev.clone())));
        } else if let Ok(mut guard) = self.fallback_ring.try_write() {
            if guard.len() >= self.fallback_capacity {
                guard.pop_front();
            }
            guard.push_back(ev.clone());
        }

        let _ = self.db_tx.send(ev);
    }
}
