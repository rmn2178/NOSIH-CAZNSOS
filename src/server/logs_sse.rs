//! Live SSE Log Stream (`GET /admin/logs/stream`) and recent log snapshot (`GET /admin/logs/recent`).

use crate::app::AppState;
use crate::kernel::trace::KernelEvent;
use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::Json;
use futures::Stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

/// Optional query filters for live SSE and recent log queries.
#[derive(Debug, Default, Deserialize)]
pub struct LogFilter {
    /// Filter by plane (`plane1`, `plane2`, `plane3`, `kernel`).
    pub plane: Option<String>,
    /// Filter by severity (`info`, `warn`, `error`).
    pub severity: Option<String>,
    /// Filter by request ID.
    pub request_id: Option<String>,
}

fn matches_filter(ev: &KernelEvent, filter: &LogFilter) -> bool {
    if let Some(p) = &filter.plane {
        if !p.is_empty() && !ev.plane.eq_ignore_ascii_case(p) {
            return false;
        }
    }
    if let Some(s) = &filter.severity {
        if !s.is_empty() && !ev.severity.eq_ignore_ascii_case(s) {
            return false;
        }
    }
    if let Some(r) = &filter.request_id {
        if !r.is_empty() && ev.request_id != *r {
            return false;
        }
    }
    true
}

/// `GET /admin/logs/recent` — return recent redacted kernel events as JSON.
pub async fn logs_recent(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<LogFilter>,
) -> Json<Vec<KernelEvent>> {
    let items: Vec<KernelEvent> = state
        .log_ring
        .snapshot()
        .await
        .into_iter()
        .filter(|ev| matches_filter(ev, &filter))
        .collect();
    Json(items)
}

/// `GET /admin/logs/stream` — stream live structured kernel events via Server-Sent Events (SSE).
pub async fn logs_stream(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<LogFilter>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let backlog = state.log_ring.snapshot().await;
    let rx = state.log_ring.subscribe();

    let backlog_stream =
        futures::stream::iter(backlog.into_iter().rev().take(50).collect::<Vec<_>>());
    let live_stream = BroadcastStream::new(rx).filter_map(Result::ok);

    let combined = backlog_stream.chain(live_stream).filter_map(move |ev| {
        if !matches_filter(&ev, &filter) {
            return None;
        }
        serde_json::to_string(&ev)
            .ok()
            .map(|data| Ok(Event::default().data(data)))
    });

    Sse::new(combined).keep_alive(KeepAlive::default())
}
