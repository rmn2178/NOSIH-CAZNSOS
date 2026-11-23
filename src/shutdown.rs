//! Graceful shutdown handler flushing SQLite WAL and Merkle state.

use crate::app::AppState;
use std::sync::Arc;
use tracing::info;

/// Wait for Ctrl-C / SIGTERM and checkpoint SQLite WAL cleanly.
pub async fn shutdown_signal(state: Arc<AppState>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received; checkpointing SQLite WAL");
    state.storage.checkpoint_wal();
}
