//! Top-level Axum router assembly with loopback admin guard and CSP headers.

use crate::app::AppState;
use crate::server::admin::export::{export_logs, metrics_cards, render_viz_svg};
use crate::server::admin::keys::{
    delete_key, get_config, list_keys, rotate_key, test_key, update_config, upload_keys,
};
use crate::server::admin::require_admin;
use crate::server::logs_sse::{logs_recent, logs_stream};
use crate::server::openai::auth::require_local_key;
use crate::server::openai::chat::{chat_completions, embeddings};
use crate::server::openai::models::{health, list_models};
use crate::ui::serve_ui_asset;
use axum::middleware;
use axum::routing::{delete, get, post};
use axum::Router;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

/// Assemble the complete HTTP router for `nosih-caznsos`.
pub fn build_router(state: Arc<AppState>) -> Router {
    let public_v1 = Router::new().route("/v1/health", get(health));

    let authed_v1 = Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/models", get(list_models))
        .route("/v1/embeddings", post(embeddings))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_local_key,
        ));

    let admin_routes = Router::new()
        .route("/admin/keys", post(upload_keys).get(list_keys))
        .route("/admin/keys/:id", delete(delete_key))
        .route("/admin/keys/:id/rotate", post(rotate_key))
        .route("/admin/keys/:id/test", post(test_key))
        .route("/admin/config", get(get_config).post(update_config))
        .route("/admin/export", get(export_logs).post(export_logs))
        .route("/admin/viz/svg", get(render_viz_svg))
        .route("/admin/metrics/cards", get(metrics_cards))
        .route("/admin/logs/recent", get(logs_recent))
        .route("/admin/logs/stream", get(logs_stream))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_admin,
        ));

    let ui_routes = Router::new()
        .route("/", get(serve_ui_asset))
        .route("/*path", get(serve_ui_asset));

    Router::new()
        .merge(public_v1)
        .merge(authed_v1)
        .merge(admin_routes)
        .merge(ui_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
