//! `GET /v1/health` and `GET /v1/models` endpoints.

use crate::app::AppState;
use axum::extract::State;
use axum::Json;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Liveness endpoint returning version, active carbon intensity, and Merkle root.
pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    let carbon = state.kernel.forecaster.read().await.current();
    let sth = state.kernel.merkle.latest_sth().ok();
    Json(json!({
        "status": "ok",
        "name": "nosih-caznsos",
        "version": env!("CARGO_PKG_VERSION"),
        "carbon_gco2_per_kwh": carbon.gco2_per_kwh,
        "carbon_source": carbon.source,
        "merkle_root": sth.as_ref().map(|s| s.root_hash_hex.clone()),
        "merkle_tree_size": sth.as_ref().map(|s| s.tree_size).unwrap_or(0),
    }))
}

/// OpenAI-compatible `GET /v1/models` listing virtual NOSIH tiers plus configured models.
pub async fn list_models(State(state): State<Arc<AppState>>) -> Json<Value> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let settings = state.settings.read().await.clone();

    let mut ids = vec![
        ("nosih-auto".to_string(), "nosih-router".to_string()),
        ("nosih-symbolic".to_string(), "nosih-cpu".to_string()),
        ("nosih-small".to_string(), "nosih-tier".to_string()),
        ("nosih-medium".to_string(), "nosih-tier".to_string()),
        ("nosih-large".to_string(), "nosih-tier".to_string()),
        (settings.tier_models.small, "configured".to_string()),
        (settings.tier_models.medium, "configured".to_string()),
        (settings.tier_models.large, "configured".to_string()),
    ];
    for (m, p) in settings.model_routes {
        ids.push((m, p));
    }

    let data: Vec<Value> = ids
        .into_iter()
        .map(|(id, owned_by)| {
            json!({
                "id": id,
                "object": "model",
                "created": now,
                "owned_by": owned_by,
            })
        })
        .collect();

    Json(json!({
        "object": "list",
        "data": data,
    }))
}
