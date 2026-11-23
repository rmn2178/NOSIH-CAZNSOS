//! Multi-format upstream key upload (JSON single/array, `.env`, JSONL), masking, rotation, and 1-token probe.

use crate::app::AppState;
use crate::config::secrets::UploadKeyInput;
use crate::config::settings::Settings;
use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bytes::Bytes;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Instant;

/// Upload one or many upstream provider keys (accepts single JSON, JSON array, JSONL, or `.env` lines).
pub async fn upload_keys(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> AppResult<(StatusCode, Json<Value>)> {
    let text = std::str::from_utf8(&body)
        .map_err(|_| AppError::BadRequest("invalid_utf8_body".into()))?
        .trim();

    let inputs = parse_key_upload_payload(text)?;
    if inputs.is_empty() {
        return Err(AppError::BadRequest("no_keys_found_in_payload".into()));
    }

    let mut inserted = Vec::with_capacity(inputs.len());
    for inp in inputs {
        let rec = state.vault.insert_key(&inp)?;
        inserted.push(rec);
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "uploaded": inserted.len(),
            "keys": inserted,
        })),
    ))
}

fn parse_key_upload_payload(text: &str) -> AppResult<Vec<UploadKeyInput>> {
    if text.starts_with('[') {
        return serde_json::from_str::<Vec<UploadKeyInput>>(text)
            .map_err(|e| AppError::BadRequest(format!("invalid_json_array: {e}")));
    }
    if text.starts_with('{') {
        if let Ok(single) = serde_json::from_str::<UploadKeyInput>(text) {
            return Ok(vec![single]);
        }
        // Try JSONL
        let mut out = Vec::new();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() {
                continue;
            }
            let item = serde_json::from_str::<UploadKeyInput>(l)
                .map_err(|e| AppError::BadRequest(format!("invalid_jsonl_line: {e}")))?;
            out.push(item);
        }
        return Ok(out);
    }

    // Parse `.env`-style lines (e.g. OPENAI_API_KEY=sk-...)
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let key_val = v.trim().trim_matches('"').trim_matches('\'').to_string();
            if key_val.is_empty() {
                continue;
            }
            let provider = infer_provider_from_env(k.trim());
            out.push(UploadKeyInput {
                provider: provider.to_string(),
                api_key: key_val,
                label: Some(k.trim().to_string()),
                base_url: None,
                max_usd_per_day: None,
                max_requests_per_hour: None,
                allowed_models: Vec::new(),
            });
        }
    }
    Ok(out)
}

fn infer_provider_from_env(env_key: &str) -> &'static str {
    let k = env_key.to_uppercase();
    if k.contains("ANTHROPIC") {
        "anthropic"
    } else if k.contains("GEMINI") || k.contains("GOOGLE") {
        "gemini"
    } else if k.contains("GROQ") {
        "groq"
    } else if k.contains("MISTRAL") {
        "mistral"
    } else if k.contains("TOGETHER") {
        "together"
    } else if k.contains("OPENROUTER") {
        "openrouter"
    } else if k.contains("COHERE") {
        "cohere"
    } else if k.contains("OLLAMA") {
        "ollama"
    } else {
        "openai"
    }
}

/// List all uploaded provider keys with secrets masked.
pub async fn list_keys(State(state): State<Arc<AppState>>) -> AppResult<Json<Value>> {
    let keys = state.vault.list_masked()?;
    Ok(Json(json!({ "keys": keys })))
}

/// Delete an uploaded provider key by ID.
pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let deleted = state.vault.delete_key(&id)?;
    if !deleted {
        return Err(AppError::NotFound(format!("key:{id}")));
    }
    Ok(Json(json!({ "deleted": true, "id": id })))
}

/// Rotate payload.
#[derive(Debug, Deserialize)]
pub struct RotatePayload {
    /// New upstream API key value.
    pub api_key: String,
}

/// Atomically rotate an existing key's encrypted ciphertext.
pub async fn rotate_key(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<RotatePayload>,
) -> AppResult<Json<Value>> {
    let ok = state.vault.rotate_key(&id, &body.api_key)?;
    if !ok {
        return Err(AppError::NotFound(format!("key:{id}")));
    }
    Ok(Json(json!({ "rotated": true, "id": id })))
}

/// Test a stored provider key by firing a lightweight probe (or stub probe) and returning latency.
pub async fn test_key(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    use secrecy::ExposeSecret;
    let t0 = Instant::now();
    let rec = state
        .vault
        .resolve_by_id(&id)?
        .ok_or_else(|| AppError::NotFound(format!("key:{id}")))?;
    if state.providers.stub_mode || rec.provider == "ollama" {
        return Ok(Json(json!({
            "ok": true,
            "provider": rec.provider,
            "latency_ms": t0.elapsed().as_millis(),
            "detail": "verified_local_or_stub",
        })));
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let base = rec
        .base_url
        .as_deref()
        .unwrap_or_else(|| crate::plane3::providers::openai::default_base_url(&rec.provider));
    let url = format!("{}/models", base.trim_end_matches('/'));
    let req_builder = if rec.provider == "anthropic" {
        client
            .get(&url)
            .header("x-api-key", rec.api_key.expose_secret())
            .header("anthropic-version", "2023-06-01")
    } else {
        client
            .get(&url)
            .bearer_auth(rec.api_key.expose_secret())
    };
    let resp = req_builder.send().await;
    let (ok, detail) = match resp {
        Ok(r) => (r.status().is_success(), format!("HTTP {}", r.status())),
        Err(e) => (false, format!("unreachable: {e}")),
    };
    Ok(Json(json!({
        "ok": ok,
        "provider": rec.provider,
        "latency_ms": t0.elapsed().as_millis(),
        "detail": detail,
    })))
}

/// Return current runtime settings for the UI Config tab.
pub async fn get_config(State(state): State<Arc<AppState>>) -> Json<Value> {
    let cfg = state.settings.read().await.clone();
    Json(json!({ "settings": cfg }))
}

/// Update runtime settings from the UI Config tab.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(new_cfg): Json<Settings>,
) -> Json<Value> {
    *state.settings.write().await = new_cfg.clone();
    Json(json!({ "saved": true, "settings": new_cfg }))
}
