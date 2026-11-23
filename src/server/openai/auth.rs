//! Local API key authentication accepting `Authorization: Bearer <KEY>` or `x-api-key`.

use crate::app::AppState;
use crate::error::api_error::AppError;
use crate::plane1::crypto::hmac::ct_eq;
use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

/// Authenticated request metadata injected into extensions.
#[derive(Debug, Clone)]
pub struct LocalAuthInfo {
    /// Provenance origin from `X-NOSIH-Origin` (defaults to `"user"`).
    pub origin: String,
}

/// Axum middleware enforcing constant-time local key verification and token-bucket rate limiting.
pub async fn require_local_key(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let bearer = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")))
        .map(str::trim);

    let x_key = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);

    let presented = bearer.or(x_key).unwrap_or("");
    if presented.is_empty() || !ct_eq(presented.as_bytes(), state.local_key.as_str().as_bytes()) {
        return Err(AppError::Unauthorized);
    }

    if !state.rate_limiter.allow("local").await {
        return Err(AppError::RateLimited);
    }

    let origin = req
        .headers()
        .get("x-nosih-origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "user".to_string());

    req.extensions_mut().insert(LocalAuthInfo { origin });
    Ok(next.run(req).await)
}
