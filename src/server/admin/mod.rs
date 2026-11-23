//! Admin control plane guarded by loopback binding + `X-NOSIH-Admin` CSRF-safe token.

pub mod export;
pub mod keys;

use crate::app::AppState;
use crate::error::api_error::AppError;
use crate::plane1::crypto::hmac::ct_eq;
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;
use std::sync::Arc;

/// Middleware enforcing loopback-only (or allowlisted IP) + `X-NOSIH-Admin` token header.
pub async fn require_admin(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        let ip_str = addr.ip().to_string();
        if !addr.ip().is_loopback() {
            let allowed = state.settings.read().await.admin_allowlist.contains(&ip_str);
            if !allowed {
                return Err(AppError::Forbidden("admin_loopback_only".into()));
            }
        }
    }

    let presented = req
        .headers()
        .get("x-nosih-admin")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");

    if presented.is_empty() || !ct_eq(presented.as_bytes(), state.admin_token.as_str().as_bytes()) {
        return Err(AppError::Forbidden("missing_or_invalid_admin_token".into()));
    }

    Ok(next.run(req).await)
}
