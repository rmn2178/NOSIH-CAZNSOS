//! Local API key authentication accepting `Authorization: Bearer <KEY>` or `x-api-key`.
//!
//! Enforces provenance anti-spoofing: unverified `X-NOSIH-Origin` headers are capped at
//! `UserDirect` unless accompanied by a valid `X-NOSIH-Origin-Sig` HMAC-SHA256 signature
//! or a verified privileged `X-NOSIH-Admin` token.

use crate::app::AppState;
use crate::error::api_error::AppError;
use crate::plane1::crypto::hmac::{ct_eq, hmac_sha256_hex};
use crate::types::integrity::IntegrityRank;
use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

const ORIGIN_SIG_DOMAIN: &[u8] = b"NOSIH-ORIGIN-SIG-V1\x00";

/// Authenticated request metadata injected into extensions.
#[derive(Debug, Clone)]
pub struct LocalAuthInfo {
    /// Verified or capped provenance origin string.
    pub origin: String,
    /// True if privileged origin claims were cryptographically verified.
    pub origin_verified: bool,
}

/// Axum middleware enforcing constant-time local key verification, rate limiting,
/// and anti-spoofing provenance capping.
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

    let raw_origin = req
        .headers()
        .get("x-nosih-origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "user".to_string());

    // Privileged origins (rank < UserDirect) require either a valid HMAC signature
    // in `X-NOSIH-Origin-Sig` or a valid `X-NOSIH-Admin` token.
    let admin_verified = req
        .headers()
        .get("x-nosih-admin")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .is_some_and(|tok| {
            !tok.is_empty() && ct_eq(tok.as_bytes(), state.admin_token.as_str().as_bytes())
        });

    let sig_verified = req
        .headers()
        .get("x-nosih-origin-sig")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .is_some_and(|sig| {
            let expected = hmac_sha256_hex(
                state.origin_hmac_key.as_bytes(),
                ORIGIN_SIG_DOMAIN,
                raw_origin.as_bytes(),
            );
            ct_eq(sig.as_bytes(), expected.as_bytes())
        });

    let origin_verified = admin_verified || sig_verified;
    let origin = if origin_verified {
        raw_origin
    } else {
        match IntegrityRank::from_unverified_origin(&raw_origin) {
            IntegrityRank::UserDirect => "user".to_string(),
            IntegrityRank::DerivedDet => "det".to_string(),
            _ => "untrusted".to_string(),
        }
    };

    req.extensions_mut().insert(LocalAuthInfo {
        origin,
        origin_verified,
    });
    Ok(next.run(req).await)
}
