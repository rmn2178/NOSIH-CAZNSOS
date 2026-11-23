//! Single `AppError` enum rendering clean OpenAI-shaped JSON error envelopes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

/// OpenAI-compatible error envelope returned on every non-2xx response.
#[derive(Debug, Clone, Serialize)]
pub struct OpenAiErrorEnvelope {
    /// Structured error object.
    pub error: OpenAiErrorDetail,
}

/// Inner OpenAI error detail.
#[derive(Debug, Clone, Serialize)]
pub struct OpenAiErrorDetail {
    /// Human-readable message.
    pub message: String,
    /// Error category.
    #[serde(rename = "type")]
    pub error_type: String,
    /// Machine-readable error code.
    pub code: String,
    /// Unique request identifier for log correlation.
    pub request_id: String,
}

/// Unified application error enum.
#[derive(Debug, Error)]
pub enum AppError {
    /// Missing or invalid local API key.
    #[error("Invalid or missing API key")]
    Unauthorized,
    /// Admin endpoint called without valid `X-NOSIH-Admin` token or non-loopback peer.
    #[error("Forbidden: {0}")]
    Forbidden(String),
    /// Invalid request syntax or RFC 8785 JCS validation failure.
    #[error("Bad request: {0}")]
    BadRequest(String),
    /// Unknown model or resource.
    #[error("Not found: {0}")]
    NotFound(String),
    /// Token bucket rate limit exceeded.
    #[error("Rate limit exceeded")]
    RateLimited,
    /// Capability or budget rejected by Plane I.
    #[error("Capability rejected: {0}")]
    CapabilityDenied(String),
    /// Upstream provider returned an error or unreachable.
    #[error("Upstream provider error: {0}")]
    Upstream(String),
    /// SQLite storage error.
    #[error("Storage error: {0}")]
    Storage(String),
    /// Internal server error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AppError {
    /// HTTP status code for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) | Self::CapabilityDenied(_) => StatusCode::FORBIDDEN,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
            Self::Storage(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Machine-readable code string.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "invalid_api_key",
            Self::Forbidden(_) => "forbidden",
            Self::BadRequest(_) => "invalid_request_error",
            Self::NotFound(_) => "not_found",
            Self::RateLimited => "rate_limit_exceeded",
            Self::CapabilityDenied(_) => "capability_denied",
            Self::Upstream(_) => "upstream_error",
            Self::Storage(_) => "storage_error",
            Self::Internal(_) => "internal_error",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let env = OpenAiErrorEnvelope {
            error: OpenAiErrorDetail {
                message: self.to_string(),
                error_type: self.code().to_string(),
                code: self.code().to_string(),
                request_id: format!("req-{}", Uuid::new_v4()),
            },
        };
        (status, Json(env)).into_response()
    }
}
