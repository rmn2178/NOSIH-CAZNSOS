//! Embedded SPA UI route handler with strict Content-Security-Policy (`default-src 'self'`).

pub mod assets;

use crate::ui::assets::UiAssets;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

/// Serve embedded SPA UI assets with `Content-Security-Policy: default-src 'self'`.
pub async fn serve_ui_asset(uri: Uri) -> Response {
    let raw_path = uri.path().trim_start_matches('/');
    let path = if raw_path.is_empty() {
        "index.html"
    } else {
        raw_path
    };

    let asset = UiAssets::get(path).or_else(|| UiAssets::get("index.html"));
    let Some(file) = asset else {
        return (StatusCode::NOT_FOUND, "UI asset not found").into_response();
    };

    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut resp = (StatusCode::OK, file.data.into_owned()).into_response();
    if let Ok(ct) = HeaderValue::from_str(mime.as_ref()) {
        resp.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    resp.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:"),
    );
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}
