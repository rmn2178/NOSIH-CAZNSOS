//! Optional ElectricityMaps live carbon intensity fetcher (never called without user key).

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use serde_json::Value;
use std::time::Duration;

/// Fetch latest carbon intensity for `zone` using a user-supplied ElectricityMaps token.
pub async fn fetch_electricity_maps(zone: &str, api_key: &str) -> AppResult<f64> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| AppError::Upstream(e.to_string()))?;
    let url = format!(
        "https://api.electricitymap.org/v3/carbon-intensity/latest?zone={zone}"
    );
    let resp = client
        .get(url)
        .header("auth-token", api_key)
        .send()
        .await
        .map_err(|e| AppError::Upstream(e.to_string()))?;
    let body: Value = resp
        .json()
        .await
        .map_err(|e| AppError::Upstream(e.to_string()))?;
    body.get("carbonIntensity")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| AppError::Upstream("missing_carbonIntensity_field".into()))
}
