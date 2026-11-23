//! Stage 1: Strict JCS ingress validation, provenance binding, and 10D CPU profiling.

use crate::error::result::AppResult;
use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::plane1::jcs::parser::parse_json_strict;
use crate::plane1::semiring::SemiringLabel;
use crate::plane2::profiler::features::extract_features_10d;
use crate::types::confidentiality::ConfidentialityRank;
use crate::types::decimal::ExactDecimal;
use crate::types::energy::ModelTier;
use crate::types::ids::RequestId;
use crate::types::integrity::IntegrityRank;
use serde_json::Value;
use std::time::Instant;

/// Execute Stage 1: parse strict RFC 8785 JSON, bind provenance, and profile in 10D.
pub async fn run_stage1(
    kernel: &NosihKernel,
    raw_body: &[u8],
    requested_model: &str,
    prompt: &str,
    origin_header: &str,
) -> AppResult<(KernelContext, Value)> {
    let t0 = Instant::now();
    let parsed = parse_json_strict(raw_body)?;
    let has_tools = parsed
        .get("tools")
        .and_then(|v| v.as_array())
        .is_some_and(|arr| !arr.is_empty());
    let integrity = IntegrityRank::from_origin(origin_header);
    let provenance = SemiringLabel::from_origin(integrity, ConfidentialityRank::Internal);
    let profile = extract_features_10d(prompt);
    let carbon = kernel.forecaster.read().await.current();
    let request_id = RequestId::generate();

    kernel.log_ring.emit(
        request_id.as_str(),
        "stage1_ingress",
        "plane1",
        "info",
        &format!(
            "JCS ok; integrity={:?}; tokens={}; spoof_filtered={}; tools={}",
            integrity, profile.token_count, profile.spoof_filtered, has_tools
        ),
        t0.elapsed().as_micros() as u64,
        None,
        None,
        None,
        None,
        format!("{integrity:?}"),
        "Internal".into(),
        "ingress_ok".into(),
    );

    Ok((
        KernelContext {
            request_id,
            tenant_id: "local-default".into(),
            prompt: prompt.to_string(),
            requested_model: requested_model.to_string(),
            has_tools,
            provenance,
            profile,
            carbon,
            selected_tier: ModelTier::Medium,
            chosen_provider: "openai".into(),
            chosen_model: requested_model.to_string(),
            cdow_mitigated: false,
            pre_debited_usd: ExactDecimal::ZERO,
        },
        parsed,
    ))
}
