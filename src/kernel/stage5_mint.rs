//! Stage 5: Mint, attenuate, and verify `SPCCE-Macaroon` -> `Authorized<ProviderCall>`.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::plane1::macaroon::caveat::Caveat;
use crate::types::authorized::{Authorized, ProviderCall};
use crate::types::decimal::ExactDecimal;
use crate::types::energy::ModelTier;
use crate::types::ids::JtiNonce;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

/// Tier-specific exact USD price per 1M tokens (zero floating-point).
pub(crate) fn tier_usd_per_million(tier: ModelTier) -> ExactDecimal {
    match tier {
        ModelTier::Cache | ModelTier::Symbolic => ExactDecimal::ZERO,
        ModelTier::Small => ExactDecimal::from_i64_with_scale(15, 2), // $0.15 / 1M
        ModelTier::Medium => ExactDecimal::from_i64_with_scale(25, 2), // $0.25 / 1M
        ModelTier::Large => ExactDecimal::from_i64_with_scale(250, 2), // $2.50 / 1M
    }
}

/// Execute Stage 5: mint per-request Macaroon, attenuate caveats, and verify into `Authorized<ProviderCall>`.
pub async fn run_stage5(
    kernel: &NosihKernel,
    ctx: &mut KernelContext,
) -> AppResult<Authorized<ProviderCall>> {
    let t0 = Instant::now();
    let root = kernel
        .macaroon
        .mint_root(&ctx.tenant_id, ctx.request_id.as_str(), 60)?;
    let jti = JtiNonce::try_generate()
        .map_err(|e| AppError::Internal(format!("csprng_jti_failed: {e}")))?
        .0;
    let tok = root
        .attenuate(Caveat::new("provider", json!(ctx.chosen_provider)))?
        .attenuate(Caveat::new("model", json!(ctx.chosen_model)))?
        .attenuate(Caveat::new("max_usd", json!("5.00")))?
        .attenuate(Caveat::new("jti_single_use", json!(jti)))?;

    let rate = tier_usd_per_million(ctx.selected_tier);
    let min_floor = ExactDecimal::from_i64_with_scale(1, 4); // $0.0001 minimum reservation
    let est_tokens = (ctx.profile.token_count as u64).saturating_mul(2).max(256);
    let computed = ExactDecimal::token_cost_usd(est_tokens, rate);
    let est_cost = if computed > min_floor {
        computed
    } else {
        min_floor
    };

    let macaroon = Arc::clone(&kernel.macaroon);
    let provider = ctx.chosen_provider.clone();
    let model = ctx.chosen_model.clone();
    let req_id = ctx.request_id.as_str().to_string();
    let auth = tokio::task::spawn_blocking(move || {
        macaroon.verify_and_authorize(&tok, &provider, &model, &req_id, est_cost)
    })
    .await
    .map_err(|e| AppError::Internal(format!("stage5_join_err: {e}")))??;

    ctx.pre_debited_usd = est_cost;

    kernel.log_ring.emit(
        ctx.request_id.as_str(),
        "stage5_mint",
        "plane1",
        "info",
        "SPCCE-Macaroon verified; JTI consumed; Authorized<ProviderCall> minted",
        t0.elapsed().as_micros() as u64,
        None,
        None,
        Some(est_cost.to_string()),
        None,
        format!("{:?}", ctx.provenance.integrity),
        "Internal".into(),
        "authorized".into(),
    );
    Ok(auth)
}
