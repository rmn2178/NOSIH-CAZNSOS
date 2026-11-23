//! Stage 5: Mint, attenuate, and verify `SPCCE-Macaroon` -> `Authorized<ProviderCall>`.

use crate::error::result::AppResult;
use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::plane1::macaroon::caveat::Caveat;
use crate::types::authorized::{Authorized, ProviderCall};
use crate::types::decimal::ExactDecimal;
use crate::types::ids::JtiNonce;
use serde_json::json;
use std::time::Instant;

/// Execute Stage 5: mint per-request Macaroon, attenuate caveats, and verify into `Authorized<ProviderCall>`.
pub async fn run_stage5(
    kernel: &NosihKernel,
    ctx: &KernelContext,
) -> AppResult<Authorized<ProviderCall>> {
    let t0 = Instant::now();
    let root = kernel
        .macaroon
        .mint_root(&ctx.tenant_id, ctx.request_id.as_str(), 60)?;
    let jti = JtiNonce::generate().0;
    let tok = root
        .attenuate(Caveat::new("provider", json!(ctx.chosen_provider)))?
        .attenuate(Caveat::new("model", json!(ctx.chosen_model)))?
        .attenuate(Caveat::new("max_usd", json!("5.00")))?
        .attenuate(Caveat::new("jti_single_use", json!(jti)))?;

    let est_cost = ExactDecimal::from_i64_with_scale(1, 4); // $0.0001 pre-debit
    let auth = kernel.macaroon.verify_and_authorize(
        &tok,
        &ctx.chosen_provider,
        &ctx.chosen_model,
        ctx.request_id.as_str(),
        est_cost,
    )?;

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
