//! Stage 6: Pre-authorized `PA-PCS-PMC` warmup + authorized upstream provider call.

use crate::error::result::AppResult;
use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::plane3::power::pa_pcs_pmc::authorize_warmup;
use crate::plane3::providers::chain::ProviderChain;
use crate::plane3::providers::traits::{ChatRequest, ProviderOutput};
use crate::types::authorized::{Authorized, ProviderCall};
use std::time::Instant;

/// Execute Stage 6: authorize warmup via `PA-PCS-PMC` and invoke `ProviderChain::call`.
pub async fn run_stage6(
    kernel: &NosihKernel,
    providers: &ProviderChain,
    ctx: &KernelContext,
    auth: Authorized<ProviderCall>,
    req: &ChatRequest,
) -> AppResult<(ProviderOutput, f64)> {
    let t0 = Instant::now();
    let warmup_auth = authorize_warmup(&auth);
    let warmup_j = {
        let mut mgr = kernel.power.write().await;
        mgr.tick_idle(&ctx.chosen_provider, ctx.carbon.gco2_per_kwh);
        mgr.warmup(warmup_auth)
    };

    let output = providers.call(auth, req).await?;

    kernel.log_ring.emit(
        ctx.request_id.as_str(),
        "stage6_execute",
        "plane3",
        "info",
        &format!(
            "Upstream {} ({}) executed; warmup={:.2}J",
            ctx.chosen_provider, ctx.chosen_model, warmup_j
        ),
        t0.elapsed().as_micros() as u64,
        None,
        None,
        None,
        None,
        format!("{:?}", ctx.provenance.integrity),
        "Internal".into(),
        "executed".into(),
    );

    Ok((output, warmup_j))
}
