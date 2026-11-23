//! Stage 7: CCEC Merkle commit, PS-RCSC cache store, Conformal PID & CA-DPD-LinUCB feedback update.

use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::plane2::cache::key::ProvenanceScopeKey;
use crate::plane3::power::accountant::estimate_footprint;
use crate::types::energy::ModelTier;
use std::time::Instant;

/// Execute Stage 7: commit CCEC certificate to `MTLog`, store cache, and update online learners.
#[allow(clippy::too_many_arguments)]
pub async fn run_stage7(
    kernel: &NosihKernel,
    ctx: &KernelContext,
    response_text: &str,
    tokens_in: u64,
    tokens_out: u64,
    latency_ms: f64,
    warmup_j: f64,
    succeeded: bool,
) -> (f64, Option<usize>) {
    let t0 = Instant::now();
    let (energy_wh, co2_g) = estimate_footprint(
        ctx.selected_tier,
        tokens_in + tokens_out,
        warmup_j,
        ctx.carbon,
    );
    let cost_str = format!("{:.6}", ((tokens_in + tokens_out) as f64 / 1_000_000.0) * 0.25);

    let leaf = kernel
        .ccec
        .issue(
            ctx.request_id.as_str(),
            &ctx.chosen_provider,
            &ctx.chosen_model,
            ctx.selected_tier.as_str(),
            energy_wh.0,
            ctx.carbon.gco2_per_kwh,
            co2_g,
            &cost_str,
        )
        .ok()
        .map(|r| r.leaf_index);

    kernel.conformal.write().await.update_route(true, succeeded);
    kernel.bandit.write().await.update(
        ctx.selected_tier.arm_index(),
        &ctx.profile.vector,
        if succeeded { 1.0 } else { 0.0 },
        [
            (latency_ms / 3000.0).clamp(0.0, 1.0),
            (energy_wh.0 / 0.5).clamp(0.0, 1.0),
            (co2_g / 0.1).clamp(0.0, 1.0),
        ],
    );

    if succeeded && ctx.selected_tier != ModelTier::Cache && !response_text.is_empty() {
        let scope = ProvenanceScopeKey {
            tenant_id: ctx.tenant_id.clone(),
            model_class: ctx.requested_model.clone(),
            policy_epoch: "epoch-1".into(),
            origin_integrity: ctx.provenance.integrity,
            schema_digest: "openai-v1".into(),
        };
        kernel.cache.write().await.store(
            &ctx.prompt,
            &scope,
            response_text.to_string(),
            ctx.chosen_model.clone(),
        );
    }

    kernel.log_ring.emit(
        ctx.request_id.as_str(),
        "stage7_update",
        "kernel",
        "info",
        &format!(
            "CCEC leaf={:?} energy={:.5}Wh co2={:.5}g",
            leaf, energy_wh.0, co2_g
        ),
        t0.elapsed().as_micros() as u64,
        Some(tokens_in),
        Some(tokens_out),
        Some(cost_str),
        Some(co2_g),
        format!("{:?}", ctx.provenance.integrity),
        "Internal".into(),
        "committed".into(),
    );

    (co2_g, leaf)
}
