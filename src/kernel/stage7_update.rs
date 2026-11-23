//! Stage 7: CCEC Merkle commit, exact-decimal budget reconciliation, PS-RCSC cache store,
//! and Conformal PID & CA-DPD-LinUCB feedback update.

use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::kernel::stage5_mint::tier_usd_per_million;
use crate::plane2::cache::key::ProvenanceScopeKey;
use crate::plane3::power::accountant::estimate_footprint;
use crate::types::decimal::ExactDecimal;
use crate::types::energy::ModelTier;
use std::sync::Arc;
use std::time::Instant;

/// Execute Stage 7: reconcile exact-decimal budget, commit CCEC certificate to `MTLog`,
/// store cache, and update online learners.
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
    let total_tokens = tokens_in.saturating_add(tokens_out);
    let (energy_wh, co2_g) = estimate_footprint(
        ctx.selected_tier,
        total_tokens,
        warmup_j,
        ctx.carbon,
    );

    // Exact-decimal cost calculation (zero f64 in monetary path).
    let actual_cost = if succeeded {
        ExactDecimal::token_cost_usd(total_tokens, tier_usd_per_million(ctx.selected_tier))
    } else {
        ExactDecimal::ZERO
    };
    let cost_str = actual_cost.to_string();

    // Offload budget reconciliation + CCEC Merkle commit off Tokio worker threads.
    let budget = Arc::clone(&kernel.budget);
    let ccec = Arc::clone(&kernel.ccec);
    let tenant_id = ctx.tenant_id.clone();
    let pre_debited = ctx.pre_debited_usd;
    let req_id = ctx.request_id.as_str().to_string();
    let provider = ctx.chosen_provider.clone();
    let model = ctx.chosen_model.clone();
    let tier_str = ctx.selected_tier.as_str().to_string();
    let energy_val = energy_wh.0;
    let carbon_val = ctx.carbon.gco2_per_kwh;
    let cost_for_ccec = cost_str.clone();

    let leaf = tokio::task::spawn_blocking(move || {
        if !succeeded {
            if pre_debited.is_positive() {
                let _ = budget.refund(&tenant_id, pre_debited);
            }
        } else if actual_cost > pre_debited {
            if let Some(delta) = actual_cost.checked_sub_nonneg(pre_debited) {
                if delta.is_positive() {
                    let _ = budget.ensure_and_debit(&tenant_id, delta);
                }
            }
        } else if pre_debited > actual_cost {
            if let Some(excess) = pre_debited.checked_sub_nonneg(actual_cost) {
                if excess.is_positive() {
                    let _ = budget.refund(&tenant_id, excess);
                }
            }
        }

        ccec.issue(
            &req_id,
            &provider,
            &model,
            &tier_str,
            energy_val,
            carbon_val,
            co2_g,
            &cost_for_ccec,
        )
        .ok()
        .map(|r| r.leaf_index)
    })
    .await
    .ok()
    .flatten();

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
            "CCEC leaf={:?} energy={:.5}Wh co2={:.5}g cost=${}",
            leaf, energy_wh.0, co2_g, cost_str
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
