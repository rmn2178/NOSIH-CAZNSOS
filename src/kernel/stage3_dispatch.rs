//! Stage 3: Carbon-Conformal Dispatch (`CA-DPD-LinUCB` + `PCSP` + Symbolic CPU check).

use crate::config::settings::Settings;
use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::plane3::dag::executor::try_symbolic_eval;
use crate::plane3::providers::chain::ProviderChain;
use crate::types::energy::ModelTier;
use std::time::Instant;

/// Execute Stage 3: select execution tier and concrete `(provider, model)` or CPU symbolic answer.
pub async fn run_stage3(
    kernel: &NosihKernel,
    ctx: &mut KernelContext,
    settings: &Settings,
) -> Option<String> {
    let t0 = Instant::now();
    let symbolic_ans = if ctx.requested_model == "nosih-symbolic"
        || (ctx.requested_model == "nosih-auto" && ctx.profile.has_math)
    {
        try_symbolic_eval(&ctx.prompt)
    } else {
        None
    };

    let has_sym = symbolic_ans.is_some();
    let proposed = match ctx.requested_model.as_str() {
        "nosih-symbolic" => ModelTier::Symbolic,
        "nosih-small" => ModelTier::Small,
        "nosih-medium" => ModelTier::Medium,
        "nosih-large" => ModelTier::Large,
        "nosih-auto" => {
            if has_sym {
                ModelTier::Symbolic
            } else {
                let pens = kernel
                    .pcsp
                    .read()
                    .await
                    .penalty_vector(ctx.provenance.integrity, ctx.carbon);
                let arm = kernel
                    .bandit
                    .read()
                    .await
                    .select(&ctx.profile.vector, &[2, 3, 4], &pens);
                ModelTier::from_arm(arm)
            }
        }
        _ => ModelTier::Medium,
    };

    let (selected, mitigated) = kernel.pcsp.write().await.arbitrate(
        proposed,
        ctx.provenance.integrity,
        ctx.carbon,
        has_sym,
    );
    ctx.selected_tier = selected;
    ctx.cdow_mitigated = mitigated;

    let concrete_model = match ctx.requested_model.as_str() {
        "nosih-auto" | "nosih-small" | "nosih-medium" | "nosih-large" | "nosih-symbolic" => {
            match selected {
                ModelTier::Cache => "nosih-cache".to_string(),
                ModelTier::Symbolic => "nosih-symbolic".to_string(),
                ModelTier::Small => settings.tier_models.small.clone(),
                ModelTier::Medium => settings.tier_models.medium.clone(),
                ModelTier::Large => settings.tier_models.large.clone(),
            }
        }
        explicit => explicit.to_string(),
    };

    let chosen_provider = if settings.stub_provider {
        "stub".to_string()
    } else if let Some(mapped) = settings.model_routes.get(&concrete_model) {
        mapped.clone()
    } else {
        ProviderChain::infer_provider(&concrete_model).to_string()
    };

    ctx.chosen_model = concrete_model;
    ctx.chosen_provider = chosen_provider;

    kernel.log_ring.emit(
        ctx.request_id.as_str(),
        "stage3_dispatch",
        "plane2",
        "info",
        &format!(
            "C(t)={:.1} tier={} model={} provider={} cdow_mitigated={}",
            ctx.carbon.gco2_per_kwh,
            ctx.selected_tier.as_str(),
            ctx.chosen_model,
            ctx.chosen_provider,
            ctx.cdow_mitigated
        ),
        t0.elapsed().as_micros() as u64,
        None,
        None,
        None,
        None,
        format!("{:?}", ctx.provenance.integrity),
        "Internal".into(),
        format!("dispatch:{}", ctx.selected_tier.as_str()),
    );

    if selected == ModelTier::Symbolic {
        symbolic_ans
    } else {
        None
    }
}
