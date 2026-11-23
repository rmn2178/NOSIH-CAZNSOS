//! Stage 2: Provenance-Scoped Semantic Cache (`PS-RCSC`) lookup.

use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::plane2::cache::key::ProvenanceScopeKey;
use crate::plane2::cache::store::CacheLookup;
use std::time::Instant;

/// Execute Stage 2: check `PS-RCSC` cache partitioned by canonical JCS scope digest.
pub async fn run_stage2(kernel: &NosihKernel, ctx: &KernelContext) -> CacheLookup {
    let t0 = Instant::now();
    let scope = ProvenanceScopeKey {
        tenant_id: ctx.tenant_id.clone(),
        model_class: ctx.requested_model.clone(),
        policy_epoch: "epoch-1".into(),
        origin_integrity: ctx.provenance.integrity,
        schema_digest: "openai-v1".into(),
    };
    let conformal = kernel.conformal.read().await.clone();
    let res = kernel
        .cache
        .read()
        .await
        .lookup(&ctx.prompt, &scope, ctx.profile.risk_score, &conformal);

    kernel.log_ring.emit(
        ctx.request_id.as_str(),
        "stage2_cache",
        "plane2",
        "info",
        &format!("PS-RCSC status={} sim={:.3}", res.status, res.similarity),
        t0.elapsed().as_micros() as u64,
        None,
        None,
        None,
        None,
        format!("{:?}", ctx.provenance.integrity),
        "Internal".into(),
        res.status.clone(),
    );
    res
}
