//! Stage 4: Static Kahn + IFC DAG Verification before capability minting.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::plane3::dag::ifc::{IfcNode, verify_ifc_dag};
use crate::types::energy::ModelTier;
use std::time::Instant;

/// Execute Stage 4: run static Kahn + IFC DAG verification over the request execution graph.
///
/// Marks tool-calling requests and `ModelTier::Large` dispatches as privileged sinks so that
/// `IntegrityRank::Untrusted` inputs cannot flow into privileged execution without sanitization.
pub async fn run_stage4(kernel: &NosihKernel, ctx: &KernelContext) -> AppResult<()> {
    let t0 = Instant::now();
    let is_privileged_sink = ctx.has_tools || ctx.selected_tier == ModelTier::Large;
    let nodes = vec![
        IfcNode {
            id: "ingress_prompt".into(),
            integrity: ctx.provenance.integrity,
            confidentiality: ctx.provenance.confidentiality,
            privileged_sink: false,
            deps: Vec::new(),
        },
        IfcNode {
            id: "provider_dispatch".into(),
            integrity: ctx.provenance.integrity,
            confidentiality: ctx.provenance.confidentiality,
            privileged_sink: is_privileged_sink,
            deps: vec!["ingress_prompt".into()],
        },
    ];
    verify_ifc_dag(&nodes).map_err(AppError::CapabilityDenied)?;

    kernel.log_ring.emit(
        ctx.request_id.as_str(),
        "stage4_verify",
        "plane3",
        "info",
        &format!(
            "Static Kahn + IFC DAG verification passed (privileged_sink={is_privileged_sink})"
        ),
        t0.elapsed().as_micros() as u64,
        None,
        None,
        None,
        None,
        format!("{:?}", ctx.provenance.integrity),
        "Internal".into(),
        "ifc_valid".into(),
    );
    Ok(())
}
