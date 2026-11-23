//! Stage 4: Static Kahn + IFC DAG Verification before capability minting.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::plane3::dag::ifc::{IfcNode, verify_ifc_dag};
use std::time::Instant;

/// Execute Stage 4: run static Kahn + IFC DAG verification.
pub async fn run_stage4(kernel: &NosihKernel, ctx: &KernelContext) -> AppResult<()> {
    let t0 = Instant::now();
    let nodes = vec![IfcNode {
        id: "provider_dispatch".into(),
        integrity: ctx.provenance.integrity,
        confidentiality: ctx.provenance.confidentiality,
        privileged_sink: false,
        deps: Vec::new(),
    }];
    verify_ifc_dag(&nodes).map_err(AppError::CapabilityDenied)?;

    kernel.log_ring.emit(
        ctx.request_id.as_str(),
        "stage4_verify",
        "plane3",
        "info",
        "Static Kahn + IFC DAG verification passed",
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
