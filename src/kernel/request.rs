//! Kernel request context flowing across stages 1 through 7.

use crate::plane1::semiring::SemiringLabel;
use crate::plane2::profiler::features::FeatureProfile10D;
use crate::types::carbon::CarbonIntensity;
use crate::types::decimal::ExactDecimal;
use crate::types::energy::ModelTier;
use crate::types::ids::RequestId;

/// Mutable request context passed sequentially through the 7 kernel stages.
#[derive(Debug, Clone)]
pub struct KernelContext {
    /// Unique request ID.
    pub request_id: RequestId,
    /// Tenant identifier.
    pub tenant_id: String,
    /// Extracted user prompt text.
    pub prompt: String,
    /// Requested OpenAI model string.
    pub requested_model: String,
    /// True if the request includes tool definitions (privileged tool-call sink for IFC).
    pub has_tools: bool,
    /// Bound provenance semiring label.
    pub provenance: SemiringLabel,
    /// 10D anti-spoofing CPU feature profile.
    pub profile: FeatureProfile10D,
    /// Active grid carbon intensity.
    pub carbon: CarbonIntensity,
    /// Chosen execution tier.
    pub selected_tier: ModelTier,
    /// Concrete upstream provider name.
    pub chosen_provider: String,
    /// Concrete upstream model name.
    pub chosen_model: String,
    /// Whether PCSP C-DoW mitigation triggered.
    pub cdow_mitigated: bool,
    /// Exact USD amount pre-debited in Stage 5 for reconciliation or refund.
    pub pre_debited_usd: ExactDecimal,
}
