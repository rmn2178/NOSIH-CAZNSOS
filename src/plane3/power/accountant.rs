//! Deterministic proxy energy & Scope-2 CO2 accountant (`PROXY_ESTIMATE`).

use crate::types::carbon::CarbonIntensity;
use crate::types::energy::{EnergyWh, ModelTier};

/// Fixed connection warmup energy proxies (Joules).
pub const TLS_HANDSHAKE_J: f64 = 0.8;
/// OAuth/auth refresh proxy (Joules).
pub const AUTH_REFRESH_J: f64 = 1.5;
/// TCP connect proxy (Joules).
pub const TCP_CONNECT_J: f64 = 0.2;

/// Compute deterministic proxy energy (`Wh`) and Scope-2 CO2 (`g`) for a completed request.
pub fn estimate_footprint(
    tier: ModelTier,
    total_tokens: u64,
    warmup_joules: f64,
    carbon: CarbonIntensity,
) -> (EnergyWh, f64) {
    let tok_wh = (total_tokens.max(1) as f64 / 1000.0) * tier.proxy_wh_per_1k_tokens();
    let total_wh = EnergyWh(tok_wh + EnergyWh::from_joules(warmup_joules).0);
    let co2_g = carbon.emissions_grams(total_wh);
    (total_wh, co2_g)
}
