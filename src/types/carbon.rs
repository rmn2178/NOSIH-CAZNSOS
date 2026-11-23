//! Carbon intensity newtype (`CarbonIntensity`) in gCO2eq/kWh.

use crate::types::energy::EnergyWh;
use serde::{Deserialize, Serialize};

/// Grid carbon intensity in grams CO2 equivalent per kilowatt-hour (`gCO2eq/kWh`).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CarbonIntensity {
    /// Intensity value in `gCO2eq/kWh`.
    pub gco2_per_kwh: f64,
    /// Data source tag (`"forecast"` or `"observed"`).
    pub source: CarbonSource,
}

/// Whether the carbon intensity reading came from live API observation or diurnal forecast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarbonSource {
    /// Built-in deterministic diurnal prior + OU residual.
    Forecast,
    /// Live API observation (e.g. ElectricityMaps).
    Observed,
}

impl CarbonIntensity {
    /// Compute operational CO2 emissions in grams for a given `EnergyWh`.
    pub fn emissions_grams(self, energy: EnergyWh) -> f64 {
        energy.to_kwh() * self.gco2_per_kwh
    }
}
