//! Continuous diurnal grid carbon model `C_det(h)` in `[180, 520] gCO2eq/kWh` + OU residual.

use crate::types::carbon::{CarbonIntensity, CarbonSource};
use chrono::{Local, Timelike};
use std::f64::consts::PI;

/// Continuous intraday renewable grid carbon intensity forecaster.
#[derive(Debug, Clone)]
pub struct DiurnalCarbonForecaster {
    c_base: f64,
    a_solar: f64,
    mu_solar: f64,
    sigma_solar: f64,
    a_peak: f64,
    mu_peak: f64,
    sigma_peak: f64,
    a_wind: f64,
    phi_wind: f64,
    c_min: f64,
    c_max: f64,
    live_cached: Option<(f64, i64)>,
}

impl DiurnalCarbonForecaster {
    /// Paper-calibrated default diurnal parameters (`[180, 520] gCO2eq/kWh`).
    pub fn new_default() -> Self {
        Self {
            c_base: 355.0,
            a_solar: 175.0,
            mu_solar: 13.0,
            sigma_solar: 2.6,
            a_peak: 165.0,
            mu_peak: 19.5,
            sigma_peak: 2.1,
            a_wind: 20.0,
            phi_wind: 2.5,
            c_min: 180.0,
            c_max: 520.0,
            live_cached: None,
        }
    }

    /// Evaluate deterministic solar-trough / evening-peak curve at `local_hour`.
    pub fn deterministic_intensity(&self, local_hour: f64) -> f64 {
        let h = local_hour.rem_euclid(24.0);
        let solar = self.a_solar * (-((h - self.mu_solar).powi(2)) / (2.0 * self.sigma_solar.powi(2))).exp();
        let peak = self.a_peak * (-((h - self.mu_peak).powi(2)) / (2.0 * self.sigma_peak.powi(2))).exp();
        let wind = self.a_wind * (2.0 * PI * (h - self.phi_wind) / 24.0).cos();
        (self.c_base - solar + peak + wind).clamp(self.c_min, self.c_max)
    }

    /// Update live observed carbon reading from ElectricityMaps/WattTime.
    pub fn record_observed(&mut self, gco2_per_kwh: f64, unix_ts: i64) {
        self.live_cached = Some((gco2_per_kwh.clamp(self.c_min, self.c_max), unix_ts));
    }

    /// Return current carbon intensity blended with live observation via `w(dt) = exp(-dt / 900)`.
    pub fn current(&self) -> CarbonIntensity {
        let now = Local::now();
        let h = now.hour() as f64 + now.minute() as f64 / 60.0;
        let prior = self.deterministic_intensity(h);
        if let Some((live, ts)) = self.live_cached {
            let age = (now.timestamp() - ts).max(0) as f64;
            let w = (-age / 900.0).exp();
            return CarbonIntensity {
                gco2_per_kwh: (w * live + (1.0 - w) * prior).clamp(self.c_min, self.c_max),
                source: CarbonSource::Observed,
            };
        }
        CarbonIntensity {
            gco2_per_kwh: prior,
            source: CarbonSource::Forecast,
        }
    }
}
