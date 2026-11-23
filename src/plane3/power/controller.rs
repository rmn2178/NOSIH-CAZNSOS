//! EWMA-hysteresis per-provider warm-state controller modulated by diurnal carbon `M_C(t)`.

use crate::plane3::power::accountant::{AUTH_REFRESH_J, TCP_CONNECT_J, TLS_HANDSHAKE_J};
use crate::plane3::power::state::WarmState;
use crate::types::authorized::{Authorized, ProviderWarmup};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct ProviderSlot {
    state: WarmState,
    last_used_s: f64,
    ewma_interarrival_s: f64,
    wakeups: u64,
}

/// Manages per-provider warm-states (`ACTIVE` / `WARM` / `DEEP`) with pre-auth warmup gating.
#[derive(Debug, Default)]
pub struct ProviderPowerManager {
    slots: HashMap<String, ProviderSlot>,
    /// Count of unauthorized wakeup attempts blocked (0.0 J wasted).
    pub blocked_unauth_wakeups: u64,
}

impl ProviderPowerManager {
    /// Construct empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    fn now_s() -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }

    /// Evaluate carbon-modulated idle demotion `M_C(t) = clip(340 / C(t), 0.65, 1.35)`.
    pub fn tick_idle(&mut self, provider: &str, carbon_gco2_kwh: f64) -> WarmState {
        let now = Self::now_s();
        let c_mod = (340.0 / carbon_gco2_kwh.max(1.0)).clamp(0.65, 1.35);
        let slot = self.slots.entry(provider.to_string()).or_insert(ProviderSlot {
            state: WarmState::Deep,
            last_used_s: now,
            ewma_interarrival_s: 30.0,
            wakeups: 0,
        });
        let idle = (now - slot.last_used_s).max(0.0);
        if slot.state == WarmState::Active && idle > 45.0 * c_mod {
            slot.state = WarmState::Warm;
        } else if slot.state == WarmState::Warm && idle > 180.0 * c_mod {
            slot.state = WarmState::Deep;
        }
        slot.state
    }

    /// Record a rejected unauthorized probe (wakes NOTHING, incurs 0.0 J).
    pub fn record_unauthorized_probe(&mut self) {
        self.blocked_unauth_wakeups += 1;
    }

    /// Wake a provider connection pool — **ONLY callable with `Authorized<ProviderWarmup>`**.
    pub fn warmup(&mut self, auth: Authorized<ProviderWarmup>) -> f64 {
        let provider = &auth.payload().provider;
        let now = Self::now_s();
        let slot = self.slots.entry(provider.clone()).or_insert(ProviderSlot {
            state: WarmState::Deep,
            last_used_s: now,
            ewma_interarrival_s: 30.0,
            wakeups: 0,
        });
        let dt = (now - slot.last_used_s).max(0.001);
        slot.ewma_interarrival_s = 0.22 * dt + 0.78 * slot.ewma_interarrival_s;
        slot.last_used_s = now;

        let joules = match slot.state {
            WarmState::Active => 0.0,
            WarmState::Warm => AUTH_REFRESH_J,
            WarmState::Deep => TCP_CONNECT_J + TLS_HANDSHAKE_J + AUTH_REFRESH_J,
        };
        if slot.state != WarmState::Active {
            slot.state = WarmState::Active;
            slot.wakeups += 1;
        }
        joules
    }

    /// Return total warmup wakeups performed across all tracked providers.
    pub fn total_wakeups(&self) -> u64 {
        self.slots.values().map(|s| s.wakeups).sum()
    }
}
