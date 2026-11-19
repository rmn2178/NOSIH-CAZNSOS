"""Dynamic Diurnal Carbon Forecaster, Predictive Multi-State Power Controller (PCS-PMC),
and Transparent Hybrid CPU/TDP Energy & Carbon Accountant for NOSIH.
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Deque, Dict, Optional, Tuple


class PowerState(str, Enum):
    ACTIVE = "ACTIVE"
    WARM_STANDBY = "WARM_STANDBY"
    DEEP_SLEEP = "DEEP_SLEEP"


@dataclass(frozen=True)
class TierPowerProfile:
    tier_id: str
    label: str
    active_cpu_w: float
    active_gpu_w: float
    idle_active_w: float
    idle_warm_w: float
    idle_sleep_w: float
    wake_warm_s: float
    wake_warm_j: float
    wake_deep_s: float
    wake_deep_j: float
    trans_act_warm_j: float
    trans_warm_deep_j: float
    cost_per_1m_tokens_usd: float

    @property
    def active_total_w(self) -> float:
        return self.active_cpu_w + self.active_gpu_w

    def breakeven_act_to_warm_s(self) -> float:
        delta_p = max(1e-6, self.idle_active_w - self.idle_warm_w)
        return (self.trans_act_warm_j + self.wake_warm_j) / delta_p

    def breakeven_warm_to_deep_s(self) -> float:
        delta_p = max(1e-6, self.idle_warm_w - self.idle_sleep_w)
        return (self.trans_warm_deep_j + self.wake_deep_j) / delta_p


DEFAULT_TIER_PROFILES: Dict[str, TierPowerProfile] = {
    "T0a_CACHE": TierPowerProfile(
        "T0a_CACHE", "PS-RCSC Cache", 2.5, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    ),
    "T0b_SYMBOLIC": TierPowerProfile(
        "T0b_SYMBOLIC", "CPU Symbolic Ops", 4.5, 0.0, 1.5, 1.5, 1.5, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    ),
    "T1_SMALL": TierPowerProfile(
        "T1_SMALL", "Small Neural (3B)", 12.0, 40.0, 18.0, 8.0, 2.5, 0.10, 6.0, 0.85, 50.0, 2.0, 4.0, 0.10
    ),
    "T2_MEDIUM": TierPowerProfile(
        "T2_MEDIUM", "Medium Neural (8B)", 20.0, 95.0, 30.0, 12.0, 2.5, 0.14, 12.0, 1.10, 105.0, 4.0, 8.0, 0.25
    ),
    "T3_LARGE": TierPowerProfile(
        "T3_LARGE", "Large Neural (32B)", 30.0, 145.0, 45.0, 18.0, 2.5, 0.18, 18.0, 1.40, 175.0, 6.0, 12.0, 0.85
    ),
}


class DiurnalCarbonForecaster:
    """Continuous diurnal renewable grid carbon intensity model C(t) in [180, 520] gCO2eq/kWh."""

    def __init__(
        self,
        c_base: float = 355.0,
        a_solar: float = 175.0,
        mu_solar: float = 13.0,
        sigma_solar: float = 2.6,
        a_peak: float = 165.0,
        mu_peak: float = 19.5,
        sigma_peak: float = 2.1,
        a_wind: float = 20.0,
        phi_wind: float = 2.5,
        c_min: float = 180.0,
        c_max: float = 520.0,
        theta_ou: float = 0.35,
        sigma_ou: float = 18.0,
        tau_stale_s: float = 900.0,
    ) -> None:
        self.c_base = c_base
        self.a_solar = a_solar
        self.mu_solar = mu_solar
        self.sigma_solar = sigma_solar
        self.a_peak = a_peak
        self.mu_peak = mu_peak
        self.sigma_peak = sigma_peak
        self.a_wind = a_wind
        self.phi_wind = phi_wind
        self.c_min = c_min
        self.c_max = c_max
        self.theta_ou = theta_ou
        self.sigma_ou = sigma_ou
        self.tau_stale_s = tau_stale_s
        self._eps = 0.0

    def deterministic_intensity(self, local_hour: float) -> float:
        h = local_hour % 24.0
        solar = self.a_solar * math.exp(-((h - self.mu_solar) ** 2) / (2.0 * self.sigma_solar ** 2))
        peak = self.a_peak * math.exp(-((h - self.mu_peak) ** 2) / (2.0 * self.sigma_peak ** 2))
        wind = self.a_wind * math.cos(2.0 * math.pi * (h - self.phi_wind) / 24.0)
        return max(self.c_min, min(self.c_max, self.c_base - solar + peak + wind))

    def step_intensity(
        self,
        local_hour: float,
        dt_hours: float = 0.05,
        z_noise: float = 0.0,
        live_signal: Optional[float] = None,
        live_age_s: float = 0.0,
    ) -> float:
        decay = math.exp(-self.theta_ou * max(0.0, dt_hours))
        self._eps = decay * self._eps + self.sigma_ou * math.sqrt(max(0.0, 1.0 - decay * decay)) * z_noise
        prior = max(self.c_min, min(self.c_max, self.deterministic_intensity(local_hour) + self._eps))
        if live_signal is not None:
            w = math.exp(-max(0.0, live_age_s) / self.tau_stale_s)
            return max(self.c_min, min(self.c_max, w * live_signal + (1.0 - w) * prior))
        return prior


class PredictivePowerController:
    """PCS-PMC: 3-state GPU/RAM power FSM with break-even & EWMA burstiness hysteresis."""

    def __init__(
        self,
        profile: TierPowerProfile,
        ewma_rho: float = 0.22,
        eta_down: float = 1.35,
        eta_arr: float = 1.15,
        kappa_cv: float = 0.25,
        min_dwell_act_s: float = 1.0,
        min_dwell_warm_s: float = 4.0,
        thrash_window_s: float = 300.0,
        thrash_limit: int = 3,
    ) -> None:
        self.profile = profile
        self.rho = ewma_rho
        self.eta_down = eta_down
        self.eta_arr = eta_arr
        self.kappa_cv = kappa_cv
        self.min_dwell_act_s = min_dwell_act_s
        self.min_dwell_warm_s = min_dwell_warm_s
        self.thrash_window_s = thrash_window_s
        self.thrash_limit = thrash_limit

        self.state = PowerState.ACTIVE
        self.last_arrival_t: Optional[float] = None
        self.last_state_change_t: float = 0.0
        self.idle_since_t: float = 0.0
        self.ewma_interarrival_s: float = 15.0
        self.ewma_var_s2: float = 4.0
        self.wakeup_timestamps: Deque[float] = deque()

        self.warm_events = 0
        self.sleep_events = 0
        self.wakeup_events = 0
        self.thrash_damp_events = 0
        self.blocked_unauthorized_wakeups = 0
        self.saved_unauthorized_wake_j = 0.0
        self.total_transition_energy_j = 0.0
        self.total_wakeup_latency_s = 0.0
        self.time_in_state_s: Dict[PowerState, float] = {
            PowerState.ACTIVE: 0.0,
            PowerState.WARM_STANDBY: 0.0,
            PowerState.DEEP_SLEEP: 0.0,
        }
        self._last_tick_t: float = 0.0

    @property
    def cv(self) -> float:
        return math.sqrt(max(0.0, self.ewma_var_s2)) / max(1e-6, self.ewma_interarrival_s)

    def _hysteresis_factor(self) -> float:
        return self.eta_down * (1.0 + self.kappa_cv * min(self.cv, 2.0))

    def current_idle_power_w(self) -> float:
        if self.state == PowerState.ACTIVE:
            return self.profile.idle_active_w
        if self.state == PowerState.WARM_STANDBY:
            return self.profile.idle_warm_w
        return self.profile.idle_sleep_w

    def _advance_clock(self, now_s: float) -> None:
        dt = max(0.0, now_s - self._last_tick_t)
        self.time_in_state_s[self.state] += dt
        self._last_tick_t = now_s

    def on_authorized_request_arrival(self, now_s: float, authorized: bool) -> Tuple[float, float]:
        """PA-PCS-PMC: Gate GPU wakeup behind Plane I authorization to defeat Sleep-Thrashing DoS."""
        if not authorized:
            self._advance_clock(now_s)
            if self.state != PowerState.ACTIVE:
                self.blocked_unauthorized_wakeups += 1
                self.saved_unauthorized_wake_j += (
                    self.profile.wake_warm_j if self.state == PowerState.WARM_STANDBY else self.profile.wake_deep_j
                )
            return 0.0, 0.0
        return self.on_request_arrival(now_s)

    def on_request_arrival(self, now_s: float) -> Tuple[float, float]:
        self._advance_clock(now_s)
        if self.last_arrival_t is not None:
            dt = max(1e-3, now_s - self.last_arrival_t)
            prev_mean = self.ewma_interarrival_s
            self.ewma_interarrival_s = self.rho * dt + (1.0 - self.rho) * prev_mean
            self.ewma_var_s2 = self.rho * ((dt - self.ewma_interarrival_s) ** 2) + (1.0 - self.rho) * self.ewma_var_s2
        self.last_arrival_t = now_s
        self.idle_since_t = now_s

        wake_lat = 0.0
        wake_j = 0.0
        if self.state == PowerState.WARM_STANDBY:
            wake_lat = self.profile.wake_warm_s
            wake_j = self.profile.wake_warm_j
        elif self.state == PowerState.DEEP_SLEEP:
            wake_lat = self.profile.wake_deep_s
            wake_j = self.profile.wake_deep_j

        if self.state != PowerState.ACTIVE:
            self.state = PowerState.ACTIVE
            self.last_state_change_t = now_s
            self.wakeup_events += 1
            self.total_wakeup_latency_s += wake_lat
            self.total_transition_energy_j += wake_j
            self.wakeup_timestamps.append(now_s)
            while self.wakeup_timestamps and (now_s - self.wakeup_timestamps[0]) > self.thrash_window_s:
                self.wakeup_timestamps.popleft()
            if len(self.wakeup_timestamps) > self.thrash_limit:
                self.eta_down = min(4.0, self.eta_down * 1.5)
                self.thrash_damp_events += 1

        return wake_lat, wake_j

    def evaluate_idle_transition(
        self,
        now_s: float,
        carbon_gco2_kwh: Optional[float] = None,
        carbon_ref_gco2_kwh: float = 340.0,
    ) -> PowerState:
        self._advance_clock(now_s)
        t_idle = max(0.0, now_s - self.idle_since_t)
        t_dwell = max(0.0, now_s - self.last_state_change_t)
        c_mod = 1.0
        if carbon_gco2_kwh is not None and carbon_gco2_kwh > 0.0:
            # Faster demotion during fossil peaks (C > C_ref), relaxed dwell during clean solar valleys
            c_mod = max(0.65, min(1.35, carbon_ref_gco2_kwh / carbon_gco2_kwh))
        h_mult = self._hysteresis_factor() * c_mod

        if self.state == PowerState.ACTIVE:
            tau_be = self.profile.breakeven_act_to_warm_s()
            if (
                t_idle >= h_mult * tau_be
                and self.ewma_interarrival_s >= self.eta_arr * tau_be
                and t_dwell >= self.min_dwell_act_s
            ):
                self.state = PowerState.WARM_STANDBY
                self.last_state_change_t = now_s
                self.warm_events += 1
                self.total_transition_energy_j += self.profile.trans_act_warm_j

        elif self.state == PowerState.WARM_STANDBY:
            tau_be = self.profile.breakeven_warm_to_deep_s()
            if (
                t_idle >= h_mult * tau_be
                and self.ewma_interarrival_s >= self.eta_arr * tau_be
                and t_dwell >= self.min_dwell_warm_s
            ):
                self.state = PowerState.DEEP_SLEEP
                self.last_state_change_t = now_s
                self.sleep_events += 1
                self.total_transition_energy_j += self.profile.trans_warm_deep_j

        return self.state


class TransparentEnergyAccountant:
    """Strictly provenance-tagged HYBRID_CPU_TDP energy, CO2, and operational cost accountant."""

    def __init__(self, pue: float = 1.0, electricity_usd_per_kwh: float = 0.12) -> None:
        self.pue = pue
        self.electricity_rate = electricity_usd_per_kwh
        self.accounting_mode = "HYBRID_CPU_TDP"

    def compute_query_footprint(
        self,
        profile: TierPowerProfile,
        exec_latency_s: float,
        carbon_intensity_g_per_kwh: float,
        tokens_total: int = 256,
        wake_energy_j: float = 0.0,
        phase_factor: float = 0.85,
    ) -> Dict[str, float | str]:
        eff_power_w = profile.active_cpu_w + phase_factor * profile.active_gpu_w
        active_j = eff_power_w * max(0.0, exec_latency_s) + max(0.0, wake_energy_j)
        energy_kwh = (active_j / 3_600_000.0) * self.pue
        co2_g = energy_kwh * carbon_intensity_g_per_kwh
        token_cost_usd = (tokens_total / 1_000_000.0) * profile.cost_per_1m_tokens_usd
        elec_cost_usd = energy_kwh * self.electricity_rate
        return {
            "accounting_mode": self.accounting_mode,
            "energy_kwh": energy_kwh,
            "co2_g": co2_g,
            "cost_usd": token_cost_usd + elec_cost_usd,
            "eff_power_w": eff_power_w,
        }
