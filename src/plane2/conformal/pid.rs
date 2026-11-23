//! Online Conformal PID controller (`tau_{t+1}` with P + `k_I * tanh` integral term).

use std::collections::VecDeque;

/// Dual-channel online conformal risk controller for routing and cache admission.
#[derive(Debug, Clone)]
pub struct ConformalPidGate {
    /// Target risk `alpha` (default `0.05`).
    pub alpha: f64,
    /// Proportional step size `eta`.
    pub eta: f64,
    /// Nonlinear integral gain `k_I`.
    pub ki: f64,
    /// Current routing acceptance threshold `tau_t^route`.
    pub tau_route: f64,
    /// Current cache admission threshold `tau_t^cache`.
    pub tau_cache: f64,
    window: usize,
    errors: VecDeque<f64>,
}

impl ConformalPidGate {
    /// Default paper parameters (`alpha=0.05`, `eta=0.04`, `k_I=0.01`, `W=150`).
    pub fn new_default() -> Self {
        Self {
            alpha: 0.05,
            eta: 0.04,
            ki: 0.01,
            tau_route: 0.25,
            tau_cache: 0.12,
            window: 150,
            errors: VecDeque::with_capacity(150),
        }
    }

    /// Channel 1: Update routing selective-risk threshold.
    pub fn update_route(&mut self, accepted: bool, is_correct: bool) -> f64 {
        let loss = if accepted && !is_correct { 1.0 } else { 0.0 };
        if self.errors.len() >= self.window {
            self.errors.pop_front();
        }
        self.errors.push_back(loss);
        let gap = self.alpha - loss;
        let integ = if self.ki > 0.0 {
            let s: f64 = self.errors.iter().map(|&e| self.alpha - e).sum();
            self.ki * (s / 5.0).tanh()
        } else {
            0.0
        };
        self.tau_route = (self.tau_route + self.eta * gap + integ).clamp(0.005, 0.95);
        self.tau_route
    }

    /// Channel 2: Admit semantic cache hit iff `(1 - sim) + 0.15 * risk <= tau_cache`.
    pub fn should_admit_cache(&self, cosine_sim: f64, risk_score: f64) -> (bool, f64) {
        let nonconf = ((1.0 - cosine_sim) + 0.15 * risk_score).max(0.0);
        (nonconf <= self.tau_cache, nonconf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_only_telescoping_bound_holds() {
        let mut gate = ConformalPidGate::new_default();
        gate.ki = 0.0;
        let t_total = 10_000usize;
        let mut errs = 0usize;
        for t in 0..t_total {
            let score = ((t % 100) as f64) / 100.0;
            let accepted = score <= gate.tau_route;
            let is_correct = score < 0.85;
            if accepted && !is_correct {
                errs += 1;
            }
            gate.update_route(accepted, is_correct);
        }
        let mean_err = errs as f64 / t_total as f64;
        let bound = gate.alpha + (0.95 - 0.005 + gate.eta) / (gate.eta * t_total as f64) + 1e-3;
        assert!(mean_err <= bound, "mean_err={mean_err} exceeded bound={bound}");
    }
}
