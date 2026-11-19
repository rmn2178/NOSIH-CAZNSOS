"""Dual-Channel Online Adaptive Conformal Inference (ACI) & Conformal PID Risk Controller.

Implements:
- Channel 1: Online Routing Selective-Risk Controller (Rolling Risk Control / Conformal PID,
  Gibbs & Candes NeurIPS 2021; Feldman et al. TMLR 2023; Angelopoulos et al. NeurIPS 2023)
  directly controlling selective acceptance threshold tau_t^route so E[ell_t] -> alpha_target
  while maximizing non-degenerate acceptance rate.
- Channel 2: Online Cache-Validity Risk Controller with Horvitz-Thompson IPW shadow auditing.
"""
from __future__ import annotations

import math
from collections import deque
from typing import Deque, Tuple

import numpy as np


class DualChannelACIGate:
    """Distribution-free online risk controller for both routing and semantic cache admission."""

    def __init__(
        self,
        route_target_alpha: float = 0.05,
        route_lr: float = 0.04,
        route_ki: float = 0.01,
        window_size: int = 150,
        cache_target_alpha: float = 0.02,
        cache_lr: float = 0.04,
        cache_audit_prob: float = 0.10,
        cache_kappa: float = 0.15,
    ) -> None:
        # Channel 1: Routing selective-risk PID controller
        self.alpha_route_target = route_target_alpha
        self.tau_route_t = 0.25  # initial acceptance threshold (nonconformity <= 0.25 => conf >= 0.75)
        self.eta_route = route_lr
        self.ki_route = route_ki
        self.window_size = window_size
        self.route_scores: Deque[float] = deque(maxlen=window_size)
        self.route_errors: Deque[float] = deque(maxlen=window_size)

        # Channel 2: Cache validity controller
        self.alpha_cache_target = cache_target_alpha
        self.eta_cache = cache_lr
        self.p_audit = max(1e-3, min(1.0, cache_audit_prob))
        self.kappa = cache_kappa
        self.tau_cache_t = 0.10
        self.tau_min = 0.005
        self.tau_max = 0.35
        self.valid_cache_scores: Deque[float] = deque(maxlen=window_size)

    # ---------------- Channel 1: Routing ----------------
    def current_route_threshold(self) -> float:
        return self.tau_route_t

    def should_accept_route(self, confidence: float) -> Tuple[bool, float, float]:
        """Returns (accepted, nonconformity_score, current_threshold)."""
        score = float(np.clip(1.0 - confidence, 0.0, 1.0))
        tau = self.tau_route_t
        return (score <= tau), score, tau

    def update_route(self, confidence: float, accepted: bool, is_correct: bool) -> float:
        """Update selective-risk Conformal PID controller:
        tau_{t+1} = clip(tau_t + eta*(alpha_target - ell_t) + k_I * tanh(sum(alpha_target - ell_j))).
        """
        score = float(np.clip(1.0 - confidence, 0.0, 1.0))
        self.route_scores.append(score if is_correct else 1.0)
        loss = 1.0 if (accepted and not is_correct) else 0.0
        self.route_errors.append(loss)

        err_gap = self.alpha_route_target - loss
        integral_term = self.ki_route * math.tanh(
            sum(self.alpha_route_target - e for e in self.route_errors) / 5.0
        )
        self.tau_route_t = float(
            np.clip(self.tau_route_t + self.eta_route * err_gap + integral_term, 0.005, 0.95)
        )
        return self.tau_route_t

    # ---------------- Channel 2: Cache Validity ----------------
    def cache_nonconformity(self, cosine_sim: float, risk_score: float) -> float:
        return float(max(0.0, (1.0 - cosine_sim) + self.kappa * risk_score))

    def cache_conformal_pvalue(self, score: float) -> float:
        if not self.valid_cache_scores:
            return 1.0
        ge_count = sum(1 for s in self.valid_cache_scores if s >= score)
        return (1.0 + ge_count) / (1.0 + len(self.valid_cache_scores))

    def should_admit_cache_hit(self, cosine_sim: float, risk_score: float) -> Tuple[bool, float, float]:
        """Admit iff s_cache <= tau_cache_t AND conformal p-value > alpha_cache_target."""
        s = self.cache_nonconformity(cosine_sim, risk_score)
        pval = self.cache_conformal_pvalue(s)
        admitted = (s <= self.tau_cache_t) and (pval > self.alpha_cache_target)
        return admitted, s, pval

    def update_cache_audit(self, score: float, audited: bool, is_invalid: bool) -> float:
        """Horvitz-Thompson inverse-propensity weighted online threshold update."""
        if audited and not is_invalid:
            self.valid_cache_scores.append(score)
        ipw_loss = (1.0 / self.p_audit) if (audited and is_invalid) else 0.0
        self.tau_cache_t = float(
            np.clip(
                self.tau_cache_t + self.eta_cache * (self.alpha_cache_target - ipw_loss),
                self.tau_min,
                self.tau_max,
            )
        )
        return self.tau_cache_t
