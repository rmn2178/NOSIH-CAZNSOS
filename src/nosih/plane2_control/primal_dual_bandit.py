"""DPD-LinUCB: Discounted Primal-Dual Safe Contextual Bandit Router (Pure NumPy).

Implements:
- Exponentially discounted ridge regression (Russac et al., NeurIPS 2019 D-LinUCB)
  for non-stationary drift adaptation
- Projected online Lagrangian dual price updates (Agrawal & Devanur, NeurIPS 2016 LinCBwK)
  for hard/average latency & monetary/energy knapsack constraints
- Includes StationaryLinUCBBaseline (baseline equivalent) for rigorous head-to-head benchmarking
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple

import numpy as np


class DPDLinUCBRouter:
    """Discounted Primal-Dual Safe Contextual Bandit (DPD-LinUCB)."""

    def __init__(
        self,
        num_arms: int = 6,
        dim: int = 10,
        gamma: float = 0.992,
        lambda_reg: float = 1.0,
        alpha_scale: float = 0.65,
        budgets: Tuple[float, float] = (0.35, 0.35),  # normalized (latency_budget, cost_budget)
        dual_lr: float = 0.08,
        dual_max: float = 5.0,
    ) -> None:
        self.K = num_arms
        self.d = dim
        self.gamma = gamma
        self.lambda_reg = lambda_reg
        self.alpha_scale = alpha_scale
        self.budgets = np.array(budgets, dtype=np.float64)
        self.M = len(self.budgets)
        self.dual_lr = dual_lr
        self.dual_max = dual_max

        # Discounted precision V_a and doubly-discounted covariance V_tilde_a
        self.V = np.array([lambda_reg * np.eye(dim, dtype=np.float64) for _ in range(num_arms)])
        self.V_tilde = np.array([lambda_reg * np.eye(dim, dtype=np.float64) for _ in range(num_arms)])
        self.V_inv = np.array([(1.0 / lambda_reg) * np.eye(dim, dtype=np.float64) for _ in range(num_arms)])

        # Sufficient statistics for reward and M resource costs
        self.u_r = np.zeros((num_arms, dim), dtype=np.float64)
        self.u_c = np.zeros((num_arms, self.M, dim), dtype=np.float64)

        # Cached ridge estimators (updated on update(), making select_arm ultra-fast!)
        self.theta = np.zeros((num_arms, dim), dtype=np.float64)
        self.phi = np.zeros((num_arms, self.M, dim), dtype=np.float64)

        # Projected Lagrangian dual prices mu_t >= 0
        self.mu = np.zeros(self.M, dtype=np.float64)
        self.t = 0

    def _beta_t(self) -> float:
        # D-LinUCB confidence width factor
        eff_n = (1.0 - (self.gamma ** (2 * max(1, self.t)))) / max(1e-9, 1.0 - self.gamma ** 2)
        return self.alpha_scale * math.sqrt(
            2.0 * math.log(10.0) + self.d * math.log(1.0 + (4.0 * eff_n) / (self.lambda_reg * self.d))
        )

    def predict_costs(self, x: np.ndarray, feasible_arms: List[int]) -> Dict[int, np.ndarray]:
        return {a: np.clip(self.phi[a] @ x, 0.0, 1.0) for a in feasible_arms}

    def select_arm(
        self,
        x: np.ndarray,
        feasible_arms: List[int],
        explore: bool = True,
        hard_latency_cap: Optional[float] = None,
    ) -> Tuple[int, Dict[str, float]]:
        """Select arm maximizing UCB_r(x) - sum_m mu_m * (LCB_c^m(x) - b_m)."""
        beta = self._beta_t() if explore else 0.0
        candidate_arms = list(feasible_arms)

        # Optional per-round hard latency safety filter (retains fastest arm to satisfy Slater's condition)
        if hard_latency_cap is not None and len(candidate_arms) > 1:
            safe = []
            for a in candidate_arms:
                est_lat = float(np.clip(self.phi[a, 0] @ x, 0.0, 1.0))
                if est_lat <= hard_latency_cap:
                    safe.append(a)
            if safe:
                candidate_arms = safe

        best_arm = candidate_arms[0]
        best_score = -1e18
        best_meta: Dict[str, float] = {}

        for a in candidate_arms:
            mean_r = float(self.theta[a] @ x)
            if explore:
                v_inv_x = self.V_inv[a] @ x
                var = float(max(0.0, v_inv_x @ (self.V_tilde[a] @ v_inv_x)))
                width = beta * math.sqrt(var)
            else:
                width = 0.0

            ucb_r = mean_r + width
            mean_c = self.phi[a] @ x
            lcb_c = np.clip(mean_c - 0.5 * width, 0.0, 1.0)
            lagrangian = ucb_r - float(self.mu @ (lcb_c - self.budgets))

            if lagrangian > best_score:
                best_score = lagrangian
                best_arm = a
                best_meta = {
                    "ucb_r": ucb_r,
                    "mean_r": mean_r,
                    "width": width,
                    "pred_lat_norm": float(np.clip(mean_c[0], 0.0, 1.0)),
                    "pred_cost_norm": float(np.clip(mean_c[1], 0.0, 1.0)) if self.M > 1 else 0.0,
                    "lagrangian": lagrangian,
                    "mu_lat": float(self.mu[0]),
                    "mu_cost": float(self.mu[1]) if self.M > 1 else 0.0,
                }

        return best_arm, best_meta

    def update(self, arm_idx: int, x: np.ndarray, reward: float, costs: Tuple[float, ...]) -> None:
        """Online O(d^2) discounted ridge update + projected dual price ascent."""
        self.t += 1
        g = self.gamma
        g2 = g * g
        eye = np.eye(self.d, dtype=np.float64)

        # Exponentially discount ALL arms so unobserved arms also decay under drift
        self.V = g * self.V + (1.0 - g) * self.lambda_reg * eye
        self.V_tilde = g2 * self.V_tilde + (1.0 - g2) * self.lambda_reg * eye
        self.u_r *= g
        self.u_c *= g

        # Rank-1 update for pulled arm
        outer = np.outer(x, x)
        self.V[arm_idx] += outer
        self.V_tilde[arm_idx] += outer
        self.u_r[arm_idx] += reward * x
        c_vec = np.clip(np.array(costs, dtype=np.float64), 0.0, 1.0)
        for m in range(self.M):
            self.u_c[arm_idx, m] += c_vec[m] * x

        # Refresh V_inv and ridge estimators for pulled arm (fast O(d^3) for d=10 is ~5 us)
        self.V_inv[arm_idx] = np.linalg.inv(self.V[arm_idx])
        self.theta[arm_idx] = self.V_inv[arm_idx] @ self.u_r[arm_idx]
        for m in range(self.M):
            self.phi[arm_idx, m] = self.V_inv[arm_idx] @ self.u_c[arm_idx, m]

        # Projected dual ascent: mu_{t+1} = clip(mu_t + eta * (c_t - b), 0, mu_max)
        self.mu = np.clip(self.mu + self.dual_lr * (c_vec - self.budgets), 0.0, self.dual_max)


class StationaryLinUCBBaseline:
    """Stationary scalarized LinUCB (prior orchestrators baseline) for head-to-head comparisons."""

    def __init__(self, num_arms: int = 6, dim: int = 10, lambda_reg: float = 1.0, alpha: float = 0.65) -> None:
        self.K = num_arms
        self.d = dim
        self.alpha = alpha
        self.A_inv = np.array([(1.0 / lambda_reg) * np.eye(dim, dtype=np.float64) for _ in range(num_arms)])
        self.b = np.zeros((num_arms, dim), dtype=np.float64)

    def select_arm(self, x: np.ndarray, feasible_arms: List[int], explore: bool = True) -> int:
        best_a = feasible_arms[0]
        best_score = -1e18
        for a in feasible_arms:
            theta = self.A_inv[a] @ self.b[a]
            score = float(theta @ x)
            if explore:
                score += self.alpha * math.sqrt(max(0.0, float(x @ (self.A_inv[a] @ x))))
            if score > best_score:
                best_score = score
                best_a = a
        return best_a

    def update(self, arm_idx: int, x: np.ndarray, scalar_reward: float) -> None:
        # Sherman-Morrison O(d^2) without forgetting
        a_inv_x = self.A_inv[arm_idx] @ x
        denom = 1.0 + float(x @ a_inv_x)
        self.A_inv[arm_idx] -= np.outer(a_inv_x, a_inv_x) / denom
        self.b[arm_idx] += scalar_reward * x
