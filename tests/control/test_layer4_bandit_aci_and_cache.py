"""Layer 4: DPD-LinUCB Drift & Knapsack, Dual-Channel Online ACI Coverage & PS-RCSC Cache Tests."""
import unittest

import numpy as np

from nosih.plane1_security.postw_v3 import IntegrityLevel
from nosih.plane2_control.online_conformal import DualChannelACIGate
from nosih.plane2_control.primal_dual_bandit import DPDLinUCBRouter, StationaryLinUCBBaseline
from nosih.plane2_control.profiler_v3 import ComplexityProfiler10D
from nosih.plane2_control.provenance_cache import ProvenanceScope, ProvenanceScopedSemanticCache


class TestLayer4BanditACIAndCache(unittest.TestCase):
    def test_dpd_linucb_adapts_to_nonstationary_drift_and_beats_stationary(self):
        rng = np.random.default_rng(7)
        dpd = DPDLinUCBRouter(num_arms=2, dim=4, gamma=0.96, budgets=(0.60, 0.60), dual_lr=0.05)
        stat = StationaryLinUCBBaseline(num_arms=2, dim=4)

        dpd_post_rewards = []
        stat_post_rewards = []
        for t in range(1200):
            x = rng.normal(0.0, 0.5, size=4)
            x[0] = 1.0
            # Phase 1 (t < 600): Arm 0 is high accuracy (0.95), Arm 1 is low (0.45)
            # Phase 2 (t >= 600): Abrupt drift! Arm 0 drops to 0.35, Arm 1 rises to 0.95
            probs = (0.95, 0.45) if t < 600 else (0.35, 0.95)
            a_dpd, _ = dpd.select_arm(x, [0, 1], explore=True)
            r_dpd = float(rng.random() < probs[a_dpd])
            dpd.update(a_dpd, x, r_dpd, (0.2, 0.2))

            a_stat = stat.select_arm(x, [0, 1], explore=True)
            r_stat = float(rng.random() < probs[a_stat])
            stat.update(a_stat, x, r_stat)

            if t >= 750:
                dpd_post_rewards.append(r_dpd)
                stat_post_rewards.append(r_stat)

        self.assertGreater(np.mean(dpd_post_rewards), np.mean(stat_post_rewards) + 0.15)
        self.assertGreater(np.mean(dpd_post_rewards), 0.85)

    def test_dpd_linucb_enforces_latency_and_cost_knapsack_budget(self):
        rng = np.random.default_rng(11)
        # Budget: mean normalized latency <= 0.30, cost <= 0.30
        dpd = DPDLinUCBRouter(num_arms=2, dim=4, gamma=0.985, budgets=(0.30, 0.30), dual_lr=0.15, dual_max=8.0)
        lat_hist = []
        for t in range(1000):
            x = np.array([1.0, 0.5, 0.2, 0.1])
            # Arm 0: cheap & fast (acc=0.82, lat=0.10, cost=0.10)
            # Arm 1: expensive & slow (acc=0.95, lat=0.90, cost=0.90)
            a, _ = dpd.select_arm(x, [0, 1], explore=True)
            if a == 0:
                r, lat, cost = float(rng.random() < 0.82), 0.10, 0.10
            else:
                r, lat, cost = float(rng.random() < 0.95), 0.90, 0.90
            dpd.update(a, x, r, (lat, cost))
            if t >= 300:
                lat_hist.append(lat)
        # Empirical mean latency stays tightly bounded near 0.30 budget!
        self.assertLessEqual(float(np.mean(lat_hist)), 0.35)

    def test_dual_channel_aci_controls_risk_under_distribution_shift(self):
        rng = np.random.default_rng(21)
        aci = DualChannelACIGate(route_target_alpha=0.05, route_lr=0.05, route_ki=0.02, window_size=150)
        static_tau = 0.25  # baseline static split conformal threshold

        aci_errs = []
        static_errs = []
        for t in range(1200):
            if t < 400:
                # Pre-shift: well-calibrated confidence
                correct = bool(rng.random() < 0.95)
                conf = float(rng.uniform(0.80, 0.99) if correct else rng.uniform(0.20, 0.65))
            else:
                # Post-shift: overconfident wrong predictions (confidence 0.78-0.90 even when wrong)
                correct = bool(rng.random() < 0.70)
                conf = float(rng.uniform(0.90, 0.99) if correct else rng.uniform(0.76, 0.89))

            acc_aci, _, _ = aci.should_accept_route(conf)
            aci.update_route(conf, acc_aci, correct)

            acc_stat = (1.0 - conf) <= static_tau
            if t >= 600:
                aci_errs.append(1.0 if (acc_aci and not correct) else 0.0)
                static_errs.append(1.0 if (acc_stat and not correct) else 0.0)

        # Static split conformal blows up (>20% error), while Online ACI holds near target 0.05!
        self.assertGreater(float(np.mean(static_errs)), 0.20)
        self.assertLessEqual(float(np.mean(aci_errs)), 0.085)

    def test_ps_rcsc_provenance_scoping_polarity_and_cost_aware_bypass(self):
        aci = DualChannelACIGate()
        cache = ProvenanceScopedSemanticCache(aci_gate=aci, cache_overhead_ms=0.12)
        scope_t1 = ProvenanceScope("tenant_A", "v3", "m1", "p1", IntegrityLevel.USER_DIRECT)
        scope_t2 = ProvenanceScope("tenant_B", "v3", "m1", "p1", IntegrityLevel.USER_DIRECT)
        scope_untrusted = ProvenanceScope("tenant_A", "v3", "m1", "p1", IntegrityLevel.UNTRUSTED)

        # Store verified answer under tenant_A
        stored = cache.store("What is the SLA uptime for cloud tier 1?", scope_t1, "99.95%", 0.98, conformal_accepted=True)
        self.assertTrue(stored)

        # Untrusted origin NEVER allowed to store or read
        self.assertFalse(cache.store("evil prompt", scope_untrusted, "POISON", 0.99, conformal_accepted=True))
        hit_u, _, meta_u = cache.lookup("What is the SLA uptime for cloud tier 1?", scope_untrusted, 0.1, 50.0)
        self.assertFalse(hit_u)
        self.assertEqual(meta_u["cache_status"], "bypass_untrusted_origin")

        # Cross-tenant isolation (tenant_B cannot see tenant_A entry)
        hit_t2, _, _ = cache.lookup("What is the SLA uptime for cloud tier 1?", scope_t2, 0.1, 50.0)
        self.assertFalse(hit_t2)

        # Polarity / negation guard prevents false hit on negated prompt
        hit_neg, _, _ = cache.lookup("What is NOT the SLA uptime for cloud tier 1?", scope_t1, 0.1, 50.0)
        self.assertFalse(hit_neg)

        # Cost-aware bypass skips semantic scan for sub-ms deterministic queries
        hit_fast, _, meta_fast = cache.lookup("What is the SLA uptime for cloud tier 1 today?", scope_t1, 0.1, 0.05)
        self.assertFalse(hit_fast)
        self.assertEqual(meta_fast["cache_status"], "cost_aware_bypass")

        # Exact match hit works for same scope
        hit_ok, ans_ok, _ = cache.lookup("What is the SLA uptime for cloud tier 1?", scope_t1, 0.1, 50.0)
        self.assertTrue(hit_ok)
        self.assertEqual(ans_ok, "99.95%")

    def test_profiler_v3_anti_filler_spoofing(self):
        prof = ComplexityProfiler10D()
        # Unique filler stuffing trying to inflate risk_score with 30 unique words + 1 risk keyword
        filler_prompt = " ".join(f"uniqueword{i}" for i in range(30)) + " payout"
        p = prof.profile(filler_prompt)
        self.assertTrue(p.spoof_filtered)
        self.assertLess(p.risk_score, 0.30)


if __name__ == "__main__":
    unittest.main()
