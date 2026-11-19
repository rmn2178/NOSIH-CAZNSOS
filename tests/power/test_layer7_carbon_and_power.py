"""Layer 7: Dynamic Diurnal Carbon Forecaster, PCS-PMC Hysteresis Power Control & Energy Accounting."""
import unittest

from nosih.plane3_execution.power_carbon import (
    DEFAULT_TIER_PROFILES,
    DiurnalCarbonForecaster,
    PowerState,
    PredictivePowerController,
    TransparentEnergyAccountant,
)


class TestLayer7CarbonAndPower(unittest.TestCase):
    def test_diurnal_carbon_forecaster_bounds_and_solar_vs_peak(self):
        fc = DiurnalCarbonForecaster()
        c_midday = fc.deterministic_intensity(13.0)
        c_evening = fc.deterministic_intensity(19.5)
        self.assertGreaterEqual(c_midday, 180.0)
        self.assertLessEqual(c_evening, 520.0)
        self.assertLess(c_midday, 220.0)
        self.assertGreater(c_evening, 480.0)
        fresh = fc.step_intensity(13.0, live_signal=450.0, live_age_s=0.0)
        stale = fc.step_intensity(13.0, live_signal=450.0, live_age_s=3600.0)
        self.assertGreater(fresh, stale)

    def test_pcs_pmc_multistate_transitions_and_thrash_damping(self):
        prof = DEFAULT_TIER_PROFILES["T3_LARGE"]
        pmc = PredictivePowerController(prof, thrash_limit=2)
        self.assertEqual(pmc.state, PowerState.ACTIVE)

        pmc.evaluate_idle_transition(10.0)
        self.assertEqual(pmc.state, PowerState.WARM_STANDBY)
        self.assertEqual(pmc.warm_events, 1)

        pmc.evaluate_idle_transition(60.0)
        self.assertEqual(pmc.state, PowerState.DEEP_SLEEP)
        self.assertEqual(pmc.sleep_events, 1)
        self.assertAlmostEqual(pmc.current_idle_power_w(), 2.5, places=2)

        w_lat, w_j = pmc.on_request_arrival(65.0)
        self.assertEqual(pmc.state, PowerState.ACTIVE)
        self.assertGreater(w_lat, 0.0)
        self.assertGreater(w_j, 0.0)

        init_eta = pmc.eta_down
        for step in range(3):
            base_t = 100.0 + step * 30.0
            pmc.evaluate_idle_transition(base_t + 10.0)
            pmc.on_request_arrival(base_t + 12.0)
        self.assertGreater(pmc.eta_down, init_eta)
        self.assertGreaterEqual(pmc.thrash_damp_events, 1)

    def test_transparent_energy_accountant_symbolic_vs_large_neural(self):
        acct = TransparentEnergyAccountant()
        sym = acct.compute_query_footprint(DEFAULT_TIER_PROFILES["T0b_SYMBOLIC"], 0.004, 400.0, tokens_total=0)
        lrg = acct.compute_query_footprint(DEFAULT_TIER_PROFILES["T3_LARGE"], 2.0, 400.0, tokens_total=400)
        self.assertEqual(sym["accounting_mode"], "HYBRID_CPU_TDP")
        self.assertLess(sym["energy_kwh"] * 1000.0, lrg["energy_kwh"])
        self.assertLess(sym["co2_g"] * 1000.0, lrg["co2_g"])


if __name__ == "__main__":
    unittest.main()
