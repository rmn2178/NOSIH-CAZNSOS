"""Checklist Power, Carbon Forecasting & Signal Validation Tests."""
import math
import unittest

import numpy as np

from nosih.plane3_execution.power_carbon import (
    DEFAULT_TIER_PROFILES,
    DiurnalCarbonForecaster,
    PowerState,
    PredictivePowerController,
)
from nosih.plane3_execution.tools import SignalFFTSobelExtractor


class TestCarbonForecastHysteresisAndSignal(unittest.TestCase):
    def test_diurnal_carbon_multiday_mae_and_stale_fallback(self):
        fc = DiurnalCarbonForecaster()
        rng = np.random.default_rng(42)
        errs = []
        for day in range(3):
            for h in range(24):
                true_c = fc.deterministic_intensity(float(h)) + float(rng.normal(0.0, 8.0))
                pred_c = fc.step_intensity(float(h), dt_hours=1.0, z_noise=0.0, live_signal=None)
                errs.append(abs(pred_c - true_c))
        mae = float(np.mean(errs))
        rmse = float(math.sqrt(np.mean([e * e for e in errs])))
        self.assertLess(mae, 15.0)
        self.assertLess(rmse, 20.0)

        # Delayed/stale live telemetry decays smoothly back toward diurnal prior
        c_fresh = fc.step_intensity(13.0, live_signal=480.0, live_age_s=10.0)
        c_mid = fc.step_intensity(13.0, live_signal=480.0, live_age_s=900.0)
        c_stale = fc.step_intensity(13.0, live_signal=480.0, live_age_s=7200.0)
        self.assertGreater(c_fresh, c_mid)
        self.assertGreater(c_mid, c_stale)

    def test_pcs_pmc_ewma_hysteresis_reduces_wakeups_vs_naive_fixed_timeout(self):
        prof = DEFAULT_TIER_PROFILES["T3_LARGE"]
        pmc = PredictivePowerController(prof, thrash_limit=2)
        # Bursty traffic: 12s gaps (just above naive 10s fixed timeout!)
        naive_wakeups = 0
        now_s = 0.0
        for _ in range(15):
            pmc.on_request_arrival(now_s)
            now_s += 12.0
            if 12.0 > 10.0:
                naive_wakeups += 1
            pmc.evaluate_idle_transition(now_s)
        # PCS-PMC avoids deep-sleep thrashing compared to naive 10s fixed timeout
        self.assertEqual(pmc.sleep_events, 0)
        self.assertLess(pmc.wakeup_events, naive_wakeups)

    def test_fft_and_sobel_analytical_ground_truth(self):
        ext = SignalFFTSobelExtractor()
        # Analytical 1024 Hz sine wave at 8192 Hz sample rate
        t = np.arange(1024) / 8192.0
        wf = np.sin(2.0 * np.pi * 1024.0 * t).astype(np.float32)
        # Analytical 64x64 bright square [16:48, 16:48]
        img = np.zeros((64, 64), dtype=np.float32)
        img[16:48, 16:48] = 1.0
        out = ext.extract(waveform=wf, image=img, sample_rate_hz=8192.0)
        self.assertAlmostEqual(out["dominant_freq_hz"], 1024.0, delta=0.5)
        self.assertGreater(out["snr_db"], 30.0)
        x0, y0, x1, y1 = out["bbox"]
        self.assertTrue(14 <= x0 <= 17 and 14 <= y0 <= 17 and 46 <= x1 <= 49 and 46 <= y1 <= 49)


if __name__ == "__main__":
    unittest.main()
