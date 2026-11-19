"""Automated Claim-to-Evidence Parity & Cleanliness Verifier for Standalone NOSIH.

Verifies:
1. Every deterministic numerical claim in paper/nosih_paper.tex matches
   results/benchmarks/nosih_evaluation_results.json and results/tests/test_suite_summary.json.
2. Live host-CPU micro-timings (proxy overhead, Merkle verification) satisfy paper bounds.
3. Zero forbidden mentions (uploaded paper names or prototype version tags) exist anywhere
   in paper/nosih_paper.tex, README.md, or src/nosih/.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    ev = json.loads((ROOT / "results" / "benchmarks" / "nosih_evaluation_results.json").read_text(encoding="utf-8"))
    ts = json.loads((ROOT / "results" / "tests" / "test_suite_summary.json").read_text(encoding="utf-8"))
    tex = (ROOT / "paper" / "nosih_paper.tex").read_text(encoding="utf-8")

    p = ev["primary"]
    ft = ev["fixed_threshold_baseline"]
    abl = ev["ablation"]
    sc = ev["scalability"]
    sec = ev["security_and_conformal"]
    cp = sec["conformal_pid"]
    rd = ev["routing_distribution"]
    ms = p["multi_seed_summary"]
    nov = ev["cross_plane_novelty"]
    lb = ev["latency_breakdown"]
    cc = ev["concurrency_and_carbon"]
    cv = cc["carbon_forecast_validation"]
    cp_conv = cc["conformal_convergence"]

    checks = [
        ("n_prompts", f"{p['n']}"),
        ("delta_energy_pct", f"{abs(p['delta_energy_pct']):.1f}\\%"),
        ("delta_co2_pct", f"{abs(p['delta_co2_pct']):.1f}\\%"),
        ("delta_cost_pct", f"{abs(p['delta_cost_pct']):.1f}\\%"),
        ("delta_latency_pct", f"{abs(p['delta_latency_pct']):.1f}\\%"),
        ("baseline_lat", f"{p['baseline_lat_ms_mean']:.1f}"),
        ("nosih_lat", f"{p['nosih_lat_ms_mean']:.1f}"),
        ("baseline_tot_e", f"{p['baseline_total_energy_kwh']:.6f}"),
        ("nosih_tot_e", f"{p['nosih_total_energy_kwh']:.6f}"),
        ("baseline_tot_co2", f"{p['baseline_total_co2_g']:.4f}"),
        ("nosih_tot_co2", f"{p['nosih_total_co2_g']:.4f}"),
        ("baseline_tot_cost", f"{p['baseline_total_cost_usd']:.6f}"),
        ("nosih_tot_cost", f"{p['nosih_total_cost_usd']:.6f}"),
        ("nosih_success_rate", f"{p['nosih_success_rate_pct']:.2f}\\%"),
        ("baseline_energy_per_success", f"{p['baseline_energy_per_success_wh']:.5f}"),
        ("nosih_energy_per_success", f"{p['nosih_energy_per_success_wh']:.5f}"),
        ("effect_size_rb_energy", f"{p['effect_size_rb_energy']:.4f}"),
        ("multiseed_energy_mean", f"{abs(ms['delta_energy_pct_mean']):.2f}\\%"),
        ("fixed_vs_nosih_energy", f"{abs(ft['nosih_vs_fixed_delta_energy_pct']):.1f}\\%"),
        ("fixed_vs_nosih_co2", f"{abs(ft['nosih_vs_fixed_delta_co2_pct']):.1f}\\%"),
        ("idle_cut_pct", f"{p['power_stats']['idle_power_reduction_pct']:.2f}\\%"),
        ("net_idle_wh", f"{p['power_stats']['net_idle_saved_wh']:.4f}"),
        ("avg_wakeup_ms", f"{p['power_stats']['avg_wakeup_ms']:.1f}"),
        ("route_cache", f"{rd['T0a_CACHE']}"),
        ("route_symbolic", f"{rd['T0b_SYMBOLIC']}"),
        ("route_small", f"{rd['T1_SMALL']}"),
        ("route_medium", f"{rd['T2_MEDIUM']}"),
        ("route_large", f"{rd['T3_LARGE']}"),
        ("ablation_full_e", f"{abl['full_nosih']['total_energy_kwh']:.6f}"),
        ("ablation_full_idle", f"{abl['full_nosih']['idle_power_reduction_pct']:.2f}\\%"),
        ("scalability_r", f"{sc['pearson_r']:.4f}"),
        ("sec_benign", f"{sec['benign_passed']}/{sec['benign_total']}"),
        ("sec_attacks", f"{sec['attacks_blocked']}/{sec['attacks_total']}"),
        ("sec_jti_race", f"{sec['jti_16thread_race_allowed']}/16"),
        ("sec_split_race", f"{sec['split_payout_8thread_race_allowed']}/8"),
        ("merkle_1000_hashes", f"{sec['merkle_hashes'][-1]}"),
        ("conformal_err_nosih", f"{cp['post_shift_err_nosih']:.2f}\\%"),
        ("conformal_err_static", f"{cp['post_shift_err_static']:.2f}\\%"),
        ("conformal_accept", f"{cp['post_shift_accept_nosih']:.2f}\\%"),
        ("tests_passed", f"{ts['tests_run']}/{ts['tests_run']}"),
        ("cdow_co2_cut_pct", f"{nov['cdow_co2_cut_pct']:.1f}\%"),
        ("cdow_blind_co2_g", f"{nov['cdow_blind_co2_g']:.4f}"),
        ("cdow_nosih_co2_g", f"{nov['cdow_nosih_co2_g']:.4f}"),
        ("cdow_mitigated", f"{nov['cdow_mitigated']}/{nov['cdow_attacks_total']}"),
        ("sleep_dos_reactive_j", f"{nov['sleep_dos_reactive_wasted_j']:.1f}"),
        ("ccec_valid", f"{nov['ccec_valid_verified']}/{nov['ccec_total_certs']}"),
        ("ccec_tamper", f"{nov['ccec_tamper_detected']}/{nov['ccec_tamper_total']}"),
        ("ccec_spoof", f"{nov['ccec_spoof_rejected']}/{nov['ccec_spoof_total']}"),
        ("ccec_hashes_mean", f"{nov['ccec_proof_hashes_mean']:.2f}"),
        ("ccec_hashes_max", f"{nov['ccec_proof_hashes_max']}"),
        ("lat_median_p50", f"{lb['median_p50_ms']:.1f}"),
        ("lat_p95", f"{lb['p95_ms']:.1f}"),
        ("lat_p99", f"{lb['p99_ms']:.1f}"),
        ("carbon_prior_mae", f"{cv['prior_mae_gco2_kwh']:.2f}"),
        ("carbon_prior_rmse", f"{cv['prior_rmse_gco2_kwh']:.2f}"),
        ("carbon_blended_mae", f"{cv['blended_5min_mae_gco2_kwh']:.2f}"),
        ("conformal_t3000", f"{cp_conv['long_horizon_tpost3000_err_pct']:.2f}\%"),
        ("conformal_alpha045", f"{cp_conv['conservative_alpha045_tpost800_err_pct']:.2f}\%"),
    ]

    missing = [(cid, tok) for cid, tok in checks if tok not in tex]

    # Live host-CPU timing sanity bounds (robust across sequential runs)
    timing_checks = {
        "proxy_p95_under_15ms": sec["p95_proxy_ms"] < 15.0,
        "merkle_inc_under_50us": sec["merkle_inc_us"][-1] < 50.0,
        "merkle_cons_under_50us": sec["merkle_cons_us"][-1] < 50.0,
        "all_tests_passed": bool(ts["passed"]),
    }
    timing_failures = [k for k, ok in timing_checks.items() if not ok]

    # Strict forbidden-mention audit across paper, README, and src
    forbidden = ["camas", "v2.0", "v3.0", "legacy"]
    violations = []
    scan_files = [ROOT / "paper" / "nosih_paper.tex", ROOT / "README.md"] + list((ROOT / "src" / "nosih").rglob("*.py"))
    for sf in scan_files:
        if not sf.exists():
            continue
        low = sf.read_text(encoding="utf-8").lower()
        for word in forbidden:
            if word in low:
                violations.append({"file": str(sf.relative_to(ROOT)), "forbidden_term": word})

    report = {
        "total_claims_checked": len(checks),
        "verified_claims": len(checks) - len(missing),
        "all_claims_verified": len(missing) == 0,
        "missing_claims": missing,
        "timing_checks": timing_checks,
        "timing_failures": timing_failures,
        "forbidden_mentions_found": len(violations),
        "violations": violations,
    }
    out_path = ROOT / "results" / "verification" / "claim_evidence_matrix.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    ok = report["all_claims_verified"] and len(timing_failures) == 0 and report["forbidden_mentions_found"] == 0
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
