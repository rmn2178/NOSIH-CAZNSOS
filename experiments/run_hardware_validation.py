"""Physical GPU/CPU Hardware Validation Runner for NOSIH (GPU-Host Deployment Script).

Use this script on a physical GPU machine with NVIDIA NVML, Intel/AMD RAPL,
local Ollama/vLLM inference endpoints, and optional Electricity Maps / WattTime API keys
to replace CALIBRATED_TRACE_SIM / HYBRID_CPU_TDP profiles with physically measured
wattmeter telemetry (accounting_mode='HARDWARE_NVML_RAPL', execution_mode='LIVE_GPU_INFERENCE').

Usage:
  python3 experiments/run_hardware_validation.py \\
    --ollama-url http://localhost:11434 \\
    --small-model qwen2.5:3b \\
    --medium-model llama3.1:8b \\
    --large-model qwen2.5:32b \\
    --carbon-zone IN-SO
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from nosih.plane3_execution.hardware_probe import probe_hardware_environment


def read_rapl_uj() -> Optional[int]:
    p = Path("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj")
    if p.exists():
        try:
            return int(p.read_text(encoding="utf-8").strip())
        except Exception:
            return None
    return None


def sample_nvml_power_w() -> Optional[float]:
    try:
        import pynvml  # type: ignore

        pynvml.nvmlInit()
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        mw = pynvml.nvmlDeviceGetPowerUsage(handle)
        pynvml.nvmlShutdown()
        return mw / 1000.0
    except Exception:
        return None


def query_ollama(url: str, model: str, prompt: str, timeout_s: float = 30.0) -> Dict[str, Any]:
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(f"{url.rstrip('/')}/api/generate", data=payload, headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    lat_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "response": body.get("response", ""),
        "latency_ms": round(lat_ms, 2),
        "eval_count": body.get("eval_count", 0),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="NOSIH Physical GPU/CPU Hardware Validation Runner")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--small-model", default="qwen2.5:3b")
    ap.add_argument("--medium-model", default="llama3.1:8b")
    ap.add_argument("--large-model", default="qwen2.5:32b")
    ap.add_argument("--carbon-zone", default="IN-SO")
    ap.add_argument("--out", default=str(ROOT / "results" / "benchmarks" / "hardware_validation_report.json"))
    args = ap.parse_args()

    hw = probe_hardware_environment()
    rapl_ok = read_rapl_uj() is not None
    nvml_w = sample_nvml_power_w()

    report: Dict[str, Any] = {
        "hardware_probe": hw,
        "rapl_energy_counter_readable": rapl_ok,
        "nvml_live_power_w": nvml_w,
        "models_configured": {
            "T1_SMALL": args.small_model,
            "T2_MEDIUM": args.medium_model,
            "T3_LARGE": args.large_model,
        },
        "carbon_zone": args.carbon_zone,
    }

    if not rapl_ok or nvml_w is None:
        report["status"] = "HARDWARE_SENSORS_UNAVAILABLE"
        report["note"] = (
            "Physical NVML GPU and/or RAPL CPU energy counters are not accessible in this environment. "
            "Run this script on a bare-metal or GPU-passthrough Linux host with Ollama/vLLM active "
            "to collect HARDWARE_NVML_RAPL measurements."
        )
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 0

    # Live GPU measurement loop when physical sensors are present
    samples = []
    prompts = [
        ("T1_SMALL", args.small_model, "Summarize GSTR-2B input tax credit reconciliation in one sentence."),
        ("T2_MEDIUM", args.medium_model, "Compare Raft consensus and sharded LSM storage trade-offs concisely."),
        ("T3_LARGE", args.large_model, "Outline a zero-trust capability architecture for multi-agent tool execution."),
    ]
    for tier, model, prompt in prompts:
        e0 = read_rapl_uj()
        p0 = sample_nvml_power_w() or 0.0
        res = query_ollama(args.ollama_url, model, prompt)
        p1 = sample_nvml_power_w() or p0
        e1 = read_rapl_uj()
        cpu_j = ((e1 - e0) / 1e6) if (e0 is not None and e1 is not None and e1 >= e0) else None
        gpu_j = 0.5 * (p0 + p1) * (res["latency_ms"] / 1000.0)
        samples.append({
            "tier": tier,
            "model": model,
            "latency_ms": res["latency_ms"],
            "cpu_rapl_j": round(cpu_j, 4) if cpu_j is not None else None,
            "gpu_nvml_j": round(gpu_j, 4),
            "accounting_mode": "HARDWARE_NVML_RAPL",
            "execution_mode": "LIVE_GPU_INFERENCE",
        })

    report["status"] = "COMPLETED_PHYSICAL_HARDWARE_RUN"
    report["samples"] = samples
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
