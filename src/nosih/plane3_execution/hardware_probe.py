"""Honest Host Hardware & Sensor Inventory Probe for NOSIH.

Physically inspects CPU, OS, Python version, and hardware power-sensor availability
(Intel RAPL sysfs, NVIDIA NVML). Never fabricates hardware power readings.
"""
from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import Any, Dict


def probe_hardware_environment() -> Dict[str, Any]:
    rapl_path = Path("/sys/class/powercap/intel-rapl")
    rapl_available = rapl_path.exists() and any(rapl_path.glob("intel-rapl:*"))

    nvml_available = False
    gpu_name = None
    try:
        import pynvml  # type: ignore
        pynvml.nvmlInit()
        if pynvml.nvmlDeviceGetCount() > 0:
            h = pynvml.nvmlDeviceGetHandleByIndex(0)
            gpu_name = pynvml.nvmlDeviceGetName(h)
            nvml_available = True
        pynvml.nvmlShutdown()
    except Exception:
        nvml_available = False

    return {
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python_version": sys.version.split()[0],
        "cpu_count_logical": os.cpu_count() or 1,
        "rapl_available": rapl_available,
        "nvml_available": nvml_available,
        "gpu_detected": gpu_name,
        "energy_accounting_mode": "MEASURED_HW" if (rapl_available and nvml_available) else "HYBRID_CPU_TDP",
        "neural_execution_mode": "CALIBRATED_TRACE_SIM",
    }
