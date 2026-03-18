# Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""Shared utilities for ESP32 benchmark scripts."""

import json
import platform
from pathlib import Path

import numpy as np


def get_system_info():
    """Collect system information for benchmark records."""
    info = {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "machine": platform.machine(),
        "hostname": platform.node(),
    }
    try:
        if platform.system() == "Darwin":
            import subprocess
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True,
            )
            info["cpu_model"] = result.stdout.strip()
        elif platform.system() == "Linux":
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "model name" in line:
                        info["cpu_model"] = line.split(":")[1].strip()
                        break
    except Exception:
        pass
    return info


def compute_timing_stats(values, prefix):
    """Compute timing statistics from a list of microsecond values.

    Returns a dict with keys like {prefix}_mean_us, {prefix}_std_us, etc.
    """
    arr = np.array(values) if values else np.array([0])
    return {
        f"{prefix}_mean_us": round(float(np.mean(arr)), 2),
        f"{prefix}_std_us": round(float(np.std(arr)), 2),
        f"{prefix}_median_us": round(float(np.median(arr)), 2),
        f"{prefix}_min_us": round(float(np.min(arr)), 2),
        f"{prefix}_max_us": round(float(np.max(arr)), 2),
        f"{prefix}_p95_us": round(float(np.percentile(arr, 95)), 2),
        f"{prefix}_p99_us": round(float(np.percentile(arr, 99)), 2),
    }


def save_results(data, output_file):
    """Save benchmark results to a JSON file."""
    if not output_file:
        return
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Results saved to {output_file}")
