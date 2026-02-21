#!/usr/bin/env python3
# Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""Statistical analysis of repeated cross-machine benchmarks."""

import json
import sys
from pathlib import Path
import numpy as np
from scipy import stats


def load_results(results_dir):
    """Load all result files from iterations."""
    insecure_latencies = []
    secure_latencies = []

    results_path = Path(results_dir)

    for iter_dir in sorted(results_path.glob("iter*")):
        # Load insecure inlet result
        insecure_files = list(iter_dir.glob("inlet_insecure_*.json"))
        if insecure_files:
            with open(insecure_files[0]) as f:
                data = json.load(f)
                lat = data.get("results", {}).get("latency_mean_ms")
                if lat:
                    insecure_latencies.append(lat)

        # Load secure inlet result
        secure_files = list(iter_dir.glob("inlet_secure_*.json"))
        if secure_files:
            with open(secure_files[0]) as f:
                data = json.load(f)
                lat = data.get("results", {}).get("latency_mean_ms")
                if lat:
                    secure_latencies.append(lat)

    return np.array(insecure_latencies), np.array(secure_latencies)


def analyze(insecure, secure):
    """Perform statistical analysis."""
    print("=" * 60)
    print("STATISTICAL ANALYSIS: Encryption Overhead")
    print("=" * 60)
    print(f"\nSample size: n={len(insecure)} iterations")
    print()

    print("INSECURE (no encryption):")
    print(f"  Mean:    {insecure.mean():.3f} ms")
    print(f"  Std Dev: {insecure.std(ddof=1):.3f} ms")
    print(f"  SEM:     {stats.sem(insecure):.3f} ms")
    print(f"  Range:   {insecure.min():.3f} - {insecure.max():.3f} ms")
    print(f"  Values:  {insecure.tolist()}")
    print()

    print("SECURE (with encryption):")
    print(f"  Mean:    {secure.mean():.3f} ms")
    print(f"  Std Dev: {secure.std(ddof=1):.3f} ms")
    print(f"  SEM:     {stats.sem(secure):.3f} ms")
    print(f"  Range:   {secure.min():.3f} - {secure.max():.3f} ms")
    print(f"  Values:  {secure.tolist()}")
    print()

    # Calculate overhead
    overhead_ms = secure.mean() - insecure.mean()
    overhead_pct = (overhead_ms / insecure.mean()) * 100

    print("ENCRYPTION OVERHEAD:")
    print(f"  Absolute: {overhead_ms:.3f} ms")
    print(f"  Relative: {overhead_pct:.2f}%")
    print()

    # Paired t-test
    t_stat, p_value = stats.ttest_rel(secure, insecure)
    print("PAIRED T-TEST:")
    print(f"  t-statistic: {t_stat:.4f}")
    print(f"  p-value:     {p_value:.4f}")

    alpha = 0.05
    if p_value < alpha:
        print(f"  Result: SIGNIFICANT difference (p < {alpha})")
        if overhead_ms > 0:
            print(f"          Encryption adds ~{overhead_ms:.2f} ms latency")
        else:
            print(f"          Secure is {abs(overhead_ms):.2f} ms FASTER (unexpected!)")
    else:
        print(f"  Result: NO significant difference (p >= {alpha})")
        print("          Encryption overhead is negligible")
    print()

    # 95% confidence interval
    diff = secure - insecure
    ci = stats.t.interval(0.95, len(diff) - 1, loc=diff.mean(), scale=stats.sem(diff))
    print("95% CONFIDENCE INTERVAL for overhead:")
    print(f"  [{ci[0]:.3f}, {ci[1]:.3f}] ms")
    if ci[0] <= 0 <= ci[1]:
        print("  Note: Includes zero - overhead may be negligible")
    print()

    # Effect size (Cohen's d)
    pooled_std = np.sqrt((insecure.std(ddof=1) ** 2 + secure.std(ddof=1) ** 2) / 2)
    cohens_d = (secure.mean() - insecure.mean()) / pooled_std
    print(f"EFFECT SIZE (Cohen's d): {cohens_d:.3f}")
    if abs(cohens_d) < 0.2:
        print("  Negligible effect")
    elif abs(cohens_d) < 0.5:
        print("  Small effect")
    elif abs(cohens_d) < 0.8:
        print("  Medium effect")
    else:
        print("  Large effect")
    print()

    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python statistical_analysis.py <results_directory>")
        sys.exit(1)

    results_dir = sys.argv[1]
    insecure, secure = load_results(results_dir)

    if len(insecure) == 0 or len(secure) == 0:
        print("Error: No results found!")
        sys.exit(1)

    analyze(insecure, secure)
