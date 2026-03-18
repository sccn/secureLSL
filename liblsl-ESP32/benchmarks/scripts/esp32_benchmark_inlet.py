#!/usr/bin/env python3
# Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""ESP32 Benchmark - Desktop Inlet.

Receives samples from an ESP32 LSL outlet and measures:
- Pull timing (time per pull_sample call, includes blocking wait)
- Inter-sample jitter (variability of arrival intervals)
- Throughput (actual vs nominal sample rate)
- Packet loss (samples missed)

Does NOT compute absolute cross-machine latency (clocks unsynchronized).
Records embedded timestamps from channel 0 for drift analysis.

Usage:
    uv run python esp32_benchmark_inlet.py --duration 60
    uv run python esp32_benchmark_inlet.py --name ESP32Bench --duration 60 -o results/test.json
"""

import argparse
import time
from datetime import datetime

import numpy as np
import pylsl

from bench_utils import compute_timing_stats, get_system_info, save_results


def run_benchmark(stream_name, duration, output_file):
    """Run the desktop inlet benchmark against an ESP32 outlet."""
    print(f"Resolving stream '{stream_name}'...")
    try:
        streams = pylsl.resolve_byprop("name", stream_name, timeout=30)
    except Exception as exc:
        print(f"ERROR: Stream resolution failed: {exc}")
        return None

    if not streams:
        print(f"ERROR: Stream '{stream_name}' not found within 30s")
        return None

    stream_info = streams[0]
    channels = stream_info.channel_count()
    nominal_rate = stream_info.nominal_srate()
    print(f"Found: {stream_info.name()} ({channels}ch @ {nominal_rate}Hz) "
          f"from {stream_info.hostname()}")

    try:
        inlet = pylsl.StreamInlet(stream_info, max_buflen=360)
    except Exception as exc:
        print(f"ERROR: Failed to create inlet: {exc}")
        return None

    # Warmup: 2 seconds
    print("Warmup (2s)...")
    warmup_end = time.time() + 2.0
    while time.time() < warmup_end:
        inlet.pull_sample(timeout=1.0)

    # Measurement
    print(f"Measuring for {duration}s...")
    pull_durations_us = []
    inter_sample_intervals_us = []
    embedded_timestamps = []
    last_pull_time = None
    consecutive_timeouts = 0

    start_time = time.time()
    start_iso = datetime.now().isoformat()
    received = 0
    progress_interval = max(int(nominal_rate * 5), 1)

    try:
        while time.time() - start_time < duration:
            t0 = time.perf_counter()
            sample, _ = inlet.pull_sample(timeout=5.0)
            t1 = time.perf_counter()

            if sample is None:
                consecutive_timeouts += 1
                if consecutive_timeouts == 1:
                    elapsed = time.time() - start_time
                    print(f"  WARNING: No sample (5s timeout at t={elapsed:.0f}s)")
                if consecutive_timeouts >= 3:
                    print(f"  ERROR: {consecutive_timeouts} consecutive timeouts, aborting")
                    break
                continue

            consecutive_timeouts = 0
            received += 1
            pull_durations_us.append((t1 - t0) * 1e6)

            # Record embedded timestamp from channel 0
            embedded_timestamps.append(sample[0])

            # Inter-sample interval
            if last_pull_time is not None:
                inter_sample_intervals_us.append((t1 - last_pull_time) * 1e6)
            last_pull_time = t1

            # Progress
            if received % progress_interval == 0:
                elapsed = time.time() - start_time
                print(f"  {received} samples, {received / elapsed:.1f} Hz actual")

    except KeyboardInterrupt:
        print("\nInterrupted, saving partial results...")

    end_time = time.time()
    end_iso = datetime.now().isoformat()
    actual_duration = end_time - start_time
    actual_rate = received / actual_duration if actual_duration > 0 else 0
    expected = int(nominal_rate * actual_duration) if nominal_rate > 0 else received
    loss_pct = 100 * (expected - received) / expected if expected > 0 else 0

    # Compute statistics
    results = {
        "samples_received": received,
        "expected_samples": expected,
        "actual_duration": round(actual_duration, 2),
        "actual_rate": round(actual_rate, 2),
        "rate_accuracy": round(actual_rate / nominal_rate, 4) if nominal_rate > 0 else 0,
        "packet_loss_pct": round(loss_pct, 2),
        **compute_timing_stats(pull_durations_us, "pull"),
        "jitter_std_us": round(float(np.std(inter_sample_intervals_us)), 2)
        if inter_sample_intervals_us else 0,
        "interval_mean_us": round(float(np.mean(inter_sample_intervals_us)), 2)
        if inter_sample_intervals_us else 0,
    }

    print(f"\n{'='*60}")
    print(f"Benchmark Results: {stream_name}")
    print(f"{'='*60}")
    print(f"Samples:  {received}/{expected} ({loss_pct:.1f}% loss)")
    print(f"Rate:     {actual_rate:.1f} Hz (nominal {nominal_rate:.0f})")
    print(f"Pull:     {results['pull_mean_us']:.1f} +/- {results['pull_std_us']:.1f} us "
          f"(p95={results['pull_p95_us']:.1f})")
    print(f"Jitter:   {results['jitter_std_us']:.1f} us std")
    print(f"{'='*60}")

    output = {
        "system_info": get_system_info(),
        "stream_info": {
            "name": stream_info.name(),
            "type": stream_info.type(),
            "channels": channels,
            "nominal_rate": nominal_rate,
            "hostname": stream_info.hostname(),
        },
        "device": "ESP32",
        "is_remote": True,
        "duration": duration,
        "start_time": start_iso,
        "end_time": end_iso,
        "pull_durations_us": [round(x, 2) for x in pull_durations_us],
        "inter_sample_intervals_us": [round(x, 2) for x in inter_sample_intervals_us],
        "embedded_timestamps": embedded_timestamps[:1000],
        "latencies_ms": [],  # not computed (cross-machine, clocks unsynchronized)
        "results": results,
    }

    save_results(output, output_file)
    return output


def main():
    parser = argparse.ArgumentParser(description="ESP32 Benchmark - Desktop Inlet")
    parser.add_argument("--name", default="ESP32Bench", help="Stream name to resolve")
    parser.add_argument("--duration", type=int, default=60, help="Test duration (seconds)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    result = run_benchmark(args.name, args.duration, args.output)
    if not result:
        exit(1)


if __name__ == "__main__":
    main()
