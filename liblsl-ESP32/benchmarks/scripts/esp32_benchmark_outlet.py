#!/usr/bin/env python3
# Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""ESP32 Benchmark - Desktop Outlet.

Pushes samples at a specified rate for ESP32 inlet testing.
Embeds timestamps in channel 0 for timing analysis.

Usage:
    uv run python esp32_benchmark_outlet.py --channels 8 --rate 250 --duration 60
    uv run python esp32_benchmark_outlet.py --channels 8 --rate 250 --duration 60 -o results/out.json
"""

import argparse
import math
import os
import time
from datetime import datetime

import pylsl

from bench_utils import compute_timing_stats, get_system_info, save_results


def run_benchmark(channels, rate, duration, stream_name, output_file):
    """Run the desktop outlet benchmark for ESP32 inlet testing."""
    if rate <= 0:
        print("ERROR: rate must be > 0")
        return None

    print(f"Desktop outlet: {channels}ch @ {rate}Hz for {duration}s")
    print(f"Stream name: {stream_name}")

    try:
        info = pylsl.StreamInfo(
            stream_name, "Benchmark", channels, rate,
            pylsl.cf_float32, f"desktop_bench_{os.getpid()}"
        )
        outlet = pylsl.StreamOutlet(info)
    except Exception as exc:
        print(f"ERROR: Failed to create outlet: {exc}")
        return None

    print("Outlet created, pushing samples...")

    push_durations_us = []
    start_time = time.time()
    start_iso = datetime.now().isoformat()
    sample = [0.0] * channels
    pushed = 0

    target_interval = 1.0 / rate
    next_push = time.perf_counter()

    try:
        while time.time() - start_time < duration:
            now = time.perf_counter()
            if now < next_push:
                sleep_time = next_push - now
                if sleep_time > 0.0001:
                    time.sleep(sleep_time - 0.0001)
                while time.perf_counter() < next_push:
                    pass

            t = time.time()
            sample[0] = t
            for ch in range(1, channels):
                sample[ch] = math.sin(2 * math.pi * ch * t * 0.01)

            t0 = time.perf_counter()
            outlet.push_sample(sample)
            t1 = time.perf_counter()

            push_durations_us.append((t1 - t0) * 1e6)
            pushed += 1
            next_push += target_interval

            if pushed % (rate * 5) == 0:
                elapsed = time.time() - start_time
                print(f"  {pushed} samples, {pushed / elapsed:.1f} Hz")

    except KeyboardInterrupt:
        print("\nInterrupted, saving partial results...")

    end_iso = datetime.now().isoformat()
    actual_duration = time.time() - start_time
    actual_rate = pushed / actual_duration if actual_duration > 0 else 0

    results = {
        "samples_sent": pushed,
        "actual_duration": round(actual_duration, 2),
        "actual_rate": round(actual_rate, 2),
        **compute_timing_stats(push_durations_us, "push"),
    }

    print(f"\n{'='*60}")
    print(f"Desktop Outlet Results")
    print(f"{'='*60}")
    print(f"Pushed:   {pushed} samples in {actual_duration:.1f}s ({actual_rate:.1f} Hz)")
    print(f"Push:     {results['push_mean_us']:.1f} +/- {results['push_std_us']:.1f} us")
    print(f"{'='*60}")

    output = {
        "system_info": get_system_info(),
        "channels": channels,
        "rate": rate,
        "duration": duration,
        "stream_name": stream_name,
        "start_time": start_iso,
        "end_time": end_iso,
        "push_durations_us": [round(x, 2) for x in push_durations_us[:10000]],
        "results": results,
    }

    save_results(output, output_file)
    return output


def main():
    parser = argparse.ArgumentParser(description="ESP32 Benchmark - Desktop Outlet")
    parser.add_argument("--channels", type=int, default=8, help="Channel count")
    parser.add_argument("--rate", type=int, default=250, help="Sample rate (Hz)")
    parser.add_argument("--duration", type=int, default=60, help="Duration (seconds)")
    parser.add_argument("--name", default="DesktopBench", help="Stream name")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    run_benchmark(args.channels, args.rate, args.duration, args.name, args.output)


if __name__ == "__main__":
    main()
