#!/usr/bin/env python3
# Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""
Secure LSL Benchmark - Outlet

Pushes samples at specified rate while recording timing information.
Designed to work with benchmark_inlet.py for round-trip measurements.

Usage:
    python benchmark_outlet.py --channels 64 --rate 1000 --duration 60

The outlet embeds high-precision timestamps in the data for latency measurement.
"""

import argparse
import json
import os
import platform
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pylsl

# Report pylsl library path if set
_pylsl_lib = os.environ.get("PYLSL_LIB")
if _pylsl_lib:
    print(f"Using PYLSL_LIB: {_pylsl_lib}")


def get_system_info():
    """Collect system information for the benchmark record."""
    info = {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "machine": platform.machine(),
        "hostname": platform.node(),
    }

    # Try to get CPU info on Linux/macOS
    try:
        if platform.system() == "Darwin":
            import subprocess

            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
            )
            info["cpu_model"] = result.stdout.strip()
        elif platform.system() == "Linux":
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "model name" in line:
                        info["cpu_model"] = line.split(":")[1].strip()
                        break
    except Exception:
        pass

    return info


def check_security_from_config():
    """Check security status from LSLAPICFG config file."""
    config_path = os.environ.get("LSLAPICFG")
    if not config_path:
        return None

    try:
        with open(config_path) as f:
            content = f.read().lower()
            # Simple check for enabled = true/false in [security] section
            if "[security]" in content:
                if "enabled = true" in content or "enabled=true" in content:
                    return True
                elif "enabled = false" in content or "enabled=false" in content:
                    return False
    except Exception:
        pass
    return None


def run_benchmark(
    channels: int,
    rate: float,
    duration: float,
    stream_name: str,
    output_file: str = None,
    secure_mode: bool = None,
):
    """
    Run the outlet benchmark.

    Args:
        channels: Number of channels
        rate: Sampling rate in Hz
        duration: Duration in seconds
        stream_name: Name for the LSL stream
        output_file: Optional file to save timing data
        secure_mode: Explicitly set security mode (True/False/None for auto-detect)
    """

    print("=" * 60)
    print("Secure LSL Benchmark - Outlet")
    print("=" * 60)

    # System info
    sys_info = get_system_info()
    print(f"Platform: {sys_info.get('platform', 'Unknown')}")
    print(f"CPU: {sys_info.get('cpu_model', sys_info.get('processor', 'Unknown'))}")
    print(f"Hostname: {sys_info.get('hostname', 'Unknown')}")

    # Security status - use explicit mode if provided, otherwise check config
    if secure_mode is not None:
        security_enabled = secure_mode
    else:
        security_enabled = check_security_from_config()

    if security_enabled is True:
        print("Security: ENABLED (encrypted)")
    elif security_enabled is False:
        print("Security: DISABLED (plaintext)")
    else:
        print("Security: UNKNOWN")

    print("-" * 60)
    print(f"Channels: {channels}")
    print(f"Rate: {rate} Hz")
    print(f"Duration: {duration} seconds")
    print(f"Expected samples: {int(rate * duration)}")
    print("-" * 60)

    # Create stream info
    # Use double64 for high-precision timestamp embedding
    info = pylsl.StreamInfo(
        stream_name,
        "Benchmark",
        channels,
        rate,
        "double64",  # Use double64 for full timestamp precision
        f"benchmark_{platform.node()}_{int(time.time())}",
    )

    # Add metadata
    desc = info.desc()
    desc.append_child_value("manufacturer", "SecureLSL-Benchmark")
    desc.append_child_value("security_enabled", str(security_enabled))

    channels_node = desc.append_child("channels")
    # First channel contains high-precision timestamp (float64)
    ch = channels_node.append_child("channel")
    ch.append_child_value("label", "timestamp")
    ch.append_child_value("unit", "seconds")
    ch.append_child_value("type", "Timing")

    # Remaining channels are synthetic data
    for i in range(1, channels):
        ch = channels_node.append_child("channel")
        ch.append_child_value("label", f"ch_{i}")
        ch.append_child_value("unit", "uV")
        ch.append_child_value("type", "EEG")

    # Create outlet
    print("Creating outlet...")
    outlet = pylsl.StreamOutlet(info, chunk_size=0, max_buffered=360)

    print(f"Stream '{stream_name}' is now available")
    print("Waiting for inlet connection...")

    # Wait for consumer
    while not outlet.have_consumers():
        time.sleep(0.1)

    print("Inlet connected! Starting benchmark...")
    print()

    # Prepare timing data collection
    timing_data = {
        "system_info": sys_info,
        "security_enabled": security_enabled,
        "channels": channels,
        "rate": rate,
        "duration": duration,
        "stream_name": stream_name,
        "start_time": None,
        "end_time": None,
        "push_times": [],
        "push_durations": [],
    }

    # Pre-allocate sample buffer - use float64 for full precision
    sample = np.zeros(channels, dtype=np.float64)

    # Calculate timing
    sample_interval = 1.0 / rate
    total_samples = int(rate * duration)

    # Warmup
    print("Warmup (1 second)...")
    warmup_end = time.perf_counter() + 1.0
    while time.perf_counter() < warmup_end:
        now = time.time()
        sample[0] = now  # Full precision timestamp in float64
        outlet.push_sample(sample)
        time.sleep(sample_interval)

    print("Starting measurement...")
    timing_data["start_time"] = datetime.now().isoformat()

    start_time = time.perf_counter()
    next_sample_time = start_time
    samples_sent = 0

    # Progress reporting
    last_report = start_time
    report_interval = 5.0  # Report every 5 seconds

    try:
        while samples_sent < total_samples:
            current_time = time.perf_counter()

            if current_time >= next_sample_time:
                # Embed current timestamp in sample (full precision float64)
                now = time.time()
                sample[0] = now  # Full timestamp with microsecond precision

                # Fill remaining channels with synthetic data
                for i in range(1, channels):
                    sample[i] = np.sin(2 * np.pi * samples_sent / rate + i)

                # Time the push operation
                push_start = time.perf_counter()
                outlet.push_sample(sample)
                push_end = time.perf_counter()

                push_duration = (push_end - push_start) * 1e6  # microseconds
                timing_data["push_durations"].append(push_duration)
                timing_data["push_times"].append(now)

                samples_sent += 1
                next_sample_time = start_time + samples_sent * sample_interval

                # Progress report
                if current_time - last_report >= report_interval:
                    elapsed = current_time - start_time
                    progress = samples_sent / total_samples * 100
                    actual_rate = samples_sent / elapsed
                    avg_push = np.mean(
                        timing_data["push_durations"][-int(rate * report_interval) :]
                    )
                    print(
                        f"  {progress:5.1f}% | {samples_sent:8d} samples | "
                        f"{actual_rate:.1f} Hz | avg push: {avg_push:.1f} us"
                    )
                    last_report = current_time
            else:
                # Small sleep to avoid busy-waiting
                sleep_time = min(next_sample_time - current_time, 0.0001)
                if sleep_time > 0:
                    time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\nInterrupted by user")

    end_time = time.perf_counter()
    timing_data["end_time"] = datetime.now().isoformat()

    # Calculate statistics
    actual_duration = end_time - start_time
    actual_rate = samples_sent / actual_duration

    push_durations = np.array(timing_data["push_durations"])

    print()
    print("=" * 60)
    print("Results")
    print("=" * 60)
    print(f"Samples sent: {samples_sent}")
    print(f"Actual duration: {actual_duration:.2f} s")
    print(f"Actual rate: {actual_rate:.2f} Hz (target: {rate} Hz)")
    print()
    print("Push timing (time to push one sample):")
    print(f"  Mean:   {np.mean(push_durations):8.2f} us")
    print(f"  Std:    {np.std(push_durations):8.2f} us")
    print(f"  Median: {np.median(push_durations):8.2f} us")
    print(f"  Min:    {np.min(push_durations):8.2f} us")
    print(f"  Max:    {np.max(push_durations):8.2f} us")
    print(f"  P95:    {np.percentile(push_durations, 95):8.2f} us")
    print(f"  P99:    {np.percentile(push_durations, 99):8.2f} us")

    # Save results
    if output_file:
        timing_data["results"] = {
            "samples_sent": samples_sent,
            "actual_duration": actual_duration,
            "actual_rate": actual_rate,
            "push_mean_us": float(np.mean(push_durations)),
            "push_std_us": float(np.std(push_durations)),
            "push_median_us": float(np.median(push_durations)),
            "push_min_us": float(np.min(push_durations)),
            "push_max_us": float(np.max(push_durations)),
            "push_p95_us": float(np.percentile(push_durations, 95)),
            "push_p99_us": float(np.percentile(push_durations, 99)),
        }

        # Convert numpy arrays to lists for JSON
        timing_data["push_durations"] = push_durations.tolist()

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(timing_data, f, indent=2)

        print(f"\nResults saved to: {output_file}")

    return timing_data


def main():
    parser = argparse.ArgumentParser(
        description="Secure LSL Benchmark - Outlet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic 64-channel EEG simulation
  python benchmark_outlet.py --channels 64 --rate 1000 --duration 60

  # High-density EEG
  python benchmark_outlet.py --channels 256 --rate 2000 --duration 120

  # Quick test
  python benchmark_outlet.py --channels 8 --rate 500 --duration 10
        """,
    )

    parser.add_argument(
        "--channels",
        "-c",
        type=int,
        default=64,
        help="Number of channels (default: 64)",
    )
    parser.add_argument(
        "--rate",
        "-r",
        type=float,
        default=1000,
        help="Sampling rate in Hz (default: 1000)",
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=float,
        default=60,
        help="Duration in seconds (default: 60)",
    )
    parser.add_argument(
        "--name",
        "-n",
        type=str,
        default="SecureLSL-Benchmark",
        help="Stream name (default: SecureLSL-Benchmark)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output file for timing data (JSON)",
    )
    parser.add_argument(
        "--secure",
        action="store_true",
        default=None,
        help="Explicitly mark as secure mode (for benchmarking)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=None,
        help="Explicitly mark as insecure mode (for benchmarking)",
    )

    args = parser.parse_args()

    # Determine security mode
    secure_mode = None
    if args.secure:
        secure_mode = True
    elif args.insecure:
        secure_mode = False

    # Generate default output filename if not specified
    if args.output is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = platform.node().replace(".", "_")
        args.output = f"../results/outlet_{hostname}_{args.channels}ch_{int(args.rate)}Hz_{timestamp}.json"

    run_benchmark(
        channels=args.channels,
        rate=args.rate,
        duration=args.duration,
        stream_name=args.name,
        output_file=args.output,
        secure_mode=secure_mode,
    )


if __name__ == "__main__":
    main()
