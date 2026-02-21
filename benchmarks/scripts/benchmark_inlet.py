#!/usr/bin/env python3
# Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""
Secure LSL Benchmark - Inlet

Receives samples and measures end-to-end latency, jitter, and throughput.
Designed to work with benchmark_outlet.py.

Usage:
    python benchmark_inlet.py --duration 60

Metrics collected:
- End-to-end latency (outlet timestamp vs receive time)
- Pull timing (time to pull each sample)
- Jitter (variability in timing)
- Throughput (actual vs nominal rate)
- CPU and memory usage
"""

import argparse
import json
import os
import platform
import threading
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pylsl

# Optional: psutil for CPU/memory monitoring
try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("Note: Install psutil for CPU/memory monitoring: pip install psutil")

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

    # Try to get CPU info
    try:
        if platform.system() == "Darwin":
            import subprocess

            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                info["cpu_model"] = result.stdout.strip()
            else:
                # Apple Silicon
                result = subprocess.run(
                    ["sysctl", "-n", "hw.model"], capture_output=True, text=True
                )
                info["cpu_model"] = result.stdout.strip()
        elif platform.system() == "Linux":
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "model name" in line:
                        info["cpu_model"] = line.split(":")[1].strip()
                        break
                    elif "Model" in line:  # Raspberry Pi
                        info["cpu_model"] = line.split(":")[1].strip()
    except Exception:
        pass

    if HAS_PSUTIL:
        info["cpu_count"] = psutil.cpu_count()
        info["memory_total_gb"] = psutil.virtual_memory().total / (1024**3)

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


class ResourceMonitor:
    """Monitor CPU and memory usage in background thread."""

    def __init__(self, interval=1.0):
        self.interval = interval
        self.running = False
        self.thread = None
        self.cpu_samples = []
        self.memory_samples = []
        self.timestamps = []

    def start(self):
        if not HAS_PSUTIL:
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)

    def _monitor_loop(self):
        process = psutil.Process()
        while self.running:
            try:
                self.timestamps.append(time.time())
                self.cpu_samples.append(process.cpu_percent())
                self.memory_samples.append(process.memory_info().rss / (1024**2))  # MB
            except Exception:
                pass
            time.sleep(self.interval)

    def get_stats(self):
        if not self.cpu_samples:
            return {}
        return {
            "cpu_mean_percent": float(np.mean(self.cpu_samples)),
            "cpu_max_percent": float(np.max(self.cpu_samples)),
            "cpu_std_percent": float(np.std(self.cpu_samples)),
            "memory_mean_mb": float(np.mean(self.memory_samples)),
            "memory_max_mb": float(np.max(self.memory_samples)),
            "samples": len(self.cpu_samples),
        }


def run_benchmark(
    duration: float,
    stream_name: str = None,
    stream_type: str = "Benchmark",
    output_file: str = None,
    secure_mode: bool = None,
):
    """
    Run the inlet benchmark.

    Args:
        duration: Duration in seconds
        stream_name: Optional specific stream name to connect to
        stream_type: Stream type to search for
        output_file: Optional file to save timing data
        secure_mode: Explicitly set security mode (True/False/None for auto-detect)
    """

    print("=" * 60)
    print("Secure LSL Benchmark - Inlet")
    print("=" * 60)

    # System info
    sys_info = get_system_info()
    print(f"Platform: {sys_info.get('platform', 'Unknown')}")
    print(f"CPU: {sys_info.get('cpu_model', sys_info.get('processor', 'Unknown'))}")
    print(f"Hostname: {sys_info.get('hostname', 'Unknown')}")
    print("-" * 60)

    # Resolve stream
    print(f"Looking for stream (type='{stream_type}')...")
    if stream_name:
        streams = pylsl.resolve_byprop("name", stream_name, timeout=30.0)
    else:
        streams = pylsl.resolve_byprop("type", stream_type, timeout=30.0)

    if not streams:
        print("ERROR: No stream found!")
        return None

    stream_info = streams[0]
    print(f"Found: {stream_info.name()} @ {stream_info.hostname()}")
    print(f"  Channels: {stream_info.channel_count()}")
    print(f"  Rate: {stream_info.nominal_srate()} Hz")

    # Security status - use explicit mode if provided, otherwise check config
    if secure_mode is not None:
        security_enabled = secure_mode
    else:
        security_enabled = check_security_from_config()

    if security_enabled is True:
        print("  Security: ENABLED (encrypted)")
    elif security_enabled is False:
        print("  Security: DISABLED (plaintext)")
    else:
        print("  Security: UNKNOWN")

    # Check if cross-machine
    is_remote = stream_info.hostname() != platform.node()
    print(f"  Remote: {is_remote} ({stream_info.hostname()} -> {platform.node()})")

    print("-" * 60)

    # Create inlet
    inlet = pylsl.StreamInlet(stream_info, max_buflen=360, max_chunklen=0)
    channels = stream_info.channel_count()
    nominal_rate = stream_info.nominal_srate()

    # Prepare timing data collection
    timing_data = {
        "system_info": sys_info,
        "stream_info": {
            "name": stream_info.name(),
            "type": stream_info.type(),
            "channels": channels,
            "nominal_rate": nominal_rate,
            "hostname": stream_info.hostname(),
            "source_id": stream_info.source_id(),
        },
        "security_enabled": security_enabled,
        "is_remote": is_remote,
        "duration": duration,
        "start_time": None,
        "end_time": None,
        "latencies_ms": [],
        "pull_durations_us": [],
        "inter_sample_intervals_us": [],
    }

    # Start resource monitoring
    monitor = ResourceMonitor(interval=0.5)
    monitor.start()

    # Warmup
    print("Warmup (2 seconds)...")
    warmup_end = time.perf_counter() + 2.0
    while time.perf_counter() < warmup_end:
        sample, timestamp = inlet.pull_sample(timeout=1.0)
        if sample is None:
            print("  Waiting for samples...")

    print("Starting measurement...")
    timing_data["start_time"] = datetime.now().isoformat()

    start_time = time.perf_counter()
    samples_received = 0
    last_receive_time = None

    # Progress reporting
    last_report = start_time
    report_interval = 5.0

    try:
        while time.perf_counter() - start_time < duration:
            # Time the pull operation
            pull_start = time.perf_counter()
            sample, lsl_timestamp = inlet.pull_sample(timeout=1.0)
            pull_end = time.perf_counter()

            if sample is None:
                continue

            receive_time = time.time()
            pull_duration = (pull_end - pull_start) * 1e6  # microseconds

            # Extract embedded timestamp from sample
            # sample[0] contains the full precision timestamp (float64)
            embedded_time = float(sample[0])

            # Calculate end-to-end latency
            latency_ms = (receive_time - embedded_time) * 1000

            # Only record valid latencies (filter out warmup artifacts)
            # Valid range: 0-1000ms (anything larger is likely a stale sample)
            if 0 < latency_ms < 1000:
                timing_data["latencies_ms"].append(latency_ms)
                timing_data["pull_durations_us"].append(pull_duration)

                # Inter-sample interval
                if last_receive_time is not None:
                    interval = (receive_time - last_receive_time) * 1e6
                    timing_data["inter_sample_intervals_us"].append(interval)

                samples_received += 1

            last_receive_time = receive_time

            # Progress report
            current_time = time.perf_counter()
            if current_time - last_report >= report_interval:
                elapsed = current_time - start_time
                progress = elapsed / duration * 100
                actual_rate = samples_received / elapsed if elapsed > 0 else 0

                if timing_data["latencies_ms"]:
                    recent_latencies = timing_data["latencies_ms"][
                        -int(nominal_rate * report_interval) :
                    ]
                    avg_latency = np.mean(recent_latencies)
                    print(
                        f"  {progress:5.1f}% | {samples_received:8d} samples | "
                        f"{actual_rate:.1f} Hz | latency: {avg_latency:.2f} ms"
                    )
                else:
                    print(
                        f"  {progress:5.1f}% | {samples_received:8d} samples | {actual_rate:.1f} Hz"
                    )

                last_report = current_time

    except KeyboardInterrupt:
        print("\nInterrupted by user")

    end_time = time.perf_counter()
    timing_data["end_time"] = datetime.now().isoformat()

    # Stop resource monitoring
    monitor.stop()

    # Calculate statistics
    actual_duration = end_time - start_time
    actual_rate = samples_received / actual_duration if actual_duration > 0 else 0

    latencies = np.array(timing_data["latencies_ms"])
    pull_durations = np.array(timing_data["pull_durations_us"])
    intervals = np.array(timing_data["inter_sample_intervals_us"])

    print()
    print("=" * 60)
    print("Results")
    print("=" * 60)
    print(f"Samples received: {samples_received}")
    print(f"Actual duration: {actual_duration:.2f} s")
    print(f"Actual rate: {actual_rate:.2f} Hz (nominal: {nominal_rate} Hz)")
    print(f"Rate accuracy: {actual_rate / nominal_rate * 100:.2f}%")
    print()

    if len(latencies) > 0:
        print("End-to-end latency (outlet push -> inlet receive):")
        print(f"  Mean:   {np.mean(latencies):8.3f} ms")
        print(f"  Std:    {np.std(latencies):8.3f} ms")
        print(f"  Median: {np.median(latencies):8.3f} ms")
        print(f"  Min:    {np.min(latencies):8.3f} ms")
        print(f"  Max:    {np.max(latencies):8.3f} ms")
        print(f"  P5:     {np.percentile(latencies, 5):8.3f} ms")
        print(f"  P95:    {np.percentile(latencies, 95):8.3f} ms")
        print(f"  P99:    {np.percentile(latencies, 99):8.3f} ms")
        print()

    if len(pull_durations) > 0:
        print("Pull timing (time to pull one sample):")
        print(f"  Mean:   {np.mean(pull_durations):8.2f} us")
        print(f"  Std:    {np.std(pull_durations):8.2f} us")
        print(f"  Median: {np.median(pull_durations):8.2f} us")
        print(f"  P95:    {np.percentile(pull_durations, 95):8.2f} us")
        print(f"  P99:    {np.percentile(pull_durations, 99):8.2f} us")
        print()

    if len(intervals) > 0:
        expected_interval = 1e6 / nominal_rate
        print(f"Inter-sample interval (expected: {expected_interval:.1f} us):")
        print(f"  Mean:   {np.mean(intervals):8.1f} us")
        print(f"  Std:    {np.std(intervals):8.1f} us (jitter)")
        print(f"  Median: {np.median(intervals):8.1f} us")
        print()

    # Resource usage
    resource_stats = monitor.get_stats()
    if resource_stats:
        print("Resource usage:")
        print(f"  CPU mean:   {resource_stats['cpu_mean_percent']:6.1f}%")
        print(f"  CPU max:    {resource_stats['cpu_max_percent']:6.1f}%")
        print(f"  Memory:     {resource_stats['memory_mean_mb']:6.1f} MB")

    # Compile results
    results = {
        "samples_received": samples_received,
        "actual_duration": actual_duration,
        "actual_rate": actual_rate,
        "rate_accuracy": actual_rate / nominal_rate if nominal_rate > 0 else 0,
    }

    if len(latencies) > 0:
        results.update(
            {
                "latency_mean_ms": float(np.mean(latencies)),
                "latency_std_ms": float(np.std(latencies)),
                "latency_median_ms": float(np.median(latencies)),
                "latency_min_ms": float(np.min(latencies)),
                "latency_max_ms": float(np.max(latencies)),
                "latency_p5_ms": float(np.percentile(latencies, 5)),
                "latency_p95_ms": float(np.percentile(latencies, 95)),
                "latency_p99_ms": float(np.percentile(latencies, 99)),
            }
        )

    if len(pull_durations) > 0:
        results.update(
            {
                "pull_mean_us": float(np.mean(pull_durations)),
                "pull_std_us": float(np.std(pull_durations)),
                "pull_p95_us": float(np.percentile(pull_durations, 95)),
            }
        )

    if len(intervals) > 0:
        results.update(
            {
                "jitter_std_us": float(np.std(intervals)),
                "interval_mean_us": float(np.mean(intervals)),
            }
        )

    results.update(resource_stats)

    timing_data["results"] = results

    # Save results
    if output_file:
        # Convert numpy arrays to lists for JSON
        timing_data["latencies_ms"] = latencies.tolist() if len(latencies) > 0 else []
        timing_data["pull_durations_us"] = (
            pull_durations.tolist() if len(pull_durations) > 0 else []
        )
        timing_data["inter_sample_intervals_us"] = (
            intervals.tolist() if len(intervals) > 0 else []
        )

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(timing_data, f, indent=2)

        print(f"\nResults saved to: {output_file}")

    return timing_data


def main():
    parser = argparse.ArgumentParser(
        description="Secure LSL Benchmark - Inlet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic benchmark
  python benchmark_inlet.py --duration 60

  # Connect to specific stream
  python benchmark_inlet.py --name SecureLSL-Benchmark --duration 120

  # Quick test
  python benchmark_inlet.py --duration 10
        """,
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
        default=None,
        help="Specific stream name to connect to",
    )
    parser.add_argument(
        "--type",
        "-t",
        type=str,
        default="Benchmark",
        help="Stream type to search for (default: Benchmark)",
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
        args.output = f"../results/inlet_{hostname}_{timestamp}.json"

    run_benchmark(
        duration=args.duration,
        stream_name=args.name,
        stream_type=args.type,
        output_file=args.output,
        secure_mode=secure_mode,
    )


if __name__ == "__main__":
    main()
