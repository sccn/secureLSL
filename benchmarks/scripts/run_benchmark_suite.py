#!/usr/bin/env python3
# Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""
Secure LSL Comprehensive Benchmark Suite

Runs systematic benchmarks to answer reviewer questions:
1. Effect of channel count on overhead
2. Effect of sampling rate on overhead
3. Effect of multiple inlets (fan-out)
4. Comparison across platforms

Usage:
    python run_benchmark_suite.py --suite channel-sweep --duration 30
    python run_benchmark_suite.py --suite rate-sweep --duration 30
    python run_benchmark_suite.py --suite multi-inlet --duration 30
    python run_benchmark_suite.py --suite full --duration 60
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Benchmark configurations
CHANNEL_SWEEP = [8, 32, 64, 128, 256]  # Channels to test
RATE_SWEEP = [250, 500, 1000, 2000]  # Hz to test
MULTI_INLET_COUNTS = [1, 2, 4]  # Number of simultaneous inlets


def get_platform_id():
    """Get short platform identifier."""
    hostname = platform.node().lower()
    cpu = platform.processor().lower()

    if "raspberry" in cpu or "pi" in hostname:
        return "pi5"
    elif "apple" in cpu or "mac" in hostname:
        return "macmini"
    elif "i7" in cpu or "i9" in cpu:
        return "i7"
    else:
        return hostname.split(".")[0]


def create_security_config(enabled: bool, temp_dir: Path) -> Path:
    """Create a temporary lsl_api.cfg with security enabled or disabled.

    Args:
        enabled: Whether security should be enabled
        temp_dir: Directory to create config file in

    Returns:
        Path to the config file
    """
    config_file = temp_dir / f"lsl_api_{'secure' if enabled else 'insecure'}.cfg"

    if enabled:
        # For secure mode, we need a valid key
        # Use lsl-keygen to generate one, or use a test key
        config_content = """[security]
enabled = true
; A test key is auto-generated on first use if not present
; For benchmarking, we let liblsl generate a session key

[log]
level = 4
"""
    else:
        # Insecure mode - explicitly disable security
        config_content = """[security]
enabled = false

[log]
level = 4
"""

    config_file.write_text(config_content)
    return config_file


def get_env_with_security(enabled: bool, temp_dir: Path) -> dict:
    """Get environment variables for running with security enabled/disabled."""
    env = os.environ.copy()

    # Create and point to appropriate config
    config_path = create_security_config(enabled, temp_dir)
    env["LSLAPICFG"] = str(config_path)

    return env


def check_security_enabled(env: dict = None):
    """Check if security is currently enabled."""
    try:
        import pylsl

        info = pylsl.StreamInfo("_check", "Test", 1, 1, "float32", "_check")
        if hasattr(info, "security_enabled"):
            return info.security_enabled()
    except Exception:
        pass
    return None


def run_outlet(channels, rate, duration, name, output_file, env=None, secure=None):
    """Run outlet in subprocess."""
    cmd = [
        sys.executable,
        "benchmark_outlet.py",
        "--channels",
        str(channels),
        "--rate",
        str(rate),
        "--duration",
        str(duration),
        "--name",
        name,
        "--output",
        output_file,
    ]
    # Add security mode flag
    if secure is True:
        cmd.append("--secure")
    elif secure is False:
        cmd.append("--insecure")

    return subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
    )


def run_inlet(duration, name, output_file, env=None, secure=None):
    """Run inlet in subprocess."""
    cmd = [
        sys.executable,
        "benchmark_inlet.py",
        "--duration",
        str(duration),
        "--name",
        name,
        "--output",
        output_file,
    ]
    # Add security mode flag
    if secure is True:
        cmd.append("--secure")
    elif secure is False:
        cmd.append("--insecure")

    return subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
    )


def wait_for_stream(name, timeout=30):
    """Wait for a stream to become available."""
    import pylsl

    start = time.time()
    while time.time() - start < timeout:
        streams = pylsl.resolve_byprop("name", name, timeout=1.0)
        if streams:
            return True
        time.sleep(0.5)
    return False


def run_single_test(
    channels, rate, duration, test_id, results_dir, secure: bool, temp_dir: Path
):
    """Run a single outlet-inlet test pair.

    Args:
        channels: Number of channels
        rate: Sampling rate in Hz
        duration: Duration in seconds
        test_id: Unique test identifier
        results_dir: Directory for results
        secure: Whether to run with security enabled
        temp_dir: Temp directory for config files
    """
    platform_id = get_platform_id()
    security = "secure" if secure else "insecure"
    stream_name = f"Bench_{test_id}_{security}_{int(time.time())}"

    outlet_file = results_dir / f"{test_id}_{platform_id}_{security}_outlet.json"
    inlet_file = results_dir / f"{test_id}_{platform_id}_{security}_inlet.json"

    # Get environment with appropriate security setting
    env = get_env_with_security(secure, temp_dir)

    print(f"\n{'=' * 60}")
    print(f"Test: {test_id}")
    print(f"  Channels: {channels}, Rate: {rate} Hz, Duration: {duration}s")
    print(f"  Security: {security.upper()}")
    print(f"  Config: {env.get('LSLAPICFG', 'default')}")
    print(f"{'=' * 60}")

    # Start outlet
    print("Starting outlet...")
    outlet_proc = run_outlet(
        channels,
        rate,
        duration + 5,
        stream_name,
        str(outlet_file),
        env=env,
        secure=secure,
    )

    # Wait for stream to be available, with better error reporting
    time.sleep(3)  # Give outlet more time to start
    if not wait_for_stream(stream_name):
        print("ERROR: Stream not found!")
        # Check if outlet process is still running
        poll_result = outlet_proc.poll()
        if poll_result is not None:
            print(f"  Outlet process exited with code: {poll_result}")
            stdout, stderr = outlet_proc.communicate()
            if stderr:
                print(f"  Stderr: {stderr.decode()[:500]}")
            if stdout:
                print(f"  Stdout: {stdout.decode()[:500]}")
        outlet_proc.terminate()
        return None

    # Start inlet
    print("Starting inlet...")
    inlet_proc = run_inlet(
        duration, stream_name, str(inlet_file), env=env, secure=secure
    )

    # Wait for completion
    try:
        inlet_proc.wait(timeout=duration + 30)
        outlet_proc.terminate()
    except subprocess.TimeoutExpired:
        print("WARNING: Test timed out")
        inlet_proc.terminate()
        outlet_proc.terminate()

    # Check results
    if inlet_file.exists():
        with open(inlet_file) as f:
            data = json.load(f)
            data["_security_mode"] = security
            results = data.get("results", {})
            lat = results.get("latency_mean_ms", 0)
            std = results.get("latency_std_ms", 0)
            cpu = results.get("cpu_mean_percent", 0)
            print(
                f"\n  Results: Latency = {lat:.2f} +/- {std:.2f} ms, CPU = {cpu:.1f}%"
            )
            return data
    else:
        print("ERROR: No results file generated")
        return None


def run_channel_sweep(duration, results_dir, temp_dir):
    """Test effect of different channel counts."""
    print("\n" + "=" * 60)
    print("CHANNEL SWEEP BENCHMARK")
    print("Testing: " + ", ".join(f"{c}ch" for c in CHANNEL_SWEEP))
    print("Running both SECURE and INSECURE modes for comparison")
    print("=" * 60)

    results = []
    for channels in CHANNEL_SWEEP:
        # Run insecure first (baseline)
        test_id = f"CH{channels:03d}"
        result = run_single_test(
            channels,
            1000,
            duration,
            test_id,
            results_dir,
            secure=False,
            temp_dir=temp_dir,
        )
        if result:
            result["_test_type"] = "channel_sweep"
            result["_variable"] = channels
            results.append(result)
        time.sleep(2)

        # Run secure
        result = run_single_test(
            channels,
            1000,
            duration,
            test_id,
            results_dir,
            secure=True,
            temp_dir=temp_dir,
        )
        if result:
            result["_test_type"] = "channel_sweep"
            result["_variable"] = channels
            results.append(result)
        time.sleep(2)

    return results


def run_rate_sweep(duration, results_dir, temp_dir):
    """Test effect of different sampling rates."""
    print("\n" + "=" * 60)
    print("RATE SWEEP BENCHMARK")
    print("Testing: " + ", ".join(f"{r}Hz" for r in RATE_SWEEP))
    print("Running both SECURE and INSECURE modes for comparison")
    print("=" * 60)

    results = []
    for rate in RATE_SWEEP:
        test_id = f"RT{rate:04d}"
        # Insecure baseline
        result = run_single_test(
            64, rate, duration, test_id, results_dir, secure=False, temp_dir=temp_dir
        )
        if result:
            result["_test_type"] = "rate_sweep"
            result["_variable"] = rate
            results.append(result)
        time.sleep(2)

        # Secure
        result = run_single_test(
            64, rate, duration, test_id, results_dir, secure=True, temp_dir=temp_dir
        )
        if result:
            result["_test_type"] = "rate_sweep"
            result["_variable"] = rate
            results.append(result)
        time.sleep(2)

    return results


def run_multi_inlet_test(duration, results_dir, temp_dir):
    """Test with multiple inlets receiving from one outlet."""
    print("\n" + "=" * 60)
    print("MULTI-INLET BENCHMARK")
    print("Testing: " + ", ".join(f"{n} inlet(s)" for n in MULTI_INLET_COUNTS))
    print("Running both SECURE and INSECURE modes for comparison")
    print("=" * 60)

    platform_id = get_platform_id()
    all_results = []

    for secure in [False, True]:
        security = "secure" if secure else "insecure"
        env = get_env_with_security(secure, temp_dir)

        print(f"\n{'=' * 40}")
        print(f"Mode: {security.upper()}")
        print(f"{'=' * 40}")

        for num_inlets in MULTI_INLET_COUNTS:
            test_id = f"MI{num_inlets:02d}"
            stream_name = f"MultiInlet_{security}_{int(time.time())}"

            print(f"\n--- Testing with {num_inlets} inlet(s) [{security}] ---")

            # Start outlet
            outlet_file = (
                results_dir / f"{test_id}_{platform_id}_{security}_outlet.json"
            )
            outlet_proc = run_outlet(
                64,
                1000,
                duration + 10,
                stream_name,
                str(outlet_file),
                env=env,
                secure=secure,
            )

            time.sleep(2)
            if not wait_for_stream(stream_name):
                print("ERROR: Stream not found!")
                outlet_proc.terminate()
                continue

            # Start multiple inlets
            inlet_procs = []
            inlet_files = []
            for i in range(num_inlets):
                inlet_file = (
                    results_dir / f"{test_id}_{platform_id}_{security}_inlet{i}.json"
                )
                inlet_files.append(inlet_file)
                proc = run_inlet(
                    duration, stream_name, str(inlet_file), env=env, secure=secure
                )
                inlet_procs.append(proc)
                time.sleep(0.5)  # Stagger starts slightly

            # Wait for completion
            try:
                for proc in inlet_procs:
                    proc.wait(timeout=duration + 30)
                outlet_proc.terminate()
            except subprocess.TimeoutExpired:
                for proc in inlet_procs:
                    proc.terminate()
                outlet_proc.terminate()

            # Collect results from all inlets
            for i, inlet_file in enumerate(inlet_files):
                if inlet_file.exists():
                    with open(inlet_file) as f:
                        data = json.load(f)
                        data["_test_type"] = "multi_inlet"
                        data["_variable"] = num_inlets
                        data["_inlet_id"] = i
                        data["_security_mode"] = security
                        all_results.append(data)

                        results = data.get("results", {})
                        lat = results.get("latency_mean_ms", 0)
                        print(f"  Inlet {i}: Latency = {lat:.2f} ms")

            time.sleep(2)

    return all_results


def run_full_suite(duration, results_dir, temp_dir):
    """Run all benchmark suites."""
    all_results = []

    # Channel sweep
    results = run_channel_sweep(duration, results_dir, temp_dir)
    all_results.extend(results)

    # Rate sweep
    results = run_rate_sweep(duration, results_dir, temp_dir)
    all_results.extend(results)

    # Multi-inlet (if running locally)
    results = run_multi_inlet_test(duration, results_dir, temp_dir)
    all_results.extend(results)

    return all_results


def generate_sweep_analysis(results_dir):
    """Generate analysis specifically for sweep tests with secure vs insecure comparison."""
    import glob
    import numpy as np
    import matplotlib.pyplot as plt

    # Colors for secure vs insecure
    SECURE_COLOR = "#2e7d32"  # Dark green
    INSECURE_COLOR = "#1a237e"  # Dark blue (baseline)

    # Load all results
    all_results = []
    for f in glob.glob(str(results_dir / "*.json")):
        try:
            with open(f) as fp:
                data = json.load(fp)
                all_results.append(data)
        except Exception:
            pass

    if not all_results:
        print("No results to analyze")
        return

    # Separate by test type
    channel_results = [r for r in all_results if r.get("_test_type") == "channel_sweep"]
    rate_results = [r for r in all_results if r.get("_test_type") == "rate_sweep"]
    multi_results = [r for r in all_results if r.get("_test_type") == "multi_inlet"]

    # Put figures in machine-specific directory (parallel to results)
    # results_dir is like ../results/macmini, so figures go to ../figures/macmini
    platform_name = results_dir.name  # e.g., "macmini"
    figures_dir = results_dir.parent.parent / "figures" / platform_name
    figures_dir.mkdir(parents=True, exist_ok=True)

    # Plot 1: Channel count vs latency (secure vs insecure)
    if channel_results:
        fig, ax = plt.subplots(figsize=(10, 6))

        # Separate secure and insecure results
        secure_data = {}
        insecure_data = {}

        for r in channel_results:
            ch = r.get("_variable")
            lat = r.get("results", {}).get("latency_mean_ms", 0)
            security = r.get("_security_mode", "insecure")

            if ch and lat > 0:
                if security == "secure":
                    secure_data[ch] = lat
                else:
                    insecure_data[ch] = lat

        if insecure_data:
            channels = sorted(insecure_data.keys())
            lats = [insecure_data[c] for c in channels]
            ax.plot(
                channels,
                lats,
                "o-",
                color=INSECURE_COLOR,
                linewidth=2,
                markersize=8,
                label="Insecure (baseline)",
            )

        if secure_data:
            channels = sorted(secure_data.keys())
            lats = [secure_data[c] for c in channels]
            ax.plot(
                channels,
                lats,
                "s-",
                color=SECURE_COLOR,
                linewidth=2,
                markersize=8,
                label="Secure (encrypted)",
            )

        ax.set_xlabel("Channel Count")
        ax.set_ylabel("Mean Latency (ms)")
        ax.set_title("Security Overhead vs Channel Count", fontweight="bold")
        ax.set_xscale("log", base=2)
        ax.legend()
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(figures_dir / "channel_sweep.pdf", dpi=300)
        plt.savefig(figures_dir / "channel_sweep.png", dpi=150)
        print(f"Saved: {figures_dir / 'channel_sweep.pdf'}")
        plt.close()

    # Plot 2: Sampling rate vs latency (secure vs insecure)
    if rate_results:
        fig, ax = plt.subplots(figsize=(10, 6))

        secure_data = {}
        insecure_data = {}

        for r in rate_results:
            rate = r.get("_variable")
            lat = r.get("results", {}).get("latency_mean_ms", 0)
            security = r.get("_security_mode", "insecure")

            if rate and lat > 0:
                if security == "secure":
                    secure_data[rate] = lat
                else:
                    insecure_data[rate] = lat

        if insecure_data:
            rates = sorted(insecure_data.keys())
            lats = [insecure_data[r] for r in rates]
            ax.plot(
                rates,
                lats,
                "o-",
                color=INSECURE_COLOR,
                linewidth=2,
                markersize=8,
                label="Insecure (baseline)",
            )

        if secure_data:
            rates = sorted(secure_data.keys())
            lats = [secure_data[r] for r in rates]
            ax.plot(
                rates,
                lats,
                "s-",
                color=SECURE_COLOR,
                linewidth=2,
                markersize=8,
                label="Secure (encrypted)",
            )

        ax.set_xlabel("Sampling Rate (Hz)")
        ax.set_ylabel("Mean Latency (ms)")
        ax.set_title("Security Overhead vs Sampling Rate", fontweight="bold")
        ax.legend()
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(figures_dir / "rate_sweep.pdf", dpi=300)
        plt.savefig(figures_dir / "rate_sweep.png", dpi=150)
        print(f"Saved: {figures_dir / 'rate_sweep.pdf'}")
        plt.close()

    # Plot 3: Multi-inlet scalability (secure vs insecure)
    if multi_results:
        fig, ax = plt.subplots(figsize=(10, 6))

        # Separate by security mode
        secure_results = [
            r for r in multi_results if r.get("_security_mode") == "secure"
        ]
        insecure_results = [
            r for r in multi_results if r.get("_security_mode") != "secure"
        ]

        for results, color, label in [
            (insecure_results, INSECURE_COLOR, "Insecure"),
            (secure_results, SECURE_COLOR, "Secure"),
        ]:
            if not results:
                continue

            inlet_counts = sorted(
                set(r.get("_variable") for r in results if r.get("_variable"))
            )
            mean_latencies = []
            std_latencies = []

            for count in inlet_counts:
                lats = [
                    r.get("results", {}).get("latency_mean_ms", 0)
                    for r in results
                    if r.get("_variable") == count
                    and r.get("results", {}).get("latency_mean_ms", 0) > 0
                ]
                if lats:
                    mean_latencies.append(np.mean(lats))
                    std_latencies.append(np.std(lats))

            if mean_latencies:
                ax.errorbar(
                    inlet_counts[: len(mean_latencies)],
                    mean_latencies,
                    yerr=std_latencies,
                    fmt="o-" if label == "Insecure" else "s-",
                    color=color,
                    linewidth=2,
                    markersize=8,
                    capsize=5,
                    capthick=2,
                    label=label,
                )

        ax.set_xlabel("Number of Simultaneous Inlets")
        ax.set_ylabel("Mean Latency (ms)")
        ax.set_title("Multi-Inlet Scalability: Secure vs Insecure", fontweight="bold")
        ax.legend()
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(figures_dir / "multi_inlet.pdf", dpi=300)
        plt.savefig(figures_dir / "multi_inlet.png", dpi=150)
        print(f"Saved: {figures_dir / 'multi_inlet.pdf'}")
        plt.close()

    # Plot 4: Overhead summary
    if channel_results or rate_results:
        fig, ax = plt.subplots(figsize=(10, 6))

        overheads = []
        labels = []

        # Calculate overhead for each test
        for r in channel_results + rate_results:
            security = r.get("_security_mode", "")
            if security == "secure":
                lat = r.get("results", {}).get("latency_mean_ms", 0)
                var = r.get("_variable", 0)
                test_type = r.get("_test_type", "")

                # Find corresponding insecure result
                for r2 in channel_results + rate_results:
                    if (
                        r2.get("_security_mode") != "secure"
                        and r2.get("_variable") == var
                        and r2.get("_test_type") == test_type
                    ):
                        insecure_lat = r2.get("results", {}).get("latency_mean_ms", 0)
                        if insecure_lat > 0:
                            overhead_ms = lat - insecure_lat
                            overheads.append(overhead_ms)
                            if test_type == "channel_sweep":
                                labels.append(f"{var}ch")
                            else:
                                labels.append(f"{var}Hz")
                        break

        if overheads:
            colors = [SECURE_COLOR if o >= 0 else "#c62828" for o in overheads]
            ax.bar(range(len(overheads)), overheads, color=colors, alpha=0.8)
            ax.set_xticks(range(len(labels)))
            ax.set_xticklabels(labels, rotation=45, ha="right")
            ax.axhline(y=0, color="black", linestyle="-", linewidth=0.5)
            ax.set_xlabel("Test Configuration")
            ax.set_ylabel("Latency Overhead (ms)")
            ax.set_title("Security Overhead: Secure - Insecure", fontweight="bold")
            ax.grid(True, alpha=0.3, axis="y")

            plt.tight_layout()
            plt.savefig(figures_dir / "overhead_summary.pdf", dpi=300)
            plt.savefig(figures_dir / "overhead_summary.png", dpi=150)
            print(f"Saved: {figures_dir / 'overhead_summary.pdf'}")
            plt.close()

    print("\nSweep analysis complete!")


def main():
    parser = argparse.ArgumentParser(
        description="Run comprehensive Secure LSL benchmark suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Benchmark Suites:
  channel-sweep   Test different channel counts (8, 32, 64, 128, 256)
  rate-sweep      Test different sampling rates (250, 500, 1000, 2000 Hz)
  multi-inlet     Test multiple simultaneous inlets (1, 2, 4)
  full            Run all benchmarks

Examples:
  # Quick channel sweep (30s per test)
  python run_benchmark_suite.py --suite channel-sweep --duration 30

  # Full suite with longer tests
  python run_benchmark_suite.py --suite full --duration 60

  # Generate analysis plots
  python run_benchmark_suite.py --analyze ../results/
        """,
    )

    parser.add_argument(
        "--suite",
        "-s",
        type=str,
        choices=["channel-sweep", "rate-sweep", "multi-inlet", "full"],
        help="Benchmark suite to run",
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=int,
        default=30,
        help="Duration per test in seconds (default: 30)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="../results",
        help="Output directory for results",
    )
    parser.add_argument(
        "--analyze",
        "-a",
        type=str,
        default=None,
        help="Analyze results in given directory",
    )

    args = parser.parse_args()

    if args.analyze:
        generate_sweep_analysis(Path(args.analyze))
        return

    if not args.suite:
        parser.print_help()
        return

    # Create machine-specific results directory
    platform_id = get_platform_id()
    base_results_dir = Path(args.output)
    results_dir = base_results_dir / platform_id
    results_dir.mkdir(parents=True, exist_ok=True)

    # Create temp directory for config files
    temp_dir = Path(tempfile.mkdtemp(prefix="lsl_benchmark_"))

    print("=" * 60)
    print("Secure LSL Comprehensive Benchmark Suite")
    print("=" * 60)
    print(f"Platform: {platform_id}")
    print("Mode: Running BOTH secure and insecure tests for comparison")
    print(f"Suite: {args.suite}")
    print(f"Duration per test: {args.duration}s")
    print(f"Output directory: {results_dir}")
    print(f"Config directory: {temp_dir}")
    print("=" * 60)

    start_time = time.time()

    try:
        if args.suite == "channel-sweep":
            run_channel_sweep(args.duration, results_dir, temp_dir)
        elif args.suite == "rate-sweep":
            run_rate_sweep(args.duration, results_dir, temp_dir)
        elif args.suite == "multi-inlet":
            run_multi_inlet_test(args.duration, results_dir, temp_dir)
        elif args.suite == "full":
            run_full_suite(args.duration, results_dir, temp_dir)
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)

    elapsed = time.time() - start_time
    print(f"\n{'=' * 60}")
    print(f"Benchmark complete! Total time: {elapsed / 60:.1f} minutes")
    print(f"Results saved to: {results_dir}")
    print("=" * 60)

    # Generate sweep analysis (optional, may fail if matplotlib not installed)
    try:
        generate_sweep_analysis(results_dir)
    except ImportError as e:
        print(f"\nNote: Could not generate inline plots ({e})")
        print("Run analyze_results.py separately to generate figures.")


if __name__ == "__main__":
    main()
