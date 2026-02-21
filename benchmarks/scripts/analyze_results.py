#!/usr/bin/env python3
# Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""
Secure LSL Benchmark - Analysis and Visualization

Analyzes benchmark results and generates publication-quality figures
matching the style of the LSL paper (Imaging Neuroscience).

Usage:
    python analyze_results.py ../results/*.json --output ../figures/

Figures generated:
- F1: Latency distribution (secure vs insecure) - similar to LSL paper F4
- F2: Security overhead across platforms
- F3: Latency time series
- F4: Jitter comparison with box plots
"""

import argparse
import json
import os
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
from scipy import stats

# Match LSL paper style
plt.rcParams.update(
    {
        "font.size": 10,
        "axes.titlesize": 11,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "figure.titlesize": 12,
        "axes.grid": False,
        "axes.spines.top": False,
        "axes.spines.right": False,
    }
)

# LSL paper color - dark blue
LSL_BLUE = "#1a237e"  # Dark navy blue like in F4
SECURE_COLOR = "#2e7d32"  # Dark green for secure
INSECURE_COLOR = "#c62828"  # Dark red for insecure


def format_k(x, pos):
    """Format y-axis as 0.1k, 0.2k, etc."""
    if x >= 1000:
        return f"{x / 1000:.0f}k"
    elif x >= 100:
        return f"{x / 1000:.1f}k"
    else:
        return f"{int(x)}"


def load_results(file_paths):
    """Load all result files."""
    results = []
    for path in file_paths:
        try:
            with open(path, "r") as f:
                data = json.load(f)
                data["_filename"] = os.path.basename(path)
                results.append(data)
        except Exception as e:
            print(f"Warning: Could not load {path}: {e}")
    return results


def classify_result(result):
    """Classify a result by platform and security status."""
    hostname = result.get("system_info", {}).get("hostname", "").lower()
    cpu_model = result.get("system_info", {}).get("cpu_model", "").lower()
    machine = result.get("system_info", {}).get("machine", "").lower()

    # Determine platform
    if (
        "raspberry" in cpu_model
        or "pi" in hostname
        or ("aarch64" in machine and "apple" not in cpu_model)
    ):
        platform_name = "Raspberry Pi 5"
        platform_key = "pi5"
    elif "apple" in cpu_model or "mac" in hostname:
        platform_name = "Mac Mini (Apple Silicon)"
        platform_key = "macmini"
    elif "i7" in cpu_model or "i9" in cpu_model:
        platform_name = "Workstation (Intel i7)"
        platform_key = "i7"
    else:
        platform_name = hostname or "Unknown"
        platform_key = "unknown"

    # Security status
    security = result.get("security_enabled", None)
    if security is True:
        security_label = "secure"
    elif security is False:
        security_label = "insecure"
    else:
        security_label = "unknown"

    # Remote or local
    is_remote = result.get("is_remote", False)

    return {
        "platform": platform_key,
        "platform_name": platform_name,
        "security": security_label,
        "is_remote": is_remote,
    }


def add_stats_box(ax, data, position="upper right"):
    """Add statistics box like in LSL paper F4."""
    p5 = np.percentile(data, 5)
    p95 = np.percentile(data, 95)
    mean = np.mean(data)
    median = np.median(data)
    std = np.std(data)

    stats_text = (
        f"5th centile = {p5:.3f}\n"
        f"mean = {mean:.3f}\n"
        f"median = {median:.3f}\n"
        f"95th centile = {p95:.3f}\n"
        f"Standard Deviation = {std:.3f}"
    )

    # Position mapping
    if position == "upper right":
        xy = (0.97, 0.97)
        ha, va = "right", "top"
    elif position == "upper left":
        xy = (0.03, 0.97)
        ha, va = "left", "top"
    else:
        xy = (0.97, 0.97)
        ha, va = "right", "top"

    ax.text(
        xy[0],
        xy[1],
        stats_text,
        transform=ax.transAxes,
        fontsize=8,
        verticalalignment=va,
        horizontalalignment=ha,
        family="monospace",
        bbox=dict(
            boxstyle="round,pad=0.3", facecolor="white", edgecolor="gray", alpha=0.9
        ),
    )


def plot_latency_distribution_lsl_style(results, output_dir):
    """
    Plot latency distribution comparing secure vs insecure.
    Matches LSL paper Figure F4 style exactly.
    """
    # Separate by security status
    secure_latencies = []
    insecure_latencies = []

    for r in results:
        latencies = r.get("latencies_ms", [])
        if not latencies:
            continue

        classification = classify_result(r)
        if classification["security"] == "secure":
            secure_latencies.extend(latencies)
        elif classification["security"] == "insecure":
            insecure_latencies.extend(latencies)

    if not secure_latencies and not insecure_latencies:
        print("No latency data available")
        return

    # Create figure with shared y-axis for proper comparison
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)

    # Compute common bin edges for both datasets
    all_latencies = insecure_latencies + secure_latencies
    bin_min = np.percentile(all_latencies, 1)
    bin_max = np.percentile(all_latencies, 99)
    common_bins = np.linspace(bin_min, bin_max, 41)

    plot_data = []

    for ax, data, title, color in [
        (axes[0], insecure_latencies, "Insecure (No Encryption)", INSECURE_COLOR),
        (axes[1], secure_latencies, "Secure (Encrypted)", SECURE_COLOR),
    ]:
        if not data:
            ax.text(
                0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes
            )
            ax.set_title(title, fontweight="bold")
            plot_data.append(None)
            continue

        data = np.array(data)

        # Create histogram with common bins
        n, bins, patches = ax.hist(
            data,
            bins=common_bins,
            color=LSL_BLUE,
            alpha=0.9,
            edgecolor="white",
            linewidth=0.3,
        )

        # Add Gaussian fit (red curve like in F5p)
        mu, sigma = np.mean(data), np.std(data)
        x = np.linspace(bin_min, bin_max, 100)
        gaussian = stats.norm.pdf(x, mu, sigma) * len(data) * (bins[1] - bins[0])
        ax.plot(x, gaussian, "r-", linewidth=1.5, label="Gaussian fit")

        # Add statistics box
        add_stats_box(ax, data, position="upper left")

        # Formatting
        ax.set_xlabel("latency (ms)")
        ax.set_title(f"{title}\nn = {len(data):,}", fontweight="bold")

        # Y-axis formatting like LSL paper
        ax.yaxis.set_major_formatter(FuncFormatter(format_k))

        plot_data.append(data)

    # Set shared y-axis label only on left plot
    axes[0].set_ylabel("samples")

    # Set same x-limits and add box plots
    for ax, data in zip(axes, plot_data):
        ax.set_xlim(bin_min, bin_max)
        if data is None:
            continue
        ax_box = ax.inset_axes([0.1, -0.15, 0.8, 0.08])
        ax_box.boxplot(
            data,
            vert=False,
            widths=0.6,
            patch_artist=True,
            boxprops=dict(facecolor="white", edgecolor="black"),
            medianprops=dict(color="black"),
            whiskerprops=dict(color="black"),
            capprops=dict(color="black"),
            flierprops=dict(marker="o", markersize=2, alpha=0.5),
        )
        ax_box.set_xlim(bin_min, bin_max)
        ax_box.axis("off")

    fig.suptitle(
        "Security Overhead: End-to-End Latency Distribution",
        fontsize=12,
        fontweight="bold",
    )
    plt.tight_layout()
    plt.subplots_adjust(bottom=0.18)

    output_path = output_dir / "F1_latency_distribution.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.savefig(output_path.with_suffix(".png"), dpi=150, bbox_inches="tight")
    print(f"Saved: {output_path}")
    plt.close()

    # Calculate and print overhead
    if secure_latencies and insecure_latencies:
        overhead_ms = np.mean(secure_latencies) - np.mean(insecure_latencies)
        overhead_pct = overhead_ms / np.mean(insecure_latencies) * 100
        print(f"\n  Latency overhead: {overhead_ms:.3f} ms ({overhead_pct:.1f}%)")


def plot_overhead_by_platform(results, output_dir):
    """
    Plot security overhead comparison across platforms.
    Bar chart showing latency with/without encryption.
    """
    # Group results by platform
    platforms = {}

    for r in results:
        classification = classify_result(r)
        platform_key = classification["platform"]
        platform_name = classification["platform_name"]
        security = classification["security"]

        if platform_key == "unknown" or security == "unknown":
            continue

        if platform_key not in platforms:
            platforms[platform_key] = {
                "name": platform_name,
                "secure": [],
                "insecure": [],
            }

        latencies = r.get("latencies_ms", [])
        if latencies:
            mean_lat = np.mean(latencies)
            platforms[platform_key][security].append(mean_lat)

    if not platforms:
        print("No valid platform data for overhead comparison")
        return

    # Create figure
    fig, ax = plt.subplots(figsize=(8, 5))

    platform_order = ["i7", "macmini", "pi5"]
    available = [p for p in platform_order if p in platforms]

    x = np.arange(len(available))
    width = 0.35

    insecure_means = []
    secure_means = []
    labels = []

    for p in available:
        labels.append(platforms[p]["name"])
        insecure_means.append(
            np.mean(platforms[p]["insecure"]) if platforms[p]["insecure"] else 0
        )
        secure_means.append(
            np.mean(platforms[p]["secure"]) if platforms[p]["secure"] else 0
        )

    ax.bar(
        x - width / 2,
        insecure_means,
        width,
        label="Insecure",
        color=INSECURE_COLOR,
        alpha=0.8,
        edgecolor="white",
    )
    ax.bar(
        x + width / 2,
        secure_means,
        width,
        label="Secure",
        color=SECURE_COLOR,
        alpha=0.8,
        edgecolor="white",
    )

    # Add overhead percentage labels
    for i, (ins, sec) in enumerate(zip(insecure_means, secure_means)):
        if ins > 0 and sec > 0:
            overhead = (sec - ins) / ins * 100
            ax.annotate(
                f"+{overhead:.1f}%",
                xy=(x[i] + width / 2, sec),
                xytext=(0, 5),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=9,
                fontweight="bold",
                color=SECURE_COLOR,
            )

    ax.set_ylabel("Mean Latency (ms)")
    ax.set_xlabel("Platform")
    ax.set_title("Security Overhead Across Platforms", fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()

    # Add 5% overhead reference line
    if insecure_means:
        ref_line = np.mean(insecure_means) * 1.05
        ax.axhline(y=ref_line, color="gray", linestyle="--", alpha=0.5)
        ax.text(
            len(available) - 0.5,
            ref_line,
            "5% overhead",
            ha="right",
            va="bottom",
            fontsize=8,
            color="gray",
        )

    plt.tight_layout()

    output_path = output_dir / "F2_platform_comparison.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.savefig(output_path.with_suffix(".png"), dpi=150, bbox_inches="tight")
    print(f"Saved: {output_path}")
    plt.close()


def plot_latency_timeseries(results, output_dir):
    """
    Plot latency over time (like F5p panel A).
    Shows stability of timing throughout the test.
    """
    fig, axes = plt.subplots(2, 1, figsize=(10, 6), sharex=True)

    for r in results[:2]:  # Show first two results (ideally secure and insecure)
        classification = classify_result(r)
        latencies = r.get("latencies_ms", [])

        if not latencies:
            continue

        latencies = np.array(latencies)

        if classification["security"] == "secure":
            ax = axes[1]
            title = "Secure (Encrypted)"
        else:
            ax = axes[0]
            title = "Insecure (No Encryption)"

        # Subsample for plotting (every 100th point)
        step = max(1, len(latencies) // 10000)
        x = np.arange(0, len(latencies), step)
        y = latencies[::step]

        ax.plot(x / 1000, y, color=LSL_BLUE, alpha=0.5, linewidth=0.5)

        # Add mean line
        mean_lat = np.mean(latencies)
        ax.axhline(
            y=mean_lat,
            color="red",
            linestyle="-",
            linewidth=1,
            label=f"mean = {mean_lat:.2f} ms",
        )

        # Add +/- 1 std band
        std_lat = np.std(latencies)
        ax.axhline(
            y=mean_lat + std_lat, color="red", linestyle="--", linewidth=0.5, alpha=0.5
        )
        ax.axhline(
            y=mean_lat - std_lat, color="red", linestyle="--", linewidth=0.5, alpha=0.5
        )

        ax.set_ylabel("latency (ms)")
        ax.set_title(title, fontweight="bold")
        ax.legend(loc="upper right")

    axes[1].set_xlabel("samples (x10³)")
    fig.suptitle("Latency Stability Over Time", fontsize=12, fontweight="bold")
    plt.tight_layout()

    output_path = output_dir / "F3_latency_timeseries.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.savefig(output_path.with_suffix(".png"), dpi=150, bbox_inches="tight")
    print(f"Saved: {output_path}")
    plt.close()


def plot_jitter_comparison(results, output_dir):
    """
    Plot jitter comparison with histograms and box plots.
    Similar to LSL paper F5p panel B.
    Uses shared y-axis for proper comparison.
    """
    secure_jitter = []
    insecure_jitter = []

    for r in results:
        classification = classify_result(r)
        intervals = r.get("inter_sample_intervals_us", [])

        if not intervals or len(intervals) < 100:
            continue

        nominal_rate = r.get("stream_info", {}).get("nominal_rate", 1000)
        expected_interval = 1e6 / nominal_rate

        # Jitter = deviation from expected interval, convert to ms
        jitter = (np.array(intervals) - expected_interval) / 1000  # ms

        if classification["security"] == "secure":
            secure_jitter.extend(jitter.tolist())
        elif classification["security"] == "insecure":
            insecure_jitter.extend(jitter.tolist())

    if not secure_jitter and not insecure_jitter:
        print("No jitter data available")
        return

    # Use sharey=True to ensure same y-axis range for proper comparison
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)

    # First pass: create histograms and find common bin edges
    all_data = insecure_jitter + secure_jitter
    bin_min = np.percentile(all_data, 1)
    bin_max = np.percentile(all_data, 99)
    common_bins = np.linspace(bin_min, bin_max, 41)

    max_count = 0
    plot_data = []

    for ax, data, title in [
        (axes[0], insecure_jitter, "Insecure (No Encryption)"),
        (axes[1], secure_jitter, "Secure (Encrypted)"),
    ]:
        if not data:
            ax.text(
                0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes
            )
            ax.set_title(title, fontweight="bold")
            plot_data.append(None)
            continue

        data = np.array(data)

        # Histogram with common bins
        n, bins, patches = ax.hist(
            data,
            bins=common_bins,
            color=LSL_BLUE,
            alpha=0.9,
            edgecolor="white",
            linewidth=0.3,
        )
        max_count = max(max_count, n.max())

        # Gaussian fit
        mu, sigma = np.mean(data), np.std(data)
        x = np.linspace(bin_min, bin_max, 100)
        gaussian = stats.norm.pdf(x, mu, sigma) * len(data) * (bins[1] - bins[0])
        ax.plot(x, gaussian, "r-", linewidth=1.5)

        ax.set_xlabel("Δt (ms)")
        ax.set_title(f"{title}\nStd = {sigma:.3f} ms", fontweight="bold")
        ax.yaxis.set_major_formatter(FuncFormatter(format_k))

        plot_data.append(data)

    # Set shared y-axis label only on left plot
    axes[0].set_ylabel("samples")

    # Add box plots at bottom with same x-limits
    for ax, data in zip(axes, plot_data):
        if data is None:
            continue
        ax_box = ax.inset_axes([0.1, -0.15, 0.8, 0.08])
        ax_box.boxplot(
            data,
            vert=False,
            widths=0.6,
            patch_artist=True,
            boxprops=dict(facecolor="white", edgecolor="black"),
            medianprops=dict(color="black"),
            whiskerprops=dict(color="black"),
            capprops=dict(color="black"),
            flierprops=dict(marker="o", markersize=2, alpha=0.5),
        )
        ax_box.set_xlim(bin_min, bin_max)
        ax_box.axis("off")

    # Set same x-limits for both plots
    for ax in axes:
        ax.set_xlim(bin_min, bin_max)

    fig.suptitle("Timing Jitter Comparison", fontsize=12, fontweight="bold")
    plt.tight_layout()
    plt.subplots_adjust(bottom=0.18)

    output_path = output_dir / "F4_jitter_comparison.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.savefig(output_path.with_suffix(".png"), dpi=150, bbox_inches="tight")
    print(f"Saved: {output_path}")
    plt.close()


def generate_summary_table(results, output_dir):
    """Generate summary tables in Markdown and LaTeX."""
    rows = []

    for r in results:
        classification = classify_result(r)
        res = r.get("results", {})
        stream_info = r.get("stream_info", {})

        if not res:
            continue

        lat_mean = res.get("latency_mean_ms", 0)
        lat_std = res.get("latency_std_ms", 0)

        row = {
            "Platform": classification["platform_name"],
            "Security": "Encrypted"
            if classification["security"] == "secure"
            else "Plaintext",
            "Network": "Remote" if classification["is_remote"] else "Local",
            "Channels": stream_info.get("channels", "-"),
            "Rate": f"{stream_info.get('nominal_rate', '-')} Hz",
            "Latency": f"{lat_mean:.2f} ± {lat_std:.2f} ms",
            "CPU": f"{res.get('cpu_mean_percent', 0):.1f}%",
            "Jitter": f"{res.get('jitter_std_us', 0) / 1000:.3f} ms",
        }
        rows.append(row)

    if not rows:
        return

    # Markdown table
    md_path = output_dir / "summary_table.md"
    with open(md_path, "w") as f:
        f.write("# Benchmark Results Summary\n\n")
        headers = list(rows[0].keys())
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("|" + "|".join(["---"] * len(headers)) + "|\n")
        for row in rows:
            f.write("| " + " | ".join(str(row[h]) for h in headers) + " |\n")

    print(f"Saved: {md_path}")

    # LaTeX table
    tex_path = output_dir / "summary_table.tex"
    with open(tex_path, "w") as f:
        f.write("\\begin{table}[htbp]\n")
        f.write("\\centering\n")
        f.write("\\caption{Security Overhead Benchmark Results}\n")
        f.write("\\label{tab:security-benchmark}\n")
        f.write("\\begin{tabular}{llllllll}\n")
        f.write("\\toprule\n")
        headers = list(rows[0].keys())
        f.write(" & ".join(headers) + " \\\\\n")
        f.write("\\midrule\n")
        for row in rows:
            values = [str(row[h]).replace("%", "\\%") for h in headers]
            f.write(" & ".join(values) + " \\\\\n")
        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")

    print(f"Saved: {tex_path}")


def plot_rate_sweep_analysis(results, output_dir):
    """
    Analyze how latency and CPU usage scale with sampling rate.
    Shows whether encryption overhead is rate-dependent.
    """
    # Group by rate and security mode
    secure_data = {}  # rate -> list of results
    insecure_data = {}

    for r in results:
        # Check if this is a rate sweep result
        stream_info = r.get("stream_info", {})
        rate = stream_info.get("nominal_rate", 0)
        if rate == 0:
            continue

        classification = classify_result(r)
        res = r.get("results", {})
        lat = res.get("latency_mean_ms", 0)
        cpu = res.get("cpu_mean_percent", 0)

        if lat <= 0:
            continue

        entry = {"rate": rate, "latency": lat, "cpu": cpu}

        if classification["security"] == "secure":
            if rate not in secure_data:
                secure_data[rate] = []
            secure_data[rate].append(entry)
        elif classification["security"] == "insecure":
            if rate not in insecure_data:
                insecure_data[rate] = []
            insecure_data[rate].append(entry)

    if not secure_data and not insecure_data:
        print("No rate sweep data available")
        return

    # Create figure with 2 subplots: Latency and CPU
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Plot 1: Latency vs Rate
    ax = axes[0]
    for data, color, label in [
        (insecure_data, INSECURE_COLOR, "Insecure"),
        (secure_data, SECURE_COLOR, "Secure"),
    ]:
        if not data:
            continue
        rates = sorted(data.keys())
        mean_lats = [np.mean([e["latency"] for e in data[r]]) for r in rates]
        std_lats = [np.std([e["latency"] for e in data[r]]) for r in rates]

        ax.errorbar(
            rates,
            mean_lats,
            yerr=std_lats,
            fmt="o-",
            color=color,
            linewidth=2,
            markersize=8,
            capsize=5,
            label=label,
        )

    ax.set_xlabel("Sampling Rate (Hz)")
    ax.set_ylabel("Mean Latency (ms)")
    ax.set_title("Latency vs Sampling Rate", fontweight="bold")
    ax.legend()
    ax.grid(True, alpha=0.3)

    # Plot 2: CPU vs Rate
    ax = axes[1]
    for data, color, label in [
        (insecure_data, INSECURE_COLOR, "Insecure"),
        (secure_data, SECURE_COLOR, "Secure"),
    ]:
        if not data:
            continue
        rates = sorted(data.keys())
        mean_cpu = [np.mean([e["cpu"] for e in data[r]]) for r in rates]

        ax.plot(
            rates, mean_cpu, "o-", color=color, linewidth=2, markersize=8, label=label
        )

    ax.set_xlabel("Sampling Rate (Hz)")
    ax.set_ylabel("CPU Usage (%)")
    ax.set_title("CPU Usage vs Sampling Rate", fontweight="bold")
    ax.legend()
    ax.grid(True, alpha=0.3)

    fig.suptitle(
        "Rate Sweep Analysis: Security Overhead Scaling", fontsize=12, fontweight="bold"
    )
    plt.tight_layout()

    output_path = output_dir / "F5_rate_sweep.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.savefig(output_path.with_suffix(".png"), dpi=150, bbox_inches="tight")
    print(f"Saved: {output_path}")
    plt.close()


def plot_channel_sweep_analysis(results, output_dir):
    """
    Analyze how latency scales with channel count.
    Shows encryption overhead vs data payload size.
    """
    secure_data = {}
    insecure_data = {}

    for r in results:
        stream_info = r.get("stream_info", {})
        channels = stream_info.get("channels", 0)
        if channels == 0:
            continue

        classification = classify_result(r)
        res = r.get("results", {})
        lat = res.get("latency_mean_ms", 0)
        cpu = res.get("cpu_mean_percent", 0)

        if lat <= 0:
            continue

        entry = {"channels": channels, "latency": lat, "cpu": cpu}

        if classification["security"] == "secure":
            if channels not in secure_data:
                secure_data[channels] = []
            secure_data[channels].append(entry)
        elif classification["security"] == "insecure":
            if channels not in insecure_data:
                insecure_data[channels] = []
            insecure_data[channels].append(entry)

    if not secure_data and not insecure_data:
        print("No channel sweep data available")
        return

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Plot 1: Latency vs Channels
    ax = axes[0]
    for data, color, label in [
        (insecure_data, INSECURE_COLOR, "Insecure"),
        (secure_data, SECURE_COLOR, "Secure"),
    ]:
        if not data:
            continue
        channels = sorted(data.keys())
        mean_lats = [np.mean([e["latency"] for e in data[c]]) for c in channels]
        std_lats = [np.std([e["latency"] for e in data[c]]) for c in channels]

        ax.errorbar(
            channels,
            mean_lats,
            yerr=std_lats,
            fmt="o-",
            color=color,
            linewidth=2,
            markersize=8,
            capsize=5,
            label=label,
        )

    ax.set_xlabel("Channel Count")
    ax.set_ylabel("Mean Latency (ms)")
    ax.set_title("Latency vs Channel Count", fontweight="bold")
    ax.set_xscale("log", base=2)
    ax.legend()
    ax.grid(True, alpha=0.3)

    # Plot 2: Overhead percentage vs Channels
    ax = axes[1]
    if secure_data and insecure_data:
        channels = sorted(set(secure_data.keys()) & set(insecure_data.keys()))
        overheads = []
        for c in channels:
            sec_lat = np.mean([e["latency"] for e in secure_data[c]])
            insec_lat = np.mean([e["latency"] for e in insecure_data[c]])
            if insec_lat > 0:
                overhead_pct = (sec_lat - insec_lat) / insec_lat * 100
                overheads.append(overhead_pct)

        if overheads:
            colors = [SECURE_COLOR if o >= 0 else "#c62828" for o in overheads]
            ax.bar(range(len(channels)), overheads, color=colors, alpha=0.8)
            ax.set_xticks(range(len(channels)))
            ax.set_xticklabels([str(c) for c in channels])
            ax.axhline(y=0, color="black", linestyle="-", linewidth=0.5)
            ax.axhline(y=5, color="gray", linestyle="--", alpha=0.5, label="5% target")

    ax.set_xlabel("Channel Count")
    ax.set_ylabel("Overhead (%)")
    ax.set_title("Security Overhead by Channel Count", fontweight="bold")
    ax.legend()
    ax.grid(True, alpha=0.3, axis="y")

    fig.suptitle(
        "Channel Sweep Analysis: Payload Size Impact", fontsize=12, fontweight="bold"
    )
    plt.tight_layout()

    output_path = output_dir / "F6_channel_sweep.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.savefig(output_path.with_suffix(".png"), dpi=150, bbox_inches="tight")
    print(f"Saved: {output_path}")
    plt.close()


def plot_multi_inlet_analysis(results, output_dir):
    """
    Analyze fan-out scalability with multiple inlets.
    Shows how latency changes when multiple consumers receive same stream.
    """
    # Look for multi-inlet test results (multiple inlet files for same outlet)
    # Group by number of inlets
    secure_data = {}  # num_inlets -> list of latencies
    insecure_data = {}

    for r in results:
        classification = classify_result(r)
        res = r.get("results", {})
        lat = res.get("latency_mean_ms", 0)

        if lat <= 0:
            continue

        # Try to detect number of inlets from filename or metadata
        filename = r.get("_filename", "")
        # Extract inlet count if present (e.g., MI01, MI02, MI04)
        import re

        mi_match = re.search(r"MI(\d+)", filename)
        if mi_match:
            num_inlets = int(mi_match.group(1))
        else:
            num_inlets = 1  # Default single inlet

        if classification["security"] == "secure":
            if num_inlets not in secure_data:
                secure_data[num_inlets] = []
            secure_data[num_inlets].append(lat)
        elif classification["security"] == "insecure":
            if num_inlets not in insecure_data:
                insecure_data[num_inlets] = []
            insecure_data[num_inlets].append(lat)

    # Only plot if we have multi-inlet data
    if not any(k > 1 for k in list(secure_data.keys()) + list(insecure_data.keys())):
        print("No multi-inlet data available")
        return

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Plot 1: Latency vs Number of Inlets
    ax = axes[0]
    for data, color, label in [
        (insecure_data, INSECURE_COLOR, "Insecure"),
        (secure_data, SECURE_COLOR, "Secure"),
    ]:
        if not data:
            continue
        inlet_counts = sorted(data.keys())
        mean_lats = [np.mean(data[n]) for n in inlet_counts]
        std_lats = [np.std(data[n]) for n in inlet_counts]

        ax.errorbar(
            inlet_counts,
            mean_lats,
            yerr=std_lats,
            fmt="o-",
            color=color,
            linewidth=2,
            markersize=10,
            capsize=5,
            capthick=2,
            label=label,
        )

    ax.set_xlabel("Number of Simultaneous Inlets")
    ax.set_ylabel("Mean Latency (ms)")
    ax.set_title("Fan-Out Scalability", fontweight="bold")
    ax.set_xticks(sorted(set(list(secure_data.keys()) + list(insecure_data.keys()))))
    ax.legend()
    ax.grid(True, alpha=0.3)

    # Plot 2: Latency increase factor
    ax = axes[1]
    for data, color, label in [
        (insecure_data, INSECURE_COLOR, "Insecure"),
        (secure_data, SECURE_COLOR, "Secure"),
    ]:
        if not data or 1 not in data:
            continue
        inlet_counts = sorted(data.keys())
        baseline = np.mean(data[1]) if 1 in data else np.mean(data[min(inlet_counts)])
        factors = [np.mean(data[n]) / baseline for n in inlet_counts]

        ax.plot(
            inlet_counts,
            factors,
            "o-",
            color=color,
            linewidth=2,
            markersize=10,
            label=label,
        )

    ax.axhline(y=1.0, color="gray", linestyle="--", alpha=0.5)
    ax.set_xlabel("Number of Simultaneous Inlets")
    ax.set_ylabel("Latency Factor (vs 1 inlet)")
    ax.set_title("Scalability Factor", fontweight="bold")
    ax.legend()
    ax.grid(True, alpha=0.3)

    fig.suptitle(
        "Multi-Inlet Analysis: Consumer Scalability", fontsize=12, fontweight="bold"
    )
    plt.tight_layout()

    output_path = output_dir / "F7_multi_inlet.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.savefig(output_path.with_suffix(".png"), dpi=150, bbox_inches="tight")
    print(f"Saved: {output_path}")
    plt.close()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Secure LSL benchmark results (LSL paper style)",
    )

    parser.add_argument("files", nargs="+", help="Result JSON files to analyze")
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="../figures",
        help="Output directory for figures",
    )

    args = parser.parse_args()

    # Expand glob patterns
    import glob

    files = []
    for pattern in args.files:
        files.extend(glob.glob(pattern))

    if not files:
        print("No input files found!")
        return

    print(f"Loading {len(files)} result file(s)...")
    results = load_results(files)
    print(f"Loaded {len(results)} valid result(s)")

    if not results:
        print("No valid results!")
        return

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\nGenerating figures (LSL paper style)...")

    # Core comparison figures
    plot_latency_distribution_lsl_style(results, output_dir)
    plot_overhead_by_platform(results, output_dir)
    plot_latency_timeseries(results, output_dir)
    plot_jitter_comparison(results, output_dir)

    # Sweep analysis figures
    plot_rate_sweep_analysis(results, output_dir)
    plot_channel_sweep_analysis(results, output_dir)
    plot_multi_inlet_analysis(results, output_dir)

    # Summary tables
    generate_summary_table(results, output_dir)

    print("\nDone!")


if __name__ == "__main__":
    main()
