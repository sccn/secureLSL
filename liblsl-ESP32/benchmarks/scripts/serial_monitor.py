#!/usr/bin/env python3
# Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""ESP32 Serial Monitor for Benchmark Telemetry.

Reads JSON lines from ESP32 serial port during benchmarks.
Collects progress reports and final summary, saves to JSON.

Usage:
    uv run python serial_monitor.py --port /dev/cu.usbserial-0001
    uv run python serial_monitor.py --port /dev/cu.usbserial-0001 -o results/esp32.json
"""

import argparse
import json
import sys
import time

import serial

from bench_utils import save_results


def _fmt(val, spec=".1f"):
    """Format a value safely, returning '?' if not numeric."""
    try:
        return f"{val:{spec}}"
    except (TypeError, ValueError):
        return str(val)


def monitor(port, baud=115200, timeout=120, output=None):
    """Read ESP32 serial output, parse JSON lines, save results."""
    try:
        port_handle = serial.Serial(port, baud, timeout=1)
    except (serial.SerialException, OSError) as exc:
        print(f"ERROR: Cannot open serial port '{port}': {exc}")
        print("Check: is the device connected? Is another process using the port?")
        print("  List available ports: ls /dev/cu.usbserial-*")
        return None

    print(f"Monitoring {port} at {baud} baud (timeout={timeout}s)")

    config = None
    progress = []
    summary = None
    monitor_data = None
    start = time.time()
    any_data = False
    summary_time = None
    json_errors = 0

    try:
        while time.time() - start < timeout:
            # If we got summary, wait max 10s more for monitor data
            if summary_time and time.time() - summary_time > 10:
                print("Monitor data not received within 10s of summary, finishing.")
                break

            try:
                raw = port_handle.readline()
            except (serial.SerialException, OSError) as exc:
                print(f"WARNING: Serial read error: {exc}")
                break

            if not raw:
                continue

            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            # Try to parse as JSON
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    any_data = True
                    json_errors = 0  # reset consecutive error count
                    msg_type = data.get("type", "")

                    if msg_type == "config":
                        config = data
                        print(f"[config] {data.get('mode')} {data.get('channels')}ch "
                              f"@ {data.get('rate')}Hz, security={data.get('security')}")
                    elif msg_type == "progress":
                        progress.append(data)
                        print(f"[progress] t={_fmt(data.get('t', 0), '.0f')}s "
                              f"samples={data.get('samples', 0)} "
                              f"rate={_fmt(data.get('rate_hz', 0))}Hz "
                              f"heap={data.get('heap', 0)}")
                    elif msg_type == "summary":
                        summary = data
                        summary_time = time.time()
                        mode = data.get("mode", "?")
                        if mode == "outlet":
                            print(f"\n[SUMMARY] {data.get('samples_pushed', 0)} samples, "
                                  f"push={_fmt(data.get('push_mean_us', 0))} +/- "
                                  f"{_fmt(data.get('push_std_us', 0))} us, "
                                  f"p95={data.get('push_p95_us', 0)} us")
                        else:
                            print(f"\n[SUMMARY] {data.get('samples_received', 0)} samples, "
                                  f"loss={_fmt(data.get('packet_loss_pct', 0))}%, "
                                  f"jitter={_fmt(data.get('jitter_std_us', 0))} us")
                    elif msg_type == "monitor":
                        monitor_data = data
                        print(f"[monitor] heap={data.get('heap_mean', 0)} "
                              f"(min={data.get('heap_min', 0)}), "
                              f"rssi={data.get('rssi_mean', 0)} dBm")

                    # Stop after summary + monitor
                    if summary and monitor_data:
                        print("\nBenchmark complete.")
                        break

                    continue
                except json.JSONDecodeError:
                    json_errors += 1
                    if json_errors <= 3:
                        print(f"  [WARN] Malformed JSON: {line[:80]}")
                    elif json_errors == 4:
                        print("  [WARN] Suppressing further JSON parse warnings")
                    continue

            # Print non-JSON lines that look interesting
            if any(k in line for k in ["bench", "Benchmark", "Outlet", "Inlet",
                                        "Security", "WiFi", "connected"]):
                print(f"  {line}")

    except KeyboardInterrupt:
        print("\nInterrupted by user")
    finally:
        port_handle.close()

    # Build result
    result = {
        "device": "ESP32-WROOM-32",
        "config": config,
        "progress": progress,
        "summary": summary,
        "monitor": monitor_data,
        "collection_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }

    save_results(result, output)

    if not any_data:
        print("WARNING: No data received. Check serial port, baud rate, and ESP32 firmware.")
    elif not summary:
        if progress:
            print(f"WARNING: Received {len(progress)} progress reports but no summary. "
                  "Benchmark may still be running; increase --timeout.")
        else:
            print("WARNING: No benchmark data received. ESP32 may not be running benchmark firmware.")

    return result


def main():
    parser = argparse.ArgumentParser(description="ESP32 Benchmark Serial Monitor")
    parser.add_argument("--port", required=True, help="Serial port")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    parser.add_argument("--timeout", type=int, default=120, help="Max time (seconds)")
    parser.add_argument("--output", "-o", help="Output JSON file path")
    args = parser.parse_args()

    result = monitor(args.port, args.baud, args.timeout, args.output)

    if not result or not result.get("summary"):
        sys.exit(1)


if __name__ == "__main__":
    main()
