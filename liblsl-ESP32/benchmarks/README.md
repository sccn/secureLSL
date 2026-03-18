# ESP32 LSL Benchmarks

Systematic performance benchmarks for liblsl-ESP32, measuring throughput, jitter, and secureLSL encryption overhead.

## Prerequisites

### Hardware
- ESP32-DevKitC v4 connected via USB
- Desktop (Mac/Linux) on same WiFi network

### Software
```bash
# ESP-IDF (for firmware)
. ~/esp/esp-idf/export.sh

# Python dependencies (for desktop scripts)
cd benchmarks/scripts
uv pip install -r requirements.txt
```

## Quick Start

### 1. Flash the benchmark firmware

```bash
cd benchmarks/throughput_bench
idf.py menuconfig
# -> Benchmark Configuration:
#    Mode: Outlet
#    Channels: 8
#    Sample rate: 250 Hz
#    Duration: 60 seconds
#    Security: disabled
# -> WiFi SSID/Password

idf.py build
idf.py -p /dev/cu.usbserial-XXXX flash
```

### 2. Run the desktop inlet

Open two terminals:

**Terminal 1** (serial monitor):
```bash
cd benchmarks/scripts
uv run python serial_monitor.py --port /dev/cu.usbserial-XXXX --output ../results/esp32_outlet.json
```

**Terminal 2** (LSL inlet):
```bash
cd benchmarks/scripts
uv run python esp32_benchmark_inlet.py --name ESP32Bench --duration 60 --output ../results/desktop_inlet.json
```

### 3. View results

Both terminals show real-time progress and a final summary with:
- Push/pull timing (mean, std, p95, p99)
- Throughput (actual vs nominal rate)
- Jitter (inter-sample interval std dev)
- Heap and stack usage (ESP32 side)

## Test Matrix

### Encryption Overhead (primary comparison)

| Test | Security | What to measure |
|------|----------|----------------|
| E1a | OFF | Baseline: 8ch 250Hz, no encryption |
| E1b | ON | Encrypted: same config with secureLSL |

Compare `push_mean_us` between E1a and E1b to quantify encryption overhead.

### Channel Sweep

Flash with different `BENCH_CHANNELS` settings:

| Channels | Rate | Security |
|----------|------|----------|
| 4 | 250 Hz | Both |
| 8 | 250 Hz | Both |
| 16 | 250 Hz | Both |
| 32 | 250 Hz | Both |
| 64 | 250 Hz | Both |

### Rate Sweep

Flash with different `BENCH_SAMPLE_RATE` settings:

| Rate | Channels | Security |
|------|----------|----------|
| 100 Hz | 8 | Both |
| 250 Hz | 8 | Both |
| 500 Hz | 8 | Both |

## ESP32 Inlet Testing

### Desktop pushes to ESP32

```bash
# Flash ESP32 in inlet mode
idf.py menuconfig  # -> Mode: Inlet, Target: DesktopBench

# Run desktop outlet
uv run python esp32_benchmark_outlet.py --name DesktopBench --channels 8 --rate 250 --duration 60

# Monitor ESP32 serial
uv run python serial_monitor.py --port /dev/cu.usbserial-XXXX --output ../results/esp32_inlet.json
```

## Metrics

### Clock-independent (primary)
- **Jitter**: std dev of inter-sample arrival intervals (us)
- **Throughput**: actual sample rate / nominal rate
- **Packet loss**: (expected - received) / expected
- **Push timing**: time per push_sample on ESP32 (us)
- **Pull timing**: time per pull_sample on desktop (us)
- **Encryption overhead**: secure vs insecure push_mean_us delta

### ESP32-specific
- **Heap free**: available SRAM during streaming
- **Heap min**: minimum free heap observed
- **Stack HWM**: high-water mark for benchmark task
- **WiFi RSSI**: signal strength during test

### Why no absolute latency?
ESP32 uses monotonic `lsl_esp32_local_clock()` (seconds since boot).
Desktop uses `time.time()` (unix wall clock). Without NTP sync or LSL
time correction (not implemented), absolute cross-machine latency
is meaningless. We focus on relative metrics instead.

## Output Format

All scripts produce JSON files compatible with the secureLSL analysis pipeline.
Key fields:

```json
{
  "results": {
    "samples_received": 15000,
    "actual_rate": 249.8,
    "packet_loss_pct": 0.13,
    "pull_mean_us": 150.2,
    "pull_p95_us": 320.5,
    "jitter_std_us": 45.3
  }
}
```

ESP32-side metrics (from `serial_monitor.py`):
```json
{
  "summary": {
    "push_mean_us": 42.1,
    "push_p95_us": 55.3,
    "heap_free": 210000,
    "heap_min": 208000,
    "wifi_rssi": -42
  }
}
```

## File Structure

```
benchmarks/
  throughput_bench/    # ESP32 firmware (configurable via menuconfig)
  scripts/
    esp32_benchmark_inlet.py    # Desktop receives from ESP32
    esp32_benchmark_outlet.py   # Desktop pushes to ESP32
    serial_monitor.py           # Parses ESP32 serial JSON
    requirements.txt
  results/             # Output directory (gitignored)
  README.md            # This file
```
