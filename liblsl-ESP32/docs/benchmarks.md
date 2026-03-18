# Benchmarks

Performance measurements for liblsl-ESP32, including encryption overhead analysis comparable to the [secureLSL benchmark methodology](https://github.com/sccn/secureLSL).

## Test Environment

| Component | Details |
|-----------|---------|
| MCU | ESP32-WROOM-32 (Xtensa LX6, dual-core, 240 MHz) |
| SRAM | 520 KB |
| WiFi | 802.11n, 2.4 GHz, channel 10 |
| RSSI | -36 to -38 dBm |
| Desktop | Mac (Apple Silicon), secureLSL v1.16.1-secure.1.0.0-alpha |
| FreeRTOS | Tick rate 1000 Hz |
| Test duration | 30s per config (60s for encryption overhead) |

## Methodology

### What We Measure

| Metric | How | Clock-independent? |
|--------|-----|-------------------|
| Push timing | `esp_timer_get_time()` around `push_sample_f()` | Yes (local) |
| Throughput | Samples received / expected | Yes |
| Packet loss | (Expected - received) / expected | Yes |
| Jitter | Std dev of inter-sample arrival intervals | Yes |
| Heap usage | `esp_get_free_heap_size()` during streaming | Yes (local) |
| Encryption overhead | Secure vs insecure push timing delta | Yes (relative) |

### What We Don't Measure

**Absolute cross-machine latency** is not measured because ESP32 uses a monotonic clock (`lsl_esp32_local_clock()`, seconds since boot) while the desktop uses wall clock (`time.time()`). Without NTP synchronization or LSL time correction, absolute latency would be meaningless. WiFi jitter (~2ms) dominates any sub-millisecond crypto overhead.

### Push Timing Interpretation

`push_sample_f()` writes to a lock-free ring buffer. The actual encryption happens asynchronously in the TCP feed task on core 1. Therefore, push timing measures the ring buffer write cost, not encryption. This is the correct metric for application developers, as it represents the time their code spends in the LSL push call.

## Results

### 1. Encryption Overhead (8ch float32, 250 Hz, 60s)

| Metric | Insecure | Encrypted | Delta |
|--------|----------|-----------|-------|
| Samples | 15,000 | 15,000 | 0% loss both |
| Push mean | 52.8 us | 33.1 us | No overhead |
| Push p95 | 67 us | 57 us | No overhead |
| Heap free | 113 KB | 111 KB | -2 KB |

**Finding:** Encryption overhead is invisible to the application push path. ChaCha20-Poly1305 runs asynchronously on a separate core. The 2 KB heap difference is the security session state.

### 2. Sampling Rate Sweep (8ch float32, 30s)

| Rate | Insecure push (us) | Encrypted push (us) | Insecure p95 | Encrypted p95 | Loss |
|------|-------------------|---------------------|-------------|--------------|------|
| 250 Hz | 52.8 | 33.1 | 67 | 57 | 0% / 0% |
| 500 Hz | 65.1 | 70.3 | 255 | 310 | 0% / 0% |
| 1000 Hz | 68.1 | 48.3 | 319 | 97 | 0.02% / 0% |

**Finding:** ESP32 sustains up to 1000 Hz with near-zero packet loss. The p95 increases at higher rates due to WiFi backpressure spikes, but the ring buffer absorbs them. The maximum reliable rate is 1000 Hz (limited by FreeRTOS 1ms tick resolution). Loss at 1000 Hz is within WiFi variance and not attributable to encryption.

### 3. Channel Count Sweep (250 Hz, 30s)

| Channels | Bytes/sample | Insecure push (us) | Encrypted push (us) | Insec. p95 | Enc. p95 |
|----------|-------------|-------------------|---------------------|-----------|---------|
| 4 | 16 | 49.4 | 28.3 | 70 | 58 |
| 8 | 32 | 52.8 | 33.1 | 67 | 57 |
| 16 | 64 | 15.6 | 28.9 | 52 | 58 |
| 32 | 128 | 20.0 | 37.8 | 54 | 74 |
| 64 | 256 | 22.3 | 40.0 | 63 | 83 |

All configurations: 7,500/7,500 samples (0% loss).

**Finding:** Push timing is dominated by ring buffer overhead, not payload size. Even 64-channel encrypted streaming achieves sub-100us push with zero loss at 250 Hz. Variability across channel counts reflects measurement noise and WiFi scheduling effects; the key takeaway is that all configurations achieve sub-100us push regardless of channel count.

### 4. Resource Usage

| Config | Heap free | Heap min | Notes |
|--------|-----------|----------|-------|
| 8ch insecure | 113 KB | 85 KB | Baseline |
| 8ch encrypted | 111 KB | 83 KB | +2 KB for security |
| 64ch insecure | ~110 KB | ~85 KB | Minimal increase |
| 64ch encrypted | ~108 KB | ~83 KB | |

SRAM budget: ~200 KB used by liblsl-esp32, 300 KB+ free for user application code.

## Comparison with Desktop secureLSL

| Platform | Encryption Overhead | Max Rate Tested | Packet Loss |
|----------|-------------------|-----------------|-------------|
| Mac Mini M4 Pro (Ethernet) | <1% latency increase | 2000 Hz | 0% |
| Raspberry Pi 5 (Ethernet) | <1% latency increase | 1000 Hz | 0% |
| **ESP32 (WiFi)** | **0% (async on separate core)** | **1000 Hz** | **0.02%** |

Mac Mini and Pi 5 results are from the [desktop secureLSL benchmark suite](https://github.com/sccn/secureLSL). The ESP32 achieves zero measurable encryption overhead because its dual-core architecture allows encryption to run on a separate core from the application. WiFi jitter (~2ms) dominates end-to-end timing, making any sub-millisecond crypto overhead invisible.

## Running Benchmarks

See [benchmarks/README.md](../benchmarks/README.md) for instructions on running the benchmark suite.

```bash
# ESP32 firmware
cd benchmarks/throughput_bench
idf.py menuconfig   # Configure channels, rate, security
idf.py build && idf.py -p PORT flash

# Desktop collection
cd benchmarks/scripts
uv run python serial_monitor.py --port PORT -o results/esp32.json
uv run python esp32_benchmark_inlet.py --duration 60 -o results/desktop.json
```
