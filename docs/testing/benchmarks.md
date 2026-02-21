# Performance Benchmarks

This page documents comprehensive performance benchmarks measuring the overhead of ChaCha20-Poly1305 authenticated encryption in Secure LSL. Testing was conducted across multiple network configurations to validate that security features do not significantly impact real-time streaming performance.

**Key finding:** Encryption adds only **0.8-0.9 ms (~1%)** latency overhead, which is negligible for practical neuroscience applications.

---

## 1. Test Environment

### 1.1 Hardware Platforms

| Platform | CPU | Memory | OS |
|----------|-----|--------|----|
| Mac Mini (M4 Pro) | Apple M4 Pro | 24 GB | macOS 15.3 (Sequoia) |
| Desktop (Intel i9) | Intel i9-13900K (32 threads) | 62 GB | Ubuntu 24.04 |
| Raspberry Pi 5 | Cortex-A76 (4-core) | 8 GB | Debian 12 (Bookworm) |

### 1.2 Software Configuration

| Component | Version / Setting |
|-----------|------------------|
| liblsl | Custom build with security extensions |
| Cryptographic library | libsodium 1.0.18+ |
| Encryption algorithm | ChaCha20-Poly1305 (AEAD) |
| Key exchange | X25519 + HKDF |
| Authentication | Ed25519 signatures |

### 1.3 Network Configurations

| Configuration | Description | Typical Latency |
|---------------|-------------|-----------------|
| Direct Ethernet | 1 Gbps point-to-point cable | 0.4-1.2 ms |
| WiFi | 802.11ac through home router | 5-20 ms |

> **Note:** A same-machine (local) configuration was also measured during development. The encryption overhead in that case was below measurement precision and is not included here; only cross-machine results where network latency provides a meaningful baseline are reported.

---

## 2. Methodology

### 2.1 Test Parameters

| Parameter | Value |
|-----------|-------|
| Channels | 64 (float32) |
| Sample rate | 1000 Hz |
| Duration | 30 seconds per test |
| Samples per test | 30,000 |
| Iterations | 5 per configuration |

This simulates a typical 64-channel EEG recording at 1000 Hz, a common scenario in neuroscience labs.

### 2.2 Metrics Collected

1. **End-to-end latency:** Time from sample creation to reception.
2. **Push timing:** Time to push one sample to the outlet.
3. **Sample delivery rate:** Percentage of samples successfully received.
4. **CPU utilization:** Mean and peak CPU usage during streaming.
5. **Memory usage:** RAM consumption during operation.

### 2.3 Statistical Analysis

- Paired t-test for comparing secure vs. insecure modes.
- 95% confidence intervals for overhead estimates.
- Cohen's d effect size measurement.
- Significance threshold: alpha = 0.05.

---

## 3. Results

### 3.1 Cross-Machine Benchmark: Direct Ethernet

**Configuration:** Mac Mini (outlet) to Raspberry Pi 5 (inlet) via 1 Gbps Ethernet cable.

| Metric | Insecure | Secure | Overhead |
|--------|----------|--------|----------|
| Mean latency | 77.38 +/- 5.00 ms | 78.20 +/- 4.44 ms | +0.82 ms (1.06%) |
| Sample delivery | 96.9% | 96.9% | 0% |

**Statistical analysis:**

| Statistic | Value |
|-----------|-------|
| t-statistic | 0.8099 |
| p-value | 0.4634 |
| Result | No significant difference (p >= 0.05) |
| Cohen's d | 0.174 (negligible effect) |
| 95% CI for overhead | [-1.99, 3.64] ms (includes zero) |

**Raw latency values (ms), 5 iterations:**

| Iteration | Insecure | Secure |
|-----------|----------|--------|
| 1 | 69.68 | 71.95 |
| 2 | 75.90 | 78.51 |
| 3 | 81.71 | 84.16 |
| 4 | 81.81 | 79.59 |
| 5 | 77.77 | 76.76 |

### 3.2 Cross-Machine Benchmark: WiFi

**Configuration:** Mac Mini (outlet) to Raspberry Pi 5 (inlet) via 802.11ac WiFi.

| Metric | Insecure | Secure | Overhead |
|--------|----------|--------|----------|
| Mean latency | 78.51 +/- 2.90 ms | 79.37 +/- 3.51 ms | +0.85 ms (1.09%) |
| Sample delivery | 96.8% | 96.9% | +0.1% |

**Statistical analysis:**

| Statistic | Value |
|-----------|-------|
| t-statistic | 2.8068 |
| p-value | 0.0485 |
| Result | Marginally significant (p < 0.05) |
| Cohen's d | 0.265 (small effect) |
| 95% CI for overhead | [0.009, 1.70] ms |

**Raw latency values (ms), 5 iterations:**

| Iteration | Insecure | Secure |
|-----------|----------|--------|
| 1 | 76.07 | 75.93 |
| 2 | 76.17 | 76.68 |
| 3 | 77.54 | 78.53 |
| 4 | 79.90 | 81.22 |
| 5 | 82.90 | 84.47 |

### 3.3 Local Benchmark: Channel Sweep

This test isolates encryption overhead from network variability by measuring latency on the same machine across different channel counts.

**Mac Mini M4 Pro** (macOS, 1000 Hz, 15s per test):

| Channels | Insecure (ms) | Secure (ms) | Overhead |
|----------|--------------|-------------|----------|
| 8        | 0.091        | 0.091       | +0.1%    |
| 32       | 0.096        | 0.097       | +0.8%    |
| 64       | 0.104        | 0.108       | +3.4%    |
| 128      | 0.125        | 0.129       | +3.3%    |
| 256      | 0.154        | 0.167       | +8.2%    |

**Intel i9-13900K** (Ubuntu 24.04, GCC 13.3.0, 1000 Hz, 30s per test):

| Channels | Insecure (ms) | Secure (ms) | Overhead |
|----------|--------------|-------------|----------|
| 8        | 0.088        | 0.076       | -13.6%   |
| 32       | 0.092        | 0.083       | -9.8%    |
| 64       | 0.090        | 0.098       | +8.9%    |
| 128      | 0.130        | 0.106       | -18.5%   |
| 256      | 0.207        | 0.266       | +28.5%   |

**Key observations:**

- For typical EEG configurations (32-128 channels), overhead stays below 3.5% on M4 Pro.
- On the i9-13900K, overhead fluctuates both positive and negative, indicating that the difference is within measurement noise for most channel counts.
- At 256 channels (1000 Hz), the i9 shows more variation; absolute latencies remain sub-millisecond.
- Zero packet loss across all channel counts on both platforms.

### 3.4 Local Benchmark: Sampling Rate Sweep

**Mac Mini M4 Pro** (32 channels, varying rate):

| Rate (Hz) | Insecure (ms) | Secure (ms) | Overhead |
|-----------|--------------|-------------|----------|
| 250       | 0.160        | 0.155       | -2.7%    |
| 500       | 0.141        | 0.141       | -0.1%    |
| 1000      | 0.126        | 0.128       | +1.5%    |
| 2000      | 0.118        | 0.119       | +0.6%    |

**Intel i9-13900K** (64 channels, varying rate):

| Rate (Hz) | Insecure (ms) | Secure (ms) | Overhead |
|-----------|--------------|-------------|----------|
| 250       | 0.331        | 0.317       | -4.2%    |
| 500       | 0.183        | 0.189       | +3.3%    |
| 1000      | 0.082        | 0.087       | +6.1%    |
| 2000      | 0.066        | 0.063       | -4.5%    |

**Key observations:**

- Overhead is within measurement noise across all tested rates on both platforms.
- Negative overhead values indicate the difference is indistinguishable from system jitter.
- Zero packet loss at all rates, including 2000 Hz on both platforms.

### 3.5 Local Benchmark: Multi-Inlet Fan-Out

**Mac Mini M4 Pro** (32 channels, 1000 Hz, varying inlet count):

| Inlets | Insecure (ms) | Secure (ms) | Overhead |
|--------|--------------|-------------|----------|
| 1      | 0.127        | 0.129       | +1.6%    |
| 2      | 0.138        | 0.140       | +1.4%    |
| 4      | 0.154        | 0.156       | +1.3%    |

**Intel i9-13900K** (64 channels, 1000 Hz, varying inlet count):

| Inlets | Insecure (ms) | Secure (ms) | Overhead |
|--------|--------------|-------------|----------|
| 1      | 0.116        | 0.086       | -25.9%   |
| 2      | 0.079        | 0.082       | +3.8%    |
| 4      | 0.111        | 0.188       | +69.4%   |

**Key observations:**

- On M4 Pro, encryption overhead remains stable (~1.3-1.6%) as inlet count increases.
- On i9-13900K, single-inlet and two-inlet overhead is within noise; four-inlet secure latency is higher (0.188 ms vs 0.111 ms), but absolute values remain well under 1 ms.
- Per-inlet latency increases with fan-out (expected behavior, not security-related).
- Zero packet loss across all inlet counts on both platforms.

### 3.6 Summary

| Configuration | Overhead (ms) | Overhead (%) | Significant? | Effect size |
|---------|---------------|--------------|--------------|-------------|
| Cross-machine Ethernet | +0.82 | 1.06% | No | Negligible (d=0.174) |
| Cross-machine WiFi | +0.85 | 1.09% | Marginal | Small (d=0.265) |
| Local, 32ch @ 1000 Hz | +0.001 | +0.8% | No | Within noise |
| Local, 64ch @ 1000 Hz | +0.004 | +3.4% | No | Within noise |
| Local, 128ch @ 1000 Hz | +0.004 | +3.3% | No | Within noise |

---

## 4. Discussion

### 4.1 Performance Impact

The benchmark results demonstrate that ChaCha20-Poly1305 encryption adds minimal overhead to LSL streaming:

1. **Absolute overhead is consistent.** Both Ethernet and WiFi show 0.8-0.9 ms additional latency with encryption enabled.

2. **Relative overhead is negligible.** At 1.06-1.09%, the overhead is well within acceptable limits for real-time neuroscience applications.

3. **Effect size is negligible to small.** Cohen's d values of 0.17-0.27 indicate the practical significance is minimal.

4. **Sample delivery is unaffected.** Both modes achieve approximately 97% sample delivery. Encryption does not cause packet loss.

### 4.2 Network Latency Dominates

The measured end-to-end latencies (77-79 ms) are dominated by network stack processing, OS scheduling delays, and buffer management. The encryption overhead (~0.8 ms) represents only ~1% of the total latency.

### 4.3 Statistical Significance

The WiFi test shows marginal statistical significance (p=0.048), but this should be interpreted cautiously:

- The effect size is small (Cohen's d = 0.265).
- The 95% confidence interval nearly includes zero: [0.009, 1.70] ms.
- The practical significance for neuroscience applications is minimal.

The Ethernet test shows no statistical significance (p=0.46), with a negligible effect size and a confidence interval that includes zero.

### 4.4 Comparison with Design Goals

| Requirement | Target | Achieved |
|-------------|--------|----------|
| Performance overhead | < 5% | 1.06-1.09% |
| Sample delivery | > 95% | ~97% |
| Real-time capable | Yes | Yes |

---

## 5. Conclusions

1. **ChaCha20-Poly1305 encryption is suitable for real-time LSL streaming.** The measured overhead of ~1% is negligible for practical applications.

2. **Security can be enabled by default** without impacting performance for typical neuroscience use cases.

3. **Network latency dominates total latency.** Encryption overhead is a small fraction of the end-to-end delay.

4. **The implementation meets design goals** of less than 5% performance overhead while providing authenticated encryption.

---

## 6. Reproducing the Benchmarks

### 6.1 Prerequisites

- Two machines with Secure LSL built from source (see [Installation](../getting-started/installation.md)).
- Shared keypair distributed to both machines (see [Configuration](../getting-started/configuration.md)).
- Python 3 with `numpy`, `scipy`, and `pylsl` installed.

### 6.2 Running the Benchmarks

```bash
# Deploy benchmark scripts to the Raspberry Pi
./benchmarks/scripts/deploy_to_rpi.sh pi@<RPI_IP>

# Run the full benchmark suite (5 iterations, 64 channels, 1000 Hz, 30 s)
./benchmarks/scripts/setup_cross_machine_benchmark.sh \
    --iterations 5 \
    --channels 64 \
    --rate 1000 \
    --duration 30

# Run statistical analysis on collected results
python3 benchmarks/scripts/statistical_analysis.py results/ethernet_5x/
python3 benchmarks/scripts/statistical_analysis.py results/wifi_5x/
```

### 6.3 Network Setup for Direct Ethernet

1. Connect the Mac and Raspberry Pi with an Ethernet cable.
2. Configure static IPs on both machines (e.g., 192.168.x.1 and 192.168.x.2).
3. Add the route on the Mac: `sudo route add -net 192.168.x.0/24 -interface en0`
4. Add the IP on the Raspberry Pi: `sudo ip addr add 192.168.x.2/24 dev eth0`

### 6.4 Benchmark Scripts

| Script | Description |
|--------|-------------|
| `scripts/benchmark_outlet.py` | Outlet benchmark script |
| `scripts/benchmark_inlet.py` | Inlet benchmark script |
| `scripts/run_cross_machine.sh` | Cross-machine test runner |
| `scripts/setup_cross_machine_benchmark.sh` | Full benchmark suite |
| `scripts/statistical_analysis.py` | Statistical analysis |
| `scripts/deploy_to_rpi.sh` | Raspberry Pi deployment helper |

### 6.5 Toggling Security Mode

**To disable security** (insecure baseline):

```bash
# Option 1: Rename config
mv ~/.lsl_api/lsl_api.cfg ~/.lsl_api/lsl_api.cfg.secure

# Option 2: Edit config - set enabled = false in [security] section
```

**To enable security:**

```bash
# Option 1: Restore config
mv ~/.lsl_api/lsl_api.cfg.secure ~/.lsl_api/lsl_api.cfg

# Option 2: Edit config - set enabled = true in [security] section
```

### 6.6 Results Directory Structure

```
results/
  ethernet_5x/
    iter1/
      inlet_insecure_*.json
      inlet_secure_*.json
      outlet_insecure_*.json
      outlet_secure_*.json
    iter2/
    ...
    iter5/
  wifi_5x/
    iter1/
    ...
    iter5/
```
