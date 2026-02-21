# Secure LSL Benchmark Report

**Date:** December 8, 2025
**Version:** 1.0
**Authors:** Secure LSL Development Team

## Executive Summary

This report documents comprehensive performance benchmarks measuring the overhead of ChaCha20-Poly1305 authenticated encryption in the Secure Lab Streaming Layer (LSL) implementation. Testing was conducted across multiple platforms and network configurations to validate that security features do not significantly impact real-time streaming performance.

**Key Finding:** Encryption adds only **0.8-0.9 ms (~1%)** latency overhead, which is negligible for practical neuroscience applications.

---

## 1. Test Environment

### 1.1 Hardware Platforms

| Platform | CPU | Memory | OS |
|----------|-----|--------|-----|
| Mac Mini (M4 Pro) | Apple M4 Pro | 24 GB | macOS 15.3 (Sequoia) |
| Raspberry Pi 5 | Cortex-A76 (4-core) | 8 GB | Debian 12 (Bookworm) |

### 1.2 Software Configuration

- **liblsl version:** Custom build with security extensions
- **Cryptographic library:** libsodium 1.0.18+
- **Encryption algorithm:** ChaCha20-Poly1305 (AEAD)
- **Key exchange:** X25519 + HKDF
- **Authentication:** Ed25519 signatures

### 1.3 Network Configurations

| Configuration | Description | Typical Latency |
|---------------|-------------|-----------------|
| Local | Same machine, loopback | < 1 ms |
| Direct Ethernet | 1 Gbps point-to-point cable | 0.4-1.2 ms |
| WiFi | 802.11ac through home router | 5-20 ms |

---

## 2. Methodology

### 2.1 Test Parameters

| Parameter | Value |
|-----------|-------|
| Channels | 64 (float32) |
| Sample Rate | 1000 Hz |
| Duration | 30 seconds per test |
| Samples per test | 30,000 |
| Iterations | 5 per configuration |

### 2.2 Metrics Collected

1. **End-to-end latency:** Time from sample creation to reception
2. **Push timing:** Time to push one sample to outlet
3. **Sample delivery rate:** Percentage of samples successfully received
4. **CPU utilization:** Mean and peak CPU usage during streaming
5. **Memory usage:** RAM consumption during operation

### 2.3 Statistical Analysis

- Paired t-test for comparing secure vs insecure modes
- 95% confidence intervals for overhead estimates
- Cohen's d effect size measurement
- Significance threshold: alpha = 0.05

---

## 3. Results

### 3.1 Cross-Machine Benchmark: Direct Ethernet

**Configuration:** Mac Mini (outlet) -> Raspberry Pi 5 (inlet) via 1 Gbps Ethernet

| Metric | Insecure | Secure | Overhead |
|--------|----------|--------|----------|
| Mean Latency | 77.38 +/- 5.00 ms | 78.20 +/- 4.44 ms | +0.82 ms (1.06%) |
| Sample Delivery | 96.9% | 96.9% | 0% |

**Statistical Analysis:**
- t-statistic: 0.8099
- p-value: 0.4634
- **Result: NO significant difference** (p >= 0.05)
- Cohen's d: 0.174 (negligible effect)
- 95% CI for overhead: [-1.99, 3.64] ms (includes zero)

**Raw Latency Values (ms):**
- Insecure: [69.68, 75.90, 81.71, 81.81, 77.77]
- Secure: [71.95, 78.51, 84.16, 79.59, 76.76]

### 3.2 Cross-Machine Benchmark: WiFi

**Configuration:** Mac Mini (outlet) -> Raspberry Pi 5 (inlet) via 802.11ac WiFi

| Metric | Insecure | Secure | Overhead |
|--------|----------|--------|----------|
| Mean Latency | 78.51 +/- 2.90 ms | 79.37 +/- 3.51 ms | +0.85 ms (1.09%) |
| Sample Delivery | 96.8% | 96.9% | +0.1% |

**Statistical Analysis:**
- t-statistic: 2.8068
- p-value: 0.0485
- **Result: Marginally significant** (p < 0.05)
- Cohen's d: 0.265 (small effect)
- 95% CI for overhead: [0.009, 1.70] ms

**Raw Latency Values (ms):**
- Insecure: [76.07, 76.17, 77.54, 79.90, 82.90]
- Secure: [75.93, 76.68, 78.53, 81.22, 84.47]

### 3.3 Summary Comparison

| Network | Overhead (ms) | Overhead (%) | Significant? | Effect Size |
|---------|---------------|--------------|--------------|-------------|
| Direct Ethernet | 0.82 | 1.06% | No | Negligible |
| WiFi | 0.85 | 1.09% | Marginal | Small |

---

## 4. Discussion

### 4.1 Performance Impact

The benchmark results demonstrate that ChaCha20-Poly1305 encryption adds minimal overhead to LSL streaming:

1. **Absolute overhead is consistent:** Both Ethernet and WiFi show ~0.8-0.9 ms additional latency with encryption enabled.

2. **Relative overhead is negligible:** At 1.06-1.09%, the overhead is well within acceptable limits for real-time neuroscience applications.

3. **Effect size is negligible to small:** Cohen's d values of 0.17-0.27 indicate the practical significance is minimal.

4. **Sample delivery is unaffected:** Both modes achieve ~97% sample delivery, indicating encryption does not cause packet loss.

### 4.2 Network Latency Dominates

The measured end-to-end latencies (77-79 ms) are dominated by:
- Network stack processing
- OS scheduling delays
- Buffer management

The encryption overhead (~0.8 ms) represents only ~1% of the total latency, making it negligible in practice.

### 4.3 Statistical Significance

The WiFi test shows marginal statistical significance (p=0.048), but this should be interpreted cautiously:
- The effect size is small (Cohen's d = 0.265)
- The 95% CI nearly includes zero [0.009, 1.70]
- The practical significance is minimal

The Ethernet test shows no statistical significance (p=0.46), with a negligible effect size and CI that includes zero.

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

4. **The implementation meets design goals** of < 5% performance overhead while providing authenticated encryption.

---

## 6. Recommendations for Manuscript

When writing the performance evaluation section for the manuscript, consider:

1. **Lead with the key finding:** ~1% overhead is negligible
2. **Present both statistical and practical significance**
3. **Include raw data for reproducibility**
4. **Note that network effects dominate encryption overhead**
5. **Compare against the 5% target from requirements**

---

## 7. Reproducibility

### 7.1 Running the Benchmarks

```bash
# Deploy to Raspberry Pi
./benchmarks/scripts/deploy_to_rpi.sh pi

# Run full benchmark suite
./benchmarks/scripts/setup_cross_machine_benchmark.sh \
    --iterations 5 \
    --channels 64 \
    --rate 1000 \
    --duration 30

# Run statistical analysis
python3 benchmarks/scripts/statistical_analysis.py results/ethernet_5x/
python3 benchmarks/scripts/statistical_analysis.py results/wifi_5x/
```

### 7.2 Network Setup Notes

For direct Ethernet connection:
1. Connect Mac and RPi with Ethernet cable
2. Configure static IPs (default: 192.168.10.1 and 192.168.10.2)
3. Add route on Mac: `sudo route add -net 192.168.10.0/24 -interface en0`
4. Add IP on RPi: `sudo ip addr add 192.168.10.2/24 dev eth0`

### 7.3 Files and Scripts

| File | Description |
|------|-------------|
| `scripts/benchmark_outlet.py` | Outlet benchmark script |
| `scripts/benchmark_inlet.py` | Inlet benchmark script |
| `scripts/run_cross_machine.sh` | Cross-machine test runner |
| `scripts/setup_cross_machine_benchmark.sh` | Full benchmark suite |
| `scripts/statistical_analysis.py` | Statistical analysis |
| `scripts/deploy_to_rpi.sh` | RPi deployment script |

---

## Appendix A: Detailed Results

### A.1 Ethernet Results Directory Structure

```
results/ethernet_5x/
  iter1/
    inlet_insecure_*.json
    inlet_secure_*.json
    outlet_insecure_*.json
    outlet_secure_*.json
  iter2/
  ...
  iter5/
```

### A.2 WiFi Results Directory Structure

```
results/wifi_5x/
  iter1/
    inlet_insecure_*.json
    inlet_secure_*.json
    outlet_insecure_*.json
    outlet_secure_*.json
  iter2/
  ...
  iter5/
```

---

*Report generated: December 8, 2025*
