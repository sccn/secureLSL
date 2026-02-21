# Secure LSL Benchmark Protocol

Empirical validation of security overhead in Secure LSL.

## Objective

Measure the latency overhead introduced by encryption/decryption compared to vanilla (insecure) LSL, matching the methodology of the LSL paper (Imaging Neuroscience).

## Test Platforms

All platforms connected via **wired Ethernet** (no WiFi latency):

| Platform | Description | Connection |
|----------|-------------|------------|
| **Intel i7 Workstation** | Intel Core i7 | Gigabit Ethernet |
| **Mac Mini** | Apple Silicon (M1/M2) | Gigabit Ethernet |
| **Raspberry Pi 5** | ARM Cortex-A76 | Gigabit Ethernet |

## Experimental Design

### Primary Comparison: Secure vs Insecure

For each platform, run identical tests with and without encryption:

| Test | Security | Description |
|------|----------|-------------|
| A | OFF | Baseline (vanilla LSL, no encryption) |
| B | ON | Secure LSL (ChaCha20-Poly1305 encryption) |

### Test Parameters

Standard biosignal simulation:
- **Channels**: 64 (typical EEG)
- **Rate**: 1000 Hz
- **Duration**: 60 seconds per test
- **Samples**: ~60,000 per test

## Test Matrix

### Phase 1: Local Tests (Same Machine)

Isolate encryption overhead without network variables.

| ID | Platform | Security | Channels | Rate | Duration |
|----|----------|----------|----------|------|----------|
| L1a | i7 Workstation | OFF | 64 | 1000 Hz | 60s |
| L1b | i7 Workstation | ON | 64 | 1000 Hz | 60s |
| L2a | Mac Mini | OFF | 64 | 1000 Hz | 60s |
| L2b | Mac Mini | ON | 64 | 1000 Hz | 60s |
| L3a | Raspberry Pi 5 | OFF | 64 | 1000 Hz | 60s |
| L3b | Raspberry Pi 5 | ON | 64 | 1000 Hz | 60s |

### Phase 2: Cross-Network Tests

Measure overhead with realistic network conditions.

| ID | Outlet | Inlet | Security | Duration |
|----|--------|-------|----------|----------|
| N1a | Mac Mini | i7 | OFF | 60s |
| N1b | Mac Mini | i7 | ON | 60s |
| N2a | i7 | Pi5 | OFF | 60s |
| N2b | i7 | Pi5 | ON | 60s |
| N3a | Pi5 | Mac Mini | OFF | 60s |
| N3b | Pi5 | Mac Mini | ON | 60s |

### Phase 3: Parameter Sweep Tests

Systematic tests to answer reviewer questions.

**Channel Count Sweep** (64ch baseline):
| ID | Channels | Rate | Security | Notes |
|----|----------|------|----------|-------|
| CH008 | 8 | 1000 Hz | Both | Minimal load |
| CH032 | 32 | 1000 Hz | Both | Light EEG |
| CH064 | 64 | 1000 Hz | Both | Standard EEG |
| CH128 | 128 | 1000 Hz | Both | High-density |
| CH256 | 256 | 1000 Hz | Both | Maximum |

**Sampling Rate Sweep** (64ch fixed):
| ID | Channels | Rate | Security | Notes |
|----|----------|------|----------|-------|
| RT0250 | 64 | 250 Hz | Both | Low rate |
| RT0500 | 64 | 500 Hz | Both | Standard |
| RT1000 | 64 | 1000 Hz | Both | High rate |
| RT2000 | 64 | 2000 Hz | Both | Very high |

**Multi-Inlet Scalability** (one outlet, multiple inlets):
| ID | Inlets | Channels | Rate | Notes |
|----|--------|----------|------|-------|
| MI01 | 1 | 64 | 1000 Hz | Baseline |
| MI02 | 2 | 64 | 1000 Hz | Dual recording |
| MI04 | 4 | 64 | 1000 Hz | Multi-client |

### Phase 4: Stability Test (Optional)

Long-duration test for packet loss verification.

| ID | Setup | Security | Duration |
|----|-------|----------|----------|
| S1 | i7 local | ON | 1 hour |

---

## Setup Instructions

### 1. Install Dependencies (Each Machine)

```bash
# Create environment
conda create -n securelsl-bench python=3.11 numpy matplotlib scipy psutil
conda activate securelsl-bench
pip install pylsl
```

### 2. Build Secure liblsl

```bash
cd /path/to/secureLSL/liblsl
mkdir -p build && cd build
cmake -DLSL_SECURITY=ON ..
cmake --build . --parallel

# Set environment variable
export PYLSL_LIB=$(pwd)/liblsl.dylib  # .so on Linux
```

### 3. Generate Security Keys

```bash
# For SECURE tests only
./lsl-keygen
./lsl-config --check
```

### 4. Copy Scripts

```bash
scp -r benchmarks/scripts user@machine:/path/to/benchmarks/
```

---

## Running Tests

### Toggle Security Mode

**To DISABLE security** (for insecure baseline):
```bash
# Option 1: Rename config
mv ~/.lsl_api/lsl_api.cfg ~/.lsl_api/lsl_api.cfg.secure

# Option 2: Edit config
# Set enabled = false in [security] section
```

**To ENABLE security**:
```bash
# Option 1: Restore config
mv ~/.lsl_api/lsl_api.cfg.secure ~/.lsl_api/lsl_api.cfg

# Option 2: Edit config
# Set enabled = true in [security] section
```

### Run Local Test

**Terminal 1 (Outlet)**:
```bash
cd /path/to/benchmarks/scripts
conda activate securelsl-bench
export PYLSL_LIB=/path/to/liblsl.dylib

python benchmark_outlet.py \
    --channels 64 \
    --rate 1000 \
    --duration 60 \
    --output ../results/L1a_i7_insecure_outlet.json
```

**Terminal 2 (Inlet)**:
```bash
python benchmark_inlet.py \
    --duration 60 \
    --output ../results/L1a_i7_insecure_inlet.json
```

### Run Automated Sweep Tests

The `run_benchmark_suite.py` script automates parameter sweeps:

```bash
# Channel count sweep (tests 8, 32, 64, 128, 256 channels)
python run_benchmark_suite.py --suite channel-sweep --duration 30

# Sampling rate sweep (tests 250, 500, 1000, 2000 Hz)
python run_benchmark_suite.py --suite rate-sweep --duration 30

# Multi-inlet scalability (tests 1, 2, 4 simultaneous inlets)
python run_benchmark_suite.py --suite multi-inlet --duration 30

# Run all sweeps
python run_benchmark_suite.py --suite full --duration 60
```

### Run Cross-Network Test

**On Outlet Machine (e.g., Mac Mini)**:
```bash
python benchmark_outlet.py \
    --channels 64 \
    --rate 1000 \
    --duration 60 \
    --name "CrossNet-Test" \
    --output ../results/N1b_macmini_secure_outlet.json
```

**On Inlet Machine (e.g., i7)**:
```bash
python benchmark_inlet.py \
    --duration 60 \
    --name "CrossNet-Test" \
    --output ../results/N1b_i7_secure_inlet.json
```

---

## Analysis

### Collect Results

```bash
# Copy all results to one machine
rsync -av user@machine1:/path/to/results/ ./all_results/
rsync -av user@machine2:/path/to/results/ ./all_results/
```

### Generate Figures

```bash
cd /path/to/secureLSL/benchmarks/scripts
conda activate securelsl-bench

python analyze_results.py \
    ../results/*.json \
    --output ../figures/
```

### Output Figures

| File | Description |
|------|-------------|
| `F1_latency_distribution.pdf` | Secure vs Insecure histogram (like LSL F4) |
| `F2_platform_comparison.pdf` | Overhead across platforms |
| `F3_latency_timeseries.pdf` | Latency stability over time |
| `F4_jitter_comparison.pdf` | Timing jitter with box plots |
| `channel_sweep.pdf` | Latency vs channel count |
| `rate_sweep.pdf` | Latency vs sampling rate |
| `multi_inlet.pdf` | Multi-inlet scalability |
| `summary_table.md` | Results in Markdown |
| `summary_table.tex` | Results in LaTeX |

---

## Expected Results

Based on ChaCha20-Poly1305 performance characteristics:

| Metric | Target | Notes |
|--------|--------|-------|
| Latency overhead | <5% | ChaCha20 is ~2-3 cycles/byte |
| CPU overhead | <5% | Per-sample encryption is lightweight |
| Jitter impact | Negligible | Constant-time operations |
| Packet loss | 0% | AEAD doesn't drop packets |

---

## Checklist

### Before Testing
- [ ] All machines use same liblsl version
- [ ] Network connectivity verified (`ping`)
- [ ] LSL discovery works (`python -c "import pylsl; print(pylsl.resolve_streams())"`)
- [ ] Security keys generated (for secure tests)
- [ ] No heavy background processes

### During Each Test
- [ ] Verify security state matches test ID (a=OFF, b=ON)
- [ ] Monitor for errors in terminal
- [ ] Note any anomalies

### After Testing
- [ ] All JSON files have data
- [ ] Sample counts match expected (~60k for 60s @ 1kHz)
- [ ] Run analysis script
- [ ] Review figures

---

## Troubleshooting

### "Stream not found"
```bash
# Check outlet is running and discoverable
python -c "import pylsl; print(pylsl.resolve_streams())"
```

### Security mismatch
```bash
# Verify both machines have same security state
./lsl-config --check
```

### High latency on Pi
```bash
# Set CPU governor to performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

---

## File Naming Convention

```
{TestID}_{Platform}_{Security}_{Role}.json

Examples:
  L1a_i7_insecure_inlet.json
  L1b_i7_secure_inlet.json
  N1b_macmini_secure_outlet.json
```
