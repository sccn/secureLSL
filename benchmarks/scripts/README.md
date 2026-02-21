# Secure LSL Benchmark Scripts

## Quick Start

### SSH Setup (Recommended)

Add to `~/.ssh/config`:
```
Host pi
    HostName 192.168.1.100
    User pi
    IdentityFile ~/.ssh/id_ed25519
```

Now you can use `ssh pi` without passwords.

### Deploy to Raspberry Pi

```bash
# Deploy and build
./deploy_to_rpi.sh pi --build

# Or just sync files
./deploy_to_rpi.sh pi --sync-only
```

### Run Cross-Machine Benchmarks

```bash
# Default: Mac (outlet) -> RPi (inlet), both secure and insecure
./run_cross_machine.sh pi

# Custom configuration
./run_cross_machine.sh pi -c 128 -r 2000 -d 60

# Reverse direction: RPi (outlet) -> Mac (inlet)
./run_cross_machine.sh pi --rpi-outlet

# Only secure test
./run_cross_machine.sh pi --secure-only
```

### Local Benchmarks

```bash
# Run full suite on Mac
python run_benchmark_suite.py --suite all --duration 30

# Run specific suite
python run_benchmark_suite.py --suite channel-sweep --duration 30
python run_benchmark_suite.py --suite rate-sweep --duration 30
python run_benchmark_suite.py --suite multi-inlet --duration 30
```

### Analyze Results

```bash
# Analyze all results
python analyze_results.py ../results/macos-arm64/*.json -o ../figures/macos-arm64/

# Analyze specific results
python analyze_results.py ../results/cross_machine_*/*.json -o ../figures/cross_machine/
```

## Scripts Overview

- **deploy_to_rpi.sh** - Deploy benchmarks to Raspberry Pi
- **run_cross_machine.sh** - Coordinate Mac-RPi cross-machine tests
- **run_benchmark_suite.py** - Run comprehensive benchmark suite
- **benchmark_outlet.py** - Run outlet benchmark
- **benchmark_inlet.py** - Run inlet benchmark
- **analyze_results.py** - Generate figures and analysis

## Results Structure

```
benchmarks/
├── results/
│   ├── macos-arm64/          # Mac Mini results
│   ├── rpi5/                 # Raspberry Pi 5 results
│   └── cross_machine_*/      # Cross-machine test results
└── figures/
    ├── macos-arm64/          # Mac Mini figures
    ├── rpi5/                 # Raspberry Pi 5 figures
    └── cross_machine/        # Cross-machine figures
```

## Figures Generated

- **F1**: Latency distribution (secure vs insecure)
- **F2**: Platform comparison
- **F3**: Latency time series
- **F4**: Jitter comparison
- **F5**: Rate sweep analysis
- **F6**: Channel sweep analysis
- **F7**: Multi-inlet scalability
