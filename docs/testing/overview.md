# Testing and Validation

Secure LSL has been validated through multiple layers of testing: automated unit and integration tests in C++, manual end-to-end verification on real hardware, and quantitative performance benchmarks.

## Summary

| Test Layer | Scope | Result |
|------------|-------|--------|
| C++ Unit Tests | Core security logic | 27 test cases, 3059 assertions |
| C++ Exported API Tests | Public C API surface | 13 test cases, 1036 assertions |
| Integration Tests | End-to-end scenarios on Mac, Intel i9, RPi 5 | All key scenarios pass |
| Performance Benchmarks | Latency overhead: cross-machine + local sweep | Sub-millisecond overhead |

## Key Results

**Correctness**

- All 27 C++ unit test cases pass with 3059 assertions verified on macOS (Apple M4 Pro). Functional tests also pass on Intel i9-13900K (Ubuntu 24.04).
- All 13 exported (C API) test cases pass with 1036 assertions.
- End-to-end integration tests cover key management, secure streaming, rejection scenarios, Lab Recorder integration, and SigVisualizer integration.

**Performance**

- Cross-machine (Ethernet/WiFi): encryption adds approximately 0.8-0.9 ms latency overhead (1.06-1.09%).
- Local channel sweep (8-256 channels at 1000 Hz): overhead within noise for typical EEG configurations on both Apple M4 Pro and Intel i9-13900K.
- Local rate sweep (250-2000 Hz): overhead within measurement noise across all rates on both platforms.
- Multi-inlet fan-out (1-4 inlets): overhead stable on M4 Pro; slight increase at 4 inlets on i9, but absolute latency stays sub-millisecond.
- Zero packet loss across all configurations tested.

**Security enforcement**

- Devices with different keys are rejected with `403 Public key mismatch`.
- Insecure clients connecting to secure outlets are rejected with `403 Security required` (tested both same-machine and cross-machine).
- Lab Recorder and SigVisualizer display informative error dialogs on security mismatches before any data transfer occurs.
- Device-bound session tokens enable passphrase-free auto-unlock, verified across machines.

**Error handling**

- Wrong passphrase: clear error message, process exits, no crash.
- Missing config file: falls back to default config or insecure mode gracefully.
- Corrupted key file: clear error message, process exits, no crash.
- Import with wrong passphrase: refused with clear error message.

## Test Pages

- [Unit Tests](unit-tests.md): C++ test suite details and how to run them.
- [Integration Tests](integration-tests.md): Manual end-to-end test log covering key management, cross-machine streaming, Lab Recorder, and error handling.
- [Benchmarks](benchmarks.md): Full performance benchmark report with statistical analysis and reproduction instructions.
