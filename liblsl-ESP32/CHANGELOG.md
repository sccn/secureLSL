# Changelog

All notable changes to liblsl-ESP32 are documented here.

## [0.3.0] - 2026-03-18 -- secureLSL Encryption

### Added
- **secureLSL encryption**: ChaCha20-Poly1305 authenticated encryption with Ed25519 key exchange
- Key management: NVS-backed keypair storage (generate, import, export)
- Security handshake: TCP header negotiation with unanimous enforcement
- Encrypted data framing: wire-compatible with desktop secureLSL
- Public API: `lsl_esp32_enable_security()`, `lsl_esp32_generate_keypair()`, etc.
- Shared TCP utilities module (`lsl_tcp_common`)
- Secure outlet and inlet examples with key provisioning via menuconfig
- Benchmark suite: throughput firmware + desktop Python scripts
- Testing walkthrough documentation
- Benchmark results: rate sweep (250-1000Hz), channel sweep (4-64ch)

### Verified
- Bidirectional encrypted interop with desktop secureLSL
- Zero packet loss at 250Hz and 500Hz (encrypted and unencrypted)
- 0.02% loss at 1000Hz
- Zero measurable encryption overhead on push path (async on core 1)

## [0.2.0] -- LSL Inlet

### Added
- Stream resolver: UDP multicast discovery with XML response parsing
- TCP data client: connect, negotiate headers, validate test patterns
- Inlet core: FreeRTOS queue, receiver task, pull_sample with timeout
- Public API: `lsl_esp32_resolve_stream()`, `lsl_esp32_create_inlet()`, `lsl_esp32_inlet_pull_sample_f()`
- Stream info accessor functions
- Basic inlet example
- XML parser for `<info>` schema
- Sample deserialization and test pattern validation

### Verified
- Desktop pylsl outlet to ESP32 inlet: 250+ samples received
- Stream resolution in <0.1s on local network

## [0.1.0] -- LSL Outlet

### Added
- Stream info descriptors with XML serialization
- UDP multicast discovery server (239.255.172.215:16571)
- TCP data server with protocol 1.10 negotiation
- Binary sample serialization (float32, double64, int32, int16, int8)
- SPMC ring buffer (64 pre-allocated slots)
- Public API: `lsl_esp32_create_outlet()`, `lsl_esp32_push_sample_f/d/i/s/c()`
- Basic outlet example (8ch sine wave at 250Hz)
- Monotonic clock (`lsl_esp32_local_clock()`)

### Verified
- pylsl discovers and receives ESP32 outlet: 100/100 samples
- Heap stable at ~207KB during streaming

## [0.0.1] -- Project Setup

### Added
- ESP-IDF project scaffold
- Crypto benchmarks (ChaCha20: 124us for 256B, Ed25519 keygen: 27ms)
- CI pipeline: clang-format, cppcheck, typos, ESP-IDF build
- Pre-commit hooks
- Getting started guide (macOS)
