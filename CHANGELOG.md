# Changelog

All notable changes to Secure LSL will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.16.1-secure.1.1.0-alpha] - 2026-03-18

### Added
- **ESP32 support**: liblsl-ESP32, a clean-room C reimplementation of the LSL wire protocol for ESP32 microcontrollers with full secureLSL encryption
- ESP32 outlet and inlet with ChaCha20-Poly1305 encryption, wire-compatible with desktop
- Four ESP32 examples: basic_outlet, basic_inlet, secure_outlet, secure_inlet
- ESP32 benchmark suite: throughput firmware and desktop Python collection scripts
- ESP32 documentation integrated into mkdocs site

### Verified
- Bidirectional encrypted interop: ESP32 to desktop and desktop to ESP32
- Zero packet loss at 250/500 Hz, 0.02% at 1000 Hz
- Zero measurable encryption overhead on ESP32 push path (dual-core async)

## [1.16.1-secure.1.0.0-alpha] - 2025-12-07

### Added
- Initial security layer implementation
- Ed25519 device authentication
- ChaCha20-Poly1305 authenticated encryption
- X25519 + HKDF session key derivation
- Replay attack prevention with nonce tracking
- Security configuration via lsl_api.cfg [security] section
- Key generation tool: `lsl-keygen`
- Configuration validator: `lsl-config`
- Version query API:
  - `lsl_is_secure_build()` - detect secure library at runtime
  - `lsl_base_version()` - get upstream liblsl version
  - `lsl_security_version()` - get security layer version
  - `lsl_full_version()` - get combined version string
- C++ wrappers for all version functions
- Renamed binary to `liblsl-secure` to prevent confusion
- MkDocs documentation site with security guides
- Cross-platform test suite (Python, MATLAB, C++)
- Interoperability tests between all language bindings

### Changed
- Library output name: `liblsl` -> `liblsl-secure`
- Version string includes security info in `lsl_library_info()`

### Security
- All data encryption uses libsodium (NIST-validated)
- Constant-time cryptographic operations
- Secure memory zeroing for sensitive data
- Unanimous security enforcement (secure outlets reject insecure inlets and vice versa)

## Version Format

Secure LSL uses dual versioning:
- **Base version**: Tracks upstream liblsl (e.g., 1.16.1)
- **Security version**: Tracks security layer (e.g., 1.0.0)
- **Combined**: `{base}-secure.{security}[-stage]`

Stages: `alpha` -> `beta` -> `rc.N` -> (stable)
