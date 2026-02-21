# Changelog

All notable changes to Secure LSL will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
