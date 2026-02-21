# Secure LSL (sLSL)

**Encrypted Lab Streaming Layer for clinical and research environments**

[![Version](https://img.shields.io/badge/version-1.16.1--secure.1.0.0--alpha-blue)](https://github.com/sccn/secureLSL)
[![License](https://img.shields.io/badge/license-Proprietary-red)](LICENSE)

Secure LSL is a drop-in replacement for [liblsl](https://github.com/sccn/liblsl) that adds transparent end-to-end encryption. Your existing LSL applications work unchanged; security is handled entirely within the library.

## Features

- **End-to-end encryption**: ChaCha20-Poly1305 authenticated encryption
- **Device authentication**: Ed25519 digital signatures
- **Replay attack prevention**: Monotonic nonce tracking
- **Zero code changes**: Existing applications work unmodified
- **Cross-platform**: macOS, Linux, Windows (x86_64, ARM)
- **Full interoperability**: Python, MATLAB, C++, C# all work together

## Quick Start

```bash
# 1. Build the library (or download a release)
cd liblsl && mkdir build && cd build
cmake -DLSL_SECURITY=ON .. && cmake --build . --parallel

# 2. Generate encryption keys
./lsl-keygen

# 3. Verify setup
./lsl-config --check
# Output: Security: ENABLED

# 4. Run your existing LSL applications (no changes needed)
```

## Verifying You're Using Secure LSL

Always verify you're using the secure library at runtime:

**Python:**
```python
import pylsl
print(pylsl.library_info())  # Should contain "security"
```

**C++:**
```cpp
#include <lsl_cpp.h>
if (!lsl::is_secure_build()) {
    std::cerr << "WARNING: Not using secure LSL!" << std::endl;
}
std::cout << "Version: " << lsl::full_version() << std::endl;
// Output: 1.16.1-secure.1.0.0-alpha
```

**Command line:**
```bash
./lslver
# Look for "security:X.X.X" in output
```

## Documentation

- [Quick Start Guide](docs/getting-started/quickstart.md)
- [Installation](docs/getting-started/installation.md)
- [Configuration Reference](docs/getting-started/configuration.md)
- [Migration from LSL](docs/getting-started/migration.md)
- [Security Architecture](docs/security/how-it-works.md)
- [API Reference](docs/api/c-api.md)

Or view the full documentation site:
```bash
pip install -r docs/requirements.txt
mkdocs serve
# Open http://localhost:8000
```

## Compatibility

| Binding | Status | Notes |
|---------|--------|-------|
| Python (pylsl) | Works | Set `PYLSL_LIB` to point to liblsl-secure |
| MATLAB | Works | Update `loadlibrary` path |
| C++ | Works | Link with `-llsl-secure` |
| C# | Works | Update DllImport attribute |
| LabRecorder | Works | Build with secure liblsl |

All 150+ LSL applications work without modification.

## Binary Naming

The secure library uses a distinct name to prevent confusion:

| Platform | Regular LSL | Secure LSL |
|----------|-------------|------------|
| macOS | `liblsl.dylib` | `liblsl-secure.dylib` |
| Linux | `liblsl.so` | `liblsl-secure.so` |
| Windows | `lsl.dll` | `lsl-secure.dll` |

## Version Information

Secure LSL uses a dual versioning scheme:

- **Base version**: Tracks upstream liblsl (e.g., 1.16.1)
- **Security version**: Tracks security layer (e.g., 1.0.0-alpha)
- **Full version**: Combined (e.g., 1.16.1-secure.1.0.0-alpha)

Query versions at runtime:
```c
lsl_base_version();      // "1.16.1"
lsl_security_version();  // "1.0.0"
lsl_full_version();      // "1.16.1-secure.1.0.0-alpha"
lsl_is_secure_build();   // 1

// Passphrase-protected keys
lsl_security_is_locked();           // 1 if key needs passphrase
lsl_security_unlock("passphrase");  // Unlock the key
lsl_local_security_fingerprint();   // "BLAKE2b:79:8c:1d:7d..."
```

## Repository Structure

```
secureLSL/
├── liblsl/              # Core library with security layer
├── docs/                # MkDocs documentation
├── benchmarks/          # Performance testing
├── tests/               # Integration tests
│   ├── python/          # Python tests
│   └── matlab/          # MATLAB tests
└── mkdocs.yml           # Documentation config
```

## Building

### Requirements

- CMake 3.12+
- C++17 compiler
- libsodium 1.0.18+

### Build Commands

```bash
# macOS
brew install libsodium cmake
cd liblsl && mkdir build && cd build
cmake -DLSL_SECURITY=ON ..
cmake --build . --parallel

# Linux
apt install libsodium-dev cmake build-essential
cd liblsl && mkdir build && cd build
cmake -DLSL_SECURITY=ON ..
cmake --build . --parallel

# Windows (vcpkg)
vcpkg install libsodium
cd liblsl && mkdir build && cd build
cmake -DLSL_SECURITY=ON -DCMAKE_TOOLCHAIN_FILE=[vcpkg-root]/scripts/buildsystems/vcpkg.cmake ..
cmake --build . --config Release
```

## Security Overview

| Feature | Implementation | Purpose |
|---------|---------------|---------|
| Device Identity | Ed25519 signatures | Only authorized devices connect |
| Data Encryption | ChaCha20-Poly1305 | Protect biosignal confidentiality |
| Tamper Detection | AEAD authentication | Detect any modification |
| Replay Prevention | Monotonic nonces | Block packet replay attacks |
| Key Exchange | X25519 + HKDF | Secure session key derivation |

For detailed security information, see [Security Architecture](docs/security/how-it-works.md).

## Regulatory Compliance

Secure LSL helps meet requirements for:

- **EU Cyber Resilience Act** (2024/2847) - Secure by default, encryption, data integrity
- **EU NIS2 Directive** (2022/2555) - Cryptography policies, multi-factor authentication
- **European Health Data Space** (2025/327) - Encryption in transit, access control
- **HIPAA** Technical Safeguards (45 CFR 164.312)
- **GDPR** Article 32 security requirements
- **FDA** 21 CFR Part 11 electronic records

For NIS2 compliance requiring multi-factor authentication, run `lsl-keygen` and enter a passphrase when prompted (passphrase-protection is the default).

## License

Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.

Author: Seyed Yahya Shirazi, SCCN, INC, UCSD

Secure LSL is proprietary software. See [LICENSE](LICENSE) for terms.

This software incorporates [liblsl](https://github.com/sccn/liblsl) (MIT License) and [libsodium](https://libsodium.org/) (ISC License). The original open-source components are available from their respective repositories.
