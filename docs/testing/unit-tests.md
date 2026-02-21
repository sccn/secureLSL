# Unit Tests

Secure LSL's C++ core and exported C API are covered by automated test suites built on the [Catch2](https://github.com/catchorg/Catch2) framework. These tests run as part of the CMake build and verify the cryptographic primitives, key management, session negotiation, and data integrity logic.

## Test Suite Summary

| Suite | Test Cases | Assertions | Platform Tested |
|-------|-----------|------------|-----------------|
| C++ core (`lsl_test_internal`) | 27 | 3059 | macOS 15.3 (Apple M4 Pro) |
| C API exports (`lsl_test_exported`) | 13 | 1036 | macOS 15.3 (Apple M4 Pro) |

Tests are run as part of each validation pass.

## What Is Tested

### C++ Core Test Cases (`lsl_test_internal`, 27 cases, 3059 assertions)

The internal test suite (`lsl_test_internal`) tests the internal C++ implementation. It links against `lslobj` and `lslboost`, and includes `int/security.cpp`. It covers:

- **Cryptographic primitives**: ChaCha20-Poly1305 encryption and decryption correctness, AEAD authentication tag verification, key derivation via HKDF.
- **Key management**: Ed25519 keypair generation, base64 encoding and decoding, passphrase-based key encryption and decryption, key export and import round-trips.
- **Session negotiation**: X25519 ephemeral key exchange, shared secret derivation, session token generation and validation.
- **Data integrity**: Sample serialization and deserialization, sequential sample counter verification, detection of tampered or replayed packets.
- **Configuration parsing**: Reading and writing `lsl_api.cfg` security sections, handling missing fields, handling malformed values.

### C API Exported Test Cases (`lsl_test_exported`, 13 cases, 1036 assertions)

The exported API test suite (`lsl_test_exported`) tests the exported C API. It links against `lsl` and includes `ext/security_api.cpp`. It verifies that the public C interface behaves correctly for:

- `lsl_get_security_enabled()` and `lsl_local_security_enabled()` return values.
- Secure `StreamOutlet` creation and property reporting.
- Secure `StreamInlet` discovery and connection.
- Rejection behavior when keys do not match.
- Rejection behavior when one side has no security configured.

## Running the Tests

Tests are built automatically when `LSL_SECURITY=ON` is set during the CMake configure step.

```bash
# Configure with security enabled
cd liblsl
mkdir -p build && cd build
cmake -DLSL_SECURITY=ON -DLSL_UNITTESTS=ON ..
cmake --build . --parallel

# Run C++ internal tests
./lsl_test_internal

# Run C++ exported tests
./lsl_test_exported
```

### Verbose Output

To see each test case name and assertion count:

```bash
./lsl_test_internal --reporter console --verbosity high
./lsl_test_exported --reporter console --verbosity high
```

### Filtering Tests

Run a specific test by name:

```bash
./lsl_test_internal "[crypto]"
./lsl_test_exported "[keypair]"
```

## Test Environment

| Item | Value |
|------|-------|
| Hardware | Apple Mac Mini M4 Pro, 24 GB RAM |
| OS | macOS 15.3 (Sequoia) |
| Compiler | Apple Clang (Xcode) |
| libsodium | 1.0.18+ |
| Test framework | Catch2 |
| Date | Most recent: February 2026 |

## Continuous Integration

The test suite is integrated into the CMake build so that any build with `-DLSL_SECURITY=ON -DLSL_UNITTESTS=ON` will compile and can immediately run both test executables. Tests are expected to pass on macOS, Linux (Debian/Ubuntu), and Raspberry Pi OS (Bookworm).
