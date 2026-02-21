# API Reference

Secure LSL provides APIs for C, C++, Python, and MATLAB. The API documentation is automatically generated from source code comments using Doxygen.

## Security-Specific Functions

These functions are specific to Secure LSL and not present in standard liblsl:

| Function | Description |
|----------|-------------|
| `lsl_is_secure_build()` | Check if this is a secure build |
| `lsl_local_security_enabled()` | Check if security credentials are loaded |
| `lsl_security_is_locked()` | Check if key needs passphrase |
| `lsl_security_unlock()` | Unlock passphrase-protected key |
| `lsl_local_security_fingerprint()` | Get local device's public key fingerprint |
| `lsl_get_security_enabled()` | Check if a stream has security enabled |
| `lsl_get_security_fingerprint()` | Get a stream's public key fingerprint |

## Version Functions

| Function | Description |
|----------|-------------|
| `lsl_base_version()` | Base liblsl version (e.g., "1.16.1") |
| `lsl_security_version()` | Security layer version (e.g., "1.0.0") |
| `lsl_full_version()` | Combined version string |

## Quick Links

- **C API**: Auto-generated from header files in `liblsl/include/lsl/`
- **C++ API**: Auto-generated from `lsl_cpp.h`
- **Python**: Uses the C API via ctypes (pylsl)
- **MATLAB**: Uses the C API via loadlibrary

## Usage Patterns

### Checking Security Status (C)

```c
#include <lsl_c.h>

// Check if this is a secure build
if (!lsl_is_secure_build()) {
    fprintf(stderr, "WARNING: Not using secure LSL!\n");
}

// Check if credentials are loaded
if (!lsl_local_security_enabled()) {
    fprintf(stderr, "Run lsl-keygen to enable security\n");
}

// Handle passphrase-protected keys
if (lsl_security_is_locked()) {
    lsl_security_unlock("my_passphrase");
}

// Get local fingerprint for verification
printf("Local fingerprint: %s\n", lsl_local_security_fingerprint());
```

### Checking Security Status (C++)

```cpp
#include <lsl_cpp.h>

// Check build type
if (!lsl::is_secure_build()) {
    std::cerr << "WARNING: Not using secure LSL!" << std::endl;
}

// Handle passphrase-protected keys
if (lsl::security_is_locked()) {
    lsl::security_unlock("my_passphrase");
}

// Get fingerprint
std::cout << "Fingerprint: " << lsl::local_security_fingerprint() << std::endl;
```

### Checking Stream Security

```cpp
// Resolve streams
auto streams = lsl::resolve_streams();
for (auto& info : streams) {
    std::cout << info.name() << ": ";
    if (info.security_enabled()) {
        std::cout << "ENCRYPTED (" << info.security_fingerprint() << ")\n";
    } else {
        std::cout << "NOT ENCRYPTED\n";
    }
}
```
