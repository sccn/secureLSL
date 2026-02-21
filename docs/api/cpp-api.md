# C++ API Usage Guide

The C++ API provides an object-oriented interface to Secure LSL.

!!! tip "Full Reference"
    For complete class documentation, see the [auto-generated C++ Reference](../liblsl-cpp/annotated.md) from Doxygen.

---

## Class: `lsl::stream_info`

Extended methods for security status.

### `security_enabled()`

Check if security is enabled for this stream.

```cpp
bool security_enabled() const;
```

**Returns:** `true` if security is enabled, `false` otherwise.

**Example:**

```cpp
lsl::stream_info info("MyStream", "EEG", 64, 1000, lsl::cf_float32, "uid123");
if (info.security_enabled()) {
    std::cout << "Security is enabled\n";
}
```

---

### `security_fingerprint()`

Get the security fingerprint for this stream.

```cpp
std::string security_fingerprint() const;
```

**Returns:** Fingerprint string (e.g., `"BLAKE2b:70:14:e1:b5:..."`) or empty string if security disabled.

**Example:**

```cpp
std::string fp = info.security_fingerprint();
if (!fp.empty()) {
    std::cout << "Fingerprint: " << fp << "\n";
}
```

---

## Namespace: `lsl`

### `local_security_enabled()`

Check if local security configuration is enabled.

```cpp
bool lsl::local_security_enabled();
```

**Returns:** `true` if security is configured locally, `false` otherwise.

**Example:**

```cpp
if (lsl::local_security_enabled()) {
    std::cout << "This device has security enabled\n";
}
```

---

## Usage Patterns

### Creating a Secure Outlet

```cpp
#include <lsl_cpp.h>
#include <iostream>
#include <vector>

int main() {
    // Check if security is configured
    if (!lsl::local_security_enabled()) {
        std::cerr << "Security not configured. Run lsl-keygen first.\n";
        return 1;
    }

    // Create stream info (security is automatic)
    lsl::stream_info info("SecureEEG", "EEG", 64, 1000, lsl::cf_float32, "myuid123");

    // Verify security status
    if (info.security_enabled()) {
        std::cout << "Stream will be encrypted\n";
        std::cout << "Fingerprint: " << info.security_fingerprint() << "\n";
    }

    // Create outlet (encryption is transparent)
    lsl::stream_outlet outlet(info);

    // Push samples (encrypted automatically)
    std::vector<float> sample(64);
    while (true) {
        // Fill sample with data
        outlet.push_sample(sample);
    }

    return 0;
}
```

### Creating a Secure Inlet

```cpp
#include <lsl_cpp.h>
#include <iostream>
#include <vector>

int main() {
    // Resolve secure streams
    std::vector<lsl::stream_info> results = lsl::resolve_stream("type", "EEG", 1, 5.0);

    for (const auto& info : results) {
        std::cout << "Found: " << info.name() << "\n";

        if (info.security_enabled()) {
            std::cout << "  Encrypted: YES\n";
            std::cout << "  Fingerprint: " << info.security_fingerprint() << "\n";
        } else {
            std::cout << "  Encrypted: NO\n";
        }
    }

    if (!results.empty()) {
        // Create inlet (decryption is transparent)
        lsl::stream_inlet inlet(results[0]);

        // Pull samples (decrypted automatically)
        std::vector<float> sample(64);
        while (true) {
            double timestamp = inlet.pull_sample(sample);
            // Process sample
        }
    }

    return 0;
}
```

### Verifying Stream Security

```cpp
#include <lsl_cpp.h>
#include <iostream>

void verify_streams() {
    // Resolve all EEG streams
    auto streams = lsl::resolve_stream("type", "EEG", 0, 2.0);

    std::cout << "Security Status Report\n";
    std::cout << "=====================\n\n";

    for (const auto& stream : streams) {
        std::cout << "Stream: " << stream.name() << "\n";
        std::cout << "  Host: " << stream.hostname() << "\n";
        std::cout << "  Channels: " << stream.channel_count() << "\n";

        if (stream.security_enabled()) {
            std::cout << "  Security: ENABLED\n";
            std::cout << "  Fingerprint: " << stream.security_fingerprint() << "\n";
        } else {
            std::cout << "  Security: DISABLED\n";
        }
        std::cout << "\n";
    }
}
```

---

## Exception Handling

Security errors throw `lsl::lost_error` or `lsl::timeout_error`:

```cpp
try {
    lsl::stream_inlet inlet(info);
    std::vector<float> sample(64);
    inlet.pull_sample(sample, 5.0);
} catch (const lsl::lost_error& e) {
    std::cerr << "Connection lost: " << e.what() << "\n";
    // May indicate security mismatch
} catch (const lsl::timeout_error& e) {
    std::cerr << "Timeout: " << e.what() << "\n";
}
```

Common security-related exceptions:

| Exception | Common Cause |
|-----------|--------------|
| `lsl::lost_error` | Security mismatch, authentication failure |
| `lsl::timeout_error` | Connection refused due to security |

---

## Multi-Inlet Pattern

When connecting to multiple streams:

```cpp
#include <lsl_cpp.h>
#include <thread>
#include <vector>

class SecureMultiInlet {
public:
    void connect(const std::string& stream_type) {
        auto streams = lsl::resolve_stream("type", stream_type, 0, 5.0);

        for (const auto& info : streams) {
            // Verify security before connecting
            if (!info.security_enabled() && lsl::local_security_enabled()) {
                std::cerr << "Skipping insecure stream: " << info.name() << "\n";
                continue;
            }

            inlets_.emplace_back(std::make_unique<lsl::stream_inlet>(info));
            std::cout << "Connected to: " << info.name() << "\n";
        }
    }

    void pull_all(std::vector<std::vector<float>>& samples) {
        samples.resize(inlets_.size());
        for (size_t i = 0; i < inlets_.size(); ++i) {
            samples[i].resize(inlets_[i]->info().channel_count());
            inlets_[i]->pull_sample(samples[i], 0.0);
        }
    }

private:
    std::vector<std::unique_ptr<lsl::stream_inlet>> inlets_;
};
```

---

## Thread Safety

All security-related methods are thread-safe:

- `security_enabled()` and `security_fingerprint()` can be called from any thread
- Multiple outlets/inlets can operate concurrently
- Session key rotation is handled internally with proper locking

---

## Header Files

```cpp
#include <lsl_cpp.h>  // Main C++ header (includes security extensions)
```

---

## Next Steps

- [C API Reference](c-api.md) - Low-level C interface
- [Python API Reference](python.md) - Python bindings
- [MATLAB API Reference](matlab.md) - MATLAB usage
