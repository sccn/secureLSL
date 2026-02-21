# Custom Application Integration

How to integrate Secure LSL into your own applications.

---

## Overview

The key principle of Secure LSL is **transparency**. Dynamically linked applications work by pointing to liblsl-secure and configuring keys. Statically linked C++ applications need to be recompiled against liblsl-secure.

---

## Integration Steps

### Step 1: Link Against Secure liblsl

=== "CMake"

    ```cmake
    # Find secure liblsl
    find_package(LSL REQUIRED
        HINTS /path/to/secureLSL/liblsl/build
    )

    # Link your application
    target_link_libraries(your_app PRIVATE LSL::lsl)
    ```

=== "Manual Linking"

    ```bash
    # Compile
    g++ -I/path/to/secureLSL/liblsl/include your_app.cpp \
        -L/path/to/secureLSL/liblsl/build -llsl \
        -o your_app
    ```

=== "Python"

    ```bash
    # Set environment variable before importing pylsl
    export PYLSL_LIB=/path/to/secureLSL/liblsl/build/liblsl-secure.dylib
    python your_script.py
    ```

### Step 2: Generate and Distribute the Shared Keypair

All devices in a lab must share the **same** keypair. Generate on one device, then export and import on all others.

**On the first device (key generator):**

```bash
# Generate and export the shared keypair (prompts for a passphrase)
./lsl-keygen --export lab_shared
```

**On ALL devices (including the first one):**

```bash
# Import the shared keypair (prompts for the same passphrase)
./lsl-keygen --import lab_shared.key.enc
```

!!! warning "Use the Same Keypair on All Devices"
    Running `./lsl-keygen` independently on each device creates **different** keypairs. Devices with different keys will reject each other with "security mismatch" errors. Always use `--export` and `--import` to distribute the same keypair to every device.

### Step 3: Run Your Application

No code changes needed. Your application now uses encrypted streams.

---

## Adding Security Awareness

While your code works without changes, you can add security awareness for better user experience.

### Display Security Status

=== "C++"

    ```cpp
    #include <lsl_cpp.h>
    #include <iostream>

    void display_security_status(const lsl::stream_info& info) {
        std::cout << "Stream: " << info.name() << "\n";

        if (info.security_enabled()) {
            std::cout << "  Status: ENCRYPTED 🔒\n";
            std::cout << "  Fingerprint: " << info.security_fingerprint() << "\n";
        } else {
            std::cout << "  Status: NOT ENCRYPTED ⚠️\n";
        }
    }
    ```

=== "Python"

    ```python
    import lsl_security_helper  # must come before import pylsl
    import pylsl

    def display_security_status(info):
        print(f"Stream: {info.name()}")

        if info.security_enabled():
            print(f"  Status: ENCRYPTED")
            print(f"  Fingerprint: {info.security_fingerprint()}")
        else:
            print(f"  Status: NOT ENCRYPTED")
    ```

=== "MATLAB"

    ```matlab
    function display_security_status(info)
        fprintf('Stream: %s\n', info.name());

        if info.security_enabled()
            fprintf('  Status: ENCRYPTED\n');
            fprintf('  Fingerprint: %s\n', info.security_fingerprint());
        else
            fprintf('  Status: NOT ENCRYPTED\n');
        end
    end
    ```

### Require Security

For applications handling sensitive data, you may want to require encryption:

=== "C++"

    ```cpp
    void connect_secure_only(const std::string& stream_type) {
        // Check local security first
        if (!lsl::local_security_enabled()) {
            throw std::runtime_error("Security not configured. Run lsl-keygen first.");
        }

        // Resolve streams
        auto streams = lsl::resolve_stream("type", stream_type, 1, 5.0);

        if (streams.empty()) {
            throw std::runtime_error("No streams found");
        }

        // Verify encryption
        if (!streams[0].security_enabled()) {
            throw std::runtime_error("Stream is not encrypted. "
                "Enable security on the stream source.");
        }

        // Safe to connect
        lsl::stream_inlet inlet(streams[0]);
        // ...
    }
    ```

=== "Python"

    ```python
    import lsl_security_helper  # must come before import pylsl
    import pylsl

    def connect_secure_only(stream_type):
        # Check local security first
        if not pylsl.local_security_enabled():
            raise RuntimeError("Security not configured. Run lsl-keygen first.")

        # Resolve streams
        streams = pylsl.resolve_stream('type', stream_type, timeout=5.0)

        if not streams:
            raise RuntimeError("No streams found")

        # Verify encryption
        if not streams[0].security_enabled():
            raise RuntimeError("Stream is not encrypted. "
                "Enable security on the stream source.")

        # Safe to connect
        inlet = pylsl.StreamInlet(streams[0])
        return inlet
    ```

---

## Security-Aware UI Patterns

### Stream Selector with Security Indicators

```python
import lsl_security_helper  # must come before import pylsl
import pylsl
from tkinter import *

class SecureStreamSelector:
    def __init__(self, root):
        self.root = root
        self.listbox = Listbox(root, width=50)
        self.listbox.pack()

        self.refresh_streams()

    def refresh_streams(self):
        self.listbox.delete(0, END)
        streams = pylsl.resolve_streams(wait_time=2.0)

        for stream in streams:
            # Add security indicator
            prefix = "[SECURE] " if stream.security_enabled() else "[INSECURE] "
            name = f"{prefix}{stream.name()} ({stream.type()}, {stream.channel_count()}ch)"
            self.listbox.insert(END, name)
```

### Connection Status Display

```cpp
class SecurityStatusWidget {
public:
    void update(const lsl::stream_info& info) {
        if (info.security_enabled()) {
            set_icon("lock_icon.png");
            set_status("Encrypted");
            set_fingerprint(info.security_fingerprint());
            set_color(GREEN);
        } else {
            set_icon("warning_icon.png");
            set_status("NOT Encrypted");
            set_fingerprint("");
            set_color(YELLOW);
        }
    }

private:
    void set_icon(const std::string& path);
    void set_status(const std::string& text);
    void set_fingerprint(const std::string& fp);
    void set_color(Color c);
};
```

---

## Error Handling

Handle security-related connection failures gracefully:

=== "C++"

    ```cpp
    try {
        lsl::stream_inlet inlet(info);
        std::vector<float> sample(info.channel_count());
        inlet.pull_sample(sample, 5.0);
    } catch (const lsl::lost_error& e) {
        std::string msg = e.what();

        if (msg.find("security") != std::string::npos) {
            std::cerr << "Security error: " << msg << "\n";
            std::cerr << "Check that all devices have matching security configuration.\n";
        } else {
            std::cerr << "Connection lost: " << msg << "\n";
        }
    }
    ```

=== "Python"

    ```python
    try:
        inlet = pylsl.StreamInlet(info)
        sample, ts = inlet.pull_sample(timeout=5.0)
    except pylsl.LostError as e:
        msg = str(e)

        if "security" in msg.lower():
            print(f"Security error: {msg}")
            print("Check that all devices have matching security configuration.")
        else:
            print(f"Connection lost: {msg}")
    ```

---

## Configuration Management

### Application-Specific Configuration

For applications that need custom configuration paths:

```cpp
// Set config before creating any LSL objects
setenv("LSLAPICFG", "/path/to/app/config/lsl_api.cfg", 1);

// Now create outlets/inlets
lsl::stream_outlet outlet(info);
```

### Bundled Configuration

For standalone applications, bundle the configuration:

```cpp
#include <filesystem>

void ensure_security_config() {
    namespace fs = std::filesystem;

    // Check if user has config
    fs::path user_config = fs::path(getenv("HOME")) / ".lsl_api" / "lsl_api.cfg";

    if (!fs::exists(user_config)) {
        std::cout << "Security not configured.\n";
        std::cout << "Run: lsl-keygen\n";
        // Or offer to run it automatically
    }
}
```

---

## Testing Secure Streams

### Unit Test Pattern

```cpp
#include <gtest/gtest.h>
#include <lsl_cpp.h>

TEST(Security, OutletInletEncrypted) {
    // Create secure outlet
    lsl::stream_info out_info("TestSecure", "Test", 1, 100, lsl::cf_float32, "test123");
    ASSERT_TRUE(out_info.security_enabled());

    lsl::stream_outlet outlet(out_info);

    // Resolve and verify security
    auto results = lsl::resolve_stream("name", "TestSecure", 1, 5.0);
    ASSERT_FALSE(results.empty());
    ASSERT_TRUE(results[0].security_enabled());

    // Create inlet and verify data transfer
    lsl::stream_inlet inlet(results[0]);

    std::vector<float> out_sample = {42.0f};
    outlet.push_sample(out_sample);

    std::vector<float> in_sample(1);
    inlet.pull_sample(in_sample, 5.0);

    ASSERT_FLOAT_EQ(out_sample[0], in_sample[0]);
}
```

### Integration Test with Security Verification

```python
import lsl_security_helper  # must come before import pylsl
import pytest
import pylsl

def test_secure_stream_round_trip():
    """Verify data survives encryption/decryption."""

    # Create outlet
    info = pylsl.StreamInfo('SecureTest', 'Test', 8, 256, 'float32', 'pytest123')
    assert info.security_enabled(), "Security should be enabled"

    outlet = pylsl.StreamOutlet(info)

    # Resolve and verify
    streams = pylsl.resolve_stream('name', 'SecureTest', timeout=5.0)
    assert len(streams) > 0
    assert streams[0].security_enabled()

    # Create inlet
    inlet = pylsl.StreamInlet(streams[0])

    # Test data transfer
    test_data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
    outlet.push_sample(test_data)

    received, _ = inlet.pull_sample(timeout=5.0)
    assert received == pytest.approx(test_data)
```

---

## Deployment Checklist

Before deploying your secure application:

- [ ] Application is linked against secure liblsl
- [ ] All deployment machines have `lsl-keygen` available
- [ ] Documentation explains security setup
- [ ] Error messages guide users through security issues
- [ ] Optional: Application shows security status in UI
- [ ] Optional: Application can require encryption for sensitive data

---

## Next Steps

- [C++ API Reference](../api/cpp-api.md) - Full API documentation
- [Python API Reference](../api/python.md) - Python bindings
- [How Encryption Works](../security/how-it-works.md) - Technical details
