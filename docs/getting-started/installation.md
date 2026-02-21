# Installation

How to install Secure LSL on your system.

---

## Requirements

- **Operating System**: macOS, Linux, or Windows
- **CMake**: 3.12 or later
- **C++ Compiler**: C++17 support (GCC 7+, Clang 5+, MSVC 2019+)
- **libsodium**: 1.0.18 or later

---

## Install Dependencies

=== "macOS"

    ```bash
    # Using Homebrew
    brew install cmake libsodium
    ```

=== "Ubuntu/Debian"

    ```bash
    sudo apt update
    sudo apt install cmake libsodium-dev build-essential
    ```

=== "Fedora/RHEL"

    ```bash
    sudo dnf install cmake libsodium-devel gcc-c++
    ```

=== "Windows"

    ```powershell
    # Using vcpkg
    vcpkg install libsodium:x64-windows

    # Or download CMake from cmake.org
    ```

---

## Build from Source

### Clone the Repository

```bash
git clone https://github.com/sccn/secureLSL.git
cd secureLSL/liblsl
```

### Build liblsl

```bash
mkdir -p build && cd build
cmake -DLSL_SECURITY=ON ..
cmake --build . --parallel
```

Build options:

| Option | Default | Description |
|--------|---------|-------------|
| `LSL_SECURITY` | ON | Enable security features |
| `LSL_SECURITY_TOOLS` | ON | Build lsl-keygen and lsl-config |
| `CMAKE_BUILD_TYPE` | Release | Build type (Release/Debug) |

### Windows Build

```powershell
# Using vcpkg for dependencies
git clone https://github.com/sccn/secureLSL.git
cd secureLSL\liblsl
mkdir build && cd build

# Configure with vcpkg toolchain
cmake -DLSL_SECURITY=ON -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake ..

# Build
cmake --build . --config Release
```

### Verify Build

```bash
# Check library was built (note: secure build produces liblsl-secure)
ls -l liblsl-secure.dylib   # macOS
ls -l liblsl-secure.so      # Linux
# Windows: dir lsl-secure.dll

# Check tools were built
./lsl-keygen --help
./lsl-config --help

# Verify it's a secure build
./lslver  # Should show "security:1.0.0-alpha" in output
```

---

## Install the Library

### System-wide Installation

```bash
sudo make install
```

This installs:

- `liblsl-secure.so` / `liblsl-secure.dylib` / `lsl-secure.dll` to system library path
- Header files to system include path
- `lsl-keygen` and `lsl-config` to system bin path

### Local Installation

For development or testing without system installation:

```bash
# Set library path (add to your shell profile)
export LD_LIBRARY_PATH=/path/to/secureLSL/liblsl/build:$LD_LIBRARY_PATH  # Linux
export DYLD_LIBRARY_PATH=/path/to/secureLSL/liblsl/build:$DYLD_LIBRARY_PATH  # macOS
```

---

## Python (pylsl)

pylsl automatically finds liblsl. To use the secure version:

### Option 1: Environment Variable

```bash
export PYLSL_LIB=/path/to/secureLSL/liblsl/build/liblsl-secure.dylib  # macOS
export PYLSL_LIB=/path/to/secureLSL/liblsl/build/liblsl-secure.so     # Linux
python your_script.py
```

### Option 2: System Installation

If you installed liblsl system-wide, pylsl will find it automatically.

### Verify Python Setup

```python
import pylsl
print(pylsl.library_info())  # Should contain "security:X.X.X"

# Test security API
info = pylsl.StreamInfo('Test', 'Test', 1, 100, 'float32', 'test123')
print(f"Security available: {hasattr(info, 'security_enabled')}")
```

---

## MATLAB

MATLAB uses liblsl via its LSL library loader.

### Setup

1. Build secure liblsl as shown above
2. Point MATLAB to the library:

```matlab
% Add to your startup.m or script
addpath('/path/to/secureLSL/liblsl/build');

% Load the secure library
lib = lsl_loadlib('/path/to/secureLSL/liblsl/build/liblsl-secure.dylib');  % macOS
% lib = lsl_loadlib('/path/to/secureLSL/liblsl/build/liblsl-secure.so');   % Linux
```

### Verify MATLAB Setup

```matlab
lib = lsl_loadlib('/path/to/liblsl-secure.dylib');
info = lsl_streaminfo(lib, 'Test', 'Test', 1, 100, 'cf_float32', 'test123');
% Security is automatically enabled if configured
```

---

## Pre-built Binaries

!!! note "Coming Soon"
    Pre-built binaries are not yet available. Please build from source using the instructions above.

Once available, pre-built binaries for common platforms will be on the [releases page](https://github.com/sccn/secureLSL/releases):

| Platform | File |
|----------|------|
| macOS (Apple Silicon) | `liblsl-secure-macos-arm64.zip` |
| macOS (Intel) | `liblsl-secure-macos-x64.zip` |
| Linux (x64) | `liblsl-secure-linux-x64.tar.gz` |
| Windows (x64) | `liblsl-secure-windows-x64.zip` |

---

## Verify Installation

After installation, verify everything works:

```bash
# Generate keys (will prompt for a passphrase to protect the private key)
./lsl-keygen

# Check configuration
./lsl-config --check

# Expected output:
# LSL Security Configuration Status
# ==================================
#
#   Security subsystem: initialized
#   Security enabled:   YES
#   Config file:        /Users/you/.lsl_api/lsl_api.cfg
#   Key fingerprint:    BLAKE2b:70:14:e1:b5:...
#   Key created:        2025-12-05T19:00:00Z
#   Session lifetime:   3600 seconds
#   Device token:       not set
#
#   [OK] Configuration valid
```

---

## Next Steps

- [Quick Start Guide](quickstart.md) - Get streaming in 5 minutes
- [Configuration Options](configuration.md) - Advanced settings
- [Troubleshooting](../troubleshooting.md) - Common issues
