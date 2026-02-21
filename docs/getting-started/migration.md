# Migration from LSL to Secure LSL

This guide helps existing LSL users transition to Secure LSL with minimal friction.

## What Changes

| Aspect | Regular LSL | Secure LSL |
|--------|-------------|------------|
| Binary name | `liblsl.dylib` | `liblsl-secure.dylib` |
| Configuration | Optional `lsl_api.cfg` | Required `[security]` section |
| Your code | - | **No changes needed** (dynamically linked apps) |
| Network traffic | Plaintext | Encrypted |
| Discovery | Works | Works (with security metadata) |

## What Stays the Same

- All API functions (C, C++, Python, MATLAB)
- Stream discovery mechanism
- XDF file format (data is decrypted before recording)
- Channel formats and timestamps

!!! note "Dynamic vs Static Linking"
    **Dynamically linked applications** (pylsl, MATLAB, most LSL apps) require no code changes; just point them to liblsl-secure.

    **Statically linked C++ applications** must be recompiled against liblsl-secure. See the [C++ migration section](#c) below for details.

## App Compatibility Reference

The table below lists LSL applications from the [labstreaminglayer](https://github.com/labstreaminglayer) organization and their linking strategy. Nearly all apps load liblsl dynamically and work as drop-in replacements.

!!! note "Status Key"
    **Verified** = run end-to-end against liblsl-secure on real hardware.
    **Unverified (source-verified)** = source code confirms dynamic linking but app has not been run.
    **Rebuild Required** = static linking; must recompile against liblsl-secure.
    See [Drop-In Testing Protocol](../testing/drop-in-testing.md) for test procedures and how to contribute results.

### Language Bindings

| Binding | Language | Linking | Migration | Status | How It Loads liblsl |
|---------|----------|---------|-----------|--------|---------------------|
| [pylsl](https://github.com/labstreaminglayer/pylsl) | Python | Dynamic | Drop-in | **Verified** | `ctypes.CDLL()` via `PYLSL_LIB` env var or system path |
| [liblsl-Matlab](https://github.com/labstreaminglayer/liblsl-Matlab) | MATLAB | Dynamic | Drop-in | Unverified (source-verified) | MEX wrappers using `dlopen()`/`LoadLibrary()` |
| [liblsl-Csharp](https://github.com/labstreaminglayer/liblsl-Csharp) | C# | Dynamic | Drop-in | Unverified (source-verified) | `[DllImport("lsl")]` P/Invoke |
| [LSL4Unity](https://github.com/labstreaminglayer/LSL4Unity) | C# (Unity) | Dynamic | Drop-in | Unverified (source-verified) | `[DllImport("lsl")]`; replace native plugin in `Plugins/` |
| [liblsl-Java](https://github.com/labstreaminglayer/liblsl-Java) | Java | Dynamic | Drop-in | Unverified (source-verified) | JNA `Native.load()` |
| [liblsl-rust](https://github.com/labstreaminglayer/liblsl-rust) | Rust | **Static** | Rebuild | Rebuild Required | `build.rs` compiles liblsl with `LSL_BUILD_STATIC=ON` |
| [liblsl-Android](https://github.com/labstreaminglayer/liblsl-Android) | Java/C++ | **Static** | Rebuild | Rebuild Required | Builds liblsl from source via CMake NDK |

### Recording and Visualization

| App | Language | Linking | Migration | Status | Notes |
|-----|----------|---------|-----------|--------|-------|
| [LabRecorder](https://github.com/labstreaminglayer/App-LabRecorder) | C++ / Qt6 | Dynamic | Drop-in | **Verified** | Links `LSL::lsl` via CMake `find_package(LSL)` |
| [SigVisualizer](https://github.com/labstreaminglayer/App-SigVisualizer) | Python | Dynamic | Drop-in | **Verified** | Uses pylsl; set `PYLSL_LIB` to liblsl-secure |
| [MATLABViewer](https://github.com/labstreaminglayer/App-MATLABViewer) | MATLAB | Dynamic | Drop-in | Unverified (source-verified) | Uses liblsl-Matlab MEX bindings |
| [XDFStreamer](https://github.com/labstreaminglayer/App-XDFStreamer) | C++ / Qt5 | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |

### EEG Device Apps

| App | Language | Linking | Migration | Status | Notes |
|-----|----------|---------|-----------|--------|-------|
| [BrainProducts (RDA)](https://github.com/labstreaminglayer/App-BrainProducts) | C++ / Qt5 | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [BrainAmpSeries](https://github.com/labstreaminglayer/App-BrainAmpSeries) | C++ / Qt5 | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [BioSemi](https://github.com/labstreaminglayer/App-BioSemi) | C++ / Qt5 | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [emotiv](https://github.com/labstreaminglayer/App-emotiv) | C++ / Qt | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [Cognionics](https://github.com/labstreaminglayer/App-Cognionics) | C++ | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [EGIAmpServer](https://github.com/labstreaminglayer/App-EGIAmpServer) | C++ / Qt5 | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [eegoSports](https://github.com/labstreaminglayer/App-eegoSports) | C++ | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |

### Eye Tracker Apps

| App | Language | Linking | Migration | Status | Notes |
|-----|----------|---------|-----------|--------|-------|
| [EyeLink](https://github.com/labstreaminglayer/App-EyeLink) | Python | Dynamic | Drop-in | Unverified (source-verified) | Uses pylsl |
| [PupilLabs](https://github.com/labstreaminglayer/App-PupilLabs) | Python | Dynamic | Drop-in | Unverified (source-verified) | Pupil Capture plugin using pylsl |
| [TobiiPro](https://github.com/labstreaminglayer/App-TobiiPro) | C++ / Qt5 | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [TobiiStreamEngine](https://github.com/labstreaminglayer/App-TobiiStreamEngine) | C++ / Qt5 | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [SMIEyetracker](https://github.com/labstreaminglayer/App-SMIEyetracker) | C++ | Dynamic | Drop-in | Unverified (source-verified) | Links liblsl shared library |

### Input and Motion Capture Apps

| App | Language | Linking | Migration | Status | Notes |
|-----|----------|---------|-----------|--------|-------|
| [Input (Keyboard/Mouse)](https://github.com/labstreaminglayer/App-Input) | C++ | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [GameController](https://github.com/labstreaminglayer/App-GameController) | C++ / Qt4 | Dynamic | Drop-in | Unverified (source-verified) | Legacy VS project; links liblsl DLL |
| [Gamepad](https://github.com/labstreaminglayer/App-Gamepad) | C++ / Qt5 | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [OptiTrack](https://github.com/labstreaminglayer/App-OptiTrack) | C++ | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |

### Other Apps

| App | Language | Linking | Migration | Status | Notes |
|-----|----------|---------|-----------|--------|-------|
| [AudioCapture](https://github.com/labstreaminglayer/App-AudioCapture) | C++ | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [OpenVR](https://github.com/labstreaminglayer/App-OpenVR) | C++ / Qt5 | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [MQTT](https://github.com/labstreaminglayer/App-MQTT) | C++ | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [SerialPort](https://github.com/labstreaminglayer/App-SerialPort) | C++ | Dynamic | Drop-in | Unverified (source-verified) | Links `LSL::lsl` via CMake |
| [Zephyr](https://github.com/labstreaminglayer/App-Zephyr) | Python | Dynamic | Drop-in | Unverified (source-verified) | Uses pylsl |
| [RippleTrellis](https://github.com/labstreaminglayer/App-RippleTrellis) | Python | Dynamic | Drop-in | Unverified (source-verified) | Uses pylsl |

### Game Engine Plugins

| Plugin | Framework | Linking | Migration | Status | Notes |
|--------|-----------|---------|-----------|--------|-------|
| [plugin-UE4](https://github.com/labstreaminglayer/plugin-UE4) | Unreal Engine 4 | Dynamic | Drop-in | Unverified (source-verified) | Delay-loaded DLL; replace pre-built binary in `ThirdParty/` |
| [OpenEphysLSL-Inlet](https://github.com/labstreaminglayer/OpenEphysLSL-Inlet) | C++ | Dynamic | Drop-in | Unverified (source-verified) | Open Ephys plugin; links `LSL::lsl` |

!!! tip "Summary"
    Out of 35+ apps and bindings in the LSL ecosystem, only **liblsl-rust** and **liblsl-Android** use static linking and require a rebuild. Every other app loads liblsl as a shared library at runtime and works by simply replacing the binary with liblsl-secure. Three apps (pylsl, LabRecorder, SigVisualizer) have been verified on Mac Mini M4 Pro and Raspberry Pi 5. See the [Drop-In Testing Protocol](../testing/drop-in-testing.md) to verify additional apps or platforms.

## Migration Steps

### Step 1: Install Secure liblsl (2 minutes)

=== "macOS"

    ```bash
    # Option A: Build from source
    brew install libsodium cmake
    cd secureLSL/liblsl
    mkdir build && cd build
    cmake -DLSL_SECURITY=ON ..
    cmake --build . --parallel

    # Option B: Download release (when available)
    # brew install sccn/tap/liblsl-secure
    ```

=== "Linux"

    ```bash
    # Install dependencies
    sudo apt install libsodium-dev cmake build-essential

    # Build
    cd secureLSL/liblsl
    mkdir build && cd build
    cmake -DLSL_SECURITY=ON ..
    cmake --build . --parallel
    sudo make install
    ```

=== "Windows"

    ```powershell
    # Install libsodium via vcpkg
    vcpkg install libsodium

    # Build
    cd secureLSL\liblsl
    mkdir build && cd build
    cmake -DLSL_SECURITY=ON -DCMAKE_TOOLCHAIN_FILE=[vcpkg-root]/scripts/buildsystems/vcpkg.cmake ..
    cmake --build . --config Release
    ```

### Step 2: Generate and Distribute Keys (5 minutes)

All devices in your lab must share the **same** keypair. Generate on one device, then distribute to all others.

**On the first device (key generator):**

```bash
# Generate and export a shared keypair (prompts for a passphrase)
./lsl-keygen --export lab_shared
# Creates: lab_shared.pub and lab_shared.key.enc

# Securely transfer lab_shared.key.enc to each other device
# (e.g., via scp, USB, or your lab's file sharing)
```

**On every device (including the one that generated the key):**

```bash
# Import the shared keypair (enter the same passphrase)
./lsl-keygen --import lab_shared.key.enc
```

!!! warning "Do Not Generate Keys Independently on Each Device"
    Running `./lsl-keygen` on each device creates a **different** keypair. Devices with different keys reject each other with "security mismatch" errors. Always use `--export` / `--import` to share one keypair across all lab devices.

!!! warning "Protect Your Private Key"
    The private key in `~/.lsl_api/lsl_api.cfg` authorizes access to the lab's encrypted streams.
    Delete `lab_shared.key.enc` after distributing it, or store securely.
    Never commit the key file to version control.

### Step 3: Update Configuration (1 minute)

The `lsl-keygen` command automatically creates or updates your `lsl_api.cfg`.
Verify it contains a `[security]` section with `enabled = true` and a key field:

```ini
[security]
enabled = true
encrypted_private_key = <base64-encoded-encrypted-key>  ; default (with passphrase)
; or:
; private_key = <base64-encoded-key>  ; if generated with --insecure
```

Configuration file locations:

- **macOS/Linux**: `~/.lsl_api/lsl_api.cfg`
- **Windows**: `%USERPROFILE%\.lsl_api\lsl_api.cfg`
- **Or**: Same directory as your application

### Step 4: Verify Setup (30 seconds)

```bash
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

### Step 5: Run Your Existing Code

Dynamically linked applications work without code changes:

```python
# No changes needed!
import pylsl

# Create outlet (automatically encrypted)
info = pylsl.StreamInfo("EEG", "EEG", 8, 250, pylsl.cf_float32, "mydevice")
outlet = pylsl.StreamOutlet(info)

# Push samples (encrypted transparently)
outlet.push_sample([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0])
```

## Per-Binding Instructions

### Python (pylsl)

Point pylsl to the secure library:

```bash
# Option 1: Environment variable
export PYLSL_LIB=/path/to/liblsl-secure.dylib

# Option 2: In Python before importing
import os
os.environ['PYLSL_LIB'] = '/path/to/liblsl-secure.dylib'
import pylsl  # Must import AFTER setting env
```

Verify you're using secure LSL:

```python
import pylsl
info = pylsl.library_info()
if 'security' not in info:
    print("WARNING: Not using secure LSL!")
else:
    print(f"Using: {info}")
```

### MATLAB

Update the library path in your MATLAB code:

```matlab
% Load the secure library using liblsl-Matlab's lsl_loadlib wrapper
% (set LIBLSL path to point to liblsl-secure before starting MATLAB)
lib = lsl_loadlib();
```

Or set the library path before starting MATLAB:

```bash
# macOS/Linux
export DYLD_LIBRARY_PATH=/path/to/secure/lib:$DYLD_LIBRARY_PATH
matlab
```

### C++

Relink your application with the secure library:

```bash
# Change from:
g++ myapp.cpp -llsl -o myapp

# To:
g++ myapp.cpp -llsl-secure -o myapp
```

Or update your CMakeLists.txt:

```cmake
# The target name is still 'lsl' in CMake
find_package(LSL REQUIRED)
target_link_libraries(myapp PRIVATE LSL::lsl)
```

### C#

Update the DllImport attribute:

```csharp
// Change from:
[DllImport("lsl")]

// To:
[DllImport("lsl-secure")]
```

## Verifying Security is Active

### Runtime Check

```python
import lsl_security_helper  # must come before import pylsl; adds security methods
import pylsl

# Check library info
info = pylsl.library_info()
print(info)
# Should contain: security:X.X.X

# Check stream security (requires lsl_security_helper imported above)
streams = pylsl.resolve_streams(wait_time=2.0)
if streams:
    stream_info = streams[0]
    print(f"Security enabled: {stream_info.security_enabled()}")
```

### Stream Discovery

Secure streams advertise their security status. You can see this in the stream metadata:

```python
streams = pylsl.resolve_streams()
for s in streams:
    print(f"Stream: {s.name()}")
    # Security info is in the stream's XML description
```

### Visual Indicators

LabRecorder and SigVisualizer (with security patches) show:

- Lock icon for encrypted streams
- Security status banner in main window
- Warning for mixed secure/insecure environments

## Troubleshooting

### "Using wrong library" Error

**Symptom**: Your application loads regular liblsl instead of liblsl-secure.

**Solution**:

1. Check which library is loaded:
   ```python
   import pylsl
   print(pylsl.library_info())
   ```

2. Set the correct path:
   ```bash
   export PYLSL_LIB=/path/to/liblsl-secure.dylib
   ```

3. Verify no conflicting libraries:
   ```bash
   # macOS
   ls /usr/local/lib/liblsl*

   # Remove or rename regular liblsl if needed
   ```

### Security Mismatch Errors

**Symptom**: "Security mismatch: secure inlet cannot connect to insecure outlet"

**Cause**: One device has security enabled, another doesn't.

**Solution**: Enable security on all devices in your lab with the same shared key:

1. Generate and export a key on one device: `lsl-keygen --export lab_shared`
2. Import on every device (including the generator): `lsl-keygen --import lab_shared.key.enc`
3. Verify fingerprints match: `lsl-config --show-public`
4. Restart all LSL applications

### Key File Permissions

**Symptom**: "Cannot read private key" or permission denied errors.

**Solution**:

```bash
# Ensure correct permissions
chmod 600 ~/.lsl_api/lsl_api.cfg
chmod 700 ~/.lsl_api/
```

### Missing libsodium

**Symptom**: Build fails with "libsodium not found"

**Solution**:

```bash
# macOS
brew install libsodium

# Ubuntu/Debian
sudo apt install libsodium-dev

# Windows (vcpkg)
vcpkg install libsodium
```

## Multi-Device Lab Setup

For labs with multiple devices:

1. **Install secure LSL on each device**
2. **Generate a shared keypair** on one device and export it (`lsl-keygen --export lab_shared`)
3. **Import the shared key** on every device, including the generator (`lsl-keygen --import lab_shared.key.enc`)
4. **Verify fingerprints match** on each device with `lsl-config --show-public`
5. **Test connectivity** between devices before experiments

```bash
# On Device A (outlet)
./cpp_secure_outlet

# On Device B (inlet)
./cpp_secure_inlet
# Should connect and show encrypted data transfer
```

## Rollback to Regular LSL

If you need to temporarily disable security:

1. Edit `lsl_api.cfg`:
   ```ini
   [security]
   enabled = false
   ```

2. Or use regular liblsl binary:
   ```bash
   export PYLSL_LIB=/path/to/liblsl.dylib  # regular version
   ```

!!! warning "Security Implications"
    Disabling security means your data is transmitted in plaintext.
    Only do this for debugging or compatibility testing.

## Getting Help

- [Troubleshooting Guide](../troubleshooting.md)
- [FAQ](../faq.md)
- [GitHub Issues](https://github.com/sccn/secureLSL/issues)
