# Drop-In Compatibility Testing Protocol

This page describes how to verify that LSL applications work as drop-in replacements when liblsl-secure is substituted for the standard liblsl binary,
documents what "verified" and "unverified" mean in the compatibility table, and explains
how contributors can submit test results.

---

## Status Definitions

| Status | Meaning |
|--------|---------|
| **Verified** | App was run end-to-end with liblsl-secure. Streams were created, discovered, and data was received without code changes. Test was performed on real hardware. |
| **Unverified (source-verified)** | Source code was inspected and confirms dynamic linking (so drop-in replacement is expected to work), but the app has not been run against liblsl-secure. |
| **Rebuild Required** | App uses static linking or bundles liblsl at compile time. It must be recompiled against liblsl-secure. |

Unverified entries are honest placeholders. They reflect what the source code
promises, not what has been demonstrated in practice. Do not treat them as
guarantees.

---

## Hardware Used for Verified Tests

All verified results reported in this documentation were collected on:

- **Primary machine**: Mac Mini M4 Pro (macOS 15, Apple Silicon), December 2025
- **Secondary machine**: Raspberry Pi 5 (Raspberry Pi OS Bookworm, ARM64), December 2025
- **Network**: WiFi (802.11ac, 5 GHz), latency 5-8 ms between machines

Tests on other platforms (Windows, Intel Linux, older hardware) are still needed.
Community contributions for those platforms are welcome.

---

## Test Procedures by App Category

### Python Apps (via pylsl)

Python apps use pylsl, which loads liblsl via `ctypes.CDLL()`. No recompilation
is needed. Point pylsl at liblsl-secure with the `PYLSL_LIB` environment variable.

**Prerequisites:**

- liblsl-secure built and available (e.g., `~/secureLSL/liblsl/build/liblsl-secure.dylib`)
- Security credentials configured in `~/.lsl_api/lsl_api.cfg`
- pylsl installed (`uv pip install pylsl` or available in the app's environment)

**Test procedure:**

1. Set the library path:

    ```bash
    export PYLSL_LIB=/path/to/liblsl-secure.dylib   # macOS
    export PYLSL_LIB=/path/to/liblsl-secure.so       # Linux
    ```

2. Verify pylsl loads the secure build:

    ```python
    import pylsl
    info = pylsl.library_info()
    print(info)
    # Should contain: security:1.0.0 (or similar)
    ```

3. Launch the application normally. If it creates or resolves LSL streams,
   those streams are now encrypted.

4. Run a secure outlet in another terminal and confirm the app discovers and
   receives data:

    ```python
    python3 -c "import pylsl; o = pylsl.StreamOutlet(pylsl.StreamInfo('Test','EEG',1,100,pylsl.cf_float32,'test')); [o.push_sample([float(i)]) or __import__('time').sleep(0.01) for i in range(500)]"
    ```

5. Confirm data flows without errors or code changes in the app.

**Apps in this category**: SigVisualizer, EyeLink, PupilLabs, Zephyr, RippleTrellis.

---

### MATLAB Apps (via liblsl-Matlab)

MATLAB apps use MEX wrappers that call `dlopen()`/`LoadLibrary()` at runtime.

**Test procedure:**

1. Copy or symlink liblsl-secure to the location MATLAB expects liblsl:

    ```bash
    # macOS example
    cp /path/to/liblsl-secure.dylib /path/to/liblsl-Matlab/liblsl.dylib
    ```

2. Set the security config:

    ```bash
    export LSLAPICFG=~/.lsl_api/lsl_api.cfg
    matlab
    ```

3. In MATLAB, run the app's standard startup. Confirm stream creation and
   resolution work.

4. Check for a security version string from the library:

    ```matlab
    lsl_loadlib();           % or the app's own load call
    % Use lsl_loadlib() handle to confirm library loaded
    ```

**Apps in this category**: liblsl-Matlab, MATLABViewer.

---

### C++ Apps (dynamically linked via CMake)

Most C++ LSL apps link `LSL::lsl` via CMake's `find_package(LSL)`. At runtime
they load whichever `liblsl.dylib` / `liblsl.so` / `lsl.dll` is on the library
search path.

**Test procedure:**

1. Make liblsl-secure available on the library path:

    === "macOS"

        ```bash
        # Option A: set DYLD_LIBRARY_PATH (may not work for GUI apps due to SIP)
        export DYLD_LIBRARY_PATH=/path/to/secureLSL/liblsl/build:$DYLD_LIBRARY_PATH

        # Option B: copy into the app bundle (recommended for GUI apps)
        # Find the actual filename first
        ls YourApp.app/Contents/Frameworks/liblsl*
        # Then copy using the exact filename you see
        cp liblsl-secure.dylib YourApp.app/Contents/Frameworks/liblsl.2.dylib
        ```

    === "Linux"

        ```bash
        export LD_LIBRARY_PATH=/path/to/secureLSL/liblsl/build:$LD_LIBRARY_PATH
        ```

    === "Windows"

        ```powershell
        # Copy lsl-secure.dll to the same directory as the .exe
        Copy-Item lsl-secure.dll C:\path\to\app\lsl.dll
        ```

2. Set security credentials:

    ```bash
    export LSLAPICFG=~/.lsl_api/lsl_api.cfg
    ```

3. Launch the app. It should discover secure streams and operate normally.

4. Verify by running a secure outlet and checking that the app receives data.

**Apps in this category**: LabRecorder, XDFStreamer, BrainProducts, BrainAmpSeries,
BioSemi, emotiv, Cognionics, EGIAmpServer, eegoSports, TobiiPro,
TobiiStreamEngine, SMIEyetracker, Input, GameController, Gamepad, OptiTrack,
AudioCapture, OpenVR, MQTT, SerialPort, OpenEphysLSL-Inlet.

---

### C# Apps (via liblsl-Csharp or LSL4Unity)

C# apps use P/Invoke (`[DllImport("lsl")]`) which resolves the native library
at runtime.

**Test procedure:**

1. Replace the native library:

    - **liblsl-Csharp**: Copy liblsl-secure to the location where `lsl.dll`
      (Windows) or `liblsl.so`/`liblsl.dylib` is expected.
    - **LSL4Unity**: Replace `Assets/Plugins/lsl.dll` (Windows) or the
      platform-specific binary in `Assets/Plugins/` with liblsl-secure, renamed
      to match the expected filename.

2. Set security credentials and run the app or Unity project.

3. Confirm streams are created, discovered, and data flows correctly.

**Apps in this category**: liblsl-Csharp, LSL4Unity.

---

### Java Apps (via liblsl-Java)

Java apps use JNA (`Native.load()`), which searches `java.library.path` for
the native library.

**Test procedure:**

1. Add liblsl-secure to the Java library path:

    ```bash
    java -Djava.library.path=/path/to/secureLSL/liblsl/build -jar yourapp.jar
    ```

2. Confirm the app loads and streams work.

**Apps in this category**: liblsl-Java.

---

### Unreal Engine Plugin (plugin-UE4)

The UE4 plugin uses delay-loaded DLL loading. The pre-built binary in
`ThirdParty/` must be replaced.

**Test procedure:**

1. Navigate to `plugin-UE4/ThirdParty/` and find the platform-specific
   `lsl.dll` (Windows) or equivalent.
2. Replace it with liblsl-secure renamed to match.
3. Rebuild the plugin (UE4 may require a full project rebuild after plugin
   binary changes).
4. Test stream creation and resolution in a UE4 project.

---

## Rebuild-Required Apps

The following apps use static linking and must be recompiled:

| App | Why |
|-----|-----|
| liblsl-rust | `build.rs` compiles liblsl with `LSL_BUILD_STATIC=ON` |
| liblsl-Android | CMake NDK build compiles liblsl from source |

**Rebuild procedure (liblsl-rust example):**

```bash
# Point the build to liblsl-secure source
LSL_DIR=/path/to/secureLSL/liblsl/build cargo build
```

Consult each app's build documentation for details.

---

## Verified Test Results

The following apps have been run end-to-end against liblsl-secure on the
hardware described above. Results are from December 2025.

| App | Platform | Test Date | Result | Notes |
|-----|----------|-----------|--------|-------|
| pylsl | Mac Mini M4 Pro | 2025-12-16 | PASS | Used as inlet and outlet in mixed security scenarios. Security version confirmed. |
| LabRecorder | Mac Mini M4 Pro + RPi 5 (WiFi) | 2025-12-16/17 | PASS | Secure stream discovery, recording (28 kb in 12 s), security mismatch detection dialog, cross-machine recording (32 kb in 14 s). |
| SigVisualizer | Mac Mini M4 Pro | 2025-12-17 | PASS | Encrypted data visualized correctly; security mismatch error dialog shown with stream names and lock icon. |

All other apps in the compatibility table are Unverified (source-verified).

---

## How to Contribute Test Results

If you have verified that an app works (or does not work) with liblsl-secure,
please open a GitHub issue or pull request with the following information:

1. **App name and version** (e.g., LabRecorder v2.16.0)
2. **liblsl-secure version** (e.g., 1.16.1-secure.1.0.0-alpha)
3. **Platform**: OS, CPU architecture (e.g., Ubuntu 24.04, x86-64)
4. **Test performed**: Brief description (e.g., "ran secure outlet, app discovered
   stream, recorded 30 s of data, XDF file opened in MNE-Python")
5. **Result**: PASS or FAIL (with error message if FAIL)
6. **Date**

Open an issue at:
[https://github.com/sccn/secureLSL/issues](https://github.com/sccn/secureLSL/issues)

Label it `app-compatibility`.

---

## Common Failure Modes

### App loads the wrong liblsl

**Symptom**: Streams are not encrypted; `library_info()` does not show a
security version.

**Fix**: Check `PYLSL_LIB`, `DYLD_LIBRARY_PATH` / `LD_LIBRARY_PATH`, or the
app bundle's `Frameworks/` directory. The secure library must appear before any
system-installed liblsl.

### Security mismatch (403 error)

**Symptom**: Connection is refused with "403 Security required" or "403 Public
key mismatch".

**Fix**: Ensure all devices share the same keypair. Generate on one device,
export with `lsl-keygen --export`, and import on each other device with
`lsl-keygen --import`. Verify fingerprints match with `lsl-config --show-public`.

### SIP blocks DYLD_LIBRARY_PATH on macOS

**Symptom**: GUI apps on macOS ignore `DYLD_LIBRARY_PATH` due to System
Integrity Protection.

**Fix**: Copy liblsl-secure into the app bundle:

```bash
# Find the actual filename first
ls YourApp.app/Contents/Frameworks/liblsl*
# Then copy using the exact filename you see
cp liblsl-secure.dylib YourApp.app/Contents/Frameworks/liblsl.2.dylib
```

### Missing libsodium at runtime

**Symptom**: App crashes on startup with "libsodium not found" or similar.

**Fix**: Install libsodium:

```bash
brew install libsodium          # macOS
sudo apt install libsodium-dev  # Ubuntu/Debian
```
