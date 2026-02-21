# Quick Start Guide

Get your LSL streams encrypted in under 5 minutes. No code changes required for dynamically linked applications.

---

## Prerequisites

- An existing LSL setup (outlets and inlets working)
- Secure LSL library installed (see [Installation](installation.md))

---

## Step 1: Generate and Distribute Encryption Keys

**On your primary device** (e.g., the admin workstation), generate and export a shared keypair:

```bash
./lsl-keygen --export lab_shared
```

You'll be prompted for a passphrase to protect the exported key:

```
LSL Security Key Generator - Export Mode
========================================

Exported keys are always passphrase-protected for security.

Enter passphrase for exported key: ********
Confirm passphrase: ********

Generating Ed25519 keypair...

[OK] Keypair generated successfully!
[OK] Public key saved to: lab_shared.pub
[OK] Encrypted private key saved to: lab_shared.key.enc

Fingerprint: BLAKE2b:70:14:e1:b5:7f:93:ae:af...

To use this key on another device:
  1. Copy lab_shared.key.enc to the target device
  2. Run: lsl-keygen --import lab_shared.key.enc
  3. Enter the same passphrase when prompted
```

!!! tip "Passphrase Protection"
    Like SSH keys, the private key is encrypted with a passphrase by default.
    This provides two-factor authentication: something you have (the key file)
    plus something you know (the passphrase).

    For convenience on lab workstations, you can create a device-bound session
    token that remembers the passphrase securely:

    ```bash
    ./lsl-config --remember-device --passphrase
    ```

!!! note "Low-risk Environments"
    For closed lab environments without regulatory requirements (EU CRA, NIS2, HIPAA, GDPR),
    you can skip the passphrase by pressing Enter twice (with confirmation), or use:

    ```bash
    ./lsl-keygen --export lab_shared --insecure
    ```

**Then import the key on every device, including the primary device:**

!!! warning "`--export` Generates a New Key"
    `lsl-keygen --export` generates a **new** keypair and writes it to portable files.
    It does **not** install the key into your local config. You must run `--import` on
    every device, including the machine that generated the key.

    If you already have a key in your config and want to export it for other devices,
    use `--export-existing` instead:
    ```bash
    ./lsl-keygen --export-existing lab_shared
    ```

```bash
# On the primary device (the one that generated the key)
./lsl-keygen --import lab_shared.key.enc
# Enter the same passphrase used during generation

# Copy the encrypted key to each other device
scp lab_shared.key.enc user@device2:~/

# On each other device, import the shared key
./lsl-keygen --import lab_shared.key.enc
# Enter the same passphrase used during generation

# (Optional) Create a device-bound session token for convenience
./lsl-config --remember-device --passphrase
```

See [Multi-Device Setup](configuration.md#multi-device-setup) for details.

---

## Step 2: Verify Configuration

Check that security is properly configured:

```bash
./lsl-config --check
```

Expected output:

```
LSL Security Configuration Status
==================================

  Security subsystem: initialized
  Security enabled:   YES
  Config file:        /Users/you/.lsl_api/lsl_api.cfg
  Key fingerprint:    BLAKE2b:70:14:e1:b5:7f:93:ae:af...
  Key created:        2025-12-05T19:00:00Z
  Session lifetime:   3600 seconds
  Device token:       not set

  [OK] Configuration valid
```

---

## Step 3: Run Your Applications

That's it! Your existing LSL applications now stream encrypted data automatically.

=== "Python"

    ```python
    import pylsl

    # Same code as before - encryption is automatic
    info = pylsl.StreamInfo('MyEEG', 'EEG', 64, 1000, 'float32', 'myuid')
    outlet = pylsl.StreamOutlet(info)

    # Data is encrypted transparently
    outlet.push_sample([0.0] * 64)
    ```

=== "MATLAB"

    ```matlab
    % Same code as before - encryption is automatic
    info = lsl_streaminfo(lib, 'MyEEG', 'EEG', 64, 1000, 'cf_float32', 'myuid');
    outlet = lsl_outlet(info);

    % Data is encrypted transparently
    outlet.push_sample(zeros(1, 64));
    ```

=== "C++"

    ```cpp
    // Same code as before - encryption is automatic
    lsl::stream_info info("MyEEG", "EEG", 64, 1000, lsl::cf_float32, "myuid");
    lsl::stream_outlet outlet(info);

    // Data is encrypted transparently
    std::vector<float> sample(64, 0.0f);
    outlet.push_sample(sample);
    ```

---

## Verifying You're Using Secure LSL

Before anything else, verify you're using the secure library:

=== "Python"

    ```python
    import pylsl
    info = pylsl.library_info()
    print(info)
    # Should contain "security:X.X.X"
    ```

=== "C++"

    ```cpp
    #include <lsl_cpp.h>
    #include <iostream>

    int main() {
        std::cout << "Secure build: " << lsl::is_secure_build() << "\n";
        std::cout << "Base version: " << lsl::base_version() << "\n";
        std::cout << "Security version: " << lsl::security_version() << "\n";
        std::cout << "Full version: " << lsl::full_version() << "\n";
        return 0;
    }
    // Output:
    // Secure build: 1
    // Base version: 1.16.1
    // Security version: 1.0.0
    // Full version: 1.16.1-secure.1.0.0-alpha
    ```

=== "Command Line"

    ```bash
    ./lsl-config --check
    # Or run lslver:
    ./lslver
    # Look for "security:X.X.X" in the output
    ```

!!! warning "Wrong Library?"
    If you see `lsl::is_secure_build() = 0` or the library info doesn't contain "security",
    you're using the regular liblsl. See [Migration Guide](migration.md) for how to switch.

---

## Verifying Encryption is Active

### Check Stream Security Status

You can verify a stream is encrypted using the security API:

=== "Python"

    ```python
    import lsl_security_helper  # must come before import pylsl
    import pylsl

    streams = pylsl.resolve_stream('type', 'EEG')
    for stream in streams:
        if stream.security_enabled():
            print(f"[secure] {stream.name()} is encrypted")
            print(f"   Fingerprint: {stream.security_fingerprint()}")
        else:
            print(f"[warning] {stream.name()} is NOT encrypted")
    ```

=== "C++"

    ```cpp
    std::vector<lsl::stream_info> streams = lsl::resolve_stream("type", "EEG");
    for (const auto& stream : streams) {
        if (stream.security_enabled()) {
            std::cout << "🔒 " << stream.name() << " is encrypted\n";
            std::cout << "   Fingerprint: " << stream.security_fingerprint() << "\n";
        }
    }
    ```

### Visual Confirmation in LabRecorder

With the secure version of LabRecorder, encrypted streams show a lock icon:

```
Available Streams:
  🔒 EEG-Amplifier (lab-eeg-01)
  🔒 EyeTracker (lab-eye-01)
  🔒 MotionCapture (lab-mocap-01)
```

---

## What About Devices Without Keys?

Secure LSL uses **unanimous security enforcement**:

- If your device has security enabled, it will **only** connect to other secured devices
- Connections to unsecured devices fail with a clear error message:

```
Connection refused: outlet does not have security enabled.
Unanimous security enforcement requires all devices to use encryption.
```

This ensures you never accidentally mix encrypted and unencrypted streams.

!!! warning "All or Nothing"
    All devices in your lab must have the **same shared key** imported. Partial deployment is intentionally not supported to prevent security gaps.

---

## Troubleshooting

### "Connection refused: security mismatch"

One device has security enabled, another doesn't. Ensure all devices have the same shared key imported via `./lsl-keygen --import`.

### "Configuration file not found"

Run `lsl-keygen` to generate the configuration file.

### Streams aren't connecting

Check that all devices have the same security state:

```bash
./lsl-config --check
```

[See full troubleshooting guide →](../troubleshooting.md)

---

## Next Steps

- [Understand how the encryption works](../security/how-it-works.md)
- [Configure advanced options](configuration.md)
- [Set up LabRecorder with security](../integration/labrecorder.md)
