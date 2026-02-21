# LabRecorder Integration

How to use LabRecorder with Secure LSL streams.

---

## Overview

LabRecorder is the standard application for recording LSL streams to XDF files. The secure version of LabRecorder:

- Shows encryption status for each stream
- Only connects to streams matching your security configuration
- Records encrypted data (which arrives decrypted) to standard XDF files

---

## Setup

### Use Secure LabRecorder (Drop-In Approach)

LabRecorder links liblsl dynamically, so you do not need to rebuild it. Instead, replace the liblsl library it loads with `liblsl-secure`:

=== "macOS (app bundle)"

    ```bash
    # Copy liblsl-secure into the LabRecorder app bundle
    cp /path/to/secureLSL/liblsl/build/liblsl-secure.dylib \
       /Applications/LabRecorder.app/Contents/Frameworks/liblsl.dylib
    ```

=== "Linux"

    ```bash
    # Set LD_LIBRARY_PATH so LabRecorder finds liblsl-secure instead of system liblsl
    export LD_LIBRARY_PATH=/path/to/secureLSL/liblsl/build:$LD_LIBRARY_PATH
    ./LabRecorder
    ```

=== "Windows"

    Place `lsl-secure.dll` in the same directory as `LabRecorder.exe`, renaming it to `lsl.dll` (or whichever DLL name LabRecorder expects), so it is found before the system version.

### Configure Security

Ensure you have generated keys:

```bash
./lsl-keygen
./lsl-config --check
```

---

## Using Secure LabRecorder

### Stream Display

Secure LabRecorder displays encryption status for each discovered stream:

```
Available Streams:
  🔒 EEG-Amplifier (lab-eeg-01)     [64ch @ 1000Hz]
  🔒 EyeTracker (lab-eye-01)        [4ch @ 120Hz]
  🔒 MotionCapture (lab-mocap-01)   [48ch @ 100Hz]
```

The lock icon (🔒) indicates the stream is encrypted.

### Recording

1. Launch LabRecorder
2. Select the streams you want to record
3. Click "Start Recording"

Recording works exactly as before. The security layer is transparent:

- Data arrives encrypted over the network
- LabRecorder decrypts it automatically
- XDF files contain the original, unencrypted data

!!! note "XDF Files Are Not Encrypted"
    XDF files contain decrypted data. Use disk encryption (FileVault, BitLocker, LUKS) to protect recorded data at rest.

---

## Security Verification

### Check Stream Security in GUI

The secure LabRecorder shows additional security information:

- **Lock icon**: Stream is encrypted
- **Fingerprint**: Visible in stream details (hover or click)
- **Warning icon**: Stream is not encrypted (when local security is enabled)

### Programmatic Check

You can verify security before recording:

```python
import lsl_security_helper  # must come before import pylsl
import pylsl

streams = pylsl.resolve_streams(wait_time=5.0)
for stream in streams:
    status = "[SECURE]" if stream.security_enabled() else "[INSECURE]"
    print(f"{status}: {stream.name()}")
```

---

## Security Mismatch Detection

LabRecorder automatically detects security mismatches **before** recording starts and displays an informative error dialog.

### What Gets Detected

- **Secure stream + Insecure recorder**: Stream requires encryption but LabRecorder has no credentials
- **Insecure stream + Secure recorder**: LabRecorder has credentials but stream is unencrypted

### Error Dialog

When a mismatch is detected, you'll see a dialog like:

```
Security Mismatch
─────────────────
The following streams require security, but Lab Recorder does not have
security credentials configured:

  • EEG-Amplifier
  • EMG-Device

To fix this:
  1. Run 'lsl-keygen' to generate credentials, or
  2. Import shared credentials from an authorized device

Recording cannot proceed with mismatched security settings.
```

### Resolution

1. **If you need security**: Run `lsl-keygen` or import your lab's shared key
2. **If streams should be insecure**: Remove security config from stream sources
3. **Verify all devices**: Use `lsl-config --show-public` to confirm matching fingerprints

---

## Error Messages

### "Connection refused: security mismatch"

**Cause**: LabRecorder has security enabled, but the outlet doesn't (or vice versa).

**Solution**:
1. Check security status on both devices: `./lsl-config --check`
2. Run `./lsl-keygen` on any device without keys, or import shared lab key
3. Restart the stream source and LabRecorder

### "403 Public key mismatch - not authorized"

**Cause**: LabRecorder and the stream source have **different** keys.

**Solution**:
1. All devices must share the same keypair
2. Export and import the shared lab key to all devices
3. Verify fingerprints match: `./lsl-config --show-public`

### "No streams found"

**Possible causes**:

1. Streams are on a different network
2. Security mismatch preventing discovery
3. Firewall blocking UDP multicast

**Solution**:
1. Verify network connectivity
2. Check security status on all devices
3. Ensure firewall allows LSL traffic

---

## Best Practices

### 1. Verify Security Before Recording

Always check that streams show the lock icon before recording sensitive data.

### 2. Document Security Status

Include security verification in your recording protocol:

```
Recording Checklist:
[ ] All stream sources have security enabled (lsl-config --check)
[ ] LabRecorder shows lock icons for all streams
[ ] Recording device has security enabled
[ ] Disk encryption is active for recording storage
```

### 3. Consistent Security State

All devices in your lab should have the same security state:

- **All secure**: Every device has keys (recommended)
- **All insecure**: No device has keys (legacy mode only)

Mixed environments will cause connection failures.

---

## Troubleshooting

### Streams Visible But Won't Record

1. Check that security is enabled on both the stream source and LabRecorder device
2. Verify both are using the secure liblsl library
3. Check for firewall issues on TCP connections

### Performance Issues

Security adds minimal overhead (<5% CPU, <1ms latency). If you see performance issues:

1. Verify you're using release builds, not debug
2. Check that libsodium was built with optimizations
3. Ensure no other processes are competing for CPU

### Lock Icon Not Showing

If streams appear without the lock icon:

1. The stream source may not have security enabled
2. LabRecorder may be using the standard (non-secure) liblsl
3. Check `lsl-config --check` on both devices

---

## Configuration File

LabRecorder uses the same `lsl_api.cfg` as other LSL applications:

```ini
[security]
enabled = true
private_key = MC4CAQAwBQYDK2VwBCIEIPt8vW9...
key_created = 2025-12-05T19:00:00Z

[log]
level = 4
```

Set `LSLAPICFG` environment variable to use a custom location:

```bash
export LSLAPICFG=/path/to/custom/lsl_api.cfg
./LabRecorder
```

---

## Next Steps

- [SigVisualizer Integration](sigvisualizer.md) - Real-time visualization
- [Custom Applications](custom-apps.md) - Build your own secure apps
- [Troubleshooting](../troubleshooting.md) - Common issues
