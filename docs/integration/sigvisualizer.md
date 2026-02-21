# SigVisualizer Integration

Using SigVisualizer with Secure LSL streams for real-time visualization.

---

## Overview

SigVisualizer is a Python/PyQt5 application for real-time visualization of LSL streams. When used with secure liblsl, it automatically:

- Displays encryption status for discovered streams (lock icon 🔒)
- Decrypts incoming data transparently
- Detects security mismatches before connecting
- Shows the stream's security status in the status bar

---

## Setup

### Install Dependencies

SigVisualizer requires Python with PyQt5 and pylsl:

```bash
# Clone SigVisualizer
git clone https://github.com/labstreaminglayer/App-SigVisualizer.git
cd App-SigVisualizer

# Install dependencies
pip install PyQt5 pylsl numpy
```

### Configure Secure liblsl

Point Python to the secure liblsl library:

```bash
# macOS
export PYLSL_LIB=/path/to/secureLSL/liblsl/build/liblsl-secure.dylib

# Linux
export PYLSL_LIB=/path/to/secureLSL/liblsl/build/liblsl-secure.so

# Windows
set PYLSL_LIB=C:\path\to\secureLSL\liblsl\build\lsl-secure.dll
```

### Configure Security Credentials

Generate or import keys on the visualization workstation:

```bash
# Generate new keys
./lsl-keygen

# Or import your lab's shared key
./lsl-keygen --import /path/to/lab_shared.key.enc

# Verify
./lsl-config --check
```

### Run SigVisualizer

```bash
# With secure liblsl
PYLSL_LIB=/path/to/liblsl-secure.dylib python sigvisualizer.py
```

---

## Using Secure SigVisualizer

### Stream Selection

When you open SigVisualizer, encrypted streams are marked with a lock icon:

```
Select Stream:
  🔒 EEG-Amplifier [64 channels]
  🔒 EMG-Device [8 channels]
  ⚠️  LegacyDevice [16 channels]  (insecure)
```

### Security Indicators

- **🔒 Lock icon**: Stream is encrypted
- **⚠️ Warning icon**: Stream is not encrypted (security risk)
- **Fingerprint**: Available in stream info panel

### Connecting to Secure Streams

1. Launch SigVisualizer
2. Click "Select Stream" or use the stream selector
3. Choose a stream (encrypted streams show 🔒)
4. Visualization begins with decrypted data

The decryption is transparent; you see the original signal data.

---

## Security Status Panel

SigVisualizer shows security information in the status bar:

```
┌─────────────────────────────────────────────────────┐
│ Stream: EEG-Amplifier                               │
│ Security: ENABLED 🔒                                │
│ Fingerprint: BLAKE2b:70:14:e1:b5:7f:93:ae:af...     │
│ Session: 2h 14m (last key rotation: 1h 30m ago)    │
└─────────────────────────────────────────────────────┘
```

---

## Best Practices

### 1. Verify Security Before Viewing Sensitive Data

Always confirm the lock icon is present when visualizing sensitive biosignal data.

### 2. Use Secure Networks

Even with encryption, use secured lab networks:

- Wired connections preferred over WiFi
- Isolated VLANs for research equipment
- Firewall protection from external networks

### 3. Session Logging

Enable logging to track security events:

```ini
[log]
level = 4  ; Info level captures security events
```

---

## Security Mismatch Detection

SigVisualizer automatically detects security mismatches when you click "Update" to find streams.

### What Gets Detected

- **Secure stream + Insecure visualizer**: Stream requires encryption but SigVisualizer has no credentials
- **Insecure stream + Secure visualizer**: SigVisualizer has credentials but stream is unencrypted

### Error Dialog

When a mismatch is detected, you'll see a dialog showing:

- The affected stream names (with lock icon for secure streams)
- Instructions on how to fix the issue
- Clear indication that visualization cannot proceed

```
Security Mismatch
─────────────────
The following streams require security, but SigVisualizer does not have
security credentials configured:

  • SecureEEG

To fix this:
  1. Run 'lsl-keygen' to generate credentials, or
  2. Import shared credentials from an authorized device

Cannot visualize streams with mismatched security settings.
```

### After Fixing

After configuring credentials, click "Update" again to retry stream discovery.

---

## Troubleshooting

### "Cannot connect to stream"

**Possible causes**:

1. Security mismatch between visualizer and stream source
2. Different keys on devices (403 Public key mismatch)
3. Network connectivity issues
4. Stream is no longer available

**Solution**:
1. Check `./lsl-config --check` on both devices
2. Verify fingerprints match: `./lsl-config --show-public`
3. Verify network connectivity
4. Click "Update" to refresh stream list

### No Lock Icon on Known-Secure Stream

1. Verify SigVisualizer is built with secure liblsl
2. Check the stream source has security enabled
3. Restart the stream source and refresh

### High Latency

Normal security overhead is <1ms. If you see higher latency:

1. Check network conditions
2. Verify CPU load on both devices
3. Use release builds, not debug

---

## Running SigVisualizer

```bash
# Basic launch
PYLSL_LIB=/path/to/liblsl-secure.dylib python sigvisualizer.py

# With custom security config
PYLSL_LIB=/path/to/liblsl-secure.dylib LSLAPICFG=/path/to/lsl_api.cfg python sigvisualizer.py

# With verbose logging (set in lsl_api.cfg)
# [log]
# level = 6
```

---

## Next Steps

- [LabRecorder Integration](labrecorder.md) - Recording streams
- [Custom Applications](custom-apps.md) - Build your own
- [Troubleshooting](../troubleshooting.md) - Common issues
