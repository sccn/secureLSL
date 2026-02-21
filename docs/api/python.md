# Python API Reference

Using Secure LSL with Python via pylsl.

---

## Setup

### Point to Secure liblsl

Before importing pylsl, ensure it uses the secure library:

```bash
export PYLSL_LIB=/path/to/secure/liblsl-secure.dylib
python your_script.py
```

Or in Python:

```python
import os
os.environ['PYLSL_LIB'] = '/path/to/secure/liblsl-secure.dylib'
import pylsl
```

### Verify Library

```python
import pylsl
print(pylsl.library_info())  # Should contain "security:X.X.X"
```

---

## Security Methods

!!! note "Security methods require lsl_security_helper"
    `security_enabled()`, `security_fingerprint()`, and `local_security_enabled()` are not part of standard pylsl. They are provided by `lsl_security_helper.py`, which monkey-patches these methods onto `pylsl.StreamInfo` using ctypes.

    Get the helper from the repository's `tests/python/` directory:

    ```bash
    cp tests/python/lsl_security_helper.py ./
    ```

    Then import it **before** pylsl in every script that uses security methods:

    ```python
    import lsl_security_helper  # must come before import pylsl
    import pylsl
    ```

### `StreamInfo.security_enabled()`

Check if security is enabled for a stream.

```python
def security_enabled(self) -> bool
```

**Returns:** `True` if security is enabled, `False` otherwise.

**Example:**

```python
import lsl_security_helper  # must come before import pylsl
import pylsl

info = pylsl.StreamInfo('MyStream', 'EEG', 64, 1000, 'float32', 'uid123')
if info.security_enabled():
    print("Security is enabled")
```

---

### `StreamInfo.security_fingerprint()`

Get the security fingerprint for a stream.

```python
def security_fingerprint(self) -> str
```

**Returns:** Fingerprint string (e.g., `"BLAKE2b:70:14:e1:b5:..."`) or empty string if security disabled.

**Example:**

```python
fingerprint = info.security_fingerprint()
if fingerprint:
    print(f"Fingerprint: {fingerprint}")
```

---

### `local_security_enabled()`

Check if local security is configured.

```python
def local_security_enabled() -> bool
```

**Returns:** `True` if security is configured, `False` otherwise.

**Example:**

```python
import lsl_security_helper  # must come before import pylsl
import pylsl

if pylsl.local_security_enabled():
    print("This device has security enabled")
else:
    print("Run lsl-keygen to enable security")
```

---

## Usage Patterns

### Creating a Secure Outlet

```python
import lsl_security_helper  # must come before import pylsl
import pylsl
import numpy as np

# Check if security is configured
if not pylsl.local_security_enabled():
    raise RuntimeError("Security not configured. Run lsl-keygen first.")

# Create stream info (security is automatic)
info = pylsl.StreamInfo(
    name='SecureEEG',
    type='EEG',
    channel_count=64,
    nominal_srate=1000,
    channel_format='float32',
    source_id='myuid123'
)

# Verify security status
if info.security_enabled():
    print(f"Stream will be encrypted")
    print(f"Fingerprint: {info.security_fingerprint()}")

# Create outlet (encryption is transparent)
outlet = pylsl.StreamOutlet(info)

# Push samples (encrypted automatically)
sample = np.zeros(64)
while True:
    # Fill sample with data
    outlet.push_sample(sample)
```

### Creating a Secure Inlet

```python
import lsl_security_helper  # must come before import pylsl
import pylsl

# Resolve secure streams
streams = pylsl.resolve_stream('type', 'EEG', timeout=5.0)

for stream in streams:
    print(f"Found: {stream.name()}")

    if stream.security_enabled():
        print(f"  Encrypted: YES")
        print(f"  Fingerprint: {stream.security_fingerprint()}")
    else:
        print(f"  Encrypted: NO")

if streams:
    # Create inlet (decryption is transparent)
    inlet = pylsl.StreamInlet(streams[0])

    # Pull samples (decrypted automatically)
    while True:
        sample, timestamp = inlet.pull_sample(timeout=1.0)
        if sample:
            # Process sample
            pass
```

### Security Status Report

```python
import lsl_security_helper  # must come before import pylsl
import pylsl

def print_security_report():
    """Print security status of all discovered streams."""
    print("Security Status Report")
    print("=" * 50)

    # Check local status first
    print(f"\nLocal security: {'ENABLED' if pylsl.local_security_enabled() else 'DISABLED'}")

    # Discover all streams
    streams = pylsl.resolve_streams(wait_time=2.0)

    print(f"\nDiscovered {len(streams)} stream(s):\n")

    for stream in streams:
        print(f"Stream: {stream.name()}")
        print(f"  Type: {stream.type()}")
        print(f"  Host: {stream.hostname()}")
        print(f"  Channels: {stream.channel_count()}")

        if stream.security_enabled():
            print(f"  Security: ENABLED")
            print(f"  Fingerprint: {stream.security_fingerprint()}")
        else:
            print(f"  Security: DISABLED")
        print()

if __name__ == '__main__':
    print_security_report()
```

---

## Error Handling

Security-related errors raise `pylsl.LostError`:

```python
import pylsl

try:
    streams = pylsl.resolve_stream('name', 'SecureStream', timeout=5.0)
    if streams:
        inlet = pylsl.StreamInlet(streams[0])
        sample, ts = inlet.pull_sample(timeout=1.0)
except pylsl.LostError as e:
    print(f"Connection lost: {e}")
    # May indicate security mismatch
except Exception as e:
    print(f"Error: {e}")
```

Common security error messages:

| Error Message | Cause |
|---------------|-------|
| "Connection refused: security mismatch" | One side secure, other insecure |
| "Connection refused: outlet does not have security enabled" | Secure inlet, insecure outlet |
| "Authentication failed" | Key verification failed |

---

## NumPy Integration

Works seamlessly with NumPy arrays:

```python
import pylsl
import numpy as np

# Create outlet
info = pylsl.StreamInfo('SecureData', 'EEG', 64, 1000, 'float32', 'uid')
outlet = pylsl.StreamOutlet(info)

# Push numpy arrays (encrypted)
data = np.random.randn(64).astype(np.float32)
outlet.push_sample(data)

# Push chunks (encrypted)
chunk = np.random.randn(100, 64).astype(np.float32)
outlet.push_chunk(chunk)
```

---

## Real-time Streaming Example

```python
import lsl_security_helper  # must come before import pylsl
import pylsl
import numpy as np
import time

def secure_streaming_example():
    """Demonstrate secure real-time streaming."""

    # Create secure outlet
    info = pylsl.StreamInfo('SecureDemo', 'Demo', 8, 256, 'float32', 'demo123')

    if not info.security_enabled():
        print("Warning: Security not enabled!")

    outlet = pylsl.StreamOutlet(info)
    print(f"Streaming on: {info.name()}")
    print(f"Security: {'ENABLED' if info.security_enabled() else 'DISABLED'}")

    # Stream for 10 seconds
    start = time.time()
    sample_count = 0

    while time.time() - start < 10:
        # Generate sample
        sample = np.sin(2 * np.pi * np.arange(8) * sample_count / 256)
        outlet.push_sample(sample.astype(np.float32))
        sample_count += 1
        time.sleep(1/256)  # Maintain nominal rate

    print(f"Streamed {sample_count} samples (encrypted)")

if __name__ == '__main__':
    secure_streaming_example()
```

---

## Multi-Stream Recording

```python
import lsl_security_helper  # must come before import pylsl
import pylsl
from threading import Thread
import queue

class SecureRecorder:
    """Record multiple secure streams."""

    def __init__(self):
        self.inlets = []
        self.queues = []
        self.running = False

    def connect(self, stream_type: str):
        """Connect to all streams of given type."""
        streams = pylsl.resolve_stream('type', stream_type, timeout=5.0)

        for info in streams:
            # Skip insecure streams if we have security enabled
            if pylsl.local_security_enabled() and not info.security_enabled():
                print(f"Skipping insecure stream: {info.name()}")
                continue

            inlet = pylsl.StreamInlet(info)
            q = queue.Queue()
            self.inlets.append((inlet, info.name()))
            self.queues.append(q)
            print(f"Connected to: {info.name()} (secure: {info.security_enabled()})")

    def start(self):
        """Start recording."""
        self.running = True
        for i, (inlet, name) in enumerate(self.inlets):
            t = Thread(target=self._record_stream, args=(inlet, self.queues[i]))
            t.daemon = True
            t.start()

    def _record_stream(self, inlet, q):
        while self.running:
            sample, ts = inlet.pull_sample(timeout=0.1)
            if sample:
                q.put((ts, sample))

    def stop(self):
        self.running = False
```

---

## Next Steps

- [C++ API Reference](cpp-api.md) - C++ interface
- [MATLAB API Reference](matlab.md) - MATLAB usage
- [Quick Start Guide](../getting-started/quickstart.md) - Getting started
