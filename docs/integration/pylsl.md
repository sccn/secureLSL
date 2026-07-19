# pylsl Integration

Using the security-enabled Python binding.

---

## Overview

`pylsl` is the Python binding for Lab Streaming Layer. The security-enabled
version ships as a component of this repository at `apps/pylsl/` and adds:

- automatic preference for `liblsl-secure` when it is present
- library-level version queries (base, security, and full version strings)
- per-stream security status, so an application can tell whether a discovered
  stream is encrypted

It remains under its upstream MIT license, including the security additions.

---

## Install

```bash
pip install -e apps/pylsl
```

The binding locates `liblsl-secure` automatically when it is installed. To point
at a specific build, set `PYLSL_LIB`:

```bash
export PYLSL_LIB=/path/to/secureLSL/liblsl/build/liblsl-secure.so
```

---

## Checking the build

```python
import pylsl

pylsl.is_secure_build()   # True when linked against liblsl-secure
pylsl.base_version()      # underlying liblsl version
pylsl.security_version()  # security layer version
pylsl.full_version()      # combined version string
```

`check_security()` combines the test with a warning, which is convenient at
application start-up:

```python
pylsl.check_security()  # warns if not linked against a secure build
```

---

## Checking stream security

`StreamInfo` exposes two methods:

```python
from pylsl import resolve_streams

for info in resolve_streams():
    if info.security_enabled():
        print(f"{info.name()}: encrypted, key {info.security_fingerprint()[:16]}")
    else:
        print(f"{info.name()}: plaintext")
```

Both are methods rather than properties. `security_fingerprint()` returns the
fingerprint of the public key the stream was authorized under, which lets an
application confirm a stream belongs to the expected trust group.

---

## Behavior on a stock liblsl

The security symbols are resolved defensively at import time. Linked against a
stock `liblsl` that does not export them, the binding imports and behaves exactly
as upstream, and the security properties report that the information is
unavailable rather than raising.

This means the same application code runs against both libraries, which is what
makes the drop-in library replacement work without application changes.

---

## See also

- [LabRecorder Integration](labrecorder.md)
- [SigVisualizer Integration](sigvisualizer.md)
- [Custom Applications](custom-apps.md)
