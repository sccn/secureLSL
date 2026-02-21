# Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""
Helper module to add security API support to pylsl.

This module patches pylsl.StreamInfo with security_enabled() and
security_fingerprint() methods, and adds a module-level
pylsl.local_security_enabled() function, when used with a
security-enabled liblsl.

Usage:
    import lsl_security_helper  # Import before using security methods
    import pylsl

    if pylsl.local_security_enabled():
        streams = pylsl.resolve_streams()
        for s in streams:
            if s.security_enabled():
                print(f"Stream {s.name()} is encrypted: {s.security_fingerprint()}")
"""

import ctypes
import pylsl
from pylsl.lib import lib


def _setup_security_functions():
    """Set up ctypes declarations for security functions."""
    try:
        # lsl_get_security_enabled returns int32_t (1=enabled, 0=disabled, -1=error)
        lib.lsl_get_security_enabled.restype = ctypes.c_int32
        lib.lsl_get_security_enabled.argtypes = [ctypes.c_void_p]

        # lsl_get_security_fingerprint returns const char*
        lib.lsl_get_security_fingerprint.restype = ctypes.c_char_p
        lib.lsl_get_security_fingerprint.argtypes = [ctypes.c_void_p]

        # lsl_local_security_enabled returns int32_t (1=enabled, 0=disabled)
        lib.lsl_local_security_enabled.restype = ctypes.c_int32
        lib.lsl_local_security_enabled.argtypes = []

        return True
    except AttributeError:
        # Functions not available in this liblsl build
        return False


def _security_enabled(self) -> bool:
    """Check if the stream has security/encryption enabled.

    Returns True if security is enabled, False otherwise.
    """
    try:
        result = lib.lsl_get_security_enabled(self.obj)
        return result == 1
    except Exception:
        return False


def _security_fingerprint(self) -> str:
    """Get the security fingerprint of the stream's public key.

    Returns the fingerprint string (BLAKE2b:xxxx...) or empty string if
    security is not enabled.
    """
    try:
        result = lib.lsl_get_security_fingerprint(self.obj)
        if result:
            return result.decode("utf-8")
        return ""
    except Exception:
        return ""


def _local_security_enabled() -> bool:
    """Check if this device has security configured.

    Returns True if the local device has a keypair configured, False otherwise.
    """
    try:
        return bool(lib.lsl_local_security_enabled())
    except Exception:
        return False


# Patch StreamInfo class with security methods and add module-level function
_security_available = _setup_security_functions()

if _security_available:
    pylsl.StreamInfo.security_enabled = _security_enabled
    pylsl.StreamInfo.security_fingerprint = _security_fingerprint
    pylsl.local_security_enabled = _local_security_enabled
else:
    # Provide stub methods that always return False/empty
    pylsl.StreamInfo.security_enabled = lambda self: False
    pylsl.StreamInfo.security_fingerprint = lambda self: ""
    pylsl.local_security_enabled = lambda: False
    print("Warning: Security API not available in liblsl. Using stub methods.")
