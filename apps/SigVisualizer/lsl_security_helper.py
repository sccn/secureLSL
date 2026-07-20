"""
Helper module to add security API support to pylsl.

This module ensures security_enabled() and security_fingerprint() methods
are available on pylsl.StreamInfo, and provides local_security_enabled()
to check if the local device has security credentials configured.

Either uses native pylsl support (pylsl >= TBD with secure-lsl-support branch)
or patches the class.

Usage:
    import lsl_security_helper  # Import before using pylsl
    import pylsl

    # Check local security status
    if lsl_security_helper.local_security_enabled():
        print("Local security credentials are configured")

    streams = pylsl.resolve_streams()
    for s in streams:
        if s.security_enabled():
            print(f"Stream {s.name()} is encrypted: {s.security_fingerprint()}")
"""

import ctypes
import pylsl
from pylsl.lib import lib


def _check_native_support():
    """Check if pylsl has native security_enabled/security_fingerprint methods."""
    return (
        hasattr(pylsl.StreamInfo, "security_enabled")
        and hasattr(pylsl.StreamInfo, "security_fingerprint")
        and callable(getattr(pylsl.StreamInfo, "security_enabled", None))
    )


def _setup_security_functions():
    """Set up ctypes declarations for security functions."""
    try:
        # lsl_get_security_enabled returns int32_t (1=enabled, 0=disabled, -1=error)
        lib.lsl_get_security_enabled.restype = ctypes.c_int32
        lib.lsl_get_security_enabled.argtypes = [ctypes.c_void_p]

        # lsl_get_security_fingerprint returns const char*
        lib.lsl_get_security_fingerprint.restype = ctypes.c_char_p
        lib.lsl_get_security_fingerprint.argtypes = [ctypes.c_void_p]

        return True
    except AttributeError:
        # Functions not available in this liblsl build
        return False


def _setup_local_security_function():
    """Set up ctypes declaration for local security enabled check."""
    try:
        # lsl_local_security_enabled returns int32_t (1=enabled, 0=disabled)
        lib.lsl_local_security_enabled.restype = ctypes.c_int32
        lib.lsl_local_security_enabled.argtypes = []
        return True
    except AttributeError:
        return False


# Track if local security function is available
_local_security_available = _setup_local_security_function()


def local_security_enabled() -> bool:
    """Check if the local device has security credentials configured.

    Returns True if security credentials are loaded and enabled locally,
    False otherwise (either not a secure build or no credentials configured).
    """
    if not _local_security_available:
        return False
    try:
        return lib.lsl_local_security_enabled() == 1
    except Exception:
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

    Returns the fingerprint string (SHA256:xxxx...) or empty string if
    security is not enabled.
    """
    try:
        result = lib.lsl_get_security_fingerprint(self.obj)
        if result:
            return result.decode("utf-8")
        return ""
    except Exception:
        return ""


# Check for native support first (pylsl with secure-lsl-support branch)
if _check_native_support():
    # pylsl already has native support; no patching needed
    _security_available = True
else:
    # No native support; try to patch StreamInfo class
    _security_available = _setup_security_functions()

    if _security_available:
        pylsl.StreamInfo.security_enabled = _security_enabled
        pylsl.StreamInfo.security_fingerprint = _security_fingerprint
    else:
        # Provide stub methods that always return False/empty
        pylsl.StreamInfo.security_enabled = lambda self: False
        pylsl.StreamInfo.security_fingerprint = lambda self: ""
        print("Warning: Security API not available in liblsl. Using stub methods.")
