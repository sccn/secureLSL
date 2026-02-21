# C API Usage Guide

The C API provides low-level access to Secure LSL functionality.

!!! tip "Full Reference"
    For complete function signatures and parameters, see the [auto-generated C Reference](../liblsl-c/functions.md) from Doxygen.

---

## Security Query Functions

### `lsl_get_security_enabled`

Check if security is enabled for a stream.

```c
int32_t lsl_get_security_enabled(lsl_streaminfo info);
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `info` | `lsl_streaminfo` | Stream info handle |

**Returns:** `1` if security is enabled, `0` otherwise.

**Example:**

```c
lsl_streaminfo info = lsl_create_streaminfo("MyStream", "EEG", 64, 1000, cft_float32, "uid123");
if (lsl_get_security_enabled(info)) {
    printf("Security is enabled\n");
}
```

---

### `lsl_get_security_fingerprint`

Get the security fingerprint for a stream.

```c
const char* lsl_get_security_fingerprint(lsl_streaminfo info);
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `info` | `lsl_streaminfo` | Stream info handle |

**Returns:** Fingerprint string (e.g., `"BLAKE2b:70:14:e1:b5:..."`) or empty string if security disabled.

**Example:**

```c
const char* fingerprint = lsl_get_security_fingerprint(info);
if (fingerprint && strlen(fingerprint) > 0) {
    printf("Fingerprint: %s\n", fingerprint);
}
```

---

### `lsl_local_security_enabled`

Check if local security configuration is enabled.

```c
int32_t lsl_local_security_enabled(void);
```

**Returns:** `1` if local security is configured, `0` otherwise.

**Example:**

```c
if (lsl_local_security_enabled()) {
    printf("This device has security enabled\n");
} else {
    printf("Run lsl-keygen to enable security\n");
}
```

---

### `lsl_local_security_fingerprint`

Get the local device's public key fingerprint.

```c
const char* lsl_local_security_fingerprint(void);
```

**Returns:** Fingerprint string (e.g., `"BLAKE2b:79:8c:1d:7d:..."`) or empty string if security is not enabled or key is locked.

**Example:**

```c
const char* fp = lsl_local_security_fingerprint();
if (fp && strlen(fp) > 0) {
    printf("Local device fingerprint: %s\n", fp);
}
```

---

### `lsl_security_is_locked`

Check if the local security key is locked (passphrase-protected).

```c
int32_t lsl_security_is_locked(void);
```

**Returns:** `1` if the key is locked and needs a passphrase, `0` if unlocked or not encrypted.

**Example:**

```c
if (lsl_security_is_locked()) {
    printf("Key is passphrase-protected. Call lsl_security_unlock().\n");
}
```

---

### `lsl_security_unlock`

Unlock a passphrase-protected security key.

```c
int32_t lsl_security_unlock(const char* passphrase);
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `passphrase` | `const char*` | The passphrase to unlock the key |

**Returns:** `1` on success, `0` on failure (wrong passphrase or key not locked).

**Example:**

```c
if (lsl_security_is_locked()) {
    if (lsl_security_unlock("my_passphrase")) {
        printf("Key unlocked successfully\n");
    } else {
        printf("Wrong passphrase\n");
    }
}
```

---

## Stream Info Extensions

When security is enabled, stream info XML includes a `<security>` node:

```xml
<info>
  <name>MyEEG</name>
  <type>EEG</type>
  <channel_count>64</channel_count>
  ...
  <security>
    <enabled>true</enabled>
    <public_key>base64_encoded_key</public_key>
    <fingerprint>BLAKE2b:70:14:e1:b5:...</fingerprint>
  </security>
</info>
```

Access via standard XML parsing:

```c
const char* xml = lsl_get_xml(info);
// Parse XML to extract security node
```

---

## Usage Pattern

### Creating a Secure Outlet

```c
#include <lsl_c.h>

int main() {
    // Check if security is configured locally
    if (!lsl_local_security_enabled()) {
        fprintf(stderr, "Security not configured. Run lsl-keygen first.\n");
        return 1;
    }

    // Create stream info (security is automatic)
    lsl_streaminfo info = lsl_create_streaminfo(
        "SecureEEG",    // name
        "EEG",          // type
        64,             // channels
        1000,           // sampling rate
        cft_float32,    // format
        "myuid123"      // source ID
    );

    // Verify security is enabled
    if (lsl_get_security_enabled(info)) {
        printf("Stream will be encrypted\n");
        printf("Fingerprint: %s\n", lsl_get_security_fingerprint(info));
    }

    // Create outlet (encryption happens automatically)
    lsl_outlet outlet = lsl_create_outlet(info, 0, 360);

    // Push samples (they are encrypted transparently)
    float sample[64];
    while (1) {
        // Fill sample with data
        lsl_push_sample_f(outlet, sample);
    }

    lsl_destroy_outlet(outlet);
    lsl_destroy_streaminfo(info);
    return 0;
}
```

### Creating a Secure Inlet

```c
#include <lsl_c.h>

int main() {
    // Resolve secure streams
    lsl_streaminfo results[10];
    int count = lsl_resolve_byprop(results, 10, "type", "EEG", 0, 5.0);

    for (int i = 0; i < count; i++) {
        printf("Found: %s\n", lsl_get_name(results[i]));

        if (lsl_get_security_enabled(results[i])) {
            printf("  Encrypted: YES\n");
            printf("  Fingerprint: %s\n", lsl_get_security_fingerprint(results[i]));
        } else {
            printf("  Encrypted: NO\n");
        }
    }

    if (count > 0) {
        // Create inlet (decryption happens automatically)
        lsl_inlet inlet = lsl_create_inlet(results[0], 360, 0, 1);

        // Pull samples (they are decrypted transparently)
        float sample[64];
        double timestamp;
        while (1) {
            timestamp = lsl_pull_sample_f(inlet, sample, 64, LSL_FOREVER, NULL);
            // Process sample
        }

        lsl_destroy_inlet(inlet);
    }

    // Clean up
    for (int i = 0; i < count; i++) {
        lsl_destroy_streaminfo(results[i]);
    }

    return 0;
}
```

---

## Error Handling

Security-related errors are reported through LSL's standard error mechanism:

```c
int32_t error_code;
lsl_pull_sample_f(inlet, sample, 64, 1.0, &error_code);

if (error_code != 0) {
    printf("Error: %s\n", lsl_last_error());
}
```

Common security error messages:

| Error | Cause |
|-------|-------|
| "Connection refused: security mismatch" | One side has security, other doesn't |
| "Connection refused: outlet does not have security enabled" | Secure inlet, insecure outlet |
| "Connection refused: outlet requires security" | Insecure inlet, secure outlet |
| "Authentication failed" | Key verification failed |
| "Decryption failed" | Data tampering detected |

---

## Thread Safety

All security functions are thread-safe. Multiple threads can:

- Query security status simultaneously
- Create multiple secure outlets/inlets
- Push/pull from different streams concurrently

---

## Next Steps

- [C++ API Reference](cpp-api.md) - Object-oriented interface
- [Python API Reference](python.md) - Python bindings
- [How Encryption Works](../security/how-it-works.md) - Technical details
