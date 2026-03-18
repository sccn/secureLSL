# Security Guide

liblsl-ESP32 supports secureLSL encryption, providing end-to-end authenticated encryption between ESP32 devices and desktop LSL applications.

## Overview

When security is enabled, all streaming data is encrypted with ChaCha20-Poly1305 (the same algorithm used by desktop secureLSL). This provides:

- **Confidentiality**: streaming data cannot be read by eavesdroppers
- **Integrity**: tampered packets are detected and rejected
- **Authentication**: only devices with the shared keypair can communicate
- **Replay prevention**: monotonically increasing nonces prevent replay attacks

## Key Concepts

### Shared Keypair Model

All devices in a lab share the same Ed25519 keypair. Authorization is based on public key matching: if a connecting device presents the same public key, it is authorized to communicate. This is the same model used by desktop secureLSL.

### Unanimous Enforcement

Both sides must agree on security state. If the outlet has security enabled but the inlet does not (or vice versa), the connection is rejected with a 403 error. Mixed encrypted/unencrypted networks are not allowed.

## Setup

### Step 1: Generate or Import Keys

**Option A: Generate on ESP32**
```c
#include "lsl_esp32.h"
#include "nvs_flash.h"

// NVS must be initialized before key operations
nvs_flash_init();

// Generate new Ed25519 keypair (stored in NVS)
lsl_esp32_generate_keypair();

// Export public key for sharing with desktop
char pubkey[LSL_ESP32_KEY_BASE64_SIZE];
lsl_esp32_export_pubkey(pubkey, sizeof(pubkey));
printf("Public key: %s\n", pubkey);
```

**Option B: Import desktop keypair**
```c
// Import base64-encoded keypair (from desktop secureLSL config)
lsl_esp32_import_keypair(
    "PqyFnq8EdB4kkp88KBHZ2DuSy9qbEspO5QSUqPnUvc0=",  // public
    "NdausXwoiZ7yPgh0UcncBc1LDAy58dNaD6d/guA8i8E+..."   // private
);
```

**Option C: Configure via menuconfig**

The secure examples (`examples/secure_outlet`, `examples/secure_inlet`) support key configuration via `idf.py menuconfig`:
```
Example Configuration -> secureLSL public key (base64)
Example Configuration -> secureLSL private key (base64)
```

### Step 2: Configure Desktop

Edit `~/.lsl_api/lsl_api.cfg` (or `~/lsl_api/lsl_api.cfg`):
```ini
[security]
enabled = true
private_key = NdausXwoiZ7yPgh0UcncBc1LDAy58dNaD6d/guA8i8E+rIWerwR0HiSSnzwoEdnYO5LL2psSyk7lBJSo+dS9zQ==
```

The desktop must use the secureLSL library (built with `-DLSL_SECURITY=ON`), not standard liblsl.

### Step 3: Enable Security in Code

```c
void app_main(void) {
    nvs_flash_init();

    // Enable security before creating outlets/inlets
    lsl_esp32_err_t err = lsl_esp32_enable_security();
    if (err != LSL_ESP32_OK) {
        ESP_LOGE(TAG, "Security setup failed: %d", err);
        return;
    }

    wifi_helper_init_sta();

    // Create outlet as usual -- encryption is automatic
    lsl_esp32_stream_info_t info = lsl_esp32_create_streaminfo(...);
    lsl_esp32_outlet_t outlet = lsl_esp32_create_outlet(info, 0, 360);

    // Push samples -- encrypted transparently
    lsl_esp32_push_sample_f(outlet, data, 0.0);
}
```

## Extracting Keys from Desktop Config

The desktop's `lsl_api.cfg` contains a base64 private key (64 bytes: 32-byte seed + 32-byte public key). To extract the public key for ESP32:

```python
import base64
sk_b64 = "YOUR_PRIVATE_KEY_BASE64"
sk = base64.b64decode(sk_b64)
pk = sk[32:]  # Public key is last 32 bytes
pk_b64 = base64.b64encode(pk).decode()
print(f"Public key: {pk_b64}")
```

## Algorithms

| Operation | Algorithm | Library |
|-----------|-----------|---------|
| Device identity | Ed25519 | libsodium |
| Key exchange | X25519 (from Ed25519 conversion) | libsodium |
| Key derivation | BLAKE2b with "lsl-sess" domain separator | libsodium |
| Stream encryption | ChaCha20-Poly1305 IETF | libsodium |
| Key storage | ESP32 NVS (Non-Volatile Storage) | ESP-IDF |

## Key Storage

Keys are stored in NVS namespace `"lsl_security"`:

| Field | Type | Size |
|-------|------|------|
| enabled | uint8 | 1 byte |
| public_key | blob | 32 bytes |
| private_key | blob | 64 bytes |

Keys persist across reboots. To erase: `nvs_flash_erase()` (erases all NVS data).

## Troubleshooting

### "Security mismatch: server=enabled, client=disabled"
Both sides must have security in the same state. Either enable security on both or disable on both.

### "Failed to connect to outlet" with 403
The ESP32 or desktop rejected the connection due to a security mismatch or key mismatch. Check that both sides have the same keypair.

### "Security enabled but keys not loadable"
No keypair is provisioned in NVS. Call `lsl_esp32_generate_keypair()` or `lsl_esp32_import_keypair()` first.

### Desktop pylsl gets 403 from secure ESP32
Standard pylsl (liblsl v1.17+) is not compiled with security support. Use the secureLSL library built with `-DLSL_SECURITY=ON`.
