# Configuration

Advanced configuration options for Secure LSL.

---

## Configuration File

Secure LSL uses LSL's standard configuration file (`lsl_api.cfg`) with an added `[security]` section.

### File Locations

The configuration file is searched in this order:

1. `$LSLAPICFG` environment variable (if set)
2. `./lsl_api.cfg` (current working directory)
3. `~/.lsl_api/lsl_api.cfg` (user home directory)
4. `/etc/lsl_api/lsl_api.cfg` (system-wide, Linux/macOS)
5. `%PROGRAMDATA%\lsl_api\lsl_api.cfg` (system-wide, Windows)

### File Format

```ini
[security]
enabled = true
; Key field is 'encrypted_private_key' (default, with passphrase)
; or 'private_key' (when generated with --insecure)
encrypted_private_key = base64_encoded_encrypted_key_here
key_created = 2025-12-05T19:00:00Z
session_key_lifetime = 3600

[log]
level = 4
```

---

## Security Section

### `enabled`

**Type:** boolean
**Default:** `true` (if private_key is present)

Enables or disables security. When disabled, the device operates in legacy insecure mode.

```ini
[security]
enabled = true
```

!!! warning
    Setting `enabled = false` when other devices have security enabled will cause connection failures.

### `private_key`

**Type:** string (base64-encoded)
**Required:** Yes, unless `encrypted_private_key` is set

The Ed25519 private key for this device. Generated automatically by `lsl-keygen`.

```ini
[security]
private_key = MC4CAQAwBQYDK2VwBCIEIPt8vW9...
```

!!! warning "Protect This Key"
    Share only with authorized lab devices using `lsl-keygen --export`. Never commit to version control or transmit unencrypted over the network.

### `encrypted_private_key`

**Type:** string (base64-encoded)
**Required:** No (alternative to `private_key` for two-factor authentication)

The Ed25519 private key encrypted with a passphrase. Generated when `lsl-keygen` prompts for a passphrase during key generation (the default behavior).
This enables two-factor authentication:

- **Something you have:** the key file
- **Something you know:** the passphrase

```ini
[security]
encrypted_private_key = AAAAAAAAAAAAAAAA...  ; salt + nonce + encrypted key
```

!!! tip "NIS2 Compliance"
    Using passphrase-protected keys satisfies NIS2 multi-factor authentication requirements
    for environments where MFA is mandated.

**Unlocking at runtime:**

1. **Environment variable:** Set `LSL_KEY_PASSPHRASE` before starting your application
2. **Programmatic:** Call `lsl_security_unlock(passphrase)` in your code

```bash
# Option 1: Environment variable
export LSL_KEY_PASSPHRASE="your-passphrase"
./your_lsl_application
```

```cpp
// Option 2: Programmatic unlock (C++)
#include <lsl_c.h>
lsl_security_unlock("your-passphrase");
```

### `key_created`

**Type:** ISO 8601 timestamp
**Default:** Set by `lsl-keygen`

When the key was generated. Used for key rotation tracking.

```ini
[security]
key_created = 2025-12-05T19:00:00Z
```

### `session_key_lifetime`

**Type:** integer (seconds)
**Default:** `3600` (1 hour)

How often session keys are rotated. Lower values provide more forward secrecy but slightly more overhead.

```ini
[security]
session_key_lifetime = 3600  ; 1 hour (default)
```

| Value | Use Case |
|-------|----------|
| 3600 | Standard research use (default) |
| 86400 | Long-running experiments with minimal overhead |
| 604800 | Maximum performance, minimal key rotation |

### `public_key`

**Type:** string (base64-encoded)
**Required:** No (derived from private_key automatically)

The Ed25519 public key. Generated automatically from the private key.

```ini
[security]
public_key = PqyFnq8EdB4kkp88KBHZ2DuSy9qbEspO5QSUqPnUvc0=
```

---

## Device-Bound Session Tokens

For passphrase-protected keys, you can create a device-bound session token to avoid entering the passphrase on every startup. The token is cryptographically bound to your specific hardware.

### Creating a Session Token

```bash
# Create session token (default: 30 days expiry)
./lsl-config --remember-device --passphrase
# Enter your passphrase when prompted

# Create with custom expiry (90 days)
./lsl-config --remember-device --passphrase --days 90

# Create with no expiry (never expires)
./lsl-config --remember-device --passphrase --days -1
```

### How It Works

1. **Device ID**: A unique identifier derived from your hardware (CPU, motherboard, etc.)
2. **Token file**: Stored in `~/.lsl_api/` with encrypted session key
3. **Auto-unlock**: On startup, if token is valid and matches device, key unlocks automatically

### Managing Session Tokens

```bash
# Show your device ID
./lsl-config --show-device-id

# Remove session token (will require passphrase again)
./lsl-config --forget-device
```

### Security Properties

- **Device-bound**: Token only works on the specific hardware where it was created
- **Time-limited**: Expires after configured duration
- **Revocable**: Can be removed with `--forget-device`
- **Hardware-tied**: Moving the token file to another device won't work

!!! tip "Use Cases"
    - **Lab workstations**: Create long-lived tokens for dedicated recording machines
    - **Portable devices**: Use shorter expiry for laptops that may be lost/stolen
    - **Headless systems**: Essential for servers that need unattended startup

---

## Log Section

### `level`

**Type:** integer (0-6)
**Default:** `4` (Info)

Controls log verbosity:

| Level | Name | Description |
|-------|------|-------------|
| 0 | Off | No logging |
| 1 | Fatal | Only fatal errors |
| 2 | Error | Errors |
| 3 | Warning | Warnings and errors |
| 4 | Info | General information |
| 5 | Verbose | Detailed information |
| 6 | Debug | Full debug output |

```ini
[log]
level = 6  ; Enable debug logging for troubleshooting
```

---

## Environment Variables

### `LSLAPICFG`

Override the configuration file location:

```bash
export LSLAPICFG=/path/to/custom/lsl_api.cfg
./my_lsl_application
```

Useful for:

- Testing with different configurations
- Running multiple LSL instances with different keys
- Containerized deployments

### `PYLSL_LIB`

Point Python to a specific liblsl library:

```bash
export PYLSL_LIB=/path/to/liblsl-secure.dylib
python my_script.py
```

---

## Using lsl-keygen

The `lsl-keygen` tool generates keys and creates the configuration file.

### Basic Usage

```bash
./lsl-keygen
```

By default, you will be prompted for a passphrase to protect the private key (like SSH keys).
Creates keys at the default location (`~/.lsl_api/lsl_api.cfg`).

### Options

| Option | Description |
|--------|-------------|
| `--output PATH` | Write configuration to specific path |
| `--force` | Overwrite existing configuration |
| `--insecure` | Store private key WITHOUT passphrase protection (skips the interactive passphrase prompt) |
| `--show-public` | Display public key and fingerprint after generation |
| `--export NAME` | Generate a **new** keypair and export to NAME.pub and NAME.key.enc files (does not install into local config) |
| `--export-existing NAME` | Export the **existing** key from local config to NAME.pub and NAME.key.enc files |
| `--export-public` | Display current public key for sharing |
| `--import FILE` | Import encrypted key file (.key.enc) into local config |
| `--help` | Show help message |

### Examples

```bash
# Generate keys with passphrase protection (default)
./lsl-keygen

# Generate to specific file
./lsl-keygen --output /path/to/lsl_api.cfg

# Regenerate keys (overwrites existing)
./lsl-keygen --force

# Generate WITHOUT passphrase (not recommended for production)
./lsl-keygen --insecure

# Generate and export keys for distribution (new keypair, not installed locally)
./lsl-keygen --export lab_eeg

# Export the existing key from your config (no new key generated)
./lsl-keygen --export-existing lab_eeg

# Import an exported key (on every device, including the one that generated it)
./lsl-keygen --import lab_eeg.key.enc
```

### Passphrase Protection (Default)

By default, `lsl-keygen` prompts for a passphrase to encrypt the private key:

```bash
$ ./lsl-keygen
LSL Security Key Generator
==========================

Private key will be encrypted with a passphrase for security.
(Press Enter for no passphrase, but this is NOT recommended)

Enter passphrase: ********
Confirm passphrase: ********

Generating Ed25519 keypair...

[OK] Keypair generated successfully!
[OK] Configuration saved to: /Users/you/.lsl_api/lsl_api.cfg
[OK] Private key encrypted with passphrase (2FA enabled)

To unlock at runtime (in order of preference):
  1. Device-bound session token: lsl-config --remember-device (recommended)
  2. Environment variable: LSL_KEY_PASSPHRASE (less secure)
  3. Programmatic: call lsl_security_unlock() in your application
```

This satisfies NIS2 multi-factor authentication requirements by combining:

- **Something you have:** the encrypted key file
- **Something you know:** the passphrase

!!! warning "Environment Variable Security"
    While you can use `LSL_KEY_PASSPHRASE` for convenience, environment variables
    are visible to other processes on the same system. For better security, use
    device-bound session tokens instead:

    ```bash
    ./lsl-config --remember-device --passphrase
    ```

### Low-Risk Environments

For closed lab environments without regulatory requirements (EU CRA, NIS2, HIPAA, GDPR),
you can skip the passphrase:

1. **Press Enter twice** when prompted for passphrase (requires confirmation)
2. **Use `--insecure` flag** to skip the prompt entirely (shows warning)

---

## Using lsl-config

The `lsl-config` tool validates and displays configuration.

### Basic Usage

```bash
./lsl-config --check
```

### Output

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

### Options

| Option | Description |
|--------|-------------|
| `--check` | Validate configuration and show status (default) |
| `--show-public` | Display public key and fingerprint for sharing |
| `--show-device-id` | Display this device's unique hardware identifier |
| `--remember-device` | Create device-bound session token (use with `--passphrase`) |
| `--forget-device` | Remove device-bound session token |
| `--days N` | Set session token expiry in days (use with `--remember-device`) |
| `--check-network` | Scan network for LSL streams and verify security |
| `--help` | Show help message |

### Displaying Public Key for Sharing

Use `--show-public` to display your device's public key:

```bash
$ ./lsl-config --show-public
LSL Device Public Key
=====================

Fingerprint:
  BLAKE2b:70:14:e1:b5:7f:93:ae:af...

Public Key (base64):
  abc123DEF456...

This public key can be safely shared with other lab members.
```

---

## Example Configurations

### Research Lab (Default)

Standard configuration for most research environments (generated by `lsl-keygen` with passphrase):

```ini
[security]
enabled = true
encrypted_private_key = AAAAAAAAAAAAAAAA...  ; salt + nonce + encrypted key
public_key = PqyFnq8EdB4kkp88KBHZ2DuSy9qbEspO5QSUqPnUvc0=
key_created = 2025-12-05T19:00:00Z
session_key_lifetime = 3600

[log]
level = 4
```

If you used `--insecure` (no passphrase), the key field will be named `private_key` instead.

### Clinical Environment

High-security configuration for clinical deployments:

```ini
[security]
enabled = true
encrypted_private_key = AAAAAAAAAAAAAAAA...  ; salt + nonce + encrypted key
key_created = 2025-12-05T19:00:00Z
session_key_lifetime = 3600  ; Rotate keys hourly

[log]
level = 3  ; Warnings only in production
```

### Development/Testing

Debug configuration for development:

```ini
[security]
enabled = true
encrypted_private_key = AAAAAAAAAAAAAAAA...  ; salt + nonce + encrypted key
key_created = 2025-12-05T19:00:00Z
session_key_lifetime = 3600

[log]
level = 6  ; Full debug output
```

### Legacy Mode (Not Recommended)

For backward compatibility with systems that cannot be updated:

```ini
[security]
enabled = false

[log]
level = 4
```

!!! danger "Security Risk"
    Legacy mode provides no encryption or authentication. Use only when absolutely necessary and only on isolated networks.

---

## Multi-Device Setup

### Shared Key Authorization Model

Secure LSL uses a **shared keypair model** for authorization. All devices that need to communicate securely must have the **same keypair** (public + private key). Devices with different keys will be rejected as "not authorized."

This model ensures:

- **Simple deployment**: One key pair for your entire lab
- **Clear authorization**: Only devices with your lab's key can connect
- **Easy management**: Add new devices by importing the shared key

### Setting Up Multiple Devices

**Step 1: Generate and export the lab key on your admin/primary machine:**

```bash
# Generate and export a shared keypair (passphrase will be prompted interactively)
./lsl-keygen --export lab_shared
# Enter a strong passphrase when prompted - you'll need this for all devices
# Creates: lab_shared.pub and lab_shared.key.enc
```

!!! warning "`--export` Creates a New Key"
    `--export` generates a new keypair and writes it to files only. It does **not** install
    the key into your local config. You must `--import` on every device, including this one.

    If you already generated a key with `./lsl-keygen` and want to share it, use
    `--export-existing` instead:
    ```bash
    ./lsl-keygen --export-existing lab_shared
    ```

**Step 2: Distribute to all lab devices:**

```bash
# Copy encrypted key to each device
scp lab_shared.key.enc user@device1:~/.lsl_api/
scp lab_shared.key.enc user@device2:~/.lsl_api/
scp lab_shared.key.enc pi@raspberry-pi:/tmp/
```

**Step 3: Import on every device (including the admin machine):**

```bash
# On each device (including the one that generated the key), import the shared key
./lsl-keygen --import /path/to/lab_shared.key.enc
# Enter the same passphrase used during generation

# Verify the fingerprint matches
./lsl-config --show-public
# All devices should show: BLAKE2b:xx:xx:xx:xx...
```

**Step 4: (Optional) Create device-bound session tokens:**

```bash
# On each device, create a session token for unattended operation
./lsl-config --remember-device --passphrase
# Enter passphrase once, then no more prompts on this device
```

### Verification

All authorized devices should show the **same fingerprint**:

```bash
# On any device
./lsl-config --show-public

# Output should match across all devices:
# Fingerprint: BLAKE2b:79:8c:1d:7d:a6:b4:34:22...
```

### What Happens with Different Keys

If a device has a **different** key, connections are rejected:

```
Connection refused: 403 Public key mismatch - not authorized
```

This is intentional security behavior - only devices with your lab's shared key can participate in secure streams.

!!! note "Security Considerations"
    - Exported keys are always encrypted with a passphrase-derived key
    - The `.key.enc` file is safe to transfer over untrusted networks
    - Each device needs the passphrase to unlock (or a device-bound session token)
    - Treat the passphrase like a lab password - share only with authorized personnel

---

## Next Steps

- [Quick Start Guide](quickstart.md) - Basic usage
- [How Encryption Works](../security/how-it-works.md) - Technical details
- [Troubleshooting](../troubleshooting.md) - Common issues
