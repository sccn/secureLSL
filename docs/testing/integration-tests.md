# Integration Tests

This page documents manual end-to-end integration testing performed on real hardware. All scenarios listed below have been verified to pass.

---

## Test Environment

| Device | Hardware | OS | Role |
|--------|----------|----|------|
| Mac Mini | Apple M4 Pro, 24 GB | macOS 15.3 (Sequoia) | Primary dev machine, inlet, Lab Recorder |
| Desktop (Intel) | Intel i9-13900K (32 threads), 62 GB | Ubuntu 24.04 | Secondary validation platform |
| Raspberry Pi 5 | Cortex-A76 (4-core), 8 GB | Debian 12 (Bookworm) | Outlet for cross-machine tests |

Network configuration for cross-machine tests: 802.11ac WiFi (home router), ping latency 5-8 ms.

---

## Test Summary

| Category | Tests | Machine(s) | Result |
|----------|-------|------------|--------|
| Key management (generate, passphrase, token, export/import) | 4 | Mac Mini, Intel i9 | All PASS |
| Secure stream communication (same machine) | 3 | Mac Mini, Intel i9 | All PASS |
| Cross-machine: same keys, different keys, insecure client | 3 | Mac + RPi 5 (WiFi) | All PASS |
| Cross-machine: device-bound session tokens | 1 | Mac + RPi 5 (WiFi) | PASS |
| Lab Recorder: secure/insecure/mismatch scenarios | 5 | Mac + RPi 5 (WiFi) | All PASS |
| SigVisualizer: secure/mismatch scenarios | 3 | Mac | All PASS |
| Error handling (wrong passphrase, missing config, corrupted key, bad import) | 4 | Mac Mini, Intel i9 | All PASS |
| C++ unit tests | 27 cases, 3059 assertions | Mac Mini | PASS |
| C++ exported API tests | 13 cases, 1036 assertions | Mac Mini | PASS |

---

## Category Details

### 1. Key Management Tests

#### 1.1 Key generation without passphrase

**Procedure:** Run `lsl-keygen` with a fresh config directory.

**Verified:**

- [x] Config file created with `[security]` section.
- [x] `private_key` field contains a base64-encoded Ed25519 private key.
- [x] `public_key` field contains a base64-encoded Ed25519 public key.
- [x] No `encrypted_private_key` field present.

#### 1.2 Key generation with passphrase

**Procedure:** Run `lsl-keygen` and enter a test passphrase at the interactive prompt.

**Verified:**

- [x] Config file created with `[security]` section.
- [x] `encrypted_private_key` field is present.
- [x] No plaintext `private_key` field.
- [x] `public_key` field present.

#### 1.3 Device-bound session token

**Procedure:** After generating a passphrase-protected key, run `lsl-config --remember-device --passphrase`.

**Verified:**

- [x] Device ID displayed as a 64-character hex string.
- [x] Passphrase prompted securely (no echo in terminal).
- [x] Session token created successfully.
- [x] Session token file created in `~/.lsl_api/`.
- [x] Public key displays WITHOUT passphrase prompt after token creation.
- [x] `--forget-device` removes the token.

#### 1.4 Key export and import

**Procedure:** Export key with `lsl-keygen --export`, copy files, import on a simulated new device with `lsl-keygen --import`.

**Verified:**

- [x] `.pub` file created (public key).
- [x] `.key.enc` file created (encrypted private key).
- [x] Import succeeds with the correct passphrase.

---

### 2. Secure Stream Communication Tests

#### 2.1 Insecure outlet rejected by secure inlet

**Scenario:** An outlet without a security config attempts to connect to a secure inlet.

**Result:** Connection rejected with `403 Security required but client has no security enabled`.

#### 2.2 Secure outlet rejects insecure inlet

**Scenario:** A secure outlet refuses an incoming connection from an inlet that has no security credentials.

**Result:** Connection rejected with `403 Security required but client has no security enabled`.

#### 2.3 Both insecure (baseline)

**Scenario:** Standard LSL communication with security disabled on both sides.

**Result:** 50 samples received correctly. No errors.

---

### 3. Lab Recorder Integration Tests

All Lab Recorder tests used a build linked against `liblsl-secure.dylib`. The secure library is a drop-in replacement: the Lab Recorder binary is identical; only the library it loads changes.

#### 3.1 Secure stream discovery with lock icon

Lab Recorder discovers a secure stream and displays a lock icon at the end of the stream name. Security status is visible in the stream list.

**Result:** PASS.

#### 3.2 Secure outlet + secure recorder (recording works)

A Raspberry Pi 5 outlet streams with security enabled. Lab Recorder on the Mac Mini, configured with the same shared keypair, records the stream.

**Result:** Recording successful. 28 KB XDF file created in 12 seconds. Log shows "Secure session established" and "Using encrypted data transfer".

#### 3.3 Insecure outlet + insecure recorder (baseline)

Both sides have no security configuration.

**Result:** Recording successful. No errors.

#### 3.4 Secure outlet + insecure recorder (rejection)

A Raspberry Pi 5 outlet streams with security enabled. Lab Recorder has no security credentials.

**Result:** Connection rejected repeatedly. Log shows `403 Security required but client has no security enabled`. Recording file created but remains at 0 KB.

#### 3.5 Security mismatch detection UI (pre-recording check)

When a user selects a secure stream in Lab Recorder configured without security (or vice versa) and clicks Start, Lab Recorder detects the mismatch before opening any connections and displays a clear error dialog.

**Result:** PASS.

- Error dialog appears immediately before recording starts.
- Dialog lists the affected stream names.
- Dialog explains the issue and how to resolve it.
- Warning text: "Recording cannot proceed with mismatched security settings."
- Recording does NOT start; no empty files are created.

---

### 4. Cross-Machine Tests (Mac Mini + Raspberry Pi 5)

Tests were conducted over **802.11ac WiFi** (ping latency 5-8 ms). All functional integration tests in this section used WiFi only; the Ethernet configuration was evaluated separately in the performance benchmarks (see [Benchmarks](benchmarks.md)). The shared keypair was distributed using `lsl-keygen --export` on the Mac Mini and `lsl-keygen --import` on the Raspberry Pi 5.

#### 4.1 Matching keys: accepted

**Procedure:**

- Raspberry Pi 5 runs `cpp_secure_outlet` (outlet).
- Mac Mini runs `cpp_secure_inlet` (inlet) and joins mid-stream.

**Result:** PASS.

- Stream discovered across network.
- Log: "Secure session established with client (fingerprint: BLAKE2b:xx:xx...)".
- Encrypted data transmitted and decrypted correctly.
- Sequential sample values (e.g., 25388, 25389, 25390...) confirm correct decryption.
- Validation warnings about sample offset are expected when an inlet joins a running outlet; they are not failures.

#### 4.2 Different keys: rejected

**Procedure:**

- Raspberry Pi 5 runs outlet with the shared lab key.
- Mac Mini inlet uses a different key (different keypair).

**Result:** PASS.

- Stream is discoverable (visible to the resolver).
- Connection attempt fails with `403 Public key mismatch - not authorized`.
- Outlet log: "Connection refused: client has different public key".
- Inlet retried 9 times; all rejected. No data transferred.

#### 4.3 Cross-machine Lab Recorder recording

**Procedure:**

- Raspberry Pi 5 runs secure outlet.
- Mac Mini runs Lab Recorder with the same shared keypair.

**Result:** PASS. 32 KB XDF file recorded in 14 seconds. Lock icon visible for the remote stream.

---

### 5. SigVisualizer Integration Tests

SigVisualizer uses the same `lsl_security_helper.py` helper used by Lab Recorder to check local security status before creating inlets.

| Scenario | Result | Notes |
|----------|--------|-------|
| Secure outlet + insecure SigVisualizer | PASS | Error dialog shown before connection attempt; stream name visible with lock icon |
| Secure outlet + secure SigVisualizer | PASS | Data visualized correctly with encryption active |
| Lock icon display | PASS | Lock icon shown for secure streams in stream list |

---

### 6. Cross-Machine: Insecure Client Rejected

**Procedure:**

- Raspberry Pi 5 runs a secure outlet.
- Mac Mini runs an insecure inlet (no security config).

**Result:** PASS.

- Stream IS discovered across the network.
- Connection rejected with `403 Security required but client has no security enabled`.
- Outlet log: "Connection refused: client does not have security enabled (unanimous security enforcement)".
- Inlet retried 3 times; all rejected. Timed out with no data transferred.

### 7. Cross-Machine: Device-Bound Session Tokens

**Procedure:**

- Generate a passphrase-protected shared keypair.
- Import on both Mac Mini and Raspberry Pi 5.
- Create device-bound session tokens on both devices (`lsl-config --remember-device`).
- Run outlet on RPi and inlet on Mac; neither should prompt for a passphrase.

**Result:** PASS.

- Both devices show "Auto-unlock successful using device session token".
- Secure session established; 20 samples received with encrypted data transfer.
- No passphrase prompts at any point after token creation.
- Device IDs are hardware-bound (different tokens per machine).

### 8. Error Handling Tests

The following error and rejection scenarios have been validated:

| Scenario | Expected Behavior | Verified |
|----------|------------------|---------|
| Wrong key on inlet | `403 Public key mismatch - not authorized` | Yes (cross-machine test 4.2) |
| Insecure client, secure outlet | `403 Security required but client has no security enabled` | Yes (tests 2.1, 2.2, 3.4, 6) |
| Security mismatch in Lab Recorder | Pre-recording error dialog, no file created | Yes (test 3.5) |
| Security mismatch in SigVisualizer | Pre-connection error dialog | Yes (section 5) |
| Wrong passphrase | "Failed to decrypt private key: invalid passphrase", exit 1 | Yes |
| Missing config file | Falls back to default config or insecure mode, no crash | Yes |
| Corrupted key file | "Invalid private_key format", exit 1, no crash | Yes |
| Import with wrong passphrase | "Error: Invalid passphrase", import refused | Yes |

---

## How to Reproduce

See the [Benchmarks](benchmarks.md) page for hardware setup. For integration testing:

```bash
# Build
cd liblsl
mkdir -p build && cd build
cmake -DLSL_SECURITY=ON ..
cmake --build . --parallel

# Generate shared key
./lsl-keygen

# Terminal 1: Start outlet
LSLAPICFG=~/.lsl_api/lsl_api.cfg ./cpp_secure_outlet

# Terminal 2: Start inlet
LSLAPICFG=~/.lsl_api/lsl_api.cfg ./cpp_secure_inlet
```

For firewall configuration, ensure LSL ports are open on all machines:

- TCP/UDP 16571-16600

```bash
# Linux (ufw)
sudo ufw allow 16571:16600/tcp
sudo ufw allow 16571:16600/udp

# macOS: System Settings > Network > Firewall > Allow incoming connections for the app
```
