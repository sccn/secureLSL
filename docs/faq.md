# Frequently Asked Questions

Quick answers to common questions about Secure LSL.

---

## General

### Do I need to change my existing code?

**For dynamically linked applications** (pylsl, MATLAB, most LSL apps): no code changes needed. Just point them to liblsl-secure (e.g., set `PYLSL_LIB` for Python) and set up keys.

**For statically linked C++ applications**: you need to recompile against liblsl-secure.

Setup steps:

1. Generate keys on your primary device: `./lsl-keygen`
2. Export and import the shared key on all other devices (see [Configuration](getting-started/configuration.md#multi-device-setup))
3. Point your applications to the secure library
4. Encryption happens automatically

---

### Is this an official LSL project?

Secure LSL is developed by the SCCN lab, the original creators of LSL. It is designed as a backward-compatible extension that can be merged into the main LSL codebase.

---

### What happens if I don't generate keys?

If no keys are configured, the device operates in insecure (legacy) mode. However:

- It can only connect to other insecure devices
- Any secure device on the network will refuse connections
- You'll see clear error messages explaining the mismatch

---

## Security

### How secure is the encryption?

Secure LSL uses the same cryptographic algorithms trusted by:

- **Signal** (end-to-end encrypted messaging)
- **WireGuard** (modern VPN protocol)
- **Google Chrome** (TLS connections)

Specifically, we use Ed25519 for device identity and ChaCha20-Poly1305 for authenticated encryption, both providing strong security against all known attacks.

---

### Can someone decrypt my recorded data if they get my keys later?

**No**, due to forward secrecy. Each connection uses ephemeral session keys derived from a fresh key exchange. Even if your device's private key is compromised later, past recordings cannot be decrypted.

---

### What if someone captures my encrypted network traffic?

They'll see only random-looking bytes. Without the session keys (which exist only in memory during the connection), the data is computationally infeasible to decrypt.

---

### How do I verify a stream is really encrypted?

Use the security API:

```python
import lsl_security_helper  # must come before import pylsl
import pylsl

streams = pylsl.resolve_stream('type', 'EEG')
for stream in streams:
    if stream.security_enabled():
        print(f"Encrypted: {stream.name()}")
        print(f"Fingerprint: {stream.security_fingerprint()}")
```

The fingerprint is a unique identifier derived from the outlet's public key.

---

### What attacks does Secure LSL protect against?

| Attack | Protection |
|--------|------------|
| Eavesdropping | ChaCha20 encryption makes data unreadable |
| Data tampering | Poly1305 authentication detects any modification |
| Replay attacks | Nonce tracking rejects duplicate packets |
| Man-in-the-middle | Key exchange prevents interception |
| Unauthorized access | Ed25519 verifies device identity |

---

### What attacks does Secure LSL NOT protect against?

| Attack | Why | Mitigation |
|--------|-----|------------|
| Denial of service | Network-level attack | Use firewalls |
| Compromised endpoints | OS security issue | Use endpoint protection |
| Physical access to device | Hardware attack | Physical security |
| Data at rest | Out of scope | Use disk encryption |

---

## Performance

### How much overhead does encryption add?

Minimal. In our benchmarks (64ch @ 1000Hz):

| Platform | Overhead | Added Latency |
|----------|----------|---------------|
| Mac Mini M4 Pro (local) | ~1% CPU | < 0.01ms |
| Raspberry Pi 5 (local) | ~1% CPU | < 0.02ms |
| Cross-machine (Ethernet) | 1.06% | +0.8ms |
| Cross-machine (WiFi) | 1.09% | +0.9ms |

This is negligible for biosignal applications.

---

### Will encryption cause packet loss?

**No.** In 48-hour stress tests at maximum throughput, we observed zero packet loss attributable to encryption.

---

### Does encryption affect time synchronization?

Time synchronization remains accurate. The encryption overhead is deterministic and sub-millisecond, well within LSL's synchronization tolerances.

---

## Compatibility

### Does it work with LabRecorder?

Yes. Use the secure version of LabRecorder, which shows lock icons for encrypted streams:

```
Available Streams:
  🔒 EEG-Amplifier (lab-eeg-01)
  🔒 EyeTracker (lab-eye-01)
```

---

### Does it work with MATLAB?

Yes. MATLAB uses the same liblsl library, so encryption works automatically once you point MATLAB to the secure liblsl.

---

### Can I mix secure and insecure devices?

**No**, and this is intentional. Mixed environments create security gaps. Secure LSL enforces unanimous security:

- All secure → encrypted communication
- All insecure → legacy communication
- Mixed → connection refused with clear error

---

### What LSL versions are supported?

Secure LSL is based on liblsl 1.16+ and maintains full API compatibility with standard LSL applications.

---

## Configuration

### Where are keys stored?

By default:

- macOS/Linux: `~/.lsl_api/lsl_api.cfg`
- Windows: `%USERPROFILE%\.lsl_api\lsl_api.cfg`

You can override this with the `LSLAPICFG` environment variable.

---

### Can multiple users share a computer?

Each user account needs the shared lab key imported into their `~/.lsl_api/lsl_api.cfg`. Run `./lsl-keygen --import lab_shared.key.enc` under each user account that will use LSL.

---

### How do I regenerate keys?

```bash
./lsl-keygen --force
```

The `--force` flag overwrites existing keys. Note that this creates a new keypair; you will need to re-export and re-import on all other lab devices.

---

### How do I set up keys on multiple devices?

Secure LSL uses a **shared keypair model**: all devices in your lab must have the same key. Generate and export on one device, then import on every device (including the one that generated it):

```bash
# On the primary device, generate and export
./lsl-keygen --export lab_shared

# On EVERY device (including the primary), import
./lsl-keygen --import lab_shared.key.enc
```

If you already have a key in your config and want to export it for other devices, use `--export-existing` instead of `--export` (which generates a new key).

See the [Multi-Device Setup](getting-started/configuration.md#multi-device-setup) guide for details.

---

## Troubleshooting

### "Connection refused: security mismatch"

Devices have different keypairs (or one is missing a key). All devices must share the same keypair. Import the shared key on any device that lacks it:

```bash
./lsl-keygen --import lab_shared.key.enc
```

Do NOT run `./lsl-keygen` independently on each device -- this creates different keypairs that will continue to reject each other.

### "Configuration file not found"

Run `./lsl-keygen` to generate the configuration.

### Streams visible but won't connect

1. Check security status: `./lsl-config --check`
2. Verify both devices use secure liblsl
3. Check firewall settings for TCP

[See full troubleshooting guide →](troubleshooting.md)

---

## Still have questions?

- Check the [troubleshooting guide](troubleshooting.md)
- Read [how encryption works](security/how-it-works.md)
- Open an issue on [GitHub](https://github.com/sccn/secureLSL/issues)
