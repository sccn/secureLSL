# Troubleshooting

Solutions to common issues with Secure LSL.

---

## Connection Issues

### "Connection refused: security mismatch"

**Symptom**: Connection fails with message about security configuration mismatch.

**Cause**: One device has security enabled, the other doesn't.

**Solution**:

1. Check security status on both devices:
   ```bash
   ./lsl-config --check
   ```

2. Ensure all devices have the **same** keypair. Import the lab's shared key on any device showing "security disabled":
   ```bash
   # On the device missing the key -- import the shared keypair
   ./lsl-keygen --import lab_shared.key.enc
   # (NOT ./lsl-keygen -- that creates a NEW, different keypair)
   ```

3. Restart your LSL applications

!!! note "Unanimous Enforcement"
    Secure LSL requires all devices to have the same security state. You cannot mix secure and insecure devices.

---

### "Connection refused: outlet does not have security enabled"

**Symptom**: Your inlet (receiver) has security enabled but the outlet (sender) doesn't.

**Solution**: Import the shared keypair on the outlet device:
```bash
# On the outlet device (e.g., EEG amplifier computer)
./lsl-keygen --import lab_shared.key.enc
# (NOT ./lsl-keygen -- that creates a different keypair causing further mismatches)
```

---

### "Connection refused: outlet requires security but local security is not configured"

**Symptom**: The outlet has security enabled but your inlet doesn't.

**Solution**: Import the shared keypair on your inlet device:
```bash
# On the inlet device (e.g., recording workstation)
./lsl-keygen --import lab_shared.key.enc
# (NOT ./lsl-keygen -- that creates a different keypair causing further mismatches)
```

---

### Streams are visible but won't connect

**Possible causes**:

1. **Security mismatch**: Check both devices with `./lsl-config --check`
2. **Firewall blocking TCP**: LSL uses TCP for data; ensure ports are open
3. **Different LSL versions**: Ensure both devices use the secure liblsl version

---

## Configuration Issues

### "Configuration file not found"

**Symptom**: Security features not working, config check shows no file.

**Solution**:
```bash
# Generate configuration with keys
./lsl-keygen

# Verify it was created
./lsl-config --check
```

**Default locations**:
- macOS/Linux: `~/.lsl_api/lsl_api.cfg`
- Windows: `%USERPROFILE%\.lsl_api\lsl_api.cfg`

---

### Using a custom config location

Set the `LSLAPICFG` environment variable:

```bash
# Point to specific config file
export LSLAPICFG=/path/to/my/lsl_api.cfg

# Generate keys there
./lsl-keygen --output /path/to/my/lsl_api.cfg
```

---

### "Private key is invalid"

**Symptom**: Security check fails with key validation error.

**Cause**: The config file was corrupted or manually edited incorrectly.

**Solution**: Regenerate the keys:
```bash
./lsl-keygen --force  # --force overwrites existing
```

!!! warning
    This creates a new device identity. Other devices won't recognize this device until they reconnect.

---

## Performance Issues

### Higher latency than expected

**Check**:

1. Network conditions (WiFi vs wired)
2. CPU load on the device
3. Whether you're running debug builds

**Expected overhead**:

| Platform | Latency Overhead |
|----------|-----------------|
| Mac Mini M4 Pro (local) | < 0.01ms |
| Raspberry Pi 5 (local) | < 0.02ms |
| Cross-machine (Ethernet) | +0.8ms |

If you see significantly higher, check for other issues.

---

### CPU usage increased significantly

**Normal increase**: 2-5% for standard biosignal workloads.

**If much higher**:

1. Ensure you're using a release build, not debug
2. Check if libsodium was compiled with optimizations
3. Verify no other processes are competing for CPU

---

## Debugging

### Enable verbose logging

Set log level in your config file:

```ini
[security]
enabled = true
private_key = ...

[log]
level = 6  ; Debug level logging
```

Log levels:
- 0 = Off
- 3 = Warning
- 4 = Info
- 6 = Debug (verbose)

---

### Check what library is loaded

Python:
```python
import pylsl
print(pylsl.library_info())  # Should contain "security:X.X.X"
```

You should see version info containing "security" from your secure liblsl, not from a standard system version.

---

### Verify security API is available

Python:
```python
import lsl_security_helper  # must come before import pylsl; provides security_enabled()
import pylsl
streams = pylsl.resolve_stream('type', 'EEG', timeout=5.0)
if streams:
    info = streams[0]
    print(f"Security API available: {info.security_enabled()}")
```

---

## Still Having Issues?

1. **Check the logs**: Enable debug logging as shown above
2. **Verify versions**: Ensure all devices use the same secure liblsl version
3. **Simplify**: Test with just two devices first
4. **Report bugs**: Open an issue at [GitHub](https://github.com/sccn/secureLSL/issues)

When reporting issues, include:
- OS and version
- liblsl version
- Output of `./lsl-config --check`
- Relevant log messages
