# Security Model

Threat model and security guarantees for Secure LSL.

---

## Architecture Overview

Secure LSL implements a centrally-managed authorization model designed for the operational realities of research and clinical data acquisition environments. A trusted administrator generates a keypair and provisions it to all authorized devices within a deployment. Private keys are encrypted at rest using a passphrase-derived key, providing resistance against offline attacks on stolen configuration files.

Data transmission uses unique per-connection session keys derived through key agreement and key derivation, with authenticated encryption providing confidentiality, integrity, and replay protection. This architecture establishes a cryptographically enforced trust boundary at the network level while remaining transparent to dynamically linked applications, requiring no code changes for the vast majority of existing LSL software. Statically linked C++ applications must be recompiled against liblsl-secure.

---

## Threat Model

### Assets to Protect

1. **Biosignal data in transit**: EEG, EMG, ECG, and other physiological signals
2. **Research integrity**: Ensuring recorded data hasn't been tampered with
3. **Device authenticity**: Verifying data sources are legitimate

### Adversary Capabilities

Secure LSL protects against adversaries who can:

| Capability | Protected? |
|------------|-----------|
| Read network traffic (passive eavesdropping) | Yes |
| Modify network traffic (active MITM) | Yes |
| Inject packets into the network | Yes |
| Replay captured packets | Yes |
| Connect unauthorized devices | Yes |
| Compromise the network infrastructure | Yes |

Secure LSL does NOT protect against:

| Capability | Why Not |
|------------|---------|
| Physical access to devices | Out of scope (endpoint security) |
| Compromise of endpoint OS | Out of scope (endpoint security) |
| Denial of service | Network-level mitigation required |
| Side-channel attacks on the host | Mitigated by libsodium, not fully prevented |

---

## Security Guarantees

### Confidentiality

**Guarantee**: Only authorized endpoints can read biosignal data.

- Authenticated encryption with 256-bit symmetric keys
- Unique session keys per connection
- Key material never transmitted in plaintext

### Integrity

**Guarantee**: Any modification to data in transit is detected.

- Per-packet message authentication
- Verification before decryption
- In testing, 10,000 modified packets were presented: **100% detected and rejected**

### Authorization

**Guarantee**: Only devices with the shared keypair can communicate.

- Public key comparison during connection establishment
- Mutual verification ensures both parties possess matching credentials
- Mismatched keys result in immediate connection rejection

### Replay Protection

**Guarantee**: Captured packets cannot be re-injected.

- Monotonically increasing nonces per connection
- Sliding window tolerates minor reordering
- In testing, all replay attempts were rejected

### Session Key Isolation

**Guarantee**: Each connection uses a unique session key.

- Session keys derived per connection with connection-specific context
- Automatic periodic key rotation
- Session keys exist only in memory during connection lifetime

---

## Unanimous Security Enforcement

Secure LSL enforces unanimous security: either all devices are secure, or all are insecure. Mixed environments are rejected.

### Enforcement Matrix

| Outlet | Inlet | Result |
|--------|-------|--------|
| Secure | Secure | Connected (encrypted) |
| Insecure | Insecure | Connected (plaintext) |
| Secure | Insecure | Rejected |
| Insecure | Secure | Rejected |

**Why this design?**

1. **No partial protection**: A single insecure link exposes the entire data flow
2. **Clear compliance**: "Is the system secure?" has a yes/no answer
3. **Migration pressure**: Adding one secure device encourages updating all
4. **Prevents downgrade attacks**: Attackers cannot force insecure connections

### Error Messages

Clear, actionable error messages guide users:

- "Connection refused: outlet does not have security enabled"
- "Connection refused: outlet requires security but local security is not configured"
- "Connection refused: security configuration mismatch"

---

## Cryptographic Choices

### Why Ed25519?

| Property | Benefit |
|----------|---------|
| 32-byte keys | Fits in discovery packets |
| Fast verification | No delay for real-time systems |
| Side-channel resistant | Safe on shared systems |
| Widely deployed | Proven in OpenSSH, Signal |

### Why ChaCha20-Poly1305?

| Property | Benefit |
|----------|---------|
| No hardware dependency | Fast on ARM, embedded devices |
| Authenticated | Encryption + integrity in one operation |
| Constant-time | No timing side channels |
| IETF standardized | Interoperable, well-analyzed |

---

## Compliance Mapping

### EU Cyber Resilience Act (2024/2847)

*Full compliance mandatory from 11 December 2027; vulnerability reporting from 11 September 2026*

| Requirement | Annex I Reference | Secure LSL Implementation |
|-------------|-------------------|--------------------------|
| No known exploitable vulnerabilities | S2.a | Built on libsodium; no custom cryptography |
| Secure by default configuration | S2.b | Security enabled by default; explicit opt-out required |
| Unauthorized access protection | S2.d | Keypair verification; unauthorized devices rejected |
| Data confidentiality via encryption | S2.e | Authenticated encryption for all data in transit |
| Data integrity protection | S2.f | MAC detects any modification; tampered packets rejected |
| Limit attack surfaces | S2.j | Minimal external interfaces |
| Security event logging | S2.l | Connections, authentication failures, and key events logged |

### EU NIS2 Directive (2022/2555)

*In effect since 18 October 2024*

| Requirement | Article | Secure LSL Implementation |
|-------------|---------|--------------------------|
| Cryptography policies | Art. 21(2)(h) | Standard authenticated encryption and key exchange |
| Multi-factor authentication | Art. 21(2)(j) | Passphrase + device-bound token |
| Access control | Art. 21(2)(d) | Keypair authorization; unauthorized devices rejected |
| Incident logging | Art. 21(2)(b) | Security events logged |
| Risk assessment | Art. 21(2)(a) | Documented threat model |

### European Health Data Space (EU 2025/327)

*Entered into force 26 March 2025; main provisions apply March 2029*

| Requirement | Secure LSL Implementation |
|-------------|--------------------------|
| Encryption of data in transit | Authenticated encryption |
| Access control compliance | Keypair authorization |
| Interoperability security | Standard cryptographic primitives (libsodium) |
| Data integrity guarantees | MAC on all transmitted data |

### HIPAA Technical Safeguards

| Requirement | Secure LSL Implementation |
|-------------|--------------------------|
| S164.312(a)(1) Access Control | Device authentication |
| S164.312(b) Audit Controls | Security event logging |
| S164.312(c)(1) Integrity | Message authentication |
| S164.312(d) Authentication | Device identity verification |
| S164.312(e)(1) Transmission Security | Authenticated encryption |

### GDPR Article 32

| Requirement | Implementation |
|-------------|---------------|
| Pseudonymisation and encryption | Authenticated encryption for data in transit |
| Confidentiality | Authenticated encryption |
| Integrity | Message authentication |
| Regular testing | Automated security tests |

### FDA 21 CFR Part 11

| Requirement | Implementation |
|-------------|---------------|
| Electronic signatures | Device identity |
| Audit trails | Logging of security events |
| Data integrity | Authenticated encryption |

---

## Security Boundaries

### What We Protect

- Data in transit
- Device authentication
- Data integrity
- Replay prevention

### What We Do Not Protect

| Not Protected | Why | Solution |
|--------------|-----|----------|
| Data at rest (XDF files) | Out of scope | File/disk encryption |
| Denial of service | Network infrastructure issue | Firewalls, network security |
| Compromised endpoints | OS security issue | Endpoint protection |
| Metadata (stream names) | Required for discovery | Acceptable trade-off |

Actual biosignal values are always encrypted.

---

## Operational Security

### Key Management

1. **Generation**: Run `lsl-keygen` and enter a passphrase when prompted (cryptographically secure random, passphrase-protected by default)
2. **Storage**: Private key encrypted at rest in `~/.lsl_api/lsl_api.cfg`
3. **Distribution**: Export with `lsl-keygen --export`, import on target devices with `lsl-keygen --import`
4. **Session keys**: Rotate automatically per connection
5. **Device tokens**: Optional device-bound tokens for automatic unlock via `lsl-config --remember-device`

### Incident Response

If the shared keypair is compromised:

1. Generate new keypair: `lsl-keygen --force` (enter new passphrase when prompted)
2. Distribute new keypair to all authorized devices
3. Future sessions protected with new keypair
4. Unauthorized devices with old keypair will be rejected

### Audit Trail

Enable logging for security events:

```ini
[log]
level = 4  ; Info level captures security events
```

Logged events include connection establishment, security negotiation outcomes, authentication failures, decryption failures, and key rotation events.

---

## Regulatory References

| Regulation | Official Source |
|------------|-----------------|
| EU Cyber Resilience Act (2024/2847) | [EUR-Lex Full Text](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng) |
| EU NIS2 Directive (2022/2555) | [EUR-Lex Full Text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555) |
| European Health Data Space (2025/327) | [EUR-Lex](https://eur-lex.europa.eu/) |

---

## Next Steps

- [How Encryption Works](how-it-works.md) -- Technical explanation
- [Architecture Overview](../architecture/overview.md) -- System architecture
- [FAQ](../faq.md) -- Common questions
