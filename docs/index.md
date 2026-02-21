# Secure LSL

!!! info inline end "Current Version"
    **{{ slsl_version.full }}**

    - Base: {{ slsl_version.base }}
    - Security: {{ slsl_version.security }}
    - Stage: {{ slsl_version.stage }}

**Transparent encryption for Lab Streaming Layer biosignal streaming**

Secure LSL adds end-to-end encryption to LSL without requiring any changes to your existing applications. Your EEG, eye tracking, and other biosignal data is automatically protected using the same cryptographic standards trusted by banks and governments.

---

## Why Secure LSL?

<div class="grid cards" markdown>

- :material-shield-lock: **Regulatory Compliance**

    Meet EU CRA, NIS2, HIPAA, and GDPR requirements for clinical and research applications involving human subjects.

- :material-lightning-bolt: **Minimal Migration**

    Dynamically linked LSL applications (pylsl, MATLAB, most apps) work by pointing to the new library. Statically linked C++ apps need recompilation.

- :material-clock-fast: **Real-Time Performance**

    Less than 5% overhead. Your 1000 Hz EEG streams stay synchronized to the millisecond.

- :material-check-all: **Tamper Detection**

    Every packet is authenticated. Any modification, even a single bit flip, is detected immediately.

</div>

---

## Quick Start

Get secure streaming in a few steps:

```bash
# 1. Generate and export a shared keypair (creates lab_shared.pub + lab_shared.key.enc)
./lsl-keygen --export lab_shared

# 2. Import on EVERY device (including the one that generated it)
./lsl-keygen --import lab_shared.key.enc

# 3. (Optional) Create a device-bound session token for convenience
./lsl-config --remember-device --passphrase

# Your existing LSL applications now stream encrypted data automatically.
```

[Get Started :material-arrow-right:](getting-started/quickstart.md){ .md-button .md-button--primary }

---

## How It Works

1. **Discovery (UDP)** -- Your EEG amplifier advertises itself on the network, including a security fingerprint that identifies it as a trusted device.
2. **Secure Connection (TCP)** -- When LabRecorder connects, both sides exchange keys and verify each other's identity before any data flows.
3. **Encrypted Streaming** -- Every sample is encrypted with a session key before transmission and verified on receipt. Replay protection ensures old packets cannot be re-injected.

The encryption happens inside the LSL library itself. Applications that load liblsl dynamically (pylsl, MATLAB) see regular LSL data; the encryption/decryption is completely invisible. Statically linked C++ applications need to be recompiled against liblsl-secure.

[Learn More :material-arrow-right:](security/how-it-works.md){ .md-button }

---

## Security at a Glance

| What | How | Why It Matters |
|------|-----|----------------|
| **Device Identity** | Ed25519 digital signatures | Only authorized devices can connect |
| **Data Encryption** | ChaCha20-Poly1305 | Your biosignals are unreadable to eavesdroppers |
| **Tamper Detection** | Authenticated encryption | Modified packets are rejected automatically |
| **Replay Prevention** | Monotonic nonces | Old packets can't be re-injected |
| **Forward Secrecy** | Session keys rotate periodically | Past recordings stay safe even if keys leak |

---

## Supported Platforms

- **Operating Systems**: macOS, Linux, Windows
- **Languages**: C/C++, Python (pylsl), MATLAB
- **Hardware**: x86_64, ARM (Apple Silicon, Raspberry Pi)

Most LSL applications load liblsl dynamically and require no code changes; just point them to liblsl-secure. Statically linked applications need recompilation. See the [Migration Guide](getting-started/migration.md) for details.

---

## Regulatory Compliance

Secure LSL helps you meet:

- **EU Cyber Resilience Act** (2024/2847) - Secure by default (§2.b), encryption (§2.e), integrity (§2.f) — *mandatory Dec 2027*
- **EU NIS2 Directive** (2022/2555) - Multi-factor authentication (Art. 21(2)(j)), cryptography (Art. 21(2)(h)) — *in effect*
- **European Health Data Space** (2025/327) - Encryption in transit, access control — *main provisions apply March 2029*
- **HIPAA** Technical Safeguards (45 CFR §164.312)
- **GDPR** Article 32 security requirements
- **FDA** 21 CFR Part 11 electronic records

[See Compliance Details :material-arrow-right:](security/security-model.md#compliance-mapping){ .md-button }

---

## Get Started

<div class="grid cards" markdown>

- :material-rocket-launch: **[Quick Start Guide](getting-started/quickstart.md)**

    Get encryption running in 5 minutes

- :material-book-open: **[How It Works](security/how-it-works.md)**

    Understand the security without needing a crypto PhD

- :material-code-tags: **[API Reference](api/c-api.md)**

    Check security status in your applications

- :material-frequently-asked-questions: **[FAQ](faq.md)**

    Common questions answered

</div>

---

## License

Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.

Author: Seyed Yahya Shirazi, SCCN, INC, UCSD

Secure LSL is proprietary software. See [LICENSE](../LICENSE) for terms.
