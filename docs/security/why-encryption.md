# Why Encryption Matters for Biosignal Research

You might wonder: "I'm just streaming EEG in my lab. Why do I need encryption?"

This page explains why security matters even in research settings, and why Secure LSL was designed the way it is.

---

## The Current State of LSL Security

LSL's official documentation states clearly:

> "The SessionID is not a security feature... you are still able to intercept packets involved in a session that is not yours."

This means:

- **All biosignal data travels in plaintext** over your network
- **Anyone on your network can read your data** with basic tools like Wireshark
- **No authentication** prevents unauthorized devices from connecting
- **No integrity checking** detects if data has been tampered with

In our review of 150+ LSL applications across Python, MATLAB, C++, and other languages, we found **zero existing security implementations**.

---

## Why This Matters

### 1. Regulatory Compliance

If your research involves human subjects, you likely need to comply with data protection regulations:

!!! danger "EU Cyber Resilience Act (2024/2847)"
    **Annex I, Part I** mandates security requirements for products with digital elements.

    - **§2.b**: Products must be *"made available on the market with a secure by default configuration"*
    - **§2.e**: Products must *"protect the confidentiality of stored, transmitted or otherwise processed data...by encrypting relevant data at rest or in transit"*
    - Entered into force: 10 December 2024; applies from: 11 December 2027
    - Applies to all connected products sold in the EU

!!! danger "EU NIS2 Directive (2022/2555)"
    **Article 21(2)** mandates cybersecurity risk-management measures for essential and important entities.

    - **Art. 21(2)(h)**: *"policies and procedures regarding the use of cryptography and, where appropriate, encryption"*
    - **Art. 21(2)(j)**: *"the use of multi-factor authentication or continuous authentication solutions"*
    - In effect since: 18 October 2024
    - Applies to healthcare, research infrastructure, and digital providers in the EU

!!! danger "HIPAA (US Healthcare)"
    **45 CFR §164.312(e)(1)** mandates encryption of protected health information (PHI) in transit.

    - EEG, EMG, and other biosignals collected with patient identifiers = PHI
    - Penalties: $141 per violation up to $2 million annually for willful neglect
    - This applies to clinical research, hospital settings, and any HIPAA-covered entity

!!! danger "GDPR (European Union)"
    **Article 32** requires "appropriate technical measures" including encryption of personal data.

    - Fines: Up to €20 million or 4% of global annual revenue
    - Applies to any research involving EU citizens' data

!!! info "FDA 21 CFR Part 11"
    Electronic records in regulated environments must ensure data integrity and authenticity.

### 2. Multi-Institution Collaborations

Modern neuroscience increasingly involves collaboration across institutions:

When data crosses network boundaries, plain EEG data is visible to ISPs, network administrators, and anyone with access to intermediate routers:

- Network administrators at each institution can see your data
- ISPs can inspect the traffic
- Any compromised router along the path exposes everything

### 3. Protect Your Research

Even in a "closed" lab network:

- **Shared WiFi**: Other researchers, visitors, or students on the same network can sniff traffic
- **Compromised devices**: A malware-infected laptop can capture all network traffic
- **Data integrity**: Without authentication, how do you know your recorded data wasn't modified?

### 4. Clinical Applications

Brain-computer interfaces (BCIs) and neurofeedback are moving toward clinical deployment:

- Patient neural data requires protection
- Real-time control systems must verify data authenticity
- Regulatory approval requires documented security measures

---

## The LSL Security Gap in Numbers

| What's Exposed | Impact |
|---------------|--------|
| Stream names | Reveals what you're studying |
| Channel counts | Shows experimental complexity |
| Sampling rates | Technical details of your setup |
| **Actual biosignal values** | Your research data, patient recordings |

Anyone on your network with Wireshark can see all of this in seconds.

---

## Common Objections (and Responses)

### "My lab network is isolated"

!!! question "Is it really?"
    - Does your EEG computer connect to the internet for updates?
    - Does anyone use WiFi in your lab?
    - Do you share network infrastructure with other labs?
    - Do you ever work from a laptop that connects to other networks?

### "We use a VPN for sensitive work"

!!! question "VPNs have limitations"
    - VPNs protect traffic between sites, not within your lab network
    - VPNs don't provide device authentication; anyone with VPN credentials connects
    - VPN setup is often outside researchers' control
    - Secure LSL provides end-to-end protection regardless of network path

### "Our IT department handles security"

!!! question "But do they protect your biosignal streams?"
    - Network-level security (firewalls, VLANs) is important but insufficient
    - Application-layer encryption is needed for end-to-end protection
    - Secure LSL adds the specific protection biosignal streams need

### "Performance will suffer"

!!! success "Actually, no"
    We measured overhead across platforms (64ch @ 1000Hz):

    | Platform | Overhead |
    |----------|----------|
    | Mac Mini M4 Pro (local) | ~1% CPU |
    | Raspberry Pi 5 (local) | ~1% CPU |
    | Cross-machine (Ethernet) | 1.06% latency |

    Sub-millisecond added latency. Zero packet loss attributable to encryption.

### "It's too complicated"

!!! success "It's not"
    ```bash
    # Generate and export keys on your primary device
    ./lsl-keygen --export lab_shared

    # Import on ALL devices (including the primary)
    ./lsl-keygen --import lab_shared.key.enc

    # Dynamically linked apps work without code changes.
    ```

---

## The Unified Security Model

We designed Secure LSL with a "secure by default with unanimous opt-out" model:

In your lab network (EEG amplifier, eye tracker, LabRecorder, analysis workstation), all devices must agree on security:

- **All have keys**: Encrypted communication
- **All insecure**: Plain communication (legacy mode)
- **Mixed**: Rejected with a clear error message

**Why this design?**

1. **No accidental gaps**: You can't accidentally leave one stream unprotected
2. **Clear status**: Either everything is encrypted, or you get a clear error
3. **Migration pressure**: Adding one secure device encourages updating all devices
4. **Simple auditing**: "Is security enabled?" is a yes/no answer, not a per-stream matrix

---

## What Secure LSL Protects Against

| Threat | Protection |
|--------|------------|
| **Eavesdropping** | ChaCha20-Poly1305 encryption makes data unreadable |
| **Data tampering** | Authenticated encryption detects any modification |
| **Replay attacks** | Nonce tracking rejects duplicate packets |
| **Unauthorized access** | Ed25519 authentication verifies device identity |
| **Man-in-the-middle** | Key exchange prevents interception |
| **Future key compromise** | Session key rotation provides forward secrecy |

---

## What Secure LSL Does NOT Protect

Being clear about scope:

| Not Protected | Why | Solution |
|--------------|-----|----------|
| Data at rest (XDF files) | Out of scope | File/disk encryption |
| Denial of service | Network infrastructure issue | Firewalls, network security |
| Compromised endpoints | OS security issue | Endpoint protection |
| Metadata (stream names) | Required for discovery | Acceptable trade-off |

---

## Getting Started

Ready to secure your lab?

[Quick Start Guide →](../getting-started/quickstart.md){ .md-button .md-button--primary }

Or learn more about [how the encryption works →](how-it-works.md)
