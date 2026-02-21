# How Secure LSL Works

A neuroscientist-friendly explanation of the encryption, without requiring a cryptography PhD.

---

## The Big Picture

When you stream EEG data across your lab network, that data normally travels as plain numbers that anyone on the network can read. Secure LSL wraps that data in encryption so that only the intended recipient can read it.

**Without Secure LSL:** EEG Amplifier sends plain data over the network; anyone can read it.

**With Secure LSL:** EEG Amplifier encrypts data before sending. On the network it looks like random noise. LabRecorder decrypts it back to the original data.

---

## Two Layers of Protection

Secure LSL provides two complementary protections:

### 1. Device Authentication (Who are you?)

Before any data flows, devices prove their authorization using **digital signatures**. All authorized devices in your lab share the same Ed25519 keypair, distributed through a secure export/import process:

- **Private key**: Shared only among authorized lab devices (kept secret from outsiders)
- **Public key**: Used to verify that a connecting device holds the same keypair

When your EEG amplifier connects to LabRecorder, both sides verify they hold the same keypair by comparing public keys. This prevents:

- Unauthorized devices from connecting
- Attackers from impersonating your equipment
- "Man-in-the-middle" attacks where someone intercepts your connection

!!! note "Analogy: Lab Access Cards"
    Think of this like a lab access card system. All authorized lab members have a card with the same access code. When you badge in, the system verifies your card matches. Anyone without a valid card is denied entry.

### 2. Data Encryption (Keep it secret)

Once devices are authenticated, all data is encrypted using a **session key** that only those two devices know. This means:

- Eavesdroppers see only random-looking bytes
- Even if someone captures your network traffic, they can't read your biosignals
- Each connection uses a different key, so compromising one doesn't affect others

---

## The Cryptographic Algorithms

We use algorithms trusted by banks, governments, and security experts worldwide:

### Ed25519 for Identity

**Ed25519** is a digital signature algorithm that:

- Creates compact 32-byte public keys (fits in a single network packet)
- Verifies signatures in microseconds (no delay for real-time systems)
- Is resistant to known attacks, including some quantum computing threats
- Is used by OpenSSH, Signal, and countless security-critical systems

### ChaCha20-Poly1305 for Encryption

**ChaCha20-Poly1305** is an authenticated encryption algorithm that:

- Encrypts data so only the key holder can read it (ChaCha20)
- Detects any tampering with the encrypted data (Poly1305)
- Runs 3-4x faster than AES on devices without hardware acceleration (like Raspberry Pi)
- Uses less power on mobile and embedded devices
- Is used by Google, Cloudflare, and most modern TLS connections

!!! info "Why not AES?"
    AES-GCM is excellent when hardware acceleration is available (AES-NI on Intel chips). But many biosignal devices use ARM processors without this acceleration. ChaCha20 provides equivalent security with better performance across all platforms.

---

## Authenticated Encryption: Why It Matters

Traditional encryption only hides data. An attacker could still modify the encrypted bytes, potentially causing unpredictable results when decrypted.

**Authenticated encryption** solves this by adding an **authentication tag** to each packet. This tag is like a tamper-evident seal. When decrypting:

1. First, verify the authentication tag
2. If verification fails, **reject the packet entirely** (tampered or corrupted)
3. If verification passes, decrypt and use the data

This means:

- **Bit flips detected**: Even changing a single bit is caught
- **Truncation detected**: Shortened packets are rejected
- **Injection detected**: Added bytes are rejected
- **No silent corruption**: You never get garbage data disguised as real samples

!!! success "Validation Result"
    In testing, we modified 10,000 packets in various ways (single-bit flips, multi-byte changes, truncation). **100% were detected and rejected.**

---

## Replay Attack Prevention

An attacker could capture legitimate encrypted packets and re-transmit them later. While they can't read or modify the data, replaying old packets could corrupt your recording with duplicate samples or confuse real-time processing systems.

Secure LSL prevents this using **nonces** (numbers used once). Each packet includes a monotonically increasing nonce. The inlet tracks seen nonces and rejects any that aren't newer than the last. This provides:

- **Replay detection**: Old packets are caught
- **Out-of-order tolerance**: A sliding window allows minor reordering
- **Practically unlimited**: The nonce space supports centuries of continuous operation

---

## Session Keys and Forward Secrecy

Your device's key is long-lived (you generate it once). But what if it's ever compromised?

Secure LSL protects against this with **session keys**:

1. When two devices connect, they perform a **key exchange** to create a shared secret
2. This secret is used to derive a **session key** that encrypts all data
3. Session keys are **rotated periodically**
4. Session keys are never stored; they exist only in memory

This provides **forward secrecy**: even if an attacker eventually obtains your device's private key, they cannot decrypt recordings from past sessions that used different session keys.

---

## The Unanimous Security Model

Secure LSL uses a "secure by default with unanimous opt-out" model:

- **If any device on your network has security enabled**, all connections must be secure
- **Only if all devices explicitly disable security** can they operate insecurely
- **Mixed environments are not allowed**

This design:

- Eliminates partial-security vulnerabilities
- Prevents downgrade attacks
- Simplifies compliance verification
- Creates natural migration pressure toward full security

---

## Performance Impact

Encryption isn't free, but it's very cheap:

| Platform | Configuration | Overhead | Added Latency |
|----------|--------------|----------|---------------|
| Mac Mini M4 Pro (local) | 64ch @ 1000Hz | ~1% CPU | < 0.01ms |
| Raspberry Pi 5 (local) | 64ch @ 1000Hz | ~1% CPU | < 0.02ms |
| Cross-machine, Ethernet | 64ch @ 1000Hz | 1.06% | +0.8ms |
| Cross-machine, WiFi | 64ch @ 1000Hz | 1.09% | +0.9ms |

All measurements showed **zero packet loss** in 48-hour stress tests.

The sub-millisecond latency overhead is negligible for biosignal applications where synchronization requirements are typically in the 1-10ms range.

---

## Summary

| Layer | Algorithm | Protection |
|-------|-----------|------------|
| **Identity** | Ed25519 | Only authorized devices connect |
| **Encryption** | ChaCha20 | Data is unreadable to eavesdroppers |
| **Integrity** | Poly1305 | Tampering is detected immediately |
| **Replay** | Nonce tracking | Old packets can't be re-injected |
| **Future** | Session keys | Past recordings stay safe |

All of this happens transparently inside the LSL library. Dynamically linked applications require no code changes; statically linked C++ applications need recompilation.

---

## Further Reading

- [Security Model](security-model.md) -- Threat model and compliance details
- [Architecture Overview](../architecture/overview.md) -- System architecture
