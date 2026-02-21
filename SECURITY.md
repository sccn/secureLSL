# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.0-alpha (current) | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in Secure LSL, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email: **security@sccn.ucsd.edu**
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 1 week
- **Fix timeline** communicated after assessment
- **Credit** in the release notes (unless you prefer anonymity)

### Scope

The following are in scope for security reports:

- Cryptographic implementation flaws (key exchange, encryption, authentication)
- Key material exposure (private keys leaked in logs, errors, or network traffic)
- Authentication bypass (connecting without valid credentials)
- Data integrity failures (undetected tampering)
- Configuration vulnerabilities (insecure defaults, permission issues)

The following are out of scope:

- Denial of service (network-level; not a goal of this project)
- Attacks requiring physical access to the device
- Issues in upstream dependencies (report to libsodium, liblsl directly)
- Social engineering

## Security Design

Secure LSL uses:

- **Ed25519** for device identity and signatures
- **X25519 + BLAKE2b** for session key derivation
- **ChaCha20-Poly1305** for authenticated encryption
- **libsodium** for all cryptographic operations

For technical details, see [How Encryption Works](docs/security/how-it-works.md).
