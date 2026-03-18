# Architecture

## Overview

liblsl-ESP32 is a clean-room C reimplementation of the LSL wire protocol for ESP32 microcontrollers. It is not a port of desktop liblsl; it reimplements the protocol from scratch using ESP-IDF native APIs.

## Why Not Port Desktop liblsl?

Desktop liblsl is ~50,000+ lines of C++ with deep dependencies:

| Dependency | Purpose in Desktop liblsl | ESP32 Status |
|-----------|--------------------------|-------------|
| Boost.Asio | Async networking | Available (espressif/asio), but liblsl uses more than just Asio |
| Boost.Serialization | Protocol 1.00 archives | Not available on ESP32 |
| Boost threading | Thread management | Not needed (FreeRTOS) |
| pugixml | XML parsing | Could port, but overkill |
| C++ exceptions/RTTI | Error handling | Available but adds ~100KB binary overhead |
| STL containers | Data structures | Hidden heap allocation, fragmentation risk |

The LSL wire protocol is simple: UDP multicast discovery, TCP streamfeed with test patterns, binary sample format. Reimplementing it in ~4000 lines of C gives us precise memory control and a smaller footprint than porting the C++ stack.

## Protocol Layers

```
Application (lsl_esp32.h)
    |
    +-- Outlet (lsl_outlet.c)
    |     +-- UDP Discovery Server (lsl_udp_server.c)
    |     +-- TCP Data Server (lsl_tcp_server.c)
    |     +-- Ring Buffer (lsl_ring_buffer.c)
    |
    +-- Inlet (lsl_inlet.c)
    |     +-- Stream Resolver (lsl_resolver.c)
    |     +-- TCP Data Client (lsl_tcp_client.c)
    |
    +-- Security (lsl_security.c)
    |     +-- Key Manager (lsl_key_manager.c, NVS)
    |     +-- Encrypted Framing (lsl_tcp_common.c)
    |
    +-- Shared
          +-- Stream Info + XML (lsl_stream_info.c, lsl_xml_parser.c)
          +-- Sample Format (lsl_sample.c)
          +-- Clock (lsl_clock.c)
          +-- TCP Utilities (lsl_tcp_common.c)
```

## Threading Model

All network tasks are pinned to core 1 (application core). Core 0 is reserved for the WiFi/protocol stack.

| Task | Priority | Core | Stack | Purpose |
|------|----------|------|-------|---------|
| UDP server | 5 | 1 | 4KB | Discovery responses |
| TCP accept | 6 | 1 | 4KB | Accept connections |
| TCP feed (x3) | 7 | 1 | 8KB | Per-connection data streaming |
| Inlet receiver | 7 | 1 | 6KB | Sample reception |

By default, `app_main` runs on core 0. All liblsl-esp32 network tasks are pinned to core 1. This means `push_sample_f()` (called from app_main on core 0) writes to the ring buffer, while the TCP feed task (on core 1) reads, optionally encrypts, and sends over WiFi. Push and pull operations are non-blocking ring buffer writes/reads.

## Memory Architecture

**Budget: ~200KB for liblsl-esp32, leaving 300KB+ for the user application.**

| Component | Size | Notes |
|-----------|------|-------|
| Ring buffer | 2.6KB | 64 slots x 41 bytes (8ch float32) |
| TCP feed stack (x3) | 24KB | 8KB per connection |
| UDP server stack | 4KB | |
| Sample buffers | ~2KB | Stack-allocated per-task |
| Security session | ~1.1KB/conn | Session key (56B) + ciphertext buffer (~1KB) |
| Security config | ~100B | Keypair (outlet/inlet struct) |
| libsodium | ~40KB | Flash + minimal RAM |

All hot-path allocations are pre-allocated. No `malloc` during streaming.

## Security Architecture

```
  ESP32 Outlet                    Desktop Inlet
  ============                    =============
  NVS: Ed25519 keypair            lsl_api.cfg: same keypair

  TCP Headers:                    TCP Headers:
  Security-Enabled: true    -->   Parse security headers
  Security-Public-Key: b64  -->   Verify key match

  Key Derivation:                 Key Derivation:
  Ed25519 -> X25519               Ed25519 -> X25519
  DH shared secret                DH shared secret
  BLAKE2b(secret + "lsl-sess"     BLAKE2b(secret + "lsl-sess"
    + pk_smaller + pk_larger)       + pk_smaller + pk_larger)
  = identical session key         = identical session key

  Test Patterns: plaintext  -->   Validate patterns (plaintext)

  Streaming Data:                 Streaming Data:
  [4B len][8B nonce][ct+tag] -->  Decrypt with session key
```

Key protocol details:
- Test patterns are always sent as plaintext (even when security is enabled)
- Encryption starts only for streaming data after test pattern validation
- Nonce starts at 1 (nonce 0 is reserved)
- Shared keypair model: all lab devices share the same Ed25519 keypair
- Unanimous enforcement: both sides must agree on security state

## Wire Format

### UDP Discovery (multicast 239.255.172.215:16571)
```
Query:  "LSL:shortinfo\r\n<query>\r\n<return-port> <query-id>\r\n"
Reply:  "<query-id>\r\n<shortinfo-xml>"
```

### TCP Streamfeed (protocol 1.10)
```
Request:  "LSL:streamfeed/110 <uid>\r\n" + headers + "\r\n"
Response: "LSL/110 200 OK\r\n" + headers + "\r\n"
          2 test-pattern samples (plaintext)
          streaming samples (encrypted if security enabled)
```

### Binary Sample Format
```
[1 byte]  tag: 0x01=deduced timestamp, 0x02=transmitted
[8 bytes] double timestamp (if tag=0x02)
[N bytes] channel data (little-endian)
```

### Encrypted Chunk Format
```
[4 bytes BE] payload length (excludes this field)
[8 bytes LE] nonce (monotonically increasing, starts at 1)
[N bytes]    ciphertext (ChaCha20-Poly1305, includes 16-byte auth tag)
```
