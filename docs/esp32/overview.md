# ESP32 Support

Secure LSL includes a protocol-compatible implementation for ESP32 microcontrollers, enabling WiFi-connected embedded devices to participate in encrypted LSL lab networks.

## Overview

**liblsl-ESP32** is a clean-room C reimplementation of the LSL wire protocol for ESP32, with full secureLSL encryption support. It is not a port of desktop liblsl; it reimplements the protocol from scratch using ESP-IDF native APIs.

### Scope

liblsl-ESP32 provides the **communication layer** for streaming data over WiFi using the LSL protocol. While the ESP32 includes built-in ADC peripherals, this implementation focuses on the networking and protocol stack rather than signal acquisition. For biosignal applications (EEG, EMG, ECG), the ESP32 typically serves as a wireless bridge: a dedicated ADC IC (e.g., ADS1299, ADS1294) handles acquisition with the precision, noise floor, and simultaneous sampling required for research-grade recordings, while the ESP32 handles WiFi, LSL protocol, and encryption. This separation follows established practice in wireless biosignal systems.

The current implementation uses 802.11 WiFi, but the protocol and encryption layers are transport-agnostic (standard BSD sockets). Developers can substitute alternative low-latency transports including Ethernet (SPI PHY), Bluetooth, or ESP-NOW, reusing the LSL protocol and secureLSL encryption modules. Note that LSL is designed for low-latency local network environments; high-latency transports are not suitable.

### Why a Reimplementation?

Desktop liblsl is ~50,000+ lines of C++ coupled to Boost, pugixml, and C++ features (exceptions, RTTI) that are impractical on a device with 520KB SRAM. The LSL wire protocol is simple (UDP discovery, TCP streamfeed, binary samples), making a clean C reimplementation (~4,100 lines) both smaller and more maintainable.

### Features

- **Full LSL protocol**: UDP multicast discovery + TCP data streaming (v1.10)
- **Bidirectional**: both outlet (push) and inlet (pull)
- **secureLSL encryption**: ChaCha20-Poly1305, Ed25519 key exchange, wire-compatible with desktop
- **Desktop interop**: verified with pylsl, LabRecorder, and desktop secureLSL
- **Real-time**: sustains up to 1000 Hz with near-zero packet loss
- **Lightweight**: ~200KB SRAM footprint, 300KB+ free for application

### Hardware Requirements

| Requirement | Minimum | Tested |
|------------|---------|--------|
| MCU | ESP32 (Xtensa LX6) | ESP32-WROOM-32 |
| SRAM | 520KB | ESP32-DevKitC v4 |
| Flash | 2MB+ | 4MB |
| WiFi | 802.11 b/g/n | 2.4GHz |

## Quick Start

### Prerequisites

- [ESP-IDF v5.5+](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/)
- ESP32 development board
- WiFi network shared with desktop

### 1. Flash the secure outlet example

```bash
cd liblsl-ESP32/examples/secure_outlet
idf.py menuconfig
# Set WiFi credentials and secureLSL keypair
idf.py build
idf.py -p /dev/cu.usbserial-XXXX flash monitor
```

### 2. Receive on desktop with secureLSL

```bash
# Build secureLSL with security enabled
cd liblsl/build
cmake .. -DLSL_SECURITY=ON && cmake --build . --parallel

# Receive encrypted stream
./cpp_secure_inlet --stream ESP32Secure --samples 100
```

### 3. Or use the unencrypted outlet

```bash
cd liblsl-ESP32/examples/basic_outlet
idf.py menuconfig   # Set WiFi
idf.py build && idf.py -p PORT flash monitor
```

```python
import pylsl
streams = pylsl.resolve_byprop('name', 'ESP32Test', timeout=10)
inlet = pylsl.StreamInlet(streams[0])
sample, ts = inlet.pull_sample()
```

## Security Setup

The ESP32 uses the same Ed25519 shared keypair model as desktop secureLSL.

### Key Provisioning

```c
#include "lsl_esp32.h"
#include "nvs_flash.h"

nvs_flash_init();

// Option A: Generate new keypair on ESP32
lsl_esp32_generate_keypair();

// Option B: Import desktop keypair
lsl_esp32_import_keypair("BASE64_PUBLIC_KEY", "BASE64_PRIVATE_KEY");

// Enable encryption for all subsequent outlets/inlets
lsl_esp32_enable_security();
```

The desktop must have the matching keypair in `~/.lsl_api/lsl_api.cfg`:

```ini
[security]
enabled = true
private_key = YOUR_BASE64_PRIVATE_KEY
```

### Extracting Keys from Desktop Config

```python
import base64
sk = base64.b64decode("YOUR_PRIVATE_KEY_BASE64")
pk_b64 = base64.b64encode(sk[32:]).decode()  # Public key is last 32 bytes
print(f"Public key: {pk_b64}")
```

## API Overview

```c
// Stream info
lsl_esp32_stream_info_t info = lsl_esp32_create_streaminfo(
    "MyStream", "EEG", 8, 250.0, LSL_ESP32_FMT_FLOAT32, "source_id");

// Outlet (push)
lsl_esp32_outlet_t outlet = lsl_esp32_create_outlet(info, 0, 360);
lsl_esp32_push_sample_f(outlet, data, 0.0);

// Inlet (pull)
lsl_esp32_stream_info_t found;
lsl_esp32_resolve_stream("name", "DesktopStream", 10.0, &found);
lsl_esp32_inlet_t inlet = lsl_esp32_create_inlet(found);
lsl_esp32_inlet_pull_sample_f(inlet, buf, buf_len, &timestamp, 5.0);

// Security
lsl_esp32_generate_keypair();
lsl_esp32_enable_security();
```

Full API: [`liblsl-ESP32/components/liblsl_esp32/include/lsl_esp32.h`](../../liblsl-ESP32/components/liblsl_esp32/include/lsl_esp32.h)

## Performance

Benchmarked on ESP32-DevKitC v4 over WiFi (802.11n, RSSI -36 dBm):

| Config | Rate | Packet Loss | Encryption Overhead |
|--------|------|-------------|-------------------|
| 8ch float32 | 250 Hz | 0% | Not measurable (async) |
| 8ch float32 | 500 Hz | 0% | Not measurable (async) |
| 8ch float32 | 1000 Hz | 0.02% | Not measurable (async) |
| 64ch float32 | 250 Hz | 0% | Not measurable (async) |

Encryption runs asynchronously on core 1 in the TCP feed task, while the application pushes to a lock-free ring buffer on core 0. The 2KB heap overhead for security sessions is the only measurable cost.

## Protocol Compatibility

| Feature | Desktop liblsl | liblsl-ESP32 |
|---------|---------------|-------------|
| Protocol version | 1.00 + 1.10 | 1.10 only |
| IP version | IPv4 + IPv6 | IPv4 only |
| Channel formats | All | float32, double64, int32, int16, int8 |
| secureLSL encryption | Yes | Yes (wire-compatible) |
| Max connections | Unlimited | 3 concurrent |
| Max channels | Unlimited | 128 |

## Examples

| Example | Description |
|---------|-------------|
| `basic_outlet` | Unencrypted 8-channel sine wave outlet |
| `basic_inlet` | Unencrypted stream receiver |
| `secure_outlet` | Encrypted outlet with key provisioning |
| `secure_inlet` | Encrypted receiver |

## Documentation

For detailed documentation, see:

- [Architecture](../../liblsl-ESP32/docs/architecture.md) -- protocol layers, threading, memory
- [Security Guide](../../liblsl-ESP32/docs/security.md) -- key provisioning, setup, troubleshooting
- [Benchmarks](../../liblsl-ESP32/docs/benchmarks.md) -- methodology and full results
- [Changelog](../../liblsl-ESP32/CHANGELOG.md) -- version history
