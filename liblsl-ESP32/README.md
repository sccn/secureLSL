# liblsl-ESP32

**Lab Streaming Layer protocol for ESP32 microcontrollers, with secureLSL encryption support**

[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v5.5-blue)](https://github.com/espressif/esp-idf)
[![License](https://img.shields.io/badge/license-Secure%20LSL-orange)](LICENSE)

A clean-room C reimplementation of the [Lab Streaming Layer (LSL)](https://github.com/sccn/liblsl) wire protocol for ESP32, enabling WiFi-connected microcontrollers to participate in LSL lab networks with optional end-to-end encryption via [secureLSL](https://github.com/sccn/secureLSL).

## Scope and Intended Use

liblsl-ESP32 provides the **communication layer** for streaming data over WiFi using the LSL protocol. While the ESP32 includes built-in ADC peripherals, this project focuses on the networking and protocol stack rather than signal acquisition.

For biosignal applications (EEG, EMG, ECG), the ESP32 typically serves as a **wireless bridge**: a dedicated ADC integrated circuit (e.g., ADS1299, ADS1294) performs analog-to-digital conversion with the precision, noise floor, and simultaneous sampling required for research-grade recordings, while the ESP32 handles WiFi networking, LSL protocol, and optional encryption. This separation of concerns follows established practice in wireless biosignal systems and allows the communication stack to be reused across different acquisition front-ends.

### Current Transport and Extensibility

The current implementation uses **802.11 WiFi** as the transport layer, leveraging the ESP32's integrated WiFi radio and the lwIP TCP/IP stack. However, the protocol and encryption layers are transport-agnostic by design, operating on standard BSD sockets. Developers can replace the WiFi transport with any network interface that provides TCP/IP connectivity, including:

- **Ethernet**: via SPI-connected PHY (e.g., W5500, LAN8720), providing lower latency and deterministic timing for wired lab environments
- **Bluetooth Classic (SPP)** or **BLE**: for short-range, low-power scenarios where WiFi infrastructure is unavailable
- **ESP-NOW**: Espressif's peer-to-peer protocol for low-latency ESP32-to-ESP32 communication without a WiFi access point
Note that LSL and secureLSL are designed for low-latency local network environments (lab, clinic). High-latency transports (cellular, LoRa, satellite) are not suitable for the real-time streaming guarantees the protocol assumes.

These transport extensions require replacing only the socket/network initialization layer while reusing the existing LSL protocol serialization, stream discovery (adapted per transport), and secureLSL encryption modules.

## Features

- **Full LSL protocol**: UDP multicast discovery + TCP data streaming (protocol v1.10)
- **Bidirectional**: both outlet (push) and inlet (pull) support
- **secureLSL encryption**: ChaCha20-Poly1305 authenticated encryption, Ed25519 key exchange
- **Desktop interop**: verified with pylsl, LabRecorder, and desktop secureLSL
- **Lightweight**: ~4000 lines of C, ~200KB SRAM footprint (300KB+ free for application)
- **Real-time**: sustains up to 1000 Hz sampling with near-zero packet loss
- **ESP-IDF native**: pure C, FreeRTOS tasks, lwIP sockets, NVS key storage

## Why a Reimplementation?

Desktop liblsl is ~50K+ lines of C++ deeply coupled to Boost (Asio, Serialization, threading), pugixml, exceptions, and RTTI. While Espressif provides an [official Boost.Asio port](https://components.espressif.com/components/espressif/asio), desktop liblsl's dependencies extend far beyond Asio alone, and the C++ overhead (exceptions, RTTI, STL containers) is prohibitive on a device with 520KB SRAM.

The LSL wire protocol is straightforward (UDP discovery, TCP streamfeed, binary samples), making a clean C reimplementation both smaller and more maintainable than attempting to port the desktop stack. This approach gives precise control over memory allocation with pre-allocated pools and no hidden heap usage.

## Quick Start

### Prerequisites

- [ESP-IDF v5.5+](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/)
- ESP32 development board (tested on ESP32-DevKitC v4)
- WiFi network accessible to both ESP32 and desktop

### Flash the example outlet

```bash
cd examples/basic_outlet
idf.py menuconfig   # Set WiFi SSID and password
idf.py build
idf.py -p /dev/cu.usbserial-XXXX flash monitor
```

### Receive on desktop

```python
import pylsl
streams = pylsl.resolve_byprop('name', 'ESP32Test', timeout=10)
inlet = pylsl.StreamInlet(streams[0])
sample, timestamp = inlet.pull_sample()
print(f"Received: {sample}")
```

## Encrypted Streaming

Enable secureLSL encryption for all traffic between ESP32 and desktop:

```c
#include "lsl_esp32.h"
#include "nvs_flash.h"

// 0. Initialize NVS (required for key storage)
nvs_flash_init();

// 1. Provision keys (once, stored in NVS)
lsl_esp32_generate_keypair();

// 2. Enable encryption (before creating outlets/inlets)
lsl_esp32_enable_security();

// 3. Create outlet as usual (encryption is automatic)
lsl_esp32_outlet_t outlet = lsl_esp32_create_outlet(info, 0, 360);
lsl_esp32_push_sample_f(outlet, data, 0.0);  // encrypted on the wire
```

The desktop must have the same Ed25519 keypair configured in `lsl_api.cfg`. See [examples/secure_outlet](examples/secure_outlet/) for a complete example.

## Hardware Requirements

| Requirement | Minimum | Tested |
|------------|---------|--------|
| MCU | ESP32 (Xtensa LX6) | ESP32-WROOM-32 |
| SRAM | 520KB (liblsl uses ~200KB) | ESP32-DevKitC v4 |
| Flash | 2MB+ | 4MB |
| WiFi | 802.11 b/g/n | 2.4GHz |

## Performance

Benchmarked on ESP32-DevKitC v4 over WiFi (802.11n):

| Config | Rate | Packet Loss | Push Timing | Heap Free |
|--------|------|-------------|-------------|-----------|
| 8ch float32, unencrypted | 250 Hz | 0% | 53 us | 113 KB |
| 8ch float32, encrypted | 250 Hz | 0% | 33 us | 111 KB |
| 8ch float32, unencrypted | 1000 Hz | 0.02% | 68 us | 115 KB |
| 64ch float32, encrypted | 250 Hz | 0% | 40 us | ~108 KB |

Encryption overhead is invisible to the application: ChaCha20-Poly1305 runs asynchronously on core 1 in the TCP feed task, while the application pushes to a lock-free ring buffer on core 0. See [benchmarks/](benchmarks/) for full results.

## API Overview

```c
// Clock
double lsl_esp32_local_clock(void);

// Stream info
lsl_esp32_stream_info_t lsl_esp32_create_streaminfo(name, type, channels, rate, format, source_id);

// Outlet (push)
lsl_esp32_outlet_t lsl_esp32_create_outlet(info, chunk_size, max_buffered);
lsl_esp32_push_sample_f(outlet, data, timestamp);

// Inlet (pull)
int lsl_esp32_resolve_stream(prop, value, timeout, result);
lsl_esp32_inlet_t lsl_esp32_create_inlet(info);
lsl_esp32_inlet_pull_sample_f(inlet, buf, buf_len, timestamp, timeout);

// Security
lsl_esp32_generate_keypair();
lsl_esp32_import_keypair(base64_pub, base64_priv);
lsl_esp32_enable_security();
```

Full API in [include/lsl_esp32.h](components/liblsl_esp32/include/lsl_esp32.h).

## Examples

| Example | Description |
|---------|-------------|
| [basic_outlet](examples/basic_outlet/) | 8-channel sine wave outlet at 250 Hz |
| [basic_inlet](examples/basic_inlet/) | Stream receiver with auto-discovery |
| [secure_outlet](examples/secure_outlet/) | Encrypted outlet with key provisioning |
| [secure_inlet](examples/secure_inlet/) | Encrypted receiver |

## Repository Structure

```
liblsl-ESP32/
  components/liblsl_esp32/     # Core library (ESP-IDF component)
    include/lsl_esp32.h        # Public API
    src/                       # Implementation (~4000 lines)
  examples/                    # 4 example projects
  benchmarks/                  # Throughput benchmarks + scripts
  docs/                        # Documentation
  .rules/                      # Development standards
```

## Protocol Compatibility

| Feature | Desktop liblsl | liblsl-ESP32 |
|---------|---------------|-------------|
| Protocol version | 1.00 + 1.10 | 1.10 only |
| IP version | IPv4 + IPv6 | IPv4 only |
| Channel formats | All (incl. string, int64) | float32, double64, int32, int16, int8 |
| secureLSL encryption | ChaCha20-Poly1305 | ChaCha20-Poly1305 (wire-compatible) |
| Discovery | UDP multicast | UDP multicast |
| Max connections | Unlimited | 3 concurrent |
| Max channels | Unlimited | 128 |

## Development

```bash
# Source ESP-IDF
. ~/esp/esp-idf/export.sh

# Build any example
cd examples/basic_outlet
idf.py build

# Flash and monitor
idf.py -p /dev/cu.usbserial-XXXX flash monitor

# Add as component dependency
idf.py add-dependency "espressif/libsodium^1.0.20~4"
```

## License

Secure LSL License (UCSD/SCCN). See [LICENSE](LICENSE) for details.

## Acknowledgments

- [Lab Streaming Layer](https://github.com/sccn/liblsl) -- the desktop LSL library this reimplements
- [secureLSL](https://github.com/sccn/secureLSL) -- the encryption layer we're compatible with
- [libsodium](https://doc.libsodium.org/) -- cryptographic primitives
- [ESP-IDF](https://github.com/espressif/esp-idf) -- Espressif IoT Development Framework
