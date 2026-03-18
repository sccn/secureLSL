# Getting Started on macOS

This guide walks through setting up the liblsl-ESP32 development environment on macOS (Apple Silicon or Intel).

## Prerequisites

- macOS 13+ (Ventura or later recommended)
- [Homebrew](https://brew.sh)
- An ESP32-DevKitC board (v4 tested) connected via USB
- A WiFi network accessible by both the ESP32 and your Mac

## 1. Install System Dependencies

```bash
brew install cmake ninja python3
brew install clang-format cppcheck typos-cli
```

Note: `dfu-util` is only needed for ESP32-S2/S3 boards with native USB. The
ESP32-DevKitC v4 uses UART flashing and does not require it.

Verify installations:

```bash
cmake --version    # 3.16+ required
python3 --version  # 3.9+ required
clang-format --version
cppcheck --version
typos --version
```

## 2. Install ESP-IDF

ESP-IDF (Espressif IoT Development Framework) is the official SDK for ESP32. We use **v5.5.3**.

```bash
mkdir -p ~/esp && cd ~/esp
git clone -b v5.5.3 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32
```

This downloads the Xtensa GCC toolchain, Python dependencies, and build tools. It takes 10-20 minutes depending on your connection.

### Source the environment

You must source the ESP-IDF environment in every new terminal session:

```bash
. ~/esp/esp-idf/export.sh
```

To make this convenient, add an alias to your shell profile (`~/.zshrc`):

```bash
alias get_idf='. ~/esp/esp-idf/export.sh'
```

Then run `get_idf` whenever you start working on this project.

### Verify ESP-IDF

```bash
idf.py --version
```

Should print something like `ESP-IDF v5.5.3`.

## 3. Connect and Identify the ESP32 Board

Plug in your ESP32-DevKitC via USB. Identify the serial port:

```bash
ls /dev/cu.usb*
```

Common results:

| USB-UART Chip | Port Pattern | DevKit Version |
|---|---|---|
| CP2102 | `/dev/cu.usbserial-XXXX` | DevKitC v4 |
| CP2102N | `/dev/cu.usbserial-XXXX` | DevKitC v4 |
| CH340 | `/dev/cu.usbserial-XXXX` | Some clones |
| USB-JTAG | `/dev/cu.usbmodem-XXXX` | ESP32-S3/C3 built-in |

If no `/dev/cu.usb*` devices appear:

1. Try a different USB cable (some are charge-only, no data)
2. Install the CP2102 driver if needed: [Silicon Labs CP210x](https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers)
3. Check System Settings > Privacy & Security for any blocked kernel extensions

### Identify the chip

You can confirm the board model:

```bash
. ~/esp/esp-idf/export.sh
esptool.py --port /dev/cu.usbserial-0001 chip_id
```

Expected output includes `Chip is ESP32-D0WD-V3` or similar (older boards may
show `ESP32-D0WDQ6`).

## 4. Build and Flash the Crypto Benchmark

This verifies your full toolchain: ESP-IDF, build system, flash, and serial monitor.

```bash
. ~/esp/esp-idf/export.sh
cd benchmarks/crypto_bench

# Set target (first time only)
idf.py set-target esp32

# Build
idf.py build

# Flash and monitor (replace port as needed)
idf.py -p /dev/cu.usbserial-0001 flash monitor
```

Press `Ctrl+]` to exit the serial monitor.

If flashing fails:

- Hold the **BOOT** button on the DevKit while flashing starts, then release
- Try a lower baud rate: `idf.py -p /dev/cu.usbserial-0001 -b 115200 flash`
- Ensure no other program (e.g., Arduino IDE serial monitor) is using the port

## 5. Install Desktop LSL (for interop testing)

Install pylsl to test ESP32 outlet/inlet against a desktop LSL peer:

```bash
# Using UV (preferred)
uv pip install pylsl

# Verify
python3 -c "import pylsl; print('pylsl', pylsl.__version__)"
```

Quick test to discover an ESP32 outlet (once one is running):

```bash
python3 -c "import pylsl; print(pylsl.resolve_stream('name', 'ESP32Test', timeout=5))"
```

## 6. Configure Pre-commit Hooks

The repo includes pre-commit hooks that run clang-format, cppcheck, and typos on staged C files:

```bash
cd /path/to/liblsl-ESP32
git config core.hooksPath .githooks
```

Test the hook:

```bash
# Stage a file and commit to see hooks run
git add benchmarks/crypto_bench/main/bench_utils.c
git commit -m "test: verify pre-commit hooks"
# (cancel with Ctrl+C if you don't want to actually commit)
```

## 7. WiFi Configuration

ESP32 projects that use WiFi need SSID and password configured. The
`examples/basic_outlet/` project uses Kconfig for this:

```bash
cd examples/basic_outlet
. ~/esp/esp-idf/export.sh
idf.py menuconfig
```

Navigate to **Example Configuration** and set:

- WiFi SSID
- WiFi Password

These are stored in `sdkconfig` (gitignored) and persist across builds.

Alternatively, edit `sdkconfig` directly:

```
CONFIG_ESP_WIFI_SSID="your_ssid"
CONFIG_ESP_WIFI_PASSWORD="your_password"
```

You can also store credentials in `.env` (gitignored) for reference.

### WiFi Requirements

- **2.4 GHz only**: ESP32 does not support 5 GHz or 6 GHz WiFi
- **WPA2-PSK**: recommended; WPA/WPA2 mixed mode also works
- **Same network**: your desktop and ESP32 must be on the same subnet
  for multicast discovery to work. If your desktop is on Ethernet and
  the ESP32 on WiFi, ensure your router forwards multicast between
  wired and wireless clients (most do, some don't)
- **Channel**: standard 2.4 GHz channels (1-13) at 20 MHz bandwidth
  work best; 40 MHz bandwidth on some channels may not be visible

## 8. Testing LSL Discovery

After flashing the basic_outlet example with WiFi configured:

```bash
cd examples/basic_outlet
idf.py -p /dev/cu.usbserial-0001 flash monitor
```

Wait for "LSL Outlet Ready" in the serial output, then from your desktop:

```bash
python3 -c "import pylsl; r = pylsl.resolve_byprop('name', 'ESP32Test', timeout=5); print(f'Found {len(r)} streams'); [print(f'  {s.name()} {s.type()} {s.channel_count()}ch') for s in r]"
```

Expected output:

```
Found 1 streams
  ESP32Test EEG 8ch
```

### Troubleshooting Discovery

If no streams are found:

1. **Check IP addresses**: both devices must be on the same subnet
   (e.g., both `192.168.0.x`)
2. **Check WiFi band**: ESP32 serial should show "Connected. IP: ..."
3. **Try unicast**: send a UDP packet directly to the ESP32's IP:16571
   to verify the UDP server is running
4. **Router multicast**: some routers block multicast between WiFi
   and Ethernet clients; connect both devices via WiFi if needed

## Quick Reference

| Task | Command |
|---|---|
| Source ESP-IDF | `. ~/esp/esp-idf/export.sh` |
| Build | `idf.py build` |
| Flash + monitor | `idf.py -p /dev/cu.usbserial-0001 flash monitor` |
| Monitor only | `idf.py -p /dev/cu.usbserial-0001 monitor` |
| Exit monitor | `Ctrl+]` |
| Set target | `idf.py set-target esp32` |
| Clean build | `idf.py fullclean` |
| Configure | `idf.py menuconfig` |
| Format code | `clang-format -i file.c` |
| Static analysis | `cppcheck --std=c11 --language=c file.c` |
| Spell check | `typos file.c` |
| Add component | `idf.py add-dependency "espressif/libsodium^1.0.20~4"` |

## Troubleshooting

### "Permission denied" on serial port

```bash
# Check if the port is in use
lsof /dev/cu.usbserial-0001

# On macOS, your user typically has access; if not:
sudo chmod 666 /dev/cu.usbserial-0001
```

### Build fails with "toolchain not found"

You forgot to source the ESP-IDF environment:

```bash
. ~/esp/esp-idf/export.sh
```

### Flash stuck at "Connecting..."

1. Hold the **BOOT** button on the ESP32 board
2. While holding, press and release the **EN** (reset) button
3. Release BOOT after you see "Connecting" progress

### "Fatal error: sodium.h: No such file or directory"

The libsodium component needs to be fetched:

```bash
cd benchmarks/crypto_bench
idf.py build  # automatically fetches managed components
```

### Python/pylsl issues

Use UV for Python package management:

```bash
uv pip install pylsl
```
