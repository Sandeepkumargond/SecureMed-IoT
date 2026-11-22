# SecureMed-IoT: Lightweight Cryptography for IoT Healthcare
### PRESENT-80 Block Cipher on Arduino Uno & ESP32

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Arduino%20%7C%20ESP32-blue)]()
[![Cipher](https://img.shields.io/badge/cipher-PRESENT--80-green)]()
[![ISO](https://img.shields.io/badge/standard-ISO%2FIEC%2029192--2-lightgrey)]()

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Quick Start](#quick-start)
3. [Hardware Setup](#hardware-setup)
4. [Software Installation](#software-installation)
5. [Usage](#usage)
6. [Test Vector Verification](#test-vector-verification)
7. [Benchmark Results](#benchmark-results)
8. [Security Notes](#security-notes)
9. [File Structure](#file-structure)
10. [License](#license)

---

## Project Overview

This project implements the **PRESENT-80** lightweight block cipher (ISO/IEC 29192-2) to encrypt biomedical sensor data (ECG, heart rate) on resource-constrained microcontrollers before wireless transmission.

### Why PRESENT-80?

| Property | Value |
|----------|-------|
| Block size | 64 bits |
| Key size | 80 bits |
| Rounds | 31 |
| Flash footprint (C, AVR -Os) | ~1,600 bytes |
| SRAM footprint | ~324 bytes |
| Encryption time (ATmega328P @ 16 MHz) | ~62 µs |
| Standard | ISO/IEC 29192-2:2012 |

AES-128 on the same hardware requires ~8,000 µs without a hardware accelerator — **130× slower** than PRESENT-80. For duty-cycled IoT sensor nodes, this translates directly to battery life.

### System at a Glance

```
 ┌─────────────────┐    Serial    ┌──────────────────┐    MQTT    ┌─────────────┐
 │  Arduino Uno    │ ──────────► │    ESP32 Wi-Fi   │ ─────────► │   Broker /  │
 │  ECG + HR       │             │    Gateway        │            │  Python     │
 │  PRESENT-80 enc │             │  PRESENT-80 enc  │            │  Analytics  │
 └─────────────────┘             └──────────────────┘            └─────────────┘
```

---

## Quick Start

```bash
# 1. Clone / navigate to project
cd /home/sandy/Desktop/crypto

# 2. Install Python dependencies
pip install -r python/requirements.txt

# 3. Run official test vectors
python -m unittest tests/test_present_vectors.py -v

# 4. Run the Python PRESENT demo
python python/present.py

# 5. Upload Arduino sketch (requires Arduino CLI)
arduino-cli compile --fqbn arduino:avr:uno arduino/
arduino-cli upload  --fqbn arduino:avr:uno -p /dev/ttyUSB0 arduino/

# 6. Listen to encrypted output
python python/decrypt_serial.py --port /dev/ttyUSB0 --baud 115200

# 7. Launch Interactive Web Demo UI
cd ui && python3 app.py
# Open http://localhost:5050 in your browser
```

---

## Hardware Setup

### Bill of Materials

| Component | Qty | Purpose |
|-----------|-----|---------|
| Arduino Uno (ATmega328P) | 1 | Edge encryption node |
| ESP32 DevKit v1 | 1 | Wi-Fi MQTT gateway |
| AD8232 ECG Module | 1 | ECG signal acquisition |
| MAX30102 Pulse Oximeter | 1 | Heart rate / SpO₂ |
| DS3231 RTC Module | 1 | Accurate timestamps |
| Breadboard + jumper wires | 1 set | Prototyping |
| USB-A to USB-B cable | 1 | Arduino programming |
| Micro-USB cable | 1 | ESP32 programming |

---

### Arduino Uno Wiring Diagram

```
                        ARDUINO UNO
                    ┌───────────────────┐
                    │                   │
  AD8232 ECG:       │ A0 ◄── OUTPUT    │
   OUTPUT ──────────┤                   │
   LO+    ──────────┤ D10              │
   LO-    ──────────┤ D11              │
   3.3V   ──────────┤ 3.3V            │
   GND    ──────────┤ GND             │
                    │                   │
  DS3231 RTC:       │ A4 (SDA) ◄─────  │◄── DS3231 SDA
   SDA    ──────────┤ A5 (SCL) ◄─────  │◄── DS3231 SCL
   SCL    ──────────┤ 5V              │◄── DS3231 VCC
   VCC    ──────────┤ GND             │◄── DS3231 GND
                    │                   │
  Serial to ESP32:  │ TX (D1) ───────► │──► ESP32 RX2 (GPIO16)
                    │ RX (D0) ◄─────── │◄── ESP32 TX2 (GPIO17)
                    │                   │
                    └───────────────────┘
```

### ESP32 Wiring Diagram

```
                        ESP32 DEVKIT V1
                    ┌───────────────────┐
                    │                   │
  From Arduino:     │ GPIO16 (RX2) ◄── │◄── Arduino TX (D1)
                    │ GPIO17 (TX2) ───► │──► Arduino RX (D0)
                    │                   │
  Wi-Fi (built-in): │ [Internal antenna]│
                    │                   │
  USB (programming):│ Micro-USB         │
                    │                   │
                    └───────────────────┘
```

> **Note**: Use a 3.3V logic-level shifter if connecting 5V Arduino TX directly to ESP32 RX to avoid damaging the ESP32. Alternatively, use a 1kΩ resistor voltage divider.

---

## Software Installation

### Python Environment

```bash
cd /home/sandy/Desktop/crypto/python

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate      # Linux/macOS
# venv\Scripts\activate.bat   # Windows

# Install dependencies
pip install -r requirements.txt
```

**requirements.txt** includes:
- `pyserial` — Serial port communication with Arduino
- `paho-mqtt` — MQTT client for ESP32 messages
- `matplotlib` — Benchmark visualization
- `numpy` — Signal processing for ECG data
- `scipy` — Statistical analysis

### Arduino IDE Setup

1. Download [Arduino IDE 2.x](https://www.arduino.cc/en/software)
2. Install **ESP32 board support**:
   - Preferences → Additional board manager URLs:
     ```
     https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
     ```
   - Board Manager → Search "esp32" → Install
3. No additional libraries required (all code is self-contained)

### Arduino CLI (Alternative)

```bash
# Install Arduino CLI
curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh

# Install AVR and ESP32 cores
arduino-cli core install arduino:avr
arduino-cli core install esp32:esp32
```

---

## Usage

### 1. Upload Arduino Firmware

```bash
# Compile and upload sensor_encrypt.ino
arduino-cli compile \
  --fqbn arduino:avr:uno \
  --libraries arduino/ \
  arduino/sensor_encrypt.ino

arduino-cli upload \
  --fqbn arduino:avr:uno \
  -p /dev/ttyUSB0 \
  arduino/sensor_encrypt.ino
```

**Expected Serial output** (115200 baud):
```
=== PRESENT-80 Healthcare Encryption Node ===
Key loaded from EEPROM: 0123456789ABCDEF0123
--- Sensor Reading #1 ---
ECG raw: 512  HR: 72 bpm  Timestamp: 1234
Packed block: 02000048004AD2
Encrypted:    A3F812C47E9B2D56
Enc time: 63 us  Free SRAM: 1468 bytes
```

### 2. Upload ESP32 Gateway Firmware

```bash
# Edit esp32/esp32_present.ino to set your Wi-Fi credentials:
#   const char* ssid = "YOUR_SSID";
#   const char* password = "YOUR_PASSWORD";
#   const char* mqtt_server = "192.168.1.100";

arduino-cli compile \
  --fqbn esp32:esp32:esp32 \
  esp32/esp32_present.ino

arduino-cli upload \
  --fqbn esp32:esp32:esp32 \
  -p /dev/ttyUSB1 \
  esp32/esp32_present.ino
```

### 3. Run Python Decryption Host (Serial, MQTT, or File)

```bash
# Monitor and decrypt serial output from Arduino/ESP32:
python python/decrypt_host.py \
  --serial /dev/ttyUSB0 \
  --baud 115200 \
  --key 0123456789ABCDEF0123

# Or subscribe to ESP32 MQTT stream and decrypt in real time:
python python/decrypt_host.py \
  --mqtt 192.168.1.100 \
  --key 0123456789ABCDEF0123

# Or decrypt from recorded telemetry file:
python python/decrypt_host.py \
  --file telemetry.txt \
  --key 0123456789ABCDEF0123
```

### 5. Run Benchmark Suite

```bash
# Python benchmark
python python/benchmark.py

# Arduino benchmark: upload benchmark.ino and open Serial Monitor
arduino-cli upload --fqbn arduino:avr:uno arduino/benchmark.ino

# Generate benchmark plots
python python/visualize.py --input benchmark_results.json
```

### 6. Run Security Attack Simulations

```bash
# Full security analysis simulation
python python/attack_simulation.py

# Output: attack_report.json + console report
```

---

## Test Vector Verification

Official PRESENT-80 test vectors from the original paper (Bogdanov et al., CHES 2007, Appendix I):

| # | Plaintext (hex) | Key (hex) | Expected Ciphertext (hex) |
|---|----------------|-----------|--------------------------|
| 1 | `0000000000000000` | `00000000000000000000` | `5579C1387B228445` |
| 2 | `0000000000000000` | `FFFFFFFFFFFFFFFFFFFF` | `E72C46C0F5945049` |
| 3 | `FFFFFFFFFFFFFFFF` | `00000000000000000000` | `A112FFC72F68417B` |
| 4 | `FFFFFFFFFFFFFFFF` | `FFFFFFFFFFFFFFFFFFFF` | `3333DCD3213210D2` |

### Run Tests

```bash
# Run all unit tests (verbose)
python -m unittest tests/test_present_vectors.py -v

# Expected output:
# test_avalanche ... ok
# test_avalanche_multiple_plaintexts ... ok
# test_ciphertext_is_64bit ... ok
# test_decrypt_vector_1 ... ok
# test_decrypt_vector_2 ... ok
# test_decrypt_vector_3 ... ok
# test_different_plaintexts_same_key_different_ct ... ok
# test_encrypt_decrypt_all_ones ... ok
# test_encrypt_decrypt_all_zeros ... ok
# test_key_sensitivity ... ok
# test_key_sensitivity_zero_plaintext ... ok
# test_known_vector_1 ... ok
# test_known_vector_2 ... ok
# test_known_vector_3 ... ok
# test_plaintext_is_64bit_after_decrypt ... ok
# test_roundtrip ... ok
# ----------------------------------------------------------------------
# Ran 16 tests in 0.XXXs
# OK
```

### Quick CLI Verification

```bash
python3 -c "
import sys; sys.path.insert(0, 'python')
from present import present_encrypt
key = bytes.fromhex('00000000000000000000')
ct  = present_encrypt(0, key)
expected = 0x5579C1387B228445
print(f'Vector 1: {\"PASS\" if ct == expected else \"FAIL\"}  CT=0x{ct:016X}')
"
```

---

## Benchmark Results

Measured on physical hardware (see `docs/benchmarks.md` for full methodology):

| Platform | Enc Time (µs) | Throughput (B/s) | SRAM Used (B) | Energy/Enc (µJ) |
|----------|:-------------:|:----------------:|:-------------:|:----------------:|
| ATmega328P @ 16 MHz | **~62** | **~129,000** | **~324** | **~3.35** |
| ESP32 @ 240 MHz | **~5.2** | **~1,538,000** | **~372** | **~4.12** |
| Python (x86-64) | **~12** | **~667,000** | N/A | N/A |

**vs AES-128 on ATmega328P (software)**: PRESENT-80 is ~130× faster with ~25% of the flash footprint.

---

## Security Notes

> ⚠️ **PRESENT-80 provides 80-bit security**, which is below NIST's current 112-bit recommendation (SP 800-131A Rev 2). It is suitable for data with a short confidentiality lifetime in low-threat environments.

### What is protected
- ✅ Sensor data confidentiality over MQTT (ciphertext-only security)
- ✅ Message authentication via HMAC-SHA256 (Python layer)
- ✅ Replay protection via timestamp in encrypted block

### Known limitations
- ⚠️ No hardware side-channel countermeasures on Arduino (SPA/DPA possible with physical access)
- ⚠️ Hardcoded key in firmware (use EEPROM + key provisioning in production)
- ⚠️ No TLS on MQTT (add TLS for WAN deployments)
- ⚠️ Not FIPS 140-2 certified (use AES for regulated healthcare deployments)

See [`docs/security_analysis.md`](docs/security_analysis.md) for a detailed threat model and countermeasures.

---

## File Structure

```
crypto/
├── README.md                        ← This file
│
├── arduino/                         ← Arduino Uno firmware
│   ├── present_cipher.h             ← PRESENT-80 header (sBox, pLayer, structs)
│   ├── present_cipher.c             ← PRESENT-80 C implementation
│   ├── sensor_encrypt.ino           ← ECG/HR encryption main sketch
│   └── benchmark.ino                ← Standalone benchmark sketch
│
├── esp32/                           ← ESP32 gateway firmware
│   ├── esp32_present.ino            ← ESP32 Wi-Fi + MQTT + encryption sketch
│   ├── present_esp32.h              ← PRESENT-80 header for ESP32
│   ├── present_esp32.cpp            ← PRESENT-80 C++ implementation
│   └── energy_monitor.ino           ← Energy measurement sketch
│
├── python/                          ← Python reference & tools
│   ├── present.py                   ← Reference PRESENT-80 implementation
│   ├── benchmark.py                 ← Benchmarking tool
│   ├── visualize.py                 ← Plot benchmark results
│   ├── attack_simulation.py         ← Brute-force & side-channel demos
│   ├── data_integrity.py            ← CRC-16 + HMAC-SHA256 module
│   ├── decrypt_serial.py            ← Live Arduino serial decryptor
│   ├── mqtt_subscriber.py           ← MQTT stream decryptor
│   └── requirements.txt             ← Python dependencies
│
├── docs/                            ← Documentation
│   ├── architecture.md              ← System architecture + data flow
│   ├── benchmarks.md                ← Benchmark results + methodology
│   └── security_analysis.md        ← Cryptanalysis + threat model
│
└── tests/                           ← Test suite
    └── test_present_vectors.py      ← Official test vectors + properties
```

---

## References

1. Bogdanov, A. et al. (2007). *PRESENT: An Ultra-Lightweight Block Cipher*. CHES 2007, LNCS 4727.
2. ISO/IEC 29192-2:2012. *Information technology — Lightweight cryptography — Part 2: Block ciphers*.
3. NIST SP 800-131A Rev. 2 (2019). *Transitioning the Use of Cryptographic Algorithms and Key Lengths*.
4. Rolfes, C. et al. (2008). *Ultra-Lightweight Implementations for Smart Devices*. CARDIS 2008.

---

## License

```
MIT License

Copyright (c) 2026 Lightweight Cryptography IoT Healthcare Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
