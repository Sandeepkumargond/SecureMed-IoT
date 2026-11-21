# System Architecture: Lightweight Cryptography for IoT Healthcare

## Table of Contents
1. [Overview](#overview)
2. [Hardware Components](#hardware-components)
3. [Software Stack](#software-stack)
4. [Data Flow](#data-flow)
5. [Cipher Specification: PRESENT-80](#cipher-specification-present-80)
6. [Key Management](#key-management)
7. [Security Model](#security-model)
8. [Threat Model](#threat-model)

---

## 1. Overview

This project implements the **PRESENT-80** lightweight block cipher for securing biomedical sensor data in resource-constrained IoT healthcare environments. The system encrypts ECG and heart-rate readings at the sensor node before transmitting over MQTT to a cloud backend.

### Design Goals
| Goal | Target |
|------|--------|
| Cipher | PRESENT-80 (ISO/IEC 29192-2) |
| Block size | 64 bits |
| Key size | 80 bits |
| Rounds | 31 |
| Platform | ATmega328P (Arduino Uno), ESP32 |
| Latency | < 2 ms per encryption on ATmega328P at 16 MHz |
| RAM footprint | < 512 bytes beyond stack |

---

## 2. Hardware Components

### 2.1 Arduino Uno (Edge Node)
| Component | Specification |
|-----------|--------------|
| MCU | ATmega328P, 8-bit AVR |
| Clock | 16 MHz |
| Flash | 32 KB |
| SRAM | 2 KB |
| EEPROM | 1 KB |
| ADC | 10-bit, 6 channels |
| UART | 115200 baud to host |

### 2.2 ESP32 (Gateway Node)
| Component | Specification |
|-----------|--------------|
| MCU | Xtensa LX6, dual-core 32-bit |
| Clock | 240 MHz |
| Flash | 4 MB |
| RAM | 520 KB SRAM |
| Connectivity | Wi-Fi 802.11 b/g/n, BLE 4.2 |
| Power modes | Active ~240 mA, Deep sleep ~10 µA |

### 2.3 Sensors
| Sensor | Signal | Interface |
|--------|--------|-----------|
| AD8232 ECG Module | Analog ECG waveform | Analog pin A0 |
| MAX30102 Pulse Oximeter | Heart rate, SpO₂ | I²C (SDA/SCL) |
| DS3231 RTC | Timestamp | I²C |

### 2.4 Wiring Summary (Arduino Uno)
```
AD8232 ECG Module:
  OUTPUT  --> A0
  LO+     --> D10
  LO-     --> D11
  3.3V    --> 3.3V
  GND     --> GND

DS3231 RTC:
  SDA     --> A4
  SCL     --> A5
  VCC     --> 5V
  GND     --> GND
```

---

## 3. Software Stack

```
┌─────────────────────────────────────────────────┐
│              Python Analytics Backend            │
│   present.py  │  visualize.py  │  attack_sim.py │
├─────────────────────────────────────────────────┤
│                MQTT Broker (Mosquitto)           │
│         Topic: healthcare/encrypted              │
├────────────────────┬────────────────────────────┤
│   ESP32 Gateway    │    Arduino Edge Node        │
│  esp32_present.ino │    sensor_encrypt.ino       │
│  present_esp32.cpp │    present_cipher.c         │
└────────────────────┴────────────────────────────┘
```

### Layer Descriptions
- **Sensor Layer**: Raw ADC samples from ECG and pulse oximeter
- **Cipher Layer**: PRESENT-80 encrypt/decrypt, key schedule
- **Transport Layer**: UART (Arduino→ESP32), MQTT (ESP32→Cloud)
- **Analytics Layer**: Python scripts for visualization, benchmarking, security analysis

---

## 4. Data Flow

### 4.1 Encryption Pipeline

```
 ┌──────────┐    ADC read    ┌──────────────┐
 │  ECG /   │ ─────────────► │  Pack 64-bit │
 │  HR Sensor│               │  data block  │
 └──────────┘                └──────┬───────┘
                                    │
                             ┌──────▼───────┐
                             │  PRESENT-80  │
                             │  Encryption  │
                             │  (31 rounds) │
                             └──────┬───────┘
                                    │
                      ┌─────────────▼─────────────┐
                      │  Transmit via Serial/MQTT  │
                      │  as 16-char hex string     │
                      └─────────────┬─────────────┘
                                    │
                             ┌──────▼───────┐
                             │  Python Host │
                             │  Decrypt &   │
                             │  Visualize   │
                             └──────────────┘
```

### 4.2 64-Bit Data Block Packing

```
Bit 63                              Bit 0
 ┌────────────────┬────────┬────────────┐
 │   ECG (32b)    │ HR(16b)│  TS (16b)  │
 └────────────────┴────────┴────────────┘
   bits[63:32]    [31:16]    [15:0]

ECG  = 32-bit ADC sample (smoothed)
HR   = Heart rate in BPM (0–200)
TS   = Lower 16 bits of millis() timestamp
```

### 4.3 MQTT Message Flow (ESP32)

```
ESP32                       Broker                    Python Client
  │  CONNECT                  │                            │
  │ ─────────────────────────►│                            │
  │  SUBSCRIBE healthcare/ack │                            │
  │ ─────────────────────────►│                            │
  │                           │  SUBSCRIBE healthcare/enc  │
  │                           │◄───────────────────────── │
  │  PUBLISH healthcare/enc   │                            │
  │  {"ct":"A3F...","ts":123} │                            │
  │ ─────────────────────────►│ ─────────────────────────►│
  │                           │  PUBLISH healthcare/ack    │
  │                           │◄───────────────────────── │
  │◄─────────────────────────-│ "ACK:123"                  │
```

---

## 5. Cipher Specification: PRESENT-80

PRESENT is a lightweight block cipher designed by Bogdanov et al. (2007), standardised as ISO/IEC 29192-2:2012.

### 5.1 Parameters
| Parameter | Value |
|-----------|-------|
| Block size | 64 bits |
| Key size | 80 bits (PRESENT-80) |
| Rounds | 31 |
| Structure | Substitution-Permutation Network (SPN) |

### 5.2 S-Box (nibble substitution, 4-bit → 4-bit)

```
Input (hex):   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
Output (hex):  C  5  6  B  9  0  A  D  3  E  F  8  4  7  1  2
```

As a C array:
```c
const uint8_t sBox[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};
```

### 5.3 Inverse S-Box (for decryption)

```
Input (hex):   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
Output (hex):  5  E  F  8  C  1  2  D  B  4  6  3  0  7  9  A
```

```c
const uint8_t sBoxInv[16] = {
    0x5, 0xE, 0xF, 0x8,
    0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3,
    0x0, 0x7, 0x9, 0xA
};
```

### 5.4 pLayer (bit permutation)

The pLayer permutes bit position `i` to position `P(i)`:

```
P(i) = (i × 16) mod 63   for i = 0, 1, ..., 62
P(63) = 63
```

Full pLayer table (index = source bit, value = destination bit):

```
i  →  P(i)       i  →  P(i)       i  →  P(i)       i  →  P(i)
 0 →   0          16 →   1          32 →   2          48 →   3
 1 →  16          17 →  17          33 →  18          49 →  19
 2 →  32          18 →  33          34 →  34          50 →  35
 3 →  48          19 →  49          35 →  50          51 →  51
 4 →   4          20 →   5          36 →   6          52 →   7
 5 →  20          21 →  21          37 →  22          53 →  23
 6 →  36          22 →  37          38 →  38          54 →  39
 7 →  52          23 →  53          39 →  54          55 →  55
 8 →   8          24 →   9          40 →  10          56 →  11
 9 →  24          25 →  25          41 →  26          57 →  27
10 →  40          26 →  41          42 →  42          58 →  43
11 →  56          27 →  57          43 →  58          59 →  59
12 →  12          28 →  13          44 →  14          60 →  15
13 →  28          29 →  29          45 →  30          61 →  31
14 →  44          30 →  45          46 →  46          62 →  47
15 →  60          31 →  61          47 →  62          63 →  63
```

### 5.5 Key Schedule (80-bit key)

The 80-bit key is stored in a key register `K = k79 k78 ... k0`.

Round key `Ki` for round `i` is the 64 leftmost bits: `Ki = k79 k78 ... k16`.

After extracting a round key, the register is updated:
```
1. Rotate left by 61 positions:  K = K <<< 61
2. Apply sBox to top nibble:     K[79:76] = sBox[K[79:76]]
3. XOR bits [19:15] with round counter i (5 bits):
   K[19:15] = K[19:15] XOR round_counter
```

### 5.6 Algorithm Pseudocode

```
function PRESENT_encrypt(plaintext: uint64, key: uint80) → uint64:
    state = plaintext
    generate_round_keys(key, roundKeys[1..32])

    for i = 1 to 31:
        state = state XOR roundKeys[i]          // addRoundKey
        state = apply_sBox_layer(state)          // sBoxLayer
        state = apply_pLayer(state)              // pLayer

    state = state XOR roundKeys[32]              // final key whitening
    return state

function apply_sBox_layer(state: uint64) → uint64:
    result = 0
    for nibble = 0 to 15:
        s = (state >> (nibble * 4)) AND 0xF
        result |= sBox[s] << (nibble * 4)
    return result

function apply_pLayer(state: uint64) → uint64:
    result = 0
    for i = 0 to 63:
        bit = (state >> i) AND 1
        result |= bit << P(i)
    return result
```

```
function PRESENT_decrypt(ciphertext: uint64, key: uint80) → uint64:
    state = ciphertext
    generate_round_keys(key, roundKeys[1..32])

    state = state XOR roundKeys[32]              // undo last whitening

    for i = 31 downto 1:
        state = apply_pLayer_inv(state)          // inverse pLayer
        state = apply_sBox_inv_layer(state)      // inverse sBox
        state = state XOR roundKeys[i]           // undo key addition

    return state
```

---

## 6. Key Management

### 6.1 Key Storage
- **Arduino**: 80-bit key stored in EEPROM (10 bytes at offset 0)
- **ESP32**: 80-bit key stored in NVS (Non-Volatile Storage) namespace `"crypto"`
- Keys are **never transmitted** in plaintext

### 6.2 Key Provisioning
1. During manufacturing, a unique 80-bit key is generated per device using a CSPRNG
2. Key is flashed into EEPROM/NVS via secure USB connection
3. A corresponding key record is stored in the backend key vault (encrypted at rest with AES-256)

### 6.3 Session Key Derivation (Future Work)
```
session_key = HKDF(master_key, device_id || timestamp, length=10)
```

### 6.4 Key Rotation Policy
| Trigger | Action |
|---------|--------|
| 30-day interval | Rotate session key via OTA command |
| Suspected compromise | Immediate revocation + re-provisioning |
| Device reset | Generate new key on-device, re-register |
| > 2^32 encryptions | Mandatory rotation (counter overflow) |

---

## 7. Security Model

### 7.1 Trust Boundaries
```
[Untrusted Zone]          [Trusted Zone]
     Cloud          │      Sensor Node
     Gateway        │      (physical tamper
     Network        │       resistance assumed)
                    │
  MQTT channel ─── ┼ ──► PRESENT-80 encrypted payload
  (TLS optional)   │
```

### 7.2 Security Properties
| Property | Provided By |
|----------|-------------|
| Confidentiality | PRESENT-80 encryption |
| Data integrity | CRC-16 + HMAC-SHA256 (Python layer) |
| Authenticity | HMAC with shared key |
| Replay protection | 16-bit timestamp in block + sequence number |
| Forward secrecy | Manual key rotation (future: ECDH) |

### 7.3 Assumptions
- Physical access to sensor node is restricted (clinical environment)
- Key material is provisioned in a secure manufacturing process
- MQTT broker is on a trusted LAN segment (TLS recommended for WAN)

---

## 8. Threat Model

### 8.1 Attack Surface

```
┌────────────────────────────────────────────────────┐
│                    Attack Surface                  │
├──────────────┬─────────────────────────────────────┤
│ Threat Actor │ Capability                          │
├──────────────┼─────────────────────────────────────┤
│ Passive      │ Sniff MQTT traffic                  │
│ eavesdropper │ Capture encrypted ciphertexts       │
├──────────────┼─────────────────────────────────────┤
│ Active MITM  │ Inject/modify MQTT messages         │
│              │ Replay old ciphertexts              │
├──────────────┼─────────────────────────────────────┤
│ Physical     │ Read EEPROM via JTAG                │
│ attacker     │ Power/timing side-channel analysis  │
├──────────────┼─────────────────────────────────────┤
│ Insider      │ Access to key vault                 │
│ threat       │ Clone device identity               │
└──────────────┴─────────────────────────────────────┘
```

### 8.2 Mitigations

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Ciphertext-only attack | 2^80 brute-force infeasible | ✅ Implemented |
| Known-plaintext attack | PRESENT security margin (31 rounds) | ✅ Implemented |
| Replay attack | Timestamp in plaintext block | ✅ Implemented |
| MQTT sniffing | Payload encrypted before publish | ✅ Implemented |
| MITM injection | HMAC-SHA256 authentication tag | ✅ Implemented |
| Timing side-channel | Constant-time sBox lookup | ⚠️ Partial |
| Power analysis | Masking countermeasure (Python demo) | ⚠️ Demo only |
| EEPROM extraction | EEPROM access lock fuses (manual) | 📋 Recommended |
| Key compromise | 30-day rotation policy | 📋 Recommended |

### 8.3 Out of Scope
- Physical tamper resistance (beyond EEPROM lock fuses)
- Formal verification of the firmware
- Certificate-based mutual authentication (future work with TLS)

---

*Document version: 1.0 | Last updated: 2026-11 | Refer to `security_analysis.md` for detailed cryptanalysis.*
