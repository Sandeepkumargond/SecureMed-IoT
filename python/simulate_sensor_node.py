#!/usr/bin/env python3
"""
simulate_sensor_node.py – Virtual IoT Healthcare Sensor Node
============================================================
Simulates the Arduino Uno / ESP32 sensor acquisition and encryption loop
without requiring physical microcontrollers or biometric electrodes.

Generates realistic synthetic ECG waveform and Heart Rate readings,
packs them into a 64-bit integer according to the project specification:
  Bits [63:32]: ECG raw value (12-bit ADC range, 0-4095)
  Bits [31:16]: Heart Rate (bpm, normal range 60-100)
  Bits [15:0] : Timestamp (ms counter & 0xFFFF)

Encrypts each block using PRESENT-80 (ISO/IEC 29192-2) with key:
  0x0123456789ABCDEF0123

Usage:
  python3 python/simulate_sensor_node.py --count 10 --out /tmp/sensor_stream.txt
  python3 python/simulate_sensor_node.py --count 10 --tamper --out /tmp/sensor_stream.txt
"""

import argparse
import math
import sys
import time
from pathlib import Path

# Add python dir to path
sys.path.insert(0, str(Path(__file__).parent))
from present import PRESENT

DEFAULT_KEY_HEX = "0123456789ABCDEF0123"

def generate_telemetry_blocks(count=10, tamper_at=-1):
    key = bytes.fromhex(DEFAULT_KEY_HEX)
    cipher = PRESENT(key)

    blocks = []
    print(f"[*] Simulating {count} sensor readings from Virtual IoT Node...")
    print(f"[*] PRESENT-80 Master Key: 0x{DEFAULT_KEY_HEX}\n")
    print(f"{'Packet':<8} {'Time(ms)':<10} {'Sim ECG':<10} {'Sim HR':<8} {'Plaintext (64-bit)':<20} {'Ciphertext (PRESENT-80)':<24}")
    print("-" * 84)

    for i in range(count):
        t_ms = (i + 1) * 200  # 200 ms interval
        ts_field = t_ms & 0xFFFF
        
        # Synthetic cardiac waveform with simulated QRS peak
        phase = (i % 5) / 5.0
        if phase == 0.4:
            ecg_val = 3200  # R-peak spike
        elif phase == 0.2:
            ecg_val = 1600  # Q-wave dip
        else:
            ecg_val = int(2048 + 400 * math.sin(i * 0.8))  # baseline rhythm

        # Simulated heart rate (72 +/- 4 bpm)
        hr_val = 72 + int(4 * math.sin(i * 0.5))

        # Pack 64-bit block: [ECG: 32 bits] | [HR: 16 bits] | [TS: 16 bits]
        plaintext = (ecg_val << 32) | (hr_val << 16) | ts_field

        # Encrypt with PRESENT-80
        ciphertext = cipher.encrypt(plaintext)

        # Simulate tampering on a specific packet if requested
        is_tampered = (i == tamper_at)
        if is_tampered:
            # Attacker flips bits in transit
            ciphertext ^= 0x0000000100000000

        ct_hex = f"{ciphertext:016X}"
        blocks.append(ct_hex)

        tag = " [TAMPERED!]" if is_tampered else ""
        print(f"#{i+1:<7} {t_ms:<10} {ecg_val:<10} {hr_val:<8} 0x{plaintext:016X}   0x{ct_hex}{tag}")

    print("-" * 84)
    return blocks


def main():
    parser = argparse.ArgumentParser(description="Virtual IoT Sensor Node Telemetry Generator")
    parser.add_argument("--count", type=int, default=8, help="Number of telemetry packets to generate")
    parser.add_argument("--out", type=str, default="/tmp/sensor_stream.txt", help="Output file path for ciphertexts")
    parser.add_argument("--tamper", action="store_true", help="Simulate an in-transit bit-flipping attack on packet #5")
    args = parser.parse_args()

    tamper_idx = 4 if args.tamper else -1
    blocks = generate_telemetry_blocks(args.count, tamper_idx)

    with open(args.out, "w") as f:
        for b in blocks:
            f.write(f"{b}\n")

    print(f"\n[✓] Generated {len(blocks)} encrypted packets saved to: {args.out}")
    print(f"[*] Now run the host receiver to decrypt:")
    print(f"    python3 python/decrypt_host.py --file {args.out}\n")


if __name__ == "__main__":
    main()
