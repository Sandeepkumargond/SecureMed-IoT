#!/usr/bin/env python3
"""
run_demo.py – Interactive Project Demonstration & Verification Suite
====================================================================
Comprehensive evaluation testbench and demonstration suite for the
SecureMed-IoT PRESENT-80 Lightweight Cryptography system.

Modules:
  [1] Official CHES 2007 Test Vectors & Regression Suite (18 tests)
  [2] Standalone Cipher Hex Verification (S-Box, P-Layer, Round Keys)
  [3] Data Integrity & Framing Suite (CRC-16, HMAC-SHA256)
  [4] Cryptographic Benchmark (Latency, Throughput, AES-128 comparison)
  [5] Live Virtual IoT Healthcare Sensor Telemetry -> Decryption Host
  [6] Tampering & Avalanche Demonstration (Attacker Bit-Flip Detection)
  [7] Security Attacks & Cryptanalysis Suite (Brute Force, Live 16-bit Crack)
  [8] Native C Firmware Verification (Compile & execute Arduino C with GCC)
  [9] Run Complete Verification Sequence (Steps 1, 2, 3, 5, 6, 8)
"""

import os
import subprocess
import sys
import time

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def header(title: str):
    print("\n" + "=" * 70)
    print(f"{BOLD}{CYAN}{title.center(70)}{RESET}")
    print("=" * 70 + "\n")


def run_cmd(cmd: str, desc: str = ""):
    if desc:
        print(f"{YELLOW}>>> {desc}{RESET}")
    print(f"{BOLD}$ {cmd}{RESET}\n")
    start = time.time()
    res = subprocess.run(cmd, shell=True, cwd=PROJECT_ROOT)
    elapsed = time.time() - start
    if res.returncode == 0:
        print(f"\n{GREEN}[✓] Completed successfully in {elapsed:.2f}s{RESET}")
    else:
        print(f"\n{RED}[✗] Command failed with returncode {res.returncode}{RESET}")
    return res.returncode


def demo_unit_tests():
    header("Step 1: Official Test Vectors & Unit Test Regression Suite")
    print("Key Verification Objectives:")
    print(" - Conformance with ISO/IEC 29192-2 and CHES 2007 official test vectors.")
    print(" - Correctness of 100 random round-trip encryptions.")
    print(" - Avalanche effect (>50% bit flips on single bit change) and key sensitivity.\n")
    run_cmd('python3 -m unittest discover -s tests -p "test_*.py" -v')


def demo_present_core():
    header("Step 2: PRESENT-80 Cipher Core & Round-by-Round Hex Output")
    print("Key Verification Objectives:")
    print(" - Independent verification of TV1..TV4 showing exact hex inputs and outputs.")
    print(" - Verification of inverse S-Box and inverse P-Layer during decryption.\n")
    run_cmd("python3 python/present.py")


def demo_data_integrity():
    header("Step 3: Cryptographic Data Integrity & Packet Framing")
    print("Key Verification Objectives:")
    print(" - Demonstrates CRC-16/CCITT transmission error detection.")
    print(" - Demonstrates HMAC-SHA256 message authentication and anti-tamper security.")
    print(" - Verifies structured 42-byte healthcare telemetry frames.\n")
    run_cmd("python3 python/data_integrity.py")


def demo_benchmarks():
    header("Step 4: Performance, Memory & AES-128 Comparison Benchmark")
    print("Key Verification Objectives:")
    print(" - Software latency and throughput on 10,000 blocks.")
    print(" - Demonstrates memory footprint (RSS/VMS).")
    print(" - Compares PRESENT-80 against AES-128 for lightweight IoT devices.\n")
    run_cmd("python3 python/benchmark.py")


def demo_telemetry_live():
    header("Step 5: End-to-End IoT Healthcare Telemetry -> Host Receiver")
    print("Key Verification Objectives:")
    print(" - Virtual IoT sensor generates synthetic ECG and Heart Rate vitals.")
    print(" - Microcontroller logic packs vitals into 64-bit blocks and encrypts.")
    print(" - Host engine (decrypt_host.py) receives, decrypts, and audits to CSV.\n")
    run_cmd(
        "python3 python/simulate_sensor_node.py --count 6 --out /tmp/sensor_stream.txt && "
        "python3 python/decrypt_host.py --file /tmp/sensor_stream.txt",
        "Generating simulated telemetry and executing host decryption",
    )
    print("\nRecent entries in clinical audit log (decrypt_log.csv):")
    run_cmd("tail -n 6 decrypt_log.csv")


def demo_tamper_detection():
    header("Step 6: Active Attacker Simulation (Tamper & Anomaly Detection)")
    print("Key Verification Objectives:")
    print(" - Simulates a man-in-the-middle attacker flipping 1 bit in packet #5.")
    print(" - Due to the Avalanche effect, decryption produces non-physiological vitals.")
    print(" - Host anomaly detection flags the packet as INVALID immediately.\n")
    run_cmd(
        "python3 python/simulate_sensor_node.py --count 6 --tamper --out /tmp/sensor_tampered.txt && "
        "python3 python/decrypt_host.py --file /tmp/sensor_tampered.txt",
        "Injecting single bit error in transit and verifying host validation failure",
    )


def demo_security_attacks():
    header("Step 7: Security Evaluation & Side-Channel Cryptanalysis Suite")
    print("Key Verification Objectives:")
    print(" - Brute force math: 80-bit key space requires >19,000 years to crack.")
    print(" - Live 16-bit key search: exhaustively cracks a 16-bit space in ~16s.")
    print(" - Timing attack simulation: confirms constant-time execution (no timing leak).")
    print(" - SPA & DPA power analysis simulation and 1st-order Boolean masking.\n")
    run_cmd("cd python && python3 attack_simulation.py")


def demo_native_c():
    header("Step 8: Native C Microcontroller Firmware Verification (GCC)")
    print("Key Verification Objectives:")
    print(" - Proves that the exact C code (arduino/present_cipher.c) written for the")
    print("   microcontroller compiles with zero warnings and runs with 100% precision.")
    print(" - Demonstrates sub-microsecond native C execution speed.\n")
    run_cmd(
        "gcc -O2 tests/test_c_native.c arduino/present_cipher.c -Iarduino -o tests/test_c_native && ./tests/test_c_native",
        "Compiling arduino/present_cipher.c natively with GCC",
    )


def menu():
    while True:
        print("\n" + "=" * 70)
        print(f"{BOLD}{GREEN}  SecureMed-IoT: System Verification & Demonstration Console  {RESET}")
        print("=" * 70)
        print("  [1] Run Official CHES 2007 Test Vectors (18 unittests)")
        print("  [2] Inspect Core PRESENT-80 Cipher (Hex plaintexts, keys, ciphertexts)")
        print("  [3] Test Data Integrity & Framing Suite (CRC-16 + HMAC-SHA256)")
        print("  [4] Run Performance & Memory Benchmarks (Latency & Throughput)")
        print("  [5] Run End-to-End Telemetry Pipeline (Simulated Node -> Decrypt Host)")
        print("  [6] Demonstrate Tamper Detection (In-transit bit flip anomaly)")
        print("  [7] Run Security & Attack Suite (Brute Force, Live Key Crack, SPA/DPA)")
        print("  [8] Compile & Run Native C Microcontroller Firmware (GCC)")
        print("  [9] Run Complete Verification Sequence (Steps 1, 2, 3, 5, 6, 8)")
        print("  [0] Exit")
        print("=" * 70)
        choice = input(f"{BOLD}Select an option [0-9]: {RESET}").strip()

        if choice == "1":
            demo_unit_tests()
        elif choice == "2":
            demo_present_core()
        elif choice == "3":
            demo_data_integrity()
        elif choice == "4":
            demo_benchmarks()
        elif choice == "5":
            demo_telemetry_live()
        elif choice == "6":
            demo_tamper_detection()
        elif choice == "7":
            demo_security_attacks()
        elif choice == "8":
            demo_native_c()
        elif choice == "9":
            demo_unit_tests()
            input(f"\n{YELLOW}Press Enter to proceed to Step 2 (Cipher Inspection)...{RESET}")
            demo_present_core()
            input(f"\n{YELLOW}Press Enter to proceed to Step 3 (Data Integrity)...{RESET}")
            demo_data_integrity()
            input(f"\n{YELLOW}Press Enter to proceed to Step 5 (Live Telemetry Pipeline)...{RESET}")
            demo_telemetry_live()
            input(f"\n{YELLOW}Press Enter to proceed to Step 6 (Tamper Detection)...{RESET}")
            demo_tamper_detection()
            input(f"\n{YELLOW}Press Enter to proceed to Step 8 (Native C Firmware)...{RESET}")
            demo_native_c()
            print(f"\n{GREEN}{BOLD}=== System Demonstration Completed Successfully! ==={RESET}\n")
        elif choice == "0":
            print("Exiting demonstration console.")
            break
        else:
            print(f"{RED}Invalid option, please choose between 0 and 9.{RESET}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        demo_unit_tests()
        demo_present_core()
        demo_data_integrity()
        demo_telemetry_live()
        demo_tamper_detection()
        demo_native_c()
    else:
        menu()
