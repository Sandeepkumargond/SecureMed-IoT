"""
decrypt_host.py – PRESENT-80 Healthcare Decryption Host
=========================================================
Receives 64-bit encrypted blocks from an IoT sensor node, decrypts them
using PRESENT-80, unpacks the sensor payload, validates the data, and
logs everything to a CSV file.

Payload layout (64 bits total, big-endian inside the decrypted block):
  Bits [63:32]  – ECG raw value  (32 bits, 0–4095 valid for 12-bit ADC)
  Bits [31:16]  – Heart Rate     (16 bits, 40–200 bpm valid)
  Bits [15:0]   – Timestamp      (16 bits, low 16 bits of millisecond counter)

Usage examples
--------------
  python decrypt_host.py --file encrypted.txt
  python decrypt_host.py --serial /dev/ttyUSB0 --baud 9600
  python decrypt_host.py --mqtt 192.168.1.100

The shared PRESENT-80 key must match the device firmware.
Default key (matches Arduino/ESP32 demos): 0x0123456789ABCDEF0123
Override via --key <20-hex-char string>.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import os
import sys
import time
from typing import Optional

# Reuse our pure-Python PRESENT implementation
from present import PRESENT

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

DEFAULT_KEY_HEX: str = "0123456789ABCDEF0123"   # 80-bit / 10-byte key
LOG_FILE: str = "decrypt_log.csv"
MQTT_TOPIC: str = "healthcare/encrypted"

HR_MIN: int = 40    # beats per minute
HR_MAX: int = 200
ECG_MIN: int = 0
ECG_MAX: int = 4095  # 12-bit ADC


# --------------------------------------------------------------------------- #
#  Payload helpers
# --------------------------------------------------------------------------- #

def unpack_payload(block64: int) -> dict:
    """
    Unpack a decrypted 64-bit integer into sensor fields.

    Returns
    -------
    dict with keys: ecg_raw (int), heart_rate (int), timestamp_raw (int)
    """
    ecg_raw    = (block64 >> 32) & 0xFFFFFFFF
    heart_rate = (block64 >> 16) & 0xFFFF
    timestamp  = block64 & 0xFFFF
    return {
        "ecg_raw": ecg_raw,
        "heart_rate": heart_rate,
        "timestamp_raw": timestamp,
    }


def validate_payload(payload: dict) -> bool:
    """Return True if payload values are within physiologically valid ranges."""
    hr  = payload["heart_rate"]
    ecg = payload["ecg_raw"]
    return (HR_MIN <= hr <= HR_MAX) and (ECG_MIN <= ecg <= ECG_MAX)


def decrypt_hex(hex_str: str, cipher: PRESENT) -> Optional[dict]:
    """
    Decrypt a hex string representing a 64-bit ciphertext block.

    Returns a dict with all fields on success, or None if parsing fails.
    """
    hex_str = hex_str.strip()
    if not hex_str:
        return None
    try:
        ct_int = int(hex_str, 16)
        if ct_int > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Value exceeds 64 bits")
    except ValueError as exc:
        print(f"[WARN] Cannot parse hex string '{hex_str}': {exc}", file=sys.stderr)
        return None

    pt_int  = cipher.decrypt(ct_int)
    payload = unpack_payload(pt_int)
    payload["ciphertext_hex"] = hex_str.upper().zfill(16)
    payload["valid"]          = validate_payload(payload)
    payload["host_time"]      = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return payload


# --------------------------------------------------------------------------- #
#  CSV Logger
# --------------------------------------------------------------------------- #

class CSVLogger:
    """Append decoded packets to a CSV log file."""

    _FIELDNAMES = ["host_time", "timestamp_raw", "ecg_raw", "heart_rate",
                   "valid", "ciphertext_hex"]

    def __init__(self, path: str = LOG_FILE) -> None:
        self._path = path
        self._file = open(path, "a", newline="")  # noqa: WPS515
        self._writer = csv.DictWriter(
            self._file,
            fieldnames=self._FIELDNAMES,
            extrasaction="ignore",
        )
        # Write header only when file is empty
        if os.path.getsize(path) == 0:
            self._writer.writeheader()

    def log(self, payload: dict) -> None:
        self._writer.writerow(payload)
        self._file.flush()

    def close(self) -> None:
        self._file.close()


# --------------------------------------------------------------------------- #
#  Packet printer
# --------------------------------------------------------------------------- #

def print_packet(payload: dict) -> None:
    validity = "VALID  ✓" if payload["valid"] else "INVALID ✗"
    print(
        f"[{payload['host_time']}]  "
        f"CT=0x{payload['ciphertext_hex']}  "
        f"ECG={payload['ecg_raw']:5d}  "
        f"HR={payload['heart_rate']:3d} bpm  "
        f"TS_raw=0x{payload['timestamp_raw']:04X}  "
        f"{validity}"
    )


# --------------------------------------------------------------------------- #
#  Input source: file
# --------------------------------------------------------------------------- #

def process_file(path: str, cipher: PRESENT, logger: CSVLogger) -> None:
    """Read hex strings line-by-line from a file."""
    with open(path, "r") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            payload = decrypt_hex(line, cipher)
            if payload is not None:
                print_packet(payload)
                logger.log(payload)
            else:
                print(f"[WARN] Line {lineno}: skipped invalid entry '{line}'",
                      file=sys.stderr)


# --------------------------------------------------------------------------- #
#  Input source: serial port
# --------------------------------------------------------------------------- #

def process_serial(port: str, baud: int, cipher: PRESENT, logger: CSVLogger) -> None:
    """Read hex strings from a serial port (one per line)."""
    try:
        import serial  # type: ignore[import]
    except ImportError:
        print("[ERROR] pyserial is not installed. Run: pip install pyserial",
              file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Opening serial port {port} at {baud} baud …")
    with serial.Serial(port, baud, timeout=5) as ser:
        print(f"[INFO] Listening on {port}. Press Ctrl+C to stop.")
        try:
            while True:
                raw = ser.readline()
                if not raw:
                    continue
                line = raw.decode("ascii", errors="ignore").strip()
                payload = decrypt_hex(line, cipher)
                if payload is not None:
                    print_packet(payload)
                    logger.log(payload)
        except KeyboardInterrupt:
            print("\n[INFO] Serial capture stopped by user.")


# --------------------------------------------------------------------------- #
#  Input source: MQTT
# --------------------------------------------------------------------------- #

def process_mqtt(broker: str, port: int, cipher: PRESENT, logger: CSVLogger) -> None:
    """Subscribe to MQTT topic and decrypt incoming messages."""
    try:
        import paho.mqtt.client as mqtt  # type: ignore[import]
    except ImportError:
        print("[ERROR] paho-mqtt is not installed. Run: pip install paho-mqtt",
              file=sys.stderr)
        sys.exit(1)

    def on_connect(client, userdata, flags, rc):  # noqa: ANN001
        if rc == 0:
            print(f"[INFO] Connected to MQTT broker {broker}:{port}")
            client.subscribe(MQTT_TOPIC)
            print(f"[INFO] Subscribed to '{MQTT_TOPIC}'. Press Ctrl+C to stop.")
        else:
            print(f"[ERROR] MQTT connection failed with code {rc}", file=sys.stderr)

    def on_message(client, userdata, msg):  # noqa: ANN001
        line = msg.payload.decode("ascii", errors="ignore").strip()
        payload = decrypt_hex(line, cipher)
        if payload is not None:
            print_packet(payload)
            logger.log(payload)

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(broker, port, keepalive=60)
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n[INFO] MQTT capture stopped by user.")
    finally:
        client.disconnect()


# --------------------------------------------------------------------------- #
#  CLI entry point
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PRESENT-80 Healthcare Decryption Host",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file",   metavar="FILE",   help="Read hex ciphertext from a file")
    source.add_argument("--serial", metavar="PORT",   help="Read from serial port (e.g. /dev/ttyUSB0)")
    source.add_argument("--mqtt",   metavar="BROKER", help="Subscribe to MQTT broker (e.g. 192.168.1.100)")

    parser.add_argument(
        "--baud", type=int, default=9600,
        help="Serial baud rate (default: 9600, only used with --serial)",
    )
    parser.add_argument(
        "--mqtt-port", type=int, default=1883,
        help="MQTT broker port (default: 1883, only used with --mqtt)",
    )
    parser.add_argument(
        "--key", default=DEFAULT_KEY_HEX,
        help=f"PRESENT-80 key as 20 hex chars (default: {DEFAULT_KEY_HEX})",
    )
    parser.add_argument(
        "--log", default=LOG_FILE,
        help=f"Output CSV log file (default: {LOG_FILE})",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # Parse key
    key_hex = args.key.strip()
    if len(key_hex) != 20:
        parser.error(f"--key must be exactly 20 hex characters, got {len(key_hex)}")
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        parser.error("--key contains non-hex characters")

    cipher = PRESENT(key_bytes)
    logger = CSVLogger(args.log)
    print(f"[INFO] PRESENT-80 key: 0x{key_hex.upper()}")
    print(f"[INFO] Logging to: {args.log}")

    try:
        if args.file:
            process_file(args.file, cipher, logger)
        elif args.serial:
            process_serial(args.serial, args.baud, cipher, logger)
        elif args.mqtt:
            process_mqtt(args.mqtt, args.mqtt_port, cipher, logger)
    finally:
        logger.close()
        print("[INFO] Logger closed.")


if __name__ == "__main__":
    main()
