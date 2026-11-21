"""
data_integrity.py – Data Integrity Verification for IoT Healthcare Frames
==========================================================================
Provides CRC-16 checksum and HMAC-SHA256 authentication for sensor data
transmitted from IoT nodes to the host.

Frame layout (produced by pack_sensor_frame)
--------------------------------------------
  Bytes  0–3   : ECG raw value     (uint32, big-endian)
  Bytes  4–5   : Heart Rate        (uint16, big-endian)
  Bytes  6–7   : Timestamp         (uint16, big-endian)
  Bytes  8–9   : CRC-16/CCITT     (uint16, big-endian) – covers bytes 0–7
  Bytes 10–41  : HMAC-SHA256       (32 bytes) – covers bytes 0–9

Total frame size: 42 bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import sys


# --------------------------------------------------------------------------- #
#  CRC-16 / CCITT-FALSE  (poly=0x1021, init=0xFFFF, reflect=False)
# --------------------------------------------------------------------------- #

_CRC16_TABLE: list[int] = []


def _build_crc16_table() -> None:
    """Pre-compute the CRC-16/CCITT lookup table (256 entries)."""
    for byte in range(256):
        crc = byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
        _CRC16_TABLE.append(crc)


_build_crc16_table()


def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    """
    Compute CRC-16/CCITT-FALSE over ``data``.

    Parameters
    ----------
    data : Input bytes.
    init : Initial CRC register value (default 0xFFFF).

    Returns
    -------
    16-bit CRC as an integer.
    """
    crc = init
    for byte in data:
        tbl_idx = ((crc >> 8) ^ byte) & 0xFF
        crc     = ((crc << 8) ^ _CRC16_TABLE[tbl_idx]) & 0xFFFF
    return crc


# --------------------------------------------------------------------------- #
#  IntegrityChecker
# --------------------------------------------------------------------------- #

class IntegrityChecker:
    """
    Provides CRC-16 and HMAC-SHA256 integrity / authentication services.

    All methods are stateless (no instance attributes required), but the
    class groups them logically.
    """

    # ------------------------------------------------------------------ #
    #  CRC-16
    # ------------------------------------------------------------------ #

    @staticmethod
    def add_crc(data: bytes) -> bytes:
        """
        Append a 2-byte CRC-16/CCITT checksum to ``data``.

        Parameters
        ----------
        data : Arbitrary bytes.

        Returns
        -------
        ``data`` + 2-byte big-endian CRC.
        """
        crc = crc16_ccitt(data)
        return data + struct.pack(">H", crc)

    @staticmethod
    def verify_crc(data: bytes) -> tuple[bytes, bool]:
        """
        Verify and strip the trailing 2-byte CRC from ``data``.

        Parameters
        ----------
        data : Bytes ending with a 2-byte CRC appended by ``add_crc``.

        Returns
        -------
        (payload, valid) where ``payload`` is the data without the CRC
        and ``valid`` is True iff the CRC matched.
        """
        if len(data) < 2:
            return data, False
        payload       = data[:-2]
        received_crc, = struct.unpack(">H", data[-2:])
        computed_crc  = crc16_ccitt(payload)
        return payload, (received_crc == computed_crc)

    # ------------------------------------------------------------------ #
    #  HMAC-SHA256
    # ------------------------------------------------------------------ #

    @staticmethod
    def add_hmac(data: bytes, key: bytes) -> bytes:
        """
        Append a 32-byte HMAC-SHA256 authentication tag to ``data``.

        Parameters
        ----------
        data : Message bytes.
        key  : HMAC secret key (any length; 32 bytes recommended).

        Returns
        -------
        ``data`` + 32-byte HMAC digest.
        """
        tag = hmac.new(key, data, hashlib.sha256).digest()
        return data + tag

    @staticmethod
    def verify_hmac(data: bytes, key: bytes) -> tuple[bytes, bool]:
        """
        Verify and strip the trailing 32-byte HMAC from ``data``.

        Uses ``hmac.compare_digest`` to prevent timing attacks.

        Parameters
        ----------
        data : Bytes ending with a 32-byte HMAC appended by ``add_hmac``.
        key  : HMAC secret key.

        Returns
        -------
        (payload, valid) where ``payload`` is data without the HMAC
        and ``valid`` is True iff the tag matched.
        """
        if len(data) < 32:
            return data, False
        payload      = data[:-32]
        received_tag = data[-32:]
        expected_tag = hmac.new(key, payload, hashlib.sha256).digest()
        valid        = hmac.compare_digest(received_tag, expected_tag)
        return payload, valid

    # ------------------------------------------------------------------ #
    #  Sensor Frame Packing / Unpacking
    # ------------------------------------------------------------------ #

    @staticmethod
    def pack_sensor_frame(ecg: int, hr: int, ts: int, session_key: bytes) -> bytes:
        """
        Pack sensor readings into an authenticated frame.

        Layout
        ------
          [0:4]   ECG raw (uint32 BE)
          [4:6]   Heart Rate (uint16 BE)
          [6:8]   Timestamp (uint16 BE)
          [8:10]  CRC-16/CCITT over bytes [0:8]
          [10:42] HMAC-SHA256 over bytes [0:10]

        Parameters
        ----------
        ecg         : 32-bit ECG raw ADC value.
        hr          : 16-bit heart rate (bpm).
        ts          : 16-bit timestamp (low 16 bits of ms counter).
        session_key : HMAC key (bytes).

        Returns
        -------
        42-byte frame.
        """
        if not (0 <= ecg <= 0xFFFFFFFF):
            raise ValueError(f"ECG value {ecg} out of uint32 range.")
        if not (0 <= hr <= 0xFFFF):
            raise ValueError(f"Heart rate {hr} out of uint16 range.")
        if not (0 <= ts <= 0xFFFF):
            raise ValueError(f"Timestamp {ts} out of uint16 range.")

        payload = struct.pack(">IHH", ecg, hr, ts)   # 8 bytes
        framed  = IntegrityChecker.add_crc(payload)   # 10 bytes
        framed  = IntegrityChecker.add_hmac(framed, session_key)  # 42 bytes
        return framed

    @staticmethod
    def unpack_sensor_frame(frame: bytes, session_key: bytes) -> dict:
        """
        Unpack and verify a sensor frame created by ``pack_sensor_frame``.

        Parameters
        ----------
        frame       : 42-byte frame.
        session_key : HMAC key.

        Returns
        -------
        dict with keys:
            ecg (int), heart_rate (int), timestamp (int),
            crc_valid (bool), hmac_valid (bool), frame_valid (bool),
            error (str | None)
        """
        result: dict = {
            "ecg": -1,
            "heart_rate": -1,
            "timestamp": -1,
            "crc_valid": False,
            "hmac_valid": False,
            "frame_valid": False,
            "error": None,
        }

        if len(frame) != 42:
            result["error"] = f"Frame length {len(frame)} is not 42 bytes."
            return result

        # 1. Verify HMAC
        payload_with_crc, hmac_ok = IntegrityChecker.verify_hmac(frame, session_key)
        result["hmac_valid"] = hmac_ok

        # 2. Verify CRC
        payload, crc_ok = IntegrityChecker.verify_crc(payload_with_crc)
        result["crc_valid"] = crc_ok

        # 3. Unpack sensor fields (payload should now be 8 bytes)
        if len(payload) == 8:
            ecg, hr, ts = struct.unpack(">IHH", payload)
            result["ecg"]        = ecg
            result["heart_rate"] = hr
            result["timestamp"]  = ts
        else:
            result["error"] = f"Unexpected payload length {len(payload)} after stripping CRC."

        result["frame_valid"] = hmac_ok and crc_ok and (result["error"] is None)
        return result


# --------------------------------------------------------------------------- #
#  Self-tests
# --------------------------------------------------------------------------- #

def _run_self_tests() -> bool:
    all_pass = True

    def check(name: str, cond: bool) -> None:
        nonlocal all_pass
        status = "PASS" if cond else "FAIL"
        print(f"  [{status}] {name}")
        if not cond:
            all_pass = False

    checker = IntegrityChecker()
    key     = os.urandom(32)

    # --- CRC tests ---
    print("\n[CRC-16 Tests]")
    data  = b"Hello, IoT!"
    framed = checker.add_crc(data)
    check("add_crc increases length by 2", len(framed) == len(data) + 2)

    recovered, valid = checker.verify_crc(framed)
    check("verify_crc on valid frame", valid and recovered == data)

    corrupted = bytearray(framed)
    corrupted[0] ^= 0xFF      # flip bits in first byte
    _, inv_valid = checker.verify_crc(bytes(corrupted))
    check("verify_crc detects corruption", not inv_valid)

    # Known CRC value: CRC-16/CCITT of b"\x00\x00" = 0x1D0F
    known_crc = crc16_ccitt(b"\x00\x00")
    check("CRC-16/CCITT known value 0x1D0F", known_crc == 0x1D0F)

    # --- HMAC tests ---
    print("\n[HMAC-SHA256 Tests]")
    tagged = checker.add_hmac(data, key)
    check("add_hmac increases length by 32", len(tagged) == len(data) + 32)

    recovered2, valid2 = checker.verify_hmac(tagged, key)
    check("verify_hmac on valid tag", valid2 and recovered2 == data)

    # Wrong key
    _, wrong_key_valid = checker.verify_hmac(tagged, os.urandom(32))
    check("verify_hmac rejects wrong key", not wrong_key_valid)

    # Tampered data
    tampered = bytearray(tagged)
    tampered[1] ^= 0x01
    _, tampered_valid = checker.verify_hmac(bytes(tampered), key)
    check("verify_hmac detects tampering", not tampered_valid)

    # --- Full frame pack / unpack ---
    print("\n[Sensor Frame Tests]")
    session_key = os.urandom(32)
    ecg_val = 2048
    hr_val  = 72
    ts_val  = 0xABCD

    frame = checker.pack_sensor_frame(ecg_val, hr_val, ts_val, session_key)
    check("pack_sensor_frame produces 42 bytes", len(frame) == 42)

    unpacked = checker.unpack_sensor_frame(frame, session_key)
    check("unpack ECG matches",        unpacked["ecg"]        == ecg_val)
    check("unpack heart_rate matches", unpacked["heart_rate"] == hr_val)
    check("unpack timestamp matches",  unpacked["timestamp"]  == ts_val)
    check("frame_valid is True",       unpacked["frame_valid"])
    check("crc_valid is True",         unpacked["crc_valid"])
    check("hmac_valid is True",        unpacked["hmac_valid"])

    # Corrupted frame
    bad_frame = bytearray(frame)
    bad_frame[2] ^= 0xFF
    bad_unpacked = checker.unpack_sensor_frame(bytes(bad_frame), session_key)
    check("Corrupted frame detected (frame_valid=False)", not bad_unpacked["frame_valid"])

    # Wrong session key
    wrong_unpacked = checker.unpack_sensor_frame(frame, os.urandom(32))
    check("Wrong key detected (hmac_valid=False)", not wrong_unpacked["hmac_valid"])

    # Short frame
    short_result = checker.unpack_sensor_frame(b"\x00" * 10, session_key)
    check("Short frame returns error", short_result["error"] is not None)

    print()
    return all_pass


if __name__ == "__main__":
    print("=" * 60)
    print(" data_integrity.py – Self-Test Suite")
    print("=" * 60)
    ok = _run_self_tests()
    print("=" * 60)
    print(f" Overall result: {'ALL PASS' if ok else 'SOME FAIL'}")
    print("=" * 60)
    sys.exit(0 if ok else 1)
