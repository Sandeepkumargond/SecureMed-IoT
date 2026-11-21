"""
PRESENT-80 Block Cipher - Pure Python Implementation
======================================================
PRESENT is a lightweight block cipher designed for constrained environments
(RFID, sensor nodes, IoT). This implements the 80-bit key variant.

Reference: Bogdanov et al., "PRESENT: An Ultra-Lightweight Block Cipher", CHES 2007.
"""

from __future__ import annotations


class PRESENT:
    """
    Pure-Python PRESENT-80 block cipher.

    Block size : 64 bits
    Key size   : 80 bits
    Rounds     : 31  (indices 1 … 31; 32 round-keys generated)
    """

    # ------------------------------------------------------------------ #
    #  S-Box and inverse S-Box
    # ------------------------------------------------------------------ #
    sBox: list[int] = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                       0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

    sBox_inv: list[int] = [0] * 16  # filled in __init_subclass__

    # ------------------------------------------------------------------ #
    #  P-Layer permutation table (bit positions)
    #  P(i) = (i * 16) % 63  for i in 0..62,  P(63) = 63
    # ------------------------------------------------------------------ #
    pLayer_table: list[int] = [(i * 16) % 63 for i in range(63)] + [63]

    # Inverse permutation: pLayer_inv[pLayer_table[i]] = i
    pLayer_inv_table: list[int] = [0] * 64

    def __init_subclass__(cls, **kwargs: object) -> None:  # type: ignore[override]
        super().__init_subclass__(**kwargs)

    # Class-level initialisation of inverse tables
    @classmethod
    def _build_tables(cls) -> None:
        for i, v in enumerate(cls.sBox):
            cls.sBox_inv[v] = i
        for i, v in enumerate(cls.pLayer_table):
            cls.pLayer_inv_table[v] = i

    def __init__(self, key: bytes, key_size: int = 80) -> None:
        """
        Parameters
        ----------
        key      : 80-bit key as 10 bytes (big-endian).
        key_size : Must be 80 (128-bit variant not implemented).
        """
        if key_size != 80:
            raise ValueError("Only 80-bit key size is supported.")
        if len(key) != 10:
            raise ValueError(f"Key must be exactly 10 bytes for 80-bit PRESENT, got {len(key)}.")

        # Ensure class tables are ready
        PRESENT._build_tables()

        # Convert key bytes → integer (big-endian)
        self._key_int: int = int.from_bytes(key, "big")
        self._round_keys: list[int] = self._generate_round_keys(self._key_int)

    # ------------------------------------------------------------------ #
    #  Key Schedule
    # ------------------------------------------------------------------ #
    def _generate_round_keys(self, key_register: int) -> list[int]:
        """
        Generate 32 round keys (K_1 … K_32) from an 80-bit key register.

        Each round key K_i is the leftmost 64 bits of the key register.

        After extracting K_i the register is updated:
          1. Rotate left by 61 positions (≡ right by 19)
          2. Pass bits [79:76] through sBox
          3. XOR bits [19:15] with round counter i
        """
        round_keys: list[int] = []
        kr = key_register & ((1 << 80) - 1)

        for i in range(1, 33):
            # Extract leftmost 64 bits as round key
            round_keys.append((kr >> 16) & 0xFFFFFFFFFFFFFFFF)

            # --- Update key register ---
            # 1. Rotate left by 61 bits (80-bit register)
            kr = ((kr << 61) | (kr >> 19)) & ((1 << 80) - 1)

            # 2. Pass top 4 bits through sBox
            top4 = (kr >> 76) & 0xF
            kr = (self.sBox[top4] << 76) | (kr & ((1 << 76) - 1))

            # 3. XOR bits [19:15] with round counter i (5 bits)
            kr ^= (i & 0x1F) << 15

        return round_keys

    # ------------------------------------------------------------------ #
    #  S-Layer  (apply sBox to each 4-bit nibble of a 64-bit state)
    # ------------------------------------------------------------------ #
    @classmethod
    def _sLayer(cls, state: int) -> int:
        result = 0
        for nibble_idx in range(16):  # 16 nibbles in 64 bits
            shift = nibble_idx * 4
            nibble = (state >> shift) & 0xF
            result |= cls.sBox[nibble] << shift
        return result

    @classmethod
    def _sLayer_inv(cls, state: int) -> int:
        result = 0
        for nibble_idx in range(16):
            shift = nibble_idx * 4
            nibble = (state >> shift) & 0xF
            result |= cls.sBox_inv[nibble] << shift
        return result

    # ------------------------------------------------------------------ #
    #  P-Layer  (bit permutation on a 64-bit state)
    # ------------------------------------------------------------------ #
    @classmethod
    def _pLayer(cls, state: int) -> int:
        result = 0
        for i in range(64):
            bit = (state >> i) & 1
            result |= bit << cls.pLayer_table[i]
        return result

    @classmethod
    def _pLayer_inv(cls, state: int) -> int:
        result = 0
        for i in range(64):
            bit = (state >> i) & 1
            result |= bit << cls.pLayer_inv_table[i]
        return result

    # ------------------------------------------------------------------ #
    #  Encrypt / Decrypt
    # ------------------------------------------------------------------ #
    def encrypt(self, plaintext: int) -> int:
        """
        Encrypt a 64-bit plaintext integer using PRESENT-80.

        Parameters
        ----------
        plaintext : 64-bit integer.

        Returns
        -------
        64-bit ciphertext integer.
        """
        if plaintext < 0 or plaintext > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Plaintext must be a 64-bit unsigned integer.")

        state = plaintext
        for i in range(31):                             # rounds 1..31
            state ^= self._round_keys[i]                # AddRoundKey
            state = self._sLayer(state)                 # S-Layer
            state = self._pLayer(state)                 # P-Layer
        state ^= self._round_keys[31]                   # Final AddRoundKey (K_32)
        return state

    def decrypt(self, ciphertext: int) -> int:
        """
        Decrypt a 64-bit ciphertext integer using PRESENT-80.

        Parameters
        ----------
        ciphertext : 64-bit integer.

        Returns
        -------
        64-bit plaintext integer.
        """
        if ciphertext < 0 or ciphertext > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Ciphertext must be a 64-bit unsigned integer.")

        state = ciphertext
        state ^= self._round_keys[31]                   # Undo K_32
        for i in range(30, -1, -1):                     # rounds 31..1
            state = self._pLayer_inv(state)             # Inverse P-Layer
            state = self._sLayer_inv(state)             # Inverse S-Layer
            state ^= self._round_keys[i]                # Undo AddRoundKey
        return state


# --------------------------------------------------------------------------- #
#  Convenience helpers
# --------------------------------------------------------------------------- #

def present_encrypt(plaintext: int, key: bytes) -> int:
    """
    Encrypt a 64-bit plaintext integer with an 80-bit key.
    
    Parameters
    ----------
    plaintext : 64-bit unsigned integer
    key       : 10-byte (80-bit) key
    
    Returns
    -------
    64-bit unsigned ciphertext integer
    """
    cipher = PRESENT(key)
    return cipher.encrypt(plaintext)


def present_decrypt(ciphertext: int, key: bytes) -> int:
    """
    Decrypt a 64-bit ciphertext integer with an 80-bit key.
    
    Parameters
    ----------
    ciphertext : 64-bit unsigned integer
    key        : 10-byte (80-bit) key
    
    Returns
    -------
    64-bit unsigned plaintext integer
    """
    cipher = PRESENT(key)
    return cipher.decrypt(ciphertext)


def present_encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt an 8-byte block; returns 8-byte ciphertext."""
    if len(plaintext) != 8:
        raise ValueError("Plaintext block must be 8 bytes.")
    cipher = PRESENT(key)
    pt_int = int.from_bytes(plaintext, "big")
    ct_int = cipher.encrypt(pt_int)
    return ct_int.to_bytes(8, "big")


def present_decrypt_bytes(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt an 8-byte block; returns 8-byte plaintext."""
    if len(ciphertext) != 8:
        raise ValueError("Ciphertext block must be 8 bytes.")
    cipher = PRESENT(key)
    ct_int = int.from_bytes(ciphertext, "big")
    pt_int = cipher.decrypt(ct_int)
    return pt_int.to_bytes(8, "big")


# --------------------------------------------------------------------------- #
#  Self-tests
# --------------------------------------------------------------------------- #

# Official PRESENT-80 test vectors (from Appendix I of CHES 2007 paper)
_TEST_VECTORS: list[tuple[int, int, int]] = [
    # (plaintext, key, expected_ciphertext)
    (
        0x0000000000000000,
        0x00000000000000000000,
        0x5579C1387B228445,
    ),
    (
        0x0000000000000000,
        0xFFFFFFFFFFFFFFFFFFFF,
        0xE72C46C0F5945049,
    ),
    (
        0xFFFFFFFFFFFFFFFF,
        0x00000000000000000000,
        0xA112FFC72F68417B,
    ),
    (
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFFFFFF,
        0x3333DCD3213210D2,
    ),
]


def run_self_tests(verbose: bool = True) -> bool:
    """Run all known test vectors. Returns True iff all pass."""
    all_pass = True

    for idx, (pt, k_int, exp_ct) in enumerate(_TEST_VECTORS, 1):
        key = k_int.to_bytes(10, "big")
        cipher = PRESENT(key)
        ct_got = cipher.encrypt(pt)
        enc_pass = (ct_got == exp_ct)

        pt_back = cipher.decrypt(ct_got)
        dec_pass = (pt_back == pt)

        if verbose:
            status = "PASS" if enc_pass else "FAIL"
            print(f"[TV{idx} Encrypt] PT=0x{pt:016X}  KEY=0x{k_int:020X}  "
                  f"CT=0x{ct_got:016X}  Expected=0x{exp_ct:016X}  [{status}]")
            status2 = "PASS" if dec_pass else "FAIL"
            print(f"[TV{idx} Decrypt] CT=0x{exp_ct:016X}  "
                  f"Recovered=0x{pt_back:016X}  [{status2}]")

        all_pass = all_pass and enc_pass and dec_pass

    # Additional round-trip test with arbitrary key/plaintext
    import os
    rng_key = os.urandom(10)
    rng_pt  = int.from_bytes(os.urandom(8), "big")
    cipher_rnd = PRESENT(rng_key)
    rng_ct  = cipher_rnd.encrypt(rng_pt)
    rng_pt2 = cipher_rnd.decrypt(rng_ct)
    rng_pass = rng_pt2 == rng_pt

    if verbose:
        status = "PASS" if rng_pass else "FAIL"
        print(f"[TV-Random] PT=0x{rng_pt:016X}  KEY=0x{int.from_bytes(rng_key,'big'):020X}  "
              f"CT=0x{rng_ct:016X}  Round-trip [{status}]")

    all_pass = all_pass and rng_pass

    if verbose:
        print()
        print("=" * 60)
        print(f"Overall self-test result: {'ALL PASS' if all_pass else 'SOME FAIL'}")
        print("=" * 60)

    return all_pass


if __name__ == "__main__":
    import sys
    ok = run_self_tests(verbose=True)
    sys.exit(0 if ok else 1)
