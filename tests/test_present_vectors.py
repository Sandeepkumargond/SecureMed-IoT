"""
Unit tests for PRESENT-80 implementation.

Tests cover:
  - Official PRESENT-80 test vectors (3 vectors from the original paper)
  - Round-trip encrypt/decrypt correctness (100 random cases)
  - Avalanche effect: 1-bit input change → ~50% output bits changed
  - Key sensitivity: 1-bit key change → completely different ciphertext

Usage:
    python -m unittest tests/test_present_vectors.py
    # or from project root:
    python -m unittest discover -s tests -p "test_*.py"
"""

import sys
import os
import unittest
import random
import statistics

# ---------------------------------------------------------------------------
# Locate present.py in ../python/present.py relative to this test file
# ---------------------------------------------------------------------------
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PYTHON_DIR = os.path.normpath(os.path.join(_TESTS_DIR, '..', 'python'))
if _PYTHON_DIR not in sys.path:
    sys.path.insert(0, _PYTHON_DIR)

try:
    from present import present_encrypt, present_decrypt
except ImportError as e:
    raise ImportError(
        f"Could not import 'present' from {_PYTHON_DIR}.\n"
        "Make sure python/present.py exists and defines "
        "present_encrypt(plaintext: int, key: bytes) -> int  and "
        "present_decrypt(ciphertext: int, key: bytes) -> int."
    ) from e


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def int_to_key_bytes(k: int, length: int = 10) -> bytes:
    """Convert an integer to a fixed-length bytes object (big-endian)."""
    return k.to_bytes(length, byteorder='big')


def hamming_distance(a: int, b: int, bits: int = 64) -> int:
    """Count differing bits between two integers (up to `bits` wide)."""
    xor = (a ^ b) & ((1 << bits) - 1)
    return bin(xor).count('1')


def random_uint64() -> int:
    return random.getrandbits(64)


def random_key80() -> bytes:
    return random.getrandbits(80).to_bytes(10, 'big')


# ---------------------------------------------------------------------------
# Test case
# ---------------------------------------------------------------------------

class TestPresentVectors(unittest.TestCase):
    """Official PRESENT-80 test vectors from Bogdanov et al. 2007."""

    # ------------------------------------------------------------------
    # Official test vectors
    # ------------------------------------------------------------------

    def test_known_vector_1(self):
        """
        Vector 1 (all-zero plaintext, all-zero key):
          PT  = 0x0000000000000000
          Key = 0x00000000000000000000
          CT  = 0x5579C1387B228445
        """
        plaintext = 0x0000000000000000
        key       = int_to_key_bytes(0x00000000000000000000)
        expected  = 0x5579C1387B228445

        result = present_encrypt(plaintext, key)
        self.assertEqual(
            result, expected,
            f"Vector 1 FAILED: got 0x{result:016X}, expected 0x{expected:016X}"
        )

    def test_known_vector_2(self):
        """
        Vector 2 (all-zero plaintext, all-ones key):
          PT  = 0x0000000000000000
          Key = 0xFFFFFFFFFFFFFFFFFFFF
          CT  = 0xE72C46C0F5945049
        """
        plaintext = 0x0000000000000000
        key       = int_to_key_bytes(0xFFFFFFFFFFFFFFFFFFFF)
        expected  = 0xE72C46C0F5945049

        result = present_encrypt(plaintext, key)
        self.assertEqual(
            result, expected,
            f"Vector 2 FAILED: got 0x{result:016X}, expected 0x{expected:016X}"
        )

    def test_known_vector_3(self):
        """
        Vector 3 (all-ones plaintext, all-zero key):
          PT  = 0xFFFFFFFFFFFFFFFF
          Key = 0x00000000000000000000
          CT  = 0xA112FFC72F68417B
        """
        plaintext = 0xFFFFFFFFFFFFFFFF
        key       = int_to_key_bytes(0x00000000000000000000)
        expected  = 0xA112FFC72F68417B

        result = present_encrypt(plaintext, key)
        self.assertEqual(
            result, expected,
            f"Vector 3 FAILED: got 0x{result:016X}, expected 0x{expected:016X}"
        )

    def test_known_vector_4(self):
        """
        Vector 4 (all-ones plaintext, all-ones key):
          PT  = 0xFFFFFFFFFFFFFFFF
          Key = 0xFFFFFFFFFFFFFFFFFFFF
          CT  = 0x3333DCD3213210D2
        """
        plaintext = 0xFFFFFFFFFFFFFFFF
        key       = int_to_key_bytes(0xFFFFFFFFFFFFFFFFFFFF)
        expected  = 0x3333DCD3213210D2

        result = present_encrypt(plaintext, key)
        self.assertEqual(
            result, expected,
            f"Vector 4 FAILED: got 0x{result:016X}, expected 0x{expected:016X}"
        )

    # ------------------------------------------------------------------
    # Decryption vector checks (inverse of the above)
    # ------------------------------------------------------------------

    def test_decrypt_vector_1(self):
        """Decrypt Vector 1 ciphertext back to all-zero plaintext."""
        ciphertext = 0x5579C1387B228445
        key        = int_to_key_bytes(0x00000000000000000000)
        expected   = 0x0000000000000000

        result = present_decrypt(ciphertext, key)
        self.assertEqual(
            result, expected,
            f"Decrypt Vector 1 FAILED: got 0x{result:016X}"
        )

    def test_decrypt_vector_2(self):
        """Decrypt Vector 2 ciphertext back to all-zero plaintext."""
        ciphertext = 0xE72C46C0F5945049
        key        = int_to_key_bytes(0xFFFFFFFFFFFFFFFFFFFF)
        expected   = 0x0000000000000000

        result = present_decrypt(ciphertext, key)
        self.assertEqual(
            result, expected,
            f"Decrypt Vector 2 FAILED: got 0x{result:016X}"
        )

    def test_decrypt_vector_3(self):
        """Decrypt Vector 3 ciphertext back to all-ones plaintext."""
        ciphertext = 0xA112FFC72F68417B
        key        = int_to_key_bytes(0x00000000000000000000)
        expected   = 0xFFFFFFFFFFFFFFFF

        result = present_decrypt(ciphertext, key)
        self.assertEqual(
            result, expected,
            f"Decrypt Vector 3 FAILED: got 0x{result:016X}"
        )

    def test_decrypt_vector_4(self):
        """Decrypt Vector 4 ciphertext back to all-ones plaintext."""
        ciphertext = 0x3333DCD3213210D2
        key        = int_to_key_bytes(0xFFFFFFFFFFFFFFFFFFFF)
        expected   = 0xFFFFFFFFFFFFFFFF

        result = present_decrypt(ciphertext, key)
        self.assertEqual(
            result, expected,
            f"Decrypt Vector 4 FAILED: got 0x{result:016X}"
        )

    # ------------------------------------------------------------------
    # Round-trip test (encrypt then decrypt = identity)
    # ------------------------------------------------------------------

    def test_roundtrip(self):
        """
        Encrypt then decrypt gives back the original plaintext.
        Runs 100 random (plaintext, key) pairs.
        """
        random.seed(42)  # Deterministic for reproducibility
        num_tests = 100
        failures = []

        for i in range(num_tests):
            pt  = random_uint64()
            key = random_key80()

            ct        = present_encrypt(pt, key)
            recovered = present_decrypt(ct, key)

            if recovered != pt:
                failures.append(
                    f"Test {i}: PT=0x{pt:016X} Key={key.hex()} "
                    f"CT=0x{ct:016X} Recovered=0x{recovered:016X}"
                )

        self.assertEqual(
            len(failures), 0,
            f"Round-trip failed on {len(failures)}/{num_tests} cases:\n" +
            "\n".join(failures[:5])
        )

    # ------------------------------------------------------------------
    # Avalanche effect test
    # ------------------------------------------------------------------

    def test_avalanche(self):
        """
        Flip exactly 1 bit in the plaintext and check that approximately
        50% of output bits change (avalanche effect).

        For a good cipher, the expected bit-flip rate is 0.5 (± some noise).
        We test 64 single-bit flips and require:
          - Mean bit-flip rate between 0.40 and 0.60
          - Every single flip causes at least 10 output bit changes
        """
        random.seed(0)
        key = random_key80()
        pt  = random_uint64()
        ct_base = present_encrypt(pt, key)

        flip_rates = []
        min_flips_seen = 64

        for bit in range(64):
            pt_flipped = pt ^ (1 << bit)
            ct_flipped = present_encrypt(pt_flipped, key)

            dist = hamming_distance(ct_base, ct_flipped)
            flip_rates.append(dist / 64.0)
            min_flips_seen = min(min_flips_seen, dist)

        mean_rate = statistics.mean(flip_rates)

        self.assertGreater(
            mean_rate, 0.40,
            f"Avalanche mean too low: {mean_rate:.3f} (expected ≈ 0.50)"
        )
        self.assertLess(
            mean_rate, 0.60,
            f"Avalanche mean too high: {mean_rate:.3f} (expected ≈ 0.50)"
        )
        self.assertGreater(
            min_flips_seen, 10,
            f"Worst-case bit flip count too low: {min_flips_seen} bits changed "
            f"(expected ≥ 10)"
        )

    def test_avalanche_multiple_plaintexts(self):
        """
        Avalanche test over 20 random plaintexts, checking each of the 64
        single-bit flips. Reports aggregate statistics.
        """
        random.seed(7)
        key = random_key80()
        all_rates = []

        for _ in range(20):
            pt = random_uint64()
            ct_base = present_encrypt(pt, key)
            for bit in range(64):
                ct_flip = present_encrypt(pt ^ (1 << bit), key)
                all_rates.append(hamming_distance(ct_base, ct_flip) / 64.0)

        mean_rate = statistics.mean(all_rates)
        stdev = statistics.stdev(all_rates)

        self.assertGreater(mean_rate, 0.42,
            f"Aggregate avalanche mean {mean_rate:.4f} < 0.42")
        self.assertLess(mean_rate, 0.58,
            f"Aggregate avalanche mean {mean_rate:.4f} > 0.58")
        # Standard deviation should not be too large (cipher should be consistent)
        self.assertLess(stdev, 0.20,
            f"Avalanche std dev {stdev:.4f} too high — inconsistent diffusion")

    # ------------------------------------------------------------------
    # Key sensitivity test
    # ------------------------------------------------------------------

    def test_key_sensitivity(self):
        """
        Same plaintext, 1-bit different key → completely different ciphertext.

        For every single-bit flip position in the 80-bit key:
          - The resulting ciphertext must differ from the original
          - Expected Hamming distance ≈ 32 bits (50% of 64)
          - Require at least 10 bits differ in every case
        """
        random.seed(99)
        pt      = random_uint64()
        key_int = int.from_bytes(random_key80(), 'big')
        key     = int_to_key_bytes(key_int)
        ct_base = present_encrypt(pt, key)

        all_dists = []
        worst_case = 64

        for bit in range(80):  # 80-bit key
            flipped_int = key_int ^ (1 << bit)
            flipped_key = int_to_key_bytes(flipped_int)
            ct_flipped  = present_encrypt(pt, flipped_key)

            dist = hamming_distance(ct_base, ct_flipped)
            all_dists.append(dist)
            worst_case = min(worst_case, dist)

            # Every single key-bit flip must produce a different ciphertext
            self.assertNotEqual(
                ct_base, ct_flipped,
                f"Key bit {bit} flip produced identical ciphertext! "
                f"Key={key.hex()} CT=0x{ct_base:016X}"
            )

        mean_dist = statistics.mean(all_dists)
        self.assertGreater(
            mean_dist, 24,
            f"Mean key-sensitivity Hamming distance {mean_dist:.1f} < 24 "
            f"(expected ≈ 32)"
        )
        self.assertGreater(
            worst_case, 8,
            f"Worst-case key sensitivity: only {worst_case} bits differ — "
            f"cipher is not key-sensitive enough"
        )

    def test_key_sensitivity_zero_plaintext(self):
        """
        Key sensitivity test with the all-zero plaintext (a common special case).
        1-bit key changes must still produce substantial ciphertext differences.
        """
        pt      = 0x0000000000000000
        key_int = 0x0123456789ABCDEF0123
        key     = int_to_key_bytes(key_int)
        ct_base = present_encrypt(pt, key)

        for bit in range(80):
            flipped_key = int_to_key_bytes(key_int ^ (1 << bit))
            ct_flipped  = present_encrypt(pt, flipped_key)
            dist = hamming_distance(ct_base, ct_flipped)
            self.assertGreater(
                dist, 0,
                f"Key bit {bit} flip on zero-plaintext produced no change!"
            )

    # ------------------------------------------------------------------
    # Additional edge-case tests
    # ------------------------------------------------------------------

    def test_encrypt_decrypt_all_zeros(self):
        """All-zero block with all-zero key: encrypt then decrypt = all-zeros."""
        pt  = 0x0000000000000000
        key = int_to_key_bytes(0x00000000000000000000)
        ct  = present_encrypt(pt, key)
        self.assertEqual(present_decrypt(ct, key), pt)

    def test_encrypt_decrypt_all_ones(self):
        """All-ones block with all-ones key: round-trip."""
        pt  = 0xFFFFFFFFFFFFFFFF
        key = int_to_key_bytes(0xFFFFFFFFFFFFFFFFFFFF)
        ct  = present_encrypt(pt, key)
        self.assertEqual(present_decrypt(ct, key), pt)

    def test_different_plaintexts_same_key_different_ct(self):
        """Two different plaintexts with same key must produce different ciphertexts."""
        key = int_to_key_bytes(0xDEADBEEFCAFEBABE1234)
        ct1 = present_encrypt(0x0102030405060708, key)
        ct2 = present_encrypt(0x0102030405060709, key)
        self.assertNotEqual(ct1, ct2, "Different plaintexts produced same ciphertext!")

    def test_ciphertext_is_64bit(self):
        """Ciphertext must fit in 64 bits."""
        key = random_key80()
        ct  = present_encrypt(random_uint64(), key)
        self.assertGreaterEqual(ct, 0)
        self.assertLessEqual(ct, 0xFFFFFFFFFFFFFFFF)

    def test_plaintext_is_64bit_after_decrypt(self):
        """Decrypted value must fit in 64 bits."""
        key = random_key80()
        ct  = random_uint64()
        pt  = present_decrypt(ct, key)
        self.assertGreaterEqual(pt, 0)
        self.assertLessEqual(pt, 0xFFFFFFFFFFFFFFFF)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # Verbose output when run directly
    unittest.main(verbosity=2)
