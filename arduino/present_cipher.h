/**
 * present_cipher.h
 * PRESENT-80 Lightweight Block Cipher - Header
 *
 * Full implementation of PRESENT-80 as specified in:
 * "PRESENT: An Ultra-Lightweight Block Cipher"
 * Bogdanov et al., CHES 2007
 *
 * Block size : 64 bits
 * Key size   : 80 bits
 * Rounds     : 31
 */

#ifndef PRESENT_CIPHER_H
#define PRESENT_CIPHER_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * Constants
 * ========================================================= */

/** Number of rounds in PRESENT-80 */
#define PRESENT_ROUNDS       31

/** Number of round keys (rounds + 1 for final key addition) */
#define PRESENT_NUM_KEYS     32

/** Block size in bytes */
#define PRESENT_BLOCK_BYTES   8

/** Key size in bytes (80 bits) */
#define PRESENT_KEY_BYTES    10

/* =========================================================
 * S-Box (substitution layer, 4-bit nibble lookup)
 *
 * sBox[16]:
 * Index : 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
 * Value : C  5  6  B  9  0  A  D  3  E  F  8  4  7  1  2
 * ========================================================= */
extern const uint8_t sBox[16];

/** Inverse S-Box for decryption */
extern const uint8_t sBox_inv[16];

/**
 * pLayer permutation table.
 * P(i) = (i * 16) % 63  for i in [0..62]
 * P(63) = 63
 *
 * Maps source bit position i -> destination bit position pLayer[i].
 */
extern const uint8_t pLayer[64];

/** Inverse pLayer table (for decryption) */
extern const uint8_t pLayer_inv[64];

/* =========================================================
 * Data Structures
 * ========================================================= */

/**
 * PresentBlock - 64-bit data block
 *
 * Stored as a single 64-bit unsigned integer (big-endian semantics).
 */
typedef struct {
    uint64_t data;
} PresentBlock;

/**
 * PresentKey - holds expanded round keys
 *
 * After calling generate_round_keys(), this struct contains all
 * PRESENT_NUM_KEYS (32) round keys derived from the 80-bit master key.
 * Each round key is a 64-bit value (the leftmost 64 bits of the key
 * register at the start of each round).
 */
typedef struct {
    uint64_t round_keys[PRESENT_NUM_KEYS];  /**< K_1 .. K_32 */
} PresentKey;

/* =========================================================
 * Public API
 * ========================================================= */

/**
 * generate_round_keys
 *
 * Derives all 32 round keys from an 80-bit master key and stores
 * them in the PresentKey structure.
 *
 * @param key     Pointer to 10-byte (80-bit) master key (big-endian).
 * @param pk      Output: populated PresentKey structure.
 */
void generate_round_keys(const uint8_t key[PRESENT_KEY_BYTES],
                         PresentKey *pk);

/**
 * present_encrypt
 *
 * Encrypts a 64-bit plaintext block using PRESENT-80.
 *
 * @param plaintext   64-bit plaintext.
 * @param key         Pointer to 10-byte master key.
 * @param ciphertext  Output: 64-bit ciphertext.
 * @return            0 on success.
 */
int present_encrypt(uint64_t plaintext,
                    const uint8_t key[PRESENT_KEY_BYTES],
                    uint64_t *ciphertext);

/**
 * present_decrypt
 *
 * Decrypts a 64-bit ciphertext block using PRESENT-80.
 *
 * @param ciphertext  64-bit ciphertext.
 * @param key         Pointer to 10-byte master key.
 * @param plaintext   Output: 64-bit plaintext.
 * @return            0 on success.
 */
int present_decrypt(uint64_t ciphertext,
                    const uint8_t key[PRESENT_KEY_BYTES],
                    uint64_t *plaintext);

/**
 * present_encrypt_block
 *
 * Encrypts using pre-expanded round keys (faster if key is reused).
 *
 * @param plaintext   Input block.
 * @param pk          Pre-computed round keys.
 * @param ciphertext  Output block.
 */
void present_encrypt_block(uint64_t plaintext,
                           const PresentKey *pk,
                           uint64_t *ciphertext);

/**
 * present_decrypt_block
 *
 * Decrypts using pre-expanded round keys.
 *
 * @param ciphertext  Input block.
 * @param pk          Pre-computed round keys.
 * @param plaintext   Output block.
 */
void present_decrypt_block(uint64_t ciphertext,
                           const PresentKey *pk,
                           uint64_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* PRESENT_CIPHER_H */
