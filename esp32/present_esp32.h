/**
 * present_esp32.h
 * ESP32-optimized PRESENT-80 block cipher header
 *
 * PRESENT is a lightweight 64-bit block cipher with an 80-bit key.
 * Designed for ultra-constrained environments (RFID, sensor nodes, etc.)
 * Reference: Bogdanov et al., "PRESENT: An Ultra-Lightweight Block Cipher", CHES 2007.
 */

#ifndef PRESENT_ESP32_H
#define PRESENT_ESP32_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */

#define PRESENT_ROUNDS       31          /**< Number of rounds (spec §2) */
#define PRESENT_BLOCK_BYTES   8          /**< Block size in bytes (64 bits) */
#define PRESENT_KEY80_BYTES  10          /**< Key size in bytes  (80 bits) */

/* ------------------------------------------------------------------ */
/*  Lookup tables (declared here, defined in present_esp32.cpp)        */
/* ------------------------------------------------------------------ */

/** PRESENT sBox (4-bit → 4-bit substitution) */
extern const uint8_t PRESENT_SBOX[16];

/** PRESENT inverse sBox (used for decryption) */
extern const uint8_t PRESENT_SBOX_INV[16];

/** PRESENT pLayer bit-permutation table (64 entries, index = input bit pos) */
extern const uint8_t PRESENT_PLAYER[64];

/** PRESENT inverse pLayer (64 entries) */
extern const uint8_t PRESENT_PLAYER_INV[64];

/* ------------------------------------------------------------------ */
/*  Key-schedule storage (32 round keys of 64 bits each)               */
/* ------------------------------------------------------------------ */

/**
 * @brief Pre-computed round keys for a single PRESENT-80 instance.
 *
 * Call present80_keyschedule() once per key; reuse ks for multiple
 * encrypt/decrypt calls on the same key.
 */
typedef struct {
    uint64_t rk[PRESENT_ROUNDS + 1];   /**< Round keys K1 … K32 */
} Present80KeySchedule;

/* ------------------------------------------------------------------ */
/*  Public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * @brief Expand a 10-byte (80-bit) key into 32 round keys.
 *
 * @param key   Pointer to 10-byte key array (MSB first).
 * @param ks    Output: pre-computed round-key structure.
 */
void present80_keyschedule(const uint8_t key[PRESENT_KEY80_BYTES],
                            Present80KeySchedule *ks);

/**
 * @brief Encrypt a 64-bit plaintext block using PRESENT-80.
 *
 * @param block  64-bit plaintext.
 * @param key    10-byte (80-bit) key (MSB first).
 * @return       64-bit ciphertext.
 */
uint64_t present80_encrypt(uint64_t block, const uint8_t key[PRESENT_KEY80_BYTES]);

/**
 * @brief Decrypt a 64-bit ciphertext block using PRESENT-80.
 *
 * @param block  64-bit ciphertext.
 * @param key    10-byte (80-bit) key (MSB first).
 * @return       64-bit plaintext.
 */
uint64_t present80_decrypt(uint64_t block, const uint8_t key[PRESENT_KEY80_BYTES]);

/**
 * @brief Encrypt using a pre-computed key schedule (faster for repeated calls).
 *
 * @param block  64-bit plaintext.
 * @param ks     Pre-computed key schedule from present80_keyschedule().
 * @return       64-bit ciphertext.
 */
uint64_t present80_encrypt_ks(uint64_t block, const Present80KeySchedule *ks);

/**
 * @brief Decrypt using a pre-computed key schedule (faster for repeated calls).
 *
 * @param block  64-bit ciphertext.
 * @param ks     Pre-computed key schedule from present80_keyschedule().
 * @return       64-bit plaintext.
 */
uint64_t present80_decrypt_ks(uint64_t block, const Present80KeySchedule *ks);

#ifdef __cplusplus
}
#endif

#endif /* PRESENT_ESP32_H */
