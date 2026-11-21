/**
 * present_cipher.c
 * PRESENT-80 Lightweight Block Cipher - Full Implementation
 *
 * Specification:
 *   "PRESENT: An Ultra-Lightweight Block Cipher"
 *   Bogdanov et al., CHES 2007
 *
 * Block size : 64 bits
 * Key size   : 80 bits (10 bytes)
 * Rounds     : 31
 *
 * Structure per round:
 *   state = addRoundKey(state, K_i)
 *   state = sBoxLayer(state)
 *   state = pLayer(state)
 * Final:
 *   state = addRoundKey(state, K_32)
 */

#include "present_cipher.h"

/* =========================================================
 * S-Box and inverse
 * ========================================================= */

/** Forward S-Box (4-bit nibble substitution) */
const uint8_t sBox[16] = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

/**
 * Inverse S-Box for decryption.
 * sBox_inv[sBox[x]] == x for all x in [0..15].
 *
 * Index : 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
 * Value : 5  E  F  8  C  1  2  D  B  4  6  3  0  7  9  A
 */
const uint8_t sBox_inv[16] = {
    0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA
};

/* =========================================================
 * pLayer permutation table
 *
 * Bit permutation P(i) = (i * 16) % 63 for i in [0..62],
 * P(63) = 63.
 *
 * pLayer[i] = destination of source bit i.
 * ========================================================= */
const uint8_t pLayer[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,
     2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,
     6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
};

/**
 * Inverse pLayer - maps destination bit back to source bit.
 * pLayer_inv[pLayer[i]] == i for all i in [0..63].
 */
const uint8_t pLayer_inv[64] = {
     0,  4,  8, 12, 16, 20, 24, 28,
    32, 36, 40, 44, 48, 52, 56, 60,
     1,  5,  9, 13, 17, 21, 25, 29,
    33, 37, 41, 45, 49, 53, 57, 61,
     2,  6, 10, 14, 18, 22, 26, 30,
    34, 38, 42, 46, 50, 54, 58, 62,
     3,  7, 11, 15, 19, 23, 27, 31,
    35, 39, 43, 47, 51, 55, 59, 63
};

/* =========================================================
 * Internal helper functions
 * ========================================================= */

/**
 * apply_sbox_layer
 *
 * Applies the 4-bit S-Box to each of the 16 nibbles of the 64-bit
 * state block (nibble 0 = bits 63..60, nibble 15 = bits 3..0).
 *
 * @param state   Input 64-bit state.
 * @param box     Pointer to 16-entry S-Box table.
 * @return        Substituted 64-bit state.
 */
static uint64_t apply_sbox_layer(uint64_t state, const uint8_t *box)
{
    uint64_t result = 0;
    int i;
    for (i = 0; i < 16; i++) {
        /* Extract nibble i from MSB side: nibble 0 = bits 63..60 */
        uint8_t nibble = (uint8_t)((state >> (60 - i * 4)) & 0xF);
        uint8_t sub    = box[nibble];
        result |= ((uint64_t)sub << (60 - i * 4));
    }
    return result;
}

/**
 * apply_player
 *
 * Applies the bit permutation layer to the 64-bit state.
 * Source bit i is moved to destination bit perm[i].
 *
 * Bit numbering: bit 63 = MSB, bit 0 = LSB.
 *
 * @param state   Input 64-bit state.
 * @param perm    Pointer to 64-entry permutation table.
 * @return        Permuted 64-bit state.
 */
static uint64_t apply_player(uint64_t state, const uint8_t *perm)
{
    uint64_t result = 0;
    int i;
    for (i = 0; i < 64; i++) {
        /* Extract source bit i (bit i = (state >> i) & 1) */
        uint64_t bit = (state >> i) & 1ULL;
        /* Place it at destination perm[i] */
        result |= (bit << perm[i]);
    }
    return result;
}

/* =========================================================
 * Key Schedule
 * ========================================================= */

/**
 * generate_round_keys
 *
 * Generates all 32 round keys for PRESENT-80 from a 10-byte master key.
 *
 * Key register: 80 bits stored as two values:
 *   key_high = bits 79..64 (16-bit), key_low = bits 63..0 (64-bit)
 *
 * Key Schedule per round i (1-based):
 *   1. K_i = leftmost 64 bits of key register  → stored as round_keys[i-1]
 *   2. [key_high|key_low] = [key_high|key_low] <<< 61  (rotate left 61 bits)
 *      Equivalently: rotate right by 19 bits over 80 bits.
 *   3. key_high[79..76] = sBox[key_high[79..76]]  (top 4 bits through S-Box)
 *   4. key_low[19..15] ^= round_counter  (XOR bits 19..15 with 5-bit i)
 *
 * @param key   Pointer to 10-byte master key (big-endian, byte[0] = MSB).
 * @param pk    Output PresentKey structure populated with 32 round keys.
 */
void generate_round_keys(const uint8_t key[PRESENT_KEY_BYTES],
                         PresentKey *pk)
{
    /* Load 80-bit key into two registers:
     * key_high: bits 79..64 (upper 16 bits)
     * key_low:  bits 63..0  (lower 64 bits)
     */
    uint16_t key_high;
    uint64_t key_low;
    int i;

    /* Big-endian load from byte array */
    key_high = ((uint16_t)key[0] << 8) | (uint16_t)key[1];
    key_low  = ((uint64_t)key[2] << 56) |
               ((uint64_t)key[3] << 48) |
               ((uint64_t)key[4] << 40) |
               ((uint64_t)key[5] << 32) |
               ((uint64_t)key[6] << 24) |
               ((uint64_t)key[7] << 16) |
               ((uint64_t)key[8] <<  8) |
               ((uint64_t)key[9]);

    for (i = 1; i <= PRESENT_NUM_KEYS; i++) {
        /* Step 1: Extract round key = leftmost 64 bits of key register */
        pk->round_keys[i - 1] = ((uint64_t)key_high << 48) |
                                  (key_low >> 16);

        if (i == PRESENT_NUM_KEYS) break;  /* No more schedule needed */

        /* Step 2: Rotate the 80-bit register left by 61 bits
         *         (equivalently right by 19 bits).
         *
         * New bit layout after rotate left 61 on [key_high(79..64)|key_low(63..0)]:
         *   new_bit[j] = old_bit[(j - 61 + 80) % 80]
         *
         * We compute by splitting the 80-bit value across two registers,
         * doing a 61-bit left rotation:
         *
         * Rotate left 61 = rotate right 19 on 80-bit value.
         * Easier: rotate right 19.
         *   new_low  bits [63:0]  = bits [82:19] of original extended
         *   new_high bits [79:64] = bits [98:84] ... wrap-around
         *
         * Concrete approach:
         *   Build a 128-bit (conceptual) value, extract upper 80 bits
         *   after shifting.
         *
         * Let full = (uint128) key_high << 64 | key_low  (80-bit value in low 80 bits)
         * rotate right 19:
         *   rotated = (full >> 19) | ((full & ((1<<19)-1)) << 61)
         * Since we have no uint128, we do it manually with 16+64 split.
         */
        {
            /* Rotate right 19 on 80-bit register:
             *   key_high occupies bits [79:64], key_low occupies bits [63:0]
             *
             * After rotate right 19:
             *   new[79:61] = old[18:0]  = key_low[18:0]   (19 bits from bottom)
             *   new[60:0]  = old[79:19]                   (61 bits from top)
             *
             * new_high = bits [79:64] = old[18:3] = key_low[18:3] (16 bits)
             * new_low  = bits [63:0]  = {old[2:0], old[79:64], old[63:19]}
             *                         = {key_low[2:0], key_high[15:0], key_low[63:19]}
             */
            uint16_t new_key_high = (uint16_t)((key_low >> 3) & 0xFFFF);
            uint64_t new_key_low  = ((uint64_t)(key_low & 0x7) << 61) |
                                    ((uint64_t)key_high         << 45) |
                                    (key_low >> 19);

            key_high = new_key_high;
            key_low  = new_key_low;
        }

        /* Step 3: Apply S-Box to top 4 bits of key register (bits 79..76) */
        {
            uint8_t top_nibble = (key_high >> 12) & 0xF;
            top_nibble = sBox[top_nibble];
            key_high = (key_high & 0x0FFF) | ((uint16_t)top_nibble << 12);
        }

        /* Step 4: XOR round counter into bits 19..15 of key register
         * Bit 19 of full register = bit 19 of key_low (since key_low holds bits 63..0)
         * bits 19..15 = key_low[19:15]
         */
        {
            uint8_t round_ctr = (uint8_t)i & 0x1F;  /* 5-bit round counter */
            key_low ^= ((uint64_t)round_ctr << 15);
        }
    }
}

/* =========================================================
 * Core Encryption / Decryption
 * ========================================================= */

/**
 * present_encrypt_block
 *
 * Encrypts a 64-bit block using pre-computed round keys.
 * 31 rounds of: addRoundKey -> sBoxLayer -> pLayer
 * Final: addRoundKey with K_32
 *
 * @param plaintext   64-bit input.
 * @param pk          Pre-computed round keys.
 * @param ciphertext  64-bit output.
 */
void present_encrypt_block(uint64_t plaintext,
                           const PresentKey *pk,
                           uint64_t *ciphertext)
{
    uint64_t state = plaintext;
    int round;

    for (round = 0; round < PRESENT_ROUNDS; round++) {
        /* 1. addRoundKey */
        state ^= pk->round_keys[round];
        /* 2. sBoxLayer */
        state = apply_sbox_layer(state, sBox);
        /* 3. pLayer */
        state = apply_player(state, pLayer);
    }

    /* Final key addition (round 32 / K_32) */
    state ^= pk->round_keys[PRESENT_ROUNDS];

    *ciphertext = state;
}

/**
 * present_decrypt_block
 *
 * Decrypts a 64-bit block using pre-computed round keys.
 * Inverse operations applied in reverse order:
 *   Final: addRoundKey with K_32
 *   For round = 31 downto 1:
 *     inv_pLayer -> inv_sBoxLayer -> addRoundKey
 *
 * @param ciphertext  64-bit input.
 * @param pk          Pre-computed round keys (same as for encryption).
 * @param plaintext   64-bit output.
 */
void present_decrypt_block(uint64_t ciphertext,
                           const PresentKey *pk,
                           uint64_t *plaintext)
{
    uint64_t state = ciphertext;
    int round;

    /* Undo final key addition */
    state ^= pk->round_keys[PRESENT_ROUNDS];

    for (round = PRESENT_ROUNDS - 1; round >= 0; round--) {
        /* Inverse pLayer */
        state = apply_player(state, pLayer_inv);
        /* Inverse sBoxLayer */
        state = apply_sbox_layer(state, sBox_inv);
        /* addRoundKey (XOR is its own inverse) */
        state ^= pk->round_keys[round];
    }

    *plaintext = state;
}

/**
 * present_encrypt
 *
 * Full encryption: expands keys then encrypts.
 *
 * @param plaintext   Input 64-bit block.
 * @param key         10-byte master key.
 * @param ciphertext  Output 64-bit ciphertext.
 * @return            0 on success, -1 on null pointer error.
 */
int present_encrypt(uint64_t plaintext,
                    const uint8_t key[PRESENT_KEY_BYTES],
                    uint64_t *ciphertext)
{
    PresentKey pk;
    if (!key || !ciphertext) return -1;
    generate_round_keys(key, &pk);
    present_encrypt_block(plaintext, &pk, ciphertext);
    return 0;
}

/**
 * present_decrypt
 *
 * Full decryption: expands keys then decrypts.
 *
 * @param ciphertext  Input 64-bit block.
 * @param key         10-byte master key.
 * @param plaintext   Output 64-bit plaintext.
 * @return            0 on success, -1 on null pointer error.
 */
int present_decrypt(uint64_t ciphertext,
                    const uint8_t key[PRESENT_KEY_BYTES],
                    uint64_t *plaintext)
{
    PresentKey pk;
    if (!key || !plaintext) return -1;
    generate_round_keys(key, &pk);
    present_decrypt_block(ciphertext, &pk, plaintext);
    return 0;
}
