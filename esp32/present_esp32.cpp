/**
 * present_esp32.cpp
 * Full PRESENT-80 block cipher implementation for ESP32
 *
 * Algorithm reference: Bogdanov et al., "PRESENT: An Ultra-Lightweight
 * Block Cipher", CHES 2007 (LNCS 4727, pp. 450-466).
 *
 * Key size:   80 bits (10 bytes)
 * Block size: 64 bits (8 bytes / uint64_t)
 * Rounds:     31
 *
 * All operations are on little-endian bit-ordering as per the PRESENT spec,
 * with the leftmost (most significant) bit of a 64-bit word being bit 63.
 */

#include "present_esp32.h"

/* ================================================================== */
/*  Lookup tables                                                       */
/* ================================================================== */

/**
 * PRESENT S-box (Table 2 in the original paper)
 * sBox[x] maps nibble x (0x0..0xF) to its 4-bit substitute.
 */
const uint8_t PRESENT_SBOX[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};

/**
 * Inverse S-box for decryption.
 * sBox_inv[sBox[x]] == x
 */
const uint8_t PRESENT_SBOX_INV[16] = {
    0x5, 0xE, 0xF, 0x8,
    0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3,
    0x0, 0x7, 0x9, 0xA
};

/**
 * PRESENT pLayer bit-permutation table (Table 3 in the paper).
 * PRESENT_PLAYER[i] = position to which bit i is moved.
 * Formula: P(i) = (i * 16) % 63 for i in {0..62},  P(63) = 63.
 */
const uint8_t PRESENT_PLAYER[64] = {
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
 * Inverse pLayer (pLayer^{-1}): maps destination bit back to its source.
 * PRESENT_PLAYER_INV[PRESENT_PLAYER[i]] == i.
 * Formula: P^{-1}(i) = (i * 4) % 63 for i in {0..62}, P^{-1}(63) = 63.
 */
const uint8_t PRESENT_PLAYER_INV[64] = {
     0,  4,  8, 12, 16, 20, 24, 28,
    32, 36, 40, 44, 48, 52, 56, 60,
     1,  5,  9, 13, 17, 21, 25, 29,
    33, 37, 41, 45, 49, 53, 57, 61,
     2,  6, 10, 14, 18, 22, 26, 30,
    34, 38, 42, 46, 50, 54, 58, 62,
     3,  7, 11, 15, 19, 23, 27, 31,
    35, 39, 43, 47, 51, 55, 59, 63
};

/* ================================================================== */
/*  Internal helper functions                                           */
/* ================================================================== */

/**
 * @brief Apply the 4-bit S-box to every nibble of a 64-bit word (16 nibbles).
 *
 * Bit 63 is the MSB (nibble 15), bit 0 is the LSB (nibble 0).
 * Each nibble is processed independently.
 */
static inline uint64_t sBoxLayer(uint64_t block)
{
    uint64_t out = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t nibble = (block >> (i * 4)) & 0xF;
        out |= ((uint64_t)PRESENT_SBOX[nibble]) << (i * 4);
    }
    return out;
}

/**
 * @brief Apply the inverse S-box to every nibble of a 64-bit word.
 */
static inline uint64_t sBoxLayerInv(uint64_t block)
{
    uint64_t out = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t nibble = (block >> (i * 4)) & 0xF;
        out |= ((uint64_t)PRESENT_SBOX_INV[nibble]) << (i * 4);
    }
    return out;
}

/**
 * @brief Apply the pLayer bit-permutation to a 64-bit word (forward).
 *
 * bit i of input → bit PRESENT_PLAYER[i] of output.
 */
static inline uint64_t pLayer(uint64_t block)
{
    uint64_t out = 0;
    for (int i = 0; i < 64; i++) {
        if ((block >> i) & 1ULL) {
            out |= 1ULL << PRESENT_PLAYER[i];
        }
    }
    return out;
}

/**
 * @brief Apply the inverse pLayer bit-permutation (used in decryption).
 *
 * bit PRESENT_PLAYER[i] of input → bit i of output.
 * Equivalently: bit j of input → bit PRESENT_PLAYER_INV[j] of output.
 */
static inline uint64_t pLayerInv(uint64_t block)
{
    uint64_t out = 0;
    for (int i = 0; i < 64; i++) {
        if ((block >> i) & 1ULL) {
            out |= 1ULL << PRESENT_PLAYER_INV[i];
        }
    }
    return out;
}

/* ================================================================== */
/*  Key Schedule  (§2.3 of PRESENT spec)                               */
/* ================================================================== */

/**
 * @brief Generate 32 round keys from an 80-bit key.
 *
 * The 80-bit key register K = k79 k78 ... k1 k0 is maintained in two
 * uint64_t words:
 *   hi: bits 79..64  (top 16 bits, stored in bits 15..0 of hi)
 *   lo: bits 63..0   (stored in a uint64_t)
 *
 * Each round key K_i = k79 k78 ... k16 (top 64 bits of register at round i).
 *
 * Key update per round r (1-indexed):
 *   1. [K] = [K <<< 61]  (rotate the 80-bit register left by 61 positions)
 *   2. K[79:76] = sBox[ K[79:76] ]  (apply sBox to topmost nibble)
 *   3. K[19:15] = K[19:15] XOR round_counter r
 */
void present80_keyschedule(const uint8_t key[PRESENT_KEY80_BYTES],
                            Present80KeySchedule *ks)
{
    /* Load 80-bit key into two registers.
     * key[0] = most significant byte (bits 79..72). */
    uint64_t lo = 0;
    uint16_t hi = 0; /* bits 79..64 */

    for (int i = 0; i < 8; i++) {
        lo = (lo << 8) | key[i + 2];
    }
    hi  = ((uint16_t)key[0] << 8) | key[1];

    /* Round keys K_1 to K_{32} */
    for (int round = 1; round <= PRESENT_ROUNDS + 1; round++) {
        /* Store current K_round = top 64 bits of key register */
        ks->rk[round - 1] = ((uint64_t)hi << 48) | (lo >> 16);

        /* ---- Key register update ---- */

        /* Step 1: rotate 80-bit register left by 61 positions.
         *
         * [hi(16) | lo(64)] shifted left by 61 means right by 19.
         * New_hi = bits [18..3] of old_lo
         * New_lo = bits [2..0] of old_lo concatenated with bits [79..19] of old key
         *        = (old_lo[2:0] << 61) | (old_hi << 45) | (old_lo >> 19)
         */
        uint16_t new_hi = (uint16_t)((lo >> 48) & 0xFFFF);
        uint64_t new_lo = ((lo & 0xFFFFFFFFFFFFULL) << 16)
                        | ((uint64_t)hi);
        /* Actually compute properly: rotate 80-bit value left by 61. */
        {
            /* Represent 80-bit key as (hi, lo) where hi occupies bits 79..64 */
            /* Rotate left 61 = rotate right 19 on 80-bit value */
            uint64_t tmp_lo = lo;
            uint16_t tmp_hi = hi;

            /* bits 79..0 as big integer: X = (hi << 64) | lo  (conceptual) */
            /* X <<< 61 on 80-bit */
            /* left-rotate by 61 == right-rotate by 19 */
            /* new_hi(16) = old bits [18..3]   = old_lo[18:3] */
            /* new_lo(64) = old bits [2..0] || old bits [79..19]
             *            = old_lo[2:0] || old_hi[15:0] || old_lo[63:19]  */
            new_hi = (uint16_t)(tmp_lo >> 48) & 0xFFFF;
            /* Bits [18..3] of old_lo → hi bits [15..0] */
            new_hi = (uint16_t)((tmp_lo >> 48) & 0xFFFF);
            /* Wait – let's be explicit about the 80-bit rotation: */
            /* 80-bit value: bit79=hi[15], bit64=hi[0], bit63=lo[63], bit0=lo[0] */
            /* Rotate left 61:  new_bit[i] = old_bit[(i - 61) mod 80] */
            /*                            = old_bit[(i + 19) mod 80]  (right 19) */
            /* new[79..19] = old[79-19+19 .. 0+19] = old[79..19]  -- no, recalc */
            /* Simpler: rotate right 19 */
            /* new_bit[i] = old_bit[(i + 19) mod 80] */
            /* new[0]  = old[19], new[60] = old[79], new[61] = old[0], new[79] = old[18] */

            /* Split: 80-bit = [hi:lo], rotate right 19 */
            /* new_lo[63..0] = old_lo[82..19]... wait that's >64 bits */
            /* Let's use bit-field arithmetic carefully: */
            /*   new_lo[63:0]  = old_lo[82:19] where bit 80+ wraps into hi */
            /* old_lo[63:19] occupies 45 bits, bits 63..19 → new_lo[44:0]  */
            /* old_hi[15:0]   occupies 16 bits → new_lo[60:45] */
            /* old_lo[18:3]   occupies 16 bits → new_hi[15:0]  */
            /* old_lo[2:0]    occupies 3  bits → new_lo[63:61] */

            new_hi = (uint16_t)((tmp_lo >> 3) & 0xFFFF);
            new_lo = ((tmp_lo & 0x7ULL) << 61)
                   | ((uint64_t)tmp_hi << 45)
                   | (tmp_lo >> 19);
        }

        hi = new_hi;
        lo = new_lo;

        /* Step 2: apply sBox to top nibble (bits 79..76) of updated register */
        uint8_t top_nibble = (hi >> 12) & 0xF;
        top_nibble = PRESENT_SBOX[top_nibble];
        hi = (uint16_t)((hi & 0x0FFF) | ((uint16_t)top_nibble << 12));

        /* Step 3: XOR round counter with bits [19..15] of key register */
        /* Bits [19..15] straddle the hi/lo boundary:
         *   bit 19 = lo bit 19
         *   bit 18 = lo bit 18
         *   ...
         *   bit 15 = lo bit 15
         * round is a 5-bit value (1..31) */
        lo ^= ((uint64_t)(round & 0x1F)) << 15;
    }
}

/* ================================================================== */
/*  PRESENT-80 Encryption                                              */
/* ================================================================== */

uint64_t present80_encrypt_ks(uint64_t block, const Present80KeySchedule *ks)
{
    /* 31 rounds: addRoundKey, sBoxLayer, pLayer */
    for (int r = 0; r < PRESENT_ROUNDS; r++) {
        block ^= ks->rk[r];         /* addRoundKey */
        block  = sBoxLayer(block);  /* sBoxLayer   */
        block  = pLayer(block);     /* pLayer       */
    }
    /* Final key whitening */
    block ^= ks->rk[PRESENT_ROUNDS];
    return block;
}

uint64_t present80_encrypt(uint64_t block, const uint8_t key[PRESENT_KEY80_BYTES])
{
    Present80KeySchedule ks;
    present80_keyschedule(key, &ks);
    return present80_encrypt_ks(block, &ks);
}

/* ================================================================== */
/*  PRESENT-80 Decryption                                              */
/* ================================================================== */

uint64_t present80_decrypt_ks(uint64_t block, const Present80KeySchedule *ks)
{
    /* Reverse order: final whitening first, then rounds in reverse */
    block ^= ks->rk[PRESENT_ROUNDS];

    for (int r = PRESENT_ROUNDS - 1; r >= 0; r--) {
        block = pLayerInv(block);     /* inverse pLayer   */
        block = sBoxLayerInv(block);  /* inverse sBoxLayer */
        block ^= ks->rk[r];          /* addRoundKey       */
    }
    return block;
}

uint64_t present80_decrypt(uint64_t block, const uint8_t key[PRESENT_KEY80_BYTES])
{
    Present80KeySchedule ks;
    present80_keyschedule(key, &ks);
    return present80_decrypt_ks(block, &ks);
}
