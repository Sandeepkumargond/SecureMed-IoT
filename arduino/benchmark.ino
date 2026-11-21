/**
 * benchmark.ino
 * PRESENT-80 Standalone Benchmark – Arduino Sketch
 *
 * Verifies correct operation against known test vectors, then:
 *   - Benchmarks PRESENT-80 encryption  (1000 iterations)
 *   - Benchmarks PRESENT-80 decryption  (1000 iterations)
 *   - Computes throughput in bytes/sec
 *   - Reports free SRAM
 *
 * Serial output at 9600 baud.
 *
 * Known test vectors (PRESENT-80 specification):
 *   TV1: pt=0x0000000000000000, key=0x00000000000000000000
 *        ct=0x5579C1387B228445
 *
 *   TV2: pt=0xFFFFFFFFFFFFFFFF, key=0xFFFFFFFFFFFFFFFFFFFF
 *        ct=0xE72C46C0F5945049
 */

extern "C" {
#include "present_cipher.h"
}

/* =========================================================
 * freeMemory() – AVR-compatible SRAM measurement
 * ========================================================= */
#ifdef __AVR__
#include <avr/pgmspace.h>

static int freeMemory()
{
    extern int __heap_start, *__brkval;
    int v;
    return (int)&v - (__brkval == 0 ? (int)&__heap_start : (int)__brkval);
}
#else
static int freeMemory()
{
#if defined(ESP32) || defined(ESP8266)
    return (int)esp_get_free_heap_size();
#else
    return -1;
#endif
}
#endif

/* =========================================================
 * Benchmark configuration
 * ========================================================= */
#define BENCH_ITERATIONS  1000
#define BLOCK_SIZE_BYTES  8   /**< PRESENT block = 64 bits = 8 bytes */

/* =========================================================
 * Known test vectors
 * ========================================================= */
typedef struct {
    uint64_t plaintext;
    uint8_t  key[PRESENT_KEY_BYTES];
    uint64_t expected_ct;
} TestVector;

static const TestVector test_vectors[] = {
    /* TV1: all-zero plaintext, all-zero key */
    {
        0x0000000000000000ULL,
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        0x5579C1387B228445ULL
    },
    /* TV2: all-zero plaintext, all-ones key */
    {
        0x0000000000000000ULL,
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        0xE72C46C0F5945049ULL
    },
    /* TV3: all-ones plaintext, all-ones key */
    {
        0xFFFFFFFFFFFFFFFFULL,
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        0x3333DCD3213210D2ULL
    }
};
#define NUM_TEST_VECTORS  3

/* =========================================================
 * Utility: print 64-bit hex
 * ========================================================= */
static void printHex64(uint64_t val)
{
    char buf[17];
    buf[16] = '\0';
    int i;
    for (i = 15; i >= 0; i--) {
        uint8_t nibble = (uint8_t)(val & 0xF);
        buf[i] = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
        val >>= 4;
    }
    Serial.print(buf);
}

static void printHorizontalLine()
{
    Serial.println(F("--------------------------------------------"));
}

/* =========================================================
 * Verification against known test vectors
 * ========================================================= */

/**
 * run_self_tests
 *
 * Tests all known test vectors. TV3 uses round-trip (encrypt->decrypt).
 * Prints PASS/FAIL per vector.
 *
 * @return  Number of failures (0 = all passed).
 */
static int run_self_tests()
{
    int failures = 0;
    int i;

    Serial.println(F(">>> Self-Test: Known Test Vectors"));
    printHorizontalLine();

    for (i = 0; i < NUM_TEST_VECTORS; i++) {
        const TestVector *tv = &test_vectors[i];
        uint64_t ct  = 0;
        uint64_t pt2 = 0;
        PresentKey pk;

        generate_round_keys(tv->key, &pk);
        present_encrypt_block(tv->plaintext, &pk, &ct);
        present_decrypt_block(ct, &pk, &pt2);

        Serial.print(F("  TV"));
        Serial.print(i + 1);
        Serial.print(F(": pt="));
        printHex64(tv->plaintext);
        Serial.print(F("  ct="));
        printHex64(ct);

        if (i < 2) {
            /* Check against known expected ciphertext */
            bool enc_ok = (ct == tv->expected_ct);
            bool dec_ok = (pt2 == tv->plaintext);
            Serial.print(F("  ENC:"));
            Serial.print(enc_ok ? F("PASS") : F("FAIL"));
            Serial.print(F(" DEC:"));
            Serial.print(dec_ok ? F("PASS") : F("FAIL"));
            if (!enc_ok || !dec_ok) {
                failures++;
                if (!enc_ok) {
                    Serial.print(F("  expected="));
                    printHex64(tv->expected_ct);
                }
            }
        } else {
            /* TV3: round-trip only */
            bool rt_ok = (pt2 == tv->plaintext);
            Serial.print(F("  ROUND-TRIP:"));
            Serial.print(rt_ok ? F("PASS") : F("FAIL"));
            if (!rt_ok) failures++;
        }
        Serial.println();
    }

    printHorizontalLine();
    if (failures == 0) {
        Serial.println(F("  All tests PASSED."));
    } else {
        Serial.print(F("  FAILURES: "));
        Serial.println(failures);
    }
    Serial.println();
    return failures;
}

/* =========================================================
 * Benchmark helpers
 * ========================================================= */

/**
 * benchmark_encryption
 *
 * Runs BENCH_ITERATIONS encryptions using pre-expanded keys.
 * Input block cycles through pseudo-random values to defeat
 * compiler optimizations.
 *
 * @param pk             Pre-expanded round keys.
 * @param total_us_out   Output: total microseconds.
 * @param avg_us_out     Output: average microseconds per op (x100 for 2dp).
 */
static void benchmark_encryption(const PresentKey *pk,
                                 unsigned long *total_us_out,
                                 unsigned long *avg_us_out)
{
    uint64_t block = 0x0123456789ABCDEFULL;
    uint64_t ct    = 0;
    int i;

    unsigned long t_start = micros();
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        present_encrypt_block(block, pk, &ct);
        block = ct;  /* Chain outputs to prevent dead-code elimination */
    }
    unsigned long t_end = micros();

    *total_us_out = t_end - t_start;
    *avg_us_out   = (t_end - t_start) / BENCH_ITERATIONS;

    /* Prevent optimizing away ct */
    if (ct == 0xDEADBEEFDEADBEEFULL) Serial.print(F(""));
}

/**
 * benchmark_decryption
 *
 * Runs BENCH_ITERATIONS decryptions using pre-expanded keys.
 *
 * @param pk             Pre-expanded round keys.
 * @param total_us_out   Output: total microseconds.
 * @param avg_us_out     Output: average microseconds per op.
 */
static void benchmark_decryption(const PresentKey *pk,
                                 unsigned long *total_us_out,
                                 unsigned long *avg_us_out)
{
    uint64_t block = 0x5579C1387B228445ULL;  /* Start from known CT */
    uint64_t pt    = 0;
    int i;

    unsigned long t_start = micros();
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        present_decrypt_block(block, pk, &pt);
        block = pt;  /* Chain outputs */
    }
    unsigned long t_end = micros();

    *total_us_out = t_end - t_start;
    *avg_us_out   = (t_end - t_start) / BENCH_ITERATIONS;

    if (pt == 0xDEADBEEFDEADBEEFULL) Serial.print(F(""));
}

/**
 * compute_throughput_bps
 *
 * Computes bytes-per-second from iteration count, block size, and total time.
 *
 * @param iterations     Number of operations performed.
 * @param block_bytes    Bytes per operation.
 * @param total_us       Total elapsed microseconds.
 * @return               Throughput in bytes per second.
 */
static unsigned long compute_throughput_bps(unsigned long iterations,
                                            unsigned long block_bytes,
                                            unsigned long total_us)
{
    if (total_us == 0) return 0;
    /* throughput = (iterations * block_bytes * 1e6) / total_us */
    /* Use 32-bit safe arithmetic: scale down iterations first */
    unsigned long bytes_total = iterations * block_bytes;  /* 1000 * 8 = 8000 */
    /* bytes_total * 1000000 / total_us  -- careful of overflow on 32-bit AVR */
    /* Max bytes_total = 8000, so 8000 * 1000000 = 8e9 which overflows uint32 */
    /* Use 64-bit arithmetic */
    uint64_t bps = ((uint64_t)bytes_total * 1000000ULL) / (uint64_t)total_us;
    if (bps > 0xFFFFFFFFULL) bps = 0xFFFFFFFFULL;  /* Clamp to 32-bit */
    return (unsigned long)bps;
}

/* =========================================================
 * Setup – runs once
 * ========================================================= */
void setup()
{
    Serial.begin(9600);
    while (!Serial) { /* Wait for USB CDC on Leonardo/32u4 */ }

    Serial.println();
    Serial.println(F("============================================"));
    Serial.println(F("  PRESENT-80 Benchmark  – Arduino Platform  "));
    Serial.println(F("============================================"));
    Serial.print(F("  Iterations per test  : "));
    Serial.println(BENCH_ITERATIONS);
    Serial.print(F("  Block size           : "));
    Serial.print(BLOCK_SIZE_BYTES);
    Serial.println(F(" bytes (64-bit)"));
    Serial.println();

    /* ---- 1. Self-tests ---- */
    int failures = run_self_tests();
    if (failures > 0) {
        Serial.println(F("[ERROR] Self-tests failed. Aborting benchmark."));
        while (1) delay(1000);
    }

    /* ---- 2. Key schedule (use TV1 key: all zeros) ---- */
    uint8_t bench_key[PRESENT_KEY_BYTES] = {
        0x01, 0x23, 0x45, 0x67, 0x89,
        0xAB, 0xCD, 0xEF, 0x01, 0x23
    };
    PresentKey pk;

    Serial.println(F(">>> Key Schedule"));
    printHorizontalLine();
    Serial.print(F("  Key: "));
    for (int b = 0; b < PRESENT_KEY_BYTES; b++) {
        if (bench_key[b] < 0x10) Serial.print('0');
        Serial.print(bench_key[b], HEX);
    }
    Serial.println();

    unsigned long ks_start = micros();
    generate_round_keys(bench_key, &pk);
    unsigned long ks_end   = micros();
    Serial.print(F("  Key schedule time: "));
    Serial.print(ks_end - ks_start);
    Serial.println(F(" us"));
    Serial.println();

    /* ---- 3. Encryption benchmark ---- */
    Serial.println(F(">>> Encryption Benchmark"));
    printHorizontalLine();
    unsigned long enc_total_us = 0, enc_avg_us = 0;
    benchmark_encryption(&pk, &enc_total_us, &enc_avg_us);
    unsigned long enc_bps = compute_throughput_bps(BENCH_ITERATIONS,
                                                   BLOCK_SIZE_BYTES,
                                                   enc_total_us);
    Serial.print(F("  Iterations  : ")); Serial.println(BENCH_ITERATIONS);
    Serial.print(F("  Total time  : ")); Serial.print(enc_total_us); Serial.println(F(" us"));
    Serial.print(F("  Avg per op  : ")); Serial.print(enc_avg_us);   Serial.println(F(" us"));
    Serial.print(F("  Throughput  : ")); Serial.print(enc_bps);      Serial.println(F(" bytes/sec"));
    Serial.println();

    /* ---- 4. Decryption benchmark ---- */
    Serial.println(F(">>> Decryption Benchmark"));
    printHorizontalLine();
    unsigned long dec_total_us = 0, dec_avg_us = 0;
    benchmark_decryption(&pk, &dec_total_us, &dec_avg_us);
    unsigned long dec_bps = compute_throughput_bps(BENCH_ITERATIONS,
                                                   BLOCK_SIZE_BYTES,
                                                   dec_total_us);
    Serial.print(F("  Iterations  : ")); Serial.println(BENCH_ITERATIONS);
    Serial.print(F("  Total time  : ")); Serial.print(dec_total_us); Serial.println(F(" us"));
    Serial.print(F("  Avg per op  : ")); Serial.print(dec_avg_us);   Serial.println(F(" us"));
    Serial.print(F("  Throughput  : ")); Serial.print(dec_bps);      Serial.println(F(" bytes/sec"));
    Serial.println();

    /* ---- 5. Memory report ---- */
    Serial.println(F(">>> Memory Report"));
    printHorizontalLine();
    int sram_free = freeMemory();
    Serial.print(F("  Free SRAM   : "));
    if (sram_free < 0) {
        Serial.println(F("N/A (platform not supported)"));
    } else {
        Serial.print(sram_free);
        Serial.println(F(" bytes"));
    }
    Serial.println();

    /* ---- 6. Summary ---- */
    Serial.println(F("============================================"));
    Serial.println(F("             BENCHMARK COMPLETE             "));
    Serial.println(F("============================================"));
    Serial.print(F("  ENC avg: ")); Serial.print(enc_avg_us); Serial.print(F(" us  |  "));
    Serial.print(F("DEC avg: ")); Serial.print(dec_avg_us); Serial.println(F(" us"));
    Serial.print(F("  ENC tput: ")); Serial.print(enc_bps); Serial.print(F(" B/s  |  "));
    Serial.print(F("DEC tput: ")); Serial.print(dec_bps); Serial.println(F(" B/s"));
    Serial.print(F("  Free SRAM: ")); Serial.print(sram_free); Serial.println(F(" bytes"));
    Serial.println(F("============================================"));
}

/* =========================================================
 * Loop – idle after benchmark completes
 * ========================================================= */
void loop()
{
    /* Benchmark ran once in setup(). Nothing to do in loop. */
    delay(10000);
}
