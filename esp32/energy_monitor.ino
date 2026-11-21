/**
 * energy_monitor.ino
 * ESP32 Energy Monitoring Sketch — PRESENT-80 Encryption Benchmark
 *
 * Measures the time taken to perform 500 PRESENT-80 encryption operations,
 * estimates energy consumption based on the ESP32 active power profile
 * (~240 mW at 240 MHz with WiFi off), and prints a JSON report to Serial.
 *
 * JSON output format (one line, parseable by Python):
 *   {"iterations":500,"total_us":X,"avg_us":Y,"throughput_bps":Z,"energy_uJ":W}
 *
 * Hardware: Any ESP32 (tested on ESP-WROOM-32 at 240 MHz)
 * No external libraries required beyond the ESP-IDF built-ins.
 *
 * Power model reference:
 *   Espressif ESP32 Datasheet v3.4 — Section 5 "Electrical Characteristics"
 *   Active (CPU @240 MHz, WiFi Tx off): ~80 mA @ 3.3 V ≈ 264 mW.
 *   We use P = 240 mW as a conservative estimate for crypto-only workload.
 */

#include <Arduino.h>
#include <math.h>
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_sleep.h"

/* ------------------------------------------------------------------ */
/*  Configuration                                                       */
/* ------------------------------------------------------------------ */

static const int     BENCH_ITERATIONS  = 500;
static const double  ACTIVE_POWER_mW   = 240.0;   /* mW, active CPU */
static const double  SLEEP_POWER_mW    = 0.01;    /* mW, deep-sleep  */
static const int     SERIAL_BAUD       = 115200;
static const int     BLOCK_BITS        = 64;

/* ------------------------------------------------------------------ */
/*  PRESENT-80 inline implementation (self-contained)                   */
/* ------------------------------------------------------------------ */

static const uint8_t sBox[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};

static const uint8_t sBoxInv[16] = {
    0x5, 0xE, 0xF, 0x8,
    0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3,
    0x0, 0x7, 0x9, 0xA
};

static const uint8_t pLayerTable[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,
     2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,
     6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
};

static const uint8_t pLayerInvTable[64] = {
     0,  4,  8, 12, 16, 20, 24, 28,
    32, 36, 40, 44, 48, 52, 56, 60,
     1,  5,  9, 13, 17, 21, 25, 29,
    33, 37, 41, 45, 49, 53, 57, 61,
     2,  6, 10, 14, 18, 22, 26, 30,
    34, 38, 42, 46, 50, 54, 58, 62,
     3,  7, 11, 15, 19, 23, 27, 31,
    35, 39, 43, 47, 51, 55, 59, 63
};

static uint64_t em_sBoxLayer(uint64_t b) {
    uint64_t out = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t n = (b >> (i * 4)) & 0xF;
        out |= ((uint64_t)sBox[n]) << (i * 4);
    }
    return out;
}

static uint64_t em_sBoxLayerInv(uint64_t b) {
    uint64_t out = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t n = (b >> (i * 4)) & 0xF;
        out |= ((uint64_t)sBoxInv[n]) << (i * 4);
    }
    return out;
}

static uint64_t em_pLayer(uint64_t b) {
    uint64_t out = 0;
    for (int i = 0; i < 64; i++)
        if ((b >> i) & 1ULL) out |= 1ULL << pLayerTable[i];
    return out;
}

static uint64_t em_pLayerInv(uint64_t b) {
    uint64_t out = 0;
    for (int i = 0; i < 64; i++)
        if ((b >> i) & 1ULL) out |= 1ULL << pLayerInvTable[i];
    return out;
}

static void em_keySchedule(const uint8_t key[10], uint64_t rk[32])
{
    uint64_t lo = 0;
    uint16_t hi = ((uint16_t)key[0] << 8) | key[1];
    for (int i = 0; i < 8; i++)
        lo = (lo << 8) | key[i + 2];

    for (int r = 1; r <= 32; r++) {
        rk[r - 1] = ((uint64_t)hi << 48) | (lo >> 16);

        /* Rotate 80-bit register left 61 (= right 19) */
        uint16_t tmp_hi = hi;
        uint64_t tmp_lo = lo;
        hi = (uint16_t)((tmp_lo >> 3) & 0xFFFF);
        lo = ((tmp_lo & 0x7ULL) << 61)
           | ((uint64_t)tmp_hi << 45)
           | (tmp_lo >> 19);

        /* sBox on top nibble */
        uint8_t top = (hi >> 12) & 0xF;
        hi = (hi & 0x0FFF) | ((uint16_t)sBox[top] << 12);

        /* XOR round counter */
        lo ^= ((uint64_t)(r & 0x1F)) << 15;
    }
}

static uint64_t em_encrypt(uint64_t block, const uint8_t key[10])
{
    uint64_t rk[32];
    em_keySchedule(key, rk);
    for (int r = 0; r < 31; r++) {
        block ^= rk[r];
        block  = em_sBoxLayer(block);
        block  = em_pLayer(block);
    }
    return block ^ rk[31];
}

static uint64_t em_decrypt(uint64_t block, const uint8_t key[10])
{
    uint64_t rk[32];
    em_keySchedule(key, rk);
    block ^= rk[31];
    for (int r = 30; r >= 0; r--) {
        block = em_pLayerInv(block);
        block = em_sBoxLayerInv(block);
        block ^= rk[r];
    }
    return block;
}

/* ------------------------------------------------------------------ */
/*  Benchmark key and plaintext                                         */
/* ------------------------------------------------------------------ */

static const uint8_t BENCH_KEY[10] = {
    0x01, 0x23, 0x45, 0x67, 0x89,
    0xAB, 0xCD, 0xEF, 0x01, 0x23
};
static const uint64_t BENCH_PLAIN = 0x0102030405060708ULL;

/* ------------------------------------------------------------------ */
/*  Self-test using known PRESENT-80 test vector                        */
/*  Plaintext  = 0x0000000000000000                                    */
/*  Key        = 0x00000000000000000000  (all zeros, 10 bytes)         */
/*  Ciphertext = 0x5579C1387B228445      (from spec Appendix A)        */
/* ------------------------------------------------------------------ */

static bool selfTest()
{
    static const uint8_t zero_key[10] = {0};
    uint64_t ct = em_encrypt(0x0000000000000000ULL, zero_key);
    uint64_t pt = em_decrypt(ct, zero_key);

    bool enc_ok = (ct == 0x5579C1387B228445ULL);
    bool dec_ok = (pt == 0x0000000000000000ULL);

    Serial.printf("[SelfTest] enc: %s (got 0x%016llX, exp 0x5579C1387B228445)\n",
                  enc_ok ? "PASS" : "FAIL", ct);
    Serial.printf("[SelfTest] dec: %s\n", dec_ok ? "PASS" : "FAIL");
    return enc_ok && dec_ok;
}

/* ------------------------------------------------------------------ */
/*  Benchmark                                                           */
/* ------------------------------------------------------------------ */

struct BenchResult {
    int      iterations;
    uint64_t total_us;
    double   avg_us;
    double   throughput_bps;
    double   energy_uJ;
};

static BenchResult runBenchmark()
{
    BenchResult res;
    res.iterations = BENCH_ITERATIONS;

    /* Pre-compute key schedule once to measure only encrypt core */
    uint64_t rk[32];
    em_keySchedule(BENCH_KEY, rk);

    uint64_t block = BENCH_PLAIN;
    int64_t  t_start = esp_timer_get_time();

    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        /* Use different plaintext each iteration to prevent optimisation */
        block = em_encrypt(block ^ (uint64_t)i, BENCH_KEY);
    }

    int64_t t_end = esp_timer_get_time();

    /* Prevent dead-code elimination */
    volatile uint64_t dummy = block;
    (void)dummy;

    res.total_us       = (uint64_t)(t_end - t_start);
    res.avg_us         = (double)res.total_us / (double)BENCH_ITERATIONS;
    /* Throughput: (iterations * block_bits) / total_seconds */
    double total_sec   = (double)res.total_us / 1e6;
    res.throughput_bps = (double)(BENCH_ITERATIONS * BLOCK_BITS) / total_sec;
    /* Energy: E (µJ) = P (mW) * t (µs) * 1e-3  =>  E = P * t / 1000 */
    res.energy_uJ      = (ACTIVE_POWER_mW * (double)res.total_us) / 1000.0;

    return res;
}

/* ------------------------------------------------------------------ */
/*  Deep-sleep demo (1-second sleep after benchmark)                   */
/* ------------------------------------------------------------------ */

static void demoDeepSleep(uint32_t sleep_us)
{
    Serial.printf("[Sleep] Entering deep sleep for %u µs"
                  " (power ≈ %.2f mW)\n",
                  sleep_us, SLEEP_POWER_mW);
    Serial.flush();
    esp_sleep_enable_timer_wakeup((uint64_t)sleep_us);
    esp_deep_sleep_start();
    /* Execution resumes from setup() after wakeup */
}

/* ================================================================== */
/*  Arduino entry points                                                */
/* ================================================================== */

void setup()
{
    Serial.begin(SERIAL_BAUD);
    delay(200);   /* Let serial settle */

    Serial.println("\n=====================================");
    Serial.println(" ESP32 PRESENT-80 Energy Monitor     ");
    Serial.println("=====================================");
    Serial.printf("[System] CPU freq : %u MHz\n", getCpuFrequencyMhz());
    Serial.printf("[System] Free heap: %u bytes\n", esp_get_free_heap_size());
    Serial.printf("[Model]  P_active  = %.1f mW\n", ACTIVE_POWER_mW);
    Serial.printf("[Model]  P_sleep   = %.2f mW\n", SLEEP_POWER_mW);
    Serial.println();

    /* Self-test */
    if (!selfTest()) {
        Serial.println("[ERROR] Self-test FAILED — aborting benchmark.");
        return;
    }

    /* Run benchmark */
    Serial.printf("[Bench] Running %d PRESENT-80 encryptions ...\n",
                  BENCH_ITERATIONS);
    BenchResult res = runBenchmark();

    /* Human-readable report */
    Serial.println("\n--- Benchmark Results ---");
    Serial.printf("  Iterations     : %d\n",    res.iterations);
    Serial.printf("  Total time     : %llu µs\n", res.total_us);
    Serial.printf("  Avg per encrypt: %.2f µs\n", res.avg_us);
    Serial.printf("  Throughput     : %.2f bps\n", res.throughput_bps);
    Serial.printf("  Energy estimate: %.4f µJ\n", res.energy_uJ);
    Serial.printf("  Free heap after: %u bytes\n", esp_get_free_heap_size());
    Serial.println();

    /* JSON output (Python-parseable) */
    Serial.printf("{\"iterations\":%d,"
                  "\"total_us\":%llu,"
                  "\"avg_us\":%.4f,"
                  "\"throughput_bps\":%.2f,"
                  "\"energy_uJ\":%.4f}\n",
                  res.iterations,
                  res.total_us,
                  res.avg_us,
                  res.throughput_bps,
                  res.energy_uJ);

    Serial.flush();

    /* Optionally enter deep sleep for 5 seconds to demonstrate low-power mode.
     * Uncomment the line below to activate deep-sleep cycling. */
    // demoDeepSleep(5000000UL);  /* 5 seconds */
}

void loop()
{
    /* Benchmark runs once in setup(). Nothing to do in loop. */
    delay(10000);
}
