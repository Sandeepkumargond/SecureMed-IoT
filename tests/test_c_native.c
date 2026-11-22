/**
 * test_c_native.c
 * Standalone native C verification of arduino/present_cipher.c
 * Proves that the exact C code written for the microcontroller
 * compiles and runs with 100% accuracy on Linux without any hardware.
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include "../arduino/present_cipher.h"

typedef struct {
    uint64_t pt;
    uint8_t key[10];
    uint64_t expected_ct;
    const char *desc;
} TestCase;

int main(void) {
    printf("============================================================\n");
    printf(" Native C Microcontroller Firmware Verification (GCC)\n");
    printf(" Testing arduino/present_cipher.c without hardware\n");
    printf("============================================================\n\n");

    TestCase tests[4] = {
        {
            0x0000000000000000ULL,
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
            0x5579C1387B228445ULL,
            "TV1: PT=0, Key=0"
        },
        {
            0x0000000000000000ULL,
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            0xE72C46C0F5945049ULL,
            "TV2: PT=0, Key=All-Ones"
        },
        {
            0xFFFFFFFFFFFFFFFFULL,
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
            0xA112FFC72F68417BULL,
            "TV3: PT=All-Ones, Key=0"
        },
        {
            0xFFFFFFFFFFFFFFFFULL,
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            0x3333DCD3213210D2ULL,
            "TV4: PT=All-Ones, Key=All-Ones"
        }
    };

    int passed = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t ct = 0;
        uint64_t recovered_pt = 0;

        present_encrypt(tests[i].pt, tests[i].key, &ct);
        present_decrypt(ct, tests[i].key, &recovered_pt);

        int enc_ok = (ct == tests[i].expected_ct);
        int dec_ok = (recovered_pt == tests[i].pt);

        printf("[%s]\n", tests[i].desc);
        printf("  Plaintext : 0x%016" PRIX64 "\n", tests[i].pt);
        printf("  Ciphertext: 0x%016" PRIX64 " (Expected: 0x%016" PRIX64 ") -> %s\n",
               ct, tests[i].expected_ct, enc_ok ? "PASS [✓]" : "FAIL [✗]");
        printf("  Decrypted : 0x%016" PRIX64 " -> %s\n\n",
               recovered_pt, dec_ok ? "PASS [✓]" : "FAIL [✗]");

        if (enc_ok && dec_ok) passed++;
    }

    // Benchmark 100,000 encryptions
    printf("--- Benchmarking Native C Speed (100,000 encryptions) ---\n");
    PresentKey pk;
    uint8_t sample_key[10] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0x01,0x23};
    generate_round_keys(sample_key, &pk);

    clock_t start = clock();
    uint64_t block = 0x0123456789ABCDEFULL;
    for (int i = 0; i < 100000; i++) {
        present_encrypt_block(block, &pk, &block);
    }
    clock_t end = clock();
    double total_sec = (double)(end - start) / CLOCKS_PER_SEC;
    double avg_us = (total_sec / 100000.0) * 1e6;
    double throughput_kb = ((100000.0 * 8) / (1024.0 * total_sec));

    printf("  Time for 100,000 blocks: %.4f seconds\n", total_sec);
    printf("  Average latency per block: %.3f µs\n", avg_us);
    printf("  Native C throughput: %.1f KB/sec\n\n", throughput_kb);

    if (passed == 4) {
        printf("============================================================\n");
        printf(" Result: ALL 4 OFFICIAL CHES 2007 VECTORS PASSED IN C [✓]\n");
        printf("============================================================\n");
        return 0;
    } else {
        printf("Result: SOME VECTORS FAILED [✗]\n");
        return 1;
    }
}
