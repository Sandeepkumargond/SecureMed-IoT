/**
 * sensor_encrypt.ino
 * PRESENT-80 IoT Healthcare Sensor Encryption – Arduino Sketch
 *
 * Simulates ECG and Heart Rate sensor readings, packs them into a
 * 64-bit block, and encrypts with PRESENT-80.
 *
 * Data packing layout (64 bits):
 *   bits [63:32] - ECG simulated value  (32 bits, scaled sin wave)
 *   bits [31:16] - Heart Rate in bpm    (16 bits, range 60-100)
 *   bits [15:0]  - Timestamp LSBs       (16 bits, millis() & 0xFFFF)
 *
 * Serial output at 9600 baud.
 */

extern "C" {
#include "present_cipher.h"
}

#include <math.h>

/* =========================================================
 * Hardware-independent SRAM measurement (AVR Arduino)
 * ========================================================= */
#ifdef __AVR__
#include <avr/pgmspace.h>

/** Returns approximate free SRAM in bytes on AVR platforms. */
static int freeRam()
{
    extern int __heap_start, *__brkval;
    int v;
    return (int)&v - (__brkval == 0 ? (int)&__heap_start : (int)__brkval);
}
#else
/** Stub for non-AVR platforms (ESP32, etc.) */
static int freeRam()
{
#if defined(ESP32) || defined(ESP8266)
    return (int)esp_get_free_heap_size();
#else
    return -1;  /* Unknown platform */
#endif
}
#endif

/* =========================================================
 * PRESENT-80 Key (80 bits = 10 bytes)
 * Hardcoded for demonstration. In production, use secure storage.
 * ========================================================= */
static const uint8_t PRESENT_KEY[PRESENT_KEY_BYTES] = {
    0x01, 0x23, 0x45, 0x67, 0x89,
    0xAB, 0xCD, 0xEF, 0x01, 0x23
};

/* =========================================================
 * Pre-expanded round keys (computed once in setup)
 * ========================================================= */
static PresentKey g_pk;

/* =========================================================
 * ECG simulation state
 * ========================================================= */
static float ecg_phase = 0.0f;         /**< Phase accumulator for sin wave */
static const float ECG_FREQ_HZ = 1.2f; /**< ~72 bpm carrier frequency */
static const float ECG_AMPLITUDE = 2047.5f; /**< ADC mid-scale (12-bit) */
static const float ECG_OFFSET    = 2047.5f; /**< ADC mid-scale offset */

/* =========================================================
 * Utility: print a 64-bit value as a 16-character hex string
 * ========================================================= */
static void printHex64(uint64_t val)
{
    /* Print MSB first */
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

/* =========================================================
 * Sensor simulation helpers
 * ========================================================= */

/**
 * simulate_ecg
 *
 * Generates a synthesized ECG-like signal using a sum of sinusoids.
 * Models the dominant frequency component (QRS complex).
 *
 * @param phase_rad  Current phase in radians.
 * @return           Simulated ADC reading in range [0, 4095].
 */
static uint32_t simulate_ecg(float phase_rad)
{
    /* Primary QRS wave */
    float sig = sinf(phase_rad) * ECG_AMPLITUDE;
    /* Add harmonics for more realistic shape */
    sig += sinf(phase_rad * 3.0f) * (ECG_AMPLITUDE * 0.1f);
    sig += sinf(phase_rad * 5.0f) * (ECG_AMPLITUDE * 0.05f);
    /* Offset to positive range */
    sig += ECG_OFFSET;
    /* Clamp and return */
    if (sig < 0.0f)    sig = 0.0f;
    if (sig > 4095.0f) sig = 4095.0f;
    return (uint32_t)sig;
}

/**
 * simulate_heart_rate
 *
 * Returns a pseudo-random heart rate between 60 and 100 bpm,
 * slowly drifting to simulate realistic variation.
 *
 * @return  Heart rate in bpm (60-100).
 */
static uint16_t simulate_heart_rate()
{
    /* Use a slow random walk bounded in [60, 100] */
    static int16_t hr = 72;
    static uint8_t drift_ctr = 0;

    drift_ctr++;
    if (drift_ctr >= 5) {
        drift_ctr = 0;
        int8_t delta = (int8_t)(random(-3, 4));  /* -3 to +3 */
        hr += delta;
        if (hr < 60) hr = 60;
        if (hr > 100) hr = 100;
    }
    return (uint16_t)hr;
}

/* =========================================================
 * Setup
 * ========================================================= */
void setup()
{
    Serial.begin(9600);
    while (!Serial) { /* Wait for USB serial on Leonardo/32u4 */ }

    Serial.println(F("=== PRESENT-80 Healthcare Sensor Encryption ==="));
    Serial.print(F("Free SRAM before key expand: "));
    Serial.print(freeRam());
    Serial.println(F(" bytes"));

    /* Pre-expand round keys once */
    unsigned long t0 = micros();
    generate_round_keys(PRESENT_KEY, &g_pk);
    unsigned long t1 = micros();

    Serial.print(F("Key schedule time: "));
    Serial.print(t1 - t0);
    Serial.println(F(" us"));

    Serial.print(F("Free SRAM after key expand:  "));
    Serial.print(freeRam());
    Serial.println(F(" bytes"));
    Serial.println();

    /* Seed Arduino PRNG with floating analog noise */
    randomSeed(analogRead(A1) ^ (analogRead(A2) << 4));
}

/* =========================================================
 * Main Loop
 * ========================================================= */
void loop()
{
    /* ---- 1. Read / simulate sensors ---- */

    /* Advance ECG phase (called at 1 Hz, ECG_FREQ_HZ cycles per second) */
    ecg_phase += (2.0f * M_PI * ECG_FREQ_HZ);  /* 1 second step */
    if (ecg_phase > 2.0f * M_PI * 1000.0f) {
        ecg_phase -= 2.0f * M_PI * 1000.0f;    /* prevent float overflow */
    }

    uint32_t ecg_val     = simulate_ecg(ecg_phase);
    uint16_t heart_rate  = simulate_heart_rate();
    uint16_t timestamp   = (uint16_t)(millis() & 0xFFFF);

    /* ---- 2. Pack into 64-bit plaintext block ---- */
    uint64_t plaintext = ((uint64_t)ecg_val    << 32) |
                         ((uint64_t)heart_rate << 16) |
                         ((uint64_t)timestamp);

    /* ---- 3. Encrypt ---- */
    uint64_t ciphertext = 0;
    unsigned long enc_start = micros();
    present_encrypt_block(plaintext, &g_pk, &ciphertext);
    unsigned long enc_end   = micros();
    unsigned long enc_us    = enc_end - enc_start;

    /* ---- 4. Print results ---- */
    Serial.println(F("--- Sensor Frame ---"));

    Serial.print(F("  ECG raw (12-bit ADC) : "));
    Serial.println(ecg_val);

    Serial.print(F("  Heart Rate (bpm)     : "));
    Serial.println(heart_rate);

    Serial.print(F("  Timestamp LSBs (ms)  : "));
    Serial.println(timestamp);

    Serial.print(F("  Plaintext  [hex]     : "));
    printHex64(plaintext);
    Serial.println();

    Serial.print(F("  Ciphertext [hex]     : "));
    printHex64(ciphertext);
    Serial.println();

    Serial.print(F("  Encryption time      : "));
    Serial.print(enc_us);
    Serial.println(F(" us"));

    Serial.print(F("  Free SRAM            : "));
    Serial.print(freeRam());
    Serial.println(F(" bytes"));

    /* ---- 5. Optionally verify by decrypting ---- */
    uint64_t decrypted = 0;
    present_decrypt_block(ciphertext, &g_pk, &decrypted);
    Serial.print(F("  Decrypted  [hex]     : "));
    printHex64(decrypted);
    Serial.print(F("  ["));
    Serial.print((decrypted == plaintext) ? F("OK") : F("FAIL"));
    Serial.println(F("]"));

    Serial.println();

    delay(1000);
}
