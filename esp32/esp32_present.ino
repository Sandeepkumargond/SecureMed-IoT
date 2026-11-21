/**
 * esp32_present.ino
 * ESP32 Healthcare IoT Node — PRESENT-80 Encrypted MQTT Telemetry
 *
 * Simulates ECG and Heart Rate sensor data, encrypts each reading using
 * the PRESENT-80 lightweight block cipher, and publishes the ciphertext
 * over MQTT.  Acknowledgement messages from the broker trigger decryption
 * and console print-out.
 *
 * Hardware: Any ESP32 development board (ESP-WROOM-32, ESP32-S3, etc.)
 * Libraries: WiFi (built-in), PubSubClient (Nick O'Leary)
 *
 * To install PubSubClient:
 *   Arduino IDE → Sketch → Include Library → Manage Libraries
 *   Search "PubSubClient" by Nick O'Leary → Install
 */

#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <math.h>
#include "esp_timer.h"       /* esp_timer_get_time() */
#include "esp_system.h"      /* esp_get_free_heap_size() */

/* ------------------------------------------------------------------ */
/*  Configuration constants                                             */
/* ------------------------------------------------------------------ */

/* WiFi credentials — replace with real values before deployment */
static const char* WIFI_SSID     = "YourSSID";
static const char* WIFI_PASSWORD  = "YourPassword";

/* MQTT broker */
static const char* MQTT_BROKER   = "192.168.1.100";
static const int   MQTT_PORT     = 1883;
static const char* MQTT_CLIENT_ID = "ESP32-Healthcare-Node-01";

/* MQTT topics */
static const char* TOPIC_PUB    = "healthcare/encrypted";   /* publish ciphertext */
static const char* TOPIC_SUB    = "healthcare/ack";         /* receive ACK        */

/* Publish interval (ms) */
static const uint32_t PUBLISH_INTERVAL_MS = 2000;

/* PRESENT-80 key: 80 bits = 10 bytes */
static const uint8_t PRESENT_KEY[10] = {
    0x01, 0x23, 0x45, 0x67, 0x89,
    0xAB, 0xCD, 0xEF, 0x01, 0x23
};

/* Simulated heart-rate range (bpm) */
static const int HR_MIN = 60;
static const int HR_MAX = 100;

/* ================================================================== */
/*  PRESENT-80 inline implementation                                   */
/*                                                                      */
/*  Included inline here so the sketch is self-contained               */
/*  (no dependency on external .cpp / .h in the same sketch folder     */
/*   when compiled as a plain .ino).                                   */
/* ================================================================== */

/* S-box */
static const uint8_t sBox[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};

/* Inverse S-box */
static const uint8_t sBoxInv[16] = {
    0x5, 0xE, 0xF, 0x8,
    0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3,
    0x0, 0x7, 0x9, 0xA
};

/* pLayer permutation table: PLAYER[i] = destination bit of input bit i */
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

/* Inverse pLayer */
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

/* ---- Internal helpers ---- */

static uint64_t applySBox(uint64_t block) {
    uint64_t out = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t nibble = (block >> (i * 4)) & 0xF;
        out |= ((uint64_t)sBox[nibble]) << (i * 4);
    }
    return out;
}

static uint64_t applySBoxInv(uint64_t block) {
    uint64_t out = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t nibble = (block >> (i * 4)) & 0xF;
        out |= ((uint64_t)sBoxInv[nibble]) << (i * 4);
    }
    return out;
}

static uint64_t applyPLayer(uint64_t block) {
    uint64_t out = 0;
    for (int i = 0; i < 64; i++) {
        if ((block >> i) & 1ULL)
            out |= 1ULL << pLayerTable[i];
    }
    return out;
}

static uint64_t applyPLayerInv(uint64_t block) {
    uint64_t out = 0;
    for (int i = 0; i < 64; i++) {
        if ((block >> i) & 1ULL)
            out |= 1ULL << pLayerInvTable[i];
    }
    return out;
}

/* Key schedule: fills rk[0..31] */
static void present80KeySchedule(const uint8_t key[10], uint64_t rk[32])
{
    /* Load 80-bit key: key[0] is MSB (bits 79..72) */
    uint64_t lo = 0;
    uint16_t hi = ((uint16_t)key[0] << 8) | key[1];
    for (int i = 0; i < 8; i++)
        lo = (lo << 8) | key[i + 2];

    for (int round = 1; round <= 32; round++) {
        /* Store round key = top 64 bits */
        rk[round - 1] = ((uint64_t)hi << 48) | (lo >> 16);

        /* Rotate left 61 (= right 19) on 80-bit register */
        uint16_t tmp_hi = hi;
        uint64_t tmp_lo = lo;
        hi = (uint16_t)((tmp_lo >> 3) & 0xFFFF);
        lo = ((tmp_lo & 0x7ULL) << 61)
           | ((uint64_t)tmp_hi << 45)
           | (tmp_lo >> 19);

        /* Apply sBox to top nibble (bits 79..76) */
        uint8_t top = (hi >> 12) & 0xF;
        hi = (uint16_t)((hi & 0x0FFF) | ((uint16_t)sBox[top] << 12));

        /* XOR round counter into bits [19..15] */
        lo ^= ((uint64_t)(round & 0x1F)) << 15;
    }
}

/* PRESENT-80 encrypt */
static uint64_t present80Encrypt(uint64_t block, const uint8_t key[10])
{
    uint64_t rk[32];
    present80KeySchedule(key, rk);
    for (int r = 0; r < 31; r++) {
        block ^= rk[r];
        block  = applySBox(block);
        block  = applyPLayer(block);
    }
    block ^= rk[31];
    return block;
}

/* PRESENT-80 decrypt */
static uint64_t present80Decrypt(uint64_t block, const uint8_t key[10])
{
    uint64_t rk[32];
    present80KeySchedule(key, rk);
    block ^= rk[31];
    for (int r = 30; r >= 0; r--) {
        block = applyPLayerInv(block);
        block = applySBoxInv(block);
        block ^= rk[r];
    }
    return block;
}

/* ================================================================== */
/*  Sensor simulation                                                   */
/* ================================================================== */

/**
 * Simulate an ECG sample using a composite sine-wave model.
 * Returns a value in the range 0..4095 (12-bit ADC equivalent).
 */
static uint32_t simulateECG(uint32_t time_ms)
{
    /* Fundamental frequency ~1 Hz (60 bpm baseline) */
    double t   = (double)time_ms / 1000.0;
    double ecg = 2048.0
               + 1500.0 * sin(2.0 * M_PI * 1.0 * t)      /* P-wave  */
               +  400.0 * sin(2.0 * M_PI * 2.5 * t)      /* QRS     */
               +  200.0 * sin(2.0 * M_PI * 0.5 * t);     /* T-wave  */
    /* Clamp to 12-bit ADC range */
    if (ecg < 0.0)    ecg = 0.0;
    if (ecg > 4095.0) ecg = 4095.0;
    return (uint32_t)ecg;
}

/**
 * Simulate a heart rate reading (60-100 bpm), drifting slowly over time.
 */
static uint16_t simulateHeartRate(uint32_t time_ms)
{
    double t  = (double)time_ms / 1000.0;
    double hr = 80.0 + 20.0 * sin(2.0 * M_PI * 0.05 * t); /* slow drift */
    if (hr < HR_MIN) hr = HR_MIN;
    if (hr > HR_MAX) hr = HR_MAX;
    return (uint16_t)hr;
}

/**
 * Pack sensor readings into a 64-bit block:
 *   bits [63:32] = ECG value  (32-bit, only lower 12 bits significant)
 *   bits [31:16] = Heart Rate (16-bit, bpm)
 *   bits [15: 0] = Timestamp low 16 bits (ms mod 65536)
 */
static uint64_t packSensorBlock(uint32_t ecg, uint16_t hr, uint32_t time_ms)
{
    uint64_t block = ((uint64_t)ecg << 32)
                   | ((uint64_t)hr  << 16)
                   | (uint64_t)(time_ms & 0xFFFF);
    return block;
}

/* ================================================================== */
/*  Utilities                                                           */
/* ================================================================== */

/** Convert a uint64_t to a 16-character hex string (null-terminated). */
static void uint64ToHex(uint64_t val, char buf[17])
{
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 15; i >= 0; i--) {
        buf[i] = hex[val & 0xF];
        val >>= 4;
    }
    buf[16] = '\0';
}

/** Parse a 16-character hex string back to uint64_t. */
static uint64_t hexToUint64(const char *hex)
{
    uint64_t val = 0;
    for (int i = 0; i < 16; i++) {
        val <<= 4;
        char c = hex[i];
        if (c >= '0' && c <= '9') val |= (uint64_t)(c - '0');
        else if (c >= 'A' && c <= 'F') val |= (uint64_t)(c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') val |= (uint64_t)(c - 'a' + 10);
    }
    return val;
}

/* ================================================================== */
/*  MQTT and WiFi objects                                               */
/* ================================================================== */

static WiFiClient   wifiClient;
static PubSubClient mqttClient(wifiClient);

/* ================================================================== */
/*  MQTT callback (called on subscribed message received)              */
/* ================================================================== */

static void mqttCallback(char *topic, byte *payload, unsigned int length)
{
    Serial.printf("\n[MQTT] Message received on topic: %s\n", topic);

    /* Copy payload to a null-terminated buffer */
    char msg[64] = {0};
    if (length >= sizeof(msg)) length = sizeof(msg) - 1;
    memcpy(msg, payload, length);
    msg[length] = '\0';

    Serial.printf("[MQTT] Payload: %s\n", msg);

    /* If the payload is "ack", simply acknowledge */
    if (strcmp(msg, "ack") == 0) {
        Serial.println("[ACK] Broker acknowledged last transmission.");
        return;
    }

    /* If payload looks like a 16-char hex ciphertext, decrypt and print */
    if (length == 16) {
        uint64_t cipher = hexToUint64(msg);
        int64_t  t0     = esp_timer_get_time();
        uint64_t plain  = present80Decrypt(cipher, PRESENT_KEY);
        int64_t  t1     = esp_timer_get_time();

        uint32_t ecg_dec = (uint32_t)(plain >> 32) & 0xFFFFF;
        uint16_t hr_dec  = (uint16_t)((plain >> 16) & 0xFFFF);
        uint16_t ts_dec  = (uint16_t)(plain & 0xFFFF);

        Serial.println("[ACK] Decrypted broker echo:");
        Serial.printf("  ECG raw  : %u\n", ecg_dec);
        Serial.printf("  Heart Rate: %u bpm\n", hr_dec);
        Serial.printf("  Timestamp (low 16-bit): %u ms\n", ts_dec);
        Serial.printf("  Decrypt time: %lld µs\n", t1 - t0);
    }
}

/* ================================================================== */
/*  WiFi and MQTT connection helpers                                    */
/* ================================================================== */

static void connectWiFi()
{
    Serial.printf("\n[WiFi] Connecting to '%s'", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print('.');
        if (millis() - start > 30000) {
            Serial.println("\n[WiFi] Connection timeout. Restarting...");
            ESP.restart();
        }
    }
    Serial.printf("\n[WiFi] Connected! IP: %s\n",
                  WiFi.localIP().toString().c_str());
}

static void connectMQTT()
{
    while (!mqttClient.connected()) {
        Serial.printf("[MQTT] Connecting to broker %s:%d ... ",
                      MQTT_BROKER, MQTT_PORT);
        if (mqttClient.connect(MQTT_CLIENT_ID)) {
            Serial.println("OK");
            mqttClient.subscribe(TOPIC_SUB);
            Serial.printf("[MQTT] Subscribed to '%s'\n", TOPIC_SUB);
        } else {
            Serial.printf("failed (state=%d). Retry in 5 s\n",
                          mqttClient.state());
            delay(5000);
        }
    }
}

/* ================================================================== */
/*  Arduino setup() and loop()                                          */
/* ================================================================== */

void setup()
{
    Serial.begin(115200);
    while (!Serial) { delay(10); }

    Serial.println("\n==============================");
    Serial.println(" ESP32 Healthcare PRESENT-80 ");
    Serial.println("==============================");
    Serial.printf("[Heap] Free at startup: %u bytes\n",
                  esp_get_free_heap_size());

    connectWiFi();

    mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
    mqttClient.setCallback(mqttCallback);
    connectMQTT();

    Serial.println("[Setup] Ready. Publishing every 2 seconds.\n");
}

static uint32_t lastPublishMs = 0;

void loop()
{
    /* Keep MQTT alive */
    if (!mqttClient.connected()) {
        connectMQTT();
    }
    mqttClient.loop();

    uint32_t now = millis();
    if (now - lastPublishMs >= PUBLISH_INTERVAL_MS) {
        lastPublishMs = now;

        /* 1. Simulate sensors */
        uint32_t ecg = simulateECG(now);
        uint16_t hr  = simulateHeartRate(now);

        /* 2. Pack into 64-bit block */
        uint64_t plainBlock = packSensorBlock(ecg, hr, now);

        /* 3. Encrypt */
        int64_t  t0     = esp_timer_get_time();
        uint64_t cipher = present80Encrypt(plainBlock, PRESENT_KEY);
        int64_t  t1     = esp_timer_get_time();
        int64_t  enc_us = t1 - t0;

        /* 4. Format as hex string */
        char hexStr[17];
        uint64ToHex(cipher, hexStr);

        /* 5. Publish */
        bool ok = mqttClient.publish(TOPIC_PUB, hexStr);

        /* 6. Debug output */
        Serial.println("------------------------------------");
        Serial.printf("[%7u ms] Sensor Reading\n", now);
        Serial.printf("  ECG raw     : %u  (0-4095)\n", ecg);
        Serial.printf("  Heart Rate  : %u bpm\n", hr);
        Serial.printf("  Plain block : 0x%016llX\n", plainBlock);
        Serial.printf("  Cipher      : 0x%s\n", hexStr);
        Serial.printf("  Encrypt time: %lld µs\n", enc_us);
        Serial.printf("  MQTT publish: %s\n", ok ? "OK" : "FAIL");
        Serial.printf("  Free heap   : %u bytes\n", esp_get_free_heap_size());
    }
}
