# Security Analysis: PRESENT-80 Lightweight Cipher for IoT Healthcare

## Table of Contents
1. [PRESENT-80 Security Level](#1-present-80-security-level)
2. [Known Cryptanalytic Attacks](#2-known-cryptanalytic-attacks)
3. [Side-Channel Vulnerability Analysis](#3-side-channel-vulnerability-analysis)
4. [Countermeasures Implemented](#4-countermeasures-implemented)
5. [Key Rotation Policy](#5-key-rotation-policy)
6. [Compliance and Standards](#6-compliance-and-standards)
7. [Risk Assessment Summary](#7-risk-assessment-summary)

---

## 1. PRESENT-80 Security Level

### 1.1 Key Space

PRESENT-80 uses an **80-bit key**, giving a theoretical brute-force complexity of:

```
2^80 = 1,208,925,819,614,629,174,706,176 possible keys
     ≈ 1.21 × 10^24 keys
```

### 1.2 Brute-Force Feasibility

Assuming a modern adversary with dedicated hardware:

| Adversary Capability | Keys/sec | Time to Exhaust 2^80 |
|--------------------|----------|--------------------|
| Single GPU (RTX 4090) | ~10^10 | ~3.8 × 10^13 years |
| Nation-state cluster (10^15 ops/sec) | 10^15 | ~3.8 × 10^8 years |
| Theoretical quantum (Grover's) | — | 2^40 ≈ 1.1 × 10^12 ops |
| NSA-scale (10^18 ops/sec estimate) | 10^18 | ~400,000 years |

```python
# From attack_simulation.py
key_bits = 80
ops_per_sec = 1e15  # nation-state adversary
years = (2**key_bits) / ops_per_sec / (3600 * 24 * 365)
# years ≈ 3.84 × 10^8  (384 million years)
```

### 1.3 Security Margin Assessment

| Attack Type | Best Known Complexity | Rounds Broken | Security Margin |
|-------------|----------------------|---------------|-----------------|
| Brute force | 2^80 | N/A | Adequate for ≤20 yr data |
| Linear cryptanalysis | 2^64 | 24 of 31 | 7 rounds margin |
| Differential cryptanalysis | 2^64 | 26 of 31 | 5 rounds margin |
| Biclique attack (theoretical) | 2^79.6 | Full 31 | Marginal reduction only |

> [!IMPORTANT]
> PRESENT-80 provides **80-bit security** against classical computers. NIST SP 800-131A Rev. 2 (2019) sets 112 bits as the minimum for new systems intended to protect data beyond 2030. Use PRESENT-128 or AES for long-lived healthcare records.

---

## 2. Known Cryptanalytic Attacks

### 2.1 Linear Cryptanalysis

**Principle**: Find a linear approximation `Σ(input bits) XOR Σ(output bits) = Σ(key bits)` that holds with probability significantly different from 1/2.

**Best known result for PRESENT**:
- Ohkuma (2009): Linear attack on 24-round PRESENT with complexity 2^64
- Full 31-round PRESENT: No sub-2^80 linear attack known

**Why PRESENT resists it**: The sBox has a maximum linear bias of 2^-2 (probability 1/4 ± 1/4). With 31 rounds and the pLayer maximising diffusion, linear trails through the full cipher have negligible bias.

```
Maximum linear approximation bias of PRESENT sBox:
  ε_max = 2^-2 (12 of 32 input-output combinations reach this)

Best 24-round linear hull probability ≈ 2^-64
Full 31-round: No distinguishing linear trail found (security confirmed)
```

**Resistance assessment**: ✅ **Full cipher secure against linear cryptanalysis**

---

### 2.2 Differential Cryptanalysis

**Principle**: Study how differences in plaintext pairs propagate through the cipher. If a differential trail has probability `p`, then `2/p` chosen-plaintext pairs recover round key material.

**Best known result for PRESENT**:
- Collard & Standaert (2007): Differential attack on 26 of 31 rounds
- Full 31-round: No differential attack below 2^80 known

**Differential probability bound**:
```
Best single-round differential probability through sBox: 2^-2
Maximum differential characteristic for 31 rounds: < 2^-80
  (conservative estimate; actual bound likely 2^-100+)
```

**pLayer's role in differential resistance**: The pLayer maximises the minimum number of active sBoxes per two rounds (branch number). With 4 active sBoxes minimum per round pair, the probability bound grows exponentially.

```
Minimum active sBoxes in a 2-round differential trail: 4
Probability per active sBox: ≤ 2^-2
Probability over 2 rounds: ≤ (2^-2)^4 = 2^-8
Probability over 31 rounds (conservative): ≤ 2^-8 × 15 = 2^-120
```

**Resistance assessment**: ✅ **Full cipher secure against differential cryptanalysis**

---

### 2.3 Algebraic Attacks

PRESENT's sBox is defined over GF(2^4). The algebraic complexity of solving the system of polynomial equations for the full 31-round cipher is estimated at 2^80 or above. No practical algebraic attack on PRESENT is known.

**Resistance assessment**: ✅ **Secure** (complexity comparable to brute force)

---

### 2.4 Slide and Rotational Attacks

Slide attacks exploit self-similarity in key schedules. PRESENT's key schedule XORs a 5-bit round counter into the key register at each round, breaking the structural regularity needed for slide attacks.

**Resistance assessment**: ✅ **Secure** (round counter breaks slide property)

---

### 2.5 Biclique Attack

The biclique technique (Bogdanov et al. 2011) reduces the effective brute-force search:
- Full PRESENT-80: complexity ~2^79.6 (marginal improvement over 2^80)

This reduction of 0.4 bits is negligible in practice.

**Resistance assessment**: ✅ **Effectively secure** (2^79.6 ≈ 2^80 for practical purposes)

---

### 2.6 Related-Key Attacks

The PRESENT key schedule is relatively simple. Under related-key models (where adversary can query with related keys), distinguishers for reduced-round PRESENT exist. However:
- In our deployment model, the adversary does **not** control the key
- Key material is provisioned once and not exposed

**Resistance assessment**: ✅ **Not applicable in deployment model**

---

### 2.7 Known-Plaintext Attack Simulation

The file `python/attack_simulation.py` demonstrates why full brute force is infeasible by exhausting a reduced 16-bit key space:

```python
def test_known_plaintext_attack(self, plaintext, ciphertext):
    """Exhaustive search over 2^16 keys — demonstrates infeasibility of 2^80 search."""
    for k in range(2**16):
        trial_key = k.to_bytes(2, 'big') + b'\x00' * 8  # 16-bit active portion
        if present_encrypt(plaintext, trial_key) == ciphertext:
            return k
    return None  # Not found (expected when real key uses all 80 bits)
```

A 16-bit exhaustion completes in <1 second; 80-bit is effectively impossible.

---

## 3. Side-Channel Vulnerability Analysis

### 3.1 Timing Attacks

**Vulnerability**: If the cipher execution time varies depending on the key or data value, an attacker measuring many encryption times can statistically recover key bits.

**Sources of timing variation in a naive implementation**:
- Branch-dependent on key/data bits (e.g., `if (bit) ...`)
- Table lookup cache misses (not applicable on cache-less AVR, but relevant on ESP32)
- Variable-latency multiplications

**Analysis of this implementation**:
```c
// SAFE: sBox lookup is a constant-time array access on AVR (no cache)
output = sBox[input & 0xF];  // Always 1 cycle, no branch

// SAFE: pLayer uses fixed bit operations
result |= ((state >> i) & 1) << P[i];  // Always same operations

// POTENTIALLY UNSAFE on cached platforms (ESP32):
// Cache hits vs misses for sBox[i] depending on i value
```

**Risk on ATmega328P**: Low — no data cache; all SRAM accesses are constant time.
**Risk on ESP32**: Moderate — L1 data cache introduces timing variation for table lookups.

---

### 3.2 Simple Power Analysis (SPA)

**Vulnerability**: The instantaneous power consumption of a microcontroller correlates with the Hamming weight of values being processed. An oscilloscope trace of a single encryption may reveal key-dependent information.

```
Power ≈ α × HammingWeight(data) + noise

If attacker observes power during sBox lookup for nibble i:
  Power ≈ α × HammingWeight(sBox[plaintext_nibble XOR key_nibble])
```

Since the plaintext is known (attacker can choose it), this correlates with the key nibble directly.

**Practical feasibility**: SPA on 8-bit MCU requires oscilloscope with ≥1 GSa/s, stable trigger, and electromagnetic shielding of interference. Difficult but not impossible for a well-equipped attacker.

---

### 3.3 Differential Power Analysis (DPA)

**Vulnerability**: Statistical analysis of power traces from many encryptions can recover sub-key bytes even with significant noise.

**Standard DPA against PRESENT (1st round)**:
1. Record N power traces `T_1 ... T_N` for known plaintexts `P_1 ... P_N`
2. For each hypothetical key nibble `k ∈ {0..15}` and each of the 16 sBox positions:
   - Compute predicted intermediate value `v = sBox[P_i_nibble XOR k]`
   - Correlate `HammingWeight(v)` against power at the relevant time sample
3. The correct key nibble produces the highest correlation

```python
# Simplified DPA correlation (from attack_simulation.py)
for k_hyp in range(16):  # Hypothetical key nibble
    predicted_hw = [bin(sBox[pt_nibble ^ k_hyp]).count('1') for pt_nibble in plaintexts]
    correlation = pearsonr(predicted_hw, power_traces[:, target_sample])
    if abs(correlation[0]) > threshold:
        recovered_key_nibble = k_hyp
```

**Number of traces needed**: Typically 1,000–10,000 for unprotected implementations. With masking: 100,000–1,000,000+.

---

### 3.4 Electromagnetic Analysis (EMA)

Similar to DPA but uses a near-field EM probe instead of power measurements. Can be more precise as the probe can target specific IC regions. Similar countermeasures apply.

---

### 3.5 Fault Injection Attacks

**Differential Fault Analysis (DFA)** on PRESENT:
- Inject a fault (voltage glitch, laser, clock glitch) during round 29–31
- Compare faulty and correct ciphertexts to recover round key
- Boneh et al. style DFA: ~8 faulty ciphertexts sufficient to recover last round key

**Countermeasures**: Duplicate computation + comparison, parity checks on intermediate values (not currently implemented in this project).

---

## 4. Countermeasures Implemented

### 4.1 Constant-Time sBox Lookup (ATmega328P)

On the ATmega328P, all SRAM accesses take a fixed 2-clock-cycle latency. The sBox is stored in SRAM (not Flash, to avoid variable `pgm_read_byte` timing), so lookups are inherently constant time:

```c
// present_cipher.c — constant-time on AVR (SRAM array, no branch)
static const uint8_t sBox[16] = {0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,
                                  0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2};

uint8_t nibble_sub(uint8_t x) {
    return sBox[x & 0xF];  // No branch, no early-exit
}
```

> [!NOTE]
> On ESP32, cache effects break constant-time guarantees. For higher assurance on ESP32, store sBox in IRAM (instruction RAM) which is not data-cached, or use a bitsliced implementation.

---

### 4.2 Boolean Masking (Python Demonstration)

The `python/attack_simulation.py` implements first-order Boolean masking as a demonstration:

**Principle**: Split each sensitive intermediate value `v` into two shares:
```
v = v' XOR m
```
where `m` is a fresh random mask. Neither share alone reveals `v`.

```python
# Masked sBox evaluation (1st-order Boolean masking)
def masked_sbox(x, mask_in, mask_out):
    """
    Apply sBox with input mask mask_in and output mask mask_out.
    Returns sBox[x XOR mask_in] XOR mask_out
    """
    masked_input = x ^ mask_in
    masked_output = sBox[masked_input] ^ mask_out
    return masked_output

def constant_time_encrypt(self, plaintext, key):
    mask = random.getrandbits(64)           # fresh random mask
    state = plaintext ^ mask               # mask state
    for round in range(31):
        # addRoundKey: mask passes through XOR unchanged
        state = state ^ round_keys[round]  # state = (pt^mask)^K = (pt^K)^mask
        # sBox: must re-mask per nibble with fresh masks
        state = masked_sbox_layer(state, mask)
        # pLayer: linear, mask permutes with bits
        state, mask = apply_masked_pLayer(state, mask)
    state = state ^ round_keys[31] ^ mask  # unmask at output
    return state
```

**Security**: First-order masking defeats standard DPA (which exploits single sensitive values). It does **not** protect against 2nd-order DPA (which correlates two intermediate values).

---

### 4.3 Replay Prevention (Timestamp in Block)

The 64-bit plaintext block includes a 16-bit timestamp (lower bits of `millis()`). The receiver rejects any block whose decrypted timestamp is older than a 5-second window:

```python
# python/present.py — replay check
MAX_TIMESTAMP_DELTA_MS = 5000
def decrypt_and_verify(ciphertext_hex, key, last_ts):
    block = present_decrypt(int(ciphertext_hex, 16), key)
    ts = block & 0xFFFF
    if abs(ts - last_ts) > MAX_TIMESTAMP_DELTA_MS:
        raise ReplayAttackError(f"Timestamp {ts} outside window")
    return block
```

---

### 4.4 HMAC-SHA256 Authentication

Each encrypted payload is accompanied by an HMAC-SHA256 tag computed over the ciphertext:

```python
# python/data_integrity.py
import hmac, hashlib

def add_hmac(ciphertext: bytes, auth_key: bytes) -> bytes:
    tag = hmac.new(auth_key, ciphertext, hashlib.sha256).digest()
    return ciphertext + tag  # 32-byte tag appended

def verify_hmac(frame: bytes, auth_key: bytes) -> bool:
    data, tag = frame[:-32], frame[-32:]
    expected = hmac.new(auth_key, data, hashlib.sha256).digest()
    return hmac.compare_digest(tag, expected)  # constant-time comparison
```

This protects against **message modification** and **forgery** in transit.

---

## 5. Key Rotation Policy

### 5.1 Rotation Schedule

| Trigger | Rotation Type | Mechanism | Priority |
|---------|--------------|-----------|----------|
| **30-day calendar interval** | Session key derivation | HKDF from master key + epoch | NORMAL |
| **2^32 blocks encrypted** | Counter rollover protection | Key counter tracked in NVS | HIGH |
| **Suspected compromise** | Emergency revocation | Out-of-band re-provisioning | CRITICAL |
| **Device reset/reflash** | Full key replacement | Secure manufacturing process | HIGH |
| **Patient discharge** | Session key deletion | NVS wipe command via MQTT | NORMAL |

### 5.2 Key Rotation Procedure

```
Step 1: Backend generates new_key = CSPRNG(80 bits)
Step 2: Encrypt new_key with old_key (using PRESENT-80 in CTR mode simulation)
        [or use TLS-encrypted MQTT channel]
Step 3: Send encrypted new_key to device via MQTT healthcare/keyrotate topic
Step 4: Device decrypts new_key, writes to EEPROM/NVS, ACKs
Step 5: Both sides switch to new_key on next encryption cycle
Step 6: Backend invalidates old_key in key vault
```

### 5.3 Master vs. Session Keys

```
Master Key (80 bits, stored in EEPROM)
    │
    ▼  HKDF(master_key, device_id || epoch_number, length=10)
    │
Session Key (80 bits, stored in RAM only, rotated every 30 days)
    │
    ▼  PRESENT-80 Encrypt
Ciphertext
```

The master key **never** participates directly in encryption. Only session keys are used for data encryption, limiting exposure from traffic analysis.

### 5.4 Key Derivation Function

```python
import hashlib, hmac

def derive_session_key(master_key: bytes, device_id: bytes, epoch: int) -> bytes:
    """
    HKDF-Extract + HKDF-Expand for 80-bit (10-byte) session key.
    master_key: 10 bytes (80-bit PRESENT key)
    device_id:  8 bytes (unique device identifier)
    epoch:      4-byte big-endian integer (rotation counter)
    """
    # HKDF-Extract: PRK = HMAC-SHA256(salt=device_id, IKM=master_key)
    prk = hmac.new(device_id, master_key, hashlib.sha256).digest()
    # HKDF-Expand: 10 bytes of output keying material
    info = b"PRESENT-80-session" + epoch.to_bytes(4, 'big')
    okm = hmac.new(prk, info + b'\x01', hashlib.sha256).digest()
    return okm[:10]  # First 10 bytes = 80 bits
```

---

## 6. Compliance and Standards

| Standard | Relevance | Status |
|----------|-----------|--------|
| ISO/IEC 29192-2:2012 | PRESENT cipher specification | ✅ Compliant |
| NIST SP 800-131A Rev 2 | 112-bit minimum security | ⚠️ Below (80-bit key) |
| HIPAA Security Rule §164.312(a)(2)(iv) | Encryption of PHI at rest | ✅ Addresses (with caveats) |
| IEC 62443-3-3 | Industrial/IoT security levels | SL1 compliant |
| GDPR Article 32 | Encryption as technical measure | ✅ Encryption implemented |

> [!WARNING]
> HIPAA does not mandate a specific cipher, but recommends NIST-approved algorithms. PRESENT-80 is not on NIST's approved list (FIPS 140-2). For regulated healthcare deployments requiring FIPS compliance, replace PRESENT-80 with **AES-128-GCM** using a hardware AES accelerator.

---

## 7. Risk Assessment Summary

| Risk | Likelihood | Impact | Residual Risk | Mitigation |
|------|-----------|--------|--------------|-----------|
| Brute-force key recovery | Very Low | Critical | **Low** | 2^80 infeasible |
| Differential cryptanalysis | Very Low | Critical | **Low** | 31-round margin |
| DPA on Arduino | Medium | High | **Medium** | Masking not in HW |
| Timing attack on ESP32 | Medium | High | **Medium** | Cache-side-channel |
| Replay attack | Low | High | **Low** | Timestamp + window |
| MQTT injection | Low | High | **Low** | HMAC authentication |
| EEPROM key extraction | Low | Critical | **Medium** | Physical access only |
| Key compromise via leakage | Low | Critical | **Low** | Session key rotation |
| Fault injection (DFA) | Low | Critical | **Medium** | Not mitigated |

### Overall Assessment

> **PRESENT-80 is appropriate for low-to-medium threat environments where:**
> - Data confidentiality lifetime < 20 years
> - Attackers do not have physical access to devices
> - Budget/resources preclude AES hardware acceleration
> - The alternative is transmitting unencrypted sensor data

> **Upgrade to AES-128-GCM or PRESENT-128 when:**
> - Long-term medical records (>20 years)
> - High-value patient data (ICU, oncology)
> - Regulatory compliance requires FIPS-approved algorithms
> - ESP32 hardware AES is available (use `mbedtls` AES functions)

---

*Document version: 1.0 | Last updated: 2026-11 | References: Bogdanov et al. 2007 (CHES), NIST SP 800-131A Rev 2 (2019)*
