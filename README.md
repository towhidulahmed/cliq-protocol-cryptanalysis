# Cryptographic Analysis of the ASSA ABLOY VERSO CLIQ 1-Wire Protocol

This repository contains the cryptographic analysis of the electronic locking protocol used in the ASSA ABLOY VERSO CLIQ system. The focus here is on algorithm identification and weakness analysis through differential cryptanalysis of captured unlock sessions.

For background on how the signal capture and protocol decoding works, see the initial analysis repository:
**[1wire-decoder-analysis](https://github.com/towhidulahmed/1wire-decoder-analysis)**

The earlier protocol-level research data used in this analysis was originally produced at the **University of Rostock**, Chair of Information and Communication Services (IuK). See [data/previous_research/ATTRIBUTION.md](data/previous_research/ATTRIBUTION.md) for details.

---

## 1. Introduction

This document describes the cryptographic analysis of the electronic communication between an ASSA ABLOY VERSO CLIQ key and its corresponding lock cylinder. The communication happens over a single-wire contact interface when the key is inserted into the lock.

The analysis is based on 23 captured unlock sessions collected over roughly 10 years (2014 to 2024), using multiple keys on the same locking system. The earlier captures come from research at the University of Rostock (IuK department), while the 2024 captures were collected independently using a Saleae logic analyzer.

The question we are trying to answer: what cryptographic algorithm does this system use, and how strong is it in practice?

## 2. What We Are Working With

### 2.1 The Capture Dataset

| Source | Sessions | Period | Keys | Equipment |
|--------|----------|--------|------|-----------|
| Uni Rostock IuK (previous research) | 8 | ~2014 | 2 different keys | Custom ADC + USB-FIFO |
| User 1 captures | 8 | 2024 | User 1's key | Saleae Logic Analyzer |
| User 2 captures | 2 | 2024 | User 2's key | Saleae Logic Analyzer |
| Comparison captures | 5 | 2024 | User 1's key | Saleae Logic Analyzer |
| **Total** | **23** | **2014-2024** | **3+ keys** | |

Each capture contains one complete unlock event: the full signal exchanged between the key and the lock, from the moment the key is inserted until the lock either opens or rejects.

A complete unlock session is about 255 bytes long and takes roughly 7.6 milliseconds.

### 2.2 Signal Characteristics

The signal is a standard 1-Wire bus with pulse-width encoded data:

| Parameter | Value |
|-----------|-------|
| Logic high voltage | ~2.98V (from CR2032 coin cell) |
| Logic low voltage | 0V |
| Write '1' pulse | ~4.3 us low |
| Write '0' pulse | ~13.7 us low |
| Full bit cycle | ~18.75 us |
| Communication frequency | ~131 Hz repetition |

The key acts as the bus master. The lock is the slave device and is powered by the key's battery through the contact pin.

## 3. Protocol Structure

By aligning all 23 captures and parsing the command/response boundaries, we can now describe the full protocol. Every unlock attempt follows the same four-phase structure.

### 3.1 Packet Format

Every packet starts with a 2-byte header:

- Commands (key to lock): `82 00 <sequence> <type> [data...] [CRC]`
- Responses (lock to key): `00 <sequence> <type> [data...] [CRC]`

The sequence number increments from `01` to `04` across the four phases.

### 3.2 The Four Phases

**Phase 1: Identity exchange**

The key sends a 33-byte identity packet containing:
- The system number `V1004261` in ASCII (plaintext, 8 bytes)
- 7 bytes of padding (`1E 1E 1E 1E 1E 1E 1E`)
- A configuration byte (`41` or `61` depending on direction)
- 6 bytes of counter/key-ID area

The lock responds by echoing back a similar identity block. Both sides now know who they are talking to.

```
Key -> Lock:  82 00 01 01 1B 03 56 31 30 30 34 32 36 31
                                      V  1  0  0  4  2  6  1
              1E 1E 1E 1E 1E 1E 1E 41 02 00 08 01 04 [counter] [CRC]

Lock -> Key:  00 01 11 18 03 56 31 30 30 34 32 36 31
              1E 1E 1E 1E 1E 1E 1E 61 90 01 01 00 04 00 00 D2
```

**Phase 2: Nonce exchange (challenge)**

The key sends a short read-memory command. The lock responds with 8 random bytes plus a CRC byte. These 8 bytes are the challenge nonce.

```
Key -> Lock:  82 00 02 08 00 74        (read memory command)
Lock -> Key:  00 02 11 08 [8 nonce bytes] [CRC]
```

Here are the actual nonces observed across 7 sessions that had this phase fully captured:

```
Session     Nonce (8 bytes)
─────────   ────────────────────────────
prev_pkt1   DC AF E0 29 A9 9C 5B 95
prev_pkt2   E1 A9 ED 7E 73 A3 95 36
prev_pkt4   38 7F AF 1F 2F 8B E3 CC
prev_pkt5   14 5B 5A 3A 26 7D 65 6C
prev_pkt6   73 FE A4 74 7F B5 AF 7B
prev_key1   5D AC 04 FD D7 C8 73 0D
prev_key2   3F 03 5D DE 62 AC 1A 7D
```

All 7 nonces are unique. Every single byte position has 7 unique values out of 7 samples. The pairwise Hamming distance between nonces averages 50.1%, which is what you would expect from properly random data. So the nonce generation looks solid.

**Phase 3: Authentication data (encrypted payload)**

The key sends a 38-byte packet containing encrypted data. The structure is:

```
82 00 03 0A 20 [24 bytes encrypted] [8 bytes zeros] [CRC]
```

The 24 encrypted bytes change every session. The 8 zero bytes are always all zeros in every single capture across 10 years. The CRC byte at the end changes per session.

The lock responds with either:
- `00 03 11 18 [24 zero bytes] 50` if it accepts (proceeds to Phase 4)
- `00 03 21 00 58` if it rejects (authentication failed, session ends)

We actually captured a rejection in one of the previous research sessions, which confirms the lock actively validates this data.

**Phase 4: MAC verification**

The key sends a 27-byte packet containing the authentication hash:

```
82 00 04 80 15 [22 bytes MAC]
```

The lock responds with a final status. If everything checks out, the lock motor activates and the key can be turned.

Here are the MACs from 6 complete sessions:

```
Session     MAC (22 bytes, first 10 shown)
─────────   ──────────────────────────────────────
prev_pkt1   85 72 D1 57 FE BA 71 F5 E4 CE ...
prev_pkt4   E2 D1 45 F3 EA 9D C0 56 6B DD ...
prev_pkt5   EA 1D 3E 1F D1 66 59 43 FC 8A ...
prev_pkt6   09 AC 88 96 89 6D E0 0C 44 AA ...
prev_key1   72 F8 16 1C 57 A6 13 E3 74 7F ...
prev_key2   4E B4 A8 B9 23 3B 09 A5 99 3F ...
```

## 4. Identifying the Cryptographic Algorithm

### 4.1 Evidence for SHA-1

Several things point to SHA-1 as the authentication hash:

First, the protocol commands match the command set of the Maxim/Dallas DS28EC20, a 1-Wire EEPROM chip with built-in SHA-1 authentication. The `doc/` folder from the earlier research at Uni Rostock actually contains the DS28EC20 datasheet. The command structure we see in the captures lines up almost exactly with the DS28EC20's read-memory, write-scratchpad, and compute-MAC operations.

Second, the MAC is 22 bytes long. SHA-1 produces a 20-byte (160-bit) hash. The extra 2 bytes are device status bytes appended by the DS28EC20 hardware after the SHA-1 digest. Advanced entropy analysis confirms this structure:

- MAC[0] through MAC[19]: all show 6/6 unique values across sessions (full entropy)
- MAC[20]: shows only 5/6 unique values (reduced entropy — consistent with device metadata)
- MAC[21]: per-bit flip probability = 0.367 (well below the ideal 0.5 — further evidence of non-hash data)

This 20+2 structure matches the DS28EC20 datasheet, which specifies that the `Compute MAC` command returns 20 bytes of SHA-1 output followed by a 2-byte device status field.

Third, and most importantly, the statistical properties of the first 20 MAC bytes match what you would expect from SHA-1. Here is what we measured:

| Metric | Measured | Expected for good hash |
|--------|----------|----------------------|
| Mean Hamming distance between MAC pairs | **50.0%** | ~50% |
| Per-bit flip probability (pairwise) | **0.5004** | 0.5000 |
| MAC byte entropy | **6.55 bits/byte** | ~8.0 bits/byte |
| MAC[0:20] bytes dynamic | 20/20 fully unique | yes |
| MAC[20:22] bytes | reduced entropy | expected for device metadata |

The Hamming distance of exactly 50.0% and per-bit flip probability of 0.5004 are basically textbook. For a well-behaved cryptographic hash, when you change the input, roughly half the output bits should flip. That is exactly what we see.

### 4.2 Evidence for AES-128-CTR on the Encrypted Payload

ASSA ABLOY states in their product documentation that CLIQ uses 128-bit AES. Looking at the captured data:

- The encrypted payload is exactly 24 bytes of ciphertext followed by 8 bytes of static zeros. Crucially, 24 + 8 = 32 bytes = exactly 2 AES-128 blocks.
- The 24 bytes of ciphertext are NOT block-aligned (1.5 blocks), which is natural for AES-CTR (counter mode) since CTR generates a keystream that can encrypt arbitrary byte lengths.
- The 8 zero bytes are unencrypted protocol padding, not ciphertext. If AES-CBC were used, standard PKCS#7 padding would produce 32 bytes of ciphertext — but we observe only 24 bytes of ciphertext plus 8 plaintext zeros. This contradiction rules out AES-CBC with standard padding.
- No repeated 16-byte blocks were found within any single capture, which rules out ECB mode.
- Some block patterns repeat across captures, but only in the plaintext framing around the encrypted section, not in the ciphertext itself.

The block boundary alignment analysis:

```
┌─────────────── 32 bytes (2 × AES-128 blocks) ──────────────┐
│                                                              │
│  AES Block 1 (16 bytes)  │  AES Block 2 (16 bytes)         │
│  ┌──────────────────┐    │  ┌──────────┬──────────┐        │
│  │ CIPHERTEXT (16B) │    │  │ CT (8B)  │ 00 (8B)  │        │
│  │ Dynamic/random   │    │  │ Dynamic  │ Static   │        │
│  └──────────────────┘    │  └──────────┴──────────┘        │
│        bytes 0-15        │      bytes 16-23  bytes 24-31   │
└──────────────────────────┴──────────────────────────────────┘
```

The actual ciphertext portion is hard to isolate precisely because it is mixed in with protocol framing bytes. Out of the 89-byte region initially suspected to be "encrypted" (bytes 87-175 in the raw stream), only about 24 bytes are actually ciphertext. The rest is plaintext protocol data that happens to sit in the same area.

**Mode determination: AES-128-CTR is most likely.** CBC is ruled out because standard CBC+PKCS#7 would transmit 32 bytes of ciphertext, not 24 ciphertext + 8 plaintext zeros.

### 4.3 CRC-8 for Error Detection

The protocol uses CRC-8/MAXIM for data integrity on the bus. This is standard for 1-Wire and has nothing to do with security. The CRC polynomial and implementation were already identified in the previous research at Uni Rostock (see `patterns.php` in `data/previous_research/`).

### Algorithm Identification Summary

| Component | Algorithm | Confidence | Evidence |
|-----------|-----------|------------|----------|
| Authentication hash | **SHA-1** | High | MAC Hamming distance = 50.0% (textbook ideal), 20-byte hash + 2-byte device status matches DS28EC20 spec, `Compute SHA` command present |
| Payload encryption | **AES-128-CTR** | Medium-High | ASSA ABLOY claims 128-bit AES, 24-byte ciphertext (non-block-aligned → CTR mode), no ECB pattern, 24+8=32 byte block boundary alignment |
| Error detection | **CRC-8/MAXIM** | Confirmed | Polynomial identified in previous research, matches all packets |

## 5. Differential Cryptanalysis Results

This is where things get interesting. With 23 sessions in hand, we can do proper differential analysis to look for weaknesses in the implementation.

### 5.1 Pairwise Output Independence Analysis

**Terminology note:** This section measures *pairwise output independence* (whether random inputs produce ~50% bit differences in outputs), not the *Strict Avalanche Criterion* (SAC). True SAC testing requires chosen-input pairs differing in exactly 1 bit, which is impossible with passive captures — it would require injecting chosen nonces into the lock hardware. Our nonce pairs differ by ~32 bits on average (50.1% of 64 bits), so what we measure is output uniformity across random multi-bit differentials.

We compared the challenge nonces (Phase 2 input) against the MACs (Phase 4 output) across all pairs to check pairwise output independence. When the challenge changes, how much does the MAC change?

| Challenge difference | MAC change | Expected |
|---------------------|------------|----------|
| 0 bits (same challenge) | 37-47% of MAC bits flip | ~50% (other inputs differ) |
| 8 bits changed | 31-42% flip | ~50% |
| 71-73 bits changed | 31-51% flip | ~50% |

Advanced bit-level analysis across the 6 paired nonce/MAC sessions shows:

| Metric | Measured | Ideal |
|--------|----------|-------|
| Mean MAC bit-flip probability | **0.5004** | 0.5000 |
| Mean MAC Hamming distance | **50.0%** | 50.0% |
| Input-Δ vs Output-Δ correlation | **r = -0.069** | 0.000 |
| Bits with extreme bias (<0.2 or >0.8) | 7/176 (4.0%) | ~0% |

The per-bit flip probability of 0.5004 is textbook perfect. The output differential is completely independent of the input differential magnitude (r = -0.069 ≈ 0), which is exactly what a proper cryptographic hash should exhibit.

The MAC changes are in the right ballpark but skew slightly low (averaging 40.7% rather than the ideal 50%) when measured across all 15 captures (including those without paired nonce data). This mild bias is worth noting but not necessarily a fatal flaw.

However, there is one very interesting case: captures 4 and 9 in our original dataset produced **identical MAC output with 0% difference**. This could mean they are duplicate captures of the same event, or it could mean there was a nonce collision. We cannot tell for certain without more data.

### 5.2 Nonce-to-MAC Correlation Analysis (Resolved — Statistical Artifact)

We extracted the nonce bytes and the corresponding MAC bytes from sessions where both were fully captured, then computed Pearson correlations between each nonce byte position and each MAC byte position.

For a strong hash function, there should be no meaningful linear correlation between any input byte and any output byte. Initial (uncorrected) analysis found 7 correlations with |r| > 0.811:

| Input | Output | Correlation (r) | p (uncorrected) | p (Bonferroni) | Verdict |
|-------|--------|-----------------|-----------------|----------------|---------|
| Nonce byte 3 | MAC byte 4 | **-0.94** | 0.005 | 0.962 | Spurious |
| Nonce byte 4 | MAC byte 11 | **-0.91** | 0.012 | 1.000 | Spurious |
| Nonce byte 5 | MAC byte 19 | **+0.88** | 0.019 | 1.000 | Spurious |
| Nonce byte 5 | MAC byte 14 | **-0.88** | 0.019 | 1.000 | Spurious |
| Nonce byte 4 | MAC byte 14 | **-0.88** | 0.020 | 1.000 | Spurious |
| Nonce byte 0 | MAC byte 21 | **-0.84** | 0.036 | 1.000 | Spurious |
| Nonce byte 6 | MAC byte 6 | **+0.82** | 0.044 | 1.000 | Spurious |

**However, these correlations are a statistical artifact of multiple hypothesis testing (the "look-everywhere effect").** Here is why:

With n=6 paired samples and df=4, the critical |r| at α=0.05 is 0.811. We tested 176 independent pairs (8 nonce bytes × 22 MAC bytes). Under the null hypothesis of zero true correlation:

- **Expected false positives**: 176 × 0.05 = **8.8 correlations**
- **Observed**: **7 correlations** (fewer than expected from pure noise)
- **Monte Carlo validation** (10,000 random trials): 9.1 ± 3.0 expected from chance
- **Probability of ≥7 by chance**: **80.6%** (completely unremarkable)

After applying **Bonferroni correction** for 176 simultaneous tests (α_individual = 0.05/176 = 0.000284, requiring |r| > 0.985):

| Correction method | Correlations surviving |
|-------------------|----------------------|
| Bonferroni (α/176) | **0** |
| Benjamini-Hochberg FDR (q=0.05) | **0** |

**Zero correlations survive any proper multiple-testing correction.**

The initial assessment that "you would expect maybe 0 or 1 correlations above |r| = 0.8 by chance" was incorrect — it failed to account for the 176 simultaneous tests. In fact, ~8.8 is the correct expectation, and our observed 7 is well within the normal range.

This resolves what was previously listed as a high-severity weakness. The hash function shows no measurable linear bias between input and output bytes.

### 5.3 XOR Differential Analysis

We XOR'ed all pairs of captures in the encrypted payload and MAC sections, then analyzed the distribution of the resulting differential bytes.

**MAC section (22 bytes):**

| Metric | Value | What random would look like |
|--------|-------|----------------------------|
| Zero bytes in XOR differential | 15.1% | ~0.4% |
| Chi-squared statistic | 7313 | < 293 |
| Repeated differential patterns | 8 found | 0 expected |

The 15.1% zero-byte rate tells us that roughly 3-4 bytes out of the 22-byte MAC section are static across sessions. Those bytes are probably not hash output. They are likely command framing bytes that got included in the "MAC section" during our initial byte-range selection.

**Encrypted payload (24 data bytes + 8 zero bytes + 1 CRC):**

| Metric | Value | What random would look like |
|--------|-------|----------------------------|
| Static bytes | 8 out of 33 (24.2%) | 0% |
| Dynamic bytes | 25 out of 33 (75.8%) | 100% |
| Zero padding | Always 8 bytes of 0x00 | N/A |

The 8 constant zero bytes are plaintext, not ciphertext. They are always there, every session, across all 23 captures. This means the actual encrypted data is only 24 bytes. The CRC changes per session but is computed over the plaintext + ciphertext, so it is not random either.

### 5.4 Block Cipher Mode

We checked whether the encryption uses ECB mode (which would show repeated ciphertext blocks for identical plaintext blocks):

- No 16-byte block repeats within any single session. ECB mode is ruled out.
- No 8-byte block repeats either. DES-ECB is also ruled out.
- The mode is most likely AES-128-CTR (counter mode), as established in Section 4.2.

### 5.5 Counter and Key Identification Bytes

The identity packet (Phase 1) contains a 6-byte field that partially changes between sessions:

```
prev_foo2_pkt1:  9C 14 46 04 1F 6F
prev_foo2_pkt2:  9C 14 46 04 34 5A   <- same key, different session
prev_key1:       95 14 E4 03 0B ED   <- different key
prev_key2:       95 14 E4 03 16 E2   <- same different key, later session
user1_session:   38 04 17 ...        <- 2024 capture
user2_session:   96 02 07 ...        <- 2024 different key
```

Bytes 0-1 of this field (`9C 14`, `95 14`, etc.) look like a key identifier. They stay the same within one key but differ between keys. Byte 2 changes slowly (maybe a day counter or access-right version). Bytes 3-4 change more rapidly (session counter or timestamp). Byte 5 looks like a CRC or checksum over the preceding bytes.

These are transmitted in the clear and could be used to track which key was used and when.

### 5.6 Same Key vs. Different Key MAC Comparison

If the secret key stored in the chip plays a role in the MAC computation (which it should), then MACs from the same key should look different from MACs from a different key. We tested this:

| Comparison | Mean Hamming distance (MAC) |
|-----------|-----------------------------|
| Same key (User 1, 8 captures) | 41.0% |
| Same key (User 2, 2 captures) | 48.1% |
| Cross-key (User 1 vs User 2) | 39.9% |

The distances are very similar across all comparisons. This tells us that the nonce (which changes every session) dominates the MAC output variation, not the per-key secret. The secret key contributes to the computation, but its effect is masked by the much higher entropy of the random nonce.

This is actually how challenge-response is supposed to work: the nonce should make every MAC unique regardless of the key. But it also means that from the MAC alone, you cannot easily tell which key produced it.

## 6. Byte-Level Entropy Map

We computed the Shannon entropy at every byte position across all 23 captures. Higher entropy means more variation (more random, more likely to be crypto output). Lower entropy means more predictable (protocol framing, static data).

```
Byte   Classification
─────  ──────────────────────────────────────────────────
0-1    STATIC         Bus reset + start bytes (0xFF 0x5A)
2-7    STATIC         Command header + type
8-15   STATIC         System ID "V1004261" in plaintext
16-22  STATIC         Padding bytes (1E 1E 1E 1E 1E 1E 1E)
23-26  STATIC         Configuration byte + fixed bytes
27-28  LOW ENTROPY    Key identifier (2 values across keys)
29-32  MODERATE       Counter/timestamp area
33-36  HIGH           Session-specific (CRC, nonce-derived)
37-81  MIXED          Repeated identity + status exchanges
82-86  BINARY         Challenge init command (alternates between 2 variants)
87-106 MIXED          Protocol framing mixed with some dynamic data
107-137 HIGH          Likely encrypted payload area
138-175 MIXED         More protocol data + zero padding
176-187 LOW           Command bytes + mode flags
188-212 STATIC        Zero-padded memory page (all zeros)
213-217 LOW           MAC frame header
218-237 VERY HIGH     SHA-1 hash output (the actual authentication data)
238-254 MIXED         Final verification bytes + status
```

The important takeaway: only about 20-30 bytes out of the full 255-byte exchange are actually cryptographic output (hash or ciphertext). The rest is predictable protocol structure.

## 7. Identified Weaknesses

| # | Weakness | Severity |
|---|----------|----------|
| 1 | System ID `V1004261` transmitted in plaintext every session | High |
| 2 | No distance bounding, relay attack feasible (7.6ms round trip) | High |
| 3 | Key identifier bytes (27-28) visible in cleartext | Medium |
| 4 | 8 bytes of known plaintext (zero padding) in auth data | Medium |
| 5 | Protocol unchanged for 10+ years (2014 same as 2024) | Medium |
| 6 | Reject response `0x21` leaks authentication failure status | Low |
| 7 | ~~Nonce-to-MAC correlations~~ — resolved as statistical artifact (Bonferroni correction: 0 survive) | ~~High~~ None |

### 7.1 Plaintext System ID

The system number `V1004261` appears twice in every unlock session, at byte positions 8-15 and 49-56. It is transmitted as ASCII without any obfuscation. Anyone listening on the wire can identify which locking system the key belongs to.

### 7.2 No Distance Bounding

The full communication takes about 7.6 milliseconds. There is no timing constraint that would prevent a relay attack. An attacker with two devices (one near the key, one near the lock) connected by a fast link could relay the entire exchange in real time. The protocol does not check whether the response came back "too slowly" for a direct connection.

### 7.3 Key Identification in Clear

Bytes 27-28 of the identity packet effectively identify which key is being used. This means passive eavesdropping on the contact pin could tell you which specific key unlocked which door and when.

### 7.4 Constant Zero Padding

The 8-byte zero block in the authentication data packet is known plaintext. In a chosen-plaintext attack scenario, this could help narrow down the encryption key, though in practice the attacker would also need control over other inputs.

### 7.5 Nonce-to-MAC Correlations (Resolved)

~~As initially reported in Section 5.2, apparent correlations between nonce bytes and MAC bytes were observed.~~ After applying Bonferroni correction for 176 simultaneous hypothesis tests, zero correlations survive (see Section 5.2). The observed correlations were a statistical artifact of the "look-everywhere effect" at small sample size (n=6). Monte Carlo simulation confirms that 9.1 ± 3.0 false positives are expected from pure random noise, and our observed count of 7 falls within this range. **This is not a cryptographic weakness.**

### 7.6 Unchanged Protocol Over 10 Years

The protocol structure is identical between the 2014 captures and the 2024 captures. Same commands, same byte layout, same framing. There has been no protocol version upgrade in that time. This means any vulnerability found in the protocol applies to the entire installed base over at least a decade.

## 8. Comparison with Published Information

ASSA ABLOY's marketing materials state that CLIQ uses "128-bit AES encryption" and that the system provides "high security against electronic manipulation." Our analysis broadly agrees that AES-128 is used for the 24-byte encrypted payload (most likely in CTR mode), but we also found that:

- The encrypted portion is much smaller than the total communication (24 bytes out of 255)
- A significant portion of the exchange is plaintext or easily predictable
- The challenge-response uses SHA-1, which has known weaknesses (though the application here is HMAC-like, not collision-resistance)
- The initial report of nonce-to-MAC correlations was a statistical artifact that does not survive multiple-testing correction

The DS28EC20 datasheet found in the earlier research files describes a chip with exactly the capabilities we observe: 1-Wire interface, SHA-1 authentication engine, and EEPROM storage for secrets and configuration. This is almost certainly the chip family used in the lock or key, or a close relative of it.

## 9. What Would Strengthen This

The analysis has some limits because of the sample size. Here is what additional data would unlock:

| Additional data | What it would tell us |
|----------------|----------------------|
| 50+ captures with same key | Although Bonferroni correction resolved the correlation artifact at n=6, more data would further validate hash independence and enable deeper statistical analysis |
| Captures at known time intervals | Determine if byte 29 is a clock counter or access counter |
| Captures from a key that was revoked | See if the protocol changes after access revocation |
| Power trace during MAC computation | Side-channel analysis (DPA) could extract the secret key |
| Captures from different CLIQ system (different V-number) | Determine which parts of the protocol are system-specific |
| Chosen-nonce injection into lock | Required for true Strict Avalanche Criterion (SAC) testing — not possible with passive captures |

## 10. Summary

The ASSA ABLOY VERSO CLIQ system uses a two-layer security approach over a 1-Wire bus:

1. **SHA-1 challenge-response** for mutual authentication (confirmed by command structure, 20-byte hash output + 2-byte device status matching DS28EC20 spec, and textbook-perfect statistical properties including per-bit flip probability of 0.5004)
2. **AES-128-CTR** (counter mode, most likely) for a 24-byte encrypted payload containing access rights or configuration data — CBC ruled out by non-block-aligned ciphertext structure

The implementation generally works as intended, with proper nonce generation and excellent pairwise output independence (0.5004 bit-flip probability). The initially reported nonce-to-MAC correlations were resolved as a statistical artifact of multiple hypothesis testing — zero correlations survive Bonferroni correction across the 176 tested byte pairs.

Remaining areas of concern: the system ID is exposed in plaintext every session, key identifiers are transmitted in the clear, and the protocol has not changed in 10 years. The most actionable research directions would be side-channel analysis (DPA) during MAC computation and relay attack feasibility testing, as the protocol lacks distance bounding.

---

## Repository Structure

```
├── data/
│   ├── captures/
│   │   ├── user1_key/           # 8 sessions
│   │   ├── user2_key/           # 2 sessions
│   │   └── extas_comparison/    # 5 sessions
│   └── previous_research/       # Uni Rostock decoded packets (~2014)
├── scripts/
│   ├── decode_signal.py                # Core 1-Wire signal decoder
│   ├── analyze_captures.py             # Basic signal analysis
│   ├── differential_cryptanalysis.py   # Differential cryptanalysis suite
│   ├── extended_analysis.py            # Multi-source analysis (all 23 sessions)
│   └── advanced_critique_analysis.py   # Bonferroni correction, CRC-16 tests, SAC analysis, AES mode determination
├── docs/
│   └── crypto_analysis.md              # Detailed report (mirrored in this README)
└── README.md
```

## Running the Analysis

Python 3, no external dependencies.

```bash
# Basic signal decode and cross-file comparison
python3 scripts/analyze_captures.py

# Full differential cryptanalysis (Hamming, avalanche, XOR, chi-squared, correlations)
python3 scripts/differential_cryptanalysis.py

# Extended analysis combining all 23 sessions from all sources
python3 scripts/extended_analysis.py

# Advanced critique resolution (Bonferroni, CRC-16, SAC, AES-CTR analysis)
python3 scripts/advanced_critique_analysis.py
```

## Acknowledgments

**Previous research data:** University of Rostock, Faculty of Computer Science and Electrical Engineering, Chair of Information and Communication Services (IuK).
[https://www.iuk.informatik.uni-rostock.de/](https://www.iuk.informatik.uni-rostock.de/)

**Initial signal analysis and protocol decoding:** [1wire-decoder-analysis](https://github.com/towhidulahmed/1wire-decoder-analysis)

## Disclaimer

This research is conducted for academic purposes only. It is not intended to enable unauthorized access to any locking system.
