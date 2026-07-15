# Cryptographic Analysis of the ASSA ABLOY VERSO CLIQ 1-Wire Protocol

> **Research documentation. Read the [Disclaimer](#disclaimer) and [Responsible Disclosure](#responsible-disclosure) before reading further.**

This repository contains a black-box cryptanalysis of the electronic locking protocol used in the ASSA ABLOY VERSO CLIQ system. The focus is on algorithm identification, statistical verification of cryptographic claims, and weakness analysis through differential cryptanalysis of captured unlock sessions.

For background on signal capture and protocol decoding, see the companion repo: **[1wire-decoder-analysis](https://github.com/towhidulahmed/1wire-decoder-analysis)**.

Earlier protocol-level research data was originally produced at the **University of Rostock**, Chair of Information and Communication Services (IuK). See [`data/previous_research/ATTRIBUTION.md`](data/previous_research/ATTRIBUTION.md) for details.

---

## Disclaimer

**This repository is published solely for academic study and security-research purposes.** It documents the cryptographic structure observed on a single deployed CLIQ locking system and identifies open research questions. It does **not** contain working exploits, key-recovery tools, unlock-emulation code, or step-by-step instructions for defeating any locking system.

**The author assumes no responsibility for any misuse of the information in this repository.** Any exploitation, unauthorized access, or attempt to defeat a CLIQ system, or any other system, based on this analysis is the sole responsibility of the person undertaking it. The author does not endorse, encourage, or take responsibility for any act of unauthorized access, circumvention, or damage that may result from applying the information published here.

Researchers extending this work are expected to comply with all applicable laws and to act in accordance with responsible-disclosure norms. If you discover a working attack, coordinate with the vendor before publishing.

The captured data is real, drawn from a deployed system, and is published for reproducibility of the statistical analysis. The (nonce, MAC) pairs in particular enable offline brute-force attack research; researchers should not publish successful key-recovery results without vendor coordination.

System identifiers (system ID `V1004XXX`, key identifiers, installation-specific counter values) are partially redacted throughout this repository. The raw capture data in `data/previous_research/` is reproduced with permission from the University of Rostock IuK; redistribution restrictions may apply. Contact the IuK chair before re-publishing.

---

## Responsible Disclosure

| Item | Status |
|------|--------|
| System under analysis | ASSA ABLOY VERSO CLIQ (single installation, system ID partially redacted as `V1004XXX`) |
| Capture period | 2014 (Uni Rostock prior research) + 2024 (independent Saleae captures) |
| Disclosure type | **Self-disclosure** of the author's own captured data, published for academic study and research purposes only |
| Disclosure date | **2026-07-16** |
| Vendor contact | **Not attempted.** This is independent academic research; no communication with the vendor has taken place. The author makes no claim of vendor endorsement, authorization, or response. |
| Scope of disclosure | Protocol structure, statistical analysis of MAC and ciphertext, identified weaknesses. **No working key-recovery or unlock-emulation attack is demonstrated.** The author takes no responsibility for any exploitation derived from this work. |

Researchers extending this work should treat the published MACs, nonces, and ciphertexts as **real captured data from a deployed system**, not synthetic examples. Offline brute-force attack research against the published (nonce, MAC) pairs is technically feasible (see [§7.4](#74-mac-and-nonce-publication)) and should not be undertaken without vendor coordination.

---

## Threat Model

This analysis is grounded in an explicit threat model. The findings in this document are only meaningful relative to that model.

**Asset.** The ability to unlock a specific physical door protected by a CLIQ cylinder, using a legitimate CLIQ key.

**Attacker capabilities considered:**

| Capability | This analysis | Out of scope |
|---|---|---|
| Passive eavesdrop on the 1-Wire contact during a legitimate unlock | ✓ primary scenario | n/a |
| Physical access to a legitimate key (e.g., borrowed, stolen briefly) | ✓ considered | n/a |
| Active relay / forwarding of the 1-Wire signal between key and lock | ✓ considered | n/a |
| Decapping / invasive silicon extraction of the DS28EC20 chip | n/a | Out of scope (different attacker class) |
| Power/EM side-channel during MAC computation (DPA/CPA) | n/a | Out of scope (no equipment in this study; flagged as future work) |
| Nation-state cryptanalytic infrastructure (e.g., SHA-1 collision infrastructure) | n/a | Out of scope for a physical-locking-system threat model |
| Quantum-computing adversary | n/a | Not relevant for this product class |

**Attacker goals considered:**

1. **Unauthorized unlock** of a specific door (highest impact).
2. **Tracking**: determining which key unlocked which door and when (privacy goal).
3. **Cloning**: extracting enough information from one or more captures to fabricate a working key emulator.
4. **Replay/relay**: unlocking without possessing the key at unlock time.

**Security properties the protocol attempts to provide:**

- Mutual authentication (key proves identity to lock; lock proves identity to key)
- Per-session freshness (challenge-response with random nonce)
- Confidentiality of access-rights data (AES-encrypted payload)
- Integrity of message exchange (trailing checksum byte; see §4.3)

**Security properties the protocol does *not* provide:**

- Distance bounding (relay attack feasibility; see [§7.2](#72-no-distance-bounding-relay-attack-feasible))
- Anonymity / unlinkability of keys (see [§7.1](#71-plaintext-system-id-and-key-identifier) and [§7.3](#73-key-identification-in-clear))
- Forward secrecy (captured sessions remain useful if the secret is later compromised)
- Side-channel resistance (untested in this study)

---

## 1. Introduction

This document describes the cryptographic analysis of the electronic communication between an ASSA ABLOY VERSO CLIQ key and its corresponding lock cylinder. The communication happens over a single-wire contact interface when the key is inserted into the lock.

The analysis is based on 23 captured unlock sessions collected over roughly 10 years (2014 to 2024), using multiple keys on the same locking system. The earlier captures come from research at the University of Rostock (IuK department), while the 2024 captures were collected independently using a Saleae logic analyzer.

The question we are trying to answer: **what cryptographic algorithm does this system use, and how strong is it in practice under a passive-eavesdrop + relay threat model?**

---

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

A complete unlock session is about 255 bytes long and takes roughly 7.6 milliseconds end-to-end.

Of the 23 captures, only 6-7 contain a fully decodable (nonce, MAC) pair suitable for paired statistical analysis. This sample size is the single most important limitation of the study. See [§9 Limitations](#9-limitations).

### 2.2 Signal Characteristics

The signal is a standard 1-Wire bus with pulse-width encoded data:

| Parameter | Value |
|-----------|-------|
| Logic high voltage | ~2.98 V (from CR2032 coin cell) |
| Logic low voltage | 0 V |
| Write '1' pulse | ~4.3 µs low |
| Write '0' pulse | ~13.7 µs low |
| Full bit cycle | ~18.75 µs |
| Communication frequency | ~131 Hz repetition |

The key acts as the bus master. The lock is the slave device and is powered by the key's battery through the contact pin.

> **Decoder note.** The Python pulse decoder in `scripts/decode_signal.py` classifies pulses as '1' if `3 ≤ duration ≤ 7 µs` and as '0' if `duration > 11 µs`. Pulses in the 7-11 µs gap are silently dropped. The original Uni Rostock decoder (`data/previous_research/patterns.php`) uses a more robust state machine with explicit "short pulse followed by pause" / "long pulse followed by pause" patterns that handle end-of-byte transitions. Captures that produce misaligned bytes under the Python decoder should be re-decoded with the PHP variant.

---

## 3. Protocol Structure

By aligning all 23 captures and parsing the command/response boundaries, the protocol breaks down into a fixed four-phase structure. Every observed unlock attempt follows the same sequence.

```
╔══════════════════════════════════════════════════════════════════════════╗
║          CLIQ 1-Wire Protocol : Communication Flow                        ║
║       Four-phase challenge-response unlock session                         ║
║   ~255 bytes · ~7.6 ms · 1-Wire bus · pulse-width encoded                  ║
╚══════════════════════════════════════════════════════════════════════════╝

  Legend:  [K->L] = Key -> Lock  (master command)
           [L->K] = Lock -> Key  (slave response)

═══════════════════════════════════════════════════════════════════════════
  > PHASE 1 : IDENTITY EXCHANGE
    Plaintext system ID + key identifier + counter area
═══════════════════════════════════════════════════════════════════════════

  [K->L]  82 00 01 01 1B 03 | 56 31 30 30 34 XX XX XX | 1Ex7 | 41 02 00 08 01 04 | [6B ctr] [CRC]
         +---- header ----+ +-- sys ID "V1004XXX" --+  pad  +----- config ---------+

  [L->K]  00 01 11 18 03 | 56 31 30 30 34 XX XX XX | 1Ex7 | 61 90 01 01 00 04 00 00 [CRC]
         +---- header ---+ +-- sys ID echo --------+  pad  +------ config ----------+

  !  System ID sent in PLAINTEXT. Bytes 27-28 = key identifier (visible in clear).

═══════════════════════════════════════════════════════════════════════════
                                  |
                                  v
═══════════════════════════════════════════════════════════════════════════
  > PHASE 2 : NONCE EXCHANGE (CHALLENGE)
    Lock emits 8 random bytes, the challenge nonce
═══════════════════════════════════════════════════════════════════════════

  [K->L]  82 00 02 08 00 [CRC]
         +- read memory -+

  [L->K]  00 02 11 08 | DC AF E0 29 A9 9C 5B 95 | [CRC]
         +-- header --+ +---- 8-byte nonce -----+

  OK  7 captures: all unique nonces, mean pairwise Hamming ~ 50.1%, proper RNG.

═══════════════════════════════════════════════════════════════════════════
                                  |
                                  v
═══════════════════════════════════════════════════════════════════════════
  > PHASE 3 : ENCRYPTED AUTHENTICATION PAYLOAD
    24-byte ciphertext + 8-byte plaintext zeros + trailing byte
═══════════════════════════════════════════════════════════════════════════

  [K->L]  82 00 03 0A 20 | [======== 24B ciphertext ========] | 00x8 | [CRC]
         +-- header ---+ +-- dynamic, per-session -----------+ +- pt -+

         AES-128 in stream-compatible mode (CTR / CBC-zero-pad / CBC-CTS /
         single-block CBC). Cannot distinguish without chosen-plaintext.

  [L->K]  ACCEPT:  00 03 11 18 [24 zero bytes] 50  -> proceed to Phase 4
         REJECT:  00 03 21 00 58                  -> authentication failed

  !  8 zero bytes are PLAINTEXT padding (static across all 23 captures).
  OK  A rejection was captured in prev_pkt2, lock actively validates this data.

═══════════════════════════════════════════════════════════════════════════
                                  |
                                  v
═══════════════════════════════════════════════════════════════════════════
  > PHASE 4 : MAC VERIFICATION
    22-byte MAC, likely 20B SHA-1 + 2B device status
═══════════════════════════════════════════════════════════════════════════

  [K->L]  82 00 04 80 15 | [========== 20B SHA-1 ==========] | [2B status]
         +-- header ---+ +-- matches DS28EC20 Compute MAC ---+

         Statistical properties (n=6 paired sessions):
           Mean Hamming distance:      50.04%   (ideal: 50%)
           Per-bit flip probability:   0.5004   (ideal: 0.5000)

  [L->K]  00 04 11 02 01 01 63  ->  motor activates, key can be turned

═══════════════════════════════════════════════════════════════════════════

  Sources: 23 captures (2014-2024), Uni Rostock IuK prior research + 2024
  Saleae captures. Stats over 6-7 paired (nonce, MAC) sessions.
  System ID last 3 digits redacted for responsible disclosure.
```

### 3.1 Packet Format

Every packet starts with a 2-byte header:

- Commands (key to lock): `82 00 <sequence> <type> [data...] [trailing byte]`
- Responses (lock to key): `00 <sequence> <type> [data...] [trailing byte]`

The sequence number increments from `01` to `04` across the four phases. The trailing byte at the end of each packet is checksum-like (see [§4.3](#43-trailing-checksum-byte) for what we can and cannot say about it).

### 3.2 The Four Phases

#### Phase 1: Identity exchange

The key sends a 33-byte identity packet containing:

- The system number `V1004XXX` in ASCII (plaintext, 8 bytes; last 3 digits redacted in this document for responsible disclosure)
- 7 bytes of padding (`1E 1E 1E 1E 1E 1E 1E`)
- A configuration byte (`41` or `61` depending on direction)
- 6 bytes of counter / key-ID area

The lock responds by echoing back a similar identity block. Both sides now know who they are talking to.

```
Key -> Lock:  82 00 01 01 1B 03 56 31 30 30 34 XX XX XX
                                      V  1  0  0  4  [redacted]
              1E 1E 1E 1E 1E 1E 1E 41 02 00 08 01 04 [counter] [trailing]

Lock -> Key:  00 01 11 18 03 56 31 30 30 34 XX XX XX
              1E 1E 1E 1E 1E 1E 1E 61 90 01 01 00 04 00 00 [trailing]
```

#### Phase 2: Nonce exchange (challenge)

The key sends a short read-memory command. The lock responds with 8 random bytes plus a trailing byte. These 8 bytes are the challenge nonce.

```
Key -> Lock:  82 00 02 08 00 [trailing]            (read memory command)
Lock -> Key:  00 02 11 08 [8 nonce bytes] [trailing]
```

Across 7 sessions where this phase was fully captured, the nonces are:

```
Session     Nonce (8 bytes)
---------   -------------------------------
prev_pkt1   DC AF E0 29 A9 9C 5B 95
prev_pkt2   E1 A9 ED 7E 73 A3 95 36
prev_pkt4   38 7F AF 1F 2F 8B E3 CC
prev_pkt5   14 5B 5A 3A 26 7D 65 6C
prev_pkt6   73 FE A4 74 7F B5 AF 7B
prev_key1   5D AC 04 FD D7 C8 73 0D
prev_key2   3F 03 5D DE 62 AC 1A 7D
```

All 7 nonces are unique. Every single byte position has 7 unique values out of 7 samples. The pairwise Hamming distance between nonces averages 50.1%, which is what you would expect from properly random data. **The nonce generation looks solid.**

#### Phase 3: Authentication data (encrypted payload)

The key sends a 38-byte packet containing encrypted data. The structure is:

```
82 00 03 0A 20 [24 bytes ciphertext] [8 bytes zeros] [trailing byte]
```

The 24 encrypted bytes change every session. The 8 zero bytes are always `00 00 00 00 00 00 00 00` in every single capture across 10 years. The trailing byte changes per session.

The lock responds with either:

- `00 03 11 18 [24 zero bytes] 50` if it accepts (proceeds to Phase 4)
- `00 03 21 00 58` if it rejects (authentication failed, session ends)

A rejection was captured in `prev_pkt2`, confirming the lock actively validates this data.

#### Phase 4: MAC verification

The key sends a 27-byte packet containing the authentication hash:

```
82 00 04 80 15 [22 bytes MAC]
```

The lock responds with a final status. If everything checks out, the lock motor activates and the key can be turned.

The 6 complete MACs captured:

```
Session     MAC (22 bytes, first 10 shown)
---------   -------------------------------------
prev_pkt1   85 72 D1 57 FE BA 71 F5 E4 CE ...
prev_pkt4   E2 D1 45 F3 EA 9D C0 56 6B DD ...
prev_pkt5   EA 1D 3E 1F D1 66 59 43 FC 8A ...
prev_pkt6   09 AC 88 96 89 6D E0 0C 44 AA ...
prev_key1   72 F8 16 1C 57 A6 13 E3 74 7F ...
prev_key2   4E B4 A8 B9 23 3B 09 A5 99 3F ...
```

---

## 4. Identifying the Cryptographic Algorithm

### 4.1 Evidence for SHA-1 (Authentication MAC)

The 22-byte MAC is consistent with the DS28EC20 `Compute MAC` command, which returns 20 bytes of SHA-1 output followed by a 2-byte device-status field. Three independent lines of evidence support this:

1. **Command structure matches DS28EC20.** The Phase-4 command `82 00 04 80 15 [22 bytes]` matches the DS28EC20 datasheet's `Compute MAC` operation, and the Phase-2 `82 00 02 08 00` matches `Read Memory`. The DS28EC20 is a Maxim/Dallas 1-Wire EEPROM with built-in SHA-1 authentication engine; the earlier Uni Rostock research files include the DS28EC20 datasheet. The four commands actually used in the protocol are `0x01` (identity), `0x08` (read memory), `0x0A` (auth data), and `0x80` (compute MAC). The byte `0x33` appears only once in the entire 1,434-byte raw data stream and never in a command position; it is data, not a "Compute SHA" command.

2. **MAC length is 20+2 bytes.** SHA-1 produces a 20-byte (160-bit) digest. The extra 2 bytes are device status bytes appended by the DS28EC20 hardware. Entropy analysis of the 22-byte MAC across sessions:
   - MAC[0] through MAC[19]: all show 6/6 unique values across the 6 sessions (full entropy)
   - MAC[20]: 5/6 unique values (reduced entropy, consistent with device metadata)
   - MAC[21]: per-bit flip probability = 0.367 (well below the ideal 0.5, further evidence of non-hash data)

3. **Statistical properties of the first 20 MAC bytes match SHA-1.**

   | Metric | Measured | Expected for good hash |
   |--------|----------|------------------------|
   | Mean Hamming distance between MAC pairs (22 bytes) | **50.04%** | ~50% |
   | Mean Hamming distance (MAC[0:20] only) | **51.12%** | ~50% |
   | Per-bit flip probability (22 bytes) | **0.5004** | 0.5000 |
   | MAC byte entropy | **6.55 bits/byte** | ~8.0 bits/byte |
   | MAC[0:20] bytes dynamic | 20/20 fully unique | yes |
   | MAC[20:22] bytes | reduced entropy | expected for device metadata |

   The Hamming distance of 50.04% and per-bit flip probability of 0.5004 are textbook. For a well-behaved cryptographic hash, when you change the input, roughly half the output bits should flip. That is exactly what we see.

### 4.2 Evidence for AES-128 on the Encrypted Payload (Mode Undetermined)

ASSA ABLOY states in their product documentation that CLIQ uses 128-bit AES. Looking at the captured data:

- The encrypted payload is exactly 24 bytes of ciphertext followed by 8 bytes of static zeros. 24 + 8 = 32 bytes = exactly 2 AES-128 blocks.
- The 24 bytes of ciphertext are **NOT** block-aligned (1.5 blocks), which is natural for AES-CTR (counter mode) since CTR generates a keystream that can encrypt arbitrary byte lengths.
- The 8 zero bytes are unencrypted protocol padding, **not** ciphertext. If AES-CBC + PKCS#7 were used, standard padding would produce 32 bytes of ciphertext, but we observe only 24 bytes of ciphertext plus 8 plaintext zeros. This contradiction rules out **AES-CBC + PKCS#7**.
- No repeated 16-byte blocks were found within any single capture, which **weakly** argues against ECB (but n=7 captures is far too small to strongly rule out ECB; reliably detecting ECB requires ~2^32 captures for 16-byte blocks).

```
+--------------------------------------------------------------------------+
|  Phase-3 Payload : 32 Bytes = 2 x AES-128 Block Boundaries               |
+--------------------------------------------------------------------------+

  Byte:   0        8        16       24       32
          |        |        |        |        |
          v        v        v        v        v
         +------------------+------------------+----+
         |  CIPHERTEXT 24B  | PLAINTEXT ZEROS  | ?? |
         | dynamic/session  |  static 0x00x8   |    |
         +------------------+------------------+----+
          +- Block 1 (16B) -++- Block 2 (16B) -+
          +------------------+------------------+
                     2 x AES-128 blocks

  +----------------------------------------------------------------------+
  |  KEY OBSERVATION: 24-byte ciphertext is NOT block-aligned             |
  |                                                                      |
  |  - 24 + 8 = 32 bytes = exactly 2 AES-128 blocks                      |
  |  - 8 zero bytes are PLAINTEXT (always 0x00 across all captures)      |
  |  - Standard CBC+PKCS#7 would produce 32B ct, not 24B ct + 8B pt      |
  +----------------------------------------------------------------------+

  MODE CONSISTENCY ANALYSIS
+--------------------------------------------------------------------------+

  OK CONSISTENT (cannot be ruled out passively):
    - AES-CTR                      : stream mode, 8 zeros are pt framing
    - AES-CBC + zero-padding       : last 8B ct decrypts to 0; discarded
    - AES-CBC-CTS (NIST 800-38A)   : ciphertext stealing, no padding
    - Single-block AES-CBC + 8B unencrypted metadata
    - AES-ECB                      : cannot rule out at n=7

  X  REJECTED by observations:
    - AES-CBC + PKCS#7 padding     : would produce 32B ct, not 24+8

+--------------------------------------------------------------------------+

  VERDICT: AES mode cannot be determined passively.
  Distinguishing CTR vs CBC-zero-pad vs CBC-CTS requires:
    (a) chosen-plaintext captures (block independence test), or
    (b) side-channel analysis (counter vs chaining detection).
```

**Mode determination: AES-128 in some stream-compatible mode.** Multiple modes are consistent with the observed 24 ct + 8 pt-zero structure:

| Mode | Consistent? | Reason |
|------|-------------|--------|
| AES-CTR | ✓ | Stream mode, arbitrary length, 8 zeros are plaintext framing |
| AES-CBC with zero-padding | ✓ | 24B padded to 32B; last 8B ct decrypts to zero; receiver discards |
| AES-CBC-CTS (NIST SP 800-38A) | ✓ | Ciphertext stealing: 24B to 24B ct, no padding expansion |
| Single-block AES-CBC + 8B unencrypted metadata | ✓ | First 16B encrypted, next 8B static protocol field |
| AES-ECB | Cannot rule out | Detecting ECB requires ~2^32 captures at 16-byte block size |
| AES-CBC + PKCS#7 | ✗ | Would produce 32B ciphertext, not 24B ct + 8B pt zeros |

**Conclusion: AES-128 in some stream-compatible mode (CTR, CBC-zero-pad, CBC-CTS, or single-block CBC). Standard CBC+PKCS#7 is unlikely. Distinguishing the remaining candidates requires either chosen-plaintext captures (to test block independence) or side-channel analysis (to detect counter vs. chaining operations).**

### 4.3 Trailing Checksum Byte

A trailing byte appears at the end of every packet in the protocol. Its specific algorithm has not been identified.

A brute-force search was performed over the entire 2^17 CRC-8 parameter space (polynomial x initial value x final XOR x reflect-input x reflect-output) against 7 known (Phase-3 payload, trailing byte) pairs and 7 known (Phase-2 nonce packet, trailing byte) pairs. **Zero CRC-8 variants match any plausible input combination.** The `patterns.php` extra-zero-pass variant was also tested and does not match. Simple XOR, sum-8, and two's-complement-sum-8 checksums were also tested and do not match.

The trailing byte is therefore **unidentified**. Plausible candidates that have not yet been ruled out include:

- A non-standard CRC variant with bit-reversal or initial/final transforms not covered by the standard parameter space
- A truncated hash
- A sequence-derived value (e.g., derived from session counter state)
- A polynomial division with a non-standard width or final shift

For the purpose of this analysis, the trailing byte should be treated as **"a per-packet byte whose specific algorithm has not been identified."** It is not relevant to the cryptographic security of the protocol (it provides error detection at most, not authentication), but the inability to identify it is a quality gap in the analysis that should be filled before any "conference-grade" claim is made. See [`scripts/crc_bruteforce.py`](scripts/crc_bruteforce.py) for the search code. The full results are saved to `crc_bruteforce_results.json` in the repo root after running the script.

### Algorithm Identification Summary

| Component | Algorithm | Confidence | Evidence |
|-----------|-----------|------------|----------|
| Authentication MAC | **SHA-1** (20B) + 2B device status | **High** | MAC Hamming distance 50.04%, per-bit flip 0.5004, 20+2 structure matches DS28EC20 `Compute MAC` spec, command `0x80` matches DS28EC20 |
| Payload encryption | **AES-128** in stream-compatible mode | **Medium** | ASSA ABLOY claims AES-128; 24B ct + 8B pt zeros rules out CBC+PKCS#7; CTR, CBC-zero-pad, CBC-CTS, or single-block CBC all consistent. Cannot distinguish without chosen-plaintext. |
| Trailing checksum byte | **Unidentified** | **Low** | Brute-force over 2^17 CRC-8 variants + simple checksums: zero matches. Specific algorithm unknown. |
| Error detection | Trailing byte (algorithm TBD) | n/a | Provides at most error detection, not authentication. Not security-relevant. |

---

## 5. Differential Cryptanalysis Results

With 23 sessions in hand, differential analysis can be applied to look for weaknesses in the implementation. **The sample size is the dominant caveat throughout this section.** See [§9](#9-limitations).

### 5.1 Pairwise Output Independence Analysis

> **Terminology.** This section measures *pairwise output independence* (whether random inputs produce ~50% bit differences in outputs), not the *Strict Avalanche Criterion* (SAC). True SAC testing requires chosen-input pairs differing in exactly 1 bit, which is impossible with passive captures; it would require injecting chosen nonces into the lock hardware. Our nonce pairs differ by ~32 bits on average (50.1% of 64 bits), so what we measure is output uniformity across random multi-bit differentials.

We compared the challenge nonces (Phase-2 input) against the MACs (Phase-4 output) across all 6 paired sessions to check pairwise output independence. When the challenge changes, how much does the MAC change?

| Challenge difference | MAC change | Expected |
|---------------------|------------|----------|
| 0 bits (same challenge) | not observed | ~50% (other inputs differ) |
| 8 bits changed | 31-42% flip | ~50% |
| 71-73 bits changed | 31-51% flip | ~50% |

Bit-level analysis across the 6 paired nonce/MAC sessions:

| Metric | Measured | Ideal |
|--------|----------|-------|
| Mean MAC bit-flip probability | **0.5004** | 0.5000 |
| Mean MAC Hamming distance | **50.04%** | 50.0% |
| Input-delta vs Output-delta correlation | **r = -0.069** | 0.000 |
| Bits with extreme bias (<0.2 or >0.8) | 7/176 (4.0%) | ~0% |

The per-bit flip probability of 0.5004 is textbook. The output differential is statistically independent of the input differential magnitude (r = -0.069, approximately 0), which is what a proper cryptographic hash should exhibit.

### 5.2 Nonce-to-MAC Correlation Analysis

We extracted the nonce bytes and the corresponding MAC bytes from the 6 sessions where both were fully captured, then computed Pearson correlations between each nonce byte position and each MAC byte position (8 x 22 = 176 tests). For a strong hash function, no meaningful linear correlation should exist.

**Statistical method.** p-values are computed exactly via the regularized incomplete beta function (Student's t distribution with df=4), implemented in [`scripts/statistical_analysis.py`](scripts/statistical_analysis.py).

| Input | Output | Correlation (r) | p (exact, uncorrected) | p (Bonferroni) | Verdict |
|-------|--------|-----------------|------------------------|----------------|---------|
| Nonce[3] | MAC[4] | **-0.939** | 0.0054 | 0.956 | Spurious |
| Nonce[4] | MAC[11] | **-0.909** | 0.0122 | 1.000 | Spurious |
| Nonce[5] | MAC[19] | **+0.884** | 0.0194 | 1.000 | Spurious |
| Nonce[5] | MAC[14] | **-0.884** | 0.0194 | 1.000 | Spurious |
| Nonce[4] | MAC[14] | **-0.881** | 0.0203 | 1.000 | Spurious |
| Nonce[0] | MAC[21] | **-0.843** | 0.0351 | 1.000 | Spurious |
| Nonce[6] | MAC[6] | **+0.824** | 0.0438 | 1.000 | Spurious |

**Uncorrected significant correlations (p < 0.05): 7.** Under the null hypothesis of zero true correlation, with 176 simultaneous tests, the expected number of false positives is 176 x 0.05 = **8.8**. The observed 7 is well within the normal range.

**Bonferroni-corrected significant correlations: 0.** With alpha_individual = 0.05/176 = 0.000284, no correlations survive. The same result holds under Benjamini-Hochberg FDR at q = 0.05.

**Power analysis.** At n = 6 paired samples, df = 4, and Bonferroni-corrected alpha = 0.000284:

| Power | Minimum detectable \|r\| |
|-------|--------------------------|
| 0.50 | 0.970 |
| 0.80 | **0.989** |
| 0.90 | 0.993 |
| 0.95 | 0.996 |

Power to detect a true correlation of |r| = 0.9 is only **0.14** (14%). Power to detect |r| = 0.7 is **0.017** (1.7%). Power to detect |r| = 0.5 is **0.004** (0.4%).

**Verdict.** At n = 6 with Bonferroni correction, the test is **severely underpowered**. The correct framing of the result is not "no correlations exist" but rather: *"we cannot reject the null hypothesis of zero correlation, but we also cannot rule out linear correlations weaker than |r| approximately 0.99. Stronger claims about hash input-output independence require a larger sample."*

### 5.3 XOR Differential Analysis

The chi-squared test for uniform byte distribution is applied to the bytes of pairwise XOR differentials. To respect the IID assumption of the chi-squared test, **disjoint pairs** are used (pair capture i with capture i+1 for i = 0, 2, 4, ...), yielding n/2 independent XOR differentials rather than the C(n, 2) overlapping pairs that share captures and violate independence.

We XOR'ed disjoint pairs of captures in the MAC section and analyzed the distribution of the resulting differential bytes.

**MAC section (22 bytes), disjoint pairs (n = 3 pairs, 66 bytes):**

| Metric | Value |
|--------|-------|
| Sample size | 66 bytes |
| Chi-squared statistic | 252.1 |
| Threshold (df=255, alpha=0.05) | 293.25 |
| Verdict | "uniform" (well under threshold) |
| Reliable? | **No: expected count per byte = 66/256 = 0.26, far below the rule-of-thumb minimum of 5** |

**The chi-squared test is unreliable at this sample size.** The rule of thumb is that expected count per category should be at least 5; here it is 0.26, more than an order of magnitude below. The test cannot meaningfully distinguish "uniform" from "non-uniform" with this few bytes.

The informal observation that "3-4 bytes out of the 22-byte MAC section are static across sessions" is still plausible. Those bytes are probably command framing bytes that got included in the "MAC section" during byte-range selection, not hash output. This conclusion rests on direct inspection of byte values across captures, not on the chi-squared test.

### 5.4 Block Cipher Mode

- No 16-byte block repeats within any single session. ECB mode is weakly argued against (but n = 7 is far too small to strongly rule out; see [§4.2](#42-evidence-for-aes-128-on-the-encrypted-payload-mode-undetermined)).
- No 8-byte block repeats either. DES-ECB is weakly argued against.
- The mode is one of: AES-CTR, AES-CBC with zero-padding, AES-CBC-CTS, or single-block AES-CBC plus unencrypted metadata. Standard CBC+PKCS#7 is ruled out. See [§4.2](#42-evidence-for-aes-128-on-the-encrypted-payload-mode-undetermined) for the full enumeration.

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

- Bytes 0-1 of this field (`9C 14`, `95 14`, etc.) look like a **key identifier**. They stay the same within one key but differ between keys.
- Byte 2 changes slowly (maybe a day counter or access-right version).
- Bytes 3-4 change more rapidly (session counter or timestamp).
- Byte 5 looks like a checksum byte over the preceding bytes.

These are transmitted in the clear and could be used to track which key was used and when. This is a privacy concern, not an authentication-security concern. See [§7.3](#73-key-identification-in-clear).

### 5.6 Same Key vs. Different Key MAC Comparison

If the secret key stored in the chip plays a role in the MAC computation (which it should), then MACs from the same key should look different from MACs from a different key. We tested this:

| Comparison | Mean Hamming distance (MAC) |
|-----------|-----------------------------|
| Same key (User 1, 8 captures) | 41.0% |
| Same key (User 2, 2 captures) | 48.1% (a single pair; see note) |
| Cross-key (User 1 vs User 2) | 39.9% |

> **Note on the User 2 row.** With only 2 User-2 captures, C(2, 2) = 1 pair, so "48.1%" is a single Hamming distance (85 of 176 bits). It is reported as a percentage for consistency but should not be over-interpreted.

The distances are very similar across all comparisons. The nonce (which changes every session) dominates the MAC output variation, not the per-key secret. The secret key contributes to the computation, but its effect is masked by the much higher entropy of the random nonce.

This is actually how challenge-response is supposed to work: the nonce should make every MAC unique regardless of the key. But it also means that **from the MAC alone, you cannot easily tell which key produced it**, which is good for privacy, but also means MAC-traffic analysis cannot directly identify individual keys.

---

## 6. Byte-Level Entropy Map

We computed the Shannon entropy at every byte position across all 23 captures. Higher entropy means more variation (more random, more likely to be crypto output). Lower entropy means more predictable (protocol framing, static data).

```
Byte   Classification
-----  --------------------------------------------------
0-1    STATIC         Bus reset + start bytes (0xFF 0x5A)
2-7    STATIC         Command header + type
8-15   STATIC         System ID "V1004XXX" in plaintext
16-22  STATIC         Padding bytes (1E 1E 1E 1E 1E 1E 1E)
23-26  STATIC         Configuration byte + fixed bytes
27-28  LOW ENTROPY    Key identifier (2 values across keys)
29-32  MODERATE       Counter/timestamp area
33-36  HIGH           Session-specific (trailing byte, nonce-derived)
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

---

## 7. Identified Weaknesses

| # | Weakness | Severity | Threat-model relevance |
|---|----------|----------|------------------------|
| 1 | System ID `V1004XXX` transmitted in plaintext every session | High | Tracking, system identification |
| 2 | No distance bounding; relay attack feasible (7.6 ms round-trip) | High | Unauthorized unlock via relay |
| 3 | Key identifier bytes (27-28) visible in cleartext | Medium | Tracking, key fingerprinting |
| 4 | 8 bytes of known plaintext (zero padding) in auth data | Medium | Aids chosen-plaintext attack research |
| 5 | Protocol unchanged for 10+ years (2014 same as 2024) | Medium | Long exposure window for any vulnerability found |
| 6 | Reject response `0x21` leaks authentication failure status | Low | Timing oracle (very weak) |
| 7 | Published (nonce, MAC) pairs enable offline brute-force attack research | Medium | Depends on secret length (see §7.4) |

### 7.1 Plaintext System ID and Key Identifier

The system number `V1004XXX` appears twice in every unlock session, at byte positions 8-15 and 49-56 (the second occurrence is in the lock's identity echo). It is transmitted as ASCII without any obfuscation. Anyone listening on the wire can identify which locking system the key belongs to. This is a tracking vulnerability: an attacker with logic-analyzer access to one CLIQ installation can fingerprint it and recognize the same system elsewhere.

The system ID has been partially redacted in this document (last 3 digits replaced with `XXX`) for responsible disclosure. The full system ID appears in the raw capture data under `data/previous_research/`.

### 7.2 No Distance Bounding (Relay Attack Feasible)

The full communication takes about 7.6 milliseconds. There is no timing constraint that would prevent a relay attack. An attacker with two devices (one near the key, one near the lock) connected by a fast link (e.g., 433 MHz radio, or even a low-latency WiFi link) could relay the entire exchange in real time. The protocol does not check whether the response came back "too slowly" for a direct connection.

This is the same attack class as documented against passive keyless-entry systems in automotive contexts (see [§10 Related Work](#10-related-work)). The defense, distance bounding (Brands-Chaum or Hancke-Kuhn), requires the protocol to enforce a strict round-trip time budget per challenge-response pair, which the CLIQ protocol does not do.

This is the highest-impact weakness under the threat model in this document. **It does not require breaking any cryptography.** A pure relay of bytes unlocks the door.

### 7.3 Key Identification in Clear

Bytes 27-28 of the identity packet effectively identify which key is being used (see [§5.5](#55-counter-and-key-identification-bytes)). This means passive eavesdropping on the contact pin could tell you which specific key unlocked which door and when. For deployments where key usage is meant to be private (e.g., individual-employee activity), this is a privacy concern.

### 7.4 MAC and Nonce Publication

The 6 published (nonce, MAC) pairs in this repository are real captured data from a deployed CLIQ system. If the SHA-1 hypothesis is correct, each MAC is a deterministic function of (secret key, nonce, page data). An attacker with these pairs can perform an offline brute-force search over candidate secret keys:

- For each candidate secret, compute the expected MAC for each known nonce using the DS28EC20 MAC algorithm
- If all 6 match, the candidate is the real secret
- Time complexity: 2^(secret_bit_length) MAC computations

The DS28EC20 secret length is documented as 4 bytes (32 bits) in older Maxim parts and longer in newer variants. At 32 bits, brute-forcing 6 (nonce, MAC) pairs is feasible on a single GPU in minutes. At 64+ bits, it is infeasible on commodity hardware. The actual secret length used by this specific CLIQ installation is **not known from passive captures** and depends on the chip revision deployed.

This is a real consideration for publication. The (nonce, MAC) pairs in this repository are not synthetic; they are real. Researchers extending this work should treat them as such and should not publish any successful key-recovery result without vendor coordination.

### 7.5 Constant Zero Padding

The 8-byte zero block in the authentication data packet is known plaintext. In a chosen-plaintext attack scenario, this could help narrow down the encryption key, though in practice the attacker would also need control over other inputs. Under the passive-eavesdrop threat model, this is a low-impact observation: the zeros simply confirm that the encryption does not extend over the full 32-byte block boundary.

### 7.6 Unchanged Protocol Over 10 Years

The protocol structure is identical between the 2014 captures and the 2024 captures. Same commands, same byte layout, same framing. There has been no protocol version upgrade in that time. This means any vulnerability found in the protocol applies to the entire installed base over at least a decade. It also means the system has had no security-relevant protocol updates, a long exposure window for any weakness discovered now.

### 7.7 Reject Response Leaks Status

The `0x21` reject response at Phase 3 (vs. `0x11` accept) leaks whether authentication succeeded or failed. This is a very weak oracle: it tells you only that the entire 24-byte ciphertext + (implicit) MAC check failed, not which byte failed. It is unlikely to enable a padding-oracle-style attack because the trailing byte is not a padding indicator (it is an unidentified checksum byte). Listed for completeness; impact is low.

---

## 8. What Would Strengthen This Analysis

The analysis has several limits because of sample size and equipment. Here is what additional data or capability would unlock:

| Additional data / capability | What it would tell us |
|------------------------------|----------------------|
| 50+ captures with same key | Stronger statistical power; could detect nonce-MAC correlations down to \|r\| approximately 0.3 |
| Chosen-nonce injection into lock | True Strict Avalanche Criterion (SAC) testing; distinguish AES-CTR from CBC-zero-pad |
| Chosen-plaintext captures | Definitive AES mode determination (block independence test) |
| Captures at known time intervals | Determine if byte 29 is a clock counter or access counter |
| Captures from a key that was revoked | See if the protocol changes after access revocation |
| Power trace during MAC computation | Side-channel analysis (DPA) could extract the secret key |
| Captures from different CLIQ system (different V-number) | Determine which parts of the protocol are system-specific |
| Decapped DS28EC20 chip | Read out the secret directly (different attacker class; out of scope) |

---

## 9. Limitations

This analysis is bounded by the following limitations. Findings should be interpreted in light of them:

1. **Small paired sample size.** Only 6-7 captures have a fully decodable (nonce, MAC) pair. Statistical tests on these captures are severely underpowered (see [§5.2](#52-nonce-to-mac-correlation-analysis)). Strong claims about hash input-output independence require a larger sample.

2. **Passive captures only.** No chosen-plaintext, no chosen-nonce. AES mode cannot be definitively determined (see [§4.2](#42-evidence-for-aes-128-on-the-encrypted-payload-mode-undetermined)). True SAC testing is impossible.

3. **Single system.** All 23 captures come from a single CLIQ installation (system ID `V1004XXX`). Generalization to other CLIQ deployments is plausible (the DS28EC20 hypothesis is chip-level, not system-level) but unverified.

4. **No side-channel capability.** DPA, CPA, EMI, and glitching attacks are out of scope for this analysis. The DS28EC20 family has published side-channel vulnerabilities in the academic literature; this analysis does not assess them.

5. **Trailing checksum byte unidentified.** The brute-force search over 2^17 CRC-8 variants returned zero matches. The trailing byte is some form of per-packet checksum, but its specific algorithm is unknown. This is a quality gap, not a security gap: the trailing byte provides error detection at most.

6. **Reliance on prior research data.** The 2014 captures come from University of Rostock IuK. While their work has been re-verified where possible (hard-coded NONCES / MACS / ENCRYPTED_PAYLOADS tables in `scripts/advanced_critique_analysis.py` match the raw `foo2-packets.txt`, `key1.txt`, `key2.txt` byte-for-byte), the original capture methodology and any preprocessing steps are not under this author's control.

7. **No vendor confirmation.** ASSA ABLOY has not (yet) confirmed or denied the algorithm identifications in this analysis. The SHA-1 + AES-128 identification rests on indirect evidence (statistical properties + DS28EC20 command structure match), not on vendor documentation.

8. **Post-quantum readiness is not assessed.** This is a physical-locking-system threat model; quantum cryptanalysis is not relevant. AES-128's effective security under Grover (~64 bits) is adequate for this product class through the 2030+ horizon.

---

## 10. Related Work

The cryptanalysis of 1-Wire secure-authentication chips and similar challenge-response locking systems is an established research area. The following lines of related work are directly relevant:

- **DS28EC20 and the Maxim/Dallas 1-Wire SHA-1 family.** The DS28EC20 is part of a longer line of 1-Wire EEPROM chips with built-in SHA-1 authentication (DS28E01-100, DS2432, DS28E04-100, DS28EC20). Maxim's own application notes (AN114, AN1427, AN5112) describe the SHA-1 authentication flow and MAC computation. Researchers should consult these for the exact message layout used by the `Compute MAC` command.

- **iButton cloning.** Multiple academic and hobbyist works have demonstrated cloning attacks against earlier iButton and DS199x devices. These typically exploit weak secret lengths (32 bits) or read-out via decapping. The relevance to CLIQ depends on which DS28EC20 revision is deployed.

- **Relay / forwarding attacks on contactless and contact-based authentication.** The relay-attack feasibility identified in [§7.2](#72-no-distance-bounding-relay-attack-feasible) is the same attack class as documented against:
  - Passive Keyless Entry and Start (PKES) systems in automotive contexts (Francillon et al., USENIX Security 2011; Hancke & Kuhn, 2005).
  - Contactless smartcards (ISO/IEC 14443).
  - Earlier mechanical/electronic lock hybrids.

  The defensive countermeasure, distance bounding, was introduced by Brands and Chaum (1993) and refined by Hancke and Kuhn (2005). The CLIQ protocol does not implement distance bounding.

- **SHA-1 in HMAC/MAC mode.** SHA-1 is deprecated for collision resistance (NIST disallowed SHA-1 for signatures after 2013; SHAttered published by Stevens et al. in 2017). However, SHA-1's use as a MAC (HMAC-SHA1 or in a challenge-response MAC like DS28EC20's) is still considered acceptable per NIST SP 800-107 because HMAC security does not depend on collision resistance. The CLIQ use case is closer to HMAC than to collision-resistance.

- **AES mode security.** Standard CBC+PKCS#7 has known padding-oracle risks (Vaudenay 2002; later extended by many others). The fact that CLIQ does *not* use CBC+PKCS#7 (it uses a stream-compatible mode) avoids this class of attack. CTR mode has its own well-known pitfalls (nonce reuse catastrophic, no integrity without a separate MAC), but the CLIQ protocol's separate Phase-4 SHA-1 MAC mitigates the integrity gap.

- **ASSA ABLOY CLIQ prior research.** The University of Rostock IuK work (2014) provided the initial signal-capture setup, protocol decoding, and the CRC-8 variant identification in `data/previous_research/patterns.php`. Their work is the foundation on which this cryptanalysis builds. The companion repo **[1wire-decoder-analysis](https://github.com/towhidulahmed/1wire-decoder-analysis)** documents the signal-decoding and relay-attack-feasibility analysis separately.

Researchers extending this work should also consult the ASSA ABLOY product documentation for VERSO CLIQ, which states "128-bit AES encryption" as the cipher. The analysis in this repo is consistent with that claim (with the mode-determination caveats above).

---

## 11. Summary

The ASSA ABLOY VERSO CLIQ system uses a two-layer security approach over a 1-Wire bus:

1. **SHA-1 challenge-response MAC** for authentication (high confidence: 20-byte hash + 2-byte device status matching DS28EC20 spec; textbook statistical properties including per-bit flip probability of 0.5004 and mean Hamming distance of 50.04%).
2. **AES-128** in some stream-compatible mode (medium confidence: ASSA ABLOY claims AES-128; 24-byte ciphertext + 8-byte plaintext zeros rules out standard CBC+PKCS#7; CTR, CBC-zero-pad, CBC-CTS, or single-block CBC all consistent. Cannot be distinguished without chosen-plaintext captures).
3. **Unidentified trailing checksum byte** (low confidence: brute-force over 2^17 CRC-8 variants + simple checksums returned zero matches; specific algorithm unknown).

The implementation generally works as intended, with proper nonce generation and excellent pairwise output independence (per-bit flip probability 0.5004 over 6 paired sessions). At n = 6 with Bonferroni correction, the nonce-to-MAC correlation test is severely underpowered (minimum detectable |r| at 80% power = 0.989). The correct framing is "insufficient evidence to claim correlation," not "no correlations exist."

**Highest-impact weakness under the threat model in this document: the lack of distance bounding, which makes the protocol vulnerable to a pure relay attack.** This does not require breaking any cryptography. The 7.6 ms round-trip is well within the latency budget of a fast radio relay link.

Other areas of concern: the system ID is exposed in plaintext every session (tracking vulnerability), key identifiers are transmitted in the clear (privacy), and the protocol has not changed in 10 years (long exposure window for any vulnerability found). The most actionable research directions are: (1) building and demonstrating a relay-attack proof-of-concept with explicit timing measurements, (2) DPA during MAC computation, (3) chosen-plaintext captures to definitively determine the AES mode, and (4) the trailing-byte checksum identification.

---

## Repository Structure

```
+- data/
|  +- captures/
|  |  +- user1_key/           # 8 sessions (2024, Saleae)
|  |  +- user2_key/           # 2 sessions (2024, different key)
|  |  +- extas_comparison/    # 5 sessions (2024, comparison captures)
|  +- previous_research/      # Uni Rostock decoded packets (~2014)
|     +- foo2-packets.txt     # 6 decoded unlock sessions (hex + ASCII)
|     +- key1.txt             # Decoded session from a second key
|     +- key2.txt             # Another session from that second key
|     +- patterns.php         # Uni Rostock protocol decoder (CRC-8 variant)
|     +- dump.c               # C program for extracting transitions from ADC captures
|     +- ATTRIBUTION.md
+- scripts/
|  +- decode_signal.py                # Core 1-Wire signal decoder
|  +- analyze_captures.py             # Basic signal analysis
|  +- differential_cryptanalysis.py   # Differential cryptanalysis suite
|  +- extended_analysis.py            # Multi-source analysis (all 23 sessions)
|  +- advanced_critique_analysis.py   # Bonferroni / CRC-16 / SAC / AES-CTR analysis
|  +- crc_bruteforce.py               # CRC-8 brute-force variant search
|  +- statistical_analysis.py         # Exact p-values, power analysis, disjoint-pair chi-squared
+- critique_analysis_results.json      # Critique summary
+- README.md                           # This document
```

Diagrams are inline ASCII art in this README; there are no external image files.

## Running the Analysis

Python 3, no external dependencies. All scripts use only the standard library.

```bash
# Signal decoding and basic analysis
python3 scripts/analyze_captures.py
python3 scripts/differential_cryptanalysis.py
python3 scripts/extended_analysis.py
python3 scripts/advanced_critique_analysis.py

# Trailing-byte algorithm search
python3 scripts/crc_bruteforce.py          # Brute-force search for the trailing-byte algorithm

# Statistical analysis (exact p-values, power analysis)
python3 scripts/statistical_analysis.py    # Exact p-values, power analysis, disjoint-pair chi-squared
```

The scripts write their outputs to `statistical_analysis_results.json`, `crc_bruteforce_results.json`, `crypto_analysis_results.json`, and `critique_analysis_results.json` in the repo root.

## Acknowledgments

**Previous research data:** University of Rostock, Faculty of Computer Science and Electrical Engineering, Chair of Information and Communication Services (IuK).
[https://www.iuk.informatik.uni-rostock.de/](https://www.iuk.informatik.uni-rostock.de/)

**Initial signal analysis and protocol decoding:** [1wire-decoder-analysis](https://github.com/towhidulahmed/1wire-decoder-analysis)

**Statistical methods.** The Bonferroni correction, Benjamini-Hochberg FDR, and Monte-Carlo validation are standard. The analysis additionally uses exact Student's t p-values via the regularized incomplete beta function (Numerical Recipes §6.4) and explicit power analysis via the Fisher z-transformation.

## License

Code in `scripts/`: **MIT License** (see [`LICENSE`](LICENSE); to be added by the maintainer).

Analysis text in this README and in `data/previous_research/`: **CC-BY-4.0** for the analysis text. The `data/previous_research/` files are reproduced with permission from the University of Rostock IuK; redistribution restrictions may apply. Contact the IuK chair before re-publishing.

The capture data under `data/captures/` is the author's own work and is released under **CC0 1.0** (public domain dedication), subject to the responsible-disclosure caveats in [§Responsible Disclosure](#responsible-disclosure).

## References

1. Maxim Integrated / Analog Devices, *DS28EC20 DeepCover Secure Authenticator with 1-Wire SHA-1 Master and 20kb EEPROM*, datasheet.
2. Maxim Integrated, Application Note 114: *Getting Started with Secure 1-Wire SHA-1 Authentication*.
3. Stevens, M., Bursztein, E., Karpman, P., Albertini, A., Markov, Y. *The first collision for full SHA-1.* CRYPTO 2017.
4. Brands, S., Chaum, D. *Distance-Bounding Protocols.* EUROCRYPT 1993.
5. Hancke, G. P., Kuhn, M. G. *An RFID Distance Bounding Protocol.* SECURECOMM 2005.
6. Francillon, A., Danev, B., Capkun, S. *Relay Attacks on Passive Keyless Entry and Start Systems in Modern Cars.* USENIX Security 2011.
7. NIST SP 800-38A: *Recommendation for Block Cipher Modes of Operation.* (For CBC-CTS, CTR, CBC modes.)
8. NIST SP 800-107: *Recommendation for Applications Using Approved Hash Algorithms.* (For HMAC-SHA1 security.)
9. Vaudenay, S. *Security Flaws Induced by CBC Padding: Applications to SSL, IPSEC, WTLS...* EUROCRYPT 2002.

---

*Maintained by Md Towhidul Ahmed. Pull requests that extend the analysis (especially: chosen-plaintext captures, side-channel work, or a definitive identification of the trailing checksum byte) are welcome. Pull requests that publish working key-recovery or unlock-emulation code will not be merged without documented vendor coordination.*
