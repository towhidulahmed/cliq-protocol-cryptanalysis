# CLIQ Protocol Cryptanalysis

This repository contains the cryptographic analysis of the electronic locking protocol used in the ASSA ABLOY VERSO CLIQ system. The focus here is on algorithm identification and weakness analysis through differential cryptanalysis of captured unlock sessions.

For background on how the signal capture and protocol decoding works, see the initial analysis repository:
**[1wire-decoder-analysis](https://github.com/towhidulahmed/1wire-decoder-analysis)**

The earlier protocol-level research data used in this analysis was originally produced at the **University of Rostock**, Chair of Information and Communication Services (IuK). See [data/previous_research/ATTRIBUTION.md](data/previous_research/ATTRIBUTION.md) for details.

---

## Dataset

23 unlock sessions captured over a 10-year span (2014 to 2024), from 3 different keys on the same locking system (V1004261).

| Source | Sessions | Period | Keys |
|--------|----------|--------|------|
| University of Rostock (previous research) | 8 | ~2014 | 2 keys |
| User 1 captures | 8 | 2024 | Key A |
| User 2 captures | 2 | 2024 | Key B |
| Comparison captures | 5 | 2024 | Key A |

Each session is a complete unlock event, roughly 255 bytes, lasting about 7.6 ms over a 1-Wire bus at ~3V.

## Protocol Summary

Every unlock follows a strict four-phase command-response sequence. The key is the bus master. The lock is the slave.

```
Phase 1: IDENTITY        Key sends system ID, lock echoes back
Phase 2: CHALLENGE       Key requests nonce, lock returns 8 random bytes
Phase 3: AUTH DATA       Key sends 24 encrypted bytes + 8 zero padding
Phase 4: MAC             Key sends 22-byte SHA-1 hash, lock accepts or rejects
```

Packet direction is identifiable by the header byte: `0x82` = key (master), `0x00` = lock (slave).

Full protocol details with hex dumps are in [docs/crypto_analysis.md](docs/crypto_analysis.md).

## Cryptographic Findings

### Algorithm Identification

| Component | Algorithm | Confidence | Evidence |
|-----------|-----------|------------|----------|
| Authentication hash | **SHA-1** | High | MAC Hamming distance = 50.0% (textbook ideal), 22-byte output matches DS28EC20 spec, `Compute SHA` command present |
| Payload encryption | **AES-128** | Medium | ASSA ABLOY claims 128-bit AES, 24-byte ciphertext = 1.5 blocks, no ECB pattern detected |
| Error detection | **CRC-8/MAXIM** | Confirmed | Polynomial identified in previous research, matches all packets |

### Differential Analysis Results

**Nonce quality (8-byte challenge from lock):**
- All 7 extracted nonces are unique across sessions
- Every byte position shows 7/7 unique values
- Pairwise Hamming distance = 50.1% (good randomness)

**MAC quality (22-byte authentication hash):**
- Pairwise Hamming distance = **50.0%** (perfect for SHA-1)
- Byte entropy = 6.55 bits/byte
- 21 of 22 bytes are fully dynamic across sessions

**Nonce-to-MAC correlation (the main finding):**

With 6 matched nonce/MAC pairs, we found 10 correlations with |r| > 0.8:

| Nonce byte | MAC byte | Correlation (r) |
|-----------|----------|-----------------|
| Nonce[3] | MAC[4] | **-0.94** |
| Nonce[4] | MAC[11] | **-0.91** |
| Nonce[5] | MAC[19] | **+0.88** |
| Nonce[5] | MAC[14] | **-0.88** |
| Nonce[4] | MAC[14] | **-0.88** |

For a well-implemented SHA-1, you would expect zero meaningful linear correlation between input and output bytes. Finding 10 strong correlations at n=6 is unusual. Possible explanations: weak key mixing, simplified hash implementation, or statistical artifact (n=6 is small).

**Encrypted payload structure:**

```
[24 bytes ciphertext] [8 bytes always 0x00] [1 byte CRC]
```

- 8/33 bytes are static across all sessions (24.2%)
- The 8 constant zero bytes are known plaintext
- No 16-byte block repeats found (ECB mode ruled out)
- Likely CBC or CTR mode

### Identified Weaknesses

| # | Weakness | Severity |
|---|----------|----------|
| 1 | System ID `V1004261` transmitted in plaintext every session | High |
| 2 | Nonce-to-MAC correlations (r = -0.94) suggest hash may have linear bias | High |
| 3 | No distance bounding, relay attack feasible (7.6ms round trip) | High |
| 4 | Key identifier bytes (27-28) visible in cleartext | Medium |
| 5 | 8 bytes of known plaintext (zero padding) in auth data | Medium |
| 6 | Protocol unchanged for 10+ years (2014 same as 2024) | Medium |
| 7 | Reject response `0x21` leaks authentication failure status | Low |

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
│   └── extended_analysis.py            # Multi-source analysis (all 23 sessions)
├── docs/
│   └── crypto_analysis.md              # Full detailed report
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
```

## What Would Strengthen This

| Additional data | What it would tell us |
|----------------|----------------------|
| 50+ captures with same key | Confirm or reject the nonce-MAC correlations with proper statistical power |
| Power trace during MAC computation | Side-channel (DPA) could extract the secret key directly |
| Captures from a revoked key | Whether the protocol changes after access revocation |
| Captures from a different system (different V-number) | Which parts are system-specific vs universal |

## Acknowledgments

**Previous research data:** University of Rostock, Faculty of Computer Science and Electrical Engineering, Chair of Information and Communication Services (IuK).
[https://www.iuk.informatik.uni-rostock.de/](https://www.iuk.informatik.uni-rostock.de/)

**Initial signal analysis and protocol decoding:** [1wire-decoder-analysis](https://github.com/towhidulahmed/1wire-decoder-analysis)

## Disclaimer

This research is conducted for academic purposes only. It is not intended to enable unauthorized access to any locking system.
