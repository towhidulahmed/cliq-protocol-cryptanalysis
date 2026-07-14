# 1-Wire Protocol Cryptographic Analysis

Reverse engineering and cryptographic analysis of the ASSA ABLOY VERSO CLIQ mechatronic lock system's 1-Wire communication protocol.

This project captures and analyzes the signal exchanged between the electronic key and the lock cylinder during an unlock event. The goal is to identify the authentication and encryption mechanisms used, and to evaluate their strength.

## Background

The VERSO CLIQ system by ASSA ABLOY (branded IKON) uses a combination of mechanical and electronic security. When a key is inserted into the lock, the key's electronics communicate with the lock cylinder over a single-wire interface. If both the mechanical profile and the electronic authentication succeed, the lock can be turned.

This work extends earlier research done at the University of Rostock (see Acknowledgments).

## Repository Structure

```
.
├── data/
│   ├── captures/
│   │   ├── user1_key/          # 8 full unlock sessions from User 1's key
│   │   ├── user2_key/          # 2 full unlock sessions from User 2's key  
│   │   └── extas_comparison/   # 5 additional comparison captures
│   └── previous_research/      # Decoded packet data from earlier research (~2014)
├── scripts/
│   ├── decode_signal.py        # Core signal decoder module
│   ├── analyze_captures.py     # Basic signal analysis and cross-file comparison
│   ├── differential_cryptanalysis.py  # Full differential cryptanalysis suite
│   └── extended_analysis.py    # Multi-source analysis (all 23 sessions)
├── docs/
│   └── crypto_analysis.md      # Detailed cryptographic analysis report
└── README.md
```

## Data

All captures are CSV files from a logic analyzer. Each row is a signal transition event:

```csv
Time [s],Channel 1
5.727608843,1
5.731435167,0
```

The 1-Wire protocol uses pulse-width encoding:
- Short low pulse (~4.3 us) = logic '1'
- Long low pulse (~13.7 us) = logic '0'
- Full bit cycle = ~18.75 us

## Quick Start

All scripts are plain Python 3 with no external dependencies.

```bash
# Run the basic signal analysis
python3 scripts/analyze_captures.py

# Run differential cryptanalysis
python3 scripts/differential_cryptanalysis.py

# Run extended multi-source analysis
python3 scripts/extended_analysis.py
```

## Key Findings

- The system uses **SHA-1 challenge-response authentication** (confirmed by protocol commands and statistical analysis)
- An encrypted payload of **24 bytes** is exchanged, likely using AES-128
- The system ID (`V1004261`) is transmitted **in plaintext** in every session
- Nonce-to-MAC correlations with r = -0.94 were observed (see `docs/crypto_analysis.md`)
- The protocol has remained unchanged over a 10-year span (2014-2024 captures)

For the full analysis, read [`docs/crypto_analysis.md`](docs/crypto_analysis.md).

## Acknowledgments

The earlier research data in `data/previous_research/` was originally produced at the **University of Rostock**, Faculty of Computer Science and Electrical Engineering (*Fakultät für Informatik und Elektrotechnik*), Chair of Information and Communication Services (*Lehrstuhl für Informations- und Kommunikationsdienste*, IuK).  
Website: [https://www.iuk.informatik.uni-rostock.de/](https://www.iuk.informatik.uni-rostock.de/)

That work included signal capture, protocol decoding, and a PHP-based packet parser. The decoded packet dumps (`foo2-packets.txt`, `key1.txt`, `key2.txt`), the signal extraction tool (`dump.c`), and the protocol decoder (`patterns.php`) are included here with attribution to the original authors at the University of Rostock IuK department.

The current cryptographic analysis and the 2024 capture data were produced independently, building on the earlier foundation.

## License

This project is for academic research purposes. The previous research data is credited to the University of Rostock IuK department.

## Disclaimer

This research is conducted for academic purposes only, as part of graduate-level coursework. It is not intended to enable unauthorized access to any locking system.
