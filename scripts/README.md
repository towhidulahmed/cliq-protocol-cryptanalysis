# Scripts

Analysis scripts for the CLIQ 1-Wire protocol cryptanalysis. All scripts are Python 3, no external dependencies.

## Signal Decoding

| Script | What it does |
|--------|-------------|
| `decode_signal.py` | Core 1-Wire signal decoder. Reads logic analyzer CSV files, decodes pulse-width encoded data into bytes. |
| `analyze_captures.py` | Basic signal analysis. Decodes multiple captures, identifies protocol structure, detects 1-Wire commands, checks CRC-8 blocks. |

## Cryptanalysis

| Script | What it does |
|--------|-------------|
| `differential_cryptanalysis.py` | Differential cryptanalysis suite. Hamming distances, avalanche effect, XOR differentials, chi-squared tests, block cipher mode detection, correlation analysis. |
| `extended_analysis.py` | Multi-source analysis combining all 23 sessions from Uni Rostock prior research and 2024 Saleae captures. Protocol-aware field extraction. |
| `advanced_critique_analysis.py` | Bonferroni correction for multiple hypothesis testing, CRC-16 verification on MAC bytes, SAC vs output independence analysis, AES block mode determination. |

## Verification Scripts

| Script | What it does |
|--------|-------------|
| `crc_bruteforce.py` | Brute-force search over 2^17 CRC-8 variants to identify the trailing checksum byte algorithm. Uses algebraic shortcut for fast search. |
| `statistical_analysis.py` | Exact p-values via regularized incomplete beta function, explicit power analysis (Fisher z-transformation), disjoint-pair chi-squared test. Verifies which command bytes actually appear in the protocol. |

## Image Generation

| Script | What it does |
|--------|-------------|
| `generate_images.py` | Generates `assets/protocol_flow.png` and `assets/aes_block_alignment.png`. Classic style: white background, monospace font, black text. |

## Usage

```bash
python3 scripts/analyze_captures.py
python3 scripts/differential_cryptanalysis.py
python3 scripts/extended_analysis.py
python3 scripts/advanced_critique_analysis.py
python3 scripts/crc_bruteforce.py
python3 scripts/statistical_analysis.py
python3 scripts/generate_images.py
```

Scripts write JSON output files to the repo root: `crypto_analysis_results.json`, `critique_analysis_results.json`, `crc_bruteforce_results.json`, `statistical_analysis_results.json`.
