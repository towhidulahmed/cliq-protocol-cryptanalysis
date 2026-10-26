# Scripts

Analysis scripts for the CLIQ key-cylinder protocol. The analysis scripts are Python 3 with no external dependencies; `generate_images.py` needs Playwright with Chromium (`pip install playwright && python3 -m playwright install chromium`).

## Decoding

| Script | What it does |
|--------|-------------|
| `decode_signal.py` | Reads a logic-analyzer CSV (relative or absolute ISO 8601 timestamps), decodes pulse widths into bits, splits on idle gaps so busy polls never shift byte alignment, parses packets and checks the length field and checksum. Run on one file to print its packets. |
| `sessions.py` | Builds one record per unlock session: identity fields, key timestamp, cylinder number, nonce, encrypted block, MAC, outcome and timing. Flags duplicate recordings, loads the fragments, and loads the 2014 comparison decodes if they exist locally. |

## Analysis

| Script | What it does |
|--------|-------------|
| `protocol_analysis.py` | Session table, keys and cylinders, checksum verification, identity negotiation, wrong-key rejections, 2014 comparison. |
| `clock_analysis.py` | Decodes the key's date and time from every identity packet, checks the field ranges, and compares it with the analyzer's wall clock (including before and after re-programming). |
| `timing_analysis.py` | Exchange duration, busy-poll period and poll counts per step, per key and cylinder. |
| `statistical_analysis.py` | Bit balance (overall and per bit position), Hamming distances and constant positions of nonce, encrypted block and MAC; keystream-reuse test; same-key vs cross-key MAC distance; byte correlations with exact p-values, Bonferroni correction, power analysis, and replication in the 2014 sample. |

## Figures

| Script | What it does |
|--------|-------------|
| `generate_images.py` | Lays out `assets/protocol_flow.png` (unlock sequence diagram) and `assets/packet_format.png` (packet and field layout) as HTML from the decoded sessions and renders them to PNG at 2x. `--html` also writes the HTML sources. |

## Usage

```bash
python3 scripts/decode_signal.py data/captures/key_a/2024-06-11_17-39-27.csv
python3 scripts/protocol_analysis.py
python3 scripts/clock_analysis.py
python3 scripts/timing_analysis.py
python3 scripts/statistical_analysis.py
python3 scripts/generate_images.py
```

Each analysis script writes a `*_results.json` file to the repo root (not tracked).

## 2014 comparison data

`sessions.load_previous_research()` reads the 2014 University of Rostock decodes from `data/local_previous_research/` if that folder exists. The folder is git-ignored and its files are not part of this repository; without it, the 2014 sections are skipped.
