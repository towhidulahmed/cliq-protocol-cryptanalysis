# Previous Research Attribution

The 2014 protocol-level research data referenced in this repository was originally produced at the **University of Rostock**:

- **Faculty:** Fakultät für Informatik und Elektrotechnik (Faculty of Computer Science and Electrical Engineering)
- **Department:** Lehrstuhl für Informations- und Kommunikationsdienste (Chair of Information and Communication Services, IuK)
- **Website:** https://www.iuk.informatik.uni-rostock.de/
- **University:** https://www.uni-rostock.de/

## Data Availability

The raw 2014 research data (decoded packet dumps, protocol decoder source code, and signal extraction tools) is **not included** in this repository, as it is not the author's work. Researchers who need access to the original 2014 data should contact the University of Rostock IuK department directly.

The cryptographic values (nonces, MACs, encrypted payloads) used in the statistical analysis are hardcoded in `scripts/advanced_critique_analysis.py` for reproducibility. These were extracted from the 2014 captures during the author's analysis work.

## Context

The 2014 Uni Rostock IuK research was used as a reference study during the author's masters research at the University of Rostock in 2024. The researchers at Uni Rostock developed the initial signal capture setup (ADC + USB-FIFO + Arduino), decoded the 1-Wire communication, and identified the basic protocol structure.

The 2024 captures included in `data/captures/` are the author's own work.
