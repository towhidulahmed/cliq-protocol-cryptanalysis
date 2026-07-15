# Previous Research Attribution

The files in this directory were originally produced at the **University of Rostock**:

- **Faculty:** Fakultät für Informatik und Elektrotechnik (Faculty of Computer Science and Electrical Engineering)
- **Department:** Lehrstuhl für Informations- und Kommunikationsdienste (Chair of Information and Communication Services, IuK)
- **Website:** https://www.iuk.informatik.uni-rostock.de/
- **University:** https://www.uni-rostock.de/

## Files

| File | Description |
|------|-------------|
| `decoded_unlock_sessions.txt` | 6 decoded unlock sessions showing full hex + ASCII packet data |
| `session_key_a.txt` | Decoded session from a second key (including raw bit-level data) |
| `session_key_b.txt` | Another decoded session from that second key |
| `protocol_decoder.php` | Protocol decoder with pulse-width pattern matching and CRC-8 |
| `signal_extractor.c` | C program for extracting signal transitions from raw ADC captures |

## Context

This research was conducted as part of an investigation into the ASSA ABLOY VERSO CLIQ locking system. The researchers at Uni Rostock developed the initial signal capture setup (ADC + USB-FIFO + Arduino), decoded the 1-Wire communication, and identified the basic protocol structure.

Their work established the foundation on which the current cryptographic analysis builds.
