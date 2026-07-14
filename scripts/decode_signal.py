#!/usr/bin/env python3
"""
1-Wire Signal Decoder
Reads logic analyzer CSV captures and decodes the 1-Wire protocol signals
into binary/hex byte sequences.

Pulse timing:
  - Write '1': ~4.3 us low pulse
  - Write '0': ~13.7 us low pulse  
  - Full cycle: ~18.75 us
"""

import csv
from typing import List, Tuple


def read_csv(file_path: str) -> List[Tuple[float, int]]:
    """Read a logic analyzer CSV file (Time, Value)."""
    data = []
    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            try:
                time = float(row[0])
                value = int(row[1]) if len(row) > 1 else 0
                data.append((time, value))
            except (ValueError, IndexError):
                continue
    return data


def decode_signal(data: List[Tuple[float, int]]) -> str:
    """
    Decode 1-Wire signal transitions into a binary string.
    A low pulse of 3-7 us means '1', over 11 us means '0'.
    """
    binary = ""
    low_start = None

    for time, value in data:
        if value == 0 and low_start is None:
            low_start = time
        elif value == 1 and low_start is not None:
            duration_us = (time - low_start) * 1e6
            if 3 <= duration_us <= 7:
                binary += "1"
            elif duration_us > 11:
                binary += "0"
            low_start = None

    return binary


def binary_to_bytes(binary_data: str) -> List[int]:
    """Convert binary string to byte values. LSB-first per 1-Wire spec."""
    result = []
    for i in range(0, len(binary_data), 8):
        chunk = binary_data[i:i+8]
        if len(chunk) == 8:
            result.append(int(chunk[::-1], 2))  # reverse for LSB-first
    return result


def bytes_to_hex(data: List[int]) -> str:
    """Format byte list as hex string."""
    return ' '.join(f'{b:02X}' for b in data)


def process_capture(file_path: str) -> List[int]:
    """Full pipeline: CSV file -> decoded byte values."""
    data = read_csv(file_path)
    binary = decode_signal(data)
    return binary_to_bytes(binary)


def parse_hex_packets(file_path: str) -> List[List[int]]:
    """
    Parse the previous research packet dump format.
    Extracts hex lines and splits into individual unlock sessions.
    """
    all_bytes = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('hex:'):
                hex_str = line[4:].strip()
                for h in hex_str.split():
                    all_bytes.append(int(h, 16))

    # Split into sessions at "5A 5A" boundaries
    sessions = []
    i = 0
    while i < len(all_bytes) - 1:
        if all_bytes[i] == 0x5A and all_bytes[i+1] == 0x5A:
            start = i
            j = i + 2
            while j < len(all_bytes) - 1:
                if all_bytes[j] == 0x5A and all_bytes[j+1] == 0x5A and j - start > 50:
                    break
                j += 1
            if j >= len(all_bytes) - 1:
                j = len(all_bytes)
            session = all_bytes[start:j]
            if len(session) > 50:
                sessions.append(session)
            i = j
        else:
            i += 1

    return sessions
