#!/usr/bin/env python3
"""
1-Wire Signal Decoder
Reads logic analyzer CSV captures (Time [s], Channel) and decodes the CLIQ
key <-> cylinder exchange into validated packets.

Pulse timing (width of the low pulse):
  - '1': ~4.3 us low
  - '0': ~13.7 us low
  - Full bit slot: ~18.75 us

Framing. The bus idles high between byte groups. Byte alignment is
re-established after every idle gap, so the single-bit busy polls the key
sends while waiting for the lock never shift the bytes that follow them.
(Concatenating all bits into one stream, as an earlier version of this file
did, misaligns every lock response by 4 bits.)

Packet format:
  Command  (key -> lock):  82 00 SEQ CMD LEN DATA[LEN] CHK
  Response (lock -> key):  84 00 SEQ STS LEN DATA[LEN] CHK
  CHK is an 8-bit additive checksum: all packet bytes sum to 0x00 mod 256.
"""

import csv
import itertools
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

CMD_PREFIX = 0x82
RSP_PREFIX = 0x84

GAP_US = 150.0          # idle time that ends a byte group
ONE_US = (3.0, 7.5)     # low-pulse width for a '1'
ZERO_US = (10.0, 20.0)  # low-pulse width for a '0'


def parse_time(value: str) -> float:
    """
    Seconds as float. Accepts relative times ('38.664624190') and absolute
    ISO 8601 times with nanosecond fractions ('2024-05-28T17:08:43.960256130+00:00'),
    which are returned as Unix time.
    """
    try:
        return float(value)
    except ValueError:
        pass
    stamp, _, frac = value.partition('.')
    digits = ''.join(itertools.takewhile(str.isdigit, frac))
    whole = datetime.fromisoformat(stamp + frac[len(digits):])
    if whole.tzinfo is None:
        whole = whole.replace(tzinfo=timezone.utc)
    return whole.timestamp() + (float('0.' + digits) if digits else 0.0)


def read_csv(file_path: str) -> List[Tuple[float, int]]:
    """Read a logic analyzer CSV file (Time, Value)."""
    data = []
    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            try:
                data.append((parse_time(row[0]), int(row[1])))
            except (ValueError, IndexError):
                continue
    return data


def decode_segments(data: List[Tuple[float, int]]) -> List[Dict]:
    """
    Split the signal into bit groups separated by idle gaps.
    Returns [{'t_start', 't_end', 'bits'}], where t_start/t_end are the times
    of the first and last bit's falling edge. Pulses outside both width
    windows are counted in 'bad_pulses' of the group they occur in.
    """
    segments = []
    cur: Optional[Dict] = None
    last_bit_t = None

    for (t0, v0), (t1, _) in zip(data, data[1:]):
        if v0 != 0:
            continue
        if cur is not None and last_bit_t is not None and (t0 - last_bit_t) * 1e6 > GAP_US:
            segments.append(cur)
            cur = None
        width = (t1 - t0) * 1e6
        if ONE_US[0] <= width <= ONE_US[1]:
            bit = '1'
        elif ZERO_US[0] <= width <= ZERO_US[1]:
            bit = '0'
        else:
            if cur is not None:
                cur['bad_pulses'] += 1
            continue
        if cur is None:
            cur = {'t_start': t0, 't_end': t0, 'bits': '', 'bad_pulses': 0}
        cur['bits'] += bit
        cur['t_end'] = t0
        last_bit_t = t0

    if cur is not None:
        segments.append(cur)
    return segments


def binary_to_bytes(binary_data: str) -> List[int]:
    """Convert binary string to byte values. LSB-first per 1-Wire spec."""
    return [int(binary_data[i:i + 8][::-1], 2)
            for i in range(0, len(binary_data) - 7, 8)]


def bytes_to_hex(data: List[int]) -> str:
    """Format byte list as hex string."""
    return ' '.join(f'{b:02X}' for b in data)


def checksum_ok(packet: List[int]) -> bool:
    """All bytes of a packet, including the trailing checksum, sum to 0 mod 256."""
    return sum(packet) & 0xFF == 0


def parse_packets(segments: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """
    Turn bit groups into packets and busy polls.

    Groups whose length is not a multiple of 8 are busy polls (the key reads
    one status bit from the lock). All other groups are concatenated into a
    timed byte stream that is parsed by header and length field.
    """
    polls = []
    stream: List[Tuple[int, float]] = []  # (byte, time of its first bit)
    for seg in segments:
        if len(seg['bits']) % 8:
            polls.append({'t': seg['t_start'], 'bits': seg['bits']})
            continue
        step = (seg['t_end'] - seg['t_start']) / max(1, len(seg['bits']) - 1)
        for i, b in enumerate(binary_to_bytes(seg['bits'])):
            stream.append((b, seg['t_start'] + 8 * i * step))

    packets = []
    i = 0
    while i + 4 < len(stream):
        prefix, second = stream[i][0], stream[i + 1][0]
        if prefix not in (CMD_PREFIX, RSP_PREFIX) or second != 0x00:
            i += 1
            continue
        length = stream[i + 4][0]
        raw = [b for b, _ in stream[i:i + length + 6]]
        complete = len(raw) == length + 6
        packets.append({
            'dir': 'cmd' if prefix == CMD_PREFIX else 'rsp',
            'seq': raw[2],
            'code': raw[3],
            'data': raw[5:5 + length],
            'raw': raw,
            'complete': complete,
            'checksum_ok': complete and checksum_ok(raw),
            't_start': stream[i][1],
            't_end': stream[min(i + length + 5, len(stream) - 1)][1],
        })
        if not complete:
            break
        i += length + 6
    return packets, polls


def process_capture(file_path: str) -> Dict:
    """Full pipeline: CSV file -> {'packets', 'polls', 'segments'}."""
    segments = decode_segments(read_csv(file_path))
    packets, polls = parse_packets(segments)
    return {'packets': packets, 'polls': polls, 'segments': segments}


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <capture.csv>')
        sys.exit(1)
    result = process_capture(sys.argv[1])
    for p in result['packets']:
        arrow = 'K->L' if p['dir'] == 'cmd' else 'L->K'
        flag = 'ok ' if p['checksum_ok'] else 'BAD'
        print(f"{p['t_start']:.6f}  {arrow}  [{flag}]  {bytes_to_hex(p['raw'])}")
    print(f"{len(result['packets'])} packets, {len(result['polls'])} busy polls")
