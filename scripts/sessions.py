#!/usr/bin/env python3
"""
Session extraction for the CLIQ protocol.

Turns decoded packets into one record per unlock session (identity fields,
key timestamp, cylinder number, nonce, encrypted block, MAC, outcome,
timing) and flags duplicate exports of the same recording.

Data sources:
  - data/captures/key_a/, key_b/  : complete 2024 unlock sessions, one file each
  - data/captures/fragments/      : partial 2024 captures (identity packets with
                                    wall-clock time, wrong-key rejections)
  - data/local_previous_research/ : 2014 University of Rostock decodes. Not part
                                    of this repository; used only if present.
"""

import datetime
import glob
import os
import re
from typing import Dict, List, Optional

from decode_signal import RSP_PREFIX, checksum_ok, process_capture

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
CAPTURE_DIR = os.path.join(REPO_ROOT, 'data', 'captures')
PREVIOUS_DIR = os.path.join(REPO_ROOT, 'data', 'local_previous_research')
PREVIOUS_FILES = ['decoded_unlock_sessions.txt', 'session_key_a.txt', 'session_key_b.txt']

# Command codes (key -> lock)
CMD_IDENTITY = 0x01
CMD_NONCE = 0x08
CMD_AUTH = 0x0A
CMD_MAC = 0x80
# Status codes (lock -> key)
STS_BUSY = 0x10
STS_OK = 0x11

# Day 1 of the key's day counter is 2000-01-01.
DAY_ZERO = datetime.datetime(1999, 12, 31)
# Local time of the installation during all 2024 captures (CEST).
LOCAL_TZ = datetime.timezone(datetime.timedelta(hours=2))


def build_session(packets: List[Dict]) -> Dict:
    """Collect the protocol fields of one unlock session from its packets."""
    s = {
        'identity_attempts': [],   # [(LEN, status of the lock's reply)]
        'identity': None,          # data of the accepted identity command
        'lock_identity': None,
        'nonce': None,
        'ciphertext': None,
        'auth_tail': None,
        'mac': None,
        'errors': [],              # [(command code, status)]
        'accepted': False,
        'n_packets': len(packets),
        'n_checksum_ok': sum(1 for p in packets if p['checksum_ok']),
    }
    last_cmd = None
    for p in packets:
        if p['dir'] == 'cmd':
            last_cmd = p
            if p['code'] == CMD_AUTH and len(p['data']) == 32:
                s['ciphertext'] = p['data'][:24]
                s['auth_tail'] = p['data'][24:]
            elif p['code'] == CMD_MAC:
                s['mac'] = p['data']
            continue
        if p['code'] == STS_BUSY or last_cmd is None:
            continue
        code = last_cmd['code']
        if code == CMD_IDENTITY:
            s['identity_attempts'].append((last_cmd['raw'][4], p['code']))
        if p['code'] != STS_OK:
            s['errors'].append((code, p['code']))
            continue
        if code == CMD_IDENTITY:
            s['identity'] = last_cmd['data']
            s['lock_identity'] = p['data']
        elif code == CMD_NONCE and len(p['data']) == 8:
            s['nonce'] = p['data']
        elif code == CMD_MAC:
            s['accepted'] = True
    return s


def identity_fields(identity: List[int]) -> Dict:
    """
    Fields of an identity command (27-byte layout, the 29-byte layout adds
    two bytes at the end):
      [0]      0x03
      [1:9]    system ID, ASCII
      [9:16]   padding 0x1E
      [16:22]  key configuration block (constant per key)
      [22:24]  day counter, 16-bit little-endian, day 1 = 2000-01-01
      [24:26]  minute of the day, 16-bit little-endian, local time
      [26]     second
    """
    day = identity[22] | (identity[23] << 8)
    minute = identity[24] | (identity[25] << 8)
    second = identity[26]
    return {
        'system_id': bytes(identity[1:9]).decode('ascii', 'replace'),
        'key_config': identity[16:22],
        'key_label': f'{identity[19]:02X} {identity[20]:02X}',
        'key_time': DAY_ZERO + datetime.timedelta(days=day, minutes=minute, seconds=second),
        'key_time_raw': (day, minute, second),
    }


def cylinder_number(lock_identity: List[int]) -> int:
    """16-bit little-endian number at offsets 17-18 of the cylinder's identity block."""
    return lock_identity[17] | (lock_identity[18] << 8)


def session_timing(result: Dict) -> Dict:
    """Total duration and busy-poll statistics of one capture."""
    packets, polls = result['packets'], result['polls']
    t0 = packets[0]['t_start']
    t1 = packets[-1]['t_end']
    waits = []
    last_cmd = None
    for prev, nxt in zip(packets, packets[1:]):
        if prev['dir'] == 'cmd':
            last_cmd = prev
        inside = [q['t'] for q in polls if prev['t_end'] < q['t'] < nxt['t_start']]
        if inside and last_cmd is not None:
            waits.append({'after_seq': last_cmd['seq'], 'after_code': last_cmd['code'],
                          'polls': len(inside), 'ms': (nxt['t_start'] - prev['t_end']) * 1e3})
    poll_t = sorted(q['t'] for q in polls)
    intervals = [(b - a) * 1e3 for a, b in zip(poll_t, poll_t[1:]) if (b - a) * 1e3 < 2.0]
    return {
        'total_ms': (t1 - t0) * 1e3,
        'waits': waits,
        'poll_interval_ms': sum(intervals) / len(intervals) if intervals else None,
    }


def wall_clock(t: float) -> Optional[datetime.datetime]:
    """Analyzer time as local datetime, if the export used absolute timestamps."""
    if t < 1e9:
        return None
    return datetime.datetime.fromtimestamp(t, LOCAL_TZ).replace(tzinfo=None)


def load_captures() -> List[Dict]:
    """Decode every complete 2024 session. Duplicate exports are flagged, not dropped."""
    sessions = []
    for path in sorted(glob.glob(os.path.join(CAPTURE_DIR, 'key_*', '*.csv'))):
        result = process_capture(path)
        s = build_session(result['packets'])
        s['name'] = os.path.relpath(path, CAPTURE_DIR)
        s['folder'] = s['name'].split(os.sep)[0]
        s['timing'] = session_timing(result)
        s['analyzer_time'] = wall_clock(result['packets'][0]['t_start'])
        if s['identity']:
            s.update(identity_fields(s['identity']))
        if s['lock_identity']:
            s['cylinder'] = cylinder_number(s['lock_identity'])
        sessions.append(s)

    seen = {}
    for s in sessions:
        key = bytes(s['nonce']) if s['nonce'] else s['name']
        s['duplicate_of'] = seen.get(key)
        seen.setdefault(key, s['name'])
    return sessions


def load_fragments() -> List[Dict]:
    """Decode the partial captures in data/captures/fragments/."""
    out = []
    for path in sorted(glob.glob(os.path.join(CAPTURE_DIR, 'fragments', '*.csv'))):
        result = process_capture(path)
        out.append({'name': os.path.basename(path), 'packets': result['packets'],
                    'segments': result['segments'],
                    'analyzer_time': wall_clock(result['segments'][0]['t_start'])
                    if result['segments'] else None})
    return out


def unique(sessions: List[Dict]) -> List[Dict]:
    return [s for s in sessions if s['duplicate_of'] is None]


def load_previous_research() -> Optional[List[Dict]]:
    """
    Parse the local 2014 decodes into sessions, or return None if the folder
    is absent. The 2014 decodes list lock responses without the 0x84 byte
    seen in the 2024 captures; it is re-inserted so both years share one
    packet model.
    """
    files = [os.path.join(PREVIOUS_DIR, f) for f in PREVIOUS_FILES]
    if not all(os.path.exists(f) for f in files):
        return None

    sessions = []
    for path in files:
        current: List[Dict] = []
        for line in open(path, errors='ignore'):
            m = re.match(r'\s*hex:\s*((?:[0-9a-fA-F]{2}\s*)+)$', line)
            if not m:
                continue
            raw = [int(x, 16) for x in m.group(1).split()]
            if raw[0] == 0x5A:
                if any(p['dir'] == 'cmd' for p in current):
                    sessions.append(current)
                    current = []
                continue
            if raw[0] == 0x82 and len(raw) >= 6:
                d = 'cmd'
            elif raw[0] == 0x00 and len(raw) >= 5:
                d, raw = 'rsp', [RSP_PREFIX] + raw
            else:
                continue
            length = raw[4]
            current.append({'dir': d, 'seq': raw[2], 'code': raw[3],
                            'data': raw[5:5 + length], 'raw': raw,
                            'complete': len(raw) == length + 6,
                            'checksum_ok': len(raw) == length + 6 and checksum_ok(raw)})
        if any(p['dir'] == 'cmd' for p in current):
            sessions.append(current)

    out = []
    for packets in sessions:
        s = build_session(packets)
        s['packets'] = packets
        if s['identity']:
            s.update(identity_fields(s['identity']))
        if s['lock_identity']:
            s['cylinder'] = cylinder_number(s['lock_identity'])
        out.append(s)
    return out
