#!/usr/bin/env python3
"""
Protocol structure analysis:
  - decodes every 2024 session and reports key, key timestamp, cylinder and outcome
  - detects duplicate exports of the same recording
  - verifies the length field and the 8-bit additive checksum on every packet
  - reports the identity negotiation and the wrong-key rejections
  - compares with the 2014 University of Rostock decodes, if present locally
Output: protocol_analysis_results.json in the repo root.
"""
import json
import os
from collections import Counter

from decode_signal import bytes_to_hex
from sessions import (REPO_ROOT, load_captures, load_fragments,
                      load_previous_research, unique)

STATUS_NAMES = {0x10: 'busy', 0x11: 'ok', 0x21: 'error 0x21',
                0x23: 'error 0x23', 0x34: 'error 0x34'}
CMD_NAMES = {0x01: 'identity', 0x08: 'nonce request', 0x0A: 'encrypted block', 0x80: 'MAC'}


def negotiation(attempts):
    return '  ->  '.join(f"LEN {n} -> {STATUS_NAMES.get(st, hex(st))}" for n, st in attempts)


def main():
    print('=' * 78)
    print('PROTOCOL STRUCTURE ANALYSIS')
    print('=' * 78)
    results = {}

    sessions = load_captures()
    uniq = unique(sessions)

    print('\n--- 2024 sessions ---')
    print(f"{'file':32s} {'key cfg':7s}  {'key timestamp':19s}  cyl  nonce                    ok")
    for s in sessions:
        dup = f"  (duplicate of {s['duplicate_of']})" if s['duplicate_of'] else ''
        print(f"{s['name']:32s} {s['key_label']:7s}  {s['key_time']:%Y-%m-%d %H:%M:%S}  {s['cylinder']:3d}  "
              f"{bytes_to_hex(s['nonce'])}  {s['accepted']}{dup}")
    print(f"\nFiles: {len(sessions)}, unique recordings: {len(uniq)}")

    print('\nKeys and cylinders (unique sessions):')
    results['keys'] = {}
    for folder in sorted({s['folder'] for s in uniq}):
        g = [s for s in uniq if s['folder'] == folder]
        cfg = {bytes_to_hex(s['key_config']) for s in g}
        cyl = Counter(s['cylinder'] for s in g)
        days = sorted({s['key_time'].date().isoformat() for s in g})
        print(f"  {folder}: {len(g)} sessions, configuration block {cfg}, cylinders {dict(cyl)}, dates {days}")
        results['keys'][folder] = {'sessions': len(g), 'config': sorted(cfg),
                                   'cylinders': dict(cyl), 'dates': days}

    fragments = load_fragments()
    n_pk = sum(s['n_packets'] for s in sessions)
    n_ok = sum(s['n_checksum_ok'] for s in sessions)
    f_pk = [p for f in fragments for p in f['packets']]
    f_ok = sum(1 for p in f_pk if p['checksum_ok'])
    print(f"\nChecksum (sum of all packet bytes == 0 mod 256): sessions {n_ok}/{n_pk}, "
          f"fragments {f_ok}/{len(f_pk)}")
    results['checksum'] = {'session_packets': n_pk, 'session_ok': n_ok,
                           'fragment_packets': len(f_pk), 'fragment_ok': f_ok}

    attempts = Counter(tuple(s['identity_attempts']) for s in uniq)
    print('\nIdentity negotiation (LEN of identity command -> cylinder status):')
    for seq, n in attempts.items():
        print(f"  {n:2d} sessions: {negotiation(seq)}")
    tails = Counter(bytes_to_hex(s['auth_tail']) for s in uniq)
    print(f"\nLast 8 bytes of the 32-byte encrypted block: {dict(tails)}")
    print(f"MAC field length: {dict(Counter(len(s['mac']) for s in uniq))}")
    print(f"Accepted: {sum(s['accepted'] for s in uniq)}/{len(uniq)}")
    results['identity_negotiation'] = [{'sessions': n, 'steps': list(k)} for k, n in attempts.items()]
    results['mac_length'] = sorted({len(s['mac']) for s in uniq})
    results['accepted'] = sum(s['accepted'] for s in uniq)

    print('\n--- Wrong-key fragments (2024-08-23) ---')
    results['wrong_key'] = []
    for f in fragments:
        if 'wrong_key' not in f['name']:
            continue
        for p in f['packets']:
            print(f"  {f['analyzer_time']:%H:%M:%S}  {f['name']:44s} {bytes_to_hex(p['raw'])}")
            results['wrong_key'].append({'file': f['name'], 'raw': bytes_to_hex(p['raw'])})
        if not f['packets']:
            from decode_signal import binary_to_bytes
            data = binary_to_bytes(f['segments'][0]['bits'])
            print(f"  {f['analyzer_time']:%H:%M:%S}  {f['name']:44s} cylinder identity block, "
                  f"cylinder number {data[17] | data[18] << 8}")
            results['wrong_key'].append({'file': f['name'], 'cylinder': data[17] | data[18] << 8})

    prev = load_previous_research()
    print('\n--- 2014 University of Rostock decodes (local only) ---')
    if prev is None:
        print('  Not available. The 2014 data is not part of this repository.')
        results['previous_research'] = None
    else:
        p_pk = sum(s['n_packets'] for s in prev)
        p_ok = sum(s['n_checksum_ok'] for s in prev)
        outcome = Counter()
        for s in prev:
            if s['accepted']:
                outcome['accepted'] += 1
            elif s['errors']:
                code, st = s['errors'][-1]
                outcome[f"{STATUS_NAMES.get(st, hex(st))} after {CMD_NAMES.get(code, hex(code))}"] += 1
            elif s['mac'] is not None:
                outcome['final status not captured'] += 1
            else:
                outcome['aborted before the nonce'] += 1
        cfg = {bytes_to_hex(s['key_config']) for s in prev}
        cyl = {s['cylinder'] for s in prev}
        days = sorted({s['key_time'].date().isoformat() for s in prev})
        p_attempts = Counter(tuple(s['identity_attempts']) for s in prev)
        print(f"  Sessions: {len(prev)}; checksum valid: {p_ok}/{p_pk} packets")
        print(f"  Outcomes: {dict(outcome)}")
        print(f"  Key configuration block: {cfg}; cylinder numbers: {cyl}; key dates: {days}")
        print('  Identity negotiation: ' + '; '.join(f"{n} x {negotiation(k)}" for k, n in p_attempts.items()))
        results['previous_research'] = {
            'sessions': len(prev), 'packets': p_pk, 'checksum_ok': p_ok,
            'outcomes': dict(outcome), 'key_config': sorted(cfg), 'cylinders': sorted(cyl),
            'dates': days,
            'identity_negotiation': [{'sessions': n, 'steps': list(k)} for k, n in p_attempts.items()],
        }

    out = os.path.join(REPO_ROOT, 'protocol_analysis_results.json')
    with open(out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\nSaved: {out}')


if __name__ == '__main__':
    main()
