#!/usr/bin/env python3
"""
Timing analysis of the 2024 captures:
  - duration of the unlock exchange (first to last packet)
  - busy polling: the key reads one status bit from the lock at a fixed
    interval until the lock has a reply ready; the number of polls per
    step is how long the key was willing to wait
  - comparison of the two keys and the two cylinders
These numbers bound the latency a relay between key and cylinder must hide.
Output: timing_analysis_results.json in the repo root.
"""
import json
import os
import statistics

from sessions import REPO_ROOT, load_captures, unique

STEP_NAMES = {0x01: 'identity', 0x08: 'nonce request', 0x0A: 'encrypted block', 0x80: 'MAC'}


def summary(values):
    return {'min': min(values), 'max': max(values), 'mean': statistics.mean(values),
            'stdev': statistics.stdev(values) if len(values) > 1 else 0.0}


def main():
    print('=' * 78)
    print('TIMING ANALYSIS')
    print('=' * 78)
    uniq = unique(load_captures())
    results = {'sessions': {}, 'groups': {}, 'waits': {}}

    print(f"\n{'session':32s} {'cyl':>4s} {'total ms':>9s} {'poll ms':>8s}  polls per wait (after: identity, nonce req, encrypted block, MAC)")
    for s in uniq:
        t = s['timing']
        polls = [w['polls'] for w in t['waits']]
        print(f"{s['name']:32s} {s['cylinder']:4d} {t['total_ms']:9.1f} {t['poll_interval_ms']:8.4f}  {polls}")
        results['sessions'][s['name']] = {'total_ms': t['total_ms'], 'poll_interval_ms': t['poll_interval_ms'],
                                          'waits': t['waits']}

    print('\nPer key and cylinder:')
    for key, cyl in sorted({(s['folder'], s['cylinder']) for s in uniq}):
        g = [s for s in uniq if s['folder'] == key and s['cylinder'] == cyl]
        tot = summary([s['timing']['total_ms'] for s in g])
        poll = summary([s['timing']['poll_interval_ms'] for s in g])
        print(f"  {key} at cylinder {cyl:3d}: n={len(g):2d}  total {tot['min']:.1f}-{tot['max']:.1f} ms  "
              f"poll interval {poll['mean']:.4f} ms (sd {poll['stdev']:.4f})")
        results['groups'][f'{key}/cylinder {cyl}'] = {'n': len(g), 'total_ms': tot, 'poll_interval_ms': poll}

    print('\nWaiting time per step (all unique sessions):')
    by_step = {}
    for s in uniq:
        for w in s['timing']['waits']:
            by_step.setdefault(w['after_code'], []).append(w)
    for code, ws in by_step.items():
        polls = sorted({w['polls'] for w in ws})
        ms = summary([w['ms'] for w in ws])
        print(f"  after {STEP_NAMES.get(code, hex(code)):13s}: {polls} polls, {ms['min']:.2f}-{ms['max']:.2f} ms")
        results['waits'][STEP_NAMES.get(code, hex(code))] = {'polls': polls, 'ms': ms}

    totals = [s['timing']['total_ms'] for s in uniq]
    print(f"\nUnlock exchange duration: {min(totals):.1f}-{max(totals):.1f} ms")
    print('The number of polls varies between sessions for the same step, so the key')
    print('accepts a variable reply delay from the cylinder. The maximum delay the key')
    print('tolerates before aborting has not been measured.')

    out = os.path.join(REPO_ROOT, 'timing_analysis_results.json')
    with open(out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\nSaved: {out}')


if __name__ == '__main__':
    main()
