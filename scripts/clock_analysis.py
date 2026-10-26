#!/usr/bin/env python3
"""
Key clock analysis.

Identity bytes 22-26 carry the key's date and time: a day counter
(day 1 = 2000-01-01), the minute of the day and the second. This script
  - decodes the timestamp of every session and identity fragment
  - checks the field ranges (minute < 1440, second < 60)
  - compares the key time with the logic analyzer's wall clock where the
    CSV export kept absolute timestamps, including before and after the key
    was re-programmed on 2024-08-18
  - decodes the 2014 timestamps, if the 2014 decodes are present locally
Output: clock_analysis_results.json in the repo root.
"""
import json
import os

from sessions import (REPO_ROOT, identity_fields, load_captures, load_fragments,
                      load_previous_research, unique)


def main():
    print('=' * 78)
    print('KEY CLOCK ANALYSIS')
    print('=' * 78)
    results = {'samples': []}

    samples = []
    for s in unique(load_captures()):
        samples.append({'source': s['name'], 'key': s['folder'], 'fields': identity_fields(s['identity']),
                        'analyzer_time': s['analyzer_time']})
    for f in load_fragments():
        for p in f['packets']:
            if p['dir'] == 'cmd' and p['code'] == 0x01:
                samples.append({'source': 'fragments/' + f['name'], 'key': 'key_a',
                                'fields': identity_fields(p['data']), 'analyzer_time': f['analyzer_time']})
                break
    samples.sort(key=lambda x: x['fields']['key_time'])

    print(f"\n{'source':52s} {'day':>5s} {'min':>5s} {'s':>3s}  key time             analyzer time        offset")
    for x in samples:
        day, minute, second = x['fields']['key_time_raw']
        kt = x['fields']['key_time']
        at = x['analyzer_time']
        off = (kt - at).total_seconds() if at else None
        print(f"{x['source']:52s} {day:5d} {minute:5d} {second:3d}  {kt:%Y-%m-%d %H:%M:%S}  "
              f"{at.strftime('%Y-%m-%d %H:%M:%S') if at else '-':19s}  "
              f"{f'{off:+.0f} s' if off is not None else '-'}")
        results['samples'].append({'source': x['source'], 'key': x['key'], 'raw': [day, minute, second],
                                   'key_time': kt.isoformat(),
                                   'analyzer_time': at.isoformat() if at else None,
                                   'offset_s': off})

    raws = [x['fields']['key_time_raw'] for x in samples]
    in_range = all(m < 1440 and s < 60 for _, m, s in raws)
    paired = [r for r in results['samples'] if r['offset_s'] is not None]
    print(f"\nAll minute values < 1440 and second values < 60: {in_range} ({len(raws)} samples)")
    print(f"Samples with analyzer wall-clock time: {len(paired)}; "
          f"|offset| ranges {min(abs(r['offset_s']) for r in paired):.0f}-"
          f"{max(abs(r['offset_s']) for r in paired):.0f} s")
    results['fields_in_range'] = in_range

    print('\nRe-programming on 2024-08-18 (key_a):')
    before = [r for r in paired if r['key_time'].startswith('2024-08-18') and r['key_time'] < '2024-08-18T19:50']
    after = [r for r in paired if r['key_time'].startswith('2024-08-18') and r['key_time'] > '2024-08-18T19:50']
    for label, group in (('before', before), ('after', after)):
        offs = [r['offset_s'] for r in group]
        print(f"  {label:6s}: {len(group)} samples, offset {min(offs):+.0f} to {max(offs):+.0f} s")
    results['reprogramming'] = {'before': [r['offset_s'] for r in before],
                                'after': [r['offset_s'] for r in after]}

    prev = load_previous_research()
    print('\n2014 University of Rostock decodes (local only):')
    if prev is None:
        print('  Not available. The 2014 data is not part of this repository.')
        results['previous_research'] = None
    else:
        times = sorted(s['key_time'] for s in prev)
        print(f"  {len(times)} identity timestamps from {times[0]:%Y-%m-%d %H:%M:%S} to {times[-1]:%Y-%m-%d %H:%M:%S}")
        print(f"  Dates: {sorted({t.date().isoformat() for t in times})}")
        results['previous_research'] = {'first': times[0].isoformat(), 'last': times[-1].isoformat(),
                                        'dates': sorted({t.date().isoformat() for t in times})}

    out = os.path.join(REPO_ROOT, 'clock_analysis_results.json')
    with open(out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\nSaved: {out}')


if __name__ == '__main__':
    main()
