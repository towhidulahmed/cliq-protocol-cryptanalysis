#!/usr/bin/env python3
"""
Statistical analysis of the protocol fields of the 2024 unlock sessions
(one entry per unique recording):
  - nonce, ciphertext and MAC: bit balance and pairwise Hamming distance
  - constant byte positions, overall and per key
  - test whether the first 8 ciphertext bytes are the nonce XOR a fixed
    keystream (would indicate keystream reuse)
  - same-key vs cross-key MAC distance
  - nonce-to-MAC / nonce-to-ciphertext byte correlations with exact
    Student's t p-values, Bonferroni correction and power analysis
If the 2014 University of Rostock decodes exist locally, the same summary
numbers are also computed with them included. Only aggregates are reported.
Output: statistical_analysis_results.json in the repo root.
"""
import json
import math
import os
from itertools import combinations

from sessions import REPO_ROOT, load_captures, load_previous_research, unique


# Exact t-distribution via regularized incomplete beta
def log_beta(a, b):
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)

def _betacf(a, b, x):
    MAXIT = 200; EPS = 3.0e-12; FPMIN = 1.0e-300
    qab = a + b; qap = a + 1.0; qam = a - 1.0
    c = 1.0; d = 1.0 - qab * x / qap
    if abs(d) < FPMIN: d = FPMIN
    d = 1.0 / d; h = d
    for m in range(1, MAXIT + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN: d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN: c = FPMIN
        d = 1.0 / d; delta = d * c; h *= delta
        if abs(delta - 1.0) < EPS: break
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN: d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN: c = FPMIN
        d = 1.0 / d; delta = d * c; h *= delta
        if abs(delta - 1.0) < EPS: break
    return h

def betainc_reg(a, b, x):
    if x <= 0: return 0.0
    if x >= 1: return 1.0
    lbeta = log_beta(a, b)
    if x < (a + 1.0) / (a + b + 2.0):
        bt = math.exp(math.log(x) * a + math.log(1.0 - x) * b - lbeta) / a
        return bt * _betacf(a, b, x)
    else:
        bt = math.exp(math.log(1.0 - x) * b + math.log(x) * a - lbeta) / b
        return 1.0 - bt * _betacf(b, a, 1.0 - x)

def t_sf_two_sided(t, df):
    if df <= 0: raise ValueError("df must be positive")
    x = df / (df + t * t)
    return betainc_reg(df / 2.0, 0.5, x)

def pearson(x, y):
    n = len(x)
    if n < 3: return 0.0
    mx = sum(x)/n; my = sum(y)/n
    num = sum((xi-mx)*(yi-my) for xi, yi in zip(x, y))
    dx = math.sqrt(sum((xi-mx)**2 for xi in x))
    dy = math.sqrt(sum((yi-my)**2 for yi in y))
    if dx == 0 or dy == 0: return 0.0
    return num / (dx * dy)

def inverse_norm_cdf(p):
    a = [-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00]
    plow = 0.02425; phigh = 1 - plow
    if p < plow:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
               ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    if p <= phigh:
        q = p - 0.5; r = q * q
        return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q / \
               (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1)
    q = math.sqrt(-2 * math.log(1 - p))
    return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
            ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)

def norm_cdf(z):
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))

# Minimum detectable |r| via Fisher z
def min_detectable_r(n, alpha, power):
    z_a = inverse_norm_cdf(1 - alpha / 2)
    z_b = inverse_norm_cdf(power)
    se = 1.0 / math.sqrt(n - 3) if n > 3 else float('inf')
    return math.tanh((z_a + z_b) * se)

def power_for_r(n, alpha, r_true):
    z_a = inverse_norm_cdf(1 - alpha / 2)
    z_r = math.atanh(r_true)
    se = 1.0 / math.sqrt(n - 3) if n > 3 else float('inf')
    return (1 - norm_cdf(z_a - z_r/se)) + norm_cdf(-z_a - z_r/se)


def bits(data):
    return [(b >> i) & 1 for b in data for i in range(8)]


def hamming(a, b):
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def bit_balance(fields):
    """Fraction of one-bits and its z-score against p = 0.5."""
    allbits = [x for f in fields for x in bits(f)]
    n = len(allbits)
    ones = sum(allbits)
    return {'n_bits': n, 'ones_fraction': ones / n, 'z': (ones - n / 2) / math.sqrt(n / 4)}


def pairwise_distance(fields):
    """Mean pairwise Hamming distance as a fraction of the field length."""
    nbits = len(fields[0]) * 8
    d = [hamming(a, b) / nbits for a, b in combinations(fields, 2)]
    return {'pairs': len(d), 'mean_fraction': sum(d) / len(d), 'min': min(d), 'max': max(d)}


def constant_positions(fields):
    return [i for i in range(len(fields[0])) if len({f[i] for f in fields}) == 1]


def bit_positions(fields):
    """Per-bit-position bias: smallest two-sided p (normal approximation with
    continuity correction) and the number of positions below the Bonferroni level."""
    n = len(fields)
    n_pos = len(fields[0]) * 8
    ps = []
    for pos in range(n_pos):
        k = sum((f[pos // 8] >> (pos % 8)) & 1 for f in fields)
        z = (abs(k - n / 2) - 0.5) / math.sqrt(n / 4)
        ps.append(math.erfc(max(z, 0.0) / math.sqrt(2)))
    alpha = 0.05 / n_pos
    return {'positions': n_pos, 'min_p': min(ps), 'alpha_bonferroni': alpha,
            'significant': sum(1 for p in ps if p < alpha)}


def field_summary(name, fields):
    bal = bit_balance(fields)
    dist = pairwise_distance(fields)
    const = constant_positions(fields)
    pos = bit_positions(fields)
    uniq_vals = len({bytes(f) for f in fields})
    print(f"  {name:10s} n={len(fields):2d}  unique={uniq_vals:2d}  ones={bal['ones_fraction']:.4f} "
          f"(z={bal['z']:+.2f})  pairwise HD={dist['mean_fraction']*100:.1f}% "
          f"[{dist['min']*100:.1f}-{dist['max']*100:.1f}]  constant bytes={const}  "
          f"biased bit positions={pos['significant']}/{pos['positions']} (min p={pos['min_p']:.4f})")
    return {'n': len(fields), 'unique': uniq_vals, 'bit_balance': bal,
            'pairwise_distance': dist, 'constant_positions': const, 'bit_positions': pos}


def correlations(xs, ys, x_name, y_name):
    n = len(xs)
    df = n - 2
    n_tests = len(xs[0]) * len(ys[0])
    alpha_bonf = 0.05 / n_tests
    out = []
    for i in range(len(xs[0])):
        xv = [float(x[i]) for x in xs]
        for j in range(len(ys[0])):
            yv = [float(y[j]) for y in ys]
            r = pearson(xv, yv)
            t = r * math.sqrt(df) / math.sqrt(1 - r * r) if abs(r) < 1.0 else math.copysign(1e30, r)
            p = t_sf_two_sided(t, df)
            out.append({'x': i, 'y': j, 'r': r, 'p': p, 'p_bonf': min(1.0, p * n_tests)})
    out.sort(key=lambda c: abs(c['r']), reverse=True)
    n_unc = sum(1 for c in out if c['p'] < 0.05)
    n_bonf = sum(1 for c in out if c['p_bonf'] < 0.05)
    r80 = min_detectable_r(n, alpha_bonf, 0.80)
    top = out[0]
    print(f"  {x_name}->{y_name}: n={n}, {n_tests} tests, uncorrected p<0.05: {n_unc} "
          f"(chance: {0.05*n_tests:.1f}), Bonferroni-significant: {n_bonf}, "
          f"strongest r={top['r']:+.3f} ({x_name}[{top['x']}], {y_name}[{top['y']}]), "
          f"min detectable |r| at 80% power={r80:.3f}")
    return {'n': n, 'tests': n_tests, 'alpha_bonferroni': alpha_bonf,
            'uncorrected_significant': n_unc, 'expected_by_chance': 0.05 * n_tests,
            'bonferroni_significant': n_bonf, 'strongest': top,
            'min_detectable_r_80pct_power': r80}


def replicate(pair, xs, ys, label):
    """Correlation of one byte pair in an independent sample."""
    r = pearson([float(x[pair['x']]) for x in xs], [float(y[pair['y']]) for y in ys])
    print(f"  replication of strongest {label} pair in 2014 data: r={r:+.3f} (n={len(xs)}; "
          f"2024: r={pair['r']:+.3f})")
    return {'r': r, 'n': len(xs)}


def main():
    print('=' * 78)
    print('STATISTICAL ANALYSIS')
    print('=' * 78)
    results = {}
    uniq = unique(load_captures())
    nonces = [s['nonce'] for s in uniq]
    cts = [s['ciphertext'] for s in uniq]
    macs = [s['mac'] for s in uniq]

    print(f"\n--- Field statistics, 2024 captures ({len(uniq)} unique sessions) ---")
    results['fields'] = {
        'nonce': field_summary('nonce', nonces),
        'ciphertext': field_summary('ciphertext', cts),
        'mac': field_summary('mac', macs),
    }

    print('\n--- Per key ---')
    groups = {}
    for s in uniq:
        groups.setdefault(s['folder'], []).append(s)
    results['groups'] = {}
    for kid, g in groups.items():
        print(f"  {kid}:")
        results['groups'][kid] = {
            'ciphertext': field_summary('ciphertext', [s['ciphertext'] for s in g]),
            'mac': field_summary('mac', [s['mac'] for s in g]),
        }

    print('\n--- Keystream-reuse test: ciphertext[0:8] XOR nonce, per key ---')
    results['keystream_reuse'] = {}
    for kid, g in groups.items():
        x = {bytes(a ^ b for a, b in zip(s['ciphertext'][:8], s['nonce'])) for s in g}
        reused = len(x) < len(g)
        print(f"  {kid}: {len(x)} distinct values over {len(g)} sessions -> "
              f"{'REUSE' if reused else 'no fixed keystream'}")
        results['keystream_reuse'][kid] = {'sessions': len(g), 'distinct': len(x), 'reuse': reused}

    print('\n--- MAC distance: same key vs cross key ---')
    same, cross = [], []
    for a, b in combinations(uniq, 2):
        d = hamming(a['mac'], b['mac']) / (len(a['mac']) * 8)
        (same if a['folder'] == b['folder'] else cross).append(d)
    print(f"  same key:  {len(same):3d} pairs, mean {sum(same)/len(same)*100:.1f}%")
    print(f"  cross key: {len(cross):3d} pairs, mean {sum(cross)/len(cross)*100:.1f}%")
    results['mac_same_vs_cross'] = {'same_pairs': len(same), 'same_mean': sum(same) / len(same),
                                    'cross_pairs': len(cross), 'cross_mean': sum(cross) / len(cross)}

    print('\n--- Byte correlations (Pearson, exact t, Bonferroni) ---')
    results['correlations'] = {
        'nonce_mac': correlations(nonces, macs, 'nonce', 'MAC'),
        'nonce_ciphertext': correlations(nonces, cts, 'nonce', 'ciphertext'),
    }

    prev = load_previous_research()
    print('\n--- Including 2014 University of Rostock decodes (local only, aggregates) ---')
    if prev is None:
        print('  Not available. The 2014 data is not part of this repository.')
        results['with_previous_research'] = None
    else:
        p_n = [s['nonce'] for s in prev if s['nonce']]
        p_c = [s['ciphertext'] for s in prev if s['ciphertext']]
        p_m = [s['mac'] for s in prev if s['mac']]
        overlap = {
            'nonce': len({bytes(x) for x in p_n} & {bytes(x) for x in nonces}),
            'ciphertext': len({bytes(x) for x in p_c} & {bytes(x) for x in cts}),
            'mac': len({bytes(x) for x in p_m} & {bytes(x) for x in macs}),
        }
        print(f"  2014 fields: {len(p_n)} nonces, {len(p_c)} ciphertexts, {len(p_m)} MACs")
        print(f"  Values shared between 2014 and 2024: {overlap}")
        print('  2014 only:')
        only = {'nonce': field_summary('nonce', p_n), 'ciphertext': field_summary('ciphertext', p_c),
                'mac': field_summary('mac', p_m)}
        print('  2014 and 2024 pooled:')
        pooled = {'nonce': field_summary('nonce', nonces + p_n),
                  'ciphertext': field_summary('ciphertext', cts + p_c),
                  'mac': field_summary('mac', macs + p_m)}
        both_nc = [s for s in prev if s['nonce'] and s['ciphertext']]
        both_nm = [s for s in prev if s['nonce'] and s['mac']]
        rep = {
            'nonce_ciphertext': replicate(results['correlations']['nonce_ciphertext']['strongest'],
                                          [s['nonce'] for s in both_nc], [s['ciphertext'] for s in both_nc],
                                          'nonce->ciphertext'),
            'nonce_mac': replicate(results['correlations']['nonce_mac']['strongest'],
                                   [s['nonce'] for s in both_nm], [s['mac'] for s in both_nm], 'nonce->MAC'),
        }
        results['with_previous_research'] = {
            'counts': {'nonce': len(p_n), 'ciphertext': len(p_c), 'mac': len(p_m)},
            'shared_values': overlap, 'only_2014': only, 'pooled': pooled, 'replication': rep,
        }

    out = os.path.join(REPO_ROOT, 'statistical_analysis_results.json')
    with open(out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\nSaved: {out}')


if __name__ == '__main__':
    main()
