#!/usr/bin/env python3
"""
Statistical analyses for the CLIQ protocol cryptanalysis:
  - Disjoint-pair chi-squared test on MAC XOR differentials
  - Exact Student's t p-values for nonce-to-MAC correlations (via regularized
    incomplete beta function)
  - Explicit power analysis (Fisher z-transformation)
  - Verification of which command bytes actually appear in the protocol
Output: statistical_analysis_results.json in the repo root.
"""
import os, sys, math, json
from collections import Counter
from itertools import combinations

sys.path.insert(0, '/home/z/my-project/review/cliq-protocol-cryptanalysis/scripts')
from advanced_critique_analysis import NONCES, MACS, ENCRYPTED_PAYLOADS, hamming_distance_bytes

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

# H1: disjoint pairs
def disjoint_xor(captures, start, end):
    out = []
    for i in range(0, len(captures) - 1, 2):
        a = captures[i][start:end]; b = captures[i+1][start:end]
        out.extend(a[k] ^ b[k] for k in range(min(len(a), len(b))))
    return out

def allpair_xor(captures, start, end):
    out = []
    for i, j in combinations(range(len(captures)), 2):
        a = captures[i][start:end]; b = captures[j][start:end]
        out.extend(a[k] ^ b[k] for k in range(min(len(a), len(b))))
    return out

def chi_uniform(data):
    freq = Counter(data); n = len(data); exp = n / 256.0
    chi = sum((freq.get(i, 0) - exp) ** 2 / exp for i in range(256))
    return chi, chi < 293.25  # df=255, alpha=0.05

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

# C1: verify 0x33 command claim
def verify_c1():
    prev_dir = '/home/z/my-project/review/cliq-protocol-cryptanalysis/data/previous_research'
    all_bytes = []
    for fname in ['foo2-packets.txt', 'key1.txt', 'key2.txt']:
        with open(os.path.join(prev_dir, fname)) as f:
            for line in f:
                if line.strip().startswith('hex:'):
                    for h in line[4:].split():
                        try: all_bytes.append(int(h, 16))
                        except: pass
    positions_33 = [i for i, b in enumerate(all_bytes) if b == 0x33]
    cmds = set()
    for i in range(len(all_bytes) - 3):
        if all_bytes[i] == 0x82 and all_bytes[i+1] == 0x00:
            cmds.add((all_bytes[i+2], all_bytes[i+3]))
    return {
        'total_bytes': len(all_bytes),
        'count_0x33': len(positions_33),
        'positions_0x33': positions_33,
        'commands_sent': sorted([(hex(s), hex(c)) for s, c in cmds]),
        'has_0x33_command': any(c == 0x33 for _, c in cmds),
    }

def main():
    print("╔" + "═" * 76 + "╗")
    print("║  STATISTICAL ANALYSIS                                                    ║")
    print("╚" + "═" * 76 + "╝")

    results = {}

    # ---- Command byte verification ----
    print("\n=== Command byte verification (0x33 claim) ===")
    c1 = verify_c1()
    print(f"  0x33 occurrences in raw stream: {c1['count_0x33']}")
    print(f"  Positions: {c1['positions_0x33']}")
    print(f"  Commands actually sent: {c1['commands_sent']}")
    print(f"  Is 0x33 ever a command? {c1['has_0x33_command']}")
    results['command_verification'] = c1

    # ---- Chi-squared with disjoint vs overlapping pairs ----
    print("\n=== Chi-squared: disjoint vs overlapping pairs ===")
    keys = sorted(MACS.keys()); macs = [MACS[k] for k in keys]; n = len(macs)
    h1 = {}
    for name, (s, e) in {'MAC[0:20]': (0, 20), 'MAC[20:22]': (20, 22), 'MAC[0:22]': (0, 22)}.items():
        overlap = allpair_xor(macs, s, e)
        disjoint = disjoint_xor(macs, s, e)
        chi_o, _ = chi_uniform(overlap)
        chi_d, _ = chi_uniform(disjoint)
        reliable = len(disjoint) / 256 >= 5
        h1[name] = {
            'overlap_chi2': chi_o, 'overlap_n': len(overlap),
            'disjoint_chi2': chi_d, 'disjoint_n': len(disjoint),
            'disjoint_reliable': reliable,
        }
        print(f"  {name}:")
        print(f"    Overlapping pairs: n={len(overlap)}, chi2={chi_o:.1f}")
        print(f"    Disjoint pairs:    n={len(disjoint)}, chi2={chi_d:.1f} ({'reliable' if reliable else 'UNRELIABLE: expected count < 5'})")
    results['chi_squared'] = h1

    # ---- Exact p-values for nonce-to-MAC correlations ----
    print("\n=== Exact p-values for nonce-to-MAC correlations ===")
    paired = sorted([k for k in NONCES if k in MACS])
    n_paired = len(paired); df = n_paired - 2
    n_tests = 8 * 22; alpha_bonf = 0.05 / n_tests
    print(f"  n={n_paired}, df={df}, Bonferroni alpha={alpha_bonf:.6f}")
    corrs = []
    for ni in range(8):
        nv = [float(NONCES[k][ni]) for k in paired]
        for mi in range(22):
            mv = [float(MACS[k][mi]) for k in paired]
            r = pearson(nv, mv)
            if abs(r) < 1.0:
                t = r * math.sqrt(df) / math.sqrt(1 - r * r)
            else:
                t = math.copysign(1e30, r)
            p_exact = t_sf_two_sided(t, df)
            corrs.append({'ni': ni, 'mi': mi, 'r': r, 't': t, 'p': p_exact, 'p_bonf': min(1.0, p_exact * n_tests)})
    corrs.sort(key=lambda c: abs(c['r']), reverse=True)
    print(f"\n  Top 10 correlations by |r|:")
    print(f"  {'Nonce[i]':>9} {'MAC[j]':>7} {'r':>9} {'t':>10} {'p (exact)':>12} {'p (Bonf.)':>12}")
    for c in corrs[:10]:
        print(f"  Nonce[{c['ni']}]  MAC[{c['mi']:>2}]  {c['r']:>8.4f} {c['t']:>9.3f}  {c['p']:>11.5f}  {c['p_bonf']:>11.5f}")
    n_unc = sum(1 for c in corrs if c['p'] < 0.05)
    n_bonf = sum(1 for c in corrs if c['p_bonf'] < 0.05)
    print(f"\n  Uncorrected significant: {n_unc} (expected by chance: {0.05*n_tests:.1f})")
    print(f"  Bonferroni-significant: {n_bonf}")
    results['correlations'] = {
        'n_paired': n_paired, 'n_tests': n_tests, 'alpha_bonferroni': alpha_bonf,
        'uncorrected_significant': n_unc, 'expected_fp': 0.05 * n_tests,
        'bonferroni_significant': n_bonf,
        'top_5': corrs[:5],
    }

    # ---- Power analysis ----
    print("\n=== Power analysis at n=6 ===")
    for power in [0.50, 0.80, 0.90, 0.95]:
        r_min = min_detectable_r(n_paired, alpha_bonf, power)
        print(f"  At power={power:.2f}: minimum detectable |r| = {r_min:.4f}")
    print(f"\n  Power to detect |r|=0.9: {power_for_r(n_paired, alpha_bonf, 0.9):.3f}")
    print(f"  Power to detect |r|=0.7: {power_for_r(n_paired, alpha_bonf, 0.7):.3f}")
    print(f"  Power to detect |r|=0.5: {power_for_r(n_paired, alpha_bonf, 0.5):.3f}")
    results['power_analysis'] = {
        'n': n_paired, 'alpha_bonferroni': alpha_bonf,
        'min_detectable_r_at_80pct_power': min_detectable_r(n_paired, alpha_bonf, 0.80),
        'power_for_r_0.9': power_for_r(n_paired, alpha_bonf, 0.9),
        'power_for_r_0.7': power_for_r(n_paired, alpha_bonf, 0.7),
        'power_for_r_0.5': power_for_r(n_paired, alpha_bonf, 0.5),
    }

    # ---- AES mode interpretations ----
    print("\n=== AES mode interpretations ===")
    h2_modes = [
        ('AES-CTR', 'Consistent. 24B stream-encrypted, 8 zeros are plaintext framing.'),
        ('AES-CBC zero-pad', 'Consistent if receiver treats last 8B as plaintext zeros post-decrypt. Unverifiable passively.'),
        ('AES-CBC-CTS', 'Consistent. NIST SP 800-38A. 24B to 24B ct, no padding expansion.'),
        ('Single-block AES + 8B unencrypted metadata', 'Consistent. First 16B encrypted, next 8B static protocol field.'),
        ('AES-ECB', 'Cannot rule out at n=7. Detecting ECB needs ~2^32 captures.'),
    ]
    for mode, verdict in h2_modes:
        print(f"  - {mode}: {verdict}")
    results['aes_modes'] = {'modes': h2_modes}

    # ---- Verified statistics ----
    print("\n=== Verified statistics ===")
    pairs = list(combinations(paired, 2))
    hds = [hamming_distance_bytes(MACS[k1], MACS[k2]) for k1, k2 in pairs]
    mean_hd = sum(hds) / len(hds)
    print(f"  Mean MAC Hamming distance (22B): {mean_hd:.2f}/176 = {mean_hd/176*100:.2f}%")

    # Per-bit flip probability
    flips = []
    for k1, k2 in pairs:
        for bi in range(22):
            for bit in range(8):
                b1 = (MACS[k1][bi] >> bit) & 1
                b2 = (MACS[k2][bi] >> bit) & 1
                flips.append(1 if b1 != b2 else 0)
    print(f"  Per-bit flip probability: {sum(flips)/len(flips):.4f}")

    # Nonce uniqueness
    nonce_strs = [' '.join(f'{b:02X}' for b in NONCES[k]) for k in NONCES]
    print(f"  Unique nonces: {len(set(nonce_strs))}/{len(NONCES)}")
    for pos in range(8):
        vals = [NONCES[k][pos] for k in NONCES]
        print(f"    Nonce byte {pos}: {len(set(vals))}/{len(vals)} unique")

    # Save
    os.makedirs('/home/z/my-project/download', exist_ok=True)
    out_path = '/home/z/my-project/download/statistical_analysis_results.json'
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nSaved: {out_path}")

if __name__ == '__main__':
    main()
