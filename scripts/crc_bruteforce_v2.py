#!/usr/bin/env python3
"""
Algebraic CRC-8 search: for fixed (poly, refin, refout), all samples have
the same length, so CRC(msg, init, xorout) = CRC(msg, 0, 0) XOR T[init][len] XOR xorout
where T[init][len] is what init transforms into after len bytes of zero input.

This reduces the search from 2^17 per input variant to 2^9 × O(n) verifications.
"""
import os, sys, json, time
from typing import List, Dict, Tuple
from collections import Counter

sys.path.insert(0, '/home/z/my-project/review/cliq-protocol-cryptanalysis/scripts')
from advanced_critique_analysis import NONCES, ENCRYPTED_PAYLOADS

REFLECT8 = [int('{:08b}'.format(i)[::-1], 2) for i in range(256)]

def make_crc8_table(poly: int, refin: bool) -> List[int]:
    table = [0] * 256
    for i in range(256):
        crc = i
        if refin:
            crc = REFLECT8[crc]
            rpoly = REFLECT8[poly]
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ rpoly
                else:
                    crc >>= 1
        else:
            for _ in range(8):
                if crc & 0x80:
                    crc = ((crc << 1) ^ poly) & 0xFF
                else:
                    crc = (crc << 1) & 0xFF
        table[i] = crc
    return table

def crc8_raw(data: bytes, table: List[int], init: int) -> int:
    """CRC with init, no xorout, no refout (refout is applied externally if needed)."""
    crc = init
    for byte in data:
        crc = table[crc ^ byte]
    return crc

def crc8_zeros(n: int, table: List[int], init: int) -> int:
    """What init transforms into after processing n zero bytes."""
    crc = init
    for _ in range(n):
        crc = table[crc]
    return crc

def algebraic_search(samples: List[Tuple[bytes, int]]) -> List[Dict]:
    """For each (poly, refin, refout), compute CRC(msg_i, 0, 0) for all i.
    Then solve for (init, xorout) using the relationship:
        observed_i = raw_i XOR zeros_transform[init][len_i] XOR xorout (possibly refout-applied)
    """
    if not samples:
        return []

    matches = []
    msg_lens = set(len(m) for m, _ in samples)
    if len(msg_lens) > 1:
        # Different lengths complicate the algebraic shortcut; fall back to direct search
        # (But all our test variants have uniform length, so this branch shouldn't trigger)
        return _fallback_direct(samples)

    msg_len = msg_lens.pop()
    raw_crcs = [None] * len(samples)  # will fill in per (poly, refin, refout)
    observed = [c for _, c in samples]

    # Precompute zeros-transform table for each init (0..255) — depends on (poly, refin, refout)
    for poly in range(1, 256):
        for refin in [False, True]:
            table = make_crc8_table(poly, refin)
            # Compute raw CRC (init=0) for each sample
            raws = [crc8_raw(m, table, 0) for m, _ in samples]
            for refout in [False, True]:
                # If refout, the raw CRC is reflected before XOR with xorout
                raws_eff = [REFLECT8[r] if refout else r for r in raws]
                # For each init, compute zeros-transform
                # Then for each xorout, check if observed_i = raws_eff[i] XOR zeros_tf[init] XOR xorout
                # For fixed init: xorout = observed_i XOR raws_eff[i] XOR zeros_tf[init]
                # This xorout must be the same for all i.
                for init in range(256):
                    zeros_tf = crc8_zeros(msg_len, table, init)
                    if refout:
                        zeros_tf = REFLECT8[zeros_tf]
                    # xorout candidate from first sample
                    xorout_cand = observed[0] ^ raws_eff[0] ^ zeros_tf
                    # Verify against all other samples
                    ok = True
                    for i in range(1, len(samples)):
                        if (raws_eff[i] ^ zeros_tf ^ xorout_cand) != observed[i]:
                            ok = False
                            break
                    if ok:
                        matches.append({
                            'poly': f'0x{poly:02X}',
                            'init': f'0x{init:02X}',
                            'xorout': f'0x{xorout_cand:02X}',
                            'refin': refin,
                            'refout': refout,
                        })
    return matches

def _fallback_direct(samples):
    return []  # not needed for our case

def main():
    print("╔" + "═" * 76 + "╗")
    print("║  CRC-8 ALGEBRAIC VARIANT SEARCH                                          ║")
    print("╚" + "═" * 76 + "╝")

    all_results = {}
    keys = sorted(ENCRYPTED_PAYLOADS.keys())

    input_variants = {
        'payload[0:32]': lambda p: bytes(p['ciphertext'] + p['zeros']),
        '0x20+payload': lambda p: bytes([0x20] + p['ciphertext'] + p['zeros']),
        'ct_only[0:24]': lambda p: bytes(p['ciphertext']),
        '0x20+ct_only': lambda p: bytes([0x20] + p['ciphertext']),
        '[82,00,03,0A,20]+payload': lambda p: bytes([0x82,0x00,0x03,0x0A,0x20] + p['ciphertext'] + p['zeros']),
        '[03,0A,20]+payload': lambda p: bytes([0x03,0x0A,0x20] + p['ciphertext'] + p['zeros']),
        '[0A,20]+payload': lambda p: bytes([0x0A,0x20] + p['ciphertext'] + p['zeros']),
        'header_no_82+payload': lambda p: bytes([0x00,0x03,0x0A,0x20] + p['ciphertext'] + p['zeros']),
    }

    for variant_name, getter in input_variants.items():
        samples = [(getter(ENCRYPTED_PAYLOADS[k]), ENCRYPTED_PAYLOADS[k]['crc']) for k in keys]
        t0 = time.time()
        matches = algebraic_search(samples)
        elapsed = time.time() - t0
        all_results[f'phase3_{variant_name}'] = matches
        status = f"✓ {len(matches)} matches" if matches else "✗ no match"
        print(f"  Phase-3 '{variant_name}': {status} ({elapsed:.1f}s)")
        for m in matches[:3]:
            print(f"      poly={m['poly']} init={m['init']} xorout={m['xorout']} "
                  f"refin={m['refin']} refout={m['refout']}")

    # Phase-2 nonce packets
    nonce_packets = [
        ([0x00,0x02,0x11,0x08] + NONCES['prev_pkt1'], 0x98),
        ([0x00,0x02,0x11,0x08] + NONCES['prev_pkt2'], 0x8b),
        ([0x00,0x02,0x11,0x08] + NONCES['prev_pkt4'], 0x73),
        ([0x00,0x02,0x11,0x08] + NONCES['prev_pkt5'], 0xea),
        ([0x00,0x02,0x11,0x08] + NONCES['prev_pkt6'], 0x7a),
        ([0x00,0x02,0x11,0x08] + NONCES['prev_key1'], 0x38),
        ([0x00,0x02,0x11,0x08] + NONCES['prev_key2'], 0x3f),
    ]

    nonce_input_variants = {
        'header+nonce (12B)': lambda p: bytes(p[0]),
        'nonce_only (8B)': lambda p: bytes(p[0][4:]),
        '08+nonce': lambda p: bytes([0x08] + p[0][4:]),
        '11+08+nonce': lambda p: bytes([0x11,0x08] + p[0][4:]),
        '02+11+08+nonce': lambda p: bytes([0x02,0x11,0x08] + p[0][4:]),
    }

    for variant_name, getter in nonce_input_variants.items():
        samples = [(getter(p), p[1]) for p in nonce_packets]
        t0 = time.time()
        matches = algebraic_search(samples)
        elapsed = time.time() - t0
        all_results[f'phase2_{variant_name}'] = matches
        status = f"✓ {len(matches)} matches" if matches else "✗ no match"
        print(f"  Phase-2 '{variant_name}': {status} ({elapsed:.1f}s)")
        for m in matches[:3]:
            print(f"      poly={m['poly']} init={m['init']} xorout={m['xorout']} "
                  f"refin={m['refin']} refout={m['refout']}")

    # Save
    os.makedirs('/home/z/my-project/download', exist_ok=True)
    with open('/home/z/my-project/download/crc_bruteforce_results.json', 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to /home/z/my-project/download/crc_bruteforce_results.json")

    # Summary
    total_matches = sum(len(v) for v in all_results.values())
    print(f"\n=== SUMMARY ===")
    print(f"Total CRC-8 variants found across all input combinations: {total_matches}")
    if total_matches == 0:
        print("\n  ⚠ No standard CRC-8 variant matches any plausible input combination.")
        print("  This suggests the trailing byte is either:")
        print("  - A non-CRC checksum (e.g., XOR, modular sum, custom polynomial)")
        print("  - A CRC with non-standard parameters (e.g., the patterns.php extra-zero-pass variant)")
        print("  - A truncated hash or sequence-derived value")
        print("  The 'CRC-8/MAXIM confirmed' claim in v1 README is NOT supported by the data.")

if __name__ == '__main__':
    main()
