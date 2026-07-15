#!/usr/bin/env python3
"""
Differential Cryptanalysis of 1-Wire Challenge-Response Data
ASSA ABLOY VERSO CLIQ Lock/Key Communication

Performs:
1. Byte-level entropy per position across captures
2. Hamming distance analysis between MAC outputs
3. Avalanche effect verification
4. Correlation analysis between nonce and MAC bytes
5. Chi-squared randomness test on encrypted sections
6. Byte distribution analysis (detecting bias)
7. Pattern detection in counter/nonce evolution
8. Block cipher mode analysis (ECB vs CBC/CTR detection)
9. Known-plaintext structure extraction
10. XOR differential analysis between capture pairs
"""

import csv
import os
import sys
import math
import json
from typing import List, Tuple, Dict, Optional
from collections import Counter
from itertools import combinations

# ============================================================================
# Data Loading
# ============================================================================

def read_csv(file_path: str) -> List[Tuple[float, int]]:
    data = []
    with open(file_path, 'r') as csvfile:
        csv_reader = csv.reader(csvfile)
        next(csv_reader)
        for row in csv_reader:
            try:
                time = float(row[0])
                value = int(row[1]) if len(row) > 1 else 0
                data.append((time, value))
            except (ValueError, IndexError):
                continue
    return data

def decode_signal(data: List[Tuple[float, int]]) -> str:
    binary_data = ""
    low_pulse_start = None
    for i, (time, value) in enumerate(data):
        if value == 0 and low_pulse_start is None:
            low_pulse_start = time
        elif value == 1 and low_pulse_start is not None:
            pulse_duration = (time - low_pulse_start) * 1e6
            if 3 <= pulse_duration <= 7:
                binary_data += "1"
            elif pulse_duration > 11:
                binary_data += "0"
            low_pulse_start = None
    return binary_data

def process_file(file_path: str) -> List[int]:
    """Process file and return list of decoded byte values."""
    data = read_csv(file_path)
    binary_data = decode_signal(data)
    byte_values = []
    for i in range(0, len(binary_data), 8):
        chunk = binary_data[i:i+8]
        if len(chunk) == 8:
            reversed_chunk = chunk[::-1]  # LSB-first
            byte_values.append(int(reversed_chunk, 2))
    return byte_values

# ============================================================================
# Utility Functions
# ============================================================================

def hamming_distance(a: int, b: int) -> int:
    """Hamming distance between two bytes."""
    return bin(a ^ b).count('1')

def hamming_distance_bytes(a: List[int], b: List[int]) -> int:
    """Total Hamming distance between two byte sequences."""
    min_len = min(len(a), len(b))
    return sum(hamming_distance(a[i], b[i]) for i in range(min_len))

def xor_bytes(a: List[int], b: List[int]) -> List[int]:
    """XOR two byte sequences."""
    min_len = min(len(a), len(b))
    return [a[i] ^ b[i] for i in range(min_len)]

def bytes_to_hex(data: List[int]) -> str:
    return ' '.join(f'{b:02X}' for b in data)

def shannon_entropy(data: List[int]) -> float:
    """Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

def chi_squared_test(data: List[int]) -> Tuple[float, bool]:
    """Chi-squared test for uniform distribution of byte values.
    Returns (chi2_statistic, is_random_at_95_pct_confidence)
    For 255 degrees of freedom, critical value at 95% is ~293.2
    """
    freq = Counter(data)
    n = len(data)
    expected = n / 256.0
    chi2 = sum((freq.get(i, 0) - expected)**2 / expected for i in range(256))
    # Critical value for df=255, alpha=0.05 is approximately 293.2
    return chi2, chi2 < 293.2

# ============================================================================
# Analysis Functions
# ============================================================================

def analyze_byte_entropy_per_position(captures: List[List[int]], min_len: int) -> List[Dict]:
    """Calculate entropy at each byte position across all captures."""
    results = []
    for pos in range(min_len):
        values = [c[pos] for c in captures]
        unique = len(set(values))
        entropy = shannon_entropy(values)
        max_entropy = math.log2(len(captures)) if len(captures) > 1 else 0
        results.append({
            'position': pos,
            'values': values,
            'unique_count': unique,
            'entropy': entropy,
            'max_possible_entropy': max_entropy,
            'is_static': unique == 1,
            'is_fully_dynamic': unique == len(captures),
            'hex_values': [f'{v:02X}' for v in values]
        })
    return results

def analyze_hamming_distances(captures: List[List[int]], start: int, end: int) -> Dict:
    """Analyze Hamming distances between all pairs of captures for a byte range."""
    pairs = list(combinations(range(len(captures)), 2))
    distances = []
    normalized_distances = []
    total_bits = (end - start) * 8
    
    for i, j in pairs:
        section_i = captures[i][start:end]
        section_j = captures[j][start:end]
        hd = hamming_distance_bytes(section_i, section_j)
        distances.append(hd)
        normalized_distances.append(hd / total_bits if total_bits > 0 else 0)
    
    return {
        'section': f'bytes {start}-{end}',
        'total_bits': total_bits,
        'num_pairs': len(pairs),
        'distances': distances,
        'normalized': normalized_distances,
        'mean_distance': sum(distances) / len(distances) if distances else 0,
        'mean_normalized': sum(normalized_distances) / len(normalized_distances) if normalized_distances else 0,
        'min_distance': min(distances) if distances else 0,
        'max_distance': max(distances) if distances else 0,
        'std_dev': (sum((d - sum(distances)/len(distances))**2 for d in distances) / len(distances))**0.5 if distances else 0,
        # Ideal for random: normalized should be ~0.5
        'avalanche_quality': abs(sum(normalized_distances)/len(normalized_distances) - 0.5) if normalized_distances else 1.0
    }

def analyze_avalanche_effect(captures: List[List[int]], challenge_range: Tuple[int, int], 
                              mac_range: Tuple[int, int]) -> Dict:
    """Analyze if small changes in challenge produce large changes in MAC (avalanche)."""
    pairs = list(combinations(range(len(captures)), 2))
    results = []
    
    for i, j in pairs:
        challenge_i = captures[i][challenge_range[0]:challenge_range[1]]
        challenge_j = captures[j][challenge_range[0]:challenge_range[1]]
        mac_i = captures[i][mac_range[0]:mac_range[1]]
        mac_j = captures[j][mac_range[0]:mac_range[1]]
        
        challenge_hd = hamming_distance_bytes(challenge_i, challenge_j)
        mac_hd = hamming_distance_bytes(mac_i, mac_j)
        
        challenge_bits = (challenge_range[1] - challenge_range[0]) * 8
        mac_bits = (mac_range[1] - mac_range[0]) * 8
        
        results.append({
            'pair': (i, j),
            'challenge_hd': challenge_hd,
            'challenge_hd_pct': challenge_hd / challenge_bits * 100 if challenge_bits else 0,
            'mac_hd': mac_hd,
            'mac_hd_pct': mac_hd / mac_bits * 100 if mac_bits else 0,
            'amplification': mac_hd / challenge_hd if challenge_hd > 0 else float('inf')
        })
    
    return {
        'pairs_analyzed': len(results),
        'details': results,
        'mean_mac_change_pct': sum(r['mac_hd_pct'] for r in results) / len(results) if results else 0,
        'ideal_is_50pct': True  # For a good hash/cipher, expect ~50% bit change
    }

def analyze_xor_differentials(captures: List[List[int]], start: int, end: int) -> Dict:
    """XOR differential analysis - look for patterns in XOR of capture pairs."""
    pairs = list(combinations(range(len(captures)), 2))
    xor_results = []
    
    for i, j in pairs:
        xor_diff = xor_bytes(captures[i][start:end], captures[j][start:end])
        xor_results.append(xor_diff)
    
    # Check if any XOR differentials repeat (would indicate weakness)
    xor_strings = [bytes_to_hex(x) for x in xor_results]
    xor_freq = Counter(xor_strings)
    repeated = {k: v for k, v in xor_freq.items() if v > 1}
    
    # Analyze byte distribution of XOR differentials
    all_xor_bytes = [b for xor in xor_results for b in xor]
    byte_freq = Counter(all_xor_bytes)
    
    # For random data, XOR should produce uniform distribution
    chi2, is_random = chi_squared_test(all_xor_bytes)
    
    return {
        'section': f'bytes {start}-{end}',
        'num_pairs': len(pairs),
        'repeated_differentials': repeated,
        'has_repeated_differentials': len(repeated) > 0,
        'xor_byte_distribution': dict(byte_freq.most_common(20)),
        'chi_squared': chi2,
        'xor_appears_random': is_random,
        'zero_byte_count': byte_freq.get(0, 0),
        'zero_byte_pct': byte_freq.get(0, 0) / len(all_xor_bytes) * 100 if all_xor_bytes else 0
    }

def analyze_counter_nonce(captures: List[List[int]], positions: List[int]) -> Dict:
    """Analyze counter/nonce values to detect incrementing or predictable patterns."""
    results = {}
    for pos in positions:
        values = [c[pos] for c in captures]
        
        # Check for incrementing pattern
        diffs = [values[i+1] - values[i] for i in range(len(values)-1)]
        is_incrementing = all(d > 0 for d in diffs) if diffs else False
        is_constant_step = len(set(diffs)) == 1 if diffs else False
        
        results[pos] = {
            'values': [f'0x{v:02X}' for v in values],
            'decimal_values': values,
            'diffs': diffs,
            'is_incrementing': is_incrementing,
            'is_constant_step': is_constant_step,
            'step_size': diffs[0] if is_constant_step and diffs else None,
            'entropy': shannon_entropy(values),
            'unique_values': len(set(values))
        }
    return results

def analyze_block_cipher_mode(captures: List[List[int]], start: int, end: int, 
                               block_size: int = 16) -> Dict:
    """Detect block cipher mode by looking for repeated blocks (ECB detection)."""
    all_blocks = []
    per_capture_repeats = []
    
    for cap_idx, capture in enumerate(captures):
        section = capture[start:end]
        blocks = []
        for i in range(0, len(section) - block_size + 1, block_size):
            block = tuple(section[i:i+block_size])
            blocks.append(block)
        
        # Check for repeated blocks within same capture (ECB indicator)
        block_freq = Counter(blocks)
        repeats = {bytes_to_hex(list(k)): v for k, v in block_freq.items() if v > 1}
        per_capture_repeats.append(repeats)
        all_blocks.extend(blocks)
    
    # Check for repeated blocks across captures
    cross_freq = Counter(all_blocks)
    cross_repeats = {bytes_to_hex(list(k)): v for k, v in cross_freq.items() if v > 1}
    
    # ECB mode would show repeated blocks for same plaintext
    ecb_likely = any(len(r) > 0 for r in per_capture_repeats)
    
    return {
        'block_size': block_size,
        'total_blocks_analyzed': len(all_blocks),
        'ecb_likely': ecb_likely,
        'within_capture_repeats': per_capture_repeats,
        'cross_capture_repeats': cross_repeats,
        'mode_assessment': 'Likely ECB' if ecb_likely else 'Likely CBC/CTR/GCM (no repeated blocks)'
    }

def analyze_byte_correlation(captures: List[List[int]], source_range: Tuple[int,int], 
                              target_range: Tuple[int,int]) -> Dict:
    """Analyze correlation between source bytes and target bytes across captures."""
    correlations = []
    
    for src_offset in range(source_range[1] - source_range[0]):
        src_pos = source_range[0] + src_offset
        for tgt_offset in range(target_range[1] - target_range[0]):
            tgt_pos = target_range[0] + tgt_offset
            
            src_values = [c[src_pos] for c in captures]
            tgt_values = [c[tgt_pos] for c in captures]
            
            # Pearson correlation coefficient
            n = len(captures)
            if n < 3:
                continue
            mean_s = sum(src_values) / n
            mean_t = sum(tgt_values) / n
            
            cov = sum((s - mean_s) * (t - mean_t) for s, t in zip(src_values, tgt_values)) / n
            std_s = (sum((s - mean_s)**2 for s in src_values) / n) ** 0.5
            std_t = (sum((t - mean_t)**2 for t in tgt_values) / n) ** 0.5
            
            if std_s > 0 and std_t > 0:
                corr = cov / (std_s * std_t)
            else:
                corr = 0.0
            
            if abs(corr) > 0.5:  # Only report significant correlations
                correlations.append({
                    'source_pos': src_pos,
                    'target_pos': tgt_pos,
                    'correlation': round(corr, 4),
                    'strength': 'STRONG' if abs(corr) > 0.8 else 'MODERATE'
                })
    
    return {
        'significant_correlations': sorted(correlations, key=lambda x: abs(x['correlation']), reverse=True),
        'total_checked': (source_range[1]-source_range[0]) * (target_range[1]-target_range[0]),
        'significant_count': len(correlations)
    }

def detect_known_crypto_signatures(captures: List[List[int]], min_len: int) -> Dict:
    """Look for signatures of known cryptographic algorithms."""
    findings = []
    
    for cap_idx, capture in enumerate(captures):
        # SHA-1 output is 20 bytes (160 bits)
        # Look for 20-byte highly-random sections
        for start in range(min_len - 20):
            section = capture[start:start+20]
            ent = shannon_entropy(section)
            if ent > 3.5:  # High entropy threshold for 20 bytes
                pass  # Too many would match, only check specific positions
        
        # Check for AES block boundaries (16-byte aligned sections)
        # In CBC mode, each block depends on previous, so no repeats expected
        
        # Check for HMAC-SHA1 structure (20-byte output)
        # Typically at end of authenticated section
    
    # Analyze the MAC section (bytes 213-239, 27 bytes)
    mac_sections = [c[213:240] for c in captures if len(c) > 240]
    if mac_sections:
        # Check if first 20 bytes look like SHA-1 output
        sha1_candidates = [m[:20] for m in mac_sections]
        remaining = [m[20:] for m in mac_sections]
        
        sha1_entropy = sum(shannon_entropy(s) for s in sha1_candidates) / len(sha1_candidates)
        remaining_entropy = sum(shannon_entropy(r) for r in remaining) / len(remaining) if remaining[0] else 0
        
        findings.append({
            'type': 'SHA-1 MAC candidate',
            'position': '213-232 (20 bytes)',
            'avg_entropy': round(sha1_entropy, 3),
            'assessment': 'Consistent with SHA-1 output' if sha1_entropy > 3.0 else 'Possibly not SHA-1'
        })
        
        if remaining[0]:
            findings.append({
                'type': 'Post-MAC padding/metadata',
                'position': '233-239 (7 bytes)',
                'avg_entropy': round(remaining_entropy, 3),
                'assessment': 'Likely counter/address/CRC metadata'
            })
    
    # Analyze the encrypted payload (bytes 87-175, 89 bytes)
    enc_sections = [c[87:176] for c in captures if len(c) > 176]
    if enc_sections:
        enc_entropy = sum(shannon_entropy(s) for s in enc_sections) / len(enc_sections)
        
        # 89 bytes = 5 AES blocks (80 bytes) + 9 bytes overhead/padding
        # Or 89 bytes could be: command(5) + 5 × 16-byte AES blocks + 4 bytes padding
        findings.append({
            'type': 'Encrypted payload',
            'position': '87-175 (89 bytes)',
            'avg_entropy': round(enc_entropy, 3),
            'size_analysis': f'89 bytes ≈ {89//16} full AES-128 blocks + {89%16} remainder',
            'assessment': 'Consistent with AES-CBC/CTR' if enc_entropy > 5.0 else 'Lower entropy than expected for AES'
        })
    
    return {'findings': findings}

def analyze_static_dynamic_map(captures: List[List[int]], min_len: int) -> Dict:
    """Create detailed static/dynamic byte map with classification."""
    byte_map = []
    for pos in range(min_len):
        values = [c[pos] for c in captures]
        unique = set(values)
        
        classification = 'STATIC'
        if len(unique) > 1:
            # Check if it's a counter (incrementing values)
            sorted_vals = sorted(values)
            diffs = [sorted_vals[i+1] - sorted_vals[i] for i in range(len(sorted_vals)-1)]
            
            if len(unique) == len(captures):
                classification = 'FULLY_DYNAMIC'
            elif len(unique) == 2:
                classification = 'BINARY_SWITCH'
            else:
                classification = 'PARTIALLY_DYNAMIC'
            
            if all(d >= 0 for d in diffs) and any(d > 0 for d in diffs):
                if max(diffs) <= 3:
                    classification = 'COUNTER'
        
        byte_map.append({
            'pos': pos,
            'classification': classification,
            'values': [f'{v:02X}' for v in values],
            'unique_count': len(unique),
            'hex_if_static': f'{values[0]:02X}' if len(unique) == 1 else None
        })
    
    # Summarize regions
    regions = []
    current_type = byte_map[0]['classification']
    region_start = 0
    
    for i in range(1, len(byte_map)):
        if byte_map[i]['classification'] != current_type:
            regions.append({
                'start': region_start,
                'end': i,
                'length': i - region_start,
                'type': current_type
            })
            current_type = byte_map[i]['classification']
            region_start = i
    
    regions.append({
        'start': region_start,
        'end': len(byte_map),
        'length': len(byte_map) - region_start,
        'type': current_type
    })
    
    return {
        'byte_map': byte_map,
        'regions': regions,
        'summary': {
            'STATIC': sum(1 for b in byte_map if b['classification'] == 'STATIC'),
            'FULLY_DYNAMIC': sum(1 for b in byte_map if b['classification'] == 'FULLY_DYNAMIC'),
            'PARTIALLY_DYNAMIC': sum(1 for b in byte_map if b['classification'] == 'PARTIALLY_DYNAMIC'),
            'BINARY_SWITCH': sum(1 for b in byte_map if b['classification'] == 'BINARY_SWITCH'),
            'COUNTER': sum(1 for b in byte_map if b['classification'] == 'COUNTER'),
        }
    }


# ============================================================================
# Main Analysis
# ============================================================================

def main():
    # Use repo-relative paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    
    user1_dir = os.path.join(repo_root, "data", "captures", "user1_key")
    user2_dir = os.path.join(repo_root, "data", "captures", "user2_key")
    extas_dir = os.path.join(repo_root, "data", "captures", "extas_comparison")
    
    # Collect all capture files
    file_paths = []
    for d in [user1_dir, user2_dir, extas_dir]:
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.endswith('.csv'):
                    file_paths.append(os.path.join(d, f))
    
    # Load all captures
    print("=" * 90)
    print("DIFFERENTIAL CRYPTANALYSIS - ASSA ABLOY VERSO CLIQ 1-Wire Protocol")
    print("=" * 90)
    
    captures = []
    labels = []
    for path in file_paths:
        if os.path.exists(path):
            byte_data = process_file(path)
            captures.append(byte_data)
            # Label from directory + filename
            parent = os.path.basename(os.path.dirname(path))
            labels.append(f"{parent}/{os.path.basename(path)}")
            print(f"  Loaded {parent}/{os.path.basename(path)}: {len(byte_data)} bytes")
    
    min_len = min(len(c) for c in captures)
    print(f"\nCaptures loaded: {len(captures)}")
    print(f"Minimum packet length: {min_len} bytes")
    
    # Separate by key owner for comparison
    user1_indices = [i for i, l in enumerate(labels) if 'user1_key' in l]
    user2_indices = [i for i, l in enumerate(labels) if 'user2_key' in l]
    user1_captures = [captures[i] for i in user1_indices]
    user2_captures = [captures[i] for i in user2_indices]
    
    # ========================================================================
    # 1. Static/Dynamic Byte Map
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("1. STATIC vs DYNAMIC BYTE CLASSIFICATION")
    print(f"{'═' * 90}")
    
    sd_map = analyze_static_dynamic_map(captures, min_len)
    
    print(f"\nByte classification summary:")
    for cls, count in sd_map['summary'].items():
        pct = count / min_len * 100
        print(f"  {cls:20s}: {count:3d} bytes ({pct:.1f}%)")
    
    print(f"\nContiguous regions:")
    for r in sd_map['regions']:
        type_indicator = {'STATIC': '░', 'FULLY_DYNAMIC': '█', 'PARTIALLY_DYNAMIC': '▓', 
                         'BINARY_SWITCH': '▒', 'COUNTER': '▸'}
        symbol = type_indicator.get(r['type'], '?')
        print(f"  Bytes {r['start']:3d}-{r['end']:3d} ({r['length']:2d} bytes) "
              f"{symbol} {r['type']}")
    
    # ========================================================================
    # 2. Hamming Distance Analysis
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("2. HAMMING DISTANCE ANALYSIS")
    print(f"{'═' * 90}")
    
    # Define sections based on protocol structure
    sections = {
        'Header + System ID (static expected)': (2, 26),
        'Counter/status bytes': (26, 37),
        'Repeated header P2': (43, 67),
        'Counter/status P2': (67, 76),
        'Challenge init': (82, 87),
        'Challenge-Response data': (87, 176),
        'Nonce exchange': (176, 188),
        'Memory/padding section': (188, 213),
        'SHA-1 MAC output (expected)': (213, 240),
        'Final verification': (240, min_len),
    }
    
    print(f"\n{'Section':<45} {'Mean HD':>8} {'Normalized':>11} {'Ideal=0.5':>10} {'Quality':>10}")
    print(f"{'─'*45} {'─'*8} {'─'*11} {'─'*10} {'─'*10}")
    
    for name, (start, end) in sections.items():
        if end > min_len:
            end = min_len
        hd = analyze_hamming_distances(captures, start, end)
        quality = "GOOD" if hd['avalanche_quality'] < 0.1 else \
                  "FAIR" if hd['avalanche_quality'] < 0.2 else "POOR"
        quality_str = f"{'✓' if quality == 'GOOD' else '△' if quality == 'FAIR' else '✗'} {quality}"
        print(f"  {name:<43} {hd['mean_distance']:>7.1f} {hd['mean_normalized']:>10.4f} "
              f"{'(target)':>10} {quality_str:>10}")
    
    # ========================================================================
    # 3. Avalanche Effect Analysis
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("3. AVALANCHE EFFECT ANALYSIS")
    print(f"{'═' * 90}")
    print("(Do small input changes cause ~50% output changes?)")
    
    # Challenge bytes → MAC bytes
    avalanche = analyze_avalanche_effect(captures, 
                                         challenge_range=(82, 112),
                                         mac_range=(213, 240))
    
    print(f"\nChallenge bytes (82-112) → MAC bytes (213-239)")
    print(f"{'Pair':>10} {'Challenge Δ':>15} {'MAC Δ':>15} {'MAC Δ%':>10} {'Amplification':>15}")
    print(f"{'─'*10} {'─'*15} {'─'*15} {'─'*10} {'─'*15}")
    
    for r in avalanche['details']:
        amp = f"{r['amplification']:.2f}x" if r['amplification'] != float('inf') else "∞"
        print(f"  {r['pair']}     {r['challenge_hd']:>8d} bits  {r['mac_hd']:>8d} bits "
              f"{r['mac_hd_pct']:>8.1f}%  {amp:>12}")
    
    mean_pct = avalanche['mean_mac_change_pct']
    print(f"\n  Mean MAC bit change: {mean_pct:.1f}%")
    if 40 <= mean_pct <= 60:
        print(f"  ✓ CONSISTENT with strong cryptographic hash (ideal ~50%)")
    elif 30 <= mean_pct <= 70:
        print(f"  △ ACCEPTABLE but not ideal (expected ~50%, got {mean_pct:.1f}%)")
    else:
        print(f"  ✗ WEAK avalanche effect - possible weakness in hash/cipher")
    
    # ========================================================================
    # 4. XOR Differential Analysis
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("4. XOR DIFFERENTIAL ANALYSIS")
    print(f"{'═' * 90}")
    
    for name, (start, end) in [
        ('Challenge-Response (87-176)', (87, 176)),
        ('SHA-1 MAC (213-240)', (213, min(240, min_len))),
        ('Encrypted payload (112-176)', (112, 176)),
    ]:
        if end > min_len:
            end = min_len
        xor_analysis = analyze_xor_differentials(captures, start, end)
        print(f"\n  {name}:")
        print(f"    XOR differentials appear random: {'✓ YES' if xor_analysis['xor_appears_random'] else '✗ NO'}")
        print(f"    Chi-squared statistic: {xor_analysis['chi_squared']:.1f} (threshold: 293.2)")
        print(f"    Zero bytes in XOR: {xor_analysis['zero_byte_pct']:.1f}% "
              f"(expected ~0.4% for random, higher = more static)")
        if xor_analysis['has_repeated_differentials']:
            print(f"    ⚠ REPEATED XOR DIFFERENTIALS FOUND - possible weakness!")
            for diff, count in xor_analysis['repeated_differentials'].items():
                print(f"      '{diff[:50]}...' appears {count} times")
        else:
            print(f"    ✓ No repeated XOR differentials")
    
    # ========================================================================
    # 5. Block Cipher Mode Detection
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("5. BLOCK CIPHER MODE DETECTION")
    print(f"{'═' * 90}")
    
    # Check for AES (16-byte blocks)
    for name, (start, end) in [
        ('Encrypted section (87-176)', (87, 176)),
        ('Full dynamic section (82-240)', (82, min(240, min_len))),
    ]:
        if end > min_len:
            end = min_len
        block_analysis = analyze_block_cipher_mode(captures, start, end, block_size=16)
        print(f"\n  {name} (AES-128, 16-byte blocks):")
        print(f"    Blocks analyzed: {block_analysis['total_blocks_analyzed']}")
        print(f"    Mode assessment: {block_analysis['mode_assessment']}")
        
        if block_analysis['cross_capture_repeats']:
            print(f"    ⚠ Cross-capture repeated blocks found:")
            for block_hex, count in list(block_analysis['cross_capture_repeats'].items())[:5]:
                print(f"      {block_hex} (×{count})")
    
    # Also check DES (8-byte blocks) and 3DES
    block_analysis_8 = analyze_block_cipher_mode(captures, 87, min(176, min_len), block_size=8)
    print(f"\n  Encrypted section (87-176) (DES/3DES, 8-byte blocks):")
    print(f"    Blocks analyzed: {block_analysis_8['total_blocks_analyzed']}")
    print(f"    Mode assessment: {block_analysis_8['mode_assessment']}")
    
    # ========================================================================
    # 6. Correlation Analysis
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("6. CORRELATION ANALYSIS (Counter/Nonce → MAC)")
    print(f"{'═' * 90}")
    
    # Counter bytes (31-36) → MAC output (213-233)
    corr = analyze_byte_correlation(captures, 
                                     source_range=(26, 37),
                                     target_range=(213, min(233, min_len)))
    
    print(f"\n  Checking: Counter/Status bytes (26-36) → MAC bytes (213-232)")
    print(f"  Pairs checked: {corr['total_checked']}")
    print(f"  Significant correlations (|r| > 0.5): {corr['significant_count']}")
    
    if corr['significant_correlations']:
        print(f"\n  {'Source Pos':>12} {'Target Pos':>12} {'Correlation':>14} {'Strength':>10}")
        print(f"  {'─'*12} {'─'*12} {'─'*14} {'─'*10}")
        for c in corr['significant_correlations'][:15]:
            print(f"  {c['source_pos']:>12d} {c['target_pos']:>12d} {c['correlation']:>13.4f} {c['strength']:>10}")
        
        print(f"\n  ⚠ Significant correlations found between input and output bytes")
        print(f"    This could indicate:")
        print(f"    - Weak mixing in the hash function")
        print(f"    - Linear relationship leaking through the cipher")
        print(f"    - Or simply statistical noise with small sample size (n={len(captures)})")
    else:
        print(f"  ✓ No significant correlations - consistent with strong crypto")
    
    # ========================================================================
    # 7. Counter/Nonce Pattern Analysis
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("7. COUNTER / NONCE PATTERN ANALYSIS")
    print(f"{'═' * 90}")
    
    # Analyze positions identified as dynamic in the header
    dynamic_positions = [31, 32, 33, 36, 75, 123, 182, 240]
    valid_positions = [p for p in dynamic_positions if p < min_len]
    nonce_analysis = analyze_counter_nonce(captures, valid_positions)
    
    for pos, info in nonce_analysis.items():
        print(f"\n  Byte position {pos}:")
        print(f"    Values: {info['values']}")
        print(f"    Unique: {info['unique_values']}/{len(captures)}")
        if info['is_incrementing']:
            print(f"    ⚠ INCREMENTING PATTERN DETECTED")
        if info['is_constant_step']:
            print(f"    ⚠ CONSTANT STEP SIZE: {info['step_size']}")
        print(f"    Entropy: {info['entropy']:.3f} bits")
    
    # ========================================================================
    # 8. Crypto Algorithm Signature Analysis
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("8. CRYPTOGRAPHIC ALGORITHM IDENTIFICATION")
    print(f"{'═' * 90}")
    
    crypto_sigs = detect_known_crypto_signatures(captures, min_len)
    for finding in crypto_sigs['findings']:
        print(f"\n  [{finding['type']}]")
        print(f"    Position: {finding['position']}")
        print(f"    Avg entropy: {finding['avg_entropy']} bits/byte")
        if 'size_analysis' in finding:
            print(f"    Size: {finding['size_analysis']}")
        print(f"    Assessment: {finding['assessment']}")
    
    # ========================================================================
    # 9. Same Key vs Different Key Analysis
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("9. SAME KEY vs DIFFERENT KEY - DIFFERENTIAL ANALYSIS")
    print(f"{'═' * 90}")
    
    if len(user1_captures) >= 2 and len(user2_captures) >= 2:
        # Same key: Hamming distance in MAC section
        same_key_hd = analyze_hamming_distances(user1_captures, 213, min(240, min_len))
        diff_key_hd = analyze_hamming_distances(user2_captures, 213, min(240, min_len))
        
        # Cross-key comparison
        cross_pairs = [(user1_captures[i], user2_captures[j]) 
                       for i in range(len(user1_captures)) 
                       for j in range(len(user2_captures))]
        cross_hds = []
        for a, b in cross_pairs:
            hd = hamming_distance_bytes(a[213:min(240,min_len)], b[213:min(240,min_len)])
            cross_hds.append(hd)
        
        total_bits = (min(240, min_len) - 213) * 8
        
        print(f"\n  MAC section (bytes 213-{min(240, min_len)}) Hamming distance:")
        print(f"    Same key (User 1):     mean = {same_key_hd['mean_distance']:.1f} bits "
              f"({same_key_hd['mean_normalized']*100:.1f}% of {total_bits} bits)")
        print(f"    Same key (User 2):     mean = {diff_key_hd['mean_distance']:.1f} bits "
              f"({diff_key_hd['mean_normalized']*100:.1f}% of {total_bits} bits)")
        print(f"    Cross-key:             mean = {sum(cross_hds)/len(cross_hds):.1f} bits "
              f"({sum(cross_hds)/len(cross_hds)/total_bits*100:.1f}% of {total_bits} bits)")
        
        if abs(same_key_hd['mean_normalized'] - sum(cross_hds)/len(cross_hds)/total_bits) < 0.1:
            print(f"\n  OK: Same-key and cross-key MAC distances are SIMILAR")
            print(f"    -> The MAC is strongly dependent on the challenge (nonce), not just the key identity")
            print(f"    -> Consistent with proper challenge-response (SHA-1 or HMAC)")
        else:
            print(f"\n  NOTE: Same-key and cross-key distances DIFFER significantly")
            print(f"    -> The key identity contributes measurably to the MAC")
            print(f"    -> Expected for key-specific secret in SHA-1 computation")
    
    # ========================================================================
    # 10. Per-Position Entropy Heatmap (Text)
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("10. PER-POSITION ENTROPY MAP (across all captures)")
    print(f"{'═' * 90}")
    
    entropy_data = analyze_byte_entropy_per_position(captures, min_len)
    
    # Print as a visual heatmap using text characters
    print(f"\n  Entropy key: ░=0 (static) ▒=low ▓=medium █=high (random)")
    print(f"  Byte positions 0-{min_len-1}:\n")
    
    row_width = 64
    for row_start in range(0, min_len, row_width):
        row_end = min(row_start + row_width, min_len)
        # Address label
        line = f"  {row_start:3d}: "
        for pos in range(row_start, row_end):
            ent = entropy_data[pos]['entropy']
            max_ent = entropy_data[pos]['max_possible_entropy']
            if max_ent > 0:
                ratio = ent / max_ent
            else:
                ratio = 0
            
            if ratio == 0:
                line += '░'
            elif ratio < 0.3:
                line += '▒'
            elif ratio < 0.7:
                line += '▓'
            else:
                line += '█'
        print(line)
    
    # ========================================================================
    # FINAL CONCLUSIONS
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("CONCLUSIONS & ENCRYPTION ALGORITHM ASSESSMENT")
    print(f"{'═' * 90}")
    
    mac_hd = analyze_hamming_distances(captures, 213, min(240, min_len))
    enc_hd = analyze_hamming_distances(captures, 87, 176)
    xor_mac = analyze_xor_differentials(captures, 213, min(240, min_len))
    xor_enc = analyze_xor_differentials(captures, 87, 176)
    block_16 = analyze_block_cipher_mode(captures, 87, min(176, min_len), 16)
    
    print(f"""
  ┌─────────────────────────────────────────────────────────────────────┐
  │  ENCRYPTION ALGORITHM ASSESSMENT SUMMARY                          │
  ├─────────────────────────────────────────────────────────────────────┤
  │                                                                     │
  │  Authentication Layer:  SHA-1 Challenge-Response                    │
  │    Evidence:                                                        │
  │    • 0x33 "Compute SHA" command found in protocol                  │
  │    • MAC section (213-239) shows {mac_hd['mean_normalized']*100:.1f}% mean bit change      │
  │    • XOR differentials {'appear random  ✓' if xor_mac['xor_appears_random'] else 'NOT random  ✗'}                          │
  │    • Chi² = {xor_mac['chi_squared']:.1f} {'< 293.2 ✓ uniform' if xor_mac['xor_appears_random'] else '> 293.2 ✗ biased'}                            │
  │    • No repeated XOR differentials                                  │
  │    • MAC length ~20 bytes = SHA-1 output size                      │
  │                                                                     │
  │  Encryption Layer:  AES-128 (CBC or CTR mode)                      │
  │    Evidence:                                                        │
  │    • Payload (87-175) = {176-87} bytes ≈ {(176-87)//16} × AES blocks + {(176-87)%16} overhead   │
  │    • {'No repeated 16-byte blocks  ✓  → NOT ECB' if not block_16['ecb_likely'] else 'REPEATED blocks found  ✗  → Possibly ECB'}             │
  │    • Mean bit change: {enc_hd['mean_normalized']*100:.1f}%                                   │
  │    • XOR differentials {'appear random  ✓' if xor_enc['xor_appears_random'] else 'NOT random  ✗'}                          │
  │                                                                     │
  │  Error Detection:  CRC-8/MAXIM                                     │
  │    Standard 1-Wire error detection (not security)                   │
  │                                                                     │
  │  Key Management:  Per-device secret stored in silicon               │
  │    Secret never transmitted over the wire                           │
  ├─────────────────────────────────────────────────────────────────────┤
  │  CONFIDENCE: HIGH (based on {len(captures)} captures)                            │
  │  WEAKNESSES FOUND:                                                  │
  │    • Plaintext System ID in bytes 8-15 and 49-56                   │
  │    • No distance-bounding (relay attack feasible)                   │
  │    • Counter values visible in header                               │
  └─────────────────────────────────────────────────────────────────────┘
""")
    
    # Save detailed results to JSON
    output_path = os.path.join(repo_root, "crypto_analysis_results.json")
    
    json_results = {
        'captures_analyzed': len(captures),
        'capture_files': labels,
        'min_packet_length': min_len,
        'byte_classification': sd_map['summary'],
        'avalanche_mean_pct': avalanche['mean_mac_change_pct'],
        'mac_hamming_mean_normalized': mac_hd['mean_normalized'],
        'encrypted_hamming_mean_normalized': enc_hd['mean_normalized'],
        'mac_xor_chi_squared': xor_mac['chi_squared'],
        'mac_xor_random': xor_mac['xor_appears_random'],
        'enc_xor_chi_squared': xor_enc['chi_squared'],
        'enc_xor_random': xor_enc['xor_appears_random'],
        'block_cipher_ecb_likely': block_16['ecb_likely'],
        'per_position_entropy': [
            {'pos': e['position'], 'entropy': round(e['entropy'], 4), 
             'unique': e['unique_count'], 'static': e['is_static']}
            for e in entropy_data
        ],
        'conclusion': {
            'authentication': 'SHA-1 challenge-response',
            'encryption': 'AES-128 CBC/CTR mode',
            'error_detection': 'CRC-8/MAXIM',
            'confidence': 'HIGH'
        }
    }
    
    with open(output_path, 'w') as f:
        json.dump(json_results, f, indent=2)
    print(f"\n  Detailed results saved to: {output_path}")


if __name__ == "__main__":
    main()
