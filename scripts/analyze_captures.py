#!/usr/bin/env python3
"""
Comprehensive 1-Wire signal analyzer for ASSA ABLOY VERSO CLIQ lock/key captures.
Decodes multiple capture files, identifies protocol structure, and performs
cryptographic analysis to help determine the encryption algorithm used.
"""

import csv
import os
import sys
from typing import List, Tuple, Dict
from collections import Counter

def read_csv(file_path: str) -> List[Tuple[float, int]]:
    data = []
    with open(file_path, 'r') as csvfile:
        csv_reader = csv.reader(csvfile)
        header = next(csv_reader)  # Skip header
        for row in csv_reader:
            try:
                time = float(row[0])
                value = int(row[1]) if len(row) > 1 else int(row[0].split(',')[1])
                data.append((time, value))
            except (ValueError, IndexError):
                continue
    return data

def decode_signal(data: List[Tuple[float, int]]) -> Tuple[str, List[dict]]:
    """Decode 1-Wire signal, returning binary data and pulse info."""
    binary_data = ""
    low_pulse_start = None
    pulses = []

    for i, (time, value) in enumerate(data):
        if value == 0 and low_pulse_start is None:
            low_pulse_start = time
        elif value == 1 and low_pulse_start is not None:
            pulse_duration = (time - low_pulse_start) * 1e6  # microseconds
            pulses.append({
                'start': low_pulse_start,
                'end': time,
                'duration_us': pulse_duration,
                'bit': None
            })
            if 3 <= pulse_duration <= 7:
                binary_data += "1"
                pulses[-1]['bit'] = '1'
            elif pulse_duration > 11:
                binary_data += "0"
                pulses[-1]['bit'] = '0'
            low_pulse_start = None

    return binary_data, pulses

def binary_to_hex(binary_string: str) -> str:
    return hex(int(binary_string, 2))[2:].upper().zfill(2)

def hex_to_ascii(hex_string: str) -> str:
    try:
        ascii_char = chr(int(hex_string, 16))
        return ascii_char if ascii_char.isprintable() else '.'
    except ValueError:
        return '.'

def process_file(file_path: str) -> Dict:
    """Process a single CSV file and return decoded data."""
    data = read_csv(file_path)
    binary_data, pulses = decode_signal(data)
    
    chunk_size = 8
    hex_chunks = []
    ascii_output = ""
    for i in range(0, len(binary_data), chunk_size):
        chunk = binary_data[i:i+chunk_size]
        if len(chunk) == 8:
            reversed_chunk = chunk[::-1]  # LSB-first per 1-Wire protocol
            hex_chunk = binary_to_hex(reversed_chunk)
            hex_chunks.append(hex_chunk)
            ascii_output += hex_to_ascii(hex_chunk)
    
    return {
        'file': file_path,
        'binary': binary_data,
        'hex_chunks': hex_chunks,
        'ascii': ascii_output,
        'total_bits': len(binary_data),
        'total_bytes': len(hex_chunks),
        'pulses': pulses
    }

def find_pattern(hex_chunks: List[str], pattern: str) -> List[int]:
    """Find ASCII pattern in hex data."""
    pattern_hex = [hex(ord(c))[2:].upper().zfill(2) for c in pattern]
    positions = []
    for i in range(len(hex_chunks) - len(pattern_hex) + 1):
        if hex_chunks[i:i+len(pattern_hex)] == pattern_hex:
            positions.append(i)
    return positions

def entropy_analysis(hex_chunks: List[str], start: int, end: int) -> float:
    """Calculate Shannon entropy of a byte range (higher = more random)."""
    import math
    data = hex_chunks[start:end]
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    entropy = -sum((count/total) * math.log2(count/total) for count in freq.values())
    return entropy

def byte_frequency_analysis(hex_chunks: List[str]) -> Dict:
    """Analyze byte value distribution."""
    freq = Counter(hex_chunks)
    total = len(hex_chunks)
    return {
        'distribution': dict(freq.most_common()),
        'unique_values': len(freq),
        'total_bytes': total,
        'most_common': freq.most_common(10),
        'least_common': freq.most_common()[:-11:-1] if len(freq) > 10 else freq.most_common()
    }

def detect_1wire_commands(hex_chunks: List[str]) -> List[Dict]:
    """Identify standard 1-Wire ROM commands in the data."""
    known_commands = {
        '33': 'Read ROM',
        'F0': 'Search ROM',
        '55': 'Match ROM',
        'CC': 'Skip ROM',
        'EC': 'Alarm Search',
        '3C': 'Overdrive Skip ROM',
        '69': 'Overdrive Match ROM',
        'A5': 'Resume',
        # DS28E01 / DS2432 specific
        '0F': 'Write Scratchpad',
        'AA': 'Read Scratchpad',
        '5A': 'Copy Scratchpad',
        'F0': 'Read Memory',
        '66': 'Read Auth Page',
        '33': 'Compute SHA',
        # iButton specific
        'BE': 'Read iButton Data',
    }
    
    found = []
    for i, chunk in enumerate(hex_chunks):
        if chunk in known_commands:
            found.append({
                'position': i,
                'byte': chunk,
                'command': known_commands[chunk]
            })
    return found

def compare_captures(results: List[Dict]) -> Dict:
    """Compare multiple captures to identify static vs dynamic parts."""
    if len(results) < 2:
        return {}
    
    min_len = min(r['total_bytes'] for r in results)
    static_positions = []
    dynamic_positions = []
    
    for i in range(min_len):
        values = set(r['hex_chunks'][i] for r in results)
        if len(values) == 1:
            static_positions.append((i, list(values)[0]))
        else:
            dynamic_positions.append((i, list(values)))
    
    return {
        'min_length': min_len,
        'static_count': len(static_positions),
        'dynamic_count': len(dynamic_positions),
        'similarity_pct': (len(static_positions) / min_len * 100) if min_len > 0 else 0,
        'static_positions': static_positions,
        'dynamic_positions': dynamic_positions
    }

def segment_communication(hex_chunks: List[str], pulses: List[dict]) -> List[Dict]:
    """Try to segment the communication into logical packets based on timing gaps."""
    if not pulses:
        return []
    
    segments = []
    current_segment_start = 0
    bit_index = 0
    
    for i in range(1, len(pulses)):
        gap = (pulses[i]['start'] - pulses[i-1]['end']) * 1e6  # gap in µs
        if gap > 100:  # significant gap (> 100µs) indicates packet boundary
            byte_start = current_segment_start // 8
            byte_end = i // 8
            segments.append({
                'bit_start': current_segment_start,
                'bit_end': i,
                'byte_start': byte_start,
                'byte_end': byte_end,
                'gap_before_us': gap,
                'hex': ' '.join(hex_chunks[byte_start:byte_end]) if byte_end <= len(hex_chunks) else ''
            })
            current_segment_start = i
    
    # Last segment
    byte_start = current_segment_start // 8
    byte_end = len(pulses) // 8
    if byte_end <= len(hex_chunks):
        segments.append({
            'bit_start': current_segment_start,
            'bit_end': len(pulses),
            'byte_start': byte_start,
            'byte_end': byte_end,
            'gap_before_us': 0,
            'hex': ' '.join(hex_chunks[byte_start:byte_end])
        })
    
    return segments

def crc8_maxim(data_bytes: List[int]) -> int:
    """Calculate CRC-8/MAXIM (used in 1-Wire protocol)."""
    crc = 0
    for byte in data_bytes:
        crc ^= byte
        for _ in range(8):
            if crc & 0x01:
                crc = (crc >> 1) ^ 0x8C
            else:
                crc >>= 1
    return crc

def check_crc(hex_chunks: List[str]) -> List[Dict]:
    """Check for CRC8 patterns at various positions."""
    results = []
    data_bytes = [int(h, 16) for h in hex_chunks]
    
    # Check CRC at end of each 8-byte block (common in 1-Wire)
    for block_start in range(0, len(data_bytes) - 8, 8):
        block = data_bytes[block_start:block_start + 8]
        crc_computed = crc8_maxim(block[:7])
        if crc_computed == block[7]:
            results.append({
                'type': 'CRC8-MAXIM at end of 8-byte block',
                'position': block_start,
                'data': ' '.join(hex_chunks[block_start:block_start + 8]),
                'crc_byte': hex_chunks[block_start + 7],
                'valid': True
            })
    
    return results


def main():
    # Use repo-relative paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    
    user1_dir = os.path.join(repo_root, "data", "captures", "user1_key")
    user2_dir = os.path.join(repo_root, "data", "captures", "user2_key")
    
    # Collect all capture files
    fullpack_files = []
    for d in [user1_dir, user2_dir]:
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.endswith('.csv'):
                    fullpack_files.append(os.path.join(d, f))
    
    print("=" * 80)
    print("1-Wire Protocol Signal Analysis - ASSA ABLOY VERSO CLIQ")
    print("=" * 80)
    
    all_results = []
    
    for f in fullpack_files:
        if os.path.exists(f):
            result = process_file(f)
            all_results.append(result)
            
            print(f"\n{'─' * 60}")
            print(f"File: {os.path.basename(f)}")
            print(f"Total bits: {result['total_bits']}, Total bytes: {result['total_bytes']}")
            print(f"Hex: {' '.join(result['hex_chunks'])}")
            print(f"ASCII: {result['ascii']}")
            
            # Find V1004261
            positions = find_pattern(result['hex_chunks'], "V1004261")
            if positions:
                print(f"System ID 'V1004261' found at byte positions: {positions}")
            
            # Detect 1-Wire commands
            commands = detect_1wire_commands(result['hex_chunks'])
            if commands:
                print(f"\n1-Wire commands detected:")
                for cmd in commands:
                    print(f"  Position {cmd['position']}: 0x{cmd['byte']} = {cmd['command']}")
            
            # CRC checks
            crc_results = check_crc(result['hex_chunks'])
            if crc_results:
                print(f"\nValid CRC8 blocks found:")
                for cr in crc_results:
                    print(f"  {cr['type']} at position {cr['position']}: {cr['data']}")
            
            # Entropy analysis of different sections
            if result['total_bytes'] >= 20:
                n = result['total_bytes']
                third = n // 3
                e1 = entropy_analysis(result['hex_chunks'], 0, third)
                e2 = entropy_analysis(result['hex_chunks'], third, 2*third)
                e3 = entropy_analysis(result['hex_chunks'], 2*third, n)
                print(f"\nEntropy analysis (higher=more random/encrypted):")
                print(f"  First third  (bytes 0-{third}):     {e1:.3f} bits")
                print(f"  Middle third (bytes {third}-{2*third}):   {e2:.3f} bits")
                print(f"  Last third   (bytes {2*third}-{n}): {e3:.3f} bits")
            
            # Byte frequency
            freq = byte_frequency_analysis(result['hex_chunks'])
            print(f"\nByte frequency: {freq['unique_values']} unique values out of {freq['total_bytes']} total")
            print(f"  Top 10 most common: {freq['most_common']}")
            
            # Segment communication
            segments = segment_communication(result['hex_chunks'], result['pulses'])
            if segments:
                print(f"\nCommunication segments (separated by >100µs gaps):")
                for i, seg in enumerate(segments):
                    n_bytes = seg['byte_end'] - seg['byte_start']
                    if n_bytes > 0:
                        print(f"  Seg {i}: bytes {seg['byte_start']}-{seg['byte_end']} "
                              f"({n_bytes} bytes), gap={seg['gap_before_us']:.1f}µs")
                        if n_bytes <= 40:
                            print(f"    Hex: {seg['hex']}")
    
    # Cross-file comparison
    if len(all_results) >= 2:
        print(f"\n{'=' * 80}")
        print("CROSS-FILE COMPARISON")
        print(f"{'=' * 80}")
        
        comparison = compare_captures(all_results)
        print(f"\nFiles compared: {len(all_results)}")
        print(f"Minimum packet length: {comparison['min_length']} bytes")
        print(f"Static bytes (same across all captures): {comparison['static_count']}")
        print(f"Dynamic bytes (vary between captures): {comparison['dynamic_count']}")
        print(f"Similarity: {comparison['similarity_pct']:.1f}%")
        
        if comparison['dynamic_positions']:
            print(f"\nDynamic byte positions and values:")
            for pos, values in comparison['dynamic_positions'][:30]:
                print(f"  Byte {pos}: {values}")
        
        # Group: same key different times vs different keys
        user1_results = [r for r in all_results if 'user1_key' in r['file']]
        user2_results = [r for r in all_results if 'user2_key' in r['file']]
        
        if len(user1_results) >= 2:
            print(f"\n--- Same Key (User 1) Comparison ---")
            comp = compare_captures(user1_results)
            print(f"Files: {len(user1_results)}, Similarity: {comp['similarity_pct']:.1f}%")
            print(f"Static: {comp['static_count']}, Dynamic: {comp['dynamic_count']}")
            if comp['dynamic_positions']:
                print(f"Dynamic positions: {[p[0] for p in comp['dynamic_positions']]}")
        
        if len(user2_results) >= 2:
            print(f"\n--- Different Key (User 2) Comparison ---")
            comp = compare_captures(user2_results)
            print(f"Files: {len(user2_results)}, Similarity: {comp['similarity_pct']:.1f}%")
            print(f"Static: {comp['static_count']}, Dynamic: {comp['dynamic_count']}")
        
        if user1_results and user2_results:
            print(f"\n--- Cross-Key Comparison (User 1 vs User 2) ---")
            cross_results = [user1_results[0], user2_results[0]]
            comp = compare_captures(cross_results)
            print(f"Similarity: {comp['similarity_pct']:.1f}%")
            print(f"Static: {comp['static_count']}, Dynamic: {comp['dynamic_count']}")

    print(f"\n{'=' * 80}")
    print("ANALYSIS COMPLETE")
    print(f"{'=' * 80}")


if __name__ == "__main__":
    main()
