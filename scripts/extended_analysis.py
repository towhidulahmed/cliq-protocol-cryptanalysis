#!/usr/bin/env python3
"""
Extended Differential Cryptanalysis incorporating:
1. Previous researcher's 6 decoded packets (decoded_unlock_sessions.txt)  
2. Extas_compare CSV files (t1-t5.csv)
3. Original 10 TimeStamps captures

This gives us potentially 21 total captures for stronger statistical analysis.
"""

import csv
import os
import math
import json
from typing import List, Tuple, Dict
from collections import Counter
from itertools import combinations

# ============================================================================
# Data Loading - Multiple Formats
# ============================================================================

def read_csv_timestamps(file_path: str) -> List[Tuple[float, int]]:
    """Read TimeStamps-style CSV (time, value)."""
    data = []
    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            try:
                data.append((float(row[0]), int(row[1])))
            except (ValueError, IndexError):
                continue
    return data

def read_csv_extas(file_path: str) -> List[Tuple[float, int]]:
    """Read Extas-style CSV (Time [s], Channel 1)."""
    data = []
    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            try:
                data.append((float(row[0]), int(row[1])))
            except (ValueError, IndexError):
                continue
    return data

def decode_signal(data: List[Tuple[float, int]]) -> str:
    """Standard 1-Wire signal decoder."""
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

def binary_to_bytes(binary_data: str) -> List[int]:
    """Convert binary string to byte values (LSB-first per 1-Wire)."""
    byte_values = []
    for i in range(0, len(binary_data), 8):
        chunk = binary_data[i:i+8]
        if len(chunk) == 8:
            reversed_chunk = chunk[::-1]
            byte_values.append(int(reversed_chunk, 2))
    return byte_values

def process_csv_file(file_path: str, reader_func) -> List[int]:
    """Process a CSV file and return decoded byte values."""
    data = reader_func(file_path)
    binary_data = decode_signal(data)
    return binary_to_bytes(binary_data)

def parse_previous_work_packets(file_path: str) -> List[List[int]]:
    """Parse the decoded_unlock_sessions.txt format - extract complete unlock sessions."""
    sessions = []
    current_session = []
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        if line.startswith('hex:'):
            hex_str = line[4:].strip()
            hex_bytes = [int(h, 16) for h in hex_str.split()]
            current_session.extend(hex_bytes)
        
        # A session ends at the final packet (04 11 02 01 01 63)
        # or when we see a new "5a" after completing a full cycle
        # The pattern repeats: 5a 5a -> packets -> end
        # Check if we have a complete session (has System ID and ends with status)
    
    # The file contains 6 unlock sessions back-to-back
    # Split by looking for the 5a 5a pattern that starts each session
    all_bytes = current_session
    
    sessions = []
    i = 0
    while i < len(all_bytes) - 1:
        if all_bytes[i] == 0x5a and i + 1 < len(all_bytes) and all_bytes[i+1] == 0x5a:
            # Start of new session, find the end
            # Each complete session has the pattern: 5a 5a <data> ... 
            # ending with either "00 04 11 02 01 01 63" or "00 03 21 00 58"
            
            # Look for next 5a 5a after a reasonable distance
            session_start = i
            j = i + 2
            
            # Find next session start or end of data
            while j < len(all_bytes) - 1:
                if all_bytes[j] == 0x5a and all_bytes[j+1] == 0x5a and j - session_start > 50:
                    break
                j += 1
            
            if j >= len(all_bytes) - 1:
                j = len(all_bytes)
            
            session = all_bytes[session_start:j]
            if len(session) > 50:  # Only keep substantial sessions
                sessions.append(session)
            i = j
        else:
            i += 1
    
    return sessions

def parse_key_txt(file_path: str) -> List[int]:
    """Parse session_key_a.txt/session_key_b.txt format."""
    byte_values = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('hex:'):
                hex_str = line[4:].strip()
                for h in hex_str.split():
                    byte_values.append(int(h, 16))
    return byte_values

# ============================================================================
# Analysis Functions
# ============================================================================

def bytes_to_hex(data: List[int]) -> str:
    return ' '.join(f'{b:02X}' for b in data)

def hamming_distance(a: int, b: int) -> int:
    return bin(a ^ b).count('1')

def hamming_distance_bytes(a: List[int], b: List[int]) -> int:
    min_len = min(len(a), len(b))
    return sum(hamming_distance(a[i], b[i]) for i in range(min_len))

def shannon_entropy(data: List[int]) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

def extract_protocol_fields(session: List[int]) -> Dict:
    """Extract known protocol fields from a session."""
    result = {
        'raw_length': len(session),
        'system_id': None,
        'counter_byte_29': None,
        'counter_byte_30': None,
        'dynamic_bytes_31_32': None,
        'checksum_byte': None,
        'nonce_9bytes': None,
        'encrypted_payload': None,
        'sha1_mac': None,
        'zero_page': None,
    }
    
    # Find System ID position
    system_id_hex = [0x56, 0x31, 0x30, 0x30, 0x34, 0x32, 0x36, 0x31]  # V1004261
    for i in range(len(session) - len(system_id_hex)):
        if session[i:i+len(system_id_hex)] == system_id_hex:
            result['system_id'] = {'position': i, 'value': 'V1004261'}
            break
    
    # Based on the packet structure from decoded_unlock_sessions.txt:
    # The protocol uses a command/response structure:
    # 82 00 XX YY = command from master (lock/key)
    #    XX = command sequence number (01, 02, 03, 04)
    #    YY = command type
    # 00 XX YY ZZ = response
    
    # Find all command headers "82 00"
    commands = []
    for i in range(len(session) - 1):
        if session[i] == 0x82 and session[i+1] == 0x00:
            commands.append(i)
    
    # Find all response headers "00 0X"
    responses = []
    for i in range(len(session) - 2):
        if session[i] == 0x00 and session[i+1] in [0x01, 0x02, 0x03, 0x04]:
            if i not in commands and (i < 1 or session[i-1] != 0x82):
                responses.append(i)
    
    result['commands'] = commands
    result['responses'] = responses
    
    return result


def analyze_protocol_structure(sessions: List[List[int]], labels: List[str]):
    """Analyze the exact protocol structure using command/response parsing."""
    
    print(f"\n{'═' * 90}")
    print("PROTOCOL COMMAND/RESPONSE STRUCTURE ANALYSIS")
    print(f"{'═' * 90}")
    
    # Parse packet structure for each session
    for idx, (session, label) in enumerate(zip(sessions[:3], labels[:3])):  # Show first 3
        print(f"\n{'─' * 70}")
        print(f"Session: {label} ({len(session)} bytes)")
        print(f"{'─' * 70}")
        
        # Find all "82 00" command headers
        i = 0
        while i < len(session):
            # Command packet: 82 00 seq_num cmd_type [length] [data...]
            if i < len(session) - 3 and session[i] == 0x82 and session[i+1] == 0x00:
                seq = session[i+2]
                cmd = session[i+3]
                
                # Determine packet end by finding next 82 00 or 00 0X header
                end = i + 4
                while end < len(session) - 1:
                    if (session[end] == 0x82 and session[end+1] == 0x00):
                        break
                    if (session[end] == 0x00 and session[end+1] in [0x01,0x02,0x03,0x04] and
                        end > i + 4):
                        break
                    end += 1
                
                pkt_data = session[i:end]
                print(f"\n  CMD #{seq:02X} (type=0x{cmd:02X}): {bytes_to_hex(pkt_data[:40])}"
                      f"{'...' if len(pkt_data) > 40 else ''}")
                print(f"    Length: {len(pkt_data)} bytes")
                
                # Identify known packet types
                if cmd == 0x01:
                    print(f"    → IDENTITY packet (System ID + config)")
                elif cmd == 0x08:
                    print(f"    → READ MEMORY command")
                elif cmd == 0x0A:
                    print(f"    → WRITE/AUTH DATA (challenge + encrypted payload)")
                elif cmd == 0x80:
                    print(f"    → SHA/MAC AUTHENTICATION RESULT")
                    mac_data = pkt_data[5:]  # Skip header
                    print(f"    → MAC ({len(mac_data)} bytes): {bytes_to_hex(mac_data)}")
                
                i = end
            
            # Response packet: 00 seq_num resp_type [length] [data...]
            elif i < len(session) - 2 and session[i] == 0x00 and session[i+1] in [0x01,0x02,0x03,0x04]:
                seq = session[i+1]
                resp = session[i+2]
                
                end = i + 3
                while end < len(session) - 1:
                    if (session[end] == 0x82 and session[end+1] == 0x00):
                        break
                    if (session[end] == 0x00 and session[end+1] in [0x01,0x02,0x03,0x04] and
                        session[end+1] != seq and end > i + 3):
                        break
                    # Also break on 5a (new session)
                    if session[end] == 0x5a and end > i + 3:
                        break
                    end += 1
                
                pkt_data = session[i:end]
                print(f"\n  RSP #{seq:02X} (type=0x{resp:02X}): {bytes_to_hex(pkt_data[:40])}"
                      f"{'...' if len(pkt_data) > 40 else ''}")
                print(f"    Length: {len(pkt_data)} bytes")
                
                if resp == 0x10:
                    print(f"    → STATUS/ACK")
                elif resp == 0x11:
                    # This is the actual data response
                    data_len = session[i+3] if i+3 < len(session) else 0
                    print(f"    → DATA RESPONSE (declared length: {data_len})")
                    if data_len == 0x18:
                        print(f"    → 24 bytes of data payload (System ID echo or zero page)")
                    elif data_len == 0x08:
                        print(f"    → 8 bytes: NONCE/CHALLENGE DATA")
                        nonce = pkt_data[4:4+8] if len(pkt_data) >= 12 else pkt_data[4:]
                        print(f"    → Nonce: {bytes_to_hex(nonce)}")
                elif resp == 0x21:
                    print(f"    → ERROR/REJECT response")
                
                i = end
            else:
                i += 1


def cross_source_comparison(all_sessions: List[List[int]], all_labels: List[str]):
    """Compare sessions from different data sources."""
    
    print(f"\n{'═' * 90}")
    print("CROSS-SOURCE ANALYSIS - Previous Work + Your Captures + Extas")
    print(f"{'═' * 90}")
    
    # Group sessions by source
    prev_sessions = [(s, l) for s, l in zip(all_sessions, all_labels) if 'prev_' in l]
    your_sessions = [(s, l) for s, l in zip(all_sessions, all_labels) if 'user1_key' in l or 'user2_key' in l]
    extas_sessions = [(s, l) for s, l in zip(all_sessions, all_labels) if 'comparison' in l]
    
    print(f"\n  Previous Work sessions: {len(prev_sessions)}")
    print(f"  Your captures: {len(your_sessions)}")
    print(f"  Extas captures: {len(extas_sessions)}")
    print(f"  Total: {len(all_sessions)}")
    
    # Extract nonce (challenge) bytes from each session using the known protocol structure
    # From decoded_unlock_sessions.txt, the nonce is at: "00 02 11 08" followed by 8+1 bytes
    print(f"\n{'─' * 70}")
    print("NONCE/CHALLENGE EXTRACTION (packet: 00 02 11 08 <8 bytes> <crc>)")
    print(f"{'─' * 70}")
    
    nonce_data = []
    for session, label in zip(all_sessions, all_labels):
        # Search for pattern "00 02 11 08" - this is RSP #02 type 0x11 with 8-byte payload
        for i in range(len(session) - 12):
            if (session[i] == 0x00 and session[i+1] == 0x02 and 
                session[i+2] == 0x11 and session[i+3] == 0x08):
                nonce = session[i+4:i+12]
                crc = session[i+12] if i+12 < len(session) else None
                nonce_data.append({'label': label, 'nonce': nonce, 'crc': crc})
                print(f"  {label:25s}  Nonce: {bytes_to_hex(nonce)}  CRC: {crc:02X}" if crc else
                      f"  {label:25s}  Nonce: {bytes_to_hex(nonce)}")
                break
    
    # Extract MAC (authentication hash) from each session
    # From decoded_unlock_sessions.txt, MAC is at: "82 00 04 80 15" followed by 22 bytes
    print(f"\n{'─' * 70}")
    print("SHA-1 MAC EXTRACTION (packet: 82 00 04 80 15 <22 bytes>)")
    print(f"{'─' * 70}")
    
    mac_data = []
    for session, label in zip(all_sessions, all_labels):
        for i in range(len(session) - 27):
            if (session[i] == 0x82 and session[i+1] == 0x00 and 
                session[i+2] == 0x04 and session[i+3] == 0x80 and session[i+4] == 0x15):
                mac = session[i+5:i+27]
                mac_data.append({'label': label, 'mac': mac})
                print(f"  {label:25s}  MAC: {bytes_to_hex(mac)}")
                break
    
    # Extract encrypted payload from each session
    # From decoded_unlock_sessions.txt, encrypted data is at: "82 00 03 0a 20" followed by 33 bytes
    print(f"\n{'─' * 70}")
    print("ENCRYPTED PAYLOAD EXTRACTION (packet: 82 00 03 0A 20 <33 bytes>)")
    print(f"{'─' * 70}")
    
    enc_data = []
    for session, label in zip(all_sessions, all_labels):
        for i in range(len(session) - 38):
            if (session[i] == 0x82 and session[i+1] == 0x00 and 
                session[i+2] == 0x03 and session[i+3] == 0x0A and session[i+4] == 0x20):
                payload = session[i+5:i+5+33]
                enc_data.append({'label': label, 'payload': payload})
                print(f"  {label:25s}  Enc: {bytes_to_hex(payload[:20])}...")
                break
    
    # Extract counter/timestamp bytes
    # From the identity packet, bytes at offset ~29 vary (counter/timestamp)
    print(f"\n{'─' * 70}")
    print("COUNTER/TIMESTAMP EXTRACTION (from identity packet)")
    print(f"{'─' * 70}")
    
    counter_data = []
    for session, label in zip(all_sessions, all_labels):
        for i in range(len(session) - 33):
            if (session[i] == 0x82 and session[i+1] == 0x00 and 
                session[i+2] == 0x01 and session[i+3] == 0x01):
                # Identity packet found
                counter_bytes = session[i+27:i+33]  # Last 6 bytes of identity (counter area)
                counter_data.append({'label': label, 'counter': counter_bytes, 'position': i})
                print(f"  {label:25s}  Counter area: {bytes_to_hex(counter_bytes)}")
                break
    
    # ========================================================================
    # ENHANCED DIFFERENTIAL ANALYSIS with protocol-aware field extraction
    # ========================================================================
    
    if len(nonce_data) >= 2:
        print(f"\n{'═' * 90}")
        print(f"NONCE ANALYSIS ({len(nonce_data)} samples)")
        print(f"{'═' * 90}")
        
        nonces = [d['nonce'] for d in nonce_data]
        
        # Check for nonce reuse
        nonce_strs = [bytes_to_hex(n) for n in nonces]
        nonce_freq = Counter(nonce_strs)
        repeated = {k: v for k, v in nonce_freq.items() if v > 1}
        
        if repeated:
            print(f"\n  ⚠ NONCE REUSE DETECTED!")
            for nonce_hex, count in repeated.items():
                sources = [d['label'] for d in nonce_data if bytes_to_hex(d['nonce']) == nonce_hex]
                print(f"    Nonce '{nonce_hex}' used in {count} sessions: {sources}")
        else:
            print(f"\n  ✓ All {len(nonces)} nonces are unique - no reuse detected")
        
        # Nonce entropy
        all_nonce_bytes = [b for n in nonces for b in n]
        print(f"  Nonce entropy: {shannon_entropy(all_nonce_bytes):.3f} bits/byte "
              f"(ideal: 8.0 for truly random)")
        
        # Nonce Hamming distances
        pairs = list(combinations(range(len(nonces)), 2))
        hds = [hamming_distance_bytes(nonces[i], nonces[j]) for i, j in pairs]
        mean_hd = sum(hds) / len(hds) if hds else 0
        total_bits = len(nonces[0]) * 8
        print(f"  Mean pairwise Hamming distance: {mean_hd:.1f} / {total_bits} bits "
              f"({mean_hd/total_bits*100:.1f}%)")
        print(f"  Expected for random: ~50%")
        
        # Per-byte analysis
        print(f"\n  Per-byte nonce analysis:")
        for pos in range(min(8, min(len(n) for n in nonces))):
            values = [n[pos] for n in nonces]
            unique = len(set(values))
            ent = shannon_entropy(values)
            print(f"    Byte {pos}: {len(nonces)} samples, {unique} unique, "
                  f"entropy={ent:.2f} - {[f'{v:02X}' for v in values]}")
    
    if len(mac_data) >= 2:
        print(f"\n{'═' * 90}")
        print(f"MAC ANALYSIS ({len(mac_data)} samples)")
        print(f"{'═' * 90}")
        
        macs = [d['mac'] for d in mac_data]
        
        # MAC Hamming distances
        pairs = list(combinations(range(len(macs)), 2))
        hds = [hamming_distance_bytes(macs[i], macs[j]) for i, j in pairs]
        mean_hd = sum(hds) / len(hds) if hds else 0
        total_bits = len(macs[0]) * 8
        print(f"\n  Mean pairwise Hamming distance: {mean_hd:.1f} / {total_bits} bits "
              f"({mean_hd/total_bits*100:.1f}%)")
        
        # MAC entropy
        all_mac_bytes = [b for m in macs for b in m]
        print(f"  MAC byte entropy: {shannon_entropy(all_mac_bytes):.3f} bits/byte")
        
        # Per-byte analysis to find the true SHA-1 output range
        print(f"\n  Per-byte MAC variability (to identify actual hash vs framing):")
        for pos in range(min(22, min(len(m) for m in macs))):
            values = [m[pos] for m in macs]
            unique = len(set(values))
            classification = "STATIC" if unique == 1 else (
                "DYNAMIC" if unique == len(macs) else f"PARTIAL ({unique}/{len(macs)})")
            print(f"    MAC byte {pos:2d}: {classification:20s} values={[f'{v:02X}' for v in values[:10]]}")
    
    # Nonce → MAC correlation
    if len(nonce_data) >= 3 and len(mac_data) >= 3:
        print(f"\n{'═' * 90}")
        print("NONCE → MAC CORRELATION (protocol-aware)")
        print(f"{'═' * 90}")
        
        # Match nonces and MACs from same sessions
        matched = []
        for nd in nonce_data:
            for md in mac_data:
                if nd['label'] == md['label']:
                    matched.append((nd['nonce'], md['mac']))
                    break
        
        if len(matched) >= 3:
            print(f"\n  Matched nonce/MAC pairs: {len(matched)}")
            
            # Correlate each nonce byte with each MAC byte
            significant_corrs = []
            for n_pos in range(8):
                for m_pos in range(min(22, min(len(m) for _, m in matched))):
                    n_values = [n[n_pos] for n, _ in matched]
                    m_values = [m[m_pos] for _, m in matched]
                    
                    n = len(matched)
                    mean_n = sum(n_values) / n
                    mean_m = sum(m_values) / n
                    
                    cov = sum((nv - mean_n) * (mv - mean_m) for nv, mv in zip(n_values, m_values)) / n
                    std_n = (sum((nv - mean_n)**2 for nv in n_values) / n) ** 0.5
                    std_m = (sum((mv - mean_m)**2 for mv in m_values) / n) ** 0.5
                    
                    if std_n > 0 and std_m > 0:
                        corr = cov / (std_n * std_m)
                        if abs(corr) > 0.5:
                            significant_corrs.append((n_pos, m_pos, corr))
            
            if significant_corrs:
                significant_corrs.sort(key=lambda x: abs(x[2]), reverse=True)
                print(f"\n  Significant correlations (|r| > 0.5):")
                for n_pos, m_pos, corr in significant_corrs[:20]:
                    strength = "STRONG" if abs(corr) > 0.8 else "MODERATE"
                    print(f"    Nonce[{n_pos}] → MAC[{m_pos}]: r={corr:.4f} ({strength})")
            else:
                print(f"\n  ✓ No significant correlations between nonce and MAC bytes")
                print(f"    → Consistent with strong cryptographic hash (good mixing)")
    
    # Encrypted payload XOR differential
    if len(enc_data) >= 2:
        print(f"\n{'═' * 90}")
        print(f"ENCRYPTED PAYLOAD XOR ANALYSIS ({len(enc_data)} samples)")
        print(f"{'═' * 90}")
        
        payloads = [d['payload'] for d in enc_data]
        min_plen = min(len(p) for p in payloads)
        
        pairs = list(combinations(range(len(payloads)), 2))
        
        # XOR all pairs
        all_xor_bytes = []
        for i, j in pairs:
            xor_diff = [payloads[i][k] ^ payloads[j][k] for k in range(min_plen)]
            all_xor_bytes.extend(xor_diff)
        
        zero_count = all_xor_bytes.count(0)
        zero_pct = zero_count / len(all_xor_bytes) * 100
        
        print(f"\n  Total XOR differential bytes analyzed: {len(all_xor_bytes)}")
        print(f"  Zero bytes: {zero_count} ({zero_pct:.1f}%) - expected ~0.4% for random")
        
        # Per-byte position analysis across all encrypted payloads
        print(f"\n  Per-byte encrypted payload variability:")
        static_bytes = 0
        dynamic_bytes = 0
        for pos in range(min_plen):
            values = [p[pos] for p in payloads]
            unique = len(set(values))
            if unique == 1:
                static_bytes += 1
            else:
                dynamic_bytes += 1
        
        print(f"    Static bytes: {static_bytes}/{min_plen} ({static_bytes/min_plen*100:.1f}%)")
        print(f"    Dynamic bytes: {dynamic_bytes}/{min_plen} ({dynamic_bytes/min_plen*100:.1f}%)")
        
        # The encrypted payload from decoded_unlock_sessions has this structure:
        # 82 00 03 0a 20 [24 bytes encrypted] [8 bytes zeros] [1 byte CRC]
        # Let's check if the zeros are always there
        print(f"\n  Checking for zero-padding pattern in encrypted payload:")
        for d in enc_data[:5]:
            payload = d['payload']
            if len(payload) >= 33:
                data_part = payload[:24]
                zero_part = payload[24:32]
                crc_part = payload[32] if len(payload) > 32 else None
                is_zero = all(b == 0 for b in zero_part)
                print(f"    {d['label']:25s}  Data[0:24]={bytes_to_hex(data_part[:8])}... "
                      f"Zeros[24:32]={'ALL ZEROS' if is_zero else bytes_to_hex(zero_part)} "
                      f"CRC={f'{crc_part:02X}' if crc_part is not None else '?'}")


def main():
    all_sessions = []
    all_labels = []
    
    # Use repo-relative paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    
    # ========================================================================
    # SOURCE 1: Previous Research (Uni Rostock, ~2014)
    # ========================================================================
    print("=" * 90)
    print("LOADING DATA FROM ALL SOURCES")
    print("=" * 90)
    
    prev_work_path = os.path.join(repo_root, "data", "previous_research")
    
    # Load from decoded_unlock_sessions.txt
    packets_file = os.path.join(prev_work_path, "decoded_unlock_sessions.txt")
    if os.path.exists(packets_file):
        prev_sessions = parse_previous_work_packets(packets_file)
        for i, session in enumerate(prev_sessions):
            all_sessions.append(session)
            all_labels.append(f"prev_pkt{i+1}")
            print(f"  Loaded prev_pkt{i+1}: {len(session)} bytes")
    
    # Load from session_key_a.txt, session_key_b.txt (different key from earlier research)
    for kf in ['session_key_a.txt', 'session_key_b.txt']:
        path = os.path.join(prev_work_path, kf)
        if os.path.exists(path):
            data = parse_key_txt(path)
            if len(data) > 50:
                all_sessions.append(data)
                all_labels.append(f"prev_{kf.replace('.txt','')}")
                print(f"  Loaded prev_{kf}: {len(data)} bytes")
    
    # ========================================================================
    # SOURCE 2: User 1 + User 2 captures (2024)
    # ========================================================================
    for user_dir_name in ['user1_key', 'user2_key']:
        user_dir = os.path.join(repo_root, "data", "captures", user_dir_name)
        if os.path.isdir(user_dir):
            for f in sorted(os.listdir(user_dir)):
                if f.endswith('.csv'):
                    path = os.path.join(user_dir, f)
                    data = process_csv_file(path, read_csv_timestamps)
                    if len(data) > 50:
                        all_sessions.append(data)
                        label = f"{user_dir_name}/{f.replace('.csv', '')}"
                        all_labels.append(label)
                        print(f"  Loaded {label}: {len(data)} bytes")
    
    # ========================================================================
    # SOURCE 3: Comparison captures
    # ========================================================================
    extas_dir = os.path.join(repo_root, "data", "captures", "extas_comparison")
    if os.path.isdir(extas_dir):
        for f in sorted(os.listdir(extas_dir)):
            if f.endswith('.csv'):
                path = os.path.join(extas_dir, f)
                data = process_csv_file(path, read_csv_extas)
                if len(data) > 50:
                    all_sessions.append(data)
                    all_labels.append(f"comparison/{f.replace('.csv', '')}")
                    print(f"  Loaded comparison/{f}: {len(data)} bytes")
    
    print(f"\nTotal sessions loaded: {len(all_sessions)}")
    
    # ========================================================================
    # Run analyses
    # ========================================================================
    
    analyze_protocol_structure(all_sessions, all_labels)
    cross_source_comparison(all_sessions, all_labels)
    
    # ========================================================================
    # FINAL SUMMARY
    # ========================================================================
    print(f"\n{'═' * 90}")
    print("EXTENDED ANALYSIS COMPLETE")
    print(f"{'═' * 90}")
    print(f"\n  Total unique capture sessions analyzed: {len(all_sessions)}")
    print(f"  Sources: Previous Work (2014), Your captures (2024), Extas comparison")
    print(f"  Time span: ~10 years of captures from same system V1004261")


if __name__ == "__main__":
    main()
