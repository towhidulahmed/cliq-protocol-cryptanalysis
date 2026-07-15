#!/usr/bin/env python3
"""
Generate two classic-style images for the CLIQ cryptanalysis repo:
  1. protocol_flow.png  - 4-phase Key<->Lock communication diagram
  2. aes_block_alignment.png - 32-byte AES block boundary visualization

Classic style: white background, DejaVu Sans Mono font, black/gray text,
no modern color palette, no gradients/shadows.
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.font_manager as fm
fm.fontManager.addfont('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

plt.rcParams['font.family'] = 'DejaVu Sans Mono'

INK = '#000000'
GRAY = '#666666'
LIGHT = '#999999'
RULE = '#000000'

import os
OUT_DIR = '/home/z/my-project/review/cliq-protocol-cryptanalysis/assets'
os.makedirs(OUT_DIR, exist_ok=True)

# =============================================================================
# Image 1: protocol_flow.png
# =============================================================================
def make_protocol_flow():
    fig, ax = plt.subplots(figsize=(14, 18), facecolor='white')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 128)
    ax.axis('off')
    ax.set_aspect('auto')

    # Title
    ax.text(50, 125.5, 'CLIQ 1-Wire Protocol',
            ha='center', va='center', fontsize=22, fontweight='bold',
            color=INK)
    ax.text(50, 123, 'Communication Flow - Four-Phase Challenge-Response Unlock Session',
            ha='center', va='center', fontsize=11, color=GRAY, style='italic')
    ax.plot([10, 90], [121, 121], color=INK, linewidth=1.2)
    ax.text(50, 119, '~255 bytes  |  ~7.6 ms  |  1-Wire bus  |  pulse-width encoded',
            ha='center', va='center', fontsize=9, color=GRAY)

    # Column headers
    ax.text(25, 115.5, 'KEY  (master)', ha='center', va='center',
            fontsize=10, fontweight='bold', color=INK)
    ax.text(75, 115.5, 'LOCK  (slave)', ha='center', va='center',
            fontsize=10, fontweight='bold', color=INK)
    ax.plot([25, 25], [114, 8], color=LIGHT, linewidth=0.4, linestyle='--', alpha=0.4)
    ax.plot([75, 75], [114, 8], color=LIGHT, linewidth=0.4, linestyle='--', alpha=0.4)

    def draw_phase(y_top, num, title, desc, k2l, l2k, note=None):
        bl, br = 8, 92
        hh = 3.0
        ch = max(len(k2l), len(l2k)) * 1.6 + 3
        if note:
            ch += 2.5
        yb = y_top - hh - ch

        # Header: white background, black bold text, horizontal rule beneath
        ax.text(bl + 1.5, y_top - hh/2, f'PHASE {num}:  {title}',
                ha='left', va='center', fontsize=10, fontweight='bold', color=INK)
        ax.text(br - 1.5, y_top - hh/2, desc,
                ha='right', va='center', fontsize=8, color=GRAY, style='italic')
        ax.plot([bl, br], [y_top - hh, y_top - hh], color=INK, linewidth=1.0)

        # Content border
        ax.add_patch(Rectangle((bl, yb), br - bl, ch,
                                facecolor='white', edgecolor=INK, linewidth=0.8, fill=False))

        # Key -> Lock
        y = y_top - hh - 1.8
        ax.text(25, y, 'Key -> Lock', ha='center', va='center',
                fontsize=8, fontweight='bold', color=INK,
                bbox=dict(boxstyle='square,pad=0.3', facecolor='#f5f5f5',
                          edgecolor=INK, linewidth=0.5))
        y -= 1.8
        for line in k2l:
            ax.text(25, y, line, ha='center', va='center',
                    fontsize=7.5, color=INK)
            y -= 1.5

        # Lock -> Key
        y = y_top - hh - 1.8
        ax.text(75, y, 'Lock -> Key', ha='center', va='center',
                fontsize=8, fontweight='bold', color=INK,
                bbox=dict(boxstyle='square,pad=0.3', facecolor='#f5f5f5',
                          edgecolor=INK, linewidth=0.5))
        y -= 1.8
        for line in l2k:
            ax.text(75, y, line, ha='center', va='center',
                    fontsize=7.5, color=INK)
            y -= 1.5

        if note:
            ax.text(50, yb + 1.2, note, ha='center', va='center',
                    fontsize=7.5, color=GRAY, style='italic')
        return yb

    def arrow(x, yt, yb):
        ax.annotate('', xy=(x, yb), xytext=(x, yt),
                    arrowprops=dict(arrowstyle='->', color=INK, lw=1.0))

    # Phase 1
    y = 113
    yb = draw_phase(y, 1, 'IDENTITY EXCHANGE', 'plaintext system ID + key ID + counter',
        ['82 00 01 01 1B 03', '56 31 30 30 34 XX XX XX', '1E 1E 1E 1E 1E 1E 1E',
         '41 02 00 08 01 04', '[6B counter] [CRC]'],
        ['00 01 11 18 03', '56 31 30 30 34 XX XX XX', '1E 1E 1E 1E 1E 1E 1E',
         '61 90 01 01 00 04 00 00', '[CRC]'],
        'System ID "V1004XXX" sent in PLAINTEXT.  Bytes 27-28 = key identifier (visible in clear).')
    arrow(50, yb - 0.5, yb - 3.0)

    # Phase 2
    y = yb - 3.5
    yb = draw_phase(y, 2, 'NONCE EXCHANGE  (CHALLENGE)', 'lock emits 8 random bytes',
        ['82 00 02 08 00', '[CRC]', '', '(read memory', ' command)'],
        ['00 02 11 08', 'DC AF E0 29 A9 9C 5B 95', '[CRC]', '', '(8-byte', ' challenge nonce)'],
        '7 captures: all unique nonces, mean pairwise Hamming ~ 50.1%.  Nonce generation looks solid.')
    arrow(50, yb - 0.5, yb - 3.0)

    # Phase 3
    y = yb - 3.5
    yb = draw_phase(y, 3, 'ENCRYPTED AUTHENTICATION PAYLOAD', '24B ciphertext + 8B plaintext zeros',
        ['82 00 03 0A 20', '[ 24B ciphertext  ]', '[ dynamic/session ]',
         '00 00 00 00 00 00 00 00', '[CRC]'],
        ['ACCEPT:', '00 03 11 18', '[24 zero bytes]', '50', '',
         'REJECT:', '00 03 21 00 58'],
        'AES-128 stream-compatible mode (CTR / CBC-zero-pad / CBC-CTS).  '
        '8 zero bytes are PLAINTEXT (static across all 23 captures).')
    arrow(50, yb - 0.5, yb - 3.0)

    # Phase 4
    y = yb - 3.5
    yb = draw_phase(y, 4, 'MAC VERIFICATION', '22B MAC = 20B SHA-1 + 2B status',
        ['82 00 04 80 15', '[ 20B SHA-1 digest ]', '[ 2B device status  ]', '',
         'matches DS28EC20', 'Compute MAC command'],
        ['00 04 11 02 01 01', '63', '', '-> motor activates,', '   key can be turned'],
        'Stats (n=6):  mean Hamming distance 50.04%  |  per-bit flip probability 0.5004  (textbook)')

    # No footer - removed per user request
    # Tight bounding box (no extra white space below)

    out = os.path.join(OUT_DIR, 'protocol_flow.png')
    plt.savefig(out, dpi=150, facecolor='white', bbox_inches='tight',
                pad_inches=0.3, edgecolor='none')
    plt.close(fig)
    print(f'protocol_flow.png: {os.path.getsize(out)/1024:.0f} KB')

# =============================================================================
# Image 2: aes_block_alignment.png
# =============================================================================
def make_aes_block_alignment():
    fig, ax = plt.subplots(figsize=(14, 12), facecolor='white')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 80)
    ax.axis('off')
    ax.set_aspect('auto')

    # Title
    ax.text(50, 77, 'Phase-3 Payload: 32 Bytes = 2 x AES-128 Block Boundaries',
            ha='center', va='center', fontsize=16, fontweight='bold', color=INK)
    ax.plot([10, 90], [75, 75], color=INK, linewidth=1.0)

    # ---- Byte ruler ----
    ax.text(50, 72, 'Byte Layout',
            ha='center', va='center', fontsize=11, fontweight='bold', color=INK)

    # Byte position markers
    for pos in [0, 8, 16, 24, 32]:
        x = 15 + pos * 2.0
        ax.text(x, 68, str(pos), ha='center', va='center', fontsize=8, color=GRAY)
        ax.plot([x, x], [66, 64.5], color=GRAY, linewidth=0.5)

    # Byte cells
    cell_w = 2.0
    x_start = 15
    y_cell = 56
    cell_h = 6

    # 24 ciphertext bytes (bytes 0-23)
    ax.add_patch(Rectangle((x_start, y_cell), 24 * cell_w, cell_h,
                            facecolor='white', edgecolor=INK, linewidth=1.0))
    ax.text(x_start + 12 * cell_w, y_cell + cell_h/2, 'CIPHERTEXT  (24 bytes, dynamic)',
            ha='center', va='center', fontsize=9, fontweight='bold', color=INK)

    # 8 zero bytes (bytes 24-31)
    ax.add_patch(Rectangle((x_start + 24 * cell_w, y_cell), 8 * cell_w, cell_h,
                            facecolor='#f5f5f5', edgecolor=INK, linewidth=1.0))
    ax.text(x_start + 28 * cell_w, y_cell + cell_h/2, 'PLAINTEXT ZEROS  (8 bytes, static 0x00)',
            ha='center', va='center', fontsize=8, color=GRAY)

    # Trailing byte (byte 32)
    ax.add_patch(Rectangle((x_start + 32 * cell_w, y_cell), cell_w, cell_h,
                            facecolor='white', edgecolor=INK, linewidth=1.0, linestyle='--'))
    ax.text(x_start + 32.5 * cell_w, y_cell + cell_h/2, '??',
            ha='center', va='center', fontsize=8, color=GRAY)

    # Block boundary brackets
    # Block 1: bytes 0-15
    ax.annotate('', xy=(x_start, y_cell - 2), xytext=(x_start + 16 * cell_w, y_cell - 2),
                arrowprops=dict(arrowstyle='-', color=INK, lw=1.2))
    ax.plot([x_start, x_start], [y_cell - 1.5, y_cell - 2.5], color=INK, lw=1.2)
    ax.plot([x_start + 16 * cell_w, x_start + 16 * cell_w], [y_cell - 1.5, y_cell - 2.5],
            color=INK, lw=1.2)
    ax.text(x_start + 8 * cell_w, y_cell - 4, 'AES Block 1  (bytes 0-15)',
            ha='center', va='center', fontsize=9, fontweight='bold', color=INK)

    # Block 2: bytes 16-31
    ax.annotate('', xy=(x_start + 16 * cell_w, y_cell - 2), xytext=(x_start + 32 * cell_w, y_cell - 2),
                arrowprops=dict(arrowstyle='-', color=INK, lw=1.2))
    ax.plot([x_start + 16 * cell_w, x_start + 16 * cell_w], [y_cell - 1.5, y_cell - 2.5],
            color=INK, lw=1.2)
    ax.plot([x_start + 32 * cell_w, x_start + 32 * cell_w], [y_cell - 1.5, y_cell - 2.5],
            color=INK, lw=1.2)
    ax.text(x_start + 24 * cell_w, y_cell - 4, 'AES Block 2  (bytes 16-31)',
            ha='center', va='center', fontsize=9, fontweight='bold', color=INK)

    ax.text(x_start + 16 * cell_w, y_cell - 6.5, '2 x AES-128 blocks = 32 bytes',
            ha='center', va='center', fontsize=8, color=GRAY, style='italic')

    # ---- Key Observation ----
    y_obs = 42
    ax.add_patch(Rectangle((10, y_obs - 8), 80, 8,
                            facecolor='white', edgecolor=INK, linewidth=1.0, fill=False))
    ax.text(12, y_obs - 1, 'KEY OBSERVATION',
            ha='left', va='center', fontsize=10, fontweight='bold', color=INK)
    obs_lines = [
        '- 24-byte ciphertext is NOT block-aligned (1.5 blocks)',
        '- 24 + 8 = 32 bytes = exactly 2 AES-128 blocks',
        '- 8 zero bytes are PLAINTEXT (always 0x00 across all captures)',
        '- Standard CBC+PKCS#7 would produce 32B ct, not 24B ct + 8B pt',
    ]
    for i, line in enumerate(obs_lines):
        ax.text(14, y_obs - 3 - i * 1.3, line,
                ha='left', va='center', fontsize=8, color=INK)

    # ---- Mode Consistency Analysis ----
    y_mode = 26
    ax.text(50, y_mode, 'MODE CONSISTENCY ANALYSIS',
            ha='center', va='center', fontsize=11, fontweight='bold', color=INK)
    ax.plot([30, 70], [y_mode - 1.5, y_mode - 1.5], color=INK, linewidth=0.8)

    # Consistent modes
    ax.text(15, y_mode - 4, 'CONSISTENT (cannot be ruled out passively):',
            ha='left', va='center', fontsize=9, fontweight='bold', color=INK)
    consistent = [
        'AES-CTR                      stream mode, 8 zeros are pt framing',
        'AES-CBC + zero-padding       last 8B ct decrypts to 0; discarded',
        'AES-CBC-CTS (NIST 800-38A)   ciphertext stealing, no padding',
        'Single-block AES-CBC + 8B unencrypted metadata',
        'AES-ECB                      cannot rule out at n=7',
    ]
    for i, line in enumerate(consistent):
        ax.text(17, y_mode - 5.8 - i * 1.3, f'- {line}',
                ha='left', va='center', fontsize=7.5, color=INK)

    # Rejected modes
    ax.text(60, y_mode - 4, 'REJECTED by observations:',
            ha='left', va='center', fontsize=9, fontweight='bold', color=INK)
    ax.text(62, y_mode - 5.8, '- AES-CBC + PKCS#7 padding',
            ha='left', va='center', fontsize=7.5, color=INK)
    ax.text(62, y_mode - 7.1, '  Would produce 32B ct, not 24+8',
            ha='left', va='center', fontsize=7.5, color=GRAY, style='italic')

    # ---- Verdict ----
    y_verdict = 5
    ax.add_patch(Rectangle((10, y_verdict - 2), 80, 4,
                            facecolor='#f5f5f5', edgecolor=INK, linewidth=0.8))
    ax.text(50, y_verdict + 0.5, 'VERDICT: AES mode cannot be determined passively.',
            ha='center', va='center', fontsize=9, fontweight='bold', color=INK)
    ax.text(50, y_verdict - 1, 'Distinguishing requires chosen-plaintext captures or side-channel analysis.',
            ha='center', va='center', fontsize=8, color=GRAY, style='italic')

    out = os.path.join(OUT_DIR, 'aes_block_alignment.png')
    plt.savefig(out, dpi=150, facecolor='white', bbox_inches='tight',
                pad_inches=0.3, edgecolor='none')
    plt.close(fig)
    print(f'aes_block_alignment.png: {os.path.getsize(out)/1024:.0f} KB')

# =============================================================================
# Main
# =============================================================================
if __name__ == '__main__':
    make_protocol_flow()
    make_aes_block_alignment()
