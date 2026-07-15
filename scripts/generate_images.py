#!/usr/bin/env python3
import matplotlib
matplotlib.use('Agg')
import matplotlib.font_manager as fm
fm.fontManager.addfont('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import os
from PIL import Image

plt.rcParams['font.family'] = 'DejaVu Sans Mono'

K = '#000000'
W = '#FFFFFF'

OUT = '/home/z/my-project/review/cliq-protocol-cryptanalysis/assets'
os.makedirs(OUT, exist_ok=True)

def strip_meta(path):
    """Convert to RGB, strip metadata, and crop all-white borders."""
    img = Image.open(path)
    if img.mode == 'RGBA':
        bg = Image.new('RGBA', img.size, (255, 255, 255, 255))
        bg.paste(img, mask=img.split()[3])
        img = bg.convert('RGB')
    elif img.mode != 'RGB':
        img = img.convert('RGB')
    # Crop all-white borders (tolerance: any pixel with all RGB > 250)
    from PIL import ImageChops
    bg = Image.new('RGB', img.size, (255, 255, 255))
    diff = ImageChops.difference(img, bg)
    bbox = diff.getbbox()
    if bbox:
        # Add 5px padding
        pad = 5
        l = max(0, bbox[0] - pad)
        t = max(0, bbox[1] - pad)
        r = min(img.size[0], bbox[2] + pad)
        b = min(img.size[1], bbox[3] + pad)
        img = img.crop((l, t, r, b))
    img.save(path, format='PNG', optimize=True)

def make_protocol_flow():
    fig, ax = plt.subplots(figsize=(14, 15), facecolor='white')
    ax.set_xlim(0, 100)
    ax.set_ylim(24, 118)
    ax.axis('off')
    ax.set_aspect('auto')

    ax.text(50, 116, 'CLIQ 1-Wire Protocol',
            ha='center', va='center', fontsize=22, fontweight='bold', color=K)
    ax.text(50, 113.5, 'Communication Flow - Four-Phase Challenge-Response Unlock Session',
            ha='center', va='center', fontsize=11, color=K, style='italic')
    ax.plot([10, 90], [111.5, 111.5], color=K, linewidth=1.2)
    ax.text(50, 109.5, '~255 bytes  |  ~7.6 ms  |  1-Wire bus  |  pulse-width encoded',
            ha='center', va='center', fontsize=9, color=K)

    ax.text(25, 106, 'KEY  (master)', ha='center', va='center',
            fontsize=10, fontweight='bold', color=K)
    ax.text(75, 106, 'LOCK  (slave)', ha='center', va='center',
            fontsize=10, fontweight='bold', color=K)

    def draw_phase(y_top, num, title, desc, k2l, l2k, note=None):
        bl, br = 8, 92
        hh = 3.0
        n_lines = max(len(k2l), len(l2k))
        ch = n_lines * 1.5 + 2.0
        if note:
            ch += 2.0
        yb = y_top - hh - ch

        ax.text(bl + 1.5, y_top - hh/2, f'PHASE {num}:  {title}',
                ha='left', va='center', fontsize=10, fontweight='bold', color=K)
        ax.text(br - 1.5, y_top - hh/2, desc,
                ha='right', va='center', fontsize=8, color=K, style='italic')
        ax.plot([bl, br], [y_top - hh, y_top - hh], color=K, linewidth=1.0)
        ax.add_patch(Rectangle((bl, yb), br - bl, ch,
                                facecolor=W, edgecolor=K, linewidth=0.8, fill=False))

        y = y_top - hh - 1.5
        ax.text(25, y, 'Key -> Lock', ha='center', va='center',
                fontsize=8, fontweight='bold', color=K,
                bbox=dict(boxstyle='square,pad=0.3', facecolor=W,
                          edgecolor=K, linewidth=0.5))
        y -= 1.6
        for line in k2l:
            ax.text(25, y, line, ha='center', va='center',
                    fontsize=7.5, color=K)
            y -= 1.4

        y = y_top - hh - 1.5
        ax.text(75, y, 'Lock -> Key', ha='center', va='center',
                fontsize=8, fontweight='bold', color=K,
                bbox=dict(boxstyle='square,pad=0.3', facecolor=W,
                          edgecolor=K, linewidth=0.5))
        y -= 1.6
        for line in l2k:
            ax.text(75, y, line, ha='center', va='center',
                    fontsize=7.5, color=K)
            y -= 1.4

        if note:
            ax.text(50, yb + 1.2, note, ha='center', va='center',
                    fontsize=7.5, color=K, style='italic')
        return yb

    def arrow(x, yt, yb):
        ax.annotate('', xy=(x, yb), xytext=(x, yt),
                    arrowprops=dict(arrowstyle='->', color=K, lw=1.0))

    y = 103.5
    yb = draw_phase(y, 1, 'IDENTITY EXCHANGE', 'plaintext system ID + key ID + counter',
        ['82 00 01 01 1B 03', '56 31 30 30 34 XX XX XX', '1E 1E 1E 1E 1E 1E 1E',
         '41 02 00 08 01 04', '[6B counter] [CRC]'],
        ['00 01 11 18 03', '56 31 30 30 34 XX XX XX', '1E 1E 1E 1E 1E 1E 1E',
         '61 90 01 01 00 04 00 00', '[CRC]'],
        'System ID "V1004XXX" sent in PLAINTEXT.  Bytes 27-28 = key identifier (visible in clear).')
    arrow(50, yb - 0.5, yb - 3.0)

    y = yb - 3.5
    yb = draw_phase(y, 2, 'NONCE EXCHANGE  (CHALLENGE)', 'lock emits 8 random bytes',
        ['82 00 02 08 00', '[CRC]', '', '(read memory', ' command)'],
        ['00 02 11 08', 'DC AF E0 29 A9 9C 5B 95', '[CRC]', '', '(8-byte', ' challenge nonce)'],
        '7 captures: all unique nonces, mean pairwise Hamming ~ 50.1%.  Nonce generation looks solid.')
    arrow(50, yb - 0.5, yb - 3.0)

    y = yb - 3.5
    yb = draw_phase(y, 3, 'ENCRYPTED AUTHENTICATION PAYLOAD', '24B ciphertext + 8B plaintext zeros',
        ['82 00 03 0A 20', '[ 24B ciphertext  ]', '[ dynamic/session ]',
         '00 00 00 00 00 00 00 00', '[CRC]'],
        ['ACCEPT:', '00 03 11 18', '[24 zero bytes]', '50', '',
         'REJECT:', '00 03 21 00 58'],
        'AES-128 stream-compatible mode (CTR / CBC-zero-pad / CBC-CTS).  '
        '8 zero bytes are PLAINTEXT (static across all 23 captures).')
    arrow(50, yb - 0.5, yb - 3.0)

    y = yb - 3.5
    yb = draw_phase(y, 4, 'MAC VERIFICATION', '22B MAC = 20B SHA-1 + 2B status',
        ['82 00 04 80 15', '[ 20B SHA-1 digest ]', '[ 2B device status  ]', '',
         'matches DS28EC20', 'Compute MAC command'],
        ['00 04 11 02 01 01', '63', '', '-> motor activates,', '   key can be turned'],
        'Stats (n=6):  mean Hamming distance 50.04%  |  per-bit flip probability 0.5004  (textbook)')

    out = os.path.join(OUT, 'protocol_flow.png')
    plt.savefig(out, dpi=150, facecolor='white', bbox_inches='tight',
                pad_inches=0.05, edgecolor='none')
    plt.close(fig)
    strip_meta(out)
    print(f'protocol_flow.png: {os.path.getsize(out)/1024:.0f} KB')

def make_aes_block():
    fig, ax = plt.subplots(figsize=(14, 10), facecolor='white')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 72)
    ax.axis('off')
    ax.set_aspect('auto')

    ax.text(50, 70, 'Phase-3 Payload: 32 Bytes = 2 x AES-128 Block Boundaries',
            ha='center', va='center', fontsize=15, fontweight='bold', color=K)
    ax.plot([8, 92], [68.5, 68.5], color=K, linewidth=1.0)

    # Byte ruler
    ax.text(50, 66, 'Byte Layout',
            ha='center', va='center', fontsize=11, fontweight='bold', color=K)

    x_start = 14
    cell_w = 2.2
    y_cell = 52
    cell_h = 6

    # Ruler marks
    for pos in [0, 8, 16, 24, 32]:
        x = x_start + pos * cell_w
        ax.text(x, 62, str(pos), ha='center', va='center', fontsize=8, color=K)
        ax.plot([x, x], [60.5, 59], color=K, linewidth=0.5)

    # 24 ciphertext bytes
    ax.add_patch(Rectangle((x_start, y_cell), 24 * cell_w, cell_h,
                            facecolor=W, edgecolor=K, linewidth=1.0))
    ax.text(x_start + 12 * cell_w, y_cell + cell_h/2, 'CIPHERTEXT  (24 bytes, dynamic)',
            ha='center', va='center', fontsize=9, fontweight='bold', color=K)

    # 8 zero bytes
    ax.add_patch(Rectangle((x_start + 24 * cell_w, y_cell), 8 * cell_w, cell_h,
                            facecolor=W, edgecolor=K, linewidth=1.0))
    ax.text(x_start + 28 * cell_w, y_cell + cell_h/2, 'PLAINTEXT ZEROS  (8B, static)',
            ha='center', va='center', fontsize=8, color=K)

    # Trailing byte
    ax.add_patch(Rectangle((x_start + 32 * cell_w, y_cell), cell_w, cell_h,
                            facecolor=W, edgecolor=K, linewidth=1.0, linestyle='--'))
    ax.text(x_start + 32.5 * cell_w, y_cell + cell_h/2, '??',
            ha='center', va='center', fontsize=8, color=K)

    # Block brackets
    for bx_start, bx_end, label in [
        (x_start, x_start + 16 * cell_w, 'AES Block 1  (bytes 0-15)'),
        (x_start + 16 * cell_w, x_start + 32 * cell_w, 'AES Block 2  (bytes 16-31)'),
    ]:
        ax.plot([bx_start, bx_end], [y_cell - 2, y_cell - 2], color=K, lw=1.2)
        ax.plot([bx_start, bx_start], [y_cell - 1.5, y_cell - 2.5], color=K, lw=1.2)
        ax.plot([bx_end, bx_end], [y_cell - 1.5, y_cell - 2.5], color=K, lw=1.2)
        ax.text((bx_start + bx_end) / 2, y_cell - 4, label,
                ha='center', va='center', fontsize=9, fontweight='bold', color=K)

    ax.text(x_start + 16 * cell_w, y_cell - 6.5, '2 x AES-128 blocks = 32 bytes',
            ha='center', va='center', fontsize=8, color=K, style='italic')

    # Key Observation box
    y_obs = 38
    obs_h = 9
    ax.add_patch(Rectangle((8, y_obs - obs_h), 84, obs_h,
                            facecolor=W, edgecolor=K, linewidth=1.0, fill=False))
    ax.text(10, y_obs - 1.5, 'KEY OBSERVATION',
            ha='left', va='center', fontsize=10, fontweight='bold', color=K)
    obs_lines = [
        '- 24-byte ciphertext is NOT block-aligned (1.5 blocks)',
        '- 24 + 8 = 32 bytes = exactly 2 AES-128 blocks',
        '- 8 zero bytes are PLAINTEXT (always 0x00 across all captures)',
        '- Standard CBC+PKCS#7 would produce 32B ct, not 24B ct + 8B pt',
    ]
    for i, line in enumerate(obs_lines):
        ax.text(12, y_obs - 3.5 - i * 1.4, line,
                ha='left', va='center', fontsize=8, color=K)

    # Mode Consistency
    y_mode = 24
    ax.text(50, y_mode, 'MODE CONSISTENCY ANALYSIS',
            ha='center', va='center', fontsize=11, fontweight='bold', color=K)
    ax.plot([30, 70], [y_mode - 1.5, y_mode - 1.5], color=K, linewidth=0.8)

    # Two columns
    col_y = y_mode - 4
    ax.text(8, col_y, 'CONSISTENT (cannot be ruled out):',
            ha='left', va='center', fontsize=9, fontweight='bold', color=K)
    consistent = [
        'AES-CTR',
        'AES-CBC + zero-padding',
        'AES-CBC-CTS (NIST 800-38A)',
        'Single-block AES-CBC + 8B metadata',
        'AES-ECB (cannot rule out at n=7)',
    ]
    for i, line in enumerate(consistent):
        ax.text(10, col_y - 1.8 - i * 1.3, f'- {line}',
                ha='left', va='center', fontsize=8, color=K)

    ax.text(55, col_y, 'REJECTED:',
            ha='left', va='center', fontsize=9, fontweight='bold', color=K)
    ax.text(57, col_y - 1.8, '- AES-CBC + PKCS#7 padding',
            ha='left', va='center', fontsize=8, color=K)
    ax.text(57, col_y - 3.1, '  Would produce 32B ct, not 24+8',
            ha='left', va='center', fontsize=7.5, color=K, style='italic')

    # Verdict box
    y_v = 3.5
    ax.add_patch(Rectangle((8, y_v - 2), 84, 4,
                            facecolor=W, edgecolor=K, linewidth=0.8))
    ax.text(50, y_v + 0.5, 'VERDICT: AES mode cannot be determined passively.',
            ha='center', va='center', fontsize=9, fontweight='bold', color=K)
    ax.text(50, y_v - 1, 'Distinguishing requires chosen-plaintext captures or side-channel analysis.',
            ha='center', va='center', fontsize=8, color=K, style='italic')

    out = os.path.join(OUT, 'aes_block_alignment.png')
    plt.savefig(out, dpi=150, facecolor='white', bbox_inches='tight',
                pad_inches=0.05, edgecolor='none')
    plt.close(fig)
    strip_meta(out)
    print(f'aes_block_alignment.png: {os.path.getsize(out)/1024:.0f} KB')

if __name__ == '__main__':
    make_protocol_flow()
    make_aes_block()
