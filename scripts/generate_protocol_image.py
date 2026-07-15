#!/usr/bin/env python3
"""
Generate a classic-style protocol flow diagram for the CLIQ cryptanalysis repo.

Design principles (per user request):
  - Simple classic look, NOT modern
  - White background
  - Monospace text
  - Classic color palette: black ink + dark navy accent for phase headers
  - No gradients, no shadows, no rounded corners
  - Textbook/academic style
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.font_manager as fm
fm.fontManager.addfont('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf')
fm.fontManager.addfont('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyArrowPatch
import matplotlib.patches as mpatches

# Classic palette
INK = '#000000'        # pure black for text and lines
NAVY = '#1a2b4a'       # dark navy for phase headers (the only accent)
LIGHT_GRAY = '#f5f5f5' # very light gray for alternating row backgrounds
MID_GRAY = '#888888'   # medium gray for secondary text
RULE = '#000000'       # black rule lines

plt.rcParams['font.family'] = 'DejaVu Sans Mono'
plt.rcParams['font.monospace'] = ['DejaVu Sans Mono']

# =============================================================================
# Layout
# =============================================================================
# Figure: portrait orientation, large enough for detail
# 14 x 20 inches at 150 dpi = 2100 x 3000 pixels
fig, ax = plt.subplots(figsize=(14, 20), facecolor='white')
ax.set_xlim(0, 100)
ax.set_ylim(0, 140)
ax.axis('off')
ax.set_aspect('auto')

# =============================================================================
# Title block
# =============================================================================
ax.text(50, 137, 'CLIQ 1-Wire Protocol',
        ha='center', va='center', fontsize=22, fontweight='bold',
        color=INK, family='DejaVu Sans Mono')

ax.text(50, 134.5, 'Communication Flow - Four-Phase Challenge-Response Unlock Session',
        ha='center', va='center', fontsize=11, color=MID_GRAY,
        family='DejaVu Sans Mono', style='italic')

# Horizontal rule under title
ax.plot([10, 90], [132.5, 132.5], color=INK, linewidth=1.2)

ax.text(50, 130.5, '~255 bytes  |  ~7.6 ms  |  1-Wire bus  |  pulse-width encoded',
        ha='center', va='center', fontsize=9, color=MID_GRAY,
        family='DejaVu Sans Mono')

# =============================================================================
# Column headers (KEY / LOCK)
# =============================================================================
ax.text(25, 127, 'KEY  (master)', ha='center', va='center',
        fontsize=10, fontweight='bold', color=INK, family='DejaVu Sans Mono')
ax.text(75, 127, 'LOCK  (slave)', ha='center', va='center',
        fontsize=10, fontweight='bold', color=INK, family='DejaVu Sans Mono')

# Vertical guide lines (faint)
ax.plot([25, 25], [125, 8], color=MID_GRAY, linewidth=0.4, linestyle='--', alpha=0.4)
ax.plot([75, 75], [125, 8], color=MID_GRAY, linewidth=0.4, linestyle='--', alpha=0.4)

# =============================================================================
# Helper to draw a phase block
# =============================================================================
def draw_phase(y_top, phase_num, phase_title, phase_desc, k2l_lines, l2k_lines, note=None):
    """
    Draw one phase block. y_top is the top y-coordinate.
    Returns the y-coordinate of the bottom of the block.
    """
    block_left = 8
    block_right = 92
    header_height = 3.0
    content_height = max(len(k2l_lines), len(l2k_lines)) * 1.6 + 3
    if note:
        content_height += 2.5
    block_height = header_height + content_height
    y_bottom = y_top - block_height

    # Phase header bar (navy background, white text - classic inverted header)
    header_rect = Rectangle((block_left, y_top - header_height),
                             block_right - block_left, header_height,
                             facecolor=NAVY, edgecolor=NAVY, linewidth=0)
    ax.add_patch(header_rect)
    ax.text(block_left + 1.5, y_top - header_height/2,
            f'PHASE {phase_num}:  {phase_title}',
            ha='left', va='center', fontsize=10, fontweight='bold',
            color='white', family='DejaVu Sans Mono')
    ax.text(block_right - 1.5, y_top - header_height/2,
            phase_desc,
            ha='right', va='center', fontsize=8, color='white',
            family='DejaVu Sans Mono', style='italic')

    # Content area border (thin black)
    content_rect = Rectangle((block_left, y_bottom),
                              block_right - block_left, content_height,
                              facecolor='white', edgecolor=INK, linewidth=0.8,
                              fill=False)
    ax.add_patch(content_rect)

    # Key -> Lock messages (left side)
    y = y_top - header_height - 1.8
    ax.text(25, y, 'Key -> Lock', ha='center', va='center',
            fontsize=8, fontweight='bold', color=INK, family='DejaVu Sans Mono',
            bbox=dict(boxstyle='square,pad=0.3', facecolor=LIGHT_GRAY,
                      edgecolor=INK, linewidth=0.5))
    y -= 1.8
    for line in k2l_lines:
        ax.text(25, y, line, ha='center', va='center',
                fontsize=7.5, color=INK, family='DejaVu Sans Mono')
        y -= 1.5

    # Lock -> Key messages (right side)
    y = y_top - header_height - 1.8
    ax.text(75, y, 'Lock -> Key', ha='center', va='center',
            fontsize=8, fontweight='bold', color=INK, family='DejaVu Sans Mono',
            bbox=dict(boxstyle='square,pad=0.3', facecolor=LIGHT_GRAY,
                      edgecolor=INK, linewidth=0.5))
    y -= 1.8
    for line in l2k_lines:
        ax.text(75, y, line, ha='center', va='center',
                fontsize=7.5, color=INK, family='DejaVu Sans Mono')
        y -= 1.5

    # Note at bottom of block
    if note:
        ax.text(50, y_bottom + 1.2, note, ha='center', va='center',
                fontsize=7.5, color=MID_GRAY, family='DejaVu Sans Mono',
                style='italic')

    return y_bottom

def draw_arrow_down(x, y_top, y_bottom):
    """Draw a vertical down arrow between phases."""
    ax.annotate('', xy=(x, y_bottom), xytext=(x, y_top),
                arrowprops=dict(arrowstyle='->', color=INK, lw=1.0))

# =============================================================================
# Phase 1: Identity Exchange
# =============================================================================
y = 124
y_bot = draw_phase(
    y_top=y,
    phase_num=1,
    phase_title='IDENTITY EXCHANGE',
    phase_desc='plaintext system ID + key ID + counter',
    k2l_lines=[
        '82 00 01 01 1B 03',
        '56 31 30 30 34 XX XX XX',
        '1E 1E 1E 1E 1E 1E 1E',
        '41 02 00 08 01 04',
        '[6B counter] [CRC]',
    ],
    l2k_lines=[
        '00 01 11 18 03',
        '56 31 30 30 34 XX XX XX',
        '1E 1E 1E 1E 1E 1E 1E',
        '61 90 01 01 00 04 00 00',
        '[CRC]',
    ],
    note='System ID "V1004XXX" sent in PLAINTEXT.  Bytes 27-28 = key identifier (visible in clear).'
)

# Arrow to next phase
draw_arrow_down(50, y_bot - 0.5, y_bot - 3.0)

# =============================================================================
# Phase 2: Nonce Exchange
# =============================================================================
y = y_bot - 3.5
y_bot = draw_phase(
    y_top=y,
    phase_num=2,
    phase_title='NONCE EXCHANGE  (CHALLENGE)',
    phase_desc='lock emits 8 random bytes',
    k2l_lines=[
        '82 00 02 08 00',
        '[CRC]',
        '',
        '(read memory',
        ' command)',
    ],
    l2k_lines=[
        '00 02 11 08',
        'DC AF E0 29 A9 9C 5B 95',
        '[CRC]',
        '',
        '(8-byte',
        ' challenge nonce)',
    ],
    note='7 captures: all unique nonces, mean pairwise Hamming ~ 50.1%.  Nonce generation looks solid.'
)

draw_arrow_down(50, y_bot - 0.5, y_bot - 3.0)

# =============================================================================
# Phase 3: Encrypted Authentication Payload
# =============================================================================
y = y_bot - 3.5
y_bot = draw_phase(
    y_top=y,
    phase_num=3,
    phase_title='ENCRYPTED AUTHENTICATION PAYLOAD',
    phase_desc='24B ciphertext + 8B plaintext zeros',
    k2l_lines=[
        '82 00 03 0A 20',
        '[ 24B ciphertext  ]',
        '[ dynamic/session ]',
        '00 00 00 00 00 00 00 00',
        '[CRC]',
    ],
    l2k_lines=[
        'ACCEPT:',
        '00 03 11 18',
        '[24 zero bytes]',
        '50',
        '',
        'REJECT:',
        '00 03 21 00 58',
    ],
    note='AES-128 stream-compatible mode (CTR / CBC-zero-pad / CBC-CTS).  '
         '8 zero bytes are PLAINTEXT (static across all 23 captures).'
)

draw_arrow_down(50, y_bot - 0.5, y_bot - 3.0)

# =============================================================================
# Phase 4: MAC Verification
# =============================================================================
y = y_bot - 3.5
y_bot = draw_phase(
    y_top=y,
    phase_num=4,
    phase_title='MAC VERIFICATION',
    phase_desc='22B MAC = 20B SHA-1 + 2B status',
    k2l_lines=[
        '82 00 04 80 15',
        '[ 20B SHA-1 digest ]',
        '[ 2B device status  ]',
        '',
        'matches DS28EC20',
        'Compute MAC command',
    ],
    l2k_lines=[
        '00 04 11 02 01 01',
        '63',
        '',
        '-> motor activates,',
        '   key can be turned',
    ],
    note='Stats (n=6):  mean Hamming distance 50.04%  |  per-bit flip probability 0.5004  (textbook)'
)

# =============================================================================
# Footer
# =============================================================================
ax.plot([10, 90], [5.5, 5.5], color=INK, linewidth=0.8)
ax.text(50, 4, 'Sources: 23 captures (2014-2024), Uni Rostock IuK prior research + 2024 Saleae captures.',
        ha='center', va='center', fontsize=8, color=MID_GRAY,
        family='DejaVu Sans Mono')
ax.text(50, 2.5, 'Statistics over 6-7 paired (nonce, MAC) sessions.  '
        'System ID last 3 digits redacted for responsible disclosure.',
        ha='center', va='center', fontsize=8, color=MID_GRAY,
        family='DejaVu Sans Mono')

# =============================================================================
# Save
# =============================================================================
import os
out_path = '/home/z/my-project/review/cliq-protocol-cryptanalysis/assets/protocol_flow.png'
os.makedirs(os.path.dirname(out_path), exist_ok=True)
plt.savefig(out_path, dpi=150, facecolor='white', bbox_inches='tight',
            pad_inches=0.4, edgecolor='none')
plt.close(fig)

size_kb = os.path.getsize(out_path) / 1024
print(f'Generated: {out_path} ({size_kb:.0f} KB)')

# Also check dimensions
from PIL import Image
img = Image.open(out_path)
print(f'Dimensions: {img.size[0]} x {img.size[1]} pixels')
