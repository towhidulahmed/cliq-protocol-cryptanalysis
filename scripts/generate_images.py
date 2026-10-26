#!/usr/bin/env python3
"""
Generates assets/protocol_flow.png and assets/packet_format.png.

Both figures are laid out as HTML (absolutely positioned elements, inline
styles) from the decoded 2024 sessions, so every number in them is computed,
and rendered to PNG at 2x with headless Chromium. Requires Playwright:

    pip install playwright
    python -m playwright install chromium

Pass --html to also write the HTML sources next to the PNGs.
"""
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sessions import REPO_ROOT, load_captures, unique

OUT = os.path.join(REPO_ROOT, 'assets')

# Design tokens
GROUND = '#FFFFFF'
INK = '#111111'
MUTED = '#555555'
RULE = '#BFBFBF'
LIFELINE = '#404040'
ARROW = '#111111'
BUSY = '#808080'
AMBER = ('#FFF2CC', '#BF9000', '#7F6000')    # fill, border, ink: plaintext identifiers
BLUE = ('#DDEBF7', '#2F5597', '#1F3864')     # cryptographic fields
GREY = ('#F2F2F2', '#7F7F7F', '#262626')     # framing, constants
CARD_RADIUS = 0
PILL_RADIUS = 2
SANS = "'Roboto', 'Helvetica Neue', Arial, sans-serif"
MONO = "'Roboto Mono', Consolas, 'DejaVu Sans Mono', monospace"
FONTS = ('<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
         'family=Roboto+Mono:wght@400;500&family=Roboto:wght@400;500;700&display=swap">')
W = 1400


def page(title, width, height, body):
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
{FONTS}
<style>body{{margin:0;background:{GROUND}}}</style>
</head>
<body>
<div id="figure" style="position: relative; width: {width}px; height: {height}px; background: {GROUND}; color: {INK}; font-family: {SANS}">
{body}
</div>
</body>
</html>
'''


def text(x, y, content, size=15, weight=400, color=INK, width=None, family=SANS, align='left', extra=''):
    w = f' width: {width}px;' if width else ''
    return (f'<div style="position: absolute; left: {x}px; top: {y}px;{w} font-family: {family}; '
            f'font-size: {size}px; line-height: {round(size * 1.4)}px; font-weight: {weight}; '
            f'color: {color}; text-align: {align};{extra}">{content}</div>')


def pill(label, colors, mono=False):
    fill, border, ink = colors
    family = MONO if mono else SANS
    return (f'<span style="display: inline-block; padding: 0 7px; margin: 0 2px; border-radius: {PILL_RADIUS}px; '
            f'background: {fill}; border: 1px solid {border}; color: {ink}; font-family: {family}; '
            f'font-size: 12px; line-height: 20px; font-weight: 500; vertical-align: 1px">{label}</span>')


def mono(s, color=INK):
    return f'<span style="font-family: {MONO}; color: {color}">{s}</span>'


def hline(x, y, length, color=RULE, width=1, dash=None):
    style = f'border-top: {width}px {"dashed" if dash else "solid"} {color}'
    return f'<div style="position: absolute; left: {x}px; top: {y}px; width: {length}px; height: 0; {style}"></div>'


def vline(x, y, length, color=LIFELINE, width=2):
    return (f'<div style="position: absolute; left: {x - width // 2}px; top: {y}px; width: {width}px; '
            f'height: {length}px; background: {color}"></div>')


ARROW_ID = [0]


def arrow(x1, x2, y, color=ARROW, width=2, dash=False):
    """Horizontal arrow from x1 to tip x2 (either direction), one svg per segment."""
    ARROW_ID[0] += 1
    n = abs(x2 - x1)
    h = 2 * width
    left = min(x1, x2)
    d = f'M 0 4 L {n - h} 4' if x2 > x1 else f'M {n} 4 L {h} 4'
    dash_css = '; stroke-dasharray: 5 5' if dash else ''
    mid = f'dc-arrow-head-filled-{ARROW_ID[0]}'
    return (f'<svg width="{n}" height="8" viewBox="0 0 {n} 8" preserveAspectRatio="none" '
            f'style="position: absolute; left: {left}px; top: {y - 4}px; width: {n}px; height: 8px; '
            f'overflow: visible; fill: none; stroke: {color}; stroke-width: {width}; stroke-linecap: round; '
            f'stroke-linejoin: round{dash_css}"><defs><marker id="{mid}" orient="auto" markerWidth="5" '
            f'markerHeight="5" refX="2" refY="2" overflow="visible"><path d="M0 0 L4 2 L0 4 Z" fill="{color}" '
            f'stroke="none" style="stroke: none; fill: {color}; fill: context-stroke"/></marker></defs>'
            f'<path d="{d}" marker-end="url(#{mid})"></path></svg>')


def legend(right, y):
    items = [('plaintext identifier', AMBER), ('cryptographic field', BLUE), ('framing / constant', GREY)]
    html = ''.join(f'<span style="display: flex; align-items: center; gap: 8px">'
                   f'<span style="width: 14px; height: 14px; background: {c[0]}; '
                   f'border: 1px solid {c[1]}"></span>{label}</span>' for label, c in items)
    return (f'<div style="position: absolute; right: {right}px; top: {y}px; display: flex; gap: 20px; '
            f'font-size: 13px; line-height: 20px; color: {MUTED}">{html}</div>')


# ---------------------------------------------------------------------------
# Figure 1: unlock sequence
# ---------------------------------------------------------------------------

def waits(uniq, code):
    ws = [w for s in uniq for w in s['timing']['waits'] if w['after_code'] == code]
    polls = sorted({w['polls'] for w in ws})
    p = f'{polls[0]}' if len(polls) == 1 else f'{polls[0]}-{polls[-1]}'
    return f'{p} busy polls · {min(w["ms"] for w in ws):.1f}-{max(w["ms"] for w in ws):.1f} ms'


def protocol_flow(uniq):
    KX, CX = 440, W - 64 - 140
    totals = [s['timing']['total_ms'] for s in uniq]
    poll = {k: statistics.mean(s['timing']['poll_interval_ms'] for s in uniq if s['folder'] == k)
            for k in ('key_a', 'key_b')}
    A = lambda s: pill(s, AMBER)
    B = lambda s: pill(s, BLUE)
    G = lambda s: pill(s, GREY)
    K2C, C2K = 'k2c', 'c2k'
    steps = [
        ('1', 'Identity', '29-byte format', [
            ('arrow', K2C, mono('82 00 01 01 1D') + A('system ID') + A('key config') + A('date · time') + G('0E 00')),
            ('arrow', C2K, mono('84 00 01 34 00 47') + '&nbsp; refused, ' + mono('error 0x34')),
        ]),
        ('2', 'Identity', 'key falls back to the 2014 format', [
            ('arrow', K2C, mono('82 00 02 01 1B') + A('system ID') + A('key config') + A('date · time')),
            ('busy', C2K, mono('84 00 02 10 00') + '&nbsp; busy'),
            ('wait', waits(uniq, 0x01)),
            ('arrow', C2K, mono('84 00 02 11 18') + A('system ID') + A('cylinder no.')),
        ]),
        ('3', 'Challenge', 'cylinder generates the nonce', [
            ('arrow', K2C, mono('82 00 03 08 00')),
            ('busy', C2K, mono('84 00 03 10 00') + '&nbsp; busy'),
            ('wait', waits(uniq, 0x08)),
            ('arrow', C2K, mono('84 00 03 11 08') + B('nonce · 8 B')),
        ]),
        ('4', 'Encrypted block', 'authorization is decided here', [
            ('arrow', K2C, mono('82 00 04 0A 20') + B('encrypted · 24 B') + G('00 × 8')),
            ('busy', C2K, mono('84 00 04 10 00') + '&nbsp; busy'),
            ('wait', waits(uniq, 0x0A)),
            ('arrow', C2K, mono('84 00 04 11 18') + G('00 × 24') + '&nbsp; or, unauthorized key, '
             + mono('error 0x21')),
        ]),
        ('5', 'MAC', 'verified by the cylinder', [
            ('arrow', K2C, mono('82 00 05 80 15') + B('MAC · 21 B')),
            ('busy', C2K, mono('84 00 05 10 00') + '&nbsp; busy'),
            ('wait', waits(uniq, 0x80)),
            ('arrow', C2K, mono('84 00 05 11 02 01 01') + '&nbsp; cylinder releases'),
        ]),
    ]

    el = []
    el.append(text(64, 56, 'Unlock sequence', size=28, weight=700))
    el.append(text(64, 104, f'VERSO CLIQ key and cylinder, 2024 captures &nbsp;·&nbsp; {len(uniq)} sessions, '
                            f'2 keys, 2 cylinders &nbsp;·&nbsp; {min(totals):.1f}-{max(totals):.1f} ms per unlock',
                   size=15, color=MUTED))
    el.append(legend(64, 64))

    # Lifeline heads
    for x, name, sub in ((KX, 'Key', 'bus master · powers the cylinder'),
                         (CX, 'Cylinder', 'no battery · keeps rights and audit log')):
        el.append(f'<div style="position: absolute; left: {x - 140}px; top: 164px; width: 280px; height: 64px; '
                  f'box-sizing: border-box; display: flex; align-items: center; justify-content: center; '
                  f'text-align: center; background: #FFFFFF; border: 1px solid {LIFELINE}; border-radius: {CARD_RADIUS}px">'
                  f'<span><b style="font-size: 16px; font-weight: 700">{name}</b><br>'
                  f'<span style="font-size: 12px; color: {MUTED}">{sub}</span></span></div>')

    y = 268
    rows = []
    for i, (num, title, note, items) in enumerate(steps):
        if i:
            rows.append(hline(64, y, W - 128))
            y += 24
        top = y
        rows.append(text(64, top, f'STEP {num}', size=12, weight=700, color=MUTED,
                         extra=' letter-spacing: 0.08em;'))
        rows.append(text(64, top + 20, title, size=17, weight=700, width=240))
        rows.append(text(64, top + 46, note, size=13, color=MUTED, width=230))
        for item in items:
            if item[0] == 'wait':
                rows.append(f'<div style="position: absolute; left: {KX + 24}px; top: {y + 2}px; '
                            f'width: {CX - KX - 48}px; display: flex; align-items: center; gap: 12px; '
                            f'font-size: 13px; line-height: 20px; color: {MUTED}">'
                            f'<span style="flex: 1; border-top: 1px dotted {BUSY}"></span>{item[1]}'
                            f'<span style="flex: 1; border-top: 1px dotted {BUSY}"></span></div>')
                y += 36
                continue
            kind, direction, label = item
            busy = kind == 'busy'
            rows.append(f'<div style="position: absolute; left: {KX + 20}px; top: {y}px; width: {CX - KX - 40}px; '
                        f'text-align: center; font-size: 13px; line-height: 22px; '
                        f'color: {MUTED if busy else INK}">{label}</div>')
            ay = y + 34
            if direction == K2C:
                rows.append(arrow(KX + 2, CX - 3, ay, BUSY if busy else ARROW, 1.5 if busy else 2, busy))
            else:
                rows.append(arrow(CX - 2, KX + 3, ay, BUSY if busy else ARROW, 1.5 if busy else 2, busy))
            y += 60
        y = max(y, top + 92) + 8

    el.insert(0, vline(KX, 228, y - 228))
    el.insert(1, vline(CX, 228, y - 228))
    el.extend(rows)

    y += 16
    el.append(hline(64, y, W - 128))
    el.append(text(64, y + 20,
                   f'Every packet is {mono("[82|84] 00 SEQ CODE LEN DATA CHK")}; all its bytes sum to '
                   f'{mono("0x00")} mod 256. While the cylinder is busy, the key reads one status bit every '
                   f'{poll["key_a"]:.3f} ms (key A) or {poll["key_b"]:.3f} ms (key B).',
                   size=13, color=MUTED, width=W - 128))
    height = y + 84
    return page('Unlock sequence', W, height, '\n'.join(el)), height


# ---------------------------------------------------------------------------
# Figure 2: field maps
# ---------------------------------------------------------------------------

BYTE = 39  # px per byte in every field map


def field_map(x, y, fields):
    """fields: [(label, n_bytes, colors, sublabel)] drawn as one row of cells with byte offsets above."""
    el = []
    off = 0
    cx = x
    for label, n, colors, sub in fields:
        fill, border, ink = colors
        w = n * BYTE
        el.append(text(cx, y, str(off), size=11, color=MUTED, family=MONO))
        if label:
            inner = (f'<span><span style="font-size: 13px; font-weight: 500">{label}</span>'
                     + (f'<br><span style="font-family: {MONO}; font-size: 11px; opacity: 0.85">{sub}</span>'
                        if sub else '') + '</span>')
        else:
            inner = f'<span style="font-family: {MONO}; font-size: 13px; font-weight: 500">{sub}</span>'
        el.append(f'<div style="position: absolute; left: {cx}px; top: {y + 20}px; width: {w}px; height: 52px; '
                  f'box-sizing: border-box; display: flex; align-items: center; justify-content: center; '
                  f'text-align: center; line-height: 16px; padding: 0 4px; background: {fill}; '
                  f'border: 1px solid {border}; margin-left: -1px; color: {ink}">{inner}</div>')
        off += n
        cx += w
    el.append(text(cx, y, str(off), size=11, color=MUTED, family=MONO))
    return el


def section(y, title, meta, fields, caption):
    el = [text(64, y, title, size=16, weight=700),
          text(64, y + 24, meta, size=13, color=MUTED)]
    el += field_map(64, y + 52, fields)
    if caption:
        el.append(text(64, y + 134, caption, size=13, color=MUTED, width=W - 128))
    return el


def packet_format(uniq):
    el = [text(64, 56, 'Packet and field layout', size=28, weight=700),
          text(64, 104, 'VERSO CLIQ key-cylinder protocol, decoded from the 2024 captures &nbsp;·&nbsp; '
                        'byte offsets above each field', size=15, color=MUTED),
          legend(64, 64)]

    y = 172
    el.append(text(64, y, 'Framing', size=16, weight=700))
    el.append(text(64, y + 24, 'every packet, both directions', size=13, color=MUTED))
    frame = [('SEQ', 1, GREY, '1-5'), ('CODE', 1, GREY, None), ('LEN', 1, GREY, None),
             ('DATA', 8, GREY, 'LEN bytes'), ('CHK', 1, GREY, None)]
    for i, (prefix, who) in enumerate((('82', 'Command · key → cylinder'), ('84', 'Response · cylinder → key'))):
        ry = y + 52 + i * 90
        el.append(text(64, ry, who, size=13, weight=500))
        cx = 64
        for label, n, colors, sub in [(prefix, 1, GREY, None), ('00', 1, GREY, None)] + frame:
            fill, border, ink = colors
            inner = (f'<span><span style="font-family: {MONO}; font-size: 13px; font-weight: 500">{label}</span>'
                     + (f'<br><span style="font-size: 11px">{sub}</span>' if sub else '') + '</span>')
            el.append(f'<div style="position: absolute; left: {cx}px; top: {ry + 24}px; width: {n * 52}px; '
                      f'height: 52px; box-sizing: border-box; display: flex; align-items: center; '
                      f'justify-content: center; text-align: center; line-height: 16px; background: {fill}; '
                      f'border: 1px solid {border}; margin-left: -1px; color: {ink}">{inner}</div>')
            cx += n * 52
    codes = [
        ('CODE · command', '01 identity · 08 nonce request · 0A encrypted block · 80 MAC'),
        ('CODE · status', '10 busy · 11 ok · 21 rejected at the encrypted block · 23 rejected at the MAC · '
                          '34 identity format refused'),
        ('CHK', '(0x100 - sum of all preceding bytes) mod 256'),
    ]
    tx = 64 + 13 * 52 + 64
    cy = y + 52
    for k, v in codes:
        el.append(text(tx, cy + 1, k.upper(), size=11, weight=700, color=MUTED, width=140,
                       extra=' letter-spacing: 0.06em;'))
        el.append(text(tx + 148, cy, v, size=13, width=W - 64 - tx - 148))
        cy += 62 if len(v) > 60 else 44
    y += 250
    el.append(hline(64, y, W - 128))
    y += 32
    cfg = {s['folder']: ' '.join(f'{b:02X}' for b in s['key_config']) for s in uniq}
    el += section(y, 'Key identity', 'step 2 data, LEN 0x1B, key → cylinder', [
        ('', 1, GREY, '03'), ('system ID', 8, AMBER, 'ASCII'), ('padding', 7, GREY, '1E × 7'),
        ('key config', 6, AMBER, cfg['key_a']), ('day', 2, AMBER, 'u16 LE'), ('minute', 2, AMBER, 'u16 LE'),
        ('s', 1, AMBER, 'u8')],
        'day 1 = 2000-01-01; minute of the day in local time. Key B config: ' + mono(cfg['key_b'])
        + '. The 29-byte variant of step 1 appends ' + mono('0E 00') + '.')
    y += 196
    el += section(y, 'Cylinder identity', 'step 2 reply data, LEN 0x18, cylinder → key', [
        ('', 1, GREY, '03'), ('system ID', 8, AMBER, 'ASCII'), ('padding', 7, GREY, '1E × 7'),
        ('', 1, GREY, '61'), ('cyl. no.', 2, AMBER, 'u16 LE'), ('constant', 5, GREY, '01 00 04 00 00')],
        'cylinder numbers seen: 16 and 397 (2024), 400 (2014)')
    y += 196
    el += section(y, 'Nonce', 'step 3 reply data, LEN 0x08, cylinder → key',
                  [('nonce', 8, BLUE, 'new every session')], None)
    y += 168
    el += section(y, 'Encrypted block', 'step 4 data, LEN 0x20, key → cylinder',
                  [('encrypted', 24, BLUE, 'new every session'), ('zero', 8, GREY, '00 × 8')], None)
    y += 168
    el += section(y, 'MAC', 'step 5 data, LEN 0x15, key → cylinder',
                  [('MAC', 21, BLUE, 'new every session')], None)
    y += 160
    el.append(hline(64, y, W - 128))
    el.append(text(64, y + 20, 'The vendor states 128-bit AES for key-cylinder communication. The cipher mode '
                               'and the MAC construction cannot be identified from passive captures.',
                   size=13, color=MUTED, width=W - 128))
    height = y + 84
    return page('Packet and field layout', W, height, '\n'.join(el)), height


def render(html, height, name, keep_html):
    from playwright.sync_api import sync_playwright
    path = os.path.join(OUT, name)
    if keep_html:
        with open(path.replace('.png', '.html'), 'w') as f:
            f.write(html)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        pg = browser.new_page(viewport={'width': W, 'height': height}, device_scale_factor=2)
        pg.set_content(html, wait_until='networkidle')
        pg.evaluate('document.fonts.ready')
        pg.locator('#figure').screenshot(path=path)
        browser.close()
    print(f'{name}: {os.path.getsize(path) / 1024:.0f} KB')


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    keep = '--html' in sys.argv
    uniq = unique(load_captures())
    render(*protocol_flow(uniq), 'protocol_flow.png', keep)
    render(*packet_format(uniq), 'packet_format.png', keep)
