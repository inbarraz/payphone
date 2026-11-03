"""Generate phone/RAM-MAP.md: every RAM cell the ROM points a register at.

Reads the hand-maintained name table in tools/ram_names.txt and the signature
scan in tools/ram_cells.txt (produced by tools/ram_classify.py). Run from the
repository root.
"""
import collections, io, os

d = open('ROM/TAMAC-18 V2.8 9513.bin', 'rb').read()

known, nolabel = {}, set()
for line in io.open('tools/ram_names.txt'):
    a, n = line.split()
    if n.endswith('|NOLABEL'):
        n = n[:-8]; nolabel.add(int(a, 16))
    known[int(a, 16)] = None if n == '-' else n

anchors = collections.defaultdict(list)
for i in range(len(d) - 4):
    if d[i] == 0x68 and 0xc0 <= d[i + 1] <= 0xcf:
        t = (d[i + 2] << 8) | d[i + 3]
        if t >= 0x8000:
            anchors[t].append(i)
for i in range(len(d) - 6):
    if d[i] == 0x68 and d[i + 1] == 0x83:
        t = (d[i + 4] << 8) | d[i + 5]
        if 0x8000 <= t < 0x9900:
            anchors[t].append(i + 4)

sig = {}
for line in io.open('tools/ram_cells.txt'):
    cell = int(line[:4], 16)
    parts = dict(p.split('=', 1) for p in line[5:].split() if '=' in p)
    sig[cell] = parts

PAGES = [
    (0x8000, 0x8100, 'Page `80` — the card-reader link, the credit pools and the display frame'),
    (0x8100, 0x8200, 'Page `81` — timers, mode flags and call state'),
    (0x8200, 0x8500, 'Pages `82`–`84` — the fault log and event records'),
    (0x8500, 0x8600, 'Page `85` — provisioning and the totalizer bank'),
    (0x8600, 0x8800, 'Pages `86`–`87` — the technician menu and its buffers'),
    (0x8800, 0x8A00, 'Page `88`–`89` — counters, the state machine and the stack'),
    (0x8A00, 0x8D00, 'Pages `8A`–`8C` — the DLC / line side'),
    (0x8D00, 0x9000, 'Pages `8D`–`8E` — the modem side and the ROM checksum'),
    (0x9000, 0xF000, 'Page `97` and above — RAM-resident code and its variables'),
]

out = []
W = out.append
W('# TAMAC-18 RAM map')
W('')
W('Every RAM address the firmware points a register at, with the name it carries')
W('in Ghidra or, where it has none, the signature the ROM shows for it. Generated')
W('from the image by `tools/ram_map.py`, then annotated by hand — regenerating it')
W('rewrites the Sites and Signature columns and keeps the Name column.')
W('')
W('**`Sites`** counts the `RLDI Rn,addr` instructions that point a register at the')
W('cell, plus the `SCAL` inline pointer arguments that name it. It is a lower')
W('bound on real references: code reaches most of these cells by `INC`/`DEC` from a')
W('neighbour, and the handler register map at `5FB1` keeps five of them in')
W('registers across the whole reader link, so a cell with one site may be touched')
W('from a dozen places.')
W('')
W('**`Signature`** is what the walk sees being done to the cell at those sites:')
W('`st` = number of stores, `imm` = the immediates stored, `mask` = the `ANI`')
W('masks applied, `cmp` = the values it is compared against. A cell written only')
W('`AA`/`55` and tested for equality is a sentinel; one written `00`/`01` and')
W('tested for zero is a flag; one with masks is a bit field.')
W('')
tot = named = 0
for lo, hi, title in PAGES:
    cells = [c for c in sorted(anchors) if lo <= c < hi]
    if not cells:
        continue
    W('## ' + title)
    W('')
    W('| Addr | Name | Sites | Signature |')
    W('|---|---|---|---|')
    for c in cells:
        tot += 1
        nm = known.get(c)
        if nm:
            named += 1
            disp = '`%s`' % nm + (' *(no Ghidra label)*' if c in nolabel else '')
        else:
            disp = '—'
        s = sig.get(c, {})
        bits = []
        for k in ('st', 'imm', 'mask', 'cmp'):
            if s.get(k):
                bits.append('%s=%s' % (k, s[k]))
        sites = ' '.join('`%04x`' % a for a in anchors[c][:6])
        if len(anchors[c]) > 6:
            sites += ' +%d' % (len(anchors[c]) - 6)
        W('| `%04X` | %s | %d — %s | %s |' % (c, disp, len(anchors[c]), sites,
                                              ' '.join(bits) or '—'))
    W('')
W('## Tally')
W('')
W('%d anchored cells, **%d named**, %d still unnamed.' % (tot, named, tot - named))
io.open('phone/RAM-MAP.md', 'w').write('\n'.join(out) + '\n')
print('%d cells, %d named' % (tot, named))
