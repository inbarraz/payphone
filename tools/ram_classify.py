"""Classify every page-8x/9x RAM cell the ROM anchors, by what the code does with it.

For each cell we find the RLDI sites that point a register at it, then look at the
few instructions that follow to see whether the cell is stored to, loaded from,
incremented, masked, or compared, and with what immediates.
"""
import sys, collections

d = open('ROM/TAMAC-18 V2.8 9513.bin', 'rb').read()

STR = {0x50 + n: n for n in range(16)}          # STR Rn
LDN = {0x00 + n: n for n in range(1, 16)}       # LDN Rn (0x00 is IDL)
LDA = {0x40 + n: n for n in range(16)}          # LDA Rn
INC = {0x10 + n: n for n in range(16)}
DEC = {0x20 + n: n for n in range(16)}

anchors = collections.defaultdict(list)
for i in range(len(d) - 4):
    if d[i] == 0x68 and 0xc0 <= d[i + 1] <= 0xcf:
        tgt = (d[i + 2] << 8) | d[i + 3]
        if tgt >= 0x8000:
            anchors[tgt].append((i + 4, d[i + 1] & 0xf))

def scan(start, reg, limit=24):
    """Walk forward from an RLDI, reporting what happens to M(reg) before reg moves."""
    acts = []
    i = start
    pending_imm = None
    while i < min(start + limit, len(d)):
        op = d[i]
        if op == 0xf8:                              # LDI imm
            pending_imm = d[i + 1]; i += 2; continue
        if op in STR and STR[op] == reg:
            acts.append(('store', pending_imm)); i += 1; continue
        if op in LDN and LDN[op] == reg:
            nxt = d[i + 1]
            if nxt == 0xfb:   acts.append(('xri', d[i + 2]))
            elif nxt == 0xfa: acts.append(('ani', d[i + 2]))
            elif nxt == 0xff: acts.append(('smi', d[i + 2]))
            elif nxt == 0xfc: acts.append(('adi', d[i + 2]))
            elif nxt == 0xf6: acts.append(('shr', None))
            elif nxt == 0xfe: acts.append(('shl', None))
            elif nxt in (0xc2, 0xca): acts.append(('testz', None))
            else: acts.append(('load', None))
            i += 1; continue
        if op in LDA and LDA[op] == reg:
            acts.append(('load', None)); break
        if (op in INC and INC[op] == reg) or (op in DEC and DEC[op] == reg):
            break
        if op == 0x68 and 0xc0 <= d[i + 1] <= 0xcf and (d[i + 1] & 0xf) == reg:
            break
        if op in (0xc0, 0xc2, 0xc3, 0xc9, 0xca, 0xcb, 0xc1): i += 3; continue
        if op == 0x68: i += 2; continue
        if 0x30 <= op <= 0x3f or op in (0xfb,0xfa,0xff,0xfc,0xf9,0xfd,0xfe,0xf6): i += 2; continue
        i += 1
    return acts

rows = []
for cell in sorted(anchors):
    acts = []
    for site, reg in anchors[cell]:
        acts += scan(site, reg)
    stores = [v for k, v in acts if k == 'store']
    imms   = sorted({v for v in stores if v is not None})
    kinds  = collections.Counter(k for k, _ in acts)
    masks  = sorted({v for k, v in acts if k == 'ani'})
    cmps   = sorted({v for k, v in acts if k in ('xri', 'smi')})
    rows.append(dict(cell=cell, sites=len(anchors[cell]), stores=len(stores),
                     imms=imms, masks=masks, cmps=cmps,
                     inc=kinds['adi'], dec=kinds['smi'],
                     bits=kinds['ani'] + kinds['shr'] + kinds['shl']))

for r in rows:
    print("%04x n=%-3d st=%-2d imm=%-22s mask=%-16s cmp=%s" % (
        r['cell'], r['sites'], r['stores'],
        ",".join("%02x" % v for v in r['imms'][:6]),
        ",".join("%02x" % v for v in r['masks'][:4]),
        ",".join("%02x" % v for v in r['cmps'][:6])))
print("TOTAL", len(rows), file=sys.stderr)
