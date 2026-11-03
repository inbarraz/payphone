"""Classify every page-8x/9x RAM cell the ROM anchors, by what the code does with it.

For each cell we find the RLDI sites that point a register at it, then walk
forward over the instruction stream to see whether the cell is stored to, loaded
from, masked or compared, and with what immediates.

The walk is a HEURISTIC and its limits matter, because phone/RAM-MAP.md's
Signature column comes straight out of it:

  - it follows the fall-through path only, so anything reachable solely by a
    taken branch is invisible;
  - it stops as soon as the anchored register is moved or reloaded, so a cell
    touched later through the same register is missed;
  - it does not model X, so ADD/SM against M(R(X)) are recorded as plain loads.

Treat a signature as "at least this much is true of the cell", never as a
complete account. An earlier version also mis-sized several instructions, which
put wrong immediates in the map; the lengths below are now explicit.
"""
import sys, collections

d = open('ROM/TAMAC-18 V2.8 9513.bin', 'rb').read()

STR = {0x50 + n: n for n in range(16)}          # STR Rn
LDN = {0x00 + n: n for n in range(1, 16)}       # LDN Rn (0x00 is IDL)
LDA = {0x40 + n: n for n in range(16)}          # LDA Rn
INC = {0x10 + n: n for n in range(16)}
DEC = {0x20 + n: n for n in range(16)}
GLO = {0x80 + n: n for n in range(16)}
GHI = {0x90 + n: n for n in range(16)}
PLO = {0xa0 + n: n for n in range(16)}
PHI = {0xb0 + n: n for n in range(16)}

TWO_BYTE = {0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff}   # LDI ORI ANI XRI ADI SDI SMI
LONG     = {0xc0, 0xc1, 0xc2, 0xc3, 0xc9, 0xca, 0xcb}   # LBR LBQ LBZ LBDF LBNQ LBNZ LBNF

def ilen(i):
    """Length of the instruction at i."""
    op = d[i]
    if op == 0x68:                                      # 1806 prefix
        n = d[i + 1]
        if (n & 0xf0) in (0x20, 0x80, 0xc0):            # DBNZ, SCAL, RLDI
            return 4
        if n in (0x3e, 0x3f, 0x7c, 0x7d, 0x7f, 0xfc, 0xfd, 0xff):
            return 3                                    # BCI BXI ADCI SDBI SMBI DADI DSMI
        return 2
    if op in LONG:
        return 3
    if 0x30 <= op <= 0x3f:                              # short branches
        return 2
    if op in TWO_BYTE:
        return 2
    return 1                                            # includes SHR F6 and SHL FE

def writes_d(i):
    """Does the instruction at i land a new value in D?"""
    op = d[i]
    return (op in LDN or op in LDA or op in GLO or op in GHI
            or op in TWO_BYTE or op in (0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                                        0xf6, 0xf7, 0xfe, 0x60, 0x72, 0x73)
            or (op == 0x68 and d[i + 1] in (0x06, 0x08)))

anchors = collections.defaultdict(list)
for i in range(len(d) - 4):
    if d[i] == 0x68 and 0xc0 <= d[i + 1] <= 0xcf:
        tgt = (d[i + 2] << 8) | d[i + 3]
        if tgt >= 0x8000:
            anchors[tgt].append((i + 4, d[i + 1] & 0xf))

def scan(start, reg, limit=48):
    """Walk forward from an RLDI, reporting what happens to M(reg) before reg moves."""
    acts = []
    i, imm = start, None
    while i < min(start + limit, len(d)):
        op = d[i]
        n = ilen(i)
        if op == 0xf8:                                  # LDI: remember the value
            imm = d[i + 1]; i += n; continue
        if op in STR and STR[op] == reg:
            acts.append(('store', imm)); i += n; continue
        if op in LDN and LDN[op] == reg:
            nxt = d[i + 1]
            if   nxt == 0xfb: acts.append(('xri', d[i + 2]))
            elif nxt == 0xfa: acts.append(('ani', d[i + 2]))
            elif nxt == 0xff: acts.append(('smi', d[i + 2]))
            elif nxt == 0xfc: acts.append(('adi', d[i + 2]))
            elif nxt == 0xf6: acts.append(('shr', None))
            elif nxt == 0xfe: acts.append(('shl', None))
            elif nxt in (0xc2, 0xca): acts.append(('testz', None))
            else: acts.append(('load', None))
            imm = None; i += n; continue
        if op in LDA and LDA[op] == reg:
            acts.append(('load', None)); break          # LDA moves the register
        # the register is moved, reloaded or redirected: stop
        if ((op in INC and INC[op] == reg) or (op in DEC and DEC[op] == reg)
                or (op in PLO and PLO[op] == reg) or (op in PHI and PHI[op] == reg)
                or (op == 0x68 and (d[i + 1] & 0xf0) == 0xc0 and (d[i + 1] & 0xf) == reg)
                or (op == 0x68 and (d[i + 1] & 0xf0) in (0x60, 0xa0, 0xb0)
                    and (d[i + 1] & 0xf) == reg)):
            break
        if op == 0xc0:                                  # unconditional LBR: path ends
            break
        if writes_d(i):
            imm = None
        i += n
    return acts

rows = []
for cell in sorted(anchors):
    acts = []
    for site, reg in anchors[cell]:
        acts += scan(site, reg)
    stores = [v for k, v in acts if k == 'store']
    kinds = collections.Counter(k for k, _ in acts)
    rows.append(dict(cell=cell, sites=len(anchors[cell]), stores=len(stores),
                     imms=sorted({v for v in stores if v is not None}),
                     masks=sorted({v for k, v in acts if k == 'ani'}),
                     cmps=sorted({v for k, v in acts if k in ('xri', 'smi')})))

for r in rows:
    print("%04x n=%-3d st=%-2d imm=%-22s mask=%-16s cmp=%s" % (
        r['cell'], r['sites'], r['stores'],
        ",".join("%02x" % v for v in r['imms'][:6]),
        ",".join("%02x" % v for v in r['masks'][:4]),
        ",".join("%02x" % v for v in r['cmps'][:6])))
print("TOTAL", len(rows), file=sys.stderr)
