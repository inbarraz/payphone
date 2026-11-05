"""Linear CDP1802/1805/1806 disassembler for the TAMAC-18 image.

Hand-counting bytes has been this project's most reliable source of wrong
addresses: several retracted claims (the 51B3 fall-through, "51AD tests GHI RD",
the 509C/509D slip) were all off-by-a-few arithmetic, not bad reasoning. This
exists so a range can be read without doing that arithmetic by hand.

Two things a naive linear sweep gets wrong on this architecture, both handled:

  * THE X == P INLINE FORM. When X equals P, R(X) is the program counter, so the
    instructions that increment R(X) - IRX, OUT, RET, DIS, LDXA - take their
    operand from the instruction stream and are two bytes, not one. Nothing in
    the opcode says so. In this firmware P is always R4, so the idiom is always
    spelled `SEX R4` (0xE4) immediately before, and that is the rule applied
    here. INP does NOT increment R(X), so it has no inline form.

  * INLINE CALL ARGUMENTS. SCAL pushes the return address and the callee reads
    its arguments out of the caller's instruction stream via R3, returning past
    them with SRET. The argument bytes are data, and decoding them as code
    invents plausible instructions - this is how a phantom `OUT 4` ended up in
    the credit renderer. Signatures come from cdp1806/data/inline_args.txt.

Usage:  python3 -I tools/dis.py <start-hex> <end-hex> [more ranges...]
"""
import io, os, re, sys

ROM = 'ROM/TAMAC-18 V2.8 9513.bin'
d = open(ROM, 'rb').read()

R = lambda n: 'R%X' % n

# ---------------------------------------------------------------- 1805/1806 ---
PFX = {0x00: 'STPC', 0x01: 'DTC', 0x02: 'SPM2', 0x03: 'SCM2', 0x04: 'SPM1',
       0x05: 'SCM1', 0x06: 'LDC', 0x07: 'STM', 0x08: 'GEC', 0x09: 'ETQ',
       0x0a: 'XIE', 0x0b: 'XID', 0x0c: 'CIE', 0x0d: 'CID',
       0x3e: 'BCI', 0x3f: 'BXI', 0x74: 'DADC', 0x76: 'DSAV', 0x77: 'DSMB',
       0x7c: 'DACI', 0x7f: 'DSBI', 0xf4: 'DADD', 0xf7: 'DSM',
       0xfc: 'DADI', 0xff: 'DSMI'}

def prefixed(n, i):
    """Decode the 0x68-prefixed instruction whose second byte is n."""
    hi, lo = n >> 4, n & 0xf
    if n in PFX and hi not in (2, 6, 8, 9, 0xa, 0xb, 0xc):
        if n in (0x3e, 0x3f):                       # BCI/BXI take a page offset
            return 'B%s  %02X' % ('CI' if n == 0x3e else 'XI', d[i + 2]), 3
        if n in (0x7c, 0x7f, 0xfc, 0xff):
            return '%-5s #%02X' % (PFX[n], d[i + 2]), 3
        return PFX[n], 2
    if hi == 2: return 'DBNZ %s,%04X' % (R(lo), (d[i+2] << 8) | d[i+3]), 4
    if hi == 6: return 'RLXA %s' % R(lo), 2
    if hi == 8: return 'SCAL %s,%04X' % (R(lo), (d[i+2] << 8) | d[i+3]), 4
    if hi == 9: return 'SRET %s' % R(lo), 2
    if hi == 0xa: return 'RSXD %s' % R(lo), 2
    if hi == 0xb: return 'RNX  %s' % R(lo), 2
    if hi == 0xc:
        if lo == 0: return 'RLDI R0,%04X' % ((d[i+2] << 8) | d[i+3]), 4
        return 'RLDI %s,%04X' % (R(lo), (d[i+2] << 8) | d[i+3]), 4
    return '?68 %02X' % n, 2

# ---------------------------------------------------------------------- 1802 ---
SHORT = {0x30: 'BR', 0x31: 'BQ', 0x32: 'BZ', 0x33: 'BDF', 0x34: 'B1',
         0x35: 'B2', 0x36: 'B3', 0x37: 'B4', 0x38: 'NBR', 0x39: 'BNQ',
         0x3a: 'BNZ', 0x3b: 'BNF', 0x3c: 'BN1', 0x3d: 'BN2', 0x3e: 'BN3',
         0x3f: 'BN4'}
LONGB = {0xc0: 'LBR', 0xc1: 'LBQ', 0xc2: 'LBZ', 0xc3: 'LBDF', 0xc8: 'LSKP',
         0xc9: 'LBNQ', 0xca: 'LBNZ', 0xcb: 'LBNF'}
SKIP  = {0xc4: 'NOP', 0xc5: 'LSNQ', 0xc6: 'LSNZ', 0xc7: 'LSNF',
         0xcc: 'LSIE', 0xcd: 'LSQ', 0xce: 'LSZ', 0xcf: 'LSDF'}
# Every 2-byte immediate. 7C/7D/7F are easy to miss because the rest of the 7x
# block is 1-byte register ops, and ALU below also names them - but `op in IMM`
# is tested first, so listing them here is what gives them their operand byte.
# Sized at 1 they printed the operand as a separate instruction, and since
# ADCI #00 is `7c 00` the phantom was always IDL, which reads as a mis-decode of
# DATA rather than as a tool bug. It put a bogus IDL at 048F and 1455 in this
# project's listings; Grok's review caught it.
IMM   = {0x7c: 'ADCI', 0x7d: 'SDBI', 0x7f: 'SMBI',
         0xf8: 'LDI', 0xf9: 'ORI', 0xfa: 'ANI', 0xfb: 'XRI', 0xfc: 'ADI',
         0xfd: 'SDI', 0xff: 'SMI'}
ALU   = {0xf0: 'LDX', 0xf1: 'OR', 0xf2: 'AND', 0xf3: 'XOR', 0xf4: 'ADD',
         0xf5: 'SD', 0xf6: 'SHR', 0xf7: 'SM', 0xfe: 'SHL',
         0x70: 'RET', 0x71: 'DIS', 0x72: 'LDXA', 0x73: 'STXD',
         0x74: 'ADC', 0x75: 'SDB', 0x76: 'SHRC', 0x77: 'SMB',
         0x7a: 'REQ', 0x7b: 'SEQ', 0x7c: 'ADCI', 0x7d: 'SDBI',
         0x7e: 'SHLC', 0x7f: 'SMBI', 0x60: 'IRX', 0x78: 'SAV', 0x79: 'MARK'}

# Instructions that increment R(X): two bytes when X == P.
INLINEABLE = {0x60, 0x70, 0x71, 0x72} | set(range(0x61, 0x68))

def decode(i):
    """Return (text, length) for the instruction at i."""
    op = d[i]
    if op == 0x68:
        return prefixed(d[i + 1], i)
    if op == 0x00: return 'IDL', 1
    if op < 0x10:  return 'LDN  %s' % R(op), 1
    if op < 0x20:  return 'INC  %s' % R(op & 0xf), 1
    if op < 0x30:  return 'DEC  %s' % R(op & 0xf), 1
    if op < 0x40:  return '%-4s %02X' % (SHORT[op], d[i + 1]), 2
    if op < 0x50:  return 'LDA  %s' % R(op & 0xf), 1
    if op < 0x60:  return 'STR  %s' % R(op & 0xf), 1
    if op == 0x60: return 'IRX', 1
    if op < 0x68:  return 'OUT  %d' % (op & 7), 1
    if op < 0x70:  return 'INP  %d' % (op & 7), 1
    if op in LONGB: return '%-4s %04X' % (LONGB[op], (d[i+1] << 8) | d[i+2]), 3
    if op in SKIP:  return SKIP[op], 1
    if op in IMM:   return '%-4s #%02X' % (IMM[op], d[i + 1]), 2
    if op in ALU:   return ALU[op], 1
    # 8x GLO, 9x GHI, Ax PLO, Bx PHI, Dx SEP, Ex SEX. Getting these ranges
    # off by one nibble decodes 0x90-0xBF as the wrong group entirely, which
    # read `PLO RB` at 1421 as `GHI RB` and made a table walker look like it
    # was reading a register it never touches. Cx is fully covered by LONGB
    # and SKIP above, so it needs no arm here.
    if op < 0x90:  return 'GLO  %s' % R(op & 0xf), 1
    if op < 0xa0:  return 'GHI  %s' % R(op & 0xf), 1
    if op < 0xb0:  return 'PLO  %s' % R(op & 0xf), 1
    if op < 0xc0:  return 'PHI  %s' % R(op & 0xf), 1
    if op < 0xe0:  return 'SEP  %s' % R(op & 0xf), 1
    if op < 0xf0:  return 'SEX  %s' % R(op & 0xf), 1
    return 'DB   %02X' % op, 1

# ----------------------------------------------------- inline arg signatures ---
def load_sigs(path='cdp1806/data/inline_args.txt'):
    """callee -> [kinds], and pinned @site -> [kinds]."""
    by_callee, by_site = {}, {}
    if not os.path.exists(path):
        return by_callee, by_site
    for line in io.open(path, encoding='utf-8'):
        line = line.split('#')[0].strip()
        if not line or line.startswith('program '):
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        addr, spec = parts
        kinds = [] if spec == 'none' else spec.split(',')
        if addr.startswith('@'):
            by_site[int(addr[1:], 16)] = kinds
        else:
            by_callee[int(addr, 16)] = kinds
    return by_callee, by_site

SIG_CALLEE, SIG_SITE = load_sigs()
WIDTH = {'b': 1, 'w': 2, 'p': 2}

def infer_sig(a, limit=12):
    """Work out a callee's inline-argument signature from its own prologue.

    The file above only lists callees whose signature Ghidra's analyzer cannot
    infer, so relying on it alone leaves most of them uncovered - 23 callees
    read inline arguments without appearing there, 6E6B at 84 call sites among
    them. Uncovered is not harmless: decoding an argument as code invents
    instructions that look real. The two bytes after SCAL 046E at 05EC decode
    as `LDN R4 / OUT 6`, a UART write that does not exist.

    So infer it the way the analyzer does. R3 holds the return address, which
    points at the arguments, and a callee consumes them three ways:

        RLXA Rn   2 bytes, but ONLY while X == 3 (it reads through R(X))
        LDA  R3   1 byte, regardless of X (it names R3 explicitly)
        INC  R3   1 byte, skipped rather than read - a disabled argument

    Walk until X moves off R3 or control leaves the straight line. Conditional
    reads cannot be modelled this way, which is exactly why 5E1B and the 038D
    sites are pinned by hand in the file; the file wins where both have an
    opinion.
    """
    kinds, x, i = [], None, a
    for _ in range(limit):
        if i + 3 >= len(d):
            break
        op = d[i]
        if op == 0xe3:                                  # SEX R3
            x = 3
        elif 0xe0 <= op <= 0xef:                        # SEX of anything else
            x = op & 0xf
        elif op == 0x68 and (d[i + 1] & 0xf0) == 0x60:  # RLXA Rn
            if x != 3:
                break
            kinds.append('p')
        elif op == 0x43:                                # LDA R3
            kinds.append('b')
        elif op == 0x13:                                # INC R3
            kinds.append('b')
        elif op in LONGB or op in SHORT or op == 0x00 or (
                op == 0x68 and (d[i + 1] & 0xf0) in (0x80, 0x90)):
            break                                       # branch, IDL, call, return
        _, n = decode(i)
        i += n
    return kinds

def sig_for(site, callee):
    """The file is an override; otherwise infer from the callee."""
    if site in SIG_SITE:
        return SIG_SITE[site]
    if callee in SIG_CALLEE:
        return SIG_CALLEE[callee]
    return infer_sig(callee)

def run(start, end):
    i = start
    while i < end:
        txt, n = decode(i)
        raw = d[i:i + n].hex(' ')
        note = ''
        # X == P inline form: SEX R4 immediately before, P is always R4 here.
        if n == 1 and d[i] in INLINEABLE and i > start and d[i - 1] == 0xe4:
            txt = '%-4s %02X' % (txt.split()[0], d[i + 1])
            n, raw = 2, d[i:i + 2].hex(' ')
            note = '   ; X==P inline form'
        print('%04X  %-11s  %-16s%s' % (i, raw, txt, note))
        i += n
        # Inline call arguments follow a SCAL and are DATA, not code.
        if txt.startswith('SCAL'):
            callee = int(txt[-4:], 16)
            kinds = sig_for(i - 4, callee)
            if kinds:
                off = i
                for k in kinds:
                    w = WIDTH[k]
                    val = d[off] if w == 1 else (d[off] << 8) | d[off + 1]
                    print('%04X  %-11s  %-16s   ; inline arg (%s)'
                          % (off, d[off:off + w].hex(' '),
                             ('#%02X' if w == 1 else '%04X') % val, k))
                    off += w
                i = off

# Spot decodes verified by hand against the CDP1802/1805 opcode map. The
# register-group bug above decoded a quarter of the opcode space one nibble off
# and was caught only because a listing read oddly; a wrong decode is otherwise
# silent and looks like a finding. Run `python3 -I tools/dis.py --selftest`.
SELFTEST = [
    (0x05aa, 'GHI  R2'), (0x061a, 'GHI  R5'), (0x0620, 'GLO  R5'),
    (0x1421, 'PLO  RB'), (0x7461, 'GLO  RF'), (0x0480, 'PLO  RE'),
    (0x40ae, 'GLO  R1'), (0x05d7, 'STPC'),    (0x05db, 'LDC'),
    (0x28d2, 'RLXA R4'), (0x0699, 'DSAV'),    (0x069b, 'DEC  R2'),
    (0x069c, 'RSXD R4'), (0x70b9, 'RLDI RE,8852'),
    (0x05e3, 'SCAL R3,1415'), (0x0657, 'SEX  R4'), (0x065a, 'XIE'),
    (0x40c7, 'LBZ  40F4'), (0x7087, 'LSZ'),   (0x7088, 'SMI  #88'.replace('88','01')),
    (0x05dd, 'SCM1'),    (0x0695, 'LDXA'),    (0x0698, 'RET'),
    (0x7063, 'RLXA R4'), (0x40a7, 'SCAL R3,4EFC'), (0x1423, 'DBNZ RD,142A'),
    (0x05ed, 'OUT  6'),  (0x706b, 'RSXD R5'), (0x70cc, 'SRET R3'),
    (0x048e, 'ADCI #00'), (0x1454, 'ADCI #00'), (0x06ee, 'SDBI #82'),
]

def selftest():
    bad = 0
    for a, want in SELFTEST:
        got = decode(a)[0]
        if got != want:
            print('FAIL %04X  got %-14s want %s' % (a, got, want))
            bad += 1
    print('%d/%d decodes correct' % (len(SELFTEST) - bad, len(SELFTEST)))
    return bad

if __name__ == '__main__':
    args = sys.argv[1:]
    if args[:1] == ['--selftest']:
        sys.exit(1 if selftest() else 0)
    if not args or len(args) % 2:
        sys.exit(__doc__.strip().splitlines()[-1])
    for a, b in zip(args[::2], args[1::2]):
        run(int(a, 16), int(b, 16))
        print()
