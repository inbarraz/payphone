#!/usr/bin/env python3
"""Dump the Hebrew and Latin strings out of a TAMAC-18 firmware image.

Hebrew in this ROM is not ISO-8859-8 or CP1255. The alphabet sits at
0xA0-0xBA, which is ISO-8859-8 minus 0x40 -- where the HD44780's character
generator keeps Hebrew. ASCII is stored forward and is NOT offset.

Byte order is not a single convention: a string is stored in whatever order
its consumer needs. Strings rendered straight to the LCD are in DISPLAY
order, reversed relative to logical order, because the renderer preserves
order. Strings copied through a reversing LDA/STXD loop are stored in
LOGICAL order -- 2AEB is one, and the same phrase sits at 6C18 in display
order for the direct path. So this script guesses per string, using the fact
that final-form letters can only end a word in logical order, and marks the
calls it cannot make. See phone/TAMAC18-firmware.md section 9.

Usage:
    python3 tools/dump_strings.py "ROM/TAMAC-18 V2.8 9513.bin"
    python3 tools/dump_strings.py rom.bin --descriptors
"""

import argparse
import re
import sys

HEB_LO, HEB_HI = 0xA0, 0xBA          # alef .. tav, ISO-8859-8 minus 0x40
HEB_OFFSET = 0x40
PUNCT = b" '.:,-/()*#+%?!=\"0123456789"


def decode(raw: bytes) -> str:
    """Map ROM bytes to Unicode, leaving ASCII alone."""
    out = []
    for c in raw:
        if HEB_LO <= c <= HEB_HI:
            out.append(bytes([c + HEB_OFFSET]).decode("iso8859-8"))
        elif 0x20 <= c < 0x7F:
            out.append(chr(c))
        else:
            out.append(".")
    return "".join(out)


FINAL_FORMS = {0xAA, 0xAD, 0xAF, 0xB3, 0xB5}     # final kaf mem nun pe tsadi


def is_hebrew(raw: bytes) -> bool:
    return any(HEB_LO <= c <= HEB_HI for c in raw)


def guess_order(raw: bytes) -> str:
    """'display', 'logical', or 'unknown'.

    A final-form letter can only END a word in logical order, so a run whose
    words start with one is stored reversed.
    """
    if not is_hebrew(raw):
        return "logical"                      # ASCII is stored forward
    words = [w for w in re.split(rb"[^\xa0-\xba]+", raw) if len(w) >= 2]
    at_end = sum(1 for w in words if w[-1] in FINAL_FORMS)
    at_start = sum(1 for w in words if w[0] in FINAL_FORMS)
    if at_start > at_end:
        return "display"
    if at_end > at_start:
        return "logical"
    return "unknown"


def logical(text: str, raw: bytes) -> str:
    """Return the string in reading order, reversing display-order runs.

    Ambiguous Hebrew is treated as display order, which is the overwhelming
    majority in this image. (The 23-of-24 figure quoted in the notes comes
    from a stricter one-off scan, not from this script's default charset.)

    Known limitation: a run with no Hebrew at all is reported as-is, so a
    reversed ASCII string such as "=LANIMRET" at 1AA9 prints backwards.
    Nothing in the bytes distinguishes it from forward ASCII.
    """
    if guess_order(raw) == "logical":
        return text
    # Reverse the line, then put Latin runs back the right way round: on a
    # mixed line the ROM holds each run in its own direction, so reversing
    # the whole string fixes the Hebrew and breaks the Latin.
    flipped = text[::-1]
    # Latin words AND numbers run left-to-right even inside RTL text, so the
    # line reversal has to be undone for them. Missing the digit case renders
    # TAMAC-18 as "18" reversed to "81", and version 4.30 as "03.4".
    # The optional leading mark matters: a colon that trailed "CREDIT:" in
    # the ROM is leading in the reversed line, and has to travel back with
    # the word or it lands in front of it.
    return re.sub(r"[:.]?[A-Za-z0-9]+(?:[.'&/:-][A-Za-z0-9]+)*",
                  lambda m: m.group()[::-1], flipped)


def find_strings(rom: bytes, minlen: int):
    charset = bytes(range(HEB_LO, HEB_HI + 1)) + PUNCT + bytes(
        range(0x41, 0x5B)) + bytes(range(0x61, 0x7B))
    pattern = re.compile(b"[" + re.escape(charset) + b"]{%d,}" % minlen)
    for m in pattern.finditer(rom):
        raw = m.group()
        # skip runs that are only spaces and digits
        if not any(HEB_LO <= c <= HEB_HI or 0x41 <= c <= 0x7A for c in raw):
            continue
        yield m.start(), raw


def read_descriptor(rom: bytes, addr: int):
    """Nine-byte display descriptor; see section 10b."""
    if addr + 9 > len(rom):
        return None
    d = rom[addr:addr + 9]
    return {
        "cursor": d[0],                                 # 1-based, DDRAM space
        "width": int.from_bytes(d[1:3], "big"),         # 0 = do not wrap
        "text": int.from_bytes(d[3:5], "big"),
        "command": d[5],                                # emitted after the text
        "dwell": d[6],                                  # reloads M(803A)
        "next": int.from_bytes(d[7:9], "big"),          # 0000 ends the chain
    }


def cursor_to_ddram(cursor: int) -> str:
    """The cursor byte is 1-based over DDRAM: 0x01-0x40 line 1, 0x41+ line 2."""
    ddram = (cursor - 1) & 0x7F
    line = 2 if ddram >= 0x40 else 1
    return f"line {line} col {ddram & 0x3F:2d} (cmd {0x80 | ddram:02X})"


def text_at(rom: bytes, addr: int, limit: int = 64) -> bytes:
    end = rom.find(b"\x00", addr, addr + limit)
    return rom[addr:end if end >= 0 else addr + limit]


def dump_chain(rom: bytes, addr: int, seen=None):
    """Follow a descriptor chain, guarding against loops."""
    seen = seen if seen is not None else set()
    while addr and addr not in seen and addr < len(rom):
        seen.add(addr)
        d = read_descriptor(rom, addr)
        if d is None:
            return
        raw = text_at(rom, d["text"]) if d["text"] < len(rom) else b""
        yield addr, d, raw
        addr = d["next"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="firmware image, 32 KB")
    ap.add_argument("--minlen", type=int, default=4,
                    help="shortest run to report (default 4)")
    ap.add_argument("--chain", type=lambda v: int(v, 16), metavar="ADDR",
                    help="walk the descriptor chain at this hex address")
    args = ap.parse_args()

    with open(args.image, "rb") as fh:
        rom = fh.read()

    if args.chain is not None:
        for addr, d, raw in dump_chain(rom, args.chain):
            text = decode(raw)
            print(f"{addr:04X}  {cursor_to_ddram(d['cursor'])}  "
                  f"width {d['width']:2d}  cmd {d['command']:02X}  "
                  f"dwell {d['dwell']:02X}  next {d['next']:04X}")
            print(f"        text {d['text']:04X}: {logical(text, raw)!r}")
        return 0

    count = 0
    for off, raw in find_strings(rom, args.minlen):
        text = decode(raw)
        order = guess_order(raw)
        kind = "HE" if is_hebrew(raw) else "  "
        flag = {"display": " ", "logical": "L", "unknown": "?"}[order]
        print(f"{off:04X} {kind}{flag} ({len(raw):2d})  {logical(text, raw)}")
        count += 1
    print(f"\n{count} strings", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
