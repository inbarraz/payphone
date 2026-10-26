# CDP1806 Ghidra module

A SLEIGH processor module for the RCA CDP1804/1805/1806, plus an analyzer for the
inline-argument calling convention this firmware uses.

## Inline call arguments

Some subroutines take their arguments from the *caller*, stored immediately after the
four-byte `SCAL` instruction rather than in registers or on the stack:

```
4bf6  SCAL R3,0x6e6b     ; call
4bfa  66 a8              ; <- the argument, sitting in the caller
4bfc  SEX 0x2            ; execution resumes here
```

`SCAL` leaves R(N) pointing at those bytes, the callee consumes them, and `SRET R3` returns
to wherever R3 ends up — so the call effectively skips over its own arguments. Ghidra has no
notion of this: it disassembles the argument bytes as instructions, which derails the
listing and usually kills auto-analysis a few instructions later.

The **CDP1806 inline call arguments** analyzer fixes this. For each `SCAL` whose callee takes
inline arguments it:

- overrides the instruction's fall-through so the argument bytes stop being treated as code,
- lays the arguments down as typed data (byte or 16-bit word),
- creates a reference from a 16-bit argument to the address it holds, so the pointed-at data
  picks up an xref,
- and adds an end-of-line comment showing the parsed values.

### Where the signatures come from

The analyzer reads each signature out of the callee itself. On entry R3 points at the
argument bytes, and `SRET R3` resumes at whatever R3 points at by then, so the net advance of
R3 across the subroutine *is* the argument count. The instruction that did the consuming
gives the width — `LDA R3` or `INC R3` for a byte, `RLXA Rn` while X == 3 for a 16-bit word.

The walk follows branches but never descends into a call, re-walks a block when X differs
(`SEX` inside a loop is common), and steps over nested inline-argument calls once their own
signatures are known — which is why resolution is iterative, innermost callees first.

It reports a reason and declines to guess when it cannot stay certain: a loop that moves R3,
return paths that disagree, R3 reloaded outright, `SEP`, an `R(X)` instruction while X is
unknown, or code that is not fully disassembled yet.

### Overrides

Anything the walk cannot work out — or that you simply know better — goes in
`data/inline_args.txt`:

```
1abe  p          # one 16-bit pointer
6fa5  b          # one byte
2a78  none       # takes no inline arguments
```

An address (hex, `0x` optional) and a comma-separated argspec: `b` for a byte, `w` for a
16-bit word, `p` for a word always treated as a pointer, or `none`. Entries there beat
auto-detection. The analyzer's **Override file** option names a second file that beats both,
for per-program overrides you would rather not commit.

## Building and installing

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra
cd cdp1806
gradle
```

That writes `dist/ghidra_<version>_<date>_cdp1806.zip`. Install it with
*File > Install Extensions* in Ghidra, or unzip it straight into the extensions directory —
on macOS that is `~/Library/ghidra/ghidra_<version>_PUBLIC/Extensions`.

Each Ghidra release keeps its own extensions directory, so the module needs reinstalling
after a Ghidra upgrade. A missing or stale `cdp1806.sla` is rebuilt from the `.slaspec`
automatically on first use.

## Known issues

`REVIEW.md` on the `task/improve-with-claude` branch lists the outstanding correctness
problems in the SLEIGH definition itself. The inline-argument work here is item G5 of that
review; the others still stand.
