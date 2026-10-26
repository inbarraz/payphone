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
signatures are known — which is why resolution is iterative, innermost callees first. Since
`SCAL` and `SRET` do not save or restore X, stepping over a nested call also adopts whatever
X that callee was found to leave behind.

`SEP R3` sets `P = 3`, which is the same return `SRET` performs, so it counts as a return
path. `SEP Rn` is a jump; the walk follows it only when an immediately preceding
`RLDI Rn,addr` says where to (the reboot idiom, `RLDI R0,0x0000` then `SEP R0`), and
otherwise declines rather than assume the destination consumes nothing further.

Where X cannot be determined — after `RET`, `DIS` or `MARK`, which reload it from memory —
the subroutine is walked twice, once assuming X is 3 and once assuming it is not, and the
answer is only accepted if both agree. So an unknown X costs an answer only when it actually
changes one.

A wrong answer is far worse than no answer, because the markup rewrites the listing. The walk
reports a reason and declines whenever it cannot stay certain: a loop that moves R3, return
paths that disagree, R3 reloaded or overwritten, an unfollowable `SEP`, a nested call through
a register other than R3, or code that is not fully disassembled yet. Any instruction it does
not model explicitly is still checked against what SLEIGH says it writes, so an unfamiliar
opcode that touches R3 stops the walk rather than being assumed harmless.

Only `SCAL R3` is handled. `SCAL R4` points R4 at the arguments instead, so a signature
derived from R3 movement would not describe it; those sites are skipped and logged.

### Overrides

Anything the walk cannot work out — or that you simply know better — goes in
`data/inline_args.txt`:

```
1abe  p          # one 16-bit pointer
6fa5  b          # one byte
2a78  none       # takes no inline arguments
```

An address (hex, `0x` optional) and a comma-separated argspec: `b` for a byte, `w` for a
16-bit word, `p` for a word treated as a pointer, or `none`. Entries there beat
auto-detection. The analyzer's **Override file** option names a second file that beats both,
for per-program overrides you would rather not commit.

`w` and `p` differ only in when they earn a reference: a plain word gets one when its target
is in initialized memory, while a pointer gets one for any mapped address, including
uninitialized RAM.

Addresses only mean anything for the firmware they were read from, so image-specific entries
are gated on the program name:

```
program TAMAC-18
1abe  p
```

Everything after that line applies only when the program's name contains that text. `program
*` opens it up again. Without this, an entry would be applied to any CDP1806 image that
happened to have a call at the same address.

### Variadic callees

Some subroutines read a different number of inline bytes depending on how they were called,
so no single callee signature fits. `038d` is one: with `D != 0` on entry it takes two bytes,
with `D == 0` it takes a byte and a pointer. Auto-detection reports "return paths disagree"
and declines, which is the right answer.

Prefix an address with `@` to pin a signature to one *call site* instead of to a callee:

```
@0211  b,p        # 020e sets D = 0, so the three-byte form
@0880  b,b        # 087d sets D = 1, so the two-byte form
```

A call-site entry wins over everything else, including the callee's own signature.

## Re-running

The analyzer reconciles rather than only adds. On each run it compares the markup at a call
site against what the current signature calls for, and rewrites it when they differ — so
changing `w` to `b,b`, shortening a signature, or turning pointer references on or off takes
effect on the next run, and a signature changed to `none` has its markup removed. Only markup
this analyzer owns is touched; ownership is recorded by the `inline args:` comment it writes,
so hand-made annotations are left alone.

A call site whose signature has merely become *unknown* keeps its existing markup. A callee
that is not disassembled yet is not evidence that earlier markup was wrong.

## Output

Results go to the Ghidra log (**Help > Show Log**), not to the analysis MessageLog, because
anything written there makes Ghidra raise a "warnings/errors issued during analysis" dialog
even for good news. Each marked call site is logged, as is every call target that could not
be determined along with the reason — which is what tells you where an override is needed
and why. The MessageLog is reserved for genuine problems: an unreadable override file, a
malformed line, or markup that failed to apply.

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
