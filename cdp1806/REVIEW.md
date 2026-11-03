# CDP1806 Ghidra module — review

Review date: 2026-10-26
Reviewed files: `cdp1806.slaspec` (892 lines), `cdp1806.ldefs`, `cdp1806.pspec`, `cdp1806.cspec`
Reference: *CDP1805AC, CDP1806AC* datasheet, Table 1 (Instruction Summary) and Notes 10–19.
Line numbers refer to `cdp1806.slaspec` as of commit `c8a5479`.

## Status, 2026-11-03

Fourteen of the sixteen mistakes are **fixed**: M1–M8 and M11–M16. The slaspec
compiles clean against the Ghidra 12.2 SLEIGH compiler (19 NOP constructors,
up from 17 because M11 emptied `STPC` and `ETQ`).

**M9 is only half applied.** `RET` and `DIS` now assign
`P = byte[0,4]` (lines 477 and 494), but `P` is an ordinary data register in
this spec, not SLEIGH's program counter, so that assignment does not move
disassembly. `SEP` — the instruction whose whole job is to set `P` — is still
`# TODO: Set P` with a bare `goto [reg16]`. Finishing M9 needs the same context
register for `P` that gap **G2** calls for, so M9 and M10 stand or fall
together.

**M10 is deliberately not applied.** Adding a `return` to `RET` (`0x70`) is
correct in the abstract, but `RET` loads `(X,P)` from its operand, and this
firmware uses it as an idiom to set `X` while leaving `P` unchanged — `RET
0x24` at `2AD1`, `75B7` and `6110` all continue inline. Terminating flow
there would stop the following code disassembling. The fix needs a context
register for `P` first; see gap **G2**. The gaps G1–G10 are untouched.

## How this was verified

**This section describes the module as it was reviewed, before the fixes.** The
status block above supersedes it on the compiler version and the NOP count; the
symptoms at the foot belong to gap **G1**, which is untouched, so they are still
what a stock disassembly shows.

- The slaspec compiles cleanly with the Ghidra 12.1.3 SLEIGH compiler (only the usual
  "17 NOP constructors" warning).
- The module was installed and used to import and disassemble
  `ROM/TAMAC-18 V2.8 9513.bin` from the reset vector.
- Reset path traced by hand and compared against the module's output. At reset
  `P=0, X=0, R0=0`. `0x0000: 71` is DIS, which reads its `(X,P)` byte from `M(R(X))` —
  and because `X==P` that is the inline `0x00` at `0x0001` — leaving `X=0, P=0`,
  `R0=0x0002`, then `C0 6D D5` = LBR `0x6DD5`.
- Cross-checked read-only against the live Ghidra database of the ROM.

Observed symptoms in the current module: `0x0001` disassembles as a stray `IDL`, and
auto-analysis dies at `0x6DD8` on a bogus `LBR 0xC4C4` (an address outside the 32 KB image).

---

## Mistakes

Ordered by impact on decompiled output.

### M1. DF polarity inverted on every subtract (8 instructions)

Datasheet Note 19: **"DF = 1 denotes no borrow."** The module computes the opposite.

- `subflags` (L96–98) is `DF = (op1 < op2)`; should be `op1 >= op2`.
  Used by SDB `75`, SMB `77`, SDBI `7D`, SMBI `7F`.
- SD `F5` (L780–790), SM `F7` (L799–809), SDI `FD` (L870–876), SMI `FF` (L885–891)
  inline the same inverted test. SD sets `DF=1` iff `D >= M(R(X))`; correct is
  `M(R(X)) >= D`.

Already propagating into the analysis database: in `isInRange` (0x558D) the comments read
`LSNF … ; jmp if M(RX) >= D` and `LBDF … ; jmp if borrow`. Both are the reverse of the
hardware (`LSNF` skips on DF=0 = borrow = `M(RX) < D`; `LBDF` branches on DF=1 = *no*
borrow) — they are correct readings of what the module currently emits.

### M2. Borrow-subtract arithmetic is wrong

`x - y - (NOT DF)` means `x - y - 1 + DF`.

- SDB (L544–547) and SMB (L565–567) compute `x - y - DF` — both the sign of DF and the
  `-1` are wrong.
- SMBI (L621–623) has the same error.
- SDBI (L605–609) computes `calc = imm8 + DF` and then never uses it, emitting plain
  `D = imm8 - D` with the borrow silently dropped.

### M3. `IRX` (0x60) increments the wrong thing

L224 is `X = X + 1`. The instruction is `R(X) + 1 → R(X)` — it increments the register X
points at, not the X selector. The existing comment at `0x38A5` (`IRX ; RD++`) is right.
Effect: `Compare_Words` decompiles to `cVar1 = pcStack_2[1] - pcStack_2[1]`, a comparison
that is trivially zero, because the pointer advance was lost.

### M4. `BM`/`BNF`/`BL` (0x3B) tests the wrong register

L196–198 uses `if (D == 0)`; should be `DF == 0`. The datasheet's *operation* column does
read "IF D = 0", but that is a typo in the table — the instruction-name column on the same
rows reads "SHORT BRANCH IF DF = 0", and `0x32 BZ` already covers `D == 0`, so `0x3B`
would otherwise be a duplicate.

### M5. `LSNZ` (0xC6) typo

L679 is `if (D != 1)`; should be `D != 0`.

### M6. Duplicate constructor name — 0x6805 mislabeled

L248 and L250 both define `:SCM2`. Per Table 1, `6803` = SCM2 and `6805` = **SCM1**.
`6805` currently disassembles as SCM2.

### M7. `ADC`/`ADCI` carry is not a real 3-input carry

L533 and L599 use `carry(D,val) | DF`. With `D=0, val=0, DF=1` this reports a carry where
none occurred. Needs a widened temp:

```
local t:2 = zext(D) + zext(val) + zext(DF);
DF = t[8,1];
D  = t:1;
```

### M8. `SRET` writes into the instruction stream

`CalcAddr16` (L119) is `export *:2 loc` with `loc = inst_next` — a *ram* location. So
`CalcAddr16 = reg16;` at L350 emits a 2-byte STORE to memory at `inst_next`. It should be
a plain `local`.

### M9. `P` is never written

`SEP` (L729–731) only does `goto [reg16]`; the `P = byte[0,4]` lines in RET (L485) and DIS
(L502) are commented out. `P` is *read* in MARK (L582, L587), so it is permanently stale.
`N` is declared (L20) and never used at all.

### M10. `RET` (0x70) does not terminate flow

L475–488 has no `return`, so Ghidra falls straight through it. Noted in-file as
`# TODO: Include the return operation`.

### M11. Two timer instructions have invented semantics

- `STPC` (L235) does `CNTR = 0`; the datasheet says it stops the clock and zeroes the
  ÷32 prescaler, leaving CNTR alone.
- `ETQ` (L258) does `Q = Q ^ 1`; it should *enable* toggle-on-counter mode, not toggle Q
  immediately.

### M12. `INP 1`–`INP 7` write a literal zero

L416–471 set `D = 0` and `M(R(X)) = 0`. That is worse than leaving the value unknown — the
decompiler constant-folds every port read to 0 and deletes the dependent code. Also seven
near-identical copies of the same block.

### M13. `OUT 1`–`OUT 7` never read memory

L227–232 only bump `R(X)`; `M(R(X)) → BUS` is dropped, so every output's data flow
vanishes. The `busOutput`/`busInput` pcodeops (L69–70) are declared and never called.

### M14. Short-branch page arithmetic is off by one byte

`AbsAddr8` (L113) uses `inst_next & 0xff00`. The hardware loads the operand into `R(P).0`
while `R(P)` points *at the operand*, so the page is `(inst_next - 1) & 0xff00`. These
differ exactly when a short branch's operand byte is the last byte of a page — the classic
1802 page-boundary trap. Same issue for BCI/BXI, where the operand is at `inst_next - 1`
of a 3-byte instruction.

### M15. The cspec describes a stack that does not exist

`growth="positive"`, but SCAL, RSXD, STXD and MARK all decrement. `R3` is named the stack
pointer, but the stack is `R(X)` — and MARK hardcodes `R2`. The `__mem_r3` prototype passes
the stack pointer as a parameter. This is why `Compare_Words` decompiles with
`BADSPACEBASE`, `auStack_4 [9996]`, and a stray `_Add_Words = auStack_4`.

### M16. Comment and label errors

Harmless to execution, misleading when reading the file: `GHI` commented "Get low" (L631),
`PHI` "Put low" (L642), `BZ` "Short Branch if Q=1" (L151), plus "Psuedo" (L66) and
"directon" (L46).

---

## Gaps

### G1. The `X == P` inline-operand idiom — **now switchable by hand**

When `X == P`, `R(X)` *is* the program counter, so an instruction that
**increments `R(X)`** consumes an inline byte and the PC skips over it.

**`INP` is not one of them.** The 1802 is asymmetric here: `OUT` (61-67) is
`M(R(X)) → BUS; R(X)+1 → R(X)`, but `INP` (69-6F) is `BUS → M(R(X)); BUS → D`
with **no increment**. So `INP` with `X == P` writes the bus value at the PC — a
no-op in ROM — and stays one byte. An earlier version of this gap listed `INP`
alongside the others; it does not belong. The instructions that do increment
`R(X)`, and so have an inline form, are `OUT`, `RET`, `DIS`, `LDXA` (72) and
`IRX` (60).

Verified live:

- `DIS` at `0x0000` takes the inline `0x00` at `0x0001`.
- The init block at `0x6DD5` is `SEX 0 / REQ / OUT 5 +C0 / NOP NOP / OUT 2 +00 /
  OUT 5 +84 / …`.

Today those operand bytes are disassembled as instructions: `0x0001` shows as `IDL`, and
`0x6DD8` as `LBR 0xC4C4`, which is what kills auto-analysis right at the entry point.
**Highest-value gap to close.**

### G2. No context register for `P` (or `X`) — **partly closed**

A context register now exists, `contextreg` at offset `0x80`, carrying a one-bit
field **`XP`**:

```
XP = 0   the normal form: the operand byte comes from M(R(X))
XP = 1   the inline form:  the operand byte follows the opcode
```

`OUT`, `RET` and `DIS` each have two constructors keyed on it, so the
inline-operand forms disassemble with the right length. The field is `noflow`,
so it applies to the one instruction rather than propagating down the
fall-through, which suits an idiom used at isolated sites.

**Using it on an address:**

1. clear the bytes there (`C`), so the wrong-length instruction goes away
2. right-click → **Set Register Values…**, set `XP = 1` over just that address
3. disassemble (`D`)

Same mechanism ARM uses for `TMode` and MIPS for its 16-bit mode.

**What is still missing** is the automatic part: nothing *infers* `XP`. `SEP`,
`SEX` and `DIS` would have to `globalset` it onto the following addresses for
auto-analysis to get it right unaided, and `SEP` also still has `# TODO: Set P`
(M9). So the manual switch unblocks the known sites — `0000`, the `6DD5` reset
block, `51A8`, `51B1` — without yet fixing the general case.

`LDXA` and `IRX` also increment `R(X)` and so have inline forms; neither has a
site in this ROM that needs it, so neither was given a second constructor. Add
one the same way if a site turns up.

### G3. Nine 1806 BCD instructions are empty stubs

They disassemble but model nothing: DADD `68F4`, DADI `68FC`, DADC `6874`, DACI `687C`,
DSM `68F7`, DSMI `68FF`, DSMB `6877`, DSBI `687F`, DSAV `6876`.

### G4. The counter/timer is entirely unmodeled

LDC `6806`, STM `6807`, SCM1 `6805`, SCM2 `6803`, SPM1 `6804`, SPM2 `6802` are all empty.
`CH` and `CIL` are declared and never touched; `CI`/`XI` are only ever *cleared* (by
BCI/BXI) and never set.

### G5. SCAL inline-parameter calls cannot be expressed

At `0x70E0`, `SCAL R3,0x6E6B` is followed by inline bytes `64 51` that the callee reads via
`R(N)`. The module has no fall-through override, so these need manual marking every time.

### G6. The pspec is nearly empty

No `default_symbols` for the reset vector, no `default_memory_blocks` (ROM `0x0000–0x7FFF`,
RAM from `0x8000`), and no volatile ranges for the memory-mapped I/O — all currently set up
by hand on every import.

### G7. `T` side effects missing

Datasheet Note 10: T is destroyed by RLDI, RLXA, RSXD, RNX, SCAL, SRET and DSAV. The module
only touches T in SAV and MARK.

### G8. No interrupt or DMA model

No entry vector, and nothing ever raises `CI`/`XI`, so interrupt handlers are unreachable
from auto-analysis.

### G9. Dead declarations

Tokens `sign8`, `simm8`, `sign16`, `simm16` are defined and never used; so are registers
`N` and `CIL`. The commented-out half-register block (L12–17) and the commented-out
`LDI`/`ORI`/`ANI`/`XRI` variants (L813–858) are leftover scaffolding.

### G10. `IDL` (0x00) is an empty constructor

No halt or wait-for-interrupt semantics, so it reads as a plain NOP.

### G11. The ldefs is minimal

No `manualindexfile`, no `external_name` mappings, one variant only. The description claims
CDP1804 coverage, but the 1804 lacks parts of this instruction set.

### G12. No build or test story

The `.sla` is not in the repo and there is no install script, so the module stops existing
on each Ghidra upgrade (each version gets its own
`~/Library/ghidra/ghidra_<ver>_PUBLIC/Extensions` directory). There is also no regression
corpus — no known-good byte→mnemonic fixtures to catch issues like the `SCM2` duplicate
(M6) or the `LSNZ` typo (M5).

---

## Suggested order of work

1. **G1 + G2** — inline-operand idiom and a `P`/`X` context register. Unblocks
   auto-analysis at the entry point; everything else is easier once flow is correct.
2. **M1 + M2** — subtract DF polarity and borrow arithmetic. Already corrupting
   annotations in the database; existing comments on DF-conditional branches will need
   re-checking once fixed.
3. **M3, M4, M5, M6, M7, M8** — small, self-contained correctness fixes.
4. **M12 + M13** — model I/O through the existing `busInput`/`busOutput` pcodeops.
5. **M15 + G6** — cspec and pspec, to clean up decompiler output.
6. **G12** — install script and a fixture-based regression test, so the above stays fixed.
