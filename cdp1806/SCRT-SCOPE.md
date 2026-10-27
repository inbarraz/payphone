# Scope: an analyzer for SCRT calls (`SEP R4` + inline address)

Status: proposal, nothing implemented.
Written: 2026-10-27, against `Card Reader/ROM Image/Card Reader BSK-31 202 .BIN` (BSK31 card reader).

## The problem

The card reader firmware is plain CDP1802 code. The 1802 has no `SCAL`/`SRET`, so calls use the
RCA **Standard Call and Return Technique**: a one-byte `SEP R4` followed by a **two-byte inline
call address**.

```
011b  D4            SEP R4          ; call
011c  0F 7E         <- the target, sitting in the caller
011e  ...                           ; execution resumes here
```

Ghidra gets two things wrong about this:

1. The SLEIGH definition compiles `SEP` to `goto [reg16]`, a computed jump with no resolvable
   target. So no call is recorded, no call graph is built, and nothing links a call site to the
   subroutine it calls.
2. The two address bytes are disassembled as instructions, which puts the listing out of phase —
   the same failure the `SCAL` analyzer on `main` was written to fix, except there are **538** of
   them here rather than 50.

Returns are a one-byte `SEP R5` with no inline data, but Ghidra treats them as computed jumps
too, so function bodies never close.

## What the ROM actually contains

Measured on the image, counting only bytes that are real opcodes:

| Fact | Value |
|---|---|
| `SEP R4` call sites | 538 |
| Distinct call targets | 67 |
| `SEP R5` return sites | 63 |
| `SEP R4` sites whose inline address is in range | 538 of 538 |
| Bytes after `SEP R5` | ordinary code; no inline data |

A naive byte scan reports three extra `D4`s at `05BD`, `07CE` and `22DA`. All three are operand
bytes of a preceding branch (`CB 05 D4`, `C2 22 D4`) rather than opcodes. **The analyzer must
therefore work from the instruction listing, never from a byte scan** — which is also how the
existing `SCAL` analyzer works.

### The SCRT routines in this image

```
R4 = 12EE   SCRT_CALL
R5 = 07F1   SCRT_RETURN
```

Both are loaded by `LDI/PLO` + `LDI/PHI` pairs at `00AF`/`00B5`, and again at `0265`/`026B`.

```
12ee  SCRT_CALL     PHI RE          ; save D
12ef                SEX R6          ; R6 is the stack
12f0                GHI R3 / STXD   ; push the caller's link
12f2                GLO R3 / STXD
12f4                R3 = R0         ; R0 points at the inline address
12f8                LDA R3 / PHI R0 ; load the target, stepping R3 past it
12fa                LDA R3 / PLO R0 ;   so R3 becomes the return link
12fc                GHI RE          ; restore D
12fd                LBR 12ED        ; -> SEP R0, enter the subroutine
```

Note `12ED` (the `SEP R0` dispatch) sits one byte **below** the entry point, reached only by that
`LBR`. Ghidra invents a `FUN_12ed` from the branch target; the real entry, and the value in R4,
is `12EE`.

Register roles: **R0** = PC, **R3** = return link, **R6** = stack, **R4**/**R5** = call/return
vectors, **RE** = saved D.

## Goal

After the analyzer runs:

- every `SEP R4` is a **call** to the address inlined after it, with a real reference, so the call
  graph and "called by" work;
- execution resumes at `site + 3`, and the two address bytes are typed data, not code;
- every `SEP R5` terminates flow, so function bodies close;
- a function exists at each of the 67 targets.

## Design

### 1. Ask, do not guess

The analyzer is driven by options rather than by recognising the SCRT routine:

| Option | Default | Meaning |
|---|---|---|
| **Call register** | `R4` | Which `SEP Rn` is a call. Blank disables the analyzer. |
| **Inline bytes after SEP** | `2` | How many bytes follow the `SEP` and belong to it. |
| **Return register** | `R5` | Which `SEP Rn` is a return. Blank to skip return markup. |

Two bytes is the default because that is the callee address in the standard technique. The count
is separate from the address so the same mechanism covers a vector whose calls carry extra inline
arguments, and a vector that takes none at all.

Interpretation of the inline bytes:

- `0` — nothing follows. The `SEP` is a plain register jump; only the flow override applies.
- `2` — the two bytes are the callee address: typed as a pointer, and the source of the call
  reference.
- `>2` — the first two are the callee address; the remainder are the callee's inline arguments,
  typed as bytes.

Register assignments differ between SCRT implementations — this image uses R0/R3/R6 where the RCA
manual's example uses R3/R6/R2 — so asking is both simpler and more portable than inferring. It
also means a second vector is handled by running the analyzer again with different options,
rather than needing the design to anticipate it.

One set of options applies per run, by decision: the analyzer handles a single register and byte
count at a time, and a program with more than one vector is marked up by running it once per
vector. There is no list syntax and no attempt to combine sets.

To make the options easy to fill in, the analyzer logs the register-pair loads it can see
(`LDI lo / PLO Rn / LDI hi / PHI Rn`) together with the address each one produces. In this image
that reports `R4 = 12EE` and `R5 = 07F1` from the loads at `00AF`/`00B5`. It is a hint in the log,
not a decision the analyzer acts on.

### 2. Mark each call site

For each `SEP <call-reg>` instruction, with `N` the configured inline byte count:

- `setFlowOverride(FlowOverride.CALL)` — our `SEP` is `BRANCHIND`, which `FlowOverride.CALL` maps
  to `CALLIND`, making it a call rather than a jump;
- when `N >= 2`, add a `RefType.UNCONDITIONAL_CALL` reference to the address in the first two
  bytes and make it primary, which is what supplies the target that `CALLIND` lacks;
- `setFallThrough(site + 1 + N)`;
- lay the first two bytes down as a 2-byte pointer, so the target also picks up a data xref, and
  any remaining bytes as data;
- end-of-line comment recording the resolved target and the argument bytes.

### 3. Mark each return site

`setFlowOverride(FlowOverride.RETURN)` on `SEP <return-reg>`, so flow terminates and Ghidra can
close function bodies. *(To verify: that `FlowOverride.RETURN` maps `BRANCHIND -> RETURN` in
12.1.3 as the enum documentation implies.)*

### 4. Create functions

After markup, create a function at each distinct call target.

### 5. Iterate

A call site can only be marked once it has been disassembled, and disassembly past it only becomes
correct once it is marked. The existing analyzer already handles this by rescanning the whole
program on each pass and scheduling newly-exposed addresses for disassembly; the same approach
applies, seeded from the reset vector.

## Where the code should live

The existing `InlineArgsAnalyzer` already has machinery worth reusing: the override file with
program-name gating, the markup reconciliation that rewrites and removes rather than only adding,
ownership tracking via a comment marker, and the reporting.

Recommendation: a **sibling analyzer**, `ScrtCallAnalyzer`, with the override-file handling and the
markup reconciliation extracted into a shared helper. Not a second mode inside the existing one —
the trigger, the flow semantics and the per-site markup all differ, and merging them would make
both harder to follow.

Both analyzers can be enabled at once. They cannot collide: this ROM has no `SCAL`, and the
payphone ROM's `SEP` usage is not SCRT.

## Open questions

1. **Do any SCRT subroutines take further inline arguments after the call address?** This is the
   exact problem the existing analyzer solves for `SCAL`, and the mechanism transfers — the callee
   would read them through the link register R3 and `SRET`-equivalent past them. It cannot be
   answered until the listing is coherent. If the answer is yes, the detector generalises rather
   than being rewritten.
2. **`SEP RB` (29 sites) and `SEP RD` (26 sites).** Too frequent to be incidental. Possibly a
   second call vector, a jump table, or a coroutine switch. These no longer need to be settled
   before the design is: whatever they turn out to be, they are handled by running the analyzer
   again with the register and byte count set accordingly. Identifying them is still worth doing,
   to know what to set.
3. `SEP R1` (11), `SEP R9` (10), `SEP RC` (9) — likely register-based jumps, which is the
   zero-inline-bytes case.
4. Whether the 1806 module is the right home for a 1802-only analyzer at all, or whether the
   language definition should gain a `cdp1802` variant. The instruction sets are a strict subset,
   so the module works as-is, but the `ldefs` description currently claims 1804/1805/1806.

## Validation

Fixtures to assert, all measured from the image:

- with the defaults (call `R4`, 2 inline bytes, return `R5`) the image is marked up correctly;
- the register-pair hint reports `R4 = 12EE` and `R5 = 07F1` from the loads at `00AF`/`00B5`;
- the call site at `011B` resolves to `0F7E` and resumes at `011E`;
- setting the inline byte count to 4 moves that resume address to `0120`, confirming the count is
  honoured rather than hardcoded;
- 538 call sites marked, 67 functions created, 63 return sites overridden;
- `05BD`, `07CE` and `22DA` are **not** treated as call sites;
- a second pass changes nothing.

## Out of scope

- Showing call arguments in the decompiler.
- Fixing the `SEP`/`P`-tracking weakness in the SLEIGH definition itself (gaps G2 and G4 of
  `REVIEW.md`). A flow override is a listing-level workaround; a context-tracked `P` register
  would be the real fix and is a much larger change.
- The `X == P` inline-operand idiom (`OUT`/`INP`/`RET`/`DIS`), which this ROM also uses — see the
  reset sequence at `0000` and `000B`. That is gap G1 and a separate piece of work.
