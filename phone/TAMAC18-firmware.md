# TAMAC-18 Payphone Firmware — Reverse Engineering Notes

Working notes on the TAMAC-18 Israeli payphone ROM. Companion to
[`../card-reader/BSK31-firmware.md`](../card-reader/BSK31-firmware.md), which
covers the Landis & Gyr BSK31-202 card reader this phone drives. Between them
the reader link protocol is now documented from both ends.

Everything here was derived from the ROM image and the Ghidra database; see
§12 for what is confirmed versus inferred.

Started: 2026-10-30.

---

## 1. Identification

| | |
|---|---|
| Model | **TAMAC-18 V2.8** — banner string `TAMAC18` at `0x7BDF` |
| CPU | **CDP1806ACE** |
| Ghidra language | `cdp1806:BE:16:default` |
| ROM | 32 KiB, based at `0x0000` |

### Images in this project

| File | MD5 | Populated to |
|---|---|---|
| `TAMAC-18 V2.8 9513.bin` ≡ `Binary versions/PH00.bin` | `17c5d297…` | `0x7F21` |
| `Binary versions/PH06.bin` ≡ `B01.bin` ≡ `DLC.bin` | `bb5e8284…` | `0x7F25` |
| `Binary versions/B02.bin` | `5ed46341…` | `0x7F25` |

The labelled original and `PH00.bin` are byte-identical. Work below is against
that image.

## 2. Memory map

| Range | Contents |
|---|---|
| `0x0000`–`0x7FFF` | ROM (`code` segment) |
| `0x8000`–`0x9FFF` | RAM (`ram` segment) |
| `0xE000`–`0xE007` | **LCD** |
| `0xF000` | **write-only control register**, shadowed at `0x8E10` — not declared as a segment (§10a) |

RAM extends to `0x9FFF`, further than the reader's, and part of it holds
**code copied from ROM and executed in place** — see §10.

## 3. THE CRITICAL CONVENTION: `P = R4`

The 1802/1806 has no dedicated program counter; `P` selects which of the 16
registers acts as one. This firmware runs with **`P = R4`**.

```
0000  DIS (71 00)        reset: X=0, P=0
0002  LBR 6DD5           into init, still running on R0
...
6E03  RLDI R4,6E08       load R4 with the address of the NEXT instruction
6E07  SEP R4             make P select R4 - execution continues at 6E08
6E0C  RLDI R1,28D8       set the interrupt vector
```

Because R4 is loaded with the address that immediately follows the `SEP`, the
switch is seamless and nothing appears to jump. **This one instruction governs
how the whole listing must be read.**

Consequences:

- **Any instruction that writes R4 is a jump.** `RLXA R4` is the firmware's
  indirect-branch idiom.
- Ghidra **does not model `RLXA` into the PC register as a branch**, so the
  decompiler silently drops those jumps. This is a real gap in the SLEIGH
  definition and belongs in `cdp1806/REVIEW.md`.
- `SCAL Rn` / `SRET Rn` still behave normally: `Rn` is the link register and
  the PC they load or restore is R4.
- R4 must never be treated as scratch.

Known `RLXA R4` sites:

| Address | Role |
|---|---|
| `333D` | message dispatcher — the table jump |
| `1B2C` | inside `PerformComm?` |
| `28D2` | interrupt epilogue — **the one exception**, see §5 |

## 4. Calling convention

`SCAL R3, <addr>` to call, `SRET R3` to return. R3 is the link register.

**Callees may consume further inline bytes from the caller's instruction
stream, immediately after the 4-byte `SCAL`.** This is the convention the
`cdp1806` Ghidra extension in this repo was built to handle.

Signatures established so far (`W` = word, `B` = byte):

| Addr | Name | Signature |
|---|---|---|
| `0100` | `setDF_to_EF3_inverted` | `NONE` |
| `290A` | `memset` | `W,B,W` |
| `2919` | `hexpack` | — |
| `3658` | — | `B` |
| `365C` | `send_reader_command` | `B` |
| `36B0` | — | `W` → returns a byte in D |
| `36C2` | — | `NONE` |
| `3886` | `popcnt` | `NONE` |
| `5000` | — | `W` |
| `5032` | — | `B` |
| `5E1B` | — | `B,B,B` |
| `6E6B` | `LoadStringForDisplay` | `W` |
| `6FA5` | `setWaitFor812d_Zero` | `B` |
| `746D` | `EraseBlock` | `W,W` |

**Pitfall:** a naive scan for `OUT n` / `INP n` opcodes produces mostly false
hits, because inline argument bytes decode as plausible I/O instructions. Any
I/O inventory must honour callee signatures first. (`0x64`–`0x67` are common
inline bytes and decode as `OUT 4`–`OUT 7`.)

## 5. Interrupt system

Vector: **`R1 = 0x28D8`**, set at `6E0C` during init and re-armed at `5071`
and `0CD8`.

On an 1802 interrupt the CPU forces `X=2`, `P=1` and disables interrupts — so
on entry the program counter is R1, not R4.

### Prologue — `0x28D8`

```
28D8  DSAV              save T, D and DF
28DA  DEC R2
28DB  RSXD R4..RE       push R4 through RE via X
28F1  RLDI R4,28F6      \ switch the PC back to R4
28F5  SEP R4            /  continuing at 28F6
28F6  LBR 5071          into the card reader link ISR body
```

The `RLDI R4` / `SEP R4` pair is the same trick cold start uses at `6E03`.

### Epilogue — `0x28B7`

```
28B7  SEX R2 / INC R2
28B9  RLXA RE..R5       pop the registers
28CD  RLDI R1,28D2      point the vector at the exit stub
28D1  SEP R1            switch to P=1, continue at 28D2
28D2  RLXA R4           restore R4 - harmless ONLY because P is 1 here
28D4  LDA R2 / SHLC     restore DF
28D6  LDA R2            restore D
28D7  RET               restore X and P, re-enable interrupts
```

The deliberate `P=1` window at `28D2` is the **only** place in the firmware
where R4 can be loaded without branching.

### Other vectors

`RLDI R1` also appears at `05A6`→`0699`, `05CD`→`8E0F`, `065C`→`8E0F`,
`066F`→`8E0D`, `0679`→`067E`, `06E4`→`0699`. Two of those point into RAM.
Not yet investigated — there appear to be several interrupt modes.

## 6. The card reader link

**Port 6 is the UART data register, both directions. Port 7 is its status
register.** The entire link layer lives in the interrupt handler.

| Port 7 bit | Meaning | Test used |
|---|---|---|
| 0 | receiver has a character | `GHI RD / SHR` → DF |
| 7 | transmitter ready | `GHI RD / SHL` → DF |
| 1–3 | error bits | `ANI 0x0E` |
| 0 and 5 | idle test | `ANI 0x21` |

### ISR body — `0x5071`

```
5071  RLDI R1,28D8      re-arm the vector
5075  GHI R2 / SMI 89   stack-page sanity check: R2.hi must be 0x89
5078  LBNZ 4BD4         else bail out
507B  R5 -> 8027        receive write index
507F  R6 -> 8029        link flags
5086  INP 7             read the UART status
5087  PHI RD            keep it for the bit tests
5088  ANI 21            if both clear, bump the counter at 878C/878D
```

### Receive — classifier at `0x50DD`

`INP 6` reads the character and stores the raw byte at `0x8185`, then:

| Char | Action |
|---|---|
| `0x0D` CR | **set bit 5 of `0x8029`** — message complete |
| `0x0A` LF | ignored |
| `0x3E` `>` | set bit 6 of `0x8029` |
| `0x3F` `?` | set bit 3 of `0x8029`, reset the write index to `0x22` |
| other | range-checked, stored at `0x80<index>`, index advanced |

Characters outside `'A'`–`'Z'` and the digit range are **dropped rather than
stored**, so line noise cannot corrupt the buffer into matching a dispatch
table entry. An index past `0x27` wraps back to `0x22`.

### Transmit — `0x514B`

```
514B  R7 -> 801A              the transmit queue
514F  bit 0 of 8029 set       -> link busy, skip
5164  port 7 bit 7 clear      -> transmitter not ready, skip
5169  SEX R7                  X = the queue, so OUT sends FROM it
5180  INC R7 / LDN R7         scan upward for a non-zero slot
518A  OUT 6                   send M(R7); R7 advances
518B  DEC R7 / STR R7         stamp the slot just sent (0x00 or 0xFF)
5190  GLO R7 / XRI 21         loop until R7 reaches 8021
```

One byte per interrupt. `OUT` writes `M(R(X))`, not D — hence pointing X at
the queue.

### The `?` / `>` handshake — `0x5197`

Requires bit 3 of `0x8029` (`?` received) and bit 5 clear (no unread message),
then clears bit 3 and sends `>`:

```
51A7  SEX R4
51A8  OUT 6   <- inline 0x3E = '>'
```

`R4` is the PC, so `SEX R4` makes **X == P** and `OUT 6` takes its byte from
the instruction stream, stepping over it. **`0x51A9` is data, not code.** Same
idiom for the `0x24` after the `RET` at `0x51B1`:

```
51B0  SEX R4
51B1  RET     <- inline 0x24 -> X=2, P=4, interrupts re-enabled
51B3  LBR 28B7
```

So the link-level handshake is: **the reader sends `?`, the phone answers `>`**
once it has nothing unread of its own. Neither character belongs to the
message vocabulary — they sit beneath it.

### Link RAM map

| Address | Meaning |
|---|---|
| `801A`–`8021` | **transmit queue**, 8 slots, `0x00` = free |
| `8022`–`8026` | **receive buffer**: 2-letter prefix + up to 3 digits |
| `8027` | receive write index, `0x22`–`0x26` |
| `8028` | pointed to by RA during dispatch |
| `8029` | **link flags** — bit 0 busy, bit 3 `?` seen, bit 5 message ready, bit 6 `>` seen |
| `8031` | pointed to by R5 during dispatch; `RY` writes `0x36` |
| `805C`–`805E` | 3-byte record, pointed to by R6 during dispatch |
| `8065` | pointed to by R7 during dispatch |
| `8069` | **card session state**: `0xAA` accepted, `0x69` rejected, `0x6A` after a BR fault |
| `8185` | raw last character received |
| `878C`/`878D` | 16-bit count of interrupts with port 7 bits 0 and 5 both clear |
| `818D` | counter: cleared by `X`, incremented by `Y` (saturates at `0xFF`) |
| `818E` | counter: incremented by `MZ` and `NZ` |
| `806A` | position shadow used by `MO` |

Link reset at **`0x5FB1`** clears bit 0 of `0x8029`, zeroes `8031` and
`805C`–`805E`, calls `EraseBlock` over the receive buffer, and sets
`8134 = 0xAA`.

## 7. Receiving: the message dispatcher

**`dispatch_card_reader_message`** @ **`0x333D`** (was `proc_333d`).

Its wrapper at `0x5F35` sets the pointer registers and restores them after:
`R5 = 8031`, `R6 = 805C`, `R7 = 8065`, `RA = 8028`.

```
8029 bit 5 == 0 -> nothing to do, return 0

RB -> 8022 (received), RE -> 3300 (table), X = RB
for each 4-byte entry:
    table[0] vs received[0]
    table[1] == 0x00 -> single letter, matches ANY second character
    else table[1] vs received[1]
scan ends at the 0xFF terminator at 333C

3372  SEX RE      X = the entry's 2 address bytes
3373  RLXA R4     R4 <- those bytes = INDIRECT JUMP to the handler
```

The fall-through past `RLXA R4` is not a bug: `OK`'s entry points at `3375`,
the very next address, so `OK` costs nothing.

### Dispatch table — `0x3300`, 15 entries × 4 bytes, `0xFF`-terminated at `0x333C`

`+0`,`+1` = prefix characters (`+1` of `0x00` = wildcard); `+2`,`+3` = handler
address, big-endian.

| Code | Handler | What it does |
|---|---|---|
| `CA` | `33C5` | shared with CB, CO |
| `CB` | `33C5` | shared |
| `CO` | `33C5` | shared — **the card-data handler** |
| `MO` | `3468` | drive stepper to a position |
| `MN` | `34B3` | clear a byte, report status `0x96` |
| `NE` | `34C4` | fault announcement |
| `BR` | `33A0` | numbered fault; status `0xA9` |
| `OK` | `3375` | latch `M(802B) = 0xFF` |
| `MS` | `34EC` | measurement step — walking bit in `814D` |
| `RY` | `3389` | ready; `EraseBlock(8022,8026)`, returns DF=1 |
| `TG` | `337F` | latch `M(802A) = 0xFF` |
| `X` | `3420` | wildcard; clear counter `818D` |
| `Y` | `343C` | wildcard; increment `818D`, saturating |
| `MZ` | `3453` | prologue, then **falls into** `MO` at `3468` |
| `NZ` | `34BC` | prologue, then **falls into** `NE` at `34C4` |

**Do not set function boundaries at `3468` or `34C4`** — two handler pairs
share tails by falling through.

**`CA`, `CB`, `TG` and `MN` are not accounted for by this reader.** They are
absent from the BSK31's reply vocabulary at `0x02FF` *and* from its command
parser at `0x0EC0`. Eleven of the fifteen entries do match that vocabulary,
which is what ties this table to the reader at all; these four do not, and are
the prime candidates for the trunk link (§9a).

### Return convention — `0x34FE`

```
34FE  LDI 0 / LSKP 3503     "nothing further to do"
3501  LDI 1                 "caller should act"
3503  SHR                   DF = that value
3504  GLO RF                D  = status code
3506  SRET R3
```

Status codes set explicitly: `0xA9` (BR), `0x96` (MN), `0x93` (NE/NZ), `0x98`
(transmit index underflow). Others come back from `36B0`.

### The card-data handler — `0x33C5`

The most informative handler. It parses a value out of the `8060` buffer,
calls **`popcnt` (`3886`)**, and computes **`7 − popcount`**. A bit count
against a fixed total of 7 is how a Landis & Gyr optical card is read: units
are physically burned away, so **the bits still set are the remaining
credit**. A compare loop over `850E` checks the parsed value against a small
table, and the outcome writes `0xAA` (accepted) or `0x69` (rejected) to the
session state at `8069`.

`36C2` is almost certainly the **stepper single-step pulse**: `MO` calls it
once per unit of difference between a target and the position shadow at
`806A`, `MZ` exactly twice, `X` and `Y` once each.

## 8. Transmitting: the command set

**`send_reader_command`** @ **`0x365C`** (was `FUN_365c`). Signature `B` — one
inline selector byte, which is the **low byte of a template address** in the
table at `0x3600`.

```
365C  selector 0x20 only -> SCAL 3551 first
3667  RE -> 3600                  template table
366B  R9 -> 8021                  TOP of the transmit queue
366F  RC = 8
3673  LDN R3 / PLO RE             RE = 3600 + selector
3675  SEX R9                      X = queue, STXD walks DOWNWARD
3676  LDA RE / STXD  x8           copy the template
367C  LDA R3                      consume the inline selector
367D  selector 0x48 only -> fill three decimal digits into 801D/801E/801F
36AA  LDI 19 / STR RA
```

### Command template table — `0x3600`–`0x3657`, 11 entries × 8 bytes

**Every template is stored backwards.** The copy loop fills the queue downward
from `0x8021` while the ISR transmits upward from `0x801A`, so a row must be
read right-to-left to see the wire bytes. `0x00` is padding and the ISR skips
it.

| Sel | Stored bytes | Wire |
|---|---|---|
| `00` | `0d 0a 37 30 30 44 43 3f` | `?CD007` |
| `08` | `0d 0a 37 30 30 45 43 3f` | `?CE007` |
| `10` | `00 00 00 0d 0a 44 4d 3f` | `?MD` |
| `18` | `00 00 00 0d 0a 43 43 3f` | `?CC` |
| `20` | `00 00 00 0d 0a 4a 45 3f` | `?EJ` |
| `28` | `00 00 00 00 0d 0a 46 3f` | `?F` |
| `30` | `00 00 00 00 0d 0a 53 3f` | `?S` |
| `38` | `00 0d 0a 31 30 45 54 3f` | `?TE01` |
| `40` | `00 0d 0a 32 30 45 54 3f` | `?TE02` |
| `48` | `0d 0a 30 30 30 46 45 3f` | `?EF000` — digits filled at runtime |
| `50` | `0d 0a 32 31 30 44 43 3f` | `?CD012` |

The reversal is proven by **the reader's own command parser at `0x0EC0`**
(see `../card-reader/BSK31-firmware.md`). That parser reads character 0,
compares it, then does `INC R8` and compares character 1. For `CD` it expects
`'C'` first and `'D'` second. Read backwards, selector `00` sends `?CD007` —
`'C'` then `'D'`, which the parser accepts. Read forwards it would send `DC`,
for which the reader has no case at all. Ten of the eleven templates match a
real parser branch this way.

Digit order reverses too — selector `00` stores `"700"` and sends `"007"`.

> **Superseded reasoning.** An earlier version of this file argued the
> reversal was confirmed because selectors `38`/`40` read backwards as
> `?TE01`/`?TE02`, matching the `TE1`–`TE14` labels in the reader's menu
> strings at `03B9`–`0559`. That was **not valid evidence** — those labels are
> human-readable display text for a service terminal, not protocol tokens, and
> the agreement was a coincidence of the letters T and E. The parser is the
> real evidence. The conclusion happened to be right; the argument was not.

**Command shape: `?` + two-letter mnemonic + optional decimal digits** — the
mirror image of the reader's replies, which are a two-letter prefix plus
digits terminated by CR. `?` opens a request; CR closes a response. Commands
and replies use **separate namespaces**: none of `CD CE MD CC EJ F S EF`
appears in the reader's reply vocabulary at `0x02FF`.

Two special cases corroborate the reading:

- **Selector `0x48`** patches three decimal digits into `801D`/`801E`/`801F` —
  exactly the three `'0'` characters of `?EF000` once queued. It does so by
  **incrementing the template's own `'0'` bytes**, which is why the template
  carries `"000"` rather than blanks.
- **Selector `0x20`** (`?EJ`) calls `3551` first. `EJ` is most likely
  **eject**, which would need the transport prepared.

### Call sites

| Site | Selector | Command |
|---|---|---|
| `310C` | `48` | `?EF000` with a runtime number |
| `3114` | `28` | `?F` |
| `3145` | `08` | `?CE007` |
| `314D` | `00` | `?CD007` |
| `318C` | `10` | `?MD` |
| `31E2` | `20` | `?EJ` |
| `3954` | `18` | `?CC` |

Selectors `0x30` (`?S`), `0x38` (`?TE01`), `0x40` (`?TE02`) and `0x50`
(`?CD012`) have **no call site with a literal selector** — either issued
through a computed selector, or dead.

### Matched against the reader's parser

The BSK31 parser at `0x0EC0` accepts fourteen commands. Cross-referencing:

| Reader cmd | Handler | Phone template |
|---|---|---|
| `F` | `0CD9` | `?F` (sel 28) |
| `EF` | `10E6` | `?EF000` (sel 48) |
| `EJ` | `22DC` | `?EJ` (sel 20) |
| `EB` | `171E` | — not sent |
| `ER` | `22DC` — shares `EJ` | — not sent |
| `CC` | `139F` | `?CC` (sel 18) |
| `CD` | `070B` | `?CD007` (sel 00), `?CD012` (sel 50) |
| `MD` | `223A` | `?MD` (sel 10) |
| `AV` | `20A8` | — not sent |
| `RE` | `2050` | — not sent |
| `PD` | `2354` | — not sent |
| `TE` | `0D9E` → the TE menu dispatcher at `0DC4` | `?TE01`, `?TE02` (sel 38, 40) |
| `DR` | `1F07` | — not sent |
| `S` | clears two flags, `LBR 0C01` | `?S` (sel 30) |

`TE → 0D9E` lands immediately before the reader's TE menu dispatcher at
`0x0DC4`, which indexes by `M(0x8023)` — so `?TE01` / `?TE02` really do select
an adjustment step. That is the confirmed route into the reader's factory
adjustment mode.

**`?CE007` (selector `08`) has no counterpart.** The reader's parser has no
`CE` branch, and no `EC` branch either, so this one command is not accounted
for by this reader firmware. It is a candidate for the trunk link (§9a), or
for a different reader revision.

## 9a. The second link — almost certainly the trunk

**The phone has TWO complete interrupt handler sets**, identical in shape and
entirely separate:

| | vector / prologue | body | epilogue |
|---|---|---|---|
| card reader | `28D8` | `5071` | `28B7` → `28D2` |
| **second link** | `0699` | **`05A6`** | `067E` |

Both re-arm their own vector as their first act, and both begin with the same
stack-page check (`R2.hi` must be `0x89`) — the second one hangs deliberately
on failure (`NOP` ×5 then `LBR 05B5`).

### Entry — `proc_06ba`

```
06E1  SEX R4 / DIS 24     X==P idiom: disable interrupts
06E4  RLDI R1,0699        point the vector at the second handler
06E8  SEX R4 / RET 24     X==P idiom: re-enable
06EB  IDL                 halt until the link interrupts
```

Interrupts are off across the vector change, so none can arrive while R1 is
half-written. The `IDL` is the giveaway that this is a *session entry*: all
further work happens inside `05A6`. Reached from **`DLC_Comm` (`2F65`)** after
it prompts the operator, reads a keypress, and waits for EF3 to go active.

### Physical layer — not a UART

| Line | Use |
|---|---|
| **EF1** | counted in hardware by the 1806 counter in **SCM1** mode (`05D7` `STPC`, `05DB` `LDI 0C`/`LDC`, `05DD` `SCM1`) |
| **EF3** | sampled a bit at a time via `setDF_to_EF3_inverted` (`0100`) |
| **Q** | driven by `SEQ`/`REQ` (`REQ` at `07AC` in the `0721` setup) |

Counter opcodes cluster at `05D7`–`05DD` (this ISR), `4079`–`407F`
(`DisplayCommStatus` region), `6EEC`–`6EF2` (init), and **`GEC` at `1ADF` —
inside `PerformComm?`**, which therefore reads this counter. That ties
`PerformComm?`, `DisplayCommStatus` (`4048`) and `DLC_Comm` (`2F65`) to this
path rather than to the card reader.

So this link is **pulse/bit level, not character level** — which is why no
second UART exists.

### RAM-resident chained vector

```
066F  RLDI R1,8E0D / RLXA R1     take the next vector from RAM at 8E0D
065C  M(8E0F)                    gates whether that happens
```

The installer is at `0x0FFB`–`0x101F`: it writes a 16-bit address fetched via
R7 into `8E0D`/`8E0E`, then sets `M(8E0F) = 1` to arm it (or `= 0` at `1015`
to disarm), and finishes with `ClearBytesAt_Array8dac` (`0A3E`).

So the second link can **hand off to a dynamically installed handler**: code
registers a callback, and the next interrupt vectors to it instead of the
default. `8E0F` is the one-shot gate. Writers of `8E0D` are `066F` (the ISR
reading it) and `1003` (the installer); writers of `8E0F` are `05CD`, `065C`
(the ISR), `0756`, `100B` and `1015`.

### What is and is not established

**Established:** there is a second, independent, fully-formed interrupt link;
its physical layer is EF1/EF3/Q with the 1806 counter; `DLC_Comm` reaches it
through `proc_06ba`; `PerformComm?` reads its counter.

**Not established:** that its peer is the trunk. The name `DLC_Comm` is the
user's, and "data link control" fits, but the peer has not been identified
from this side and nothing yet shows what is exchanged over it.

### What this settles about the unmatched codes

The receive buffer `8022`–`8026` is filled **only** by the port-6 card reader
ISR. Its write index at `8027` has exactly two references in the whole image:
`507B` inside that ISR, and `6E7B`, an initialisation that sets it to `0x22`.
Nothing else writes it.

**Therefore the dispatcher at `333D` can only ever see card reader traffic**,
and `CA`, `CB`, `TG` and `MN` are *not* trunk codes. They are reader-link
codes that this reader firmware never sends — a different BSK model or
revision. The same reasoning does not cover `?CE007`, which is transmitted
rather than received, so that one remains unexplained.

What is anchored to the reader, and why:

- The receive buffer `8022`–`8026`, the flag byte `8029` and the dispatcher at
  `333D` form one chain, and **eleven of the dispatcher's fifteen prefixes
  match the BSK31's own reply vocabulary** at `0x02FF` in an independent
  image. Eleven two-letter codes agreeing is not chance.
- **Ten of the eleven transmit templates match a real branch** of the reader's
  command parser at `0x0EC0`.
- The `?` / `>` handshake is implemented at **both** ends: the phone compares
  and emits them in its ISR, and the reader compares `0x3E` at `082D` and
  `0x3F` at `083C` in its own serial ISR.

So port 6 / port 7 is the reader link. What is **not** anchored:

| Item | Status |
|---|---|
| `CA`, `CB`, `TG`, `MN` | **resolved** — reader-link codes, see above; this reader firmware just never sends them |
| `?CE007` (selector `08`) | **still open** — sent by the phone, no parser branch in the reader |
| `PerformComm?` (`1ABE`), `DLC_Comm` (`2F65`) | the second-link subsystem, documented above |
| Vectors `0699` / `067E` | **resolved** — the second link's prologue and epilogue |
| `8E0D` / `8E0F` | the second link's RAM-resident chained vector and its gate |

## 9. Idioms and pitfalls

### `RLXA R4` is a jump

See §3. The decompiler will not show it.

### The `X == P` inline-operand idiom

When X equals the PC register, `OUT`/`INP`/`RET`/`DIS` take their byte from
the instruction stream and step over it. Those bytes are operands, not code.
Confirmed at `51A8` (`OUT 6` ← `0x3E`) and `51B1` (`RET` ← `0x24`). The same
idiom appears in the reader ROM at `0x1FF7`.

### Data blocks that disassemble as code

Both the dispatch table at `0x3300` and the command table at `0x3600` are data
that reads as plausible instructions. Each must be forced to data or the
listing derails into the code that follows.

### Inline arguments defeat naive scans

See §4. Any opcode-level search must account for callee signatures.

## 10a. `0xF000` — the control register

**`0xF000` is a write-only control register with a RAM shadow at `0x8E10`** —
the identical arrangement to the card reader's `0xE000`/`0x8021` pair. The
register cannot be read back, so callers modify the shadow and push it out.

| Routine | Role |
|---|---|
| `000C` / `000F` | initialiser; writes `0x00` or `0x03` (two entry points via `LSKP`) to **both** shadow and register |
| `13A1` `copy_byte_from_8E10_to_F000` | re-commits the shadow to the register, preserving D through R5 |

**It is not in any declared segment** (`code` `0000`–`7FFF`, `ram`
`8000`–`9FFF`, `LCD` `E000`–`E007`), so these accesses show as unmapped until
a block is declared.

26 sites reference `0xF000`: `0016`, `0056`, `006C` (early init), `0411` and
`302D` (the RAM payloads, §10), `13A6`, `29DB`, and a dense block at `1DC5`,
`1DCF`, `1E39`, `1EA2`, `1ECA`, `1EE3`, `1F04`, `1F27`, `1F58`, `209A`,
`20B4`, `2198`, `2221`, `2237`, `225B`, `226C`, `2282`, `22A6`. That block
lies in the large unnamed span between `1C5F` and `24BC` and is where the
register's individual bits should be identifiable. Only four sites touch the
shadow: `0011`, `13A2`, `1ED1`, `1EEA`.

### What it probably gates

Both RAM-resident payloads (§10) write `0xF000`, and that is the clue. Payload
1 disables interrupts, pokes `F000`, checksums a block, and re-commits the
register. Payload 2 walks a verification list and, on the first mismatch,
**writes `0x00` to `F000`** and returns failure.

A routine that pokes a register and then reads memory, and which must live in
RAM to do it, implies **the register gates the ROM itself** — bank select,
write-enable or similar — because the ROM is not addressable while it is
poked. Interrupts are off across the whole sequence, which fits: an interrupt
would try to fetch from ROM. Clearing it as the response to a failed integrity
check fits a capability-withdrawal or protection latch.

**This is inference from structure, not proof.** The bits have not been
identified.

## 10. Code executed from RAM

`0x026A` (`CopyCodeTo9733AndJump`) does
`memcpy(dest=9733, src=040D, len=003F)` then `LBR 9733`. `0x304A`
(`copy_0x26_from_3011_to_9771_and_jump`) copies `0x26` bytes from `3011` to
`9771`. The two land **adjacent** at runtime: payload 1 occupies
`9733`–`9770`, payload 2 starts at `9771`.

To read either, disassemble the ROM source and add the offset — `+0x9326` for
`040D`, `+0x6760` for `3011`. Absolute targets inside each block are already
written for the RAM copy, which is why branches in the ROM image point at
`97xx`.

| Payload | ROM | RAM | Does |
|---|---|---|---|
| 1 | `040D`, `0x3F` bytes | `9733` | interrupts off → write `F000` → 16-bit checksum over R6 bytes at R7, accumulated at `8EFA` → compare against a stored word → `copy_byte_from_8E10_to_F000` → interrupts on |
| 2 | `3011`, `0x26` bytes | `9771` | walk a pointer list (RC) of RD entries, require every target byte to equal `M(00F7)`; on mismatch write `0x00` to `F000` and return `0xFF` |

Ghidra also shows functions at `910B`, `9421`, `95BF`, `96F9`, `9708`,
`9733` (`proc_from_040D`) and `9771` (`proc_from_3011`).

`PerformComm?` (`0x1ABE`) operates on RAM at `0x97xx` and on flag `0x8167`,
and calls `DisplayCommStatus` (`0x4048`). This is the **line/modem side**, a
separate subsystem from the card reader link. `DLC_Comm` (`0x2F65`) belongs
with it.

## 11. Naming added in this session

Renamed: `proc_333d` → **`dispatch_card_reader_message`**;
`FUN_365c` → **`send_reader_command`**.

Commented: `6E03` (the P switch), `28D8` (vector, prologue, epilogue),
`5071` (ISR body and flag map), `50DD` (character classifier), `514B`
(transmit and handshake), `5FB1` (link reset and RAM map), `333D`
(dispatcher), `3300` (dispatch table), all 13 handlers, `34FE` (return
convention), `3600` (command table), `365C` (`send_reader_command`).

**No function boundary exists at `0x5071`, `0x514B` or `0x5FB1`.** The Ghidra
MCP cannot create functions. Creating them by hand would let the decompiler
render the link layer properly; suggested names `cardreader_link_isr`,
`cardreader_tx`, `cardreader_link_reset`.

## 12. Confidence

**Confirmed by independent evidence:** `P = R4` (the `RLDI R4` / `SEP R4` pair
at `6E03`, and the dispatcher only works as a jump table if it holds); ports 6
and 7 as the UART data and status registers; the receive buffer, index and
flag bits (the ISR writes them and the dispatcher reads them); the transmit
queue bounds; the dispatch table layout and all 15 entries; the command
template table and its reversed storage (`?TE01`/`?TE02` against the reader's
own TE menu); `send_reader_command`'s signature and call sites.

The reversed template storage is also confirmed, but by the reader's command
parser rather than by the menu-string argument this file first used — see the
superseded-reasoning note in §8.

**Inferred, plausible, not proven:** `36C2` as the stepper step pulse; `EJ` as
eject; the popcount-against-7 reading as remaining card credit (strongly
supported by the reader being an optical-card device, but the card format was
not independently verified); `0x8029` bit 0 as a busy/inhibit flag.

**On `0xF000` (§10a):** that it is a write-only register shadowed at `0x8E10`
is established, by the same shadow-and-recommit pattern the reader uses. That
it **gates the ROM** is inference from the RAM-residency of the two payloads
that poke it — strong, but not proven, and no bit has been identified.

**Unknown:** what the mnemonics actually *do* — the parser gives each one a
handler address, but those handlers are not yet read; why four templates have
no literal call site; the other interrupt vectors (`0699`, `8E0D`, `8E0F`,
`067E`); what fills the `8060` buffer that `33C5` parses.

**On the second link (§9a):** that it exists, and its EF1/EF3/Q physical
layer, are established. That its peer is the **trunk** is not — it is a strong
inference from `DLC_Comm`'s name and its operator-driven entry, no more.

`CA`, `CB`, `TG` and `MN` are no longer in doubt: the receive buffer has
exactly one writer, so the dispatcher sees only reader traffic. **`?CE007`
remains genuinely unexplained.**

## 13. Next steps

1. Create functions at `5071`, `514B`, `5FB1` so the decompiler can render the
   link layer.
2. **Confirm the second link's peer** (§9a). The handler, its physical layer
   and its entry point are known; what travels over it is not. The RAM code
   copied from ROM `040D` and `3011`, and the chained vector at `8E0D`, are
   the next things to read.
3. Read the fourteen reader-side command handlers listed in §8 to find out
   what each mnemonic actually does.
3a. Identify the bits of `0xF000` from the dense block of accesses between
   `1DC5` and `22A6`, and declare a memory block for it in Ghidra.
4. Chase the computed selector that reaches `?TE01` / `?TE02`: that drives the
   reader into factory adjustment mode, the most powerful thing the phone can
   ask of it.
4. Record the `RLXA`-into-PC gap in `cdp1806/REVIEW.md`.
5. Identify what writes the `8060` buffer parsed by the card-data handler.
