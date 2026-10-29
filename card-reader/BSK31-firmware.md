# Landis & Gyr BSK31-202 Card Reader — Firmware Reverse Engineering Notes

Working notes from the reverse engineering of the card reader ROM used in Israeli
Bezeq payphones. Everything here was derived from the ROM image itself; see
§13 for what is confirmed versus inferred.

Last updated: 2026-10-29.

---

## 1. Hardware identification

From the physical labels and photographs of the unit:

| Field | Value |
|---|---|
| Manufacturer | **LANDIS & GYR** (Israeli label reads **SODECO**) |
| Model | **Type BSK31-202 F** |
| Stepper motor | SAIA 12 V, `UBD23N11RNZ19` |
| Origin | MADE IN TAIWAN |
| Bezeq part no. | `117-04-031-3` |
| Taas part no. | `08-208-2000` |
| Service | BEDEK repair labels |
| Date | 1996 |

The reader handles **Landis & Gyr optical phonecards**, not magnetic or smart
cards. That single fact explains the whole shape of the firmware: an optical
encoder, a light-intensity adjustment, **gain 0 order / gain 1 order** settings
(diffraction orders of the holographic read), and an **erasure power** setting —
optical cards are decremented by physically burning spots on the card.

Reader lineage per the Landis & Gyr optical-card museum: SK15 → SK20 → SK30 →
**BSK31** → BSK32 → BSK36 → BSK50.

## 2. ROM image

| | |
|---|---|
| File | `Card Reader/ROM Image/Card Reader BSK-31 202 .BIN` |
| Size | 32768 bytes (27C256-class, 32 KiB) |
| Populated | `0x0000`–`0x2432` |
| Oddity | a lone `0xCF` at `0x27FF`, otherwise padding above `0x2432` |

A second dump of the same board exists as `NM27LC256@DIP28.BIN` (also populated
to `0x27FF`), which is a different chip/read — not byte-identical.

## 3. CPU identification — plain CDP1802

The ROM is from the RCA 180x family but is **not** a 1804/5/6.

Evidence:

- **Zero** `0x68`-prefixed extended opcodes anywhere in the code. All ten `0x68`
  bytes in the image are either branch operands or the ASCII letter `h`. On a
  1804/5/6, `0x68` is the prefix byte for the whole extended instruction set
  (`SCAL`, `SRET`, `RLDI`, `DBNZ`, …), so its total absence is decisive.
- **541** `SEP R4` and **63** `SEP R5` instructions — the register-based
  **SCRT** software calling convention, which is exactly what a plain 1802 has
  to use because it lacks `SCAL`/`SRET`.

This contrasts with the *payphone* ROM in the same project, which **is** a 1806
and does use `SCAL` (`68 8N`).

## 4. Calling convention — RCA SCRT

Standard Call And Return Technique, implemented in software:

| | |
|---|---|
| `SEP R4` | **call**, followed by a 2-byte big-endian inline target address |
| `SEP R5` | **return** |
| SCRT CALL routine | `0x12EE` |
| SCRT RETURN routine | `0x07F1` |

Register roles as observed in this ROM:

| Reg | Role |
|---|---|
| R0 | PC during interrupt service |
| R1 | interrupt vector → `0x0239` |
| R3 | caller's PC / **inline argument pointer** (args read with `LDA R3`) |
| R4 | SCRT call vector (`0x12EE`) |
| R5 | SCRT return vector (`0x07F1`) |
| R6 | stack pointer (`SEX R6`, `STXD`) |
| R8 | general pointer; set to `0x8021` in the interrupt prologue |
| RA | general pointer; set to `0xE000` in the interrupt prologue |
| RE | **saved D** — SCRT stashes the accumulator here; routines that take a
       value "in D" read it back with `GHI RE` |
| RF | page-`0x81` flag pointer. **`RF.hi` is loaded with `0x81` exactly once,
       at init (`0x00D1`), and never changed** — so every `PLO RF / LDN RF`
       anywhere in the ROM is a page-`0x81` flag access |

### Inline arguments

Beyond the 2-byte call target, many callees consume **further** inline bytes
from the caller's stream via `LDA R3`. This is the central quirk of the firmware
and the reason for the custom Ghidra analyzer (§12).

## 5. Memory map

| Range | Contents |
|---|---|
| `0x0000`–`0x7FFF` | ROM |
| `0x8000`–`0x8FFF` | RAM |
| `0xE000` | **write-only hardware control register** |
| `0xE080` | **off-image interrupt dispatcher** (not in this ROM) |

### RAM variables

| Address | Meaning |
|---|---|
| `0x8021` | **shadow of the write-only control register at `0xE000`** |
| `0x8023` | TE (service menu) step index |
| `0x8024` / `0x8025` | serial output buffer page / offset, handed to the level-6 ISR |
| `0x8027` | operation code |
| `0x802B` | ADC result |
| `0x802C` / `0x802D` | per-bit measurements |
| `0x802E` | running maximum |
| `0x8031` / `0x8033` | carriage position (valid range 0–120) |
| `0x8034` | stepper phase index |
| `0x8035` | live stepper phase pattern |
| `0x8036` | **interrupt tick counter** (bumped by level 8) |
| `0x8038`, `0x8039` | counters |
| `0x803C` | string staging buffer |
| `0x80B0` | composed output line |

### Page `0x81` — flag block

`0x8101`–`0x812F`, zeroed at init. Known flags:

| Address | Meaning |
|---|---|
| `0x8100` | checked by level-7 handler |
| `0x8101` | set by the level-6 ISR at `0x0825` |
| `0x8102` | **"OK already announced"** latch (see `announce_ok_once`) |
| `0x8108` | checked by the level-6 ISR before the inbound-byte path |
| `0x810D` | required by `require_810D_else_BR09` |
| `0x8110` | command-completion flag (set by level 5) |
| `0x8111` | stepper direction |
| `0x8113` | checked by level-7 handler |
| `0x811A` | required by `require_811A_else_BR13` |
| `0x811B` | written by the level-1 ISR from port-1 bit 0 |

Because `RF.hi` is permanently `0x81`, these are all reached as
`LDI <offset> / PLO RF / LDN RF`.

## 6. I/O ports

| Port | Use |
|---|---|
| 1 | command/control; interrupt status bits (bit 0, bit 1 polled) |
| 2 | **byte-serial data, both directions** |
| 3 | **status / ready handshake** (bit 0 = transmitter ready/direction) |
| 4 | DAC |
| 5 | actuator strobe (asserted `0x10`, delay, released `0x00`) |
| 6 | control strobe |
| 7 | control strobes / release |

## 7. Interrupt system

### Prologue — `0x0239`

Saves roughly 20 registers, restores the SCRT vectors (`R4 = 0x12EE`,
`R5 = 0x07F1`), then at `0x0271`:

```
R8 = 0x8021          ; shadow of the control register
LDN R8 / STXD        ; push the current control value
DEC R6
RA = 0xE000          ; the control register itself
LBR E080             ; -> dispatcher, NOT IN THIS IMAGE
```

### Dispatch stub table — `0x0280`–`0x02FE`

Eight entries on a **16-byte stride**, so the off-image dispatcher computes
`0x0280 + (index << 4)` — a 3-bit event space, exactly the eight present.

Each stub is 15 bytes, identical but for two fields:

```
f8 <lo> a0      PLO R0   \  R0 = resume address
f8 <hi> b0      PHI R0   /
08              LDN R8      read control shadow      (LDN R8 — not R0)
f9 <code>       ORI <code>  OR in this level's code
58              STR R8      write back to 0x8021
5a              STR RA      write through to 0xE000
e1              SEX R1
c0 02 37        LBR 0237 -> RET with inline 0x60, resuming at R0
```

| Level | Code | Stub | Resume | Action |
|---|---|---|---|---|
| 1 | `01` | `0280` | `23AB` | sample port-1 bit 0 → `M(0x811B)` |
| 2 | `03` | `0290` | `207C` | debounced fault → `BR20` |
| 3 | `07` | `02A0` | `207C` | same target as level 2 |
| 4 | `0F` | `02B0` | `2430` | acknowledge only |
| 5 | `1F` | `02C0` | `236A` | command complete, sets `M(0x8110)` |
| 6 | `3F` | `02D0` | `0801` | **serial byte service** |
| 7 | `7F` | `02E0` | `1FF7` | port-6 pulse, then timed port-5 strobe |
| 8 | `FF` | `02F0` | `23D1` | `M(0x8036) += 1` — periodic timebase |

The codes are **thermometer-encoded** (`01,03,07,0F,1F,3F,7F,FF`): level *N*
sets the low *N* bits, so OR-ing leaves the register holding the highest level
seen.

The resume addresses are **not callable routines**. They are entered with `R0`
already pointing at them and end by re-joining the main loop, so they have no
entry sequence and no `SEP R5`.

### Notable resume targets

- **`0x0801` (level 6)** — the serial service. Loads
  `R8 = 0x80:M(0x8024)` and `R9 = 0x80:M(0x8025)`, the buffer pointers the
  foreground code hands over. `INP 3 / SHR` tests the transmitter-ready bit;
  low nibble masked with `0x0E` selects the inbound path; `INP 2` reads a byte.
  **This is why outbound text leaves the reader one byte at a time under
  interrupt rather than by polling.**
- **`0x1FF7` (level 7)** — uses the `X == P` idiom (§13), so `0x1FF9`,
  `0x1FFC`, `0x2018`, `0x2020` are *operand* bytes, not code. Pulses port 6
  (`0x30`, `0x10`), checks port-1 bit 1 and flags `0x8113`/`0x8100`, then does a
  fixed-width actuator pulse on port 5 (`0x10` → `delay_word(0x0884)` → `0x00`).
  The guarded one-shot pulse pattern fits the card transport solenoid.
- **`0x23D1` (level 8)** — only bumps `M(0x8036)`, so the highest-priority level
  is the periodic timebase / watchdog tick, not a phone event.

### Padding hazard

The 16th byte of stubs 1–7 (`028F 029F 02AF 02BF 02CF 02DF 02EF`) is `0xFF`
filler. Ghidra decodes `0xFF` as `SMI`, which takes an operand and swallows the
next stub's first byte, derailing the rest of the table into mid-opcode garbage.
**Force those seven bytes to data.**

**Stub 8 has no pad** — `0x02FF` is already the first byte of the message
vocabulary table.

## 8. The control register

`write_control_reg` @ **`0x2272`**. Takes its argument **in D** (read back via
`GHI RE`), writes it to both the shadow `0x8021` and the device `0xE000`:

```
SEX R6 / push RA.hi, RA.lo, R8.lo
RA = 0xE000 ; R8 = 0x8021
GHI RE / STR R8 / STR RA
pop R8.lo, RA / SEP R5
```

The register at `0xE000` **cannot be read back** — that is the entire reason
`0x8021` exists. Callers do `LDN R8` on the shadow, modify bits, and call here.

16 call sites, in two groups.

**Modify** — compute and commit:

| Site | Operation |
|---|---|
| `00E5` | `LDI 8E` — reset value: bits 1,2,3,7 |
| `0172` | `ANI F9` — clear bits 1,2 |
| `0A85` | `ANI 7F` — clear bit 7 |
| `0E92` | `ANI DF` — clear bit 5 |
| `0F93` | `ORI 06` / `ORI 40` — set bits 1,2 and 6 |
| `15A9` | `ANI CF` / `ORI 40` — clear bits 4,5, set bit 6 |
| `1808` | `ORI 40` — set bit 6 |

**Restore** — nine sites (`09B4 0AFB 1024 12D2 14B3 1689 1858 198D 19EE`) are
all preceded by `INC R6 / LDN R6`: they *pop* a value pushed earlier. The
matching pushes (`0998 0A7D 125B 144E 162F 1800 1941 19B0 1B1A`) are each
`LDN R8 / STR R6 / DEC R6` on the shadow. So every hardware operation is
bracketed:

```
push shadow -> change bits -> perform operation -> pop and re-commit
```

Bits 1 and 2 always move as a pair. Bit 6 is set by three different operations.
Bit 7 is set at reset and cleared once.

**Open conflict:** the eight interrupt stubs also write this register, OR-ing in
the thermometer codes, which overlap the device bits above. Either the low bits
are a separate service-level field that the resume handlers restore, or levels
7–8 deliberately drive the register to a safe state. **Unresolved.**

## 9. The wire protocol

### Message format

```
<prefix> <decimal suffix> CR LF
```

Composed at `0x80B0`, shifted out byte-by-byte by the level-6 ISR (`0x0801`)
over **port 2** with the **port 3** handshake.

**The suffix width is not uniform.** `MS` and `PO` use three digits; `BR` uses
two for codes 01–49 and three for 100–101. Any assumption of a fixed
three-digit suffix is wrong.

### Vocabulary table — `0x02FF`–`0x0333`

Packed `0xFF`-terminated strings, beginning in the byte immediately after the
eighth interrupt stub.

| Addr | String | Note |
|---|---|---|
| `02FF` | `OK` | one-shot power-up announcement |
| `0302` | `RY` | ready |
| `0305` | `NZ` | |
| `0308` | `CO` | |
| `030B` | `MO` | |
| `030E` | `BR` | fault; suffixes tabulated at `0x1198` |
| `0311` | `PO` | position |
| `0314` | `X` | single letter |
| `0316` | `Y` | single letter |
| `0318` | `MZ` | |
| `031B` | `NE` | accompanies a fault; sent as the group `NE` + `X` + `BR` |
| `031E` | `MS` | measurement step (MS025 / MS030 / MS035 / MS040) |
| `0321` | `RA` | |
| `0324` | `0 0` | gain/order pair — diffraction orders, gain 0/1 |
| `0328` | `0 1` | |
| `032C` | `1 0` | |
| `0330` | `1 1` | |

Thirteen two-letter prefixes contiguous at `02FF`–`0323`; four gain/order pair
strings at `0324`–`0333`. Table ends at `0333`; `0334` is `07 FF` and
`"Step number = "` begins at `0336`.

### Fault code table — `0x1198`–`0x1246`

51 entries, `0xFF`-terminated. Stores only the **numeric suffixes**; the `BR`
prefix comes from `0x030E` and the composer appends CR LF.

- idx 1–49 → bare two digits `"01"`…`"49"` (`0x1198`–`0x123E`)
- idx 50 → `"100"` (`0x123F`)
- idx 51 → `"101"` (`0x1243`)

**Five entries are stored pre-composed**, with prefix and CR LF baked in, and
are emitted literally instead of going through the composer:

| idx | Addr | Content |
|---|---|---|
| 30 | `11EF` | `BR30\r\n` |
| 31 | `11F6` | `BR31\r\n` |
| 32 | `11FD` | `BR32\r\n` |
| 37 | `1210` | `BR37\r\n` |
| 38 | `1217` | `BR38\r\n` |

Those five are referenced from the **reset/init path** (`BR32` at `0x001D`,
`BR30` at `0x0032`, `BR31` at `0x0043`) — code that runs before the message
composer and its RAM buffers are set up, so it has to ship a ready-made byte
string. The exceptions are precisely the faults detectable before the reader is
fully alive.

So the fault space is **`BR01`–`BR49` plus `BR100`/`BR101`**.

### Handshake

`announce_ok_once` @ `0x228E` sends `OK` **exactly once**, gated on port-1 bit 1
(the phone is listening) and latched by flag `0x8102`. This is the reader's
power-up announcement; everything after it is request/response.

### No public documentation

Searches across the model name, the wire codes, the fault codes and the
service-mode strings returned nothing technical. The reader lineage is
documented at optical-cards.com, but no protocol spec or service manual for the
BSK31 appears to be online. **This vocabulary is reconstructed from the ROM
alone.**

## 10. Service / adjustment mode (the "TE" menu)

The firmware contains a full factory adjustment mode that talks to a terminal
with ANSI escape sequences (`ESC[2;18H` etc.) — not to the phone.

### Menu dispatcher — `0x0DC4`

Uses two extra registers to stage the call: `RB` = jump table at `0x0DE1`,
`RA` = trampoline at `0x0DD9`; index taken from `M(0x8023)`.

| Entry | Target | Purpose (from its own menu string) |
|---|---|---|
| TE1 | `2024` | |
| TE2 | `1CC1` | |
| TE3 | `1501` | Adjustment of optical encoder |
| TE4 | `21B7` | Adjustment of intensity ( P1/A ) |
| TE5 | `1E95` | Adjustment of gain 0 order ( P3/A ) |
| TE6 | `1E5A` | Adjustment of gain 1 order ( P2/A ) |
| TE7 | `14CC` | Adjustment of stop switch |
| TE8 | `18CD` | Adjustment of erasure power ( P1/F ) |
| TE9–13 | `095C` | Adjustment of erasure/reading |
| TE14 | `1BEA` | Check of the displacement |

Each target was independently confirmed by the menu string it prints.

`MS025 → TE9`, `MS030 → TE10`, `MS035 → TE11`, `MS040 → TE12`,
`TE13 (program)`.

### Service-mode strings

`"Step number = "` (`0336`), `"ADJUSTMENT ABORTED"` (`0349`),
`"Measurement"` (`0377`), `"CONNECT ADJUSTMENT TOOL"` (`0390`),
`"BSK31 "` banner (`0563`).

This is almost certainly where the `PO` (position) and `RA` prefixes go — the
payphone's own parser table (§11) does **not** list them.

## 11. The payphone side of the protocol

The payphone firmware is the other half of this conversation.

| | |
|---|---|
| Model | **TAMAC-18 V2.8** (banner `"TAMAC18"` at `0x7BDF`) |
| CPU | CDP**1806** (uses `SCAL`, `68 8N`) |
| Image | `TAMAC-18 V2.8 9513.bin` ≡ `Binary versions/PH00.bin` |
| Second version | `PH06.bin` ≡ `B01.bin` ≡ `DLC.bin`; `B02.bin` a near-sibling |

### Receive dispatch table — `0x3300`, 15 entries, `0xFF`-terminated at `0x333C`

Four bytes per record: **two ASCII bytes + big-endian handler address**. Single
letters are NUL-padded.

| Addr | Code | Handler |
|---|---|---|
| `3300` | `CA` | `33C5` |
| `3304` | `CB` | `33C5` |
| `3308` | `CO` | `33C5` |
| `330C` | `MO` | `3468` |
| `3310` | `MN` | `34B3` |
| `3314` | `NE` | `34C4` |
| `3318` | `BR` | `33A0` |
| `331C` | `OK` | `3375` |
| `3320` | `MS` | `34EC` |
| `3324` | `RY` | `3389` |
| `3328` | `TG` | `337F` |
| `332C` | `X` | `3420` |
| `3330` | `Y` | `343C` |
| `3334` | `MZ` | `3453` |
| `3338` | `NZ` | `34BC` |

This is the **only** such table in the payphone ROM — every other candidate hit
was coincidental ASCII inside display text (`"TEMPORARY FAULT"`,
`"OUT OF SERVICE"`, `"INSERT CARD"`, …).

### Cross-check against the reader's vocabulary

- **Shared (11):** `CO MO NE BR OK MS RY X Y MZ NZ` — confirms the reader
  vocabulary against an independent image.
- **Reader sends, phone does not parse (2):** `PO`, `RA` — consistent with
  these belonging to the service terminal (§10), not the phone.
- **Phone parses, this reader does not send (4):** `CA`, `CB`, `MN`, `TG` —
  possibly other reader models or a different peripheral. `CA`/`CB`/`CO` all
  share handler `33C5`.

## 12. Ghidra tooling built for this project

### `cdp1806` Ghidra extension (merged to `main`, PR #10)

An **inline-argument analyzer** for the 1806 payphone ROM: `SCAL` calls whose
arguments sit in the caller's instruction stream right after the call. Walks the
callee's flow and measures the net `R3` advance to `SRET R3`.

### SCRT call analyzer (branch `task/scrt-call-analyzer`)

The 1802 equivalent for this reader ROM: `SEP R4` + 2-byte inline address.

Options: *Call register* (`R4`), *Inline bytes after SEP* (`2`), *Return
register* (`R5`), *Create functions at call targets*. **Off by default.**

Key implementation note — ordering matters:

```java
// Changing the flow override re-derives the instruction's fall-through and
// discards any override on it, so set the flow FIRST and the fall-through SECOND.
in.setFlowOverride(FlowOverride.CALL);
if (total > 0) { in.setFallThrough(resume); }
```

Resolution order is **signature comment → detection** (write-once-then-read-only).
Disagreements are logged, never applied.

### Signature mini-language

Stated in a callee's **repeatable comment**; the analyzer reads it and marks up
every call site.

| Token | Meaning |
|---|---|
| `B` | one inline byte |
| `W` / `WO` | word, treated as an **address** (typed as a pointer, creates a reference) |
| `WI` | word **immediate** (a number — does *not* create a reference) |
| `P` | forced pointer |
| `NONE` | no inline bytes |

The `WI` distinction was added because typing a delay count as a pointer
manufactures false references.

Heuristic used by the detector: a register only decremented/compared holds a
number; one used to reach memory holds an address.

**Design constraint: no override file.** All signature data lives in the Ghidra
database only — the project is the single record.

### Signatures assigned so far

| Addr | Name | Signature |
|---|---|---|
| `0E01` | `tty_print_line` | `W,B` |
| `018B` | — | `B` (port-7 bit selector, 04 or 08) |
| `1593` | `print_msg_and_restart` | `W` — **does not return** |
| `1A02` | — | `B` (sample selector, `01` at its only call site) |
| `1E1C` | `read_card_bit` | `NONE` |
| `2171` | `strcopy_to_0x803C` | `W` |
| `2194` | `memzero` | `W` |
| `2272` | `write_control_reg` | `NONE` |
| `228E` | `announce_ok_once` | `NONE` |
| `22A9` | `delay_word` | `WI` |
| `22C3` | `port1_cmd_and_wait` | `B` |
| `237F` | `require_810D_else_BR09` | `NONE` |
| `238E` | `require_811A_else_BR13` | `NONE` |
| `23C5` | `require_pos_in_range_else_BR48` | `NONE` |
| `23DB` | `require_ready_and_pos_in_range` | `NONE` |
| `241C` | `set_byte_at_0x81xx` | `B` |
| `2422` | `clear_byte_at_0x81xx` | `B` |

Repeatable comments are authored **by hand** — the Ghidra MCP exposes only PRE
and EOL comments, not repeatable ones.

### Named functions

| Addr | Name |
|---|---|
| `07F1` | `SCRT_RETURN` |
| `0E01` | `tty_print_line` |
| `12EE` | `SCRT_CALL` |
| `1593` | `print_msg_and_restart` |
| `1864` | `build_scale_bar` |
| `1B9F` | `stage_decimal` |
| `1DD9` | `adc_read_byte` |
| `1E1C` | `read_card_bit` |
| `20FB` | `seek_to_position` |
| `214D` | `adc_sample_comparator` |
| `2171` | `strcopy_to_0x803C` |
| `2194` | `memzero` |
| `21FB` | `test_0x8109_and_0x8031` |
| `2272` | `write_control_reg` |
| `228E` | `announce_ok_once` |
| `22A9` | `delay_word` |
| `22C3` | `port1_cmd_and_wait` |
| `230D` | `load_io_subroutines` |
| `237F` | `require_810D_else_BR09` |
| `238E` | `require_811A_else_BR13` |
| `23C5` | `require_pos_in_range_else_BR48` |
| `23DB` | `require_ready_and_pos_in_range` |
| `241C` | `set_byte_at_0x81xx` |
| `2422` | `clear_byte_at_0x81xx` |
| `242C` | `port7_release` |

## 13. Techniques and pitfalls

### Finding references to a 16-bit address

Searching for the big-endian inline-argument word alone **misses most
references**. A 16-bit value is also loaded into a register as:

```
F8 <lo>   LDI lo
A<n>      PLO Rn
F8 <hi>   LDI hi
B<n>      PHI Rn
```

so also search the byte pattern **`{lo} {??} {??} {hi}`**. Applying this raised
fault-string coverage from 38 to 41 of the 51 codes and found the `BR30`/`BR31`/
`BR32` references in the init path.

### The `X == P` inline-operand idiom

When `X` equals the PC register (e.g. after `SEX R0` while `P = R0`),
`OUT`/`INP`/`RET`/`DIS` take their byte **from the instruction stream** and
advance the PC past it. Those bytes are operands, not code. Ghidra will
disassemble them as instructions unless overridden. Seen at `0x1FF7` and in
several `OUT 5` / `OUT 6` sequences.

### `0xFF` padding derails the disassembler

`0xFF` is `SMI`, which consumes an operand. A `0xFF` pad byte therefore eats the
first byte of whatever follows. Any 16-byte-strided table of 15-byte records has
this problem — see §7.

### The register-subroutine idiom

`SEP Rn` jumps to a routine which returns with `SEP R0`, resuming after the
`SEP Rn`. Consecutive `SEP RB / SEP RD` are therefore two **calls**, not a jump
followed by dead code.

### Shared `SRET`

"No `SRET R3`" can mean two adjacent functions share one epilogue that physically
lies inside only one of them — not that detection failed.

### Ghidra gotchas learned the hard way

- `Function.getRepeatableComment()` and the code-unit REPEATABLE comment at the
  entry address are **the same storage**, not two slots. Code that "migrates"
  between them deletes what it just wrote.
- Setting `FlowOverride` re-derives fall-through and discards an override on it.
  Order the calls flow-first.
- Reading call targets from `getFlows()` silently drops targets recorded as READ
  references. Read the **operand** instead, and exclude `FALL_THROUGH`
  references or the analyzer's own markup poisons its input.
- Always verify which program the Ghidra MCP is bound to before writing.
  Two CodeBrowser windows each run a GhidraMCP plugin; the second fails with
  `BindException: Address already in use` and the MCP silently talks to the
  first. Check `list_segments` plus a known symbol first.

## 14. Open questions / next steps

1. **The dispatcher at `0xE080` is off-image.** This ROM structurally cannot
   reveal how a phone-side event maps to an interrupt level. That mapping is the
   one missing link in the protocol chain. Dumping or identifying the device at
   `0xE000`–`0xE0FF` is the highest-value remaining hardware task.
2. **Control register bit conflict** (§8) — thermometer codes overlap device
   bits. Unresolved.
3. **Decode the 15 payphone handlers** at `0x3375`–`0x34EC` to recover the
   semantics of each message and, crucially, the **request** direction. The
   reader ROM only shows what it *sends*.
4. **What are `CA`, `CB`, `MN`, `TG`?** The phone parses them; this reader never
   sends them.
5. Rename the 14 TE handler targets once functions exist there (the MCP cannot
   create functions).
6. Relax the detector's word-pair matcher to tolerate a second `PHI`/`PLO`
   (as in `1593`'s `LDA R3 / PHI RA / PHI RB / LDA R3 / PLO RA / PLO RB`), and
   teach it the `X == P` idiom.
7. A `cdp1802` language variant, once the 1806 definition is finished.

---

## Confidence

**Confirmed by multiple independent lines of evidence:** CPU family and
variant; SCRT convention and vector addresses; the eight-stub interrupt table
and its resume targets; the control-register mechanism and its save/restore
bracket; the vocabulary and fault tables and their formats; the payphone
dispatch table (independent image).

**Inferred, plausible, not proven:** the physical meaning of individual control
register bits; port 5 as the transport solenoid; `PO`/`RA` belonging to the
service terminal; the reading of the thermometer codes as a priority field.

**Unknown:** everything behind `0xE080`; the request direction of the protocol.
