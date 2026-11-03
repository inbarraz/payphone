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

## 1a. Board hardware

From photographs of the main card, front and back. Relevant to the firmware
because several conclusions below depend on which device a port actually
reaches.

**Board:** `I.M.I TAMAC-18 MAIN CARD`, cat. no. **08-208-1101**, **REV:2.3**
(back silkscreen also `B21`, `ME-2.94.VO-3992`). I.M.I / Taas.

**Daughterboard:** `TAAS TAMAC MEMORY CARD`, cat. no. **08-208-1300**,
`REV:1.1`, carrying sockets `SCT1`/`SCT2`, the SRAM, and the firmware EPROM.

Two boards have been photographed and they differ in that EPROM's label: one
reads `TAMAC-18 V2.8 9451`, the other simply **`DLC`** (serial `27956 9630`).
That is almost certainly the provenance of `Binary versions/DLC.bin` in this
repo — which is byte-identical to `PH06.bin` and `B01.bin`, and *differs* from
the `TAMAC-18 V2.8 9513` image these notes are written against. So the `DLC`
label denotes a build, not a different product.

| Ref | Part | Role |
|---|---|---|
| U201 | **CDP1806ACE** | the CPU |
| U231 | **CDP1854ACE** | **UART (ACE)** — the device behind ports 6 and 7 |
| U6 (daughter) | SRM2A256LLMT10 32K SRAM + lithium battery | battery-backed RAM, hence persistent state in `8000`–`9FFF` |
| (daughter, socketed) | **Atmel AT29C256** | the firmware flash — 256 Kbit as 32 KB × 8, A0–A14. Hence the 32 KB images and the `0000`–`7FFF` ROM window. |
| U16 | **MC145443P** | single-chip FSK modem |
| — | **CML FX611J** | modem / signalling IC |
| U19 | **PCD3311CP** | DTMF / tone generator |
| — | TEA1060 | telephone speech/transmission circuit |
| U3, U4, U5, U14, U18 | **MC14094BCP** ×5 | serial-in, parallel-out shift registers with output latches |
| U204 | MC14021BCP | parallel-in, serial-out shift register (input expander) |
| U202 | CD4099BE | 8-bit addressable latch |
| **U230** | **MC74HC4053N** | **triple 2-channel analog multiplexer — the UART peer selector**, see §6b |
| U214, U11 | M74HC4066B1 ×2 | quad analog switches; U214 by the CPU/decode area, U11 among the modem chips. **Not** the UART router — most likely audio switching around the speech circuit |
| U215, U217, U218, U219 | SN74HC367N ×4 | buffers driving the J1 connector |
| U224 | MC74HC245AN | bus transceiver |
| U210, U212 | CD74HC4040E | 12-stage counters |
| U229 | MC14526BCP | programmable divider |
| — | CD4521BE | 24-stage divider |
| — | 74HC573, 74HC139, 74HC173, 74HC02, 4050, 40106, 4011, 4075 | latches, decode, glue |
| K1 | relay | line switching |
| J1 / JP2 "M" / JP3 "R" / JP4 / LINE | connectors | external interfaces |

Three things follow that the firmware alone would not tell you:

1. **Ports 6/7 are a CDP1854 UART**, not CPU bit-banging. Its status bits
   match what the ISR tests exactly: bit 0 DA (data available), bits 1–3
   OE/PE/FE errors, bit 7 THRE (transmitter ready). The byte-stream decode in
   §6 is unaffected, but "port 6" means *the 1854's data register*.

   The board runs it in **Mode 1** (pin 2 tied to V<sub>DD</sub>), the direct
   CDP1800 interface. Pins that matter, from the Intersil datasheet:

   | Pin | Signal | | Pin | Signal |
   |---|---|---|---|---|
   | 1 | V<sub>DD</sub> | | 20 | **SDI** — serial data in |
   | 2 | MODE (= V<sub>DD</sub>) | | 24 | RTS |
   | 3 | V<sub>SS</sub> | | 25 | **SDO** — serial data out |
   | 13 | INT | | 38 | ES |
   | 17 | R CLOCK | | 39 | CTS |
   | 18 | TPB | | 40 | T CLOCK |

   **Locating pins on the board:** the square pad at the **bottom-right** of
   `U231` on the *solder* side is pin 1 (the `>` silkscreen marker and the
   `C225` decoupling cap are at the same end). Mirrored, that puts
   **SDI (pin 20) at the bottom-row leftmost pad** and **SDO (pin 25) fifth
   from the left on the top row**. Those are the two probe points for settling
   the routing question below.
2. **There is only ONE UART on the board** — see §6a.
3. **Q most likely clocks the HEF4094 shift-register chain**, not a
   communication line. Five 4094s expand serial data into parallel control
   outputs, and Q is the obvious source. An earlier version of these notes
   listed Q as a data line of the second link; that is probably wrong.

The modem chips and the LINE connector make the natural reading of the DLC
session a **modem call over the telephone line** — which is also why
`DLC_Comm` insists the handset be replaced first (§9a).

### J1 and the distribution board

**J1 is not a peripheral connector — it is the link to a separate distribution
board**, which fans out to everything else in the phone. Mapped by hand with a
meter (`Hardware RE/Hardware RE - Pinouts.xlsx`), so this is measurement, not
inference from photographs:

| Device | J1 pins |
|---|---|
| **Optical Reader** (the BSK31) | 16 → OR 03, 32 → OR 05, 35 → OR 07?, 38 → OR 11, 40 → OR 07, 47 → OR 12-15 |
| **Mag. Reader** | 23 → MR 03, 25 → MR 02, 26 → MR 04, 44 → MR 01 |
| Display (HD44780) | 3, 5, 6, 7, 8, 9, 10, 11, 12, 14, 22, 43 → Display 02..14 |
| Display contrast | 42 → Display POT |
| LCD backlight | 36 → Light 2 (A), 46 → Light 1 (K) |
| Keyboard | 20, 21, 27, 28, 29, 30, 31, 33, 34 → Keyboard 01..09 |
| **Hook switch** | 15 → Hook 4, 37 → Hook 1 |
| CHC SW | 24 → CHC SW 01 |
| Battery | 41, 49, 50 (and a separate battery connector, see the workbook) |
| GND | 1, 2, 18 |
| unassigned | 4, 13, 17, 19, 39, 45, 48 |

(The exact OR pin for J1 35 should be read from the workbook; the others are
as listed.)

Three consequences:

1. **The distribution board has a second card reader socket, but it was
   NOT FITTED.** The "Optical Reader" is the Landis & Gyr BSK31 these notes
   are about and is the one actually present. The "Mag. Reader" socket — four
   lines, a magnetic-head interface (card present, data, clock, ground) rather
   than a UART — **was never populated in this deployment**.

   So the hardware supports a magnetic card reader that Bezeq did not install.
   That is consistent with the display strings `SWIPE CREDIT CARD`,
   `INSERT CARD` and `Collect Card` being present in the ROM: the firmware
   carries support for a reader the phone does not have.
2. **The hook switch reaches the CPU through J1** (pins 15 and 37). That
   independently corroborates EF3 = hook, which §9a derived only from the
   "please replace the handset" prompt.
3. **The optical reader has five signal lines plus ground** — enough for
   transmit, receive, power and a control line, consistent with it being the
   CDP1854's peer.

### The firmware does support a credit card reader

Confirmed. The ROM carries a complete credit-card **user interface and
policy layer** for hardware this deployment never had. Strings, in 17-byte
two-line display slots with Hebrew and English paired:

| Addr | Text |
|---|---|
| `6825` / `6836` | `INSERT TELECARD/` + `SWIPE CREDIT CRD` |
| `687A` | `TELECARD    ONLY` |
| `689C` | `CREDIT CARD ONLY` |
| `68F1` | `CARD    REJECTED` |
| `6935` | `CREDIT   EXPIRED` |
| `6A89` | `CREDIT:` + Hebrew `יתרתך` ("your balance") |

The code that drives them is in the unnamed span after `FUN_4455`, around
`47E0`–`48D8`. It reads bits of the flag byte at `0x8139` to decide which card
types the terminal currently accepts, and shows `TELECARD ONLY`,
`CREDIT CARD ONLY` or the combined prompt accordingly.

Incidentally, **Q is used there as a one-bit state flag**: `SEQ` at `481B`
when one prompt is shown, `REQ` at `4830` for the other, then `LBQ`/`LBNQ` at
`47F1`/`4852` to recall which. `BQ` tests the CPU's own Q latch, so this is
the firmware reading back a bit it set — further evidence against Q being a
communication line (§1a).

### But there is NO magnetic-stripe decoder

A scan of the whole `4478`–`4BD7` span finds:

- **one** EF-line branch in total (`49BD: BN4`)
- no bit-shift-and-parity loop
- no track-2 sentinel compares (start `0x0B`, end `0x0F`, separator `0x0D`)
- I/O limited to `INP 1` ×4, `INP 2`, `INP 3`, `OUT 7`

A real F2F magnetic-head decoder would be unmistakable — a tight loop on an EF
line or port, shifting bits and checking parity. **There is none.** So the
firmware does not bit-bang a magnetic head.

### Which suggests the mag reader is a SERIAL peripheral

This resolves into a single hypothesis that accounts for every loose end at
once. The Mag. Reader socket has **four lines** on the distribution board.
Earlier these notes guessed card-present/data/clock/ground. But four lines is
equally **TX, RX, power, ground** — a serial-attached reader. If so:

| Loose end | Explained by |
|---|---|
| `CA`, `CB`, `TG`, `MN` parsed but never sent by the BSK31 | they are the **magnetic reader's** message prefixes, parsed by the same dispatcher because it is the same UART and the same `8022` buffer |
| `?CE007` sent but with no branch in the BSK31's parser | it is a **command to the magnetic reader** |
| no such traffic ever observed | the socket was **never fitted** |
| no stripe decoder in the ROM | none is needed — an intelligent reader sends ASCII messages, exactly like the BSK31 |
| `CA`/`CB` share the `CO` handler at `33C5` | all three carry card data in a similar format |

That is five anomalies closed by one assumption, which is why it is worth
recording. **It is still a hypothesis.** The test is the routing question in
§6a: if the two `M74HC4066` switches route the UART between the Optical Reader
pins on J1 (16, 32, 35, 38, 40) and the Mag. Reader pins (23, 25, 26, 44),
the hypothesis is confirmed and the phone has **three** UART peers — optical
reader, magnetic reader, and the DLC modem — selected by vector and switch.

### The unattributed codes, after the J1 mapping

`CA`, `CB`, `TG` and `MN` are parsed by the dispatcher but never sent by the
BSK31.

> **Retracted.** A previous version of this section floated the magnetic
> reader as their source. **The Mag. Reader socket was never fitted**, so it
> cannot be the origin of any traffic the phone actually received. The idea
> was also weak on its own terms, since four lines is not a UART.

The unfitted socket establishes the general point that **this firmware carries
support for hardware that is not installed** — and the credit-card UI above
confirms it concretely. The best current account of the four prefixes is the
serial-magnetic-reader hypothesis immediately above.

### What the photographs cannot settle

**Net tracing from these photographs is not reliable** — fine-pitch traces,
routing on both sides, partial obscuring. No claim of the form "pin X of U231
reaches U214" should be made from them, and none is made here.

The back of the board also carries several **rework wires** in the area
bounded by U214, U207, U211, U220, U221, U223 and U200 — i.e. around the
decode and UART region. Any net traced there must account for them.

**The open question this leaves** is whether the single UART's serial lines
are physically routed between the card reader connector and the modem, and if
so by what. Settling it needs continuity measurements, not photographs:

1. From the CDP1854's serial-in and serial-out pins (per the
   [Harris/Intersil CDP1854A datasheet](https://pccomponents.com/datasheets/HARRI-CDP1854ACE116.pdf))
   to the switch pins of **U214** and **U11**.
2. From those switches' other sides to **J1** and to the modem (`MC145443P`,
   `FX611J`).
3. What drives the 4066 control pins — if it is one of the `MC14094BCP`
   shift-register outputs, then the routing is **software-controlled**, and
   the firmware selects its peer. That would be the single most useful fact
   still missing, because it would tie the physical path to the vector swap in
   `proc_06ba`.

### CDP1806AC pinout (U201), 40-pin DIP

From `Documentation/Datasheets/cdp1806.pdf`. The pins that matter for tracing:

| Pin | Signal | | Pin | Signal |
|---|---|---|---|---|
| 4 | **Q** | | 21 | **EF4** |
| 7 | /MRD | | 22 | **EF3** |
| 8–15 | BUS 7..0 | | 23 | **EF2** |
| 16 | V<sub>DD</sub> | | 24 | **EF1** |
| 17 | **N2** | | 25–32 | MA0..MA7 |
| 18 | **N1** | | 33 | TPB |
| 19 | **N0** | | 34 | TPA |
| 20 | V<sub>SS</sub> | | 35 | /MWR |
| 1 | CLOCK | | 36 | **/INTERRUPT** |
| 5/6 | SC1 / SC0 | | 37/38 | DMA OUT / DMA IN |

`N0`–`N2` are the three I/O port-select lines: they carry the port number of
every `INP n` / `OUT n`, so whatever decodes them determines which device each
port reaches.

Per the block diagram in `cdp1806 diagram.pdf`, the counter/timer's **mode
control takes EF1, EF2 and TPA** as its possible clock sources. So the
`SCM1`/`SCM2` ambiguity noted in §9a is not academic: it decides whether the
second link counts **EF1 or EF2**, and tracing both resolves it from hardware.

### What differs between builds

Three distinct images exist in this project:

| Image(s) | MD5 | |
|---|---|---|
| `TAMAC-18 V2.8 9513.bin` = `PH00.bin` | `17c5d297…` | the one these notes are written against |
| `PH06.bin` = `B01.bin` = `DLC.bin` | `bb5e8284…` | |
| `B02.bin` | `5ed46341…` | |

**Every differing byte lies in `0x7C00`–`0x7F25`. Not one byte of code
differs.** V2.8 vs PH06 is 496 bytes in 4 runs, all at or above `7C01`;
PH06 vs B02 is just 4 bytes.

So the three images are **the same program with different configuration
data** — which is why `DLC.bin` being labelled `DLC` on its EPROM denotes a
build, not a different product.

| Address | V2.8 | PH06 | B02 | Reading |
|---|---|---|---|---|
| `7BFA` | `0430` | `0430` | `0430` | **software version 4.30** — see below |
| `7BFE` | `7AAE` | `7AAE` | `7AAE` | fixed, unidentified |
| `7C00` | `031C` | `0320` | — | **a length**, +4 |
| `7C02` | `009E` | `00A9` | `00A2` | **build identifier** |

**`7BFA` is a software version.** The formatter at `60A6` renders it as
packed BCD with a decimal point — `NumToString` (`4FDF`) converts two digits
per byte, `'.'` goes at `804E`, and a leading `'0'` is blanked — and the
descriptor displayed alongside it chains `662A` → `6A01` **"טמ"כ 18"**
(TAMAC 18) → `6633` → `6A12` **"מהד' תכנה:"** (*software edition*). So that
screen reads **TAMAC 18 / software version 4.30**.

Note **4.30 is not the EPROM's "V2.8" label** — two different versioning
schemes, and the one reported to DLC is the internal edition number.

`7C02` also matters: **`build_dlc_record` copies it twice into the record sent
to DLC**, and it varies with every build, so it is a build identifier
alongside the version. `7BFE` does not vary and remains unidentified.

> **Superseded.** These notes first called `7BFA` and `7BFE` "fixed model or
> hardware identifiers", and then, on seeing the decimal point and the
> leading-zero blanking, read `7BFA` as a **money amount**. Both were wrong.
> The decimal point is a version separator. Checking the label displayed
> beside the number would have settled it immediately; inferring the meaning
> of a number from its formatting alone did not.

`7C06` is an 11-entry pointer table. Entries 0–2 are unchanged between V2.8
and PH06 while entries 3–10 all shift by exactly **+4**, localising the
insertion to the third region at `7D07`. There, V2.8 reads
`05 c0 01 0a / 06 c0 01 0a / …` and PH06 reads
`04 10 01 0a / 05 c0 01 0a / …` — PH06 **inserts one extra 4-byte record**
for code `04` and shifts the rest down, which is the whole `+4`.

The first byte of each record runs in sequence and looks like a code or
index; the other three are parameters. **A tariff or destination-code table
is the natural reading** for a payphone whose builds differ only here — same
program, different charging configuration. **Not confirmed:** nothing yet
shows what consumes the table.

### Where the card's credit actually lives

The idle screen selector at `3A0B` shows a **credit screen** when
`M(8144) != 0`: descriptor `6672` → `6A89` (`"CREDIT:"` / Hebrew `"יתרתך"`)
chained to `679B` → the RAM buffer at **`0x804C`**.

The descriptors chain: each is 9 bytes, `01 00 10 <text> 0c 01 <next>`, and
**the second pointer is the next descriptor**, not a second string. `0000`
ends the chain.

But `804C` is a **display line**, not a value. The card's own credit takes a
different route and never passes through the money-looking formatter:

```
reader sends "CO<digits>"
  -> the UART ISR classifier at 510D converts digit characters to NUMERIC
     VALUES as it stores them, so 8024/8025 hold values rather than ASCII
  -> 36B0 packs the two into one byte at 8060
  -> the CA/CB/CO handler at 33C5 calls popcnt (3886)
     and stores 7 - popcount at 8062
```

So **`M(0x8062)` is the card's unit count** and `M(0x8060)` the raw packed
byte from the message.

That the firmware computes **7 minus the population count** rather than
reading a number is itself the evidence: on a Landis & Gyr optical card units
are physically burned away, so the bits still set *are* the remaining credit.

Worth noting the ISR detail, since it is what makes `36B0`'s nibble-packing
work at all: buffer positions 0–1 store `'A'`–`'Z'` raw (the message prefix),
while positions 2 onward are **hex digits converted to their numeric value**
(`'0'`–`'9'` and `'A'`–`'F'`), anything else rejected.

### The seven NOPs at 4B2D

Byte-identical in all three builds, so the removed instruction **cannot** be
recovered by comparing them. Whatever was taken out was taken out before this
firmware line diverged.

## 2. Memory map

> **Addresses here are the phone's.** The card reader is a separate CPU with
> its own 32 KB space, and both put working state at `80xx`, so the same
> number means different things in the two documents — `8034` is
> `PORT5_shadow` here and the **stepper phase index** in
> [`card-reader/BSK31-firmware.md`](../card-reader/BSK31-firmware.md);
> `8035` is `PORT2_shadow` here and the **live phase pattern** there. Never
> carry a bare address between the two.


| Range | Contents |
|---|---|
| `0x0000`–`0x7FFF` | ROM (`code` segment) |
| `0x8000`–`0x9FFF` | RAM (`ram` segment) |
| `0xE000`–`0xE007` | **LCD**, an HD44780 (16x2). `E000` = instruction register, `E001` = data register — see §10b |
| `0xF000` | **write-only control register**, shadowed at `0x8E10` — not declared as a segment (§10a) |

The firmware only *references* `0x8000`–`0x9FFF`, but the cold-start clear
at `305B` wipes `0x8000`–`0xDFFF`, stopping exactly below the LCD — which
fits the 32K SRAM being decoded across `0x8000`–`0xFFFF` with the LCD and
control register overlaid. See §10q. Part of this space holds **code copied
from ROM and executed in place** (§10), and all of it is
**battery-backed**.

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

## 6. How the ports are decoded — measured

**There is no external I/O decoder for the UART. It decodes its own port
select**, which is the entire point of the 1854's Mode 1.

| CPU (U201) | | UART (U231) | Signal |
|---|---|---|---|
| pin 19 **N0** | → | pin 16 | **RSEL** — register select |
| pin 18 **N1** | → | pin 23 | **CS1** |
| pin 17 **N2** | → | pin 35 | **CS3** |

The datasheet's timing notes give the selection logic:

> "Write is the overlap of TPB, **CS1, and CS3 = 1** and **/CS2**, RD/WR = 0"
> "Read is the overlap of **CS1, CS3**, RD/WR **= 1** and **/CS2 = 0**"

So **CS1 and CS3 are active HIGH** and CS2 is active low. The UART is therefore
selected whenever **N1 = 1 and N2 = 1** — which is exactly **ports 6 and 7**,
and nothing else.

**This confirms from hardware the port map derived from firmware in §6.** It
also explains why only ports 6 and 7 ever touch the UART: no other port number
can select it.

`N0` → `RSEL` then picks the register pair:

| Port | RSEL | Read | Write |
|---|---|---|---|
| **6** | 0 | receiver holding register | transmitter holding register |
| **7** | 1 | **status register** | **control register** |

### `OUT 7` writes the UART control register

Which makes one instruction worth singling out, at `0x0701`:

```
06FE  SEX R4
06FF  DIS   <- inline 0x44    X=4, P=4; interrupts OFF
0701  OUT 7 <- inline 0x32    UART CONTROL REGISTER = 0x32
0703  RET   <- inline 0x24    X=2, P=4; interrupts ON
0705  XIE
```

This is the **only** genuine UART configuration write in the image, and it is
performed with interrupts disabled.

**Decoded.** `Documentation/Datasheets/CDP1854A.PDF`, Table 4 — Control
Register Bit Assignment:

| Bit | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
|---|---|---|---|---|---|---|---|---|
| Signal | TR | BREAK | IE | WLS2 | WLS1 | SBS | EPE | PI |

`0x32` = `0011 0010`:

| Bit | Value | Meaning |
|---|---|---|
| 7 TR | 0 | transmit request not asserted |
| 6 BREAK | 0 | no break |
| **5 IE** | **1** | **interrupts ENABLED** |
| 4 WLS2 | 1 | \ |
| 3 WLS1 | 0 | — word length / stop bits, see below |
| 2 SBS | 0 | / |
| **1 EPE** | **1** | **even** parity |
| **0 PI** | **0** | parity **not** inhibited — parity is active |

WLS2=1, WLS1=0, SBS=0 gives **7 data bits, 1 stop bit**.

### The wire format is 7E1

> **7 data bits, even parity, 1 stop bit, interrupts enabled.**

Which fits the protocol exactly: everything on this link is **7-bit ASCII** —
`OK`, `RY`, `BR30`, `?CD007`, `?TE01`, CR and LF. A 7-bit word length is not a
coincidence, it is the natural choice for a text protocol, and it corroborates
the whole reconstruction in §6–§8 independently of the firmware.

**IE = 1 also matters**: the UART is configured to raise interrupts. That makes
it near-certain that the CPU's `/INTERRUPT` (pin 36) is driven by the 1854's
INT output (pin 13), which was listed as an open trace in §1a — and it supports
the model that **both** interrupt handlers are UART-driven (§6a).

### Baud rate is not in the control register

The 1854 has no baud generator: bit rate comes from the external **T CLOCK**
(pin 40) and **R CLOCK** (pin 17), each at **16×** the bit rate. To establish
the baud rate, either measure those pins or work out the divider chain from the
crystal (`X201`) through the `CD74HC4040E` counters (`U210`, `U212`) and the
`CD4521BE`. **Not yet determined.**

So anyone tapping pins 4 and 15 of `U230` (§6b) should set their analyser to
**7E1** and find the baud rate empirically.

> **Correction.** An earlier opcode scan reported `OUT 7` at `4997`, `7592` and
> `75A6` as well. All three are false: `4997` lies inside a
> `LoadStringForDisplay` descriptor (`01 00 10 <ptr> 0c 01 <ptr>`), and the
> other two were mis-aligned — the byte at `7592` is `0x61`, not `0x67`. The
> span around `7585` is a run of `OUT` instructions with X pointed at `0x8033`,
> writing one byte to several ports in turn.

### Ports 2 and 5 are output latches with RAM shadows

Established at `399D`:

```
399D  RLDI RB,8034
39A5  SEX RB          X = 8034
39A6  OUT 5           sends M(8034) to PORT 5; R(X) -> 8035
39A7  NOP / NOP       settling
39A9  OUT 2           sends M(8035) to PORT 2
```

`OUT` writes `M(R(X))` and then **increments** `R(X)`, so a single pointer
load serves both ports. The same idiom appears at `241D`, `2950` and `295E`.

| Port | Direction | Shadow |
|---|---|---|
| **2** | output | **`0x8035`** (`PORT2_shadow`) |
| **5** | output | **`0x8034`** (`PORT5_shadow`) |
| 6 | UART data | — |
| 7 | UART status / control | — |

**Their adjacency is load-bearing** — the two-port write depends on `8035`
following `8034` in memory.

This explains the read-modify-write pattern (`LDN` / `ORI` or `ANI` / `STR`)
that appears on these two bytes all over the ROM: they are shadows of
write-only latches, exactly like `CTRL_F000` and its shadow at `8E10`
(§10a). Around 26 sites load a pointer to `8034`, so **any `ORI`/`ANI` on it
is a hardware output change, not internal state.**

Known bits of `8034`: bit 0 toggled in timed patterns by
`play_toggle_pattern` and cleared by `proc_35a5` on return to idle; bit 2 an
enable; bit 6 toggled at `39A1`; bits 4–5 manipulated at `53A0`. **No bit has
been traced to a component.**

`399D` also performs a **hardware self-test**: it writes both ports, reads
back port 1, and jumps into the halt path of `standby_reboot_or_halt` if the
top two bits do not come back set. A failure there is fatal.

### Still to trace here

- **UART pin 4 (CS2)** — the remaining enable. If it is tied low the UART
  answers ports 6/7 unconditionally; if it is driven, something can gate the
  UART off the bus entirely.
- **Whether N0–N2 branch anywhere else.** `flush_output_latches` (§10u)
  shows ports **1, 3 and 4 driven as outputs** from the shadows at
  `8034`–`8037`, so the remaining question is which devices they reach, not
  whether they are decoded.

**Port 3 is an input port**, and **bit 6 is the hardware-strap sense line** —
see §10k. `read_hardware_straps` (`6173`) drives five lines through the low
bits of `M(8033)` and reads them back one at a time on `INP 3`, assembling a
5-bit hardware version in `M(8074)`.

## 6a. One UART, two owners

**The board has a single CDP1854, and the firmware has TWO complete service
routines for it**, selected by which interrupt vector is armed:

| Vector | ISR | Service | Buffers |
|---|---|---|---|
| `R1 = 28D8` | `5071` | inline, in the ISR | flat: `8022`–`8026` receive, `801A`–`8021` transmit |
| `R1 = 0699` | `05A6` → `dlc_uart_service` (`0A61`) | separate routine | **ring buffers**: `8B0B`/`8B0D`/`8B0F` receive, `8C1F`/`8C21`/`8C23` transmit, advanced by `04F0` |

`proc_06ba` swaps the vector with interrupts off, so **the UART is
time-multiplexed between the two peers by changing which handler owns it.**
The two buffer sets never touch.

`dlc_uart_service` (`0A61`) tests the same status bits — `SHR` for DA, `SHL`
for THRE, `ANI 0x08` for the framing-error bit — and files framing errors into
a third ring at `8B0F`, setting `M(8C1D)` on error. It is altogether more
careful than the card reader path, which fits a noisy modem link rather than a
short cable run.

### The router: U230

**Measured, both directions:**

| UART | | U230 | Switch |
|---|---|---|---|
| **SDO** (pin 25, transmit) | → | **pin 4** | **C common** |
| **SDI** (pin 20, receive) | → | **pin 15** | **B common** |

`U230` is an `MC74HC4053N` — a triple 2-channel analog multiplexer, i.e. three
independent SPDT switches each with its own control input. Per the TI
CD4053B datasheet:

| Pin | Signal |
|---|---|
| 1 | BY in/out |
| 2 | BX in/out |
| 3 | **CY in/out** |
| **4** | **C common out/in** |
| 5 | **CX in/out** |
| 6 | INH (disables all channels) |
| 9 | **control C** |
| 10 | control B |
| 11 | control A |
| 12 | AX in/out |
| 13 | AY in/out |
| 14 | A common out/in |
| 15 | B common out/in |

**Pin 4 is the C switch's COMMON terminal, not a channel input.** So the UART
transmit output arrives at the common and is steered to **one of two
destinations** — pin 5 (CX) or pin 3 (CY) — selected by pin 9.

**The UART is switched between two peers, in hardware, under software
control.** That is now measurement rather than inference.

**Transmit and receive are switched symmetrically**, as a matched pair:

```
                        C switch                        B switch
  SDO (TX) --> pin 4 ==<  pin 5 (CX)      pin 2 (BX) >== pin 15 <-- SDI (RX)
                        \  pin 3 (CY)      pin 1 (BY) /
                    control C = pin 9   control B = pin 10
```

**Measured: pins 9, 10 and 11 are all connected together.** So the three
switches are ganged — `U230` is wired as a **3-pole, 2-throw switch driven by
a single select line**. Transmit, receive and one further signal all move to
the same peer together, and cross-connection is impossible by construction.

That means the A switch (pins 12/13 → 14) is **not spare**: it is the third
wire of a 3-wire interface. A handshake is the obvious candidate, since the
1854 brings out CTS (pin 39) and RTS (pin 24).

Note the arithmetic: **three SPDT switches route TWO peers, not three.** So
`U230` selects between two of {optical reader, magnetic reader, DLC modem} and
the third must be reached another way — or is simply the unfitted one.

### U230 is the choke point for ALL serial traffic

Every byte the phone exchanges with a card reader or with DLC passes through
pins 4 and 15. **That makes them the ideal tap for a logic analyser**: probe
pin 4 for everything the phone transmits and pin 15 for everything it
receives, and the whole protocol reconstructed in §6–§8 can be checked against
live traffic — message framing, the `?`/`>` handshake, the `?XX` command
forms, and whether `CA`/`CB`/`TG`/`MN` ever actually appear.

### CPU pins worth tracing

In priority order, with what each would resolve:

| Pin | Signal | What it answers |
|---|---|---|
| **19, 18, 17** | N0, N1, N2 | **Highest value.** Trace to the decoder (likely `U208`, a 74HC139) and then its outputs: that gives the **device behind every port number**. The firmware uses `INP 1/2/3/6/7` and `OUT 4/5/6/7` and only ports 6/7 are identified. |
| **24, 23** | EF1, EF2 | The second link's clock source. If either reaches the `MC145443` modem, the DLC-over-modem reading is confirmed, and it settles `SCM1` vs `SCM2` from hardware. |
| **36** | /INTERRUPT | If it comes from the CDP1854's INT (its pin 13), **both** ISRs are UART-driven, which is strong support for the time-multiplexed-UART model. If something else raises it, the second link is not the UART at all. |
| **4** | Q | Tests the claim in §1a that Q clocks the `MC14094` chain. **Also worth checking whether Q reaches U230 pin 9** — if it does, the peer select is software-driven after all. |
| **22** | EF3 | Should reach J1 pins 15/37 (Hook). Would confirm the hook identification from hardware; currently it rests on firmware plus the J1 mapping. |
| **21** | EF4 | Unidentified. Only one `BN4` appears in the whole credit-card span. |

### What drives the select line — still open

This is now the single most valuable unknown, because it is the join between
the firmware and the hardware: whatever drives pins 9/10/11 is what the
firmware writes to choose a peer, and it should pair with the interrupt-vector
swap in `proc_06ba`.

**One candidate is already eliminated.** `SetByte_Array8dac` (`0331`) and
`ResetByte_Array_8dac` (`034B`) look like hardware bit-setters — `proc_06ba`
calls `SetByte_Array8dac(0x0E)` on its way into a DLC session — but they are
not. Both simply write `1` or `0` to **RAM** at `0x8DAC + index`, with a bounds
check at 30 entries:

```
0331  SMI 1E / LBDF 0A5C      index >= 0x1E -> error
0338  R6 = 8DAC ; R6 += index
0345  LDI 1 / STR R6          M(8DAC+index) = 1
```

So `0x8DAC`–`0x8DC9` is a **software flag array**, cleared in blocks by
`0721` and `ClearBytesAt_Array8dac` (`0A3E`), and it drives nothing directly.

Remaining candidates for the select line, in rough order of likelihood:

| Candidate | Why |
|---|---|
| `U202` **CD4099BE** addressable latch | the right part for individually settable control bits |
| an `MC14094BCP` output | five of them on the board, serial-loaded |
| `CTRL_F000` bit 0 or 1 | a 2-bit write-only control register already identified (§10a) |
| a port bit — note `OUT 7` appears at `0701`, `4997`, `7592`, `75A6` | direct, if port 7 writes reach a latch |

**Next measurements**

1. **Trace U230 pin 9 back to its driver.** That answers the question outright.
2. **U230 pins 5 and 3, and pins 2 and 1** — the two peers. Whether they reach
   the Optical Reader pins on J1 (16, 32, 35, 38, 40), the Mag. Reader pins
   (23, 25, 26, 44), or the modem, decides the serial-magnetic-reader
   hypothesis above.
3. **U230 pin 6 (INH)** — if driven rather than tied, the firmware can isolate
   the UART entirely.
4. **U230 pins 12/13/14** — which third signal rides with TX and RX.

### What this costs us

The dispatcher at `333D` reads `8022`/`8023`, filled only by the `5071` ISR.
So it still only sees traffic received **while the card-reader vector is
armed**. But with a shared UART, *"received in card-reader mode"* is not the
same as *"sent by the card reader"* — what is on the wire depends on external
routing, and the board carries M74HC4066 analog switches that could route the
UART between the reader connector and the modem.

> **Correction.** An earlier version of these notes declared `CA`, `CB`, `TG`
> and `MN` resolved as "reader-link codes this reader firmware never sends",
> on the argument that the receive buffer has exactly one writer. The premise
> is true but the conclusion was too strong: one writer does not mean one
> peer. **Those four, and `?CE007`, cannot be attributed on firmware evidence
> alone.** Settling it needs the board traced — specifically what the 4066
> switches route and what J1 carries.

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

`36C2` is **`account_one_unit_spent`**: it sets `M(88BD) = 0xAA` and bumps the
six-digit totalizer at `8526`, so that counter is the cumulative tally of card
units burned. `MO` calls it once per unit of difference between the value the
reader reports and the shadow at `806A`, `MZ` exactly twice, `X` and `Y` once
each. An earlier reading here guessed a **stepper single-step pulse**; that was
wrong — the stepper is in the reader's own ROM, on its own CPU — and §10ak lays
out the call pattern that makes it a unit count.

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

## 9a. The second link — "DLC"

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

### The peer is named `DLC`

`DLC_Comm`'s own prompt says so. Hebrew in this ROM is stored in *display*
order, so the bytes read right-to-left:

| Addr | Stored | Reads |
|---|---|---|
| `2FCF` | `? DLC -ל  תרושקת` | **תקשורת ל-DLC ?** — "Communication to DLC?" |
| `2FE9` | `תרפופשה  חנה  אנ` | **נא הנח השפופרת** — "Please replace the handset" |

So `DLC` is **the firmware's own name for the remote peer**, not an inference
from the function name. `DLC_Comm` is a maintenance or reporting session an
operator starts from the keypad: confirm, put the handset down, then hand off
to `proc_06ba`. What `DLC` stands for, and whether it is the trunk itself or
equipment behind it, is still unknown.

### Physical layer — not a UART

| Line | Use |
|---|---|
| **EF1** | counted in hardware by the 1806 counter — `05D7` `STPC`, `05DB` `LDI 0C`/`LDC`, then the counter-mode opcode `68 05` at `05DD`. **Note:** the Ghidra module decodes `68 05` as `SCM2`, while the RCA opcode table has `68 03` = SCM2 and `68 05` = SCM1. One of the two is wrong and it has not been checked against `Documentation/Datasheets/CDP1805AC.PDF`. Either way it is a counter mode counting an EF line |
| **EF3** | **the hook switch** — not a data line; see the correction below |
| **Q** | driven by `SEQ`/`REQ` — but see §1a: Q most likely clocks the five HEF4094 output shift registers, so it is probably **not** a link data line |

> **Correction.** An earlier version of this file listed EF3 as a data or
> carrier line sampled a bit at a time. **It is the hook switch.**
> `DLC_Comm` displays *"Please replace the handset"* and then loops on
> `setDF_to_EF3_inverted` until EF3 goes high, so **EF3 high = handset on
> hook**. The second-link ISR calls it at `05F4` and files the result in the
> `8DAC` flag array — that is hook *status*, not received data. A session
> requires the handset down, which makes sense: the subscriber must not be
> mid-call while the phone talks to the far end.
>
> That leaves **EF1 (hardware-counted) and Q (output)** as the actual data
> path, and the data direction of this link is therefore still not pinned
> down.

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
the peer is called **`DLC`** by the firmware itself; `DLC_Comm` reaches it
through `proc_06ba`; the session requires the handset on hook (EF3);
`PerformComm?` reads the same 1806 counter the ISR sets up in EF1-counting
mode.

**Not established:** what travels over it, in either direction. EF1 counting
and Q are the only candidate data lines left now that EF3 is identified as
the hook switch, and neither has been tied to a data format. Whether `DLC` is
the trunk itself or equipment behind it is also unknown.

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
| `CA`, `CB`, `TG`, `MN` | **not attributable** — see the correction in §6a; one UART is shared between both peers |
| `?CE007` (selector `08`) | **still open** — sent by the phone, no parser branch in the reader |
| `PerformComm?` (`1ABE`), `DLC_Comm` (`2F65`) | the second-link subsystem, documented above |
| Vectors `0699` / `067E` | **resolved** — the second link's prologue and epilogue |
| `8E0D` / `8E0F` | the second link's RAM-resident chained vector and its gate |

## 8a. The DLC frame format

The outbound record and its framing are now traced end to end.

### Relocated code

`07A3` does `memcpy(dest=9100, src=1CB7, len=067A)` — **1658 bytes of ROM
`1CB7`–`1F30` run at RAM `9100`–`9779`**, offset `+0x7449`. So that code
exists in two places and an edit to one copy does not affect the other. The
smaller payloads from `040D` and `3011` (§10) land *inside* this block,
overwriting its tail.

### `build_dlc_record` (RAM `910B`, ROM `1CC2`)

Composes a ~70-byte record at **`0x8D26`**. `SEX RB / RNX R9` sets the output
pointer. Fields in order:

| Off | Size | Source | Content |
|---|---|---|---|
| 0 | 1 | literal | `01` record type |
| 1 | 4 | ROM `13E8` | **`"DLCA"`** tag |
| 5 | 4 | literal | zeros |
| 9 | 11 | RAM `8501` | identifier, **zero bytes replaced by `'A'`** |
| 20 | 4 | RAM `8EFD` | |
| 24 | 2 | ROM `7BFA` | `04 30` |
| 26 | 2 | ROM `7BFE` | `7A AE` |
| 28 | 6 | literal | zeros |
| 34 | 2 | ROM `7C02` | `00 9E` |
| 36 | 2 | ROM `7C02` | the same constant **again** |
| 38 | 2 | literal | zeros |
| 40 | 2 | RAM `8DF4` | |
| 42 | 1 | RAM `8EFC` | |
| 43 | 1 | RAM `97A1` | mode |
| 44 | 5 | conditional | if `M(97A1)==2`: 4 bytes from `8DE8` + 1 from `8DF0`; else zeros |
| 49 | 2 | RAM `8DD7` | |
| 51 | 4 | RAM `8DD9`… | **copied, and the source zeroed as it goes** |
| 55 | 1 | RAM | |
| 56 | 4 | RAM | |
| 60 | 1 | RAM `8DC2` | |
| 61 | 9 | literal | nine `0x46` `'F'` filler |

**The read-and-clear at `91DB`–`91E6` is the telling detail.** You only zero a
counter once its value is captured for reporting, so this is an **accounting
record**, not merely an identity block.

The ROM constants sit just after the banner at `7BDF`, which also carries
author credits (`...I SHABTAI and BERENIKE SHAMSHON`, then `TAMAC18`). Their
meaning — version, build, checksum — is **not established**.

### The framer, `038D`

**Variable inline signature**, which is a genuine edge case for the analyzer
(§12), since it assumes one fixed signature per callee:

- `D == 0` → **three** inline bytes; the payload length is read *from memory*
- `D != 0` → **two** inline bytes; the payload length is an *immediate*

Either way `RA.hi` is the payload length. It then builds at `0x8C27`:

```
CC  00  <len>  <2 from 8DA7>  <2 mode>  <payload…>  <CRC hi> <CRC lo>  84
```

with **`len` = payload + 7**, counting from `0xCC` up to but not including the
CRC. `0xCC` opens the frame and `0x84` closes it.

### The CRC is CRC-16/MODBUS

`0837` seeds a 16-bit accumulator with **`0xFFFF`**, XORs each data byte into
the low half, does eight right shifts per byte, and XORs with **`0xA001`**
whenever the shifted-out bit is 1. That is reflected CRC-16-IBM —
**CRC-16/MODBUS**, no final XOR.

`8E6D` holds the high half (it takes the `0xA0` XOR), `8E6E` the low half.
The framer appends them **high byte first**, consistent with this firmware's
big-endian convention — but **note that most MODBUS implementations transmit
the CRC low byte first**, so this is byte-swapped relative to the usual wire
order. Worth knowing before checking a capture against a reference
implementation.

The routine refuses a length of zero or above `0xA0` (160), returning 2.

### The chain

```
proc_0889
  -> build_dlc_record (910B)   70 bytes at 8D26, counters read-and-cleared
  -> 038D with length 0x46     frame at 8C27: CC, len, header, payload,
                               CRC-16/MODBUS, 84
```

`0x8C27` sits immediately above the DLC transmit ring at `8C1F`/`8C21`/`8C23`
(§6a), which is consistent with the framer writing where the ring can pick it
up — **worth confirming rather than assuming.**

## 9. Idioms and pitfalls

### `RLXA R4` is a jump

See §3. The decompiler will not show it.

### `FormatCardDigitsToAscii` (`0x2AAB`) — the idiom at its worst

The clearest example in the image of why the `DIS`/`RET` idiom matters, and
one where **Ghidra's listing is wrong from the second instruction onward**.

```
2AAB  SEX R4
2AAC  DIS 0x34        X = R3, P = R4, interrupts OFF
2AAE  RLXA RC         RC = the inline argument, R3 advanced past it
2AB0  RLDI RD,8024
2AB4  RLDI R5,0003
2AB8  LDA RD / ADI 0x30 / STR RC / INC RC
2ABD  DBNZ R5,2AB8    three digits, each + '0'
2AC1  LDI 0 / STR RC  NUL terminator
2AC8  DEC RC x3       rewind
2ACC  SCAL R3,2ADA    ReplaceLeadingZerosWithSpaces
2AD0  SEX R4
2AD1  RET 0x24        X = R2, P = R4, interrupts back ON
2AD3  SRET R3
```

`P` is `R4` and `2AAB` is `SEX R4`, so `X == P` and the `DIS` takes its
operand from the instruction stream — the `0x34` at `2AAD`. Ghidra decodes
that byte as a `B1` branch instead, and **everything after it is phantom**
(`INP4` at `2AAF` does not exist).

The `DIS`/`RET` pair is doing **two** jobs, which is what makes it look odd:

1. It brackets a **critical section**. `8024`–`8026` are written by the card
   reader link (`proc_5032` at `5034`), so the three digits are snapshotted
   with interrupts off and cannot tear.
2. It switches `X` to `R3` and back to `R2`. After a `SCAL`, `R3` points at
   the inline argument — so `X = R3` is exactly what `RLXA` needs, and
   advancing `R3` past the argument is also what makes the `SRET` return to
   the instruction *after* it.

Callers pass a RAM buffer that a descriptor then points at, which is the
compose / describe / render layering of §10b: `6228` → `803F`,
`6246` → `803C`, `6256` → `804F`.

### `DIS` and `RET` change X too

A trap when hand-tracing the `X == P` idiom below: **`DIS` and `RET` load
both X and P from their operand byte**, not just P. At `551B` a `DIS` carries
inline `0xB4`, which sets `X = RB` and `P = R4` — so the `OUT` instructions
that follow are sending *memory through `R(X)`*, not inline bytes.

Anything that tracks only `SEX` when deciding whether `X == P` will misread
that whole region. Two of the hand disassemblies in this project got it wrong
before it was spotted.

### The `X == P` inline-operand idiom

When X equals the PC register, `OUT`/`INP`/`RET`/`DIS` take their byte from
the instruction stream and step over it. Those bytes are operands, not code.
Confirmed at `51A8` (`OUT 6` ← `0x3E`) and `51B1` (`RET` ← `0x24`). The same
idiom appears in the reader ROM at `0x1FF7`.

### Hebrew is encoded at `0xA0`, not `0xE0`

The Hebrew alphabet sits at **`0xA0`–`0xBA`**, which is ISO-8859-8 (or
CP1255) **minus `0x40`**. That is where this LCD's character generator keeps
Hebrew, so the firmware stores the codes the panel wants rather than a
standard codepage. This is the "non-standard Hebrew encoding" noted in the
author's blog post (§12a).

| Letter | Byte | | Letter | Byte |
|---|---|---|---|---|
| א | `A0` | | ם | `AD` |
| ב | `A1` | | מ | `AE` |
| ג | `A2` | | ן | `AF` |
| ד | `A3` | | נ | `B0` |
| ה | `A4` | | ס | `B1` |
| ו | `A5` | | ע | `B2` |
| ז | `A6` | | ף | `B3` |
| ח | `A7` | | פ | `B4` |
| ט | `A8` | | ץ | `B5` |
| י | `A9` | | צ | `B6` |
| ך | `AA` | | ק | `B7` |
| כ | `AB` | | ר | `B8` |
| ל | `AC` | | ש | `B9` |
| | | | ת | `BA` |

Space, digits, `'`, `.`, `:` and `-` are plain ASCII. **ASCII is not
offset** — which is why `OUT  OF  SERVICE` reads directly out of the ROM
while the Hebrew line beside it does not.

To read a string: add `0x40` to every byte in `0xA0`–`0xBA`, decode as
ISO-8859-8, then reverse (see below). Verified across **84 Hebrew runs** in
the image, including `68AD` = הטלפון אינו שמיש paired with
`OUT  OF  SERVICE`, `2FE9` = נא  הנח  השפופרת, and `6A12` =
מהד' תכנה: (the software-edition label behind the 4.30 version string).

### Byte order follows the consumer, not the language

Most Hebrew is stored **reversed relative to logical order**, because the LCD
is written left to right while Hebrew reads right to left, and
`LCD_RenderNextDescriptor` (§10b) preserves order: it does `LDA RE` forward
into `STR R7` forward. So a string on the direct LCD path must already be in
display order. Latin strings on the same path are stored forward
(`OUT  OF  SERVICE`, `INTL. CALLS ONLY`, `TEMPORARY  FAULT`, `Collect Card`
all read normally), and mixed strings keep each run in its own order.

**But the convention is not about the language — it is about the consumer.**
A string is stored in whatever order the code that reads it will produce.
`2AEB` holds לחצן  חיוג  חוזר in **logical** order, because its reader
reverses it:

```
26C4  RLDI RD,2AEB      source
26C8  LDA RD            read FORWARD
26C9  STXD              write BACKWARD, decrementing
26CA  DBNZ RC,26C8
```

`LDA` advances while `STXD` decrements, so the copy loop reverses the string
as it fills the buffer. The identical phrase is stored **again** at `6C18`, in
display order, for the direct LCD path — the same text held twice because two
consumers need opposite orders.

That is the same fill-down/read-up mechanism behind the command templates at
`0x3600` and behind `1AA9` = `=LANIMRET` (`TERMINAL=`), which previously had
only a plausible explanation. All three now have one cause.

Measured over the image, using the fact that a final-form letter
(ך ם ן ף ץ) can only **end** a word in logical order: of the runs where the
test is decidable, **23 are display order and 1 is logical** (`2AEB`), with
58 ambiguous — no final forms, or final forms at both ends — defaulting to
display order.

Those figures come from a one-off scan with a stricter pattern (minimum
length 6, at least 5 Hebrew bytes), **not** from `tools/dump_strings.py`,
whose looser default charset reports different totals on the same image.
They also sum to 82 rather than the 84 quoted above, which counted runs the
stricter scan rejected. Treat all four numbers as indicative.

`tools/dump_strings.py` implements this: it decodes the `0xA0` encoding,
guesses order per string, and marks the calls it cannot make.

```
$ python3 tools/dump_strings.py "ROM/TAMAC-18 V2.8 9513.bin" --chain 6591
6591  line 1 col  0 (cmd 80)  width 16  cmd 0C  dwell 01  next 659A
        text 68AD: 'הטלפון אינו שמיש'
659A  line 2 col  0 (cmd C0)  width  0  cmd 0C  dwell 01  next 0000
        text 68BE: 'OUT  OF  SERVICE'
```

### Strings are reached through descriptors

`LoadStringForDisplay` (`6E6B`) takes a pointer to a **descriptor**, not to
text. The descriptor then points at the characters, which is why fetching the
bytes at a `6E6B` argument shows a short binary record rather than a string.
The project's Ghidra database follows the convention `descXxx` for the
descriptor and `sXxx` for the text.

The nine-byte record is decoded in full in §10b: cursor column, field width,
text pointer, an LCD command, a dwell time, and a pointer to the **next**
descriptor. Descriptors chain, and `LCD_RenderNextDescriptor` (`279A`) walks
one link per call.

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

## 10b. The display: HD44780 and the display list

`LCD_RenderNextDescriptor` (`0x279A`, was `proc_279a`) is the bottom of the
display stack. It is **not** a `printf` — there is no format-specifier parsing
anywhere in it. It renders **one descriptor per call** to an HD44780-class
LCD and saves the successor, so repeated calls cycle messages across the
display.

### The controller is an HD44780

Three writes identify it, and all three are textbook HD44780 instructions:

| Address | Code | Byte written to `E000` | HD44780 instruction |
|---|---|---|---|
| `27BB` | `LDA RC / ADI 80 / SMI 01` | `0x80 \| (unkByte1-1)` | Set DDRAM Address, line 1 |
| `27E3` | `LDI C1 / SMI 01` | `0xC0` = `0x80 \| 0x40` | Set DDRAM Address, **line 2** |
| `27FF` | `STR R7` (descriptor `+5`) | typically `0x0C` | Display on, cursor off, blink off |

The two registers inside the `E000`–`E007` block are therefore:

| Address | Register |
|---|---|
| `0xE000` | instruction register. `STR R7` writes a command; `LDN R7` reads back the busy flag and the address counter. |
| `0xE001` | data register. The character loop does `INC R7` / `STR R7` / `DEC R7`. |

`HD44780.pdf` and `HD44100.pdf` are both in the local datasheets folder — the
'780 controller plus the '44100 segment-driver extender, which is the usual
pairing for a panel wider than the controller drives alone.

Writing `0xC0` as the wrap target means the panel has **2 lines**, and the
field width in the descriptor (below) is `0x0010`, so **16 columns**.

### The descriptor format

Nine bytes. Field names are kept from the annotations already in the Ghidra
project.

| Offset | Size | Name | Meaning |
|---|---|---|---|
| `+0` | byte | `unkByte1` | cursor position **+ 1**; emitted as `0x80\|(n-1)`, so `01` is column 0 of line 1 |
| `+1` | word | `strModifierLen` | **field width**. After this many characters the renderer emits `0xC0` and continues on line 2. `0x0010` = 16. |
| `+3` | word | `ptrString` | the text, NUL-terminated |
| `+5` | byte | `unkByte2` | an LCD command emitted after the text; also saved to `M(803B)` |
| `+6` | byte | `unkByte3` | **dwell** — reloaded into the `M(803A)` countdown, setting how many calls this message stays up |
| `+7` | word | — | **next descriptor**; `0000` ends the chain |

Checked against `desc` at `6672` = `01 00 10 6a 89 0c 01 67 9b`: column 0,
width 16, text at `6A89`, command `0x0C`, dwell 1, next descriptor `679B` —
the same chain the pointer walk at `3A0B` followed.

This supersedes the earlier guess that the record was `01 00 10 <text> 0c 01
<next>` with an unexplained second pointer. The "second pointer" is the next
descriptor, and the three loose bytes are a cursor column, an LCD command and
a dwell time.

### One descriptor per call, paced by the dwell byte

The entry guard is a countdown, not an argument check:

```
279F  LDX / LSZ / SMI 01 / STXD / LBNZ 27AF
```

`M(803A)` is decremented (floored at zero) and the routine **returns
immediately unless the result is 0**. So a descriptor's `+6` byte sets how
long it stays on screen before the next one is rendered.

The pointer test at `27AA` is a neat idiom worth recognising elsewhere:

```
27AA  INC RC
27AB  DBNZ RC,27B2
```

The `INC` and the `DBNZ`'s own decrement cancel, so this tests `RC` for zero
**without disturbing it**. A `0000` pointer ends the chain and the display
freezes on the last message until something rewrites `8038`.

### The persistent state block

`RD` is loaded with `803A` at entry and walked, so the structure straddles it:

| Address | Size | Contents |
|---|---|---|
| `0x8037` | byte | `R6` from the last render — the verify error count |
| `0x8038` | word | pointer to the **next** descriptor, big-endian |
| `0x803A` | byte | countdown; the renderer returns immediately until it reaches 0 |
| `0x803B` | byte | the last LCD command emitted (copy of `+5`) |

**These offsets must be traced by hand — Ghidra's references for the tail are
wrong.** It attributes the stores at `2808` and `280B` to `803A`, because it
cannot follow the X-indexed walk. `STXD` at `2807` leaves `RD` at `8039`, the
`RSXD RC` at `2808` writes `M(8039)` then `M(8038)` and decrements twice more,
so the `STXD` at `280B` lands on **`8037`** and `RD` finishes at `8036`.

The producer/consumer split is visible in the cross-references to `803A`:
`LoadStringForDisplay` (`6E6B`) writes it at `6E75`, and `3199`/`319F` writes
it too. Those seed the state block; `LCD_RenderNextDescriptor` consumes it —
that is the layering of the display stack.

A trap in reading the tail: the existing comment at `2802` reads "Load and
ignore `strdesc.unkByte3`", and the `LDXA` does look like a discard — but
`RLXA` at `2803` **does not touch D**, so that byte is still live when `STXD`
at `2807` writes it to `M(803A)`. It is the dwell reload. On the 1802/1806 it
is always worth asking which instructions leave `D` alone.

### `R6` is an LCD write-verify error count

After each **command** write the routine stashes the byte at `M(R2)` and reads
`E000` back:

```
SHL / LSNF / INC R6        bit 7 of the readback is the BUSY FLAG
SHR / XOR  / LSZ / INC R6  SHL-then-SHR masks bit 7 off, leaving the
                           ADDRESS COUNTER, XORed against the address
                           just written
```

So `R6` counts "controller still busy" plus "panel did not accept the
command", and it is handed back on the stack at `280A`. The character loop
deliberately skips the verify — its `LDN R7` at `27DD` is a read-and-discard
for timing only.

### Callers, and the power-up display self-test

All four call sites are `SCAL R3` (`68 83 27 9a`):

| Site | Context |
|---|---|
| `2793` | in `FUN_2500`, falls through to `280F` |
| `063C` | after `SCAL 3733` and `SCAL 7572` |
| `39CB`, `39CF` | **called twice in a row**, after `SCAL 6E6B` (`LoadStringForDisplay`), inside a `DBNZ RA` loop back to `399D` that ends in `LBR 29D8` = reboot |

The `39CB`/`39CF` pair is what the `R6` error count exists for: load a
message, render it twice, and on failure fall through to a reboot. That is a
**power-up display self-test**.

### Where formatting actually happens

Numbers are composed into RAM buffers before a descriptor ever sees them:

- `NumToString` (`4FDF`) for packed BCD
- `printNumberString_at_R7` (`586C`) for keypad-code digit strings

A descriptor then just points at the result. So the display path is three
layers: compose into RAM → describe (position, width, dwell) → render.

## 10c. Out of service: `RF.0` and the fault predicate

`Print_Out_of_Service` (`0x48A9`) is the terminal fault display. Thirteen
sites reach it, but **they are not thirteen independent health checks** —
twelve of them call the same predicate, and the thirteenth inlines one case of
it.

### `RF.0` is the global state / fault register

`is_out_of_service_state` (`0x744F`, was `FUN_744f`) tests `RF.0` against five
values and returns `D == 0` (Z set) when it matches:

```
744F  GLO RF / XRI 0x99 / LBZ 746A
7455  GLO RF / XRI 0x80 / LBZ 746A
745B  GLO RF / XRI 0x84 / LBZ 746A
7461  GLO RF / XRI 0x87 / LBZ 746A
7467  GLO RF / XRI 0x94          falls through, D = RF.0 ^ 0x94
746A  SEX R2 / SRET R3
```

So the out-of-service states are **`{ 0x80, 0x84, 0x87, 0x94, 0x99 }`**. Other
`RF.0` codes are tested elsewhere — `0x91` at `4949` and `495F`, and `FUN_48E8`
splits the range with `SMI 0x80` at `497F` — so `RF.0` is a general state byte
of which these five are the fault subset.

### The routine has multiple entry points

This is easy to miss and will mislead an xref reading. Entering part way
through tests only the remaining codes:

| Entry | Codes tested |
|---|---|
| `SCAL 744F` | all five |
| `SCAL 7461` | only `{ 0x87, 0x94 }` — used at `48DE`, inside `Print_Out_of_Service` itself |

Any reference landing on `7455`, `745B`, `7461` or `7467` is a deliberately
narrowed test. Check the entry address before assuming what a caller cares
about.

### The twelve paired sites

Each is `SCAL R3,744F` followed by a branch to `48A9`:

| Predicate call | Branch |
|---|---|
| `4606` | `460A` |
| `4644` | `4648` |
| `46A6` | `46AA` |
| `46BB` | `46BF` |
| `46D4` | `46D8` |
| `471F` | `4723` |
| `4752` | `4756` |
| `480B` | `480F` |
| `4820` | `4824` |
| `4846` | `484A` |
| `4953` | `4957` (in `FUN_48E8`) |
| `6F86` | `6F91` |

`6F91` is the odd one: it is `C0 48 A9` = **`LBR`**, with the polarity
inverted — `6F8A: LBNZ 449E` escapes when the state is healthy and falls
through to the display otherwise. Ghidra reports it as an unconditional
*call* because `48A9` is a function entry; it is a branch.

The thirteenth site, **`4930`**, does not call the predicate. It inlines a
single case:

```
492D  GLO RF / XRI 0x94 / LBZ 48A9
```

Three further callers of `744F` consume the result without going out of
service: `4B66` (in `FUN_4AF6`, the main idle loop), `276F` (in `FUN_2500`)
and `7642` (in `proc_7640`).

### What it displays

| | |
|---|---|
| `48B2` | `SCAL R3,6E6B`, inline arg `6591` — the fault message |
| `48D7` | `SCAL R3,6E6B`, inline arg `6451` — 16 spaces, blanking the display |

Descriptor `6591` = `01 00 10 68 ad 0c 01 65 9a`, a two-link chain:

| Desc | Cursor | Width | Text | Content |
|---|---|---|---|---|
| `6591` | `0x01` → DDRAM `0x00` (line 1) | 16 | `68AD` | הטלפון אינו שמיש |
| `659A` | `0x41` → `0xC0` (**line 2**) | 0 | `68BE` | `OUT  OF  SERVICE` |

Two refinements to the descriptor format (§10b) fall out of this:

- the 1-based cursor byte runs through **DDRAM space**, so `0x01`–`0x40` is
  line 1 and `0x41` upward is line 2. `0x41` emits exactly the `0xC0` that
  `LCD_RenderNextDescriptor` writes for its own wrap.
- **width 0 means do not wrap.** `DBNZ R5` would run 65536 times, so the NUL
  terminator ends the string instead.

### The rest of the routine

```
48A9  M(88C5) = 0
48B0  REQ                 drops Q
48B8  M(8036) &= 0xDF     clears bit 5
48C1  SCAL R3,6FB3
48C5  IDL loop: exit to 5F67 if M(8165) == 0, else spin while M(8129) != 0
48DE  SCAL R3,7461        narrowed re-test of { 0x87, 0x94 }
48E2  LBZ 4BD4, else LBR 4B65
```

The `M(8036) &= 0xDF` is worth noting: `8036` is a **flags byte in its own
right**, not merely the address where `LCD_RenderNextDescriptor`'s `RD`
pointer happens to stop (§10b).

### If you instrument this

The branches in are plain `LBZ`/`LBR`, so **no return address is left
anywhere**. A patch at `48A9` cannot recover which of the thirteen sites
failed without either recording it at the site or inferring it from `RF.0`
and the surrounding state.

## 10d. `RF.0` — the global state register

`RF.0` holds the phone's current operating or fault state. It is the pivot the
whole call-progress flow turns on: the out-of-service display, the retry
logic, the fault log and the main idle loop are all selected by its value.

### Bit 7 partitions the space

`497F` does `GLO RF / SMI 0x80 / LBDF 4AF6` — **every state `>= 0x80` leaves
for the main idle loop**. That split is load-bearing, and it sorts the map:

| Range | Meaning |
|---|---|
| `0x00` | idle / cleared |
| `< 0x80` | normal operating states |
| `>= 0x80` | abnormal — terminal faults and transients |

### Two chained predicates, both with multiple entry points

The abnormal range is read by two routines of identical shape, and their sets
are **disjoint**:

| Routine | Set | Behaviour |
|---|---|---|
| `is_out_of_service_state` (`744F`) | `{80, 84, 87, 94, 99}` | pure test; returns Z on match |
| `clear_state_if_transient` (`4D1C`) | `{81, 82, 83, 85, 93, 96, 98}` | **mutates** — `4D44: PLO RF` resets the state to 0 |

Both are chains of `GLO RF / XRI nn / LBZ <tail>`, which means **entering part
way through tests only the remaining codes**:

| Entry | Codes tested |
|---|---|
| `SCAL 744F` | all five |
| `SCAL 7461` | `{87, 94}` — used at `48DE` |
| `SCAL 4D1C` | all seven |
| `SCAL 4D22` | `{82, 83, 85, 93, 96, 98}` — used at `495B` |

Any reference landing mid-chain is a deliberately narrowed test. **Check the
entry address before assuming what a caller cares about** — this is the
easiest way to misread this subsystem.

### The setters, and an idiom that defeats scanning

States are written with `LDI nn / PLO RF`, but three sites use a two-way form
where `LSKP` sits between two loads, giving one routine two entry points:

```
7440  LDI 0x89
7442  LSKP          skips the next two bytes
7443  LDI 0x84
7445  PLO RF
7446  SEX R2 / SRET R3
```

| Site | Entry → value |
|---|---|
| `7440` / `7443` | `0x89` / `0x84` |
| `48A0` / `48A3` | `0x89` / `0x88`, then `LBR 4AF6` |
| `31D0` / `31D3` | `0x74` / `0x73` |

A scan for `F8 nn AF` **misses the first value of each pair**, because the
`LSKP` breaks the byte pattern.

### Meanings, from the messages each state selects

Several states name themselves: the per-state handler block at `4BEF`–`4D1C`,
reached from the main idle loop, tests `RF.0` and calls `LoadStringForDisplay`
with an inline descriptor. Reading the descriptor gives the state's meaning.

| State | Handler | Message |
|---|---|---|
| `0x26` | `62A5` | תקלה בקורא אופטי או בכרטיס תשלום — *fault in the optical reader or in the payment card* |
| `0x73`, `0x74` | setters `31D0`/`31D3`, `61DF` | אנא המתן... / `PLEASE WAIT...` |
| `0x75` | `4BEF` | כרטיס זה אינו מאפשר חיוג לחו"ל — *this card does not permit international dialling* |
| `0x81` | `4C0E` | עקב תקלה נותקת / `TEMPORARY  FAULT` |
| `0x88` | `4C37` | יתרתך: / `CREDIT:` — displays the card balance from RAM at `804C` |
| `0x94` | `48A9` | הטלפון אינו שמיש / `OUT  OF  SERVICE` (§10c) |
| `0xA9` | `2A78` | שיבוש בקריאת כרטיס — *corruption reading card* |

**Two traps when doing this sweep.** A naive "nearest `LoadStringForDisplay`"
search produces false pairs:

- the six states in the `4D1C` chain all appear to select `6741`, but that
  descriptor belongs to the code *after* the predicate, reached by `LBR 4D49`
  from `show_fault_log`. The chain entries select nothing.
- the setters at `48A0`/`48A3` sit immediately before `Print_Out_of_Service`,
  so `0x88` and `0x89` look like out-of-service codes. They are not — both
  branch to the main idle loop, and `0x88`'s own handler at `4C37` displays
  the credit balance.

Only associations where the state's **own handler** loads the descriptor, or
where two independent sites agree, are listed above.

### The map

| Value | Role | Setters |
|---|---|---|
| `00` | idle / cleared | `4901`, `494F`, `4988`, `4D44`, `5FD4`, `47F7`, `4D05`, `4DB1`, `62BC`, `777A` |
| `54` | normal operating state | `289C` |
| `73`, `74` | **please wait** | `31D3`, `31D0`, `61DF` |
| `75` | **no international calls** | `4710` |
| `25` | normal — tested only (`464B`, `4759`) | not seen written by `LDI`/`PLO` |
| `26` | **optical reader / payment card fault** | not seen written; cleared at `62BB` |
| `80` | out of service | `4AED`, when a counter reaches `0x19` |
| `84` | out of service | `7443`, `269A` |
| `87` | out of service | `287B` |
| `94` | out of service | `286E` |
| `99` | out of service | `284A` |
| `81` | **temporary fault**, auto-cleared | `32D5` |
| `82`, `93`, `96`, `98` | transient, auto-cleared | `2DC3`, `2DC9`/`34DC`, `34B6`, `515E` |
| `83`, `85` | transient, auto-cleared | **tested but never `LDI`-written** |
| `88` | **show credit / balance** | `48A3` |
| `A9` | **error reading card** | `33B5` |
| `86`, `89`, `90`, `95`, `97` | abnormal, in neither predicate set | `4A51`, `7440`/`48A0`, `378A`, `35F5`, `2776` |
| `91` | **special** — see below | **never `LDI`-written** |

### `0x83` and `0x88` are written through `RE` at `7384`

```
7377  LBNZ 7389         skipped entirely when M(8144) is non-zero
737A  LDI 0x88
737C  LSKP              two-way entry, as at 7440 / 48A0 / 31D0
737D  LDI 0x83
737F  PLO RE            RE.0 = 0x88 or 0x83
7380  GLO RF / XRI 0x91
7383  LSZ               0xCE - skip WHEN the state IS 0x91
7384  GLO RE / PLO RF   RF.0 = RE.0
```

**Correction.** An earlier version of this section read `7383` as `LSNZ` and
concluded that `0x91` is a pending state resolved *into* `0x88` or `0x83`.
The byte is `0xCE`, which is **`LSZ`** (`0xC6` is `LSNZ`), so the sense is
the opposite: when `RF.0` already is `0x91` the copy is **skipped**, and the
write happens only when the state is something else. Ghidra's own listing
says `LSZ`; the error was in reading it.

So this site does not explain where `0x91` comes from. It explains where
`0x83` and `0x88` come from, and `0x91` acts as a **guard** suppressing the
overwrite. Where `0x91` itself is set is still open.

Every *other* `GLO Rn / PLO RF` a byte scan reports is the operand byte of an
`LDI` read at the wrong alignment: `269B` "GLO R4" is the `0x84` of
`LDI 0x84` at `269A`, `2777` "GHI R7" is the `0x97` of `LDI 0x97` at `2776`,
and so on down the list.

### Values that are tested but never produced

`0x25` and `0x26` **arrive from the card reader** as `BR` fault codes — see
§10m, where the `BR` handler packs the reader's two digits and does
`PLO RF`. `0x85` and `0x91` are equality-tested but have **no
`LDI` anywhere in the image** — `LDI 0x85` in particular occurs zero times.
`0x91` is explained above (it must be set by an interrupt handler or restored
from battery-backed RAM). The others are either set the same way or are
vestigial, and since all three builds differ only in configuration data
(§1a), comparison cannot settle it.

**`0xAA` is not a status code.** `LDI 0xAA` occurs 28 times and **every one is
followed by `STR Rn`**, never `PLO RF`. It is a RAM sentinel — `M(807A)`,
`M(816C)`, `M(8134)`, `M(807C)` — and easy to mistake for a state because it
sits beside state handling everywhere.

**`0x50` is probably not a state.** It appears only at `628D` as
`GLO RF / SMI 0x50` — a magnitude comparison, not an equality test — so it
reads more like a threshold than a member of the set.

`0x91` is tested six times (`283E`, `4949`, `495F`, `4C8E`, `7380`, `75D8`)
and never assigned by an immediate, so it arrives from a register — most
likely set by an interrupt handler. `wait_and_triage_state` clears it at
`494F` and gates its hook-switch retry arm on it. Worth pinning down.

### Caveat on method

`RF.0` is a register, so **it cannot be cross-referenced**. This map comes from
byte scanning validated against decoded instruction streams. Scans over this
image are unreliable in data regions — the run of `RLDI RF,68CF` at `6B7A` is
a pointer table being misread, and `F8 93 AF` at `2DC9` reads equally well as
`GHI R3 / PLO RF` at the wrong alignment (§9).

Every value above was checked against a decoded stream, but **the setter list
is a lower bound**: assignments through `GHI`/`GLO Rn` → `PLO RF` are not
enumerated.

## 10e. `wait_and_triage_state` (`0x48E8`) and the fault log

### `wait_and_triage_state` — beep, wait, triage

Entered **by a branch, not a call** — `45D3` is `LBR 48E8`, which Ghidra
reports as an unconditional call only because `48E8` is a function entry. It
never returns; there is no `SRET` in it. The guard upstream is:

```
45CC  LDN R6 / XRI 0x10 / LBZ 45D6     M(8030) == 0x10 -> normal path
45D2  STR R6                           else flip bit 4 back into M(8030)
45D3  LBR 48E8                         and come here
```

What it does:

| Step | |
|---|---|
| `48E8` | `M(8034) \|= 0x04` — PORT5 shadow, opens the audio path |
| `48F1` | `SCAL 6FFF` → `play_toggle_pattern` (`3AA8`) with inline arg `3AA0` — **an audible beep** |
| `4901` | `PLO RF` with D still 0 — **clears the state** |
| `4902` | `M(8034) &= ~0x04` — closes the audio path; the pair around the tone is a pulse |
| `491A` | `M(8131) = 30`, `M(8139) = 4` — two timers |
| `492C` | `IDL` wait loop, polling the timers |
| `492D` | `GLO RF / XRI 0x94 / LBZ 48A9` — the one out-of-service site that **inlines** the test instead of calling `744F` |
| `4953` | `SCAL 744F` → the full check |
| `495B` | `SCAL 4D22` → `clear_state_if_transient`, narrowed entry |
| `496A` | `SCAL 0100` — samples **EF3, the hook switch**, returning it in DF |
| `4975` | arms a retry: `M(816C) = 0xAA`, `M(812F) = 50` |
| `497E` | `GLO RF / SMI 0x80 / LBDF 4AF6` — the bit-7 partition |

Three exits:

| Target | Condition |
|---|---|
| `48A9` `Print_Out_of_Service` | `RF.0` is a terminal fault |
| `4AF6` the main idle loop | `RF.0 >= 0x80` |
| `5F67` `show_fault_log` | `M(8165) == 0` |

`Print_Out_of_Service` makes the **same `M(8165)` test** at `48C6`, so
`M(8165)` is what decides between sitting on the fault message and dropping
into the fault-log readout.

**Not established:** what `M(8030)` means, and therefore what condition routes
here rather than to `45D6`. The timers (`8131`, `8139`, `812F`) and flags
(`8149`, `816C`, `8165`) are known only by address. Treat the routine's
purpose as structural — beep, wait, triage — not as a named feature.

### `show_fault_log` (`0x5F67`)

This is the diagnostic readout — the "reports faults to the service centre"
capability from the technician story in §12a, at least its local half.
Identified from what it displays:

| Call | Descriptor | Text |
|---|---|---|
| `5FE5` | `643F` | two lines of dots — a cleared screen |
| `5FFA` | `670B` | `698A` = תקלה מס':  -בדוק (*Fault no.: - check*) |
| `6052` | `65F4` | `699B` = אין תקלות נוספות (*No further faults*) |

It drives `get_key_with_timeout` (`5EEB`, inline arg `05`) between entries and
only advances on key code `0x0C`.

The log is a table in battery-backed RAM, walked at `600D`–`604B`:

```
600D  RLDI RB,840A           first entry
6011  LDN RB / ANI 0x7F      code = low 7 bits; 0 means empty, skip
6017  RLDI RD,6069           code table base
601B  LDN RB / ANI 0x7F / SMI 0x46
6020  RD += (code - 0x46)    so valid codes start at 0x46
6029  LDN RD                 the table entry for this fault
6031  SCAL 5E8B              format / display
6036  SCAL 5EEB, arg 05      wait for a key
603E  XRI 0x0C / LBNZ 6035   only 0x0C advances
6043  INC RB / INC RB        2 BYTES PER ENTRY
6045  GLO RB / SMI 0x42      stop at 8442
604B  LBNF 6011              loop
```

So the fault log occupies **`840A`–`8441`, 28 entries of 2 bytes**, with bit 7
of the first byte a flag, the low 7 bits the fault code, and codes indexing a
table at `6069` biased by `0x46`.

**Resolved:** the `6069` table is decoded in §10f — packed BCD fault numbers
for codes `0x46`–`0x78`. The second byte of each log entry is decoded in
§10i — an occurrence counter with a threshold, incremented by `5E1B`. The Hebrew technician strings nearby — `69D4` קוד טכנאי:
(*technician code*), `69DF` קוד מכלול (*module code*), `69F0` הכנס קודי הודעות
— belong to this subsystem and are the obvious next thread.

## 10f. The keypad tables

Three tables define one index space. The matrix table establishes it, and two
parallel tables render an index either as ASCII or as an internal code.

### `0x2400` — the 3×4 matrix, in column-major order

Two halves of 12 bytes:

```
2400:  01  04  07  0B  | 02  05  08  0A | 03  06  09  0C    scan index
240C: '1' '4' '7' '*'  |'2' '5' '8' '0' |'3' '6' '9'  01    matching ASCII
```

So the keypad is the usual layout, and the index space is:

| Index | Key |
|---|---|
| `01`–`09` | digits 1–9 |
| `0A` | `0` |
| `0B` | `*` |
| `0C` | `#` |

`#` has no printable form in this character set and is carried as **`0x01`**
in both ASCII tables (`2417` and `2699`).

### `0x268D` — index → ASCII

Thirteen bytes, loaded by `RLDI R5,268D` at `266D`:

```
268D: 00 '1' '2' '3' '4' '5' '6' '7' '8' '9' '0' '*' 01
```

Used where a key must be displayed or dialled.

### `0x2D00` — index → internal key code

Sixteen bytes, a **permutation of `0x10`–`0x1F`**:

| idx | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| val | `1D` | `11` | `12` | `13` | `14` | `15` | `16` | `17` | `18` | `19` | `10` | `1E` | `1F` | `1A` | `1B` | `1C` |

giving a uniform code space:

| Code | Meaning |
|---|---|
| `0x10`–`0x19` | digits 0–9 (`0x10` is `0`, so code = `0x10 + digit`) |
| `0x1A`–`0x1D` | the function keys — redial, card change and so on, per the strings at `6C18` לחצן חיוג חוזר, `6C07` לחצן החלפת כרטיס, `6BB2` חוגת לחיצים |
| `0x1E` | `*` |
| `0x1F` | `#` |

**How it is indexed, and why nothing cross-references it.** The table starts
at low byte `0x00` and has exactly 16 entries, so the index *is* the low
address byte. The code builds the pointer arithmetically rather than loading
it, which is why a search for a `2D00` pointer finds nothing:

```
2B4D  LDI 0x2D / PHI RE      page
2B50  LDI 0x00 / ADD / PLO RE   index from M(X)
2B5A  LDN RE                 table[index]
```

The result is stored into a record through `R7`, and the surrounding code
`ORI 0x10`s neighbouring bytes (`2B57`, `2B75`) — the same `0x10` bias the
codes carry.

**Not established:** what record the block at `2B00`–`2B6F` is building. It
ends in `LBR 73BC`, which is only `STR RA / SEX R2 / SRET R3` — a generic
"store this byte through `RA`". The constants it writes (`0x2E`, `0x42`,
`0x67`, `0x15`, `0x04`) are not fault-log codes: the log at `840A` is written
at `3F83`, `3F8A` and `5BDE`, never through `73BC`.

### `0x6069` — fault code → displayed fault number

A bonus from the same sweep, closing the question left open in §10e. 51 bytes,
`6069`–`609B`, **packed BCD**, indexed at `601B`–`6029` in `show_fault_log` as
`RD = 6069 + (code - 0x46)`, so it covers codes `0x46`–`0x78`.

Two checks confirm it: every byte has both nibbles `<= 9`, and the run ends
exactly where code resumes at `609C` (`E2` = `SEX R2`). A zero entry means the
code is unused.

| Code | № | Code | № | Code | № | Code | № |
|---|---|---|---|---|---|---|---|
| `46` | 14 | `55` | 23 | `63` | 24 | `73` | 41 |
| `48` | 43 | `57` | 12 | `64` | 40 | `74` | 41 |
| `49` | 43 | `58` | 14 | `65` | 21 | `75` | 38 |
| `50` | 14 | `59` | 20 | `66` | 13 | `76` | 39 |
| `51` | 14 | `60` | 23 | `67` | 19 | `77` | 23 |
| `52` | 33 | `61` | 35 | `68` | 36 | `78` | 42 |
| `53` | 34 | `62` | 40 | `69` | 37 | | |
| `54` | 23 | | | | | | |

This is the number shown in תקלה מס':  -בדוק (*Fault no.: - check*). Several
codes share a displayed number (14, 23, 40, 41, 43 each appear more than
once), so the mapping is many-to-one — the displayed number identifies a
**class** of fault, not the code.

## 10g. The `8119` buffer and its three routines

A 25-byte RAM buffer at **`8101`–`8119` that grows downward**, with two
pointer cells just above it. Three routines own it, and the single caller
uses all three in sequence.

| Routine | Address | Was |
|---|---|---|
| `InitBuffer8119` | `1A26` | `FUN_1a26` |
| `LoadBuffer8119` | `2C81` | `FUN_2c81` |
| `WaitForBuffer8119` | `2C6E` | `FUN_2c6e` |

### `InitBuffer8119` (`1A26`)

```
1A26  RLDI RC,8119 / RLDI RA,0019
1A31  STXD / DBNZ RA,1A31     zero 0x19 bytes downward: 8101..8119
1A5F  RLDI RC,811B
1A63  LDI 0x19
1A65  STXD                    M(811B) = 0x19
1A66  STR RC                  M(811A) = 0x19
```

Both pointers start at `0x19`, the low byte of the buffer's top, so **equal
pointers mean nothing pending**. It also clears `M(814C)`, `M(812B)`,
`M(8182)`, sets `M(814B) = 0x80` and `M(813A) = M(8513) - 1`.

### `LoadBuffer8119` (`2C81`)

```
2C81  RLDI RD,8119    destination, the TOP
2C86  LDA RC          read source FORWARD
2C87  LBZ 2C8E        first zero ends it, and is not copied
2C8A  STXD            write BACKWARD
2C8B  LBR 2C86
2C8E  GLO RD / RLDI RD,811A / STR RD    M(811A) = where it stopped
```

`source[0]` lands at `8119`, `source[1]` at `8118`, and so on — the
`LDA` forward / `STXD` backward pairing from §9. It always starts at `8119`
regardless of the current pointer, so it **loads** the buffer rather than
appending.

### `WaitForBuffer8119` (`2C6E`)

```
2C6E  IDL
2C70  SCAL R3,729E    the periodic service pass, every iteration
2C74  RLDI R6,811A / SEX R6
2C79  LDA R6          D = M(811A), R6 -> 811B
2C7A  XOR             D ^= M(811B)
2C7B  LBNZ 2C6E       loop while they differ
```

The **same idiom appears at `3B5F`**, so "compare `M(811A)` against `M(811B)`
and loop" is a reusable drain check rather than something specific to this
call site. `FUN_729E` is not a transmit routine — it is the general periodic
supervision pass (§10d, it holds the `0x91` resolution at `7380`), called
here to keep the machine serviced while blocked.

### The only caller

```
19DA  SCAL 1A26       init
19DE  RLDI RC,1A81    source
19E3  SCAL 2C81       load
19E8  SCAL 2C6E       wait
19ED  SCAL 6FA5
```

The source at `1A81` is `01 03 01 00`, so **only three bytes are copied** —
the copy stops at the `00` at `1A84`. This sits in the `PerformComm`
neighbourhood that also holds the backwards `=LANIMRET` (`TERMINAL=`) at
`1AA9` and the `"\r.\rD1\r34011503\r"` script bytes at `1A86`.

### What is not established

**Where the pointers advance, so that the wait can ever end.** Every *direct*
write to `811B` — `1A65`, `3B20`, `7054`, `45F1` — only resets it to `0x19`.
The one site that moves `M(811A)`, at `25D4`, *decrements* it with a wrap
from `0x01` to `0x15`:

```
25D4  RLDI R7,811A / RLDI R8,8119
25DC  LDN R7 / PLO R8 / PLO RA     form the pointer 81:M(811A)
25DF  XRI 0x01 / LBZ 25E8
25E4  LDN R7 / SMI 0x01 / LSKP
25E8  LDI 0x15
25EA  STR R7
```

That reads like a ring over `8101`–`8115` and does not obviously converge on
`0x19`. So either an interrupt path advances a pointer through a register
alias that leaves no cross-reference on `811A`/`811B`, or `25D4` belongs to a
different flow reusing the same cells. **Do not infer the direction of
consumption from `WaitForBuffer8119` alone** — and in particular, do not
assume the downward fill means the bytes come out reversed until the consumer
is found.

What *is* settled is that `M(811A)` is a pointer low byte: both `25D4` and
`2652` combine it with a `0x81` page to form an address.

## 10h. `GuardOrAbortCaller` (`0x5DF9`) — a non-local return

The fault-reporting path has a guard that, when its condition fails, **does
not return to its caller at all**. It makes the caller return `0xFF` to the
caller's caller, skipping whatever remained. A decompiler renders it as an
ordinary return, so this is one to recognise by hand.

```
5DF9  RLDI RC,807C
5DFD  LDN RC / XRI 0xAA / LBZ 5E19     M(807C) == 0xAA -> normal return
5E03  RLDI RC,8169
5E07  LDN RC / XRI 0x55                D = M(8169) ^ 0x55
5E0B  SCAL R3,0100                     samples EF3, the HOOK SWITCH
5E0F  ADCI 0x00                        D = D + DF
5E11  SHR                              DF = bit 0 of that
5E12  LBDF 5E19                        set -> normal return
5E15  RLDI R3,5DF4                     else PATCH THE RETURN ADDRESS
5E19  SRET R3
```

### How the unwind works

Under the `SCAL` convention `R3` holds the return address and the caller's
old `R3` sits on the stack. `SRET` jumps to `R3` *and* pops the saved value.
So `RLDI R3,5DF4 / SRET R3` lands at `5DF4` with `R3` now holding the
**caller's** return address — and `5DF4` is the "return `0xFF`" tail of the
routine immediately above:

```
5DF1  LDI 0x00 / LSKP     return 0
5DF4  LDI 0xFF            return 0xFF   <- the redirect target
5DF6  SEX R2 / SRET R3
```

Its `SRET` therefore returns `0xFF` one level further out. Two frames unwind,
and a shared epilogue is reused as a "return failure" exit.

### `0100` does not clobber D

Worth stating because it looks as though it must. `SHR / B3 / ORI 0x80 /
RSHL` restores `D` exactly and leaves `DF = NOT EF3` — a clean "sample the
hook switch into `DF`, preserving `D`". That is why the `ADCI 0x00` at `5E0F`
can still be operating on `M(8169) ^ 0x55`.

### Context

All three callers are inside `FUN_5BFD`, at `5C5B`, `5C60` and `5C91`,
bracketing a call to `CopyCodeTo9733AndJump` (`026A`) at `5C6D`. `FUN_5BFD`
is reached from `FUN_5B5B` and `FUN_5B65`, and `FUN_5B65` is what writes the
fault log at `840A`. So this is the abort path of fault reporting.

## 10i. `5E1B` — the fault-log counter, and what the second byte holds

`5E1B` takes **three inline argument bytes**, signature `b,b,b`. The reads are
scattered and conditional — `LDA R3` at `5E20`, `5E36`, `5E41` and `5E55`,
plus bare `INC R3` skips at `5E28` and `5E5A` — but every path consumes
exactly three:

| Path | Reads | Total |
|---|---|---|
| `D == 0` | `5E20`, skip `5E28`, skip `5E5A` | 3 |
| `D != 0`, `M(8167) & 0x20` | `5E20`, `5E36`, `5E55` | 3 |
| `D != 0`, else, equal | `5E20`, `5E41`, `5E55` | 3 |
| `D != 0`, else, less | `5E20`, `5E41`, `5E55` | 3 |
| `D != 0`, else, greater | `5E20`, `5E41`, skip `5E5A` | 3 |

So it is variable in *which* bytes it reads but uniform in how many, and one
callee signature covers it. It is now declared in
`cdp1806/data/inline_args.txt`.

**Until it is declared, the argument bytes disassemble as code.** At `5C4F`
they read as `DEC R7 / LDN R5 / OUT 1` — inventing a **port 1 access that
does not exist**. Given that ports 1, 3 and 4 are still unidentified (§6),
that is exactly the kind of false lead to guard against.

### What it does

```
5E1B  PLO RC           selector passed in D
5E1C  RLDI R8,8442
5E20  LDA R3 / PLO R8  arg1 is a LOW BYTE, so R8 = 84:arg1
...   increment M(R8), saturating; compare against arg2; on reaching the
      threshold set M(97A6) = 6
5E54  DEC R8 / LDA R3 / OR / STR R8    OR arg3 into the byte BELOW
5E67  LDN R8 / ANI 0x80 / STR R8       otherwise keep only bit 7
```

### The call sites answer an open question

| Site | Args | Target |
|---|---|---|
| `5C4F` | `27 05 61` | `8427` |
| `5C89` | `13 01 51` | `8413` |
| `5DDD` | `3b 03 75` | `843B` |
| `5DEA` | `3d 02 76` | `843D` |

All four are **odd** offsets from `840A`, so each addresses the *second* byte
of a fault-log entry — the log being `840A`–`8441`, two bytes per entry,
walked at `600D`–`604B` in `show_fault_log` (§10e).

**These four are not all of them.** A byte scan finds **30** `SCAL 5E1B`
sites, sixteen of them in `5C0F`–`5DEA`. Every one of the 30 has an **odd**
first argument, so the "second byte of a log entry" reading holds across all
of them — but any statement resting on there being four sites does not.

So the second byte, left open in §10e, is a **counter with a threshold**. The
`DEC R8` / `OR` then writes a bit into the first byte, which is the fault
code. **Reaching the threshold is what raises the fault** — the firmware
counts occurrences before logging, which is why a transient glitch does not
produce a fault entry.

## 10j. `show_version_and_comm` (`0x609C`) — the technician identity page

Sits immediately after the fault-number BCD table at `6069`–`609B`, so the
listing here only makes sense once that table is marked as data.

### Screen 1 — model and software version

```
609D  SCAL 6E6B, desc 662A
        6A01 = "    טמ"כ  18    "   TAMAC-18
        6A12 = "מהד' תכנה:    . "   software edition:
60A6  SCAL 4FDF (NumToString), inline args 804C, 7BFA, 0001
60B0  M(804E) = '.'
60B8  SCAL 4FDF, inline args 804F, 7BFB, 0001
60C2  M(8051) = 0                 terminator
60C9  if M(804C) == '0' then ' '  blank a leading zero
60D7  SCAL 6E6B, desc 679B        679B draws LINE 2 from RAM at 804C
```

The version string is composed into `804C` as `XX.YY` from the two bytes
**`7BFA` and `7BFB`**, then drawn over the left of line 2 while the Hebrew
label already occupies the right. This is the display path behind the **4.30
software version**, and it independently confirms that `7BFA`/`7BFB` are
version bytes — the reading that replaced the earlier mistaken "money amount"
guess (§12).

### The unlock sequence

`5EEB` is `get_key_with_timeout` (inline arg `05`). Keys are dispatched at
`60EE`–`6109`:

| Key | Effect |
|---|---|
| `0x0C` | advance to screen 2 |
| `0x01` | `INC RD` — count presses |
| `0x03` | if `RD == 1`, take the reset path; else reset `RD` |

So **"1" then "3"** is an unlock:

```
610F  SEX R4
6110  DIS 0x24      X == P, so the 0x24 at 6111 is the OPERAND
6112  M(845D) = 0
6119  LBR 29D8      REBOOT
```

Another instance of the §9 idiom — Ghidra shows a phantom `DEC R4` at `6111`.

### Screen 2 — hardware version

```
611D  SCAL 6E6B, desc 663C
        6A23 = "מהד' חמרה:      "   hardware edition:
6125  SCAL 6173
6134  LDN RA from 8074
613B  SMI 0x0A / LBDF 613A          count tens into R6
6140  ADI 0x3A / STR R5             units digit, ASCII, at 803D
6144  GLO R6 / LSZ / ADI 0x10 / ADI 0x20 / STR R5   tens at 803C, or a space
614C  SCAL 6E6B, desc 6765          6765 draws LINE 1 from RAM at 803C
```

So **`M(8074)` is the hardware version**, rendered as two decimal digits.
`803C` is shared display scratch — `FormatCardDigitsToAscii` is called with
that same destination at `6246` (§10g neighbourhood).

### Then communicate

```
6153  wait for key 0x0C again
6161  SCAL 2F65     DLC_Comm, the operator-initiated DLC session
6169  SCAL 415E
616D  LBZ 77EF, else LBR 77F4
```

So the page ends by handing off to the DLC link — identity, versions, then
report.

**Not established:** what `6173` and `415E` do, and what `M(845D)` holds that
is worth clearing before a reboot.

### A dumper bug this exposed

`662A` first rendered as `טמ"כ 81`. Numbers run **left-to-right even inside
RTL text**, so a digit run has to be restored after the line reversal exactly
as a Latin word does — and `tools/dump_strings.py` was only matching
letter-initial runs. Uncorrected it would also have shown version 4.30 as
`03.4`. Fixed; the regex now matches `[A-Za-z0-9]+(?:[.'&/:-][A-Za-z0-9]+)*`.

## 10k. `read_hardware_straps` (`0x6173`) — and port 3

The hardware version is **sensed at run time**, not stored in the ROM.
`show_version_and_comm` calls this just before rendering `M(8074)` under the
label מהד' חמרה: (*hardware edition*).

```
6173  M(8074) = 0            clear the result
617A  RC = 8033              the drive field
617E  R6 = 8185              where INP 3 lands
6182  LDI 0x10               walking mask, bit 4 first
6184  STR R2                 keep the mask on the stack

      five passes, masks 10 08 04 02 01:
6185  LDN RC / ANI 0xE0 / STR RC   clear the LOW 5 BITS, keep the top three
6189  IDL                          settle
618A  LDN RC / OR / STR RC         set just this one bit
618D  IDL                          settle
618E  SEX R6
618F  INP 3                        D = port 3, and M(8185) = D
6190  ANI 0x40                     sense line is BIT 6
6196  SEX RD / LDN R2 / OR / STR RD    M(8074) |= mask
619B  LDX / SHR / LBNF 6184        carry out of 0x01 ends the loop
61A0  LDN RC / ANI 0xE0 / STR RC   release the drive lines
```

### Port 3 is an input port

Bit 6 carries the strap sense line. This is the first identification of one
of the three unknown ports (§6). The `INP 3` is verified against the raw
bytes (`6b` at `618F`) and `X` is `R6`, not `P`, so it is a true `INP` and
not an inline operand — worth checking explicitly, given how often that
distinction has mattered in this image.

The top three bits of `M(8033)` survive every `ANI 0xE0`, so bits 7–5 are
unrelated flags, consistent with `setFlags_8033_and_8036` and the `ANI 0xC0`
at `2B22`.

### The drive side is not established

`M(8033)` is **not** flushed to any port by the shadow-flush idiom. The only
such site in the whole image is `399D`:

```
399D  RLDI RB,8034
39A5  SEX RB
39A6  OUT 5        <- M(8034)
39A9  OUT 2        <- M(8035)
```

which relies on `OUT` auto-incrementing `X` and therefore covers `8034` and
`8035` only. The two `IDL`s in the scan loop suggest an interrupt handler
acts on the low bits of `8033` between the write and the read, but that
handler has not been found. **Do not assume `8033` is a port latch.**

## 10l. How the phone knows there is no card

**The phone has no card-presence input of its own.** Everything it knows
about the card comes from messages the reader sends over the serial link
(§6, §7). The chain is: reader message → `M(8062)` → `M(8069)` → the idle
display selector.

### The idle display selector (`0x2E17`)

```
2E17  RLDI RE,8062 / LDN RE / SMI 0x05 / LBZ 2E2E   M(8062) == 5 -> choose
2E21  RLDI RE,8069 / LDN RE / XRI 0x6A / LBNZ 2E2E  else, not the fault value
2E2B  LBR 2E6D                                      otherwise show nothing

2E2E  M(8191) != 0      -> 2E52, desc 6696
2E36  M(8501) == 0      -> 2E52
2E3E  M(81B5) == 0x42   -> 2E52
2E49  SCAL 6E6B, desc 66BA     <- THE INSERT-CARD PROMPT
```

`66BA` chains `66C3` (line 2 from the RAM buffer at `804C`) into `64D4`, and
`64D4` is a **four-link cycle that loops back on itself**, dwell `0x96` = 150:

| Desc | Text |
|---|---|
| `64D4` | הכנס  טלכרט   או |
| `64DD` | העבר כרטיס אשראי |
| `64E6` | `INSERT TELECARD/` |
| `64EF` | `SWIPE CREDIT CRD` → next = `64D4` |

That self-reference is what makes the prompt alternate Hebrew and English
indefinitely, paced by the dwell countdown in `LCD_RenderNextDescriptor`
(§10b). It is the clearest demonstration that the display list is a real
sequencer and not a one-shot.

### Where `M(8062)` comes from

In the `CA`/`CB`/`CO` handler at `33C5`:

```
33C6  SCAL PackCardNibbles(8060)   packs the digits at 8024/8025
33CC  SCAL 3886                    returns a POPCOUNT in D
33D4  SDI 0x07                     D = 7 - popcount
33DA  STR R9                       M(8062) = that
```

and the same handler sets the status byte from it:

| `M(8062)` | Result |
|---|---|
| 3 | `33EB`, checks a table at `850E` |
| 4 or 5 | `3415`: `M(8061) = 0xAA`, `M(8069) = 0xAA` |
| otherwise | `3406` → `3410`: `M(8069) = 0x69` |

### `M(8069)` is the card-session status

Four values, written **only** by reader-message handlers, and enumerated by
the chained `SMI 0x6A / ADI 1 / ADI 0x14 / SMI 0x55` ladder at `7336` in
`FUN_729E`:

| Value | Set at | Meaning |
|---|---|---|
| `0x55` | `313C` | set immediately before `SCAL 365C` (`send_reader_command`) — a command is outstanding |
| `0x69` | `3214`, `3410` | card data accepted |
| `0x6A` | `33BE` | in the **`BR` fault handler** |
| `0xAA` | `341C` | the `M(8062)` 4-or-5 outcome |

### What is inference

That **`M(8062) == 5` is the empty-reader signature**. The code path is
solid — `8062` of 4 or 5 yields status `0xAA`, and `8062 == 5` is what lets
the selector reach the insert-card prompt — but *why* an empty reader should
yield `7 − popcount == 5`, i.e. two bits set, has not been verified against
the reader itself. Confirming it needs the reader's reply with an empty slot.

### A dead branch worth knowing about

`46AE` also loads `64D4`, but it is **unreachable**: `469E` calls `75BB`,
which is `LDI 0xFF / SEX R2 / SRET R3` and therefore always non-zero, so the
`LBNZ 46BA` at `46A2` is always taken and `46C3` shows `650A`
("כרטיס טלכרט בלבד / `TELECARD    ONLY`") instead. Since no byte of code
differs between the three builds (§1a), that branch is dead in all of them.

## 10m. Reader fault codes become `RF.0`

`PackCardNibbles` (`36B0`, was `FUN_36b0`) takes its destination as a
**2-byte inline argument**:

```
36B0  SEX R3          X = R3, which after a SCAL points at the inline args
36B1  RLXA R8         R8 = dest, R3 advanced past it
36B3  RLDI R9,8024
36B7  LDA R9 / SHL x4 / SEX R9 / OR    pack M(8024)<<4 | M(8025)
36BE  STR R8
```

Declared as `36b0  p` in `cdp1806/data/inline_args.txt`. Undeclared, `33A5`
decodes as `GLO R0 / IDL` — and **an `IDL` inside a card-reader message
handler would hang the dispatcher**, which is the tell that those bytes are
data rather than code.

That matters beyond tidiness. In the **`BR` (fault) handler** at `33A0`:

```
33A1  SCAL PackCardNibbles(8000)
33A7  PLO RF                      <- RF.0 = the packed reader fault code
33A8  LBZ 33BF
33AB  if M(8069) == 0xAA then RF.0 = 0xA9   (error reading card)
33BE  M(8069) = 0x6A
```

**So a reader `BRxx` fault code becomes `RF.0` directly.** The reader's BR
suffixes run **01–49** (its own table at `1198`, §`card-reader/`), which is
exactly where the two status codes `0x25` and `0x26` sit — the ones tested in
this image but **never written by any `LDI`** (§10d). They arrive over the
wire.

This also explains the shape of the whole status space: every code is valid
packed BCD **except `0xA9`**, which is deliberately outside BCD so the
internally generated "error reading card" cannot collide with a reader code.
And `0x26`'s message — תקלה בקורא אופטי או בכרטיס תשלום, *fault in the
optical reader or in the payment card* — is exactly what a reader-originated
fault should say.

## 10n. The module-name table (`0x6B74`) — faults name the part to check

31 word pointers at `6B74`–`6BB1`, each to a fixed **16-byte** Hebrew string
naming an assembly. This is the "קוד מכלול" (*module code*) subsystem whose
label sits at `69DF`, and it completes the fault log: the readout tells a
technician a number **and the part to check**.

### How an entry is rendered

`show_fault_entry` (`5E8B`, was `FUN_5e8b`), called from `show_fault_log` at
`6031` with the BCD fault number already looked up from `6069`:

```
5E8E  ANI 0xF0 / SHR x4 / ADI 0x30 / STR R8   high digit -> 8041
5E9C  LDX / ANI 0x0F / ADI 0x30 / STR R8      low digit  -> 8042
5EA7  LDX / SMI 0x10 / LBNF ...               BCD -> binary by subtraction
5EB5  GLO R8 / ADD / SMI 0x0C / SHL           index = (number - 12) * 2
5EBC  SCAL 6E6B, desc 6789                    LINE 1, col 5, width 11, from 8041
5EC4  RLDI R8,6B74 / ADD / PLO R8 / RLXA R8   the module pointer
5ED2  copy 16 bytes to 804C
5EE2  SCAL 6E6B, desc 679B                    LINE 2 from 804C
```

Two descriptors cooperate on line 1: `670B` draws the label
תקלה מס':  -בדוק (*Fault no.: - check*) with a gap, and `6789` drops the two
digits into **column 5, width 11**. The module name then fills line 2.

**So the module index is `fault number - 12`**, covering numbers **12–42**.

### The table

| idx | Fault | Module |
|---|---|---|
| 0 | 12 | חוגת   לחיצים |
| 1 | 13 | שפופרת |
| 2 | 14 | כרטיס ראשי |
| 3 | 15 | *(unused — filler)* |
| 4 | 16 | *(unused — filler)* |
| 5 | 17 | *(unused — filler)* |
| 6 | 18 | *(unused — filler)* |
| 7 | 19 | סוללה |
| 8 | 20 | לחצן החלפת כרטיס |
| 9 | 21 | לחצן  חיוג  חוזר |
| 10 | 22 | *(unused — filler)* |
| 11 | 23 | קורא אופטי |
| 12 | 24 | קורא מגנטי |
| 13 | 25 | *(unused — filler)* |
| 14 | 26 | *(unused — filler)* |
| 15 | 27 | *(unused — filler)* |
| 16 | 28 | *(unused — filler)* |
| 17 | 29 | *(unused — filler)* |
| 18 | 30 | *(unused — filler)* |
| 19 | 31 | *(unused — filler)* |
| 20 | 32 | גביות  ללא הצלחה |
| 21 | 33 | שפופרת מורמת שוא |
| 22 | 34 | הרמות  ללא  מתקף |
| 23 | 35 | כ' ראשי/ק' אופטי |
| 24 | 36 | כ' ראשי/מ תחזוקה |
| 25 | 37 | כ' ראשי/מ' אשראי |
| 26 | 38 | ארקה   מנותקת |
| 27 | 39 | כ' ראשי/מ' אשראי |
| 28 | 40 | מ' גביה ללא חיוג |
| 29 | 41 | טרם בוצעה תקשורת |
| 30 | 42 | תאורה    חיצונית |

**Twelve** entries point at `68CF`, a message used elsewhere
(בקשתך אושרה-חייג) — indexes 3–6, 10 and 13–19 — simply filler for fault
numbers that are never raised. Index 27 repeats index 25's string.

### Fault code → module, end to end

Combining the BCD table (§10f) with this one gives the full chain
**code → number → module** for every live entry at `6069`:

| Code | № | Module |
|---|---|---|
| `46` | 14 | כרטיס ראשי |
| `48` | 43 | **out of range — see below** |
| `49` | 43 | **out of range — see below** |
| `50` | 14 | כרטיס ראשי |
| `51` | 14 | כרטיס ראשי |
| `52` | 33 | שפופרת מורמת שוא |
| `53` | 34 | הרמות  ללא  מתקף |
| `54` | 23 | קורא אופטי |
| `55` | 23 | קורא אופטי |
| `57` | 12 | חוגת   לחיצים |
| `58` | 14 | כרטיס ראשי |
| `59` | 20 | לחצן החלפת כרטיס |
| `60` | 23 | קורא אופטי |
| `61` | 35 | כ' ראשי/ק' אופטי |
| `62` | 40 | מ' גביה ללא חיוג |
| `63` | 24 | קורא מגנטי |
| `64` | 40 | מ' גביה ללא חיוג |
| `65` | 21 | לחצן  חיוג  חוזר |
| `66` | 13 | שפופרת |
| `67` | 19 | סוללה |
| `68` | 36 | כ' ראשי/מ תחזוקה |
| `69` | 37 | כ' ראשי/מ' אשראי |
| `73` | 41 | טרם בוצעה תקשורת |
| `74` | 41 | טרם בוצעה תקשורת |
| `75` | 38 | ארקה   מנותקת |
| `76` | 39 | כ' ראשי/מ' אשראי |
| `77` | 23 | קורא אופטי |
| `78` | 42 | תאורה    חיצונית |

Several codes share a module, which is expected: four distinct codes
(`46`, `50`, `51`, `58`) all point at כרטיס ראשי (*main card*), and four
(`54`, `55`, `60`, `77`) at קורא אופטי (*optical reader*). The code
identifies the test; the module identifies the part.

### The priority fault at `29E7`

Not every fault comes from the log. `show_fault_log` calls `show_optical_reader_fault` (`29E7`) at
`6006` — after the `670B` label is drawn and **before** the log walk at
`600D` — and that routine hard-codes one:

```
29E9  RLDI R5,88BB
29ED  LDN R5 / LBZ 2A05      nothing wrong -> skip
29F1  LDI 0x23               BCD 23
29F3  SCAL R3,5E8B           show_fault_entry
29F7  SCAL R3,5EEB, arg 05   wait for key 0x0C
```

`0x23` is a packed-BCD **number**, so 23 decimal, giving index
`23 - 12 = 11` — entry 11 is `6BE5`:

| | |
|---|---|
| line 1 | תקלה מס': 23 -בדוק |
| line 2 | **קורא אופטי** — *the optical reader* |

So the optical reader is reported ahead of everything in the `840A` log,
which fits it being the critical peripheral.

`M(88BB)` is the gate, and it has **no write cross-reference** — it is set
through a pointer register rather than a direct `RLDI`, like the `8119`
pointers in §10g. `standby_reboot_or_halt` reads it at `23A6` with the same
`LDN` / `LBZ` shape. Finding its writer would say exactly which reader
failure raises fault 23.

### An apparent off-by-one

Codes **`0x48` and `0x49` map to fault number 43**, giving index 31 — one
past the end. The table ends at `6BB1` and the strings begin at `6BB2`, so
index 31 reads the word `0x20AD`, which is **code**
(`48 57 17 68 2b 94 ...`), not a pointer. Those two codes would therefore
display garbage on line 2.

Either they are never logged, or this is a real firmware bug. Every other
live code in the `6069` table lands inside the table, so it is not a
systematic misreading of the index arithmetic. Since no byte of code differs
between the three builds (§1a), it would be present in all of them.

## 10o. The cleaning card, and how card types are told apart

`detect_cleaning_card` (`0x2A0C`, was `FUN_2a0c`) recognises the **reader
cleaning card**. It is a four-way AND over one card value and three state
bytes, and a clean leaf function with a proper save/restore — unusual in this
image.

```
2A0C  RSXD RC / RSXD RD / STXD     save RC, RD and D
2A11  RLDI RD,88BA                 the result cell
2A15  M(813B) != 0    -> fail
2A1D  M(8060) != 0x30 -> fail      <- card_packed_byte, i.e. THE CARD TYPE
2A27  M(805E) != 0x78 -> fail
2A31  M(813F) != 0x0B -> fail
2A3B  LDI 0xAA / LSKP
2A3E  LDI 0x00
2A40  STR RD                       M(88BA) = 0xAA or 0
2A41  IRX / LDXA / RLXA RD / RLXA RC / DEC R2 / SEX R2 / SRET R3
```

### What the flag does

| | |
|---|---|
| `46EE` | `M(88BA) == 0xAA`? |
| `46F5` | `SCAL 2CF0` = `register_cleaning_event` — clears `M(88BA)`, then `LBR 36D5` |
| `36D6` | `store_byte_84xx(0x48, 0x79)` → **`M(8448) = 0x79`**, recording the event in the same `84xx` page as the fault log |
| `36DD` | `SCAL 6E6B`, desc `00E5` → פעולת הנקיון / נרשמה — ***the cleaning operation has been registered*** |
| `46F9` | `LBR 4AF6`, back to the main idle loop |

So inserting the cleaning card makes the phone **log the maintenance event
and confirm it on screen**. The flag is consumed once and cleared, so the
message appears exactly once per insertion.

**`register_cleaning_event` is one function split across two ROM regions.**
`2CF0` saves `R5`, `RC`, `RD`, clears the flag and branches to `36D5`; the
keypad table at `2D00` (§10f) occupies the gap. The continuation ends with

```
36E3  LDI 0xFF / STXD
36E6  M(812D) = 0x96              a 150-tick timer
36ED  IDL / LDN RC / LBNZ 36ED    hold the message up until it expires
36F3  IRX / LDXA
36F5  RLXA RD / RLXA RC / RLXA R5 / DEC R2 / SEX R2 / SRET R3
```

and that restore matches `2CF0`'s saves exactly — which is what proves the
two halves are one routine rather than a branch into unrelated code.

### `store_byte_84xx` (`0x5E6E`)

```
5E6E  RLDI R8,8442
5E72  LDA R3 / PLO R8    arg1 is a LOW BYTE, so R8 = 0x84:arg1
5E74  LDA R3 / STR R8    M(R8) = arg2
```

Two inline bytes, `b,b` — the analyzer detects this one unaided. Note `PLO R8`
*replaces* the low byte, so the `8442` in the `RLDI` only sets the page; the
offset is the argument. Other call sites: `5F68` → `M(8445) = 0x70`,
`3095` → `M(8444) = 0x62`. It is the one-byte sibling of `5E1B` (§10i),
which does the counter-and-threshold work on the same page.

### `M(8060)` is the card type

The same byte is discriminated immediately below the cleaning check:

```
4701  M(8060) == 0x78, with bit 3 of M(8139)  ->  RF.0 = 0x75 = NO_INTL_CALLS
```

So the packed nibble pair the reader returns (`PackCardNibbles`, §10m) is how
the phone tells card types apart — `0x30` is the cleaning card, `0x78` a card
barred from international calls. That is the same cell the idle selector
reads for card presence (§10l), so one byte carries both "is there a card"
and "what kind".

## 10p. Card kinds and card rights

The firmware separates **what kind of card it is** from **what the card is
allowed to do**. Two different bytes carry those.

### `M(8060)` — the card kind

The packed nibble pair from `PackCardNibbles` (§10m). Only **three** sites
touch it at all, and only two compare it:

| Value | Meaning | Site |
|---|---|---|
| `0x30` | **cleaning card** — with three further conditions, logs the maintenance event (§10o) | `2A1D` |
| `0x78` | **barred from international calls** — with bit 3 of `M(8139)`, sets `RF.0 = 0x75` | `4700` |

The third site is `33CA`, where `33C5` writes it. So the ROM hard-codes
exactly two card kinds.

### `M(8139)` — the card's rights, as a bitmask

Not a type code: **every bit 0–7 is used** somewhere, and compound masks
(`0x15`, `0x30`, `0x41`, `0x51`, `0x82`) appear too.

| Bit | Seen at | What it gates |
|---|---|---|
| 0 | `2723`, `377B`, `42CE` (via `SHR`) | — |
| 1 `0x02` | `2814`, `3A63` | — |
| 2 `0x04` | `41D7`, `5F88` | — |
| 3 `0x08` | `2723`, `4706`, `7305` | **international calls**, with `M(8060) == 0x78` |
| 4 `0x10` | `0095`, `2559`, `3A3D`, `477E`, `47E9` | routes to `47F7`, clearing `RF.0` |
| 5 `0x20` | `486A`, `740E` | — |
| 7 `0x80` | `35D4` (`0x82`), `486A` | — |

### The class selector (`47E1`)

```
47E1  RLDI R6,8139
47E5  LDN R6 / LBZ 47F1      rights == 0 -> 47F1
47E9  ANI 0x10 / LBNZ 47F7
47EE  LBR 4807               -> main idle loop
47F1  LBQ 480A               Q set -> CREDIT CARD ONLY  (desc 657F @4813)
47F4  LBR 481F               else  -> FREE CALLS ONLY   (desc 64F8 @4828)
```

With no rights bits at all, the **Q flag** picks between the two.

### The reachable class messages

| Desc | Shown at | Text |
|---|---|---|
| `650A` | `46C3`, chained from `669F` | כרטיס טלכרט בלבד / `TELECARD    ONLY` |
| `657F` | `4813` | שיחות אשראי בלבד / `CREDIT CARD ONLY` |
| `64F8` | `4828` | חיוג חופשי  בלבד / `FREE CALLS  ONLY` |
| `66A8` | `4BF6` | כרטיס זה אינו מאפשר חיוג לחו"ל — the `RF.0 = 0x75` handler |
| `66F9` | `3A6E` | השירות בתשלום / `A PAY  SERVICE` |

### Two dead messages

Present in the ROM, **never loaded and never chained**:

- `6475` → שיחות בינל' בלבד (*international calls only*) — a card class the
  firmware can name but never displays
- `63FF` → a duplicate of the telecard-only descriptor

Since no byte of code differs between the three builds (§1a), both are dead
in all of them. `6475` is the interesting one: it implies an
international-only card class that this firmware revision dropped, or that
was configured out.

### Up to four more kinds, defined in RAM not ROM

`33C5` holds a **configurable accept-list** in battery-backed RAM:

```
33F0  RLDI RC,850E
33F4  LDA RC / SMI 1 / ANI 3 / ADI 1     count = 1..4
33FD  LDA RC / XOR / LBZ 3415            compare against the card value
3402  DBNZ RD,33FD
```

A match sets card status `0xAA`. So **up to four further card values are
accepted by configuration**, and their identities are not in the ROM at all —
they live in the battery-backed SRAM of a given unit. A dump of `850E`
onward from a live phone would reveal which cards that unit was provisioned
to take.

## 10q. The battery-backed RAM

Everything the phone remembers across a power cut lives in one chip: **U6 on
the `TAAS TAMAC MEMORY CARD` daughterboard, an SRM2A256LLMT10 — 32K × 8 SRAM
with a lithium cell** (§1a). There is no EEPROM and no other non-volatile
store, so the fault log, the tariff state, the accept-list and the counters
all depend on that battery.

### How much of it there is

| Evidence | Says |
|---|---|
| Ghidra's `ram` segment | `8000`–`9FFF` |
| Address references in the image | 1070 into `8000`–`8FFF`, 35 into `9000`–`9FFF`, **none** into `A000`–`DFFF` |
| The cold-start clear at `305B` | wipes `8000`–`DFFF` |

```
3058  SEX R4 / DIS 0x24      interrupts off
305B  RLDI RC,DFFF
305F  RLDI RD,6000           0x6000 = 24576 bytes
3066  STXD / DBNZ RD,3066    clears 8000..DFFF, downward
306B  RLDI R2,89FA           the stack
```

So the firmware only *uses* `8000`–`9FFF`, but cold start assumes RAM exists
up to `DFFF` and stops exactly below the LCD at `E000`. That fits a 32K part
decoded at `8000`–`FFFF` with the LCD and the `F000` control register
overlaid on its top pages. **It is consistent, not proven** — writes to
absent memory would be harmless either way. The single `DFFF` reference is
the clear loop itself; nothing else in the image ever addresses that region.

### Cold start versus warm start

```
3038  SCAL R3,304A
3041  LBNZ 3058      check failed -> FULL COLD INIT
3044  SCAL R3,4455   otherwise keep the RAM and carry on
```

and `304A` is the check itself:

```
304A  SCAL 28F9(dest 9771, src 3011, len 0026)   relocate 38 bytes to RAM
3055  LBR 9771                                    and run them there
```

The relocated routine (ROM image at `3011`) walks a region XORing bytes and
can write **0 to `F000`** at `302B`–`3031`. That closes the loop on §10a,
where clearing the control register was guessed to be the response to a
failed integrity check: it is.

`28F9(dest, src, count)` is a plain memcpy taking **three** 2-byte inline
pointers — `SEX R3` then three `RLXA`s. The analyzer resolves it unaided.

### What cold start writes

| Cell | Value |
|---|---|
| `8000`–`DFFF` | zeroed |
| `R2` (stack) | `89FA` |
| `844D` | `0xAA` |
| `867B`, `867C` | `0x55` |
| `8500` | `M(0D00)` = `0x05` |
| `850D`–`8515` | 9 bytes copied from ROM `0D01` |
| `8444` | `0x62`, via `store_byte_84xx` |
| `8E0A` | `0x01` |
| `97A1` | `0` |
| `9798`, `979C`, `979F`, `97AE` | word constants |

then `LBR 29D8` — reboot into the initialised machine.

### The ROM defaults, and the accept-list

```
0D00:  05 | 40 02 0f 78 00 00 01 01 01
            ^^^^^^^^^^^^^^^^^^^^^^^^^^ -> 850D..8515
```

| Cell | Default | Meaning |
|---|---|---|
| `850D` | `0x40` | |
| `850E` | `0x02` | **count** for the accept-list; `33F4` computes `((n-1)&3)+1` so 1–4 |
| `850F` | `0x0F` | **accepted card value 1** |
| `8510` | `0x78` | **accepted card value 2** |
| `8511`, `8512` | `0x00` | unused list slots |
| `8513` | `0x01` | read at `1A52`, becomes `M(813A) = M(8513) - 1` |
| `8514` | `0x01` | tested at `347D` |
| `8515` | `0x01` | |

So out of the box a phone accepts **two card values, `0x0F` and `0x78`**,
and can be provisioned with up to four (§10p). `0x78` is the one `4700`
separately marks as barred from international calls.

### Known structures

| Range | Contents |
|---|---|
| `8000`–`80FF` | working state: card type/value, port shadows, display scratch |
| `8101`–`8119` | the 25-byte downward buffer, pointers at `811A`/`811B` (§10g) |
| `8129`–`8199` | timers and flags |
| `840A`–`8441` | **the fault log**, 28 entries × 2 bytes (§10e, §10i) |
| `8442`–`84xx` | event cells written by `store_byte_84xx` and `5E1B` |
| `8500`–`85xx` | **configuration**, including the accept-list |
| `867B`, `867C` | `0x55` sentinels |
| `88xx` | `88BA` cleaning flag, `88BB` optical-reader fault, `88C5` |
| `89FA` | the stack (`R2`) |
| `9100`–`97xx` | **code relocated from ROM and executed in place** (§10) |

### The `0xAA` / `0x55` sentinel convention

Validity is marked with `0xAA` or `0x55` rather than a flag bit, throughout:
`807A`, `807C`, `8134`, `844D`, `8864`, `8865`, `867B`/`867C`, `816C`,
`8183`, `8079`, and `8169` (`0x55` as one of its four card-session states,
§10l). `LDI 0xAA` alone occurs 28 times, every one followed by `STR` — which
is how §10d established that `0xAA` is **not** a status code.

Two complementary bit patterns are the classic choice for detecting a RAM
that has lost its battery: all-zeros and all-ones both fail.

### Why this matters practically

A unit whose lithium cell has died comes up, fails the integrity check,
clears `8000`–`DFFF` and re-seeds the ROM defaults — losing its fault log,
its counters and any provisioned card values. Conversely, **reading
`850D`–`8515` and `840A`–`8441` out of a phone with a live battery recovers
that unit's provisioning and its fault history**, neither of which is
derivable from the ROM.

## 10r. `build_report_template` (`0x2C97`) and two stubs

Lays out a 40-byte ASCII record template at `81BA`–`81E1` and arms a flag.
Returns `0xFF` on success, `0` if any precondition fails.

```
2C97  M(81B5) != 0    -> fail
2CA3  M(8191) != 0    -> fail
2CAC  M(8859) != 0xA5 -> fail        the caller's request token
2CB1  SCAL 6FFF                      a tone, via play_toggle_pattern
2CB6  SCAL 290A(81E1, 0x30, 0x0028)  fill 40 bytes with ASCII '0'
2CBF  M(81BA) = ';'
2CC6  M(81CB) = '='
2CCD  M(81E0) = '?'
2CD5  SCAL 75C6(0x44)                a STUB - see below
2CDA  M(845C) = 0x80
2CE1  return 0xFF  /  2CE6  M(8859) = 0, return 0
```

### `290A` is a *downward* memset

Its loop is `STXD` / `DBNZ`, so `memset(81E1, '0', 40)` covers `81E1` **down
to** `81BA`. That is why the base of the record is `81BA`, and why the three
separators are written after the fill rather than before. Signature: dest
word, fill byte, count word.

| Offset | Content |
|---|---|
| `81BA` | `;` |
| `81BB`–`81CA` | 16 × `'0'` |
| `81CB` | `=` |
| `81CC`–`81DF` | 20 × `'0'` |
| `81E0` | `?` |
| `81E1` | `'0'` |

### Three routines at `75C0` that are easy to confuse

| Address | Body | Meaning |
|---|---|---|
| `75C0` | `SEX R4 / DIS 0x24 / LBR 75C3` | **halt** — interrupts off, spin |
| `75C6` | `INC R3 / SEX R2 / SRET R3` | **stub that skips one inline byte** |
| `75C7` | `SEX R2 / SRET R3` | no-op (`empty_75c7`) |

So `SCAL 75C6(0x44)` is a **disabled call whose argument still sits in the
ROM**. A call to `75C6` anywhere means functionality was removed and the
call site left behind — worth recognising. `75BB` next door is the
`LDI 0xFF / SRET` that makes `46AE` dead code (§10l).

### The caller

Only `769C`, which runs it on a counter threshold:

```
769C  M(885D) >= 45 ?
76A6  M(885D) = 0
76A9  M(97A8) = M(97AC) = M(97B0) = 0
76BA  M(8859) = 0xA5         arm the request
76C2  SCAL 2C97
76C6  separately, M(845A) >= 45 -> store_byte_84xx(0x46, 0x71)
```

### What it is for — inference, not proof

The ASCII `;` `=` `?` separators, the periodic trigger, and `M(845C)` —
which is also touched throughout the `build_dlc_record` neighbourhood at
`1C1A`–`1C41` and at `2F30` in `DLC_Comm` — all point at a report destined
for the DLC link.

But **nothing in the image loads `81BA`–`81E1` by absolute address**: the
three writes here are the only `RLDI` references to them. The buffer must be
reached through a pointer computed elsewhere, so the claim that this record
is transmitted is unproven. Find the reader before relying on it.

## 10s. `periodic_report_check` (`0x769C`) — every 45 calls

Called once per pass of the main idle loop, from `4B81`, and from nowhere
else. Two independent threshold checks, both at 45 (`0x2D`):

```
769C  M(885D) >= 45 ?
76A6    M(885D) = 0
76A9    M(97A8) = M(97AC) = M(97B0) = 0
76BA    M(8859) = 0xA5                  arm the request token
76C2    SCAL build_report_template      2C97
76C6  M(845A) >= 45 ?
76D0    M(845A) = 0
76D4    SCAL store_byte_84xx(0x46,0x71) M(8446) = 0x71
```

Both tests are `SMI 0x2D` / `LBNF`, so they fire at **45 or more** — a
counter that overshoots still triggers.

### What the counters count

Both are incremented at a single site, together, inside `FUN_420E`:

```
4252  RLDI R7,845A / LDN R7 / ADI 0x01 / STR R7
425A  RLDI R7,885D / LDN R7 / ADI 0x01 / STR R7
4263  SCAL R3,1C5F
4268  SCAL R3,77AD
```

**They count PULSES, not calls.** §10ai decodes the site: `4243` reads
**port 3 bit 7** and compares it against the previous sample in `M(8078)`,
so the increments happen on a **rising edge**. The `SCAL 0100` at the top of
`FUN_420E` belongs to an earlier job in that stage, and every branch out of
the `ANI 0x96` test rejoins at `4238`, before the detector. So
`periodic_report_check` fires every **45 pulses**.

### The `97xx` counter records

`1C5F` calls `increment_counter16` (`04F0`) **four** times — `1C60`→`97A6`,
`1C67`→`97AA`, `1C6E`→`97AE` and `1C75`→`979F`. The first three are
the **`varC`** fields of the three `SupervisedOpDesc` channel records
(§10z); `979F` is a fourth counter outside that array, and the cells this routine clears — `97A8`, `97AC`, `97B0`
— are their **`varB`** fields, the ones the engine range-checks against
`limitB`. The record is 4 bytes: `varA`, a 16-bit `varC`, then `varB`.

So the discipline is read-and-clear, as `build_dlc_record` uses (§8a), but
the two cells play different roles in the supervised-operation engine rather
than being a count and a spare byte.

`increment_counter16` saturates rather than wrapping:

```
04F0  SEX R3 / RLXA RC          RC = inline pointer
04F3  LDA RC / SMI 0xFF / LBNZ 04FF
04F9  LDN RC / SMI 0xFF / LBZ 0508     both 0xFF -> leave it alone
04FF  LDN RC / ADI 0x01 / STR RC
0503  DEC RC / LDN RC / ADCI 0x00 / STR RC
```

### Three more inline signatures declared

Added to `cdp1806/data/inline_args.txt`:

| Callee | Signature | Why |
|---|---|---|
| `04f0` | `p` | the counter pointer |
| `290a` | `p,b,b,b` | memset — **downward**, so the pointer is the *top* of the region (§10r). The count is `b,b` because both word kinds would reference it: `w` references any target in initialized memory, and every count here lies in ROM |
| `75c6` | `b` | a stub that only steps over its byte; **auto-detection cannot infer this**, since the routine never loads it |

## 10t. `flush_nopulse_fault_counter` (`0x75F9`) — a fault counter end to end

The clearest worked example of the fault machinery in §10i, §10f and §10n
acting together on one real fault.

```
75F9  RLDI R5,88BE
75FD  LDN R5 / LBZ 760E        nothing pending -> return
7601  ADI 0x01                 D = M(88BE) + 1, which is 5E1B's SELECTOR
7604  SCAL 5E1B(0x17, 0x28, 0x53)
760B  LDI 0 / STR R5           clear the pending byte
```

### Which fault

`5E1B`'s first inline byte is a **low byte**, so offset `0x17` gives
`R8 = 8417` — an odd offset from `840A`, therefore the **counter byte** of
the log entry whose code byte sits at `8416` (§10i). The other arguments are
the threshold `0x28` = **40**, and the code `0x53` OR'd in on reaching it.

Following the two tables: code `0x53` → BCD table at `6069` → fault **34**
→ module table at `6B74` index 22 → **הרמות  ללא  מתקף**, *lifts
without pulse*.

So the phone counts off-hook events that produced no dial pulse and raises
fault 34 after forty of them.

### Why `M(88BE)` carries two values

`5E1B` clears its counter when the selector is 0 and increments it
otherwise. The `ADI 0x01` is what maps the pending byte onto that:

| `M(88BE)` | selector | effect |
|---|---|---|
| `0x01` | `0x02` | **increment** the counter |
| `0xFF` | `0x00` | **clear** the counter |

### Where it is armed

`75CA`, which runs only while `M(807A) == 0xAA` and `RF.0 == 0x91`:

```
75DE  LDN RA (M(8144))
75DF  LBZ 75E5 / LDI 0xFF / LSKP / LDI 0x01
75EB  STR RC                M(88BE) = 0xFF if M(8144) != 0, else 0x01
75EC  ADI 0x01 / LBNZ 75F6  only the 0xFF case falls through
75F2  SCAL 75F9
```

A non-zero `M(8144)` means the pulse arrived, so the counter is cleared
immediately. A zero `M(8144)` arms a count, which a later call — from
`4CD4`, in the `RF.0 == 0x97` handler — applies.

That is the whole life cycle of one fault: armed on a hook event, counted to
a threshold, written into the log as a code, and finally rendered by
`show_fault_entry` as a number plus the part to check.

## 10u. `flush_output_latches` (`0x7572`) — ports 1, 3 and 4 are outputs

The widest view of the output ports in the image, and the routine that
settles two of the three unidentified ports.

### No `OUT` here takes an inline operand

Worth stating plainly, because it is the natural suspicion. `OUT` consumes a
byte from the instruction stream only when **X == P**, and the `DIS` at
`7589` sets **X = R5**, so `X != P` for the whole body. Every `C4` is a
genuine `NOP` — an inter-write delay for the latches — and every byte in
`758B`–`75B5` is code.

**Two bytes *are* misread, but they are not `OUT` operands:**

| Address | Shown as | Actually |
|---|---|---|
| `758A` | `STR R4` | the **`DIS` operand** `0x54` → X=R5, P=R4, IE=0 |
| `75B8` | `DEC R4` | the **`RET` operand** `0x24` → X=R2, P=R4, IE=1 |

Neither breaks alignment, which is why the rest of the listing is correct.

### The write sequence

`R5` walks up from `8033`; each `OUT` outputs `M(R5)` then increments it, so
the `DEC`s are what re-aim it.

```
OUT5 M(8033)   NOP NOP   OUT1 M(8034)
OUT5 M(8034)   NOP NOP   OUT2 M(8035)
M(8034) &= ~0x40
OUT5 M(8034)   NOP NOP   OUT2 M(8035)      <- repeat, bit 6 now low
OUT5 M(8035)   NOP NOP   OUT3 M(8036)
OUT5 M(8036)   NOP NOP   OUT4 M(8037)
M(8036) &= ~0x12
OUT5 M(8036)   NOP NOP   OUT4 M(8037)      <- repeat, bits 1 and 4 now low
```

Each read-modify-write precedes a **repeat of the same port write**, so they
are **strobe pulses**: present a bit, write the data, drop the bit, write
again. Bit 6 of `M(8034)` strobes around the port 2 write; bits 1 and 4 of
`M(8036)` around the port 4 write.

### Ports 1, 3 and 4 are outputs

That closes most of the gap left in §6. **Port 3 is both** —
`read_hardware_straps` (`6173`) does `INP 3` for the strap sense, and the
1802 uses the same N code for input and output with direction set by `MRD`,
so one N value can serve two devices.

### What port 5 receives is still unresolved

Taking each pair literally gives `port n <- M(8033+n)`, with port 5 carrying
the byte one below. But the only other flush in the image, at `399D`, is
`SEX RB(8034) / OUT 5 / NOP NOP / OUT 2`, making `port 5 <- M(8034)` and
`port 2 <- M(8035)`.

The two agree on `port 2 <- M(8035)` and disagree on port 5. Either `OUT 5`
is a latch-enable whose data the hardware ignores, or the two routines drive
different devices. **`8033` should not be called "the port 5 shadow" on this
evidence** — which is why it stays named `strap_drive_and_flags` (§10k).

## 10v. `init_comm_session` (`0x74A7`)

Prepares a DLC communication session: sets a timeout, optionally displays
בתקשורת (*in communication*), clears two working buffers, and saves the
stack and link registers.

### `M(845C)` is a mode argument, not a persistent flag

The caller writes it immediately before calling, and clears it after:

```
1C1A  M(845C) = 0xC0 / SCAL 74A7     full setup
1C35  M(845C) = 0x80 / SCAL 74A7     buffers only
1C45  M(845C) = 0
```

```
74A7  LDN R6 / XRI 0xC0 / LBNZ 74CB  not 0xC0 -> straight to the clear
74B1  M(8167) & 0x20 ?
74BB    clear -> M(8167) = 0x0E, LBR 74CB      no message
74C1    set   -> M(8167) = 0x28, display 664E  "     בתקשורת    "
74CB  SCAL EraseBlock(8600, 862A)    43 bytes
74D5  SCAL EraseBlock(8700, 8794)    149 bytes
74DD  RLDI RA,8794 / SEX RA / RSXD R2 / RSXD R3
74E6  RLDI RA,755C                   a continuation address
74EA  RLDI R9,8629 / RLDI RD,0006 / fill
```

So the `0xC0` path is the one that touches user-visible state — the timeout
and the message — while `0x80` only resets the buffers. Both share
everything from `74CB`.

The two timeout values `0x0E` and `0x28` are selected by **bit 5 of
`M(8167)`**, the same bit the main idle loop saves to `81FB` and clears at
`4B05`.

### Context

Both callers sit in the `build_dlc_record` neighbourhood (`PerformComm` at
`1ABE`, `build_dlc_record` at `1CC2`), and the message says *in
communication*, so this is the **DLC link**, not the card reader. The
buffers at `8600`–`862A` and `8700`–`8794` are session working space and are
**not** the 70-byte DLC record at `8D26` (§8a).

## 10w. `service_tick` (`0x728A`) — one tick of the machine

```
728A  IDL                wait for the next interrupt - this is what makes it
                         a TICK rather than a poll
728C  SCAL R3,729E       periodic supervision: RF.0 triage, timers, the 0x91
                         resolution at 7380 (§10d)
7291  SCAL R3,2D10       per-tick state and display update; its tail is the
                         idle display selector at 2E17 (§10l)
7296  SCAL R3,3900       service_card_reader_link
729A  GLO RF             RETURN RF.0, the global state register
729C  SEX R2 / SRET R3
```

**The return value is the point of the routine.** Callers tick the machine
and then dispatch on whatever state came back:

```
463C  SCAL 728A / LBZ 4660 / SCAL 744F / LBZ 48A9
474A  SCAL 728A / LBZ 46EA / SCAL 744F / LBZ 48A9
```

so a zero state means "nothing happened, carry on", and a non-zero one is
handed to `is_out_of_service_state` and the rest of the triage (§10d).

### `3900` → `service_card_reader_link`

Named in passing, because the evidence is unambiguous. It opens by loading
exactly the pointer registers the dispatcher expects — `R5=8031`,
`R6=805C`, `R7=8065`, `RA=8028`, `R9=8067`, the map recorded at `5FB1` —
then calls **`send_reader_command`** (`365C`) at `3954` and
**`dispatch_card_reader_message`** (`333D`) at `3962`. Both halves of the
link, serviced once per tick.

### A lighter variant

The pair `2D10` + `3900` is also invoked directly at `4596`/`459A`, without
the `IDL` or the supervision pass — a refresh rather than a full tick.

## 10x. `0x70DF` — why "empty line" was the wrong reading

Renamed from `LoadEmptyLine_AND_8036_with_0xBF` to
**`BlankDisplayAndClear8036Bit6`**.

```
70DF  SEX R2
70E0  SCAL 6E6B, desc 6451
70E6  RLDI R6,8036 / LDN R6 / ANI 0xBF / STR R6
70EE  SRET R3
```

### It blanks both lines, not one

Descriptor `6451` is a **two-link chain**:

| Desc | Cursor | Line | Width | Text |
|---|---|---|---|---|
| `6451` | `0x01` → cmd `0x80` | 1 | 16 | `6ADE` |
| `64CB` | `0x41` → cmd `0xC0` | 2 | 0 | `6ADE` |

and `6ADE` is sixteen spaces. So the **whole display** is cleared. Reading
it as a single blank line mis-predicts what is left on screen — a good
reminder that in this firmware a descriptor is a *chain head*, never a
single line (§10b).

### Bit 6 of `M(8036)` is a latch, and this is half of a pair

```
70CE  M(8134) = 0x5A ; M(8036) |= 0x40     set it
70DF  blank the display ; M(8036) &= ~0x40 clear it
```

`4574` guards on it — `LDN / ANI 0x40 / LBNZ 4583` — so `70CE` runs only
while the bit is clear. It is also set at `5FDC` entering `show_fault_log`
(alongside `M(8134) = 0xAA`), and cleared at `7580` and `4132`.

### Callers

| Site | Context |
|---|---|
| `3850` | after an `IDL` wait for `M(812F)` and `M(8863)` to reach zero, and only when bit 5 of `M(8167)` is clear — tidying the screen on the way out |
| `4C76` | in `proc_4C75`, which blanks and then calls `6FB3` |

## 10y. The software timer set — `arm_timer_set` (`0x70CE`) and the tick at `40F4`

```
70CE  RLDI R6,8134 / LDI 0x5A / STR R6     M(8134) = 0x5A = 90
70D5  RLDI R6,8036 / LDN R6 / ORI 0x40 / STR R6
70DD  SRET R3
```

Two writes, one idea: **`M(8134)` is both a mode selector and a countdown.**

### The tick, prescaled

```
40F4  RLDI R5,8130 / LDN R5 / ADI 0x01 / STR R5   M(8130)++
40FC  SMI 0x32 / LBNF 412A                        below 50, do nothing
4100  LDI 0 / STR R5                              reset the prescaler
4104  M(8134) == 0xAA ? RE = 40E7 : RE = 40D6
411A  LDN RE / LBZ 412A        a zero high byte ends the table
411E  RLXA R5                  the next counter's address
4120  LDN R5 / LBZ 411A        already zero, skip
4124  SMI 0x01 / STR R5        decrement it
412A  if M(8134) == 0 -> M(8036) &= ~0x40
```

So counters tick once per **50** base ticks.

### Two tables, differing by two entries

| Table | Counters |
|---|---|
| `40D6` | `888E` `8131` `8133` **`8134`** `8136` **`8128`** `8137` `811D` |
| `40E7` | `888E` `8131` `8133` — `8136` — `8137` `811D` |

The second is the first **minus `8134` and `8128`**, and that is the whole
trick:

| Mode | `M(8134)` | Behaviour |
|---|---|---|
| normal, armed here | `0x5A` | `8134` is **in** the table, so it counts *itself* down — 90 prescaled units — and on reaching zero the tick clears bit 6 of `M(8036)`. A **self-expiring** arm. |
| `show_fault_log`, armed at `5FD5` | `0xAA` | `8134` is **excluded**, so it never expires. A **latched** mode that only an explicit write ends. |

### What bit 6 of `M(8036)` means

"The timer set is running." `4574` guards on it — `LDN / ANI 0x40 / LBNZ
4583` — so `arm_timer_set` only re-arms once the previous arm has expired.
`BlankDisplayAndClear8036Bit6` (§10x) clears the bit by hand without
touching `M(8134)`, which is why the two routines are not symmetrical.

Nine callers: `37CD`, `4542`, `457F`, `4601`, `4F44`, `4F9B`, `4FBE`,
`59A6`, `7420`.

## 10z. The supervised-operation engine and its three channels

Recovered from the session transcript — this was worked out earlier and
never written down, and it **corrects the `97xx` layout given in §10s**.

### `proc_4bd7` is a thin driver

```
4BD8  SCAL 1ABE ; inline 1C7E    channel 0
4BDF  SCAL 1ABE ; inline 1C91    channel 1
4BE6  SCAL 1ABE ; inline 1CA4    channel 2
```

(`4BD7`, `4BDE` and `4BE5` are the `SEX R2` before each call.)

Three calls, nothing else. Each inline argument is a `0x13`-byte parameter
block.

### `SupervisedOpDesc` — 19 bytes, no padding

| Off | Size | Field | ch0 `1C7E` | ch1 `1C91` | ch2 `1CA4` |
|---|---|---|---|---|---|
| `00` | 1 | `channel` | `00` | `01` | `02` |
| `01` | 2 | `varA` | `97A5` | `97A9` | `97AD` |
| `03` | 2 | `varB` | `97A8` | `97AC` | `97B0` |
| `05` | 1 | `limitB` | `28` (40) | `08` | `24` (36) |
| `06` | 2 | `count` | `0006` | `0000` | `000B` |
| `08` | 2 | `varC` | `97A6` | `97AA` | `97AE` |
| `0A` | 2 | **`handler`** | **`1C1A`** | **`1C30`** | **`1C57`** |
| `0C` | 2 | `varD` | `97A5` | `97A9` | `97AD` |
| `0E` | 1 | `value` | `05` | `01` | `03` |
| `0F` | 2 | `varE` | `97A8` | `97AC` | `97B0` |
| `11` | 1 | `limitE` | `28` | `08` | `24` |
| `12` | 1 | `trailer` | `14` | `14` | `14` |

The layout was verified from both ends: Ghidra's own reference engine puts
`1C1A`'s referrer at `1C88` = `1C7E + 0x0A`, and `1C57`'s at `1CAE` =
`1CA4 + 0x0A`, matching the hand-traced `RLXA` consumption order.

A caveat if you rebuild the type: `channel` is a byte at `00` followed by a
pointer at `01`, so a C parser will pad to 20 bytes. Build it in the
Structure Editor with packing **disabled**, and check the size reads `0x13`.

### The three handlers

Each descriptor names **its own handler**, reached from `1B2C` by
`SEX RE / RLXA R4` — an `RLXA`-into-PC jump (§9). Each handler ends in
`LBR 1B2E`, jumping *back into* `1ABE`, so the two are **co-routines**, not
caller and callee.

| Ch | Handler | What it does |
|---|---|---|
| 0 | `1C1A` | `M(845C) = 0xC0`, `SCAL 74A7`, expects `0xCA` back |
| 1 | `1C30` | `SCAL 6FFF`, `M(845C) = 0x80` then `0x00`, `SCAL 74A7`, expects `M(81B5) == 0x42` |
| **2** | `1C57` | **`SCAL 06BA` — the DLC session entry** |

**So this is where a DLC session starts automatically**, as against
`DLC_Comm` (§9a), where an operator starts one from the keypad.

It also sharpens §10v: `init_comm_session`'s two call sites are not two
points in one routine but **channel 0's and channel 1's handlers**.

### `1ABE` — what the `PerformComm?` name is worth

It is a **generic supervised-operation engine**: take a descriptor,
range-check counters, jump to the handler it names, then retry and time out
until success or one of four error codes.

**For the name:** retries (counter at `97A4`), a timeout at `8136`, four
error codes, `DisplayCommStatus` on both paths, hook polling while waiting,
display descriptor `664E` shared with `DLC_Comm`, and channel 2 genuinely
running a DLC session.

**Against it:** **no `INP` or `OUT` anywhere in the routine** — it drives
nothing. Two of its three uses are not obviously communication, and the
engine is entirely generic.

`run_supervised_op` would be more honest. The `?` in the existing name is
doing real work and the name should not be read as *"this is the comm
driver"*: the link layer is the UART ISR at `5071` and `dlc_uart_service` at
`0A61`, well below this.

### Correction to §10s

§10s described the `97xx` cells as "three counters four bytes apart" with
"each record {16-bit count, byte}". The descriptors give the real layout —
a 4-byte record per channel, three named fields:

| Ch | `varA`/`varD` | `varC` (16-bit) | `varB`/`varE` | limit |
|---|---|---|---|---|
| 0 | `97A5` | `97A6`–`97A7` | `97A8` | 40 |
| 1 | `97A9` | `97AA`–`97AB` | `97AC` | 8 |
| 2 | `97AD` | `97AE`–`97AF` | `97B0` | 36 |

That reconciles both observations: `increment_counter16` (§10s) bumps
**`varC`**, and `periodic_report_check` clears **`varB`** — the byte the
engine range-checks against `limitB`. `97A4`, just below the array, is
`1ABE`'s retry counter.

## 10aa. `get_scaled_credit` (`0x533E`) and the credit divisor

Returns `M(805E)` divided by the divisor configured in `M(8514)`.

```
533E  R8 = 805E, R7 = 8515
5346  M(8515) == 1    -> 536C, return M(805E) UNSCALED
534D  M(8514) == 1    -> 536C, return M(805E)
5353  M(8514) == 2    -> 5369, return M(805E) >> 1
5358  M(8514) == 4    -> 5366, return M(805E) >> 2
535D  otherwise       -> SCAL 38E3 with D = M(805E)
```

The divisor is **1, 2, 3 or 4**, and the "otherwise" arm is the 3 case — the
only one that is not a power of two, which is exactly why it needs a
routine. `M(8515) == 1` bypasses scaling entirely.

### A shared byte in the shift arms

`5368` is `NBR`, a never-taken short branch, so it steps over the byte at
`5369`. Entering at `5366` runs `LDN R8 / SHR`, skips `5369`, and falls into
the `SHR` at `536A` — **two** shifts, a divide by 4. Entering at `5369` runs
`LDN R8` then that same `SHR` once. The byte at `5369` is doing double duty
as `NBR`'s operand and as an instruction.

### `38E3` → `divide_by_3`

```
38E8  SMI 0x18 / INC RC / LBDF    count v div 24
38EF  ADI 0x18                    restore the remainder
38F1  SMI 0x03 / INC RD / LBDF    count (v mod 24) div 3
38F7  GLO RC / SHL x3             quotient * 8
38FC  GLO RD / ADD                plus the remainder's quotient
```

`8*(v div 24) + ((v mod 24) div 3)` **is** `v div 3`. Splitting it that way
caps the loop at about 18 iterations instead of 85.

### `credit_times_rate_ge_1000` (`0x52F7`) — the other half of the test

The same caller takes a second route to "enough credit", and it is a
multiply:

```
52F8  SCAL compare_words16(8122, 8124)
5300  LBDF 530A         DF = word@8122 >= word@8124
5303  RD = 8124         ... so RD points at the LARGER of the two
530A  RD = 8122
5313  LDA RD / SMI 0x04 / LBDF 5336    rate high byte >= 4 -> return 20
531A  RE += word@RD                     16-bit add, low then high with ADC
5327  DBNZ RC,531A                      repeat RC.0 times
532B  continue only if RE.1 == 3
5331  RE.0 >= 0xE8 ?
5336  return 20   /   5339  return 0
```

The loop is a **multiply by repeated addition** — `RE = credit * rate` — and
`RE.1 == 3` with `RE.0 >= 0xE8` means `RE >= 0x03E8`, i.e. **1000**. The
early bail at `RE.1 >= 4` covers everything above that.

**It takes an implicit argument in `RC.0`**, the scaled credit. The routine
zeroes `RC.1` but never `RC.0`; the caller leaves it there with `PLO RC` at
`5267`, right after `SCAL get_scaled_credit`. Miss that and the loop count
looks undefined.

`389A` → `compare_words16`: a 16-bit big-endian compare of two inline
pointers, returning the result in `DF`.

So `FUN_524F` has **two independent routes to "enough credit"** — scaled
credit ≥ 100, or product ≥ 1000 — and only failing both reaches `528B`, the
low-credit path.

**Not established:** what the two rate words at `8122` and `8124` are, why
there are two, or why the **larger** is chosen. A day/night or local/trunk
tariff pair would fit, but nothing here shows it. Nor are the units of 1000
shown.

### What `M(805E)` holds

`FUN_3A0B`, the credit display, reads it at `3A7B`; the per-tick update
writes it at `2DB5`; `show_fault_log` clears it together with `805C` and
`805D` as a three-byte group. Its only caller, `FUN_524F`, compares this
routine's result against **100** (`5268`) and **20** (`5272`) and then sets
flags at `8184`, `814A` and `806B` — which reads as low-credit thresholds.

So "credit scaled by a configured divisor" is well supported. **The
divisor's units are not**: whether `M(8514)` converts card units to money,
to seconds, or to something else is not shown by this code. The ROM default
is 1 (§10q), so an unprovisioned phone does no scaling at all — another
reason to read `850D`–`8515` out of a live unit.

## 10ab. `parse_config_record` (`0x5426`) — remote provisioning

Parses a received character stream and writes the whole provisioning block
at `850D`–`8515`. Returns 0 on success, 1 on any validation failure. **This
is how a phone gets provisioned.**

```
5437  M(850D)                       first field
544C  M(850E) = count, kept in R5.0 as the loop counter
5451  loop, count times:
        5452  SCAL 38CB             assemble the next value
        5457  SCAL 3886             POPCOUNT it
        545B  SMI 0x04 / LBNZ 54B1  must be EXACTLY 4 - else fail
        5461  store to 850F, 8510, 8511, 8512
5479  M(8513)
548D  M(8514)  = credit_divisor
549D  M(8515)
549F  SCAL parse_digits_into(ptr)   two more fields
54AA  SCAL parse_digits_into(ptr)
54B0  LSZ 54B3                      D == 0 -> success
```

Every field is validated by `558D` and masked with `ANI 0x0F`, so the stream
carries one digit per byte.

### The popcount rule, confirmed by the ROM defaults

Accept-list entries must have **exactly four set bits**. The defaults seeded
from ROM `0D01` (§10q) both pass:

| | | |
|---|---|---|
| `0x0F` | `00001111` | popcount 4 |
| `0x78` | `01111000` | popcount 4 |

So **this ROM only accepts card values with four set bits** — a
constant-weight code, which gives free error detection. Why the values are
encoded that way is not shown here. The cleaning card's `0x30` has popcount
2 and is matched by `detect_cleaning_card` on a separate path (§10o), so it
never meets this rule.

### `parse_digits_into` (`0x54B5`) and the keypad encoding

Takes a **2-byte inline destination pointer** and parses up to 11 characters
into digit *values*:

| Input | Becomes |
|---|---|
| `'1'`–`'9'` | 1–9 |
| `'0'` | **10** |
| `'A'` | 0 |
| `'-'` | skipped |
| anything `558D` rejects | skipped |

`'0'` → 10 is the **keypad index encoding** of §10f, where index `0x0A` is
the `0` key — so the wire format speaks keypad indices, not ASCII values.

**Ghidra mis-decodes `54AE`/`54AF`** as `GLO R5 / LDN R1`; they are the
inline pointer. The tell is the first call: the `SCAL` at `549F` is four
bytes, yet the next real instruction is the `LBNZ` at `54A5`. Now declared
as `54b5  p`.

### Where the record comes from

The only caller is `3E2B`. It first calls `5A8E` with `D = 6` and bails if
that returns zero; `5A8E` does serial I/O — `OUT 6`, the UART data
register, polled against `INP 3` bit 1, with a 25-unit timeout. The caller
sits in the `3Dxx`–`3Fxx` block that drives `845C`, the DLC mode byte, and
writes the fault log at `3F83`/`3F8A`. It stores the result in `M(8190)`.

So this is **remote provisioning over the DLC link**: the accept list, the
credit divisor and the rest of `850D`–`8515` can all be set from the far
end. Which is exactly consistent with §10q — those cells are
battery-backed, and the ROM only seeds defaults at cold start.

**Still unnamed:** `558D`, the per-character validator, and `38CB`, which
assembles the byte that gets popcounted.

## 10ac. `test_dial_and_reader` (`0x5370`)

The dial-and-reader test from the technician menu. It displays
בדוק חוגה / קורא (*check dial / reader*), then runs a pattern while
polling for keypresses and servicing the card reader.

```
5370  M(8074) = 0
5377  GHI RF / LBZ 5380      RF.1 != 0 -> SCAL 3658(0x20), a reader command
5380  M(8029) &= ~0x20       clear the link's "message ready" bit (§6)
5389  SCAL 290A(805B, 0x20, 0x0010)   memset DOWNWARD -> 804C..805B spaces
5393  SCAL 6E6B, desc 6645   "בדוק חוגה / קורא"
53AC  SCAL get_key_with_timeout(25)

      loop from 53C8:
53CD    LDA R7 / STR R5      next pattern byte -> M(8033)
53CF    LDA R7 / STR R6      next byte         -> M(812B)
53D1    SCAL get_key_with_timeout(1)
53D9    M(8074) == 0xAA ?    -> show desc 67B6, line 2 from 804C, dwell 50
53EB    SCAL 5F35            the card reader dispatcher wrapper
```

### The pattern table at `6D17`

Twelve 2-byte pairs — a value for `M(8033)` and a hold count for `M(812B)`,
which is **24 in every entry**:

```
3C 3C 3D 3E 3E 3D 3C 29 39 39 29 3C
```

Low five bits: `11100 11100 11101 11110 11110 11101 11100 01001 11001 11001
01001 11100`. Those are the same low bits of `M(8033)` that
`read_hardware_straps` drives (§10k), so this walks that field through a
fixed sequence while the technician exercises the dial and inserts a card.
What the lines physically reach is still not established.

### A tension worth flagging

`M(8074)` is named `hardware_version`, from `read_hardware_straps`, which
clears it and ORs in five strap bits — a value of `0x00`–`0x1F` that
`show_version_and_comm` renders as two decimal digits (§10k, §10j).

Here the **same cell** is cleared at `5370` and then tested for **`0xAA`**,
which is not a 5-bit value. So either this test reuses it as a scratch
"result ready" flag, or the `hardware_version` reading is too confident.
Both uses cannot be the cell's only purpose, and nothing yet decides which.

Sole caller: `77F0`, in the technician-menu block around `77F4`.

## 10ad. `update_low_credit_warning` (`0x524F`)

Decides each tick whether the card still has enough credit, and raises or
tears down the warning. Called from `2DCF` inside `FUN_2D10`, the per-tick
update — so it runs on **every** `service_tick`.

```
524F  M(8065) = 0
5256  M(8144) == 0          -> 52B8, the clear path
525E  M(8144) bit 7 clear   -> 52B8
5263  SCAL get_scaled_credit        result also left in RC.0 by PLO at 5267
5268  SMI 0x64 / LBDF 5277          scaled credit >= 100  -> ENOUGH
526E  SCAL credit_times_rate_ge_1000
5272  SMI 0x14 / LBNF 528B          0 -> NOT ENOUGH, 20 -> ENOUGH
```

**Two independent routes to "enough":** scaled credit ≥ 100, or
credit × rate ≥ 1000. Only failing both reaches `528B`.

| Path | Effect |
|---|---|
| **Enough** (`5277`) | `M(806B)`, `M(8184)`, `M(814A)` all cleared, then fall into the clear path |
| **Not enough** (`528B`) | suppressed if `M(806B) == 0xAA`; skipped if `M(8184) != 0` (already warned); else `M(8184) = 0xAA`, `M(8149) = (M(8149) & 0x40) \| 0x80`, and `M(814A) = 0xFE` if it was zero |
| **Clear** (`52B8`) | if `M(8149)` bit 7 is set, clear it and call `setFlags_8033_and_8036` |

### `M(814A) = 0xFE` is a two-tick arm

The caller consumes it immediately: `2DD3` reads `M(814A)`, increments it
when non-zero, exits when it wraps to 0, and otherwise displays descriptor
`6576`. `0xFE` therefore gives exactly **two** ticks of display.

And `6576` is another **self-referential cycle** — `6576 → 645A → 6576`,
dwell `0x0F` each — alternating line 2 between the RAM credit buffer at
`804C` and the text `6B22`, **`"0 ----> "`**. So the warning flashes the
remaining credit against an arrow toward zero.

That is the third self-referential descriptor chain found (§10l, §10b): the
display list uses them wherever a message has to persist without the code
re-issuing it.

### The guard is on contested ground

`M(8144)` gates the whole routine, and that cell's meaning is disputed —
§1a ties it to the credit screen, §10t reads it as "the dial pulse
arrived". Nothing here settles it; this routine only needs it non-zero with
bit 7 set.

## 10ae. `step_state_machine` (`0x5227`) — a table-driven transition engine

Advances a state machine, but only when its input has changed. Returns
`0xFF` if it stepped, `0` otherwise. Takes a **2-byte inline pointer** to a
descriptor.

```
5227  SEX R3 / RLXA RE        RE = the descriptor pointer, inline
522E  LDN RC / SEX RC / IRX / XOR     M(8866) ^ M(8867)
5232  LBZ 524A                nothing changed -> return 0
5235  LDX / DEC RC / STR RC   M(8866) = M(8867), update the shadow
5238  LDN RC with RC = 886A   the input value
523E  SCAL classify_into_range
5243  SCAL next_state_from_table
5247  LDI 0xFF
```

### The descriptor is two words

Both callees do `SEX RE / RLXA`, which **advances `RE`**, so they consume
one word each:

| | |
|---|---|
| `desc[0]` | range table — read by `classify_into_range` (`328E`) |
| `desc[1]` | state table — read by `next_state_from_table` (`3270`) |

The call at `54FA` passes `3220`, where those words are `32CD` and `325C`.
**`3218` is an array of such descriptors** — `32C5`/`323C`, `32BF`/`3224`,
`32CD`/`325C` — so the routine is generic and `3220` is one entry.

### The two halves

**`classify_into_range`** walks the range table in **pairs** — two `LDA RC`
per iteration, a lower and an upper bound — counting into `RD` until a zero
entry ends the table, and stores the index in `M(886B)`. It answers "which
bracket does `M(886A)` fall into".

**`next_state_from_table`** computes `M(886B) + 4 * M(886C)`, indexes the
state table with it, and writes the result back to `M(886C)`. Four columns,
indexed by *(current state, input bracket)* — a transition table.

| Cell | Role |
|---|---|
| `8866` | previous value — the change-detection shadow |
| `8867` | current value |
| `886A` | the input the bracket is computed from |
| `886B` | bracket index |
| `886C` | **the state** |

### What the caller does with it

```
5500  LBZ 39E5              did not step
5503  M(886C) != 4 -> 39E5  only state 4 proceeds
550D  SCAL 0100             sample EF3, the hook switch
5514  INP 1 / ANI 0x40      port 1, bit 6
```

State 4 is the trigger, gated further on the hook and on port 1 bit 6.

**That is a second input use of port 1** — `45E1` reads its bit 0 into
`M(8191)` — so port 1 carries at least two sense lines, alongside being
driven as an output by `flush_output_latches` (§10u).

**Not established:** what `M(886A)` measures, so neither the brackets nor
the states have meanings yet. The neighbourhood is tariff and credit code,
so a duration or pulse count would fit, but nothing here shows it.

## 10af. `digits_to_binary16` (`0x5000`)

Converts a run of decimal **digit values** at `R5` into a 16-bit binary
number in `RC`. The count is a 2-byte inline argument.

```
5003  RC = 0
5007  LBR 5022              enter at the ADD, so the first pass is 0*10 + d

      loop body:
500C  SCAL shift_rc_left16  RC *= 2
5010  SCAL shift_rc_left16  RC *= 4
5014  RC += the pushed value           -> 5x
501E  SCAL shift_rc_left16             -> 10x
5022  RC = 10x + M(R5), R5++
502C  DBNZ RD,500A
```

The classic `RC = RC*10 + digit`, with the ×10 built as `(x*4 + x)*2`
because `shift_rc_left16` (`3876`) is the only primitive available — it
shifts `RC` left one bit via `GLO/SHL/PLO` then `GHI/RSHL/PHI` to carry
across the halves.

The input is **digit values, not ASCII**: nothing subtracts `0x30`. That
matches `parse_digits_into` (§10ab), which also produces values.

### The count must be `b,b`, not `w`

Both call sites pass a small number — `0x0003` at `5039`, `0x0004` at
`52E9` — which falls in ROM address range, so `w` would manufacture data
references to addresses 3 and 4. Same trap Codex caught on `290a`.
Declared `5000  b,b`.

### Callers

| Site | Setup |
|---|---|
| `5039` | `R5 = 8024`, count 3 — the reader digit cells `8024`–`8026`, so this turns a reader numeric suffix into a binary value |
| `52E9` | count 4 — the caller unpacks nibbles onto the stack at `52D8`–`52E3` first |

The second is worth noting. After converting, `GHI RC / LBNZ 52B8` bails if
the value exceeds 255, then `GLO RC / LBR 5268` jumps **into**
`update_low_credit_warning` at its "scaled credit ≥ 100" test (§10ad). So
there is an alternative entry to the credit comparison that supplies a
4-digit decimal value instead of `get_scaled_credit`'s output.

## 10ag. `wait_idle_then_blank_display` (`0x3831`)

Blocks until two pending conditions clear, then tidies the display — unless
the display is being held.

```
3833  IDL                     wait for the next interrupt
3834  M(812F) != 0 -> 3833    a countdown still running
383C  M(8863) != 0 -> 3833    a flag still set
3844  M(8167) & 0x20          the display-hold flag
384B  LBNZ 3854               held, so leave the screen alone
384E  SCAL BlankDisplayAndClear8036Bit6
3852  IDL / IDL               two ticks for it to render
```

The `IDL` in the loop makes this a **tick-paced wait**, not a spin.
`M(812F)` is driven by the timer machinery — set to 50 at `497A` in
`wait_and_triage_state`, cleared at `493B` — and `M(8863)` is set to `0xAA`
at `3567`.

### Bit 5 of `M(8167)` is a session-wide display-hold flag

Not local to this routine. It is **tested at fourteen sites**, six of them
inside the supervised-operation engine at `1ABE` (`1ACE`, `1AF2`, `1B19`,
`1B3D`, `1B67`, `1BB4`), plus `2702`, `3844`, `402A`, `5C9C`, `5E2C`,
`72E7` and `74B1`. Written by `LDI 0x20` at `4D8E` and `5F75`, `LDI 0xC0`
at `31BC`, `LDI 0x80` at `4551`, `LDI 0x00` at `45AD`.

Two uses pin its sense: `init_comm_session` (§10v) takes the longer timeout
and puts בתקשורת on screen when the bit is **set**, and this routine
declines to blank when it is **set**. Both read as *"a message is up, leave
it"*.

Sole caller: `5C57`, in `FUN_5BFD`, immediately before the first
`GuardOrAbortCaller` call at `5C5B` (§10h). So the fault-reporting sequence
waits for the machine to go quiet and clears the screen before starting.

## 10ah. `increment_decimal_counter` (`0x3806`) and the totalizer bank

Adds 1 to a multi-digit **decimal** counter at `RD`, propagating the 9→0
carry. The digit count is a 1-byte inline argument; the base comes in `RD`.

```
3806  LDN R3 / PLO RC / PHI RC   both halves of RC = the digit count
3809  LDN RD / SMI 0x09          current digit == 9 ?
380C  LBNZ 3829                  no  -> M(RD) += 1, done
380F  GLO RC / LBZ 381D          out of digits -> the wrap path
3813  DEC RC / LDI 0 / STR RD / INC RD / LBR 3809
                                 yes -> zero it, carry upward
382D  INC R3                     step over the inline byte
```

**Digits are stored least significant first** — the carry walks *upward*
with `INC RD`, so the lowest address holds the units. The values are digit
*values*, not ASCII: the comparison is against `9`, not `'9'`. Same
convention as `digits_to_binary16` (§10af) and `parse_digits_into`
(§10ab).

### Four counters, contiguous

| Base | Digits | Bumped at |
|---|---|---|
| `8516` | 4 | `429D` |
| `851A` | 6 | `4233` |
| `8520` | 6 | `2D24` |
| `8526` | 6 | `36CE` |

`8516`+4 = `851A`, +6 = `8520`, +6 = `8526`, +6 = `852C`. So
**`8516`–`852B` is one 22-digit bank of totalizers**, sitting immediately
after the provisioning block at `850D`–`8515` (§10q). That tightens the
`85xx` map considerably:

```
8500         from M(0D00)
850D..8515   provisioning: accept list, divisors
8516..852B   four decimal totalizers
852C..       a buffer the technician menu edits (4E35 onward)
```

### Who bumps what

| Site | Context |
|---|---|
| `2D24` | `FUN_2D10`, the per-tick update |
| `36CE` | `FUN_36C2`, which also sets `M(88BD) = 0xAA`; called from the reader dispatch handlers at `342B`, `344C`, `3460`, `3496` |
| `4233`, `429D` | both inside `FUN_420E` — the same routine that increments `845A` and `885D`, the counters `periodic_report_check` tests against 45 (§10s) |

So these are **event totalizers**, and the `420E` pair in particular move
on the same event as the every-45 counters.

**Two of the four are now identified.** `851A` is a **minute meter**: §10ai
shows the `4233` site fires once per 60 ticks of off-hook time with a valid
card, and §10aj makes the tick exactly one second. `8526` counts **card units
burned** — §10ak works out the call pattern of `account_one_unit_spent`, the
only caller of `increment_decimal_counter` for that base.

`8520` is bumped at `2D24`, the first thing `apply_charge_and_refresh_display`
does when a metering pulse arrives, so it counts **charged periods** — one per
pulse, before any exemption test. `8516` remains unidentified. Dumping
`8500`–`852B` from a live unit would still settle the units each one is kept in.

None of the four can be renamed over the MCP — see the caveat in §11.

## 10ai. `meter_and_drive_line` (`0x420E`) — and what the counters count

**Not a called function.** Entered by `LBR 420E` from `415B`, leaving by
`LBR 4A12` at `43E5` — one segment of a straight-line per-tick chain. Four
jobs.

### 1. Duration meter (`420F`–`4237`)

```
420F  SCAL 0100             sample EF3, the hook switch
4216  M(8139) == 0          -> skip
421E  ANI 0x96 / LBZ        -> skip
4223  M(811D) != 0          -> skip, still counting down
422B  M(811D) = 0x3C (60)   reload
422E  increment_decimal_counter(851A, 6 digits)
```

`M(811D)` is one of the eight cells in the soft-timer table at `40D6`
(§10y), so the tick decrements it. The slow tick is **exactly 1 Hz**
(§10aj), so **`851A` advances once per 60 seconds of off-hook time with a
valid card — it is a minute meter**, matching per-minute charging.

### 2. Pulse counter (`4238`–`4276`) — this settles §10s

```
4240  LDN R7 / PLO RD       RD.0 = M(8078), the PREVIOUS sample
4243  INP3 / ANI 0x80       read PORT 3, BIT 7
4246  STR R7                M(8078) = the new sample
4247  LBZ 426F              clear -> clear bit 7 of M(8033)
424E  GLO RD / LBNZ 4273    previous non-zero -> no edge
4252  M(845A) += 1
425A  M(885D) += 1
4263  SCAL 1C5F             bumps the 97xx varC counters
```

A **rising-edge detector on port 3 bit 7**. So `845A` and `885D` count
**pulses, not completed calls**.

§10s guessed "completed calls" from the `SCAL 0100` at the top of this
stage — but that call belongs to job 1, and **every branch out of the
`ANI 0x96` test rejoins at `4238`**, before the detector. The pulse reading
is what the code shows. So `periodic_report_check` fires every **45
pulses**.

**Port 3 bit 7 is therefore a pulse input**, alongside bit 6 which
`read_hardware_straps` uses as the strap sense (§10k).

### 3. Second meter (`4277`–`42A4`)

Gated on the hook, `M(8144)`, `M(8139) & 0x96` and `M(811F)`, it bumps the
**4-digit** counter at `8516` and latches `M(811F) = 1`, so it counts once
per arming rather than once per tick.

### 4. Output sequencer (`42B2`–`43E5`)

With `R7 = 8033`, `R8 = 8032`, `R5 = 8149`, `R6 = 8132`, it switches on the
low three bits of `M(8149)` and on bits 3–5 against `0x28`, writing
patterns into the **low six bits of `M(8033)`** while preserving the top
two with `ANI 0xC0` — values `0x01`, `0x08`, `0x0A`, `0x0C`. It loads
`M(8132)` with 100 or 10 as a dwell and clears the group at
`8147`–`8149`.

That is the same `M(8033)` low field `read_hardware_straps` drives (§10k)
and `test_dial_and_reader` walks (§10ac). A state machine driving it during
call progress is the strongest evidence yet that the field is a genuine
output — though what it reaches is still unknown.

## 10aj. The timebase — the slow tick is exactly one second

The board's crystal nearest the CPU reads **2.4576 MHz**, and that settles
the whole timing chain to the integer.

```
2,457,600 Hz  / 4096  =  600 Hz     EF1
          600 /   12  =   50 Hz     base tick
           50 /   50  =    1 Hz     slow tick
```

| Stage | Where it is in the ROM |
|---|---|
| ÷ 4096 | **not in the ROM** — external, and 4096 = 2^12 is one CMOS ripple counter |
| ÷ 12 | `STPC` / `LDI 0x0C` / `LDC` / `SCM1` at `05D7`, `4079`, `6EEC`. `SCM1` clocks the 1806 counter from **EF1**, and the counter is loaded with 12 |
| ÷ 50 | the prescaler at `40F4`: `M(8130)` counts to `0x32` before the slow table is touched (§10y) |

**Every division is exact**, which is the strongest argument for it. The
alternatives do not land anywhere sensible: EF1 at mains 50 Hz would make
`M(811D) = 60` into **12 minutes**, and 100 Hz into 6.

### What that makes the timers

| Cell | Value | Meaning |
|---|---|---|
| `811D` | 60 | **60 seconds** — the `851A` duration meter's interval (§10ai). *Not* the charge interval: §10ak shows charging is driven by the exchange's metering pulse, not by this timer |
| `8131` | 30 | 30 s |
| `8134` | 90 | 90 s, the `arm_timer_set` lifetime (§10y) |

Israeli calls were charged by the minute, and `meter_and_drive_line` bumps
the 6-digit counter at `851A` once per `M(811D)` expiry. **So `851A` is a
minute meter** — a *statistic*, though, not the billing mechanism. §10ak shows
the money comes off the card on the exchange's metering pulse; nothing in the
charging path reads a timer.

### The same crystal sets the baud rate

§6 records that the UART's baud rate is not in the control register, so it
comes from an external clock. 2.4576 MHz is the canonical UART crystal:
÷16 = 153,600 Hz = 16 × **9600 baud**, with ÷32 and ÷64 giving 4800 and
2400. One crystal serves both the serial links and, through the divider,
the timebase.

### The caveat

The ÷4096 divider is **inferred, not observed** — it is off-chip and no
instruction touches it. What the ROM fixes is the ÷12 and the ÷50; the
crystal fixes the input. The inference is that the only divider making all
three stages exact is a power of two, and 4096 is the one that lands on
1 Hz. Confirming it means finding the divider chip on the board and
checking EF1 with a scope.

## 10ak. How the card gets debited — and when it is actually burned

**The card is written during the call, within one tick of each charge, not at
hangup.** And the charge clock is not in the phone: it is the exchange's
metering pulse.

### The chain, end to end

| Step | Where | What happens |
|---|---|---|
| 1 | `detect_metering_pulse` (`3733`) | a pulse on **port 3 bit 0** sets `charge_event_pending` (`M(8143)`) |
| 2 | `apply_charge_and_refresh_display` (`2D10`) stage 1 | `debit_pending` (`M(8145)`) `+=` the divisor |
| 3 | stage 2 | spend `credit_drain_pool` (`M(805D)`) first; when it is dry, `credit_bulk_pool` (`M(805C)`) `-=` N and `burn_units_pending` (`M(8064)`) `= N` |
| 4 | `service_card_reader_link` at `3103` | N = 1 → **`?F`**; N > 1 → **`?EF0NN`** |
| 5 | reply handlers `X` (`3420`) / `Y` (`343C`) | clear `M(8064)`, call `account_one_unit_spent` → totalizer `8526` |

Step 4 is the burn, and it goes out on the **next tick after the debit**. There
is no "remember it and settle on eject" anywhere in that path.

### 1. The charge comes from the line, not from a timer

`detect_metering_pulse` is called from `meter_and_drive_line` at `42AA`, which
is on the **50 Hz base tick** — the `1 Hz` slow tick is only the prescaler at
`40F4`, and the chain runs on past it to `LBR 420E` at `415B`. So every count
in this routine is a 20 ms sample.

```
3741  INP3 / ANI 0x01          port 3 bit 0
3744  clear -> 32DB            the release path
374F  M(816B) == 0x55 -> ret   three inhibits
3759  M(8DC5) == 1   -> ret
3763  M(8180) != 0   -> ret
376C  M(8070)++                while the input is high
3773  M(8070) >= 0x19 -> 32D5  RF.0 = 0x81, temporary fault

32DB  M(8071)++                while it is low
32E5  M(8071) < 2 -> ret       2 quiet samples = 40 ms confirms release
32E9  M(8070) < 4  -> discard  under 80 ms is noise
32EF  M(8070) >= 0x19 -> fault
32F4  -> 377B                  A VALID PULSE
377B  M(8143) = 1
```

So **a high of 4–24 samples — 80 to 480 ms — bracketed by 40 ms of release is
one charge event.** That is an exchange metering pulse, and the window is about
right for the European 100–200 ms convention. Anything held past ~500 ms is
rejected as a stuck line.

**Nothing in the charging path consults a clock.** `M(8145)` is written only by
`2D54`, inside stage 1; `M(8143)` is set only at `37A0`. The 60-second timer
`minute_meter_timer` and the counter it drives (`851A`, §10ai, §10aj) are a
**duration meter** — they never touch either cell. Per-minute billing in Israel
therefore came from the exchange sending one pulse a minute; the phone needs no
tariff clock, which is also why nothing here reads `8122`/`8124` (§10aa).

`377B` does one more thing worth noting: at `37A1`–`37AA` it **swaps the two
rate words** at `8122`/`8124` (`RLXA RD` / `IRX` / `RSXD RD`). Whatever that
pair is, it alternates on every charge event.

### 2. Two pools, and only one of them costs a card write

`credit_value` (`M(805E)`) is **the sum of two bytes**, computed at `2DB1`:

```
2DB1  LDA R5        D = M(805C), R5 -> 805D
2DB2  SEX R5        X = 805D
2DB3  ADD           D = M(805C) + M(805D)
2DB4  INC R5 / STR R5   M(805E) = the sum
```

(The decompiler renders this as `M(805C) * 2`; it mismodels the `SEX`. The
disassembly is unambiguous.)

Stage 2 spends them differently:

| Pool | How it is spent | Card traffic |
|---|---|---|
| `credit_drain_pool` (`805D`) | one unit per charge event, in the loop at `2D73` | **none** |
| `credit_bulk_pool` (`805C`) | `M(805C) -= M(8145)` at `2D88`, then N units owed | one `?F`/`?EF` per debit |

A borrow on that subtraction — not enough credit — yields `RF.0 = 0x82`.

So `805D` reads as **credit already committed to the card**, and `805C` as
credit still sitting on it. The names chosen are deliberately mechanical; see
the open question below.

### 3. The burn command

The link machine's **resting state is `M(8031) = 0xFF`**, installed by `31EE`
after every completed exchange. `3989` reads the state, `398D` adds one, and the
`LSZ` at `3100` falls through to `3103` only for `0xFF`; every other value is a
**resume-address low byte**, jumped to by `PLO R4` at `3102` (`M(8031)` is now
named `link_resume_point`). The whole link layer is a coroutine in page `31`.

```
3104  D = M(8064)
3105  == 0 -> 3129
3108  SHR
3109  == 1 -> 3114     send ?F      (selector 0x28)
310C                   send ?EF0NN  (selector 0x48)
3119  wait for the reply
3122  M(8064) still set -> state 0x1D, dispatch again next tick
3126  cleared          -> state 0xFF
```

`send_reader_command` builds the `?EF` digits **from `M(8064)` itself** — `3686`
does `DEC R7 / LDA R7` on the `8065` pointer to reach it, and `3689`–`36A9`
converts it to three ASCII digits over the template's `"000"` (§8). That closes
the loop: the number on the wire *is* the number of units just taken off the
balance.

**Why `F` and `EF` are the burn.** The reader's own TE menu names it: *TE8 —
Adjustment of erasure power ( **P1/F** )*, and TE9–13 are *Adjustment of
erasure/reading* (`../card-reader/BSK31-firmware.md` §10). Optical cards are
decremented by burning spots, `F` is the erasure letter, `EF` carries a count,
and the phone picks `?F` for exactly one unit and `?EF` for more. The reader-side
handlers (`0CD9` for `F`, `10E6` for `EF`) have **not** been read — the BSK31
ROM is not in this repo — so that is the one confirming step left.

### 4. The watchdog

While `M(8064)` is non-zero, stage 3 runs instead of stage 2:

```
2D9C  M(806C)++; < 50 -> out      50 base ticks = exactly one second
2DA5  M(806C) = 0; M(8063)--
2DA9  M(8063) == 0 -> RF.0 = 0x93
```

`burn_watchdog_units` starts equal to the unit count, so the reader gets **one
second per unit** to acknowledge. The `50` here is independent confirmation that
this chain is the 50 Hz one (§10aj).

### 5. `?CC` — the one bulk settlement, and it is not at hangup

`service_card_reader_link` has a second path, `3924`–`3958`, gated on four
things: `M(8067)` bit 0 set, no burn in flight, **`M(814A) != 0` — the low-credit
warning is up** (§10ad) — and `M(805C) != 0`. Miss any and `3981` clears the
request.

```
3932  M(8065) = M(805D)            save
3935  M(805D) = M(805E)            = M(805C) + M(805D), the whole balance
3941  RE.0 = M(805C); M(805C) = 0  collapse bulk into drain
3945  M(8031) = 0                  stop the link machine
394B  account_one_unit_spent x M(805C)
3954  send ?CC
```

Total credit is **preserved** — it moves, it is not spent — and afterwards every
charge comes out of `805D`, the path that writes nothing to the card. So `?CC`
reads as *"commit the remaining units now"*: a pre-burn of the tail of the card
once it is nearly empty, which is exactly when yanking power would otherwise be
worth trying.

`M(8067)` bit 0 is raised by `FUN_4A12` at `4AB9`, after **port 1 bit 3** reads
high for three consecutive ticks — a shift register seeded with `0x20` at
`4AAD`, shifted left each pass, with bit 0 ORed in once the `0x80` falls out.
That is **a third sense line on port 1**, alongside bit 0 (→ `M(8191)`) and
bit 6 (§10af). What it is has not been identified.

**Not established:** what `CC` does inside the reader (handler `139F`).

### 6. `36C2` is a unit counter, not a stepper pulse

§7 guessed `36C2` was the stepper single-step pulse. It is not — the stepper is
in the reader's own ROM, on its own CPU. `account_one_unit_spent` sets
`M(88BD) = 0xAA` and bumps the six-digit totalizer at `8526`, and the call
pattern is a *count*:

| Caller | Calls | Reading |
|---|---|---|
| `X` reply (`3428`) | once, after `M(8064) = 0` | one unit acknowledged |
| `Y` reply (`3449`) | once, same | same, degraded (`M(818D)++` instead of `= 0`) |
| `MZ` reply (`3460`) | exactly twice (`DBNZ RE`, `RE = 2`) | |
| `MO` reply (`3496`) | once per unit of difference between the value the reader reports and `card_units_shadow` (`M(806A)`), then `M(806A) =` that value | **reconciliation** |
| `?CC` flush (`394B`) | once per unit moved out of `805C` | |

`MO` settles it: the reader states the card's remaining units and the phone
accounts for the gap. That only makes sense if the argument is units. **So
`8526` is the cumulative count of card units burned** — one of the four
totalizers §10ah could not identify.

### 7. Who starts the link machine

Also settled here, because it was needed to prove `0xFF` is reachable. The `RY`
("ready") reply handler at `3389` does it:

```
3389  D = M(805C); == 0 -> 3391
338D  M(8065) = M(805C); M(805C) = 0
3391  M(8031) = 0x36                 -> resume at 3136
3395  clear_block(8022, 0x26)
```

`3136` sets `M(8069) = 0x55` ("command outstanding", §10l) and sends `?CD007`
or, if `M(802A)` is set, `?CE007`; the exchange then walks `3152` → `3178` →
`318C` (`?MD`) → `31AB` and finally reaches `31BA` → `31EE`, which installs
`0xFF`. From then on the link is idle-but-ready and the burn check at `3103`
runs every tick.

The three external writes of `M(8031)` are all `0xD8` (`47B4`, `4C1A`, `728C`),
which resumes at `31D8` — clear the state, clear `805C`, **send `?EJ`**. Status
`0x81` (temporary fault) takes that route, from `4C14`.

### The open question this leaves

**Nothing in the ROM ever loads a positive value into `805C` or `805D`.** Every
write found is a decrement, a zero, or the `?CC` move that only shuffles between
them:

| Site | Write |
|---|---|
| `2D77` / `2D8C` | decrement |
| `3935` / `3941` | the `?CC` move, net zero |
| `31E1`, `3390`, `3944`, `47A3`, `47AD`, `4C26`, `4C9D`, `5FCB` | `= 0` |

Searched and ruled out: every `RLDI Rn,805C`/`805D`/`805E` in the image; `805C`
and `805D` as `SCAL` inline pointer arguments; `746D`, which turns out to be a
**block clear**, not a copy (`7483`–`7487` fills downward with zero) so all three
of its call sites only clear; and both RAM-resident payloads (`040D` → `9733`,
`3011` → `9771`), which touch only `F000` and the checksum cells.

With both pools at zero the first charge event borrows at `2D88` and returns
`RF.0 = 0x82`, so an unloaded phone simply reports "no credit" — self-consistent,
but it means **the step that reads a card's value and turns it into spendable
credit has not been found.** The card's raw read *is* understood —
`card_value_7_minus_popcount` (`M(8062)`) from the `CA`/`CB`/`CO` handler, and
`card_units_shadow` (`M(806A)`) from `MO` — but neither feeds `805C`. Candidates
to check next: the `8054`–`805F` region looks like a parsed-reply field area
(`render_credit_indicator` indexes it at `2E98`/`2EB1`, and `290A` is called with
`805B` as a pointer at `538D`, `57BB` and `5872`), so the loader may be a field
copy out of a reply rather than a named store.

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
`FUN_365c` → **`send_reader_command`**; `proc_279a` →
**`LCD_RenderNextDescriptor`** (§10b); `FUN_744f` →
**`is_out_of_service_state`** (§10c); `FUN_4d1c` →
**`clear_state_if_transient`**; `FUN_48e8` → **`wait_and_triage_state`**;
`FUN_5f67` → **`show_fault_log`** (§10d–10e);
`FUN_2aab` → **`FormatCardDigitsToAscii`**; `FUN_1a26` →
**`InitBuffer8119`**; `FUN_2c81` → **`LoadBuffer8119`**; `FUN_2c6e` →
**`WaitForBuffer8119`** (§10g); `FUN_5df9` →
**`GuardOrAbortCaller`** (§10h); `FUN_609c` →
**`show_version_and_comm`** (§10j); `FUN_6173` →
**`read_hardware_straps`** (§10k); `FUN_36b0` → **`PackCardNibbles`**
(§10m); `FUN_5e8b` → **`show_fault_entry`**;
`proc_29e7` → **`show_optical_reader_fault`** (§10n);
`FUN_2a0c` → **`detect_cleaning_card`**; `FUN_5e6e` →
**`store_byte_84xx`** (§10o); `FUN_2c97` →
**`build_report_template`** (§10r); `FUN_2cf0` →
**`register_cleaning_event`** (§10o); `FUN_769c` →
**`periodic_report_check`**; `FUN_04f0` → **`increment_counter16`**
(§10s); `proc_75f9` → **`flush_nopulse_fault_counter`** (§10t);
`proc_7572` → **`flush_output_latches`** (§10u);
`FUN_74a7` → **`init_comm_session`** (§10v);
`proc_728a` → **`service_tick`**; `FUN_3900` →
**`service_card_reader_link`** (§10w); `FUN_533e` →
**`get_scaled_credit`**; `FUN_38e3` → **`divide_by_3`**;
`FUN_52f7` → **`credit_times_rate_ge_1000`**; `FUN_389a` →
**`compare_words16`** (§10aa); `FUN_5426` →
**`parse_config_record`**; `FUN_54b5` → **`parse_digits_into`** (§10ab);
`proc_5370` → **`test_dial_and_reader`** (§10ac);
`FUN_524f` → **`update_low_credit_warning`** (§10ad);
`FUN_5227` → **`step_state_machine`**; `FUN_328e` →
**`classify_into_range`**; `FUN_3270` → **`next_state_from_table`** (§10ae);
`proc_5000` → **`digits_to_binary16`**; `FUN_3876` →
**`shift_rc_left16`** (§10af); `FUN_3831` →
**`wait_idle_then_blank_display`** (§10ag); `proc_3806` →
**`increment_decimal_counter`** (§10ah); `FUN_420e` →
**`meter_and_drive_line`** (§10ai).

The timebase is worked out in §10aj: the slow timer tick is exactly 1 Hz.

Renamed from an earlier, inaccurate name:
`LoadEmptyLine_AND_8036_with_0xBF` → **`BlankDisplayAndClear8036Bit6`**
(§10x).

`proc_70ce` → **`arm_timer_set`** (§10y).

`FUN_3733` → **`detect_metering_pulse`**; `FUN_2D10` →
**`apply_charge_and_refresh_display`**; `FUN_36C2` →
**`account_one_unit_spent`**; `FUN_2E71` → **`render_credit_indicator`**
(all §10ak).

### Data named

| Address | Name | § |
|---|---|---|
| `7BFA` | `sw_version_major` | 10j |
| `7BFB` | `sw_version_minor` | 10j |
| `8024` | `reader_digit0` | 10m |
| `8025` | `reader_digit1` | 10m |
| `8026` | `reader_digit2` | 10m |
| `8033` | `strap_drive_and_flags` | 10k |
| `8037` | `LCD_verify_errcount` | 10b |
| `8038` | `LCD_next_descriptor` | 10b |
| `803A` | `LCD_dwell_countdown` | 10b |
| `803B` | `LCD_last_command` | 10b |
| `803C` | `display_scratch_803c` | 10j |
| `804C` | `display_scratch_804c` | 10j |
| `8060` | `card_packed_byte` | 10l |
| `8062` | `card_value_7_minus_popcount` | 10l |
| `8069` | `card_session_status` | 10l |
| `8074` | `hardware_version` | 10k |
| `8139` | `card_permission_bits` | 10p |
| `8514` | `credit_divisor` | 10aa |
| `811A` | `buf8119_ptr` | 10g |
| `811B` | `buf8119_end` | 10g |
| `8185` | `port3_readback` | 10k |
| `840A` | `fault_log` | 10e, 10i |
| `8448` | `cleaning_event_record` | 10o |
| `844D` | `coldstart_sentinel_844d` | 10q |
| `850E` | `accept_list_count` | 10p, 10q |
| `850F`–`8512` | `accept_list_0` … `accept_list_3` | 10p, 10q |
| `867B` | `coldstart_sentinel_867b` | 10q |
| `89FA` | `stack_top` | 10q |
| `805E` | `credit_value` | 10aa |
| `8078` | `pulse_prev_sample` | 10ai |
| `811D` | `minute_meter_timer` | 10ai, 10aj |
| `8122` | `rate_word_a` | 10aa |
| `8124` | `rate_word_b` | 10aa |
| `8130` | `timer_prescaler` | 10aj |
| `814A` | `low_credit_display_arm` | 10ad |
| `8167` | `mode_flags_8167` | 10ag |
| `8184` | `low_credit_warned` | 10ad |
| `8190` | `config_parse_result` | 10ab |
| `845A` | `pulse_count_event` | 10ah, 10ai |
| `885D` | `pulse_count_report` | 10ah, 10ai |
| `8866` | `sm_change_shadow` | 10ae |
| `8867` | `sm_change_current` | 10ae |
| `886A` | `sm_input_value` | 10ae |
| `886B` | `sm_bracket` | 10ae |
| `886C` | `sm_state` | 10ae |
| `8031` | `link_resume_point` | 10ak |
| `805C` | `credit_bulk_pool` | 10ak |
| `805D` | `credit_drain_pool` | 10ak |
| `8063` | `burn_watchdog_units` | 10ak |
| `8064` | `burn_units_pending` | 10ak |
| `806A` | `card_units_shadow` | 10ak |
| `806C` | `burn_watchdog_ticks` | 10ak |
| `8070` | `metering_high_count` | 10ak |
| `8071` | `metering_low_count` | 10ak |
| `8138` | `charge_step` | 10ak |
| `8143` | `charge_event_pending` | 10ak |
| `8145` | `debit_pending` | 10ak |

Names reflect what the code **does** with a cell, not an assumed purpose:
`card_value_7_minus_popcount` records the computation at `33D4` rather than
claiming the byte is a credit balance, and `strap_drive_and_flags` avoids
calling `8033` a port latch, which §10k shows is unproven.

**Still unnamed, meaning not established:** `8030` (the mode byte tested
against `0x10` at `45CD`), the timers and flags `812F`, `8131`, `8149`,
`8165`, `816C` (§10e), `845D` (cleared before the reset shortcut,
§10j), `97A6` (set when a fault counter hits its threshold, §10i), the
three flags the idle selector reads at `8191`, `8501` and `81B5` (§10l), and
the config bytes `850D`, `8500`, `8513`–`8515` (§10q) — of which only `8513`
has a known consumer, `M(813A) = M(8513) - 1` at `1A52`.

A caveat on the MCP: `rename_data` always answers "Rename data attempted",
which says nothing. Verify by decompiling a function that references the cell
and checking the symbol appears — `read_hardware_straps` shows
`hardware_version`, `strap_drive_and_flags` and `port3_readback`, and
`LoadStringForDisplay` shows `LCD_next_descriptor`. `list_data_items` is the
cheaper check: it is address-ordered, so one page covers a whole RAM block.

**The totalizer bank cannot be named over the MCP.** `851A`, `8516`, `8520`
and `8526` (§10ah) have no defined data and no label, because the only way the
code names them is as the inline-argument bytes of an
`increment_decimal_counter` call — Ghidra sees instruction-stream bytes, not an
operand, so it never creates a reference or a label there. `rename_data`
answers "Rename data attempted" and changes nothing, and `list_data_items`
skips straight from `8515` to `852C`. These four need labelling by hand in the
GUI; the names the notes use are `minute_meter` (`851A`), `counter4_8516`,
`counter6_8520` and `counter6_8526`.

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

## 12a. Prior work by the author

The owner of this project published a Hebrew write-up of the earlier phase of
this work, which is worth reading for provenance and for the hardware-side
experiments that the firmware analysis here builds on:

- [מסתבר שגם טלפון ציבורי הוא טלפון חכם](https://www.retro.unarmedsecurity.net/post/%D7%9E%D7%A1%D7%AA%D7%91%D7%A8-%D7%A9%D7%92%D7%9D-%D7%98%D7%9C%D7%A4%D7%95%D7%9F-%D7%A6%D7%99%D7%91%D7%95%D7%A8%D7%99-%D7%94%D7%95%D7%90-%D7%98%D7%9C%D7%A4%D7%95%D7%9F-%D7%97%D7%9B%D7%9D)
  (9 December 2024) — acquiring the phone in Binyamina in November 2019,
  picking the case lock, identifying the CDP1806ACE and the Atmel AT29C256,
  dumping the 32 KB image, and writing the Ghidra processor module.

Three points from that post corroborate findings reached here independently
from the firmware:

| Blog observation | Firmware confirmation |
|---|---|
| The LCD is "a completely standard LCD" and **Arduino LCD libraries drive it** | Arduino's `LiquidCrystal` *is* an HD44780 driver. §10b identifies the controller from the instruction bytes the firmware writes (`0x80\|addr`, `0xC0`, `0x0C`). |
| "The string length is set by the phone's screen width" | That width is the `strModifierLen` field at descriptor `+1`, `0x0010` = 16, and overflow wraps to line 2 via `0xC0`. |
| "The Hebrew string encoding is non-standard" | Hebrew is stored in **display order**, reversed relative to logical order, while Latin is stored forward (§9). |

The post also notes that the author **patched the error routine to render a
failing address to the LCD**, having had no luck tracing it with a logic
analyser, and cites address `4930`. In this image `4930` sits inside a state
machine beginning at `48E8` that switches on `RF.0` (compared against `0x94`,
`0x91`, and `SMI 0x80`), idles on `IDL` between checks, manipulates the
`8034`/`8035` port shadows, and exits either to `5F67` or — via
`4981: LBDF 0x4AF6` — to the **main idle loop**. Reconciling the blog's
`4930` with this routine is still open; it may refer to a different build or
to a file offset.

## 13. Next steps

Moved to [`OPEN-QUESTIONS.md`](../OPEN-QUESTIONS.md) at the repo root, so
there is one queue rather than two that drift apart. It carries every open
item from this file — what is unknown, where the evidence is, and what would
settle it — and separates the questions the ROM can answer from the ones
that need a live phone.
