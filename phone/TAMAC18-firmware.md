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

| Range | Contents |
|---|---|
| `0x0000`–`0x7FFF` | ROM (`code` segment) |
| `0x8000`–`0x9FFF` | RAM (`ram` segment) |
| `0xE000`–`0xE007` | **LCD**, an HD44780 (16x2). `E000` = instruction register, `E001` = data register — see §10b |
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
- **Whether N0–N2 branch anywhere else.** Ports 1, 3 and 4 are still
  unidentified (`INP 1/2/3`, `OUT 4`), and cannot be the UART, so another
  device must decode them.

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
test is decidable, **23 are display order and 1 is logical** (`2AEB`). The
remaining 58 are ambiguous — no final forms, or final forms at both ends — and
default to display order.

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

### `0x91` is a pending state, resolved through `RE`

`7380` holds the only register-mediated write to `RF.0` in the image, and it
is what produces `0x83`:

```
737A  LDI 0x88
737C  LSKP              two-way entry, as at 7440 / 48A0 / 31D0
737D  LDI 0x83
737F  PLO RE            RE.0 = 0x88 or 0x83
7380  GLO RF / XRI 0x91
7383  LSNZ              skip unless the state IS 0x91
7384  GLO RE / PLO RF   RF.0 = RE.0
```

So `0x91` is a **pending** state that resolves to `0x88` (show credit) or
`0x83` (a transient that `clear_state_if_transient` then wipes). That is why
`0x91` is tested six times but never written by an immediate, and why `LDI
0x83 / PLO RF` appears nowhere.

Every *other* `GLO Rn / PLO RF` a byte scan reports is the operand byte of an
`LDI` read at the wrong alignment: `269B` "GLO R4" is the `0x84` of
`LDI 0x84` at `269A`, `2777` "GHI R7" is the `0x97` of `LDI 0x97` at `2776`,
and so on down the list.

### Values that are tested but never produced

`0x25`, `0x26`, `0x85` and `0x91` are equality-tested but have **no
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

**Open:** the contents of the `6069` table, and what the second byte of each
entry holds. The Hebrew technician strings nearby — `69D4` קוד טכנאי:
(*technician code*), `69DF` קוד מכלול (*module code*), `69F0` הכנס קודי הודעות
— belong to this subsystem and are the obvious next thread.

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
`FUN_5f67` → **`show_fault_log`** (§10d–10e).

Data named: `8037` → `LCD_verify_errcount`; `8038` → `LCD_next_descriptor`;
`803A` → `LCD_dwell_countdown`; `803B` → `LCD_last_command`.

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
