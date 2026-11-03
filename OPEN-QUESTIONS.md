# Open questions

A running queue for the reverse engineering. Each item says **what is
unknown**, **where the evidence is**, and **what would settle it** — because
an open question without a next action tends to stay open.

## Conventions

- `- [ ]` open, `- [x]` settled — keep settled items for a while with a note
  on *how*, then prune. The method is often more reusable than the answer.
- **Needs hardware** marks anything the ROM alone cannot decide. Don't burn
  static analysis on those.
- Section references are to [`phone/TAMAC18-firmware.md`](phone/TAMAC18-firmware.md)
  unless they say `card-reader/`.

---

## Hardware and ports

- [ ] **Which devices ports 1 and 4 reach.** `flush_output_latches` (§10u)
      shows them driven as outputs from the shadows at `8034`–`8037`, so they
      are decoded; the question is now what is on the other end.
      *Settle by:* tracing the CPU's N0–N2 decode on the board.
      **Needs hardware.**
- [ ] **What port 5 actually receives.** §10u reads each pair as
      `port n <- M(8033+n)`, but the other flush at `399D` makes
      `port 5 <- M(8034)`. They agree on port 2 and disagree on port 5.
      Either `OUT 5` is a latch-enable whose data is ignored, or the two
      routines drive different devices.
      *Settle by:* scoping port 5's latch while both routines run, or finding
      a third flush site.
- [ ] **How `M(8033)`'s low bits reach the strap hardware.** `read_hardware_straps`
      (§10k) writes them and `IDL`s, but `8033` is flushed by no shadow-flush
      site — `399D` covers only `8034`/`8035`. `flush_output_latches` is the
      best candidate, but it has not been shown to run from the interrupt path.
      *Settle by:* finding what calls `7572`, or scoping the strap lines.
- [ ] **UART pin 4 (CS2)** — the remaining enable. If tied low the UART
      answers ports 6/7 unconditionally; if driven, something can gate it off
      the bus. (§6) **Needs hardware.**
- [ ] **What drives the U230 select line** (§6a). Parked. Suggested checks:
      whether the Y throws (pins 3, 1, 13) are wired at all, and the DC
      voltage on pin 9 with the board powered. **Needs hardware.**
- [ ] **`SCM1` vs `SCM2` for opcode `68 05`.** The Ghidra module says `SCM2`;
      the RCA table has `68 03` = SCM2 and `68 05` = SCM1. One is wrong.
      *Settle by:* checking `Documentation/Datasheets/CDP1805AC.PDF`. Cheap,
      and it affects the EF1 counter reading at `05DD` (§7).

## The DLC link

- [ ] **What actually travels over it, in either direction** (§9a). The
      handler, physical layer and entry point are known; the payload is not.
      *Settle by:* reading the RAM code copied from ROM `040D` and `3011`, and
      the chained vector at `8E0D`.
- [ ] **Who reads the 40-byte ASCII record at `81BA`–`81E1`** (§10r). The
      `;` `=` `?` separators and `M(845C)` suggest a DLC report, but **nothing
      loads that buffer by absolute address** — the three writes in
      `build_report_template` are the only references. Until the reader is
      found, "this record is transmitted" is unproven.
      *Settle by:* finding the pointer arithmetic that reaches `81BA`.
- [ ] **What consumes the `8119` buffer, and in which direction** (§10g).
      Every direct write to `811B` only resets it to `0x19`, and the one site
      that moves `M(811A)` (`25D4`) decrements with a wrap `0x01`→`0x15`,
      which does not converge on `WaitForBuffer8119`'s exit condition. So
      either an interrupt path advances a pointer through a register alias, or
      `25D4` is a different flow reusing the cells. **Do not assume the
      downward fill reverses the bytes until this is answered.**
- [ ] **The meaning of the three-byte field in the DLC record** — version,
      build or checksum (§8a, line ~1317).
- [ ] **`?CE007`, selector `08`** — the phone sends it, the reader has no
      parser branch for it (§8a).

## The card reader link

- [ ] **What writes `M(88BB)`**, the flag that raises fault 23 "optical
      reader" ahead of the log (§10n). It has **no write cross-reference**, so
      it is set through a pointer register.
      *Settle by:* reading the link ISR around `504C` with correct alignment.
- [ ] **Is `M(8062) == 5` really the empty-reader signature?** (§10l) The code
      path is solid — `8062` of 4 or 5 gives card status `0xAA`, and `== 5` is
      what reaches the insert-card prompt — but *why* an empty slot yields
      `7 − popcount == 5` is unverified.
      *Settle by:* capturing the reader's reply with no card in the slot.
      **Needs hardware.**
- [ ] **Where `RF.0 = 0x91` is set.** Previously marked settled on a
      misread: `7383` is `LSZ` (`0xCE`), not `LSNZ`, so that site *skips*
      when the state is already `0x91` rather than resolving it. `0x91` is
      tested six times, has no `LDI`, and its origin is unknown (§10d).
- [ ] **What `0x25` and `0x85` mean, and where they come from.** Both are
      equality-tested as `RF.0` states but have **no `LDI` anywhere** in the
      image (§10d). `0x25` is plausibly a reader `BR25` code (§10m); `0x85` is
      in the auto-clear set but `LDI 0x85` occurs zero times, so it may be
      vestigial.
- [ ] **What writes `0x802F`**, the second scale-bar marker. `802C`/`802D`/
      `802E` are all per-bit measurement state around `read_card_bit`, so
      `802F` is probably the fourth member of that group and its writer is
      likely nearby.
- [ ] **Name `2124`** once `1B9F` is understood. It stores `RE.0` into
      `0x8033` then calls `1B9F`; `set_position_target` is a guess that has
      not been earned.
- [ ] **Confirm `1593` is a print routine.** `adc_read_byte` calls it when
      the conversion rails at `0x00` or `0xFF`. If it prints, that path is
      *reporting* a measurement-out-of-range rather than handling it — which
      would tie it to a specific adjustment-menu item.
- [ ] **`0x8109` is read once and written nowhere** (`21FB`), so that test
      always takes the zero branch and the `M(0x8031) != 0x78` condition
      behind it is dead. Confirm nothing outside the ROM writes it.
- [ ] **`CA`, `CB`, `MN`, `TG`** — the phone parses them, this reader never
      sends them (`card-reader/`, item 4). Another reader model, or a
      different peripheral?
- [ ] **Decode the 15 payphone handlers** at `0x3375`–`0x34EC` to recover what
      each reader mnemonic actually does (`card-reader/`, item 3).
- [ ] **Read the fourteen reader-side command handlers** listed in §8 from
      the phone's side, to find out what each mnemonic actually asks for.
- [ ] **Chase the computed selector that reaches `?TE01` / `?TE02`** — it
      drives the reader into factory adjustment mode, the most powerful thing
      the phone can ask of it (§8).
- [ ] **The reader's dispatcher at `0xE080` is off-image** (`card-reader/`,
      item 1) — structurally unreachable from this ROM.

## Faults, timers and state

- [ ] **Fault 43 overruns the module table** (§10n). Codes `0x48` and `0x49`
      map to fault number 43 → index 31, one past the 31-entry table at
      `6B74`; index 31 reads the word `0x20AD`, which is *code*. Either those
      codes are never logged, or it is a real firmware bug present in all
      three builds.
      *Settle by:* provoking fault 43 on a live unit. **Needs hardware.**
- [ ] **What `M(8030)` means**, and therefore what condition routes to
      `wait_and_triage_state` rather than the normal path at `45D6` (§10e).
- [ ] **What `M(845D)` holds** that is worth clearing before the "1 then 3"
      reboot shortcut (§10j).
- [ ] **What `415E` does** — called right after `DLC_Comm` in
      `show_version_and_comm` (§10j).
- [ ] **What record the block at `2B00`–`2B6F` builds.** It ends in
      `LBR 73BC`, a bare `STR RA`, and the constants it writes (`0x2E`,
      `0x42`, `0x67`, `0x15`, `0x04`) are **not** fault-log codes — the log at
      `840A` is written at `3F83`, `3F8A` and `5BDE`, never through `73BC`
      (§10f).
- [ ] **Identify the bits of `0xF000`** from the dense block of accesses
      between `1DC5` and `22A6`, and declare a memory block for it in Ghidra
      (§10a). One bit is now known indirectly: the integrity check relocated
      to `9771` writes 0 to `F000` on failure (§10q).
- [ ] **What consumes the `7C06` table** — probably tariff data. It lies in
      the `7C00`–`7F25` window that is the *only* thing differing between the
      three builds (§1a), so comparison across builds should help.
- [ ] **The seven `NOP`s at `4B2D`**, in the main idle loop. Identical in all
      three builds, so build comparison cannot recover what was removed.

## Naming and tooling

- [ ] **Name the soft-timer bank.** `arm_timer_set` (§10y) revealed the whole
      set: `888E`, `8131`, `8133`, `8134`, `8136`, `8128`, `8137`, `811D`.
      Several were previously unnamed for lack of a role; now they have one.
- [ ] **Cells still unnamed because the meaning is unknown:** `8030`, `812F`,
      `8149`, `8165`, `816C`, `845D`, `97A6`, `8191`, `8501`, `81B5`, `850D`,
      `8500`, `8513`–`8515`. Only `8513` has a known consumer
      (`M(813A) = M(8513) − 1` at `1A52`).
- [ ] **Reconcile the four statements about `CA`, `CB`, `TG`, `MN`.** The
      phone notes variously call them trunk-link candidates (§7), reader-link
      codes on a one-writer argument (§9a), not attributable because the UART
      is shared (§9a table), and no longer in doubt (§12). The retraction
      stands — one writer is not one peer — but the text was never unified.
- [ ] **`M(8144)` has two incompatible meanings in the notes** — §1a ties it
      to the credit screen, §10t to "the dial pulse arrived". Neither is
      argued from the cell itself; the §10t reading was taken from the module
      title. The §1a citation also points at `3A0B`, which reads `813E` and
      `8127`, not `8144`.
- [ ] **Does anything actually gate the `845A`/`885D` increments on a
      completed call?** §10s says they count calls, but the increments at
      `4252`/`425A` run when bit 7 of `INP 3` is set and the previous sample
      at `8078` was zero — the `ANI 0x96` on `card_permission_bits` is a mask
      whose branches all rejoin, so it does not guard them.
- [ ] **`KEY_*` may be off by one.** The enum puts `*` at `0x0C`, but the
      matrix table at `2400` gives index `0x0B` = `*` and `0x0C` = `#`
      (§10f). Worth settling — it changes how every `XRI 0x0C` reads.
- [ ] **Create functions at `5071`, `514B`, `5FB1`** so the decompiler renders
      the link layer. The MCP cannot create functions; this is a GUI job.
- [ ] **Rename the 14 TE handler targets** in the reader project once
      functions exist there (`card-reader/`, item 5).
- [ ] **Record the `RLXA`-into-PC gap** in `cdp1806/REVIEW.md`.
- [ ] **Relax the detector's word-pair matcher** to tolerate a second
      `PHI`/`PLO` (`card-reader/`, item 6).
- [ ] **Decide whether to rename `1ABE`.** `PerformComm?` is defensible for
      its most important use, but the routine contains **no `INP` or `OUT` at
      all** and is entirely generic — `run_supervised_op` would be more
      honest (§10z). The `?` is doing real work either way; this is a
      judgement call, not a finding.
- [ ] **Teach the analyzer `SEP RD` inline arguments.** It is a second
      convention separate from SCRT (`card-reader/`, §idioms): `178E` reads
      its byte with `LDA R0 / PHI RE`. Same shape as the existing options — a
      register plus a byte count. Worth counting the sites before deciding.
- [ ] **Duplicate constructor name in the `.slaspec`** — `0x6805` is defined
      at both L248 and L250.
- [ ] **Mark the reader's phase table at `2428`–`242B` as data.** It sits
      between `clear_byte_at_0x81xx` and `port7_release`, so Ghidra
      disassembles it as code.
- [ ] **A `cdp1802` language variant**, once the 1806 definition is finished
      (`card-reader/`, item 7).
- [ ] **Reconcile the blog's address `4930`** with this image (§12a). Here it
      sits inside an `RF.0` state machine at `48E8` that exits to the main
      idle loop — not obviously "the error routine". May be a different build
      or a file offset.

## Only answerable with a live phone

Collected separately because they are not worth static effort:

- [ ] **Dump `850D`–`8515`** from a unit with a live battery to recover its
      provisioned card values (§10q). The ROM only gives the defaults, `0x0F`
      and `0x78`.
- [ ] **Dump `840A`–`8441`** for that unit's fault history (§10e).
- [ ] **Read the hardware straps** — five drive lines and a sense on port 3
      bit 6 (§10k) — to learn what revision a given board reports.
- [ ] **Capture the reader's reply with no card**, settling `M(8062) == 5`.

---

## Recently settled

Kept as a record of what the method looks like when it works.

- [x] **What the `6069` table holds** — packed BCD fault numbers for codes
      `0x46`–`0x78`. *Settled by* checking every byte had both nibbles ≤ 9 and
      that the run ended exactly where code resumed at `609C` (§10f).
- [x] **The second byte of each fault-log entry** — an occurrence counter with
      a threshold, written by `5E1B`. *Settled by* noticing all four call
      sites target **odd** offsets from `840A` (§10i).
- [x] **Where `0x83` and `0x88` come from** — written through `RE` at
      `7384`, the only register-mediated write to `RF.0` (§10d).
- [x] **Whether `0xAA` is a status code** — no. `LDI 0xAA` occurs 28 times,
      every one followed by `STR` (§10d).
- [x] **The Hebrew encoding** — ISO-8859-8 minus `0x40` (§9).
- [x] **Which port the strap sense is on** — port 3, bit 6 (§10k).
- [x] **How the phone knows there is no card** — it does not sense it;
      `M(8069)` is a card status byte written only by reader handlers (§10l).
- [x] **What writes the `8060` buffer** parsed by the card-data handler —
      `PackCardNibbles` (`36B0`), via a 2-byte inline pointer (§10m).
- [x] **What bit 6 of `M(8036)` means** — "the timer set is running" (§10y).
