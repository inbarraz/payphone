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
- [x] **What port 5 actually receives** — nothing of its own. §10u's rule is
      `port n <- M(0x8033+n)` for the data, with `M(0x8033+n−1)` as that write's
      control word, and both flushes obey it: `399D` strobes with `M(8034)` then
      writes port 2 from `M(8035)`; `7572` strobes with `M(8033)` then writes
      port 1 from `M(8034)`. `M(0x8038)` is never an `OUT 5` source, so port 5
      has no data byte. The `OUT 5` byte's bits **are** observed — bit 6 of
      `8034` changes between two otherwise identical port-2 writes, and bits 1
      and 4 of `8036` do the same around port 4. Two alternatives this item used
      to offer ("the data is ignored" / "the two routines drive different
      devices") are both withdrawn.
- [ ] **How `M(8033)`'s low bits reach the strap hardware.** `read_hardware_straps`
      (§10k) writes them and `IDL`s. **Two sentences here were wrong and are
      fixed:** `8033` *is* flushed — `758B RLDI R5,8033 / 758F OUT 5 / 7592
      OUT 1` inside `7572` — and `7572` *is* reached from the interrupt path, by
      `SCAL` at `0638` inside the DLC service at `05A6`, as well as from `4A94`
      on the main thread. So the mechanism is known; what remains is the
      hardware question of whether those low bits reach the strap pins.
      *Settle by:* scoping the strap lines.
- [ ] **Find the ÷4096 divider chip** feeding EF1, and scope EF1 to confirm
      600 Hz (§10aj). The ÷12 and ÷50 are in the ROM; the divider is not.
      **Needs hardware.**
- [ ] **UART pin 4 (CS2)** — the remaining enable. If tied low the UART
      answers ports 6/7 unconditionally; if driven, something can gate it off
      the bus. (§6) **Needs hardware.**
- [ ] **What drives the U230 select line** (§6a). Parked. Suggested checks:
      whether the Y throws (pins 3, 1, 13) are wired at all, and the DC
      voltage on pin 9 with the board powered. **Needs hardware.**
- [x] **`SCM1` vs `SCM2` for opcode `68 05`** — `68 05` is **SCM1**. The
      module's own comment said so while the constructor was named `SCM2`;
      review finding M6, now fixed. Confirms the EF1 counter reading at
      `05DD` (§7).

## The DLC link

- [ ] **What the payload tags mean to the far end** (§10bj). Narrowed twice.
      The record and its framing are traced end to end (§8a), the CRC is
      CRC-16/Modbus (§10au) and the Isranet session is read in full (§10at), so
      "what travels over it" is no longer open as a whole. Nor are the tags
      themselves: §10bj identifies all five phone-side — `0A` nothing to
      report, `0F` a two-value report, `0B` an eight-byte report, `01` the
      70-byte record, `02` the pre-armed unauthorised reply. What is open is
      only what the **DLC** does with each, and since the phone's own receive
      parser at `0904`–`0976` never compares them, that is probably not
      answerable from this ROM.
      *Settle by:* a capture of a live session, or a DLC-side specification.
      The two settle-by steps this item used to list are both done and neither
      bore on the payload: the RAM code copied from ROM `040D` and `3011` is a
      checksum and a magic-byte pointer-list compare (§10am), and `8E0D` is the
      main thread's resume address, not a chained vector (§10bd). An earlier
      version of this item said the five tags were "known as values but not as
      meanings", which §10bj contradicts.
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
- [x] **The meaning of the ROM constants in the DLC record** — all three are
      established (§8a, §1a, §10bg): `7BFA` = `04 30` is software version 4.30,
      `7C02` varies by build and `build_dlc_record` copies it twice, and `7BFE`
      = `7A AE` is the whole-ROM additive sum `sum(ROM[0:7BFC])`, which
      `verify_banked_checksum` compares against. This item used to call it "the
      three-byte field … version, build or checksum (§8a, line ~1317)". Two
      errors besides being stale: they are three **2-byte** words, at record
      offsets 24, 26 and 34, not one three-byte field; and line 1317 is now a
      §9a heading, which is why these notes cite sections and not line numbers.
- [ ] **`?CE007`, selector `08`** — the phone sends it, the reader has no
      parser branch for it (§8a).

## The card reader link

- [ ] **What does the reader do with `F` (`0CD9`) and `EF` (`10E6`)?** The
      phone's side is settled — `?F` for one unit, `?EF0NN` for N, with N taken
      straight from `M(8064)` (§10ak) — and the reader's TE menu ties the
      letter `F` to erasure power. Reading the two handlers would turn that
      from strong inference into proof.
      *Settle by:* adding the BSK31 ROM to the repo; it is not here.
- [ ] **What does `CC` (`139F`) do?** The phone sends `?CC` once, from the
      low-credit flush at `3924`, after collapsing the whole remaining balance
      into the drain pool (§10ak). The pre-burn reading fits but is not proven.
- [ ] **Why `?CD007` and `?CD012`, and what is the `007`?** `?CD007` goes out
      on card insertion and `?CD012` (selector `0x50`) is never sent at all.
      `?CE007` has no branch in the reader's parser. The card read computes
      `7 − popcount`, which makes `007` suggestive, but nothing connects them.
- [ ] **What writes `M(88BB)`**, the flag that raises fault 23 "optical
      reader" ahead of the log (§10n). It has **no write cross-reference**, so
      it is set through a pointer register.
      *Settle by:* not this — `504C` is a **false lead**. Those bytes are the
      opcodes `GLO R8` / `PHI RB`, not an address; `51CF` is the same pair after
      `LBR 5729`. Both real references to `88BB` are reads (`23A6` and `29E9`,
      each `LDN` / `LBZ`), `2A24` writes the *neighbour* `88BA`, and `2F05`'s
      `clear_block_range(8865, 88B9)` stops short of both. No `PHI`/`PLO` pair
      builds the address either. Still open, and it needs a different approach.
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
- [ ] **Does `M(8074)` have two uses?** `read_hardware_straps` builds a
      5-bit strap value there and `show_version_and_comm` prints it as the
      hardware version, but `test_dial_and_reader` clears it and tests it
      for `0xAA` — not a 5-bit value. Either the test reuses the cell as a
      scratch flag, or the `hardware_version` name is too confident (§10ac).
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

- [ ] **233 RAM cells are still unnamed**, out of the 399 the firmware points a
      register at, after dropping the cells a bad `SCAL`-pointer heuristic had
      invented. [`phone/RAM-MAP.md`](phone/RAM-MAP.md) has all of them with
      the signature the ROM shows — stores, immediates, `ANI` masks, comparison
      values — which is what is actually known about each. Naming them would
      mean inventing meanings.
      *Attack in this order,* highest site count first, because a cell touched
      from a dozen places has a dozen chances to give itself away: `8169`,
      `81B5`, `8186`, `8182`, `8168`, `816C`, `813A`, `813C` — §10ax records
      what each one's reference sites actually show, which is the head start.
      (`8165`, `812F` and `8183` are done.)
- [ ] **Label the fifteen cells Ghidra still has no data item for.**
      `rename_data` silently does nothing without one, and the only way the code
      names any of these is as an inline-argument byte or a pointer-list entry,
      so Ghidra never created a reference. `0048`, `8000` and `8019` are now
      done. Still outstanding, with the name each should get:

      | Address | Name |
      |---|---|
      | `8001` | `dial_buf_aux` |
      | `8026` | `reader_digit2` |
      | `8054` | `bufDisplayString_8054_bulk_digits` |
      | `8059` | `bufDisplayString_8059_drain_digits` |
      | `805B` | `bufDisplayString_805B_end` |
      | `8516` | `totalizer4_8516` |
      | `851A` | `minute_meter` |
      | `8520` | `charged_period_counter` |
      | `8526` | `units_burned_counter` |
      | `867D`, `87D0`, `88C4`, `8A00`, `8EFB` | `ram_sentinel_<addr>` |
      | `30E3` | `ram_sentinel_addr_list` |
      | `8851` | `tick_task_resume_addr` — a 16-bit resume address (§10az) |
      | `8853` | `tick_task_byte_timer` |
      | `8854` | `tick_task_word_timer` — 16-bit |
      | `8182`, `8E02`, `8ED9` | `session_timer_<addr>` |
      | `8DAE` | `feature_flag_idx2` |
      | `8186` | `call_phase_active` (§10ba) |
      | `8850` | `saved_card_permission_bits` (§10ba) |

      `89FA` (`stack_top`) has a different blocker: it is the second byte of the
      existing word at `89F9`, so that item has to be cleared first.

- [ ] **Name the soft-timer bank.** `arm_timer_set` (§10y) revealed the whole
      set: `888E`, `8131`, `8133`, `8134`, `8136`, `8128`, `8137`, `811D`.
      Several were previously unnamed for lack of a role; now they have one.
- [ ] **Cells still unnamed because the meaning is unknown:** `816C`,
      `97A6`, `81B5`, `850D`,
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
      title.

      **Correction:** this item used to add that §1a's citation "points at
      `3A0B`, which reads `813E` and `8127`, not `8144`". `3A51`, inside that
      selector, *is* `RLDI R6,8144 / LDN / LBZ 3A63`, and the non-zero arm shows
      descriptor `6672` (`CREDIT:`) — so §1a's claim is argued from the cell
      after all. The question stays open for a better reason: the thirteen
      `RLDI …,8144` sites are all reads and two have **opposite** polarity —
      `3A51` shows `CREDIT:` when it is non-zero, `2DEB`/`2E0E` show the same
      descriptor when it is zero. One name does not cover both, and no immediate
      store to `8144` has turned up.
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
- [ ] **Add an immediate-word kind to the inline-argument analyzer.** There
      is no way to declare a 16-bit inline value that is a *number*: `p`
      references any mapped target and `w` references any target in
      initialized memory, so a count in ROM range gets a spurious data
      reference either way. `290a` works around it with `b,b`, which costs
      the word view in the listing.
- [ ] **Teach the analyzer `SEP RD` inline arguments.** It is a second
      convention separate from SCRT (`card-reader/`, §idioms): `178E` reads
      its byte with `LDA R0 / PHI RE`. Same shape as the existing options — a
      register plus a byte count. Worth counting the sites before deciding.
- [ ] **Give `P` a context register so `RET` can terminate flow** (review
      gaps G1/G2, mistake M10). Until then `RET` must fall through, because
      this firmware uses `RET 0x24` to set `X` with `P` unchanged.
- [ ] **The nine 1806 BCD instructions are empty stubs** (G3), the
      counter/timer is unmodelled (G4), and the `X == P` inline-operand
      idiom the whole ROM is built on has no model (G1).
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
- [ ] **Dump `8516`–`852B`**, the four decimal totalizers (§10ah) — 4, 6, 6
      and 6 digits. Three now have a reading from the ROM (`851A` minutes,
      `8520` charged periods, `8526` card units burned, §10ah/§10ak); `8516`
      does not, and none of the four has known *units*. Readings from a unit
      with known history would settle both.
- [ ] **Read the hardware straps** — five drive lines and a sense on port 3
      bit 6 (§10k) — to learn what revision a given board reports.
- [ ] **Capture the reader's reply with no card**, settling `M(8062) == 5`.
- [ ] **Why is the ROM integrity check dormant?** `0048` holds seven ROM
      addresses whose bytes match `integrity_magic_bytes` exactly, and the
      `9771` verifier takes its list pointer inline, so pointing it there would
      make the firmware self-verifying. The constant `0048` occurs nowhere in
      the image, so nothing invokes it (§10am). Dropped in V2.8, reserved for a
      variant, or reached some way the search missed?
      *Settle by:* diffing another TAMAC-18 ROM version, if one can be found.
- [ ] **Is there a second 32 KB RAM over `0000`–`7FFF`?** §10an argues `F000`
      bit 0 maps a writable shadow there in place of the AT29C256: every site
      that *sets* bit 0 lives in code relocated to RAM at `9100`, and
      `rewrite_code_space` runs from ROM with bit 0 clear while rewriting all
      32 KB. The reasoning is internal to the firmware; the chip is the proof.
      *Settle by:* looking at the board. **Needs hardware** — but only a glance
      at the part numbers.
- [x] **What the code shadow is for** Reset writes `F000 = 0x00`, and
      nothing in the image reaches the `0x03` entry point at `000F`, so the
      phone boots and runs from the **ROM**, not the shadow (§10an — this
      corrects an earlier claim). The shadow is filled on request and switched
      in only transiently by RAM-resident code. **Answered** (§10ay): the shadow is where the CPU executes while the flash
      underneath is being programmed, because an AT29C256 cannot be read and
      programmed at once. An earlier wording called runtime patching "the
      obvious guess and no more than that".
- [x] **Where inbound reader digits get converted from ASCII** — in the link
      ISR, exactly where this item guessed. After `INP 6` stores the byte at
      `8185`, `ISR_Card_Reader_Link` classes it by the receive index: `≥ 0x27`
      resets the index to `0x22` and stores nothing; `< 0x24` stores `'A'`–`'Z'`
      raw; `≥ 0x24` maps `'0'`–`'9'` to 0–9 and `'A'`–`'F'` to `0x0A`–`0x0F`
      (via `SMI 0x41 / ADI 0x07 / ADI 0x0A`) before `STR R7`. So `'0'` arrives
      at `5144` as 0 and `'A'` as `0x0A`, which is what `digits_to_binary16`
      expects. The `'>'`, `'?'`, CR and LF cases are the §6 handshake bits.
- [x] **What `F000` bit 1 does** — **write routing** (§10ay, §10an, §12); only
      its physical decode is unobserved. The original framing, kept for the bit
      pattern it records:

      *(The original framing, kept for the bit pattern it records:)* what does
      `F000` bit 1 do? Set in `0x03` and `0x02`, cleared in
      `0x01`, `0x00`, and by a failed integrity check (§10a, §10am, §10an).
- [x] **What the relocated `1CB7`–`2330` block does** — the
      **memory-operation interpreter with an AT29C256 page programmer**, i.e.
      the remote firmware-update facility over the DLC link (§10ay, and
      §10bg–§10bj for the dispatcher, the engine, the handlers and the two
      bugs). This item is a leftover duplicate of the settled one further down;
      it was answered and this copy was missed.
- [ ] **What did `123…` reach?** `dialed_prefix_is_123` (`008F`) suppresses the
      on-screen echo once four or five digits are in and the number starts
      `1 2 3`, which reads as a calling-card or PIN prefix (§10ao). The
      mechanism is settled; the service is not, and it is a question about the
      Israeli network rather than the ROM.
      *Settle by:* period Bezeq payphone or calling-card documentation.
- [ ] **Why does the dial buffer have two extents?** `25DC` wraps `M(811A)`
      `1 → 0x15`, bounding the index at `8101`–`8115`, while `1A26` clears
      `8101`–`8119` and `3B0D` sets the top index to `0x19`. The four slots
      `8116`–`8119` sit inside the cleared region but outside the wrap
      (§10ao).
- [ ] **What does `יש"מ` stand for?** It is the ROM's own label (`69AC`) for the
      12-byte number field at `844E`, the sibling of `own_phone_number`
      (§10ap). A site or terminal identifier would fit — `844E` sits in the
      battery-backed block beside the fault log — but nothing in the image
      shows it, and it is a question about Bezeq's terminology rather than the
      firmware.
- [ ] **Trace `number_field_dialog`'s own renderer.** `5751` is the LCD path for
      `own_phone_number` and `ysm_number`, and its formatting lives in `57B6`,
      `586C` and `5909`, none of them read. `Hex2ASC_8501_to_RA` is *not* it —
      that one feeds the report builder at `55A7` (§10ap). So what the
      technician screen actually shows for a nine-digit number is still open,
      including whether it carries the same trailing `'A'` pad.
- [ ] **What is EF4?** Only two sites sample it, `23B8` and `4A13`, and both do
      so immediately before EF3 — so it is a second contact or sense line read
      alongside the hook switch, and `4A13` carries the result in `RF.1` rather
      than acting on it (§10aq). EF1 is the timebase and EF3 the hook; EF2 is
      unaccounted for too.
      *Settle by:* tracing EF4 on the board, or following `RF.1`'s consumers.

- [x] **How a thread parked at `1A7C` proceeds** — it is **resumed**, and the
      mechanism is the stack rewrite §10av said did not exist. The DLC handler
      at `0664`–`0676` sets `RA = R2 + 0x16` — the saved-`R4` slot, eleven
      `RSXD`s above the frame base — and stores the word from `8E0D` into it;
      `interrupt_leave`'s `RLXA R4` at `0693` reads it back and its `RET`
      transfers there. `8E0D` is a main-thread resume address, not a vector
      (`0679` overwrites `R1` before the `SEP`). So `IDL; IDL; LBR self` is a
      coroutine yield and the tick chain is the scheduler, with the step's
      result code in `feature_flags_8dac` as its input. The six "dead stubs" at
      `1A6A`–`1A79` are entries in the `131C` macro-step table (§10bd).

- [ ] **Mirror any remaining comments across the `1CB7` → `9100` relocation.**
      The block is copied to `9100` and runs there, so a finding is only useful
      where it executes; the notes, though, cite the ROM addresses throughout
      (§10ay now carries the conversion table). Done so far: the mapping and
      overlay note at both `1CB7` and `9100`; "never executes" markers with
      pointers to the live twin at `1CC2`, `1ECA`, `2176` and `21A5`; and the
      §10ay/§11a findings commented at the executing addresses `910B`, `9313`,
      `95BF` and `95EE`.

      **Still unverified:** whether other comments exist in `1CB7`–`2330`. The
      MCP cannot enumerate comments — it can only set them — and reading them
      needs a function to list through, which that range has none of. The list
      above was reconstructed from what the notes record, so a comment written
      into the lower range but never written up would have been missed. Defining
      a function over `1CB7`–`2330` purely to list its comments would settle it.

- [ ] **Dropped, kept for the record: the "function at 6666" report.** Inbar hit
      trouble with "the function at `6666` because of the `SCAL` to `7014`", and
      neither part matches the image as read here — `6666` is data (inside the
      9-byte LCD descriptor at `6660`, referenced from `4050` in
      `DisplayCommStatus`, with nothing referencing `6666` itself), and
      `SCAL Rn,7014` occurs exactly once in the image, at `3B2F`. So either the
      address was a slip or Ghidra was showing something the MCP cannot see.
      Dropped at Inbar's request before that was settled.

      If it resurfaces, the likely subject was the unmapped routine containing
      `3B2F`, which cannot be defined cleanly until `701B` and `7014` are
      functions — see the ordering note above. A comment at `6666` records this
      in the program too.

- [ ] **What is `?CE007` (template selector `08`)?** The phone sends it from
      `3145`, but `CE` is not among the fourteen commands the BSK31 parser at
      `0EC0` accepts, while `?CD007` — one letter away, same digits — maps to the
      reader's `CD` handler at `070B`. Either the parser census is incomplete or
      this reader rejects `CE`, perhaps a variant for different reader
      firmware. Needs the reader image.

- [x] **`page_rewrite_cycle_down` (`96AE`) is a LIVE flash-corrupting bug**, not
      dead code. It and the ascending twin at `9663` are 75 bytes differing in
      two — the write-back target — yet both set `RLDI R7,8E7B`, the buffer's
      bottom. Right for an ascending read, wrong for `9708`'s descending one,
      which walks into `8E7A`/`8E79`/`8E77`, the programmer's own control bytes.
      Reachability settled: **`9561`** sets `M(8E79) = 0` and `M(8E7A) = 2`, the
      exact pair routing `9603` → `9656` → `96AE`, and `9561` is dispatched from
      **`188F`** as **command `0A`** under feature flag `0x13` (§10bh, §10bi).
      (An earlier version of this item named `9577`/`1882`; that is command
      `09`, the working ascending rewrite.) It would need `RLDI R7,8EBA`.

- [x] **The verify side is worse than a matching mistake** — on the rewrite path
      its *direction is read from a clobbered register*. Both cycles do
      `SEX RE / RNX R7` (`9679`, `96C4`), leaving `RE = source + 64`, and
      nothing reloads it before `9630 LDN RE / SMI 1`. So every rewritten page
      picks its verify direction from `M(source + 64)` — a byte of the data
      being programmed. Command `09` therefore verifies correctly only when that
      byte happens to be 1, and command `0A` matches **neither** verifier. The
      clobbered selector hits both rewrite commands, including the one that
      writes correctly; only the wrong-ended source is unique to `0A` (§10bh).

- [ ] **Why do 21 routines set feature flag `0x0E` when nothing reads it?**
      There is no `test_feature_flag(0x0E)` or `clear_feature_flag(0x0E)`
      anywhere in the image, and `0A3E` skips index `0x0E` while zeroing 0–4 and
      6–`0x0D`; only the init wipe at `072A` clears it. It cannot signal
      anything through `0278` either, since that clamps every index at or above
      `0x0E` — including `0x1E`, "none set" — to `0x0E`, so a raised `0x0E` is
      indistinguishable from no flag at all (§10bj). Either a consumer reads
      `8DBA` by some route not found yet, or this is vestigial.

      *(The paragraph that used to follow pointed at the `96AE` page-programmer
      bug — a stray from the item above, which already answers it: `9561` sets
      `M(8E7A) = 2`, from command `0A` at `188F`. It has no bearing on flag
      `0x0E`.)*

      To settle the `8E7A` question instead, see that item. `9656` takes the descending
      branch when it is not 1, and nothing in the image anchors `8E7A` with an
      `RLDI` — it is written by a register walk from `8E79`, which has not been
      traced. If the branch is reachable, this corrupts a flash page on the
      remote-update path.

      Then check the verify side for the same mistake: `RA` walks up from the
      saved source while `R8` walks down from the saved destination, which has
      exactly the same shape.

- [ ] **`97A6` is used two incompatible ways — which wins?**
      `count_fault_occurrence` stores the immediate `6` at `97A6` from **two**
      places — `5E4D`, the threshold hit, and `5E60`, which is on the
      keep-only-bit-7 path instead (a first draft called both the threshold) —
      while `1C60` passes `97A6` to `increment_counter16` (`04F0`), a
      **saturating 16-bit** counter, in a row with `97AA`, `97AE` and `979F`.

      Both readings are correct; they collide. `04F0` increments the *second*
      byte and carries into the first, so `97A6` is the **high** byte of a
      big-endian pair at `97A6`/`97A7` — which matches the §10z channel-0
      `varC` slot — and the fault store puts `6` in that high byte, making the
      counter `0x06xx`. `97A6` sits past every `97xx` overlay, so this is not
      two uses taking turns behind a bank switch; both run from ROM. So: a cell
      deliberately shared between modes that never overlap, or a genuine
      aliasing bug. Ruled out: a mis-read pointer at either site.

- [x] **What consumes `M(886A)`** — nothing beyond the state machine. The only
      two references are `5216` (where `proc_51e8` publishes the opposite
      phase's count and then zeroes that counter) and `523A`, where
      `step_state_machine` loads it and passes it to `classify_into_range`
      (`328E`) and `next_state_from_table` (`3270`). `328E` leaves a bracket
      index at `886B` and `3270` folds it into `886C`; the raw value goes no
      further. What the count physically measures is still open, but the
      consumer chain is complete (§10bf).

- [ ] **What is `8E0C`'s 900-threshold flag for?** It holds 0 or 1 from
      comparing a 16-bit field near `8E77` against `0x0384` = 900, at `20DE`
      (live `9527`) — inside **`94DF`**, the cmd-`15` top-page read-modify-write
      stub, not "the interpreter" generally as a first draft put it. The
      threshold looks like a wear or write-count limit on the top flash page,
      which would make `8E0C` a "page is near its endurance limit" flag, but the
      consumer has not been found — and a review now says there is **no reader
      at all**: the one executed reference is the store at `20E2`, and the other
      `8E 0C` bytes in the image sit inside a descriptor after `LBR 32F9`. A
      pointer built at runtime could still reach it, so this is "no reader
      found" rather than "write-only", but it joins feature flag `0x0E` as a
      value the firmware computes and appears never to consult.

      (`8EBC`, listed here alongside it, is resolved: it is where `5C72` stores
      `verify_banked_checksum`'s result, now `banked_checksum_result`. The claim
      that it marked one-past the page buffer was wrong — §10bh.)

- [ ] **What drives bit 1 of `PORT1_shadow` (`8034`)?** It now has a precise
      waveform, which is the strongest handle yet on any bit of that port: the
      `705E` sequencer holds it high in the idle state `70C3`, and the cycle
      `7074` → `7086` → `70A5` drives it **3 s low, 3 s high, indefinitely**,
      optionally after a 28 s one-shot delay from state `7065` (§10az). §6a
      still has no bit of `8034` traced to a component. §10ba narrowed it
      sharply. The one-shot is armed by the `6FFF` entry and the sequencer is
      returned to idle (bit high) by `6FB3` — but the `7014` entry reaches the
      same billable state **without** arming it, and the choice between them is
      `M(843A) & 0x7F`, byte 0 of fault-log entry 24. `show_fault_log` uses the
      identical mask, so zero means that slot is empty; and the fault recorded
      there is `INP 2 / ANI 0x02` at `5DDD` — a **port-2-input bit-1 read-back
      check**.

      **WITHDRAWN (§10ba).** The cadence is *not* gated on that self-test.
      `6FFF` arms sequencer state `7065` unconditionally — `7004 RLDI R9,7065`,
      the only `RLDI` of `7065` in the image, with no test of `843A` in
      `6FFF`–`7003`. The fault-slot test is in **one** of its seven callers
      (`3B37`); the other six arm the cadence regardless. What `3B24` chooses is
      which *entry* that one site uses.

      **Narrowed again by §10u's port correction: the bit is a `PORT 1` output
      bit, not port 5.** `port n <- M(0x8033+n)`, so `8034` is what `OUT 1`
      sends — `758F OUT 5 <- 8033`, `7592 OUT 1 <- 8034`. The cell was named
      `PORT5_shadow` until then, which had made the cadence look like a port-5
      signal; it is a port-1 line held for seconds at a time.

      Also ruled out: an in-stream loopback. Nothing writes bit 1 and reads it
      back at `5DD7`, and the suppression at `3B28` is a one-way gate, so the
      firmware never compares the two "bit 1"s. What fits every byte is a
      call-time level on port 1 that stops pulsing once the port-2 earth fault
      is logged — §10n maps that fault's code `0x75` to displayed fault 38, the
      earth-disconnected string. Whether the two are the same net on the PCB is
      a hardware question this ROM cannot answer. Period (3 s / 3 s), duty
      cycle, delay (28 s), the port, and both the arm and suppress conditions
      are now exact.

- [x] **The second and third sections of the `13EC` timer table** — each is one
      4-byte header `{counter pointer, 16-bit limit}` followed by ordinary
      section-1 triples that run only on the tick the counter reaches the limit.
      Section 2: counter `8ED5`, limit `0x0032` = 1.000 s, decrements `8E04`
      then `8E01`. Section 3: counter `8ED7`, limit `0x0BB8` = 60.000 s,
      decrements `8E00`. So `1415` is three timebases in one walker — 50 Hz,
      1 Hz, 1/60 Hz. The layout had looked unreadable only because `tools/dis.py`
      mis-sized `ADCI` and printed a phantom `IDL` at `1455` (§10az).

- [ ] **Re-run the inline-args analyzer, then define the remaining entries.**
      The MCP reads only code inside a defined function, so anything unmapped
      has to be analysed around rather than through — which is how the `5E1B`
      extent was got wrong.

      **Done:** `0699` → `interrupt_enter` (`0699`–`06B9`) and `067E` →
      `interrupt_leave` (`067E`–`0698`), with `05A6` → `ISR_DLC_Link`. All three
      extents match §10av exactly. `05D7` was on an earlier version of this list
      in error: it is the CI-set path *inside* `ISR_DLC_Link`, not an entry
      point, and it now reads through the MCP as part of that function.

      **First, the mechanical fix.** `3aa8 p` has been added to
      `cdp1806/data/inline_args.txt`. Without it the analyzer could not find
      `play_toggle_pattern`'s return point, so **caller bodies truncated at the
      call**: `exit_call_connected` was `6FB3`–`6FC5` and
      `call_connect_with_cadence` `6FFF`–`700E`, each stopping at its
      `SCAL 3AA8` instead of at the `SRET R3` that really ends it. Re-running
      the inline-args analyzer should extend both. This is specific to `3AA8`,
      not systemic — `6E6B` resolves at all 84 of its sites and the function at
      `2D10` runs clean through five of them.

      **Then define:**

      | Address | What it is | Section |
      |---|---|---|
      | **`701B`** | the shared tail — **define this FIRST**, and give it the name `enter_call_connected`; body `701B`–`705D`, ending at the 2-byte `SRET R3` at `705C` | 10ba |
      | `7014` | the second entry, body `7014`–`701A`; define it *after* `701B` | 10ba |

      **Order matters here, and getting it wrong is what makes these fight.**
      Ghidra function bodies cannot overlap, and `6FFF` and `7014` are two
      entries converging on the one tail at `701B`:

      ```
      6FFF..7013   arm sequencer 7065, tone 3AA0, then LBR 701B  ─┐
      7014..701A   tone 3AA4, no arm, falls through              ─┼─> 701B..705D
      ```

      If either entry is created while `701B` is not yet a function,
      flow-following swallows `701B`–`705D` into it, and the other entry then
      collides and is refused or silently truncated. Define `701B` first and
      both entries stop at its boundary. The same applies to **any function
      whose flow contains `SCAL 7014`** — the only one in the image is at
      `3B2F`, in the unmapped gap between `play_toggle_pattern` (`3AA8`) and
      `byte_to_hex_ascii` (`3D18`) — so `701B` and `7014` must exist before that
      caller can be defined cleanly. Also re-create `6FFF` afterwards: its
      present body `6FFF`–`700E` is the truncation described above.
      | `70C3`, `7065`, `7074`, `7086`, `70A5` | the five `705E` sequencer states | 10az |
      | `70B9` | `set_next_tick_task` | 10az |
      | `3B24` | the fault-slot test that chooses between the entries | 10ba |
      | `9656`, `9663` | **split out of `flash_page_loop_tail`** (`9639`–`96AD`), which holds three routines: the tail and exits, the mode dispatcher at `9656`, and the ascending page-rewrite cycle at `9663` — the twin of `96AE` | 10bh |
      | `28D8` | `interrupt_enter_reader` — **split it out of `28B7`**, whose body currently merges the card-reader epilogue and prologue into one function; the DLC side is correctly split into `interrupt_leave` / `interrupt_enter` | 10av |
      | `6E0C` | the reset block — no function at all | 10ay |
      | `1CB7` | the flash programmer's **ROM source image**, 1658 bytes — no function. Low priority: it never executes (§10ay), so a function here would only document the source. The executing copy at `9100`–`9779` already has ~21 functions. |

      The sequencer states pay off most: each is a few instructions and they are
      currently invisible as code.

- [ ] **Set `XP` at the four `verify_banked_checksum` sites** — `9735` and
      `976C` in the live copy (`DIS 0x24` and `RET 0x24`), and `040F` and `0446`
      in the ROM image if that is ever disassembled (§10bg). Ghidra currently
      renders each operand as a spurious `DEC R4`.

- [ ] **Set `XP` at `05E0` and `0658`.** Two confirmed `X == P` inline sites in
      `ISR_DLC_Link` where Ghidra's listing is wrong: it shows `RET` / `DEC R4`
      and `DIS` / `DEC R4`, decoding the `0x24` operand as a spurious
      instruction. They are really `RET 0x24` and `DIS 0x24` (§10az). `ctrl
      shift X` at each (`cdp1806/ghidra_scripts/SetXPInline.java`). The notes
      already have them right; it is the listing that needs correcting.

- [x] **Why is `fast_timer_812b` in the DLC chain's timer table** — same reason
      as `812D`: something *blocks* on it reaching zero. `53B1` spins on it in
      `test_dial_and_reader`'s pattern loop, and `73C1` in `729E` returns early
      while it is non-zero; `729E` is called from `wait_until_dialling_done`
      (`2C70`), a `1A7C`-family session step that parks on `IDL` and re-tests, so
      a session would stall there if the DLC chain did not decrement it. Both
      cells in the `40AE` ∩ `13EC` overlap are explained, and the intersection
      has no further content (§10bb).

- [ ] **The DLC frame shape is read; the tag *meanings* are not.** A review
      worked out `038D` in full: it builds **one** frame shape — type 0 carries
      a payload whose first byte is a tag, type 1 carries none, and anything but
      0 or 1 returns `0xFF` at `0408`. Frame at `8C27`: `CC`, `00`, length+7,
      `M(8DA7)`, `M(8DA8)`, type, a flag byte that is `01` only for a type-0
      frame with non-zero length, the payload, the CRC high byte first, then
      `84`. Known tags: `0A` (nothing to report, `01FB`), `0F` (two-value
      report, `02E3`), `0B` (an eight-byte report, `029C`), and `01` — which
      `build_dlc_record` writes at `8D26` ahead of the 70-byte record, so
      `020A`'s tag is `01` too. **And `0x02` means "not authorised"** —
      `dispatch_interp_command` builds a 1-byte reply with that tag when neither
      feature flag `0x14` nor `0x13` is set, before any command runs (§10bj).

      **The receiver does not branch on the tag at all.** `0904` → `089A`
      checks the `CC` sync, a minimum length and the `84` trailer, then the CRC
      via `02FF`, then compares the `8DA7`/`8DA8` identity pair through `7498`.
      No compare against `0A`, `0F`, `0B` or `01` appears in `0904`–`0976`. So
      what is still open is narrower: **what each tag means to the far end** —
      possibly not answerable from this ROM — and whether any other parser
      exists.

- [x] **What do the DLC payload tags mean, and type 0 vs type 1?** The
      phone-side answer is complete: `build_dlc_frame` accepts only types 0 and
      1, and §10bj identifies all five tags — `0A` nothing to report, `0F` a
      two-value report, `0B` an eight-byte report, `01` the 70-byte record, `02`
      the pre-armed unauthorised reply. An earlier version of this item said
      "the other four wrappers' tags … are unread"; they are read. What the far
      end expects is the live part, and it is the item above.
- [ ] **Read the DLC interrupt handler — `0699` / `05A6`, not `5071`.** An
      earlier version of this item pointed at `5071` and would have sent the
      work into the wrong subsystem. `5071` is the **card-reader** handler; its
      bit-7 fall-through is the `5A8E` mailbox transport's status latch, and
      `dlc_uart_service` (`0A61`) is unreachable from it. The DLC has its own
      vector: session entry swaps `R1` to `0699` at `06E4`, that prologue
      branches to `05A6`, and `05A6` polls XI at `05B9` and calls `0A61` at
      `05C1` (§10av). Session sequencing and the NUA send's two-byte over-run
      must live in there.
      *The CI-set path at `05D7` is now read* (§10az): it is a reduced
      re-implementation of the `4071` housekeeping, which the two-vector
      architecture forces, and its timer table at `13EC` overlaps `40AE` in
      exactly the two cells that must keep counting under either vector. What
      remains unread is the XI path proper — `0A61` itself and the frame
      assembly behind it. (The `8E0D`/`8E0F` reads at `05CD`/`065C`/`066F` are
      *not* part of the gap: §10bd has them as the main-thread resume address and
      its one-shot gate, stored at `1007`/`100A` and gated at `1011`, `101B`,
      `05D3` and `075A`. An earlier wording credited §2 with a "RAM-resident
      chained vector … installed at `1003`/`100B`/`1015`" — §2 never said that,
      `1003` is the `RLDI` rather than a store, and §10bd supersedes the reading.)

      *Also open:* who sets bit 7 of `8785`. The transmit engine at
      `0AD6`–`0B2A` **is** reached, by fall-through when `0AD3 LBNF 0B2A` leaves
      `DF` set — §10au's "no reference to `0AD6`" was a branch scan, which
      cannot see a fall-through.
- [ ] **Find Isranet PAD documentation, circa the early 1990s.** Two questions
      hang on it (§10at):
      **(a) Is `D1` a terminal type or a login identifier?** The ROM shows it is
      the phone's complete answer to the `TERMINAL=` prompt — there is no third
      prompt pattern and no other string sent — but not what that prompt was
      asking for. A contemporary user recalls an identifier being required after
      the modem answered, with no password. Note that the shape of a remembered
      human login is no guide: a carrier's own identifiers follow its own
      conventions, and a fleet account could be two characters.
      **(b) Whose host was NUA `34011503`?** Presumably Bezeq's payphone
      management system. *That it is an Isranet NUA is now settled* — Phrack
      27's 1989 NUA list gives Isranet's prefix as `04251` and its one Israeli
      address an eight-digit national part, `30000215`, matching this ROM's
      eight-digit `34011503` in length and leading digit (§10at). Whose host it
      was is still open.
      *Searched and not found:* general web search turns up X.25/PAD background
      (X.3/X.28/X.29, NUI and NUA concepts) and modern Bezeq material, but
      nothing on Isranet's own login syntax. Hebrew-language sources, archived
      Israeli computing forums, or `Isranet` paired with `PSS`/`Datex-P` are the
      untried angles.
- [ ] **Why does the NUA transmit over-run by two bytes?** `uart_tx_count` is a
      plain down-counted byte count and total sent is 1 + count, which closes
      exactly for `"\r.\r"` and `"D1\r"` but gives 11 bytes for a 9-byte NUA
      string — so `1A95`/`1A96`, both `FF`, go out after the CR (§10at).
- [ ] **Create function boundaries at `0C44` and `0C57`.** Neither login step
      has one, so the decompiler cannot render them (§10as). Same problem as
      `514B`/`5FB1` on the reader link — both fall-through labels with no
      inbound reference, so Ghidra has nothing to anchor on. (`5071` is done.)
- [ ] **Scope port 1 bit 3.** Three consecutive high ticks raise `M(8067)`
      bit 0 (`4AB9`), which is what lets the `?CC` flush run. It is the third
      sense line found on port 1 and the only one with no candidate meaning
      (§10ak).

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
- [x] **What `845A` and `885D` count** — **pulses**, not calls. `4243`
      edge-detects port 3 bit 7 against the previous sample in `M(8078)`
      (§10ai). So the periodic report fires every 45 pulses.
- [x] **What the timer tick rate is** — the slow tick is **exactly 1 Hz**.
      The 2.4576 MHz crystal ÷ 4096 gives EF1 at 600 Hz, the 1806 counter
      ÷ 12 gives a 50 Hz base tick, and the `40F4` prescaler ÷ 50 gives 1 Hz.
      So `M(811D) = 60` is one minute and `851A` is a minute meter (§10aj).
- [x] **What the two words at `8122`/`8124` are** — not a tariff pair but the
      **metering period**: `4155` increments `8122` every base tick via
      `increment_word16`, and `37A1` latches it into `8124` and zeroes it on
      each accepted pulse. So `credit_times_interval_ge_1000` computes
      credit × ticks-per-unit, an estimate of remaining talk time, and takes
      the larger interval as the conservative one (§10aa, §10ak).
- [x] **What the 1658-byte `1CB7` block is** — a **memory-operation interpreter
      with an AT29C256 page programmer**, i.e. a remote firmware-update facility
      reached over the DLC link. The `AA`/`5555`, `55`/`2AAA`, `A0`/`5555`
      unlock at `21A7`–`21B7` is the JEDEC SDP program command, and `2176`
      handles 64-byte pages. That also explains the code shadow (you cannot
      execute from flash while programming it) and supports the write-routing
      reading of `F000` bit 1 (§10ay).
- [x] **Whether the DLC frame CRC is really CRC-16/Modbus** — yes, bit-exact.
      The transcribed loop matches a reference implementation at every length
      1–160, including `"123456789"` → `0x4B37` (§11a). The *coverage* was wrong
      and is fixed: `R9 = 8C27`, the frame's first byte, not `8C29` (§10au).
- [x] **What checksum the DLC frame carries** — **CRC-16/Modbus**: init
      `0xFFFF`, reflected polynomial `0xA001`, eight bit iterations, computed
      from the frame's own length field at `8C29` with that byte as the count
      and the result left at `dlc_frame_checksum` (§10au). The routine was
      already named `crc16-modbus`; §10au shows the bytes that bear it out.
- [x] **Why metering stops during a data call** — `M(8DC5)` is
      `dlc_session_active`, set at `0C83` and cleared at `0CB9`, and it is one
      of `detect_metering_pulse`'s three inhibits. The only visible interlock
      between the data side and the charging side (§10au).
- [x] **What bit 6 of `M(8036)` means** — "the timer set is running" (§10y).
- [x] **What the DLC link connects to** — **Isranet**, the Israeli X.25
      gateway, dialled on `131`. The phone wakes the PAD with `\r.\r`, answers
      `TERMINAL=` with `D1` — terminal type or login identifier, undetermined
      (§10at) — and at the `@` prompt calls NUA `34011503` before uploading its
      70-byte record (§10at, §10ar).
- [x] **Whether the card is debited during the call or only on eject** —
      **during the call**, within one tick of each charge. The debit at `2D88`
      sets `M(8064)`, and `service_card_reader_link` at `3103` sends `?F` for
      one unit or `?EF0NN` for N on the next tick; the `?EF` digits are built
      from `M(8064)` itself at `3686`–`36A9` (§10ak).
- [x] **What triggers a charge** — the **exchange's metering pulse** on port 3
      bit 0, not any timer. `detect_metering_pulse` accepts a high of 80–480 ms
      confirmed by 40 ms of release; `M(8143)`/`M(8145)` are written from
      nowhere else, and the 60-second `851A` meter is a duration statistic
      (§10ak).
- [x] **What `8526` counts** — card units burned.
      `account_one_unit_spent` (`36C2`) is its only bump, and `MO`'s
      once-per-unit-of-difference call pattern proves the argument is units,
      not stepper steps as §7 first guessed (§10ak).
- [x] **What `M(8031)` is** — the link layer's **resume-address low byte**.
      `3989`/`398D`/`3100` fall through only for `0xFF`, the resting state;
      anything else is jumped to by `PLO R4` at `3102` inside page `31`. The
      whole reader link is a coroutine (§10ak).
- [x] **What `746D` does** — `clear_block_range`: `range_to_count` (`7498`)
      makes the count `RC − RD + 1`, so it clears an **inclusive** range
      downward. That fixes three buffer extents: the reader receive buffer is
      `8022`–`8026`, the LCD line-2 buffer `804C`–`805C`, and the credit and
      link working set `805C`–`8067` (§10al).
- [x] **What loads the card's credit into `805C`/`805D`** —
      `store_reader_decimal_to_page80` (`5032`), from the `MO` reply's three
      decimal digits, with the destination cell given as an **inline argument
      byte**. That is why no search for a store to `805C` found it. It also
      explains `card_units_shadow`: `5032` leaves `X = R8 = 805C`, so `MO`'s
      `SM` at `348E` yields the units consumed since the last report (§10al).
- [ ] **What is on port 4?** An earlier version of this item answered "the
      firmware does not use port 4" and told §10k to drop it. **Too strong.**
      The two *apparent* sites it names, `2EA8` and `2EC5`, really are inline
      digit weights read through `X = R3` — but `flush_output_latches` executes
      a genuine `OUT 4` twice, at `75AB` and `75B5`, with bits 1 and 4 of
      `M(8036)` strobing between them (§10u). So port 4 is driven; what it
      reaches is the open question, as the ports-1-and-4 item above already has
      it.
