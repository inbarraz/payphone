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
      title. The §1a citation also points at `3A0B`, which reads `813E` and
      `8127`, not `8144`.
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
- [ ] **What is the code shadow actually for?** Reset writes `F000 = 0x00`, and
      nothing in the image reaches the `0x03` entry point at `000F`, so the
      phone boots and runs from the **ROM**, not the shadow (§10an — this
      corrects an earlier claim). The shadow is filled on request and switched
      in only transiently by RAM-resident code. Runtime patching is the obvious
      guess and no more than that.
- [ ] **Where do inbound reader digits get converted from ASCII?** The wire
      carries ASCII and the dispatcher compares `8022`/`8023` against ASCII
      prefixes, but `digits_to_binary16` adds `8024`–`8026` as raw values with
      no `0x30` subtracted (§10al). Something between the two converts them;
      the link ISR at `5071`/`514B` is the candidate.
- [ ] **What does `F000` bit 1 do?** Set in `0x03` and `0x02`, cleared in
      `0x01`, `0x00`, and by a failed integrity check (§10a, §10am, §10an).
- [ ] **What does the relocated `1CB7`–`2330` block do?** 1658 bytes copied to
      RAM `9100` from two call sites, entered at `9421` with `D = 0x13` and
      `R9 = 8DD2`, holding twelve of the image's `F000` writes (§10an). It is
      the largest piece of this firmware with no described purpose.
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

- [ ] **How does a thread parked at `1A7C` ever proceed?** Briefly recorded as
      settled, and withdrawn: both interrupt handlers restore the interrupted
      `R4` and `(X,P)` in full (`28D2` and `067E`), so entering the tick chain
      from `51AD` is still handler work and replaces nothing. `IDL` plus a
      forward branch is "wait for one interrupt" — the idiom at `06EB` and
      `0CDF` — but `1A7C`'s branch points back at its own `IDL` and tests
      nothing, which makes it terminal unless a handler rewrites the saved
      continuation bytes on the stack at `M(R2)` before its epilogue. Find that
      rewrite, or establish that `1A7C` is a deliberate halt (§10av).

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

- [ ] **What drives bit 1 of `PORT5_shadow` (`8034`)?** It now has a precise
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

      So the cadence is armed only while that self-test passes, and suppressed
      once the fault is logged. **A driven line whose suppression is gated on a
      read-back check is most likely an output the firmware verifies, not an
      indicator.** The two "bit 1"s are on different ports, so this is a
      correlation, not a loop-back proof — establishing whether `PORT5` bit 1
      and `PORT2` input bit 1 are the same net is the next step, and it is a
      hardware question. Period (3 s / 3 s), duty cycle, delay (28 s) and both
      the arm and suppress conditions are now exact.

- [ ] **The second and third sections of the `13EC` timer table.** Section 1 is
      five `{pointer, flag-index}` triples and is fully read (§10az). `RE = 3`
      at `1415` says there are three sections, and `144B`–`1477` handles the
      rest with a different record layout: it reads a 2-byte pointer, then
      *increments* a 16-bit counter at it and compares it against two table
      bytes, zeroing both on a match. Reading those bytes as triples yields a
      "timer" at `008E`, so the layout definitely differs, but the 4-byte shape
      the code implies does not line up with the bytes either. Raw, from
      `13FE`: `8e d5 00 32 8e 04 04 8e 01 03 00 00 00 8e d7 0b b8 8e 00 03 00
      00 00`.

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
      | `28D8` | `interrupt_enter_reader` — **split it out of `28B7`**, whose body currently merges the card-reader epilogue and prologue into one function; the DLC side is correctly split into `interrupt_leave` / `interrupt_enter` | 10av |
      | `6E0C` | the reset block — no function at all | 10ay |
      | `1CB7` | the flash programmer's **ROM source image**, 1658 bytes — no function. Low priority: it never executes (§10ay), so a function here would only document the source. The executing copy at `9100`–`9779` already has ~21 functions. |

      The sequencer states pay off most: each is a few instructions and they are
      currently invisible as code.

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

- [ ] **What do the DLC payload tags mean, and type 0 vs type 1?**
      `build_dlc_frame` accepts only types 0 and 1 and the first payload byte
      is a tag — `0x0A` for "nothing to report", `0x0F` for a two-value report
      (§10ar). The other four wrappers' tags, and whatever the receive side
      expects, are unread.
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
      *not* part of the gap — §2 already has them as a RAM-resident chained
      vector and its one-shot gate, installed at `1003`/`100B`/`1015`.)
      *Also open:* who sets bit 7 of `8785`, and whether the transmit engine at
      `0AD6`–`0B2A` is reached at all (§10au found no reference to `0AD6`).
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
- [x] **Whether the firmware uses port 4** — **no.** The two apparent `OUT 4`
      sites, `2EA8` and `2EC5`, are the inline digit weights 100/10/1 that
      `binary_to_ascii_digits` reads through `X = R3`. §10k's port list should
      drop port 4 (§10al).
