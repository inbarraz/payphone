# TAMAC-18 RAM map

Every RAM address the firmware points a register at, with the name it carries
in Ghidra or, where it has none, the signature the ROM shows for it. Generated
from the image by `tools/ram_map.py`, then annotated by hand — regenerating it
rewrites the Sites and Signature columns and keeps the Name column.

**`Sites`** counts the `RLDI Rn,addr` instructions that point a register at the
cell, plus the `SCAL` inline pointer arguments that name it. It is a lower
bound on real references: code reaches most of these cells by `INC`/`DEC` from a
neighbour, and the handler register map at `5FB1` keeps five of them in
registers across the whole reader link, so a cell with one site may be touched
from a dozen places.

**`Signature`** is what the walk sees being done to the cell at those sites:
`st` = number of stores, `imm` = the immediates stored, `mask` = the `ANI`
masks applied, `cmp` = the values it is compared against. A cell written only
`AA`/`55` and tested for equality is a sentinel; one written `00`/`01` and
tested for zero is a flag; one with masks is a bit field.

## Two things to know before using this

**`rename_data` only works where Ghidra already has a defined data item.**
The cells marked *(no Ghidra label)* have none, so the MCP rename returns its
usual "Rename data attempted" and changes nothing. They have no label because
the only way the code names them is as an inline-argument byte pair - the
operand of `increment_decimal_counter`, `clear_block_range` or
`store_reader_decimal_to_page80`, or an entry in the `30E3` pointer list - and
Ghidra sees instruction-stream bytes, not an operand, so it never creates a
reference. They need labelling by hand in the GUI; the names below are the ones
the notes use. The same holds outside RAM for `0048` and `30E3`, which Ghidra
has disassembled as instructions: they take a comment but not a name until a
data item exists there (see the notes, &sect;10am).

**An unnamed row is not a gap in the map, it is a gap in the knowledge.** The
ROM shows what is done to every one of these cells; what it does not show is
what any of them *is*. Naming the rest would mean inventing meanings, and the
signature column is the honest version of what is actually known. The rows
worth attacking first are the ones with many sites and a clear shape - `8165`
(11 sites, all in the idle loop), `812F` (13, walked by the `4F19`-`4FC2`
block), `8169`, `8183`, `81B5`, `8186`, `8182` - because a cell touched from a
dozen places has a dozen chances to give itself away.

## Page `80` — the card-reader link, the credit pools and the display frame

| Addr | Name | Sites | Signature |
|---|---|---|---|
| `8000` | — | 7 — `005d` `5d4d` `5d8c` `33a5` `4d8a` `5fc5` +1 | st=1 |
| `8001` | — | 1 — `25d0` | — |
| `8019` | `dialed_digits_end` *(no Ghidra label)* | 3 — `25b6` `2643` `264e` | st=0 |
| `801A` | `reader_tx_queue` | 1 — `514b` | st=0 |
| `801D` | `reader_tx_digit0` | 1 — `3682` | st=1 imm=01 |
| `8021` | `reader_tx_queue_top` | 1 — `366b` | st=0 |
| `8022` | `reader_msg_prefix0` | 3 — `334b` `3399` `340b` | st=0 |
| `8024` | `reader_digit0` | 4 — `2ab0` `36b3` `5034` `6231` | st=0 |
| `8027` | `reader_rx_ptr` | 2 — `507b` `6e7b` | st=1 imm=22 |
| `8028` | `reader_tx_countdown` | 5 — `3658` `390c` `5f4a` `5f9c` `6293` | st=0 |
| `8029` | `reader_link_flags` | 4 — `333d` `507f` `5380` `5fb1` | st=3 mask=20,df,fe |
| `802A` | `reader_tg_latch` | 2 — `313d` `337f` | st=1 imm=ff |
| `802B` | `reader_ok_latch` | 4 — `3375` `4561` `462b` `5c43` | st=1 imm=ff |
| `802C` | `card_measure_802c` | 3 — `466b` `468b` `5c3b` | st=2 imm=00 |
| `802D` | `card_measure_802d` | 1 — `2810` | st=1 imm=00 |
| `802E` | `card_measure_802e` | 1 — `6f4a` | st=1 imm=00 cmp=04 |
| `802F` | `card_measure_802f` | 5 — `43ef` `4615` `5c2b` `7352` `7572` | st=0 |
| `8030` | `mode_select_8030` | 3 — `451c` `45c8` `6f1d` | st=2 cmp=10 |
| `8031` | `link_resume_point` | 7 — `3900` `4726` `47ae` `4c14` `5f42` `5fb9` +1 | st=4 imm=00,d8 |
| `8032` | `call_in_progress` | 4 — `3790` `42b6` `4b1e` `703c` | st=2 cmp=aa |
| `8033` | `strap_drive_and_flags` | 16 — `0c9d` `19c3` `1a01` `2b1e` `2b78` `2b94` +10 | st=16 imm=01,10,20 mask=c0,e0 |
| `8034` | `PORT5_shadow` | 26 — `0707` `19f9` `1a14` `2824` `284e` `2c10` +20 | st=27 mask=01,02,7f,ce cmp=01,40 |
| `8035` | `PORT2_shadow` | 16 — `0cc0` `19d1` `241d` `2950` `295e` `2c57` +10 | st=15 mask=02,ef,f7,fd |
| `8036` | `timer_and_display_flags` | 23 — `01e4` `01f1` `28ac` `4132` `43f3` `4532` +17 | st=19 mask=40,7f,bf,df cmp=42 |
| `8038` | `LCD_next_descriptor` | 1 — `0721` | st=1 imm=00 |
| `803A` | `LCD_dwell_countdown` | 3 — `279a` `3199` `6e6e` | st=1 imm=00 |
| `803C` | `display_scratch_803c` | 5 — `2616` `71ec` `7201` `7679` `624a` | st=5 imm=00,20 |
| `803E` | `bufDisplayString_803E` | 5 — `4e46` `4e58` `4e75` `4ea1` `612c` | st=5 imm=00 |
| `803F` | `bufDisplayString_803F` | 1 — `622c` | — |
| `8040` | `bufDisplayString_8040` | 5 — `712c` `7133` `7157` `71a4` `71be` | st=6 imm=30,31 cmp=3a |
| `8041` | `bufDisplayString_8041` | 1 — `5e8e` | st=1 |
| `804B` | `bufDisplayString_804B` | 1 — `76e1` | st=0 |
| `804C` | `display_scratch_804c` | 7 — `57ed` `5842` `5882` `5ed2` `60c9` `57cd` +1 | st=3 imm=20 cmp=30 |
| `804E` | `bufDisplayString_804E` | 1 — `60b0` | st=1 imm=2e |
| `804F` | — | 2 — `60bc` `625a` | — |
| `8051` | `bufDisplayString_8051` | 1 — `60c2` | st=1 imm=00 |
| `8054` | `lcd_line2_bulk_digits` *(no Ghidra label)* | 1 — `2eb1` | st=0 |
| `8059` | `lcd_line2_drain_digits` *(no Ghidra label)* | 1 — `2e98` | st=0 |
| `805B` | `lcd_line2_end` *(no Ghidra label)* | 5 — `26aa` `2e74` `538d` `57bb` `5872` | st=0 |
| `805C` | `credit_bulk_pool` | 7 — `2d56` `3904` `397d` `47a7` `4c20` `5f46` +1 | st=2 imm=00 |
| `805D` | `credit_drain_pool` | 5 — `2e92` `2eab` `4776` `47d1` `4c94` | st=0 |
| `805E` | `credit_value` | 10 — `2a27` `2e05` `3a77` `460d` `472e` `479a` +4 | st=2 imm=00 cmp=78 |
| `805F` | `reader_ne_value` | 1 — `3977` | st=0 |
| `8060` | `card_packed_byte` | 3 — `2a1d` `46fc` `33ca` | st=0 cmp=30,78 |
| `8061` | `card_accepted_flag` | 2 — `3161` `33d0` | st=0 |
| `8062` | `card_value_7_minus_popcount` | 4 — `2e17` `33d6` `61ce` `72dd` | st=2 cmp=04,05 |
| `8064` | `burn_units_pending` | 2 — `2d62` `393a` | st=0 |
| `8065` | `credit_dirty_flag` | 5 — `3908` `458d` `47fa` `524f` `5f4e` | st=2 imm=00 |
| `8066` | `settle_resume_point` | 1 — `3966` | st=1 imm=59 |
| `8067` | `settle_request_shift` | 3 — `3910` `4a98` `53f2` | st=0 mask=80 |
| `8069` | `card_session_status` | 8 — `2e21` `3136` `320e` `33ab` `33b8` `3418` +2 | st=4 imm=55,69,6a cmp=6a,aa |
| `806A` | `card_units_shadow` | 2 — `3487` `34a8` | st=1 |
| `806B` | `settle_done_flag` | 3 — `395a` `5277` `528b` | st=2 imm=00,aa cmp=aa |
| `806C` | `burn_watchdog_ticks` | 1 — `2d5e` | st=0 |
| `8070` | `metering_high_count` | 1 — `373c` | st=0 |
| `8074` | `hardware_version` | 12 — `26a3` `3470` `3c00` `4558` `4583` `5370` +6 | st=9 imm=00,aa,dd,ff cmp=aa,dd |
| `8077` | — | 2 — `4624` `5c33` | st=1 imm=aa |
| `8078` | `pulse_prev_sample` | 1 — `423c` | st=1 |
| `8079` | — | 2 — `7316` `7690` | st=0 cmp=aa |
| `807A` | — | 2 — `45c1` `75ca` | st=1 imm=aa cmp=aa |
| `807B` | `saved_8183` | 2 — `26e1` `4b28` | st=1 |
| `807C` | — | 5 — `5df9` `5f6e` `777d` `77f4` `4d78` | st=3 imm=00,aa cmp=aa |
| `807D` | `port1_readback` | 3 — `2439` `413d` `7663` | st=0 |

## Page `81` — timers, mode flags and call state

| Addr | Name | Sites | Signature |
|---|---|---|---|
| `8117` | `recent_key_m2` | 1 — `2563` | st=0 |
| `8118` | `recent_key_m1` | 1 — `2759` | st=0 |
| `8119` | `recent_key_last` | 10 — `00b9` `1a26` `25d8` `2c81` `2dfd` `3191` +4 | st=2 imm=15,80 |
| `811A` | `dial_buf_ptr` | 7 — `25d4` `2652` `2c74` `2c8f` `35b7` `3b5f` +1 | st=3 imm=15 cmp=01 |
| `811B` | `dial_buf_end` | 6 — `1a5f` `2c23` `3b1a` `45f1` `7054` `72aa` | st=4 imm=19 cmp=17,18 |
| `811D` | `minute_meter_timer` | 1 — `4223` | st=1 imm=3c |
| `811F` | — | 1 — `4290` | st=0 |
| `8122` | `rate_word_a` | 4 — `37a1` `530a` `4159` `52fc` | st=0 |
| `8124` | `rate_word_b` | 1 — `5303` | st=0 |
| `8127` | — | 2 — `3a1f` `7424` | st=2 imm=c8 |
| `8128` | `slow_timer_8128` | 3 — `25a4` `72d0` `76f4` | st=1 imm=04 |
| `8129` | — | 6 — `44e9` `48ce` `4b58` `6ff5` `7623` `7649` | st=1 imm=64 cmp=32 |
| `812A` | `fast_timer_812a` | 2 — `31c3` `4a49` | st=1 imm=96 |
| `812B` | — | 5 — `1a44` `53bd` `72b2` `73d5` `73dc` | st=2 imm=00,20 |
| `812C` | — | 4 — `454a` `4569` `461d` `4633` | st=2 imm=64 |
| `812D` | `wait_timer_812d` | 5 — `36e6` `3ab3` `401e` `5ef5` `6fa5` | st=5 imm=00,96 |
| `812E` | — | 1 — `2656` | st=1 imm=0a |
| `812F` | — | 13 — `3834` `493b` `4f19` `4f2b` `4f48` `4f5e` +7 | st=7 imm=00,0f,32,64,96 |
| `8130` | `timer_prescaler` | 1 — `40f4` | st=2 imm=00 |
| `8131` | `slow_timer_8131` | 1 — `491a` | st=1 imm=1e |
| `8132` | `fast_timer_8132` | 1 — `42be` | st=0 |
| `8133` | `slow_timer_8133` | 1 — `6f46` | st=0 |
| `8134` | `slow_timer_8134` | 4 — `4104` `412a` `5fd5` `70ce` | st=2 imm=5a,aa cmp=aa |
| `8136` | `slow_timer_8136` | 2 — `1b7b` `1b91` | st=1 |
| `8137` | `slow_timer_8137` | 4 — `26fa` `4d95` `6eba` `704d` | st=3 imm=5a |
| `8138` | `charge_step` | 1 — `2d18` | st=0 |
| `8139` | `card_permission_bits` | 29 — `0095` `2559` `26dc` `2723` `2814` `282b` +23 | st=5 imm=00,04 mask=02,04,06,08 cmp=41 |
| `813A` | — | 7 — `1a59` `250c` `2c3d` `7048` `735a` `7389` +1 | st=3 imm=01 |
| `813B` | — | 5 — `009f` `2741` `2a15` `742b` `7730` | st=0 cmp=01,03,04,05,0b |
| `813C` | — | 3 — `2686` `37b9` `45f9` | st=2 imm=00,14 |
| `813D` | — | 2 — `2421` `5d23` | st=1 |
| `813E` | `dial_resume_point` | 17 — `00a3` `2500` `25c1` `267c` `26eb` `35be` +11 | st=11 imm=00,21,24,27,2a cmp=27,2a |
| `813F` | — | 5 — `2663` `2a31` `4d53` `4da9` `5eee` | st=4 imm=00 cmp=0b |
| `8143` | `charge_event_pending` | 5 — `0640` `2d10` `35cc` `379a` `48fc` | st=4 imm=01 cmp=01 |
| `8144` | `charge_phase` | 13 — `2579` `2638` `2716` `2a4b` `2c4f` `2deb` +7 | st=0 |
| `8145` | `debit_pending` | 1 — `2d5a` | st=0 |
| `8147` | `linedrive_count_8147` | 3 — `42c3` `43ae` `43c2` | st=1 imm=00 |
| `8148` | `linedrive_dwell_8148` | 1 — `43d9` | st=1 |
| `8149` | `linedrive_state_8149` | 7 — `42ba` `4912` `4b19` `52a0` `52b8` `5f7c` +1 | st=5 imm=00 mask=40,7f |
| `814A` | `low_credit_display_arm` | 4 — `2dd3` `2e78` `3924` `5283` | st=2 |
| `814B` | — | 2 — `1a36` `72ae` | st=1 imm=80 |
| `814C` | — | 3 — `1a3d` `35b0` `3b69` | st=2 imm=00 |
| `814D` | `measurement_step_bits` | 5 — `34ec` `61ca` `620b` `626e` `62ac` | st=1 mask=40,80 |
| `8155` | — | 1 — `76dd` | st=0 |
| `8164` | — | 1 — `2612` | st=0 |
| `8165` | — | 11 — `44d4` `4509` `4660` `4716` `483d` `4895` +5 | st=2 imm=05 |
| `8166` | — | 1 — `5c01` | st=0 |
| `8167` | `mode_flags_8167` | 26 — `1ace` `1af2` `1b19` `1b3d` `1b67` `1bb4` +20 | st=12 imm=00,0e,20,28,2c,80 mask=20,80,fa cmp=20 |
| `8168` | — | 2 — `475f` `47bb` | st=1 imm=aa cmp=aa |
| `8169` | — | 9 — `4b6d` `4b8c` `4bb0` `4cac` `4d07` `5951` +3 | st=2 imm=55 cmp=55 |
| `816B` | — | 7 — `19bc` `19f2` `270c` `374f` `3b43` `4025` +1 | st=4 imm=00,55 cmp=55 |
| `816C` | — | 1 — `4942` | st=1 imm=00 |
| `816D` | — | 1 — `273d` | st=0 |
| `816F` | — | 1 — `2782` | st=1 |
| `8170` | — | 2 — `4084` `7716` | st=3 imm=05 |
| `8172` | — | 1 — `711e` | st=0 |
| `8173` | — | 1 — `711a` | st=1 imm=00 |
| `8174` | `bufDisplayString_8174` | 1 — `713f` | st=1 |
| `8180` | `fast_timer_8180` | 6 — `3733` `3763` `4d9c` `6ecc` `6fee` `7021` | st=5 imm=19,64 |
| `8182` | — | 4 — `1a4b` `2b33` `4b12` `73ca` | st=4 imm=00,01 |
| `8183` | `permission_valid_8183` | 6 — `26e6` `2c36` `3a33` `4b23` `72fe` `7409` | st=2 cmp=aa |
| `8184` | `low_credit_warned` | 2 — `527e` `5295` | st=2 imm=aa |
| `8185` | `port3_readback` | 2 — `50d9` `617e` | st=1 cmp=3f |
| `8186` | — | 4 — `4180` `44dc` `6fc8` `7035` | st=2 imm=00,aa |
| `818C` | — | 2 — `5d09` `5d1b` | st=1 |
| `818D` | `burn_ack_retry_count` | 4 — `3420` `343c` `5db8` `623f` | st=3 imm=00 cmp=64 |
| `818E` | `reader_z_reply_count` | 3 — `2a53` `3453` `34bc` | st=4 imm=80 |
| `8190` | `config_parse_result` | 2 — `3e2f` `5d97` | st=1 cmp=04 |
| `8191` | `port1_bit0_latch` | 6 — `2c9f` `2e2e` `4149` `45e4` `5d78` `6ea2` | st=3 |
| `8196` | — | 1 — `3ef9` | st=1 |
| `8197` | — | 1 — `4ce7` | — |
| `819B` | — | 2 — `3e58` `3ef5` | st=1 cmp=3a |
| `81A3` | — | 2 — `3f4f` `5987` | st=4 imm=00,57,84,aa |
| `81A5` | — | 1 — `3e78` | st=0 |
| `81A9` | — | 1 — `3e74` | st=0 |
| `81AC` | — | 2 — `3d94` `3d9c` | st=0 |
| `81AD` | — | 1 — `3eb1` | st=0 |
| `81B1` | — | 1 — `3ecf` | st=0 |
| `81B4` | — | 2 — `3ead` `3ecb` | st=0 |
| `81B5` | — | 8 — `1c48` `2c97` `2e3e` `3ec0` `3eeb` `3ff5` +2 | st=0 cmp=42,43,44 |
| `81BA` | — | 1 — `2cbf` | st=1 imm=3b |
| `81CB` | — | 1 — `2cc6` | st=1 imm=3d |
| `81E0` | — | 1 — `2ccd` | st=1 imm=3f |
| `81E1` | — | 1 — `2cba` | — |
| `81F8` | — | 1 — `3d98` | st=0 |
| `81FA` | — | 1 — `52cb` | st=0 mask=0f |
| `81FB` | — | 2 — `4b0a` `7667` | st=1 mask=20 |
| `81FC` | — | 2 — `4466` `5c77` | st=3 mask=fd,fe |

## Pages `82`–`84` — the fault log and event records

| Addr | Name | Sites | Signature |
|---|---|---|---|
| `8300` | — | 1 — `6e25` | st=0 |
| `8303` | — | 1 — `52cf` | st=0 |
| `83FE` | — | 1 — `6e20` | — |
| `8409` | — | 1 — `3c1b` | st=0 |
| `840A` | `fault_log` | 4 — `3c23` `3f70` `5b9e` `600d` | st=2 mask=7f |
| `843A` | — | 1 — `3b24` | st=0 |
| `8442` | — | 5 — `3c1f` `5b97` `5ccc` `5e1c` `5e6e` | st=3 imm=00 |
| `8443` | — | 4 — `3c6d` `3faa` `5be2` `2f48` | st=2 |
| `8444` | — | 1 — `3f9c` | st=1 |
| `8445` | — | 1 — `3fa6` | st=0 |
| `8446` | — | 1 — `3f97` | st=1 |
| `8447` | — | 1 — `3fa1` | st=1 |
| `8448` | `cleaning_event_record` | 1 — `3fb0` | st=1 |
| `8449` | — | 1 — `3c69` | st=0 |
| `844A` | — | 4 — `2f51` `3bdc` `3f90` `3fe8` | st=4 imm=00,01 |
| `844B` | — | 3 — `3e50` `3fc2` `5da4` | st=2 imm=00,05 cmp=04 |
| `844C` | — | 1 — `5de4` | st=0 |
| `844D` | `coldstart_sentinel_844d` | 1 — `306f` | st=1 imm=aa |
| `844E` | — | 5 — `3ae4` `3af8` `5b7b` `54a3` `574c` | st=0 |
| `845A` | `pulse_count_event` | 6 — `23ae` `2f4c` `3f5f` `4252` `4cee` `76c6` | st=4 imm=00 cmp=2d |
| `845C` | — | 19 — `1c1a` `1c26` `1c35` `1c41` `2cda` `2f30` +13 | st=13 imm=00,23,80,c0 mask=01,f0,fc cmp=c0,ca |
| `845D` | `ram_sentinel_845d` | 1 — `6112` | st=1 imm=00 |

## Page `85` — provisioning and the totalizer bank

| Addr | Name | Sites | Signature |
|---|---|---|---|
| `8500` | — | 3 — `3084` `3bf0` `55a4` | st=1 |
| `8501` | — | 8 — `1cec` `2e36` `3ae8` `3afd` `5655` `5b6e` +2 | st=0 |
| `850D` | — | 4 — `2f26` `5437` `55ab` `308e` | st=1 cmp=40 |
| `850E` | `accept_list_count` | 3 — `33f0` `5ce0` `55c2` | st=0 |
| `850F` | `accept_list_0` | 2 — `568e` `5ce9` | st=0 |
| `8513` | — | 5 — `1a52` `4db6` `5479` `7041` `55ce` | st=1 cmp=01 |
| `8514` | `credit_divisor` | 2 — `347d` `55d6` | st=0 cmp=01 |
| `8515` | — | 3 — `2d3e` `5342` `55de` | st=0 cmp=01 |
| `8516` | `counter4_8516` *(no Ghidra label)* | 3 — `4298` `2f3f` `55e6` | st=0 |
| `851A` | `minute_meter` *(no Ghidra label)* | 2 — `422e` `55ef` | st=0 |
| `8520` | `charged_period_counter` *(no Ghidra label)* | 2 — `2d1f` `55f8` | st=0 |
| `8526` | `units_burned_counter` *(no Ghidra label)* | 2 — `36c9` `5601` | st=0 |
| `852C` | — | 7 — `4e15` `4e3e` `4e42` `4e71` `4e9d` `4e3a` +1 | st=0 |
| `852F` | — | 5 — `5614` `70fc` `7128` `71b4` `71b0` | st=0 |

## Pages `86`–`87` — the technician menu and its buffers

| Addr | Name | Sites | Signature |
|---|---|---|---|
| `8600` | — | 1 — `74d0` | — |
| `8602` | — | 1 — `5a15` | st=2 imm=02 |
| `8629` | — | 1 — `74ea` | st=0 |
| `862A` | — | 6 — `59bc` `59c0` `5a3e` `5a55` `7522` `7526` | st=3 |
| `862B` | — | 1 — `7518` | st=0 |
| `867B` | `coldstart_sentinel_867b` | 1 — `3076` | st=1 imm=55 |
| `867F` | — | 1 — `3ce4` | st=0 |
| `8680` | — | 1 — `3cc1` | st=0 |
| `8681` | — | 1 — `3bec` | st=1 imm=02 |
| `8700` | — | 2 — `62d2` `74d9` | st=0 |
| `8780` | — | 3 — `62d6` `6379` `640e` | st=2 |
| `8781` | — | 2 — `370c` `3df7` | st=0 |
| `8783` | — | 1 — `5a6f` | st=1 |
| `8785` | — | 5 — `3b84` `3d74` `4006` `509d` `6e32` | st=4 imm=00,80 |
| `8786` | — | 5 — `3cca` `50b0` `5ab3` `5b0b` `5b29` | st=2 mask=01,0f,80 |
| `8787` | — | 1 — `3d8b` | st=1 imm=00 |
| `8788` | — | 2 — `636e` `63de` | st=2 imm=00 |
| `8789` | — | 1 — `5a8e` | st=1 |
| `878A` | — | 5 — `3cd2` `3dab` `3dd4` `3dfd` `62dc` | st=7 imm=04 cmp=01 |
| `878C` | — | 3 — `508d` `5a3a` `752a` | st=1 |
| `878E` | — | 1 — `5af0` | st=3 imm=ff cmp=01 |
| `8790` | — | 1 — `5ae1` | st=0 |
| `8791` | — | 1 — `403c` | st=0 |
| `8794` | — | 1 — `74dd` | st=0 |
| `8795` | — | 3 — `3cdd` `3d05` `5ac4` | st=5 imm=00 |
| `87C0` | — | 1 — `2209` | — |

## Page `88`–`89` — counters, the state machine and the stack

| Addr | Name | Sites | Signature |
|---|---|---|---|
| `8850` | — | 4 — `26d1` `41d2` `6fd4` `7619` | st=1 mask=04,10 |
| `8851` | — | 1 — `705e` | st=0 |
| `8852` | — | 5 — `35ea` `6ec1` `6fe3` `6fff` `70b9` | st=0 |
| `8859` | — | 4 — `2ca7` `2ce6` `5991` `76ba` | st=3 imm=00,a5 cmp=a5 |
| `885B` | — | 2 — `3fe0` `7782` | st=2 |
| `885D` | `pulse_count_report` | 2 — `425a` `769c` | st=2 imm=00 cmp=2d |
| `885F` | — | 3 — `28a2` `43e8` `444b` | st=2 imm=00,aa cmp=aa |
| `8861` | — | 2 — `4ef1` `4f06` | st=1 imm=00 |
| `8862` | — | 1 — `4fd5` | st=0 |
| `8863` | — | 6 — `3567` `383c` `4eea` `4efc` `4f33` `4fca` | st=4 imm=00,aa cmp=aa |
| `8864` | — | 2 — `3548` `3551` | st=1 imm=aa cmp=aa |
| `8865` | — | 3 — `2f0d` `51e8` `2f09` | st=1 imm=aa cmp=aa |
| `8866` | `sm_change_shadow` | 1 — `522a` | st=0 |
| `8867` | `sm_change_current` | 2 — `51da` `521c` | st=1 cmp=01 |
| `8868` | — | 1 — `51f2` | st=0 |
| `886A` | `sm_input_value` | 2 — `5214` `5238` | st=1 |
| `886B` | `sm_bracket` | 2 — `3278` `32aa` | st=1 |
| `886C` | `sm_state` | 3 — `3270` `51d3` `5503` | st=2 imm=00 cmp=04 |
| `8890` | — | 1 — `2f14` | st=0 |
| `8891` | — | 1 — `2f18` | st=0 |
| `88BA` | — | 3 — `2a11` `2cf6` `46ea` | st=1 imm=00 cmp=aa |
| `88BB` | `optical_reader_fault_flag` | 2 — `23a6` `29e9` | st=0 |
| `88BD` | `units_spent_marker` | 3 — `36c2` `5063` `51b9` | st=2 imm=00,aa |
| `88BE` | — | 3 — `75e7` `75f9` `7680` | st=3 imm=00 cmp=aa |
| `88C0` | — | 1 — `77a6` | st=0 |
| `88C1` | — | 1 — `39de` | st=0 |
| `88C5` | — | 5 — `3992` `44bc` `48a9` `48f5` `6f19` | st=6 imm=00,aa mask=7f |
| `89FA` | `stack_top` *(no Ghidra label)* | 2 — `306b` `6e08` | st=0 |
| `89FE` | — | 1 — `5c98` | st=0 |

## Pages `8A`–`8C` — the DLC / line side

| Addr | Name | Sites | Signature |
|---|---|---|---|
| `8A01` | — | 3 — `023d` `0d8b` `14b8` | st=0 |
| `8A58` | — | 1 — `08eb` | — |
| `8B0B` | — | 9 — `0241` `024f` `0615` `0784` `0a7d` `0ab0` +3 | st=2 imm=00 |
| `8B0D` | — | 1 — `0aa9` | st=0 |
| `8B0E` | — | 1 — `0d8f` | st=0 |
| `8B0F` | — | 1 — `0a76` | st=0 |
| `8B10` | — | 1 — `0d9a` | st=0 |
| `8B11` | — | 1 — `0d96` | st=0 |
| `8C1B` | — | 1 — `0db1` | st=1 |
| `8C1D` | — | 1 — `0a90` | st=1 imm=01 |
| `8C1F` | — | 1 — `0af4` | st=0 |
| `8C20` | — | 2 — `0be5` `0c30` | st=0 |
| `8C21` | — | 4 — `077b` `0ad6` `0ae1` `0bc5` | st=2 imm=00 |
| `8C22` | — | 1 — `0c20` | st=0 |
| `8C23` | — | 4 — `0afb` `0bd5` `0c27` `0b0f` | st=2 imm=00 |
| `8C25` | — | 2 — `0e2e` `0f2a` | st=0 |
| `8C26` | — | 1 — `0949` | st=0 |
| `8C27` | — | 3 — `039e` `03e9` `0bec` | st=1 imm=cc |
| `8C28` | — | 1 — `0be1` | st=0 |
| `8C29` | — | 1 — `03f2` | — |
| `8C37` | — | 1 — `77dd` | st=0 |
| `8C59` | — | 1 — `1674` | st=1 imm=05 cmp=02 |

## Pages `8D`–`8E` — the modem side and the ROM checksum

| Addr | Name | Sites | Signature |
|---|---|---|---|
| `8D26` | — | 3 — `020a` `180d` `1cc2` | st=1 imm=02 |
| `8DA6` | — | 2 — `02d6` `0bcd` | st=1 cmp=01 |
| `8DA7` | — | 5 — `03af` `0772` `0953` `0e2a` `0f26` | st=1 imm=00 |
| `8DA9` | — | 2 — `1dfb` `1e56` | st=1 |
| `8DAA` | — | 1 — `1809` | st=0 |
| `8DAB` | — | 8 — `0798` `0e6b` `1817` `1ddf` `1e46` `1e74` +2 | st=4 imm=00,01 cmp=02 |
| `8DAC` | `feature_flags_8dac` | 7 — `0222` `0278` `0338` `0352` `05fb` `072e` +1 | st=4 imm=00,01 cmp=01 |
| `8DAD` | — | 2 — `04c8` `04da` | st=2 imm=01 |
| `8DAE` | — | 1 — `060a` | st=1 imm=01 |
| `8DB3` | — | 1 — `0b1c` | st=1 imm=01 |
| `8DB4` | — | 1 — `0f8e` | st=1 imm=01 |
| `8DB8` | — | 2 — `0f75` `0f87` | st=1 imm=00 |
| `8DBB` | — | 10 — `0a69` `0d84` `0dcd` `0df7` `0e0f` `0e19` +4 | st=9 imm=00,01 |
| `8DBC` | — | 3 — `04c0` `04d2` `0d5f` | st=1 imm=01 |
| `8DBD` | — | 2 — `0b14` `0b23` | st=1 imm=00 |
| `8DC2` | — | 1 — `1daf` | st=0 |
| `8DC3` | — | 3 — `0e23` `0f3d` `0f58` | st=3 imm=00 |
| `8DC5` | — | 4 — `0c83` `0cb9` `3759` `6f10` | st=3 imm=00,01 cmp=01 |
| `8DCC` | — | 4 — `17cf` `202e` `157f` `233d` | st=0 |
| `8DCD` | — | 3 — `14e1` `2050` `2071` | st=2 |
| `8DCE` | — | 2 — `193b` `2036` | st=0 |
| `8DCF` | — | 2 — `17ee` `2069` | st=1 |
| `8DD2` | — | 1 — `1371` | st=0 |
| `8DD4` | — | 1 — `1fb5` | st=0 |
| `8DD6` | — | 1 — `1fbc` | st=0 |
| `8DD7` | — | 3 — `0581` `058c` `1d88` | st=2 imm=00 |
| `8DD8` | — | 3 — `0b83` `0e3a` `0ec2` | st=3 imm=00 |
| `8DD9` | — | 6 — `056d` `0d0f` `0e7f` `0ede` `0ef6` `0f0e` | st=1 |
| `8DDA` | — | 3 — `0563` `1bf6` `0ee5` | st=1 |
| `8DDB` | — | 2 — `055e` `0d16` | st=1 |
| `8DDC` | — | 3 — `0568` `1bfe` `0efd` | st=1 |
| `8DDD` | — | 3 — `0557` `0e4d` `0f4c` | st=2 imm=00 |
| `8DDE` | — | 1 — `163d` | st=0 |
| `8DE2` | — | 1 — `0650` | — |
| `8DE6` | — | 5 — `079d` `0e5a` `0f7d` `1519` `152e` | st=4 imm=00 |
| `8DE7` | — | 3 — `0572` `0e52` `0f15` | st=2 |
| `8DE8` | — | 4 — `1387` `191b` `1d71` `0e9c` | st=0 |
| `8DEC` | — | 2 — `02a9` `155d` | st=1 |
| `8DF0` | — | 2 — `0ea7` `1d81` | st=1 |
| `8DF1` | — | 4 — `02b9` `0ea2` `13e0` `1568` | st=2 imm=00 |
| `8DF2` | — | 2 — `1550` `1590` | st=1 |
| `8DF3` | — | 1 — `13da` | st=0 |
| `8DF4` | — | 3 — `1630` `190c` `1d45` | st=1 |
| `8DFA` | — | 1 — `164a` | st=0 |
| `8DFC` | — | 1 — `09fa` | st=1 |
| `8DFD` | — | 1 — `08f2` | st=0 |
| `8DFE` | — | 1 — `075b` | st=1 |
| `8DFF` | — | 3 — `0a0f` `1ded` `1e4d` | st=1 |
| `8E00` | — | 2 — `073b` `1482` | st=2 imm=00,78 |
| `8E01` | — | 7 — `0742` `0d26` `0d30` `0d7d` `0dc6` `0df0` +1 | st=7 imm=00,05,14,1e,3c |
| `8E02` | — | 2 — `0747` `0acc` | st=2 |
| `8E03` | — | 5 — `074c` `0ac7` `0da1` `0ddf` `0e01` | st=4 imm=00,0f,64 |
| `8E04` | — | 7 — `0751` `0de6` `0e08` `0e41` `0f36` `0f4e` +1 | st=7 imm=00,14 |
| `8E05` | — | 2 — `1718` `17ac` | st=0 cmp=01 |
| `8E0A` | `code_shadow_mode` | 3 — `1ed8` `1ef1` `30c3` | st=3 imm=00,01 |
| `8E0B` | — | 2 — `0525` `0530` | st=2 imm=00 |
| `8E0C` | — | 1 — `20de` | st=1 |
| `8E0D` | — | 2 — `066f` `1003` | st=1 |
| `8E0F` | — | 5 — `05cd` `065c` `0756` `100b` `1015` | st=4 imm=00,01 |
| `8E10` | `CTRL_F000_shadow` | 4 — `0011` `13a2` `1ed1` `1eea` | st=3 imm=02,03 |
| `8E11` | — | 3 — `078d` `0a97` `0dd4` | st=2 imm=00,01 |
| `8E12` | — | 1 — `097c` | st=0 |
| `8E13` | — | 1 — `0978` | st=0 |
| `8E14` | — | 2 — `0d37` `0d69` | st=2 imm=00 |
| `8E2A` | — | 2 — `07cc` `07e6` | st=1 imm=00 |
| `8E2C` | — | 2 — `07c8` `0800` | st=1 imm=00 |
| `8E2D` | — | 1 — `0980` | st=1 imm=01 cmp=09 |
| `8E2E` | — | 4 — `09bb` `09d4` `09fe` `0a07` | st=1 |
| `8E36` | — | 3 — `090e` `0925` `091c` | st=1 |
| `8E37` | — | 1 — `0936` | — |
| `8E38` | — | 1 — `08d1` | st=1 |
| `8E68` | — | 2 — `0306` `0310` | st=0 |
| `8E6B` | — | 1 — `0317` | st=0 |
| `8E6D` | — | 1 — `03f7` | st=0 |
| `8E76` | — | 1 — `21f7` | st=0 |
| `8E77` | — | 1 — `2176` | st=0 |
| `8E79` | — | 7 — `20f4` `210a` `2120` `2136` `214d` `219c` +1 | st=5 imm=00,01 cmp=00 |
| `8E7A` | — | 2 — `21c4` `220d` | st=0 cmp=01 |
| `8E7B` | — | 7 — `20a1` `20bb` `20ec` `221d` `2233` `2268` +1 | st=2 imm=fc |
| `8EBC` | — | 1 — `5c72` | st=1 |
| `8EC0` | — | 3 — `1985` `1ec6` `1fa9` | — |
| `8EC8` | — | 2 — `14c1` `14ce` | st=1 |
| `8EC9` | — | 1 — `14da` | st=0 cmp=08 |
| `8ECC` | — | 2 — `0ba8` `0b39` | st=1 |
| `8ECD` | — | 1 — `0bad` | st=1 imm=00 |
| `8ECF` | — | 3 — `15a5` `1958` `0b5b` | st=2 |
| `8ED0` | — | 2 — `15ab` `195d` | st=2 imm=00 |
| `8ED5` | — | 1 — `0760` | st=1 imm=00 |
| `8ED7` | — | 1 — `0769` | st=1 imm=00 |
| `8EDD` | — | 4 — `06d3` `0fa0` `0fc7` `0ff3` | st=2 imm=00 |
| `8EE0` | — | 3 — `1fd8` `2016` `205d` | st=1 cmp=00 |
| `8EE1` | — | 3 — `1ff8` `203e` `200c` | st=1 |
| `8EE4` | — | 2 — `200e` `2083` | st=1 |
| `8EE6` | — | 1 — `1f4d` | st=0 |
| `8EE7` | — | 1 — `2026` | st=0 |
| `8EE8` | — | 1 — `2000` | st=0 |
| `8EEA` | — | 2 — `044c` `0d4b` | st=2 imm=00,aa |
| `8EF2` | — | 1 — `0453` | st=0 |
| `8EF3` | — | 1 — `0538` | st=1 |
| `8EF4` | — | 1 — `06f3` | st=0 |
| `8EF7` | — | 1 — `06ba` | st=0 |
| `8EF8` | — | 3 — `0593` `06c7` `070f` | st=2 imm=00,01 |
| `8EF9` | — | 1 — `1e7c` | st=0 |
| `8EFA` | — | 1 — `0416` | st=1 imm=00 |
| `8EFC` | — | 2 — `1626` `1d4f` | st=1 |
| `8EFD` | — | 2 — `15f0` `1cfa` | st=1 |
| `8F38` | — | 1 — `5f27` | — |
| `8FCA` | — | 1 — `459e` | — |
| `8FE2` | — | 1 — `729a` | — |
| `8FFB` | — | 3 — `2fbc` `495f` `4c0e` | — |
| `8FFE` | — | 3 — `478d` `4860` `4884` | — |

## Page `97` and above — RAM-resident code and its variables

| Addr | Name | Sites | Signature |
|---|---|---|---|
| `9100` | — | 2 — `07a7` `136b` | — |
| `92EB` | — | 1 — `5ad5` | — |
| `9733` | — | 1 — `026f` | — |
| `9771` | — | 1 — `304f` | — |
| `9797` | — | 3 — `15fb` `16b2` `24bc` | st=1 |
| `9798` | — | 2 — `16a4` `309c` | st=0 |
| `979B` | — | 1 — `161f` | — |
| `979C` | — | 1 — `30b2` | st=0 |
| `979F` | — | 4 — `1bd6` `24e4` `30ac` `1c79` | st=1 |
| `97A1` | `code_shadow_job_state` | 9 — `0028` `051b` `0577` `0e8f` `0f6b` `1394` +3 | st=4 imm=00 cmp=01,02 |
| `97A4` | — | 2 — `1b12` `1b52` | st=2 imm=00 |
| `97A5` | — | 1 — `5bf5` | st=1 |
| `97A6` | — | 3 — `5e4d` `5e60` `1c64` | st=2 imm=06 |
| `97A8` | — | 1 — `76a9` | st=1 imm=00 |
| `97AA` | — | 1 — `1c6b` | — |
| `97AC` | — | 1 — `76b0` | st=1 |
| `97AD` | — | 2 — `24d3` `24dc` | st=1 |
| `97AE` | — | 2 — `30a6` `1c72` | st=0 |
| `97B0` | — | 1 — `76b5` | st=1 |
| `97B1` | — | 3 — `1ac2` `1bc5` `1c08` | st=1 cmp=02 |
| `97B2` | — | 2 — `1b2e` `1b99` | st=1 imm=04 |
| `97B3` | — | 1 — `1aea` | st=0 |
| `DFFF` | — | 1 — `305b` | st=1 imm=aa |
| `E000` | — | 4 — `27b2` `296c` `2970` `6e39` | st=2 |

## Tally

399 anchored cells, **121 named**, 278 still unnamed.
