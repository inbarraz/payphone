# Payphone reverse engineering project

This repo contains the reverse engineering project of the TAMAC18-model Israeli Payphone.

The repo includes the ROMs, the Ghidra CPU definition and (soon) the Ghidra project.

## Contents

- [`cdp1806/`](cdp1806/) — Ghidra CPU definition for the CDP1806, plus the
  inline-argument and SCRT call analyzers.
- [`phone/TAMAC18-firmware.md`](phone/TAMAC18-firmware.md) — reverse
  engineering notes for the TAMAC-18 payphone firmware (CDP1806ACE): the
  `P = R4` convention, the interrupt system, and the card reader link
  protocol from the phone's side.
- [`card-reader/BSK31-firmware.md`](card-reader/BSK31-firmware.md) — reverse
  engineering notes for the Landis & Gyr BSK31-202 optical phonecard reader
  (CDP1802) used by the payphone, including its wire protocol.
- [`OPEN-QUESTIONS.md`](OPEN-QUESTIONS.md) — the running queue of what is
  still unknown, what evidence bears on it, and what would settle it.
- [`tools/dump_strings.py`](tools/dump_strings.py) — dumps the firmware's
  Hebrew and Latin strings, and walks LCD descriptor chains. Handles the
  ROM's `0xA0`-based Hebrew encoding and its per-string byte order.

## Background

The hardware phase of this project is written up (in Hebrew) at
[מסתבר שגם טלפון ציבורי הוא טלפון חכם](https://www.retro.unarmedsecurity.net/post/%D7%9E%D7%A1%D7%AA%D7%91%D7%A8-%D7%A9%D7%92%D7%9D-%D7%98%D7%9C%D7%A4%D7%95%D7%9F-%D7%A6%D7%99%D7%91%D7%95%D7%A8%D7%99-%D7%94%D7%95%D7%90-%D7%98%D7%9C%D7%A4%D7%95%D7%9F-%D7%97%D7%9B%D7%9D):
acquiring the phone, dumping the Atmel AT29C256, and building the Ghidra
processor module.
