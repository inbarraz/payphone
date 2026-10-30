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
