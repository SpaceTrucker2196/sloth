# attacker-ouis: OUIs of attack hardware

`attacker_ouis.csv` holds the two tables sloth's evil-twin rule reads on
the vendor side of a twin pair (`oui_is_hak5()`, `oui_is_espressif()` in
sloth's
[`src/wifi_oui_attacker.c`](https://github.com/SpaceTrucker2196/sloth/blob/fa366881644ad32160f5ca8e586af0fdedac00c4/src/wifi_oui_attacker.c)
at `fa366881`). Columns: `oui` (six upper-case hex digits), `family`
(`hak5` or `espressif`; one C array each, in this order) and `note` (the
row's own comment in the source, carried verbatim). Moved and held byte
for byte to that source by sloth-comint's parity check.

The source's citations, carried over:

- **hak5.** "Hak5 - Pineapple radios, Bash Bunny, Packet Squirrel. The
  00:13:37 prefix is a long-standing Hak5 vanity OUI; 00:c0:ca is the
  Alfa-Networks USB radio they ship in newer kit. Both have appeared in
  evil-twin captures at conferences and pentest engagements; matching
  them on the vendor side of a twin pair is a strong signal." sloth's
  `research/tools/wifi-pineapple-mk7.md` documents the device.
  **What the registry says is not what the row's note says:** in
  the IEEE MA-L registry (ieee-data 20260625) 00:13:37 is
  assigned to "Orient Power Home Network Ltd." and 00:C0:CA to
  "ALFA, INC.". A vanity prefix is a prefix the tool configures, not
  one the IEEE assigned to Hak5; the note is carried verbatim from the
  source and is not corrected here, because Stage 1 moves rows without
  changing them (the parity rule). Raised with the owner.
- **espressif.** "ESP32 / ESP8266 / ESP32-C3 OUI ranges. Listed
  because cheap-rogue-AP builds (ESP32-Marauder, Wi-Fi-Nugget) ride
  these chips. Espressif chips also ship in legitimate IoT, so this
  signal only matters when twin-pair geometry already triggered the
  WARN branch." Each row is an IEEE MA-L assignment to Espressif Inc.
- **AC0BFB** (from sloth #74): "The Flipper Zero's Wi-Fi devboard is an
  ESP32-S2, so this block reaches sloth as \"Flipper\" in the field -
  but the OUI cannot say that. It cannot separate a Flipper devboard
  from an ESP32 Marauder from any other ESP32 project, which is why it
  sits in the Espressif table and not a Flipper one. Unverified: taken
  from the issue's research, not measured here."

**Licence.** The assignments are the IEEE's public listing; the
selection and notes were written in sloth (SLOTH SOURCE-AVAILABLE
LICENSE 1.0) by the owner of both repositories. sloth carries them under
its own licence; sloth-comint publishes them under PolyForm
Noncommercial 1.0.0.