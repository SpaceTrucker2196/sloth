---
source_url: https://communityarchive.victronenergy.com/storage/attachments/extra-manufacturer-data-2022-12-14.pdf
retrieved: 2026-11-15
topics: [victron, ble, instant-readout, manufacturer-data, aes-ctr, gatt, smartshunt, bmv-712, orion, ve-direct, pairing, sloth-va]
citation: Victron Energy, "Extra manufacturer data" (wiki rend:ble:extra_manufacturer_data, printed 2022-12-14); Victron staff posts in the community thread "Victron Bluetooth BLE protocol publication" (2021-2023); Victron, "VE.Direct Protocol" 3.32; keshavdv/victron-ble (community; description and test vectors only)
---
# Victron Instant Readout and the 6597 GATT service — what is published

The basis for sloth-va (`src/va/`, docs/wiki/victron.md, ADR 0011).
Read first-hand on 2026-11-15 unless a line says otherwise. sloth-va
implements only what is below; each item says how sure it is.

**Verdict.** The Instant Readout payload is published by Victron and
decodable with the owner's per-device key: high confidence for the
battery monitor (BMV-712) and DC/DC converter (Orion Smart) records,
which also reproduce two independently published test vectors. The
16-bit header ahead of the record and the model id's position come
from community code, not Victron, but are confirmed by those vectors.
Over GATT, Victron documented exactly one service (65970000…) and said
it was for the SmartShunt; nothing published says the BMV-712, the
Orion-Tr Smart or the VE.Direct Bluetooth Smart dongle carry it. Their
VictronConnect service (306b0001…) is unpublished and sloth-va does not
speak it.

## [EMD] "Extra manufacturer data" (Victron wiki, printed 2022-12-14)

Fetched as a PDF from the URL above (9 pages, sha256
ddb8234c73ab5be552e7c6424b119546e38291b654ed3b8c4ee005f3b9279c03).
Permanent link printed on it:
https://wiki.victronenergy.com/rend/ble/extra_manufacturer_data.

- The extra data is "added to the Victron Manufacturer Data record type
  0x10 - Product Advertisement".
- Record header: bits 0..7 record type, 8..23 "Nonce/Data counter in LSB
  order", 24..31 "Byte 0 of the encryption key".
- Record types: 0x00 test, 0x01 solar charger, 0x02 battery monitor,
  0x03 inverter, 0x04 DC/DC converter, 0x05 SmartLithium, 0x06 inverter
  RS, 0x07 GX (TBD), 0x08 AC charger (TBD), 0x09 Smart Battery Protect,
  0x0A (Lynx Smart) BMS, 0x0B Multi RS, 0x0C VE.Bus, 0x0D DC energy
  meter.
- Key check: "When this byte does not match the key as stored on the
  receiving device, then the stored key should be discarded and the
  device should stop trying to decode the advertisement. The
  advertising device should change the key when the bluetooth pin code
  is changed."
- Cipher: "The encryption is done using a AES-CTR operation … the nonce
  is 2 bytes wide and contains the nonce bytes of the record header …
  Records that contain 16 bytes of data or less can be
  encrypted/decrypted using 1 AES operation. At the moment, this is
  true for all records." Maximum record length 20 bytes.
- "an implementation should not perform an upper bound check on the
  length … a length check should be performed for all items when
  retrieving data from the record." "Unused bits in the last byte of a
  record should be set."
- Battery Monitor: bit 32 TTG 16 bits 1 min NA 0xFFFF; 48 battery
  voltage 16 bits 0.01 V signed NA 0x7FFF; 64 alarm reason 16; 80 aux
  value 16 (aux voltage 0.01 V signed / mid voltage 0.01 V / temperature
  0.01 K, per the aux input); 96 aux input 2 bits (0 aux V, 1 mid V, 2
  temperature, 3 none); 98 battery current 22 bits 0.001 A signed NA
  0x3FFFFF; 120 consumed Ah 20 bits 0.1 Ah NA 0xFFFFF, "Consumed Ah =
  -Record value"; 140 SOC 10 bits 0.1 % range 0..100.0 % NA 0x3FF; 150
  unused 10.
- DC/DC Converter: 32 device state 8 NA 0xFF; 40 charger error 8 NA
  0xFF; 48 input voltage 16 bits 0.01 V NA 0xFFFF; 64 output voltage 16
  bits 0.01 V signed NA 0x7FFF; 80 off reason 32; 112 unused 48.

What [EMD] does **not** say: where the record sits in the
advertisement, or the counter block's byte order. The PDF's "MSB
counter that starts at 0" is about the counter half of the block; with
every record one block long it never increments.

## [ADV] the 0x10 byte (Victron staff, community)

Thiemo van Engelen (Victron) on the Orion XS thread
(https://community.victronenergy.com/t/bluetooth-data-format-of-an-orion-xs-50-extra-manufacturer-data/47862):
for Instant Readout "the 3th byte is 0x10" (counting the 2-byte company
identifier 0x02E1); any other value is not a product announcement.
Medium-high confidence: staff, but a forum post.

## [VEB] keshavdv/victron-ble (community, read 2026-11-15)

https://github.com/keshavdv/victron-ble. Read for its description and
its published test vectors; no code copied into this repository.

- Manufacturer data after the company id: 2-byte prefix (0x10, then one
  byte of unpublished meaning), model id (u16 LE), readout type (u8),
  IV (u16 LE), then the key-check byte and the ciphertext.
- AES-CTR with a 128-bit little-endian counter initialised to the IV:
  the counter block is the IV's two bytes LSB first, then zeros.
- Model ids: 0xA381/0xA383 BMV-712 Smart, 0xA389 SmartShunt 500A/50mV,
  0xA3C0 "Orion Smart 12V/12V-18A DC-DC Converter", 0xA182/0xA188/0xA189
  VE.Direct Bluetooth Smart Dongle revisions.
- Test vectors used in tests/test_va.c (checked independently on
  2026-11-15 with `openssl enc -d -aes-128-ctr`, which produced the
  decrypted bytes the library's own `parse_decrypted` tests list):
  - battery monitor: data
    `100289a302b040af925d09a4d89aa0128bdef48c6298a9`, key
    `aff4d0995b7d1e176c0c33ecb9e70dcd` → 12.53 V, 0 A, -50.0 Ah,
    50.0 %, no TTG, aux off, model SmartShunt 500A/50mV;
  - DC/DC: data `1000c0a304121d64ca8d442b90bbdf6a8cba`, key
    `64ba49f1a8562e45197a8e1fe50d7658` → off, no error, 13.15 V in,
    output NA, off reason engine shutdown (0x80);
  - key mismatch: `100289a302bb01af…` with an all-0xff key.

## [VCS] the 65970000 GATT service (Victron staff, community)

Thread "Victron Bluetooth BLE protocol publication",
https://communityarchive.victronenergy.com/questions/93919/victron-bluetooth-ble-protocol-publication.html

- mvader (Victron), 2021-07-01: a new GATT service, "available only for
  the SmartShunt"; SmartShunt firmware v2.31+, VictronConnect v5.42+,
  enabled in the device's settings in VictronConnect, then a power cycle
  and the host's service cache refreshed. Service UUID
  65970000-4bda-4c1e-af4b-551c4cf74769, distinct from the VictronConnect
  service. "A keep alive is required. Without that, the device will
  automatically disconnect after one minute."
- mvader, 2021-07-02, characteristics (all …-4bda-4c1e-af4b-551c4cf74769):
  keep-alive 6597ffff (read/write, un16, 0.001 s, 0xFFFF forever);
  consumed Ah 6597eeff (sn32, 0.1 Ah); power 6597ed8e (sn16, 1 W, NA
  0x7FFF); voltage 6597ed8d (sn16, 0.01 V, NA 0x7FFF); current 6597ed8c
  (sn32, 0.001 A, NA 0x7FFFFFFF); SOC 65970fff (un16, 0.01 %, NA
  0xFFFF). The suffixes are VE.Direct HEX register numbers (0xED8D main
  voltage etc., [VED]).
- Thiemo van Engelen (Victron), 2022-10-06: "bluetooth pairing using a
  pin code mandatory for security/privacy reasons", no way around it.
- Thiemo van Engelen, 2023-11-13/14: keep-alive is 2 bytes, 16-bit
  little-endian unsigned, milliseconds, reset on each write; 0xFFFF
  disables the timer for the session; "Make sure that you are using a
  write request and not a write command."
- Users asked about the BMV-712 from 2021 to 2022; no staff reply
  confirming it was found. Nothing found for Orion or the dongle.

## [VED] VE.Direct Protocol 3.32 (Victron)

https://www.victronenergy.nl/upload/documents/VE.Direct-Protocol-3.32.pdf
(sha256 07e2878acda139a3b6c5f7d9f99e450b1d374da5f04073c15a4c17096d3f7e0c).
PID table: 0xA381 BMV-712 Smart, 0xA382 BMV-710H Smart, 0xA383 BMV-712
Smart Rev2, 0xA389/0xA38A/0xA38B SmartShunt 500/1000/2000A, 0xA3F0
Orion XS 12V/12V-50A (no Orion Smart: it has no VE.Direct port). "CS"
state of operation: 0 off, 1 low power, 2 fault, 3 bulk, 4 absorption,
5 float, 6 storage, 7 equalize (manual), 9 inverting, 11 power supply,
245 starting-up, 246 repeated absorption, 247 auto equalize /
recondition, 248 BatterySafe, 252 external control. "OR" off reason
bits: 0x01 no input power, 0x02 switched off (power switch), 0x04
switched off (device mode register), 0x08 remote input, 0x10 protection
active, 0x20 paygo, 0x40 BMS, 0x80 engine shutdown detection, 0x100
analysing input voltage.

## Per device (the owner's three)

| Device | Instant Readout | GATT 6597 | Confidence |
|---|---|---|---|
| BMV-712 Smart (HQ2501YV9FU) | record 0x02 battery monitor; decoded | not documented for it; sloth-va connects once, lists services, reads only if present | readout high; GATT unverified |
| Orion-Tr Smart 12/12-18A isolated (HQ2515QP3RX) | record 0x04 DC/DC: state, error, input V, output V, off reason (no currents in this record) | not documented; same probe | readout high; GATT unverified |
| VE.Direct Bluetooth Smart dongle (HQ25232KEJG) | heard sending a 0x02-first advertisement, not 0x10: no Instant Readout to decode (owner has it off) | not documented; same probe, needs the MAC in victron-va.conf | readout none; GATT unverified |

Not used: the VictronConnect service 306b0001-b081-4037-83dc-e59fcc3cdfd0
and its framing are not published by Victron; community reverse
engineering exists, but sloth-va reads only what a cited source
describes, and records the service list when that is all a device
offers.

## Related pages

- [docs/wiki/victron.md](../../docs/wiki/victron.md)
- [ADR 0011](../../docs/wiki/adr/0011-sloth-va-transmits.md)
