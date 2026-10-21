---
source_url: https://www.tcpdump.org/linktypes.html
retrieved: 2026-10-21
topics: [bluetooth, ble, bredr, ubertooth, link-layer, pcap, linktype, passive]
citation: tcpdump.org link-layer header types 256 BLUETOOTH_LE_LL_WITH_PHDR, 251 BLUETOOTH_LE_LL, 192 PPI, 255 BLUETOOTH_BREDR_BB; Bluetooth Core Specification v5.4 Vol 6 Part B §1.4.1, §2.1, §2.1.2, §2.3 and Vol 2 Part B §1.2.1, §6.3.3.1; Ubertooth repository (firmware/README, firmware/common.mk, firmware/bluetooth_rxtx/bluetooth_rxtx.c, host/libubertooth/src/ubertooth_interface.h), release 2020-12-R1
---
# Ubertooth capture link types and the Core Specification clauses read

Clause-annotated summary of what `--bt-capture` (#144 slice 3) decodes
and the sources each decision rests on. The standard text is
copyrighted; this is our own description, not an excerpt. No alert
kind is cited here: this slice adds a source and its parsers, and the
rules on it are #144 slice 4.

## Link types (tcpdump.org link-layer header types)

- **256 `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`**
  (https://www.tcpdump.org/linktypes/LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR.html).
  A 10-octet little-endian pseudo-header: RF Channel (0..39, the RF
  channel numbering of Core Spec Vol 6 Part A §2), Signal Power and
  Noise Power (signed dBm), Access Address Offenses, Reference Access
  Address (4), Flags (2). Then the LE packet from the Access Address,
  CRC included. Flags: 0x0001 de-whitened, 0x0002 signal valid, 0x0004
  noise valid, 0x0008 decrypted, 0x0010 reference AA valid, 0x0020 AA
  offenses valid, 0x0040 channel aliased, 0x0380 PDU type, 0x0400 CRC
  checked, 0x0800 CRC passed, 0x3000 PDU-type dependent, 0xC000 PHY.
  `src/btle_ll.c` reads the channel, the two validity bits and the
  signal; it ignores the CRC bits by design (see below).
- **251 `LINKTYPE_BLUETOOTH_LE_LL`**: the same LE packet with no
  pseudo-header. Reached here only inside PPI.
- **192 `LINKTYPE_PPI`**: version (0), flags, header length (LE16,
  fields included), DLT (LE32) of what follows. `ubertooth-btle -c`
  writes DLT 251 inside it. The PPI fields are skipped by length, not
  decoded.
- **255 `LINKTYPE_BLUETOOTH_BREDR_BB`**
  (https://www.tcpdump.org/linktypes/LINKTYPE_BLUETOOTH_BREDR_BB.html).
  A 22-octet little-endian header: RF Channel (0..78), Signal, Noise,
  Access Code Offenses, Payload Transport Rate, Corrected Header Bits,
  Corrected Payload Bits (2), LAP (3 + reserved), Reference LAP (3),
  Reference UAP (1), packet header (4), Flags (2). Reference LAP and UAP
  are what was **configured into the capture tool**. Flags: 0x0001
  de-whitened, 0x0002 signal valid, 0x0004 noise valid, 0x0008
  decrypted, 0x0010 reference LAP valid, 0x0020 payload present, 0x0040
  channel aliased, **0x0080 reference UAP valid for HEC and CRC
  checking**, 0x0100/0x0200 HEC checked/passed, 0x0400/0x0800 CRC
  checked/passed, 0x1000/0x2000 MIC checked/passed. The 0x0080 bit
  therefore says the operator's UAP was used, never that a UAP was
  observed, and `src/bredr_bb.c` labels it that way.

The classic savefile container around them is libpcap's
(`pcap-savefile(5)`; IETF draft-ietf-opsawg-pcap): magic 0xA1B2C3D4
(microseconds) or 0xA1B23C4D (nanoseconds) in the writer's byte order,
version 2.4, link type in the last header word; per record seconds,
fraction, captured and original length. pcapng (block type 0x0A0D0D0A)
is a different container and is refused.

## Core Specification v5.4, Vol 6 Part B (Link Layer)

- **§1.4.1 channel indices.** Forty 2 MHz RF channels, 2402–2480 MHz.
  Advertising channels 37, 38, 39 sit at RF 0 (2402), RF 12 (2426) and
  RF 39 (2480); data channel indices 0..36 take the remaining RF
  channels in frequency order. `btle_rf_to_index()` is that table.
- **§2.1 packet format, §2.1.2 access address.** The advertising
  physical channel uses Access Address 0x8E89BED6; a packet on any
  other Access Address belongs to a connection and is not decoded.
  Multi-octet fields are least significant octet first.
- **§2.3 advertising physical channel PDU.** 16-bit header: PDU_Type
  (4 bits), RFU, ChSel, TxAdd, RxAdd, Length (8 bits). Types: ADV_IND
  0, ADV_DIRECT_IND 1, ADV_NONCONN_IND 2, SCAN_REQ 3, SCAN_RSP 4,
  CONNECT_IND 5, ADV_SCAN_IND 6, ADV_EXT_IND 7, AUX_CONNECT_RSP 8.
  Payload lengths: AdvA plus 0–31 octets of AdvData/ScanRspData
  (6..37) for ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND and SCAN_RSP;
  exactly 12 for ADV_DIRECT_IND (AdvA, TargetA) and SCAN_REQ (ScanA,
  AdvA); exactly 34 for CONNECT_IND (InitA, AdvA, 22-octet LLData).
  A Length outside its type's range is malformed.
- **§2.3.3.1 CONNECT_IND LLData.** AA (4), CRCInit (3), WinSize (1),
  WinOffset (2), Interval (2), Latency (2), Timeout (2), ChM (5), and a
  last octet packing Hop (5 bits, low) and SCA (3 bits, high).

The AD structures inside AdvData are walked by the slice-1 decoder,
`ble_ad_parse()` (Vol 3 Part C §11), over the trusted octets only.

## Core Specification v5.4, Vol 2 Part B (Baseband)

- **§6.3.3.1 sync word.** Derived from the 24-bit LAP; the UAP is not
  part of the access code or packet header, and the NAP is in neither;
  the full BD_ADDR is carried only in an FHS packet's payload (§6.5.1.4),
  which sloth never reads. A receiver of the access code therefore
  recovers the LAP and nothing that makes a BD_ADDR,
  which is why sloth shows LAP only and derives no vendor.
- **§1.2.1 reserved addresses.** LAPs 0x9E8B00–0x9E8B3F are reserved
  for inquiry access codes; 0x9E8B33 is the GIAC. A packet on one is an
  inquiry, not a piconet.

## Ubertooth

- **Capture limit.** `host/libubertooth/src/ubertooth_interface.h`
  defines `DMA_SIZE 50` and the USB receive packet's `data[DMA_SIZE]`:
  at most 50 octets of a packet, from its Access Address, reach the
  host. `BTLE_PAYLOAD_TRUST_MAX` (44) is that minus the Access Address
  and PDU header. A longer claim is truncated silently by the hardware
  path, so sloth bounds the trusted length by it and makes no CRC claim.
- **Jam mode.** `firmware/bluetooth_rxtx/bluetooth_rxtx.c` holds
  `jam_mode` as one firmware global, set by the `UBERTOOTH_JAM_MODE`
  vendor request from any host client and reset to `JAM_NONE` by
  `cc2400_idle()` or after a `JAM_ONCE` jam in `bt_le_sync()`;
  `connection_follow_cb()` arms jamming on a followed connection while
  it is set. `host/ubertooth-tools/src/ubertooth-btle.c` sends the
  request at the start of `-f`, `-n` and `-p`, `JAM_NONE` unless
  `-i`/`-j` (once) or `-I`/`-J` (continuous) was given.
- **Receive-only firmware.** `firmware/README`: setting `DISABLE_TX`
  when building `bluetooth_rxtx` gives firmware with no transmit
  ability; `firmware/common.mk` adds `-DTX_ENABLE` only when it is unset,
  and `tools/ubertooth-release.sh` ships that build as
  `bluetooth_rx_only`. Nothing in a capture says which firmware made it.
- **Tools and flags.** The usage text of `ubertooth-btle` (`-f` follow,
  `-n` advertisements only, `-p` promiscuous, `-A` advertising channel,
  `-q` pcap with PHDR, `-c` pcap with PPI, `-r` pcapng; `-i`/`-I`
  interfere, `-s` faux slave), `ubertooth-rx` (`-l` LAP, `-u` UAP, `-c`
  channel default 39, `-q` pcap), `ubertooth-util` (`-t` continuous
  transmit test, `-e` repeater mode, `-n` range test, `-a` power
  amplifier level) and `ubertooth-scan` / `ubertooth-follow` (both
  connect through the host's Bluetooth adapter). The allowed and
  forbidden sets in `docs/wiki/ubertooth.md` are taken from these.
