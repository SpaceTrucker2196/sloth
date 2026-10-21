---
name: ubertooth
description: The over-the-air Bluetooth source — --bt-capture reading a pcap file or FIFO an Ubertooth tool writes, the Ubertooth tools and flags that are allowed and forbidden, the jam-mode firmware global, and DISABLE_TX firmware
type: reference
---

# Ubertooth capture (`--bt-capture`)

**Summary**: `--bt-capture PATH` makes sloth read a classic pcap file or
FIFO that the **operator** fills with an Ubertooth One, through
`ubertooth-btle` (Bluetooth Low Energy) or `ubertooth-rx` (Bluetooth
Classic, BR/EDR). sloth never touches the dongle: it links no
libubertooth, sends no USB request and starts no process. It reads
bytes from a path. Whether the dongle transmits is decided by the tool
and the flags the operator runs and by the firmware flashed on it, so
this page lists which tools and flags are allowed under MISSION §2 and
which are forbidden. sloth cannot check either from the capture.

**Sources**: `src/capture/bt_capture.c`, `src/capture/bt_capture.h`,
`src/bt_stream.c`, `src/bt_stream.h`, `src/btle_ll.c`, `src/btle_ll.h`,
`src/bredr_bb.c`, `src/bredr_bb.h`, `src/ble_hci.c` (`ble_dev_observe`),
`src/jsonl.c` (`btcap_*`), `src/main.c`; `MISSION.md` §1–§2;
`research/bluetooth/ubertooth-link-types-and-core-clauses.md`;
tcpdump.org link types 256, 251, 192, 255; Bluetooth Core Specification
v5.4 Vol 6 Part B §1.4.1, §2.1, §2.3 and Vol 2 Part B §1.2.1, §6.3.3;
the Ubertooth repository (`firmware/README`, `firmware/common.mk`,
`firmware/bluetooth_rxtx/bluetooth_rxtx.c`,
`host/libubertooth/src/ubertooth_interface.h`, the `ubertooth-btle`,
`ubertooth-rx` and `ubertooth-util` usage text); #144.

**Last updated**: 2026-10-21 (#144 slice 4: the rules, view and records read this stream; #144 slice 3).

---

## What sloth reads

One path, given once. `stat()` at startup refuses a path that does not
exist or is not a regular file or a FIFO (a device node, a socket, a
directory): exit 2. The open itself happens **once**, on the reader's
own worker, after the privilege drop:

- **Off the main thread, non-blocking.** Opening a FIFO for reading
  normally blocks until a writer appears. sloth opens it `O_NONBLOCK`
  on the worker and waits in `poll()`, so startup never waits for the
  Ubertooth tool, and `sensor_health.btcap_state` reads `waiting` until
  the pcap header arrives.
- **Never reopened.** Closing and reopening a FIFO loses what the writer
  sent in between and can make the writer see `EPIPE`. The descriptor
  opened once is read to the end.
- **Stop always returns.** Reads wait in `poll()` with a 100 ms timeout
  and re-check the stop flag, so a writer that holds the FIFO open and
  sends nothing cannot keep sloth from exiting. (libpcap's savefile
  reader would block inside `fread()` there, which is why the framing
  is sloth's own, in `src/bt_stream.c`.)
- **As the run account.** The worker starts after the drop (#140), so
  the path must be readable by the account sloth runs as (`--user`).

A regular file is read to its end; a FIFO until its writer closes it.
Either way `btcap_state` then reads `eof`.

### Link types

| DLT | Name (tcpdump.org) | Written by | What sloth takes |
|---|---|---|---|
| 256 | `BLUETOOTH_LE_LL_WITH_PHDR` | `ubertooth-btle -q FILE` | RF channel, signal power (when flag 0x0002 says it is valid), and the LE packet |
| 192 | `PPI`, inner link type 251 `BLUETOOTH_LE_LL` | `ubertooth-btle -c FILE` | the LE packet only; the PPI fields are skipped, so channel and signal are unknown |
| 255 | `BLUETOOTH_BREDR_BB` | `ubertooth-rx -q FILE` | RF channel, signal power, the LAP |

Any other link type — DLT 254 (the host monitor channel, which is
`--bt-monitor`'s) included — and **pcapng** (`ubertooth-btle -r`,
`ubertooth-rx -r`) are refused at the header with a message in
`btcap_err`, and nothing further is read. A record over 65535 octets is
skipped and counted as a drop with the stream kept in step; a length
over 262144 cannot be a record and ends the stream as `error`.

### BLE: trusted length, no CRC claim

The PDU header's Length octet is what the transmitter claims. An
Ubertooth delivers at most 50 octets of a packet from its Access Address
(`DMA_SIZE`, `ubertooth_interface.h`) and drops the rest without saying
so, and a record can be shorter still. The payload sloth trusts is the
smallest of the claim, the record, and that limit (44 octets after the
Access Address and header). A claim past it is counted in
`btcap_truncated`, and:

- no field is read past the trusted length — an advertisement cut off
  before its AdvA is a drop, a CONNECT_IND cut off before its LLData
  keeps only its addresses;
- the AD structures are walked only inside it, so a name whose structure
  crosses the line is dropped, not completed;
- **no CRC is claimed.** sloth never checks the 3-octet CRC and ignores
  the producer's CRC-checked/passed flags: past the trusted length the
  octets a CRC covers are not there.

Decoded (Core Specification v5.4 Vol 6 Part B §2.3): ADV_IND,
ADV_DIRECT_IND, ADV_NONCONN_IND, ADV_SCAN_IND and SCAN_RSP into the
advertiser table; SCAN_REQ and CONNECT_IND (including LLData: access
address, CRCInit, window, interval, latency, timeout, channel map, and
the Hop/SCA octet — Hop the low 5 bits, SCA the high 3) are counted. A
Length outside its PDU type's range is a drop. ADV_EXT_IND is counted,
not decoded. Data-channel PDUs — anything not on the advertising Access
Address 0x8E89BED6, which follow mode produces — are counted and never
decoded: they are someone's connection.

Advertisers enter the same table `--bt-monitor` fills ([[ble]]), as
sensor kind `ble` with `sensor_iface` `ubertooth`. The sensor is part
of the row's key, so an advertiser heard by the host controller and by
the dongle is two rows.

### BR/EDR: the LAP and nothing else

What a receiver recovers from a BR/EDR packet is the **LAP**, the 24
bits the access code's sync word is built from (Vol 2 Part B §6.3.3.1).
The UAP is not part of the access code or the packet header, and the
NAP is in neither; the full BD_ADDR travels only inside an FHS packet's
payload (paging and inquiry response), which sloth never reads. So:

- sloth keeps a table of LAPs (64 rows, `evict_bredr_lap`) and prints
  one only as `LAP 123456`;
- **no full BD_ADDR and no OUI vendor is ever derived** — an OUI is the
  NAP and UAP, which a LAP does not contain;
- the **Reference UAP** in a DLT 255 record is the *tool reference
  UAP*: the UAP of the piconet `ubertooth-rx` is tracking, which is
  either what the operator configured (`-u`) or what libbtbb worked out
  itself over many packets — `ubertooth_callback.c` passes
  `btbb_piconet_get_uap()` whenever the piconet's UAP is marked valid,
  however it became valid. Flag 0x0080 means that value was used for
  HEC and CRC checking — **not that sloth heard it**. sloth stores it as
  `ref_uap_tool` / `ref_uap`, only on the row whose LAP is the
  reference LAP, and never as an observed UAP;
- an inquiry access code (LAP 0x9E8B00–0x9E8B3F, GIAC 0x9E8B33, Vol 2
  Part B §1.2.1) names no piconet: it is counted in `btcap_bredr_iac`
  (someone near the dongle is inquiring) and takes no row.

### Every count is a sample

An Ubertooth hears **one RF channel at a time**: `ubertooth-btle` one
of the three advertising channels (37 unless `-A` says otherwise) or the
channel a followed connection is on, `ubertooth-rx` one of the 79 BR/EDR
channels (39 unless `-c` says otherwise) while piconets hop across all
of them. `sensor_health.btcap_sampling` reads `1_of_40_channels` or
`1_of_79_channels`, Ubertooth rows in the device table carry
`sampled` = 1, and none of these counts is a rate of what was sent. The
host controller's counts ([[ble]]) are not samples in this sense and
are kept apart for that reason.

## Allowed tools and flags

Only receive and follow. Each writes classic pcap to the path sloth
reads:

| Command | What it does |
|---|---|
| `ubertooth-btle -n -q FIFO` | advertisements only, no following (DLT 256) |
| `ubertooth-btle -n -A 38 -q FIFO` | the same on advertising channel 38 (`-A` 37, 38 or 39) |
| `ubertooth-btle -f -q FIFO` | follow connections from their CONNECT_IND |
| `ubertooth-btle -p -q FIFO` | promiscuous: sniff connections already running |
| `ubertooth-btle -n -c FIFO` | as `-n -q`, written as PPI around DLT 251 |
| `ubertooth-rx -q FIFO` | BR/EDR, all LAPs, on one channel (DLT 255) |
| `ubertooth-rx -l LAP -u UAP -q FIFO` | the same for one piconet; `-u` seeds the record's tool reference UAP |

`-U N` (which dongle) is fine with any of them. Flags not listed here
are not vetted; read the tool's usage text before adding one.

A session, with the FIFO owned by the account sloth runs as:

```
mkfifo -m 600 /run/sloth/ubt.fifo        # chown it to the --user account
sloth --headless -o ble.jsonl --bt-capture /run/sloth/ubt.fifo &
ubertooth-btle -n -q /run/sloth/ubt.fifo
```

Either may start first: sloth's open does not wait for a writer, and
the tool's open waits for sloth's. Check `btcap_state` = `streaming`,
`btcap_dlt` = 256 and `btcap_recv` climbing.

## Forbidden tools and flags

Each of these makes the dongle — or the host — transmit, which
MISSION §2 forbids on every medium:

| Tool / flag | Why |
|---|---|
| `ubertooth-btle -i`, `-I` | interfere with a connection (once / continuously) |
| `ubertooth-btle -j`, `-J` | jam: undocumented aliases of `-i` and `-I` in the current getopt string |
| `ubertooth-btle -s` | faux slave mode: advertises as a peripheral |
| `ubertooth-scan` | inquires, and pages each device it finds (create connection, remote name, version, features), through the host's Bluetooth adapter |
| `ubertooth-follow` | opens a connection to the target through the host adapter (`hci_create_connection`) to learn its clock: paging |
| `ubertooth-util -t` | continuous transmit test |
| `ubertooth-util -e` | repeater mode |
| `ubertooth-util -n` | range test (transmits) |
| `ubertooth-util -a` | sets the power amplifier level |
| the **btbr** firmware | a separate image from `bluetooth_rxtx` (`firmware/btbr/` upstream); a BR/EDR firmware that transmits |
| `ubertooth-ducky`, `ubertooth-tx` | transmit tools |
| `ubertooth-ego -i` | interference mode |

### Jam mode is a firmware global

The jam setting is one variable in the `bluetooth_rxtx` firmware
(`jam_mode` in `bluetooth_rxtx.c`), not an argument of any receive
command. Any host client holding the dongle can set it with the
`UBERTOOTH_JAM_MODE` request, and it stays set until the firmware idles
the radio (`cc2400_idle()`) or a single-shot jam completes. While it is
set, the LE follow path arms jamming on every connection it follows
(`connection_follow_cb()`), so an allowed `ubertooth-btle -f` or `-p`
session **transmits** if something else set it underneath.

Current `ubertooth-btle` sends the request at the start of `-f`, `-n`
and `-p`, with `JAM_NONE` unless `-i`/`-I`/`-j`/`-J` was given, so a
clean start from it clears a leftover setting. That is a property of
that tool's current source, not a guarantee: another client, an older
tool, or a second process opening the same dongle mid-session can set
it again, and nothing in the capture shows it. Run one tool on the
dongle at a time, unplug and replug it before a sloth session, and use
receive-only firmware (below), which is the only setup where the
setting has nothing to drive.

### Use DISABLE_TX firmware

The Ubertooth firmware can be built without any transmit path:
`DISABLE_TX=1 make bluetooth_rxtx` (`firmware/README`; it drops
`-DTX_ENABLE` in `firmware/common.mk`), and the release script ships
that build as `bluetooth_rx_only`. **Flash the receive-only firmware**
on a dongle used with sloth; with it, the forbidden flags above have
nothing to drive.

**sloth cannot detect whether it is installed.** It reads a file; it
never talks to the dongle, and nothing in a pcap record says which
firmware produced it. Neither `btcap_state` nor anything else in
`sensor_health` is evidence that the dongle cannot transmit.

### Minimum firmware

**2020-12-R1**, the current Ubertooth release, with host tools from the
same release. Older releases are not supported: their tools and
firmware must match each other. The flags on this page were read from
the Ubertooth repository's current tools; if an installed release's
usage text differs, the usage text wins and this table needs updating.

## `sensor_health`

`btcap_iface` (`ubertooth`, or `""` without `--bt-capture`),
`btcap_state`, `btcap_err`, `btcap_dlt`, `btcap_refused_dlt`,
`btcap_sampling`, `btcap_stale_secs`, `btcap_recv`, `btcap_drop`,
`btcap_truncated`, the PDU counters and `btcap_bredr_laps`; meanings in
[[jsonl-schema]]. The change-only signature carries the state, the link
type, the freshness bucket and none/some bands for drops and
truncation, never the raw counters. A second sensor of kind `ble`,
iface `ubertooth`, is registered beside the host source's.

## Not built here

Since #144 slice 4 the advertisers this stream adds are read by
`BLE_ADV_FLOOD`, `BLE_HID_UNEXPECTED` and `BLE_WATCHLIST`, shown in the
`[*]` BLE view and exported as `ble_device` / `ble_alert` — each under
`iface` `ubertooth`, never summed with the host controller's counts.
A flood judged from this stream is judged on a one-channel sample, so
its counts are a lower bound and the alert says so. The LAP table is
still not exported. ADV_EXT_IND and the AUX chain are not decoded.

## Related pages

- [[ble]] — the host source (`--bt-monitor`) and the advertiser table
  this stream shares.
- [[cli-reference]] — `--bt-capture`.
- [[jsonl-schema]] — the `btcap_*` fields of `sensor_health`.
- [[non-ip-sensors]] — the sensor-family roadmap.
- [[research-corpus]] — the link-type and Core Specification citation
  document.
