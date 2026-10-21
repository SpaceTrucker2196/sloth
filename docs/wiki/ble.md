---
name: ble
description: The Bluetooth host source — what sloth reads off the Linux HCI monitor channel with --bt-monitor, the passive-scan procedure the operator runs, and what the source refuses, rejects and never writes
type: reference
---

# Bluetooth host source (BLE over the HCI monitor channel)

**Summary**: `--bt-monitor` makes sloth listen to the Linux Bluetooth
HCI monitor channel — libpcap's `bluetooth-monitor` device, link type
254 — and decode an allow-list of it: controller announcements, LE
advertising reports, and the host's own scan, advertise and connect
commands. The channel is receive-only by construction. sloth sends no
HCI or MGMT command; **the operator starts a passive scan** with their
own stack, and sloth reports in `sensor_health` whether the scan it saw
configured was in fact passive, and raises `BT_OWN_TRANSMIT` when the
host it listens through was told to transmit.

**Sources**: `src/ble_hci.c`, `src/ble_hci.h`, `src/capture/bt_monitor.c`,
`src/ble_snoop.c` (the advertising-report decoder, #144 slice 1),
`src/alerts/rules_ble.c`, `src/capture/capture.c`
(`capture_fallback_device`), `src/main.c`, `MISSION.md` §1–§2;
Bluetooth Core Specification v5.4 Vol 4 Part E §5.4, §7.1, §7.3.18,
§7.7.65.2, §7.8; Linux `include/net/bluetooth/hci_mon.h` and
`net/bluetooth/hci_sock.c`; libpcap `pcap-bt-monitor-linux.c`; #144.

**Last updated**: 2026-10-21 (#144 slice 2).

---

## What the source is

The kernel copies every HCI packet that crosses any controller — both
directions — plus index lifecycle notes and bluetoothd's MGMT traffic to
every socket bound to `HCI_CHANNEL_MONITOR`. That is what `btmon` reads,
and what libpcap opens as `bluetooth-monitor`. Each record arrives with
libpcap's 4-byte header (adapter index and monitor opcode, both
big-endian) in front of the payload.

Two properties make it the source MISSION §2 allows:

- **No transmit path.** `hci_sock_sendmsg()` refuses the monitor channel
  outright (`EOPNOTSUPP`); a monitor socket cannot put anything on any
  controller. sloth calls no libpcap send function on the handle either.
- **The operator drives the controller, not sloth.** sloth issues no HCI
  command and no MGMT command, anywhere. What scan runs, with which
  parameters, is the host stack's decision, and sloth only reports it.

Binding the channel needs `CAP_NET_RAW`, so the handle is opened before
the privilege drop, beside the IP capture handle (#140), and read on its
own worker.

### Refused everywhere: `bluetooth0`, `bluetooth1`, ...

libpcap also lists one device per controller, `bluetoothN`. Those are
`HCI_CHANNEL_RAW` sockets, and a raw socket **accepts injected HCI
packets**. No path in sloth opens one:

| Path | What happens |
|---|---|
| `--iface bluetooth0` | exit 2 at argv time |
| `[m]` monitor retarget, `probe_open` | refused with `probe_err`, the running radio untouched |
| the IP capture's fallback when `any` cannot be opened | skips every `bluetooth*` name (`capture_fallback_device`); it used to take the head of `pcap_findalldevs()`, which on some hosts is `bluetooth0` |
| `--bt-monitor` | opens the constant `bluetooth-monitor` only, and checks it anyway |

## The allow-list

The same channel carries **link keys, LTKs and IRKs** (Link Key
Notification, LE Long Term Key Request Reply, MGMT Load Link Keys) and
every ACL payload. So nothing is decoded by default. A record is read
only when it is on this list; everything else is counted in
`ble_records_ignored` after reading at most its opcode, and its bytes
are never copied.

| Monitor opcode | Inside it | What sloth takes |
|---|---|---|
| NEW_INDEX (0) | controller type, bus, address, name | `ble_controllers` |
| EVENT (3) | LE Meta 0x3E, subevent 0x02 LE Advertising Report, **one report** | the advertiser row |
| EVENT (3) | LE Meta 0x3E, subevent 0x0D LE Extended Advertising Report | counted in `ble_ext_adv_undecoded`, not decoded yet |
| COMMAND (2) | the host's own scan, advertise and connect commands, listed under [own transmissions](#own-transmissions) | scan mode, filter policy, own-transmission state |

**Nothing read off the channel is written anywhere verbatim** — not to
JSONL, `--db`, a pcap, or a log line. After a record is decoded only the
fields in `ble_device_t` and `ble_host_t` (`include/sloth.h`) exist, and
the manufacturer data's bytes are not among them.

An allow-listed record whose length does not match its clause, or that
was snapped (captured shorter than sent), is `ble_records_malformed` and
is never decoded from a prefix. The worker's snaplen is the largest
allow-listed record (262 bytes), so a long ACL record is not even copied
whole out of the kernel.

### Multi-report advertising events are rejected

An LE Advertising Report with `Num_Reports` > 1 is refused whole and
counted in `ble_multi_report_rejected`. The Core Specification draws the
event's parameters as per-field arrays (every Event_Type, then every
Address_Type, ...); the Linux kernel parses them as consecutive
per-report records. The two agree for one report and disagree for more.
Until the layout is confirmed against a controller, sloth decodes none
of a multi-report event rather than attribute one device's name to
another's address. Controllers in practice report one at a time; a
rising count here is advertising sloth heard and did not use.

## The advertiser table

One row per (address, address type), 256 rows, `STAB_OLDEST` — an
advertiser picks its own address and a random one rotates, so a spray of
fresh addresses churns the table instead of making it refuse. Every loss
is `evict_ble_device` in `sensor_health`. A row keeps the local name,
first 16-bit service UUID, manufacturer company ID, appearance, TX power
and flags once seen (an `ADV_IND` and its `SCAN_RSP` carry different AD
structures), the last and strongest RSSI, the controller index that
heard it, first/last seen on the capture clock, and a report count.

This slice keeps the table and counts it; it does not yet export it.
The `[B]` view and the `ble_device` JSONL record are #144 slice 4.

## Own transmissions

MISSION §2 holds Bluetooth to the passive absolute. The host stack can
still make the controller sloth listens through transmit, and the
monitor channel shows the command that does it. These are the ones
sloth reads (Core Specification v5.4 Vol 4 Part E):

| Command | Opcode | Transmits because |
|---|---|---|
| LE Set Scan Parameters, `LE_Scan_Type` = active | 0x200B | an active scan sends SCAN_REQ |
| LE Set Extended Scan Parameters, any PHY active | 0x2041 | the same, per PHY |
| Inquiry / Periodic Inquiry Mode | 0x0401 / 0x0403 | inquiry ID packets |
| LE Set Advertising Enable = 1 | 0x200A | legacy advertising |
| LE Set Extended Advertising Enable = 1 | 0x2039 | extended advertising |
| LE Set Periodic Advertising Enable, bit 0 | 0x2040 | periodic advertising |
| LE Create Connection / LE Extended Create Connection | 0x200D / 0x2043 | the initiator sends CONNECT_IND |
| Create Connection | 0x0405 | paging |
| Remote Name Request | 0x0419 | paging |
| Write Scan Enable, inquiry or page scan on | 0x0C1A | the controller answers other devices' inquiries and pages |

The state is **bucketed by recency, never latched**: `ble_own_tx` reads
`never`, `recent` (the last such command arrived within 120 s, on the
host clock) or `earlier`. `BT_OWN_TRANSMIT` fires while it is `recent`,
one incident per kind, and resolves through the engine's quiet period
once the host stops. It is own operational state, not an adversary
finding, so it carries no ATT&CK technique ([[alerts]]).

What it cannot see: a command the controller then rejects still counts
(sloth does not pair commands with their Command Complete); and a
transmission a controller makes without a host command — vendor
firmware, an LE connection the controller maintains once it exists — is
not visible here.

### Scan mode and filter policy

`ble_scan_mode` is the scan type the host **last set**, and it is
`unknown` until a scan-parameter command (0x200B or 0x2041) has actually
crossed the channel. It is never inferred: an active scan's SCAN_REQs
are generated inside the controller and never appear on the monitor
channel, so their absence proves nothing. A scan already running when
sloth started reads `unknown` until the host sets parameters again.

`ble_scan_filter` records the Scanning_Filter_Policy from the same
command. Policies 1 and 3 restrict reports to the controller's Filter
Accept List — the kernel's background scan for paired devices is the
common case — and `ble_scan_accept_list` reads `1` for them: such a
scan hears only devices the host already knows, and its silence about
anything else is not an empty room.

## Passive-scan procedure

sloth will not start a scan. The procedure below is the operator's, and
the point of sloth's fields is that it checks itself.

1. **Start sloth first**, with `--bt-monitor`, as root or with
   `CAP_NET_RAW`. Starting it before the scan is what lets it see the
   scan-parameter command; otherwise `ble_scan_mode` stays `unknown`.
   Check stderr for `Bluetooth HCI monitor open`, or `btmon_err` in
   `sensor_health`.
2. **Stop anything that scans actively.** `bluetoothctl scan on`, the
   desktop Bluetooth panel's device search and MGMT Start Discovery all
   run an **active** scan in the Linux kernel. Do not use them.
3. **Start a passive LE scan** with a tool that sets `LE_Scan_Type` =
   passive. BlueZ's deprecated `hcitool` does it directly:
   `hcitool -i hci0 lescan --passive --duplicates`. It uses the legacy
   scan commands, so reports arrive as subevent 0x02, the one this slice
   decodes. Another scanner on the same controller (bluetoothd's own)
   can make it fail with an I/O error; stop that first.
4. **Verify in `sensor_health`**:
   - `ble_scan_mode` = `passive` and `ble_own_tx` = `never` — the host is
     listening only;
   - `ble_scan_accept_list` = `0` — the scan is not limited to known
     devices;
   - `ble_adv_reports` climbing.

   If `ble_scan_mode` reads `active` or `BT_OWN_TRANSMIT` fires, the host
   is on the air: stop the scan and start again from step 2. If
   `ble_ext_adv_undecoded` climbs while `ble_adv_reports` stays flat, the
   stack is scanning with the extended commands (BlueZ does on BT 5
   controllers), and this slice decodes nothing from those reports yet.

### Warnings

- **This channel carries secrets.** Link keys, LTKs and IRKs cross it in
  the clear. sloth decodes none of them and writes nothing verbatim, but
  any other tool reading the same channel — `btmon -w`, Wireshark or
  tcpdump on `bluetooth-monitor` — writes them to its file. A DLT 254
  savefile is replayable through `--replay` and must be handled as key
  material.
- **`bluetoothN` is never a safe substitute.** Pointing a capture tool at
  a raw HCI device instead of `bluetooth-monitor` opens a socket that can
  transmit; sloth refuses it, other tools do not.
- **Passive is a property of the host, not of sloth.** sloth cannot stop
  another process from switching the scan to active or enabling
  advertising; it can only report that it happened.

## Replay

A libpcap savefile with link type 254 — a tcpdump or Wireshark capture
of `bluetooth-monitor` — routes to this source under `--replay`, and
`btmon_iface` reads `replay`. btmon's own `-w` output is BTSnoop, not a
libpcap savefile, and is not read. `make replay-check` replays a
generated one built from hand-assembled records (`tests/replay/gen_replay.c`);
no capture is committed.

## Not built yet

- Extended Advertising Report (0x0D) decode — counted, not decoded.
- The Ubertooth source (`--bt-capture`, #144 slice 3).
- `BLE_ADV_FLOOD`, `BLE_HID_UNEXPECTED`, `BLE_WATCHLIST`, the `[B]` view
  and the `ble_device` / `ble_alert` JSONL records (#144 slice 4).

## Related pages

- [[cli-reference]] — `--bt-monitor` and the `bluetoothN` refusals.
- [[jsonl-schema]] — the `btmon_*` / `ble_*` fields of `sensor_health`.
- [[alerts]] — `BT_OWN_TRANSMIT` and the own-operational-state form.
- [[non-ip-sensors]] — the sensor-family roadmap BLE came from.
- [[monitor-mode]] — the 802.11 counterpart: sloth reads a monitor
  interface and never configures one.
