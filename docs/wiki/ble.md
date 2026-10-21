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
Bluetooth Core Specification v5.4 Vol 4 Part E §5.4, §7.1, §7.3.2, §7.3.18,
§7.7.65.2, §7.8; Linux `include/net/bluetooth/hci_mon.h` and
`net/bluetooth/hci_sock.c`; libpcap `pcap-bt-monitor-linux.c`; #144.

**Last updated**: 2026-10-21 (#144 slice 2; on/off own-transmission state after review).

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
| NEW_INDEX (0) | controller type, bus, address, name | `ble_controllers` (primary type 0x00 only), a fresh per-controller state |
| DEL_INDEX (1) | nothing (no payload) | the controller leaves `ble_controllers` and its on-state is dropped |
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

| Command | Opcode | Transmits because | Stays on until |
|---|---|---|---|
| LE Set Scan Parameters, `LE_Scan_Type` = active | 0x200B | an active scan sends SCAN_REQ | — (counted as a command; the scan itself is the row below) |
| LE Set Extended Scan Parameters, any PHY active | 0x2041 | the same, per PHY | — |
| LE Set (Extended) Scan Enable = 1 under active parameters | 0x200C / 0x2042 | the scan sends SCAN_REQ from this moment | Scan Enable = 0 |
| Inquiry | 0x0401 | inquiry ID packets | ends on its own (`Inquiry_Length` ≤ 61.44 s) |
| Periodic Inquiry Mode | 0x0403 | inquiry ID packets, every period | Exit Periodic Inquiry Mode (0x0404) |
| LE Set Advertising Enable = 1 | 0x200A | legacy advertising | Advertising Enable = 0 |
| LE Set Extended Advertising Enable = 1 | 0x2039 | extended advertising | that set disabled, or all sets (`Num_Sets` = 0) |
| LE Set Periodic Advertising Enable, bit 0 | 0x2040 | periodic advertising | the same handle with bit 0 clear |
| LE Create Connection / LE Extended Create Connection | 0x200D / 0x2043 | the initiator sends CONNECT_IND | one-shot |
| Create Connection | 0x0405 | paging | one-shot |
| Remote Name Request | 0x0419 | paging | one-shot |
| Write Scan Enable, inquiry or page scan on | 0x0C1A | the controller answers other devices' inquiries and pages | Write Scan Enable with both bits clear |

Every persistent kind also ends at **Reset** (0x0C03, §7.3.2), which
returns the controller to its power-on state, and at **DEL_INDEX**.
Reset is read for that reason only; it carries no parameters.

**Two clocks, one finding.** The persistent kinds stay on the air from
their enable to their disable, however old the enable is, so each
controller holds them as **on/off** (`ble_own_tx_on`). The one-shot
kinds end on their own, so for them sloth keeps only how recently the
command arrived (`ble_own_tx` = `recent` within 120 s, on the host
clock). `BT_OWN_TRANSMIT` fires for every kind that is **on, or whose
own newest command is recent** (`ble_own_tx_asserted`) — one incident
per kind, each on its own clock, so an active scan followed by
advertising is two incidents. It resolves through the engine's quiet
period once a kind is neither: its disable has crossed the channel and
the window since its last command has passed. It is own operational
state, not an adversary finding, so it carries no ATT&CK technique
([[alerts]]).

Extended advertising sets are tracked by handle only from commands that
name one set. With `Num_Sets` > 1 the Core Specification's per-field
arrays and the kernel's per-set records put the handles at different
offsets — the same disagreement as multi-report advertising events — so
such an enable reads as "on, handles unknown", which only a disable of
all sets clears. A partial disable of several sets changes nothing, the
safe side. Up to 8 controllers are tracked; commands for any beyond that
share one slot whose on-state only grows, and `ble_own_tx_baseline`
stays `0`.

**What sloth was never told.** The on/off state holds only what crossed
the channel since sloth opened it. A controller that was already
advertising, or already page-scanning, when sloth started — page scan is
the normal state of a powered, connectable BlueZ adapter — shows nothing
until the host next sends one of these commands. So `ble_own_tx` =
`never` and an empty `ble_own_tx_on` mean **no transmit command seen
since the channel opened**, not "the host is listening only". The
statement becomes complete for a controller once a **Reset** of it has
been seen: from there every change crosses the channel.
`ble_own_tx_baseline` reads `1` when that holds for every tracked
controller; step 1 of the procedure below gets it there.

What else it cannot see: a command the controller then rejects still
counts (sloth does not pair commands with their Command Complete); a
state the controller ends on its own — an advertising set's `Duration`,
a connection that stops connectable advertising, an extended scan's
`Duration` — stays on until the host disables it or resets the
controller, the safe side; and a transmission a controller makes without
a host command — vendor firmware, an LE connection the controller
maintains once it exists — is not visible here.

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
   `sensor_health`. Then **power-cycle the adapter with sloth running**
   (`bluetoothctl power off`, `bluetoothctl power on`): the kernel's
   power-on sequence normally resets the controller, and everything it
   is told after that crosses the channel. `ble_own_tx_baseline` should
   read `1`; while it reads `0` (a controller the kernel does not reset
   at power-on, or more than 8 controllers), the controller may be in a
   transmitting state sloth was never shown.
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
   - `ble_own_tx_baseline` = `1`, `ble_own_tx_asserted` = `""` and
     `ble_scan_mode` = `passive` — no transmitting state is on and no
     transmit command arrived in the last 120 s, and because a Reset was
     seen this covers everything the controller was told. Without the
     baseline, `ble_own_tx` = `never` says only that no such command has
     crossed the channel since sloth opened it;
   - `ble_scan_accept_list` = `0` — the scan is not limited to known
     devices;
   - `ble_adv_reports` climbing.

   If `ble_scan_mode` reads `active` or `BT_OWN_TRANSMIT` fires, the host
   is on the air: stop the scan and start again from step 2. A powered
   BlueZ adapter commonly fires `inquiry_page_scan` here, because it is
   connectable (page scan) or discoverable (inquiry scan); turning those
   off in the stack (`bluetoothctl discoverable off`, and
   `btmgmt connectable off`) should send the Write Scan Enable that ends
   it — confirm `ble_own_tx_on` drops `inquiry_page_scan`, since the
   stack, not sloth, decides what it sends. If
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
