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
`src/alerts/rules_ble.c`, `src/ble_flood.c`, `src/ble_detect.c`,
`src/ble_watchlist.c`, `src/views/ble.c` (#144 slice 4),
`src/ble_rotation.c`, `src/siphash.c` (#156 item 2),
`research/bluetooth/ble-address-rotation.md`,
`src/capture/capture.c`
(`capture_fallback_device`), `src/main.c`, `MISSION.md` §1–§2;
Bluetooth Core Specification v5.4 Vol 4 Part E §5.2 (arrayed parameters), §5.4, §7.1, §7.3.2, §7.3.18,
§7.7.65.2, §7.7.65.13, §7.8; Vol 6 Part B §2.3.1 (legacy PDU payload); Linux `include/net/bluetooth/hci_mon.h` and
`net/bluetooth/hci_sock.c`; libpcap `pcap-bt-monitor-linux.c`; #144.

**Last updated**: 2026-10-23 (#156 item 2 review round: sequential-spray poisoning and the flood gate judged at commit; no link under controller duplicate filtering; `BLE_HID_UNEXPECTED` de-duplicates on payload chains only; banded `sensor_health` fields; expiry without frames; 3600 s poison window, full list fails closed; Fast Pair token from a 5-octet filter), 2026-10-23 (#156 item 2: address-rotation hints, `--ble-rotation-hints`, internal use only, off by default), 2026-10-23 (multi-report events decoded as consecutive records per Vol 4 Part E §5.2, for 0x02 and 0x0D; Legacy-bit PHY rule; anonymous fragment trains; LE Coded S=2), 2026-10-22 (LE Extended Advertising Report (0x0D) decoded into the advertiser table and the detectors; fragment policy; multi-report rule reconciled for 0x0D; passive extended scan in the procedure), 2026-10-21 (#144 slice 4: the three BLE detectors, the `[*]` view, `ble_device` / `ble_alert`, Service Data decode; #144 slice 3: the advertiser table is keyed by sensor too and takes the Ubertooth stream; #144 slice 2; on/off own-transmission state after review).

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
| EVENT (3) | LE Meta 0x3E, subevent 0x02 LE Advertising Report, every report | an advertiser row per report |
| EVENT (3) | LE Meta 0x3E, subevent 0x0D LE Extended Advertising Report, every report | an advertiser row per report, [as below](#extended-advertising-reports-0x0d) |
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

### Multi-report advertising events are decoded

Both advertising report events carry `Num_Reports` reports: 0x01..0x19
for the LE Advertising Report (0x02), 0x01..0x0A for the LE Extended
Advertising Report (0x0D). The clauses draw them as arrayed parameters
(`Event_Type[i]`, `Address_Type[i]`, ...), and Core v5.4 Vol 4 Part E
§5.2 says what that notation means on the wire:

> If more than one set of arrayed parameters are specified (e.g.
> ParameterA[i], ParameterB[i]), then, unless noted otherwise, the order
> of the parameters are as follows: ParameterA[0], ParameterB[0],
> ParameterA[1], ParameterB[1] ...

Neither §7.7.65.2 nor §7.7.65.13 notes otherwise, so the reports are
consecutive records: every field of report 0, its Data (and for 0x02
its RSSI after the Data), then report 1. That is also how the Linux
kernel reads both events (`struct hci_ev_le_advertising_info`,
`struct hci_ev_le_ext_adv_info`). sloth decodes every report of such an
event into its own row observation. A controller may put several
reports in one event — §7.7.65.13: "The Controller may coalesce multiple
advertising reports from the same or different advertisers into a
single HCI_LE_Extended_Advertising_Report event" — and refusing those
would undercount exactly the busy air `BLE_ADV_FLOOD` measures.

The whole event is checked before any report reaches the table: each
record must fit, and together they must fill the parameters exactly. An
event whose `Num_Reports` disagrees with its bytes (a second header cut
short, a Data_Length running past the end, a trailing octet), or which
holds one report the clause rules out, is `ble_records_malformed` and
puts none of its reports in the table. The record buckets count events,
so `ble_adv_reports` and `ble_ext_adv_reports` are events, each holding
one or more reports.

Until 2026-10-23 sloth refused `Num_Reports` > 1 on the reading that the
clauses meant per-field blocks (every Event_Type, then every
Address_Type, ...) and that the two layouts could not be told apart.
§5.2 settles the layout, so that refusal was wrong.
`ble_multi_report_rejected` is kept in `sensor_health`, always `0`, so
an archive's series continues.

## Extended advertising reports (0x0D)

A BT 5 controller that the host drives with the extended scan commands
(BlueZ does whenever the controller supports them) reports everything
it hears as subevent 0x0D, legacy PDUs included. Before this decode
such a sensor fed nothing to the table or the detectors. Each report
(§7.7.65.13) is decoded field by field, 24 fixed octets then
Data_Length octets, and the reports must fill the parameters exactly —
an overlong Data_Length or a trailing octet is malformed, never a
prefix.

| Field | What sloth does with it |
|---|---|
| Event_Type bits 0-3 (connectable, scannable, directed, scan response) | with the Legacy bit set, mapped to the 0x02 code of the same PDU — the six combinations the clause lists, anything else malformed; with it clear, `EXT_ADV`, or `EXT_SCAN_RSP` when bit 3 is set |
| Event_Type bit 4 (Legacy) | a legacy PDU through an extended scan: the same row, `last_pdu` and flood key as through a legacy scan, so `BLE_ADV_FLOOD` does not depend on which scan commands the stack chose. Must say data complete (the six listed values all do, so a Legacy-bit report saying otherwise matches none) and carry at most 31 octets (Vol 6 Part B §2.3.1). §7.7.65.13: "If the Event_Type indicates a legacy PDU (bit 4 = 1), the Primary_PHY parameter shall indicate the LE 1M PHY and the Secondary_PHY parameter shall be set to 0x00" — a Legacy-bit report with any other PHY pair is malformed. Its Advertising_SID is ignored and reads none: a legacy PDU has no ADI |
| Event_Type bits 5-6 (data status) | complete, incomplete with more to come, or incomplete truncated; 0b11 is reserved and malformed. See fragments below |
| Address_Type, Address | the row key. `0xFF` is an **anonymous** advertisement with no AdvA: the address is zeroed, so every anonymous advertiser a sensor hears is one row (`addr_type` 255) and one flood address, not a row per whatever the Address field held |
| Primary_PHY, Secondary_PHY, Advertising_SID | the last 0x0D report's, on the row (`primary_phy`, `secondary_phy`, `adv_sid`; `-1` SID for none or no ADI). PHY values as of Core v5.4: 1 LE 1M, 2 LE 2M (secondary only), 3 LE Coded (S=8 where Advertising Coding Selection is supported), 4 LE Coded S=2 (that feature only); secondary 0 is no secondary channel. Kept as received |
| TX_Power, RSSI | 127 is "not available" for both and sets nothing. TX_Power is the header's, not the AD TX Power Level structure, and is not kept |
| Periodic_Advertising_Interval, Direct_Address_Type, Direct_Address | decoded and bounded, not kept on the row |
| Data_Length, Data | walked by the same AD-structure decoder as a legacy report |

`ext_adv` on the row is 1 once an extended (non-legacy) PDU was heard
from it.

### Fragments are not reassembled

An extended advertisement longer than one event arrives as a train of
reports: data status *incomplete* on all but the last, which says
*complete* (or *truncated* when the controller gave up). sloth holds no
reassembly buffer. The **first** fragment of a train is decoded like a
complete report: its Data starts at the first octet of the
advertisement, so every AD structure it holds whole is correct, and
the one the boundary cut is dropped (the walker's truncation rule).
Such a report is counted in `ble_ext_adv_partial`. The middle and last
fragments begin mid-structure, and walking them from the top would read
AD types out of another structure's value, so they are recognised and
counted in `ble_ext_adv_fragments`, never walked. To recognise them a
train is held open in a fixed table of 16 (adapter, address, address
type, SID, scan response) keys — no data, just the key — until its
complete or truncated fragment arrives, or its controller resets or
leaves. A full table pushes out its oldest train (`ble_ext_trains_evicted`);
that train's remaining fragments are then decoded as fresh reports,
which is the one way a mid-structure fragment can reach the AD walker,
and the counter says when it may have. The table evicts the train
touched least recently, so a long train that keeps sending fragments
outlives an idle one opened after it. A legacy PDU is never
fragmented, so a Legacy-bit report never opens or joins a train. The
train accounting is per report, so one event can hold the tail of one
advertiser's train and the start of another's; the event counts as
`ble_ext_adv_reports` when at least one of its reports reached a row.

**Anonymous trains collide.** An anonymous report (Address_Type 0xFF)
has no AdvA, and its address is zeroed, so its train key is just
(adapter, SID, scan response). Two anonymous advertisers using one SID
on one adapter share a train: while the first one's train is open, the
second one's first fragment is counted as the first's tail
(`ble_ext_adv_fragments`) and not decoded. A hostile anonymous
advertiser can therefore hide its own first fragment behind another's
open train, or end that train early with a fragment of its own. Nothing
in an anonymous report tells two advertisers apart, so sloth accepts
the collision rather than guess; an anonymous row's AD fields are the
least trustworthy on the table.

The cost is the AD structures past the first fragment: a name or a
manufacturer structure that only arrives in a later fragment is not
on the row, and the detectors key on only what the first fragment held
whole. A legacy-length advertisement fits one report and is never cut.

`ble_ext_adv_undecoded` is now the 0x0D events that reached no row:
every report in them was the tail of an open train
(`ble_ext_adv_fragments` counts those tails one per report).

## The advertiser table

One row per (sensor, address, address type), 256 rows, `STAB_OLDEST` — an
advertiser picks its own address and a random one rotates, so a spray of
fresh addresses churns the table instead of making it refuse. Every loss
is `evict_ble_device` in `sensor_health`. A row keeps the local name,
first 16-bit service UUID, manufacturer company ID, appearance, TX power
and flags once seen (an `ADV_IND` and its `SCAN_RSP` carry different AD
structures), the last and strongest RSSI, the controller index that
heard it, first/last seen on the capture clock, and a report count.

Since #144 slice 3 the same table takes the Ubertooth stream's
advertisers ([[ubertooth]]). The sensor is part of the key — kind `ble`
plus `sensor_iface`, `bluetooth-monitor` or `ubertooth` — so one
advertiser heard by both is two rows: the host controller reports what
its scan hears, an Ubertooth samples one RF channel, and a sum of the
two counts would mean neither. Ubertooth rows carry `sampled` = 1 and
the LL channel index they were last heard on; host rows carry
`channel` = -1, because a legacy advertising report does not say.

Since #144 slice 4 the table is exported as the `ble_device` JSONL
record (change-only, RSSI bucketed to 10 dB) and shown in the `[*]` BLE
view (`*` because every letter and digit was taken; `b` is Beacons). A
row also keeps the first manufacturer-data octet after the company ID
(the Continuity type for Apple), the first Service Data UUID (AD type
0x16, decoded from this slice), whether a HID appearance or the 0x1812
service was advertised, and a watchlist category.

## Detectors on the advertisements (#144 slice 4)

These rules read what other devices broadcast; each is **WARN** and
none makes sloth transmit, connect or read GATT. Full gates and sources
in [[alerts]] and `research/bluetooth/`, `research/cve/2023-45866.md`.

- **`BLE_ADV_FLOOD`**: per sensor and per payload key (Event_Type,
  company ID or Service Data UUID, first octet), tumbling windows of
  `ble.flood_window_s`. Fires only when a window holds at least
  `ble.flood_distinct_addrs` **fresh** addresses (new to the key since
  the two windows before, so a crowd of stable genuine advertisers
  counts none and a key's first window cannot fire) **and** `ble.flood_rate`
  advertisements per second **and** the key is one the BLE Spam tool's
  own source emits (Apple 0x07 / 0x0F, Microsoft Swift Pair 0x03,
  Samsung 0x42 / 0x01, Google Fast Pair 0xFE2C). No threshold has a
  cited basis for where a crowded room stops, so all three are required.
- **`BLE_HID_UNEXPECTED`**: a HID appearance or the 0x1812 service from
  a public address in the Hak5 or Espressif OUI table, or HID
  appearances on `ble.hid_rotate_addrs` new random addresses inside
  `ble.hid_rotate_window_s` once that sensor's observation is older
  than that window (per sensor). A row evicted from the 256-row table
  and heard again is new again, so on a site that churns the table
  (`evict_ble_device`) a resident keyboard can count.
  A precursor of the CVE-2023-45866 class, never an exploit observation.
- **`BLE_WATCHLIST`**: a category row (`src/ble_watchlist.c`) matched.
  **The table ships empty**; a row lands with the primary source that
  documents its shape. A category, never an identity.

The stalk-grade CRIT the issue sketched is deferred: "non-resident" has
no definition yet. A flood alert from an Ubertooth row says its counts
are a one-channel sample. Each finding also has a `ble_alert` JSONL
record built from the same list the rule fires from.

## Address-rotation hints (internal use only)

**Off by default.** `--ble-rotation-hints` (owner ruling 2026-10-23,
#156 item 2) turns on an internal enrichment of the advertiser table.
It is ignored, with a notice on stderr, without `--bt-monitor` or
`--bt-capture` — and so under `--replay` too.

**What it says.** A private address (resolvable or non-resolvable, by
Address[47:46]) that went silent and another of the same sub-type that
appeared on the same sensor and adapter may be one advertiser rotating
its address. In sloth's words: *possible address rotation — the newer
address may be the same advertiser as the older one, a token carried
across the change with no overlap; this corroborates, does not confirm,
and identifies no device or person.* A timing-only hint is weaker still:
*another advertiser leaving and arriving reads the same.* **These
records alone are not grounds for personnel action or physical
identification.**

**Why the spec makes it possible.** Core v5.4 Vol 3 Part C §10.7.1.1
says advertising-data changes "should be synchronized with any changes
in private addresses", and §10.7.1 / §10.7.3 that a device "should not
send the device name or unique data in the advertising data". When a
vendor does not, a token outlives the address. The rotation interval is
**a recommended maximum of 15 minutes** (Appendix A,
T_GAP(private_addr_int)); devices have been observed holding an address
from seconds to more than four days. Sources and grades:
`research/bluetooth/ble-address-rotation.md`.

**Grades.**

- **Payload (grade A + B).** A documented token carried across the
  change: an MS-CDP beacon's Salt + Device_Hash (company 0x0006,
  Scenario_Type 1); an Apple Handoff body (0x004C, Continuity type 0x0C)
  — **unverified**, the layout is the papers' and a 2021 study saw it
  link nothing on iOS 13; Fast Pair account data whose salt did *not*
  change, which is the vendor ignoring the spec — from a 5-octet Account
  Key Filter up, filter + salt with the fixed 0x21 header left out. A
  4-octet filter (one key) is not a token: at most 8 bits set in 32 is
  at most about 23.8 bits, 39.8 with the salt, under the research's
  40-bit bound (5 octets reach at most about 53.1; ceilings, not
  measured entropy). Tokens are held only as SipHash-2-4 digests.
- **Timing (grade B + C).** No token: the old address's last report
  came before the new one's first, within 10 s, the two never
  interleaved, and the advertising shape (PDU type, payload family, AD
  structure list and lengths) agrees, with no second arrival in the
  same seam. Used only to de-duplicate, never as a link.
- A link is pending for 10 s, then committed. An older address heard
  again afterwards revokes it.

**Guards.** Static random, public and resolved-identity addresses
(Address_Type 2/3) are never candidates. A token heard on two
interleaving addresses, or on three addresses first heard inside one
10 s seam (a captured token sprayed on fresh addresses one after
another never interleaves), is poisoned for 3600 s — the longest
documented token life (MS-CDP about an hour, Becker; Celosia 2019), not
the 15-minute address interval — and every link on it is revoked. A
full poison list (16 per sensor and adapter) fails closed: no payload
link on that sensor until the window of the poison it could not record
has passed. Nothing links while `BLE_ADV_FLOOD`'s fresh-address gate is
active on the payload key, and a report under the gate excludes every
recent entry on that key, so a link proposed before the gate tripped is
refused when it falls due. Never across sensors or adapters. Never a
Fast Pair discoverable advertisement ("the BLE address shall not be
rotated"). A chain stops at 8 links and at 2 h from its first address.

**Duplicate filtering.** Exclusivity and poisoning both need the older
address to be reported *again* after the newer one appears. A
controller scanning with `Filter_Duplicates` on (LE Set Scan Enable
0x200C / LE Set Extended Scan Enable 0x2042, Vol 4 Part E §7.8.11,
§7.8.65) reports each address once, so neither can be seen. sloth reads
the parameter from the host's own enable command on each adapter, and
**proposes and commits no link on an HCI adapter whose filter is on or
was never seen** (sloth started after the scan did, or a Reset since).
The passive-scan procedure below already asks for that:
`hcitool lescan --passive --duplicates` enables with
`Filter_Duplicates` = 0; an extended-scan tool must send 0x00 in the
same field. Otherwise the feature is silent on that adapter. The
Ubertooth stream (`--bt-capture`) is raw air and is not filtered.

**Who reads it.** Internal consumers only: the `[*]` view's estimate
line ("est. N advertisers for M addresses", stated as an estimate,
with the timing-only caveat whenever a timing hint was committed) and
`BLE_HID_UNEXPECTED`'s rotation form. **That form counts payload
chains only**: rows a committed *payload* hint joins count once, so an
advertiser carrying a documented token across its rotations is one, but
a timing-only chain never reduces the count. The research grades
timing a corroborator, never a finding, and a lone fast-rotating HID
advertiser — the case form (b) exists for — is never ambiguous on
timing, so letting timing de-duplicate would suppress exactly it. The
trade: a keyboard rotating its RPA with no token (most of them) is
still counted per address, as without the flag. The deferred
stalk-grade CRIT's "non-resident" definition is not built; its hook is
the hint's chain start (`src/ble_detect.h`).

**Privacy statement.** The feature is itself a tracking capability, so:

- **default off**, and with the flag absent nothing is allocated, no
  field or line appears, and two off runs write the same bytes whether
  or not the feature ran in between (unit-tested); byte identity with
  the build before #156 is `make replay-check`, whose golden predates it
  and replays a Bluetooth monitor capture with the flag off;
- **keyed per run**: the SipHash key is drawn from `getrandom()` at
  startup, so no digest means anything outside the run that made it;
- **never exported**: no row shows a link, no JSONL field names a link,
  a token or a digest, nothing goes to the database. Token bytes are
  never stored. What leaves the process is three `sensor_health`
  decade bands — `ble_rot_hints` (payload and timing summed),
  `ble_rot_poisoned`, `ble_rot_seam_evictions` ([[jsonl-schema]]) —
  which carry no address and enter no change-only signature. **Residual
  inference, stated:** exact counts with the payload/timing split would
  let a consumer of the `ble_device` records on a quiet sensor match an
  increment, 10 s after one address's first report, to the single
  departure/arrival pair, and learn the two carried the same token
  (which it cannot compute itself: token bytes are never exported).
  Bands and no signature edge reduce that to "some link committed
  between two heartbeats"; they do not remove it;
- **bounded**: 64 recently heard private addresses per sensor and
  adapter, oldest dropped first (`ble_rot_seam_evictions`). Expiry runs
  on the frame clock carried forward by monotonic time, so a quiet
  radio or an ended `--bt-capture` file still expires. 20 s of silence
  (d_swap after the last report plus the d_swap a pending link waits)
  wipes an address's digests and shape; 2 h wipes the address and its
  chain fields, which the interleave guard needs until then — a
  deviation from the research's freshness rule, flagged there. Expired
  poison slots are wiped. A committed chain id stays on the advertiser
  row it joined for that row's life (internal, never exported), so a
  link survives the seam table's eviction; turning the flag on or off
  clears it.

Receive-only throughout (MISSION §2): no scan request, no connection,
no GATT read. The advertising interval, which the research grades as a
corroborator, is not used: the frame clock reaches the table at one
second.

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
name one set. With `Num_Sets` > 1 the handles are not read yet (§5.2
makes them consecutive per-set records, which the kernel's
`struct hci_cp_ext_adv_set` matches, so they could be), and such an
enable reads as "on, handles unknown", which only a disable of all sets
clears. A partial disable of several sets changes nothing, the
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
   scan commands, so reports arrive as subevent 0x02. Another scanner on
   the same controller (bluetoothd's own) can make it fail with an I/O
   error; stop that first. On a **BT 5 controller** the legacy commands
   may be refused once the stack has used the extended ones (the
   controller may not mix the two sets between resets), and since the
   0x0D decode a passive **extended** scan is equally usable: any tool,
   other than `bluetoothctl` and `btmgmt` (whose discovery is active),
   that sends LE Set Extended Scan Parameters (0x2041) with
   `LE_Scan_Type` = passive on every PHY it enables and then LE Set
   Extended Scan Enable (0x2042). Its reports arrive as subevent 0x0D,
   legacy PDUs included. **sloth still never starts a scan** of either
   kind and sends neither command: the tool is the operator's, and
   step 4 is how sloth checks it.
4. **Verify in `sensor_health`**:
   - `ble_own_tx_baseline` = `1`, `ble_own_tx_asserted` = `""` and
     `ble_scan_mode` = `passive` — no transmitting state is on and no
     transmit command arrived in the last 120 s, and because a Reset was
     seen this covers everything the controller was told. Without the
     baseline, `ble_own_tx` = `never` says only that no such command has
     crossed the channel since sloth opened it;
   - `ble_scan_accept_list` = `0` — the scan is not limited to known
     devices;
   - `ble_adv_reports` climbing under a legacy scan, or
     `ble_ext_adv_reports` under an extended one.

   If `ble_scan_mode` reads `active` or `BT_OWN_TRANSMIT` fires, the host
   is on the air: stop the scan and start again from step 2. A powered
   BlueZ adapter commonly fires `inquiry_page_scan` here, because it is
   connectable (page scan) or discoverable (inquiry scan); turning those
   off in the stack (`bluetoothctl discoverable off`, and
   `btmgmt connectable off`) should send the Write Scan Enable that ends
   it — confirm `ble_own_tx_on` drops `inquiry_page_scan`, since the
   stack, not sloth, decides what it sends. A climbing
   `ble_ext_adv_undecoded` is extended report events that reached no
   row: every report in them the tail of a fragmented advertisement
   (`ble_ext_adv_fragments`).

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

- Reassembly of fragmented extended advertisements — the tails are
  counted, not walked, for the reasons above.
- Reading the handles of an LE Set Extended Advertising Enable with
  `Num_Sets` > 1 (held as "handles unknown").
- LE Periodic Advertising Reports (subevent 0x0F) and the other LE Meta
  subevents — outside the allow-list (`ble_records_ignored`).
- The 802.11 crosswalk — split out of #144. Address-rotation hints are
  built (#156 item 2, internal, off by default; above); a dense-room
  false-pair measurement and a capture on current Windows, iOS/macOS
  and Android are not, so every token row keeps its "unverified".
- Watchlist rows: none shipped; each needs its primary source.

## Related pages

- [[ubertooth]] — the over-the-air source: `--bt-capture`, and the
  allowed and forbidden Ubertooth tools and flags.
- [[cli-reference]] — `--bt-monitor`, `--ble-rotation-hints` and the `bluetoothN` refusals.
- [[jsonl-schema]] — the `btmon_*` / `ble_*` fields of `sensor_health`.
- [[alerts]] — `BT_OWN_TRANSMIT` and the own-operational-state form;
  `BLE_ADV_FLOOD`, `BLE_HID_UNEXPECTED`, `BLE_WATCHLIST`.
- [[non-ip-sensors]] — the sensor-family roadmap BLE came from.
- [[monitor-mode]] — the 802.11 counterpart: sloth reads a monitor
  interface and never configures one.
