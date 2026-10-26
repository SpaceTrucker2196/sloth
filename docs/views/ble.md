# `[*]` BLE

**Issue:** [#144](https://github.com/SpaceTrucker2196/sloth/issues/144) slice 4 ·
**Code:** [`src/views/ble.c`](../../src/views/ble.c),
[`src/ble_hci.c`](../../src/ble_hci.c),
[`src/ble_flood.c`](../../src/ble_flood.c),
[`src/ble_detect.c`](../../src/ble_detect.c),
[`src/ble_watchlist.c`](../../src/ble_watchlist.c) ·
**See also:** [`alerts.md`](alerts.md),
[the BLE operator guide](../wiki/ble.md),
[the Ubertooth guide](../wiki/ubertooth.md)

The key is `*` because every letter and digit already selects a view or
is a global (`q` quits, `n` toggles DNS), and `b` is Beacons.

## Protocol

Bluetooth Low Energy advertisements other devices broadcast on the three
primary advertising channels (Core Specification v5.4 Vol 6 Part B
§2.3), as two sources deliver them:

- **`--bt-monitor`**: the Linux HCI monitor channel (libpcap
  `bluetooth-monitor`, DLT 254). The host controller reports each
  advertisement it hears as an LE Advertising Report (Vol 4 Part E
  §7.7.65.2) while the **operator's own stack** runs a passive scan.
- **`--bt-capture PATH`**: an Ubertooth capture file or FIFO the
  operator writes with `ubertooth-btle` (DLT 256 / PPI 251). One RF
  channel at a time, so its counts are a sample.

The advertisement payload is a list of AD structures (Core Spec
Supplement Part A): Flags, Service UUIDs, Local Name, TX Power,
Appearance, Service Data, Manufacturer Specific Data. sloth decodes
those fields and keeps no raw bytes. It never scans actively, connects,
pairs or reads GATT, so nothing here is something sloth asked for.

## What sloth captures

One row per **ble_device_t** — an advertiser as one sensor heard it,
keyed by (sensor, iface, address, address type). The host controller
and an Ubertooth hearing the same address are two rows, because their
counts mean different things. Fields are kept once seen: an ADV_IND and
its SCAN_RSP carry different AD structures.

| Column | Meaning |
|---|---|
| ADDRESS | most significant octet first |
| T | address type: `P` public, `R` random, `p` / `r` the resolved identity forms |
| SENSOR | the iface that heard it: `bluetooth-monitor` or `ubertooth` |
| RSSI | the last report's, dBm |
| ADV | advertisements decoded for this row (a sample on an Ubertooth row) |
| AGE | since the row was last heard |
| HWS | `H` a HID appearance or the 0x1812 service, `W` a watchlist category, `~` one-channel sample |
| ADVERTISES | local name, `mfr <company>/<first octet>`, first `svc` UUID, `sd` Service Data UUID, `app` appearance; cut with `~` when the column is short |

The SENSOR and ADVERTISES columns share the width the fixed columns
leave, so 100 columns gets a row that does not wrap and a wide terminal
gets the whole summary. `Enter` opens every decoded field of the
selected row — address and type, sensor and adapter, LL channel, last
PDU type, name, manufacturer, services, appearance (HID or not), TX
power, AD flags, RSSI and best RSSI, advertisement count, first and
last heard, and the watchlist category with the reminder that it is a
category, never an identity. `Enter` or `Esc` returns.

## Mockup

```
 BLE advertisers: 4  HID: 1  watchlist: 0  flood keys: 3  [up/dn] [Enter] detail
 ADDRESS            T  SENSOR             RSSI     ADV   AGE  HWS  ADVERTISES
>c4:7a:11:20:9e:01  R  bluetooth-monitor   -58     412    1s  ---  mfr 004c/10
 f1:22:93:aa:10:6c  R  bluetooth-monitor   -71      33    4s  ---  "LE-Bose QC" svc fe2c sd fe2c
 24:0a:c4:11:22:33  P  bluetooth-monitor   -49       9    2s  H--  "Keyboard K1" app 03c1
 d8:3c:01:7f:4e:22  R  ubertooth           -80       5   12s  --~  mfr 0006/03
 T: P public R random p/r resolved   H HID  W watchlist  ~ one-channel sample
```

With `--ble-rotation-hints` (#156, internal use only, off by default)
four lines sit above the column header — the only place the hints
show — and a fifth once any timing-only hint has committed:

```
 rotation hints (internal): est. 3 advertisers for 4 addresses - possible address rotation;
   corroborates, does not confirm, and identifies no device or person.
   These records alone are not grounds for personnel action or physical identification.
   Links cover the recent window only: an address out of it counts on its own.
   Includes timing-only hints. Weak: another advertiser leaving and arriving reads the same.
```

The estimate counts addresses a committed hint, payload or timing,
chains together once, over the **recent window only**: a link lasts
while both its addresses are in the 64-entry seam table, so an address
that has left it counts on its own again. It is the hints' only
consumer; no detector reads them (`BLE_HID_UNEXPECTED`,
`BLE_ADV_FLOOD` and `BLE_WATCHLIST` write the same with the flag on as
with it off).
No row, and no detail, says which addresses were joined
([the BLE operator guide](../wiki/ble.md#address-rotation-hints-internal-use-only) has the grades and guards).

## What's normal

- Many random addresses, most rotating every few minutes: phones,
  watches and earbuds use resolvable private addresses by design, so the
  same device appears as a new row now and then and old rows age out.
- `mfr 004c/..` rows everywhere Apple devices are: Continuity
  advertisements (Nearby Info 0x10 is the steady background), and
  Proximity Pair 0x07 from AirPods.
- `svc fe2c` / `sd fe2c` from Fast Pair headsets, `mfr 0006/03` from a
  Swift Pair peripheral being paired.
- A public-address keyboard or mouse with `H`: HID over LE is ordinary.
- Ubertooth rows with low ADV counts: it listens on one channel of 40.

## What's suspicious

- **Dozens of fresh random addresses on one payload key at once**
  (`mfr 004c/07`, `004c/0f`, `0006/03`, `0075/42`, `sd fe2c`) — the BLE
  Spam tool's shape. `BLE_ADV_FLOOD` fires only when fresh addresses
  (new to the key since the two windows before), rate and a documented
  spam key all pass together, so a room of stable AirPods is quiet; the `flood keys`
  count in the header is how many payload keys are being counted, not
  how many are flooding.
- **`H` on a public address in a Hak5 or Espressif block**, or `H`
  appearing on one new random address after another — `BLE_HID_UNEXPECTED`.
  A precursor of the CVE-2023-45866 class at most: sloth sees no
  pairing.
- **`W`**: a row matched a watchlist category. The shipped table is
  empty, so this appears only once a sourced row has been added.
- A row count pinned at 256 with `evict_ble_device` climbing in
  `sensor_health`: an address-rotation spray is churning the table.

## Distance estimate (2026-10-26)

The `DIST` column (short `~27m↘` at 100 columns, full from 106) and a
`distance (est)` line in the detail. An **estimate from signal strength**: walls and reflections dominate,
and it is not a location. The median of the row's last 8 RSSI samples
goes through ITU-R P.1238's indoor log-distance model; the cell reads
`~27m bldg ↘` — metres, band (`imm` < 1 m, `near` 1–3, `room` 3–10,
`bldg` 10–30, `far` > 30) and trend (↘ approaching, → steady, ↗
leaving, blank until enough samples); `-` is no estimate (an RSSI of 0
is no sample, never 1 m). The typical indoor error is a factor of two,
five when a body or a wall is in the way. No alert rule reads it. Model,
sources and knobs: `docs/wiki/rf-distance.md`.

The advertiser's own power is used when it states one — the extended
report header's TX_Power first, then the TX Power Level AD structure —
else an assumed 0 dBm. A Wi-Fi calibration never applies here: the BLE
controller is a different receiver. In JSONL the change-only
`ble_device` signature takes the band only, never the metres or the
trend: the trend is on every record, but under ordinary RSSI noise it
moves for an advertiser that is not moving.

See [`alerts.md`](alerts.md) for each rule's gates and the sources they
rest on, and `research/bluetooth/` for the documents.
