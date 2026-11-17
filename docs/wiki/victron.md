# Victron (sloth-va)

**Summary**: `sloth-va` is a separate helper that reads the owner's
Victron Energy devices over Bluetooth LE through BlueZ: it decrypts their
Instant Readout advertisements with the owner's per-device keys (no
transmission: a passive scan the kernel holds for a BlueZ advertisement
monitor) and, every few minutes per device, holds a short GATT session
(connect, pair with the PIN, read, disconnect) — which transmits. It
appends one JSONL record per reading to `/var/lib/sloth-va/victron.jsonl`.
It is the first sloth-family component that transmits; why that is
allowed, and how it is bounded and announced, is
[ADR 0011](adr/0011-sloth-va-transmits.md). sloth itself is unchanged by
it and links none of it.

**Sources**: `src/va/main.c`, `src/va/va_victron.c`, `src/va/va_conf.c`,
`src/va/va_aes.c`, `tests/test_va.c`, `src/victron.c`,
`src/capture/victron_reader.c`, `tests/test_victron.c`, `src/db.c`
(`write_victron()`), `src/db_schema.c`, `src/sys_status.c`,
`web/src/web_victron.c`, `web/ui/victron.js`, `web/ui/victron.css`,
`web/tests/test_victron.c`, `web/tests/test_fleet.c`,
`packaging/systemd/sloth-va.service`,
`packaging/systemd/sloth-va.sysusers.conf`, `packaging/default/sloth-va`,
`Makefile` (`sloth-va`, `WITH_SDBUS`),
`research/victron/instant-readout-and-gatt.md`.

**Last updated**: 2026-11-16 (the inverter record, 0x03, decoded: state, alarm, battery V and the AC output's V, A and VA, for the Phoenix behind the VE.Direct dongle; three new values on sloth's allow-list, JSONL 2.1.0, sloth.db v16, an inverter card in slothweb); 2026-11-16 (sloth-va registers its advertisement monitor asynchronously; the beta-site worker's fix); 2026-11-15 (#216, the cutover: `--victron` is `sloth-rf`'s alone; `sloth-wifi` refuses it); 2026-11-15 (the web: slothweb's Victron tab,
`/api/victron` and `/api/victron/history`; sloth.db v15
`victron_devices` / `victron_readings`; the `victron` `source_status`
row, so `SENSOR_SOURCE_DOWN` covers the file; the fleet decision,
withheld whole; `victron_device` gains `services` and `values_src`,
JSONL 1.10.0), 2026-11-15 (`--victron`: sloth's reader of the file,
the `victron` sensor, `victron_device` and `sensor_health`'s `victron_*`),
2026-11-15 (new: the helper, its files, its scan and session behaviour,
the per-device support table).

## What it reads, per device

From [the research note](../../research/victron/instant-readout-and-gatt.md),
which cites each item:

| Device (owner's label) | Instant Readout | GATT session | Status |
|---|---|---|---|
| BMV-712 Smart, SN HQ2501YV9FU | record 0x02 "battery monitor": voltage, current, SOC, consumed Ah, TTG, alarm reason, aux (starter V / mid V / temperature) | reads the 65970000 service if the device has it (voltage, current, power, consumed Ah, SOC); otherwise records its service list | readout: Victron's published layout, two published vectors reproduced. GATT: Victron documented the service for the SmartShunt only — unverified here |
| Orion-Tr Smart 12/12-18A isolated, SN HQ2515QP3RX | record 0x04 "DC/DC converter": device state, charger error, input V, output V, off reason (no currents) | as above | readout as above; GATT unverified |
| VE.Direct Bluetooth Smart dongle, SN HQ25232KEJG, on a Phoenix Inverter 12V 500VA 120V (model 0xA259) | record 0x03 "inverter": device state, alarm reason, battery V (`voltage_v`), AC output apparent power (`ac_apparent_va`), AC output V (`ac_voltage_v`), AC output A (`ac_current_a`) | as above; needs its MAC in `victron-va.conf` | readout: Victron's published layout, checked against hand-built vectors only (no published one). sloth-rf carries all six (JSONL 2.1.0, sloth.db v16) and slothweb's card shows them, charting battery V, AC V and AC VA. GATT unverified |

Not implemented: VictronConnect's own service
(306b0001-b081-4037-83dc-e59fcc3cdfd0) and its framing, which Victron
has not published. A device that offers only it gets a
`"session":"no_supported_service"` record listing its services, which is
the evidence for the next step. The other [EMD] record types (solar
charger, inverter RS, …) are named but not decoded.

## The two secret files

Both root-owned, mode 0600, under `/etc/sloth/`; the unit hands sloth-va
private copies with `LoadCredential=`, so the files never need to be
readable by its account. Both must exist (an empty one is fine).

```
# /etc/sloth/victron-va.conf   SERIAL PIN [MAC]  # comment
HQ2501YV9FU 123456                    # BMV-712 Smart
HQ2515QP3RX 123456                    # Orion-Tr Smart
HQ25232KEJG 123456 e4:b9:aa:47:57:1f  # VE.Direct dongle (no readout, so the owner names its address)

# /etc/sloth/victron.keys      MAC KEY(32 hex)  # comment
c7:fe:23:b1:1c:5f 0123456789abcdef0123456789abcdef
f5:d8:0c:b6:31:cf 0123456789abcdef0123456789abcdef
```

(PINs and keys above are placeholders.) The PIN is the device's
six-digit Bluetooth PIN. The key is the Instant Readout key
VictronConnect shows under the device's product info ("Instant readout
via Bluetooth" → "Show"). [EMD] says the device changes the key when its
PIN changes; sloth-va then logs a key-check mismatch once and stops
decoding that device, as the spec requires.

A malformed line is ignored and reported by line number and a fixed
reason, never its text. `sloth-va --check --config … --keys …` parses
both and exits (2 when any line was refused).

## How serial and address are matched

The owner knows serials; the radio knows addresses. A PIN is used only
on the device it belongs to:

1. A `victron-va.conf` line with a MAC: that is the owner's statement.
2. Otherwise, a device from `victron.keys` whose BlueZ name carries a
   configured serial as a whole word (Victron's default names do, e.g.
   "SmartShunt HQ2121ABCDE"). If BlueZ has no name for it yet, sloth-va
   connects once, unpaired, so BlueZ reads the GAP name, and
   disconnects ("learn" session).
3. A match is kept in `/var/lib/sloth-va/learned.map` (`MAC SERIAL`, no
   secret). A name with no configured serial is tried again after six
   hours. A device renamed by its owner has to be given a MAC.

## On the air, and what sloth shows

- **Instant Readout**: sloth-va registers an
  `org.bluez.AdvertisementMonitor1` with one pattern, AD type 0xFF
  starting `e1 02`. Without hardware offload the kernel keeps a passive
  background scan running while a monitor exists, with duplicate
  filtering off (net/bluetooth/hci_sync.c, `hci_update_passive_scan_sync`,
  `hci_passive_scan_sync`). Passive: no SCAN_REQ. BlueZ marks this API
  experimental, so bluetoothd needs `Experimental = true`; without it
  sloth-va says so and runs GATT only. `RegisterMonitor` is sent
  asynchronously and its reply handled in the event loop: BlueZ answers
  it by calling back into sloth-va's `GetManagedObjects`, which a
  blocking call left unanswered (beta-site, 2026-11-15: no `Activate`,
  no scan). It never falls back to discovery
  (`StartDiscovery` is an active scan; a test holds that the call is not
  in the source). One record per device per `--readout-every` (30 s).
- **GATT sessions**: one at a time, each bounded to 60 s, per configured
  device every `--interval` (300 s): `Connect`, `Pair` if not bonded
  (the agent answers with that device's PIN only), the keep-alive
  written as a write request (2 bytes, ms, little endian; 0xFFFF
  "forever" refused), each documented characteristic read,
  `Disconnect`. Every path out of a session that connected disconnects.
  A device BlueZ has not heard is skipped, not searched for.
- **sloth's BLE view** (with `--bt-monitor`): the kernel's passive scan
  on sloth-va's controller still feeds sloth every advertising report;
  `ble_scan_mode` reads `passive`. Each GATT connection is an LE Create
  Connection on the monitor channel, so `BT_OWN_TRANSMIT` fires (WARN,
  `le_connect`, the controller named) for 120 s after each and resolves
  after the quiet period; with three devices at 300 s it is effectively
  standing. That is the alert working, not noise: see ADR 0011.

## Output record

One line per reading or session, `type` `victron`:

```
{"type":"victron","t":1763200000,"source":"readout","mac":"c7:fe:23:b1:1c:5f",
 "serial":"HQ2501YV9FU","label":"BMV-712 HQ2501YV9FU","model_id":"0xa381",
 "model":"BMV-712 Smart","record":"battery_monitor","rssi":-71,
 "values":{"voltage_v":13.200,"alarm_reason":0,"aux_input":3,"aux_input_name":"none",
           "current_a":-1.500,"consumed_ah":-12.300,"soc_pct":87.500}}
{"type":"victron","t":1763200300,"source":"gatt","mac":"c7:fe:23:b1:1c:5f",
 "serial":"HQ2501YV9FU","session":"ok","values":{"voltage_v":13.200,...}}
```

- `source`: `readout` (decrypted advertisement) or `gatt` (a session).
- `serial`: the owner's serial when mapped, else `null`. `label`: the
  device's own name (untrusted; escaped, cut to 48 bytes).
- `values`: unit-suffixed names (`_v`, `_a`, `_ah`, `_pct`, `_min`,
  `_w`, `_c`); a value absent from the device, at its NA code or out of
  its documented range is absent, never zero or clamped. Enumerations
  carry a `_name` beside the number.
- `session` (gatt only): `ok`, `no_values`, `no_supported_service`
  (with `services`), `learned`, `name_unmatched`, `connect_failed`,
  `pair_failed`, `services_unresolved`, `timeout`, `bluez_error`.

No record field can hold a PIN, a key or a raw advertisement byte.

## sloth's side: `--victron`

sloth reads the file as a passive source, the same shape as `--rtl433`
([[cli-reference]]): `--victron /var/lib/sloth-va/victron.jsonl`.
Since the cutover (#216) `--victron` is **`sloth-rf`'s flag alone**
(`src/rf_flags.c`, `src/jsonl_rf.c`): `sloth-wifi` refuses it with exit
2 and a line naming `sloth-rf` and `sloth-migrate-rf` ([[deployment]]
§11.4), and the `victron_device` record, the `victron_*` block, the
`victron` source row and the `victron_*` tables are in `sloth-rf`'s
stream and database only. Where this section says "sloth" reads the
file, the daemon is `sloth-rf`.
`src/victron.c` parses each line against an allow-list of value names
with bounds (out of range absent and counted, never clamped; other
names counted and dropped; the device's own `label` never kept) into
one row per address, at most 16 (a 17th is refused and counted, not
evicted). `src/capture/victron_reader.c` tails the file once a second
from its end, following rotation and truncation. The sensor registry
gains kind `victron` ("Victron (sloth-va)"); `sensor_health` gains the
`victron_*` block; the change-only `victron_device` record carries each
device's latest values ([[jsonl-schema]]). sloth opens no Bluetooth
socket for this and decrypts nothing; the file is all it sees.

sloth keeps, per device, the newest GATT session's service list
(`services`: lower-case UUIDs joined by `,`, only when every byte is
`[0-9a-fA-F-,]` and it fits sloth-va's 400-byte cap, otherwise absent;
a later session without a list clears it) and which path delivered the
newest record that carried values (`values_src`, `readout` or `gatt`).
Values stay sticky across the two paths: a GATT session's `power_w`
and a readout's `soc_pct` sit on one row, so a row's values are a mix
whenever both paths deliver.

### History: sloth.db v15

With `--db`, `write_victron()` keeps `victron_devices` (one row per
address: serial, model, record type, the newest session outcome and
its services, when each path last delivered, sloth's counts) and
`victron_readings` (each value under its own column, `src` the path of
the newest values), at most one reading row a minute per device
(`DB_VICTRON_MIN_S`), observation tier for the readings and entity
tier for the inventory, so `--db-retain-days` and `--db-max-mb` apply
as to every other table. v16 added the inverter's three `ac_*` columns.
Schema, the stamp-only v14 → v15 step and the v15 → v16 one:
[[sqlite-schema]].

### Source health

`source_status` has a `victron` row, in sloth-rf's stream (`--victron`, kind `victron`,
unit `records`): `live` is `ok` however quiet (sloth-va writes nothing
while the devices are out of range), a file not there yet is `stale`,
a read error `down`. `SENSOR_SOURCE_DOWN` reads that row like any
other source's, so a broken file opens a WARN
(`tests/test_sensor_rules.c test_victron_source_down`).

### Fleet: withheld

`victron_device` does not travel, and the importer refuses a peer's
answer carrying one whole (`web/tests/test_fleet.c
test_ingest_refuses_victron`). The rule (ADR 0009, CLAUDE.md) is
provenance: a GATT session's values came through an authenticated
connection, never monitor mode, so they never travel. An Instant
Readout value is a passively heard advertisement, but sloth's row
merges both paths' values, so no record can be shown to hold readout
values only; the record is withheld whole, fail closed, until the
owner classifies the readout half and a record that carries only it
exists.

### slothweb: the Victron tab

A tab after rtl_433 (`web/ui/victron.js`, `web/ui/victron.css`), from
`web_victron.c`:

- `GET /api/victron?limit=` — the sensor block (the `victron_*`
  members) and one entry per device, the most recently heard first:
  address, serial, model, record type, `values_src`, `first_seen`,
  `last_seen`, `last_readout`, `last_gatt`, `age_s`, `stale_after_s`,
  `stale`, the counts, the last `session` and its `services` split into
  a list, `rssi`, and `values` as `{name: {v, unit}}`. Kept in memory
  from the stream, up to 32 rows, a row with no record for 660 s
  dropped. Stale: sloth writes a device on a banded change or the 300 s
  heartbeat, so a live device's newest record can be 300 s old; past
  360 s (660 s for a device heard only through GATT sessions) it is
  `stale`, and the tab marks the card and its figures.
- `GET /api/victron/history?mac=&metric=&hours=` — one value of one
  device over the last 1..720 hours (default 24) from sloth.db's
  `victron_readings`: at most 240 buckets of at least 60 s, each
  `[t, mean, min, max, n, gatt]` (gatt: the bucket's rows written while
  the newest values were a GATT session's). `metric` must be one of
  sloth's 16 value names; anything else is 400 `bad_metric`. A file
  older than v15 answers `have:false` and no points.
- Cards: a battery monitor shows voltage, current, state of charge,
  consumed Ah, time to go, alarm (and power, starter or midpoint
  voltage or temperature when present); a DC-DC charger its state
  ([VED]'s names, as sloth-va's), error, input and output voltage and
  off reason; any other device what values it has, and every card the
  last GATT session's outcome with its service list. Charts: V, A and
  SOC for a battery monitor, input and output V for a charger, each the
  bucket means as a line over their min..max, scaled to the data (not
  from zero) with the range in the caption, painted by `glyph.paint()`.
- Scope: Monitor's and Hybrid's (the rtl_433 and APRS precedent);
  under Local both routes answer `out_of_scope` once the query is
  checked.

## Options

`sloth-va --help`. `--adapter ADDR|hciN` (or `SLOTH_VA_ADAPTER`;
default hci0), `--config`, `--keys` (default `$CREDENTIALS_DIRECTORY/…`),
`--out`, `--state-dir`, `--interval` (≥ 60 s), `--readout-every`,
`--keepalive-ms`, `--no-gatt` (readout only: never connects),
`--check`. Exit 0 on SIGTERM/SIGINT, 1 failure, 2 bad files or usage.

## Unverified until it meets the devices

Tested without a radio: the decode against two published vectors and
two hand-built records, AES against FIPS-197 and SP 800-38A, both
parsers, the record. Not exercised on this host (the owner deploys):
the D-Bus glue end to end, whether BlueZ creates the device objects and
updates `ManufacturerData` under monitor-only passive scanning on this
controller, the passkey prompt Victron devices raise (the agent answers
both `RequestPasskey` and `RequestPinCode`), whether any of the three
devices has the 65970000 service, and whether BlueZ auto-reconnects to
a bonded device between sessions (check `BT_OWN_TRANSMIT`'s cadence
against the schedule after deploying).

## Related pages

- [ADR 0011](adr/0011-sloth-va-transmits.md) — why a transmitting helper, and its bounds
- [[deployment]] §10 — install, the BlueZ settings, the undo
- [[ble]] — `--bt-monitor`, `BT_OWN_TRANSMIT`, `sloth-ble-scan`
- [[rtl433]] — the file-source pattern sloth's reader follows
- [[sqlite-schema]] — `victron_devices` and `victron_readings` (v15)
- [[slothweb]] — the Victron tab
