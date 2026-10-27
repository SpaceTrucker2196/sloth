---
name: location
description: Where the sensor is — --location for a fixed sensor, --gps for an NMEA serial receiver or gpsd, how a fix is chosen and aged, what is stamped where (alerts, captures' manifests, device position samples), the accuracy caveat and the privacy of the coordinates
type: reference
---

# Sensor location (`--location`, `--gps`)

**Summary**: sloth can record **where the sensor was** when it made a
finding. `--location LAT,LON[,ALT]` gives a fixed sensor its position;
`--gps SPEC` reads a moving one's from a GPS receiver, either NMEA 0183
off a serial device (no network at all) or gpsd's JSON stream over
loopback TCP. Every new alert incident is stamped once, as it opens,
and the stamp travels with it: the JSONL `alert` and `alert.*`
records' `loc` object, the `--db` alerts row, the hashed manifest line
of every pcap the alert writes, the TUI's alert detail and slothweb's
alert page. With `--gps` and `--db`, a moving sensor also keeps a
bounded series of where it was each time it heard a device, and its
own track; slothweb draws them and exports GeoJSON and GPX. Both flags
are off by default and announced on stderr. Neither transmits on a
monitored network (MISSION §2); `--gps gpsd://` sends gpsd one
`?WATCH` line over loopback TCP.

**Sources**: `src/gps.h`, `src/gps.c` (NMEA and gpsd parsers, the
`--gps` SPEC, the arbitration state), `src/capture/gps_reader.h`,
`src/capture/gps_reader.c` (the serial / gpsd worker),
`src/position_track.h`, `src/position_track.c`, `src/alerts/engine.c`
(`fire_inv()`), `src/jsonl.c` (`emit_loc()`, `gps_*`),
`src/evidence_manifest.c`, `src/db.c`, `src/db_schema.c` (schema v9),
`src/main.c`, `src/views/alerts.c`, `src/views/iface.c`,
`packaging/systemd/sloth-sensor.service.d/gps.conf`,
`web/src/web_loc.c`, `web/src/web_positions.c`, `web/ui/location.js`;
NMEA 0183 as gpsd documents it (https://gpsd.gitlab.io/gpsd/NMEA.html);
gpsd(8) (https://gpsd.gitlab.io/gpsd/gpsd.html), the client HOWTO
(https://gpsd.gitlab.io/gpsd/client-howto.html) and the JSON protocol
(https://gpsd.gitlab.io/gpsd/gpsd_json.html); RFC 7946 (GeoJSON); GPX
1.1 (https://www.topografix.com/GPX/1/1/).

**Last updated**: 2026-10-27.

## Sources of a position

| Flag | What it is | Network | Privilege |
|---|---|---|---|
| `--location LAT,LON[,ALT]` | a fixed sensor; WGS84 decimal degrees, metres above mean sea level | none | none |
| `--gps /dev/ttyACM0` | NMEA 0183 `GGA`, `RMC`, `GSA` from a serial receiver | none | the device's group (usually `dialout`); opened **before** the privilege drop, read-only |
| `--gps gpsd://[HOST[:PORT]]` | gpsd's `TPV` and `SKY` objects | TCP, `127.0.0.1:2947` by default; a remote host needs `--gps-allow-remote` and is refused under `--strict` | none; dialled after the drop |

**There is no `gpsd://PATH`.** gpsd's `-F` Unix socket is a control
socket for adding and removing devices (`+dev`, `-dev`) and answers OK
or ERROR; the reports a client reads go over TCP only (gpsd(8)). The
serial path is therefore the no-network option, and the one a
hardened sensor should prefer.

**Why the serial device is opened before the drop.** sloth's
privilege drop clears supplementary groups (`setgroups(0, NULL)`,
`src/privdrop.c`) and fails closed if any survive, so a device
readable only by `dialout` cannot be opened after it. The descriptor is
opened once, `O_RDONLY | O_NOCTTY`, configured raw at `--gps-baud`
(9600 by default), and read by a worker started after the drop. sloth
never writes to it, so it cannot reconfigure the receiver. A lost
device is reopened with backoff; after the drop that reopen may be
refused, and `gps_err` says so.

**NMEA.** A sentence is accepted only with a correct checksum (the XOR
of every byte between `$` and `*`) and at most 82 bytes from `$` to
CRLF. The talker is ignored (`GP`, `GN`, `GL`, `GA`, `GB`, `BD`, ...);
`GGA`, `RMC` and `GSA` merge into one receiver state, everything else
is counted and skipped. Numbers are parsed without `strtod()`, so the
locale cannot change them. A fix is usable when it has a position and
GGA fix quality 1 to 5; quality 6 (dead reckoning), 7 (manual input)
and 8 (simulation) are reported but **never stamp**. A receiver saying
it has no fix (GGA quality 0, RMC status `V`, GSA mode 1) stops the
stamping at once rather than after `gps.max_fix_age_s`.

**gpsd.** sloth connects, sends `?WATCH={"enable":true,"json":true}`
and reads one JSON object per line. A `TPV` with `mode` 2 or 3 and a
position is a fix (altitude only from a 3D fix, `altMSL` before
`altHAE`); `SKY` supplies the satellites in use and HDOP.

## Which position stamps

At the moment an incident opens:

1. a GPS fix no older than `gps.max_fix_age_s` (30 s) — `loc_src` `gps`,
   `loc_ts` the fix's own time;
2. otherwise `--location`, if given — `loc_src` `fixed`, `loc_ts` the
   stamp time;
3. otherwise **nothing**. An unstamped record carries no `loc` key and
   the database columns are NULL. Never `0,0`: that is a real place.

The stamp is taken once, in the new-incident branch of the alert
engine, and is not refreshed while the incident stays open: it records
where the finding was **made**. A reopen is a new incident with its
own stamp. In `--db`, a row holds its *current* incident's stamp; a
second write of the same incident never overwrites a recorded stamp
(a restart without a fix cannot erase it).

## Accuracy

`acc_m` is an **estimate** of horizontal error, never a guarantee: for
NMEA it is HDOP x 5 m (a typical civilian UERE), for gpsd its `eph`,
else `hypot(epx, epy)`, else HDOP x 5 m. A position is the antenna's,
and a sensor in a building or a vehicle sees multipath that no figure
here reports. The device position samples are where the **sensor**
was when it heard a device; sloth has one antenna and no bearing, so a
series of them is a drive-by record to read beside the RSSI, never a
fix on the device.

## What is written where

| Output | Field(s) | When |
|---|---|---|
| JSONL `alert`, `alert.create`, `alert.update`, `alert.escalate`, `alert.resolve` | `loc` {`lat`, `lon`, `alt_m`?, `acc_m`?, `src`, `ts`} | stamped incidents only ([[jsonl-schema]]) |
| `sloth.db` `alerts` | `lat`, `lon`, `alt_m`, `acc_m`, `loc_src`, `loc_ts` (schema v9) | stamped incidents only ([[sqlite-schema]]) |
| per-session manifest line beside `--pcap-dir` / `--eapol-dir` files | `loc` | files an alert wrote, stamped ([[pcap-export]] §5) |
| `sloth.db` `device_positions`, `sensor_positions` | one row per sample | `--gps` with a fresh fix, and `--db` |
| JSONL `sensor_health` | `gps_state`, `gps_src`, `gps_fix_age_s`, `gps_quality`, `gps_sats`, `gps_hdop`, `gps_sentences`, `gps_bad_checksum`, `gps_parse_errors`, `gps_reconnects`, `gps_positions_dropped`, `gps_err` | `--location` or `--gps` given |
| TUI alert detail | `Location:` line | `--location` or `--gps` given |
| TUI interface view health strip | `gps fix 9sat`, `gps stale 45s`, `gps searching (using --location)`, `err ...` | `--location` or `--gps` given |
| slothweb | the alert page's "where the sensor was", the drawer's scatter, `/api/positions` JSON / GeoJSON / GPX | sloth.db v9 or a stream carrying `loc` ([[slothweb]]) |

A **classic pcap has no field for a location**, so a capture's
position lives in its manifest line, which also carries its SHA-256.

**Sampling** (`src/position_track.c`). Each tick with a fresh GPS fix,
for every device heard in the last two seconds, a sample is queued
when the fix has moved `gps.min_move_m` (5 m) since that device's last
sample or `gps.sample_s` (60 s) have passed; the sensor's own track on
the same rule. Nothing is sampled from `--location` alone (every row
would repeat it) or without `--db` to drain the queue. The queues are
bounded (2048 device samples, 256 track points); a full queue drops
its oldest sample and counts it in `gps_positions_dropped`. Both
tables are in the observation retention tier (1x `db.retain_days`).

## Privacy

A position track is personal data about whoever carries the sensor,
and a device sample series says where a person's phone was heard. All
of it stays on the sensor: the forensic log and the manifests are
created 0600, `sloth.db` is the operator's file, and slothweb serves it
only to its own page under its ACL. Nothing about a position is sent
off the host; the one byte stream this feature sends at all is the
`?WATCH` line to gpsd, loopback unless `--gps-allow-remote` says
otherwise. Run without the flags and no position exists anywhere.

## Deployment

The shipped unit has `PrivateDevices=true` (no serial devices) and no
IP socket family, so `--gps` needs the opt-in drop-in
`sloth-sensor.service.d/gps.conf`, installed inert by
`make install-service` ([[deployment]] §7.2): `PrivateDevices=false`,
`DevicePolicy=closed`, `DeviceAllow=/dev/ttyACM0 r` and
`SupplementaryGroups=dialout` for a serial receiver, or
`RestrictAddressFamilies=AF_INET AF_INET6` for gpsd. `--location`
needs nothing.

## Related pages

- [[cli-reference]] — the four flags, the three `gps.*` knobs and the
  exit-2 refusals.
- [[jsonl-schema]] — `loc` on the alert records and `gps_*` in
  `sensor_health`.
- [[sqlite-schema]] — schema v9, the v8 → v9 step and the two position
  tables.
- [[pcap-export]] — the manifest line's `loc`.
- [[deployment]] — the `gps.conf` drop-in.
- [[slothweb]] — the alert page, the drawer's scatter and
  `/api/positions`.
