---
title: The sensor is two daemons, sloth-wifi and sloth-rf, in one repository
date: 2026-11-15
status: Accepted
authority: owner rulings of 2026-11-14 and 2026-11-15, recorded on #211
---

# ADR 0010 — The sensor is two daemons, sloth-wifi and sloth-rf, in one repository

## Context

sloth is one binary and one process. Its original mission is the IP
capture, the 802.11 monitor radio and BLE. Since 2026-10-27 it has also
grown readers for a GNSS receiver (`--gps`), an ADS-B decoder
(`--adsb`), an APRS decoder (`--aprs`) and rtl_433's event log
(`--rtl433`). Each of those is already a module of its own (a reader
thread, a module lock, a `*_health_poll()`), but everything around them
exists once: `sloth_state_t`, the `src/poll.c` stage table, the alert
engine, the JSONL writer and its data socket, the database handle and
the `sensor_health` record. A restart, a crash or a stall of the Wi-Fi
monitor therefore stops the SDR decoders' records too, and the other way
round.

The owner wants the SDR decoders to run independently of the Wi-Fi
monitor. The measured coupling this decision cuts is
[the RF split inventory](../architecture-rf-split.md); the plan and its
slices are tracked on #211 (slices #212 to #217).

## Decision

**One binary becomes two daemons, in this repository.**

- **`sloth-wifi`** keeps the original mission: IP, 802.11 and BLE. It is
  today's `sloth`, renamed, with `sloth` kept as a symlink for a
  release. Its unit keeps its name, `sloth-sensor.service`.
- **`sloth-rf`** carries ADS-B, APRS, rtl_433, the GNSS records and
  alerts and, later, Meshtastic. Its unit is the new `sloth-rf.service`.
- **BLE stays in sloth-wifi; Meshtastic belongs to sloth-rf.**
- **GNSS is one shared gpsd reader linked into both daemons.** sloth-wifi
  uses it for location stamps, `device_positions`, the twin rules'
  motion suppression, its GNSS view and the `loc_*` members of
  `sensor_health`. sloth-rf owns the `gnss_fix`, `gnss_sky` and
  `gnss_sat` records, the `gnss_*` tables and the `GNSS_*` alerts. A
  host with a serial GPS and both daemons must use gpsd, because a
  serial device opens once. A GPS-only host that wants the GNSS tab and
  alerts runs sloth-rf with just `--gps`.
- **sloth-rf has its own store and its own data socket.**
  `/var/lib/sloth-rf/sloth-rf.db` has the same DDL and the same
  `DB_SCHEMA_VERSION` as `/var/lib/sloth/sloth.db`;
  `/run/sloth-rf/sloth-rf.sock` stands beside `/run/sloth/sloth.sock`.
- **One slothweb reads both daemons.**
- **Inputs.** sloth-wifi: the capture, the monitor radio, BLE.
  sloth-rf: `--adsb`, `--aprs`, `--aprs-freq`, `--aprs-silent-hours`,
  `--rtl433`.
- **Alerts.** sloth-rf: `GNSS_*`, `ADSB_EMERGENCY`, and
  `SENSOR_SOURCE_DOWN` / `SENSOR_UNDERVOLT` for its own sources.
  sloth-wifi: everything else.
- **sloth-rf is headless first.** slothweb is its UI; the ADS-B terminal
  view retires at cutover.
- **The stream goes to `SLOTH_JSONL_VERSION` 2.0.0 at cutover**, with the
  owner's sign-off as [ADR 0007](0007-versioning.md) requires for a
  MAJOR bump.

Unchanged for both daemons:

- **`MISSION.md` §2.** Neither daemon transmits.
- **[ADR 0009](0009-fleet-monitor-only.md).** Both daemons' rows pass the
  same allow-list; rtl_433 stays withheld from the fleet (fail closed,
  until the owner classifies it); one slothweb means one host identity.

Relation to the other records:

- **Orthogonal to [ADR 0001](0001-three-repos.md) and #184.** That
  programme splits repositories (sensor, dashboard, intelligence); this
  one splits the sensor process, inside this repository.
- **[ADR 0005](0005-no-runtime-dependency.md) is about other
  components** (`sloth`, `sloth-dash`, `sloth-comintd`; #184 §2,
  decision 5) and #211 does not extend it. What #211 rules has the
  same effect between the two daemons, and is recorded as a
  consequence below, not as a decision of its own.

Not in this programme (#211): a Meshtastic decoder, a sloth-rf terminal
UI, an rtl_433 table in the database, fleet classification of rtl_433
or APRS.

Not decided by #211, found while measuring the tree
([inventory](../architecture-rf-split.md) §9, items 1 to 3):

- Whether sloth-wifi keeps reporting a GNSS source row
  (`SYS_SRC_GNSS`, the GNSS row of `s->sensors[]`) and
  `sensor_health`'s `gps_*` / `gnss_*` members, or only the `loc_*`
  ones #211's table names. OPEN — needs owner ruling.
- Which daemon writes `sensor_positions`. #211 names `device_positions`
  (sloth-wifi) and the `gnss_*` tables (sloth-rf); the sensor's own
  track is written by the same module as `device_positions` and is in
  neither list. OPEN — needs owner ruling.
- Whether `SENSOR_UNDERVOLT`, which reports the host and not a source,
  fires from both daemons on a host that runs both. #211 gives sloth-rf
  the two `SENSOR_*` alerts "for its own sources" and sloth-wifi
  "everything else". OPEN — needs owner ruling.

Not decided by #211, and not from the inventory (found while writing
this record):

- How long the `sloth` symlink stays. #211 says "for a release" and
  names no version. OPEN — needs owner ruling.

## Consequences

Accepted:

- A host that wants both halves runs two units and two processes; a
  host with only SDRs, or only a GPS, runs sloth-rf alone.
- Neither daemon needs the other at run time. This is derived from the
  rulings, not ruled in its own words: each has its own unit, store and
  socket, and each links its own copy of the gpsd reader rather than
  asking the other for a position.
- sloth-rf needs its own `--gps` / `--location`: the APRS region check
  reads the position, and after the split that position is its own
  reader's, not sloth-wifi's.
- A serial GPS shared by both daemons goes through gpsd.
- slothweb, which assumes one socket and one database throughout, has to
  learn a second source before sloth-rf's records reach a page (#214).
  Feeding a second stream into today's pipeline would blank the rtl_433
  tab, clear the sensor position, race the metrics writer and reset
  open incidents on every connect.
- The RF records and the RF members of `sensor_health` leave
  sloth-wifi's stream at cutover, which is why the contract version
  moves to 2.0.0 rather than a MINOR.
- The ADS-B terminal view is gone at cutover; the aircraft table is read
  in slothweb.
- The two stores share one DDL and one `DB_SCHEMA_VERSION`, so a schema
  bump and its migration (owner ruling 2026-10-21) apply to both files.
- Anything that names `/usr/local/bin/sloth` keeps working through the
  symlink for a release, and has to be moved before the symlink goes.

## Related pages

- [ADR index](README.md)
- [RF split inventory](../architecture-rf-split.md) — the measured coupling this decision cuts, and the slice table.
- [ADR 0001 — three repositories](0001-three-repos.md) — the other split, of repositories.
- [ADR 0005 — no run-time dependency](0005-no-runtime-dependency.md)
- [ADR 0007 — versioning](0007-versioning.md) — the sign-off the 2.0.0 bump needs.
- [ADR 0009 — fleet sharing carries monitor data only](0009-fleet-monitor-only.md)
