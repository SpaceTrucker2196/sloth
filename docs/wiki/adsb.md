---
name: adsb
description: ADS-B aircraft (#26 slice 1) — --adsb tails the aircraft.json a local readsb / dump1090-fa decoder already writes; the parser, the aircraft table, freshness and expiry, the adsb sensor, the adsb_* sensor_health fields and the change-only adsb_aircraft record with its altitude bands and position cells
type: reference
---

# ADS-B aircraft (`--adsb`, `adsb_aircraft`)

**Summary**: `--adsb SPEC` points sloth at the `aircraft.json` that a
local, already-running Mode S / ADS-B decoder (readsb, dump1090-fa)
writes, and turns it into typed rows: one per address the decoder
lists, with callsign, squawk, emergency status, category, altitude,
speed, track, rates, position, RSSI and message count. sloth **never
opens, tunes or talks to the SDR** and uses **no network**: the source
is a file it re-reads about once a second. Slice 1 is the core only:
the parser, the table, the source's health in the sensor registry and
`sensor_health`, and the change-only `adsb_aircraft` JSONL record. No
TUI view, no slothweb tab, no alert rule and no `--db` table yet.

**Sources**: `src/adsb.h`, `src/adsb.c` (parser, spec, table, bands,
signature), `src/capture/adsb_reader.h`, `src/capture/adsb_reader.c`
(the per-poll file read), `include/sloth.h` (`adsb_aircraft_t`,
`adsb_health_t`), `src/poll.c` (`adsb_health_poll()` in the health
stage, `SENSOR_ADSB` in the sensors stage), `src/jsonl.c`
(`jsonl_emit_adsb()`, the `adsb_*` appends in
`jsonl_emit_sensor_health()`), `src/main.c` (`--adsb`); tests
`tests/test_adsb.c`, `tests/fuzz/fuzz_adsb_doc.c`. Format reference:
readsb's `README-json.md` (wiedehopf/readsb; dump1090-fa documents
the same `aircraft.json`).

**Last updated**: 2026-11-05 (`--db`: schema v12, `adsb_aircraft` and `adsb_sightings`; slothweb's "aircraft seen" history and each aircraft's recorded track and altitude profile); 2026-11-05 (slothweb: the ADS-B tab and `/api/adsb`, `web/src/web_adsb.c`, `web/ui/adsb.js`); 2026-11-05 (review: a file already stale when first read is `stale` and takes no rows; the help names `beast://`); 2026-11-05 (slice 1 shipped: feed, state, JSONL).

---

## Where it sits against the seven questions

[[non-ip-sensors]] asks every family seven questions. Slice 1's answers:

1. **Observable passively**: what the decoder already decoded from
   1090 MHz Mode S / ADS-B (and, for readsb, MLAT and TIS-B) — the
   records in `aircraft.json`.
2. **Hardware**: an RTL-SDR (or similar) on 1090 MHz feeding readsb or
   dump1090-fa, which the operator runs; sloth needs only the file.
3. **State**: `adsb_aircraft_t` keyed by (24-bit address, non-ICAO
   flag), and `adsb_health_t` (`include/sloth.h`).
4. **View**: slothweb's ADS-B tab (below); no TUI view yet (pending).
5. **JSONL / --db**: `adsb_aircraft`, plus `adsb_*` fields on `sensor_health`;
   with `--db`, the `adsb_aircraft` and `adsb_sightings` tables (v12, below)
   and a `sensor` record of kind `adsb`.
6. **Out of scope**: transmitting or interrogating (active radar),
   driving the SDR, SBS / Beast network feeds (slice 1 refuses
   `sbs://` and `beast://` as "not yet supported").
7. **Testing**: hand-written JSON documents from `README-json.md`
   (`tests/test_adsb.c`), a temporary file for the reader, a libFuzzer
   harness; no captured `aircraft.json`.

## The source

`--adsb /run/readsb/aircraft.json` or
`--adsb file:///run/readsb/aircraft.json`. Only an absolute local path:
`file://HOST/...`, a relative path, any other scheme and a trailing `/`
exit 2. `sbs://` and `beast://` exit 2 with "not yet supported". Refused
with `--replay` (a savefile is not a live decoder). The file need not
exist at startup: a decoder starting after sloth is normal, and reads
as the `error` state until it appears.

The decoder writes the file to a temporary name and renames it over the
old one about once a second (README-json.md), so a reader never sees a
half-written document. The reader (`src/capture/adsb_reader.c`), a
worker started after the privilege drop, therefore **opens the path
afresh every `ADSB_POLL_MS` (1 s)** — a descriptor kept open would keep
reading the replaced inode — `fstat()`s it, refuses anything that is
not a regular file or is over `ADSB_MAX_DOC` (2 MiB), reads it whole and
parses it. A file whose device, inode, size and mtime are all unchanged
since the last read is not parsed again: the decoder has not written.
`O_RDONLY | O_NONBLOCK`: a FIFO placed at the path cannot hang the
worker, and is refused as not a regular file.

## The parser

`adsb_doc_parse()` reads one document: top-level `now`, `messages` and
`aircraft[]`; anything else is skipped. Per aircraft it keeps `hex`
(6 hex digits; a leading `~` is a non-ICAO address such as TIS-B, kept
and flagged, a separate key from the same 24 bits without it), `type`,
`flight` (trailing spaces trimmed; all-blank or over 8 characters is
absent), `squawk` (exactly four octal digits), `alt_baro` (feet, or the
string `"ground"`), `alt_geom`, `gs`, `track`, `baro_rate`,
`geom_rate`, `lat` / `lon` (only as a pair inside ±90 / ±180),
`category` (`A0`..`D7`), `emergency` (one of `none`, `general`,
`lifeguard`, `minfuel`, `nordo`, `unlawful`, `downed`, `reserved`),
`seen`, `seen_pos`, `rssi`, `messages`. A `null`, a value of the wrong
type or one out of range leaves the field absent. Nested arrays and
objects (`mlat`, `tisb`, `nav_modes`, `acas_ra`, `lastPosition`, ...)
are skipped by depth, so `lastPosition`'s stale coordinates are never
taken for the aircraft's. Numbers are walked digit by digit, never
`strtod()` (LC_NUMERIC; the TUI calls `setlocale()`).

Bounds: a document over 2 MiB is a read error. At most
`ADSB_MAX_AIRCRAFT` (256) aircraft are kept; entries past that are
still parsed (the document must balance) and counted in
`adsb_overflow`. An entry with no or a bad `hex`, or one that is not an
object, is counted in `adsb_bad_entries`. A malformed document is
refused whole and counted in `adsb_parse_errors`, once per distinct
file, and the table stands as it was.

## The table, freshness and expiry

Rows are keyed by (address, non-ICAO). The merge is **sticky**: a key
the newest document carries overwrites the row, a key it omits keeps
the row's last value — the decoder already ages its own fields, and a
key flickering out of one document is not news. `first_seen` is the
wall time of the first document that listed the row; `last_seen` is the
read time minus the aircraft's `seen`, so an aircraft the decoder still
lists but last heard 50 s ago is 50 s old here too; `pos_ts` likewise
from `seen_pos`.

**Expiry**: a row unheard for `ADSB_EXPIRE_S` (60 s, the window in
which readsb keeps an aircraft in `aircraft.json` at all) is retired,
on sloth's monotonic clock, in the poll's health stage, and reported
once as `"state":"gone"`. A table full at 256 rows refuses a new
address and counts it in `adsb_overflow`. **A stale file at startup
takes no rows**: an unchanged file is never re-read, so without this
the aircraft a hung decoder last listed would each be written as
`live` (with `last_seen` read time minus `seen`, hours wrong) and
`gone` a minute later. Its rows come in with the first document whose
clock has moved.

**Freshness** is the decoder's own clock: the document's `now` (or,
in a document without one, the file's mtime) moving forward. States:

| `adsb_state` | Meaning |
|---|---|
| `waiting` | configured; no document parsed yet and no failure |
| `live` | the decoder's clock advanced within `ADSB_STALE_S` (10 s); the first document counts as an advance when its clock is at most 10 s behind the host's |
| `stale` | it has not for longer: the file is readable but the decoder stopped writing. Also a first document already more than 10 s old: a decoder that hung before sloth started (`adsb_age_s` -1) |
| `error` | the last attempt failed: missing or unreadable file, not a regular file, over 2 MiB, malformed. Clears on the next good document |

The registry's `adsb` sensor (name "ADS-B decoder", iface the source
label `file:/path`, `observed` the documents parsed) reads `error` for
`stale` and `error`, `active` once a document has parsed, `present`
before.

## JSONL: `adsb_aircraft`

One record per aircraft row, keyed by `hex` (`~`-prefixed for a
non-ICAO address). Written on first sight, on a **meaningful** change,
on the 300 s heartbeat while listed, and once as `"state":"gone"` on
expiry. **Never once a second**: the signature (`adsb_row_sig()`) takes
the identity, `first_seen` (a row that expired and came back is new),
the held altitude band, the held position cell, whether there is a
position, squawk, emergency, callsign and category — never the raw
altitude, position, speed, track, rates, RSSI, `seen` or message count,
each of which moves every second. `source_type` is written, not signed:
readsb's best source flips between `adsb_icao`, `mlat` and `mode_s` as
coverage comes and goes.

**Altitude bands** (`alt_band`; barometric altitude, else geometric):

| Band | Altitude |
|---|---|
| -2 | on the ground (`alt_baro` `"ground"`) |
| -1 | unknown |
| 0..9 | below 9,750 ft: `floor((alt + 250) / 1000)`, one band per 1,000 ft with edges at x,750 ft (below -250 ft is 0) |
| 10.. | from 9,750 ft: `10 + (alt - 9750) / 4000`, one band per 4,000 ft, edges at 13,750, 17,750, ... |

Every edge sits 250 ft from both the whole thousands (IFR levels) and
the x,500 levels (VFR cruising), where aircraft fly level for a long
time. On top of that the band is **held with 100 ft hysteresis**
(`ADSB_ALT_HYST_FT`): it moves only once the altitude is past the old
band's edge by 100 ft, so 25 ft altitude quanta dithering on an edge do
not write a line each. A jump of several bands, and to or from the
ground, moves at once. A climb from the ground to FL370 is about 15
records.

**Position cells**: 0.1° of latitude and of longitude (about 11 km of
latitude), held until the position leaves the held cell grown by
0.01° (about 1 km) on every side (`ADSB_CELL_HYST_DEG`). A jet at
cruise crosses a cell every one to two minutes.

So the rate is bounded by movement, not by the decoder's cadence: an
aircraft holding level and course in one cell is one record per 300 s
heartbeat. `tests/test_adsb.c` pins it: five documents with speed,
track, RSSI, message count and `now` moving every second, the altitude
wiggling ±25 ft and once 50 ft past an edge, the position moving inside
its cell — one record.

Fields: `hex`, `non_icao`, `state` (`live` / `gone`), `src` (the source
label), `source_type`, `flight`, `squawk`, `category`, `emergency` (`""`
when the decoder sent none), `on_ground`, `alt_baro`, `alt_geom` (ft,
each only when known), `alt_band`, `gs` (kt), `track` (°), `baro_rate`,
`geom_rate` (ft/min), `lat` / `lon` (five decimals) with `pos_ts`, `rssi`
(dBFS), `messages`, `first_seen`, `last_seen`. Absent figures are
omitted, never written as 0. Without `%f` (locale). Full row in
[[jsonl-schema]].

## `sensor_health`

Appended, and present **only** with `--adsb`: `adsb_state`, `adsb_src`,
`adsb_age_s` (since the decoder's clock last advanced, -1 never),
`adsb_last_read`, `adsb_aircraft` (rows now), `adsb_messages` (the
decoder's lifetime Mode S count), `adsb_reads`, `adsb_read_errors`,
`adsb_parse_errors`, `adsb_overflow`, `adsb_bad_entries`,
`adsb_expired`, `adsb_err`. The signature takes `adsb_state` and
none/some bands of the four tallies and of the error; the age, the
counts and the decoder's message total move every second and are
written, not signed.

## Privacy

The receiver's position is the operator's to protect: aircraft near the
receiver locate it roughly. The records go to the operator's own JSONL
sink only. Tests and documentation carry invented addresses, callsigns
and positions, never a receiver's.

## slothweb

The ADS-B tab (2026-11-05) reads the `adsb_aircraft` records and the
`adsb_*` block of `sensor_health` off the data socket and keeps them in
memory (`web/src/web_adsb.c`, `/api/adsb`): up to 512 rows, a gone row
kept dimmed for 600 s, a live row with no record for 660 s dropped as
aged, each row's last 32 positions as its track. The page
(`web/ui/adsb.js`) draws the decoder's health line, the aircraft table,
a north-up position plot with the tracks coloured by altitude (no map
tiles, nothing fetched) and a detail panel. Because the records are
change-only, a row's altitude and position are as of its last record:
within its band and cell, not the decoder's latest second. The SDR is a
passive radio, so the records are Monitor's, as BLE's are; under Local
the tab shows its scope note. Full description in
[`web/README.md`](../../web/README.md#ads-b).

## `--db`: `adsb_aircraft` and `adsb_sightings` (schema v12)

With `--db` and `--adsb`, `write_adsb()` (`src/db.c`) records the
aircraft on the record's own change-only rule (`adsb_row_sig()`, or the
300 s heartbeat), with its own change memory: one `adsb_sightings` row
per write (time, the decoder's last-heard time, callsign, squawk,
emergency, category, on-ground, both altitudes, band, speed, track,
vertical rate, position, RSSI, messages, source) and one upsert of the
`adsb_aircraft` inventory row for the address: earliest first seen,
latest last seen, `visits` (one more each time sloth's own `first_seen`
moves, i.e. the row expired and the address came back), `sightings`,
the newest non-empty callsign, squawk, category and source, the
altitude range, top ground speed, strongest RSSI, whether a position
or an emergency was ever reported. `adsb_sightings` is in the
observation tier, `adsb_aircraft` in the entity tier (3× retention).
The v11 → v12 step is a stamp; [[sqlite-schema]] has the columns.

slothweb reads them (`web/src/web_rfhist.c`, through the allow-list):
`/api/adsb/seen?days=&limit=&offset=&q=` the inventory rows last seen
in the window (7 days by default, up to 400; 100 a page; `q` a hex or
callsign prefix, letters and digits only) and
`/api/adsb/aircraft?hex=&days=` one aircraft's row and its sightings
(at most 400, oldest first, compact rows named in `cols`). The ADS-B
tab shows the first as the "aircraft seen" table and the second in the
detail panel: the inventory figures, every callsign and squawk it used,
an altitude profile over time (emergencies ringed), and the recorded
track dashed on the positions plot, also for an aircraft the decoder no
longer lists. Monitor's and Hybrid's, as the live panel is.

## Pending (later slices)

A TUI aircraft view, an emergency-squawk alert with its research
citation, SBS / Beast socket input.

## Related pages

- [[non-ip-sensors]] — the family roadmap and the seven questions.
- [[jsonl-schema]] — the `adsb_aircraft` record and `sensor_health`'s `adsb_*` fields.
- [[cli-reference]] — `--adsb`.
- [[gnss]] / [[location]] — the GPS family this one follows.
