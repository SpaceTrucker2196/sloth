---
name: adsb
description: ADS-B aircraft (#26 slice 1) — --adsb tails the aircraft.json a local readsb / dump1090-fa decoder already writes, or reads its SBS / BaseStation TCP output read-only; the parser, the aircraft table, freshness and expiry, the adsb sensor, the adsb_* sensor_health fields and the change-only adsb_aircraft record with its altitude bands and position cells
type: reference
---

# ADS-B aircraft (`--adsb`, `adsb_aircraft`)

**Summary**: `--adsb SPEC` points sloth at the `aircraft.json` that a
local, already-running Mode S / ADS-B decoder (readsb, dump1090-fa)
writes, and turns it into typed rows: one per address the decoder
lists, with callsign, squawk, emergency status, category, altitude,
speed, track, rates, position, RSSI and message count. sloth **never
opens, tunes or talks to the SDR**. The source is a file it re-reads
about once a second, using no network, or (2026-11-09) the decoder's
SBS / BaseStation output on a loopback TCP port, read by a client that
never writes a byte to the socket. Slice 1 is the core only:
the parser, the table, the source's health in the sensor registry and
`sensor_health`, and the change-only `adsb_aircraft` JSONL record; the
`[^]` TUI view, slothweb's tab and the `--db` tables followed, then
one alert rule, `ADSB_EMERGENCY` (#186): an emergency squawk or status,
flag only. `sbs://` input closed the family's last open item.

**Sources**: `src/adsb.h`, `src/adsb.c` (parser, spec, table, bands,
signature), `src/capture/adsb_reader.h`, `src/capture/adsb_reader.c`
(the per-poll file read), `include/sloth.h` (`adsb_aircraft_t`,
`adsb_health_t`), `src/poll.c` (`adsb_health_poll()` in the health
stage, `SENSOR_ADSB` in the sensors stage), `src/jsonl.c`
(`jsonl_emit_adsb()`, the `adsb_*` appends in
`jsonl_emit_sensor_health()`), `src/main.c` (`--adsb`); tests
`tests/test_adsb.c`, `tests/fuzz/fuzz_adsb_doc.c`; the alert
`src/alerts/rules_adsb.c`, `tests/test_adsb_rules.c`,
`research/adsb/emergency-squawks.md`; for `sbs://`
`tests/fuzz/fuzz_adsb_sbs.c` and the SBS cases in the three test files.
Format references: readsb's `README-json.md` (wiedehopf/readsb;
dump1090-fa documents the same `aircraft.json`); for SBS, readsb's own
writer, `modesSendSBSOutput()` in `net_io.c` (read at bf8f8fd), its
heartbeat (`sbs_heartbeat`, `MODES_NET_HEARTBEAT_INTERVAL` 60 s), and
its idle rule (`serviceReconnectCallback()`), which drops a silent peer
only on readsb's own outbound connectors that expect an inbound
heartbeat - the SBS output expects none, so a client that never writes,
as sloth's never does, is not dropped. That function cites the BaseStation socket-data reference
it was checked against (`Barebones42_Socket_Data.htm`); that page was
**not** read first-hand here, only through readsb's code, and the live
readsb 3.16 on the reference host's port 30003 was looked at to
confirm the shape.

**Last updated**: 2026-11-09 (#186: `--adsb sbs://`, the decoder's SBS output, loopback, read-only; the `AF_INET` drop-in note); 2026-11-08 (#186: `ADSB_EMERGENCY`, flag only; slothweb's ADS-B tab marks an aircraft with an open one; the `packaging/` note on `/run/readsb`); 2026-11-07 (the `[^]` TUI aircraft view, the `adsb` health-strip token, and `gps_bearing_deg()` beside `gps_distance_m()`); 2026-11-05 (`--db`: schema v12, `adsb_aircraft` and `adsb_sightings`; slothweb's "aircraft seen" history and each aircraft's recorded track and altitude profile); 2026-11-05 (slothweb: the ADS-B tab and `/api/adsb`, `web/src/web_adsb.c`, `web/ui/adsb.js`); 2026-11-05 (review: a file already stale when first read is `stale` and takes no rows; the help names `beast://`); 2026-11-05 (slice 1 shipped: feed, state, JSONL).

---

## Where it sits against the seven questions

[[non-ip-sensors]] asks every family seven questions. Slice 1's answers:

1. **Observable passively**: what the decoder already decoded from
   1090 MHz Mode S / ADS-B (and, for readsb, MLAT and TIS-B) — the
   records in `aircraft.json`, or the lines on its SBS port.
2. **Hardware**: an RTL-SDR (or similar) on 1090 MHz feeding readsb or
   dump1090-fa, which the operator runs; sloth needs only the file or
   the port.
3. **State**: `adsb_aircraft_t` keyed by (24-bit address, non-ICAO
   flag), and `adsb_health_t` (`include/sloth.h`).
4. **View**: the `[^]` TUI view (below) and slothweb's ADS-B tab (below).
5. **JSONL / --db**: `adsb_aircraft`, plus `adsb_*` fields on `sensor_health`;
   with `--db`, the `adsb_aircraft` and `adsb_sightings` tables (v12, below)
   and a `sensor` record of kind `adsb`.
6. **Out of scope**: transmitting or interrogating (active radar),
   driving the SDR, writing anything to the decoder, a non-loopback
   SBS source, and Beast (`beast://` is refused as "not yet
   supported").
7. **Testing**: hand-written JSON documents from `README-json.md`
   (`tests/test_adsb.c`), SBS lines written from readsb's
   `modesSendSBSOutput()`, a temporary file and a loopback listener of
   the test's own for the reader, two libFuzzer harnesses; no captured
   `aircraft.json` and no recorded SBS stream.

## The source

`--adsb /run/readsb/aircraft.json` or
`--adsb file:///run/readsb/aircraft.json`. Only an absolute local path:
`file://HOST/...`, a relative path, any other scheme and a trailing `/`
exit 2. `beast://` exits 2 with "not yet supported"; `sbs://` is its own
source (next section). Refused with `--replay` (a savefile is not a live decoder). The file need not
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

## The SBS source (`sbs://`)

`--adsb sbs://127.0.0.1:30003` (or `sbs://`, the same; `sbs://[::1]:PORT`
for IPv6). `HOST` must be a numeric loopback address (`127.0.0.0/8`,
`::1`): a name, a routable address (exit 2, "not loopback") or a port
outside 1..65535 is refused. The decoder is local, as the file one is;
reading a remote decoder is a later decision with its own flag, as
`--gps-allow-remote` is for gpsd, not a default. On startup sloth
announces on stderr that it will connect, to where, and that it sends
nothing (MISSION.md §2: a network-using input is opt-in and
announced).

**Read-only.** The worker (`src/capture/adsb_reader.c`), started after
the privilege drop, makes a non-blocking connect bounded at 3 s and
then only reads: no `send()`, `write()` or `shutdown()` is ever called
on the socket (the connect's handshake is the only thing sloth's side
puts on it). readsb's SBS output ignores what a client sends anyway
(`READ_MODE_IGNORE`). `tests/test_adsb.c ::
test_sbs_reader_session` pins that nothing arrives at the listener.

**Reconnect.** A refused or timed-out connect is a read error (`adsb_err`
"connect: ..."), retried after 2 s, doubling to 30 s while it keeps
failing. A session the decoder closes ("decoder closed the connection")
or a read error is a read error, retried after 2 s. A successful
connect clears the error. Rows stand until they expire, as they do when
`aircraft.json` goes missing.

**Framing.** CRLF-ended lines (a bare LF is taken too), at most
`ADSB_SBS_MAX_LINE` (512) bytes; readsb's are under 260 even with its
extra fields. A partial line waits for the next read. A longer line is
one parse error and is discarded up to its newline, however many reads
it spans. The main thread never touches the socket.

**The line** (`adsb_sbs_parse()`), per readsb's writer: 22 comma-separated
fields, 24 with `--sbs-extra-fields`; anything else is malformed.

| Field | Content | Kept as |
|---|---|---|
| 0 | `MSG` (the other BaseStation records `SEL`, `ID`, `AIR`, `STA`, `CLK` are ignored, not errors; readsb sends none) | - |
| 1 | transmission type 1..8 | the line's type; outside 1..8 is malformed |
| 4 | hex ident, 6 hex digits, `~` prefix for a non-ICAO address | the row key (address, non-ICAO), as `hex` |
| 6, 7 | date and time generated, `YYYY/MM/DD`, `HH:MM:SS.mmm`, UTC | the message time (below) |
| 10 | callsign, 8 characters space padded | `flight`, trimmed |
| 11 | altitude, ft; a trailing `H` is GNSS | `alt_baro`, or `alt_geom` with `H` |
| 12, 13 | ground speed kt, track deg | `gs`, `track` |
| 14, 15 | lat, lon | the position, only as a pair inside ±90 / ±180 |
| 16 | vertical rate ft/min; `H` is GNSS | `baro_rate`, or `geom_rate` with `H` |
| 17 | squawk, 4 digits | `squawk`, only as 4 octal digits |
| 18, 19, 20 | squawk-change alert, squawk emergency, SPI flags | not kept (below) |
| 21 | on ground, `-1` ground / `0` airborne | `on_ground`; a barometric altitude on a ground line is dropped, as aircraft.json's `"ground"` is |
| 22, 23 | RSSI dBFS, category (`A3`), extra fields only | `rssi`, `category` |

readsb fills only what each message carried (1 identification, 2
surface position, 3 airborne position, 4 velocity, 5 surveillance
altitude, 6 surveillance identity, 7 air-to-air, 8 all-call). A number
or date that does not parse is malformed; a well-formed value out of
range leaves its field absent, as in `aircraft.json`. Numbers are
walked digit by digit, never `strtod()`. A malformed line is counted in
`adsb_parse_errors` and sets `adsb_err` until the next good line; it
never stops the reader.

**Merge.** Every MSG line goes through the same sticky merge as an
`aircraft.json` entry, into the same table under the same 256-row cap
and the same expiry. So an MSG,3 position and an MSG,1 callsign for one
address make **one row**, and an empty field never clears a kept one.
The row's `seen` is the read time minus the line's generated time
(never negative; 0 without a time), so `last_seen`, `last_mono_ms`,
the expiry and `ADSB_EMERGENCY`'s hold all run on the aircraft's
message time exactly as they do from `aircraft.json`'s `seen`. A
decoder replaying hour-old lines therefore makes rows that expire on
the next poll.

**What SBS does not carry, and the mapping chosen:**

- **No emergency status word.** Field 19 is a flag, and readsb sets it
  from the 7500 / 7600 / 7700 squawk on the same line (or passes
  another SBS feed's flag through); on MLAT lines readsb reuses fields
  18 and 19 for the receiver count and error estimate. So the flag is
  not read: the squawk is the evidence, and `ADSB_EMERGENCY` fires on
  it as it does for `aircraft.json` (`tests/test_adsb_rules.c ::
  test_sbs_emergency_squawk_fires`). An SBS row's `emergency` stays
  absent - "general" would claim a DO-260B status the aircraft never
  sent - so the view's `emerg` count and the status-word form of the
  rule never see SBS rows. A flag of -1 on an ordinary squawk fires
  nothing (`test_sbs_flag_alone_does_not_fire`).
- **No RSSI** unless readsb runs with `--sbs-extra-fields`.
- **No per-aircraft message count.** A row's `messages` counts the MSG
  lines sloth received for it, and `adsb_messages` the MSG lines in
  all, not the decoder's lifetime Mode S count.
- **No `type`** (`adsb_icao`, `mlat`, ...): `source_type` is written `""`.
- **No airborne transition without an altitude**: a row on the ground
  becomes airborne when a barometric altitude arrives.

**Freshness** for a stream is a line arriving, any line, readsb's
heartbeat (`\r\n` alone, every 60 s to an idle client) included: so an
empty sky stays `live`. `stale` is no line for `ADSB_SBS_STALE_S`
(130 s, past two of readsb's 60 s heartbeat intervals):
connected, but the decoder is hung. `waiting` is configured with no
line yet; `error` as for the file. `adsb_reads` counts MSG lines, and
the `[^]` header labels it `lines` instead of `docs`.

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

For `sbs://` the clock is a line arriving, and `live` lasts 130 s, not
10 (the SBS section above).

The registry's `adsb` sensor (name "ADS-B decoder", iface the source
label `file:/path` or `sbs:127.0.0.1:30003`, `observed` the documents parsed) reads `error` for
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

## The `[^]` TUI view

`[^]` draws the table (`src/views/adsb.c`,
[`docs/views/adsb.md`](../views/adsb.md) has the mockup and the
column notes): one row per address, **freshest first** by the
decoder's own last-heard time with the address as the tie-break, over
a header of the decoder's state, the aircraft count, the aircraft
reporting an `emergency`, the decoder's lifetime message total, how
long since its clock last advanced, the source label and the read /
parse / overflow / bad / expired tallies. Columns: ICAO, callsign,
squawk, altitude (barometric, else geometric, else `ground`), ground
speed, track, RSSI, age, and a width-flexing RSSI bar over -30..0
dBFS. A row the decoder still lists but has not heard from for 30 s or
more is dim. The cursor follows the aircraft across the re-sort, not
the row index. The key is `^` because every letter and digit already
selects a view, `*` is BLE and `#` is GNSS.

**Distance and bearing are drawn only when the sensor's own position
is known** — `gps_location_current()` returning a stamp, so a
`--location` or a fresh `--gps` fix. Range is `gps_distance_m()` in
kilometres and direction `gps_bearing_deg()` (added beside it,
2026-11-07: the initial great-circle bearing in degrees true, with
identical, antipodal and dateline-crossing pairs pinned in
`tests/test_gps.c`). Without a sensor position the two columns are
absent rather than drawn empty, and the legend says why; with one, a
row the decoder has sent no position for reads `-` in both while the
columns stand, because what is missing there is the aircraft's
position and not the sensor's.

The view is **observation**: it grades nothing and counts the
`emergency` rows rather than judging them. `--adsb` also adds an
`adsb` token to the Interfaces health strip beside `gps` — opt-in,
the state always, the aircraft count while live, the stalled age and
the reader's error on fault — because a feed that stopped looks the
same as quiet sky at the terminal.

## `ADSB_EMERGENCY` (#186)

An aircraft listed while the source is `live` with squawk **7500**,
**7600** or **7700** (SERA.13005: unlawful interference,
radio-communication failure, emergency), or an emergency/priority status
other than `none` (`general`, `lifeguard`, `minfuel`, `nordo`,
`unlawful`, `downed`, `reserved`), raises `ADSB_EMERGENCY`
(`src/alerts/rules_adsb.c`). One incident per address and condition -
the code when there is one, else the status word - so a code change
re-fires and a steady one does not. LOW on first sight, WARN once the
condition has held `adsb.emerg_hold_s` (10 s) of the aircraft's own
message time, never CRIT.

**Flag only.** sloth surfaces the declaration and never acts on it. It
is a third party's state, not the operator's network's, and ADS-B is
unauthenticated: a false alarm can be injected (Schäfer et al. 2013
§3.2) and one receiver cannot tell it from a real one. The view above
still counts emergency rows without judging them; the judgement is the
rule's. Basis and the persistence argument: [[alerts]] § ADS-B,
`research/adsb/emergency-squawks.md`, and the assessment
`alert-assessments/ADSB_EMERGENCY.md`.

## Running beside readsb under systemd

No unit change: `sloth-sensor.service`'s `ProtectSystem=strict` leaves
`/run` readable, and the reference host's readsb leaves `/run/readsb`
0755 and `aircraft.json` 0644 (checked 2026-11-08), so the `sloth` user
reads it. Add `--adsb /run/readsb/aircraft.json` to `SLOTH_ARGS` in
`/etc/default/sloth` (`packaging/default/sloth` says the same). A
decoder writing under `/home` would need `ProtectHome=` relaxed in a
drop-in.

`sbs://` **does** need a unit change: the shipped unit's
`RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET` has no IP
family, so the connect fails with `socket: Address family not
supported by protocol` (a read error, retried) until a drop-in adds
`RestrictAddressFamilies=AF_INET` (`AF_INET6` too for `[::1]`). The
lists merge, so it widens the unit by exactly that. The `gps.conf`
drop-in's commented gpsd block is that line
(`packaging/systemd/sloth-sensor.service.d/gps.conf`, installed inert
at `/usr/local/share/sloth/sloth-sensor-gps.conf`); uncommented and
copied to `/etc/systemd/system/sloth-sensor.service.d/`, it serves
`--adsb sbs://` as well. The unit sets no `IPAddressDeny=`, so nothing
else is needed. `packaging/default/sloth` says the same.

## Pending (later slices)

Beast (`beast://`) socket input; an opt-in for a non-loopback SBS
source.

## Related pages

- [[non-ip-sensors]] — the family roadmap and the seven questions.
- [[jsonl-schema]] — the `adsb_aircraft` record and `sensor_health`'s `adsb_*` fields.
- [[cli-reference]] — `--adsb`.
- [[gnss]] / [[location]] — the GPS family this one follows.
