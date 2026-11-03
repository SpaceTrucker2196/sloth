---
name: gnss
description: GNSS observation — what sloth records off the --gps receiver beyond its position (the satellites in view with their C/N0, the DOPs, the receiver's clock against the host's), the [#] view, the gnss_fix / gnss_sky / gnss_sat records, the v10 tables, slothweb's panel, the caveats, and the detector hooks left for the next slice
type: reference
---

# GNSS observation (`[#]`, `gnss_*` records, schema v10)

**Summary**: with `--gps` sloth already reads a receiver for *where it
is* ([[location]]). Since 2026-11-02 it also records *what the receiver
sees*, the way it records the Wi-Fi and Bluetooth air: one row per
satellite in view (constellation, svid, PRN, elevation, azimuth, C/N0,
used in the solution, health), the pass they came in (counts, DOPs,
the C/N0 mean / max / spread) and the newest fix (mode, status,
accuracy, speed, the receiver's time against the host's clock). It
surfaces as the `[#]` TUI view, three change-only JSONL records plus
five `sensor_health` fields, two `--db` tables (schema v10), the `gps`
sensor in the registry, and slothweb's GNSS tab. **Observation only**:
nothing here fires an alert; the detectors that will read this sky
(spoofing, jamming, time and position jumps) are a following slice,
and their inputs are kept now (below). **Receive-only** (MISSION §2):
the one `?WATCH` line to gpsd is unchanged, and a serial device is
never written to.

**Sources**: `src/gps.h`, `src/gps.c` (the parser's `satellites[]`,
GST, `gpsd_time_parse()`, the sky / fix state, `gps_gnss_*_sig()`),
`src/sloth_clock.c` (`sloth_wall_ms()`), `src/views/gnss.c`,
`src/jsonl.c` (`jsonl_emit_gnss()`, the `gnss_*` appends in
`jsonl_emit_sensor_health()`), `src/poll.c` (`SENSOR_GPS`), `src/db.c`
(`write_gnss()`), `src/db_schema.c` (v10), `web/src/web_gnss.c`,
`web/ui/gnss.js`; tests `tests/test_gps.c` ("GNSS observation"),
`tests/test_gnss_view.c`, `tests/test_db.c` (v9 → v10),
`web/tests/test_gnss.c`.

**Last updated**: 2026-11-02 (first version).

## What is read

Only gpsd's JSON carries the sky today. `gpsd_json_parse()` reads, on
top of the position fields [[location]] needed:

- **SKY**: `nSat`, `uSat`, `hdop` / `vdop` / `pdop` / `gdop` / `tdop`,
  and the `satellites[]` array — per entry `PRN` (always present),
  `gnssid`, `svid`, `sigid`, `el`, `az`, `ss` (C/N0 in dB-Hz), `used`,
  `health`. Up to `GNSS_MAX_SATS` (48) entries are kept; the rest are
  parsed, counted (`overflow`) and dropped, so a 50-object multi-GNSS
  SKY is still one well-formed line. gpsd's `gnssid` is 0 GPS, 1 SBAS,
  2 Galileo, 3 BeiDou, 4 IMES, 5 QZSS, 6 GLONASS, 7 NavIC (`gnss_name()`);
  an NMEA-only gpsd sends PRN alone, and the row then reads gnssid -1.
- **TPV**: `status`, `speed`, `track`, `climb`, `epv`, `leapseconds`,
  `jam` (the u-blox jamming indicator, when the driver reports it) and
  `time`, parsed by `gpsd_time_parse()` (strict
  `YYYY-MM-DDTHH:MM:SS[.fff]Z`, no `strptime`, no locale).
- **GST**: the pseudorange noise statistics (`rms`, the error ellipse,
  the lat / lon / alt sigmas). GST's `lat` / `lon` / `alt` are
  standard deviations in metres: the parser moves them out of the
  position fields so nothing can take a 2 m sigma for a latitude.

A serial `--gps /dev/tty…` run gets none of this yet: NMEA `GSV` is
not parsed (see *Not in this slice*), so the `[#]` view says it is
waiting for the receiver's first satellite list, and the position path
is unchanged.

## The clock offset, honestly

`time_off_ms` = the receiver's `time` − the host's `CLOCK_REALTIME`
(`sloth_wall_ms()`) at the moment the line was framed. That includes
the serial / USB transfer and gpsd's own latency, and there is no PPS
on a USB u-blox 7, so it is biased by tens to hundreds of
milliseconds and jitters. It is enough to see a multi-second step —
the host clock being wrong, or the receiver's time being moved — and
it is **not** a time-sync quality figure. gpsd's `TOFF` / `PPS`
objects would give a far better one, but they need
`?WATCH={"pps":true}`, a change to the one line sloth sends; that is
an owner ruling, not this slice's.

## The `[#]` view

Key `#` (every letter and digit is taken; `*` is BLE). Header: fix
mode, satellites used / in view, HDOP and PDOP (heat past 2 and 5),
accuracy, speed, the clock offset (heat past 500 ms and 2 s), the
source and the pass's age; a second line with the receiver's status
word, leap seconds, the jamming indicator (heat per u-blox `jamInd`
bands) and the C/N0 mean / max, GST rms when present. The table is
one row per satellite sorted by C/N0, strongest first, untracked rows
last: constellation, svid, PRN, elevation, azimuth, C/N0, used,
health, and a heat-graded signal bar over 50 dB-Hz that flexes to the
width. Rows in the solution are bright, unhealthy rows dim. Up / down
move, Enter opens the row's figures, Esc or Enter closes. Without a
`--gps` reader the view names the flag and this page; `--location`
alone is a setting, not a receiver. `docs/views/gnss.md` has the
mockup.

## The records

Three change-only records, each signed on bands and never on a figure
that moves every second (agents/AGENTS.md), written by
`jsonl_emit_gnss()` only with a `--gps` reader, after `ble_alert` and
before `sensor_health` in the snapshot order. The bucketing lives in
`src/gps.c` (`gps_gnss_fix_sig()`, `gps_gnss_sky_sig()`,
`gps_gnss_sat_sig()`) and is shared with the `--db` writer, so the two
sinks agree on what is news.

| Record | Key | Signed on | Carries |
|---|---|---|---|
| `gnss_fix` | singleton | mode, status, `usat`, `nsat`/4, HDOP and PDOP bands (<1, <2, <5, ≥5), the clock-offset band (\|off\| <500 ms, <2 s, <10 s, ≥10 s, unknown), the speed band (<0.5 m/s, <2, <30, ≥30), the jam band (0, 1–63, 64–127, ≥128), whether there is a position | `src`, `fix_ts`, `mode`, `status`, `nsat`, `usat`, `hdop`, `vdop`, `pdop`, `lat` / `lon` (five decimals, when there is a position; [[location]]'s privacy rules apply), `alt_m`, `eph`, `epv`, `speed_mps`, `track_deg`, `rx_time_ms`, `time_off_ms`, `leap`, `jam`, the `gst_*` sigmas when a GST arrived, `tpv_count` |
| `gnss_sky` | singleton | `nsat`, `usat`, the HDOP / PDOP / VDOP bands, the mean-C/N0 band (<25, 25–35, ≥35 dB-Hz) | `src`, `sky_ts`, `nsat`, `usat`, `rows`, `overflow`, the five DOPs, `cn0_mean`, `cn0_max`, `cn0_sd`, `cn0_n`, `passes` |
| `gnss_sat` | `gnssid` + `prn` | identity, `used`, `health`, C/N0 to 6 dB, elevation and azimuth to 15° | `gnss`, `gnssid`, `svid`, `prn`, `sigid`, `el`, `az`, `cn0` (absent when not tracked), `used`, `health`, `sky_ts` |

So a steady sky writes nothing between 300 s heartbeats; a satellite
rising, setting, joining or leaving the solution or crossing a 6 dB
band writes that one `gnss_sat`; a fix lost or regained, a DOP band
crossed or the clock stepping writes one `gnss_fix`. Per satellite
rather than a nested array in `gnss_sky` for the reason `ble_device` is
per advertiser: a consumer keeps a table keyed by the row, one change
costs one line, and slothweb's decoder keeps top-level scalars only.
`tests/test_gps.c :: test_gnss_records_change_only` holds this: sixty
identical passes are one record each, one satellite crossing a band
is one more `gnss_sat` and nothing else.

**`sensor_health` appends** (after `gps_err`, only with a `--gps`
reader): `gnss_sats_in_view`, `gnss_sats_used`, `gnss_cn0_mean`,
`gnss_time_offset_ms` (present only once a TPV carried a parseable
time) and `gnss_jam` (-1 absent). The signature takes the clock-offset
band, the mean-C/N0 band and the jam band only, never the counts.

**`sensor` record**: the receiver registers as kind `gps` (name `GNSS
receiver`, iface its source label, `observed` the parsed objects),
after the radios so their ids keep their slots. `SENSOR_GPS` existed
in the enum since #28 and was never registered until now.

## The tables (schema v10)

`gnss_fixes (last_seen PK, src, mode, status, nsat, usat, hdop, vdop,
pdop, eph, epv, lat, lon, alt_m, speed_mps, track_deg, time_off_ms,
jam, cn0_mean)` and `gnss_sightings (last_seen, gnssid, prn, svid, el,
az, cn0, used, health; PK (last_seen, gnssid, prn))`, both in the
observation tier (1× `db.retain_days`), written by `write_gnss()` on
the records' banded rule with the writer's own change memory (cleared
on open). **Row rate** = the record rate: a steady sky is one fix row
and one row per satellite per 300 s heartbeat (a dozen satellites:
~3,700 sightings a day); a satellite crossing a band is one row. The
v9 → v10 step is a stamp alone (the tables ride the unconditional
schema), tested on a v9 file and on one whose stamp is refused
([[sqlite-schema]]). slothweb allow-lists both tables at min version
10; `WEB_SDB_SCHEMA_MAX` moved to 10 with it.

## slothweb

The GNSS tab (`web/ui/gnss.js`, `window.SlothGnss`, containers
`gnss-*`) reads `/api/gnss` (the sensor block, the newest fix and sky,
every satellite row with its last 16 `(ts, C/N0)` points, sorted by
C/N0) and `/api/gnss/fixes?since=&limit=` (the kept `gnss_fix` records,
oldest first, 128 a page). It draws the TUI's two header lines, the
table (a header sorts; rows bright / dim as the TUI's; the signal cell
heat-graded with the TUI's thresholds; a per-row C/N0 trail), a polar
sky plot (azimuth around, elevation inward, north up) and a fix-history
strip (mode, satellites used, HDOP, clock offset). `web_gnss.c` keeps
64 satellite rows (least recently reported evicted, a row quiet for
660 s — two heartbeats and a margin — dropped as set) and 512 fixes,
in memory only. Four global gauges ride the rollup: `gnss.sats_used`,
`gnss.hdop`, `gnss.time_off_ms` (from `gnss_fix`) and `gnss.cn0_mean`
(from `gnss_sky`), each as sparse as its record.

**Scope**: the receiver is the host's own, neither the monitor radio's
nor the IP capture's. Its records are tagged META like
`sensor_health`, the panel is served under every scope, and the answer
says so (`scope_note`).

## Privacy

The sky reveals nothing about a third party: it is which navigation
satellites the sensor's own antenna could hear. The fix is the
sensor's position, and [[location]]'s rules govern it unchanged: it
leaves at five decimals, it is never in a change-only signature, and
a `--location` run writes none of these records.

## Hooks for the detector slice (named, not fired)

`gps_gnss_history()` returns the rings kept for the rules that follow:
the last 64 positioned fixes (`ts`, lat, lon, alt, eph, mode, usat,
clock offset) and 300 one-second points of (mean C/N0, usat, nsat,
jam). The snapshot on `sloth_state_t` (`gnss_sky`, `gnss_fix`) carries
the per-pass `cn0_sd`, the used set, the GST sigmas and the offset. A
rule would live in `src/alerts/rules_gnss.c`, read the snapshot (never
the module), and needs its `research/` document first:

- `GNSS_SPOOF_SUSPECT` — uniform, high C/N0 across the set (low
  `cn0_sd` with a high mean), the used set changing while the sky does
  not, an all-satellite C/N0 step, a clock step while the position
  stands, GST sigmas collapsing. Humphreys et al., *Assessing the
  spoofing threat* (ION GNSS 2008), is the candidate source.
- `GNSS_JAMMING` — mean C/N0 falling with `nsat` unchanged, `usat`
  reaching 0 with satellites still listed, the u-blox `jam` indicator
  (the receiver description's `jamInd`); the 300 s ring.
- `GNSS_TIME_JUMP` — consecutive `time_off_ms` deltas and receiver-time
  monotonicity against the host's monotonic clock.
- `GNSS_POSITION_JUMP` — `gps_distance_m()` between consecutive fixes
  over Δt against the reported speed and `eph`; the fix ring.

None has an honest ATT&CK technique unless ICS T0856 / T0830 is judged
one; each would otherwise land on the "real basis, no technique" list
in `tests/test_research_corpus.c`. That is a decision for the owner,
noted here so the next slice does not rediscover it.

## Not in this slice

- NMEA `GSV` / `GSA` satellite lists for a serial receiver (the
  reference host runs gpsd; the position path is unchanged).
- `?WATCH={"pps":true}` and the TOFF / PPS offset (changes the one
  line sloth sends; owner ruling).
- A text sky plot in the TUI (slothweb has one).
- Persisting slothweb's GNSS tables in `slothweb.db` (sloth.db v10
  holds the history; the panel is live state).

## Related pages

- [[location]] — the position half: `--gps`, `--location`, the stamp, the position samples.
- [[jsonl-schema]] — the records' fields.
- [[sqlite-schema]] — schema v10 and the retention tiers.
- [[views-catalog]] — the `[#]` row.
- [[non-ip-sensors]] — the sensor-family roadmap this fulfils for GPS.
- [[slothweb]] — the page the GNSS tab belongs to.
