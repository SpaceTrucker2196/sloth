---
name: gnss
description: GNSS observation — what sloth records off the --gps receiver beyond its position (the satellites in view with their C/N0, the DOPs, the receiver's clock against the host's), the [#] view, the gnss_fix / gnss_sky / gnss_sat records, the v10 tables, slothweb's panel, the caveats, and the four GNSS alert rules that read it
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
sensor in the registry, and slothweb's GNSS tab. Since 2026-11-03 four
alert rules read it — `GNSS_JAMMING`, `GNSS_SPOOF_SUSPECT`,
`GNSS_TIME_JUMP`, `GNSS_POSITION_JUMP` (below). **Receive-only** (MISSION §2):
the one `?WATCH` line to gpsd is unchanged, and a serial device is
never written to.

**Sources**: `src/gps.h`, `src/gps.c` (the parser's `satellites[]`,
GST, `gpsd_time_parse()`, the sky / fix state, `gps_gnss_*_sig()`),
`src/sloth_clock.c` (`sloth_wall_ms()`), `src/views/gnss.c`,
`src/jsonl.c` (`jsonl_emit_gnss()`, the `gnss_*` appends in
`jsonl_emit_sensor_health()`), `src/poll.c` (`SENSOR_GPS`), `src/db.c`
(`write_gnss()`), `src/db_schema.c` (v10), `web/src/web_gnss.c`,
`web/ui/gnss.js`, `src/alerts/rules_gnss.c`; tests `tests/test_gps.c` ("GNSS observation"),
`tests/test_gnss_rules.c` (the GNSS rules),
`tests/test_gnss_view.c`, `tests/test_db.c` (v9 → v10),
`web/tests/test_gnss.c`.

**Last updated**: 2026-11-11 (a link to [[fleet]]'s GNSS comparison across sites, #192 I6). 2026-11-09 (#182: `GNSS_TIME_JUMP` does not judge or anchor on a fix read late, the queued read's mirror; its detail carries both gaps and the fix interval). 2026-11-06 (`/api/gnss` gains `loc`, the sensor's own position from `sensor_health`'s `loc_*`, GPS else `--location`, for the Radar view's centre); 2026-11-05 (slothweb names each satellite: the RINEX identifier and, from the IGS satellite metadata compiled in, the vehicle - name, NORAD and COSPAR numbers, SVN, block, launch, plane and slot - at the record's time; the sky plot draws each satellite's trail from `gnss_sightings`, `/api/gnss/tracks`). 2026-11-05 (slothweb's "satellites seen" history over `gnss_sightings`, `/api/gnss/seen` and `/api/gnss/sat`, and a satellite's C/N0 and elevation over a window). 2026-11-03 (the four GNSS rules replace the hooks section; the history carries the monotonic clock, `eps`, `leapseconds` and `reacq`). 2026-11-02 (verify: `GPSD_MAX_LINE` 10240 so a full multi-GNSS SKY fits; a fractional `mode` is no fix; slothweb shows any offset sloth records). 2026-11-02 (review: `jam` sticky across the TPVs gpsd omits it from; the clock-offset band held with hysteresis; the used count signed as a band in `gnss_fix` and `gnss_sky`; `el` / `az` carried with flags and absent from the records rather than -1; an empty `satellites` set empties the sky and the view says so; the `[#]` cursor follows the satellite across a re-sort; the TUI's cursor, the DataTable and the fix-ring walk in slothweb; what a set satellite writes, and the accepted band-edge case, stated); 2026-11-02 (first version).

## What is read

Only gpsd's JSON carries the sky today. `gpsd_json_parse()` reads, on
top of the position fields [[location]] needed:

- **SKY**: `nSat`, `uSat`, `hdop` / `vdop` / `pdop` / `gdop` / `tdop`,
  and the `satellites[]` array — per entry `PRN` (always present),
  `gnssid`, `svid`, `sigid`, `el`, `az`, `ss` (C/N0 in dB-Hz), `used`,
  `health`. Up to `GNSS_MAX_SATS` (48) entries are kept; the rest are
  parsed, counted (`overflow`) and dropped. A line may be up to
  `GPSD_MAX_LINE` (10240 bytes, gpsd's own response ceiling); a
  50-satellite SKY with every per-satellite field is about 5.5 kB, so it
  fits, and a longer line is refused whole and counted in
  `gps_parse_errors`. gpsd's `gnssid` is 0 GPS, 1 SBAS,
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
it is **not** a time-sync quality figure. Every receiver year sloth accepts
(1970–2999) gives an offset sloth records as it is, and slothweb shows
the whole of that range (±2⁴⁶ ms) rather than blanking it, so the
wildest clock is the one still on screen. Because a 9600-baud
receiver's latency sits in the 200–700 ms range, right across the
first band edge, the band the records sign is **held with
hysteresis** (`take_tpv()`): it moves to a new band only once the
offset clears the edge between them by a quarter of that edge
(125 ms at 500 ms, 500 ms at 2 s, 2.5 s at 10 s). The figure itself
is always exact; the TUI and the page colour the raw value.

**`jam` is sticky.** gpsd attaches the u-blox jamming indicator only
to the TPV that follows a UBX-MON-HW poll (two of fourteen TPVs in
eight seconds on the reference host), not to every TPV. A TPV without
it keeps the last reported value for `GNSS_JAM_HOLD_TPVS` (10) TPVs,
then it reads -1 again. Per TPV it flipped -1 / value every second,
which re-signed `gnss_fix` and `sensor_health` on every tick and left
the one-second series mostly -1. gpsd's `TOFF` / `PPS`
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
move, Enter opens the row's figures, Esc or Enter closes. The cursor
follows the **satellite**, not the row number: the table is sorted
again on every SKY, and the highlight (and the open detail) stays on
the bird the operator chose when two C/N0s cross; only once that bird
has left the sky does the row index stand in. A SKY that lists
nothing (the antenna gone) is said as that, not as the first pass
still awaited. Without a
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
| `gnss_fix` | singleton | mode, status, the used-count band (0, 1–3, 4–5, 6–7, ≥8), `nsat`/4, HDOP and PDOP bands (<1, <2, <5, ≥5), the clock-offset band held with hysteresis (\|off\| <500 ms, <2 s, <10 s, ≥10 s, unknown), the speed band (<0.5 m/s, <2, <30, ≥30), the jam band (0, 1–63, 64–127, ≥128), whether there is a position | `src`, `fix_ts`, `mode`, `status`, `nsat`, `usat`, `hdop`, `vdop`, `pdop`, `lat` / `lon` (five decimals, when there is a position; [[location]]'s privacy rules apply), `alt_m`, `eph`, `epv`, `speed_mps`, `track_deg`, `rx_time_ms`, `time_off_ms`, `leap`, `jam`, the `gst_*` sigmas when a GST arrived, `tpv_count` |
| `gnss_sky` | singleton | `nsat`/4, the used-count band, the HDOP / PDOP / VDOP bands, the mean-C/N0 band (<25, 25–35, ≥35 dB-Hz) | `src`, `sky_ts`, `nsat`, `usat`, `rows`, `overflow`, the five DOPs, `cn0_mean`, `cn0_max`, `cn0_sd`, `cn0_n`, `passes` |
| `gnss_sat` | `gnssid` + `prn` | identity, `used`, `health`, C/N0 to 6 dB, elevation and azimuth to 15° (absent as its own band) | `gnss`, `gnssid`, `svid`, `prn`, `sigid`, `el` and `az` (absent when gpsd sent none; `el` may be negative), `cn0` (absent when not tracked), `used`, `health`, `sky_ts` |

So a steady sky writes nothing between 300 s heartbeats; a satellite
rising, joining or leaving the solution or crossing a 6 dB band
writes that one `gnss_sat`; a fix lost or regained, a DOP band
crossed or the clock stepping writes one `gnss_fix`. The used count
is a band, not the number, because `uSat` flaps by one every few
seconds on a moving or urban receiver and the per-satellite `used`
flag already says which bird joined or left.

Two things the records do **not** say, stated so a consumer does not
expect them. **A satellite that sets writes nothing**: the emitter
walks the current sky, so a set satellite's row simply stops coming,
and a consumer infers it from the 300 s heartbeat lapsing (slothweb
drops a row quiet for 660 s); one that sets and re-rises inside a
heartbeat with the same bands is silent too. And **the per-row bands
have no hysteresis**: a satellite sitting on a 6 dB C/N0 edge or a
15° azimuth edge writes a `gnss_sat` line (and a `gnss_sightings`
row) per pass until it moves off the edge. That is bounded to the one
row and accepted; the fix-level bands, which would otherwise fire on
every TPV, are the ones held. Per satellite
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
oldest first, 128 a page; the page **walks** it — from `since=0`, then
from the last row's `ts` while a page comes back full — so the strip
reaches the newest fix once the 512-entry ring holds more than a
page). It draws the TUI's two header lines, the table (app.js's one
`DataTable`, as every table on the page: kept column widths and sort,
`aria-sort`, drag / keyboard sizing, "reset columns"; with no sort set
the rows are in the TUI's order; rows bright / dim as the TUI's; the
signal cell heat-graded with the TUI's thresholds; a per-row C/N0
trail), a polar
sky plot (azimuth around, elevation inward, north up) and a fix-history
strip (mode, satellites used, HDOP, clock offset). `web_gnss.c` keeps
64 satellite rows (least recently reported evicted, a row quiet for
660 s — two heartbeats and a margin — dropped as set) and 512 fixes,
in memory only. Four global gauges ride the rollup: `gnss.sats_used`,
`gnss.hdop`, `gnss.time_off_ms` (from `gnss_fix`) and `gnss.cn0_mean`
(from `gnss_sky`), each as sparse as its record.

**History** (2026-11-05): with `--sloth-db`, the tab also reads
sloth.db's `gnss_sightings` through the allow-list
(`web/src/web_rfhist.c`). `/api/gnss/seen?days=&limit=` is one row per
satellite seen in the window (24 h by default, up to 400 days, at most
160 rows): first and last seen, the records, the share of them in the
solution, C/N0 maximum and mean, the highest elevation, the most
recently seen first. `/api/gnss/sat?gnssid=&prn=&days=` is one
satellite's records over the window, oldest first, at most 400, as
`[ts, el, az, cn0, used, health]`. The page shows the first as the
"satellites seen" table (window 24 h / 7 d / 30 d, kept per browser)
and the second, for a row clicked there or in the live table, as two
lanes over time: C/N0 heat-graded (larger dots in the solution) and
elevation. A file older than v10 answers `"have":false` and an empty
list.

**Which satellite** (2026-11-05, `web/src/web_gnssmeta.h`). Every row
carries `id`, the RINEX identifier (RINEX 3.05 / 4.0: a system letter
- G GPS, R GLONASS, E Galileo, C BeiDou, J QZSS, I NavIC, S SBAS - and
two digits: gpsd's `svid`, the GLONASS slot, PRN - 100 for SBAS; from
the NMEA PRN where gpsd sent no `svid` and the range is one system's),
and `veh`, the vehicle transmitting it at the row's time, looked up in
the IGS satellite metadata compiled in at build
(`web/data/gnss/SOURCE.md`, release 2441, 295 vehicles): its name
(`NAVSTAR 64`, `COSMOS 2501`, `GALILEO-PFM`, `MICHIBIKI-2`), satellite
catalogue (NORAD) number - the one identifier that belongs to one
object for its life - COSPAR designator, SVN, block, launch date and
orbital plane and slot. A PRN is an assignment, not a satellite (G05
was SVN G035 until 2009 and is G050 since), hence the time. SBAS and
IMES are not in the IGS file: `veh` is null. The live and "seen"
tables have ID, SATELLITE (and NORAD in "seen") columns; the detail
lists the rest.

**Trails** (2026-11-05). `/api/gnss/tracks?hours=` (1..24, default 6)
is every satellite's `(ts, el, az)` from `gnss_sightings` over the
window, at most 32 points a satellite (the newest record of each
bucket of hours x 3600 / 32 s) and 2400 in all. The sky plot draws
each as a line fading toward its oldest point, the selected satellite
bold, with no line across a gap of more than two buckets (a satellite
setting and rising again); a window picker (1 h to 24 h) sits on the
plot and is kept per browser.

**The sensor's position** (2026-11-06): `/api/gnss` ends with `loc`,
the `web_loc.h` shape (`lat`, `lon` to seven places, `alt_m`, `acc_m`
null, `src` `gps` or `fixed`, `ts`) or `null`, kept from
`sensor_health`'s `loc_*` members ([[location]]): a fresh fix, else the
`--location`, cleared by a line without them. It is the one place
slothweb learns a `--location`-only sensor's position without an alert;
the Radar view centres its dome on it.

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

## The rules (2026-11-03)

What were the detector hooks are now four alert kinds,
`src/alerts/rules_gnss.c` ([[alerts]] § The GNSS receiver, the rows in
`docs/views/alerts.md`, one assessment each in
[alert-assessments/](alert-assessments/README.md)). Each rule reads
the snapshot, never the module: `gps_health_poll()` copies the sky, the
newest fix and the history rings each poll, `s->gnss_hist` pointing at
the rings' copy (a pointer, because `sloth_state_t` is returned by value
in tests whose stack it already nearly fills). The bases are the four
documents under `research/gnss/` ([[research-corpus]]); the thresholds
are the twelve `gnss.*` knobs ([[cli-reference]]).

| Kind | Sev | ATT&CK | Reads |
|---|---|---|---|
| `GNSS_JAMMING` | WARN; CRIT when the fix is lost | Mobile T1464 | the 300 s series: the newest point's median C/N0 over the tracked satellites (ss > 0) against the 60 s before a 10 s window, with the used set falling and the sky still listed at its size; or `jam` held high for 30 s |
| `GNSS_SPOOF_SUSPECT` | LOW on two heuristics, WARN on three | — | the sky (used C/N0 too high; uniform and high) and the fix ring (a reacquisition with a jump), two within 300 s |
| `GNSS_TIME_JUMP` | WARN | — | the fix ring: the receiver's time against the host's monotonic clock, from the last accepted fix, held on the next; a fix read from a queue, read late (#182) or that did not hold is never the reference |
| `GNSS_POSITION_JUMP` | WARN | — | the fix ring: distance against (speed + eps) × Δt + 3 × (eph₁ + eph₂), Δt the receiver's epoch spacing |

**What the history carries for them** (`gnss_hist_t`, now in
`include/sloth.h`): every positioned fix keeps the TPV's count, the
host's monotonic and wall clocks at receipt, the receiver's own time,
`speed`, `eps` (TPV `eps`, parsed since this change), `eph`,
`leapseconds`, and `reacq` — set on the first positioned fix since
sloth started, the first after a TPV that said mode 0 or 1, and the
first after the source was lost (`gps_location_source_lost()`), so no
rule compares across a gap. Every one-second point carries the
monotonic clock, the TPV's mode, and the median C/N0 and count of the
sky's **tracked** rows (ss > 0): gpsd lists satellites it is not
tracking at ss 0, and a mean over every row read four satellites lost
behind a building as a 12 dB collapse of the sky. The sky carries its
monotonic receipt time. A host clock step therefore moves
`time_off_ms` (as it always did) and never a rule's window.

**Receipt time is not epoch time.** `mono_ms` is when sloth read the
TPV. A reader that stalls (the TUI stopped with Ctrl-Z, a loaded Pi)
and then drains what gpsd queued reads fixes a second apart in the
receiver's time a millisecond apart; a host suspend stops the monotonic
clock while the receiver's keeps going. A starved reader (a loaded
host) can also read every fix late by the same amount for a while,
each a second after the last; only the read where it fell behind
shows a long gap. `GNSS_TIME_JUMP` therefore skips a fix read from a
queue and never measures from one; skips, likewise, a fix read late
(#182: summed from its reference over the reads where the receiver
kept its fix interval, the host's gaps ran more than 250 ms past the
receiver's and past the interval alike, so a receiver nudged inside the
interval while read on time is not taken for a late reader), re-anchoring unjudged on a lateness that stands 30 s so a
permanently slower reader does not blind it; and takes a
suspend (the receiver's and the host's wall clocks moving past the
monotonic one together) as a reacquisition; `GNSS_POSITION_JUMP` takes
Δt from the receiver's own time.

**What they cannot do**, from the research: tell interference from
jamming (DHS 2017), locate a jammer, see a spoofer present before sloth
started, or catch a patient drag-off; a consumer receiver has no signal
authentication. The ATT&CK reasoning — T1464 for jamming, nothing for
the other three — is `research/gnss/attack-mapping.md`, ruled by the
owner on 2026-11-03.

## Not in this slice

- NMEA `GSV` / `GSA` satellite lists for a serial receiver (the
  reference host runs gpsd; the position path is unchanged).
- `?WATCH={"pps":true}` and the TOFF / PPS offset (changes the one
  line sloth sends; owner ruling).
- A text sky plot in the TUI (slothweb has one).
- Persisting slothweb's live GNSS tables in `slothweb.db` (sloth.db
  v10 holds the history, which the tab reads since 2026-11-05; the live
  panel is live state).

## Related pages

- [[location]] — the position half: `--gps`, `--location`, the stamp, the position samples.
- [[jsonl-schema]] — the records' fields.
- [[sqlite-schema]] — schema v10 and the retention tiers.
- [[views-catalog]] — the `[#]` row.
- [[non-ip-sensors]] — the sensor-family roadmap this fulfils for GPS.
- [[slothweb]] — the page the GNSS tab belongs to.
- [[alerts]] — the four GNSS rules among the rest.
- [[fleet]] — the receivers of the owner's sites compared (#192 I6): each GNSS event regional, local or undetermined, the baseline between static sites, a clock step named to its site.
