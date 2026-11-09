# `[^]` ADS-B

**Added:** 2026-11-07 ·
**Code:** [`src/views/adsb.c`](../../src/views/adsb.c),
[`src/adsb.c`](../../src/adsb.c),
[`src/capture/adsb_reader.c`](../../src/capture/adsb_reader.c) ·
**See also:** [the ADS-B wiki page](../wiki/adsb.md),
[the non-IP sensor roadmap](../wiki/non-ip-sensors.md),
[`gnss.md`](gnss.md), [the location wiki page](../wiki/location.md)

The key is `^` because every letter and digit already selects a view or
is a global, `*` is BLE and `#` is GNSS — and because it points up,
which is where the contacts are.

## Protocol

1090 MHz Mode S and ADS-B: the squitters aircraft transmit unsolicited,
decoded by a local, already-running **decoder** — readsb or
dump1090-fa. sloth does not touch the radio. `--adsb` tails the
`aircraft.json` the decoder writes to `/run/readsb/aircraft.json` (or
`/run/dump1090-fa/aircraft.json`) and renames into place about once a
second; the format is readsb's `README-json.md`, which dump1090-fa
documents identically.

That split is deliberate and is what keeps the source inside
`MISSION.md` §2: sloth never opens, tunes or talks to the SDR, never
interrogates (an active Mode S ground station transmits; sloth does
not), and uses **no network** for this source — it reads a file. The
only transmitters in the picture are the aircraft.

Per aircraft the decoder reports, as available: `hex` (the 24-bit
address, a leading `~` marking a non-ICAO address such as TIS-B),
`type` (`adsb_icao`, `mode_s`, `mlat`, `tisb_other`, …), `flight` (the
callsign), `squawk`, `emergency`, `category`, `alt_baro` (feet, or the
string `"ground"`), `alt_geom`, `gs` (knots), `track`, `baro_rate` /
`geom_rate`, `lat` / `lon`, `rssi` (dBFS, always negative), `messages`,
and `seen` / `seen_pos` (seconds before the document's own clock).

## What sloth captures

The table `src/adsb.c` keeps, keyed by (address, non-ICAO flag) and
copied onto `sloth_state_t` once a poll: every field above, plus
`first_seen`, `last_seen` (the read time minus the aircraft's `seen`,
so an aircraft the decoder still lists but last heard 50 s ago is 50 s
old here too) and `pos_ts`. Up to 256 aircraft; more are counted as
overflow. A row unheard for 60 s is retired.

The view adds nothing to that except arithmetic the operator cannot do
in their head: **distance and bearing from the sensor**, haversine range
in kilometres (`gps_distance_m()`) and initial great-circle bearing in
degrees true (`gps_bearing_deg()`), from the sensor position
`gps_location_current()` arbitrates — a `--gps` fix, or a fixed
`--location`. No fix, no columns: see below.

Observation only. The header *counts* the aircraft reporting the
decoder's `emergency` field and grades nothing; the judgement is the
flag-only `ADSB_EMERGENCY` rule's (#186, `src/alerts/rules_adsb.c`,
[`alerts.md`](alerts.md)), which reads the same table and shows on the
Alerts view.

## View

```
 ADS-B: live  aircraft 4  emerg 1  msgs 1234567  age 0s  src file:/run/readsb/aircraft.json  [up/dn]
 docs 12  read err 0  parse err 0  overflow 0  bad 0  expired 1
 sensor at 51.50000, -0.12000 (fixed)
 ICAO     FLIGHT    SQWK     ALT     GS   TRK     DIST  BRG    RSSI   AGE  SIGNAL
>a1b2c3   BAW117    2000   37000    452   285     53.1  033   -18.3    1s  ||||||||||||||||
 00ffee   N12345    1200    2500     95    11        -    -    -3.1    5s  ||||||||||||||||||||||||||||||||||||
 ~7fab01  -            -  ground      -     -     23.1  262       -    5s
 4ca2d1   EIN24B    7700   12000    211     -        -    -   -27.8   35s  |||
 dim: not heard for 30s or more  SIGNAL: RSSI over -30..0 dBFS  ALT ft  GS kt  TRK deg  DIST km BRG deg true from the sensor
```

Rows are **freshest first** by the decoder's own last-heard time, ties
broken by address (the ICAO key space before the non-ICAO one) so the
order is stable across passes. Deliberately not by distance: the row
order would then change the moment a sensor position arrived, and the
only thing a fix should change is which columns are drawn. The cursor
follows the aircraft across the re-sort, not the row number, so an
aircraft heard again does not take the highlight with it to its
neighbour. `ALT` is barometric altitude where the aircraft sends it,
geometric where it sends only that, and `ground` where the decoder
reports `alt_baro: "ground"`. A field the decoder has not sent is `-`,
never a zero. The `SIGNAL` bar is RSSI over the -30..0 dBFS span,
heat-graded as the sparklines are, and flexes to the terminal width —
every data column is bounded by its own field (6 hex digits, an
8-character callsign, 4 octal squawk digits), so the bar is what spare
width is spent on. A row the decoder still lists but has not heard from
for 30 s or more is dim: a contact fading out before the 60 s retirement.

**`DIST` and `BRG` appear only when the sensor's own position is
known.** Without `--location` or a `--gps` fix they are absent — not a
column of dashes that still spends width — and the legend says why.
With a position, the header names it and its source, and a row the
decoder has sent no position for reads `-` in both cells while the
columns stand: what is missing there is the *aircraft's* position, not
the sensor's.

With an `sbs://` source the header's `src` reads `sbs:127.0.0.1:30003`,
its tally line counts `lines` (MSG lines) instead of `docs`, and `msgs`
is those lines too, not the decoder's lifetime count; SBS carries no
emergency status word, so `emerg` never counts an SBS row (the squawk
column still shows 7500 / 7600 / 7700, and `ADSB_EMERGENCY` fires on
it). Waiting reads as waiting for the first SBS line, and stale as no
line, not even readsb's 60 s heartbeat, for 130 s
([adsb wiki](../wiki/adsb.md#the-sbs-source-sbs)).

Without `--adsb` the view names the flag and says who owns the SDR.
With it, the four decoder states each read as themselves: `waiting`
(nothing read yet), `live`, `stale` (the file is readable but the
decoder's clock has stopped advancing, so no row is taken), `error`
(the last read or parse failed, and the table stands as it was). A live
decoder with an empty table says that rather than any of the four.

## What's normal

- A suburban receiver with a stub antenna: 5–40 aircraft in the table,
  RSSI -12 to -28 dBFS, ages under 5 s for anything in line of sight,
  the count rising and falling with the day's traffic.
- `~`-prefixed rows (TIS-B and other non-ICAO addresses) with no
  callsign and sometimes no position: the decoder is relaying what a
  ground station re-broadcast, not what the aircraft sent.
- Rows with altitude and no position, especially low and far: Mode S
  altitude replies carry no position, and ADS-B position needs both
  halves of a CPR frame pair.
- `squawk` 1200 (VFR, US) or 7000 (VFR, Europe) on light aircraft, 2000
  on an aircraft that has not been given a code.
- `ground` altitudes and ages climbing steadily near an airfield: an
  aircraft on a stand transmits intermittently.
- `age` on a row sitting at 30 s and then the row vanishing: the 60 s
  retirement, which is the window readsb itself keeps an aircraft for.

## What's suspicious

Nothing in this view is a finding — it is observation; the one
detector that reads the table is `ADSB_EMERGENCY` (#186), on the Alerts
view. What is worth an operator's eye:

- **Emergency and priority codes.** `7500` (unlawful interference),
  `7600` (radio failure), `7700` (general emergency), and the decoder's
  own `emergency` field (`general`, `lifeguard`, `minfuel`, `nordo`,
  `unlawful`, `downed`). The header's `emerg` count is how many rows
  report one. `ADSB_EMERGENCY` flags each (LOW on first sight, WARN
  once held 10 s of the aircraft's own messages, never CRIT). sloth
  surfaces these and never acts on them: there is no reply path, by §2
  and by design, and ADS-B is unauthenticated, so a declaration can be
  forged and one receiver cannot tell.
- **An aircraft whose position is implausible for its speed** — a jump
  of tens of kilometres between documents, or a position that does not
  move while the ground speed says 450 kt. Either is a decoder or a
  transponder fault far more often than it is anything else, which is
  exactly why it needs a cited threshold before it becomes a rule.
- **A `stale` or `error` decoder on a sensor that is supposed to be
  collecting.** The health line and the `adsb` token on the
  [Interfaces](interfaces.md) strip exist for this: a feed that stopped
  looks identical to quiet sky at the terminal, and that confusion is
  what every sensor-health token in sloth is there to resolve.
- **The receiver's own position is the operator's to protect.** The
  aircraft near a receiver locate it roughly, so the `DIST` / `BRG`
  columns are a disclosure if the screen is shared — the same caution
  [the wiki page](../wiki/adsb.md) states for the records.

## See also

- [the ADS-B wiki page](../wiki/adsb.md) — the parser, the table, the
  bands, `adsb_aircraft`, the `--db` tables and slothweb's tab.
- [GNSS](gnss.md) — the sibling sensor family, and the receiver that
  supplies the position these columns need.
- [Sensor location](../wiki/location.md) — what `--location` and
  `--gps` arbitrate, and what `loc_stamp_t` carries.
- [Interfaces](interfaces.md) — the health strip the `adsb` token joins.
- [JSONL schema](../wiki/jsonl-schema.md) — `adsb_aircraft`, and the
  `adsb_*` fields on `sensor_health`.
