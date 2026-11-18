---
name: direction-finding
description: Direction finding across monitor radios (--df-iface) — extra monitor-mode radios that feed only a per-transmitter, per-radio signal-level table; what a row of independent USB radios can and cannot say about where a transmitter is; the wifi_df and df_radio records
type: reference
---

# Direction finding across monitor radios (`--df-iface`)

**Summary**: `sloth-wifi --df-iface NAME[@METRES|@X,Y]` (repeatable, up to
three) listens on extra monitor-mode radios beside the sensor radio.
From each of their frames it reads two things, the transmitter address
and the level it was heard at, into a table of transmitters with one
level per radio (`src/df.c`). The sensor radio is radio 0 of that table.
Nothing else reads a frame from a `--df-iface` radio: no parser,
detector, counter, evidence ring or alert, so a frame three radios hear
is still one frame to every rule. They are not sensor radios; those are
`--monitor-iface` repeated ([[multi-radio-sensing]]), and a radio is one
or the other, never both (exit 2).
**Receive-only** (MISSION §2). Under `--hop` the extra radios are
retuned with the sensor radio, the same kind of kernel write `--hop`
already makes on sloth's own interface; without `--hop` nothing is
retuned. The output is two JSONL records, `df_radio` and `wifi_df`.
No alert rule reads either: this is a data point for an analyst.

**Sources**: `src/df.h`, `src/df.c`, `src/capture/df_radio.h`,
`src/capture/df_radio.c`, `src/capture/probe.c` (radio 0's note),
`src/main.c` (`--df-iface`, `--df-origin`, the follow in
`chanhop_drive()`), `src/jsonl.c` (`jsonl_emit_wifi_df()`),
`tests/test_df.c`. Owner's request, 2026-11-16, for the beta-site row
of Alfa adapters; 2026-11-17 for the same three in a triangle.

**Last updated**: 2026-11-17 (radios off the line: `NAME@X,Y` and the bearing, JSONL 2.4.0), 2026-11-17 (slothweb's card and `/api/df`), 2026-11-16 (several sensor radios: what this table holds then, [[multi-radio-sensing]]), 2026-11-16 (new).

## What it can say, and what it cannot

Independent USB radios share no clock, so there is no phase to compare
and no angle of arrival. The only evidence is that a nearer antenna
hears a transmitter louder.

| It says | From |
|---|---|
| which radio hears a transmitter loudest (`best_radio`, `best_iface`) | the per-radio mean level |
| by how much (`margin_db`: loudest minus quietest) | the same |
| a point along the baseline (`along_m`), when every radio that heard it has a position | the mean of the radio positions weighted by received power (linear, the free-space 1/d² weight) |
| a compass direction the levels lean in (`bearing_deg`, one of eight points, with `bearing_err_deg`), when three or more radios are placed in two dimensions and the transmitter is close to them: § Radios off the line | the direction of that same weighted mean from the middle of the array |
| how much to trust it (`quality`) | `lean` at a margin of 6 dB or more, `weak` under it, and no record at all with fewer than two radios |

| It does not say | Why |
|---|---|
| which side of the line the transmitter is on, with the radios in a line | radios in a straight line are symmetric about it |
| how far off the line it is | one dimension of positions gives one dimension of answer |
| where the transmitter is, or how far | the weighted mean always lies inside the array; it has a direction from the middle and no range |
| anything about a transmitter far away compared with the baseline | every radio hears it at the same level; it reads `weak`, which is the answer and not a fault |
| a bearing from radios on a line | there is none to be had from levels on a line |
| an angle of arrival | the bearing is which way the levels lean, in 45 degree steps, not a measured angle |

Omnidirectional antennas a metre apart resolve only transmitters within
a few metres of the row; the level one antenna sees for a fixed
transmitter already wanders several dB with multipath, which is what the
6 dB floor is for. What improves it is antenna placement, not software:
directional antennas facing different ways (the three sectors of
[[antenna-fixture-rev-n]]: loudest sector is the bearing), or a longer
baseline, or radios off the line to break the symmetry.

## Radios off the line (`NAME@X,Y`)

Owner's layout, 2026-11-17: three Alfa adapters at the corners of a
triangle with 2 m sides, matching antennas. With a position in two
dimensions on every radio (`X,Y`: metres east, metres north) the
symmetry about the line is gone, and the power-weighted mean of the
radio positions has a direction from the centroid of the array. That
direction is `bearing_deg`: compass degrees, 0 north, 90 east.

It is the direction the levels lean, not a fix and not a range. It is
given as one of eight compass points (`DF_BEARING_STEP_DEG` 45), with
`bearing_err_deg` beside it (15, 30 or 45): how far the direction moves
when one radio's level is 3 dB off (`DF_BEARING_WANDER_DB`, half the
margin floor), rounded up. A point once given stands until the direction
is 11.25 degrees past the edge of its sector, so a still transmitter on
an edge does not write a line each time its mean moves a degree.

It is withheld, and the record written without it, unless all of:

- three or more radios have an `X,Y` position and are not on one line
  (the array is at least a quarter as deep as its longest side,
  `DF_MIN_ASPECT`);
- every placed radio holds a fresh level for the transmitter, and no
  radio without a position heard it;
- the quality is `lean` (6 dB between loudest and quietest);
- that 3 dB error on any one radio moves the direction 45 degrees or
  less.

With 2 m sides that means a transmitter within about three metres of the
array: at 10 m the three radios differ by under 2 dB and the record
reads `weak`. Most transmitters have no bearing, and that is the answer.
With the three corners at 0, 120 and 240 degrees, a transmitter beside
a corner reads 0, 135 or 225.

`along_m` and `bearing_deg` are never on one record: a command line
gives positions in one form (exit 2 otherwise). At start, `X,Y`
positions that cannot give a bearing (fewer than three placed radios, or
on one line) are said so on stderr.

## Calibration: radios do not read alike

Two radios do not report the same level for the same signal: receiver,
antenna, cable and USB port differ. On the beta-site pair (one stock
antenna, one remote 9 dBi) the second radio read 7.5 dB under the first
across 42 transmitters (2026-11-16). Left in, that difference is the
whole margin and everything leans one way.

So each radio's bias against radio 0 is measured from the air
(`calibrate_locked()`, on every `df_snapshot()`): the median, over the
transmitters both radios hold a fresh level for, of the difference of
their means; taken once 8 transmitters are shared (`DF_CAL_MIN`), then
smoothed (weight 0.2). Levels are compared less the bias: `wifi_df`
carries `rssi` as measured and `level` as compared, and `df_radio`
carries `bias_db`.

What the median assumes: most transmitters are far compared with the
baseline, so most are heard equally and the median is the hardware. It
removes a constant gain difference. It does not remove a difference in
antenna pattern: a 9 dBi omni is flatter than a stock one, so the two
disagree by elevation angle transmitter by transmitter, and that
disagreement reads as a lean. **Unlike antennas give leans that mean
nothing.** It is also wrong where most transmitters really are nearer
one radio (a long baseline, sector antennas); those need a measured
offset per radio, which is not built.

## Setup

Each radio is prepared by the operator, exactly as the sensor radio is
(sloth changes no link state): monitor mode, up, NetworkManager off it.

```
sloth-wifi --monitor-iface alfa0 --hop \
    --df-iface alfa1@1.0 --df-iface alfa2@2.0
```

The beta-site triangle, sensor radio at the east corner:

```
sloth-wifi --monitor-iface alfa0 --hop --df-origin 1.0,-0.58 \
    --df-iface alfa1@0,1.15 --df-iface alfa2@-1.0,-0.58
```

- `--df-iface NAME` alone records levels with no positions: `best_radio`
  and `margin_db`, no `along_m`.
- `--df-iface NAME@METRES` places the radio on a straight baseline. With
  any position given, the sensor radio sits at 0 m unless `--df-origin
  METRES` says otherwise.
- `--df-iface NAME@X,Y` places it in two dimensions, metres east and
  metres north of any point the operator picks; the sensor radio sits at
  `0,0` unless `--df-origin X,Y` says otherwise. The two forms are not
  mixed on one command line (exit 2); a radio with no position may sit
  beside either.
- A radio that cannot be opened (absent, not in monitor mode, a raw HCI
  device) is announced on stderr and left out; the run continues. With
  no sensor radio open, none is opened.
- Not with `--replay`, and not in a `WITH_PCAP=0` build (exit 2).

**Channels.** A level is comparable only between radios that heard the
same transmission, so the extra radios must sit on the sensor radio's
channel. Under `--hop` sloth retunes them each time the sensor radio's
retune is confirmed (`df_radio_follow()`); a refused retune is counted
(`retune_failures`). Without `--hop` sloth says so at start and the
operator parks them. This is the opposite of [[wifi-sigint]]'s
multi-radio idea (a second radio parked on another channel for
coverage): these radios add no coverage.

## The table (`src/df.c`)

- Up to 4 radios (`DF_MAX_RADIOS`) and 512 transmitters
  (`DF_MAX_EMITTERS`). A full table drops a new transmitter while every
  row is fresh (`df_dropped()`), and recycles the row quiet longest once
  it is older than 30 s.
- Per radio per transmitter: an exponential mean of the level (new frame
  weight 0.25), a frame count, the time of the newest frame. A reading
  older than 30 s (`DF_FRESH_S`) starts over, and is not used in an
  estimate; nor is one from fewer than 3 frames (`DF_MIN_SAMPLES`).
- What is noted: management and data frames (Address 2 is the
  transmitter), FCS good, a negative level, an individual address.
  Control frames are left out: an ACK or CTS has no transmitter address.
- Times are the host's clock at the note, for every radio, since the
  table compares ages across radios.

## With several sensor radios

`--monitor-iface` may be given more than once ([[multi-radio-sensing]]).
Radio 0 of this table is still the first of them, and the `--df-iface`
radios still follow its channel. The further sensor radios are not in
the table: under `--hop` each sits on its own share of the channel list,
so it did not hear the transmission radio 0 heard and its level cannot
be compared. Radio 0's level is noted from radio 0's own copy of a frame
even when another sensor radio's copy was the one the detectors got. A
name given to both flags is refused at startup.

## Records

Both are sloth-wifi's, change-only, and written only when a second
radio is registered. Field tables: [[jsonl-schema]].

- **`df_radio`**, one per radio: `radio` (0 is the sensor radio),
  `iface`, `role` (`sensor` or `df`), `pos_m` or `x_m` and `y_m` when
  given, `open`,
  `running`, `noted` (frames that reached the table), and for a `df`
  radio `bias_db` once measured (how much louder than radio 0 it reads),
  `frames`, `rejects`, `retune_failures`. Signed on open, running,
  whether anything was noted, whether a retune was refused and the bias
  in 3 dB bands, never on a count.
- **`wifi_df`**, one per transmitter two or more radios hold a fresh
  level for: `mac`, `channel`, `heard_by`, `quality`, `best_radio`,
  `best_iface`, `margin_db`, `along_m` when positions allow,
  `bearing_deg` and `bearing_err_deg` when a bearing is given, `rssi`
  (one entry per radio in `df_radio` order, as measured, `null` for a
  radio with no fresh level), `level` (the same less each radio's bias:
  what `best_radio`, `margin_db` and `along_m` are computed from),
  `last_seen`. Signed on the quality, the loudest radio,
  which radios heard it, the margin in 3 dB bands, the point in
  0.25 m bands and the bearing with its error, so a transmitter standing still writes a line when
  something about its direction changes and on the heartbeat.

In slothweb: the WiFi view's direction-finding card and `GET /api/df`
([[slothweb]] § Direction finding, 2026-11-17), from the stream, the
scalars only (not the `rssi` and `level` arrays), in memory; the card
does not show the 2.4.0 members (`x_m`, `y_m`, `bearing_deg`,
`bearing_err_deg`) yet. Not in
`--db`, not in the fleet export: later slices.

## Related pages

- [[wifi-sigint]] — the sensor radio, `--hop`, the #21 merge layer
- [[multi-radio-sensing]] — more than one sensor radio, and why those are not in this table
- [[antenna-fixture-rev-n]] — the three-sector fixture this makes usable
- [[rf-distance]] — distance from one radio's level, the same caution
- [[jsonl-schema]] — `df_radio`, `wifi_df`
- [[cli-reference]] — `--df-iface`, `--df-origin`
