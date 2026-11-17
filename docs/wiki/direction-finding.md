---
name: direction-finding
description: Direction finding across monitor radios (--df-iface) — extra monitor-mode radios that feed only a per-transmitter, per-radio signal-level table; what a row of independent USB radios can and cannot say about where a transmitter is; the wifi_df and df_radio records
type: reference
---

# Direction finding across monitor radios (`--df-iface`)

**Summary**: `sloth-wifi --df-iface NAME[@METRES]` (repeatable, up to
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
of Alfa adapters.

**Last updated**: 2026-11-16 (several sensor radios: what this table holds then, [[multi-radio-sensing]]), 2026-11-16 (new).

## What it can say, and what it cannot

Independent USB radios share no clock, so there is no phase to compare
and no angle of arrival. The only evidence is that a nearer antenna
hears a transmitter louder.

| It says | From |
|---|---|
| which radio hears a transmitter loudest (`best_radio`, `best_iface`) | the per-radio mean level |
| by how much (`margin_db`: loudest minus quietest) | the same |
| a point along the baseline (`along_m`), when every radio that heard it has a position | the mean of the radio positions weighted by received power (linear, the free-space 1/d² weight) |
| how much to trust it (`quality`) | `lean` at a margin of 6 dB or more, `weak` under it, and no record at all with fewer than two radios |

| It does not say | Why |
|---|---|
| which side of the line the transmitter is on | radios in a straight line are symmetric about it |
| how far off the line it is | one dimension of positions gives one dimension of answer |
| anything about a transmitter far away compared with the baseline | every radio hears it at the same level; it reads `weak`, which is the answer and not a fault |
| a bearing in degrees | there is none to be had from levels on a line |

Omnidirectional antennas a metre apart resolve only transmitters within
a few metres of the row; the level one antenna sees for a fixed
transmitter already wanders several dB with multipath, which is what the
6 dB floor is for. What improves it is antenna placement, not software:
directional antennas facing different ways (the three sectors of
[[antenna-fixture-rev-n]]: loudest sector is the bearing), or a longer
baseline, or radios off the line to break the symmetry.

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

- `--df-iface NAME` alone records levels with no positions: `best_radio`
  and `margin_db`, no `along_m`.
- `--df-iface NAME@METRES` places the radio on a straight baseline. With
  any position given, the sensor radio sits at 0 m unless `--df-origin
  METRES` says otherwise.
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
  `iface`, `role` (`sensor` or `df`), `pos_m` when given, `open`,
  `running`, `noted` (frames that reached the table), and for a `df`
  radio `bias_db` once measured (how much louder than radio 0 it reads),
  `frames`, `rejects`, `retune_failures`. Signed on open, running,
  whether anything was noted, whether a retune was refused and the bias
  in 3 dB bands, never on a count.
- **`wifi_df`**, one per transmitter two or more radios hold a fresh
  level for: `mac`, `channel`, `heard_by`, `quality`, `best_radio`,
  `best_iface`, `margin_db`, `along_m` when positions allow, `rssi`
  (one entry per radio in `df_radio` order, as measured, `null` for a
  radio with no fresh level), `level` (the same less each radio's bias:
  what `best_radio`, `margin_db` and `along_m` are computed from),
  `last_seen`. Signed on the quality, the loudest radio,
  which radios heard it, the margin in 3 dB bands and the point in
  0.25 m bands, so a transmitter standing still writes a line when
  something about its direction changes and on the heartbeat.

Not in `--db`, not in slothweb, not in the fleet export: later slices.

## Related pages

- [[wifi-sigint]] — the sensor radio, `--hop`, the #21 merge layer
- [[multi-radio-sensing]] — more than one sensor radio, and why those are not in this table
- [[antenna-fixture-rev-n]] — the three-sector fixture this makes usable
- [[rf-distance]] — distance from one radio's level, the same caution
- [[jsonl-schema]] — `df_radio`, `wifi_df`
- [[cli-reference]] — `--df-iface`, `--df-origin`
