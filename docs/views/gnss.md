# `[#]` GNSS

**Added:** 2026-11-02 ·
**Code:** [`src/views/gnss.c`](../../src/views/gnss.c),
[`src/gps.c`](../../src/gps.c) ·
**See also:** [the GNSS wiki page](../wiki/gnss.md),
[the location wiki page](../wiki/location.md),
[`alerts.md`](alerts.md)

The key is `#` because every letter and digit already selects a view or
is a global, and `*` is BLE.

## Protocol

gpsd's JSON stream (https://gpsd.gitlab.io/gpsd/gpsd_json.html) over
loopback TCP, as `--gps gpsd://` already reads it for the sensor's
position. Three objects feed this view:

- **SKY** — the receiver's satellite list, one object per satellite:
  `PRN` (always), `gnssid` / `svid` (constellation and the PRN within
  it), `sigid`, `el`, `az` (degrees), `ss` (C/N0 in dB-Hz), `used`
  (in the navigation solution), `health`; plus `nSat`, `uSat` and the
  DOPs (`hdop`, `vdop`, `pdop`, `gdop`, `tdop`).
- **TPV** — the fix: `mode` (0 unknown, 1 none, 2 2D, 3 3D),
  `status` (1 normal, 2 DGPS, 3 RTK fix, 4 RTK float, 5 DR, 6 GNSS+DR,
  7 time-surveyed, 8 simulated, 9 P(Y)), position and its `eph` /
  `epv`, `speed`, `track`, `leapseconds`, `jam` (u-blox), `time`.
- **GST** — pseudorange noise statistics (rms, the error ellipse, the
  lat / lon / alt sigmas).

sloth sends gpsd exactly one `?WATCH={"enable":true,"json":true}` line
and writes nothing to a serial device (MISSION §2). The host's own
receiver is the only transmitter in the picture, and it transmits
nothing.

## What sloth captures

Per satellite: constellation (gpsd's `gnssid`, named GPS / SBAS /
Galileo / BeiDou / IMES / QZSS / GLONASS / NavIC), svid, PRN, signal
id, elevation, azimuth, C/N0, used, health. Per pass: satellites in
view and used, the five DOPs, the C/N0 mean / max / standard deviation.
Per fix: mode, status, accuracy, speed, track, leap seconds, the
jamming indicator, and the **clock offset** — the receiver's `time`
minus the host's wall clock as the line arrived, a coarse figure
(serial and gpsd latency, no PPS) that shows a multi-second step and
nothing finer. Up to 48 satellites are kept; more are counted.

All of it is observation. No row here is a finding; the detectors that
will read this sky are a following slice.

## View

```
 GNSS: fix 3D  sats 9/14  HDOP 1.1 PDOP 1.9  acc ±4 m  speed 0.0 m/s  clock off +120 ms  src gpsd:127.0.0.1:2947  age 1s
 status DGPS  leap 18  jam 0  C/N0 mean 38.2 max 47.5  [up/dn] [Enter] detail
 GNSS        SV   PRN   EL   AZ   C/N0  USED  HLTH  SIGNAL
>GLONASS      9    73   30  300   47.5   yes    ok  |||||||||||||||||||||||||||||||||||||||||||||||
 GPS          5     5   45  120   41.0   yes    ok  |||||||||||||||||||||||||||||||||||||||||
 Galileo     12   312   60   40   33.0   yes   BAD  |||||||||||||||||||||||||||||||||
 GPS          7     7    -    -   22.5     -    ok  ||||||||||||||||||||||
 SBAS       131   131   10  200      -     -     ?
 bright: used in the solution  dim: unhealthy  SIGNAL: C/N0 over 50 dB-Hz
```

Rows are sorted by C/N0, strongest first; a satellite the receiver
lists but does not track (no `ss`) sits last with no bar; an elevation
or azimuth gpsd did not send is `-` (a negative elevation is a bird
under the horizon, drawn as itself). The cursor follows the satellite
across the re-sort every SKY brings, not the row number. Rows in the
solution are bright, unhealthy rows dim. HDOP / PDOP warm past 2 and
hot past 5; the clock offset warms past 500 ms and reddens past 2 s;
`jam` follows u-blox's `jamInd` bands. `Enter` opens the selected
row's figures; `Esc` or `Enter` closes. Without `--gps` the view names
the flag; with a serial NMEA source it waits (GSV is not parsed yet);
a SKY that listed no satellites is said as that.

## What's normal

- Open sky, stationary: 8–14 satellites in view across two
  constellations on a u-blox 7 (GPS + GLONASS), 7–12 used, C/N0
  35–48 dB-Hz for high-elevation birds and 20–30 near the horizon,
  HDOP around 1, PDOP under 2, `status` 1 or 2 (SBAS corrections).
- Indoors or under a window: fewer used than in view, C/N0 in the
  twenties, HDOP climbing past 2, the fix dropping to 2D or none, and
  satellites appearing and leaving as reflections come and go.
- The clock offset holding within a few hundred milliseconds and
  jittering by tens — that jitter is the transport, not the receiver.
- `jam` 0 to low tens on a USB receiver beside a laptop; USB 3 ports
  and switching supplies raise it.

## What's suspicious

None of these is an alert yet; they are what the next slice's rules
will read, and what to look at by hand until then.

- **Spoofing**: every satellite's C/N0 uniform and high at once, the
  set used by the solution changing while the sky does not, the
  position still while the clock offset steps, GST sigmas collapsing to
  near zero. Humphreys et al., *Assessing the spoofing threat*, ION
  GNSS 2008.
- **Jamming**: mean C/N0 falling across the whole sky with the number
  of satellites in view unchanged, used dropping to zero with
  satellites still listed, `jam` rising into the hundreds.
- **Time jump**: the clock offset stepping by seconds between passes;
  the receiver's time running backwards against sloth's monotonic
  clock.
- **Position jump**: consecutive fixes further apart than the reported
  speed and accuracy allow.

A detector needs its source first (agents/AGENTS.md: detectors cite
their sources), and it is noted in [the GNSS wiki page](../wiki/gnss.md)
that none of the four has an honest ATT&CK technique.

## See also

- [Sensor location](../wiki/location.md) — the position half of the
  same receiver, and what it stamps.
- [JSONL schema](../wiki/jsonl-schema.md) — `gnss_fix`, `gnss_sky`,
  `gnss_sat`, the `gnss_*` `sensor_health` fields.
- [SQLite schema](../wiki/sqlite-schema.md) — `gnss_fixes`,
  `gnss_sightings` (v10).
