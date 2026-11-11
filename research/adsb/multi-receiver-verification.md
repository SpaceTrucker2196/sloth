---
source_url: https://arxiv.org/abs/1307.3664
retrieved: 2026-11-11
topics: [adsb, mode-s, spoofing, ghost-injection, plausibility, multilateration, data-fusion, coverage, radio-horizon, fleet]
citation: Strohmeier, Lenders & Martinovic, "On the Security of the Automatic Dependent Surveillance-Broadcast Protocol", arXiv:1307.3664v2 (2014), section V-F; Wikipedia, "Line-of-sight propagation", section "Atmospheric refraction"
---
# ADS-B position claims checked against a second receiver

The basis for the fleet's aircraft cross-check (slothweb
`/api/fleet/aircraft`, `web/src/web_fleetadsb.h`, #192 I7). That is a
slothweb fleet finding, not a sloth alert, so this document indexes under
no alert kind. Read first-hand on 2026-11-11 unless a line says
otherwise.

**Verdict.** A ground receiver that demonstrably hears a region, and was
hearing other aircraft at the time, but did not hear an aircraft another
receiver placed inside that region is a plausibility red flag of the kind
the literature lists: neither necessary nor sufficient for an attack, a
reason to look. Nothing read here puts a number on "well within" or on
how many positions make a coverage map; every threshold the cross-check
uses is a choice and is said to be one.

## Why a position claim needs checking

ADS-B carries no authentication: see `research/adsb/emergency-squawks.md`
for Costin & Francillon (Black Hat USA 2012) and Schafer, Lenders &
Martinovic (ACNS 2013), both read 2026-11-08, on injecting and modifying
messages with a software-defined radio.

M. Strohmeier, V. Lenders and I. Martinovic, "On the Security of the
Automatic Dependent Surveillance-Broadcast Protocol", arXiv:1307.3664v2
[cs.CR], 15 Apr 2014 (University of Oxford; armasuisse), read from the
arXiv PDF:

- The attack table names "Ghost Injection / Flooding" against both a
  ground station and an aircraft target, an application-layer message
  injection.
- Section V-F, "Traffic Modeling and Plausibility Checks": "By utilizing
  historical data as well as machine learning methods it is possible to
  create a model of a map for each ground station, providing a means to
  verify location claims made by aircraft via ADS-B." ... "Such models
  can provide hints about non-matching location claims of a message send
  by an aircraft."
- The same section lists simple red flags, citing Leinmuller, Schoch and
  Kargl (IEEE Wireless Communications 13(5), 2006; **not read**):
  "Investigating airplanes which suddenly appear well within the maximum
  communication range of a receiver"; "Dropping aircraft which are
  violating a given acceptance range threshold, producing impossible
  locations"; "Aircraft violating a given mobility grade threshold,
  producing impossible minimum or maximum velocities."
- And the caution the cross-check keeps: "Neither of these rules are
  necessary nor sufficient by themselves to detect an ongoing attack" but
  "plausibility checks can be very useful in practice."
- Section V-A (multilateration) and V-E (data fusion): several receivers
  with known positions can verify a claimed position by time difference
  of arrival; this needs synchronised receivers sloth does not have. The
  fleet cross-check is the coarse, presence-only form: did a receiver
  that should have heard it hear it at all.

What follows for the cross-check:

- **unconfirmed**: an aircraft one receiver placed well inside a second
  receiver's demonstrated range, which the second, receiving other
  aircraft, did not hear. "Demonstrated range" is the survey's per-station
  map in its simplest form: the farthest position the receiver itself
  decoded in each bearing sector over a day.
- **inconsistent**: the survey's mobility threshold applied across two
  receivers: positions for one address further apart than the aircraft
  could fly in the time between them.
- Never a detection. A receiver is shadowed by terrain and buildings, its
  antenna pattern is not uniform within a sector, and a weak transponder
  is heard at shorter range than the strongest one that set the sector's
  farthest point.

## The radio horizon

Wikipedia, "Line-of-sight propagation"
(https://en.wikipedia.org/wiki/Line-of-sight_propagation), section
"Atmospheric refraction", subsection "Refracted distance to horizon",
read 2026-11-11: under normal conditions the effective-earth factor "k is
usually chosen to be 4/3", giving "d ≈ 4.12 · √h for h in metres and d
in kilometres"; and "The radio horizon of the transmitting and receiving
antennas can be added together to increase the effective communication
range."

What follows: d = 4.12 (√h_rx + √h_ac) km, the line-of-sight limit
between a receiving antenna and an aircraft over a smooth 4/3 earth. A
position beyond it was not decoded over a line of sight. The ITU-R
recommendations that define the effective-earth model were **not read**.

## What this document does not establish

- **No threshold.** "Well within" is unquantified in the survey. The
  cross-check's 0.8 of the sector's farthest position and of the horizon,
  its 30-degree sectors, its minimum of 10 positions in a sector, its 2
  other aircraft heard, its 120 s window and its mobility allowance
  (ground speed x 1.25 + 30 m/s, plus 2 km) are choices.
- **No antenna height.** The horizon needs the antenna's height above
  the terrain, which sloth does not know; 10 m is a choice, and the
  aircraft's height is its reported altitude less the site's.
- **No timing.** Multilateration needs receive timestamps synchronised
  across receivers; a decoder's JSON and sloth's records carry none.

## Related

- `research/adsb/emergency-squawks.md` — ADS-B's lack of authentication.
- `docs/wiki/fleet.md` — "Aircraft across the sites".
