---
source_url: https://arxiv.org/abs/1307.3664
retrieved: 2026-11-11
topics: [adsb, mode-s, spoofing, ghost-injection, plausibility, multilateration, data-fusion, coverage, radio-horizon, fleet]
citation: Strohmeier, Lenders & Martinovic, "On the Security of the Automatic Dependent Surveillance-Broadcast Protocol", arXiv:1307.3664v2 (2014), section V-F; the radio horizon derived here from the 4/3 effective-earth radius (no first-hand propagation source read)
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
arXiv PDF (each quotation below re-checked against the PDF's text on
2026-11-11 in review):

- The attack table names "Ghost Injection / Flooding" against both a
  ground station and an aircraft target, an application-layer message
  injection.
- Section V-F, "Traffic Modeling and Plausibility Checks": "By utilizing
  historical data as well as machine learning methods it is possible to
  create a model of a map for each ground station, providing a means to
  verify location claims made by aircraft via ADS-B." ... "Such models
  can provide hints about non-matching location claims of a message send
  by an aircraft."
  The map the survey has in mind is a heat map of received signal
  strength (its Figure 21); the cross-check's per-sector reach is a
  cruder map of the same kind, distance only.
- The same section lists simple red flags, citing (its reference [115])
  Leinmuller, Schoch and Kargl, "Position verification approaches for
  vehicular ad-hoc networks" (IEEE Wireless Communications 13(5),
  pp. 16-21, Oct. 2006; **not read**):
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
  decoded in each bearing sector over a day, taken as the median of the
  sector's hourly farthest so one bad decode or a few hours of ducting
  cannot stretch it.
- **inconsistent**: the survey's mobility threshold applied across two
  receivers: positions for one address further apart than the aircraft
  could fly in the time between them.
- Never a detection. A receiver is shadowed by terrain and buildings, its
  antenna pattern is not uniform within a sector, and a weak transponder
  is heard at shorter range than the strongest one that set the sector's
  farthest point.

## The radio horizon

No first-hand propagation source is in the corpus (no ITU-R P.453,
P.526 or P.1546, no radio handbook), so the horizon is stated as the
standard derivation, not as a cited result.

Over a smooth sphere of radius R, the tangent from a height h meets
the surface at d = sqrt(2 R h + h^2) ~ sqrt(2 R h) for h << R.
Atmospheric refraction under a standard (linearly decreasing)
refractivity gradient bends radio rays toward the earth; the usual
model keeps rays straight and enlarges the earth instead, R_eff = k R,
with k = 4/3 the conventional value for a standard atmosphere. With R =
6,371 km:

d = sqrt(2 x 4/3 x 6,371,000 m x h) = 4,122 sqrt(h) m, h in metres,

i.e. d ~ 4.12 sqrt(h) km. Two antennas see each other over the smooth
earth while the distance between them is at most the sum of their two
horizons, d = 4.12 (sqrt h1 + sqrt h2) km.

What follows: the line-of-sight limit between a receiver on the ground
and an aircraft at height h above it is 4.12 sqrt(h) km; a position
beyond it was not decoded over a line of sight. The model is
deliberately simple: k varies with the weather (ducting raises it far
above 4/3 for hours at a time, which is why the cross-check's reach is
a median of hours), terrain is ignored, and an aircraft's reported
altitude is barometric (pressure altitude), not its height above the
site. Wikipedia's "Line-of-sight propagation" (section "Atmospheric
refraction") gives the same 4/3 and 4.12 figures and was used only as a
cross-check of the arithmetic, not as the basis.

## What this document does not establish

- **No threshold.** "Well within" is unquantified in the survey. The
  cross-check's 0.8 of the sector's reach and of the horizon,
  its 30-degree sectors, its minimum of 10 positions in a sector, its 2
  other aircraft heard, its 120 s window and its mobility allowance
  (ground speed x 1.25 + 30 m/s, plus 2 km) are choices.
- **No antenna height.** The horizon needs the antenna's height above
  the terrain, which sloth does not know; the cross-check credits none
  (0 m), the choice that can only shorten the horizon, and takes the
  aircraft's height as its reported altitude less the site's own (a
  site with no altitude decides nothing).
- **No timing.** Multilateration needs receive timestamps synchronised
  across receivers; a decoder's JSON and sloth's records carry none.

## Related

- `research/adsb/emergency-squawks.md` — ADS-B's lack of authentication.
- `docs/wiki/fleet.md` — "Aircraft across the sites".
