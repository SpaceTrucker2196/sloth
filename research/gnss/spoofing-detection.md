---
source_url: https://doi.org/10.1109/JPROC.2016.2526658
retrieved: 2026-11-02
topics: [gnss, gps, spoofing, c-n0, rpm, drift-monitoring, u-blox-7, gpsd, sky, tpv, consumer-receiver]
# The detector does not exist yet. ALERT_TYPE_GNSS_SPOOF_SUSPECT is not in
# include/sloth_alerts.def, and test_no_document_cites_a_nonexistent_alert_kind
# fails on any alert_kinds entry the enum lacks. Uncomment the line below in
# the same commit that adds the X() entry.
# alert_kinds: [ALERT_TYPE_GNSS_SPOOF_SUSPECT]
citation: Psiaki, Humphreys, "GNSS Spoofing and Detection", Proc. IEEE 104(6):1258-1270, 2016; + Humphreys et al. ION GNSS 2008
---
# GNSS spoofing — what a consumer receiver behind gpsd can observe, and what it cannot

The basis for the planned `ALERT_TYPE_GNSS_SPOOF_SUSPECT` (GNSS
observation layer: a u-blox 7 USB receiver read through gpsd 3.27, SKY
and TPV). Every source below was read first-hand on 2026-11-02; the
full list is under **Sources**. Papers that the read sources cite but
that were not themselves read (Akos 2012 on AGC; the Volpe report;
Warner & Johnston 2003) back nothing here.

**Verdict.** The sources support a *suspicion* built from several weak
observables, not a detection. Psiaki & Humphreys state that "All
current COTS GNSS receivers are vulnerable to spoofing attacks" (§VI),
and Humphreys et al. 2008 conclude "nothing short of cryptographic
authentication can guard against a sophisticated spoofing attack"
(§VII). A u-blox 7 has no authentication and no spoofing detector of
its own (below). Everything sloth can do is downstream of the
receiver's own solution.

## What the u-blox 7 lacks

u-blox 7 Receiver Description incl. Protocol Specification V14
(GPS.G7-SW-12001-B, 1 Feb 2013): UBX-NAV-STATUS `flags2` (§39.10,
p. 165-166) defines only `psmState` (power save mode state). The word
"spoof" occurs nowhere in the 196-page document.

u-blox 8 / M8 Receiver Description (UBX-13003221 R28, 30 Jan 2023):
§16 "Spoofing Detection" is "not supported in protocol versions less
than 18"; NAV-STATUS `flags2` gains `spoofDetState` (0 unknown or
deactivated, 1 no spoofing indicated, 2 spoofing indicated, 3 multiple
indications, p. 390). Two limits stated there carry over to anything
sloth builds: "the detection is only successful when the signal is
genuine first and when the transition to the spoofed signal is being
observed directly. When a receiver is started up to a spoofed signal
the detection algorithms will be unable to recognize the spoofing", and
"the detection does not work in single GNSS mode" (§16.2, p. 70). A
value of 1 "does not mean that the receiver is not spoofed".

The u-blox 7 is protocol version 14, so it has neither. gpsd 3.27's
u-blox driver (`drivers/driver_ubx.c`, tag release-3.27) does not parse
`spoofDetState` on any receiver; no gpsd JSON field carries it.

## What gpsd exposes

From gpsd_json(5) at gpsd.io, read 2026-11-02:

- SKY `satellites[]`: `PRN` and `used` always present; `az`, `el`
  ("Elevation in degrees"), `ss` ("Signal to Noise ratio in dBHz" —
  this is the C/N0 the receiver reports), `gnssid`, `svid`, `health`
  optional. SKY also carries `hdop`, `pdop`, `gdop`, `tdop`, `nSat`,
  `uSat`.
- TPV: `mode`, `time`, `lat`/`lon`, `speed`, `eph`, `epx`, `epy`, `eps`,
  `ept`, `clockbias`, `clockdrift`, `leapseconds`, `jam`. "All error
  estimates (epc, epd, epe, eph, ept, epv, epx, epy) are guessed to be
  95% confidence, may also be 50%, one sigma, or two sigma ... Use error
  estimates with caution, and only as relative 'goodness' indicators."

The u-blox 7 spec's NAV-SVINFO (§39.11, p. 167-168) shows the receiver
side: `elev` is a signed integer in degrees and `orbitAvail` means
"Ephemeris or Almanac", so `el`/`az` are the receiver's own computation
from whatever orbit data it holds — data a spoofer supplies.

## Heuristic 1: absolute C/N0 too high

**Basis.** Psiaki & Humphreys §III-A: Received Power Monitoring "looks
at the total received power on an absolute scale"; "a sudden power jump
could indicate an attack, especially if the increase were more than 1
or 2 dB" — but that is total RF power including the AGC setpoint, which
gpsd does not export (see the jamming document). §V calls RPM the
"obvious inexpensive method", with "Clock drift monitoring and scanning
for strange jumps in observables" "close seconds".

**Observable.** SKY `ss` per satellite: the per-signal half of RPM only.

**Thresholds.** Inside GNSS, "Measuring GNSS Signal Strength" (GNSS
Solutions, Nov/Dec 2010; answer by Angelo Joseph): typical L1 C/A
"C/N0: ~ 37 to 45dB-Hz", nominal received power "-158.5dBW" varying
±4 dB, and two receivers on the same antenna may report different C/N0.
Kriezis, Chen, Akos, Lo, Walter, arXiv:2509.13600v2 (preprint; v1
2025-09-17, v2 2026-07-17):
a GPS spoofing threshold "set to 53 dB-Hz" — for a u-blox F9P with an
ANN-MB antenna, calibrated from nominal data. Neither number transfers
to a u-blox 7 with an unknown antenna; both say the threshold must be
calibrated per receiver and antenna. Spens et al. (NAVI 2022, below)
say the same of phones.

**False positives.** Antenna gain and front-end noise figure (Inside
GNSS); a high-gain or amplified antenna; a GPS repeater, which DHS 2017
names as a source of unintentional spoofing.

## Heuristic 2: C/N0 uniform across satellites

**Basis — weak.** The idea is that one transmitter delivers every
counterfeit signal at one power, erasing the elevation dependence
authentic signals show (Inside GNSS: power "will vary in relation to
the satellite elevation angle"). DHS 2017 (Development Strategy 8)
gives the stationary form: "take advantage of the repeating ground
track of GPS satellites to store received power levels from each
satellite over time and comparing newly received power levels to the
reference values". **No peer-reviewed source read for this document
states a uniformity (low-spread) threshold**; the statements found were
an unreviewed 2026 preprint and a GitHub project's documentation, which
back nothing here. A spread statistic is therefore a judgement, and
the rule must say so.

**Observable.** Spread of SKY `ss` over `used` satellites, and its
deviation from a per-PRN, per-elevation baseline for a fixed sensor.

**False positives.** Few satellites (spread undefined); indoor or
window placement, where every signal arrives attenuated through the
same path; multipath and obstruction, which Kriezis et al. say "can
produce signatures similar to those of jamming".

## Heuristic 3: loss of lock on all satellites, then reacquisition

**Basis.** Psiaki & Humphreys §II-B: one capture method is "to start
by jamming the victim in order to disrupt normal tracking and induce
re-acquisition"; if spoofed signals are stronger "the receiver will
lock with high probability onto the false signals during
re-acquisition". Humphreys et al. 2008 §II: an unsynchronized attack
"may cause the victim receiver to lose lock and have to undergo a
partial or complete reacquisition. Such a forced re-acquisition would
raise suspicion", and "extended jamming is itself telltale evidence of
interference". DHS 2017 (Development Strategy 7): after interference,
"it can be prudent to delay reacquiring the signal for many minutes or
hours ... to reduce the potential for acquiring spoofing signals".

**Observable.** TPV `mode` falling to 1 with SKY `uSat` 0, then a fix
whose position or time differs from the last good one — the sequence,
not either half.

**False positives.** Cold or warm start (u-blox 7 §9, p. 19: cold
start must "search the full time and frequency space"); USB
re-enumeration; a moving receiver passing under cover.

## Heuristic 4: position or time jump

**Basis.** Psiaki & Humphreys §II-D: "A stealthy spoofing attack should
not attempt to alter the victim's position or timing fix too rapidly.
Otherwise, the attack may be recognized by the unphysical nature of
the changes" (the yacht test, "above 900 kts"); §III-C drift monitoring
on clock and position. Humphreys et al. 2008 §II: "The victim receiver
could flag jumps of more than, say, 100 ns". These are the subjects of
`ALERT_TYPE_GNSS_TIME_JUMP` and `ALERT_TYPE_GNSS_POSITION_JUMP`; see
`research/gnss/time-and-position-integrity.md` for why 100 ns is not
observable through gpsd on USB.

## Heuristic 5: impossible elevation/azimuth

**Basis — none found for detection.** No read source proposes checking
reported `el`/`az` against an independent ephemeris as a spoofing test.
What the sources do establish: the receiver computes `el`/`az` from
ephemeris or almanac (u-blox 7 NAV-SVINFO `orbitAvail`), which DHS 2017
calls "data spoofing" when forged; so a consistent spoofer produces
consistent sky positions. A negative `el` for a `used` satellite is
physically odd at a ground receiver but can come from almanac-only
orbits after a warm start (u-blox 7 §9: warm start holds "coarse
satellite position data (Almanac)"). Treat as a weak corroborator only.

## Heuristic 6: DOP inconsistent with the visible geometry

**Basis — none found for detection.** gpsd's own `libgpsd_core.c`
(release-3.27) documents the az/el line-of-sight-matrix computation it
uses to fill DOPs a receiver does not report, and quotes SiRF that a
receiver deweights satellites, so "we cannot exactly duplicate what
SiRF does internally". A mismatch between reported and recomputed DOP
is therefore expected in normal operation. Not a usable signal without
a cited tolerance; none exists in the read sources.

## Heuristic 7: clock drift steps

**Basis.** Psiaki & Humphreys §III-C: "If the spoofer causes the
receiver clock error to change too rapidly, then the victim receiver
can detect that the rate of clock drift is larger than is reasonable
for its class of oscillator". **Observable.** TPV `clockbias` (ns) and
`clockdrift` (ns/s), both optional in gpsd_json. gpsd 3.27's u-blox
driver enables UBX-NAV-CLOCK on every protocol version (`ubx_nav_on`,
skipped in passive mode) and `ubx_msg_nav_clock()` copies its `clkB`
(ns) and `clkD` (ns/s) into them; the u-blox 7 documents NAV-CLOCK
(§39.2, p. 157). So the path exists in source. The driver's own comment
says a u-blox 6 "sets clockbias and clockdrift to 0", so measure what a
u-blox 7 actually reports before a rule depends on it. No oscillator class for the u-blox 7 was found in the read
documents, so no drift-rate bound can be cited.

## What this document does not establish

- **No threshold for the u-blox 7.** Every number above was measured on
  other hardware or is an illustration ("say, 100 ns").
- **No defence against a careful spoofer.** Psiaki & Humphreys Fig. 1:
  code-phase-matched capture and drag-off "avoids detection by the
  receiver tracking loops because they all maintain lock".
- **No startup detection.** A spoofer present before sloth starts has
  no transition to observe (u-blox M8 §16.2 states the same for its own
  detector).
- **No attribution.** A repeater, a simulator and an attack look the
  same downstream of gpsd.

## Sources

- M. L. Psiaki, T. E. Humphreys, "GNSS Spoofing and Detection", Proc.
  IEEE 104(6):1258-1270, June 2016, doi:10.1109/JPROC.2016.2526658
  (bibliographic data verified via Crossref). Read from the authors'
  preprint, rnl.ae.utexas.edu/images/stories/files/papers/
  gnss_spoofing_detection.pdf; section numbers are the preprint's.
- T. E. Humphreys, B. M. Ledvina, M. L. Psiaki, B. W. O'Hanlon, P. M.
  Kintner Jr., "Assessing the Spoofing Threat: Development of a
  Portable GPS Civilian Spoofer", ION GNSS 2008, Savannah GA,
  pp. 2314-2325 (pages per the ION abstract page,
  ion.org/publications/abstract.cfm?articleID=8132). Read
  from rnl.ae.utexas.edu/images/stories/files/papers/
  ion2008r01_for_distributionW.pdf.
- N. Spens, D.-K. Lee, F. Nedelkov, D. Akos, "Detecting GNSS Jamming
  and Spoofing on Android Devices", NAVIGATION 69(3), 2022,
  doi:10.33012/navi.537.
- A. Kriezis, Y.-H. Chen, D. Akos, S. Lo, T. Walter, "GNSS Jamming and
  Spoofing Monitoring Using Low-Cost COTS Receivers", arXiv:2509.13600v2
  (v1 2025-09-17, v2 2026-07-17; preprint, venue unconfirmed).
- Inside GNSS, "Measuring GNSS Signal Strength", 2010-12-02.
- u-blox, GPS.G7-SW-12001-B (u-blox 7, protocol 14.00), 2013-02-01;
  u-blox, UBX-13003221 R28 (u-blox 8 / M8), 2023-01-30.
- DHS NCCIC/NCC, "Improving the Operation and Development of Global
  Positioning System (GPS) Equipment Used by Critical Infrastructure",
  2017-01-06.
- gpsd_json(5), gpsd.io/gpsd_json.html; gpsd release-3.27
  `drivers/driver_ubx.c`, `gpsd/libgpsd_core.c` (gitlab.com/gpsd/gpsd).
