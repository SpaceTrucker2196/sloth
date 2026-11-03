---
source_url: https://chrony-project.org/doc/latest/chrony.conf.html
retrieved: 2026-11-02
topics: [gnss, gps, time, chrony, refclock, gpsd, leap-second, week-rollover, position-jump, tpv, eph, drift-monitoring]
# The detectors do not exist yet. Neither kind is in include/sloth_alerts.def,
# and test_no_document_cites_a_nonexistent_alert_kind fails on any
# alert_kinds entry the enum lacks. Uncomment the line below in the same
# commit that adds the X() entries.
# alert_kinds: [ALERT_TYPE_GNSS_TIME_JUMP, ALERT_TYPE_GNSS_POSITION_JUMP]
citation: chrony.conf(5) refclock/trust/maxchange; gpsd time service HOWTO; GPS.gov week rollover; Psiaki & Humphreys 2016 §III-C
---
# GNSS time and position jumps — why they matter here, and how big a legitimate one is

The basis for the planned `ALERT_TYPE_GNSS_TIME_JUMP` and
`ALERT_TYPE_GNSS_POSITION_JUMP`. Every source below was read first-hand
on 2026-11-02.

**Verdict.** A jump is the observable that every spoofing source
names (Psiaki & Humphreys §II-D, §III-C; Humphreys et al. 2008 §II) and
that gpsd exposes directly. It is also produced by ordinary events —
leap seconds, week rollover in old receivers, cold starts, USB latency
— and the rule must exclude those by name rather than by a loose
threshold.

## Why a time jump matters: the receiver may steer the system clock

The owner plans GPS time into the system clock through chrony with a
gpsd refclock. From chrony.conf(5) (chrony-project.org, latest):

- `refclock SOCK`: "An application that supports the SOCK protocol is
  the gpsd daemon. It can provide accurate measurements using the
  receiver's PPS signal, and since version 3.25 also (much less
  accurate) measurements based on the timing of serial data (e.g.
  NMEA)".
- `trust`: "Assume time from this source is always true. It can be
  rejected as a falseticker in the source selection only if another
  source with this option does not agree with it." A spoofed receiver
  marked `trust` outvotes every NTP server.
- `noselect`: "Never select this source. This is useful for
  monitoring" — the safe setting while GNSS time is only compared.
- `makestep threshold limit`: steps the clock "only if there were no
  more clock updates since chronyd was started than the specified
  limit"; "On most systems it is desirable to step the
  system clock only on boot".
- `maxchange offset start ignore`: offsets larger than the maximum "will
  be ignored for the specified number of times. Another large offset
  will cause chronyd to give up and exit."

So chrony already refuses a large *step* after start-up unless told
otherwise; the exposure is `trust` or a slow pull within the slew
limits — exactly the patient drag-off Psiaki & Humphreys §II-D
describe ("The requirement of physical reasonableness forces the
spoofer to be patient"). A TIME_JUMP rule catches the impatient case;
a drift comparison against independent NTP sources is what catches the
patient one.

## How precise GNSS time through USB is

gpsd time service HOWTO (gpsd.io): in-band fix reports "are also
delayed in the receiver and on the link by as much as several hundred
mSec, and this delay is not constant ... It may be stable to 10 mSec
for hours and then jump by 200mSec. Under these circumstances you can't
expect accuracy to UTC much better than 1 second from this method."
"Note that the most popular consumer-grade GPS receivers do not usually
deliver 1PPS through USB ... In general, you can't use a USB device for
time service unless you know it has the Macx-1 mod."

Consequence: Humphreys et al. 2008's "flag jumps of more than, say,
100 ns" is a receiver-internal observable. Through gpsd on a USB
u-blox 7 with no PPS, a step under a few hundred milliseconds is
indistinguishable from link wobble. A cited lower bound for a
TIME_JUMP threshold on this hardware is therefore the HOWTO's 200 ms
jump, and anything below roughly a second is noise on its own terms.

## Edge cases that are not attacks

**Leap seconds.** gpsd HOWTO: "GPS time is not leap-second corrected";
the correction is broadcast "once every 12.5 minutes" and "may not be
available at all when a GPS receiver has just cold-booted. Thus,
reported UTC time may be slightly inaccurate between a cold boot or
leap second and the following subframe broadcast." u-blox 7 spec §6.5
(p. 10-11): users "should be prepared to handle minutes that are either 59
or 61 seconds long"; with GLONASS tracked, "users should be prepared
for the receiver to restart itself" at a leap second (§3.1, p. 4). TPV
carries `leapseconds`; a whole-second step coinciding with a change in
it, or with the first fix after a cold start, is this case.

**Week-number rollover.** GPS.gov, "GPS Week Number Rollover": the week
number "reset to zero at 23:59:42 UTC on April 6, 2019"; first rollover
"August 1999"; C/A LNAV devices "can expect the next rollover on
November 20, 2038". "Many GPS-enabled devices that were not properly
designed to account for the rollover event exhibited problems on that
date." The gpsd HOWTO: "Many GPSes have a wired-in (and undocumented)
assumption about the UTC time of the last rollover and will thus report
incorrect times outside the rollover period they were designed in." The
signature is a date error of a multiple of 1024 weeks (about 19.6
years); it is a fault, not an attack, and should be named as such.

**Cold start.** u-blox 7 §9 (p. 19): with no prior time the receiver
"must search the full time and frequency space". The first fix after
`mode` 1 has no prior to jump from; compare only fix to fix.

## How far a position can legitimately move between fixes

Psiaki & Humphreys §III-C: "the known maxima of its velocity,
acceleration, and turn rate could be used to check for excessive
drift"; §II-D's yacht spoof was caught because it showed speed "above
900 kts" for a vessel that "could not cruise above 16 kts".

What gpsd gives (gpsd_json(5)): TPV `speed` (m/s), `eps` (speed error,
m/s), `eph` ("Estimated horizontal Position (2D) Error in meters"),
`epx`/`epy` (longitude/latitude error, m), with the caveat that
estimates are "guessed to be 95% confidence, may also be 50%, one
sigma, or two sigma" and are to be used "only as relative 'goodness'
indicators".

The bound that follows is
`|Δpos| ≤ (v_max + eps)·Δt + eph₁ + eph₂`, with `v_max` the platform's
own limit — for a fixed sensor, zero, so the bound collapses to the two
error estimates. Because the confidence level of `eph` is unknown, a
multiplier on it is a judgement, not a cited value. Spens et al.
(NAVIGATION 69(3), §3.1.2) give a field number for a comparable check:
GNSS against network location, "this threshold could be set at or
below 100 m without presenting many false flags" where many access
points are visible — a phone's figure, not a u-blox 7's.

False positives: the first fix after re-acquisition, multipath at a
fixed site (the error estimate may not cover it), a 2D fix (`mode` 2)
with a fixed altitude assumption, and gpsd emitting several TPVs per
epoch ("Multiple TPV objects are often sent per epoch", gpsd_json(5)).

## What this document does not establish

- **No sub-second time detection** through USB without PPS.
- **No detection of a patient pull** within chrony's slew; that needs
  comparison against independent sources, not a jump test.
- **No velocity limit for the platform** — that is configuration.
- **No confidence level for gpsd's error estimates**, by gpsd's own
  account.

## Sources

- chrony.conf(5), chrony-project.org/doc/latest/chrony.conf.html.
- gpsd, "GPSD Time Service HOWTO", gpsd.io/gpsd-time-service-howto.html.
- gpsd_json(5), gpsd.io/gpsd_json.html.
- GPS.gov, "GPS Week Number Rollover", archive.gps.gov/support/user/
  rollover/ (page notes it "not been updated since February 2025").
- u-blox, GPS.G7-SW-12001-B (u-blox 7, protocol 14.00), 2013-02-01.
- M. L. Psiaki, T. E. Humphreys, Proc. IEEE 104(6), 2016,
  doi:10.1109/JPROC.2016.2526658 (authors' preprint).
- T. E. Humphreys et al., ION GNSS 2008, pp. 2314-2325.
- N. Spens et al., NAVIGATION 69(3), 2022, doi:10.33012/navi.537.
