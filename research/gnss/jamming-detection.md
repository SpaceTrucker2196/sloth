---
source_url: https://www.cisa.gov/resources-tools/resources/paper-improving-operation-and-development-gps-equipment-used-critical-infrastructure
retrieved: 2026-11-02
topics: [gnss, gps, jamming, interference, c-n0, agc, mon-hw, jamind, u-blox-7, gpsd, fcc, gpsjam]
# The detector does not exist yet. ALERT_TYPE_GNSS_JAMMING is not in
# include/sloth_alerts.def, and test_no_document_cites_a_nonexistent_alert_kind
# fails on any alert_kinds entry the enum lacks. Uncomment the line below in
# the same commit that adds the X() entry.
# alert_kinds: [ALERT_TYPE_GNSS_JAMMING]
citation: DHS NCCIC/NCC, "Improving the Operation and Development of GPS Equipment Used by Critical Infrastructure", 2017-01-06
---
# GNSS jamming — what a u-blox 7 behind gpsd reports, and what that cannot tell apart

The basis for the planned `ALERT_TYPE_GNSS_JAMMING`. Every source below
was read first-hand on 2026-11-02; the list is under **Sources**.

**Verdict.** The sources support flagging *interference* — C/N0
collapsing on every satellite at once while the sky is unchanged, with
the receiver's CW indicator as corroboration — and do not support
calling it intentional. DHS 2017 defines the two as the same physical
effect: "Jamming is intentionally produced RF waveforms that have the
same effect as interference; the only difference is the intent".

## The DHS 2017 paper

NCCIC / NCC, "Improving the Operation and Development of Global
Positioning System (GPS) Equipment Used by Critical Infrastructure",
TLP:WHITE, PDF dated 2017-01-06, listed by CISA as "Paper on Improving
the Operation and Development of GPS Equipment Used by Critical
Infrastructure" (January 06, 2017). PDF:
cisa.gov/sites/default/files/documents/Improving_the_Operation_and_Development_of_Global_Positioning_System_%28GPS%29_Equipment_Used_by_Critical_Infrastructure_S508C.pdf

- Threat characterization A: "Interference arises from unintentionally
  produced RF waveforms that raise the effective noise floor in the
  receiver processing".
- Development Strategy 7: the receiver "should recognize and report the
  presence of interference and jamming. Recognition can be as simple as
  monitoring for significant changes in the RF power (using a J/N meter
  or equivalent) and for changes in effective C/N0."
- Development Strategy 8: "Inspecting RF power levels to identify
  either sequential or concurrent knockoff jamming" — jamming as the
  first step of a spoofing attack.

It gives no numeric threshold.

## What the u-blox 7 measures

u-blox 7 Receiver Description incl. Protocol Specification V14
(GPS.G7-SW-12001-B):

- §13.2 (p. 33): "The field jamInd of the UBX-MON-HW message can be
  used as an indicator for continuous wave (narrowband)
  jammers/interference only. ... It is necessary to run the receiver in
  the application and then calibrate the 'not jammed' case." "This
  indicator is always enabled."
- §13.3 (p. 33-34): `jammingState` (the ITFM monitor) covers "both
  broadband and continuous wave (CW)" interference, states 0 unknown,
  1 OK, 2 warning ("position ok but interference is visible"),
  3 critical ("no reliable position fix and interference is visible").
  "The monitor is disabled by default" and is enabled by UBX-CFG-ITFM;
  it "will only function when the receiver has had at least one (good)
  first fix". Default thresholds (Appendix B.18, p. 194): broadband
  3 dB, CW 15 dB, "the dB level above 'normal'".
- §38.2 MON-HW (p. 150-151): `agcCnt` "AGC Monitor (counts SIGHI xor
  SIGLO, range 0 to 8191)"; `jamInd` "CW Jamming indicator, scaled (0 =
  no CW jamming, 255 = strong CW jamming)".

So the u-blox 7 does support all three. Whether sloth sees them is
gpsd's choice.

## What gpsd 3.27 passes through

gpsd release-3.27, `drivers/driver_ubx.c`, `ubx_msg_mon_hw()`:

- `jamInd` is copied to `session->newdata.jam`, which gpsd_json(5)
  documents as TPV `jam`: "Jamming Indicator 0 (no jamming) to 255
  (severe jamming). -1 means unset."
- `agcCnt` and the `flags` byte holding `jammingState` are decoded only
  into log messages (`GPSD_LOG`). **Neither reaches the JSON.**
- At init, gpsd sends CFG-MSG for MON-HW "every 4" epochs when the
  protocol version is below 27 — unless gpsd runs in passive mode
  (`-p`, "Do not autoconfigure the receiver"). No code in the driver
  sends UBX-CFG-ITFM (0x06 0x39), so `jammingState` stays 0, unknown,
  unless someone enables ITFM out of band.

The observable set is therefore: TPV `jam` (CW only, uncalibrated,
roughly every fourth epoch), SKY `ss` per satellite, SKY `uSat`, TPV
`mode`. Broadband interference has no gpsd field except its effect on
`ss`.

## The C/N0 signature

Spens, Lee, Nedelkov, Akos, NAVIGATION 69(3) 2022 (§3.4), crediting
Manfredini et al. 2018: "If AGC decreases and C/N0 decreases, jamming
is likely. If AGC decreases and C/N0 is relatively constant, spoofing is
more likely. And if AGC is unchanged, then any form of interference is
unlikely and poor signal may be attributed to attenuation." Their AGC
threshold (§5.1), "5-dB ... based on the range of AGC values observed during
nominal testing on the S20+", is a phone's, and "This threshold will be
different for all phones". sloth has no AGC through gpsd, so it can
apply only the C/N0 half — which is exactly the half that cannot tell
interference from attenuation.

Kriezis et al., arXiv:2509.13600v2 (preprint): a u-blox F9P monitor
calibrated per receiver; "Physical obstructions, scintillation and
multipath effects can produce signatures similar to those of jamming";
signal loss "defined as 27 dB-Hz for the purposes of this paper".

The jamming signature sloth can see is the **simultaneity**: every
tracked satellite's `ss` falling within one or two epochs, across
elevations, while `nSat` is unchanged, ending in loss of fix with
satellites still listed. Attenuation by an obstruction is
direction-dependent; a noise-floor rise is not. No read source puts a
number on "simultaneous" or on the drop; any value is a judgement.

## Legal status (United States)

FCC, "Jammer Enforcement" (fcc.gov/general/jammer-enforcement; read via
the 2026-10-22 Wayback capture, page marked "Updated September 2026"):
"Under 47 U.S.C. §§ 302a(b) and 333 of the Communications Act of 1934
... it is generally illegal (with few exceptions) to operate,
manufacture, market, sell, import, distribute, or ship a radiofrequency
(RF) jamming device designed to interfere with authorized radio
communications such as those involving cell phones, GPS, Wi-Fi". "There
are no exceptions for personal, commercial, educational, or vehicular
use." Signs listed include "Loss of GPS signals and location services";
the page also warns that signal failures have ordinary causes.

FCC 13-106, *Gary P. Bojczak*, NAL released 2013-08-02: a GPS jammer
in a pickup interfered with the "ground-based augmentation system" at
Newark Liberty; proposed forfeiture $31,875 under 47 U.S.C. §§ 301,
302a(b), 333. The respondent used it to block his employer's vehicle
tracking: the case shows a jammer aimed at one receiver affecting
another nearby, not an attack on the affected system.

## Why GPSJam's map is not this

GPSJAM FAQ (gpsjam.org/faq): the map "aggregates that data over 24
hours", hex colour from the share of aircraft reporting low
navigation accuracy (the FAQ does not name the ADS-B field; NACp, below,
is the one that carries position accuracy); "the data doesn't tell me
what's causing the low accuracy"; aircraft "fly thousands of feet above
the ground where they have line-of-sight to many more potential sources
of GPS interference than you do on the ground". 14 CFR 91.227(c)(1)
requires NACp "less than 0.05 nautical miles" and NIC "less than 0.2
nautical miles" for ADS-B Out, so a "bad" aircraft is one whose own
navigation integrity fell below an aviation bound.

The difference for sloth: GPSJam is many receivers, at altitude, over a
day, reporting a derived accuracy; sloth is one fixed ground receiver,
per epoch, reporting raw C/N0. A red hex says nothing about a ground
site, and a ground-level event will not appear on the map.

## u-blox application note

Searched for a u-blox jamming/interference application note; none was
found. The vendor's own description is §13 of the protocol
specification, above.

## What this document does not establish

- **No threshold** for `jam`, for a C/N0 drop, or for "simultaneous" on
  a u-blox 7. The vendor says `jamInd` must be calibrated in place.
- **No intent.** Interference and jamming are the same effect (DHS).
- **No broadband indicator** through gpsd 3.27.
- **No location of the source.** One receiver cannot bearing a jammer.

## Sources

- DHS NCCIC/NCC, "Improving the Operation and Development of Global
  Positioning System (GPS) Equipment Used by Critical Infrastructure",
  2017-01-06 (CISA resource page and PDF above).
- u-blox, GPS.G7-SW-12001-B, u-blox 7 Receiver Description incl.
  Protocol Specification V14, 2013-02-01.
- gpsd release-3.27 `drivers/driver_ubx.c`; gpsd_json(5) and gpsd(8)
  at gpsd.io.
- N. Spens et al., NAVIGATION 69(3), 2022, doi:10.33012/navi.537.
- A. Kriezis et al., arXiv:2509.13600v2 (preprint; v2 2026-07-17).
- FCC Enforcement Bureau, "Jammer Enforcement", Updated September 2026.
- FCC 13-106, Gary P. Bojczak, NAL/Acct. No. 201332380001, 2013.
- J. Wiseman, GPSJAM FAQ, gpsjam.org/faq.
- 14 CFR 91.227 (via law.cornell.edu/cfr/text/14/91.227).
