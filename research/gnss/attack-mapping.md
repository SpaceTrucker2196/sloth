---
source_url: https://attack.mitre.org/techniques/T1464/
retrieved: 2026-11-02
topics: [gnss, gps, jamming, spoofing, mitre, att&ck, ics, mobile, technique-mapping, exemption]
# Names the four planned GNSS kinds in prose only; see the other three
# research/gnss/ documents for why alert_kinds is commented out.
citation: MITRE ATT&CK Mobile T1464; ICS T0830, T0814, T1692.002 (was T0856); Enterprise T1498 — read 2026-11-02
---
# GNSS spoofing and jamming against ATT&CK — which technique, if any, is honest

Whether the four planned GNSS kinds get an `alert_technique()` value,
or take the second exemption form in `agents/AGENTS.md` (a real,
citable basis but no honest ATT&CK technique, pinned by
`tests/test_research_corpus.c ::
test_uncitable_kinds_with_a_real_basis_are_still_cited`). Every page
below was fetched from attack.mitre.org on 2026-11-02, and the
Enterprise, Mobile and ICS technique lists were each searched for
"GPS", "GNSS", "jamm" and "satellite navigation".

**Result.** One technique in any matrix names GPS jamming: **Mobile
T1464**. No technique in any matrix names GNSS spoofing.

## Mobile T1464 — Network Denial of Service

"Network DoS can be performed by exhausting the network bandwidth that
services rely on, or by jamming the signal going to or coming from
devices. A Network DoS will occur when an adversary is able to jam radio
signals (e.g. Wi-Fi, cellular, GPS) around a device to prevent it from
communicating." Tactic Impact; platforms Android, iOS; MTC IDs include
GPS-0; version 1.4, created 25 October 2017, last modified 19 May 2025.

The text fits `ALERT_TYPE_GNSS_JAMMING` literally. Two reservations,
stated so the owner can rule: it is a **Mobile** technique (every ID in
`include/sloth_alerts.def` today is Enterprise), and the observable
cannot separate jamming from unintentional interference (DHS 2017, in
`research/gnss/jamming-detection.md`). The second did not stop
`RF_DEGRADED` taking T1498 as "the observable, not a claim of intent"
(its comment in the .def), so on precedent it does not disqualify.

**Recommendation:** `X(GNSS_JAMMING, "T1464")`, with a comment
naming the matrix. If the owner prefers to keep the .def Enterprise-only,
the exemption form is the honest alternative — not T1498.

## Enterprise T1498 — Network Denial of Service

"Network DoS can be performed by exhausting the network bandwidth
services rely on. Example resources include specific websites, email
services, DNS, and web-based applications." Bandwidth of a network
connection; a GNSS receiver is not on one. **Not a fit** for jamming.
(`research/mitre/T1498.md` argues airtime is the 802.11 resource; there
is no shared network airtime between sloth and the GNSS constellation.)

## ICS T0830 — Adversary-in-the-Middle

"Adversaries with privileged network access may seek to modify network
traffic in real time"; "the most-common are Address Resolution Protocol
(ARP) poisoning and the use of a proxy". Network traffic between ICS
devices. **Not a fit** for spoofing: a spoofer does not sit between two
parties of a network session, it transmits counterfeit satellite
signals.

## ICS T0856 — Spoof Reporting Message (now T1692.002)

attack.mitre.org/techniques/T0856/ now redirects to
**T1692.002 Unauthorized Message: Reporting Message** (created 20 April
2026). "In control systems, reporting messages contain telemetry data
(e.g., I/O values) pertaining to the current state of equipment and the
industrial process." A GNSS signal is not an ICS reporting message, and
the procedure example is the Maroochy radio telemetry case. **Not a
fit.** Note for anyone citing T0856 elsewhere: the ID is superseded.

## ICS T0814 — Denial of Service

"Adversaries may perform Denial-of-Service (DoS) attacks to disrupt
expected device functionality. Examples of DoS attacks include
overwhelming the target device with a high volume of requests". Request
floods and crafted inputs against a device. **Not a fit** for RF
jamming of a receiver.

## Recommendation for the other three kinds

`ALERT_TYPE_GNSS_SPOOF_SUSPECT`, `ALERT_TYPE_GNSS_TIME_JUMP` and
`ALERT_TYPE_GNSS_POSITION_JUMP`: **empty technique, second exemption
form.** Each has a real basis — Psiaki & Humphreys 2016, Humphreys et
al. 2008, DHS 2017, chrony and gpsd documentation, in
`research/gnss/spoofing-detection.md` and
`research/gnss/time-and-position-integrity.md` — and no ATT&CK
technique describes the behaviour. Each belongs on the explicit list in
`test_uncitable_kinds_with_a_real_basis_are_still_cited`, added in the
same commit as its `.def` entry, with its `alert_kinds` line in the
backing document uncommented. TIME_JUMP and POSITION_JUMP can also come
from faults (week rollover, cold start), which is a second reason not
to assign an adversary technique.
