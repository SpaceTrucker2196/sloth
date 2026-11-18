---
source_url: https://mrncciew.com/2023/10/06/multiple-bssid-mbssid/
retrieved: 2026-11-09
topics: [karma, pineap, mbssid, multi-vap, rsne, ie-fingerprint]
alert_kinds: [ALERT_TYPE_KARMA_AP]
citation: "Rasika Nayanajith, \"Multiple BSSID (MBSSID)\", mrncciew.com, 2023-10-06 (practitioner lab captures, not normative text)"
---
# What per-BSS IE variation can and cannot tell a passive sensor

The basis for the **IE-fingerprint collapse** signal on `KARMA_AP`
(#187 S4): across the distinct SSIDs one BSSID advertises, sloth counts
the distinct IE fingerprints (`karma_ie_distinct_fp()`,
`src/karma_detect.c`). This document exists because the *rationale*
that signal is usually given does not survive checking, and the weight
is sized to what survives rather than to the story.

## The claim that does not hold

The signal is normally explained as: a legitimate multi-VAP AP varies
its RSN and vendor IEs per VAP, because guest, corporate and IoT VAPs
carry different security; a single spoofing radio does not; so
uniformity separates the two. That contrast is real in the abstract and
**sloth cannot draw it**, for two independent reasons:

1. **A BSSID is associated with exactly one BSS.** Real multi-SSID gear
   runs each SSID as a virtual AP with *its own* BSSID, derived from the
   physical radio's base MAC — by flipping the locally-administered bit
   per VAP, or by assigning each VAP an address from a pool [2]. To a
   client each VAP "appears as an independent access point with its own
   unique SSID" [2]. sloth's `ssid_history[]` is per BSSID
   (`beacon_snoop.c`), so each of those VAPs contributes **one** SSID to
   **its own** row and never reaches `KARMA_SSID_THRESH`. The benign
   population this signal claims to separate is not in the candidate
   set at all.

2. **The one shape that does put several SSIDs behind one address is not
   decoded.** In an 802.11ax Multiple BSSID set a single *transmitted*
   BSSID beacons on behalf of *nontransmitted* BSSIDs, each described by
   a Nontransmitted BSSID Profile carrying at minimum its own SSID
   element [1]. sloth does not decode those profiles
   (`docs/wiki/fragattacks.md`), so a Multiple BSSID set contributes
   only the transmitted BSSID's own SSID.

## And where it would hold, it holds weakly

Even inside a Multiple BSSID set, per-profile IE differences appear only
when the SSIDs are *configured* differently. In the source's own first
capture every SSID shared one security configuration, and the author
notes those settings are "common across all SSIDs" and that he "did not
see much of a difference in 'non-transmitted' BSSID profile Information
Elements (IE)"; only after changing the security settings did the
nontransmitted SSIDs receive "all those additional information elements
where the configuration does not match with the 'transmitted SSID'"
[1]. So uniform IEs across one address is the *default* for a uniformly
configured estate, not a tell.

**Not claimed here:** the source gives no IEEE clause number or element
ID for the Multiple BSSID element, and never names the RSNE directly —
the per-profile security reading is its described behaviour, not a quoted
normative requirement [1]. No clause number is asserted anywhere in this
document or in the code comments that cite it. [2] is patent text
describing the general VAP-addressing pattern, not a vendor
implementation or the standard; derivation schemes vary.

## What the signal is therefore worth

The benign cases that actually cross the threshold — a BSS renamed over
a long session, hotspot or captive-portal gear cycling SSIDs — keep one
security posture, so they collapse exactly as a lure does. A collapse is
therefore **weak, same-direction corroboration**: it earns
`KARMA_W_IE_COLLAPSE` = 10 confidence, sits in the informational tier
beside `KARMA_W_PMKID`, and never escalates severity. The attack side is
cited where the rest of KARMA's basis lives
(`research/mitre/T1557.md`, `docs/wiki/alert-assessments/KARMA_AP.md`):
PineAP answers for its whole SSID pool from "a single BSSID, or ... a
pseudo-random BSSID for each SSID", so the single-BSSID configuration is
one radio choosing its own posture once.

The **converse** is the better-founded half: a distinct-fingerprint
count that tracks the SSID count means that one address really is
presenting different security postures per name, which a single
spoofing radio does not do. sloth reports the count in both directions
for that reason. It is not spent as negative confidence today — see
`docs/views/karma.md` § Open.

## Bibliography

1. Rasika Nayanajith, "Multiple BSSID (MBSSID)", mrncciew.com,
   2023-10-06 — https://mrncciew.com/2023/10/06/multiple-bssid-mbssid/
   (read 2026-11-09). Transmitted vs nontransmitted BSSIDs; the SSID and
   Multiple BSSID-Index elements are mandatory in a profile; two lab
   captures, before and after changing per-SSID security, with the
   quoted observations above. Practitioner source.
2. US 7,701,912 B2, "System and method for concurrently utilizing
   multiple system identifiers" —
   https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/7701912
   (read 2026-11-09). Per-VAP BSSIDs derived from the physical AP's base
   MAC, by locally-administered-bit modification or from an address
   pool; each VAP appears to a client as an independent AP with its own
   SSID. Patent text, cited for the addressing pattern only.

Checked and **not** cited: NIST SP 800-153 §3.2 / §4.3, which #187
names. The publication is real (Souppaya & Scarfone, February 2012) but
the text of those two sections was not retrieved, so nothing here rests
on them.
