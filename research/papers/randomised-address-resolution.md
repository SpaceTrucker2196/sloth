---
source_url: https://petsymposium.org/popets/2017/popets-2017-0054.php
retrieved: 2026-11-25
topics: [wifi, ble, privacy, mac-randomization, locally-administered, probe-request, ie-fingerprint, sequence-number, association, persistent-address, sweep, baseline]
citation: Vanhoef, Matte, Cunche, Cardoso, Piessens, "Why MAC Address Randomization is not Enough: An Analysis of Wi-Fi Network Discovery Mechanisms", ACM ASIA CCS 2016, pp. 413-424 (HAL hal-01282900); Matte, Cunche, Rousseau, Vanhoef, "Defeating MAC Address Randomization Through Timing Attacks", ACM WiSec 2016, pp. 15-20 (HAL hal-01330476); Martin, Mayberry, Donahue, Foppe, Brown, Riggins, Rye, Brown, "A Study of MAC Address Randomization in Mobile Devices and When it Fails", PoPETs 2017(4):365-383, doi:10.1515/popets-2017-0054, arXiv:1703.02874; Fenske, Brown, Martin, Mayberry, Ryan, Rye, "Three Years Later: A Study of MAC Address Randomization In Mobile Devices And When It Succeeds", PoPETs 2021(3):164-181, doi:10.2478/popets-2021-0042; Android Open Source Project, "MAC randomization behavior" (source.android.com/docs/core/connect/wifi-mac-randomization-behavior); Apple Support 102509, "Use private Wi-Fi addresses on Apple devices"; Bluetooth Core v5.4 Vol 3 Part C Appendix A, Vol 4 Part E §7.8.45, Vol 6 Part B §1.3.2 and §6.1 (via research/bluetooth/ble-address-rotation.md); IEEE 802-2014 §8.2
---
# Resolving randomised addresses for a sweep's comparison

The basis for the sweep's resolution of randomised addresses (#249
follow-up, owner ruling 2026-11-25: "resolve randomised addresses";
`src/sweep.c`, [[sweep-session]] § 3). No alert kind reads it: it
decides only whether a Wi-Fi client address with the locally
administered bit (IEEE 802-2014 §8.2) or a private BLE address is
compared with the label's baseline as new, known or missing, or stays
a count.

**How the sources were read.** On 2026-11-25 each source's bibliographic
record and abstract were checked on the publisher's or an archive's
page (PoPETs, HAL, arXiv, AOSP, Apple Support). The full texts were
**not** re-read for this note; a claim below that goes beyond an
abstract is marked as the note's own reasoning. The ASIA CCS and WiSec
papers' DOIs were not confirmed by that check and are therefore not
given; their HAL records are.

## What the literature says can link randomised addresses

- **Information-element fingerprints and sequence numbers.** Vanhoef et
  al. (ASIA CCS 2016) track unassociated devices that randomise by the
  content and order of the information elements in their probe requests
  and by 802.11 sequence numbers carried across an address change; their
  abstract reports that in some cases the IE fingerprint alone uniquely
  identified a device *in their datasets*.
- **Timing.** Matte et al. (WiSec 2016) group one device's probe
  requests across random addresses from the timing of its scans alone,
  with an accuracy of up to 75 %.
- **Measured failure.** Martin et al. (PoPETs 2017) extend the passive
  techniques and report defeating randomisation for about 96 % of the
  Android phones they observed; Fenske et al. (PoPETs 2021), testing 160
  phone models, find recent phones with current software generally
  randomise well and many in use still do not.

## What the platforms say about the address a client associates with

- Android (AOSP, "MAC randomization behavior"): since Android 10 the
  default is **persistent** randomisation, an address derived from the
  network profile (SSID, security type, or the Passpoint FQDN) that stays
  the same for that network; re-randomisation happens only at a new
  connection under the conditions the page lists (a lapsed DHCP lease
  and more than 4 h since the last disconnect, or the address over 24 h
  old in the newer versions of the page), and non-persistent
  randomisation is an exception an app or the developer options ask for.
- Apple (Support 102509): a different address per network, which the
  device "might rotate" periodically; the per-network setting is Off,
  Fixed or Rotating, and an address not used on a network for six weeks
  is replaced at the next join.

## What the sweep takes from this, and what it does not

The ruling's own risk statement governs: a wrong merge that hides a new
device is worse than leaving it unresolved. Every technique above
*links two addresses into one device*, and every one of them has a
coincidence rate: an IE fingerprint names a model and a software build
before it names a device (two phones of one model are the case it
cannot separate, and a sweep's baseline is exactly where a planted
device of a common model would hide behind a known one), timing reaches
75 % at best, and a sequence-number seam in a dense room lands by chance
(the measured coincidence rate is `tests/test_seqnum_track.c`'s dense
fixture). Carried across two sweeps, a link of that kind would let a
device heard today be called KNOWN because a *different* device with the
same fingerprint was heard at the baseline: the hidden new device.

So the sweep resolves an address only to **itself**, when the evidence
says the address is stable, and never merges two addresses into a
baseline identity:

| method | evidence | confidence | basis |
|---|---|---|---|
| `assoc` | a Wi-Fi client address with the local bit took part in a (re)association exchange (`assoc_track.c`) | 60 | AOSP and Apple: the address a client joins with is per network and persistent (Android) or fixed or slowly rotating (Apple), so it recurs at the next sweep while the device keeps joining that network |
| `persistent` | a randomised Wi-Fi client address, or a resolvable or non-resolvable private BLE address, heard over a span of at least 900 s within the sweep | 40 | BLE: Core v5.4 recommends a private address change at most every 15 min (T_GAP(private_addr_int), Vol 3 Part C Appendix A; Vol 6 Part B §6.1), so one held longer is not rotating as recommended. Wi-Fi: no standard interval exists; the same 900 s is a judgement, stated as one, informed by the probe-address churn the studies above describe |

The confidences are the note's own ordinal judgement of how likely the
address names one device at the next sweep, on the 0..100 axis
`seqnum_track.c` uses; they are not measured rates.

Neither method can hide a new device: the identity is the address, so
a device is KNOWN only when the very same 46 random bits were in the
baseline. Their error is noise in the other direction: an Apple address
on "Rotating", an Android address re-randomised after 24 h, or a BLE
device with an RPA_Timeout of up to an hour (Vol 4 Part E §7.8.45) is
NEW at one sweep and MISSING at the next. That is the conservative
failure the ruling asks for.

One linking technique is used, and only to tidy a count, never to
compare: a randomised probe address whose sequence numbers continue,
with a strong score (`seqnum_corr_is_strong()`: confidence at least
`SEQNUM_CORR_CONF_STRONG` and exactly one side universal), into a
universal address heard in the same sweep is reported as **linked** to
that device rather than unresolved (method `seqnum`). The universal
device is compared as it always was, so a wrong link moves one address
from one count to another and cannot change any row's status.

Not used, and why:

- **IE fingerprints and probed SSID lists** for identity: model-level
  collisions (above), and a probed SSID list is a person's network
  history; the baseline would have to store it to compare it.
- **BLE rotation hints** (`src/ble_rotation.c`, #156): internal,
  opt-in, keyed per run (their digests are not comparable across runs,
  so they cannot carry an identity to the next sweep), and their
  contract names one consumer; no other may read a hint.
- **Timing of scans**: sloth's frame clock is one second.

## What a resolved row stores

The address itself (heard on the monitor radio or the BLE receiver),
its kind, the channel, the OUI vendor where there is one, the method
and the confidence: monitor data, which the fleet rule allows to
travel ([[adr/0009-fleet-monitor-only]]). No fingerprint, no probed SSID,
no sequence number, no token or digest. The baseline file stays outside
sloth.db.

## What this does not establish

- That a resolved address belongs to one person or one device over
  time: it says only that the address was stable in this sweep.
- Any rate: no figure here was measured by sloth.
