---
source_url: https://papers.mathyvanhoef.com/usenix2021.pdf
retrieved: 2026-09-03
topics: [fragattacks, fragmentation, aggregation, amsdu, rsn, plaintext-injection, wpa2, wpa3]
alert_kinds: [ALERT_TYPE_FRAG_PLAINTEXT, ALERT_TYPE_FRAG_BCAST]
citation: Vanhoef, "Fragment and Forge: Breaking Wi-Fi Through Frame Aggregation and Fragmentation", USENIX Security 2021
---
# FragAttacks — Vanhoef, USENIX Security 2021

Twelve CVEs against 802.11 frame aggregation and fragmentation. Three
are design flaws in the standard itself, present since 1997; the other
nine are implementation bugs found across essentially every vendor
tested. Their shared outcome is that an adversary in radio range can
have frames of their choosing accepted into an encrypted WPA/WPA2/WPA3
session **without holding the key**.

The three design flaws:

- **CVE-2020-24588 — aggregation.** The A-MSDU Present bit lives in the
  QoS Control field, which is authenticated in neither WPA nor WPA2 nor
  WPA3 unless SPP A-MSDU is negotiated. Flipping it makes the receiver
  reparse an otherwise valid encrypted payload as aggregated subframes
  with attacker-chosen destinations.
- **CVE-2020-24587 — mixed key.** Fragments of one frame encrypted under
  different keys are reassembled together, because receivers do not check
  that all fragments of a frame were protected by the same key.
- **CVE-2020-24586 — fragment cache.** The fragment cache is not cleared
  when a station (re)connects, so a fragment injected before an
  association can complete a frame delivered after it.

The nine implementation bugs are mostly of one shape: accepting frames
that a protected network should never accept. CVE-2020-26140 accepts
plaintext data frames outright; -26143 accepts fragmented plaintext ones;
-26145 accepts plaintext broadcast fragments as if they were complete
frames; -26144 accepts a plaintext A-MSDU whose first subframe carries an
RFC1042 EAPOL header.

## Why sloth cites this

`ALERT_TYPE_FRAG_PLAINTEXT` (-26140, -26143) and `ALERT_TYPE_FRAG_BCAST`
(-26145) are the members of the family whose on-air artefact is
observable by a passive monitor: they are attacks *made of* unprotected
frames, so the evidence is in the clear by construction.

Sloth's gate for both is per-station and ordered — it must have seen
that station transmit a Protected frame before the unprotected one
counts. The paper is why: these are "accepting plaintext after key
install" bugs, so the detector needs evidence the key was installed, and
a station's own encrypted traffic is that evidence. A beacon advertising
RSN is not: it says what the AP offers, not what this station completed.

## What it does not support

The paper does not license the A-MSDU detector as it is usually
described. The subframe headers CVE-2020-24588 manipulates are inside
the ciphertext; only the A-MSDU Present bit is in the plaintext MAC
header. A passive monitor that does not decrypt — and sloth does not,
per `MISSION.md` §2 — cannot compare a subframe DA against Address 3 or
read a subframe's LLC prefix. Any detector claiming to is either
decrypting or guessing.

Nor does the paper support treating a detection as a compromise. Every
signal here is a frame that was *transmitted*. Whether the victim's
driver accepted it is a decision inside another machine, and nine of the
twelve CVEs exist precisely because that decision varies by vendor.

## Related

- CVE-2020-26146 and -26147 concern reassembly of fragments with
  non-consecutive packet numbers and of mixed encrypted/plaintext
  fragments. The CCMP packet number is transmitted in the clear, so both
  are observable — but only with a fragment session table, which sloth
  does not yet keep.
- Advisory index: https://github.com/vanhoefm/fragattacks/blob/master/ADVISORIES.md
