---
source_url: https://papers.mathyvanhoef.com/usenix2021.pdf
retrieved: 2026-09-03
topics: [fragattacks, fragmentation, aggregation, amsdu, rsn, plaintext-injection, wpa2, wpa3]
alert_kinds: [ALERT_TYPE_FRAG_PLAINTEXT, ALERT_TYPE_FRAG_BCAST, ALERT_TYPE_FRAG_CACHE, ALERT_TYPE_FRAG_MIXED, ALERT_TYPE_FRAG_AMSDU, ALERT_TYPE_FRAG_AMSDU_EAPOL]
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

`ALERT_TYPE_FRAG_CACHE` (-24586) and `ALERT_TYPE_FRAG_MIXED` (-26147)
ride a fragment-session table keyed on `(BSSID, SA, DA, TID)`, added in
slice 2. Neither is gated on the RSN-witnessed state the two above use:
the fragment cache the first abuses, and the reassembly the second
mixes protection states within, both exist before decryption.

## The A-MSDU detector reads the paper sideways

The paper does not license the A-MSDU detector as it is usually
described. The subframe headers CVE-2020-24588 manipulates are inside
the ciphertext; only the A-MSDU Present bit is in the plaintext MAC
header. A passive monitor that does not decrypt — and sloth does not,
per `MISSION.md` §2 — cannot compare a subframe DA against Address 3 or
read a subframe's LLC prefix. Any detector claiming to is either
decrypting or guessing.

What the paper *does* license is detecting the replay. §5 describes the
attack as retransmitting a frame the victim already sent with the
aggregation bit flipped, and CCMP's own replay-protection rule
(802.11-2020 §12.5.3.4.4) says a packet number is never reused under one
key. `ALERT_TYPE_FRAG_AMSDU` is the intersection: same transmitter, same
PN, differing A-MSDU bit. The evidence is entirely in the plaintext MAC
and CCMP headers.

## The other half of the same design flaw needs no workaround

CVE-2020-26144 is the paper's other A-MSDU finding, and unlike -24588 it
needs none of the above: the frame in question is unprotected, so the
subframe header — including its LLC/SNAP — is not behind any cipher at
all. What licenses `ALERT_TYPE_FRAG_AMSDU_EAPOL` is a fact the paper
states about legitimate 802.11 traffic rather than about the attack:
EAPOL is always its own MPDU, never a subframe of an aggregated one. A
plaintext A-MSDU whose first subframe's LLC/SNAP claims the EAPOL
EtherType is therefore not an ambiguous signal needing a replacement
proxy the way -24588's was — it is the paper's own confusion case,
observed directly.

## What it does not support

Nor does the paper support treating a detection as a compromise. Every
signal here is a frame that was *transmitted*. Whether the victim's
driver accepted it is a decision inside another machine, and nine of the
twelve CVEs exist precisely because that decision varies by vendor.

## Related

- CVE-2020-26146 (non-consecutive packet numbers) is not implemented.
  The CCMP PN is readable, but it is one counter shared by every frame
  on a (key, TID), not a per-reassembly sequence — ordinary interleaved
  traffic and fragment retries both open gaps that are not attacks. See
  `docs/wiki/fragattacks.md` for the full argument.
- Advisory index: https://github.com/vanhoefm/fragattacks/blob/master/ADVISORIES.md
