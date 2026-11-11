---
source_url: https://hashcat.net/forum/thread-7717.html
retrieved: 2026-11-11
topics: [pmkid, wpa2, psk, eapol, m1, clientless, hashcat, hcxdumptool]
alert_kinds: [ALERT_TYPE_PMKID_HARVEST]
citation: "atom (Jens Steube), \"New attack on WPA/WPA2 using PMKID\", hashcat forum thread 7717, 2018-08-04"
---
# The PMKID attack: one M1 is enough

The primary disclosure of the attack `PMKID_HARVEST` (#172) detects
being run. Posted on the hashcat forum by its administrator, "atom"
(Jens Steube, hashcat's author), on 2018-08-04; read 2026-11-11.
Quotations are from the first post.

## What the post says

- "The new attack is performed on the RSN IE (Robust Security Network
  Information Element) of a single EAPOL frame."
- "The main difference from existing attacks is that in this attack,
  capture of a full EAPOL 4-way handshake is not required."
- "No more regular users required - because the attacker directly
  communicates with the AP (aka "client-less" attack)".
- "We receive all the data we need in the first EAPOL frame from the
  AP."
- The value: "The PMKID is computed by using HMAC-SHA1 where the key is
  the PMK", written `PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP |
  MAC_STA)`.
- The procedure: "Run hcxdumptool to request the PMKID from the AP and
  to dump the recieved frame to a file", and "If an AP recieves our
  association request packet and supports sending PMKID" the frame
  arrives.

## What sloth reads from it

The attacker's side of that exchange is visible to a passive sensor:
an association request from the attacker's station, the AP's first
EAPOL-Key message (M1) back to it, and then **nothing** — no M2,
because the attacker has no PMK to compute one with and needs none.
Done across many APs, that is one station with many unanswered M1s.
`PMKID_HARVEST` counts exactly that (`src/harvest_track.c`): distinct
BSSIDs the station asked, answered with an M1, and left without an M2
past the collector's pairing window. Its CRIT corroborator is the value
this post is about: the unanswered M1s carried a PMKID KDE, from
several BSSIDs, to a station that answered none of them.

## What it does not say

- **No counts or timing.** The post describes one exchange per AP. The
  rule's three BSSIDs, half unanswered, and 15-minute window are
  sloth's judgements (`src/harvest_track.h`), tunable, and not values
  from this source.
- **Not every AP sends a PMKID**, as the post's own "supports sending
  PMKID" says; the WARN does not depend on one.
- **A PMKID in an M1 is not itself an attack.** PMK caching puts one
  there for a station that then answers with an M2; that answered case
  is the one the rule excludes.

## Related

- `research/tools/hcxdumptool.md` — the tool the post uses, and its
  second shape (`HANDSHAKE_HARVEST`).
- `research/ieee/802.11-2020-12.7-eapol-key.md` — the messages and the
  PMKID KDE as the collector parses them.
