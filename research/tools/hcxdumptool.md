---
source_url: https://github.com/ZerBea/hcxdumptool
retrieved: 2026-11-11
topics: [hcxdumptool, pmkid, handshake, deauthentication, eapol, harvesting]
alert_kinds: [ALERT_TYPE_PMKID_HARVEST, ALERT_TYPE_HANDSHAKE_HARVEST]
citation: ZerBea, hcxdumptool README (GitHub repository front page, retrieved 2026-11-11)
---
# hcxdumptool: the two harvesting shapes, in the tool's own words

The tool documentation behind `PMKID_HARVEST` and `HANDSHAKE_HARVEST`
(#172). Quotations are from the README on the repository's front page,
retrieved 2026-11-11.

## What the README says it does

It describes itself as "A tool to capture packets from WLAN devices and
to discover potential weak points within own WiFi networks", and says
"By default, hcxdumptool is utilizing three attack vectors":

- "Connecting to an ACCESS POINT to get a PMKID (turn off by
  --associationmax=0)" — the clientless shape; sloth's
  `PMKID_HARVEST`.
- "Disconnecting a CLIENT from an associated ACCESS POINT to get a
  complete handshake (M1M2M3M4)" (turned off by
  `--disable_disassociation`) — the forced-reconnect shape; sloth's
  `HANDSHAKE_HARVEST`.
- "Allowing a CLIENT to connect to hcxdumptool (OSI layer 2 attack) to
  get a challenge (M1M2)" — the tool acting as an AP. Not detected by
  either new kind; the closest existing detectors are the rogue-AP
  family (`KARMA_AP`, `KARMA_PROBE_FORGE`, `EVIL_TWIN`).

It also says "hcxdumptool is able to prevent complete WLAN traffic
transmission. (Depending on selected options.)" and "hcxdumptool should
only be used in a 100% controlled environment!"

## How each shape looks to a passive sensor

- **Connecting to get a PMKID.** The tool's station sends association
  requests to APs and receives each AP's M1; it does not hold the key,
  so no M2 follows. `src/harvest_track.c` keys this on the soliciting
  station: distinct BSSIDs it asked, answered with an M1, left without
  an M2.
- **Disconnecting a client.** Deauthentication or disassociation frames
  claimed from the AP's address reach a station; the station rejoins,
  and its fresh M1/M2 pair is the handshake the tool wanted. The
  tracker joins the two: at least two distinct frames claimed from the
  BSSID, then a new M1/M2 pair on that (BSSID, station) within 30 s.

## What it does not say

- **No target counts, rates, dwell or deauth counts.** The thresholds
  in `src/harvest_track.h` are sloth's judgements, labelled as such and
  tunable. In particular nothing here says how many deauths one
  disconnect uses, so `harvest.deauth_min` (2) is chosen to sit under
  `DEAUTH_FLOOD` and above a single legitimate deauth, not to match the
  tool.
- **Which station address the tool uses** for its association requests
  is not stated. A tool that rotated its address per AP would not be
  one station to the tracker; the rule would miss it, not misreport it.

## Related

- `research/papers/steube-2018-pmkid.md` — the attack the first vector
  serves.
- `research/ieee/802.11-2020-12.7-eapol-key.md` — the EAPOL-Key
  messages both shapes are counted from.
