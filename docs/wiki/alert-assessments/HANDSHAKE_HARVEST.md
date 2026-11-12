---
type: HANDSHAKE_HARVEST
technique: T1040
rule_file: src/alerts/rules_harvest.c:100 rule_handshake_harvest() (tracking in src/harvest_track.c, fed by deauth_record() and eapol_observe_frame(); tune rows harvest.deauth_min, harvest.reconnect_s, harvest.window_s in src/tune.c)
count_semantics: per poll while the BSSID's chain row holds a victim; one fire per BSSID; a victim ages out harvest.window_s (900 s) after its captured reconnect. Not per frame
severity_assessment: agree - WARN for one victim, because an AP band-steering a client with repeated deauths has the same shape; CRIT at two distinct victims of one BSSID inside the window
false_positive_risk: medium for WARN, low for CRIT - the single-victim shape has a known benign twin (steering), two independently knocked-off stations each reconnecting immediately does not
noise_verdict: not measured - new rule (#172, 2026-11-11); no reference-host firing data yet
prevalence: hcxdumptool's second default vector [1], and the long-standing aireplay-style capture practice; frequency near an arbitrary sensor unknown
tuning: [harvest.deauth_min (2, 1..1000); harvest.reconnect_s (30, 1..600); harvest.window_s (900, 600..86400)]
researched: 2026-11-11
---
## What the rule checks

`harvest_note_deauth()` (`src/harvest_track.c`, called from `deauth_record()` after its duplicate bail, so retransmissions do not count) keeps per (BSSID, victim) the distinct deauthentication / disassociation frames whose transmitter address is the BSSID, the victim being the station or broadcast; a gap over `harvest.reconnect_s` starts a new burst. `harvest_note_eapol()` receives `fresh_pair` once per attempt when the collector pairs an M2 with its M1 on the replay counter; if a note for (BSSID, station) or (BSSID, broadcast) holds >= `harvest.deauth_min` (2) frames, the last within `harvest.reconnect_s` (30 s), the station is recorded as a victim on the BSSID's chain row.

`rule_handshake_harvest()` (`src/alerts/rules_harvest.c:100`) fires per row with a victim; CRIT at `HARVEST_CHAIN_CRIT_VICTIMS` (2). Key `hsharvest:<bssid>`; evidence the deauth frames.

## The mechanism

hcxdumptool's README: "Disconnecting a CLIENT from an associated ACCESS POINT to get a complete handshake (M1M2M3M4)" [1]. A station that accepts the forged frame rejoins, and its new handshake is captured; M1 and M2 are enough for an offline guess at the passphrase [2].

## Evidence that proves it

The deauth frames claimed from the AP, then the victim's fresh M1/M2 pair with that AP within seconds; for CRIT, the same for a second station. The `[a]` Deauth and `[e]` EAPOL views show both halves. The BSSID's counts (victims, the deauths before them) are on the stream as the `harvest_chain` record (JSONL 1.3.0), the victims as a count only, and on slothweb's WiFi view in the "lures and key harvesting" card; slothweb shows the alert's detail since 2026-11-12.

## Benign causes

- Band steering or load balancing by deauthentication, with the client returning to the same BSSID (WARN).
- An AP restarting its BSS and deauthenticating everyone by broadcast twice, clients rejoining: a CRIT on the operator's own AP after a reboot is possible and is recognisable from the AP's own logs.

Not counted at all: a station leaving its own AP (transmitter is the station), and a single deauth.

## Assessment

The deauth count sits deliberately under `DEAUTH_FLOOD` (5 in 5 s): the slow form is the point. Both rules can fire on one burst and report different things. Management frame protection on the operator's network removes the mechanism.

## Bibliography

1. ZerBea, hcxdumptool README - https://github.com/ZerBea/hcxdumptool (accessed 2026-11-11); `research/tools/hcxdumptool.md`.
2. IEEE Std 802.11-2020 §12.7 as the tree's collector cites it - `research/ieee/802.11-2020-12.7-eapol-key.md`.

## Verification notes

Written 2026-11-11 with the rule, against `src/alerts/rules_harvest.c:100`, `src/harvest_track.{c,h}`, `src/deauth_snoop.c` and `src/eapol_log.c`. Tests: `tests/test_harvest_track.c`.
