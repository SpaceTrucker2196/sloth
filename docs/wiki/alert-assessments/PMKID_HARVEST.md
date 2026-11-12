---
type: PMKID_HARVEST
technique: T1040
rule_file: src/alerts/rules_harvest.c:46 rule_pmkid_harvest() (tracking in src/harvest_track.c, fed by assoc_request_observe(), eapol_observe_frame(); tune rows harvest.window_s, harvest.min_bssids, harvest.unanswered_pct in src/tune.c)
count_semantics: per poll while the station row holds >= harvest.min_bssids unanswered M1s at >= harvest.unanswered_pct; one fire per soliciting station; a target ages out after harvest.window_s (900 s) without activity, so the incident ends at most a window after the station's last request or M1. Not per frame
severity_assessment: agree - WARN for the solicitation pattern alone; CRIT only when >= 3 of the unanswered M1s carried a PMKID KDE and the station answered no M1 at all, i.e. offline-attackable material was actually handed over to a station that never showed it held a key
false_positive_risk: low-medium - a roaming phone, PMK caching and FT roaming are excluded by construction (answered M1s, or no M1); the residual is a station heard asking but whose M2s are lost to range on more than half of three or more BSSIDs, which the 50 % ratio and the WARN tier are for
noise_verdict: not measured - new rule (#172, 2026-11-11); no reference-host firing data yet
prevalence: the attack is public since 2018 and is hcxdumptool's default first vector [1][2]; how often one runs in range of an arbitrary sensor is unknown
tuning: [harvest.window_s (900, 600..86400); harvest.min_bssids (3, 2..16); harvest.unanswered_pct (50, 1..100); the 10 s M2 grace is the collector's EAPOL_PAIR_WINDOW_S]
researched: 2026-11-11
---
## What the rule checks

`harvest_note_assoc_req()` (`src/harvest_track.c`, called from `assoc_request_observe()`) opens a row per station that sends a (re)association request and a target per BSSID it asks. `harvest_note_eapol()` (called from `eapol_observe_frame()` after classification) marks an M1 to that station from an asked BSSID, with whether it carried a PMKID KDE, and an M2 from the station. `harvest_snapshot()` counts per station: BSSIDs asked, BSSIDs that answered with an M1, those whose M1 is older than `EAPOL_PAIR_WINDOW_S` (10 s) with no M2 (unanswered), unanswered with a PMKID, and BSSIDs the station sent an M2 to.

`rule_pmkid_harvest()` (`src/alerts/rules_harvest.c:46`) fires when unanswered >= `harvest.min_bssids` (3) and unanswered x 100 >= `harvest.unanswered_pct` (50) x M1-answering BSSIDs. CRIT when PMKID-bearing unanswered >= 3 and the station answered none. Key `pmkidharvest:<sta>`; evidence the newest M1 per unanswered BSSID.

## The mechanism

Steube's 2018 disclosure: the attack "is performed on the RSN IE ... of a single EAPOL frame", needs no full handshake and no client, because "the attacker directly communicates with the AP", and "We receive all the data we need in the first EAPOL frame from the AP" [1]. hcxdumptool's first default vector is "Connecting to an ACCESS POINT to get a PMKID" [2]. The tool's station has no PMK, so it never sends M2: that is the passive tell.

## Evidence that proves it

One station, several BSSIDs, each having been asked to associate and each having answered with an M1, none answered; CRIT adds that the M1s carried PMKIDs. The cited frames are those M1s. The EAPOL `[e]` view shows them as a run of `M1` rows to one STA. The station's counts (asked, M1s, unanswered, with the PMKID KDE, answered) are on the stream as the `harvest_station` record (JSONL 1.3.0) and on slothweb's WiFi view in the "lures and key harvesting" card, whose detail slothweb also shows on the alert since 2026-11-12.

What refutes it: the station's M2s appearing (a real client whose M2s the sensor missed briefly), or the station being the operator's own device failing to join.

## Benign causes

- A station with a wrong passphrase still sends M2 (with a bad MIC), so it is answered, not unanswered.
- A station heard asking but whose M2s are lost to range: the request must be heard for a target to count, and the ratio needs half or more unanswered across three or more BSSIDs.
- Roaming, PMK caching, FT: answered, or no M1 [3].

## Assessment

The thresholds are judgements; neither source gives counts or timing [1][2]. The window is long (15 min) by design: the issue's complaint was a slow harvest under the flood thresholds, and `ASSOC_FLOOD` counts requests to one BSSID, not distinct BSSIDs per station. A harvester that rotates its MAC per target is not one station here and is missed; that is a stated limit, not a false negative the tests hide.

## Bibliography

1. atom (Jens Steube), "New attack on WPA/WPA2 using PMKID", hashcat forum, 2018-08-04 - https://hashcat.net/forum/thread-7717.html (accessed 2026-11-11); `research/papers/steube-2018-pmkid.md`.
2. ZerBea, hcxdumptool README - https://github.com/ZerBea/hcxdumptool (accessed 2026-11-11); `research/tools/hcxdumptool.md`.
3. IEEE Std 802.11-2020 §12.7 as the tree's collector cites it - `research/ieee/802.11-2020-12.7-eapol-key.md`.

## Verification notes

Written 2026-11-11 with the rule, against `src/alerts/rules_harvest.c:46`, `src/harvest_track.{c,h}`, `src/eapol_log.c` and `src/assoc_track.c`. Tests: `tests/test_harvest_track.c`, hand-built (re)association requests, EAPOL-Key data frames and deauthentications per IEEE 802.11-2020, through the observers the capture path calls.
