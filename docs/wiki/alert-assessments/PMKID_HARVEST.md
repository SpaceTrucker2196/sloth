---
type: PMKID_HARVEST
technique: T1040
rule_file: src/alerts/rules_harvest.c:52 rule_pmkid_harvest() (tracking in src/harvest_track.c, fed by assoc_request_observe(), eapol_observe_frame(); tune rows harvest.window_s, harvest.min_bssids, harvest.unanswered_pct in src/tune.c)
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

`rule_pmkid_harvest()` (`src/alerts/rules_harvest.c:52`) fires when unanswered >= `harvest.min_bssids` (3) and unanswered x 100 >= `harvest.unanswered_pct` (50) x M1-answering BSSIDs. CRIT when PMKID-bearing unanswered >= 3 and the station answered none. Key `pmkidharvest:<sta>`; evidence the newest M1 per unanswered BSSID.

## The mechanism

Steube's 2018 disclosure: the attack "is performed on the RSN IE ... of a single EAPOL frame", needs no full handshake and no client, because "the attacker directly communicates with the AP", and "We receive all the data we need in the first EAPOL frame from the AP" [1]. hcxdumptool's first default vector is "Connecting to an ACCESS POINT to get a PMKID" [2]. The tool's station has no PMK, so it never sends M2: that is the passive tell.

## Evidence that proves it

One station, several BSSIDs, each having been asked to associate and each having answered with an M1, none answered; CRIT adds that the M1s carried PMKIDs. The cited frames are those M1s. The EAPOL `[e]` view shows them as a run of `M1` rows to one STA. The station's counts (asked, M1s, unanswered, with the PMKID KDE, answered) are on the stream as the `harvest_station` record (JSONL 1.3.0) and on slothweb's WiFi view in the "lures and key harvesting" card, whose detail slothweb also shows on the alert since 2026-11-12.

The detail ends `- cluster #N`: the station row's cluster id, which every EAPOL record counted in that row carries as `harvest_cluster_id` and the `harvest_station` record as `cluster_id` (JSONL 1.7.0), and which the EAPOL view's `[g]` groups. Since 2026-11-12.

What refutes it: the station's M2s appearing (a real client whose M2s the sensor missed briefly), or the station being the operator's own device failing to join.

## Benign causes

- A station with a wrong passphrase still sends M2 (with a bad MIC), so it is answered, not unanswered.
- A station heard asking but whose M2s are lost to range: the request must be heard for a target to count, and the ratio needs half or more unanswered across three or more BSSIDs.
- Roaming, PMK caching, FT: answered, or no M1 [3].

## Clusters and the QUEUE_EVICT mark

A cluster is one station row: its id is assigned when the row opens and is never reused, so a station that ages out of `harvest.window_s` and solicits again is a new cluster (the issue's `(sta_mac, window_start)` key). Framing Frames (CVE-2022-47522) [4] reassociates under a station's address so the AP releases that station's queued frames, the same association exchange that solicits an M1. When `QUEUE_EVICT` recorded a release on one of the row's own (BSSID, station) pairs within `harvest.window_s` of now, either side (`harvest_snapshot()`, `qe_pair()`), the detail adds `- QUEUE_EVICT release on <sta> at <bssid> in the window (<n> pairs)`, which is that `QUEUE_EVICT` alert's own key pair, and `harvest_station.qevict` carries the count. Severity and confidence do not move: an uncorroborated release is how an ordinary roam looks (`rule_queue_evict()`), so the mark joins two incidents for the reader rather than adding evidence to either.

## Harvest-friendly AP posture

Separately from the rule: an AP heard handing the PMKID KDE to any station in M1 (`harvest_ap_posture()`) is a hygiene finding, not an attacker signal. With a PSK-family AKM on its beacon the value is attackable offline [1]; with SAE or 802.1X it is not a passphrase target. It is `beacon.harvest_posture` (1 / 0, absent when not observed, JSONL 1.7.0) and a line under the EAPOL view's header for the selected row's AP. The issue's "no 802.11r / FT in RSN capability" qualifier is not applied: FT is an AKM, not an RSN capability bit, and no source in the corpus says FT stops an AP sending the KDE, so FT-PSK counts as PSK.

## Assessment

The thresholds are judgements; neither source gives counts or timing [1][2]. The window is long (15 min) by design: the issue's complaint was a slow harvest under the flood thresholds, and `ASSOC_FLOOD` counts requests to one BSSID, not distinct BSSIDs per station. A harvester that rotates its MAC per target is not one station here and is missed; that is a stated limit, not a false negative the tests hide.

## Bibliography

1. atom (Jens Steube), "New attack on WPA/WPA2 using PMKID", hashcat forum, 2018-08-04 - https://hashcat.net/forum/thread-7717.html (accessed 2026-11-11); `research/papers/steube-2018-pmkid.md`.
2. ZerBea, hcxdumptool README - https://github.com/ZerBea/hcxdumptool (accessed 2026-11-11); `research/tools/hcxdumptool.md`.
3. IEEE Std 802.11-2020 §12.7 as the tree's collector cites it - `research/ieee/802.11-2020-12.7-eapol-key.md`.
4. CVE-2022-47522, Framing Frames (USENIX Security 2023) - `research/cve/2022-47522.md`.

## Verification notes

Written 2026-11-11 with the rule, against `src/alerts/rules_harvest.c:52`, `src/harvest_track.{c,h}`, `src/eapol_log.c` and `src/assoc_track.c`. Clusters, the QUEUE_EVICT mark and the posture added 2026-11-12 (`tests/test_harvest_track.c` `test_cluster_*`, `test_queue_evict_marks_*`, `test_ap_posture*`; `tests/test_jsonl_lures.c`; `tests/test_views_render.c` `test_eapol_view_*`). Tests: `tests/test_harvest_track.c`, hand-built (re)association requests, EAPOL-Key data frames and deauthentications per IEEE 802.11-2020, through the observers the capture path calls.
