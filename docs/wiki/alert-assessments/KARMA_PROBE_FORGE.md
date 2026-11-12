---
type: KARMA_PROBE_FORGE
technique: T1557
rule_file: src/alerts/rules_twin.c:2236 rule_karma_probe_forge() (capture side karma_observe_frame(), counting karma_forged_ssids(), both in src/karma_detect.c; tune rows karma.forge_ssids and karma.forge_window_s in src/tune.c)
count_semantics: per poll while the forge row holds >= karma.forge_ssids never-beaconed answered SSIDs, one fire per answering BSSID; the row ages names out after karma.forge_window_s (600 s) of no further answer, so the incident outlives the last forged answer by at most the window. Not per frame
severity_assessment: agree - WARN for one station's directed probes answered with two names the BSSID never beaconed; CRIT when two distinct stations were answered, or when the BSSID is also a KARMA_AP beacon fan-out (the issue's S1 + S2)
false_positive_risk: low - an honest BSS answers only for its own SSID, and that answer (hidden or not) is filtered before the table; the residual is unverified gear behaviour (an 802.11ax Multiple BSSID transmitter writing a nontransmitted SSID into its own response), for which karma.forge_ssids is the knob
noise_verdict: not measured - new rule (#187 S2, 2026-11-11); no reference-host firing data yet
prevalence: the mechanism is the original KARMA (2005) and a standard airbase-ng option [1][2]; modern clients that stopped sending directed probes for their whole preferred list give it less to see [1]
tuning: [karma.forge_ssids (2, 2..8); karma.forge_window_s (600, 10..86400); the 5 s request/response pairing bound is protocol, not a knob]
researched: 2026-11-11
---
## What the rule checks

The capture side, `karma_observe_frame()` (`src/karma_detect.c`), is fed every Probe Request and every Probe Response by `src/capture/probe.c`. A directed Probe Request (non-empty SSID, unicast SA) is remembered in a 128-entry ring. A Probe Response is recorded on its BSSID's forge row only when its DA is a station whose directed probe for exactly that SSID arrived within `KARMA_FORGE_PAIR_S` (5 s, monotonic clock), and the SSID is not the BSSID's current name per `beacon_find_ssid()`. The capture path reveals a hidden AP's name from its probe response before this check, so a hidden AP answering for its own name is filtered.

`rule_karma_probe_forge()` (`src/alerts/rules_twin.c:2164`) walks the snapshot (`s->karma_forge`) and calls `karma_forged_ssids()`: the row's SSIDs that are neither the BSSID's current name nor anywhere in its beacon `ssid_history[]`. With no beacon row for the BSSID, or a history at `MAX_AP_SSID_HISTORY` (8), the answer is 0. At `karma.forge_ssids` (2) or more the rule fires; CRIT when the forged answers went to `KARMA_FORGE_STA_CRIT` (2) distinct stations, or when the same BSSID beacons `karma.ssid_thresh` (3) or more SSIDs. Key `karmaforge:<bssid>`. Evidence: the newest answering Probe Response per forged name.

## The mechanism

Dai Zovi and Macaulay built KARMA as "a special access point that responded to any Probe Request, allowing us to serve any SSID requested by a client within range" [1]. airbase-ng ships the same behaviour as `-P`, which "causes the fake access point to respond to all probes regardless of the ESSIDs specified" [2]. Neither has to beacon the names it answers to; the stock airbase-ng beacon carries "default" [2]. `KARMA_AP` judges the beacon history alone, so that radio never becomes one of its candidates (`KARMA_AP.md` says so); this kind reads the answers.

## Evidence that proves it

The finding is the set of answers: a Probe Response from one BSSID naming SSID A to a station that had just asked for A, and another naming B, where neither A nor B was ever beaconed by that BSSID and neither is its name. The cited frames are those responses. The counts (names forged, stations answered, beacon fan-out) are on the stream as the BSSID's `karma_suspect` record (JSONL 1.3.0, the `[y]` row) and on slothweb's WiFi view in the "lures and key harvesting" card; slothweb still withholds this alert's detail, because the rule formats a variable named `fan_note` and its audit refuses the word "note". CRIT adds that the answers reached different stations (different people's private network names from one radio), or that the same radio is also beaconing a pool of names.

What refutes it: the BSSID beaconing those names later (the `-C` mode of airbase-ng, [2]) moves it to `KARMA_AP`'s fan-out instead, and the names stop counting as forged here; a hidden AP's own name never counts.

## Benign causes

- None known from the protocol: one BSS has one SSID, and the paper describes ordinary APs answering "Probe Requests containing their SSID" [1].
- Unverified: an 802.11ax Multiple BSSID transmitter that wrote a nontransmitted profile's SSID into its own response's SSID element would read as forging. sloth does not decode those profiles and this has not been checked against the clause.

## Assessment

The rule fills a stated gap rather than adding a parallel signal: `KARMA_AP`'s assessment records that the probe-response-only KARMA radio is out of its sight. Severity is conservative for a protocol-level observation. WARN on one station leaves room for the unverified MBSSID case above; CRIT requires a second independent station or the beacon fan-out. The issue's latency signal (S3) is not built because no primary source for its threshold was found.

## Bibliography

1. D. A. Dai Zovi and S. A. Macaulay, "Attacking Automatic Wireless Network Selection", 2005 - https://www.theta44.org/karma/aawns.pdf (accessed 2026-11-11); `research/papers/daizovi-macaulay-2005-karma.md`.
2. aircrack-ng documentation, airbase-ng - https://www.aircrack-ng.org/doku.php?id=airbase-ng (accessed 2026-11-11); `research/tools/airbase-ng.md`.
3. MITRE ATT&CK T1557 Adversary-in-the-Middle - `research/mitre/T1557.md` (repo).

## Verification notes

Written 2026-11-11 with the rule, against `src/alerts/rules_twin.c:2164`, `src/karma_detect.{c,h}` and `src/capture/probe.c`. Quotations in [1] were read from the PDF's extracted text and in [2] from the page on the date given. The tests are `tests/test_karma.c :: test_forge_*`: hand-built frames per IEEE 802.11-2020 §9.3.3.3, §9.3.3.10, §9.3.3.11 and §9.4.2.2, run through the capture path's observer order.
