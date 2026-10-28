---
type: ASSOC_FLOOD
technique: T1498.001
rule_file: src/alerts/rules_wifi_mgmt.c:135 rule_assoc_flood()
count_semantics: per evaluation tick, per BSSID key, while a flood is standing. fire_ev() bumps count every poll in which the busiest BSSID's in-window (Re)Association-request total is still >= threshold; one increment is one poll (~4/s), NOT one association frame. The underlying measurement (assoc_flood_bssid) counts every observed request frame in the 256-slot ASSOC_REQ_RING over the window - including 802.11 retransmissions, since the Retry bit is not filtered - so the detail's "N assoc reqs" is a per-frame count but the alert's own count is per-tick
severity_assessment: agree - WARN off your network, CRIT on a --my-bssid BSSID, matches the impact: an assoc flood is an availability attack and only becomes CRIT when it is aimed at an AP the operator owns
false_positive_risk: low - the rate threshold (21 reqs to one BSSID in 60 s) is far above any roaming policy; the realistic benign trip is a broken client in a reassociation loop, which the detail flags as "(few sources)"
noise_verdict: not seen on the reference host - no rows. Expected: a sustained 21-assoc/60s flood at one BSSID is an uncommon event, and the per-BSSID keying plus the ring-backed window keep it from firing on ordinary churn. If it did fire and proved noisy, the lever is assoc.flood_thresh / assoc.flood_window_s in the --tune registry
prevalence: association/authentication flooding is a textbook, long-documented 802.11 DoS [3][7]; real-world incidence is low relative to deauth because MFP does not stop it and yet deauth is the more common tool
tuning: [--tune assoc.flood_thresh (default 21, 2..256), --tune assoc.flood_window_s (default 60, 1..3600), --my-bssid (WARN->CRIT), --hop/--monitor-only (needs monitor mode for assoc-request frames)]
researched: 2026-10-27
---
## What the rule checks

`rule_assoc_flood()` (src/alerts/rules_wifi_mgmt.c:135-171) finds the busiest BSSID by in-window (Re)Association-request volume and fires if it crosses the threshold.

- **Input.** `assoc_flood_bssid(now, window_s, thresh, &bssid, &distinct)` (src/assoc_track.c:319-359) walks `ASSOC_REQ_RING` (256 slots, src/assoc_track.c), counts requests per BSSID inside the window, and returns the highest count plus a distinct-STA tally. Requests enter the ring when probe.c hands a parsed (Re)Association Request to `assoc_request_observe()` (src/capture/probe.c:679-680), which calls `flood_record()` (src/assoc_track.c:191). Because only the single busiest BSSID is returned, at most one `assocflood:` key is asserted per tick: if two BSSIDs are over threshold at once the second gets an incident only when it out-counts the first.
- **Thresholds** (registry, src/tune.c:189-190): `assoc.flood_thresh` default `ASSOC_FLOOD_THRESH` = 21 (include/sloth.h:1222), `assoc.flood_window_s` default `ASSOC_FLOOD_WIN_SECS` = 60 (:1223). The ring is one 256-slot buffer shared by **all** BSSIDs (src/assoc_track.c:294, 307-317), so the effective window is the shorter of `window_s` and "the last 256 requests heard anywhere": a long `--tune assoc.flood_window_s` in a busy RF environment does not look back as far as it says, and `n` can never exceed 256.
- **Condition.** Fire if `n >= thresh` (line 152).
- **Key.** `assocflood:<bssid>` (line 159) - per-BSSID, so a busy AP with many ordinary clients is one incident, not many.
- **Distinct-STA count shapes the message, does not gate.** `distinct > 3` reads `(spoofed-MAC flood)`; otherwise `(few sources)` (line 164). The comment (lines 136-145) is explicit: few STAs at high rate is a targeted/broken client, many STAs at high rate is a spoofed-MAC flood (the common tooling shape); gating on either would blind the rule to the other.
- **Severity.** `ownership_is_my_bssid(bssid)` -> CRIT, else WARN (line 169).
- **Evidence.** `fire_ev()` with `assoc_flood_evidence()` (src/assoc_track.c:361-378): the newest in-window (Re)Association Requests to the BSSID, walked newest-first with the same window test the count used, so a cited frame was always counted. No `match_ip` (802.11 management has no IP), so the evidence-ring path is the only route back to the bytes (docs/wiki/pcap-export.md:151).

## The attack

T1498.001, Direct Network Flood, is "a high-volume of network traffic to a target" [2]. The association-flood instance aims at the AP's association table: each (Re)Association Request asks the AP to allocate an Association ID and client state, and an AP has a finite table. Flood it - typically from many spoofed source MACs so each request looks like a new client - and the table fills, after which legitimate clients cannot associate. The repo's T1498 note names it "association requests at a rate no roaming policy produces, filling an AP's association table" [1].

It is the missing member of sloth's flood set (beacon, deauth, probe, auth were already covered; rules_wifi_mgmt.c:136). mdk4's documented flood modes are beacon (`b`), authentication DoS (`a` - "too many clients can freeze or reset several APs"), deauth/disassoc (`d`), and EAPOL-start (`e`) [3a]; aircrack-ng's `aireplay-ng -1` performs open-system (or shared-key) authentication plus association to obtain an associated MAC for other attacks; it is not a flood tool - its documentation is about getting one association to stick, down to an `-o 1` option that sends one packet set at a time because the default "confuses some APs" [3b]. An association flood is the natural companion to the auth flood: both exhaust per-client state, and crucially neither is prevented by 802.11w/PMF, because association requests precede key establishment. Bellardo & Savage's 2003 analysis of practical 802.11 management-frame DoS is the foundational reference [7].

An attacker gains denial of service only - no interception, no credential. It is loud and needs no proximity advantage beyond reaching the AP.

## Evidence that proves it

What sloth records:

- The alert detail: `N assoc reqs to <bssid> from D STA(s) in <window>s (spoofed-MAC flood | few sources)` and the `- YOUR network` tag when owned.
- Cited evidence frames via the evidence ring: the newest in-window (Re)Association Requests (docs/wiki/pcap-export.md:151). With `--collect-handshakes` + `--eapol-dir`, the per-alert evidence pcap holds those frames (docs/wiki/pcap-export.md summary, section on the evidence ring).
- JSONL `wifi_assoc_req` records (docs/wiki/jsonl-schema.md): `bssid`, `sta_mac`, `requested_ssid`, `is_reassoc`, `akm_bits`, `pairwise_bits`, `requested_mfp`, `vendor_ie_hash`, per pair.
- JSONL `assoc` records for any requests the AP actually granted (status 0).
- `sensor_health` carries no counter specific to this rule, but the monitor radio's frame totals move.

To call it real: a high distinct-STA count (`D` large, `(spoofed-MAC flood)`) where the source MACs are random-looking and mostly locally-administered, few or none of them completing an association (`assoc` rows do not keep pace with the request rate), and the requested SSIDs/parameters implausibly uniform across "clients". The evidence pcap should show a tight burst of (Re)Association Requests to one BSSID with addr2 values that never appear as real traffic sources.

What refutes it: `D` = 1-2 with `(few sources)` and a `wifi_assoc_req`/`assoc` pair that shows a single real client that keeps re-requesting - a broken supplicant or a flapping link, not a flood. A dense but legitimate environment stays below 21/60s per BSSID by construction.

## Benign causes

- **A malfunctioning client in a reassociation loop** - one STA re-requesting repeatedly; the detail's `(few sources)` and a single `sta_mac` in `wifi_assoc_req` identify it. This is the realistic false trip.
- **A controller deployment with aggressive reassociation** during a mass roam event - possible in principle, but 21 requests to one BSSID in 60 s is far above normal roaming, so this is unlikely to be sustained.
- **Retransmissions count.** `assoc_request_observe()` records every parsed request into the ring ("Every request feeds the flood window, including repeats from one STA", src/assoc_track.c:188-191) and nothing dedupes on the Retry bit or sequence number, so a client re-sending an unacknowledged request several times contributes each copy. The first-in-window-slot test at assoc_track.c:325-333 only stops a BSSID being *scored* more than once per pass; it does not deduplicate frames. A weak-signal client retrying hard plus repeated attempts is therefore a plausible `(few sources)` trip.

## Assessment

**Severity.** WARN off-network, CRIT on `--my-bssid`, is right: the impact of an availability attack depends entirely on whether it is your AP being filled. The ownership escalation (#52) is the same pattern the whole flood set uses.

**Prevalence.** Association/authentication flooding is well documented [3][7] but, in practice, less common than deauth flooding because deauth tooling is more ubiquitous; MFP has pushed some attackers toward assoc/auth exhaustion precisely because PMF does not protect pre-association frames.

**Reference host noise verdict.** Not seen (no keys, no fires). This is the expected result: a 21-req/60s flood at a single BSSID is an uncommon, bursty event, and the per-BSSID key plus the 256-slot ring and 60 s window keep ordinary association churn well below threshold. There is nothing to dedupe. Were it to fire continuously in some environment, the count is per-tick, so a standing flood would inflate `count` at ~4 Hz while the detail stays stable (one `alert.create`, throttled updates); the correct response then is to raise `assoc.flood_thresh` or shorten `assoc.flood_window_s` via `--tune`, not to touch the rule.

**Is the evidence sufficient to act on?** Yes. The distinct-STA tally plus the cited frames plus the `assoc`/`wifi_assoc_req` join distinguish a spoofed-MAC flood from a broken client with good confidence, and the evidence pcap preserves the frames.

**First step for a responder.** Read the distinct-STA count. `(spoofed-MAC flood)` with many random sources and no matching `assoc` grants is an attack on the AP's table - locate the transmitter and, if it is your AP, consider rate-limiting/association controls on the controller. `(few sources)` is almost always one sick client - find that STA.

## Bibliography

1. research/mitre/T1498.md - repo research note (retrieved 2026-09-07); defines ASSOC_FLOOD as "association requests at a rate no roaming policy produces, filling an AP's association table" (accessed 2026-10-27)
2. MITRE ATT&CK T1498.001, Direct Network Flood - https://attack.mitre.org/techniques/T1498/001/ (accessed 2026-10-27)
3. [3a] mdk4 attack modes (aircrack-ng), README - https://github.com/aircrack-ng/mdk4 (modes a/b/d/e; "authentication DoS", accessed 2026-10-27); [3b] aircrack-ng fake authentication (-1) - https://www.aircrack-ng.org/doku.php?id=fake_authentication (open-system/shared-key auth + associate to obtain one associated MAC; the page does not describe a flood mode; accessed 2026-10-27)
7. J. Bellardo, S. Savage, "802.11 Denial-of-Service Attacks: Real Vulnerabilities and Practical Solutions", 12th USENIX Security Symposium, 2003 - https://www.usenix.org/legacy/events/sec03/tech/bellardo.html (accessed 2026-10-27)
8. IEEE 802.11-2020, Part 11 WLAN MAC and PHY (association request frame, §9.3.3.x) - https://standards.ieee.org/ieee/802.11/7028/ (accessed 2026-10-27; the page now lists the standard as superseded by IEEE 802.11-2024 - the clause numbering here is the 2020 edition's, which is what sloth's research notes use)
9. docs/views/alerts.md:138 (rule table row); docs/wiki/where-exploits-happen.md:56; docs/wiki/alert-remediation.md:850-864; docs/wiki/pcap-export.md:151 - repo documents (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree at commit 0d60387.

- **Code.** `rule_file`, thresholds (`ASSOC_FLOOD_THRESH` 21 / `ASSOC_FLOOD_WIN_SECS` 60 at include/sloth.h:1222-1223, registry rows src/tune.c:189-190 with ranges 2..256 / 1..3600), condition `n < thresh` (line 152), key, distinct-STA wording, severity and `fire_ev()` with `assoc_flood_evidence()` (src/assoc_track.c:361-378) all match. Corrected line references: span 135-171, key 159, message branch 164, severity 169, comment 136-145, ring entry src/capture/probe.c:679-680 via `assoc_request_observe()` -> `flood_record()` (src/assoc_track.c:191). Added: only the busiest BSSID fires per tick.
- **Count semantics** confirmed: `fire_ev()` -> `fire_inv()` bumps `evaluations`/`count` on every re-assertion (engine.c:478-479); the ring count in the detail is per frame.
- **Noise arithmetic.** No reference-host rows; nothing to recompute.
- **Sources.** [2] MITRE T1498.001 fetched; quoted phrase confirmed. [3a] mdk4 README fetched; modes b/a/p/d/m/e/s/w/f/x confirmed, the mode-a quote is verbatim, and the README has no dedicated association-flood mode (consistent with the entry). [3b] aircrack-ng fake-authentication page fetched; it describes open-system/shared-key auth plus association and does not use the word "flood" either way - the sentence claiming it "explicitly does not flood" was reworded to what the page supports. [7] USENIX page fetched; confirmed. [8] IEEE page fetched; exists, now marked superseded by 802.11-2024. [1] research/mitre/T1498.md exists, lists `ALERT_TYPE_ASSOC_FLOOD` in `alert_kinds`, quoted definition at line 33-34. [9] repo paths/lines confirmed (alerts.md:138, where-exploits-happen.md:56, alert-remediation.md heading 850, pcap-export.md table row).
- Bibliography numbering (1, 2, 3, 7, 8, 9) is left as found; no body citation points at a missing number.

### Second verification pass (2026-10-27, tree at d70d394)

- **Benign-cause bullet corrected (substantive).** The entry said duplicate frames are "bounded by the ring's distinct-frame counting". They are not: assoc_track.c:325-333 de-duplicates *BSSIDs being scored*, not frames, and every request (retransmissions included) is recorded. Front matter `count_semantics` and *Benign causes* rewritten accordingly.
- **Added:** the 256-slot ring is shared across all BSSIDs, which caps `n` at 256 and silently shortens a long tuned window in a busy environment.
- Rule re-read (src/alerts/rules_wifi_mgmt.c:135-171): `n < thresh` early return (152), key `assocflood:%s` (159), `distinct > 3` wording (164), `mine` -> CRIT (169), `fire_ev()` with `assoc_flood_evidence()`; tune rows src/tune.c:189-190 (2..256, 1..3600). All as stated.
- **Cadence (second pass).** "~4/s" is the nominal floor, not a fixed rate: `POLL_MS` 250 is the *longest* wait between polls, because the wait in src/main.c:1666/1671 returns early on the event-wake fd, which `fire_inv()` signals on every new incident key and every escalation (src/alerts/engine.c:526, 608), and the TUI also returns on a keypress. Polls per second are therefore >= 4, and any duration derived as `count / 4` is an upper bound.
- Sources re-opened: [2] MITRE T1498.001 (quote verbatim); [3a] mdk4 README (modes b/a/p/d/m/e/s/w/f/x, mode-a "Too many clients can freeze or reset several APs", no association-flood mode); [3b] aircrack-ng fake authentication (auth + association, `-o 1` "confuses some APs", no flood); [7] USENIX Bellardo & Savage; [8] IEEE 802.11-2020 page (superseded by 802.11-2024). [1] research/mitre/T1498.md lists `ALERT_TYPE_ASSOC_FLOOD` with the quoted definition at line 33. No source struck.
