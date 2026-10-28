---
type: RF_DEGRADED
technique: T1498
rule_file: src/alerts/rules_wifi_mgmt.c:1063 rule_rf_degraded()
count_semantics: per evaluation tick, per channel key - fire() bumps count every poll in which that channel's current-window retry ratio is still at or above 40%; one increment is one poll (~4/s at POLL_MS 250), NOT one retried frame. The 40% ratio itself is computed over a tumbling (reset, not sliding) 300 s window of >=100 frames in src/rf_quality.c, so the alert is a thresholded measurement, not a per-event counter
severity_assessment: agree - WARN is correct and load-bearing: a retry ratio is an observable with at least four benign causes, and the rule explicitly refuses to call it jamming
false_positive_risk: high - "false positive" is the wrong frame here; the rule reports a real measurement whose CAUSE is ambiguous. Interference and congestion trip it as readily as a jammer
noise_verdict: quiet on the reference host - 122,791 fires over 10 keys, max_sev 1 (WARN). Given per-tick counting that is ~12k ticks per channel = roughly 50 minutes of continuous degradation per channel averaged, i.e. a handful of genuinely bad channels held degraded for a long time, not a firehose. 10 keys = 10 distinct channel numbers. No dedupe needed; if it were noisier the knobs are RF_RETRY_DEGRADED_PCT / RF_WINDOW_SECS / RF_MIN_FRAMES (compile-time, not in the --tune registry)
prevalence: jamming proper is rare and illegal [5]; the benign producers of the same signal (congestion, hidden nodes, microwave ovens, range) are everyday [3][4]
tuning: [--hop (monitor-mode channel hopping feeds rf_quality; without monitor mode the rule has no input), --monitor-only; no --tune knob - the three thresholds are #defines in src/rf_quality.h]
researched: 2026-10-27
---
## What the rule checks

`rule_rf_degraded()` (src/alerts/rules_wifi_mgmt.c:1063-1080) reads `s->channels[]`, the per-channel summary that `rf_quality_snapshot()` annotates. The snapshot only fills rows that already exist - and `channel_summary_t` rows exist only for channels with a beaconing AP (src/rf_quality.h, `rf_quality_snapshot` comment: "Rows for channels with no beacon are not created") - so a channel carrying retries but no beacons can never fire this rule.

- **Input.** `channel_summary_t` rows (include/sloth.h:1984-1985 carry `retry_pct`, `badfcs_pct`). `rf_quality_observe()` (src/rf_quality.c) counts every 802.11 frame per (channel, band) from the Frame Control **Retry** bit and the radiotap FCS-failed flag, fed at src/capture/probe.c:418 (`rf_quality_observe(channel, band, fr.retry ? 1 : 0, rt.bad_fcs, fts)`).
- **Thresholds** (src/rf_quality.h): `RF_MIN_FRAMES 100` (below this, ratio is `-1` = "not enough to say"), `RF_RETRY_DEGRADED_PCT 40`, `RF_WINDOW_SECS 300`. The window **tumbles**, it does not slide: `roll_if_stale()` (src/rf_quality.c:39-47) zeroes a channel's frame/retry/bad-FCS counters once the window is more than 300 s old and opens a new one ("Counters are reset rather than decayed"). Right after each roll the ratio is `-1` until 100 new frames arrive, so a continuously bad channel drops out of the condition briefly every ~5 minutes; the incident survives that gap because it resolves only after 300 s without a re-assertion. Early in each window the ratio is computed over as few as 100 frames.
- **Condition.** For each channel, skip if `retry_pct < 40` (line 1066; `-1` is also skipped). Otherwise fire.
- **Key.** `rfdegraded:<channel>` (line 1070) - one incident per channel number.
- **Detail.** `ch <n>: <r>% retries, <b>% bad-FCS over <frames> frames - interference, hidden node or jamming` (lines 1071-1076; a `badfcs_pct` of `-1` renders as `0`). The wording deliberately lists competing causes rather than naming an attacker.
- **Severity.** Always WARN (line 1077). No CRIT, no ownership escalation - a channel is shared airtime with no BSSID to own.
- **Count.** Plain `fire()`, no evidence IDs, no `match_ip`. Each poll with the channel still degraded increments `evaluations`/`count`; the detail moves only when the integer percentages or frame count change, so `observations` tracks measurement changes while `count` tracks polls.
- **Band detail (#149).** `rf_quality` keys on (channel, band) internally because 5/6 GHz channel numbers overlap, then sums bands into the one per-number `channel_summary` row (src/rf_quality.h comments). The alert key is the bare channel number, so a degraded 6 GHz ch149 and a healthy 5 GHz ch149 share one incident.

## The attack

MITRE T1498, Network Denial of Service, is "degrade or block the availability of targeted resources to users" [2]; the repo maps RF_DEGRADED here because that is where an operator looks for it, "not because sloth believes an adversary is present" [1a]. On 802.11 the contended resource is airtime, shared by every radio in earshot regardless of network, which makes wireless DoS "unusually cheap and unusually indiscriminate" [1a].

A retry ratio is the downstream symptom. An 802.11 transmitter sets the Retry bit on any frame it is re-sending after a missing ACK; sustained high retries mean frames are not getting through. The classic deliberate cause is a radio-frequency jammer - a transmitter that floods the band with noise or protocol frames. Xu et al. study the feasibility of both launching and detecting jamming with commodity radios [3] (their constant/deceptive/random/reactive jammer taxonomy and packet-delivery-ratio detection metric are as the paper is generally cited; only its title, authors and venue were re-verified for this entry, the ACM full text being closed); Pelechrinis et al. survey the same space [3a]. Bellardo & Savage's 2003 work is the management-frame-attack companion: deauth/auth floods as practical 802.11 DoS [7]. A frame flood (mdk4, aireplay-ng) raises retries because it collides with legitimate traffic; a noise jammer raises them by corrupting receptions (which also shows as bad FCS). Operating a jammer in the US is illegal: the FCC's enforcement advisory says that unless you are an authorised federal user "you may not operate a jammer in the U.S., even on private property", with penalties "up to $112,500 for any single act" plus seizure and criminal sanctions [5].

The honest point, which the rule's own wording makes, is that identical numbers come from non-adversarial sources: a microwave oven radiates in the 2.4 GHz ISM band and was measured interfering with WLANs as early as 1997 [4]; a hidden node (two stations that cannot hear each other but both reach the AP) collides at the AP; a client at the edge of range retransmits constantly. None of these is an attacker.

## Evidence that proves it

What sloth records:

- The alert detail: channel, retry %, bad-FCS %, frame count over the window.
- JSONL `channel_summary` (docs/wiki/jsonl-schema.md:707): `channel`, `band`, `ap_count`, `assoc_count`, `best_signal`, `top_ssid`, the measured control-frame volume `ctrl_total`/`ctrl_rts`/`ctrl_cts`/`ctrl_ack`/`ctrl_blockack`, and `last_seen`. **The retry and bad-FCS ratios are not in that record** (src/jsonl.c:1344-1360 writes exactly the fields above), so the only JSONL trace of the measurement is the alert record's own detail string.
- The `[m]` Channel view shows the `retry` and `ctrl` columns per band (docs/views/channel.md:88-96, 163-184).
- No pcap and no evidence-ring citation: the signal is an aggregate ratio, not a set of frames, so there is nothing to cite (docs/wiki/pcap-export.md:140-160 lists the citing rules; this is not one).

To lean toward deliberate jamming rather than interference: a very high **bad-FCS** fraction alongside the retries points at corrupted receptions (noise/reactive jamming) rather than mere contention - but only if failed-FCS frames reach the capture at all. On mac80211 a monitor interface passes bad-FCS frames only when created with `NL80211_MNTR_FLAG_FCSFAIL` ("pass frames with bad FCS", [9]), and nothing under src/ requests that flag, so on a default monitor interface a near-zero bad-FCS figure can mean "not delivered", not "not happening". Treat a low bad-FCS figure as weak evidence unless the interface was set up with `fcsfail`; a retry spike "confined to one channel while its neighbours stay clean" (docs/views/channel.md:207) argues against a broadband domestic source like a microwave (which smears across 2.4 GHz); and a correlated flood alert on the same channel (`DEAUTH_FLOOD`, `AUTH_FLOOD`, `BEACON_FLOOD`, `RTS_FLOOD`) names a protocol-level DoS as the cause (docs/wiki/alert-remediation.md:850-860 directs exactly this correlation).

What refutes an attack reading: the retries track a known busy period (a conference, an office at 9am), the same ratio appears on adjacent channels (broadband interference), the bad-FCS fraction is low (contention, not corruption), or a single far client dominates the `assoc` rows.

## Benign causes

- **Channel congestion** - many APs/clients contending; the measurement and the cause are the same shape as an attack and sloth cannot separate them [1a].
- **Microwave ovens and other ISM emitters** - documented 2.4 GHz interference [4].
- **Hidden-node collisions** - a topology problem, not an intruder.
- **A distant client at the edge of range** - retransmits every frame; one weak `assoc` row explains it.
- **DFS/weather-radar environments** and overlapping non-Wi-Fi systems.

The discriminators are: is it one channel or many; is bad-FCS high or low; is there a co-channel flood alert; and what the `assoc`/`channel_summary` rows say about load.

## Assessment

**Severity.** WARN, and it must stay WARN: calling an ambiguous measurement a CRIT would train the operator to distrust the type the first time a microwave set it off. The rule reports the observable and hands attribution to the operator (rules_wifi_mgmt.c:1063-1073).

**Prevalence.** Deliberate RF jamming is rare (and unlawful in the US [5]); the everyday producers of the same reading - congestion, hidden nodes, ovens, range - are common [3][4]. So a firing RF_DEGRADED is far more often an RF-health finding than a security one.

**Reference host noise verdict.** Quiet. 122,791 fires on 10 keys, all WARN. Per-tick counting (one increment per ~250 ms poll while a channel is >=40% retries) means ~12,279 fires per channel ~= at most 51 minutes of sustained degradation per channel over the capture (an upper bound: polls run at >= 4/s, see Verification notes), i.e. a small number of channels that were genuinely bad for extended periods - not a per-frame firehose. 10 keys is 10 distinct channel numbers, which is a realistic hop set. No dedupe or threshold change is warranted on this evidence. If an operator did want to quiet it, the levers are compile-time (`RF_RETRY_DEGRADED_PCT`, `RF_WINDOW_SECS`, `RF_MIN_FRAMES`); they are not in the `--tune` registry, so raising the floor means a rebuild.

**Is the evidence sufficient to act on?** Sufficient to investigate an RF problem; insufficient to assert an attack. The alert is a prompt to look at the Channel view and the co-channel flood alerts, not a verdict.

**First step for a responder.** Check whether a flood alert fired on the same channel in the same window (that converts "degraded" into "attacked"); if not, treat it as interference - compare adjacent channels, look at the bad-FCS fraction, and move the network off the channel or find the emitter.

## Bibliography

1. research/mitre/T1498.md - repo research note (retrieved 2026-09-07); [1a] its statements that airtime is the contended resource, that RF_DEGRADED "is not a flood detector ... the observable a flood produces, and also the observable a microwave oven produces", and that the T1498 mapping is "where an operator will look for it, not because sloth believes an adversary is present" (accessed 2026-10-27)
2. MITRE ATT&CK T1498, Network Denial of Service - https://attack.mitre.org/techniques/T1498/ (accessed 2026-10-27)
3. W. Xu, W. Trappe, Y. Zhang, T. Wood, "The feasibility of launching and detecting jamming attacks in wireless networks", MobiHoc '05, doi:10.1145/1062689.1062697 (DOI resolved via Crossref 2026-10-27; ACM DL full text returned 403); [3a] K. Pelechrinis, M. Iliofotou, S. V. Krishnamurthy, "Denial of Service Attacks in Wireless Networks: The Case of Jammers", IEEE Communications Surveys & Tutorials vol. 13, 2011, doi:10.1109/SURV.2011.041110.00022 (DOI resolved via Crossref 2026-10-27)
4. A. Kamerman, N. Erkocevic, "Microwave oven interference on wireless LANs operating in the 2.4 GHz ISM band", PIMRC '97 vol. 3, doi:10.1109/PIMRC.1997.627080 (DOI resolved via Crossref 2026-10-27)
5. FCC Enforcement Advisory DA 12-347 (No. 2012-02), "Cell Jammers, GPS Jammers, and Other Jamming Devices" - https://docs.fcc.gov/public/attachments/DA-12-347A1.pdf (PDF fetched and text-extracted 2026-10-27; quotes above are verbatim)
6. FCC, Jammer Enforcement - https://www.fcc.gov/general/jammer-enforcement (returned 403 on two fetch attempts 2026-10-27; **not relied on** - every legal claim above is sourced to [5])
7. J. Bellardo, S. Savage, "802.11 Denial-of-Service Attacks: Real Vulnerabilities and Practical Solutions", 12th USENIX Security Symposium, 2003 - https://www.usenix.org/legacy/events/sec03/tech/bellardo.html (accessed 2026-10-27)
9. Linux kernel include/uapi/linux/nl80211.h, `enum nl80211_mntr_flags`: "@NL80211_MNTR_FLAG_FCSFAIL: pass frames with bad FCS" - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/linux/nl80211.h (fetched 2026-10-27)
8. docs/views/alerts.md:205 (rule table row); docs/views/channel.md:163-222; docs/wiki/alert-remediation.md:833-848 - repo documents (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree at commit 0d60387.

- **Code.** `rule_file`, thresholds (`RF_MIN_FRAMES` 100, `RF_RETRY_DEGRADED_PCT` 40, `RF_WINDOW_SECS` 300 in src/rf_quality.h), key, severity and the plain `fire()` all match. Corrected line references: span 1063-1080, condition 1066, key 1070, detail 1071-1076, fire 1077. Added two facts the entry lacked: a `badfcs_pct` of -1 renders as 0, and rows exist only for channels with a beaconing AP, so a beaconless channel cannot fire.
- **Evidence section corrected.** The entry claimed a `degraded` record and implied the ratio reaches JSONL `channel_summary`; src/jsonl.c:1344-1360 writes no retry/bad-FCS field. Replaced with the actual field list and the statement that the ratio appears in JSONL only via the alert detail.
- **Noise arithmetic** re-checked: 122,791 / 10 = 12,279 per key; / 4 Hz = 3,070 s = 51 min. Holds. The ~4 Hz cadence follows from `POLL_MS` 250 and `alerts_update()` once per poll (src/poll.c:296); the reference-host counts themselves were not re-derivable here (no data file in the KB directory), so they are taken as given.
- **Sources.** [2] MITRE T1498 fetched; quoted phrase confirmed. [3], [3a], [4] resolved through the Crossref API (titles, authors, venues confirmed); publisher pages were 403/empty, so the Xu et al. sentence was softened to what was verified. [5] PDF fetched and text-extracted; the $112,500 figure and the "even on private property" wording are verbatim - the body now quotes [5] rather than asserting "under the Communications Act", which came from the unreachable [6]. [6] still 403; marked not-relied-on and every citation of it removed from the body and front matter. [7] USENIX page fetched; abstract confirms the 802.11 management/media-access DoS scope. [1] research/mitre/T1498.md exists, lists `ALERT_TYPE_RF_DEGRADED` in `alert_kinds`, and the quoted sentences are at lines 42-44 and 54-56. [8] repo paths/lines confirmed.

### Second verification pass (2026-10-27, tree at d70d394)

- **Window semantics corrected (substantive).** The entry described a "rolling 5-minute" ratio in which "observations older than 5 minutes stop counting". The code resets instead: `roll_if_stale()` (src/rf_quality.c:39-47) zeroes the counters once the window is older than `RF_WINDOW_SECS` and the snapshot sums the per-band rows under one channel number (src/rf_quality.c:147-175). Front matter and *What the rule checks* corrected, with the consequence (a brief `-1` gap every window, absorbed by the 300 s resolve).
- **Bad-FCS discriminator qualified.** grep shows no `FCSFAIL`/monitor-flag request anywhere in src/ or include/; the kernel delivers failed-FCS frames to a monitor interface only with `NL80211_MNTR_FLAG_FCSFAIL` (new source [9], fetched from git.kernel.org). The "high bad-FCS points at jamming" heuristic is now caveated.
- Rule re-read (src/alerts/rules_wifi_mgmt.c:1063-1080), thresholds (src/rf_quality.h), probe.c:418 call site counting every frame type incl. control: all as stated.
- **Cadence (second pass).** "~4/s" is the nominal floor, not a fixed rate: `POLL_MS` 250 is the *longest* wait between polls, because the wait in src/main.c:1666/1671 returns early on the event-wake fd, which `fire_inv()` signals on every new incident key and every escalation (src/alerts/engine.c:526, 608), and the TUI also returns on a keypress. Polls per second are therefore >= 4, and any duration derived as `count / 4` is an upper bound. The 51-minute figure is relabelled as an upper bound.
- Sources re-opened: [2] MITRE T1498 (quote verbatim); [3]/[3a]/[4] re-resolved via Crossref (titles, authors, venues match); [5] FCC DA-12-347 PDF re-fetched and text-extracted - "even on private property" and "up to $112,500 for any single act" verbatim; [7] USENIX Bellardo & Savage page (management and media-access DoS confirmed). [1] research/mitre/T1498.md lists `ALERT_TYPE_RF_DEGRADED` and carries both quoted sentences (lines 42-44, 54-56). [6] left as not-relied-on.
