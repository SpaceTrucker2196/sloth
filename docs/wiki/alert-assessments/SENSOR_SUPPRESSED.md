---
type: SENSOR_SUPPRESSED
technique: ""
rule_file: src/alerts/rules_sensor.c:577 rule_sensor_suppressed()
count_semantics: per rule evaluation - one fire() per alerts_update() tick per signal whose last one-minute window was over its threshold. Three keys, one per signal (`suppressed:evict`, `suppressed:drop`, `suppressed:silent`); the detail names the worst table, the handle or the channel and the threshold passed, never the minute's own count, so `observations` moves only when what is named changes.
severity_assessment: agree - WARN. The sensor is still hearing and is losing a share of what it hears; a whole domain gone is SENSOR_SOURCE_DOWN's CRIT. No source gives a loss rate past which the sensor should be called blind.
false_positive_risk: medium, unmeasured for silent - the eviction and drop thresholds are set well above the reference sensor's measured baseline (2026-11-23), not from a source; the silent-channel run of 3 has no baseline at all (the look's hop_silent_channels 0 counts never-heard channels, which the signal excludes), and a sparse channel heard once early in the run beside a busy one in its band can raise it on a quiet site. A segment far busier than Beta-Site's can evict past 600 a minute without anyone attacking it, and a channel whose only transmitters switch off reads as silent; both are the rule saying what it measures, and both still cost the rules evidence.
noise_verdict: not measured - written 2026-11-23 with the rule; the baseline is one 115 s look at the live stream, no firing data yet.
prevalence: not an adversary technique - a state of the sensor's own collection. Its causes include a beacon or probe spray (mdk4, a Flipper or ESP32 spammer), a deauth or RTS flood, a host too slow for the link, and a jammer on one channel; the rule does not tell them apart.
tuning: --tune suppress.evict_per_min (600), suppress.drop_pct (1), suppress.drop_min (100), suppress.silent_intervals (3)
researched: 2026-11-23
---
## What the rule checks

`rule_sensor_suppressed()` (sloth-wifi's rule table only) keeps a one-minute window, the length of the coverage record's interval (`COV_IV_MS`), and at each window's end judges two signals; the third follows the coverage record:

- **evict**: per synthesis table of `src/sensor_health.h`, the rise of its lifetime tally `sh_evict_count()` over the minute, against `suppress.evict_per_min` (600). Not judged: the six flow rings and `evidence_frame` (they roll over on a working sensor by design; the reference sensor's evidence ring ran 143 a second), `alert` and `pcap_cooldown` (sloth's own bookkeeping) and `rtl433` (sloth-rf's).
- **drop**: per capture handle (the monitor radio's and `--iface`'s), `ps_drop + ps_ifdrop` over the minute as a share of `ps_recv` (pcap_stats(3PCAP)), against `suppress.drop_pct` (1 %), with at least `suppress.drop_min` (100) drops. A handle with no `pcap_stats()` sample at both ends is not judged.
- **silent**: from each closed `coverage_interval`, the channels merged by frequency over the radios. A channel visited in the interval with no frame, while another visited channel of its band heard frames, and which heard frames in an earlier interval of this run, extends its run; a channel heard, not visited, or with its whole band quiet resets it. A run of `suppress.silent_intervals` (3) is the signal.

A signal over its threshold opens an incident (key `suppressed:<signal>`, WARN), is re-asserted every tick until a window ends under it, and closes with the `alert.resolve` reason `recovered` after `SENSOR_RECOVER_S` (120 s) under it without a break, the hold SENSOR_SOURCE_DOWN uses. Nothing is judged on a `--replay` (tables fill at file speed; the coverage record is not kept).

While an incident is open the coverage environment carries what it suppresses (`cov_env_t.suppressed`, `suppressed_frames`), and the rules that read that evidence report `partly` with the reason `suppressed` (`docs/wiki/coverage-assessment.md`): an evicting 802.11 table names its frame classes (the probe tables probe requests, the beacon table beacons, the EAPOL and EAP tables EAPOL, and so on; the sequence-number and RF-channel tables every 802.11 kind), an IP table every IP kind, a BLE table every BLE advertising kind, the device table both 802.11 and IP; a dropping handle every kind on its input; a silent channel every 802.11 kind.

## The attack

None claimed. An own-operational-state kind, the first exemption form (`tests/test_research_corpus.c :: test_own_state_kinds_are_named`), empty technique. A flood of fresh transmitter addresses fills sloth's bounded tables, a flood of frames overruns the kernel ring, and a jammer silences one channel: each costs the sensor evidence, and each has benign causes the rule cannot tell from it. It reports the loss, not its cause.

## Evidence that proves it

- the alert detail: the worst table and whether others passed, the handle and its interface, or the channel and its band, with the threshold;
- `sensor_health`'s `evict_<table>` lifetime tallies and the `capture_*` / `monitor_*` `recv`, `drop` and `ifdrop` fields, differenced over the minute;
- the `coverage_interval` records' `chans` (per channel `ms` and `frames`) for the silent channel;
- the `rule_status` rows that turned `partly` / `suppressed` while it was open.

## Benign causes

A segment busier than the tables are sized for (a conference hall, a stadium), many phones probing with rotating random addresses, a host whose CPU or SD card cannot keep up with the capture, a channel whose only APs were switched off or moved.

## Assessment

**Severity.** WARN: the sensor still hears the site, and the incident says which part of what it hears is being lost. SENSOR_SOURCE_DOWN keeps the CRIT for a domain gone whole.

**Sufficient to act on?** As a statement about the sensor, yes: the counters are sloth's own. As a statement about an attacker, no; look at the flood rules (`BEACON_FLOOD`, `PROBE_FLOOD`, `DEAUTH_FLOOD`, `RTS_FLOOD`) for the same minutes.

## Bibliography

1. src/sensor_health.h - the eviction tally, its tables and the flow-ring distinction (accessed 2026-11-23)
2. pcap_stats(3PCAP), libpcap - ps_recv, ps_drop, ps_ifdrop (accessed 2026-11-23)
3. src/cov_interval.h, docs/wiki/jsonl-schema.md `coverage_interval` - the per-channel time and frames (accessed 2026-11-23)
4. docs/wiki/coverage-assessment.md - the statuses and the `suppressed` reason (accessed 2026-11-23)
5. Beta-Site live stream, tcp:127.0.0.1:8765, 2026-11-23, 115 s of `sensor_health` - the baseline in src/alerts.h (accessed 2026-11-23)

## Verification notes

Written 2026-11-23 with the rule; verified against the working tree only. Tests: `tests/test_sensor_suppressed.c` (a thousand hand-built probe requests through the monitor callback, recovery, the thresholds and the tallies not judged, the device table, monitor and capture drops and their absences, a silent channel and the four shapes that are not one, a replay, separate incidents), `tests/test_rule_coverage.c :: test_suppressed`, `tests/test_rule_coverage_live.c :: test_suppressed_reaches_the_statuses`.
