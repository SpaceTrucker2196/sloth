---
type: GNSS_SPOOF_SUSPECT
technique: ""
rule_file: src/alerts/rules_gnss.c:861 rule_gnss_spoof_suspect() (bound and benign-step helpers at lines 341 and 181; tune rows in src/tune.c, gnss.spoof_*)
count_semantics: per poll tick while at least two of the three heuristics have each been seen within gnss.spoof_window_s - fire() bumps count every poll (>= 4/s) in that state, so a single sighting of two heuristics keeps the incident asserted for up to the window (300 s) afterwards; one increment is one poll. One incident per receiver (key `gnssspoof`)
severity_assessment: agree - LOW on two heuristics, WARN on three, never CRIT: the research calls every heuristic weak alone and says nothing short of cryptographic authentication stops a careful spoofer, so the rule reports a suspicion
false_positive_risk: medium - a GPS repeater (DHS 2017's unintentional spoofing) can satisfy heuristics 1 and 2 together, an amplified antenna heuristic 1, a cold start or USB re-enumeration heuristic 3; requiring two in one window and gating heuristic 2 on a high mean keep the common single causes out
noise_verdict: not measured - new rule (2026-11-03); no reference-host firing data yet. Expected silent on a nominal sky: heuristic 1 needs four used satellites at 53 dB-Hz, 8 dB over the nominal band's top
prevalence: civil GNSS spoofing of a fixed ground sensor is rare in the read sources; the documented demonstrations are Humphreys et al.'s portable spoofer [3] and Psiaki & Humphreys' survey [2]; repeaters and amplified antennas are the common producers of the same readings [1]
tuning: [gnss.spoof_cn0_high_db (53, 30..99), gnss.spoof_high_sats (4, 1..48), gnss.spoof_cn0_mean_db (45, 20..99), gnss.spoof_cn0_sd_db (1, 1..20), gnss.spoof_min_sats (6, 3..48), gnss.spoof_window_s (300, 10..3600); heuristic 3 also reads gnss.pos_jump_k and gnss.time_jump_ms]
researched: 2026-11-03
---
## What the rule checks

`rule_gnss_spoof_suspect()` (src/alerts/rules_gnss.c:861) keeps, per heuristic, the monotonic time it was last seen and the figures it was seen with, and fires while at least two were seen within `gnss.spoof_window_s`. The sky is evaluated only when it is younger than `GNSS_LIVE_MS` (5 s). Only satellites **in the solution** with a C/N0 count: a spoofer must be in the fix to move it.

- **Heuristic 1, absolute C/N0 too high**: at least `gnss.spoof_high_sats` used satellites at or above `gnss.spoof_cn0_high_db`.
- **Heuristic 2, uniform and high**: over at least `gnss.spoof_min_sats` used satellites, the standard deviation of C/N0 under `gnss.spoof_cn0_sd_db` with the mean at or above `gnss.spoof_cn0_mean_db`.
- **Heuristic 3, reacquisition with a jump**: a positioned fix flagged `reacq` (the first since a TPV said mode 0/1, or since the source was lost; src/gps.c) whose distance from the fix before it exceeds the `GNSS_POSITION_JUMP` bound, or whose time stepped against the monotonic clock by `gnss.time_jump_ms` (leap second and week rollover excluded, as in `GNSS_TIME_JUMP`). Each fix pair is judged once.
- **Key** `gnssspoof`. **Severity** LOW for two, WARN for three; there is no CRIT path. **Detail** names each heuristic seen with its figures (`[1] n used >= X dB-Hz (max)`, `[2] n used, mean, sd`, `[3] reacquired m away, time ms`) and ends "each is weak alone - a repeater, an amplified antenna or a cold start can explain one". No `match_ip`.

Empty technique, second exemption form: no technique in any ATT&CK matrix names GNSS spoofing; ICS T0830 is a network session and T0856 (now T1692.002) an ICS reporting message (research/gnss/attack-mapping.md) [4]. On the list in tests/test_research_corpus.c.

## The attack

A spoofer transmits counterfeit satellite signals stronger than the authentic ones and walks the receiver's solution. Psiaki & Humphreys: one capture method is "to start by jamming the victim in order to disrupt normal tracking and induce re-acquisition"; if the spoofed signals are stronger "the receiver will lock with high probability onto the false signals during re-acquisition" (§II-B) [2]. Humphreys et al. 2008: an unsynchronised attack "may cause the victim receiver to lose lock and have to undergo a partial or complete reacquisition. Such a forced re-acquisition would raise suspicion" [3]. Received Power Monitoring "looks at the total received power on an absolute scale" (§III-A); gpsd exports only the per-signal half of it, `ss` [2]. One transmitter delivering every counterfeit signal at one power also erases the elevation dependence authentic signals show - the basis of heuristic 2, which the research calls weak [1].

What none of this can do: "All current COTS GNSS receivers are vulnerable to spoofing attacks" (§VI) [2]; "nothing short of cryptographic authentication can guard against a sophisticated spoofing attack" [3]; a code-phase-matched capture "avoids detection by the receiver tracking loops because they all maintain lock" [2]; and a spoofer present before sloth started has no transition to observe - the u-blox M8's own detector "will be unable to recognize the spoofing" in that case [1].

## Evidence that proves it

What sloth records: the alert detail; the `gnss_sat` rows (per satellite C/N0 to 6 dB, elevation and azimuth to 15 degrees, used) and `gnss_sky` (`cn0_mean`, `cn0_max`, `cn0_sd`, `cn0_n`); `gnss_fix` (mode, position, `time_off_ms`, `eph`); with `--db`, `gnss_fixes` and `gnss_sightings`. The `[#]` view and slothweb's GNSS tab show the sky sorted by C/N0.

To strengthen the suspicion: the high, uniform C/N0 appeared on every used satellite at once, not slowly; it followed a loss of lock; the position or the time moved at reacquisition and stayed moved; nothing on the operator's own premises (a repeater, a new amplified antenna) explains it. To weaken it: a repeater or amplified antenna in the building, a recent receiver restart or USB re-plug, or a receiver indoors.

## Benign causes

- A GPS repeater, which DHS 2017 names as a source of unintentional spoofing [1].
- A high-gain or amplified antenna, raising every satellite's C/N0 [1].
- Antenna gain and front-end noise figure: two receivers on one antenna may report different C/N0 (Inside GNSS) [1].
- A cold or warm start, a USB re-enumeration, or a moving receiver passing under cover, behind a reacquisition with a jump [1].

Excluded and tested (tests/test_gnss_rules.c): any one heuristic alone; an indoor sky (uniform but weak) beside a reacquisition jump; high C/N0 on satellites outside the solution; two heuristics 400 s apart; a reacquisition to the same place and time; a stale sky.

## Assessment

**Severity.** LOW/WARN, never CRIT, is the only honest range for heuristics the research calls weak alone.

**Defaults.** 53 dB-Hz is Kriezis et al.'s spoofing threshold for a u-blox F9P with an ANN-MB antenna, 8 dB over the top of the nominal "~ 37 to 45dB-Hz"; "Neither number transfers to a u-blox 7 with an unknown antenna", so it is the conservative choice [1]. Four satellites because a fix needs four. For heuristic 2 "No peer-reviewed source read for this document states a uniformity (low-spread) threshold" [1]: 1 dB is below what a sky across elevations shows, six satellites make the spread meaningful, and the 45 dB-Hz mean gate (the nominal band's top) keeps the indoor case out. 300 s spans a jam-then-capture sequence; DHS 2017 advises delaying reacquisition "for many minutes or hours".

**Sufficient to act on?** Sufficient to stop trusting this receiver's position and time for anything that matters and to look for a repeater or an antenna change; not sufficient to assert an attack.

**First step for a responder.** Compare the reported position and time against an independent reference, and look for a repeater or amplified antenna on the premises.

## Bibliography

1. research/gnss/spoofing-detection.md - repo research note (retrieved 2026-11-02): u-blox GPS.G7-SW-12001-B and UBX-13003221 R28 §16, gpsd_json(5), Inside GNSS "Measuring GNSS Signal Strength" (2010), Kriezis et al. arXiv:2509.13600v2, DHS 2017
2. M. L. Psiaki, T. E. Humphreys, "GNSS Spoofing and Detection", Proc. IEEE 104(6):1258-1270, 2016, doi:10.1109/JPROC.2016.2526658 - as quoted in research/gnss/spoofing-detection.md (authors' preprint section numbers)
3. T. E. Humphreys, B. M. Ledvina, M. L. Psiaki, B. W. O'Hanlon, P. M. Kintner Jr., "Assessing the Spoofing Threat: Development of a Portable GPS Civilian Spoofer", ION GNSS 2008, pp. 2314-2325 - as quoted in research/gnss/spoofing-detection.md
4. research/gnss/attack-mapping.md - the ATT&CK Enterprise, Mobile and ICS search for a spoofing technique (read 2026-11-02)

## Verification notes

Written 2026-11-03 with the rule, against the working tree that adds it. Code facts checked against src/alerts/rules_gnss.c, src/gps.c (the `reacq` flag: first positioned fix, after a mode 0/1 TPV, after `gps_location_source_lost()`) and src/tune.c. Sources **not re-fetched**: quotations are from research/gnss/spoofing-detection.md and research/gnss/attack-mapping.md, which record their own first-hand reading on 2026-11-02. No reference-host firing data yet.
