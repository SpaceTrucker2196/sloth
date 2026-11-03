---
type: GNSS_JAMMING
technique: T1464
rule_file: src/alerts/rules_gnss.c:306 rule_gnss_jamming() (constants at lines 34-69; tracked median in src/gps.c sky_tracked_median_x10(); tune rows in src/tune.c, gnss.jam_*)
count_semantics: per poll tick while either path holds - fire() bumps count every poll (>= 4/s at POLL_MS 250) in which the newest one-second point shows the collapse (held against its onset baseline while the median stays down) or a jamInd run at or above gnss.jam_ind spans gnss.jam_hold_s; one increment is one poll, not one satellite or one TPV. One incident per receiver (key `gnssjam`), resolving through the engine's quiet period once neither path holds
severity_assessment: agree - WARN for a collapse or a held indicator, CRIT only when the fix is lost (mode 0/1), the research's end state of a jam and the point where every position stamp sloth writes is gone; never a claim of intent, which DHS 2017 says the observable cannot carry
false_positive_risk: medium - the C/N0 path cannot tell jamming from attenuation (an antenna fault, a cable, a tunnel or garage for a moving sensor), which the research states; the slow-decline, keeps-its-solution, shrinking-list, partial-obstruction and empty-sky cases are excluded and tested. The median is over tracked satellites only (ss > 0), so satellites lost behind an obstruction do not dilute it. The indicator path is uncalibrated (the vendor says calibrate in place), so a receiver whose ordinary jamInd sits high would fire it
noise_verdict: not measured - new rule (2026-11-03); the reference host runs `--gps gpsd://127.0.0.1:2947` with a 3D fix on 13 satellites and no firing data exists yet. Expected quiet at a fixed outdoor antenna: a collapse needs a 10 dB fall of the tracked median within 10 s with the used set falling
prevalence: GPS jamming devices are illegal to operate in the US with "no exceptions for personal, commercial, educational, or vehicular use" [4], yet the FCC's Bojczak case is a vehicle jammer disrupting an airport's augmentation system [5]; unintentional interference is the common cause of the same reading [1]
tuning: [gnss.jam_cn0_drop_db (10, 1..60), gnss.jam_window_s (10, 2..120), gnss.jam_ind (128, 1..255), gnss.jam_hold_s (30, 2..299); the 60 s baseline, its 30-point minimum, the 2-satellite used-set and list falls and the 3 s gap are compile-time constants in src/alerts/rules_gnss.c]
researched: 2026-11-03
---
## What the rule checks

`rule_gnss_jamming()` (src/alerts/rules_gnss.c:306) reads the one-second series in `s->gnss_hist` - per point the median C/N0 ×10 and the count of the sky's **tracked** satellites (ss > 0; src/gps.c `sky_tracked_median_x10()`), satellites used and listed, the TPV's `jam` (u-blox MON-HW `jamInd`, sticky for `GNSS_JAM_HOLD_TPVS` TPVs in src/gps.c) and its mode, each stamped with the host's monotonic clock at receipt. It reads the snapshot `gps_health_poll()` copied, never src/gps.c. Nothing is evaluated if the newest point is older than `GNSS_LIVE_MS` (5 s): a receiver not being heard says nothing about now.

- **Path (a), the collapse.** The baseline is the mean of the tracked median and the rounded mean tracked, used and listed counts of the points in the 60 s (`GNSS_JAM_BASELINE_MS`) before a `gnss.jam_window_s` window ending at the newest point, counting only points that tracked a satellite, and only when at least 30 such points exist (`GNSS_JAM_BASELINE_MIN`), so the first minute of a run cannot fire. It fires when the newest point's tracked median is at least `gnss.jam_cn0_drop_db` under the baseline (a point tracking nothing while the sky is listed counts as 0: every satellite fell out of tracking, the research's end state), the newest point still lists satellites (`nsat > 0`) and the list did not fall by two (`GNSS_JAM_NSAT_FALL`: "while nSat is unchanged"), and the used set fell by at least two (`GNSS_JAM_USAT_FALL`; uSat flaps by one) or the fix is lost. Tracked only and a median, because gpsd lists untracked satellites at ss 0 and "Attenuation by an obstruction is direction-dependent": the first version averaged the ss-0 rows in, and four of ten satellites lost behind a building read as a 12 dB collapse while the other six never moved. Once it fires, the onset baseline is held while the median stays under it by the drop, so a standing jam is not resolved by its own collapse ageing into the baseline.
- **Path (b), the indicator.** Walking back from the newest point while `jam >= gnss.jam_ind` and no two points are more than 3 s apart (`GNSS_JAM_GAP_MS`), the run must span `gnss.jam_hold_s` (each point stands for its second).
- **Key** `gnssjam` (the `akey_*` builder, no remote string). **Severity** CRIT when the newest point's mode is 0 or 1, else WARN. **Detail**: the baseline and current tracked median, the drop, the window, the tracked and used counts before and after, the satellites still listed, the held `jamInd` and its span, "fix lost" when it is, and "interference or jamming: the receiver cannot tell which (DHS 2017), nor locate the source". No `match_ip`, so no pcap.

## The attack

A GNSS jammer raises the noise floor in L1 until the receiver cannot track: DHS 2017 defines interference as "unintentionally produced RF waveforms that raise the effective noise floor in the receiver processing" and jamming as the same waveforms produced intentionally - "the only difference is the intent" [1]. DHS's Development Strategy 7 asks the receiver to "recognize and report the presence of interference and jamming", "as simple as monitoring for significant changes in the RF power ... and for changes in effective C/N0" [1]; Strategy 8 names "concurrent knockoff jamming" as the first step of a spoofing attack [1]. Mobile ATT&CK T1464 is the one technique in any matrix whose text names it: an adversary "able to jam radio signals (e.g. Wi-Fi, cellular, GPS) around a device to prevent it from communicating" [3]. The mapping is the observable, on `RF_DEGRADED`'s precedent, not a claim of intent.

What a u-blox 7 behind gpsd can show is narrower than what the receiver measures. The u-blox 7 has `jamInd` ("CW Jamming indicator, scaled (0 = no CW jamming, 255 = strong CW jamming)"), `agcCnt`, and the ITFM `jammingState` monitor, which "is disabled by default"; gpsd 3.27 copies only `jamInd` into the TPV and logs the other two (research/gnss/jamming-detection.md) [2]. Broadband interference therefore has no gpsd field except its effect on `ss` - which is why path (a) exists - and the signature that separates a noise-floor rise from an obstruction is the simultaneity: "Attenuation by an obstruction is direction-dependent; a noise-floor rise is not" [2].

## Evidence that proves it

What sloth records: the alert detail's figures; the `gnss_sky` record's mean-C/N0 band and `gnss_fix`'s jam band and mode as they cross bands (docs/wiki/gnss.md, change-only); the `gnss_sat` rows showing each satellite's C/N0 band moving together; `sensor_health`'s `gnss_cn0_mean` and `gnss_jam`; the `[#]` view and slothweb's GNSS tab. With `--db`, `gnss_fixes` and `gnss_sightings` hold the same history.

To lean towards interference rather than an antenna fault: satellites at every elevation and azimuth fell together (an obstruction is directional), the receiver's `jamInd` rose with it (CW interference; uncalibrated), and the C/N0 recovered without anyone touching the antenna. Spens et al.'s rule of thumb needs the AGC, which gpsd does not export: "If AGC decreases and C/N0 decreases, jamming is likely ... if AGC is unchanged ... poor signal may be attributed to attenuation" [6]. Nothing sloth records locates a source.

## Benign causes

- The antenna, its cable or its amplifier failing, or something placed over it - the same reading.
- A moving sensor entering a tunnel or a garage; foliage when the solution is lost.
- Physical obstructions, scintillation and multipath, which "can produce signatures similar to those of jamming" (Kriezis et al.) [2].
- Nearby equipment radiating in the band unintentionally (DHS's interference) [1].
- For the indicator path: a receiver whose ordinary `jamInd` is high, since the vendor requires calibrating the "not jammed" case in place [2].

Excluded and tested (tests/test_gnss_rules.c): a sky falling 20 dB over five minutes; a 12 dB dip that keeps the solution; the list shrinking with the drop; four of ten satellites lost behind an obstruction with the rest unchanged, fed through src/gps.c's own parser; an empty sky (antenna removed); a stale series; a run with a 10 s gap; 20 s of high `jamInd`.

## Assessment

**Severity.** WARN with CRIT on fix loss is right: the loss of fix is the operational consequence (no position stamps, no GNSS time) and is unambiguous, while the cause never is.

**Defaults.** 10 dB because "No read source puts a number on 'simultaneous' or on the drop; any value is a judgement" [2]: it is the distance from the bottom of the nominal "~ 37 to 45dB-Hz" band to the 27 dB-Hz Kriezis et al. use as signal loss [2]. 10 s stretches the research's "one or two epochs" over gpsd's SKY cadence. `jamInd` 128 is the top half of the scale and the top band the `[#]` view grades, so an uncalibrated install errs quiet; 30 s because gpsd attaches `jam` about one TPV in four.

**Sufficient to act on?** Sufficient to treat the receiver's position and time as unavailable and to look for a local cause; not sufficient to assert an attack or to look for a person.

**First step for a responder.** Check the antenna and its cable, and whether the C/N0 fell on every satellite at once.

## Bibliography

1. DHS NCCIC/NCC, "Improving the Operation and Development of Global Positioning System (GPS) Equipment Used by Critical Infrastructure", 2017-01-06 - as quoted in research/gnss/jamming-detection.md (read first-hand 2026-11-02 by that document)
2. research/gnss/jamming-detection.md - repo research note (retrieved 2026-11-02): u-blox GPS.G7-SW-12001-B §13.2-13.3 and §38.2, gpsd release-3.27 `drivers/driver_ubx.c`, Kriezis et al. arXiv:2509.13600v2, Inside GNSS 2010 (via research/gnss/spoofing-detection.md)
3. MITRE ATT&CK Mobile T1464, Network Denial of Service - https://attack.mitre.org/techniques/T1464/ - as quoted in research/gnss/attack-mapping.md (read 2026-11-02)
4. FCC Enforcement Bureau, "Jammer Enforcement", Updated September 2026 - as quoted in research/gnss/jamming-detection.md
5. FCC 13-106, Gary P. Bojczak, NAL released 2013-08-02 - as summarised in research/gnss/jamming-detection.md
6. N. Spens, D.-K. Lee, F. Nedelkov, D. Akos, "Detecting GNSS Jamming and Spoofing on Android Devices", NAVIGATION 69(3), 2022, doi:10.33012/navi.537 - as quoted in research/gnss/jamming-detection.md

## Verification notes

Written 2026-11-03 with the rule, against the working tree that adds it. Code facts (line numbers, constants, knob defaults and ranges, key, severity) checked against src/alerts/rules_gnss.c and src/tune.c in that tree. The sources were **not re-fetched** for this file: every quotation is taken from research/gnss/jamming-detection.md and research/gnss/attack-mapping.md, which record their own first-hand reading on 2026-11-02. No reference-host firing data exists yet, so the noise verdict is an expectation, labelled as one.
