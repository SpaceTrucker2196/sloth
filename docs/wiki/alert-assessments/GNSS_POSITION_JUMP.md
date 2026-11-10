---
type: GNSS_POSITION_JUMP
technique: ""
rule_file: src/alerts/rules_gnss.c:639 rule_gnss_position_jump() (the bound in pos_bound_m() at line 302, Δt in fix_dt_s() at line 207; tune row gnss.pos_jump_k in src/tune.c)
count_semantics: per offending fix pair - each consecutive pair of positioned fixes is judged once, and a pair past the bound is one fire(); a receiver that jumps away and back is two fires in one incident. One incident per receiver (key `gnsspos`). Not per poll
severity_assessment: agree - WARN: an unphysical move is the observable the spoofing literature names, and is not CRIT because multipath and receiver faults produce it too
false_positive_risk: medium - multipath at a fixed site can exceed the error estimate (the research says the estimate "may not cover it"), and gpsd's eph has no stated confidence level; the speed term, the eph multiplier and the reacquisition skip keep a moving vehicle and a cold start out
noise_verdict: not measured - new rule (2026-11-03); no reference-host firing data yet. A fixed outdoor antenna with eph of a few metres has a bound near 6 x eph; multipath is the expected producer if it fires
prevalence: position spoofing is demonstrated in the literature (Psiaki & Humphreys' yacht case) [2]; multipath outliers are routine at urban fixed sites [1]
tuning: [gnss.pos_jump_k (3, 1..100); the speed and its error come from the receiver's own TPV speed and eps]
researched: 2026-11-03
---
## What the rule checks

`rule_gnss_position_jump()` (src/alerts/rules_gnss.c:639) walks the positioned-fix ring in `s->gnss_hist` (mode >= 2 with a position; the ring holds no other) and judges each consecutive pair once. The bound (`pos_bound_m()`, line 302) is

`(v + eps) × Δt + gnss.pos_jump_k × (eph₁ + eph₂)`

with `v` the larger of the two fixes' reported `speed`, `eps` the larger reported speed error (gpsd TPV `eps`, 0 when absent), and Δt the time between the two fixes' epochs: the receiver's own time difference (`fix_dt_s()`, line 207), which is the research's Δt. The host's receipt gap is not it: a reader that stalls and then drains gpsd's queue reads fixes a second apart a millisecond apart, and the first version's bound shrank to the error estimates alone for a car doing 30 m/s. The receiver's difference is used when it is positive and at most 30 s (`GNSS_BACKLOG_MAX_MS`) past the host's elapsed time (the larger of its monotonic and wall clocks', so a suspend counts); otherwise the monotonic gap, so a receiver clock stepped by an hour cannot stretch the bound over a position jump made with it. It fires when the great-circle distance (`gps_distance_m()`) exceeds the bound.

- **Not judged**: a pair whose second fix is a reacquisition (the first positioned fix since start, after a mode 0/1 TPV, or after a lost source), and a pair where either fix has no `eph` - no error estimate, no bound, no claim.
- **Key** `gnsspos`. **Severity** WARN. **Detail**: distance, Δt, the bound, the speed and eps used, both eph values and k, and "a spoofed position, multipath or a receiver fault look alike here". No `match_ip`.

Empty technique, second exemption form, with a second reason: faults produce it too (research/gnss/attack-mapping.md).

## The attack

Psiaki & Humphreys §III-C: "the known maxima of its velocity, acceleration, and turn rate could be used to check for excessive drift"; their §II-D yacht spoof was caught because it showed speeds "above 900 kts" for a vessel that "could not cruise above 16 kts" [2]. The research turns that into `|Δpos| <= (v_max + eps)·Δt + eph₁ + eph₂`, with `v_max` the platform's own limit - for a fixed sensor zero, so "the bound collapses to the two error estimates" [1]. sloth knows no platform limit, so the receiver's reported speed stands in for it: a spoofer moving the solution smoothly with a matching speed is not caught, which is the patient drag-off the literature says jump tests cannot see [2].

## Evidence that proves it

What sloth records: the alert detail; `gnss_fix` records (position to five decimals, `eph`, `speed_mps`, mode) when a band moves; with `--db`, `gnss_fixes` and the position samples; the alert's own `loc` stamp ([[location]]), which is the position as the incident opened.

To lean towards a moved solution rather than multipath: the fix stayed at the new position, the jump coincided with other GNSS findings (`GNSS_TIME_JUMP`, `GNSS_SPOOF_SUSPECT`, `GNSS_JAMMING`), and the reported speed did not account for it. To lean towards multipath: the fix returned within a few seconds, the sensor is fixed near reflecting surfaces, and `eph` was small.

## Benign causes

- Multipath at a fixed site; "the error estimate may not cover it" [1].
- A 2D fix (mode 2) with an assumed altitude [1].
- gpsd sending several TPVs per epoch ("Multiple TPV objects are often sent per epoch") [1] - the same position, so harmless to the bound.
- The first fix after a reacquisition [1] - not judged.

Excluded and tested (tests/test_gnss_rules.c): a vehicle at 30 m/s moving 30 m a second; the same vehicle's queued fixes read a millisecond apart after a 3 s stall, and one fix read 400 ms late at 35 m/s; a cold start's first fix 5 km away; fixes without `eph`; and `gnss.pos_jump_k` moving a 20 m jump from over to under the bound. Also tested the other way: an hour's step of the receiver's clock does not widen the bound over a 1 km jump.

## Assessment

**Severity.** WARN is right for an observable whose benign twin is common.

**Default.** k = 3 because "Because the confidence level of eph is unknown, a multiplier on it is a judgement, not a cited value" [1]: three covers `eph` read as one sigma, the least conservative of gpsd's four readings ("guessed to be 95% confidence, may also be 50%, one sigma, or two sigma"), to three sigma per fix. Spens et al.'s 100 m threshold is a phone's GNSS-against-network-location check and is not transferred [1].

**Sufficient to act on?** Sufficient to treat the receiver's position as unverified while it recurs; not sufficient to assert spoofing alone.

**First step for a responder.** For a fixed sensor, compare against its known location; check whether the jump held or snapped back.

## Bibliography

1. research/gnss/time-and-position-integrity.md - repo research note (retrieved 2026-11-02): gpsd_json(5) TPV `speed`, `eps`, `eph`, `epx`/`epy` and the confidence caveat; Spens et al., NAVIGATION 69(3), 2022, §3.1.2
2. M. L. Psiaki, T. E. Humphreys, "GNSS Spoofing and Detection", Proc. IEEE 104(6):1258-1270, 2016, doi:10.1109/JPROC.2016.2526658 - as quoted in research/gnss/time-and-position-integrity.md and research/gnss/spoofing-detection.md

## Verification notes

Written 2026-11-03 with the rule, against the working tree that adds it. Code facts checked against src/alerts/rules_gnss.c, src/gps.c (`eps` parsed from the TPV since this change; the per-fix `reacq` and `mono_ms`) and src/tune.c. Sources **not re-fetched**: quotations are from research/gnss/time-and-position-integrity.md and research/gnss/spoofing-detection.md, which record their own first-hand reading on 2026-11-02. No reference-host firing data yet.
