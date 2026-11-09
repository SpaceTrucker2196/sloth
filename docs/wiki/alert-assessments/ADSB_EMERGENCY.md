---
type: ADSB_EMERGENCY
technique: ""
rule_file: src/alerts/rules_adsb.c:103 rule_adsb_emergency() (the condition in condition() at line 43, the three codes in emerg_code() at line 32; tune row adsb.emerg_hold_s in src/tune.c)
count_semantics: per poll while the condition stands - one fire() per listed aircraft with a condition each alert pass, one incident per (address, condition); the detail changes at most twice (status filled in, first sight to held) and then holds still, so observations stay put while evaluations follow the poll rate. Not per message
severity_assessment: agree - LOW on first sight, WARN once held 10 s of the aircraft's own messages, never CRIT: the declaration is unambiguous when real, but unauthenticated, forgeable, and about a third party rather than the operator's network
false_positive_risk: medium - a decode error or a code dialled through in passing is kept at LOW by the hold; a forged false alarm (Schafer et al. 2013 §3.2) cannot be told from a real one by one receiver, and lifeguard / minfuel are priority states rather than distress
noise_verdict: not measured - new rule (#186, 2026-11-08); no reference-host firing data yet. Emergency squawks are rare in any one receiver's coverage
prevalence: rare; the literature demonstrates forged ADS-B messages with commodity SDRs against enthusiast receivers [3][4]
tuning: [adsb.emerg_hold_s (10, 2..59); the codes and status words are fixed by SERA.13005 and readsb's README-json.md]
researched: 2026-11-08
---
## What the rule checks

`rule_adsb_emergency()` (src/alerts/rules_adsb.c:103) walks the ADS-B table `adsb_health_poll()` copied onto the state (`s->adsb_rows`), only while the source is `live` (`s->adsb.state == ADSB_LIVE`). An aircraft has a condition (`condition()`, line 43) when its squawk is exactly `7500`, `7600` or `7700` (`emerg_code()`, line 32), else when its emergency/priority status is present and not `none`. The condition is the code when there is one, else the status word.

- **Key** `adsbemerg:<icao hex>:<icao|nonicao>:<condition>`: a code change re-keys and re-fires; a status following its code from `none` to `general` is the same incident.
- **Severity** LOW until the same condition has held `adsb.emerg_hold_s` (10 s) measured on the row's `last_mono_ms` - the decoder's last message from the aircraft on sloth's monotonic clock - then WARN. Never CRIT.
- **Detail**: the address (`non-ICAO ~` for a '~' address), callsign (`-` absent), squawk, status word, `first sight` or `held past adsb.emerg_hold_s`, and "flag only: ADS-B is unauthenticated and a false alarm can be injected; sloth cannot verify it and takes no action". No `match_ip`.
- **Not evaluated**: a row the table no longer lists (its incident expires on the quiet period), and every row while the source is `stale`, `error` or `waiting`.

Empty technique, second exemption form (research/adsb/emergency-squawks.md).

## The mechanism

SERA.13005 (the ICAO procedure in EU law): 7700 "a state of emergency", 7600 "a state of radio-communication failure", 7500 "a state of unlawful interference" [1]. readsb reports the ADS-B "emergency/priority status, a superset of the 7x00 squawks (2.2.3.2.7.8.1.1)" with the words none, general, lifeguard, minfuel, nordo, unlawful, downed, reserved [2]. ADS-B has no "entity authentication to protect against message injection" [3], and Schafer et al. describe the "False Alarm Attack" - re-injecting or modifying a real aircraft's messages "in order to indicate a fake alarm" [4].

## Evidence that proves it

What sloth records: the alert detail; `adsb_aircraft` records (change-only, the squawk and emergency in the signature) and, with `--db`, `adsb_aircraft` / `adsb_sightings`, so the aircraft's track around the declaration is kept.

Towards a real declaration: the condition held for minutes on a consistent address, callsign and track; the aircraft's behaviour changed with it (descent, diversion). Towards a decode error: one LOW that never held. Towards a forgery: nothing sloth can show - a second, independent receiver or air traffic control is the only check [4].

## Benign causes

- A code dialled through in passing while changing squawk, or a corrupted reply - held at LOW.
- `lifeguard` (a medical priority flight) and `minfuel` - priority states, reported because they are declarations, not distress.
- A training or test transponder on the ground.

Excluded and tested (tests/test_adsb_rules.c): status `none` and absent, squawks 1200, 7000, 7777, 0000 and 7701, a row the table has dropped, a stale source, and an aircraft relisted with `seen` growing (no new messages) which stays LOW.

## Assessment

**Severity.** LOW/WARN, never CRIT: a real emergency is serious but not the operator's to act on, and a forged one is indistinguishable here.

**Default.** 10 s is a judgement - ten of readsb's one-second documents - not a cited figure; no source read gives one [2].

**Sufficient to act on?** No; it is a flag. It is sufficient to look at the aircraft.

**First step for a responder.** Open the aircraft in the ADS-B view and read its track and how long the condition held.

## Bibliography

1. Commission Implementing Regulation (EU) No 923/2012, SERA.13005, UK CAA regulatory library - read 2026-11-08
2. readsb README-json.md (wiedehopf/readsb, branch dev), DO-260B clause references as given there - read 2026-11-08; DO-260B itself not read
3. A. Costin, A. Francillon, "Ghost in the Air(Traffic): On insecurity of ADS-B protocol and practical attacks on ADS-B devices", Black Hat USA 2012, §III - read 2026-11-08
4. M. Schafer, V. Lenders, I. Martinovic, "Experimental Analysis of Attacks on Next Generation Air Traffic Communication", ACNS 2013, LNCS 7954, §3.2, doi:10.1007/978-3-642-38980-1_16 - read 2026-11-08

## Verification notes

Written 2026-11-08 with the rule, against the working tree that adds it. Code facts checked against src/alerts/rules_adsb.c, src/adsb.c (the sticky merge; `last_mono_ms` = read time minus `seen`) and src/tune.c. Sources [1], [2], [3], [4] read first-hand on 2026-11-08 (research/adsb/emergency-squawks.md quotes them); ICAO Doc 8168 / Doc 4444, FAA AIM 4-1-20 and RTCA DO-260B not read. No reference-host firing data yet.
