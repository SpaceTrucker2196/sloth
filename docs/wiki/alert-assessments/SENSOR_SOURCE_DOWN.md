---
type: SENSOR_SOURCE_DOWN
technique: ""
rule_file: src/alerts/rules_sensor.c:157 rule_sensor_source_down()
count_semantics: per rule evaluation - one fire() per alerts_update() tick per configured source that is open or past its hold (down 10 s, or not ok 300 s). One key per source (`srcdown:<name>`); the detail carries the state, the reader's own word and the freshness band, never an age in seconds, so `observations` moves only when one of those changes.
severity_assessment: agree - CRIT for the monitor radio and the IP capture, whose loss leaves the sensor silent on its whole 802.11 or wired domain while the views look like a quiet network; WARN for the Bluetooth, GNSS, ADS-B and APRS sources, which each feed one domain beside them.
false_positive_risk: low - the input is sloth's own reader state (source_status); the holds keep a reconnect that succeeds within seconds and a short lull out. A wired capture on a segment that is genuinely silent for five minutes would fire, which is the rule saying exactly what it measures.
noise_verdict: not measured - written 2026-11-11 with the rule; no reference-host firing data yet. By construction one incident per episode per source: re-asserted in every state but ok, closed (`recovered`) after 120 s of ok.
prevalence: not an adversary technique - a state of the sensor's own receivers; most often a USB radio or decoder that dropped, an interface renamed or unplugged, or a decoder process that stopped.
tuning: [none - SENSOR_SRC_DOWN_HOLD_S (10 s), SENSOR_SRC_STALE_S (300 s) and SENSOR_RECOVER_S (120 s) are compile-time constants in src/alerts/rules.h]
researched: 2026-11-11
---
## What the rule checks

The input is `sys_status_get()`'s `src[]`, the seven `source_status` rows `src/sys_status.c` `fill_sources()` re-derives every poll from the readers' own health (`cap_health`, `mon_health`, `bt_health`, `btcap`, `gps`, `adsb`, `aprs` on the state). Each row is `not_configured`, `ok`, `stale` or `down` by that file's rules: a pcap stream not open or whose worker exited is `down`, one with no frame for more than 60 s or none yet is `stale`; a decoder in error is `down`, connecting or quiet `stale`.

`rule_sensor_source_down()` skips a row that is `not_configured`. For the rest it keeps two clocks per source: how long it has read `down` without a break, and how long it has read anything but `ok`. It opens an incident, key `srcdown:<name>`, when the first reaches `SENSOR_SRC_DOWN_HOLD_S` (10 s) or the second `SENSOR_SRC_STALE_S` (300 s); while one is open it re-asserts it in every state but `ok`; it resolves it with the `alert.resolve` reason `recovered` once the source has read `ok` for `SENSOR_RECOVER_S` (120 s) without a break. Severity is CRIT for `capture` and `monitor`, WARN for the others.

## The attack

None. An own-operational-state kind (`tests/test_research_corpus.c :: test_own_state_kinds_are_named`), empty technique. A source going down could be the result of something an adversary did (a jammed band, an unplugged radio), but the rule cannot tell that from a fault and does not claim to.

## Evidence that proves it

- the alert detail: source name, kind, endpoint, state, the reader's own word (`not open`, `exit: iface_gone: ...`, `error: connection refused`, `no frame yet`) and the freshness band;
- the `source_status` row, written the moment its state changes, and the `sys_status` batch's `sources_down` (docs/wiki/jsonl-schema.md);
- `sensor_health`'s per-stream liveness fields for the pcap streams;
- slothweb's Alerts view, which shows the detail since 2026-11-12 (`web/src/web_alertfmt.c`: every field the host's own text, the same strings the `source_status` row carries).

## Benign causes

A USB receiver that dropped off the bus (see `SENSOR_UNDERVOLT`), an interface that was renamed or unplugged, a decoder (readsb, gpsd, Dire Wolf) stopped or restarted, a wired segment with no traffic.

## Assessment

**Severity.** CRIT for the two main sources is the point of the rule: a sensor that lost its monitor radio keeps drawing views, and an operator reading an empty Probes view as "nobody is probing" is the failure this exists to prevent. WARN for the others.

**Sufficient to act on?** Yes: the receiver is on the operator's own bench.

## Bibliography

1. src/sys_status.h, src/sys_status.c - the source rows, their states and the 60 s stale figure (accessed 2026-11-11)
2. docs/wiki/jsonl-schema.md - `source_status`, `sys_status.sources_down` (accessed 2026-11-11)
3. docs/wiki/alerts.md - the own-operational-state section (accessed 2026-11-11)

## Verification notes

Written 2026-11-11 with the rule; verified against the working tree only. The tests are `tests/test_sensor_rules.c` (down at startup after the hold, severity by source, stale past the threshold, recovery, down then stale, a flapping source, not configured).
