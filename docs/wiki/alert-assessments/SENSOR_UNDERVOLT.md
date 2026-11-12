---
type: SENSOR_UNDERVOLT
technique: ""
rule_file: src/alerts/rules_sensor.c:87 rule_sensor_undervolt()
count_semantics: per rule evaluation - one fire() per alerts_update() tick while the host-status snapshot's under-voltage alarm reads 1 (sampled every SYS_SAMPLE_SECS, 10 s, so the value held between samples is re-asserted every tick). One key per host (`undervolt:host`); the detail names the first alarming node and holds still while the alarm does, so `observations` moves only when the set of alarming nodes changes.
severity_assessment: agree - WARN; the alarm is the host's own supply dipping below what the board needs, a fault that threatens the sensor's storage and USB receivers but is not an attack and not, by itself, evidence that anything was damaged. CRIT is not given: no source read for this rule states a held duration past which damage is to be expected.
false_positive_risk: low - the input is the kernel's own alarm attribute; a node that reports 1 is the hardware or firmware saying so. The one gap is the other way: a dip shorter than the 10 s sample interval is not seen.
noise_verdict: not measured - written 2026-11-11 with the rule; no reference-host firing data yet. By construction one incident per episode: held across a flapping alarm and closed (`recovered`) after 120 s of the alarm reading 0.
prevalence: not an adversary technique - a configuration state of the sensor's host, common on a Raspberry Pi run from an undersized supply or a long thin cable, and absent on hosts with no `inN_lcrit_alarm` node (most desktops and VMs), where the rule never fires.
tuning: [none - SENSOR_RECOVER_S (120 s) is a compile-time constant in src/alerts/rules.h; the sample interval is SYS_SAMPLE_SECS in src/sys_status.h]
researched: 2026-11-11
---
## What the rule checks

The input is `sys_status_get()`, the snapshot `src/sys_status.c` re-derives on the poll's health stage (`src/poll.c` `st_health()`, before `alerts_update()`). `sample_hwmon()` reads every `/sys/class/hwmon/hwmonN/inM_lcrit_alarm` through the platform's text reader and sets `has_undervolt` when any exists and `undervolt` when any reads 1; on a Raspberry Pi that node is the firmware's under-voltage flag exposed by the `rpi_volt` hwmon driver (`src/sys_status.c`, the comment in `sample_hwmon()`). The kernel's hwmon ABI defines `inN_lcrit_alarm` as the critical low-voltage alarm, 0 or 1 [1].

`rule_sensor_undervolt()` returns while there is no snapshot or no alarm node. With the alarm at 1 it fires WARN under the key `undervolt:host`, the detail naming the first node whose alarm reads 1 (its `id`, e.g. `hwmon1/in0`, and its label, the driver name) and whether other nodes agree. With the alarm at 0 it starts a clear hold; an open incident is resolved with the `alert.resolve` reason `recovered` once the alarm has read 0 for `SENSOR_RECOVER_S` (120 s) without a break. A flapping alarm therefore stays one incident.

## The attack

None. This is one of the own-operational-state kinds pinned by `tests/test_research_corpus.c :: test_own_state_kinds_are_named`, with an empty technique in `include/sloth_alerts.def`. What it reports is the sensor's own power supply.

Why it matters to a sensor: a supply below the board's minimum is how SD cards get corrupted (a write interrupted by a brown-out) and how USB receivers drop off the bus, and a dropped receiver is a source going down - which `SENSOR_SOURCE_DOWN` then reports with its own severity.

## Evidence that proves it

- the alert detail (node id and driver);
- the `sys_status` record's `undervolt` field and the `sys_sensor` row of class `volt` with `alarm` 1, in the batch written at once when the alarm goes from 0 to 1 (docs/wiki/jsonl-schema.md, *Host status and the source inventory*);
- slothweb's Sensor health page, which charts `sys.undervolt`, and its Alerts view, which shows the detail since 2026-11-12 (`web/src/web_alertfmt.c`: the hwmon id and the driver's label are the host kernel's text).

To confirm on the host: `cat /sys/class/hwmon/hwmon*/in*_lcrit_alarm`, and the kernel log.

## Benign causes

All causes are "benign" in that nobody is attacking: an undersized or non-rated supply, a long or thin USB cable, USB devices drawing more than the board can supply, a supply sagging under load.

## Assessment

**Severity.** WARN. The condition is real and worth showing on every view, but CRIT is reserved for a finding with a stated basis for its urgency; a held-duration CRIT would need a source stating the span, and none was found.

**Sufficient to act on?** Yes: the fix is on the operator's own bench.

## Bibliography

1. Linux kernel documentation, Documentation/hwmon/sysfs-interface.rst - the `in[0-*]_lcrit_alarm` attribute, the voltage critical-minimum alarm, 0 or 1 (the document the sys_status test fixtures are written from, tests/test_sys_status.c header; not re-fetched for this page)
2. src/sys_status.h, src/sys_status.c - the reader and its cadence (accessed 2026-11-11)
3. docs/wiki/jsonl-schema.md - `sys_status.undervolt`, `sys_sensor.alarm` (accessed 2026-11-11)

## Verification notes

Written 2026-11-11 with the rule; verified against the working tree only. The tests are `tests/test_sensor_rules.c` (fires and clears, two alarming nodes, a flapping alarm, no alarm node).
