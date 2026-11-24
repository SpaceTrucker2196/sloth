---
name: passive-cueing
description: --cue. A finding of six fixed 802.11 kinds holds the --hop scheduler 4x longer on the channel it was heard on for 120 s, within limits; receive-only, opt-in, refused under --strict
type: reference
---

# Passive cueing

**Summary**: under `--cue` (with `--hop`), a new `EVIL_TWIN`, `KARMA_AP`, `KARMA_PROBE_FORGE`, `DEAUTH_FLOOD`, `PMKID_HARVEST` or `HANDSHAKE_HARVEST` incident makes the hop scheduler dwell 4 times its normal plan on the channel the finding was heard on, for 120 s, so the sensor collects more of what follows. Only sloth's own monitor radio is retuned, nothing is transmitted, no other receiver is started and no cue leaves the sensor. Cues are capped (4 at once, 8 started per 10 minutes, at most half of a radio's time, every other channel still visited); a cue over a cap is refused and counted, and the refusals feed `SENSOR_SUPPRESSED`, because false triggers are how an attacker would hold the radio on one channel.

**Status**: #248, scheduler dwell only, 2026-11-24 (JSONL 2.13.0). Built: the flag, the policy, the cued dwell, the `cue` record, the `sensor_health` fields, `suppressed:cue`. Not built, by ruling: recordings by `sloth-rf` (ruling 5), cues to another site (ruling 6, sloth-mesh#19), a BLE crosswalk mark. Not in sloth.db.

**Sources**: `src/chancue.h`, `src/chancue.c` (the policy); `src/wifi_chanhop.h`, `src/wifi_chanhop.c` (the cued dwell, `chanhop_cue_fits()`, `chanhop_set_cue()`); `src/cue_live.c` (the findings, the records); `src/main.c` (`--cue`, the announcement); `src/observe.c` (the `--strict` refusal); `src/alerts/rules_sensor.c` (`suppressed:cue`); `src/mon_radios.c` (`mon_hop_sched_rw()`); `tests/test_chancue.c`, `tests/test_observe.c`, `tests/test_sensor_suppressed.c`. FM 2-0 (2004) 8-14, 1-26, 4-18. Issue #248 and the owner's rulings of 2026-11-23 on it.

**Last updated**: 2026-11-24 (#248: the page).

---

## 1. Why

FM 2-0 (2004) 8-14: SIGINT "is often used to cue, and be cued by," other sensors; 1-26 asks collection to find gaps and "cue or redirect" sensors; 4-18 to plan for "the quick retasking" of sensors. Before this, `--hop` (#22) followed its own plan: a twin found on channel 6 did not change how long the radio stayed on channel 6, so the handshakes, deauthentications and probe responses that follow a twin were heard for one dwell in eleven. This is the narrowest form of cueing: the sensor cueing its own receiver.

## 2. The rulings (2026-11-23)

The owner answered yes to all six:

1. A longer dwell that follows a finding is inside MISSION.md § 2: it retunes only sloth's own receiver and puts nothing on the segment. Recorded as a dated note beside the #22 carve-out; no rule text changed.
2. Opt-in: `--cue`, off by default, announced on stderr at start with what it enables, the kinds and the caps; refused under `--strict`.
3. Limits: all cues together at most 50 % of radio time; a cue raises the cued channel's dwell to 4x the normal dwell for 120 s; caps on concurrent cues and on the cue rate; a cue over any limit is refused and counted, and the count feeds `SENSOR_SUPPRESSED`; every other channel keeps a minimum share.
4. The kinds, a fixed list: `EVIL_TWIN`, `KARMA_AP`, `KARMA_PROBE_FORGE`, `DEAUTH_FLOOD`, `PMKID_HARVEST`, `HANDSHAKE_HARVEST`. Never own-state kinds, never wired kinds.
5. `sloth-rf` does not start recordings.
6. No cue travels to another site (sloth-mesh#19).

## 3. The command line

| Command line | Result |
|---|---|
| `--hop --cue` | on; one stderr line names the kinds, the 4x / 120 s dwell and the caps |
| `--cue` without `--hop` | ignored, one stderr line says so; the run goes on (as `--monitor-iface` radios are left where they were parked without `--hop`) |
| `--strict --cue` | refused, exit 2, before anything opens (`OBSERVE_PROFILE_REFUSE_CUE_UNDER_STRICT`); `--strict --allow-active --cue` names the `--allow-active` refusal first |
| `--cue` in a `WITH_PCAP=0` build | ignored with a notice: nothing hops |
| `--cue` with `--preflight` or `--handoff` | nothing announced; they start nothing |

## 4. The finding's channel

The channel a finding was heard on is the radiotap frequency of the first frame it cites in the evidence ring (`cue_live_finding_mhz()`): every one of the six kinds cites frames (`fire_ev` / `fire_inv`), and for `EVIL_TWIN` the accused half comes first. A finding whose cited frames have left the ring, or carry no frequency, does not cue (refused `no_channel`). No kind is excluded for want of a channel. A frequency in no radio's `--hop` rotation (a radio parked by hand, or a frame whose radiotap names a channel the list does not hold) is refused `not_hopped`: a cue never adds a channel.

Each incident is offered once, as it opens (the hop stage runs after `alerts_update()`); a finding on a channel already cued is absorbed, with no record and the running cue's end unchanged. "Once" holds for as long as the incident stays open: the set of incidents offered is rebuilt every poll from the open incidents the alert table still holds, so an id leaves it only when its incident resolves or is evicted, and incident ids are never reused. (Until the #248 review it was a ring of the last 128 ids, and an incident open while 128 newer ones passed through was offered again.) Every `cue` record of a poll is written: the events are flushed after the expiry tick and after each request, so a burst of incidents in one poll (after a monitor outage, say) cannot overflow the 32-event queue.

## 5. The dwell

A cued channel's dwell is `CHANHOP_CUE_MULT` (4) times its normal plan, the #22 activity plan (`base + 8 ms × activity`, clamped to 100..2000 ms). On the reference sensor the mean planned dwell was 897 ms with busy channels at the 2000 ms cap (2026-11-24, 55 s of its live stream), so 4x the *base* 250 ms would have changed nothing where it matters; the multiple is of the channel's own plan, up to 8000 ms. A cue set while the radio is on that channel lengthens the dwell under way. The rotation order never changes: every channel is visited once a rotation, cued or not. When the 120 s are up the cue ends (`ended`) and the next visit is planned normally; a cued dwell under way finishes.

The dwell is measured where it always was: `coverage_interval`'s per-channel `ms`, `sensor_health`'s `hop_dwell_*`, and `cue_cued_ms` (radio 0's time in cued dwells). The coverage assessment needs no new status: a cue moves channel time, which `coverage_interval` already reports.

## 6. The limits

| Limit | Value | Refusal word |
|---|---|---|
| cues at once, all radios | 4 (`CUE_MAX_ACTIVE`) | `active_cap` |
| cues started in any 10 minutes | 8 (`CUE_RATE_MAX`, `CUE_RATE_WINDOW_MS`) | `rate_cap` |
| on the radio holding the channel, the cued channels' planned dwells together against the uncued channels' | at most equal: cues at most 50 % of that radio's time | `share_cap` |
| the same rule with no other cue running on that radio | the share can hold one cue at all | `share_small` (not a limit) |

**The share rule** (`chanhop_cue_fits()`): with the candidate counted as cued, Σ 4 × plan(cued) ≤ Σ plan(uncued). So cues take at most half of the radio, and since an uncued channel's own dwell is unchanged and the rotation is at most twice as long, **every uncued channel keeps at least half of the share it would have with no cue** - never zero. With the default 11 channels at equal plans, two cues fit (8 ≤ 9 plans) and a third does not (12 > 8). The rule is also applied when each cued dwell is planned (`cued_plan()`): if the neighbours' activity has fallen since the cue was admitted, the cued dwell is cut to what is left of the half, never below its normal plan, so the 50 % holds in the plan and not only at admission.

**Per radio, not summed over radios.** With several sensor radios ([[multi-radio-sensing]]) a cue is served by the radio whose share of the list holds its channel, and the share rule is that radio's. The default 11 channels dealt among three radios leave shares of 4, 4 and 3, where one channel at 4x would take 4/7 or 4/6 of its radio even with no other cue: every cue is refused `share_small` (`chanhop_cue_fits_alone()`), the radio layout's refusal and not load's, checked before the caps. With two radios (6 and 5 channels) one cue fits on each; with a longer `--hop` list more do. The stricter reading of "50 % of radio time" was chosen because a channel is covered only by the radio that holds it; summing over radios would let one radio's channels fall to a third of their share. Whether to relax it for several radios is the owner's call.

**Refusals and SENSOR_SUPPRESSED.** Every refusal is counted (`cue_refused`); the three limit refusals also in `cue_refused_limit`, and `SENSOR_SUPPRESSED`'s `suppressed:cue` signal opens when that rises by `suppress.cue_refused_per_min` (5) or more in a minute ([[coverage-assessment]] § 7), reaching every 802.11 kind as `partly`, `suppressed`. `no_channel`, `not_hopped` and `share_small` are not limits and are not counted there: none of them is airtime taken by other cues, so a sensor whose shares are too short to cue (three radios on the default list) does not raise `suppressed:cue` on ordinary findings (#248 review; it did before, at five findings a minute). The default is unmeasured; the reasoning is in `src/alerts.h`.

## 7. Receive-only

A cue changes one number per slot, how long the scheduler stays; the retune that follows is the one `--hop` already makes, `set_channel` on sloth's own monitor interface. `cue_live_step()` makes no platform call. `tests/test_chancue.c :: test_cue_is_receive_only` drives cues through the whole hop stage (three sensor radios, 130 s) against a platform whose every operation but `set_channel` is a tripwire, and asserts that `set_channel` is the only one called and only on the three monitor interfaces; seen red with a deliberate `g_platform.wifi_scan()` (the nl80211 scan trigger behind `--allow-active`) added to the cue step.

## 8. Output

- the `cue` record ([[jsonl-schema]]): `ty`, `kind`, `state` (`started`, `ended`, `refused`), `channel`, `freq_mhz`, `band`, `duration_s`, `radio` or `reason`, `incident_id`. No address: the alert carries those. A burst of identical refusals is one line a minute.
- `sensor_health`: `cue_active`, `cue_started`, `cue_refused`, `cue_refused_limit`, `cue_cued_ms`, whenever `--cue` is on (zeros while no monitor interface runs the scheduler: `cue_live_publish()` runs before `chanhop_drive()`'s guard), absent otherwise; the signature takes the active count and decades of the two tallies. `cue_cued_ms` is lifetime: a re-deal of the shares resets radio 0's scheduler but `deal()` carries its cued totals over.
- Not in sloth.db, the report or a TUI view in this slice.

## 9. Tests

`tests/test_chancue.c`: the six kinds; the 4x dwell for 120 s and back, by the scheduler's accounting; a cue on the current channel; the clamp; every channel cued at once (two admitted, nine refused, cues ≤ 50 % of the measured time, every other channel ≥ 1/22 of it); the issue's ten false triggers; the active and rate caps; the refusals that are no limit; several radios, and a share re-dealt; the finding's channel; the issue's acceptance (a twin under `--hop --cue` gives channel 6 about 34 s of 120 against 11 s without); the records and fields; off by default; receive-only; from the #248 review, an incident offered once while 200 others pass through, 41 records of one poll all written, `cue_cued_ms` monotonic across a re-deal, the `cue_*` members with no monitor interface, and `share_small` on 4/4/3 shares counted as no limit. `tests/test_observe.c` (`--strict --cue`, `--cue` without `--hop`), `tests/test_sensor_suppressed.c` (`suppressed:cue` from the real policy, and its absences), `tests/test_docs_consistency.c :: test_usage_cue_names_kinds_and_limits`. Each absence assertion was seen red under a named mutation.

## Related pages

- [[monitor-mode]] — `--hop`, the scheduler a cue steers
- [[multi-radio-sensing]] — which radio serves a cue
- [[coverage-assessment]] — § 7, `SENSOR_SUPPRESSED` and `suppressed:cue`
- [[cli-reference]] — `--cue`, `suppress.cue_refused_per_min`
- [[jsonl-schema]] — the `cue` record
- [[alerts]] — the six kinds
