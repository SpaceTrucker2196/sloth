---
name: coverage-assessment
description: Which alert rules can fire in the sensor's present configuration. The per-rule input declaration, the three statuses (observable, partly, blind), the reason words, and what is built and what is not
type: reference
---

# Coverage assessment: which rules can fire

**Summary**: a quiet site and a blind sensor give the same empty alert list. Each alert kind now declares what it reads (`include/sloth_alert_inputs.def`), and `cov_rule_status()` (`src/rule_coverage.c`) derives from that and from what the sensor has one of three statuses: `observable`, `partly`, `blind`, with one reason word. This page is the reference for the declaration and the derivation. It is receive-only: nothing here transmits or retunes a radio.

**Status**: slices 1 and 2 of #242, 2026-11-23. Built: the declaration for all <!-- count:rules -->100<!-- /count --> kinds, the derivation, and the output in the stream: both daemons derive the status each tick and write `rule_status` and `coverage` records and three counts on `sensor_health` (JSONL 2.8.0, § 4). **Not built yet**: a `--report` section, a view, the per-interval coverage record (time on each channel, frames by type, capture drops) with its `sloth.db` table, and `SENSOR_SUPPRESSED`. sloth-mesh does not read the new records yet.

**Sources**: `include/sloth_alert_inputs.def`; `src/rule_coverage.h`, `src/rule_coverage.c`; `src/rule_coverage_live.c`, `src/rule_coverage_capture.c`; `tests/test_rule_coverage.c`, `tests/test_rule_coverage_live.c`; [[jsonl-schema]]; issue #242 (parent #241); US Army FM 2-0 (2004) 4-48, 4-51, 8-34; [[collection-cycle]].

**Last updated**: 2026-11-23

---

## 1. Why

FM 2-0 4-51 asks of each requirement whether it "has been answered, will be answered with the current" collection, or what must change. 4-48 adds that assessment must "identify enemy efforts at deception and denial". sloth reported some gaps before this (`NO_MONITOR_MODE`, `SENSOR_SOURCE_DOWN`, the `sensor_health` counters), and none of them said which rules a gap silences.

## 2. The declaration

One row for each kind, in the order of `include/sloth_alerts.def`. It is a sibling file and not a new column there, because `sloth_alerts.def` is in the [[contract]] and sloth-mesh includes it with a two-argument `X`.

| Column | Content |
|---|---|
| `INPUT` | the one input the rule reads its evidence from (table below) |
| `FRAMES` | for an 802.11 rule, the frame classes: `beacon` (beacons and probe responses), `probe` (probe requests), `auth`, `assoc`, `deauth`, `action`, `ctrl`, `data`, `eapol` |
| `BANDS` | for an 802.11 rule about one band, that band: `2.4`, `5`, `5dfs` (channels 52-64 and 100-144), `6`. Most rules read every band |
| `SHAPE` | for an 802.11 rule, what the evidence looks like in time (table below) |
| `NEEDS` | operator configuration the rule is silent without: `own_net` (`--my-ssid` / `--my-bssid`), `roster` (`--known-mac` / `--known-macs`), `db` (`--db`) |

| Input | What it is | Kinds |
|---|---|---|
| `dot11` | 802.11 frames from a radio in monitor mode | 58 |
| `ip` | packets of the IP capture (`--iface`) | 26 |
| `host` | the host's own kernel tables: sockets, the neighbour table, the interface list | 5 |
| `ble_adv` | BLE advertising, from `--bt-monitor` or `--bt-capture` | 3 |
| `ble_hci` | the host controller's own commands, `--bt-monitor` only | 1 |
| `gnss` | the `--gps` receiver | 4 |
| `adsb` | the `--adsb` decoder | 1 |
| `sys` | sloth's own status sampler | 2 |

The `host` row is the one that surprises: `PORT_SCAN`, `THREAT_IP`, `BEACONING` and `ARP_SPOOF` read the host's socket and neighbour tables, not the capture, so they see what reaches this host and nothing else on the segment.

| Shape | Meaning | Under a hopping radio |
|---|---|---|
| `state` | repeated or standing content, such as a beacon | one visit to the channel reads it |
| `rate` | a count inside a time window | time off the channel lowers the count |
| `event` | one frame, sent once | missed when the radio is elsewhere |
| `exchange` | an ordered exchange of several frames | broken when the radio leaves in the middle |

A corroborating input that a rule can use and does not need (the wired check of `EVIL_TWIN`) is not declared.

## 3. The status

`cov_rule_status(kind, env, &why)` is a pure function. The caller fills `env`: the state of each input (not configured, down, stale, up), the bands and the number of channels the radios cover, the number of radios, whether they hop, and the configuration present.

| Status | Reason | When |
|---|---|---|
| `blind` | `no_source` | the rule's input is not configured |
| `blind` | `source_down` | configured, not delivering |
| `blind` | `no_own_net` | the rule needs a designated network and none is given |
| `blind` | `no_roster` | the rule needs the roster and none is given |
| `blind` | `no_db` | the rule reads history and there is no database |
| `blind` | `band` | an 802.11 rule about a band that no radio is in |
| `partly` | `source_stale` | the input is up and has delivered nothing lately |
| `partly` | `fixed_channel` | an 802.11 rule, and the radios are not retuned |
| `partly` | `hop` | an 802.11 rule whose shape is not `state`, with more channels than radios |
| `observable` | (none) | none of the above |

When several apply, the first row in this table is the one reported, so the reason names the first thing to fix.

Two cases from the tests:

- No monitor radio: all 58 `dot11` kinds read `blind`, `no_source`. No other kind changes.
- One radio on the default `--hop` list (1, 6, 11, 36-48, 149-161): `HANDSHAKE_HARVEST` reads `partly`, `hop`; `EVIL_TWIN` reads `observable`; `DFS_MASKING` reads `blind`, `band`, because that list has no DFS channel.

## 4. What a running daemon writes

Each tick, after the source rows ([[jsonl-schema]] `source_status`) are derived, the daemon builds the environment and the status of each kind **it** raises: 95 in sloth-wifi, 6 in sloth-rf.

| Part of the environment | Where it comes from |
|---|---|
| each input: not configured, down, stale, up | the daemon's own `source_status` rows. The capture interface counts as `dot11` when it is itself in monitor mode, as `ip` otherwise. `btmon` gives both BLE inputs, `btcap` advertising only. Of two sources of one input, the better one counts |
| `host` | up in sloth-wifi for as long as it runs |
| radios, channels, hopping | the radio table and the hop scheduler's published list ([[multi-radio-sensing]]). A radio that is not retuned counts one channel |
| bands | under `--hop`, the bands of the hop list. Without `--hop`, the band of the newest frame of each radio in the radio table; unknown for a single radio, and then no rule is called blind for a band |
| configuration | a designated SSID or BSSID, a roster entry, an open database |

Output ([[jsonl-schema]] has the fields):

- `rule_status`, one record for each kind, when its status or reason changes, on the 300 s heartbeat, and for every kind once after a sink opens.
- `coverage`, one summary record: the three counts and the radio figures.
- `rules_observable`, `rules_partly`, `rules_blind` on `sensor_health`.

One hopping radio on the default list with no IP capture, no BLE and nothing designated gives 23 observable, 37 partly and 35 blind of sloth-wifi's 95.

**A `--replay` run is not assessed.** It reads files: its source rows read `down` because no device is open, while every frame of the file reaches the rules. No status is kept and none of the three outputs is written.

## 5. Limits

- **`observable` means: on the channels the radios visit.** A transmitter on a channel in no radio's plan is not heard, and the status does not say so. Only the band is checked. The channel list and the time on each belong to the coverage record, which is not built.
- **The status is about the sensor, not the site.** `observable` with no finding is "looked and found nothing". It is not "nothing is there".
- **The declaration is written by hand** from the rule functions. A test holds its form, its order and the number of kinds on each input; it cannot prove that a row matches its rule. A change to a rule's inputs changes its row in the same commit.
- **`source_stale` follows the source row**: 60 s with nothing received. On a quiet BLE or GNSS source that can be the site and not a fault; the word says only that nothing arrived.
- **Frame classes are declared and not yet used.** The derivation reads the input, the band, the shape and the needs. `FRAMES` is for the coverage record ("no frame of this class was received").
- `fixed_channel` is reported for every 802.11 rule when the radios do not hop, also on a site whose own access points are all on that channel.

## Related pages

- [[collection-cycle]] — where the assessment sits in the cycle (the minute step)
- [[alerts]] — the rules
- [[monitor-mode]] and [[multi-radio-sensing]] — the radios and the hop list
- [[contract]] — why the declaration is a sibling file
