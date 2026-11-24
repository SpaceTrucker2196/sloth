---
name: coverage-assessment
description: Which alert rules can fire in the sensor's present configuration. The per-rule input declaration, the three statuses (observable, partly, blind), the reason words, and what is built and what is not
type: reference
---

# Coverage assessment: which rules can fire

**Summary**: a quiet site and a blind sensor give the same empty alert list. Each alert kind now declares what it reads (`include/sloth_alert_inputs.def`), and `cov_rule_status()` (`src/rule_coverage.c`) derives from that and from what the sensor has one of three statuses: `observable`, `partly`, `blind`, with one reason word. This page is the reference for the declaration and the derivation. It is receive-only: nothing here transmits or retunes a radio.

**Status**: slices 1 and 2 of #242 and item 2, 2026-11-23. Built: the declaration for all <!-- count:rules -->101<!-- /count --> kinds, the derivation, and the output in the stream: both daemons derive the status each tick and write `rule_status` and `coverage` records and three counts on `sensor_health` (JSONL 2.8.0, § 4); and the per-interval coverage record, sloth-wifi's `coverage_interval` once a minute and a `coverage_intervals` row in sloth.db (JSONL 2.9.0, schema v18, § 6). Item 4, `SENSOR_SUPPRESSED`, sloth-wifi's own-state alert for a sensor losing evidence while its sources read up, and the reason `suppressed` it puts on the rules it costs (§ 7). Item 3's remaining parts: a "Collection coverage" section in `--report` and `--report-json`, and a "Collection gaps" section in the Stats view (`6`), § 8. **Not built**: sloth-rf has no report path and no view, so neither carries its assessment; its status is on its stream only (§ 4). sloth-mesh does not read the new records yet, and schema v18 needs a sloth-mesh change first: its slothweb accepts sloth.db up to v17 and refuses a v18 file whole, so `WEB_SDB_SCHEMA_MAX` 18 and a contract re-pin there must be installed before this sloth is ([[sqlite-schema]], v18).

**Sources**: `include/sloth_alert_inputs.def`; `src/rule_coverage.h`, `src/rule_coverage.c`; `src/rule_coverage_live.c`, `src/rule_coverage_capture.c`; `src/posture_coverage.c`, `src/views/stats.c`; `src/cov_interval.h`, `src/cov_interval.c`, `src/cov_interval_capture.c`, `src/wifi_chanhop.c` (`chanhop_slot_time_ms`), `src/capture/probe.c` (`mon_frame_class_totals`); `tests/test_rule_coverage.c`, `tests/test_rule_coverage_live.c`, `tests/test_cov_interval.c`; [[jsonl-schema]]; issue #242 (parent #241); US Army FM 2-0 (2004) 4-48, 4-51, 8-34; [[collection-cycle]].

**Last updated**: 2026-11-23 (item 3: § 8, the report section and the Stats view's collection gaps; § 5 quotes the two limits they print), 2026-11-23 (item 4 review: § 7 says the silent-channel default has no measured baseline, and what an operator's clear keeps; the kind counts follow the build), 2026-11-23 (item 4: § 7, `SENSOR_SUPPRESSED` and the reason `suppressed`), 2026-11-23 (item 2 review: the v18 deploy order; overflowed channel time stays in the band totals; the sampler's clock), 2026-11-23 (item 2: § 6, the per-interval coverage record), 2026-11-23

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
| `partly` | `suppressed` | a `SENSOR_SUPPRESSED` incident is open on the rule's input, or on a frame class of its evidence (§ 7) |
| `partly` | `fixed_channel` | an 802.11 rule, and the radios are not retuned |
| `partly` | `hop` | an 802.11 rule whose shape is not `state`, with more channels than radios |
| `observable` | (none) | none of the above |

When several apply, the first row in this table is the one reported, so the reason names the first thing to fix. The reason words are appended only (they are on the stream), so `suppressed` is last in `cov_reason_t` and ranked in this table where it is: a loss the sensor measured now says more than what follows from its channel plan.

Two cases from the tests:

- No monitor radio: all 58 `dot11` kinds read `blind`, `no_source`. No other kind changes.
- One radio on the default `--hop` list (1, 6, 11, 36-48, 149-161): `HANDSHAKE_HARVEST` reads `partly`, `hop`; `EVIL_TWIN` reads `observable`; `DFS_MASKING` reads `blind`, `band`, because that list has no DFS channel.

## 4. What a running daemon writes

Each tick, after the source rows ([[jsonl-schema]] `source_status`) are derived, the daemon builds the environment and the status of each kind **it** raises: <!-- count:rules-wifi -->96<!-- /count --> in sloth-wifi, <!-- count:rules-rf -->6<!-- /count --> in sloth-rf.

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

One hopping radio on the default list with no IP capture, no BLE and nothing designated gives 24 observable, 37 partly and 35 blind of sloth-wifi's <!-- count:rules-wifi -->96<!-- /count --> (`tests/test_rule_coverage_live.c`; the 24th is `SENSOR_SUPPRESSED`, which needs nothing more).

**A `--replay` run is not assessed.** It reads files: its source rows read `down` because no device is open, while every frame of the file reaches the rules. No status is kept and none of the three outputs is written.

## 5. Limits

The report's "Collection coverage" section and the Stats view's "Collection gaps" print the first two of these as two sentences (`cov_limits[]`, `src/rule_coverage_live.c`; `tests/test_posture.c` holds them to this page):

> Observable means: on the channels the radios visit. A transmitter on a channel in no radio's plan is not heard, and the status does not say so.
>
> The status is about the sensor, not the site. Observable with no finding is "looked and found nothing", not "nothing is there".

- **`observable` means: on the channels the radios visit.** A transmitter on a channel in no radio's plan is not heard, and the status does not say so. Only the band is checked. The channel list and the time on each are in the coverage record (§ 6).
- **The status is about the sensor, not the site.** `observable` with no finding is "looked and found nothing". It is not "nothing is there".
- **The declaration is written by hand** from the rule functions. A test holds its form, its order and the number of kinds on each input; it cannot prove that a row matches its rule. A change to a rule's inputs changes its row in the same commit.
- **`source_stale` follows the source row**: 60 s with nothing received. On a quiet BLE or GNSS source that can be the site and not a fault; the word says only that nothing arrived.
- **Frame classes are used only for `suppressed`.** Otherwise the derivation reads the input, the band, the shape and the needs. The coverage record (§ 6) counts the frames of each class a minute; a status that reads "no frame of this class was received" is not built.
- `fixed_channel` is reported for every 802.11 rule when the radios do not hop, also on a site whose own access points are all on that channel.

## 6. The per-interval coverage record

The status says which rules can fire. The record says what the sensor did in the last minute, so that "nothing fired" can be read against "this is what was looked at": the time each monitor radio spent on each channel and the frames it heard there, the share of radio time in each band, the frames received by class, the capture drops, and the sources up or down at the end. sloth-wifi writes it; sloth-rf has no radio and writes none. Field reference: [[jsonl-schema]] (`coverage_interval`); the table: [[sqlite-schema]] (`coverage_intervals`).

**Cadence.** One record per 60 s interval (`COV_IV_MS`), on the monotonic clock from the first poll. A measurement, not a change feed: it is written whatever it holds, and has no signature, because a minute with the same figures as the last is still a minute that was watched. It is not a tunable: a share or a count is compared across sensors and across time, and that needs one length. A partial interval at shutdown is not written.

**Time on a channel.** Under `--hop` it is the hop scheduler's own dwell accounting: each slot keeps the measured length of its closed dwells (start of dwell to start of the next, so the poll loop's servicing delay is inside it, as in `hop_dwell_measured_ms`), and the open dwell is added at the sample. A refused retune leaves the time with the channel the radio stayed on. The interval's figure is the difference of two such readings; after a re-deal (a radio lost) the scheduler starts again and the slot is read from zero. The sampler reads the clock when it runs, after the hop stage, not at the tick's start: the hop stage stamps a retune on its own later reading, and a slot read at an earlier instant would credit a dwell closed in the interval's last tick past the interval's end. A radio that is not retuned has the whole time it ran on the frequency of its newest frame, `unknown` before one. A minute with more than 32 (radio, channel) pairs (a re-deal) lists 32 and counts the rest in `chan_overflow`; their time stays in the band totals and `radio_ms`, so the shares describe the whole minute. Radio 0 counts while its worker runs, a further radio while its reader is alive; a radio that is down is not radio time. On Beta-Site on 2026-11-23 (one radio, 11 channels) the mean planned dwell was 861 ms and the measured one 998 ms, so one record holds about 60 dwells, five or six per channel.

**Frames by class.** The classes are the `COV_F_*` of § 2 (beacon and probe response, probe request, authentication, (re)association, deauthentication and disassociation, action, control, data, EAPOL), then `other` and `fcs_bad`. The monitor path counts them where it records every frame (`mon_frame_record()` in `src/capture/probe.c`), after the cross-radio de-duplication, under the lock that tally already takes, so the count costs an increment and no lock of its own, and the classes sum to the frames received. A frame radiotap marked FCS-failed is `fcs_bad`, not the type its damaged octets state. EAPOL is a data frame whose LLC/SNAP EtherType is 0x888E (the EAPOL EtherType of IEEE 802.1X); a Protected data frame is `data`, its body being ciphertext that sloth does not read. A capture interface that is itself in monitor mode is decoded for IP only, and its frames are not in these counts.

**Drops.** The interval's difference of the capture handle's and radio 0's `pcap_stats()` totals. A handle not open with a sample at both ends is not measured, and the member is absent. The further `--monitor-iface` radios take no `pcap_stats()` sample, so their drops are not measured.

**A `--replay` run writes no record.** The file's frames arrive as fast as it reads, so a minute of host time holds an arbitrary slice of the file, and there is no radio to dwell. `tests/replay/golden.jsonl` is therefore unchanged by this record.

**Kept** on the observation tier of [[retention]]: a row qualifies a minute of observations and expires with them (30 days by default), and the size ceiling may take it.

## 7. SENSOR_SUPPRESSED

#242 item 4. `SENSOR_SOURCE_DOWN` says a source stopped. This says a source is delivering and the sensor is still losing what it delivers (`rule_sensor_suppressed()`, `src/alerts/rules_sensor.c`; sloth-wifi's rule table only). An own-state kind, the first exemption form of "Detectors cite their sources": no technique, no adversary claimed. Three signals, each judged over one minute (`COV_IV_MS`), each its own incident at WARN:

| Signal | Key | Over the minute | Default |
|---|---|---|---|
| table evictions | `suppressed:evict` | one synthesis table's `sh_evict_count()` rose by at least `suppress.evict_per_min`. The six flow rings and `evidence_frame` are not judged (they roll over on a working sensor by design), nor `alert`, `pcap_cooldown` or `rtl433` | 600 |
| capture drops | `suppressed:drop` | a handle (the monitor radio's or `--iface`'s) dropped `ps_drop + ps_ifdrop` of at least `suppress.drop_pct` percent of its `ps_recv`, and at least `suppress.drop_min` frames | 1 %, 100 |
| a silent channel | `suppressed:silent` | from the `coverage_interval` records (§ 6): a channel visited with no frame for `suppress.silent_intervals` intervals in a row, while another visited channel of its band heard frames in each, after it heard frames earlier in the run. Always empty, the whole band quiet, or not visited: not this signal | 3 |

**Thresholds.** No source gives any of them. Each is set well above what the reference sensor (Beta-Site) does, measured on its live stream for 115 s on 2026-11-23 (`sensor_health`, differenced): the busiest synthesis table, `frag_sta`, evicted 0.70 a second (42 a minute; `ble_device` 0.14, `ble_flood` 0.03, every other table 0); `evidence_frame` 143 a second, which is why it is not judged; neither handle had dropped a frame in its lifetime (capture 3.08 M received, monitor 439 k). **The silent-channel run of 3 has no measured baseline.** The one figure the look had, the hopper's `hop_silent_channels` 0, counts channels visited and never heard in the whole run, which is the population this signal leaves out; it says nothing about a channel heard once going quiet for three minutes while its band is heard. The look was also shorter than two intervals, and the reference sensor runs a build without the `coverage_interval` record. One frame at any time in the run makes a channel eligible, so a sparse channel (one scanning phone's probe early on, then nobody) beside a busy one in its band can raise it on a quiet site; how often that happens is unknown until hours of `coverage_interval` records from a deployed build are read. The baseline is written beside the defaults in `src/alerts.h`; each is a `--tune` knob ([[cli-reference]]).

**Lifecycle.** A signal opens at the end of the first minute over its threshold, is re-asserted every tick until a minute ends under it, and closes with the reason `recovered` once it has been under for 120 s without a break (`SENSOR_RECOVER_S`, the hold `SENSOR_SOURCE_DOWN` uses). The detail names the worst table, the handle or the channel, and the threshold passed, never the minute's own count. Nothing is judged on a `--replay`.

**What it does to the statuses.** While an incident is open, the capture side's filler copies what it suppresses into `cov_env_t` (`suppressed`, a bit per input; `suppressed_frames`, `COV_F_*`), and every kind it reaches reads `partly`, `suppressed`; `cov_rule_status()` stays a pure function of the environment. What each signal reaches:

- **evictions**: the evicting table's evidence, mapped per table in `evict_scope()`: the probe tables (`probe_client`, `pnl_*`) probe requests, `probe_latency` probe requests and beacons, `beacon_ap` beacons, the association tables association frames, the EAP, EAPOL, WPS and RADIUS-posture tables EAPOL, the deauth tables deauthentications, the FragAttacks, PM and queue tables data frames; `seqnum_client` and `rf_channel` every 802.11 kind; `device` the 802.11 and IP kinds; the wired tables every IP kind; the BLE tables every BLE advertising kind;
- **drops**: every kind on the handle's input (802.11 for the monitor radio, and for `--iface` when it is itself in monitor mode; IP otherwise);
- **a silent channel**: every 802.11 kind.

The status follows the incident one tick late: the health stage that derives it runs before the rules.

**An operator's clear.** `alerts_clear()` (the `c` key in the Alerts view) ends the incidents (`cleared`) and restarts the windows and each channel's run, and keeps which channels this run has heard: that is what the radio observed, not alert history. A channel still silent opens a new incident after `suppress.silent_intervals` more intervals; were the heard set dropped, a channel jammed before the clear could not raise the signal again in that run.

Tests: `tests/test_sensor_suppressed.c` (a thousand hand-built probe requests through the monitor callback fill the probe-client, probe-latency and sequence-number tables and raise it; recovery; drops; a silent channel; the absences, each seen red under a mutation), `tests/test_rule_coverage.c :: test_suppressed`, `tests/test_rule_coverage_live.c :: test_suppressed_reaches_the_statuses`.

**Not covered.** The further `--monitor-iface` radios' drops (they take no `pcap_stats()` sample, § 6). An eviction tally that does not exist: a table with no `evict_*` field loses rows unmeasured (`src/sensor_health.h` lists them).

## 8. In the report and the Stats view

#242 item 3. The status is on the stream (§ 4); an operator reading a report or a terminal needs it beside the alerts, since an empty alert list means nothing without it.

**`--report` / `--report-json`**: a "Collection coverage" section after the alert summary, and a `coverage` object, the JSON report's last member ([[posture-report]] has the fields). In order:

- the three counts of this daemon's rules;
- every kind that is `blind` or `partly`, grouped by status and reason, the blind groups first and each in the precedence of § 3 (the first thing to fix first), each kind with its input;
- the radio figures the 802.11 statuses were derived from: radios, channels, hopping, bands;
- the newest closed `coverage_interval` (§ 6), when one has closed: radio time by band and its share, frames by class, the drops of each handle that was measured ("not measured", absent in the JSON, otherwise);
- each open `SENSOR_SUPPRESSED` incident, its key and detail (§ 7); a resolved one is not listed;
- the two limits of § 5, verbatim.

**Not assessed.** Before the first status sample, and on a `--replay` run (§ 4), there is no status: the section says `Not assessed:` and why (the JSON `"assessed": false` and `why`), and prints no count. Zero blind rules would read as full coverage. The limits are printed in both cases.

**The Stats view** (`6`, [`stats.md`](../views/stats.md)): a "Collection gaps" section under the interface totals, the place in the TUI where the session's own figures are. One line with the counts and the radio figures; one line for each reason, its kinds grouped by input (`blind no_source (30)  ip: … ble_adv: …`), broken between words at the terminal's width and indented under the reason, so the list flexes with the screen and no kind name is split; open `SENSOR_SUPPRESSED` incidents by key; the two limits. "not assessed: <why>" and no count when there is no status. The Interfaces view's health strip was the other candidate: it is one fault-only line under a paged table, and a list of up to 90 kinds is not a fault token.

Both read what the daemon already holds (`cov_live_gaps()`, `cov_live_state()`, `cov_iv_get()`, the alert snapshot): no new observation, and the same grouping in both. Tests: `tests/test_posture.c` (not assessed before a sample and on a replay; a hopping radio with a closed interval and an open and a resolved incident; the limits held to § 5), `tests/test_stats.c` (the same states drawn, and the wrap at 100 columns); every absence assertion seen red under a mutation.

**sloth-rf** has neither: it takes no `--report` (it ignores `SIGUSR1`, which writes sloth-wifi's live report) and is headless.

## Related pages

- [[collection-cycle]] — where the assessment sits in the cycle (the minute step)
- [[alerts]] — the rules
- [[monitor-mode]] and [[multi-radio-sensing]] — the radios and the hop list
- [[contract]] — why the declaration is a sibling file
- [[posture-report]] — the report the section is in
