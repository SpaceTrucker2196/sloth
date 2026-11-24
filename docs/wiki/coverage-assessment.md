---
name: coverage-assessment
description: Which alert rules can fire in the sensor's present configuration. The per-rule input declaration, the three statuses (observable, partly, blind), the reason words, and what is built and what is not
type: reference
---

# Coverage assessment: which rules can fire

**Summary**: a quiet site and a blind sensor give the same empty alert list. Each alert kind now declares what it reads (`include/sloth_alert_inputs.def`), and `cov_rule_status()` (`src/rule_coverage.c`) derives from that and from what the sensor has one of three statuses: `observable`, `partly`, `blind`, with one reason word. This page is the reference for the declaration and the derivation. It is receive-only: nothing here transmits or retunes a radio.

**Status**: slices 1 and 2 of #242 and item 2, 2026-11-23; #246's quality fields on each finding (§ 9: `complete`, `latency_ms`, `corroboration`, `src_state`; JSONL 2.10.0, schema v19). Built: the declaration for all <!-- count:rules -->101<!-- /count --> kinds, the derivation, and the output in the stream: both daemons derive the status each tick and write `rule_status` and `coverage` records and three counts on `sensor_health` (JSONL 2.8.0, § 4); and the per-interval coverage record, sloth-wifi's `coverage_interval` once a minute and a `coverage_intervals` row in sloth.db (JSONL 2.9.0, schema v18, § 6). Item 4, `SENSOR_SUPPRESSED`, sloth-wifi's own-state alert for a sensor losing evidence while its sources read up, and the reason `suppressed` it puts on the rules it costs (§ 7). Item 3's remaining parts: a "Collection coverage" section in `--report` and `--report-json`, and a "Collection gaps" section in the Stats view (`6`), § 8. Before a run, `sloth --preflight` (#247) prints the statuses the command line would have, an expectation from `cov_rule_status()` over the environment it implies ([[preflight]] § 4). **Not built**: sloth-rf has no report path and no view, so neither carries its assessment; its status is on its stream only (§ 4). sloth-mesh does not read the new records yet, and schemas v18 and v19 need a sloth-mesh change first: its slothweb accepts sloth.db up to v17 and refuses a newer file whole, so `WEB_SDB_SCHEMA_MAX` 19 and a contract re-pin there must be installed before this sloth is ([[sqlite-schema]], v18, v19).

**Sources**: `include/sloth_alert_inputs.def`; `src/rule_coverage.h`, `src/rule_coverage.c`; `src/rule_coverage_live.c`, `src/rule_coverage_capture.c`; `src/posture_coverage.c`, `src/views/stats.c`; `src/cov_interval.h`, `src/cov_interval.c`, `src/cov_interval_capture.c`, `src/wifi_chanhop.c` (`chanhop_slot_time_ms`), `src/capture/probe.c` (`mon_frame_class_totals`); `tests/test_rule_coverage.c`, `tests/test_rule_coverage_live.c`, `tests/test_cov_interval.c`; `src/alert_quality.h`, `src/alert_quality.c`, `src/alert_quality_capture.c`, `src/cov_timeline.c`, `tests/test_alert_quality.c` (§ 9); issue #246; US Army FM 2-0 (2004) 1-28, chapter 5, 8-28; [[jsonl-schema]]; issue #242 (parent #241); US Army FM 2-0 (2004) 4-48, 4-51, 8-34; [[collection-cycle]].

**Last updated**: 2026-11-23 (#246 review: § 9, a cited frame gone from the evidence ring is not judged `full`, a `full` incident keeps it when the rule goes blind, no `corroboration` in a `--replay`, the sloth-mesh consumers named), 2026-11-23 (#246: § 9, the quality fields on each finding), 2026-11-23 (#247: `--preflight` prints the expected statuses, [[preflight]] § 4), 2026-11-23 (item 3 review: § 8, the Stats view's short form on a short screen, and the groups hold every blind and partly kind), 2026-11-23 (item 3: § 8, the report section and the Stats view's collection gaps; § 5 quotes the two limits they print), 2026-11-23 (item 4 review: § 7 says the silent-channel default has no measured baseline, and what an operator's clear keeps; the kind counts follow the build), 2026-11-23 (item 4: § 7, `SENSOR_SUPPRESSED` and the reason `suppressed`), 2026-11-23 (item 2 review: the v18 deploy order; overflowed channel time stays in the band totals; the sampler's clock), 2026-11-23 (item 2: § 6, the per-interval coverage record), 2026-11-23

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

When several apply, the first row in this table is the one reported, so the reason names the first thing to fix. The reason words are appended only (they are on the stream), so `suppressed` is last in `cov_reason_t` and ranked in this table where it is: a loss the sensor measured now says more than what follows from its channel plan. `drops`, appended after it for #246, is no rule's status: only a finding's `complete_why` carries it (§ 9).

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

**The Stats view** (`6`, [`stats.md`](../views/stats.md)): a "Collection gaps" section under the interface totals, the place in the TUI where the session's own figures are. One line with the counts and the radio figures; one line for each reason, its kinds grouped by input (`blind no_source (30)  ip: … ble_adv: …`), broken between words at the terminal's width and indented under the reason, so the list flexes with the screen and no kind name is split; open `SENSOR_SUPPRESSED` incidents by key; the two limits. "not assessed: <why>" and no count when there is no status. The view does not scroll, so when the whole list would push the traffic sections under it below the last row (at the 100x33 minimum on a hopping sensor), each reason is one count on one line, `(kinds and limits: --report)`, with the open incidents still listed. The groups hold every blind and partly kind: a reason appended to `cov_reason_t` fails the build until it has its place in the order, and a pairing the order does not name is listed after it rather than left out; "every rule is observable" is printed from the counts, not from the groups. The Interfaces view's health strip was the other candidate: it is one fault-only line under a paged table, and a list of up to 90 kinds is not a fault token.

Both read what the daemon already holds (`cov_live_gaps()`, `cov_live_state()`, `cov_iv_get()`, the alert snapshot): no new observation, and the same grouping in both. Tests: `tests/test_rule_coverage_live.c` (the groups hold every partly and blind kind once, across six environments), `tests/test_posture.c` (not assessed before a sample and on a replay; a hopping radio with a closed interval and an open and a resolved incident; the limits held to § 5), `tests/test_stats.c` (the same states drawn, the wrap at 100 columns, and the short form at 100x33 with every traffic section on the screen); every absence assertion seen red under a mutation.

**sloth-rf** has neither: it takes no `--report` (it ignores `SIGUSR1`, which writes sloth-wifi's live report) and is headless.

## 9. Quality fields on each finding

#246 (from #241 item 5). The status says which rules *can* fire; it says nothing about a finding that did. FM 2-0 asks of a product whether it is complete and timely and whether another source confirms it (the production step, page 1-28; chapter 5), and notes that a SIGINT product depends on the collection system's position relative to the emitter (8-28). Every finding now carries four answers, stamped in `fire_inv()` (`src/alerts/engine.c`) before its first record goes out and refreshed on each evaluation: `complete` with `complete_why`, `latency_ms`, `corroboration` and `src_state` (`src/alert_quality.h`). They are **evidence about the observation, never an input**: no rule reads them, and none of them moves when a rule fires, its severity, key, title or detail. Each is omitted while it is not known; none is ever `0` or `""` for unknown.

**`complete`** is `full`, or `partial` with one word, in this order of precedence:

| Word | When |
|------|------|
| `source_down` | the rule's input reads `down` (it fired on what it held from before) |
| `source_stale` | the input delivered nothing lately (§ 3) |
| `suppressed` | `SENSOR_SUPPRESSED` is open on its evidence (§ 7) |
| `drops` | the monitor handle's `pcap_stats()` drop total rose inside the window the cited frames span |
| `hop` | a hopping radio was away from a channel a cited frame is on for part of that window, by more than 100 ms; for a finding that cites no frame, its rule reads `partly`, `hop` (§ 3) |

The window is the span from the oldest to the newest frame the incident cites that the evidence ring still holds (at most 8, the newest the rule kept), so it is the evidence's own span, not the rule's whole window. `drops` is a word only a finding carries: it was appended to `cov_reason_t`, and `cov_rule_status()` never returns it, SENSOR_SUPPRESSED's drop signal being the rule-level form of the same loss. `fixed_channel` never makes a finding partial: a radio that is not retuned sat on the channel its evidence was heard on for the whole window. Not assessed (absent) where the assessment is not, a `--replay` or before the first status sample (§ 4), where it calls the rule blind for anything but a down source, which contradicts the fire, and where a frame the incident cites has left the evidence ring: the frames still held span a window that is not the incident's, so a drop or a hop gap in the rest cannot be ruled out, and a flood that turns the ring over (its evictions are not a `SENSOR_SUPPRESSED` signal, § 7) must not buy a `full`. Only the source words and the rule's own `partly`, `hop` still decide then. Once `partial`, an incident stays `partial` with its first word: the window it was judged on was this incident's. Once `full`, an evaluation that cannot judge (the rule now blind, the cited frames gone) leaves `full` standing, as sloth.db's upsert does, so the stream's last record and the row agree.

**How the hop state over a window is known.** Not from the coverage record: a minute holds about sixty dwells on the reference sensor (§ 6), and a window of a few beacons lies inside one dwell or straddles a hop. `src/cov_timeline.c` keeps the dwell history itself: one entry per confirmed retune (radio, frequency, the wall clock in ms), fed by `chanhop_service()` for radio 0 and `mon_hop_service()` for the others, which is every retune there is, and a radio dealt out of the list (lost) is marked gone so its last dwell does not run on. A dwell lasts until the same radio's next entry; the covered time of a channel is the union over the radios. 1024 entries (16 KB), bounded and allocated once: about 17 minutes at the reference sensor's ~1 s measured dwell with one radio, about 25 s at the scheduler's 100 ms floor on four radios. A window older than the history cannot be shown covered and reads `partial`, `hop`. The 100 ms slack is the scheduler's shortest dwell: a dwell is stamped when the retune is confirmed, after the driver call returns, so a frame on the new channel can carry a capture time a little before it, and a gap shorter than one dwell cannot hold a visit elsewhere. The wall clock, because frame capture times are the kernel's realtime clock. **Drops** are sampled the same way, one sample of radio 0's handle total a poll tick (128 samples), so a drop in the tick that holds the window's edge counts as inside it; the further radios' handles take no sample (§ 6), and their drops are not judged.

**`latency_ms`** is the oldest cited frame's capture time to the moment the incident opened, taken once. Only for a finding all of whose cited frames the ring still holds, in an assessed run: a replayed file's capture times are not this run's clock. A lower bound: the cited frames are the newest the rule kept.

**`corroboration`** is how many monitor radios ([[multi-radio-sensing]]) delivered a frame the incident cited, over its life; the evidence ring records the radio of each frame (`evidence_rec_t.radio`). A radio whose copy of a frame lost the cross-radio de-duplication did not deliver it and is not counted, so this is a lower bound on the radios that heard the evidence: two radios on one channel hearing one flood count 2 only when each delivered part of it. `1` on a one-radio sensor. Absent for a finding that cites no frame, and in a `--replay`: a replayed frame's radio is the replay's, not one of this sensor's, so no count was taken. Other kinds of source the issue names (the IP capture, BLE) and **a second site through the mesh are not counted**: the mesh is out of scope here.

**`src_state`** is the rule's input (§ 2) in this tick's environment: `ok`, `stale` or `down`, the `sensor_health` word. `intel_pack` stays as it was (#231).

**Where they are.** On `alert` and every `alert.*` record ([[jsonl-schema]], JSONL 2.10.0); in sloth.db's `alert_incidents` row of the incident, five nullable columns ([[sqlite-schema]], v19), whose upsert keeps a partial partial, the latency first written and the highest corroboration; in the TUI's alert detail (Enter in the Alerts view) as one `Quality:` line; in `--report` as a "Finding quality" section, one line per finding, and in `--report-json` as `findings` ([[posture-report]]). **A partial finding says so in its title line where a person reads it**, `EVIL_TWIN (partial: hop)`, in the alert detail and the report, and never in the alert's `title` field: that is the rule name ([[jsonl-schema]], `title`), the finding's identity in the stream, in sloth.db and in sloth-mesh's alert pages, and a title that changed with the observation would split one finding in two. sloth-rf's findings carry `complete` and `src_state` only: it has no evidence ring. **The sloth-mesh consumers that would show them** (none reads them yet, and nothing there breaks: the readers take named keys and named columns): the live alert ring and ticker, `web_live.c` (`alert_record()`), for the stream fields, and the alert page's incident rows, `web_slothdb.c` (`alert_incidents()`), for the v19 columns, once `WEB_SDB_SCHEMA_MAX` reaches 19.

**Not built.** `rx` (the signal level and the sensor's position source at the time), which #246 also lists: the cited frames' signal is in the evidence ring and the position in `loc`, and neither is summarised here. Corroboration by another kind of source or another site.

Tests: `tests/test_alert_quality.c` (the judge's precedence; the dwell and drop history; a twin whose window a hop plan misses part of reads `partial`, `hop`, and the same twin inside one dwell `full`; a flood two radios each delivered part of reads `corroboration` 2 through the real monitor callback, and one whose second copies lost the de-duplication 1; the source, drops and not-assessed cases; a `full` incident that goes blind stays `full`; cited frames gone from the ring are not `full`; the capture stage writing the drop totals; the hop stage writing each radio's dwells; the stream, the alert detail and the report), `tests/test_db.c` (the columns' upsert, and a v18 file migrated and refused); every absence assertion seen red under a mutation.

## Related pages

- [[preflight]] — the statuses a command line would have, before the run.
- [[collection-cycle]] — where the assessment sits in the cycle (the minute step)
- [[alerts]] — the rules
- [[monitor-mode]] and [[multi-radio-sensing]] — the radios and the hop list
- [[contract]] — why the declaration is a sibling file
- [[posture-report]] — the report the section is in
