---
type: BEACON_FLOOD
technique: T1498.001
rule_file: src/alerts/rules_wifi_mgmt.c:84 rule_beacon_flood()
count_semantics: per evaluation tick, one global key, while the condition stands. fire_ev() bumps count every poll (>= 4/s, POLL_MS 250 is the longest wait) in which at least beacon.flood_thresh BSSIDs were first-seen inside the trailing beacon.flood_window_s; one increment is one poll, NOT one beacon and NOT one new BSSID. The underlying measurement (beacon_recent_new_bssids) counts stamps in a 256-slot new-BSSID ring, so the detail's "N new BSSIDs" is a per-first-sighting count and the alert's count is per tick; a burst that stops ages out of the window about window_s later and the key resolves 300 s after the last tick that met it
severity_assessment: agree - WARN with no ownership split is right: a fabricated network is nobody's --my-bssid, the harm is scan-list pollution and airtime, and the rule names its tool shape (mdk) rather than claiming an intent it cannot see
false_positive_risk: medium - the signal is "first-seen BSSID rate", and three things besides an attacker produce first sightings in bulk: a sensor start in a dense area (every real AP is new to an empty table), the 256-row beacon table evicting and re-admitting APs in an environment with more than 256 BSSIDs, and a --hop sweep arriving on a crowded band; none is filtered, so a tripped rule needs the cited beacons read before it is called a flood
noise_verdict: low, bursty on the reference host - 1 key, 814 fires, max_sev WARN, 17 reopens over 2026-10-14..11-03. The key is the constant "beacon_flood", so 17 reopens plus the first incident is 18 incidents; 814 / 18 is about 45 evaluations each, which at >= 4/s is at most about 11 s of standing condition per incident - the length of the 10 s window after a single burst, not a sustained flood. Eighteen short bursts in twenty days on a hopping sensor is consistent with eighteen process starts or hop sweeps into a dense band as much as with eighteen mdk4 runs; the alert.create timestamps against the JSONL session starts decide it. No throttling needed; the single key already collapses it to one incident at a time
prevalence: common as tooling, uncommon as a live attack - beacon flooding is a one-flag mode in mdk4 ("b") [3], a documented side effect of airbase-ng with an ESSID list [4] and a headline feature of sub-$10 ESP8266 firmware ("create dozens of networks and confuse WiFi scanners") [5]; no fetched source quantifies a field rate, so none is claimed
tuning: [beacon.flood_thresh (TUNE_BEACON_FLOOD_THRESH, default 40, 2..256), beacon.flood_window_s (TUNE_BEACON_FLOOD_WINDOW_S, default 10, 1..3600), --hop (changes how fast first sightings arrive; no threshold scales with it), --collect-handshakes + --eapol-dir + pcap.min_severity (WARN is below the default CRIT floor, so no evidence pcap is written unless the floor is lowered)]
researched: 2026-11-03
---
## What the rule checks

`rule_beacon_flood()` (src/alerts/rules_wifi_mgmt.c:84-105) asks how
many BSSIDs were first seen inside the trailing window and fires when
that number reaches the threshold.

- **Input.** `beacon_recent_new_bssids(now, win)`
  (src/beacon_snoop.c:102-109) counts the stamps in `g_new_bssid_ts[]`
  that are non-zero and no older than `win`. A stamp is written by
  `note_new_bssid()` (src/beacon_snoop.c:37-41) from exactly one place:
  the new-entry path of `beacon_record()` (src/beacon_snoop.c:1281-1294),
  which runs when a beacon's BSSID is not already in the 256-row
  `g_aps[]` table (`MAX_BEACON_APS`, include/sloth.h:1326). A beacon from
  a known BSSID updates its row and writes no stamp. The ring is
  `BEACON_NEW_TS_RING` = 256 slots (src/beacon_snoop.c:29), so `n` can
  never exceed 256 and a long tuned window looks back only as far as the
  last 256 first sightings.
- **The rate, not the size.** The comment at rules_wifi_mgmt.c:85-88 is
  the design: "a real RF neighbourhood gains BSSIDs slowly", so the rule
  keys on first-sighting rate and a dense but stable area does not trip
  it. That is also the rule's blind spot, below: anything that makes
  known APs look new again (an empty table, eviction) is a first
  sighting.
- **Thresholds** (registry, src/tune.c:185-186): `beacon.flood_thresh`
  default `BEACON_FLOOD_THRESH` = 40 (include/sloth.h:1245),
  `beacon.flood_window_s` default `BEACON_FLOOD_WIN_SECS` = 10 (:1246).
- **Condition.** `n >= thresh` (line 93 returns otherwise).
- **Key.** The constant `"beacon_flood"` (line 104): one incident for the
  whole sensor, whatever the sources. There is no per-transmitter or
  per-channel key because a fabricated BSSID carries no stable identity
  to key on.
- **Detail.** `<n> new BSSIDs in <win>s (mdk-style beacon flood)` (line
  96).
- **Severity.** `ALERT_SEV_WARN`, unconditionally (line 103). There is no
  `--my-bssid` escalation because the finding is about BSSIDs that are
  by construction not the operator's.
- **Evidence.** `fire_ev()` with `beacon_flood_evidence(now, win, ...)`
  (src/beacon_snoop.c:79-93): the beacon that *introduced* each of the
  newest in-window BSSIDs, under the same window test the count used,
  up to `ALERT_EVIDENCE_IDS` = 8 (include/sloth.h:854). No `match_ip`
  (line 104), so the evidence ring is the only route back to bytes
  (docs/wiki/pcap-export.md:154).
- **Table pressure.** When `g_aps[]` is full the least-recently-seen AP
  is evicted and `evict_beacon_ap` is bumped (src/beacon_snoop.c:1283-
  1291); the evicted BSSID's next beacon is a first sighting again and
  writes a stamp.

Count semantics: `fire_ev()` calls `fire_inv()`, which on an open key
bumps `evaluations` and `count` every call (src/alerts/engine.c:479-480)
and `observations` only when the detail or severity changed (:488-491).
The key resolves `ALERT_RESOLVE_AFTER_S` = 300 s after its last
assertion (include/sloth.h:860). `POLL_MS` = 250 is the longest wait
between polls (include/sloth.h:28); new keys and escalations wake the
loop early, so polls per second are >= 4 and any duration derived as
`count / 4` is an upper bound.

## The mechanism

T1498.001 is the plain form of a denial-of-service: "Adversaries may
attempt to cause a denial of service (DoS) by directly sending a
high-volume of network traffic to a target" [2]. The repo corpus note
frames the 802.11 case precisely: a beacon flood is "hundreds of
fabricated networks", which "fills every client's scan list, which is
`mdk4 b`'s entire function" [1]. The resource spent is not bandwidth
but airtime and, at the receiver, the finite scan list and the display
and association logic that iterate it.

The tooling is trivial and widely shipped. mdk4's mode `b` "Sends beacon
frames to show fake APs at clients" and the README notes it "can
sometimes crash network scanners and even drivers!" [3]. airbase-ng,
given a list of ESSIDs, beacons all of them - "When using a list of
ESSIDs, all ESSIDs will be broadcast with beacons" - and adjusts the
beacon interval as the list grows [4]. On commodity microcontrollers the
same capability is a selling point: the esp8266 firmware advertises
"create dozens of networks and confuse WiFi scanners" [5]. None of these
needs proximity beyond radio range and none needs any credential.

What the attacker gains is disruption and confusion only: no
interception, no key. A flood can be an end in itself (a scanner that
cannot show the real network) or cover for something else (an evil twin
hiding among fabricated SSIDs). sloth reports the rate and names the tool
shape; it does not assert intent, because a beacon carries none.

## Evidence that proves it

What sloth records:

- The alert detail: `<n> new BSSIDs in <win>s (mdk-style beacon flood)`.
- Cited evidence frames via the evidence ring: the beacon that
  introduced each of the newest in-window BSSIDs, not a known AP
  beaconing again, because the finding is the arrival
  (docs/wiki/pcap-export.md:154). With `--collect-handshakes` and
  `--eapol-dir`, those frames reach the per-alert evidence pcap - but
  only if `pcap.min_severity` is lowered to WARN, since this rule never
  escalates past WARN and the default floor is CRIT.
- JSONL `beacon` records per BSSID (docs/wiki/jsonl-schema.md:702):
  `ssid`, `bssid`, `signal_dbm`, `channel`, `enc`, and the full
  fingerprint set - `vendor_ies_hash`, `ie_order_hash`, `beacon_ms`,
  `fp_flags`, TBTT jitter. A fabricated flood tends to leave these
  implausibly uniform or implausibly varied across "APs".
- `sensor_health`: `evict_beacon_ap` climbs when the 256-row table
  overflows (docs/wiki/jsonl-schema.md:806), which is itself a signal
  that first-sighting churn is running high for a reason other than an
  attacker.

To call it real: a dense cluster of BSSIDs appearing in one short window
with addresses that never carry data traffic, SSIDs that are random or
sequential, beacon-interval or IE-order fingerprints that repeat across
"distinct" APs (one radio emitting many), and signal strengths that do
not spread the way a room full of real APs does. The cited beacons are
the frames to read first.

What refutes it: the new BSSIDs are real APs with distinct fingerprints
and plausible signal spread - a conference, an apartment block, a sensor
that just started with an empty table, or a `--hop` sweep that just
arrived on a crowded channel. In those cases the count is high once and
then the window empties as the APs become known and stop writing stamps.

## Benign causes

- **A cold start in a dense area.** Every real AP is a first sighting to
  an empty `g_aps[]` table, so a sensor booted in an apartment block or
  at a venue can cross 40 first sightings in 10 s on legitimate beacons
  alone (src/beacon_snoop.c:1281-1294 writes a stamp only on the
  new-entry path, so this is exactly the admit-everything moment).
- **Table eviction churn.** With more than 256 BSSIDs in range the
  `g_aps[]` table evicts the least-recently-seen AP
  (src/beacon_snoop.c:1283-1291); that AP's next beacon is a fresh first
  sighting and writes another stamp. A crowded band can therefore
  manufacture a steady first-sighting rate from entirely real APs.
- **Channel hopping.** `--hop` arriving on a busy channel delivers a
  burst of beacons sloth has not heard on that channel yet; the base
  dwell is 250 ms (src/wifi_chanhop.c:42) so a sweep can stack several
  channels' worth of first sightings into one window.
- **Genuine flood.** mdk4 `b`, airbase-ng with an ESSID list, or ESP8266
  beacon spam [3][4][5] - the case the rule is for.

Tell them apart by the fingerprints and signal spread of the cited
beacons (real APs differ; one radio's fakes repeat), by whether
`evict_beacon_ap` is climbing (churn, not necessarily attack), and by
whether the burst is a one-time window at startup or a sustained rate.

## Assessment

**Severity.** WARN, no ownership split, is correct. A fabricated BSSID
is by definition not a `--my-bssid` network, so the escalation the other
flood rules use has nothing to key on, and the harm - a polluted scan
list and spent airtime - is real but not a compromise. The detail names
the tool shape ("mdk-style") rather than asserting an adversary, which
matches what a rate signal can honestly support.

**Prevalence.** The capability is everywhere - one mdk4 flag, an
airbase-ng option, a hobbyist board [3][4][5] - but a sustained live
flood against a specific monitored neighbourhood is far less common than
the tooling's availability suggests. No fetched source quantifies a
field rate, so none is claimed.

**Reference host:** 1 key, 814 fires, WARN, 17 reopens, 2026-10-14 to
2026-11-03. The key is the constant `"beacon_flood"`, so the 17 reopens
plus the opening incident are 18 incidents sharing one row; 814
evaluations over 18 incidents is about 45 ticks each, which at >= 4
ticks/s is at most about 11 s of standing condition per incident - the
length of the 10 s window following a single burst, not a sustained
flood. Eighteen short bursts across twenty days on a hopping sensor is
as consistent with eighteen process starts or hop sweeps into a dense
band as with eighteen tool runs; the `alert.create` timestamps lined up
against the JSONL session starts are what decides which. Noise is low and
needs no intervention: the single global key already collapses the
condition to one incident at a time, and `observations` (not `count`) is
the figure to trend, since it moves only when the detail changes.

**Sufficient to act on alone?** No - treat it as a prompt to read the
cited beacons, not a verdict. First response: open the evidence frames
(or the `beacon` JSONL rows) for the window and check whether the new
BSSIDs are real APs (distinct fingerprints, plausible signal spread) or
one radio's fabrications (repeating `ie_order_hash` / `beacon_ms`,
addresses with no data traffic); check `evict_beacon_ap` to see whether
ordinary table churn in a crowded band is manufacturing first sightings;
and confirm the burst is not simply this sensor starting cold or hopping
onto a busy channel. If it is a genuine flood, nothing on the network
side stops a radio beaconing - the fix is to locate the transmitter
(docs/wiki/alert-remediation.md:660-672). If the environment is honestly
dense, raise `beacon.flood_thresh` or shorten `beacon.flood_window_s`
via `--tune` (src/tune.c:185-186).

## Bibliography

1. research/mitre/T1498.md - repo corpus document citing ALERT_TYPE_BEACON_FLOOD, which describes beacon flooding as "hundreds of fabricated networks ... `mdk4 b`'s entire function" (source: https://attack.mitre.org/techniques/T1498/, retrieved 2026-09-07) (accessed 2026-11-03)
2. MITRE ATT&CK T1498.001, Direct Network Flood - https://attack.mitre.org/techniques/T1498/001/ (accessed 2026-11-03)
3. mdk4 README, attack mode `b` (beacon flooding) and mode `a`, aircrack-ng/mdk4 - https://github.com/aircrack-ng/mdk4 (accessed 2026-11-03)
4. aircrack-ng, "airbase-ng" (ESSID-list beaconing) - https://www.aircrack-ng.org/doku.php?id=airbase-ng (accessed 2026-11-03)
5. SpacehuhnTech/esp8266_deauther README ("create dozens of networks and confuse WiFi scanners"; "Use it only against your own networks and devices!") - https://github.com/SpacehuhnTech/esp8266_deauther (accessed 2026-11-03)
6. J. Bellardo, S. Savage, "802.11 Denial-of-Service Attacks: Real Vulnerabilities and Practical Solutions", 12th USENIX Security Symposium, 2003 - https://www.usenix.org/legacy/events/sec03/tech/bellardo.html (accessed 2026-11-03)

## Verification notes

Verified 2026-11-03 against the working tree (HEAD 8ac44d5) and by
fetching every external source.

Code: `rule_beacon_flood()` at src/alerts/rules_wifi_mgmt.c:84-105 -
`beacon_recent_new_bssids(now, win)` (src/beacon_snoop.c:102-109) over
the 256-slot `g_new_bssid_ts[]` ring (src/beacon_snoop.c:29), stamps
written only on `beacon_record()`'s new-entry path via `note_new_bssid()`
(src/beacon_snoop.c:37-41, 1281-1294), `n < thresh` early return (line
93), constant key `"beacon_flood"` (line 104), WARN unconditionally (line
103), `fire_ev()` with `beacon_flood_evidence()` (src/beacon_snoop.c:79-
93), no `match_ip` - all as written. Thresholds `BEACON_FLOOD_THRESH` 40
/ `BEACON_FLOOD_WIN_SECS` 10 (include/sloth.h:1245-1246), registry rows
`beacon.flood_thresh` 2..256 / `beacon.flood_window_s` 1..3600
(src/tune.c:185-186). `MAX_BEACON_APS` 256 and `evict_beacon_ap` on
overflow (src/beacon_snoop.c:1283-1291). `ALERT_EVIDENCE_IDS` 8
(include/sloth.h:854), `ALERT_RESOLVE_AFTER_S` 300 (:860), `POLL_MS` 250
(:28). Base dwell 250 ms (src/wifi_chanhop.c:42).

Count semantics: `fire_ev()` -> `fire_inv()` bumps `evaluations`/`count`
every re-assertion (src/alerts/engine.c:479-480) and `observations` only
on a detail/severity change (:488-491); the "N new BSSIDs" figure in the
detail is per first-sighting, the alert's count per tick.

Noise arithmetic: 17 reopens + 1 = 18 incidents; 814 / 18 = 45.2
evaluations per incident; 45.2 / 4 = 11.3 s standing per incident, an
upper bound. Checks.

Sources: [2] MITRE T1498.001 fetched; "Adversaries may attempt to cause
a denial of service (DoS) by directly sending a high-volume of network
traffic to a target" verbatim; the page carries no 802.11-specific text,
so the wireless framing rests on [1], not [2]. [3] mdk4 README fetched;
mode `b` "Sends beacon frames to show fake APs at clients" and "This can
sometimes crash network scanners and even drivers!" verbatim, ten modes
(b a p d m e s w f x) confirmed. [4] airbase-ng page fetched; "When using
a list of ESSIDs, all ESSIDs will be broadcast with beacons" verbatim and
the beacon-interval-scales-with-count behaviour confirmed. [5]
esp8266_deauther README fetched; "create dozens of networks and confuse
WiFi scanners" and "Use it only against your own networks and devices!"
verbatim. [6] USENIX Bellardo & Savage page fetched; title and authors
confirmed; cited for the foundational-DoS context only, as its abstract
treats management/MAC-layer DoS generally. [1] research/mitre/T1498.md
read; `alert_kinds` lists `ALERT_TYPE_BEACON_FLOOD` and the quoted
sentence is in the `BEACON_FLOOD` paragraph.

Struck: none. (An IEEE 802.11-2020 beacon-clause citation was
considered - the repo's ieee/ notes cover BTM §9.6.14, spectrum §11.8
and the Country element, none of which is the beacon-flood mechanism, so
no IEEE document is cited here rather than cite one that does not fit.)
