---
type: EVIL_TWIN_PROXIMITY
technique: T1557
rule_file: src/alerts/rules_twin.c:1852 (rule_evil_twin_proximity)
count_semantics: per poll tick (default 250 ms) per BSSID whose 60 s RSSI swing stays >= the threshold; `count` aliases `evaluations` (engine.c:478-479). Not per beacon and not per distinct swing event - the min/max are recomputed each beacon over a 60 s window (RSSI_WIN_SECS, 16 samples), so one sustained spread keeps re-firing every tick
severity_assessment: agree - WARN, and the rule's own comment calls it noisy on its own; it is a corroborator for EVIL_TWIN, not a standalone finding
false_positive_risk: high - any mobile radio walking past the sensor, or the sensor/AP antenna environment changing, produces a >=15 dBm swing with no attacker present; the rule's comment says so
noise_verdict: noisy on the reference host - 458 keys, 70,568,495 fires, max_sev 1. 70.6e6 / 458 = 1.54e5 evaluations per BSSID; at 4 ticks/s that is ~11 hours of held swing-state per BSSID. 458 distinct BSSIDs crossing a 15 dBm swing is ordinary RF churn in a busy band, not 458 rogues. Recommend: only show it beside an EVIL_TWIN on the same SSID (which the remediation already says), or gate the alert on an existing twin candidate for that SSID; raise --tune twin.proximity_dbm in a reflective/mobile environment; show first_seen/last_seen not count
prevalence: not an attack class of its own - it is a weak proxy for an evil twin being switched on or carried closer; prevalence of the thing it hints at is covered under EVIL_TWIN (common) [4][5]
tuning: [--tune twin.proximity_dbm (default 15, 1..100; TUNE_EVIL_TWIN_PROXIMITY_DBM)]
researched: 2026-10-27
---
## What the rule checks

`rule_evil_twin_proximity()` (`src/alerts/rules_twin.c:1699-1719`) walks the beacon table `s->beacon_aps[]` and, for each AP, reads two projected fields `rssi_min_60s` and `rssi_max_60s`. These are maintained by `rssi_ring_push()` (`src/beacon_snoop.c:865-884`), called once per Beacon (:1126, :1399): every beacon pushes the radiotap antenna-signal value into a 16-slot ring (RSSI_WIN_SAMPLES), samples older than RSSI_WIN_SECS = 60 s are dropped, and min/max over the surviving samples are re-derived. 0 dBm is impossible for real Wi-Fi so it doubles as "unseen"; the rule skips a BSSID whose min or max is 0 (:1704). Because the ring is only re-derived when a beacon arrives, an AP that stops beaconing keeps its last min/max until BEACON_AGE_SECS (300 s) evicts it, so the swing can out-live the samples that produced it.

The condition is a single threshold: `delta = rssi_max_60s - rssi_min_60s`, and if `delta >= EVIL_TWIN_PROXIMITY_DBM` (default 15, `--tune twin.proximity_dbm`, `tune.c:50`) it fires `ALERT_TYPE_EVIL_TWIN_PROXIMITY` at `ALERT_SEV_WARN` (:1705-1718). It is a same-BSSID, same-channel swing - the rule header (:1689-1697) is explicit that this is not a roam (which would be a different BSSID). Key is `twin-prox:<bssid>` (:1712), one incident per BSSID. Detail: `<bssid> '<ssid>' RSSI swing <delta> dBm (<min> → <max>) in 60s` (:1713-1716).

No confidence, no evidence IDs, no `match_ip` - a plain `fire()` (:1717-1718). So `--pcap-dir` writes nothing and there is no evidence-ring citation for this type. One fire per qualifying BSSID per tick; the incident resolves 300 s (ALERT_RESOLVE_AFTER_S) after the swing last met the threshold.

The radiotap antenna-signal field is "RF signal power at the antenna ... in decibels difference from 1mW" [6]; the radiotap header is "a mechanism to supply additional information about frames, from the driver to userspace applications such as libpcap" [6], i.e. it is written by the capturing driver on sloth's side. That is the crux of the rule's weakness: the number describes the path between the transmitter and sloth's own antenna, not anything the transmitter did.

## The attack

This rule has no attack of its own. It is phase 3 of sloth's evil-twin pipeline (`rules_twin.c:1689-1697`), a corroborating signal for `EVIL_TWIN` (T1557.004 [4]). The idea: a rogue AP being switched on nearby, carried toward the victim, or ramping transmit power will show a large received-signal swing over a short window, where a fixed legitimate AP sits at a roughly stable level. A WiFi Pineapple or ESP32 in a bag that someone walks across a room is the mental model [5][7]. Combined with a same-SSID twin candidate and a deauth flood, a rising signal is consistent with "the attacker just moved into range and is trying to be the strongest radio under this name" - the stronger-signal coercion ATT&CK describes for evil twins [4].

What an attacker gains is nothing from this signal directly; the gain is in the evil twin the proximity hint accompanies (credential/handshake capture - see EVIL_TWIN). Standalone, a signal swing proves only that the received level moved.

## Evidence that proves it

sloth records the swing magnitude and the min/max dBm and the 60 s window in the detail; nothing else, and no frames are cited. To treat it as real evidence of a rogue, a reader must find a concurrent `EVIL_TWIN` or `EVIL_TWIN_PROXIMITY`-plus-twin on the same SSID (the remediation says exactly this: "Check for an EVIL_TWIN on the same SSID", `alert-remediation.md:474`) and, ideally, see the swing trend upward (a radio approaching) rather than oscillate (multipath). A monotone climb from a weak floor to a strong peak on a BSSID that is also a twin candidate is the pattern worth acting on.

What refutes it: the swing is from a mobile device the sensor happened to hear at varying range; the sensor's own antenna or environment changed (a laptop lid, a body moving between radios); multipath fading in a reflective indoor space, which the RSSI-distance research notes can move the received level by as much as a tenfold change in distance does [8]. Because the value is measured at sloth's own antenna and stamped by its driver [6], none of these involve the transmitter doing anything.

## Benign causes

- **A passer-by's radio** heard at changing distance - the single commonest cause, named in the rule's own comment (:1694).
- **Multipath / fading indoors.** Walls, bodies and reflections swing the received level without any transmitter motion [8].
- **Legitimate AP power management or band changes.** An AP adjusting transmit power (TPC) legitimately moves its received level.
- **Sensor-side antenna changes** - the laptop moved, an obstruction appeared. The swing is about the path to sloth, not the AP.

Tell them apart by correlation: a proximity swing with no same-SSID twin candidate and no deauth activity is almost always one of the above. The rule exists to be read beside EVIL_TWIN, not alone.

## Assessment

Severity (WARN) is correct and the rule is honest about being noisy; it should never be the sole basis for action. Prevalence as an attack is not meaningful - it is a hint, and the thing it hints at (an evil twin) is common and serious [4][5][10]. The evidence is not sufficient to act on by itself; the rule is designed as a corroborator.

The reference-host figures confirm the noise: 70.6e6 fires on 458 keys is ordinary RF churn being counted per tick, not 458 rogues approaching. A responder should ignore a lone proximity alert and only weight it when it lands on a BSSID that already carries an `EVIL_TWIN` row for the same SSID; then the rising signal adds "and it is getting closer / louder" to that finding. Operationally: raise `twin.proximity_dbm` in a reflective or high-traffic environment, and on the alert page show the swing and timestamps rather than the tick count. The best improvement would be to gate emission on an existing twin candidate for the SSID, so the alert cannot fire for RF churn with no twin to corroborate.

## Bibliography

1. `research/mitre/T1557.md` (repo) - "EVIL_TWIN / EVIL_TWIN_PROXIMITY - the rogue AP exists and is close."
2. `docs/wiki/alert-remediation.md` §EVIL_TWIN_PROXIMITY (repo) - read it beside EVIL_TWIN on the same SSID.
3. `docs/views/twins.md` (repo) - the phase 1-4 pipeline this rule is phase 3 of; "High RSSI swing on the twin - a rogue being switched on / moved".
4. MITRE ATT&CK T1557.004 - Adversary-in-the-Middle: Evil Twin - https://attack.mitre.org/techniques/T1557/004/ (accessed 2026-10-27).
5. WiFi Pineapple PineAP documentation - https://documentation.hak5.org/wifi-pineapple/ui-overview/pineap (accessed 2026-10-27).
6. Radiotap "Antenna signal" field definition - https://www.radiotap.org/fields/Antenna%20signal.html ; radiotap overview (header supplied "from the driver to userspace applications such as libpcap") - https://www.radiotap.org/ (both accessed 2026-10-27).
7. ESP32 Marauder attack wiki ("Beacon Spam AP spams beacon frames that copy a known access point") - https://github.com/justcallmekoko/ESP32Marauder/wiki/attack (accessed 2026-10-27).
8. `research/papers/rssi-distance-estimation.md` (repo), citing ITU-R P.1238 - indoor RSSI is an order-of-magnitude figure; walls/bodies/reflections move the received level by up to a tenfold distance change.
9. IEEE Std 802.11-2020 (pub. 2021-02-26; superseded by 802.11-2024), Part 11 - https://standards.ieee.org/ieee/802.11/7028/ (accessed 2026-10-27).
10. "Australian charged for evil twin WiFi attack", 2024-07-01 - https://www.bleepingcomputer.com/news/security/australian-charged-for-evil-twin-wifi-attack-on-plane/ (accessed 2026-10-27).

## Verification notes

Verified 2026-10-27 against `src/alerts/rules_twin.c:1689-1719`, `src/beacon_snoop.c:861-884`, `src/tune.c:50`, `include/sloth.h:1297,1330-1331` and every external URL.

Code: rule_file, count semantics, the `>= 15 dBm` threshold (`twin.proximity_dbm`, 1..100), the `twin-prox:<bssid>` key and WARN severity are exactly what the code does. Line anchors re-pinned: function range → `:1699-1719`; zero-skip `:1703-1704` → `:1704`; key `:1716` → `:1712`; detail `:1718-1722` → `:1713-1716`; `fire()` `:1723` → `:1717-1718`; `rssi_ring_push` → `:865-884`; `engine.c:475-479` → `:478-479`. Added: the min/max are re-derived only when a beacon arrives, so a silent AP keeps a stale swing until BEACON_AGE_SECS evicts it. Detail arrow is `→` (U+2192) in the source. Noise arithmetic re-checked: 70,568,495 / 458 = 154,079 ≈ 1.54e5; / 4 Hz = 38,520 s ≈ 10.7 h. Holds.

Sources: [6] the radiotap field page defines the field as "RF signal power at the antenna ... in decibels difference from 1mW" but contains **no** sentence saying it is "set by the receiving radio, not the sender" - that quote was struck and the point re-sourced to radiotap.org's overview sentence that the header passes "from the driver to userspace applications such as libpcap". [4] T1557.004, [5] PineAP, [7] Marauder, [9] IEEE, [10] BleepingComputer all open and support their sentences (Marauder reworded to its verbatim line; IEEE noted as superseded). [8] `research/papers/rssi-distance-estimation.md` exists and carries the "tenfold" / ITU-R P.1238 statement at line 13; it does not name this alert type, which is fine - it is cited for propagation, not as the type's corpus entry. `research/mitre/T1557.md` names EVIL_TWIN_PROXIMITY (lines 5, 20). `docs/wiki/alert-remediation.md:474` is the "Check for an EVIL_TWIN on the same SSID" line as cited; §EVIL_TWIN_PROXIMITY header is at line 467.

### Second pass, 2026-10-27

Re-read `rules_twin.c:1689-1719`, `beacon_snoop.c:865-884` (`rssi_ring_push`), its two call sites `:1126` (existing-AP update) and `:1399` (new-AP slot in `beacon_record_ev`, which starts at `:1111`), `tune.c:50`, `include/sloth.h:1297,1330-1331`, `engine.c:478-479`. Every anchor pins; rule_file, the `delta >= twin.proximity_dbm` (15, 1..100) threshold, the zero-skip, the `twin-prox:<bssid>` key, WARN and the plain `fire()` with no match_ip are what the code does. No text changes were needed. Tick caveat shared by every per-tick count in this batch: `poll_tick()` (`src/poll.c:296` → `alerts_update`) runs on every main-loop wake, and the loop wakes early on an alert escalation and, in TUI mode, on a keypress (`src/main.c:1666-1673`, `include/sloth.h:28`), so 250 ms is the *slowest* cadence; the per-key durations derived at 4 ticks/s are upper bounds, not measurements. Arithmetic unchanged: 70,568,495 / 458 = 154,079; / 4 = 38,520 s = 10.7 h (upper bound).

Sources re-opened: [4] T1557.004 ("Adversaries may provide a stronger signal strength or block access to Wi-Fi access points" verbatim), [5] PineAP, [6] radiotap field page ("RF signal power at the antenna ... in decibels difference from 1mW" verbatim; still says nothing about which side sets it) and radiotap.org overview ("a mechanism to supply additional information about frames, from the driver to userspace applications such as libpcap" verbatim), [7] Marauder, [9] IEEE (superseded by 802.11-2024), [10] BleepingComputer. All open and support their sentences. Repo: `research/mitre/T1557.md:5,20` names EVIL_TWIN_PROXIMITY; `research/papers/rssi-distance-estimation.md:13` carries the "tenfold" line; `docs/wiki/alert-remediation.md:467` (§) and `:474` ("Check for an `EVIL_TWIN` on the same SSID") as cited.
