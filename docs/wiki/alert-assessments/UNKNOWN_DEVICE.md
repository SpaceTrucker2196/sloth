---
type: UNKNOWN_DEVICE
technique: T1200
rule_file: src/alerts/rules_wifi_mgmt.c:1101 rule_unknown_device()
count_semantics: per evaluation tick, per standing (unrostered STA) key - fire() bumps `evaluations`/`count` every poll in which the STA is still in `s->assocs[]` on a designated BSSID/SSID and still absent from the roster; one increment is one poll (~4/s at the default 250 ms POLL_MS), not one frame or one association
severity_assessment: agree - WARN is right for "a device I did not list is on my network": actionable, but the commonest cause is an incomplete roster, and the rule cannot escalate on anything it observes
false_positive_risk: high - every guest handset, every rotated private MAC and every device the operator forgot to roster fires it; the rule is only as good as the roster
noise_verdict: not seen on the reference host - no rows at all, which is expected: the rule is inert unless BOTH `--known-mac(s)` and `--my-ssid`/`--my-bssid` are configured (rules_wifi_mgmt.c:1026-1027), and the reference host evidently configured neither or saw no unrostered client. No tuning needed on this evidence
prevalence: unknown as a base rate - T1200 is an ATT&CK technique with no published incidence figures [2]; the ordinary population an unrostered MAC belongs to is visitors and randomised addresses [1][3][4], and the implant case is rare by comparison
tuning: [--known-mac MAC, --known-macs FILE, --my-ssid SSID, --my-bssid BSSID, --refresh-ms N (sets the count cadence; no --tune knob touches this rule)]
researched: 2026-10-27
---
## What the rule checks

`rule_unknown_device()` (src/alerts/rules_wifi_mgmt.c:1065-1094) is a pure function of two operator inputs and one observed table.

- **Gates.** It returns immediately if the roster is empty (`ownership_known_count() == 0`, line 1066) or if no network has been designated (`!ownership_any()`, line 1067). Both inputs are required; with either missing the rule can never fire.
- **Input table.** `s->assocs[]` (include/sloth.h:2009-2024), the association table built from frames the AP sent - association/reassociation responses with status 0 and EAPOL M3 (`ASSOC_SRC_*`). It is not built from probe requests, by design (comment at lines 1056-1061): per-SSID MAC randomisation is stable across reconnects, probe randomisation is not.
- **Condition.** For each row: the BSSID is in the `--my-bssid` set or the SSID is in the `--my-ssid` set (lines 1071-1072), and the STA MAC is neither on the roster nor one of the host's own interface addresses (`ownership_is_own_device()`, line 1079 - #183: a sensor is associated to the network it watches, and the rule must not name it; the gate above still counts only the operator's entries, so the rule stays inert until they roster something).
- **Key.** `unknowndev:<sta_mac>` (line 1086) - one incident per unrostered station, whichever of the operator's BSSIDs it is on.
- **Detail.** `<sta> on '<ssid>' [<bssid>] not in roster` with a trailing `(randomised MAC)` when the STA's first octet has the locally-administered bit set (`sta_random`, set at src/assoc_track.c:455 from `sta[0] & 0x02`).
- **Severity.** Always `ALERT_SEV_WARN` (line 1091). There is no CRIT branch and no ownership escalation - the ownership check is the precondition, not a modifier.
- **Count.** Plain `fire()` (no evidence IDs, no `match_ip`), so each poll in which a row still satisfies the condition increments `evaluations` and the compat alias `count` (src/alerts/engine.c:478-479). The detail string is stable, so `observations` stays at 1 unless the SSID/BSSID in the row changes. Because the key is the STA alone and `s->assocs[]` is keyed by (BSSID, STA), one unrostered STA associated to two designated BSSIDs fires the same key twice per poll with two different details - `count` then climbs at twice the poll rate and `observations` moves every poll, so the detail flips between the two BSSIDs.
- **Resolve.** The incident expires 300 s after the last evaluation (`ALERT_RESOLVE_AFTER_S`, include/sloth.h:860; `expire_incidents()`, engine.c:917-925), i.e. once the STA is rostered, the designation no longer covers the row, or the row leaves the table. The association table does **not** age rows: `g_tbl` (`MAX_ASSOC_ENTRIES` = 128, include/sloth.h:1999) evicts the least-recently-seen pair only when it is full (src/assoc_track.c:441-447). In a quiet environment an unrostered STA that associated once therefore stays in the table, and the incident stays open, for the life of the process.

## The attack

MITRE T1200, Hardware Additions, is an adversary physically introducing a device - a laptop on a spare port, a dropbox, a rogue AP, or simply a station joining the WLAN with a credential it should not have - to get access that software controls were not watching for [2]. The defensive counterpart is asset inventory: CIS Control 1 is "actively manage (inventory, track, and correct) all enterprise assets ... to accurately know the totality of assets that need to be monitored and protected" [5], and NIST SP 800-153 frames WLAN monitoring as part of securing a WLAN [6]. sloth's rule is the WLAN-side instance of that control: a device associated to a network the operator designated as theirs that the operator's roster does not list.

What makes this hard in 2026 is MAC randomisation. Apple devices use "a different MAC address for each Wi-Fi network", and since iOS 18 / macOS 15 a "Rotating" setting changes that per-network address every two weeks [3]. Android generates "a persistent randomized MAC address based on the network profile's parameters" that is stable until factory reset, and since Android 12 some networks use non-persistent randomization that "re-randomizes the MAC address at the start of every connection" [4]. A roster of hardware addresses therefore drifts out of date on its own, and the repo's own research note is blunt about it: "an unrostered MAC is far more often a guest's handset than an implant" [1].

No tooling is specific to this alert - any client is the "tool". The adversarial case is a station that obtained the PSK (shoulder-surfed, shared, cracked offline from a captured handshake) or an 802.1X credential and simply joined.

## Evidence that proves it

What sloth records:

- The alert detail: STA, SSID, BSSID, and whether the STA address is locally administered.
- JSONL `assoc` records (docs/wiki/jsonl-schema.md:708): `bssid`, `sta_mac`, `ssid`, `sta_random`, `source` (which frame proved the association), `channel`, `signal_dbm`, `first_seen`, `last_seen`, `frame_count`, and the AP-side distance estimate. These are "of the AP, not the client" - every frame behind the row is one the AP sent.
- JSONL `wifi_assoc_req` for the same pair (what the client asked for: `akm_bits`, `requested_mfp`, `vendor_ie_hash`, `phy`), and `eapol` records (`assoc_evidence` on M3).
- JSONL `device` rows (`vendor`, `hostname`, `ip`, `sources` bitmask) once the client speaks IP.
- No pcap: `fire()` is called with `match_ip = NULL` (line 1046) and no evidence IDs, so neither the per-alert `--pcap-dir` path nor the evidence-ring path applies (docs/wiki/pcap-export.md:1-20, 140-160). The association frames themselves are not retained for this alert.
- `sensor_health` has no counter specific to this rule.

To call it real: the STA is **not** randomised (a vendor OUI resolves in the `device` row), it associated with a credential (an `eapol` row with `assoc_evidence`, or 802.1X identity in `rogue_radius`/EAP records), it obtained an IP and generated traffic (`device`, DNS/TLS logs), and nobody in the household/office claims it. A fixed, globally-administered MAC from an unusual vendor that persists across days, on an SSID whose passphrase was never meant to leave the building, is the shape of a real finding.

What refutes it: `(randomised MAC)` in the detail plus a vendor name in the `device` row of a phone/laptop maker, a `first_seen` that coincides with a visitor, or a hostname that names a family member's device. Any of those says "roster gap", and the fix is `--known-mac`.

## Benign causes

- **The sensor's own host** - a host running sloth on the designated network is associated to it, so before #183 it was its own first "unknown device". Exonerated now without being rostered, from the `iface` records (`ownership_is_own_device()`).
- **Guest and visitor devices** - the dominant case; the repo's research note says so explicitly [1].
- **Rotating private addresses** - Apple's Rotating mode (every two weeks) [3] and Android non-persistent randomization (per connection) [4] produce a new "unknown" from a device the operator already knows. The detail's `(randomised MAC)` marker is the tell.
- **A device re-provisioned or factory reset** - Android's persistent random MAC changes on factory reset [4].
- **IoT and appliances nobody rostered** (printers, TVs, thermostats): fixed MACs, so they fire once and stand until added.
- **Operator error in the roster file** - `--known-macs` rejects a malformed line (docs/wiki/cli-reference.md:296), but a typo in a valid-looking MAC silently excludes the device.

## Assessment

**Severity.** WARN is right. The finding is actionable (disconnect or roster), but the rule has no observable that distinguishes an implant from a guest, so it should never page as CRIT on its own. The repo's own doc chose WARN for exactly this reason (rules_wifi_mgmt.c:1022-1024).

**Prevalence.** There is no published base rate for T1200 on WLANs - the ATT&CK page itself says "public references of usage by threat actors are scarce" [2]. The honest statement is that the population of unrostered MACs is dominated by legitimate visitors and randomised addresses [1][3][4].

**Reference host.** Not seen: zero keys, zero fires. That is the expected outcome of the double gate - the reference host did not configure both a roster and a designation (or configured them and had a complete roster). Nothing to tune. If it is enabled, expect one incident per unrostered station that re-fires every poll (~4 Hz at `POLL_MS` 250, include/sloth.h:28) while the association row is live - which, since the table never ages a row out, can be the rest of the run - with a stable detail and therefore a quiet JSONL stream (one `alert.create`, one `alert.resolve`).

**Is the evidence sufficient to act on?** Yes for the action the alert implies - identify the device - and no for any stronger claim. The rule proves "associated and not listed"; everything else comes from joining the `device`, `assoc`, `wifi_assoc_req` and `eapol` rows.

**First step for a responder.** Read `(randomised MAC)` and the `device` row's vendor. If it is a phone-vendor OUI or a private address, ask who visited; if it is a fixed address from an unfamiliar vendor, pull its IP traffic from the DNS/TLS logs, then decide whether to rotate the PSK (a stranger with the passphrase will be back under a new MAC).

## Bibliography

1. research/mitre/T1200.md - repo research note, MITRE ATT&CK T1200 (retrieved 2026-09-07); states the roster dependency and the randomisation caveat (accessed 2026-10-27)
2. MITRE ATT&CK T1200, Hardware Additions - https://attack.mitre.org/techniques/T1200/ (accessed 2026-10-27)
3. Apple, "Use private Wi-Fi addresses on Apple devices" - https://support.apple.com/en-us/102509 (accessed 2026-10-27)
4. Android Open Source Project, "MAC randomization behavior" - https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior (accessed 2026-10-27)
5. CIS Critical Security Control 1: Inventory and Control of Enterprise Assets - https://www.cisecurity.org/controls/inventory-and-control-of-enterprise-assets (accessed 2026-10-27)
6. NIST SP 800-153, Guidelines for Securing Wireless Local Area Networks (WLANs), Feb 2012 - https://csrc.nist.gov/pubs/sp/800/153/final (accessed 2026-10-27)
7. docs/views/alerts.md:206 (rule table row); docs/wiki/alert-remediation.md:815-829; docs/wiki/cli-reference.md:293-296 (flags) - repo documents (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree at commit 0d60387.

- **Code.** `rule_file`, count semantics, gates, condition, key, severity and the `match_ip = NULL` fire all match src/alerts/rules_wifi_mgmt.c. Corrected line references: function span 1025-1049 (was 1025-1058), key at line 1041 (was 1040), `assoc_t` at include/sloth.h:2009-2024. `evaluations`/`count` bump per fire at engine.c:478-479 and `observations` only on a detail/severity change at 487-490, as stated.
- **Resolve semantics corrected.** The entry said the incident closes "once the assoc row ages out". There is no age-out: the association table is LRU-evicted only when its 128 slots are full (src/assoc_track.c:441-447), so the row - and the incident - can persist for the whole run. Text in *What the rule checks* and *Reference host* updated.
- **Noise arithmetic.** No reference-host rows, so nothing to recompute; the ~4 Hz cadence follows from `POLL_MS` 250 and `alerts_update()` running once per poll (src/poll.c:296).
- **Sources.** [2] MITRE T1200 fetched; description confirmed, no incidence figures (added its own "scarce" caveat to *Prevalence*). [3] Apple 102509 fetched; "different MAC address for each Wi-Fi network" and "rotates to a different private address every 2 weeks" confirmed. [4] AOSP page fetched; both quoted sentences confirmed verbatim. [5] CIS Control 1 fetched; quoted overview confirmed. [6] NIST SP 800-153 landing page fetched; abstract says the publication covers WLAN "security configuration and monitoring". [1] research/mitre/T1200.md exists, lists `ALERT_TYPE_UNKNOWN_DEVICE` in `alert_kinds`, and contains the quoted "guest's handset" sentence (line 37). [7] repo paths and line ranges confirmed (alerts.md:206, alert-remediation.md heading at 815, cli-reference.md:293-296).

### Second verification pass (2026-10-27, tree at d70d394)

- Re-read `rule_unknown_device()` (src/alerts/rules_wifi_mgmt.c:1025-1049): gates (1026-1027), key `unknowndev:%s` (1041), WARN fire with `match_ip = NULL` (1046), the `(randomised MAC)` suffix and the 16-char SSID cap (`%.16s`) all match. The no-age-out claim re-confirmed at src/assoc_track.c:441-447.
- **Added:** the per-STA key over a per-(BSSID, STA) table means a STA on two designated BSSIDs is evaluated twice per poll (count x2, detail flips). Previously unstated.
- **Cadence (second pass).** "~4/s" is the nominal floor, not a fixed rate: `POLL_MS` 250 is the *longest* wait between polls, because the wait in src/main.c:1666/1671 returns early on the event-wake fd, which `fire_inv()` signals on every new incident key and every escalation (src/alerts/engine.c:526, 608), and the TUI also returns on a keypress. Polls per second are therefore >= 4, and any duration derived as `count / 4` is an upper bound.
- Sources re-opened: [2] MITRE T1200 (both quoted phrases, including "public references of usage by threat actors are scarce"), [3] Apple 102509 (both quotes; Rotating on iOS 18 / macOS Sequoia 15 and later), [4] AOSP (both quotes; non-persistent from Android 12), [5] CIS Control 1 (quote verbatim), [6] NIST SP 800-153 (Feb 2012; abstract names "ongoing maintenance and monitoring"). [1] research/mitre/T1200.md lists `ALERT_TYPE_UNKNOWN_DEVICE` (line 5) and carries the quoted sentence (line 37). No source struck.
