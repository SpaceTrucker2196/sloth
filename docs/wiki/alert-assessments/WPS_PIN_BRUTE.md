---
type: WPS_PIN_BRUTE
technique: T1110.001
rule_file: src/alerts/rules_enterprise.c:92 of rule_wps_pin_brute()
count_semantics: per poll tick (POLL_MS 250 ms, include/sloth.h:28) on which a session still qualifies; fire() bumps evaluations (= count) once per alerts_update() under the key (src/alerts/engine.c:478-479). The meaningful number is in the detail string, not in count: it is the number of completed M1->M3->EAP-NACK restart cycles (one refused PIN guess) inside the trailing 60 s window, read from an 8-slot ring, so the detail saturates at 8 per session (src/wps_track.h:38-45, src/wps_track.c:181-195).
severity_assessment: agree (CRIT) - five refused PIN guesses in 60 s is a machine rate (Viehboeck measured 0.5-3 s per attempt [4]; reaver's default delay is 1 s [7]), and Viehboeck's lockout table lists "3 attempts / 1 minute" as the WSC 2.0 certification requirement [4], so reaching the threshold means either no lockout or an attacker ignoring it.
false_positive_risk: low - no human completes five full WSC exchanges per minute, and the tracker only counts a NACK that followed M3, discarding ordinary M2D refusals (src/wps_track.c:133-146).
noise_verdict: not seen on the reference host - host data is null. Per-STA keying is wpsbrute:<bssid>:<sta>; the rotating-MAC arm keys on wpsbrute-uuid:<bssid>:<16-byte UUID-E> and reports a group once from its lead member (rules_enterprise.c:119-128), so an N-MAC spray whose MACs each stay under the threshold is one row, not N. The per-STA arm still runs independently: any single MAC that itself reaches 5 cycles also gets its own `wpsbrute:` row, so a spray whose MACs each cross the threshold yields N+1 rows. Expected shape: one row per attacking station (or one per UUID-E group), count rising ~4/s while the attack is live. Not noisy. Threshold is already tunable (--wps-pin-brute-cycles / tune wps.pin_brute_cycles, default 5, src/tune.c:67); raise it to quiet a chatty environment.
prevalence: historically very high exposure, declining - CISA TA12-006A: "Most Wi-Fi access points that support Wi-Fi Protected Setup (WPS) are affected" [8]; Viehboeck: "WPS is activated by default on all devices I had access to" [4]. WPS PIN remains present on much consumer gear 14 years on, though many vendors added lockout or disabled external-registrar PIN.
tuning: [--wps-pin-brute-cycles, tune wps.pin_brute_cycles]
researched: 2026-10-27
---
## What the rule checks

Input is the WPS session table built by `src/wps_track.c` from the EAP-WSC opcode stream (`wps_track_observe()` on the capture thread). The rule snapshots it under lock with `wps_track_snapshot()` into a local array of up to `MAX_WPS_SESSIONS` (64), so the walk sees a consistent set (src/alerts/rules_enterprise.c:94-95). It sits at line 56 of `src/alerts/rules_table.c`, 30th in run order.

The countable unit is the restart cycle. `src/wps_track.c` runs a state machine over WSC 2.0 message types: IDLE -> M1 -> `M1_SEEN` -> M3 -> `M3_SEEN` -> NACK -> `NACKED`, and a NACK arriving from `M3_SEEN` increments `cycle_count` and stamps `cycle_ts[cycle_count % 8]` (src/wps_track.c:133-146). The guard at rules-level: `wps_track_cycles_since(&sess, now, WPS_PIN_BRUTE_WINDOW_S)` counts only cycles whose NACK landed in the last `WPS_PIN_BRUTE_WINDOW_S` = 60 s (src/alerts.h:313), reading the ring on a copy with no lock (src/wps_track.c:181-195). The rule fires when that count `>= alerts_wps_pin_brute_cycles()` (default 5; src/alerts/rules_enterprise.c:97-101).

A NACK that did **not** follow M3 is never counted - it is an ordinary M2D-style refusal, and the state machine only advances to a countable cycle from `M3_SEEN` (src/wps_track.c:133-146). The repo pins that distinction with `test_wps_pin_brute_ignores_nacks_without_m3`.

Two findings, two shapes:

1. **Per station** (rules_enterprise.c:99-117). Key `wpsbrute:<bssid>:<sta>` via plain `snprintf` (line 109). Detail: `<c> WPS PIN attempts (M1-M3-NACK) from <sta> at <bssid> in 60s - external-registrar brute force, VU#723755[ - YOUR network]`. The "YOUR network" suffix is appended when `ownership_is_my_bssid()` is true.
2. **Per UUID-E across >= 2 stations** (rules_enterprise.c:119-166). The enrollee identity inside M1 is what a MAC-rotating attacker usually forgets to vary, so cycles are summed over `(bssid, uuid_e)` across sessions. Reported once, from the first member (`lead` scan, rules_enterprise.c:119-128), and only when `stas >= 2` (so a single-MAC session is never double-reported) and summed `cycles >= thresh`. Key is built with the typed `akey_*` builder carrying all 16 UUID-E bytes (rules_enterprise.c:150-154); the detail prints the first 8 bytes as hex.

Both fire `ALERT_SEV_CRIT` with `match_ip = NULL` (rules_enterprise.c:115, 160), so no per-alert pcap and no evidence-ring citation (plain `fire()`). Technique `T1110.001` (include/sloth_alerts.def:155). Only the *count* threshold is tunable; the 60 s window is fixed because it is the rate the threshold is defined over, not operator policy (docs/wiki/alerts.md:779-784).

## The attack

WPS (Wi-Fi Protected Setup) lets a client join a WPA/WPA2 network by entering an 8-digit PIN instead of the passphrase. Viehboeck's 2011 disclosure [4], carried by CERT/CC VU#723755 (CVE-2011-5053) [1][2], is that the external-registrar method authenticates on the AP's PIN alone and leaks how much of a guess was right. During the exchange, a NACK after message M4 means the first half of the PIN was wrong, and a NACK after M6 means the second half was wrong [4]. Because the 8th digit is a checksum of the first seven, the search space collapses from 10^8 to 10^4 + 10^3 = 11,000 attempts [1][4]. At the 0.5-3 s per attempt Viehboeck measured, an AP with no lockout falls "in less than four hours (at 1.3 seconds/attempt)" [4]; CISA put practical recovery at 4-10 hours [8]. The outcome is full compromise: "brute force the WPS PIN and retrieve the password for the wireless network, change the configuration of the access point, or cause a denial of service" [1].

The standard tooling is `reaver` (its `-d`/`--delay` defaults to 1 s between attempts, `--lock-delay` 60 s, and it targets the online method unless `-K`/`-Z` selects the offline Pixie-Dust variant) [7] and `bully` (a leaner C re-implementation with `-l`/`--lockwait` 43 s and `-D`/`--detectlock`) [9]. `wifite2` wraps both. The MAC-rotation evasion exists because a conformant AP rate-limits or locks per enrollee MAC; rotating the source MAC while leaving the M1 UUID-E constant defeats the per-MAC limiter, which is exactly the second detection shape above.

CERT's only workaround is to disable the external registrar (WPS PIN); "we are currently unaware of a practical solution to this problem" [1][5]. Viehboeck's lockout table lists "3 attempts / 1 minute" as the "Requirement for WSC 2.0", while his prose hedges that it "might be a requirement in the (new) WSC Specification Version 2" - the WSC 2.0 text itself is behind Wi-Fi Alliance membership and was not read [4]; hostapd implements it as a 60 s lock that doubles every 3 further failures and disables the AP PIN indefinitely after 10 consecutive failures [10].

## Evidence that proves it

What sloth records:

- `alert` / `alert.create` JSONL: `title WPS_PIN_BRUTE`, `key wpsbrute:<bssid>:<sta>` or `wpsbrute-uuid:<bssid>:<16-byte UUID-E hex>` (docs/wiki/alerts.md:133), `sev 2`, `technique T1110.001`, `count` = evaluations. The attempt count and the station/UUID-E are in `detail`.
- The `[b] -> Enter` WPS detail screen for the BSSID renders the session's opcode timeline (`wps_track_events()`, up to 16 frames) and the per-session cycle count - the same table the rule read.
- No pcap: `match_ip` is NULL. The EAP-WSC frames themselves are the only byte-level evidence and sloth keeps them only as the opcode summary, not as a capture.
- sensor_health: `evict_wps_session` climbs if the 64-slot session table is thrashing (a MAC-rotation spray is designed to force exactly this - the tracker notes `SH_EVICT_WPS_SESSION` on eviction, src/wps_track.h:34). A rising `evict_wps_session` beside this alert corroborates the rotating-MAC shape.

To call it real, a reader should see: five or more complete M1->M3->NACK cycles from one station inside a minute (per-station), or the same cycle total summed across two or more MACs that share one UUID-E (rotating). A genuine brute force shows a steady cadence near the tool's delay (reaver ~1 s/attempt). The UUID-E being identical across MACs is the single strongest tell of a deliberate rotation, because a benign fleet of clients would each carry a distinct enrollee UUID.

What would refute it as an attack: a single client retrying a wrong PIN a handful of times (below threshold), or cycles spread over tens of minutes (the window excludes them). A NACK stream with no preceding M3 is already excluded by the tracker, so a count of zero despite visible WPS traffic is the normal benign reading.

## Benign causes

- **A client with a genuinely wrong PIN retrying hard.** This is the one benign trigger the research names: it "is also what the first minute of an attack looks like, and is why the rule reports attempts rather than claiming a compromise" [1]. Distinguish by duration and repetition - a human gives up; a tool runs for hours.
- **A misconfigured provisioning script.** The T1110 doc notes a backup job or automation with a stale credential is the single most common benign trigger for the whole brute-force family [11]; for WPS this is rarer (WPS is interactive) but a reconnecting IoT device with a cached bad PIN can produce a low, steady cycle rate.
- **A channel-hopping receiver's partial view.** sloth may hear only some of the EAP exchange. This under-counts, never over-counts (the ring saturates low by design, src/wps_track.c:184), so it cannot manufacture a false positive - only miss a real one, which is what `WPS_LOCKOUT_CYCLING` exists to backstop.

## Assessment

**Severity.** CRIT is correct. The threshold is above any human rate, the NACK-after-M3 filter removes the benign refusal class, and success yields the network passphrase and AP configuration control [1]. A false positive costs an operator a WPS-disable they should perform anyway.

**Prevalence.** The exposure was near-universal at disclosure - CISA TA12-006A: "Most Wi-Fi access points that support Wi-Fi Protected Setup (WPS) are affected" [8]; Viehboeck: "WPS is activated by default on all devices I had access to" [4]. Fourteen years on, lockout and disabled external-registrar PIN are common mitigations, but WPS PIN is still shipped and enabled on a long tail of consumer routers, so an AP in range exposing it is realistic.

**Noise on the reference host.** Not seen (null). The keying is tight: per attacking station, or one row per UUID-E group with the N-MAC spray collapsed to one lead (plus a per-STA row for any single rotated MAC that itself reaches the threshold - the two arms are independent). Count rises ~4/s (250 ms tick) while live. This does not fan out, and the per-frame count concern in the task prompt does not apply - the rule counts *cycles in a window*, capped at the ring size, not frames. If a lab or pentest environment generates steady WPS traffic, `--wps-pin-brute-cycles N` raises the floor. No dedupe change is warranted.

**Is the evidence sufficient to act on?** Yes. The attempt count, station, BSSID and (for the rotating shape) shared UUID-E together are a high-confidence call. First response: if the BSSID is the operator's (the detail says "YOUR network"), disable WPS external-registrar PIN now - it is the only workaround CERT offers (docs/wiki/alert-remediation.md:1266-1285) - and if the attack may have reached the full PIN, change the passphrase. If the BSSID is not the operator's, it is its owner's to change; inform them.

**Gaps.** sloth sees the attempts, never confirmed success (it has no view of whether the correct PIN was finally accepted). On a hopping radio it may see none of the EAP exchange at all, which is the reason `WPS_LOCKOUT_CYCLING` reads the same attack from the beacon side.

## Bibliography

1. research/cert/vu-723755.md - repo document citing this type (retrieved 2026-10-02), with the VU#723755 quotes and the rule's cycle-counting rationale (accessed 2026-10-27)
2. research/mitre/T1110.md - repo document; maps WPS_PIN_BRUTE to T1110.001 and tabulates the on-wire failure shape (accessed 2026-10-27)
3. docs/views/alerts.md row `WPS_PIN_BRUTE` (line 187); docs/wiki/alert-remediation.md §`WPS_PIN_BRUTE` (lines 1266-1285); docs/wiki/alerts.md:762 threshold table (accessed 2026-10-27)
4. Stefan Viehboeck, "Brute forcing Wi-Fi Protected Setup", Version 3, 26.12.2011 - https://sviehb.wordpress.com/wp-content/uploads/2011/12/viehboeck_wps.pdf (accessed 2026-10-27; text extracted locally with pdftotext - confirmed: "WPS is activated by default on all devices I had access to", the EAP-NACK-after-M4 / after-M6 half-PIN oracle, "(=11.000) attempts", "between 0.5 and 3 seconds", "less than four hours (at 1.3 seconds/attempt)", and the lockout table row "3 / 1 minutes / ... / Requirement for WSC 2.0")
5. CERT/CC VU#723755, WiFi Protected Setup (WPS) PIN brute force vulnerability - https://kb.cert.org/vuls/id/723755 (accessed 2026-10-27; confirmed quotes, CVSS 9.3, date public 2011-12-27, CVE-2011-5053, workaround = disable the external registrar; the page does NOT contain the "most ... access points" sentence - that is CISA's, [8])
6. CVE-2011-5053, MITRE CVE record - https://cveawg.mitre.org/api/cve/CVE-2011-5053 (accessed 2026-10-27; PUBLISHED, published 2012-01-06, external-registrar does not properly inform clients of failed PIN auth)
7. reaver-wps-fork-t6x - https://github.com/t6x/reaver-wps-fork-t6x (accessed 2026-10-27; README confirmed: online brute force "between 4-10 hours", `-d, --delay=<seconds>` default [1], `-l, --lock-delay=<seconds>` default [60], `-L, --ignore-locks`, `-K, --pixie-dust` / `-Z`)
8. CISA (US-CERT) Alert TA12-006A, Wi-Fi Protected Setup (WPS) Vulnerable to Brute-Force Attack, released 2012-01-06 - https://www.cisa.gov/news-events/alerts/2012/01/06/wi-fi-protected-setup-wps-vulnerable-brute-force-attack (accessed 2026-10-27; confirmed verbatim: "Most Wi-Fi access points that support Wi-Fi Protected Setup (WPS) are affected.", "Freely available attack tools can recover a WPS PIN in 4-10 hours.", solution "Depending on the access point, it may be possible to disable WPS.")
9. bully - https://github.com/aanarchyy/bully (accessed 2026-10-27; C re-implementation of the WPS PIN attack, -l lockwait 43 s, -D detectlock, -L lockignore)
10. hostapd src/ap/wps_hostapd.c, wps_pwd_auth_fail() - AP PIN lockout: lock after 3 failures, 60 s initial, doubling every 3, disabled indefinitely after 10 consecutive (read via https://raw.githubusercontent.com/latelee/hostapd/master/src/ap/wps_hostapd.c, a public mirror; accessed 2026-10-27)
11. MITRE ATT&CK T1110.001 Password Guessing - https://attack.mitre.org/techniques/T1110/001/ (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree at c5650a3.

Code (re-read `src/alerts/rules_enterprise.c:1-170`, `src/wps_track.c:120-200`, `src/wps_track.h`, `src/alerts.h:305-320`, `src/tune.c:67`, `src/alerts/engine.c`):

- `rule_file` (line 92), the snapshot under lock into a 64-slot local, `wps_track_cycles_since()` over `WPS_PIN_BRUTE_WINDOW_S` = 60 (alerts.h:313), `>= thresh` with default 5 (tune.c:67), both findings, both keys (`wpsbrute:<bssid>:<sta>` at 109 via `snprintf`; `wpsbrute-uuid` via `akey_*` at 150-154 carrying all 16 UUID-E bytes), `stas >= 2` gate, lead-only reporting, CRIT, `match_ip` NULL - all confirmed.
- NACK-after-M3-only counting confirmed at wps_track.c:133-146 (M1 re-arms at 133, `cycle_count++` at 142 only from `M3_SEEN`); corrected the two line-range citations (were 131-145 / 135-145).
- `wps_track.h` ring constants are at 38 (`MAX_WPS_SESSIONS 64`) and 45 (`WPS_CYCLE_RING 8`); corrected from 40-50.
- Guard/threshold lines corrected to 97-101 (was 99-100). `fire()` evaluation bump corrected to engine.c:478-479.
- `ALERT_SEV_CRIT = 2` (sloth.h:889), so "sev 2" is right. `tests/test_alerts.c` contains `test_wps_pin_brute_ignores_nacks_without_m3`. `wps_track_events()` and `WPS_EVT_RING 16` exist (wps_track.h:185, views/beacon.c:146).
- The UUID-E arm sums `cycles` across sessions, so its detail figure can exceed 8; the per-session saturation statement in the frontmatter is correct for the per-station arm only. Left as written since it says "per session".

Sources:

- [4] Viehboeck v3, 26.12.2011: fetched and extracted with pdftotext. Every quoted phrase confirmed. His lockout table does list "3 / 1 minutes / ... / Requirement for WSC 2.0", but his prose says it "might be a requirement in the (new) WSC Specification Version 2". Rewrote the two places that stated the WSC 2.0 lockout as fact (frontmatter severity line, "The attack") to attribute the claim to his table and record the hedge.
- [5] kb.cert.org VU#723755: confirmed lockout sentence, impact sentence, "unaware of a practical solution", CVE-2011-5053, CVSS 9.3, 2011-12-27, workaround. It does NOT contain "most Wi-Fi access points supporting WPS are affected". That sentence is CISA's; re-attributed in the frontmatter prevalence line and the Assessment, and the CERT-workaround sentence now cites [1][5] instead of [1][2][3].
- [6] CVE-2011-5053 record: PUBLISHED, 2012-01-06, description confirmed.
- [7] reaver README: "between 4-10 hours", `-d` [1], `-l, --lock-delay` [60], `-L`, `-K`/`-Z` confirmed.
- [8] CISA TA12-006A: the entry had a bare `https://www.cisa.gov/` URL. Replaced with the alert's actual URL; confirmed release 2012-01-06 and the verbatim sentences "Most Wi-Fi access points that support Wi-Fi Protected Setup (WPS) are affected." and "Freely available attack tools can recover a WPS PIN in 4-10 hours." The "4-10 hours" sentence in "The attack" now cites [8] alone.
- [9] bully README: C implementation, `-l` [43], `-D`, `-L`, `-M` confirmed.
- [10] hostapd mirror `wps_pwd_auth_fail()`: lock at `ap_pin_failures >= 3`, initial 60 s, `*= 2` when `failures % 3 == 0`, "AP PIN disabled indefinitely" at 10 consecutive - confirmed.
- [11] T1110.001 confirmed.
- research paths: `research/cert/vu-723755.md` and `research/mitre/T1110.md` exist and both name WPS_PIN_BRUTE. docs/views/alerts.md:187, alert-remediation.md:1266, wiki/alerts.md:762 and 779-784 confirmed.

Second pass, 2026-10-27, against 0d60387 (HEAD). `git diff --stat c5650a3..HEAD` touches only `web/`, `docs/assets/slothweb/`, `docs/wiki/log.md` and `docs/wiki/slothweb.md`, so every source line cited above was re-read on the current tree and is unchanged: `src/alerts/rules_enterprise.c:92-162` (snapshot 94-95, `wps_track_cycles_since` 100, `c < thresh` 101, per-STA key 109, UUID-E lead scan 121-127, `stas < 2 || cycles < thresh` 139, `akey_*` key 150-154, both `fire()` CRIT with NULL `match_ip` at 115/160), `src/wps_track.c:133-146` and `181-195`, `src/wps_track.h:38/45/50/185`, `src/alerts.h:313`, `src/tune.c:67` (default 5), `src/alerts/engine.c:478-479`, `tests/test_alerts.c:8075`.

Sources re-fetched this pass: [4] Viehboeck PDF (HEAD 200, application/pdf), [5] kb.cert.org (lockout, impact, "unaware of a practical solution", CVE-2011-5053, 9.3, 2011-12-27, external-registrar workaround; no "Most Wi-Fi access points"), [7] reaver README ("between 4-10 hours", `-d` 1 s, `-l` 60 s, `-L`, `-K`/`-Z`), [8] CISA TA12-006A (both verbatim sentences, released 2012-01-06, revised 2013-01-23), [9] bully README (C implementation, `-l` 43, `-D`, `-L`, `-M`), [10] hostapd mirror (`ap_pin_failures < 3` return, 60 s initial, `*= 2` every 3, "AP PIN disabled indefinitely" at 10 consecutive), [11] T1110.001. All resolve and support their sentences. No text changed in this pass.

Third pass, 2026-10-27, against d70d394 (HEAD; `git diff --stat 0d60387..HEAD` is `LEDGER.md` only, so the tree is the one the second pass read). Code re-read independently rather than from the earlier notes; every external source re-fetched with curl (browser User-Agent) and grepped for the quoted text.

Code: `rule_wps_pin_brute()` (rules_enterprise.c:92-163), the M1/M3/NACK state machine and ring stamp (wps_track.c:133-146), `wps_track_cycles_since()` (181-195, `have` capped at `WPS_CYCLE_RING` = 8 at 184), `WPS_PIN_BRUTE_WINDOW_S` 60 (alerts.h:313), tune default 5 / lo 1 (tune.c:67), CLI alias `--wps-pin-brute-cycles` (main.c:504), CRIT with NULL `match_ip` at 115/160, `akey_*` key at 150-154 - all re-confirmed. `>= thresh`, and `stas < 2 || cycles < thresh` (139), as stated.

Changes: (1) the lead-member scan is 119-128 (the loop through its `continue`), not 121-127 / 119-125 - the body and frontmatter disagreed with each other and with the code; both now say 119-128. (2) The "N-MAC spray is one row" claim was too strong: the per-STA loop (99-117) runs over every session regardless of the UUID-E arm, so a spray whose individual MACs each reach 5 cycles produces N per-STA rows plus the UUID-E row. Frontmatter and the noise paragraph now say so. (3) Line refs: state machine 133-146 (frontmatter said 131-145), snapshot 94-95 (was 94-96), and "slot 56" corrected to "line 56, 30th in run order".

Sources: [4] Viehboeck PDF (200; pdftotext lines 27, 289-292, 306, 398, 406, 544, 595 carry every quoted phrase), [5] kb.cert.org (200, gzip; "brute force the WPS PIN and retrieve the password ...", "many wireless routers do not implement any kind of lock out policy", "unaware of a practical solution", Date Public 2011-12-27, CVE-2011-5053, 9.3, the disable-external-registrar workaround), [6] CVE-2011-5053 (PUBLISHED 2012-01-06; EAP-NACK wording), [7] reaver README (`-d` [1], `-l` [60], `-L`, `-K`/`-Z`, "between 4-10 hours"), [8] CISA TA12-006A (all three sentences verbatim), [9] bully README (`-l` [43], `-D`, `-L`, `-M`), [10] hostapd `wps_pwd_auth_fail()` (mirror and upstream w1.fi/cgit agree: lock at `ap_pin_failures >= 3`, 60 s first, doubled when `ap_pin_failures % 3 == 0`, indefinite at 10 consecutive), [11] ATT&CK T1110.001 title confirmed. Nothing struck. research paths `research/cert/vu-723755.md` and `research/mitre/T1110.md` exist and name the type.
