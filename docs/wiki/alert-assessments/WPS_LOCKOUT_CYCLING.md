---
type: WPS_LOCKOUT_CYCLING
technique: T1110.001
rule_file: src/alerts/rules_enterprise.c:176 of rule_wps_lockout_cycling()
count_semantics: per poll tick (POLL_MS 250 ms, include/sloth.h:28) on which an AP still shows >= threshold completed AP-Setup-Locked locked->unlocked cycles inside the trailing 1 h window; fire() bumps evaluations (= count) once per alerts_update() under the key (src/alerts/engine.c:478-479). The windowed cycle number is in the detail, read from an 8-slot transition ring (src/beacon_snoop.c:1083-1094), so the detail saturates at 8.
severity_assessment: agree - WARN for a third-party AP, CRIT for the operator's own (--my-bssid). The sawtooth is strong evidence of a brute force seen from the victim side, but the lock bit alone cannot prove intent, so CRIT is reserved for the network the operator can actually act on.
false_positive_risk: medium - a guest fat-fingering the PIN twice, or firmware that locks on any failure and releases on a short timer, produces the same two cycles per hour; the threshold of 2 is deliberately low because the observable is cheap to see and expensive to miss.
noise_verdict: not seen on the reference host - host data is null. Keyed wpslockout:<bssid> (rules_enterprise.c:189), one row per AP, count rising ~4/s while the condition holds. Not noisy - one key per locking AP, no fan-out. Threshold tunable with --wps-lockout-cycles / tune wps.lockout_cycles (default 2, src/tune.c:68).
prevalence: narrower than it looks - the rule only fires on APs that DO implement the lockout CERT says many lack [1], and of those only on APs that advertise the unlocked state explicitly (AP Setup Locked = 0x00). hostapd, the base of most Linux/OpenWrt APs, emits attribute 0x1057 only while locked and omits it when unlocked [13]; sloth reads omission as unknown and records no transition, so a hostapd AP's sawtooth is never counted. Where both conditions hold, an active WPS_PIN_BRUTE produces the sawtooth even when no EAP frame was heard.
tuning: [--wps-lockout-cycles, tune wps.lockout_cycles]
researched: 2026-10-27
---
## What the rule checks

Input is the beacon table `s->beacon_aps[]`. Each `beacon_ap_t` keeps an 8-slot ring of AP-Setup-Locked transitions (`WPS_LOCK_RING` = 8, include/sloth.h:1296). The WPS IE attribute 0x1057 (`ATTR_AP_SETUP_LOCKED` [12]) is parsed in `src/beacon_snoop.c:641-643` into `wps_locked` with the convention 0=unknown, 1=unlocked, 2=locked (include/sloth.h:1501). On every beacon, `wps_lock_note()` records a transition **only between two known states** - a beacon that omits the attribute (unknown) records nothing, so the retained transitions strictly alternate (src/beacon_snoop.c:1047-1060). A completed `locked(2) -> unlocked(1)` step increments the lifetime `wps_lock_cycles` (src/beacon_snoop.c:1059).

The consequence of "omitted = unknown" is a detection gap, not just a noise guard. An AP that signals "unlocked" by dropping the attribute rather than sending it with value 0x00 never produces a known `unlocked` state after its first lock: the beacon parser leaves `wps_locked` at 0 for that frame, `wps_lock_note()` returns early, and the stored state stays `2` (src/beacon_snoop.c:1196-1197, 1484-1485). hostapd is such an AP - `wps_build_ap_setup_locked()` writes 0x1057 only `if (wps->ap_setup_locked && wps->ap_setup_locked != 2)`, always with value 1 [13] - so on hostapd-based APs this rule cannot fire however many times the AP locks and releases. The repo's tests build the unlocked beacon with an explicit `0x10 0x57 0x00 0x01 0x00` (tests/test_beacon_snoop.c:855) and do not cover the omitted form.

The rule (line 57 of rules_table.c, 31st in run order) walks the beacon table; for each AP with `wps_lock_cycles > 0` (cheap reject) it calls `wps_lock_cycles_in_window(a, now, WPS_LOCKOUT_WINDOW_S)`, which counts every `-> unlocked` transition in the ring inside the last `WPS_LOCKOUT_WINDOW_S` = 3600 s (src/alerts.h:315, src/beacon_snoop.c:1083-1094), and fires when that is `>= alerts_wps_lockout_cycles()` (default 2; src/alerts/rules_enterprise.c:177-184).

Key `wpslockout:<bssid>` (plain `snprintf`, rules_enterprise.c:189). Severity is CRIT when `ownership_is_my_bssid(a->bssid)` else WARN (rules_enterprise.c:197-198). Detail: `<c> WPS lockout cycles on <bssid> (SSID <ssid,32>) in 1h - AP is repeatedly locking out registrar attempts, VU#723755[ - YOUR network]`. `match_ip` is NULL - no pcap, no evidence-ring citation. Technique `T1110.001` (include/sloth_alerts.def:157). An AP that locks once and stays locked produces no `locked->unlocked` step and never fires - that is a configured posture, not an attack. The count threshold is tunable; the 1 h window is not (docs/wiki/alerts.md:779-784).

Window arithmetic is worth stating: `wps_lock_cycles_in_window()` counts every `-> unlocked` transition inside the window, not every locked->unlocked *pair*, so an `unlocked` whose preceding `LOCKED` has aged out of the 8-slot ring still counts - correctly, because the AP really did unlock then (docs/views/beacons.md:159-166).

## The attack

This is the same attack as `WPS_PIN_BRUTE` (CVE-2011-5053 / CERT VU#723755 [1][5]), read from the victim AP instead of from the attacker's station. CERT's text is that "many wireless routers do not implement any kind of lock out policy for brute force attempts" [1][5]; Viehboeck's lockout table lists "3 attempts / 1 minute" as the WSC 2.0 certification requirement, with his prose hedging that it "might be a requirement" in WSC 2.0 - the spec text itself was not read [4]. On an AP that implements it, a brute force shows up as the AP repeatedly entering the AP-Setup-Locked state and releasing on a timer - a sawtooth on the lock bit. hostapd's lockout, for example, starts at 60 s and doubles every 3 further failures until it disables the AP PIN entirely after 10 consecutive failures [10]; a tool like `reaver` (`--lock-delay`, default 60 s) or `bully` (`-l`/`--lockwait`, 43 s; `-D`/`--detectlock`) waits out each lock and resumes, re-triggering it [7][9].

Why read it this way at all: the AP-Setup-Locked bit rides **every beacon**, which a channel-hopping passive receiver hears continuously, while the EAP-WSC exchange that `WPS_PIN_BRUTE` counts is a brief unicast burst the same receiver will usually miss [1][2]. So this rule fires on attacks whose individual PIN attempts were never observed - it is the backstop for `WPS_PIN_BRUTE`'s blind spots. The two together are "the same attack seen from the attacker's side and from the victim's" [2].

## Evidence that proves it

What sloth records:

- `alert` / `alert.create` JSONL: `title WPS_LOCKOUT_CYCLE` (note the title string is `WPS_LOCKOUT_CYCLE`, the enum/type is `WPS_LOCKOUT_CYCLING`; rules_enterprise.c:199), `key wpslockout:<bssid>`, `sev 1` (WARN) or `2` (CRIT on own BSSID), `technique T1110.001`, `count` = evaluations. The windowed cycle count and SSID are in `detail`.
- The `beacon` JSONL record for the BSSID: `wps_locked` (0/1/2), `has_wps`, `wps_state`. `wps_locked` is sticky: it holds the value from the most recent beacon that *carried* attribute 0x1057, and a beacon omitting it leaves the old value in place (src/beacon_snoop.c:1197, 1485). The "live, not sticky" note at docs/wiki/jsonl-schema.md:700 belongs to `wps_config_methods`/`wps_device_pwd_id`, not to this field - so on an AP that omits the attribute when unlocked, the record keeps saying `2` after the AP has released.
- The **WPS ACTIVITY** block on the Beacons detail screen (`b`, then Enter on the AP) renders the same ring the rule reads, through the same `wps_lock_cycles_in_window()`: lifetime cycle count, windowed count against the threshold, and the retained locked/unlocked timeline with a relative age per transition (docs/views/beacons.md:131-166, docs/wiki/alerts.md:768-776). The alert figure and the screen figure are one number by construction.
- No pcap: `match_ip` NULL. The beacons themselves are the evidence, summarised in the ring, not captured.
- sensor_health: `evict_beacon_ap` if the beacon table is thrashing.

To call it real, a reader should see the alternating sawtooth on the timeline (locked, unlocked, locked, unlocked...) at a cadence consistent with a lock timer (tens of seconds to minutes), ideally with a matching `WPS_PIN_BRUTE` on the same BSSID if any EAP was heard. The lifetime cycle count climbing steadily over an hour, rather than two isolated cycles, raises confidence.

What would refute it: two cycles spread across an afternoon (a human mis-typing the PIN twice), or a firmware that locks and releases quickly on any single failure. The timeline distinguishes these - an attack sawtooths densely and continuously; a benign cause shows two sparse teeth.

## Benign causes

- **A guest fat-fingering the PIN.** Two wrong attempts an afternoon apart is two cycles in different windows, but a clumsy guest in one hour can reach the threshold of 2. The research names this exactly [1][3].
- **Firmware that locks on any failure and releases on a short timer.** Some consumer APs lock aggressively, so ordinary intermittent client failures produce a low sawtooth. This is a property of the AP, not an attack; the timeline looks sparse and irregular rather than densely alternating.
- **A legitimate client reconnecting with a stale cached PIN.** Produces repeated single failures; whether that trips lockout depends on the firmware's threshold.

None of these are false in the sense the rule claims - the AP *is* cycling its lockout - but they are not attacks. The rule reports the observable honestly ("AP is repeatedly locking out registrar attempts") and leaves attribution to the operator.

## Assessment

**Severity.** The WARN/CRIT split on ownership is right. For a neighbor's AP, the operator has no standing and nothing to fix, so WARN. For `--my-bssid`, the sawtooth means someone is grinding the operator's own WPS PIN and CRIT is warranted. The low threshold (2) reflects that the lock bit is cheap to observe and a missed brute force is expensive.

**Prevalence.** By construction this only fires on APs that implement lockout - the ones CERT says "do" exist among the many that do not [1] - and, within those, only on APs that send AP Setup Locked = 0x00 when unlocked rather than omitting the attribute. hostapd omits it [13], so that subset excludes most Linux/OpenWrt APs. Where the AP does advertise both states, an active WPS brute force reliably produces the pattern. So where it fires, the underlying attack prevalence tracks `WPS_PIN_BRUTE`'s: historically near-universal WPS exposure (CISA: "Most Wi-Fi access points that support Wi-Fi Protected Setup (WPS) are affected" [8]; Viehboeck: "activated by default on all devices I had access to" [4]), now a declining tail.

**Noise on the reference host.** Not seen (null). One key per AP, count rising ~4/s while the condition holds, no fan-out. The per-frame concern in the task prompt does not apply: the rule counts *transitions in a window* capped at the 8-slot ring, not beacons. If a particular AP's firmware sawtooths benignly, `--wps-lockout-cycles N` raises the floor. No dedupe change needed.

**Is the evidence sufficient to act on?** For a direction, yes; for confirmation, pair it with the timeline. The WPS ACTIVITY screen is the corroboration path - a reader should look at the teeth before acting. First response mirrors `WPS_PIN_BRUTE`: on the operator's own AP, disable WPS external-registrar PIN; change the passphrase if the attack may have reached the full PIN (docs/wiki/alert-remediation.md:1287-1304). On a third party's AP, inform the owner.

**Gaps.** The largest one is structural: an AP that signals unlocked by omitting attribute 0x1057 (hostapd does [13]) is invisible to this rule, because omission is read as unknown and never closes a cycle. Treating omission-after-locked as unlocked would close it, at the cost of a beacon that merely lost its WPS IE counting as a release - a trade the code has not made and this entry does not make for it. Beyond that, the lock bit cannot distinguish a determined attacker from a benign aggressive-lockout firmware - only the cadence does, and only a human reading the timeline resolves it. sloth sees the lockout, never the PIN attempts behind it (that is the whole point), and never success.

## Bibliography

1. research/cert/vu-723755.md - repo document citing this type; the lockout-sentence reading and why the beacon side is visible when the EAP side is not (accessed 2026-10-27)
2. research/mitre/T1110.md - repo document; "same attack ... from the attacker's side and from the victim's" and the T1110.001 mapping (accessed 2026-10-27)
3. docs/views/alerts.md row `WPS_LOCKOUT_CYCLING` (line 161); docs/wiki/alert-remediation.md §`WPS_LOCKOUT_CYCLING` (1287-1304); docs/wiki/alerts.md:763, 768-776; docs/views/beacons.md:131-166 (accessed 2026-10-27)
4. Stefan Viehboeck, "Brute forcing Wi-Fi Protected Setup", Version 3, 26.12.2011 - https://sviehb.wordpress.com/wp-content/uploads/2011/12/viehboeck_wps.pdf (accessed 2026-10-27, pdftotext; confirmed the lockout table row "3 / 1 minutes / ... / Requirement for WSC 2.0" and the hedge "it might be a requirement in the (new) WSC Specification Version 2")
5. CERT/CC VU#723755 - https://kb.cert.org/vuls/id/723755 (accessed 2026-10-27; "many wireless routers do not implement any kind of lock out policy")
7. reaver-wps-fork-t6x - https://github.com/t6x/reaver-wps-fork-t6x (accessed 2026-10-27; README confirmed `-l, --lock-delay=<seconds>` default [60], `-L, --ignore-locks`)
8. CISA (US-CERT) Alert TA12-006A, Wi-Fi Protected Setup (WPS) Vulnerable to Brute-Force Attack, released 2012-01-06 - https://www.cisa.gov/news-events/alerts/2012/01/06/wi-fi-protected-setup-wps-vulnerable-brute-force-attack (accessed 2026-10-27; "Most Wi-Fi access points that support Wi-Fi Protected Setup (WPS) are affected.")
9. bully - https://github.com/aanarchyy/bully (accessed 2026-10-27; README confirmed `-l, --lockwait N` [43], `-D, --detectlock`, `-L, --lockignore`, `-M, --m57nack`)
10. hostapd src/ap/wps_hostapd.c, wps_pwd_auth_fail() lockout escalation (public mirror https://raw.githubusercontent.com/latelee/hostapd/master/src/ap/wps_hostapd.c; accessed 2026-10-27)
12. hostapd src/wps/wps_defs.h: ATTR_AP_SETUP_LOCKED = 0x1057 (public mirror https://raw.githubusercontent.com/latelee/hostapd/master/src/wps/wps_defs.h; accessed 2026-10-27)
13. hostap upstream src/wps/wps_registrar.c, `wps_build_ap_setup_locked()` - https://w1.fi/cgit/hostap/plain/src/wps/wps_registrar.c (accessed 2026-10-27; lines 513-523: the attribute is written only when `ap_setup_locked` is set and not 2, always with value 1; the same function is called for both the Beacon and Probe Response WPS IE. The latelee mirror's copy, lines 480-490, is identical)

## Verification notes

Verified 2026-10-27 against the working tree at c5650a3.

Code (re-read `src/alerts/rules_enterprise.c:165-200`, `src/beacon_snoop.c:636-665` and `1040-1098`, `include/sloth.h`, `src/alerts.h`, `src/tune.c:68`):

- `rule_file` (176), cheap reject on `wps_lock_cycles <= 0`, `wps_lock_cycles_in_window()` over `WPS_LOCKOUT_WINDOW_S` = 3600 (alerts.h:315), `>= thresh` default 2 (tune.c:68), ownership-split severity, `match_ip` NULL, title string `WPS_LOCKOUT_CYCLE` - all confirmed.
- Corrected the key line to 189 (was 206, in both frontmatter and body), the severity expression to 197-198 (was 196-199), and the title string line to 199 (was 198).
- `wps_lock_note()` confirmed at beacon_snoop.c:1052-1060: records only between known states, `wps_lock_cycles++` at 1059 on 2->1. `wps_lock_cycles_in_window()` at 1083-1094 counts `wps_lock_to[i] == 1` inside the window, as the "Window arithmetic" paragraph says. Attribute 0x1057 parse corrected to 641-643 (was 642-644); the 0=unknown/1=unlocked/2=locked convention is at sloth.h:1501, `WPS_LOCK_RING 8` at 1296.
- `fire()` evaluation bump corrected to engine.c:478-479.

Sources:

- [4] Viehboeck: table row confirmed by pdftotext, with the prose hedge "might be a requirement" also present. Rewrote the "WSC 2.0 certification later required" sentence in "The attack" to attribute it to his table and record the hedge; expanded the bibliography entry.
- [5] CERT: lockout sentence confirmed verbatim. Added [5] beside [1] where it is quoted.
- [7] reaver, [9] bully, [10] hostapd lockout escalation, [12] `ATTR_AP_SETUP_LOCKED = 0x1057` in the wps_defs.h mirror - all confirmed.
- The Assessment's "historically near-universal WPS exposure [3][4]" leaned on [3] (repo docs) for the "most access points" claim. Re-sourced to CISA TA12-006A, added as [8] (the number this entry family uses for it), with the verbatim sentence.
- Bibliography numbering skips 6, 8 (now present), 11: the gaps are the shared numbering with WPS_PIN_BRUTE and are left so cross-references between the two entries line up.
- research paths: `research/cert/vu-723755.md` and `research/mitre/T1110.md` exist and both name WPS_LOCKOUT_CYCLING. docs/views/alerts.md:161, alert-remediation.md:1287, views/beacons.md:131-166 confirmed.

Second pass, 2026-10-27, against 0d60387 (HEAD). `git diff --stat c5650a3..HEAD` touches only `web/`, `docs/assets/slothweb/`, `docs/wiki/log.md` and `docs/wiki/slothweb.md`, so every source line cited above was re-read on the current tree and is unchanged: `src/alerts/rules_enterprise.c:176-199` (cheap reject 180, window count 181, `c < thresh` 182, key 189, ownership split 197-198, title `WPS_LOCKOUT_CYCLE` 199, NULL `match_ip`), `src/beacon_snoop.c:641-643` (0x1057), `1052-1060` (`wps_lock_note`, cycles++ on 2->1), `1083-1094` (`wps_lock_to[i] == 1` in window), `include/sloth.h:1296/1501`, `src/alerts.h:315` (3600), `src/tune.c:68` (default 2), `src/alerts/engine.c:478-479`.

Sources re-fetched this pass: [4] Viehboeck PDF (HEAD 200), [5] kb.cert.org (lockout sentence verbatim), [7] reaver, [8] CISA TA12-006A, [9] bully, [10] hostapd `wps_pwd_auth_fail()`, [12] `ATTR_AP_SETUP_LOCKED = 0x1057` in the wps_defs.h mirror. All resolve and support their sentences. No text changed in this pass.

Third pass, 2026-10-27, against d70d394 (HEAD; `git diff --stat 0d60387..HEAD` is `LEDGER.md` only, so the tree is the one the second pass read). Code re-read independently rather than from the earlier notes; every external source re-fetched with curl (browser User-Agent) and grepped for the quoted text.

Code: `rule_wps_lockout_cycling()` (rules_enterprise.c:176-200), cheap reject 180, window count 181, `c < thresh` 182, key 189, ownership split 197-198, title `WPS_LOCKOUT_CYCLE` 199; `wps_lock_note()` (beacon_snoop.c:1052-1060), `wps_lock_cycles_in_window()` (1083-1094), the 0x1057 parse (641-643: value 0x01 -> 2, any other value -> 1, absent -> 0), `WPS_LOCK_RING` 8, `WPS_LOCKOUT_WINDOW_S` 3600, tune default 2 - all re-confirmed. Since transitions are only recorded between distinct known states, every `-> unlocked` slot the window counts was preceded by a `locked`, so the windowed count and the lifetime `wps_lock_cycles` measure the same thing.

Changes: (1) **Substantive - new detection gap.** Traced who calls `wps_lock_note()` (beacon_snoop.c:1196, 1484) and what the beacon parser does with an absent attribute: it leaves `wps_locked` 0, which `wps_lock_note()` ignores, and the stored state is only overwritten by a non-zero value (1197, 1485). Fetched hostapd's `wps_build_ap_setup_locked()` from upstream and from the mirror: it emits 0x1057 only while locked. So a hostapd AP's release is never seen and the rule cannot fire on it. Added to "What the rule checks", the frontmatter prevalence, the Assessment's prevalence paragraph and Gaps, with new source [13]. No code changed; whether to treat omission-after-locked as unlocked is a design decision for the rule's owner. (2) The Evidence bullet said `wps_locked` in the `beacon` record "reflects only the most recent beacon (live, not sticky)". Wrong for this field: it is sticky across beacons that omit the attribute (1197/1485). The jsonl-schema.md:700 parenthetical it cited describes `wps_config_methods`/`wps_device_pwd_id`. Rewritten. (3) "slot 57" corrected to "line 57, 31st in run order".

Sources: [4] Viehboeck PDF (lockout-table row "Requirement for WSC 2.0" at pdftotext line 544 with "3" / "1 minutes" beside it; the hedge "it might be a requirement in the (new) WSC Specification Version 2" at 595), [5] kb.cert.org ("many wireless routers do not implement any kind of lock out policy for brute force attempts."), [7] reaver README (`-l, --lock-delay` [60], `-L, --ignore-locks`), [8] CISA (verbatim), [9] bully README (`-l` [43], `-D`, `-L`, `-M`), [10] hostapd `wps_pwd_auth_fail()` (upstream and mirror: 60 s, doubled when `ap_pin_failures % 3 == 0`, indefinite at 10 consecutive), [12] wps_defs.h 0x1057 - all confirmed. [13] added. Nothing struck. research paths `research/cert/vu-723755.md` (lists the kind in `alert_kinds`) and `research/mitre/T1110.md` exist and name the type.
