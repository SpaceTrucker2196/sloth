---
type: WPS_PBC_RACE
technique: T1557
rule_file: src/alerts/rules_enterprise.c:220 of rule_wps_pbc_race()
count_semantics: per poll tick (POLL_MS 250 ms, include/sloth.h:28) on which an AP advertising Device Password ID 0x0004 (Push Button) still has > threshold distinct live unfinished WSC sessions inside the trailing 120 s walk time; fire() bumps evaluations (= count) once per alerts_update() under the key (src/alerts/engine.c:478-479). The concurrent-enrollee number is recomputed each tick and carried in the detail, not in count.
severity_assessment: agree (CRIT) - WSC itself defines concurrent PBC sessions as an unresolvable condition the registrar MUST abort on (config error 12, WPS_CFG_MULTIPLE_PBC_DETECTED [12]), so sloth is reporting a protocol error state, not inferring intent. Caveat: what sloth counts is any unfinished WSC session to the BSSID, not specifically a PBC enrollee (the session table carries no Device Password ID), so the count approximates the protocol's overlap condition rather than reproducing it.
false_positive_risk: medium - two household members pressing WPS at the same moment is indistinguishable from an attacker racing the window; the protocol cannot tell them apart either, which is why its answer is to abort. Firing above 2 rather than at 2 keeps the ordinary two-party case quiet. A second source: any concurrent WSC PIN sessions to the AP (a reaver run, or a rotating-MAC spray) count toward `live` if they land while the PBC window is open, because the session count does not check the enrollee's method.
noise_verdict: not seen on the reference host - host data is null. Keyed wpspbc:<bssid> (rules_enterprise.c:245), one row per AP with the window open, count rising ~4/s while the race persists. Not noisy - gated on a non-sticky beacon attribute that is only present during the 120 s window, and on >2 concurrent enrollees, so it cannot fire unless a real overlap is live. Threshold tunable with --wps-pbc-concurrent / tune wps.pbc_concurrent (default 2, fires above; src/tune.c:69).
prevalence: low opportunistically, deliberate with tooling - PBC is a narrow 120 s window requiring physical proximity; a drive-by race is rare, but the condition is trivially manufactured by someone in range who wants onto the network.
tuning: [--wps-pbc-concurrent, tune wps.pbc_concurrent]
researched: 2026-10-27
---
## What the rule checks

Two inputs, both already parsed: the beacon table `s->beacon_aps[]` and the WPS session table (`wps_track_snapshot()` into a 64-slot local, src/alerts/rules_enterprise.c:221-224). The rule sits at line 58 of rules_table.c, 32nd in run order.

The beacon gate: for each AP whose `wps_device_pwd_id == WPS_DEV_PWD_ID_PBC` (0x0004, src/beacon_snoop.h:50; `ATTR_DEV_PASSWORD_ID` 0x1012 / `DEV_PW_PUSHBUTTON` 0x0004 [12], parsed at src/beacon_snoop.c:657-660). This value is deliberately non-sticky - it reflects only the most recent beacon (include/sloth.h:1508-1512, docs/wiki/jsonl-schema.md:700) - because the walk-time window has to be open *now* for a race to be possible; a latched flag would turn every later session into a false finding (src/alerts/rules_enterprise.c:211-218).

Then the concurrency count (rules_enterprise.c:230-238): over the session table, count sessions where `bssid` matches, `state != WPS_S_DONE` (a finished registration is enrolled, not racing), and `last_seen >= now - WPS_PBC_WALK_TIME_S` (120 s; src/alerts.h:317). Fire when `live > alerts_wps_pbc_concurrent()` (default 2; note the comparison is strictly greater, so the default fires on the *third* concurrent enrollee; rules_enterprise.c:238).

What `live` does **not** check: the session's own registration method. `wps_session_t` keeps BSSID, STA, UUID-E, a coarse state and timestamps (src/wps_track.h), but no Device Password ID from the enrollee's M1, so the PBC gate is the AP's beacon only. Any session that is not `WPS_S_DONE` and was heard inside 120 s counts - including `IDLE` (an EAP-WSC exchange seen before M1), `NACKED`, and PIN-method sessions. "Concurrent PBC enrollees" in the detail is therefore the rule's reading, not something the session table proves; a PIN brute force, single-MAC or rotating, aimed at an AP during its PBC window would be counted the same way.

Key `wpspbc:<bssid>` (plain `snprintf`, rules_enterprise.c:245). `ALERT_SEV_CRIT` always (rules_enterprise.c:251), `match_ip` NULL - no pcap, no evidence-ring citation. Detail: `<live> concurrent WPS PBC enrollees at <bssid> (SSID <ssid,32>) in the 120s walk time - session overlap, registrar must abort[ - YOUR network]`. Technique `T1557` (include/sloth_alerts.def:159). The count threshold is tunable; the 120 s walk time is fixed by the WSC protocol and is not a flag - "a knob that moved the walk time would be measuring something the protocol does not do" (docs/wiki/cli-reference.md:272, docs/wiki/alerts.md:779-784).

## The attack

WPS Push-Button Configuration (PBC) authenticates by physical proximity and nothing else. Pressing the button on the AP opens a window - the WSC "walk time", fixed at 120 s (`WPS_PBC_WALK_TIME` in the WFA reference implementation [6][12]) - during which any enrollee in RF range can register with no secret involved [6]. The only thing between an attacker and the network is that they must be present during the window and that the owner is expected to notice a second device enrolling [6].

WSC bounds this with the session-overlap rule: a registrar that sees PBC enrollees from more than one device MUST abort, because it cannot tell which belongs to the person who pressed the button. The protocol carries a Configuration Error for it - 12, "Multiple PBC sessions detected" (`WPS_CFG_MULTIPLE_PBC_DETECTED` [12]), surfaced by the event `WPS_EV_PBC_OVERLAP` in hostapd, which sets `pbc_status = WPS_PBC_STATUS_OVERLAP` [10]. Overlap is not a warning in WSC; it is an unrecoverable condition [6].

So more than one *other* enrollee racing the person at the button is an abort condition by the protocol's own account. `mdk4` is the tool the repo cites for manufacturing it - the research doc [1] and the rule's own comment (rules_enterprise.c:211) both say "`mdk4 w`" - but the README's `w` mode is "WIDS Confusion", and none of its documented modes (b/a/p/d/m/e/s/w/f/x) mentions WPS or PBC [13]. The attribution to a specific mdk4 mode is therefore unsupported by the tool's own documentation; the overlap would have to be produced by injecting concurrent WSC enrollee sessions, not by a named flag. The attacker's gain, uniquely in the T1557 family, is to end up *inside* the WLAN as an enrolled station rather than beside it as a rogue AP [11]: winning the race enrols the attacker's device onto the real network.

## Evidence that proves it

What sloth records:

- `alert` / `alert.create` JSONL: `title WPS_PBC_RACE`, `key wpspbc:<bssid>`, `sev 2`, `technique T1557`, `count` = evaluations. The live enrollee count and SSID are in `detail`.
- The `beacon` JSONL record for the BSSID: `wps_device_pwd_id` = `0x0004` while the window is open (live, not sticky; docs/wiki/jsonl-schema.md:700), `has_wps`, `wps_state`. A reader confirming the finding should see this field = 4 at the alert timestamp and absent/zero before and after.
- The `[b]` WPS detail screen shows the per-session opcode timelines for the BSSID - the concurrent sessions the count summed.
- No pcap: `match_ip` NULL. The WSC frames are kept only as the opcode summary.
- sensor_health: `evict_wps_session` if the session table is pressured by many concurrent enrollees.

To call it real, a reader should see: the AP's beacon advertising Device Password ID 0x0004 (the window genuinely open) **and** three or more distinct stations with live unfinished WSC registrations against that BSSID inside the 120 s. The combination is the finding - a single enrollee, or sessions outside the walk time, do not qualify.

What would refute it as an attack: the window being open with exactly the owner's one device plus one expected device (two enrollees - below the strictly-greater-than-2 threshold), or sessions that reached `WSC_Done` (enrolled, excluded), or sessions last heard more than 120 s ago (concurrency is the whole finding; stale sessions are excluded).

## Benign causes

- **Two household members pressing WPS at the same moment.** This is the canonical benign trigger, and the protocol cannot distinguish it from an attacker either - which is precisely why its answer is to abort [6][3]. Firing *above* two keeps the ordinary two-party case (owner + one guest device) quiet.
- **A device retrying enrolment while the owner's device is also mid-enrol.** Same shape; resolves itself when the overlap aborts and one device retries alone.
- **PIN-method sessions during the PBC window.** Not benign in the sense of harmless, but not a PBC race either: the session count does not check the enrollee's method, so three or more concurrent WSC PIN sessions (for example a `WPS_PIN_BRUTE` spray from rotating MACs) to an AP whose beacon is advertising PBC fire this rule too. A concurrent `WPS_PIN_BRUTE` on the same BSSID is the tell.

There is no clean fingerprint separating benign overlap from a malicious race, by design - the indistinguishability is the reason the protocol aborts. The honest finding is "session overlap", not "attack confirmed", and the detail says exactly that ("registrar must abort").

## Assessment

**Severity.** CRIT is correct and unusually well-grounded: WSC itself treats the observed condition as unresolvable and mandates an abort [6][12], so sloth is reporting a protocol error state rather than inferring intent. The T1557 mapping is apt because the winning enrollee ends up inside the WLAN [11].

**Prevalence.** Low opportunistically - PBC is a 120 s window needing RF proximity, so a drive-by race is uncommon. But the condition is trivial to manufacture for anyone in range who wants on the network, and the detection is cheap (two already-parsed inputs), so the rule is worth having even though it will rarely fire benignly.

**Noise on the reference host.** Not seen (null). Double gating - the non-sticky PBC beacon attribute (present only during the live window) and `> 2` concurrent enrollees - means it cannot fire unless a real overlap is happening right now. One key per AP, count rising ~4/s while the race persists, no fan-out. The per-frame concern in the task prompt does not apply: the rule counts *distinct live sessions in the walk time*, not frames. `--wps-pbc-concurrent N` raises the floor if a particular environment legitimately overlaps. No dedupe change needed.

**Is the evidence sufficient to act on?** Yes for the protocol condition; the attacker's identity is not isolated (the detail names the AP, not the winning station). First response: on the operator's own network, identify and remove any device that enrolled during the window and is not the operator's; prefer not to use PBC where unknown devices are in range, since the window authenticates by proximity alone (docs/wiki/alert-remediation.md:1306-1325). There is no vendor fix - session overlap is a protocol condition the registrar must abort on.

**Gaps.** The session table does not record the enrollee's Device Password ID, so sloth cannot confirm that the concurrent sessions it counts are PBC sessions at all - only that the AP was advertising PBC while they ran. Beyond that, sloth cannot say which enrollee was the attacker, nor whether one actually completed enrolment before the abort (it sees the overlap, not the registrar's internal decision). The attack can also be run with no visible tool signature, so attribution rests entirely on the operator knowing their own devices.

## Bibliography

1. research/papers/wps-pbc-session-overlap.md - repo document citing this type; walk time, config error 12, WPS_EV_PBC_OVERLAP, and why this earns CRIT (accessed 2026-10-27)
2. research/mitre/T1557.md - repo document; maps WPS_PBC_RACE to T1557 as the one entry where the adversary ends up inside the WLAN (accessed 2026-10-27)
3. docs/views/alerts.md row `WPS_PBC_RACE` (line 188); docs/wiki/alert-remediation.md §`WPS_PBC_RACE` (1306-1325); docs/wiki/alerts.md:764, 779-784; docs/wiki/cli-reference.md:264, 272 (accessed 2026-10-27)
6. WPS PBC walk time and session overlap, as implemented in hostap src/wps/wps_defs.h (WPS_PBC_WALK_TIME 120) and wps.h (WPS_EV_PBC_OVERLAP) - https://w1.fi/cgit/hostap/plain/src/wps/wps_defs.h (canonical; on 2026-10-27 it 301-redirects to https://git.w1.fi/cgit/hostap/plain/src/wps/wps_defs.h, which served an Anubis anti-bot interstitial to the automated fetch). Read via the public mirror https://raw.githubusercontent.com/latelee/hostapd/master/src/wps/wps_defs.h, which confirmed `#define WPS_PBC_WALK_TIME 120` and `WPS_CFG_MULTIPLE_PBC_DETECTED = 12`; `WPS_EV_PBC_OVERLAP` is not in that file (it is in wps.h, per [1]) and was not re-read. The underlying WSC 2.0 specification text is behind Wi-Fi Alliance membership and is not quoted.
10. hostapd src/ap/wps_hostapd.c, hostapd_wps_event_pbc_overlap() -> WPS_PBC_STATUS_OVERLAP (public mirror https://raw.githubusercontent.com/latelee/hostapd/master/src/ap/wps_hostapd.c; accessed 2026-10-27)
11. MITRE ATT&CK T1557 Adversary-in-the-Middle - https://attack.mitre.org/techniques/T1557/ (accessed 2026-10-27)
12. hostapd src/wps/wps_defs.h: WPS_CFG_MULTIPLE_PBC_DETECTED = 12, ATTR_DEV_PASSWORD_ID = 0x1012, DEV_PW_PUSHBUTTON = 0x0004 (public mirror https://raw.githubusercontent.com/latelee/hostapd/master/src/wps/wps_defs.h; accessed 2026-10-27)
13. mdk4 - https://github.com/aircrack-ng/mdk4 (accessed 2026-10-27; README modes: b Beacon Flooding, a Authentication DoS, p SSID Probing and Bruteforcing, d Deauthentication and Disassociation, m Michael Countermeasures Exploitation, e EAPOL Start and Logoff Packet Injection, s IEEE 802.11s mesh attacks, w WIDS Confusion, f Packet Fuzzer, x Poc Testing - no mode mentions WPS or PBC)

## Verification notes

Verified 2026-10-27 against the working tree at c5650a3.

Code (re-read `src/alerts/rules_enterprise.c:203-255`, `src/beacon_snoop.h:45-52`, `src/beacon_snoop.c:657-660`, `include/sloth.h:1508-1512`, `src/alerts.h:317`, `src/tune.c:69`):

- `rule_file` (220), the beacon gate on `wps_device_pwd_id == WPS_DEV_PWD_ID_PBC` (0x0004), the three session filters (bssid match, `state != WPS_S_DONE`, `last_seen >= now - 120`), strict `live > thresh` with default 2, CRIT, `match_ip` NULL - all confirmed.
- Corrected line citations: snapshot 221-224 (was 222-224), concurrency loop 230-238 (was 231-239), fire comparison 238 (was 240), key `snprintf` 245 (was 248, frontmatter and body), Device Password ID parse 657-660 (was 658-661), the non-sticky field comment/declaration 1508-1512 (was 1508).
- `fire()` evaluation bump corrected to engine.c:478-479.

Sources:

- [6] `https://w1.fi/cgit/hostap/plain/src/wps/wps_defs.h` now 301-redirects to `git.w1.fi`, which served an Anubis anti-bot interstitial. The latelee mirror confirmed `WPS_PBC_WALK_TIME 120`, `WPS_CFG_MULTIPLE_PBC_DETECTED = 12`, `ATTR_DEV_PASSWORD_ID = 0x1012`, `DEV_PW_PUSHBUTTON = 0x0004`. `WPS_EV_PBC_OVERLAP` is not in wps_defs.h (it is in wps.h per [1]) and was not re-read; the bibliography entry now says all of this.
- [10] hostapd `hostapd_wps_event_pbc_overlap()` setting `pbc_status = WPS_PBC_STATUS_OVERLAP` confirmed.
- [11] T1557 confirmed. [12] confirmed via the same mirror.
- [13] mdk4 README: ten modes listed, `w` is "WIDS Confusion", none mentions WPS or PBC. The repo's research doc `research/papers/wps-pbc-session-overlap.md` and the rule's own comment (rules_enterprise.c:211) both assert "`mdk4 w`" manufactures the overlap; the entry's "The attack" paragraph now states that discrepancy explicitly rather than merely omitting the mode letter. That is a defect in the research doc and code comment, not in this entry, and is flagged for the repo rather than fixed here.
- research paths: `research/papers/wps-pbc-session-overlap.md` and `research/mitre/T1557.md` exist and both name WPS_PBC_RACE. docs/views/alerts.md:188, alert-remediation.md:1306, wiki/alerts.md:764 and 779-784, cli-reference.md:264 and 272 confirmed.

Second pass, 2026-10-27, against 0d60387 (HEAD). `git diff --stat c5650a3..HEAD` touches only `web/`, `docs/assets/slothweb/`, `docs/wiki/log.md` and `docs/wiki/slothweb.md`, so every source line cited above was re-read on the current tree and is unchanged: `src/alerts/rules_enterprise.c:220-252` (snapshot 221-224, PBC gate 228, session filters 231-236, `live <= thresh` continue at 238, key 245, CRIT with NULL `match_ip` 251), `src/beacon_snoop.h:50`, `src/beacon_snoop.c:657-660`, `include/sloth.h:1508-1512`, `src/alerts.h:316-317` (2, 120), `src/tune.c:69` (default 2, "fires when exceeded"), `src/alerts/engine.c:478-479`; the `mdk4 w` comment is still at rules_enterprise.c:212 and `research/papers/wps-pbc-session-overlap.md:38`.

Sources re-fetched this pass: [6]/[12] wps_defs.h mirror (`WPS_PBC_WALK_TIME 120`, `WPS_CFG_MULTIPLE_PBC_DETECTED = 12`, `ATTR_DEV_PASSWORD_ID = 0x1012`, `DEV_PW_PUSHBUTTON = 0x0004`; `WPS_EV_PBC_OVERLAP` absent from that file, as stated), [10] hostapd mirror (`hostapd_wps_event_pbc_overlap()` sets `pbc_status = WPS_PBC_STATUS_OVERLAP`), [11] T1557, [13] mdk4 README (ten modes, `w` = WIDS Confusion, none mentions WPS/PBC). All resolve and support their sentences. No text changed in this pass.

Third pass, 2026-10-27, against d70d394 (HEAD; `git diff --stat 0d60387..HEAD` is `LEDGER.md` only, so the tree is the one the second pass read). Code re-read independently rather than from the earlier notes; every external source re-fetched with curl (browser User-Agent) and grepped for the quoted text.

Code: `rule_wps_pbc_race()` (rules_enterprise.c:220-254) - snapshot 221-224, PBC beacon gate 228, the three session filters (BSSID, `!= WPS_S_DONE`, `last_seen` within `WPS_PBC_WALK_TIME_S` 120) 231-236, `live <= thresh` continue at 238, key 245, CRIT with NULL `match_ip` 251; `WPS_DEV_PWD_ID_PBC` 0x0004 (beacon_snoop.h:50), 0x1012 parse (beacon_snoop.c:657-660), `WPS_PBC_CONCURRENT` 2 / walk time 120 (alerts.h:316-317), tune default 2 "fires when exceeded" (tune.c:69) - all re-confirmed. `WPS_S_DONE` is set on WSC_Done or M8 (wps_track.c:146-148).

Changes: (1) **Substantive.** The entry described `live` as counting "PBC enrollees". The code counts any non-DONE WSC session to the BSSID; `wps_session_t` has no Device Password ID field, so PIN-method and pre-M1 sessions count too. Added a paragraph to "What the rule checks", a benign/alternate-cause bullet, a caveat on the frontmatter severity line ("approximates the protocol's overlap condition"), a second false-positive source, and a Gaps sentence. CRIT is still the rule's choice and the entry still agrees with it. (2) "slot 58" corrected to "line 58, 32nd in run order".

Sources: [6]/[12] hostapd wps_defs.h (mirror: `#define WPS_PBC_WALK_TIME 120` line 379, `WPS_CFG_MULTIPLE_PBC_DETECTED = 12` line 221, `ATTR_DEV_PASSWORD_ID = 0x1012` line 71, `DEV_PW_PUSHBUTTON = 0x0004` line 164), [10] hostapd `hostapd_wps_event_pbc_overlap()` setting `WPS_PBC_STATUS_OVERLAP` (mirror lines 734-737), [11] ATT&CK T1557 title confirmed, [13] mdk4 README (`ATTACK MODE w: WIDS Confusion`; no WPS/PBC mode) - all confirmed, and the existing note that mdk4's `w` mode does not support the repo's attribution stands. Nothing struck. research paths `research/papers/wps-pbc-session-overlap.md` (still says "`mdk4`'s `w` mode", line 38) and `research/mitre/T1557.md` exist and name the type.
