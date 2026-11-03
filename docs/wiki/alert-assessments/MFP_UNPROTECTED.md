---
type: MFP_UNPROTECTED
technique: T1562.004
rule_file: src/alerts/rules_wifi_mgmt.c:439 rule_mfp_unprotected()
count_semantics: per evaluation tick, per BSSID key, for as long as the violation table holds the offender. fire() (not fire_ev()) re-asserts the key every poll (>= 4/s; POLL_MS 250 is the longest wait) while action_mfp_violations() still returns a worst offender with count > 0; one increment is one poll, NOT one unprotected frame. The detail's "N unprotected robust action frame(s)" is the offender's cumulative frame tally in g_mfpv[], which is monotonic - it is never cleared on the live path - so once a single violating frame is seen the key fires every tick thereafter and both N and the alert count only grow
severity_assessment: agree - CRIT with no ownership split is right: an unprotected robust Action frame on a BSS that advertises MFP required is either a non-conforming stack or an injection (CVE-2019-16275), and the rule states it cannot tell which rather than overclaiming
false_positive_risk: low-to-medium - the three-state MFP check (required=2, not capable=1 or off=0, not -1 "no beacon on file") removes the obvious misfires, so the residual is a genuinely non-conforming client/AP stack emitting an unprotected robust Action frame on a required BSS, which is a real finding even when it is not an attack
noise_verdict: not seen on the reference host - no rows, host is null for this type. Expected: it needs a BSS heard beaconing MFP required AND an individually addressed robust Action frame on it with the Protected bit clear, a narrow conjunction on a hopping sensor that hears most BSSIDs only part-time. Were it to fire, note that g_mfpv[] is never cleared on the live path, so a single violating frame makes the key fire every tick for the rest of the run; trend observations, not count, and read the one cited frame
prevalence: the on-air artefact of a specific, bounded vulnerability class (CVE-2019-16275, hostapd before 2.10) plus any non-conforming stack; not a volume attack and no tool mode sprays it. No fetched source quantifies a field rate, so none is claimed
tuning: [none - compile-time constants: MFP_VIOLATION_MAX_BSS 32 (src/action_snoop.h), the robustness exclusion set (Public 4 / Unprotected WNM 11 / Vendor 127) and the beacon_find_mfp()==2 gate; no --tune key, no threshold - a single qualifying frame fires it]
researched: 2026-11-03
---
## What the rule checks

`rule_mfp_unprotected()` (src/alerts/rules_wifi_mgmt.c:439-456) fires on
the BSSID that has emitted the most unprotected robust Action frames on
a BSS advertising MFP required.

- **Input.** `action_mfp_violations(&bssid, &count, &cat)`
  (src/action_snoop.c:344-358) returns the number of offending BSSIDs
  and writes the worst offender, its cumulative count and its worst
  category. An entry is created by `mfp_violation_note()`
  (src/action_snoop.c:319-341) from `action_observe_frame()` when three
  conditions all hold (src/action_snoop.c:413-416): the category is
  robust, the Protected bit is clear, the destination is individually
  addressed, and `beacon_find_mfp(bssid) == 2`.
- **Robust is an exclusion list.** `action_category_is_robust()`
  (src/action_snoop.c:299-306) treats every Action category as robust
  except the three the standard defines as never protected - Public (4),
  Unprotected WNM (11), Vendor Specific (127)
  (src/action_snoop.h:31-33). Written as an allow-list the detector
  would go quiet on every category added after it, silently; the
  exclusion list does not.
- **Individually addressed only.** `!(da[0] & 0x01)`
  (src/action_snoop.c:414). Group-addressed management frames are
  protected by BIP, which appends a Management MIC element rather than
  setting the Protected bit, so reading that bit on a broadcast answers
  a question it was never asked.
- **MFP required, not merely capable, and not "unheard".**
  `beacon_find_mfp()` (src/beacon_snoop.c:1423-1435) returns 2 required,
  1 capable, 0 off, and -1 for a BSSID with no beacon on file. Only `==
  2` qualifies. On a hopping radio most BSSIDs are unheard most of the
  time, so conflating -1 with 0 would fire on every untuned network;
  keeping the three states apart is deliberate
  (docs/wiki/action-frames.md:72-107).
- **Protected frames never reach here.** `action_observe_frame()`
  returns early on a set Protected bit, counting the frame as
  `g_protected` and parsing nothing (src/action_snoop.c:380-389); the
  violation path only ever ran on frames with the bit clear.
- **Key.** `mfpunprot:<bssid>` (line 448) - per BSSID.
- **Detail.** `<n> unprotected robust action frame(s) on <bssid>
  (category <cat>) - this BSS advertises MFP required (CVE-2019-16275)`
  (lines 450-452).
- **Severity.** `ALERT_SEV_CRIT`, unconditionally (line 454).
- **Path.** `fire()` (line 454), i.e. `fire_conf()` with confidence 0 -
  no evidence ring (this rule does not cite frames the way the flood
  rules do), no `match_ip`.
- **Table.** `g_mfpv[]` holds `MFP_VIOLATION_MAX_BSS` = 32 BSSIDs
  (src/action_snoop.h; src/action_snoop.c:315), evicting the
  least-recently-seen on overflow (src/action_snoop.c:327-337). Each
  entry's `count` only increments (src/action_snoop.c:339); the table is
  cleared only by `action_mfp_clear()`, which is not called on the live
  path, so a violation is sticky for the run.

Count semantics: `fire()` -> `fire_conf()` -> `fire_inv()` bumps
`evaluations`/`count` every re-assertion (src/alerts/engine.c:479-480)
and `observations` only when the detail or severity changed (:488-491).
Because the offender's `count` grows and the table is never cleared, the
detail changes (N rises) and the key re-fires each tick a new violating
frame arrives, then holds; it resolves `ALERT_RESOLVE_AFTER_S` = 300 s
after the last assertion (include/sloth.h:860). `POLL_MS` = 250 is the
longest wait between polls (include/sloth.h:28); the loop wakes early on
new keys, so polls per second are >= 4.

## The mechanism

On a BSS whose beacon advertises MFP required, an individually addressed
robust Action frame must be protected; one that is not "should never be
accepted. A stack that processes one is vulnerable, and a frame that
arrives that way is either a non-conforming implementation or an
injection" [1]. CVE-2019-16275 is hostapd's instance of the first being
exploitable as the second: "hostapd before 2.10 and wpa_supplicant
before 2.10 allow an incorrect indication of disconnection in certain
situations because source address validation is mishandled" (CVSS 3.1
base 6.5 MEDIUM, CWE-346, published 2019-09-12) [3]. The vendor advisory
states the mechanism: hostapd "did not perform sufficient source address
validation for some received Management frames and this could result in
ending up sending a frame that caused associated stations to incorrectly
believe they were disconnected from the network even if management frame
protection ... was ... enabled", so "an attacker in radio range ... could
inject a specially constructed unauthenticated IEEE 802.11 frame ... to
cause associated stations to be disconnected", on "All hostapd and
wpa_supplicants versions with PMF support (CONFIG_IEEE80211W=y)", fixed by
"AP: Silently ignore management frame from unexpected source address" in
v2.10 [4].

sloth fires on the on-air artefact of that shape, not on the bug itself:
a robust Action frame, individually addressed, Protected bit clear, on a
BSS whose own beacon says MFP is required [1]. It cannot tell a
non-conforming stack from an injection - "both put the same bytes on the
air - and does not claim to. What the alert says is that the frame
arrived and the BSS said it should not have" [1].

The technique label is `T1562.004`, which in current ATT&CK is "Impair
Defenses: Disable or Modify System Firewall" [2]; sloth assigns it in
`include/sloth_alerts.def` because the finding is a defeat of a defence
the BSS advertised (MFP), and the operator will look for it under
defence-impairment. The authoritative source for the finding is the CVE,
not the ATT&CK page, and it is cited as such.

This is distinct from a downgrade: MFP *capable* (not required) is the
ordinary WPA2 posture, where an unprotected Action frame is legal; that
lane is `WPA_DOWNGRADE`'s subject, which is why this rule gates on `==
2` and not on `>= 1` [1].

## Evidence that proves it

What sloth records:

- The alert detail: count, BSSID, Action category, and the explicit
  `this BSS advertises MFP required (CVE-2019-16275)`.
- The `beacon` JSONL record for the BSSID with `mfp` = 2
  (docs/wiki/jsonl-schema.md:702) - the anchor the gate read; without a
  beacon advertising required, the rule never fires, so the record is
  always present for a real finding.
- The `[a]` action view's category counts and `protected action` row
  (docs/views/deauth.md:166-178): a violation sits beside the counted
  categories, and a large `protected action` count means most robust
  Action traffic on nearby PMF BSSes is ciphertext and correctly not
  flagged.
- `sensor_health`: no counter specific to this rule; the monitor radio's
  frame totals move.

Unlike the flood rules this one cites no evidence-ring frames (it uses
`fire()`, not `fire_ev()`), so the corroborating bytes are the `beacon`
record proving MFP required plus whatever Action-frame logging the `[a]`
view retains, not a per-alert evidence pcap.

To call it real: a BSSID whose beacon genuinely advertises MFP required
(`mfp` = 2), a robust-category Action frame to an individual address with
the Protected bit clear, and - to lean toward injection over a buggy
stack - a correlated disconnect symptom (a client dropping, a
`DEAUTH_FLOOD` or `SA_QUERY_FLOOD` at the same BSSID). The category in
the detail says which robust surface was abused.

What refutes it: the BSS does not actually advertise required (a stale or
misread beacon), the frame was group-addressed (BIP, not the Protected
bit), or the category is one of the never-protected three - all of which
the gate already excludes, so a surviving firing has cleared them.

## Benign causes

- **A non-conforming client or AP stack.** A device that emits an
  unprotected robust Action frame on a required BSS without any attacker
  - a driver or firmware bug. This is a real finding (the BSS's policy
  was violated) even though no adversary is present; sloth deliberately
  does not distinguish it from injection (src/action_snoop.c:343-357
  comment; [1]).
- **A transient beacon/association race.** A frame in flight across a
  policy change could in principle arrive unprotected; the required gate
  plus individual-addressing make this narrow, and it would not sustain.
- **Not a benign cause, but a non-finding to rule out:** a group-
  addressed robust Action frame (BIP-protected, Protected bit legitimately
  clear) - already excluded by `!(da[0] & 0x01)`
  (src/action_snoop.c:414), so it never creates an entry.

Tell a bug from an injection by whether a disconnect symptom follows and
by whether the same stack misbehaves consistently (a bug) or the frames
look crafted and correlate with other 802.11w-evasion findings (an
attack).

## Assessment

**Severity.** CRIT, no ownership split, is right. The finding is that a
BSS's advertised protection was violated; that matters wherever the BSS
is, and there is no `--my-bssid` axis because the rule is about the BSS's
own policy, not about a flood aimed at the operator's gear. The detail's
refusal to claim stack-bug-versus-injection is the honest position for a
passive receiver [1].

**Prevalence.** This is the artefact of a bounded vulnerability class -
hostapd before 2.10 [3][4] and any non-conforming stack - not a volume
attack, and no tool mode sprays it. No fetched source quantifies a field
rate, so none is claimed.

**Reference host:** not seen - no rows, host is null for this type. That
is the expected result: the rule needs a conjunction that is rare on a
hopping sensor - a BSS actually heard beaconing MFP required *and* an
individually addressed robust Action frame on it with the Protected bit
clear - and on a `--hop` sensor most BSSIDs are unheard most of the time,
so `beacon_find_mfp()` returns -1 (not 2) for them and the gate never
opens. There is nothing to tune or throttle. Were it to fire, the
important operational fact is that `g_mfpv[]` is never cleared on the
live path (src/action_snoop.c has no live caller of `action_mfp_clear()`),
so one qualifying frame makes the key fire every tick for the rest of the
run and both the detail's N and the alert `count` only grow; `observations`
(which moves only when the detail changes) is the figure to trend, and the
real content is the single violating frame and the BSS's beacon, not the
fire count.

**Sufficient to act on alone?** As a CRIT it is a strong prompt, but
confirm the BSS and the frame before acting, because sloth cannot see
whether the frame was crafted or buggy. First response: confirm from the
`beacon` record that the BSS advertises MFP required (`mfp` = 2); note
the Action category; check for a disconnect symptom at the same BSSID
(client drop, `DEAUTH_FLOOD`, `SA_QUERY_FLOOD`) that would favour
injection over a stack bug. Fix: update the AP - hostapd 2.10 and later
for CVE-2019-16275 [4] - and update or replace the client stack if it is
the non-conforming source (docs/wiki/alert-remediation.md:1221-1239).
There is no threshold to tune; a single qualifying frame fires it by
design.

## Bibliography

1. research/cve/2019-16275.md - repo corpus document citing ALERT_TYPE_MFP_UNPROTECTED ("either a non-conforming implementation or an injection ... both put the same bytes on the air - and does not claim to") (source: https://nvd.nist.gov/vuln/detail/CVE-2019-16275, retrieved 2026-09-07) (accessed 2026-11-03)
2. MITRE ATT&CK T1562.004, Impair Defenses: Disable or Modify System Firewall (the technique the .def assigns this kind) - https://attack.mitre.org/techniques/T1562/004/ (accessed 2026-11-03)
3. NVD, CVE-2019-16275 ("hostapd before 2.10 and wpa_supplicant before 2.10 allow an incorrect indication of disconnection in certain situations because source address validation is mishandled"; CVSS 3.1 6.5 MEDIUM AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H; CWE-346; published 2019-09-12) - https://nvd.nist.gov/vuln/detail/CVE-2019-16275 (accessed 2026-11-03 via https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-16275)
4. hostapd security advisory 2019-7, "AP mode PMF disconnection protection bypass" (source address validation; inject an unauthenticated frame to disconnect PMF stations; fix "AP: Silently ignore management frame from unexpected source address"; v2.10) - https://w1.fi/security/2019-7/ap-mode-pmf-disconnection-protection-bypass.txt (accessed 2026-11-03)
5. Wi-Fi Alliance, "Security" (PMF "extends security protections to unicast ... and multicast ... management action frames"; "PMF is required for all new certified devices") - https://www.wi-fi.org/discover-wi-fi/security (accessed 2026-11-03)
6. docs/views/alerts.md:190 - sloth rule-table row for MFP_UNPROTECTED, incl. the required-vs-capable-vs-unheard distinction (accessed 2026-11-03)

## Verification notes

Verified 2026-11-03 against the working tree (HEAD 8ac44d5) and by
fetching every external source.

Code: `rule_mfp_unprotected()` at src/alerts/rules_wifi_mgmt.c:439-456 -
`action_mfp_violations()` (src/action_snoop.c:344-358) over `g_mfpv[]`
of `MFP_VIOLATION_MAX_BSS` 32 (src/action_snoop.c:315;
src/action_snoop.h), entries created by `mfp_violation_note()`
(src/action_snoop.c:319-341) under the three-way gate at
src/action_snoop.c:413-416 (`action_category_is_robust()`
299-306, `!f->protected_`, `!(da[0] & 0x01)`, `beacon_find_mfp(bssid)
== 2`). Protected frames bail early as `g_protected`
(src/action_snoop.c:380-389). `beacon_find_mfp()` three-state return
(src/beacon_snoop.c:1423-1435). Early return on no offender or count 0
(line 443), key `mfpunprot:<bssid>` (line 448), CRIT (line 454) via
`fire()` (not `fire_ev()`), no `match_ip`. Each entry's `count` only
increments (src/action_snoop.c:339); no live caller of
`action_mfp_clear()` in src/, so the table is sticky for the run.
`ALERT_RESOLVE_AFTER_S` 300 (include/sloth.h:860), `POLL_MS` 250 (:28).
Robust exclusions Public 4 / Unprotected WNM 11 / Vendor 127
(src/action_snoop.h:31-33).

Count semantics: `fire()` -> `fire_conf()` -> `fire_inv()` bumps
`evaluations`/`count` on every re-assertion (src/alerts/engine.c:479-480),
`observations` only on a detail/severity change (:488-491). With a
monotonic, never-cleared offender count the detail's N rises and the key
re-fires each tick a new violation arrives; the "N frames" figure is
cumulative per BSSID, the alert count per tick.

Noise arithmetic: none - host is null for this type (no rows). Nothing to
recompute.

Sources: [2] MITRE T1562.004 fetched; name "Impair Defenses: Disable or
Modify System Firewall", ID T1562.004, "Adversaries may disable or modify
system firewalls in order to bypass controls limiting network usage"
verbatim - noted explicitly in the body because the ATT&CK title does not
describe the Wi-Fi finding; the authoritative source is the CVE. [3] NVD
CVE-2019-16275 fetched via the NVD REST API; description, CVSS 3.1 6.5
MEDIUM, vector AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H, CWE-346, published
2019-09-12 all verbatim. [4] hostapd advisory 2019-7 .txt fetched; "did
not perform sufficient source address validation for some received
Management frames", stations "incorrectly believe they were disconnected
... even if management frame protection", "inject a specially constructed
unauthenticated IEEE 802.11 frame", affected "All hostapd and
wpa_supplicants versions with PMF support (CONFIG_IEEE80211W=y)", fix "AP:
Silently ignore management frame from unexpected source address" / "v2.10
or newer" all verbatim. [5] Wi-Fi Alliance security page fetched; PMF
"extends security protections to unicast (protection from eavesdropping
and forging)" and "multicast (protection from forging) management action
frames" and "PMF is required for all new certified devices" verbatim. [1]
research/cve/2019-16275.md read; `alert_kinds` lists
`ALERT_TYPE_MFP_UNPROTECTED` and the quoted sentences are in its text. [6]
docs/views/alerts.md:190 is the MFP_UNPROTECTED row.

Struck: w1.fi's cgit paths and the /security/2019-7/ directory index were
behind an Anubis bot-wall or returned only a listing, and nvd.nist.gov's
HTML detail page rendered empty; the advisory was read from its direct
.txt URL (which returned) and the CVE fields from the NVD REST API. No
claim rests on a page that did not return.
