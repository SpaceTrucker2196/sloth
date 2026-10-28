---
type: MLE_COMMON_INFO_LEN_BAD
technique: T1669
rule_file: src/alerts/rules_mle.c:52 of rule_mle_common_info_len_bad()
count_semantics: per poll tick (POLL_MS 250 ms, include/sloth.h:28) on which an MLD entry still carries a non-zero lifetime malformed_common_info_len_total; fire() bumps evaluations (= count) once per alerts_update() under the key (src/alerts/engine.c:478-479). The malformed-frame tally is in the detail (malformed_common_info_len_total, incremented once per offending frame in mle_observe(), src/mle.c:428-432), not in count.
severity_assessment: too low, arguably - WARN, same reasoning and same caveat as MLE_INVALID_LINK_ID: the value is an unauthenticated crash-shaped input (CVE-2026-58374 class), and the rule notes one frame is enough. WARN is defensible because sloth sees the frame shape, not a confirmed crash.
false_positive_risk: low - a Common Info Length under 7 cannot cover the field itself plus the mandatory 6-byte MLD MAC, and one placing Link Info past the element is self-contradictory; a conformant sender satisfies both bounds regardless of 802.11be draft revision.
noise_verdict: not seen on the reference host - host data is null. Keyed mle_common_info_len:<mld_mac> (rules_mle.c:60), one row per transmitting MLD. Sticky accumulation like the sibling rule (src/mle.c:428-432), so a repeat offender re-fires the same incident with a rising detail tally. The MLD table has no age-out (LRU eviction only, src/mle.c:369-379), so one offending frame keeps the row asserted and unresolved for the life of the process (~345,600 count/day). One key per MLD MAC: a rotating-MAC sender fans out to at most 64 live rows (SLOTH_MLD_MAX), with no sensor_health eviction tally for that table.
prevalence: new and rare in the wild - part of the same w1.fi 2026-1 advisory as MLE_INVALID_LINK_ID; CVE-2026-58374 published 2026-06-30 [5][6]; the oss-security disclosure mentions no PoC and none was found in the fetched sources [7]. Wi-Fi 7 deployment is early [14].
tuning: []
researched: 2026-10-27
---
## What the rule checks

Input is the MLD table `s->mlds[]`, populated by `mle_observe()` from `mle_parse()` on Beacons/Probe Responses (src/capture/probe.c:552) and (Re)Association Requests (src/assoc_track.c:202). The rule sits at line 64 of rules_table.c, 38th in run order.

The parser check (src/mle.c:118-137): for a Basic Multi-Link element, the MLD MAC Address is read first, from a fixed offset (`common_off + 1`, i.e. ie_body byte 4) that does not depend on the Common Info Length or the Presence Bitmap, so identity is captured safely whatever the attacker-controlled bytes claim (mle.c:118-122, with `len >= 10` guaranteeing the six bytes exist). Then `common_len = ie_body[common_off]` (byte 3) is validated:

```
if (common_len < 7 || common_off + common_len > len) {
    out->malformed_common_info_len = 1;
    out->bad_common_info_len = (uint8_t)common_len;
    sh_parse_fault_note(SH_PF_MLE_MALFORMED);
    return 1;
}
```

(src/mle.c:133-137). The floor of 7 is because Common Info Length "covers itself" plus the mandatory 6-byte MLD MAC (1 + 6 = 7); the upper bound is that the declared length must not place the start of Link Info (`common_off + common_len`) past the element's own end (`len`). Either violation is the "attacker-controlled length drives a pointer" shape, and the parser stops there - it has identity (the MAC, already read) but no safe offset to continue into Link Info [1]. Deliberately, it does **not** decode the optional Common Info subfields (EML Capabilities, MLD Capabilities, etc.), whose presence-bitmap bit positions moved across 802.11be draft revisions - asserting a bit position sloth cannot verify against the sender's draft would risk flagging legitimate hardware, so only the two bounds every conformant sender must satisfy are checked (mle.c comments, [1]).

`mle_observe()` (src/mle.c:428-432) accumulates onto the MLD entry: `malformed_common_info_len_total++`, stores `bad_common_info_len`, stamps `_last_seen`. Sticky - never cleared by a later clean frame (mle.c:419-422).

The rule (rules_mle.c:52-70) fires when `m->malformed_common_info_len_total` is non-zero. Key `mle_common_info_len:<mld_mac>` (plain `snprintf`, rules_mle.c:60). `ALERT_SEV_WARN`, `match_ip` NULL - no pcap, no evidence-ring citation. Detail: `MLD <mac> sent a Multi-Link Element with Common Info Length=<bad> (must be >=7 and fit inside the element; <total> such frame(s) seen) - CVE-2026-58374 class`. Technique `T1669` (include/sloth_alerts.def:163). No threshold, no knob.

## The attack

Same family and same CVE as `MLE_INVALID_LINK_ID`. The w1.fi 2026-1 advisory describes the problem as issues that "show up in various cases where frames including information on affiliated links are parsed and processed in both AP and STA modes" and lists eight mitigation commits spanning association, association rejection, probe/beacon scan results and reconfiguration [6]; the repo's research doc summarises that as "eight related multi-link parsing gaps" [1] - the phrase is the repo's, not the advisory's. The advisory text itself carries no CVE number; the link_id write in AP association processing is the one that received CVE-2026-58374, per the CVE record's references [5]. Two of the eight mitigation commits are Common Info length fixes - "MLD: Fix length check in common info for association failure cases" and "BSS: Fix validate of ML common info length during scan result parsing" - and the Acknowledgments credit the report of "Incorrect validation of MLE common info length" separately from the link ID reports [6]. Both of those fixes are in **wpa_supplicant**, not hostapd: 41c86a2 patches `wpas_ml_parse_assoc()` in wpa_supplicant/events.c (a Common Info length running past the end of the MLE in an association-failure response could wrap `ml_len` and read beyond the frame), and 595194d patches wpa_supplicant/bss.c scan-result parsing (a Common Info length too short for the optional fields the presence bitmap claims, a two-byte over-read) [15][16]. The party at risk from this shape is therefore a Wi-Fi 7 *client*, reading a frame from an AP or a spoofed one.

The Common Info Length field of a Basic Multi-Link Element tells a parser how far the Common Info section extends and therefore where the Link Info (per-STA profiles) begins. A parser that trusts this field without checking it against its structural floor (it must cover itself plus the mandatory MLD MAC) or against the element's actual length will compute a Link Info start that lies outside the buffer it allocated, then read from there [1][6]. That is a buffer read overflow one field over from the link_id write - the same "attacker-controlled length drives a pointer" shape [1]. The advisory's impact is "process termination due to buffer read overflow checks and memory corruption", reachable "by sending invalid Management frames without needing authentication" [6]. No credential, no association, no user interaction [5].

Mapped to T1669 (Wi-Fi Networks, Initial Access [11]): the access vector is an unauthenticated, management-frame-driven exchange, not a specific optional field. sloth detects the input class on the air, before it reaches a vulnerable parser; it cannot and does not confirm a crash (MISSION §2) [1].

## Evidence that proves it

What sloth records:

- `alert` / `alert.create` JSONL: `title MLE_COMMON_INFO_LEN_BAD`, `key mle_common_info_len:<mld_mac>`, `sev 1`, `technique T1669`, `count` = evaluations. The declared `Common Info Length` value and the lifetime count of such frames are in `detail`.
- The `wifi_mld` JSONL record for the MLD MAC - captured even from a malformed frame because the MLD MAC is read at a fixed offset before the length is validated (mle.c:118-122), so the transmitter's asserted identity is always present (docs/wiki/jsonl-schema.md:711).
- sensor_health `parse_fault_mle_malformed` - incremented on this exact path by `sh_parse_fault_note(SH_PF_MLE_MALFORMED)` (mle.c:136). This counter moving in step with the alert confirms the parser saw a bad length (docs/wiki/jsonl-schema.md:1262-1266). It rides the heartbeat, not the change-only signature.
- No pcap, no evidence-ring citation: plain `fire()`. The raw bytes are not retained; the finding rests on the declared length value in the detail.

To call it real, a reader should see a `wifi_mld` record for the same MLD MAC, a `parse_fault_mle_malformed` increment at the alert time, and a detail naming a Common Info Length below 7 or large enough to run Link Info past the element. A value of, say, 0-6 is unambiguous; a value that overshoots `len` depends on the element's own length, so the detail's number is the anchor.

What would refute it: nothing benign satisfies "Common Info Length < 7" or "Link Info starts past the element" - the research states there is "no benign reason a conformant MLD ever sends a length this shape" [1]. There is no benign fingerprint to list; the value is malformed by the standard's own structural requirements, which do not depend on the draft revision.

## Benign causes

As with the sibling rule, none produce a correct reading. The only non-adversarial explanations are instrument-side:

- **A buggy early Wi-Fi 7 implementation** emitting a non-conformant Common Info Length. Still worth surfacing as a malformed management frame, but not an attack; none is documented in the fetched sources.
- **A sloth parse error.** The parser reads the length byte directly and validates two simple bounds (mle.c:133-137), and `tests/test_mle.c` / `tests/test_mle_bss.c` build the inputs per clause, so this is low-likelihood; a single hit on known-conformant hardware warrants inspecting the capture.

Because the MLD MAC is read before the length is validated (mle.c:118-122), even a malformed frame yields identity - so a benign-but-buggy transmitter can be located and its firmware checked rather than merely counted.

## Assessment

**Severity.** WARN, matching `MLE_INVALID_LINK_ID`, on the same ground: sloth sees the crash-shaped value, not a confirmed crash, and cannot see the target's patch state. The repo's WARN-vs-CRIT line puts both "value shaped to cause an overread" rules at WARN and reserves CRIT for `MLE_SUBELEM_OVERRUN`, where the chain has already overrun its container (rules_mle.c:74-98, [1]). Defensible, but a responder should treat a hit as actionable, not informational - the input is a pre-auth memory-corruption trigger.

**Prevalence.** New and rare, same posture as the sibling. CVE-2026-58374 published 2026-06-30 [5]; the Common Info length gaps are two of the advisory's eight parsing fixes [6]; no PoC is mentioned in [7] or was found in the fetched sources; Wi-Fi 7 is early in deployment [14].

**Noise on the reference host.** Not seen (null). Sticky per MLD MAC - one key, re-firing the same incident with a rising detail tally rather than new incidents. The per-frame task concern is handled by stickiness: frames are tallied in the detail, and `count` is ticks. But the MLD table never ages entries out, so the row stays asserted and unresolved for the life of the process unless LRU-evicted (mle.c:369-379), and a rotating-MLD-MAC sender opens one row per MAC, up to 64 live (`SLOTH_MLD_MAX`); evicted rows resolve after 300 s. The eviction is not counted in sensor_health - only `parse_fault_mle_malformed` moves. Bounded and tolerable against `MAX_ALERTS` 128; no dedupe or knob added here.

**Is the evidence sufficient to act on?** To know a malformed-length frame was transmitted, yes, corroborated by `parse_fault_mle_malformed` and the `wifi_mld` identity. To know an AP crashed, no (passive receiver, MISSION §2). First response (docs/wiki/alert-remediation.md:1345+): note the MLD MAC and the declared length; update wpa_supplicant on Wi-Fi 7 clients (both Common Info fixes, 41c86a2 and 595194d, are client-side [15][16]) and hostapd on APs to versions carrying the w1.fi 2026-1 fixes (2.12); locate the transmitter. Vendor fix: the w1.fi 2026-1 mitigation commits.

**Gaps.** No retained bytes (no evidence-ring wiring), so the finding is the declared length value plus the corroborating counters, not the frame. Coverage of the advisory's two Common Info fixes is partial. sloth's upper bound (`common_off + common_len > len`) is the shape 41c86a2 fixes, but that fix is in wpa_supplicant's association-failure path, i.e. an association *response*, and sloth's MLE inputs are Beacons/Probe Responses and (Re)Association Requests only - the same shape in a beacon is caught, the one in a response is not seen. The 595194d shape (a length consistent with the element but shorter than the optional fields the presence bitmap claims) passes both of sloth's bounds and is not detected, by the deliberate choice not to decode presence-bitmap fields. Two refusals run before the length check and are false-negative paths: an element under 10 octets (mle.c:78) and an all-zero or group-addressed MLD MAC (mle.c:121-122, `mac_is_usable()` at 18-22). The parser intentionally does not decode optional Common Info subfields, so it cannot distinguish a length that is wrong-but-harmless-looking from one deliberately crafted - it reports the bound violation and stops, which is the conservative and correct behaviour.

## Bibliography

1. research/cve/2026-58374.md - repo document citing this type; the Common Info length check rationale, the "two bounds every conformant sender must satisfy regardless of draft revision", and the fixed-offset MLD MAC read (accessed 2026-10-27)
2. research/ieee/802.11be-9.4.2.312-mld-identity.md - repo MLD identity reference naming this kind (accessed 2026-10-27)
3. docs/views/alerts.md row `MLE_COMMON_INFO_LEN_BAD` (line 192); docs/wiki/alert-remediation.md §`MLE_COMMON_INFO_LEN_BAD` (1345+); docs/wiki/wifi-state-of-the-art.md:48-49; docs/wiki/jsonl-schema.md:711, 1262-1266 (accessed 2026-10-27)
5. CVE-2026-58374, MITRE CVE record - https://cveawg.mitre.org/api/cve/CVE-2026-58374 (accessed 2026-10-27; PUBLISHED 2026-06-30, CVSS 3.1 base 6.5, affected hostapd < 2.12 with CONFIG_IEEE80211BE, no credentials/auth/interaction required)
6. w1.fi security advisory 2026-1, "Missing multi-link parsing validation in wpa_supplicant and hostapd", 2026-06-05 - https://w1.fi/security/2026-1/missing-ml-parsing-validation.txt (accessed 2026-10-27, re-read as text in the second pass; "Incorrect validation of MLE common info length" is a reported-issue line in the Acknowledgments (line 46), not a section heading; mitigation commits "MLD: Fix length check in common info for association failure cases" and "BSS: Fix validate of ML common info length during scan result parsing"; fixed 2.12; the advisory does not mention a CVE number or the word "eight")
7. oss-security, hostapd OOB write in Wi-Fi 7 MLD association parsing, posted 29 Jun 2026 (archive date 2026-06-30), Abhinav Agarwal - https://www.openwall.com/lists/oss-security/2026/06/30/1 (accessed 2026-10-27; the post covers the link_id write only, mentions no PoC, and records a CVE request rather than the CVE number; it is the same advisory family via the CVE record's references [5])
11. MITRE ATT&CK T1669 Wi-Fi Networks (Initial Access) - https://attack.mitre.org/techniques/T1669/ (accessed 2026-10-27)
14. IEEE 802.11be-2024, Enhancements for Extremely High Throughput - https://standards.ieee.org/ieee/802.11be/7516/ (accessed 2026-10-27; board approval 2024-09-26, published 2025-07-22; the page's scope text does not mention multi-link operation by name)
15. hostap commit 41c86a2ebed50567c73de23c102c2bf83eb883f2, "MLD: Fix length check in common info for association failure cases" (Jouni Malinen, 2026-03-31) - https://w1.fi/cgit/hostap/patch/?id=41c86a2ebed50567c73de23c102c2bf83eb883f2 (accessed 2026-10-27; touches wpa_supplicant/events.c only, adds `sizeof(*ml) + common_info->len > ml_len` check in `wpas_ml_parse_assoc()`; message: "invalid MLE might result in ml_len wrapping around to a huge value and reading beyond the end of the buffer")
16. hostap commit 595194d0305189922a057e8ea8b743a1bd8d2d29, "BSS: Fix validation of ML common info length during scan result parsing" (Jouni Malinen, 2026-05-18) - https://w1.fi/cgit/hostap/patch/?id=595194d0305189922a057e8ea8b743a1bd8d2d29 (accessed 2026-10-27; touches wpa_supplicant/bss.c only; message: reading "two bytes beyond the end of the buffer" when MSD info and EML capabilities "were claimed to be present but were not actually included")

## Verification notes

Verified 2026-10-27 against the working tree at c5650a3.

Code (re-read `src/alerts/rules_mle.c:41-70`, `src/mle.c:80-140` and `362-435`):

- `rule_file` (52), the non-zero `malformed_common_info_len_total` predicate, WARN, `match_ip` NULL, plain `fire()`, detail text, no threshold - confirmed.
- Corrected the key line to 60 (was 61, frontmatter and body). Parser citations corrected: the MLD MAC fixed-offset read is 119-121, `common_len` read at 124, the bounds check block 133-137 (was 131-139), `sh_parse_fault_note` at 136 (was 135), so the "parser check" range is 118-137 (was 118-140). `fire()` evaluation bump corrected to engine.c:478-479.
- The quoted code block matches mle.c:133-137 verbatim. `len >= 10` guaranteeing the six MAC bytes is stated in the comment at 119. `mle_observe()` accumulation at 428-431 confirmed sticky (419-422).

Sources:

- [5] CVE record: confirmed as for the sibling entry (PUBLISHED 2026-06-30, 6.5, no credentials/auth/interaction).
- [6] w1.fi 2026-1: fetched as text; "Incorrect validation of MLE common info length" is present at line 46, but as a reported-issue line under Acknowledgments (crediting Martin Brodeur), not as a vulnerability heading - the first pass called it a heading and the second pass corrected that. Both Common Info commit titles confirmed verbatim: "MLD: Fix length check in common info for association failure cases", "BSS: Fix validate of ML common info length during scan result parsing". Impact and no-authentication sentences confirmed.
- [7] oss-security: covers the link_id write only; mentions no PoC; records a CVE request rather than the number. Reworded "no public PoC found [7]" in the frontmatter and Assessment and expanded the bibliography entry.
- [11] T1669 confirmed. [14] IEEE page: dates confirmed; struck "multi-link operation in scope" (not in the page's scope text).
- research paths: `research/cve/2026-58374.md` and `research/ieee/802.11be-9.4.2.312-mld-identity.md` both exist and both name MLE_COMMON_INFO_LEN_BAD. docs/views/alerts.md:192, alert-remediation.md:1345 (section runs to 1361), jsonl-schema.md:711 and 1262-1266 confirmed.

Second pass, 2026-10-27, against 0d60387 (HEAD). `git diff --stat c5650a3..HEAD` touches only `web/`, `docs/assets/slothweb/`, `docs/wiki/log.md` and `docs/wiki/slothweb.md`, so every source line cited above was re-read on the current tree and is unchanged: `src/alerts/rules_mle.c:52-70` (key at 60, WARN, `fire()` with NULL `match_ip`), `src/mle.c:118-137` (bounds check, `sh_parse_fault_note` at 136), `src/mle.c:419-432`, `src/mle.c:369-379`, `include/sloth.h:28`, `src/alerts/engine.c:478-479`, `src/alerts/rules_table.c:64`, `include/sloth_alerts.def:163`.

Sources re-fetched this pass: [5] CVE record (PUBLISHED 2026-06-30, CVSS 3.1 6.5, references include the advisory, two fix commits and the oss-security post), [6] advisory (curl, 3,704 bytes), [7] oss-security (no PoC; CVE requested under a CAN identifier, no CVE number), [11] T1669, [14] IEEE page - all resolve and support their sentences.

Changes in this pass: (1) "The attack" opened by quoting "eight related multi-link parsing gaps" as the advisory's words with [6]; the advisory does not contain "eight" and does not carry a CVE number. The phrase is `research/cve/2026-58374.md:20` and is now attributed to [1]; the advisory's own sentence is quoted instead, and the CVE-to-link_id linkage now cites the CVE record [5]. (2) Bibliography [6] and the first-pass note corrected: the common-info line is an Acknowledgments entry, not a heading. No change to frontmatter, thresholds, key or noise arithmetic.

Third pass, 2026-10-27, against d70d394 (HEAD; `git diff --stat 0d60387..HEAD` is `LEDGER.md` only, so the tree is the one the second pass read). Code re-read independently rather than from the earlier notes; every external source re-fetched with curl (browser User-Agent) and grepped for the quoted text.

Code: `rule_mle_common_info_len_bad()` (rules_mle.c:52-70; key 60, WARN, NULL `match_ip`, plain `fire()`), the bounds check (mle.c:133-137, `sh_parse_fault_note` at 136, early `return 1` so `mle_observe()` still runs), the fixed-offset MLD MAC read (121) and its `len < 10` guard (78), `mle_observe()` accumulation (428-432) - all re-confirmed. MLE inputs: Beacon/Probe Response at src/capture/probe.c:552-553 and (Re)Association Request at src/assoc_track.c:202-203; no association-response path.

Changes: (1) **Substantive - who is at risk.** Fetched both Common Info fix commits as patches from w1.fi/cgit: each touches only wpa_supplicant (events.c, bss.c). The entry's attack section treated the shape as an AP-side bug in the CVE-2026-58374 family; it now says the two Common Info fixes are client-side and names what each fixes, with new sources [15][16]. The first-response line now says to update wpa_supplicant on Wi-Fi 7 clients as well as hostapd. (2) **Coverage gap.** 595194d's shape (length too short for claimed optional fields) passes sloth's two bounds, and 41c86a2's shape lives in association responses, which sloth does not parse for MLEs. Added to Gaps, with the two pre-check refusals (`len < 10`, unusable MLD MAC). (3) Same resolution/fan-out correction as MLE_INVALID_LINK_ID: no MLD age-out, so the row never resolves while held; rotating MACs fan out to 64; no sensor_health eviction tally. The old "lands in `evict`" line was wrong. Rewrote frontmatter noise_verdict and the Assessment noise paragraph. (4) "slot 64" corrected to "line 64, 38th in run order".

Sources: [5] CVE record, [6] advisory (two Common Info commit titles at lines 83/86; "Incorrect validation of MLE common info length" at line 46; no "eight", no CVE number, no CVSS), [7] oss-security (link_id only, CVE requested, no PoC), [11] T1669, [14] IEEE page - all confirmed as described. [15][16] added. Nothing struck. research paths `research/cve/2026-58374.md` (2 hits) and `research/ieee/802.11be-9.4.2.312-mld-identity.md` (1 hit) exist and name the type.
