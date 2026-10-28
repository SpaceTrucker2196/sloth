---
type: MLE_CROSS_LINK_CIPHER_DOWNGRADE
technique: T1557
rule_file: src/alerts/rules_mle.c:159 of rule_mle_cross_link_cipher_downgrade()
count_semantics: per poll tick while sloth_mld_t.cross_link_cipher_downgrade_total > 0. fire() at rules_mle.c:194 is reached on every alerts_update() pass (src/poll.c:296; one per poll tick: POLL_MS = 250 ms default, include/sloth.h:28, overridable with --refresh-ms, and the loop also wakes early on an escalation (main.c:1628-1671, src/event_wake.h)) for as long as the MLD remains in the 64-slot roster; the counter is lifetime and never cleared (src/mle.c:439-446). count = ticks of residence, not frames; the per-frame figure is the "%u such frame(s) seen" field in the detail.
severity_assessment: agree - a posture mismatch being advertised, not an exploit; nothing says a client took the weak link. WARN is right; it should not go CRIT on ownership alone because on the operator's own AP it is a misconfiguration, not an attack.
false_positive_risk: low-medium - the cipher arm only fires when two Complete Per-STA Profiles each carry an explicit RSNE whose strongest pairwise suite differs; an AP that genuinely runs CCMP-128 on 2.4 GHz and GCMP-256 on 6 GHz will fire, and that is a real (if deliberate) asymmetry, not a parser error. The PMF arm was demoted to context after review found a conformant tri-band AP tripping it.
noise_verdict: not seen on the reference host - host:null. No MLD in range advertises differing pairwise suites across links with explicit RSNEs. If it fires it is one key per MLD MAC that re-fires every tick for the roster lifetime; a misconfigured AP you own sits at WARN permanently - the intended "fix the posture" nag, but worth acknowledging as such.
prevalence: no public literature beyond the clause was located for cross-link cipher asymmetry as an attack; the AiTM technique it feeds (T1557) is well documented in general [6]. The posture is likely to appear on real tri-band Wi-Fi 7 APs whose 6 GHz link is WPA3-only while legacy bands stay WPA2 - a configuration, not an adversary.
tuning: [none specific; --iface <monitor radio> / --hop; --my-bssid not consulted; --pcap-dir never applies (match_ip NULL); no evidence IDs cited]
researched: 2026-10-27
---
## What the rule checks

**Input.** `s->mlds[]` from `src/mle.c :: mle_observe()`; the per-frame finding is computed in `mle_parse()` from Basic Multi-Link Elements in Beacons / Probe Responses (`src/beacon_snoop.c`) and (Re)Association Requests (`src/assoc_track.c`).

**Condition, per frame (mle.c:208-351).** For each Per-STA Profile with STA Control bit 4 (Complete Profile, mask 0x0010) set, `info_len >= 1` and `prof_off + 2 <= slen` (mle.c:219), the STA Profile is located at `2 + STA Info Length` into the subelement body, a 2-octet Capability Information field is skipped (the Beacon/Probe Response form), and `sta_profile_rsn()` (mle.c:40-72) walks the element list: it must **tile the region exactly** (`tlv_exact`) and contain an RSNE (tag 48, ≥ 8 bytes) that `rsn_ie_parse()` accepts with RSN Capabilities present; otherwise that link yields no posture (this is how an Association Request's different prefix produces nothing rather than a wrong answer). From each qualifying link it keeps the strongest pairwise cipher rank (`rsn_cipher_rank_best`) and the MFPR bit, tracking only the weakest and strongest links and the first MFPR-set / MFPR-clear links.

After the walk, **only if** the frame has no subelement overrun and no invalid/repeated link_id (`!malformed_subelem_len && !malformed_link_id`, mle.c:308) and `rsn_links >= 2`:
- **Cipher arm (the finding):** `lo_rank < hi_rank` → `cross_link_cipher_downgrade = 1`, `downgrade_link_id = lo_rank_link`, `downgrade_peer_link_id = hi_rank_link` (mle.c:315-320).
- **PMF arm (context only, owner ruling 2026-10-13):** one link MFPR=1 and another MFPR=0 → `downgrade_pmf_mismatch = 1` with its own link pair (mle.c:346-350). This **cannot** raise the alert by itself (mle.c:322-345: a tri-band AP requiring PMF on one band and negotiating it on the others is conformant).

Links **without** an explicit RSNE are not compared - under 802.11be inheritance an omitted element means "same as the reporting AP" (mle.c:280-296) [2]. Two links whose bitmaps differ but whose *strongest* suite agrees do not fire. A cipher selector newer than IEEE 802.11-2020 Table 9-149 ranks *unknown* and never counts as weak [1]. A Non-Inheritance element (ext ID 56) is not decoded, so a link suppressing the AP's RSNE without supplying one reads as inheriting - a named false negative (mle.c:293-296) [2].

`mle_observe()` accumulates `cross_link_cipher_downgrade_total++`, the cipher arm's link pair (`downgrade_link_id`, `downgrade_peer_link_id`), and the `downgrade_pmf_mismatch` / `downgrade_cipher_mismatch` flags (mle.c:439-446). **It does not copy `pmf_mismatch_link_id` / `pmf_mismatch_peer_link_id`** into the roster entry; those fields are only zeroed when the entry is created (mle.c:377) and never written afterwards. The rule reads the roster copy (`mle_snapshot()`, mle.c:467-477), so whenever the PMF note is printed it names link_id 0 for both sides, whatever links the frame actually had. The tests that check the PMF pair (tests/test_mle.c:848-849, 912-915) assert on `mle_parse()`'s output, not on the observed entry or the alert text, so nothing catches this. This is a code defect (a two-line fix in `mle_observe()`), reported here and not fixed in this pass.

**Rule (rules_mle.c:159-197).** Fires for each roster entry with `cross_link_cipher_downgrade_total != 0`.

**Key.** `"mle_cipher_downgrade:<mld_mac>"` (rules_mle.c:168).

**Detail.** `"MLD <mac> advertises link_id <downgrade_link_id> with a weaker pairwise cipher than its sibling link_id <downgrade_peer_link_id> in the same Multi-Link element - <total> such frame(s) seen[ - also: link_id <x> negotiates PMF where link_id <y> requires it, which the standard permits and is not itself a downgrade] - IEEE 802.11be 9.4.2.312"` (rules_mle.c:177-193). The two arms carry separate link pairs because they can involve different links (rules_mle.c:169-176). **In practice the PMF clause's link pair is always `link_id 0 ... link_id 0`**: see the next paragraph.

**Severity.** WARN, unconditionally (rules_mle.c:194). No ownership gate; no confidence.

**Escalation / resolution.** None; the detail's count moves per new frame → `alert.update` at most once per 60 s; the alert persists for the MLD's roster lifetime.

**Sensor health.** None specific (not a parse fault).

## The attack

A Wi-Fi 7 AP MLD is one logical network reachable over several radios, and the Basic Multi-Link Element can carry, per link, a Complete Profile including that link's own RSNE - the ciphers and management-frame-protection stance a client would get on that link [2][5]. A client that can reach the MLD on any of its links takes whichever is offered or steered to it. If one link advertises a weaker pairwise cipher than its siblings, that link becomes the lane an adversary prefers the client use: the weakest cipher in the set bounds the protection of the association's traffic that flows over it [2].

This is a *posture* an adversary leverages rather than an action the adversary performs. ATT&CK T1557 Adversary-in-the-Middle (Credential Access / Collection) covers positioning between devices by exploiting features of protocols that control traffic flow [6]; the Evil Twin sub-technique T1557.004 is the Wi-Fi shape [6]. The fully adversarial form is a rogue AP MLD cloning a real one and advertising a weak link to draw clients; the exposure form is a legitimately configured but asymmetric AP. Tooling for the adversarial form would be an 802.11be-capable hostapd build with per-link `wpa_pairwise` settings - no purpose-built tool was located. The clause text (IEEE 802.11be-2024 §9.4.2.312 [5]) is paywalled; the structure here is from the repo's clause summary [2].

## Evidence that proves it

**What sloth records.** `alert` / `alert.create` with `title=MLE_CROSS_LINK_CIPHER_DOWNGRADE`, `sev=1`, `technique=T1557`, key and detail above; `count` = ticks (jsonl-schema.md:297, 390). The `wifi_mld` record for `mld_mac` maps link IDs to per-link addresses (jsonl-schema.md:711). The `beacon` records for each per-link BSSID carry that link's `enc`/RSN summary as seen in its own Beacon.

**No pcap, no evidence IDs.** `fire()` with `match_ip = NULL` (rules_mle.c:194-195).

**What makes it real.** In the per-link `beacon` records, the link the detail calls weaker should show the weaker RSN pairwise set in its *own* Beacon too - the Per-STA Profile and the link's own Beacon describe the same radio, so they should agree. If they do, the asymmetry is the AP's real configuration (or the rogue's): an operator-owned AP → misconfiguration; an AP not in inventory using your SSID → an evil-twin lane. If the Per-STA Profile claims a weaker cipher than the link's own Beacon advertises, the Multi-Link Element is misdescribing a sibling - the forged-element shape and much stronger evidence of an attacker. Corroborating alerts on the same MLD or links: `EVIL_TWIN`, `MLD_MAC_COLLISION`, `MLE_PR_BEACON_DIFF`, `MLE_RECONFIG_NO_MLO`, `BTM_ABUSE` steering toward the weak link.

**What refutes it.** The MLD is yours, the weak link is 2.4/5 GHz on WPA2-CCMP for legacy clients while 6 GHz runs WPA3/GCMP-256, and the per-link Beacons agree with the element: a deliberate compatibility posture, not an adversary. The alert text already frames the PMF arm this way.

## Benign causes

- **Mixed-generation band plan.** A tri-band AP keeping CCMP-128/WPA2 on legacy bands for old clients and GCMP-256 on 6 GHz fires the cipher arm legitimately. Whether that is acceptable is the operator's policy call; the remediation page says "configure every link of the MLD with the same posture" [4].
- **PMF required on one band only.** Explicitly *not* a trigger on its own since the 2026-10-13 ruling (mle.c:322-345); appears only as context. Review built a conformant tri-band input that used to fire [1].
- **Partial profiles / inheritance.** Not compared; an AP omitting the RSNE from a profile is read as "same as the AP", not as weaker (mle.c:280-296) [2].
- **Transient configuration change.** An operator changing one band's security while the AP stays up produces a short-lived asymmetry; because the counter is lifetime, the alert persists until the roster entry is evicted even after the asymmetry is gone.

## Assessment

**Severity.** WARN is right and the structure is honest: the rule reports an advertised mismatch, not an attack, and says so. I would not escalate on ownership (the owner's own asymmetric AP is a config issue, the same reasoning `QUEUE_EVICT` applies to roaming). A justified escalation would be the cipher arm plus the same SSID on an inventory-approved AP MLD whose own element does not show the asymmetry (the twin case) - that is an `EVIL_TWIN`-family join, not this rule's job.

**Prevalence.** Of the attack form, unknown and undocumented in anything this pass could reach. Of the posture form, likely common wherever WPA2 legacy bands coexist with WPA3-only 6 GHz under one MLD.

**Reference host.** `host:null`. Not seen. For a site with Wi-Fi 7 APs, a quiet rule means their links share one posture or their Per-STA Profiles omit the RSNE (inherited) - both quiet by design. If it fires on the owner's AP, it stays at WARN for the roster entry's life at ~4 evaluations/s; that is the intended nag, but a recency bound on `cross_link_cipher_downgrade_last_seen` would let a fixed AP's alert resolve.

**Is the evidence sufficient?** For the posture case, yes, for the cipher arm: the detail names both link IDs and the `wifi_mld` record maps them to BSSIDs whose own Beacons confirm the ciphers. For the attack case it is a lead, not proof - sloth cannot see which link a client chose. Recording the two cipher-suite selectors in the detail (it currently says only "weaker") would make the finding self-contained.

**Responder's first steps.** (1) Map link IDs to BSSIDs via `wifi_mld`. (2) Compare each link's own `beacon` RSN with the element's claim. (3) If the AP is yours: set the same pairwise cipher (and ideally MFPR) on every link, or accept the asymmetry knowingly [4]. (4) If it is not yours and uses your SSID: treat as a twin; locate, do not join (MISSION §2) [7].

## Bibliography

1. sloth, `docs/views/alerts.md` row `MLE_CROSS_LINK_CIPHER_DOWNGRADE` (line 195) (in-repo 2026-10-27).
2. sloth research corpus, `research/ieee/802.11be-9.4.2.312-mld-identity.md` - §"The per-link RSNE, and why absence is not weakness" and §"Where the STA Profile begins" (in-repo 2026-10-27).
3. sloth research corpus, `research/cve/2026-58374.md` - the sibling bounds rules whose faults gate this comparison (in-repo 2026-10-27).
4. sloth, `docs/wiki/alert-remediation.md` §`MLE_CROSS_LINK_CIPHER_DOWNGRADE` (line 1400) (in-repo 2026-10-27).
5. IEEE 802.11be-2024, Amendment 2: Enhancements for Extremely High Throughput (EHT), approved 2024-09-26, published 2025-07-22 - https://standards.ieee.org/ieee/802.11be/7516/ (accessed 2026-10-27). Paywalled; clause not read. Cipher-suite ranking refers to IEEE 802.11-2020 Table 9-149 - https://standards.ieee.org/ieee/802.11/7028/ (accessed 2026-10-27).
6. MITRE ATT&CK, T1557 Adversary-in-the-Middle (Credential Access, Collection), sub-techniques T1557.001-.004 - https://attack.mitre.org/techniques/T1557/ (accessed 2026-10-27)
7. sloth, `MISSION.md` §2 (in-repo 2026-10-27).

No public literature beyond the clause was located for cross-link cipher downgrade in MLO.

## Verification notes

Verified 2026-10-27 against the working tree (HEAD 0d60387) and every external source re-fetched.

**Code (all confirmed).** `rule_mle_cross_link_cipher_downgrade()` at rules_mle.c:159, `fire()` at :194 with `ALERT_SEV_WARN`, key `mle_cipher_downgrade:<mac>` at :168, detail :185-193 with the PMF note :177-184 verbatim, `match_ip NULL`. Parse side: Complete Profile mask 0x0010 (mle.c:208), MAC-present 0x0020 (:172), `sta_profile_rsn()` mle.c:40-72 with `tlv_exact` and `rsn_ie_parse()` requiring `has_caps`; gate `!malformed_subelem_len && !malformed_link_id && rsn_links >= 2` at :308-309; cipher arm :315-320; PMF arm context-only :346-350 with the 2026-10-13 ruling comment :322-345; accumulation mle.c:439-446. `rsn_cipher_rank_best()` (rsn_ie.c:146-154) returns 0 for unknown suites and the `if (rank)` at mle.c:227 keeps them out of the comparison - confirms "unknown never counts as weak". Changed: added the `prof_off + 2 <= slen` precondition (mle.c:219); line cites tightened (mle.c:208-351, 40-72, 280-296, 293-296); tick cadence now notes `--refresh-ms` and early wake.

**Sources.** [1] alerts.md:195 - confirmed, including the Table 9-149 "ranked unknown" sentence. [2] corpus page exists, names the kind, and has the inheritance and STA-Profile-offset sections - confirmed. [3] `research/cve/2026-58374.md` exists. [4] alert-remediation.md:1400 heading - confirmed. [5] IEEE 802.11be-2024 dates confirmed; the 802.11-2020 page (7028) resolves and is marked superseded by 802.11-2024, which does not affect the Table 9-149 reference. [6] T1557 (Credential Access, Collection; .001-.004) - confirmed. No source struck.

**Second pass (2026-10-27, HEAD d70d394, which differs from 0d60387 only in LEDGER.md).** Code re-read (rules_mle.c:159-197; mle.c:140-351, 362-449, 467-477; include/sloth.h:2230-2262). **Changed:** (a) **Code defect found:** `mle_observe()` copies the cipher arm's link pair and the PMF flag into the roster entry but not `pmf_mismatch_link_id` / `pmf_mismatch_peer_link_id`, so the PMF context clause in every live alert reads "link_id 0 negotiates PMF where link_id 0 requires it". The parse-side tests pass because they inspect `mle_parse()` output only. Described in "What the rule checks" and flagged in the detail paragraph and the evidence assessment. Should be filed against the repo. (b) Key cite :167 → :168; detail span :175-193 → :177-193; comment span :168-175 → :169-176. Severity, count semantics, the gate at mle.c:308-309 and `match_ip NULL` confirmed unchanged. **Repo doc drift (not this file):** docs/views/alerts.md:195 still says the rule fires when links "disagree on **MFPR** ... or on pairwise-cipher strength". Since the 2026-10-13 ruling the PMF arm cannot raise the alert by itself (mle.c:322-345), so the row overstates the trigger. Bib [1] is cited here only for the Table 9-149 sentence, which is still accurate. Sources re-fetched: [5] 802.11be-2024 dates; 802.11-2020 (7028) superseded by 802.11-2024 (approved 2020-12-03, published 2021-02-26); [6] T1557 tactics and .001-.004. All confirmed. The corpus file names `ALERT_TYPE_MLE_CROSS_LINK_CIPHER_DOWNGRADE`.
