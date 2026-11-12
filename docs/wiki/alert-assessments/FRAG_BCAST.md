---
type: FRAG_BCAST
technique: T1557
rule_file: src/alerts/rules_twin.c:794 (rule_fragattack(); FRAG_BCAST branch lines 707-717; counter incremented in src/fragattack.c:566-573)
count_semantics: per poll tick, not per frame. fire() increments count (= evaluations) every alerts_update() pass while the BSS row's plaintext_bcast_frag counter is > 0 (src/alerts/engine.c:478-480). That counter is cumulative and never decays (src/fragattack.c:573), so one offending fragment makes the alert re-fire every tick until the 64-slot BSS row is evicted or sloth exits. The number of fragments actually observed is the leading integer in the detail string, not count.
severity_assessment: agree - a fragmented, unprotected, group-addressed data frame on a BSS whose transmitter has already been seen sending protected frames has no conforming explanation; CRIT on the first one is right. The re-fire-every-tick behaviour is a count-semantics problem, not a severity problem.
false_positive_risk: low - the per-station ordered key-install gate (src/fragattack.c:550-564) excludes open networks and mid-association clients; what remains is a non-conforming stack, a corrupted header bit, or the attack.
noise_verdict: not seen on the reference host - host:null. By construction one hit yields one fire per poll on a single key - at least 4/s at the default POLL_MS=250 (include/sloth.h:28) and ~40/s as measured on the reference host, where event wakes cut the wait short, i.e. ~3.5 million/day (see FRAG_AMSDU for the live example of this shape); recommend re-firing only when the per-BSS counter has advanced, or letting last_hit age drive resolution.
prevalence: rare as an attack; the vulnerable-receiver set was documented (Apple clients, NetBSD/FreeBSD APs, Samsung i9305 among 75 tested combinations) [3][5]; no in-the-wild use reported by the researcher or the Wi-Fi Alliance [4][8].
tuning: [none - rule_fragattack has no --tune knob; FRAG_MAX_BSS=64 and the key-install gate are compile-time (src/fragattack.h). --hop makes the rule quieter, not noisier (a hopping radio may miss the Protected frame that arms the gate). --pcap-dir has no effect: fire() is called with match_ip=NULL (rules_twin.c:618-619, src/alert_pcap.c:105)]
researched: 2026-10-27
---
## What the rule checks

Input: the per-BSS table in `src/fragattack.c`, fed one 802.11 data frame at a time from the monitor-capture thread (`frag_observe_frame()`, called from `src/capture/probe.c:523`). `rule_fragattack()` (`src/alerts/rules_twin.c:581`) walks a locked copy of each row (`frag_bss_copy`, rules_twin.c:584-586) and, when `b->plaintext_bcast_frag > 0`, fires `ALERT_TYPE_FRAG_BCAST` at `ALERT_SEV_CRIT` (rules_twin.c:610-620).

The counter increments in `observe_locked()` (`src/fragattack.c:470-601`) only when all of these hold for one frame:

- data frame (`f->type == 2`, line 472), not Null/QoS-Null (line 477), not four-address/WDS (line 481);
- Protected bit clear (the Protected case returns at 550-557);
- the transmitter `(BSSID, SA)` has previously been seen sending a Protected frame — `sta_known()` at line 564. This is the key-install gate: the station's own encrypted traffic is the evidence a key was installed (since #180 an SA equal to the BSSID or to the AP MLD MAC its beacon advertised counts as the BSSID, so an 802.11be AP MLD is one station to the gate; the mld-sibling heuristic is not used here); the beacon's RSN element is deliberately not used (src/fragattack.h, "What 'protected network' means here");
- Address 1 is a group address (`dot11_is_group_addr(da)`, line 566);
- the frame is fragmented: FN > 0 or More Fragments set (`fragmented`, line 488; checked at 572).

It fires on the fragment, not on a completed reassembly, because only the victim can perform the reassembly (comment 567-571).

Key: `fragbcast:<BSSID>` (rules_twin.c:611) — one incident per BSSID; the station pair is not in the key. Detail: `"%u plaintext broadcast fragment%s on %.17s - broadcast reassembly is not permitted in an RSN (CVE-2020-26145)"` (rules_twin.c:612-617). Unlike the other FRAG_* details, it carries no SA->DA pair even though the row records them (src/fragattack.c:598-600).

Escalation: none, always CRIT. Resolution: the engine resolves a key after `ALERT_RESOLVE_AFTER_S` = 300 s with no re-fire (include/sloth.h:860), but because the counter never decrements the rule re-asserts the key every tick until the row is evicted (STAB_OLDEST by `last_seen`, refreshed by every data frame on that BSS — src/fragattack.c:220-229), so the incident effectively lives for the process lifetime.

## The attack

802.11 lets a sender split one MSDU into several fragments that the receiver reassembles; fragments of one MSDU share a sequence number, carry increasing fragment numbers, and set More Fragments on all but the last [3, §2.2][11]. Fragmentation applies to individually addressed frames; the paper states plainly that "broadcast frames should never be fragmented" [3, §6.4].

CVE-2020-26145 is an implementation bug: some receivers "process broadcasted fragments as normal unfragmented frames" and "accept second (or subsequent) broadcast fragments even when sent unencrypted in a protected Wi-Fi network" [3, §6.4][5]. A sender in radio range can therefore place an arbitrary packet (IPv4, ARP) in a plaintext fragment with a broadcast receiver address, and a vulnerable receiver treats it as a complete frame and hands the payload up the stack — packet injection into a WPA/WPA2/WPA3 network without the key [3, §6.4][4]. The payoff the paper demonstrates is DNS redirection and reaching hosts behind the router's NAT [3, §3.3]. Notable affected receivers were Apple devices and NetBSD/FreeBSD APs; some devices are vulnerable only during the 4-way handshake, which does not limit the attack because the victim can be forced to reconnect [3, §6.4]. The CVE record was filed against the Samsung Galaxy S3 i9305 and later extended to Siemens SCALANCE industrial WLAN products [5].

The reference implementation is the `fragattacks` test tool (a modified hostap with patched mac80211 drivers, kernel ≤ 5.12); its `ping I,D,P --bcast-ra` and `ping D,BP --bcast-ra` cases produce exactly this frame [6]. No mainstream framework (mdk4, aireplay-ng, bettercap) is documented as shipping a FragAttacks module; none was found in the sources consulted.

## Evidence that proves it

What sloth records:

- The alert: `alert` + `alert.create` JSONL records with `incident_id`, key `fragbcast:<BSSID>`, and the detail string (emitted at src/alerts/engine.c:606-607). `alert.update` records follow when the leading count changes (engine.c:528-536).
- **No pcap.** `fire()` passes `match_ip = NULL` (rules_twin.c:618-619) and `alert_pcap.c` returns early without a `match_ip` (src/alert_pcap.c:105). `docs/views/fragattack.md` says the per-alert pcap carries the offending frames; for this family the code does not write one.
- **No evidence-ring IDs.** The rule uses `fire()`, not `fire_ev()`, so `evidence_id_count` is 0 (engine.c:671-677).
- The `[c]` FragAttacks view shows the per-BSS counter, the `SA -> DA` pair, age, and the `protected_frames` gate count (rendered in src/views/fragattack.c:125-127 and 156 from the snapshot built at src/fragattack.c:655-693).
- `sensor_health` carries eviction tallies for the fragattack tables (`frag_bss/sta/session/assoc/mpdu`, src/sensor_health.c:126-130, and since #180 `frag_ap_ident`, the per-BSSID AP identity; a rising one means the gate stops merging an AP MLD's two addresses, which makes the rule miss, not false-fire). A rising `frag_sta` eviction count means the gate is forgetting stations, which makes the rule miss, not false-fire.

To call it real: on the named BSSID, a data frame with Address 1 a group/broadcast address, Protected = 0, fragment number ≥ 1 or More Fragments = 1, from a transmitter that earlier sent Protected = 1 frames on that BSSID; the fragment payload begins with an LLC/SNAP header (`AA AA 03 00 00 00` + EtherType) wrapping an IPv4/ARP packet [3, §6.4]. Several such fragments with no fragment 0 ever sent is the `ping D,BP --bcast-ra` fingerprint [6].

What would refute it: the frame carrying a bad-FCS indication (header corruption, not a transmitted bit — sloth's capture-path FCS handling was not verified here); a transmitter whose every frame is unprotected on a BSSID that also carries others' encrypted traffic (a legacy device on a conflated BSSID); a `protected_frames` gate count of exactly 1 from a single ambiguous frame.

## Benign causes

- **Non-conforming AP/client** that fragments group-addressed frames and sends them unprotected after key install. The paper found no conforming stack that does this; this is the "driver bug" reading `docs/views/alerts.md:176` gives for the sibling FRAG_PLAINTEXT row (the FRAG_BCAST row at :177 does not name one). Fingerprint: steady, forever, on every large group frame from one transmitter — not a burst, not during someone else's handshake.
- **Header corruption.** More Fragments and Protected are single bits a monitor radio can mis-receive. Fingerprint: isolated single hits on a weak signal, often with the retry flag; a correct stack would have dropped the frame on FCS. Stated from the frame format, not independently sourced.
- **BSSID conflation.** `sta_known` is keyed on `(BSSID, SA)`; if an open and a protected service genuinely shared a BSSID, encrypted frames from one would arm the gate for the other. Fingerprint: beacons for that BSSID advertising no RSN.

No documented vendor behaviour (band steering, mesh, Apple randomisation) produces plaintext broadcast fragments; none was found in sources.

## Assessment

Severity: CRIT is justified on the first fragment. The per-station ordered gate means an associating client cannot trip it, so what fires is outside the protocol regardless of whether any receiver accepts the frame.

Prevalence: FragAttacks was disclosed 2021-05-11 with coordinated patches from the Linux wireless maintainers, Intel, Cisco, Microsoft, Samsung, Netgear and roughly 40 vendors [7][9][12][13]; the Wi-Fi Alliance reported "no evidence of the vulnerabilities being used against Wi-Fi users maliciously" [8] and the researcher's FAQ says the same [4]. Five years on, the unpatched population is consumer/IoT gear; the payoff requires the attacker to be in radio range and to want injection on that LAN. Rare, targeted, worth a CRIT when seen.

Noise on the reference host: not seen (host:null). The arithmetic that matters is the one FRAG_AMSDU shows: one hit becomes one fire per poll for as long as the BSS row survives, because the rule tests `> 0` on a monotonic counter. If it ever fires, expect `count` in the millions/day for a single event: the reference host's steady single-key alerts all advance at ~40.6 evaluations/s (sloth-snap.db `alerts`, count / (last_seen - first_seen)), not the 4/s the 250 ms POLL_MS alone would give. Row eviction does end incidents in practice — the reference host's one FRAG_AMSDU incident stopped after ~1.7 h while the process ran on — so "process lifetime" is the upper bound, not the typical case. `observations` (engine.c:486-489) already separates "evidence moved" from "re-evaluated"; the fix is to remember the last-reported counter per BSS and fire only on change, or to drive resolution from `last_hit` age.

Sufficient to act on? For triage yes (BSSID, count, time); for proof no — there is no pcap and no evidence ring for this family and the detail omits the SA/DA pair the row holds. A responder should open the `[c]` view for the `SA -> DA` pair and `protected_frames` count, capture that channel externally, and check the named BSSID's firmware against the vendor's FragAttacks advisory [7].

## Bibliography

1. research/papers/fragattacks-usenix2021.md — repo research-corpus entry citing this type (accessed 2026-10-27)
2. docs/wiki/fragattacks.md — repo detector write-up, "FRAG_BCAST — CVE-2020-26145" and "The gate, and why it is not the beacon" (accessed 2026-10-27)
3. M. Vanhoef, "Fragment and Forge: Breaking Wi-Fi Through Frame Aggregation and Fragmentation", USENIX Security 2021 — https://papers.mathyvanhoef.com/usenix2021.pdf (accessed 2026-10-27; §2.2, §3.3, §6.1 "75 devices", §6.4)
4. FragAttacks project site / FAQ — https://www.fragattacks.com/ (accessed 2026-10-27)
5. CVE-2020-26145 record — https://cveawg.mitre.org/api/cve/CVE-2020-26145 (accessed 2026-10-27; NVD mirror https://nvd.nist.gov/vuln/detail/CVE-2020-26145 is JS-rendered and was not parseable)
6. vanhoefm/fragattacks test tool README — https://github.com/vanhoefm/fragattacks (accessed 2026-10-27; `ping I,D,P --bcast-ra`, `ping D,BP --bcast-ra`)
7. FragAttacks vendor advisory index — https://github.com/vanhoefm/fragattacks/blob/master/ADVISORIES.md (accessed 2026-10-27)
8. Wi-Fi Alliance, "Security update — fragmentation" (2021-05-11) — https://www.wi-fi.org/security-update-fragmentation (accessed 2026-10-27)
9. J. Berg, "various 802.11 security issues — fragattacks.com", oss-security, 2021-05-11 — https://www.openwall.com/lists/oss-security/2021/05/11/12 (accessed 2026-10-27; the mac80211 patch series it links, https://lore.kernel.org/linux-wireless/20210511180259.159598-1-johannes@sipsolutions.net/, returned 403 and was not read)
10. MITRE ATT&CK T1557, Adversary-in-the-Middle (v2.5) — https://attack.mitre.org/techniques/T1557/ (accessed 2026-10-27)
11. IEEE Std 802.11-2020, §10.4 (Fragmentation) and §9.2.4.4 (Sequence Control / fragment number) — standard is paywalled and not fetched; the "broadcast frames should never be fragmented" rule is quoted via [3, §6.4]; clause numbers are from the standard's contents and should be checked against a copy.
12. Intel Security Advisory INTEL-SA-00473 (2021-05-11; CVE-2020-24586/-24587/-24588 each CVSS 5.3) — https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00473.html (accessed 2026-10-27)
13. Cisco Security Advisory cisco-sa-wifi-faf-22epcEWu (2021-05-11; rates CVE-2020-26145 CVSS 6.5, tied with -26140/-26143/-26144 for the highest Cisco gives any of the twelve) — https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and by fetching every external URL.

- Code: `rule_fragattack` is at rules_twin.c:581; the FRAG_BCAST branch is 610-620 (was written 609-620), key at 611 (was 610), detail at 612-617 (was 611-616). Counter path src/fragattack.c:566-573, gate at 550-564, `fire(..., NULL, 0, now)` at 618-619, `packet_matches` early return at src/alert_pcap.c:105, `ALERT_RESOLVE_AFTER_S`=300 at include/sloth.h:860, `FRAG_MAX_BSS`=64 at src/fragattack.h:153 — all confirmed. Count semantics (`evaluations++` / `count` alias at engine.c:478-479) confirmed; the noise arithmetic (one standing hit → one fire per tick) follows.
- The view reference pointed at `src/fragattack.c:655-693`, which is the snapshot; the rendering is `src/views/fragattack.c:125-127,156`. The column shows `SA -> DA`, not a `LAST SA -> DA` label. Corrected.
- `docs/views/alerts.md:177` is the FRAG_BCAST row and does not say "driver bug"; that phrase is on :176 (FRAG_PLAINTEXT). Corrected.
- Sources: [3] fetched and text-extracted; §2.2, §3.3, §6.4 headings and the quotes ("broadcast frames should never be fragmented", "process broadcasted fragments as normal unfragmented frames", "even when sent unencrypted", Apple/NetBSD/FreeBSD, "we tested 75 devices" with §5.4 pointing to §6.1 as the device overview) all confirmed. [4] confirmed ("Not that we are aware of"). [5] confirmed (Samsung i9305, Siemens SCALANCE). [6] confirmed (`ping I,D,P --bcast-ra`, `ping D,BP --bcast-ra`, kernel ≤ 5.12). [7] confirmed — it lists roughly 40 vendors, so "~30" was corrected. [8] exact quote confirmed. [9] confirmed (J. Berg, 2021-05-11, lore link). [10] T1557 v2.5 confirmed. [12] Intel 5.3 ×3 confirmed. [13] Cisco confirmed. [11] IEEE remains unfetched and is marked as such.
- `research/papers/fragattacks-usenix2021.md` exists and names `ALERT_TYPE_FRAG_BCAST` (front-matter line 5, body line 40).

Re-verified 2026-10-27 against HEAD 0d60387. `git log` shows no commit touching `src/alerts/`, `src/fragattack.[ch]`, `src/alerts/engine.c`, `include/sloth.h`, `src/capture/probe.c`, `src/alert_pcap.c`, `src/db.[ch]` or `src/rsn_ie.h` since c5650a3, and every line number above was re-read and still matches. Every external URL was fetched again; the two previously unreachable ones (the lore.kernel.org patch series, HTTP 403; the NVD page, JS-rendered) are still unreachable and remain marked as such. The USENIX and Dragonblood PDFs were text-extracted locally (`pdftotext`) and the quoted phrases grepped for directly rather than trusting a summariser.

- Second-pass corrections: the JSONL emission site is engine.c:606-607 (`jsonl_emit_alert` / `alert.create`), not 596-598 (that is the per-type summary bookkeeping just above it) — fixed. [7] ADVISORIES.md counted from the raw file: 41 linked entries, so "roughly 40 vendors" stands. [13] Cisco's 6.5 for CVE-2020-26145 added to the bibliography line; the text did not previously carry any score for this CVE. [3] re-confirmed by grep: "broadcast frames should never be fragmented", "process broadcasted fragments as normal unfrag-mented frames", "even when sent unencrypted", "Notable affected devices are those of Apple and APs on NetBSD and FreeBSD", "In total this means we tested 75 devices" (§6.1 Experimental setup), §6.4 heading "Broadcast plaintext fragments". [4] "Not that we are aware of" re-confirmed. [5] Samsung i9305 4.4.4 and eight Siemens SCALANCE WAM/WUM models re-confirmed. [6] both `--bcast-ra` cases and "kernel versions below or equal to 5.12" re-confirmed. [8] exact sentence re-confirmed. [9] author/date/subject/lore link re-confirmed. [10] T1557 is still v2.5 (page now stamped ATT&CK v20, last modified 2026-05-12). [12] 5.3 x3 re-confirmed.

Third pass 2026-10-27 against HEAD d70d394 (no src/ or include/ commit since c5650a3; all line numbers re-read and still match).

- Noise arithmetic corrected: the poll tick is not 1 s. POLL_MS=250 (include/sloth.h:28) and event wakes shorten it; on the reference host (~/sloth-snap.db `alerts`) every steady single-key alert advances at ~40.6 evaluations/s. "~86,400 fires/day at a 1 s tick" replaced with ≥4/s nominal, ~40/s (~3.5M/day) measured.
- "for the life of the process" softened: row eviction does end these incidents in practice (the reference host's FRAG_AMSDU incident stopped after ~1.7 h while sloth kept running).
- [13] Cisco 6.5 is tied with three other CVEs for the highest score, not the sole highest; reworded.
- Code re-checked: gate (564), group-address test (566), `fragmented` (488/572), key/detail/fire 610-620 — unchanged and correct.
- Sources re-fetched (curl + pdftotext for PDFs, WebFetch for Intel which 403s curl): USENIX paper, fragattacks.com, CVE records, fragattacks README/ADVISORIES (41 links), Wi-Fi Alliance, oss-security, ATT&CK pages, Intel (5.3 x3), Cisco (6.5 for -26140/-26143/-26144/-26145; 5.7 for -24586/-24588; 4.8 for -24587/-26146/-26147) — every quoted phrase grepped and present. research/papers/fragattacks-usenix2021.md names the type.

**#180 (2026-11-03).** The AP-identity block (`frag_ap_identity()`, the per-BSSID beacon table, `gate_identity()`) was inserted above `observe_locked()`, so every `src/fragattack.c` line number above is pre-#180: `observe_locked` moved 470 -> 590, the `sta_known` gate 564 -> 699, `plaintext_bcast_frag++` 573 -> 708, `plaintext_unicast++` 595 -> 730, `snapshot_locked` 655 -> 790. Behaviour change for this rule: the gate files an SA equal to the BSSID or to the AP MLD MAC that BSSID's beacon advertised under the BSSID, so an 802.11be AP MLD is one station to it. count_semantics and noise_verdict are unaffected.
