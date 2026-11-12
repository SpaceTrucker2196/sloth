---
type: FRAG_CACHE
technique: T1557
rule_file: src/alerts/rules_twin.c:817 (rule_fragattack(); FRAG_CACHE branch lines 781-794; counter incremented in src/fragattack.c:336-346 inside frag_track())
count_semantics: per poll tick, not per reassembly. fire() increments count (= evaluations) every alerts_update() pass while the BSS row's cumulative cache_poison counter is > 0 (src/alerts/engine.c:478-480); the counter never decays (src/fragattack.c:342). The leading integer in the detail string is the number of *continuation fragments* that arrived after a straddling (re)association (src/fragattack.c:340-342 runs once per FN>0 frame, retransmissions included), not the number of reassemblies: a three-fragment MSDU straddling one reassociation counts 2, and a retried continuation counts again.
severity_assessment: too high (marginally) - CRIT is right for the CVE's own failure mode, but the session match ignores the sequence number and has no age limit, so the rule can also count a stale, abandoned session being "completed" by an unrelated fragment after a reassociation. WARN until the sequence number matches, CRIT when it does, would be truer to the evidence.
false_positive_risk: medium - on a hopping radio that misses fragment 0 of a new MSDU, a continuation for the same (BSSID,SA,DA,TID) is matched against whatever older session is still on file, and a reassociation in between (roaming, power-save reconnect) is ordinary.
noise_verdict: not seen on the reference host - host:null. If it fires, expect the per-tick re-fire pattern (one hit -> one fire per poll on one key: at least 4/s at the default POLL_MS=250 (include/sloth.h:28), and ~40/s measured on the reference host, where event wakes shorten the wait (~3.5 million/day)); recommend firing on counter change and ageing sessions out (the paper notes Linux clears fragments after 2 s [3, §5.4]).
prevalence: a design flaw present in every 802.11 device since 1997 [3, §5.4][5]; demonstrated against Windows/Linux clients (over half of tested cards), FreeBSD APs and all four tested home routers, not Android/iOS [3, §5.4]; no in-the-wild use reported [4][8].
tuning: [none - no --tune knob; FRAG_MAX_SESSIONS=128 and FRAG_MAX_ASSOC_EVT=128 are compile-time (src/fragattack.h). --hop drives the main false-positive path (missed fragment-0 frames). --pcap-dir has no effect (match_ip=NULL, rules_twin.c:695-696)]
researched: 2026-10-27
---
## What the rule checks

Two inputs feed the detector, both on the monitor-capture thread:

1. **Fragment sessions.** For every fragmented data frame (`fragmented`, src/fragattack.c:488; not gated on the Protected bit — comment 315-319), `frag_track()` (line 320) keys a session on `(BSSID, SA, DA, TID)` (`sess_key_t`, 108-111; looked up by `sess_find`, 279-283). A fragment number 0 opens or replaces the session and records `start_seen = now` (326, 302). FN > 0 is a continuation; with no session on file it is ignored (333-334).
2. **Association events.** `frag_note_association(bssid, sta, now)` (261) is called from `src/capture/probe.c:616` on a status-0 (Re)Association Response — the same site that feeds `assoc_observe()`. It records `last_assoc` per `(BSSID, STA)` (248-259).

Condition (src/fragattack.c:336-346): a continuation arrives, and either endpoint (SA or DA) completed a (re)association strictly after the session opened (`frag_assoc_after`, 272-277: `r->last_assoc > since`, strict because the 1 s clock cannot order same-second events). Then `cache_poison++` and `last_sa/last_da/last_hit` update. The increment happens on the continuation regardless of `more`; the session closes only when `!more` (404).

Two things the condition does **not** check, read from the code:

- **Sequence number.** `s->seq_ctrl` is stored (307) but used only by the PN-gap branch (390). A continuation with a different sequence number than the fragment 0 that opened the session is still treated as completing it. 802.11 reassembly is keyed on (Address 2, sequence number, fragment number) [11]; sloth's session key is looser.
- **Age.** A session lives until a new FN 0 replaces it, `!more` closes it, or the 128-slot STAB_OLDEST table evicts it (src/fragattack.c:122). There is no receive-lifetime timeout.

`rule_fragattack()` fires `ALERT_TYPE_FRAG_CACHE` at CRIT when `b->cache_poison > 0` (684-697). Key: `fragcache:<BSSID>` (685). Detail: `"%u fragment reassembly%s on %.17s completed after a (re)association - last %.17s -> %.17s (CVE-2020-24586)"` (686-691). No escalation; resolution only on row eviction (see FRAG_BCAST for why that is rare).

## The attack

Receivers hold decrypted fragments in a per-sender fragment cache until the final fragment arrives. CVE-2020-24586 is one of the three design flaws: "The 802.11 standard ... doesn't require that received fragments be cleared from memory after (re)connecting to a network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP, CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or exfiltrate user data" [5]. The standard "does not state when decrypted fragments should be removed from memory ... decrypted fragments are not dropped when the security context changes due to a (re)connect or (re)association" [3, §4.1].

The paper's attack (§5): the adversary, possessing valid credentials for a hotspot-type network, connects under the victim's spoofed MAC and places a fragment holding the start of an attacker-destined (or attacker-chosen) packet into the AP's cache; because the cache is not cleared across (re)association, that fragment is still present when the real victim reconnects and later sends its own fragment with the matching sequence number, and the two reassemble into one frame that the AP processes or forwards — exfiltrating the victim's data or injecting the attacker's packet [3, §5.2-5.3]. The design flaw has been in the standard since 1997 (confirmed against WEP) [3, §5.4]. The passively observable footprint sloth keys on is narrower and does not claim the attack succeeded: it is the straddling itself — a reassembly completing across a (re)association boundary at which the cache should have been empty.

Tooling: the `fragattacks` test tool's cache cases, e.g. `ping I,E,R,AE`, inject fragments across a disconnect/reassociate cycle [6]. The attack needs patched drivers to run in practice [3, §5.4]. No mainstream framework is documented as shipping it.

## Evidence that proves it

What sloth records: the `alert`/`alert.create` JSONL with key `fragcache:<BSSID>` and the detail (which here does carry the `last SA -> DA` pair). No pcap (`match_ip = NULL`, rules_twin.c:695-696; src/alert_pcap.c:105) and no evidence-ring IDs (`fire()`, not `fire_ev()`). The `[c]` view shows the per-BSS `cache_poison` counter, the SA->DA pair, age, and the `protected_frames` gate count. `sensor_health` carries `frag_session` and `frag_assoc` eviction counts — a rising `frag_session` count means sessions are being evicted before completing, which both misses real cases and, because eviction frees slots, does not itself cause false fires.

To call it real: on the named BSSID, correlate three things sloth timestamps internally — (a) a fragment 0 opening a session for `(BSSID, SA, DA, TID)`; (b) a (Re)Association Response with status 0 for SA or DA, strictly later; (c) a continuation fragment for the same key completing the reassembly. In the attack, the two fragments were sent under different credentials/MACs but share the sequence number and addresses the receiver reassembles on, and one fragment's payload is an attacker-chosen IP/ARP packet [3, §5.2]. The honest confirming signal is a reassembly whose fragment 0 and continuation also share the *sequence number* and are separated by a genuine reassociation, with no intervening fragment of the same sequence.

What would refute it (the benign fingerprint): the continuation carries a *different* sequence number than the opening fragment (so sloth matched an abandoned session the sequence-number-blind key let through); or the "reassociation" was the victim's own roam/power-save reconnect and the fragments are all that client's own traffic resuming. Because sloth does not reassemble or decrypt, it cannot show the payload, so neither direction is provable from the alert alone.

## Benign causes

- **Roaming / power-save reconnect mid-reassembly.** A client that reassociates (band steering, roaming between APs on one ESS, waking from power save) while a fragmented frame was in flight produces a completion straddling a real reassociation. This is the most likely false positive and is not independently sourced — it follows from the rule matching on reassociation timing without reassembly success. Fingerprint: the SA/DA are both legitimate clients of that AP, the counter advances slowly and sporadically, and the sequence numbers are consistent.
- **Missed fragment 0 on a hopping radio.** `--hop` means sloth may hear a continuation whose opening fragment landed while tuned elsewhere; matched against a stale session, a nearby reassociation then trips the rule. Fingerprint: co-occurs with high `frag_session` eviction and `--hop` in the run flags.
- **Non-conforming stack** that legitimately fragments across reassociations — rarer than the two above but the CVE's literal target.

## Assessment

Severity: CRIT reflects that the fragment cache should be empty at a (re)association boundary and a completion straddling it is the CVE's own failure mode. The caveat is that sloth's session key omits the sequence number and has no age bound, so the signal is "a reassembly straddled a reassociation", not the stronger "the same MSDU's fragments straddled it". That gap is why false_positive_risk is medium rather than low; a WARN/CRIT split on whether the sequence numbers match would separate the two.

Prevalence: disclosed 2021-05-11, patched across vendors [7][10]; no in-the-wild use reported [4][8]. As a design flaw it affected essentially all unpatched stacks that cache fragments, but the attack requires the adversary to be on the network (hotspot-type, shared password) or in a multi-channel MitM position and to want injection/exfiltration — not a drive-by. Uncommon in practice.

Noise on the reference host: not seen (host:null). The structural warning stands: the rule tests `> 0` on a monotonic counter, so a single hit re-fires every tick for the process lifetime. Combined with the medium false-positive rate on roaming networks, this is the FRAG_* member most likely to become a persistent false CRIT on a busy enterprise ESS. Recommend (1) firing on counter change only, (2) ageing sessions to a receive-lifetime bound, and (3) splitting severity by sequence-number match.

Sufficient to act on? For triage only. A responder should open the `[c]` view for the SA->DA pair, confirm from an external capture on that channel whether the two fragments share a sequence number and whether a real reassociation occurred, and rule out roaming before escalating. Then check the AP's firmware against the vendor advisory [7].

## Bibliography

1. research/papers/fragattacks-usenix2021.md — repo research-corpus entry citing this type (accessed 2026-10-27)
2. docs/wiki/fragattacks.md — repo detector write-up, "FRAG_CACHE — CVE-2020-24586" (accessed 2026-10-27)
3. M. Vanhoef, "Fragment and Forge...", USENIX Security 2021 — https://papers.mathyvanhoef.com/usenix2021.pdf (accessed 2026-10-27; §4.1 design flaws, §5 fragment cache, §5.4 experiments / Linux 2 s clear)
4. FragAttacks project site / FAQ — https://www.fragattacks.com/ (accessed 2026-10-27)
5. CVE-2020-24586 record — https://cveawg.mitre.org/api/cve/CVE-2020-24586 (accessed 2026-10-27; references Intel INTEL-SA-00473 and Cisco advisory)
6. vanhoefm/fragattacks test tool README — https://github.com/vanhoefm/fragattacks (accessed 2026-10-27; cache cases `ping I,E,R,AE`, `ping I,E,R,AE --full-recon`)
7. FragAttacks vendor advisory index — https://github.com/vanhoefm/fragattacks/blob/master/ADVISORIES.md (accessed 2026-10-27)
8. Wi-Fi Alliance, "Security update — fragmentation" (2021-05-11) — https://www.wi-fi.org/security-update-fragmentation (accessed 2026-10-27)
9. MITRE ATT&CK T1557, Adversary-in-the-Middle (v2.5) — https://attack.mitre.org/techniques/T1557/ (accessed 2026-10-27)
10. Intel Security Advisory INTEL-SA-00473 (2021-05-11; CVE-2020-24586 CVSS 5.3) — https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00473.html (accessed 2026-10-27); Cisco cisco-sa-wifi-faf-22epcEWu rates CVE-2020-24586 CVSS 5.7 — https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu (accessed 2026-10-27)
11. IEEE Std 802.11-2020, §10.4 (Fragmentation and defragmentation; reassembly keyed on Address 2 + sequence number + fragment number) — paywalled, not fetched; reassembly-key statement cross-checked against the code's own comment (src/fragattack.c:336-346) and [3, §5].

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and by fetching every external URL.

- Code: FRAG_CACHE branch rules_twin.c:684-697, key 685, detail 686-691 (was 686-690), `fire(..., NULL, 0, now)` 695-696 — confirmed. `frag_track` 320-405: FN 0 → `sess_open` (326; `start_seen = now` at 302), continuation with no session dropped (333-334), `frag_assoc_after` strict `>` (272-277), `cache_poison++` at 342 regardless of `more`, close on `!more` at 404, `seq_ctrl` stored 307 and read only at 390 — confirmed. `frag_note_association` (261) is called from src/capture/probe.c:616 — confirmed. `FRAG_MAX_SESSIONS`/`FRAG_MAX_ASSOC_EVT`=128 at src/fragattack.h:155-156. The `sess_key_t` typedef is at 108-111, not 281 (281 is its use inside `sess_find`); corrected. Count semantics and noise arithmetic follow from engine.c:478-479 as described.
- Sources: [3] fetched; §4.1 "Fragmentation design flaws", §5 "Poisoning the Fragment Cache", §5.2 "Exfiltrating client data", §5.3 "Packet injection", §5.4 "Experiments" confirmed, with the quotes "does not state when decrypted fragments should be removed", "more than half of all tested network cards", "Android and iOS ... not vulnerable", "only FreeBSD is vulnerable in AP mode", "all our four home routers", "since its release in 1997", "clears fragments from memory after two seconds" all present in §5.4. [5] description and references (Intel-SA-00473, Cisco) confirmed. [6] confirmed; the flag is `--full-recon`, not `--full-reconnect` — corrected. [7], [8], [9], [10] (Intel 5.3; Cisco 5.7 for CVE-2020-24586) confirmed. [11] IEEE remains unfetched and is marked as such.
- `research/papers/fragattacks-usenix2021.md` names `ALERT_TYPE_FRAG_CACHE` (lines 5, 52).

Re-verified 2026-10-27 against HEAD 0d60387. `git log` shows no commit touching `src/alerts/`, `src/fragattack.[ch]`, `src/alerts/engine.c`, `include/sloth.h`, `src/capture/probe.c`, `src/alert_pcap.c`, `src/db.[ch]` or `src/rsn_ie.h` since c5650a3, and every line number above was re-read and still matches. Every external URL was fetched again; the two previously unreachable ones (the lore.kernel.org patch series, HTTP 403; the NVD page, JS-rendered) are still unreachable and remain marked as such. The USENIX and Dragonblood PDFs were text-extracted locally (`pdftotext`) and the quoted phrases grepped for directly rather than trusting a summariser.

- Second-pass: no text changes needed. [3] re-confirmed by grep: "does not state when decrypted fragments should be removed", "two seconds", "since its release in 1997", "more than half of all tested", "Android and iOS", "four home routers"; headings §4.1 "Fragmentation design flaws", §5.2 "Exfiltrating client data", §5.3 "Packet injection", §5.4 "Experiments". [5] description and the Intel/Cisco/fragattacks.com references re-confirmed. [6] `ping I,E,R,AE` and `--full-recon` re-confirmed (the README also has a `--full-reconnect` variant, described as deauthenticate-and-reconnect; the entry's `--full-recon` is the reassociation one and is correct as written). [10] Intel 5.3 / Cisco 5.7 for CVE-2020-24586 re-confirmed.

Third pass 2026-10-27 against HEAD d70d394 (no src/ or include/ commit since c5650a3; all line numbers re-read and still match).

- Noise arithmetic corrected: the poll tick is not 1 s. POLL_MS=250 (include/sloth.h:28) and event wakes shorten it; on the reference host (~/sloth-snap.db `alerts`) every steady single-key alert advances at ~40.6 evaluations/s. "~86,400 fires/day at a 1 s tick" replaced with ≥4/s nominal, ~40/s (~3.5M/day) measured.
- count_semantics corrected: `cache_poison++` (src/fragattack.c:340-342) runs once per continuation fragment (FN>0, retransmissions included), so the detail's leading integer counts fragments, not reassemblies — a three-fragment MSDU straddling one reassociation counts 2.
- Code re-checked: non-QoS frames reach frag_track with TID 0 (dot11_frame_tid, src/dot11_frame.c:212-216), so the session key description stands.
- Sources re-fetched (curl + pdftotext for PDFs, WebFetch for Intel which 403s curl): USENIX paper, fragattacks.com, CVE records, fragattacks README/ADVISORIES (41 links), Wi-Fi Alliance, oss-security, ATT&CK pages, Intel (5.3 x3), Cisco (6.5 for -26140/-26143/-26144/-26145; 5.7 for -24586/-24588; 4.8 for -24587/-26146/-26147) — every quoted phrase grepped and present. research/papers/fragattacks-usenix2021.md names the type.
