---
type: FRAG_MIXED
technique: T1557
rule_file: src/alerts/rules_twin.c:678 (rule_fragattack(); FRAG_MIXED branch lines 796-806; counter incremented in src/fragattack.c:348-356 inside frag_track())
count_semantics: per poll tick, not per reassembly. fire() increments count (= evaluations) every alerts_update() pass while the BSS row's cumulative mixed_protect counter is > 0 (src/alerts/engine.c:478-480); the counter never decays (src/fragattack.c:352). The leading integer in the detail is the number of continuation fragments whose Protected bit differed from the session's fragment 0 (src/fragattack.c:351-352 runs once per FN>0 frame, retransmissions included), not the number of reassemblies.
severity_assessment: agree - a reassembly whose fragments disagree on the Protected bit has essentially no conforming cause on an RSN; CRIT is right. The re-fire-every-tick behaviour is the shared count-semantics issue, not a severity issue.
false_positive_risk: low-to-medium - lower than FRAG_CACHE because the signal is intrinsic to the two fragments (one encrypted, one not) rather than a timing correlation; the residual risk is a hopping radio that pairs a continuation with a stale session of the opposite protection state, since the session key omits the sequence number.
noise_verdict: not seen on the reference host - host:null. If it fires, expect the per-tick re-fire pattern (one hit -> one fire per poll on one key: at least 4/s at the default POLL_MS=250 (include/sloth.h:28), and ~40/s measured on the reference host, where event wakes shorten the wait (~3.5 million/day)); recommend firing on counter change and ageing sessions out.
prevalence: an implementation flaw; the paper found 53 of 68 fragmentation-capable device combinations affected by some plaintext-acceptance variant, with CVE-2020-26147 specifically the "reassemble mixed encrypted/plaintext" case [3, §6.3][5]; no in-the-wild use reported [4][8].
tuning: [none - no --tune knob; FRAG_MAX_SESSIONS=128 compile-time (src/fragattack.h). --hop is the main residual false-positive path. --pcap-dir has no effect (match_ip=NULL, rules_twin.c:707-708)]
researched: 2026-10-27
---
## What the rule checks

Same session table as FRAG_CACHE. For each fragmented data frame `frag_track()` (src/fragattack.c:320) opens a session on fragment 0, recording `start_protected = protected_bit` (303, 291). On a continuation it compares the continuation's Protected bit against the session's opening one (348-356):

```
if (protected_bit != s->start_protected) { b->mixed_protect++; ... }
```

So the counter increments when a reassembly's fragments do not all agree on the Protected bit — one encrypted, one plaintext. The check is not gated on RSN state (the fragment cache and reassembly exist before decryption — comment 315-319), and it runs on the continuation regardless of `more`; the session closes on `!more` (404).

As with FRAG_CACHE, the session key `(BSSID, SA, DA, TID)` omits the sequence number (stored at 307, consulted only by the PN-gap branch at 390) and sessions have no age bound beyond FN-0 replacement, `!more`, or STAB_OLDEST eviction.

`rule_fragattack()` fires `ALERT_TYPE_FRAG_MIXED` at CRIT when `b->mixed_protect > 0` (699-709). Key: `fragmixed:<BSSID>` (700). Detail: `"%u reassembly%s on %.17s mixed an encrypted fragment with a plaintext one - last %.17s -> %.17s (CVE-2020-26147)"` (701-706). No escalation; resolution only on row eviction.

## The attack

CVE-2020-26147 is the implementation flaw of receivers that "reassemble fragments even though some of them were sent in plaintext" [5], instead of requiring every fragment of one MSDU to be encrypted. Each fragment is unremarkable alone — an all-encrypted sequence is normal, an all-plaintext one is normal on an open network — the violation exists only once they are combined into one MSDU (docs/wiki/fragattacks.md, "FRAG_MIXED"). The paper: "devices reassemble mixed encrypted and plaintext fragments, instead of only accepting encrypted ones ... This allows an attacker to replace certain encrypted fragments with plaintext ones" [3, §6.3]. It measured the receiver population: 21 devices required only the first fragment encrypted, 9 only the last, 3 only one; combined with the pure plaintext-acceptance bugs (CVE-2020-26140/-26143), 53 of 68 fragmentation-capable device combinations were affected by at least one plaintext-acceptance variant [3, §6.3]. The affected-receiver list in the CVE record names the Linux kernel 5.8.9, Cisco, Arista and Siemens products [5].

What the attacker gains is, again, packet injection or selective fragment exfiltration into a protected session [3, §6.3]. The passive footprint sloth keys on is the mix itself, and it does not claim the receiver accepted it.

Tooling: the `fragattacks` tool's `ping I,E,P` and `ping I,P,E` cases send the encrypted-then-plaintext and plaintext-then-encrypted combinations [6].

## Evidence that proves it

What sloth records: `alert`/`alert.create` JSONL with key `fragmixed:<BSSID>` and the detail (carrying the `last SA -> DA` pair). No pcap (`match_ip = NULL`) and no evidence ring. The `[c]` view shows the per-BSS `mixed_protect` counter, SA->DA, age and gate count. `sensor_health` carries `frag_session` eviction counts.

To call it real: on the named BSSID, for one `(SA, DA, TID)` and one sequence number, two fragments where one has Frame Control Protected = 1 and the other Protected = 0, both part of the same reassembly (fragment numbers 0 and ≥1, More Fragments set on all but the last). That the two share a sequence number is the signal sloth's session key does not itself enforce, so it is the first thing to confirm from an external capture. The plaintext fragment's payload beginning with an LLC/SNAP + IP/ARP header is the attacker's injected content [3, §6.3].

What would refute it (benign fingerprint): the two fragments carry different sequence numbers (sloth matched a stale session the sequence-blind key let through on a hopping radio); or a capture artifact where a radiotap/driver mislabels the Protected bit on one frame. Because sloth neither reassembles nor decrypts, the payload cannot be shown from the alert.

## Benign causes

- **Missed fragment 0 on a hopping radio**, pairing a continuation with a stale session of the opposite protection state. Residual false-positive path; follows from the sequence-blind session key plus `--hop`. Fingerprint: co-occurs with `--hop` and `frag_session` evictions; the SA/DA and sequence numbers will not line up on an external capture.
- **Protected-bit mislabelling** by the capture stack (radiotap flags, driver quirks). Fingerprint: isolated, on a specific adapter/driver, not reproducible on another capture of the same traffic. Stated from the frame format, not independently sourced.
- There is **no documented legitimate behaviour** that mixes encrypted and plaintext fragments within one MSDU on an RSN; the paper treats any such mix as the bug [3, §6.3]. This is why the risk is lower than FRAG_CACHE's timing-based signal.

## Assessment

Severity: CRIT is justified — the mix is intrinsic to the two fragments, not a timing inference, and has no conforming reading on a protected network. The one caveat is the shared session-key weakness (no sequence number, no age bound), which on a hopping radio can manufacture a mix from two unrelated fragments; that keeps the false-positive risk from being as low as, say, FRAG_AMSDU's PN-keyed signal.

Prevalence: disclosed 2021-05-11, patched across vendors including the Linux kernel [5][7][9]; no in-the-wild use reported [4][8]. The receiver population was broad in 2021 (53/68 combinations) but has had five years of patching; the attack still requires a multi-channel MitM in radio range and a network that uses fragmentation.

Noise on the reference host: not seen (host:null). The shared structural warning applies: `> 0` on a monotonic counter re-fires every tick for the process lifetime. The fix is the same as the rest of the family — fire on counter change, age sessions out, and (to cut the hopping-radio false positive) require the mixed fragments to share a sequence number before counting.

Sufficient to act on? For triage yes; for proof, confirm from an external capture that the encrypted and plaintext fragments share a sequence number and reassembly, then check the receiver's firmware against the vendor advisory [7].

## Bibliography

1. research/papers/fragattacks-usenix2021.md — repo research-corpus entry citing this type (accessed 2026-10-27)
2. docs/wiki/fragattacks.md — repo detector write-up, "FRAG_MIXED — CVE-2020-26147" (accessed 2026-10-27)
3. M. Vanhoef, "Fragment and Forge...", USENIX Security 2021 — https://papers.mathyvanhoef.com/usenix2021.pdf (accessed 2026-10-27; §6.3 mixed plaintext/encrypted fragments, device counts)
4. FragAttacks project site / FAQ — https://www.fragattacks.com/ (accessed 2026-10-27)
5. CVE-2020-26147 record — https://cveawg.mitre.org/api/cve/CVE-2020-26147 (accessed 2026-10-27; affected: Linux kernel 5.8.9, Cisco, Arista, Siemens)
6. vanhoefm/fragattacks test tool README — https://github.com/vanhoefm/fragattacks (accessed 2026-10-27; `ping I,E,P`, `ping I,P,E`)
7. FragAttacks vendor advisory index — https://github.com/vanhoefm/fragattacks/blob/master/ADVISORIES.md (accessed 2026-10-27)
8. Wi-Fi Alliance, "Security update — fragmentation" (2021-05-11) — https://www.wi-fi.org/security-update-fragmentation (accessed 2026-10-27)
9. J. Berg, oss-security, 2021-05-11 — https://www.openwall.com/lists/oss-security/2021/05/11/12 (accessed 2026-10-27; mac80211 patch series linked but 403 on fetch)
10. MITRE ATT&CK T1557, Adversary-in-the-Middle (v2.5) — https://attack.mitre.org/techniques/T1557/ (accessed 2026-10-27)
11. IEEE Std 802.11-2020, §10.4 (reassembly requires consistent security framing) — paywalled, not fetched; the "all fragments must be encrypted" requirement is quoted via [3, §6.3] and [5].

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and by fetching every external URL.

- Code: FRAG_MIXED branch is rules_twin.c:699-709 (was 698-709), key at 700 (was 699), detail 701-706 (was 700-705), `fire(..., NULL, 0, now)` 707-708 — corrected/confirmed. `start_protected = protected_bit` at src/fragattack.c:303 (set via `sess_open`, called at 326), the comparison and `mixed_protect++` at 351-352, close on `!more` at 404, sequence-blind key (`seq_ctrl` only read at 390), comment 315-319 — confirmed. Count semantics and noise arithmetic follow from engine.c:478-479.
- Sources: [3] fetched; §6.3 "Mixed plaintext and encrypted fragments" confirmed with the exact figures (21 first-fragment, 9 last-fragment, 3 any-one, 11 plaintext, 9 fragmented-plaintext, "53 out of 68 devices that support fragmentation") and the quote "reassemble mixed encrypted and plaintext fragments, instead of only accepting encrypted ones ... replace certain encrypted fragments with plaintext ones". [5] confirmed (Linux kernel 5.8.9; Cisco, Siemens SCALANCE, Arista). [6] `ping I,E,P` / `ping I,P,E` confirmed. [7], [8], [9], [10] confirmed. Cisco rates CVE-2020-26147 at CVSS 4.8 (not cited in the text; noted here for completeness). [11] IEEE remains unfetched and is marked as such.
- `research/papers/fragattacks-usenix2021.md` names `ALERT_TYPE_FRAG_MIXED` (lines 5, 52).

Re-verified 2026-10-27 against HEAD 0d60387. `git log` shows no commit touching `src/alerts/`, `src/fragattack.[ch]`, `src/alerts/engine.c`, `include/sloth.h`, `src/capture/probe.c`, `src/alert_pcap.c`, `src/db.[ch]` or `src/rsn_ie.h` since c5650a3, and every line number above was re-read and still matches. Every external URL was fetched again; the two previously unreachable ones (the lore.kernel.org patch series, HTTP 403; the NVD page, JS-rendered) are still unreachable and remain marked as such. The USENIX and Dragonblood PDFs were text-extracted locally (`pdftotext`) and the quoted phrases grepped for directly rather than trusting a summariser.

- Second-pass: no text changes needed. [3] re-confirmed by grep: §6.3 heading "Mixed plaintext and encrypted fragments", "reassemble mixed encrypted and plaintext fragments", "replace certain encrypted fragments", "21 devices only require that the first fragment is encrypted", "53 out of 68 devices that support frag[mentation]". [5] Linux kernel 5.8.9, Cisco, Arista, Siemens SCALANCE W-series re-confirmed. [6] `ping I,E,P` / `ping I,P,E` re-confirmed. Cisco's 4.8 for CVE-2020-26147 re-confirmed.

Third pass 2026-10-27 against HEAD d70d394 (no src/ or include/ commit since c5650a3; all line numbers re-read and still match).

- Noise arithmetic corrected: the poll tick is not 1 s. POLL_MS=250 (include/sloth.h:28) and event wakes shorten it; on the reference host (~/sloth-snap.db `alerts`) every steady single-key alert advances at ~40.6 evaluations/s. "~86,400 fires/day at a 1 s tick" replaced with ≥4/s nominal, ~40/s (~3.5M/day) measured.
- count_semantics corrected: `mixed_protect++` (src/fragattack.c:351-352) runs per continuation fragment and compares against fragment 0's Protected bit only, so the detail integer counts fragments, not reassemblies.
- Sources re-fetched (curl + pdftotext for PDFs, WebFetch for Intel which 403s curl): USENIX paper, fragattacks.com, CVE records, fragattacks README/ADVISORIES (41 links), Wi-Fi Alliance, oss-security, ATT&CK pages, Intel (5.3 x3), Cisco (6.5 for -26140/-26143/-26144/-26145; 5.7 for -24586/-24588; 4.8 for -24587/-26146/-26147) — every quoted phrase grepped and present. research/papers/fragattacks-usenix2021.md names the type.
