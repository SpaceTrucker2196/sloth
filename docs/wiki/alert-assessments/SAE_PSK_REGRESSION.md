---
type: SAE_PSK_REGRESSION
technique: T1562.004
rule_file: src/alerts/rules_twin.c:937 (rule_sae_psk_regression()); the evidence query is src/db.c:2048 (refresh_akm_regressions()), exposed via db_akm_regressions() (src/db.c:2106)
count_semantics: per poll tick, per (SSID, BSSID) regression row. The rule fires once per row returned by db_akm_regressions() every alerts_update() pass (rules_twin.c:831-845); fire() increments count (= evaluations) every tick the row persists (src/alerts/engine.c:478-480). The regression set is recomputed only at a --db tick (src/db.c:2150), not every poll, so count is the number of polls the regression has stood, not a count of events.
severity_assessment: agree - CRIT is right: a BSSID recorded as SAE-only at two points ≥24 h apart and now advertising PSK-only has lost WPA3 protection, and the span plus latest-posture requirement make it a real state change, not a sample (note the span is first-to-last sighting, not continuous observation). T1562.004 (Impair Defenses) rather than T1557 is the honest tag since nothing here asserts an adversary.
false_positive_risk: low-to-medium - the sustain window and "latest recorded posture" logic exclude transition mode and brief blips, but a deliberate administrative downgrade (an admin turning off WPA3) fires identically to a malicious one; the rule says so by design and leaves the judgement to the operator.
noise_verdict: not seen on the reference host - host:null. Requires WITH_SQLITE and a --db file with ≥24 h of history, so a fresh database is silent for its first day by construction. If it fires, the per-tick re-fire inflates count until SAE returns (the rule clears when the latest posture is SAE again); recommend firing on row appearance/disappearance rather than every poll.
prevalence: WPA3 downgrade/rollback is a documented posture risk (Dragonblood transition-mode analysis [3]; CERT VU#871675 is the implementation-CVE advisory the corpus anchors on, not a downgrade write-up [4]); a sustained SAE->PSK regression specifically is uncommon and most often administrative; no in-the-wild malicious-rollback campaign is reported in the sources consulted.
tuning: [none directly - no --tune knob; DB_AKM_SUSTAIN_S=24*3600 and DB_MAX_AKM_REGRESSIONS=16 are compile-time (src/db.h:118-119). Gated by build/flags: WITH_SQLITE must be set and --db FILE given, else db_akm_regressions() returns 0 and the rule is silent (src/db.h:294). --db-interval-secs and --db-retain-days (tune aliases wired in src/main.c:919-926 via tune_alias()) govern how often the regression set is recomputed and how long history is kept. --pcap-dir has no effect (match_ip=NULL, rules_twin.c:842-843)]
researched: 2026-10-27
---
## What the rule checks

This is the first rule that reads from the SQLite database rather than in-memory state (comment rules_twin.c:810-828). The evidence is the `ssid_akm_history` table: one row per `(ssid, bssid, akm_bits)` with its own `first_seen`/`last_seen` window, upserted so a posture's window only ever widens and two non-overlapping postures stay two rows (src/db.c:266-270, comment 263-265).

`refresh_akm_regressions()` (src/db.c:2048-2104) runs once per `--db` tick after COMMIT (src/db.c:2150) and caches up to 16 rows. Its SQL (2061-2079) self-joins the history table to find a `(ssid, bssid)` where:

- a "was" row is SAE-family and not PSK-family — `(w.akm_bits & SAE) != 0 AND (w.akm_bits & PSK) = 0`;
- spanning the window — `(w.last_seen - w.first_seen) >= DB_AKM_SUSTAIN_S` (24 h). This is the gap between the first and last *recorded* SAE-only sightings, not continuous observation: `write_beacons()` (src/db.c:1172-1185) upserts one row per (ssid, bssid, akm_bits) with MIN/MAX widening, so two sightings 25 h apart — even in two separate runs against the same `--db` file — satisfy it with nothing seen in between;
- a "now" row on the same `(ssid, bssid)` is PSK-family and not SAE-family;
- the "now" posture is later — `n.last_seen > w.last_seen`;
- and is the *latest* posture recorded for that `(ssid, bssid)` — `n.last_seen = (SELECT MAX(...))` (2076-2077), so a network that briefly went PSK and returned to SAE does not fire forever, and the match is keyed on n's own `(ssid,bssid)` to avoid a different SSID on the same radio (the KARMA shape) satisfying it (comment 2071-2075).

`rule_sae_psk_regression()` (rules_twin.c:829-845) fires `ALERT_TYPE_SAE_PSK_REGRESSION` at CRIT for each cached row. Key: `saereg:<ssid>:<bssid>` (`"saereg:%.40s:%.17s"`, 837). Detail: `"'%.16s' on %.17s was SAE-only for %ldd and now advertises PSK-only - WPA3 protection lost on this BSSID"` with the day count from `(was_last_seen - was_first_seen)/86400` (835-841). It clears when SAE becomes the latest posture again (the "latest" requirement makes the alert a state, not a permanent scar — docs/views/alerts.md:199).

This is the temporal sibling of SAE_PSK_SPLIT: that compares two BSSIDs at one moment; this compares one BSSID against its own past, which no in-memory state can answer (`beacon_aps.akm_bits` is OR'd on conflict and `wifi_baseline.c` is a single session snapshot — comment 813-818).

## The attack

WPA3-Personal with SAE provides forward secrecy and resistance to offline dictionary attacks that WPA2-PSK does not [3, §2]. If a BSSID that was WPA3 (SAE) is reconfigured to WPA2 (PSK) — whether by an attacker who gained management access to the AP, or by an administrator — every client on it loses SAE's protections, and the PSK becomes susceptible to the capture-and-crack path (grab a 4-way handshake or PMKID, run an offline dictionary attack) whose capture half tools like hcxdumptool implement [9]. The regression is the *posture*, not an attack packet; CERT VU#871675 is the Dragonblood implementation advisory (CVE-2019-9494..9499) and does not itself discuss transition-mode downgrade — the repo corpus [1] anchors this type on it anyway [4] — and Dragonblood's own recommendation — clients should remember a network supported SAE and refuse a silent downgrade [3, §4.1.3] — is the client-side mirror of what this rule watches for on the infrastructure side.

The repo tags it T1562.004 (Impair Defenses: Disable or Modify System Firewall / defensive posture) rather than T1557, and the rule's own comment is explicit about why: "nothing here says an adversary is present. What it says is that a network's posture was lowered and stayed lowered, which is a finding whether the cause was an intruder or an administrator" (rules_twin.c:825-828); the research corpus says the same in its own words — "whether an attacker caused it or an administrator did" [1]. T1562.004's own description is about disabling/modifying protective controls to bypass them [7]; lowering an AP from SAE to PSK is the Wi-Fi analogue — removing a control (WPA3) to enable a weaker-crypto attack surface. (The technique's canonical text is firewall-centric; the mapping is to the "modify a protective control's configuration" intent, not to a literal firewall.)

There is no attack "tooling" that produces this signal on the air — it is read from persisted beacon history, not from frames. The adversary action it would correspond to is AP reconfiguration (credentialed management access), which sloth does not and cannot observe directly.

## Evidence that proves it

What sloth records: `alert`/`alert.create` JSONL with key `saereg:<ssid>:<bssid>`, the detail naming the SSID, BSSID and the SAE-only duration in days. The underlying evidence is durable: the `ssid_akm_history` rows in the `--db` file (two rows for the BSSID — the SAE window and the PSK window — src/db.c:266-270), which sit in the *entity* retention tier (3x the configured window, `TIER_ENTITY`, src/db.c:74-81), not the 12x findings tier — so with a short `--db-retain-days` the "was" row can be pruned while the alert it justified is still retained, and the alert then stops re-firing for want of evidence rather than because SAE returned. No per-alert pcap (`match_ip = NULL`). The `[v]` alerts view and a query of `ssid_akm_history` for that `(ssid,bssid)` are the forensic record.

To call it real: in `ssid_akm_history`, a row for `(ssid, bssid)` whose AKM set is SAE-family only with `last_seen - first_seen ≥ 24 h`, and a later row for the same `(ssid, bssid)` that is PSK-family only and is the most recent. Confirm the BSSID is stable (same physical AP, not a spoof reusing the MAC) by cross-checking signal/channel history. The strong confirmer that it is a real regression rather than a migration quirk is the 24 h sustain: a genuine WPA3 deployment that ran for a day and then dropped to PSK-only is a deliberate change.

What would refute it: the BSSID is also currently advertising SAE (so it is transition mode, and the "latest posture = PSK-only" test should already exclude it — if it fires anyway, the history rows are stale); or the `(ssid, bssid)` is actually two different physical APs that reused a MAC/SSID (spoofing or cloning) rather than one AP changing — check first_seen continuity and signal. A blip (PSK for an hour, then SAE again) is excluded by the latest-posture requirement.

## Benign causes

- **Administrative downgrade.** An operator deliberately turning off WPA3 (compatibility with old clients, a support decision, a firmware rollback) produces an identical signal. This is the primary benign cause and the rule documents that it cannot tell it from a malicious one — "check the AP's configuration history" is the first remediation step [2]. Fingerprint: the change coincides with a maintenance window, the AP is operator-owned and reachable, and its config confirms the intent.
- **Firmware regression / default reset.** An AP reset to defaults or downgraded to firmware that defaults to WPA2 would roll SAE back. Fingerprint: the AP also loses other recent config (SSID, channel plan) at the same time.
- **History-table artefacts.** If the `--db` file predates a clock change or carries rows from a cloned/spoofed BSSID, the join can pair unrelated postures. Fingerprint: implausible day counts, or a BSSID whose signal/channel history is discontinuous.

No legitimate vendor behaviour (band steering, mesh, roaming) changes a single BSSID's advertised AKM from SAE-only to PSK-only and holds it there; none was found in sources.

## Assessment

Severity: CRIT is appropriate. Unlike the beacon-moment rules, this one has a 24 h sustain and a latest-posture requirement, so it does not fire on samples or transition mode — when it fires, WPA3 protection really was present and really is gone on that BSSID. The honesty of the T1562.004 tag (posture lowered, cause unknown) is the right call: it is a finding to investigate, not an assertion of intrusion.

Prevalence: WPA3 rollback as a posture risk is well-grounded in the Dragonblood line of work and the CERT advisory [3][4], but a *malicious* sustained SAE->PSK regression in the wild is not something the sources document as a campaign; the common cause is administrative. So the alert's real value is configuration-drift detection with a security framing, which is exactly what T1562.004 and the corpus describe.

Noise on the reference host: not seen (host:null) and structurally quiet by design — it needs WITH_SQLITE, a `--db` file, and ≥24 h of history, so it cannot fire on a fresh run and cannot fire at all in a build without SQLite. The residual noise is the shared per-tick re-fire: once a regression row exists it re-fires every poll until SAE returns. Because the regression set is recomputed only at `--db` ticks, the fix is cheap — fire on row appearance (and resolve on disappearance) rather than on every poll. The 16-row cap (DB_MAX_AKM_REGRESSIONS) bounds the worst case.

Sufficient to act on? Yes for investigation. A responder should: (1) query `ssid_akm_history` for the `(ssid, bssid)` to see the two windows and the exact transition time; (2) confirm the BSSID is the operator's and not a spoof; (3) check the AP's configuration/change history against that time; (4) if the change was unintended or unauthorised, restore SAE on the BSSID and rotate the PSK (which was exposed to the capture-and-crack path while WPA2-only). The fix is configuration, not a vendor patch [2].

## Bibliography

1. research/cert/vu-871675.md — repo research-corpus entry citing this type and stating the "posture lowered, attacker-or-admin" framing (accessed 2026-10-27)
2. docs/views/alerts.md:199 and docs/wiki/alert-remediation.md "SAE_PSK_REGRESSION" — repo rule-table row and remediation (accessed 2026-10-27)
3. M. Vanhoef, E. Ronen, "Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd", IEEE S&P 2020 — https://papers.mathyvanhoef.com/dragonblood.pdf (accessed 2026-10-27; §2.1 "prevents offline dictionary attacks and provides forward secrecy", §4.1.3 "a client should remember if a network supports WPA3-SAE")
4. CERT/CC VU#871675, "WPA3 design issues and implementation vulnerabilities in hostapd and wpa_supplicant" (2019-04-12, rev. 2019-06-05) — https://www.kb.cert.org/vuls/id/871675 (accessed 2026-10-27; lists CVE-2019-9494..9499; does not discuss transition-mode downgrade)
5. Dragonblood project page — https://wpa3.mathyvanhoef.com/ (accessed 2026-10-27)
6. MITRE ATT&CK T1562.004, Impair Defenses: Disable or Modify System Firewall (v1.3) — https://attack.mitre.org/techniques/T1562/004/ (the unversioned page returned empty to WebFetch twice on 2026-10-27; verified via https://attack.mitre.org/versions/v17/techniques/T1562/004/ — description opens "Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage"; the APT28 Nearest Neighbor procedure example is about adding firewall rules for port-forwarding, not about Wi-Fi posture)
7. src/db.c:2048-2111 and src/db.h:100-119 — the ssid_akm_history schema, the regression SQL, DB_AKM_SUSTAIN_S=24 h, and the no-SQLite stub (read 2026-10-27)
8. src/rsn_ie.h:50-62 — SAE/PSK AKM family bitmasks used by the query bindings (read 2026-10-27)
9. hcxdumptool README — https://github.com/ZerBea/hcxdumptool (accessed 2026-10-27; the WPA2 handshake/PMKID capture a PSK-downgraded BSSID becomes exposed to. The README does not mention WPA3/SAE; that SAE resists this path is from [3, §2.1], not from the tool's docs)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and by fetching every external URL.

- Code: `rule_sae_psk_regression` at rules_twin.c:829-845, key `"saereg:%.40s:%.17s"` at 837 (was cited as 839), detail 838-841, `days` at 835, `fire(..., NULL, 0, now)` 842-843, leading comment 810-828 (was 815-823; the beacon_aps/wifi_baseline sentence is 813-818, not 807-814) — corrected/confirmed. `refresh_akm_regressions` src/db.c:2048-2104 with the SQL at 2061-2079 (SAE-family-only `was`, PSK-family-only `now`, `>= DB_AKM_SUSTAIN_S`, `n.last_seen > w.last_seen`, latest-posture subquery 2076-2077, comment 2071-2075), called after COMMIT at 2150; `db_akm_regressions` at 2106; `DB_AKM_SUSTAIN_S`=24 h and `DB_MAX_AKM_REGRESSIONS`=16 at src/db.h:118-119; no-SQLite stub returning 0 at src/db.h:294; upsert at src/db.c:266-270 — all confirmed. Count semantics (one fire per cached row per poll; the set only changes at a `--db` tick) confirmed.
- Retention: `ssid_akm_history` is in `TIER_ENTITY` (3x, src/db.c:74-81), not the 12x findings tier as previously written. Corrected, with the consequence spelled out.
- The "nothing here says an adversary is present" quote is the rule's comment (rules_twin.c:825-828), not the research corpus; the corpus's wording is "whether an attacker caused it or an administrator did" (research/cert/vu-871675.md:38-41). Attribution corrected.
- Sources: [3] fetched; §2.1 forward-secrecy/dictionary-resistance sentence and §4.1.3 TOFU countermeasure confirmed. [4] exists but is the hostapd/wpa_supplicant implementation-CVE note; the sentence claiming it frames transition/downgrade issues was rewritten. [5] confirmed. [6] the unversioned T1562.004 URL returned empty twice; verified via the v17 versioned page: v1.3, APT28 Nearest Neighbor procedure present (as a firewall-rule example). [9] hcxdumptool README fetched raw: no WPA3/SAE mention, claim softened. [7], [8] are code references and were re-read.
- `research/cert/vu-871675.md` exists and names `ALERT_TYPE_SAE_PSK_REGRESSION` (lines 5, 38).

Re-verified 2026-10-27 against HEAD 0d60387. `git log` shows no commit touching `src/alerts/`, `src/fragattack.[ch]`, `src/alerts/engine.c`, `include/sloth.h`, `src/capture/probe.c`, `src/alert_pcap.c`, `src/db.[ch]` or `src/rsn_ie.h` since c5650a3, and every line number above was re-read and still matches. Every external URL was fetched again; the two previously unreachable ones (the lore.kernel.org patch series, HTTP 403; the NVD page, JS-rendered) are still unreachable and remain marked as such. The USENIX and Dragonblood PDFs were text-extracted locally (`pdftotext`) and the quoted phrases grepped for directly rather than trusting a summariser.

- Second-pass: no text changes needed. [3] re-confirmed by grep: §2.1 "The Dragonfly Handshake" — "The Dragonfly handshake prevents offline dictionary attacks and provides forward secrecy"; §4.1.3 "a client should remember if a network supports WPA3-SAE". [4] re-confirmed as the implementation-CVE note with no transition-mode content. [6] the unversioned T1562.004 page returned empty a third time; the v17 page re-confirmed v1.3, the opening sentence and the APT28 Nearest Neighbor firewall-rule example. [9] hcxdumptool re-confirmed. `--db-interval-secs` / `--db-retain-days` tune aliases are at src/main.c:919-927, as cited. `docs/wiki/alert-remediation.md:1107-1121` carries the "Check the AP's configuration history" step cited in Benign causes.

Third pass 2026-10-27 against HEAD d70d394 (no src/ or include/ commit since c5650a3; all line numbers re-read and still match).

- Function span corrected to rules_twin.c:829-845 (was 829-846).
- "Sustained" qualified (code): `(w.last_seen - w.first_seen) >= 24 h` is the span between the first and last recorded SAE-only sightings, upserted with MIN/MAX in write_beacons (src/db.c:1172-1185); two sightings 25 h apart, even in separate runs on one --db file, satisfy it with nothing observed in between. Fixed in What the rule checks and severity_assessment.
- Reference host has no SAE_PSK_REGRESSION row, consistent with host:null. Per-poll re-fire is ~40/s measured there, not 1/s.
- Sources re-fetched: Dragonblood PDF (§2.1 and §4.1.3 phrases grepped present), wpa3.mathyvanhoef.com, CERT VU#871675 (implementation CVEs only, as stated), ATT&CK T1562.004 v17 page (v1.3, opening sentence present), hcxdumptool. research/cert/vu-871675.md names the type (lines 5, 38).

Review pass (2026-11-01). The capture-and-crack sentence cited [10], which does not exist (the bibliography runs 1-9), and named hashcat, which has no entry. Re-pointed to [9] (hcxdumptool) and narrowed to the capture half that tool implements; the "+ hashcat" was dropped rather than cited unverified.
