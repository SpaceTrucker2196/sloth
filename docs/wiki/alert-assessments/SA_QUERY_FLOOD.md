---
type: SA_QUERY_FLOOD
technique: T1499
rule_file: src/alerts/rules_wifi_mgmt.c:402 rule_sa_query_flood()
count_semantics: per evaluation tick, per (BSSID, STA) key, while a storm stands. fire_ev() bumps count every poll (>= 4/s; POLL_MS 250 is the longest wait) in which that pair's in-window SA-Query total is still >= threshold; one increment is one poll, NOT one SA-Query frame. The measurement (saq_flood_pair) counts stamps in the pair's own timestamp ring (SAQ_FLOOD_THRESH*4 = 48 slots) that fall inside the window, so the detail's "N SA-Query frames" is a per-frame count and the alert's count is per tick; the ring slides, so an old burst does not keep the pair over threshold
severity_assessment: agree - CRIT with no ownership split is defensible: a sustained SA Query storm is the AP successfully refusing spoofed disassociations under MFP, i.e. an attack in progress against that BSS whoever owns it, and the rule says so rather than overclaiming the attacker's frames it never heard
false_positive_risk: low-to-medium - a legitimate SA Query exchange is a handful of frames over a few hundred milliseconds (hostapd default dot11AssociationSAQueryMaximumTimeout 1000 TU), far below 12 in 10 s; the residual risk is a client or AP SA-Query state-machine bug, and (before 2026-10-14) a parser artefact that read protected-frame ciphertext as an SA Query category
noise_verdict: a confined burst on the reference host - 30 keys, 30,645 fires, max_sev CRIT, 0 reopens, and seen only 2026-10-15..10-20 (a five-day window, then nothing for the remaining two weeks of the capture). 30,645 fires over 30 (BSSID, STA) keys is about 1,020 evaluations per pair; at >= 4/s that is at most about 4 minutes of standing storm per pair, and 0 reopens means no pair's incident ever resolved and re-fired - each pair stormed once, continuously, inside that window. A set of 30 pairs active for five days and then silent points at a bounded cause - one AP or client population, or a change on the sensor side such as the 2026-10-14 protected-frame parser fix settling in - without the host data saying which
prevalence: the MFP-era successor to deauth flooding; its visibility is a side effect of 802.11w being deployed, and it is cited from two directions - T1499 endpoint DoS [1b] and CVE-2019-16275's PMF-bypass class [1a]. No fetched source quantifies a field rate, so none is claimed
tuning: [saq.flood_thresh (TUNE_SAQ_FLOOD_THRESH, default 12, 2..48), saq.flood_window_s (TUNE_SAQ_FLOOD_WINDOW_S, default 10, 1..3600), --collect-handshakes + --eapol-dir (gates the evidence pcap; CRIT already clears the default pcap.min_severity floor), --hop/--monitor-only (needs monitor mode to hear the Action frames)]
researched: 2026-11-03
---
## What the rule checks

`rule_sa_query_flood()` (src/alerts/rules_wifi_mgmt.c:402-430) finds the
busiest (BSSID, STA) pair by in-window SA-Query volume and fires if it
crosses the threshold.

- **Input.** `saq_flood_pair(now, win, thresh, &bssid, &sta, &count)`
  (src/action_snoop.c:244-264) walks up to `SAQ_MAX_PAIRS` = 64 pairs
  (src/action_snoop.c:204), counts each pair's timestamps inside the
  window (src/action_snoop.c:254), and returns the busiest pair's count
  if it is `>= thresh`, else 0 (src/action_snoop.c:263). A stamp is
  written by `saq_observe()` (src/action_snoop.c:211-243) from
  `action_observe_frame()` (src/action_snoop.c:422-426) for every
  Action frame of category `ACTION_CAT_SA_QUERY` = 8
  (src/action_snoop.h:29); the STA is "whichever address is not the
  BSSID" and group addresses are excluded (src/action_snoop.c:423-426).
  Each pair's ring is `SAQ_FLOOD_THRESH*4` = 48 timestamps
  (src/action_snoop.c:192-202); it is a sliding window, not a counter,
  so a legitimate burst an hour ago does not keep the pair over
  threshold (src/action_snoop.c:234-239 comment).
- **Protected SA Query is invisible (#124).** `action_observe_frame()`
  returns early on a frame whose Protected bit is set, tallying it as
  `g_protected` and parsing nothing (src/action_snoop.c:380-389). On a
  PMF link SA Query is itself CCMP ciphertext, so the AP's protected SA
  Queries are not counted here; what this rule sees is *unprotected* SA
  Query, which on a non-PMF BSS is a finding of its own. Before
  2026-10-14 the parser read the first ciphertext octet as a category,
  so a protected Action frame whose PN0 was 0x08 counted toward this rule
  (a 1/256 source of false firings on PMF networks)
  (docs/views/alerts.md:189).
- **Thresholds** (registry, src/tune.c:195-196): `saq.flood_thresh`
  default `SAQ_FLOOD_THRESH` = 12 (src/action_snoop.h:282),
  `saq.flood_window_s` default `SAQ_FLOOD_WIN_SECS` = 10
  (src/action_snoop.h:281).
- **Condition.** `saq_flood_pair(...)` returns non-zero (line 407
  returns otherwise).
- **Key.** `saqflood:<bssid>:<sta>` (line 414) - per pair, so two
  stations being queried are two exchanges; merging them would let
  ordinary traffic on a busy BSS reach the threshold.
- **Detail.** `<n> SA-Query frames in <win>s between <bssid> and <sta>
  - the AP is refusing spoofed disassociations` (lines 416-418).
- **Severity.** `ALERT_SEV_CRIT`, unconditionally (line 428). The
  comment (lines 419-424) is the rationale: a legitimate exchange is a
  handful of frames over a few hundred milliseconds, so anything
  sustained means the AP is fending something off and MFP is working -
  worth telling the operator precisely because nothing else will.
- **Evidence.** `fire_ev()` with `saq_flood_evidence(bssid, sta, now,
  win, ...)` (src/action_snoop.c:266-289): the pair's newest in-window
  SA-Query frames - the AP's answers, not the attacker's questions -
  up to `ALERT_EVIDENCE_IDS` = 8 (include/sloth.h:854). No `match_ip`
  (line 428): the evidence ring is the only route back to bytes
  (docs/wiki/pcap-export.md:153).

Count semantics: `fire_ev()` calls `fire_inv()`, which bumps
`evaluations`/`count` every re-assertion (src/alerts/engine.c:479-480)
and `observations` only when the detail or severity changed (:488-491).
The incident resolves `ALERT_RESOLVE_AFTER_S` = 300 s after the last
assertion (include/sloth.h:860). `POLL_MS` = 250 is the longest wait
between polls (include/sloth.h:28); the loop wakes early on new keys, so
polls per second are >= 4 and any duration from `count / 4` is an upper
bound.

## The mechanism

SA Query is management-frame protection's own mechanism. When an AP on
an MFP-protected BSS receives an *unprotected* disassociation or
deauthentication claiming to be from an associated station, it does not
act on it: it sends an SA Query Request and waits for the station to
answer, and the spoofed frame is discarded (hostapd starts exactly this
on the AP side - "STA has already been associated with MFP and SA Query
timeout has not been reached. Reject the association attempt temporarily
and start SA Query, if one is not pending") [5]. On the client side
wpa_supplicant does the same on an unprotected disconnect ("SME:
Unprotected disconnect dropped - possible AP/STA state mismatch -
trigger SA Query") and only gives up, deauthenticating, when the query
times out ("SME: SA Query timed out") [6].

So a storm of SA Queries is not an attack on the client - it is the
visible symptom of someone spraying spoofed disassociations at an
MFP-protected network, which is what deauth flooding becomes once MFP
takes the direct route away [1b]. The repo corpus note states it: "the
one that is mostly a *symptom*: the AP is answering spoofed
disassociations. What it costs is the queried station's airtime and, if
the exchange fails, its association" [1b]. CVE-2019-16275 cites the same
exchange from the other direction: a storm of SA Queries is "a network
*successfully* defending itself against the attack class this CVE is
about" [1a].

The detection choice is deliberate and is the rule's reason to exist.
The attacker's own frames are aimed at the AP and may never be heard - a
directional antenna from across a car park does not reach a monitor
radio by the AP, and a hopping sensor may be on another channel - but
the AP's response goes out on the BSS's own channel at ordinary power and
is heard (src/action_snoop.c:261-280 comment; docs/wiki/action-frames.md
lines 34-58). Detecting the answer rather than the question is why this
rule earns a place beside the deauth-flood rule.

A legitimate SA Query is short: hostapd's `dot11AssociationSAQueryMaximum
Timeout` defaults to 1000 TU (about 1.024 s) and the retry timeout to a
small value, with the retries measured in TU = 1.024 ms [7], so a real
exchange is a handful of frames over a fraction of a second. Twelve in
ten seconds is comfortably above that and below what a flood produces.

## Evidence that proves it

What sloth records:

- The alert detail: `<n> SA-Query frames in <win>s between <bssid> and
  <sta> - the AP is refusing spoofed disassociations`.
- Cited evidence frames via the evidence ring: the pair's newest
  in-window SA-Query frames - the AP's answers, which is what the rule
  hears (docs/wiki/pcap-export.md:153). With `--collect-handshakes` and
  `--eapol-dir`, the per-alert evidence pcap holds them; CRIT already
  clears the default `pcap.min_severity` floor.
- The `[a]` action view's `protected action` row
  (docs/views/deauth.md:166-178): on a PMF link the SA Queries are
  ciphertext and are counted there, not parsed - so a large protected
  count beside a quiet SA-Query rate means the exchange is there and
  unreadable, not absent.
- `sensor_health`: no counter is specific to this rule, but the monitor
  radio's frame totals move (docs/wiki/jsonl-schema.md:1069).

To call it real: a sustained SA-Query rate between one BSSID and one STA
well above a sub-second exchange, ideally with a `DEAUTH_FLOOD` or
unprotected-disassoc finding at the same BSSID (the questions, if sloth
happened to hear them), and no benign state-machine churn in the same
window. Because the rule counts only *unprotected* SA Query, a storm here
also tells you the SA Query traffic was in the clear, which on a BSS that
advertises PMF is itself anomalous.

What refutes it: the count sits at or just over the threshold and
coincides with a known client or AP SA-Query implementation bug; or the
firing predates 2026-10-14 and the BSS runs PMF, in which case it may be
the pre-fix parser artefact that read protected ciphertext as category 8
(docs/views/alerts.md:189).

## Benign causes

- **An SA-Query state-machine bug.** A client or AP that retries SA
  Query more than the standard's short sequence - a non-conforming
  implementation looping - produces the frames without an attacker. The
  per-pair key isolates it to the one (BSSID, STA) involved.
- **Pre-2026-10-14 parser artefact.** Before the #124 fix the parser
  read the first ciphertext octet of a protected Action frame as a
  category, so any protected Action frame with PN0 = 0x08 counted as SA
  Query (a 1/256 source). Firings recorded before that date on a PMF BSS
  may be this, not a storm (docs/views/alerts.md:189;
  docs/wiki/action-frames.md:126-129).
- **A genuine spoofed-disassoc campaign.** The case the rule is for: the
  AP answering a deauth/disassoc flood under MFP [1a][1b].

Tell them apart by the rate (a bug tends to sit near threshold; a storm
runs far above), by whether the BSS actually advertises PMF, by the
firing date relative to the 2026-10-14 fix, and by a correlated
`DEAUTH_FLOOD` at the same BSSID.

## Assessment

**Severity.** CRIT, no ownership split, is defensible. Unlike the deauth
and auth rules, this one has no `--my-bssid` escalation because its
finding is not "a flood aimed at an AP" but "an AP is actively refusing
an attack" - a state that is serious wherever it happens, and one the
operator will not learn about any other way, because the attacker's
frames may be unheard. The detail is careful to claim only what was
observed (the AP's answers), not the attacker's questions.

**Prevalence.** This is the MFP-era shape of deauth flooding, so its
field incidence tracks 802.11w deployment: it appears precisely where
PMF has made the direct deauth route fail [1a][1b]. No fetched source
quantifies a field rate, so none is claimed.

**Reference host:** 30 keys, 30,645 fires, CRIT, 0 reopens, and seen
only between 2026-10-15 and 2026-10-20 - a five-day window inside a
twenty-day capture, then nothing. 30,645 evaluations over 30 pairs is
about 1,020 ticks per pair; at >= 4/s that is at most about 4 minutes of
standing storm per pair. The 0 reopens is the telling figure: no pair's
incident ever resolved and re-fired, so each of the 30 pairs stormed once
and continuously within that window rather than flapping. A set of 30
pairs that is active for five days and then entirely silent points at a
bounded cause - a specific AP or client population that was present and
then left, or a sensor-side change such as the 2026-10-14 protected-frame
parser fix (#124) taking effect and no longer miscounting ciphertext -
and the host data alone does not say which; the `alert.create` timestamps
and the affected BSSIDs would. Noise is low: the per-pair key already
collapses each exchange to one incident, and the window slides, so there
is nothing to throttle.

**Sufficient to act on alone?** As a CRIT, it is a strong prompt but not
a closed case, because what sloth hears is the defence, not the attack.
First response: note the BSSID and station (not a spoofable transmitter -
this rule heard the AP). Confirm the BSS advertises PMF and check the
firing date against the 2026-10-14 parser fix to rule out the artefact.
Read the AP's logs, which may be the only other record of the spoofed
frames [8]. Look for a correlated `DEAUTH_FLOOD` / unprotected-disassoc
finding at the same BSSID (the questions). Keep MFP required and the AP
firmware current - hostapd before 2.10 mishandled this class
(CVE-2019-16275) - and locate the transmitter of the spoofed frames
(docs/wiki/alert-remediation.md:1202-1219). If a state-machine bug makes
one pair noisy, raise `saq.flood_thresh` or widen `saq.flood_window_s`
via `--tune` (src/tune.c:195-196).

## Bibliography

1. research/cve/2019-16275.md - repo corpus document citing ALERT_TYPE_SA_QUERY_FLOOD as "[1a]" ("a network *successfully* defending itself against the attack class this CVE is about"); research/mitre/T1499.md cites it as "[1b]" ("the one that is mostly a *symptom*") (sources: https://nvd.nist.gov/vuln/detail/CVE-2019-16275 and https://attack.mitre.org/techniques/T1499/, both retrieved 2026-09-07) (accessed 2026-11-03)
2. MITRE ATT&CK T1499, Endpoint Denial of Service - https://attack.mitre.org/techniques/T1499/ (accessed 2026-11-03)
3. NVD, CVE-2019-16275 ("hostapd before 2.10 ... allow an incorrect indication of disconnection ... because source address validation is mishandled"; CVSS 3.1 6.5 MEDIUM AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H; CWE-346; published 2019-09-12) - https://nvd.nist.gov/vuln/detail/CVE-2019-16275 (accessed 2026-11-03 via https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-16275)
4. hostapd security advisory 2019-7, "AP mode PMF disconnection protection bypass" (the spoofed-disconnect class SA Query defends against) - https://w1.fi/security/2019-7/ap-mode-pmf-disconnection-protection-bypass.txt (accessed 2026-11-03)
5. hostapd src/ap/ieee802_11.c, check_assoc_ies() ("STA has already been associated with MFP and SA Query timeout has not been reached. Reject the association attempt temporarily and start SA Query") - https://fuchsia.googlesource.com/third_party/hostap/+/refs/heads/main/src/ap/ieee802_11.c (accessed 2026-11-03)
6. wpa_supplicant wpa_supplicant/sme.c, sme_event_unprot_disconnect() / sme_check_sa_query_timeout() ("SME: Unprotected disconnect dropped - possible AP/STA state mismatch - trigger SA Query"; "SME: SA Query timed out") - https://fuchsia.googlesource.com/third_party/hostap/+/refs/heads/main/wpa_supplicant/sme.c (accessed 2026-11-03)
7. hostapd.conf reference, `assoc_sa_query_max_timeout` / `assoc_sa_query_retry_timeout` ("in TU = 1.024 ms; for MFP"; dot11AssociationSAQueryMaximumTimeout) - https://fuchsia.googlesource.com/third_party/hostap/+/refs/heads/main/hostapd/hostapd.conf (accessed 2026-11-03)
8. docs/views/alerts.md:189 - sloth rule-table row for SA_QUERY_FLOOD, incl. the #124 scope and the pre-2026-10-14 parser artefact note (accessed 2026-11-03)

## Verification notes

Verified 2026-11-03 against the working tree (HEAD 8ac44d5) and by
fetching every external source.

Code: `rule_sa_query_flood()` at src/alerts/rules_wifi_mgmt.c:402-430 -
`saq_flood_pair()` (src/action_snoop.c:244-264) over up to
`SAQ_MAX_PAIRS` 64 pairs (src/action_snoop.c:204), each a 48-slot
timestamp ring (`SAQ_FLOOD_THRESH*4`, src/action_snoop.c:192-202), fed by
`saq_observe()` (src/action_snoop.c:211-243) from `action_observe_frame()`
category 8 (src/action_snoop.c:422-426), STA = non-BSSID address with
group addresses excluded (src/action_snoop.c:423-426). Early return on no
pair over threshold (line 407), key `saqflood:<bssid>:<sta>` (line 414),
CRIT unconditional (line 428), `fire_ev()` with `saq_flood_evidence()`
(src/action_snoop.c:266-289), no `match_ip` - all as written. Protected
frames bail early and are tallied as `g_protected`
(src/action_snoop.c:380-389). Thresholds `SAQ_FLOOD_THRESH` 12 /
`SAQ_FLOOD_WIN_SECS` 10 (src/action_snoop.h:281-282); registry
`saq.flood_thresh` 2..SAQ_FLOOD_THRESH*4 (= 48) / `saq.flood_window_s`
1..3600 (src/tune.c:195-196). `ALERT_EVIDENCE_IDS` 8
(include/sloth.h:854), `ALERT_RESOLVE_AFTER_S` 300 (:860), `POLL_MS` 250
(:28).

Count semantics: `fire_ev()` -> `fire_inv()` bumps `evaluations`/`count`
every re-assertion (src/alerts/engine.c:479-480), `observations` only on
a detail/severity change (:488-491); the "N SA-Query frames" figure is
per frame, the alert's count per tick.

Noise arithmetic: 30,645 / 30 keys = 1,021 evaluations per pair; 1,021 /
4 = 255 s = 4.3 min standing per pair, an upper bound. 0 reopens =
30 pairs, 30 incidents, each a single continuous storm. Checks.

Sources: [2] MITRE T1499 fetched; endpoint-DoS definition verbatim (see
AUTH_FLOOD). [3] NVD CVE-2019-16275 fetched via the NVD REST API;
description "hostapd before 2.10 ... allow an incorrect indication of
disconnection in certain situations ... because source address validation
is mishandled", CVSS 3.1 base 6.5 MEDIUM, vector
AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H, CWE-346, published 2019-09-12 - all
verbatim. [4] hostapd advisory 2019-7 text fetched; "did not perform
sufficient source address validation", stations "incorrectly believe they
were disconnected ... even if management frame protection", "inject a
specially constructed unauthenticated IEEE 802.11 frame", affected "All
hostapd and wpa_supplicants versions with PMF support (CONFIG_IEEE80211W=
y)", fix "AP: Silently ignore management frame from unexpected source
address" / "v2.10 or newer" - all verbatim; the file names no SA Query,
so this entry is cited only for the spoofed-disconnect class, not for the
SA Query text. [5] ieee802_11.c (upstream fuchsia mirror) fetched; the
check_assoc_ies() comment and `WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY` /
`ap_sta_start_sa_query()` confirmed verbatim. [6] sme.c (same mirror)
fetched; "SME: Unprotected disconnect dropped - possible AP/STA state
mismatch - trigger SA Query", "SME: Association SA Query attempt %d",
"SME: SA Query timed out" and the timeout -> deauthenticate path all
verbatim. [7] hostapd.conf (same mirror) fetched; the two SA-Query-timeout
comments with "in TU = 1.024 ms; for MFP" verbatim. [1a]/[1b]
research/cve/2019-16275.md and research/mitre/T1499.md both list
`ALERT_TYPE_SA_QUERY_FLOOD` in `alert_kinds`; the quoted sentences are in
their text. [8] docs/views/alerts.md:189 is the SA_QUERY_FLOOD row.

Struck: w1.fi's cgit paths (hostapd.conf, ChangeLog, src/ap/ieee802_11.c,
wpa_supplicant/sme.c) all served an Anubis bot-wall (an access-denied
page returned 200) or redirected to git.w1.fi which did the same; the
upstream source and config comments are quoted from the
fuchsia.googlesource.com mirror of hostap instead, which returned each
file. nvd.nist.gov's HTML detail page rendered empty, so the record was
read from the NVD REST API. No claim rests on a page that did not return.
Vanhoef's PMF/Dragonblood PDFs were fetched but their body text is in
compressed streams the fetcher could not read (only the Dragonblood
title, authors and a DoS-in-WPA3 abstract line extracted, which is not
about SA Query), so no Vanhoef claim is made here - the SA Query
mechanism is cited from the hostapd/wpa_supplicant source and the CVE
instead.
