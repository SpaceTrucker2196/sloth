---
type: AUTH_FLOOD
technique: T1499
rule_file: src/alerts/rules_wifi_mgmt.c:107 rule_auth_flood()
count_semantics: per evaluation tick, per BSSID key, while a flood stands. fire_ev() bumps count every poll (>= 4/s; POLL_MS 250 is the longest wait) in which the busiest BSSID's in-window 802.11 Authentication-frame total is still >= threshold; one increment is one poll, NOT one auth frame. The measurement (auth_flood_bssid) counts every frame in the 512-slot AUTH_RING over the window, retransmissions included - nothing dedupes the Retry bit or sequence number - so the detail's "N auth frames" is a per-frame count while the alert's own count is per tick
severity_assessment: agree - WARN off your network, CRIT on a --my-bssid BSSID, matches the impact: an association-table exhaustion DoS only becomes critical when it is filling an AP the operator owns
false_positive_risk: low - 30 auth frames to one BSSID in 5 s is far above any roaming or reconnect rate; the realistic benign trip is a broken client reauth-looping, and because retransmissions count, a weak-signal client retrying hard can inflate one BSSID's tally
noise_verdict: present and quiet on the reference host - 8 keys, 7,443 fires, max_sev CRIT, 42 reopens over 2026-10-14..11-01. Fires are re-evaluations (>= 4/s), not frames; 7,443 across 8 BSSID keys is about 930 evaluations per key, and with 42 reopens spread over them each incident holds for only tens of seconds - short bursts per AP, not a standing firehose. The per-BSSID key already dedupes; no extra throttle is needed. CRIT means at least one flooded BSSID was --my-bssid designated
prevalence: a textbook, long-documented 802.11 DoS [1][6], and a one-flag tool mode (mdk4 "a") [3]; less common in the field than deauth flooding because deauth tooling is more ubiquitous, and PMF does not stop auth/assoc exhaustion because it precedes key establishment. No fetched source quantifies a field rate, so none is claimed
tuning: [auth.flood_thresh (TUNE_AUTH_FLOOD_THRESH, default 30, 2..512), auth.flood_window_s (TUNE_AUTH_FLOOD_WINDOW_S, default 5, 1..3600), --my-bssid (WARN->CRIT, #52), --collect-handshakes + --eapol-dir + pcap.min_severity (a WARN flood writes no evidence pcap until it is CRIT or the floor is lowered)]
researched: 2026-11-03
---
## What the rule checks

`rule_auth_flood()` (src/alerts/rules_wifi_mgmt.c:107-132) finds the
busiest BSSID by in-window Authentication-frame volume and fires when it
crosses the threshold.

- **Input.** `auth_flood_bssid(now, win, thresh, bssid)`
  (src/auth_track.c:46-74) walks the 512-slot `AUTH_RING`
  (src/auth_track.c:8), tallies frames per BSSID inside the window from
  each BSSID's first in-window slot (so each distinct BSSID is scored
  once per pass, src/auth_track.c:52-62), and returns the highest count
  with that BSSID. A frame enters the ring when probe.c hands a parsed
  Authentication frame (management subtype 11) to `auth_observe_ev()`
  (src/capture/probe.c:681), which records `(bssid, now, event_id)`
  (src/auth_track.c:19-25). addr3 is the BSSID being authenticated to
  (src/capture/probe.c:678-680).
- **Retransmissions count.** `auth_observe_ev()` records every parsed
  auth frame; nothing dedupes on the Retry bit or sequence number, so a
  client resending an unacknowledged auth several times contributes each
  copy. The first-in-window-slot test (src/auth_track.c:52-62) only
  stops a BSSID being scored twice in one pass; it does not deduplicate
  frames.
- **Thresholds** (registry, src/tune.c:187-188): `auth.flood_thresh`
  default `AUTH_FLOOD_THRESH` = 30 (include/sloth.h:1249),
  `auth.flood_window_s` default `AUTH_FLOOD_WIN_SECS` = 5 (:1250). The
  512-slot ring is shared by all BSSIDs, so a long tuned window in a busy
  environment looks back only as far as the last 512 auth frames heard
  anywhere, and `n` can never exceed 512.
- **Condition.** `n >= thresh` (line 116 returns otherwise).
- **Key.** `authflood:<bssid>` (line 122) - per-AP, so a busy roaming
  environment is one incident per AP, not many.
- **Detail.** `<n> auth frames to <bssid> in <win>s (assoc-table DoS)`
  with ` - YOUR network` appended when the BSSID is `--my-bssid`
  designated (lines 124-126).
- **Severity.** `ownership_is_my_bssid(bssid)` (src/ownership.c:122-127)
  -> CRIT, else WARN (lines 121, 130-131).
- **Evidence.** `fire_ev()` with `auth_flood_evidence(bssid, now, win,
  ...)` (src/auth_track.c:28-44): the newest in-window Authentication
  frames to the BSSID, walked newest-first with the same window test the
  count used, up to `ALERT_EVIDENCE_IDS` = 8 (include/sloth.h:854). No
  `match_ip` (line 131): an auth frame has no IP, so the evidence ring is
  the only route back to the flood's bytes
  (docs/wiki/pcap-export.md:150).

Count semantics: `fire_ev()` calls `fire_inv()`, which bumps
`evaluations`/`count` every re-assertion (src/alerts/engine.c:479-480)
and `observations` only when the detail or severity changed (:488-491).
The incident resolves `ALERT_RESOLVE_AFTER_S` = 300 s after the last
assertion (include/sloth.h:860). `POLL_MS` = 250 is the longest wait
between polls (include/sloth.h:28); the loop wakes early on new keys and
escalations, so polls per second are >= 4 and any duration from
`count / 4` is an upper bound.

## The mechanism

T1499, Endpoint Denial of Service: "Adversaries may perform Endpoint
Denial of Service (DoS) attacks to degrade or block the availability of
services to users" [2] - exhausting a finite resource inside one machine
rather than the link between machines. The repo corpus note states the
802.11 instance: "`AUTH_FLOOD` - authentication requests filling an AP's
association table. The table is a few hundred entries; the flood does not
have to saturate anything else" [1]. hostapd's own station table caps at
IEEE 802.11's limit of 2007 association IDs ("max_num_sta ... default:
2007") [7], so the resource is real and bounded.

Each Authentication frame drives the AP's state machine toward
allocating per-station state; a flood, typically from many spoofed
source MACs so each frame looks like a new client, drives that state
toward its cap, after which real clients cannot authenticate or
associate. The attacker gains denial of service only - no interception,
no credential. The tooling is a single mode: mdk4's mode `a` "Sends
authentication frames to all APs found in range" and the README warns
"Too many clients can freeze or reset several APs" [3]. Bellardo and
Savage's 2003 experimental analysis of 802.11 management-frame DoS is
the foundational reference for this class of attack [6].

Critically, this attack is not stopped by 802.11w / PMF: authentication
and association precede key establishment, so there is no pairwise key
with which to protect the frames. That is why sloth watches auth/assoc
exhaustion separately from the deauth family, and why MFP deployment
tends to push attackers toward exactly this shape (the corpus note files
`AUTH_FLOOD` and `SA_QUERY_FLOOD` together under T1499 [1]).

## Evidence that proves it

What sloth records:

- The alert detail: `<n> auth frames to <bssid> in <win>s
  (assoc-table DoS)`, plus ` - YOUR network` when the BSSID is owned.
- Cited evidence frames via the evidence ring: the newest in-window
  Authentication frames to the flooded BSSID
  (docs/wiki/pcap-export.md:150). With `--collect-handshakes` and
  `--eapol-dir` and a WARN-or-lower `pcap.min_severity`, the per-alert
  evidence pcap holds those frames.
- `sensor_health` carries no counter specific to this rule, but the
  monitor radio's frame totals and `monitor_recv_delta` move
  (docs/wiki/jsonl-schema.md:1069).
- There is no dedicated `auth` JSONL record; the flood surfaces through
  the alert, and any association the AP did grant shows as an `assoc`
  JSONL record (status 0).

To call it real: a high in-window count from source MACs that are
random-looking and mostly locally-administered, very few of them
completing an association (no matching `assoc` grants), and the cited
frames forming a tight burst to one BSSID with addr2 values that never
appear as real traffic sources. A flood aimed at a `--my-bssid` AP, with
that AP's own logs showing clients refused during the window, is the
strongest confirmation.

What refutes it: the count comes from one or two real STA MACs
reauthenticating - a broken supplicant or a flapping link, visible as a
single `sta_mac` reappearing in `assoc`/`wifi_assoc_req`, not a spoofed
swarm. Because retransmissions count, a weak-signal client retrying hard
is the plausible single-source trip.

## Benign causes

- **A malfunctioning client re-authenticating in a loop.** One STA
  re-sending auth repeatedly; the evidence frames share a source MAC.
  This is the realistic false trip, and it is made more likely by the
  fact that retransmissions are counted (src/auth_track.c:19-25, which
  records every frame).
- **A mass reconnect event.** A controller reboot or a channel-wide
  reconfiguration can make many real clients reauthenticate at once -
  but 30 auth frames to one BSSID in 5 s is well above a normal roam, so
  a sustained trip from this cause is unlikely.
- **Retransmissions inflate a single source.** Nothing filters the Retry
  bit, so a hard-retrying client contributes each copy; a weak link plus
  repeated attempts can reach the threshold from one STA.

Tell them apart by the distinct-source count in the cited frames (a
spoofed flood is many locally-administered MACs; a broken client is one),
by whether any `assoc` grants keep pace, and by whose BSSID it is.

## Assessment

**Severity.** WARN off-network, CRIT on `--my-bssid`, is right: the
impact of an availability attack depends entirely on whether it is the
operator's AP whose table is filling. This is the same ownership
escalation (#52) the whole flood set uses, and severity encodes stakes,
not confidence.

**Prevalence.** Auth/assoc flooding is well documented [1][6] and a
one-flag tool mode [3], but in the field it is less common than deauth
flooding because deauth tooling is more ubiquitous; PMF has nudged some
attackers toward auth/assoc exhaustion precisely because it is not
protected by 802.11w. No fetched source quantifies a field rate, so none
is claimed.

**Reference host:** 8 keys, 7,443 fires, CRIT, 42 reopens, 2026-10-14 to
2026-11-01. Fires are re-evaluations at >= 4/s, not frames: 7,443 across
8 BSSID keys is roughly 930 evaluations per key, and with 42 reopens
distributed over those keys each individual incident holds for only tens
of seconds - short per-AP bursts, re-asserted each tick while standing,
not a continuous flood. The CRIT means at least one of the eight flooded
BSSIDs was `--my-bssid` designated, which is the firing worth attention.
The per-BSSID key already collapses a busy AP to one incident, so there
is nothing to throttle; `observations` (not `count`) is the figure to
trend, since it moves only when the detail changes.

**Sufficient to act on alone?** Close, with one check. The per-BSSID
count plus the cited frames distinguish a spoofed-swarm flood from a
single looping client well, but the rule cannot see whether the AP's
table actually filled (T1499 is "the attempt, never the effect" [1]).
First response: read the source MACs in the cited frames - many random
locally-administered addresses with no matching `assoc` grants is an
attack on the table; one or two repeating MACs is a sick client, find
that STA. If it is a flood on a `--my-bssid` AP, check the AP's logs for
clients refused during the window and consider association rate-limiting
on the controller (docs/wiki/alert-remediation.md:677-692). If a dense
but legitimate environment inflates it, raise `auth.flood_thresh` or
widen `auth.flood_window_s` via `--tune` (src/tune.c:187-188).

## Bibliography

1. research/mitre/T1499.md - repo corpus document citing ALERT_TYPE_AUTH_FLOOD, which defines it as "authentication requests filling an AP's association table" (source: https://attack.mitre.org/techniques/T1499/, retrieved 2026-09-07) (accessed 2026-11-03)
2. MITRE ATT&CK T1499, Endpoint Denial of Service - https://attack.mitre.org/techniques/T1499/ (accessed 2026-11-03)
3. mdk4 README, attack mode `a` (authentication DoS), aircrack-ng/mdk4 - https://github.com/aircrack-ng/mdk4 (accessed 2026-11-03)
4. aircrack-ng, "airbase-ng" (client-side AP attacks; context for the auth/assoc surface) - https://www.aircrack-ng.org/doku.php?id=airbase-ng (accessed 2026-11-03)
5. docs/views/alerts.md:137 - sloth rule-table row for AUTH_FLOOD (accessed 2026-11-03)
6. J. Bellardo, S. Savage, "802.11 Denial-of-Service Attacks: Real Vulnerabilities and Practical Solutions", 12th USENIX Security Symposium, 2003 - https://www.usenix.org/legacy/events/sec03/tech/bellardo.html (accessed 2026-11-03)
7. hostapd.conf reference, `max_num_sta` ("IEEE 802.11 has a limit of 2007 different association IDs ... default: 2007") - https://fuchsia.googlesource.com/third_party/hostap/+/refs/heads/main/hostapd/hostapd.conf (accessed 2026-11-03)

## Verification notes

Verified 2026-11-03 against the working tree (HEAD 8ac44d5) and by
fetching every external source.

Code: `rule_auth_flood()` at src/alerts/rules_wifi_mgmt.c:107-132 -
`auth_flood_bssid()` (src/auth_track.c:46-74) over the 512-slot
`AUTH_RING` (src/auth_track.c:8), fed by `auth_observe_ev()`
(src/auth_track.c:19-25) from src/capture/probe.c:681 (subtype 11, addr3
= BSSID, probe.c:677-680), `n < thresh` early return (line 116), key
`authflood:<bssid>` (line 122), CRIT iff `ownership_is_my_bssid()`
(src/ownership.c:122-127; lines 121, 130-131), `fire_ev()` with
`auth_flood_evidence()` (src/auth_track.c:28-44), no `match_ip` - all as
written. The ` - YOUR network` suffix (lines 124-126) is appended on an
owned BSSID. Nothing filters the Retry bit in `auth_observe_ev()`, so
retransmissions count. Thresholds `AUTH_FLOOD_THRESH` 30 /
`AUTH_FLOOD_WIN_SECS` 5 (include/sloth.h:1249-1250); registry
`auth.flood_thresh` 2..512 / `auth.flood_window_s` 1..3600
(src/tune.c:187-188). `ALERT_EVIDENCE_IDS` 8 (include/sloth.h:854),
`ALERT_RESOLVE_AFTER_S` 300 (:860), `POLL_MS` 250 (:28).

Count semantics: `fire_ev()` -> `fire_inv()` bumps `evaluations`/`count`
on every re-assertion (src/alerts/engine.c:479-480) and `observations`
only on a detail/severity change (:488-491); the "N auth frames" figure
is per frame, the alert's count per tick.

Noise arithmetic: 7,443 / 8 keys = 930 evaluations per key; 930 / 4 =
233 s of standing time budget per key spread across its incidents
(1 + reopens), i.e. tens of seconds each once 42 reopens are divided
across 8 keys. Checks as an upper bound.

Sources: [2] MITRE T1499 fetched; "Adversaries may perform Endpoint
Denial of Service (DoS) attacks to degrade or block the availability of
services to users" verbatim; sub-techniques OS/Service/Application
Exhaustion Flood and Application or System Exploitation confirmed. [3]
mdk4 README fetched; mode `a` "Sends authentication frames to all APs
found in range" and "Too many clients can freeze or reset several APs"
verbatim. [4] airbase-ng page fetched; "multi-purpose tool aimed at
attacking clients as opposed to the Access Point (AP) itself" verbatim -
cited for surface context only, as the page describes no auth-flood mode.
[6] USENIX Bellardo & Savage fetched; title and authors ("John Bellardo
and Stefan Savage, University of California, San Diego") confirmed, and
the paper's focus on "attacks on the 802.11 MAC protocol itself" is in
the readable body. [7] hostapd.conf (fuchsia mirror of upstream) fetched;
`max_num_sta` comment "IEEE 802.11 has a limit of 2007 different
association IDs ... (default: 2007)" verbatim. [1] research/mitre/
T1499.md read; `alert_kinds` lists `ALERT_TYPE_AUTH_FLOOD` and the quoted
definition is in its paragraph. [5] docs/views/alerts.md:137 is the
AUTH_FLOOD rule-table row.

Struck: the hostapd.conf text was first sought at w1.fi, which serves an
Anubis bot-wall (HTTP 200 access-denied page) for the cgit paths and a
bare directory index for /security/2019-7/; the config comment is quoted
from the fuchsia.googlesource.com upstream mirror instead, which returned
the file. No claim was kept on an unfetched page.
