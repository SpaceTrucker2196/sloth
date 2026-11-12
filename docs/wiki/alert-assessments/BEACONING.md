---
type: BEACONING
technique: T1071
rule_file: src/alerts/rules_wired.c:1562 (rule_beaconing); helpers src/beacon_detect.c; beacon_fire_track rules_wired.c:1363 (fire at :1382) / beacon_fire_overflow rules_wired.c:1391 (fire at :1416)
count_semantics: per poll tick (default 250 ms) per open per-destination finding - each strong (remote_ip, remote_port) track that holds a seat fires once per tick (key `beacon:<ip>:<port>`), and all strong tracks past the cap fire once per tick as the single `beacon-overflow` finding; `count` is tick re-evaluations while the track stays strong, not per packet, flow or callout
severity_assessment: agree - WARN is correct; periodicity is a shape, not an intent (update checkers, telemetry and NTP beacon by design), and the destination matters more than the rhythm
false_positive_risk: high - any well-behaved periodic client (NTP, telemetry, update pollers, keepalives, dashboards on a timer) is periodic by design and can satisfy v1/v2; the detector is explicit that it reports a shape
noise_verdict: noisy on the reference host - 40 keys, 172,989,288 fires, max_sev WARN (1). The fires count is tick re-evaluations, not beacon callouts: ~1.73e8 fires over 40 keys is ~4.3M evaluations per key, which at 4 or more evaluations/s (POLL_MS 250 is the longest wait between ticks, include/sloth.h:28; the loop wakes early at main.c:1666/1671) is at most ~12.5 days of continuously-held beacon state per destination - long-lived periodic flows (NTP, telemetry, keepalives) re-fired every tick. Because at most 16 seats plus the overflow key fire per tick, the 40 keys cannot all have been open at once; they took turns in the 17 slots. This is the expected shape of benign periodic traffic, not 173M attacks. The #148 cap already bounds open findings to bd.max_findings (16) + one overflow; the dedup key already collapses per destination. `observations` is not the figure to trend: the detail carries `n` (rules_wired.c:1368-1379), which grows with every callout until the 16-sample window fills (BD_MAX_SAMPLES, beacon_detect.h:13), after which the sliding window moves period/jitter; each change against the stored `detail_sig`, refreshed only on an emitted event (engine.c:487, 534), makes `observations` follow `evaluations` for up to 60 s. Trend the open-incident count (40) and a per-track callout total instead, not `count`
prevalence: true C2 beaconing is common in intrusions (Cobalt Strike was #8 in Red Canary's 2022 Threat Detection Report, the only post-exploitation framework in its top 10 [5]); but benign periodic traffic vastly outnumbers it on any network, so base rate favours false positives
tuning: [bd.min_samples (5), bd.min_interval_s (10), bd.max_jitter_pct (25) - v1; bd.min_samples_v2 (12), bd.min_concentration_pct (60) - v2; bd.max_findings (16, 1..64) - open-findings cap (#148); pcap.min_severity (default CRIT, so a WARN exports no pcap unless lowered to 0), pcap.key_cooldown_secs]
researched: 2026-10-27
---
## What the rule checks

The detector (`src/beacon_detect.c`) tracks regular-interval IP flows.
`bd_update()` (`beacon_detect.c:78-90`) runs each tick over `s->conns`:
for every remote (ip, port) it records a sample timestamp when the flow
is new or has been idle at least `BD_GAP_S` = 5 s, so one long-lived
connection does not log a sample every tick - it logs one per re-contact.
Tracks are per (remote_ip, remote_port), max `BD_MAX_TRACKS` = 128, with
a 16-slot sample ring; an IPv4-mapped IPv6 peer is canonicalised to its
IPv4 form so one flow is one track (#148, `beacon_detect.c:20-27`). The
samples come only from this host's own socket table, so every track is a
destination *this machine* connects to.

`bd_is_strong()` (`beacon_detect.c:210-236`) classifies a track:

- **v1 (low jitter):** `>= bd.min_samples` (5) samples, mean interval
  `>= bd.min_interval_s` (10 s), and stddev/mean `<= bd.max_jitter_pct/100`
  (0.25). Returns 1.
- **v2 (gap concentration):** `>= bd.min_samples_v2` (12) samples, median
  gap `>= bd.min_interval_s` (10 s), and the fraction of inter-arrival
  gaps within +-30% of the median `>= bd.min_concentration_pct/100`
  (0.60). Returns 2. v2 catches jittered C2 up to ~40% additive jitter
  that v1's stddev/mean test rules out.

`rule_beaconing()` (`rules_wired.c:1456+`) collects every strong track,
sorts by strength (`beacon_stronger()`: v1 before v2, then lower
jitter/higher concentration, then more samples), and keeps at most
`bd.max_findings` (default 16, ceiling 64) **open per-destination
findings**, one per strong (ip, port), key `beacon:<ip>:<port>`
(`beacon_key()` via `akey_*`; an IPv6 destination is bracketed,
`beacon:[2001:db8::1]:443`, `src/alert_key.h:17`), detail e.g.
`"203.0.113.7:443 every 60s (jitter=1.2s, n=12)"` (v1) or
`"... every ~60s jittered (concentration=0.73, n=16)"` (v2), with
`match_ip`/`match_port` = the destination so a pcap exports against it.
Seats change hands only when a challenger beats the weakest holder by a
margin (hysteresis, `beacon_clearly_stronger()`). All strong tracks past
the cap are counted in **one** `beacon-overflow` finding whose detail
names the next few and `(+N more)` (`beacon_fire_overflow()`,
rules_wired.c:1416), with no `match_ip`. This cap is the #148 owner
ruling: without it one detector could claim all 128 engine slots and
churn every other rule's findings (#96's 16.1M duplicate pcaps came from
that churn).

Count semantics: each open finding and the overflow re-fire every tick
while strong, so `count` is tick re-evaluations; `observations` moves
only when the detail (period, jitter/concentration, n) changes. A
displaced or no-longer-strong finding resolves (reason `displaced` /
quiet period).

## The attack

An implant that has compromised a host does not usually keep a live
connection open - it "checks in" to its C2 on an interval to fetch
commands and return results, so it blends into normal outbound traffic
and survives network interruptions. T1071 covers this
application-layer C2; MITRE's detection guidance explicitly calls out
"beacon-like intervals" and "unbalanced traffic" as the signal [6]. The
tell is the *rhythm*: "a human-driven session is bursty; an implant
checking in is periodic, and periodicity survives encryption" [1], so a
timing detector sees the beacon even when the payload is TLS.

Operators defeat naive timing detection by adding jitter. Cobalt Strike's
Beacon - #8 in Red Canary's 2022 Threat Detection Report, the only
post-exploitation framework in its top 10, "particularly" popular with
"ransomware operators" [5] - exposes `sleeptime` ("Default sleep time
(in milliseconds)", 60000) and `jitter` ("Default jitter factor
(0-99%)", 0) in its Malleable C2 profile language [4]; the jitter
factor exists to randomise the check-in interval so a fixed-period
detector does not see a fixed period. Sliver and most modern implants
offer the same. sloth's v2 concentration test exists to catch these: it
tolerates up to ~40% additive jitter (the repo's stated design targets
are Cobalt Strike at a 30% "interactive" jitter setting and Sliver at a
30% default [2]; the Cobalt Strike figure is not on the page cited at
[4], and Sliver's own documentation states its default jitter as "up to
30s" - seconds, not a percentage - without naming the default check-in
interval it applies to [7], so both numbers are carried as the repo's
claim, not verified here), and intentionally does not claim 50%+
jitter, where 16 samples cannot be
separated from random gaps - the mitigation there is a longer flow
feeding v1 (`beacon_detect.h:25-45`, `docs/wiki/beacon-detection.md:38-60`).
This is the same family of analysis as RITA's "Beaconing Detection",
Active Countermeasures' Zeek-log beacon scorer [8]. The crucial caveat
the corpus states: "what makes an implant's beacon interesting is the
destination, not the rhythm" [1] - periodicity alone is not malice.

## Evidence that proves it

What sloth records:

- The alert detail: destination ip:port, the detected period, and either
  jitter (v1) or concentration (v2) plus sample count n - enough for an
  operator to judge confidence at a glance.
- `match_ip`/`match_port` = the destination (per-finding only, not the
  overflow), so a pcap exports against the C2 candidate's flow - though
  only if `pcap.min_severity` is lowered to 0, since BEACONING is WARN
  and the default floor is CRIT.
- The `conn`/Top-hosts views and process attribution for the local
  process holding the flow.
- The `beacon-overflow` JSONL finding lists the next strong destinations
  (`docs/wiki/jsonl-schema.md:541`).
- `sensor_health`: no beacon-specific eviction field is exported for the
  128-track ring in this list; the engine's own `evict_alert` covers slot
  pressure.

To call it a real implant: the destination is not a known service
(not in Top-hosts as a CDN/NTP/telemetry endpoint), and the pairing
signals line up - a `BEACONING` host whose JA3 does not match a known
browser is a strong implant signal, and `BEACONING` + a threat-intel hit
(`THREAT_IP`/`THREAT_DOMAIN`) on the same flow is "case closed"
[1][2][3]. What refutes it: the destination resolves to a known
update/telemetry/NTP/monitoring service, the period matches a documented
poll interval (NTP's poll ranges 16 s to 36 h, 2^4..2^17 [9]), or the
process holding the socket is a legitimate updater/agent.

## Benign causes

- **Time sync.** NTP polls servers at regular, standardised intervals
  (2^tau seconds, tau 4..17) - periodic by specification [9].
- **Telemetry and keepalives.** OS/app telemetry, cloud agents, MQTT
  keepalives, metrics push, heartbeat/health pollers - all beacon by
  design. The corpus names "update checkers, telemetry and NTP-like
  services" as periodic-by-design [1].
- **Update pollers / dashboards on a timer**, package managers, CRL/OCSP
  refresh.
- **Domain-fronted or CDN traffic** where the apparent remote is a
  stable edge IP contacted regularly.

The way to tell any of these from C2 is the destination, the JA3/TLS
fingerprint, and the process - never the rhythm alone
(`docs/wiki/beacon-detection.md:86-92`).

## Assessment

WARN is correct and the detector is honest that it reports a shape, not an
intent [1]. v1+v2 together give good coverage of real implants including
jittered ones up to ~40%, and the #148 cap plus per-destination keying is
a sound answer to the engine-slot-exhaustion problem that an
unbounded-per-track rule created (#96's duplicate-pcap storm). The
severity is right because a false positive here is a benign periodic flow,
which is abundant.

Prevalence: true C2 beaconing is common in intrusions - Cobalt Strike
was the only post-exploitation framework in Red Canary's 2022 top 10 [5] - but on any given network benign
periodic traffic outnumbers malicious by orders of magnitude, so the base
rate strongly favours false positives and the alert is a triage pointer,
not a verdict.

Reference-host noise verdict: **noisy**, and the arithmetic shows why it
is benign noise rather than 173M attacks. 172,989,288 fires on 40 keys is
~4.3M re-evaluations per key; ticks run at 4/s or more (POLL_MS 250 is
the longest wait, include/sloth.h:28), so that is at most ~12.5 days of
continuously-held beacon state per destination. In other words, long-lived
periodic flows (NTP, telemetry, keepalives) stayed strong for days and
re-fired every tick - the count is dominated by re-evaluation of a handful
of persistent benign beacons, not by new incidents. (One bound worth stating: since #148 at
most 16 seats plus the overflow key fire per tick, so 173M fires need at
least 173M / 17 = ~10.2M ticks, which at 4 or more ticks/s is at most
~29 days with every slot full; the 40 keys therefore took turns in the 17
slots rather than all being open for most of the run. A shorter capture
with the same total would mean the figure predates the cap. The metrics
do not say which.) The mitigations that matter are already in
place: the per-destination key collapses each flow to one incident, and
the #148 cap bounds *open* findings to 16 + overflow. The remaining
problem is purely the `count` metric being read as if it were callouts;
the honest figure is the incident count (40), not `observations`: the
detail carries `n`, which grows with every callout until the 16-sample
window fills, and then the sliding window moves period/jitter, so each
change - against a stored `detail_sig` refreshed only on an emitted event
(engine.c:487, 534) - makes `observations` follow `evaluations` for up to
60 s. Recommendations if an operator wants it quieter: (a) trend the
incident count and a per-track callout total, never `count`; (b)
raise `bd.min_interval_s` to push past fast keepalives, or raise
`bd.min_concentration_pct` / lower `bd.max_jitter_pct` to tighten v2/v1;
(c) maintain a destination allowlist of known periodic services so NTP
and telemetry stop occupying seats - the rule has no allowlist today,
which is the main structural gap.

Is the evidence sufficient to act on? Not on its own - periodicity is a
shape. It becomes actionable combined with destination reputation, JA3,
and process attribution, and conclusive with a co-located `THREAT_IP`/
`THREAT_DOMAIN` hit [1][3]. First response: identify the destination; if
it is a known service, note it so the next occurrence reads against it;
if not, find the local process holding the connection and read
`THREAT_IP`/`THREAT_DOMAIN`/JA3 for the same flow, then isolate and
examine the process (`docs/wiki/alert-remediation.md:165-184`).

## Bibliography

1. research/mitre/T1071-004.md - MITRE ATT&CK T1071/.004 ("Regularity. BEACONING watches the interval rather than the content ... periodicity survives encryption"; "what makes an implant's beacon interesting is the destination, not the rhythm"); the repo's corpus document for this kind; retrieved 2026-09-07 from https://attack.mitre.org/techniques/T1071/004/ (accessed 2026-10-27)
2. docs/wiki/beacon-detection.md - v1/v2 thresholds, why these numbers, pairing with JA3/threat-intel (repo, read 2026-10-27)
3. docs/wiki/alert-remediation.md § BEACONING; docs/views/alerts.md rule-table row and § BEACONING cap (#148) (repo, read 2026-10-27)
4. Cobalt Strike, Malleable C2 profile language - options table: `sleeptime` "Default sleep time (in milliseconds)" 60000, `jitter` "Default jitter factor (0-99%)" 0 - https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_profile-language.htm (accessed 2026-10-27)
5. Red Canary 2022 Threat Detection Report - Cobalt Strike (#8 overall; "the only post-exploitation framework to make the top 10"; "a popular command and control (C2) framework among adversaries, particularly ransomware operators") - https://redcanary.com/threat-detection-report/threats/cobalt-strike/ (accessed 2026-10-27)
6. Application Layer Protocol, Technique T1071 - MITRE ATT&CK (detection: "beacon-like intervals", "unbalanced traffic") - https://attack.mitre.org/techniques/T1071/ (accessed 2026-10-27)
7. Sliver, "Getting Started" (docs source, BishopFox/sliver `docs/sliver-docs/pages/docs/md/Getting Started.md`): "The 'Next Check-in' value includes any random jitter (by default up to 30s)" - https://raw.githubusercontent.com/BishopFox/sliver/master/docs/sliver-docs/pages/docs/md/Getting%20Started.md (accessed 2026-10-27). The page states the default jitter in seconds and does not state the default check-in interval, so the repo's "Sliver at default 30%" (`docs/wiki/beacon-detection.md`, `src/beacon_detect.h:31-34`) is not confirmed by it; https://sliver.sh/docs?name=Beacons+and+Sessions rendered only "Loading documentation..." and no "Beacons and Sessions.md" exists in the current docs tree (both re-tried 2026-10-27)
8. RITA, Active Countermeasures / Black Hills Information Security - "Beaconing Detection: Search for signs of beaconing behavior in and out of your network" - https://github.com/activecm/rita (accessed 2026-10-27)
9. RFC 5905, "Network Time Protocol Version 4" - poll interval 2^tau s, tau 4 (16 s) .. 17 (36 h): periodic by specification - https://www.rfc-editor.org/rfc/rfc5905 (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and every
reachable external source re-opened.

Code: `rule_beaconing()` at `src/alerts/rules_wired.c:1456-1544`,
`beacon_fire_track()` at `:1363` (fire `:1382`), `beacon_fire_overflow()`
at `:1391` (fire `:1416`), `beacon_key()` at `:1354` via
`akey_begin/akey_ip/akey_u` -> `beacon:<ip>:<port>`; overflow key literal
`beacon-overflow`, `match_ip` NULL, resolved "drained" when no track is
unseated. Detail formats `"%.39s:%u every %.0fs (jitter=%.1fs, n=%d)"`
and `"%.39s:%u every ~%.0fs jittered (concentration=%.2f, n=%d)"`
(`:1370`, `:1378`) match the examples. `bd_is_strong()`
(`beacon_detect.c:210-236`): v1 `n >= bd.min_samples` (5), `mean >=
bd.min_interval_s` (10), `jitter/mean <= bd.max_jitter_pct/100` (0.25);
v2 `n >= bd.min_samples_v2` (12), median `>= 10`, fraction of gaps in
`[0.70, 1.30] x median` `>= 0.60` - all confirmed, defaults and ranges
in `src/tune.c:203-211` (`bd.max_findings` 16, 1..64). `BD_GAP_S` 5,
`BD_MAX_TRACKS` 128, `BD_MAX_SAMPLES` 16, IPv4-mapped canonicalisation
(`beacon_detect.c:20-27`), `bd_update()` at `:78`. `sensor_health.h:29`
lists `beacon_detect` among the tables whose loss is unmeasured (the
`evict_beacon_ap` field is `beacon_snoop`'s 802.11 table, not this
one), and `evict_alert` exists - so the sensor_health paragraph is
right. No allowlist in `beacon_detect.c` or the rule (grep). The 16.1M
duplicate-pcap figure is `docs/views/alerts.md:260` /
`docs/wiki/log.md:2507`. Noise arithmetic 172,989,288 / 40 = 4.32M per
key, / 4 per s = 12.5 days - as stated, with the cap caveat added.

Changed: rule_file line references re-stated so the function starts and
the `fire()` lines are both named (the old text labelled the fire lines
as the functions). The Cobalt Strike sentence quoted "harder to detect by
security tools that look for predictable traffic patterns" - that text is
not on the cited Malleable C2 page; the quotation is removed and the
sentence now quotes only what the page's options table says (sleeptime
60000, jitter 0-99% default 0). "Top-ranked" for Cobalt Strike replaced
with what Red Canary actually says (#8 in the 2022 report, the only
post-exploitation framework in the top 10). The 30% "interactive" Cobalt
Strike / 30% Sliver jitter figures are now marked as the repo's own
claim ([2], `beacon_detect.h`) since neither reachable source states
them. [7] updated to record the second failed attempt. Added the
seats-cap bound to the noise paragraph.

Sources: [4] confirmed as fixed. [5] confirmed as fixed. [6] T1071:
"blending in with existing traffic" and detection analytic "unbalanced
traffic or beacon-like intervals" both verbatim. [8] RITA README:
"Search for signs of beaconing behavior in and out of your network"
verbatim. [9] RFC 5905: "tau ranges from 4 (16 s) to 17 (36 h)",
MINPOLL/MAXPOLL verbatim. [1] `research/mitre/T1071-004.md` lists
`ALERT_TYPE_BEACONING` and carries the "Regularity" and "destination, not
the rhythm" sentences. [2][3] repo paths exist (`beacon-detection.md:38-60`,
`:86-92`; `alert-remediation.md:165`; `jsonl-schema.md:541`).

Second pass, 2026-10-27, HEAD 0d60387. No cited source file changed
since c5650a3. Re-read: `rule_beaconing()` `rules_wired.c:1456-1544`,
`beacon_key()` `:1354-1361`, `beacon_fire_track()` `:1363-1385` (fire
`:1382`), `beacon_fire_overflow()` `:1391-1418` (fire `:1416-1417`,
key literal `beacon-overflow`, `NULL, 0`), `beacon_stronger()` `:1297`,
`beacon_clearly_stronger()` `:1315`, `BEACON_OVERFLOW_NAMES` 4 `:1256`,
"drained" resolve `:1543`; `bd_update()` `beacon_detect.c:78-90`
(`BD_GAP_S` re-contact rule `:84`), `bd_concentration_compute()`
`:151-191` (`n >= bd.min_samples_v2` `:154`, median `>=
bd.min_interval_s` `:179`, window `0.70..1.30 x median` `:181-182`),
`bd_is_strong()` `:210-236`; `tune.c:203-211`; `sensor_health.h:29`.
Three line references corrected (`bd_update` 78-91 -> 78-90,
`bd_is_strong` 210-234 -> 210-236, overflow `fire()` 1417 -> 1416, in
the front matter, body and notes). Added that `akey_ip` brackets an
IPv6 destination, so the key shape for a v6 peer is
`beacon:[addr]:port`. Sources: [4] Malleable C2 options table
re-confirmed (sleeptime 60000 "Default sleep time (in milliseconds)",
jitter 0 "Default jitter factor (0-99%)"; no "predictable traffic
patterns" sentence and no 30% figure on the page). [5] Red Canary
re-confirmed verbatim: "At #8, it is the only post-exploitation
framework to make the top 10" and "Cobalt Strike remains a popular
command and control (C2) framework among adversaries, particularly
ransomware operators". [6] T1071 analytic "unbalanced traffic or
beacon-like intervals" verbatim. [8] RITA line verbatim. [9] RFC 5905
§5 "tau ranges from 4 (16 s) to 17 (36 h)" and §7.2 MINPOLL/MAXPOLL
verbatim. [7] Sliver: `sliver.sh/docs?name=Beacons+and+Sessions` still
renders only "Loading documentation...", and the current docs tree
(`BishopFox/sliver/docs/sliver-docs/pages/docs/md/`) has no "Beacons
and Sessions" page at all. Its "Getting Started" page is readable and
says the default jitter is "up to 30s" - a duration, not a percentage -
and does not give the default check-in interval. So the repo's "Sliver
at default 30%" (`beacon_detect.h:31-34`, `docs/wiki/beacon-detection.md`)
is not supported by the reachable source; [7] now cites that page and
the body sentence says so. Worth a follow-up in the repo: the v2 design
rationale in `beacon_detect.h` rests on two jitter figures neither of
which its cited sources state.

Review pass (2026-11-01). Reversed the bounds: 250 ms is the longest wait between ticks, so 12.5 days per key and ~29 days in aggregate are both upper bounds. Dropped "40 flows open for most of the capture" (only 17 keys fire per tick). Withdrew the `observations` recommendation: `n` grows with every callout until BD_MAX_SAMPLES (16), then period/jitter move with the window, and `observations` rises whenever the new detail differs from the stored `detail_sig`, which is refreshed only on an emitted event (engine.c:487-488, 519, 534), so a detail that moves at all makes it track `evaluations` between 60 s updates.
