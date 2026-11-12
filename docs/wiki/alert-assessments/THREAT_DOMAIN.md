---
type: THREAT_DOMAIN
technique: T1071.004
rule_file: src/alerts/rules_wired.c:1279 (rule_threat_domain)
count_semantics: per poll tick (default 250 ms) per matched IOC - the rule fires once per distinct matched IOC string each tick a dns_log row still matches it (key `threat-d:<ioc>`), so `count` is tick re-evaluations while the matching query stays in the DNS ring, not per query packet
severity_assessment: agree in principle (CRIT for a confirmed-bad name is correct) - BUT with the shipped list it is moot: the list is synthetic demo data that matches nothing in real traffic, so the real severity question only exists once an operator loads a feed
false_positive_risk: low in mechanism (exact suffix match on a label boundary, cut-name rows skipped) - the risk is staleness of whatever feed replaces the demo list, not matching error
noise_verdict: not seen on the reference host - host:null, as expected: the shipped IOC list is synthetic (RFC 5737 / RFC 2606-style sentinels) and matches nothing, so THREAT_DOMAIN detects nothing in production until the list is replaced ([3],[4])
prevalence: domain-based C2/phishing indicators are a mainstay of threat intel, but a *match* is only as prevalent as the loaded feed; with the demo list, zero
tuning: [no --tune knob for the rule; it depends entirely on the IOC list compiled into src/threat_intel.c; pcap.min_severity (default CRIT, so this rule does export a pcap at default), pcap.key_cooldown_secs]
researched: 2026-10-27
---
## What the rule checks

`rule_threat_domain()` (`src/alerts/rules_wired.c:1171-1201`) walks
`s->dns_log[]`. For each entry it skips rows with an empty `qname` and -
critically - rows flagged `qname_trunc` (#152): the stored name is only a
63-byte prefix (or is cut at a NUL octet), and since an IOC match is a
suffix match, a hit on a cut row is a match on *where the cut fell*, not
on the queried name's suffix, so it carries no evidence and is dropped,
not downgraded (`rules_wired.c:1174-1184`). For every remaining row it
calls `ti_match_domain(e->qname, &ioc)`; on a match it fires
`ALERT_TYPE_THREAT_DOMAIN` at `ALERT_SEV_CRIT`, key `threat-d:<ioc>`,
detail `"<src> queried <qname> (demo IOC <ioc>)"` (`%.30s` / `%.30s` /
`%.16s` widths, `?` when `src` is empty), `match_ip = src`,
`match_port = 53`.

The matcher (`src/threat_intel.c:58-67`) is a case-insensitive
**suffix** match on a label boundary (`domain_suffix_match()`,
`threat_intel.c:46-56`): `evilcorp.example` matches `evilcorp.example`
and `*.evilcorp.example` but not `notevilcorp.example` (the byte before
the suffix must be `.`). It reads `dns_log` only - TLS SNI and HTTP
`Host:` are **not** matched against the list
(`docs/views/alerts.md:163`; the SNI/Host triggers this page once listed
were never implemented and were removed in #152).

The IOC list is `bad_domains[]` in `src/threat_intel.c:24-32`:
`malware.testing.com`, `phishing.testing.com`, `c2.example-bad.com`,
`evilcorp.example`, `badactor.test`, `drive-by.testing.com`. These are
**synthetic demo data, not a threat feed** - the header comment states it
in full (`threat_intel.c:5-22`), and the operator is told in three
kept-in-sync surfaces: the alert detail says `(demo IOC ...)` not
`(IOC ...)`, the help view's "Embedded data" section says `Threat intel:
SYNTHETIC DEMO LIST`, and the source header (#96). In practice they match
nothing, so the rule detects nothing in production until the list is
swapped for a real feed (`docs/wiki/threat-intel.md`). sloth ships no
feed and cannot fetch one, because fetching is a network write that
MISSION §2 forbids (`threat_intel.c:16-17`).

Count semantics: the key is the IOC string, so all queries matching one
IOC collapse to one incident; `fire()` re-asserts it each tick a matching
row is still in the DNS ring, bumping `count`. `observations` moves when
the detail (which includes the specific `qname` and `src`) changes.

## The attack

DNS is the protocol most likely to be allowed outbound from a network
that blocks everything else, which is why adversaries use it to reach
command-and-control and phishing infrastructure by name [1]. T1071.004
covers DNS as an application-layer channel [2]. A domain IOC is the
matcher rather than the heuristic: instead of scoring a name's shape
(that is `DGA_DOMAIN`) it checks whether the name is on a list someone
else compiled of domains known to front malware delivery, phishing, or
C2. Public examples include abuse.ch's ThreatFox, whose export datasets
include "Botnet C2 domains" and "Payload delivery domains" [6] (its
better-known sibling Feodo Tracker is an IP-only blocklist and belongs
under `THREAT_IP`), and many commercial and community blocklists.

What a match gives a responder is a high-value, low-effort signal - but a
*fragile* one. On Bianco's Pyramid of Pain, domain names sit near the
bottom: "there are a large number of DNS providers out there with lax
registration standards (many of them free), so in practice it's not too
hard to change domains" [7]. An adversary rotates a burned domain in
minutes, so a feed is only as good as it is fresh, and it goes stale in
both directions: a name drops off when the campaign moves, and a
sinkholed domain becomes a *good* thing to see resolved rather than a bad
one [1]. A match therefore says "this name was on a list", not "this name
is hostile right now".

## Evidence that proves it

What sloth records:

- The alert detail: the querying host (`src`), the exact `qname`, and the
  matched IOC - with the honest `demo IOC` marker that tells a 02:00
  operator the shipped list is synthetic (`rules_wired.c:1191-1197`).
- The `dns` JSONL records: the query and (if seen) the response for that
  name, so a responder can confirm whether it resolved and to what.
- A per-alert pcap: THREAT_DOMAIN is CRIT, so it meets the default
  `pcap.min_severity` = 2 and `alert_pcap_dump()` filters the general
  ring on `match_ip = src`, port 53 (at most 64 captured bytes/packet).
- No rule-specific `sensor_health` counter; `evict_dns_log` indicates
  ring pressure.

To call a (real-feed) match actionable: the host actually *resolved* the
name and a connection to the answer followed - read `THREAT_IP` and the
`conn` view for a session to the resolved address, and `BEACONING` for
periodicity to it [1][3]. The strongest case is a threat-domain lookup
followed by a beacon to the resolved IP. What refutes it: the name is on
a sinkholed/retired indicator (now benign), the lookup came from a
security tool or passive DNS replication rather than real use, or - with
the demo list - the "match" is a test/synthetic name that no real client
would query (and a cut-name coincidence is already excluded by the
`qname_trunc` guard, #152).

## Benign causes

- **Stale indicators.** The dominant false-positive mode once a real feed
  is loaded: an address/name re-allocated or sinkholed. A sinkholed
  domain resolving is a *good* sign misread as bad [1].
- **Security tooling** resolving IOCs on purpose (your own threat-intel
  enrichment, a sandbox, passive-DNS collectors).
- **Demo-list artefacts.** With the shipped list, any "match" is a
  synthetic sentinel; four of the six domains sit under ordinary
  registrable `.com` names (`testing.com`, `example-bad.com`) chosen to
  look fake, so a host that genuinely resolved `malware.testing.com`
  would raise a meaningless CRIT (`docs/wiki/threat-intel.md`).
- **Cut-name coincidences** - already excluded by the `qname_trunc` skip
  (#152); noted here because it was a real pre-#152 false-positive (any
  web page could make a browser resolve
  `<43 a>.malware.testing.com.evil.example`).

## Assessment

The *mechanism* is sound and conservative: exact suffix match on a label
boundary, case-insensitive, cut-name rows excluded, one incident per IOC,
and - unusually honest - the detail tells the operator the shipped data
is synthetic. CRIT is the right severity for a confirmed-bad domain
lookup *if the feed is real and current*. But with the shipped list the
severity question is moot: the list matches nothing in production, so
THREAT_DOMAIN "detects nothing until you replace the lists - a working
pipeline with no data in it" [4]. That is a deliberate design choice
(passive guarantee, no network fetch), not a bug, and the single most
important thing to convey to anyone reading a THREAT_DOMAIN assessment:
do not present sloth's threat-intel matching as a detection capability
without naming the feed that was loaded [4].

False-positive risk is low in mechanism and entirely a function of feed
quality once populated - domains are a bottom-of-pyramid indicator that
adversaries rotate cheaply [7] and that go stale both ways [1], so a real
deployment needs a fresh, curated feed and should treat every match as
"was on a list" pending confirmation.

Reference-host noise: not seen (host:null), exactly as expected for the
synthetic list. There is nothing to tune or dedupe; the key already
collapses per-IOC.

Is the evidence sufficient to act on? The match plus the retained `dns`
records and the CRIT-default pcap are enough to confirm *that the name was
queried*; they are not enough to confirm the name is currently hostile -
that needs feed provenance/recency and the follow-on (resolution +
connection + beacon). First response: confirm the querying host and
whether a connection to the answer followed; verify the indicator is
current (not sinkholed/retired); if current, isolate the host and
investigate what made the lookup, and block the name at the resolver
(`docs/wiki/alert-remediation.md:125-144`).

## Bibliography

1. research/mitre/T1071-004.md - MITRE ATT&CK T1071.004 DNS ("THREAT_DOMAIN and THREAT_IP are the matcher rather than the heuristic"; "indicators go stale in both directions"); the repo's corpus document for this kind; retrieved 2026-09-07 from https://attack.mitre.org/techniques/T1071/004/ (accessed 2026-10-27)
2. Application Layer Protocol: DNS, Technique T1071.004 - MITRE ATT&CK - https://attack.mitre.org/techniques/T1071/004/ (accessed 2026-10-27)
3. docs/wiki/alert-remediation.md § THREAT_DOMAIN; docs/views/alerts.md rule-table row (match semantics, qname_trunc guard) (repo, read 2026-10-27)
4. docs/wiki/threat-intel.md - "The shipped IOC list is synthetic demo data"; src/threat_intel.c:5-32 header and bad_domains[] (repo, read 2026-10-27)
5. RFC 2606 "Reserved Top Level DNS Names" (.test/.example/.invalid/.localhost) and RFC 5737 "IPv4 Address Blocks Reserved for Documentation" - why the demo sentinels are safe/implausible - https://www.rfc-editor.org/rfc/rfc2606 , https://www.rfc-editor.org/rfc/rfc5737 (accessed 2026-10-27)
6. abuse.ch ThreatFox export datasets ("Botnet C2 domains", "Payload delivery domains") - example of a real domain IOC feed one would load in place of the demo list - https://threatfox.abuse.ch/export/ (accessed 2026-10-27). abuse.ch Feodo Tracker (Dridex, Emotet, TrickBot, QakBot, BazarLoader) is "a blocklist of IP addresses" only - https://feodotracker.abuse.ch/blocklist/ (accessed 2026-10-27)
7. Bianco, "The Pyramid of Pain" (domain names are a low, easily-rotated indicator) - https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and every
external source re-opened.

Code: `rule_threat_domain()` at `src/alerts/rules_wired.c:1171-1201`:
skips `!qname[0] || qname_trunc` (`:1184`), `ti_match_domain()`
(`:1186`), CRIT, key `threat-d:<ioc>`, detail `"%.30s queried %.30s
(demo IOC %.16s)"` (`:1195-1197`), `match_ip = src`, `match_port = 53`.
`domain_suffix_match()` at `threat_intel.c:46-56` is case-insensitive
suffix with a `.` label-boundary check; `bad_domains[]` is the six
names listed (`:24-32`); the header comment is `:5-22`. Help view
string `Threat intel: SYNTHETIC DEMO LIST` at `src/views/help.c:112`.
`docs/views/alerts.md:163` says TLS SNI / HTTP Host are not matched, and
`docs/wiki/threat-intel.md:28-29` says the SNI/Host triggers "were
never" implemented. Count semantics follow `fire_inv()`
(`engine.c:478-489`). No tune knob for the rule (confirmed by grep).
"Four of the six under registrable .com" - `malware.testing.com`,
`phishing.testing.com`, `c2.example-bad.com`, `drive-by.testing.com` -
checks.

Changed: rule span `1171-1202` -> `1171-1201`; guard comment
`1176-1188` -> `1174-1184`; detail `1192-1198` -> `1191-1197`;
`domain_suffix_match` `43-56` -> `46-56`; `bad_domains[]` `24-31` ->
`24-32`; header `5-21` -> `5-22` (and `5-31` -> `5-32` in [4]). Detail
format widths added. Feodo Tracker was cited as an example
"domain/IP C2 feed": its blocklist page says it is "a blocklist of IP
addresses" only, so it cannot replace the *domain* list; re-sourced to
abuse.ch ThreatFox, whose export page names "Botnet C2 domains" and
"Payload delivery domains" datasets, and Feodo Tracker is kept only as
the IP-feed cross-reference to `THREAT_IP`.

Sources: [2] T1071.004 exists. [5] RFC 2606 (".test .example .invalid
.localhost") and RFC 5737 (three TEST-NET blocks "SHOULD NOT appear on
the public Internet") confirmed verbatim. [6] re-sourced as above.
[7] Pyramid of Pain domain-name sentence confirmed verbatim ("there are
a large number of DNS providers out there with lax registration
standards (many of them free), so in practice it's not too hard to
change domains"). [1] `research/mitre/T1071-004.md` lists
`ALERT_TYPE_THREAT_DOMAIN` and carries the "matcher rather than the
heuristic" and "go stale in both directions" sentences quoted. [3][4]
repo paths exist.

Second pass, 2026-10-27, HEAD 0d60387. No cited source file changed
since c5650a3. Re-read: `rule_threat_domain()` `rules_wired.c:1171-1201`
(guard `:1184`, `ti_match_domain()` `:1186`, key `threat-d:%s`, detail
`"%.30s queried %.30s (demo IOC %.16s)"` `:1195-1197`, CRIT, `match_ip`
src, port 53); `threat_intel.c` header `:5-22`, `bad_domains[]` `:24-32`
(six names as listed), `domain_suffix_match()` `:46-56`
(`strcasecmp` on the tail, `tail[-1] == '.'`), `ti_match_domain()`
`:58-67`; `help.c:112`; `alerts.md:163`; `threat-intel.md:28-29`.
Nothing to change in the text. [2] [5] [6] [7] re-opened: RFC 2606's
four TLDs, RFC 5737's "SHOULD NOT appear on the public Internet",
ThreatFox's "Botnet C2 domains" / "Payload delivery domains" (host-file
and RPZ exports), Feodo Tracker "a blocklist of IP addresses that are
associated with such botnet C2s", and the Pyramid of Pain domain
sentence - all verbatim.
