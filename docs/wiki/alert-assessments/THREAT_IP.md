---
type: THREAT_IP
technique: T1071
rule_file: src/alerts/rules_wired.c:1296 (rule_threat_ip)
count_semantics: per poll tick (default 250 ms) per matched IOC address - fires once per distinct matched IOC each tick a conn still has that remote address (key `threat-i:<ioc>`); `count` is tick re-evaluations while the connection is in the socket table, not per packet or per flow
severity_assessment: agree in principle (CRIT for a confirmed-bad remote is correct) - but moot with the shipped list, which is synthetic (RFC 5737 documentation addresses) and matches nothing real
false_positive_risk: low in mechanism (exact string match on the remote address) - the real risk is feed staleness (addresses are re-allocated) once a real list replaces the demo one
noise_verdict: not seen on the reference host - host:null, as expected: the shipped bad_ips[] are RFC 5737 documentation addresses that cannot appear on the public Internet, so THREAT_IP detects nothing in production until the list is replaced ([3],[4])
prevalence: IP-based C2 indicators are common in feeds (e.g. abuse.ch Feodo Tracker), but a *match* is only as prevalent as the loaded feed; with the demo list, zero
tuning: [no --tune knob; depends entirely on bad_ips[] compiled into src/threat_intel.c; pcap.min_severity (default CRIT, so it exports at default), pcap.key_cooldown_secs]
researched: 2026-10-27
---
## What the rule checks

`rule_threat_ip()` (`src/alerts/rules_wired.c:1203-1220`) walks
`s->conns[]` - the host's own socket snapshot: TCP from INET_DIAG
(`src/platform/linux_tcpdiag.c`), UDP from `/proc/net/udp{,6}`
(`src/platform/linux.c:123-124`). For each connection it calls
`ti_match_ip(c->remote_addr, &ioc)`; on a match it fires
`ALERT_TYPE_THREAT_IP` at `ALERT_SEV_CRIT`, key `threat-i:<ioc>`, detail
`"connection to <remote_addr>:<remote_port> (demo IOC <ioc>)"`,
`match_ip = remote_addr`, `match_port = remote_port`.

The matcher (`src/threat_intel.c:69-78`) is an **exact string** compare
against `bad_ips[]` - so it is literal text, not CIDR/subnet, and the
stored address must match byte-for-byte (an IPv4-mapped IPv6 spelling of
the same address would not match an IPv4 entry). The list
(`threat_intel.c:34-41`) is the four RFC 5737 documentation addresses
`192.0.2.66`, `192.0.2.99`, `198.51.100.7`, `203.0.113.13` - **synthetic
demo data**, genuinely non-routable, chosen so they cannot appear in real
traffic (`threat_intel.c:5-21`). As with `THREAT_DOMAIN`, the operator is
told via the `(demo IOC ...)` marker in the detail, the help view's
`SYNTHETIC DEMO LIST`, and the source header (#96). In practice they
match nothing, so the rule detects nothing until the list is replaced
(`docs/wiki/threat-intel.md`); sloth ships and fetches no feed because a
fetch is a network write MISSION §2 forbids.

Count semantics: the key is the IOC address, so repeated connections to
one bad address are one incident; `fire()` re-asserts each tick the
socket is still present, bumping `count`. `observations` moves when the
detail changes (a new remote port, say).

## The attack

T1071 is Application Layer Protocol - adversaries "communicate using OSI
application layer protocols to blend in with existing traffic" [5]. An IP
IOC is the matcher form of detection (as opposed to a behavioural
heuristic): the remote address of an outbound connection is on a list
someone else compiled of addresses hosting C2 or other malicious
infrastructure. Public feeds that populate such a list include abuse.ch's
Feodo Tracker, which shares "botnet C&C servers" for Dridex, Emotet,
TrickBot, QakBot and BazarLoader [6].

What a match gives a responder is a direct, high-value signal: this host
talked to a known-bad endpoint. But IP addresses are the *weakest*
durable indicator on Bianco's Pyramid of Pain - "any reasonably advanced
adversary can change IP addresses whenever it suits them, with very
little effort" [7] - so a match is fragile: addresses are re-allocated,
and "a match says the indicator was on a list, not that it is currently
hostile" [1][3]. The signal is strongest when paired: an IP IOC that is
also contacted *periodically* (`BEACONING` on the same pair) is a far
stronger implant signal than either alone, which the corpus and the
remediation page both stress [1][3].

## Evidence that proves it

What sloth records:

- The alert detail: the matched remote address, the remote port, and the
  `demo IOC` marker.
- A per-alert pcap: THREAT_IP is CRIT and carries `match_ip`/`match_port`,
  so at the default `pcap.min_severity` = 2 it exports - the general ring
  filtered on the (remote_addr, remote_port) flow (at most 64 captured
  bytes/packet), which is the actual traffic to the bad endpoint.
- The `conn` snapshot and, via `match_ip`/`match_port`, the flow in the
  packet/connection views; `BEACONING` if the connection recurs on an
  interval; `THREAT_DOMAIN` if a listed name resolved to it.
- Process attribution on the local host (which process holds the socket)
  from the connection/PID path.
- No rule-specific `sensor_health` counter.

To call a (real-feed) match actionable: there is sustained or repeated
traffic to the address (not a single stray SYN), ideally periodic
(`BEACONING`), from an identifiable local process, and the indicator is
current. What refutes it: the address was re-allocated and now hosts a
legitimate service (CDN, cloud tenant), the "connection" is a scan
backscatter or a single failed SYN, or - with the demo list - the address
is an RFC 5737 sentinel that cannot route and so could only appear in a
test harness.

## Benign causes

- **Stale / re-allocated indicators.** The dominant mode once a real feed
  is loaded: cloud and hosting IPs churn constantly, and a bad address
  today is a SaaS tenant tomorrow [1][7].
- **Shared infrastructure.** One IP behind a CDN or cloud load balancer
  can host both malicious and benign tenants; an IOC on that IP flags
  every host that talks to anything there.
- **Security tooling** deliberately connecting to IOCs (sandboxing,
  enrichment).
- **Demo-list artefacts.** With the shipped list a match can only come
  from a test that injects an RFC 5737 address; it means nothing in
  production (`docs/wiki/threat-intel.md`).

## Assessment

The mechanism is simple and conservative (exact-match, one incident per
IOC, honest `demo IOC` marker, CRIT-default pcap so the actual traffic is
captured), and CRIT is right for a confirmed-bad remote *with a real,
current feed*. As shipped it is moot: the four addresses are
non-routable documentation prefixes that "SHOULD NOT appear on the public
Internet" [8], so THREAT_IP fires on nothing real - a working pipeline
with no data in it, and the same caveat as THREAT_DOMAIN applies: never
present it as a detection capability without naming the loaded feed [4].

Two mechanism notes that bound a real deployment's results: the match is
exact-string, not CIDR, so a feed expressed as subnets must be expanded
to individual addresses, and an IPv4-mapped-IPv6 spelling of a listed
IPv4 address will miss. False-positive risk is low in matching but
entirely gated on feed freshness - IPs are the most easily rotated
indicator [7] and re-allocation makes stale entries actively misleading.

Reference-host noise: not seen (host:null), exactly as expected. Nothing
to tune or dedupe; the key collapses per-IOC and the CRIT pcap cooldown
(`pcap.key_cooldown_secs`, default 3600) already prevents repeated
exports for one key.

Is the evidence sufficient to act on? The match plus the exported flow
pcap and `conn`/process attribution confirm *that this host talked to the
address*; they do not confirm the address is currently hostile - that
needs feed provenance and the pairing signals. First response: identify
the local host, remote address and port; verify the indicator is current
(addresses are re-allocated); read `BEACONING` on the same pair (periodic
contact to a listed address is much stronger than either alone); if
current, isolate the host, find the owning process, and block the address
at the perimeter (`docs/wiki/alert-remediation.md:146-163`).

## Bibliography

1. research/mitre/T1071-004.md - MITRE ATT&CK T1071/.004 ("THREAT_DOMAIN and THREAT_IP are the matcher rather than the heuristic"; "an address is re-allocated ... a match says the indicator was on a list, not that it is currently hostile"; "which is why BEACONING is worth reading beside THREAT_IP"); the repo's corpus document for this kind; retrieved 2026-09-07 from https://attack.mitre.org/techniques/T1071/004/ (accessed 2026-10-27)
2. Application Layer Protocol, Technique T1071 - MITRE ATT&CK - https://attack.mitre.org/techniques/T1071/ (accessed 2026-10-27)
3. docs/wiki/alert-remediation.md § THREAT_IP (pair with BEACONING; check currency); docs/views/alerts.md rule-table row (repo, read 2026-10-27)
4. docs/wiki/threat-intel.md - "The shipped IOC list is synthetic demo data"; src/threat_intel.c:34-41 bad_ips[] and header (repo, read 2026-10-27)
5. Application Layer Protocol, Technique T1071 - MITRE ATT&CK (full description) - https://attack.mitre.org/techniques/T1071/ (accessed 2026-10-27)
6. abuse.ch Feodo Tracker - example real IP C2 feed to load in place of the demo list ("a blocklist of IP addresses that are associated with such botnet C2s"; Dridex, Emotet, TrickBot, QakBot, BazarLoader) - https://feodotracker.abuse.ch/ and https://feodotracker.abuse.ch/blocklist/ (accessed 2026-10-27)
7. Bianco, "The Pyramid of Pain" (IP addresses are the most easily changed indicator) - https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html (accessed 2026-10-27)
8. RFC 5737, "IPv4 Address Blocks Reserved for Documentation" (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 SHOULD NOT appear on the public Internet) - https://www.rfc-editor.org/rfc/rfc5737 (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and every
external source re-opened.

Code: `rule_threat_ip()` at `src/alerts/rules_wired.c:1203-1220`: walks
`s->conns[]`, `ti_match_ip(c->remote_addr, &ioc)`, CRIT, key
`threat-i:<ioc>`, detail `"connection to %s:%u (demo IOC %s)"`,
`match_ip = remote_addr`, `match_port = remote_port` - exactly as
written. `ti_match_ip()` (`threat_intel.c:69-78`) is `strcmp` against
`bad_ips[]` (`:34-41`): `192.0.2.66`, `192.0.2.99`, `198.51.100.7`,
`203.0.113.13`. `conn_t` carries `pid` (`sloth.h:96`), so the process
attribution claim holds. `pcap.min_severity` default 2 and
`pcap.key_cooldown_secs` default 3600 (`src/tune.c:121-122`). No tune
knob for the rule. Count semantics follow `fire_inv()`.

Changed: rule span `1203-1222` -> `1203-1220`. The conns description
said "TCP/UDP socket snapshot from INET_DIAG": only TCP comes from
INET_DIAG (`linux_tcpdiag.c` requests `IPPROTO_TCP`); UDP rows are read
from `/proc/net/udp` and `/proc/net/udp6` (`linux.c:123-124`) -
corrected. `bad_ips[]` `33-40` -> `34-41` (body and [4]). [6] now
quotes the Feodo Tracker blocklist page so the "IP feed" claim is
sourced rather than assumed.

Sources: [2]/[5] T1071: "blending in with existing traffic" confirmed
(page wording is "to avoid detection/network filtering by blending in
with existing traffic"). [6] Feodo Tracker families (Dridex, Emotet,
TrickBot, QakBot, BazarLoader) and IP-only nature confirmed.
[7] Pyramid of Pain: "Any reasonably advanced adversary can change IP
addresses whenever it suits them, with very little effort" verbatim.
[8] RFC 5737 "SHOULD NOT appear on the public Internet" verbatim. [1]
`research/mitre/T1071-004.md` lists `ALERT_TYPE_THREAT_IP` and carries
the three sentences quoted. [3][4] repo paths exist
(`alert-remediation.md:146` is the `THREAT_IP` section).

Second pass, 2026-10-27, HEAD 0d60387. No cited source file changed
since c5650a3. Re-read: `rule_threat_ip()` `rules_wired.c:1203-1220`
(`ti_match_ip(c->remote_addr, ...)`, CRIT, key `threat-i:%s`, detail
`"connection to %s:%u (demo IOC %s)"`, `match_ip` remote_addr,
`match_port` remote_port); `ti_match_ip()` `threat_intel.c:69-78` is
`strcmp`; `bad_ips[]` `:34-41`; `linux.c:123-124` for the UDP rows;
`sloth.h:96` `pid`; `tune.c:121-122`. One quotation corrected: the
corpus sentence is "A match says the indicator was on a list, not that
it is currently hostile" (`research/mitre/T1071-004.md:53-54`); the
body had "the address was on a list" inside quotation marks, now
"indicator". [2]/[5] [6] [7] [8] re-opened and re-confirmed verbatim
(T1071 "to avoid detection/network filtering by blending in with
existing traffic"; Feodo Tracker families "Dridex, Heodo (aka Emotet),
TrickBot, QakBot (aka QuakBot / Qbot) and BazarLoader (aka
BazarBackdoor)"; Pyramid of Pain IP sentence; RFC 5737).
