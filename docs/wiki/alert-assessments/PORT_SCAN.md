---
type: PORT_SCAN
technique: T1046
rule_file: src/alerts/rules_wired.c:27 (rule_port_scan)
count_semantics: per poll tick (default 250 ms, POLL_MS include/sloth.h:28; --refresh-ms) while the source's scan_entry stays flagged in s->scan_entries - not per connection, packet or port; `observations` moves only when the detail (the port count) changes
severity_assessment: agree - LOW is right for reconnaissance that reaches only this host's own listening ports; the rule cannot see anything worse than "touched N services"
false_positive_risk: medium - a legitimate client that opens many services on this host (a browser against a local web stack, a monitoring/vuln scanner, a CDN-less mesh peer) counts the same as nmap; but the private-source exclusion removes most LAN noise
noise_verdict: not seen on the reference host - host:null. Expected: the rule only counts *public* (non-RFC1918, non-CGNAT, IPv4) sources connecting to this host's *own* listening TCP ports, so a NAT'd host with no exposed services can never fire it; the silence is a blind spot, not cleanliness
prevalence: ubiquitous - unsolicited scanning is the baseline condition of every public IPv4 address ("Internet background radiation", [5]); whole-Internet scanners run continuously ([6], [7], [8])
tuning: [scan.port_thresh (default 8, 2..64; SCAN_PORT_THRESH include/sloth.h:145), pcap.min_severity (default 2 = CRIT only, so a LOW never exports a pcap unless set to 0), pcap.key_cooldown_secs]
researched: 2026-10-27
---
## What the rule checks

`rule_port_scan()` (`src/alerts/rules_wired.c:27-41`) does no detection
of its own. It walks `s->scan_entries[]` and, for every entry with
`flagged` set, fires `ALERT_TYPE_PORT_SCAN` at `ALERT_SEV_LOW` with key
`scan:<ip>` (plain `snprintf`, not an `akey_*` builder - the IP comes
from the kernel socket table, not from remote-chosen text), detail
`"<ip> scanned <port_count> distinct ports"`, and `match_ip = ip`,
`match_port = 0`.

The table is built by `scan_update()` (`src/scan.c:53-110`), which runs
in the DERIVE phase of every poll tick (`src/poll.c:214`) over the
host's own TCP socket snapshot (`s->conns`, from INET_DIAG with every
state requested, `src/platform/linux_tcpdiag.c:32`):

- Only TCP rows that are not themselves a LISTEN socket (`scan.c:63-64`).
- Only remote addresses that pass `scan_is_routable()` (`scan.c:15-26`):
  RFC 1918, loopback, link-local, 100.64/10 CGNAT, 0/8 and 224+/8 are
  dropped. The check is `sscanf("%u.%u")`, so **any IPv6 remote fails
  the parse and is dropped too** - an IPv6 scanner is invisible.
- Only when the *local* port is in this host's LISTEN set
  (`scan_build_listen_set()`, `scan.c:39-47`; check at `scan.c:70`).
  This is the #41 fix: outbound flows with ephemeral local ports can no
  longer look like an inbound scan. The consequence is that **a probe to
  a closed port creates no socket and is never counted**: the rule
  counts distinct *listening* ports a public source has reached. A host
  with fewer than `scan.port_thresh` listening TCP ports cannot raise
  this alert at all.
- Per source, distinct local ports are unioned into `ports[]` (max
  `MAX_SCAN_PORTS` = 64); `flagged` latches once `port_count >=
  tune_val(TUNE_SCAN_PORT_THRESH)` (`scan.c:93-100`). Default 8.
- Entries expire `SCAN_TTL_SECS` = 60 s after `last_seen`
  (`scan.c:104-109`); `last_seen` is refreshed every tick while *any*
  qualifying socket from that IP is still in the table (ESTABLISHED,
  TIME_WAIT, SYN_RECV all count), so a lingering connection keeps the
  alert re-asserted.
- The table holds `MAX_SCAN_ENTRIES` = 32 sources and refuses a 33rd
  (`scan.c:80`) with no `evict_*` counter - this is one of the tables
  whose loss is unmeasured.

Count semantics follow from `fire_inv()` (`src/alerts/engine.c:478-489`):
each tick the key is re-asserted bumps `evaluations` (aliased as
`count`); `observations` moves only when the rendered detail changes,
i.e. when `port_count` grows. The incident resolves `ALERT_RESOLVE_AFTER_S`
= 300 s after the last assertion (`include/sloth.h:860`), i.e. about
six minutes after the source's last socket disappears.

## The attack

A port scan is the adversary asking every door of a host whether it is
open, before choosing one to push on. MITRE files it as T1046, Network
Service Discovery: enumerating the services on remote hosts by "port,
vulnerability, and/or wordlist scans using tools that are brought onto a
system" [2]. The canonical tool is Nmap, whose default SYN scan sends a
SYN and reads the reply without completing the handshake, while its
connect scan (`-sT`) asks the operating system to `connect()` and so
completes the handshake on open ports - which is why "target machines
are more likely to log the connection" [4]. At Internet scale, masscan
"can scan the entire Internet in under 5 minutes, transmitting 10
million packets per second, from a single machine", using "its own ad
hoc TCP/IP stack" [7]; services such as Shodan continuously
query "all devices directly connected to the Internet" for banner data
[8]. What the attacker gains is an inventory: which services exist, and
therefore which exploit, brute-force or default-credential attempt to
try next - the follow-on alerts (`ATTACK_PATH`, `ATTACK_TOOL_UA`, the
brute-force rules) are where the scan turns into an intrusion [1].

Which of these sloth can see depends on the scan type. A connect scan
or any scan that reaches a listening port leaves a socket (SYN_RECV for
a half-open SYN, TIME_WAIT after a connect), and INET_DIAG reports all
states, so those are counted. A SYN scan of a port that is closed
leaves nothing. A scan of *another* host on the LAN is never in this
host's socket table and is not this rule's business.

## Evidence that proves it

What sloth records:

- The alert row: `<ip> scanned <N> distinct ports`, `match_ip` set,
  `match_port` 0. The JSONL `alert`/`alert.create` carries `key`,
  `incident_id`, `evaluations`, `observations`; `observations` is the
  number of times the port count grew, which is the honest "how many
  new ports" figure.
- The `scan_entry` JSONL record (`ip`, `port_count`, `first_seen`,
  `last_seen`, `flagged`, `ports[]`; `docs/wiki/jsonl-schema.md:719`)
  and the `--db` scan table (flagged entries only, `src/db.c:1739-1743`)
  list the exact local ports touched.
- A per-alert pcap is written only if `pcap.min_severity` is lowered to
  0 (the default 2 exports CRIT only, `docs/wiki/cli-reference.md:76`);
  then the general packet ring is filtered on `match_ip` and the file
  holds the SYNs and RSTs/SYN-ACKs of the scan, at most 64 captured
  bytes each (`docs/wiki/pcap-export.md`).
- No `sensor_health` counter is specific to this rule; the scan table
  has no eviction counter.

To call it real: the `ports[]` list spans unrelated services (22, 80,
443, 3306, 5432, 8080...) and `first_seen`..`last_seen` is seconds, not
hours - sequential or near-simultaneous touches across unrelated ports
is the scanner's fingerprint, and the `conn` snapshot around the alert
shows those sockets in SYN_RECV or TIME_WAIT with no bytes exchanged.
What refutes it: the same source holds long-lived ESTABLISHED sessions
with traffic on each port (a client using the services, not probing
them), or the ports are all one application's cluster (a reverse-proxy
fan-out), or the source is a documented scanner (GreyNoise classifies
search engines, universities and security research as benign actors
[6]).

## Benign causes

- **Internet background radiation.** Pang et al. measured 138 remote
  hosts each scanning 25,000 or more LBL addresses in one day - "more
  than double the site's entire quantity of successfully-established
  incoming connections" [5]. For an exposed host this alert is the
  weather; the remediation page says the same [1].
- **Search engines and research scanners** - Shodan [8], Censys,
  universities; GreyNoise's benign class exists for exactly these [6].
- **The operator's own vulnerability scanner or monitoring**
  (`docs/wiki/alert-remediation.md:56-66`), if it runs from a public
  address - from a private one it is excluded by `scan_is_routable()`.
- **One legitimate client, many services**: a reverse proxy or a remote
  user with SSH, a web UI, a database port and a metrics endpoint all on
  this host. The ports list tells the two apart.
- **NAT'd clusters**: many real users behind one public IP each using
  one service add up to one "scanner" touching eight ports.

## Assessment

LOW is the right severity: the rule reports that a public address
reached at least eight of this host's listening services, which is
reconnaissance "early rather than urgent" [1]; it does not know whether
any port was closed-probed, whether the source is hostile, or what it
did next. Prevalence is total - every public IPv4 address is scanned
continuously [5][7][8] - so on an exposed host the signal is the source
and the follow-on, not the scan.

The reference host reports no firing at all (host:null). Given the
rule's inputs that is the expected outcome for a host behind NAT with no
exposed TCP services, and it should not be read as "no one scanned": the
rule is blind to (a) private-source scans, so an attacker already on the
LAN running nmap against this host is invisible; (b) all IPv6 sources;
(c) probes to closed ports; (d) scans of any other host. The honest
statement is that `PORT_SCAN` covers the case "a public address found
and touched >= 8 of my open services", and nothing else. The evidence
sloth keeps (`ports[]`, first/last seen, the socket states) is
sufficient to confirm that narrow case; it is not sufficient to grade
the source's intent.

Noise if it did fire: `count` grows at up to 4/s for as long as any
socket from the source lingers plus 60 s TTL, then the incident resolves
300 s later; `observations` stays at the number of distinct port-count
values. That is tolerable for a LOW, and the key per source already
dedupes. Two things worth changing: count the private-source case under
a separate, higher-severity key (the remediation page itself says an
inside scanner is the finding [1], and `MY_NETWORK_RECON` is the
wireless analogue), and add an `evict_scan_entry` counter so a full
32-row table reports its loss like every other table since #110.

First response: read `ports[]` and the source; if it is a public
address and nothing followed, log it; if it is inside the network
(which this rule cannot show today - look at the `conn` view for
RFC 1918 peers touching many local ports) isolate and inspect the
source host [1].

## Bibliography

1. research/mitre/T1595.md - MITRE ATT&CK T1595 Active Scanning (with T1046), the repo's corpus document for this kind; retrieved 2026-09-07 from https://attack.mitre.org/techniques/T1595/ (accessed 2026-10-27)
2. Network Service Discovery, Technique T1046 - Enterprise | MITRE ATT&CK - https://attack.mitre.org/techniques/T1046/ (accessed 2026-10-27)
3. docs/wiki/alert-remediation.md § PORT_SCAN; docs/views/alerts.md rule table row `PORT_SCAN` (repo, read 2026-10-27)
4. Nmap Reference Guide - Port Scanning Techniques - https://nmap.org/book/man-port-scanning-techniques.html (accessed 2026-10-27)
5. Pang, Yegneswaran, Barford, Paxson, Peterson, "Characteristics of Internet Background Radiation", IMC 2004 - https://conferences.sigcomm.org/imc/2004/papers/p27-pang.pdf (accessed 2026-10-27)
6. GreyNoise, "Understanding GreyNoise Classifications" - https://docs.greynoise.io/docs/understanding-greynoise-classifications (accessed 2026-10-27)
7. masscan README, robertdavidgraham/masscan - https://github.com/robertdavidgraham/masscan (accessed 2026-10-27)
8. Shodan Help Center, "What is Shodan?" - https://help.shodan.io/the-basics/what-is-shodan (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and every
external source re-opened.

Code (rule_file, count_semantics, thresholds, key): `rule_port_scan()`
at `src/alerts/rules_wired.c:27-41`, key `scan:<ip>`, LOW, `match_ip =
ip`, `match_port = 0`, detail string - all exactly as written.
`scan_update()`, `scan_is_routable()` (incl. the `sscanf("%u.%u")` IPv6
blind spot), the LISTEN-set check, `MAX_SCAN_PORTS` 64, `SCAN_TTL_SECS`
60, `MAX_SCAN_ENTRIES` 32, `tune_val(TUNE_SCAN_PORT_THRESH)` default 8
(range 2..64 in `src/tune.c:182`), INET_DIAG `idiag_states =
0xffffffff` (`linux_tcpdiag.c:32`), `fire_inv()` evaluations /
observations split (`engine.c:478-489`), `ALERT_RESOLVE_AFTER_S` 300
(`sloth.h:860`), `POLL_MS` 250 (`sloth.h:28`), flagged-only `--db`
rows (`db.c:1739-1743`), `scan_entry` JSONL row
(`jsonl-schema.md:719`), `pcap.min_severity` default 2 - all confirmed.
No `evict_scan*` field exists in `sensor_health` (confirmed by grep),
so the "loss is unmeasured" claim stands. Noise arithmetic (4/s while
flagged, +60 s TTL, +300 s resolve) follows from those constants.

Changed: `src/poll.c:212` -> `:214` (where `scan_update()` is actually
called); `scan.c:79` -> `:80` (the `MAX_SCAN_ENTRIES` refusal). Two
quotations corrected to the sources' wording: Nmap says "target
machines are more likely to log the connection" (not "more likely to be
logged by target systems"); masscan says "its own ad hoc TCP/IP stack"
(not "asynchronous").

Sources: [2] T1046 quote confirmed verbatim. [4] confirmed (wording
fixed). [5] PDF fetched and read: "138 different remote hosts each
scanned 25,000 or more LBL addresses ... more than double the site's
entire quantity of successfully-established incoming connections" is
verbatim from the introduction. [6] GreyNoise benign class confirmed
("search engine, security research organization, university").
[7] masscan confirmed (wording fixed). [8] Shodan: "gathers information
about all devices directly connected to the Internet" and banner text
confirmed. [1] `research/mitre/T1595.md` exists, lists
`ALERT_TYPE_PORT_SCAN` in `alert_kinds` and names `PORT_SCAN` (T1046)
in its body. [3] repo paths exist (`alert-remediation.md:56` is the
`PORT_SCAN` section).

Second pass, 2026-10-27, HEAD 0d60387. `git diff c5650a3..HEAD -- src
include research` touches nothing this entry depends on, so every code
claim above was re-read rather than re-derived: `rule_port_scan()`
`rules_wired.c:27-41`, `scan_update()` `scan.c:53-110` (routable filter
`:66`, LISTEN-set check `:70`, 33rd-source refusal `:80`, flag latch
`:98-99`, TTL sweep `:104-109`), `fire_inv()` `engine.c:478-489`,
`poll.c:214`, `linux_tcpdiag.c:32`, `tune.c:182`, `db.c:1739-1743` -
all as stated. One line span tightened: `scan_is_routable()` is
`scan.c:15-26`. [5] could not be text-extracted by the fetcher this
time; the PDF was pulled down and read with `pdftotext`, and the
introduction reads verbatim: "138 different remote hosts each scanned
25,000 or more LBL addresses, for a total of about 8 million connection
attempts. This is more than double the site's entire quantity of
successfully-established incoming connections" - the entry's quotation
is a faithful excerpt. [2] [4] [6] [7] [8] and the T1595 page re-opened
and re-confirmed; no wording changes needed.
