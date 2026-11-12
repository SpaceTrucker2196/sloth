---
type: NXDOMAIN_BURST
technique: T1071.004
rule_file: src/alerts/rules_wired.c:44 (rule_nxdomain_burst)
count_semantics: per poll tick (default 250 ms) while a source still has >= ALERT_NXDOMAIN_THRESH NXDOMAIN responses inside the trailing ALERT_NXDOMAIN_WINDOW_S = 60 s of dns_log; the rule recounts the whole window every tick, so `count` is tick re-evaluations, not NXDOMAIN packets - the packet count is in the detail
severity_assessment: agree - LOW is correct; an NXDOMAIN burst is a side effect, not an intent, and the dedicated DGA_DOMAIN / DNS_TUNNEL rules carry the WARN/CRIT shapes
false_positive_risk: high - browsers (Chromium's random-hostname interception probes), misconfigured search domains, dead CDNs/typos and offline mDNS/SRV lookups all produce NXDOMAIN bursts from one source
noise_verdict: quiet on the reference host - 3 keys, 177,498 fires, max_sev LOW (0). Fires are tick re-evaluations (<= 4/s) while a source holds >=10 NXDOMAIN in 60 s; 177,498 over 3 source IPs is roughly 59,000 evaluations each, ~4 h of sustained burst state per source - almost certainly a browser's probe traffic or a stub resolver with a bad search domain, not an implant. The key dedupes per source already; `observations` (not `count`) is what to trend. If it is a known client, add it to context rather than tuning
prevalence: the burst itself is extremely common (benign); genuinely malicious DGA/tunnel bursts are far rarer and better identified by DGA_DOMAIN/DNS_TUNNEL ([2],[6],[7])
tuning: [no --tune knob - ALERT_NXDOMAIN_THRESH (10) and ALERT_NXDOMAIN_WINDOW_S (60) are compile-time #defines in include/sloth.h:843-844, not in the registry; pcap.min_severity (default CRIT, so a LOW exports no pcap unless set to 0)]
researched: 2026-10-27
---
## What the rule checks

`rule_nxdomain_burst()` (`src/alerts/rules_wired.c:43-83`) builds a
per-source counter over a sliding window on each poll tick. It walks
`s->dns_log[]`, and for every entry that is a response
(`e->is_resp`) whose `answer` is exactly `"NXDOMAIN"` and whose
timestamp is within `ALERT_NXDOMAIN_WINDOW_S` = 60 s of `now`, it
increments a bucket keyed by `e->src`. The source is the DNS packet
source, i.e. the resolver that answered - set at
`src/dns_log.c:62` from `pkt->src` at `src/capture/capture.c:828`, where
port 53 UDP is parsed. (So on a network with one local resolver, the
"source" of every NXDOMAIN response is that resolver, and the rule keys
on it, not on the client that asked - a material limitation, see
Assessment.) The DNS parser writes the literal string `"NXDOMAIN"` for
RCODE 3 (`src/dns_log.c:74-75`).

There are at most 32 buckets (`bucket_t buckets[32]`, a 33rd distinct
source in one window is silently skipped, `rules_wired.c:60-61`). For
every bucket whose `count >= ALERT_NXDOMAIN_THRESH` (= 10), it fires
`ALERT_TYPE_NXDOMAIN_BURST` at `ALERT_SEV_LOW`, key
`nxdomain:<src>` (plain `snprintf`, `%.45s`), detail
`"<src> saw <count> NXDOMAIN responses in 60s"`, `match_ip = src`,
`match_port = 53`.

Both thresholds are compile-time `#define`s (`include/sloth.h:843-844`),
**not** in the `--tune` registry - unlike most detector thresholds since
#120, these two cannot be adjusted at runtime.

Count semantics: the whole 60 s window is recounted every tick and the
rule re-fires while the count stays at or above 10, so `fire()` bumps
`evaluations`/`count` up to ~4/s (`engine.c:478`); `observations` moves
only when the NXDOMAIN count in the window changes. The incident resolves
300 s after the last tick the burst was still present.

## The attack

NXDOMAIN is the DNS Name Error response, RCODE 3: "the domain referred to
by the QNAME does not exist" [4]. A burst of them from one asker is not an
attack in itself - it is a *side effect* of two things sloth cares about,
both filed under T1071.004 (DNS as an application-layer channel) or its
neighbour T1568.002 (Domain Generation Algorithms) [2].

The first is a DGA. Malware that hard-codes a C2 address dies when that
address is seized; malware that generates a fresh batch of candidate
domains every hour or day does not, because the defender cannot block
what has not been registered yet [6]. The bot tries each generated name;
only the few the operator actually registered resolve, and "most of the
DGA-generated (random) domains that a bot queries would result in
Non-Existent Domain (NXDomain) responses" - which is precisely the
signal Antonakakis et al. built Pleiades on, detecting DGA malware from
the NXDOMAIN traffic alone without reverse-engineering the binary [7].
Failed-lookup bursts as a detection feature in their own right have
published prior art too: Yadav & Reddy build botnet detection on bursts of
failed (NXDOMAIN) lookups [5].
MITRE's DGA detection guidance is to "correlate resolver logs with high
NXDOMAIN rates" alongside "repeated DNS queries to random-looking
domains" [6].

The second is a DNS tunnel. A tunnel encodes data in query names to a
server the attacker controls; the generated names mostly do not exist in
normal namespace, so failed lookups pile up as a by-product [2]. sloth
gives each of these its own dedicated detector - `DGA_DOMAIN` (scores the
label's entropy) and `DNS_TUNNEL` (length/entropy of the name) - both at
WARN/CRIT. `NXDOMAIN_BURST` is the cheap, content-free precursor: it sees
the failures without reading the names, which is why it is LOW and why
the corpus frames it as "failure as a side effect" [1].

What it is emphatically not: proof of malice. The same burst is produced
by entirely benign software, in volumes that dwarf the malicious case
(see Benign causes).

## Evidence that proves it

What sloth records:

- The alert detail: source and the NXDOMAIN count in the trailing 60 s.
- The `dns` JSONL records for that source around the alert window: each
  carries `qname`, `qtype`, and `answer` = `NXDOMAIN`
  (`docs/views/dns.md:48`). These are the actual failed names - the
  thing a responder must read to decide what the burst is.
- A per-alert pcap only if `pcap.min_severity` is lowered to 0 (default
  CRIT skips a LOW); then it is filtered on `match_ip = src`, port 53.
- No rule-specific `sensor_health` counter; `evict_dns_log` tells you if
  the DNS ring overflowed and the window undercounts.

To call it real (a DGA/tunnel): the failed `qname`s are long and/or
high-entropy, look algorithmic (`istgmxdejdnxuyla.ru`,
`cityjulydish.net` [6]) or carry encoded payload, come from one *client*
(not just one resolver), and the same host also trips `DGA_DOMAIN` or
`DNS_TUNNEL` and ideally `BEACONING` to a C2 [1][2]. What refutes it: the
failed names are ordinary words with a bogus search-domain suffix
appended (`printer.corp.local`, `wpad.example`), or are the 7-15
random-letter single-label probes Chromium emits (see below), or are
offline `*.local` / SRV lookups.

## Benign causes

- **Browser interception probes.** Chromium issues three DNS queries for
  random 7-15 character hostnames at startup, on IP change, and on DNS
  config change, to detect NXDOMAIN-hijacking resolvers. These probes
  were measured at ~45.8% of all DNS root-server traffic on a day in May
  2020 - on the order of tens of billions of queries a day - and they
  are designed to fail [8]. A laptop that changes networks a few times
  can trip this rule by itself.
- **Misconfigured search domains.** A stub resolver appending a dead
  search suffix to every short name turns one mistyped or
  single-label lookup into several NXDOMAINs (`docs/views/dns.md:65`,
  `docs/wiki/alert-remediation.md:104`).
- **Typos and autofill**, dead or moved CDNs, stale bookmarks.
- **Offline name resolution** - `wpad`, mDNS `.local`, SRV lookups for
  services that are not present.

Tell them apart by reading the `qname`s: benign bursts are ordinary or
single-label-random-at-startup; DGA bursts are sustained, algorithmic and
accompanied by `DGA_DOMAIN`.

## Assessment

LOW is the right call and the rule is honest about being a shape rather
than an intent [1][2]. Its weaknesses are two, and both matter for how
much to trust a firing:

1. **It keys on the DNS packet source, which on most networks is the
   resolver, not the client.** `e->src` is the responder's address
   (`capture.c:828` -> `dns_log.c:62`). Where all clients use one local
   resolver, every NXDOMAIN response shares that source, so the rule
   collapses all clients' failures into one bucket keyed by the resolver
   and loses which host is actually generating the names - exactly the
   attribution a responder needs. This also explains a low distinct-key
   count: the reference host fired on just 3 keys. A per-client variant
   (key on the asker) would be far more actionable.
2. **Its thresholds are not tunable.** 10-in-60 s is a compile-time
   constant; a site with chatty browsers cannot raise it without a
   rebuild. Given how much benign NXDOMAIN traffic exists [8], 10/60 s is
   a low bar.

Prevalence: the *burst* is one of the most common things on any network
because of browser probes and search-domain misconfig [8]; the malicious
case it hints at (DGA/tunnel) is real but rarer and is better served by
`DGA_DOMAIN`/`DNS_TUNNEL`, which read the names.

Reference-host noise: quiet in distinct incidents (3 keys) but heavy in
raw fires (177,498) because the rule re-evaluates every tick a burst is
present; ~59,000 evaluations per source is roughly 4 h of continuous
burst state each. That pattern - few sources, continuously over
threshold - is the fingerprint of a resolver forwarding a steady trickle
of browser/search-domain NXDOMAINs, not of an implant (an implant's DGA
burst is spiky and comes with high-entropy names and a C2 beacon). No
tuning is needed; the fix is interpretive: identify the 3 sources, and if
they are the site resolver, read the underlying `qname`s per client. The
dedup key already prevents multiple incidents per source, and
`observations` (which moves only when the count changes) is the figure to
watch rather than `count`.

Is the evidence sufficient to act on? Only as a pointer. The burst alone
says "names are failing"; the `dns` records (the actual `qname`s) are
what decide it, and they are retained. First response: pull the failed
names for the source; if algorithmic/high-entropy, correlate with
`DGA_DOMAIN`/`DNS_TUNNEL`/`BEACONING` on the same client and treat the
client as possibly infected; if they are ordinary names with a bad
suffix, fix the resolver/search-domain configuration
(`docs/wiki/alert-remediation.md:104-123`).

## Bibliography

1. research/mitre/T1071-004.md - MITRE ATT&CK T1071.004 DNS (names NXDOMAIN_BURST as "failure as a side effect"); the repo's corpus document for this kind; retrieved 2026-09-07 from https://attack.mitre.org/techniques/T1071/004/ (accessed 2026-10-27)
2. Application Layer Protocol: DNS, Technique T1071.004 - MITRE ATT&CK - https://attack.mitre.org/techniques/T1071/004/ (accessed 2026-10-27)
3. docs/wiki/alert-remediation.md § NXDOMAIN_BURST; docs/views/dns.md § NXDOMAIN burst; docs/views/alerts.md rule-table row (repo, read 2026-10-27)
4. RFC 2308, "Negative Caching of DNS Queries (DNS NCACHE)" §1, §2.1 (NXDOMAIN = Name Error, RCODE 3, QNAME does not exist); RFC 1035 §4.1.1 - https://www.rfc-editor.org/rfc/rfc2308 (accessed 2026-10-27)
5. S. Yadav, A. L. N. Reddy, "Winning with DNS Failures: Strategies for Faster Botnet Detection", SecureComm 2011, Security and Privacy in Communication Networks (LNICST, Springer, 2012) - botnet detection built on bursts of failed (NXDOMAIN) lookups - doi:10.1007/978-3-642-31909-9_26 (title and authors confirmed via Crossref, accessed 2026-11-01). Antonakakis et al. [7] is likewise NXDOMAIN-based detection: its abstract opens on the observation that most DGA-generated names a bot queries return NXDOMAIN
6. Domain Generation Algorithms, Technique T1568.002 - MITRE ATT&CK (detection analytic: "Correlate resolver logs with high NXDOMAIN rates"; "repeated DNS queries to random-looking domains") - https://attack.mitre.org/techniques/T1568/002/ (accessed 2026-10-27)
7. Antonakakis, Perdisci, Nadji, Vasiloglou, Abu-Nimeh, Lee, Dagon, "From Throw-Away Traffic to Bots: Detecting the Rise of DGA-Based Malware", USENIX Security 2012 - https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/antonakakis (accessed 2026-10-27)
8. M. Thomas (Verisign), "Chromium's impact on root DNS traffic", APNIC Blog, 2020 (random-hostname interception probes; ~45.8% of root traffic) - https://blog.apnic.net/2020/08/21/chromiums-impact-on-root-dns-traffic/ (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and every
external source re-opened.

Code: `rule_nxdomain_burst()` at `src/alerts/rules_wired.c:43-83`:
`is_resp` && `answer == "NXDOMAIN"` && `now - ts <= 60`, 32 buckets
(33rd skipped at `:60`), fires LOW when `count >= ALERT_NXDOMAIN_THRESH`
(10), key `nxdomain:%.45s`, detail `"%.45s saw %d NXDOMAIN responses in
%ds"`, `match_ip = src`, `match_port = 53`. `ALERT_NXDOMAIN_WINDOW_S` 60
and `ALERT_NXDOMAIN_THRESH` 10 are `#define`s at `sloth.h:843-844` and
are not in `src/tune.c` (confirmed: no `nxdomain` knob). `e->src` is
`pkt->src` (`capture.c:828` -> `dns_log_parse(..., pkt->src, ...)`, stored
at `dns_log.c:62`), so for a response row it is the answering resolver -
the attribution limitation stands. RCODE 3 -> literal `"NXDOMAIN"` at
`dns_log.c:74-75`. `ALERT_SEV_LOW == 0` (`sloth.h:887`). Noise
arithmetic: 177,498 / 3 = 59,166 evaluations per source; at 4/s about
4.1 h each - as stated.

Changed: rule span `43-84` -> `43-83`. Key precision `%.45s` noted. The
T1568.002 quotation "repeated failed lookups" is not on the page; the
page's analytic says "Identify processes issuing repeated DNS queries to
random-looking domains ... Correlate resolver logs with high NXDOMAIN
rates" - body text and bibliography re-worded to that.

Sources: [2] T1071.004 exists. [4] RFC 2308 §1 ("NXDOMAIN - an alternate
expression for the Name Error RCODE") and §2.1 ("the domain referred to
by the QNAME does not exist") verbatim. [6] fixed as above. [7] USENIX
page confirms the paper and the abstract sentence "Most of the
DGA-generated (random) domains that a bot queries would result in
Non-Existent Domain (NXDomain) responses" verbatim. [8] APNIC post
(Matthew Thomas, Verisign, with Duane Wessels): three lookups per
trigger, 7-15 lowercase letters, triggers on startup / IP change / DNS
config change, "45.80% of total traffic appear to be from Chromium
probes" in May 2020, ~60 billion queries a day - all confirmed. [1]
`research/mitre/T1071-004.md` lists `ALERT_TYPE_NXDOMAIN_BURST` and
carries the "Failure as a side effect" paragraph. [3] repo paths exist
(`alert-remediation.md:104`, `dns.md:48`/`:65`).

Second pass, 2026-10-27, HEAD 0d60387. No cited source file changed
since c5650a3. Re-read: `rule_nxdomain_burst()` `rules_wired.c:43-83`
(`is_resp`, `strcmp(answer, "NXDOMAIN")`, `now - ts > 60` skip, 32
`bucket_t`, 33rd skipped at `:60`, LOW, key `nxdomain:%.45s`, detail
`"%.45s saw %d NXDOMAIN responses in %ds"`, `match_ip` src, port 53);
`sloth.h:843-844`; `dns_log.c:62` (`out->src` = `src_ip`) and `:74-75`
(RCODE 3 -> `"NXDOMAIN"`); `capture.c:828` sits inside the UDP decoder's
`port_is(pkt, 53)` branch (`:822`), so "port 53 UDP" is right and
`pkt->src` is the answering resolver for a response row. No `nxdomain`
knob in `src/tune.c`. Nothing to change in the text. [2] [4] [6] [7]
[8] re-opened: RFC 2308 §1/§2.1, the T1568.002 analytic (both example
domains present on the page), the USENIX abstract sentence, and the
APNIC figures (three lookups, 7-15 letters a-z, startup / IP change /
DNS-config change, 45.80% on 13 May 2020, ~60 billion/day) all
re-confirmed verbatim.

Review pass, 2026-11-01. [5] previously claimed no public literature
exists for the burst heuristic; that was false and is replaced by Yadav &
Reddy (SecureComm 2011; Crossref confirms title, authors and
doi:10.1007/978-3-642-31909-9_26). [7] is now noted as NXDOMAIN-based
detection in the bibliography as well as the body. [8] re-credited to
M. Thomas, the post's author (Duane Wessels is a contributor), matching
DGA_DOMAIN [5].
