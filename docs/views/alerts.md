# Alerts  `[v]`

Rule-derived events: port scans, deauth floods, NXDOMAIN bursts,
threat-intel hits, periodic beaconing.

## Engine

A small dedup-by-key ring (`src/alerts.c`) — each rule scans the
current state every poll, builds a stable key (e.g. `scan:<ip>`,
`threat-d:<domain>`), and either bumps an existing alert's hit count
or appends a fresh one. New keys also get a JSONL log line and (if
`--pcap-dir` is set) a per-alert pcap dump of the matching packets.

## Severity tiers

Three tiers, rendered as a yellow → orange → red palette and propagated
to every panel that touches a flagged IP (see "Cross-panel coloring"
below):

| Tier | Hue    | Meaning |
|------|--------|---------|
| LOW  | yellow | Reconnaissance / suspicious-but-passive. Worth logging; nothing on fire yet. |
| WARN | orange | Clearly malicious behaviour, not yet an active exploit. |
| CRIT | red    | Active attack or IOC hit. Pages somebody. |

## Rules

Every rule maps to a canonical MITRE ATT&CK technique (populated by
`alert_technique()` in `src/alerts.c` and emitted as a `"technique"`
field in the JSONL log). Posture alerts that don't correspond to
adversary behaviour map to the empty string and the JSONL field is
omitted.

| Rule | Sev | ATT&CK | Trigger | match_ip / port |
|------|-----|--------|---------|-----------------|
| `PORT_SCAN` | LOW  | T1046     | one source touched ≥ 8 distinct local ports | scanner / 0 |
| `NXDOMAIN_BURST` | LOW  | T1071.004 | ≥ 10 NXDOMAIN replies to one source in 60 s | src / 53 |
| `PROBE_FLOOD` | LOW  | T1595     | 802.11 client flooding probe-requests | — (L2 only) |
| `DEAUTH_FLOOD` | WARN | T1498.001 | ≥ 5 deauth/disassoc frames in 5 s to one target. **CRIT** when the target BSSID is `--my-bssid` designated (#52) | — (L2 only) |
| `BEACON_FLOOD` | WARN | T1498.001 | ≥ 40 distinct new BSSIDs first-seen in 10 s (mdk3/mdk4-style fake-AP flood) | — (L2 only) |
| `AUTH_FLOOD` | WARN | T1499     | ≥ 30 802.11 auth frames to one BSSID in 5 s (association-table exhaustion DoS). **CRIT** when the BSSID is `--my-bssid` designated (#52) | — (L2 only) |
| `BEACONING` | WARN | T1071     | flow with ≥ 5 samples, mean ≥ 10 s, jitter/mean ≤ 0.25 | remote / port |
| `DGA_DOMAIN` | WARN | T1568.002 | DNS qname matches DGA entropy heuristic | src / 53 |
| `WEAK_TLS` | WARN | T1600     | TLS 1.0/1.1 or known-weak cipher observed | src / 443 |
| `NO_MONITOR_MODE` | WARN | —         | ≥1 iface seen but none in monitor mode — WiFi SIGINT views will be empty | — (host posture) |
| `CLEARTEXT_CRED` | WARN | T1040     | username observed in the clear (HTTP Basic, FTP, POP3, IMAP, SMTP AUTH PLAIN/LOGIN; passwords never stored) | client / server-port |
| `THREAT_DOMAIN` | CRIT | T1071.004 | DNS qname matches embedded IOC list | src / 53 |
| `THREAT_IP` | CRIT | T1071     | conn remote IP matches embedded IOC list | remote / port |
| `ARP_SPOOF` | CRIT | T1557.002 | one IP maps to two MACs within a short window | — (L2 only) |
| `ROGUE_DHCP` | CRIT | T1557     | unexpected DHCP OFFER from a non-baseline server | dhcp-srv / 67 |
| `EVIL_TWIN` | CRIT | T1557     | duplicate SSID with mismatched BSSID / cipher | — (L2 only) |
| `KARMA_AP` | CRIT | T1557     | one BSSID beacons ≥3 distinct SSIDs; detail names PNL-match count (PineAP beacon-response), flags a concurrent deauth flood as deauth-then-lure, marks `+PMKID` when a PMKID has been harvested **from that BSSID** (#68 — a protocol observable, unlike a tool's beacon quirks), and names the tool when the signature table can. That table is **empty on purpose**: a tool's fingerprint is an empirical fact about a binary, not something derivable from a spec, and invented rows would pass every test while matching nothing. See [[tool-fingerprints]] | — (L2 only) |
| `SSID_CONFUSION` | CRIT | T1557.004 | same SSID advertised on a second BSSID with downgraded RSN — WPA3→WPA2, MFP required→off, GCMP→CCMP (CVE-2023-52424), or 802.1X-Enterprise cloned as PSK (eaphammer/hostapd-wpe lure, #31) | — (L2 only) |
| `MGMT_FUZZ` | WARN/CRIT | T1499 | malformed beacon IEs from one BSSID (length overrun, oversize SSID, truncated RSN) — mdk4 mode m / crafted aireplay frames; WARN ≥3, CRIT ≥5 | — (L2 only) |
| `ROGUE_RADIUS` | WARN/CRIT | T1557.004 | a BSSID's 802.1X EAP conversation offered a weak inner method (EAP-MD5/GTC → CRIT) or leaked a real username with no anonymous outer identity (→ WARN) — eaphammer / hostapd-wpe lure | — (L2 only) |
| `DNS_TUNNEL` | CRIT | T1071.004 | dnscat2 / iodine signature in DNS traffic | src / 53 |
| `BLOCKACK_ATTACK` | WARN/CRIT | T1499.004 | a Block-Ack Request whose Starting Sequence Number jumps forward more than 128 frames — the **Bl0ck** attack ([arXiv 2302.05899](https://arxiv.org/pdf/2302.05899)). A spoofed BAR sent on behalf of a legitimate station forces its peer to advance the Block-Ack receive window past frames still queued; everything skipped is discarded and the connection stalls. Quiet by design: no deauth, no flood, nothing the rate rules watch. What the operator sees is a client that stopped working. The comparison is **modulo 4096** — SSN is a 12-bit field and a station transmitting steadily wraps every few thousand frames, so a plain subtraction makes this a false-positive generator. State is per `(receiver, transmitter, TID)`: traffic classes have independent sequence spaces. A retry burst on the channel is reported but **not required** — requiring it would make the rule depend on `rf_quality` having sampled the right channel at the right moment. **CRIT** on `--my-bssid` | — (L2 only) |
| `CAPTIVE_PORTAL` | WARN/CRIT | T1557 | a connectivity-check probe answered by something other than the real endpoint. Four kinds under one type: a **complete** response on a sentinel URL that differs from the published answer, a sentinel host resolving into RFC1918/CGNAT space, one resolving outside its operator's known range, or a TLS ClientHello for a sentinel going to a private address. The three signals are independent on purpose — a portal that chunks its HTTP answer to evade the body check still has to answer the DNS query. **Only fires on a complete body**: sloth does not reassemble TCP, so a prefix that differs is a segment boundary, not an interception. `DNS_UNEXPECTED` is WARN because CDN ranges change; the rest are CRIT. Benign trigger: a hotel network, or a local DNS filter answering for the sentinel. See [[captive-portal]] | — |
| `RTS_FLOOD` | WARN/CRIT | T1498 | one source sending ≥ 500 RTS/s **sustained for ≥ 5 s**. An RTS asks every radio in earshot to stay quiet for the NAV reservation it carries — the mechanism that makes 802.11 work around hidden nodes, and a way to silence a channel without transmitting anything a flood detector was watching for. The sustain requirement is the whole difference from a retry burst: a client fighting interference emits RTS hard for a moment, a flood keeps going. **CRIT** when the Duration exceeds the legal maximum of 32767 µs — no conforming radio emits one, so that is a generated frame rather than a busy client — or when the source is `--my-bssid`. Benign trigger: a hidden-node pair on a congested channel, which is why the rate is set well above saturation | — (L2 only) |
| `FRAG_PLAINTEXT` | CRIT | T1557 | an unprotected, non-EAPOL data frame from a station whose **encrypted** traffic sloth has already seen on that BSS — FragAttacks CVE-2020-26140 and CVE-2020-26143 ([Vanhoef, USENIX Security 2021](https://papers.mathyvanhoef.com/usenix2021.pdf)). The gate is deliberately *not* "the beacon advertised RSN": it is per `(BSSID, station)` and it is **ordered**, so protection must have been witnessed before the plaintext frame. That is what makes it quiet on an open network and on a client that is still associating — the two cases that would otherwise drown the rule. EAPOL is exempt (rekeying is legitimately unprotected), as are Null and QoS-Null (no body, always unprotected) and any frame whose EtherType cannot be read, which includes continuation fragments. CRIT on the first hit, not on a threshold: a station past key install has no legitimate reason to send one. Benign trigger: a driver bug — which is what nine of the twelve FragAttacks CVEs are. See [[fragattacks]] | — (L2 only) |
| `FRAG_BCAST` | CRIT | T1557 | a **fragmented** group-addressed data frame with Protected clear on a BSS where protection has been witnessed — CVE-2020-26145. Broadcast reassembly is not permitted in an RSN at all, so the fragment is already a violation before anything reassembles it; the rule fires on the fragment rather than waiting for a completion only the victim can perform. Needs no LLC header and has nothing to exempt, because broadcast EAPOL does not exist. Benign trigger: as above, a non-conforming AP. See [[fragattacks]] | — (L2 only) |
| `RRM_SURVEY_ABUSE` | WARN/CRIT | T1595.002 | ≥ 6 **targeted** 802.11k Beacon Requests at one (BSSID, STA) pair in 5 min — an AP asking a client to scan and report what it can hear. The client obliges; that is the protocol working. It is also how an AP enumerates the airspace *through someone else's radio*, and the report is exactly the input for a convincing evil twin. The discriminator is not the rate: a legitimate AP asks about SSIDs **it** advertises, so the rule fires only when the asker has been heard beaconing *something* but never that SSID. Requests with no SSID subelement are ordinary steering and never count. **CRIT** when an outsider (not `--my-bssid`) surveys a `--my-ssid` network, or the asker is a known twin. Benign trigger: a controller-managed deployment whose VAP layout sloth has only partly observed | — (L2 only) |
| `CSA_ABUSE` | WARN/CRIT | T1557 | a Channel Switch Announcement misused to move clients. Three shapes, descending confidence: **forged TA** (an Action frame whose addr2 is not the BSSID it claims to speak for — in a genuine announcement they are equal), **storm** (≥ 4 distinct target channels from one BSSID in 60 s; a legitimate AP picks one and commits), and **steering** (the target channel hosts the rogue half of a detected twin pair). Cheaper and quieter than a deauth flood, and it works on firmware that ignores deauth — roaming support is a certification checkbox. **CRIT** on a forgery, a twin-hosting target, a target AP with a `WPA_DOWNGRADE` posture, or `--my-bssid`. A beacon's addr2/addr3 mismatch is *not* treated as a forgery: they are equal by construction, so a difference means the frame was misread. Benign trigger: a DFS radar event moving an AP off a weather-radar channel | — (L2 only) |
| `PEAP_NO_SERVER_CERT` | WARN/CRIT | T1557 | a TLS-in-EAP method (PEAP / EAP-TLS / EAP-TTLS) reached **EAP-Success** without the AP ever presenting a TLS ServerHello or Certificate — the client authenticated to a server that never proved who it was ([CVE-2023-52160](https://nvd.nist.gov/vuln/detail/CVE-2023-52160)). Only AP→STA frames count: a Certificate travelling the other way is the *client* authenticating. EAP-Failure is not a finding — the client refused, which is correct behaviour. **CRIT** when the BSSID is `--my-bssid` or the STA is on the `--known-macs` roster, because that is the operator's own fleet demonstrating it would fall for a rogue enterprise AP. The detail distinguishes "no ServerHello" (unambiguous) from "no Certificate observed" (a long chain can cross an EAP fragment boundary sloth does not reassemble). See [[enterprise-rogue]] | — (L2 only) |
| `WPA_DOWNGRADE` | WARN/CRIT | T1600 | an AP advertising a **weaker lane beside its primary one**, after ≥ 30 s of observation. Four kinds, one alert each: PSK and SAE both on offer (WPA2/WPA3 transition), an OWE BSS paired with an open companion, MFP capable-but-not-required on a SAE BSS (the Dragonblood primitive), and a legacy WPA1 IE beside the RSN IE (TKIP still on offer). None is an attack — each is the *prerequisite* [CVE-2023-52424](https://nvd.nist.gov/vuln/detail/CVE-2023-52424) and [Dragonblood](https://www.kb.cert.org/vuls/id/871675) need. **CRIT** when the BSSID is `--my-bssid`, or when a client has actually taken the weak lane (an assoc-request downgrade from #60 within the hour). The 30 s floor exists because a single beacon caught mid-`--hop` is a sample, not a configuration. Benign trigger: a migration window an operator is deliberately running | — (L2 only) |
| `BTM_ABUSE` | WARN/CRIT | T1498 | ≥ 4 802.11v BSS-Transition-Management Requests carrying **Disassociation Imminent** at one (BSSID, STA) pair in 60 s — the deauth-equivalent forced roam ([Ali & Kulkarni 2023](https://www.sciencedirect.com/science/article/abs/pii/S0167404823001712)). Gated on the Disassociation-Imminent bit, not the rate alone: a Request without it leaves the client free to decline and is what ordinary load balancing looks like, so rate alone would fire on every busy enterprise AP. Detail carries both counts (`4/7 req 60s`), the candidate list, and two tells — a transmitter or a candidate BSSID never heard beaconing. **CRIT** when a candidate is the rogue half of a detected twin pair, or the BSSID is `--my-bssid`, or the STA is on the `--known-macs` roster. Benign trigger: an aggressive band-steering policy on a controller-managed network | — (L2 only) |
| `RF_DEGRADED` | WARN | T1498     | a channel's 802.11 retry ratio at or above 40% over at least 100 frames in a 5-minute window. The passive signature of a channel that is not working. Deliberately **not** called jamming: the same measurement comes from a microwave oven, a distant client at the edge of range, a hidden node, or a deliberate jammer — the detail carries the ratio and sample size so the operator attributes it. Needs monitor mode | — (L2 only) |
| `UNKNOWN_DEVICE` | WARN | T1200     | a device associated to a `--my-ssid`/`--my-bssid` network that is absent from the `--known-mac`/`--known-macs` roster. **Requires both** — silent unless the operator opted into each. Keys on association, not probing: per-SSID MAC randomisation is stable across reconnects so a rostered device keeps its address, whereas probe randomisation rotates constantly and would make every passing handset "unknown". Benign trigger: a contractor's laptop nobody rostered |
| `RECURRING_TRANSIT` | WARN | T1595     | the same device observed *passing* (see [[probe]] presence classification) ≥ 3 times within 2 h. One drive-by is traffic; a circuit is reconnaissance. Observations within 5 min coalesce into one pass, so a slow drive-by is not counted as three. MACs linked by a seqnum correlation count as one device, so randomisation does not defeat it. Benign trigger: a delivery round, or a neighbour with a short commute | — (L2 only) |
| `MY_NET_RECON` | WARN | T1595     | a client's PNL names an operator-designated SSID (`--my-ssid`) while the client is **not** associated to that network. Off entirely unless something is designated. Association exonerates — checked by designated BSSID *or* SSID, so the operator's own users never trip it. Benign trigger: a former guest's phone still remembers the network | — (L2 only) |
| `ICMP_TUNNEL` | WARN | T1095     | ≥ 8 Echo Requests one src→dst pair in 60 s carrying oversized payloads (≥ 64 B, above default ping's 56/32 B) — ptunnel / icmptunnel / Loki covert channel; detail shows the payload size range. Benign trigger: sustained `ping -s` / MTU path testing | dst / 0 |
| `ATTACK_TOOL_UA` | CRIT | T1595     | HTTP User-Agent matches known offensive tooling | src / 80 |
| `ATTACK_PATH` | CRIT | T1190     | HTTP path matches known exploit signature | src / 80 |
| `SMB1_USE` | CRIT | T1210     | SMB1 dialect seen on the wire (deprecated 2017) | src / 445 |
| `KERB_PREAUTH_BURST` | WARN | T1110.003 | Kerberos AS-REQ pre-auth failure spray (password spray) | src / 88 |
| `LDAP_SEARCH_FLOOD` | WARN | T1087.002 | LDAP search-request flood (AD enumeration) | src / 389 |
| `BGP_NOTIFICATION_BURST` | WARN | T1499     | burst of BGP NOTIFICATION frames on a session | src / 179 |
| `SSH_BRUTE_FORCE` | WARN | T1110.001 | SSH connect-then-drop pattern from one source | src / 22 |
| `RDP_BRUTE_FORCE` | WARN | T1110.001 | RDP X.224 CR bursts (Cobalt Strike / mstsc.exe) | src / 3389 |
| `SNMP_COMMUNITY_BRUTE` | WARN | T1110.001 | SNMPv1/v2c fan-out with rotating community strings | src / 161 |
| `MQTT_BROKER_BRUTE` | CRIT | T1110.001 | MQTT CONNECT/CONNACK-fail burst (Mirai-class sweep) | src / 1883 |
| `ROGUE_RA` | CRIT | T1557     | unexpected IPv6 Router Advertisement | src / 0 |
| `EVIL_TWIN_PROXIMITY` | WARN | T1557     | evil-twin candidate at similar RSSI to the real AP | — (L2 only) |

## Cross-panel coloring

When a rule fires with a known `match_ip`, the IP is added to the
TUI's alert-hot list at the rule's severity for the next hour
(`ALERT_HOT_TTL_S`). Every panel that renders that IP — connections,
top hosts, packets, hostname-resolved dashboard rows — paints it in
the matching tier colour. Promotion only: a later LOW alert on an IP
that already has a CRIT entry does not demote it.

The IOC lists in
[`src/threat_intel.c`](../../src/threat_intel.c) are intentionally
synthetic (RFC 5737 doc IPs, `.testing` / `.example` sentinels). They
exist so the alerts pipeline can be exercised in tests — swap in your
own feed for production.

## View

```
 ── Alerts: 2 crit 1 warn 2 low 5 total ────────────────────────
 Time      Sev   Title            n    Detail
 22:01:01  CRIT  THREAT_IP        1    connection to 192.0.2.66:443 (IOC 192.0.2.66)
 22:01:01  CRIT  THREAT_DOMAIN    4    192.168.1.5 queried malware.testing.com (IOC ...)
 22:00:55  WARN  BEACONING        12   203.0.113.7:443 every 60s (jitter=1.2s, n=12)
 22:00:30  LOW   PORT_SCAN        1    10.0.0.99 scanned 18 distinct ports
 22:00:15  LOW   NXDOMAIN_BURST   3    192.168.1.50 saw 15 NXDOMAIN responses in 60s

 ── context: ip=192.0.2.66  port=443  region=ARIN (US/CA)  owner=(unknown)
```

Row colours match the severity tier: LOW = yellow, WARN = orange,
CRIT = red. The Count column heat-colours on ≥ 2 hits to flag
sustained conditions.

The footer below the table shows enrichment for the selected alert:
RIR region (from the `/8` table) and embedded hosting-org lookup.

## Keybindings

`↑`/`↓` navigate. `c` clears all alerts and their pcap-dumped state
(future hits of the same key re-arm).

## Threat-intel

To add your own IOCs, edit `bad_domains[]` and `bad_ips[]` in
[`src/threat_intel.c`](../../src/threat_intel.c). Domain matching is
suffix-aware and case-insensitive — `evilcorp.example` matches both
itself and `*.evilcorp.example` but not `notevilcorp.example`.

## See also

- Per-rule modules: [`src/beacon_detect.c`](../../src/beacon_detect.c),
  [`src/scan.c`](../../src/scan.c),
  [`src/deauth_snoop.c`](../../src/deauth_snoop.c).
- Per-alert pcap: [`src/alert_pcap.c`](../../src/alert_pcap.c).
