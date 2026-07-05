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
| `DEAUTH_FLOOD` | WARN | T1498.001 | ≥ 5 deauth/disassoc frames in 5 s to one target | — (L2 only) |
| `BEACON_FLOOD` | WARN | T1498.001 | ≥ 40 distinct new BSSIDs first-seen in 10 s (mdk3/mdk4-style fake-AP flood) | — (L2 only) |
| `AUTH_FLOOD` | WARN | T1499     | ≥ 30 802.11 auth frames to one BSSID in 5 s (association-table exhaustion DoS) | — (L2 only) |
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
| `KARMA_AP` | CRIT | T1557     | one BSSID beacons ≥3 distinct SSIDs; detail names PNL-match count (PineAP beacon-response) and flags a concurrent deauth flood as deauth-then-lure | — (L2 only) |
| `SSID_CONFUSION` | CRIT | T1557.004 | same SSID advertised on a second BSSID with downgraded RSN — WPA3→WPA2, MFP required→off, GCMP→CCMP (CVE-2023-52424), or 802.1X-Enterprise cloned as PSK (eaphammer/hostapd-wpe lure, #31) | — (L2 only) |
| `MGMT_FUZZ` | WARN/CRIT | T1499 | malformed beacon IEs from one BSSID (length overrun, oversize SSID, truncated RSN) — mdk4 mode m / crafted aireplay frames; WARN ≥3, CRIT ≥5 | — (L2 only) |
| `ROGUE_RADIUS` | WARN/CRIT | T1557.004 | a BSSID's 802.1X EAP conversation offered a weak inner method (EAP-MD5/GTC → CRIT) or leaked a real username with no anonymous outer identity (→ WARN) — eaphammer / hostapd-wpe lure | — (L2 only) |
| `DNS_TUNNEL` | CRIT | T1071.004 | dnscat2 / iodine signature in DNS traffic | src / 53 |
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
