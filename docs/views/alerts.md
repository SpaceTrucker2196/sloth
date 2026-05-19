# Alerts  `[v]`

Rule-derived events: port scans, deauth floods, NXDOMAIN bursts,
threat-intel hits, periodic beaconing.

## Engine

A small dedup-by-key ring (`src/alerts.c`) — each rule scans the
current state every poll, builds a stable key (e.g. `scan:<ip>`,
`threat-d:<domain>`), and either bumps an existing alert's hit count
or appends a fresh one. New keys also get a JSONL log line and (if
`--pcap-dir` is set) a per-alert pcap dump of the matching packets.

## Rules

| Rule | Sev | Trigger | match_ip / port |
|------|-----|---------|-----------------|
| `PORT_SCAN`      | CRIT | one source touched ≥ 8 distinct local ports | scanner / 0 |
| `DEAUTH_FLOOD`   | WARN | ≥ 5 deauth/disassoc frames in 5 s to one target | — (L2 only) |
| `NXDOMAIN_BURST` | WARN | ≥ 10 NXDOMAIN replies to one source in 60 s | src / 53 |
| `THREAT_DOMAIN`  | CRIT | DNS qname matches embedded IOC list | src / 53 |
| `THREAT_IP`      | CRIT | conn remote IP matches embedded IOC list | remote / port |
| `BEACONING`      | WARN | flow with ≥ 5 samples, mean ≥ 10 s, jitter/mean ≤ 0.25 | remote / port |

The IOC lists in
[`src/threat_intel.c`](../../src/threat_intel.c) are intentionally
synthetic (RFC 5737 doc IPs, `.testing` / `.example` sentinels). They
exist so the alerts pipeline can be exercised in tests — swap in your
own feed for production.

## View

```
 ── Alerts: 3 crit 1 warn 4 total ──────────────────────────────
 Time      Sev   Title            n    Detail
 22:01:01  CRIT  THREAT_IP        1    connection to 192.0.2.66:443 (IOC 192.0.2.66)
 22:01:01  CRIT  THREAT_DOMAIN    4    192.168.1.5 queried malware.testing.com (IOC ...)
 22:00:55  WARN  BEACONING        12   203.0.113.7:443 every 60s (jitter=1.2s, n=12)
 22:00:30  CRIT  PORT_SCAN        1    10.0.0.99 scanned 18 distinct ports
 22:00:15  WARN  NXDOMAIN_BURST   3    192.168.1.50 saw 15 NXDOMAIN responses in 60s

 ── context: ip=192.0.2.66  port=443  region=ARIN (US/CA)  owner=(unknown)
```

CRIT rows: heat-1.0 red. WARN: heat-0.7 orange. Count column lights
up when ≥ 2 hits on the same key (sustained condition).

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
