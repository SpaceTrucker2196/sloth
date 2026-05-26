---
name: alerts
description: Alert engine internals — dedup-by-key ring, the six rules, severity levels, per-alert pcap hook
type: reference
---

# Alerts

**Summary**: A small dedup-by-key ring runs every poll. Each rule scans current state, builds a stable key, and either bumps an existing alert's hit count or appends a fresh one. New keys also get a JSONL log line and (when `--pcap-dir` is set) a per-alert pcap dump.

**Sources**: `docs/views/alerts.md`, `docs/views/dns.md`, `docs/views/connections.md`, `docs/views/deauth.md`.

**Last updated**: 2026-05-25.

---

## Engine

- File: `src/alerts.c`.
- Dedup key examples: `scan:<ip>`, `threat-d:<domain>`, `threat-ip:<ip>:<port>`.
- New-key path: JSONL line + (optional) pcap dump of the matching
  packets via `src/alert_pcap.c`. See [[pcap-export]].
- `c` clears all alerts and resets dedup state; future hits re-arm.

## Severity tiers

Three tiers, yellow → orange → red, with cross-panel coloring (see
[[ip-palette]]):

| Tier | Hue    | Meaning                                          |
|------|--------|--------------------------------------------------|
| LOW  | yellow | Recon / suspicious-but-passive (port scan, etc.) |
| WARN | orange | Clearly malicious, not yet active exploitation   |
| CRIT | red    | Active attack or IOC hit                         |

## Rules (current)

The full table lives in [`docs/views/alerts.md`](../views/alerts.md);
the headline rules per tier:

- **LOW**: `PORT_SCAN`, `NXDOMAIN_BURST`, `PROBE_FLOOD`
- **WARN**: `DEAUTH_FLOOD`, `BEACONING`, `DGA_DOMAIN`, `WEAK_TLS`
- **CRIT**: `THREAT_DOMAIN`, `THREAT_IP`, `ARP_SPOOF`, `ROGUE_DHCP`,
  `EVIL_TWIN`, `KARMA_AP`, `DNS_TUNNEL`, `ATTACK_TOOL_UA`,
  `ATTACK_PATH`

## Cross-panel coloring

Any alert with a concrete `match_ip` adds that IP to the TUI
alert-hot list at the rule's severity for `ALERT_HOT_TTL_S` (1h).
Every panel that renders the IP (connections, top-hosts, packets,
hostname rows) paints it in the matching tier colour. Promotion only
— a later LOW does not demote an earlier CRIT on the same IP within
the TTL window.

## How rules find each other

- DNS rules read `s->dns_log[]` (see [`dns.md`](../views/dns.md)).
- Connection rules read `s->conns[]` (see [`connections.md`](../views/connections.md)).
- Deauth rule reads `s->deauth_events[]` (see [`deauth.md`](../views/deauth.md)).
- Threat-intel matching uses the embedded lists in `src/threat_intel.c` —
  see [[threat-intel]].
- Beaconing math lives in `src/beacon_detect.c` — see [[beacon-detection]].

## Adding a rule

Per `CLAUDE.md` "How to add an alert rule":

1. Add `ALERT_TYPE_<NAME>` to the enum in `include/sloth.h`.
2. Write `rule_<name>(state, now)` in `src/alerts.c` that calls `fire(...)`.
3. Wire the call from `alerts_update()`.
4. If the alert has a known target IP, pass `match_ip` + `match_port`
   to `fire()` so per-alert pcap works.
5. Add a row to the rule table in `docs/views/alerts.md`.
6. Test: seed state that should trigger, run `alerts_update`, assert
   `find_alert(type) >= 0`.

## Footer enrichment

The selected alert's footer shows RIR region (from the `/8` table) and
embedded hosting-org lookup (`src/ip_owner.c`). Useful for triage when
the rule fires on an unfamiliar IP.

## Related pages

- [[threat-intel]] — IOC list format, suffix matching, swap-in.
- [[beacon-detection]] — periodicity math.
- [[pcap-export]] — `--pcap-dir` mechanics.
- [[attack-map]] — protocol → threat table.
