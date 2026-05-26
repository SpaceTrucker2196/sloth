---
name: threat-intel
description: Embedded IOC matcher — domain + IP lists, suffix-aware matching, how to swap in your own feed
type: reference
---

# Threat intelligence

**Summary**: Sloth ships with embedded synthetic IOC lists in `src/threat_intel.c`. They exist so the alerts pipeline can be exercised in tests. Swap them for your own feed in production.

**Sources**: `docs/views/alerts.md`, `docs/views/dns.md`, `docs/views/connections.md`.

**Last updated**: 2026-05-25.

---

## What ships

- `bad_domains[]` — synthetic, intentionally non-routable sentinels
  (`.testing`, `.example`).
- `bad_ips[]` — RFC 5737 documentation prefixes (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`).

These are placeholders. They will never match real traffic, which is
the point — production deployments swap them for a real feed.

## Matching semantics

- **Domains**: suffix-aware, case-insensitive. `evilcorp.example`
  matches both `evilcorp.example` and `*.evilcorp.example`, but
  **not** `notevilcorp.example`.
- **IPs**: exact match against the remote IP of an outbound connection
  observed via `src/platform/linux_tcpdiag.c`.

## What triggers

- DNS qname hit → [`ALERT_THREAT_DOMAIN`](../views/alerts.md#threat_domain) CRIT.
- TLS SNI hit → same `THREAT_DOMAIN` (SNI is a qname analogue).
- HTTP `Host:` hit → same `THREAT_DOMAIN`.
- Connection remote IP hit → [`ALERT_THREAT_IP`](../views/alerts.md#threat_ip) CRIT.

Each alert carries `match_ip` + `match_port` so [[pcap-export]] can
write the matching packets to `--pcap-dir`.

## Swapping in your own feed

Edit `bad_domains[]` and `bad_ips[]` in `src/threat_intel.c`. No file
loader today — the lists are baked at build time. Keeping them in code
makes the binary self-contained (no `/etc` dep) and makes the suffix
matcher trivially testable.

If you need runtime-loaded feeds, that's a new feature — wire it in
`src/threat_intel.c` and keep the existing matchers' signatures so
[[alerts]] doesn't need to change.

## Related pages

- [[alerts]] — the engine that consumes IOC matches.
- [[ja3-fingerprinting]] — complementary fingerprint-based detection.
- [[pcap-export]] — packet capture for matching connections.
