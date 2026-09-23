---
name: threat-intel
description: Embedded IOC matcher — SYNTHETIC DEMO DATA, domain + IP lists, suffix-aware matching, how to swap in your own feed
type: reference
---

# Threat intelligence

> ## ⚠️ The shipped IOC list is synthetic demo data
>
> It is **not** a threat feed, and sloth does not have one. Until you
> replace the lists, `THREAT_DOMAIN` and `THREAT_IP` **detect nothing** —
> they are a working pipeline with no data in it. Do not present sloth's
> threat-intel matching as a detection capability in a deployment,
> tender or compliance document without saying which feed you loaded.

**Summary**: Sloth ships with embedded **synthetic** IOC lists in
`src/threat_intel.c`. They exist so the alerts pipeline can be exercised
in tests and so an operator has a template to extend. Swap them for your
own feed before production.

**Sources**: `src/threat_intel.c`, `src/alerts.c`
(`rule_threat_domain`, `rule_threat_ip`), `src/views/help.c`,
`docs/views/alerts.md`, `docs/views/dns.md`,
`docs/views/connections.md`, issue #96.

**Last updated**: 2026-09-23 (#96 — synthetic status labelled in code,
UI and docs).

---

## What ships

- `bad_domains[]` — 6 sentinel names: `malware.testing.com`,
  `phishing.testing.com`, `drive-by.testing.com`, `c2.example-bad.com`,
  `evilcorp.example`, `badactor.test`.
- `bad_ips[]` — 4 addresses from the RFC 5737 documentation prefixes:
  `192.0.2.66`, `192.0.2.99`, `198.51.100.7`, `203.0.113.13`.

These are placeholders, and in practice they match nothing — which is
the point. Production deployments swap them for a real feed.

One caveat worth stating rather than glossing: only `evilcorp.example`
and `badactor.test` sit under RFC 2606 **reserved** TLDs. The other four
are under `testing.com` / `example-bad.com`, which are ordinary
registrable `.com` names picked to look obviously fake. The IP entries
are genuinely non-routable by RFC 5737. So the domain list is
*implausible*, not *impossible*, and a host that really resolved
`malware.testing.com` would raise a CRIT that means nothing.

### How the operator is told

Three surfaces say so, and they are kept in sync deliberately:

| Surface | What it says |
|---------|--------------|
| Alert row (Alerts view, JSONL, `--report`) | the detail line reads `(demo IOC …)`, not `(IOC …)` — pinned by `tests/test_alerts.c` |
| Help view `[?]`, "Embedded data" section | `Threat intel: SYNTHETIC DEMO LIST` — pinned by `tests/test_help.c` |
| `src/threat_intel.c` / `.h` header comments | full statement, including why no feed ships |

A docs-only disclosure was judged insufficient in #96: the operator
reads the TUI, not the wiki.

## Why no feed ships

Sloth cannot fetch one. Retrieving a feed over the network is a network
write, which [`MISSION.md`](../../MISSION.md) §2 forbids — the passive
guarantee is the product. A future runtime loader that reads a file the
*operator* fetched out-of-band would be in scope; the fetch itself never
is.

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
