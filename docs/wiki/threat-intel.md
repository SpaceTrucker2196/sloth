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

**Sources**: `src/threat_intel.c`, `src/alerts/rules_wired.c`
(`rule_threat_domain`, `rule_threat_ip`), `src/views/help.c`,
`docs/views/alerts.md`, `docs/views/dns.md`,
`docs/views/connections.md`, issue #96.

**Last updated**: 2026-10-21 (#152 — a cut qname is not matched; the
SNI and HTTP `Host:` triggers this page used to list were never
implemented and are removed. #118 moved `rule_threat_domain` and
`rule_threat_ip` to `src/alerts/rules_wired.c`; #96 labelled the
synthetic status in code, UI and docs).

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

### A cut name is not matched (#152)

`dns_log` keeps 63 bytes of a query name. The stored text of a longer
name is a prefix, and a prefix can end on an IOC domain:
`<43 x a>.malware.testing.com.evil.example` stores as
`<43 x a>.malware.testing.com`, a name under the IOC that nobody
queried. A NUL octet inside a label cuts the stored text the same way
(`x.malware.testing.com\0x` stores as `x.malware.testing.com`). Any web
page can make a browser resolve such a name, so before #152 an attacker
could raise a CRIT for an IOC domain at will.

`dns_log_parse()` flags a row whose stored text is shorter than the wire
name (`dns_log_entry_t.qname_trunc`, from `dns_read_name_len()`), and
`rule_threat_domain` skips flagged rows, the guard `SURV_DNS` has had
since #105. **Skipped, not down-graded**: the match is a suffix match
and the wire name continues past the stored text, so a match on a cut
row is a match on where the cut fell, not on the queried name's suffix,
and carries no evidence either way. A long name that really is under an
IOC can have its cut land on an IOC string too
(`<label>.malware.testing.com.<more>.malware.testing.com`), but that hit
is the same coincidence as the benign one. Nothing real is lost beyond truncation's own
cost — an IOC lookup longer than 63 bytes had its IOC suffix cut off
before the rule ever saw it, and a feed swapped in for the demo list is
missed on such names either way.

Pinned in `tests/test_alerts.c` by wire-built queries (RFC 1035 §4.1.1
header, §3.1 labels) through `dns_log_parse()`: a 76-byte name whose
stored prefix ends on `malware.testing.com` and a NUL-octet name stay
quiet; the same labels at exactly 63 bytes still fire CRIT.

### Other name-against-table rules, checked for the same exposure

| Rule | Reads | Table | Status |
|------|-------|-------|--------|
| `SURV_DNS` | `dns_log` qname | vendor watchlist | skips `qname_trunc` (#105, d54110e) |
| `SURV_CLOUD_SNI` | `tls_log` SNI | vendor watchlist | skips `host_trunc` (#105, d54110e) |
| `THREAT_DOMAIN` | `dns_log` qname | IOC list | skips `qname_trunc` (#152) |
| `DGA_DOMAIN` | `dns_log` qname | none — entropy of the leftmost label | not exposed: it scores the leftmost label, which a 63-byte cut keeps whole and a NUL octet only shortens; either way it is the asker's own text, and no listed name is attributed |
| `DNS_TUNNEL` | `dns_log` qname | none — buckets by 2-label parent | not a table match, but a cut name's parent is the cut prefix's last two labels; left alone, because tunnel queries are exactly the long names truncation cuts, and skipping them would blind the detector |
| `WEAK_TLS` | `tls_log` SNI | none — the SNI is only shown in the detail | not exposed |
| `CAPTIVE_PORTAL` (`cp_check_dns`, `cp_check_tls` in `src/capture/capture.c`) | parsed DNS qname, TLS SNI | connectivity-check sentinels (`src/captive_portal.c`) | not fixed, not material: `host_eq` is an **exact** match and every sentinel is shorter than 63 bytes, so the 63-byte cut can never produce one. A NUL octet in the last label can (`captive.apple.com\0x` stores as `captive.apple.com`, flagged but not skipped), but only an on-path or local injector can put that name in front of sloth, and such a party could spoof the real sentinel anyway, so skipping the flag would add nothing |

## What triggers

- DNS qname hit (query or response, whole name only) →
  [`ALERT_THREAT_DOMAIN`](../views/alerts.md#threat_domain) CRIT.
- TLS SNI and HTTP `Host:` are **not** matched against the list. Earlier
  revisions of this page said they were; `rule_threat_domain` has only
  ever read `dns_log`.
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
