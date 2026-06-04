---
name: IPv6 NDP — rogue RA detection
description: How sloth observes Router Advertisements and fires ROGUE_RA
type: feature
---

# IPv6 NDP — rogue RA detection

The Neighbor Discovery Protocol (RFC 4861) replaces ARP, ICMP Router
Discovery, and ICMP Redirect for IPv6. It's the LAN-side control
plane: hosts use it to find routers, find each other, and detect
duplicate addresses. Because the protocol is unauthenticated by
default (RFC 3971's Secure Neighbor Discovery shipped but is rarely
deployed), it's a fertile attack surface.

Sloth's first pass at NDP visibility is narrow on purpose: track
**Router Advertisements** (ICMPv6 type 134) and fire `ROGUE_RA` when
more than one distinct router source advertises a non-zero lifetime.
This is the IPv6 analogue of [[alerts]]'s `ROGUE_DHCP` rule.

## Threat model

A single legitimate default router exists on a normal segment. When
two RA-emitters compete, three things happen:

1. SLAAC-configured hosts (basically every IPv6 client) pick one of
   the two as default router, often the **most recent** announcement.
2. The attacker's router can NAT64/translate the victim's IPv6 traffic
   back to IPv4, MITMing arbitrary connections. This is the
   [`mitm6`](https://github.com/dirkjanm/mitm6) attack pattern.
3. Windows clients in particular prefer IPv6 over IPv4 when both are
   available, so an injected default route silently steals **all**
   traffic the moment the rogue RA is observed — no user action
   required.

Even when the operator's network is IPv4-only on paper, modern
endpoints SLAAC themselves as soon as a router shows up. Detecting
the second RA-emitter is therefore the highest-leverage piece of NDP
visibility.

## What sloth captures

`src/ndp_snoop.c` parses ICMPv6 type 134 frames per RFC 4861 §4.2:

| Field | Notes |
|-------|-------|
| `src_ip` | IPv6 source address from the IPv6 header (typically link-local). |
| `src_mac` | Extracted from the **Source Link-Layer Address** option (RFC 4861 §4.6.1). `has_src_mac` is 1 iff the option was present. |
| `cur_hop_limit` | RA byte 4. |
| `flags` | RA byte 5 — M (Managed) / O (Other Config) / H (Home Agent) + reserved bits. |
| `router_lifetime` | RA bytes 6-7, big-endian seconds. `0` means "I'm not a default router" and disqualifies this source from `ROGUE_RA`. |
| `prefixes[]` | Up to 4, captured from **Prefix Information Options** (RFC 4861 §4.6.2). Formatted as `addr/len`. |
| `first_seen`, `last_seen`, `count` | Bookkeeping. |

What sloth **does not** capture (in v1):

- **NS / NA** (types 135/136) — the per-host neighbor cache. Worth
  building when an operator asks for it.
- **RS** (133) — host solicitations. Operationally low-signal.
- **Redirect** (137) — has its own attack surface but limited
  blast radius compared to RA.
- **DAD exhaustion** — bursty NS flooding. Detectable but the rate
  shape is different from rogue-RA and warrants its own rule.

## Alert: `ROGUE_RA`

```
ROGUE_RA: 2 distinct IPv6 routers on segment: fe80::1, fe80::dead
```

| Field | Value |
|-------|-------|
| Severity | CRIT |
| Dedup key | `rogue_ra:<comma-joined sorted router IPs>` |
| `match_ip` | first router by alphabetical sort |
| `match_port` | 0 (NDP runs over ICMPv6, no L4 port) |

Detection is identical in shape to `rule_rogue_dhcp`: collect the
distinct source IPs from `s->ndp_ras` where `router_lifetime > 0`,
sort, fire when count ≥ 2. The dedup key stays stable as long as the
same pair of competitors keeps advertising; a third router joining
mints a new key.

## What's normal

- Exactly one entry, lifetime non-zero, src_ip is the router's
  link-local (`fe80::...`), prefixes contain the SLAAC prefix the
  network actually uses.
- Occasional `router_lifetime = 0` entries from hosts running RA
  guard / Linux network managers that emit "I'm not a router"
  advertisements during shutdown.

## What's suspicious

- A second `router_lifetime > 0` entry whose `src_mac` doesn't match
  the legit router's expected vendor OUI.
- An entry where the advertised prefix doesn't match the segment's
  expected IPv6 range — an attacker's prefix often differs by a
  single nibble (`2001:db8:dead::/64` vs the real `2001:db8::/64`).
- Sudden change in the legit router's `cur_hop_limit` or `flags`
  byte — possible MITM impersonating the real router rather than
  competing with it.

## Wire format

The state is emitted on every poll as `type:"ndp_ra"` JSONL records
— full schema in [[jsonl-schema]]. The iOS / forwarder consumers
can key on `src_ip` to deduplicate.

## References

- RFC 4861 — Neighbor Discovery for IP version 6.
- RFC 4862 — IPv6 Stateless Address Autoconfiguration.
- RFC 6105 — IPv6 Router Advertisement Guard.
- [mitm6](https://github.com/dirkjanm/mitm6) — the canonical rogue-RA
  attack tool; bundled in Kali / CommandoVM.
- CERT/CC VU#287283 — historical RA-flood DoS.

## Related pages

- [[alerts]] — the rule that fires on the tracker's state.
- [[jsonl-schema]] — the `ndp_ra` wire format.
- [[architecture]] — where `ndp_snoop.c` fits in the source tree.
- [[dashboard]] — the panel set the alerts roll up into.
