---
name: BGP observability — BGP_NOTIFICATION_BURST alert
description: Detecting session-instability and hijack-precursor patterns on TCP/179
type: feature
---

# BGP observability

BGP-4 (RFC 4271) is the inter-domain routing protocol that wires
the internet together — and, increasingly, the protocol large
enterprises run inside the data centre to glue together top-of-rack
fabric. Sessions run over TCP/179. Sloth's first BGP pass is
narrow: walk the RFC 4271 §4.1 19-byte header per message,
classify by type (OPEN / UPDATE / NOTIFICATION / KEEPALIVE),
aggregate per peer-pair, and fire `BGP_NOTIFICATION_BURST` when
a single peer-pair emits ≥3 NOTIFICATION messages — the shape
of a flapping peer or a hijack precursor tearing down a
legitimate session.

## What we detect

BGP's common header is fixed at 19 bytes:

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                           Marker                              +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Length               |      Type     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Marker**: 16 bytes of `0xFF` in modern BGP (the field is a
  vestige of MD5 authentication; reused for framing today).
- **Length**: total message length in network byte order, 19–4096.
- **Type**: one byte — the four message types we count.

| Type | Name           | RFC 4271 § | What we infer |
|------|----------------|-----------:|---------------|
| 1    | OPEN           | 4.2        | session start (capability exchange) |
| 2    | UPDATE         | 4.3        | route announcement / withdrawal |
| 3    | NOTIFICATION   | 4.5        | session teardown (the rare-event signal) |
| 4    | KEEPALIVE      | 4.4        | heartbeat, default 60s |

A TCP segment can carry multiple back-to-back BGP messages; the
walker iterates while a valid marker + length + known type are
present, stopping on the first malformed or unknown record.

Per-(peer_a, peer_b) aggregation with IPs sorted lexically — so
messages in either direction collapse to one session entry. 32
peer-pairs tracked; oldest-by-last-seen eviction on overflow.

## Alert: `BGP_NOTIFICATION_BURST`

```
BGP_NOTIFICATION_BURST: 10.0.0.1 <-> 10.0.0.2: 3 BGP NOTIFICATION
messages (session-instability or hijack-precursor; opens=2
updates=14 keepalives=42)
```

| Field | Value |
|-------|-------|
| Severity | CRIT |
| Threshold | `notification_count ≥ 3` per peer-pair |
| Dedup key | `bgp-notif:<peer_a><>peer_b>` |
| `match_ip` | `peer_a` (smaller-IP endpoint) |
| `match_port` | 179 |

Why 3: in normal operation NOTIFICATIONs are rare — they're sent
only on session teardown for hold-timer expiry, protocol errors,
or operator-initiated reset. A healthy peering relationship can
go weeks without one. Three NOTIFICATIONs on the same peer-pair
inside the active aggregation window means either a flapping
peer (operationally interesting — congestion, MTU, hold-timer
mis-tuning) or a route-hijack precursor (an attacker on path
tearing down the legitimate session before announcing
competing prefixes). Either way an operator should look.

## What's normal

- `keepalive_count` dominates the counters — one per peer
  every ~60s by default.
- `update_count` correlated with route churn — handful per hour
  on a stable iBGP fabric, more on a default-free DFZ peer.
- `open_count` low (one per session lifetime).
- `notification_count` zero or near-zero. A NOTIFICATION at
  startup (e.g. capability mismatch fixed by a config push) is
  expected and falls below the threshold.

## What's suspicious

- `notification_count ≥ 3` from one peer-pair — fires the alert.
- High `open_count` with few KEEPALIVEs in between — repeated
  session establishment that doesn't stick (flapping under the
  hold-timer floor).
- High `update_count` from an unfamiliar peer-pair — possible
  unauthorised session, or operator mis-configuration pulling
  routes from the wrong neighbour. Not currently a dedicated
  alert; the `bgp_session` record exposes the counters for
  SIEM-side rules.

## Deliberately out of scope (for now)

- **AS-number extraction.** OPEN carries the peer's ASN; UPDATE
  paths carry the AS_PATH attribute. Decoding either would
  unlock proper prefix-hijack detection (announcement of a
  prefix legitimately originated by another ASN). The marker /
  length / type walk is the foundation; AS parsing is a Tier 2
  follow-up.
- **Prefix-hijack detection.** Requires AS_PATH parsing plus
  ground-truth on which prefixes belong to which ASN (RPKI ROAs
  or an IRR snapshot). Out of scope for a passive observer with
  no external state.
- **Route-flap dampening detection.** The classic stability
  heuristic — same prefix oscillating up/down in UPDATE
  announcements/withdrawals. Needs UPDATE NLRI parsing.
- **BMP** (BGP Monitoring Protocol, RFC 7854). Would give us
  the RIB-In view without parsing per-message framing, but is
  an active-config approach — operators have to enable it on
  the router. Sloth stays passive.
- **MD5-authenticated BGP.** The marker field is supposed to be
  the MD5 digest under TCP/MD5 (RFC 2385), but virtually no one
  uses it anymore. Sloth assumes the modern `0xFF`-filled
  marker; sessions running TCP/MD5 simply won't match the
  marker check and will be silently skipped.

## References

- RFC 4271 — BGP-4.
- RFC 7454 — BGP operations and security.
- MITRE ATT&CK T1565.002 — Transmitted Data Manipulation
  (BGP-hijack subset).
- Cloudflare post-mortem on the June 2019 Verizon / DQE Communications
  hijack — illustrates the NOTIFICATION / re-establishment pattern
  a passive observer would see at the edge.

## Related pages

- [[alerts]] — the rule that fires on the tracker's state.
- [[jsonl-schema]] — `bgp_session` wire format.
- [[ldap-snoop]] / [[kerberos-snoop]] / [[smb-snoop]] — the
  AD-substrate passive observables. BGP joins them as
  infrastructure-layer visibility a passive observer can
  surface without ever putting a packet on the wire.
