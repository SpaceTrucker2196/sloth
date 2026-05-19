# ICMP  `[i]`

Log of ICMPv4 ([RFC 792](https://www.rfc-editor.org/rfc/rfc792)) and
ICMPv6 ([RFC 4443](https://www.rfc-editor.org/rfc/rfc4443)) messages.

## Protocol

ICMP carries IP-layer control messages: ping (echo request/reply),
"destination unreachable", "TTL exceeded" (used by traceroute),
redirects, MTU discovery, and — on IPv6 — neighbour discovery / router
advertisement.

It runs directly over IP (proto 1 for v4, proto 58 for v6), with no
ports. Most ICMP is benign housekeeping; the interesting traffic is
echo (ping) and the error replies that reveal network topology.

## What sloth captures

Per entry: src, dst, type, code, sequence (for echos), v4/v6 flag.

## View

```
 ── ICMP log ───────────────────────────────────────────────────
 v   src              type
 v4  192.168.1.5      Echo Req          ← bright — outbound ping
 v4  8.8.8.8          Echo Reply
 v4  10.0.0.1         Unreachable       ← heat orange — error
 v6  fe80::1          Neigh Sol         ← v6 neighbour discovery
 v6  fe80::2          Router Adv
```

Echo Request: bright. Errors (Unreachable / TTL Exceeded / Param
Prob): heat orange. Everything else: normal.

## What's normal

- Sporadic ping for connectivity checks.
- IPv6 Neighbour Solicitation/Advertisement and Router
  Advertisement on healthy v6 networks.

## What's suspicious

- **Echo Request floods** from one source — ping sweep or ICMP DoS.
  See `[v] Alerts` if it correlates with [PORT_SCAN](alerts.md#port_scan).
- **Long string of "TTL Exceeded"** to one source — somebody's
  running traceroute against you (recon).
- **ICMP redirect** from anything other than your gateway —
  [ICMP redirect attack](https://www.imperva.com/learn/ddos/icmp-attacks/),
  trying to insert a man-in-the-middle.
- **ICMP tunnel** signatures: large echo payloads (>1KB), sequence
  numbers that don't increment normally, or huge volumes of pings to
  one destination. Tools like
  [ptunnel](https://github.com/utoni/ptunnel-ng) hide TCP traffic in
  ICMP.
- **Rogue Router Advertisement** (ICMPv6 type 134) from an unexpected
  source — `[v6] RA` flooding can hijack default routes on a LAN.
  See [RA Guard](https://www.rfc-editor.org/rfc/rfc6105).

## See also

- Parser: [`src/icmp_log.c`](../../src/icmp_log.c).
- ICMPv4 types: [IANA ICMP parameters](https://www.iana.org/assignments/icmp-parameters).
- ICMPv6 types: [IANA ICMPv6 parameters](https://www.iana.org/assignments/icmpv6-parameters).
