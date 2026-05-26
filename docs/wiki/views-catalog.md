---
name: views-catalog
description: All 24 sloth views indexed by keybinding, grouped into observation / synthesis / WiFi SIGINT
type: reference
---

# Views catalog

**Summary**: Full keybinding-to-view map, with one-line descriptions and links to the per-view source docs in `docs/views/`.

**Sources**: `docs/views/README.md` and all `docs/views/*.md`.

**Last updated**: 2026-05-25.

---

## Observation — straight from the wire / kernel

| Key | View | Source doc | One-liner |
|-----|------|-----------|-----------|
| `1` | Interfaces  | [interfaces.md](../views/interfaces.md) | rtnetlink + sysfs view of every iface |
| `2` | Connections | [connections.md](../views/connections.md) | TCP/UDP sockets + PID + RTT + retx (INET_DIAG) |
| `3` | WiFi        | [wifi.md](../views/wifi.md) | nl80211 stations, signal, link state |
| `4` | Packets     | [packets.md](../views/packets.md) | live pcap, BPF filter, hex detail, pcap export |
| `5` | Processes   | [processes.md](../views/processes.md) | per-process socket inventory |
| `6` | Stats       | [stats.md](../views/stats.md) | counters from `/proc/net/snmp` |
| `7` | Probe       | [probe.md](../views/probe.md) | 802.11 probe-request sniffer |
| `8` | ARP         | [arp.md](../views/arp.md) | kernel ARP table |
| `9` | mDNS        | [mdns.md](../views/mdns.md) | multicast DNS service announcements |
| `0` | NBNS        | [nbns.md](../views/nbns.md) | NetBIOS name service / LLMNR |
| `d` | DHCP        | [dhcp.md](../views/dhcp.md) | DHCP DISCOVER/OFFER/REQUEST/ACK |
| `s` | SSDP        | [ssdp.md](../views/ssdp.md) | UPnP discovery |
| `b` | Beacons     | [beacons.md](../views/beacons.md) | passive 802.11 beacon sniffer |
| `a` | Deauth      | [deauth.md](../views/deauth.md) | deauth / disassoc + flood detection |
| `h` | HTTP        | [http.md](../views/http.md) | plaintext HTTP req log |
| `t` | TLS         | [tls.md](../views/tls.md) | ClientHello, SNI, JA3 — see [[ja3-fingerprinting]] |
| `u` | QUIC        | [quic.md](../views/quic.md) | QUIC initials |
| `r` | DNS         | [dns.md](../views/dns.md) | every Q/R on UDP/53 |
| `p` | NTP         | [ntp.md](../views/ntp.md) | NTP traffic |
| `i` | ICMP        | [icmp.md](../views/icmp.md) | ICMP log |

## Synthesis — derived from observation

| Key | View | Source doc | One-liner |
|-----|------|-----------|-----------|
| `v` | Alerts    | [alerts.md](../views/alerts.md) | rule-derived events — see [[alerts]] |
| `g` | Devices   | [devices.md](../views/devices.md) | join of ARP + DHCP + beacons + probes + stations |
| `o` | Dashboard | [dashboard.md](../views/dashboard.md) | seven-band composite — see [[dashboard]] |

## WiFi SIGINT (v1.1)

See [[wifi-sigint]] for the full SIGINT primitives.

| Key | View | Source doc | One-liner |
|-----|------|-----------|-----------|
| `k` | PNL    | [pnl.md](../views/pnl.md) | per-MAC PNL aggregation + OS fingerprint |
| `e` | EAPOL  | [eapol.md](../views/eapol.md) | PMKID + 4-way handshake capture |
| `j` | Seqnum | [seqnum.md](../views/seqnum.md) | MAC-randomisation deanonymisation — see [[mac-randomisation]] |
| `w` | Assoc  | [assoc.md](../views/assoc.md) | confirmed STA ↔ AP associations |

## Adding a view

See `CLAUDE.md` "How to add a new view" — 11-step checklist that keeps
`VIEW_COUNT` in sync, lays out the file, wires the key, and demands a
test + a per-view doc.

## Related pages

- [[sloth]]
- [[architecture]]
- [[dashboard]]
- [[attack-map]]
