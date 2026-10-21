---
name: views-catalog
description: Every sloth view indexed by keybinding, grouped into observation / synthesis / WiFi SIGINT
type: reference
---

# Views catalog

**Summary**: Full keybinding-to-view map, with one-line descriptions and links to the per-view source docs in `docs/views/`.

**Sources**: `include/sloth_views.def` (the one list the enum, the tab
bar, the help card, the draw dispatch and the view-select keys are all
generated from — #117), `docs/views/README.md` and all `docs/views/*.md`.

**Count**: `VIEW_COUNT` = **<!-- count:views -->36<!-- /count -->**. Every key below is a row of
`include/sloth_views.def`; if the two disagree, the `.def` is right.

**Last updated**: 2026-10-21 (#144 slice 4: `*` BLE, the first punctuation view key); 2026-10-15 (#117 — keys and count now generated from `sloth_views.def`).

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
| `m` | Channel     | [channel.md](../views/channel.md) | per-channel 802.11 activity histogram |

## Synthesis — derived from observation

| Key | View | Source doc | One-liner |
|-----|------|-----------|-----------|
| `v` | Alerts    | [alerts.md](../views/alerts.md) | rule-derived events — see [[alerts]] |
| `g` | Devices   | [devices.md](../views/devices.md) | join of ARP + DHCP + beacons + probes + stations, with a `CAMERA` row type and an `Enter` signal-trail detail ([[camera-detection]]) |
| `o` | Dashboard | [dashboard.md](../views/dashboard.md) | seven-band composite — see [[dashboard]] |
| `l` | OSI stack | [osi.md](../views/osi.md) | every observed count mapped onto its OSI layer |
| `x` | Twins     | [twins.md](../views/twins.md) | evil-twin episode table |
| `y` | KARMA     | [karma.md](../views/karma.md) | KARMA / PineAP candidate table (#30) |
| `z` | RADIUS    | [rogue-radius.md](../views/rogue-radius.md) | 802.1X EAP method / identity-leak table (#31, #38) — see [[enterprise-rogue]] |
| `c` | FragAttacks | [fragattack.md](../views/fragattack.md) | per-BSSID FragAttacks counters (#75) — see [[fragattacks]] |
| `*` | BLE | [ble.md](../views/ble.md) | BLE advertisers per sensor, HID / watchlist flags, `Enter` detail (#144 slice 4) — see [[ble]]. `*` because every letter and digit is taken |
| `f` | Research  | [research.md](../views/research.md) | the cited source behind each alert that fired (#73) — see [[research-corpus]] |
| `?` | Help      | — | keybindings, version, and the embedded-data disclosures |

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
