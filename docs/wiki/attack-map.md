---
name: attack-map
description: Threat-to-view map — start here if you're hunting a specific threat class
type: reference
---

# Attack map

**Summary**: Cross-reference table from threat class → which sloth view (or wiki concept page) is the right entry point.

**Sources**: `docs/views/README.md`, `docs/views/alerts.md`, all per-view docs.

**Last updated**: 2026-05-25.

---

## Network-layer attacks

| Threat | Start here |
|--------|------------|
| DGA / DNS tunnelling | [dns.md](../views/dns.md), [[alerts]] (`NXDOMAIN_BURST`) |
| TLS downgrade / weak crypto | [tls.md](../views/tls.md), [[ja3-fingerprinting]] |
| Implant / C2 fingerprint | [[ja3-fingerprinting]], [[beacon-detection]] |
| ARP spoofing / MITM | [arp.md](../views/arp.md) |
| Rogue DHCP | [dhcp.md](../views/dhcp.md) |
| Port scan | [[alerts]] (`PORT_SCAN`) |
| Credential stuffing on HTTP | [http.md](../views/http.md) |
| Threat-intel domain / IP hit | [[threat-intel]], [[alerts]] |
| Responder / LLMNR poisoning | [nbns.md](../views/nbns.md) |
| UPnP-IGD abuse / CallStranger | [ssdp.md](../views/ssdp.md) |
| NTP amplification | [ntp.md](../views/ntp.md) |
| ICMP tunnel / RA flood | [icmp.md](../views/icmp.md) |

## WiFi / 802.11 attacks

| Threat | Start here |
|--------|------------|
| Evil-twin / rogue AP | [beacons.md](../views/beacons.md), [deauth.md](../views/deauth.md), [[wifi-sigint]] |
| WPA capture / PMKID harvest | [eapol.md](../views/eapol.md), [[wifi-sigint]] |
| Deauth-driven handshake harvest | [deauth.md](../views/deauth.md) + [eapol.md](../views/eapol.md) |
| Hidden-SSID disclosure | [beacons.md](../views/beacons.md) (revealed `*` rows) |
| Probe-request PNL leakage | [probe.md](../views/probe.md), [pnl.md](../views/pnl.md) |
| MAC-randomisation deanonymisation | [[mac-randomisation]], [seqnum.md](../views/seqnum.md), [pnl.md](../views/pnl.md) |
| KARMA / mana — auto-respond to every probe | [pnl.md](../views/pnl.md), [assoc.md](../views/assoc.md) |
| Beacon flood (mdk3/4) | [beacons.md](../views/beacons.md) |

## Triage tips

- **Bold IP across multiple [[dashboard]] panels** → start with
  [connections.md](../views/connections.md) and pivot to
  [packets.md](../views/packets.md).
- **Sustained CRIT alert** → the alert footer shows RIR + hosting-org
  enrichment; the alert key already names the IP / domain.
- **WiFi anomaly** → run the four [[wifi-sigint]] views side-by-side;
  they're designed to compose.

## Related pages

- [[alerts]] — the six alert rules and what each one keys on.
- [[threat-intel]] — the IOC list and its match semantics.
- [[ja3-fingerprinting]] — TLS-client identification primitive.
- [[beacon-detection]] — C2 periodicity detector.
- [[mac-randomisation]] — the seqnum deanonymisation primitive.
- [[wifi-sigint]] — the four 802.11 SIGINT views.
